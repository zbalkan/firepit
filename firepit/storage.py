"""DuckDB-native STIX 2.1 storage.

Firepit accepts raw STIX 2.1 JSON and lets DuckDB perform object iteration,
JSON extraction, and casts into the static native schema. Python only handles
the storage boundary, transactions, and provenance.
"""

from __future__ import annotations

import json
import os
import uuid

import duckdb

from firepit.exceptions import InvalidObject
from firepit.stixschema import rendered_schema
from firepit.validate import validate_name
from firepit.views import install_views

_NATIVE_META = "duckdb_native_model"
_NATIVE_VERSION = "6"
_NESTED_PREFIXES = ("MAP(", "STRUCT(")


def _qident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _json_path(name: str) -> str:
    return '$."' + name.replace('"', '\\"') + '"'


def _is_nested(dtype: str) -> bool:
    return dtype.endswith("[]") or dtype.startswith(_NESTED_PREFIXES)


def _json_projection(source: str, name: str, dtype: str) -> str:
    """Project one known STIX property into its declared DuckDB type."""
    path = _json_path(name)
    if dtype == "VARCHAR":
        return f"json_extract_string({source}, '{path}')"
    if dtype == "JSON":
        return f"json_extract({source}, '{path}')"
    if _is_nested(dtype):
        return f"CAST(json_extract({source}, '{path}') AS {dtype})"
    return f"CAST(json_extract_string({source}, '{path}') AS {dtype})"


def _bundle_text(bundle) -> str:
    if isinstance(bundle, dict):
        return json.dumps(bundle, ensure_ascii=False, separators=(",", ":"))
    if hasattr(bundle, "read"):
        data = bundle.read()
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        return data
    if isinstance(bundle, (str, os.PathLike)):
        value = os.fspath(bundle)
        if isinstance(value, str) and value.lstrip().startswith("{"):
            return value
        with open(value, "r", encoding="utf-8") as fp:
            return fp.read()
    raise TypeError("bundle must be a dict, JSON string, file-like object, or path")


class DuckDBStorage:
    """A narrow STIX 2.1 ingestion layer over one DuckDB schema."""

    def __init__(self, dbname, session_id=None):
        self.dbname = os.fspath(dbname)
        self.session_id = session_id or "main"
        validate_name(self.session_id)
        self.connection = duckdb.connect(self.dbname)
        self.connection.execute("SET python_enable_replacements=false")
        self.connection.execute(
            f"CREATE SCHEMA IF NOT EXISTS {_qident(self.session_id)}"
        )
        self.connection.execute(f"SET search_path='{self.session_id}'")
        self._prepare_native_model()
        install_views(self.connection, self.session_id)

    def close(self):
        self.connection.close()

    def _prepare_native_model(self):
        existing = {
            row[0]
            for row in self.connection.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = ? AND table_type = 'BASE TABLE'",
                (self.session_id,),
            ).fetchall()
        }

        if existing:
            if "__metadata" not in existing:
                raise RuntimeError(
                    "existing Firepit session is not a native DuckDB model; "
                    "create a new database/session"
                )
            row = self.connection.execute(
                'SELECT value FROM "__metadata" WHERE name = ?', (_NATIVE_META,)
            ).fetchone()
            if not row:
                raise RuntimeError(
                    "pre-native Firepit session is not supported; "
                    "create a new database/session"
                )
            if row[0] != _NATIVE_VERSION:
                raise RuntimeError(
                    f"unsupported native storage version {row[0]}; "
                    "create a new database/session"
                )
        else:
            self.connection.execute(
                'CREATE TABLE "__metadata" '
                '(name VARCHAR PRIMARY KEY, value VARCHAR)'
            )
            self.connection.execute(
                'INSERT INTO "__metadata" (name, value) VALUES (?, ?)',
                (_NATIVE_META, _NATIVE_VERSION),
            )
            self.connection.execute(
                'CREATE TABLE "raw_query" ('
                'query_id VARCHAR PRIMARY KEY, source VARCHAR, stix_pattern VARCHAR, '
                'native_query VARCHAR, started_at TIMESTAMPTZ, completed_at TIMESTAMPTZ, '
                'status VARCHAR, result_count UBIGINT, error VARCHAR)'
            )
            self.connection.execute(
                'CREATE TABLE "raw_bundle" ('
                'bundle_id UUID PRIMARY KEY, query_id VARCHAR, received_at TIMESTAMPTZ, '
                'bundle JSON)'
            )
            self.connection.execute(
                'CREATE TABLE "raw_run_object" ('
                'query_id VARCHAR, object_id VARCHAR, '
                'UNIQUE(query_id, object_id))'
            )

        self._create_native_table("identity")
        self._create_native_table("observed-data")

    def _table_exists(self, obj_type):
        return self.connection.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = ? AND table_name = ? AND table_type = 'BASE TABLE'",
            (self.session_id, obj_type),
        ).fetchone() is not None

    def _create_native_table(self, obj_type):
        validate_name(obj_type)
        if self._table_exists(obj_type):
            return
        schema = rendered_schema(obj_type)
        columns = []
        for name, dtype in schema.items():
            constraint = " UNIQUE" if name == "id" else ""
            columns.append(f"{_qident(name)} {dtype}{constraint}")
        columns.append('"_raw" JSON')
        self.connection.execute(
            f"CREATE TABLE {_qident(obj_type)} ({', '.join(columns)})"
        )

    def _validate_bundle(self, bundle_text: str):
        try:
            bundle_type = self.connection.execute(
                "SELECT json_extract_string(?::JSON, '$.type')", (bundle_text,)
            ).fetchone()[0]
        except duckdb.Error as exc:
            raise InvalidObject(f"invalid STIX JSON: {exc}") from exc
        if bundle_type != "bundle":
            raise InvalidObject("expected a STIX bundle")

        row = self.connection.execute(
            "SELECT "
            "COUNT(*) FILTER (WHERE json_extract_string(value, '$.id') IS NULL) AS missing_id, "
            "COUNT(*) FILTER (WHERE json_extract_string(value, '$.spec_version') "
            "IS NOT NULL AND json_extract_string(value, '$.spec_version') <> '2.1') AS old_version, "
            "COUNT(*) FILTER (WHERE json_extract_string(value, '$.type') = 'observed-data' "
            "AND json_extract(value, '$.objects') IS NOT NULL) AS embedded, "
            "COUNT(*) FILTER (WHERE json_extract_string(value, '$.type') = 'observed-data' "
            "AND json_extract(value, '$.objects') IS NULL "
            "AND json_extract(value, '$.object_refs') IS NULL) AS missing_refs "
            "FROM json_each(?::JSON, '$.objects')",
            (bundle_text,),
        ).fetchone()
        if row[0]:
            raise InvalidObject("every STIX object must provide id")
        if row[1]:
            raise InvalidObject("Firepit accepts STIX 2.1 only")
        if row[2]:
            raise InvalidObject(
                "embedded observed-data.objects is not supported; "
                "provide STIX 2.1 observed-data.object_refs"
            )
        if row[3]:
            raise InvalidObject("observed-data must provide object_refs")

    def _object_types(self, bundle_text: str):
        return [
            row[0]
            for row in self.connection.execute(
                "SELECT DISTINCT json_extract_string(value, '$.type') AS obj_type "
                "FROM json_each(?::JSON, '$.objects') "
                "WHERE json_extract_string(value, '$.type') IS NOT NULL",
                (bundle_text,),
            ).fetchall()
        ]

    def _object_count(self, bundle_text: str) -> int:
        return int(
            self.connection.execute(
                "SELECT COUNT(*) FROM json_each(?::JSON, '$.objects')",
                (bundle_text,),
            ).fetchone()[0]
        )

    def _insert_type_from_json(self, obj_type: str, bundle_text: str, query_id):
        self._create_native_table(obj_type)
        schema = rendered_schema(obj_type)
        columns = list(schema) + ["_raw"]
        col_sql = ", ".join(_qident(name) for name in columns)
        projections = [
            _json_projection("value", name, dtype)
            for name, dtype in schema.items()
        ]
        projections.append("value::JSON")
        stmt = (
            f"INSERT INTO {_qident(obj_type)} ({col_sql}) "
            f"SELECT {', '.join(projections)} "
            "FROM json_each(?::JSON, '$.objects') "
            "WHERE json_extract_string(value, '$.type') = ?"
        )

        if "id" in schema:
            updates = []
            for name in columns:
                if name == "id":
                    continue
                expr = (
                    f"COALESCE(EXCLUDED.{_qident(name)}, "
                    f"{_qident(obj_type)}.{_qident(name)})"
                )
                updates.append(f"{_qident(name)} = {expr}")
            stmt += " ON CONFLICT (id) DO UPDATE SET " + ", ".join(updates)

        try:
            self.connection.execute(stmt, (bundle_text, obj_type))
        except duckdb.ConversionException as exc:
            raise InvalidObject(
                f"{obj_type} contains a value incompatible with the STIX schema: {exc}"
            ) from exc

        if query_id:
            self.connection.execute(
                'INSERT INTO "raw_run_object" (query_id, object_id) '
                "SELECT ?, json_extract_string(value, '$.id') "
                "FROM json_each(?::JSON, '$.objects') "
                "WHERE json_extract_string(value, '$.type') = ? "
                "AND json_extract_string(value, '$.id') IS NOT NULL "
                "ON CONFLICT DO NOTHING",
                (str(query_id), bundle_text, obj_type),
            )

    def _mark_query_running(self, qid, source, stix_pattern, native_query):
        self.connection.execute(
            'INSERT INTO "raw_query" '
            '(query_id, source, stix_pattern, native_query, started_at, status, result_count) '
            "VALUES (?, ?, ?, ?, current_timestamp, 'RUNNING', 0) "
            'ON CONFLICT (query_id) DO UPDATE SET '
            'source = EXCLUDED.source, stix_pattern = EXCLUDED.stix_pattern, '
            'native_query = EXCLUDED.native_query, started_at = EXCLUDED.started_at, '
            "completed_at = NULL, status = 'RUNNING', result_count = 0, error = NULL",
            (qid, source, stix_pattern, native_query),
        )

    def cache(self, query_id, bundles, batchsize=2000, source=None,
              stix_pattern=None, native_query=None, **_kwargs):
        """Ingest raw STIX 2.1 JSON and record acquisition provenance."""
        del batchsize
        if not isinstance(bundles, list):
            bundles = [bundles]
        bundle_texts = [_bundle_text(bundle) for bundle in bundles]
        qid = str(query_id) if query_id is not None else None
        object_count = 0

        if qid:
            self._mark_query_running(qid, source, stix_pattern, native_query)

        self.connection.execute("BEGIN")
        try:
            for text in bundle_texts:
                self._validate_bundle(text)
                self.connection.execute(
                    'INSERT INTO "raw_bundle" VALUES (?, ?, current_timestamp, ?::JSON)',
                    (str(uuid.uuid4()), qid, text),
                )
                object_count += self._object_count(text)
                for obj_type in self._object_types(text):
                    self._insert_type_from_json(obj_type, text, qid)

            if qid:
                self.connection.execute(
                    'UPDATE "raw_query" SET completed_at = current_timestamp, '
                    "status = 'COMPLETED', result_count = ? WHERE query_id = ?",
                    (object_count, qid),
                )
            self.connection.execute("COMMIT")
            install_views(self.connection, self.session_id)
        except Exception as exc:
            self.connection.execute("ROLLBACK")
            if qid:
                self.connection.execute(
                    'UPDATE "raw_query" SET completed_at = current_timestamp, '
                    "status = 'FAILED', error = ? WHERE query_id = ?",
                    (str(exc), qid),
                )
            raise

    def delete(self):
        self.connection.execute(
            f"DROP SCHEMA IF EXISTS {_qident(self.session_id)} CASCADE"
        )
        self.connection.close()


def get_storage(path, session_id=None):
    return DuckDBStorage(path, session_id)


def session_exists(path, session_id=None):
    if not os.path.exists(path):
        return False
    session_id = session_id or "main"
    raw = duckdb.connect(path)
    try:
        row = raw.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = ? AND table_name = '__metadata'",
            (session_id,),
        ).fetchone()
        return row is not None
    finally:
        raw.close()
