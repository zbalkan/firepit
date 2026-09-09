"""DuckDB-native STIX 2.1 storage.

Firepit accepts raw STIX 2.1 JSON and lets DuckDB perform object iteration,
JSON extraction, and casts into the static native schema. Python only handles
the storage boundary, transactions, and provenance.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from uuid import UUID

import duckdb

from firepit.exceptions import InvalidObject
from firepit.stixschema import SCO_TYPES, rendered_schema
from firepit.validate import validate_name
from firepit.views import install_views

_NATIVE_META = "duckdb_native_model"
_NATIVE_VERSION = "6"
_NESTED_PREFIXES = ("MAP(", "STRUCT(")
_INTEGER_TYPES = {
    "TINYINT", "SMALLINT", "INTEGER", "BIGINT", "HUGEINT",
    "UTINYINT", "USMALLINT", "UINTEGER", "UBIGINT", "UHUGEINT",
}
_STIX_TYPE_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$", re.ASCII)


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


def _expected_json_types(dtype: str):
    """Return acceptable DuckDB JSON type labels for a top-level STIX field."""
    if dtype == "JSON":
        return None
    if dtype in {"VARCHAR", "TIMESTAMPTZ"}:
        return {"VARCHAR", "NULL"}
    if dtype == "BOOLEAN":
        return {"BOOLEAN", "NULL"}
    if dtype in _INTEGER_TYPES:
        return {"BIGINT", "UBIGINT", "NULL"}
    if dtype in {"DOUBLE", "FLOAT", "REAL"} or dtype.startswith("DECIMAL("):
        return {"DOUBLE", "BIGINT", "UBIGINT", "NULL"}
    if dtype.endswith("[]"):
        return {"ARRAY", "NULL"}
    if dtype.startswith(_NESTED_PREFIXES):
        return {"OBJECT", "NULL"}
    return None


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


def _validate_stix_type(obj_type: str) -> None:
    if (
        not isinstance(obj_type, str)
        or not 3 <= len(obj_type) <= 250
        or _STIX_TYPE_RE.fullmatch(obj_type) is None
    ):
        raise InvalidObject(f"invalid STIX object type: {obj_type!r}")


def _validate_identifier(obj_type: str, object_id: str) -> None:
    if not isinstance(object_id, str):
        raise InvalidObject(f"{obj_type} must provide a string id")
    prefix, sep, uuid_text = object_id.partition("--")
    if sep != "--" or prefix != obj_type:
        raise InvalidObject(
            f"STIX id {object_id!r} does not match object type {obj_type!r}"
        )
    try:
        UUID(uuid_text)
    except (TypeError, ValueError, AttributeError) as exc:
        raise InvalidObject(f"invalid STIX identifier: {object_id!r}") from exc


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
        _validate_stix_type(obj_type)
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
            bundle_row = self.connection.execute(
                "SELECT json_extract_string(j, '$.type'), "
                "json_extract_string(j, '$.id'), "
                "json_exists(j, '$.objects'), json_type(j, '$.objects') "
                "FROM (SELECT ?::JSON AS j)",
                (bundle_text,),
            ).fetchone()
        except duckdb.Error as exc:
            raise InvalidObject(f"invalid STIX JSON: {exc}") from exc

        bundle_type, bundle_id, has_objects, objects_type = bundle_row
        if bundle_type != "bundle":
            raise InvalidObject("expected a STIX bundle")
        if bundle_id is not None:
            _validate_identifier("bundle", bundle_id)
        if has_objects and objects_type != "ARRAY":
            raise InvalidObject("bundle.objects must be a list of STIX objects")

        rows = self.connection.execute(
            "SELECT json_extract_string(value, '$.type'), "
            "json_extract_string(value, '$.id'), "
            "json_extract_string(value, '$.spec_version'), "
            "json_exists(value, '$.objects'), "
            "json_exists(value, '$.object_refs'), "
            "json_type(value, '$.object_refs'), "
            "json_array_length(value, '$.object_refs') "
            "FROM json_each(?::JSON, '$.objects')",
            (bundle_text,),
        ).fetchall()

        for (
            obj_type,
            object_id,
            spec_version,
            has_embedded,
            has_object_refs,
            object_refs_type,
            object_refs_count,
        ) in rows:
            if obj_type is None:
                raise InvalidObject("every STIX object must provide type")
            _validate_stix_type(obj_type)
            if object_id is None:
                raise InvalidObject("every STIX object must provide id")
            _validate_identifier(obj_type, object_id)

            if obj_type in SCO_TYPES:
                if spec_version not in (None, "2.1"):
                    raise InvalidObject("Firepit accepts STIX 2.1 only")
            elif spec_version != "2.1":
                raise InvalidObject(
                    f"{obj_type} must explicitly declare spec_version 2.1"
                )

            if obj_type == "observed-data":
                if has_embedded:
                    raise InvalidObject(
                        "embedded observed-data.objects is not supported; "
                        "provide STIX 2.1 observed-data.object_refs"
                    )
                if not has_object_refs:
                    raise InvalidObject("observed-data must provide object_refs")
                if object_refs_type != "ARRAY" or not object_refs_count:
                    raise InvalidObject(
                        "observed-data.object_refs must be a non-empty list"
                    )

    def _object_types(self, bundle_text: str):
        return [
            row[0]
            for row in self.connection.execute(
                "SELECT DISTINCT json_extract_string(value, '$.type') AS obj_type "
                "FROM json_each(?::JSON, '$.objects')",
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

    def _validate_known_shapes(self, obj_type: str, bundle_text: str, schema):
        fields = []
        for name, dtype in schema.items():
            if name == "id":
                continue
            expected = _expected_json_types(dtype)
            if expected is not None:
                fields.append((name, expected))
        if not fields:
            return

        select = ", ".join(
            f"json_type(value, '{_json_path(name)}')" for name, _ in fields
        )
        rows = self.connection.execute(
            f"SELECT {select} FROM json_each(?::JSON, '$.objects') "
            "WHERE json_extract_string(value, '$.type') = ?",
            (bundle_text, obj_type),
        ).fetchall()
        for row in rows:
            for (name, expected), actual in zip(fields, row):
                if actual is not None and actual not in expected:
                    allowed = ", ".join(sorted(expected - {"NULL"}))
                    raise InvalidObject(
                        f"{obj_type}.{name} has JSON type {actual}; expected {allowed}"
                    )

    def _insert_type_from_json(self, obj_type: str, bundle_text: str, query_id):
        schema = rendered_schema(obj_type)
        self._validate_known_shapes(obj_type, bundle_text, schema)
        self._create_native_table(obj_type)
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
            if obj_type not in SCO_TYPES:
                incoming_modified = (
                    "TRY_CAST(json_extract_string(EXCLUDED._raw, '$.modified') "
                    "AS TIMESTAMPTZ)"
                )
                existing_modified = (
                    f"TRY_CAST(json_extract_string({_qident(obj_type)}._raw, "
                    "'$.modified') AS TIMESTAMPTZ)"
                )
                stmt += (
                    f" WHERE {incoming_modified} IS NULL "
                    f"OR {existing_modified} IS NULL "
                    f"OR {incoming_modified} >= {existing_modified}"
                )

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
                "ON CONFLICT DO NOTHING",
                (str(query_id), bundle_text, obj_type),
            )

    def _mark_query_running(self, qid, source, stix_pattern, native_query):
        try:
            self.connection.execute(
                'INSERT INTO "raw_query" '
                '(query_id, source, stix_pattern, native_query, started_at, status, result_count) '
                "VALUES (?, ?, ?, ?, current_timestamp, 'RUNNING', 0)",
                (qid, source, stix_pattern, native_query),
            )
        except duckdb.ConstraintException as exc:
            raise InvalidObject(
                f"query_id {qid!r} already exists; use a new acquisition run id"
            ) from exc

    def cache(self, query_id, bundles, source=None,
              stix_pattern=None, native_query=None):
        """Ingest raw STIX 2.1 JSON and record acquisition provenance."""
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

            install_views(self.connection, self.session_id)
            if qid:
                self.connection.execute(
                    'UPDATE "raw_query" SET completed_at = current_timestamp, '
                    "status = 'COMPLETED', result_count = ? WHERE query_id = ?",
                    (object_count, qid),
                )
            self.connection.execute("COMMIT")
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
