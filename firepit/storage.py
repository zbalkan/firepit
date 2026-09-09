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

from firepit.exceptions import InvalidAttr, InvalidObject, UnknownViewname
from firepit.stixschema import rendered_schema
from firepit.validate import validate_name
from firepit.views import install_views

_NATIVE_META = "duckdb_native_model"
_NATIVE_VERSION = "5"
_NESTED_PREFIXES = ("MAP(", "STRUCT(")


def _qident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _json_path(name: str) -> str:
    return '$."' + name.replace('"', '\\"') + '"'


def _is_nested(dtype: str) -> bool:
    return dtype.endswith("[]") or dtype.startswith(_NESTED_PREFIXES)


def _json_projection(source: str, name: str, dtype: str) -> str:
    path = _json_path(name)
    if dtype == "VARCHAR":
        return f"json_extract_string({source}, '{path}')"
    if dtype == "JSON":
        return f"json_extract({source}, '{path}')"
    if _is_nested(dtype):
        return f"TRY_CAST(json_extract({source}, '{path}') AS {dtype})"
    return f"TRY_CAST(json_extract_string({source}, '{path}') AS {dtype})"


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


class Result:
    """Small dict-row wrapper for the transitional Python API."""

    def __init__(self, columns=(), rows=()):
        self._columns = tuple(columns)
        self._rows = list(rows)
        self._pos = 0

    def fetchone(self):
        if self._pos >= len(self._rows):
            return None
        row = self._rows[self._pos]
        self._pos += 1
        return dict(zip(self._columns, row))

    def fetchall(self):
        rows = self._rows[self._pos:]
        self._pos = len(self._rows)
        return [dict(zip(self._columns, row)) for row in rows]

    def close(self):
        self._pos = len(self._rows)


class DuckDBStorage:
    placeholder = "?"

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

    def _result(self):
        description = self.connection.description or ()
        columns = [item[0] for item in description]
        rows = self.connection.fetchall() if description else []
        return Result(columns, rows)

    def _execute(self, statement, values=None):
        try:
            self.connection.execute(statement, values or ())
        except duckdb.BinderException as exc:
            raise InvalidAttr(str(exc)) from exc
        except duckdb.CatalogException as exc:
            msg = str(exc)
            if "does not exist" in msg and ("Table" in msg or "View" in msg):
                raise UnknownViewname(msg) from exc
            raise
        return self._result()

    def _query(self, statement, values=None):
        return self._execute(statement, values)

    def _prepare_native_model(self):
        self.connection.execute(
            'CREATE TABLE IF NOT EXISTS "__metadata" '
            '(name VARCHAR PRIMARY KEY, value VARCHAR)'
        )
        row = self.connection.execute(
            'SELECT value FROM "__metadata" WHERE name = ?', (_NATIVE_META,)
        ).fetchone()
        if row and row[0] != _NATIVE_VERSION:
            raise RuntimeError(
                f"unsupported native storage version {row[0]}; "
                "create a new Firepit session/database"
            )

        self.connection.execute(
            'CREATE TABLE IF NOT EXISTS "raw_query" ('
            'query_id VARCHAR PRIMARY KEY, source VARCHAR, stix_pattern VARCHAR, '
            'native_query VARCHAR, started_at TIMESTAMPTZ, completed_at TIMESTAMPTZ, '
            'status VARCHAR, result_count UBIGINT, error VARCHAR)'
        )
        self.connection.execute(
            'CREATE TABLE IF NOT EXISTS "raw_bundle" ('
            'bundle_id UUID PRIMARY KEY, query_id VARCHAR, received_at TIMESTAMPTZ, '
            'bundle JSON)'
        )
        self.connection.execute(
            'CREATE TABLE IF NOT EXISTS "raw_run_object" ('
            'query_id VARCHAR, object_id VARCHAR)'
        )
        if not row:
            self.connection.execute(
                'INSERT INTO "__metadata" (name, value) VALUES (?, ?)',
                (_NATIVE_META, _NATIVE_VERSION),
            )

        self._create_native_table("identity")
        self._create_native_table("observed-data")

    def _table_exists(self, obj_type):
        row = self.connection.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = ? AND table_name = ? AND table_type = 'BASE TABLE'",
            (self.session_id, obj_type),
        ).fetchone()
        return row is not None

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
            raise InvalidObject("Firepit accepts STIX 2.1 only")
        if row[1]:
            raise InvalidObject(
                "embedded observed-data.objects is not supported; "
                "provide STIX 2.1 observed-data.object_refs"
            )
        if row[2]:
            raise InvalidObject("observed-data must provide object_refs")

    def _object_types(self, bundle_text: str):
        rows = self.connection.execute(
            "SELECT DISTINCT json_extract_string(value, '$.type') AS obj_type "
            "FROM json_each(?::JSON, '$.objects') "
            "WHERE json_extract_string(value, '$.type') IS NOT NULL",
            (bundle_text,),
        ).fetchall()
        return [row[0] for row in rows]

    def _object_count(self, bundle_text: str) -> int:
        return int(self.connection.execute(
            "SELECT COUNT(*) FROM json_each(?::JSON, '$.objects')",
            (bundle_text,),
        ).fetchone()[0])

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
                if obj_type == "observed-data" and name == "first_observed":
                    expr = (
                        'COALESCE(LEAST("observed-data".first_observed, '
                        'EXCLUDED.first_observed), "observed-data".first_observed, '
                        'EXCLUDED.first_observed)'
                    )
                elif obj_type == "observed-data" and name == "last_observed":
                    expr = (
                        'COALESCE(GREATEST("observed-data".last_observed, '
                        'EXCLUDED.last_observed), "observed-data".last_observed, '
                        'EXCLUDED.last_observed)'
                    )
                elif obj_type == "observed-data" and name == "number_observed":
                    expr = (
                        'COALESCE("observed-data".number_observed, 0) + '
                        'COALESCE(EXCLUDED.number_observed, 0)'
                    )
                else:
                    expr = (
                        f"COALESCE(EXCLUDED.{_qident(name)}, "
                        f"{_qident(obj_type)}.{_qident(name)})"
                    )
                updates.append(f"{_qident(name)} = {expr}")
            stmt += " ON CONFLICT (id) DO UPDATE SET " + ", ".join(updates)

        self.connection.execute(stmt, (bundle_text, obj_type))

        if query_id:
            self.connection.execute(
                'INSERT INTO "raw_run_object" (query_id, object_id) '
                "SELECT ?, json_extract_string(value, '$.id') "
                "FROM json_each(?::JSON, '$.objects') "
                "WHERE json_extract_string(value, '$.type') = ? "
                "AND json_extract_string(value, '$.id') IS NOT NULL",
                (str(query_id), bundle_text, obj_type),
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

        self.connection.execute("BEGIN")
        try:
            if qid:
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

    def lookup(self, viewname, cols="*", limit=None, offset=None, col_dict=None):
        del col_dict
        validate_name(viewname)
        if cols == "*":
            projection = "*"
        else:
            if isinstance(cols, str):
                cols = [item.strip() for item in cols.split(",")]
            projection = ", ".join(_qident(item) for item in cols)
        sql = f"SELECT {projection} FROM {_qident(viewname)}"
        if limit:
            sql += f" LIMIT {int(limit)}"
        if offset:
            sql += f" OFFSET {int(offset)}"
        rows = self._query(sql).fetchall()
        if cols == "*" and self._table_exists(viewname):
            for row in rows:
                row.setdefault("type", viewname)
        return rows

    def values(self, path, viewname):
        _, _, column = path.rpartition(":")
        rows = self._query(
            f"SELECT {_qident(column)} FROM {_qident(viewname)}"
        ).fetchall()
        return [row[column] for row in rows]

    def count(self, viewname):
        row = self._query(
            f"SELECT COUNT(*) AS count FROM {_qident(viewname)}"
        ).fetchone()
        return int(row["count"])

    def value_counts(self, viewname, path):
        _, _, column = path.rpartition(":")
        sql = (
            f"SELECT v.{_qident(column)} AS {_qident(path)}, COUNT(*) AS count "
            f"FROM {_qident(viewname)} v "
            f'JOIN "observed-data" o ON list_contains(o.object_refs, v.id) '
            f'GROUP BY v.{_qident(column)}'
        )
        return self._query(sql).fetchall()

    def number_observed(self, viewname, path, value=None):
        _, _, column = path.rpartition(":")
        sql = (
            f"SELECT SUM(o.number_observed) AS count FROM {_qident(viewname)} v "
            f'JOIN "observed-data" o ON list_contains(o.object_refs, v.id)'
        )
        params = []
        if value is not None:
            sql += f" WHERE v.{_qident(column)} = ?"
            params.append(value)
        row = self._query(sql, params).fetchone()
        return int(row["count"] or 0) if row else self.count(viewname)

    def summary(self, viewname, path=None, value=None):
        sql = (
            f"SELECT MIN(o.first_observed) AS first_observed, "
            f"MAX(o.last_observed) AS last_observed, "
            f"SUM(o.number_observed) AS number_observed "
            f"FROM {_qident(viewname)} v "
            f'JOIN "observed-data" o ON list_contains(o.object_refs, v.id)'
        )
        params = []
        if path and value is not None:
            _, _, column = path.rpartition(":")
            sql += f" WHERE v.{_qident(column)} = ?"
            params.append(value)
        row = self._query(sql, params).fetchone()
        if not row or row["number_observed"] is None:
            return {
                "first_observed": None,
                "last_observed": None,
                "number_observed": self.count(viewname),
            }
        row["number_observed"] = int(row["number_observed"])
        return row

    def timestamped(self, viewname, path=None, value=None,
                    timestamp="first_observed", limit=None):
        projection = [f"o.{_qident(timestamp)} AS {_qident(timestamp)}"]
        if path:
            paths = path if isinstance(path, (list, tuple)) else [path]
            for item in paths:
                _, _, column = item.rpartition(":")
                projection.append(f"v.{_qident(column)} AS {_qident(item)}")
        sql = (
            f"SELECT {', '.join(projection)} FROM {_qident(viewname)} v "
            f'JOIN "observed-data" o ON list_contains(o.object_refs, v.id)'
        )
        params = []
        if path and value is not None and not isinstance(path, (list, tuple)):
            _, _, column = path.rpartition(":")
            sql += f" WHERE v.{_qident(column)} = ?"
            params.append(value)
        sql += f" ORDER BY o.{_qident(timestamp)}"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return self._query(sql, params).fetchall()

    def tables(self):
        rows = self._query(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = ? AND table_type = 'BASE TABLE'",
            (self.session_id,),
        ).fetchall()
        return [row["table_name"] for row in rows if not row["table_name"].startswith("__")]

    def types(self, private=False):
        del private
        internal = {"raw_query", "raw_bundle", "raw_run_object"}
        return [name for name in self.tables() if name not in internal]

    def views(self):
        rows = self._query(
            "SELECT view_name FROM duckdb_views() WHERE schema_name = ?",
            (self.session_id,),
        ).fetchall()
        return [row["view_name"] for row in rows]

    def table_type(self, viewname):
        return viewname if self._table_exists(viewname) else None

    def columns(self, viewname):
        try:
            return [row["name"] for row in self._query(
                f"PRAGMA table_info({_qident(viewname)})"
            ).fetchall()]
        except UnknownViewname:
            return []

    def schema(self, viewname=None):
        if viewname:
            return [
                {"name": row["name"], "type": row["type"]}
                for row in self._query(
                    f"PRAGMA table_info({_qident(viewname)})"
                ).fetchall()
            ]
        result = []
        for table in self.tables():
            for row in self.schema(table):
                result.append({"table": table, **row})
        return result

    def provenance(self, query_id=None):
        if query_id is None:
            return self._query('SELECT * FROM "raw_query" ORDER BY started_at').fetchall()
        return self._query(
            'SELECT * FROM "raw_query" WHERE query_id = ?', (str(query_id),)
        ).fetchone()

    def delete(self):
        self.connection.execute(f"DROP SCHEMA IF EXISTS {_qident(self.session_id)} CASCADE")
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
