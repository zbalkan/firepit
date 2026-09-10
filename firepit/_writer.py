"""Private STIX 2.1 ingestion into Firepit's canonical DuckDB model."""

from __future__ import annotations

import json
import os
import uuid

import duckdb

from firepit._stix import indicator_observable, validate_bundle, validate_object
from firepit.exceptions import InvalidObject
from firepit.validate import validate_name
from firepit.views_wide import VIEW_VERSION, install_views

_MODEL_VERSION = "9"
_INTERNAL_PREFIX = "__firepit_"
_OBJECT_STRUCTURE = '{"id":"VARCHAR","type":"VARCHAR","modified":"TIMESTAMPTZ"}'


def _qident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _qname(schema: str, name: str) -> str:
    return f"{_qident(schema)}.{_qident(name)}"


def _bundle_dict(bundle):
    if isinstance(bundle, dict):
        return bundle
    if hasattr(bundle, "read"):
        data = bundle.read()
        return json.loads(data.decode() if isinstance(data, bytes) else data)
    if isinstance(bundle, (str, os.PathLike)):
        value = os.fspath(bundle)
        if isinstance(value, str) and value.lstrip().startswith("{"):
            return json.loads(value)
        with open(value, encoding="utf-8") as handle:
            return json.load(handle)
    raise TypeError("bundle must be a dict, JSON string, file-like object, or path")


def _json_text(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


class _Writer:
    def __init__(self, dbname, session_id=None):
        self.dbname = os.fspath(dbname)
        self.public_schema = session_id or "main"
        validate_name(self.public_schema)
        self.internal_schema = _INTERNAL_PREFIX + self.public_schema
        self.connection = duckdb.connect(self.dbname)
        self.connection.execute("SET python_enable_replacements=false")
        self._prepare_model()

    def _table(self, name):
        return _qname(self.internal_schema, name)

    def close(self):
        self.connection.close()

    def _prepare_model(self):
        for schema in (self.public_schema, self.internal_schema):
            self.connection.execute(f"CREATE SCHEMA IF NOT EXISTS {_qident(schema)}")

        if self.connection.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = ? AND table_type = 'BASE TABLE' LIMIT 1",
            (self.public_schema,),
        ).fetchone():
            raise RuntimeError(
                "pre-v9 Firepit session is not supported; "
                "create a new database/session and re-ingest STIX 2.1 data"
            )

        metadata = self._table("metadata")
        self.connection.execute(
            f"CREATE TABLE IF NOT EXISTS {metadata} "
            "(name VARCHAR PRIMARY KEY, value VARCHAR)"
        )
        self.connection.execute(
            f"INSERT INTO {metadata} VALUES ('model_version', ?) ON CONFLICT DO NOTHING",
            (_MODEL_VERSION,),
        )
        version = self.connection.execute(
            f"SELECT value FROM {metadata} WHERE name = 'model_version'"
        ).fetchone()[0]
        if version != _MODEL_VERSION:
            raise RuntimeError(
                f"unsupported internal model version {version}; create a new database/session"
            )

        tables = {
            "runs": """
                run_id VARCHAR PRIMARY KEY,
                source VARCHAR,
                stix_pattern VARCHAR,
                native_query VARCHAR,
                started_at TIMESTAMPTZ NOT NULL,
                completed_at TIMESTAMPTZ,
                status VARCHAR NOT NULL,
                result_count UBIGINT NOT NULL,
                error VARCHAR
            """,
            "bundles": """
                bundle_id UUID PRIMARY KEY,
                run_id VARCHAR NOT NULL,
                received_at TIMESTAMPTZ NOT NULL,
                bundle JSON NOT NULL
            """,
            "objects": """
                id VARCHAR PRIMARY KEY,
                stix_type VARCHAR NOT NULL,
                last_ingested_at TIMESTAMPTZ NOT NULL,
                source VARCHAR,
                observable_key VARCHAR,
                observable_value VARCHAR,
                data JSON NOT NULL
            """,
        }
        for name, columns in tables.items():
            self.connection.execute(
                f"CREATE TABLE IF NOT EXISTS {self._table(name)} ({columns})"
            )

        row = self.connection.execute(
            f"SELECT value FROM {metadata} WHERE name = 'view_version'"
        ).fetchone()
        if row is None or row[0] != VIEW_VERSION:
            install_views(self.connection, self.public_schema, self.internal_schema)
            self.connection.execute(
                f"INSERT INTO {metadata} VALUES ('view_version', ?) "
                "ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value",
                (VIEW_VERSION,),
            )

    def _start_run(self, run_id, source, stix_pattern, native_query):
        try:
            self.connection.execute(
                f"INSERT INTO {self._table('runs')} "
                "(run_id, source, stix_pattern, native_query, started_at, status, result_count) "
                "VALUES (?, ?, ?, ?, current_timestamp, 'RUNNING', 0)",
                (run_id, source, stix_pattern, native_query),
            )
        except duckdb.ConstraintException as exc:
            raise InvalidObject(
                f"run_id {run_id!r} already exists; use a new acquisition run id"
            ) from exc

    def _finish_run(self, run_id, status, count=0, error=None):
        self.connection.execute(
            f"UPDATE {self._table('runs')} SET completed_at = current_timestamp, "
            "status = ?, result_count = ?, error = ? WHERE run_id = ?",
            (status, count, error, run_id),
        )

    def _normalize_object(self, obj):
        data = _json_text(obj)
        stix = self.connection.execute(
            f"SELECT json_transform_strict(?::JSON, '{_OBJECT_STRUCTURE}')",
            (data,),
        ).fetchone()[0]
        observable_key, observable_value = indicator_observable(obj)
        return (
            stix["id"], stix["type"], stix["modified"],
            observable_key, observable_value, data,
        )

    def _existing_object(self, object_id):
        return self.connection.execute(
            f"SELECT data::VARCHAR, "
            f"(json_transform_strict(data, '{_OBJECT_STRUCTURE}')).modified "
            f"FROM {self._table('objects')} WHERE id = ?",
            (object_id,),
        ).fetchone()

    @staticmethod
    def _canonical_action(existing, data, modified, object_id):
        if existing is None:
            return "insert"
        if existing[0] == data:
            return "same"

        old_modified = existing[1]
        if old_modified is None and modified is None:
            raise InvalidObject(
                f"STIX object {object_id!r} reused an immutable id with different content"
            )
        if old_modified is None or modified is None:
            raise InvalidObject(
                f"STIX object {object_id!r} changed versioning semantics"
            )
        if modified < old_modified:
            return "older"
        if modified == old_modified:
            raise InvalidObject(
                f"STIX object {object_id!r} has conflicting content at the same modified timestamp"
            )
        return "update"

    def _write_object(self, obj, source):
        object_id, stix_type, modified, observable_key, observable_value, data = (
            self._normalize_object(obj)
        )
        action = self._canonical_action(
            self._existing_object(object_id), data, modified, object_id
        )
        table = self._table("objects")

        if action == "insert":
            self.connection.execute(
                f"INSERT INTO {table} "
                "(id, stix_type, last_ingested_at, source, "
                "observable_key, observable_value, data) "
                "VALUES (?, ?, current_timestamp, ?, ?, ?, ?::JSON)",
                (object_id, stix_type, source, observable_key, observable_value, data),
            )
        elif action == "update":
            self.connection.execute(
                f"UPDATE {table} SET stix_type = ?, last_ingested_at = current_timestamp, "
                "source = ?, observable_key = ?, observable_value = ?, data = ?::JSON "
                "WHERE id = ?",
                (
                    stix_type, source, observable_key, observable_value,
                    data, object_id,
                ),
            )
        elif action == "same":
            self.connection.execute(
                f"UPDATE {table} SET last_ingested_at = current_timestamp WHERE id = ?",
                (object_id,),
            )

    def ingest(self, run_id, bundles, source=None, stix_pattern=None, native_query=None):
        run_id = str(run_id)
        self._start_run(run_id, source, stix_pattern, native_query)
        bundles = bundles if isinstance(bundles, list) else [bundles]

        count = 0
        self.connection.execute("BEGIN")
        try:
            for supplied in bundles:
                bundle = _bundle_dict(supplied)
                objects = validate_bundle(bundle)
                self.connection.execute(
                    f"INSERT INTO {self._table('bundles')} "
                    "(bundle_id, run_id, received_at, bundle) "
                    "VALUES (?, ?, current_timestamp, json(?::JSON))",
                    (str(uuid.uuid4()), run_id, _json_text(bundle)),
                )
                for raw_obj in objects:
                    self._write_object(validate_object(raw_obj), source)
                    count += 1

            self._finish_run(run_id, "COMPLETED", count)
            self.connection.execute("COMMIT")
        except Exception as exc:
            self.connection.execute("ROLLBACK")
            self._finish_run(run_id, "FAILED", error=str(exc))
            raise


def ingest(path, run_id, bundles, session_id=None, source=None,
           stix_pattern=None, native_query=None):
    """Private acquisition entry point used by STIX-Shifter orchestration."""
    writer = _Writer(path, session_id)
    try:
        writer.ingest(run_id, bundles, source, stix_pattern, native_query)
    finally:
        writer.close()
