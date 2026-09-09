"""Private STIX ingestion writer.

This module is not part of the public query API. It owns the physical DuckDB
schemas and tables used to materialize the two public analyst views.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime

import duckdb

from firepit._stix import validate_bundle, validate_object
from firepit.exceptions import InvalidObject
from firepit.validate import validate_name
from firepit.views import install_views

_MODEL_VERSION = "7"
_INTERNAL_PREFIX = "__firepit_"


def _qident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _qname(schema: str, name: str) -> str:
    return f"{_qident(schema)}.{_qident(name)}"


def _bundle_dict(bundle):
    if isinstance(bundle, dict):
        return bundle
    if hasattr(bundle, "read"):
        data = bundle.read()
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        return json.loads(data)
    if isinstance(bundle, (str, os.PathLike)):
        value = os.fspath(bundle)
        if isinstance(value, str) and value.lstrip().startswith("{"):
            return json.loads(value)
        with open(value, "r", encoding="utf-8") as handle:
            return json.load(handle)
    raise TypeError("bundle must be a dict, JSON string, file-like object, or path")


def _json_text(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _json_object(value):
    if isinstance(value, str):
        return json.loads(value)
    return value


def _timestamp_text(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


class _Writer:
    def __init__(self, dbname, session_id=None):
        self.dbname = os.fspath(dbname)
        self.public_schema = session_id or "main"
        validate_name(self.public_schema)
        self.internal_schema = _INTERNAL_PREFIX + self.public_schema
        self.connection = duckdb.connect(self.dbname)
        self.connection.execute("SET python_enable_replacements=false")
        self._prepare_model()

    def close(self):
        self.connection.close()

    def _prepare_model(self):
        self.connection.execute(
            f"CREATE SCHEMA IF NOT EXISTS {_qident(self.public_schema)}"
        )
        self.connection.execute(
            f"CREATE SCHEMA IF NOT EXISTS {_qident(self.internal_schema)}"
        )

        public_tables = self.connection.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = ? AND table_type = 'BASE TABLE'",
            (self.public_schema,),
        ).fetchall()
        if public_tables:
            raise RuntimeError(
                "pre-v7 Firepit session is not supported; "
                "create a new database/session and re-ingest STIX 2.1 data"
            )

        metadata = _qname(self.internal_schema, "metadata")
        self.connection.execute(
            f"CREATE TABLE IF NOT EXISTS {metadata} "
            "(name VARCHAR PRIMARY KEY, value VARCHAR)"
        )
        row = self.connection.execute(
            f"SELECT value FROM {metadata} WHERE name = 'model_version'"
        ).fetchone()
        if row is None:
            self.connection.execute(
                f"INSERT INTO {metadata} VALUES ('model_version', ?)",
                (_MODEL_VERSION,),
            )
        elif row[0] != _MODEL_VERSION:
            raise RuntimeError(
                f"unsupported internal model version {row[0]}; "
                "create a new database/session"
            )

        self.connection.execute(
            f"CREATE TABLE IF NOT EXISTS {_qname(self.internal_schema, 'runs')} ("
            "query_id VARCHAR PRIMARY KEY, "
            "source VARCHAR, "
            "stix_pattern VARCHAR, "
            "native_query VARCHAR, "
            "started_at TIMESTAMPTZ NOT NULL, "
            "completed_at TIMESTAMPTZ, "
            "status VARCHAR NOT NULL, "
            "result_count UBIGINT NOT NULL, "
            "error VARCHAR)"
        )
        self.connection.execute(
            f"CREATE TABLE IF NOT EXISTS {_qname(self.internal_schema, 'bundles')} ("
            "bundle_id UUID PRIMARY KEY, "
            "query_id VARCHAR NOT NULL, "
            "received_at TIMESTAMPTZ NOT NULL, "
            "bundle JSON NOT NULL)"
        )
        self.connection.execute(
            f"CREATE TABLE IF NOT EXISTS {_qname(self.internal_schema, 'objects')} ("
            "id VARCHAR PRIMARY KEY, "
            "stix_type VARCHAR NOT NULL, "
            "spec_version VARCHAR, "
            "created TIMESTAMPTZ, "
            "modified TIMESTAMPTZ, "
            "revoked BOOLEAN, "
            "confidence INTEGER, "
            "labels VARCHAR[], "
            "valid_from TIMESTAMPTZ, "
            "valid_until TIMESTAMPTZ, "
            "pattern VARCHAR, "
            "pattern_type VARCHAR, "
            "pattern_version VARCHAR, "
            "first_ingested_at TIMESTAMPTZ NOT NULL, "
            "last_ingested_at TIMESTAMPTZ NOT NULL, "
            "source VARCHAR, "
            "last_query_id VARCHAR NOT NULL, "
            "data JSON NOT NULL)"
        )
        self.connection.execute(
            f"CREATE TABLE IF NOT EXISTS {_qname(self.internal_schema, 'run_objects')} ("
            "query_id VARCHAR NOT NULL, "
            "object_id VARCHAR NOT NULL, "
            "UNIQUE(query_id, object_id))"
        )
        install_views(self.connection, self.public_schema, self.internal_schema)

    def _start_run(self, query_id, source, stix_pattern, native_query):
        try:
            self.connection.execute(
                f"INSERT INTO {_qname(self.internal_schema, 'runs')} "
                "(query_id, source, stix_pattern, native_query, started_at, "
                "status, result_count) "
                "VALUES (?, ?, ?, ?, current_timestamp, 'RUNNING', 0)",
                (query_id, source, stix_pattern, native_query),
            )
        except duckdb.ConstraintException as exc:
            raise InvalidObject(
                f"query_id {query_id!r} already exists; use a new acquisition run id"
            ) from exc

    def _finish_run(self, query_id, status, *, count=0, error=None):
        self.connection.execute(
            f"UPDATE {_qname(self.internal_schema, 'runs')} "
            "SET completed_at = current_timestamp, status = ?, "
            "result_count = ?, error = ? WHERE query_id = ?",
            (status, count, error, query_id),
        )

    def _existing_object(self, object_id):
        return self.connection.execute(
            f"SELECT data, modified FROM {_qname(self.internal_schema, 'objects')} "
            "WHERE id = ?",
            (object_id,),
        ).fetchone()

    @staticmethod
    def _canonical_action(existing, obj):
        if existing is None:
            return "insert"

        old_data = _json_object(existing[0])
        new_text = _json_text(obj)
        old_text = _json_text(old_data)
        if old_text == new_text:
            return "same"

        old_modified = existing[1]
        new_modified = obj.get("modified")

        if old_modified is None and new_modified is None:
            raise InvalidObject(
                f"STIX object {obj['id']!r} reused an immutable id with different content"
            )
        if old_modified is None or new_modified is None:
            raise InvalidObject(
                f"STIX object {obj['id']!r} changed versioning semantics"
            )

        try:
            new_dt = datetime.fromisoformat(
                str(new_modified).replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise InvalidObject(
                f"invalid modified timestamp for {obj['id']!r}"
            ) from exc

        if new_dt < old_modified:
            return "older"
        if new_dt == old_modified:
            raise InvalidObject(
                f"STIX object {obj['id']!r} has conflicting content at the same "
                "modified timestamp"
            )
        return "update"

    def _write_object(self, obj, query_id, source):
        action = self._canonical_action(self._existing_object(obj["id"]), obj)
        data = _json_text(obj)
        table = _qname(self.internal_schema, "objects")

        values = (
            obj["id"],
            obj["type"],
            obj.get("spec_version"),
            _timestamp_text(obj.get("created")),
            _timestamp_text(obj.get("modified")),
            obj.get("revoked"),
            obj.get("confidence"),
            obj.get("labels"),
            _timestamp_text(obj.get("valid_from")),
            _timestamp_text(obj.get("valid_until")),
            obj.get("pattern"),
            obj.get("pattern_type"),
            obj.get("pattern_version"),
            source,
            query_id,
            data,
        )

        if action == "insert":
            self.connection.execute(
                f"INSERT INTO {table} "
                "(id, stix_type, spec_version, created, modified, revoked, confidence, "
                "labels, valid_from, valid_until, pattern, pattern_type, pattern_version, "
                "first_ingested_at, last_ingested_at, source, last_query_id, data) "
                "VALUES (?, ?, ?, ?::TIMESTAMPTZ, ?::TIMESTAMPTZ, ?, ?, ?, "
                "?::TIMESTAMPTZ, ?::TIMESTAMPTZ, ?, ?, ?, current_timestamp, "
                "current_timestamp, ?, ?, ?::JSON)",
                values,
            )
        elif action == "update":
            self.connection.execute(
                f"UPDATE {table} SET "
                "stix_type = ?, spec_version = ?, created = ?::TIMESTAMPTZ, "
                "modified = ?::TIMESTAMPTZ, revoked = ?, confidence = ?, labels = ?, "
                "valid_from = ?::TIMESTAMPTZ, valid_until = ?::TIMESTAMPTZ, "
                "pattern = ?, pattern_type = ?, pattern_version = ?, "
                "last_ingested_at = current_timestamp, source = ?, last_query_id = ?, "
                "data = ?::JSON WHERE id = ?",
                (
                    obj["type"], obj.get("spec_version"),
                    _timestamp_text(obj.get("created")),
                    _timestamp_text(obj.get("modified")),
                    obj.get("revoked"), obj.get("confidence"), obj.get("labels"),
                    _timestamp_text(obj.get("valid_from")),
                    _timestamp_text(obj.get("valid_until")),
                    obj.get("pattern"), obj.get("pattern_type"),
                    obj.get("pattern_version"), source, query_id, data, obj["id"],
                ),
            )
        elif action == "same":
            self.connection.execute(
                f"UPDATE {table} SET last_ingested_at = current_timestamp, "
                "source = ?, last_query_id = ? WHERE id = ?",
                (source, query_id, obj["id"]),
            )
        elif action != "older":
            raise AssertionError(f"unexpected canonical action: {action}")

        self.connection.execute(
            f"INSERT INTO {_qname(self.internal_schema, 'run_objects')} "
            "(query_id, object_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
            (query_id, obj["id"]),
        )

    def ingest(self, query_id, bundles, source=None, stix_pattern=None, native_query=None):
        query_id = str(query_id)
        self._start_run(query_id, source, stix_pattern, native_query)

        if not isinstance(bundles, list):
            bundles = [bundles]

        count = 0
        self.connection.execute("BEGIN")
        try:
            for supplied in bundles:
                bundle = _bundle_dict(supplied)
                objects = validate_bundle(bundle)
                self.connection.execute(
                    f"INSERT INTO {_qname(self.internal_schema, 'bundles')} "
                    "(bundle_id, query_id, received_at, bundle) "
                    "VALUES (?, ?, current_timestamp, ?::JSON)",
                    (str(uuid.uuid4()), query_id, _json_text(bundle)),
                )
                for raw_obj in objects:
                    obj = validate_object(raw_obj)
                    self._write_object(obj, query_id, source)
                    count += 1

            install_views(self.connection, self.public_schema, self.internal_schema)
            self._finish_run(query_id, "COMPLETED", count=count)
            self.connection.execute("COMMIT")
        except Exception as exc:
            self.connection.execute("ROLLBACK")
            self._finish_run(query_id, "FAILED", error=str(exc))
            raise


def ingest(path, query_id, bundles, session_id=None, source=None,
           stix_pattern=None, native_query=None):
    """Private acquisition entry point used by STIX-Shifter orchestration."""
    writer = _Writer(path, session_id)
    try:
        writer.ingest(
            query_id,
            bundles,
            source=source,
            stix_pattern=stix_pattern,
            native_query=native_query,
        )
    finally:
        writer.close()
