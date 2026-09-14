"""Private STIX 2.1 ingestion into Firepit's canonical DuckDB model."""

from __future__ import annotations

import io
import json
import os
import uuid
from collections.abc import Iterable
from typing import IO, Any, Mapping

import duckdb

from firepit._stix import (indicator_observable, validate_bundle,
                           validate_object)
from firepit.exceptions import InvalidObject
from firepit.validate import validate_name
from firepit.views_wide import VIEW_VERSION, install_views

_MODEL_VERSION = "9"
_INTERNAL_PREFIX = "__firepit_"
_OBJECT_STRUCTURE = '{"id":"VARCHAR","type":"VARCHAR","modified":"TIMESTAMPTZ"}'

SingleBundle = Mapping[str, Any] | str | os.PathLike | IO[str] | IO[bytes]
BundleCollection = Iterable[SingleBundle]


def _qident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _qname(schema: str, name: str) -> str:
    return f"{_qident(schema)}.{_qident(name)}"


def _bundle_dict(bundle: SingleBundle) -> dict:
    if isinstance(bundle, Mapping):
        return dict(bundle)
    if isinstance(bundle, io.IOBase):
        data = bundle.read()
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        return json.loads(data)
    if isinstance(bundle, os.PathLike):
        with open(bundle, encoding="utf-8") as handle:
            return json.load(handle)
    if isinstance(bundle, str):
        stripped = bundle.lstrip()
        if stripped.startswith(("{", "[")):
            return json.loads(bundle)
        with open(bundle, encoding="utf-8") as handle:
            return json.load(handle)
    raise TypeError(
        "bundle must be a dict, JSON string, file-like object, or path")


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


class _Writer:
    def __init__(self, dbname: str | os.PathLike, session_id: str | None = None) -> None:
        self.dbname = os.fspath(dbname)
        self.public_schema = session_id or "main"
        validate_name(self.public_schema)
        self.internal_schema = _INTERNAL_PREFIX + self.public_schema
        self.connection = duckdb.connect(self.dbname)
        self.connection.execute("SET python_enable_replacements=false")
        self.connection.execute("SET TimeZone='UTC'")
        self._prepare_model()

    def _table(self, name: str) -> str:
        return _qname(self.internal_schema, name)

    def close(self) -> None:
        self.connection.close()

    def _prepare_model(self) -> None:
        for schema in (self.public_schema, self.internal_schema):
            self.connection.execute(
                f"CREATE SCHEMA IF NOT EXISTS {_qident(schema)}")

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
        row = self.connection.execute(
            f"SELECT value FROM {metadata} WHERE name = 'model_version'"
        ).fetchone()
        version = row[0] if row else None
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
            install_views(self.connection, self.public_schema,
                          self.internal_schema)
            self.connection.execute(
                f"INSERT INTO {metadata} VALUES ('view_version', ?) "
                "ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value",
                (VIEW_VERSION,),
            )

    def _start_run(self, run_id: str, source: str | None, stix_pattern: str | None, native_query: str | None) -> None:
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

    def _finish_run(self, run_id: str, status: str, count: int = 0, error: str | None = None) -> None:
        self.connection.execute(
            f"UPDATE {self._table('runs')} SET completed_at = current_timestamp, "
            "status = ?, result_count = ?, error = ? WHERE run_id = ?",
            (status, count, error, run_id),
        )

    def _reject_batch_conflicts(self, pool_table: str) -> None:
        checks = (
            ("a.modified IS NULL AND b.modified IS NULL",
             "reused an immutable id with different content"),
            ("(a.modified IS NULL) != (b.modified IS NULL)",
             "changed versioning semantics"),
            ("a.modified = b.modified",
             "has conflicting content at the same modified timestamp"),
        )
        for condition, message in checks:
            row = self.connection.execute(
                f"SELECT a.id FROM {pool_table} a JOIN {pool_table} b "
                f"ON a.id = b.id AND a.data != b.data AND {condition} "
                "LIMIT 1"
            ).fetchone()
            if row is not None:
                raise InvalidObject(f"STIX object {row[0]!r} {message}")

    def _write_batch(self, objects: list[tuple[Any, Any, Any]], source: str | None) -> None:
        data = [o[0] for o in objects]
        observable_keys = [o[1] for o in objects]
        observable_values = [o[2] for o in objects]
        table = self._table("objects")

        self.connection.execute("DROP TABLE IF EXISTS staged")
        self.connection.execute(
            "CREATE TEMP TABLE staged AS "
            f"SELECT (json_transform(data::JSON, '{_OBJECT_STRUCTURE}')).id AS id, "
            f"(json_transform(data::JSON, '{_OBJECT_STRUCTURE}')).type AS stix_type, "
            f"(json_transform(data::JSON, '{_OBJECT_STRUCTURE}')).modified AS modified, "
            "ok::VARCHAR AS observable_key, ov::VARCHAR AS observable_value, data "
            "FROM (SELECT UNNEST(?) AS data, UNNEST(?) AS ok, UNNEST(?) AS ov)",
            (data, observable_keys, observable_values),
        )

        self.connection.execute("DROP TABLE IF EXISTS pool")
        self.connection.execute(
            "CREATE TEMP TABLE pool AS "
            f"SELECT id, (json_transform(data::JSON, '{_OBJECT_STRUCTURE}')).modified AS modified, data "
            f"FROM {table} WHERE id IN (SELECT id FROM staged) "
            "UNION ALL "
            "SELECT id, modified, data FROM staged"
        )
        self._reject_batch_conflicts("pool")

        self.connection.execute("DROP TABLE IF EXISTS candidates")
        self.connection.execute(
            "CREATE TEMP TABLE candidates AS "
            "SELECT id, stix_type, modified, observable_key, observable_value, data "
            "FROM staged "
            "QUALIFY ROW_NUMBER() OVER "
            "(PARTITION BY id ORDER BY modified DESC NULLS LAST) = 1"
        )

        self.connection.execute(
            f"INSERT INTO {table} "
            "(id, stix_type, last_ingested_at, source, "
            "observable_key, observable_value, data) "
            "SELECT id, stix_type, now(), ?, "
            "observable_key, observable_value, data FROM candidates "
            "ON CONFLICT (id) DO UPDATE SET "
            "last_ingested_at = now(), "
            "stix_type = CASE WHEN EXCLUDED.data != objects.data "
            "THEN EXCLUDED.stix_type ELSE objects.stix_type END, "
            "source = CASE WHEN EXCLUDED.data != objects.data "
            "THEN EXCLUDED.source ELSE objects.source END, "
            "observable_key = CASE WHEN EXCLUDED.data != objects.data "
            "THEN EXCLUDED.observable_key ELSE objects.observable_key END, "
            "observable_value = CASE WHEN EXCLUDED.data != objects.data "
            "THEN EXCLUDED.observable_value ELSE objects.observable_value END, "
            "data = CASE WHEN EXCLUDED.data != objects.data "
            "THEN EXCLUDED.data ELSE objects.data END "
            "WHERE EXCLUDED.data = objects.data OR "
            f"(json_transform(EXCLUDED.data::JSON, '{_OBJECT_STRUCTURE}')).modified > "
            f"(json_transform(objects.data::JSON, '{_OBJECT_STRUCTURE}')).modified",
            (source,),
        )

    def ingest(self, run_id: str, bundles: SingleBundle | Iterable[SingleBundle],
               source: str | None = None, stix_pattern: str | None = None, native_query: str | None = None) -> None:
        run_id = str(run_id)
        self._start_run(run_id, source, stix_pattern, native_query)

        bundle_iter: Iterable[SingleBundle]
        if isinstance(bundles, (str, os.PathLike, Mapping, io.IOBase)):
            bundle_iter = [bundles]  # type: ignore[list-item]
        else:
            try:
                bundle_iter = iter(bundles)  # type: ignore[assignment]
            except TypeError:
                bundle_iter = [bundles]  # type: ignore[list-item]

        count = 0
        self.connection.execute("BEGIN")
        try:
            validated = []
            for supplied in bundle_iter:
                bundle = _bundle_dict(supplied)
                objects = validate_bundle(bundle)
                self.connection.execute(
                    f"INSERT INTO {self._table('bundles')} "
                    "(bundle_id, run_id, received_at, bundle) "
                    "VALUES (?, ?, current_timestamp, json(?::JSON))",
                    (str(uuid.uuid4()), run_id, _json_text(bundle)),
                )
                for raw_obj in objects:
                    obj = validate_object(raw_obj)
                    observable_key, observable_value = indicator_observable(
                        obj)
                    validated.append(
                        (_json_text(obj), observable_key, observable_value))

            count = len(validated)
            if validated:
                self._write_batch(validated, source)

            self._finish_run(run_id, "COMPLETED", count)
            self.connection.execute("COMMIT")
        except Exception as exc:
            self.connection.execute("ROLLBACK")
            self._finish_run(run_id, "FAILED", error=str(exc))
            raise


def ingest(path: str | os.PathLike, run_id: str,
           bundles: SingleBundle | Iterable[SingleBundle],
           session_id: str | None = None, source: str | None = None,
           stix_pattern: str | None = None, native_query: str | None = None) -> None:
    """Private acquisition entry point used by STIX-Shifter orchestration."""

    writer = _Writer(path, session_id)
    try:
        writer.ingest(run_id, bundles, source, stix_pattern, native_query)
    finally:
        writer.close()
