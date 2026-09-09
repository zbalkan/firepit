"""DuckDB-native STIX storage.

The native store is authoritative. Known STIX 2.1 fields are stored with
DuckDB scalar/LIST/MAP/STRUCT types; unknown/custom content remains in `_raw`
JSON. Compatibility metadata is retained temporarily for the remaining legacy
API and is removed by later modernization phases.
"""

from __future__ import annotations

from collections import defaultdict
import json
import logging
import os
import re
import uuid

import duckdb

from firepit import raft
from firepit.exceptions import InvalidAttr, InvalidObject, UnknownViewname
from firepit.stix20 import stix2sql
from firepit.stix21 import makeid
from firepit.stixschema import ListType, MapType, StructType
from firepit.stixschema import rendered_schema, schema_for
from firepit.validate import validate_name

logger = logging.getLogger(__name__)

_NATIVE_META = "duckdb_native_model"
_NATIVE_VERSION = "2"
_NESTED_PREFIXES = ("MAP(", "STRUCT(")


def _qident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _is_nested(dtype: str) -> bool:
    return dtype.endswith("[]") or dtype.startswith(_NESTED_PREFIXES)


def _placeholder(dtype: str) -> str:
    if dtype == "JSON":
        return "?::JSON"
    if _is_nested(dtype):
        return f"CAST(?::JSON AS {dtype})"
    return "?"


def _bind_value(value, dtype: str):
    if value is None:
        return None
    if dtype == "JSON" or _is_nested(dtype):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return value


def _project_value(type_spec, value):
    if value is None:
        return None
    if isinstance(type_spec, StructType):
        if not isinstance(value, dict):
            return value
        return {
            name: _project_value(field_type, value.get(name))
            for name, field_type in type_spec.fields.items()
        }
    if isinstance(type_spec, ListType):
        values = value if isinstance(value, list) else [value]
        return [_project_value(type_spec.element, item) for item in values]
    if isinstance(type_spec, MapType):
        if not isinstance(value, dict):
            return value
        return {
            str(key): _project_value(type_spec.value, item)
            for key, item in value.items()
        }
    return value


class Result:
    """Small dict-row result wrapper used by the compatibility API."""

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


class NativeDuckDBStorage:
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
        self.connection.execute(
            f"SET search_path='{self.session_id}'"
        )
        self._prepare_native_model()

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
            'CREATE TABLE IF NOT EXISTS "__symtable" '
            '(name VARCHAR PRIMARY KEY, type VARCHAR, appdata VARCHAR)'
        )
        self.connection.execute(
            'CREATE TABLE IF NOT EXISTS "__queries" '
            '(sco_id VARCHAR, query_id VARCHAR)'
        )
        self.connection.execute(
            'CREATE TABLE IF NOT EXISTS "__contains" '
            '(source_ref VARCHAR, target_ref VARCHAR, x_firepit_rank INTEGER)'
        )
        self.connection.execute(
            'CREATE TABLE IF NOT EXISTS "__reflist" '
            '(ref_name VARCHAR, source_ref VARCHAR, target_ref VARCHAR)'
        )
        self.connection.execute(
            'CREATE TABLE IF NOT EXISTS "__columns" '
            '(otype VARCHAR, path VARCHAR, shortname VARCHAR, dtype VARCHAR, '
            ' UNIQUE(otype, path))'
        )
        if not row:
            self.connection.execute(
                'INSERT INTO "__metadata" (name, value) VALUES (?, ?)',
                (_NATIVE_META, _NATIVE_VERSION),
            )

        # Create the two SDO tables that Firepit historically guaranteed.
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
        for name, dtype in schema.items():
            self.connection.execute(
                'INSERT INTO "__columns" (otype, path, shortname, dtype) '
                'VALUES (?, ?, ?, ?) ON CONFLICT (otype, path) DO NOTHING',
                (obj_type, name, name, dtype),
            )

    @staticmethod
    def _normalize_objects(bundle):
        for obj in raft.get_objects(bundle):
            if not obj.get("type") and obj.get("id"):
                obj["type"] = str(obj["id"]).partition("--")[0]
            if obj.get("type") == "observed-data" and "objects" in obj:
                yield from raft.upgrade_2021(obj)
            else:
                yield obj

    @staticmethod
    def _project(obj):
        type_schema = schema_for(obj["type"])
        row = {
            name: _project_value(type_spec, obj.get(name))
            for name, type_spec in type_schema.items()
        }
        row["_raw"] = obj
        return row

    @staticmethod
    def _compat_edges(obj):
        obj_type = obj.get("type")
        oid = str(obj.get("id", ""))
        contains = []
        reflists = []
        if obj_type == "observed-data":
            for ref in obj.get("object_refs", ()):
                contains.append((oid, str(ref), None))
        else:
            for name, refs in obj.items():
                if not name.endswith("_refs"):
                    continue
                if not isinstance(refs, list):
                    refs = [refs]
                for ref in refs:
                    ref = str(ref)
                    if ref and ref != oid:
                        reflists.append((name, oid, ref))
        return contains, reflists

    def _insert_rows(self, obj_type, rows, query_id):
        if not rows:
            return
        self._create_native_table(obj_type)
        schema = rendered_schema(obj_type)
        columns = list(schema) + ["_raw"]
        dtypes = [schema[name] for name in schema] + ["JSON"]
        col_sql = ", ".join(_qident(name) for name in columns)
        row_sql = "(" + ", ".join(_placeholder(dtype) for dtype in dtypes) + ")"
        stmt = (
            f"INSERT INTO {_qident(obj_type)} ({col_sql}) VALUES "
            + ", ".join([row_sql] * len(rows))
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

        values = []
        qrows = []
        for row in rows:
            for name, dtype in zip(columns, dtypes):
                values.append(_bind_value(row.get(name), dtype))
            if query_id and row.get("id"):
                qrows.append((row["id"], str(query_id)))
        self.connection.execute(stmt, values)
        if qrows:
            self.connection.executemany(
                'INSERT INTO "__queries" (sco_id, query_id) VALUES (?, ?)', qrows
            )

    def cache(self, query_id, bundles, batchsize=2000, **_kwargs):
        """Ingest STIX using the explicit DuckDB-native schema.

        The active path never flattens nested STIX properties and never mutates
        table schemas in response to an unknown property.
        """
        if not isinstance(bundles, list):
            bundles = [bundles]
        pending = defaultdict(list)
        contains = []
        reflists = []
        self.connection.execute("BEGIN")
        try:
            for bundle in bundles:
                for obj in self._normalize_objects(bundle):
                    obj_type = obj.get("type")
                    if not obj_type:
                        continue
                    if "id" in obj:
                        obj["id"] = str(obj["id"])
                    cedges, redges = self._compat_edges(obj)
                    contains.extend(cedges)
                    reflists.extend(redges)
                    pending[obj_type].append(self._project(obj))
                    if len(pending[obj_type]) >= batchsize:
                        self._insert_rows(obj_type, pending[obj_type], query_id)
                        pending[obj_type].clear()
            for obj_type, rows in pending.items():
                self._insert_rows(obj_type, rows, query_id)
            if contains:
                self.connection.executemany(
                    'INSERT INTO "__contains" VALUES (?, ?, ?)', contains
                )
            if reflists:
                self.connection.executemany(
                    'INSERT INTO "__reflist" VALUES (?, ?, ?)', reflists
                )
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def load(self, viewname, objects, sco_type=None, query_id=None, preserve_ids=True):
        if not objects:
            return sco_type
        query_id = query_id or str(uuid.uuid4())
        normalized = []
        for obj in objects:
            if isinstance(obj, str):
                if not sco_type:
                    raise InvalidObject("sco_type is required for scalar input")
                obj = {"type": sco_type, "value": obj}
            if not isinstance(obj, dict):
                raise InvalidObject("unknown data format")
            obj = dict(obj)
            obj_type = obj.get("type") or sco_type
            if not obj_type:
                raise InvalidObject("missing `type`")
            obj["type"] = obj_type
            if not obj.get("id") or not preserve_ids:
                obj["id"] = makeid(obj)
            normalized.append(obj)
            sco_type = sco_type or obj_type
        self.cache(query_id, {"type": "bundle", "objects": normalized})
        self.extract(viewname, sco_type, query_id, "")
        return sco_type

    def reassign(self, viewname, objects):
        if not objects:
            return
        for obj in objects:
            if not isinstance(obj, dict) or not obj.get("id") or not obj.get("type"):
                raise InvalidObject("reassign requires typed STIX objects with IDs")
        self.cache(None, {"type": "bundle", "objects": objects})

    def _create_view(self, viewname, select, sco_type=None):
        validate_name(viewname)
        self.connection.execute(f"DROP VIEW IF EXISTS {_qident(viewname)}")
        self.connection.execute(f"CREATE VIEW {_qident(viewname)} AS {select}")
        self.connection.execute(
            'INSERT INTO "__symtable" (name, type) VALUES (?, ?) '
            'ON CONFLICT (name) DO UPDATE SET type = EXCLUDED.type',
            (viewname, sco_type),
        )

    def extract(self, viewname, sco_type, query_id, pattern):
        validate_name(viewname)
        validate_name(sco_type)
        where = stix2sql(pattern, sco_type) if pattern else None
        clauses = [
            f'{_qident(sco_type)}.id IN ('
            f'SELECT sco_id FROM "__queries" WHERE query_id = ?)'
        ]
        if where:
            clauses.append(where)
        sql = f"SELECT * FROM {_qident(sco_type)} WHERE " + " AND ".join(clauses)
        # View definitions cannot contain parameters.
        escaped = str(query_id).replace("'", "''")
        sql = sql.replace("?", f"'{escaped}'", 1)
        self._create_view(viewname, sql, sco_type)

    def filter(self, viewname, sco_type, input_view, pattern):
        where = stix2sql(pattern, sco_type) if pattern else None
        sql = f"SELECT * FROM {_qident(input_view)}"
        if where:
            sql += f" WHERE {where}"
        self._create_view(viewname, sql, sco_type)

    def assign(self, viewname, on, op=None, by=None, ascending=True, limit=None):
        sql = f"SELECT * FROM {_qident(on)}"
        if op == "sort" and by:
            _, _, column = by.rpartition(":")
            sql += f" ORDER BY {_qident(column)} {'ASC' if ascending else 'DESC'}"
            if limit:
                sql += f" LIMIT {int(limit)}"
        elif op == "group" and by:
            _, _, column = by.rpartition(":")
            sql = (
                f"SELECT {_qident(column)}, COUNT(*) AS count "
                f"FROM {_qident(on)} GROUP BY {_qident(column)}"
            )
        self._create_view(viewname, sql, self.table_type(on) or on)

    def join(self, viewname, l_var, l_on, r_var, r_on):
        _, _, lcol = l_on.rpartition(":")
        _, _, rcol = r_on.rpartition(":")
        sql = (
            f"SELECT * FROM {_qident(l_var)} l JOIN {_qident(r_var)} r "
            f"ON l.{_qident(lcol)} = r.{_qident(rcol)}"
        )
        self._create_view(viewname, sql, self.table_type(l_var) or l_var)

    def merge(self, viewname, input_views):
        if not input_views:
            raise ValueError("input_views must not be empty")
        sql = " UNION BY NAME ".join(
            f"SELECT * FROM {_qident(name)}" for name in input_views
        )
        self._create_view(viewname, sql, self.table_type(input_views[0]))

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
        obj_type = self.table_type(viewname) or viewname
        if cols == "*" or "type" in cols:
            for row in rows:
                row.setdefault("type", obj_type)
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
            f'JOIN "__contains" c ON v.id = c.target_ref '
            f'GROUP BY v.{_qident(column)}'
        )
        return self._query(sql).fetchall()

    def number_observed(self, viewname, path, value=None):
        _, _, column = path.rpartition(":")
        sql = (
            f"SELECT SUM(o.number_observed) AS count FROM {_qident(viewname)} v "
            f'JOIN "__contains" c ON v.id = c.target_ref '
            f'JOIN "observed-data" o ON c.source_ref = o.id'
        )
        values = []
        if value is not None:
            sql += f" WHERE v.{_qident(column)} = ?"
            values.append(value)
        row = self._query(sql, values).fetchone()
        return int(row["count"] or 0) if row else self.count(viewname)

    def summary(self, viewname, path=None, value=None):
        sql = (
            f"SELECT MIN(o.first_observed) AS first_observed, "
            f"MAX(o.last_observed) AS last_observed, "
            f"SUM(o.number_observed) AS number_observed "
            f"FROM {_qident(viewname)} v "
            f'JOIN "__contains" c ON v.id = c.target_ref '
            f'JOIN "observed-data" o ON c.source_ref = o.id'
        )
        values = []
        if path and value is not None:
            _, _, column = path.rpartition(":")
            sql += f" WHERE v.{_qident(column)} = ?"
            values.append(value)
        row = self._query(sql, values).fetchone()
        if not row or row["number_observed"] is None:
            return {
                "first_observed": None,
                "last_observed": None,
                "number_observed": self.count(viewname),
            }
        row["number_observed"] = int(row["number_observed"])
        return row

    def timestamped(self, viewname, path=None, value=None,
                    timestamp="first_observed", limit=None, run=True):
        if not run:
            raise NotImplementedError("query-object output is being retired")
        projection = [f"o.{_qident(timestamp)} AS {_qident(timestamp)}"]
        if path:
            paths = path if isinstance(path, (list, tuple)) else [path]
            for item in paths:
                _, _, column = item.rpartition(":")
                projection.append(f"v.{_qident(column)} AS {_qident(item)}")
        sql = (
            f"SELECT {', '.join(projection)} FROM {_qident(viewname)} v "
            f'JOIN "__contains" c ON v.id = c.target_ref '
            f'JOIN "observed-data" o ON c.source_ref = o.id'
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
        return [r["table_name"] for r in rows if not r["table_name"].startswith("__")]

    def types(self, private=False):
        rows = self.tables()
        return rows if private else [name for name in rows if not name.startswith("__")]

    def views(self):
        rows = self._query(
            "SELECT view_name FROM duckdb_views() WHERE schema_name = ?",
            (self.session_id,),
        ).fetchall()
        return [row["view_name"] for row in rows]

    def table_type(self, viewname):
        if self._table_exists(viewname):
            return viewname
        row = self._query(
            'SELECT type FROM "__symtable" WHERE name = ?', (viewname,)
        ).fetchone()
        return row["type"] if row else None

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

    def set_appdata(self, viewname, data):
        self.connection.execute(
            'UPDATE "__symtable" SET appdata = ? WHERE name = ?',
            (data, viewname),
        )

    def get_appdata(self, viewname):
        row = self.connection.execute(
            'SELECT appdata FROM "__symtable" WHERE name = ?', (viewname,)
        ).fetchone()
        return row[0] if row else None

    def get_view_data(self, viewnames=None):
        if viewnames:
            placeholders = ", ".join(["?"] * len(viewnames))
            return self._query(
                f'SELECT * FROM "__symtable" WHERE name IN ({placeholders})',
                tuple(viewnames),
            ).fetchall()
        return self._query('SELECT * FROM "__symtable"').fetchall()

    def remove_view(self, viewname):
        self.connection.execute(f"DROP VIEW IF EXISTS {_qident(viewname)}")
        self.connection.execute('DELETE FROM "__symtable" WHERE name = ?', (viewname,))

    def rename_view(self, oldname, newname):
        view_type = self.table_type(oldname)
        sql = self.connection.execute(
            "SELECT sql FROM duckdb_views() WHERE schema_name = ? AND view_name = ?",
            (self.session_id, oldname),
        ).fetchone()
        if not sql:
            raise UnknownViewname(oldname)
        definition = re.sub(r"^CREATE VIEW\s+\S+\s+AS\s+", "", sql[0], count=1).rstrip(";")
        self._create_view(newname, definition, view_type)
        self.remove_view(oldname)

    def delete(self):
        self.connection.execute(f"DROP SCHEMA IF EXISTS {_qident(self.session_id)} CASCADE")
        self.connection.close()


def get_native_storage(path, session_id=None):
    return NativeDuckDBStorage(path, session_id)


def get_storage(path, session_id=None):
    return NativeDuckDBStorage(path, session_id)


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
