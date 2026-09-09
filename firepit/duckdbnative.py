"""Experimental DuckDB-native STIX storage.

This is an additive path used to prove the native representation before the
legacy SplitWriter/flattening pipeline is replaced.  It preserves the public
SqlStorage query surface by deriving Firepit's compatibility relationship
tables, but stores known STIX properties using DuckDB scalar, LIST, MAP and
STRUCT types.  The complete normalized STIX object is retained in ``_raw`` as
the explicit JSON provenance/fallback column.
"""

from collections import defaultdict

import ujson

from firepit import raft
from firepit.duckdbstorage import DuckDBStorage
from firepit.stixschema import ListType
from firepit.stixschema import MapType
from firepit.stixschema import StructType
from firepit.stixschema import rendered_schema
from firepit.stixschema import schema_for
from firepit.validate import validate_name


_NATIVE_META = 'duckdb_native_model'
_NATIVE_VERSION = '1'
_NESTED_PREFIXES = ('MAP(', 'STRUCT(')


def get_native_storage(path, session_id=None):
    return NativeDuckDBStorage(path, session_id)


def _is_nested(dtype):
    return dtype.endswith('[]') or dtype.startswith(_NESTED_PREFIXES)


def _placeholder(dtype):
    if dtype == 'JSON':
        return '?::JSON'
    if _is_nested(dtype):
        # JSON is only the parameter interchange format here; CAST converts it
        # into a native DuckDB LIST/MAP/STRUCT before it reaches storage.
        return f'CAST(?::JSON AS {dtype})'
    return '?'


def _bind_value(value, dtype):
    if value is None:
        return None
    if dtype == 'JSON' or _is_nested(dtype):
        return ujson.dumps(value, ensure_ascii=False)
    return value


def _project_value(type_spec, value):
    """Project *value* onto a known STIX schema shape.

    STRUCT projection is intentionally selective: unknown keys are not sent to
    DuckDB's STRUCT cast, but remain present in the enclosing object's ``_raw``
    JSON.  This lets standard extensions use typed nested columns without
    losing vendor extension members or future STIX fields.
    """
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


class NativeDuckDBStorage(DuckDBStorage):
    """DuckDBStorage variant using the explicit STIX 2.1 native schema."""

    def __init__(self, dbname, session_id=None):
        super().__init__(dbname, session_id)
        self._prepare_native_model()

    def _prepare_native_model(self):
        row = self.connection.execute(
            'SELECT value FROM "__metadata" WHERE name = ?',
            (_NATIVE_META,),
        ).fetchone()
        if row:
            if row['value'] != _NATIVE_VERSION:
                raise RuntimeError(
                    f'unsupported native storage version {row["value"]}'
                )
            return

        # DuckDBStorage bootstraps these two tables using the historical TEXT
        # schema.  On a new/empty session replace them with the native schema.
        # Never reinterpret an already populated compatibility database.
        for table in ('identity', 'observed-data'):
            count = self.connection.execute(
                f'SELECT count(*) AS count FROM "{table}"'
            ).fetchone()['count']
            if count:
                raise RuntimeError(
                    'native storage requires a new/empty Firepit session'
                )

        cursor = self.connection.cursor()
        cursor.execute('BEGIN')
        try:
            cursor.execute('DROP TABLE "identity"')
            cursor.execute('DROP TABLE "observed-data"')
            self._create_native_table('identity', cursor)
            self._create_native_table('observed-data', cursor)
            cursor.execute(
                'CREATE TABLE IF NOT EXISTS "__reflist" ('
                'ref_name VARCHAR, source_ref VARCHAR, target_ref VARCHAR)'
            )
            cursor.execute(
                'INSERT INTO "__metadata" (name, value) VALUES (?, ?)',
                (_NATIVE_META, _NATIVE_VERSION),
            )
            cursor.execute('COMMIT')
        except Exception:
            cursor.execute('ROLLBACK')
            raise
        finally:
            cursor.close()

    def _table_exists(self, obj_type):
        row = self.connection.execute(
            'SELECT table_name FROM information_schema.tables '
            'WHERE table_schema = ? AND table_name = ?',
            (self.session_id, obj_type),
        ).fetchone()
        return row is not None

    def _create_native_table(self, obj_type, cursor=None):
        validate_name(obj_type)
        if self._table_exists(obj_type):
            return
        if cursor is None:
            cursor = self.connection.cursor()

        schema = rendered_schema(obj_type)
        columns = []
        for name, dtype in schema.items():
            constraint = ' UNIQUE' if name == 'id' else ''
            columns.append(f'"{name}" {dtype}{constraint}')
        columns.append('"_raw" JSON')
        cursor.execute(
            f'CREATE TABLE "{obj_type}" ({", ".join(columns)})'
        )
        self._register_columns(obj_type, cursor)

    def _register_columns(self, obj_type, cursor):
        for name, dtype in rendered_schema(obj_type).items():
            cursor.execute(
                'INSERT INTO "__columns" '
                '(otype, path, shortname, dtype) VALUES (?, ?, ?, ?) '
                'ON CONFLICT (otype, path) DO NOTHING',
                (obj_type, name, name, dtype),
            )

    @staticmethod
    def _normalize_objects(bundle):
        for obj in raft.get_objects(bundle):
            if not obj.get('type') and obj.get('id'):
                obj['type'] = str(obj['id']).partition('--')[0]
            # STIX 2.0 embedded SCOs are normalized to the 2.1 object model at
            # the boundary.  Everything downstream sees standalone SCOs plus
            # observed-data.object_refs.
            if obj.get('type') == 'observed-data' and 'objects' in obj:
                yield from raft.upgrade_2021(obj)
            else:
                yield obj

    @staticmethod
    def _compat_edges(obj):
        obj_type = obj.get('type')
        oid = str(obj.get('id', ''))
        contains = []
        reflists = []

        if obj_type == 'observed-data':
            for ref in obj.get('object_refs', ()):
                contains.append((oid, str(ref), None))
            return contains, reflists

        for name, refs in obj.items():
            if not name.endswith('_refs'):
                continue
            if not isinstance(refs, list):
                refs = [refs]
            for ref in refs:
                ref = str(ref)
                if ref and ref != oid:
                    reflists.append((name, oid, ref))
        return contains, reflists

    @staticmethod
    def _project(obj):
        obj_type = obj['type']
        type_schema = schema_for(obj_type)
        projected = {
            name: _project_value(type_spec, obj.get(name))
            for name, type_spec in type_schema.items()
        }
        projected['_raw'] = obj
        return projected

    def _insert_rows(self, obj_type, rows, query_id, cursor):
        if not rows:
            return
        self._create_native_table(obj_type, cursor)
        schema = rendered_schema(obj_type)
        columns = list(schema) + ['_raw']
        dtypes = [schema[name] for name in schema] + ['JSON']
        column_sql = ', '.join(f'"{name}"' for name in columns)
        row_sql = '(' + ', '.join(_placeholder(dtype) for dtype in dtypes) + ')'
        stmt = (
            f'INSERT INTO "{obj_type}" ({column_sql}) VALUES '
            + ', '.join([row_sql] * len(rows))
        )

        if 'id' in schema:
            updates = []
            for name in columns:
                if name == 'id':
                    continue
                if obj_type == 'observed-data' and name == 'first_observed':
                    expr = (
                        'COALESCE(LEAST("observed-data".first_observed, '
                        'EXCLUDED.first_observed), '
                        '"observed-data".first_observed, EXCLUDED.first_observed)'
                    )
                elif obj_type == 'observed-data' and name == 'last_observed':
                    expr = (
                        'COALESCE(GREATEST("observed-data".last_observed, '
                        'EXCLUDED.last_observed), '
                        '"observed-data".last_observed, EXCLUDED.last_observed)'
                    )
                elif obj_type == 'observed-data' and name == 'number_observed':
                    expr = (
                        'COALESCE("observed-data".number_observed, 0) + '
                        'COALESCE(EXCLUDED.number_observed, 0)'
                    )
                else:
                    expr = (
                        f'COALESCE(EXCLUDED."{name}", '
                        f'"{obj_type}"."{name}")'
                    )
                updates.append(f'"{name}" = {expr}')
            stmt += ' ON CONFLICT (id) DO UPDATE SET ' + ', '.join(updates)

        values = []
        query_rows = []
        for row in rows:
            for name, dtype in zip(columns, dtypes):
                values.append(_bind_value(row.get(name), dtype))
            oid = row.get('id')
            if query_id and oid:
                query_rows.append((oid, str(query_id)))
        cursor.execute(stmt, values)

        if query_rows:
            placeholders = ', '.join(['(?, ?)'] * len(query_rows))
            qvalues = [value for pair in query_rows for value in pair]
            cursor.execute(
                'INSERT INTO "__queries" (sco_id, query_id) VALUES '
                + placeholders,
                qvalues,
            )

    @staticmethod
    def _insert_edges(cursor, contains, reflists):
        if contains:
            placeholders = ', '.join(['(?, ?, ?)'] * len(contains))
            values = [value for row in contains for value in row]
            cursor.execute(
                'INSERT INTO "__contains" '
                '(source_ref, target_ref, x_firepit_rank) VALUES '
                + placeholders,
                values,
            )
        if reflists:
            placeholders = ', '.join(['(?, ?, ?)'] * len(reflists))
            values = [value for row in reflists for value in row]
            cursor.execute(
                'INSERT INTO "__reflist" '
                '(ref_name, source_ref, target_ref) VALUES '
                + placeholders,
                values,
            )

    def cache(self, query_id, bundles, batchsize=2000, **_kwargs):
        """Cache bundles using native DuckDB types rather than flattening.

        Standard scalar and nested properties are projected from the STIX 2.1
        schema.  Unknown/custom properties remain available in the ``_raw``
        JSON column instead of triggering ``ALTER TABLE ADD COLUMN``.
        """
        if not isinstance(bundles, list):
            bundles = [bundles]

        pending = defaultdict(list)
        contains = []
        reflists = []
        cursor = self.connection.cursor()
        cursor.execute('BEGIN')
        try:
            for bundle in bundles:
                for obj in self._normalize_objects(bundle):
                    obj_type = obj.get('type')
                    if not obj_type:
                        continue
                    if 'id' in obj:
                        obj['id'] = str(obj['id'])
                    cedges, redges = self._compat_edges(obj)
                    contains.extend(cedges)
                    reflists.extend(redges)
                    pending[obj_type].append(self._project(obj))
                    if len(pending[obj_type]) >= batchsize:
                        self._insert_rows(
                            obj_type, pending[obj_type], query_id, cursor
                        )
                        pending[obj_type].clear()

            for obj_type, rows in pending.items():
                self._insert_rows(obj_type, rows, query_id, cursor)
            self._insert_edges(cursor, contains, reflists)
            cursor.execute('COMMIT')
        except Exception:
            cursor.execute('ROLLBACK')
            raise
        finally:
            cursor.close()
