import logging

import ujson

from firepit.aio.asyncstorage import AsyncStorage
from firepit.duckdbstorage import get_storage, session_exists
from firepit.exceptions import SessionExists, SessionNotFound
from firepit.sqlstorage import SqlStorage, infer_type


logger = logging.getLogger(__name__)


class SyncWrapper(AsyncStorage):
    """Adapts the synchronous DuckDBStorage to AsyncStorage's async interface"""

    class Placeholder:
        def __str__(self, _offset=0):
            return '?'

    def __init__(self,
                 connstring: str = None,
                 session_id: str = None,
                 store: SqlStorage = None):
        if store:
            logger.debug('Wrapping storage object %s', store)
            self.store = store
            self.dialect = self.store.dialect
        else:
            super().__init__(connstring, session_id)
            self.placeholder = '?'
            self.dialect = 'duckdb'

        # SQL data type inference function (database-specific)
        self.infer_type = infer_type

    async def create(self, ssl_context=None):
        """
        Create a new "session" (DuckDB schema).  Fail if it already exists.
        """
        # DuckDB's session model is schema-per-file, like PostgreSQL's
        # -- "the file exists" isn't "the session exists".
        if session_exists(self.connstring, self.session_id):
            raise SessionExists(self.session_id or self.connstring)
        logger.debug('Creating storage for session %s', self.session_id)
        self.store = get_storage(self.connstring, self.session_id)
        self.conn = self.store.connection
        self.placeholder = self.store.placeholder
        self.dialect = self.store.dialect

    async def attach(self):
        """
        Attach/connect to an existing session.  Fail if it doesn't exist.
        """
        if not session_exists(self.connstring, self.session_id):
            raise SessionNotFound(self.session_id or self.connstring)
        logger.debug('Attaching to storage for session %s', self.session_id)
        self.store = get_storage(self.connstring, self.session_id)
        self.conn = self.store.connection
        self.placeholder = self.store.placeholder
        self.dialect = self.store.dialect

    async def cache(self,
                    query_id: str,
                    bundle: dict):
        """
        Ingest a single, in-memory STIX bundle, labelled with `query_id`.
        """
        self.store.cache(query_id, bundle)

    async def execute(self, stmt, *values):
        """Execute SQL statement `stmt` with parameters `*values`"""
        return self.store.connection.execute(stmt, values)

    async def tables(self):
        return self.store.tables()

    async def views(self):
        """Get all view names"""
        return self.store.views()

    async def table_type(self, viewname):
        """Get the SCO type for table/view `viewname`"""
        return self.store.table_type(viewname)

    async def types(self, private=False):
        return self.store.types(private)

    async def columns(self, viewname):
        """Get the column names (properties) of `viewname`"""
        return self.store.columns(viewname)

    async def schema(self, viewname=None):
        """Get the schema (names and types) of `viewname`"""
        return self.store.schema(viewname)

    async def delete(self):
        """Delete ALL data in this store"""
        self.store.delete()

    async def set_appdata(self, viewname, data):
        """Attach app-specific data to a viewname"""
        self.store.set_appdata(viewname, data)

    async def get_appdata(self, viewname):
        """Retrieve app-specific data for a viewname"""
        return self.store.get_appdata(viewname)

    async def get_view_data(self, viewnames=None):
        """Retrieve information about one or more viewnames"""
        return self.store.get_view_data(viewnames)

    async def run_query(self, query):
        return self.store.run_query(query).fetchall()

    async def fetch(self, query, *args):
        """Passthrough to underlying DB"""
        return self.store._query(query, args).fetchall()

    async def fetchrow(self, query, *args):
        """Passthrough to underlying DB"""
        return self.store._query(query, tuple(args)).fetchone()

    async def remove_view(self, viewname):
        """Remove view `viewname`"""
        return self.store.remove_view(viewname)

    async def assign_query(self, viewname, query, sco_type=None):
        """
        Create a new view `viewname` defined by `query`
        """
        return self.store.assign_query(viewname, query, sco_type)

    async def lookup(self, viewname, cols="*", limit=None, offset=None, col_dict=None):
        """Get the value of `viewname`"""
        return self.store.lookup(viewname, cols, limit, offset, col_dict)

    async def _is_sql_view(self, name):
        return self.store._is_sql_view(name)

    async def write_df(self, tablename, df, query_id, schema):
        cursor = self.store.connection.cursor()  # TODO: need a context manager here?
        objs = df.to_dict(orient='records')
        for obj in objs:
            self._write_one(cursor, tablename, obj, schema, query_id)
        self.store.connection.commit()

    def _write_one(self, cursor, tablename, obj, schema, query_id):
        # `i != 'type'` here used to compare a (k, v) tuple against a
        # string, so it never actually filtered anything -- fixed to
        # `k != 'type'`, and `values` below now comes from the same
        # filtered list so the column/value counts stay in sync.
        pairs = [(k, v) for k, v in obj.items() if k != 'type']
        colnames = [k for k, _ in pairs]
        valnames = ', '.join([f'"{x}"' for x in colnames])
        ph = self.store.placeholder
        phs = ', '.join([ph] * len(colnames))
        stmt = f'INSERT INTO "{tablename}" ({valnames}) VALUES ({phs})'
        if 'id' in colnames:
            excluded = self.store._get_excluded(colnames, tablename)
            if excluded and tablename != 'observed-data':
                action = f'UPDATE SET {excluded}'
            else:
                action = 'NOTHING'
            stmt += f' ON CONFLICT (id) DO {action}'
        # else: no ON CONFLICT here, matching SqlStorage.upsert() --
        # id-less tables like __contains have no UNIQUE/PK constraint
        # for a conflict target to reference.  Under SQLite this was
        # a no-op (nothing to ever conflict on); under DuckDB it's a
        # hard error ("no UNIQUE/PRIMARY KEY constraints... specify
        # ON CONFLICT columns manually").
        values = tuple(ujson.dumps(v, ensure_ascii=False)
                       if isinstance(v, list) else v for _, v in pairs)
        #logger.debug('_upsert: "%s", %s', stmt, values)
        cursor.execute(stmt, values)

        if query_id and 'id' in colnames:
            # Now add to query table as well
            stmt = (f'INSERT INTO "__queries" (sco_id, query_id)'
                    f' VALUES ({ph}, {ph})')
            cursor.execute(stmt, (obj['id'], query_id))

    #TODO: how is this different than columns?
    async def properties(self, obj_type=None):
        return self.store.schema(obj_type)

    async def new_type(self, obj_type, schema):
        self.store._create_table(obj_type, schema)

    async def new_property(self, obj_type, prop_name, prop_type):
        self.store._add_column(obj_type, prop_name, prop_type)
