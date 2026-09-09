import ipaddress
import logging
import os
import re

from base64 import b64decode

import duckdb
import ujson
from duckdb.sqltypes import BOOLEAN
from duckdb.sqltypes import VARCHAR

from firepit.exceptions import DuplicateTable
from firepit.exceptions import InvalidAttr
from firepit.exceptions import UnexpectedError
from firepit.exceptions import UnknownViewname
from firepit.splitter import SqlWriter
from firepit.sqlstorage import DB_VERSION
from firepit.sqlstorage import SqlStorage
from firepit.sqlstorage import infer_type
from firepit.sqlstorage import validate_name

logger = logging.getLogger(__name__)


# Unlike SQLite/PostgreSQL, __contains has no UNIQUE constraint here
# either -- see the matching #TODO in sqlitestorage.py.  upsert() never
# emits ON CONFLICT for tables without an `id` column, so one isn't
# needed for correctness, only for dedup on re-caching, which neither
# existing backend does.
CONTAINS_TABLE = ('CREATE TABLE IF NOT EXISTS "__contains" '
                  '(source_ref TEXT, target_ref TEXT, x_firepit_rank INTEGER);')

COLUMNS_TABLE = ('CREATE TABLE IF NOT EXISTS "__columns" '
                 '(otype TEXT, path TEXT, shortname TEXT, dtype TEXT,'
                 ' UNIQUE(otype, path));')

# Bootstrap some common SDO tables
ID_TABLE = ('CREATE TABLE "identity" ('
            ' "id" TEXT UNIQUE,'
            ' "identity_class" TEXT,'
            ' "name" TEXT,'
            ' "created" TEXT,'
            ' "modified" TEXT'
            ')')

OD_TABLE = ('CREATE TABLE "observed-data" ('
            ' "id" TEXT UNIQUE,'
            ' "created_by_ref" TEXT,'
            ' "created" TEXT,'
            ' "modified" TEXT,'
            ' "first_observed" TEXT,'
            ' "last_observed" TEXT,'
            ' "number_observed" BIGINT'
            ')')


def get_storage(path, session_id=None):
    return DuckDBStorage(path, session_id)


def session_exists(path, session_id=None):
    """
    Check whether `session_id` (a schema) already has data in the
    DuckDB file at `path`, without creating anything -- used by
    SyncWrapper.create()/.attach() for the SessionExists/
    SessionNotFound checks SQLite gets for free from one-file-per-
    session (DuckDB's session model is schema-per-file, like
    PostgreSQL's, so "does the file exist" isn't the right question).
    Returns False if `path` itself doesn't exist yet.
    """
    if not os.path.exists(path):
        return False
    session_id = session_id or 'main'
    raw = duckdb.connect(path)
    try:
        raw.execute('SET python_enable_replacements=false')
        rows = raw.execute(
            "SELECT table_name FROM information_schema.tables"
            " WHERE table_schema = ? AND table_name = '__queries'",
            (session_id,)).fetchall()
        return bool(rows)
    finally:
        raw.close()


def _in_subnet(value, net):
    """UDF implementing STIX ISSUBSET"""
    if value is None or net is None:
        return None
    if '/' in value:
        value = ipaddress.IPv4Network(value).network_address
    else:
        value = ipaddress.IPv4Address(value)
    net = ipaddress.IPv4Network(net)
    return value in net


def _match(pattern, value):
    """
    UDF implementing SQL match()/STIX MATCHES.

    Kept as a Python function (reused verbatim from the SQLite
    backend) rather than DuckDB's `regexp_matches`/`~`, because
    DuckDB's RE2 engine has no equivalent of Python's re.DOTALL, so
    a SQL-native version would not match the same strings SQLite does
    (e.g. `.` matching a newline).
    """
    if pattern is None or value is None:
        return None
    return bool(re.search(pattern, value, re.DOTALL))


def _match_bin(pattern, value):
    """UDF implementing SQL match()/STIX MATCHES for binaries"""
    if pattern is None or value is None:
        return None
    val = b64decode(value).decode('utf-8')
    return bool(re.search(pattern, val, re.DOTALL))


def _like_bin(pattern, value):
    """UDF implementing SQL/STIX LIKE for binaries"""
    if pattern is None or value is None:
        return None
    try:
        exp = re.escape(pattern).replace('%', '.*').replace('_', '.')
        val = b64decode(value).decode('utf-8')
        return bool(re.search(exp, val, re.DOTALL))
    except Exception as e:
        logger.error('%s', e, exc_info=e)
        return False


def _map_error(e):
    """Translate a duckdb.Error into the firepit exception SqlStorage expects"""
    msg = str(e)
    if isinstance(e, duckdb.CatalogException):
        if 'already exists' in msg:
            m = re.search(r'"([^"]+)"', msg)
            return DuplicateTable(m.group(1) if m else msg)
        if 'does not exist' in msg:
            return UnknownViewname(msg)
    elif isinstance(e, duckdb.BinderException):
        return InvalidAttr(msg)
    elif isinstance(e, duckdb.ParserException):
        # We see this on SQL injection attempts
        return UnexpectedError(msg)
    return UnexpectedError(msg)


class _Cursor:
    """
    Dict-row DB-API-like wrapper around a *single* duckdb connection.

    DuckDB has neither sqlite3's `row_factory` nor psycopg2's
    `RealDictCursor`, but every call site in SqlStorage assumes rows
    are dict-like, so this fakes that up from `.description`.

    Every `_Cursor` a given store hands out -- from `.cursor()`, or
    returned by `_execute`/`_query` -- wraps the *same* physical
    duckdb connection, deliberately, for two reasons:

    1. Correctness: duckdb's own `.cursor()` returns a genuinely
       independent connection with its own transaction state.
       SqlStorage's `_get_cursor()` (several call sites obtain a
       cursor, do a few statements, then commit via
       `self.connection.commit()` -- a *different* object) would
       silently lose those writes if `.cursor()` opened a real second
       connection, since the parent's commit would never reach them.

    2. Speed: opening a real duckdb connection is far more expensive
       than sqlite3's lightweight `Cursor`, and needs `search_path`
       re-applied every time (duckdb doesn't share session settings
       across connections) -- prohibitively slow at the rate
       SplitWriter calls `_execute` while ingesting.

    A caller must not expect a live, lazily-streamed result: `execute`
    fetches and caches all rows immediately rather than leaving them
    pending on the connection.  This isn't just about interleaving
    queries from two different callers -- SqlStorage's own `_query`
    (sqlstorage.py) executes, then commits `self.connection` (the
    *same* connection every `_Cursor` here shares), and only then
    returns the cursor for the caller to fetch from.  Measured
    directly: that intervening `commit()` silently discards a still-
    pending duckdb result, so without eager fetching, any query run
    through `_query` between a `_get_cursor()` and its matching
    `commit()` comes back empty.  Fetching up front sidesteps that
    regardless of what happens to the connection afterward.

    `owns` marks the one `_Cursor` created in `DuckDBStorage.__init__`
    as `self.connection`: only *it* actually closes the underlying
    connection on `close()`.  Every other `_Cursor` (from `.cursor()`)
    is a disposable Python-level view onto the same connection, and
    `close()` on it is a no-op -- callers throughout SqlStorage treat
    "get a cursor, use it, close it" as a cheap, side-effect-free
    pattern, which duckdb's own `.close()` is not.
    """

    def __init__(self, raw, owns=True):
        self._raw = raw
        self._owns = owns
        self.description = None
        self._rows = []
        self._pos = 0

    def cursor(self):
        return _Cursor(self._raw, owns=False)

    def execute(self, stmt, values=None):
        try:
            self._raw.execute(stmt, values or ())
            self.description = self._raw.description
            # Eager fetch -- see the class docstring for why this
            # can't be left as a live, pending duckdb result.
            self._rows = self._raw.fetchall()
        except duckdb.Error as e:
            logger.error('%s: %s', stmt, e)
            raise _map_error(e) from e
        self._pos = 0
        return self

    def fetchone(self):
        if self._pos >= len(self._rows):
            return None
        row = self._rows[self._pos]
        self._pos += 1
        return dict(zip((d[0] for d in self.description), row))

    def fetchall(self):
        cols = [d[0] for d in self.description] if self.description else []
        rows = self._rows[self._pos:]
        self._pos = len(self._rows)
        return [dict(zip(cols, row)) for row in rows]

    def commit(self):
        self._raw.commit()

    def rollback(self):
        self._raw.rollback()

    def close(self):
        if self._owns:
            self._raw.close()


class DuckDBStorage(SqlStorage):
    def __init__(self, dbname, session_id=None):
        super().__init__()
        self.dbname = dbname
        self.session_id = session_id or 'main'
        validate_name(self.session_id)

        raw = duckdb.connect(dbname)

        # DuckDB's Python client will otherwise resolve an unknown
        # table/view name against variables in the calling Python
        # frame.  firepit table/view names come straight from STIX
        # types and user-supplied names, so this must be off.
        raw.execute('SET python_enable_replacements=false')

        # Kept as Python UDFs rather than SQL macros -- see _match().
        # Unlike SQLite (where these are re-registered per Python
        # connection object and simply shadow any prior one), DuckDB
        # keeps a registered function in the file's catalog for as
        # long as this process has it open -- reopening the same file
        # (e.g. a fresh DuckDBStorage after delete()) hits "already
        # exists" rather than silently rebinding, so that's expected
        # here and safe to ignore.
        for name, fn in (('in_subnet', _in_subnet), ('match', _match),
                          ('match_bin', _match_bin), ('like_bin', _like_bin)):
            try:
                raw.create_function(name, fn, [VARCHAR, VARCHAR], BOOLEAN,
                                     null_handling='special')
            except duckdb.CatalogException:
                pass

        search_path = f'"{self.session_id}"'
        raw.execute(f'CREATE SCHEMA IF NOT EXISTS {search_path}')
        raw.execute(f"SET search_path='{search_path}'")

        self.connection = _Cursor(raw)
        logger.debug("Connection to DuckDB %s (session %s) successful",
                     dbname, self.session_id)

        exists = self.connection.execute(
            "SELECT table_name FROM information_schema.tables"
            " WHERE table_schema = ? AND table_name = '__queries'",
            (self.session_id,)).fetchall()
        if exists:
            # Attaching to existing session
            self._checkdb()
        else:
            # Do DB initialization
            cursor = self.connection.cursor()
            cursor.execute(CONTAINS_TABLE)
            cursor.execute(COLUMNS_TABLE)
            cursor.execute(ID_TABLE)
            cursor.execute(OD_TABLE)
            self._initdb(cursor)

    def _initdb(self, cursor):
        """
        Overrides parent: the base implementation's `__contains` DDL
        uses SQLite-only syntax (`ON CONFLICT IGNORE` on a table
        constraint, and an untyped column), so this duplicates the
        rest of it with CONTAINS_TABLE substituted in.
        """
        stmt = ('CREATE TABLE IF NOT EXISTS "__metadata" '
                '(name TEXT, value TEXT);')
        self._execute(stmt, cursor)
        stmt = ('CREATE TABLE IF NOT EXISTS "__symtable" '
                '(name TEXT, type TEXT, appdata TEXT,'
                ' UNIQUE(name));')
        self._execute(stmt, cursor)
        stmt = ('CREATE TABLE IF NOT EXISTS "__queries" '
                '(sco_id TEXT, query_id TEXT);')
        self._execute(stmt, cursor)
        self._execute(CONTAINS_TABLE, cursor)
        self._execute(COLUMNS_TABLE, cursor)
        self._set_meta(cursor, 'dbversion', DB_VERSION)
        self.connection.commit()
        cursor.close()

    def _get_writer(self, **kwargs):
        """Get a DB inserter object"""
        filedir = os.path.dirname(self.dbname)
        return SqlWriter(filedir, self, infer_type=infer_type)

    def _execute(self, statement, cursor=None):
        logger.debug('Executing statement: %s', statement)
        if not cursor:
            cursor = self.connection.cursor()
        return cursor.execute(statement)

    def upsert_many(self, cursor, tablename, objs, query_id, schema):
        """
        Overrides parent: the base implementation's `upsert_many` is a
        Python loop issuing one `INSERT ... VALUES (?, ...)` per
        object.  DuckDB optimizes for bulk operations, not many small
        individually-bound statements -- issuing thousands of them in
        a loop (measured here) is ~60x slower than folding them into
        one multi-row `INSERT ... VALUES (...), (...), ...`, which is
        what this does instead (mirroring PgStorage.upsert_multirow).
        `objs` is already de-duplicated by id upstream in
        RecordList/SplitWriter, so -- like PostgreSQL -- a single
        statement never needs to update the same target row twice.
        """
        if not objs:
            return
        colnames = list(schema.keys())
        valnames = ', '.join([f'"{x}"' for x in colnames])
        row_placeholder = f"({', '.join([self.placeholder] * len(colnames))})"
        stmt = (f'INSERT INTO "{tablename}" ({valnames})'
                f' VALUES {", ".join([row_placeholder] * len(objs))}')
        idx = None
        if 'id' in colnames:
            idx = colnames.index('id')
            excluded = self._get_excluded(colnames, tablename)
            action = f'UPDATE SET {excluded}' if excluded and tablename != 'observed-data' else 'NOTHING'
            stmt += f' ON CONFLICT (id) DO {action}'
        values = []
        query_values = []
        for obj in objs:
            if query_id and idx is not None:
                query_values.append(obj[idx])
                query_values.append(query_id)
            values.extend(ujson.dumps(value, ensure_ascii=False)
                          if isinstance(value, (list, dict)) else value for value in obj)
        cursor.execute(stmt, values)

        if query_id and idx is not None:
            placeholders = ', '.join([f'({self.placeholder}, {self.placeholder})'] * len(objs))
            stmt = f'INSERT INTO "__queries" (sco_id, query_id) VALUES {placeholders}'
            cursor.execute(stmt, query_values)

    def _add_column(self, tablename, prop_name, prop_type):
        stmt = f'ALTER TABLE "{tablename}" ADD COLUMN "{prop_name}" {prop_type};'
        logger.debug('new_property: "%s"', stmt)
        try:
            cursor = self._execute(stmt)
            cursor.close()
        except DuplicateTable:
            # Column already exists -- same backstop SQLite keeps
            pass

    def _create_view(self, viewname, select, sco_type, deps=None, cursor=None):
        """Overrides parent"""
        validate_name(viewname)
        if not cursor:
            cursor = self._get_cursor()
        is_new = True
        if not deps:
            deps = []
        elif viewname in deps:
            is_new = False
            # Get the query that makes up the current view
            slct = self._get_view_def(viewname)
            if self._is_sql_view(viewname, cursor):
                self._execute(f'DROP VIEW IF EXISTS "{viewname}"', cursor)
            else:
                self._execute(f'ALTER TABLE "{viewname}" RENAME TO "_{viewname}"', cursor)
                slct = slct.replace(viewname, f'_{viewname}')
            # Swap out the viewname for its definition
            select = re.sub(f'FROM "{viewname}"', f'FROM ({slct}) AS tmp', select, count=1)
            select = re.sub(f'"{viewname}"', 'tmp', select)
        if self._is_sql_view(viewname, cursor):
            is_new = False
            self._execute(f'DROP VIEW IF EXISTS "{viewname}"', cursor)
        try:
            self._execute(f'CREATE VIEW "{viewname}" AS {select}', cursor)
        except UnknownViewname:
            # The SCO type this view is built on was never
            # encountered during ingest, so its table doesn't exist.
            # SQLite tolerates that (a SELECT against a missing table
            # just returns nothing); DuckDB, like PostgreSQL, does
            # not, so build an empty view instead -- matching
            # PgStorage._create_empty_view.
            self._execute(f'CREATE VIEW "{viewname}" AS SELECT NULL AS id WHERE 1<>1', cursor)
        if is_new:
            self._new_name(cursor, viewname, sco_type)
        return cursor

    def _get_view_def(self, viewname):
        validate_name(viewname)
        cursor = self.connection.cursor()
        row = cursor.execute(
            "SELECT sql FROM duckdb_views()"
            " WHERE schema_name = ? AND view_name = ?",
            (self.session_id, viewname)).fetchone()
        if row:
            # DuckDB re-serializes the view definition (unlike SQLite,
            # which stores it verbatim), always schema-qualifying the
            # name and always appending a trailing `;` -- strip both so
            # the result is safe to embed in a subquery, matching what
            # SQLite's sqlite_master.sql already gives us.
            slct = row['sql']
            slct = re.sub(r'^CREATE VIEW\s+\S+\s+AS\s+', '', slct, count=1)
            slct = slct.rstrip()
            if slct.endswith(';'):
                slct = slct[:-1]
            # DuckDB has its own quoting gap: it re-serializes a
            # hyphenated table's star-qualifier (`"network-traffic".*`)
            # WITHOUT quotes (`network-traffic.*`), even though it
            # correctly quotes the same identifier as a table
            # reference a few tokens later.  Left alone, that becomes
            # unparseable as soon as this definition is re-embedded
            # into another view -- which is exactly what happens here.
            slct = re.sub(r'(?<!")\b([A-Za-z_]\w*(?:-\w+)+)\.\*', r'"\1".*', slct)
            return slct
        # Must be a table
        return f'SELECT * FROM "{viewname}"'

    def _is_sql_view(self, name, cursor=None):
        validate_name(name)
        c = cursor or self.connection.cursor()
        row = c.execute(
            "SELECT view_name FROM duckdb_views()"
            " WHERE schema_name = ? AND view_name = ?",
            (self.session_id, name)).fetchone()
        return row is not None

    def tables(self):
        stmt = ("SELECT table_name FROM information_schema.tables"
                " WHERE table_schema = ? AND table_type = 'BASE TABLE'")
        rows = self._query(stmt, (self.session_id,)).fetchall()
        return [r['table_name'] for r in rows if not r['table_name'].startswith('__')]

    def types(self, private=False):
        stmt = ("SELECT table_name FROM information_schema.tables"
                " WHERE table_schema = ? AND table_type = 'BASE TABLE'"
                " EXCEPT SELECT name FROM __symtable")
        rows = self._query(stmt, (self.session_id,)).fetchall()
        if private:
            return [r['table_name'] for r in rows]
        return [r['table_name'] for r in rows if not r['table_name'].startswith('__')]

    def columns(self, viewname):
        validate_name(viewname)
        stmt = f'PRAGMA table_info("{viewname}")'
        try:
            cursor = self._execute(stmt)
            rows = cursor.fetchall()
            result = [row['name'] for row in rows]
        except UnknownViewname:
            result = []
        logger.debug('%s columns = %s', viewname, result)
        return result

    def schema(self, viewname=None):
        if viewname:
            validate_name(viewname)
            stmt = f'PRAGMA table_info("{viewname}")'
            cursor = self._execute(stmt)
            return [{k: v for k, v in row.items() if k in ['name', 'type']}
                    for row in cursor.fetchall()]
        result = []
        for obj_type in self.types(True):
            stmt = f'PRAGMA table_info("{obj_type}")'
            cursor = self._execute(stmt)
            for row in cursor.fetchall():
                result.append({
                    'table': obj_type,
                    'name': row['name'],
                    'type': row['type']
                })
        return result

    def delete(self):
        """Delete ALL data in this session"""
        self.connection.execute(f'DROP SCHEMA IF EXISTS "{self.session_id}" CASCADE')
        self.connection.close()
