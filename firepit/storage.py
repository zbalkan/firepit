"""Read-only Firepit query surface over DuckDB.

The public object deliberately exposes no DuckDB connection. User SQL is
parsed by DuckDB and must contain exactly one SELECT statement. The underlying
connection is also opened read-only and external access is disabled.
"""

from __future__ import annotations

import os

import duckdb

from firepit.exceptions import InvalidQuery
from firepit.validate import validate_name

PUBLIC_VIEWS = frozenset({"ThreatIntelIndicators", "ThreatIntelObjects"})
_INTERNAL_SCHEMA_PREFIX = "__firepit_"
_FORBIDDEN_CATALOG_TOKENS = (
    _INTERNAL_SCHEMA_PREFIX,
    "information_schema",
    "duckdb_",
    "pg_catalog",
    "sqlite_",
)


def _qident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


class Firepit:
    """Query-only handle over the two public threat-intelligence views."""

    __slots__ = ("__connection", "__session_id", "__closed")

    def __init__(self, dbname, session_id=None):
        self.__session_id = session_id or "main"
        validate_name(self.__session_id)
        self.__closed = False

        path = os.fspath(dbname)
        if not os.path.exists(path):
            raise FileNotFoundError(path)

        connection = None
        try:
            connection = duckdb.connect(path, read_only=True)
            connection.execute("SET python_enable_replacements=false")
            connection.execute("SET enable_external_access=false")
            connection.execute(
                f"SET search_path={_qident(self.__session_id)}"
            )
        except Exception:
            if connection is not None:
                try:
                    connection.close()
                except duckdb.Error:
                    pass
            raise

        self.__connection = connection
        try:
            self.__verify_public_surface()
        except Exception:
            self.close()
            raise

    @property
    def session_id(self):
        """Return the public Firepit schema name."""
        return self.__session_id

    def __verify_public_surface(self):
        rows = self.__connection.execute(
            "SELECT view_name FROM duckdb_views() "
            "WHERE schema_name = ? AND NOT internal",
            (self.__session_id,),
        ).fetchall()
        views = {row[0] for row in rows}
        if views != PUBLIC_VIEWS:
            missing = PUBLIC_VIEWS - views
            extra = views - PUBLIC_VIEWS
            details = []
            if missing:
                details.append("missing " + ", ".join(sorted(missing)))
            if extra:
                details.append("unexpected " + ", ".join(sorted(extra)))
            raise RuntimeError(
                f"Firepit session {self.__session_id!r} has an invalid public "
                "surface: " + "; ".join(details)
            )

    def __ensure_open(self):
        if self.__closed:
            raise RuntimeError("Firepit handle is closed")

    def __validated_sql(self, sql: str):
        if not isinstance(sql, str) or not sql.strip():
            raise InvalidQuery("query must be a non-empty SQL string")
        self.__ensure_open()

        try:
            statements = self.__connection.extract_statements(sql)
        except duckdb.Error as exc:
            raise InvalidQuery(str(exc)) from exc

        if len(statements) != 1:
            raise InvalidQuery("exactly one SQL statement is allowed")

        statement = statements[0]
        if statement.type != duckdb.StatementType.SELECT:
            raise InvalidQuery("only SELECT statements are allowed")

        normalized = statement.query.casefold()
        if any(token in normalized for token in _FORBIDDEN_CATALOG_TOKENS):
            raise InvalidQuery("only the public Firepit views are queryable")

        return statement.query

    def __execute(self, sql, parameters):
        query = self.__validated_sql(sql)
        try:
            return self.__connection.execute(query, parameters or ())
        except duckdb.Error as exc:
            raise InvalidQuery(str(exc)) from exc

    @staticmethod
    def __columns(cursor):
        return tuple(column[0] for column in (cursor.description or ()))

    def query(self, sql, parameters=None):
        """Execute one read-only SELECT and return rows as dictionaries."""
        cursor = self.__execute(sql, parameters)
        columns = self.__columns(cursor)
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def query_one(self, sql, parameters=None):
        """Execute one read-only SELECT and return its first row."""
        cursor = self.__execute(sql, parameters)
        columns = self.__columns(cursor)
        row = cursor.fetchone()
        return dict(zip(columns, row)) if row is not None else None

    def query_value(self, sql, parameters=None):
        """Execute one read-only SELECT and return the first scalar value."""
        cursor = self.__execute(sql, parameters)
        row = cursor.fetchone()
        return row[0] if row is not None else None

    def indicators(self, where=None, parameters=None, *, limit=None):
        """Query ``ThreatIntelIndicators`` with optional filter sugar."""
        sql = 'SELECT * FROM "ThreatIntelIndicators"'
        if where:
            sql += f" WHERE {where}"
        if limit is not None:
            limit = int(limit)
            if limit < 0:
                raise ValueError("limit must be non-negative")
            sql += f" LIMIT {limit}"
        return self.query(sql, parameters)

    def objects(self, where=None, parameters=None, *, limit=None):
        """Query ``ThreatIntelObjects`` with optional filter sugar."""
        sql = 'SELECT * FROM "ThreatIntelObjects"'
        if where:
            sql += f" WHERE {where}"
        if limit is not None:
            limit = int(limit)
            if limit < 0:
                raise ValueError("limit must be non-negative")
            sql += f" LIMIT {limit}"
        return self.query(sql, parameters)

    def close(self):
        if not self.__closed:
            self.__connection.close()
            self.__closed = True

    def __enter__(self):
        self.__ensure_open()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


def get_storage(path, session_id=None):
    """Open a query-only Firepit handle."""
    return Firepit(path, session_id)
