"""Read-only Firepit query surface over public threat-intelligence views."""

from __future__ import annotations

import os

import duckdb

from firepit.exceptions import InvalidQuery
from firepit.validate import validate_name
from firepit.views_wide import PUBLIC_VIEWS

_FORBIDDEN = ("__firepit_", "information_schema", "duckdb_", "pg_catalog", "sqlite_")


def _qident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


class Firepit:
    """Query-only handle over Firepit's public views."""

    __slots__ = ("__connection", "__session_id", "__closed")

    def __init__(self, dbname, session_id=None):
        self.__session_id = session_id or "main"
        validate_name(self.__session_id)
        self.__closed = False

        path = os.fspath(dbname)
        if not os.path.exists(path):
            raise FileNotFoundError(path)

        connection = duckdb.connect(path, read_only=True)
        try:
            connection.execute("SET python_enable_replacements=false")
            connection.execute("SET enable_external_access=false")
            connection.execute(f"SET search_path={_qident(self.__session_id)}")
            self.__connection = connection
            self.__verify_public_surface()
        except Exception:
            connection.close()
            raise

    @property
    def session_id(self):
        return self.__session_id

    def __verify_public_surface(self):
        rows = self.__connection.execute(
            "SELECT table_name, table_type FROM information_schema.tables "
            "WHERE table_schema = ?",
            (self.__session_id,),
        ).fetchall()
        views = {name for name, kind in rows if kind == "VIEW"}
        tables = {name for name, kind in rows if kind == "BASE TABLE"}
        expected = set(PUBLIC_VIEWS)
        if views == expected and not tables:
            return

        problems = []
        if missing := expected - views:
            problems.append("missing views: " + ", ".join(sorted(missing)))
        if extra := views - expected:
            problems.append("unexpected views: " + ", ".join(sorted(extra)))
        if tables:
            problems.append("unexpected base tables: " + ", ".join(sorted(tables)))
        raise RuntimeError(
            f"Firepit session {self.__session_id!r} has an invalid public surface: "
            + "; ".join(problems)
        )

    def __validated_sql(self, sql: str):
        self.__ensure_open()
        if not isinstance(sql, str) or not sql.strip():
            raise InvalidQuery("query must be a non-empty SQL string")
        try:
            statements = self.__connection.extract_statements(sql)
        except duckdb.Error as exc:
            raise InvalidQuery(str(exc)) from exc
        if len(statements) != 1:
            raise InvalidQuery("exactly one SQL statement is allowed")
        statement = statements[0]
        if statement.type != duckdb.StatementType.SELECT:
            raise InvalidQuery("only SELECT statements are allowed")
        if any(token in statement.query.casefold() for token in _FORBIDDEN):
            raise InvalidQuery("only the public Firepit views are queryable")
        return statement.query

    def __execute(self, sql, parameters=None):
        try:
            return self.__connection.execute(
                self.__validated_sql(sql), parameters or ()
            )
        except duckdb.Error as exc:
            raise InvalidQuery(str(exc)) from exc

    @staticmethod
    def __dict(cursor, row):
        if row is None:
            return None
        return dict(zip((col[0] for col in cursor.description or ()), row))

    def query(self, sql, parameters=None):
        """Execute one SELECT and return all rows as dictionaries."""
        cursor = self.__execute(sql, parameters)
        columns = tuple(col[0] for col in cursor.description or ())
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def query_one(self, sql, parameters=None):
        """Execute one SELECT and return its first row."""
        cursor = self.__execute(sql, parameters)
        return self.__dict(cursor, cursor.fetchone())

    def query_value(self, sql, parameters=None):
        """Execute one SELECT and return its first scalar value."""
        row = self.__execute(sql, parameters).fetchone()
        return row[0] if row else None

    def _view(self, name, where=None, parameters=None, limit=None):
        sql = f'SELECT * FROM "{name}"'
        if where:
            sql += f" WHERE {where}"
        if limit is not None:
            limit = int(limit)
            if limit < 0:
                raise ValueError("limit must be non-negative")
            sql += f" LIMIT {limit}"
        return self.query(sql, parameters)

    def indicators(self, where=None, parameters=None, *, limit=None):
        return self._view("ThreatIntelIndicators", where, parameters, limit)

    def objects(self, where=None, parameters=None, *, limit=None):
        return self._view("ThreatIntelObjects", where, parameters, limit)

    def __ensure_open(self):
        if self.__closed:
            raise RuntimeError("Firepit handle is closed")

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
    return Firepit(path, session_id)
