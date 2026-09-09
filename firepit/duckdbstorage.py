"""Temporary import compatibility for the retired DuckDB backend module."""

from firepit.storage import DuckDBStorage
from firepit.storage import get_storage
from firepit.storage import session_exists

__all__ = ["DuckDBStorage", "get_storage", "session_exists"]
