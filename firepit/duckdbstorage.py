"""Compatibility import for the DuckDB-native storage implementation.

This module remains temporarily so existing imports do not break while the
storage class layout is collapsed in the final modernization phase.
"""

from firepit.duckdbnative import NativeDuckDBStorage as DuckDBStorage
from firepit.duckdbnative import get_storage
from firepit.duckdbnative import session_exists

__all__ = ["DuckDBStorage", "get_storage", "session_exists"]
