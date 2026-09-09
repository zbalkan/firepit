"""Firepit: DuckDB-native STIX storage."""

__author__ = "IBM Security"
__email__ = "pcoccoli@us.ibm.com"
__version__ = "2.3.35"

from firepit.duckdbnative import get_storage as _get_storage
from firepit.storageurl import storage_path
from firepit.validate import validate_name


def get_storage(url, session_id=None):
    """Open the DuckDB-native Firepit store.

    `session_id` maps to a DuckDB schema. A bare path or `duckdb://` URL points
    to the DuckDB database file.
    """
    if session_id:
        validate_name(session_id)
    return _get_storage(storage_path(url), session_id)


__all__ = ["get_storage"]
