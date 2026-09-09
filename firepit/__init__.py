"""Firepit: DuckDB-native STIX 2.1 storage."""

__author__ = "IBM Security"
__email__ = "pcoccoli@us.ibm.com"
__version__ = "3.0.0"

from firepit.storage import get_storage as _get_storage
from firepit.storageurl import storage_path
from firepit.validate import validate_name


def get_storage(url, session_id=None):
    """Open a DuckDB-backed Firepit session."""
    if session_id:
        validate_name(session_id)
    return _get_storage(storage_path(url), session_id)


__all__ = ["get_storage"]
