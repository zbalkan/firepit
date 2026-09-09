"""async local storage for firepit"""

from firepit.aio.asyncwrapper import SyncWrapper
from firepit.storageurl import storage_path
from firepit.validate import validate_name


def get_async_storage(connstring, session_id=None):
    """
    Get an async storage object for firepit.  A file path with no
    scheme means DuckDB.  `session_id` partitions the data (a DuckDB
    schema).
    """
    if session_id:
        validate_name(session_id)
    return SyncWrapper(storage_path(connstring), session_id)
