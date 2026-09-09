"""async local storage for firepit"""

from urllib.parse import urlparse

from firepit.aio.asyncwrapper import SyncWrapper
from firepit.validate import validate_name


def get_async_storage(connstring, session_id=None):
    """
    Get an async storage object for firepit.  A file path with no
    scheme means DuckDB.  `session_id` partitions the data (a DuckDB
    schema).
    """
    if session_id:
        validate_name(session_id)
    url = urlparse(connstring)
    if url.scheme in ('duckdb', ''):
        return SyncWrapper(url.path, session_id)
    raise NotImplementedError(url.scheme)
