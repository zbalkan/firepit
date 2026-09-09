"""Top-level package for STIX Columnar Storage."""

__author__ = """IBM Security"""
__email__ = 'pcoccoli@us.ibm.com'
__version__ = '2.3.35'


from urllib.parse import urlparse

from firepit.duckdbstorage import get_storage as _get_storage
from firepit.validate import validate_name


def get_storage(url, session_id=None):
    """
    Get a storage object for firepit.  `session_id` partitions the data
    (a DuckDB schema); a file path with no scheme means DuckDB.
    """
    if session_id:
        validate_name(session_id)
    url = urlparse(url)
    if url.scheme in ('duckdb', ''):
        return _get_storage(url.path, session_id)
    raise NotImplementedError(url.scheme)
