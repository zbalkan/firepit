"""Storage connection-string handling for DuckDB-only firepit."""

import os


_DUCKDB_SCHEME = 'duckdb://'


def storage_path(value):
    """Return the DuckDB file path represented by *value*.

    Bare paths are intentionally not passed through ``urlparse``.  A Windows
    drive path such as ``C:\\data\\firepit.db`` contains a colon and is
    otherwise misclassified as a URI scheme.  ``duckdb://`` is the only URI
    form firepit accepts; everything else is rejected explicitly.
    """
    value = os.fspath(value)
    if value.startswith(_DUCKDB_SCHEME):
        path = value[len(_DUCKDB_SCHEME):]
        if not path:
            raise ValueError('duckdb:// requires a database path')
        return path
    if '://' in value:
        raise NotImplementedError(value.split('://', 1)[0])
    return value
