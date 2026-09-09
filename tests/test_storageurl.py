import pathlib

import pytest

from firepit.storageurl import storage_path


def test_storage_path_accepts_bare_posix_path():
    assert storage_path('/tmp/firepit.db') == '/tmp/firepit.db'


def test_storage_path_accepts_duckdb_uri():
    assert storage_path('duckdb:///tmp/firepit.db') == '/tmp/firepit.db'


def test_storage_path_preserves_windows_drive_path():
    path = r'C:\\data\\firepit.db'
    assert storage_path(path) == path


def test_storage_path_accepts_windows_duckdb_uri():
    assert storage_path('duckdb://C:/data/firepit.db') == 'C:/data/firepit.db'


def test_storage_path_accepts_pathlike():
    path = pathlib.PureWindowsPath(r'C:\\data\\firepit.db')
    assert storage_path(path) == str(path)


def test_storage_path_rejects_other_schemes():
    with pytest.raises(NotImplementedError) as excinfo:
        storage_path('sqlite3:///tmp/firepit.db')
    assert excinfo.value.args == ('sqlite3',)


def test_storage_path_rejects_empty_duckdb_uri():
    with pytest.raises(ValueError):
        storage_path('duckdb://')
