import duckdb
import pytest

from firepit import get_storage


def test_pre_native_database_is_rejected_explicitly(tmpdir):
    path = str(tmpdir.join("legacy.duckdb"))
    raw = duckdb.connect(path)
    raw.execute('CREATE SCHEMA hunt')
    raw.execute("SET search_path='hunt'")
    raw.execute('CREATE TABLE "__metadata" (name VARCHAR, value VARCHAR)')
    raw.execute('INSERT INTO "__metadata" VALUES (\'dbversion\', \'2.2\')')
    raw.close()

    with pytest.raises(RuntimeError, match="pre-native Firepit session"):
        get_storage(path, "hunt")
