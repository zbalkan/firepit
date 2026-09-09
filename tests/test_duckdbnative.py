from firepit import get_storage


def _bundle():
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "network-traffic",
                "spec_version": "2.1",
                "id": "network-traffic--11111111-1111-4111-8111-111111111111",
                "src_port": 49152,
                "dst_port": 443,
                "protocols": ["tcp"],
                "src_byte_count": 1024,
            },
            {
                "type": "file",
                "spec_version": "2.1",
                "id": "file--11111111-1111-4111-8111-111111111111",
                "name": "sample.exe",
                "hashes": {
                    "SHA-256": "0123456789abcdef",
                    "MD5": "0123456789abcdef0123456789abcdef",
                },
            },
            {
                "type": "windows-registry-key",
                "spec_version": "2.1",
                "id": "windows-registry-key--11111111-1111-4111-8111-111111111111",
                "key": "HKEY_LOCAL_MACHINE\\Software\\Example",
                "values": [
                    {"name": "Enabled", "data": "1", "data_type": "REG_DWORD"}
                ],
            },
            {
                "type": "process",
                "spec_version": "2.1",
                "id": "process--11111111-1111-4111-8111-111111111111",
                "pid": 4242,
                "environment_variables": {"TEMP": "C:\\Temp"},
                "child_refs": [
                    "process--22222222-2222-4222-8222-222222222222"
                ],
                "x_vendor_context": {"score": 7},
            },
        ],
    }


def test_native_storage_preserves_nested_types(tmpdir):
    store = get_storage(str(tmpdir.join("native.duckdb")), "hunt")
    try:
        store.cache("q1", _bundle())

        row = store._query(
            'SELECT protocols, typeof(protocols) AS dtype FROM "network-traffic"'
        ).fetchone()
        assert row["protocols"] == ["tcp"]
        assert row["dtype"] == "VARCHAR[]"

        row = store._query(
            'SELECT hashes, typeof(hashes) AS dtype FROM "file"'
        ).fetchone()
        assert row["hashes"]["SHA-256"] == "0123456789abcdef"
        assert row["dtype"] == "MAP(VARCHAR, VARCHAR)"

        row = store._query(
            'SELECT "values", typeof("values") AS dtype '
            'FROM "windows-registry-key"'
        ).fetchone()
        assert row["values"][0]["name"] == "Enabled"
        assert row["values"][0]["data_type"] == "REG_DWORD"
        assert row["dtype"].startswith("STRUCT(")
        assert row["dtype"].endswith("[]")

        row = store._query(
            'SELECT environment_variables FROM "process"'
        ).fetchone()
        assert row["environment_variables"]["TEMP"] == "C:\\Temp"
    finally:
        store.close()


def test_unknown_fields_remain_in_raw_json_without_schema_growth(tmpdir):
    store = get_storage(str(tmpdir.join("native.duckdb")), "hunt")
    try:
        store.cache("q1", _bundle())
        assert "x_vendor_context" not in store.columns("process")
        row = store._query(
            'SELECT json_extract(_raw, \'$.x_vendor_context.score\') AS score '
            'FROM "process"'
        ).fetchone()
        assert str(row["score"]) == "7"
    finally:
        store.close()


def test_native_storage_reopens_same_session(tmpdir):
    path = str(tmpdir.join("native.duckdb"))
    store = get_storage(path, "hunt")
    store.cache("q1", _bundle())
    store.close()

    reopened = get_storage(path, "hunt")
    try:
        row = reopened._query(
            'SELECT count(*) AS count FROM "network-traffic"'
        ).fetchone()
        assert row["count"] == 1
    finally:
        reopened.close()
