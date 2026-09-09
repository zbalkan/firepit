import json

import pytest

from firepit import get_storage
from firepit.exceptions import InvalidObject


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
        row = store.connection.execute(
            'SELECT protocols, typeof(protocols) FROM "network-traffic"'
        ).fetchone()
        assert row == (["tcp"], "VARCHAR[]")

        row = store.connection.execute(
            'SELECT hashes, typeof(hashes) FROM "file"'
        ).fetchone()
        assert row[0]["SHA-256"] == "0123456789abcdef"
        assert row[1] == "MAP(VARCHAR, VARCHAR)"

        row = store.connection.execute(
            'SELECT "values", typeof("values") FROM "windows-registry-key"'
        ).fetchone()
        assert row[0][0]["name"] == "Enabled"
        assert row[0][0]["data_type"] == "REG_DWORD"
        assert row[1].startswith("STRUCT(")
        assert row[1].endswith("[]")

        row = store.connection.execute(
            'SELECT environment_variables FROM "process"'
        ).fetchone()
        assert row[0]["TEMP"] == "C:\\Temp"
    finally:
        store.close()


def test_raw_json_text_is_projected_by_duckdb(tmpdir):
    store = get_storage(str(tmpdir.join("native-json.duckdb")), "hunt")
    try:
        store.cache("q1", json.dumps(_bundle()))
        row = store.connection.execute(
            'SELECT pid, typeof(pid), child_refs, typeof(child_refs) FROM "process"'
        ).fetchone()
        assert row[0] == 4242
        assert row[1] == "UBIGINT"
        assert row[2] == ["process--22222222-2222-4222-8222-222222222222"]
        assert row[3] == "VARCHAR[]"
    finally:
        store.close()


def test_unknown_fields_remain_in_raw_json_without_schema_growth(tmpdir):
    store = get_storage(str(tmpdir.join("native.duckdb")), "hunt")
    try:
        store.cache("q1", _bundle())
        columns = {
            row[1]
            for row in store.connection.execute('PRAGMA table_info("process")').fetchall()
        }
        assert "x_vendor_context" not in columns
        row = store.connection.execute(
            "SELECT json_extract(_raw, '$.x_vendor_context.score') FROM \"process\""
        ).fetchone()
        assert str(row[0]) == "7"
    finally:
        store.close()


def test_native_storage_reopens_same_session(tmpdir):
    path = str(tmpdir.join("native.duckdb"))
    store = get_storage(path, "hunt")
    store.cache("q1", _bundle())
    store.close()

    reopened = get_storage(path, "hunt")
    try:
        assert reopened.connection.execute(
            'SELECT count(*) FROM "network-traffic"'
        ).fetchone()[0] == 1
    finally:
        reopened.close()


def test_known_schema_type_mismatch_fails_instead_of_becoming_null(tmpdir):
    bundle = {
        "type": "bundle",
        "objects": [{
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "src_port": "not-a-port",
            "protocols": ["tcp"],
        }],
    }
    store = get_storage(str(tmpdir.join("strict.duckdb")), "hunt")
    try:
        with pytest.raises(InvalidObject, match="incompatible with the STIX schema"):
            store.cache("bad", bundle)
        row = store.connection.execute(
            'SELECT status, error FROM "raw_query" WHERE query_id = ?',
            ("bad",),
        ).fetchone()
        assert row[0] == "FAILED"
        assert "incompatible" in row[1]
    finally:
        store.close()


def test_reingesting_same_observed_data_id_is_idempotent(tmpdir):
    ip = "ipv4-addr--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    obs = "observed-data--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "ipv4-addr", "spec_version": "2.1", "id": ip, "value": "192.0.2.1"},
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": obs,
                "first_observed": "2026-09-09T10:00:00Z",
                "last_observed": "2026-09-09T10:00:00Z",
                "number_observed": 3,
                "object_refs": [ip],
            },
        ],
    }
    store = get_storage(str(tmpdir.join("idempotent.duckdb")), "hunt")
    try:
        store.cache("q1", bundle)
        store.cache("q2", bundle)
        row = store.connection.execute(
            'SELECT observation_records, observation_count '
            'FROM "observation_summary" WHERE object_ref = ?',
            (ip,),
        ).fetchone()
        assert row == (1, 3)
    finally:
        store.close()
