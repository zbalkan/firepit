import json

import pytest

import firepit.storage as storage_module
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


def _ipv4_bundle(value="192.0.2.1"):
    return {
        "type": "bundle",
        "id": "bundle--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "objects": [
            {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": "ipv4-addr--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "value": value,
            }
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


def test_missing_object_type_is_rejected(tmpdir):
    bundle = {
        "type": "bundle",
        "objects": [{"id": "ipv4-addr--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}],
    }
    store = get_storage(str(tmpdir.join("missing-type.duckdb")), "hunt")
    try:
        with pytest.raises(InvalidObject, match="provide type"):
            store.cache("q1", bundle)
    finally:
        store.close()


def test_invalid_object_type_is_rejected(tmpdir):
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "Bad_Type",
                "spec_version": "2.1",
                "id": "Bad_Type--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            }
        ],
    }
    store = get_storage(str(tmpdir.join("invalid-type.duckdb")), "hunt")
    try:
        with pytest.raises(InvalidObject, match="invalid STIX object type"):
            store.cache("q1", bundle)
    finally:
        store.close()


def test_object_id_must_match_type(tmpdir):
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": "file--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "value": "192.0.2.1",
            }
        ],
    }
    store = get_storage(str(tmpdir.join("id-mismatch.duckdb")), "hunt")
    try:
        with pytest.raises(InvalidObject, match="does not match object type"):
            store.cache("q1", bundle)
    finally:
        store.close()


def test_non_sco_without_spec_version_is_rejected(tmpdir):
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "identity",
                "id": "identity--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "identity_class": "organization",
                "name": "Example",
            }
        ],
    }
    store = get_storage(str(tmpdir.join("missing-version.duckdb")), "hunt")
    try:
        with pytest.raises(InvalidObject, match="explicitly declare spec_version 2.1"):
            store.cache("q1", bundle)
    finally:
        store.close()


def test_duplicate_query_id_does_not_mutate_previous_run(tmpdir):
    store = get_storage(str(tmpdir.join("duplicate-query.duckdb")), "hunt")
    try:
        store.cache("q1", _ipv4_bundle(), source="source-a")
        with pytest.raises(InvalidObject, match="already exists"):
            store.cache("q1", _ipv4_bundle("192.0.2.2"), source="source-b")

        row = store.connection.execute(
            'SELECT source, status, result_count FROM "raw_query" WHERE query_id = ?',
            ("q1",),
        ).fetchone()
        assert row == ("source-a", "COMPLETED", 1)
        assert store.connection.execute(
            'SELECT COUNT(*) FROM "raw_bundle" WHERE query_id = ?', ("q1",)
        ).fetchone()[0] == 1
    finally:
        store.close()


def test_older_version_does_not_overwrite_newer_object(tmpdir):
    object_id = "identity--cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    newer = {
        "type": "bundle",
        "objects": [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": object_id,
                "created": "2026-09-09T10:00:00Z",
                "modified": "2026-09-09T12:00:00Z",
                "identity_class": "organization",
                "name": "New Name",
            }
        ],
    }
    older = {
        "type": "bundle",
        "objects": [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": object_id,
                "created": "2026-09-09T10:00:00Z",
                "modified": "2026-09-09T11:00:00Z",
                "identity_class": "organization",
                "name": "Old Name",
            }
        ],
    }
    store = get_storage(str(tmpdir.join("versions.duckdb")), "hunt")
    try:
        store.cache("newer", newer)
        store.cache("older", older)
        row = store.connection.execute(
            'SELECT name FROM "identity" WHERE id = ?', (object_id,)
        ).fetchone()
        assert row == ("New Name",)
    finally:
        store.close()


def test_view_install_failure_rolls_back_ingestion(tmpdir, monkeypatch):
    store = get_storage(str(tmpdir.join("view-failure.duckdb")), "hunt")
    try:
        def fail_views(*_args, **_kwargs):
            raise RuntimeError("view refresh failed")

        monkeypatch.setattr(storage_module, "install_views", fail_views)
        with pytest.raises(RuntimeError, match="view refresh failed"):
            store.cache("q1", _ipv4_bundle())

        assert store.connection.execute(
            'SELECT status FROM "raw_query" WHERE query_id = ?', ("q1",)
        ).fetchone() == ("FAILED",)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema = 'hunt' AND table_name = 'ipv4-addr'"
        ).fetchone()[0] == 0
        assert store.connection.execute(
            'SELECT COUNT(*) FROM "raw_bundle" WHERE query_id = ?', ("q1",)
        ).fetchone()[0] == 0
    finally:
        store.close()
