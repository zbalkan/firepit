import os

import pytest

from firepit import get_storage
from firepit.exceptions import InvalidObject


@pytest.fixture
def bundle_21():
    cwd = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(cwd, "spec_2_1_bundle.json")


def test_stix_21(bundle_21, tmpdir):
    store = get_storage(str(tmpdir.join("stix21.duckdb")), "hunt")
    try:
        store.cache("q1", bundle_21)

        tables = {
            row[0]
            for row in store.connection.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = ? AND table_type = 'BASE TABLE'",
                ("hunt",),
            ).fetchall()
        }
        assert {"identity", "domain-name", "ipv4-addr"} <= tables

        domain = store.connection.execute(
            'SELECT id, value FROM "domain-name"'
        ).fetchone()
        assert domain == (
            "domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7",
            "example.com",
        )

        ip = store.connection.execute(
            'SELECT id, value FROM "ipv4-addr"'
        ).fetchone()
        assert ip == (
            "ipv4-addr--28bb3599-77cd-5a82-a950-b5bc3caf07c4",
            "198.51.100.3",
        )

        rows = store.connection.execute(
            'SELECT object_ref, observation_records, observation_count '
            'FROM "observation_summary" ORDER BY object_ref'
        ).fetchall()
        by_ref = {row[0]: row[1:] for row in rows}
        assert by_ref[domain[0]] == (1, 50)
        assert by_ref[ip[0]] == (1, 50)
    finally:
        store.close()


def test_explicit_stix_20_is_rejected(tmpdir):
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "ipv4-addr",
                "spec_version": "2.0",
                "id": "ipv4-addr--11111111-1111-4111-8111-111111111111",
                "value": "192.0.2.1",
            }
        ],
    }
    store = get_storage(str(tmpdir.join("reject-version.duckdb")), "hunt")
    try:
        with pytest.raises(InvalidObject, match="STIX 2.1 only"):
            store.cache("q1", bundle)
    finally:
        store.close()


def test_embedded_observed_data_objects_are_rejected(tmpdir):
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": "observed-data--11111111-1111-4111-8111-111111111111",
                "first_observed": "2026-09-09T10:00:00Z",
                "last_observed": "2026-09-09T10:00:00Z",
                "number_observed": 1,
                "objects": {"0": {"type": "ipv4-addr", "value": "192.0.2.1"}},
            }
        ],
    }
    store = get_storage(str(tmpdir.join("reject-20.duckdb")), "hunt")
    try:
        with pytest.raises(InvalidObject, match="object_refs"):
            store.cache("q1", bundle)
    finally:
        store.close()


def test_sco_without_spec_version_is_valid_stix_21_input(tmpdir):
    ip_id = "ipv4-addr--11111111-1111-4111-8111-111111111111"
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "ipv4-addr",
                "id": ip_id,
                "value": "192.0.2.1",
            }
        ],
    }
    store = get_storage(str(tmpdir.join("sco-no-version.duckdb")), "hunt")
    try:
        store.cache("q1", bundle)
        assert store.connection.execute(
            'SELECT id, value FROM "ipv4-addr"'
        ).fetchone() == (ip_id, "192.0.2.1")
    finally:
        store.close()


def test_object_without_id_is_rejected(tmpdir):
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "value": "192.0.2.1",
            }
        ],
    }
    store = get_storage(str(tmpdir.join("missing-id.duckdb")), "hunt")
    try:
        with pytest.raises(InvalidObject, match="provide id"):
            store.cache("q1", bundle)
    finally:
        store.close()
