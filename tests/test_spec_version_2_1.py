import os

import pytest

from firepit import get_storage
from firepit.exceptions import InvalidObject
from .helpers import tmp_storage


@pytest.fixture
def bundle_21():
    cwd = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(cwd, "spec_2_1_bundle.json")


def test_stix_21(bundle_21, tmpdir):
    store = tmp_storage(tmpdir)
    try:
        store.cache("q1", [bundle_21])

        types = store.types()
        assert "identity" in types
        assert "domain-name" in types
        assert "ipv4-addr" in types

        cols = store.columns("domain-name")
        assert "type" not in cols
        assert "spec_version" not in cols
        data = store.lookup("domain-name", cols=["id", "value"])
        assert data == [
            {
                "id": "domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7",
                "value": "example.com",
            }
        ]

        cols = store.columns("ipv4-addr")
        assert "type" not in cols
        assert "spec_version" not in cols
        data = store.lookup("ipv4-addr", cols=["id", "value"])
        assert data == [
            {
                "id": "ipv4-addr--28bb3599-77cd-5a82-a950-b5bc3caf07c4",
                "value": "198.51.100.3",
            }
        ]

        value_counts = store.value_counts("domain-name", "value")
        assert value_counts == [{"value": "example.com", "count": 1}]
        assert store.number_observed("domain-name", "value", "example.com") == 50

        value_counts = store.value_counts("ipv4-addr", "value")
        assert value_counts == [{"value": "198.51.100.3", "count": 1}]
        assert store.number_observed("ipv4-addr", "value", "198.51.100.3") == 50
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
        assert store.lookup("ipv4-addr", cols=["id", "value"]) == [
            {"id": ip_id, "value": "192.0.2.1"}
        ]
    finally:
        store.close()
