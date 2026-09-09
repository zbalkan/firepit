import os

import pytest

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
