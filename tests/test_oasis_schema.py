import pytest

from firepit._stix import standard_object_types, validate_object
from firepit.exceptions import InvalidObject


def test_oasis_registry_is_authoritative_for_standard_types():
    types = standard_object_types()
    assert "indicator" in types
    assert "threat-actor" in types
    assert "relationship" in types
    assert "process" in types
    assert "network-traffic" in types


def test_oasis_indicator_schema_is_enforced():
    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--11111111-1111-4111-8111-111111111111",
        "created": "2026-09-09T10:00:00Z",
        "modified": "2026-09-09T10:00:00Z",
        "pattern_type": "stix",
        "valid_from": "2026-09-09T10:00:00Z",
    }
    with pytest.raises(InvalidObject):
        validate_object(indicator)


def test_unknown_custom_object_keeps_raw_shape():
    custom = {
        "type": "x-example-event",
        "spec_version": "2.1",
        "id": "x-example-event--11111111-1111-4111-8111-111111111111",
        "vendor_field": {"score": 7},
    }
    assert validate_object(custom) is custom
