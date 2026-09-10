import pytest

from firepit._stix import validate_object
from firepit.exceptions import InvalidObject


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
