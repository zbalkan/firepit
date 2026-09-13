import sys

import pytest

from firepit._stix import (
    _oasis,
    _patterns,
    indicator_observable,
    validate_bundle,
    validate_object,
)
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


def test_oasis_import_failure_is_reported_as_a_clear_runtime_error(monkeypatch):
    _oasis.cache_clear()
    monkeypatch.setitem(sys.modules, "stix2", None)
    try:
        with pytest.raises(RuntimeError, match=r"firepit\[ingest\]"):
            _oasis()
    finally:
        _oasis.cache_clear()


def test_patterns_import_failure_is_reported_as_a_clear_runtime_error(monkeypatch):
    _patterns.cache_clear()
    monkeypatch.setitem(sys.modules, "stix2patterns.v20.pattern", None)
    try:
        with pytest.raises(RuntimeError, match=r"firepit\[ingest\]"):
            _patterns()
    finally:
        _patterns.cache_clear()


def test_bundle_must_declare_bundle_type():
    with pytest.raises(InvalidObject, match="expected a STIX bundle"):
        validate_bundle({"type": "not-a-bundle", "objects": []})


def test_bundle_id_must_be_a_string():
    with pytest.raises(InvalidObject, match="bundle id must be a string"):
        validate_bundle({"type": "bundle", "id": 12345, "objects": []})


def test_bundle_objects_must_be_a_list():
    with pytest.raises(InvalidObject, match="bundle.objects must be a list"):
        validate_bundle({"type": "bundle", "objects": "not-a-list"})


def test_non_dict_bundle_member_is_rejected():
    with pytest.raises(InvalidObject, match="every bundle member must be a STIX object"):
        validate_object("not-a-dict")


def test_object_type_must_be_a_string():
    with pytest.raises(InvalidObject, match="must provide a string type"):
        validate_object({"type": 1, "id": "indicator--11111111-1111-4111-8111-111111111111"})


def test_object_id_must_be_a_string():
    with pytest.raises(InvalidObject, match="must provide a string id"):
        validate_object({"type": "indicator", "id": 1})


def test_nested_bundle_is_rejected():
    with pytest.raises(InvalidObject, match="cannot be nested"):
        validate_object({
            "type": "bundle",
            "id": "bundle--11111111-1111-4111-8111-111111111111",
        })


def test_malformed_object_id_is_rejected():
    with pytest.raises(InvalidObject):
        validate_object({
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--not-a-valid-uuid",
            "created": "2026-09-09T10:00:00Z",
            "modified": "2026-09-09T10:00:00Z",
            "name": "bad id",
            "identity_class": "organization",
        })


def test_standard_non_observable_requires_explicit_spec_version():
    with pytest.raises(InvalidObject, match="must explicitly declare spec_version 2.1"):
        validate_object({
            "type": "threat-actor",
            "id": "threat-actor--11111111-1111-4111-8111-111111111111",
            "created": "2026-09-09T10:00:00Z",
            "modified": "2026-09-09T10:00:00Z",
            "name": "no spec version",
        })


def test_embedded_observed_data_objects_is_rejected():
    with pytest.raises(InvalidObject, match="embedded observed-data.objects"):
        validate_object({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": "observed-data--11111111-1111-4111-8111-111111111111",
            "created": "2026-09-09T10:00:00Z",
            "modified": "2026-09-09T10:00:00Z",
            "first_observed": "2026-09-09T10:00:00Z",
            "last_observed": "2026-09-09T10:00:00Z",
            "number_observed": 1,
            "objects": {"0": {"type": "ipv4-addr", "value": "192.0.2.1"}},
        })


def test_indicator_observable_ignores_non_string_pattern():
    obj = {"type": "indicator", "pattern_type": "stix", "pattern": 123}
    assert indicator_observable(obj) == (None, None)


def test_indicator_observable_ignores_unknown_pattern_version():
    obj = {
        "type": "indicator",
        "pattern_type": "stix",
        "pattern": "[ipv4-addr:value = '192.0.2.1']",
        "pattern_version": "9.9",
    }
    assert indicator_observable(obj) == (None, None)


def test_indicator_observable_rejects_unparseable_pattern():
    obj = {
        "type": "indicator",
        "pattern_type": "stix",
        "pattern": "[ipv4-addr:value = ",
    }
    with pytest.raises(InvalidObject, match="invalid STIX pattern"):
        indicator_observable(obj)


def test_indicator_observable_ignores_non_equality_comparison():
    obj = {
        "type": "indicator",
        "pattern_type": "stix",
        "pattern": "[ipv4-addr:value != '192.0.2.1']",
    }
    assert indicator_observable(obj) == (None, None)


def test_indicator_observable_ignores_unquoted_value():
    obj = {
        "type": "indicator",
        "pattern_type": "stix",
        "pattern": "[network-traffic:src_port = 22]",
    }
    assert indicator_observable(obj) == (None, None)
