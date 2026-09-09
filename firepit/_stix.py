"""OASIS-backed STIX 2.1 validation for the private ingestion path.

The query-only Firepit runtime does not import ``stix2``. Acquisition installs
the optional ``ingest`` extra and this module uses cti-python-stix2 as the
authoritative source for standard STIX object definitions and constraints.
"""

from __future__ import annotations

from firepit.exceptions import InvalidObject


def _oasis():
    try:
        import stix2
        from stix2 import v21
        from stix2.properties import IDProperty, TypeProperty
    except ImportError as exc:
        raise RuntimeError(
            "STIX ingestion requires the optional dependency set: "
            "python -m pip install 'firepit[ingest]'"
        ) from exc
    return stix2, v21, IDProperty, TypeProperty


def _validate_type_and_id(obj_type: str, object_id: str):
    _, _, IDProperty, TypeProperty = _oasis()
    try:
        TypeProperty(obj_type, spec_version="2.1")
        IDProperty(obj_type, spec_version="2.1").clean(object_id)
    except (TypeError, ValueError) as exc:
        raise InvalidObject(str(exc)) from exc


def validate_bundle(bundle):
    """Validate the bundle envelope and return its member objects."""
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise InvalidObject("expected a STIX bundle")

    bundle_id = bundle.get("id")
    if bundle_id is not None:
        if not isinstance(bundle_id, str):
            raise InvalidObject("bundle id must be a string")
        _validate_type_and_id("bundle", bundle_id)

    objects = bundle.get("objects", [])
    if not isinstance(objects, list):
        raise InvalidObject("bundle.objects must be a list")
    return objects


def validate_object(obj):
    """Validate one STIX 2.1 object with the OASIS reference library.

    Unknown custom object types are intentionally retained as dictionaries
    because cti-python-stix2 has no schema with which to validate them. Their
    type and identifier are still checked against STIX 2.1 naming rules.
    """
    if not isinstance(obj, dict):
        raise InvalidObject("every bundle member must be a STIX object")

    stix2, v21, _, _ = _oasis()
    obj_type = obj.get("type")
    object_id = obj.get("id")
    if not isinstance(obj_type, str):
        raise InvalidObject("every STIX object must provide a string type")
    if not isinstance(object_id, str):
        raise InvalidObject(f"{obj_type} must provide a string id")

    _validate_type_and_id(obj_type, object_id)

    observables = v21.OBJ_MAP_OBSERVABLE
    standard = {**v21.OBJ_MAP, **observables}
    if obj_type == "bundle":
        raise InvalidObject("a STIX bundle cannot be nested in bundle.objects")

    spec_version = obj.get("spec_version")
    if obj_type in observables:
        if spec_version not in (None, "2.1"):
            raise InvalidObject("Firepit accepts STIX 2.1 only")
    elif obj_type in standard:
        if spec_version != "2.1":
            raise InvalidObject(
                f"{obj_type} must explicitly declare spec_version 2.1"
            )
    elif spec_version not in (None, "2.1"):
        raise InvalidObject("Firepit accepts STIX 2.1 only")

    if obj_type == "observed-data" and "objects" in obj:
        raise InvalidObject(
            "embedded observed-data.objects is not supported; "
            "provide STIX 2.1 observed-data.object_refs"
        )

    if obj_type in standard:
        try:
            stix2.parse(obj, allow_custom=True, version="2.1")
        except Exception as exc:
            raise InvalidObject(f"invalid {obj_type}: {exc}") from exc

    return obj


def standard_object_types():
    """Return standard STIX 2.1 object type names from cti-python-stix2."""
    _, v21, _, _ = _oasis()
    return frozenset(
        type_name
        for type_name in {*v21.OBJ_MAP, *v21.OBJ_MAP_OBSERVABLE}
        if type_name != "bundle"
    )
