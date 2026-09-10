"""OASIS-backed STIX 2.1 validation for private ingestion."""

from functools import lru_cache

from firepit.exceptions import InvalidObject


@lru_cache(maxsize=1)
def _oasis():
    try:
        import stix2
        from stix2 import v21
        from stix2.properties import IDProperty, TypeProperty
    except ImportError as exc:
        raise RuntimeError(
            "STIX ingestion requires: python -m pip install 'firepit[ingest]'"
        ) from exc

    observables = frozenset(v21.OBJ_MAP_OBSERVABLE)
    standard = {**v21.OBJ_MAP, **v21.OBJ_MAP_OBSERVABLE}
    return stix2, standard, observables, IDProperty, TypeProperty


def _validate_type_and_id(obj_type: str, object_id: str):
    _, _, _, IDProperty, TypeProperty = _oasis()
    try:
        TypeProperty(obj_type, spec_version="2.1")
        IDProperty(obj_type, spec_version="2.1").clean(object_id)
    except (TypeError, ValueError) as exc:
        raise InvalidObject(str(exc)) from exc


def validate_bundle(bundle):
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise InvalidObject("expected a STIX bundle")

    if (bundle_id := bundle.get("id")) is not None:
        if not isinstance(bundle_id, str):
            raise InvalidObject("bundle id must be a string")
        _validate_type_and_id("bundle", bundle_id)

    objects = bundle.get("objects", [])
    if not isinstance(objects, list):
        raise InvalidObject("bundle.objects must be a list")
    return objects


def validate_object(obj):
    if not isinstance(obj, dict):
        raise InvalidObject("every bundle member must be a STIX object")

    obj_type = obj.get("type")
    object_id = obj.get("id")
    if not isinstance(obj_type, str):
        raise InvalidObject("every STIX object must provide a string type")
    if not isinstance(object_id, str):
        raise InvalidObject(f"{obj_type} must provide a string id")
    if obj_type == "bundle":
        raise InvalidObject("a STIX bundle cannot be nested in bundle.objects")

    stix2, standard, observables, _, _ = _oasis()
    _validate_type_and_id(obj_type, object_id)

    spec_version = obj.get("spec_version")
    if obj_type in standard and obj_type not in observables:
        if spec_version != "2.1":
            raise InvalidObject(f"{obj_type} must explicitly declare spec_version 2.1")
    elif spec_version not in (None, "2.1"):
        raise InvalidObject("Firepit accepts STIX 2.1 only")

    if obj_type == "observed-data" and "objects" in obj:
        raise InvalidObject(
            "embedded observed-data.objects is not supported; provide object_refs"
        )

    if obj_type in standard:
        try:
            stix2.parse(obj, allow_custom=True, version="2.1")
        except Exception as exc:
            raise InvalidObject(f"invalid {obj_type}: {exc}") from exc
    return obj
