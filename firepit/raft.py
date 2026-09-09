#!/usr/bin/env python

"""Minimal STIX 2.1 object extraction for the transition to DuckDB JSON ingestion."""

import json

from firepit.exceptions import InvalidObject


def _validate_object(obj):
    if not isinstance(obj, dict):
        raise InvalidObject("STIX bundle objects must be JSON objects")

    spec_version = obj.get("spec_version")
    if spec_version is not None and spec_version != "2.1":
        raise InvalidObject(
            f"Firepit accepts STIX 2.1 only; got spec_version {spec_version!r}"
        )

    if obj.get("type") == "observed-data" and "objects" in obj:
        raise InvalidObject(
            "embedded observed-data.objects is not supported; "
            "provide STIX 2.1 observed-data.object_refs"
        )

    return obj


def _yield_objects(bundle, types=None):
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise InvalidObject("expected a STIX bundle")

    for obj in bundle.get("objects", []):
        obj = _validate_object(obj)
        if not types or obj.get("type") in types:
            yield obj


def get_objects(source, types=None):
    """Yield STIX 2.1 objects from an in-memory bundle, JSON text, or local file."""
    if isinstance(source, dict):
        bundle = source
    elif hasattr(source, "read"):
        data = source.read()
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        bundle = json.loads(data)
    elif isinstance(source, str):
        if source.lstrip().startswith("{"):
            bundle = json.loads(source)
        else:
            with open(source, "r", encoding="utf-8") as fp:
                bundle = json.load(fp)
    else:
        raise TypeError("source must be a dict, JSON string, file-like object, or path")

    yield from _yield_objects(bundle, types)


def upgrade_2021(_obs):
    """Retained only as a fail-fast compatibility hook during Phase 7."""
    raise InvalidObject(
        "STIX 2.0 observed-data upgrade has been removed; provide STIX 2.1 input"
    )
