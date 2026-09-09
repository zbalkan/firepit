import json

import pytest

from firepit import get_storage
from firepit._writer import ingest
from firepit.exceptions import InvalidObject


def _indicator(*, object_id=None, pattern=True):
    obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": object_id or "indicator--11111111-1111-4111-8111-111111111111",
        "created": "2026-09-09T10:00:00Z",
        "modified": "2026-09-09T10:00:00Z",
        "pattern_type": "stix",
        "valid_from": "2026-09-09T10:00:00Z",
    }
    if pattern:
        obj["pattern"] = "[ipv4-addr:value = '192.0.2.1']"
    return obj


def _bundle(*objects):
    return {"type": "bundle", "objects": list(objects)}


def _data_name(store, stix_type):
    row = store.query_one(
        "SELECT json_extract_string(Data, '$.name') AS Name "
        'FROM "ThreatIntelObjects" WHERE StixType = ?',
        (stix_type,),
    )
    return row["Name"]


def test_oasis_validation_rejects_invalid_standard_object(tmpdir):
    path = str(tmpdir.join("ingest.duckdb"))
    with pytest.raises(InvalidObject):
        ingest(path, "q1", _bundle(_indicator(pattern=False)), session_id="hunt")


def test_explicit_stix_20_is_rejected(tmpdir):
    path = str(tmpdir.join("ingest.duckdb"))
    obj = {
        "type": "ipv4-addr",
        "spec_version": "2.0",
        "id": "ipv4-addr--11111111-1111-4111-8111-111111111111",
        "value": "192.0.2.1",
    }
    with pytest.raises(InvalidObject, match="2.1"):
        ingest(path, "q1", _bundle(obj), session_id="hunt")


def test_custom_object_is_preserved_in_objects_view(tmpdir):
    path = str(tmpdir.join("custom.duckdb"))
    obj = {
        "type": "x-example-event",
        "spec_version": "2.1",
        "id": "x-example-event--11111111-1111-4111-8111-111111111111",
        "vendor_field": {"score": 7},
    }
    ingest(path, "q1", _bundle(obj), session_id="hunt", source="custom-feed")

    with get_storage(path, "hunt") as store:
        row = store.query_one(
            'SELECT Data, SourceSystem FROM "ThreatIntelObjects" '
            "WHERE StixType = 'x-example-event'"
        )
        data = json.loads(row["Data"]) if isinstance(row["Data"], str) else row["Data"]
        assert data["vendor_field"] == {"score": 7}
        assert row["SourceSystem"] == "custom-feed"


def test_duplicate_query_id_is_rejected(tmpdir):
    path = str(tmpdir.join("runs.duckdb"))
    bundle = _bundle(_indicator())
    ingest(path, "q1", bundle, session_id="hunt")
    with pytest.raises(InvalidObject, match="already exists"):
        ingest(path, "q1", bundle, session_id="hunt")


def test_newest_modified_version_is_canonical_independent_of_arrival_order(tmpdir):
    path = str(tmpdir.join("versions.duckdb"))
    actor_id = "threat-actor--22222222-2222-4222-8222-222222222222"
    newer = {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": actor_id,
        "created": "2026-09-09T10:00:00Z",
        "modified": "2026-09-10T10:00:00Z",
        "name": "New Name",
        "threat_actor_types": ["crime-syndicate"],
    }
    older = {
        **newer,
        "modified": "2026-09-09T10:00:00Z",
        "name": "Old Name",
    }

    ingest(path, "new", _bundle(newer), session_id="hunt")
    ingest(path, "old", _bundle(older), session_id="hunt")

    with get_storage(path, "hunt") as store:
        assert _data_name(store, "threat-actor") == "New Name"


def test_conflicting_same_modified_version_is_rejected(tmpdir):
    path = str(tmpdir.join("versions.duckdb"))
    actor_id = "threat-actor--22222222-2222-4222-8222-222222222222"
    first = {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": actor_id,
        "created": "2026-09-09T10:00:00Z",
        "modified": "2026-09-09T10:00:00Z",
        "name": "Name A",
        "threat_actor_types": ["crime-syndicate"],
    }
    second = {**first, "name": "Name B"}

    ingest(path, "q1", _bundle(first), session_id="hunt")
    with pytest.raises(InvalidObject, match="same modified timestamp"):
        ingest(path, "q2", _bundle(second), session_id="hunt")


def test_immutable_sco_id_cannot_change_content(tmpdir):
    path = str(tmpdir.join("immutable.duckdb"))
    object_id = "ipv4-addr--33333333-3333-4333-8333-333333333333"
    first = {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": object_id,
        "value": "192.0.2.1",
    }
    second = {**first, "value": "192.0.2.2"}

    ingest(path, "q1", _bundle(first), session_id="hunt")
    with pytest.raises(InvalidObject, match="immutable id"):
        ingest(path, "q2", _bundle(second), session_id="hunt")
