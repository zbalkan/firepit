import json

from firepit import get_storage
from firepit._writer import ingest


_INDICATOR_COLUMNS = [
    "AdditionalFields",
    "AzureTenantId",
    "_BilledSize",
    "Confidence",
    "Created",
    "Data",
    "Id",
    "IsActive",
    "_IsBillable",
    "IsDeleted",
    "LastUpdateMethod",
    "Modified",
    "ObservableKey",
    "ObservableValue",
    "Pattern",
    "_ResourceId",
    "Revoked",
    "SourceSystem",
    "_SubscriptionId",
    "Tags",
    "TenantId",
    "TimeGenerated",
    "Type",
    "ValidFrom",
    "ValidUntil",
    "WorkspaceId",
]

_OBJECT_COLUMNS = [
    "AdditionalFields",
    "AzureTenantId",
    "_BilledSize",
    "Data",
    "Id",
    "_IsBillable",
    "IsDeleted",
    "LastUpdateMethod",
    "_ResourceId",
    "SourceSystem",
    "StixType",
    "_SubscriptionId",
    "TenantId",
    "TimeGenerated",
    "Type",
    "WorkspaceId",
]


def _bundle():
    indicator_id = "indicator--11111111-1111-4111-8111-111111111111"
    actor_id = "threat-actor--22222222-2222-4222-8222-222222222222"
    relationship_id = "relationship--33333333-3333-4333-8333-333333333333"
    ipv4_id = "ipv4-addr--44444444-4444-4444-8444-444444444444"
    observed_1 = "observed-data--55555555-5555-4555-8555-555555555555"
    observed_2 = "observed-data--66666666-6666-4666-8666-666666666666"
    file_id = "file--77777777-7777-4777-8777-777777777777"
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": "2026-09-09T10:00:00Z",
                "modified": "2026-09-09T10:00:00Z",
                "name": "Test IP",
                "description": "Test indicator",
                "indicator_types": ["malicious-activity"],
                "pattern": "[ipv4-addr:value = '192.0.2.1']",
                "pattern_type": "stix",
                "valid_from": "2026-09-09T10:00:00Z",
                "confidence": 85,
                "labels": ["test", "ip"],
            },
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": actor_id,
                "created": "2026-09-09T10:00:00Z",
                "modified": "2026-09-09T10:00:00Z",
                "name": "Example Actor",
                "threat_actor_types": ["crime-syndicate"],
                "aliases": ["Example Group"],
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": relationship_id,
                "created": "2026-09-09T10:00:00Z",
                "modified": "2026-09-09T10:00:00Z",
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": actor_id,
            },
            {
                "type": "ipv4-addr",
                "id": ipv4_id,
                "value": "192.0.2.1",
            },
            {
                "type": "file",
                "id": file_id,
                "name": "sample.bin",
                "size": 42,
                "hashes": {"SHA-256": "a" * 64},
            },
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": observed_1,
                "created": "2026-09-09T10:01:00Z",
                "modified": "2026-09-09T10:01:00Z",
                "first_observed": "2026-09-09T09:00:00Z",
                "last_observed": "2026-09-09T10:00:00Z",
                "number_observed": 2,
                "object_refs": [ipv4_id],
            },
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": observed_2,
                "created": "2026-09-09T11:01:00Z",
                "modified": "2026-09-09T11:01:00Z",
                "first_observed": "2026-09-09T10:30:00Z",
                "last_observed": "2026-09-09T11:00:00Z",
                "number_observed": 3,
                "object_refs": [ipv4_id],
            },
        ],
    }


def _as_json(value):
    return json.loads(value) if isinstance(value, str) else value


def _seed(path):
    ingest(path, "run-1", _bundle(), session_id="hunt", source="test-feed")


def test_base_indicator_view_remains_sentinel_compatible(tmpdir):
    path = str(tmpdir.join("views.duckdb"))
    _seed(path)

    with get_storage(path, "hunt") as store:
        row = store.query_one('SELECT * FROM "ThreatIntelIndicators"')
        assert list(row) == _INDICATOR_COLUMNS
        assert row["Confidence"] == 85
        assert row["IsDeleted"] is False
        assert row["Revoked"] is False
        assert row["SourceSystem"] == "test-feed"
        assert row["Pattern"] == "[ipv4-addr:value = '192.0.2.1']"
        assert row["ObservableKey"] == "ipv4-addr:value"
        assert row["ObservableValue"] == "192.0.2.1"
        assert row["Type"] == "ThreatIntelIndicators"
        assert set(row["Tags"].split(",")) == {"test", "ip"}

        data = _as_json(row["Data"])
        assert data["id"] == row["Id"]
        assert data["indicator_types"] == ["malicious-activity"]


def test_base_objects_view_remains_sentinel_compatible(tmpdir):
    path = str(tmpdir.join("views.duckdb"))
    _seed(path)

    with get_storage(path, "hunt") as store:
        rows = store.query('SELECT * FROM "ThreatIntelObjects" ORDER BY StixType, Id')
        assert len(rows) == 6
        assert list(rows[0]) == _OBJECT_COLUMNS
        assert "indicator" not in {row["StixType"] for row in rows}
        assert all(row["IsDeleted"] is False for row in rows)
        assert all(row["Type"] == "ThreatIntelObjects" for row in rows)


def test_relationship_and_actor_extended_views_remove_bidirectional_joins(tmpdir):
    path = str(tmpdir.join("views.duckdb"))
    _seed(path)

    with get_storage(path, "hunt") as store:
        relationship = store.query_one('SELECT * FROM "ThreatIntelRelationshipsEx"')
        assert relationship["RelationshipType"] == "indicates"
        assert relationship["SourceStixType"] == "indicator"
        assert relationship["SourceName"] == "Test IP"
        assert relationship["TargetStixType"] == "threat-actor"
        assert relationship["TargetName"] == "Example Actor"

        actor_link = store.query_one('SELECT * FROM "ThreatIntelActorRelationsEx"')
        assert actor_link["ThreatActorName"] == "Example Actor"
        assert actor_link["ThreatActorDirection"] == "target"
        assert actor_link["RelatedStixType"] == "indicator"
        assert actor_link["RelatedName"] == "Test IP"
        assert actor_link["RelatedPattern"] == "[ipv4-addr:value = '192.0.2.1']"


def test_observation_extended_views_replace_timestamp_summary_and_counts(tmpdir):
    path = str(tmpdir.join("views.duckdb"))
    _seed(path)

    with get_storage(path, "hunt") as store:
        rows = store.query(
            'SELECT ObservationId, ObjectId, NumberObserved '
            'FROM "ThreatIntelObservationsEx" ORDER BY ObservationId'
        )
        assert len(rows) == 2
        assert {row["NumberObserved"] for row in rows} == {2, 3}

        summary = store.query_one(
            'SELECT * FROM "ThreatIntelObservationSummaryEx" '
            "WHERE ObservableValue = '192.0.2.1'"
        )
        assert summary["ObservationRecords"] == 2
        assert summary["ObservationCount"] == 5
        assert str(summary["FirstObserved"]).startswith("2026-09-09 09:00:00")
        assert str(summary["LastObserved"]).startswith("2026-09-09 11:00:00")


def test_observable_extended_views_replace_common_value_counts(tmpdir):
    path = str(tmpdir.join("views.duckdb"))
    _seed(path)

    with get_storage(path, "hunt") as store:
        observable = store.query_one(
            'SELECT * FROM "ThreatIntelObservablesEx" '
            "WHERE ObservableKey = 'ipv4-addr:value'"
        )
        assert observable["ObservableValue"] == "192.0.2.1"

        file_hash = store.query_one(
            'SELECT ObservableValue FROM "ThreatIntelObservablesEx" '
            "WHERE ObservableKey = 'file:hashes.SHA-256'"
        )
        assert file_hash["ObservableValue"] == "a" * 64

        stats = store.query_one(
            'SELECT * FROM "ThreatIntelObservableStatsEx" '
            "WHERE ObservableKey = 'ipv4-addr:value' "
            "AND ObservableValue = '192.0.2.1'"
        )
        assert stats["ObjectCount"] == 1
        assert stats["ObservationRecords"] == 2
        assert stats["ObservationCount"] == 5


def test_wide_indicator_view_flattens_common_hunting_fields_and_actor_links(tmpdir):
    path = str(tmpdir.join("views.duckdb"))
    _seed(path)

    with get_storage(path, "hunt") as store:
        row = store.query_one('SELECT * FROM "ThreatIntelIndicatorsW"')
        assert row["IndicatorId"].startswith("indicator--")
        assert row["StixType"] == "indicator"
        assert row["Name"] == "Test IP"
        assert row["Description"] == "Test indicator"
        assert row["ThreatType"] == "malicious-activity"
        assert row["IndicatorTypes"] == ["malicious-activity"]
        assert row["IPv4Address"] == "192.0.2.1"
        assert row["NetworkIP"] == "192.0.2.1"
        assert row["ThreatActorNames"] == ["Example Actor"]
        assert row["ThreatActorRelationshipTypes"] == ["indicates"]


def test_wide_objects_view_exposes_relationship_and_type_specific_fields(tmpdir):
    path = str(tmpdir.join("views.duckdb"))
    _seed(path)

    with get_storage(path, "hunt") as store:
        relationship = store.query_one(
            'SELECT RelationshipType, SourceStixType, SourceName, '
            'TargetStixType, TargetName FROM "ThreatIntelObjectsW" '
            "WHERE StixType = 'relationship'"
        )
        assert relationship == {
            "RelationshipType": "indicates",
            "SourceStixType": "indicator",
            "SourceName": "Test IP",
            "TargetStixType": "threat-actor",
            "TargetName": "Example Actor",
        }

        actor = store.query_one(
            'SELECT Name, ThreatActorTypes, Aliases FROM "ThreatIntelObjectsW" '
            "WHERE StixType = 'threat-actor'"
        )
        assert actor["Name"] == "Example Actor"
        assert actor["ThreatActorTypes"] == ["crime-syndicate"]
        assert actor["Aliases"] == ["Example Group"]

        file_row = store.query_one(
            'SELECT FileName, FileSize FROM "ThreatIntelObjectsW" '
            "WHERE StixType = 'file'"
        )
        assert file_row == {"FileName": "sample.bin", "FileSize": 42}
