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
        ],
    }


def _as_json(value):
    return json.loads(value) if isinstance(value, str) else value


def test_indicator_view_uses_sentinel_foundation_and_preserves_full_data(tmpdir):
    path = str(tmpdir.join("views.duckdb"))
    ingest(path, "q1", _bundle(), session_id="hunt", source="test-feed")

    with get_storage(path, "hunt") as store:
        row = store.query_one('SELECT * FROM "ThreatIntelIndicators"')
        assert list(row) == _INDICATOR_COLUMNS
        assert row["Confidence"] == 85
        assert row["IsDeleted"] is False
        assert row["Revoked"] is False
        assert row["SourceSystem"] == "test-feed"
        assert row["Pattern"] == "[ipv4-addr:value = '192.0.2.1']"
        assert row["ObservableKey"] is None
        assert row["ObservableValue"] is None
        assert row["Type"] == "ThreatIntelIndicators"
        assert set(row["Tags"].split(",")) == {"test", "ip"}

        data = _as_json(row["Data"])
        assert data["id"] == row["Id"]
        assert data["indicator_types"] == ["malicious-activity"]
        assert data["pattern"] == row["Pattern"]


def test_objects_view_excludes_indicators_and_keeps_relationship_data(tmpdir):
    path = str(tmpdir.join("views.duckdb"))
    ingest(path, "q1", _bundle(), session_id="hunt", source="test-feed")

    with get_storage(path, "hunt") as store:
        rows = store.query(
            'SELECT * FROM "ThreatIntelObjects" ORDER BY StixType'
        )
        assert len(rows) == 2
        assert list(rows[0]) == _OBJECT_COLUMNS
        assert {row["StixType"] for row in rows} == {
            "relationship",
            "threat-actor",
        }
        assert all(row["IsDeleted"] is False for row in rows)
        assert all(row["Type"] == "ThreatIntelObjects" for row in rows)

        relationship = store.query_one(
            'SELECT Id, '
            "json_extract_string(Data, '$.source_ref') AS SourceRef, "
            "json_extract_string(Data, '$.target_ref') AS TargetRef "
            'FROM "ThreatIntelObjects" WHERE StixType = ?',
            ("relationship",),
        )
        assert relationship["SourceRef"].startswith("indicator--")
        assert relationship["TargetRef"].startswith("threat-actor--")
