import pytest

from firepit import get_storage
from firepit._writer import ingest
from firepit.exceptions import InvalidQuery


def _indicator_bundle():
    return {
        "type": "bundle",
        "id": "bundle--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--11111111-1111-4111-8111-111111111111",
                "created": "2026-09-09T10:00:00Z",
                "modified": "2026-09-09T10:00:00Z",
                "indicator_types": ["malicious-activity"],
                "pattern": "[ipv4-addr:value = '192.0.2.1']",
                "pattern_type": "stix",
                "valid_from": "2026-09-09T10:00:00Z",
                "confidence": 80,
                "labels": ["test"],
            }
        ],
    }


def _seed(path):
    ingest(path, "q1", _indicator_bundle(), session_id="hunt", source="unit-test")


def test_public_handle_exposes_query_sugar_not_duckdb(tmpdir):
    path = str(tmpdir.join("query.duckdb"))
    _seed(path)

    with get_storage(path, "hunt") as store:
        assert not hasattr(store, "connection")
        assert not hasattr(store, "cursor")
        assert not hasattr(store, "execute")
        assert not hasattr(store, "cache")
        assert not hasattr(store, "delete")

        rows = store.query(
            'SELECT Id, Confidence FROM "ThreatIntelIndicators" WHERE Confidence >= ?',
            (50,),
        )
        assert rows == [{
            "Id": "indicator--11111111-1111-4111-8111-111111111111",
            "Confidence": 80,
        }]

        assert store.query_one(
            'SELECT Id FROM "ThreatIntelIndicators"'
        )["Id"].startswith("indicator--")
        assert store.query_value(
            'SELECT COUNT(*) FROM "ThreatIntelIndicators"'
        ) == 1
        assert len(store.indicators(limit=1)) == 1
        assert store.objects() == []


@pytest.mark.parametrize(
    "sql",
    [
        'INSERT INTO "ThreatIntelIndicators" VALUES (1)',
        'UPDATE "ThreatIntelIndicators" SET Confidence = 1',
        'DELETE FROM "ThreatIntelIndicators"',
        'CREATE TABLE x(i INTEGER)',
        'DROP VIEW "ThreatIntelIndicators"',
        'PRAGMA show_tables',
        'ATTACH DATABASE "other.duckdb" AS other',
        'SELECT 1; SELECT 2',
        'SELECT * FROM "__firepit_hunt"."objects"',
        'SELECT * FROM information_schema.tables',
        'SELECT * FROM duckdb_views()',
    ],
)
def test_public_query_rejects_writes_multiple_statements_and_internal_catalogs(
    tmpdir, sql
):
    path = str(tmpdir.join("query.duckdb"))
    _seed(path)

    with get_storage(path, "hunt") as store:
        with pytest.raises(InvalidQuery):
            store.query(sql)


def test_external_file_access_is_disabled(tmpdir):
    path = str(tmpdir.join("query.duckdb"))
    _seed(path)

    with get_storage(path, "hunt") as store:
        with pytest.raises(InvalidQuery):
            store.query("SELECT * FROM read_csv_auto('does-not-exist.csv')")
