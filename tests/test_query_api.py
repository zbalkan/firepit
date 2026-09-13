import duckdb
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
    ingest(path, "run-1", _indicator_bundle(), session_id="hunt", source="unit-test")


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


def test_public_schema_rejects_base_tables(tmpdir):
    path = str(tmpdir.join("query.duckdb"))
    _seed(path)

    connection = duckdb.connect(path)
    try:
        connection.execute('CREATE TABLE hunt.exposed(i INTEGER)')
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="unexpected base tables: exposed"):
        get_storage(path, "hunt")


def test_public_schema_rejects_stale_view_version(tmpdir):
    path = str(tmpdir.join("query.duckdb"))
    _seed(path)

    connection = duckdb.connect(path)
    try:
        connection.execute(
            "UPDATE __firepit_hunt.metadata SET value = '0' "
            "WHERE name = 'view_version'"
        )
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="view version"):
        get_storage(path, "hunt")


def test_missing_database_file_raises_file_not_found(tmpdir):
    path = str(tmpdir.join("does-not-exist.duckdb"))
    with pytest.raises(FileNotFoundError):
        get_storage(path, "hunt")


def test_session_id_property_reflects_open_session(tmpdir):
    path = str(tmpdir.join("query.duckdb"))
    _seed(path)

    with get_storage(path, "hunt") as store:
        assert store.session_id == "hunt"


def test_public_schema_rejects_missing_views(tmpdir):
    path = str(tmpdir.join("query.duckdb"))
    _seed(path)

    connection = duckdb.connect(path)
    try:
        connection.execute('DROP VIEW "hunt"."ThreatIntelObjects"')
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="missing views: ThreatIntelObjects"):
        get_storage(path, "hunt")


def test_public_schema_rejects_unexpected_views(tmpdir):
    path = str(tmpdir.join("query.duckdb"))
    _seed(path)

    connection = duckdb.connect(path)
    try:
        connection.execute('CREATE VIEW "hunt"."ExtraView" AS SELECT 1 AS x')
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="unexpected views: ExtraView"):
        get_storage(path, "hunt")


def test_public_schema_rejects_missing_metadata_table(tmpdir):
    path = str(tmpdir.join("query.duckdb"))
    _seed(path)

    connection = duckdb.connect(path)
    try:
        connection.execute("DROP TABLE __firepit_hunt.metadata")
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="unsupported or missing public view version"):
        get_storage(path, "hunt")


def test_empty_query_is_rejected(tmpdir):
    path = str(tmpdir.join("query.duckdb"))
    _seed(path)

    with get_storage(path, "hunt") as store:
        with pytest.raises(InvalidQuery):
            store.query("   ")


def test_query_one_returns_none_when_nothing_matches(tmpdir):
    path = str(tmpdir.join("query.duckdb"))
    _seed(path)

    with get_storage(path, "hunt") as store:
        assert store.query_one(
            'SELECT Id FROM "ThreatIntelIndicators" WHERE Confidence > 100'
        ) is None


def test_view_convenience_methods_accept_a_where_clause(tmpdir):
    path = str(tmpdir.join("query.duckdb"))
    _seed(path)

    with get_storage(path, "hunt") as store:
        assert len(store.indicators(where="Confidence >= ?", parameters=(50,))) == 1
        assert store.indicators(where="Confidence >= ?", parameters=(90,)) == []


def test_negative_limit_is_rejected(tmpdir):
    path = str(tmpdir.join("query.duckdb"))
    _seed(path)

    with get_storage(path, "hunt") as store:
        with pytest.raises(ValueError):
            store.indicators(limit=-1)


def test_closed_handle_rejects_further_queries(tmpdir):
    path = str(tmpdir.join("query.duckdb"))
    _seed(path)

    store = get_storage(path, "hunt")
    store.close()
    store.close()  # idempotent

    with pytest.raises(RuntimeError, match="closed"):
        store.query('SELECT 1')
