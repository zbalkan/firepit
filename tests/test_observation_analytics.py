from datetime import datetime, timezone

from firepit import get_storage


def _bundle():
    ip = "ipv4-addr--11111111-1111-4111-8111-111111111111"
    obs1 = "observed-data--22222222-2222-4222-8222-222222222222"
    obs2 = "observed-data--33333333-3333-4333-8333-333333333333"
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": ip,
                "value": "192.0.2.25",
            },
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": obs1,
                "first_observed": "2026-09-09T10:00:00Z",
                "last_observed": "2026-09-09T10:05:00Z",
                "number_observed": 3,
                "object_refs": [ip],
            },
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": obs2,
                "first_observed": "2026-09-09T11:00:00Z",
                "last_observed": "2026-09-09T11:02:00Z",
                "number_observed": 2,
                "object_refs": [ip],
            },
        ],
    }


def test_observation_record_count_and_number_observed_are_distinct(tmpdir):
    store = get_storage(str(tmpdir.join("observations.duckdb")), "hunt")
    try:
        store.cache("q1", _bundle())
        row = store._query(
            'SELECT COUNT(*) AS observation_records, '
            'SUM(number_observed) AS observation_count '
            'FROM "observation_ref" WHERE object_ref = ?',
            ("ipv4-addr--11111111-1111-4111-8111-111111111111",),
        ).fetchone()
        assert row["observation_records"] == 2
        assert row["observation_count"] == 5
    finally:
        store.close()


def test_summary_uses_native_object_refs(tmpdir):
    store = get_storage(str(tmpdir.join("observations.duckdb")), "hunt")
    try:
        store.cache("q1", _bundle())
        summary = store.summary("ipv4-addr", "value", "192.0.2.25")
        assert summary["number_observed"] == 5
        assert summary["first_observed"].astimezone(timezone.utc) == datetime(
            2026, 9, 9, 10, 0, tzinfo=timezone.utc
        )
        assert summary["last_observed"].astimezone(timezone.utc) == datetime(
            2026, 9, 9, 11, 2, tzinfo=timezone.utc
        )
    finally:
        store.close()
