import pytest

from firepit import get_storage


@pytest.mark.parametrize(
    "bundle",
    [
        {
            "type": "bundle",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "x-oca-event",
                    "spec_version": "2.1",
                    "id": "x-oca-event--11111111-1111-4111-8111-111111111111",
                    "action": "network-connection",
                    "code": 1,
                },
                {
                    "type": "observed-data",
                    "spec_version": "2.1",
                    "id": "observed-data--11111111-1111-4111-8111-111111111111",
                    "first_observed": "2026-09-09T10:00:00Z",
                    "last_observed": "2026-09-09T10:00:00Z",
                    "number_observed": 1,
                    "object_refs": [
                        "x-oca-event--11111111-1111-4111-8111-111111111111"
                    ],
                },
            ],
        },
        {
            "type": "bundle",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "file",
                    "spec_version": "2.1",
                    "id": "file--22222222-2222-4222-8222-222222222222",
                    "name": "agent.exe",
                    "hashes": {"SHA-256": "abc"},
                },
                {
                    "type": "process",
                    "spec_version": "2.1",
                    "id": "process--22222222-2222-4222-8222-222222222222",
                    "pid": 1234,
                    "command_line": "agent.exe --run",
                    "image_ref": "file--22222222-2222-4222-8222-222222222222",
                },
                {
                    "type": "observed-data",
                    "spec_version": "2.1",
                    "id": "observed-data--22222222-2222-4222-8222-222222222222",
                    "first_observed": "2026-09-09T11:00:00Z",
                    "last_observed": "2026-09-09T11:00:00Z",
                    "number_observed": 1,
                    "object_refs": [
                        "file--22222222-2222-4222-8222-222222222222",
                        "process--22222222-2222-4222-8222-222222222222",
                    ],
                },
            ],
        },
        {
            "type": "bundle",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "ipv4-addr",
                    "spec_version": "2.1",
                    "id": "ipv4-addr--33333333-3333-4333-8333-333333333333",
                    "value": "192.0.2.10",
                },
                {
                    "type": "network-traffic",
                    "spec_version": "2.1",
                    "id": "network-traffic--33333333-3333-4333-8333-333333333333",
                    "src_ref": "ipv4-addr--33333333-3333-4333-8333-333333333333",
                    "src_port": 53000,
                    "dst_port": 443,
                    "protocols": ["tcp"],
                    "extensions": {
                        "tcp-ext": {"src_flags_hex": "00000002"}
                    },
                },
                {
                    "type": "observed-data",
                    "spec_version": "2.1",
                    "id": "observed-data--33333333-3333-4333-8333-333333333333",
                    "first_observed": "2026-09-09T12:00:00Z",
                    "last_observed": "2026-09-09T12:00:00Z",
                    "number_observed": 4,
                    "object_refs": [
                        "ipv4-addr--33333333-3333-4333-8333-333333333333",
                        "network-traffic--33333333-3333-4333-8333-333333333333",
                    ],
                },
            ],
        },
    ],
)
def test_representative_stix_shifter_21_shapes_ingest(bundle, tmpdir):
    store = get_storage(str(tmpdir.join("shifter.duckdb")), "hunt")
    try:
        store.cache("q1", bundle, source="stix-shifter")
        row = store.connection.execute(
            'SELECT status, result_count FROM "raw_query" WHERE query_id = \'q1\''
        ).fetchone()
        assert row == ("COMPLETED", len(bundle["objects"]))
    finally:
        store.close()
