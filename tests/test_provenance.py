from firepit import get_storage


def _bundle(object_id, value):
    return {
        "type": "bundle",
        "id": "bundle--11111111-1111-4111-8111-111111111111",
        "objects": [
            {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": object_id,
                "value": value,
            }
        ],
    }


def test_provenance_is_independent_from_sco_identity(tmpdir):
    path = str(tmpdir.join("provenance.duckdb"))
    store = get_storage(path, "hunt")
    try:
        object_id = "ipv4-addr--11111111-1111-4111-8111-111111111111"
        store.cache("q1", _bundle(object_id, "10.0.0.1"), source="source-a")
        store.cache("q2", _bundle(object_id, "10.0.0.1"), source="source-b")

        rows = store._query(
            'SELECT query_id, object_id FROM "raw_run_object" '
            'WHERE object_id = ? ORDER BY query_id',
            (object_id,),
        ).fetchall()
        assert rows == [
            {"query_id": "q1", "object_id": object_id},
            {"query_id": "q2", "object_id": object_id},
        ]

        assert store.count("ipv4-addr") == 1
        assert store.provenance("q1")["source"] == "source-a"
        assert store.provenance("q2")["source"] == "source-b"
    finally:
        store.close()


def test_raw_bundle_is_retained(tmpdir):
    store = get_storage(str(tmpdir.join("raw.duckdb")), "hunt")
    try:
        store.cache(
            "q1",
            _bundle("ipv4-addr--22222222-2222-4222-8222-222222222222", "192.0.2.1"),
        )
        row = store._query(
            'SELECT json_extract_string(bundle, \'$.type\') AS type '
            'FROM "raw_bundle"'
        ).fetchone()
        assert row["type"] == "bundle"
    finally:
        store.close()
