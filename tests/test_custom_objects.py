from firepit import get_storage


def test_custom_object_retains_unknown_fields_in_raw(tmpdir):
    store = get_storage(str(tmpdir.join("custom.duckdb")), "hunt")
    try:
        process_id = "process--11111111-1111-4111-8111-111111111111"
        event_id = "x-oca-event--22222222-2222-4222-8222-222222222222"
        bundle = {
            "type": "bundle",
            "objects": [
                {
                    "type": "x-oca-event",
                    "spec_version": "2.1",
                    "id": event_id,
                    "kind": "event",
                    "process_ref": process_id,
                }
            ],
        }
        store.cache("q1", bundle)

        columns = {
            row[1]
            for row in store.connection.execute(
                'PRAGMA table_info("x-oca-event")'
            ).fetchall()
        }
        assert "process_ref" not in columns
        assert "_raw" in columns

        row = store.connection.execute(
            "SELECT json_extract_string(_raw, '$.process_ref') "
            'FROM "x-oca-event" WHERE id = ?',
            (event_id,),
        ).fetchone()
        assert row[0] == process_id
    finally:
        store.close()
