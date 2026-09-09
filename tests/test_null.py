from firepit import get_storage


def _bundle(identity):
    return {"type": "bundle", "objects": [identity]}


def test_reingest_missing_known_field_does_not_clobber_value(tmpdir):
    store = get_storage(str(tmpdir.join("nulls.duckdb")), "hunt")
    try:
        identity_id = "identity--11111111-1111-4111-8111-111111111111"
        store.cache(
            "q1",
            _bundle(
                {
                    "type": "identity",
                    "spec_version": "2.1",
                    "id": identity_id,
                    "identity_class": "organization",
                    "name": "Example",
                    "x_extra": "foo",
                }
            ),
        )
        store.cache(
            "q2",
            _bundle(
                {
                    "type": "identity",
                    "spec_version": "2.1",
                    "id": identity_id,
                    "identity_class": "organization",
                }
            ),
        )

        row = store.connection.execute(
            'SELECT name FROM "identity" WHERE id = ?', (identity_id,)
        ).fetchone()
        assert row[0] == "Example"

        row = store.connection.execute(
            "SELECT COUNT(*) FROM raw_bundle "
            "WHERE json_extract_string(bundle, '$.objects[0].x_extra') = 'foo'"
        ).fetchone()
        assert row[0] == 1
    finally:
        store.close()
