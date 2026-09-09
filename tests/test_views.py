from firepit import get_storage


def _bundle():
    src = "ipv4-addr--11111111-1111-4111-8111-111111111111"
    dst = "ipv6-addr--22222222-2222-4222-8222-222222222222"
    parent = "process--33333333-3333-4333-8333-333333333333"
    child = "process--44444444-4444-4444-8444-444444444444"
    user = "user-account--55555555-5555-4555-8555-555555555555"
    conn = "network-traffic--66666666-6666-4666-8666-666666666666"
    obs = "observed-data--77777777-7777-4777-8777-777777777777"
    return {
        "type": "bundle",
        "objects": [
            {"type": "ipv4-addr", "spec_version": "2.1", "id": src, "value": "192.0.2.10"},
            {"type": "ipv6-addr", "spec_version": "2.1", "id": dst, "value": "2001:db8::10"},
            {"type": "user-account", "spec_version": "2.1", "id": user, "account_login": "alice"},
            {"type": "process", "spec_version": "2.1", "id": parent, "pid": 100, "command_line": "parent.exe"},
            {
                "type": "process", "spec_version": "2.1", "id": child,
                "pid": 200, "command_line": "child.exe", "parent_ref": parent,
                "creator_user_ref": user, "opened_connection_refs": [conn],
            },
            {
                "type": "network-traffic", "spec_version": "2.1", "id": conn,
                "src_ref": src, "dst_ref": dst, "src_port": 50000,
                "dst_port": 443, "protocols": ["tcp"],
            },
            {
                "type": "observed-data", "spec_version": "2.1", "id": obs,
                "first_observed": "2026-09-09T10:00:00Z",
                "last_observed": "2026-09-09T10:01:00Z",
                "number_observed": 2, "object_refs": [child, conn],
            },
        ],
    }


def test_native_reference_lists_are_canonical(tmpdir):
    store = get_storage(str(tmpdir.join("refs.duckdb")), "hunt")
    try:
        store.cache("q1", _bundle())
        assert len(store.connection.execute(
            'SELECT opened_connection_refs FROM "process" WHERE pid = 200'
        ).fetchone()[0]) == 1
        assert len(store.connection.execute(
            'SELECT object_refs FROM "observed-data"'
        ).fetchone()[0]) == 2
        internal = {
            row[0] for row in store.connection.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = ?",
                ("hunt",),
            ).fetchall()
        }
        assert "__contains" not in internal
        assert "__reflist" not in internal
    finally:
        store.close()


def test_observation_ref_view_expands_object_refs(tmpdir):
    store = get_storage(str(tmpdir.join("refs.duckdb")), "hunt")
    try:
        store.cache("q1", _bundle())
        rows = store.connection.execute(
            'SELECT object_ref, number_observed FROM "observation_ref" ORDER BY object_ref'
        ).fetchall()
        assert len(rows) == 2
        assert {row[1] for row in rows} == {2}
    finally:
        store.close()


def test_explicit_process_and_network_views(tmpdir):
    store = get_storage(str(tmpdir.join("views.duckdb")), "hunt")
    try:
        store.cache("q1", _bundle())
        process = store.connection.execute(
            'SELECT parent_pid, parent_command_line, user_name '
            'FROM "stixv_process" WHERE pid = 200'
        ).fetchone()
        assert process == (100, "parent.exe", "alice")

        network = store.connection.execute(
            'SELECT src_ipv4, src_ipv6, dst_ipv4, dst_ipv6 '
            'FROM "stixv_network_traffic"'
        ).fetchone()
        assert network == ("192.0.2.10", None, None, "2001:db8::10")
    finally:
        store.close()


def test_base_table_queries_do_not_auto_dereference(tmpdir):
    store = get_storage(str(tmpdir.join("lookup.duckdb")), "hunt")
    try:
        store.cache("q1", _bundle())
        row = store.connection.execute(
            'SELECT parent_ref FROM "process" WHERE pid = 200'
        ).fetchone()
        assert row[0].startswith("process--")
    finally:
        store.close()
