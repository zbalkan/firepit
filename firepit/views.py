"""Explicit DuckDB views for common STIX relationships and observation analytics."""


def _table_exists(connection, session_id, table):
    return connection.execute(
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema = ? AND table_name = ? AND table_type = 'BASE TABLE'",
        (session_id, table),
    ).fetchone() is not None


def install_views(connection, session_id):
    """Create or refresh the small set of intentional analytical views."""
    if _table_exists(connection, session_id, "observed-data"):
        connection.execute(
            'CREATE OR REPLACE VIEW "observation_ref" AS '
            'SELECT o.id AS observed_data_id, ref.object_ref, '
            'o.first_observed, o.last_observed, o.number_observed '
            'FROM "observed-data" o '
            'CROSS JOIN UNNEST(o.object_refs) AS ref(object_ref)'
        )
        connection.execute(
            'CREATE OR REPLACE VIEW "observation_summary" AS '
            'SELECT ref.object_ref, '
            'COUNT(*) AS observation_records, '
            'SUM(o.number_observed) AS observation_count, '
            'MIN(o.first_observed) AS first_observed, '
            'MAX(o.last_observed) AS last_observed '
            'FROM "observed-data" o '
            'CROSS JOIN UNNEST(o.object_refs) AS ref(object_ref) '
            'GROUP BY ref.object_ref'
        )

    if _table_exists(connection, session_id, "process"):
        has_user = _table_exists(connection, session_id, "user-account")
        has_file = _table_exists(connection, session_id, "file")
        select = [
            "p.*",
            "parent.pid AS parent_pid",
            "parent.command_line AS parent_command_line",
            "usr.account_login AS user_name" if has_user else
            "CAST(NULL AS VARCHAR) AS user_name",
            "img.name AS image_name" if has_file else
            "CAST(NULL AS VARCHAR) AS image_name",
        ]
        joins = [
            'LEFT JOIN "process" parent ON p.parent_ref = parent.id',
        ]
        if has_user:
            joins.append(
                'LEFT JOIN "user-account" usr ON p.creator_user_ref = usr.id'
            )
        if has_file:
            joins.append('LEFT JOIN "file" img ON p.image_ref = img.id')
        connection.execute(
            'CREATE OR REPLACE VIEW "stixv_process" AS SELECT '
            + ", ".join(select)
            + ' FROM "process" p '
            + " ".join(joins)
        )

    if _table_exists(connection, session_id, "network-traffic"):
        has_v4 = _table_exists(connection, session_id, "ipv4-addr")
        has_v6 = _table_exists(connection, session_id, "ipv6-addr")
        select = ["nt.*"]
        joins = []
        for side in ("src", "dst"):
            ref = f"{side}_ref"
            if has_v4:
                alias = f"{side}4"
                joins.append(
                    f'LEFT JOIN "ipv4-addr" {alias} ON nt.{ref} = {alias}.id'
                )
                select.append(f"{alias}.value AS {side}_ipv4")
            else:
                select.append(f"CAST(NULL AS VARCHAR) AS {side}_ipv4")
            if has_v6:
                alias = f"{side}6"
                joins.append(
                    f'LEFT JOIN "ipv6-addr" {alias} ON nt.{ref} = {alias}.id'
                )
                select.append(f"{alias}.value AS {side}_ipv6")
            else:
                select.append(f"CAST(NULL AS VARCHAR) AS {side}_ipv6")
        connection.execute(
            'CREATE OR REPLACE VIEW "stixv_network_traffic" AS SELECT '
            + ", ".join(select)
            + ' FROM "network-traffic" nt '
            + " ".join(joins)
        )
