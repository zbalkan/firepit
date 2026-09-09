"""Public Sentinel-inspired threat-intelligence views."""

PUBLIC_VIEWS = ("ThreatIntelIndicators", "ThreatIntelObjects")


def _qident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _qname(schema: str, name: str) -> str:
    return f"{_qident(schema)}.{_qident(name)}"


def install_views(connection, public_schema, internal_schema):
    """Expose exactly two analyst-facing views over the internal object store."""
    existing = connection.execute(
        "SELECT view_name FROM duckdb_views() "
        "WHERE schema_name = ? AND NOT internal",
        (public_schema,),
    ).fetchall()
    for (view_name,) in existing:
        if view_name not in PUBLIC_VIEWS:
            connection.execute(
                f"DROP VIEW {_qname(public_schema, view_name)}"
            )

    objects = _qname(internal_schema, "objects")

    connection.execute(
        f"CREATE OR REPLACE VIEW "
        f"{_qname(public_schema, 'ThreatIntelIndicators')} AS "
        "SELECT "
        "CAST(NULL AS JSON) AS AdditionalFields, "
        "CAST(NULL AS VARCHAR) AS AzureTenantId, "
        "CAST(NULL AS DOUBLE) AS _BilledSize, "
        "confidence AS Confidence, "
        "created AS Created, "
        "data AS Data, "
        "id AS Id, "
        "("
        "NOT COALESCE(revoked, FALSE) "
        "AND (valid_from IS NULL OR valid_from <= current_timestamp) "
        "AND (valid_until IS NULL OR valid_until > current_timestamp)"
        ") AS IsActive, "
        "CAST(NULL AS VARCHAR) AS _IsBillable, "
        "FALSE AS IsDeleted, "
        "'Firepit' AS LastUpdateMethod, "
        "modified AS Modified, "
        "CAST(NULL AS VARCHAR) AS ObservableKey, "
        "CAST(NULL AS VARCHAR) AS ObservableValue, "
        "pattern AS Pattern, "
        "CAST(NULL AS VARCHAR) AS _ResourceId, "
        "COALESCE(revoked, FALSE) AS Revoked, "
        "source AS SourceSystem, "
        "CAST(NULL AS VARCHAR) AS _SubscriptionId, "
        "array_to_string(labels, ',') AS Tags, "
        "CAST(NULL AS VARCHAR) AS TenantId, "
        "last_ingested_at AS TimeGenerated, "
        "'ThreatIntelIndicators' AS Type, "
        "valid_from AS ValidFrom, "
        "valid_until AS ValidUntil, "
        "CAST(NULL AS VARCHAR) AS WorkspaceId "
        f"FROM {objects} WHERE stix_type = 'indicator'"
    )

    connection.execute(
        f"CREATE OR REPLACE VIEW "
        f"{_qname(public_schema, 'ThreatIntelObjects')} AS "
        "SELECT "
        "CAST(NULL AS JSON) AS AdditionalFields, "
        "CAST(NULL AS VARCHAR) AS AzureTenantId, "
        "CAST(NULL AS DOUBLE) AS _BilledSize, "
        "data AS Data, "
        "id AS Id, "
        "CAST(NULL AS VARCHAR) AS _IsBillable, "
        "FALSE AS IsDeleted, "
        "'Firepit' AS LastUpdateMethod, "
        "CAST(NULL AS VARCHAR) AS _ResourceId, "
        "source AS SourceSystem, "
        "stix_type AS StixType, "
        "CAST(NULL AS VARCHAR) AS _SubscriptionId, "
        "CAST(NULL AS VARCHAR) AS TenantId, "
        "last_ingested_at AS TimeGenerated, "
        "'ThreatIntelObjects' AS Type, "
        "CAST(NULL AS VARCHAR) AS WorkspaceId "
        f"FROM {objects} WHERE stix_type <> 'indicator'"
    )
