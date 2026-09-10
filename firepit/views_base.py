"""Sentinel-compatible base threat-intelligence views."""

BASE_VIEWS = ("ThreatIntelIndicators", "ThreatIntelObjects")


def qident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def qname(schema: str, name: str) -> str:
    return f"{qident(schema)}.{qident(name)}"


def create_view(connection, schema: str, name: str, select: str):
    connection.execute(f"CREATE OR REPLACE VIEW {qname(schema, name)} AS\n{select}")


def install_base_views(connection, public_schema: str, internal_schema: str):
    objects = qname(internal_schema, "objects")

    create_view(connection, public_schema, "ThreatIntelIndicators", f"""
        WITH indicators AS (
            SELECT
                id, data, source, last_ingested_at,
                TRY_CAST(json_extract(data, '$.confidence') AS INTEGER) AS confidence,
                TRY_CAST(json_extract_string(data, '$.created') AS TIMESTAMPTZ) AS created,
                TRY_CAST(json_extract_string(data, '$.modified') AS TIMESTAMPTZ) AS modified,
                COALESCE(TRY_CAST(json_extract(data, '$.revoked') AS BOOLEAN), FALSE) AS revoked,
                TRY_CAST(json_extract(data, '$.labels') AS VARCHAR[]) AS labels,
                TRY_CAST(json_extract_string(data, '$.valid_from') AS TIMESTAMPTZ) AS valid_from,
                TRY_CAST(json_extract_string(data, '$.valid_until') AS TIMESTAMPTZ) AS valid_until,
                json_extract_string(data, '$.pattern') AS pattern
            FROM {objects}
            WHERE stix_type = 'indicator'
        )
        SELECT
            CAST(NULL AS JSON) AS AdditionalFields,
            CAST(NULL AS VARCHAR) AS AzureTenantId,
            CAST(NULL AS DOUBLE) AS _BilledSize,
            confidence AS Confidence,
            created AS Created,
            data AS Data,
            id AS Id,
            NOT revoked
                AND (valid_from IS NULL OR valid_from <= current_timestamp)
                AND (valid_until IS NULL OR valid_until > current_timestamp) AS IsActive,
            CAST(NULL AS VARCHAR) AS _IsBillable,
            FALSE AS IsDeleted,
            'Firepit' AS LastUpdateMethod,
            modified AS Modified,
            CAST(NULL AS VARCHAR) AS ObservableKey,
            CAST(NULL AS VARCHAR) AS ObservableValue,
            pattern AS Pattern,
            CAST(NULL AS VARCHAR) AS _ResourceId,
            revoked AS Revoked,
            source AS SourceSystem,
            CAST(NULL AS VARCHAR) AS _SubscriptionId,
            array_to_string(labels, ',') AS Tags,
            CAST(NULL AS VARCHAR) AS TenantId,
            last_ingested_at AS TimeGenerated,
            'ThreatIntelIndicators' AS Type,
            valid_from AS ValidFrom,
            valid_until AS ValidUntil,
            CAST(NULL AS VARCHAR) AS WorkspaceId
        FROM indicators
    """)

    create_view(connection, public_schema, "ThreatIntelObjects", f"""
        SELECT
            CAST(NULL AS JSON) AS AdditionalFields,
            CAST(NULL AS VARCHAR) AS AzureTenantId,
            CAST(NULL AS DOUBLE) AS _BilledSize,
            data AS Data,
            id AS Id,
            CAST(NULL AS VARCHAR) AS _IsBillable,
            FALSE AS IsDeleted,
            'Firepit' AS LastUpdateMethod,
            CAST(NULL AS VARCHAR) AS _ResourceId,
            source AS SourceSystem,
            stix_type AS StixType,
            CAST(NULL AS VARCHAR) AS _SubscriptionId,
            CAST(NULL AS VARCHAR) AS TenantId,
            last_ingested_at AS TimeGenerated,
            'ThreatIntelObjects' AS Type,
            CAST(NULL AS VARCHAR) AS WorkspaceId
        FROM {objects}
        WHERE stix_type <> 'indicator'
    """)
