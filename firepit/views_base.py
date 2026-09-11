"""Sentinel-compatible base threat-intelligence views."""

BASE_VIEWS = ("ThreatIntelIndicators", "ThreatIntelObjects")

_INDICATOR_STRUCTURE = (
    '{"confidence":"INTEGER","created":"TIMESTAMPTZ",'
    '"modified":"TIMESTAMPTZ","revoked":"BOOLEAN",'
    '"labels":["VARCHAR"],"valid_from":"TIMESTAMPTZ",'
    '"valid_until":"TIMESTAMPTZ","pattern":"VARCHAR"}'
)


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
            SELECT id, data, source, last_ingested_at,
                   observable_key, observable_value,
                   json_transform(data, '{_INDICATOR_STRUCTURE}') AS stix
            FROM {objects}
            WHERE stix_type = 'indicator'
        )
        SELECT
            CAST(NULL AS JSON) AS AdditionalFields,
            CAST(NULL AS VARCHAR) AS AzureTenantId,
            CAST(NULL AS DOUBLE) AS _BilledSize,
            stix.confidence AS Confidence,
            stix.created AS Created,
            data AS Data,
            id AS Id,
            NOT COALESCE(stix.revoked, FALSE)
                AND (stix.valid_from IS NULL OR stix.valid_from <= current_timestamp)
                AND (stix.valid_until IS NULL OR stix.valid_until > current_timestamp) AS IsActive,
            CAST(NULL AS VARCHAR) AS _IsBillable,
            FALSE AS IsDeleted,
            'Firepit' AS LastUpdateMethod,
            stix.modified AS Modified,
            observable_key AS ObservableKey,
            observable_value AS ObservableValue,
            stix.pattern AS Pattern,
            CAST(NULL AS VARCHAR) AS _ResourceId,
            COALESCE(stix.revoked, FALSE) AS Revoked,
            source AS SourceSystem,
            CAST(NULL AS VARCHAR) AS _SubscriptionId,
            array_to_string(stix.labels, ',') AS Tags,
            CAST(NULL AS VARCHAR) AS TenantId,
            last_ingested_at AS TimeGenerated,
            'ThreatIntelIndicators' AS Type,
            stix.valid_from AS ValidFrom,
            stix.valid_until AS ValidUntil,
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
