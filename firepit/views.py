"""Public Sentinel-inspired threat-intelligence views."""

BASE_VIEWS = ("ThreatIntelIndicators", "ThreatIntelObjects")
DERIVED_VIEWS = (
    "ThreatIntelObservedObjects",
    "ThreatIntelObservationSummary",
    "ThreatIntelValueCounts",
    "ThreatIntelRelationships",
)
PUBLIC_VIEWS = BASE_VIEWS + DERIVED_VIEWS


def _qident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _qname(schema: str, name: str) -> str:
    return f"{_qident(schema)}.{_qident(name)}"


def install_views(connection, public_schema, internal_schema):
    """Expose analyst-facing views over the internal canonical object store."""
    existing = {
        row[0]
        for row in connection.execute(
            "SELECT view_name FROM duckdb_views() "
            "WHERE schema_name = ? AND NOT internal",
            (public_schema,),
        ).fetchall()
    }

    # Derived views depend on the two Sentinel-style base views. Remove them
    # before replacing the base views so refresh is deterministic even when
    # the database tracks view dependencies.
    for view_name in reversed(DERIVED_VIEWS):
        if view_name in existing:
            connection.execute(
                f"DROP VIEW {_qname(public_schema, view_name)}"
            )

    for view_name in existing:
        if view_name not in PUBLIC_VIEWS:
            connection.execute(
                f"DROP VIEW {_qname(public_schema, view_name)}"
            )

    objects = _qname(internal_schema, "objects")
    indicators = _qname(public_schema, "ThreatIntelIndicators")
    intel_objects = _qname(public_schema, "ThreatIntelObjects")
    observed_objects = _qname(public_schema, "ThreatIntelObservedObjects")

    connection.execute(
        f"CREATE OR REPLACE VIEW {indicators} AS "
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
        f"CREATE OR REPLACE VIEW {intel_objects} AS "
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

    connection.execute(
        f"CREATE VIEW {observed_objects} AS "
        "SELECT "
        "od.Id AS ObservationId, "
        "json_extract_string(ref.value, '$') AS ObjectId, "
        "COALESCE(obj.StixType, "
        "split_part(json_extract_string(ref.value, '$'), '--', 1)) AS StixType, "
        "CAST(json_extract_string(od.Data, '$.first_observed') AS TIMESTAMPTZ) "
        "AS FirstObserved, "
        "CAST(json_extract_string(od.Data, '$.last_observed') AS TIMESTAMPTZ) "
        "AS LastObserved, "
        "CAST(json_extract_string(od.Data, '$.number_observed') AS UBIGINT) "
        "AS NumberObserved, "
        "obj.Data AS Data, "
        "COALESCE(obj.SourceSystem, od.SourceSystem) AS SourceSystem, "
        "od.TimeGenerated AS ObservationTimeGenerated, "
        "obj.TimeGenerated AS ObjectTimeGenerated "
        f"FROM {intel_objects} AS od "
        "CROSS JOIN LATERAL json_each("
        "json_extract(od.Data, '$.object_refs')) AS ref "
        f"LEFT JOIN {intel_objects} AS obj "
        "ON obj.Id = json_extract_string(ref.value, '$') "
        "WHERE od.StixType = 'observed-data'"
    )

    connection.execute(
        f"CREATE VIEW {_qname(public_schema, 'ThreatIntelObservationSummary')} AS "
        "SELECT "
        "ObjectId, "
        "StixType, "
        "COUNT(*)::UBIGINT AS ObservationRecords, "
        "SUM(NumberObserved)::UBIGINT AS ObservationCount, "
        "MIN(FirstObserved) AS FirstObserved, "
        "MAX(LastObserved) AS LastObserved "
        f"FROM {observed_objects} "
        "GROUP BY ObjectId, StixType"
    )

    connection.execute(
        f"CREATE VIEW {_qname(public_schema, 'ThreatIntelValueCounts')} AS "
        "WITH leaves AS ("
        "SELECT DISTINCT "
        "o.ObservationId, "
        "o.ObjectId, "
        "o.StixType, "
        "o.StixType || ':' || regexp_replace("
        r"substr(j.fullkey, 3), '\[[0-9]+\]', '[*]', 'g') AS StixPath, "
        "json_extract_string(j.atom, '$') AS Value, "
        "j.type AS ValueType, "
        "o.NumberObserved, "
        "o.FirstObserved, "
        "o.LastObserved "
        f"FROM {observed_objects} AS o "
        "CROSS JOIN LATERAL json_tree(o.Data) AS j "
        "WHERE j.atom IS NOT NULL"
        ") "
        "SELECT "
        "StixType, "
        "StixPath, "
        "Value, "
        "ValueType, "
        "COUNT(*)::UBIGINT AS ObservationRecords, "
        "SUM(NumberObserved)::UBIGINT AS ObservationCount, "
        "MIN(FirstObserved) AS FirstObserved, "
        "MAX(LastObserved) AS LastObserved "
        "FROM leaves "
        "GROUP BY StixType, StixPath, Value, ValueType"
    )

    connection.execute(
        f"CREATE VIEW {_qname(public_schema, 'ThreatIntelRelationships')} AS "
        "WITH all_intel AS ("
        "SELECT Id, 'indicator' AS StixType, Data, SourceSystem, TimeGenerated "
        f"FROM {indicators} "
        "UNION ALL "
        "SELECT Id, StixType, Data, SourceSystem, TimeGenerated "
        f"FROM {intel_objects}"
        ") "
        "SELECT "
        "r.Id AS RelationshipId, "
        "json_extract_string(r.Data, '$.relationship_type') AS RelationshipType, "
        "json_extract_string(r.Data, '$.source_ref') AS SourceId, "
        "COALESCE(src.StixType, split_part("
        "json_extract_string(r.Data, '$.source_ref'), '--', 1)) AS SourceStixType, "
        "json_extract_string(src.Data, '$.name') AS SourceName, "
        "json_extract_string(src.Data, '$.value') AS SourceValue, "
        "src.Data AS SourceData, "
        "json_extract_string(r.Data, '$.target_ref') AS TargetId, "
        "COALESCE(dst.StixType, split_part("
        "json_extract_string(r.Data, '$.target_ref'), '--', 1)) AS TargetStixType, "
        "json_extract_string(dst.Data, '$.name') AS TargetName, "
        "json_extract_string(dst.Data, '$.value') AS TargetValue, "
        "dst.Data AS TargetData, "
        "json_extract_string(r.Data, '$.description') AS Description, "
        "CAST(json_extract_string(r.Data, '$.start_time') AS TIMESTAMPTZ) "
        "AS StartTime, "
        "CAST(json_extract_string(r.Data, '$.stop_time') AS TIMESTAMPTZ) "
        "AS StopTime, "
        "r.Data AS Data, "
        "r.SourceSystem AS SourceSystem, "
        "r.TimeGenerated AS TimeGenerated "
        f"FROM {intel_objects} AS r "
        "LEFT JOIN all_intel AS src "
        "ON src.Id = json_extract_string(r.Data, '$.source_ref') "
        "LEFT JOIN all_intel AS dst "
        "ON dst.Id = json_extract_string(r.Data, '$.target_ref') "
        "WHERE r.StixType = 'relationship'"
    )
