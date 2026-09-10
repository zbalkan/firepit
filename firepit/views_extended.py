"""Firepit semantic views derived only from the two base views."""

from firepit.views_base import create_view, qname

EXTENDED_VIEWS = (
    "ThreatIntelRelationshipsEx",
    "ThreatIntelActorRelationsEx",
    "ThreatIntelObservationsEx",
    "ThreatIntelObservationSummaryEx",
    "ThreatIntelObservablesEx",
    "ThreatIntelObservableStatsEx",
)


def all_objects_cte(public_schema: str) -> str:
    indicators = qname(public_schema, "ThreatIntelIndicators")
    objects = qname(public_schema, "ThreatIntelObjects")
    return f"""
        all_objects AS (
            SELECT Id, 'indicator'::VARCHAR AS StixType, Data, SourceSystem, TimeGenerated
            FROM {indicators}
            UNION ALL
            SELECT Id, StixType, Data, SourceSystem, TimeGenerated
            FROM {objects}
        )
    """


def install_extended_views(connection, public_schema: str):
    objects = qname(public_schema, "ThreatIntelObjects")
    all_objects = all_objects_cte(public_schema)

    relationships = qname(public_schema, "ThreatIntelRelationshipsEx")
    create_view(connection, public_schema, "ThreatIntelRelationshipsEx", f"""
        WITH {all_objects}
        SELECT
            r.Id AS RelationshipId,
            json_extract_string(r.Data, '$.relationship_type') AS RelationshipType,
            json_extract_string(r.Data, '$.source_ref') AS SourceRef,
            s.StixType AS SourceStixType,
            COALESCE(json_extract_string(s.Data, '$.name'), json_extract_string(s.Data, '$.value')) AS SourceName,
            json_extract_string(s.Data, '$.value') AS SourceValue,
            CASE WHEN s.StixType = 'indicator' THEN json_extract_string(s.Data, '$.pattern') END AS SourcePattern,
            s.Data AS SourceData,
            json_extract_string(r.Data, '$.target_ref') AS TargetRef,
            t.StixType AS TargetStixType,
            COALESCE(json_extract_string(t.Data, '$.name'), json_extract_string(t.Data, '$.value')) AS TargetName,
            json_extract_string(t.Data, '$.value') AS TargetValue,
            CASE WHEN t.StixType = 'indicator' THEN json_extract_string(t.Data, '$.pattern') END AS TargetPattern,
            t.Data AS TargetData,
            json_extract_string(r.Data, '$.description') AS Description,
            TRY_CAST(json_extract_string(r.Data, '$.created') AS TIMESTAMPTZ) AS Created,
            TRY_CAST(json_extract_string(r.Data, '$.modified') AS TIMESTAMPTZ) AS Modified,
            TRY_CAST(json_extract_string(r.Data, '$.start_time') AS TIMESTAMPTZ) AS StartTime,
            TRY_CAST(json_extract_string(r.Data, '$.stop_time') AS TIMESTAMPTZ) AS StopTime,
            COALESCE(TRY_CAST(json_extract(r.Data, '$.revoked') AS BOOLEAN), FALSE) AS Revoked,
            r.SourceSystem, r.TimeGenerated, r.Data
        FROM {objects} r
        LEFT JOIN all_objects s ON s.Id = json_extract_string(r.Data, '$.source_ref')
        LEFT JOIN all_objects t ON t.Id = json_extract_string(r.Data, '$.target_ref')
        WHERE r.StixType = 'relationship'
    """)

    create_view(connection, public_schema, "ThreatIntelActorRelationsEx", f"""
        SELECT
            SourceRef AS ThreatActorId,
            SourceName AS ThreatActorName,
            'source'::VARCHAR AS ThreatActorDirection,
            RelationshipId, RelationshipType,
            TargetRef AS RelatedId, TargetStixType AS RelatedStixType,
            TargetName AS RelatedName, TargetValue AS RelatedValue,
            TargetPattern AS RelatedPattern, TargetData AS RelatedData,
            SourceSystem, TimeGenerated, Data AS RelationshipData
        FROM {relationships}
        WHERE SourceStixType = 'threat-actor'
        UNION ALL
        SELECT
            TargetRef, TargetName, 'target'::VARCHAR,
            RelationshipId, RelationshipType,
            SourceRef, SourceStixType, SourceName, SourceValue, SourcePattern, SourceData,
            SourceSystem, TimeGenerated, Data
        FROM {relationships}
        WHERE TargetStixType = 'threat-actor'
    """)

    observations = qname(public_schema, "ThreatIntelObservationsEx")
    create_view(connection, public_schema, "ThreatIntelObservationsEx", f"""
        WITH {all_objects}
        SELECT
            o.Id AS ObservationId,
            json_extract_string(ref.value, '$') AS ObjectId,
            target.StixType,
            TRY_CAST(json_extract_string(o.Data, '$.first_observed') AS TIMESTAMPTZ) AS FirstObserved,
            TRY_CAST(json_extract_string(o.Data, '$.last_observed') AS TIMESTAMPTZ) AS LastObserved,
            TRY_CAST(json_extract(o.Data, '$.number_observed') AS UBIGINT) AS NumberObserved,
            COALESCE(json_extract_string(target.Data, '$.name'), json_extract_string(target.Data, '$.value')) AS ObjectName,
            json_extract_string(target.Data, '$.value') AS ObservableValue,
            target.Data AS ObjectData,
            o.SourceSystem, o.TimeGenerated, o.Data AS ObservationData
        FROM {objects} o
        CROSS JOIN json_each(o.Data, '$.object_refs') ref
        LEFT JOIN all_objects target ON target.Id = json_extract_string(ref.value, '$')
        WHERE o.StixType = 'observed-data'
    """)

    summary = qname(public_schema, "ThreatIntelObservationSummaryEx")
    create_view(connection, public_schema, "ThreatIntelObservationSummaryEx", f"""
        SELECT
            ObjectId,
            min(StixType) AS StixType,
            min(ObjectName) AS ObjectName,
            min(ObservableValue) AS ObservableValue,
            count(*)::UBIGINT AS ObservationRecords,
            COALESCE(sum(NumberObserved), 0)::UBIGINT AS ObservationCount,
            min(FirstObserved) AS FirstObserved,
            max(LastObserved) AS LastObserved,
            max(TimeGenerated) AS TimeGenerated
        FROM {observations}
        GROUP BY ObjectId
    """)

    observables = qname(public_schema, "ThreatIntelObservablesEx")
    create_view(connection, public_schema, "ThreatIntelObservablesEx", f"""
        WITH {all_objects},
        simple AS (
            SELECT
                Id AS ObjectId,
                StixType,
                CASE StixType
                    WHEN 'ipv4-addr' THEN 'ipv4-addr:value'
                    WHEN 'ipv6-addr' THEN 'ipv6-addr:value'
                    WHEN 'domain-name' THEN 'domain-name:value'
                    WHEN 'url' THEN 'url:value'
                    WHEN 'email-addr' THEN 'email-addr:value'
                    WHEN 'mac-addr' THEN 'mac-addr:value'
                    WHEN 'autonomous-system' THEN 'autonomous-system:number'
                    WHEN 'directory' THEN 'directory:path'
                    WHEN 'file' THEN 'file:name'
                    WHEN 'mutex' THEN 'mutex:name'
                    WHEN 'software' THEN 'software:name'
                    WHEN 'user-account' THEN 'user-account:account_login'
                    WHEN 'windows-registry-key' THEN 'windows-registry-key:key'
                    WHEN 'x509-certificate' THEN 'x509-certificate:serial_number'
                END AS ObservableKey,
                CASE StixType
                    WHEN 'autonomous-system' THEN json_extract_string(Data, '$.number')
                    WHEN 'directory' THEN json_extract_string(Data, '$.path')
                    WHEN 'user-account' THEN json_extract_string(Data, '$.account_login')
                    WHEN 'windows-registry-key' THEN json_extract_string(Data, '$.key')
                    WHEN 'x509-certificate' THEN json_extract_string(Data, '$.serial_number')
                    WHEN 'file' THEN json_extract_string(Data, '$.name')
                    WHEN 'mutex' THEN json_extract_string(Data, '$.name')
                    WHEN 'software' THEN json_extract_string(Data, '$.name')
                    ELSE json_extract_string(Data, '$.value')
                END AS ObservableValue,
                Data, SourceSystem, TimeGenerated
            FROM all_objects
        )
        SELECT ObjectId, StixType, ObservableKey, ObservableValue, Data, SourceSystem, TimeGenerated
        FROM simple
        WHERE ObservableKey IS NOT NULL AND ObservableValue IS NOT NULL
        UNION ALL
        SELECT o.Id, o.StixType, o.StixType || ':hashes.' || h.key,
               json_extract_string(h.value, '$'), o.Data, o.SourceSystem, o.TimeGenerated
        FROM all_objects o
        CROSS JOIN json_each(o.Data, '$.hashes') h
        WHERE o.StixType IN ('file', 'x509-certificate')
          AND json_extract_string(h.value, '$') IS NOT NULL
        UNION ALL
        SELECT Id, StixType, 'network-traffic:src_ref',
               json_extract_string(Data, '$.src_ref'), Data, SourceSystem, TimeGenerated
        FROM all_objects
        WHERE StixType = 'network-traffic' AND json_extract_string(Data, '$.src_ref') IS NOT NULL
        UNION ALL
        SELECT Id, StixType, 'network-traffic:dst_ref',
               json_extract_string(Data, '$.dst_ref'), Data, SourceSystem, TimeGenerated
        FROM all_objects
        WHERE StixType = 'network-traffic' AND json_extract_string(Data, '$.dst_ref') IS NOT NULL
    """)

    create_view(connection, public_schema, "ThreatIntelObservableStatsEx", f"""
        SELECT
            o.ObservableKey, o.ObservableValue,
            count(DISTINCT o.ObjectId)::UBIGINT AS ObjectCount,
            COALESCE(sum(s.ObservationRecords), 0)::UBIGINT AS ObservationRecords,
            COALESCE(sum(s.ObservationCount), 0)::UBIGINT AS ObservationCount,
            min(s.FirstObserved) AS FirstObserved,
            max(s.LastObserved) AS LastObserved,
            max(o.TimeGenerated) AS TimeGenerated
        FROM {observables} o
        LEFT JOIN {summary} s ON s.ObjectId = o.ObjectId
        GROUP BY o.ObservableKey, o.ObservableValue
    """)
