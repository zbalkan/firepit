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

_RELATIONSHIP_STRUCTURE = (
    '{"relationship_type":"VARCHAR","source_ref":"VARCHAR",'
    '"target_ref":"VARCHAR","description":"VARCHAR",'
    '"created":"TIMESTAMPTZ","modified":"TIMESTAMPTZ",'
    '"start_time":"TIMESTAMPTZ","stop_time":"TIMESTAMPTZ",'
    '"revoked":"BOOLEAN"}'
)
_ENDPOINT_STRUCTURE = '{"name":"VARCHAR","value":"VARCHAR","pattern":"VARCHAR"}'
_OBSERVATION_STRUCTURE = (
    '{"object_refs":["VARCHAR"],"first_observed":"TIMESTAMPTZ",'
    '"last_observed":"TIMESTAMPTZ","number_observed":"UBIGINT"}'
)
_OBSERVABLE_STRUCTURE = (
    '{"value":"VARCHAR","number":"VARCHAR","path":"VARCHAR",'
    '"account_login":"VARCHAR","key":"VARCHAR","serial_number":"VARCHAR",'
    '"name":"VARCHAR","hashes":"MAP(VARCHAR, VARCHAR)",'
    '"src_ref":"VARCHAR","dst_ref":"VARCHAR"}'
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
        WITH {all_objects},
        relationships AS (
            SELECT r.*,
                   json_transform_strict(r.Data, '{_RELATIONSHIP_STRUCTURE}') AS stix
            FROM {objects} r
            WHERE r.StixType = 'relationship'
        ),
        endpoints AS (
            SELECT o.*,
                   json_transform(o.Data, '{_ENDPOINT_STRUCTURE}') AS stix
            FROM all_objects o
        )
        SELECT
            r.Id AS RelationshipId,
            r.stix.relationship_type AS RelationshipType,
            r.stix.source_ref AS SourceRef,
            s.StixType AS SourceStixType,
            COALESCE(s.stix.name, s.stix.value) AS SourceName,
            s.stix.value AS SourceValue,
            CASE WHEN s.StixType = 'indicator' THEN s.stix.pattern END AS SourcePattern,
            s.Data AS SourceData,
            r.stix.target_ref AS TargetRef,
            t.StixType AS TargetStixType,
            COALESCE(t.stix.name, t.stix.value) AS TargetName,
            t.stix.value AS TargetValue,
            CASE WHEN t.StixType = 'indicator' THEN t.stix.pattern END AS TargetPattern,
            t.Data AS TargetData,
            r.stix.description AS Description,
            r.stix.created AS Created,
            r.stix.modified AS Modified,
            r.stix.start_time AS StartTime,
            r.stix.stop_time AS StopTime,
            COALESCE(r.stix.revoked, FALSE) AS Revoked,
            r.SourceSystem, r.TimeGenerated, r.Data
        FROM relationships r
        LEFT JOIN endpoints s ON s.Id = r.stix.source_ref
        LEFT JOIN endpoints t ON t.Id = r.stix.target_ref
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
        WITH {all_objects},
        observed AS (
            SELECT o.*,
                   json_transform_strict(o.Data, '{_OBSERVATION_STRUCTURE}') AS stix
            FROM {objects} o
            WHERE o.StixType = 'observed-data'
        ),
        endpoints AS (
            SELECT o.*,
                   json_transform(o.Data, '{_ENDPOINT_STRUCTURE}') AS stix
            FROM all_objects o
        )
        SELECT
            o.Id AS ObservationId,
            ref.ObjectId,
            target.StixType,
            o.stix.first_observed AS FirstObserved,
            o.stix.last_observed AS LastObserved,
            o.stix.number_observed AS NumberObserved,
            COALESCE(target.stix.name, target.stix.value) AS ObjectName,
            target.stix.value AS ObservableValue,
            target.Data AS ObjectData,
            o.SourceSystem, o.TimeGenerated, o.Data AS ObservationData
        FROM observed o
        CROSS JOIN UNNEST(o.stix.object_refs) AS ref(ObjectId)
        LEFT JOIN endpoints target ON target.Id = ref.ObjectId
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
        typed AS (
            SELECT o.*,
                   json_transform(o.Data, '{_OBSERVABLE_STRUCTURE}') AS stix
            FROM all_objects o
        ),
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
                    WHEN 'autonomous-system' THEN stix.number
                    WHEN 'directory' THEN stix.path
                    WHEN 'user-account' THEN stix.account_login
                    WHEN 'windows-registry-key' THEN stix.key
                    WHEN 'x509-certificate' THEN stix.serial_number
                    WHEN 'file' THEN stix.name
                    WHEN 'mutex' THEN stix.name
                    WHEN 'software' THEN stix.name
                    ELSE stix.value
                END AS ObservableValue,
                Data, SourceSystem, TimeGenerated
            FROM typed
        )
        SELECT ObjectId, StixType, ObservableKey, ObservableValue, Data, SourceSystem, TimeGenerated
        FROM simple
        WHERE ObservableKey IS NOT NULL AND ObservableValue IS NOT NULL
        UNION ALL
        SELECT o.Id, o.StixType, o.StixType || ':hashes.' || h.entry.key,
               h.entry.value, o.Data, o.SourceSystem, o.TimeGenerated
        FROM typed o
        CROSS JOIN UNNEST(map_entries(o.stix.hashes)) AS h(entry)
        WHERE o.StixType IN ('file', 'x509-certificate')
        UNION ALL
        SELECT Id, StixType, 'network-traffic:src_ref',
               stix.src_ref, Data, SourceSystem, TimeGenerated
        FROM typed
        WHERE StixType = 'network-traffic' AND stix.src_ref IS NOT NULL
        UNION ALL
        SELECT Id, StixType, 'network-traffic:dst_ref',
               stix.dst_ref, Data, SourceSystem, TimeGenerated
        FROM typed
        WHERE StixType = 'network-traffic' AND stix.dst_ref IS NOT NULL
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
