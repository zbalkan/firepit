"""Wide one-row-per-record views and public-view installation."""

from firepit.views_base import BASE_VIEWS, create_view, install_base_views, qname
from firepit.views_extended import EXTENDED_VIEWS, install_extended_views

WIDE_VIEWS = ("ThreatIntelIndicatorsW", "ThreatIntelObjectsW")
PUBLIC_VIEWS = BASE_VIEWS + EXTENDED_VIEWS + WIDE_VIEWS
VIEW_VERSION = "1"

_INDICATOR_STRUCTURE = (
    '{"spec_version":"VARCHAR","name":"VARCHAR","description":"VARCHAR",'
    '"indicator_types":["VARCHAR"],"created_by_ref":"VARCHAR","lang":"VARCHAR",'
    '"labels":["VARCHAR"],"object_marking_refs":["VARCHAR"],'
    '"granular_markings":"JSON","extensions":"JSON",'
    '"external_references":"JSON","kill_chain_phases":"JSON"}'
)
_OBJECT_STRUCTURE = (
    '{"spec_version":"VARCHAR","name":"VARCHAR","description":"VARCHAR",'
    '"created":"TIMESTAMPTZ","modified":"TIMESTAMPTZ",'
    '"created_by_ref":"VARCHAR","revoked":"BOOLEAN","confidence":"INTEGER",'
    '"lang":"VARCHAR","labels":["VARCHAR"],"object_marking_refs":["VARCHAR"],'
    '"granular_markings":"JSON","extensions":"JSON","external_references":"JSON",'
    '"value":"VARCHAR","hashes":"JSON","mime_type":"VARCHAR",'
    '"threat_actor_types":["VARCHAR"],"aliases":["VARCHAR"],"roles":["VARCHAR"],'
    '"goals":["VARCHAR"],"sophistication":"VARCHAR","resource_level":"VARCHAR",'
    '"primary_motivation":"VARCHAR","secondary_motivations":["VARCHAR"],'
    '"personal_motivations":["VARCHAR"],"first_observed":"TIMESTAMPTZ",'
    '"last_observed":"TIMESTAMPTZ","number_observed":"UBIGINT",'
    '"object_refs":["VARCHAR"],"pid":"UBIGINT","command_line":"VARCHAR",'
    '"parent_ref":"VARCHAR","creator_user_ref":"VARCHAR","image_ref":"VARCHAR",'
    '"src_ref":"VARCHAR","dst_ref":"VARCHAR","src_port":"INTEGER",'
    '"dst_port":"INTEGER","protocols":["VARCHAR"],"size":"UBIGINT",'
    '"path":"VARCHAR","account_login":"VARCHAR","user_id":"VARCHAR",'
    '"key":"VARCHAR"}'
)


def _actor_links(actor_relations: str) -> str:
    return f"""
        actor_links AS (
            SELECT
                RelatedId,
                list(DISTINCT ThreatActorId ORDER BY ThreatActorId) AS ThreatActorIds,
                list(DISTINCT ThreatActorName ORDER BY ThreatActorName)
                    FILTER (WHERE ThreatActorName IS NOT NULL) AS ThreatActorNames,
                list(DISTINCT RelationshipType ORDER BY RelationshipType)
                    FILTER (WHERE RelationshipType IS NOT NULL) AS ThreatActorRelationshipTypes
            FROM {actor_relations}
            GROUP BY RelatedId
        )
    """


def install_wide_views(connection, public_schema: str):
    indicators = qname(public_schema, "ThreatIntelIndicators")
    objects = qname(public_schema, "ThreatIntelObjects")
    relationships = qname(public_schema, "ThreatIntelRelationshipsEx")
    actor_relations = qname(public_schema, "ThreatIntelActorRelationsEx")
    actor_links = _actor_links(actor_relations)

    create_view(connection, public_schema, "ThreatIntelIndicatorsW", f"""
        WITH {actor_links},
        parsed AS (
            SELECT i.*, json_transform(i.Data, '{_INDICATOR_STRUCTURE}') AS stix
            FROM {indicators} i
        )
        SELECT
            p.* EXCLUDE (stix),
            p.Id AS IndicatorId,
            'indicator'::VARCHAR AS StixType,
            p.stix.spec_version AS SpecVersion,
            p.stix.name AS Name,
            p.stix.description AS Description,
            p.stix.indicator_types[1] AS ThreatType,
            p.stix.indicator_types AS IndicatorTypes,
            p.stix.created_by_ref AS CreatedByRef,
            p.stix.lang AS Lang,
            p.stix.labels AS Labels,
            p.stix.object_marking_refs AS ObjectMarkingRefs,
            p.stix.granular_markings AS GranularMarkings,
            p.stix.extensions AS Extensions,
            p.stix.external_references AS ExternalReferences,
            p.stix.kill_chain_phases AS KillChainPhases,
            CASE WHEN p.ObservableKey = 'ipv4-addr:value'
                 THEN p.ObservableValue END AS IPv4Address,
            CASE WHEN p.ObservableKey = 'ipv6-addr:value'
                 THEN p.ObservableValue END AS IPv6Address,
            CASE WHEN p.ObservableKey = 'network-traffic:src_ref.value'
                 THEN p.ObservableValue END AS NetworkSourceIP,
            CASE WHEN p.ObservableKey = 'network-traffic:dst_ref.value'
                 THEN p.ObservableValue END AS NetworkDestinationIP,
            CASE WHEN p.ObservableKey = 'domain-name:value'
                 THEN p.ObservableValue END AS DomainName,
            CASE WHEN p.ObservableKey = 'email-addr:value'
                 THEN p.ObservableValue END AS EmailAddress,
            CASE WHEN p.ObservableKey = 'url:value'
                 THEN p.ObservableValue END AS Url,
            CASE p.ObservableKey
                WHEN 'file:hashes.SHA-256' THEN 'SHA-256'
                WHEN 'file:hashes.SHA-512' THEN 'SHA-512'
                WHEN 'file:hashes.SHA-1' THEN 'SHA-1'
                WHEN 'file:hashes.MD5' THEN 'MD5'
            END AS FileHashType,
            CASE WHEN p.ObservableKey IN (
                'file:hashes.SHA-256', 'file:hashes.SHA-512',
                'file:hashes.SHA-1', 'file:hashes.MD5'
            ) THEN p.ObservableValue END AS FileHashValue,
            CASE WHEN p.ObservableKey IN (
                'x509-certificate:hashes.SHA-256',
                'x509-certificate:hashes.SHA-1'
            ) THEN p.ObservableValue END AS X509Certificate,
            CASE WHEN p.ObservableKey = 'x509-certificate:issuer'
                 THEN p.ObservableValue END AS X509Issuer,
            CASE WHEN p.ObservableKey = 'x509-certificate:serial_number'
                 THEN p.ObservableValue END AS X509CertificateNumber,
            CASE WHEN p.ObservableKey IN ('ipv4-addr:value', 'ipv6-addr:value')
                 THEN p.ObservableValue END AS NetworkIP,
            a.ThreatActorIds, a.ThreatActorNames, a.ThreatActorRelationshipTypes
        FROM parsed p
        LEFT JOIN actor_links a ON a.RelatedId = p.Id
    """)

    create_view(connection, public_schema, "ThreatIntelObjectsW", f"""
        WITH {actor_links},
        parsed AS (
            SELECT o.*, json_transform(o.Data, '{_OBJECT_STRUCTURE}') AS stix
            FROM {objects} o
        )
        SELECT
            o.* EXCLUDE (stix),
            o.stix.spec_version AS SpecVersion,
            o.stix.name AS Name,
            o.stix.description AS Description,
            o.stix.created AS Created,
            o.stix.modified AS Modified,
            o.stix.created_by_ref AS CreatedByRef,
            COALESCE(o.stix.revoked, FALSE) AS Revoked,
            o.stix.confidence AS Confidence,
            o.stix.lang AS Lang,
            o.stix.labels AS Labels,
            o.stix.object_marking_refs AS ObjectMarkingRefs,
            o.stix.granular_markings AS GranularMarkings,
            o.stix.extensions AS Extensions,
            o.stix.external_references AS ExternalReferences,
            o.stix.value AS Value,
            o.stix.hashes AS Hashes,
            o.stix.mime_type AS MimeType,
            r.RelationshipType, r.SourceRef, r.SourceStixType, r.SourceName,
            r.TargetRef, r.TargetStixType, r.TargetName,
            o.stix.threat_actor_types AS ThreatActorTypes,
            o.stix.aliases AS Aliases,
            o.stix.roles AS Roles,
            o.stix.goals AS Goals,
            o.stix.sophistication AS Sophistication,
            o.stix.resource_level AS ResourceLevel,
            o.stix.primary_motivation AS PrimaryMotivation,
            o.stix.secondary_motivations AS SecondaryMotivations,
            o.stix.personal_motivations AS PersonalMotivations,
            o.stix.first_observed AS FirstObserved,
            o.stix.last_observed AS LastObserved,
            o.stix.number_observed AS NumberObserved,
            o.stix.object_refs AS ObjectRefs,
            o.stix.pid AS Pid,
            o.stix.command_line AS CommandLine,
            o.stix.parent_ref AS ParentRef,
            o.stix.creator_user_ref AS CreatorUserRef,
            o.stix.image_ref AS ImageRef,
            o.stix.src_ref AS SrcRef,
            o.stix.dst_ref AS DstRef,
            o.stix.src_port AS SrcPort,
            o.stix.dst_port AS DstPort,
            o.stix.protocols AS Protocols,
            CASE WHEN o.StixType = 'file' THEN o.stix.name END AS FileName,
            o.stix.size AS FileSize,
            CASE WHEN o.StixType = 'directory' THEN o.stix.path END AS DirectoryPath,
            o.stix.account_login AS AccountLogin,
            o.stix.user_id AS UserId,
            CASE WHEN o.StixType = 'windows-registry-key' THEN o.stix.key END AS RegistryKey,
            a.ThreatActorIds AS RelatedThreatActorIds,
            a.ThreatActorNames AS RelatedThreatActorNames,
            a.ThreatActorRelationshipTypes AS RelatedThreatActorRelationshipTypes
        FROM parsed o
        LEFT JOIN {relationships} r ON r.RelationshipId = o.Id
        LEFT JOIN actor_links a ON a.RelatedId = o.Id
    """)


def install_views(connection, public_schema: str, internal_schema: str):
    existing = {
        row[0]
        for row in connection.execute(
            "SELECT view_name FROM duckdb_views() WHERE schema_name = ? AND NOT internal",
            (public_schema,),
        ).fetchall()
    }
    for name in reversed(EXTENDED_VIEWS + WIDE_VIEWS):
        if name in existing:
            connection.execute(f"DROP VIEW {qname(public_schema, name)}")
    for name in existing - set(BASE_VIEWS):
        connection.execute(f"DROP VIEW IF EXISTS {qname(public_schema, name)}")

    install_base_views(connection, public_schema, internal_schema)
    install_extended_views(connection, public_schema)
    install_wide_views(connection, public_schema)
