"""Wide one-row-per-record views and public-view installation."""

from firepit.views_base import BASE_VIEWS, create_view, install_base_views, qname
from firepit.views_extended import EXTENDED_VIEWS, install_extended_views

WIDE_VIEWS = ("ThreatIntelIndicatorsW", "ThreatIntelObjectsW")
PUBLIC_VIEWS = BASE_VIEWS + EXTENDED_VIEWS + WIDE_VIEWS

_INDICATOR_STRINGS = {
    "SpecVersion": "spec_version",
    "Name": "name",
    "Description": "description",
    "ThreatType": "indicator_types[0]",
    "CreatedByRef": "created_by_ref",
    "Lang": "lang",
}
_INDICATOR_LISTS = {
    "IndicatorTypes": "indicator_types",
    "Labels": "labels",
    "ObjectMarkingRefs": "object_marking_refs",
}
_OBJECT_STRINGS = {
    "SpecVersion": "spec_version",
    "Name": "name",
    "Description": "description",
    "CreatedByRef": "created_by_ref",
    "Lang": "lang",
    "Value": "value",
    "MimeType": "mime_type",
    "Sophistication": "sophistication",
    "ResourceLevel": "resource_level",
    "PrimaryMotivation": "primary_motivation",
    "CommandLine": "command_line",
    "ParentRef": "parent_ref",
    "CreatorUserRef": "creator_user_ref",
    "ImageRef": "image_ref",
    "SrcRef": "src_ref",
    "DstRef": "dst_ref",
    "AccountLogin": "account_login",
    "UserId": "user_id",
}
_OBJECT_LISTS = {
    "Labels": "labels",
    "ObjectMarkingRefs": "object_marking_refs",
    "ThreatActorTypes": "threat_actor_types",
    "Aliases": "aliases",
    "Roles": "roles",
    "Goals": "goals",
    "SecondaryMotivations": "secondary_motivations",
    "PersonalMotivations": "personal_motivations",
    "ObjectRefs": "object_refs",
    "Protocols": "protocols",
}
_JSON_FIELDS = {
    "GranularMarkings": "granular_markings",
    "Extensions": "extensions",
    "ExternalReferences": "external_references",
}


def _json_columns(alias: str, fields: dict[str, str], cast=None) -> str:
    if cast:
        return ",\n".join(
            f"TRY_CAST(json_extract({alias}.Data, '$.{path}') AS {cast}) AS {name}"
            for name, path in fields.items()
        )
    return ",\n".join(
        f"json_extract_string({alias}.Data, '$.{path}') AS {name}"
        for name, path in fields.items()
    )


def _json_values(alias: str, fields: dict[str, str]) -> str:
    return ",\n".join(
        f"json_extract({alias}.Data, '$.{path}') AS {name}"
        for name, path in fields.items()
    )


def _pattern_value(path: str) -> str:
    pattern = path + r"\s*=\s*''([^'']+)''"
    return f"NULLIF(regexp_extract(Pattern, '{pattern}', 1), '')"


def _hash_value(stix_type: str, algorithm: str) -> str:
    return _pattern_value(f"{stix_type}:hashes[^=]*{algorithm}[^=]*")


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

    file_hashes = {
        algorithm: _hash_value("file", algorithm)
        for algorithm in ("SHA-256", "SHA-512", "SHA-1", "MD5")
    }
    file_hash_value = "COALESCE(" + ", ".join(file_hashes.values()) + ")"
    x509_hash = "COALESCE(" + ", ".join(
        _hash_value("x509-certificate", algorithm)
        for algorithm in ("SHA-256", "SHA-1")
    ) + ")"

    create_view(connection, public_schema, "ThreatIntelIndicatorsW", f"""
        WITH {actor_links},
        parsed AS (
            SELECT
                i.*,
                {_pattern_value("ipv4-addr:value")} AS IPv4Address,
                {_pattern_value("ipv6-addr:value")} AS IPv6Address,
                {_pattern_value(r"network-traffic:src_ref\.value")} AS NetworkSourceIP,
                {_pattern_value(r"network-traffic:dst_ref\.value")} AS NetworkDestinationIP,
                {_pattern_value("domain-name:value")} AS DomainName,
                {_pattern_value("email-addr:value")} AS EmailAddress,
                {_pattern_value("url:value")} AS Url,
                CASE
                    WHEN regexp_matches(Pattern, 'file:hashes[^=]*SHA-256') THEN 'SHA-256'
                    WHEN regexp_matches(Pattern, 'file:hashes[^=]*SHA-512') THEN 'SHA-512'
                    WHEN regexp_matches(Pattern, 'file:hashes[^=]*SHA-1') THEN 'SHA-1'
                    WHEN regexp_matches(Pattern, 'file:hashes[^=]*MD5') THEN 'MD5'
                END AS FileHashType,
                {file_hash_value} AS FileHashValue,
                {x509_hash} AS X509Certificate,
                {_pattern_value("x509-certificate:issuer")} AS X509Issuer,
                {_pattern_value("x509-certificate:serial_number")} AS X509CertificateNumber
            FROM {indicators} i
        )
        SELECT
            p.*,
            p.Id AS IndicatorId,
            'indicator'::VARCHAR AS StixType,
            {_json_columns("p", _INDICATOR_STRINGS)},
            {_json_columns("p", _INDICATOR_LISTS, "VARCHAR[]")},
            {_json_values("p", _JSON_FIELDS)},
            json_extract(p.Data, '$.kill_chain_phases') AS KillChainPhases,
            COALESCE(p.IPv4Address, p.IPv6Address) AS NetworkIP,
            a.ThreatActorIds, a.ThreatActorNames, a.ThreatActorRelationshipTypes
        FROM parsed p
        LEFT JOIN actor_links a ON a.RelatedId = p.Id
    """)

    create_view(connection, public_schema, "ThreatIntelObjectsW", f"""
        WITH {actor_links}
        SELECT
            o.*,
            {_json_columns("o", _OBJECT_STRINGS)},
            TRY_CAST(json_extract_string(o.Data, '$.created') AS TIMESTAMPTZ) AS Created,
            TRY_CAST(json_extract_string(o.Data, '$.modified') AS TIMESTAMPTZ) AS Modified,
            COALESCE(TRY_CAST(json_extract(o.Data, '$.revoked') AS BOOLEAN), FALSE) AS Revoked,
            TRY_CAST(json_extract(o.Data, '$.confidence') AS INTEGER) AS Confidence,
            {_json_columns("o", _OBJECT_LISTS, "VARCHAR[]")},
            {_json_values("o", _JSON_FIELDS)},
            json_extract(o.Data, '$.hashes') AS Hashes,
            r.RelationshipType, r.SourceRef, r.SourceStixType, r.SourceName,
            r.TargetRef, r.TargetStixType, r.TargetName,
            TRY_CAST(json_extract_string(o.Data, '$.first_observed') AS TIMESTAMPTZ) AS FirstObserved,
            TRY_CAST(json_extract_string(o.Data, '$.last_observed') AS TIMESTAMPTZ) AS LastObserved,
            TRY_CAST(json_extract(o.Data, '$.number_observed') AS UBIGINT) AS NumberObserved,
            TRY_CAST(json_extract(o.Data, '$.pid') AS UBIGINT) AS Pid,
            TRY_CAST(json_extract(o.Data, '$.src_port') AS INTEGER) AS SrcPort,
            TRY_CAST(json_extract(o.Data, '$.dst_port') AS INTEGER) AS DstPort,
            CASE WHEN o.StixType = 'file' THEN json_extract_string(o.Data, '$.name') END AS FileName,
            TRY_CAST(json_extract(o.Data, '$.size') AS UBIGINT) AS FileSize,
            CASE WHEN o.StixType = 'directory' THEN json_extract_string(o.Data, '$.path') END AS DirectoryPath,
            CASE WHEN o.StixType = 'windows-registry-key' THEN json_extract_string(o.Data, '$.key') END AS RegistryKey,
            a.ThreatActorIds AS RelatedThreatActorIds,
            a.ThreatActorNames AS RelatedThreatActorNames,
            a.ThreatActorRelationshipTypes AS RelatedThreatActorRelationshipTypes
        FROM {objects} o
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
