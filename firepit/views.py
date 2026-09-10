"""Public Sentinel-compatible and Firepit-derived threat-intelligence views."""

PUBLIC_BASE_VIEWS = (
    "ThreatIntelIndicators",
    "ThreatIntelObjects",
)

PUBLIC_EXTENDED_VIEWS = (
    "ThreatIntelRelationshipsEx",
    "ThreatIntelActorRelationsEx",
    "ThreatIntelObservationsEx",
    "ThreatIntelObservationSummaryEx",
    "ThreatIntelObservablesEx",
    "ThreatIntelObservableStatsEx",
)

PUBLIC_WIDE_VIEWS = (
    "ThreatIntelIndicatorsW",
    "ThreatIntelObjectsW",
)

PUBLIC_VIEWS = PUBLIC_BASE_VIEWS + PUBLIC_EXTENDED_VIEWS + PUBLIC_WIDE_VIEWS


def _qident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _qname(schema: str, name: str) -> str:
    return f"{_qident(schema)}.{_qident(name)}"


def _all_objects_cte(public_schema: str) -> str:
    indicators = _qname(public_schema, "ThreatIntelIndicators")
    objects = _qname(public_schema, "ThreatIntelObjects")
    return f"""
        all_objects AS (
            SELECT Id, 'indicator'::VARCHAR AS StixType, Data, SourceSystem,
                   TimeGenerated
            FROM {indicators}
            UNION ALL
            SELECT Id, StixType, Data, SourceSystem, TimeGenerated
            FROM {objects}
        )
    """


def install_views(connection, public_schema, internal_schema):
    """Install the immutable base pair plus Firepit-derived analyst views."""
    existing = {
        row[0]
        for row in connection.execute(
            "SELECT view_name FROM duckdb_views() "
            "WHERE schema_name = ? AND NOT internal",
            (public_schema,),
        ).fetchall()
    }

    # Derived views depend on the base pair. Drop them before refreshing the
    # base views so dependency handling remains deterministic.
    for view_name in reversed(PUBLIC_EXTENDED_VIEWS + PUBLIC_WIDE_VIEWS):
        if view_name in existing:
            connection.execute(f"DROP VIEW {_qname(public_schema, view_name)}")

    # Remove names from the pre-convention derived-view experiment as well as
    # any other unexpected public view.
    for view_name in existing:
        if view_name not in PUBLIC_BASE_VIEWS:
            connection.execute(f"DROP VIEW IF EXISTS {_qname(public_schema, view_name)}")

    objects = _qname(internal_schema, "objects")
    indicators = _qname(public_schema, "ThreatIntelIndicators")
    public_objects = _qname(public_schema, "ThreatIntelObjects")

    # Base pair: keep names and columns stable. Firepit enrichment lives above.
    connection.execute(f"""
        CREATE OR REPLACE VIEW {indicators} AS
        SELECT
            CAST(NULL AS JSON) AS AdditionalFields,
            CAST(NULL AS VARCHAR) AS AzureTenantId,
            CAST(NULL AS DOUBLE) AS _BilledSize,
            confidence AS Confidence,
            created AS Created,
            data AS Data,
            id AS Id,
            (
                NOT COALESCE(revoked, FALSE)
                AND (valid_from IS NULL OR valid_from <= current_timestamp)
                AND (valid_until IS NULL OR valid_until > current_timestamp)
            ) AS IsActive,
            CAST(NULL AS VARCHAR) AS _IsBillable,
            FALSE AS IsDeleted,
            'Firepit' AS LastUpdateMethod,
            modified AS Modified,
            CAST(NULL AS VARCHAR) AS ObservableKey,
            CAST(NULL AS VARCHAR) AS ObservableValue,
            pattern AS Pattern,
            CAST(NULL AS VARCHAR) AS _ResourceId,
            COALESCE(revoked, FALSE) AS Revoked,
            source AS SourceSystem,
            CAST(NULL AS VARCHAR) AS _SubscriptionId,
            array_to_string(labels, ',') AS Tags,
            CAST(NULL AS VARCHAR) AS TenantId,
            last_ingested_at AS TimeGenerated,
            'ThreatIntelIndicators' AS Type,
            valid_from AS ValidFrom,
            valid_until AS ValidUntil,
            CAST(NULL AS VARCHAR) AS WorkspaceId
        FROM {objects}
        WHERE stix_type = 'indicator'
    """)

    connection.execute(f"""
        CREATE OR REPLACE VIEW {public_objects} AS
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

    all_objects = _all_objects_cte(public_schema)

    relationships = _qname(public_schema, "ThreatIntelRelationshipsEx")
    connection.execute(f"""
        CREATE OR REPLACE VIEW {relationships} AS
        WITH {all_objects}
        SELECT
            r.Id AS RelationshipId,
            json_extract_string(r.Data, '$.relationship_type') AS RelationshipType,
            json_extract_string(r.Data, '$.source_ref') AS SourceRef,
            s.StixType AS SourceStixType,
            COALESCE(json_extract_string(s.Data, '$.name'),
                     json_extract_string(s.Data, '$.value')) AS SourceName,
            json_extract_string(s.Data, '$.value') AS SourceValue,
            CASE WHEN s.StixType = 'indicator'
                 THEN json_extract_string(s.Data, '$.pattern') END AS SourcePattern,
            s.Data AS SourceData,
            json_extract_string(r.Data, '$.target_ref') AS TargetRef,
            t.StixType AS TargetStixType,
            COALESCE(json_extract_string(t.Data, '$.name'),
                     json_extract_string(t.Data, '$.value')) AS TargetName,
            json_extract_string(t.Data, '$.value') AS TargetValue,
            CASE WHEN t.StixType = 'indicator'
                 THEN json_extract_string(t.Data, '$.pattern') END AS TargetPattern,
            t.Data AS TargetData,
            json_extract_string(r.Data, '$.description') AS Description,
            TRY_CAST(json_extract_string(r.Data, '$.created') AS TIMESTAMPTZ) AS Created,
            TRY_CAST(json_extract_string(r.Data, '$.modified') AS TIMESTAMPTZ) AS Modified,
            TRY_CAST(json_extract_string(r.Data, '$.start_time') AS TIMESTAMPTZ) AS StartTime,
            TRY_CAST(json_extract_string(r.Data, '$.stop_time') AS TIMESTAMPTZ) AS StopTime,
            COALESCE(TRY_CAST(json_extract(r.Data, '$.revoked') AS BOOLEAN), FALSE) AS Revoked,
            r.SourceSystem,
            r.TimeGenerated,
            r.Data
        FROM {public_objects} r
        LEFT JOIN all_objects s ON s.Id = json_extract_string(r.Data, '$.source_ref')
        LEFT JOIN all_objects t ON t.Id = json_extract_string(r.Data, '$.target_ref')
        WHERE r.StixType = 'relationship'
    """)

    actor_relations = _qname(public_schema, "ThreatIntelActorRelationsEx")
    connection.execute(f"""
        CREATE OR REPLACE VIEW {actor_relations} AS
        SELECT
            SourceRef AS ThreatActorId,
            SourceName AS ThreatActorName,
            'source'::VARCHAR AS ThreatActorDirection,
            RelationshipId, RelationshipType,
            TargetRef AS RelatedId,
            TargetStixType AS RelatedStixType,
            TargetName AS RelatedName,
            TargetValue AS RelatedValue,
            TargetPattern AS RelatedPattern,
            TargetData AS RelatedData,
            SourceSystem, TimeGenerated,
            Data AS RelationshipData
        FROM {relationships}
        WHERE SourceStixType = 'threat-actor'
        UNION ALL
        SELECT
            TargetRef AS ThreatActorId,
            TargetName AS ThreatActorName,
            'target'::VARCHAR AS ThreatActorDirection,
            RelationshipId, RelationshipType,
            SourceRef AS RelatedId,
            SourceStixType AS RelatedStixType,
            SourceName AS RelatedName,
            SourceValue AS RelatedValue,
            SourcePattern AS RelatedPattern,
            SourceData AS RelatedData,
            SourceSystem, TimeGenerated,
            Data AS RelationshipData
        FROM {relationships}
        WHERE TargetStixType = 'threat-actor'
    """)

    observations = _qname(public_schema, "ThreatIntelObservationsEx")
    connection.execute(f"""
        CREATE OR REPLACE VIEW {observations} AS
        WITH {all_objects}
        SELECT
            o.Id AS ObservationId,
            json_extract_string(ref.value, '$') AS ObjectId,
            target.StixType,
            TRY_CAST(json_extract_string(o.Data, '$.first_observed') AS TIMESTAMPTZ) AS FirstObserved,
            TRY_CAST(json_extract_string(o.Data, '$.last_observed') AS TIMESTAMPTZ) AS LastObserved,
            TRY_CAST(json_extract(o.Data, '$.number_observed') AS UBIGINT) AS NumberObserved,
            COALESCE(json_extract_string(target.Data, '$.name'),
                     json_extract_string(target.Data, '$.value')) AS ObjectName,
            json_extract_string(target.Data, '$.value') AS ObservableValue,
            target.Data AS ObjectData,
            o.SourceSystem,
            o.TimeGenerated,
            o.Data AS ObservationData
        FROM {public_objects} o
        CROSS JOIN json_each(o.Data, '$.object_refs') AS ref
        LEFT JOIN all_objects target ON target.Id = json_extract_string(ref.value, '$')
        WHERE o.StixType = 'observed-data'
    """)

    observation_summary = _qname(public_schema, "ThreatIntelObservationSummaryEx")
    connection.execute(f"""
        CREATE OR REPLACE VIEW {observation_summary} AS
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

    observables = _qname(public_schema, "ThreatIntelObservablesEx")
    connection.execute(f"""
        CREATE OR REPLACE VIEW {observables} AS
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
                    ELSE NULL
                END AS ObservableKey,
                CASE StixType
                    WHEN 'ipv4-addr' THEN json_extract_string(Data, '$.value')
                    WHEN 'ipv6-addr' THEN json_extract_string(Data, '$.value')
                    WHEN 'domain-name' THEN json_extract_string(Data, '$.value')
                    WHEN 'url' THEN json_extract_string(Data, '$.value')
                    WHEN 'email-addr' THEN json_extract_string(Data, '$.value')
                    WHEN 'mac-addr' THEN json_extract_string(Data, '$.value')
                    WHEN 'autonomous-system' THEN json_extract_string(Data, '$.number')
                    WHEN 'directory' THEN json_extract_string(Data, '$.path')
                    WHEN 'file' THEN json_extract_string(Data, '$.name')
                    WHEN 'mutex' THEN json_extract_string(Data, '$.name')
                    WHEN 'software' THEN json_extract_string(Data, '$.name')
                    WHEN 'user-account' THEN json_extract_string(Data, '$.account_login')
                    WHEN 'windows-registry-key' THEN json_extract_string(Data, '$.key')
                    WHEN 'x509-certificate' THEN json_extract_string(Data, '$.serial_number')
                    ELSE NULL
                END AS ObservableValue,
                Data, SourceSystem, TimeGenerated
            FROM all_objects
        )
        SELECT ObjectId, StixType, ObservableKey, ObservableValue,
               Data, SourceSystem, TimeGenerated
        FROM simple
        WHERE ObservableKey IS NOT NULL AND ObservableValue IS NOT NULL
        UNION ALL
        SELECT
            o.Id,
            o.StixType,
            o.StixType || ':hashes.' || h.key AS ObservableKey,
            json_extract_string(h.value, '$') AS ObservableValue,
            o.Data, o.SourceSystem, o.TimeGenerated
        FROM all_objects o
        CROSS JOIN json_each(o.Data, '$.hashes') AS h
        WHERE o.StixType IN ('file', 'x509-certificate')
          AND json_extract_string(h.value, '$') IS NOT NULL
        UNION ALL
        SELECT Id, StixType, 'network-traffic:src_ref',
               json_extract_string(Data, '$.src_ref'), Data, SourceSystem, TimeGenerated
        FROM all_objects
        WHERE StixType = 'network-traffic'
          AND json_extract_string(Data, '$.src_ref') IS NOT NULL
        UNION ALL
        SELECT Id, StixType, 'network-traffic:dst_ref',
               json_extract_string(Data, '$.dst_ref'), Data, SourceSystem, TimeGenerated
        FROM all_objects
        WHERE StixType = 'network-traffic'
          AND json_extract_string(Data, '$.dst_ref') IS NOT NULL
    """)

    observable_stats = _qname(public_schema, "ThreatIntelObservableStatsEx")
    connection.execute(f"""
        CREATE OR REPLACE VIEW {observable_stats} AS
        SELECT
            o.ObservableKey,
            o.ObservableValue,
            count(DISTINCT o.ObjectId)::UBIGINT AS ObjectCount,
            COALESCE(sum(s.ObservationRecords), 0)::UBIGINT AS ObservationRecords,
            COALESCE(sum(s.ObservationCount), 0)::UBIGINT AS ObservationCount,
            min(s.FirstObserved) AS FirstObserved,
            max(s.LastObserved) AS LastObserved,
            max(o.TimeGenerated) AS TimeGenerated
        FROM {observables} o
        LEFT JOIN {observation_summary} s ON s.ObjectId = o.ObjectId
        GROUP BY o.ObservableKey, o.ObservableValue
    """)

    actor_links = f"""
        actor_links AS (
            SELECT
                RelatedId,
                list(DISTINCT ThreatActorId ORDER BY ThreatActorId) AS ThreatActorIds,
                list(DISTINCT ThreatActorName ORDER BY ThreatActorName)
                    FILTER (WHERE ThreatActorName IS NOT NULL) AS ThreatActorNames,
                list(DISTINCT RelationshipType ORDER BY RelationshipType)
                    FILTER (WHERE RelationshipType IS NOT NULL)
                    AS ThreatActorRelationshipTypes
            FROM {actor_relations}
            GROUP BY RelatedId
        )
    """

    indicators_w = _qname(public_schema, "ThreatIntelIndicatorsW")
    connection.execute(f"""
        CREATE OR REPLACE VIEW {indicators_w} AS
        WITH {actor_links},
        parsed AS (
            SELECT
                i.*,
                NULLIF(regexp_extract(Pattern, 'ipv4-addr:value\\s*=\\s*''([^'']+)''', 1), '') AS IPv4Address,
                NULLIF(regexp_extract(Pattern, 'ipv6-addr:value\\s*=\\s*''([^'']+)''', 1), '') AS IPv6Address,
                NULLIF(regexp_extract(Pattern, 'network-traffic:src_ref\\.value\\s*=\\s*''([^'']+)''', 1), '') AS NetworkSourceIP,
                NULLIF(regexp_extract(Pattern, 'network-traffic:dst_ref\\.value\\s*=\\s*''([^'']+)''', 1), '') AS NetworkDestinationIP,
                NULLIF(regexp_extract(Pattern, 'domain-name:value\\s*=\\s*''([^'']+)''', 1), '') AS DomainName,
                NULLIF(regexp_extract(Pattern, 'email-addr:value\\s*=\\s*''([^'']+)''', 1), '') AS EmailAddress,
                NULLIF(regexp_extract(Pattern, 'url:value\\s*=\\s*''([^'']+)''', 1), '') AS Url,
                CASE
                    WHEN regexp_matches(Pattern, 'file:hashes[^=]*SHA-256') THEN 'SHA-256'
                    WHEN regexp_matches(Pattern, 'file:hashes[^=]*SHA-512') THEN 'SHA-512'
                    WHEN regexp_matches(Pattern, 'file:hashes[^=]*SHA-1') THEN 'SHA-1'
                    WHEN regexp_matches(Pattern, 'file:hashes[^=]*MD5') THEN 'MD5'
                    ELSE NULL
                END AS FileHashType,
                COALESCE(
                    NULLIF(regexp_extract(Pattern, 'file:hashes[^=]*SHA-256[^=]*\\s*=\\s*''([^'']+)''', 1), ''),
                    NULLIF(regexp_extract(Pattern, 'file:hashes[^=]*SHA-512[^=]*\\s*=\\s*''([^'']+)''', 1), ''),
                    NULLIF(regexp_extract(Pattern, 'file:hashes[^=]*SHA-1[^=]*\\s*=\\s*''([^'']+)''', 1), ''),
                    NULLIF(regexp_extract(Pattern, 'file:hashes[^=]*MD5[^=]*\\s*=\\s*''([^'']+)''', 1), '')
                ) AS FileHashValue,
                COALESCE(
                    NULLIF(regexp_extract(Pattern, 'x509-certificate:hashes[^=]*SHA-256[^=]*\\s*=\\s*''([^'']+)''', 1), ''),
                    NULLIF(regexp_extract(Pattern, 'x509-certificate:hashes[^=]*SHA-1[^=]*\\s*=\\s*''([^'']+)''', 1), '')
                ) AS X509Certificate,
                NULLIF(regexp_extract(Pattern, 'x509-certificate:issuer\\s*=\\s*''([^'']+)''', 1), '') AS X509Issuer,
                NULLIF(regexp_extract(Pattern, 'x509-certificate:serial_number\\s*=\\s*''([^'']+)''', 1), '') AS X509CertificateNumber
            FROM {indicators} i
        )
        SELECT
            p.*,
            p.Id AS IndicatorId,
            'indicator'::VARCHAR AS StixType,
            json_extract_string(p.Data, '$.spec_version') AS SpecVersion,
            json_extract_string(p.Data, '$.name') AS Name,
            json_extract_string(p.Data, '$.description') AS Description,
            json_extract_string(p.Data, '$.indicator_types[0]') AS ThreatType,
            TRY_CAST(json_extract(p.Data, '$.indicator_types') AS VARCHAR[]) AS IndicatorTypes,
            json_extract_string(p.Data, '$.created_by_ref') AS CreatedByRef,
            json_extract_string(p.Data, '$.lang') AS Lang,
            TRY_CAST(json_extract(p.Data, '$.labels') AS VARCHAR[]) AS Labels,
            json_extract(p.Data, '$.kill_chain_phases') AS KillChainPhases,
            TRY_CAST(json_extract(p.Data, '$.object_marking_refs') AS VARCHAR[]) AS ObjectMarkingRefs,
            json_extract(p.Data, '$.granular_markings') AS GranularMarkings,
            json_extract(p.Data, '$.extensions') AS Extensions,
            json_extract(p.Data, '$.external_references') AS ExternalReferences,
            COALESCE(p.IPv4Address, p.IPv6Address) AS NetworkIP,
            a.ThreatActorIds,
            a.ThreatActorNames,
            a.ThreatActorRelationshipTypes
        FROM parsed p
        LEFT JOIN actor_links a ON a.RelatedId = p.Id
    """)

    objects_w = _qname(public_schema, "ThreatIntelObjectsW")
    connection.execute(f"""
        CREATE OR REPLACE VIEW {objects_w} AS
        WITH {actor_links}
        SELECT
            o.*,
            json_extract_string(o.Data, '$.spec_version') AS SpecVersion,
            json_extract_string(o.Data, '$.name') AS Name,
            json_extract_string(o.Data, '$.description') AS Description,
            TRY_CAST(json_extract_string(o.Data, '$.created') AS TIMESTAMPTZ) AS Created,
            TRY_CAST(json_extract_string(o.Data, '$.modified') AS TIMESTAMPTZ) AS Modified,
            json_extract_string(o.Data, '$.created_by_ref') AS CreatedByRef,
            COALESCE(TRY_CAST(json_extract(o.Data, '$.revoked') AS BOOLEAN), FALSE) AS Revoked,
            TRY_CAST(json_extract(o.Data, '$.confidence') AS INTEGER) AS Confidence,
            json_extract_string(o.Data, '$.lang') AS Lang,
            TRY_CAST(json_extract(o.Data, '$.labels') AS VARCHAR[]) AS Labels,
            TRY_CAST(json_extract(o.Data, '$.object_marking_refs') AS VARCHAR[]) AS ObjectMarkingRefs,
            json_extract(o.Data, '$.granular_markings') AS GranularMarkings,
            json_extract(o.Data, '$.extensions') AS Extensions,
            json_extract(o.Data, '$.external_references') AS ExternalReferences,
            json_extract_string(o.Data, '$.value') AS Value,
            json_extract(o.Data, '$.hashes') AS Hashes,
            json_extract_string(o.Data, '$.mime_type') AS MimeType,
            r.RelationshipType,
            r.SourceRef,
            r.SourceStixType,
            r.SourceName,
            r.TargetRef,
            r.TargetStixType,
            r.TargetName,
            TRY_CAST(json_extract(o.Data, '$.threat_actor_types') AS VARCHAR[]) AS ThreatActorTypes,
            TRY_CAST(json_extract(o.Data, '$.aliases') AS VARCHAR[]) AS Aliases,
            TRY_CAST(json_extract(o.Data, '$.roles') AS VARCHAR[]) AS Roles,
            TRY_CAST(json_extract(o.Data, '$.goals') AS VARCHAR[]) AS Goals,
            json_extract_string(o.Data, '$.sophistication') AS Sophistication,
            json_extract_string(o.Data, '$.resource_level') AS ResourceLevel,
            json_extract_string(o.Data, '$.primary_motivation') AS PrimaryMotivation,
            TRY_CAST(json_extract(o.Data, '$.secondary_motivations') AS VARCHAR[]) AS SecondaryMotivations,
            TRY_CAST(json_extract(o.Data, '$.personal_motivations') AS VARCHAR[]) AS PersonalMotivations,
            TRY_CAST(json_extract_string(o.Data, '$.first_observed') AS TIMESTAMPTZ) AS FirstObserved,
            TRY_CAST(json_extract_string(o.Data, '$.last_observed') AS TIMESTAMPTZ) AS LastObserved,
            TRY_CAST(json_extract(o.Data, '$.number_observed') AS UBIGINT) AS NumberObserved,
            TRY_CAST(json_extract(o.Data, '$.object_refs') AS VARCHAR[]) AS ObjectRefs,
            TRY_CAST(json_extract(o.Data, '$.pid') AS UBIGINT) AS Pid,
            json_extract_string(o.Data, '$.command_line') AS CommandLine,
            json_extract_string(o.Data, '$.parent_ref') AS ParentRef,
            json_extract_string(o.Data, '$.creator_user_ref') AS CreatorUserRef,
            json_extract_string(o.Data, '$.image_ref') AS ImageRef,
            json_extract_string(o.Data, '$.src_ref') AS SrcRef,
            json_extract_string(o.Data, '$.dst_ref') AS DstRef,
            TRY_CAST(json_extract(o.Data, '$.src_port') AS INTEGER) AS SrcPort,
            TRY_CAST(json_extract(o.Data, '$.dst_port') AS INTEGER) AS DstPort,
            TRY_CAST(json_extract(o.Data, '$.protocols') AS VARCHAR[]) AS Protocols,
            CASE WHEN o.StixType = 'file' THEN json_extract_string(o.Data, '$.name') END AS FileName,
            TRY_CAST(json_extract(o.Data, '$.size') AS UBIGINT) AS FileSize,
            CASE WHEN o.StixType = 'directory' THEN json_extract_string(o.Data, '$.path') END AS DirectoryPath,
            json_extract_string(o.Data, '$.account_login') AS AccountLogin,
            json_extract_string(o.Data, '$.user_id') AS UserId,
            CASE WHEN o.StixType = 'windows-registry-key' THEN json_extract_string(o.Data, '$.key') END AS RegistryKey,
            a.ThreatActorIds AS RelatedThreatActorIds,
            a.ThreatActorNames AS RelatedThreatActorNames,
            a.ThreatActorRelationshipTypes AS RelatedThreatActorRelationshipTypes
        FROM {public_objects} o
        LEFT JOIN {relationships} r ON r.RelationshipId = o.Id
        LEFT JOIN actor_links a ON a.RelatedId = o.Id
    """)
