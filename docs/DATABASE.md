# Database model

Firepit stores canonical STIX 2.1 objects and acquisition provenance in private DuckDB tables. Analysts query public views only.

## Public view hierarchy

Firepit has three public view tiers.

### Base: Sentinel-compatible contracts

- `ThreatIntelIndicators`
- `ThreatIntelObjects`

These names and columns are the compatibility foundation and are kept stable. `Data` contains the complete canonical STIX object.

### Extended: `ThreatIntel<Semantic>Ex`

`Ex` views provide Firepit semantics that naturally change row grain or aggregate data. They are derived only from the two base views.

- `ThreatIntelRelationshipsEx` — one row per STIX relationship, with source and target type/name/value/pattern enrichment.
- `ThreatIntelActorRelationsEx` — one row per threat-actor association, normalized so the actor can be either relationship source or target.
- `ThreatIntelObservationsEx` — one row per `observed-data.object_refs` membership.
- `ThreatIntelObservationSummaryEx` — one row per referenced object with observation-record count, represented observation count, and first/last timestamps.
- `ThreatIntelObservablesEx` — one row per common searchable observable value or hash.
- `ThreatIntelObservableStatsEx` — one row per observable key/value with object and observation statistics.

This tier replaces the reusable semantics formerly implemented by Firepit's mutable query/view API: dereference joins, `timestamped`, `summary`, `number_observed`, and `value_counts`.

### Wide: `W`

- `ThreatIntelIndicatorsW`
- `ThreatIntelObjectsW`

A `W` view preserves the one-row-per-base-record grain and appends denormalized search columns. It is intended for interactive hunting and for queries that would otherwise contain many repeated `json_extract*` expressions.

`ThreatIntelIndicatorsW` includes common STIX metadata, indicator types, name/description, marking/reference fields, common equality-pattern observables, and related threat-actor lists.

`ThreatIntelObjectsW` includes common STIX metadata plus fields useful for relationship, threat-actor, observed-data, process, network-traffic, file, account, directory, and registry searches.

## Row-grain rule

The suffix communicates cardinality:

```text
no suffix   compatibility/base row grain
Ex          semantic view; row grain may expand or aggregate
W           wide view; row grain must remain identical to its base view
```

This rule is important because an analyst can safely substitute `ThreatIntelIndicatorsW` for `ThreatIntelIndicators` when they want more columns without unexpectedly multiplying rows. The same applies to `ThreatIntelObjectsW`.

## Relationship model

`ThreatIntelRelationshipsEx` joins relationship `source_ref` and `target_ref` against the union of the two base views. It exposes endpoint metadata without requiring the analyst to repeat the dereference joins.

`ThreatIntelActorRelationsEx` then normalizes actor direction. A threat actor is always represented in `ThreatActorId`/`ThreatActorName`, while the opposite endpoint is represented in `RelatedId`, `RelatedStixType`, `RelatedName`, `RelatedValue`, and `RelatedPattern`.

This directly replaces the common two-branch pattern of joining relationships once with the actor as source, once with the actor as target, and then unioning the results.

## Observation model

`ThreatIntelObservationsEx` expands `observed-data.object_refs`. `ThreatIntelObservationSummaryEx` aggregates that expansion:

```text
ObservationRecords = number of linked observed-data SDOs
ObservationCount   = sum(number_observed)
FirstObserved      = minimum first_observed
LastObserved       = maximum last_observed
```

These quantities remain distinct because an observation record can represent more than one occurrence.

## Observable model

`ThreatIntelObservablesEx` extracts common SCO search values such as IP addresses, domains, URLs, email addresses, MAC addresses, file names, hashes, certificate serials/hashes, account logins, registry keys, and network endpoint references.

`ThreatIntelObservableStatsEx` groups these values and combines them with observation summaries. It is the static view replacement for the old value-count/number-observed query helpers.

## Wide indicator pattern extraction

The base Sentinel-style `ObservableKey` and `ObservableValue` fields remain unchanged. Firepit does not reintroduce a STIX pattern compiler merely to populate them.

Instead, `ThreatIntelIndicatorsW` exposes named convenience columns such as `NetworkIP`, `DomainName`, `EmailAddress`, `Url`, `FileHashType`, `FileHashValue`, `X509Certificate`, `X509Issuer`, and `X509CertificateNumber` for common equality predicates.

These use conservative regular-expression extraction. They are intentionally best effort. Complex STIX patterns remain represented by the authoritative `Pattern` and `Data` columns.

## Private storage

The `__firepit_<session>` schema contains implementation tables for canonical objects, acquisition runs, bundles, and run/object provenance. Their structure is private and may change independently of the public view contracts.

Canonical object storage is intentionally narrow: `Data` is authoritative, while the private object table keeps only the object ID, STIX type, last-ingestion timestamp, source, and canonical JSON. Version comparison reads the canonical object's `modified` value from `Data` rather than maintaining another copy.

A query-only Firepit handle verifies that the public session schema contains the expected view family and no base tables. It opens DuckDB read-only and does not expose the underlying connection.

## Schema version

Firepit 3 currently uses private model version 8. Older/pre-native database sessions are rejected explicitly; there is no implicit conversion from earlier private models or the legacy SQLite/PostgreSQL-era model.
