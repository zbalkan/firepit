# Database model

Firepit stores canonical STIX 2.1 objects and acquisition-run provenance in private DuckDB tables. Analysts query public views only.

## JSON transformation and schema normalization

`Data` is the authoritative STIX object. Firepit does not duplicate the complete STIX schema in Python or maintain a table per object type.

OASIS `cti-python-stix2` validates standard objects at the ingestion boundary. DuckDB performs analytical mapping with `json_transform` and `json_transform_strict`: selected structures become native `STRUCT`, arrays become `LIST`, homogeneous dictionaries such as hashes become `MAP`, and timestamps use `TIMESTAMPTZ`. Fields outside those projections remain unchanged in `Data`.

The private writer also uses DuckDB to normalize the small identity/version envelope (`id`, `type`, `modified`) before canonical-version comparison.

## Public view hierarchy

### Base: Sentinel-compatible schema contracts

- `ThreatIntelIndicators`
- `ThreatIntelObjects`

`Data` contains the complete canonical STIX object. Firepit-specific columns are not added to the base schemas.

For STIX Indicators, `ObservableKey` and `ObservableValue` are populated only when OASIS `stix2-patterns` inspection finds exactly one unqualified equality comparison. Complex, compound, qualified, or non-equality patterns leave these columns `NULL`. This avoids representing one fragment of a STIX pattern as though it described the whole indicator.

### Extended: `ThreatIntel<Semantic>Ex`

`Ex` views contain reusable semantics which naturally expand or aggregate row grain:

- `ThreatIntelRelationshipsEx` — relationship endpoint enrichment.
- `ThreatIntelActorRelationsEx` — actor relationships normalized across source and target directions.
- `ThreatIntelObservationsEx` — `observed-data.object_refs` expansion.
- `ThreatIntelObservationSummaryEx` — observation record/count/time aggregation.
- `ThreatIntelObservablesEx` — common SCO values and hashes as STIX paths.
- `ThreatIntelObservableStatsEx` — observable/value and observation aggregation.

They replace domain-specific behavior formerly hidden behind Firepit's mutable query/view helpers while leaving ordinary filtering, sorting, projection, and grouping to SQL.

### Wide: `W`

- `ThreatIntelIndicatorsW`
- `ThreatIntelObjectsW`

A `W` view preserves the one-row-per-base-record grain and appends denormalized search columns. It is intended for interactive hunting where repeated JSON extraction or relationship correlation would otherwise dominate the query.

The indicator W view derives IP/domain/email/URL/hash/X.509 convenience fields from the already-inspected base `ObservableKey`/`ObservableValue`; it does not parse STIX patterns with regular expressions.

## Row-grain rule

```text
no suffix   base/compatibility row grain
Ex          semantic view; row grain may expand or aggregate
W           wide view; row grain remains identical to its base view
```

## Relationship model

`ThreatIntelRelationshipsEx` joins relationship `source_ref` and `target_ref` against the union of the two base views. `ThreatIntelActorRelationsEx` then normalizes actor direction so actor-centric hunting does not require separate source/target branches followed by a union.

## Observation model

`ThreatIntelObservationsEx` transforms `observed-data` into typed fields and expands `object_refs` with `UNNEST`. `ThreatIntelObservationSummaryEx` preserves the distinction between records and represented occurrences:

```text
ObservationRecords = number of linked observed-data SDOs
ObservationCount   = sum(number_observed)
FirstObserved      = minimum first_observed
LastObserved       = maximum last_observed
```

## Observable model

`ThreatIntelObservablesEx` maps common SCO fields into native DuckDB types. STIX `hashes` is represented as `MAP(VARCHAR, VARCHAR)` and expanded with `map_entries`/`UNNEST`. `ThreatIntelObservableStatsEx` groups those values and combines them with observation summaries.

## Private storage

The private `__firepit_<session>` schema contains three data tables plus metadata:

```text
metadata   private model and public-view versions
runs       one row per acquisition run
bundles    raw STIX bundles associated with a run
objects    canonical object representation used by the public views
```

`run_objects` is deliberately absent. Bundle membership is already preserved in the raw bundle, and no public or internal operation required a second per-object membership table.

The canonical object row stores `id`, STIX type, last-ingestion time, source associated with the canonical payload/version, a safely inspected indicator observable when one exists, and complete `Data` JSON. Receiving the identical canonical payload from another source updates its ingestion time but does not rewrite `SourceSystem` merely because that source arrived later. A newer canonical STIX version can establish a new source together with its new payload.

The raw `runs` and `bundles` tables preserve acquisition evidence independently of the canonical object row.

## View lifecycle

Physical model compatibility and view-definition compatibility are versioned separately. Model version 9 describes the current private table layout. A `view_version` metadata value identifies the installed public view definitions.

A writer recreates the public view family only when the expected view version differs. The query-only handle checks both the expected view names/zero-base-table invariant and the view version before accepting queries. This avoids unconditional DDL on every ingestion while still detecting a stale public view contract.

## Query boundary

The query handle opens DuckDB read-only, disables external access, exposes no DuckDB connection, accepts one `SELECT`, and rejects internal/catalog namespace access. These controls protect the supported API boundary; they do not constitute filesystem access control over the DuckDB file itself.

## Schema version

Firepit 3 currently uses private model version 9. Older/pre-native sessions are rejected explicitly; there is no implicit conversion from earlier private models or the legacy SQLite/PostgreSQL-era model.
