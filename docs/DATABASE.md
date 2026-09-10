# Database model

Firepit separates its physical storage model from the analyst-facing contract.

## Public contract

A session schema contains views only. The two main views are modeled after Microsoft Sentinel's threat-intelligence tables:

- `ThreatIntelIndicators`
- `ThreatIntelObjects`

Four read-only views are derived from those two main views:

- `ThreatIntelObservedObjects`
- `ThreatIntelObservationSummary`
- `ThreatIntelValueCounts`
- `ThreatIntelRelationships`

There are no public base tables. The Python query handle opens DuckDB read-only and does not expose the underlying DuckDB connection.

## Main views

### ThreatIntelIndicators

Contains canonical STIX `indicator` objects. Frequently queried fields such as `Confidence`, `Pattern`, `Created`, `Modified`, `ValidFrom`, and `ValidUntil` are projected as columns. `Data` contains the complete canonical STIX object.

### ThreatIntelObjects

Contains every canonical non-indicator object, including SCOs, SDOs, SROs, and `observed-data`. `StixType` identifies the STIX object type and `Data` preserves the complete object.

These two views are the only foundation for the derived analytical views.

## Derived views

### ThreatIntelObservedObjects

Expands `observed-data.object_refs` into one row per observation/object association and joins each reference to its canonical object in `ThreatIntelObjects`.

Important columns are:

- `ObservationId`
- `ObjectId`
- `StixType`
- `FirstObserved`
- `LastObserved`
- `NumberObserved`
- `Data`
- `SourceSystem`

This is the relational equivalent of the historical timestamped and observed-data attribute extraction queries.

### ThreatIntelObservationSummary

Groups `ThreatIntelObservedObjects` by object and exposes:

- `ObservationRecords` — number of observation/object associations;
- `ObservationCount` — sum of STIX `number_observed`;
- `FirstObserved` — earliest observation timestamp;
- `LastObserved` — latest observation timestamp.

This deliberately keeps record count and represented observation count separate.

### ThreatIntelValueCounts

Traverses the `Data` JSON of observed objects with DuckDB `json_tree()` and aggregates scalar property values. It exposes:

- `StixType`
- `StixPath`
- `Value`
- `ValueType`
- `ObservationRecords`
- `ObservationCount`
- `FirstObserved`
- `LastObserved`

Array indexes are normalized to `[*]`, making repeated-property paths stable for grouping. Each object/observation/path/value combination contributes at most once before aggregation.

This view replaces the historical path-based `value_counts()` query without requiring a Python query builder or Pandas dataframe.

### ThreatIntelRelationships

Selects STIX `relationship` objects from `ThreatIntelObjects`, extracts `source_ref` and `target_ref`, and resolves both endpoints against the union of `ThreatIntelIndicators` and `ThreatIntelObjects`.

It exposes source/target IDs and types plus common `name` and `value` properties and the complete source/target `Data` objects. This covers common historical join/dereference queries without recursive auto-dereference.

## Internal physical model

Physical tables live under a private schema named `__firepit_<session>`. Current tables include canonical objects, acquisition runs, original bundles, and run/object associations. These table names and layouts are implementation details, not a public API.

Standard STIX 2.1 objects are validated on the private ingestion path using OASIS `cti-python-stix2`. Firepit does not maintain a separate handwritten STIX schema model.

## Canonical object semantics

Canonical identity is the STIX object ID. For versioned objects, a newer `modified` version replaces an older version; an older version arriving later does not overwrite the newer canonical object. Conflicting content at the same `modified` timestamp is rejected. Immutable SCO identifiers cannot be reused for different content.

Acquisition provenance is tracked independently, so the same canonical object may participate in multiple runs without duplicating the public object row.

## Schema version

Firepit 3 uses private model version 7. Earlier layouts are rejected explicitly; there is no implicit conversion from legacy Firepit database models.
