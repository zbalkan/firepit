# Database model

Firepit separates its physical DuckDB representation from the analyst-facing schema.

## Public schema

For a session named `hunt`, the public schema is `hunt`. It contains exactly two views and no base tables:

```text
hunt.ThreatIntelIndicators
hunt.ThreatIntelObjects
```

These names and their broad column layout are based on Microsoft Sentinel's current threat-intelligence tables so analysts can reuse familiar concepts and query patterns.

### ThreatIntelIndicators

Contains canonical STIX `indicator` objects. Important columns include:

- `Id`
- `Confidence`
- `Created`
- `Modified`
- `Pattern`
- `ValidFrom`
- `ValidUntil`
- `Revoked`
- `IsActive`
- `SourceSystem`
- `Tags`
- `TimeGenerated`
- `Data`

`Data` contains the complete canonical STIX object as JSON. Firepit does not truncate the object.

`ObservableKey` and `ObservableValue` are currently nullable. Firepit does not maintain a second STIX-pattern parser merely to derive them.

### ThreatIntelObjects

Contains every canonical stored STIX object except indicators. Important columns include:

- `Id`
- `StixType`
- `SourceSystem`
- `TimeGenerated`
- `Data`

Relationships are therefore queried as ordinary STIX objects. For example:

```python
rows = store.query(
    """
    SELECT
        Id,
        json_extract_string(Data, '$.source_ref') AS SourceRef,
        json_extract_string(Data, '$.target_ref') AS TargetRef
    FROM ThreatIntelObjects
    WHERE StixType = 'relationship'
    """
)
```

## Sentinel compatibility

The views intentionally resemble Sentinel rather than attempting byte-for-byte equivalence. Azure-specific columns such as tenant, workspace, resource, subscription, and billing fields are present where useful for query portability but are `NULL` when Firepit has no corresponding concept.

`IsDeleted` is false because deletion is not an analyst-facing Firepit operation. `LastUpdateMethod` identifies Firepit. `TimeGenerated` represents the latest successful ingestion time for the canonical object.

## Internal physical schema

The private schema is named:

```text
__firepit_<session>
```

For example:

```text
__firepit_hunt
```

Its current implementation includes internal relations for:

```text
metadata
runs
bundles
objects
run_objects
```

These names are documentation of the current implementation, not a public compatibility contract. User code must not query or mutate them.

The canonical `objects` relation stores selected metadata used by the public views plus the complete STIX object in a JSON `data` column. This avoids duplicating the full OASIS STIX schema as a hand-maintained Firepit schema.

## STIX validation

The private ingestion path uses OASIS `cti-python-stix2` for standard STIX 2.1 objects. Firepit therefore delegates standard object properties and semantic constraints to the reference implementation instead of maintaining a parallel handwritten schema.

Unknown custom object types cannot have an authoritative schema inferred by Firepit. Their type, identifier, and version envelope are validated, and their full content is retained in `Data`.

## Canonical object versioning

Object identity is the STIX ID. For mutable STIX objects, a version with a later `modified` timestamp replaces an older canonical version regardless of arrival order. An older version arriving later does not overwrite the newer canonical object. Different content with the same ID and same `modified` timestamp is rejected.

For immutable objects without `modified`, reusing the same ID with different content is rejected.

Acquisition provenance remains separate from canonical identity, so multiple acquisition runs can reference the same object without duplicating the canonical object.

## Read-only boundary

The public Firepit handle opens DuckDB read-only, disables external access, exposes no connection object, and permits one `SELECT` statement at a time. On open, it verifies that the public schema contains exactly the two expected views and no base tables.

This is an API boundary, not filesystem access control. A process which can directly open the DuckDB file with write permissions is outside Firepit's protection boundary; use operating-system permissions where that matters.
