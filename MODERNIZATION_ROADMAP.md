# Firepit DuckDB Modernization Roadmap — Completed

## Final status

The modernization is complete on `claude/firepit-duckdb-modernize-9tj618`.

Firepit 3 is a query-only threat-intelligence interface backed by DuckDB. Acquisition/orchestration and physical storage are private; analysts query a stable view family.

```text
remote source
    |
    v
acquisition/orchestration
    - STIX-Shifter
    - paging / polling / retry
    |
    | STIX 2.1 bundles
    v
private Firepit writer
    - OASIS object validation
    - OASIS pattern inspection for safe key/value observables
    - DuckDB JSON transformation
    - canonical version selection
    - acquisition-run provenance
    |
    v
__firepit_<session>
    - metadata
    - runs
    - raw bundles
    - canonical objects
    |
    v
public <session> schema
    - 2 Sentinel-compatible base views
    - Firepit semantic Ex views
    - 2 wide W views
    |
    v
Firepit query-only API
```

## Completed reductions

### Backend and execution surface

Removed SQLite, PostgreSQL, dialect machinery, asynchronous storage wrappers, Pandas/dataframe native-result translation, HTTP acquisition, `splint`, `woodchipper`, and the Firepit CLI. DuckDB is the only database engine.

### Kestrel compatibility

Removed symtable/appdata state, mutable hunt variables, compatibility query metadata, relationship emulation tables, recursive dereferencing, and the generic relational query AST.

### Query-language ownership

Removed Firepit's STIX-pattern-to-SQL compiler and Lark grammar. Remote source translation belongs to STIX-Shifter; public Firepit analysis uses SQL.

Firepit does inspect Indicator patterns for the narrower purpose of populating existing Sentinel-style `ObservableKey`/`ObservableValue` columns. This uses the OASIS STIX 2.1 pattern parser, not a Firepit grammar or regex approximation, and only one unqualified equality comparison is reduced to a key/value pair.

### STIX 2.1 boundary

Removed STIX 2.0 embedded `observed-data.objects` compatibility and Firepit-generated SCO identifiers. Standard STIX 2.1 object acceptance is delegated to OASIS `cti-python-stix2`; Firepit retains only local policy checks such as the 2.1 boundary and rejection of embedded observed-data objects.

### Private physical storage

Private model version 9 contains metadata, acquisition runs, raw bundles, and canonical objects. The previous `run_objects` membership table was removed because raw bundles already preserve membership and no operation consumed the duplicate relation.

`query_id` terminology was replaced with `run_id`: the stored entity represents one acquisition execution, while a source query may be reused across executions.

Canonical versioned STIX objects are selected by `modified`, not arrival order. Conflicting content at the same `id`/`modified` version is rejected rather than resolving an undefined conflict by arrival order.

`SourceSystem` identifies the source associated with the canonical payload/version. Receiving byte-equivalent canonical content from another source does not reassign this value solely because it arrived later. Acquisition evidence remains in the private run and raw-bundle records.

### DuckDB-native JSON mapping

Complete STIX remains available as canonical `Data` JSON. DuckDB performs selected schema mapping with `json_transform`/`json_transform_strict`; analytical projections use native scalar, `STRUCT`, `LIST`, and `MAP` types without maintaining a complete handwritten STIX schema in Firepit.

### Public view contract

The analyst-facing schema contains views only. Two Sentinel-inspired views provide the stable base schema contracts:

- `ThreatIntelIndicators`
- `ThreatIntelObjects`

Derived tiers are:

- `ThreatIntel<Semantic>Ex` for reusable relational/expansion/aggregation semantics;
- `ThreatIntelIndicatorsW` and `ThreatIntelObjectsW` for wide one-row-per-base-record hunting projections.

The Ex tier retains useful semantics formerly provided by `timestamped`, `summary`, `number_observed`, `value_counts`, and dereference helpers without rebuilding a Python query language.

### View lifecycle

Public view definitions have an independent `view_version`. Writers install/recreate the view family only when this version is missing or changes. Query handles require the expected view version as well as the expected names and zero public base tables.

This separates physical-model compatibility from logical-view compatibility and avoids unconditional DDL during ordinary ingestion.

### Query-only API

The public `Firepit` handle:

- exposes no DuckDB connection, cursor, relation, or mutation API;
- accepts exactly one `SELECT` statement;
- rejects DDL, DML, `PRAGMA`, `ATTACH`, multiple statements, internal schemas, and catalog relations;
- opens DuckDB read-only;
- disables external access;
- verifies the supported public view contract before accepting queries.

These controls enforce different parts of the API boundary; they are not presented as filesystem isolation for the DuckDB file.

### Repository cleanup

Packaging is defined in `pyproject.toml`. Query-only installations depend only on `duckdb`; OASIS STIX libraries are ingestion extras. Python 3.11 through 3.14 are supported.

Legacy setup files, requirements files, tox, Makefiles, Pylint configuration, Sphinx/RST documentation, and obsolete migration-era fixtures were removed.

## Deliberately not added

Several possible changes were reviewed and intentionally not included:

- No second materialized normalized-object representation was added. The Ex and W contracts are required to derive from the two base views, and a duplicate hidden representation would add storage/schema ownership without a demonstrated need.
- No set-based staging/MERGE subsystem was added. Row-at-a-time ingestion may become an optimization target if measurement shows it matters, but additional staging machinery is not justified solely by architectural preference.
- `cti-stix-validator` was not made the ingestion authority for this release. It is useful validation tooling but is explicitly non-normative and brings a broader dependency/checking surface; the existing `cti-python-stix2` object boundary plus OASIS pattern parser satisfies the current responsibilities with less change.
- SCO content-collision handling remains conservative. A principled merge policy for same-ID SCOs would require explicit rules for non-ID-contributing properties; Firepit does not silently invent such a merge.

## Acceptance boundary

The test suite is intended to cover OASIS STIX 2.1 acceptance, custom-object preservation, canonical version ordering, same-version conflict handling, acquisition-run identity, safe Indicator observable extraction, complex-pattern non-reduction, canonical source behavior, base/Ex/W view semantics, view-version validation, complete `Data` preservation, and the query-only boundary across supported Python/platform combinations.

## End state

Firepit is a small STIX 2.1 analytical layer rather than a general storage framework or query-language implementation. STIX-Shifter owns source translation, OASIS tooling owns STIX object/pattern semantics, DuckDB owns storage/transformation/query execution, and Firepit owns the canonicalization policy plus the analyst-facing threat-intelligence view contract.
