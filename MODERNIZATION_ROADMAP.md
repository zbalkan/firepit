# Firepit DuckDB Modernization Roadmap — Completed

## Final status

The modernization is complete on `claude/firepit-duckdb-modernize-9tj618`.

Firepit no longer exposes the historical multi-backend/Kestrel storage surface. The final design is a query-only threat-intelligence interface backed by DuckDB, with STIX 2.1 acquisition and physical storage kept private.

```text
remote source
    |
    v
acquisition/orchestration
    - STIX-Shifter
    - paging / polling / retry
    - OASIS cti-python-stix2 validation
    |
    | STIX 2.1 bundles
    v
private Firepit writer
    |
    v
__firepit_<session>
    - canonical objects
    - raw bundles
    - runs
    - run/object provenance
    |
    v
public <session> schema
    - ThreatIntelIndicators
    - ThreatIntelObjects
    - derived hunting views
    |
    v
Firepit query-only API
```

## Completed reductions

### Execution and backend reduction

Removed SQLite, PostgreSQL, backend dialect machinery, async wrappers, Pandas/dataframe ingestion, HTTP acquisition, `splint`, `woodchipper`, and the Firepit CLI. DuckDB is the only database engine.

### Kestrel compatibility removal

Removed symtable/appdata state, mutable hunt variables, compatibility query metadata, relationship emulation tables, recursive dereferencing, and the generic relational query AST.

### Query-language reduction

Removed local STIX-pattern compilation and its Lark grammar. Remote STIX-pattern translation belongs to STIX-Shifter; Firepit's public surface accepts read-only SQL only.

### STIX 2.1 boundary

Removed STIX 2.0 embedded `observed-data.objects` support and Python-side compatibility transformation. Standard STIX 2.1 validation is now delegated to OASIS `cti-python-stix2` in the optional private ingestion path.

The intermediate handwritten `stixschema.py` was removed after it proved the storage direction; Firepit no longer maintains a parallel copy of the OASIS object schema.

### Private physical storage

The final physical model uses a private `__firepit_<session>` schema for acquisition provenance and canonical STIX objects. The physical layout is not a public compatibility contract.

Canonical mutable STIX objects are selected by `modified` timestamp, not arrival order. Conflicting content at the same version and immutable-ID reuse are rejected.

### Public view contract

The analyst-facing schema contains no base tables. Two Sentinel-inspired views form the stable foundation:

- `ThreatIntelIndicators`
- `ThreatIntelObjects`

Four additional views are derived only from those two main views to preserve useful historical Firepit hunting semantics without restoring the old query engine:

- `ThreatIntelObservedObjects` — observed-data/object expansion and timestamp context;
- `ThreatIntelObservationSummary` — observation record count, summed `number_observed`, and first/last timestamps;
- `ThreatIntelValueCounts` — scalar STIX property value counts over observed objects;
- `ThreatIntelRelationships` — relationship endpoint expansion and common dereference fields.

The complete canonical STIX object remains available in `Data`.

### Query-only API

The public `Firepit` handle:

- exposes no DuckDB connection, cursor, relation, or mutation API;
- accepts exactly one `SELECT` statement;
- rejects DDL, DML, `PRAGMA`, `ATTACH`, multiple statements, internal schemas, and catalog relations;
- opens DuckDB read-only;
- disables external access;
- verifies that the public schema contains exactly the expected public views and zero base tables.

### Packaging and repository cleanup

Packaging is defined in `pyproject.toml`. Query-only installations depend only on `duckdb`; `stix2` is an optional ingestion dependency. Python 3.11 through 3.14 are supported.

Removed legacy `setup.py`, `setup.cfg`, requirements files, tox, project Makefile, Pylint configuration, Sphinx/RST documentation, and obsolete migration-era fixtures.

## Acceptance boundary

The final test suite is intended to cover:

- OASIS validation for standard STIX 2.1 objects;
- custom-object preservation;
- canonical version ordering;
- duplicate acquisition-run rejection;
- immutable-ID and same-version conflict detection;
- provenance independent from canonical identity;
- the two main Sentinel-style views plus four derived hunting views;
- zero public base tables;
- complete `Data` preservation;
- observed-data expansion, observation summaries, value counts, and relationship expansion;
- absence of exposed DuckDB handles;
- rejection of write SQL, multiple statements, internals, catalogs, attachments, and external file access;
- persistence and reopen behavior;
- CI on CPython 3.11, 3.12, 3.13, and 3.14 across Linux, macOS, and Windows.

## End state

Firepit is now a small query-only STIX 2.1 threat-intelligence interface. Acquisition and physical storage are private implementation concerns; analysts see two stable Sentinel-style main views, four derived hunting views, and a constrained read-only query API.
