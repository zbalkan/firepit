# History

## 3.0.0

Firepit 3 is a breaking architectural reduction centered on DuckDB and STIX 2.1.

Major changes:

- DuckDB is the sole database backend.
- CPython 3.11-3.14 is supported.
- Packaging is defined in `pyproject.toml`.
- STIX 2.0 embedded-object compatibility was removed.
- Standard STIX 2.1 validation is delegated to OASIS `cti-python-stix2` on the private ingestion path.
- Physical canonical-object and acquisition-provenance tables are private implementation details.
- The public schema contains no base tables.
- `ThreatIntelIndicators` and `ThreatIntelObjects`, modeled after Microsoft Sentinel's threat-intelligence tables, are the two main public views.
- `ThreatIntelObservedObjects`, `ThreatIntelObservationSummary`, `ThreatIntelValueCounts`, and `ThreatIntelRelationships` are derived from the two main views to preserve useful historical hunting semantics.
- SQLite/PostgreSQL dialect abstractions were removed.
- Kestrel-era symtable/appdata state, mutable hunt variables, and compatibility query metadata were removed.
- Relationship emulation tables and recursive auto-dereference were removed.
- The generic query AST, heuristic aggregation, and local STIX-pattern compiler were removed.
- AIO/Pandas ingestion, HTTP acquisition, `splint`, `woodchipper`, and the Firepit CLI were removed.
- The public Python API is query-only and exposes no DuckDB connection or mutation API.
- Query-only installations depend only on `duckdb`; `stix2` is an optional ingestion dependency.
- Pre-v7/legacy database layouts are rejected explicitly.

The implementation history is recorded in [MODERNIZATION_ROADMAP.md](MODERNIZATION_ROADMAP.md).

## 2.x and earlier

Earlier releases relationalized STIX over SQLite and PostgreSQL and primarily served the Kestrel 1 storage contract. Refer to Git history and published releases for detailed historical changes.
