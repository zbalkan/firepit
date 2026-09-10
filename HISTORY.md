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
- Canonical `Data` is authoritative; the private object table retains only identity/source/ingestion metadata needed by the public views.
- The public schema contains views only and no base tables.
- `ThreatIntelIndicators` and `ThreatIntelObjects`, modeled after Microsoft Sentinel's threat-intelligence tables, remain the two stable base contracts.
- Firepit semantic views use the `ThreatIntel<Semantic>Ex` naming convention and provide relationship, threat-actor, observation, observable, and observable-statistics enrichment without restoring the old query engine.
- `ThreatIntelIndicatorsW` and `ThreatIntelObjectsW` are wide one-row-per-base-record search views with computed STIX fields and common denormalized hunting columns.
- The `Ex` tier replaces reusable historical Firepit semantics such as dereference joins, `timestamped`, `summary`, `number_observed`, and `value_counts`.
- The `W` tier removes repeated JSON extraction and common bidirectional threat-actor correlation from analyst queries while keeping the original `Pattern` and `Data` authoritative.
- View definitions are split by contract into base, extended, and wide modules.
- SQLite/PostgreSQL dialect abstractions were removed.
- Kestrel-era symtable/appdata state, mutable hunt variables, and compatibility query metadata were removed.
- Relationship emulation tables and recursive auto-dereference were removed.
- The generic query AST, heuristic aggregation, and local STIX-pattern compiler were removed.
- AIO/Pandas ingestion, HTTP acquisition, `splint`, `woodchipper`, and the Firepit CLI were removed.
- The public Python API is query-only and exposes no DuckDB connection or mutation API.
- Query-only installations depend only on `duckdb`; `stix2` is an optional ingestion dependency.
- Pre-v8/legacy database layouts are rejected explicitly.

The implementation history is recorded in [MODERNIZATION_ROADMAP.md](MODERNIZATION_ROADMAP.md).

## 2.x and earlier

Earlier releases relationalized STIX over SQLite and PostgreSQL and primarily served the Kestrel 1 storage contract. Refer to Git history and published releases for detailed historical changes.
