# History

## 3.0.0

Firepit 3 is a breaking architectural reduction centered on DuckDB and STIX 2.1.

Major changes:

- DuckDB is the sole database backend.
- CPython 3.11-3.14 is supported.
- Packaging is defined in `pyproject.toml`.
- STIX 2.0 embedded-object compatibility was removed.
- Standard STIX 2.1 validation is delegated to OASIS `cti-python-stix2` on the private ingestion path.
- STIX Indicator convenience observables are inspected with OASIS `stix2-patterns`; only one unqualified equality comparison is reduced to `ObservableKey`/`ObservableValue`. Regex-based partial pattern interpretation was removed.
- Physical canonical-object and acquisition-provenance tables are private implementation details.
- Private acquisition identity is a `run_id`, not a reusable query identity.
- The unused per-run/per-object membership table was removed; raw bundles retain the acquired object membership.
- Canonical `Data` remains authoritative. Re-seeing identical content does not change its canonical `SourceSystem` merely because another feed arrived later.
- JSON-to-column mapping and schema normalization use DuckDB `json_transform`/`json_transform_strict`, including native `STRUCT`, `LIST`, `MAP`, and timestamp projection.
- Canonical mutable STIX objects are selected by `modified` rather than arrival order; conflicting content at the same version is rejected.
- The public schema contains views only and no base tables.
- `ThreatIntelIndicators` and `ThreatIntelObjects`, modeled after Microsoft Sentinel's threat-intelligence tables, are the two stable base schema contracts.
- Firepit semantic views use the `ThreatIntel<Semantic>Ex` naming convention for relationship, threat-actor, observation, observable, and statistics semantics.
- `ThreatIntelIndicatorsW` and `ThreatIntelObjectsW` are wide one-row-per-base-record search views.
- Public view definitions have an independent version. Writers rebuild views only when that version changes, and query handles reject stale/missing view versions.
- View definitions are split by contract into base, extended, and wide modules.
- SQLite/PostgreSQL dialect abstractions were removed.
- Kestrel-era symtable/appdata state, mutable hunt variables, and compatibility query metadata were removed.
- Relationship emulation tables and recursive auto-dereference were removed.
- The generic query AST, heuristic aggregation, and local STIX-pattern compiler were removed.
- AIO/Pandas native-result translation, HTTP acquisition, `splint`, `woodchipper`, and the Firepit CLI were removed.
- The public Python API is query-only and exposes no DuckDB connection or mutation API.
- Query-only installations depend only on `duckdb`; OASIS STIX libraries are optional ingestion dependencies.
- Pre-v9/legacy database layouts are rejected explicitly.

The implementation history is recorded in [MODERNIZATION_ROADMAP.md](MODERNIZATION_ROADMAP.md).

## 2.x and earlier

Earlier releases relationalized STIX over SQLite and PostgreSQL and primarily served the Kestrel 1 storage contract. Refer to Git history and published releases for detailed historical changes.
