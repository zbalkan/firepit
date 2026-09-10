# History

## 3.0.0

Firepit 3 is a breaking architectural reduction centered on DuckDB, STIX 2.1, and a query-only public contract.

Major changes:

- DuckDB is the sole database engine.
- CPython 3.11-3.14 is supported.
- Packaging is defined in `pyproject.toml`.
- The public API no longer exposes DuckDB connections, cursors, mutation methods, or arbitrary execution objects.
- The public session schema contains exactly two Sentinel-inspired views: `ThreatIntelIndicators` and `ThreatIntelObjects`.
- Physical canonical-object and provenance tables moved behind a private `__firepit_<session>` schema.
- Standard STIX 2.1 validation is delegated to OASIS `cti-python-stix2` through the optional ingestion dependency set.
- The handwritten STIX schema module was removed.
- The complete canonical STIX object is preserved in each public view's `Data` column.
- Canonical mutable objects are ordered by STIX `modified` time instead of arrival order.
- Duplicate acquisition run IDs, conflicting same-version objects, and immutable-ID content changes are rejected.
- STIX 2.0 embedded-object compatibility was removed.
- SQLite/PostgreSQL backends and dialect abstractions were removed.
- Kestrel-era symtable/appdata/mutable-variable semantics were removed.
- Relationship emulation tables and recursive auto-dereference were removed.
- The generic relational query AST, heuristic aggregation, and local STIX-pattern compiler were removed.
- AIO/Pandas ingestion, HTTP acquisition, `splint`, `woodchipper`, and the Firepit CLI were removed.
- The query-only installation depends only on `duckdb`; `stix2` is optional for the private ingestion path.
- Legacy setuptools, tox, Makefile, Pylint, requirements-file, and Sphinx/RST scaffolding was removed.

The implementation history is summarized in [MODERNIZATION_ROADMAP.md](MODERNIZATION_ROADMAP.md).

## 2.x and earlier

Earlier releases relationalized STIX over SQLite and PostgreSQL and primarily served the Kestrel 1 storage contract. Refer to Git history and published releases for detailed historical changes.
