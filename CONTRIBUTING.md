# Contributing

Firepit 3 is intentionally narrow. Contributions should preserve the separation between private acquisition/storage internals and the public query-only interface.

## Development setup

Use CPython 3.11 through 3.14.

```bash
python -m pip install -e ".[test]"
python -m pytest
```

CI covers the supported Python range on Linux, macOS, and Windows.

## Design rules

- DuckDB is the only database engine.
- STIX 2.1 is the only supported STIX generation.
- OASIS `cti-python-stix2` is the authority for standard STIX object validation; do not recreate the standard object schema manually in Firepit.
- Keep `stix2` out of the public query path. It belongs to the optional private ingestion path.
- The public session schema must contain exactly `ThreatIntelIndicators` and `ThreatIntelObjects`, with no base tables.
- Physical relations under `__firepit_<session>` are private and may change between model versions.
- Do not expose a DuckDB connection, cursor, relation, arbitrary execution object, or mutation API from the public package surface.
- Public SQL must remain one read-only `SELECT` statement and must not expose Firepit internals, catalogs, attachment, or external file access.
- Preserve the complete canonical STIX object in `Data`; do not truncate standard or custom content merely to fit convenience columns.
- Acquisition provenance must remain independent from canonical STIX object identity.
- Mutable STIX object versions must be ordered by `modified`; arrival order must not decide the canonical version.
- Do not reintroduce Pandas/dataframe processing, HTTP acquisition, Kestrel state, a database-independent query AST, a local STIX-pattern compiler, or automatic recursive dereferencing.

## Tests

Tests should target public and semantic contracts rather than private table layouts. Important cases include:

- public handle exposes query helpers but no DuckDB API;
- DDL, DML, multiple statements, catalogs, internals, and external access are rejected;
- public schema contains exactly two views and zero base tables;
- Sentinel-inspired view columns remain stable;
- standard STIX 2.1 validation is delegated to OASIS;
- custom object content is retained in `Data`;
- repeated acquisition runs preserve independent provenance;
- older mutable object versions cannot overwrite newer ones;
- conflicting content at the same `modified` timestamp is rejected;
- immutable IDs cannot be reused for different content;
- database reopen behavior remains deterministic.

## Commit structure

Keep correctness fixes, public-contract changes, and documentation changes independently reviewable. Changes to private storage are acceptable when they do not widen or silently alter the public contract.
