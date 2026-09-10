# Contributing

Firepit 3 is intentionally narrow. Contributions should preserve the separation between private acquisition/storage internals and the public query-only interface.

## Development setup

Use CPython 3.11 through 3.14.

```bash
python -m pip install -e ".[test]"
python -m pytest
```

CI is configured for the supported Python range on Linux, macOS, and Windows.

## Design rules

- DuckDB is the only database engine.
- STIX 2.1 is the only accepted STIX generation.
- OASIS `cti-python-stix2` is the authority for standard STIX object handling at ingestion; do not recreate the standard object schema manually in Firepit.
- Use OASIS `stix2-patterns` when Firepit must inspect STIX patterns. Do not approximate the pattern grammar with regular expressions or another local parser.
- Keep OASIS STIX dependencies out of the public query path. They belong to the optional private ingestion path.
- The public session schema contains the complete `PUBLIC_VIEWS` family and no base tables. The two unsuffixed Sentinel-inspired views are the stable base schema contracts; `Ex` and `W` are derived from them.
- Physical relations under `__firepit_<session>` are private and may change between model versions.
- Do not expose a DuckDB connection, cursor, relation, arbitrary execution object, or mutation API from the public package surface.
- Public SQL remains one read-only `SELECT` statement and must not expose Firepit internals, catalogs, attachment, or external file access.
- Preserve the complete canonical STIX object in `Data`; do not truncate standard or custom content merely to fit convenience columns.
- Versioned STIX objects are ordered by `modified`; arrival order must not decide the canonical version.
- Acquisition executions use `run_id`; do not overload a source query identifier as run identity.
- Receiving identical canonical content from another source must not change `SourceSystem` solely because it arrived later.
- Bump the public `VIEW_VERSION` whenever an existing database needs its view definitions recreated because the public view SQL changed.
- Do not add a second normalized storage representation or a staging/MERGE subsystem without a demonstrated workload that justifies the additional model and lifecycle.
- Do not reintroduce Pandas/dataframe native-result translation, HTTP acquisition, Kestrel state, a database-independent query AST, a local STIX-pattern compiler, or automatic recursive dereferencing.

## Tests

Tests should target public and semantic contracts rather than private table layouts. Important cases include:

- public handle exposes query helpers but no DuckDB API;
- DDL, DML, multiple statements, catalogs, internals, and external access are rejected;
- public schema contains the expected view family and zero base tables;
- public view version is present and current;
- Sentinel-inspired base column schemas remain stable;
- standard STIX 2.1 object handling is delegated to OASIS;
- a single unqualified equality Indicator can produce `ObservableKey`/`ObservableValue`;
- compound or qualified Indicator patterns are not reduced to a misleading single observable;
- custom object content is retained in `Data`;
- acquisition runs have independent identities;
- older mutable object versions cannot overwrite newer ones;
- conflicting content at the same `modified` timestamp is rejected;
- identical re-ingestion does not reassign the canonical source;
- database reopen behavior remains deterministic.

## Commit structure

Keep correctness fixes, public-contract changes, and documentation changes independently reviewable. Changes to private storage are acceptable when they do not widen or silently alter the public contract.
