# Contributing

Firepit 3 has completed the DuckDB-native reduction. Contributions should preserve the narrow storage boundary rather than rebuild historical compatibility layers.

## Development setup

Use CPython 3.11 through 3.14.

```bash
python -m pip install -e ".[test]"
python -m pytest
```

CI runs the supported Python range on Linux, macOS, and Windows.

## Design rules

- DuckDB is the only storage backend.
- STIX 2.1 is the only supported storage model.
- Prefer scalar, `STRUCT`, `LIST`, and `MAP` types when STIX defines the shape.
- Use JSON only for raw provenance, unknown/custom content, or genuinely heterogeneous fields.
- Known-field type errors must fail ingestion rather than silently become `NULL`.
- Do not add Pandas/dataframe processing to core storage.
- Do not add HTTP acquisition, credentials, connector polling, or STIX-Shifter execution to Firepit.
- Do not reintroduce a database-independent query AST or local STIX-pattern compiler.
- Do not reintroduce Kestrel variable/appdata semantics.
- Do not auto-dereference arbitrary references.
- Prefer direct DuckDB SQL and small explicit views for analytical behavior.

## Tests

New behavior should be covered at the semantic boundary. Important cases include:

- native nested STIX types;
- malformed known fields;
- custom/unknown property retention;
- list references and explicit enrichment views;
- repeated SCO identity across runs;
- multiple `observed-data` records;
- `observation_records` versus `observation_count`;
- idempotent re-ingestion of the same STIX object ID;
- persistence/reopen behavior;
- explicit rejection of STIX 2.0 and pre-native databases;
- representative STIX-Shifter 2.1 bundle shapes.

## Commit structure

Keep unrelated changes independently reviewable. Architectural changes should explain which semantic boundary they alter and why the change belongs in Firepit rather than acquisition or analysis.
