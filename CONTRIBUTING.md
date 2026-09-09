# Contributing

Firepit is in the middle of a deliberate architectural reduction. Contributions should simplify the DuckDB-native STIX 2.1 path rather than preserve compatibility layers that are scheduled for removal.

## Development setup

Use CPython 3.11 through 3.14.

```bash
python -m pip install -e ".[test]"
python -m pytest
```

Run the full configured Python matrix with:

```bash
tox
```

## Design rules

Changes should follow these constraints:

- DuckDB is the only storage backend.
- STIX 2.1 is the target internal model.
- Prefer DuckDB scalar, `STRUCT`, `LIST`, and `MAP` types over JSON when the schema is known.
- JSON is a fallback for raw provenance, custom fields, or genuinely heterogeneous values.
- Do not introduce Pandas or dataframe processing into the core storage path.
- Do not add a new database-independent query abstraction.
- Do not reintroduce Kestrel-specific variable/state semantics.
- Acquisition, credentials, remote polling, pagination, and STIX-Shifter orchestration belong above Firepit.
- Analytical behavior should be expressed in DuckDB SQL or explicit views/macros.

## Tests

A change that removes a compatibility layer should add or retain tests for the replacement semantics, not for the implementation being deleted.

Important coverage areas include:

- nested standard STIX extensions;
- list references;
- mixed IPv4/IPv6 references;
- repeated SCO identity across acquisition runs;
- `number_observed > 1` semantics;
- custom property preservation;
- persistence after reopening a DuckDB file;
- Python 3.11-3.14.

## Commit structure

Keep architectural deletions independently reviewable. Prefer one commit per modernization phase or roadmap item. Large items may be split into a small number of coherent commits when required for correctness.
