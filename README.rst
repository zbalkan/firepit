===============================
Firepit - STIX Storage for DuckDB
===============================


.. image:: https://img.shields.io/pypi/v/firepit.svg
        :target: https://pypi.python.org/pypi/firepit

.. image:: https://readthedocs.org/projects/firepit/badge/?version=latest
        :target: https://firepit.readthedocs.io/en/latest/?badge=latest
        :alt: Documentation Status


Firepit stores STIX data in DuckDB and is being modernized around DuckDB's
native analytical and nested data types.

This modernization branch supports CPython 3.11 through 3.14.

* Free software: Apache Software License 2.0
* Documentation: https://firepit.readthedocs.io


Current direction
-----------------

The original Firepit transformed STIX observations into a relational shape for
SQLite/PostgreSQL and was primarily designed as the local data store for
Kestrel.  This branch deliberately narrows that architecture:

* DuckDB is the only database backend.
* Known STIX 2.1 structure is being moved to native scalar, ``LIST``, ``MAP``,
  and ``STRUCT`` columns instead of flattened text columns.
* Complete source objects can be retained as JSON for provenance and unknown or
  custom properties.
* STIX-Shifter/remote acquisition belongs in the Python orchestration layer;
  Firepit is the storage and analytical boundary.
* DuckDB SQL and optional PRQL are the intended local query languages.

The remaining Kestrel-era compatibility APIs and flattened-schema machinery are
being retired incrementally.  See ``MODERNIZATION_ROADMAP.md`` for the planned
cutover and deletion order.


Motivation
----------

STIX is a graph-like data model with nested objects and references.  DuckDB can
represent much of that structure directly while still providing a relational
analytical interface.  The modernization therefore avoids emulating nested
STIX structure through backend-portable text columns where DuckDB has a native
type for the same concept.

The acquisition boundary remains STIX 2.1 JSON.  A separate Python layer can
use `STIX-Shifter <https://github.com/opencybersecurityalliance/stix-shifter>`_
to authenticate to remote sources, translate and execute queries, handle
pagination/retries, and deliver the resulting STIX JSON to Firepit.


Roadmap
-------

The detailed code-reduction and compatibility-removal plan is maintained in
`MODERNIZATION_ROADMAP.md <MODERNIZATION_ROADMAP.md>`_.
