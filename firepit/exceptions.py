class InvalidAttr(Exception):
    """A requested DuckDB/STIX attribute is invalid."""


class InvalidObject(Exception):
    """Input is not valid for the STIX 2.1 storage boundary."""


class InvalidViewname(Exception):
    """A SQL identifier supplied as a table/view/session name is invalid."""


class UnknownViewname(Exception):
    """A requested DuckDB table or view does not exist."""
