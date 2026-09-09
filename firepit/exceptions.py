class InvalidObject(Exception):
    """Input is not valid for the STIX 2.1 storage boundary."""


class InvalidViewname(Exception):
    """A SQL identifier supplied as a table/view/session name is invalid."""
