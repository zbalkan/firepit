class InvalidObject(Exception):
    """Input is not valid for the private STIX 2.1 ingestion boundary."""


class InvalidQuery(Exception):
    """A public Firepit query is not a permitted read-only SELECT."""


class InvalidSession(Exception):
    """A Firepit session/schema name is invalid."""
