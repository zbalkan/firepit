"""Firepit: query-only STIX 2.1 threat-intelligence views."""

__author__ = "IBM Security"
__email__ = "pcoccoli@us.ibm.com"
__version__ = "3.0.0"

from firepit.storage import Firepit, get_storage

__all__ = ["Firepit", "get_storage"]
