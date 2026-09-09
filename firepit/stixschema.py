"""DuckDB-native type definitions for the STIX 2.1 data model.

Firepit historically inferred SQL columns from observed values because its
SQLite/PostgreSQL backends had no useful nested type system.  DuckDB does, so
known STIX structure should be represented with native scalar, LIST, STRUCT,
and MAP types.  JSON is reserved for properties whose shape is genuinely
heterogeneous or intentionally open-ended.

This module is deliberately independent of ingestion.  It is the schema
contract that the DuckDB writer can adopt incrementally without changing the
public storage/query API in the same commit.
"""

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class ListType:
    element: object


@dataclass(frozen=True)
class MapType:
    key: object
    value: object


@dataclass(frozen=True)
class StructType:
    fields: Mapping[str, object]


def list_of(element):
    return ListType(element)


def map_of(key, value):
    return MapType(key, value)


def struct(fields):
    return StructType(dict(fields))


def _quote_field(name):
    return '"' + name.replace('"', '""') + '"'


def render_type(type_spec):
    """Render a schema type specification as DuckDB SQL type syntax."""
    if isinstance(type_spec, str):
        return type_spec
    if isinstance(type_spec, ListType):
        return f'{render_type(type_spec.element)}[]'
    if isinstance(type_spec, MapType):
        return f'MAP({render_type(type_spec.key)}, {render_type(type_spec.value)})'
    if isinstance(type_spec, StructType):
        fields = ', '.join(
            f'{_quote_field(name)} {render_type(field_type)}'
            for name, field_type in type_spec.fields.items()
        )
        return f'STRUCT({fields})'
    raise TypeError(f'unsupported STIX type specification: {type_spec!r}')


COMMON_SCO_FIELDS = {
    'id': 'VARCHAR',
    'defanged': 'BOOLEAN',
}


STIX_21_SCHEMAS = {
    'artifact': {
        'mime_type': 'VARCHAR',
        # STIX carries this as base64 text.  Keep the lexical form rather than
        # silently changing API semantics by decoding it into BLOB here.
        'payload_bin': 'VARCHAR',
        'url': 'VARCHAR',
        'hashes': map_of('VARCHAR', 'VARCHAR'),
    },
    'autonomous-system': {
        'number': 'UBIGINT',
        'name': 'VARCHAR',
        'rir': 'VARCHAR',
    },
    'directory': {
        'path': 'VARCHAR',
        'path_enc': 'VARCHAR',
        'ctime': 'TIMESTAMPTZ',
        'mtime': 'TIMESTAMPTZ',
        'atime': 'TIMESTAMPTZ',
        'contains_refs': list_of('VARCHAR'),
    },
    'domain-name': {
        'value': 'VARCHAR',
        'resolves_to_refs': list_of('VARCHAR'),
    },
    'email-addr': {
        'value': 'VARCHAR',
        'display_name': 'VARCHAR',
        'belongs_to_ref': 'VARCHAR',
    },
    'email-message': {
        'is_multipart': 'BOOLEAN',
        'date': 'TIMESTAMPTZ',
        'content_type': 'VARCHAR',
        'from_ref': 'VARCHAR',
        'sender_ref': 'VARCHAR',
        'to_refs': list_of('VARCHAR'),
        'cc_refs': list_of('VARCHAR'),
        'bcc_refs': list_of('VARCHAR'),
        'message_id': 'VARCHAR',
        'subject': 'VARCHAR',
        'received_lines': list_of('VARCHAR'),
        # Header values may be scalar or repeated and therefore do not have a
        # single homogeneous MAP value type.  This is an intentional JSON
        # exception rather than flattening each arbitrary header into columns.
        'additional_header_fields': 'JSON',
        'body': 'VARCHAR',
        'raw_email_ref': 'VARCHAR',
    },
    'file': {
        'hashes': map_of('VARCHAR', 'VARCHAR'),
        'size': 'UBIGINT',
        'name': 'VARCHAR',
        'name_enc': 'VARCHAR',
        'magic_number_hex': 'VARCHAR',
        'mime_type': 'VARCHAR',
        'ctime': 'TIMESTAMPTZ',
        'mtime': 'TIMESTAMPTZ',
        'atime': 'TIMESTAMPTZ',
        'parent_directory_ref': 'VARCHAR',
        'contains_refs': list_of('VARCHAR'),
        'content_ref': 'VARCHAR',
    },
    'ipv4-addr': {
        'value': 'VARCHAR',
        'resolves_to_refs': list_of('VARCHAR'),
        'belongs_to_refs': list_of('VARCHAR'),
    },
    'ipv6-addr': {
        'value': 'VARCHAR',
        'resolves_to_refs': list_of('VARCHAR'),
        'belongs_to_refs': list_of('VARCHAR'),
    },
    'mac-addr': {
        'value': 'VARCHAR',
    },
    'mutex': {
        'name': 'VARCHAR',
    },
    'network-traffic': {
        'start': 'TIMESTAMPTZ',
        'end': 'TIMESTAMPTZ',
        'is_active': 'BOOLEAN',
        'src_ref': 'VARCHAR',
        'dst_ref': 'VARCHAR',
        'src_port': 'USMALLINT',
        'dst_port': 'USMALLINT',
        'protocols': list_of('VARCHAR'),
        'src_byte_count': 'UBIGINT',
        'dst_byte_count': 'UBIGINT',
        'src_packets': 'UBIGINT',
        'dst_packets': 'UBIGINT',
    },
    'process': {
        'is_hidden': 'BOOLEAN',
        'pid': 'UBIGINT',
        'created_time': 'TIMESTAMPTZ',
        'cwd': 'VARCHAR',
        'command_line': 'VARCHAR',
        'environment_variables': map_of('VARCHAR', 'VARCHAR'),
        'opened_connection_refs': list_of('VARCHAR'),
        'creator_user_ref': 'VARCHAR',
        'image_ref': 'VARCHAR',
        'parent_ref': 'VARCHAR',
        'child_refs': list_of('VARCHAR'),
    },
    'software': {
        'name': 'VARCHAR',
        'cpe': 'VARCHAR',
        'swid': 'VARCHAR',
        'languages': list_of('VARCHAR'),
        'vendor': 'VARCHAR',
        'version': 'VARCHAR',
    },
    'url': {
        'value': 'VARCHAR',
    },
    'user-account': {
        'user_id': 'VARCHAR',
        'credential': 'VARCHAR',
        'account_login': 'VARCHAR',
        'account_type': 'VARCHAR',
        'display_name': 'VARCHAR',
        'is_service_account': 'BOOLEAN',
        'is_privileged': 'BOOLEAN',
        'can_escalate_privs': 'BOOLEAN',
        'is_disabled': 'BOOLEAN',
        'account_created': 'TIMESTAMPTZ',
        'account_expires': 'TIMESTAMPTZ',
        'credential_last_changed': 'TIMESTAMPTZ',
        'account_first_login': 'TIMESTAMPTZ',
        'account_last_login': 'TIMESTAMPTZ',
    },
    'windows-registry-key': {
        'key': 'VARCHAR',
        'values': list_of(struct({
            'name': 'VARCHAR',
            'data': 'VARCHAR',
            'data_type': 'VARCHAR',
        })),
        'modified_time': 'TIMESTAMPTZ',
        'creator_user_ref': 'VARCHAR',
        'number_of_subkeys': 'UBIGINT',
    },
    'x509-certificate': {
        'is_self_signed': 'BOOLEAN',
        'hashes': map_of('VARCHAR', 'VARCHAR'),
        'version': 'VARCHAR',
        'serial_number': 'VARCHAR',
        'signature_algorithm': 'VARCHAR',
        'issuer': 'VARCHAR',
        'validity_not_before': 'TIMESTAMPTZ',
        'validity_not_after': 'TIMESTAMPTZ',
        'subject': 'VARCHAR',
        'subject_public_key_algorithm': 'VARCHAR',
        'subject_public_key_modulus': 'VARCHAR',
        'subject_public_key_exponent': 'UBIGINT',
        # The extension dictionary contains optional substructures and is kept
        # as the explicit open-ended exception until its standard sub-schema
        # is modelled as STRUCT fields.
        'x509_v3_extensions': 'JSON',
    },
    # Firepit stores these SDOs alongside SCO tables and they are part of the
    # observation/query model, so give them the same explicit DuckDB schema.
    'identity': {
        'identity_class': 'VARCHAR',
        'name': 'VARCHAR',
        'sectors': list_of('VARCHAR'),
        'contact_information': 'VARCHAR',
        'created': 'TIMESTAMPTZ',
        'modified': 'TIMESTAMPTZ',
    },
    'observed-data': {
        'created_by_ref': 'VARCHAR',
        'created': 'TIMESTAMPTZ',
        'modified': 'TIMESTAMPTZ',
        'first_observed': 'TIMESTAMPTZ',
        'last_observed': 'TIMESTAMPTZ',
        'number_observed': 'UBIGINT',
        'object_refs': list_of('VARCHAR'),
    },
}


def schema_for(obj_type):
    """Return a copy of the known native DuckDB schema for *obj_type*."""
    fields = dict(COMMON_SCO_FIELDS)
    fields.update(STIX_21_SCHEMAS.get(obj_type, {}))
    return fields


def column_type(obj_type, property_name):
    """Return DuckDB SQL type syntax for a known STIX property, or ``None``."""
    type_spec = schema_for(obj_type).get(property_name)
    return render_type(type_spec) if type_spec is not None else None


def rendered_schema(obj_type):
    """Return all known fields for *obj_type* with rendered DuckDB types."""
    return {name: render_type(type_spec)
            for name, type_spec in schema_for(obj_type).items()}
