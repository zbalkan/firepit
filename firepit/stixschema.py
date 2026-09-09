"""DuckDB-native type definitions for the STIX 2.1 data model.

Known STIX structure is represented with DuckDB scalar, LIST, MAP and STRUCT
columns. JSON is an explicit exception for genuinely heterogeneous or
open-ended values; it is not the default storage type.
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


HASHES = map_of('VARCHAR', 'VARCHAR')

EMAIL_MIME_PART = struct({
    'body': 'VARCHAR',
    'body_raw_ref': 'VARCHAR',
    'content_type': 'VARCHAR',
    'content_disposition': 'VARCHAR',
})

WINDOWS_PROCESS_EXT = struct({
    'aslr_enabled': 'BOOLEAN',
    'dep_enabled': 'BOOLEAN',
    'priority': 'VARCHAR',
    'owner_sid': 'VARCHAR',
    'windows_title': 'VARCHAR',
    # STARTUP_INFO is a defined dictionary, but its values are not constrained
    # to one homogeneous scalar type by STIX.
    'startup_info': 'JSON',
    'integrity_level': 'VARCHAR',
})

WINDOWS_SERVICE_EXT = struct({
    'service_name': 'VARCHAR',
    'descriptions': list_of('VARCHAR'),
    'display_name': 'VARCHAR',
    'group_name': 'VARCHAR',
    'start_type': 'VARCHAR',
    'service_dll_refs': list_of('VARCHAR'),
    'service_type': 'VARCHAR',
    'service_status': 'VARCHAR',
})

PROCESS_EXTENSIONS = struct({
    'windows-process-ext': WINDOWS_PROCESS_EXT,
    'windows-service-ext': WINDOWS_SERVICE_EXT,
})

HTTP_REQUEST_EXT = struct({
    'request_method': 'VARCHAR',
    'request_value': 'VARCHAR',
    'request_version': 'VARCHAR',
    'request_header': map_of('VARCHAR', list_of('VARCHAR')),
    'message_body_length': 'UBIGINT',
    'message_body_data_ref': 'VARCHAR',
})

ICMP_EXT = struct({
    'icmp_type_hex': 'VARCHAR',
    'icmp_code_hex': 'VARCHAR',
})

SOCKET_EXT = struct({
    'address_family': 'VARCHAR',
    'is_blocking': 'BOOLEAN',
    'is_listening': 'BOOLEAN',
    'options': map_of('VARCHAR', 'BIGINT'),
    'socket_type': 'VARCHAR',
    'socket_descriptor': 'UBIGINT',
    'socket_handle': 'UBIGINT',
})

TCP_EXT = struct({
    'src_flags_hex': 'VARCHAR',
    'dst_flags_hex': 'VARCHAR',
})

NETWORK_TRAFFIC_EXTENSIONS = struct({
    'http-request-ext': HTTP_REQUEST_EXT,
    'icmp-ext': ICMP_EXT,
    'socket-ext': SOCKET_EXT,
    'tcp-ext': TCP_EXT,
})

ALTERNATE_DATA_STREAM = struct({
    'name': 'VARCHAR',
    'hashes': HASHES,
    'size': 'UBIGINT',
})

ARCHIVE_EXT = struct({
    'contains_refs': list_of('VARCHAR'),
    'comment': 'VARCHAR',
})

NTFS_EXT = struct({
    'sid': 'VARCHAR',
    'alternate_data_streams': list_of(ALTERNATE_DATA_STREAM),
})

PDF_EXT = struct({
    'version': 'VARCHAR',
    'is_optimized': 'BOOLEAN',
    'document_info_dict': map_of('VARCHAR', 'VARCHAR'),
    'pdfid0': 'VARCHAR',
    'pdfid1': 'VARCHAR',
})

RASTER_IMAGE_EXT = struct({
    'image_height': 'UBIGINT',
    'image_width': 'UBIGINT',
    'bits_per_pixel': 'UBIGINT',
    # EXIF values are explicitly allowed to be integer or string. Keep this
    # localized field as JSON until UNION conversion is implemented robustly.
    'exif_tags': 'JSON',
})

WINDOWS_PE_OPTIONAL_HEADER = struct({
    'magic_hex': 'VARCHAR',
    'major_linker_version': 'UBIGINT',
    'minor_linker_version': 'UBIGINT',
    'size_of_code': 'UBIGINT',
    'size_of_initialized_data': 'UBIGINT',
    'size_of_uninitialized_data': 'UBIGINT',
    'address_of_entry_point': 'UBIGINT',
    'base_of_code': 'UBIGINT',
    'base_of_data': 'UBIGINT',
    'image_base': 'UBIGINT',
    'section_alignment': 'UBIGINT',
    'file_alignment': 'UBIGINT',
    'major_os_version': 'UBIGINT',
    'minor_os_version': 'UBIGINT',
    'major_image_version': 'UBIGINT',
    'minor_image_version': 'UBIGINT',
    'major_subsystem_version': 'UBIGINT',
    'minor_subsystem_version': 'UBIGINT',
    'win32_version_value_hex': 'VARCHAR',
    'size_of_image': 'UBIGINT',
    'size_of_headers': 'UBIGINT',
    'checksum_hex': 'VARCHAR',
    'subsystem_hex': 'VARCHAR',
    'dll_characteristics_hex': 'VARCHAR',
    'size_of_stack_reserve': 'UBIGINT',
    'size_of_stack_commit': 'UBIGINT',
    'size_of_heap_reserve': 'UBIGINT',
    'size_of_heap_commit': 'UBIGINT',
    'loader_flags_hex': 'VARCHAR',
    'number_of_rva_and_sizes': 'UBIGINT',
    'hashes': HASHES,
})

WINDOWS_PE_SECTION = struct({
    'name': 'VARCHAR',
    'size': 'UBIGINT',
    'entropy': 'DOUBLE',
    'hashes': HASHES,
})

WINDOWS_PEBINARY_EXT = struct({
    'pe_type': 'VARCHAR',
    'imphash': 'VARCHAR',
    'machine_hex': 'VARCHAR',
    'number_of_sections': 'UBIGINT',
    'time_date_stamp': 'TIMESTAMPTZ',
    'pointer_to_symbol_table_hex': 'VARCHAR',
    'number_of_symbols': 'UBIGINT',
    'size_of_optional_header': 'UBIGINT',
    'characteristics_hex': 'VARCHAR',
    'file_header_hashes': HASHES,
    'optional_header': WINDOWS_PE_OPTIONAL_HEADER,
    'sections': list_of(WINDOWS_PE_SECTION),
})

FILE_EXTENSIONS = struct({
    'archive-ext': ARCHIVE_EXT,
    'ntfs-ext': NTFS_EXT,
    'pdf-ext': PDF_EXT,
    'raster-image-ext': RASTER_IMAGE_EXT,
    'windows-pebinary-ext': WINDOWS_PEBINARY_EXT,
})

UNIX_ACCOUNT_EXT = struct({
    'gid': 'UBIGINT',
    'groups': list_of('VARCHAR'),
    'home_dir': 'VARCHAR',
    'shell': 'VARCHAR',
})

USER_ACCOUNT_EXTENSIONS = struct({
    'unix-account-ext': UNIX_ACCOUNT_EXT,
})

X509_V3_EXTENSIONS = struct({
    'basic_constraints': 'VARCHAR',
    'name_constraints': 'VARCHAR',
    'policy_constraints': 'VARCHAR',
    'key_usage': 'VARCHAR',
    'extended_key_usage': 'VARCHAR',
    'subject_key_identifier': 'VARCHAR',
    'authority_key_identifier': 'VARCHAR',
    'subject_alternative_name': 'VARCHAR',
    'issuer_alternative_name': 'VARCHAR',
    'subject_directory_attributes': 'VARCHAR',
    'crl_distribution_points': 'VARCHAR',
    'inhibit_any_policy': 'VARCHAR',
    'private_key_usage_period_not_before': 'TIMESTAMPTZ',
    'private_key_usage_period_not_after': 'TIMESTAMPTZ',
    'certificate_policies': 'VARCHAR',
    'policy_mappings': 'VARCHAR',
})

SCO_TYPES = {
    'artifact', 'autonomous-system', 'directory', 'domain-name',
    'email-addr', 'email-message', 'file', 'ipv4-addr', 'ipv6-addr',
    'mac-addr', 'mutex', 'network-traffic', 'process', 'software', 'url',
    'user-account', 'windows-registry-key', 'x509-certificate',
}

STIX_21_SCHEMAS = {
    'artifact': {
        'mime_type': 'VARCHAR',
        'payload_bin': 'VARCHAR',
        'url': 'VARCHAR',
        'hashes': HASHES,
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
        'additional_header_fields': map_of('VARCHAR', list_of('VARCHAR')),
        'body': 'VARCHAR',
        'body_multipart': list_of(EMAIL_MIME_PART),
        'raw_email_ref': 'VARCHAR',
    },
    'file': {
        'hashes': HASHES,
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
        'extensions': FILE_EXTENSIONS,
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
    'mac-addr': {'value': 'VARCHAR'},
    'mutex': {'name': 'VARCHAR'},
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
        'extensions': NETWORK_TRAFFIC_EXTENSIONS,
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
        'extensions': PROCESS_EXTENSIONS,
    },
    'software': {
        'name': 'VARCHAR',
        'cpe': 'VARCHAR',
        'swid': 'VARCHAR',
        'languages': list_of('VARCHAR'),
        'vendor': 'VARCHAR',
        'version': 'VARCHAR',
    },
    'url': {'value': 'VARCHAR'},
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
        'extensions': USER_ACCOUNT_EXTENSIONS,
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
        'hashes': HASHES,
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
        'x509_v3_extensions': X509_V3_EXTENSIONS,
    },
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
    'relationship': {
        'created_by_ref': 'VARCHAR',
        'created': 'TIMESTAMPTZ',
        'modified': 'TIMESTAMPTZ',
        'revoked': 'BOOLEAN',
        'labels': list_of('VARCHAR'),
        'confidence': 'USMALLINT',
        'lang': 'VARCHAR',
        'relationship_type': 'VARCHAR',
        'description': 'VARCHAR',
        'source_ref': 'VARCHAR',
        'target_ref': 'VARCHAR',
        'start_time': 'TIMESTAMPTZ',
        'stop_time': 'TIMESTAMPTZ',
    },
}


def schema_for(obj_type):
    """Return a copy of the known native DuckDB schema for *obj_type*."""
    fields = {'id': 'VARCHAR'}
    if obj_type in SCO_TYPES:
        fields['defanged'] = 'BOOLEAN'
    fields.update(STIX_21_SCHEMAS.get(obj_type, {}))
    return fields


def column_type(obj_type, property_name):
    """Return DuckDB SQL type syntax for a known STIX property, or ``None``."""
    type_spec = schema_for(obj_type).get(property_name)
    return render_type(type_spec) if type_spec is not None else None


def rendered_schema(obj_type):
    """Return all known fields for *obj_type* with rendered DuckDB types."""
    return {
        name: render_type(type_spec)
        for name, type_spec in schema_for(obj_type).items()
    }
