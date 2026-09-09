from firepit.stixschema import column_type
from firepit.stixschema import rendered_schema
from firepit.stixschema import render_type
from firepit.stixschema import schema_for
from firepit.stixschema import list_of
from firepit.stixschema import map_of
from firepit.stixschema import struct


def test_render_nested_types():
    assert render_type(list_of('VARCHAR')) == 'VARCHAR[]'
    assert render_type(map_of('VARCHAR', 'VARCHAR')) == 'MAP(VARCHAR, VARCHAR)'
    assert render_type(list_of(struct({
        'name': 'VARCHAR',
        'size': 'UBIGINT',
    }))) == 'STRUCT("name" VARCHAR, "size" UBIGINT)[]'


def test_network_traffic_uses_complete_native_shape():
    assert column_type('network-traffic', 'protocols') == 'VARCHAR[]'
    assert column_type('network-traffic', 'src_port') == 'USMALLINT'
    assert column_type('network-traffic', 'src_byte_count') == 'UBIGINT'
    assert column_type('network-traffic', 'start') == 'TIMESTAMPTZ'
    assert column_type('network-traffic', 'ipfix') == 'JSON'
    assert column_type('network-traffic', 'src_payload_ref') == 'VARCHAR'
    assert column_type('network-traffic', 'dst_payload_ref') == 'VARCHAR'
    assert column_type('network-traffic', 'encapsulates_refs') == 'VARCHAR[]'
    assert column_type('network-traffic', 'encapsulated_by_ref') == 'VARCHAR'


def test_sco_common_fields_are_native():
    schema = rendered_schema('url')
    assert schema['defanged'] == 'BOOLEAN'
    assert schema['object_marking_refs'] == 'VARCHAR[]'
    assert schema['granular_markings'].startswith('STRUCT(')
    assert schema['granular_markings'].endswith('[]')
    assert schema['extensions'] == 'MAP(VARCHAR, JSON)'


def test_sdo_and_sro_common_fields_are_native():
    indicator = rendered_schema('indicator')
    relationship = rendered_schema('relationship')
    for schema in (indicator, relationship):
        assert schema['created'] == 'TIMESTAMPTZ'
        assert schema['modified'] == 'TIMESTAMPTZ'
        assert schema['confidence'] == 'UTINYINT'
        assert schema['external_references'].startswith('STRUCT(')
        assert schema['object_marking_refs'] == 'VARCHAR[]'
        assert schema['extensions'] == 'MAP(VARCHAR, JSON)'


def test_artifact_and_identity_include_standard_fields():
    assert column_type('artifact', 'encryption_algorithm') == 'VARCHAR'
    assert column_type('artifact', 'decryption_key') == 'VARCHAR'
    assert column_type('identity', 'description') == 'VARCHAR'
    assert column_type('identity', 'roles') == 'VARCHAR[]'


def test_file_hashes_are_map_not_json():
    assert column_type('file', 'hashes') == 'MAP(VARCHAR, VARCHAR)'
    assert column_type('file', 'contains_refs') == 'VARCHAR[]'


def test_registry_values_are_list_of_structs():
    assert column_type('windows-registry-key', 'values') == (
        'STRUCT("name" VARCHAR, "data" VARCHAR, "data_type" VARCHAR)[]'
    )


def test_process_environment_is_map():
    assert column_type('process', 'environment_variables') == (
        'MAP(VARCHAR, VARCHAR)'
    )


def test_observed_data_object_refs_are_native_list():
    assert column_type('observed-data', 'object_refs') == 'VARCHAR[]'


def test_known_email_and_x509_shapes_are_native():
    assert column_type('email-message', 'additional_header_fields') == (
        'MAP(VARCHAR, VARCHAR[])'
    )
    body = column_type('email-message', 'body_multipart')
    assert body.startswith('STRUCT(')
    assert body.endswith('[]')
    assert '"body_raw_ref" VARCHAR' in body

    x509 = column_type('x509-certificate', 'x509_v3_extensions')
    assert x509.startswith('STRUCT(')
    assert '"basic_constraints" VARCHAR' in x509
    assert '"private_key_usage_period_not_before" TIMESTAMPTZ' in x509


def test_json_is_exception_not_default():
    process = column_type('process', 'extensions')
    file_type = column_type('file', 'extensions')
    assert '"startup_info" JSON' in process
    assert '"exif_tags" JSON' in file_type
    assert column_type('network-traffic', 'ipfix') == 'JSON'
    assert column_type('file', 'not_a_stix_property') is None


def test_windows_process_errata_field_name_is_preserved():
    process = column_type('process', 'extensions')
    assert '"windows_title" VARCHAR' in process


def test_schema_for_returns_copy():
    schema = schema_for('file')
    schema['name'] = 'BROKEN'
    assert column_type('file', 'name') == 'VARCHAR'


def test_rendered_schema_is_tooling_ready():
    schema = rendered_schema('process')
    assert schema['id'] == 'VARCHAR'
    assert schema['created_time'] == 'TIMESTAMPTZ'
    assert schema['opened_connection_refs'] == 'VARCHAR[]'
