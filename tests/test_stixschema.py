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


def test_network_traffic_uses_native_list_and_numeric_types():
    assert column_type('network-traffic', 'protocols') == 'VARCHAR[]'
    assert column_type('network-traffic', 'src_port') == 'USMALLINT'
    assert column_type('network-traffic', 'src_byte_count') == 'UBIGINT'
    assert column_type('network-traffic', 'start') == 'TIMESTAMPTZ'


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


def test_json_is_explicit_exception_not_default():
    assert column_type('email-message', 'additional_header_fields') == 'JSON'
    assert column_type('x509-certificate', 'x509_v3_extensions') == 'JSON'
    assert column_type('file', 'not_a_stix_property') is None


def test_schema_for_returns_copy():
    schema = schema_for('file')
    schema['name'] = 'BROKEN'
    assert column_type('file', 'name') == 'VARCHAR'


def test_rendered_schema_is_tooling_ready():
    schema = rendered_schema('process')
    assert schema['id'] == 'VARCHAR'
    assert schema['created_time'] == 'TIMESTAMPTZ'
    assert schema['opened_connection_refs'] == 'VARCHAR[]'
