from firepit import get_storage
from firepit.stixschema import column_type
from firepit.stixschema import schema_for


def test_common_properties_are_scoped_to_scos():
    assert 'defanged' in schema_for('process')
    assert 'defanged' not in schema_for('identity')
    assert 'defanged' not in schema_for('observed-data')
    assert 'defanged' not in schema_for('relationship')


def test_relationship_has_native_analysis_fields():
    schema = schema_for('relationship')
    assert schema['relationship_type'] == 'VARCHAR'
    assert schema['source_ref'] == 'VARCHAR'
    assert schema['target_ref'] == 'VARCHAR'
    assert schema['start_time'] == 'TIMESTAMPTZ'


def test_standard_extensions_are_structs():
    process = column_type('process', 'extensions')
    network = column_type('network-traffic', 'extensions')
    file_type = column_type('file', 'extensions')
    user = column_type('user-account', 'extensions')

    assert process.startswith('STRUCT(')
    assert '"windows-process-ext" STRUCT(' in process
    assert '"windows-service-ext" STRUCT(' in process
    assert '"http-request-ext" STRUCT(' in network
    assert '"tcp-ext" STRUCT(' in network
    assert '"archive-ext" STRUCT(' in file_type
    assert '"windows-pebinary-ext" STRUCT(' in file_type
    assert '"unix-account-ext" STRUCT(' in user


def test_known_heterogeneous_extension_members_remain_json():
    process = column_type('process', 'extensions')
    file_type = column_type('file', 'extensions')
    assert '"startup_info" JSON' in process
    assert '"exif_tags" JSON' in file_type


def _extension_bundle():
    return {
        'type': 'bundle',
        'objects': [
            {
                'type': 'process',
                'spec_version': '2.1',
                'id': 'process--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                'pid': 100,
                'extensions': {
                    'windows-process-ext': {
                        'aslr_enabled': True,
                        'dep_enabled': True,
                        'owner_sid': 'S-1-5-18',
                        'future_standard_field': 'preserve-me',
                    },
                    'x-vendor-process-ext': {
                        'risk': 7,
                    },
                },
            },
            {
                'type': 'network-traffic',
                'spec_version': '2.1',
                'id': 'network-traffic--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                'protocols': ['tcp', 'http'],
                'extensions': {
                    'http-request-ext': {
                        'request_method': 'get',
                        'request_value': '/',
                        'request_header': {
                            'User-Agent': ['test-agent'],
                        },
                    },
                    'tcp-ext': {
                        'src_flags_hex': '00000002',
                    },
                },
            },
        ],
    }


def test_native_storage_exposes_standard_extensions_as_struct(tmpdir):
    store = get_storage(str(tmpdir.join('extensions.db')), 'hunt')
    try:
        store.cache('q1', _extension_bundle())
        row = store._query(
            'SELECT extensions, typeof(extensions) AS dtype FROM "process"'
        ).fetchone()
        assert row['dtype'].startswith('STRUCT(')
        win = row['extensions']['windows-process-ext']
        assert win['aslr_enabled'] is True
        assert win['owner_sid'] == 'S-1-5-18'
        assert 'future_standard_field' not in win

        row = store._query(
            'SELECT extensions FROM "network-traffic"'
        ).fetchone()
        http = row['extensions']['http-request-ext']
        assert http['request_header']['User-Agent'] == ['test-agent']
        assert row['extensions']['tcp-ext']['src_flags_hex'] == '00000002'
    finally:
        store.close()


def test_unknown_extension_members_survive_in_raw_json(tmpdir):
    store = get_storage(str(tmpdir.join('extensions.db')), 'hunt')
    try:
        store.cache('q1', _extension_bundle())
        row = store._query(
            'SELECT '
            'json_extract_string(_raw, '
            '\'$.extensions."windows-process-ext".future_standard_field\') '
            'AS future_field, '
            'json_extract(_raw, \'$.extensions."x-vendor-process-ext".risk\') '
            'AS vendor_risk '
            'FROM "process"'
        ).fetchone()
        assert row['future_field'] == 'preserve-me'
        assert str(row['vendor_risk']) == '7'
    finally:
        store.close()
