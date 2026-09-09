#!/usr/bin/env python

"""Streaming helpers for local STIX bundle input."""

from collections import OrderedDict
from collections import defaultdict

import ijson
import ujson

from firepit import stix21


def _get_objects(fp, types):
    try:
        for obj in ijson.items(fp, 'objects.item'):
            if not types or obj['type'] in types:
                yield obj
    except ijson.common.IncompleteJSONError:
        pass


def _yield_objects(bundle, types):
    if 'type' not in bundle or bundle['type'] != 'bundle':
        bundle = {}
    for obj in bundle.get('objects', []):
        if not types or obj.get('type') in types:
            yield obj


def get_objects(source, types=None):
    """Yield STIX objects from an in-memory bundle, file-like object or file path.

    Remote acquisition intentionally does not live in Firepit. Authentication,
    HTTP, retries, paging and STIX-Shifter orchestration belong in the caller.
    """
    if isinstance(source, dict):
        yield from _yield_objects(source, types)
    elif hasattr(source, 'read'):
        yield from _get_objects(source, types)
    else:
        with open(source, 'r') as fp:
            bundle = ujson.loads(fp.read())
        yield from _yield_objects(bundle, types)


def _set_id(obs):
    sid = stix21.makeid(obs)
    obs['id'] = sid
    return sid


def json_normalize(d, prefix='', sep='.', flat_lists=False):
    r = OrderedDict()
    otype = d.get('type', '')
    for k, v in d.items():
        if '-' in k:
            if ':' in k:
                otype, _, path = k.rpartition(':')
                parts = path.split('.')
                key = f"{otype}:" + '.'.join([f"'{part}'" if '-' in part else part for part in parts])
            else:
                key = f"'{k}'"
        else:
            key = k
        if prefix:
            key = f'{prefix}{sep}{key}'
        if k == 'extensions' or (isinstance(v, dict) and not (isinstance(otype, str) and otype.startswith('x-'))):
            r.update(json_normalize(v, key, sep, flat_lists))
        elif flat_lists and isinstance(v, list):
            for i, val in enumerate(v):
                r[f'{key}[{i}]'] = val
        else:
            r[key] = v
    return r


def upgrade_2021(obs):
    """Upgrade a STIX 2.0 observation to a STIX 2.1-shaped observation."""
    results = [obs]
    if 'objects' not in obs:
        return results
    scos = obs['objects']
    object_refs = set()
    ref_map = {}
    for idx, sco in scos.items():
        sid = _set_id(sco)
        ref_map[idx] = sid
        object_refs.add(sid)
        sco['spec_version'] = '2.1'
        if 'binary_ref' in sco:
            sco['image_ref'] = sco.pop('binary_ref')
        results.append(sco)

    for obj in results:
        if obj['type'] == 'relationship':
            continue
        for prop, val in list(obj.items()):
            if prop.endswith('_ref'):
                if val.isdigit():
                    obj[prop] = ref_map[val]
            elif prop.endswith('_refs'):
                refs = []
                if isinstance(val, list):
                    for item in val:
                        if item.isdigit():
                            refs.append(ref_map[item])
                elif val.isdigit():
                    refs.append(ref_map[val])
                if refs:
                    obj[prop] = refs
                else:
                    del obj[prop]

    del obs['objects']
    obs['object_refs'] = list(object_refs)
    obs['spec_version'] = '2.1'
    return results


def _rank(results, sco_id, rank):
    for result in results:
        if result['type'] == '__contains' and result['target_ref'] == sco_id:
            result['x_firepit_rank'] = rank


def flatten_21(obj):
    """Legacy compatibility flattening for STIX 2.1 objects."""
    results = []
    oid = str(obj['id'])
    obj['id'] = oid

    obj_type = obj['type']
    if obj_type == 'identity':
        return [obj]
    if obj_type == 'observed-data':
        for ref in obj['object_refs']:
            results.append({
                'type': '__contains',
                'source_ref': oid,
                'target_ref': str(ref),
            })
        del obj['object_refs']
        results.append(json_normalize(obj, flat_lists=False))
        return results

    ref_lists = []
    for prop, val in obj.items():
        if prop.endswith('_ref'):
            obj[prop] = str(val)
        elif prop.endswith('_refs'):
            if not isinstance(val, list):
                val = [val]
            for ref in val:
                ref = str(ref)
                if ref != oid:
                    results.append({
                        'type': '__reflist',
                        'ref_name': prop,
                        'source_ref': oid,
                        'target_ref': ref,
                    })
            ref_lists.append(prop)

    for prop in ref_lists:
        del obj[prop]
    results.append(json_normalize(obj, flat_lists=False))
    return results


def flatten(obs):
    """Legacy relational flattening retained until native storage cutover."""
    if obs.get('spec_version', '2.0') == '2.1' or 'object_refs' in obs:
        return flatten_21(obs)
    if 'objects' not in obs:
        return [obs]

    scos = obs['objects']
    ref_map = {}
    results = []
    prefs = defaultdict(list)
    reffed = set()

    for idx, orig_sco in scos.items():
        sco = json_normalize(orig_sco, flat_lists=False)
        prefs[sco['type']].append(idx)
        sid = stix21.makeid(orig_sco, obs)
        orig_sco['id'] = sid
        sco['id'] = sid
        ref_map[idx] = sid

        ref_lists = []
        for prop, val in sco.items():
            if prop.endswith('_ref'):
                if val in scos and val != idx:
                    if scos[idx]['type'] == scos[val]['type']:
                        _mark_tree(scos, val, reffed)
                    elif scos[val]['type'].endswith('-addr'):
                        if 'dst_' in prop:
                            reffed.add(val)
                        elif prop.endswith('src_ref'):
                            prefs[scos[val]['type']].insert(0, val)
                    elif val in reffed:
                        reffed.add(idx)
            elif prop.endswith('_refs'):
                if not isinstance(val, list):
                    val = [val]
                for ref in val:
                    if ref in scos and ref != idx:
                        results.append({
                            'type': '__reflist',
                            'ref_name': prop,
                            'source_ref': idx,
                            'target_ref': ref,
                        })
                        if scos[idx]['type'] == scos[ref]['type']:
                            reffed.add(ref)
                ref_lists.append(prop)

        for prop in ref_lists:
            del sco[prop]

        results.append({
            'type': '__contains',
            'source_ref': obs['id'],
            'target_ref': sco['id'],
        })
        results.append(sco)

    for obj in results:
        if obj['type'] in ('__contains', 'relationship'):
            continue
        invalid = []
        for prop, val in obj.items():
            if prop.endswith('_ref'):
                if val not in ref_map:
                    invalid.append(prop)
                else:
                    obj[prop] = ref_map[val]
        for prop in invalid:
            del obj[prop]

        obj_type = obj['type']
        k = None
        for idx, sid in ref_map.items():
            if sid == obj.get('id'):
                k = idx
        if k and k not in reffed:
            if obj_type not in prefs:
                _rank(results, scos[k]['id'], 1)
            else:
                for item in prefs[obj_type]:
                    if item in reffed:
                        continue
                    if item == k:
                        _rank(results, scos[k]['id'], 1)
                    break

    del obs['objects']
    results.append(json_normalize(obs, flat_lists=False))
    return results


def _mark_tree(objs, k, reffed):
    reffed.add(k)
    for attr, val in objs[k].items():
        if attr.endswith('_ref'):
            if val not in objs or val == k:
                continue
            _mark_tree(objs, val, reffed)
        elif attr.endswith('_refs'):
            for ref in val:
                if ref not in objs or ref == k:
                    continue
                _mark_tree(objs, ref, reffed)
