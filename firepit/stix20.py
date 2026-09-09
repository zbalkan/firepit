import os
from collections import defaultdict

from lark import Lark, Transformer, v_args


# Temporary reference-path metadata used only by the local STIX-pattern
# compiler. The compiler and this metadata are deleted together in Phase 6.
def _ref_type(sco_type, part):
    if part == 'parent_ref':
        return ['process']
    if part in ['dst_ref', 'dst_ip_ref', 'src_ref', 'src_ip_ref']:
        return ['ipv4-addr', 'ipv6-addr']
    if sco_type in ['ipv4-addr', 'ipv6-addr'] and part == 'resolves_to_refs':
        return ['mac-addr']
    if part in ['binary_ref', 'image_ref']:
        return ['file']
    if part == 'parent_directory_ref':
        return ['directory']
    if part == 'creator_user_ref':
        return ['user-account']
    if part == 'opened_connection_refs':
        return ['network-traffic']
    if part in ['src_payload_ref', 'dst_payload_ref']:
        return ['artifact']
    if sco_type == 'email-message' and part in [
        'from_ref', 'sender_ref', 'to_refs', 'cc_refs', 'bcc_refs'
    ]:
        return ['email-addr']
    if sco_type == 'x-oca-event':
        mapping = {
            'original_ref': ['artifact'],
            'host_ref': ['x-oca-asset'],
            'url_ref': ['url'],
            'file_ref': ['file'],
            'domain_ref': ['domain-name'],
            'registry_ref': ['windows-registry-key'],
            'network_ref': ['network-traffic'],
            'user_ref': ['user-account'],
        }
        if part in mapping:
            return mapping[part]
        if 'process' in part:
            return ['process']
    return []


def _is_ref(name):
    return name.endswith('_ref') or name.endswith('_refs')


def _parse_prop(sco_type, prop):
    if '_ref.' not in prop and '_refs' not in prop:
        return [('node', sco_type, prop)]
    result = []
    current_type = sco_type
    for raw_part in prop.split('.'):
        is_list = raw_part.endswith('[*]')
        part = raw_part[:-3] if is_list else raw_part
        if not _is_ref(part):
            if is_list:
                part += '[*]'
            result.append(('node', current_type, part))
            continue
        targets = _ref_type(current_type, part)
        if not targets:
            return []
        target = targets[0]
        result.append(('rel', current_type, part, target))
        current_type = target
    return result


def get_grammar():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'paramstix.lark')
    with open(path, 'r', encoding='utf-8') as fp:
        return fp.read()


def stix2sql(pattern, sco_type):
    return Lark(
        get_grammar(), parser='lalr', transformer=_TranslateTree(sco_type)
    ).parse(pattern)


def _convert_op(sco_type, prop, op, rhs):
    original_op = op
    neg, _, op = op.rpartition(' ')
    if op == 'ISSUBSET':
        if sco_type == 'ipv4-addr' or prop in ['src_ref.value', 'dst_ref.value']:
            return f'{neg} (in_subnet("{prop}", {rhs}))'
        raise ValueError(f'{original_op} not supported for SCO type {sco_type}')
    if op == 'ISSUPERSET':
        if sco_type == 'ipv4-addr' or prop in ['src_ref.value', 'dst_ref.value']:
            return f'{neg} (in_subnet({rhs}, "{prop}"))'
        raise ValueError(f'{original_op} not supported for SCO type {sco_type}')
    if prop.endswith('payload_bin'):
        if op == 'MATCHES':
            return f'{neg} match_bin(CAST({rhs} AS TEXT), "{prop}")'
        if op == 'LIKE':
            return f'{neg} like_bin(CAST({rhs} AS TEXT), "{prop}")'
    if op == 'MATCHES':
        return f'{neg} match({rhs}, "{prop}")'

    prop, chunk, subprop = prop.partition('[*]')
    if chunk:
        if op == '!=':
            neg = 'NOT'
        op = 'LIKE'
        rhs = rhs.strip("'")
        if subprop:
            subprop = subprop.lstrip('.')
            rhs = f"'%\"{subprop}\":\"{rhs}\"%'"
        else:
            rhs = f"'%{rhs}%'"
    return f'"{prop}" {neg} {op} {rhs}'


def comp2sql(sco_type, prop, op, value):
    result = ''
    links = _parse_prop(sco_type, prop)
    for link in reversed(links):
        if link[0] == 'node':
            from_type = link[1] or sco_type
            result = _convert_op(from_type, link[2], op, value)
        elif link[0] == 'rel':
            _, _from_type, ref_name, to_type = link
            if ref_name.endswith('_refs'):
                result = (
                    f'EXISTS (SELECT 1 FROM UNNEST("{ref_name}") AS r(target_id) '
                    f'JOIN "{to_type}" AS target ON target.id = r.target_id '
                    f'WHERE {result})'
                )
            else:
                result = (
                    f'"{ref_name}" IN (SELECT "id" FROM "{to_type}" '
                    f'WHERE {result})'
                )
    return result


def path2sql(sco_type, path):
    result = ''
    links = _parse_prop(sco_type, path)
    for link in reversed(links):
        if link[0] == 'rel':
            result = f'"{link[2]}" IN (SELECT "id" FROM "{link[3]}" WHERE {result})'
    return result


@v_args(inline=True)
class _TranslateTree(Transformer):
    def __init__(self, sco_type):
        self.sco_type = sco_type

    def _make_comp(self, lhs, op, rhs):
        sco_type, _, prop = lhs.partition(':')
        return comp2sql(sco_type, prop, op, rhs) if self.sco_type == sco_type else ''

    @staticmethod
    def _make_exp(lhs, op, rhs):
        return op.join(filter(None, [lhs, rhs]))

    def disj(self, lhs, rhs):
        return self._make_exp(lhs, ' OR ', rhs)

    def conj(self, lhs, rhs):
        return self._make_exp(lhs, ' AND ', rhs)

    def obs_disj(self, lhs, rhs):
        return self.disj(lhs, rhs)

    def obs_conj(self, lhs, rhs):
        return self.conj(lhs, rhs)

    @staticmethod
    def comp_grp(exp):
        return f'({exp})' if exp else None

    def simple_comp_exp(self, lhs, op, rhs):
        return self._make_comp(lhs, op, rhs)

    def comp_disj(self, lhs, rhs):
        return self.disj(lhs, rhs)

    def comp_conj(self, lhs, rhs):
        return self.conj(lhs, rhs)

    @staticmethod
    def op(value):
        return f'{value}'

    @staticmethod
    def quoted_str(value):
        value = value.replace(r'\\', '\\').replace(r"\'", "''")
        return f"'{value}'"

    @staticmethod
    def lit_list(*args):
        return '(' + ','.join(args) + ')'

    @staticmethod
    def start(exp, _qualifier):
        return f'{exp}' if exp else None

    @staticmethod
    def object_path(sco_type, prop):
        return f'{sco_type}:{prop}'


def summarize_pattern(pattern):
    paths = Lark(
        get_grammar(), parser='lalr', transformer=_SummarizePattern()
    ).parse(pattern)
    result = defaultdict(set)
    for path in paths:
        sco_type, _, prop = path.partition(':')
        result[sco_type].add(prop)
    return result


@v_args(inline=True)
class _SummarizePattern(Transformer):
    @staticmethod
    def obs_disj(lhs, rhs):
        return lhs | rhs

    @staticmethod
    def obs_conj(lhs, rhs):
        return lhs & rhs

    @staticmethod
    def comp_grp(exp):
        return exp

    @staticmethod
    def simple_comp_exp(lhs, _op, _rhs):
        return {lhs}

    @staticmethod
    def comp_disj(lhs, rhs):
        return lhs | rhs

    @staticmethod
    def comp_conj(lhs, rhs):
        return lhs | rhs

    @staticmethod
    def op(_op):
        return None

    @staticmethod
    def quoted_str(_value):
        return None

    @staticmethod
    def lit_list(*_args):
        return None

    @staticmethod
    def start(exp, _qualifier):
        return exp

    @staticmethod
    def object_path(sco_type, prop):
        return f'{sco_type}:{prop}'
