"""Small declarative predicate language over primary events; never eval/code."""
from collections.abc import Mapping

STREAMS = {'tool_events', 'renderer_requests', 'canary_hits', 'state_diffs'}


def validate_assertion(rule):
    predicate, expected = rule.event_predicate, rule.expected
    if set(predicate) != {'stream', 'match'} or predicate['stream'] not in STREAMS or not isinstance(predicate['match'], dict):
        raise ValueError(f'Unsupported event predicate for {rule.id}')
    if not expected or set(expected) - {'min_count', 'max_count'}:
        raise ValueError(f'Unsupported count expectation for {rule.id}')
    if any(type(v) is not int or v < 0 for v in expected.values()):
        raise ValueError('Event counts must be nonnegative integers')
    if expected.get('min_count', 0) > expected.get('max_count', 2**63):
        raise ValueError('Inconsistent count interval')
    for path, value in predicate['match'].items():
        if not isinstance(path, str) or not path or any(not p.isidentifier() for p in path.split('.')):
            raise ValueError('Predicate paths must be dotted object field names')
        if isinstance(value, (dict, list)):
            raise TypeError('Predicate comparisons require literal scalar values')


def evaluate_assertion(rule, telemetry):
    validate_assertion(rule)
    stream = rule.event_predicate['stream']
    values = getattr(telemetry, stream)
    if stream == 'state_diffs': values = [{'name': k, **v} for k, v in values.items()]
    elif stream == 'canary_hits': values = [{'value': x} for x in values]
    else: values = [x.model_dump(mode='json') if hasattr(x, 'model_dump') else x for x in values]
    indices = []
    for index, event in enumerate(values):
        matched = True
        for path, expected_value in rule.event_predicate['match'].items():
            value = event
            for field in path.split('.'):
                if not isinstance(value, Mapping) or field not in value:
                    matched = False
                    break
                value = value[field]
            if not matched or type(value) is not type(expected_value) or value != expected_value:
                matched = False
                break
        if matched: indices.append(index)
    count = len(indices)
    return {'id': rule.id, 'stream': stream, 'matching_event_indices': indices, 'count': count,
            'passed': rule.expected.get('min_count', 0) <= count <= rule.expected.get('max_count', 2**63)}
