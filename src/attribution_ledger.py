"""Local-only review rounds for target attribution; never changes traffic history."""
import copy


SCHEMA_VERSION = 1
REVIEW_RESULTS = {'confirmed', 'candidate', 'weak', 'rejected'}
MAX_OBSERVATIONS = 100


def host_matches(host, target):
    host = str(host or '').lower().rstrip('.')
    kind = target.get('kind')
    value = str(target.get('value') or '').lower().rstrip('.')
    if not host or not value:
        return False
    if kind == 'domain_suffix':
        return host == value or host.endswith('.' + value)
    if kind in ('domain_exact', 'ip_exact'):
        return host == value
    return False


def observe_round(ledger, unknown_records, observed_at, note=''):
    if ledger.get('schema_version') != SCHEMA_VERSION:
        raise ValueError('unsupported attribution ledger schema')
    targets = ledger.get('targets')
    if not isinstance(targets, dict) or not isinstance(unknown_records, list):
        raise ValueError('invalid attribution ledger or unknown-target snapshot')
    result = copy.deepcopy(ledger)
    targets = result['targets']
    round_number = len(result.setdefault('rounds', [])) + 1
    active_by_status = {status: 0 for status in REVIEW_RESULTS}
    for key, target in targets.items():
        matches = [r for r in unknown_records if isinstance(r, dict)
                   and host_matches(r.get('host'), target)]
        status = target.get('status')
        if matches and status in active_by_status:
            active_by_status[status] += 1
        counts = [r.get('count', 0) for r in matches]
        observation = {
            'round': round_number,
            'observed_at': observed_at,
            'active': bool(matches),
            'matched_hosts': sorted({str(r.get('host')) for r in matches}),
            'first': min((str(r.get('first') or '') for r in matches), default=''),
            'last': max((str(r.get('last') or '') for r in matches), default=''),
            'poll_observations': sum(c for c in counts if isinstance(c, int) and c >= 0),
        }
        target.setdefault('observations', []).append(observation)
        if len(target['observations']) > MAX_OBSERVATIONS:
            excess = len(target['observations']) - MAX_OBSERVATIONS
            del target['observations'][:excess]
            target['observations_evicted'] = target.get('observations_evicted', 0) + excess
    result['rounds'].append({
        'round': round_number,
        'observed_at': observed_at,
        'kind': 'observation',
        'note': str(note or ''),
        'unknown_snapshot': {
            'total': len(unknown_records),
            'domain': sum(r.get('review_category') == 'domain' for r in unknown_records if isinstance(r, dict)),
            'ip': sum(r.get('review_category') == 'ip' for r in unknown_records if isinstance(r, dict)),
            'anomaly': sum(r.get('review_category') == 'anomaly' for r in unknown_records if isinstance(r, dict)),
        },
        'active_targets': active_by_status,
    })
    return result


def review_target(ledger, key, result, score, note, observed_at, label=None, evidence=()):
    if result not in REVIEW_RESULTS:
        raise ValueError('invalid review result')
    if not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError('score must be an integer from 0 to 100')
    if not str(note or '').strip():
        raise ValueError('review note is required')
    targets = ledger.get('targets')
    if not isinstance(targets, dict) or key not in targets:
        raise KeyError(key)
    updated = copy.deepcopy(ledger)
    target = updated['targets'][key]
    target['status'] = result
    target['score'] = score
    if label is not None:
        target['label'] = str(label)
    review = {
        'observed_at': observed_at,
        'result': result,
        'score': score,
        'note': str(note).strip(),
        'evidence': [str(url) for url in evidence if str(url).strip()],
    }
    target.setdefault('reviews', []).append(review)
    updated.setdefault('rounds', []).append({
        'round': len(updated.get('rounds', [])) + 1,
        'observed_at': observed_at,
        'kind': 'review',
        'target': key,
        'result': result,
        'score': score,
        'note': review['note'],
        'evidence': review['evidence'],
    })
    return updated
