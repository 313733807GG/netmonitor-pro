"""Bounded review evidence. Counts are polling observations, not visits/bytes."""
import ipaddress
import json
import logging
import os
import threading
import time
import connection_labels as cl

MAX_ENTRIES = 500
MAX_IP_ENTRIES = 500
MAX_ANOMALY_ENTRIES = 200
MAX_CONTEXTS = 16
FLUSH_INTERVAL = 60
LOG = logging.getLogger('netmonitor')

def review_category(host, record):
    # Text anomalies have their own protected pool even on an IP/known service.
    if record.get('anomalies') or host.startswith('process:'):
        return 'anomaly'
    try:
        ipaddress.ip_address(host)
        return 'ip'
    except ValueError:
        return 'domain'

def _default_path():
    base = os.environ.get('NETMONITOR_LOG_DIR') or os.path.join(
        os.environ.get('LOCALAPPDATA') or os.path.expanduser('~'), 'NetMonitorPro', 'logs')
    return os.path.join(base, 'unknown-targets.json')

def _is_private_ip(text):
    try:
        return ipaddress.ip_address(text).is_private
    except ValueError:
        return False

class UnknownTargetLog:
    def __init__(self, path=None, legacy=()):
        self.path = path or _default_path()
        self.legacy = legacy
        self.items = {}
        self.dirty = False
        self.last_flush = 0.0
        self.last_attempt = None
        self.last_error = ''
        self.lock = threading.Lock()
        self._load()

    def _load(self):
        try:
            with open(self.path, encoding='utf-8') as f:
                data = json.load(f)
            if not isinstance(data, list):
                raise ValueError('expected JSON array')
            for rec in data:
                if not isinstance(rec, dict) or not isinstance(rec.get('host'), str):
                    continue
                if not isinstance(rec.get('count'), int):
                    rec['count'] = 0
                if rec.get('schema_version') != 2:
                    rec['legacy_count'] = rec['count']
                    # Preserve the v1 last-observed context before new rows
                    # replace compatibility fields. Missing facts stay empty.
                    rec['contexts'] = [{k:rec.get(k,'') for k in (
                        'proc','pid','process_path','rule','group','exit','kind',
                        'network','destination_port','source','name','first','last')}]
                    rec['contexts'][0]['count'] = rec['count']
                    rec['contexts'][0]['legacy'] = True
                    rec['schema_version'] = 2
                    rec['count_semantics'] = 'legacy_row_observations_plus_poll_observations'
                    self.dirty = True
                self.items[rec['host']] = rec
            self._prune()
        except FileNotFoundError:
            pass
        except Exception as exc:
            self.last_error = str(exc)
            LOG.warning('unknown target log load failed: %s', exc)

    def _prune(self):
        for host, rec in list(self.items.items()):
            if not rec.get('anomalies') and not host.startswith('process:') and not cl.needs_review({'host':host}, self.legacy):
                del self.items[host]
                self.dirty = True
        pools = {'domain':[], 'ip':[], 'anomaly':[]}
        for host, rec in self.items.items():
            category = review_category(host, rec)
            if rec.get('review_category') != category:
                rec['review_category'] = category
                self.dirty = True
            pools[category].append(host)
        for category, limit in (('domain',MAX_ENTRIES),('ip',MAX_IP_ENTRIES),('anomaly',MAX_ANOMALY_ENTRIES)):
            hosts=pools[category]
            if len(hosts)>limit:
                oldest=sorted(hosts,key=lambda h:str(self.items[h].get('last','')))
                for host in oldest[:len(hosts)-limit]:del self.items[host]
                self.dirty=True

    def counts(self):
        with self.lock:
            result={'domain':0,'ip':0,'anomaly':0}
            for host,record in self.items.items():result[review_category(host,record)]+=1
            return result

    def note(self, rows, source):
        iso = time.strftime('%Y-%m-%dT%H:%M:%S%z')
        with self.lock:
            seen = set()
            for row in rows:
                raw = str(row.get('raw_host') or row.get('host') or '')
                anomalies = cl.review_anomalies(row)
                if not anomalies and (not raw or _is_private_ip(raw) or not cl.needs_review(row,self.legacy)):
                    continue
                host = raw or 'process:' + str(row.get('proc') or '?')
                rec = self.items.setdefault(host,{'host':host,'first':iso,'count':0})
                if host not in seen:
                    rec['count'] += 1
                    seen.add(host)
                rec.update(last=iso,count_semantics=(
                    'legacy_row_observations_plus_poll_observations' if 'legacy_count' in rec
                    else 'poll_observations'),schema_version=2)
                if anomalies:
                    samples = rec.setdefault('anomalies',{})
                    for field,value in anomalies.items():
                        samples[field] = value[:1024]
                context = {k:row.get(k,'') for k in (
                    'proc','pid','process_path','proc_parent','rule','group','exit','kind',
                    'source_ip','source_port','destination_ip','destination_port','network',
                    'connection_id','owner_source','owner_confidence')}
                context.update(source=source,name=cl.connection_name(row,self.legacy),last=iso,first=iso,count=1)
                keys = ('proc','pid','process_path','rule','group','exit','kind','network','destination_port','source')
                contexts = rec.setdefault('contexts',[])
                match = next((c for c in contexts if all(c.get(k)==context[k] for k in keys)),None)
                if match is not None:
                    context['first'] = match.get('first',iso)
                    context['count'] = match.get('count',0)+1
                    contexts.remove(match)
                contexts.append(context)
                if len(contexts)>MAX_CONTEXTS:
                    rec['contexts_evicted'] = rec.get('contexts_evicted',0)+len(contexts)-MAX_CONTEXTS
                    del contexts[:-MAX_CONTEXTS]
                for key in ('name','proc','rule','group','source','exit','pid','process_path','kind'):
                    rec[key] = context[key]
                self.dirty = True
            self._prune()
            now = time.monotonic()
            if self.dirty and (self.last_attempt is None or now-self.last_attempt>=FLUSH_INTERVAL):
                self._flush()

    def _flush(self):
        self.last_attempt = time.monotonic()
        tmp = self.path + '.tmp'
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)),exist_ok=True)
            data = sorted(self.items.values(),key=lambda r:str(r.get('last','')),reverse=True)
            with open(tmp,'w',encoding='utf-8') as f:
                # Preserve even invalid Unicode without making the write fail.
                json.dump(data,f,ensure_ascii=True,indent=1)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp,self.path)
        except Exception as exc:
            self.last_error = str(exc)
            LOG.warning('unknown target log save failed; pending data retained: %s',exc)
            return False
        self.dirty = False
        self.last_error = ''
        self.last_flush = time.time()
        return True

    def flush(self):
        with self.lock:
            return self._flush() if self.dirty else True
