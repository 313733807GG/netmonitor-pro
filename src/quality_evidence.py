"""Session-only, bounded evidence for verified exits of each subscription/node."""
import copy,ipaddress
from collections import OrderedDict

def family_label(item):
    try:return 'IPv'+str(ipaddress.ip_address(item['ip']).version)
    except (ValueError,KeyError,TypeError):return ''

class QualityEvidence:
    def __init__(self):self.nodes=OrderedDict()
    def record(self,key,result):
        if not key or (result.get('cancelled') and not result.get('partial')) or result.get('route_verified') is not True:return
        base=key[:2];node=self.nodes.setdefault(base,{'records':OrderedDict(),'ips':set()})
        self.nodes.move_to_end(base)
        node.pop('views',None)
        if result.get('discovery'):node['discovery']=copy.deepcopy(result['discovery'])
        if len(self.nodes)>128:self.nodes.popitem(last=False)
        for ip in result.get('observed_ips',[]):
            try:node['ips'].add(str(ipaddress.ip_address(ip)))
            except ValueError:pass
        observations=list(result.get('observations',[]))
        observations.extend({'source':s,'data':result[s]} for s in ('ippure','cleanip') if result.get(s))
        for o in observations:
            s=o['source'];item=o['data'];ip=item.get('ip')
            if s not in ('ippure','cleanip') or not family_label(item):continue
            node['records'][(s,ip)]=dict(copy.deepcopy(item),_observed_at=item.get('_observed_at') or result.get('time',''));node['records'].move_to_end((s,ip));node['ips'].add(ip)
        while len(node['records'])>32:node['records'].popitem(last=False)
        # Track protocol evidence, not an unbounded address history.
        node['families']=node.get('families',set()) | {ipaddress.ip_address(ip).version for ip in node['ips']}
        node['ips']=set(ip for _,ip in node['records'])
    def query_snapshot(self,key):
        node=self.nodes.get(key[:2]) if key else None
        if not node:return {}
        return {'discovery':copy.deepcopy(node.get('discovery') or {}),
                'records':[{'source':source,'data':copy.deepcopy(item)} for (source,_),item in node['records'].items()]}
    def view(self,key,current):
        node=self.nodes.get(key[:2]) if key else None
        if not node:return current
        cached=node.setdefault('views',{}).get(key)
        if cached and cached[0] is current:return cached[1]
        out=copy.deepcopy(current or {'errors':{}})
        records=[{'source':s,'data':v} for (s,_),v in node['records'].items()]
        out.update(node=key[1],route_verified=True,node_evidence=records,dual_stack=node.get('families')=={4,6})
        if len(key)==2:
            for s in ('ippure','cleanip'):
                items=[r['data'] for r in records if r['source']==s]
                if items:
                    if s=='ippure':chosen=max(items,key=lambda v:v.get('score') if v.get('score') is not None else -1)
                    else:chosen=max(items,key=lambda v:(100-v['score'],v.get('risk') if v.get('risk') is not None else -1))
                    out[s]=copy.deepcopy(chosen)
            out['summary_mode']=True
        pure=out.get('ippure') or {};clean=out.get('cleanip') or {}
        out['ip_mismatch']=bool(pure.get('ip') and clean.get('ip') and pure['ip']!=clean['ip'])
        marked=OrderedDict()
        for r in records:
            if r['source']!='cleanip':continue
            data=r['data'];report=data.get('risk_details') or {}
            for x in report.get('items',[]):
                if x.get('status') not in ('hit','conflict'):continue
                item=dict(x,detail='出口 '+data['ip']+'：'+x.get('detail',''))
                if x['label'] not in marked or x['status']=='hit':marked[x['label']]=item
        out['node_risk_items']=list(marked.values())
        node['views'][key]=(current,out)
        return out

def risk_clean(result):
    clean=copy.deepcopy((result or {}).get('cleanip') or {})
    from cleanip_details import EMPTY
    summaries=[]
    for record in (result or {}).get('node_evidence',[]):
        data=record['data'];flags=str(data.get('flags') or '')
        if record['source']=='cleanip' and not data.get('risk_details') and flags not in EMPTY:
            summaries.append({'ip':data['ip'],'flags':flags})
    clean['_node_summaries']=summaries
    items=(result or {}).get('node_risk_items')
    if items:
        clean['risk_details']={'hits':[i['label'] for i in items if i['status']=='hit'],
          'items':items,'scope':('api_summary' if clean.get('coverage_note') else 'web'),'url':'同节点本次运行已检测出口汇总；各IP见下方依据','data_as_of':'各次检测时间可能不同'}
    return clean

def type_inputs(result):
    from ip_quality import UNKNOWN_TYPE_LABELS
    unknown_labels=UNKNOWN_TYPE_LABELS
    pure=dict(result.get('ippure') or {});clean=dict(result.get('cleanip') or {})
    records=result.get('node_evidence') or []
    ps=[r['data'] for r in records if r['source']=='ippure'];cs=[r['data'] for r in records if r['source']=='cleanip']
    for flag,bad in (('broadcast',True),('residential',False)):
        values=[x[flag] for x in ps if isinstance(x.get(flag),bool)]
        if values:pure[flag]=bad if bad in values else not bad
    for field,positive,negatives in (('native_type','原生 IP',('广播 IP','非原生 IP')),('ip_type','住宅 IP',None)):
        values=[x[field] for x in cs if x.get(field)]
        bad=[v for v in values if v in negatives] if negatives else [v for v in values if v!='住宅 IP' and v.strip().casefold() not in unknown_labels]
        if bad:clean[field]=bad[0]
        elif positive in values:clean[field]=positive
    return pure,clean
