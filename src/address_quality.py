"""Discover verified node exits, then query each explicitly by address."""
import time,copy
import cleanip_credentials
from cleanip_mcp import Client as CleanIPClient
import ip_quality as q
from lookup_parsers import public_ip

def collect_quality(pipe,node,owner=None,family=None,cache=None,force=False):
    cache=cache or {};prior=copy.deepcopy(cache.get('discovery') or {'ips':{},'errors':{}})
    saved={(x['source'],x['data']['ip']):copy.deepcopy(x['data']) for x in cache.get('records',[])
           if x.get('source') in ('ippure','cleanip') and x.get('data',{}).get('ip')}
    result={'node':node,'route_verified':True,'mode':str(family) if family else 'auto',
            'observed_ips':[],'observations':[],'time':time.strftime('%Y-%m-%d %H:%M:%S'),
            'errors':{},'discovery':{'ips':{},'errors':{}},'reused':[],'queried':[]}
    fresh={};pure_api_error=''
    records={'ippure':[],'cleanip':[]};failures={'ippure':[],'cleanip':[]}
    def check():
        if owner is not None and owner.isInterruptionRequested():raise OSError('检测已取消')
        if pipe.configs().get('mode') not in ('rule','global'):raise OSError('检测已取消：代理模式已改变')
    def cached(site,ip):
        item=fresh.get((site,ip))
        if item and not item.get('details_error'):return item
        item=saved.get((site,ip))
        return item if not force and item and not item.get('details_error') else None
    def add(site,ip,data,reused=False):
        if public_ip(data['ip'])!=ip:raise ValueError('查询结果IP不符，未入库')
        records[site].append(data);result['observations'].append({'source':site,'data':data})
        if reused and (site,ip) not in fresh:result['reused'].append([site,ip])
        elif (site,ip) in fresh and [site,ip] not in result['queried']:result['queried'].append([site,ip])
    def finish():
        for site,values in records.items():
            if values:
                key=(lambda x:x['score'] if x.get('score') is not None else -1) if site=='ippure' else (lambda x:(100-x['score'],x.get('risk') if x.get('risk') is not None else -1))
                result[site]=max(values,key=key)
            if failures[site]:result['errors'][site]='；'.join(failures[site])[:500]
        pure=result.get('ippure') or {};clean=result.get('cleanip') or {}
        result['ip_mismatch']=bool(pure.get('ip') and clean.get('ip') and pure['ip']!=clean['ip'])
        return result
    wanted=(str(family),) if family else ('4','6');known=prior.get('ips') or {}
    if not force and all(v in known for v in wanted) and all(cached(s,known[v]) for v in wanted for s in records):
        result['discovery']=prior;result['observed_ips']=list(known.values())
        for v in wanted:
            for site in records:add(site,known[v],cached(site,known[v]),True)
        return finish()
    snapshot=pipe.proxies();group=snapshot.get('proxies',{}).get(q.PROBE_GROUP,{})
    if group.get('type')!='Selector' or node not in group.get('all',[]) or not q.proxy_leaf(snapshot,node):raise ValueError('检测入口或目标节点不可用')
    check()
    if not pipe.select_probe_node(node):raise ValueError('无法设置检测专用出口')
    try:
        for version in (4,6):
            check();v=str(version)
            if not force and v in known:result['discovery']['ips'][v]=public_ip(known[v],version);continue
            if not force and known and family and family!=version:
                if v in prior.get('errors',{}):result['discovery']['errors'][v]=prior['errors'][v]
                continue
            try:
                raw,_=q.proxy_get(pipe,f'ipv{version}.icanhazip.com','/',q.PROBE_PORT,node,owner,max_bytes=128)
                result['discovery']['ips'][v]=public_ip(raw.decode('ascii'),version)
            except Exception as exc:result['discovery']['errors'][v]=str(exc)[:180]
        # If both echo services are unavailable, IPPure may still establish
        # the actual exit. CleanIP requires an authorized per-IP API query;
        # never revive its redesigned legacy web interface for discovery.
        if not result['discovery']['ips']:
            for site,host,path,parser in (('ippure','my.ippure.com','/v1/info',q.parse_ippure),):
                check()
                try:
                    raw,_=q.proxy_get(pipe,host,path,q.PROBE_PORT,node,owner)
                    item=parser(raw);ip=public_ip(item['ip']);v=str(q.ipaddress.ip_address(ip).version)
                    item['query_method']='公开出口接口（IP已核实）'
                    fresh[(site,ip)]=item;result['observations'].append({'source':site,'data':item})
                    result['discovery']['ips'][v]=ip;result['discovery']['errors'].pop(v,None)
                except Exception:pass
        result['observed_ips']=list(result['discovery']['ips'].values());check()
        selected=[ip for v,ip in result['discovery']['ips'].items() if not family or str(family)==v]
        if not selected:
            result['errors']['request']='未取得'+('IPv'+str(family) if family else '节点')+'出口地址，未判定该节点不支持此协议'
            return result
        # The public interface reports its actual exit only. Never assign
        # that score to another address; no browser fallback is started.
        if any(not cached('ippure',ip) for ip in selected):
            try:
                raw,_=q.proxy_get(pipe,'my.ippure.com','/v1/info',q.PROBE_PORT,node,owner)
                item=q.parse_ippure(raw);ip=public_ip(item['ip'])
                item['query_method']='公开出口接口（实际出口已核实）';fresh[('ippure',ip)]=item
                result['observations'].append({'source':'ippure','data':item})
                if ip not in result['observed_ips']:result['observed_ips'].append(ip)
                version=q.ipaddress.ip_address(ip).version
                result['discovery']['ips'].setdefault(str(version),ip)
                result['discovery']['errors'].pop(str(version),None)
                if (not family or version==family) and ip not in selected:selected.append(ip)
            except Exception as exc:pure_api_error=str(exc)[:160]
        api_key='';credential_error=''
        if any(not cached('cleanip',ip) for ip in selected):
            try:api_key=cleanip_credentials.load_key()
            except ValueError as exc:credential_error=str(exc)
        api=CleanIPClient(pipe,node,api_key,owner) if api_key else None
        api_block=''
        for ip in selected:
            check();item=cached('cleanip',ip)
            if item:add('cleanip',ip,item,True);continue
            try:
                if credential_error:raise ValueError(credential_error)
                if not api:raise ValueError('未配置 CleanIP API 密钥；网页已改版，请运行 tools/configure_cleanip.py 自行配置')
                if api_block:raise ValueError(api_block)
                result['queried'].append(['cleanip',ip])
                data=api.query(ip)
                add('cleanip',ip,data)
                if data.get('details_error'):result['errors']['cleanip_details']=data['details_error']
            except Exception as exc:
                if api and any(x in str(exc) for x in ('401','403','429','额度','权限')):api_block=str(exc)[:140]
                failures['cleanip'].append(ip+'：'+str(exc)[:140])
                if ('cleanip',ip) in fresh:add('cleanip',ip,fresh[('cleanip',ip)])
        check();pending=[]
        for ip in selected:
            item=cached('ippure',ip)
            if item:add('ippure',ip,item,True)
            else:pending.append(ip)
        for ip in pending:
            failures['ippure'].append(ip+'：'+(pure_api_error or '轻量接口未取得此IP资料（已停用后台浏览器补查）'))
        check();return finish()
    except OSError as exc:
        if '取消' in str(exc):return dict(finish(),cancelled=True,partial=bool(result['observations']))
        raise
    finally:
        if not pipe.select_probe_node('REJECT'):q.logging.getLogger('netmonitor').warning('IP quality cleanup failed: dedicated selector could not return to REJECT')
