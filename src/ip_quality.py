"""AI-route evidence, per-launch quality cache, and dedicated-loopback probes."""
import http.client
import gzip
import io
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import ssl
import time
import logging
UNKNOWN_TYPE_LABELS = {'','未知','未知 ip','未知类型','未知类型 ip','待确认','未识别',
                       'unknown','unknown ip','unknown type','n/a','—','-'}
from cleanip_details import parse_report
import ui_theme as theme

PROBE_GROUP = 'NetMonitor-IP-Check'
PROBE_PORT = 17893
GROUP_TYPES = {'Selector','URLTest','Fallback','LoadBalance'}
AI_DOMAINS = ('chatgpt.com','openai.com','claude.ai','anthropic.com','gemini.google.com')

def domain_is(host, domain):
    return host == domain or host.endswith('.'+domain)

def leaf(snapshot, name):
    proxies=snapshot.get('proxies',{})
    seen=set()
    while name in proxies and proxies[name].get('type') in GROUP_TYPES:
        if name in seen or proxies[name].get('type')=='LoadBalance': return ''
        seen.add(name);name=proxies[name].get('now','')
    return name

def proxy_leaf(snapshot, name):
    typ=str(snapshot.get('proxies',{}).get(name,{}).get('type','')).lower()
    return bool(name and name not in ('DIRECT','PASS','COMPATIBLE',PROBE_GROUP)
                and not name.upper().startswith('REJECT') and typ not in ('direct','reject','rejectdrop','pass'))

def ai_target(connections, snapshot, mode, previous=None):
    """Real chatgpt.com traffic wins; other AI services only when primary absent."""
    if mode=='direct': return {'state':'direct','node':'','group':'','evidence':'直连模式'}
    if mode=='global':
        node=leaf(snapshot,'GLOBAL')
        if not node or node=='GLOBAL' or snapshot.get('proxies',{}).get(node,{}).get('type') in GROUP_TYPES:
            return {'state':'waiting','node':'','group':'GLOBAL','evidence':'等待 GLOBAL 出口确认'}
        return {'state':'confirmed' if proxy_leaf(snapshot,node) else 'direct',
                'node':node if proxy_leaf(snapshot,node) else '', 'group':'GLOBAL', 'evidence':'全局 GLOBAL 出口'}
    if mode!='rule': return {'state':'waiting','node':'','group':'','evidence':'模式未确认'}
    candidates=[]
    for c in connections:
        meta=c.get('metadata') or {}; host=str(meta.get('host') or '').lower().rstrip('.')
        chains=c.get('chains') or []
        if not chains or PROBE_GROUP in chains or meta.get('inboundName')=='netmonitor-ip-check': continue
        rank=next((i for i,d in enumerate(AI_DOMAINS) if domain_is(host,d)),None)
        if rank is None: continue
        node,group=chains[0],chains[-1]
        # Old long-lived connections can survive a selector switch. They do not
        # represent the new selection and must not pin the displayed target.
        if snapshot.get('proxies',{}).get(group,{}).get('type') in GROUP_TYPES:
            current=leaf(snapshot,group)
            if current and current!=node: continue
        candidates.append((rank,str(c.get('start','')),node,group,host))
    if candidates:
        rank=min(x[0] for x in candidates)
        chosen=max((x for x in candidates if x[0]==rank),key=lambda x:x[1])
        _,_,node,group,host=chosen
        return {'state':'confirmed' if proxy_leaf(snapshot,node) else 'direct',
                'node':node if proxy_leaf(snapshot,node) else '', 'group':group,
                'evidence':'已观测 '+host, 'other_ai_exits':len({x[2] for x in candidates}-{node})}
    if previous and previous.get('state')=='confirmed' and previous.get('group')!='GLOBAL':
        if leaf(snapshot,previous.get('group',''))==previous.get('node'):
            return dict(previous,evidence='最近确认的 AI 出口（当前无活跃 AI 连接）')
    return {'state':'waiting','node':'','group':'','evidence':'等待 AI 实际连接确认'}

def profile_id(channel=None, client=None):
    from proxy_clients import profile_identity
    return profile_identity(channel, client)

def quality_key(data):
    if not data.get('api_on') or not (data.get('sp_on') or data.get('tun_on')): return ''
    if data.get('mode')=='direct' or data.get('ai_target_state')!='confirmed': return ''
    node=data.get('ai_node','')
    if not node or node.upper()=='DIRECT':return ''
    key=(str(data.get('profile_id','unknown')),node)
    mode=data.get('quality_mode','auto')
    return key if mode=='auto' else key+(mode,)

class QualityCache:
    """No disk persistence. A failed attempt is cached too; manual retry is explicit."""
    def __init__(self): self.results={};self.pending=None
    def begin(self,key,manual=False):
        if not key or self.pending is not None or (key in self.results and not manual): return False
        self.pending=key;return True
    def finish(self,key,result):
        if self.pending==key:self.pending=None
        # A lifecycle cancellation is not the node's first completed test.
        if result.get('cancelled'):return
        previous=self.results.get(key,{})
        if (result.get('errors') and not any(result.get(k) for k in ('ippure','cleanip'))
                and any(previous.get(k) for k in ('ippure','cleanip'))):
            self.results[key]=dict(previous,refresh_errors=result['errors'],refresh_time=result.get('time',''),
                                   protocol_mismatches=result.get('protocol_mismatches',{}))
        else:self.results[key]=result

def score(value):
    if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or not 0<=value<=100:
        raise ValueError('评分缺失或格式异常')
    return float(value)

def ippure_badge(value):
    v=score(value)
    for ceiling,label,color in ((15,'极度纯净','#186638'),(25,'纯净','#36a95c'),(40,'中性','#9bba25'),
                                (50,'轻微风险','#e2b900'),(70,'较高风险','#f47721'),(100,'高风险','#e34248')):
        if v<=ceiling:return f'{v:g}% {label}',color

def clean_color(value):
    v=score(value)
    return theme.SCORE_GREEN if v>=85 else (theme.SCORE_LIME if v>=70 else (theme.SCORE_YELLOW if v>=50 else theme.SCORE_RED))

def risk_color(value):
    """Same CleanIP palette, reversing the low-is-good risk direction."""
    return clean_color(100-score(value))

def parse_ippure(body):
    obj=json.loads(body)
    ip=str(ipaddress.ip_address(obj['ip']))
    result={'ip':ip,'score':None if ipaddress.ip_address(ip).version==6 else score(obj.get('fraudScore'))}
    result['location']={k:str(obj.get(k) or '')[:100] for k in ('country','countryCode','region','city')}
    for source,dest in (('isResidential','residential'),('isBroadcast','broadcast')):
        if isinstance(obj.get(source),bool):result[dest]=obj[source]
    return result

def parse_cleanip(body):
    text=body.decode('utf-8') if isinstance(body,bytes) else body
    text=re.sub(r'\x1b\[[0-9;]*m','',text)
    def match(pattern):
        m=re.search(pattern,text,re.M)
        if not m:raise ValueError('CleanIP 返回格式变化或需要验证')
        return m
    ip=str(ipaddress.ip_address(match(r'^\s*IP\s+([0-9a-fA-F:.]+)\s')[1]))
    purity=score(float(match(r'CleanIP\s*评分[^\r\n]*?([0-9]+(?:\.[0-9]+)?)/100')[1]))
    risk=score(float(match(r'风险评分\s+([0-9]+(?:\.[0-9]+)?)/100')[1]))
    flags=match(r'风险标记\s+([^\r\n]+)')[1].strip()[:240]
    grade=re.search(r'CleanIP\s*评分[^\r\n]*?/100\s*\(([A-F][+]?)\)',text)
    result={'ip':ip,'score':purity,'risk':risk,'flags':flags,'grade':grade[1] if grade else ''}
    location=re.search(r'^\s*归属地\s+([^\r\n]+)',text,re.M)
    if location:
        parts=[x.strip() for x in location[1].split('·') if x.strip()]
        result['location']={'country':parts[0] if parts else '', 'parts':parts[1:3]}
    for field,pattern in (('ip_type',r'^\s*IP 类型\s+([^\r\n]+)'),('native_type',r'^\s*原生\s*/\s*广播\s+([^\r\n]+)')):
        found=re.search(pattern,text,re.M)
        if found:
            label=found[1].strip()[:60]
            # CLI's no-color variant surrounds the badge text with brackets.
            if label.startswith('[') and label.endswith(']'):label=label[1:-1].strip()
            result[field]=label
    return result

def location_display(result):
    from location_names import location_display as render_location
    return render_location(result)


def type_badges(result):
    """Keep source labels; negative evidence wins without inventing IDC from false."""
    from quality_evidence import type_inputs
    pure,clean=type_inputs(result)
    if pure.get('ip') and clean.get('ip') and pure['ip']!=clean['ip'] and not (result.get('route_verified') is True and result.get('node')):
        return [('出口不一致','unknown','两站看到不同 IP，不合并类型结论','待确认')]
    badges=[]
    for field,flag,positive,negative in (('native_type','broadcast','原生 IP','广播 IP'),('ip_type','residential','住宅 IP','非住宅 IP')):
        original=clean.get(field,'')
        known=original and original.strip().casefold() not in UNKNOWN_TYPE_LABELS
        p=pure.get(flag)
        p_negative=(p is True) if flag=='broadcast' else (p is False)
        p_positive=(p is False) if flag=='broadcast' else (p is True)
        c_positive=original==positive
        # Unannounced and unrecognized native labels are not evidence of broadcast.
        c_negative=original in ('广播 IP','非原生 IP') if flag=='broadcast' else bool(known and not c_positive)
        conflict=(p_negative and c_positive) or (p_positive and c_negative)
        if p_negative or c_negative:
            label=original if c_negative else negative
            color='negative'
            source='CleanIP' if c_negative else 'IPPure'
        elif c_positive or p_positive:
            label=original if c_positive else positive
            color='positive'
            source='CleanIP' if c_positive else 'IPPure'
        elif known:
            label=original;color='unknown';source='CleanIP'
        else:
            label='归属待确认' if flag=='broadcast' else '类型待确认';color='unknown';source='待确认'
        pure_label=negative if p_negative else (positive if p_positive else '未提供')
        detail=f'CleanIP：{original or "未提供"}\nIPPure：{pure_label}'
        if result.get('node_evidence'):
            detail+='\n节点已检测出口的类型证据（负面优先）：'
            for record in result['node_evidence']:
                item=record['data'];value=item.get(field) if record['source']=='cleanip' else item.get(flag)
                detail+='\n'+record['source']+' '+item.get('ip','')+'：'+str(value if value is not None else '未提供')
        if result.get('ip_mismatch'):detail+='\n同节点不同出口汇总：IPPure '+str(pure.get('ip'))+'；CleanIP '+str(clean.get('ip'))
        if conflict:label+=' · 分歧';detail+='\n按约定优先显示非原生/非住宅证据；保留各站原结论。'
        elif not (known and isinstance(p,bool)):detail+='\n尚未获得两站共同印证。'
        badges.append((label,color,detail,source))
    return badges

def connection_for_port(pipe,port,owner=None,attempts=3):
    for _ in range(attempts):
        if owner is not None and owner.isInterruptionRequested():raise OSError('检测已取消')
        for c in pipe.connections().get('connections',[]):
            if str((c.get('metadata') or {}).get('sourcePort'))==str(port):return c
        time.sleep(.15)
    return None

class FixedTargetHTTPS(http.client.HTTPSConnection):
    """CONNECT a literal destination while validating TLS against the service name."""
    def __init__(self,port,host,target):
        super().__init__('127.0.0.1',port,timeout=10,context=ssl.create_default_context(),source_address=('127.0.0.2',0))
        self.service_host=host
        self.set_tunnel(target,443,headers={'Host':('['+target+']' if ':' in target else target)+':443'})
    def connect(self):
        http.client.HTTPConnection.connect(self)
        self.sock=self._context.wrap_socket(self.sock,server_hostname=self.service_host)

def resolve_target(pipe,host,family):
    qtype='A' if family==4 else 'AAAA'
    data=pipe.get('/dns/query?name='+host+'&type='+qtype) or {}
    for answer in data.get('Answer',[])[:32]:
        if answer.get('type')!=(1 if family==4 else 28):continue
        try:address=ipaddress.ip_address(answer.get('data',''))
        except ValueError:continue
        if address.version==family and address.is_global and not address.is_multicast:
            return str(address)
    raise ValueError('检测站没有可核实的公网 IPv'+str(family)+' 地址，未换协议')

def retry_ipv4_allowed(exc):
    if isinstance(exc,(json.JSONDecodeError,ssl.SSLCertVerificationError)):return False
    message=str(exc).lower()
    if any(x in message for x in ('403','429','401','验证','未允许','出口未能核实','取消')):return False
    return isinstance(exc,(OSError,ValueError,KeyError,TypeError))

def proxy_get(pipe,host,path,port,node=None,owner=None,hold=False,max_bytes=262144,family=None):
    """Never follow redirects or fall back to direct access. Check real chain."""
    allowed={'my.ippure.com','cleanip.io','chatgpt.com','ipv4.icanhazip.com','ipv6.icanhazip.com'}
    if host not in allowed:raise ValueError('未允许的检测地址')
    if family in (4,6):conn=FixedTargetHTTPS(port,host,resolve_target(pipe,host,family))
    elif node is None and host=='chatgpt.com':
        conn=http.client.HTTPConnection('127.0.0.1',port,timeout=8)
        conn.set_tunnel(host,443)
    else:
        conn=http.client.HTTPSConnection('127.0.0.1',port,timeout=10,context=ssl.create_default_context())
        conn.set_tunnel(host,443)
    if owner is not None:owner.connection=conn
    try:
        conn.connect()
        if owner is not None:
            owner.track_socket(conn.sock)
            if hasattr(owner,'register_port'):owner.register_port(conn.sock.getsockname()[1],host)
        if owner is not None and owner.isInterruptionRequested():raise OSError('检测已取消')
        confirming=node is None and host=='chatgpt.com'
        if confirming:
            # Send only a standard TLS ClientHello so lazy/sniffing proxy
            # paths can establish their route. Do not wait for remote TLS,
            # certificates, or an HTTP response to confirm the connection.
            incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO()
            handshake=ssl.create_default_context().wrap_bio(incoming,outgoing,server_hostname=host)
            try:handshake.do_handshake()
            except ssl.SSLWantReadError:pass
            conn.sock.sendall(outgoing.read())
        route=connection_for_port(pipe,conn.sock.getsockname()[1],owner,attempts=10 if confirming else 3)
        if owner is not None and owner.isInterruptionRequested():raise OSError('检测已取消')
        if node:
            chains=(route or {}).get('chains',[])
            if not chains or chains[0]!=node or PROBE_GROUP not in chains:
                raise ValueError('检测出口未能核实，未采集评分')
        if node is None and host=='chatgpt.com':return b'',route
        conn.request('GET',path,headers={'Host':host,'Accept':'application/json, text/plain, text/html','Accept-Encoding':('gzip' if max_bytes>262144 else 'identity'),'User-Agent':'NetMonitor/22 IP-quality','Connection':'close'})
        response=conn.getresponse()
        if node is None and host=='chatgpt.com':
            return b'',route  # even a 403 confirms the connection's real route
        if response.status!=200:raise ValueError(f'检测接口 HTTP {response.status}（不代表节点失效）')
        deadline=time.monotonic()+15
        chunks=[];size=0
        while True:
            if owner is not None and owner.isInterruptionRequested():raise OSError('检测已取消')
            if time.monotonic()>deadline:raise TimeoutError('检测响应超时')
            chunk=response.read1(16384)
            if not chunk:break
            chunks.append(chunk);size+=len(chunk)
            if size>max_bytes:raise ValueError('检测响应过大')
        return decode_response(b''.join(chunks),response.getheader('Content-Encoding',''),max_bytes),route
    finally:
        conn.close()
        if owner is not None:owner.connection=None

def collect_quality(pipe,node,owner=None,family=None):
    result={'node':node,'route_verified':True,'mode':str(family) if family else 'auto','observed_ips':[],'observations':[],
            'time':time.strftime('%Y-%m-%d %H:%M:%S'),'errors':{}}
    if owner is not None and owner.isInterruptionRequested():return dict(result,cancelled=True)
    snapshot=pipe.proxies()
    group=snapshot.get('proxies',{}).get(PROBE_GROUP,{})
    if group.get('type')!='Selector' or node not in group.get('all',[]) or not proxy_leaf(snapshot,node):
        raise ValueError('检测入口或目标节点不可用')
    if not pipe.select_probe_node(node):raise ValueError('无法设置检测专用出口')
    try:
        for label,host,path,parser in (('ippure','my.ippure.com','/v1/info',parse_ippure),('cleanip','cleanip.io','/cli',parse_cleanip)):
            if owner is not None and owner.isInterruptionRequested():return dict(result,cancelled=True)
            try:
                if pipe.configs().get('mode') not in ('rule','global'):
                    return dict(result,cancelled=True)
                body,_=proxy_get(pipe,host,path,PROBE_PORT,node,owner,**({'family':family} if family else {}))
                parsed=parser(body)
                # A verified node's other-family answer is real risk evidence,
                # but never a successful result for the requested family.
                result['observed_ips'].append(parsed['ip'])
                result['observations'].append({'source':label,'data':parsed})
                require_family(result,label,parsed,family)
                result[label]=parsed
                if label=='ippure' and parsed.get('score') is None and family is None:
                    raise ValueError('IPv6不提供IPPure系数')
            except Exception as exc:
                result['errors'][label]=str(exc)[:180]
                if label=='ippure' and family is None and retry_ipv4_allowed(exc):
                    if owner is not None and owner.isInterruptionRequested():return dict(result,cancelled=True)
                    if pipe.configs().get('mode') not in ('rule','global'):return dict(result,cancelled=True)
                    result['ippure_retry']='IPv4补测一次'
                    try:
                        body,_=proxy_get(pipe,host,path,PROBE_PORT,node,owner,family=4)
                        parsed=parser(body)
                        result['observed_ips'].append(parsed['ip'])
                        result['observations'].append({'source':label,'data':parsed})
                        require_family(result,label,parsed,4)
                        result['ippure']=parsed
                        result['errors'].pop(label,None)
                    except Exception as retry_exc:result['errors'][label]+='；IPv4补测：'+str(retry_exc)[:120]
        if owner is not None and owner.isInterruptionRequested():return dict(result,cancelled=True)
        clean_observation=next((x['data'] for x in reversed(result['observations']) if x['source']=='cleanip'),None)
        if clean_observation:
            try:
                if pipe.configs().get('mode') not in ('rule','global'):return dict(result,cancelled=True)
                ip=clean_observation['ip']
                body,_=proxy_get(pipe,'cleanip.io','/'+ip,PROBE_PORT,node,owner,max_bytes=2*1024*1024)
                clean_observation['risk_details']=parse_report(body,ip)
            except Exception as exc:result['errors']['cleanip_details']=str(exc)[:180]
        if owner is not None and owner.isInterruptionRequested():return dict(result,cancelled=True)
        if result.get('ippure') and result.get('cleanip'):
            result['ip_mismatch']=result['ippure']['ip']!=result['cleanip']['ip']
        return result
    finally:
        # Only our dedicated selector; never restore/change ordinary groups.
        if not pipe.select_probe_node('REJECT'):
            logging.getLogger('netmonitor').warning('IP quality cleanup failed: dedicated selector could not return to REJECT')


def require_family(result,source,item,family):
    actual=ipaddress.ip_address(item['ip']).version
    if family and actual!=family:
        result.setdefault('protocol_mismatches',{})[source]={'requested':family,'actual':actual,'ip':item['ip']}
        raise ValueError(f'指定IPv{family}，网站识别IPv{actual}；未取得IPv{family}专项结果（实际IP {item["ip"]}）')


def quality_feedback(result):
    mode=result.get('mode','auto')
    title=('自动' if mode=='auto' else 'IPv'+mode)+'检测'
    if result.get('cancelled'):return title+'已取消，未更新结果'
    errors=result.get('errors') or {}
    valid=sum(bool(result.get(site)) and site not in errors for site in ('ippure','cleanip'))
    status='完成' if not errors else ('部分完成' if valid else '未完成')
    lines=[title+status]
    if errors.get('request'):return '\n'.join(lines+[errors['request']])
    for site,name in (('ippure','IPPure'),('cleanip','CleanIP')):
        mismatch=(result.get('protocol_mismatches') or {}).get(site)
        if mismatch:
            text=f'未取得IPv{mismatch["requested"]}（返回IPv{mismatch["actual"]}）'
        elif site in errors:text='失败，悬停查看原因'
        elif result.get(site):
            text='IPv6不提供分数' if site=='ippure' and result[site].get('score') is None else '完成'
        else:text='未取得结果'
        lines.append(name+'：'+text)
    if errors.get('cleanip_details'):lines.append('风险明细未完成，不能据此认定未检出')
    elif not errors:
        if result.get('reused') and not result.get('queried'):lines.append('已复用成功结果；没有重复请求评分网站')
        elif result.get('reused'):lines.append('已补查缺项，其余复用成功结果')
        else:lines.append('数值相同也已重新查询；检测时间已更新')
    if (result.get('discovery') or {}).get('errors'):lines.append('部分协议地址暂未取得，不判定为单IP节点')
    return '\n'.join(lines)


def decode_response(body,encoding,max_bytes):
    if encoding.lower()=='gzip':
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:body=stream.read(max_bytes+1)
    elif encoding and encoding.lower()!='identity':raise ValueError('检测接口返回不支持的压缩类型')
    if len(body)>max_bytes:raise ValueError('检测响应过大')
    return body
