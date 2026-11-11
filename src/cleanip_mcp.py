"""Authorized CleanIP summaries, with verified proxy routing and no browser."""
import http.client
import json
import ssl
import time
from lookup_parsers import public_ip

MAX_BYTES = 2 * 1024 * 1024
FLAGS = {'vpn':'VPN', 'proxy':'代理', 'residential_proxy':'住宅代理', 'tor':'Tor',
         'relay':'中继', 'hosting':'机房 IP', 'abuser':'滥用', 'bogon':'保留地址'}
TYPES = {'Residential IP':'住宅 IP', 'Datacenter IP':'机房 IP', 'Data Center IP':'机房 IP',
         'Hosting IP':'机房 IP', 'Mobile IP':'移动 IP', 'Business IP':'商业 IP'}

def parse_result(result, expected):
    import ip_quality as q
    if not isinstance(result, dict) or result.get('isError'):
        raise ValueError('CleanIP API 查询被拒绝，请核对密钥权限或每日额度')
    obj = result.get('structuredContent')
    if obj is None:
        texts = [x.get('text','') for x in result.get('content',[]) if x.get('type')=='text']
        if len(texts) != 1:
            raise ValueError('CleanIP API 返回结构变化')
        try:obj = json.loads(texts[0])
        except (ValueError, TypeError):raise ValueError('CleanIP API 返回结构变化') from None
    if not isinstance(obj, dict) or obj.get('error') or obj.get('ok') is False:
        raise ValueError('CleanIP API 查询被拒绝，请核对密钥权限或每日额度')
    if public_ip(obj.get('ip')) != public_ip(expected):
        raise ValueError('CleanIP API 查询IP不符，未采用结果')
    value = q.score(obj.get('cleanip_score'))
    grade = obj.get('grade', '')
    if grade not in ('A+','A','B','C','D','F'):
        raise ValueError('CleanIP API 评级结构变化')
    risk = obj.get('risk') or {}
    if not isinstance(risk, dict):raise ValueError('CleanIP API 风险结构变化')
    items = []
    for field, label in FLAGS.items():
        flag = risk.get(field)
        if type(flag) is bool:
            items.append({'label':label, 'status':'hit' if flag else 'clear',
                          'detail':label+'：API 返回 '+str(flag).lower()})
    reports = risk.get('abuse_reports')
    if type(reports) is int and reports >= 0:
        items.append({'label':'举报记录','status':'hit' if reports else 'clear',
                      'detail':'举报记录：'+str(reports)+'（API 未提供统计时间范围）'})
    hits = [x['label'] for x in items if x['status']=='hit']
    location = obj.get('location') or {}
    if not isinstance(location, dict):raise ValueError('CleanIP API 地区结构变化')
    label = str(obj.get('ip_type') or '未知类型')[:80]
    native = {'native':'原生 IP','broadcast':'广播 IP'}.get(obj.get('native_or_broadcast'),'归属待确认')
    url = 'https://cleanip.io/'+public_ip(expected)
    result = {'ip':public_ip(expected),'score':value,'grade':grade,'risk':None,
              'flags':'、'.join(hits) or ('未检出（API 摘要）' if items else '标记未提供'),
              'ip_type':TYPES.get(label,label),'native_type':native,
              'location':{k:str(location.get(k) or '')[:100] for k in ('country','region','city')},
              'query_method':'CleanIP 官方 MCP（授权 API 摘要）','query_url':url,
              'risk_details':{'ip':public_ip(expected),'scope':'api_summary','hits':hits,'items':items,
                              'url':url,'data_as_of':str(obj.get('data_as_of') or '未提供')[:80]},
              'coverage_note':'API 未提供独立风险分和网页全部24项核验状态；未返回的细项不代表通过。'}
    # Keep returned evidence available to tooltips without interpreting absent findings.
    result['api_evidence'] = {k:obj[k] for k in ('risk','network','scenario_scores','scenario_limited_by',
                             'findings','risk_factors','positive_factors','verdict') if k in obj}
    return result

def decode_rpc(body, content_type, ident):
    try:
        text = body.decode('utf-8')
        if 'text/event-stream' in content_type:
            messages=[]
            for block in text.replace('\r\n','\n').split('\n\n'):
                data='\n'.join(line[5:].lstrip() for line in block.splitlines() if line.startswith('data:'))
                if data:messages.append(json.loads(data))
            matching=[x for x in messages if isinstance(x,dict) and x.get('id')==ident]
            if len(matching)!=1:raise ValueError()
            obj=matching[0]
        else:obj=json.loads(text)
    except (ValueError, UnicodeError):raise ValueError('CleanIP API 响应结构异常') from None
    if not isinstance(obj,dict) or obj.get('jsonrpc')!='2.0' or obj.get('id')!=ident:
        raise ValueError('CleanIP API 响应ID不符')
    if obj.get('error'):
        raise ValueError('CleanIP API 查询被拒绝，请核对密钥权限或每日额度')
    if not isinstance(obj.get('result'),dict):raise ValueError('CleanIP API 响应缺少结果')
    return obj['result']

class Client:
    def __init__(self, pipe, node, key, owner=None):
        self.pipe,self.node,self.key,self.owner=pipe,node,key,owner
        self.session=None;self.protocol='2025-03-26';self.ready=False;self.ident=0

    def _request(self, method, params=None, notification=False):
        import ip_quality as q
        owner=self.owner
        def check():
            if owner is not None and owner.isInterruptionRequested():raise OSError('检测已取消')
            if self.pipe.configs().get('mode') not in ('rule','global'):raise OSError('检测已取消：代理模式改变')
        check()
        conn=http.client.HTTPSConnection('127.0.0.1',q.PROBE_PORT,timeout=10,context=ssl.create_default_context())
        conn.set_tunnel('cleanip.io',443)
        if owner is not None:owner.connection=conn
        try:
            conn.connect()
            if owner is not None:
                owner.track_socket(conn.sock)
                if hasattr(owner,'register_port'):owner.register_port(conn.sock.getsockname()[1],'cleanip.io')
            route=q.connection_for_port(self.pipe,conn.sock.getsockname()[1],owner)
            chains=(route or {}).get('chains',[])
            if not chains or chains[0]!=self.node or q.PROBE_GROUP not in chains:
                raise ValueError('检测出口未能核实，未发送 CleanIP 密钥')
            check()
            headers={'Host':'cleanip.io','Authorization':'Bearer '+self.key,
                     'Content-Type':'application/json','Accept':'application/json, text/event-stream',
                     'Accept-Encoding':'identity','MCP-Protocol-Version':self.protocol,
                     'User-Agent':'NetMonitor/22 IP-quality','Connection':'close'}
            if self.session:headers['Mcp-Session-Id']=self.session
            self.ident+=1;ident=self.ident
            payload={'jsonrpc':'2.0','method':method}
            if not notification:payload['id']=ident
            if params is not None:payload['params']=params
            conn.request('POST','/mcp',body=json.dumps(payload).encode('utf-8'),headers=headers)
            response=conn.getresponse()
            if response.status not in ((200,202,204) if notification else (200,)):
                if response.status==429:raise ValueError('CleanIP API HTTP 429：额度或请求频率受限，未自动重复请求')
                raise ValueError('CleanIP API HTTP '+str(response.status)+'：授权查询失败（不代表节点失效）')
            session=response.getheader('Mcp-Session-Id')
            if session:
                if len(session)>512 or any(ord(c)<33 or ord(c)>126 for c in session):raise ValueError('CleanIP API 会话结构异常')
                self.session=session
            chunks=[];size=0;deadline=time.monotonic()+20
            while True:
                check()
                if time.monotonic()>deadline:raise TimeoutError('CleanIP API 响应超时')
                chunk=response.read1(16384)
                if not chunk:break
                chunks.append(chunk);size+=len(chunk)
                if size>MAX_BYTES:raise ValueError('CleanIP API 响应过大')
            if notification:return {}
            return decode_rpc(b''.join(chunks),response.getheader('Content-Type',''),ident)
        finally:
            conn.close()
            if owner is not None:owner.connection=None

    def query(self, ip):
        ip=public_ip(ip)
        if not self.ready:
            init=self._request('initialize',{'protocolVersion':self.protocol,'capabilities':{},
                 'clientInfo':{'name':'NetMonitor','version':'22.0.13'}})
            protocol=init.get('protocolVersion')
            if protocol not in ('2024-11-05','2025-03-26','2025-06-18'):
                raise ValueError('CleanIP API 协议版本暂不支持')
            self.protocol=protocol
            self._request('notifications/initialized',notification=True);self.ready=True
        return parse_result(self._request('tools/call',{'name':'check_ip','arguments':{'ip':ip}}),ip)


def evidence_text(clean):
    data=clean.get('api_evidence') or {}
    lines=[]
    network=data.get('network')
    if isinstance(network,dict):
        for key,label in (('asn','ASN'),('isp','运营商'),('organization','组织'),('company','公司'),('prefix','网段'),('hostname','主机名')):
            if network.get(key) is not None:lines.append(label+'：'+str(network[key])[:200])
    scenarios=data.get('scenario_scores')
    labels={'advertising':'广告','ai_subscription':'AI 订阅','disney_plus':'Disney+','ecommerce':'电商',
            'facebook':'Facebook','gaming':'游戏','netflix':'Netflix','office':'办公','payment':'支付',
            'search':'搜索','tiktok':'TikTok','twitter':'X / Twitter','youtube':'YouTube'}
    if isinstance(scenarios,dict):
        entries=[]
        for key,value in scenarios.items():
            if type(value) in (int,float) and 0<=value<=100:entries.append(labels.get(key,key)+' '+str(value))
        if entries:lines.append('场景评分（API 评估，不代表实测解锁）：'+'；'.join(entries))
    for key,label in (('verdict','评估结论'),('findings','风险依据'),('risk_factors','风险因素'),('positive_factors','正向依据')):
        value=data.get(key)
        if value:lines.append(label+'：'+(value if isinstance(value,str) else json.dumps(value,ensure_ascii=False))[:1200])
    return '\n'.join(lines)
