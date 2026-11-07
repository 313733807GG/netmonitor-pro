"""Parse displayed website results, bound to an explicitly requested address."""
import ipaddress,json,re
from cleanip_details import ReportParser,parse_report,risk_display

def public_ip(value,family=None):
    ip=ipaddress.ip_address(str(value).strip())
    if not ip.is_global or ip.is_multicast or (family and ip.version!=family):
        raise ValueError('未取得匹配协议的公网出口地址')
    return str(ip)

def parse_ippure_page(text,expected):
    expected=public_ip(expected);lines=[x.strip() for x in text.splitlines()]
    def after(label):
        try:return lines[lines.index(label)+1]
        except (ValueError,IndexError):raise ValueError('IPPure 网页结果尚未完整加载')
    if public_ip(after('IP'))!=expected:raise ValueError('IPPure 网页查询IP不符')
    origin,kind=after('IP来源'),after('IP属性')
    if origin not in ('原生IP','广播IP','非原生IP') or kind not in ('住宅IP','机房IP','非住宅IP'):
        raise ValueError('IPPure 网页分类尚未完整加载')
    value=None
    if ipaddress.ip_address(expected).version==4:
        match=re.fullmatch(r'(\d+(?:\.\d+)?)%\s*.+',after('IPPure系数'))
        if not match or not 0<=float(match[1])<=100:raise ValueError('IPPure 网页分数未取得')
        value=float(match[1])
    location={};variants=[]
    for source in ('MaxMind','IPInfo.io','DB-IP','IP2Location'):
        try:parts=[x.strip() for x in after(source).split(',') if x.strip()]
        except ValueError:continue
        if len(parts)>=2:
            candidate={'country':parts[0],'region':parts[1],'city':parts[2] if len(parts)>2 else '', 'parts':parts[1:]}
            if not location:location=dict(candidate)
            variants.append(candidate)
    location['alternatives']=variants
    return {'ip':expected,'score':value,'broadcast':origin!='原生IP','residential':kind=='住宅IP',
            'location':location,'query_method':'网页指定IP查询','query_url':'https://ippure.com/'}

def parse_cleanip_page(body,expected):
    expected=public_ip(expected)
    if len(body)>2*1024*1024:raise ValueError('CleanIP 报告过大')
    parser=ReportParser();parser.feed(body.decode('utf-8') if isinstance(body,bytes) else body);parser.close()
    flat=json.loads(''.join(parser.data))
    from report_selection import select_report
    report,ref=select_report(flat,expected)
    def fields(name):
        obj=ref(report[name]);return {k:ref(v) for k,v in obj.items()} if isinstance(obj,dict) else {}
    purity,risk,geo=fields('purity'),fields('risk'),fields('geo')
    from ip_quality import score
    if purity.get('score') is None or risk.get('risk_score') is None:raise ValueError('CleanIP 评分暂未就绪，请稍后补查')
    value=score(purity.get('score'));risk_value=score(risk.get('risk_score'))
    labels={'Residential IP':'住宅 IP','Datacenter IP':'机房 IP','Data Center IP':'机房 IP',
            'Mobile IP':'移动 IP','Business IP':'商业 IP','Hosting IP':'机房 IP'}
    label=str(purity.get('ip_type') or '未知类型')
    native=purity.get('is_native')
    result={'ip':expected,'score':value,'risk':risk_value,'grade':str(purity.get('grade') or ''),
            'flags':'未检出','ip_type':labels.get(label,label),
            'native_type':'原生 IP' if native is True else ('广播 IP' if native is False else '归属待确认'),
            'location':{k:str(geo.get(k) or '') for k in ('country','region','city')},
            'query_method':'网页指定IP查询','query_url':'https://cleanip.io/'+expected}
    variants=[]
    if 'geo_sources' in report:
        try:
            sources=ref(report['geo_sources'])
            if isinstance(sources,list):
                for index in sources[:30]:
                    row=ref(index)
                    if isinstance(row,dict):variants.append({k:str(ref(row[k]) or '') for k in ('country','region','city','district') if k in row})
        except (ValueError,TypeError):pass
    result['location']['alternatives']=variants
    try:result['risk_details']=parse_report(body,expected);result['flags']=risk_display(result)[0]
    except (ValueError,KeyError,TypeError) as e:
        result['flags']='明细未取得';result['details_error']=str(e)
    return result
