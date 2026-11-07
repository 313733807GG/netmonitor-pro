"""Read public report chips without running scripts or browser leak tests."""
from html.parser import HTMLParser
import ipaddress
import json
import re

LABELS = frozenset(('代理','住宅代理','VPN','Tor','中继','匿名出口','爬虫',
    '评论垃圾','论坛垃圾','邮件采集','滥用','威胁情报','高欺诈分','HTTP蜜罐',
    'C&C','恶意软件','黑名单','失陷设备','DNSBL','近期举报','多人举报',
    '已知攻击者','本地威胁','登录攻击','注册攻击','机房 IP','机房IP',
    '风险标记','反诈分','外部名单','本站黑名单','DDoS 节点','邮件直投策略',
    '近 90 天举报','举报置信分','账号攻击','攻击情报','RPKI 授权'))
EMPTY = frozenset(('', '—', '-', '未检出', '无', 'none', 'None'))

class ReportParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth=0;self.chip=None;self.label_depth=None
        self.items=[];self.nuxt=False;self.data=[]
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='script' and attrs.get('id')=='__NUXT_DATA__':self.nuxt=True
        if tag not in ('span','button'):return
        self.depth+=1
        classes=set(attrs.get('class','').split())
        if 'risk-chip' in classes or 'risk-chip-identity' in classes:
            if self.chip is not None:raise ValueError('风险明细结构异常')
            status=next((s for s in ('hit','clear','unknown','conflict') if 'risk-chip--'+s in classes),None)
            if 'risk-chip-identity' in classes:status='identity'
            self.chip={'depth':self.depth,'status':status,'label':'','detail':(attrs.get('title') or attrs.get('aria-label') or '')[:1500]}
        elif self.chip is not None and classes & {'risk-chip__label','ip-identity-badge__label'}:self.label_depth=self.depth
    def handle_data(self,data):
        if self.nuxt:self.data.append(data)
        if self.chip is not None and self.label_depth is not None:self.chip['label']+=data
    def handle_endtag(self,tag):
        if tag=='script':self.nuxt=False
        if tag not in ('span','button'):return
        if self.label_depth==self.depth:self.label_depth=None
        if self.chip is not None and self.chip['depth']==self.depth:
            self.chip['label']=self.chip['label'].strip()
            if self.chip['status']=='identity':
                self.chip['status']='hit' if self.chip['label'] in ('机房 IP','机房IP') else 'unknown'
            if self.chip['label'] in LABELS:self.items.append(self.chip)
            self.chip=None
        self.depth-=1

def parse_report(body,expected_ip):
    expected=str(ipaddress.ip_address(expected_ip))
    if len(body)>2*1024*1024:raise ValueError('CleanIP 明细响应过大')
    parser=ReportParser();parser.feed(body.decode('utf-8') if isinstance(body,bytes) else body);parser.close()
    flat=json.loads(''.join(parser.data))
    from report_selection import select_report
    report,ref=select_report(flat,expected)
    items={x['label']:x for x in parser.items}
    if len(items)<20 or any(x['status'] is None for x in items.values()):
        raise ValueError('CleanIP 风险明细缺失或页面格式变化')
    meta=ref(report['meta']) if 'meta' in report else {}
    at=ref(meta['data_as_of']) if isinstance(meta,dict) and 'data_as_of' in meta else ''
    return {'ip':expected,'hits':[x['label'] for x in items.values() if x['status']=='hit'],
            'items':[{k:v for k,v in x.items() if k!='depth'} for x in items.values()],
            'data_as_of':str(at)[:80],'url':'https://cleanip.io/'+expected}

def risk_colored_parts(clean, prefix='标记：'):
    report=clean.get('risk_details') or {}
    parts=[(prefix,None)]
    seen=set()
    for item in report.get('items',[]):
        label=item['label'];status=item.get('status')
        if status not in ('hit','conflict') or label in seen:continue
        if seen:parts.append(('、',None))
        seen.add(label)
        color='#F59E0B' if status=='conflict' or label in ('机房 IP','机房IP') else '#FF4D5E'
        parts.append((label,color))
    if not seen:parts.append((risk_display(clean)[0],None))
    elif clean.get('_node_summaries'):parts.append(('；汇总：'+'、'.join(dict.fromkeys(x['flags'] for x in clean['_node_summaries'])),None))
    return parts


def risk_display(clean):
    """Display colored website items, including conflicts; summary is fallback only."""
    summary=str(clean.get('flags') or '—')
    report=clean.get('risk_details')
    tooltip='CleanIP 汇总：'+summary
    extra=clean.get('_node_summaries') or []
    if extra:tooltip+='\n其他出口仅有汇总：'+'；'.join(x['ip']+' '+x['flags'] for x in extra)
    if not report:
        if extra:summary='汇总：'+'、'.join(dict.fromkeys(x['flags'] for x in extra))
        return summary,tooltip+'\n明细未取得，当前仅为汇总。'
    hits=report.get('hits',[])
    marked=[x['label'] for x in report.get('items',[]) if x.get('status') in ('hit','conflict')]
    chosen='、'.join(dict.fromkeys(marked)) or '未检出'
    if extra:
        suffix='汇总：'+'、'.join(dict.fromkeys(x['flags'] for x in extra))
        chosen=(chosen+'；'+suffix) if marked else suffix
    tooltip+='\n网页命中明细：'+('、'.join(hits) or '未检出')
    conflicts=[x for x in report.get('items',[]) if x.get('status')=='conflict']
    if conflicts:
        tooltip+='\n网页来源有分歧（不算确定命中）：'+'、'.join(x['label'] for x in conflicts)
        tooltip+='\n'+'\n'.join(x['detail'] for x in conflicts)
    tooltip+='\n来源：'+report.get('url','')+'\n数据时间：'+report.get('data_as_of','未提供')
    summary_items=set() if summary in EMPTY else set(filter(None,re.split(r'[、,，;；|/\s·]+',summary)))
    if set(hits)!=summary_items:
        tooltip+='\n汇总与明细不一致（文字或覆盖范围不同）；展示以网页变色项目为准。'
    tooltip+='\n'+'\n'.join(x['detail'] for x in report.get('items',[]) if x.get('status')=='hit')
    tooltip+='\n展示网页命中及来源分歧项目；打钩、未检测不列出。未运行 DNS/WebRTC 泄漏检测。'
    return chosen,tooltip
