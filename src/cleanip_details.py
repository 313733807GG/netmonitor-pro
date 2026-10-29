"""Read public report chips without running scripts or browser leak tests."""
from html.parser import HTMLParser
import ipaddress
import json
import re

LABELS = frozenset(('代理','住宅代理','VPN','Tor','中继','匿名出口','爬虫',
    '评论垃圾','论坛垃圾','邮件采集','滥用','威胁情报','高欺诈分','HTTP蜜罐',
    'C&C','恶意软件','黑名单','失陷设备','DNSBL','近期举报','多人举报',
    '已知攻击者','本地威胁','登录攻击','注册攻击','机房 IP','机房IP'))
EMPTY = frozenset(('', '—', '-', '未检出', '无', 'none', 'None'))

class ReportParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth=0;self.chip=None;self.label_depth=None
        self.items=[];self.nuxt=False;self.data=[]
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='script' and attrs.get('id')=='__NUXT_DATA__':self.nuxt=True
        if tag!='span':return
        self.depth+=1
        classes=set(attrs.get('class','').split())
        if 'risk-chip' in classes:
            if self.chip is not None:raise ValueError('风险明细结构异常')
            status=next((s for s in ('hit','clear','unknown') if 'risk-chip--'+s in classes),None)
            self.chip={'depth':self.depth,'status':status,'label':'','detail':attrs.get('title','')[:1500]}
        elif self.chip is not None and 'risk-chip__label' in classes:self.label_depth=self.depth
    def handle_data(self,data):
        if self.nuxt:self.data.append(data)
        if self.chip is not None and self.label_depth is not None:self.chip['label']+=data
    def handle_endtag(self,tag):
        if tag=='script':self.nuxt=False
        if tag!='span':return
        if self.label_depth==self.depth:self.label_depth=None
        if self.chip is not None and self.chip['depth']==self.depth:
            self.chip['label']=self.chip['label'].strip()
            if self.chip['label'] in LABELS:self.items.append(self.chip)
            self.chip=None
        self.depth-=1

def parse_report(body,expected_ip):
    expected=str(ipaddress.ip_address(expected_ip))
    if len(body)>2*1024*1024:raise ValueError('CleanIP 明细响应过大')
    parser=ReportParser();parser.feed(body.decode('utf-8') if isinstance(body,bytes) else body);parser.close()
    flat=json.loads(''.join(parser.data))
    if not isinstance(flat,list) or len(flat)>30000:raise ValueError('CleanIP 明细数据结构变化')
    def ref(index):
        if type(index) is not int or index<0 or index>=len(flat):raise ValueError('CleanIP 明细引用异常')
        return flat[index]
    reports=[x for x in flat if isinstance(x,dict) and {'ip','risk','ok'}<=x.keys()]
    if len(reports)!=1 or ref(reports[0]['ip'])!=expected or ref(reports[0]['ok']) is not True:
        raise ValueError('CleanIP 明细 IP 未核实或与评分 IP 不同')
    items={x['label']:x for x in parser.items}
    if len(items)<20 or any(x['status'] is None for x in items.values()):
        raise ValueError('CleanIP 风险明细缺失或页面格式变化')
    meta=ref(reports[0]['meta']) if 'meta' in reports[0] else {}
    at=ref(meta['data_as_of']) if isinstance(meta,dict) and 'data_as_of' in meta else ''
    return {'ip':expected,'hits':[x['label'] for x in items.values() if x['status']=='hit'],
            'items':[{k:v for k,v in x.items() if k!='depth'} for x in items.values()],
            'data_as_of':str(at)[:80],'url':'https://cleanip.io/'+expected}

def risk_display(clean):
    """Explicit hits win; retain summary if details are unavailable or disagree."""
    summary=str(clean.get('flags') or '—')
    report=clean.get('risk_details')
    tooltip='CleanIP 汇总：'+summary
    if not report:
        return summary,tooltip+'\n明细未取得，当前仅为汇总。'
    hits=report.get('hits',[])
    chosen='、'.join(hits) if hits else (summary if summary not in EMPTY else '未检出')
    tooltip+='\n网页命中明细：'+('、'.join(hits) or '未检出')
    tooltip+='\n来源：'+report.get('url','')+'\n数据时间：'+report.get('data_as_of','未提供')
    summary_items=set() if summary in EMPTY else set(filter(None,re.split(r'[、,，;；|/\s·]+',summary)))
    if set(hits)!=summary_items:
        tooltip+='\n汇总与明细不一致（文字或覆盖范围不同）；优先保留明确命中，不将差异当作全部通过。'
    tooltip+='\n'+'\n'.join(x['detail'] for x in report.get('items',[]) if x.get('status')=='hit')
    tooltip+='\n仅展示已返回的命中；未运行 DNS/WebRTC 泄漏检测。'
    return chosen,tooltip
