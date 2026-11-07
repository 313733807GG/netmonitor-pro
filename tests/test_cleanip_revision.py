import unittest,json
from cleanip_details import parse_report,risk_display,risk_colored_parts,LABELS
from lookup_parsers import parse_cleanip_page
from report_selection import select_report
from quality_retry import QualityRetry

class CleanipRevisionTests(unittest.TestCase):
    def report(self,tag='button'):
        flat=[{'ok':1,'ip':2,'risk':3},True,'1.1.1.1',{}]
        labels=['代理','住宅代理','VPN','Tor','中继','匿名出口','滥用','风险标记','爬虫','反诈分','评论垃圾','论坛垃圾','DNSBL','外部名单','本站黑名单','HTTP蜜罐','DDoS 节点','邮件直投策略','近 90 天举报','举报置信分','账号攻击','攻击情报','本地威胁','失陷设备','RPKI 授权']
        chips=[]
        for label in labels:
            status='hit' if label in ('滥用','近 90 天举报') else 'conflict' if label=='外部名单' else 'unknown' if label=='反诈分' else 'clear'
            chips.append(f'<{tag} class="risk-chip risk-chip--{status}" aria-label="{label} · 测试依据"><i></i><span class="risk-chip__label">{label}</span><b class="risk-chip__value">12</b></{tag}>')
        chips.append(f'<{tag} class="risk-chip risk-chip--hit"><span class="risk-chip__label">WebRTC 泄漏</span></{tag}>')
        return '<script id="__NUXT_DATA__">'+json.dumps(flat)+'</script>'+''.join(chips)
    def test_new_buttons_and_accessible_details(self):
        result=parse_report(self.report(),'1.1.1.1')
        self.assertEqual(len(result['items']),25)
        self.assertIn('滥用',result['hits']);self.assertNotIn('WebRTC 泄漏',result['hits'])
        self.assertEqual(result['items'][0]['label'],'代理')
        self.assertEqual(result['items'][0]['detail'],'代理 · 测试依据')
        text,tip=risk_display({'risk_details':result})
        self.assertIn('近 90 天举报',text);self.assertNotIn('近期举报',text)
        self.assertIn('外部名单',text);self.assertNotIn('反诈分',text)
        self.assertIn(('外部名单','#F59E0B'),risk_colored_parts({'risk_details':result}))
    def test_old_spans_still_parse(self):
        self.assertEqual(len(parse_report(self.report('span'),'1.1.1.1')['items']),25)
    def test_exact_query_placeholder_is_pending_not_wrong_ip(self):
        flat=[{'q:1.1.1.1':1},{'kind':2},'ip']
        with self.assertRaisesRegex(ValueError,'暂未就绪'):select_report(flat,'1.1.1.1')
        with self.assertRaisesRegex(ValueError,'未包含'):select_report(flat,'8.8.8.8')
    def test_pending_does_not_accept_unrelated_completed_report(self):
        flat=[{'q:1.1.1.1':1},{'kind':2},'ip',{'ok':4,'ip':5,'risk':6},True,'8.8.8.8',{}]
        with self.assertRaisesRegex(ValueError,'暂未就绪'):select_report(flat,'1.1.1.1')
    def test_pending_only_schedules_one_missing_retry(self):
        retry=QualityRetry();result={'errors':{'cleanip':'CleanIP 报告暂未就绪，请稍后补查'}}
        retry.completed('node',result,now=0);self.assertFalse(retry.due('node',14));self.assertTrue(retry.due('node',15))
        retry.consume('node');retry.completed('node',result,now=20);self.assertFalse(retry.due('node',100))

if __name__=='__main__':unittest.main()
