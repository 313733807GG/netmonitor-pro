import unittest,json
from unittest.mock import Mock,patch
import address_quality as a
from lookup_parsers import public_ip,parse_cleanip_page,parse_ippure_page
from cleanip_details import LABELS

def report(ip='1.1.1.1',score=75):
    flat=[]
    def put(x):
        i=len(flat);flat.append(None)
        flat[i]={k:put(v) for k,v in x.items()} if isinstance(x,dict) else x
        return i
    put({'ok':True,'ip':ip,'risk':{'risk_score':100-score},'purity':{'score':score,'grade':'B','ip_type':'Residential IP','is_native':True},'geo':{'country':'日本','region':'东京','city':'新宿'}})
    chips=''.join('<span class="risk-chip risk-chip--clear"><span class="risk-chip__label">'+label+'</span></span>' for label in LABELS)
    return ('<script id="__NUXT_DATA__">'+json.dumps(flat)+'</script>'+chips).encode()

def pure(ip='1.1.1.1'):
    return 'IP\n'+ip+'\nASN\nAS1\n位置\nMaxMind\nJapan, Tokyo, Shinjuku\nIP来源\n原生IP\nIP属性\n住宅IP\nIPPure系数\n85% 极度风险'

def authorized_client(request):
    """Exercise the collector with deterministic API results, never real keys."""
    client=Mock()
    client.query.side_effect=lambda ip:parse_cleanip_page(request(None,'cleanip.io','/'+ip)[0],ip)
    return patch.object(a,'CleanIPClient',return_value=client)

class AddressTests(unittest.TestCase):
    def test_public_family_validation(self):
        for ip in ('127.0.0.1','192.168.1.1','::1','ff02::1'):
            with self.assertRaises(ValueError):public_ip(ip)
        with self.assertRaises(ValueError):public_ip('1.1.1.1',6)
    def test_clean_report_exact_address_and_values(self):
        r=parse_cleanip_page(report(),'1.1.1.1')
        self.assertEqual((r['score'],r['risk'],r['ip_type']),(75,25,'住宅 IP'))
        self.assertEqual(r['native_type'],'原生 IP');self.assertIn('risk_details',r)
        with self.assertRaises(ValueError):parse_cleanip_page(report(),'8.8.8.8')
    def test_browser_parsing_rejects_wrong_or_partial_ip(self):
        self.assertEqual(parse_ippure_page(pure(),'1.1.1.1')['score'],85)
        with self.assertRaises(ValueError):parse_ippure_page(pure(),'8.8.8.8')
        with self.assertRaises(ValueError):parse_ippure_page(pure().replace('住宅IP','加载中'),'1.1.1.1')
    def test_v6_never_inherits_a_v4_score(self):
        self.assertIsNone(parse_ippure_page(pure('2606:4700::1111'),'2606:4700::1111')['score'])
    def setup_case(self,miss6=False):
        p=Mock();state={'now':'REJECT'}
        p.proxies.side_effect=lambda:{'proxies':{'N':{'type':'SS'},a.q.PROBE_GROUP:{'type':'Selector','all':['N','REJECT'],'now':state['now']}}}
        def select(n):state['now']=n;return True
        p.select_probe_node.side_effect=select;p.configs.return_value={'mode':'rule'}
        calls=[]
        def request(pipe,host,path,*args,**kw):
            calls.append((host,path))
            if host=='ipv4.icanhazip.com':return b'1.1.1.1\n',{}
            if host=='ipv6.icanhazip.com':
                if miss6:raise TimeoutError('timeout')
                return b'2606:4700::1111\n',{}
            if host=='my.ippure.com':return b'{"ip":"1.1.1.1","fraudScore":85,"isResidential":true}',{}
            return report(path[1:],50 if ':' in path else 95),{}
        browser=Mock();browser.__enter__=Mock(return_value=browser);browser.__exit__=Mock(return_value=False)
        browser.lookup.side_effect=lambda ip:parse_ippure_page(pure(ip),ip)
        return p,request,browser,calls,state
    def test_automatic_discovers_both_and_queries_both_sites_by_ip(self):
        p,request,browser,calls,state=self.setup_case()
        with patch.object(a.q,'proxy_get',side_effect=request),authorized_client(request):r=a.collect_quality(p,'N')
        self.assertEqual(len({(x['source'],x['data']['ip']) for x in r['observations']}),3);self.assertEqual(r['ippure']['ip'],'1.1.1.1')
        self.assertEqual(r['cleanip']['ip'],'2606:4700::1111');self.assertEqual(r['cleanip']['score'],50)
        self.assertEqual(state['now'],'REJECT');self.assertIn('ippure',r['errors']);self.assertIn('2606:4700::1111',r['errors']['ippure'])
    def test_manual_family_selects_address_not_transport(self):
        p,request,browser,calls,state=self.setup_case()
        with patch.object(a.q,'proxy_get',side_effect=request),authorized_client(request):r=a.collect_quality(p,'N',family=6)
        self.assertNotIn('ippure',r);self.assertIn('轻量接口未取得',r['errors']['ippure'])
        self.assertNotIn(('cleanip.io','/1.1.1.1'),calls);self.assertEqual(len(r['observations']),2)
        self.assertEqual(r['cleanip']['ip'],'2606:4700::1111')
    def test_ipv6_timeout_does_not_assert_ipv4_only(self):
        p,request,browser,calls,state=self.setup_case(True)
        with patch.object(a.q,'proxy_get',side_effect=request),authorized_client(request):r=a.collect_quality(p,'N')
        self.assertIn('6',r['discovery']['errors']);self.assertNotIn('ipv4_only',r)
        self.assertEqual(r['observed_ips'],['1.1.1.1']);self.assertEqual(state['now'],'REJECT')
    def test_missing_requested_family_does_not_query_other_address(self):
        p,request,browser,calls,state=self.setup_case(True)
        with patch.object(a.q,'proxy_get',side_effect=request) as ctor:r=a.collect_quality(p,'N',family=6)
        self.assertIn('request',r['errors']);self.assertEqual(len(calls),2);self.assertEqual(state['now'],'REJECT')
    def test_public_interface_failure_keeps_cleanip_and_cleans_selector(self):
        p,request,browser,calls,state=self.setup_case()
        def get(pipe,host,path,*args,**kw):
            if host=='my.ippure.com':raise OSError('HTTP 403')
            return request(pipe,host,path,*args,**kw)
        with patch.object(a.q,'proxy_get',side_effect=get),authorized_client(get):r=a.collect_quality(p,'N')
        self.assertIn('cleanip',r);self.assertNotIn('ippure',r);self.assertIn('ippure',r['errors']);self.assertEqual(state['now'],'REJECT')
    def test_cancel_mid_query_releases_selector(self):
        p,request,browser,calls,state=self.setup_case();owner=Mock();owner.isInterruptionRequested.side_effect=[False,False,False,True]
        with patch.object(a.q,'proxy_get',side_effect=request),authorized_client(request):r=a.collect_quality(p,'N',owner)
        self.assertTrue(r['cancelled']);self.assertEqual(state['now'],'REJECT')
