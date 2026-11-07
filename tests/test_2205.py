import unittest,json,copy,tempfile
from pathlib import Path
from unittest.mock import Mock,patch
import ip_quality as q
from quality_evidence import QualityEvidence,risk_clean
import connection_labels as cl
from unknown_log import UnknownTargetLog
from traffic_history import TrafficHistoryStore

class NewQualityTests(unittest.TestCase):
    def pipe(self):
        p=Mock();p.proxies.return_value={'proxies':{'N':{'type':'SS'},q.PROBE_GROUP:{'type':'Selector','all':['N','REJECT']}}};p.configs.return_value={'mode':'rule'}
        return p
    def test_ipv6_has_type_but_no_invented_score(self):
        r=q.parse_ippure('{"ip":"2001:4860::1","fraudScore":0,"isResidential":false}')
        self.assertIsNone(r['score']);self.assertFalse(r['residential'])
    def test_auto_retries_once_ipv4_and_keeps_v6_evidence(self):
        calls=[]
        def request(p,h,path,port,node,owner,**kw):
            calls.append((h,kw.get('family')))
            if h=='my.ippure.com':return (json.dumps({'ip':'1.1.1.1' if kw.get('family')==4 else '2001:4860::1','fraudScore':8}).encode(),{})
            raise OSError('unavailable')
        with patch.object(q,'proxy_get',side_effect=request):r=q.collect_quality(self.pipe(),'N')
        self.assertEqual(calls.count(('my.ippure.com',4)),1);self.assertEqual(r['ippure']['score'],8)
        self.assertEqual(len(r['observed_ips']),2)
    def test_blocked_or_challenged_request_never_retries(self):
        for error in (ValueError('检测接口 HTTP 403'),ValueError('检测接口 HTTP 429'),json.JSONDecodeError('html','x',0)):
            p=self.pipe()
            with patch.object(q,'proxy_get',side_effect=error) as get:r=q.collect_quality(p,'N')
            self.assertEqual(get.call_count,2);self.assertNotIn('ippure_retry',r)
            self.assertEqual(p.select_probe_node.call_args.args,('REJECT',))
    def test_ipv6_specialist_does_not_fallback_or_accept_ipv4(self):
        with patch.object(q,'proxy_get',return_value=(b'{"ip":"1.1.1.1","fraudScore":8}',{})) as get:
            r=q.collect_quality(self.pipe(),'N',family=6)
        self.assertNotIn('ippure',r);self.assertNotIn('ippure_retry',r)
        self.assertTrue(all(c.kwargs.get('family')==6 for c in get.call_args_list))
    def test_resolver_rejects_fake_and_private_addresses(self):
        p=Mock();p.get.return_value={'Answer':[{'type':1,'data':'198.18.0.1'},{'type':1,'data':'127.0.0.1'}]}
        with self.assertRaises(ValueError):q.resolve_target(p,'my.ippure.com',4)
    def test_modes_have_isolated_keys(self):
        d=dict(api_on=True,tun_on=True,mode='rule',ai_target_state='confirmed',ai_node='N',profile_id='P')
        self.assertNotEqual(q.quality_key(d),q.quality_key(dict(d,quality_mode='6')))
    def test_same_node_dual_address_can_compare_types(self):
        r=dict(node='N',route_verified=True,ip_mismatch=True,ippure={'ip':'1.1.1.1','residential':False,'broadcast':True},cleanip={'ip':'2001:4860::1','ip_type':'住宅 IP','native_type':'原生 IP'})
        self.assertEqual(q.type_badges(r)[0][3],'IPPure')
        r.pop('route_verified');self.assertEqual(q.type_badges(r)[0][0],'出口不一致')
    def test_worst_scores_and_union_do_not_cross_nodes(self):
        e=QualityEvidence();key=('P','N')
        def result(ip,score,risk,hit):
            return {'node':'N','route_verified':True,'ippure':{'ip':ip,'score':score,'residential':True},'cleanip':{'ip':ip,'score':100-risk,'risk':risk,'ip_type':'住宅 IP','flags':'未检出','risk_details':{'items':[{'label':hit,'status':'hit','detail':'report'}]}}}
        a=result('1.1.1.1',80,5,'代理');b=result('2001:4860::1',None,70,'滥用')
        e.record(key,a);e.record(key+('6',),b);v=e.view(key,b)
        self.assertTrue(v['dual_stack']);self.assertEqual(v['ippure']['score'],80);self.assertEqual(v['cleanip']['risk'],70)
        self.assertEqual({x['label'] for x in risk_clean(v)['risk_details']['items']},{'代理','滥用'})
        self.assertIsNone(e.view(('P','Other'),None))
        self.assertIsNone(e.view(key+('6',),b)['ippure']['score'])
    def test_cancelled_evidence_is_not_saved(self):
        e=QualityEvidence();e.record(('P','N'),{'cancelled':True,'route_verified':True,'observed_ips':['1.1.1.1']});self.assertFalse(e.nodes)

class PerformanceTests(unittest.TestCase):
    def test_connection_table_shared_only_within_one_tick(self):
        from app import DataEngine
        engine=DataEngine.__new__(DataEngine)
        def tick():
            a=engine._connections_snapshot();b=engine._connections_snapshot()
            self.assertIs(a,b);return a
        engine._tick_impl=tick
        with patch('app.psutil.net_connections',side_effect=[[1],[2]]) as read:
            self.assertEqual(engine.tick(),(1,));self.assertEqual(engine.tick(),(2,));self.assertEqual(read.call_count,2)
        self.assertIsNone(engine._tick_connections)
    def test_changed_aliases_invalidate_cache(self):
        with patch.object(cl,'ALIASES',(('test.example','one'),)):
            self.assertEqual(cl.service_name('a.test.example'),'one')
        with patch.object(cl,'ALIASES',(('test.example','two'),)):
            self.assertEqual(cl.service_name('a.test.example'),'two')
    def test_repeated_note_skips_full_review_but_rule_change_rechecks(self):
        with tempfile.TemporaryDirectory() as d:
            log=UnknownTargetLog(str(Path(d)/'u.json'))
            log.items={'unresolved.example':{'host':'unresolved.example','first':'x','last':'x','count':1}}
            log._prune()
            with patch.object(log,'_keep_record',wraps=log._keep_record) as keep:
                log.note([], 'test');log.note([], 'test');keep.assert_not_called()
                with patch.object(cl,'ALIASES',(('unresolved.example','Known'),)):
                    log.note([], 'test')
                self.assertFalse(log.items);keep.assert_called_once()
    def test_history_default_ten_seconds(self):self.assertEqual(TrafficHistoryStore.WRITE_INTERVAL,10)
