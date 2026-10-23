import unittest
from unittest.mock import patch, Mock
import ip_quality as q
from pipe_client import MihomoPipe

class QualityTests(unittest.TestCase):
    def setUp(self):
        self.s={'proxies':{'AI':{'type':'Selector','now':'A'},'Media':{'type':'Selector','now':'B'},
                          'GLOBAL':{'type':'Selector','now':'A'},'A':{'type':'SS'},'B':{'type':'SS'},
                          q.PROBE_GROUP:{'type':'Selector','now':'REJECT','all':['A','B','REJECT']}}}
    def conn(self,host='chatgpt.com',node='A',group='AI',start='1'):
        return {'metadata':{'host':host},'chains':[node,group],'start':start}
    def data(self,**kw):
        d=dict(api_on=True,sp_on=False,tun_on=True,mode='rule',ai_target_state='confirmed',ai_node='A',profile_id='subscription')
        d.update(kw);return d
    def test_ai_ignores_media(self):
        t=q.ai_target([self.conn(),self.conn('netflix.com','B','Media')],self.s,'rule')
        self.assertEqual(t['node'],'A')
        self.s['proxies']['Media']['now']='A'
        self.assertEqual(q.ai_target([self.conn()],self.s,'rule')['node'],'A')
    def test_own_probes_not_ai_evidence(self):
        t=q.ai_target([self.conn(group=q.PROBE_GROUP)],self.s,'rule')
        self.assertEqual(t['state'],'waiting')
    def test_changed_ai_rejects_old_connection(self):
        prev=q.ai_target([self.conn()],self.s,'rule')
        self.s['proxies']['AI']['now']='B'
        self.assertEqual(q.ai_target([self.conn()],self.s,'rule',prev)['state'],'waiting')
        self.assertEqual(q.ai_target([self.conn(node='B',start='2')],self.s,'rule',prev)['node'],'B')
    def test_idle_retains_confirmed_target(self):
        prev=q.ai_target([self.conn()],self.s,'rule')
        self.assertEqual(q.ai_target([],self.s,'rule',prev)['node'],'A')
    def test_direct_not_detected(self):
        self.assertEqual(q.ai_target([self.conn(node='DIRECT',group='DIRECT')],self.s,'rule')['state'],'direct')
        for d in (self.data(mode='direct'),self.data(ai_target_state='direct'),self.data(api_on=False),self.data(tun_on=False)):
            self.assertFalse(q.quality_key(d))
    def test_global_wins(self):
        self.s['proxies']['GLOBAL']['now']='B'
        self.assertEqual(q.ai_target([self.conn()],self.s,'global')['node'],'B')
    def test_global_missing_or_cyclic_waits(self):
        self.assertEqual(q.ai_target([],{},'global')['state'],'waiting')
        self.s['proxies']['GLOBAL']['now']='GLOBAL'
        self.assertEqual(q.ai_target([],self.s,'global')['state'],'waiting')
    def test_collector_failure_resets_only_probe(self):
        p=Mock();p.proxies.return_value=self.s;p.configs.return_value={'mode':'rule'}
        with patch.object(q,'proxy_get',side_effect=OSError('offline')):
            result=q.collect_quality(p,'A')
        self.assertEqual(set(result['errors']),{'ippure','cleanip'})
        self.assertEqual([c.args[0] for c in p.select_probe_node.call_args_list],['A','REJECT'])
    def test_direct_switch_sends_no_score_requests(self):
        p=Mock();p.proxies.return_value=self.s;p.configs.return_value={'mode':'direct'}
        with patch.object(q,'proxy_get') as request:
            q.collect_quality(p,'A')
            request.assert_not_called()
        self.assertEqual(p.select_probe_node.call_args.args,('REJECT',))
    def test_cancelled_route_lookup_does_not_query(self):
        p=Mock();owner=Mock();owner.isInterruptionRequested.return_value=True
        with self.assertRaises(OSError):q.connection_for_port(p,12345,owner)
        p.connections.assert_not_called()
    def test_cache_once_per_node_and_manual(self):
        c=q.QualityCache();k=q.quality_key(self.data())
        self.assertTrue(c.begin(k));self.assertFalse(c.begin(('x','B')))
        c.finish(k,{'errors':{'ippure':'unavailable'}})
        self.assertFalse(c.begin(k));self.assertTrue(c.begin(k,manual=True))
        c.finish(k,{'ippure':{'score':9}})
        self.assertEqual(c.results[k]['ippure']['score'],9)
        self.assertTrue(q.QualityCache().begin(k))
    def test_cache_mode_and_other_group_changes_do_not_repeat(self):
        self.assertEqual(q.quality_key(self.data()),q.quality_key(self.data(mode='global',sp_on=True)))
        self.assertNotEqual(q.quality_key(self.data()),q.quality_key(self.data(profile_id='other')))
    def test_parsers(self):
        self.assertEqual(q.parse_ippure('{"ip":"1.1.1.1","fraudScore":9}')['score'],9)
        text='  IP  1.1.1.1 (IPv4)\n CleanIP 评分 [#####] 89/100 (A)\n 风险评分 11/100 极低风险\n 风险标记 未检出\n'
        c=q.parse_cleanip(text);self.assertEqual((c['score'],c['risk'],c['flags']),(89,11,'未检出'))
    def test_invalid_never_zero_score(self):
        for val in (None,True,float('nan'),-1,101,'9'):
            with self.assertRaises(ValueError):q.score(val)
        with self.assertRaises(ValueError):q.parse_cleanip('<html>Verify you are human</html>')
        with self.assertRaises(ValueError):q.parse_ippure('{"ip":"1.1.1.1"}')
    def test_thresholds(self):
        self.assertIn('极度纯净',q.ippure_badge(9)[0])
        self.assertNotEqual(q.ippure_badge(15)[1],q.ippure_badge(16)[1])
        self.assertIn('高风险',q.ippure_badge(71)[0])
    def test_probe_group_does_not_break_unique_selector(self):
        p=MihomoPipe()
        s={'proxies':{'Provider':{'type':'Selector','now':'A'},'A':{'type':'SS'},q.PROBE_GROUP:self.s['proxies'][q.PROBE_GROUP]}}
        self.assertEqual(p.ai_selection(s)[1],'A')
    def test_only_dedicated_group_can_be_written(self):
        p=MihomoPipe();p._chan=('tcp',1,'')
        with patch.object(p,'proxies',return_value=self.s),patch.object(p,'_exchange',return_value=(204,b'')) as call:
            self.assertTrue(p.select_probe_node('A'))
            self.assertIn(q.PROBE_GROUP,call.call_args.args[1])
            self.assertFalse(p.select_probe_node('AI'))

if __name__=='__main__':unittest.main()
