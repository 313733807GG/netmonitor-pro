import unittest,gzip,copy
from unittest.mock import patch,Mock
import test_address_quality as fixtures
import address_quality as a
from quality_evidence import QualityEvidence
from quality_retry import QualityRetry
from ip_quality import decode_response,quality_feedback

class QueryCacheTests(unittest.TestCase):
    def first(self):
        p,request,browser,calls,state=fixtures.AddressTests().setup_case()
        with patch.object(a.q,'proxy_get',side_effect=request):r=a.collect_quality(p,'N')
        # Model an earlier successful IPv6 public-interface observation.
        r['observations'].append({'source':'ippure','data':{'ip':'2606:4700::1111','score':None,'residential':True}})
        e=QualityEvidence();e.record(('p','N'),r)
        return p,request,browser,calls,state,r,e
    def test_select_family_reuses_both_sites_without_external_calls(self):
        p,request,browser,calls,state,r,e=self.first();p.reset_mock()
        with patch.object(a.q,'proxy_get') as request:
            v=a.collect_quality(p,'N',family=6,cache=e.query_snapshot(('p','N','6')))
        request.assert_not_called();p.select_probe_node.assert_not_called()
        self.assertEqual(len(v['reused']),2);self.assertEqual(v['queried'],[])
        self.assertIn('没有重复请求',quality_feedback(v))
    def test_only_missing_site_and_ip_is_fetched(self):
        p,request,browser,calls,state,r,e=self.first();cache=e.query_snapshot(('p','N'))
        cache['records']=[x for x in cache['records'] if not (x['source']=='cleanip' and ':' in x['data']['ip'])]
        calls.clear();browser.reset_mock()
        with patch.object(a.q,'proxy_get',side_effect=request):
            v=a.collect_quality(p,'N',cache=cache)
        self.assertEqual(calls,[('cleanip.io','/2606:4700::1111')])
        self.assertEqual(len(v['reused']),3);self.assertEqual(v['queried'],[['cleanip','2606:4700::1111']])
    def test_left_refresh_rechecks_selected_family(self):
        p,request,browser,calls,state,r,e=self.first();calls.clear();browser.reset_mock()
        with patch.object(a.q,'proxy_get',side_effect=request):
            v=a.collect_quality(p,'N',family=4,cache=e.query_snapshot(('p','N')),force=True)
        self.assertEqual(v['reused'],[]);self.assertEqual(len(v['queried']),2)
        self.assertIn(('my.ippure.com','/v1/info'),calls);self.assertNotIn(('cleanip.io','/2606:4700::1111'),calls)
    def test_preserved_evidence_does_not_get_new_timestamp(self):
        _,_,_,_,_,r,e=self.first();old=e.query_snapshot(('p','N'))['records'][0]['data']['_observed_at']
        snap=e.query_snapshot(('p','N'));r2=dict(r,time='tomorrow',observations=snap['records'])
        r2.pop('ippure',None);r2.pop('cleanip',None);e.record(('p','N'),r2)
        self.assertEqual(e.query_snapshot(('p','N'))['records'][0]['data']['_observed_at'],old)
    def test_partial_cancel_keeps_old_node_success_but_not_other_node(self):
        _,_,_,_,_,r,e=self.first();e=QualityEvidence()
        result=dict(r,cancelled=True,partial=True,observations=r['observations'][:1]);result.pop('ippure');result.pop('cleanip')
        e.record(('p','N'),result)
        self.assertEqual(len(e.query_snapshot(('p','N'))['records']),1)
        self.assertEqual(e.query_snapshot(('p','OTHER')),{});self.assertEqual(e.query_snapshot(('other','N')),{})
    def test_retry_once_only_after_15_seconds(self):
        r=QualityRetry();key=('p','N');result={'errors':{'cleanip':'timeout'}}
        r.completed(key,result,now=0);self.assertFalse(r.due(key,14.9));self.assertTrue(r.due(key,15))
        r.consume(key);r.completed(key,result,now=16);self.assertFalse(r.due(key,1000))
        r.reset(key);r.completed(key,result,now=2000);self.assertTrue(r.due(key,2015))
    def test_access_barriers_never_schedule_retry(self):
        for error in ('HTTP 403','HTTP 429','需要网页验证','查询IP不符'):
            r=QualityRetry();r.completed(('p','N'),{'errors':{'ippure':error}},now=0)
            self.assertFalse(r.due(('p','N'),100))
    def test_gzip_decompression_is_bounded(self):
        self.assertEqual(decode_response(gzip.compress(b'hello'),'gzip',10),b'hello')
        with self.assertRaises(ValueError):decode_response(gzip.compress(b'a'*10000),'gzip',100)
