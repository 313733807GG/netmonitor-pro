import unittest,json
from unittest.mock import Mock,patch
import address_quality as a
import test_address_quality as fixtures
from quality_evidence import QualityEvidence

class LookupFallbackTests(unittest.TestCase):
    def test_echo_failure_reuses_matching_public_result_without_browser(self):
        p,request,browser,calls,state=fixtures.AddressTests().setup_case()
        def get(pipe,host,path,*args,**kw):
            if 'icanhazip' in host:raise OSError('EOF')
            if host=='my.ippure.com':return b'{"ip":"1.1.1.1","fraudScore":8,"isResidential":true}',{}
            if path=='/cli':raise OSError('unavailable')
            return fixtures.report(path[1:]),{}
        with patch.object(a.q,'proxy_get',side_effect=get),fixtures.authorized_client(get):r=a.collect_quality(p,'N')
        self.assertEqual(r['ippure']['score'],8);self.assertEqual(r['cleanip']['score'],75)
        self.assertEqual(r['discovery']['ips'],{'4':'1.1.1.1'});self.assertEqual(state['now'],'REJECT')
    def test_new_actual_ip_is_not_assigned_to_another_query_slot(self):
        p,request,browser,calls,state=fixtures.AddressTests().setup_case()
        def get(pipe,host,path,*args,**kw):
            if host=='my.ippure.com':return b'{"ip":"8.8.8.8","fraudScore":80,"isResidential":false}',{}
            return request(pipe,host,path,*args,**kw)
        with patch.object(a.q,'proxy_get',side_effect=get),fixtures.authorized_client(get):r=a.collect_quality(p,'N')
        self.assertIn('8.8.8.8',r['observed_ips']);self.assertIn(('cleanip.io','/8.8.8.8'),calls)
        self.assertEqual(next(x['data']['score'] for x in r['observations'] if x['source']=='ippure' and x['data']['ip']=='8.8.8.8'),80)
    def test_cancel_after_first_success_preserves_it_for_its_node(self):
        p,request,browser,calls,state=fixtures.AddressTests().setup_case();owner=Mock();owner.isInterruptionRequested.return_value=False
        def get(pipe,host,path,*args,**kw):
            answer=request(pipe,host,path,*args,**kw)
            if host=='cleanip.io' and path=='/1.1.1.1':owner.isInterruptionRequested.return_value=True
            return answer
        with patch.object(a.q,'proxy_get',side_effect=get),fixtures.authorized_client(get):r=a.collect_quality(p,'N',owner)
        self.assertTrue(r['partial']);self.assertTrue(r['cancelled']);self.assertEqual(state['now'],'REJECT')
        e=QualityEvidence();e.record(('p','N'),r)
        self.assertEqual(e.query_snapshot(('p','N'))['records'][0]['data']['ip'],'1.1.1.1')
