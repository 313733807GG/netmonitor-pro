import unittest,copy,json
from unittest.mock import Mock,patch
from types import SimpleNamespace as NS
import ip_quality as q
from quality_evidence import QualityEvidence,risk_clean
from app import NetMonitorWidget

class FeedbackTests(unittest.TestCase):
    def pipe(self):
        p=Mock();p.proxies.return_value={'proxies':{'N':{'type':'SS'},q.PROBE_GROUP:{'type':'Selector','all':['N','REJECT']}}};p.configs.return_value={'mode':'rule'};return p
    def test_mismatch_is_not_requested_score_but_keeps_negative_evidence(self):
        p=self.pipe()
        with patch.object(q,'proxy_get',return_value=(b'{"ip":"2001:4860::1","fraudScore":0,"isResidential":false}',{})),patch.object(q,'parse_cleanip',side_effect=ValueError('test')):
            r=q.collect_quality(p,'N',family=4)
        self.assertNotIn('ippure',r);self.assertEqual(r['protocol_mismatches']['ippure']['actual'],6)
        self.assertIn('2001:4860::1',r['observed_ips'])
        e=QualityEvidence();e.record(('p','N','4'),r);v=e.view(('p','N','4'),r)
        self.assertNotIn('ippure',v);self.assertFalse(v['node_evidence'][0]['data']['residential'])
        self.assertIn('未取得IPv4（返回IPv6）',q.quality_feedback(r))
    def test_mismatched_cleanip_still_reads_same_observed_ip_risks(self):
        p=self.pipe();calls=[]
        cli={'ip':'1.1.1.1','score':45.,'risk':55.,'grade':'D','flags':'VPN'}
        def request(pipe,host,path,*a,**kw):
            calls.append((host,path));return (b'{"ip":"2001:4860::1","fraudScore":0}',{})
        report={'items':[{'label':'VPN','status':'hit','detail':'hit'}]}
        with patch.object(q,'proxy_get',side_effect=request),patch.object(q,'parse_cleanip',return_value=cli),patch.object(q,'parse_report',return_value=report):
            r=q.collect_quality(p,'N',family=6)
        self.assertNotIn('cleanip',r);self.assertIn(('cleanip.io','/1.1.1.1'),calls)
        e=QualityEvidence();e.record(('p','N','6'),r)
        self.assertEqual(risk_clean(e.view(('p','N','6'),r))['risk_details']['items'][0]['label'],'VPN')
    def test_failed_refresh_preserves_old_and_current_mismatch(self):
        c=q.QualityCache();key=('p','N','4')
        c.results[key]={'time':'old','ippure':{'ip':'1.1.1.1','score':10}}
        c.begin(key,True);r={'time':'new','errors':{'ippure':'mismatch'},'protocol_mismatches':{'ippure':{'requested':4,'actual':6,'ip':'::1'}}}
        c.finish(key,r)
        self.assertEqual(c.results[key]['time'],'old');self.assertEqual(c.results[key]['refresh_time'],'new')
        self.assertEqual(c.results[key]['protocol_mismatches'],r['protocol_mismatches'])
    def test_success_feedback_confirms_requery_even_if_unchanged(self):
        r={'mode':'4','ippure':{'score':9},'cleanip':{'score':97},'errors':{}}
        text=q.quality_feedback(r);self.assertIn('IPv4检测完成',text);self.assertIn('数值相同也已重新查询',text)
    def test_ipv6_no_score_is_not_request_failure(self):
        r={'mode':'6','ippure':{'score':None},'cleanip':{'score':97},'errors':{}}
        text=q.quality_feedback(r);self.assertIn('IPv6检测完成',text);self.assertIn('IPv6不提供分数',text)
    def test_detail_failure_is_not_silent_clean_result(self):
        r={'mode':'auto','ippure':{'score':9},'cleanip':{'score':97},'errors':{'cleanip_details':'timeout'}}
        self.assertIn('风险明细未完成',q.quality_feedback(r))
    def test_stale_completion_never_toasts_on_another_node(self):
        d={'api_on':True,'tun_on':True,'ai_target_state':'confirmed','ai_node':'NEW','profile_id':'p'}
        w=NS(quality_cache=Mock(),quality_evidence=Mock(),_shutting_down=False,_last_data=d,_render_quality=Mock(),_show_toast=Mock())
        NetMonitorWidget._quality_done(w,('p','OLD'),{'mode':'auto','errors':{}},True)
        w._show_toast.assert_not_called()
        NetMonitorWidget._quality_done(w,('p','NEW'),{'mode':'auto','errors':{}},True)
        w._show_toast.assert_called_once()
