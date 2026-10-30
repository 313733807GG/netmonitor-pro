import unittest
from unittest.mock import Mock,patch
import ip_quality as q
from app import user_explicit_proxy,register_health_probe_port

class QualityRecoveryTests(unittest.TestCase):
    def test_cancelled_first_attempt_can_restart(self):
        c=q.QualityCache();k=('subscription','node')
        self.assertTrue(c.begin(k))
        c.finish(k,{'cancelled':True,'errors':{'request':'closed'}})
        self.assertNotIn(k,c.results)
        self.assertTrue(c.begin(k))

    def test_cancelled_refresh_does_not_destroy_previous_result(self):
        c=q.QualityCache();k=('s','n');old={'ippure':{'score':9}}
        c.results[k]=old;c.begin(k,True)
        c.finish(k,{'cancelled':True})
        self.assertIs(c.results[k],old)
        self.assertIsNone(c.pending)

    def test_failed_manual_refresh_retains_success_with_visible_reason(self):
        c=q.QualityCache();k=('s','n')
        c.results[k]={'time':'old','ippure':{'ip':'1.1.1.1','score':9}}
        c.begin(k,True);c.finish(k,{'time':'new','errors':{'request':'timeout'}})
        self.assertEqual(c.results[k]['time'],'old')
        self.assertEqual(c.results[k]['refresh_time'],'new')
        self.assertEqual(c.results[k]['refresh_errors'],{'request':'timeout'})
        c.begin(k,True);c.finish(k,{'cleanip':{'ip':'8.8.8.8','score':70}})
        self.assertNotIn('ippure',c.results[k]) # never combine different attempts/IPs
        self.assertNotIn('refresh_errors',c.results[k])

    def test_cancel_before_start_does_not_select_node(self):
        p=Mock();owner=Mock();owner.isInterruptionRequested.return_value=True
        self.assertTrue(q.collect_quality(p,'A',owner)['cancelled'])
        p.select_probe_node.assert_not_called()

    def test_cancel_during_request_discards_partial_attempt_and_resets(self):
        p=Mock();p.proxies.return_value={'proxies':{'A':{'type':'SS'},q.PROBE_GROUP:{'type':'Selector','all':['A','REJECT']}}}
        p.configs.return_value={'mode':'rule'}
        owner=Mock();owner.isInterruptionRequested.return_value=False
        def fail(*args):
            owner.isInterruptionRequested.return_value=True
            raise OSError('closed')
        with patch.object(q,'proxy_get',side_effect=fail):r=q.collect_quality(p,'A',owner)
        self.assertTrue(r['cancelled'])
        self.assertEqual(p.select_probe_node.call_args.args,('REJECT',))

    def test_palette_reverses_risk_direction(self):
        for risk in (0,15,16,30,31,50,51,100):
            self.assertEqual(q.risk_color(risk),q.clean_color(100-risk))

    def test_own_connections_do_not_keep_takeover_on(self):
        base={'metadata':{'type':'HTTP','host':'chatgpt.com','sourcePort':61234},'chains':['A',q.PROBE_GROUP]}
        self.assertFalse(user_explicit_proxy(base))
        base['chains']=['A','AI'];register_health_probe_port(61234,'chatgpt.com')
        self.assertFalse(user_explicit_proxy(base))
        base['metadata'].update(sourcePort=61235,process='browser.exe')
        self.assertTrue(user_explicit_proxy(base))

    def test_netmonitor_exe_identity_excluded_but_real_application_allowed(self):
        c={'metadata':{'type':'Socks5','host':'chatgpt.com','process':'NetMonitor.exe'}}
        self.assertFalse(user_explicit_proxy(c))
        c['metadata']['process']='ChatGPT.exe'
        self.assertTrue(user_explicit_proxy(c))

if __name__=='__main__':unittest.main()
