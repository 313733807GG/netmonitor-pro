import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import proxy_clients as clients
from controller_transport import config_endpoints, PIPE_PREFIX
from pipe_client import MihomoPipe
from ip_quality import profile_id, quality_key
from monitoring_state import strict_route_state


class FlClashTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fl = self.root / clients.FLCLASH_DIR
        self.fl.mkdir(parents=True)
        self.verge = self.root / clients.VERGE_DIR
        self.verge.mkdir()
        self.env = patch.dict('os.environ', APPDATA=str(self.root))
        self.env.start()
        self.processes = patch('proxy_clients.running_clients', return_value={'flclash'})
        self.processes.start()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.env.stop)
        self.addCleanup(self.processes.stop)

    def prefs(self, controller='127.0.0.1:9090', secret='fl-secret', profile=1001, nested_string=True):
        config = {'currentProfileId':profile,'patchClashConfig':{'external-controller':controller,'secret':secret}}
        outer = {'flutter.config':json.dumps(config) if nested_string else config}
        (self.fl/'shared_preferences.json').write_text(json.dumps(outer),encoding='utf-8-sig')

    def test_flclash_preferences_bom_and_generated_auth(self):
        self.prefs()
        self.assertEqual(config_endpoints(), [('tcp',9090,'fl-secret')])
        self.assertEqual(clients.client_for_channel(('tcp',9090,'fl-secret')), 'flclash')

    def test_nested_object_is_supported(self):
        self.prefs(nested_string=False)
        self.assertEqual(config_endpoints(), [('tcp',9090,'fl-secret')])

    def test_live_preference_wins_over_stale_runtime_file(self):
        (self.fl/'config.json').write_text(json.dumps({'external-controller':'127.0.0.1:9999','secret':'stale'}))
        (self.fl/'config.yaml').write_text('external-controller: 127.0.0.1:9998\nsecret: stale\n')
        self.prefs(secret='rotated')
        self.assertEqual(config_endpoints(), [('tcp',9090,'rotated')])
        self.prefs(controller='')
        self.assertEqual(config_endpoints(), [])

    def test_runtime_json_fallback_without_preferences(self):
        (self.fl/'config.json').write_text(json.dumps({'external-controller':'127.0.0.1:9090','secret':'fallback'}))
        self.assertEqual(config_endpoints(), [('tcp',9090,'fallback')])

    def test_remote_addresses_and_injected_auth_rejected(self):
        for address in ('example.org:9090','192.168.1.2:9090','127.0.0.1:0','127.0.0.1:65536',None,9090):
            self.prefs(controller=address)
            self.assertEqual(config_endpoints(), [])
        for secret in ('bad\r\nHeader: yes','bad\x00value',True,None):
            self.prefs(secret=secret)
            self.assertEqual(config_endpoints(), [])

    def test_flclash_priority_when_only_flclash_is_running(self):
        self.prefs()
        (self.verge/'clash-verge.yaml').write_text("external-controller-pipe: '"+PIPE_PREFIX+"verge-mihomo-x'\nsecret: verge-auth\n")
        self.assertEqual(config_endpoints()[0], ('tcp',9090,'fl-secret'))
        with patch('proxy_clients.running_clients',return_value={'verge'}):
            self.assertEqual(config_endpoints()[0][0], 'pipe')

    def test_profile_namespace_and_subscription_changes(self):
        channel = ('tcp',9090,'fl-secret')
        self.prefs(profile=1001)
        (self.verge/'profiles.yaml').write_text('current: "1001"\n')
        a=profile_id(channel)
        b=profile_id(('pipe',PIPE_PREFIX+'verge-mihomo-test','verge-secret'))
        self.assertEqual(a,'flclash:1001')
        self.assertEqual(b,'verge:1001')
        data=dict(api_on=True,sp_on=True,tun_on=False,mode='rule',ai_target_state='confirmed',ai_node='same-node')
        self.assertNotEqual(quality_key(dict(data,profile_id=a)),quality_key(dict(data,profile_id=b)))
        self.prefs(profile=1002)
        self.assertNotEqual(profile_id(channel),a)

    def test_unknown_client_does_not_use_verge_profile_or_secret(self):
        (self.verge/'profiles.yaml').write_text('current: private-subscription\n')
        result=profile_id(('tcp',9998,'secret-not-for-cache'))
        self.assertNotIn('private-subscription',result)
        self.assertNotIn('secret-not-for-cache',result)
        self.assertEqual(profile_id(), 'offline')

    def test_invalid_preferences_and_profile_id_fail_closed(self):
        for text in ('{bad','[]',json.dumps({'flutter.config':'bad'})):
            (self.fl/'shared_preferences.json').write_text(text)
            self.assertEqual(clients.flclash_settings(),{})
        for value in (None,True,{},'../../profiles',1.5):
            self.prefs(profile=value)
            self.assertEqual(profile_id(('tcp',9090,'fl-secret')),'flclash:unknown')

    def test_core_is_not_gui_and_other_clients_do_not_light_gui(self):
        self.assertFalse(clients.gui_process_matches('FlClashCore.exe'))
        self.assertFalse(clients.gui_process_matches('FlClashHelperService.exe'))
        self.assertFalse(clients.gui_process_matches('FlClash.exe','verge'))
        self.assertFalse(clients.gui_process_matches('clash-verge.exe','flclash'))
        self.assertTrue(clients.gui_process_matches('FlClash.exe','flclash'))
        self.assertTrue(clients.gui_process_matches('clash-verge.exe','verge'))

    def test_service_alone_does_not_change_client_priority(self):
        # Unpatch this one helper to exercise actual name classification.
        self.processes.stop()
        names=('clash-verge-service.exe','FlClashHelperService.exe','FlClashCore.exe')
        with patch('proxy_clients.psutil.process_iter',return_value=[SimpleNamespace(info={'name':n}) for n in names]):
            self.assertEqual(clients.running_clients(),{'flclash'})
        self.processes.start()

    def test_live_discovery_uses_flclash_auth_not_native_ipc(self):
        self.prefs()
        pipe=MihomoPipe();called=[]
        def exchange(channel,path,timeout):
            called.append(channel)
            if channel==('tcp',9090,'fl-secret'):
                return 200,b'{"meta":true,"version":"v1.19.33"}'
            raise OSError('not present')
        with patch('controller_transport.os.listdir',return_value=['FlClashCore_random']),patch.object(pipe,'_exchange',side_effect=exchange):
            self.assertTrue(pipe._detect())
        self.assertEqual(pipe.client_id,'flclash')
        self.assertTrue(all('FlClashCore_' not in str(c[1]) for c in called))

    def test_flclash_auth_never_sent_to_verge_dynamic_pipe(self):
        self.prefs()
        pipe=MihomoPipe();called=[]
        def exchange(channel,path,timeout):
            called.append(channel)
            raise OSError('offline')
        with patch('controller_transport.os.listdir',return_value=['verge-mihomo-production-test']),patch.object(pipe,'_exchange',side_effect=exchange):
            self.assertFalse(pipe._detect())
        self.assertFalse(any(c[0]=='pipe' and c[2]=='fl-secret' for c in called))

    def test_probe_cleanup_remains_bound_to_original_client(self):
        pipe=MihomoPipe();pipe._chan=('tcp',9090,'old-secret');pipe.client_id='flclash'
        bound=pipe.fixed_session()
        pipe._chan=('pipe',PIPE_PREFIX+'verge-mihomo-new','new-secret');pipe.client_id='verge'
        calls=[]
        def exchange(channel,path,timeout,method='GET',payload=None):
            calls.append((channel,method,payload))
            if method=='GET':return 200,b'{"proxies":{"NetMonitor-IP-Check":{"type":"Selector","all":["REJECT"]}}}'
            return 204,b''
        with patch.object(bound,'_exchange',side_effect=exchange):
            self.assertTrue(bound.select_probe_node('REJECT'))
        self.assertTrue(all(c[0]==('tcp',9090,'old-secret') for c in calls))
        self.assertEqual(calls[-1][2],{'name':'REJECT'})
        self.assertEqual(pipe.client_id,'verge')

    def test_verge_tcp_auth_still_works_on_its_dynamic_service_pipe(self):
        self.prefs()
        (self.verge/'clash-verge.yaml').write_text('external-controller: 127.0.0.1:9097\nsecret: verge-secret\n')
        pipe=MihomoPipe()
        expected=('pipe',PIPE_PREFIX+'verge-mihomo-production-check','verge-secret')
        def exchange(channel,path,timeout):
            if channel==expected:return 200,b'{"version":"v1.19.32"}'
            raise OSError('offline')
        with patch('controller_transport.os.listdir',return_value=['verge-mihomo-production-check']),patch.object(pipe,'_exchange',side_effect=exchange):
            self.assertTrue(pipe._detect())
        self.assertEqual(pipe._chan,expected)

    def test_flclash_tun_schema_and_all_modes(self):
        for mode in ('rule','global','direct'):
            for enabled in (True,False):
                cfg={'mode':mode,'tun':{'enable':enabled,'stack':'Mixed','auto-route':True}}
                self.assertIs(strict_route_state(cfg),False)
                cfg['tun']['strict-route']=True
                self.assertIs(strict_route_state(cfg),True)
        self.assertIsNone(strict_route_state({},False))

if __name__=='__main__':
    unittest.main()
