import unittest,time
from types import SimpleNamespace as NS
from unittest.mock import Mock,patch
from proxy_runtime import flclash_runtime
import app
from ip_quality import quality_key

class FlClashRuntimeTests(unittest.TestCase):
    def test_stop_ignores_stale_tun_and_auxiliary_listener(self):
        cfg={'mixed-port':0,'port':0,'tun':{'enable':True,'device':'FlClash'},'listeners':[{'port':17893}]}
        r=flclash_runtime(cfg,{'AnotherVPN':NS(isup=True)})
        self.assertIs(r['proxy_running'],False);self.assertIs(r['tun_active'],False)
    def test_modes_tun_only_mixed_only_both(self):
        for mode in ('rule','global','direct'):
            for port,tun in ((7897,False),(0,True),(7897,True)):
                cfg={'mode':mode,'mixed-port':port,'tun':{'enable':tun,'device':'CustomTun'}}
                r=flclash_runtime(cfg,{'CustomTun':NS(isup=tun)})
                self.assertIs(r['proxy_running'],True);self.assertEqual(r['tun_active'],tun)
    def test_interface_read_failure_does_not_claim_stopped(self):
        r=flclash_runtime({'mixed-port':0,'tun':{'enable':True}},None)
        self.assertIsNone(r['proxy_running']);self.assertTrue(r['runtime_uncertain'])
    def test_invalid_ports_do_not_count_as_running(self):
        for port in ('7897',True,-1,65536,None):
            self.assertIsNone(flclash_runtime({'mixed-port':port}, {})['proxy_running'])
    def test_explicit_old_connection_cannot_override_stop(self):
        e=app.DataEngine.__new__(app.DataEngine)
        e.last_time=time.time();e.last_net=NS(bytes_sent=0,bytes_recv=0)
        e._scan_ports=lambda:None;e.traffic=Mock(status='running',accurate=True,elevated=True,event_count=1)
        e.history=Mock(status='running',last_error='',db_path='test',dropped_batches=0)
        e.system_proxy=lambda:(True,'127.0.0.1:7897');e._detect_sw=lambda *a:'FlClash';e.gui_alive=lambda:True
        e._system_conns=Mock(return_value=[{'name':'system-row'}]);e.pipe=Mock(client_id='flclash',generation=1,version='test',last_error='',channel_name='local',_chan=None)
        e.pipe.configs.return_value={'mode':'rule','mixed-port':0,'tun':{'enable':True,'device':'FlClash'}}
        e.pipe.proxies.return_value={'proxies':{}};e.pipe.active_groups.return_value=[]
        e.pipe.main_selection.return_value=None;e.pipe.global_selection.return_value=''
        e.pipe.connections.return_value={'connections':[{'metadata':{'host':'old'}}]}
        with patch.object(app.psutil,'net_io_counters',return_value=e.last_net),patch.object(app.psutil,'net_if_stats',return_value={}),patch.object(app,'probe_selection',return_value=None),patch.object(app,'user_explicit_proxy',return_value=True),patch.object(app,'profile_id',return_value='flclash:test'):
            d=e.tick()
        self.assertFalse(d['takeover']);self.assertFalse(d['tun_on']);self.assertTrue(d['api_on'])
        self.assertFalse(d['proxy_running']);self.assertEqual(d['list_mode'],'sys')
        self.assertEqual(d['conns'],[{'name':'system-row'}]);self.assertEqual(d['ai_node'],'')
        self.assertFalse(quality_key(d));self.assertFalse(app.effective_proxy_takeover(d))
        e.history.submit.assert_not_called()
