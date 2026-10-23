import unittest
from unittest.mock import patch
from diagnostics import display_text
from monitoring_state import latency_style, probe_selection, route_evidence, mode_label
from pipe_client import MihomoPipe
from app import proxy_health_key, connection_color, BLUE, GREEN, RED, YELLOW, format_node_status


class StateTests(unittest.TestCase):
    def setUp(self):
        self.pipe = MihomoPipe()
        self.snapshot = {'proxies': {
            'GLOBAL':{'type':'Selector','now':'全局节点'},
            'AI服务':{'type':'Selector','now':'AI节点'},
            '全局节点':{'type':'Shadowsocks'}, 'AI节点':{'type':'AnyTLS'},
        }}

    def test_mode_target_matrix(self):
        for system_proxy in (False,True):
            for tun in (False,True):
                for mode in ('rule','global','direct'):
                    with self.subTest(sp=system_proxy,tun=tun,mode=mode):
                        selection = probe_selection(self.pipe,self.snapshot,mode)
                        expected = {'rule':'AI节点','global':'全局节点','direct':None}[mode]
                        self.assertEqual(selection[1] if selection else None,expected)
                        data = {'mode':mode,'sw_on':True,'takeover':system_proxy or tun,'api_on':True,
                                'sp_on':system_proxy,'tun_on':tun,'api_generation':1,
                                'ai_group':selection[0] if selection else '',
                                'ai_node':selection[1] if selection else ''}
                        self.assertEqual(bool(proxy_health_key(data)),bool(expected and (system_proxy or tun)))
                        self.assertIn('TUN '+('开' if tun else '关')+' · ',mode_label(data))

    def test_global_direct_and_balance_never_use_ai_group(self):
        for name,item in [('DIRECT',{'type':'Direct'}),('均衡',{'type':'LoadBalance','now':'全局节点'})]:
            self.snapshot['proxies']['GLOBAL']['now']=name
            self.snapshot['proxies'][name]=item
            self.assertEqual(probe_selection(self.pipe,self.snapshot,'global')[1],'')

    def test_unknown_mode_is_not_a_guessed_ai_selection(self):
        self.assertIsNone(probe_selection(self.pipe,self.snapshot,'?'))

    def test_empty_chains_are_unknown_blue(self):
        for chains in ([],None,'DIRECT'):
            category,node,group=route_evidence(chains,self.snapshot)
            self.assertEqual((category,node,group),('system','',''))
            self.assertEqual(connection_color({'kind':category}),BLUE)

    def test_alias_direct_and_reject_follow_types_not_names(self):
        self.snapshot['proxies'].update({'国内':{'type':'Direct'},'广告':{'type':'Reject'}})
        for name,kind,color in [('国内','direct',GREEN),('广告','reject',RED),('AI节点','proxy',YELLOW)]:
            category,_,_=route_evidence([name,'AI服务'],self.snapshot)
            self.assertEqual(category,kind)
            self.assertEqual(connection_color({'kind':category}),color)

    def test_unresolved_group_is_not_paid_proxy(self):
        self.assertEqual(route_evidence(['AI服务'],self.snapshot)[0],'system')
        self.assertEqual(route_evidence(['PASS'],self.snapshot)[0],'system')

    def test_latency_thresholds_and_failure(self):
        for ms,color in [(0,GREEN),(200,GREEN),(201,YELLOW),(500,YELLOW),(501,RED)]:
            self.assertEqual(latency_style(True,ms),(f'{ms} ms',color))
        self.assertEqual(latency_style(False,0),('超时/失败',RED))
        self.assertEqual(latency_style(None,0)[0],'— ms')

    def test_target_and_core_generation_invalidate_results(self):
        data={'sw_on':True,'takeover':True,'api_on':True,'mode':'rule','ai_group':'AI','ai_node':'A','api_generation':1}
        self.assertNotEqual(proxy_health_key(data),proxy_health_key(dict(data,api_generation=2)))
        self.assertNotEqual(proxy_health_key(data),proxy_health_key(dict(data,ai_node='B')))

    def test_current_selection_does_not_claim_observed_until_evidence(self):
        data={'target_unified':True,'mode':'rule','ai_group':'AI服务','ai_node':'AI节点',
              'proxy_routes':[('国外网站','旧节点',4)]}
        label,node=format_node_status(data)
        self.assertEqual(node,'AI节点'); self.assertIn('当前选择',label); self.assertIn('另1个出口',label)
        data['proxy_routes'].append(('AI服务','AI节点',1))
        self.assertIn('已观测出口',format_node_status(data)[0])

    def test_chinese_and_emoji_are_preserved(self):
        self.assertEqual(display_text('哔哩哔哩.exe 🚀 节点'), '哔哩哔哩.exe 🚀 节点')

    def test_control_characters_are_logged_and_displayed_safely(self):
        with self.assertLogs('netmonitor',level='WARNING'):
            result=display_text('app\x00\ud800\u202e.exe')
        self.assertNotIn('\x00',result); self.assertNotIn('\ud800',result); self.assertNotIn('\u202e',result)

