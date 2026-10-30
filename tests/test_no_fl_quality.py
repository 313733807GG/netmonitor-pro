import unittest,sqlite3
from unittest.mock import patch
import ip_quality as iq

class NoFlQualityTests(unittest.TestCase):
    def test_collect_quality_does_not_read_local_database(self):
        class Pipe:
            client_id='flclash'
            def proxies(self):return {'proxies':{'N':{'type':'SS'},iq.PROBE_GROUP:{'type':'Selector','all':['N','REJECT']}}}
            def select_probe_node(self,node):return True
            def configs(self):return {'mode':'rule'}
        pure=b'{"ip":"1.1.1.1","fraudScore":9}'
        clean='IP 1.1.1.1 (IPv4)\nCleanIP 评分 97/100 (A+)\n风险评分 3/100\n风险标记 未检出\n'
        with patch.object(iq,'proxy_get',side_effect=[(pure,{}),(clean,{}),(b'<html/>',{})]),patch.object(sqlite3,'connect',side_effect=AssertionError('Unexpected DB read')) as db:
            result=iq.collect_quality(Pipe(),'N')
            self.assertIn('cleanip',result);self.assertNotIn('flclash',result);db.assert_not_called()

    def test_old_third_source_cannot_affect_type_labels(self):
        r={'ippure':{'residential':True,'broadcast':False},'cleanip':{'ip_type':'住宅 IP','native_type':'原生 IP'}}
        before=iq.type_badges(r)
        r['flclash']={'status':'ok','type':'hosting','ip_type':'机房 IP','level':'risky','flags':['Tor']}
        self.assertEqual(before,iq.type_badges(r))
