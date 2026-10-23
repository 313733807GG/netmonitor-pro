import unittest
from ip_quality import parse_ippure, parse_cleanip, type_badges

class IPTypesTests(unittest.TestCase):
    def result(self,residential=True,broadcast=False,ip_type='住宅 IP',native_type='原生 IP'):
        return {'ippure':{'ip':'1.1.1.1','residential':residential,'broadcast':broadcast},'cleanip':{'ip':'1.1.1.1','ip_type':ip_type,'native_type':native_type}}
    def test_agreement_uses_cleanip(self):
        badges=type_badges(self.result())
        self.assertEqual([x[0] for x in badges],['原生 IP','住宅 IP'])
        self.assertTrue(all(x[3]=='CleanIP' for x in badges))
    def test_ippure_negative_owns_style(self):
        badges=type_badges(self.result(False,True))
        self.assertEqual([x[3] for x in badges],['IPPure','IPPure'])
        self.assertIn('广播',badges[0][0]);self.assertIn('非住宅',badges[1][0])
        self.assertTrue(all('分歧' in x[0] for x in badges))
    def test_both_negative_agreement_uses_cleanip(self):
        for kind in ('IDC','机房 IP','非住宅 IP'):
            badges=type_badges(self.result(False,True,kind,'广播 IP'))
            self.assertEqual([x[0] for x in badges],['广播 IP',kind])
            self.assertTrue(all(x[3]=='CleanIP' and x[1]=='negative' for x in badges))
    def test_dimensions_choose_sources_independently(self):
        badges=type_badges(self.result(True,True,'IDC','原生 IP'))
        self.assertEqual([x[3] for x in badges],['IPPure','CleanIP'])
        self.assertTrue(all('分歧' in x[0] for x in badges))
        badges=type_badges(self.result(False,False,'住宅 IP','广播 IP'))
        self.assertEqual([x[3] for x in badges],['CleanIP','IPPure'])
    def test_cleanip_negative_keeps_exact_type(self):
        badges=type_badges(self.result(ip_type='移动 IP',native_type='广播 IP'))
        self.assertEqual([x[3] for x in badges],['CleanIP','CleanIP'])
        self.assertTrue(badges[1][0].startswith('移动 IP'))
    def test_neither_classification_invented(self):
        badges=type_badges({})
        self.assertTrue(all(x[1]=='unknown' for x in badges))
        self.assertFalse(any('机房' in x[0] for x in badges))
    def test_single_source_not_claimed_corroborated(self):
        badges=type_badges({'cleanip':self.result()['cleanip']})
        self.assertIn('尚未获得两站',badges[0][2])
    def test_ip_mismatch_not_merged(self):
        r=self.result();r['cleanip']['ip']='8.8.8.8'
        self.assertEqual(type_badges(r)[0][0],'出口不一致')
    def test_unannounced_not_broadcast(self):
        r={'cleanip':{'native_type':'未通告','ip_type':'未知'}}
        self.assertEqual(type_badges(r)[0][:2],('未通告','unknown'))
    def test_boolean_fields_strict(self):
        r=parse_ippure('{"ip":"1.1.1.1","fraudScore":9,"isBroadcast":false,"isResidential":"false"}')
        self.assertIs(r['broadcast'],False);self.assertNotIn('residential',r)
    def test_original_cli_types_and_ansi(self):
        text='IP  1.1.1.1 (IPv4)\nIP 类型  \x1b[97m商业 IP\x1b[0m\n原生 / 广播  广播 IP\nCleanIP 评分 89/100 (A)\n风险评分 11/100\n风险标记 未检出\n'
        r=parse_cleanip(text)
        self.assertEqual(r['ip_type'],'商业 IP');self.assertEqual(r['native_type'],'广播 IP')
        r=parse_cleanip(text.replace('商业 IP','[商业 IP]').replace('广播 IP','[广播 IP]'))
        self.assertEqual(r['ip_type'],'商业 IP');self.assertEqual(r['native_type'],'广播 IP')

if __name__=='__main__':unittest.main()
