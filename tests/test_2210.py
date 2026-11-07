import unittest,json,tempfile
from unittest.mock import Mock,patch
from pathlib import Path
from location_names import location_display,comparison
from report_selection import select_report
import ip_quality as q

class Fixes2210(unittest.TestCase):
    def test_regional_country_not_dropped_with_region_field(self):
        for country,region,want in [('台湾','台北市','台湾 · 台北市'),('Hong Kong','Kowloon','香港 · 九龙')]:
            self.assertEqual(location_display({'cleanip':{'location':{'country':country,'region':region,'city':''}}})[0],want)
    def test_ancestor_descendant_agree_any_depth(self):
        full={'country':'台湾','parts':['彰化县','员林市','某里','某路']}
        partial={'country':'Taiwan','parts':['员林市','某路']}
        self.assertEqual(comparison(full,partial),'same')
    def test_missing_middle_level_with_evidence(self):
        a={'country':'台湾','parts':['彰化县'],'alternatives':[{'country':'台湾','region':'彰化县','city':'员林市'}]}
        b={'country':'台湾','parts':['员林市']}
        r={'cleanip':{'location':a},'ippure':{'location':b}}
        self.assertEqual(location_display(r)[0],'台湾 · 彰化县')
    def test_unproven_hierarchy_not_a_false_conflict(self):
        a={'country':'台湾','region':'彰化县'};b={'country':'台湾','city':'员林市'}
        self.assertEqual(comparison(a,b),'incomplete')
        self.assertNotIn('分歧',location_display({'cleanip':{'location':a},'ippure':{'location':b}})[0])
    def test_actual_different_city_still_conflicts(self):
        a={'country':'台湾','region':'彰化县','city':'员林市'};b={'country':'台湾','region':'彰化县','city':'鹿港镇'}
        self.assertEqual(comparison(a,b),'different')
    def test_english_fallback_chinese_and_unknown_preserved(self):
        r={'ippure':{'location':{'country':'United States','region':'California','city':'Los Angeles'}}}
        self.assertEqual(location_display(r)[0],'加利福尼亚州 · 洛杉矶')
        r={'ippure':{'location':{'country':'Japan','region':'Tokyo','city':'Edogawa'}}}
        self.assertEqual(location_display(r)[0],'东京 · 江户川')
        r={'ippure':{'location':{'country':'Example','city':'UnlistedPlace'}}}
        text,tip=location_display(r);self.assertEqual(text,'UnlistedPlace');self.assertIn('保留原文',tip)
    def test_report_selects_requested_report_among_unrelated(self):
        flat=[{'ok':1,'ip':2,'risk':3},True,'1.1.1.1',{}, {'ok':1,'ip':5,'risk':3},'8.8.8.8']
        report,ref=select_report(flat,'8.8.8.8');self.assertEqual(ref(report['ip']),'8.8.8.8')
    def test_report_pending_is_distinct_from_wrong_ip(self):
        flat=[{'ok':1,'ip':2,'risk':3},False,'1.1.1.1',{}]
        with self.assertRaisesRegex(ValueError,'未就绪'):select_report(flat,'1.1.1.1')
        with self.assertRaisesRegex(ValueError,'未包含'):select_report(flat,'8.8.8.8')
    def test_route_confirmation_does_not_require_tls_or_get(self):
        conn=Mock();conn.sock.getsockname.return_value=('127.0.0.1',54321)
        route={'chains':['N','AI'],'metadata':{'host':'chatgpt.com'}}
        with patch.object(q.http.client,'HTTPConnection',return_value=conn),patch.object(q,'connection_for_port',return_value=route):
            body,actual=q.proxy_get(Mock(),'chatgpt.com','/cdn-cgi/trace',7897)
        self.assertEqual(actual,route);conn.request.assert_not_called();conn.close.assert_called_once()
        hello=conn.sock.sendall.call_args.args[0];self.assertEqual(hello[0],22);self.assertIn(b'chatgpt.com',hello)
        conn.sock.recv.assert_not_called()
