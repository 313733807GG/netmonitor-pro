import ctypes,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
import app
from location_names import comparison,location_display
from lookup_parsers import parse_ippure_page

class Continuation2210(unittest.TestCase):
    def test_window_match_rejects_explorer_and_accepts_hidden_legacy_qt(self):
        class User32:
            windows={1:('NetMonitor','CabinetWClass'),2:('NetMonitor notes','Qt6QWindowIcon'),3:('NetMonitor Pro v22','Qt663QWindowIcon')}
            def EnumWindows(self,callback,arg):
                for hwnd in self.windows:
                    if not callback(hwnd,arg):break
            def GetWindowTextW(self,hwnd,buf,size):buf.value=self.windows[hwnd][0]
            def GetClassNameW(self,hwnd,buf,size):buf.value=self.windows[hwnd][1]
        self.assertEqual(app.find_existing_netmonitor_window(User32()),3)
        User32.windows={1:('NetMonitor','CabinetWClass')}
        self.assertIsNone(app.find_existing_netmonitor_window(User32()))
        User32.windows={4:('NetMonitor','Qt663QWindowIcon')}
        self.assertEqual(app.find_existing_netmonitor_window(User32()),4)

    def test_real_tool_window_class_can_be_activated(self):
        class User32:
            def EnumWindows(self,callback,arg):callback(55,arg)
            def GetWindowTextW(self,hwnd,buf,size):buf.value='NetMonitor'
            def GetClassNameW(self,hwnd,buf,size):buf.value='Qt6112QWindowToolSaveBits'
        self.assertEqual(app.find_existing_netmonitor_window(User32()),55)

    def test_deep_siblings_not_hidden_by_common_city(self):
        for left,right in [('甲里','乙里'),('甲路','乙路'),('甲村','乙村')]:
            a={'country':'台湾','parts':['彰化县','员林市',left]}
            b={'country':'台湾','parts':['彰化县','员林市',right]}
            self.assertEqual(comparison(a,b),'different')

    def test_omitted_deep_level_requires_evidence(self):
        a={'country':'台湾','parts':['彰化县','员林市','甲里']}
        b={'country':'台湾','parts':['彰化县','员林市','甲路']}
        self.assertEqual(comparison(a,b),'incomplete')
        a['alternatives']=[{'country':'台湾','parts':['彰化县','员林市','甲里','甲路']}]
        self.assertEqual(comparison(a,b),'same')

    def test_failed_cleanip_keeps_chinese_and_single_source_notice(self):
        text,tip=location_display({'ippure':{'location':{'country':'United States','region':'California','city':'Los Angeles'}},'errors':{'cleanip':'TLS timeout'}})
        self.assertEqual(text,'加利福尼亚州 · 洛杉矶')
        self.assertIn('单来源',tip)

    def test_ippure_parser_preserves_arbitrary_depth(self):
        text='IP\n1.1.1.1\nIP来源\n原生IP\nIP属性\n住宅IP\nIPPure系数\n10% 低风险\nMaxMind\n台湾, 彰化县, 员林市, 甲里, 甲路'
        result=parse_ippure_page(text,'1.1.1.1')
        self.assertEqual(result['location']['parts'],['彰化县','员林市','甲里','甲路'])



if __name__=='__main__':unittest.main()
