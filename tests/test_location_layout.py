import unittest
from ip_quality import location_display,parse_cleanip,parse_ippure
from connection_labels import service_name

class LocationTests(unittest.TestCase):
    def make(self,a,b):return {'ippure':{'ip':'1.1.1.1','location':a},'cleanip':{'ip':'1.1.1.1','location':b}}
    def test_taiwan_kept_as_region(self):
        text,tip=location_display(self.make({'country':'Taiwan','region':'Taiwan','city':'Taipei'},{'country':'中国台湾','parts':['台北市']}))
        self.assertEqual(text,'台湾 · 台北市')
        self.assertNotIn('分歧',text)
    def test_us_country_removed(self):
        text,_=location_display(self.make({'country':'United States','region':'California','city':'Los Angeles'},{'country':'美国','parts':['加利福尼亚州','洛杉矶']}))
        self.assertEqual(text,'加利福尼亚州 · 洛杉矶')
    def test_conflict_prefers_clean(self):
        text,_=location_display(self.make({'country':'Taiwan','region':'Taiwan','city':'Taipei'},{'country':'台湾','parts':['新北市']}))
        self.assertEqual(text,'台湾 · 新北市（分歧）')
    def test_missing_not_invented(self):
        self.assertEqual(location_display({})[0],'地区待确认')
        self.assertEqual(location_display({'cleanip':{'location':{'country':'美国','parts':['洛杉矶']}}})[0],'洛杉矶')
    def test_hk_region(self):
        self.assertEqual(location_display({'cleanip':{'location':{'country':'中国','parts':['香港','九龙']}}})[0],'香港 · 九龙')
    def test_different_ips(self):
        r=self.make({'city':'Tokyo'},{'parts':['东京']});r['cleanip']['ip']='8.8.8.8'
        self.assertEqual(location_display(r)[0],'出口不一致')
    def test_parser_location(self):
        a=parse_ippure('{"ip":"1.1.1.1","fraudScore":9,"country":"Taiwan","region":"Taiwan","city":"Taipei"}')
        self.assertEqual(a['location']['city'],'Taipei')
        b=parse_cleanip('IP 1.1.1.1 (IPv4)\n归属地 台湾 · 台北市\nCleanIP 评分 89/100 (A)\n风险评分 11/100\n风险标记 未检出\n')
        self.assertEqual(b['location']['parts'],['台北市'])
    def test_verified_aliases_boundary(self):
        for host in ('cleanip.io','static.cleanipcdn.com','a.tile.openstreetmap.org','doh.pub','platform.claude.com','pay-static.cdn-apple.com'):
            self.assertNotEqual(service_name(host),host)
        self.assertEqual(service_name('notcleanip.io'),'notcleanip.io')

if __name__=='__main__':unittest.main()
