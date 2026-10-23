import unittest,json,tempfile
from pathlib import Path
from unittest.mock import patch
import unknown_log as ul

class ReviewCategoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=str(Path(self.tmp.name)/'unknown.json');self.log=ul.UnknownTargetLog(self.path)
    def tearDown(self):self.tmp.cleanup()
    def row(self,host,**kw):return dict(host=host,proc='sample.exe',**kw)
    def test_ip_flood_cannot_evict_domain(self):
        with patch.object(ul,'MAX_ENTRIES',2),patch.object(ul,'MAX_IP_ENTRIES',3):
            self.log.note([self.row('first.invalid'),self.row('second.invalid')],'proxy')
            self.log.note([self.row(f'8.9.10.{i}') for i in range(1,12)],'system')
            self.assertEqual(self.log.counts(),{'domain':2,'ip':3,'anomaly':0})
            self.assertIn('first.invalid',self.log.items)
    def test_domain_flood_cannot_evict_ip(self):
        with patch.object(ul,'MAX_ENTRIES',2):
            self.log.note([self.row('8.9.10.11')],'system')
            self.log.note([self.row(f'n{i}.invalid') for i in range(8)],'proxy')
            self.assertEqual(self.log.counts(),{'domain':2,'ip':1,'anomaly':0})
    def test_anomalies_independent_including_ip(self):
        with patch.object(ul,'MAX_ANOMALY_ENTRIES',2),patch.object(ul,'MAX_IP_ENTRIES',1):
            self.log.note([{'host':'8.9.10.12','proc':'bad\ufffd.exe'},{'host':'x.invalid','proc':'bad\x01.exe'}],'system')
            self.log.note([self.row('8.9.10.13'),self.row('8.9.10.14')],'system')
            self.assertEqual(self.log.counts(),{'domain':0,'ip':1,'anomaly':2})
    def test_migrate_preserves_all_old_evidence(self):
        records=[{'host':'older.invalid','schema_version':2,'count':18,'first':'2020','last':'2021','contexts':[{'proc':'old.exe','count':5}]},
                 {'host':'2001:4860:4860::8889','schema_version':2,'count':19,'first':'2020','last':'2021'}]
        Path(self.path).write_text(json.dumps(records),encoding='utf-8')
        log=ul.UnknownTargetLog(self.path)
        self.assertTrue(log.dirty);self.assertEqual(log.counts(),{'domain':1,'ip':1,'anomaly':0})
        self.assertEqual(log.items['older.invalid']['contexts'],records[0]['contexts'])
        log.flush();again=ul.UnknownTargetLog(self.path)
        self.assertEqual(again.items['older.invalid']['count'],18)
        self.assertFalse(again.dirty)
    def test_anomaly_promotion_and_cleanup(self):
        self.log.note([self.row('one.invalid')],'proxy')
        self.log.note([{'host':'one.invalid','proc':'bad\ufffd.exe'}],'proxy')
        self.log.legacy=[('one.invalid','Known')];self.log.note([],'proxy')
        self.assertEqual(self.log.counts(),{'domain':0,'ip':0,'anomaly':1})
    def test_eviction_stays_within_pool_and_keeps_newest(self):
        self.log.items={h:{'host':h,'last':stamp,'count':1} for h,stamp in [('a.invalid','2020'),('b.invalid','2021'),('c.invalid','2022'),('8.9.10.10','2019')]}
        with patch.object(ul,'MAX_ENTRIES',2):self.log._prune()
        self.assertNotIn('a.invalid',self.log.items);self.assertIn('8.9.10.10',self.log.items)
    def test_ipv6_is_ip_not_domain(self):
        self.assertEqual(ul.review_category('2001:db8::1',{}),'ip')
        self.assertEqual(ul.review_category('process:unknown',{}),'anomaly')

if __name__=='__main__':unittest.main()
