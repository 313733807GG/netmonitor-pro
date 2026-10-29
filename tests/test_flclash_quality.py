import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from unittest.mock import patch

import flclash_quality as fq
import ip_quality as iq


class FlClashQualityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'database.sqlite'
        self.now=int(time.time())-1
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('CREATE TABLE ip_qualities(ip TEXT PRIMARY KEY,quality TEXT NOT NULL,checked_at INTEGER NOT NULL)')

    def record(self,kind='residential',source='ipLocate',stamp=None,**flags):
        data=dict(ip='1.1.1.1',source=source,type=kind,isProxy=False,isVpn=False,isTor=False,isAbuser=False)
        data.update(flags)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('INSERT OR REPLACE INTO ip_qualities VALUES(?,?,?)',('1.1.1.1',json.dumps(data),self.now if stamp is None else stamp))
        return fq.read_quality('1.1.1.1',self.path,now=self.now)

    def result(self,kind='residential',residential=True,clean_type='住宅 IP',**flags):
        return {'ippure':{'ip':'1.1.1.1','score':9,'residential':residential,'broadcast':False},
                'cleanip':{'ip':'1.1.1.1','score':97,'risk':3,'flags':'未检出','ip_type':clean_type,'native_type':'原生 IP'},
                'flclash':self.record(kind,**flags)}

    def test_reader_matches_flclash_grade_and_type(self):
        for kind,level in (('residential','good'),('mobile','good'),('business','good'),('hosting','normal')):
            with self.subTest(kind=kind):
                r=self.record(kind)
                self.assertEqual((r['status'],r['level']),('ok',level))
        self.assertEqual(self.record(isProxy=True)['level'],'good')
        self.assertEqual(self.record(isTor=True)['level'],'risky')
        self.assertEqual(self.record(isAbuser=True)['level'],'risky')

    def test_lookup_is_read_only_and_never_creates_missing_database(self):
        self.record();before=hashlib.sha256(self.path.read_bytes()).hexdigest()
        fq.read_quality('1.1.1.1',self.path)
        self.assertEqual(before,hashlib.sha256(self.path.read_bytes()).hexdigest())
        absent=self.path.parent/'absent.sqlite'
        self.assertEqual(fq.read_quality('1.1.1.1',absent)['status'],'missing')
        self.assertFalse(absent.exists())

    def test_expired_future_and_other_ip_excluded(self):
        self.assertEqual(self.record(stamp=self.now-fq.MAX_AGE-1)['status'],'expired')
        self.assertEqual(self.record(stamp=self.now+1)['status'],'invalid')
        self.record()
        self.assertEqual(fq.read_quality('8.8.8.8',self.path)['status'],'missing')
        self.assertEqual(self.record(ip='8.8.8.8')['status'],'ip_mismatch')

    def test_malformed_boolean_and_json_fail_closed(self):
        self.assertEqual(self.record(isTor='false')['status'],'unavailable')
        self.assertEqual(self.record(kind='unknown')['status'],'unavailable')
        self.assertEqual(self.record(source='newUnverifiedSource')['status'],'unavailable')
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('UPDATE ip_qualities SET quality=?',('{bad',))
        self.assertEqual(fq.read_quality('1.1.1.1',self.path)['status'],'unavailable')

    def test_all_positive_uses_cleanip_and_keeps_native_two_source(self):
        badges=iq.type_badges(self.result())
        self.assertEqual([b[3] for b in badges],['CleanIP','CleanIP'])
        self.assertEqual(badges[1][0],'住宅 IP')
        self.assertIn('三方对住宅/非住宅结论一致',badges[1][2])
        self.assertIn('不提供原生/广播',badges[0][2])

    def test_flclash_only_negative_overrides_two_positive(self):
        for kind,label in (('hosting','机房 IP'),('business','商业 IP'),('mobile','移动网络 IP')):
            badge=iq.type_badges(self.result(kind))[1]
            self.assertEqual(badge[3],'FlClash')
            self.assertEqual(badge[0],label+' · 分歧')
            self.assertEqual(badge[1],'negative')

    def test_both_sites_negative_not_overridden_by_flclash_positive(self):
        badge=iq.type_badges(self.result(residential=False,clean_type='IDC'))[1]
        self.assertEqual((badge[3],badge[1]),('CleanIP','negative'))
        self.assertIn('分歧',badge[0])

    def test_all_negative_agreement_uses_cleanip(self):
        badge=iq.type_badges(self.result('hosting',False,'机房 IP'))[1]
        self.assertEqual(badge[0],'机房 IP')
        self.assertEqual(badge[3],'CleanIP')
        self.assertIn('三方对住宅/非住宅结论一致',badge[2])

    def test_different_negative_subtypes_are_marked(self):
        badge=iq.type_badges(self.result('business',False,'机房 IP'))[1]
        self.assertEqual((badge[0],badge[3]),('机房 IP · 分歧','CleanIP'))

    def test_ippure_negative_priority_preserved(self):
        badge=iq.type_badges(self.result(residential=False))[1]
        self.assertEqual(badge[3],'IPPure')
        self.assertIn('非住宅',badge[0])

    def test_inferred_residential_not_claimed_as_third_confirmation(self):
        r=self.result();r['flclash']=self.record(source='ipQuery')
        badge=iq.type_badges(r)[1]
        self.assertIn('不足三方',badge[2]);self.assertIn('推定',badge[2])
        r['ippure'].pop('residential');r['cleanip'].pop('ip_type')
        self.assertEqual(iq.type_badges(r)[1][1],'unknown')

    def test_other_or_expired_flclash_ip_never_changes_type(self):
        r=self.result('hosting');r['flclash']['ip']='8.8.8.8'
        self.assertEqual(iq.type_badges(r)[1][0],'住宅 IP')
        r=self.result('hosting');r['flclash']['checked_at']=self.now-fq.MAX_AGE-1
        self.assertEqual(iq.type_badges(r)[1][0],'住宅 IP')

    def test_two_site_ip_mismatch_blocks_merged_result(self):
        r=self.result();r['cleanip']['ip']='8.8.8.8'
        self.assertEqual(iq.type_badges(r)[0][0],'出口不一致')
        self.assertIsNone(fq.usable_record(r))

    def test_flclash_risk_added_without_altering_original_scores(self):
        r=self.result(isTor=True,isAbuser=True);before=json.dumps(r,sort_keys=True)
        label,tip=fq.risk_annotation(r)
        self.assertIn('Fl风险',label);self.assertIn('Tor',label)
        self.assertIn('CleanIP 风险标记：未检出',tip)
        self.assertEqual(before,json.dumps(r,sort_keys=True))

    def test_no_fake_grade_when_flclash_record_missing(self):
        r=self.result();r['flclash']={'status':'missing','message':'未检测'}
        label,tip=fq.risk_annotation(r)
        self.assertEqual(label,'未检出');self.assertIn('未检测',tip)
        self.assertNotIn('质量优',tip)

    def test_unknown_type_is_not_negative_evidence(self):
        for label in ('未知类型','Unknown type','未知 IP','N/A'):
            r=self.result(clean_type=label)
            badge=iq.type_badges(r)[1]
            self.assertEqual((badge[0],badge[1],badge[3]),('住宅 IP','positive','IPPure'))
            r.pop('flclash')
            self.assertEqual(iq.type_badges(r)[1][0],'住宅 IP')

    def test_cache_only_queried_for_confirmed_same_ip_on_supported_clients(self):
        class Pipe:
            client_id='flclash'
            def proxies(self):return {'proxies':{'N':{'type':'SS'},iq.PROBE_GROUP:{'type':'Selector','all':['N','REJECT']}}}
            def select_probe_node(self,node):return True
            def configs(self):return {'mode':'rule'}
        pure=b'{"ip":"1.1.1.1","fraudScore":9}'
        clean='IP 1.1.1.1 (IPv4)\nCleanIP 评分 97/100 (A+)\n风险评分 3/100\n风险标记 未检出\n'
        with patch('ip_quality.proxy_get',side_effect=[(pure,{}),(clean,{})]),patch('flclash_quality.read_quality',return_value=self.record()) as read:
            result=iq.collect_quality(Pipe(),'N')
            read.assert_called_once_with('1.1.1.1');self.assertEqual(result['flclash']['status'],'ok')
        with patch('ip_quality.proxy_get',side_effect=[(pure,{}),(clean.replace('1.1.1.1','8.8.8.8'),{})]),patch('flclash_quality.read_quality') as read:
            result=iq.collect_quality(Pipe(),'N');read.assert_not_called()
            self.assertEqual(result['flclash']['status'],'ip_mismatch')
        pipe=Pipe();pipe.client_id='verge'
        with patch('ip_quality.proxy_get',side_effect=[(pure,{}),(clean,{})]),patch('flclash_quality.read_quality',return_value=self.record()) as read:
            result=iq.collect_quality(pipe,'N');read.assert_called_once_with('1.1.1.1');self.assertEqual(result['flclash']['status'],'ok')
        pipe.client_id=''
        with patch('ip_quality.proxy_get',side_effect=[(pure,{}),(clean,{})]),patch('flclash_quality.read_quality') as read:
            result=iq.collect_quality(pipe,'N');read.assert_not_called();self.assertNotIn('flclash',result)

if __name__=='__main__':unittest.main()
