import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import unknown_log as ul
import connection_labels as cl

class ReviewLogTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=str(Path(self.tmp.name)/'unknown.json')
        self.log=ul.UnknownTargetLog(self.path,legacy=[('chatgpt.com','ChatGPT')])
    def tearDown(self):
        self.tmp.cleanup()
    def row(self,**kw):
        r=dict(host='unknown.example.invalid',raw_host='unknown.example.invalid',
               proc='one.exe',pid=1,process_path='C:\\Apps\\one.exe',exit='Node-A',
               group='Proxy',rule='Match',kind='proxy',network='tcp',destination_port=443)
        r.update(kw)
        return r
    def read(self):
        return json.loads(Path(self.path).read_text(encoding='utf-8'))
    def test_failed_write_keeps_dirty_and_exit_retries(self):
        with patch.object(ul.os,'replace',side_effect=PermissionError('locked')):
            self.log.note([self.row()],'proxy')
        self.assertTrue(self.log.dirty)
        self.assertTrue(self.log.last_error)
        self.assertTrue(self.log.flush())
        self.assertEqual(len(self.read()),1)
    def test_failed_write_empty_poll_retries_after_interval(self):
        with patch.object(ul.os,'replace',side_effect=PermissionError('locked')):
            self.log.note([self.row()],'proxy')
        with patch.object(ul.time,'monotonic',return_value=self.log.last_attempt+61):
            self.log.note([],'system')
        self.assertFalse(self.log.dirty)
        self.assertEqual(len(self.read()),1)
    def test_anomaly_on_known_host_survives_cleanup_reload(self):
        r=self.row(host='chatgpt.com',raw_host='chatgpt.com',proc='bad\ufffd.exe')
        self.log.note([r],'proxy');self.log.note([],'proxy');self.log.flush()
        self.assertIn('proc',self.read()[0]['anomalies'])
        other=ul.UnknownTargetLog(self.path,legacy=[('chatgpt.com','ChatGPT')])
        self.assertEqual(len(other.items),1)
    def test_surrogate_does_not_break_json(self):
        self.log.note([self.row(proc='bad\ud800.exe')],'proxy')
        self.assertEqual(self.read()[0]['anomalies']['proc'],'bad\ud800.exe')
    def test_private_ip_anomaly_is_not_dropped(self):
        self.log.note([self.row(raw_host='192.168.1.2',proc='bad\x01.exe')],'system')
        self.assertEqual(len(self.read()),1)
    def test_system_missing_destination_anomaly(self):
        self.log.note([self.row(raw_host='',host='',proc='bad\ufffd.exe',kind='system',exit='')],'system')
        self.assertTrue(self.read()[0]['host'].startswith('process:'))
        self.assertEqual(self.read()[0]['exit'],'')
    def test_multi_owner_and_node_retained(self):
        self.log.note([self.row(),self.row(proc='two.exe',pid=2,exit='Node-B')],'proxy')
        records=self.read()
        self.assertEqual(records[0]['count'],1)
        self.assertEqual({c['exit'] for c in records[0]['contexts']},{'Node-A','Node-B'})
        self.assertEqual({c['pid'] for c in records[0]['contexts']},{1,2})
    def test_bounds(self):
        with patch.object(ul,'MAX_ENTRIES',3),patch.object(ul,'MAX_CONTEXTS',2):
            self.log.note([self.row(raw_host=f'h{i}.invalid') for i in range(5)],'proxy')
            self.assertEqual(len(self.log.items),3)
            self.log.note([self.row(pid=i) for i in range(4)],'proxy')
            record=self.log.items['unknown.example.invalid']
            self.assertEqual(len(record['contexts']),2)
            self.assertEqual(record['contexts_evicted'],2)
    def test_legacy_load_and_alias_cleanup(self):
        Path(self.path).write_text(json.dumps([{'host':'unknown.example.invalid','first':'2026-01-01','last':'2026-01-02','count':7}]),encoding='utf-8')
        other=ul.UnknownTargetLog(self.path)
        other.note([self.row()],'proxy');other.flush()
        self.assertEqual(self.read()[0]['count'],8)
        other.legacy=[('example.invalid','Known')]
        other.note([],'proxy');other.flush()
        self.assertEqual(self.read(),[])
    def test_known_brand_false_positive_remains_fixed(self):
        self.assertFalse(cl.needs_review({'host':'log5-applog-lq.fqnovel.com'}))
    def test_legacy_owner_context_is_preserved(self):
        Path(self.path).write_text(json.dumps([{'host':'unknown.example.invalid','proc':'old.exe','count':8}]),encoding='utf-8')
        other=ul.UnknownTargetLog(self.path)
        other.note([self.row(proc='new.exe')],'proxy');other.flush()
        self.assertEqual({c['proc'] for c in self.read()[0]['contexts']},{'old.exe','new.exe'})
    def test_throttle(self):
        self.log.note([self.row()],'proxy')
        self.log.note([self.row()],'proxy')
        self.assertEqual(self.read()[0]['count'],1)
        self.log.flush()
        self.assertEqual(self.read()[0]['count'],2)
    def test_system_collector_skips_plain_ip_before_top20(self):
        import app
        class Engine:
            _connections_snapshot=app.DataEngine._connections_snapshot
            proxy_listen=set()
            _proc_rates={}
            pid_paths={i:'C:\\Apps\\process.exe' for i in range(1,26)}
            PROXY_PROCS=[]
            SERVICE_HINTS=[]
            traffic=SimpleNamespace(accurate=False)
            unknown_log=self.log
            def _pid_name(self,pid): return f'p{pid}.exe'
        sockets=[SimpleNamespace(type=app.socket.SOCK_STREAM,pid=i,status='ESTABLISHED',laddr=SimpleNamespace(ip='192.168.1.1',port=1000+i),
                 raddr=SimpleNamespace(ip=f'8.8.9.{i}',port=443)) for i in range(1,26)]
        with patch.object(app.psutil,'net_connections',side_effect=lambda kind:sockets if kind=='inet' else []):
            rows=app.DataEngine._system_conns(Engine())
        self.assertEqual(len(rows),20)
        self.assertEqual(self.log.items,{})
        self.assertEqual(self.log.counts(),{'domain':0,'ip':0,'anomaly':0})

if __name__=='__main__': unittest.main()
