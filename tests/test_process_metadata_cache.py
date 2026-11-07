import unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
from app import DataEngine

class MetadataCacheTests(unittest.TestCase):
    def test_reuse_and_pid_recycling(self):
        e=DataEngine.__new__(DataEngine);e.last_port_scan=0;e.system_proxy=lambda:(False,'')
        proc=Mock();proc.create_time.return_value=10;proc.name.return_value='one.exe';proc.exe.return_value='C:/one.exe'
        con=SimpleNamespace(pid=123,laddr=SimpleNamespace(ip='127.0.0.1',port=7897),status='LISTEN')
        with patch('app.psutil.net_connections',return_value=[con]),patch('app.psutil.Process',return_value=proc):
            for now in (100,102):
                with patch('app.time.time',return_value=now):e._scan_ports()
            self.assertEqual(proc.exe.call_count,1)
            proc.create_time.return_value=20;proc.name.return_value='two.exe'
            with patch('app.time.time',return_value=104):e._scan_ports()
            self.assertEqual(e.pid_names[123],'two.exe');self.assertEqual(proc.exe.call_count,2)
            with patch('app.time.time',return_value=166):e._scan_ports()
            self.assertEqual(proc.exe.call_count,3)

    def test_unreadable_creation_time_still_gets_name(self):
        e=DataEngine.__new__(DataEngine);e.last_port_scan=0;e.system_proxy=lambda:(False,'')
        proc=Mock();proc.create_time.side_effect=OSError();proc.name.return_value='visible.exe';proc.exe.return_value='C:/visible.exe'
        con=SimpleNamespace(pid=123,laddr=SimpleNamespace(ip='127.0.0.1',port=7897),status='LISTEN')
        with patch('app.psutil.net_connections',return_value=[con]),patch('app.psutil.Process',return_value=proc):e._scan_ports()
        self.assertEqual(e.pid_names[123],'visible.exe');self.assertFalse(e._metadata_cache)
