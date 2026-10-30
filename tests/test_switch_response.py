import unittest,socket,threading,time
from types import SimpleNamespace
from unittest.mock import Mock,patch
from app import NetMonitorWidget,CancelableNetworkWorker
from controller_transport import ControllerTransport

class SwitchResponseTests(unittest.TestCase):
    def context(self):
        workers=[Mock() for _ in range(3)]
        for w in workers:w.isRunning.return_value=True
        return SimpleNamespace(engine=SimpleNamespace(pipe=SimpleNamespace(ai_route_hint={'old':True})),probe_retry_timer=Mock(),probe_state=True,probe_worker=workers[0],quality_worker=workers[1],route_worker=workers[2]),workers
    def test_transition_cancels_old_work_and_resets_cooldown(self):
        c,workers=self.context()
        d=dict(profile_id='p',api_generation=1,mode='rule',ai_target_state='waiting',ai_node='',ai_group='')
        with patch('app.time.monotonic',return_value=10):NetMonitorWidget._prepare_target_transition(c,d)
        self.assertEqual(c._route_retry_at,10.25);self.assertIsNone(c.probe_state)
        for w in workers:w.cancel.assert_called_once()
        NetMonitorWidget._prepare_target_transition(c,dict(d,sel_node='unrelated'))
        for w in workers:w.cancel.assert_called_once()
    def test_stale_route_completion_is_ignored(self):
        c,_=self.context();c._route_epoch=2;c._shutting_down=False
        NetMonitorWidget._route_done(c,{'route':{'old':True}},'rule','p',1)
        self.assertEqual(c.engine.pipe.ai_route_hint,{'old':True})
    def test_tcp_controller_wait_can_be_cancelled(self):
        server=socket.socket();server.bind(('127.0.0.1',0));server.listen();self.addCleanup(server.close)
        ready=threading.Event();release=threading.Event()
        def accept():
            conn,_=server.accept()
            with conn:conn.recv(4096);ready.set();release.wait(3)
        thread=threading.Thread(target=accept);thread.start()
        owner=CancelableNetworkWorker();transport=ControllerTransport();errors=[]
        def request():
            try:transport._exchange(('tcp',server.getsockname()[1],''),'/proxies/N/delay?timeout=8000',9,owner=owner)
            except OSError:errors.append(True)
        request_thread=threading.Thread(target=request);request_thread.start()
        try:
            self.assertTrue(ready.wait(2));started=time.monotonic();owner.cancel();request_thread.join(1)
            self.assertFalse(request_thread.is_alive());self.assertTrue(errors);self.assertLess(time.monotonic()-started,1)
        finally:release.set();thread.join(3);request_thread.join(3)
