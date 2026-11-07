import json,socket,socketserver,threading,time,unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
from pipe_client import MihomoPipe
from app import NetMonitorWidget
import ip_quality as q


class LookupAndRouteTests(unittest.TestCase):
 def test_route_poll_covers_delayed_actual_connection(self):
  pipe=Mock();pipe.connections.side_effect=[{'connections':[]}]*4+[{'connections':[{'metadata':{'sourcePort':'1234'},'chains':['N','AI']}]}]
  with patch('ip_quality.time.sleep'):
   result=q.connection_for_port(pipe,1234,attempts=10)
  self.assertEqual(result['chains'],['N','AI'])
 def test_initial_route_retry_is_bounded_and_short(self):
  c=SimpleNamespace(_route_retry_at=0,route_worker=None,engine=SimpleNamespace(pipe=Mock()),_start_quality=Mock(),_render_quality=Mock())
  worker=Mock();worker.isRunning.return_value=False
  data={'api_on':True,'tun_on':True,'mode':'rule','ai_target_state':'waiting','main_proxy_port':7897,'profile_id':'p','ai_candidate_node':'N'}
  with patch('app.time.monotonic',return_value=10),patch('app.IPQualityWorker',return_value=worker):
   NetMonitorWidget._refresh_quality(c,data)
  self.assertEqual(c._route_retry_at,11);self.assertEqual(c._route_attempt,1)

class ControllerTransientTests(unittest.TestCase):
 def test_one_local_io_error_does_not_reset_healthy_controller(self):
  pipe=MihomoPipe();pipe._chan=('pipe','fake','s')
  with patch.object(pipe,'_exchange',side_effect=[OSError('busy'),(200,b'{"mode":"rule"}')]) as exchange,patch('controller_transport.time.sleep'):
   self.assertEqual(pipe.configs(),{'mode':'rule'});self.assertEqual(exchange.call_count,2)
  self.assertIsNotNone(pipe._chan)
 def test_persistent_failure_still_disconnects(self):
  pipe=MihomoPipe();pipe._chan=('pipe','fake','s')
  with patch.object(pipe,'_exchange',side_effect=OSError('gone')) as exchange,patch('controller_transport.time.sleep'):
   self.assertEqual(pipe.configs(),{});self.assertEqual(exchange.call_count,2)
  self.assertIsNone(pipe._chan)

if __name__=='__main__':unittest.main()
