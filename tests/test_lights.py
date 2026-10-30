import unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
from app import NetMonitorWidget
from ip_quality import QualityCache,quality_key

class LightTests(unittest.TestCase):
    def test_lights_share_clock_after_hidden_or_off_period(self):
        lights=[SimpleNamespace(state=s,phase=i,isVisible=lambda:True,update=Mock()) for i,s in enumerate(('ok','off','bad','warn','ok'))]
        c=SimpleNamespace(isVisible=lambda:True,**dict(zip(('light_sw','light_take','light_node','mini_v_light','mini_h_light'),lights)))
        with patch('app.time.monotonic',return_value=100):NetMonitorWidget._animate(c)
        self.assertEqual(len({x.phase for x in lights}),1)
        lights[1].update.assert_not_called()
