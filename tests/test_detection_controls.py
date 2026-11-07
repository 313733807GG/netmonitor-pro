import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtWidgets import QApplication, QPushButton

from app import NetMonitorWidget
from dropdown_controls import FixedLabelComboBox
from monitoring_state import proxy_switch_state


class DetectionControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_quality_button_busy_text_round_trip(self):
        quality = FixedLabelComboBox('IP质量')
        delay = QPushButton('测AI延迟')
        context = SimpleNamespace(
            _shutting_down=False, btn_ip_quality=quality, btn_delay=delay,
            probe_worker=None, quality_worker=None,
        )
        NetMonitorWidget._sync_detection_buttons(context)
        self.assertEqual(quality.text(), 'IP质量')
        self.assertTrue(quality.isEnabled())

        worker = Mock()
        worker.isRunning.return_value = True
        context.quality_worker = worker
        NetMonitorWidget._sync_detection_buttons(context)
        self.assertEqual(quality.text(), '检测中…')
        self.assertFalse(quality.isEnabled())

        worker.isRunning.return_value = False
        NetMonitorWidget._sync_detection_buttons(context)
        self.assertEqual(quality.text(), 'IP质量')
        self.assertTrue(quality.isEnabled())
        quality.close()
        delay.close()
    def test_verge_and_flclash_proxy_switches_are_checked_separately(self):
        base = {'sw_on': True, 'sp_on': True, 'tun_on': False,
                'takeover': True, 'proxy_running': True}
        self.assertTrue(proxy_switch_state(base | {'client_id': 'verge'})[0])
        off = base | {'sp_on': False, 'takeover': False}
        allowed, hint = proxy_switch_state(off | {'client_id': 'verge'})
        self.assertFalse(allowed)
        self.assertIn('Clash Verge', hint)

        stopped = base | {'client_id': 'flclash', 'proxy_running': False}
        allowed, hint = proxy_switch_state(stopped)
        self.assertFalse(allowed)
        self.assertIn('FlClash', hint)
        self.assertTrue(proxy_switch_state(base | {
            'client_id': 'flclash', 'sp_on': False, 'tun_on': True,
        })[0])
        self.assertFalse(proxy_switch_state(stopped | {'proxy_running': None})[0])

        for client in ('verge', 'flclash'):
            explicit_only = base | {'client_id': client, 'sp_on': False,
                                    'tun_on': False, 'takeover': True}
            self.assertFalse(proxy_switch_state(explicit_only)[0])
        self.assertFalse(proxy_switch_state({'sw_on': False})[0])

    def test_off_state_disables_only_manual_side_and_blocks_worker(self):
        quality = FixedLabelComboBox('IP质量')
        delay = QPushButton('测AI延迟')
        data = {'client_id': 'verge', 'sw_on': True, 'sp_on': False,
                'tun_on': False, 'takeover': False}
        context = SimpleNamespace(
            _shutting_down=False, btn_ip_quality=quality, btn_delay=delay,
            probe_worker=None, quality_worker=None, _last_data=data,
            _show_toast=Mock(), _start_quality=Mock(),
        )
        NetMonitorWidget._sync_detection_buttons(context)
        self.assertFalse(quality.manual_enabled)
        self.assertTrue(quality.isEnabled())
        self.assertIn('当前不可手动检测', quality.toolTip())
        NetMonitorWidget.on_ip_quality(context)
        context._start_quality.assert_not_called()
        self.assertIn('Clash Verge', context._show_toast.call_args.args[0])
        quality.close()
        delay.close()


if __name__ == '__main__':
    unittest.main()
