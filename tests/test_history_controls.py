import os
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication, QPushButton
from PySide6.QtGui import QAction

from app import NetMonitorWidget
from title_controls import CLOSE_BUTTON_CSS, PIN_BUTTON_CSS, history_button_css, title_icon
from traffic_history import TrafficHistoryStore


class HistoryControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def isolated_widget(self, saved_pause=None):
        """Build the real GUI with isolated QSettings, database and no ETW."""
        unique = f"{os.getpid()}-{time.time_ns()}"
        ini_path = os.path.abspath(f"test-history-settings-{unique}.ini")
        db_path = os.path.abspath(f"test-history-settings-{unique}.sqlite3")
        settings = QSettings(ini_path, QSettings.IniFormat)
        if saved_pause is not None:
            settings.setValue('history_paused', saved_pause)
        history = TrafficHistoryStore(db_path)
        self.assertTrue(history.running, history.last_error)
        engine = SimpleNamespace(
            history=history,
            traffic=SimpleNamespace(accurate=False),
        )
        sampler = Mock()

        def create_sampler(actual_engine):
            self.assertIs(actual_engine, engine)
            # EngineSampler must not start before the saved/default state applies.
            self.assertEqual(history.paused, saved_pause is not False)
            return sampler

        with patch('app.DataEngine', return_value=engine) as engine_factory, \
                patch.dict(os.environ, {'NETMONITOR_SETTINGS_INI': ini_path}), \
                patch('app.EngineSampler', side_effect=create_sampler), \
                patch('app.QTimer.singleShot', return_value=None), \
                patch.object(NetMonitorWidget, '_autostart_get', return_value=False):
            widget = NetMonitorWidget(capture=False)
        engine_factory.assert_called_once_with(capture=False)

        def cleanup():
            for name in ('timer', 'anim', 'probe_timer', 'probe_retry_timer', 'toast_timer'):
                getattr(widget, name).stop()
            widget.tray.hide()
            widget.hide()
            try:
                QApplication.instance().aboutToQuit.disconnect(widget._shutdown)
            except (TypeError, RuntimeError):
                pass
            history.close()
            settings.sync()
            for path in (ini_path, db_path, db_path + '-shm', db_path + '-wal'):
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
            widget.deleteLater()

        self.addCleanup(cleanup)
        return widget, history, settings

    def test_first_run_pauses_before_sampling_and_shows_paused(self):
        widget, history, settings = self.isolated_widget()
        self.assertTrue(history.paused)
        self.assertEqual(widget.btn_history_pause.text(), '● 已暂停')
        self.assertEqual(widget.act_history_pause.text(), '恢复流量入账')
        self.assertFalse(settings.contains('history_paused'))
        self.assertFalse(history.record([{'upload_bytes': 1}]))
        self.assertTrue(history.flush())

    def test_explicit_resume_choice_is_preserved(self):
        widget, history, settings = self.isolated_widget(saved_pause=False)
        self.assertFalse(history.paused)
        self.assertEqual(widget.btn_history_pause.text(), '● 入账中')
        self.assertEqual(widget.act_history_pause.text(), '暂停流量入账')
        self.assertFalse(settings.value('history_paused', True, type=bool))

    def context(self, paused=False):
        history = SimpleNamespace(
            paused=paused, running=True, status='running', last_error='',
            db_path='test.sqlite3', dropped_batches=0,
        )
        history.pause = Mock(side_effect=lambda: setattr(history, 'paused', True) or True)
        history.resume = Mock(side_effect=lambda: setattr(history, 'paused', False) or True)
        context = SimpleNamespace(
            engine=SimpleNamespace(history=history),
            btn_history_pause=QPushButton(),
            act_history_pause=QAction('暂停流量入账'),
            act_history_status=QAction('流量账本'),
            act_history_export_24h=QAction('导出24小时'),
            act_history_export_year=QAction('导出1年'),
            history_export_worker=None,
            settings=Mock(),
            _show_toast=Mock(),
        )
        return context

    def test_c_capsule_and_tray_tooltip_follow_state(self):
        context = self.context()
        NetMonitorWidget._update_history_control(context)
        self.assertEqual(context.btn_history_pause.text(), '● 入账中')
        self.assertEqual(context.act_history_pause.text(), '暂停流量入账')
        self.assertIn('点击暂停流量入账', context.act_history_pause.toolTip())
        self.assertEqual(context.act_history_pause.toolTip(), context.act_history_pause.statusTip())

        context.engine.history.paused = True
        NetMonitorWidget._update_history_control(context)
        self.assertEqual(context.btn_history_pause.text(), '● 已暂停')
        self.assertEqual(context.act_history_pause.text(), '恢复流量入账')
        self.assertIn('不会补记', context.act_history_pause.toolTip())
        self.assertEqual(history_button_css(True), context.btn_history_pause.styleSheet())

    def test_toggle_persists_actual_state_and_updates_controls(self):
        context = self.context()
        context._update_history_control = lambda: NetMonitorWidget._update_history_control(context)
        context._update_history_actions = Mock()
        NetMonitorWidget._toggle_history_paused(context)
        context.engine.history.pause.assert_called_once_with()
        context.settings.setValue.assert_called_with('history_paused', True)
        self.assertEqual(context.btn_history_pause.text(), '● 已暂停')

        NetMonitorWidget._toggle_history_paused(context)
        context.engine.history.resume.assert_called_once_with()
        context.settings.setValue.assert_called_with('history_paused', False)
        self.assertEqual(context.btn_history_pause.text(), '● 入账中')

    def test_paused_status_keeps_exports_available(self):
        context = self.context(paused=True)
        NetMonitorWidget._update_history_actions(context, {
            'history_status': 'running', 'history_path': 'test.sqlite3',
            'history_error': '', 'history_dropped': 0,
        })
        self.assertIn('已暂停', context.act_history_status.text())
        self.assertTrue(context.act_history_export_24h.isEnabled())
        self.assertTrue(context.act_history_export_year.isEnabled())

    def test_title_icons_and_styles_match_confirmed_design(self):
        self.assertFalse(title_icon('pin').isNull())
        self.assertFalse(title_icon('close').isNull())
        self.assertIn('QPushButton:checked', PIN_BUTTON_CSS)
        self.assertIn('#357FC5', PIN_BUTTON_CSS)
        self.assertIn('#357FC5', CLOSE_BUTTON_CSS)
        with self.assertRaises(ValueError):
            title_icon('unknown')


if __name__ == '__main__':
    unittest.main()
