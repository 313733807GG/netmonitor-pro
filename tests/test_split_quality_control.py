import os
import unittest
from unittest.mock import Mock

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import QPoint, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from dropdown_controls import ArrowComboBox, FixedLabelComboBox
import ui_theme as theme


class SplitQualityControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def combo(self):
        combo = FixedLabelComboBox('IP质量')
        combo.setFixedSize(78, 28)
        for label, mode in (('自动检测 / 风险汇总', 'auto'),
                            ('仅检测 IPv4', '4'), ('仅检测 IPv6', '6')):
            combo.addItem(label, mode)
        combo.setStyleSheet(theme.controls_css())
        combo.show()
        self.app.processEvents()
        self.addCleanup(combo.hidePopup)
        self.addCleanup(combo.close)
        return combo

    def test_left_side_only_manual_and_right_side_only_popup(self):
        combo = self.combo()
        manual = Mock()
        selected = Mock()
        combo.manualTriggered.connect(manual)
        combo.activated.connect(selected)

        QTest.mouseClick(combo, Qt.LeftButton, pos=QPoint(20, 14))
        self.app.processEvents()
        manual.assert_called_once_with()
        selected.assert_not_called()
        self.assertFalse(combo.view().isVisible())

        QTest.mouseClick(combo, Qt.LeftButton, pos=QPoint(66, 14))
        self.app.processEvents()
        self.assertTrue(combo.view().isVisible())
        manual.assert_called_once_with()
        selected.assert_not_called()
        combo.hidePopup()

    def test_manual_off_does_not_block_arrow_popup(self):
        combo = self.combo()
        manual = Mock()
        combo.manualTriggered.connect(manual)
        combo.setManualEnabled(False)
        QTest.mouseClick(combo, Qt.LeftButton, pos=QPoint(20, 14))
        self.app.processEvents()
        manual.assert_not_called()
        self.assertFalse(combo.view().isVisible())

        QTest.mouseClick(combo, Qt.LeftButton, pos=QPoint(66, 14))
        self.app.processEvents()
        self.assertTrue(combo.view().isVisible())
        manual.assert_not_called()
        combo.hidePopup()

    def test_white_divider_is_drawn_at_split_boundary(self):
        combo = self.combo()
        image = combo.grab().toImage()
        self.assertEqual(image.pixelColor(combo.width() - 24, 7).name(), '#ffffff')

    def test_popup_does_not_elide_and_has_hover_tracking(self):
        combo = self.combo()
        combo.showPopup()
        self.app.processEvents()
        view = combo.view()
        metrics = view.fontMetrics()
        required = max(metrics.horizontalAdvance(combo.itemText(i))
                       for i in range(combo.count())) + 34
        self.assertGreaterEqual(view.parentWidget().width(), required)
        self.assertEqual(view.textElideMode(), Qt.ElideNone)
        self.assertTrue(view.hasMouseTracking())
        combo.hidePopup()

    def test_hover_and_current_item_share_button_highlight(self):
        css = theme.controls_css()
        self.assertIn('QComboBox QAbstractItemView::item:hover', css)
        self.assertIn('QComboBox QAbstractItemView::item:selected', css)
        self.assertIn(f'background:{theme.HOVER}', css)
        self.assertIn('border-left:3px solid #DCE6F2', css)


if __name__ == '__main__':
    unittest.main()
