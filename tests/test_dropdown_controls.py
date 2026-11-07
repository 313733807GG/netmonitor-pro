import os
import unittest

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import QUrl
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QApplication, QComboBox

from dropdown_controls import FixedLabelComboBox
from status_ui import TypeBadges
import ui_theme as theme


class DropdownControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_fixed_label_does_not_change_with_selected_mode(self):
        combo = FixedLabelComboBox('IP质量')
        combo.addItem('自动检测 / 风险汇总', 'auto')
        combo.addItem('仅检测 IPv4', '4')
        combo.addItem('仅检测 IPv6', '6')
        combo.setStyleSheet(theme.controls_css())
        combo.show()
        self.app.processEvents()
        first = combo.grab().toImage()
        combo.setCurrentIndex(2)
        self.app.processEvents()
        second = combo.grab().toImage()
        self.assertEqual(first, second)
        self.assertEqual(combo.display_label, 'IP质量')
        self.assertEqual(combo.itemData(2), '6')
        combo.setText('检测中…')
        self.assertEqual(combo.text(), '检测中…')
        self.app.processEvents()
        combo.setText('IP质量')
        self.app.processEvents()
        self.assertEqual(first, combo.grab().toImage())
        combo.close()

    def test_native_popup_and_theme_match_regular_combo(self):
        quality = FixedLabelComboBox('IP质量')
        probe = QComboBox()
        for combo in (quality, probe):
            combo.addItem('项目一')
            combo.addItem('项目二')
            combo.setStyleSheet(theme.controls_css())
            combo.show()
        self.app.processEvents()
        self.assertIs(type(quality.view()), type(probe.view()))
        self.assertEqual(quality.styleSheet(), probe.styleSheet())
        self.assertEqual(quality.view().palette(), probe.view().palette())
        for combo in (quality, probe):
            combo.showPopup()
            self.app.processEvents()
            self.assertTrue(combo.view().isVisible())
            combo.hidePopup()
            combo.close()

    def test_unknown_badges_use_new_neutral_solid_icons(self):
        badges = TypeBadges()
        badges.render({})
        self.assertEqual(len(badges.badges), 2)
        self.assertIn('unknown_origin', badges.badges[0].icon)
        self.assertIn('unknown_type', badges.badges[1].icon)
        for badge in badges.badges:
            self.assertFalse(QPixmap(QUrl(badge.icon).toLocalFile()).isNull())
        badges.deleteLater()

    def test_shared_style_removes_separate_arrow_background(self):
        css = theme.controls_css()
        self.assertIn('QComboBox::drop-down', css)
        self.assertIn('background:transparent;width:20px', css)
        self.assertIn('QComboBox QAbstractItemView', css)


if __name__ == '__main__':
    unittest.main()
