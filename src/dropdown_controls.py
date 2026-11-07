"""Native combo-box popup with shared vector arrow and split action label."""
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QComboBox, QStyle, QStyleOptionComboBox
from PySide6.QtGui import QColor, QPainter, QPen


def paint_down_arrow(combo):
    painter = QPainter(combo)
    painter.setRenderHint(QPainter.Antialiasing)
    color = '#DCE6F2' if combo.isEnabled() else '#8796A9'
    painter.setPen(QPen(QColor(color), 1.7, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    x = combo.width() - 16
    y = combo.height() / 2 - 2
    painter.drawLine(x, y, x + 4, y + 4)
    painter.drawLine(x + 4, y + 4, x + 8, y)
    painter.end()


def paint_split_divider(combo):
    painter = QPainter(combo)
    painter.setPen(QPen(QColor('#FFFFFF'), 1))
    x = combo.width() - 24
    painter.drawLine(x, 5, x, combo.height() - 6)
    painter.end()


class ArrowComboBox(QComboBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.view().setMouseTracking(True)
        self.view().setTextElideMode(Qt.ElideNone)

    def showPopup(self):
        self.view().ensurePolished()
        metrics = self.view().fontMetrics()
        text_width = max((metrics.horizontalAdvance(self.itemText(i))
                          for i in range(self.count())), default=0)
        width = max(self.width(), text_width + 34)
        self.view().setMinimumWidth(width)
        super().showPopup()
        popup = self.view().parentWidget()
        if popup and popup.width() < width:
            popup.resize(width, popup.height())

    def paintEvent(self, event):
        super().paintEvent(event)
        paint_down_arrow(self)


class FixedLabelComboBox(ArrowComboBox):
    manualTriggered = Signal()

    def __init__(self, label, parent=None):
        super().__init__(parent)
        self.display_label = label
        self._manual_pressed = False
        self.manual_enabled = True

    def setManualEnabled(self, enabled):
        enabled = bool(enabled)
        if enabled != self.manual_enabled:
            self.manual_enabled = enabled
            self._manual_pressed = False
            self.update()

    def text(self):
        return self.display_label

    def setText(self, text):
        text = str(text)
        if text != self.display_label:
            self.display_label = text
            self.update()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and event.position().x() < self.width() - 24:
            event.accept()
            if not self.manual_enabled:
                return
            self._manual_pressed = True
            self.setFocus(Qt.MouseFocusReason)
            return
        self._manual_pressed = False
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        if self._manual_pressed:
            self._manual_pressed = False
            if (event.button() == Qt.LeftButton
                    and event.position().x() < self.width() - 24):
                self.manualTriggered.emit()
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def paintEvent(self, event):
        option = QStyleOptionComboBox()
        self.initStyleOption(option)
        option.currentText = self.display_label
        painter = QPainter(self)
        self.style().drawComplexControl(QStyle.CC_ComboBox, option, painter, self)
        self.style().drawControl(QStyle.CE_ComboBoxLabel, option, painter, self)
        painter.end()
        paint_down_arrow(self)
        paint_split_divider(self)
