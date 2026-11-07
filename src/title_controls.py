"""Compact vector icons and styles for the full-window title controls."""
from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap


PIN_BUTTON_CSS = """
    QPushButton { background:#343E4A; border:1px solid #596676; border-radius:6px; padding:0; }
    QPushButton:hover { background:#455262; border-color:#8796A9; }
    QPushButton:checked { background:#357FC5; border-color:#65B5FF; }
    QPushButton:checked:hover { background:#438FCD; }
"""

CLOSE_BUTTON_CSS = """
    QPushButton { background:#357FC5; border:1px solid #65B5FF; border-radius:6px; padding:0; }
    QPushButton:hover { background:#438FCD; }
    QPushButton:pressed { background:#2C6CA9; }
"""


def history_button_css(paused):
    if paused:
        return """
            QPushButton { background:#3A2933; color:#F0A2B8; border:1px solid #BA6987;
                          border-radius:13px; padding:0; font-size:11px; }
            QPushButton:hover { background:#503440; }
        """
    return """
        QPushButton { background:#20332F; color:#8CE2C5; border:1px solid #3E7569;
                      border-radius:13px; padding:0; font-size:11px; }
        QPushButton:hover { background:#29473F; }
    """


def title_icon(kind):
    pixmap = QPixmap(32, 32)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    if kind == 'pin':
        painter.translate(16, 15)
        painter.rotate(-24)
        painter.scale(0.9, 0.9)
        path = QPainterPath(QPointF(-6, -9))
        path.lineTo(6, -9)
        path.lineTo(5, -5)
        path.lineTo(3, -4)
        path.lineTo(5, 2)
        path.lineTo(9, 5)
        path.lineTo(9, 7)
        path.lineTo(2, 7)
        path.lineTo(1, 12)
        path.lineTo(-1, 12)
        path.lineTo(-2, 7)
        path.lineTo(-9, 7)
        path.lineTo(-9, 5)
        path.lineTo(-5, 2)
        path.lineTo(-3, -4)
        path.lineTo(-5, -5)
        path.closeSubpath()
        painter.fillPath(path, QColor('#FFFFFF'))
    elif kind == 'close':
        pen = QPen(QColor('#FFFFFF'), 2.2, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(pen)
        painter.drawLine(QPointF(10, 10), QPointF(22, 22))
        painter.drawLine(QPointF(22, 10), QPointF(10, 22))
    else:
        painter.end()
        raise ValueError(f'unknown title icon: {kind}')
    painter.end()
    return QIcon(pixmap)
