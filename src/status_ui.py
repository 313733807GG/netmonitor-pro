"""Small locally drawn icons and source-aware IP badges, without emoji fonts."""
import html
from PySide6.QtCore import Qt, QTemporaryDir, QRectF, QUrl, QSize
from PySide6.QtGui import QPainter, QPixmap, QColor, QPen, QPainterPath
from PySide6.QtWidgets import QLabel, QFrame, QHBoxLayout, QSizePolicy
from ip_quality import type_badges
import ui_theme as theme

_icons={}
_icon_dir=None

def draw_type_icon(p,kind,color):
    """Solid B glyphs in a 24-unit design grid; shared across source styles."""
    p.save();p.scale(2/3,2/3)
    c=QColor(color);pen=QPen(c,1.8,Qt.SolidLine,Qt.RoundCap,Qt.RoundJoin)
    p.setPen(pen);p.setBrush(c);path=QPainterPath()
    if kind=='native':
        path.moveTo(12,2);path.cubicTo(8,4,5,5,3,5);path.lineTo(3,11)
        path.cubicTo(3,17,8,21,12,23);path.cubicTo(16,21,21,17,21,11)
        path.lineTo(21,5);path.cubicTo(18,5,15,4,12,2);path.closeSubpath()
    elif kind=='home':
        path.moveTo(2,11);path.lineTo(12,3);path.lineTo(22,11);path.lineTo(19,11)
        path.lineTo(19,21);path.lineTo(5,21);path.lineTo(5,11);path.closeSubpath()
    elif kind=='broadcast':
        p.setBrush(Qt.NoBrush)
        for rect in (QRectF(2,2,20,18),QRectF(6,6,12,10)):
            p.drawArc(rect,-42*16,84*16);p.drawArc(rect,138*16,84*16)
        p.drawLine(12,12,12,21);p.drawLine(8,21,16,21);p.setBrush(c)
        path.addEllipse(QRectF(10,9,4,4))
    elif kind=='mobile':path.addRoundedRect(QRectF(6,2,12,21),3,3)
    elif kind=='unknown':path.addRoundedRect(QRectF(3,3,18,18),5,5)
    else:
        path.addRoundedRect(QRectF(3,3,18,8),2,2);path.addRoundedRect(QRectF(3,14,18,8),2,2)
    p.drawPath(path)
    p.setPen(QPen(QColor(theme.BACKGROUND),1.8,Qt.SolidLine,Qt.RoundCap,Qt.RoundJoin))
    p.setBrush(Qt.NoBrush)
    if kind=='native':p.drawLine(7,12,11,16);p.drawLine(11,16,17,9)
    elif kind=='home':p.drawRoundedRect(QRectF(10,14,5,7),1,1)
    elif kind=='mobile':p.drawLine(10,18,14,18)
    elif kind=='unknown':p.drawLine(9,9,15,9);p.drawLine(15,9,12,12);p.drawPoint(12,17)
    elif kind=='server':
        for y in (7,18):p.drawPoint(7,y);p.drawLine(12,y,17,y)
    p.restore()

def icon_path(kind,color='#E5E7EB'):
    global _icon_dir
    key=(kind,color)
    if key in _icons:return _icons[key]
    if _icon_dir is None:_icon_dir=QTemporaryDir()
    pix=QPixmap(32,32);pix.fill(Qt.transparent)
    p=QPainter(pix);p.setRenderHint(QPainter.Antialiasing);p.scale(2,2)
    p.setPen(QPen(QColor(color),1.3));p.setBrush(Qt.NoBrush)
    if kind=='system':
        p.drawRoundedRect(QRectF(3,2,10,9),1,1);p.drawLine(1,13,15,13)
    elif kind=='tun':
        p.translate(0,-1)  # lift this glyph only; other icons keep bottom alignment
        p.drawRoundedRect(QRectF(1.5,2.5,13,9),1.2,1.2)
        p.drawRect(QRectF(5,5,6,4))
        for x in (4,7,10):p.drawLine(x,12,x,14)
    elif kind=='global':
        p.drawEllipse(QRectF(2,2,12,12));p.drawEllipse(QRectF(5,2,6,12))
        p.drawLine(2,8,14,8);p.drawLine(4,4,12,4);p.drawLine(4,12,12,12)
    elif kind=='rule':
        p.drawLine(2,5,13,5);p.drawLine(10,2,13,5);p.drawLine(10,8,13,5)
        p.drawLine(14,11,3,11);p.drawLine(6,8,3,11);p.drawLine(6,14,3,11)
    elif kind=='direct':
        path=QPainterPath();path.moveTo(8,1);path.lineTo(15,8);path.lineTo(8,15);path.lineTo(1,8);path.closeSubpath();p.drawPath(path)
        p.drawLine(4,8,11,8);p.drawLine(8,5,11,8);p.drawLine(8,11,11,8)
    else:
        draw_type_icon(p,kind,color)
    p.end()
    path=_icon_dir.filePath(kind+color.replace('#','')+'.png');pix.save(path)
    _icons[key]=QUrl.fromLocalFile(path).toString();return _icons[key]

def image_tag(kind):
    return f'<img src="{icon_path(kind,theme.ACCENT)}" width="14" height="14" style="vertical-align:bottom">'

def mode_rich_text(data):
    value=data.get('strict_route') if data.get('api_on') else None
    state='开' if value is True else ('关' if value is False else '未知')
    color=theme.ACCENT if value is True else (theme.PINK if value is False else theme.MUTED)
    if not data.get('tun_on') and value is True:state+=' · 未生效'
    mode=data.get('mode');name={'rule':'规则','global':'全局','direct':'直连'}.get(mode,'未知')
    return (f'{image_tag("system")} 系统代理 {"开" if data.get("sp_on") else "关"} · '
            f'{image_tag("tun")} TUN {"开" if data.get("tun_on") else "关"}'
            f'<span style="color:{color}">（&#8201;严格路由 {state}&#8201;）</span>'
            f'<br>{image_tag(mode if mode in ("rule","global","direct") else "rule")} {name}模式')

class ElidedLabel(QLabel):
    def __init__(self,parent=None):
        super().__init__(parent);self.full_text='';self._colored_parts=None;self.setTextFormat(Qt.PlainText)
        self.setSizePolicy(QSizePolicy.Ignored,QSizePolicy.Fixed);self.setFixedHeight(20)
    def set_full_text(self,text):
        self._colored_parts=None;self.setTextFormat(Qt.PlainText)
        self.full_text=str(text);self._update_text()
    def set_colored_parts(self,parts):
        self._colored_parts=parts;self.full_text=''.join(text for text,color in parts)
        self.setTextFormat(Qt.RichText);self._update_text()
    def _update_text(self):
        visible=self.fontMetrics().elidedText(self.full_text,Qt.ElideRight,max(0,self.contentsRect().width()))
        if self._colored_parts is None:self.setText(visible);return
        cut=len(visible)-1 if visible.endswith('…') and visible!=self.full_text else len(visible)
        out=[];remaining=cut
        for text,color in self._colored_parts:
            chunk=text[:max(0,remaining)];remaining-=len(chunk)
            if chunk:out.append('<span style="color:'+color+'">'+html.escape(chunk)+'</span>' if color else html.escape(chunk))
            if remaining<=0:break
        if visible.endswith('…') and visible!=self.full_text:out.append('…')
        self.setText(''.join(out))
    def resizeEvent(self,event):super().resizeEvent(event);self._update_text()

class BadgeLabel(QLabel):
    def __init__(self,text,icon,parent=None):
        super().__init__(parent);self.full_text=text;self.icon=icon
        self.setSizePolicy(QSizePolicy.Preferred,QSizePolicy.Fixed)
    def natural_width(self):
        return self.fontMetrics().horizontalAdvance(self.full_text)+36
    def sizeHint(self):return QSize(self.natural_width(),28)
    def minimumSizeHint(self):return QSize(0,28)
    def resizeEvent(self,event):
        super().resizeEvent(event)
        text=self.fontMetrics().elidedText(self.full_text,Qt.ElideRight,max(0,self.width()-36))
        self.setText(f'<img src="{self.icon}" width="14" height="14" style="vertical-align:bottom">&nbsp; {html.escape(text)}')

class TypeBadges(QFrame):
    def __init__(self,parent=None):
        super().__init__(parent);self.setObjectName('ipTypes');self.setStyleSheet('QFrame#ipTypes {background:transparent;border:0;}')
        self.row=QHBoxLayout(self);self.row.setContentsMargins(0,2,0,2);self.row.setSpacing(8)
        self._signature=None
        self.badges=[]
    def render(self,result):
        badges=type_badges(result)
        if badges==self._signature:return
        self._signature=badges
        self.badges=[]
        while self.row.count()>0:
            item=self.row.takeAt(0)
            if item.widget():item.widget().hide();item.widget().deleteLater()
        for text,tone,detail,source in badges:
            fg,bg,border={'positive':(theme.GREEN,'#294E43','#4BA57D'),'negative':(theme.RED,'#593741','#BD6373'),'unknown':(theme.MUTED,'#414B5A','#758397')}[tone]
            if source=='IPPure':bg=('#186638' if tone=='positive' else '#A12D3C') if tone!='unknown' else bg;fg='#FFFFFF'
            if source=='FlClash':bg='#593741' if tone=='negative' else '#414B5A'
            kind='native' if '原生' in text and '非原生' not in text else ('broadcast' if '广播' in text or '非原生' in text else ('home' if text.startswith('住宅') else ('mobile' if '移动' in text else 'server')))
            if tone=='unknown':kind='unknown'
            badge=BadgeLabel(text,icon_path(kind,fg))
            badge.setTextFormat(Qt.RichText)
            badge.setFixedHeight(28)
            badge.setAlignment(Qt.AlignCenter)
            radius=12 if source=='FlClash' else 5
            badge.setStyleSheet(f'QLabel {{ color:{fg};background:{bg};border:1px solid {border};border-radius:{radius}px;padding:2px 5px;font-size:12px;font-weight:600;letter-spacing:0px; }}')
            badge.ensurePolished()
            badge.setMaximumWidth(badge.natural_width())
            badge.setToolTip(text+'\n'+detail+'\n展示来源：'+source)
            self.row.addWidget(badge)
            self.badges.append(badge)
        self.row.addStretch(1)
