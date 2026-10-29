"""Palette A: shared across full, offline, direct, busy and mini states."""
BACKGROUND='#303741'
SURFACE='#3C4552'
BUTTON='#566171'
HOVER='#68778B'
PRESSED='#414D5E'
TEXT='#FFFFFF'
MUTED='#AEBAC9'
ACCENT='#38B9FF'
GREEN='#48F5AF'
YELLOW='#FFE36B'
RED='#FF718D'
PINK='#FF92D0'
NODE='#FFF0B8'
SCORE_GREEN='#48EF9A'
SCORE_LIME='#C3EC55'
SCORE_YELLOW='#FFE05C'
SCORE_RED='#FF718D'

def controls_css():
    return f'''
        QPushButton {{ background:{BUTTON};color:{TEXT};border:1px solid transparent;
          border-radius:6px;padding:3px 7px;font-size:11.5px; }}
        QPushButton:hover {{ background:{HOVER};border-color:#8796A9; }}
        QPushButton:pressed {{ background:{PRESSED};border-color:#9BAAC0; }}
        QPushButton:disabled {{ background:#454F5D;color:#C2CCD8;border-color:#647084; }}
        QComboBox {{ background:{BUTTON};color:{TEXT};border:1px solid transparent;
          border-radius:6px;padding:2px 4px;font-size:11.5px; }}
        QComboBox:hover {{ background:{HOVER};border-color:#8796A9; }}
        QComboBox:on {{ background:{PRESSED};border-color:#9BAAC0; }}
        QComboBox QAbstractItemView {{ background:{SURFACE};color:{TEXT};
          selection-background-color:{HOVER};selection-color:{TEXT}; }}
    '''
