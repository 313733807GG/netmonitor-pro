"""Palette A: shared across full, offline, direct, busy and mini states."""
BACKGROUND='#303741'
SURFACE='#3C4552'
BUTTON='#566171'
HOVER='#68778B'
PRESSED='#414D5E'
TEXT='#FFFFFF'
MUTED='#AEBAC9'
GREEN='#57E0AA'
YELLOW='#F4C865'
RED='#FF7D8B'
PINK='#F69AC4'
NODE='#F6DE9A'

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
