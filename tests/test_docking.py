import unittest
from PySide6.QtCore import QRect
from docking import SNAP_DISTANCE,snap_edge,dock_position,nearest_edge

class DockingTests(unittest.TestCase):
    def test_equal_threshold_all_directions_and_negative_origins(self):
        for screen in (QRect(0,0,1920,1040),QRect(-1600,-300,1600,900),QRect(0,1080,1920,1040)):
            for gap,expected in ((-80,True),(0,True),(SNAP_DISTANCE,True),(SNAP_DISTANCE+1,False)):
                cases={'l':QRect(screen.left()+gap,screen.top()+100,380,680),
                       'r':QRect(screen.right()-379-gap,screen.top()+100,380,680),
                       't':QRect(screen.left()+400,screen.top()+gap,380,680),
                       'b':QRect(screen.left()+400,screen.bottom()-679-gap,380,680)}
                for edge,rect in cases.items():self.assertEqual(snap_edge(rect,screen),edge if expected else None)
    def test_secondary_bottom_stays_bottom_after_resize(self):
        screen=QRect(-1920,1080,1920,1040);full=QRect(-1400,1440,380,680)
        edge=nearest_edge(full,screen,('t','b'))[0]
        self.assertEqual(edge,'b')
        mini=QRect(full.x(),full.y(),272,54)
        x,y=dock_position(mini,screen,edge)
        self.assertEqual(y+mini.height()-1,screen.bottom())
        self.assertGreaterEqual(x,screen.left())
    def test_oversize_window_is_not_placed_above_screen(self):
        screen=QRect(1920,0,800,600)
        x,y=dock_position(QRect(2000,100,380,680),screen,'b')
        self.assertEqual(y,screen.top())
