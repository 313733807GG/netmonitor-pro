"""Logical-pixel docking geometry, independent of resize side effects."""
EDGE_GAP=8
SNAP_DISTANCE=2

def nearest_edge(rect,screen,edges=('l','r','t','b')):
    distances={'l':abs(rect.left()-screen.left()),'r':abs(rect.right()-screen.right()),
               't':abs(rect.top()-screen.top()),'b':abs(rect.bottom()-screen.bottom())}
    return min(edges,key=lambda edge:distances[edge]),distances

def snap_edge(rect,screen):
    distances={'l':rect.left()-screen.left(),'r':screen.right()-rect.right(),
               't':rect.top()-screen.top(),'b':screen.bottom()-rect.bottom()}
    candidates=[edge for edge,gap in distances.items() if gap<=SNAP_DISTANCE]
    return min(candidates,key=lambda edge:abs(distances[edge])) if candidates else None

def dock_position(rect,screen,edge):
    x=max(screen.left(),min(rect.x(),max(screen.left(),screen.right()-rect.width()+1)))
    y=max(screen.top(),min(rect.y(),max(screen.top(),screen.bottom()-rect.height()+1)))
    if edge=='l':x=screen.left()
    elif edge=='r':x=max(screen.left(),screen.right()-rect.width()+1)
    elif edge=='t':y=screen.top()
    elif edge=='b':y=max(screen.top(),screen.bottom()-rect.height()+1)
    return x,y
