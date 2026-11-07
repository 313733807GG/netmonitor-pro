"""One delayed missing-item retry per user attempt; never retry access barriers."""
import time
from collections import OrderedDict

class QualityRetry:
    def __init__(self):self.items=OrderedDict()
    def reset(self,key):self.items.pop(key,None)
    def due(self,key,now=None):
        item=self.items.get(key);now=time.monotonic() if now is None else now
        return bool(item and item['at'] is not None and now>=item['at'])
    def consume(self,key):
        item=self.items[key];item['count']+=1;item['at']=None
    def completed(self,key,result,now=None):
        if result.get('cancelled'):return
        errors=list((result.get('errors') or {}).values())+list((result.get('discovery') or {}).get('errors',{}).values())
        def transient(text):
            s=str(text).lower()
            if any(x in s for x in ('403','429','401','验证','captcha','结构','ip不符')):return False
            return any(x in s for x in ('timeout','超时','未就绪','eof','reset','中断','断开','connection','连接失败'))
        if not any(transient(e) for e in errors):self.reset(key);return
        item=self.items.setdefault(key,{'count':0,'at':None});self.items.move_to_end(key)
        if len(self.items)>128:self.items.popitem(last=False)
        if item['count']<1:item['at']=(time.monotonic() if now is None else now)+15
