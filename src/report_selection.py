"""Select the requested Nuxt report without accepting unrelated/unfinished data."""
import ipaddress

def select_report(flat,expected):
    expected=str(ipaddress.ip_address(expected))
    if not isinstance(flat,list) or len(flat)>30000:raise ValueError('CleanIP 报告结构变化')
    def ref(index):
        if type(index)!=int or not 0<=index<len(flat):raise ValueError('CleanIP 报告引用异常')
        return flat[index]
    def unwrap(index):
        value=ref(index)
        for _ in range(8):
            if isinstance(value,list) and len(value)==2 and value[0] in ('Ref','ShallowRef','Reactive','ShallowReactive','ComputedRef'):
                value=ref(value[1])
            else:return value
        raise ValueError('CleanIP 报告引用过深')
    rooted=[];pending=False
    for item in flat:
        if isinstance(item,dict) and 'q:'+expected in item and type(item['q:'+expected])==int and item['q:'+expected]>=0:
            candidate=unwrap(item['q:'+expected])
            if isinstance(candidate,dict) and {'ip','risk','ok'}<=candidate.keys():rooted.append(candidate)
            elif isinstance(candidate,dict) and set(candidate)=={'kind'} and ref(candidate['kind'])=='ip':
                # Current SSR returns this exact placeholder while the report
                # is being obtained. It contains no score or verified address.
                pending=True
    if pending:raise ValueError('CleanIP 报告暂未就绪，请稍后补查')
    candidates=rooted or [x for x in flat if isinstance(x,dict) and {'ip','risk','ok'}<=x.keys()]
    matched=[]
    for candidate in candidates:
        try:ip=str(ipaddress.ip_address(ref(candidate['ip'])))
        except (ValueError,TypeError):continue
        if ip==expected and candidate not in matched:matched.append(candidate)
    if not matched:raise ValueError('CleanIP 报告未包含所查询IP，未接收结果')
    if len(matched)!=1:raise ValueError('CleanIP 出现多份不同报告，未接收结果')
    if ref(matched[0]['ok']) is not True:raise ValueError('CleanIP 报告暂未就绪，请稍后补查')
    return matched[0],ref
