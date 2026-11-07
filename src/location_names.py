"""Evidence-based hierarchy comparison and deterministic Chinese place names."""
import re

ALIASES={
 'taiwan (province of china)':'台湾','taiwan, province of china':'台湾','hong kong sar china':'香港','pingtung':'屏东','pingtung city':'屏东市','taiwan':'台湾','taiwan province':'台湾','中国台湾':'台湾','台湾省':'台湾','臺灣':'台湾',
 'hong kong':'香港','hong kong sar':'香港','中国香港':'香港','hong kong island':'香港岛','kowloon':'九龙','new territories':'新界',
 'macao':'澳门','macau':'澳门','中国澳门':'澳门','china':'中国','united states':'美国','united states of america':'美国',
 'japan':'日本','singapore':'新加坡','south korea':'韩国','republic of korea':'韩国','canada':'加拿大','australia':'澳大利亚',
 'united kingdom':'英国','germany':'德国','france':'法国','netherlands':'荷兰','russia':'俄罗斯','india':'印度',
 'thailand':'泰国','vietnam':'越南','malaysia':'马来西亚','indonesia':'印度尼西亚','philippines':'菲律宾',
 'taipei':'台北市','taipei city':'台北市','台北':'台北市','臺北市':'台北市','new taipei':'新北市','new taipei city':'新北市',
 'taoyuan':'桃园市','taoyuan city':'桃园市','taichung':'台中市','taichung city':'台中市','tainan':'台南市','kaohsiung':'高雄市',
 'changhua':'彰化','changhua county':'彰化县','changhua city':'彰化市','彰化縣':'彰化县','yuanlin':'员林','yuanlin city':'员林市','員林市':'员林市',
 'hsinchu':'新竹','hsinchu city':'新竹市','hsinchu county':'新竹县','yilan':'宜兰','keelung':'基隆市',
 'tokyo':'东京','東京都':'东京','osaka':'大阪','kyoto':'京都','nagoya':'名古屋','fukuoka':'福冈','yokohama':'横滨','saitama':'埼玉',
 'shinjuku':'新宿','shinjuku city':'新宿','edogawa':'江户川','katsushika':'葛饰','chiyoda':'千代田','minato':'港区','shibuya':'涩谷',
 'seoul':'首尔','busan':'釜山','bangkok':'曼谷','kuala lumpur':'吉隆坡','jakarta':'雅加达','manila':'马尼拉',
 'california':'加利福尼亚州','washington':'华盛顿州','texas':'得克萨斯州','new york':'纽约','virginia':'弗吉尼亚州',
 'new jersey':'新泽西州','oregon':'俄勒冈州','illinois':'伊利诺伊州','florida':'佛罗里达州','georgia':'佐治亚州',
 'arizona':'亚利桑那州','nevada':'内华达州','massachusetts':'马萨诸塞州','colorado':'科罗拉多州','ohio':'俄亥俄州',
 'los angeles':'洛杉矶','san jose':'圣何塞','san francisco':'旧金山','san diego':'圣迭戈','seattle':'西雅图',
 'new york city':'纽约','chicago':'芝加哥','dallas':'达拉斯','houston':'休斯敦','miami':'迈阿密','atlanta':'亚特兰大',
 'phoenix':'凤凰城','las vegas':'拉斯维加斯','boston':'波士顿','denver':'丹佛','portland':'波特兰','ashburn':'阿什本',
 'london':'伦敦','manchester':'曼彻斯特','paris':'巴黎','frankfurt':'法兰克福','berlin':'柏林','amsterdam':'阿姆斯特丹',
 'toronto':'多伦多','vancouver':'温哥华','montreal':'蒙特利尔','ontario':'安大略省','british columbia':'不列颠哥伦比亚省','quebec':'魁北克省',
 'sydney':'悉尼','melbourne':'墨尔本','brisbane':'布里斯班','new south wales':'新南威尔士州','victoria':'维多利亚州',
 'beijing':'北京市','shanghai':'上海市','guangdong':'广东省','shenzhen':'深圳市','guangzhou':'广州市','zhejiang':'浙江省','hangzhou':'杭州市',
}
SPECIAL={'台湾','香港','澳门'}

def zh(value,level=None):
    value=str(value or '').strip()
    contextual={'region':{'new york':'纽约州','changhua':'彰化县','pingtung':'屏东县'},'city':{'new york':'纽约市','washington':'华盛顿','changhua':'彰化市','yuanlin':'员林市'}}
    if value.casefold() in contextual.get(level,{}):return contextual[level][value.casefold()]
    return ALIASES.get(value.casefold(),ALIASES.get(value,value))

def path(location):
    values=[(location.get('country',''),'country')]
    if 'parts' in location:
        parts=location.get('parts') or []
        values += [(value,('region' if i==0 else 'city') if len(parts)>=2 else None) for i,value in enumerate(parts)]
    else:values += [(location.get(k,''),k) for k in ('region','city','district')]
    out=[]
    for value,level in values:
        value=zh(value,level)
        if value and value.casefold() not in [x.casefold() for x in out]:out.append(value)
    if len(out)>1 and out[0]=='中国' and out[1] in SPECIAL:out.pop(0)
    return out

def equivalent(a,b):
    a,b=a.casefold(),b.casefold()
    if a==b:return True
    # An unsuffixed abbreviation may match a full label, but city and county
    # labels with distinct explicit suffixes remain different.
    suffixes=('省','州','县','市','郡','区')
    return (a.endswith(suffixes) and not b.endswith(suffixes) and a[:-1]==b) or (b.endswith(suffixes) and not a.endswith(suffixes) and b[:-1]==a)

def subsequence(a,b):
    it=iter([x.casefold() for x in b])
    return all(any(equivalent(x,y) for y in it) for x in a)

def display(location):
    chain=path(location);country=zh(location.get('country',''))
    if chain and country and chain[0]==country and country not in SPECIAL:chain=chain[1:]
    return chain[:2]

def comparison(a,b):
    pa,pb=path(a),path(b)
    candidates=[pa,pb]+[path(x) for loc in (a,b) for x in loc.get('alternatives',[]) if isinstance(x,dict)]
    if any(subsequence(pa,c) and subsequence(pb,c) for c in candidates):return 'same'
    def levels(loc):
        result={k:zh(loc.get(k,''),k) for k in ('country','region','city','district')}
        if result['country']=='中国' and result['region'] in SPECIAL:result['country']=result['region'];result['region']=''
        if result['region']==result['country']:result['region']=''
        parts=loc.get('parts') or []
        if len(parts)>=2:result['region'],result['city']=zh(parts[0]),zh(parts[1])
        elif parts:
            value=zh(parts[0])
            if value.endswith(('县','省','州')):result['region']=value
            elif value.endswith('市') or value in ('东京','大阪','九龙','新界'):result['city']=value
        return result
    aa,bb=levels(a),levels(b)
    if any(aa[k] and bb[k] and not equivalent(aa[k],bb[k]) for k in aa):return 'different'
    # Unlabelled paths can omit intermediate levels. Only infer a deep
    # sibling conflict when the common parent and explicit level agree.
    shared=0
    for left,right in zip(pa,pb):
        if not equivalent(left,right):break
        shared+=1
    if shared>=2 and shared<min(len(pa),len(pb)):
        left,right=pa[shared],pb[shared]
        for suffix in ('省','州','县','市','郡','区','镇','乡','里','村','街道','路','街'):
            if left.endswith(suffix) and right.endswith(suffix):return 'different'
    return 'incomplete'

def location_display(result):
    pure=result.get('ippure') or {};clean=result.get('cleanip') or {}
    a,b=pure.get('location') or {},clean.get('location') or {}
    pa,pb=display(a),display(b)
    detail='IPPure：'+(' → '.join(path(a)) or '未提供')+'\nCleanIP：'+(' → '.join(path(b)) or '未提供')
    if pure.get('ip') and clean.get('ip') and pure['ip']!=clean['ip'] and not (result.get('route_verified') is True and result.get('node')):
        return '出口不一致',detail+'\n两站IP不同，未合并地址。'
    if not pa and not pb:return '地区待确认',detail
    chosen=pb or pa;suffix=''
    if pa and pb:
        status=comparison(a,b)
        if status=='different':suffix='（分歧）';detail+='\n可比较的同级地区不同，按CleanIP显示。'
        elif status=='same':detail+='\n两站同属已知地址层级，按CleanIP显示。'
        else:detail+='\n层级信息不完整，暂无法直接比较；不据此判定分歧，按CleanIP显示。'
    else:detail+='\n单来源结果，尚未双站印证。'
    if any(re.search('[A-Za-z]',x) for x in chosen):detail+='\n部分地名暂无可靠中文对照，保留原文。'
    if len(chosen)<2:detail+='\n仅有一级地区，没有猜补下级地址。'
    return ' · '.join(chosen)+suffix,detail
