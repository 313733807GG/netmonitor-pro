"""Read FlClash's same-IP quality evidence without changing its database."""
import ipaddress
import json
import math
import os
from pathlib import Path
import sqlite3
import time
from contextlib import closing

MAX_AGE = 3 * 24 * 60 * 60
TYPE_LABELS = {'residential':'住宅 IP','mobile':'移动网络 IP','business':'商业 IP','hosting':'机房 IP'}
SOURCE_LABELS = {'identMe':'ident.me','ipApiCom':'ip-api.com','ipQuery':'ipquery.io',
                 'ipLocate':'iplocate.io','proxyCheck':'proxycheck.io','ipApiIs':'ipapi.is'}
FLAG_LABELS = {'isTor':'Tor','isAbuser':'滥用','isVpn':'VPN','isProxy':'代理'}
UNKNOWN_TYPE_LABELS = {'','未知','未知 ip','未知类型','未知类型 ip','待确认','未识别',
                       'unknown','unknown ip','unknown type','n/a','—','-'}


def read_quality(ip, db_path=None, now=None):
    now = time.time() if now is None else now
    try:
        target = str(ipaddress.ip_address(ip))
    except (ValueError, TypeError):
        return {'status':'invalid','message':'待核对的出口 IP 无效'}
    path = Path(db_path) if db_path is not None else Path(os.environ.get('APPDATA',''))/'com.follow/clash/database.sqlite'
    if not path.is_file():
        return {'status':'missing','message':'没有 FlClash 本机质量记录'}
    try:
        with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=0.5)) as db:
            row=db.execute('SELECT quality,checked_at FROM ip_qualities WHERE ip=?',(target,)).fetchone()
        if not row:
            return {'status':'missing','message':'FlClash 尚未检测此出口 IP；可在其 IP 详情中刷新'}
        raw,stamp=row
        if (isinstance(stamp,bool) or not isinstance(stamp,(int,float)) or not math.isfinite(stamp) or stamp>now):
            return {'status':'invalid','message':'FlClash 记录时间异常，不参与印证'}
        if now-stamp>MAX_AGE:
            return {'status':'expired','message':'FlClash 记录已超过 3 天，请在其 IP 详情中刷新'}
        if not isinstance(raw,str) or len(raw)>65536:
            raise ValueError('invalid record')
        data=json.loads(raw)
        if not isinstance(data,dict) or str(ipaddress.ip_address(data.get('ip','')))!=target:
            return {'status':'ip_mismatch','message':'FlClash 记录 IP 不匹配，不参与印证'}
        kind=data.get('type');source=data.get('source')
        if kind not in TYPE_LABELS or source not in SOURCE_LABELS:
            raise ValueError('unsupported classification')
        if any(not isinstance(data.get(key,False),bool) for key in FLAG_LABELS):
            raise ValueError('invalid flags')
        flags=[label for key,label in FLAG_LABELS.items() if data.get(key,False)]
        level='risky' if data.get('isTor') or data.get('isAbuser') else ('normal' if kind=='hosting' else 'good')
        return {'status':'ok','ip':target,'type':kind,'ip_type':TYPE_LABELS[kind],
                'source':source,'source_label':SOURCE_LABELS[source],'checked_at':stamp,
                'level':level,'quality_label':{'risky':'风险','normal':'普通','good':'优'}[level],
                'flags':flags,'inferred_residential':kind=='residential' and source in ('ipApiCom','ipQuery')}
    except (OSError,sqlite3.Error,ValueError,TypeError):
        return {'status':'unavailable','message':'FlClash 本机质量记录暂不可读或格式已变化'}


def usable_record(result, now=None):
    record=result.get('flclash') or {}
    if record.get('status')!='ok' or record.get('type') not in TYPE_LABELS:
        return None
    ips={item.get('ip') for item in (result.get('ippure') or {},result.get('cleanip') or {}) if item.get('ip')}
    if len(ips)!=1 or record.get('ip') not in ips:
        return None
    stamp=record.get('checked_at')
    now=time.time() if now is None else now
    if not isinstance(stamp,(int,float)) or isinstance(stamp,bool) or not math.isfinite(stamp) or not 0<=now-stamp<=MAX_AGE:
        return None
    return record


def details(result):
    record=usable_record(result)
    stored=result.get('flclash') or {}
    if not stored:
        return ''
    if record is None:
        return 'FlClash：'+str(stored.get('message') or '记录过期或出口 IP 不一致，未参与印证')
    checked=time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(record['checked_at']))
    text=f"FlClash：{record['ip_type']} · 质量{record['quality_label']}\n来源：{record['source_label']}；本机缓存时间：{checked}"
    text+='\nFlClash 风险标记：'+('、'.join(record['flags']) or '未检出')
    text+='\n只比较同一出口 IP；本机记录最多保留 3 天，不是本轮实时请求。'
    if record.get('inferred_residential'):
        text+='\n此来源的住宅结论可能由未标记机房/移动推定，不作为明确住宅证据。'
    text+='\nFlClash 不提供原生/广播及地理层级；这些字段仍按原两站判定。质量等级不换算或覆盖网站分数。'
    return text


def merge_residential_badge(result, existing):
    """Negative evidence wins; keep CleanIP precedence among matching evidence."""
    third=usable_record(result)
    if third is None:
        extra=details(result)
        return existing[0],existing[1],existing[2]+('\n'+extra if extra else ''),existing[3]
    pure=result.get('ippure') or {};clean=result.get('cleanip') or {}
    c_label=clean.get('ip_type','')
    c_known=bool(c_label and c_label.strip().casefold() not in UNKNOWN_TYPE_LABELS)
    evidence=[]
    if c_known:evidence.append(('CleanIP',c_label,c_label!='住宅 IP'))
    if isinstance(pure.get('residential'),bool):
        evidence.append(('IPPure','住宅 IP' if pure['residential'] else '非住宅 IP',not pure['residential']))
    if not third.get('inferred_residential'):
        evidence.append(('FlClash',third['ip_type'],third['type']!='residential'))
    if not evidence:
        return existing[0],existing[1],existing[2]+'\n'+details(result),existing[3]
    negatives=[x for x in evidence if x[2]]
    positives=[x for x in evidence if not x[2]]
    chosen=(negatives or positives)[0]
    conflict=bool(negatives and positives)
    c_fine={'机房 IP':'hosting','IDC':'hosting','数据中心 IP':'hosting',
            '商业 IP':'business','移动 IP':'mobile','移动网络 IP':'mobile'}.get(c_label)
    if c_fine and third['type']!='residential' and c_fine!=third['type']:
        conflict=True
    detail='CleanIP：'+(c_label or '未提供')+'\nIPPure：'+('住宅 IP' if pure.get('residential') is True else ('非住宅 IP' if pure.get('residential') is False else '未提供'))
    detail+='\n'+details(result)
    if conflict:
        detail+='\n来源存在分歧；优先非住宅证据，同为负面时保留 CleanIP → IPPure → FlClash 的来源优先级。'
    elif len(evidence)==3:
        detail+='\n三方对住宅/非住宅结论一致，沿用 CleanIP 样式。'
    else:
        detail+='\n可用明确类型来源不足三方，不宣称三方已共同印证。'
    return chosen[1]+(' · 分歧' if conflict else ''),'negative' if chosen[2] else 'positive',detail,chosen[0]


def risk_annotation(result):
    """Preserve raw numbers and source flags; never synthesize a third score."""
    clean=result.get('cleanip') or {}
    original=str(clean.get('flags') or '—')
    third=usable_record(result)
    tooltip='CleanIP 风险标记：'+original
    if result.get('flclash'):tooltip+='\n'+details(result)
    if third is None:return original,tooltip
    flags=third['flags']
    nonempty=original not in ('—','-','未检出','无','None','none')
    if flags:
        label=('Fl风险：' if third['level']=='risky' else 'Fl：')+'、'.join(flags)
        if nonempty:label+='；'+original
    else:
        label=original+' · Fl：'+third['quality_label']
    return label,tooltip
