"""Maintainer-only single-IP query using the local encrypted key and verified node.
Run with the independent Python -I tools/check_cleanip.py [public_ip].
Omitting the IP discovers the current node's IPv4. Never switches ordinary groups.
"""
import json,site,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
site.addsitedir(str(ROOT/'.runtime/site-packages'));sys.path.insert(0,str(ROOT/'src'))
from pipe_client import MihomoPipe
from cleanip_credentials import load_key
from cleanip_mcp import Client
from lookup_parsers import public_ip
import ip_quality as q

def main():
    key=load_key()
    if not key:raise ValueError('请先配置本机 CleanIP API 密钥')
    pipe=MihomoPipe()
    if not pipe._detect():raise ValueError('代理控制接口不可用')
    pipe=pipe.fixed_session();snapshot=pipe.proxies();cfg=pipe.configs()
    target=q.ai_target(pipe.connections().get('connections',[]),snapshot,cfg.get('mode'))
    if target['state']!='confirmed':raise ValueError('等待 AI 出口确认')
    group=snapshot['proxies'].get(q.PROBE_GROUP,{})
    if group.get('now')!='REJECT':raise ValueError('已有检测正在运行，请稍后再查')
    ip=public_ip(sys.argv[1]) if len(sys.argv)>1 else None
    if not pipe.select_probe_node(target['node']):raise ValueError('无法设置专用检测出口')
    try:
        if ip is None:
            raw,_=q.proxy_get(pipe,'ipv4.icanhazip.com','/',q.PROBE_PORT,target['node'],max_bytes=128)
            ip=public_ip(raw.decode('ascii'),4)
        result=Client(pipe,target['node'],key).query(ip)
    finally:
        if not pipe.select_probe_node('REJECT'):raise ValueError('专用组恢复失败，请检查代理控制接口')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':
    try:
        if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8')
        main()
    except Exception as exc:
        print('CleanIP check failed: '+str(exc),file=sys.stderr);sys.exit(1)
