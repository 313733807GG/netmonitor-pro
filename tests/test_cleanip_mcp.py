import copy,json,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
import cleanip_credentials as credentials
import cleanip_mcp as m
import address_quality as a
from quality_evidence import QualityEvidence
from quality_retry import QualityRetry
from cleanip_details import risk_display
import test_address_quality as fixtures

def sample(ip='1.1.1.1'):
 return {'structuredContent':{'ip':ip,'cleanip_score':93,'grade':'A','ip_type':'Residential IP',
 'native_or_broadcast':'native','risk':{'vpn':False,'proxy':False,'tor':False,'abuse_reports':0},
 'location':{'country':'台湾','region':'台湾','city':'新北'},'scenario_scores':{'ai_subscription':92}}}

class MCPTests(unittest.TestCase):
 def test_missing_risk_score_and_unreturned_items_are_never_invented(self):
  r=m.parse_result(sample(),'1.1.1.1')
  self.assertIsNone(r['risk']);self.assertEqual(r['score'],93)
  self.assertEqual(r['ip_type'],'住宅 IP');self.assertEqual(r['native_type'],'原生 IP')
  self.assertEqual(len(r['risk_details']['items']),4)
  self.assertNotIn('DNSBL',[x['label'] for x in r['risk_details']['items']])
  self.assertNotIn('details_error',r)
  self.assertIn('未提供',risk_display(r)[1])
 def test_positive_negative_and_missing_flags_remain_distinct(self):
  s=sample();s['structuredContent']['risk']={'vpn':True,'proxy':False,'tor':None,'abuse_reports':2}
  r=m.parse_result(s,'1.1.1.1');items={x['label']:x['status'] for x in r['risk_details']['items']}
  self.assertEqual(items,{'VPN':'hit','代理':'clear','举报记录':'hit'})
  self.assertIn('VPN',r['flags']);self.assertNotIn('代理',r['flags'])
 def test_ip_mismatch_and_invalid_scores_fail_closed(self):
  with self.assertRaisesRegex(ValueError,'IP不符'):m.parse_result(sample(),'8.8.8.8')
  for value in (True,-1,101,float('nan'),None):
   s=sample();s['structuredContent']['cleanip_score']=value
   with self.assertRaises(ValueError):m.parse_result(s,'1.1.1.1')
 def test_server_error_does_not_echo_secret_or_accept_as_report(self):
  secret='cip_'+'a'*48
  with self.assertRaises(ValueError) as caught:m.parse_result({'isError':True,'content':[{'type':'text','text':secret}]},'1.1.1.1')
  self.assertNotIn(secret,str(caught.exception))
 def test_text_only_result_supported_without_guessing(self):
  obj=sample()['structuredContent'];r=m.parse_result({'content':[{'type':'text','text':json.dumps(obj)}]},'1.1.1.1')
  self.assertEqual(r['score'],93)
 def test_json_and_sse_rpc_validate_id(self):
  obj={'jsonrpc':'2.0','id':7,'result':sample()};raw=json.dumps(obj).encode()
  self.assertEqual(m.decode_rpc(raw,'application/json',7),sample())
  self.assertEqual(m.decode_rpc(b'data: '+raw+b'\n\n','text/event-stream',7),sample())
  with self.assertRaises(ValueError):m.decode_rpc(raw,'application/json',8)
 def test_route_mismatch_sends_no_key_or_http_request(self):
  p=Mock();p.configs.return_value={'mode':'rule'};conn=Mock();conn.sock.getsockname.return_value=('127.0.0.1',1234)
  client=m.Client(p,'N','cip_'+'a'*48)
  with patch.object(m.http.client,'HTTPSConnection',return_value=conn),patch.object(a.q,'connection_for_port',return_value={'chains':['OTHER',a.q.PROBE_GROUP]}):
   with self.assertRaisesRegex(ValueError,'未发送'):client.query('1.1.1.1')
  conn.request.assert_not_called();conn.close.assert_called_once()
 def test_cancel_before_connect_never_sends_key(self):
  owner=Mock();owner.isInterruptionRequested.return_value=True
  with patch.object(m.http.client,'HTTPSConnection') as ctor:
   with self.assertRaisesRegex(OSError,'取消'):m.Client(Mock(),'N','secret',owner).query('1.1.1.1')
  ctor.assert_not_called()
 def test_auth_headers_are_only_sent_to_fixed_https_endpoint(self):
  p=Mock();p.configs.return_value={'mode':'rule'};conn=Mock();conn.sock.getsockname.return_value=('127.0.0.1',1234)
  response=conn.getresponse.return_value;response.status=401
  client=m.Client(p,'N','cip_'+'a'*48)
  with patch.object(m.http.client,'HTTPSConnection',return_value=conn),patch.object(a.q,'connection_for_port',return_value={'chains':['N',a.q.PROBE_GROUP]}):
   with self.assertRaisesRegex(ValueError,'401'):client.query('1.1.1.1')
  conn.set_tunnel.assert_called_once_with('cleanip.io',443)
  self.assertEqual(conn.request.call_args.args[:2],('POST','/mcp'))
  self.assertNotIn(client.key,conn.request.call_args.kwargs['body'].decode())
  conn.close.assert_called_once()
 def test_client_initializes_once_for_two_ips(self):
  client=m.Client(Mock(),'N','secret')
  with patch.object(client,'_request',side_effect=[{'protocolVersion':'2025-03-26'},{},sample(),sample('2606:4700::1111')]) as request:
   self.assertEqual(client.query('1.1.1.1')['score'],93)
   self.assertEqual(client.query('2606:4700::1111')['ip'],'2606:4700::1111')
  self.assertEqual([x.args[0] for x in request.call_args_list],['initialize','notifications/initialized','tools/call','tools/call'])
 def test_missing_key_requires_configuration_without_legacy_web_fallback(self):
  p,request,unused,calls,state=fixtures.AddressTests().setup_case()
  def get(pipe,host,path,*args,**kw):
   if 'icanhazip' in host:raise OSError('echo unavailable')
   return request(pipe,host,path,*args,**kw)
  with patch.object(a.q,'proxy_get',side_effect=get),patch.object(credentials,'load_key',return_value=''),patch.object(a,'CleanIPClient') as client:
   result=a.collect_quality(p,'N')
  self.assertNotIn('cleanip',result);self.assertIn('网页已改版',result['errors']['cleanip'])
  self.assertIn('configure_cleanip.py',result['errors']['cleanip'])
  self.assertFalse(any(site=='cleanip' for site,ip in result['queried']))
  client.assert_not_called();self.assertFalse(any(host=='cleanip.io' for host,path in calls))
  self.assertEqual(state['now'],'REJECT')
 def test_api_queries_both_ips_and_restores_selector(self):
  p,request,unused,calls,state=fixtures.AddressTests().setup_case()
  with patch.object(a.q,'proxy_get',side_effect=request),patch.object(credentials,'load_key',return_value='secret'),patch.object(a,'CleanIPClient') as client:
   client.return_value.query.side_effect=lambda ip:m.parse_result(sample(ip),ip)
   result=a.collect_quality(p,'N')
  self.assertEqual(client.return_value.query.call_count,2)
  self.assertFalse(any(host=='cleanip.io' for host,path in calls));self.assertEqual(state['now'],'REJECT')
  self.assertIsNone(result['cleanip']['risk'])
 def test_quota_failure_stops_second_ip_and_does_not_retry_or_leak(self):
  p,request,unused,calls,state=fixtures.AddressTests().setup_case()
  with patch.object(a.q,'proxy_get',side_effect=request),patch.object(credentials,'load_key',return_value='secret'),patch.object(a,'CleanIPClient') as client:
   client.return_value.query.side_effect=ValueError('CleanIP API HTTP 429：额度受限')
   result=a.collect_quality(p,'N')
  self.assertEqual(client.return_value.query.call_count,1);self.assertEqual(state['now'],'REJECT')
  retry=QualityRetry();retry.completed(('p','N'),result,0);self.assertFalse(retry.due(('p','N'),100))
 def test_cached_success_does_not_read_key_or_call_api(self):
  p,request,unused,calls,state=fixtures.AddressTests().setup_case(True)
  cache={'discovery':{'ips':{'4':'1.1.1.1'},'errors':{}},'records':[
   {'source':'cleanip','data':m.parse_result(sample(),'1.1.1.1')},
   {'source':'ippure','data':{'ip':'1.1.1.1','score':3}}]}
  with patch.object(credentials,'load_key') as loader,patch.object(a,'CleanIPClient') as client:
   result=a.collect_quality(p,'N',family=4,cache=cache)
  loader.assert_not_called();client.assert_not_called();self.assertEqual(len(result['reused']),2)
 def test_none_risk_cache_sorting_mixes_with_old_numeric_scores(self):
  api=m.parse_result(sample(),'1.1.1.1');old=dict(api,ip='2606:4700::1111',risk=7)
  r={'node':'N','route_verified':True,'observations':[{'source':'cleanip','data':x} for x in (api,old)]}
  e=QualityEvidence();e.record(('p','N'),r);v=e.view(('p','N'),r)
  self.assertEqual(v['cleanip']['risk'],7)
 def test_dpapi_storage_has_no_plaintext_and_roundtrips(self):
  key='cip_'+'a'*48
  with tempfile.TemporaryDirectory() as directory,patch.object(credentials,'credential_path',return_value=Path(directory)/'key.dpapi'):
   credentials.save_key(key)
   # Runner patches load_key to isolate all other offline tests.
   raw=credentials.credential_path().read_bytes()
   self.assertNotIn(key.encode(),raw);self.assertEqual(credentials._crypt(raw).decode(),key)
   with self.assertRaises(ValueError):credentials.save_key(key+'\r\nInjected: x')


class RetryGuardTests(unittest.TestCase):
 def test_other_site_timeout_does_not_retry_cleanip_access_barrier(self):
  retry=QualityRetry();key=('p','N')
  retry.completed(key,{'errors':{'cleanip':'CleanIP API HTTP 429：额度受限','ippure':'timeout'}},0)
  self.assertFalse(retry.due(key,100))
