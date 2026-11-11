import unittest,subprocess,os,importlib.util
from unittest.mock import patch
import address_quality as a
import test_address_quality as fixtures

class NoBrowserTests(unittest.TestCase):
 def test_automatic_manual_and_family_queries_never_spawn_programs(self):
  for family,force in ((None,False),(None,True),(4,True),(6,True)):
   p,request,unused,calls,state=fixtures.AddressTests().setup_case()
   with patch.object(a.q,'proxy_get',side_effect=request),fixtures.authorized_client(request),patch.object(subprocess,'Popen',side_effect=AssertionError('external launch forbidden')),patch.object(os,'startfile',side_effect=AssertionError('external launch forbidden')):
    result=a.collect_quality(p,'N',family=family,force=force)
   self.assertEqual(state['now'],'REJECT');self.assertIn('cleanip',result)
   if family==6:self.assertNotIn('ippure',result)
   if family in (None,6):self.assertIn('轻量接口未取得',result['errors']['ippure'])
 def test_browser_runtime_modules_are_absent(self):
  for name in ('browser_lookup','browser_proxy_gate','external_process','websocket'):
   self.assertIsNone(importlib.util.find_spec(name),name)
 def test_public_failure_cause_is_preserved(self):
  p,request,unused,calls,state=fixtures.AddressTests().setup_case()
  def get(pipe,host,path,*args,**kw):
   if host=='my.ippure.com':raise ValueError('检测接口 HTTP 429')
   return request(pipe,host,path,*args,**kw)
  with patch.object(a.q,'proxy_get',side_effect=get),fixtures.authorized_client(get):result=a.collect_quality(p,'N')
  self.assertIn('429',result['errors']['ippure']);self.assertIn('cleanip',result)

if __name__=='__main__':unittest.main()
