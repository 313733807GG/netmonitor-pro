import unittest
from monitoring_state import strict_route_state
from connection_labels import service_name

class StrictRouteTests(unittest.TestCase):
    def config(self,mode='rule',enabled=True):
        return {'mode':mode,'tun':{'enable':enabled,'stack':'System','auto-route':True}}
    def test_missing_false_across_modes_and_tun_switch(self):
        for mode in ('rule','global','direct'):
            for enabled in (False,True):
                for system_proxy in (False,True):
                    with self.subTest(mode=mode,tun=enabled,system_proxy=system_proxy):
                        c=self.config(mode,enabled);c['system_proxy']=system_proxy
                        self.assertIs(strict_route_state(c),False)
    def test_explicit_values_across_modes(self):
        for mode in ('rule','global','direct'):
            for enabled in (False,True):
                for strict in (False,True):
                    c=self.config(mode,enabled);c['tun']['strict-route']=strict
                    self.assertIs(strict_route_state(c),strict)
    def test_failures_never_fabricate_off(self):
        for c in (None,{}, {'mode':'rule'}, {'mode':'rule','tun':{}}, {'mode':'rule','tun':[]}, {'mode':'rule','tun':{'enable':True}}, {'mode':'?','tun':self.config()['tun']}):
            self.assertIsNone(strict_route_state(c))
        self.assertIsNone(strict_route_state(self.config(),False))
    def test_malformed_boolean_and_false_auto_route(self):
        for value in ('false','true',0,1,None):
            c=self.config();c['tun']['strict-route']=value
            self.assertIsNone(strict_route_state(c))
        c=self.config();c['tun']['auto-route']=False
        self.assertIs(strict_route_state(c),False)
    def test_new_aliases_match_only_their_domain(self):
        for host in ('antigravity.google','antigravity-unleash.goog','ublockorigin.pages.dev','blacklist.tampermonkey.net','img-home.csdnimg.cn','captcha.gtimg.com','api.oaistatsig.com'):
            self.assertNotEqual(service_name(host),host)
        for host in ('other.pages.dev','other.run.app','fakeoaistatsig.com','other.gtimg.com'):
            self.assertEqual(service_name(host),host)

if __name__=='__main__':unittest.main()
