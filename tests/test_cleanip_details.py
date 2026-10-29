import json,unittest
from cleanip_details import LABELS,parse_report,risk_display

def page(hits=(),unknown=(),ip='1.1.1.1'):
    data=[{'ip':1,'ok':2,'risk':3},ip,True,{}]
    chips=''.join('<span class="risk-chip risk-chip--'+('hit' if label in hits else 'unknown' if label in unknown else 'clear')+'" title="网站依据"><span class="risk-chip__label">'+label+'</span></span>' for label in LABELS)
    return (chips+'<script id="__NUXT_DATA__" type="application/json">'+json.dumps(data)+'</script>').encode()

class DetailTests(unittest.TestCase):
    def test_explicit_hits_and_unknown_are_distinct(self):
        r=parse_report(page(('VPN','DNSBL'),('Tor',)),'1.1.1.1')
        self.assertEqual(set(r['hits']),{'VPN','DNSBL'})
        self.assertNotIn('Tor',r['hits'])
    def test_wrong_ip_rejected(self):
        with self.assertRaises(ValueError):parse_report(page(),'8.8.8.8')
    def test_error_page_rejected(self):
        with self.assertRaises(ValueError):parse_report(b'<html>verification needed</html>','1.1.1.1')
    def test_chips_missing_rejected(self):
        with self.assertRaises(ValueError):parse_report(b'<script id="__NUXT_DATA__">[{"ip":1,"ok":2,"risk":3},"1.1.1.1",true,{}]</script>','1.1.1.1')
    def test_hits_override_clear_summary_and_explain(self):
        report=parse_report(page(('VPN',)),'1.1.1.1')
        text,tip=risk_display({'flags':'未检出','risk_details':report})
        self.assertEqual(text,'VPN');self.assertIn('不一致',tip)
    def test_summary_hit_survives_clear_details(self):
        text,tip=risk_display({'flags':'代理','risk_details':parse_report(page(),'1.1.1.1')})
        self.assertEqual(text,'代理');self.assertIn('不一致',tip)
    def test_different_positive_results_explain_difference(self):
        text,tip=risk_display({'flags':'代理','risk_details':parse_report(page(('VPN',)),'1.1.1.1')})
        self.assertEqual(text,'VPN');self.assertIn('不一致',tip)
    def test_unknown_not_shown_as_incomplete_suffix(self):
        text,_=risk_display({'flags':'未检出','risk_details':parse_report(page(unknown=('Tor',)),'1.1.1.1')})
        self.assertEqual(text,'未检出')
    def test_missing_details_preserves_summary(self):
        self.assertEqual(risk_display({'flags':'VPN'})[0],'VPN')
    def test_leak_tests_excluded(self):
        raw=page().replace(b'<script', '<span class="risk-chip risk-chip--hit"><span class="risk-chip__label">DNS 泄漏</span></span><script'.encode(),1)
        self.assertEqual(parse_report(raw,'1.1.1.1')['hits'],[])
    def test_oversize_rejected(self):
        with self.assertRaises(ValueError):parse_report(b'x'*(2*1024*1024+1),'1.1.1.1')
