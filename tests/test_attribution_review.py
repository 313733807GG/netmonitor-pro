import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import attribution_ledger as al
import connection_labels as cl
import unknown_log as ul


class CandidateLabelTests(unittest.TestCase):
    def test_domain_candidate_uses_clean_name_but_stays_in_review(self):
        row = {'host': 'abc.rdt.tfogc.com', 'raw_host': 'abc.rdt.tfogc.com',
               'proc': 'sample.exe'}
        self.assertEqual(cl.connection_name(row), '腾讯 · 下载分发')
        self.assertTrue(cl.needs_review(row))
        self.assertIn('微信官方下载路径', cl.label_basis(row))
        self.assertEqual(cl.service_name('nottfogc.com'), 'nottfogc.com')
        for _, label, _ in cl.CANDIDATE_SERVICES:
            for marker in ('疑似', '待复核', '历史关联'):
                self.assertNotIn(marker, label)
        for candidate in cl.IP_CANDIDATES:
            for marker in ('疑似', '待复核', '历史关联'):
                self.assertNotIn(marker, candidate['label'])

    def test_existing_specific_pages_name_is_not_shadowed(self):
        self.assertEqual(cl.service_name('ublockorigin.pages.dev'),
                         'uBlock Origin · 过滤规则')

    def test_20261103_confirmed_and_candidate_boundaries(self):
        for host in ('gemini.google', 'p26-item.ecombdimg.com',
                     'hdaa.shuzilm.cn', 'my.microsoftpersonalcontent.com'):
            self.assertFalse(cl.needs_review({'host': host}), host)
        self.assertEqual(cl.service_name('other.r2.dev'), 'other.r2.dev')
        self.assertEqual(cl.service_name('other.microsoftpersonalcontent.com'),
                         'other.microsoftpersonalcontent.com')
        self.assertTrue(cl.needs_review({'host': 'default.exp-tas.com'}))
        self.assertEqual(cl.service_name('default.exp-tas.com'), '微软 · 实验配置')
        self.assertIn('最新微软Edge端点页', cl.label_basis({'host': 'default.exp-tas.com'}))

    def test_all_ip_candidates_require_full_context(self):
        for candidate in cl.IP_CANDIDATES:
            with self.subTest(candidate=candidate['host']):
                row = {'host': candidate['host'], 'raw_host': candidate['host'],
                       'proc': 'ImeService.exe',
                       'process_path': 'C:\\Program Files\\DoubaoIME\\versions\\v1\\ImeService.exe',
                       'destination_port': 443, 'network': 'udp'}
                self.assertEqual(cl.ip_candidate(row), candidate)
                self.assertEqual(cl.connection_name(row), '豆包输入法 · 接口')
                self.assertIn('非永久IP归属', cl.label_basis(row))
                self.assertTrue(cl.needs_review(row))
                self.assertEqual(cl.service_name(candidate['host']), candidate['host'])

    def test_ip_candidate_rejects_changed_context(self):
        row = {'host': '122.14.229.138', 'raw_host': '122.14.229.138',
               'proc': 'ImeService.exe',
               'process_path': 'C:\\Program Files\\DoubaoIME\\versions\\v1\\ImeService.exe',
               'destination_port': 443, 'network': 'udp'}
        changes = (
            {'proc': 'chrome.exe'},
            {'process_path': 'C:\\Other\\ImeService.exe'},
            {'destination_port': 80},
            {'network': 'tcp'},
            {'destination_port': 'invalid'},
        )
        for change in changes:
            with self.subTest(change=change):
                self.assertIsNone(cl.ip_candidate(row | change))

    def test_same_ip_only_evidence_does_not_create_label(self):
        row = {'host': '182.244.29.177', 'raw_host': '182.244.29.177',
               'proc': 'MuMuNxDevice.exe', 'destination_port': 443, 'network': 'tcp'}
        self.assertIsNone(cl.ip_candidate(row))
        self.assertNotIn('疑似', cl.connection_name(row))

    def test_candidate_records_survive_unknown_log_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'unknown.json')
            log = ul.UnknownTargetLog(path)
            rows = [
                {'host': 'abc.smtcdns.net', 'raw_host': 'abc.smtcdns.net'},
                {'host': '122.14.229.138', 'raw_host': '122.14.229.138',
                 'proc': 'ImeService.exe',
                 'process_path': 'C:\\Program Files\\DoubaoIME\\v1\\ImeService.exe',
                 'destination_port': 443, 'network': 'udp'},
                {'host': '8.9.10.11', 'raw_host': '8.9.10.11'},
            ]
            log.note(rows, 'proxy')
            log.flush()
            retained = ul.UnknownTargetLog(path).items
            self.assertEqual(len(retained), 2)
            self.assertNotIn('8.9.10.11', retained)


class AttributionLedgerTests(unittest.TestCase):
    def ledger(self):
        return {
            'schema_version': 1,
            'targets': {
                'smtcdns.net': {'kind': 'domain_suffix', 'value': 'smtcdns.net',
                                'status': 'candidate', 'score': 65},
                '8.8.8.8': {'kind': 'ip_exact', 'value': '8.8.8.8',
                            'status': 'weak', 'score': 20},
            },
            'rounds': [],
        }

    def test_observe_preserves_prior_rounds_and_does_not_mutate_input(self):
        original = self.ledger()
        before = copy.deepcopy(original)
        records = [
            {'host': 'a.smtcdns.net', 'review_category': 'domain', 'count': 3,
             'first': '2026-01-01', 'last': '2026-01-02'},
            {'host': 'b.smtcdns.net', 'review_category': 'domain', 'count': 4,
             'first': '2025-12-01', 'last': '2026-01-03'},
            {'host': '8.8.8.8', 'review_category': 'ip', 'count': 2},
        ]
        first = al.observe_round(original, records, '2026-01-03T00:00:00+08:00')
        self.assertEqual(original, before)
        target = first['targets']['smtcdns.net']
        self.assertEqual(target['observations'][0]['poll_observations'], 7)
        self.assertEqual(target['observations'][0]['first'], '2025-12-01')
        self.assertEqual(first['rounds'][0]['active_targets']['candidate'], 1)
        second = al.observe_round(first, [], '2026-01-04T00:00:00+08:00')
        self.assertEqual(len(second['targets']['smtcdns.net']['observations']), 2)
        self.assertFalse(second['targets']['smtcdns.net']['observations'][-1]['active'])
        self.assertTrue(second['targets']['smtcdns.net']['observations'][0]['active'])

    def test_review_appends_instead_of_erasing_history(self):
        first = al.review_target(self.ledger(), 'smtcdns.net', 'confirmed', 90,
                                 'first-party evidence', '2026-01-01',
                                 evidence=['https://example.com/official'])
        second = al.review_target(first, 'smtcdns.net', 'rejected', 10,
                                  'later evidence contradicts it', '2026-01-02')
        reviews = second['targets']['smtcdns.net']['reviews']
        self.assertEqual([r['result'] for r in reviews], ['confirmed', 'rejected'])
        self.assertEqual(second['rounds'][-1]['result'], 'rejected')
        self.assertEqual(second['targets']['smtcdns.net']['score'], 10)

    def test_observation_retention_is_bounded(self):
        ledger = self.ledger()
        with patch.object(al, 'MAX_OBSERVATIONS', 1):
            first = al.observe_round(ledger, [], '2026-01-01')
            second = al.observe_round(first, [], '2026-01-02')
        target = second['targets']['smtcdns.net']
        self.assertEqual(len(target['observations']), 1)
        self.assertEqual(target['observations_evicted'], 1)

    def test_invalid_review_is_rejected(self):
        with self.assertRaises(ValueError):
            al.review_target(self.ledger(), 'smtcdns.net', 'candidate', 101,
                             'invalid', '2026-01-01')
        with self.assertRaises(ValueError):
            al.observe_round({'schema_version': 99}, [], '2026-01-01')


if __name__ == '__main__':
    unittest.main()
