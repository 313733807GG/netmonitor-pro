import unittest
from app import display_provider_name, format_node_status

class ProviderDisplayTests(unittest.TestCase):
    def test_cleanup_promo_suffix(self):
        for label in ('示例服务商 - 官方网站','示例服务商（官方网站）','示例服务商 | 官网','示例服务商 官网：https://example.com'):
            self.assertEqual(display_provider_name(label),'示例服务商')
    def test_other_group_names_preserved(self):
        for label in ('GLOBAL','AI服务','香港-01','示例服务商','官网'):
            self.assertEqual(display_provider_name(label),label)
    def test_display_only_does_not_change_input(self):
        d={'ai_target_state':'confirmed','ai_group':'示例服务商 - 官方网站','ai_node':'测试节点 E1'}
        self.assertEqual(format_node_status(d),('当前AI节点: 示例服务商 → 测试节点 E1','测试节点 E1'))
        self.assertEqual(d['ai_group'],'示例服务商 - 官方网站')

if __name__=='__main__':unittest.main()
