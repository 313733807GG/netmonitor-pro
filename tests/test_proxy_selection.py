import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import app
from app import (
    AI_PROBE_URL,
    BLUE,
    GREEN,
    RED,
    YELLOW,
    DataEngine,
    choose_primary_route,
    connection_class,
    connection_color,
    effective_proxy_takeover,
    format_node_status,
    format_proxy_speed_pair,
    health_text,
    health_tooltip,
    is_local_address,
    is_loopback_address,
    proxy_server_ports,
    proxy_action_node,
    proxy_action_state,
    proxy_health_key,
    register_health_probe_port,
    resolve_connection_owner,
    source_process_name,
    supplemental_system_status,
    traffic_role_for,
)
from pipe_client import MihomoPipe


class ProxySelectionTests(unittest.TestCase):
    @staticmethod
    def pipe_with(proxies):
        pipe = MihomoPipe()
        pipe.proxies = lambda: {"proxies": proxies}
        return pipe

    def test_rule_selection_never_falls_back_to_global(self):
        pipe = self.pipe_with({
            "GLOBAL": {"type": "Selector", "now": "香港D | 家宽 | 直连"},
            "闪现": {"type": "Selector", "now": "日本B | 原生 | 直连"},
            "自动选择": {"type": "URLTest", "now": "日本A | 原生 | 直连"},
            "故障转移": {"type": "Fallback", "now": "日本B | 原生 | 直连"},
        })

        self.assertEqual(pipe.main_selection(), ("闪现", "日本B | 原生 | 直连"))
        self.assertEqual(pipe.global_selection(), "香港D | 家宽 | 直连")

    def test_nested_rule_group_uses_root_selector_and_leaf_node(self):
        pipe = self.pipe_with({
            "GLOBAL": {"type": "Selector", "now": "备用节点"},
            "自动选择": {"type": "URLTest", "now": "日本A"},
            "节点选择": {"type": "Selector", "now": "自动选择"},
        })

        self.assertEqual(pipe.main_selection(), ("节点选择", "日本A"))

    def test_ai_selection_resolves_decorated_group_to_fixed_leaf(self):
        pipe = self.pipe_with({
            "国外网站": {"type": "Selector", "now": "台湾A"},
            "🧚 AI服务": {"type": "Selector", "now": "AI固定节点"},
            "AI固定节点": {"type": "Hysteria2"},
        })

        self.assertEqual(
            pipe.ai_selection(),
            ("🧚 AI服务", "AI固定节点", "Selector"),
        )

    def test_ai_selection_resolves_nested_group_but_never_uses_active_route(self):
        pipe = self.pipe_with({
            "AI服务": {"type": "Selector", "now": "AI子组"},
            "AI子组": {"type": "URLTest", "now": "日本AI"},
            "国外网站": {"type": "Selector", "now": "台湾A"},
        })

        self.assertEqual(pipe.ai_selection(), ("AI服务", "日本AI", "Selector"))

    def test_ai_selection_fails_closed_when_group_is_missing_or_direct(self):
        self.assertIsNone(self.pipe_with({
            "节点列表": {"type": "Selector", "now": "日本A"},
            "国外网站": {"type": "Selector", "now": "台湾A"},
        }).ai_selection())
        self.assertIsNone(self.pipe_with({
            "AI服务": {"type": "Selector", "now": "DIRECT"},
        }).ai_selection())

    def test_live_bytes_outrank_idle_connection_count(self):
        stats = {
            ("旧策略", "旧节点"): [0, 20],
            ("闪现", "日本B"): [4096, 1],
        }
        self.assertEqual(choose_primary_route(stats), ("闪现", "日本B"))

    def test_connection_count_is_idle_fallback(self):
        stats = {
            ("策略A", "节点A"): [0, 2],
            ("策略B", "节点B"): [0, 7],
        }
        self.assertEqual(choose_primary_route(stats), ("策略B", "节点B"))
        self.assertEqual(choose_primary_route({}), ("", ""))

    def test_rule_label_prefers_real_chain_over_global_configuration(self):
        label, node = format_node_status({
            "mode": "rule",
            "global_now": "香港D",
            "sel_group": "GLOBAL",
            "sel_node": "香港D",
            "active_group": "闪现",
            "active_node": "日本B",
        })
        self.assertEqual(label, "当前流量: 闪现 → 日本B")
        self.assertEqual(node, "日本B")

    def test_global_label_uses_global_chain(self):
        label, node = format_node_status({
            "mode": "global",
            "global_now": "新加坡A",
            "active_group": "闪现",
            "active_node": "日本B",
        })
        self.assertEqual(label, "全局出口: 🌐 新加坡A")
        self.assertEqual(node, "新加坡A")

        pending_label, pending_node = format_node_status({
            "mode": "global", "global_now": "", "sel_node": "规则模式旧选择",
        })
        self.assertEqual(pending_label, "全局出口: 检测中…")
        self.assertEqual(pending_node, "—")

    def test_direct_and_reject_routes_are_not_presented_as_proxy_nodes(self):
        label, node = format_node_status({"mode": "direct"})
        self.assertEqual(label, "路由模式: 🎯 DIRECT（新连接直连）")
        self.assertEqual(node, "DIRECT")

        label, node = format_node_status({
            "mode": "global", "global_now": "REJECT-DROP",
        })
        self.assertEqual(label, "全局出口: ⛔ REJECT（拦截）")
        self.assertEqual(node, "REJECT-DROP")
        self.assertEqual(proxy_action_node({
            "mode": "global", "global_now": "REJECT-DROP",
        }), "")

    def test_rule_label_reports_the_dominant_actual_route(self):
        label, node = format_node_status({
            "mode": "rule",
            "active_route_group": "局域网",
            "active_route_exit": "DIRECT",
            "active_group": "节点选择",
            "active_node": "日本B",
        })
        self.assertEqual(label, "当前流量: 局域网 → DIRECT（直连）")
        self.assertEqual(node, "DIRECT")

    def test_top_proxy_labels_show_directional_rates(self):
        self.assertEqual(
            format_proxy_speed_pair({"proxy_up": 2048, "proxy_down": 3 * 1024}),
            ("↑2K/s", "↓3K/s"),
        )

    def test_top_proxy_labels_preserve_combined_only_fallback(self):
        self.assertEqual(
            format_proxy_speed_pair({"proxy_up": 0, "proxy_down": 0, "proxy_total": 4096}),
            ("⇅4K/s", "合计"),
        )

    def test_estimated_proxy_total_is_visibly_marked(self):
        self.assertEqual(
            format_proxy_speed_pair({
                "proxy_up": 0, "proxy_down": 0, "proxy_total": 4096,
                "proxy_total_estimated": True,
            }),
            ("≈4K/s", "估算"),
        )

    def test_proxy_actions_reject_missing_or_inactive_proxy(self):
        allowed, hint = proxy_action_state({"sw_on": False})
        self.assertFalse(allowed)
        self.assertIn("未检测到代理软件", hint)

        allowed, hint = proxy_action_state({
            "sw_on": True, "takeover": False, "mode": "rule",
        })
        self.assertFalse(allowed)
        self.assertIn("未接管网络", hint)

        allowed, hint = proxy_action_state({
            "sw_on": True, "takeover": True, "mode": "direct",
        })
        self.assertFalse(allowed)
        self.assertIn("直连模式", hint)

        allowed, hint = proxy_action_state({
            "sw_on": True, "takeover": True, "mode": "global",
            "global_now": "DIRECT", "api_on": True,
        })
        self.assertFalse(allowed)
        self.assertIn("GLOBAL 当前选择 DIRECT", hint)

        allowed, hint = proxy_action_state({
            "sw_on": True, "takeover": True, "mode": "global",
            "global_now": "REJECT-DROP", "api_on": True,
        })
        self.assertFalse(allowed)
        self.assertIn("拦截出口", hint)

        allowed, hint = proxy_action_state({
            "sw_on": True, "takeover": True, "mode": "rule",
            "api_on": False,
        })
        self.assertFalse(allowed)
        self.assertIn("无法绕过分流", hint)

        allowed, hint = proxy_action_state({
            "sw_on": True, "takeover": True, "mode": "rule",
            "api_on": True, "ai_group": "", "ai_node": "",
        })
        self.assertFalse(allowed)
        self.assertIn("不会回退", hint)

    def test_proxy_actions_allow_real_node_and_background_core(self):
        ready = {
            "sw_on": True, "takeover": True, "mode": "rule", "api_on": True,
            "active_node": "台湾国外网站", "ai_group": "AI服务",
            "ai_node": "日本AI", "ai_group_type": "Selector", "gui_alive": True,
        }
        self.assertEqual(proxy_action_state(ready), (True, ""))
        self.assertEqual(proxy_action_node(ready), "日本AI")

        background = dict(ready, gui_alive=False)
        allowed, hint = proxy_action_state(background)
        self.assertTrue(allowed)
        self.assertIn("后台内核节点", hint)

        auto_group = dict(ready, ai_group_type="URLTest")
        allowed, hint = proxy_action_state(auto_group)
        self.assertTrue(allowed)
        self.assertIn("策略组本身可能切换", hint)

    def test_ai_health_copy_identifies_rule_bypass_and_locked_leaf(self):
        result = {
            "kind": "ai_probe", "ok": True,
            "group": "AI服务", "node": "日本AI",
            "checks": [
                {"label": "ChatGPT", "url": AI_PROBE_URL,
                 "ok": True, "delay": 123},
                {"label": "OpenAI", "url": "https://openai.com/favicon.ico",
                 "ok": False, "delay": 0},
            ],
        }
        lines = health_text(result)
        self.assertIn("AI目标: AI服务 → 日本AI", lines[0])
        self.assertIn("ChatGPT 123ms", lines[1])
        self.assertIn("部分目标异常", lines[2])
        tip = health_tooltip(result)
        self.assertIn("指定叶子节点", tip)
        self.assertIn("绕过订阅", tip)

    def test_proxy_action_node_ignores_global_and_active_routes(self):
        data = {
            "mode": "global", "global_now": "新加坡A",
            "active_node": "台湾国外网站", "sel_node": "香港D",
            "ai_group": "AI服务", "ai_node": "日本AI",
        }
        self.assertEqual(proxy_action_node(data), "日本AI")

    def test_effective_takeover_distinguishes_capture_from_proxy_routing(self):
        self.assertTrue(effective_proxy_takeover({
            "sw_on": True, "takeover": True, "mode": "rule",
            "gui_alive": False,
        }))
        self.assertFalse(effective_proxy_takeover({
            "sw_on": True, "takeover": True, "mode": "direct",
        }))
        self.assertFalse(effective_proxy_takeover({
            "sw_on": True, "takeover": False, "mode": "rule",
        }))
        self.assertFalse(effective_proxy_takeover({
            "sw_on": True, "takeover": True, "mode": "global",
            "global_now": "DIRECT",
        }))
        self.assertFalse(effective_proxy_takeover({
            "sw_on": True, "takeover": True, "mode": "global",
            "global_now": "REJECT-DROP",
        }))
        self.assertTrue(effective_proxy_takeover({
            "sw_on": True, "takeover": True, "mode": "global",
            "global_now": "新加坡A",
        }))

    def test_health_results_have_no_target_in_non_proxy_states(self):
        self.assertEqual(proxy_health_key({
            "sw_on": True, "takeover": True, "mode": "global",
            "global_now": "DIRECT", "api_on": True,
        }), "")
        self.assertEqual(proxy_health_key({
            "sw_on": True, "takeover": True, "mode": "direct",
            "api_on": True, "sel_node": "旧节点",
        }), "")
        self.assertEqual(proxy_health_key({
            "sw_on": True, "takeover": True, "mode": "rule",
            "api_on": True, "active_node": "台湾国外网站",
            "ai_group": "AI服务", "ai_node": "日本AI",
        }), "AI|AI服务|日本AI")
        self.assertEqual(proxy_health_key({
            "sw_on": True, "takeover": True, "mode": "?",
            "api_on": False, "sw_name": "FlClash", "sp_srv": "127.0.0.1:7897",
        }), "")

    def test_connection_colors_share_one_category_mapping(self):
        self.assertEqual(connection_color({"kind": "sys"}), BLUE)
        self.assertEqual(connection_color({"kind": "sys", "fact_proxy": True}), BLUE)
        self.assertEqual(connection_color({"kind": "sys", "is_proxy_sw": True}), BLUE)
        self.assertEqual(connection_color({
            "kind": "sys", "actual_route_kind": "proxy",
        }), YELLOW)
        self.assertEqual(connection_color({"kind": "direct"}), GREEN)
        self.assertEqual(connection_color({"kind": "proxy"}), YELLOW)
        self.assertEqual(connection_color({"kind": "reject"}), RED)

    def test_supplemental_badges_cannot_contradict_their_colors(self):
        cases = (
            ({"kind": "sys", "proxy_socket_count": 0, "direct_socket_count": 2},
             "系统连接", "system", BLUE),
            ({"kind": "sys", "proxy_socket_count": 1, "direct_socket_count": 0},
             "路径待确认", "system", BLUE),
            ({"kind": "sys", "proxy_socket_count": 1, "direct_socket_count": 2},
             "路径待确认", "system", BLUE),
        )
        for row, badge, display_class, color in cases:
            self.assertEqual(supplemental_system_status(row), (badge, display_class))
            row["display_class"] = display_class
            self.assertEqual(connection_class(row), display_class)
            self.assertEqual(connection_color(row), color)

        # A local proxy socket alone never claims a paid-node route.
        stale = {
            "kind": "sys", "fact_proxy": True, "direct_socket_count": 1,
            "display_class": "proxy",
        }
        self.assertEqual(connection_class(stale), "system")
        self.assertEqual(connection_color(stale), BLUE)
        self.assertEqual(supplemental_system_status(stale)[0], "路径待确认")

    def test_connection_owner_does_not_switch_when_a_port_is_reused(self):
        first = resolve_connection_owner(
            metadata_process="Doubao.exe",
            metadata_path=r"C:\Apps\Doubao.exe",
            socket_owner=(101, "Doubao.exe"),
            socket_source="socket_exact",
            pid_paths={101: r"C:\Apps\Doubao.exe"},
            pid_start_times={101: 1000.5},
            observed_at=10,
        )
        reused = resolve_connection_owner(
            metadata_process="Doubao.exe",
            metadata_path=r"C:\Apps\Doubao.exe",
            socket_owner=(202, "MSI.CentralServer.exe"),
            socket_source="socket_exact",
            cached=first,
            pid_paths={202: r"C:\MSI\MSI.CentralServer.exe"},
            pid_start_times={202: 2000.5},
            observed_at=20,
        )
        self.assertEqual(reused["pid"], 101)
        self.assertEqual(reused["name"], "Doubao.exe")
        self.assertEqual(reused["start_time"], 1000.5)
        self.assertEqual(reused["confidence"], "high")

    def test_unknown_owner_can_be_upgraded_but_known_socket_owner_is_sticky(self):
        unknown = resolve_connection_owner(observed_at=1)
        known = resolve_connection_owner(
            socket_owner=(33, "Kimi.exe"), socket_source="socket_exact",
            cached=unknown, observed_at=2,
        )
        conflicting = resolve_connection_owner(
            socket_owner=(44, "Other.exe"), socket_source="socket_exact",
            cached=known, observed_at=3,
        )
        self.assertEqual(known["pid"], 33)
        self.assertEqual(conflicting["pid"], 33)

    def test_health_probe_source_port_is_isolated_from_user_traffic(self):
        register_health_probe_port(
            54321, "www.gstatic.com", observed_at=100, ttl=60,
        )
        self.assertEqual(
            traffic_role_for(54321, "www.gstatic.com", "NetMonitor.exe",
                             observed_at=110),
            "health_check",
        )
        self.assertEqual(
            traffic_role_for(54321, "example.com", "Browser.exe", observed_at=111),
            "user",
        )
        self.assertEqual(
            traffic_role_for(54322, "example.com", "Browser.exe", observed_at=110),
            "user",
        )

    def test_loopback_and_private_address_detection_handles_windows_forms(self):
        self.assertTrue(is_loopback_address("127.0.0.1"))
        self.assertTrue(is_loopback_address("::1"))
        self.assertTrue(is_loopback_address("::ffff:127.0.0.1"))
        self.assertTrue(is_local_address("[fe80::1%12]"))
        self.assertTrue(is_local_address("192.168.1.2"))
        self.assertFalse(is_local_address("8.8.8.8"))

    def test_windows_proxy_setting_ports_support_per_protocol_format(self):
        self.assertEqual(proxy_server_ports("127.0.0.1:7897"), [7897])
        self.assertEqual(
            proxy_server_ports("http=127.0.0.1:7890;https=127.0.0.1:7891"),
            [7890, 7891],
        )
        self.assertEqual(proxy_server_ports("socks=[::1]:1080"), [1080])

    def test_source_process_mapping_never_uses_an_ambiguous_port(self):
        exact = {("127.0.0.1", 50123): (10, "browser.exe")}
        safe_ports = {50124: (20, "player.exe")}
        self.assertEqual(
            source_process_name(exact, safe_ports, "127.0.0.1", 50123),
            "browser.exe",
        )
        self.assertEqual(
            source_process_name(exact, safe_ports, "::1", 50124),
            "player.exe",
        )
        self.assertEqual(
            source_process_name(exact, safe_ports, "127.0.0.1", 50125),
            "?",
        )

    def test_mihomo_byte_delta_is_written_to_persistent_ledger(self):
        class FakeTraffic:
            status = "running"
            accurate = True
            elevated = True
            event_count = 10

            @staticmethod
            def snapshot():
                return {}

            @staticmethod
            def status_text():
                return "test"

        class FakeHistory:
            status = "running"
            last_error = ""
            db_path = r"C:\test\history.sqlite3"
            dropped_batches = 0

            def __init__(self):
                self.rows = []
                self.observed_at = None

            def record(self, rows, observed_at=None):
                self.rows.extend(rows)
                self.observed_at = observed_at
                return True

        class FakePipe:
            channel_name = "test-pipe"

            @staticmethod
            def available():
                return True

            @staticmethod
            def configs():
                return {"mode": "rule", "tun": {"enable": True}}

            @staticmethod
            def proxies():
                return {"proxies": {}}

            @staticmethod
            def active_groups(_snapshot):
                return []

            @staticmethod
            def main_selection(_snapshot):
                return None

            @staticmethod
            def ai_selection(_snapshot):
                return None

            @staticmethod
            def global_selection(_snapshot):
                return ""

            @staticmethod
            def connections():
                return {"connections": [{
                    "id": "connection-1",
                    "upload": 400,
                    "download": 900,
                    "rule": "DOMAIN-SUFFIX",
                    "rulePayload": "kimi.com",
                    "chains": ["香港 3倍消耗", "国外流量"],
                    "metadata": {
                        "host": "api.kimi.com",
                        "destinationIP": "1.2.3.4",
                        "destinationPort": 443,
                        "sourceIP": "127.0.0.1",
                        "sourcePort": 50123,
                        "network": "tcp",
                    },
                }]}

        engine = DataEngine.__new__(DataEngine)
        engine.pipe = FakePipe()
        engine.traffic = FakeTraffic()
        engine.history = FakeHistory()
        engine.last_net = SimpleNamespace(bytes_sent=1000, bytes_recv=2000)
        engine.last_time = time.time() - 1
        engine.conn_bytes = {"connection-1": (100, 200)}
        engine.port_pid = {("127.0.0.1", 50123): (1234, "Kimi.exe")}
        engine.port_pid_by_port = {}
        engine.pid_paths = {1234: r"C:\Apps\Kimi\Kimi.exe"}
        engine._ptr_cache = {}
        engine._ptr_pending = set()
        engine._proc_rates = {}
        engine._scan_ports = lambda: None
        engine.system_proxy = lambda: (True, "127.0.0.1:7897")
        engine._detect_sw = lambda _api, _server: ""
        engine.gui_alive = lambda: True

        net = SimpleNamespace(bytes_sent=1000, bytes_recv=2000)
        with patch.object(app.psutil, "net_io_counters", return_value=net):
            result = engine.tick()

        self.assertEqual(result["n_proxy"], 1)
        self.assertEqual(len(engine.history.rows), 1)
        row = engine.history.rows[0]
        self.assertEqual(row["process_pid"], 1234)
        self.assertEqual(row["process_name"], "Kimi.exe")
        self.assertEqual(row["process_path"], r"C:\Apps\Kimi\Kimi.exe")
        self.assertEqual(row["source_port"], 50123)
        self.assertEqual(row["owner_source"], "socket_exact")
        self.assertEqual(row["owner_confidence"], "high")
        self.assertEqual(row["traffic_role"], "user")
        self.assertEqual(row["destination_host"], "api.kimi.com")
        self.assertEqual(row["rule_payload"], "kimi.com")
        self.assertEqual(row["route_group"], "国外流量")
        self.assertEqual(row["exit_node"], "香港 3倍消耗")
        self.assertEqual(row["multiplier"], 3.0)
        self.assertEqual(row["upload_bytes"], 300)
        self.assertEqual(row["download_bytes"], 700)


if __name__ == "__main__":
    unittest.main()
