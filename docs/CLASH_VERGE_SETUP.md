# Clash Verge 的 IP 质量检测入口

> v22.0.1 最新行为与维护变化见 [V22_CHANGES.md](V22_CHANGES.md)；FlClash 配置见 [FLCLASH_SETUP.md](FLCLASH_SETUP.md)。

本版本已在 Clash Verge Rev / Mihomo v1.19.32 和 FlClash 0.9.2 / Mihomo v1.19.33 实机验证。其他 Mihomo 客户端可能适用但需自行适配；非 Mihomo 内核不建议下载使用。

## 为什么需要入口

浏览器访问检测网站通常遵循原分流规则，未必与 AI 出口相同。NetMonitor 使用独立选择组和只绑定本机的监听器，查询前选择 AI 叶子节点，并通过连接链核实出口。它只切换专用组，不切换普通策略组；结束后尝试恢复 REJECT。没有此入口时不会偷偷使用其他节点或直连来获取一个可能错误的分数。

固定参数：

| 项目 | 值 |
|---|---|
| 选择组 | `NetMonitor-IP-Check`，select，默认 REJECT |
| 监听器 | `netmonitor-ip-check`，mixed |
| 地址 | `127.0.0.1:17893`，UDP 关闭 |

这不是控制 API 端口，也不要求把正常代理端口改成 17893。不要绑定 `0.0.0.0`，不要在浏览器/系统代理里使用此端口。组隐藏仅为减少误操作，不是访问控制；同机其他进程仍可能访问本地监听器。

## 合并配置

先保存自己现有脚本的副本。打开 Clash Verge Rev 的全局扩展脚本编辑入口（不同版本界面名称可能不同），使用仓库的 [`examples/clash-verge-ip-quality.js`](../examples/clash-verge-ip-quality.js)。

没有现有脚本时可使用完整示例；已有 `main(config, profileName)` 时只加入 `addNetMonitorProbe` 函数，然后在原 main 完成自己的处理后、return config 前调用：

```javascript
return addNetMonitorProbe(config);
```

**保留原来的订阅、个人规则、选择组及节点选择，不要将整份现有脚本直接替换为示例。** 示例从合成后的 `proxies` 和 `proxy-providers` 收集节点，不附带任何代理服务器。禁止使用 NetMonitor 保留组/监听器名称处理别的用途。

合并后需应用/重载配置才能生效。该操作可能短暂中断网络、下载和 AI 对话，提前保存工作并选择时机；NetMonitor 不自动替你重载。若 17893 已被占用，先排查占用者，不要静默改端口或结束不明进程。软件与脚本端口需成对修改并重新构建才可使用其他端口。

## 验证与维护

1. 在有效配置中确认专用组初始 REJECT，监听器只在 127.0.0.1:17893，没有改变普通组。
2. 开启系统代理或 TUN，实际访问 AI 服务，使 NetMonitor 获得可信的 AI 目标；在规则模式下优先 ChatGPT/OpenAI。
3. 点击 IP质量，确认有结果或明确错误，检测后专用组回到 REJECT。不要把网站拒绝/人机验证当作代理节点损坏。
4. Verge 升级或订阅变化后重新核对入口和节点集合；新订阅的节点需在有效专用组中。

查询会向 IPPure (`my.ippure.com/v1/info`) 与 CleanIP (`cleanip.io/cli`) 发送 HTTPS 请求，两站会看到检测出口 IP 及请求信息。软件不上传本地账本或待鉴定清单，不绕过第三方验证，也不保证接口持续可用。

浏览器手动打开检测网站仍按正常规则选出口，不会因为此入口自动改走 AI 节点。无需给检测网站追加全局 AI 分流规则。
