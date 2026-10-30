# FlClash 设置与维护

> 22.0.2：已移除Fl质量参考，原单元格留空；仅IPPure与CleanIP参与评分和类型印证。安装及新增订阅必须按[代理商检测入口说明](PROVIDER_SETUP.md)逐份检查。

> v22.0.2 最新行为与维护变化见 [V22_CHANGES.md](V22_CHANGES.md)；FlClash 配置见 [FLCLASH_SETUP.md](FLCLASH_SETUP.md)。

实测 FlClash 0.9.2 / Mihomo v1.19.33；其他版本需要重新核对。NetMonitor支持FlClash及Clash Verge Rev，不附带代理订阅或服务。不要同时启动两个占用相同代理/控制/检测端口的内核。

## 本机控制接口

在FlClash常规/入站设置启用外部控制器，建议仅监听127.0.0.1:9090并生成密钥。NetMonitor读取本机偏好获取认证；不要把密钥、shared_preferences.json或订阅数据库上传。正常代理端口和NetMonitor检测端口是不同用途。

## IP质量入口

使用[通用扩展脚本](../examples/flclash-ip-quality.js)。新建脚本扩展，将它绑定到需要检测的每个订阅；以后新增订阅也要绑定。已有脚本须合并addNetMonitorProbe调用，不可直接覆盖。

FlClash的standard/script扩展互斥，切换前核对附加规则和matchTarget兜底设置，必要时把它们合并到脚本，否则会丢失原分流偏好。本仓库示例只添加NetMonitor专用组与本机监听器，不包含个人直连规则或任何节点。

专用组NetMonitor-IP-Check初始REJECT，监听器netmonitor-ip-check仅127.0.0.1:17893，UDP关闭。应用配置可能短暂断网，应先保存工作并选择时机；NetMonitor不自动重载代理。

启动代理连接，访问AI服务，再在NetMonitor点IP质量。应确认实际AI出口及评分成功，结束后专用组恢复REJECT，普通选择组不变。缺少入口时显示不可用，不自动改走别的出口。

## FlClash自身的质量结果

22.0.2不再读取FlClash质量缓存。无需先在FlClash IP详情检测；NetMonitor仅查询IPPure与CleanIP。

两站及FlClash的住宅/非住宅判断一致时用CleanIP样式；有明确非住宅证据优先该来源；多个负面来源按CleanIP→IPPure→FlClash优先，细分类不一致注明分歧。FlClash没有原生/广播和地区字段，这两项仍由原两站判定。

## 升级与排障

更新客户端、订阅或扩展后核对控制接口、认证和专用入口。不要用旧整库覆盖新订阅和缓存；回退扩展只恢复相关脚本/绑定。Windows可能拦截FlClash自身的未签名DLL，需从CodeIntegrity事件区分，不能直接归因于NetMonitor脚本或混换来历不明DLL。
