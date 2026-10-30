# 详细安装、升级与卸载

> 22.0.2：已移除Fl质量参考，原单元格留空；仅IPPure与CleanIP参与评分和类型印证。安装及新增订阅必须按[代理商检测入口说明](PROVIDER_SETUP.md)逐份检查。

> v22.0.2 最新行为与维护变化见 [V22_CHANGES.md](V22_CHANGES.md)；FlClash 配置见 [FLCLASH_SETUP.md](FLCLASH_SETUP.md)。

适用于 NetMonitor v22.0.2 Windows x64 便携包。仅在 Clash Verge Rev 中适配和实机验证；其他 Mihomo 客户端需要自行适配，非 Mihomo 内核不建议使用。

## 1. 准备与选择下载内容

1. 确认使用 Windows x64。ARM64、32位系统和其他操作系统没有本版原生发行包，不保证兼容。
2. 先确认 Clash Verge Rev 自身可正常联网，并记录当前使用系统代理还是 TUN，以及规则/全局/直连模式。NetMonitor 不提供代理服务。
3. 在[本版 Release](https://github.com/313733807GG/netmonitor-pro/releases/tag/v22.0.2)下载 `NetMonitor-v22.0.2-windows-x64.zip` 和 `SHA256SUMS.txt`。
4. `NetMonitor-v22.0.2-source.zip`、GitHub的Source code (zip/tar.gz)是源码，需要自己准备Python环境，不是双击即用的程序。
5. 已有旧版时先看本页“升级与回退”。不要边运行旧程序边覆盖文件。

便携包自带运行库，不需要另装Python。EXE没有发布者代码签名；哈希只用于核对文件一致性，不代替签名或系统安全检查。

## 2. 校验下载包

在下载目录打开PowerShell，执行下面的校验。文件必须来自同一Release；路径不同请自行更改首行。

```powershell
$packageDir = Join-Path $env:USERPROFILE 'Downloads'
$packageName = 'NetMonitor-v22.0.2-windows-x64.zip'
$checksumFile = Join-Path $packageDir 'SHA256SUMS.txt'
$checksumRows = @(Get-Content -LiteralPath $checksumFile | Where-Object {
    $_ -match ('\s+' + [regex]::Escape($packageName) + '$')
})
if ($checksumRows.Count -ne 1) { throw '校验文件缺失、重复或与版本不匹配' }
$expectedHash = ($checksumRows[0] -split '\s+')[0]
if ($expectedHash -notmatch '^[0-9a-fA-F]{64}$') { throw '校验值格式异常' }
$actualHash = (Get-FileHash -LiteralPath (Join-Path $packageDir $packageName) -Algorithm SHA256).Hash
if ($actualHash -ne $expectedHash) { throw '校验失败，请重新从官方Release下载' }
'SHA256 校验通过'
```

校验不一致时不要启动。下载ZIP失败、网页返回HTML或下载不完整，也不能改扩展名当作成功。

## 3. 首次安装

使用Windows“全部解压”，解压到自己的独立目录。例如 `%LOCALAPPDATA%\Programs\NetMonitor` 或自己选择的应用目录；不要直接在ZIP内运行。源码、安装目录与用户数据位置互相独立，不要求使用维护者电脑的盘符和路径。

最终目录应包含：

```text
NetMonitor/
  NetMonitor.exe
  _internal/                 ← 整个目录都要保留
  README.md
  docs/                     ← 本套详细说明及展示图
  examples/                 ← 不含个人配置的Clash Verge脚本示例
  THIRD_PARTY_LICENSES/
  THIRD_PARTY_NOTICES.md
  LICENSE
```

如果解压结果多一层`NetMonitor`，找到实际包含EXE和_internal的那层作为安装目录。不要把新目录复制到旧目录里面形成多层嵌套。

启动`NetMonitor.exe`，按正常Windows UAC提示允许管理员权限，以启用ETW。可在EXE属性“详细信息”确认文件版本为`22.0.2.0`。本版已验证EXE SHA256为：

```text
B0398C2F0E13BC6387D016C4C1307F935069205E92C6B7BD346C9616FFFF9D11
```

若Windows阻止EXE或依赖DLL，记录具体提示与被阻止文件，检查系统安全记录。不要关闭安全保护或替换来源不明DLL。无法获准运行时报告失败；源码运行也要使用本机受信任的Python和依赖，不保证能绕过应用控制。

可自行创建指向实际EXE的桌面快捷方式，工作目录设为实际安装目录。首次安装不要求开启开机自启，也无需创建计划任务。

## 4. 配置IP质量检测

普通流量监控与IP质量检测是两项功能。IP质量需要按[Clash Verge入口配置](CLASH_VERGE_SETUP.md)合并示例函数，保留自己的原有全局脚本和规则。

- 固定本机入口`127.0.0.1:17893`，专用组`NetMonitor-IP-Check`，默认REJECT；这是检测入口，不能替代系统/浏览器代理端口。
- 已有脚本只有一个`main`入口，应在原处理结束返回前调用`addNetMonitorProbe(config)`，不能直接覆盖原脚本。
- 合并脚本前保存副本。应用/重载Clash Verge可能中断网络及AI对话，先保存工作、选好时机。
- 其他进程占用17893时先查明占用者，不应结束不明进程，也不能只改单边端口。

未配置入口时，NetMonitor仍可显示基本流量，评分会等待或报不可用。不要把没有配置入口误判为软件已完整安装成功。

## 5. 安装验收

| 检查 | 应看到什么 | 不满足时 |
|---|---|---|
| 程序版本与位置 | 实际启动的是选定目录下22.0.2.0 | 检查旧快捷方式、旧实例和解压层级 |
| ETW采集 | 托盘显示“精准进程流量：已启用（ETW）” | 用正常UAC授权启动并检查日志 |
| 控制接口 | 能读取模式、TUN、连接分流 | 核对Clash Verge服务/控制接口与版本，不公开密钥 |
| 严格路由 | 与当前内核配置一致；未知时看悬停/日志 | 区分API失败、字段异常与TUN未生效 |
| AI目标 | 代理接管并有可信AI连接时显示目标 | 直连/无连接/不明确时等待是正常结果 |
| IP质量 | 点击后返回分数或明确的第三方错误 | 检查入口、真实出口、网站限流/验证 |
| 检测后状态 | 专用组恢复REJECT，普通组选择不变 | 停止连续测试，按维护说明排查 |
| 本机数据 | 原账本可读，新流量持续写入同一数据目录 | 先检查路径、权限和测试环境覆盖，不能重建掩盖问题 |

不要为了验收主动切换用户正在使用的代理模式或重载网络；在已有状态下验证并说明未覆盖的情况。详细操作见[使用说明](USAGE.md)。

## 6. 升级与回退

1. 记录旧程序实际路径、版本、快捷方式目标和数据位置。在托盘选“退出”，确认旧实例结束；隐藏窗口不等于退出。
2. 备份完整旧安装目录，另行备份`%LOCALAPPDATA%\NetMonitorPro`和QSettings注册表设置。软件退出后复制整个数据目录；运行中只能用SQLite一致性备份，不能只复制活跃数据库主文件而遗漏WAL。
3. 对新ZIP校验、解压到新的暂存目录。检查EXE、_internal和说明完整，再替换完整安装目录。不要只覆盖EXE或混用不同版本DLL。
4. 更新快捷方式实际目标，启动后执行上一节验收，确认原账本继续增长，旧记录仍在。
5. 如需回退，退出新版后恢复完整旧程序，不默认恢复旧数据库覆盖新记录。旧版可能只有500条待鉴定总上限，先单独备份新版unknown-targets.json，避免回退后被淘汰。

可在PowerShell中导出窗口等设置（只生成备份，不修改现有设置）：

```powershell
$backupDir = Join-Path $env:USERPROFILE ('NetMonitor-settings-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $backupDir | Out-Null
reg export 'HKCU\Software\NetMonitorPro' (Join-Path $backupDir 'settings.reg') /y
```

若该注册表键尚不存在，导出失败不代表账本损坏。恢复注册表会改变设置，先确认目标机器/账号，不盲目导入别人的备份。

## 7. 卸载

在托盘关闭“开机自启”（如自己启用过），选择“退出”，移除确认过的快捷方式及实际安装目录。便携版不要求运行卸载器。不要删除来源不明的同名目录。

默认保留`%LOCALAPPDATA%\NetMonitorPro`，以便以后继续使用历史。确实需要永久删除日志、账本或注册表设置时先备份并明确选择；卸载程序与删除历史数据不是同一动作。

如不再使用IP检测入口，在Clash Verge原脚本中仅移除`addNetMonitorProbe`及对应调用，保留后续个人改动，再择时应用配置。不要拿旧脚本备份直接覆盖当前全部规则。
