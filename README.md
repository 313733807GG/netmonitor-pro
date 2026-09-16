# NetMonitor Pro

Windows 桌面流量监控工具：以 Windows ETW 获取精准进程上下行，以 Clash/Mihomo 控制接口补充真实分流出口、策略组与节点信息。

> 适用于 Windows 10 / 11 x64。该项目不包含代理订阅、节点、控制器密钥或个人流量记录。

## 功能

- 无需 Npcap、WinDivert 等第三方抓包驱动；管理员模式使用 Windows 自带 ETW 采集 TCP、UDP、QUIC 进程流量。
- 显示系统总流量、进程实时上下行、活跃连接、规则、策略组和实际出口节点。
- 统一配色：系统连接蓝、直连绿、代理黄、拦截红。
- 基于 Mihomo 连接 API 持久记录 PID、程序、域名、规则、节点、实际字节和倍率计费估算，并提供超量事件与 CSV 导出。
- AI 节点探测、体检和延迟测试固定使用 `AI服务` 策略组当前选择的叶子节点，不会误用“国外网站”或最近活跃节点。
- 主窗口和横/竖吸附条共用同一个 AI 节点状态灯。

## 快速开始

### 环境

- Windows 10 / 11 x64
- Python 3.12（当前测试环境）
- 可选：Clash Verge Rev、Mihomo 或兼容控制接口的代理内核

```powershell
git clone https://github.com/313733807GG/netmonitor-pro.git
cd netmonitor-pro
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -r requirements.txt
```

### 运行

```powershell
.\.venv\Scripts\python app.py
```

程序默认会请求管理员权限，以启用 ETW 精准进程流量。若仅需排障或普通权限连接视图：

```powershell
.\.venv\Scripts\python app.py --normal-mode
```

### 测试

```powershell
.\.venv\Scripts\python -m unittest discover -s tests -v
```

### 构建 Windows 发布包

```powershell
.\.venv\Scripts\python -m PyInstaller --noconfirm --clean NetMonitor.spec
```

构建产物位于 `dist/NetMonitor/`；请通过 GitHub Releases 分发发行包，不要把生成的 EXE、DLL 或 ZIP 提交到源码分支。

## 项目结构

```text
app.py                 主界面、采样协调、管理员启动与节点状态逻辑
pipe_client.py         Clash/Mihomo 命名管道和控制接口客户端
traffic_capture.py     Windows ETW 进程网络字节采集
traffic_history.py     SQLite 流量账本、倍率估算与 CSV 导出
etw/                   随项目分发的 pywintrace 兼容层
tests/                 单元测试
THIRD_PARTY_LICENSES/  第三方许可证文本
NetMonitor.spec        PyInstaller 构建配置
```

## 使用与隐私

- 常规使用说明见 [使用说明.txt](使用说明.txt)，v19 AI 节点改动见 [优化说明_v19.md](优化说明_v19.md)。
- 本地账本默认位于 `%LOCALAPPDATA%\NetMonitorPro\traffic-history\traffic_history.sqlite3`，不随 Git 仓库提交。
- 提交 Issue、日志、截图或配置前，请删除订阅链接、节点名称、控制器 Token、IP 地址及可识别的流量记录。

## 贡献

欢迎提交 Issue 和 Pull Request。提交前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)，并确保测试通过。

## 许可证

本项目使用 [MIT License](LICENSE)。`etw/` 的兼容层对应第三方许可证见 [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES)。
