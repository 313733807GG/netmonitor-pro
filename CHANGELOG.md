# Changelog

本文件记录稳定版本的重要变更，格式参考 [Keep a Changelog](https://keepachangelog.com/)。

## [19.0.0] - 2026-09-01

### Added

- AI 服务策略组当前叶子节点的定向探测、体检和延迟测试。
- 主界面和横/竖吸附条同步的 AI 节点状态灯。
- AI 策略组识别、嵌套叶子解析及“无目标不回退”测试。

### Changed

- 探测请求不再由订阅的普通分流规则选择节点；“国外网站”、GLOBAL 和最近活跃节点不再是 AI 检测后备目标。
- 无 AI 组、控制接口不可用、DIRECT/REJECT 或未接管时，界面明确停止检测并说明原因。

详细说明见 [CHANGELOG_v19.md](CHANGELOG_v19.md)。历史版本记录保留为根目录的 `CHANGELOG_v*.md` 文件。
