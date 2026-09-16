# Contributing to NetMonitor Pro

感谢参与改进项目。

## 提交前检查

1. 不要提交代理订阅、节点、控制器 Token、IP 地址、个人流量账本、导出 CSV 或构建产物。
2. 保持 Python 代码兼容 Windows 10/11 与 Python 3.12。
3. 执行测试：

   ```powershell
   python -m unittest discover -s tests -v
   ```

4. 为新逻辑补充或更新测试，特别是路由、节点归属、颜色状态和历史账本逻辑。
5. 在 Pull Request 中说明问题、改动范围、验证方式以及可能影响的代理内核版本。

## 提交信息

建议使用简短、可读的提交标题，例如：

```text
fix: prevent AI probe from falling back to foreign-site group
feat: export billed traffic by hour
docs: clarify administrator startup behavior
```

## 讨论范围

项目只读取本机可用的 Windows 网络事件与 Mihomo/Clash 控制接口；不包含、收集或分发代理订阅与节点配置。请勿在公开 Issue 中粘贴敏感配置。
