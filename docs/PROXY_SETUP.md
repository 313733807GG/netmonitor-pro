# Clash Verge Rev / FlClash：AI应完成的必要关联配置

目标是让NetMonitor读取当前代理状态，并通过独立本机入口查询实际AI节点的出口质量。NetMonitor不提供订阅，不替换普通上网节点，也不要求开启流量账本。

历史实机覆盖包括Clash Verge Rev 2.5.10、FlClash 0.9.2/0.9.3及Mihomo v1.19.32/v1.19.33。它们是历史验证范围，不是未来版本保证；正式Release清单必须区分本次实际重验与沿用历史覆盖。其他Mihomo客户端不自动视为受支持，非Mihomo软件不能直接套用。

## 1. 三种端口/接口不要混淆

| 用途 | 示例/约束 | AI要做什么 |
|---|---|---|
| 普通代理入口 | 客户端当前mixed/http/socks端口，如7897 | 保持用户现有设置 |
| 控制接口 | Verge本机命名管道；FlClash通常127.0.0.1上的HTTP API | 发现真实接口与认证，不公开密钥 |
| NetMonitor检测入口 | `127.0.0.1:17893`，mixed，UDP关闭 | 用通用脚本持久添加，不设成系统/浏览器代理 |

保留组：`NetMonitor-IP-Check`，类型select、hidden=true，默认首项REJECT；包含合成后实际节点和proxy-providers。保留监听器：`netmonitor-ip-check`，proxy指向该组。

只监听127.0.0.1；隐藏组不是安全访问控制，同机进程仍可能连接。不可使用0.0.0.0，不打开防火墙公网端口，不关闭证书检查。该入口仍是无浏览器版的必要功能，不能因移除Edge就把它删掉。

示例对这个专用本机监听器显式设置`users: []`，避免继承普通代理入口的全局认证后让NetMonitor请求收到407；普通入口的认证不变。它是仅供本机使用的无认证入口，必须保持127.0.0.1绑定与默认REJECT。已有同名监听器若显式配置了不同认证，应报告冲突，不静默移除认证。

## 2. 合并脚本的通用规则

对应示例：

- [Clash Verge](../examples/clash-verge-ip-quality.js)
- [FlClash](../examples/flclash-ip-quality.js)

示例没有订阅、节点地址、密钥或个人直连规则。AI应在本地读取现有脚本、备份，再合并；不是让用户自行复制并猜测。

没有现有main时可采用完整示例。已有main时只加入helper，保证原来的处理执行完毕且只保留一个main，例如：

```javascript
function main(config, profileName) {
  const result = existingTransform(config, profileName); // 保留原逻辑
  return addNetMonitorProbe(result);                     // 原逻辑之后合并
}
```

上例是结构示意，不代表原脚本一定有existingTransform。原main可能原地修改、返回另一个对象、存在多个return或异步行为，必须按实际语义合并，不能正则替换所有`return config`。不要把整个原main再执行一次。

检查所有保留名与17893冲突。已有同名对象只有确认属于NetMonitor且结构兼容才更新；不明对象、另一个监听器或其他进程占用时停止对应配置，说明原因，不静默换端口或覆盖。软件端口与脚本端口必须一致，当前公开程序不提供随意单边改端口的保证。

离线对同一合成配置应用两次，结果应幂等；普通规则、DNS/TUN、普通组、订阅内容、普通节点选择不能丢失。已存在的个人嗅探设置保留。旧安装若有127.0.0.2/32的sniffer.skip-src-address兼容项，不盲删；新安装不需要为当前按IP查询流程强制开启或重写全局嗅探。

## 3. Clash Verge Rev

### 发现与控制接口

标准Windows配置目录线索：`%APPDATA%\io.github.clash-verge-rev.clash-verge-rev`。读取客户端设置与实际进程路径核对；便携/新版位置可能不同。

NetMonitor读取本机配置中的external-controller-pipe或本机external-controller及secret，并发现实际Verge生产管道。不要照抄旧机器的管道hash。已有管道可用时，不额外开放TCP控制接口。

### 全局扩展合并

1. 查当前全局扩展脚本的真实文件/条目，备份内容及关联配置。不要把生成的运行配置当作持久源文件改写。
2. 保留全局Script.js或客户端当前对应入口的全部个人逻辑，按上节合并helper。
3. 检查脚本在所有目标订阅应用时执行。不要为同一订阅额外重复注册第二个相同监听器。
4. 离线运行或使用客户端验证功能检查合成结果。准备好后集中一次应用/重载，提前说明可能短暂断网。
5. 在实际内核中只读确认专用组、监听地址/端口和目标节点成员。检查普通选择器未变。

新增订阅一般沿用有效全局脚本，但必须检查生成结果；客户端升级、全局脚本被覆盖、订阅带保留名冲突时要重新核验。不要为验收遍历所有节点测速。

## 4. FlClash

### 控制接口与运行状态

标准配置目录线索：`%APPDATA%\com.follow\clash`。当前适配读取shared_preferences.json中的flutter.config（可能是JSON字符串或对象），优先patchClashConfig中的实时external-controller/secret，再按兼容规则读取运行配置。

在客户端常规/入站设置中启用本机控制器，使用可用的127.0.0.1端口及客户端生成的有效认证；9090是已验证场景的常见值，不是遇冲突仍强占的要求。不要复制维护者密钥，也不要把认证放进聊天输出。FlClashCore专有IPC管道不是Mihomo HTTP接口，不向它发送HTTP。

FlClash的总代理、系统代理、TUN开关彼此独立。总代理停止后API、旧连接或TUN配置值可能仍在；应结合普通入口和实际运行状态验收，不能只看`/configs`里tun.enable=true就宣称接管成功。

### 每份订阅都要绑定

1. 枚举本机现有、用户打算使用的订阅，生成仅保存在本机的绑定清单；不输出订阅URL中的令牌。
2. 对每份订阅检查extend_type、script_id、附加规则、match_target及已有脚本。**standard与script模式可能互斥**；切到script前须把原标准扩展行为保留下来，不能只改一个开关导致原规则失效。
3. 新建或复用确认属于NetMonitor的脚本；已有自定义脚本先合并，不整份替换。使用客户端支持的脚本创建/绑定入口，获取本机实际生成的ID。
4. 将脚本绑定到每个目标订阅，再读回确认。只创建JS文件但不绑定，或只改当前订阅，均不算全部完成。
5. 所有持久配置离线检查完后，再择时应用并验证当前订阅；其他订阅的运行验收在用户允许切换时进行。

新增或删除后重导入的订阅需要重新检查/绑定；原地更新链接或节点列表通常保留绑定，但必须读取确认。不要硬编码维护者的profile/script ID；这些ID可能超出JavaScript精确整数范围，工具中保留字符串或64位整数。

### 只有确实需要时，才采用离线数据库方式

优先客户端支持的界面/API。如果安装AI只能操作本机文件，可在**FlClash GUI及内核均已退出**、网络中断时机已协调的前提下，核实当前版本schema，再处理`database.sqlite`与`scripts/<本机ID>.js`。

已验证历史schema包括profiles的id/extend_type/script_id/match_target及scripts表；这只是核对线索，不保证未来相同。先用PRAGMA table_info检查，不用旧SQL盲写。备份SQLite完整状态（含WAL或一致性备份）、偏好与原脚本。

对实际选定的profile ID进行参数化事务更新，例如以下仅是字段关系，不是可直接照抄的安装命令：

```sql
UPDATE profiles SET extend_type = ?, script_id = ? WHERE id = ?;
```

必须同时确认脚本记录存在、JS文件位置正确、唯一ID与当前客户端格式相容。保存每行原值，检查行数、所有非目标字段和其他表未变化，失败回滚并恢复本轮新增文件。不得修改订阅URL、认证或用旧整库替换当前数据库。已有附加规则/兜底无法可靠迁移时不执行此更新，明确保留基础监控、评分配置尚待完成。

## 5. 实机验收

| 项目 | 正确结果 |
|---|---|
| 控制接口 | 本机认证成功，模式/客户端/连接列表可读 |
| 监听 | 当前代理内核持有127.0.0.1:17893，非公网绑定 |
| 组 | select、REJECT及当前订阅节点/提供者有效 |
| 持久性 | 订阅重新应用后仍存在；FlClash绑定读回一致 |
| 用户配置 | 普通节点选择、规则与DNS/TUN设置未被示例覆盖 |
| 一次定向检测 | 有真实AI连接链依据，结果或站点错误如实显示 |
| 完成/取消 | 专用组回REJECT，不残留其他选择 |
| 两客户端 | 分别验证，不同时启动争用端口 |

控制接口已读通但入口未配置，不叫“全部安装完成”。第三方报告未就绪也不能叫“节点不支持IPv6”。没有实测的订阅/版本明确标注，不要求用户进行全节点测速。

必要时提醒用户正常访问一次AI服务以产生可验证连接；这不是要求开启历史入账。所有测试结束后保持用户原模式/节点，软件自启关闭，首次入账仍关闭。

参考：[Mihomo mixed监听器](https://wiki.metacubex.one/config/inbound/listeners/mixed/)、[监听器通用字段](https://wiki.metacubex.one/config/inbound/listeners/#通用字段)、[Clash Verge Rev项目](https://github.com/clash-verge-rev/clash-verge-rev)、[FlClash项目](https://github.com/chen08209/FlClash)。遇界面/schema变化应对照实际版本官方源码，不假定菜单位置永久不变。
