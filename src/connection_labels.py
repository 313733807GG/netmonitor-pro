"""Display-only aliases; never change routing, accounting or merge keys."""
import ipaddress
import ntpath
import time
from functools import lru_cache

ALIASES = (
    # 2026-11-03 current review; third-party sites are not represented as official.
    ('public.games.geforce.com', 'NVIDIA GeForce · 游戏目录服务'),
    ('gfwsl.geforce.com', 'NVIDIA GeForce · 应用服务'),
    ('gfwsl.geforce.cn', 'NVIDIA GeForce · 中国服务'),
    ('gemini.google', 'Google Gemini'),
    ('lawnchair.app', 'Lawnchair · 启动器项目'),
    ('gkd-subscription-667.pages.dev', 'GKD · 第三方规则订阅'),
    ('ecombdimg.com', '抖音电商 · 图片资源'),
    ('stripecdn.com', 'Stripe · 静态资源'),
    ('gh-proxy.org', 'GH Proxy · 第三方 GitHub 镜像'),
    ('cpfgenerator.org', 'CPF Generator · 巴西税号工具'),
    ('whiz.tools', 'Whiz Tools · 在线工具'),
    ('loongweb.com', 'LoongWeb · 网站服务'),
    ('brazil-visa.tw', 'Brazil Visa · 第三方签证信息'),
    ('pub-a0d1f5ea1fb84aaab0ba80e79d99c07e.r2.dev', 'Cloudflare R2 · 公共存储'),
    ('ipqualityscore.com', 'IPQualityScore · IP 信誉服务'),
    ('hdaa.shuzilm.cn', '数字联盟 · 可信ID与设备风控'),
    ('my.microsoftpersonalcontent.com', 'OneDrive · 个人内容'),
    ('telegram.me', 'Telegram · 官方短链'),
    ('yastatic.net', 'Yandex · 静态资源'),
    ('cdn-cookieyes.com', 'CookieYes · 静态资源'),
    ('rapidproxy.io', 'RapidProxy · 代理服务'),
    ('proxy001.com', 'Proxy001 · 代理服务'),
    ('mokeaigc.ai', 'Moke AIGC · AI 服务'),
    ('loliapi.com', 'LoliAPI · 图片接口'),
    ('cisco.com', 'Cisco · 网络服务'),
    ('logitechg.com.cn', '罗技 G · 中国服务'),
    ('logitech.io', '罗技 · 应用服务'),
    ('skyvpn.me', 'SkyVPN · 应用服务'),

    # 2026-10-31 historical review: public service domains and first-party documentation.
    ('blob.core.windows.net', '微软 Azure · 存储'),
    ('sfx.ms', 'OneDrive · 应用服务'),
    ('aka.ms', '微软 · 官方短链'),
    ('azurewebsites.net', '微软 Azure · 应用托管'),
    ('static.microsoft', '微软 · 静态资源'),
    ('msftncsi.com', 'Windows · 网络连接检测'),
    ('customeremail.microsoftrewards.com', '微软 Rewards · 邮件'),
    ('hitv.com', '芒果TV · 网络服务'),
    ('blz-contentstack.com', '战网 · 游戏资源'),
    ('166.net', '网易 · 网络服务'),
    ('miaozhen.com', '秒针 · 网站统计'),
    ('sectigo.com', 'Sectigo · 证书状态检查'),
    ('nvidia.cn', 'NVIDIA · 中国服务'),
    ('nvidiagrid.net', 'NVIDIA GRID · 云服务'),
    ('msi.cn', '微星 · 中国服务'),
    ('alidns.com', '阿里公共 DNS'),
    ('favicon.la', 'Favicon.la · 图标代理'),
    ('favicon.im', 'Favicon.im · 图标代理'),
    ('huorong.cn', '火绒安全 · 更新服务'),
    ('bluecdn.com', 'BlueCDN · 内容分发'),
    ('miwifi.com', '小米路由器 · 网络服务'),
    ('feishucdn.com', '飞书 · 静态资源'),
    ('loli.net', 'loli.net · 公共镜像'),
    ('superbed.cc', 'Superbed · 图床'),
    ('dicebear.com', 'DiceBear · 头像服务'),
    ('imgdb.cn', 'IMGDB · 图床'),
    ('liblib.tv', 'LiblibAI · 模型服务'),
    ('globalsign.net', 'GlobalSign · 证书状态检查'),
    ('adtidy.org', 'AdGuard · 过滤规则'),
    ('imgbb.com', 'ImgBB · 图床'), ('ibb.co', 'ImgBB · 图片资源'),
    ('bilibili.cn', 'B站 · 服务'),
    ('pool.ntp.org', 'NTP Pool · 公共时间服务'),
    ('telesco.pe', 'Telegram · 内容分发'),
    ('publicsuffix.org', 'Public Suffix List · 公共后缀目录'),
    ('browserleaks.net', 'BrowserLeaks · 浏览器检测'),
    ('browserleaks.com', 'BrowserLeaks · 浏览器检测'),
    ('surfshark.com', 'Surfshark · 网络检测'),
    ('sendgrid.net', 'SendGrid · 邮件链接'),
    ('tapnow.media', 'TapNow · 应用服务'),
    ('zloemu.net', 'ZloEmu · 游戏服务'),
    ('usercentrics.eu', 'Usercentrics · 隐私同意管理'),
    ('stripe.network', 'Stripe · 支付服务'),
    ('proxy-cheap.com', 'Proxy-Cheap · 代理服务'),
    ('zdassets.com', 'Zendesk · 静态资源'),
    ('orayimg.com', 'Oray 贝锐 · 静态资源'),
    ('oray.com', 'Oray 贝锐 · 应用服务'),
    ('onesproxy.com', 'OnesProxy · 代理服务'),
    ('live2support.com', 'Live2Support · 网页客服'),
    ('teo-rum.com', '腾讯 EdgeOne · 网络错误上报'),
    ('okx.com', 'OKX · 交易平台'),
    ('sora.com', 'Sora · AI 视频服务'),
    ('coinbase.com', 'Coinbase · 交易平台'),
    ('perplexity.ai', 'Perplexity · AI 搜索'),
    ('discord.com', 'Discord · 应用服务'),
    ('fast.com', 'Netflix Fast · 网络测速'),
    ('tiktok.com', 'TikTok · 视频服务'),
    ('disneyplus.com', 'Disney+ · 视频服务'),
    ('bamgrid.com', 'Disney · 应用接口'),
    ('recaptcha.net', 'Google reCAPTCHA · 安全验证'),
    ('typekit.net', 'Adobe Typekit · 字体服务'),
    ('gstatic.cn', 'Google · 静态资源'),
    ('google.com.tw', 'Google 服务'),
    ('freeswitch.org', 'FreeSWITCH · STUN 网络服务'),
    ('nextcloud.com', 'Nextcloud · STUN 网络服务'),
    ('voip.blackberry.com', 'BlackBerry · STUN 网络服务'),
    ('ohttp-relay-safebrowsing-chrome.google.fastly-edge.com', 'Google Safe Browsing · 隐私中继'),
    ('adnxs.com', 'Xandr · 广告服务'),
    ('3lift.com', 'TripleLift · 广告服务'),
    ('adsrvr.org', 'The Trade Desk · 广告服务'),
    ('linkedin.com', 'LinkedIn · 广告统计'),
    ('iqoo.com', 'iQOO · 账户服务'),
    ('npmjs.org', 'npm · 软件包仓库'),
    ('apache.org', 'Apache · 软件仓库'),
    ('oracle.com', 'Oracle · 软件下载'),
    ('braze-images.com', 'Braze · 图片资源'),
    ('ocsp-certum.com', 'Certum · 证书状态检查'),
    ('comodoca.com', 'Comodo CA · 证书状态检查'),
    ('cdn-go.cn', '腾讯云 · CDN 资源'),
    ('antigravity-hub-auto-updater-974169037036.us-central1.run.app', 'Google Antigravity · 更新服务'),
    ('gitcode.com', 'GitCode · 代码托管'),
    ('apnic.net', 'APNIC · 网络注册信息'),
    ('gitlab.io', 'GitLab Pages · 网站托管'),
    ('malware-filter.pages.dev', '恶意网站过滤规则 · 公共列表'),
    ('v2ex.com', 'V2EX · 网站资源'),
    ('metacubex.one', 'MetaCubeX · 项目文档'),
    ('alicdn.com', '阿里云 · 静态资源'),
    ('aliyuncs.com', '阿里云 · 应用服务'),
    ('bcebos.com', '百度智能云 · 对象存储'),
    ('tencent.com', '腾讯 · 网络服务'),
    ('mat1.gtimg.com', '腾讯 · 静态资源'), ('qqmc.gtimg.com', '腾讯 · 静态资源'),
    ('gtimg.cn', '腾讯 · 静态资源'),
    ('qlogo.cn', 'QQ · 头像资源'),
    ('rescdn.qqmail.com', 'QQ邮箱 · 静态资源'),
    ('weiyun.com', '腾讯微云 · 应用服务'),
    ('bytetos.com', '字节跳动 · 内容资源'),
    ('bytednsdoc.com', '字节跳动 · 文档资源'),
    ('douyinvod.com', '抖音 · 视频资源'), ('idouyinvod.com', '抖音 · 视频资源'),
    ('volceapplog.com', '火山引擎 · 应用日志'),
    ('volcvideo.com', '火山引擎 · 音视频服务'),
    ('bytetcc.com', '字节跳动 · 配置服务'),
    ('bytescm.com', '字节跳动 · 内容资源'),
    ('byted-static.com', '字节跳动 · 静态资源'),
    ('byteeffecttos.com', '字节跳动 · 特效资源'),
    ('iesdouyin.com', '抖音 · 社交服务'),
    ('applogcdn.com', '字节跳动 · 日志资源'),
    ('huoshanstatic.com', '火山引擎 · 静态资源'),
    ('example.com', 'IANA · 示例域名'),

    # Official Battle.net download page references blzstatic.cn assets.
    ('battlenet.com.cn', '战网国服 · 暴雪游戏服务'),
    ('blzstatic.cn', '战网国服 · 游戏资源'),
    # 2026-10-30 official site titles + local process evidence.
    ('primevideo.com', 'Prime Video · 视频服务'),
    ('gitee.com', 'Gitee · 代码托管'),
    ('dns.alidns.com', '阿里公共 DNS'),
    ('liveupdate.msi.cn', '微星 · 软件更新'),
    ('snowshot.top', 'Snow Shot · 截图工具'),

    # CleanIP's own page documents this DNS-test zone and analytics endpoint.
    # Do not generalize to all of proxypurity.com without equivalent evidence.
    ('dp.proxypurity.com', 'CleanIP · DNS 检测'),
    ('stats.proxypurity.com', 'CleanIP · 网站统计'),
    # 2026-10-28 first-party documentation / site code; see 21.0.11 review notes.
    ('bitwarden.com', 'Bitwarden · 密码管理'),
    ('bitwarden.net', 'Bitwarden · 图标及资源'),
    ('salesmartly.com', 'SaleSmartly · 网页客服'),
    ('crisp.chat', 'Crisp · 网页客服'),
    ('stripe.com', 'Stripe · 支付服务'),
    ('iplocate.io', 'IPLocate · IP 查询'),
    ('ipquery.io', 'IPQuery · IP 查询'),
    ('proxycheck.io', 'ProxyCheck · IP 检测'),
    ('ip-api.com', 'IP-API · IP 查询'),
    ('api.myip.com', 'MyIP · 公网 IP 查询'),
    ('ident.me', 'ident.me · 公网 IP 查询'),
    ('freeipapi.com', 'FreeIPAPI · IP 查询'),
    ('surfsharkdns.com', 'Surfshark · DNS 泄漏检测'),
    ('posthog.com', 'PostHog · 网站分析'),
    ('canny.io', 'Canny · 用户反馈'),
    ('pypi.org', 'PyPI · Python 软件包'),
    ('files.pythonhosted.org', 'PyPI · 软件包下载'),
    ('office.net', '微软 Office · 应用资源'),
    ('office365.com', '微软 Microsoft 365'),
    ('livechatinc.com', 'LiveChat · 网页客服'),
    ('vivo.com.cn', 'vivo · 应用服务'),
    ('vivo.com', 'vivo · 应用服务'),
    ('global.stun.twilio.com', 'Twilio · STUN 网络服务'),
    ('nodejs.org', 'Node.js · 开发工具'),
    ('gitlab.com', 'GitLab · 代码托管'),
    ('azul.com', 'Azul · Java 服务'),
    ('zendesk.com', 'Zendesk · 网页客服'),
    ('cookieyes.com', 'CookieYes · 隐私同意管理'),
    ('globalping.io', 'Globalping · 网络检测'),
    # 2026-10-24 first-party pages and local application evidence.
    ('antigravity.google', 'Google Antigravity'),
    ('antigravity-unleash.goog', 'Antigravity · 应用服务'),
    ('ublockorigin.pages.dev', 'uBlock Origin · 过滤规则'),
    ('tampermonkey.net', 'Tampermonkey · 扩展服务'),
    ('csdnimg.cn', 'CSDN · 网站资源'),
    ('captcha.gtimg.com', '腾讯 · 安全验证'),
    ('oaistatsig.com', 'OpenAI · 应用服务'),
    # Verified first-party service endpoints, 2026-10-23 (see maintenance memo).
    ('cleanip.io', 'CleanIP · IP 检测'),
    ('static.cleanipcdn.com', 'CleanIP · 网站静态资源'),
    ('tile.openstreetmap.org', 'OpenStreetMap · 地图瓦片'),
    ('doh.pub', '腾讯 DNSPod · 加密 DNS'),
    ('platform.claude.com', 'Claude · 开发者平台'),
    ('cdn-apple.com', '苹果 · 内容分发'),
    ('pixpin.cn', 'PixPin · 应用服务'),
    ('myip.ipip.net', 'IPIP · 公网 IP 查询'),
    ('hw-v2-web-player-tracker.biliapi.net', 'B站播放器统计'),
    ('biliapi.net', 'B站接口'), ('biliapi.com', 'B站接口'),
    ('bilivideo.cn', 'B站视频资源'),
    ('dl.google.com', 'Google 下载'),
    ('accounts.google.com', 'Google 登录'),
    ('mtalk.google.com', 'Google 消息连接'),
    ('google.com', 'Google 服务'), ('google.com.hk', 'Google 服务'),
    ('githubassets.com', 'GitHub 静态资源'),
    ('oaistatic.com', 'OpenAI 静态资源'),
    ('oaiusercontent.com', 'OpenAI 用户内容'),
    ('login.live.com', '微软账户登录'),
    ('outlook.live.net', 'Outlook 邮箱资源'),
    ('outlook.com', 'Outlook 邮箱'),
    ('live.com', '微软 Live 服务'),
    ('microsoftonline.com', '微软账户认证'),
    ('msauth.net', '微软认证资源'),
    ('bing.net', '必应资源'),
    ('s-microsoft.com', '微软静态资源'),
    ('azurefd.net', 'Azure 分发服务'),
    ('azureedge.net', 'Azure 分发服务'),
    ('logitech.com', '罗技'), ('logitechg.com', '罗技 G'), ('logi.com', '罗技支持'),
    ('blender.org', 'Blender'), ('msi.com', '微星'),
    ('apple.com.cn', '苹果中国'),
    ('douyinstatic.com', '抖音静态资源'), ('douyinpic.com', '抖音图片'),
    ('bytedance.com', '字节服务'),
    ('feishu.cn', '飞书接口'),
    ('iqiyi.com', '爱奇艺'), ('iqiyipic.com', '爱奇艺图片'),
    ('bdstatic.com', '百度静态资源'), ('bdimg.com', '百度图片资源'),
    ('zhimg.com', '知乎图片资源'),
    ('jsdelivr.net', 'jsDelivr 公共资源'), ('unpkg.com', 'unpkg 公共资源'),
    ('hcaptcha.com', 'hCaptcha 验证'),
    ('ping0.cc', 'Ping0 IP 检测'), ('ippure.com', 'IPPure IP 检测'),
    ('ipinfo.io', 'IPinfo IP 信息'), ('ipapi.co', 'IPapi IP 信息'),
    ('icanhazip.com', '公网 IP 查询'),
    ('qznovelvod.com', '阅读视频（按域名）'),
    ('substrate.office.com', '微软 Office 服务'),
    # 字节跳动官方 API 域（2018 年注册，eName 注册商，2026-10-14 whois 核实），
    # vod-settings 等子域为火山引擎视频点播（VOD）配置下发接口
    ('bytedanceapi.com', '字节跳动 · 云服务接口'),
    # 字节跳动 CDN 的 GSLB 调度域：NS 为 NS3/NS4.BYTEDNS.COM（火山引擎 DNS），
    # 哈希长子域+短 TTL 负责把内容请求分配到最近边缘节点，2026-10-11 核实
    ('bdcgslb.com', '字节跳动 · CDN 调度'),
    # bdurl.net 改判字节跳动（2026-10-21）：eName 注册 + ALIDNS VIP NS，与
    # bytedanceapi/snssdk 同型；公开流量分析确认 bd=ByteDance 而非百度，dig 子域为拨测
    ('bdurl.net', '字节跳动 · 网络服务'),
    ('fqnovelpic.com', '阅读图片资源'),
    ('fqnovelvod.com', '阅读视频资源'),
    ('byteimg.com', '字节图片资源'),
    ('bytevod.com', '字节视频资源'),
    ('office.com', '微软 Office'),
    ('kimi.com', 'Kimi'), ('kimi.ai', 'Kimi'), ('apitd.net', 'Kimi'),
    ('doubao.com', '豆包'), ('zijieapi.com', '字节系服务'),
    ('baidu.com', '百度'), ('miui.com', '小米服务'),
    ('deepseek.com', 'DeepSeek'), ('claude.ai', 'Claude'),
    ('douyin.com', '抖音'), ('douyincdn.com', '抖音资源'),
    ('t.me', 'Telegram'), ('telegram.org', 'Telegram'),
    ('weixin.qq.com', '微信'),
    ('akamai.net', 'Akamai CDN'), ('akamaized.net', 'Akamai CDN'),
    ('akamaihd.net', 'Akamai CDN'),
    ('functional.events.data.microsoft.com', '微软遥测'),
    # 域名归属七牛云关联公司北京空山信息（法人许式伟，2026-10-11 天眼查核实），
    # 数字子域形式为 App 内嵌云服务 SDK 的上报/存储通道
    ('qrstuvwxyzab.com', '七牛云 · 数据服务'),
    # 字节跳动 SDK 服务域（头条/抖音/番茄系共用，2011 年注册，2026-10-11 whois 核实）
    ('snssdk.com', '字节跳动 · 应用服务'),
    # 杭州优云科技（uyun.com）PCDN 调度域：随机子域+短 TTL 为边缘节点分配特征，
    # 2026-10-11 CNNIC whois 核实（2025-01 注册，阿里云注册商）。注意与未注册的
    # qjspcdn.cn 区分：domain_matches 要求点号边界，两者互不干扰
    ('jspcdn.cn', '优云 PCDN · 内容分发'),
    # ---- 2026-10-21 待鉴定批次（逐条证据见维护备忘当日条目）----
    # 抖音电商后端 API（ec3/ecom3 子域，APK 走 com.bytedance.android.ec.sdk）
    ('ecombdapi.com', '字节跳动 · 电商接口'),
    # 抖音音视频通话 RTC 信令/网关（vc-brain 子域，v2ray bytedance 官方域表收录）
    ('ndcpp.com', '字节跳动 · 音视频服务'),
    # 字节 Gecko 资源平台 CDN（备案主体：北京抖音信息服务有限公司）
    ('bytegecko.com', '字节跳动 · CDN 资源'),
    # 字节静态资源公共库（NS 为 BYTEDNS，2026-10-21 RDAP 核实）
    ('yhgfb-cn-static.com', '字节跳动 · 静态资源'),
    # 北京字跳网络（字节跳动）SDK 域（备案核实；zlink 子域为域名调度）
    ('ugsdk.cn', '字节跳动 · SDK 服务'),
    ('ibytedapm.com', '字节跳动 · 应用监控'),
    ('bytegoofy.com', '字节跳动 · 安全服务'),
    ('bytecdn.com', '字节跳动 · CDN'),
    ('oceanengine.com', '字节跳动 · 巨量引擎广告'),
    ('volccdn.com', '火山引擎 CDN'),
    ('fqnovelstatic.com', '阅读静态资源'),
    # PCDN 服务商（共享计算）：sd-gl/cf-gl/seeds-open 等子域为 PCDN SDK 调度端点
    ('comfylink.com', '网心云 · PCDN 服务'), ('kuiniuca.com', '网心云 · PCDN 服务'),
    ('pkoplink.com', '网心云 · PCDN 服务'),
    ('xinqiucc.com', '星球云 · PCDN 服务'),
    ('qiezibenpao.com', '江西节点 · PCDN 服务'),
    # B站关联公司杭州不同凡想（CNNIC whois 联系邮箱 @bilibili.com）MCDN/PCDN 视频分发，
    # 2026-10-21 起从 UNVERIFIED 升级为本条确认标注
    ('mountaintoys.cn', 'B站 · MCDN 视频分发'),
    ('mumu.nie.netease.com', '网易 MuMu 模拟器'),
    ('proxima.nie.netease.com', '网易数据上报'),
    ('fp.ps.netease.com', '网易资源下载'),
    ('sentry.netease.com', '网易 Sentry 错误上报'),
    # 网易游戏资源 CDN（网易官方组件库文档注明 comm.res.easebar.com 替代 nie.res）
    ('easebar.com', '网易 · 游戏资源'),
    ('qiyukf.com', '网易七鱼客服'), ('qiyukf.net', '网易七鱼客服'),
    ('nosdn.127.net', '网易 NOS 云资源'),
    ('netease.com', '网易服务'), ('127.net', '网易服务'),
    ('xiaohongshu.com', '小红书'), ('xhscdn.com', '小红书资源'),
    ('xhslink.cn', '小红书短链'),
    ('trustdecision.com', 'TrustDecision 设备风控'),
    ('biliimg.com', 'B站图片资源'), ('biligame.com', 'B站游戏'),
    # GearUP Portal（新加坡游戏加速器），event.sc 子域为埋点
    ('gearupportal.com', 'GearUP 游戏加速器'),
    # 公网出口 IP 查询服务（Clash 系工具常用）
    ('ipwho.is', 'ipwho.is IP 查询'), ('ip.sb', 'ip.sb IP 查询'),
    ('skk.moe', 'skk.moe IP 查询'), ('geojs.io', 'GeoJS IP 查询'),
    ('ipapi.is', 'ipapi.is IP 查询'),
    # 证书吊销/状态检查（CRL/OCSP）
    ('pki.goog', 'Google 证书吊销列表'),
    ('ctldl.windowsupdate.com', '微软证书信任列表更新'),
    ('windowsupdate.com', 'Windows 更新'),
    ('lencr.org', "Let's Encrypt 证书检查"),
    ('verisign.com', 'Verisign 证书吊销列表'),
    ('digicert.com', 'DigiCert 证书状态检查'), ('digicert.cn', 'DigiCert 证书状态检查'),
    ('globalsign.com', 'GlobalSign 证书状态检查'),
    ('ssl.com', 'SSL.com 证书状态检查'),
    ('amazontrust.com', 'Amazon Trust 证书状态检查'),
    ('rapidssl.com', 'RapidSSL 证书吊销列表'),
    ('nelreports.net', 'NEL 网络错误上报'),
    ('msftconnecttest.com', 'Windows 网络连接检测'),
    ('windows.cloud.microsoft', 'Windows 云服务'),
    ('location.live.net', '微软定位服务'),
    ('xboxservices.com', '微软 Xbox 服务'),
    ('skype.com', '微软 Skype'),
    ('dc.services.visualstudio.com', '微软开发者遥测'),
    ('gvt1.com', 'Google 分发服务'), ('gvt1-cn.com', 'Google 中国节点'),
    ('time.android.com', 'Android 时间服务'),
    ('ota.nvidia.com', 'NVIDIA 更新服务'), ('nvidia.com', 'NVIDIA 服务'),
    # Clash Verge 官方更新检查域（官网隐私政策注明 update.hwdns.net）
    ('hwdns.net', 'Clash Verge 更新服务'),
    # 公开 LLM 元数据目录站（AI 工具枚举模型用）
    ('models.dev', 'AI 模型目录'),
    ('awyydssub3.org', '代理订阅服务'),
    ('myapp.com', '腾讯应用宝'),
    ('github.io', 'GitHub Pages'),
    ('onedns.net', 'OneDNS 域名过滤'),
    ('amplitude.com', 'Amplitude 数据分析'),
    ('qhstatic.com', '360 静态资源'),
    ('scorecardresearch.com', 'comScore 统计'),
    ('bingapis.com', '必应接口'),
    ('yandexcloud.net', 'Yandex 云存储'),
    ('sentry.io', 'Sentry 错误上报'),
    ('mediav.com', 'MediaV 广告'),
    # 公共 DNS 任播地址（运营方长期固定，不属于"按临时 CDN IP 推断"）
    ('223.5.5.5', '阿里公共 DNS'), ('223.6.6.6', '阿里公共 DNS'),
    ('1.12.12.12', '腾讯公共 DNS'), ('120.53.53.53', '腾讯公共 DNS'),
)

# These are deliberately NOT ownership assertions. Keep a visible uncertainty
# marker and explain it in the tooltip/report; never infer an application from
# a CDN, random hostname or an IP previously used by another process.
UNVERIFIED = (
    # qjspcdn.cn 公网未注册（CNNIC whois 无记录 + NXDOMAIN，2026-10-11 核实），
    # 随机字母子域是典型的失效 SDK/探测流量特征，单列以便 tooltip 说明
    ('qjspcdn.cn', '失效域名（qjspcdn）'),
    ('rytesa.cn', '待识别（rytesa）'),
)

# Connection lists use concise names. Evidence and uncertainty remain in
# tooltips and review history, and candidates stay in the review log.
CANDIDATE_SERVICES = (
    ('smtcdns.net', '腾讯 · CDN 调度',
     '公开分流规则常将其列入腾讯域，但本轮缺少第一方归属说明；置信度中等'),
    ('cdntips.net', '腾讯 · 下载分发',
     '公开样本的下载路径嵌入 QQ 官方地址，仍需第一方资料交叉确认；置信度中等'),
    ('tfogc.com', '腾讯 · 下载分发',
     '公开样本出现微信官方下载路径；只能作为分发方向线索，置信度较低'),
    ('gaming-sdk.com', 'Discord · 游戏 SDK',
     '公开 SDK 文档出现 API v9/OAuth 端点，尚待 Discord 第一方资料确认'),
    ('default.exp-tas.com', '微软 · 实验配置',
     '公开主机资料和功能配置响应指向微软，本机来源为PhoneExperienceHost；最新微软Edge端点页未直接列出，置信度中等'),
    ('officeppe.com', '微软 Office · 预发布服务',
     '子域包含 Office 预发布环境特征，不作为正式生产服务确认'),
    ('weixinbridge.com', '微信 · 网页桥接',
     '名称指向微信桥接服务，缺少第一方归属资料'),
    ('byte-test.com', '字节跳动 · 网络拨测',
     '子域 perfops 指向性能拨测，字节归属尚未由第一方资料确认'),
    ('vegslb.com', '火山引擎 · 负载调度',
     '与字节系服务共同出现且名称类似 GSLB，仍需独立归属证据'),
    ('ctcdn.com.cn', '中国电信 · CDN',
     '域名指向电信 CDN 方向，但本轮未取得运营方第一方说明'),
    ('pancdn.net', 'PCDN · 内容分发',
     '仅标识可能的分发类型，不推断具体运营商或来源应用'),
    ('fenxi.com', '友盟 · 统计分析',
     '统计子域与域名名称提供方向线索，归属仍待第一方资料确认'),
)

# Dynamic addresses are matched only with the original process, port and
# protocol context. They are deliberately absent from the permanent ALIASES.
IP_CANDIDATES = (
    {'host':'122.14.229.138','label':'豆包输入法 · 接口',
     'proc':'imeservice.exe','path_contains':'doubaoime','port':443,'network':'udp',
     'basis':'历史账本中同进程/UDP 443 关联 ime-igw.doubao.com，跨13天、25个连接；非永久IP归属'},
    {'host':'101.126.56.149','label':'豆包输入法 · 接口',
     'proc':'imeservice.exe','path_contains':'doubaoime','port':443,'network':'udp',
     'basis':'历史账本中同进程/UDP 443 关联 ime-igw.doubao.com，跨12天、24个连接；非永久IP归属'},
    {'host':'101.126.56.184','label':'豆包输入法 · 接口',
     'proc':'imeservice.exe','path_contains':'doubaoime','port':443,'network':'udp',
     'basis':'历史账本中同进程/UDP 443 关联 ime-igw.doubao.com，跨10天、32个连接；非永久IP归属'},
    {'host':'122.14.236.20','label':'豆包输入法 · 接口',
     'proc':'imeservice.exe','path_contains':'doubaoime','port':443,'network':'udp',
     'basis':'历史账本中同进程/UDP 443 关联 ime-igw.doubao.com，跨7天、19个连接；非永久IP归属'},
)

# 安卓 App 品牌域（用于"引擎内 App"标注：引擎转发流量内核标不出进程，
# 这些域名在桌面端几乎不会被本机程序直连，结合引擎运行状态可归因）
APP_BRANDS = (
    (('fqnovel.com', 'fqnovelpic.com', 'fqnovelvod.com', 'qznovelvod.com',
      'fqnovelstatic.com'), '番茄小说'),
    (('douyin.com', 'douyinpic.com', 'douyinstatic.com', 'douyincdn.com'), '抖音'),
    # bdurl.net 2026-10-21 改判字节系（原误判百度App）
    (('bdstatic.com', 'bdimg.com', 'baidu.com'), '百度App'),
    (('zijieapi.com', 'snssdk.com', 'bytedanceapi.com', 'bdurl.net', 'ugsdk.cn',
      'ecombdapi.com', 'ndcpp.com', 'ibytedapm.com', 'bytegoofy.com',
      'bytegecko.com', 'yhgfb-cn-static.com'), '字节系App'),
    (('miui.com', 'xiaomi.com'), '小米服务'),
)

# 内核/端口属主能确认进程时的友好名
PROC_FRIENDLY = {
    'msedge.exe': 'Edge', 'chrome.exe': 'Chrome', 'firefox.exe': 'Firefox',
    'kimi.exe': 'Kimi', 'msmpeng.exe': 'Windows Defender',
    'androwsassistant.exe': '应用宝安卓引擎',
    # 代理软件与内核
    'verge-mihomo.exe': '代理内核', 'mihomo.exe': '代理内核',
    'clash-verge.exe': 'Clash Verge', 'flclash.exe': 'FlClash',
    'clash.exe': 'Clash', 'sing-box.exe': 'sing-box', 'v2ray.exe': 'v2ray',
    # Windows 系统常见进程
    'svchost.exe': '系统服务', 'imeservice.exe': '输入法服务',
    'textinputhost.exe': '输入法', 'searchhost.exe': '系统搜索',
    'startmenuexperiencehost.exe': '开始菜单',
    'shellexperiencehost.exe': '系统界面',
    'securityhealthservice.exe': 'Windows 安全中心',
    'nvcontainer.exe': 'NVIDIA 服务', 'onedrive.exe': 'OneDrive',
    'explorer.exe': '资源管理器', 'windowsterminal.exe': '终端',
    # 常用应用
    'qq.exe': 'QQ', 'wechat.exe': '微信', 'weixin.exe': '微信',
    'tim.exe': 'TIM', 'dingtalk.exe': '钉钉', 'feishu.exe': '飞书',
    'cloudmusic.exe': '网易云音乐', 'qqmusic.exe': 'QQ音乐',
    'steam.exe': 'Steam', 'steamwebhelper.exe': 'Steam',
    'baidunetdisk.exe': '百度网盘', 'thunder.exe': '迅雷',
    'code.exe': 'VS Code', 'doubao.exe': '豆包', 'wps.exe': 'WPS',
    'bilibili.exe': '哔哩哔哩', '哔哩哔哩.exe': '哔哩哔哩',
    'qqbrowser.exe': 'QQ浏览器', 'wegame.exe': 'WeGame',
    # 本机实测出现过的（2026-10-11 用户截图收集）
    'system': '系统内核', 'lockapp.exe': '锁屏界面',
    'kimi-webbridge.exe': 'Kimi 浏览器桥', 'lightkeeperservice.exe': 'MSI 灯效服务',
    'msi.terminalserver.exe': 'MSI Center 服务',
    'lghub_agent.exe': '罗技 G HUB', 'lghub_updater.exe': '罗技 G HUB 更新',
    'lghub_system_tray.exe': '罗技 G HUB', 'pixpin.exe': 'PixPin 截图',
    'androws.exe': '应用宝', 'androwsstore.exe': '应用宝商店',
    'androwssvr.exe': '应用宝服务', 'androwsdlsvr.exe': '应用宝下载服务',
    'androwsxyacc.exe': '应用宝加速组件', 'leishensdk_yyb.exe': '应用宝加速组件',
    'tencent.androwsextensionformsow.exe': '应用宝扩展组件',
    'lsass.exe': '系统安全服务', 'services.exe': '系统服务控制',
    'spoolsv.exe': '打印服务', 'wininit.exe': '系统初始化',
    'vmms.exe': 'Hyper-V 虚拟机',
    # GPT 桌面版（原 Codex 客户端）
    'chatgpt.exe': 'ChatGPT',
    # 常见常驻服务与桌面进程
    # 网易 MuMu 模拟器
    'mumunxdevice.exe': 'MuMu 模拟器', 'mumunxmain.exe': 'MuMu 模拟器',
    'mumunxservice.exe': 'MuMu 模拟器服务', 'mumunxupdater.exe': 'MuMu 模拟器更新',
    'cefviewwing.exe': 'MuMu 模拟器 · 界面渲染',
    'hipsdaemon.exe': '火绒安全',
    'mpdefendercoreservice.exe': 'Windows Defender',
    'winstore.app.exe': '微软商店',
    'msi.centralserver.exe': 'MSI Center 服务',
    'creative.sbcommand.exe': '创新声卡服务',
    'microsoftstartfeedprovider.exe': '微软资讯组件',
    'taskhostw.exe': 'Windows 任务宿主',
    'backgroundtaskhost.exe': 'Windows 后台任务',
    'runtimebroker.exe': 'Windows 运行时代理',
    'windowspackagemanagerserver.exe': 'winget 包管理服务',
    'crashpad_handler.exe': '崩溃上报进程',
    'aria2.exe': 'aria2 下载',
}

# 同名难辨的通用渲染进程：显示名取决于父进程是谁
GENERIC_RENDERERS = frozenset({
    'cefrendererprocess.exe',          # CEF 内嵌浏览器（应用宝/网易云等通用名）
    'cefsharp.browsersubprocess.exe',  # CefSharp
    'msedgewebview2.exe',              # WebView2
})

# 通用渲染进程认爹表：父进程名包含关键词 → 显示名
PARENT_BRAND = [
    ('androws', '应用宝 · 界面渲染'),
]


def friendly_proc(proc):
    """系统连接视图的进程显示名：命中别名表 → 友好名；否则仅去掉 .exe 后缀，
    原始名仍保留在悬停提示的“进程”字段中供核对。"""
    p = str(proc or '').strip()
    hit = PROC_FRIENDLY.get(p.lower())
    if hit:
        return hit
    return p[:-4] if p.lower().endswith('.exe') else p

_ENGINE_CACHE = {'t': 0.0, 'on': False}


def _is_engine_proc(proc, path):
    """进程是否属于应用宝安卓引擎（AndrowsAssistant / Tencent.Androws* 等）"""
    return 'androws' in (str(proc) + ' ' + str(path)).lower()


def engine_running(ttl=60):
    """应用宝安卓引擎是否在运行（60 秒缓存，避免每行都扫进程表）"""
    now = time.time()
    if now - _ENGINE_CACHE['t'] < ttl:
        return _ENGINE_CACHE['on']
    on = False
    try:
        import psutil
        for p in psutil.process_iter(['name']):
            if (p.info.get('name') or '').lower().startswith('androws'):
                on = True
                break
    except Exception:
        pass
    _ENGINE_CACHE['t'] = now
    _ENGINE_CACHE['on'] = on
    return on


def app_brand(host):
    """域名 → 安卓 App 品牌；命中才返回，否则空串"""
    h = str(host or '').lower().rstrip('.')
    if domain_matches(h, 'byteimg.com') and 'novel' in h.split('.')[0]:
        return '番茄小说'
    for suffixes, brand in APP_BRANDS:
        for s in suffixes:
            if domain_matches(h, s):
                return brand
    return ''


def domain_matches(host, suffix):
    host, suffix = host.lower().rstrip('.'), suffix.lower().rstrip('.')
    return host == suffix or host.endswith('.' + suffix)


def ip_candidate(row):
    raw = str(row.get('raw_host') or row.get('host') or '').strip()
    path = str(row.get('process_path') or '').lower().replace('/', '\\')
    proc = ntpath.basename(str(row.get('proc') or path)).lower()
    for candidate in IP_CANDIDATES:
        if raw != candidate['host'] or proc != candidate['proc']:
            continue
        if candidate['path_contains'] not in path:
            continue
        try:
            port = int(row.get('destination_port') or 0)
        except (TypeError, ValueError):
            continue
        if port != candidate['port']:
            continue
        if str(row.get('network') or '').lower() != candidate['network']:
            continue
        return candidate
    return None


def review_anomalies(row):
    """Detect invalid/control text independently of known service aliases."""
    import unicodedata
    result = {}
    for field in ('raw_host','host','proc','process_path','proc_parent'):
        value = str(row.get(field) or '')
        if any(ch == '\ufffd' or unicodedata.category(ch) in ('Cc','Cs')
               or ch in '\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069' for ch in value):
            result[field] = value
    return result


def needs_review(row, legacy=()):
    """目标是否缺少确认名称；日志层会另行过滤普通裸 IP。

    命中"待核实/失效"名单、候选名称、或任何别名表都认不出的目标都算。
    候选名称继续收集证据；已识别的正常目标返回 False。"""
    if review_anomalies(row):
        return True
    raw = str(row.get('raw_host') or row.get('host') or '').strip()
    if not raw:
        return False
    for suffix, _ in UNVERIFIED:
        if domain_matches(raw, suffix):
            return True
    for suffix, _, _ in CANDIDATE_SERVICES:
        if domain_matches(raw, suffix):
            return True
    if app_brand(raw):
        return False    # 引擎品牌域已能归因（应用宝 · 番茄小说 等），不算未识别
    return service_name(raw, legacy) == raw

def rules_revision():
    return (tuple(ALIASES),tuple(UNVERIFIED),tuple(CANDIDATE_SERVICES),repr(IP_CANDIDATES))

def service_name(host, legacy=()):
    return _service_name_cached(str(host or ''),tuple(legacy),tuple(ALIASES),tuple(UNVERIFIED),tuple(CANDIDATE_SERVICES))

@lru_cache(maxsize=2048)
def _service_name_cached(host, legacy, aliases, unverified, candidates):
    host = str(host or '')
    for suffix, label in unverified:
        if domain_matches(host, suffix):
            return label
    for suffix, label, _ in candidates:
        if domain_matches(host, suffix):
            return label
    if domain_matches(host, 'byteimg.com') and 'novel' in host.split('.')[0].lower():
        return '阅读图片资源'
    for suffix, label in (*aliases, *legacy):
        # Old keyword-only entries were prone to false positives.
        if '.' in suffix and domain_matches(host, suffix):
            return label
    return host

def label_basis(row, legacy=()):
    raw = str(row.get('raw_host') or row.get('host') or '')
    path = str(row.get('process_path') or '')
    proc = ntpath.basename(str(row.get('proc') or path))
    # ':System' 是 mihomo 认不出属主时给的伪进程名，与空值同等对待
    proc_known = (bool(proc) and proc not in ('?', '未知', '未知进程')
                  and proc.strip().lower() != ':system')
    try:
        ipaddress.ip_address(raw)
        is_ip = True
    except ValueError:
        is_ip = False
    if proc_known and _is_engine_proc(proc, path):
        return '来源进程为应用宝安卓引擎组件（Androws*）；引擎内 App 的目标按域名品牌标注'
    if not proc_known and engine_running():
        if app_brand(raw):
            return '内核未能标注来源程序；应用宝引擎运行中，按域名品牌推断为引擎内安卓 App（推断）'
        if is_ip:
            return '内核未能标注来源程序且无域名；应用宝引擎运行中，判定为引擎转发流量（推断）'
    if domain_matches(raw, 'qjspcdn.cn'):
        return ('该域名公网未注册（CNNIC whois 无记录 + NXDOMAIN，2026-10-11 核实）；'
                '随机字母子域疑似失效 SDK 或探测流量，来源程序待核实')
    for suffix, _, basis in CANDIDATE_SERVICES:
        if domain_matches(raw, suffix):
            return basis + '；该名称仍保留在待鉴定清单，后续轮次可改判'
    for suffix, _ in UNVERIFIED:
        if domain_matches(raw, suffix):
            return '仅缩短难读主机名；所属应用和用途待核实（' + suffix + '）'
    candidate = ip_candidate(row)
    if candidate:
        return candidate['basis'] + '；仅在同进程/端口/协议上下文显示候选，仍待交叉认证'
    if domain_matches(raw, 'qznovelvod.com'):
        return '依据域名及 reading/video 字样推断资源类型，未确认具体应用'
    if connection_name(row, legacy) == '豆包输入法':
        return '当前连接的程序路径包含 DoubaoIME，程序为 ImeService.exe；不是按 IP 固定归类'
    if service_name(raw, legacy) != raw:
        if proc_known and proc.lower() in PROC_FRIENDLY:
            return ('来源进程已识别为 ' + PROC_FRIENDLY[proc.lower()] +
                    '；目标按域名边界匹配服务名称（仅标识目标服务，不代表内容安全）')
        return '按域名边界匹配服务名称；仅标识目标服务，不代表来源程序或内容安全'
    return '目标服务未确认；来源程序及原始地址保留供核对'

def connection_name(row, legacy=()):
    host = str(row.get('host') or '')
    raw = str(row.get('raw_host') or host)
    path = str(row.get('process_path') or '').replace('/', '\\')
    proc = ntpath.basename(str(row.get('proc') or path))
    parts = path.lower().split('\\')
    candidate = ip_candidate(row)
    if candidate:
        return candidate['label']
    if 'doubaoime' in parts and ntpath.basename(path).lower() == 'imeservice.exe':
        return '豆包输入法'
    try:
        ipaddress.ip_address(raw)
        is_ip = True
    except ValueError:
        is_ip = False
    # ':System' 是 mihomo 认不出属主时给的伪进程名，与空值同等对待
    proc_known = (bool(proc) and proc not in ('?', '未知', '未知进程')
                  and proc.strip().lower() != ':system')
    brand = app_brand(raw)
    # 引擎进程自己的连接：标出引擎 + 目标 App 品牌
    if proc_known and _is_engine_proc(proc, path):
        return '应用宝 · ' + brand if brand else '应用宝安卓引擎'
    # 引擎转发客户机流量：内核标不出属主；引擎在运行 + 品牌域/裸IP → 归因引擎（推断）
    if not proc_known and engine_running():
        if brand:
            return '应用宝 · ' + brand
        if is_ip:
            return '应用宝安卓引擎'
    # 通用渲染进程（CEF/WebView2 同名难辨）：按父进程认爹
    if proc_known and proc.lower() in GENERIC_RENDERERS:
        plist = row.get('proc_parent') or []
        parents = ' '.join(plist)
        for key, plabel in PARENT_BRAND:
            if key in parents:
                return plabel
        if plist:
            return friendly_proc(plist[0]) + ' · 界面渲染'
    label = service_name(raw, legacy)
    if label != raw:
        # 来源进程可识别（在友好名表内）时，显示为“程序 · 目标服务”，
        # 直读“谁在连什么”；程序名已含在目标名里时不重复
        if proc_known and proc.lower() in PROC_FRIENDLY:
            fp = friendly_proc(proc)
            if fp not in label:
                return fp + ' · ' + label
        return label
    if proc_known:
        return friendly_proc(proc)
    if is_ip:
        return 'IP 连接 · ' + raw
    return '未知服务 · ' + raw
