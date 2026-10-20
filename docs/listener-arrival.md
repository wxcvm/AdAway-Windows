# AdGuard DNS 与请求到达检测

设置 → “AdGuard 检测与协同…” → “检测 DNS 与请求是否到达 AdAway”。保留原来的 AdGuard Home 手动协同向导。
独立窗口提供广告规则、Hosts 规则两个可修改/留空的测试域名，编辑不自动发起诊断。预设 ad.doubleclick.net 来自 AdGuard 官方 DNS 广告域名示例，不保证在用户当前规则中被拦截。
参考：https://kb.adguard.com/kb/pt-BR/general/ad-filtering/how-ad-blocking-works/

按已应用配置分别检查：AdGuard 进程、AdAway 管理回执、HTTP 响应入口、系统 DNS 返回是否指向当前本机监听、携带测试域名 Host 的请求是否得到新鲜 nonce 回执。
进程存在不能证明 WFP/代理接管，系统 DNS 返回也可能来自缓存或 Hosts；具体 AdGuard 规则及语法类别以其日志为准。
公网或不匹配的 DNS 返回只显示结果，不建立到公网源站的连接。请求不经过系统 HTTP 代理，不跟随重定向；每次本机 HTTP 连接最多 2 秒/4096 字节。
沿用 Winsock GetAddrInfoExW 的系统 DNS 与 2 秒预算，沿用 BCrypt 生成随机 128 位 nonce，没有新建通用转发器、DNS 上游或网络接管。

生产 native 入口的固定 GET /adaway-listener-probe/<32 hex> 在任何转发前处理，只返回固定格式 nonce、no-store；拒绝非法 nonce 与其他方法。
它是公开无状态回执，不是认证，不返回内部配置/统计/浏览记录，不改变规则或用户排行。HTTPS 证书信任与其他应用流量路径明确未验证。
回执头文件从 Android 独立固定提交校验；production portable core 仍固定 4470606366e614abdb308fdfe94734d28167439c，只增加受检查的覆盖层入口。

测试覆盖实际 webserver.exe 与 native 客户端的 IPv4/IPv6 回执、域名 Host、错误 nonce/方法/普通 HTTP 200 拒绝，GUI 编辑/手动检测与实际回执。
一次性 CI 的系统 DNS 夹具临时追加 .invalid Hosts 映射，完成后按原字节恢复；日常主机不运行此写入步骤，产品功能不修改 Hosts、DNS、WFP、代理、AdGuard 或证书。
