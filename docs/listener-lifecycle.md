# 双协议监听、随启动创建与 HTTPS 诊断

设置页把 IPv4 / IPv6 分开输入和检查，二者可以同时启用；留空关闭对应协议，不能全部关闭。只有 IPv6 也可以运行。点击“仅本机（推荐）”填入 127.0.0.1 / ::1；“所有网卡”填入 0.0.0.0 / ::，允许局域网访问。两个协议各自有创建/移除按钮，不再从单个输入框猜测要操作的协议。备用端口只修改草稿。

“随服务器启动创建缺失地址”默认关闭。勾选后点击保存，或保存并重启；只有实际服务器启动且地址缺失时才请求管理员授权，在软件回环接口创建私有 IPv4 / ULA（/32 或 /128，SkipAsSource）。地址本身仍只在当前开机/接口生命周期存在，重启后启动服务器时按选项重新创建；没有添加提权计划任务、驱动、持久网卡配置或更改 DNS/默认路由。取消 UAC 时不启动响应监听，日志和仪表盘报告错误，配置可从设置页修正。正常进程保持原权限。

双地址准备作为一个事务：第二个地址/端口失败时回滚本次新增的第一个地址，原有地址不取得所有权。创建后主程序仍需实际 bind；显式启用的任一地址/端口失败时关闭本次其他响应监听，避免部分启动显示成功。绑定阶段若发生竞争，已成功准备的托管地址可保留供重试或按归属移除；不声称所有后续运行故障都会撤销地址。

旧 bind_ip / bind_all 设置保留原有含义：旧的单 IPv6 不会迁移为全网卡或隐式打开 IPv4。保存新格式后写入 listen_ipv4 / listen_ipv6，CLI 使用 --listen-ipv4 / --listen-ipv6，值 - 表示关闭，显式配置要求所有已启用监听成功。沿用 Android 独立固定提交的 listener_pair 契约，生产 portable core 固定提交保持不变。

AdGuard 检测窗口读取本次真实启动配置，保存草稿不改变其检测目标。HTTP、HTTPS、DNS、UDP 结果分别呈现。HTTPS 复用项目固定 OpenSSL 3.5.9：只连接匹配监听的本机地址，使用原域名 SNI/Host 和证书名称校验，信任锚从 Windows ROOT 只读加载。固定本机基线使用 localhost SNI。禁止跳过证书验证、修改信任库、代理或跟随跳转。报告分为连接/TLS 未完成、证书拒绝、TLS 与证书通过但无回执、加密回执通过；不把普通 HTTPS 页面计为 AdAway。

这是基于所读信任锚的离线链/名称校验，不下载 AIA/吊销信息，不等于 Schannel 的完整在线策略或所有浏览器、其他账户、证书固定应用的结果。每个 TLS 连接 2.5 秒/4096 字节预算。

QUIC / HTTP/3 尚未实现。窗口明确说明 TCP/443 不证明 UDP/443，并只读显示 IPv4/IPv6 UDP 443（以及自定义 HTTPS 端口）的绑定 PID；UDP 绑定不能识别为 QUIC。没有发送伪 QUIC 探测，也不修改 AdGuard 或防火墙来强制回退 TCP。

实现选择：保留已有 IP Helper、Winsock、OpenSSL 和 BCrypt；没有为已有能力重复增加网络库。评估 MsQuic 后，完整 QUIC 服务涉及 UDP、ALPN h3、HTTP/3 与 QPACK、证书策略及部署/许可证验证，应独立集成和验收，不在 TCP 监听上添加一个“支持 QUIC”的开关。

参考：
- https://docs.openssl.org/3.5/man3/SSL_set1_host/
- https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createunicastipaddressentry
- https://microsoft.github.io/msquic/msquicdocs/docs/Deployment.html

CI 使用一次性 Windows runner，通过实际 INI→main→双协议启动/创建/恢复/禁用/失败链路，并在临时 CurrentUser ROOT 安装测试进程生成的 CA 来验证严格 HTTPS 正反例，结束后移除该测试 CA。日常主机不执行地址/信任写入。
