# Windows 流量接管与 AdGuard 协同：M1 基线

该仓库是 Windows 独立产品；核心 C 服务端通过 `fetch-upstream.sh` 从 Android 仓库固定提交获取。本阶段**不复制**该服务端核心，也不安装驱动或修改路由。

## 已实现

- `traffic_mode_policy.h/.c`：独立、无副作用的运行模式决策器。
- `traffic_mode_policy_test.c`：13 组固定测试输入；在 Windows CI 中运行。
- `traffic_observer_win32.h/.c`：只读 AdGuard 进程探测。进程存在只是一条弱证据，不能证明流量接管冲突。
- `adguard_home_plan.h/.c`：AdGuard Home 自定义阻断 IP 的端口、绑定、CA 和 DNS 验证前置检查（10 项 C 测试）。
- Windows 设置页与托盘的“AdGuard Home 协同向导”：可选同机/远程客户端，给出候选 IPv4 并复制；所有配置需要用户自己在 AdGuard Home 中确认。
- Windows CI 的完整构建、监听冒烟和新单元测试已通过（参见 PR #1）。
- `wintun_probe_win32.c/.h`：使用 Windows 安全 DLL 搜索路径加载可选 `wintun.dll`，检查所需 API 与驱动版本；不会创建适配器、建立会话或改系统路由，侧边栏只显示“已发现 / 未发现 / 未接管”。
- `windows_capture_plan.c/.h`：纯 C 接管前置条件检查及 8 项测试；未具备用户授权、可用驱动接口、完整 TCP/UDP+DNS 转发、回滚快照时禁止实际接管。
- 不随构建自动下载或捆绑 Wintun DLL；后续正式集成必须独立核实 DLL 的来源、签名和分发许可证。
- `windows_network_inventory_win32.c`：利用 Windows IP Helper 读取 IPv4 默认路由及 IPv6 网卡网关候选数、活动网卡和 DNS 服务器计数（托盘右键“查看网络基线”），不更改配置，不采集或持久化具体 IP。
- `windows_network_journal.c`：纯 C 的内存撤销日志模型，测试逆序执行、失败保持待撤销与重复调用的幂等性。**它既没有持久化，也没有任何系统网络写操作，不足以作为真实路由恢复机制。**
- GUI 侧边栏显示“过滤范围：本地监听”“全局接管：尚未实现”和 AdGuard 进程提示，不把监听端口正常显示为全局覆盖。

## 未实现

- Windows TUN/WFP 接管、DNS 接管、IPv4/IPv6 TCP/UDP 流量转发与按应用过滤。
- Wintun 实际适配器生命周期、逐项记录并持久化路由/DNS 变更、按原值恢复并在异常退出时自动执行、完整 TCP/UDP 转发、权限提升、安全失败回退。目前仅有只读计数快照与内存日志决策测试，不能替代生产回滚。
- AdGuard 活动 WFP/代理/路由接管的可信识别。
- AdGuard Home 的 **DNS 实际应答与外部客户端 80/443、TLS 握手** 端到端验证（目前只有静态检查与本机管理服务探测）。
- 自动模式切换、系统路由备份/恢复和网络故障回滚执行器。

## 决策约束

- `TRAFFIC_TARGET_CAPTURE` 需要后端支持、用户授权和无冲突证据；当前 Windows 程序没有捕获后端，不能进入该模式。
- `TRAFFIC_TARGET_PREPARE_LISTENER` 只能启动本地监听及协同配置流程，**不能**标为已过滤。
- `TRAFFIC_TARGET_LISTENER` 只允许在流量确实能够抵达监听服务的情况下显示已协同。
- 仅 AdGuard 进程存在不会改变模式；其他过滤器仍在接管时不能争抢路由。
- 捕获失败时优先撤销本产品新增的网络规则，不触碰其他应用的设置。

## 下一阶段

1. 设计带置信度的 Windows 活动拦截证据探测（WFP、代理、DNS、TUN）。
2. 先做 TUN 捕获原型，验证 DNS、TCP/UDP、IPv6、回路保护和退出恢复。
3. 加入可验证的监听入口设置向导；优先支持 AdGuard Home。
4. 两端共用规则一致性测试，稳定后再抽出独立 `AdAway-Core`。
