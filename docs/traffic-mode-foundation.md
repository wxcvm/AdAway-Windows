# Windows 流量接管与 AdGuard 协同：M1 基线

该仓库是 Windows 独立产品；核心 C 服务端通过 `fetch-upstream.sh` 从 Android 仓库固定提交获取。本阶段**不复制**该服务端核心，也不安装驱动或修改路由。

## 已实现

- `traffic_mode_policy.h/.c`：独立、无副作用的运行模式决策器。
- `traffic_mode_policy_test.c`：13 组固定测试输入；在 Windows CI 中运行。
- `traffic_observer_win32.h/.c`：只读 AdGuard 进程探测。进程存在只是一条弱证据，不能证明流量接管冲突。
- GUI 侧边栏显示“过滤范围：本地监听”“全局接管：尚未实现”和 AdGuard 进程提示，不把监听端口正常显示为全局覆盖。

## 未实现

- Windows TUN/WFP 接管、DNS 接管、IPv4/IPv6 TCP/UDP 流量转发与按应用过滤。
- AdGuard 活动 WFP/代理/路由接管的可信识别。
- AdGuard Home 自定义阻断 IP、80/443 可达性、HTTPS CA 信任的端到端验证。
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
