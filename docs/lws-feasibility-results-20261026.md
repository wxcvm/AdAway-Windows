# Windows LWS 验证结果（2026-10-26）

## 当前结论

**不建议当前公共 HTTP 挂载适配方案迁入生产（NO-GO）。** 这不是宣称 LWS 的全部公共客户端或事件后端方案都不可行。

冻结消费者源码：`f1f0e116d57c00ea1f73dd94040cd2be69a25f85`；固定共享源码：Android `d710dd89ff9e77204ec5815394a8757fba033ce4`。本提交仅增加最终报告，不移动共享源码或生产 portable core 固定版本。

## 实际进程证据

[40256075862](https://github.com/wxcvm/AdAway-Windows/actions/runs/40256075862) 的所需正确性步骤仍为 **失败**，其独立基准采集步骤成功并不改变这一结论。

- Mongoose：24组完整正确性测试通过。
- LWS：前20组通过，第一条 IPv4 明文 HTTP `/forward/text` 转发失败。
- 两后端各18项原生双栈/严格TLS/完整正文检查通过；损坏图片负例正确被拒绝。
- 基础HTTP的10条字段对照一致，但原始结果明确标记 `source_runs_complete:false`，不计作完整适配通过。
- 声明4096字节，实际4018；SHA-256证明它们是4013个 `x` 加错误的5字节 `0\r\n\r\n`。真实正文缺83字节，HTTP读取器按总长度报告少78字节。
- 正常/详细日志与此前两次独立运行均重现，不能解释为HTTPS证书拒绝。

## 配对数据

五负载 × 两种日志模式 × 1/16/64并发 × 五轮 × 两后端，共300阶段；每阶段预热2秒、测量5秒，非quick，负载错误0。但25/30组超过10%的配对波动，性能结论为 **INCONCLUSIVE**。不能宣布性能准入通过或推断 Android 真机表现。

[公开JSON/日志附件](https://github.com/wxcvm/AdAway-Windows/actions/runs/40256075862/artifacts/12624232063) 不含基准exe、CA私钥或安装包。所有原始测量JSON、完整直方图、能力原文及逐文件SHA-256也已在共享报告中gzip长期归档，共约274KiB。

## 集中报告与边界

[固定报告提交：双端全文、原始数据和CSV](https://github.com/wxcvm/AdAway/blob/9b34e4fbe2ece33ce9ae8e3184b57a4d1303e3b1/docs/lws-feasibility-results-20261026.md)。Linux另300阶段均无负载错误，9/30组超波动；其Android验证包括API30/API35实际模拟器与三ABI构建，ARM64/RISC-V仅构建。

保持草稿[PR 38](https://github.com/wxcvm/AdAway-Windows/pull/38)与Android[PR 97](https://github.com/wxcvm/AdAway/pull/97)，所需正确性不通过时不自动合并。没有填充丢失字节、扩大容量、吞掉异常、禁用证书验证或私有LWS补丁；生产入口、覆盖层、应用版本/安装身份、稳定更新源均未改变，没有发布应用或安装真实设备。

下一次若继续技术试验，应先用独立公共客户端/事件后端验证完整转发、分段/半关闭、背压与取消，再谈迁移；本报告不授权自动切换。
