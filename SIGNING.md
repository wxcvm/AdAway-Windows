# Windows 发布与代码签名政策

**当前临时政策（2026-10-17）：Windows 1.75 起允许未签名正式发布。**

仓库的 `.github/workflows/windows-release.yml` 使用 `WINDOWS_UNSIGNED_RELEASE: '1'`。
在此模式下，正式版和预览版不会因缺少 `WINDOWS_CERT_PFX_B64` 或
`WINDOWS_CERT_PASSWORD` 而失败，也不会尝试 Authenticode 签名。
发布标题和说明必须清楚标示“未签名”，以免被误认为来自受信任发布者。

## 安全限制

- 未签名的程序和安装器可能被 Windows SmartScreen、Smart App Control 或安全软件拦截，并不一定能手动放行。不要为运行软件关闭 Windows 安全保护。
- 官方 GitHub Release 的 SHA-256 校验用于检测文件是否被篡改或下载损坏，但 **不等同于可信代码签名**。
- 当恢复签名政策时，必须先准备可信证书并逐项验证主 EXE 与安装器，然后把 `WINDOWS_UNSIGNED_RELEASE` 改为 `'0'`，重启签名验证。
- 除非另有明确批准，不允许重新生成自签名证书冒充正式可信签名。

## 未来恢复代码签名所需 Secrets

| Secret | 用途 |
|---|---|
| `WINDOWS_CERT_PFX_B64` | Base64 编码的原代码签名 PFX |
| `WINDOWS_CERT_PASSWORD` | 该 PFX 的密码 |

证书和密码绝不能提交仓库、日志或发送到聊天。
在恢复签名前需要核实使用哪张受信任证书；自签名证书无法消除 SmartScreen 警告。

## 当前安装器 UX 合同

`installer.iss` 使用稳定 AppId，默认首选 `D:\ADBlock`；
没有 D 盘时回退至 `%LOCALAPPDATA%\Programs\ADBlock`。
使用者可以在向导中改路径。安装完成的启动按钮默认选中；
也有开始菜单和桌面快捷方式。静默升级完成后会自动重启程序。
原有安装路径在升级时优先保留，不会强制把现有安装迁移到 D 盘。

所有这些功能都应通过 Windows CI 编译、安装、快捷方式和实际 GUI 启动验证。
