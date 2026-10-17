# Windows 签名（Code Signing）

本仓库的正式发布产物 `webserver.exe` 用 **Authenticode** 签名（CI 用 `osslsigncode`，在
`.github/workflows/windows-release.yml` 的 `Code-sign webserver.exe` 一步里执行）。

## 需要两个仓库 Secrets

| Secret | 内容 |
|---|---|
| `WINDOWS_CERT_PFX_B64` | 生产签名证书 `.pfx` 的 **base64**（单行，无换行） |
| `WINDOWS_CERT_PASSWORD` | 该 `.pfx` 的密码 |

上传（在仓库根目录，本机有证书文件时）：

```
# Linux/macOS/Git-Bash
base64 -w0 release.pfx > pfx.b64
gh secret set WINDOWS_CERT_PFX_B64 --repo wxcvm/AdAway-Windows < pfx.b64
gh secret set WINDOWS_CERT_PASSWORD --repo wxcvm/AdAway-Windows   # 交互式输入，勿写进命令历史
```
```
# Windows PowerShell
[Convert]::ToBase64String([IO.File]::ReadAllBytes('release.pfx')) | Set-Content -NoNewline pfx.b64
gh secret set WINDOWS_CERT_PFX_B64 --repo wxcvm/AdAway-Windows < pfx.b64
gh secret set WINDOWS_CERT_PASSWORD --repo wxcvm/AdAway-Windows
```
> 上传后**删除本地的 `pfx.b64`**；`.pfx` 与密码都**不要**提交进仓库。

## CI 里的强制策略（已实现）

- `workflow_dispatch` 且 ref 为 `refs/heads/main`：**缺证书直接失败**（不允许产出"正式"却未签名的构建）；
- `refs/tags/progress-win-*`、`refs/heads/preview/release-*`：同样强制；
- 其它普通 CI：缺证书则**跳过**签名（不失败）。

## 签名后如何验证（重要，踩过的坑）

`osslsigncode verify` 默认用 **运行时的 CA 信任库**；**自签名证书不在其中**，所以"普通 verify"
会失败 —— 这不代表签名坏了。CI 已改为**用签名证书本身作为 CAfile** 验证：

```
openssl pkcs12 -in cert.pfx -clcerts -nokeys -passin "pass:$WINDOWS_CERT_PASSWORD" -out cert.pem
osslsigncode verify -CAfile cert.pem webserver.exe
```

## 诚实的边界（不要夸大）

- **自签名 = 不消除 Windows 的"未知发布者"提示**。它只提供：完整性、以及"同一把钥匙签名"的可验证性。
- 要让 SmartScreen 不再拦，需要**受信任的代码签名证书（EV 更佳）**；届时**只需替换上面两个 Secrets**，CI 无需改动。
- 只签 `webserver.exe`；**安装器 exe / 便携 zip** 由各自工作流产出，**目前未签名**，产物名里也如实写着 `unsigned`。
- 签名**不能替代**完整性校验：发布里仍保留 `SHA256SUMS.txt`。

## 怎么确认 CI 真的签了

触发一次 `Windows 11 webserver release` 的 `workflow_dispatch`（ref = main），然后看该步日志：
- 有证书 → 出现 `signed OK (verified against the signing certificate)`；
- 无证书 → 该步**报错退出**（这正是"不接受未签名的正式发布"的守卫）。