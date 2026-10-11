# 迁出说明（F）

本仓库由 AdAway 仓库的 `webserver/win32` 迁出（独立仓库的第一步）。要点：

- 核心契约见 AdAway 仓库 `docs/windows-core-contract.md`（block_config.json 键、/internal-stats 字段、
  五个规则/策略文件、规则语义子集、迁出硬约束）。**契约先行**，本仓库不得单方面改变键名或字段含义。
- 不把 AdAway 的 `webserver.c` 当共享 Core：它同时承担平台分支、监听、代理、统计与系统适配。
- 发布必须 `gh release create ... --latest=false`：否则会抢走 Android 的 latest（曾经真的发生过）。
- 所有 Action 固定到 commit SHA；文件行尾 LF（.bat/.iss 用 CRLF）。
- 迁移时把原来的 `webserver/win32/xxx` 路径改为仓库根目录下的 `xxx`，流水线里的相对路径已同步改写，
  并由脚本断言"被引用的工程文件都存在"。
