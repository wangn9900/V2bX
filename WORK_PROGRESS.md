# 工作进度与架构记录 - Sing-box 核心重构
**日期**：2025-12-15

## 1. 核心目标达成 (Status: SUCCESS)
- [x] **Core Logic**:
    - [x] Removed `xray` and `hysteria2` support from `initconfig.sh` and `V2bX.sh`.
    - [x] Enforced `Sing-box` as the default and only core.
    - [x] Modified `V2bX` core (Go) to support VLESS Fallback (Initially attempted in Go, then shifted to script-based Nginx deployment). `v1.1.0` released.
- [x] **Script Enhancement**:
    - [x] Integrated `Nginx` installation in `install.sh`.
    - [x] Configured `Nginx` to listen on `127.0.0.1:80` as a catch-all masquerade site.
    - [x] Synchronized logic between `initconfig.sh` (standalone wizard) and `V2bX.sh` (management script).
    - [x] Fixed syntax errors in `initconfig.sh`.
- [ ] **Verification**:
    - [x] Verify `V2bX generate` wizard flow (User currently testing).
    - [ ] Confirm Nginx fallback works with V2bX VLESS+TLS nodes.与新版客户端（如 MOMclash）的兼容性问题。
    - [x] **Bug Fix**: Fixed `ConnCounter.Read/Write` using `Store` instead of `Add`, causing traffic under-reporting for clients using standard IO paths (e.g., Mobile Hy2).

## 2. 关键架构调整 (如何工作的)

为了让您既能“本地修代码”又能“云端自动发版”，我们建立了以下机制：

### 核心依赖逻辑
*   **go.mod 配置**：V2bX 指向了相对路径 `replace ... => ./sing-box_mod`。
*   **本地环境**：在 `V2bX/sing-box_mod` 建立了一个指向由于 `e:\GitHub\sing-box_mod` 的**软链接**。本地 `go build` 直接生效。
*   **云端环境 (CI)**：GitHub Actions 脚本已修改，构建时会自动 Checkout 您的 `wangn9900/sing-box_mod` 仓库到相应目录。

### 开发维护流程
以后由于只要修改了 **Sing-box 核心代码**：
1.  **本地修改**：在 `e:\GitHub\sing-box_mod` 目录修改代码。
2.  **推送云端**：务必运行 `git push` 把修改推送到 GitHub。
3.  **重新编译**：直接在 V2bX 触发新的 Release (Tag) 或 Build，CI 会自动拉最新的核心代码进行打包。
    *   *不再需要手动 update go.mod 或手动发 sing-box 的 release。*

## 3. 私有化分发脚本
*   **文件位置**：`e:\GitHub\V2bX\install_custom.sh`
*   **功能**：一键安装/更新 V2bX，所有下载源（Core Release, 管理脚本）均已指向您的账号 `wangn9900`。
*   **下一步**：建议 将此脚本内容更新到您的 `wangn9900/V2bX-script` 仓库的 `install.sh` 中，完成闭环。

## 4. 当前版本信息
*   **V2bX Version**: `v1.1.9` (已修复流量统计 Bug，Release ✅)
*   **Core**: `sing-box_mod` (Go 1.23 PATCHED)
*   **QUIC**: `v0.55.0`

## 5. 关键修复记录 (2025-12-23)
*   **Hy2/AnyTLS Mobile Traffic Fix**:
    *   **现象**: 手机端 (Mobile Client) 使用 Hy2/AnyTLS/XTLS 协议时，服务端流量统计几乎为 0。
    *   **原因**: 新版 Sing-box 内核在处理特定协议流时回退到标准 `Read/Write` 接口，而 V2bX 的 `ConnCounter` 在这两个方法中使用 `Store` (覆盖) 而非 `Add` (累加)，导致流量计数被不断重置。
    *   **方案**: 修正 `common/counter/conn.go`，将 `Store` 替换为 `Add`。验证后 TCP/UDP 流量统计均准确。
