# CSSwitch 桌面 app（Tauri）

跨平台桌面 app（正常窗口，非菜单栏），把 CSSwitch 的日常操作收进一个面板：本地 / 远程模式切换、第三方 / 官方模式切换、选 provider、填第三方 key、一键开始、起停代理与沙箱、三盏状态灯。

架构上它只是**进程管家**：Rust 后端负责起停子进程、注入环境变量、读写配置、探活。虚拟 OAuth 伪造已在 v0.1.4 移进 Rust 原生实现（`src/oauth_forge.rs`，app 运行时不再需要 node）；翻译逻辑仍在 `proxy/csswitch_proxy.py` 作子进程调用（下一步移 axum 拔 python），沙箱启动仍走 `scripts/launch-virtual-sandbox.sh`，以保住铁律护栏与已验证行为。

## 三条运行链路（互不依赖，可只用其一）

| 链路 | Science 跑在哪 | 起的是什么 | 外部依赖 |
|---|---|---|---|
| **本地** | 本机原生 | 直接 spawn `claude-science serve` | Python + Claude Science |
| **WSL** | Ubuntu 发行版 | `wsl.exe` 内置的 `csswitch-helper`（ELF） | WSL2 + Science |
| **SSH 远程** | 远程 Linux 主机 | `ssh` 远端 `csswitch-helper` | SSH + 远端 Science |

> 本地模式**不需要 bash，也不需要 WSL**——直接起 Science 可执行文件。
> WSL / SSH 共用同一 helper 协议（`remote/transport.rs` 按 target kind 分发）。

## 组成

```
desktop/
  src/                    前端面板（原生 HTML/CSS/JS，无框架）
    index.html  styles.css  main.js
  src-tauri/
    src/lib.rs            Tauri 入口与 command 注册
    src/lib_tauri.rs      后端主体（~2100 行）：本地模式全链路、模式切换、配置、探活
    src/remote_commands.rs 远程 / WSL 的 Tauri command 与 helper 资产管理
    src/oauth_forge.rs    虚拟 OAuth 伪造（HKDF-SHA256 + AES-256-GCM v2 令牌；护栏拒真实目录）
    src/config.rs         ~/.csswitch/config.json 读写（0700/0600、拒符号链接、原子写、掩码）
    src/proc.rs           探活 / which（which_all 遍历 PATH）/ 有界子进程执行 / 一次性 secret
    src/templates.rs      provider 预设、adapter 映射、模型与 thinking 策略
    src/fs_ext.rs         跨平台文件权限 / 原子写抽象
    src/remote/
      mod.rs  types.rs  store.rs  transport.rs
      ssh.rs              SSH 远程：命令编排 + helper 上传与自愈（内嵌 shell）
      wsl.rs              WSL：经 wsl.exe 进 Linux，复用同一 helper 协议
      auth.rs             远程主机 profile 与密钥存储
      credentials.rs      密码 / 密钥的凭据存储（含本机加密回退）
      prompt.rs  askpass.rs  交互式口令识别与 SSH askpass 辅助
    src/cli/              csswitch-helper 源码（被上面两个文件内联编译进去）
      commands.rs  serve.rs  proc_manager.rs  types.rs  logger.rs
    tauri.conf.json       窗口与 bundle 配置（resources 打包 proxy/ scripts/ helper-assets/）
    helper-assets/        内置的 Linux helper 二进制（WSL / SSH 模式用）
```

## 前置依赖

**构建期**：Rust（<https://rust-lang.org/tools/install>）、Node + npm（Tauri CLI 走 npm）。
打出的 app **运行时不需要 node**——虚拟 OAuth 伪造已是 Rust 原生实现。
macOS 另需 Xcode Command Line Tools。

**运行期按链路**：

| | 本地 | WSL | SSH 远程 |
|---|---|---|---|
| Claude Science | 已安装 | Ubuntu 内已安装 | 远程主机已安装 |
| Python 3 | **必需**（起翻译代理） | WSL 内 | 远程主机内 |
| bash | **不需要** | 不需要 | 不需要 |
| WSL2 | — | 必需 | — |

> **Python 是硬依赖**：翻译逻辑目前仍是 `proxy/csswitch_proxy.py` 作子进程调用。官方上游已用
> Rust 重写该层并移除此依赖，本分支暂未跟进（见 `docs/known-issues.md` #14）。
>
> **Windows 装 Python 须用 python.org 正式版**，不要用 Microsoft Store 版：后者的执行别名
> 会静默退出，`python --version` 无输出。app 已按「`--version` 输出含 Python 才算可用」
> 逐个验证 PATH 里的候选，故商店 stub 不会误命中，但手动排查时容易困惑。

**首次进入沙箱需点一次 Sign in**：app 打开 `?nonce=...` 后，Science 返回一个带
「Sign in」按钮的中转页，点击后才签发 `operon_auth` 并进入工作区。该 cookie 保持到
daemon 重启，因此**每次启动点一次**（见 `docs/known-issues.md` #13）。

## 开发运行

```bash
cd desktop
npm install
npm run tauri dev
```

CSSwitch 以正常窗口打开面板（420×700，已去托盘/菜单栏）。

后端定位 `proxy/` 与 `scripts/` 的顺序（`asset_root()`）：**① 打包后**优先用 Tauri 资源目录
（`Contents/Resources/`，见下「构建」——`proxy/`、`scripts/` 已被 bundle 进去）；**② 开发态**回退到
从可执行文件位置逐级上溯找仓库根（含 `proxy/csswitch_proxy.py`）。刻意**不看当前工作目录**，
避免据启动目录找到来路不明的脚本；开发时也可用 `CSSWITCH_REPO=/path/to/CSSwitch` 显式指定。

## 构建

```bash
cd desktop
npm run tauri build
```

产物按平台不同是 Windows `.exe` 安装器或 macOS `.app` / `.dmg`。`proxy/`、`scripts/` 与 `helper-assets/` 已通过 `tauri.conf.json` 的 `bundle.resources`
打进安装包资源目录，从正式安装的 app 启动也能找到并调用它们（自包含）。
沙箱运行状态落在可写的 `~/.csswitch/sandbox/home`（不写进只读的 `.app` 包内）。

> **签名/分发说明**：本版做 **ad-hoc 签名**（`bundle.macOS.signingIdentity: "-"`，正确封装资源），
> 但**未做 Apple 公证（notarization）**——那需要付费的 Apple Developer ID 证书。因此从 Finder 首次打开会被
> Gatekeeper 拦：请**右键 →「打开」**，或系统设置 → 隐私与安全性 →「仍要打开」。
> macOS 产物目前仍是 **arm64（Apple Silicon）**；Intel Mac 需要额外的 x86_64 / universal 构建。Windows CI 同时产出 x64 与 arm64 安装器。

## 铁律保障

- 第三方 key 经**环境变量**注入代理子进程，绝不进命令行参数（避免 `ps` 泄露）；回显前端只给末 4 位掩码。
- 沙箱端口 / 目录护栏由被调脚本负责（对真实端口 8765 与真实目录 `~/.claude-science` 失败关闭）。
- 退 app 默认停代理、保留沙箱运行（见 spec §5.1）。
- 子进程 stderr/stdout 收进 `~/.csswitch/logs/`。

### ⚠️ `auth_dir` 必须显式重定向（Windows 必读）

`--data-dir` **只覆盖 `data_dir`，不覆盖 `auth_dir`（登录态所在）**。Science 的 `auth_dir`
默认取 `os.homedir()/.claude-science`；Windows 的 `os.homedir()` 读 `USERPROFILE`，而我们
**刻意不覆盖 `USERPROFILE`**（覆盖会破坏 winsbx 护栏的 AppData 根解析）。两者相加的后果是：
`auth_dir` 落到**真实凭证目录**，沙箱里伪造的 `.oauth-tokens/*.enc` 根本不被读取，
`/api/auth/status` 恒为 `authenticated:false`，用户看到登录页。

更严重的是：真实目录里若存在真实 token，Science 会**直接用用户真实账号运行**——
此时沙箱并没有在用伪造登录，违反铁律 1/2。

因此起 `serve` / `url` / `stop` 时**必须**附带 `--config` 指向一份把
`[paths] auth_dir` 钉回沙箱的 config.toml（见 `lib_tauri.rs::write_science_config`）。
改这条路径时务必真机验证 `/api/auth/status` 返回 `authenticated:true`，
否则会以「登录页」的形式静默回归。根因证据链见 `findings/2026-10-12-windows-local-mode-auth-dir.md`。

### 已知隔离缺口

即便如此，Science 仍会经 `SHGetKnownFolderPath`（读 `USERPROFILE`）向**真实目录**写入
`auth-owner.lock` 等文件。**沙箱与真实目录尚未完全隔离**，属待收敛的铁律隐患。

## 测试

后端纯逻辑（config / proc）有 Rust 单元测试：

```bash
cd desktop/src-tauri
cargo test
```

覆盖：0700/0600 权限、符号链接拒绝、原子写、key 掩码、探活、which、secret 生成。
面板与整链联调为手动冒烟（会启动沙箱 Science，须用户明确同意，守铁律）。
