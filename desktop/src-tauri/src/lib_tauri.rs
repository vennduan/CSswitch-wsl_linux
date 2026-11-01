use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

// 跨平台文件权限操作（Unix 设权限，Windows no-op）。
use crate::fs_ext::{open_log_file, set_file_permissions};
use serde::Deserialize;
use serde_json::json;
use tauri::{Manager, State};

/// spawn 子进程时压制控制台窗口。
///
/// 本 app 是 GUI 子系统程序（`windows_subsystem = "windows"`），Windows 规则下它拉起的
/// 控制台子进程会各自新开一个可见控制台窗口。状态轮询每 2.5s 跑一次
/// `claude-science status`，于是 DOS 窗口按轮询节奏不停闪。`CREATE_NO_WINDOW` 消掉它。
///
/// 注意此 flag **不被孙进程继承**：`bash launch-*.sh` 内部再拉起的程序仍需自行处理。
#[cfg(target_os = "windows")]
fn hidden(cmd: &mut Command) -> &mut Command {
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(0x0800_0000) // CREATE_NO_WINDOW
}
#[cfg(not(target_os = "windows"))]
fn hidden(cmd: &mut Command) -> &mut Command {
    cmd
}

/// Claude Science 二进制路径，仅 macOS 本地模式有效。
#[cfg(target_os = "macos")]
const SCIENCE_BIN: &str = "/Applications/Claude Science.app/Contents/Resources/bin/claude-science";

/// 平台分派：定位 Claude Science CLI。
/// macOS：/Applications 路径；Windows：官方安装目录 / PATH；其他平台（helper 构建）None。
fn science_bin_any() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let p = PathBuf::from(SCIENCE_BIN);
        return if p.is_file() { Some(p) } else { None };
    }
    #[cfg(target_os = "windows")]
    {
        return science_bin_windows();
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        return None;
    }
}

/// Windows 上定位 Claude Science CLI（官方安装器 v0.1.x 默认布局）：
/// 1) `%LOCALAPPDATA%\Programs\ClaudeScience\claude-science.com`（console shim，同步转发）
/// 2) 同目录 `claude-science.exe`（真实二进制）
/// 3) PATH 里的 `claude-science`（用户自装到别处）
#[cfg(target_os = "windows")]
fn science_bin_windows() -> Option<PathBuf> {
    let names = ["claude-science.com", "claude-science.exe"];
    if let Some(lad) = std::env::var_os("LOCALAPPDATA") {
        let dir = PathBuf::from(lad).join("Programs").join("ClaudeScience");
        for n in names {
            let p = dir.join(n);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            for n in names {
                let p = dir.join(n);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    None
}

/// 给 Science CLI 子进程设置独立 HOME（铁律 3：与真实目录隔开）。
/// Windows **绝不覆盖 USERPROFILE**：Science 自带的 winsbx 护栏经 SHGetKnownFolderPath
/// 解析 local AppData 根来构建 protected-root 表，该解析受 env USERPROFILE 影响——
/// 覆盖成沙箱路径后解析结果不存在（win32 error 3），护栏拒绝 arming，serve 以 rc=4 退出；
/// 且伪造假 AppData 根会让护栏的 protected-root 表指向假目录，削弱其对真实 AppData 的保护。
/// 真机冒烟已验证：HOME-only 覆盖 + --data-dir 即可完整 arming，真实目录零改动。
fn science_cli_env(cmd: &mut Command, home: &Path) {
    cmd.env("HOME", home);
}

/// 写一份 Science 的 config.toml，把 `[paths] auth_dir` 钉到沙箱，并返回其路径。
///
/// **这是 Windows 本地模式能否工作的关键。** Science 的 `auth_dir`（登录态所在）
/// 默认取 `os.homedir()/.claude-science`，而 Windows 的 `os.homedir()` 读 `USERPROFILE`
/// ——我们为不破坏 winsbx 护栏刻意不覆盖 `USERPROFILE`，于是 `auth_dir` 落到**真实凭证目录**，
/// 沙箱里伪造的 `.oauth-tokens/*.enc` 根本不被读取，`/api/auth/status` 恒为未登录。
/// `--data-dir` **只**设 `data_dir`，不设 `auth_dir`，所以必须另给 `--config`。
/// 真机验证：加上本配置后 `/api/auth/status` 返回 `authenticated:true`（伪造身份）。
///
/// **跨平台**：Windows 必需（上面那套）；macOS 侧本来 `HOME` 已指向沙箱、`auth_dir` 自然落在沙箱内，
/// 这里再钉一次是**冗余但无害**的加固。此前本函数被 `#[cfg(target_os = "windows")]` 挡住，而
/// `sandbox_url()`（macOS + Windows 共用）会调用它 → **macOS 编译直接失败**（`E0425: cannot find
/// function write_science_config`）。该断裂自 2026-10-12 的 Windows 修复 commit 起就存在，只因 CI
/// 在本 fork 从未真正跑过而没被发现（2026-11-01 由 macOS CI 任务暴露）。
fn write_science_config(auth_dir: &Path) -> Result<PathBuf, String> {
    // TOML 用正斜杠，避开反斜杠转义；路径里不含引号，Windows 合法路径不会引号。
    let p = auth_dir.to_string_lossy().replace('\\', "/");
    let cfg_path = sandbox_home().join("science-config.toml");
    let body = format!("[paths]\nauth_dir = \"{p}\"\n");
    if let Some(parent) = cfg_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("建沙箱配置目录失败：{e}"))?;
    }
    std::fs::write(&cfg_path, body.as_bytes())
        .map_err(|e| format!("写 Science 配置失败：{e}"))?;
    Ok(cfg_path)
}

/// 沙箱里 Science 自己展开的 kernel runtime 目录（`data-dir/runtime/`）。
fn sandbox_runtime_dir() -> PathBuf {
    sandbox_home().join(".claude-science").join("runtime")
}

/// 沙箱内路径逐级检查：不得有任何一级是符号链接（防预置链接把删/写指到真实目录）。
/// 且相对路径里**不得出现 `..`**——`Path::strip_prefix` 只按字面前缀匹配，
/// `home\..\..` 会被判成「在 home 之下」而实际指向沙箱外，必须显式拒绝。
fn sandbox_path_is_safe(path: &Path) -> bool {
    let root = sandbox_home();
    if config::assert_not_symlink(&root).is_err() {
        return false;
    }
    let Ok(rel) = path.strip_prefix(&root) else {
        return false;
    };
    let mut cur = root.clone();
    for comp in rel.components() {
        match comp {
            std::path::Component::Normal(c) => cur = cur.join(c),
            // `..` / 根 / 前缀：一律拒绝（会逃出沙箱）。
            _ => return false,
        }
        if config::assert_not_symlink(&cur).is_err() {
            return false;
        }
    }
    true
}

/// 清沙箱里的 runtime 残留。`full=false` 只删 `.tmp-*` 临时目录（daemon 解压中途被杀的残留）；
/// `full=true` 连正式目录一起删（半成品目录会让 Science 下次「改名到位」直接失败）。
///
/// 铁律：只删 `sandbox_home()` 之下的路径；路径逐级校验不得含符号链接，否则拒绝。
fn clean_sandbox_runtime(full: bool) -> bool {
    let dir = sandbox_runtime_dir();
    if !sandbox_path_is_safe(&dir) {
        return false;
    }
    clean_runtime_dir(&dir, full)
}

/// 清理指定 runtime 目录（`clean_sandbox_runtime` 的可测内核）。
fn clean_runtime_dir(dir: &Path, full: bool) -> bool {
    if !dir.exists() {
        return false;
    }
    if full {
        return std::fs::remove_dir_all(dir).is_ok();
    }
    let mut any = false;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            // Science 解压时用的临时名形如 `0.1.50-release.tmp-<pid>-<ts>`；
            // 不写死版本号前缀，任何 `*.tmp-*` 都清掉。
            if name.contains(".tmp-") {
                let p = e.path();
                let _ = if p.is_dir() {
                    std::fs::remove_dir_all(&p)
                } else {
                    std::fs::remove_file(&p)
                };
                any = true;
            }
        }
    }
    any
}

/// 递归复制目录（用于把 runtime 从真实安装目录搬到沙箱）。
fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let from = e.path();
        let to = dst.join(e.file_name());
        if from.is_dir() {
            copy_dir(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// 从**真实** Science 目录把 runtime 复制到沙箱，让 Science 跳过自己那次「解压 + 改名」。
///
/// 背景：Science 首次在沙箱 data-dir 展开 kernel runtime 时，先解到 `runtime/<ver>.tmp-<pid>-<ts>`
/// 再改名到位。Windows 上这一步会因为杀毒软件 / 索引器占用而 `EPERM` 失败（客户真机复现），
/// 而失败留下的半成品目录会让**之后每一次**启动都在同一步失败。
/// 官方安装已经在真实目录里展开过同一份 runtime，复制过去即可绕过（我们本机验证：runtime 已在位时
/// Science 不再重复展开）。
///
/// 铁律：真实目录**只读**，且只碰 `runtime/` 这一个子目录——`.oauth-tokens/`、`encryption.key`、
/// `active-org.json`、`orgs/`、`.key-backups/` 等凭证一律不读不拷（铁律 1/2）。
fn copy_runtime_from_real_install() -> Option<String> {
    let real_runtime = dirs::home_dir()?.join(".claude-science").join("runtime");
    if !real_runtime.is_dir() {
        return None;
    }
    let ver_dir = std::fs::read_dir(&real_runtime)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.is_dir()
                && p.file_name()
                    .map(|n| n.to_string_lossy().contains("-release"))
                    .unwrap_or(false)
        })?;
    let name = ver_dir.file_name()?.to_os_string();
    let dst = sandbox_runtime_dir().join(&name);
    if dst.exists() {
        return None; // 沙箱已有 → 不覆盖（Science 会自己判断是否需要展开）
    }
    if !sandbox_path_is_safe(&dst) {
        return None;
    }
    copy_dir(&ver_dir, &dst).ok()?;
    Some(dst.display().to_string())
}

#[derive(Default)]
struct AppState {
    proxy: Option<Child>,
    proxy_port: u16,
    secret: String,
    provider: String,
    /// 当前代理进程所用 key 的非加密指纹（仅内存、绝不落盘/打印）。
    /// 换 key 后指纹变化 → 触发重启，避免复用带旧 key 的代理。
    key_fp: u64,
    sandbox: Option<Child>,
    sandbox_port: u16,
    sandbox_url: Option<String>,
}

/// key 的非加密指纹（FNV-1a 64-bit），只用于判断「key 是否变了」。绝不打印、绝不落盘。
/// 使用 FNV-1a 而非 std DefaultHasher，确保跨 Rust 版本哈希值稳定，避免工具链升级后误判 key 变化。
fn key_fingerprint(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in s.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

// ---------- profile / adapter 元信息 ----------
fn key_env_for_adapter(adapter: &str) -> &'static str {
    match adapter {
        "deepseek" => "DEEPSEEK_API_KEY",
        "qwen" => "DASHSCOPE_API_KEY",
        _ => "CSSWITCH_RELAY_KEY",
    }
}

fn is_native_adapter(adapter: &str) -> bool {
    adapter == "deepseek" || adapter == "qwen"
}

fn parse_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = rest.split(['/', ':', '?', '#']).next().unwrap_or("");
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn upstream_host(adapter: &str, base_url: &str) -> String {
    match adapter {
        "deepseek" => "api.deepseek.com".to_string(),
        "qwen" => "dashscope.aliyuncs.com".to_string(),
        _ => parse_host(base_url).unwrap_or_default(),
    }
}

struct ProxyLaunch {
    adapter: String,
    base_url: String,
    model: String,
    key: String,
    key_env: &'static str,
    thinking_policy: &'static str,
}

fn proxy_launch_for(profile: &config::Profile) -> ProxyLaunch {
    let adapter = templates::adapter_for(&profile.template_id).to_string();
    ProxyLaunch {
        key_env: key_env_for_adapter(&adapter),
        adapter,
        base_url: profile.base_url.clone(),
        model: profile.model.clone(),
        key: profile.api_key.clone(),
        thinking_policy: templates::thinking_policy_for(&profile.template_id),
    }
}

fn assert_profile_runnable(profile: &config::Profile) -> Result<(), String> {
    match profile.api_format.as_str() {
        "anthropic" | "openai_chat" => {}
        other => {
            return Err(format!(
                "api_format `{other}` 暂不支持，请选 anthropic 或 openai_chat。"
            ));
        }
    }
    let launch = proxy_launch_for(profile);
    if launch.key.trim().is_empty() {
        return Err("当前 Profile 未填写 API Key。请填写后重试。".into());
    }
    if !is_native_adapter(&launch.adapter) {
        if launch.base_url.trim().is_empty()
            || !(launch.base_url.starts_with("http://") || launch.base_url.starts_with("https://"))
        {
            return Err("relay 配置需要 http(s):// 开头的 base_url。".into());
        }
        if launch.model.trim().is_empty() {
            return Err("relay 配置需要选择或填写模型。".into());
        }
    }
    Ok(())
}

// ---------- 路径与日志 ----------
/// 定位 CSSwitch 仓库根（含 proxy/csswitch_proxy.py）。优先 CSSWITCH_REPO，
/// 否则从可执行文件与当前目录逐级上溯。找不到返回 None。
fn repo_root() -> Option<PathBuf> {
    let marker = Path::new("proxy/csswitch_proxy.py");
    // 显式指定优先：规范化后再判定，避免相对/软链歧义。
    if let Some(r) = std::env::var_os("CSSWITCH_REPO") {
        if let Ok(p) = std::fs::canonicalize(PathBuf::from(r)) {
            if p.join(marker).is_file() {
                return Some(p);
            }
        }
    }
    // 否则只从【可执行文件位置】上溯。刻意不看 current_dir：启动目录可被影响，
    // 若据此找到别处的 csswitch_proxy.py，会把带 key 的环境交给来路不明的脚本。
    if let Ok(exe) = std::env::current_exe() {
        let mut dir: Option<&Path> = exe.parent();
        while let Some(d) = dir {
            if d.join(marker).is_file() {
                return Some(d.to_path_buf());
            }
            dir = d.parent();
        }
    }
    None
}

/// 定位「资源根」（含 proxy/、scripts/）。打包成 .app 后，proxy/ 与 scripts/ 被
/// bundle 进 `Contents/Resources`；开发态则回退到仓库根。找不到返回 None。
/// 这样从 Finder 启动的正式 .app 也能找到代理脚本（修 P1-1）。
fn asset_root(app: &tauri::AppHandle) -> Option<PathBuf> {
    let marker = Path::new("proxy/csswitch_proxy.py");
    // 打包态：Tauri 资源目录。
    if let Ok(res) = app.path().resource_dir() {
        if res.join(marker).is_file() {
            return Some(res);
        }
    }
    // 开发态：从可执行文件位置上溯（见 repo_root 注释，刻意不看 current_dir）。
    repo_root()
}

/// 沙箱可写工作目录（独立 HOME）：`~/.csswitch/sandbox/home`。
/// 本地模式（macOS / Windows）使用；远程模式不落本地沙箱状态。
/// 打包后资源目录只读，沙箱状态（虚拟登录、克隆运行时、钥匙串）必须落在可写处；
/// macOS 交给 launch/stop 脚本（`SANDBOX_HOME` 环境变量）；Windows 直接作 CLI 的
/// HOME/USERPROFILE。纯路径构造，所有平台编译（Linux 上只是不被本地模式调用）。
fn sandbox_home() -> PathBuf {
    config::default_dir().join("sandbox").join("home")
}

fn log_path(name: &str) -> PathBuf {
    config::default_dir().join("logs").join(name)
}

/// 打开（truncate）一个子进程日志文件，父目录 0700、文件 0600（防同机其它用户读到 secret 尾巴）。
/// 跨平台：Unix 用 `O_NOFOLLOW` 防符号链接跟随；Windows 无此概念，仅做普通 open。
/// 注意：symlink 检查 `config::assert_not_symlink` 本身在所有平台可用
/// （`std::fs::symlink_metadata` + `is_symlink()` 是跨平台的）。
fn open_log(name: &str) -> std::io::Result<std::fs::File> {
    let p = log_path(name);
    if let Some(parent) = p.parent() {
        config::assert_not_symlink(parent)?;
        std::fs::create_dir_all(parent)?;
        let _ = set_file_permissions(parent, 0o700);
    }
    // 日志路径不许是符号链接：否则 truncate+写会覆盖链接目标文件（修 P2-1）。
    config::assert_not_symlink(&p)?;
    let f = open_log_file(&p)?;
    // 文件已存在时 mode 不复位，显式再夹一次。
    let _ = set_file_permissions(&p, 0o600);
    Ok(f)
}

/// 把字符串里的 secret 明文替换成 ****，用于任何要回显给前端的错误尾巴。
fn redact(s: &str, secret: &str) -> String {
    if secret.is_empty() {
        s.to_string()
    } else {
        s.replace(secret, "****")
    }
}

fn tail_file(path: &Path, max: usize) -> String {
    match std::fs::read(path) {
        Ok(b) => {
            let start = b.len().saturating_sub(max);
            String::from_utf8_lossy(&b[start..]).trim().to_string()
        }
        Err(_) => String::new(),
    }
}

/// 只取文件里 `from` 之后新增的内容（本次启动新写的日志），末尾最多 `max` 字节。
/// 用于判断「这次启动报了什么错」时不被上一次失败的旧日志误导。
fn tail_file_from(path: &Path, from: usize, max: usize) -> String {
    match std::fs::read(path) {
        Ok(b) => {
            let start = from.min(b.len());
            let mut seg = &b[start..];
            if seg.len() > max {
                seg = &seg[seg.len() - max..];
            }
            String::from_utf8_lossy(seg).trim().to_string()
        }
        Err(_) => String::new(),
    }
}

fn kill_child(slot: &mut Option<Child>) {
    kill_owned(slot.take())
}

/// 终止子进程（值语义版，供不持锁的停止路径使用）。
fn kill_owned(c: Option<Child>) {
    if let Some(mut c) = c {
        let _ = c.kill();
        let _ = c.wait();
    }
}

/// 轮询等待端口真正不再响应，超时返回 false。
///
/// 停止流程必须用它做**实证**：CLI 退出码 0 只说明命令跑完了，不代表 daemon 死了
/// （stale lockfile 时 `claude-science stop` 同样返回 0）。不实测就会向用户谎报
/// 「已停止」，而残留 daemon 继续占着端口，下次启动报「端口被占用」。
fn wait_port_free(port: u16, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if !proc::http_health(port, None, 300) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

/// 取锁并从 poison 中恢复：某线程持锁时 panic 不应把整个 app 卡死。
fn lock(m: &Mutex<AppState>) -> std::sync::MutexGuard<'_, AppState> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// 用系统浏览器打开 URL。
/// 跨平台：macOS 用 `open` 命令，Windows 用 `cmd /c start`（或 Tauri opener 插件）。
/// 校验退出码：非零视为失败（P2c）。
fn open_in_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let st = Command::new("open")
            .arg(url)
            .status()
            .map_err(|e| format!("打开浏览器失败：{e}"))?;
        if !st.success() {
            return Err(format!("open 非零退出（{:?}）", st.code()));
        }
    }
    #[cfg(target_os = "windows")]
    {
        let st = hidden(&mut Command::new("cmd"))
            .args(["/c", "start", url])
            .status()
            .map_err(|e| format!("打开浏览器失败：{e}"))?;
        if !st.success() {
            return Err(format!("start 非零退出（{:?}）", st.code()));
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        // Linux 等其他平台：尝试 xdg-open
        let st = Command::new("xdg-open")
            .arg(url)
            .status()
            .map_err(|e| format!("打开浏览器失败：{e}"))?;
        if !st.success() {
            return Err(format!("xdg-open 非零退出（{:?}）", st.code()));
        }
    }
    Ok(())
}

// ---------- 代理生命周期核心 ----------
/// 转义 ERE（extended regex）元字符，让路径按字面参与进程匹配（避免路径里的
/// `.`/`(`/`[` 等被当作正则、误配或失配）。
/// Unix：`pkill -f`（ensure_proxy）；Windows：PowerShell `-match`（.NET 正则，转义兼容）。
fn ere_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if "\\.^$*+?()[]{}|".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// 本次 ensure_proxy 对代理做了什么（供一键据实提示）。
#[derive(Clone, Copy, PartialEq)]
enum ProxyAction {
    Reused,    // 端口+provider+key 指纹一致且健康，原样复用
    Restarted, // 首次起 / 换 key / 换 provider / 不健康，重起了代理
}

/// 定位可起翻译代理的 Python 解释器。
/// 顺序：① 用户在「高级设置」里手工指定的路径（最优先）→ ② 平台自动探测。
/// Windows：`python3` 常是 WindowsApps 商店 stub（假命中：执行弹商店且无输出），且
/// `fs::metadata` 不做 PATHEXT 解析（必须带 .exe 后缀才找得到），故候选带 .exe 变体并对每个
/// 命中做 `--version` 验证，再退回 `python`。Unix 走 [`proc::find_exe`]（PATH+常见目录+登录 shell）
/// 并额外试 `python` 与 conda 常见目录（conda 环境未 activate 时 PATH 里没有 python3）。
fn find_python() -> Option<PathBuf> {
    // ① 用户指定路径：存在且 `--version` 验证通过就用它（不看是否在 PATH）。
    if let Some(p) = configured_python() {
        if python_works(&p) {
            return Some(p);
        }
    }
    #[cfg(target_os = "windows")]
    {
        for name in ["python3.exe", "python.exe", "python3", "python"] {
            // 关键：遍历 PATH 里的【全部】同名候选，而不是只取第一个。
            // 靠前的 WindowsApps 商店别名（python.exe 静默退出、无输出）会把后面
            // 真正可用的解释器挡死——只查第一个会让本机明明装着 Python 却报「缺少解释器」。
            for p in proc::which_all(name) {
                if python_works(&p) {
                    return Some(p);
                }
            }
        }
        return None;
    }
    #[cfg(not(target_os = "windows"))]
    {
        for name in ["python3", "python"] {
            if let Some(p) = proc::find_exe(name) {
                if python_works(&p) {
                    return Some(p);
                }
            }
        }
        // conda：环境常未 activate，PATH 里没有 python3，但解释器在 envs/<env>/bin 下。
        for p in conda_pythons() {
            if python_works(&p) {
                return Some(p);
            }
        }
        None
    }
}

/// 读配置里的自定义 Python 路径（`~/.csswitch/config.json` 的 `python_path`）。
fn configured_python() -> Option<PathBuf> {
    let dir = config::default_dir();
    let cfg = config::load_from(&dir).ok()?;
    let raw = cfg.python_path?.trim().to_string();
    if raw.is_empty() {
        return None;
    }
    let p = PathBuf::from(&raw);
    if p.is_absolute() && p.exists() {
        return Some(p);
    }
    // 也允许填命令名（如 `python3.12`），走 PATH 解析。
    proc::find_exe(&raw).or(Some(p))
}

/// Unix 常见 conda 布局下的 python 解释器（只读枚举，不执行任何东西）。
#[cfg(not(target_os = "windows"))]
fn conda_pythons() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Some(home) = dirs::home_dir() else { return out };
    let mut roots = vec![home.join("anaconda3"), home.join("miniconda3"), home.join("miniforge3")];
    if let Some(conda_envs) = std::env::var_os("CONDA_ENVS_PATH") {
        for d in std::env::split_paths(&conda_envs) {
            roots.push(d);
        }
    }
    for root in roots {
        // <root>/bin/python3 与 <root>/envs/*/bin/python3
        for cand in [root.join("bin").join("python3")] {
            if cand.is_file() {
                out.push(cand);
            }
        }
        let envs = root.join("envs");
        if let Ok(rd) = std::fs::read_dir(&envs) {
            for e in rd.flatten() {
                let cand = e.path().join("bin").join("python3");
                if cand.is_file() {
                    out.push(cand);
                }
            }
        }
    }
    out
}

/// 验证 Python 可执行（Windows 上 WindowsApps stub 会返回假命中）：`--version` 输出
/// （stdout；stub 无输出则看 stderr）含 "Python" 才算可用（真实解释器形如 "Python 3.12.4"）。
fn python_works(p: &Path) -> bool {
    let out = match hidden(&mut Command::new(p))
        .arg("--version")
        .stdin(Stdio::null())
        .output()
    {
        Ok(o) => o,
        Err(_) => return false,
    };
    let s = String::from_utf8_lossy(&out.stdout);
    let s = if s.trim().is_empty() {
        String::from_utf8_lossy(&out.stderr)
    } else {
        s
    };
    s.contains("Python")
}

/// 确保代理在跑且健康；返回 (端口, secret, 本次动作)。幂等：已健康则复用。
fn ensure_proxy(
    app: &tauri::AppHandle,
    state: &State<'_, Mutex<AppState>>,
) -> Result<(u16, String, ProxyAction), String> {
    let dir = config::default_dir();
    let cfg = config::load_from(&dir).map_err(|e| e.to_string())?;
    let profile = cfg.active_profile().cloned()
        .ok_or("没有生效的配置 Profile。请先「＋ 新建」或「设为当前」。")?;
    assert_profile_runnable(&profile)?;
    let launch = proxy_launch_for(&profile);
    let key_fp = key_fingerprint(&launch.key);
    let port = cfg.proxy_port;
    let root = asset_root(app)
        .ok_or("找不到代理脚本 proxy/csswitch_proxy.py（打包资源或仓库根均未命中）。开发态可设 CSSWITCH_REPO。")?;

    // path-secret：**持久化复用**。已在跑的沙箱把该 secret 嵌进了 ANTHROPIC_BASE_URL，
    // 若每次起代理都换 secret，代理一重启（换 key/换 provider/重开 app）沙箱就会拿旧 secret
    // 打到新代理 → 全部 403（修 P1：代理重启后沙箱失联）。故从 config 读稳定 secret，
    // 首次为空才生成一次并写回，之后所有代理进程都复用它。
    let secret = if !cfg.secret.is_empty() {
        cfg.secret.clone()
    } else {
        let s = proc::gen_secret().map_err(|e| format!("无法生成安全 secret：{e}"))?;
        let s2 = s.clone();
        config::update(&dir, move |c| c.secret = s2).map_err(|e| e.to_string())?;
        s
    };

    // 整个「检查 → 清残留 → 起进程 → 记账」在同一把锁内完成，避免并发双击时
    // 两路都判定「没健康代理」各起一个、后者覆盖前者的 Child 句柄导致前者被孤儿泄漏。
    {
        let mut st = lock(state);
        // 幂等：已在跑且健康、且【端口 + provider + key 指纹】都一致才复用。
        // 只比端口会在「换 provider / 换 key」后误用带旧配置的代理（修 P1-2）。
        if st.proxy.is_some()
            && st.proxy_port == port
            && st.provider == launch.adapter
            && st.key_fp == key_fp
            && proc::http_health(port, Some(&st.secret), 500)
        {
            return Ok((port, st.secret.clone(), ProxyAction::Reused));
        }
        // 清残留（换端口/换 provider/换 key/不健康）。
        kill_child(&mut st.proxy);
        let script = root.join("proxy/csswitch_proxy.py");
        // 再清掉上次会话遗留、绑在同端口上的孤儿代理：崩溃或强退不会触发本进程的 kill，
        // 孤儿仍占着端口 → 新代理绑不上（Errno 48）→ 探活超时。
        // 收紧（P2 GPT 复审）：匹配【本安装的绝对脚本路径】+ 端口，而非仅「脚本名+端口」，
        // 避免误杀另一个 checkout / 用户手启的同名代理。路径里的正则元字符转义按字面匹配。
        // 跨平台：Unix 用 `pkill -f`；Windows 无 pkill，用 PowerShell Win32_Process 按命令行
        // 匹配（.NET 正则与 ere_escape 输出兼容），匹配串经环境变量传入不进 PowerShell argv。
        #[cfg(unix)]
        {
            let pat = format!("{}.*--port {port}", ere_escape(&script.to_string_lossy()));
            let _ = Command::new("pkill").arg("-f").arg(&pat).status();
        }
        #[cfg(target_os = "windows")]
        {
            let pat = format!("{}.*--port {port}", ere_escape(&script.to_string_lossy()));
            let _ = hidden(&mut Command::new("powershell"))
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "$p = $env:CSSWITCH_KILL_PAT; Get-CimInstance Win32_Process -Filter \"Name='python.exe' OR Name='python3.exe'\" | Where-Object { $_.CommandLine -and $_.CommandLine -match $p } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }",
                ])
                .env("CSSWITCH_KILL_PAT", &pat)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }

        // Python 解释器：懒定位（复用路径不付 PATH 扫描 + --version 验证的成本）。
        let py = find_python().ok_or_else(|| {
            let hint = match configured_python() {
                Some(p) => format!("已配置的路径 {} 不可用（不存在或不是真正的解释器）。", p.display()),
                None => "未找到可用的 python3 / python。".to_string(),
            };
            format!(
                "缺少可用的 Python 解释器（起翻译代理需要）。{hint}\n\
                 请安装 Python 3 正式版（python.org；Windows 上不要用 Microsoft Store 版）并确保其在 PATH 中；\
                 也可在「高级设置」里直接填写 python.exe 的完整路径。"
            )
        })?;

        let mut logf = open_log("proxy.log").map_err(|e| format!("建日志失败：{e}"))?;
        let logf2 = logf.try_clone().map_err(|e| e.to_string())?;
        let mut cmd = Command::new(&py);
        hidden(&mut cmd);
        cmd.arg(&script)
            .arg("--provider")
            .arg(&launch.adapter)
            .arg("--port")
            .arg(port.to_string())
            .arg("--auth-token")
            .arg(&secret)
            // key 经环境变量注入，绝不作为命令行参数（避免 ps 泄露）。
            .env(launch.key_env, &launch.key);
        if !is_native_adapter(&launch.adapter) {
            cmd.env("CSSWITCH_RELAY_BASE_URL", &launch.base_url);
            if !launch.model.is_empty() {
                cmd.env("CSSWITCH_RELAY_MODEL", &launch.model);
            }
            if !launch.thinking_policy.is_empty() {
                cmd.env("CSSWITCH_RELAY_THINKING", launch.thinking_policy);
            }
        }
        let child = cmd
            .stdout(Stdio::from(logf))
            .stderr(Stdio::from(logf2))
            .spawn()
            .map_err(|e| format!("启动代理失败：{e}"))?;
        st.proxy = Some(child);
        st.proxy_port = port;
        st.secret = secret.clone();
        st.provider = launch.adapter.clone();
        st.key_fp = key_fp;
    }

    // 探活最多 ~4s（锁外，不阻塞 status 等命令）。
    let mut ok = false;
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(100));
        if proc::http_health(port, Some(&secret), 400) {
            ok = true;
            break;
        }
    }
    if !ok {
        let mut st = lock(state);
        // 只在仍是本次起的代理时才清（secret 匹配），避免误杀并发重启起来的新代理。
        if st.secret == secret {
            kill_child(&mut st.proxy);
        }
        let tail = redact(&tail_file(&log_path("proxy.log"), 500), &secret);
        return Err(format!(
            "代理起后探活超时（端口 {port} 可能被占用，或 key 无效）。\n{tail}"
        ));
    }
    Ok((port, secret, ProxyAction::Restarted))
}

/// 停沙箱。返回 Err 表示停止动作非零退出（Science 可能没停干净），
/// 调用方据此如实报告，不再无条件报「已停止」（修 P1 停止虚假成功）。
/// macOS：调 stop 脚本；Windows：调 Science CLI `stop --data-dir`（按 data-dir 停，绝不碰
/// 真实实例）；其他平台本地沙箱不存在，直接清 state 返回 Ok。
fn stop_sandbox_inner(app: &tauri::AppHandle, st: &mut AppState) -> Result<(), String> {
    let sandbox = st.sandbox.take();
    let port = st.sandbox_port;
    st.sandbox_url = None;
    stop_sandbox_detached(app, sandbox, port)
}

/// 停止沙箱的实际工作：接收 child 句柄与端口，**不接触 AppState**。
///
/// 拆出来是为了让调用方能在**不持全局 Mutex** 的前提下做这些阻塞的子进程调用——
/// Tauri 同步 command 跑在主线程，持锁阻塞会让每 2.5s 轮询一次的 `status` 全部排队，
/// 表现为整个窗口「未响应」。
fn stop_sandbox_detached(
    app: &tauri::AppHandle,
    sandbox: Option<Child>,
    port: u16,
) -> Result<(), String> {
    // 沙箱由脚本以 --detached 起 Science，本进程持有的是脚本 child（已退出）。
    // 真正停 Science 要调 stop 脚本（按 data-dir，绝不碰真实 8765）。
    // 修 P1（GPT 复审）：定位不到资源根 / 停止脚本时，绝不静退返回成功——detached 沙箱
    // 可能仍在跑，谎报「已停止」会让「切官方模式」误以为第三方链路已拆。此时如实报错。
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = (app, port);
        kill_owned(sandbox);
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        let _ = app;
        let mut err = None;
        // Windows：Science CLI 自带 `stop --data-dir`（lockfile 定位，只停该 data-dir 的
        // daemon，绝不影响真实实例）。先优雅 stop；CLI 定位不到时如实报错。
        match science_bin_windows() {
            Some(bin) => {
                let home = sandbox_home();
                let mut cmd = Command::new(&bin);
                hidden(&mut cmd);
                cmd.arg("stop")
                    .arg("--data-dir")
                    .arg(home.join(".claude-science"));
                if let Ok(c) = write_science_config(&home.join(".claude-science")) {
                    cmd.arg("--config").arg(c);
                }
                science_cli_env(&mut cmd, &home);
                // 有界执行：残留 daemon 占着 data-dir 锁文件时 stop 会挂住，
                // 裸 .status() 会无限期阻塞调用方。
                if proc::run_bounded(cmd, Duration::from_secs(8)).is_none() {
                    err = Some("停止沙箱命令超时无响应。".to_string());
                }
            }
            None => {
                err = Some(
                    "找不到 Claude Science CLI，无法确认沙箱已停止（沙箱可能仍在运行）。"
                        .to_string(),
                );
            }
        }
        // 兜底：若 --detached 未生效、本进程持有的就是 daemon 本体，kill 之（stale lockfile
        // 由下次 `stop` 的「no daemon running」语义兜住）。
        kill_owned(sandbox);
        // 实证：命令退出码为 0 **不等于**端口已释放（stale lockfile 时 stop 同样返回 0）。
        // 不实测就会谎报「已停止」，而 daemon 继续占端口，下次启动报「端口被占用」。
        if port != 0 && !wait_port_free(port, Duration::from_secs(6)) {
            let msg = format!("沙箱端口 {port} 仍在响应，daemon 可能未停干净。");
            err = Some(match err {
                Some(e) => format!("{e} {msg}"),
                None => msg,
            });
        }
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
    #[cfg(target_os = "macos")]
    {
    let mut err = None;
    match asset_root(app) {
        Some(root) => {
            let stop = root.join("scripts/stop-science-sandbox.sh");
            if stop.is_file() {
                match hidden(&mut Command::new("bash")) // stop 脚本 #!/usr/bin/env bash（跨 macOS/Git Bash 可执行）
                    .arg(&stop)
                    // 与 launch 时一致的可写沙箱 HOME，stop 才能按同一 data-dir 停对进程。
                    .env("SANDBOX_HOME", sandbox_home())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                {
                    Ok(s) if s.success() => {}
                    Ok(s) => err = Some(format!("停止沙箱脚本非零退出（{:?}）。", s.code())),
                    Err(e) => err = Some(format!("调用停止沙箱脚本失败：{e}")),
                }
            } else {
                err = Some(format!(
                    "找不到停止脚本 {}，无法确认沙箱已停止（沙箱可能仍在运行）。",
                    stop.display()
                ));
            }
        }
        None => {
            err = Some(
                "定位不到资源根，取不到停止脚本，无法确认沙箱已停止（沙箱可能仍在运行）。"
                    .to_string(),
            );
        }
    }
    kill_owned(sandbox);
    if port != 0 && !wait_port_free(port, Duration::from_secs(6)) {
        let msg = format!("沙箱端口 {port} 仍在响应，daemon 可能未停干净。");
        err = Some(match err {
            Some(e) => format!("{e} {msg}"),
            None => msg,
        });
    }
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
    } // #[cfg(target_os = "macos")]
}

// ---------- Tauri commands ----------
fn build_list_templates() -> Vec<serde_json::Value> {
    templates::all()
        .iter()
        .map(|t| {
            json!({
                "id": t.id,
                "name": t.name,
                "category": t.category,
                "api_format": t.api_format,
                "adapter": t.adapter,
                "base_url": t.base_url,
                "base_url_editable": t.base_url_editable,
                "requires_model_override": t.requires_model_override,
                "builtin_models": t.builtin_models,
                "website_url": t.website_url,
                "icon": t.icon,
                "icon_color": t.icon_color,
                "thinking_policy": t.thinking_policy,
            })
        })
        .collect()
}

fn build_get_config(dir: &Path) -> Result<serde_json::Value, String> {
    let cfg = config::load_from(dir).map_err(|e| e.to_string())?;
    let notice = cfg.pending_notice.clone();
    if notice.is_some() {
        config::update(dir, |c| c.pending_notice = None).map_err(|e| e.to_string())?;
    }
    Ok(json!({
        "schema_version": cfg.schema_version,
        "active_id": cfg.active_id,
        "proxy_port": cfg.proxy_port,
        "sandbox_port": cfg.sandbox_port,
        "mode": cfg.mode,
        "python_path": cfg.python_path.clone().unwrap_or_default(),
        "pending_notice": notice,
        "templates": build_list_templates(),
        "profiles": cfg.profiles.iter().map(|p| json!({
            "id": p.id,
            "name": p.name,
            "template_id": p.template_id,
            "category": p.category,
            "api_format": p.api_format,
            "base_url": p.base_url,
            "model": p.model,
            "key": config::mask(&p.api_key),
            "website_url": p.website_url,
            "icon": p.icon,
            "icon_color": p.icon_color,
            "sort_index": p.sort_index,
            "notes": p.notes,
        })).collect::<Vec<_>>(),
    }))
}

#[tauri::command]
fn get_config() -> Result<serde_json::Value, String> {
    build_get_config(&config::default_dir())
}

#[tauri::command]
fn list_templates() -> Vec<serde_json::Value> {
    build_list_templates()
}

/// 切换运行模式（"proxy" 第三方 / "official" 官方）。
///
/// 切到「官方」是**真正的切换**，不只是改配置：先把第三方链路拆掉（停沙箱 Science + 杀代理、
/// 清 secret）。否则代理/沙箱会留在后台空跑；且 macOS 单实例语义下，后面 `open` 可能只是聚焦
/// 还活着的沙箱实例（带着改过的 ANTHROPIC_* 环境）而非官方实例，把用户误导回第三方链路。
/// 切回「第三方」不自动起任何东西（仍需用户填 key 后点「一键开始」）。全程绝不碰真实 8765。
#[tauri::command]
fn set_mode(
    app: tauri::AppHandle,
    state: State<'_, Mutex<AppState>>,
    mode: String,
) -> Result<(), String> {
    if mode != "proxy" && mode != "official" {
        return Err(format!("未知模式：{mode}（只支持 proxy / official）。"));
    }
    let dir = config::default_dir();

    // 事务化（修 P2 GPT 复审）：切官方要「先拆第三方链路，成功了再落盘 official」。
    // 旧序（先落盘再拆）若拆沙箱失败，会留下「磁盘=official、UI/进程=第三方」的状态分裂
    // （前端收到 Err 保持第三方 UI，磁盘却已是 official，下次启动就错进官方模式）。
    // 现序保证：拆失败 → 不落盘、保持 proxy 模式、如实报错，磁盘/UI/进程一致。
    if mode == "official" {
        {
            let mut st = lock(&state);
            // 先停沙箱：失败就在动代理/落盘之前中止，状态不分裂。
            stop_sandbox_inner(&app, &mut st).map_err(|e| {
                format!("停止沙箱失败，未切换到官方模式：{e}（真实实例 8765 未受影响）")
            })?;
            kill_child(&mut st.proxy);
            st.secret.clear();
        }
    }
    // 拆链已成功（或切回 proxy 无需拆）→ 落盘。
    config::update(&dir, {
        let mode = mode.clone();
        move |c| c.mode = mode
    })
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// 官方模式：干净地打开用户【真实】的 Claude Science（用户自己的官方登录与订阅）。
/// macOS：`open` Claude Science.app；Windows：经 Start Menu 快捷方式（`cmd /c start`）正常
/// 启动；其他平台返回明确提示，引导用户使用远程模式管理服务器上的 Science。
///
/// 铁律：绝不碰/复制真实凭证；正常启动而非注入环境变量，
/// 并显式抹掉任何 `ANTHROPIC_*`，确保**不用改过的环境变量启动真实实例**（真实实例走它自己的
/// 官方端点，不经本代理）。CSSwitch 只把用户交回官方客户端，不托管其登录。
#[tauri::command]
fn open_official() -> Result<(), String> {
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        return Err("本地模式「打开官方 Claude Science」仅支持 macOS / Windows。请使用远程模式连接到运行 Science 的 Linux 服务器。".into());
    }
    #[cfg(target_os = "windows")]
    {
        // Start Menu 快捷方式（per-user / all-users 各查一次）。不直接 spawn
        // claude-science.exe：无子命令时行为未知（可能是交互式 REPL，会挂住调用方）。
        let mut cands: Vec<PathBuf> = Vec::new();
        if let Some(ad) = std::env::var_os("APPDATA") {
            cands.push(
                PathBuf::from(ad)
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs")
                    .join("Claude Science.lnk"),
            );
        }
        if let Some(pd) = std::env::var_os("ProgramData") {
            cands.push(
                PathBuf::from(pd)
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs")
                    .join("Claude Science.lnk"),
            );
        }
        let lnk = cands.into_iter().find(|p| p.is_file()).ok_or(
            "找不到 Claude Science 的开始菜单快捷方式（%APPDATA% / %ProgramData% 下的 Start Menu\\Programs\\Claude Science.lnk）。请确认已安装官方 Claude Science Windows 版。",
        )?;
        // `start` 后跟空标题，路径含空格可整体带引号。防御性：显式抹掉任何 ANTHROPIC_*，
        // 杜绝把改过的环境变量带进真实实例（铁律 3）。
        let st = hidden(&mut Command::new("cmd"))
            .args(["/c", "start", ""])
            .arg(&lnk)
            .env_remove("ANTHROPIC_BASE_URL")
            .env_remove("ANTHROPIC_API_KEY")
            .env_remove("ANTHROPIC_AUTH_TOKEN")
            .status()
            .map_err(|e| format!("打开官方 Claude Science 失败：{e}"))?;
        if st.success() {
            return Ok(());
        }
        Err(format!(
            "start 非零退出（{:?}）：未能打开官方 Claude Science。",
            st.code()
        ))
    }
    #[cfg(target_os = "macos")]
    {
        let app_path = "/Applications/Claude Science.app";
        let mut cmd = Command::new("open");
        if Path::new(app_path).is_dir() {
            cmd.arg(app_path);
        } else {
            cmd.arg("-a").arg("Claude Science");
        }
        // 防御性：即便 `open` 通常不向被启动 app 传本进程环境，也显式抹掉，杜绝把改过的
        // ANTHROPIC_* 带进真实实例（铁律 3）。
        cmd.env_remove("ANTHROPIC_BASE_URL")
            .env_remove("ANTHROPIC_API_KEY")
            .env_remove("ANTHROPIC_AUTH_TOKEN");
        match cmd.status() {
            Ok(s) if s.success() => Ok(()),
            Ok(_) => Err("未能打开 Claude Science。请确认已安装官方 Claude Science。".into()),
            Err(e) => Err(format!("打开官方 Claude Science 失败：{e}")),
        }
    }
}

#[derive(Deserialize)]
struct UiSettings {
    proxy_port: u16,
    sandbox_port: u16,
    /// 用户手工指定的 Python 解释器路径（空串=自动探测）。
    #[serde(default)]
    python_path: Option<String>,
}

#[tauri::command]
fn set_config(cfg: UiSettings) -> Result<(), String> {
    if cfg.proxy_port == 8765 || cfg.sandbox_port == 8765 {
        return Err("端口 8765 是真实 Science 实例保留端口，不能用。".into());
    }
    // Windows 版真实 Science 默认端口是 8000（serve 不带 --port 时）：沙箱/代理都不能占它，
    // 否则用户真实实例起不来（铁律 3）。
    #[cfg(target_os = "windows")]
    if cfg.proxy_port == 8000 || cfg.sandbox_port == 8000 {
        return Err("端口 8000 是 Windows 版真实 Science 默认端口，不能用。".into());
    }
    if cfg.proxy_port == 0 || cfg.sandbox_port == 0 {
        return Err("端口不能为 0。".into());
    }
    if cfg.proxy_port == cfg.sandbox_port {
        return Err("代理端口与沙箱端口不能相同。".into());
    }
    let dir = config::default_dir();
    let py_path = cfg
        .python_path
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    config::update(&dir, move |c| {
        c.proxy_port = cfg.proxy_port;
        c.sandbox_port = cfg.sandbox_port;
        c.python_path = py_path.clone();
    })
    .map(|_| ())
    .map_err(|e| e.to_string())
}

#[tauri::command]
fn set_settings(cfg: UiSettings) -> Result<(), String> {
    set_config(cfg)
}

#[tauri::command]
fn save_provider_key(provider: String, key: String) -> Result<String, String> {
    let dir = config::default_dir();
    let key2 = key.clone();
    config::update(&dir, move |c| {
        // 兼容旧接口：按 adapter/template_id 找到 active profile 并保存 key
        if let Some(p) = c.active_profile_mut() {
            if templates::adapter_for(&p.template_id) == provider || p.template_id == provider {
                p.api_key = key2;
            }
        }
    })
    .map_err(|e| e.to_string())?;
    Ok(config::mask(&key))
}

fn template_default_model(tpl: &templates::Template) -> String {
    tpl.builtin_models.first().map(|s| (*s).to_string()).unwrap_or_default()
}

fn validate_base_url_for_profile(profile: &config::Profile) -> Result<(), String> {
    let launch = proxy_launch_for(profile);
    if !is_native_adapter(&launch.adapter)
        && (launch.base_url.trim().is_empty()
            || !(launch.base_url.starts_with("http://") || launch.base_url.starts_with("https://")))
    {
        return Err("base_url 必须以 http:// 或 https:// 开头。".into());
    }
    Ok(())
}

fn create_profile_inner(
    dir: &Path,
    template_id: &str,
    name: &str,
    key: Option<&str>,
    base_url: Option<&str>,
    model: Option<&str>,
) -> Result<String, String> {
    let tpl = templates::by_id(template_id).ok_or_else(|| format!("未知模板：{template_id}"))?;
    let id = config::new_id();
    let mut model_value = model.unwrap_or("").trim().to_string();
    if tpl.requires_model_override && model_value.is_empty() {
        model_value = template_default_model(tpl);
    }
    if tpl.requires_model_override && model_value.is_empty() {
        return Err("该来源需要选择或填写模型。".into());
    }
    let base = base_url
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(tpl.base_url)
        .to_string();
    let now = config::now_ms();
    let mut candidate = config::Profile {
        id: id.clone(),
        name: if name.trim().is_empty() { tpl.name.to_string() } else { name.trim().to_string() },
        template_id: tpl.id.to_string(),
        category: tpl.category.to_string(),
        api_format: tpl.api_format.to_string(),
        base_url: base,
        api_key: key.unwrap_or("").trim().to_string(),
        model: model_value,
        website_url: Some(tpl.website_url.to_string()),
        icon: Some(tpl.icon.to_string()),
        icon_color: Some(tpl.icon_color.to_string()),
        sort_index: None,
        created_at: Some(now),
        notes: None,
    };
    validate_base_url_for_profile(&candidate)?;
    config::update(dir, |c| {
        candidate.sort_index = Some(c.profiles.len() as i64);
        c.profiles.push(candidate);
    })
    .map_err(|e| e.to_string())?;
    Ok(id)
}

fn update_profile_metadata_inner(
    dir: &Path,
    id: &str,
    name: &str,
    notes: Option<&str>,
) -> Result<(), String> {
    if config::load_from(dir).map_err(|e| e.to_string())?.profile_by_id(id).is_none() {
        return Err(format!("找不到 profile：{id}"));
    }
    config::update(dir, |c| {
        if let Some(p) = c.profile_by_id_mut(id) {
            p.name = if name.trim().is_empty() { "未命名".into() } else { name.trim().into() };
            p.notes = notes.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        }
    })
    .map(|_| ())
    .map_err(|e| e.to_string())
}

fn update_profile_connection_inner(
    dir: &Path,
    id: &str,
    base_url: Option<&str>,
    api_format: Option<&str>,
    model: Option<&str>,
    key: Option<&str>,
) -> Result<(), String> {
    let cfg = config::load_from(dir).map_err(|e| e.to_string())?;
    let mut candidate = cfg
        .profile_by_id(id)
        .cloned()
        .ok_or_else(|| format!("找不到 profile：{id}"))?;
    if let Some(v) = base_url {
        candidate.base_url = v.trim().to_string();
    }
    if let Some(v) = api_format {
        candidate.api_format = v.trim().to_string();
    }
    if let Some(v) = model {
        candidate.model = v.trim().to_string();
    }
    if let Some(v) = key {
        if !v.trim().is_empty() {
            candidate.api_key = v.trim().to_string();
        }
    }
    validate_base_url_for_profile(&candidate)?;
    if templates::by_id(&candidate.template_id)
        .map(|t| t.requires_model_override)
        .unwrap_or(true)
        && candidate.model.trim().is_empty()
    {
        return Err("该来源需要选择或填写模型。".into());
    }
    config::update(dir, |c| {
        if let Some(p) = c.profile_by_id_mut(id) {
            *p = candidate;
        }
    })
    .map(|_| ())
    .map_err(|e| e.to_string())
}

fn clear_profile_key_inner(dir: &Path, id: &str) -> Result<(), String> {
    if config::load_from(dir).map_err(|e| e.to_string())?.profile_by_id(id).is_none() {
        return Err(format!("找不到 profile：{id}"));
    }
    config::update(dir, |c| {
        if let Some(p) = c.profile_by_id_mut(id) {
            p.api_key.clear();
        }
    })
    .map_err(|e| e.to_string())?;
    config::drop_rolling_backup(dir);
    Ok(())
}

fn delete_profile_inner(dir: &Path, id: &str) -> Result<(), String> {
    if config::load_from(dir).map_err(|e| e.to_string())?.profile_by_id(id).is_none() {
        return Err(format!("找不到 profile：{id}"));
    }
    config::update(dir, |c| {
        c.profiles.retain(|p| p.id != id);
        if c.active_id == id {
            c.active_id.clear();
        }
    })
    .map_err(|e| e.to_string())?;
    config::drop_rolling_backup(dir);
    Ok(())
}

fn stop_proxy_state(state: &State<'_, Mutex<AppState>>) {
    let mut st = lock(state);
    kill_child(&mut st.proxy);
    st.provider.clear();
    st.secret.clear();
    st.key_fp = 0;
}

#[tauri::command]
fn create_profile(
    template_id: String,
    name: String,
    key: Option<String>,
    base_url: Option<String>,
    model: Option<String>,
) -> Result<String, String> {
    create_profile_inner(
        &config::default_dir(),
        &template_id,
        &name,
        key.as_deref(),
        base_url.as_deref(),
        model.as_deref(),
    )
}

#[tauri::command]
fn update_profile_metadata(id: String, name: String, notes: Option<String>) -> Result<(), String> {
    update_profile_metadata_inner(&config::default_dir(), &id, &name, notes.as_deref())
}

#[tauri::command]
fn update_profile_connection(
    state: State<'_, Mutex<AppState>>,
    id: String,
    base_url: Option<String>,
    api_format: Option<String>,
    model: Option<String>,
    key: Option<String>,
) -> Result<(), String> {
    let dir = config::default_dir();
    let was_active = config::load_from(&dir)
        .map(|c| c.active_id == id)
        .unwrap_or(false);
    update_profile_connection_inner(
        &dir,
        &id,
        base_url.as_deref(),
        api_format.as_deref(),
        model.as_deref(),
        key.as_deref(),
    )?;
    if was_active {
        stop_proxy_state(&state);
    }
    Ok(())
}

#[tauri::command]
fn clear_profile_key(state: State<'_, Mutex<AppState>>, id: String) -> Result<(), String> {
    let dir = config::default_dir();
    let was_active = config::load_from(&dir)
        .map(|c| c.active_id == id)
        .unwrap_or(false);
    clear_profile_key_inner(&dir, &id)?;
    if was_active {
        stop_proxy_state(&state);
    }
    Ok(())
}

#[tauri::command]
fn delete_profile(state: State<'_, Mutex<AppState>>, id: String) -> Result<(), String> {
    let dir = config::default_dir();
    let was_active = config::load_from(&dir)
        .map(|c| c.active_id == id)
        .unwrap_or(false);
    delete_profile_inner(&dir, &id)?;
    if was_active {
        stop_proxy_state(&state);
    }
    Ok(())
}

#[tauri::command]
fn set_active_profile(
    state: State<'_, Mutex<AppState>>,
    id: String,
    skip_verify: bool,
) -> Result<serde_json::Value, String> {
    let dir = config::default_dir();
    let cfg = config::load_from(&dir).map_err(|e| e.to_string())?;
    let profile = cfg
        .profile_by_id(&id)
        .cloned()
        .ok_or_else(|| format!("找不到 profile：{id}"))?;
    if !skip_verify {
        if let Err(e) = assert_profile_runnable(&profile) {
            return Ok(json!({
                "committed": false,
                "active_id": cfg.active_id,
                "hint": e,
            }));
        }
    }
    config::update(&dir, |c| c.active_id = id.clone()).map_err(|e| e.to_string())?;
    stop_proxy_state(&state);
    Ok(json!({
        "committed": true,
        "active_id": id,
        "hint": if skip_verify { "已跳过校验并设为当前。" } else { "已设为当前。" },
    }))
}

#[derive(Deserialize)]
struct FetchModelsReq {
    template_id: String,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    key: String,
    #[serde(default)]
    profile_id: Option<String>,
}

#[tauri::command]
fn fetch_models(req: FetchModelsReq) -> Result<serde_json::Value, String> {
    let tpl = templates::by_id(req.template_id.trim())
        .ok_or_else(|| format!("未知模板：{}", req.template_id))?;
    // TODO: 未来实现根据 base_url/key/profile_id 向上游 API 实时拉取模型列表。
    // 当前仅返回模板内置的模型名。
    let _ = (&req.base_url, &req.key, &req.profile_id);
    let models = tpl
        .builtin_models
        .iter()
        .map(|id| json!({ "id": id, "supports_tools": serde_json::Value::Null }))
        .collect::<Vec<_>>();
    Ok(json!({
        "models": models,
        "source": "builtin",
        "error_kind": serde_json::Value::Null,
        "upstream_status": serde_json::Value::Null,
    }))
}

#[tauri::command]
fn start_proxy(
    app: tauri::AppHandle,
    state: State<'_, Mutex<AppState>>,
) -> Result<serde_json::Value, String> {
    let (port, _secret, _action) = ensure_proxy(&app, &state)?;
    Ok(json!({ "port": port }))
}

/// 「存 key 即验证」：确保代理在跑，再经代理向上游发一个**最小**请求
/// （`max_tokens:1`，一句 "ping"），据响应状态码判断 key 是否真的可用。
/// 返回 `{ok, hint}`：ok=true 表示上游接受（key 有效）；ok=false 表示上游拒绝或异常，
/// hint 给人话。彻底避免「只看绿灯（代理起来了）≠ key 真能用」。
#[tauri::command]
fn verify_key(
    app: tauri::AppHandle,
    state: State<'_, Mutex<AppState>>,
) -> Result<serde_json::Value, String> {
    let (port, secret, _action) = ensure_proxy(&app, &state)?;
    // 走稳定模型 id（代理内部映射到当前 provider 的真实模型），非流式、只要 1 个 token。
    let body = br#"{"model":"claude-opus-4-8","max_tokens":1,"messages":[{"role":"user","content":"ping"}]}"#;
    match proc::http_post_status(port, Some(&secret), "/v1/messages", body, 15000) {
        Some(200) => Ok(json!({ "ok": true, "hint": "key 有效，上游已接受。" })),
        Some(code @ (401 | 403)) => Ok(
            json!({ "ok": false, "hint": format!("上游拒绝（{code}），key 可能无效或无权限。") }),
        ),
        Some(code) => Ok(json!({
            "ok": false,
            "hint": format!("上游返回 {code}，可能是 key 无效、额度不足或上游异常。")
        })),
        None => Err("验证请求无响应（多为网络或上游不通）。".to_string()),
    }
}

#[tauri::command]
async fn stop_all(app: tauri::AppHandle, state: State<'_, Mutex<AppState>>) -> Result<(), String> {
    // 持锁期间只搬走句柄/字段；所有阻塞的子进程调用都在锁外做完。
    // 否则本命令会占着全局 Mutex 等子进程退出，而前端每 2.5s 轮询一次 status()
    // 也要这把锁 → 全部排队 → 窗口「未响应」。
    let (sandbox, proxy, port) = {
        let mut st = lock(&state);
        st.sandbox_url = None;
        st.secret.clear();
        (st.sandbox.take(), st.proxy.take(), st.sandbox_port)
    };
    // 先停沙箱并记录结果；代理无论如何都杀。沙箱没停干净则如实返错，不虚报成功。
    let sandbox_res = stop_sandbox_detached(&app, sandbox, port);
    kill_owned(proxy);
    sandbox_res.map_err(|e| format!("代理已停；但{e}真实实例 8765 未受影响。"))
}

/// Science 日志里出现这些片段 = 沙箱起不来（致命）。最常见的是 runtime 展开失败：
/// Science 把自己的 kernel runtime 解到 `runtime/<ver>.tmp-<pid>-<ts>` 再改名到位，
/// Windows 上这一步会被杀毒软件 / 索引器 / 权限挡住（客户真机 EPERM 复现）。
fn fatal_sandbox_log(tail: &str) -> bool {
    tail.contains("Couldn't unpack")
        || tail.contains("console trampoline sync failed")
        || tail.contains("EPERM")
        || tail.contains("rename '")
        || tail.contains("ENOTEMPTY")
}

/// 起沙箱 Science 并探活，失败时按「runtime 展开失败」自愈重试一次。
///
/// **冷启动可能要好几分钟**：Science 首次在沙箱 data-dir 里展开自己的 kernel runtime
/// （Windows 约 124 MB）并起内核，端口才监听。原实现只等 20s 就判超时，客户真机上直接把
/// 还在解压的 daemon 杀掉 → 留下半成品 runtime → 之后每次启动都在「改名到位」那步 EPERM 失败
/// （自伤循环）。现在：给足 180s、daemon 死了立刻报错、命中解压类错误就清残留 +
/// 复制官方 runtime 并重试一次。
#[cfg(target_os = "windows")]
fn spawn_sandbox_and_probe(
    app: &tauri::AppHandle,
    state: &State<'_, Mutex<AppState>>,
    bin: &Path,
    auth_dir: &Path,
    sport: u16,
    proxy_url: &str,
    sbx_home: &Path,
    secret: &str,
    logf: &std::fs::File,
) -> Result<(), String> {
    let mut attempt = 0u8;
    loop {
        attempt += 1;
        // 只看本次启动新产生的日志（上次失败留下的旧尾巴不能用来判断这次）。
        let log_start = std::fs::metadata(log_path("sandbox.log"))
            .map(|m| m.len() as usize)
            .unwrap_or(0);
        let mut cmd = Command::new(bin);
        hidden(&mut cmd);
        cmd.arg("serve")
            .arg("--data-dir")
            .arg(auth_dir)
            // auth_dir 必须在 config 里指回沙箱，否则 Science 去真实目录读登录态（铁律 1/2）。
            .arg("--config")
            .arg(write_science_config(auth_dir)?)
            .arg("--port")
            .arg(sport.to_string())
            .arg("--no-browser")
            .arg("--no-auto-update")
            .arg("--detached")
            .env("ANTHROPIC_BASE_URL", proxy_url)
            .env("no_proxy", "127.0.0.1,localhost")
            .env("NO_PROXY", "127.0.0.1,localhost");
        science_cli_env(&mut cmd, sbx_home);
        let child = cmd
            .stdout(Stdio::from(logf.try_clone().map_err(|e| e.to_string())?))
            .stderr(Stdio::from(logf.try_clone().map_err(|e| e.to_string())?))
            .spawn()
            .map_err(|e| format!("起沙箱失败：{e}"))?;
        {
            let mut st = lock(state);
            st.sandbox = Some(child);
            st.sandbox_port = sport;
        }

        // 轮询沙箱 /health 直到就绪或超时（冷启动含 runtime 展开，给 180s）。
        //
        // **不用「父进程退出」判失败**：`serve --detached` 的启动器进程在 daemon 就绪后
        // **自己就会退出**（真正的 daemon 是它派生的 `--_daemon-child`），照退出判定会把
        // 健康的 daemon 误杀。改为看日志里有没有致命错误（runtime 展开失败等）——那才是
        // 真正起不来的信号。
        let deadline = std::time::Instant::now() + Duration::from_secs(180);
        let mut ok = false;
        while std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
            if proc::http_health(sport, None, 400) {
                ok = true;
                break;
            }
            // 日志出现致命错误（runtime 展开失败 / 权限不足）→ 立刻中止等待。
            let tail = tail_file_from(&log_path("sandbox.log"), log_start, 4000);
            if fatal_sandbox_log(&tail) {
                break;
            }
        }
        if ok {
            return Ok(());
        }

        let new_tail = redact(
            &tail_file_from(&log_path("sandbox.log"), log_start, 2500),
            secret,
        );
        let unpack_failed = fatal_sandbox_log(&new_tail);
        // 探活失败：停掉刚起的沙箱（不留下孤儿进程），并清掉它可能留下的 runtime 临时目录
        // ——留着它会让下一次启动在同一步失败。
        {
            let mut st = lock(state);
            let _ = stop_sandbox_inner(app, &mut st); // best-effort 清理
        }
        clean_sandbox_runtime(false);

        if attempt == 1 && unpack_failed {
            // 自愈：半成品 runtime 目录会让 Science 下次「改名到位」必失败（EPERM/ENOTEMPTY）。
            // 清掉它，再把**真实安装目录**里已展开好的同一份 runtime 复制进沙箱，
            // 让 Science 跳过自己那次解压（真实目录只读，且只碰 runtime/ 子目录）。
            let cleaned = clean_sandbox_runtime(true);
            let copied = copy_runtime_from_real_install();
            let detail = match copied {
                Some(p) => {
                    format!("已清理半成品 runtime 并复制官方 runtime（{p}），正在重试启动。")
                }
                None if cleaned => "已清理半成品 runtime，正在重试启动。".to_string(),
                None => "正在清理 runtime 残留并重试启动。".to_string(),
            };
            let _ = detail;
            continue;
        }

        if unpack_failed {
            return Err(format!(
                "沙箱启动失败（端口 {sport}）。Science 展开自己的运行时文件时被系统拒绝（通常是\
                 杀毒软件/索引器正在占用，或目录权限不足）；请关闭杀毒软件实时防护后重试，\
                 或用管理员身份运行一次让文件落地。日志：\n{new_tail}"
            ));
        }
        return Err(format!(
            "沙箱起后探活超时（端口 {sport}，已等 180 秒）。首次启动需展开 runtime（约 124 MB），\
             请确认磁盘有空间、杀毒软件未拦截；日志：\n{new_tail}"
        ));
    }
}

/// 「一键开始」：起代理 → 写虚拟 OAuth → 起沙箱 Science → 探活 → 开浏览器。
/// macOS：经 launch/stop 脚本；Windows：原生 `claude-science serve --detached`（独立
/// data-dir + HOME/USERPROFILE，铁律 3）。其他平台应使用远程模式 (`remote_*` 命令)。
#[tauri::command]
async fn one_click_login(
    app: tauri::AppHandle,
    state: State<'_, Mutex<AppState>>,
) -> Result<serde_json::Value, String> {
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = (&app, &state);
        return Err("本地模式「一键开始」仅支持 macOS / Windows。请切换到「远程服务器」模式管理 Linux 服务器上的 Science。".into());
    }
    #[cfg(target_os = "macos")]
    {
    // 1~3. 确保代理在跑且健康（内部已查 key、探活）。带回本次是复用还是重启。
    let (pport, secret, proxy_action) = ensure_proxy(&app, &state)?;

    let dir = config::default_dir();
    let cfg = config::load_from(&dir).map_err(|e| e.to_string())?;
    let sport = cfg.sandbox_port;

    // sandbox_home() 作沙箱根：伪造器要求解析后的 auth_dir 落在其下，防符号链接重定向（P1）。
    let sbx_home = sandbox_home();
    let auth_dir = sbx_home.join(".claude-science");

    // 沙箱已健康 → 但「daemon 活着」≠「登录态可用」：先只读校验虚拟登录是否自洽（修 0.2.1 Bug2）。
    // - 自洽 → 绝不重伪造、绝不重跑 launch（连 auth 文件都不读，operon 可能正在用），只重取
    //   URL + 打开。修 #3/#6：活动 org 不变，旧对话一直在。
    // - 健康但登录失效（旧版遗留 / 凭证损坏 / 已落登录页）→ 重开也只会再落登录页，故停沙箱、
    //   落到下面「修复保 org + 重启」路径自愈（0.2.0 的健康快捷路径漏了这一步）。
    // P2b：asset_root() 只在下面「需启动」分支才取。
    // P2（GPT 复审）：用 sandbox_running_ours 而非裸端口 /health——按 data-dir 强身份判定，
    // 避免端口被冒名服务占用且恰好返回 200 时误报「已重新打开 Science」。
    if sandbox_running_ours(sport) {
        if oauth_forge::login_intact(&auth_dir, "virtual@localhost.invalid", &sbx_home) {
            let url = sandbox_url(sport);
            {
                let mut st = lock(&state);
                st.sandbox_port = sport;
                st.sandbox_url = Some(url.clone());
            }
            let base = match proxy_action {
                ProxyAction::Reused => "已在运行",
                ProxyAction::Restarted => "已用新配置重启代理，Science 沿用不变",
            };
            // P2c：捕获打开结果——open 失败不谎报「已重新打开」，改提示手动打开。
            let msg = match crate::nonce_autologin::open_science_ui(&url) {
                Ok(()) => format!("{base}，已重新打开 Science。"),
                Err(_) => format!("{base}，服务已就绪，请手动打开：{url}"),
            };
            return Ok(json!({ "url": url, "msg": msg, "action": "reopened" }));
        }
        // 健康但登录态失效：停沙箱，让下面 relaunch 拿到修复后的登录材料（daemon 运行中不会
        // 重读 auth）。ensure_virtual_login 幂等：保住 org（旧对话不丢），只重铸失效的登录。
        {
            let mut st = lock(&state);
            let _ = stop_sandbox_inner(&app, &mut st);
        }
    }

    // 沙箱没起 / 挂了 / 登录失效已停 → 需要 launch 资源，此时才定位（P2b）。确保虚拟登录（幂等）+ launch。
    let root = asset_root(&app)
        .ok_or("找不到 scripts/launch-virtual-sandbox.sh（打包资源或仓库根均未命中）。")?;

    // 进程内确保虚拟 OAuth（Rust 原生密码学，零 node）。幂等：现有登录完整就复用、部分坏就
    // 修复但保住 org、真首次才铸新 —— 修 #3/#6 的核心（不再无条件换 org 孤儿化旧对话）。
    let (forged, login_action) =
        oauth_forge::ensure_virtual_login(&auth_dir, "virtual@localhost.invalid", &sbx_home)
            .map_err(|e| format!("写虚拟登录失败：{e}"))?;

    let launch = root.join("scripts/launch-virtual-sandbox.sh");
    if !launch.is_file() {
        return Err("找不到 scripts/launch-virtual-sandbox.sh。".into());
    }

    // 4. 起沙箱：脚本以 --detached 起 Science，然后返回。
    let proxy_url = format!("http://127.0.0.1:{pport}/{secret}");
    let mut logf = open_log("sandbox.log").map_err(|e| format!("建日志失败：{e}"))?;
    // 虚拟登录摘要面包屑（无密钥；uuid/假账号/沙箱路径均不敏感），便于用户附日志排查。
    {
        use std::io::Write;
        let mut lw = &logf;
        let _ = writeln!(
            lw,
            "[oauth] 虚拟登录已就绪（Rust，零 node；action={:?}）：auth_dir={} account={} org={} enc={}",
            login_action,
            forged.auth_dir.display(),
            forged.account_uuid,
            forged.org_uuid,
            forged.enc_file.display()
        );
    }
    let logf2 = logf.try_clone().map_err(|e| e.to_string())?;
    let status = hidden(&mut Command::new("bash")) // launch 脚本 #!/usr/bin/env bash（跨 macOS/Git Bash 可执行）
        .arg(&launch)
        .arg("--port")
        .arg(sport.to_string())
        .arg("--proxy-url")
        .arg(&proxy_url)
        .arg("--skip-oauth-forge") // OAuth 已由上面 Rust 进程内伪造，脚本别再调 node
        // 沙箱状态落在可写目录（打包后资源目录只读），launch/stop/取 URL 三处同一路径。
        .env("SANDBOX_HOME", sandbox_home())
        .stdout(Stdio::from(logf))
        .stderr(Stdio::from(logf2))
        .status()
        .map_err(|e| format!("起沙箱失败：{e}"))?;
    if !status.success() {
        let tail = redact(&tail_file(&log_path("sandbox.log"), 600), &secret);
        return Err(format!("起沙箱脚本失败。\n{tail}"));
    }

    // 5. 轮询沙箱 /health 直到就绪或超时（~8s）。
    let mut ok = false;
    for _ in 0..80 {
        std::thread::sleep(Duration::from_millis(100));
        if proc::http_health(sport, None, 400) {
            ok = true;
            break;
        }
    }
    if !ok {
        let tail = redact(&tail_file(&log_path("sandbox.log"), 600), &secret);
        // 探活超时：脚本已把 Science 以 --detached 起在后台，必须停掉，
        // 否则留一个孤儿沙箱进程（修 P2-2）。
        {
            let mut st = lock(&state);
            let _ = stop_sandbox_inner(&app, &mut st); // best-effort 清理，结果不影响这里的报错
        }
        return Err(format!(
            "沙箱起后探活超时（端口 {sport}）。已尝试停掉刚起的沙箱。\n{tail}"
        ));
    }

    // 5b. 身份确认（修 P2 GPT 复审）：/health 200 只证明端口在服务，不证明是我们的 Science。
    // 用 data-dir 强身份再确认一次；不是我们的（端口被冒名服务占用）→ 当启动失败处理，
    // 停掉可能已在后台的沙箱并如实报错，别对着冒名服务谎报「已启动」。
    if !sandbox_running_ours(sport) {
        {
            let mut st = lock(&state);
            let _ = stop_sandbox_inner(&app, &mut st);
        }
        return Err(format!(
            "端口 {sport} 有服务响应，但按 data-dir 确认不是本沙箱 Science（疑似被其它服务占用）。已尝试停掉刚起的沙箱。"
        ));
    }

    // 6. 取 UI URL（登录态），交系统浏览器打开。
    let url = sandbox_url(sport);
    {
        let mut st = lock(&state);
        st.sandbox_port = sport;
        st.sandbox_url = Some(url.clone());
    }
    let started = match login_action {
        oauth_forge::LoginAction::Created => "已启动",
        _ => "沙箱已重新启动，沿用原有对话", // Reused / Repaired
    };
    // P2c：同样捕获打开结果。
    let msg = match crate::nonce_autologin::open_science_ui(&url) {
        Ok(()) => format!("{started}。"),
        Err(_) => format!("{started}，服务已就绪，请手动打开：{url}"),
    };
    Ok(json!({ "url": url, "msg": msg, "action": "started" }))
    } // #[cfg(target_os = "macos")]

    #[cfg(target_os = "windows")]
    {
    // 1~3. 确保代理在跑且健康（内部已查 key、探活）。带回本次是复用还是重启。
    let (pport, secret, proxy_action) = ensure_proxy(&app, &state)?;

    let dir = config::default_dir();
    let cfg = config::load_from(&dir).map_err(|e| e.to_string())?;
    let sport = cfg.sandbox_port;

    // sandbox_home() 作沙箱根 + 独立 HOME/USERPROFILE（铁律 3：与真实用户目录完全隔开）。
    let sbx_home = sandbox_home();
    let auth_dir = sbx_home.join(".claude-science");

    // 沙箱已健康 → daemon 活着 ≠ 登录态可用：先只读校验虚拟登录是否自洽（修 0.2.1 Bug2）。
    // - 自洽 → 绝不重伪造、绝不重起（连 auth 文件都不读，operon 可能正在用），只重取 URL +
    //   打开。活动 org 不变，旧对话一直在。
    // - 健康但登录失效 → 重开也只会再落登录页，故停沙箱、落到下面「修复保 org + 重启」路径。
    if sandbox_running_ours(sport) {
        if oauth_forge::login_intact(&auth_dir, "virtual@localhost.invalid", &sbx_home) {
            let url = sandbox_url(sport);
            {
                let mut st = lock(&state);
                st.sandbox_port = sport;
                st.sandbox_url = Some(url.clone());
            }
            let base = match proxy_action {
                ProxyAction::Reused => "已在运行",
                ProxyAction::Restarted => "已用新配置重启代理，Science 沿用不变",
            };
            // P2c：捕获打开结果——失败不谎报「已重新打开」，改提示手动打开。
            let msg = match crate::nonce_autologin::open_science_ui(&url) {
                Ok(()) => format!("{base}，已重新打开 Science。"),
                Err(_) => format!("{base}，服务已就绪，请手动打开：{url}"),
            };
            return Ok(json!({ "url": url, "msg": msg, "action": "reopened" }));
        }
        {
            let mut st = lock(&state);
            let _ = stop_sandbox_inner(&app, &mut st);
        }
    }

    // 定位 Claude Science CLI（Windows 本地模式必需；官方安装目录 / PATH）。
    let bin = science_bin_windows().ok_or(
        "找不到 Claude Science（本地模式需要）。已查 %LOCALAPPDATA%\\Programs\\ClaudeScience 与 PATH 仍未命中；请确认已安装官方 Claude Science Windows 版。",
    )?;

    // 进程内确保虚拟 OAuth（Rust 原生密码学，零 node）。幂等：现有登录完整就复用、部分坏就
    // 修复但保住 org、真首次才铸新；绝不触碰真实凭证树（铁律 1/2）。
    let (forged, login_action) =
        oauth_forge::ensure_virtual_login(&auth_dir, "virtual@localhost.invalid", &sbx_home)
            .map_err(|e| format!("写虚拟登录失败：{e}"))?;

    // 4. 起沙箱：`serve --detached`。独立 data-dir + 独立 HOME/USERPROFILE（铁律 3）。
    // 推理经 ANTHROPIC_BASE_URL 导去本地代理（推理不走 Anthropic）；回环地址不走路由代理
    // （用户 shell 里的小写 https_proxy 指向 127.0.0.1:7890，不能让它劫持对代理的直连）。
    let proxy_url = format!("http://127.0.0.1:{pport}/{secret}");
    let mut logf = open_log("sandbox.log").map_err(|e| format!("建日志失败：{e}"))?;
    // 虚拟登录摘要面包屑（无密钥；uuid/假账号/沙箱路径均不敏感），便于用户附日志排查。
    {
        use std::io::Write;
        let _ = writeln!(
            logf,
            "[oauth] 虚拟登录已就绪（Rust，零 node；action={:?}）：auth_dir={} account={} org={} enc={}",
            login_action,
            forged.auth_dir.display(),
            forged.account_uuid,
            forged.org_uuid,
            forged.enc_file.display()
        );
    }
    // 4b. 起沙箱 + 探活（含 runtime 展开失败自愈）。
    spawn_sandbox_and_probe(
        &app,
        &state,
        &bin,
        &auth_dir,
        sport,
        &proxy_url,
        &sbx_home,
        &secret,
        &logf,
    )?;

    // 5b. 身份确认（修 P2 GPT 复审）：/health 200 只证明端口在服务，不证明是我们的 Science。
    // 按 data-dir 强身份再确认一次；不是我们的 → 当启动失败处理，停掉并如实报错。
    // 重试 8s：daemon 刚起来时 CLI 可能还没登记完，误判会把自己起的沙箱杀掉。
    if !sandbox_identity_confirmed(sport, Duration::from_secs(8)) {
        {
            let mut st = lock(&state);
            let _ = stop_sandbox_inner(&app, &mut st);
        }
        return Err(format!(
            "端口 {sport} 有服务响应，但按 data-dir 确认不是本沙箱 Science（疑似被其它服务占用）。已尝试停掉刚起的沙箱。"
        ));
    }

    // 6. 取 UI URL（登录态），交系统浏览器打开。
    let url = sandbox_url(sport);
    {
        let mut st = lock(&state);
        st.sandbox_port = sport;
        st.sandbox_url = Some(url.clone());
    }
    let started = match login_action {
        oauth_forge::LoginAction::Created => "已启动",
        _ => "沙箱已重新启动，沿用原有对话", // Reused / Repaired
    };
    let msg = match crate::nonce_autologin::open_science_ui(&url) {
        Ok(()) => format!("{started}。"),
        Err(_) => format!("{started}，服务已就绪，请手动打开：{url}"),
    };
    Ok(json!({ "url": url, "msg": msg, "action": "started" }))
    } // #[cfg(target_os = "windows")]
}

/// 从 `claude-science url` 的 stdout 里取**第一条**合法 http(s) URL。
/// 本地模式（macOS / Windows）需要（依赖 `claude-science` 二进制调用）。
/// Science 的 `url` 命令会输出多行（第一行是真 URL，随后行是「single-use…」说明）；把整段
/// stdout 当 URL 交给浏览器会带上换行与说明文字 → 打开错误入口、nonce 不被正确消费 → 落到
/// `/login`（修 0.2.1 Bug1）。故逐行找第一条以 `http://`/`https://` 开头的行，并只取该行首个
/// 非空白 token（URL 内不含空白，若同行尾随了说明也被切掉）。找不到返回 None。
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn first_http_url(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        let t = line.trim();
        if t.starts_with("http://") || t.starts_with("https://") {
            let url = t.split_whitespace().next().unwrap_or(t);
            return Some(url.to_string());
        }
    }
    None
}

/// 取沙箱 UI 链接：`<bin> url --data-dir <home>/.claude-science`，HOME/USERPROFILE 指向
/// 沙箱 HOME。本地模式（macOS / Windows）调用（one_click_login）。
/// 失败退回 http://127.0.0.1:<port>。沙箱 HOME 用 [`sandbox_home`]（与 launch 时一致）。
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn sandbox_url(port: u16) -> String {
    if let Some(bin) = science_bin_any() {
        let home = sandbox_home();
        let data_dir = home.join(".claude-science");
        let mut cmd = Command::new(&bin);
        hidden(&mut cmd);
        cmd.arg("url").arg("--data-dir").arg(&data_dir);
        if let Ok(c) = write_science_config(&data_dir) {
            cmd.arg("--config").arg(c);
        }
        science_cli_env(&mut cmd, &home);
        if let Some(s) = proc::run_bounded(cmd, Duration::from_secs(8)) {
            // 只取第一条合法 URL（修 0.2.1 Bug1）：url 命令多行输出里第一行才是真 URL。
            if let Some(url) = first_http_url(&s) {
                return url;
            }
        }
    }
    format!("http://127.0.0.1:{port}")
}

/// 判断「我们自己的」沙箱 Science 是否在跑（供一键健康分派与 status 灯）。收紧（P2 GPT 复审）：
/// 优先用 Science CLI 按【我们的 data-dir】查 `{"running":true}`，这是强身份——不会被恰好
/// 占用 `port` 且返回 200 的冒名服务骗过；再叠加端口 /health 确认确实在服务。二进制不在
/// （远程模式 / helper 构建）时退化为仅端口探活（原行为）。status() 在所有平台调用本函数。
fn sandbox_identity(port: u16, use_cache: bool) -> bool {
    // 先做便宜的 TCP 探活：端口都没响应时**直接返回，绝不 spawn 子进程**。
    // 前端每 2.5s 轮询一次，而 Windows 上每次 CreateProcess 都要过 Defender / 杀软钩子并
    // 同步等待——持续高频 spawn 是「配置很好但整机很卡、CPU/内存却不高」的来源
    // （瓶颈在进程创建开销，不在计算）。空闲态下这个短路让每轮 spawn 次数归零。
    if !proc::http_health(port, None, 400) {
        return false;
    }
    if let Some(bin) = science_bin_any() {
        // 端口有响应时才需要 CLI 做强身份校验（防止冒名服务）。该校验要 spawn 进程，
        // 故缓存结果 TTL=10s：身份在两次校验之间不会变，没必要每 2.5s 付一次 spawn 代价。
        static IDENTITY: Mutex<Option<(std::time::Instant, bool)>> = Mutex::new(None);
        // 单飞锁：同一时刻只允许**一个**身份校验在跑。
        // 这条是 async 化之后必须补的——同步 command 跑在主线程上天然串行，而 async
        // command 可以并发进入；前端每 2.5s 轮询、单次最长阻塞 5s，一旦并发就会各自
        // spawn 一次子进程，N 个并发轮询 = N 倍 CreateProcess 风暴（还要各过一次杀毒
        // 软件），足以把整机拖死。持锁期间只有首个调用者真正 spawn，其余等锁后命中缓存。
        static INFLIGHT: Mutex<()> = Mutex::new(());
        const TTL: Duration = Duration::from_secs(10);
        if use_cache {
            let g = IDENTITY.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((at, v)) = *g {
                if at.elapsed() < TTL {
                    return v;
                }
            }
        }
        let _flight = INFLIGHT.lock().unwrap_or_else(|e| e.into_inner());
        // 等锁期间可能已被别人填好缓存，再查一次避免重复 spawn。
        if use_cache {
            let g = IDENTITY.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((at, v)) = *g {
                if at.elapsed() < TTL {
                    return v;
                }
            }
        }
        let home = sandbox_home();
        let data_dir = home.join(".claude-science");
        let mut cmd = Command::new(&bin);
        hidden(&mut cmd);
        cmd.arg("status").arg("--data-dir").arg(&data_dir);
        science_cli_env(&mut cmd, &home);
        // 走有界执行：残留 daemon 占着 data-dir 时 status 可能挂住。
        let running = match proc::run_bounded(cmd, Duration::from_secs(5)) {
            Some(s) => {
                // 审核 P2-8 修复：用 serde_json 解析而非 contains 字符串匹配（避免嵌套误判）。
                serde_json::from_str::<serde_json::Value>(&s)
                    .map(|v| v.get("running").and_then(|r| r.as_bool()).unwrap_or(false))
                    .unwrap_or(false)
            }
            // 调用失败/超时 → 保守退化到端口探活（端口已确认有响应）。
            None => true,
        };
        let mut g = IDENTITY.lock().unwrap_or_else(|e| e.into_inner());
        *g = Some((std::time::Instant::now(), running));
        return running;
    }
    true
}

/// 轮询用的宽松身份判定（吃 TTL 缓存）。
fn sandbox_running_ours(port: u16) -> bool {
    sandbox_identity(port, true)
}

/// 启动后的强身份确认：**绕过缓存并重试**。
///
/// 端口探活通过 ≠ CLI 已登记完 daemon。刚 `serve --detached` 起来的几秒内，
/// `claude-science status` 可能仍报 `running:false`。此时若直接判定「不是本沙箱」，
/// 就会把刚起好的沙箱当成冒名服务杀掉并报错（客户现场即此症状）。
/// 必须 `use_cache=false`——否则重试只会反复读到刚写入的 false 缓存，永远不成功。
fn sandbox_identity_confirmed(port: u16, wait: Duration) -> bool {
    let deadline = std::time::Instant::now() + wait;
    loop {
        if sandbox_identity(port, false) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(400));
    }
}

/// 状态轮询。**必须 async**：Tauri v2 的同步 command 在主线程执行，而本命令内部要 spawn
/// `claude-science status` 子进程。同步执行时，一旦那个子进程挂住（残留 daemon 占着
/// data-dir 锁文件、CLI 自身卡死），主线程就一直等 → 窗口停止重绘、连关闭按钮都不响应。
/// 声明 async 让它离开主线程，卡住也只影响这一次的返回值，不再冻结 UI。
#[tauri::command]
async fn status(state: State<'_, Mutex<AppState>>) -> Result<serde_json::Value, String> {
    // 先在锁外加载配置（磁盘 I/O），避免阻塞其他需要锁的命令。
    let cfg = match config::load_from(&config::default_dir()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("status: 读取配置失败，使用默认值: {e}");
            config::Config::default()
        }
    };
    let (adapter, base_url) = cfg
        .active_profile()
        .map(|p| (templates::adapter_for(&p.template_id).to_string(), p.base_url.clone()))
        .unwrap_or_default();

    // 只在锁内取 AppState 字段（无 I/O）。
    let (pport, secret, sport) = {
        let st = lock(&state);
        let pport = if st.proxy_port != 0 {
            st.proxy_port
        } else {
            cfg.proxy_port
        };
        let sport = if st.sandbox_port != 0 {
            st.sandbox_port
        } else {
            cfg.sandbox_port
        };
        (pport, st.secret.clone(), sport)
    };
    let proxy = if !secret.is_empty() && proc::http_health(pport, Some(&secret), 300) {
        "green"
    } else {
        "amber"
    };
    // 状态灯也用 data-dir 强身份（修 P2 GPT 复审），避免端口被冒名服务占用时误显绿灯。
    // status() 是按需调用（前端 refreshStatus 在动作后触发，非高频轮询），一次子进程可接受。
    let sandbox = if sandbox_running_ours(sport) {
        "green"
    } else {
        "amber"
    };
    // 无活跃 profile 时 adapter/base_url 为空，跳过上游探活避免空主机名连接。
    let upstream = if adapter.is_empty() {
        "amber"
    } else if proc::tcp_reachable(&upstream_host(&adapter, &base_url), 443, 500) {
        "green"
    } else {
        "amber"
    };
    // 状态探测永不失败：任何异常都退化成灯色，交给前端显示。
    Ok(json!({ "proxy": proxy, "sandbox": sandbox, "upstream": upstream }))
}

#[tauri::command]
fn open_url(state: State<'_, Mutex<AppState>>, url: Option<String>) -> Result<(), String> {
    let url = match url {
        Some(url) => {
            let trimmed = url.trim();
            if trimmed != url {
                return Err("URL 不能包含首尾空白。".to_string());
            }
            let lower = trimmed.to_ascii_lowercase();
            let allowed = lower.starts_with("http://127.0.0.1:")
                || lower.starts_with("http://localhost:")
                || lower.starts_with("http://[::1]:");
            if !allowed {
                return Err("只允许打开本地沙箱 URL。".to_string());
            }
            url
        }
        None => lock(&state)
            .sandbox_url
            .clone()
            .ok_or("还没有沙箱 URL，请先「一键开始」。")?,
    };
    crate::nonce_autologin::open_science_ui(&url)
}

/// 运行诊断脚本 `scripts/doctor.sh`。仅 macOS 本地模式有效。
/// Windows/其他平台上返回明确提示，引导使用远程模式诊断。
#[tauri::command]
fn run_doctor(app: tauri::AppHandle) -> Result<String, String> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = &app;
        return Err("本地模式「自检」仅支持 macOS。请切换到「远程服务器」模式使用远程诊断功能。".into());
    }
    #[cfg(target_os = "macos")]
    {
    let root = asset_root(&app).ok_or("找不到 scripts/doctor.sh（打包资源或仓库根均未命中）。")?;
    let cfg = config::load_from(&config::default_dir()).unwrap_or_default();
    let doctor = root.join("scripts/doctor.sh");
    let active = cfg.active_profile().cloned();
    let adapter = active
        .as_ref()
        .map(|p| templates::adapter_for(&p.template_id).to_string())
        .unwrap_or_default();
    let mut cmd = Command::new("bash");
    hidden(&mut cmd);
    cmd.arg(&doctor)
        .env("CSSWITCH_PROVIDER", &adapter)
        .env("CSSWITCH_PROXY_PORT", cfg.proxy_port.to_string())
        .env("CSSWITCH_SANDBOX_PORT", cfg.sandbox_port.to_string());
    // doctor 只做 -n 判空来报 key 有无。只让它知道「存在」，绝不把真实 key 传进其环境。
    if let Some(p) = active.as_ref() {
        if !p.api_key.is_empty() {
            cmd.env(key_env_for_adapter(&adapter), "***present***");
        }
    }
    let out = cmd.output().map_err(|e| e.to_string())?;
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    let err = String::from_utf8_lossy(&out.stderr);
    if !err.trim().is_empty() {
        text.push_str("\n[stderr] ");
        text.push_str(err.trim());
    }
    Ok(text)
    } // #[cfg(target_os = "macos")]
}

/// 当前 app 版本（供前端「检查更新」与页脚版本号用）。
#[tauri::command]
fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// 打开 GitHub Releases 页（检查更新时用系统浏览器打开，浏览器走用户自己的代理）。
#[tauri::command]
fn open_release_page() -> Result<(), String> {
    open_in_browser("https://github.com/SuperJJ007/CSswitch/releases/latest")
}

/// 打开「报 bug」页（预填 bug 模板）；用系统浏览器，走用户自己的代理。
#[tauri::command]
fn report_bug() -> Result<(), String> {
    open_in_browser("https://github.com/SuperJJ007/CSswitch/issues/new?template=bug_report.yml")
}

/// 在文件管理器中打开日志目录 `~/.csswitch/logs`（跨平台）。
/// macOS 用 `open`，Windows 用 `explorer`，Linux 用 `xdg-open`。
#[tauri::command]
fn open_logs() -> Result<(), String> {
    let dir = config::default_dir().join("logs");
    let _ = std::fs::create_dir_all(&dir);
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(&dir)
            .status()
            .map_err(|e| format!("打开日志目录失败：{e}"))?;
    }
    #[cfg(target_os = "windows")]
    {
        hidden(&mut Command::new("explorer"))
            .arg(&dir)
            .status()
            .map_err(|e| format!("打开日志目录失败：{e}"))?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Command::new("xdg-open")
            .arg(&dir)
            .status()
            .map_err(|e| format!("打开日志目录失败：{e}"))?;
    }
    Ok(())
}

#[tauri::command]
fn quit_app(app: tauri::AppHandle, state: State<'_, Mutex<AppState>>) -> Result<(), String> {
    // 默认：退 app 停代理、保留沙箱运行（spec §5.1）。
    {
        let mut st = lock(&state);
        kill_child(&mut st.proxy);
        st.secret.clear();
    }
    app.exit(0);
    Ok(())
}

// ---------- 入口 ----------
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(Mutex::new(AppState::default()))
        .invoke_handler(tauri::generate_handler![
            // 本地命令（macOS 本地模式）
            get_config,
            list_templates,
            set_config,
            set_settings,
            set_mode,
            open_official,
            save_provider_key,
            create_profile,
            update_profile_metadata,
            update_profile_connection,
            clear_profile_key,
            delete_profile,
            set_active_profile,
            fetch_models,
            start_proxy,
            verify_key,
            stop_all,
            one_click_login,
            status,
            open_url,
            run_doctor,
            app_version,
            open_release_page,
            report_bug,
            open_logs,
            quit_app,
            // 远程命令（跨平台）
            remote_commands::remote_list_profiles,
            remote_commands::remote_save_profile,
            remote_commands::remote_delete_profile,
            remote_commands::remote_validate_profile,
            remote_commands::remote_list_wsl_distributions,
            remote_commands::remote_save_login_secret,
            remote_commands::remote_delete_login_secret,
            remote_commands::remote_auth_prompt_respond,
            remote_commands::remote_check_health,
            remote_commands::remote_prepare_helper,
            remote_commands::remote_install_helper,
            remote_commands::remote_get_config,
            remote_commands::remote_set_config,
            remote_commands::remote_save_provider_key,
            remote_commands::remote_start_proxy,
            remote_commands::remote_stop_proxy,
            remote_commands::remote_stop_all,
            remote_commands::remote_proxy_status,
            remote_commands::remote_verify_key,
            remote_commands::remote_status,
            remote_commands::remote_logs,
            remote_commands::remote_doctor,
            remote_commands::remote_one_click,
        ])
        .setup(|app| {
            remote::askpass::set_app_handle(app.handle().clone());
            // 正常桌面应用：进 Dock、走常规应用生命周期（默认 Regular 策略，
            // 不再设 Accessory）。窗口在 tauri.conf.json 里配了 decorations（标题栏
            // 三键：关闭/最小化/缩放）+ visible + center，启动即居中弹出、可拖动
            // （修 #4；标题栏自带拖动，顺带解决 #1 拖不动）。托盘图标已移除。

            // 关窗即退出：与「退出」按钮一致 —— 停代理、清 secret，保留沙箱运行
            // （spec §5.1）。不接这一步，从标题栏红叉关窗会绕过 quit_app 直接退，
            // 把代理子进程留成孤儿。
            if let Some(win) = app.get_webview_window("main") {
                let handle = app.handle().clone();
                win.on_window_event(move |ev| {
                    if let tauri::WindowEvent::CloseRequested { .. } = ev {
                        let state = handle.state::<Mutex<AppState>>();
                        let mut st = lock(&state);
                        kill_child(&mut st.proxy);
                        st.secret.clear();
                    }
                });
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    // first_http_url 和 sandbox_home 在本地模式平台（macOS/Windows）编译，测试同门。
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    use super::{first_http_url, sandbox_home};
    use super::{key_fingerprint, redact};

    /// 测试 URL 解析（本地模式平台，依赖 first_http_url）。
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn first_http_url_takes_only_first_valid_url() {
        // Science 的 `url` 命令输出两行：第一行是真 URL，第二行是「single-use…」说明。
        // 旧代码把整段 stdout 当 URL 交给 open → 换行+说明污染参数、nonce 不被消费 → 落登录页。
        // 只能取第一条合法 http(s) URL（修 0.2.1 Bug1）。
        let multi = "http://127.0.0.1:8990/setup?nonce=abc123\n\
                     This is a single-use link, expires in 60 seconds.";
        assert_eq!(
            first_http_url(multi).as_deref(),
            Some("http://127.0.0.1:8990/setup?nonce=abc123"),
            "多行输出必须只取第一行 URL，丢弃说明文字"
        );
        // 同一行 URL 后跟了说明，只取 URL token（URL 内不含空白）。
        let inline = "https://x.example/y?z=1  (single-use)";
        assert_eq!(
            first_http_url(inline).as_deref(),
            Some("https://x.example/y?z=1")
        );
        // 前导非 URL 行被跳过，取第一条 http 行。
        let lead = "Open this link in your browser:\nhttp://127.0.0.1:8990/a";
        assert_eq!(
            first_http_url(lead).as_deref(),
            Some("http://127.0.0.1:8990/a")
        );
        // 无任何 URL → None（sandbox_url 据此退回裸端口）。
        assert_eq!(first_http_url("no url here\nnor here"), None);
        // 单行纯 URL 原样返回。
        assert_eq!(
            first_http_url("http://127.0.0.1:8990").as_deref(),
            Some("http://127.0.0.1:8990")
        );
    }

    #[test]
    fn redact_scrubs_secret_and_is_noop_when_empty() {
        assert_eq!(
            redact("推理指向 http://127.0.0.1:18991/abcd1234 尾巴", "abcd1234"),
            "推理指向 http://127.0.0.1:18991/**** 尾巴"
        );
        assert_eq!(redact("原样返回", ""), "原样返回");
        assert!(!redact("leak abcd1234 leak abcd1234", "abcd1234").contains("abcd1234"));
    }

    #[test]
    fn key_fingerprint_stable_and_distinct() {
        // 同 key 稳定、异 key 不同：这是「换 key 触发代理重启」判断的基础（P1-2）。
        assert_eq!(key_fingerprint("sk-aaaa"), key_fingerprint("sk-aaaa"));
        assert_ne!(key_fingerprint("sk-aaaa"), key_fingerprint("sk-bbbb"));
        assert_ne!(key_fingerprint(""), key_fingerprint("x"));
    }

    /// 测试 sandbox_home 路径（本地模式平台，依赖 sandbox_home 函数）。
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn sandbox_home_is_writable_under_config_dir() {
        // 沙箱状态目录必须在可写的 ~/.csswitch 下（不在只读的 .app 资源里）——P1-1。
        let h = sandbox_home();
        // Path::ends_with 按路径分量比较（Windows 的 \ 分隔符同样命中）。
        assert!(h.ends_with("sandbox/home"), "应以 sandbox/home 结尾：{h:?}");
        assert!(
            h.to_string_lossy().contains(".csswitch"),
            "应在 .csswitch 下：{h:?}"
        );
    }

    /// Windows：定位已安装的 Claude Science CLI（本机装有官方安装版；未安装则跳过）。
    #[cfg(target_os = "windows")]
    #[test]
    fn science_bin_windows_finds_installed_cli() {
        let Some(bin) = super::science_bin_windows() else {
            return;
        };
        assert!(bin.is_file(), "定位到的 CLI 必须存在：{bin:?}");
        let s = bin.to_string_lossy();
        assert!(
            s.ends_with(".com") || s.ends_with(".exe"),
            "应是 .com shim 或 .exe：{bin:?}"
        );
    }

    /// tail_file_from 只取本次启动新增的日志，不被上次的旧尾巴误导（自愈判断依赖这个）。
    #[test]
    fn tail_file_from_only_returns_new_bytes() {
        let dir = std::env::temp_dir().join("csswitch-test-tailfrom");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("t.log");
        std::fs::write(&p, b"OLD-ERROR-EPERM\n").unwrap();
        let from = std::fs::metadata(&p).unwrap().len() as usize;
        std::fs::write(&p, b"OLD-ERROR-EPERM\nNEW-GOOD-LINE\n").unwrap();
        let got = super::tail_file_from(&p, from, 2500);
        assert!(!got.contains("OLD-ERROR"), "旧内容不应出现：{got:?}");
        assert!(got.contains("NEW-GOOD-LINE"), "新内容应出现：{got:?}");
        // from 超过文件长度时也不应 panic。
        let _ = super::tail_file_from(&p, 999_999, 2500);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// sandbox_path_is_safe：只接受沙箱目录下的路径，越界（真实目录）一律拒绝。
    #[test]
    fn sandbox_path_is_safe_rejects_outside_paths() {
        assert!(
            !super::sandbox_path_is_safe(&super::sandbox_home().join("..").join("..")),
            "越界路径必须被拒绝"
        );
        let inside = super::sandbox_home()
            .join(".claude-science")
            .join("runtime");
        // 该路径目前可能还不存在；不存在不是符号链接，逐级检查应通过。
        assert!(
            super::sandbox_path_is_safe(&inside),
            "沙箱内的 runtime 路径应被接受：{inside:?}"
        );
    }

    /// clean_runtime_dir：只删 `.tmp-*` 残留时，正式目录必须保留；full=true 时全删。
    #[test]
    fn clean_runtime_dir_only_removes_tmp_when_not_full() {
        let dir = std::env::temp_dir().join("csswitch-test-runtime-clean");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("0.1.50-release")).unwrap();
        std::fs::create_dir_all(dir.join("0.1.50-release.tmp-123-456")).unwrap();
        std::fs::write(dir.join("0.1.50-release").join("keep.txt"), b"x").unwrap();

        assert!(super::clean_runtime_dir(&dir, false), "应报告清理过东西");
        assert!(
            dir.join("0.1.50-release").join("keep.txt").is_file(),
            "正式目录必须保留"
        );
        assert!(
            !dir.join("0.1.50-release.tmp-123-456").exists(),
            ".tmp- 临时目录应被清掉"
        );

        assert!(super::clean_runtime_dir(&dir, true), "full 应报告成功");
        assert!(!dir.exists(), "full=true 应删掉整个 runtime 目录");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
