//! 免掉 Claude Science 每次启动都要手点一次的「Sign in」中转页。
//!
//! 背景（逆向 Claude Science 0.1.50 的 daemon JS 确认，证据见 findings/ 与 known-issues #13）：
//! `claude-science url` 给出带**一次性 nonce**（TTL 180s、单次消费）的链接。浏览器 GET 该链接时，
//! daemon 发现请求没带 bearer，就返回一个中转页：
//!
//! ```html
//! <form method="post" action="./api/auth/nonce">
//!   <input type="hidden" name="nonce" value="…">
//!   <input type="hidden" name="dest" value="…">
//!   <button type="submit">Sign in</button>
//! </form>
//! ```
//!
//! 手点一次 → POST `/api/auth/nonce` → daemon 回 `Set-Cookie: operon_auth=<bearer>; HttpOnly;
//! SameSite=Strict` + 一个 meta-refresh 页 → 进工作区。cookie 随 daemon 重启失效，
//! 所以**每次启动都要重来一遍**（厂商的 CSRF 设计，非 bug）。
//!
//! 这里把它自动化，且**只用系统浏览器**、不碰用户凭证：
//!
//! 1. **nonce 只在 POST 时消费**：GET 走 `uBs()` 只读校验，POST 走 `dBs()` 置 `used` → 可跳过 GET 直接 POST；
//! 2. **POST 的 origin 白名单对该路由专门放行**任意 `127.0.0.1` / `localhost` 端口
//!    （`iBs = /^https?:\/\/(?:127\.0\.0\.1|localhost)(?::\d+)?$/`），且该路由被排除在 CSRF token 之外；
//! 3. **cookie 不区分端口** → `127.0.0.1:<helper>` → `127.0.0.1:<science>` 属同站，`SameSite=Strict` 照常落地。
//!
//! 于是：进程内先取回 daemon 那张表单（**自己解析出 action 与 hidden 值**，不臆测路径，
//! daemon 若改路由也能跟上），再起一个**只监听 127.0.0.1 随机口**的一次性小服务发一页自动提交的表单，
//! 让**系统浏览器**自己去 POST —— cookie 由浏览器原生接受、仍是 HttpOnly、直达工作区。
//!
//! 铁律：小服务只回一页静态 HTML（含一次性 nonce 与目标路径），**不含任何密钥**；
//! 仅监听回环、随机口、随机路径、限时退出；非回环目标（远程模式）一律回落老流程。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use rand::Rng;

/// daemon 那张中转表单里要用的东西。
struct SigninForm {
    /// POST 的绝对地址（由 daemon 自己写在 action 里）。
    action: String,
    /// 一次性 nonce。
    nonce: String,
    /// 登录成功后要去的路径。
    dest: String,
    /// 小服务的随机路径段（防本地其它进程猜到）。
    token: String,
}

/// 打开 Science UI。若链接带一次性 nonce，则自动完成 daemon 的 Sign in 中转页。
///
/// 任何一步不成立（不是回环 URL / 取不到表单 / 起不了小服务 / 浏览器打不开）都**回落老流程**
/// （直接打开原链接，用户手点一次 Sign in），绝不因此让用户打不开 Science。
pub fn open_science_ui(url: &str) -> Result<(), String> {
    let Some((host, port, path)) = split_url(url) else {
        return crate::open_in_browser(url);
    };
    // 远程模式的 Science 在别的机器上：daemon 的 origin 白名单只放行 127.0.0.1/localhost，
    // 从本机 helper 页 POST 过去会被拒 → 远程链路不参与这条路。
    if !is_loopback(&host) {
        return crate::open_in_browser(url);
    }
    let Some((status, body)) = http_get(&host, port, &path, 4000) else {
        return crate::open_in_browser(url);
    };
    if status != 200 {
        return crate::open_in_browser(url);
    }
    let Some((action, nonce, dest)) = parse_form(&body) else {
        // 浏览器已有有效 cookie 时 daemon 直接返回应用（没有表单）——老流程打开即可。
        return crate::open_in_browser(url);
    };
    let origin = format!("http://{host}:{port}");
    let form = SigninForm {
        action: resolve_action(&path, &origin, &action),
        nonce,
        dest,
        token: random_token(),
    };
    // helper 页必须与目标**同主机**：operon_auth 是 SameSite=Strict，而
    // `localhost` 与 `127.0.0.1` 在 cookie 语义里是**两个不同的站**——helper 在
    // 127.0.0.1 而目标在 localhost 时，POST 之后的跳转属跨站，Strict cookie 不带上，
    // 页面会回「You've been signed out」。所以沿用目标的 host。
    let Ok((helper_port, helper_host)) = spawn_autologin_page(&form, &host) else {
        return crate::open_in_browser(url);
    };
    let helper = format!("http://{helper_host}:{helper_port}/{}", form.token);
    match crate::open_in_browser(&helper) {
        Ok(()) => Ok(()),
        // 小服务打不开 → 回落老流程（用户手点一次）。
        Err(_) => crate::open_in_browser(url),
    }
}

/// 拆 `http://host:port/path?query` → (host, port, path+query)。非 http / 畸形 → None。
fn split_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if hostport.is_empty() {
        return None;
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()?),
        None => (hostport.to_string(), 80u16),
    };
    Some((host, port, path.to_string()))
}

fn is_loopback(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    h == "127.0.0.1" || h == "localhost" || h == "::1"
}

/// 把 daemon 表单里的相对 action 解析成绝对 URL（相对**文档 URL**的目录）。
fn resolve_action(doc_path: &str, origin: &str, action: &str) -> String {
    let a = action.trim();
    if a.starts_with("http://") || a.starts_with("https://") {
        return a.to_string();
    }
    let a = a.strip_prefix("./").unwrap_or(a);
    if a.starts_with('/') {
        return format!("{origin}{a}");
    }
    let dir = match doc_path.rfind('/') {
        Some(i) => &doc_path[..=i],
        None => "/",
    };
    format!("{origin}{dir}{a}")
}

/// 从 daemon 返回的 HTML 里取出 `action` 与两个 hidden 值。
fn parse_form(body: &str) -> Option<(String, String, String)> {
    let action = html_unescape(&attr_value(body, "action")?);
    let nonce = html_unescape(&input_value(body, "nonce")?);
    let dest = input_value(body, "dest").map(|d| html_unescape(&d)).unwrap_or_default();
    Some((action, nonce, dest))
}

/// 取第一个 `name="…"` 的属性值。
fn attr_value(html: &str, name: &str) -> Option<String> {
    let pat = format!("{name}=\"");
    let i = html.find(&pat)?;
    let rest = &html[i + pat.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// 取 `name="<name>" value="…"` 的值。
fn input_value(html: &str, name: &str) -> Option<String> {
    let pat = format!("name=\"{name}\" value=\"");
    let i = html.find(&pat)?;
    let rest = &html[i + pat.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn html_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn random_token() -> String {
    let r = rand::thread_rng().gen::<u64>();
    format!("{r:016x}{:016x}", r.rotate_left(17))
}

/// 起一次性小服务，只发一页自动提交表单。返回监听端口。
///
/// 仅监听 127.0.0.1:0（随机口），路径带随机 token；页面里只有一次性 nonce 与目标路径，
/// **没有任何密钥**。服务到时限即退出。
fn spawn_autologin_page(form: &SigninForm, host: &str) -> std::io::Result<(u16, String)> {
    // 目标 host 是 `localhost` 时，浏览器可能把 localhost 解析到 ::1 或 127.0.0.1，
    // 两个都监听才不会被解析差异坑到；端口号保持一致，URL 仍写 `localhost`。
    let mut listeners: Vec<TcpListener> = Vec::new();
    let (port, url_host) = match host {
        "::1" => {
            let l = TcpListener::bind("[::1]:0")?;
            let p = l.local_addr()?.port();
            listeners.push(l);
            (p, "[::1]".to_string())
        }
        "localhost" => {
            let l = TcpListener::bind("127.0.0.1:0")?;
            let p = l.local_addr()?.port();
            listeners.push(l);
            if let Ok(l6) = TcpListener::bind(format!("[::1]:{p}")) {
                listeners.push(l6);
            }
            (p, "localhost".to_string())
        }
        _ => {
            let l = TcpListener::bind("127.0.0.1:0")?;
            let p = l.local_addr()?.port();
            listeners.push(l);
            (p, "127.0.0.1".to_string())
        }
    };
    let path = format!("/{}", form.token);
    let html = build_page(form);
    for listener in listeners {
        let path = path.clone();
        let html = html.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(60);
            let _ = listener.set_nonblocking(true);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        let _ = s.set_nonblocking(false);
                        serve_one(&mut s, &path, &html);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(80));
                    }
                    Err(_) => break,
                }
            }
        });
    }
    Ok((port, url_host))
}

/// 处理一个连接：路径命中就发页面，否则 404。
fn serve_one(s: &mut TcpStream, path: &str, html: &str) {
    let mut buf = [0u8; 4096];
    let n = s.read(&mut buf).unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]).to_string();
    let hit = req
        .split_whitespace()
        .nth(1)
        .map(|p| p == path)
        .unwrap_or(false);
    if !hit {
        let _ = s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        return;
    }
    let body = html.as_bytes();
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(body);
    let _ = s.flush();
}

/// 自动提交页：拿到即 POST 到 daemon 的 action，daemon 回 cookie + meta-refresh，直达工作区。
fn build_page(form: &SigninForm) -> String {
    format!(
        r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Signing in — Claude Science</title>
<style>body{{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#0f1115;color:#e8eaed;margin:0;display:flex;align-items:center;justify-content:center;height:100vh}}
.card{{max-width:26rem;padding:2rem;text-align:center}}h1{{font-size:1.05rem;font-weight:600;margin:0 0 .5rem}}
p{{opacity:.65;font-size:.85rem;margin:.25rem 0}}
button{{margin-top:1rem;padding:.5rem 1.1rem;border-radius:.5rem;border:1px solid #3a3f4b;background:#1b1f27;color:#e8eaed;cursor:pointer}}</style>
</head><body><div class="card">
<h1>正在登录 Claude Science…</h1>
<p>若未自动跳转，请点「继续」。</p>
<form id="f" method="post" action="{action}">
<input type="hidden" name="nonce" value="{nonce}">
<input type="hidden" name="dest" value="{dest}">
<button type="submit" id="go">继续</button>
</form>
</div>
<script>(function(){{var f=document.getElementById("f");if(f){{f.submit();}}}})();</script>
</body></html>"#,
        action = html_escape(&form.action),
        nonce = html_escape(&form.nonce),
        dest = html_escape(&form.dest),
    )
}

/// 极简 HTTP GET（仅回环明文，无需 TLS）。返回 (状态码, 响应体)。
fn http_get(host: &str, port: u16, path: &str, timeout_ms: u64) -> Option<(u16, String)> {
    let addr = (host, port).to_socket_addrs().ok()?.next()?;
    let dur = Duration::from_millis(timeout_ms);
    let mut s = TcpStream::connect_timeout(&addr, dur).ok()?;
    let _ = s.set_read_timeout(Some(dur));
    let _ = s.set_write_timeout(Some(dur));
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: text/html\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if buf.len() > 4_194_304 {
            break;
        }
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())?;
    let (head, body) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h.to_string(), b.to_string()),
        None => (text.clone(), String::new()),
    };
    let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        dechunk(&body)
    } else {
        body
    };
    Some((status, body))
}

/// 粗解码 chunked 响应（Bun 偶尔会这么发）。
fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    loop {
        let Some((size_line, tail)) = rest.split_once("\r\n") else {
            break;
        };
        let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or("0"), 16).unwrap_or(0);
        if size == 0 {
            break;
        }
        if tail.len() < size {
            out.push_str(tail);
            break;
        }
        out.push_str(&tail[..size]);
        rest = &tail[size..];
        rest = rest.strip_prefix("\r\n").unwrap_or(rest);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// daemon 真实返回的中转页形状（2026-10 从 Science 0.1.50 的 daemon JS 里确认）。
    const REAL_FORM: &str = r#"<div id="op-signin"><form method="post" action="./api/auth/nonce" id="signin-form"><input type="hidden" name="nonce" value="a1b2c3d4e5f6"><input type="hidden" name="dest" value="/setup"><button type="submit">Sign in</button></form></div>"#;

    #[test]
    fn parses_real_form() {
        let (action, nonce, dest) = parse_form(REAL_FORM).expect("应能解析");
        assert_eq!(action, "./api/auth/nonce");
        assert_eq!(nonce, "a1b2c3d4e5f6");
        assert_eq!(dest, "/setup");
    }

    #[test]
    fn resolves_relative_action_against_doc_path() {
        assert_eq!(
            resolve_action("/setup", "http://127.0.0.1:8990", "./api/auth/nonce"),
            "http://127.0.0.1:8990/api/auth/nonce"
        );
        assert_eq!(
            resolve_action("/", "http://127.0.0.1:8990", "./api/auth/nonce"),
            "http://127.0.0.1:8990/api/auth/nonce"
        );
        // daemon 若挂在子路径下（action 已是绝对路径），直接用。
        assert_eq!(
            resolve_action("/base/setup", "http://127.0.0.1:8990", "/base/api/auth/nonce"),
            "http://127.0.0.1:8990/base/api/auth/nonce"
        );
    }

    #[test]
    fn splits_and_gates_loopback() {
        let (h, p, path) = split_url("http://127.0.0.1:8990/setup?nonce=abc").unwrap();
        assert_eq!((h.as_str(), p, path.as_str()), ("127.0.0.1", 8990, "/setup?nonce=abc"));
        assert!(is_loopback(&h));
        assert!(split_url("https://127.0.0.1:8990/").is_none(), "只处理 http");
        assert!(!is_loopback("192.168.1.7"));
    }

    #[test]
    fn escapes_page_values() {
        let form = SigninForm {
            action: "http://127.0.0.1:8990/api/auth/nonce".into(),
            nonce: "a\"b".into(),
            dest: "/x?y=1&z=2".into(),
            token: "t".into(),
        };
        let html = build_page(&form);
        assert!(html.contains("value=\"a&quot;b\""));
        assert!(html.contains("value=\"/x?y=1&amp;z=2\""));
        assert!(html.contains("f.submit()"), "必须自动提交");
    }
}
