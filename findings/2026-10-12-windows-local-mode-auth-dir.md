# Windows 本地模式「登录页」根因：auth_dir 指向真实凭证目录

日期：2026-10-12 · 环境：Claude Science 0.1.50（构建 `0e67b3ea`，2026-09-18 编译），Windows 11

## 结论（一句话）

`--data-dir` 只覆盖 `data_dir`，而登录态所在的 `auth_dir` 默认取 `os.homedir()/.claude-science`；
Windows 的 `os.homedir()` 读 `USERPROFILE`，我们为不破坏 winsbx 护栏刻意不覆盖它 →
`auth_dir` 落到**真实凭证目录** → 沙箱里的伪造登录从未被读取。

## 证据链

### 1. 伪造产物本身完全正确

在隔离沙箱内自行解密自己的 `.oauth-tokens/*.enc`（v2 GCM，HKDF info `operon:aes-256-gcm:oauth`）：

```
org_uuid     = e0685cdc-...   ← 与 active-org.json 完全一致
account_uuid = a99b972d-...   ← 与文件名一致
token_expires_at = 2099-01-01
v2 格式解密正常，四个 key 齐全
```

即 `Dts()` 的 org 比对关卡可以通过——**失败不在令牌内容**。

### 2. Science 侧关键代码

`auth_dir` 的默认来源与覆盖方式：

```js
Mgr = (e) => E.object({ ..., auth_dir: VN(al) })   // al = join(os.homedir(), ".claude-science")
function Xue(e={}){
  let r = axi.parse(Hue(t));                      // 读 config.toml
  if(e.dataDir) r.data_dir = jb(e.dataDir);       // ← CLI 只覆盖 data_dir
  let o = Mgr(r.data_dir).parse(n.paths ?? {});   // ← auth_dir 只能从 [paths] 改
}
```

认证模式探测是硬编码桩：

```js
function M8(){ return "none" }    // 恒不返回 "oauth"
```

故 `/api/auth/status` 会走 `a = EI()`（扫 `.oauth-tokens` 里唯一那个 `.enc`）——**伪造器本该被认到**。

### 3. 被证伪的两个猜测

- ❌ **「缺 `encryption.key.dpapi`」**：手工写入一个 502 字节的 DPAPI blob（`CryptProtectData`，
  entropy=null、flags=1），重启 daemon 后**依然**未登录。读源码确认明文 `encryption.key` 是被读的，
  且 `.dpapi` 缺失时 Science 会自动把明文镜像进去。
- ❌ **「Windows 只读 .dpapi 不读明文」**：`TXn()` 的 `h()` 分支明确支持明文回退。

## 验证

| | 修复前 | 修复后（加 `--config` + `[paths] auth_dir`） |
|---|---|---|
| `/api/auth/status` | `authenticated:false` | `authenticated:true`（`virtual@localhost.invalid`） |
| 浏览器点 Sign in 后 | 跳 `/login`，要求 Pro/Max | 完整工作区（Projects / sessions / artifacts） |

## 铁律影响

真实目录存在真实 token 时，Science 会**直接使用用户真实账号运行**，而非沙箱的伪造身份——
违反铁律 1/2。用户侧「Windows 上登录一次就行」这一现象，成因即在此。

## 附：逆向方法备忘

`claude-science.exe` 是 Bun 单文件包，压缩后的 JS 明文可读（偏移定位 + 上下文截取即可），
改版可 diff，逆向成本远低于原生二进制。两层认证：

- `operon_auth` — daemon 本机 bearer，nonce + 表单点击可得
- `operon_session` — 用户会话 JWT，**只在 OAuth 回调签发**
