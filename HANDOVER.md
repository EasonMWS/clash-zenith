# Zenith 移交报告

> 交接日期：2026-10-25
> 仓库 HEAD：`9e9cc5d`（v1.4.1，93 个提交）
> 这份文档是写给**下一个接手的人**的。它假设你会改代码、会看日志，但**没参与过这个项目的开发**。
> 所以它不只写"东西在哪"，还写了"为什么是这样"和"哪些坑会骗你"。

---

## 0. 先读这一段

**Zenith 是一个 Windows 上的 Clash 客户端，只做一件事：把 Cloudflare CDN 中转的节点，选中最快的那条边缘 IP。**

它不是通用客户端。详见「[已知限制](#9-已知限制别夸大口径)」——**那里列的东西比功能表重要**，因为一个夸大口径的代理客户端比一个功能少的更糟。

**如果你的第一件事是"让它跑起来"，直接跳到「[交接清单](#12-交接清单接手后照做)」。**

---

## 1. 立刻会踩到的第一件事：部署版本落后于仓库

**这是交接时最实际的问题，先说。**

```
仓库 HEAD (app.go)   : 1.4.1
当前已部署的 exe     : 1.4.0      ← 用 `Zenith.exe -version` 自报
两者 SHA256          : 不同
```

**含义：** 仓库里 `v1.4.1` 的改动（版本号、README 时钟排查章节、CHANGELOG、**6 个新增测试**，
共 491 行改动）**没有体现在正在运行的二进制里**。

**但功能上是准的**——`#PROXY` 那个 DNS 修复已经在部署的二进制里了
（我改完 DNS 才升的版本号，中间部署过一次）。所以**跑的不是"有 bug 的旧版"，
只是一个不对应任何标签的中间构建**。

**可复验的证据：**

```powershell
# 部署的二进制里：有 alidns，没有 1.1.1.1 的 DoH（说明 DNS 已修）
$b = [IO.File]::ReadAllBytes('D:\Zenith\Zenith.exe')
$t = [Text.Encoding]::ASCII.GetString($b)
($t | Select-String -Pattern 'dns\.alidns\.com' -AllMatches).Matches.Count   # → 1
($t | Select-String -Pattern '1\.1\.1\.1/dns-query' -AllMatches).Matches.Count # → 0

# 但 v1.4.0 标签的源码里还是旧的那套
git show v1.4.0:src/config.go | Select-String 'dns-query'
# → ['https://1.1.1.1/dns-query#PROXY', 'https://8.8.8.8/dns-query#PROXY']

# 它自报的版本
D:\Zenith\Zenith.exe -version     # → Zenith 1.4.0 (go1.24.5)
```

**接手后第一件事：重新构建并部署一次**，让版本号归位。见「[构建与部署](#7-构建与部署精确步骤)」。

**这个现象本身是个教训：部署的二进制可以漂在标签之间。**
区别"跑的是哪个版本"不能靠 `LastWriteTime`，要**让它自报**（`-version`），
或者**比 SHA256**（`Get-FileHash Zenith.exe` vs 从 HEAD 重新构建）。

---

## 2. 这个项目是什么

### 2.1 一句话

订阅里给你的是一个**绑定在某个域名上的隧道**。真正决定速度的是**你连到 Cloudflare 的哪一台边缘服务器**
——同一个订阅、同一个域名，换不同的边缘 IP，实测延迟能从 250ms 变到 2000ms。

主流做法是把这件事交给外部脚本（社区叫"优选 IP 脚本"）。Zenith 把它做进客户端：
**自己测所有候选边缘 IP，选出真的能跑通的那几个，并且持续盯着它们。**

### 2.2 和主流客户端的定位差别

| | 主流客户端（Clash Verge / FlClash / mihomo 本身） | Zenith |
|---|---|---|
| 优选 IP | 交给外部脚本，或只做 TCP 连通性 | **内置，真实 WebSocket 升级验证** |
| 节点存活判定 | 内核 `url-test`（HTTP 204 探测） | **真实流量穿过隧道** |
| 失效处理 | 换下一个 | 换 + 重扫 + 池验证 |

**但对比功能数量，它一定输。**见「已知限制」。

### 2.3 技术栈

| | |
|---|---|
| 语言 | Go 1.24.5，`CGO_ENABLED=0` |
| 依赖 | **零第三方依赖**（只有标准库）—— 故意的，为了让"克隆下来双击就能跑"成立 |
| 内核 | mihomo (Clash.Meta) `v1.19.32`，58.38MB，随仓库分发 |
| 前端 | 原生 JS + HTML + CSS，无框架、无构建步骤 |
| 平台 | **仅 Windows**（用了 win32 API：托盘、服务、注册表、pnputil） |

---

## 3. 仓库状态

```
远程      https://github.com/EasonMWS/clash-zenith.git
分支      main
HEAD      9e9cc5d  2026-10-15  1.4.1
提交数    93
首个提交  aea7957  2026-10-07
```

### 3.1 标签

| 标签 | 提交 | 日期 | 主题 |
|---|---|---|---|
| `v1.0.0` | `f1edaa6` | 2026-10-07 | 首个可发布版本 |
| `v1.0.1` | `c7c2e3c` | 2026-10-08 | 稳定性与 DNS |
| `v1.0.2` | `58ce822` | 2026-10-09 | 连续可用性 |
| `v1.2.2` | `0e5d223` | 2026-10-09 | TUN 一键启用 |
| `v1.3.1` | `76ccc85` | 2026-10-09 | 不把自己搞断网 |
| `v1.4.0` | `3f75e46` | 2026-10-13 | 常驻服务能装了，启动 22 秒 → 0.9 秒 |
| `v1.4.1` | `9e9cc5d` | 2026-10-15 | DNS 不被自己掐死，时钟偏差 |

### 3.2 版本号的含义

**语义化版本，但主要标记"能用的状态"，不承诺兼容性周期。**（`CHANGELOG.md` 开头有同样的话。）

---

## 4. 文件地图

### 4.1 顶层

```
D:\Zenith\
├── src\             Go 后端（20,346 行 / 27 个文件）
├── web\             前端（2,116 行 / 3 个文件）
├── core\            内核与资源（58.8MB，随仓库分发）
│   ├── mihomo.exe              v1.19.32
│   └── wintun\                 TUN 驱动 + 许可证 + manifest
├── data\            运行时数据（大部分不进仓库，见 §8）
├── docs\            ARCHITECTURE.md
├── logs\            运行时日志（不进仓库）
├── .github\         release workflow + issue/PR 模板
├── build.ps1        构建脚本（有 UTF-8 BOM，别丢）
├── README.md        45KB，双语（English / 中文）
├── CHANGELOG.md     36KB，每个版本带实测数据
├── CONTRIBUTING.md
├── LICENSE          GPL-3.0 + 反商业附加说明
└── Zenith.exe       构建产物（不进仓库）
```

### 4.2 `src/` 逐个文件

| 文件 | 行数 | 职责 |
|---|---|---|
| `main.go` | 865 | 入口、命令行分发、启动顺序、托盘菜单内容 |
| `app.go` | 2,665 | **核心中枢**。`App` 结构（42 字段）、后台主循环、健康检查、auto-pick、池验证、状态汇总 |
| `store.go` | 733 | 状态持久化（`state.json`），带 `Revision` 计数器防 mtime 抖动 |
| `config.go` | 573 | **生成 mihomo 配置**（YAML 拼接）。DNS 段、TUN 段、proxy-groups、rules 都在这里 |
| `configtxn.go` | 344 | 配置事务：先写候选 → 校验 → 生效 → 失败回滚 |
| `subscription.go` | 970 | **订阅解析**（手写 YAML 子集解析器 + 分享链接解析），以及流量/到期信息 |
| `optimizer.go` | 1,186 | **优选 IP 扫描**。`probeWS`（WebSocket 升级）+ `probeHTTPS`（真实响应）双验证 |
| `core.go` | 536 | 内核进程管理 + mihomo REST API 封装（`/proxies`、`/delay`、`/configs`…） |
| `corefail.go` | 225 | 内核崩溃分类与恢复策略 |
| `tun.go` | 1,645 | **TUN 占管**。两条激活路径（常驻服务 / 每次授权）、事务、回滚、恢复、验证 |
| `tunclaims.go` | 156 | TUN 的三类断言：已接管 / 已出口 / 已泄露 |
| `tunverify.go` | 390 | TUN 生效后的端到端验证（真实请求 + 出口 IP 对比） |
| `service.go` | 696 | Windows 常驻服务：注册、启动、控制、通道 |
| `scm.go` | 445 | **真实 SCM 协议实现**（`StartServiceCtrlDispatcher` + 控制处理器） |
| `serviceproof.go` | 166 | 服务通道的身份证明（HMAC + nonce，防伪造响应） |
| `sysproxy.go` | 494 | 系统代理：注册表读写、四道护栏、端口占用检测 |
| `startup.go` | 139 | 启动时清理上一次留下的死代理 |
| `server.go` | 722 | HTTP API（28 个路由）+ 界面托管 + 跨源校验 |
| `tray.go` | 514 | 托盘图标（直接 `Shell_NotifyIcon` + 消息泵） |
| `winapi.go` | 433 | win32 封装：网卡删除、进程查询、提权 |
| `handover.go` | 362 | 提权激活的交接记录（谁请求、等多久、结果） |
| `secret.go` | 217 | 敏感文件 ACL（`control.secret` 等） |
| `redact.go` | 96 | **给界面显示的配置脱敏**（订阅 URL、UUID、密钥） |
| `origin.go` | 160 | 请求来源校验（防跨源打 API） |
| `yamlkeys.go` | 247 | YAML 键名白名单（防订阅内容改写配置结构） |
| `logrotate.go` | 196 | 日志轮转 + 脱敏 |
| `regression_test.go` | 5,171 | **171 个测试**（按"曾经坏过的东西"组织） |

### 4.3 `web/`

| 文件 | 行数 | 说明 |
|---|---|---|
| `app.js` | 1,041 | 全部界面逻辑。2.5 秒轮询 `/api/status`，单文件状态机 |
| `index.html` | 338 | 单页，含 `zenith-token` 元标签（API 鉴权） |
| `style.css` | 737 | 全部样式 |

**没有构建步骤。改完直接刷新页面。**

---

## 5. 架构与数据流

更完整的版本在 `docs/ARCHITECTURE.md`。这里给交接需要的最小模型。

### 5.1 三层职责

```
┌─ 前端 (web/) ──────────────  只做展示和发指令，不做判断
│      ↕ HTTP (127.0.0.1:7799, 带 token)
├─ App 中枢 (app.go) ────────  所有决策在这里
│      ├─ Store        状态持久化
│      ├─ Core         内核进程 + REST API
│      ├─ Optimizer    边缘优选
│      ├─ SystemProxy  系统代理
│      └─ Health       存活判定 + auto-pick
│      ↕ REST (127.0.0.1:7797, Bearer secret)
└─ mihomo 内核 ──────────────  真正的流量处理
```

### 5.2 一次"切换节点"发生了什么

1. `App.switchTo(name)` → `core.Select("PROXY", name)`
2. `core.CloseConnections()` —— **丢掉现有连接**，否则旧路由会一直用下去
3. `store.SetCurrent(name)`
4. 如果是用户点的：记 `userPicked` + `userPickedAt`（10 分钟宽限，但见 §6 的坑）

### 5.3 后台主循环（`app.background()`，10 秒一次）

```
1. 内核看门狗      Ensure() / 分类失败 / 必要时重启
2. 死代理护栏      GuardDeadProxy() —— 代理指向死端口就关掉它
3. auto-pick       只在 AutoPickOff=false 时跑
4. 订阅自动更新     只在 SubscriptionAutoUpdate=true 时跑
5. 优选自动扫描     只在 AutoOptimize=true 时跑
```

### 5.4 健康检查（独立循环，`app.healthLoop()`，10 秒）

**这是整个项目最容易被改坏的地方，改之前读完 §6.2、§6.3。**

```
1. sweepPool(current)             验证候选池（每轮 3 个，按排名）
2. healthProbeThroughTunnel()     真实请求穿过混合端口
3. 失败 → 立刻复测一次（2 倍超时）
4. 两次都失败 → 记一次失败
5. 连续 3 次 → 换节点（先试域名节点，再试候选，最多 3 个）
6. 每次成功 → reactToSlowness()   用**内核 /delay** 的数字，不是真实流量
```

### 5.5 优选扫描（`optimizer.go`）

对每个候选边缘 IP：

```
probeWS    TLS 握手 + WebSocket Upgrade，必须返回 101
probeHTTPS 同一连接上发真实 HTTP 请求，必须收到响应
两者都过才算"可用"，记录中位数耗时
```

**注意 `probeHTTPS` 的注释**：它证明边缘的 web 层有应答，**不证明隧道把流量转到了远端**。
真正的端到端验证是别的东西。

---

## 6. 端口、默认值、关键常量（以及为什么是这些值）

### 6.1 端口

| 用途 | 默认 | 说明 |
|---|---|---|
| 混合端口（HTTP+SOCKS） | `7890` | **实际会轮换**，见 §6.4 |
| `ControlPort`（mihomo REST） | `7797` | **内核真正监听的那个**。`NewCore(...)` 收到的就是它 |
| 界面 | `7799` | 单实例检测靠这个端口 |
| DNS | `MixedPort + 300` 派生 | 默认 `7890 → 8190`；当前机 `7944 → 8244`。**不是固定值** |
| 常驻服务 | `7795` | 只有 TUN 用 |
| `APIPort` | `7798` | **⚠️ 声明了但内核不用它**。它出现在 `/api/status` 的 `ports.api` 和设置里，但 `NewCore` 拿的是 `ControlPort`（7797） |

**⚠️ 读 `/api/status` 时的陷阱**：返回的是

```json
{"api": 7798, "control": 7797, "mixed": 7944, "ui": 7799}
```

**内核实际监听的是 `control`（7797），不是 `api`。**实测：内核进程在听 `7797`、`7944`、`8244`。
**别按 `ports.api` 去连内核 REST API，会连不上。**

### 6.2 关键常量（都在 `app.go` 顶部）

| 常量 | 值 | 为什么是这个值（**都是实测出来的，不是拍的**） |
|---|---|---|
| `coreStartGrace` | 4 分钟 | 首次运行要下载规则库，慢链路要几分钟 |
| `coreRestartDelay` | 20 秒 | 内核已经服务过之后的宽限。实测恢复 **9 秒** |
| `portReleaseWait` | 20 秒 | 旧内核退出、释放端口要这么久。**短了会轮换端口**（§6.4） |
| `healthInterval` | 10 秒 | 1 秒会把检查端点击穿，504 被误读成"节点死" |
| `healthTimeoutMS` | 6000 | 真实请求的首个探测超时 |
| `healthFailLimit` | 3 | 连续失败次数上限 |
| `healthRetryDelay` | 30 秒 | 两次强制切换之间的最小间隔 |
| `tunnelOverheadMS` | 1200 | **TUN 自身开销**。同一节点：真实流量 1238–1955ms，内核 `/delay` 238–304ms |
| `aliveFor` | 20 分钟 | 成功探测后节点保持"可选"的时长。**必须 > 一次完整池扫描**，否则池会自己排空 |
| `slowNodeMS` | 1200 | "太慢"阈值。**用内核 `/delay` 比较，不是真实流量**（§6.3） |
| `slowStrikesNeeded` | 2 | 连续两次才算慢 |
| `serviceProofMaxSkew` | 20 秒 | 服务通道 nonce 的新鲜度上限 |
| `handoverTimeout` | 2 分钟 | 提权激活的交接等待上限 |
| `approvalGrace` | 8 秒 | 点"启用"后等 UAC 弹窗出现的宽限 |
| `tunAdapterWait` | 15 秒 | 内核重启时网卡会短暂消失，等它回来 |

### 6.3 三个"测量口径"的陷阱（**最容易改坏的**）

**这三个坑的共同点：症状都指向节点，而病因在测量方式。**

#### ① 节点死活：必须用**真实流量**，不能用 `/delay`

```go
// 错：会用健康检查把能用的节点扔掉
a.core.Delay(node, timeout, "")

// 对：
a.healthProbeThroughTunnel(timeout)   // 真实请求穿过混合端口
```

**实测数据**——隧道正常、六个节点各测两次：

```
优选01 · 172.66.200.1    /delay 249ms    CONNECT OK/OK
优选02 · 108.162.192.1   /delay [504]    CONNECT OK/OK   ← 报死，实际能用
优选03 · 172.69.250.1    /delay [504]    CONNECT OK/OK   ← 报死，实际能用
优选04 · 162.159.1.1     /delay [503]    CONNECT OK/OK   ← 报死，实际能用
优选05 · 172.69.30.1     /delay [504]    CONNECT OK/OK   ← 报死，实际能用
优选06 · 172.66.1.1      /delay 249ms    CONNECT OK/OK
```

**六个全都能用，`/delay` 报了四个死。**用它判死活 = 程序一直在扔能用的节点。

#### ② 节点快慢：必须用**内核 `/delay`**，不能用真实流量

```
真实流量经过 TUN:   1537 / 1389 / 1483 / 1640 / 1485 / 1503 / 1955 / 1238 ms
内核 /delay 接口:   238 / 256 / 304 ms
                    ↑ 差约 1200ms，那是 TUN 的开销，不是节点的速度
```

**把真实流量喂给 1200ms 的阈值 → 每个健康节点都判"太慢" → 疯狂切换**
（实测每 60 秒在两个节点之间互跳）。

**规则：死活用真实流量，快慢用内核测量。**（`nodeSpeedMS()` 就是干这个的）

#### ③ 扫描的"可用"≠ 现在可用

扫描写进节点名字的 `"254ms"` 和 `MeasuredMS` 是**扫描那一刻**的数字，**之后没人复查**。
所以有 `aliveFor`（20 分钟）和 `sweepPool()`（持续验证池）。

**没有这两样，auto-pick 会从一堆几小时前的数字里挑最快的，切过去，然后健康检查再把它切走——循环。**

### 6.4 端口轮换（看起来像 bug，其实是保护）

内核默认 `SO_REUSEADDR`，两个代理会**绑定同一个端口并共享连接**——静默、且非常误导。
所以端口被占时会换一个。**但它曾经换得太勤，因为三个 bug 叠在一起：**

1. 等待循环的条件写反了（"端口上没人在听"才等，而**正在关闭的内核恰恰在听**）
2. 判断"是不是自己的内核"靠读命令行，而提权启动的内核**读不到命令行**（`cmd=[]`）
3. 做了正确决定然后忽略了它（`break` 跳出循环 vs `return` 跳出函数）

**修复后实测：27 小时 0 次轮换。**

**⚠️ 改这里的代码前先读 `EnsureUsablePort()` 上面的注释。**那段注释写的就是这三个坑。

---

## 7. 构建与部署（精确步骤）

### 7.1 前置

```
Go 1.24.5          D:\AI\tools\go\bin\go.exe（当前机器）
rsrc               build.ps1 会自动装/用
PowerShell         build.ps1 有 UTF-8 BOM，编辑器别丢
```

### 7.2 构建

```powershell
cd D:\Zenith
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

`build.ps1` 做的事：

1. 用 `rsrc` 把 `data/zenith.ico` 编译成 `.syso`（exe 图标）
2. `CGO_ENABLED=0`，`-trimpath`，`-ldflags "-s -w -H=windowsgui"`
   - **`-H=windowsgui` 意味着没有控制台**。从 cmd 启动也不会附着到它的控制台。
3. 输出 `Zenith.exe`，并保留一个 `Zenith.exe~` 作为上一版
4. 校验产物（大小、MZ 头、图标标记）

**`-Clean` 不会删 `data/` 和 `logs/`**（故意的，你的订阅和日志在里面）。

### 7.3 部署（这台机器上的实际做法）

**⚠️ 必须先停掉正在跑的实例，否则 exe 被占用，构建"成功"但实际没写进去。**
这个坑踩过一次，还"验证"了一个旧二进制。

```powershell
# 1. 停服务（需要管理员）
sc.exe stop ZenithService

# 2. 停所有进程
Get-Process Zenith,mihomo -ErrorAction SilentlyContinue | Stop-Process -Force

# 3. 构建
powershell -ExecutionPolicy Bypass -File D:\Zenith\build.ps1

# 4. 启动
Start-Process D:\Zenith\Zenith.exe -WorkingDirectory D:\Zenith
```

**带 GUI 的启动方式**（`Start-Process` 不会创建控制台窗口）。
服务会自动以 `AUTO_START` 拉起，或用 `sc.exe start ZenithService`。

### 7.4 ⚠️ 四个会浪费你半天的陷阱

#### 陷阱 1：手改 `data/config.yaml` 没用

**内核每次启动都会从 `src/config.go` 重新生成它。**

```
手改 → 重启 → 被覆盖 → 症状原样回来 → 看起来像"修复没生效"
```

**实际上"修复被覆盖了"。**这个坑踩了两次。

**改配置永远改 `src/config.go`，然后重新构建。**

#### 陷阱 2：`Get-Process Zenith` 会连服务一起杀

服务进程也叫 `Zenith.exe`（会话 0）。`Get-Process -Name Zenith | Stop-Process`
会把它也杀掉，导致 `sc.exe` 报 `FAILED 5`（拒绝访问）——

**按会话过滤：**

```powershell
Get-CimInstance Win32_Process -Filter "Name='Zenith.exe'" |
  Where-Object { $_.SessionId -ne 0 } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

#### 陷阱 3：`FlClashCore.exe` 也是 mihomo 内核

**这台机器上装了 FlClash**（`D:\Flclash`）。它的内核同名家族，
粗暴的"杀掉所有 mihomo"会顺手把 FlClash 弄坏（用户会看到 `DioException`）。

**要杀就按 CommandLine 精确匹配。**

#### 陷阱 4：推送需要代理，而 `github.com` 直连不通

```powershell
$port = (Get-NetTCPConnection -State Listen | Where-Object LocalPort -in 7899,7908,7915,7944).LocalPort | Select-Object -First 1
git config http.proxy  "http://127.0.0.1:$port"
git config https.proxy "http://127.0.0.1:$port"
```

**而且端口会变**（§6.4）。**在循环里重试推送（8–12 次）**，代理抖动很常见。

---

## 8. 数据目录与隐私（**交接最容易出事的地方**）

### 8.1 `data/` 里哪些能公开、哪些绝对不行

| 文件 | 含隐私 | 说明 |
|---|---|---|
| `state.json` | **⚠️ 是** | **订阅 URL 原文**、节点列表、设置 |
| `state.json.bak-*` | **⚠️ 是** | 同上 |
| `config.yaml` | **⚠️ 是** | 生成的配置，**含 UUID、订阅域名、ws 路径** |
| `config.last-good.yaml` | **⚠️ 是** | 同上 |
| `control.secret` | **⚠️ 是** | 内核 API 的 Bearer token |
| `config-transaction.json` | **⚠️ 是** | 配置事务记录 |
| `tun-transaction.json` | **⚠️ 是** | TUN 事务记录 |
| `activation-handover.json` | **⚠️ 是** | 提权交接 |
| `proxy-snapshot.json` | **⚠️ 是** | 接管系统代理前的快照 |
| `service-state.json` | **⚠️ 是** | 服务状态 |
| `candidates.txt` / `candidates.stat.json` | **⚠️ 是** | 候选 IP 池（不算秘密，但和你的订阅绑定） |
| `cache.db` | 可公开 | 规则缓存 |
| `GeoSite.dat` / `geoip.metadb` | 可公开 | 规则库，**进仓库**（让新克隆能秒开） |
| `free.flag` | 可公开 | 首次运行标记 |
| `zenith.ico` | 可公开 | 图标，**进仓库** |

### 8.2 `.gitignore` 已经完全覆盖（实测逐个 `git check-ignore` 确认）

```
/Zenith.exe          /Zenith.exe~        *.exe
!core/mihomo.exe                        ← 内核例外，故意进仓库

/data/state.json     /data/state.json.*
/data/config.yaml    /data/config.yaml.*
/data/config.last-good.yaml
/data/control.secret
/data/proxy-snapshot.json
/data/candidates.txt /data/candidates.stat.json
/data/cache.db       /data/nodes.json
/data/ui-profile/    /data/ASN.mmdb     /data/*.part
/data/*-transaction.json                ← 两种事务记录一起覆盖
/data/activation-handover.json
/data/activation.yield
/data/service-state.json
/logs/
```

**实测结论：§8.1 里标记为「⚠️ 含隐私」的每一个文件，`git check-ignore` 都返回「已忽略」。**

**仓库里 `data/` 下只有 4 个文件被跟踪**（都是公开资源）：

```
data/GeoSite.dat    data/free.flag
data/geoip.metadb   data/zenith.ico
```

**所以 `.gitignore` 本身是好的。风险不在它，在"有人用了 `git add -f`"或"新增了运行时文件但忘了加规则"。**

**新增任何写进 `data/` 的文件时，同一次提交里就把规则加进 `.gitignore`。**

### 8.3 提交前必做的隐私扫描

**方法：从本地运行时文件里取真实值，然后扫工作区 + git index。**

要扫的值（**从 `data/` 现取，不要硬编码在脚本里**）：

| 来源 | 取什么 |
|---|---|
| `data/control.secret` | 整个内容 |
| `data/config.yaml` | 所有 `uuid:`、所有域名、所有 `path:` |
| `data/state.json` | 所有 `http(s)://`（排除公开探测目标），订阅 URL 的随机路径段 |

**已知的公开值（命中它们不算泄露）**：`gstatic.com`、`cloudflare.com`、`baidu.com`、
`github.com`、`1.1.1.1`、`8.8.8.8`、`223.5.5.5`、`119.29.29.29`、`127.0.0.1`、
`198.18.0.0/16`、Cloudflare 的公开边缘段（`104.x`、`172.64-71.x`、`188.114.x`…）。

### 8.4 历史泄露的现状

**当前所有凭据在任何历史提交里都不存在**（逐对象扫过 93 个提交的每个 blob）。

**唯一残留**：一个**已在服务端撤销**的旧 UUID，在 7 个旧提交的 `src/regression_test.go` 里。
HEAD 已换成占位符。**它已经失效，拿它连不上任何东西。**

**如果你要彻底清除历史，需要 `git filter-repo`（不是 `filter-branch`——在 Windows 上
`--tree-filter` 会把反斜杠路径搞坏，实测 `D:\AI\temp\repl.py` 变成 `AItemprel.py`）。**

---

## 9. 已知限制（别夸大口径）

**以下照着 README 抄的，都是已经声明过的：**

- **默认是系统代理客户端，不是整机隧道。** 不读系统代理的程序——大多数游戏、
  原始 UDP、自带网络栈的软件——都会直连。TUN 能覆盖这部分，**但没有 Kill Switch**。
- **DNS 和 IPv6 不阻断。** 隧道会抑制多宿主 DNS 泄露，全局 IPv6 会被报告成一条未覆盖路径，
  **但没有任何东西阻止它**。想彻底干净，自己在网卡上关 IPv6。
- **嗅探不是拦截。** 只能从**已经进入内核**的连接里还原域名。管不了没进内核的流量。
- **一次出口检测成功不代表 DNS 干净。** 出口 IP 和 DNS 是某一时刻的抽样，
  不覆盖系统 DNS、IPv6、第二块网卡。
- **站点返回 403/401 不算失败。** 那说明连接通了、对端回应了。
  只有传输层错误才算在节点头上。

### 9.1 未验证过的（交接时要诚实）

| 项 | 状态 |
|---|---|
| TUN 完整寿命 | 兼容模式下成功跑通过**一次**，一台机器 |
| 睡眠/唤醒 | 未系统验证 |
| 多网卡 | 未验证 |
| 与 VPN 共存 | 未验证 |
| 长时间（>24h）连续运行 | 有过 27 小时观察，但非受控测试 |
| 非中文 Windows | 未验证 |

---

## 10. 测试

**171 个测试**，全部在 `src/regression_test.go`（5,171 行）。

```powershell
cd D:\Zenith\src
go test -count=1 -timeout 300s ./...      # → ok, 约 11 秒
go test -count=1 -list '.*' ./...         # 数一遍：171
```

**⚠️ 数测试的陷阱**：PowerShell 的 `Select-String` **默认不区分大小写**，
所以 `Select-String -Pattern '^func Test'` 会把一个辅助函数
`func testAppForHandover(dir string) *App` 也算进去，得出 **172**。
**真实测试数是 171**，用 `go test -list` 或严格签名 `\(t \*testing\.T\)` 才是对的。

**测试的组织方式**：不是按函数，是按**"曾经坏过的东西"**。
每个测试的注释里写的是**实测数据和根因**，不是"应该返回 true"。

**覆盖的主题（抽样）：**

- 快照不可变性与并发安全
- TUN 事务归属与回滚范围
- 配置校验（拒绝内核会拒绝的东西）
- 订阅解析：额外键不能重构配置、危险键名
- 端口解析、token 比较、随机性
- 服务通道的身份证明
- 健康检查：单次探测不算数、成功递减而非清零
- 池验证：扫描结果播种、按排名优先
- 启动：快路径（自己的内核占着端口就直接领养）
- 时钟：未来时间戳不算"刚跑过"
- DNS：**名字服务器不能走代理**
- 界面：报告"实测可用 N 个"

**⚠️ 有些测试是"锚点测试"**——它们用 `strings.Contains(源码, "…")` 断言某个注释或写法存在。
**改文案会打破它们。**这是故意的：那些注释记录的是实测结论，删掉就会有人把 bug 改回去。
**改文案时同步改测试，并读一遍那段注释再决定。**

---

## 11. 排查手册（按症状查）

### 11.1 ⭐ 节点全挂，但网络正常 → **先看系统时间**

**这是最贵的一条，绕了四小时。**

```powershell
w32tm /query /status
```

看 `Last Successful Sync Time`。**服务停了就重启它：**

```powershell
Stop-Service w32time
Set-Date -Date "<真实时间>"
Set-Service w32time -StartupType Automatic
Start-Service w32time
w32tm /resync /force
```

**为什么它会伪装成"节点全挂"：**

| 依赖时间的东西 | 时钟差几小时 |
|---|---|
| TLS 证书有效期 | 证书"还没生效"或"已过期" → 握手失败 |
| 服务端鉴权 | 令牌异常 → 切断连接 |
| 订阅有效期校验 | 订阅状态异常 |

**它的症状组合极具误导性：**

- **CONNECT 成功**（`200 Connection established`），**紧接着 TLS 立刻被切断**（`SSLEOFError`）
- **直连能通，走代理不通**
- **只有部分站点失败**（容错窗口大的能过：Google 静态、Bing、Apple、阿里 DoH；
  严格校验的不过：GitHub、Microsoft、Cloudflare、Steam）
- **内核日志里没有任何错误行** —— 对端是**礼貌地拒绝**，不是报错

**⚠️ 改时区本身是安全的。**实测从 `UTC+8` 切到 `UTC-11`（偏移变 19 小时），
代理 6/6 全通，因为 **UTC 那一瞬间没变**。**只有"时钟本身错了"才会坏。**

### 11.2 所有请求 502 Bad Gateway

**先查 DNS，不是节点。**开内核 debug 日志：

```powershell
# 临时打开 debug
$secret = Get-Content D:\Zenith\data\control.secret -Raw
Invoke-RestMethod -Method Patch -Uri "http://127.0.0.1:7797/configs?log-level=debug" `
  -Headers @{ Authorization = "Bearer $($secret.Trim())" } -Body '{}'
```

然后看 `logs/engine.log` 里有没有：

```
[DNS] resolve xxx error: all DNS requests failed
```

**如果有 → DNS 配置问题。**具体看 §11.3。

### 11.3 DNS 相关

**`nameserver` / `nameserver-policy` 里千万不要加 `#PROXY` 后缀。**

```
❌ ['https://1.1.1.1/dns-query#PROXY']
✅ ['https://dns.alidns.com/dns-query']
```

**实测**（逐项加回，每次只改一条）：

| 配置 | gstatic | github |
|---|---|---|
| 基线 | 204/403ms | 200/573ms |
| + `#PROXY`（1.1.1.1） | **URLError** | **URLError** |
| + `#PROXY`（alidns） | **URLError** | **URLError** |
| 去掉后缀（alidns） | 204/1042ms | 200/550ms |

**两个理由**：一是实测它会掐死所有境外解析；二是**它本来就会死锁**——
走代理的查询需要先解析代理自己的域名，而启动时还没有任何节点被选中。

**另外**：`1.1.1.1:443`、`8.8.8.8:443`、`cloudflare-dns.com` 从这台机器
**通过隧道也连不上**（CONNECT 成功、TLS 被切断）。`dns.alidns.com`、`doh.pub` 可以。

### 11.4 端口莫名其妙轮换

看日志：

```
mixed port 7917 is already in use by another program; moving Zenith to 7926
```

**那个"别的程序"通常是我们自己**（几秒前还在服务该端口的旧内核）。
读 `EnsureUsablePort()` 上面的注释——那三个 bug 都在里面。

### 11.5 双击后很久才出窗口

日志里有 **`launch: ready in X.Xs`**。超过 2 秒会变成 `[WARN]`，并点名是哪几个
reconciliation 花的钱。

正常值：**0.6–1.8 秒**。

### 11.6 服务装不上 / 要求两次授权

**根因曾是 `RegisterServiceCtrlHandlerExW` 的实例句柄传 `0`** ——
文档说可以，实际返回 `ERROR_INVALID_PARAMETER`。

现在传真实模块句柄。**自检：**

```powershell
D:\Zenith\Zenith.exe -scm-test
```

（注意：这个模式**不是由 SCM 启动的**，所以 `StartServiceCtrlDispatcherW` 失败是**正确**的，
退出码 1060。它只用来验证协议本身。）

**看日志：**

```
service: RegisterServiceCtrlHandlerExW returned handle=0x...
         err=The operation completed successfully.
service: reporting RUNNING
```

### 11.7 TUN 开不起来 / 状态自己丢失

```powershell
Get-NetAdapter -Name Zenith          # 网卡在不在
sc.exe queryex ZenithService         # 服务在不在跑
```

**看日志里的 `TUN:` 行。**常见：

- `adapter "Zenith" is not present; clearing the mode` → 正常（TUN 真的没生效）
- `still held by this installation's own core after 20s; adopting it` → 正常（内核重启中）
- `adapter ... is present and carrying traffic while the stored mode is off; restoring` → 正常（自愈）

### 11.8 日志在哪

| 文件 | 内容 |
|---|---|
| `logs/zenith.log` | **Zenith 自己的日志**（它做了什么、为什么） |
| `logs/engine.log` | **mihomo 内核的日志**（流量、DNS、规则匹配） |

**排查顺序：先 `zenith.log` 看决策，再 `engine.log` 看内核实际怎么做的。**

---

## 12. 交接清单（接手后照做）

### 必做

- [ ] **重新构建并部署一次**，让版本号归位（§1、§7.3）
- [ ] **确认系统时间准确**：`w32tm /query/status`，偏差应 < 2 秒（§11.1）
- [ ] **确认 `w32time` 是 `Running / Automatic`**（否则时钟漂移会不知不觉发生）
- [ ] **跑一遍测试**：`cd src; go test -count=1 -timeout 300s ./...` → **171 个全过**（§10 有数测试的陷阱）
- [ ] **读 `docs/ARCHITECTURE.md`**，然后读 `app.go` 顶部的常量注释
- [ ] **读 `CHANGELOG.md` 的 1.4.0 和 1.4.1**——里面是最近两个版本的全部实测教训

### 改代码前必读

- [ ] `EnsureUsablePort()` 上面的注释（端口轮换的三个 bug）
- [ ] `healthProbeThroughTunnel()` 的注释（`/delay` 为什么不能说谎）
- [ ] `nodeSpeedMS()` 的注释（死活 vs 快慢，两个口径）
- [ ] `sweepPool()` 的注释（为什么扫描结果要播种）
- [ ] `config.go` 里 DNS 段的注释（`#PROXY` 的实测）
- [ ] `clampFutureTime()` 的注释（系统时钟不单调）

### 提交前必做

- [ ] **隐私扫描**（§8.3）——从 `data/` 现取真实值，扫工作区 + index
- [ ] `git status` 确认没有 `data/`、`logs/` 被跟踪
- [ ] 确认 `.gitignore` 覆盖了 §8.2 全部条目
- [ ] 推送到 `main`，**并在循环里重试**（§7.4 陷阱 4）
- [ ] 打标签 + 更新 `CHANGELOG.md`（**带实测数据，不只是"修了 bug"**）

### 别做

- [ ] ❌ **别手改 `data/config.yaml`** —— 会被覆盖（§7.4 陷阱 1）
- [ ] ❌ **别用 `Get-Process Zenith | Stop-Process`** —— 会杀掉服务（§7.4 陷阱 2）
- [ ] ❌ **别粗暴杀所有 mihomo** —— 会弄坏 FlClash（§7.4 陷阱 3）
- [ ] ❌ **别用 `/delay` 判节点死活**（§6.3 ①）
- [ ] ❌ **别用真实流量判节点快慢**（§6.3 ②）
- [ ] ❌ **别在 nameserver 上加 `#PROXY`**（§11.3）
- [ ] ❌ **别在测试里删那些"锚点注释"** —— 它们记录的是实测结论

---

## 13. 版本历史要点

**完整内容看 `CHANGELOG.md`（36KB，每个版本都带实测数据）。这里只给脉络。**

| 版本 | 核心 |
|---|---|
| 1.0.0 | 首个可发布版本：订阅 + 优选管线跑通 |
| 1.0.1 | 稳定性与 DNS |
| 1.0.2 | 连续可用性 |
| 1.2.0 | TUN 一键启用 + 评审发现的安全底座 |
| 1.2.2 | TUN 完整实现 |
| 1.3.0 | 常驻服务（一次授权不再需要授权） |
| 1.3.1 | 不把自己搞断网、两种接管互斥、TUN 不让人干等 |
| 1.4.0 | **常驻服务真正能装**（`hInst`）、**启动 22 秒 → 0.9 秒**、**节点死活改用真实流量**、池验证、端口不再轮换 |
| 1.4.1 | **DNS 不被自己掐死**（`#PROXY`）、**时钟偏差的排查方法**、未来时间戳不阻塞调度、`alpn` 不丢 |

**1.4.0 和 1.4.1 是信息量最大的两个版本**，因为它们记录了最多的"症状指向错误方向"的案例。

---

## 14. 环境依赖（这台机器上）

| 项 | 值 |
|---|---|
| 项目目录 | `D:\Zenith` |
| Go | `D:\AI\tools\go\bin\go.exe`（1.24.5） |
| 桌面快捷方式 | `C:\Users\<用户>\Desktop\Zenith.lnk` → `D:\Zenith\Zenith.exe` |
| 服务名 | `ZenithService`（`AUTO_START`，LocalSystem） |
| 服务 binPath | `"D:\Zenith\Zenith.exe" -service -root "D:\Zenith" -datadir "D:\Zenith\data"` |
| 同机其他代理 | `D:\Flclash`（**注意 §7.4 陷阱 3**） |
| 系统时间 | 曾经偏差 15 小时（已修，`w32time` 已设自动） |

**这些都是"当前这台机器"的状态，不是项目需求。搬到别的机器要重新确认。**

---

## 15. 最后

**这个项目最大的特点不是功能，是"每个决定都有实测依据"。**

`CHANGELOG.md` 里写的不是"修了个 bug"，而是"为什么坏、怎么证明、为什么这么修"，
**包括哪里想错了**。`regression_test.go` 里的测试是按"曾经坏过的东西"组织的，
注释里带着当时的数字。

**请保持这个习惯。**一个新功能少写点没关系，但**一个判断如果没实测，就别写成断言**——
因为在这个项目里，**症状指向错误方向是常态，不是例外**。

---

*本报告由开发过程整理，所有数字均来自该机器上的实测记录。*
