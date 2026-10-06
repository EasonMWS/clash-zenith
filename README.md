# Zenith

**A Windows Clash client whose point is one thing: it finds the fastest
Cloudflare edge for you, and proves it works before using it.**

Most clients pick nodes with a ping. Zenith opens a real WebSocket tunnel to each
candidate edge and times the handshake — because an edge that answers a ping is
not necessarily an edge that will carry your traffic. Then it keeps you on the
winner.

It also happens to be a single 7 MB executable with no runtime and no
dependencies. Clone it, double click it, it works.

[English](#english) · [中文](#中文)

<p>
<img alt="platform" src="https://img.shields.io/badge/platform-Windows%2010%2F11-4f8cff">
<img alt="go" src="https://img.shields.io/badge/Go-1.21%2B-35d07f">
<img alt="deps" src="https://img.shields.io/badge/dependencies-none-35d07f">
<img alt="license" src="https://img.shields.io/badge/license-GPL--3.0-ffb020">
</p>

---

## English

### The problem, precisely

Cloudflare is anycast. The same edge IP can land in a different data centre from
one hour to the next, so a node measuring 500 ms this morning can measure 4
seconds this evening. On top of that, the address your provider hands out is
whatever the local DNS resolver returns — rarely the best one available to you.

The usual fixes fall short in one specific way:

- **The core's own `url-test` group** sends an HTTP 204 probe. That answers
  "does this node respond", not "how fast does this tunnel carry data".
- **Community scripts** that pull a preferred-IP list only test TCP or TLS
  reachability. An edge can complete a TLS handshake and still refuse to carry
  your WebSocket upgrade.
- **Both** operate on the whole node list, so a subscription that mixes a relay
  with direct Singapore / Japan / US nodes gets treated as if every node were
  interchangeable.

### What Zenith does instead

1. Builds a candidate pool of Cloudflare edge addresses (256 to start; every IP
   it verifies gets appended, so the pool sharpens with use).
2. Opens a **real WebSocket tunnel** to each one — TLS to the edge IP with the
   node's own SNI, then an actual `Upgrade: websocket` request.
   **Only an HTTP `101` counts.** Repeatedly, an edge completes TLS and then
   answers the upgrade with `400 Bad Request`; ranking by reachability would have
   put a dead edge at the top.
3. Ranks by median over several rounds, penalising edges that failed any round.
4. Rewrites the node list with the winners and hot-reloads the core — no restart,
   no dropped connections.
5. Keeps you on the fastest verified node, ranked by those measured handshake
   times rather than by a ping.

### Why the ping is not good enough (measured, not asserted)

On a real run with the same node set:

| Selection method | Node it chose | Its time |
|---|---|---|
| Core `url-test` (HTTP 204 probe) | `优选06 · 103.21.244.250` | **247 ms** |
| Zenith (real WebSocket handshake) | `优选01 · 104.19.160.1` | **231 ms** |

The core picked the slower node. Not because its measurement was imprecise, but
because it was measuring the wrong thing — and this is the whole reason Zenith
exists.

On the same scan: **121 of 256 candidate edges passed the WebSocket probe.** The
other 135 either refused the upgrade or never completed it. A tool that ranked by
ping would have had no way to tell those apart.

### Compared with the usual approach

| | Community preferred-IP script | Zenith |
|---|---|---|
| What is measured | TCP / TLS reachability | Real WebSocket upgrade (needs `101`) |
| Wrong edges filtered out | No | Yes — 135 of 256 rejected |
| Runs | Manually, or on a cron you wire up | Built in, on a schedule |
| Survives a subscription refresh | No, the update overwrites it | Yes, it owns the generated config |
| Mixed relay + direct subscriptions | Treated uniformly | Each WebSocket relay optimised separately; direct nodes untouched |
| Setup | Write a script, find an IP source | Press one button |

### Honest about scope

This is not "a better Clash client". It is a Windows client built around solving
one problem properly. Judged as a general client it is a one-person project
against [clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev)
(149k stars) and [FlClash](https://github.com/chen08209/FlClash) (54k stars): no
macOS or Linux, no TUN mode, no plugin ecosystem, no test suite.

Judged as "make my Cloudflare relay actually fast", it does something the
mainstream clients leave to external scripts.

### Features

| | |
|---|---|
| **Real WebSocket verification** | An edge is only used if it completes the upgrade |
| **Automatic edge optimisation** | Scans the pool, ranks by median handshake time, rewrites the node list, hot-reloads |
| **Always uses the fastest verified node** | Ranked by measured handshake time, not a ping. A clear win switches at once; a marginal one is confirmed first, so noise never bounces you between equivalent nodes |
| **A manual pick is respected** | Click a node and it stays for a while. Auto-pick chooses among verified edges; it does not overrule you |
| **Handles mixed subscriptions** | Every WebSocket relay optimised on its own; direct nodes (trojan / ss / hysteria2) left exactly as they are |
| **Nothing to install** | One executable plus the core. No runtime, no dependencies |
| **Lives in the tray** | Closing the window keeps it running. The tray menu opens the window, switches mode, toggles the system proxy, starts an optimisation or quits |
| **No stray console window** | Built as a GUI binary, so double clicking it opens only the interface |
| **No surprise restarts** | Node changes go through the core API; the window never flickers |
| **Multiple subscriptions** | Add, switch, refresh and delete any number of them from the UI |
| **Three modes** | Rule based split routing, global proxy, direct |
| **Custom rules** | A rule editor with one-click templates for power users |
| **Safe with the system proxy** | Refuses to steal the proxy from another running client, and always hands it back — or switches it off if the old owner is gone |
| **Built in logs** | Application and core logs, viewable in the app |

### Quick start

**Option A — download the ready binary (nothing else needed)**

Take `Zenith-windows-amd64.zip` from the Releases page, unzip it anywhere and
double click `Zenith.exe`. The proxy core and the rule databases are inside.

**Option B — clone and build**

```powershell
git clone <this repository> Zenith
cd Zenith
.\build.ps1
.\Zenith.exe
```

Needs Go 1.21 or newer. The core and the rule databases ship with the clone, so
the first launch is ready in about two seconds with no download.

Then, either way:

1. Double click `Zenith.exe`.
2. Open 订阅 (Subscriptions), paste your subscription URL, press 添加.
3. Zenith optimises automatically on a schedule. Press 立即优选 (Optimise now)
   the first time if you want it done immediately — it takes a couple of minutes,
   and the progress bar shows which candidate it is on.

That is all. Closing the window keeps Zenith in the tray so the proxy stays up;
quit from the tray menu when you actually want it gone.

### Command line

```
Zenith.exe                 open the window
Zenith.exe -headless       backend only, no window
Zenith.exe -browser        open the UI in your normal browser
Zenith.exe -no-proxy       run without touching the system proxy
Zenith.exe -stop           stop a running instance and exit
Zenith.exe -port 7800      use a different UI port
Zenith.exe -version        print the version
```

`-no-proxy` exists because two instances on different UI ports would otherwise
both try to own the system proxy, and whichever started last would silently
take it.

### How it is put together

```
Zenith.exe            the whole application: window, API, optimiser
core/mihomo.exe       the proxy core (MetaCubeX/mihomo)
web/                  the interface (HTML/CSS/JS, no build step)
src/                  the Go source
data/                 your settings, subscriptions and generated config
logs/                 zenith.log and engine.log
```

The Go program owns everything: it generates `data/config.yaml`, starts the core,
serves the UI on `127.0.0.1:7799`, and exposes a small JSON API that the UI talks
to. Everything is bound to loopback, so nothing is reachable from your network.

### Build from source

Needs Go 1.21 or newer.

```powershell
.\build.ps1
```

The script compiles `src/` into `Zenith.exe` in the repository root.

### Configuration

Settings live in `data/state.json` and can be edited from the app. Ports
default to mixed `7890`, core API `7798`, UI `7799`, core control `7797`.

### Troubleshooting

| Symptom | What to do |
|---|---|
| Window opens but everything says disconnected | Check `logs/zenith.log`; the core may still be unpacking geodata on a first run |
| No nodes after adding a subscription | The subscription may be expired; open 订阅 and press 更新 to see the error |
| Every node times out | Refresh the subscription first. If it still fails, the provider's backend is down — that is not something an IP change can fix |
| System proxy was not taken over | Another proxy client is running. That is deliberate: Zenith will not cut you off from the client you are using |

### License and intent

GPL-3.0. See [LICENSE](LICENSE).

The bundled core is [mihomo](https://github.com/MetaCubeX/mihomo), also GPL-3.0.

**This project is a personal tool and the author does not welcome commercial
reskinning.** The GPL does permit commercial use, so this is a request rather
than a restriction — but note that the GPL also requires anyone distributing a
modified version to publish its source under the same terms, which makes
slapping a new name on it and selling it rather pointless.

---

## 中文

**一个把一件事做到底的 Windows Clash 客户端：自动找到最快的 Cloudflare
边缘节点，并且在用之前先验证它真的能用。**

多数客户端用 ping 挑节点。Zenith 会对每一个候选边缘**真的建立一条 WebSocket
隧道并计时握手**——因为**能 ping 通的边缘，不一定是愿意转发你流量的边缘**。
挑出赢家之后，它会一直让你待在赢家上。

顺带它还是一个 7MB 单文件、零依赖的可执行程序，克隆下来双击就能跑。

### 问题到底出在哪

Cloudflare 是 Anycast。同一个边缘 IP 在不同时段可能被调度到不同机房，早上测
500ms 的节点晚上可能变成 4 秒。而且机场给你的那个地址是**你本地 DNS 解析出来的
结果**，往往不是你能用到的最好的那个。

常见的两种解法各有一个具体的短板：

- **内核自带的 `url-test` 组**：发 HTTP 204 探测。它回答的是"这个节点有没有响应"，
  不是"这条隧道转发数据有多快"。
- **社区脚本**拉一份优选 IP 列表：只测 TCP 或 TLS 连通性。**一个边缘可以完成 TLS
  握手，然后拒绝转发你的 WebSocket 升级请求**。
- **两者都是**对整个节点列表统一处理，所以一个"中转 + 新加坡/日本/美国直连"混合的
  订阅会被当成所有节点都可以互换。

### Zenith 怎么做

1. 建一个 Cloudflare 边缘地址候选池（初始 256 个；之后**每验证通过一个就追加进池子**，
   所以池子越用越准）。
2. 对每个地址**真的开一条 WebSocket 隧道**——用节点自己的 SNI 连到这个边缘 IP，
   然后发一个真实的 `Upgrade: websocket` 请求。
   **只有返回 HTTP `101` 才算数。** 实测中反复出现这种情况：边缘完成了 TLS 握手，
   然后对升级请求返回 `400 Bad Request`。按"连通性"排序的话，这种死边缘会被排到最前面。
3. 每个地址测多轮取中位数，任何一轮失败的都会被加罚分。
4. 用赢家重写节点列表，然后让内核原地热重载——不重启，不断连接。
5. 之后一直让你待在最快的已验证节点上，排序依据是**实测的握手时间**，不是 ping。

### 为什么 ping 不够用（这是实测的，不是推断）

同一批节点上实测对比：

| 挑选方式 | 选中了谁 | 它的耗时 |
|---|---|---|
| 内核 `url-test`（HTTP 204 探测） | `优选06 · 103.21.244.250` | **247 ms** |
| Zenith（真实 WebSocket 握手） | `优选01 · 104.19.160.1` | **231 ms** |

**内核挑中了更慢的那个。** 不是因为它的测量不准，而是因为它测的东西不对——
这就是 Zenith 存在的全部理由。

同一次扫描里：**256 个候选边缘中有 121 个通过了 WebSocket 探测。** 另外 135 个要么
拒绝了升级请求，要么根本没完成。一个按 ping 排序的工具没有办法区分这两类。

### 和常见做法对比

| | 社区优选 IP 脚本 | Zenith |
|---|---|---|
| 测的是什么 | TCP / TLS 连通性 | **真实 WebSocket 升级（必须返回 `101`）** |
| 能不能滤掉假可用边缘 | 不能 | 能——256 个里滤掉了 135 个 |
| 怎么跑 | 手动，或自己配定时任务 | 内置，按计划自动跑 |
| 订阅刷新后还在吗 | 不在，更新会覆盖掉 | 在，生成的配置由它掌管 |
| 混合订阅（中转 + 直连） | 统一处理 | 每个 WebSocket 中转各优选一批，直连节点不动 |
| 上手成本 | 写脚本、找 IP 源 | 按一个按钮 |

### 关于定位，说实话

这**不是"一个更好的 Clash 客户端"**。它是一个围绕"把一件事做对"构建的 Windows
客户端。如果按通用客户端来评判，它是一个人对着
[clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev)（14.9 万星）和
[FlClash](https://github.com/chen08209/FlClash)（5.4 万星）写的项目：没有 macOS 和
Linux、没有 TUN 模式、没有插件生态、没有测试。

但如果按"让我的 Cloudflare 中转真的快起来"来评判，它做到了主流客户端交给外部脚本
去做的那件事。

### 功能

| | |
|---|---|
| **真实 WebSocket 验证** | 只有完成升级握手的边缘才会被使用 |
| **自动优选** | 扫描候选池，按中位握手时间排序，重写节点列表，原地热重载 |
| **自动用最快的** | 按**实测握手时间**排序，不是 ping。差距明显时立刻切换，差距小时会先确认，所以你不会被噪声在几个差不多的节点之间来回甩 |
| **尊重你的手动选择** | 点选的节点会保持一段时间。自动挑只在已验证的边缘之间做选择，不会否决你 |
| **支持混合订阅** | 每个 WebSocket 中转各优选一批；直连节点（trojan / ss / hysteria2）原样保留 |
| **零安装** | 一个可执行文件加内核，无运行时、无依赖 |
| **常驻系统托盘** | 关掉窗口程序不退出。右键托盘图标：打开窗口、切换模式、开关系统代理、立即优选、退出 |
| **不会多弹命令行** | 编译为 GUI 子系统程序，双击只出界面 |
| **不惊扰** | 切节点走内核 API，窗口不会闪 |
| **多订阅** | 界面上添加、切换、刷新、删除任意多个订阅 |
| **三种模式** | 规则分流、全局代理、直连 |
| **自定义规则** | 给高级用户准备的规则编辑器，附带常用模板一键插入 |
| **系统代理安全** | 检测到别的代理客户端在运行就不抢；退出时归还原主，原主已退出则关闭代理 |
| **内置日志** | 应用日志和内核日志都能在界面里看 |

### 快速开始

**方式 A — 直接下载现成的（什么都不用装）**

从 Releases 页面下载 `Zenith-windows-amd64.zip`，解压到任意位置，双击
`Zenith.exe`。内核和地理数据都在压缩包里。

**方式 B — 克隆自己编译**

```powershell
git clone <本仓库> Zenith
cd Zenith
.\build.ps1
.\Zenith.exe
```

需要 Go 1.21 或更新版本。内核和地理数据随仓库提供，所以首次启动约两秒就绪，
不需要下载任何东西。

然后两种方式都一样：

1. 双击 `Zenith.exe`。
2. 打开「订阅」页，粘贴订阅地址，按「添加」。
3. 优选会按计划自动跑。想立刻看到效果就按一次「立即优选」——首次要一两分钟，
   进度条会显示正在测第几个候选地址。

就这样。**关掉窗口程序会留在托盘**，代理不会断；真想关掉的时候从托盘菜单退出。

### 命令行

```
Zenith.exe                 打开窗口
Zenith.exe -headless       只跑后端，不开窗口
Zenith.exe -browser        用默认浏览器打开界面
Zenith.exe -no-proxy       运行但不碰系统代理
Zenith.exe -stop           停止正在运行的实例
Zenith.exe -port 7800      换个界面端口
Zenith.exe -version        显示版本
```

`-no-proxy` 是为这种情况准备的：两个实例用不同界面端口跑时，都会去抢系统代理，
后启动的那个会悄悄把它拿走。

### 目录结构

```
Zenith.exe            整个程序：窗口、API、优选引擎
core/mihomo.exe       代理内核（MetaCubeX/mihomo）
web/                  界面（HTML/CSS/JS，无需构建）
src/                  Go 源码
data/                 你的设置、订阅与生成的配置
logs/                 zenith.log 与 engine.log
```

Go 程序掌管一切：生成 `data/config.yaml`、启动内核、在 `127.0.0.1:7799` 提供界面，
并暴露一套小的 JSON API 给界面调用。所有服务都绑定在回环地址，局域网访问不到。

### 从源码构建

需要 Go 1.21 或更新版本。

```powershell
.\build.ps1
```

脚本会把 `src/` 编译成仓库根目录下的 `Zenith.exe`。

### 排障

| 现象 | 处理 |
|---|---|
| 窗口能开但显示与后端失联 | 看 `logs/zenith.log`；首次运行时内核可能还在解压地理数据 |
| 添加订阅后没有节点 | 订阅可能过期了；在「订阅」页按「更新」看具体错误 |
| 所有节点都超时 | 先刷新订阅。仍然失败说明机场后端挂了，这不是换 IP 能解决的 |
| 系统代理没被接管 | 检测到别的代理客户端在运行。这是故意的：Zenith 不会把你正在用的客户端顶掉 |

### 许可与态度

GPL-3.0，见 [LICENSE](LICENSE)。

内置内核 [mihomo](https://github.com/MetaCubeX/mihomo) 同样是 GPL-3.0。

**本项目是自用工具，作者不欢迎任何形式的套壳商业化。** GPL 本身允许商用，所以这
只是一个请求而非法律限制——但请注意 GPL 同时要求任何分发修改版的人以相同条款公开
源码，这让"改个名字拿去卖"这件事变得没什么意义。
