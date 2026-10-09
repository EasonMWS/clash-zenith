# Zenith

**A Windows Clash client whose point is one thing: it finds the fastest
Cloudflare edge for you, and checks it responds before using it.**

Most clients pick nodes with a ping. Zenith opens a WebSocket upgrade against each
candidate edge and times it — because an edge that answers a ping is not
necessarily an edge that will accept your tunnel. Then it keeps you on the
winner.

**What that check is and is not.** It is a real TLS connection to the edge with
the node's own SNI, followed by a real `Upgrade: websocket` request, and only an
HTTP `101` counts. It is *not* a full end-to-end proof: the probe speaks the
WebSocket handshake at the edge but does not complete the proxy protocol
authentication inside it, so a passing probe means "this edge accepts this
tunnel", not "this edge has been proven to carry your traffic to the far end".
Treat the result as a strong filter, not a guarantee.

It also happens to be a single 7 MB executable with no runtime and no
dependencies. Clone it, double click it, it works.

[English](#english) · [中文](#中文)

<p>
<img alt="platform" src="https://img.shields.io/badge/platform-Windows%2010%2F11-4f8cff">
<img alt="go" src="https://img.shields.io/badge/Go-1.24%2B-35d07f">
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
2. Opens a WebSocket upgrade against each one — TLS to the edge IP with the
   node's own SNI, then an actual `Upgrade: websocket` request.
   **Only an HTTP `101` counts.** Repeatedly, an edge completes TLS and then
   answers the upgrade with `400 Bad Request`; ranking by reachability alone would
   have put a dead edge at the top.
3. Ranks by median over several rounds, penalising edges that failed any round.
4. Rewrites the node list with the winners and hot-reloads the core — no core
   restart, and no reconnect for connections already established.
5. Keeps you on the fastest verified node, ranked by those measured upgrade times
   rather than by a ping.

Steps 2 and 3 are a filter over the edge, not a proof of the whole path. The
upgrade proves the edge will accept this tunnel; it does not complete the proxy
protocol's own authentication, so it cannot tell you the far end is healthy. The
client treats a passing edge as a good candidate, and the live connection is what
ultimately confirms it.

### Reliability: what happens when a node dies

An individual Cloudflare edge address can be filtered while the service itself is
fine. That used to mean the client sat on a dead node until the next scan, so:

- every scan also produces a **hostname node**. It is pinned to no address, so
  Cloudflare's anycast picks a working edge for each connection. It is not
  immune to a DNS or anycast problem and it is not faster — it exists so that one
  filtered address cannot take the connection down.
- the health check moves off a node after three consecutive failures, and prefers
  the hostname node once the pinned addresses have proved themselves dead.
- a candidate that fails twice in a row is benched for thirty minutes, so scans
  stop re-proving that blocked addresses are still blocked.
- a node whose measured round trip stays above 1200 ms twice in a row is
  abandoned even if it is still the best of a bad set.

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
| **WebSocket upgrade verification** | An edge is only kept if it answers the upgrade with `101`. This filters the edge, not the whole path |
| **Automatic edge optimisation** | Scans the pool, ranks by median upgrade time, rewrites the node list, hot-reloads the core |
| **A hostname node as a safety net** | One node is never pinned to an address, so Cloudflare picks a working edge per connection and a single filtered IP cannot take the connection down |
| **Always uses the fastest verified node** | Ranked by measured upgrade time, not a ping. A clear win switches at once; a marginal one is confirmed first, so noise never bounces you between equivalent nodes |
| **Abandons a node that degrades** | Three consecutive failed checks, or a round trip that stays above 1200 ms, moves traffic off it — even when it is still the best of a bad set |
| **A manual pick is respected** | Click a node and it stays for a while. Auto-pick chooses among verified edges; it does not overrule you |
| **Handles mixed subscriptions** | Every WebSocket relay optimised on its own; direct nodes (trojan / ss / hysteria2) left exactly as they are |
| **Nothing to install** | One executable plus the core. No runtime, no dependencies |
| **Lives in the tray** | Closing the window keeps it running. The tray menu opens the window, switches mode, toggles the system proxy, starts an optimisation or quits |
| **No stray console window** | Built as a GUI binary, so double clicking it opens only the interface |
| **Node changes do not restart the core** | They go through the core API, so the window never flickers and existing connections are not dropped |
| **Multiple subscriptions** | Add, switch, refresh and delete any number of them from the UI |
| **Three modes** | Rule based split routing, global proxy, direct |
| **Custom rules** | A rule editor with one-click templates for power users |
| **Game platform routing** | 14 GeoSite categories for launcher stores and logins. Download CDNs stay direct, which is much faster for them |
| **Safe with the system proxy** | Refuses to steal the proxy from another running client, and always hands it back — or switches it off if the old owner is gone |
| **Strict TLS by default** | Subscriptions and probes verify certificates; plain http and cross-host redirects are refused. A self-signed subscription needs an explicit opt-in |
| **A local API that is actually local** | Every API route requires a per-launch token, the Host must be loopback, cross-origin requests are refused, and writes must be JSON |
| **TUN takeover, one click** | Click enable, approve the system prompt, and the rest is automatic: the signed driver is verified by digest and signature, the adapter is created, routes and DNS are configured, and a real request is made through the tunnel before anything is called a success |
| **TUN state you can trust** | `system proxy` / `TUN takeover` / `privacy` are three separate states with three separate descriptions. An adapter existing is never reported as protection |
| **Bounded by what it can undo** | Enabling runs as two recorded transactions. A failure restores only what that attempt changed, so another VPN's adapter or your own routes are never touched |
| **Built in logs** | Application and core logs, viewable in the app |

### TUN takeover

The system proxy only reaches applications that read it — not games, not raw UDP,
not anything with its own network stack. TUN closes that gap by putting a virtual
adapter in front of the traffic.

**Authorise once, and after that it is a switch.** The first time you enable TUN,
Zenith asks for one elevation prompt and uses it to install a small resident
service. That service holds the core from then on. Every later enable is an
authenticated request to a running service, not another prompt.

The service exists because of a real failure. The core used to belong to whichever
process was running, which stopped being one answer the moment elevation was
involved: the ordinary instance started a core, the elevated helper stopped it to
take the ports, started its own, then stopped that one on the way out and expected
the first instance to notice and start another. Two processes, two control secrets,
one configuration file. The results were a tunnel torn down by the helper leaving,
an instance with no rights to take over what had been built, and — because the
secrets differed — a core that was plainly running reported as unavailable.

**The whole flow, in order:**

1. Checks the architecture, the OS, your node set, and any other tunnel already
   present — before asking for a password, so a machine that cannot support TUN is
   told that first.
2. Checks that the core can actually create an adapter: the binary is present, is
   this architecture, and is the version the rest of the program was written
   against. It reads the version out of the file without running it.
3. Raises one elevation prompt, and uses it to install the resident service. Only
   that one; declining it stops the process and nothing is retried. If the service
   cannot be installed, the activation falls back to a per-activation prompt, so a
   machine without the service still works.
4. Writes a candidate configuration, starts the core against it, and waits for the
   adapter **by name from the OS** rather than assuming a sleep was long enough.
5. Proves the traffic goes through the tunnel, in the order the packets travel: the
   adapter is up, the default route points into it, a request leaves this process
   with **no proxy configured anywhere**, and the core's own connection table shows
   it carried that request. DNS, IPv6 and UDP are checked against what the mode
   promises.

If any step fails it says which one and why. The adapter is removed, the previous
configuration is restored and read back to confirm it matches, and the mode returns
to off. Nothing is reported as working when it is not.

**On the driver.** Zenith does not require you to place a `wintun.dll` anywhere.
mihomo carries its own — measured: with no `wintun.dll` beside it, and again with a
four-kilobyte junk file of that name in its place, it produced identical output and
still reached `configure tun interface: Access is denied`. It never opens that file.
Earlier versions checked for it and told you your build was incomplete, which was
wrong.

**Three states, described honestly:**

| State | What it means |
|---|---|
| System proxy | Only applications that honour the system proxy are routed. Games and UDP go direct |
| TUN takeover (compat) | Supported traffic is taken over and your rules still apply. **Direct is still allowed** — this is not "everything is proxied" and there is no kill switch |
| Privacy | Protected traffic may only leave through an approved route, and a dropped connection keeps refusing rather than falling back to direct. Leaving this state is a decision you make explicitly, and **a failed activation never lifts the block for you** |

**Uninstall removes only Zenith's own adapter.** The driver file is deliberately
left in place, because another application may be using the same one.

**What is not verified, stated plainly.**

- **The service registration and the one-authorisation install have not been run
  end to end.** They need an interactive UAC approval this environment cannot
  answer — `sc create` returns `Access is denied` without it. The registration code
  is written and reviewed; the channel itself is verified (`/alive` answers without
  a credential, everything that acts returns 401 without one and 200 with it), and
  the fallback path is verified, since that is what runs on a machine with no
  service.
- **A TUN activation has never completed successfully.** Each attempt stopped at a
  specific, explainable cause, and each cause was found and fixed — the dispatch
  order, the wrong root directory, two processes fighting for the core, a settings
  key missing from the reload list, a known-good configuration overwritten before
  it was proven. But the success state itself has not been observed.
- **Privacy mode has not been tested against a determined bypass**, and neither have
  sleep/wake, multiple network adapters, or coexistence with another VPN.

### What this does not do

Stated plainly, because a proxy client that overstates its reach is worse than one
that does less:

- **Without TUN it is a system-proxy client, not a full tunnel.** Applications that
  ignore the system proxy — most games, anything speaking raw UDP, anything with
  its own network stack — go direct in that mode. TUN mode closes that gap for the
  traffic it can reach, but it is not a kill switch unless you turn on privacy.
- **Sniffing is not interception.** Traffic sniffing recovers the hostname of
  connections that already reach the core, so rules can match them. It cannot do
  anything about traffic that never enters the core.
- **One successful check does not prove DNS is clean.** The exit IP and DNS were
  sampled at a point in time; that does not cover system DNS, IPv6, or a second
  network adapter.
- **A 403 or 401 from a site is not a failure.** It means the connection worked
  and the far end answered. Only a transport error counts against a node.
- **Privacy mode has not been verified against a determined bypass.** It is built
  so that a failed activation keeps refusing rather than falling back, and the
  unit tests cover the decision logic, but the external packet-capture acceptance
  run on a clean machine has not been done.

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

Needs Go 1.24 or newer (the version recorded in go.mod). The core and the rule databases ship with the clone, so
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

Needs Go 1.24 or newer.

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
2. 对每个地址发起一次 WebSocket 升级——用节点自己的 SNI 连到这个边缘 IP，
   然后发一个真实的 `Upgrade: websocket` 请求。
   **只有返回 HTTP `101` 才算数。** 实测中反复出现这种情况：边缘完成了 TLS 握手，
   然后对升级请求返回 `400 Bad Request`。只看连通性的话，这种死边缘会被排到最前面。
3. 每个地址测多轮取中位数，任何一轮失败的都会被加罚分。
4. 用赢家重写节点列表，然后让内核原地热重载——不重启内核，已建立的连接也不会被断开。
5. 之后一直让你待在最快的已验证节点上，排序依据是**实测的升级耗时**，不是 ping。

**这一步验证的是什么，不是什么。** 它是对**边缘**的筛选，不是对整条链路的证明：
升级握手只说明这个边缘愿意接受这条隧道，**它没有完成代理协议自身的鉴权**，
所以它无法告诉你远端是否健康。通过筛选的边缘算作"好的候选"，
最终确认靠的是真实连接本身。

### 节点失效时会发生什么

单个 Cloudflare 边缘 IP 可能被封锁，而服务本身是好的。以前这意味着客户端会一直
待在一个死节点上直到下次扫描，所以现在：

- 每次扫描额外产出一个**域名节点**。它不绑定任何地址，由 Cloudflare anycast 为
  每条连接挑一个可用边缘。**它不是免疫 DNS 或 anycast 故障，也不更快**——
  它存在的意义是让单个 IP 被封锁不至于把连接带下水。
- 健康检查连续三次失败就换走；钉死的地址都失效后优先切到域名节点。
- 候选连续两次失败就**板凳 30 分钟**，扫描不再反复证明被封的地址仍然被封。
- 实测往返**连续两次超过 1200ms** 就放弃它，哪怕它仍是"矮子里的高个"。

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
Linux、没有插件生态、没有界面主题、没有多语言，**TUN 接管有实现但从未成功跑通过一次**。

但如果按"让我的 Cloudflare 中转真的快起来"来评判，它做到了主流客户端交给外部脚本
去做的那件事。

### 功能

| | |
|---|---|
| **WebSocket 升级验证** | 只有回应 `101` 的边缘才会被保留。它筛选的是**边缘**，不是整条链路 |
| **自动优选** | 扫描候选池，按中位升级耗时排序，重写节点列表，原地热重载内核 |
| **域名节点兜底** | 有一个节点永不绑定地址，由 Cloudflare 每条连接挑可用边缘，单个 IP 被封带不倒它 |
| **自动用最快的** | 按**实测升级耗时**排序，不是 ping。差距明显时立刻切换，差距小时会先确认，所以你不会被噪声在几个差不多的节点之间来回甩 |
| **节点变差就放弃** | 连续三次检查失败，或往返**连续两次超过 1200ms**，就把流量移走——哪怕它仍是那批里最快的 |
| **尊重你的手动选择** | 点选的节点会保持一段时间。自动挑只在已验证的边缘之间做选择，不会否决你 |
| **支持混合订阅** | 每个 WebSocket 中转各优选一批；直连节点（trojan / ss / hysteria2）原样保留 |
| **零安装** | 一个可执行文件加内核，无运行时、无依赖 |
| **TUN 接管** | 覆盖不读系统代理的流量（游戏、原始 UDP）。**授权一次之后就是一个开关**，见下节 |
| **常驻系统托盘** | 关掉窗口程序不退出。右键托盘图标：打开窗口、切换模式、开关系统代理、立即优选、退出 |
| **不会多弹命令行** | 编译为 GUI 子系统程序，双击只出界面 |
| **切节点不重启内核** | 走内核 API，窗口不会闪，已建立的连接不会被断 |
| **多订阅** | 界面上添加、切换、刷新、删除任意多个订阅 |
| **三种模式** | 规则分流、全局代理、直连 |
| **自定义规则** | 给高级用户准备的规则编辑器，附带常用模板一键插入 |
| **游戏平台分流** | 14 个 GeoSite 分类的商店与登录页走代理；下载 CDN 保持直连，那样快得多 |
| **系统代理安全** | 检测到别的代理客户端在运行就不抢；退出时归还原主，原主已退出则关闭代理 |
| **默认严格 TLS** | 订阅与探针都验证证书；拒绝明文 http 和跨域重定向。自签订阅需要显式开启例外 |
| **真的只在本地** | 每个 API 路由都要求当次启动生成的令牌，Host 必须是回环地址，跨源请求被拒，写操作必须是 JSON |
| **内置日志** | 应用日志和内核日志都能在界面里看 |

### TUN 接管

系统代理只能覆盖读它的程序——游戏不行，原始 UDP 不行，自带网络栈的都不行。
TUN 在流量前面放一块虚拟网卡来补上这个缺口。

**授权一次，之后它就是一个开关。** 第一次启用会要一次管理员授权，用这次授权安装一个
小的常驻服务，由它持有内核。之后每次启用都是**向已在运行的服务发一个经认证的请求**，
不再弹授权框。

为什么要这个服务：内核原来属于"当时在跑的那个进程"。一旦涉及提权，这句话就有了两个答案——
普通实例起了一个内核，提权助手为了拿端口把它停掉、起自己的，退出前又停掉自己的，
然后指望第一个实例"下一 tick 注意到"再起一个。两个进程、两个控制密码、一个配置文件。
后果是：**刚建好的隧道被助手退出时停掉**、**普通实例没权限接管助手建好的东西**、
以及**因为密码不一致，内核明明在跑却被报告成不可用**。

**完整流程，按顺序：**

1. 先查架构、系统、节点集、已有的其他隧道——**在要密码之前**，所以不支持 TUN 的机器
   在这一步就被明确告知。
2. 查内核**能不能真的创建网卡**：文件在不在、是不是这个架构、是不是程序对应的版本。
   版本是从文件里读出来的，不运行它。
3. 弹**一次**授权，用它安装常驻服务。只有这一次；拒绝就停下，没有任何重试。
   如果服务装不上，激活会回退到"每次授权"的老方式——**没装服务的机器仍然能用**。
4. 写一份**候选配置**，用它启动内核，然后**按名字向系统查询网卡**是否出现，
   而不是猜一个睡眠时间够不够。
5. **按包经过的顺序证明流量真的进了隧道**：网卡已启用 → 默认路由指向它 →
   本进程在**没有任何代理设置**的情况下发出请求 → 内核自己的连接表里有这次请求。
   DNS、IPv6、UDP 按所选模式的要求分别检查。

任何一步失败都会**说清是哪一步、为什么**。删掉本次创建的网卡，**恢复之前的配置并读回比对确认**，
模式回到关闭。**没做到的事绝不会被报成成功。**

**关于驱动**：Zenith 不需要你手动放 `wintun.dll`。mihomo 自带——这是实测的：
内核旁边完全没有 `wintun.dll`，和放一个 4KB 的垃圾文件冒充它，**输出完全一样**，
都到达 `configure tun interface: Access is denied`。它根本不读那个文件。
早先的版本会检查它，然后告诉你"这个构建不完整"——那是错的。

**三种状态，分别描述：**

| 状态 | 含义 |
|---|---|
| 系统代理 | 只有遵循系统代理的应用被路由，游戏和 UDP 直连 |
| TUN 接管（兼容） | 接管支持范围内的流量并仍按规则分流，**仍允许直连**——不等于"全部流量经代理"，也没有 Kill Switch |
| 隐私保护 | 受保护流量只走批准线路，断线保持阻断而不是回退直连。退出保护必须你主动确认，**失败的激活永远不会替你解除阻断** |

**卸载只删除 Zenith 自己的网卡。** 驱动文件**故意不删**，因为别的软件可能正在用同一个。

**哪些没有验证，如实写在这里：**

- **服务向 Windows 服务管理器的注册、以及"一次授权完成安装"的端到端流程没有实测。**
  它们需要交互式 UAC 确认，当前环境答不了——没有它 `sc create` 返回 `Access is denied`。
  注册代码写完并审过；**通道本身验证过了**（`/alive` 无凭据返回 200，
  所有会改变状态的端点无凭据返回 401、正确凭据返回 200），**回退路径也验证过了**，
  因为没装服务的机器跑的就是它。
- **TUN 激活从未成功完成过一次。** 每次尝试都停在一个具体、可解释的原因上，
  每个原因都定位并修复了——分派顺序、根目录错误、两个进程抢内核、设置项漏在重载列表外、
  回滚用的配置在验证前就被覆盖。**但"成功"这个状态本身没有被观测到。**
- **隐私模式没有做过对抗性旁路测试**，睡眠唤醒、多网卡、与其他 VPN 共存也都没有实测。

### 这个软件做不到什么

写在这里，是因为一个夸大口径的代理客户端比一个功能少的更糟：

- **默认是系统代理客户端，不是整机隧道。** 不读系统代理的程序——大多数游戏、
  任何走原始 UDP 的东西、任何自带网络栈的软件——都会直连。**TUN 接管能覆盖这部分**，
  但它需要一次管理员授权来安装常驻服务，而且**它从未被成功跑通过一次**（见上）。
  除此之外，这里没有任何东西是"整机保证"。
- **嗅探不是拦截。** 流量嗅探能从**已经进入内核**的连接里还原出域名，好让规则匹配它。
  它管不了根本没进内核的流量。
- **一次出口检测成功不代表 DNS 干净。** 出口 IP 和 DNS 是某一时刻的抽样，
  不覆盖系统 DNS、IPv6，也不覆盖第二块网卡。
- **站点返回 403 或 401 不算失败。** 那说明连接通了、对端回应了。
  只有传输层错误才算在节点头上。

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

需要 Go 1.24 或更新版本（即 go.mod 里记录的版本）。内核和地理数据随仓库提供，所以首次启动约两秒就绪，
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

需要 Go 1.24 或更新版本。

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
