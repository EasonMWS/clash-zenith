# Zenith

A small, self-contained Clash client for Windows. Clone it, double click it, it
works — there is nothing to install.

[English](#english) · [中文](#中文)

---

## English

### What it is

Zenith is a personal desktop proxy client built around the
[mihomo](https://github.com/MetaCubeX/mihomo) core. It bundles its own runtime,
its own core and its own UI, so it has no prerequisites: no Python, no Node, no
.NET, no browser extension.

### Why another client

Most clients reload their configuration by restarting. That means every node
change costs a restart — a window that flickers, connections that drop, a
tray icon that blinks. Zenith drives the core through its REST API instead, so
**switching a node never restarts anything**.

It also handles one specific annoyance: Cloudflare-fronted nodes. Cloudflare is
anycast, so the same edge IP can land in a different data centre from one hour to
the next, and a node that measured 500 ms this morning can measure 4 seconds this
evening. Zenith keeps a pool of candidate edge addresses, fires a real WebSocket
upgrade at each one (only a `101` proves the edge can actually tunnel the node's
traffic), ranks them by median latency and rewrites the node list with the
winners. The core hot-reloads that config in place.

### Features

| | |
|---|---|
| **Nothing to install** | One executable plus the core. No runtime, no dependencies |
| **Multiple subscriptions** | Add, switch, refresh and delete any number of them from the UI |
| **Automatic edge optimisation** | Scans a candidate pool, verifies each edge with a real WebSocket handshake, keeps the fastest N |
| **Manual / automatic control** | One switch. On: Zenith keeps picking the fastest node. Off: it never touches your choice |
| **Three modes** | Rule based split routing, global proxy, direct |
| **Custom rules** | An advanced editor for your own routing rules, plus one-click templates |
| **No surprise restarts** | Node changes go through the core API; the window never flickers |
| **Safe with the system proxy** | Refuses to steal the proxy from another running client, and always hands it back — or switches it off if the old owner is gone |
| **Built in logs** | Application and core logs, viewable in the app |

### Quick start

1. Download or clone this repository.
2. Double click `Zenith.exe`.
3. Open 订阅 (Subscriptions), paste your subscription URL, press 添加.
4. Press 立即优选 (Optimise now) once. It takes a couple of minutes on the first
   run and then runs on a schedule.

That is all. The window can be closed at any time — closing it stops the proxy
and restores your system settings.

### Command line

```
Zenith.exe                 open the window
Zenith.exe -headless       backend only, no window
Zenith.exe -browser        open the UI in your normal browser
Zenith.exe -stop           stop a running instance and exit
Zenith.exe -port 7800      use a different UI port
Zenith.exe -version        print the version
```

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

### 这是什么

Zenith 是一个自用的 Windows 代理客户端，内核是
[mihomo](https://github.com/MetaCubeX/mihomo)。它自带运行时、自带内核、自带界面，
所以**没有任何前置依赖**——不需要 Python、Node、.NET，也不需要装浏览器插件。

### 为什么又写一个

多数客户端靠重启来加载新配置。于是每换一次节点就要重启一次：窗口闪一下、
连接断掉、托盘图标跳一下。Zenith 改用内核的 REST API，**切换节点不会重启任何东西**。

它还专门解决一个烦人的问题：走 Cloudflare 的节点。CF 是 Anycast，同一个边缘 IP
在不同时段可能被调度到不同机房，早上测 500ms 的节点晚上可能变成 4 秒。Zenith
维护一个候选边缘地址池，对每个地址发**真实的 WebSocket 升级请求**（只有返回 `101`
才证明这个边缘真的能转发节点流量），按中位延迟排序，把最快的若干個写进节点列表，
然后让内核原地热重载。

### 功能

| | |
|---|---|
| **零安装** | 一个可执行文件加内核，无运行时、无依赖 |
| **多订阅** | 界面上添加、切换、刷新、删除任意多个订阅 |
| **自动优选** | 扫描候选池，用真实 WebSocket 握手验证每个边缘，保留最快的若干个 |
| **手动 / 自动开关** | 一个开关。打开时它自动挑最快的；关闭后它绝不碰你的选择 |
| **三种模式** | 规则分流、全局代理、直连 |
| **自定义规则** | 给高级用户准备的规则编辑器，附带常用模板一键插入 |
| **不惊扰** | 切节点走内核 API，窗口不会闪 |
| **系统代理安全** | 检测到别的代理客户端在运行就不抢；退出时归还原主，原主已退出则关闭代理 |
| **内置日志** | 应用日志和内核日志都能在界面里看 |

### 快速开始

1. 下载或克隆本仓库。
2. 双击 `Zenith.exe`。
3. 打开「订阅」页，粘贴订阅地址，按「添加」。
4. 按一次「立即优选」。首次需要一两分钟，之后会按计划自动运行。

就这样。窗口随时可以关闭——关掉它就停止代理并还原系统设置。

### 命令行

```
Zenith.exe                 打开窗口
Zenith.exe -headless       只跑后端，不开窗口
Zenith.exe -browser        用默认浏览器打开界面
Zenith.exe -stop           停止正在运行的实例
Zenith.exe -port 7800      换个界面端口
Zenith.exe -version        显示版本
```

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
