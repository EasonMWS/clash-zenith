# 参与开发

这个项目是自用工具开源的，欢迎提 Issue 和 PR。下面是要点。

## 环境

- Windows 10 / 11
- Go 1.21 或更新（开发时用的是 1.24.5）
- 不需要 Node、Python、.NET —— 界面是手写的 HTML/CSS/JS，没有构建步骤

## 编译

```powershell
.\build.ps1
```

脚本会编译 `src/` 到根目录的 `Zenith.exe`，并自动检查产物的三个关键属性：是否为 GUI 子系统（否则会多弹一个命令行窗口）、图标资源是否嵌入、体积是否正常。

只想快速验证能编译：

```powershell
cd src
go build -o ..\Zenith.exe .
```

## 代码结构

| 文件 | 职责 |
|---|---|
| `src/main.go` | 启动流程、命令行参数、窗口、托盘菜单 |
| `src/app.go` | 编排层：把 store / core / optimizer / sysproxy 串起来 |
| `src/store.go` | 设置、订阅、节点的 JSON 持久化（原子写） |
| `src/subscription.go` | 订阅抓取、自写的 YAML 子集解析器、各类分享链接 |
| `src/config.go` | 生成 mihomo 的 `config.yaml` |
| `src/core.go` | mihomo 进程管理 + REST API 封装 |
| `src/optimizer.go` | 日志 + 边缘 IP 扫描与优选 |
| `src/sysproxy.go` | 注册表读写与安全判定 |
| `src/tray.go` | Windows 托盘图标（直接绑定 Shell_NotifyIcon，无第三方库） |
| `src/server.go` | 本地 HTTP 服务（API + 静态界面） |
| `web/` | 界面，纯静态 |

更详细的内部说明见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 几条硬性约定

这些不是风格偏好，是踩过坑之后总结出来的，改动时请保持：

1. **不要引入第三方 Go 依赖。** 整个项目只用标准库，这是"克隆下来就能编译"的前提。托盘图标、YAML 解析、图标资源生成全是手写的。
2. **不要用 `syscall.StringToUTF16` / `UTF16PtrFromString` 处理外部字符串。** 它们遇到内含 NUL 的字符串会 panic，而节点名和错误信息来自机场，可能含任意字符。用 `tray.go` 里的 `utf16z` / `utf16zRaw`。
3. **编译必须带 `-H=windowsgui`。** 否则 Windows 会分配控制台窗口，关闭它会通过 `CTRL_CLOSE_EVENT` 直接杀掉进程。
4. **mihomo 配置里，列表项的第一个键要和 `- ` 同行。** 缩进错一格内核就报 `did not find expected '-' indicator`。生成逻辑在 `config.go`，改完请用真实内核验证。
5. **vmess 的 `alterId` 即使是 0 也必须显式写出**，否则内核报 `has unset fields: alterId`。
6. **改系统代理的逻辑要维持四道护栏**（见 ARCHITECTURE）：别人在用就不抢、先快照、退出归还原主、原主没了就关掉。顺序上必须先停内核再还代理。
7. **日志里不要出现订阅地址、UUID、节点密码。** `data/` 整个目录都在 `.gitignore` 里，别把里面的东西挪出来。

## 测试

没有单元测试，验证方式是实跑。改完请至少确认：

```powershell
# 1. 能编译、静态检查通过
cd src; go vet .

# 2. 起得来、内核能连上
.\Zenith.exe -headless -no-proxy -port 7801
# 然后 GET http://127.0.0.1:7801/api/status 看 coreUp 是否为 true

# 3. 改过配置生成的话，把生成的 config.yaml 喂给真实内核验证
.\core\mihomo.exe -d data -f data\config.yaml
# 看有没有 fatal："Parse config error"
```

`-no-proxy` 很重要：它保证测试实例不会去动系统代理。

## 提交 PR

- 一个 PR 做一件事
- 说明你**实际验证了什么**，以及没验证什么
- 界面改动请附截图

## 许可

GPL-3.0。提交即表示同意以相同许可发布。请注意作者不欢迎套壳商业化，详见 README。
