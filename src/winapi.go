package main

// ---------------------------------------------------------------------------
// Windows specifics the TUN feature needs, kept in one place so the rest of the
// code can be read as policy rather than as syscalls.
// ---------------------------------------------------------------------------

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// runtimeGOARCH is captured once so the manifest check reads as data rather than
// as a build constant scattered through the logic.
var runtimeGOARCH = runtime.GOARCH

// ---- elevation ------------------------------------------------------------

// shellExecuteRunas launches a program through the shell's "runas" verb, which is
// what raises the UAC prompt. It returns as soon as the child starts; the child
// signals its own result through the API.
func shellExecuteRunas(exe string, args []string, cwd string) error {
	verbPtr, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	exePtr, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	// Parameters are a single command line string.
	quoted := make([]string, 0, len(args))
	for _, a := range args {
		if strings.ContainsAny(a, " \t\"") {
			quoted = append(quoted, `"`+strings.ReplaceAll(a, `"`, `\"`)+`"`)
		} else {
			quoted = append(quoted, a)
		}
	}
	paramsPtr, err := syscall.UTF16PtrFromString(strings.Join(quoted, " "))
	if err != nil {
		return err
	}
	var cwdPtr *uint16
	if cwd != "" {
		if p, err := syscall.UTF16PtrFromString(cwd); err == nil {
			cwdPtr = p
		}
	}
	shell32 := syscall.NewLazyDLL("shell32.dll")
	shellExecuteW := shell32.NewProc("ShellExecuteW")
	// SW_SHOWNORMAL = 1
	ret, _, _ := shellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(paramsPtr)),
		uintptr(unsafe.Pointer(cwdPtr)),
		1,
	)
	// ShellExecuteW returns a value <= 32 on failure; 5 specifically means the
	// user declined the elevation prompt.
	if ret <= 32 {
		if ret == 5 {
			return errUserDeclined
		}
		return fmt.Errorf("ShellExecuteW 返回 %d", ret)
	}
	return nil
}

// errUserDeclined marks the one elevation failure that must never be retried:
// the user said no.
var errUserDeclined = fmt.Errorf("user declined elevation")

func isUserCancel(err error) bool {
	return err == errUserDeclined || strings.Contains(err.Error(), "declined")
}

// ---- adapters -------------------------------------------------------------

// adapterDescriptions lists the description of every network adapter, obtained
// from the OS rather than from a guessed name.
func adapterDescriptions() []string {
	out, err := HiddenCommand("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InterfaceDescription")
	if err != nil {
		return nil
	}
	var res []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			res = append(res, line)
		}
	}
	return res
}

// tunAdapterExists reports whether Zenith's own adapter is present, matched by
// the name Zenith gave it rather than by a generic pattern, so another product's
// adapter is never mistaken for ours.
func tunAdapterExists(name string) bool {
	out, err := HiddenCommand("powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name", name))
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) != ""
}

// removeTunAdapter deletes exactly one adapter, by name, and refuses if that name
// is not Zenith's. It exists so uninstall and rollback cannot remove a network
// interface belonging to anything else.
func removeTunAdapter(name string) error {
	if name == "" || name != defaultTunDevice {
		return fmt.Errorf("拒绝删除非 Zenith 自己的网卡（%q）", name)
	}
	if !tunAdapterExists(name) {
		return nil
	}
	if _, err := HiddenCommand("powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("Remove-NetAdapter -Name '%s' -Confirm:$false -ErrorAction Stop", name)); err != nil {
		return err
	}
	return nil
}

// ---- system proxy ownership ----------------------------------------------

// systemProxyOwner names the program the current system proxy setting appears to
// belong to, based on which process is listening on that port. It answers "is
// this ours", which is what every recovery path keys off.
func systemProxyOwner(stateDir string) string {
	st := NewSystemProxy(stateDir).Status()
	if !st.Enabled || st.Server == "" {
		return ""
	}
	port := portFromServer(st.Server)
	if port == 0 {
		return ""
	}
	return ownerOfPort(port)
}

// ownerOfPort maps a listening port to a process name.
func ownerOfPort(port int) string {
	pids := ListeningPids(port)
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		if name := processNameOf(pid); name != "" {
			return name
		}
	}
	return ""
}

func processNameOf(pid int) string {
	return ProcessName(pid)
}

// ---- signature ------------------------------------------------------------

// authenticodeSigner reports who signed a file, using the OS verifier rather than
// a hand-rolled parser. A file whose digest matches but whose signature cannot be
// confirmed is reported as such rather than silently accepted.
func authenticodeSigner(path string) (string, bool) {
	// Get-AuthenticodeSignature is part of Windows and consults the same trust
	// machinery the loader does.
	out, err := HiddenCommand("powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("$s = Get-AuthenticodeSignature -LiteralPath '%s'; "+
			"if ($s.Status -eq 'Valid') { $s.SignerCertificate.Subject } else { '' }",
			strings.ReplaceAll(path, "'", "''")))
	if err != nil {
		return "", false
	}
	subj := strings.TrimSpace(out)
	if subj == "" {
		return "", false
	}
	// Keep the meaningful part; the full DN is long and mostly boilerplate.
	if i := strings.Index(subj, ","); i > 0 {
		subj = subj[:i]
	}
	return subj, true
}

// ---- verification request -------------------------------------------------

// httpThroughProxy makes one real HTTP request through the local proxy port and
// reports whether a real HTTP response came back.
//
// The point is to test the path, not the target: any status line at all means the
// request left through the tunnel and something answered, which is exactly the
// claim being verified. A connection error means it did not, and that is a failure
// however healthy the adapter looks.
func httpThroughProxy(port int, target string, timeout time.Duration) error {
	if port <= 0 {
		return fmt.Errorf("代理端口无效")
	}
	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			DisableKeepAlives: true,
		},
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Zenith-verify/"+AppVersion)
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Any status proves the tunnel carried it; 4xx and 5xx are still answers.
	return nil
}

// ---- misc -----------------------------------------------------------------

// windowsBuild returns a readable Windows version string.
func windowsBuild() string {
	out, err := HiddenCommand("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"[System.Environment]::OSVersion.Version.ToString()")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// copyToHash streams a file into a hash. Streaming matters: the core binary is
// 58 MB and the component check runs on every enable attempt.
func copyToHash(h io.Writer, f *os.File) (int64, error) {
	buf := make([]byte, 256*1024)
	var total int64
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if _, werr := h.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}
