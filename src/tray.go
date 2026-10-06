package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Windows tray icon, implemented directly on Shell_NotifyIcon.
//
// No external dependency: the shell API is small enough to bind by hand, and
// this keeps the "clone it and it builds" promise intact.
//
// The icon needs a real window to receive its callback messages, so a tiny
// message-only window is created on a locked OS thread that then runs the
// message pump for the whole process. All UI work is dispatched from there.
// ---------------------------------------------------------------------------

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procRegisterClassExW  = user32.NewProc("RegisterClassExW")
	procCreateWindowExW   = user32.NewProc("CreateWindowExW")
	procDefWindowProcW    = user32.NewProc("DefWindowProcW")
	procDestroyWindow     = user32.NewProc("DestroyWindow")
	procGetMessageW       = user32.NewProc("GetMessageW")
	procTranslateMessage  = user32.NewProc("TranslateMessage")
	procDispatchMessageW  = user32.NewProc("DispatchMessageW")
	procPostMessageW      = user32.NewProc("PostMessageW")
	procPostQuitMessage   = user32.NewProc("PostQuitMessage")
	procCreatePopupMenu   = user32.NewProc("CreatePopupMenu")
	procAppendMenuW       = user32.NewProc("AppendMenuW")
	procDestroyMenu       = user32.NewProc("DestroyMenu")
	procTrackPopupMenu    = user32.NewProc("TrackPopupMenu")
	procSetForegroundWnd  = user32.NewProc("SetForegroundWindow")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procLoadImageW       = user32.NewProc("LoadImageW")
	procDestroyIcon      = user32.NewProc("DestroyIcon")
	procSendMessageW     = user32.NewProc("SendMessageW")
	procMessageBoxW      = user32.NewProc("MessageBoxW")
	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	procShellNotifyIconW = shell32.NewProc("Shell_NotifyIconW")
	procSetProcessDpiCtx = user32.NewProc("SetProcessDpiAwarenessContext")
)

const (
	wmDestroy     = 0x0002
	wmClose       = 0x0010
	wmCommand     = 0x0111
	wmRButtonUp   = 0x0205
	wmLButtonUp   = 0x0202
	wmTrayMessage = 0x0400 + 1 // WM_APP + 1

	nimAdd    = 0x00000000
	nimModify = 0x00000001
	nimDelete = 0x00000002
	nifMsg    = 0x00000001
	nifIcon   = 0x00000002
	nifTip    = 0x00000004

	mfString    = 0x00000000
	mfSeparator = 0x00000800
	mfGrayed    = 0x00000001
	mfChecked   = 0x00000008

	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100

	imageIcon      = 1
	lrLoadFromFile = 0x00000010
	lrDefaultSize  = 0x00000040

	hwndMessage = ^uintptr(2) // HWND_MESSAGE, a message only window

	idiApplication = 32512
)

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra   int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type notifyIconData struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         [16]byte
	hBalloonIcon     uintptr
}

type point struct{ x, y int32 }

type msgW struct {
	hwnd     uintptr
	message  uint32
	wParam   uintptr
	lParam   uintptr
	time     uint32
	pt       point
	lPrivate uint32
}

// utf16z converts a Go string to a NUL terminated UTF-16 buffer.
//
// syscall.StringToUTF16 panics on an embedded NUL by design, and the strings
// that reach here come from node names and error messages - provider supplied
// text that can contain anything. A panic would take the whole application
// down, so the conversion is done by hand and any interior NUL is dropped.
func utf16z(s string, size int) []uint16 {
	buf := make([]uint16, size)
	n := 0
	for _, r := range s {
		if r == 0 {
			continue
		}
		if n >= size-1 {
			break
		}
		// encode as UTF-16, possibly two units
		if r > 0xFFFF {
			r -= 0x10000
			buf[n] = uint16(0xD800 + (r >> 10))
			n++
			if n >= size-1 {
				break
			}
			buf[n] = uint16(0xDC00 + (r & 0x3FF))
			n++
			continue
		}
		buf[n] = uint16(r)
		n++
	}
	buf[n] = 0
	return buf
}

// messageBoxText converts a title/text pair safely for the Win32 calls.
func messageBoxText(title, text string) (uintptr, uintptr) {
	t := append(utf16zRaw(title), 0)
	x := append(utf16zRaw(text), 0)
	return uintptr(unsafe.Pointer(&t[0])), uintptr(unsafe.Pointer(&x[0]))
}

// utf16zRaw encodes a string as UTF-16 units with no terminator, dropping any
// interior NUL. Callers append the terminator themselves.
func utf16zRaw(s string) []uint16 {
	out := make([]uint16, 0, len(s)+1)
	for _, r := range s {
		if r == 0 {
			continue
		}
		if r > 0xFFFF {
			r -= 0x10000
			out = append(out, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
			continue
		}
		out = append(out, uint16(r))
	}
	return out
}

// menuItem is one row of the tray context menu.
type menuItem struct {
	id       int
	label    string
	separate bool
	checked  bool
	disabled bool
}

// Tray owns the icon, its menu and the message pump.
type Tray struct {
	mu       sync.Mutex
	hwnd     uintptr
	icon     uintptr
	added    bool
	tip      string
	handlers map[int]func()

	// queried whenever the menu is about to open, so the check marks and
	// labels always reflect the live state
	menu func() []menuItem

	ready  chan struct{}
	closed chan struct{}
}

func NewTray() *Tray {
	return &Tray{
		handlers: map[int]func(){},
		ready:    make(chan struct{}),
		closed:   make(chan struct{}),
	}
}

// On registers the action for a menu id.
func (t *Tray) On(id int, fn func()) {
	t.mu.Lock()
	t.handlers[id] = fn
	t.mu.Unlock()
}

// SetMenu installs the function that builds the context menu on demand.
func (t *Tray) SetMenu(fn func() []menuItem) {
	t.mu.Lock()
	t.menu = fn
	t.mu.Unlock()
}

// Run creates the message window, adds the icon and pumps messages until Stop.
// It blocks, so it belongs in its own goroutine; the internals pin themselves to
// one OS thread because a window belongs to the thread that created it.
func (t *Tray) Run(iconPath, tip string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hInst, _, _ := procGetModuleHandleW.Call(0)

	clsName := append(utf16zRaw("ZenithTrayWnd"), 0)
	wc := wndClassExW{
		cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		lpfnWndProc:   syscall.NewCallback(t.wndProc),
		hInstance:     hInst,
		lpszClassName: &clsName[0],
	}
	if atom, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); atom == 0 {
		return fmt.Errorf("RegisterClassExW failed: %v", err)
	}
	Log("tray: window class registered")

	hwnd, _, err := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(&clsName[0])), 0, 0,
		0, 0, 0, 0, hwndMessage, 0, hInst, 0)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW failed: %v", err)
	}
	Log("tray: message window created (hwnd=%d)", hwnd)
	t.mu.Lock()
	t.hwnd = hwnd
	t.tip = tip
	t.mu.Unlock()

	if err := t.loadIcon(iconPath); err != nil {
		// a missing icon file must not stop the tray from working
		Log("tray: %v; falling back to the default application icon", err, "WARN")
	} else {
		Log("tray: icon loaded")
	}
	if err := t.add(); err != nil {
		return err
	}
	Log("tray: icon added to the notification area")
	close(t.ready)

	var m msgW
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	t.remove()
	close(t.closed)
	return nil
}

// Ready returns a channel closed once the icon is on screen.
func (t *Tray) Ready() <-chan struct{} { return t.ready }

// Stop removes the icon and ends the message loop.
func (t *Tray) Stop() {
	t.mu.Lock()
	hwnd := t.hwnd
	t.mu.Unlock()
	if hwnd != 0 {
		procPostMessageW.Call(hwnd, wmClose, 0, 0)
	}
}

// Notify shows a balloon tip, used for short status messages.
func (t *Tray) Notify(title, text string) {
	t.mu.Lock()
	hwnd, added := t.hwnd, t.added
	t.mu.Unlock()
	if hwnd == 0 || !added {
		return
	}
	var nid notifyIconData
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = hwnd
	nid.uID = 1
	nid.uFlags = 0x00000010 // NIF_INFO
	copy(nid.szInfoTitle[:], utf16z(title, len(nid.szInfoTitle)))
	copy(nid.szInfo[:], utf16z(text, len(nid.szInfo)))
	nid.dwInfoFlags = 0x00000001 // NIIF_INFO
	procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
}

// SetTip updates the hover text.
func (t *Tray) SetTip(text string) {
	t.mu.Lock()
	t.tip = text
	hwnd, added := t.hwnd, t.added
	t.mu.Unlock()
	if hwnd == 0 || !added {
		return
	}
	var nid notifyIconData
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = hwnd
	nid.uID = 1
	nid.uFlags = nifTip
	copy(nid.szTip[:], utf16z(text, len(nid.szTip)))
	procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
}

func (t *Tray) loadIcon(path string) error {
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			p := append(utf16zRaw(path), 0)
			h, _, _ := procLoadImageW.Call(0, uintptr(unsafe.Pointer(&p[0])), imageIcon,
				0, 0, lrLoadFromFile|lrDefaultSize)
			if h != 0 {
				t.mu.Lock()
				t.icon = h
				t.mu.Unlock()
				return nil
			}
		}
	}
	h, _, _ := procLoadImageW.Call(0, idiApplication, imageIcon, 0, 0, lrDefaultSize)
	t.mu.Lock()
	t.icon = h
	t.mu.Unlock()
	return fmt.Errorf("could not load %s", filepath.Base(path))
}

func (t *Tray) add() error {
	t.mu.Lock()
	nid := notifyIconData{
		cbSize:           uint32(unsafe.Sizeof(notifyIconData{})),
		hWnd:             t.hwnd,
		uID:              1,
		uFlags:           nifMsg | nifIcon | nifTip,
		uCallbackMessage: wmTrayMessage,
		hIcon:            t.icon,
	}
	copy(nid.szTip[:], utf16z(t.tip, len(nid.szTip)))
	t.mu.Unlock()

	ok, _, err := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
	if ok == 0 {
		return fmt.Errorf("Shell_NotifyIcon(NIM_ADD) failed: %v", err)
	}
	t.mu.Lock()
	t.added = true
	t.mu.Unlock()
	return nil
}

func (t *Tray) remove() {
	t.mu.Lock()
	added, hwnd := t.added, t.hwnd
	t.added = false
	t.mu.Unlock()
	if !added || hwnd == 0 {
		return
	}
	var nid notifyIconData
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = hwnd
	nid.uID = 1
	procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
}

func (t *Tray) wndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmTrayMessage:
		switch uint32(lParam) & 0xFFFF {
		case wmRButtonUp, wmLButtonUp:
			t.showMenu()
		}
		return 0
	case wmCommand:
		id := int(wParam & 0xFFFF)
		t.mu.Lock()
		fn := t.handlers[id]
		t.mu.Unlock()
		if fn != nil {
			// run off the message thread: a handler may open a window or do
			// blocking work, and stalling the pump would freeze the menu
			go fn()
		}
		return 0
	case wmClose:
		procDestroyWindow.Call(hwnd)
		procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}

func (t *Tray) showMenu() {
	t.mu.Lock()
	hwnd := t.hwnd
	build := t.menu
	t.mu.Unlock()
	if hwnd == 0 || build == nil {
		return
	}
	items := build()

	hmenu, _, _ := procCreatePopupMenu.Call()
	if hmenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hmenu)

	for _, it := range items {
		if it.separate {
			procAppendMenuW.Call(hmenu, mfSeparator, 0, 0)
			continue
		}
		flags := uintptr(mfString)
		if it.checked {
			flags |= mfChecked
		}
		if it.disabled {
			flags |= mfGrayed
		}
		labelBuf := append(utf16zRaw(it.label), 0)
		label := uintptr(unsafe.Pointer(&labelBuf[0]))
		procAppendMenuW.Call(hmenu, flags, uintptr(it.id), label)
	}

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))

	// The documented dance: without setting the foreground window first, the
	// menu does not dismiss when the user clicks elsewhere.
	procSetForegroundWnd.Call(hwnd)
	cmd, _, _ := procTrackPopupMenu.Call(hmenu,
		tpmRightButton|tpmReturnCmd, uintptr(pt.x), uintptr(pt.y), 0, hwnd, 0)
	procPostMessageW.Call(hwnd, 0, 0, 0) // WM_NULL, lets the menu close cleanly

	if cmd != 0 {
		t.mu.Lock()
		fn := t.handlers[int(cmd)]
		t.mu.Unlock()
		if fn != nil {
			go fn()
		}
	}
}

// EnableDpiAwareness asks Windows not to bitmap scale the app, which otherwise
// makes the window and the tray icon blurry on a scaled display.
func EnableDpiAwareness() {
	const dpiAwarenessPerMonitorV2 = ^uintptr(3) // -4
	procSetProcessDpiCtx.Call(dpiAwarenessPerMonitorV2)
}

// ---- modal dialogs --------------------------------------------------------

const (
	mbYesNo        = 0x00000004
	mbIconQuestion = 0x00000020
	mbIconInfo     = 0x00000040
	mbSetForeground = 0x00010000
	idYes          = 6
)

func messageBox(title, text string, flags uintptr) int {
	tp, xp := messageBoxText(title, text)
	ret, _, _ := procMessageBoxW.Call(0, xp, tp, flags)
	return int(ret)
}

// Confirm asks a yes/no question and reports whether the user agreed.
func Confirm(title, text string) bool {
	return messageBox(title, text, mbYesNo|mbIconQuestion|mbSetForeground) == idYes
}

// Info shows a short informational dialog.
func Info(title, text string) {
	messageBox(title, text, mbIconInfo|mbSetForeground)
}
