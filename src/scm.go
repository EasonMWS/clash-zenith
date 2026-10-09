package main

// ---------------------------------------------------------------------------
// Speaking the Service Control Manager's protocol.
//
// The service was registered with Windows and could never start. The review found
// the reason by reading the source, and it is exact: there was no
// StartServiceCtrlDispatcher, no control handler, no status reporting - the
// `-service` branch simply opened a listening socket and served.
//
// From the SCM's side that is not a service. It starts the process, waits for it to
// connect to the dispatcher, and when it does not, concludes the start failed and
// marks it stopped. Which is what `sc query` said: AUTO_START, and STOPPED, having
// never once run. Confirmed on this machine after a reboot that was supposed to
// start it.
//
// The protocol is small and the standard library has the calls, so this is written
// against syscall rather than pulling in a dependency: the program ships with an
// embedded core and is meant to build offline, and one more module to fetch is one
// more thing that can fail on a clone with no network.
//
// The shape of a correct service, and why each part is load-bearing:
//
//   - connect to the dispatcher within 30 seconds of being started, or be judged
//     failed;
//   - register a handler before doing any work, so a stop request during start-up is
//     not lost;
//   - report START_PENDING with a checkpoint while starting, and advance the
//     checkpoint, so the SCM can tell a slow start from a hung one;
//   - report RUNNING once it is serving;
//   - honour stop, and report STOP_PENDING then STOPPED, because a service that
//     ignores stop is killed with its children.
// ---------------------------------------------------------------------------

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Service control codes the SCM sends.
const (
	svcControlStop     = 0x00000001
	svcControlInterro  = 0x00000004
	svcControlShutdown = 0x00000005
)

// Service state values reported back.
const (
	svcStateStopped      = 0x00000001
	svcStateStartPending = 0x00000002
	svcStateStopPending  = 0x00000003
	svcStateRunning      = 0x00000004
	svcStatePaused       = 0x00000007
)

// Accepted control codes, advertised so the SCM knows what may be asked.
const (
	svcAcceptStop     = 0x00000001
	svcAcceptShutdown = 0x00000004
)

// svcStatus mirrors SERVICE_STATUS. Field order and sizes are the ABI; do not
// reorder.
type svcStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

// svcStatusHandle is the handle RegisterServiceCtrlHandlerEx returns.
type svcStatusHandle syscall.Handle

// scmDispatcher is the shared state between the service body and the handler the
// SCM calls. The handler runs on a thread the SCM owns, so everything it touches is
// guarded.
type scmDispatcher struct {
	mu     sync.Mutex
	handle svcStatusHandle
	// checkpoint advances on every pending report, which is how the SCM tells a
	// slow start from a hung one.
	checkpoint uint32
	stopCh     chan struct{}
	stopOnce   sync.Once
	// state is the last value reported, kept so an interrogate can answer without
	// guessing.
	state uint32
}

func (d *scmDispatcher) report(state uint32, accepted uint32, waitHint uint32) {
	d.mu.Lock()
	if state == svcStateStartPending || state == svcStateStopPending {
		d.checkpoint++
	}
	d.state = state
	cp := d.checkpoint
	h := d.handle
	d.mu.Unlock()
	if h == 0 {
		return
	}
	st := svcStatus{
		ServiceType:      0x00000010, // SERVICE_WIN32_OWN_PROCESS
		CurrentState:     state,
		ControlsAccepted: accepted,
		CheckPoint:       cp,
		WaitHint:         waitHint,
	}
	// The call's return value is the only signal, and there is nothing useful to do
	// with a failure: the SCM will have decided already.
	_, _, _ = procSetServiceStatus.Call(uintptr(h), uintptr(unsafe.Pointer(&st)))
}

// requestStop records that the SCM asked us to stop.
//
// It is safe to call more than once, which matters: a service that panics on a
// repeated stop request is worse than one that ignores it.
func (d *scmDispatcher) requestStop() {
	d.stopOnce.Do(func() { close(d.stopCh) })
}

// Stopped reports the channel the service body waits on.
func (d *scmDispatcher) Stopped() <-chan struct{} { return d.stopCh }

// svcInstance is the one dispatcher for this process.
//
// It reaches the handler through a package variable rather than through the
// handler's lpContext parameter. That parameter arrives as a uintptr, and converting
// it back to a pointer is what go vet refuses - correctly, because the runtime cannot
// track a pointer that Windows holds. One process runs one service, so a single value
// is not a simplification, it is the actual shape of the thing.
var svcInstance *scmDispatcher

var (
	advapi32                 = syscall.NewLazyDLL("advapi32.dll")
	procStartServiceCtrlDisp = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlH = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus     = advapi32.NewProc("SetServiceStatus")
)

// serviceMainCallback is the function pointer the SCM calls on a new thread.
//
// It must not be a Go closure: the address is passed to Windows and called from a
// thread the runtime did not create, so it has to be a real function with a stable
// address. The arguments arrive as a count and a pointer to an array of strings.
var serviceMainCallback = syscall.NewCallback(serviceMainTrampoline)

// svcRunFunc is what the service body does. It is set once before the dispatcher
// starts, because the callback above cannot capture anything.
var (
	svcRunMu   sync.Mutex
	svcRunFunc func(stop <-chan struct{}) error
	svcResult  error
	svcDone    = make(chan struct{})
)

// RunAsService connects to the SCM and runs fn as the service body.
//
// It returns only when the service has stopped, or with an error if the SCM would
// not accept this process as a service - which is what happens when the binary is
// run by hand with -service rather than by the SCM, and is worth reporting plainly
// because that is exactly how it will be tested.
func RunAsService(name string, fn func(stop <-chan struct{}) error) error {
	svcRunMu.Lock()
	svcRunFunc = fn
	svcRunMu.Unlock()

	// SERVICE_TABLE_ENTRYW: a name and a callback, terminated by a zero entry.
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	type tableEntry struct {
		name *uint16
		proc uintptr
	}
	table := []tableEntry{
		{name: namePtr, proc: serviceMainCallback},
		{name: nil, proc: 0},
	}

	ret, _, callErr := procStartServiceCtrlDisp.Call(uintptr(unsafe.Pointer(&table[0])))
	if ret == 0 {
		return fmt.Errorf("无法连接到服务控制管理器：%v。"+
			"这通常意味着这个进程不是由 SCM 启动的——用 -service 直接运行不会成功，"+
			"这是预期行为", callErr)
	}
	<-svcDone
	return svcResult
}

// serviceMainTrampoline is called by Windows on the service's own thread.
//
// It registers the handler, reports the states, runs the body and reports the
// outcome. Everything here is on a thread that is not a goroutine, so it hands the
// actual work to one.
func serviceMainTrampoline(argc uint32, argv **uint16) uintptr {
	d := &scmDispatcher{stopCh: make(chan struct{})}

	svcInstance = d
	h, _, regErr := procRegisterServiceCtrlH.Call(
		uintptr(argc), 0, syscall.NewCallback(serviceCtrlHandler), 0)
	if h == 0 {
		// Nothing can be reported without a status handle; the SCM will time the
		// start out. Set the result so the caller learns why.
		svcRunMu.Lock()
		svcResult = fmt.Errorf("无法注册服务控制处理函数：%v", regErr)
		svcDone <- struct{}{}
		close(svcDone)
		svcRunMu.Unlock()
		return 0
	}
	d.mu.Lock()
	d.handle = svcStatusHandle(h)
	d.mu.Unlock()

	// START_PENDING with a generous wait hint. The SCM will not time the start out
	// while the checkpoint keeps advancing, and a service that reports RUNNING and
	// then takes a minute to answer looks hung rather than slow.
	d.report(svcStateStartPending, 0, 30000)

	svcRunMu.Lock()
	body := svcRunFunc
	svcRunMu.Unlock()

	var runErr error
	bodyDone := make(chan struct{})
	if body != nil {
		go func() {
			defer close(bodyDone)
			defer func() {
				if r := recover(); r != nil {
					runErr = fmt.Errorf("服务主体发生内部错误：%v", r)
				}
			}()
			runErr = body(d.Stopped())
		}()
	} else {
		close(bodyDone)
		runErr = fmt.Errorf("服务主体没有设置")
	}

	// Report RUNNING once the body has had a moment to open its listener, or as soon
	// as it finishes if it finishes first. Reporting RUNNING before the socket is
	// open would mean a client can see the service and fail to reach it.
	select {
	case <-bodyDone:
		// Fell through to the stop path below.
	case <-time.After(400 * time.Millisecond):
		d.report(svcStateRunning, svcAcceptStop|svcAcceptShutdown, 0)
		select {
		case <-bodyDone:
		case <-d.Stopped():
			d.report(svcStateStopPending, svcAcceptStop, 15000)
			select {
			case <-bodyDone:
			case <-time.After(15 * time.Second):
				// The body did not stop in time. Reported rather than waited on
				// forever, because a service that never stops is killed along with
				// anything it started.
			}
		}
	}

	if runErr != nil {
		svcRunMu.Lock()
		svcResult = runErr
		svcRunMu.Unlock()
	}
	d.report(svcStateStopped, 0, 0)
	svcRunMu.Lock()
	close(svcDone)
	svcRunMu.Unlock()
	return 0
}

// serviceCtrlHandler is called by the SCM for control requests.
//
// It must return quickly: it runs on an SCM-owned thread and blocking there stops
// the SCM from delivering anything else. So it records the request and returns; the
// body notices and shuts itself down.
func serviceCtrlHandler(ctrl uint32, eventType uint32, eventData uintptr, context uintptr) uintptr {
	d := svcInstance
	if d == nil {
		return 0
	}
	switch ctrl {
	case svcControlStop, svcControlShutdown:
		d.requestStop()
	case svcControlInterro:
		// Answer with what was last reported rather than a guess, so an interrogate
		// cannot claim a state the service is not in.
		d.mu.Lock()
		st := d.state
		d.mu.Unlock()
		d.report(st, svcAcceptStop, 0)
	}
	return 0
}

// IsRunningAsService reports whether this process was started by the SCM, so the
// -service flag can say which of the two situations it is in rather than failing
// with a generic message.
func IsRunningAsService() bool {
	// A process started by the SCM has a parent of services.exe. Checking the parent
	// is cheaper and more reliable than attempting the connection and interpreting
	// the error.
	pid := os.Getppid()
	if pid <= 0 {
		return false
	}
	out, err := HiddenCommand("powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf(`(Get-CimInstance Win32_Process -Filter "ProcessId=%d" `+
			`-ErrorAction SilentlyContinue).Name`, pid))
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(out), "services.exe")
}
