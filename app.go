package main

import (
	"context"
	"errors"
	goruntime "runtime"
	"strings"
	"sync"

	wailsrt "github.com/wailsapp/wails/v2/pkg/runtime"

	"ProxySwitch/internal/errs"
	"ProxySwitch/internal/proxy"
)

const defaultProxyIP = "10.0.0.232"

// App is the Wails-bound application object. All exported methods are exposed
// to the frontend.
type App struct {
	ctx       context.Context
	mu        sync.Mutex
	proxyIP   string
	on        bool
	switching bool
}

func NewApp() *App {
	return &App{proxyIP: defaultProxyIP}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	// Async residual detection — running this synchronously would delay first
	// paint by ~100ms (PowerShell startup on Windows).
	go func() {
		if proxy.DetectResidual(a.proxyIP) {
			a.mu.Lock()
			a.on = true
			a.mu.Unlock()
			wailsrt.EventsEmit(ctx, "state:residual")
		}
	}()
}

// beforeClose returns true to prevent close, false to allow.
func (a *App) beforeClose(ctx context.Context) bool {
	a.mu.Lock()
	on := a.on
	a.mu.Unlock()
	if !on {
		return false
	}
	if err := proxy.Restore(); err == nil {
		return false
	} else {
		sel, _ := wailsrt.MessageDialog(ctx, wailsrt.MessageDialogOptions{
			Type:          wailsrt.QuestionDialog,
			Title:         "禁用代理失败",
			Message:       errs.Friendly(err) + "\n\n网卡可能仍处于代理状态。是否仍然退出?",
			Buttons:       []string{"强制退出", "留下手动处理"},
			DefaultButton: "留下手动处理",
		})
		if sel == "留下手动处理" {
			return true
		}
		return false
	}
}

// Toggle flips between proxy-on and proxy-off based on current state.
// On macOS, returns an error whose message equals "NEED_PASSWORD" when no
// sudo password has been cached yet — the frontend should then show its
// password modal and call SubmitSudoPassword before retrying.
func (a *App) Toggle() error {
	a.mu.Lock()
	if a.switching {
		a.mu.Unlock()
		return errors.New("操作进行中,请稍候")
	}
	a.switching = true
	on := a.on
	proxyIP := a.proxyIP
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		a.switching = false
		a.mu.Unlock()
	}()

	var err error
	if on {
		err = proxy.Restore()
	} else {
		err = proxy.Switch(proxyIP)
	}
	if err != nil {
		if errors.Is(err, errs.ErrNeedPassword) {
			return errors.New("NEED_PASSWORD")
		}
		return errors.New(errs.Friendly(err))
	}

	a.mu.Lock()
	a.on = !on
	a.mu.Unlock()
	return nil
}

func (a *App) GetState() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.on
}

func (a *App) GetProxyIP() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.proxyIP
}

// UpdateProxyIP changes the in-memory proxy IP. Only allowed while proxy is
// off — changing it mid-flight would leave the NIC pointing at the old IP
// with no way to detect or undo it.
func (a *App) UpdateProxyIP(ip string) error {
	if !isValidIPv4(ip) {
		return errors.New("IP 格式不正确")
	}
	a.mu.Lock()
	if a.on {
		a.mu.Unlock()
		return errors.New("请先关闭代理后再修改 IP")
	}
	a.proxyIP = ip
	a.mu.Unlock()
	return nil
}

// IsMacOS lets the frontend decide whether to show the password modal flow.
func (a *App) IsMacOS() bool {
	return goruntime.GOOS == "darwin"
}

// Quit asks the runtime to exit (triggers beforeClose).
func (a *App) Quit() {
	wailsrt.Quit(a.ctx)
}

func isValidIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}
