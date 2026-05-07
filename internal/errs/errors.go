package errs

import (
	"errors"
	"strings"
)

var (
	ErrNoActiveNIC   = errors.New("未检测到活跃网卡")
	ErrCannotGetIP   = errors.New("无法获取当前 IP 地址")
	ErrBadPassword   = errors.New("管理员密码错误,请重试")
	ErrNeedElevation = errors.New("权限不足,请以管理员身份运行")
	ErrNeedPassword  = errors.New("NEED_PASSWORD")
)

// Friendly maps a raw error (often from netsh / networksetup stderr) into a
// Chinese, non-truncated message. Unknown errors are returned verbatim with a
// "操作失败" prefix so the user still sees the full text instead of a stub.
func Friendly(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrNeedPassword) {
		return "NEED_PASSWORD"
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	switch {
	case errors.Is(err, ErrNoActiveNIC), strings.Contains(msg, "未检测到活跃网卡"), strings.Contains(lower, "no active"):
		return ErrNoActiveNIC.Error()
	case errors.Is(err, ErrCannotGetIP), strings.Contains(msg, "无法获取"), strings.Contains(lower, "cannot get ip"):
		return ErrCannotGetIP.Error()
	case errors.Is(err, ErrBadPassword), strings.Contains(lower, "incorrect password"), strings.Contains(lower, "sorry, try again"):
		return ErrBadPassword.Error()
	case errors.Is(err, ErrNeedElevation), strings.Contains(lower, "requires elevation"), strings.Contains(lower, "access is denied"):
		return ErrNeedElevation.Error()
	}
	return "操作失败:" + msg
}
