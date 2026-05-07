//go:build windows

package main

// On Windows the process is launched with requireAdministrator manifest, so
// no in-app password flow is needed. These methods exist purely so the Wails
// binding surface stays identical between platforms.

func (a *App) SubmitSudoPassword(_ string) error {
	return nil
}

func (a *App) HasSudoPassword() bool {
	return true
}
