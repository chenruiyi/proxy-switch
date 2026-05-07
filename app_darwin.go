//go:build darwin

package main

import (
	"errors"

	"ProxySwitch/internal/errs"
	"ProxySwitch/internal/macauth"
)

// SubmitSudoPassword validates the password by running a no-op sudo command.
// If valid, it's cached for the rest of the session.
func (a *App) SubmitSudoPassword(pw string) error {
	if err := macauth.SetAndValidate(pw); err != nil {
		return errors.New(errs.Friendly(err))
	}
	return nil
}

// HasSudoPassword reports whether a password is currently cached.
func (a *App) HasSudoPassword() bool {
	return macauth.HasPassword()
}
