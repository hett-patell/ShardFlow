//go:build integration
// +build integration

// Package netns provides setup/teardown helpers for the integration test
// triangle (lab-gw, lab-vic, lab-op).
package netns

import (
	"os/exec"
	"path/filepath"
	"runtime"
)

// Setup runs setup.sh; must be invoked as root.
func Setup() error {
	_, file, _, _ := runtime.Caller(0)
	return exec.Command(filepath.Join(filepath.Dir(file), "setup.sh")).Run()
}

// Teardown runs teardown.sh.
func Teardown() error {
	_, file, _, _ := runtime.Caller(0)
	return exec.Command(filepath.Join(filepath.Dir(file), "teardown.sh")).Run()
}

// InNS runs a command inside the named netns and returns its combined output.
func InNS(ns string, name string, args ...string) ([]byte, error) {
	full := append([]string{"netns", "exec", ns, name}, args...)
	return exec.Command("ip", full...).CombinedOutput()
}
