package runtimepath

import (
	"os"
	"path/filepath"
)

// Resolve returns the original path when it is empty, absolute, or already
// exists in the current working directory. Otherwise it also checks beside the
// running executable and returns that candidate when present.
func Resolve(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}

	if _, err := os.Stat(path); err == nil {
		return path
	}

	exePath, err := os.Executable()
	if err != nil {
		return path
	}

	exeDir := filepath.Dir(exePath)
	candidate := filepath.Join(exeDir, path)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}

	return path
}
