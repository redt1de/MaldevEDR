package util

import (
	"os"
)

func FileExists(fpath string) bool {
	if _, err := os.Stat(fpath); err == nil {
		return true
	}
	return false
}

func FileReadable(fpath string) bool {
	f, err := os.Stat(fpath)
	if err != nil {
		return false
	}
	if f.Mode().Perm()&0444 == 0444 {
		return true
	}
	return false
}
