package shadowsocks_2022

import (
	"os"
	"testing"
)

func openResourceCount(t *testing.T) (string, int) {
	t.Helper()
	files, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return "Linux FD", len(files)
}
