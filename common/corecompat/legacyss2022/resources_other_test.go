//go:build !windows && !linux

package shadowsocks_2022

import "testing"

func openResourceCount(t *testing.T) (string, int) {
	t.Skip("resource count implemented for Windows/Linux")
	return "", 0
}
