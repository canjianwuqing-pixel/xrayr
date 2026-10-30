package shadowsocks_2022

import (
	"syscall"
	"testing"
	"unsafe"
)

func openResourceCount(t *testing.T) (string, int) {
	t.Helper()
	handle, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	var count uint32
	result, _, err := syscall.NewLazyDLL("kernel32.dll").NewProc("GetProcessHandleCount").Call(uintptr(handle), uintptr(unsafe.Pointer(&count)))
	if result == 0 {
		t.Fatal(err)
	}
	return "Windows handles", int(count)
}
