package shadowsocks

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"github.com/xtls/xray-core/common/protocol"
)

func ephemeralPassword() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func TestReplayDynamicRebuildAndPlain(t *testing.T) {
	p := ephemeralPassword()
	raw := &Account{CipherType: CipherType_XCHACHA20_POLY1305, Password: p, IvCheck: true}
	a, err := raw.AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	v := new(Validator)
	u := &protocol.MemoryUser{Email: "ephemeral", Account: a}
	if err = v.Add(u); err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 32)
	rand.Read(iv)
	if err = a.(*MemoryAccount).CheckIV(iv); err != nil {
		t.Fatal(err)
	}
	if err = v.Del(u.Email); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := raw.AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	if err = rebuilt.(*MemoryAccount).CheckIV(iv); err != ErrIVNotUnique {
		t.Fatal("rebuild reset replay state", err)
	}
	u.Account = rebuilt
	if err = v.Add(u); err != nil {
		t.Fatal(err)
	}
	plain, _ := (&Account{CipherType: CipherType_NONE, Password: ephemeralPassword()}).AsAccount()
	pv := new(Validator)
	if pv.Add(&protocol.MemoryUser{Account: plain}) != nil {
		t.Fatal("plain single user removed")
	}
	if pv.Add(&protocol.MemoryUser{Account: plain}) == nil {
		t.Fatal("plain multiuser restriction changed")
	}
}

// Run each size in a fresh test process; excluded from routine/race workloads.
func TestReplayMemoryScale(t *testing.T) {
	n, err := strconv.Atoi(os.Getenv("KUAIYUN_MEMORY_USERS"))
	if err != nil {
		t.Skip("set KUAIYUN_MEMORY_USERS for isolated memory measurement")
	}
	if n < 1 || n > 2000 {
		t.Fatal("invalid measurement size")
	}
	type sample struct {
		Users        int
		Phase        string
		RSS          uint64
		HeapAlloc    uint64
		HeapSys      uint64
		Mallocs      uint64
		TotalAlloc   uint64
		NumGC        uint32
		PauseTotalNs uint64
		ElapsedNs    int64
	}
	p, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	record := func(phase string) {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		mi, err := p.MemoryInfo()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(sample{n, phase, mi.RSS, m.HeapAlloc, m.HeapSys, m.Mallocs, m.TotalAlloc, m.NumGC, m.PauseTotalNs, time.Since(start).Nanoseconds()})
		t.Log(string(b))
	}
	record("baseline")
	accounts := make([]*MemoryAccount, n)
	for i := range accounts {
		a, err := (&Account{CipherType: CipherType_AES_128_GCM, Password: ephemeralPassword(), IvCheck: true}).AsAccount()
		if err != nil {
			t.Fatal(err)
		}
		accounts[i] = a.(*MemoryAccount)
	}
	record("registered_idle")
	for i, a := range accounts {
		for j := 0; j < 128; j++ {
			var iv [16]byte
			binary.BigEndian.PutUint64(iv[:8], uint64(i))
			binary.BigEndian.PutUint64(iv[8:], uint64(j))
			if err := a.CheckIV(iv[:]); err != nil {
				t.Fatal(err)
			}
		}
	}
	record("128_IV_per_user")
	runtime.KeepAlive(accounts)
}
