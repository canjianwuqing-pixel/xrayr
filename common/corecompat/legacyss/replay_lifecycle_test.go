package shadowsocks

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

func ephemeralPassword() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func TestLegacyReplayAccountLifecycle(t *testing.T) {
	raw := &Account{CipherType: CipherType_XCHACHA20_POLY1305, Password: ephemeralPassword(), IvCheck: true}
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
	if _, err = rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	if err = a.(*MemoryAccount).CheckIV(iv); err != nil {
		t.Fatal(err)
	}
	if err = a.(*MemoryAccount).CheckIV(iv); err != ErrIVNotUnique {
		t.Fatal("replay accepted", err)
	}
	if err = v.Del(u.Email); err != nil {
		t.Fatal(err)
	}
	if err = v.Add(u); err != nil {
		t.Fatal(err)
	}
	if err = v.GetByEmail(u.Email).Account.(*MemoryAccount).CheckIV(iv); err != ErrIVNotUnique {
		t.Fatal("same account forgot history", err)
	}
	// Preserve the original account-local scope. Rebuilding a distinct account is
	// not a claim of cross-rebuild, cross-node or persistent replay history.
	rebuilt, err := raw.AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	if err = rebuilt.(*MemoryAccount).CheckIV(iv); err != nil {
		t.Fatal("accounts unexpectedly share history", err)
	}
}

func TestLegacyPlainHasNoSalt(t *testing.T) {
	a, err := (&Account{CipherType: CipherType_NONE, Password: ephemeralPassword(), IvCheck: true}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	account := a.(*MemoryAccount)
	for range 3 {
		if err = account.CheckIV(nil); err != nil {
			t.Fatal(err)
		}
	}
	if account.replayFilter != nil {
		t.Fatal("zero-IV cipher allocated a filter")
	}
	v := new(Validator)
	if err = v.Add(&protocol.MemoryUser{Account: a}); err != nil {
		t.Fatal(err)
	}
	if err = v.Add(&protocol.MemoryUser{Account: a}); err == nil {
		t.Fatal("plain multi-user restriction removed")
	}
}
