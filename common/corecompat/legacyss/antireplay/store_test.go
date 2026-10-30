package antireplay

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
)

func TestLazyReplayLifecycleAndBudget(t *testing.T) {
	s := NewStore(1 << 20)
	a := s.Filter(1, []byte(t.Name()))
	if s.Used() != 0 {
		t.Fatal("idle handle allocated replay history")
	}
	iv := []byte("first IV")
	if err := a.CheckError(iv); err != nil {
		t.Fatal(err)
	}
	if err := s.Filter(1, []byte(t.Name())).CheckError(iv); err != ErrReplay {
		t.Fatal("rebuild forgot IV", err)
	}
	if err := s.Filter(2, []byte(t.Name())).CheckError(iv); err != nil {
		t.Fatal("cipher separation", err)
	}
	for i := 0; i < 1000; i++ {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(i))
		if err := a.CheckError(b[:]); err != nil {
			t.Fatal("promotion", i, err)
		}
	}
	if a.CheckError(iv) != ErrReplay {
		t.Fatal("promotion lost exact history")
	}
	tiny := NewStore(identityCharge + entryCharge)
	f := tiny.Filter(1, []byte("key"))
	if f.CheckError(iv) != nil || f.CheckError([]byte("new")) != ErrBudget {
		t.Fatal("budget did not fail closed")
	}
	if f.CheckError(iv) != ErrReplay {
		t.Fatal("budget evicted history")
	}
}

func TestReplayAtomicConcurrentCheck(t *testing.T) {
	s := NewStore(1 << 20)
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Go(func() {
			if s.Filter(1, []byte(t.Name())).CheckError([]byte("same")) == nil {
				allowed.Add(1)
			}
		})
	}
	wg.Wait()
	if allowed.Load() != 1 {
		t.Fatal("duplicate IV accepted", allowed.Load())
	}
}

func TestReplayRotationPreservesLegacyCapacity(t *testing.T) {
	s := NewStore(8 << 20)
	f := s.Filter(1, []byte(t.Name()))
	// One full original slot (rotation was >100000, not >=100000).
	for i := 0; i <= slotCapacity; i++ {
		var iv [8]byte
		binary.BigEndian.PutUint64(iv[:], uint64(i))
		err := f.CheckError(iv[:])
		if err != nil && err != ErrReplay {
			t.Fatal(err)
		}
	}
	for _, i := range []uint64{0, 255, 256, 99999} {
		var iv [8]byte
		binary.BigEndian.PutUint64(iv[:], i)
		if f.CheckError(iv[:]) != ErrReplay {
			t.Fatal("lost IV before rotation", i)
		}
	}
}
