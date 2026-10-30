package antireplay

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"sync"
	"sync/atomic"

	"github.com/riobard/go-bloom"
)

const (
	// Preserve the original ten 100,000-entry slots, including its > rotation
	// boundary. Small slots use exact SHA-256 sets before lossless promotion.
	slotCapacity   = 100000
	exactLimit     = 256
	slotCount      = 10
	entryCharge    = 128
	identityCharge = 4096
	bloomCharge    = 359439 + 1024
	DefaultBudget  = 256 << 20
)

var (
	ErrReplay    = errors.New("IV is not unique")
	ErrBudget    = errors.New("SS replay protection memory budget exhausted; IV rejected")
	defaultStore = NewStore(DefaultBudget)
)

type replaySlot struct {
	exact  map[[32]byte]struct{}
	bloom  bloom.Filter
	count  int
	charge int64
}
type replayState struct {
	mu       sync.Mutex
	slots    [slotCount]replaySlot
	position int
}
type replayShard struct {
	sync.Mutex
	states map[[32]byte]*replayState
}

// Store owns only credential digests and replay history, never passwords. It
// deliberately retains retired identities until process exit: deleting a user
// must not let a recreated credential replay old packets. No timer/GC evicts
// security state. Exhaustion fails closed instead of shortening retention.
type Store struct {
	shards [64]replayShard
	used   atomic.Int64
	budget int64
}

func NewStore(budget int64) *Store { return &Store{budget: budget} }
func (s *Store) Used() int64       { return s.used.Load() }
func (s *Store) reserve(n int64) bool {
	for {
		old := s.used.Load()
		if n > s.budget-old {
			return false
		}
		if s.used.CompareAndSwap(old, old+n) {
			return true
		}
	}
}

type Filter struct {
	store    *Store
	identity [32]byte
	base     [32]byte
}

// Namespace separates the local client and server roles without forgetting
// server history across account rebuilds. Loopback relays can use the same key
// on both roles without treating their own outbound packets as inbound replays.
func (f *Filter) Namespace(name string) *Filter {
	b := append(append([]byte(nil), f.base[:]...), []byte(name)...)
	return &Filter{store: f.store, identity: sha256.Sum256(b), base: f.base}
}

// NewFilter allocates only a handle. Cipher and effective key identify the
// credential across node/user object rebuilds; IVs remain isolated by key.
func NewFilter(cipher uint32, key []byte) *Filter { return defaultStore.Filter(cipher, key) }
func (s *Store) Filter(cipher uint32, key []byte) *Filter {
	h := sha256.New()
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], cipher)
	h.Write(prefix[:])
	h.Write(key)
	f := &Filter{store: s}
	copy(f.identity[:], h.Sum(nil))
	f.base = f.identity
	return f
}
func (*Filter) Interval() int64         { return 9999999 }
func (f *Filter) Check(sum []byte) bool { return f.CheckError(sum) == nil }
func doubleFNV(b []byte) (uint64, uint64) {
	x, y := fnv.New64(), fnv.New64a()
	x.Write(b)
	y.Write(b)
	return x.Sum64(), y.Sum64()
}
func (f *Filter) CheckError(iv []byte) error {
	s := f.store
	shard := &s.shards[f.identity[0]%64]
	shard.Lock()
	state := shard.states[f.identity]
	if state == nil {
		if !s.reserve(identityCharge) {
			shard.Unlock()
			return ErrBudget
		}
		state = new(replayState)
		if shard.states == nil {
			shard.states = make(map[[32]byte]*replayState)
		}
		shard.states[f.identity] = state
	}
	shard.Unlock()
	state.mu.Lock()
	defer state.mu.Unlock()
	digest := sha256.Sum256(iv)
	for i := range state.slots {
		slot := &state.slots[i]
		if _, ok := slot.exact[digest]; ok {
			return ErrReplay
		}
		if slot.bloom != nil && slot.bloom.Test(digest[:]) {
			return ErrReplay
		}
	}
	slot := &state.slots[state.position]
	if slot.count > slotCapacity {
		state.position = (state.position + 1) % slotCount
		slot = &state.slots[state.position]
		// Reuse a full slot without transient allocations or budget evictions.
		if slot.bloom != nil {
			slot.bloom.Reset()
		}
		clear(slot.exact)
		slot.count = 0
	}
	if slot.bloom == nil {
		if len(slot.exact) < exactLimit {
			if !s.reserve(entryCharge) {
				return ErrBudget
			}
			if slot.exact == nil {
				slot.exact = make(map[[32]byte]struct{})
			}
			slot.exact[digest] = struct{}{}
			slot.charge += entryCharge
			slot.count++
			return nil
		}
		// Reserve the entire new bitmap before allocating, including the transient
		// exact set. Failed promotion retains every previous entry.
		if !s.reserve(bloomCharge) {
			return ErrBudget
		}
		slot.bloom = bloom.New(slotCapacity, 1e-6, doubleFNV)
		for old := range slot.exact {
			slot.bloom.Add(old[:])
		}
		slot.exact = nil
		s.used.Add(-slot.charge)
		slot.charge = bloomCharge
	}
	slot.bloom.Add(digest[:])
	slot.count++
	return nil
}
