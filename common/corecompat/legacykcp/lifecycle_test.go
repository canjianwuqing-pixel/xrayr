package kcp

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

type countedCloser struct{ count atomic.Int32 }

func (c *countedCloser) Close() error { c.count.Add(1); return nil }
func TestConcurrentReadReleaseAndTerminate(t *testing.T) {
	for i := 0; i < 100; i++ {
		closer := new(countedCloser)
		c := NewConnection(ConnMetadata{}, &KCPPacketWriter{Writer: buf.DiscardBytes}, closer, &Config{})
		c.receivingWorker.leftOver = buf.MergeBytes(nil, make([]byte, 128))
		var wg sync.WaitGroup
		wg.Go(func() {
			for j := 0; j < 100; j++ {
				c.receivingWorker.Read(make([]byte, 3))
			}
		})
		wg.Go(c.Terminate)
		wg.Go(c.Terminate)
		wg.Wait()
		if closer.count.Load() != 1 || c.State() != StateTerminated {
			t.Fatal("termination not idempotent")
		}
	}
}
func TestConcurrentDeadlinesWakeBlockedRead(t *testing.T) {
	c := NewConnection(ConnMetadata{}, &KCPPacketWriter{Writer: buf.DiscardBytes}, nopCloser{}, &Config{})
	defer c.Terminate()
	done := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 16)); done <- err }()
	for i := 0; i < 100; i++ {
		c.SetDeadline(time.Now().Add(20 * time.Millisecond))
	}
	select {
	case err := <-done:
		if err != ErrIOTimeout {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not wake blocked read")
	}
}

func TestFutureTimestampDoesNotExpireConnection(t *testing.T) {
	c := NewConnection(ConnMetadata{}, &KCPPacketWriter{Writer: buf.DiscardBytes}, nopCloser{}, &Config{})
	defer c.Terminate()
	c.dataUpdater.Stop()
	c.pingUpdater.Stop()
	// Input may publish a newer time after flush sampled its own current time.
	atomic.StoreUint32(&c.lastIncomingTime, c.Elapsed()+1000)
	c.flush()
	if c.State() != StateActive {
		t.Fatal("future timestamp falsely triggered idle close", c.State())
	}
}

func TestElapsedCounterOrderAndRollover(t *testing.T) {
	for _, test := range []struct{ now, previous, want uint32 }{{100, 101, 0}, {30000, 0, 30000}, {20, 0xfffffff0, 36}, {100, 100, 0}} {
		if got := elapsedSince(test.now, test.previous); got != test.want {
			t.Fatal(test, got)
		}
	}
}

func TestPeerClosedIdleTimeoutReleasesLostTermination(t *testing.T) {
	c := NewConnection(ConnMetadata{}, &KCPPacketWriter{Writer: buf.DiscardBytes}, nopCloser{}, &Config{})
	defer c.Terminate()
	c.SetState(StatePeerClosed)
	// A peer's last termination packet can be lost. The idle policy must
	// still reclaim the half-closed connection instead of pinging forever.
	atomic.StoreUint32(&c.lastIncomingTime, c.Elapsed()-31000)
	c.flush()
	if c.State() == StatePeerClosed || c.State() == StateActive {
		t.Fatal("lost termination left a permanent connection")
	}
}
