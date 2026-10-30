package shadowsocks_2022

import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

type trackedConn struct {
	net.Conn
	once   sync.Once
	closed *atomic.Int32
}

func (c *trackedConn) Close() error { c.once.Do(func() { c.closed.Add(1) }); return c.Conn.Close() }
func TestLoopbackReconnectResourceOwnership(t *testing.T) {
	// Bound runtime worker creation for a reproducible process-wide handle
	// measurement; this test does not run in parallel with other tests.
	previousProcs := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(previousProcs)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var serverWG sync.WaitGroup
	serverWG.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	})
	defer func() { listener.Close(); serverWG.Wait() }()
	o, err := NewClient(context.Background(), clientConfig(2))
	if err != nil {
		t.Fatal(err)
	}
	var opened, closed atomic.Int32
	dial := testDialer{func(ctx context.Context) (stat.Connection, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		if err != nil {
			return nil, err
		}
		opened.Add(1)
		return &trackedConn{Conn: conn, closed: &closed}, nil
	}}
	run := func() {
		up, _ := pipe.New()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		o.Process(processContext(ctx, xnet.Network_UDP), &transport.Link{Reader: up, Writer: buf.Discard}, dial)
	}
	_, cold := openResourceCount(t)
	// Compare equal batches after lazy runtime/IO completion resource setup.
	// A connection leak still grows in the second batch and fails this test.
	for i := 0; i < 100; i++ {
		run()
	}
	runtime.GC()
	label, before := openResourceCount(t)
	goroutines := runtime.NumGoroutine()
	for i := 0; i < 100; i++ {
		run()
	}
	deadline := time.Now().Add(2 * time.Second)
	var after int
	for {
		runtime.GC()
		_, after = openResourceCount(t)
		if after <= before+4 && runtime.NumGoroutine() <= goroutines+2 {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("%s cold=%d warmed=%d after=%d; goroutines before=%d after=%d; opened=%d closed=%d", label, cold, before, after, goroutines, runtime.NumGoroutine(), opened.Load(), closed.Load())
	if opened.Load() != 200 || opened.Load() != closed.Load() {
		t.Fatal("dial ownership leak")
	}
	if after > before+4 || runtime.NumGoroutine() > goroutines+2 {
		t.Fatal("resource growth after reconnects")
	}
}
