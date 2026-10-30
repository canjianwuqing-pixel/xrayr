package kcp_test

import (
	"context"
	"crypto/rand"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	. "github.com/wyx2685/XrayR/common/corecompat/legacykcp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/sync/errgroup"
)

func TestDialAndListen(t *testing.T) {
	// Keep the same ten clients and 10MiB payload on a reproducible four-CPU
	// fixture; very high host CPU counts cause artificial loopback UDP bursts.
	previousProcs := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previousProcs)
	listerner, err := NewListener(context.Background(), net.LocalHostIP, net.Port(0), &internet.MemoryStreamConfig{
		ProtocolName:     "mkcp",
		ProtocolSettings: &Config{},
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			payload := make([]byte, 4096)
			for {
				nBytes, err := c.Read(payload)
				if err != nil {
					break
				}
				for idx, b := range payload[:nBytes] {
					payload[idx] = b ^ 'c'
				}
				c.Write(payload[:nBytes])
			}
			c.Close()
		}(conn)
	})
	common.Must(err)
	defer listerner.Close()

	port := net.Port(listerner.Addr().(*net.UDPAddr).Port)

	var errg errgroup.Group
	for i := 0; i < 10; i++ {
		errg.Go(func() error {
			clientConn, err := DialKCP(context.Background(), net.UDPDestination(net.LocalHostIP, port), &internet.MemoryStreamConfig{
				ProtocolName:     "mkcp",
				ProtocolSettings: &Config{},
			})
			if err != nil {
				return err
			}
			defer clientConn.Close()

			clientSend := make([]byte, 1024*1024)
			rand.Read(clientSend)
			go clientConn.Write(clientSend)

			clientReceived := make([]byte, 1024*1024)
			if received, err := io.ReadFull(clientConn, clientReceived); err != nil {
				c := clientConn.(*Connection)
				return errors.New("KCP truncated response: bytes=", received, " state=", c.State(), " elapsed=", c.Elapsed()).Base(err)
			}

			clientExpected := make([]byte, 1024*1024)
			for idx, b := range clientSend {
				clientExpected[idx] = b ^ 'c'
			}
			if r := cmp.Diff(clientReceived, clientExpected); r != "" {
				return errors.New(r)
			}
			return nil
		})
	}

	if err := errg.Wait(); err != nil {
		t.Fatal(err)
	}

	// Lost final control packets may require idle(30s)+ready(15s)+terminate(8s)
	// plus updater scheduling. This bounds the existing timers, not a new delay.
	for i := 0; i < 160 && listerner.ActiveConnections() > 0; i++ {
		time.Sleep(500 * time.Millisecond)
	}
	if v := listerner.ActiveConnections(); v != 0 {
		t.Error("active connections: ", v)
	}
}
