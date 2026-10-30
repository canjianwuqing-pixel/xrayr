package kcp_test

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/wyx2685/XrayR/common/corecompat/legacyheader/srtp"
	dtls "github.com/wyx2685/XrayR/common/corecompat/legacyheader/tls"
	"github.com/wyx2685/XrayR/common/corecompat/legacyheader/wechat"
	kcp "github.com/wyx2685/XrayR/common/corecompat/legacykcp"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"google.golang.org/protobuf/proto"
)

func TestSharedHeaderKCPConnectionsLoopback(t *testing.T) {
	for _, header := range []proto.Message{&srtp.Config{}, &dtls.PacketConfig{}, &wechat.VideoConfig{}} {
		t.Run(string(header.ProtoReflect().Descriptor().FullName()), func(t *testing.T) {
			config := &kcp.Config{HeaderConfig: serial.ToTypedMessage(header), Seed: &kcp.EncryptionSeed{Seed: ""}}
			stream := &internet.MemoryStreamConfig{ProtocolName: "kuaiyun-kcp", ProtocolSettings: config}
			listener, err := kcp.NewListener(context.Background(), net.LocalHostIP, 0, stream, func(conn stat.Connection) { go func() { defer conn.Close(); io.Copy(conn, conn) }() })
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			port := net.Port(listener.Addr().(*net.UDPAddr).Port)
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Go(func() {
					conn, err := kcp.DialKCP(context.Background(), net.UDPDestination(net.LocalHostIP, port), stream)
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					payload := bytes.Repeat([]byte("KCP shared header"), 1024)
					written := make(chan error, 1)
					go func() { _, err := conn.Write(payload); written <- err }()
					reply := make([]byte, len(payload))
					_, err = io.ReadFull(conn, reply)
					if err != nil {
						t.Error(err)
					} else if !bytes.Equal(payload, reply) {
						t.Error("shared header corrupted data")
					}
					if err = <-written; err != nil {
						t.Error(err)
					}
				})
			}
			wg.Wait()
		})
	}
}
