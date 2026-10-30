package kcp

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"github.com/wyx2685/XrayR/common/corecompat/legacyheader/srtp"
	dtls "github.com/wyx2685/XrayR/common/corecompat/legacyheader/tls"
	"github.com/wyx2685/XrayR/common/corecompat/legacyheader/wechat"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/serial"
)

func TestLegacyCongestionAlgorithm(t *testing.T) {
	c := NewConnection(ConnMetadata{}, &KCPPacketWriter{Writer: buf.DiscardBytes}, nopCloser{}, &Config{Congestion: true})
	defer c.Terminate()
	c.roundTrip.rto = 100
	w := c.sendingWorker
	w.controlWindow = 100
	w.OnPacketLoss(15)
	if w.controlWindow != 75 {
		t.Fatal(w.controlWindow)
	}
	w.OnPacketLoss(5)
	if w.controlWindow != 93 {
		t.Fatal(w.controlWindow)
	}
	w.controlWindow = 1
	w.OnPacketLoss(99)
	if w.controlWindow != 16 {
		t.Fatal(w.controlWindow)
	}
	w.controlWindow = 100000
	w.OnPacketLoss(0)
	if w.controlWindow != 2*c.Config.GetSendingInFlightSize() {
		t.Fatal("upper bound")
	}
	c.Config.Congestion = false
	w.controlWindow = 100
	w.OnPacketLoss(99)
	if w.controlWindow != 100 {
		t.Fatal("false did not disable control")
	}
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func TestSharedKCPPacketWritersAndWireMTU(t *testing.T) {
	for _, msg := range []interface{}{&srtp.Config{}, &dtls.PacketConfig{}, &wechat.VideoConfig{}} {
		for _, seed := range []*EncryptionSeed{nil, {Seed: ""}, {Seed: "public-test-seed"}} {
			t.Run(fmt.Sprintf("%T/%v", msg, seed != nil), func(t *testing.T) {
				config := &Config{Seed: seed}
				switch m := msg.(type) {
				case *srtp.Config:
					config.HeaderConfig = serial.ToTypedMessage(m)
				case *dtls.PacketConfig:
					config.HeaderConfig = serial.ToTypedMessage(m)
				case *wechat.VideoConfig:
					config.HeaderConfig = serial.ToTypedMessage(m)
				}
				header, err := config.GetPackerHeader()
				if err != nil {
					t.Fatal(err)
				}
				security, err := config.GetSecurity()
				if err != nil {
					t.Fatal(err)
				}
				var wg sync.WaitGroup
				for i := 0; i < 16; i++ {
					wg.Go(func() {
						var wire bytes.Buffer
						writer := &KCPPacketWriter{Header: header, Security: security, Writer: &wire}
						for j := 0; j < 32; j++ {
							wire.Reset()
							payload := bytes.Repeat([]byte{1}, 1350-writer.Overhead())
							if _, err := writer.Write(payload); err != nil {
								t.Error(err)
								return
							}
							if wire.Len() != 1350 {
								t.Errorf("wire MTU %d", wire.Len())
								return
							}
							packet := wire.Bytes()
							n := int(header.Size())
							plain, err := security.Open(nil, packet[n:n+security.NonceSize()], packet[n+security.NonceSize():], nil)
							if err != nil || !bytes.Equal(plain, payload) {
								t.Errorf("frame mismatch %v", err)
								return
							}
						}
					})
				}
				wg.Wait()
			})
		}
	}
}
