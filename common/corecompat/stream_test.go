package corecompat

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type packetCapture struct{ wire []byte }

func (p *packetCapture) WriteTo(b []byte, _ net.Addr) (int, error) {
	p.wire = append([]byte(nil), b...)
	return len(b), nil
}
func (p *packetCapture) ReadFrom(b []byte) (int, net.Addr, error) {
	if p.wire == nil {
		return 0, nil, io.EOF
	}
	n := copy(b, p.wire)
	p.wire = nil
	return n, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}, nil
}
func (*packetCapture) Close() error { return nil }
func (*packetCapture) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (*packetCapture) SetDeadline(time.Time) error      { return nil }
func (*packetCapture) SetReadDeadline(time.Time) error  { return nil }
func (*packetCapture) SetWriteDeadline(time.Time) error { return nil }

func TestLegacyKCPMasksPacketRoundTrip(t *testing.T) {
	for _, header := range []string{"none", "srtp", "utp", "wechat-video", "dtls", "wireguard", "dns"} {
		for _, seeded := range []bool{false, true} {
			t.Run(header+map[bool]string{false: "/original", true: "/seed"}[seeded], func(t *testing.T) {
				var s conf.StreamConfig
				raw := `{"network":"kcp","kcpSettings":{"header":{"type":"` + header + `"}}}`
				if err := json.Unmarshal([]byte(raw), &s); err != nil {
					t.Fatal(err)
				}
				if seeded {
					seed := "ephemeral-test-seed"
					s.KCPSettings.Seed = &seed
				}
				if err := NormalizeStream(&s); err != nil {
					t.Fatal(err)
				}
				if s.KCPSettings.HeaderConfig != nil || s.KCPSettings.Seed != nil {
					t.Fatal("legacy fields not translated")
				}

				built, err := s.Build()
				if err != nil {
					t.Fatal(err)
				}
				if err = PreserveLegacyHeaders(built); err != nil {
					t.Fatal(err)
				}
				var masks []finalmask.Udpmask
				for _, msg := range built.Udpmasks {
					m, err := msg.GetInstance()
					if err != nil {
						t.Fatal(err)
					}
					masks = append(masks, m.(finalmask.Udpmask))
				}

				manager := finalmask.NewUdpmaskManager(masks)
				capture := new(packetCapture)
				client, err := manager.WrapPacketConnClient(capture)
				if err != nil {
					t.Fatal(err)
				}
				server, err := manager.WrapPacketConnServer(capture)
				if err != nil {
					t.Fatal(err)
				}
				payload := []byte("legacy KCP packet payload")
				if _, err = client.WriteTo(payload, nil); err != nil {
					t.Fatal(err)
				}
				if header == "srtp" && !bytes.HasPrefix(capture.wire, []byte{0xb5, 0xe8}) {
					t.Fatal("SRTP outer header order changed")
				}
				buffer := make([]byte, 4096)
				n, _, err := server.ReadFrom(buffer)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(buffer[:n], payload) {
					t.Fatal("packet round trip changed payload")
				}
				before := len(s.FinalMask.Udp)
				if err = NormalizeStream(&s); err != nil {
					t.Fatal(err)
				}
				if len(s.FinalMask.Udp) != before {
					t.Fatal("normalization not idempotent")
				}
			})
		}
	}
}

func TestRejectAmbiguousLegacyAndModernMasks(t *testing.T) {
	var s conf.StreamConfig
	if err := json.Unmarshal([]byte(`{"network":"kcp","kcpSettings":{"header":{"type":"srtp"}},"finalmask":{"udp":[{"type":"mkcp-legacy"}]}}`), &s); err != nil {
		t.Fatal(err)
	}
	if err := NormalizeStream(&s); err == nil {
		t.Fatal("ambiguous framing silently accepted")
	}
}

func TestRemovedKCPTuningIsNotSilentlyDiscarded(t *testing.T) {
	if err := ValidateTransportJSON([]byte(`[{"streamSettings":{"network":"kcp","kcpSettings":{"congestion":true}}}]`)); err == nil {
		t.Fatal("silently discarded legacy congestion")
	}
	if err := ValidateTransportJSON([]byte(`[{"streamSettings":{"network":"kcp","kcpSettings":{"header":{"type":"srtp"}}}}]`)); err != nil {
		t.Fatal(err)
	}
}
