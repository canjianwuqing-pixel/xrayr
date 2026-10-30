package shadowsocks_2022

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	B "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
)

type finalPacketReader struct{}

func (finalPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	p := buf.New()
	p.WriteString("last packet")
	return buf.MultiBuffer{p}, io.EOF
}
func TestLinkPacketEOFAndSizeBoundaries(t *testing.T) {
	timer := signal.CancelAfterInactivity(context.Background(), func() {}, time.Minute)
	defer timer.SetTimeout(0)
	c := &linkPacketConn{link: &transport.Link{Reader: errorReader{io.EOF}, Writer: buf.Discard}, dest: net.UDPDestination(net.LocalHostIP, 53), timer: timer, shutdown: func() {}}
	out := B.NewPacket()
	defer out.Release()
	if _, err := c.ReadPacket(out); !errors.Is(err, io.EOF) {
		t.Fatal("EOF swallowed", err)
	}
	c.pending = nil
	c.link.Reader = finalPacketReader{}
	if _, err := c.ReadPacket(out); err != nil || string(out.Bytes()) != "last packet" {
		t.Fatal("packet+EOF lost", err)
	}
	if _, err := c.ReadPacket(out); !errors.Is(err, io.EOF) {
		t.Fatal("pending EOF lost", err)
	}
	oversized := B.NewSize(buf.Size + 1)
	oversized.Truncate(buf.Size + 1)
	if err := c.WritePacket(oversized, M.SocksaddrFromNet(&net.UDPAddr{IP: net.LocalHostIP.IP(), Port: 53})); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal("oversized packet silently truncated", err)
	}
	c.release()
}
