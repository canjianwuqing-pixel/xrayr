package shadowsocks_2022

import (
	"io"
	"os"
	"time"

	B "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/transport"
)

type managedPipe struct {
	*singbridge.PipeConnWrapper
	shutdown func()
}

func (c *managedPipe) Close() error { c.shutdown(); return nil }

// Only this reader goroutine owns cached/pending. Close interrupts blocking IO
// but release runs after CopyPacketConn joins both workers, avoiding a close/read
// race on pooled buffers. No raw inbound read/write interface is exposed.
type linkPacketConn struct {
	link     *transport.Link
	dest     net.Destination
	cached   buf.MultiBuffer
	pending  error
	timer    *signal.ActivityTimer
	shutdown func()
}

func (c *linkPacketConn) ReadPacket(out *B.Buffer) (M.Socksaddr, error) {
	c.timer.Update()
	if len(c.cached) == 0 {
		if c.pending != nil {
			return M.Socksaddr{}, c.pending
		}
		c.cached, c.pending = c.link.Reader.ReadMultiBuffer()
	}
	var packet *buf.Buffer
	c.cached, packet = buf.SplitFirst(c.cached)
	if packet == nil {
		if c.pending != nil {
			return M.Socksaddr{}, c.pending
		}
		return M.Socksaddr{}, io.ErrNoProgress
	}
	defer packet.Release()
	if _, err := out.Write(packet.Bytes()); err != nil {
		return M.Socksaddr{}, err
	}
	dest := c.dest
	if packet.UDP != nil {
		dest = *packet.UDP
	}
	return singbridge.ToSocksaddr(dest), nil
}
func (c *linkPacketConn) WritePacket(in *B.Buffer, dest M.Socksaddr) error {
	defer in.Release()
	c.timer.Update()
	endpoint, err := singbridge.ToDestination(dest, net.Network_UDP)
	if err != nil {
		return err
	}
	if in.Len() > buf.Size {
		return io.ErrShortBuffer
	}
	packet := buf.New()
	if _, err = packet.Write(in.Bytes()); err != nil {
		packet.Release()
		return err
	}
	packet.UDP = &endpoint
	return c.link.Writer.WriteMultiBuffer(buf.MultiBuffer{packet})
}
func (c *linkPacketConn) Close() error                   { c.shutdown(); return nil }
func (c *linkPacketConn) release()                       { buf.ReleaseMulti(c.cached); c.cached = nil }
func (*linkPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*linkPacketConn) SetDeadline(time.Time) error      { return os.ErrInvalid }
func (*linkPacketConn) SetReadDeadline(time.Time) error  { return os.ErrInvalid }
func (*linkPacketConn) SetWriteDeadline(time.Time) error { return os.ErrInvalid }
