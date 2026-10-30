// Package legacyheader adapts original packet header serializers to finalmask.
package legacyheader

import "net"

type Header interface {
	Size() int32
	Serialize([]byte)
}
type Factory func() Header
type Mask struct{ New Factory }

func (*Mask) UDP()        {}
func (*Mask) HeaderConn() {}
func (m *Mask) WrapPacketConnClient(raw net.PacketConn, _, _ int) (net.PacketConn, error) {
	return &conn{PacketConn: raw, header: m.New()}, nil
}
func (m *Mask) WrapPacketConnServer(raw net.PacketConn, a, b int) (net.PacketConn, error) {
	return m.WrapPacketConnClient(raw, a, b)
}

type conn struct {
	net.PacketConn
	header Header
}

func (c *conn) Size() int                                 { return int(c.header.Size()) }
func (c *conn) ReadFrom(p []byte) (int, net.Addr, error)  { return len(p) - c.Size(), nil, nil }
func (c *conn) WriteTo(p []byte, _ net.Addr) (int, error) { c.header.Serialize(p); return len(p), nil }
