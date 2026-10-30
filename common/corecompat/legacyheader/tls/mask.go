package tls

import (
	"context"
	"github.com/wyx2685/XrayR/common/corecompat/legacyheader"
	"net"
)

func (*PacketConfig) UDP()        {}
func (*PacketConfig) HeaderConn() {}
func (c *PacketConfig) WrapPacketConnClient(raw net.PacketConn, a, b int) (net.PacketConn, error) {
	m, err := New(context.Background(), c)
	if err != nil {
		return nil, err
	}
	return m.(*legacyheader.Mask).WrapPacketConnClient(raw, a, b)
}
func (c *PacketConfig) WrapPacketConnServer(raw net.PacketConn, a, b int) (net.PacketConn, error) {
	return c.WrapPacketConnClient(raw, a, b)
}
