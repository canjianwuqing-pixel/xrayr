package srtp

import (
	"context"
	"github.com/wyx2685/XrayR/common/corecompat/legacyheader"
	"net"
)

func (*Config) UDP()        {}
func (*Config) HeaderConn() {}
func (c *Config) WrapPacketConnClient(raw net.PacketConn, a, b int) (net.PacketConn, error) {
	m, err := New(context.Background(), c)
	if err != nil {
		return nil, err
	}
	return m.(*legacyheader.Mask).WrapPacketConnClient(raw, a, b)
}
func (c *Config) WrapPacketConnServer(raw net.PacketConn, a, b int) (net.PacketConn, error) {
	return c.WrapPacketConnClient(raw, a, b)
}
