package wireguard

import (
	"context"
	"github.com/wyx2685/XrayR/common/corecompat/legacyheader"
	"net"
)

func (*WireguardConfig) UDP()        {}
func (*WireguardConfig) HeaderConn() {}
func (c *WireguardConfig) WrapPacketConnClient(raw net.PacketConn, a, b int) (net.PacketConn, error) {
	m, err := NewWireguard(context.Background(), c)
	if err != nil {
		return nil, err
	}
	return m.(*legacyheader.Mask).WrapPacketConnClient(raw, a, b)
}
func (c *WireguardConfig) WrapPacketConnServer(raw net.PacketConn, a, b int) (net.PacketConn, error) {
	return c.WrapPacketConnClient(raw, a, b)
}
