package wechat

import (
	"context"
	"github.com/wyx2685/XrayR/common/corecompat/legacyheader"
	"net"
)

func (*VideoConfig) UDP()        {}
func (*VideoConfig) HeaderConn() {}
func (c *VideoConfig) WrapPacketConnClient(raw net.PacketConn, a, b int) (net.PacketConn, error) {
	m, err := NewVideoChat(context.Background(), c)
	if err != nil {
		return nil, err
	}
	return m.(*legacyheader.Mask).WrapPacketConnClient(raw, a, b)
}
func (c *VideoConfig) WrapPacketConnServer(raw net.PacketConn, a, b int) (net.PacketConn, error) {
	return c.WrapPacketConnClient(raw, a, b)
}
