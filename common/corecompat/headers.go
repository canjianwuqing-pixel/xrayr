package corecompat

import (
	"github.com/wyx2685/XrayR/common/corecompat/legacyheader/srtp"
	"github.com/wyx2685/XrayR/common/corecompat/legacyheader/tls"
	"github.com/wyx2685/XrayR/common/corecompat/legacyheader/utp"
	"github.com/wyx2685/XrayR/common/corecompat/legacyheader/wechat"
	"github.com/wyx2685/XrayR/common/corecompat/legacyheader/wireguard"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/header"
	"google.golang.org/protobuf/proto"
)

// Preserve the legacy serializers' initialization and state. In particular,
// v26.7.28's SRTP serializer otherwise emits a zero prefix instead of 0xb5e8.
func PreserveLegacyHeaders(stream *internet.StreamConfig) error {
	if stream == nil {
		return nil
	}
	for i, mask := range stream.Udpmasks {
		instance, err := mask.GetInstance()
		if err != nil {
			return err
		}
		h, ok := instance.(*header.Config)
		if !ok {
			continue
		}
		var config proto.Message
		switch h.ID {
		case 1:
			config = &tls.PacketConfig{}
		case 2:
			config = &srtp.Config{}
		case 3:
			config = &utp.Config{}
		case 4:
			config = &wechat.VideoConfig{}
		case 5:
			config = &wireguard.WireguardConfig{}
		default:
			continue
		}
		stream.Udpmasks[i] = serial.ToTypedMessage(config)
	}
	return nil
}
