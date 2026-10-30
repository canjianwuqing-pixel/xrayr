package corecompat

import (
	"encoding/json"
	"strings"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// BuildInbound preserves legacy Shadowsocks ciphers and replay checking. The
// target core still builds receiver/transport settings; only the proxy changes.
func buildInboundNative(c *conf.InboundDetourConfig) (*core.InboundHandlerConfig, error) {
	if err := NormalizeStream(c.StreamSetting); err != nil {
		return nil, err
	}
	if strings.ToLower(c.Protocol) != "shadowsocks" {
		return finishInbound(c.Build())
	}
	var legacy LegacyShadowsocksServerConfig
	if c.Settings != nil {
		if err := json.Unmarshal(*c.Settings, &legacy); err != nil {
			return nil, err
		}
	}
	proxy, err := legacy.Build()
	if err != nil {
		return nil, err
	}
	copy := *c
	copy.Protocol = "dokodemo-door"
	settings := json.RawMessage(`{"address":"127.0.0.1","network":"tcp,udp"}`)
	copy.Settings = &settings
	result, err := copy.Build()
	if err != nil {
		return nil, err
	}
	result.ProxySettings = serial.ToTypedMessage(proxy)
	return finishInbound(result, nil)
}

func buildOutboundNative(c *conf.OutboundDetourConfig) (*core.OutboundHandlerConfig, error) {
	if err := NormalizeStream(c.StreamSetting); err != nil {
		return nil, err
	}
	if strings.ToLower(c.Protocol) != "shadowsocks" {
		return finishOutbound(c.Build())
	}
	var legacy LegacyShadowsocksClientConfig
	if c.Settings != nil {
		if err := json.Unmarshal(*c.Settings, &legacy); err != nil {
			return nil, err
		}
	}
	proxy, err := legacy.Build()
	if err != nil {
		return nil, err
	}
	copy := *c
	copy.Protocol = "freedom"
	settings := json.RawMessage(`{}`)
	copy.Settings = &settings
	result, err := copy.Build()
	if err != nil {
		return nil, err
	}
	result.ProxySettings = serial.ToTypedMessage(proxy)
	return finishOutbound(result, nil)
}

func finishInbound(c *core.InboundHandlerConfig, err error) (*core.InboundHandlerConfig, error) {
	if err != nil {
		return nil, err
	}
	obj, err := c.ReceiverSettings.GetInstance()
	if err != nil {
		return nil, err
	}
	receiver := obj.(*proxyman.ReceiverConfig)
	if err = PreserveLegacyHeaders(receiver.StreamSettings); err != nil {
		return nil, err
	}
	c.ReceiverSettings = serial.ToTypedMessage(receiver)
	return c, nil
}
func finishOutbound(c *core.OutboundHandlerConfig, err error) (*core.OutboundHandlerConfig, error) {
	if err != nil {
		return nil, err
	}
	obj, err := c.SenderSettings.GetInstance()
	if err != nil {
		return nil, err
	}
	sender := obj.(*proxyman.SenderConfig)
	if err = PreserveLegacyHeaders(sender.StreamSettings); err != nil {
		return nil, err
	}
	c.SenderSettings = serial.ToTypedMessage(sender)
	return c, nil
}
