package corecompat

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/wyx2685/XrayR/common/corecompat/legacyheader/dns"
	"github.com/wyx2685/XrayR/common/corecompat/legacyheader/srtp"
	dtls "github.com/wyx2685/XrayR/common/corecompat/legacyheader/tls"
	"github.com/wyx2685/XrayR/common/corecompat/legacyheader/utp"
	"github.com/wyx2685/XrayR/common/corecompat/legacyheader/wechat"
	"github.com/wyx2685/XrayR/common/corecompat/legacyheader/wireguard"
	kcp "github.com/wyx2685/XrayR/common/corecompat/legacykcp"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

type legacyKCPJSON struct {
	Mtu        *uint32         `json:"mtu"`
	Tti        *uint32         `json:"tti"`
	Up         *uint32         `json:"uplinkCapacity"`
	Down       *uint32         `json:"downlinkCapacity"`
	Congestion *bool           `json:"congestion"`
	Read       *uint32         `json:"readBufferSize"`
	Write      *uint32         `json:"writeBufferSize"`
	MaxWindow  *uint32         `json:"maxSendingWindow"`
	Cwnd       *uint32         `json:"cwndMultiplier"`
	Header     json.RawMessage `json:"header"`
	Seed       *string         `json:"seed"`
}

func decodeLegacyKCP(raw []byte) (*legacyKCPJSON, error) {
	if strings.TrimSpace(string(raw)) == "null" {
		return new(legacyKCPJSON), nil
	}
	fields, err := foldObject(raw)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{"mtu": true, "tti": true, "uplinkcapacity": true, "downlinkcapacity": true, "congestion": true, "readbuffersize": true, "writebuffersize": true, "maxsendingwindow": true, "cwndmultiplier": true, "header": true, "seed": true}
	for key := range fields {
		if !allowed[key] {
			return nil, fmt.Errorf("unknown kcpSettings field %q", key)
		}
	}
	var v legacyKCPJSON
	if err = json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(v.Header)) == "null" {
		v.Header = nil
	}
	if v.Write != nil && v.MaxWindow != nil {
		return nil, fmt.Errorf("writeBufferSize and maxSendingWindow cannot both be set")
	}
	return &v, nil
}
func bytesFromMiB(n *uint32) (*uint32, error) {
	if n == nil {
		return nil, nil
	}
	value := uint64(*n) * 1024 * 1024
	if *n == 0 {
		value = 512 * 1024
	}
	if value > math.MaxUint32 {
		return nil, fmt.Errorf("KCP buffer MiB multiplication overflows uint32")
	}
	v := uint32(value)
	return &v, nil
}

func prepareKCP(s *conf.StreamConfig, raw json.RawMessage) (*conf.StreamConfig, *kcp.Config, error) {
	if s == nil {
		return nil, nil, nil
	}
	network := s.Network
	if s.Method != nil {
		network = s.Method
	}
	if network == nil || (strings.ToLower(string(*network)) != "kcp" && strings.ToLower(string(*network)) != "mkcp") {
		return s, nil, nil
	}
	var v *legacyKCPJSON
	var err error
	if len(raw) > 0 {
		v, err = decodeLegacyKCP(raw)
	} else {
		v = new(legacyKCPJSON)
		if c := s.KCPSettings; c != nil {
			v.Mtu = c.Mtu
			v.Tti = c.Tti
			v.Up = c.UpCap
			v.Down = c.DownCap
			v.MaxWindow = c.MaxSendingWindow
			v.Cwnd = c.CwndMultiplier
			v.Header = c.HeaderConfig
			v.Seed = c.Seed
		}
	}
	if err != nil {
		return nil, nil, err
	}
	if s.FinalMask != nil && len(s.FinalMask.Udp) > 0 {
		if v.Congestion != nil || v.Read != nil || v.Write != nil || v.Header != nil || v.Seed != nil {
			return nil, nil, fmt.Errorf("legacy KCP fields and explicit UDP finalmask cannot be combined")
		}
		if err = NormalizeStream(s); err != nil {
			return nil, nil, err
		}
		return s, nil, nil
	}
	if v.Cwnd != nil {
		return nil, nil, fmt.Errorf("cwndMultiplier requires explicit modern UDP finalmask; not equivalent to legacy congestion")
	}
	c := new(kcp.Config)
	if v.Mtu != nil {
		c.Mtu = &kcp.MTU{Value: *v.Mtu}
	}
	if v.Tti != nil {
		c.Tti = &kcp.TTI{Value: *v.Tti}
	}
	if c.GetMTUValue() < 576 || c.GetMTUValue() > 1460 {
		return nil, nil, fmt.Errorf("legacy KCP MTU must be 576..1460")
	}
	if c.GetTTIValue() < 10 || c.GetTTIValue() > 100 {
		return nil, nil, fmt.Errorf("legacy KCP TTI must be 10..100")
	}
	for _, cap := range []*uint32{v.Up, v.Down} {
		if cap != nil && uint64(*cap)*1024*1024 > math.MaxUint32 {
			return nil, nil, fmt.Errorf("KCP capacity overflows uint32")
		}
	}
	if v.Up != nil {
		c.UplinkCapacity = &kcp.UplinkCapacity{Value: *v.Up}
	}
	if v.Down != nil {
		c.DownlinkCapacity = &kcp.DownlinkCapacity{Value: *v.Down}
	}
	if v.Congestion != nil {
		c.Congestion = *v.Congestion
	}
	read, err := bytesFromMiB(v.Read)
	if err != nil {
		return nil, nil, err
	}
	if read != nil {
		c.ReadBuffer = &kcp.ReadBuffer{Size: *read}
	}
	write, err := bytesFromMiB(v.Write)
	if err != nil {
		return nil, nil, err
	}
	if v.MaxWindow != nil {
		write = v.MaxWindow
	}
	if write != nil {
		c.WriteBuffer = &kcp.WriteBuffer{Size: *write}
	}
	if c.GetWriteBufferSize() < c.GetMTUValue() {
		return nil, nil, fmt.Errorf("KCP sending window must be >= MTU")
	}
	if v.Seed != nil {
		c.Seed = &kcp.EncryptionSeed{Seed: *v.Seed}
	}
	if len(v.Header) > 0 {
		fields, err := foldObject(v.Header)
		if err != nil {
			return nil, nil, err
		}
		for key := range fields {
			if key != "type" && key != "domain" {
				return nil, nil, fmt.Errorf("unknown KCP header field %q", key)
			}
		}
		var h struct{ Type, Domain string }
		if err = json.Unmarshal(v.Header, &h); err != nil {
			return nil, nil, err
		}
		var header proto.Message
		switch strings.ToLower(h.Type) {
		case "", "none":
		case "srtp":
			header = &srtp.Config{}
		case "dtls":
			header = &dtls.PacketConfig{}
		case "utp":
			header = &utp.Config{}
		case "wechat", "wechat-video":
			header = &wechat.VideoConfig{}
		case "wireguard":
			header = &wireguard.WireguardConfig{}
		case "dns":
			if h.Domain == "" {
				h.Domain = "www.baidu.com"
			}
			header = &dns.Config{Domain: h.Domain}
		default:
			return nil, nil, fmt.Errorf("unknown KCP header %q", h.Type)
		}
		if header != nil {
			c.HeaderConfig = serial.ToTypedMessage(header)
		}
	}
	clone := *s
	tcp := conf.TransportProtocol("tcp")
	clone.Network = &tcp
	clone.Method = nil
	clone.KCPSettings = nil
	return &clone, c, nil
}
func installKCP(s *internet.StreamConfig, c *kcp.Config) {
	s.ProtocolName = "kuaiyun-kcp"
	s.TransportSettings = append(s.TransportSettings, &internet.TransportConfig{ProtocolName: "kuaiyun-kcp", Settings: serial.ToTypedMessage(c)})
}
func BuildInbound(c *conf.InboundDetourConfig) (*core.InboundHandlerConfig, error) {
	return buildCompatInbound(c, nil)
}
func buildCompatInbound(c *conf.InboundDetourConfig, raw json.RawMessage) (*core.InboundHandlerConfig, error) {
	clone := *c
	stream, k, err := prepareKCP(c.StreamSetting, raw)
	if err != nil {
		return nil, err
	}
	clone.StreamSetting = stream
	result, err := buildInboundNative(&clone)
	if err != nil || k == nil {
		return result, err
	}
	obj, err := result.ReceiverSettings.GetInstance()
	if err != nil {
		return nil, err
	}
	r := obj.(*proxyman.ReceiverConfig)
	installKCP(r.StreamSettings, k)
	result.ReceiverSettings = serial.ToTypedMessage(r)
	return result, nil
}
func BuildOutbound(c *conf.OutboundDetourConfig) (*core.OutboundHandlerConfig, error) {
	return buildCompatOutbound(c, nil)
}
func buildCompatOutbound(c *conf.OutboundDetourConfig, raw json.RawMessage) (*core.OutboundHandlerConfig, error) {
	clone := *c
	stream, k, err := prepareKCP(c.StreamSetting, raw)
	if err != nil {
		return nil, err
	}
	clone.StreamSetting = stream
	result, err := buildOutboundNative(&clone)
	if err != nil || k == nil {
		return result, err
	}
	obj, err := result.SenderSettings.GetInstance()
	if err != nil {
		return nil, err
	}
	r := obj.(*proxyman.SenderConfig)
	installKCP(r.StreamSettings, k)
	result.SenderSettings = serial.ToTypedMessage(r)
	return result, nil
}
func BuildInboundJSON(data []byte) ([]*core.InboundHandlerConfig, error) {
	if err := ValidateTransportJSON(data); err != nil {
		return nil, err
	}
	var handlers []json.RawMessage
	if err := json.Unmarshal(data, &handlers); err != nil {
		return nil, err
	}
	result := make([]*core.InboundHandlerConfig, 0, len(handlers))
	for _, h := range handlers {
		var c conf.InboundDetourConfig
		if err := json.Unmarshal(h, &c); err != nil {
			return nil, err
		}
		raw, err := kcpRaw(h)
		if err != nil {
			return nil, err
		}
		built, err := buildCompatInbound(&c, raw)
		if err != nil {
			return nil, err
		}
		result = append(result, built)
	}
	return result, nil
}
func BuildOutboundJSON(data []byte) ([]*core.OutboundHandlerConfig, error) {
	if err := ValidateTransportJSON(data); err != nil {
		return nil, err
	}
	var handlers []json.RawMessage
	if err := json.Unmarshal(data, &handlers); err != nil {
		return nil, err
	}
	result := make([]*core.OutboundHandlerConfig, 0, len(handlers))
	for _, h := range handlers {
		var c conf.OutboundDetourConfig
		if err := json.Unmarshal(h, &c); err != nil {
			return nil, err
		}
		raw, err := kcpRaw(h)
		if err != nil {
			return nil, err
		}
		built, err := buildCompatOutbound(&c, raw)
		if err != nil {
			return nil, err
		}
		result = append(result, built)
	}
	return result, nil
}
