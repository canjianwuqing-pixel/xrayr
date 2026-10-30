// Package corecompat translates legacy transport configuration in memory while
// leaving the user's files and business settings unchanged.
package corecompat

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xtls/xray-core/infra/conf"
)

// NormalizeStream preserves legacy mKCP framing using the core's replacement
// mkcp-legacy masks, rather than removing the old header/encryption feature.
func NormalizeStream(s *conf.StreamConfig) error {
	if s == nil {
		return nil
	}
	network := s.Network
	if s.Method != nil {
		network = s.Method
	}
	if network == nil || (strings.ToLower(string(*network)) != "kcp" && strings.ToLower(string(*network)) != "mkcp") {
		return nil
	}
	k := s.KCPSettings
	if k == nil {
		k = &conf.KCPConfig{}
		s.KCPSettings = k
	}
	if s.FinalMask != nil && len(s.FinalMask.Udp) > 0 {
		if k.HeaderConfig != nil || k.Seed != nil {
			return fmt.Errorf("legacy KCP header/seed and explicit UDP finalmask cannot be combined")
		}
		return nil // Already explicitly configured in the target format.
	}
	var header struct {
		Type   string `json:"type"`
		Domain string `json:"domain"`
	}
	if len(k.HeaderConfig) > 0 {
		if err := json.Unmarshal(k.HeaderConfig, &header); err != nil {
			return fmt.Errorf("legacy KCP header: %w", err)
		}
	}
	header.Type = strings.ToLower(header.Type)
	if header.Type == "wechat-video" {
		header.Type = "wechat"
	}
	switch header.Type {
	case "", "none", "srtp", "utp", "wechat", "dtls", "wireguard", "dns":
	default:
		return fmt.Errorf("unknown legacy KCP header %q", header.Type)
	}
	mask := func(settings conf.MkcpLegacy) conf.Mask {
		b, _ := json.Marshal(settings)
		raw := json.RawMessage(b)
		return conf.Mask{Type: "mkcp-legacy", Settings: &raw}
	}
	var masks []conf.Mask
	seed := ""
	if k.Seed != nil {
		seed = *k.Seed
	}
	// The encryption transform is applied before the outer packet header.
	masks = append(masks, mask(conf.MkcpLegacy{Value: seed}))
	if header.Type != "" && header.Type != "none" {
		masks = append(masks, mask(conf.MkcpLegacy{Header: header.Type, Value: header.Domain}))
	}
	if s.FinalMask == nil {
		s.FinalMask = &conf.FinalMask{}
	}
	s.FinalMask.Udp = masks
	k.HeaderConfig = nil
	k.Seed = nil
	return nil
}
