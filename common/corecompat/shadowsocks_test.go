package corecompat

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	legacyss "github.com/wyx2685/XrayR/common/corecompat/legacyss"
	legacy2022 "github.com/wyx2685/XrayR/common/corecompat/legacyss2022"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/infra/conf"
)

func TestRejectSignedInvalidUoTVersions(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{-1, 3, 256} {
		var config LegacyShadowsocksClientConfig
		raw := map[string]interface{}{"servers": []interface{}{map[string]interface{}{"address": "127.0.0.1", "port": 12345, "method": "2022-blake3-aes-128-gcm", "password": base64.StdEncoding.EncodeToString(key), "uot": true, "uotVersion": version}}}
		data, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, &config); err != nil {
			t.Fatal(err)
		}
		if _, err = config.Build(); err == nil {
			t.Fatal("invalid signed version accepted", version)
		}
	}
}

func TestLegacyShadowsocksInboundOutboundAndIVCheck(t *testing.T) {
	for _, method := range []string{"none", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		t.Run(method, func(t *testing.T) {
			var in conf.InboundDetourConfig
			if err := json.Unmarshal([]byte(`{"listen":"127.0.0.1","port":12345,"protocol":"shadowsocks","settings":{"method":"`+method+`","password":"test-only-password","ivCheck":true,"network":"tcp,udp"}}`), &in); err != nil {
				t.Fatal(err)
			}
			built, err := BuildInbound(&in)
			if err != nil {
				t.Fatal(err)
			}
			obj, err := built.ProxySettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			cfg := obj.(*legacyss.ServerConfig)
			account, err := cfg.Users[0].GetTypedAccount()
			if err != nil {
				t.Fatal(err)
			}
			a := account.(*legacyss.MemoryAccount)
			if method != "none" {
				iv := make([]byte, 32)
				if _, err = rand.Read(iv); err != nil {
					t.Fatal(err)
				}
				if err = a.CheckIV(iv); err != nil {
					t.Fatal(err)
				}
				if err = a.CheckIV(iv); err == nil {
					t.Fatal("replayed IV accepted")
				}
			}
			var out conf.OutboundDetourConfig
			if err = json.Unmarshal([]byte(`{"protocol":"shadowsocks","settings":{"servers":[{"address":"127.0.0.1","port":12345,"method":"`+method+`","password":"test-only-password","ivCheck":true}]}}`), &out); err != nil {
				t.Fatal(err)
			}
			ob, err := BuildOutbound(&out)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = ob.ProxySettings.GetInstance(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSS2022UDPOverTCPConfigPreserved(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	settings := map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": 12345, "method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString(key), "uot": true, "uotVersion": 2}}}
	b, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	raw := json.RawMessage(b)
	build, err := BuildOutbound(&conf.OutboundDetourConfig{Protocol: "shadowsocks", Settings: &raw})
	if err != nil {
		t.Fatal(err)
	}
	obj, err := build.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	cfg := obj.(*legacy2022.ClientConfig)
	if !cfg.UdpOverTcp || cfg.UdpOverTcpVersion != 2 {
		t.Fatal("UDP-over-TCP setting lost")
	}
	if _, err = common.CreateObject(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}
