package controller

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/wyx2685/XrayR/api"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport/internet/reality"
	"google.golang.org/protobuf/proto"
)

func TestREALITYMinClientVersionPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name                             string
		localMode, nilLocal, minimumOnly bool
		remote, local, selected          string
		want                             []byte
	}{
		{name: "remote_empty_local_nil", nilLocal: true, want: []byte{26, 3, 27}},
		{name: "both_empty", want: []byte{26, 3, 27}},
		{name: "local_fallback", local: "1.8.2", selected: "1.8.2", want: []byte{1, 8, 2}},
		{name: "local_minimum_only", minimumOnly: true, local: "1.8.2", selected: "1.8.2", want: []byte{1, 8, 2}},
		{name: "remote_preferred", remote: "26.3.27", local: "1.8.2", selected: "26.3.27", want: []byte{26, 3, 27}},
		{name: "remote_without_local", nilLocal: true, remote: "26.4.1", selected: "26.4.1", want: []byte{26, 4, 1}},
		{name: "unselected_local_not_validated", remote: "26.3.27", local: "invalid", selected: "26.3.27", want: []byte{26, 3, 27}},
		{name: "local_mode_unchanged", localMode: true, remote: "26.3.27", local: "1.8.2", selected: "1.8.2", want: []byte{1, 8, 2}},
		{name: "local_mode_empty_ignores_remote", localMode: true, remote: "27.1.1", want: []byte{26, 3, 27}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			remote := &api.REALITYConfig{
				Dest: "remote.example.invalid:443", PrivateKey: realityKey(t),
				ServerNames: []string{"remote.example.invalid"}, ShortIds: []string{"01", "02"},
				ProxyProtocolVer: 1, MinClientVer: tc.remote, MaxClientVer: "28.1.2", MaxTimeDiff: 60000,
			}
			cfg := &Config{EnableREALITY: true, DisableLocalREALITYConfig: !tc.localMode}
			if !tc.nilLocal {
				cfg.REALITYConfigs = &REALITYConfig{
					Show: true, Dest: "local.example.invalid:8443", PrivateKey: realityKey(t),
					ServerNames: []string{"local.example.invalid"}, ShortIds: []string{"03"},
					ProxyProtocolVer: 2, MinClientVer: tc.local, MaxClientVer: "29.2.3", MaxTimeDiff: 120000,
				}
			}
			if tc.minimumOnly {
				cfg.REALITYConfigs = &REALITYConfig{MinClientVer: tc.local}
			}
			node := &api.NodeInfo{NodeType: "Vless", Port: 12345, TransportProtocol: "tcp",
				EnableREALITY: true, REALITYConfig: remote, VlessFlow: "xtls-rprx-vision"}
			before, err := json.Marshal([]any{cfg, node})
			if err != nil {
				t.Fatal(err)
			}
			in, err := InboundBuilder(cfg, node, "test")
			if err != nil {
				t.Fatal(err)
			}
			obj, err := in.ReceiverSettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			stream := obj.(*proxyman.ReceiverConfig).StreamSettings
			if stream.SecurityType != "xray.transport.internet.reality.Config" || len(stream.SecuritySettings) != 1 {
				t.Fatal("REALITY security configuration missing")
			}
			security, err := stream.SecuritySettings[0].GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(security.(*reality.Config).MinClientVer, tc.want) {
				t.Fatalf("core MinClientVer = %v, want %v", security.(*reality.Config).MinClientVer, tc.want)
			}
			// Compare the complete core message to preserve all other REALITY fields.
			show := cfg.REALITYConfigs != nil && cfg.REALITYConfigs.Show
			expected := &conf.REALITYConfig{
				Show: show, Dest: mustJSONDest(remote.Dest),
				PrivateKey: remote.PrivateKey, ServerNames: remote.ServerNames, ShortIds: remote.ShortIds,
				Xver: remote.ProxyProtocolVer, MinClientVer: tc.selected,
				MaxClientVer: remote.MaxClientVer, MaxTimeDiff: remote.MaxTimeDiff,
			}
			if tc.localMode {
				local := cfg.REALITYConfigs
				expected.Dest, expected.Xver = mustJSONDest(local.Dest), local.ProxyProtocolVer
				expected.ServerNames = local.ServerNames
				expected.MaxClientVer, expected.MaxTimeDiff = local.MaxClientVer, local.MaxTimeDiff
				expected.ShortIds = append(append([]string(nil), local.ShortIds...), remote.ShortIds...)
				// Existing local mode uses the remote key when a remote config exists.
			}
			want, err := expected.Build()
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(security, want) {
				t.Fatal("REALITY fields differ from the selected source configuration")
			}
			id := uuid.New()
			users := []api.UserInfo{{UID: 1, Email: "test@example.invalid", UUID: id.String()}}
			controller := &Controller{Tag: "test", config: cfg, nodeInfo: node}
			user, err := controller.buildVlessUser(&users)[0].Account.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			if account := user.(*vless.Account); account.Id != id.String() || account.Flow != "xtls-rprx-vision" {
				t.Fatal("VLESS identity or Vision flow changed")
			}
			after, err := json.Marshal([]any{cfg, node})
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("input configuration mutated")
			}
		})
	}
}

func TestREALITYMinClientVersionInvalidSelection(t *testing.T) {
	for _, tc := range []struct{ name, remote, local string }{
		{"invalid_remote_not_overridden", "invalid", "1.8.2"},
		{"invalid_local_fallback_rejected", "", "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{DisableLocalREALITYConfig: true, REALITYConfigs: &REALITYConfig{MinClientVer: tc.local}}
			node := &api.NodeInfo{NodeType: "Vless", Port: 12345, TransportProtocol: "tcp", EnableREALITY: true,
				REALITYConfig: &api.REALITYConfig{Dest: "remote.example.invalid:443", PrivateKey: realityKey(t),
					ServerNames: []string{"remote.example.invalid"}, ShortIds: []string{""}, MinClientVer: tc.remote}}
			if _, err := InboundBuilder(cfg, node, "test"); err == nil {
				t.Fatal("invalid selected version bypassed core validation")
			}
		})
	}
}

func TestREALITYMinClientVersionIgnoredWithoutREALITY(t *testing.T) {
	for _, protocol := range []string{"Vless", "Vmess", "Trojan", "Shadowsocks"} {
		t.Run(protocol, func(t *testing.T) {
			node := &api.NodeInfo{NodeType: protocol, Port: 12345, TransportProtocol: "tcp", CypherMethod: "aes-128-gcm"}
			baseline, err := InboundBuilder(&Config{DisableLocalREALITYConfig: true}, node, "test")
			if err != nil {
				t.Fatal(err)
			}
			cfg := &Config{DisableLocalREALITYConfig: true, REALITYConfigs: &REALITYConfig{MinClientVer: "1.8.2"}}
			actual, err := InboundBuilder(cfg, node, "test")
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(actual.ReceiverSettings, baseline.ReceiverSettings) || actual.ProxySettings.Type != baseline.ProxySettings.Type {
				t.Fatal("minimum version changed an unrelated inbound")
			}
			if protocol != "Shadowsocks" && !proto.Equal(actual.ProxySettings, baseline.ProxySettings) {
				t.Fatal("unrelated proxy settings changed")
			}
			// Shadowsocks generates a fresh bootstrap password on each build.
		})
	}
}
