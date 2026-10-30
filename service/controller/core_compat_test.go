package controller

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/wyx2685/XrayR/api"
	_ "github.com/wyx2685/XrayR/cmd/distro/all"
	"github.com/xtls/xray-core/app/proxyman"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
)

func realityKey(t *testing.T) string {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes())
}

func TestREALITYConfigurationSources(t *testing.T) {
	key := realityKey(t)
	for _, tc := range []struct {
		name    string
		cfg     *Config
		node    *api.NodeInfo
		wantErr bool
	}{
		{"local", &Config{EnableREALITY: true, REALITYConfigs: &REALITYConfig{Dest: "example.invalid:443", PrivateKey: key, ServerNames: []string{"example.invalid"}, ShortIds: []string{""}}}, &api.NodeInfo{}, false},
		{"remote", &Config{DisableLocalREALITYConfig: true}, &api.NodeInfo{EnableREALITY: true, REALITYConfig: &api.REALITYConfig{Dest: "example.invalid:443", PrivateKey: key, ServerNames: []string{"example.invalid"}, ShortIds: []string{""}}}, false},
		{"disabled", &Config{}, &api.NodeInfo{}, false},
		{"missing-local", &Config{EnableREALITY: true}, &api.NodeInfo{}, true},
		{"missing-remote", &Config{DisableLocalREALITYConfig: true}, &api.NodeInfo{EnableREALITY: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.node.NodeType = "Vless"
			tc.node.Port = 12345
			tc.node.TransportProtocol = "tcp"
			c, err := InboundBuilder(tc.cfg, tc.node, "test")
			if tc.wantErr {
				if err == nil {
					t.Fatal("missing config must return error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			obj, err := c.ReceiverSettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			rs := obj.(*proxyman.ReceiverConfig)
			if tc.name == "disabled" {
				if rs.StreamSettings.SecurityType != "" {
					t.Fatal("unexpected security")
				}
				return
			}
			stream := rs.StreamSettings
			if stream.SecurityType != "xray.transport.internet.reality.Config" || len(stream.SecuritySettings) != 1 {
				t.Fatalf("missing REALITY settings: %v", stream.SecurityType)
			}
			security, err := stream.SecuritySettings[0].GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			if len(security.(*reality.Config).PrivateKey) != 32 {
				t.Fatal("key not transferred")
			}
		})
	}
	if _, err := InboundBuilder(nil, nil, "test"); err == nil {
		t.Fatal("nil inputs accepted")
	}
}

func TestLocalShortIDsDoNotMutateConfiguration(t *testing.T) {
	ids := make([]string, 1, 4)
	ids[0] = "01"
	got := mergeShortIDs(ids, &api.REALITYConfig{ShortIds: []string{"02"}})
	got[0] = "03"
	if ids[0] != "01" || len(ids) != 1 {
		t.Fatal("mutated original config")
	}
	if len(mergeShortIDs(ids, nil)) != 1 {
		t.Fatal("nil remote lost local IDs")
	}
}

func TestProtocolAndTransportBuilders(t *testing.T) {
	for _, protocol := range []string{"Vless", "Vmess", "Trojan", "Shadowsocks"} {
		for _, transport := range []string{"tcp", "ws", "grpc", "httpupgrade", "xhttp"} {
			t.Run(protocol+"/"+transport, func(t *testing.T) {
				node := &api.NodeInfo{NodeType: protocol, Port: 12345, TransportProtocol: transport, CypherMethod: "aes-128-gcm"}
				in, err := InboundBuilder(&Config{}, node, "test")
				if err != nil {
					t.Fatal(err)
				}
				obj, err := in.ReceiverSettings.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				stream := obj.(*proxyman.ReceiverConfig).StreamSettings
				if _, err = internet.ToMemoryStreamConfig(stream); err != nil {
					t.Fatal(err)
				}
				if _, err = OutboundBuilder(&Config{SendIP: "0.0.0.0", EnableDNS: true, DNSType: "UseIP"}, node, "test"); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestVLESSDynamicUsers(t *testing.T) {
	var cfg conf.Config
	if err := json.Unmarshal([]byte(`{"inbounds":[{"tag":"test","listen":"127.0.0.1","port":12345,"protocol":"vless","settings":{"decryption":"none"}}],"outbounds":[{"protocol":"freedom"}],"stats":{}}`), &cfg); err != nil {
		t.Fatal(err)
	}
	cc, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}
	s, err := core.New(cc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := &Controller{server: s, ibm: s.GetFeature(inbound.ManagerType()).(inbound.Manager), Tag: "test", nodeInfo: &api.NodeInfo{VlessFlow: "xtls-rprx-vision"}}
	h, err := c.ibm.GetHandler(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	um := h.(proxy.GetInbound).GetInbound().(proxy.UserManager)
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := uuid.New()
			user := api.UserInfo{UID: n + 1, Email: fmt.Sprintf("user%d@example.invalid", n), UUID: id.String()}
			users := []api.UserInfo{user}
			if err := c.addUsers(c.buildVlessUser(&users), "test"); err != nil {
				t.Error(err)
				return
			}
			email := c.buildUserTag(&user)
			if um.GetUser(context.Background(), email) == nil {
				t.Error("user not authenticated by manager")
			}
			if err := c.removeUsers([]string{email}, "test"); err != nil {
				t.Error(err)
			}
			if um.GetUser(context.Background(), email) != nil {
				t.Error("removed user still present")
			}
		}(n)
	}
	wg.Wait()
	if um.GetUsersCount(context.Background()) != 0 {
		t.Fatal("users left after deletion")
	}
	if err = c.removeUsers([]string{"absent@example.invalid"}, "test"); err == nil {
		t.Fatal("missing user removal not rejected")
	}
}

func TestTrafficAcknowledgementPreservesConcurrentIncrements(t *testing.T) {
	sm, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	c := &Controller{stm: sm}
	counter, err := sm.GetOrRegisterCounter("user>>>test>>>traffic>>>uplink")
	if err != nil {
		t.Fatal(err)
	}
	counter.Add(100)
	up, _, uc, _ := c.getTraffic("test")
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				counter.Add(1)
			}
		}()
	}
	c.resetTraffic([]trafficSnapshot{{uc, up}})
	wg.Wait()
	if counter.Value() != 8000 {
		t.Fatalf("lost concurrent bytes: %d", counter.Value())
	}
}
