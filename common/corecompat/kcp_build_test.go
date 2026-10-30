package corecompat

import (
	"encoding/json"
	"fmt"
	"testing"

	kcp "github.com/wyx2685/XrayR/common/corecompat/legacykcp"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/transport/internet"
)

func builtKCP(t *testing.T, settings string) *kcp.Config {
	t.Helper()
	handlers, err := BuildOutboundJSON([]byte(`[{"protocol":"freedom","streamSettings":{"network":"kcp","kcpSettings":` + settings + `}}]`))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := handlers[0].SenderSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	stream := obj.(*proxyman.SenderConfig).StreamSettings
	if stream.ProtocolName != "kuaiyun-kcp" {
		t.Fatal("legacy algorithm not selected")
	}
	memory, err := internet.ToMemoryStreamConfig(stream)
	if err != nil {
		t.Fatal(err)
	}
	return memory.ProtocolSettings.(*kcp.Config)
}
func TestKCPRawTuningAndSeedStates(t *testing.T) {
	for _, test := range []struct {
		fields string
		size   uint32
		seed   *string
	}{
		{`{}`, 2 << 20, nil},
		{`{"seed":null,"header":null,"congestion":null}`, 2 << 20, nil},
		{`{"writeBufferSize":0}`, 512 << 10, nil},
		{`{"WRITEBUFFERSIZE":3,"ReadBufferSize":7,"Congestion":true}`, 3 << 20, nil},
		{`{"maxSendingWindow":576,"mtu":576}`, 576, nil},
	} {
		c := builtKCP(t, test.fields)
		if c.GetWriteBufferSize() != test.size {
			t.Fatal(c.GetWriteBufferSize())
		}
	}
	c := builtKCP(t, `{"ReadBufferSize":7,"Congestion":true}`)
	if !c.Congestion || c.GetReadBufferSize() != 7<<20 {
		t.Fatal("legacy fields lost")
	}
	for _, raw := range []string{`{}`, `{"seed":""}`, `{"seed":"non-secret-seed"}`} {
		c := builtKCP(t, raw)
		security, err := c.GetSecurity()
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		json.Unmarshal([]byte(raw), &obj)
		if (c.Seed == nil) != (obj["seed"] == nil) {
			t.Fatal("seed presence lost")
		}
		if (security.NonceSize() == 0) != (c.Seed == nil) {
			t.Fatal("empty seed selected original framing")
		}
	}
}

func TestKCPInboundAndModernBoundary(t *testing.T) {
	result, err := BuildInboundJSON([]byte(`[{"port":12345,"listen":"127.0.0.1","protocol":"vless","settings":{"clients":[],"decryption":"none"},"StreamSettings":{"Network":"mkcp","KcpSettings":{"Seed":"","Congestion":true}}}]`))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := result[0].ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	stream := obj.(*proxyman.ReceiverConfig).StreamSettings
	memory, err := internet.ToMemoryStreamConfig(stream)
	if err != nil {
		t.Fatal(err)
	}
	c := memory.ProtocolSettings.(*kcp.Config)
	if c.Seed == nil || c.Seed.Seed != "" || !c.Congestion {
		t.Fatal("custom inbound lost fields")
	}
	modern, err := BuildOutboundJSON([]byte(`[{"protocol":"freedom","streamSettings":{"network":"mkcp","kcpSettings":{"cwndMultiplier":2},"finalmask":{"udp":[{"type":"mkcp-legacy"}]}}}]`))
	if err != nil {
		t.Fatal(err)
	}
	obj, err = modern[0].SenderSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	if obj.(*proxyman.SenderConfig).StreamSettings.ProtocolName != "mkcp" {
		t.Fatal("explicit modern transport redirected")
	}
}
func TestKCPBoundariesAndAmbiguity(t *testing.T) {
	invalid := []string{
		`{"writeBufferSize":4096}`, `{"writeBufferSize":-1}`, `{"writeBufferSize":1.5}`,
		`{"writeBufferSize":1,"maxSendingWindow":1048576}`, `{"maxSendingWindow":1349}`,
		`{"mtu":575}`, `{"mtu":1461}`, `{"tti":9}`, `{"tti":101}`,
		`{"uplinkCapacity":4096}`,
		`{"congestion":true,"Congestion":false}`, `{"ReadBufferSize":1,"readBufferSize":2}`,
		`{"congestIon":"true"}`, `{"unknown":1}`, `{"header":{"Type":"srtp","type":"dtls"}}`,
	}
	for _, raw := range invalid {
		t.Run(raw, func(t *testing.T) {
			_, err := BuildOutboundJSON([]byte(`[{"protocol":"freedom","streamSettings":{"network":"kcp","kcpSettings":` + raw + `}}]`))
			if err == nil {
				t.Fatal("invalid/ambiguous setting accepted")
			}
		})
	}
	for _, field := range []string{`"Congestion":true`, `"readBufferSize":0`, `"seed":""`, `"header":{"type":"none"}`} {
		raw := fmt.Sprintf(`[{"protocol":"freedom","streamSettings":{"network":"kcp","kcpSettings":{%s},"finalmask":{"udp":[{"type":"mkcp-legacy"}]}}}]`, field)
		if _, err := BuildOutboundJSON([]byte(raw)); err == nil {
			t.Fatal("legacy/finalmask conflict", field)
		}
	}
	if c := builtKCP(t, `{"writeBufferSize":4095}`); c.GetWriteBufferSize() != uint32(4095<<20) {
		t.Fatal("maximum valid window changed")
	}
}
