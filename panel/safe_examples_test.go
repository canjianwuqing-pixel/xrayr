package panel

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/wyx2685/XrayR/common/corecompat"
	"github.com/xtls/xray-core/infra/conf"
)

func TestSafeOutboundAndRouteSample(t *testing.T) {
	data, err := os.ReadFile("../release/config/custom_outbound.json")
	if err != nil {
		t.Fatal(err)
	}
	var configs []conf.OutboundDetourConfig
	if err = json.Unmarshal(data, &configs); err != nil {
		t.Fatal(err)
	}
	tags := map[string]bool{}
	for _, c := range configs {
		if c.Protocol == "wireguard" || c.Tag == "warp" {
			t.Fatal("credential-bearing WARP sample retained")
		}
		tags[c.Tag] = true
	}
	if _, err = corecompat.BuildOutboundJSON(data); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile("../release/config/route.json")
	if err != nil {
		t.Fatal(err)
	}
	var route struct {
		Rules []struct {
			Outbound string `json:"outboundTag"`
		}
	}
	if err = json.Unmarshal(data, &route); err != nil {
		t.Fatal(err)
	}
	for _, r := range route.Rules {
		if !tags[r.Outbound] {
			t.Fatal("dangling sample route", r.Outbound)
		}
	}
}
