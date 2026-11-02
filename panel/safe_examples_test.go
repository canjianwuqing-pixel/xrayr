package panel

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/wyx2685/XrayR/common/corecompat"
	"github.com/xtls/xray-core/infra/conf"
	"gopkg.in/yaml.v3"
)

func TestReleaseTemplateKeepsOriginalFields(t *testing.T) {
	data, err := os.ReadFile("../release/config/config.yml.example")
	if err != nil {
		t.Fatal(err)
	}
	var root yaml.Node
	if err = yaml.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	var walk func(*yaml.Node, string)
	walk = func(n *yaml.Node, path string) {
		switch n.Kind {
		case yaml.DocumentNode:
			for _, child := range n.Content {
				walk(child, path)
			}
		case yaml.MappingNode:
			for i := 0; i < len(n.Content); i += 2 {
				key, value := n.Content[i].Value, n.Content[i+1]
				next := path + "/" + key
				paths[next] = true
				switch key {
				case "ApiHost", "ApiKey", "PrivateKey", "PublicKey", "RedisPassword", "ALICLOUD_ACCESS_KEY", "ALICLOUD_SECRET_KEY":
					if value.Value != "" {
						t.Errorf("template embeds a local credential/address at %s", next)
					}
				case "NodeID":
					if value.Value != "0" {
						t.Errorf("template embeds a configured node at %s", next)
					}
				}
				walk(value, next)
			}
		case yaml.SequenceNode:
			for _, child := range n.Content {
				walk(child, path+"[]")
			}
		}
	}
	walk(&root, "")
	keys := make([]string, 0, len(paths))
	for path := range paths {
		keys = append(keys, path)
	}
	sort.Strings(keys)
	// Key paths from the original 0bb4713 template, without copying its values.
	if len(keys) != 78 || fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(keys, "\n")))) != "e0c209031242f65248258e52c659dc91a675824aa0541adbc15e2c6a45353441" {
		t.Fatal("original YAML fields or nesting changed")
	}
}

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
