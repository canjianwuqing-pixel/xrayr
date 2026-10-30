package panel

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	routingsession "github.com/xtls/xray-core/features/routing/session"
)

func TestCustomDNSInboundOutboundAndRoute(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg := &Config{
		DnsConfigPath:      write("dns.json", `{"hosts":{"full:custom.example.invalid":"192.0.2.11"},"servers":[]}`),
		RouteConfigPath:    write("route.json", `{"domainStrategy":"AsIs","rules":[{"type":"field","domain":["full:custom.example.invalid"],"outboundTag":"custom-out"}]}`),
		InboundConfigPath:  write("in.json", `[{"tag":"custom-in","listen":"127.0.0.1","port":12345,"protocol":"socks","settings":{"auth":"noauth","udp":true}}]`),
		OutboundConfigPath: write("out.json", `[{"tag":"custom-out","protocol":"blackhole","settings":{}}]`),
	}
	p := New(cfg)
	s := p.loadCore(cfg)
	defer s.Close() // No Start: no listening socket or panel request.
	ctx := context.Background()
	if _, err := s.GetFeature(inbound.ManagerType()).(inbound.Manager).GetHandler(ctx, "custom-in"); err != nil {
		t.Fatal(err)
	}
	if s.GetFeature(outbound.ManagerType()).(outbound.Manager).GetHandler("custom-out") == nil {
		t.Fatal("custom outbound missing")
	}
	ips, ttl, err := s.GetFeature(dns.ClientType()).(dns.Client).LookupIP("custom.example.invalid", dns.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.11" || ttl == 0 {
		t.Fatalf("custom DNS: %v %d %v", ips, ttl, err)
	}
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: net.TCPDestination(net.ParseAddress("custom.example.invalid"), 443)}})
	route, err := s.GetFeature(routing.RouterType()).(routing.Router).PickRoute(routingsession.AsRoutingContext(ctx))
	if err != nil || route.GetOutboundTag() != "custom-out" {
		t.Fatalf("custom route: %v %v", route, err)
	}
}
