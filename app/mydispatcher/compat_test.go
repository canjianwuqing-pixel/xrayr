package mydispatcher

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/wyx2685/XrayR/api"
	"github.com/wyx2685/XrayR/common/limiter"
	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/proxyman"
	appoutbound "github.com/xtls/xray-core/app/proxyman/outbound"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport"
)

func TestHostsAndLookupIPTTL(t *testing.T) {
	var cfg conf.DNSConfig
	if err := json.Unmarshal([]byte(`{"hosts":{"full:host.example.invalid":"192.0.2.12","full:alias.example.invalid":"host.example.invalid"},"servers":[]}`), &cfg); err != nil {
		t.Fatal(err)
	}
	c, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}
	d := new(DefaultDispatcher)
	if err = d.ConfigureHosts(c.StaticHosts); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"host.example.invalid", "alias.example.invalid"} {
		addrs, err := d.hosts.Lookup(domain, dns.IPOption{IPv4Enable: true, IPv6Enable: true})
		if err != nil || len(addrs) != 1 || addrs[0].String() != "192.0.2.12" {
			t.Fatalf("hosts %s: %v %v", domain, addrs, err)
		}
	}
	addrs, err := d.hosts.Lookup("missing.example.invalid", dns.IPOption{IPv4Enable: true})
	if err != nil || len(addrs) != 0 {
		t.Fatal("unmatched hosts must not resolve externally")
	}
	client, err := appdns.New(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var dc dns.Client = client
	ips, ttl, err := dc.LookupIP("host.example.invalid", dns.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.12" || ttl != 10 {
		t.Fatalf("LookupIP: %v %d %v", ips, ttl, err)
	}
}

type sniffResult string

func (s sniffResult) Domain() string   { return string(s) }
func (s sniffResult) Protocol() string { return "tls" }

func TestDomainExcludedFromSniffOverride(t *testing.T) {
	rules, err := geodata.ParseDomainRules([]string{"full:excluded.example.invalid", "domain:skip.example.invalid"}, geodata.Domain_Full)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := geodata.DomainReg.BuildDomainMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}
	d := new(DefaultDispatcher)
	req := session.SniffingRequest{ExcludeForDomain: matcher, OverrideDestinationForProtocol: []string{"tls"}}
	dest := net.TCPDestination(net.ParseAddress("192.0.2.1"), 443)
	for _, domain := range []string{"EXCLUDED.example.invalid", "child.skip.example.invalid", ""} {
		if d.shouldOverride(context.Background(), sniffResult(domain), req, dest) {
			t.Fatalf("overrode excluded/empty domain %q", domain)
		}
	}
	if !d.shouldOverride(context.Background(), sniffResult("allowed.example.invalid"), req, dest) {
		t.Fatal("allowed domain not overridden")
	}
}

func TestHostsQueryStrategyAndFQDN(t *testing.T) {
	var cfg conf.DNSConfig
	if err := json.Unmarshal([]byte(`{"hosts":{"full:host.example.invalid":["192.0.2.12","2001:db8::12"]},"queryStrategy":"UseIPv6"}`), &cfg); err != nil {
		t.Fatal(err)
	}
	c, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}
	d := new(DefaultDispatcher)
	if err = d.ConfigureDNS(c); err != nil {
		t.Fatal(err)
	}
	addresses, err := d.lookupHosts("HOST.example.invalid.")
	if err != nil || len(addresses) != 1 || addresses[0].IP().String() != "2001:db8::12" {
		t.Fatalf("query strategy or FQDN ignored: %v %v", addresses, err)
	}
}

type statsPolicy struct{}

func (statsPolicy) Type() interface{}        { return policy.ManagerType() }
func (statsPolicy) Start() error             { return nil }
func (statsPolicy) Close() error             { return nil }
func (statsPolicy) ForSystem() policy.System { return policy.System{} }
func (statsPolicy) ForLevel(uint32) policy.Session {
	p := policy.SessionDefault()
	p.Stats.UserUplink = true
	p.Stats.UserDownlink = true
	return p
}

type echoHandler struct{ target chan net.Destination }

func (*echoHandler) Start() error                         { return nil }
func (*echoHandler) Close() error                         { return nil }
func (*echoHandler) Tag() string                          { return "test" }
func (*echoHandler) SenderSettings() *serial.TypedMessage { return nil }
func (*echoHandler) ProxySettings() *serial.TypedMessage  { return nil }
func (h *echoHandler) Dispatch(ctx context.Context, l *transport.Link) {
	h.target <- session.OutboundsFromContext(ctx)[0].Target
	defer common.Close(l.Writer)
	_ = buf.Copy(l.Reader, l.Writer)
}

func TestDispatchLinkVisionAccountingAndRateWriter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	user := &protocol.MemoryUser{Email: "test|test@example.invalid|1"}
	in := &session.Inbound{Tag: "test", User: user, Source: net.TCPDestination(net.ParseAddress("127.0.0.1"), 12345), CanSpliceCopy: 2}
	ctx = session.ContextWithInbound(ctx, in)
	sm, err := appstats.NewManager(ctx, &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	om, err := appoutbound.New(ctx, &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	h := &echoHandler{target: make(chan net.Destination, 1)}
	if err = om.AddHandler(ctx, h); err != nil {
		t.Fatal(err)
	}
	d := new(DefaultDispatcher)
	if err = d.Init(&Config{}, om, nil, statsPolicy{}, sm, nil); err != nil {
		t.Fatal(err)
	}
	users := []api.UserInfo{{UID: 1, Email: "test@example.invalid", SpeedLimit: 1000}}
	if err = d.Limiter.AddInboundLimiter("test", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	var dnsCfg conf.DNSConfig
	if err = json.Unmarshal([]byte(`{"hosts":{"full:echo.example.invalid":"192.0.2.25"}}`), &dnsCfg); err != nil {
		t.Fatal(err)
	}
	dc, err := dnsCfg.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err = d.ConfigureHosts(dc.StaticHosts); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 30)
	var output bytes.Buffer
	// Drain immediately before the timed writes. DNS setup above can take
	// long enough to refill the bucket on native Linux runners.
	bucket, ok, reject := d.Limiter.GetUserBucket("test", user.Email, "127.0.0.1", true)
	if !ok || reject || !bucket.AllowN(time.Now(), bucket.Burst()) {
		t.Fatal("limiter setup")
	}
	start := time.Now()
	err = d.DispatchLink(ctx, net.TCPDestination(net.ParseAddress("echo.example.invalid"), 443), &transport.Link{Reader: buf.NewReader(bytes.NewReader(payload)), Writer: buf.NewWriter(&output)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, output.Bytes()) {
		t.Fatal("DispatchLink returned before complete echo")
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Fatal("uplink/downlink bypassed shared user rate writer")
	}
	if in.CanSpliceCopy != 3 {
		t.Fatal("raw copy could bypass business wrappers")
	}
	if target := <-h.target; target.Address.String() != "192.0.2.25" {
		t.Fatalf("hosts target: %v", target)
	}
	for _, direction := range []string{"uplink", "downlink"} {
		c := sm.GetCounter("user>>>" + user.Email + ">>>traffic>>>" + direction)
		if c == nil || c.Value() != int64(len(payload)) {
			t.Fatalf("%s accounting mismatch", direction)
		}
	}
}

func TestConcurrentStatsAndUserUpdates(t *testing.T) {
	ctx := context.Background()
	sm, err := appstats.NewManager(ctx, &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	d := &DefaultDispatcher{stats: sm, policy: statsPolicy{}, Limiter: limiter.New()}
	users := []api.UserInfo{{UID: 1, Email: "test@example.invalid", SpeedLimit: 10000000}}
	if err = d.Limiter.AddInboundLimiter("test", 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if err := d.Limiter.UpdateInboundLimiter("test", &users); err != nil {
					t.Error(err)
				}
				cctx := session.ContextWithInbound(ctx, &session.Inbound{Tag: "test", User: &protocol.MemoryUser{Email: "test|test@example.invalid|1"}, Source: net.TCPDestination(net.ParseAddress("127.0.0.1"), 12345)})
				in, out, err := d.getLink(cctx)
				if err != nil {
					t.Error(err)
					return
				}
				if err = in.Writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte("abc"))); err != nil {
					t.Error(err)
				}
				mb, err := out.Reader.ReadMultiBuffer()
				buf.ReleaseMulti(mb)
				if err != nil {
					t.Error(err)
				}
				common.Close(in.Writer)
				common.Close(out.Writer)
				common.Interrupt(in.Reader)
				common.Interrupt(out.Reader)
			}
		}()
	}
	wg.Wait()
	c := sm.GetCounter("user>>>test|test@example.invalid|1>>>traffic>>>uplink")
	if c == nil || c.Value() != 1200 {
		t.Fatal("concurrent accounting lost bytes")
	}
}
