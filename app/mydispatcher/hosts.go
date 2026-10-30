package mydispatcher

import (
	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/features/dns"
	"strings"
)

// ConfigureHosts installs the same immutable static mapping used by the core DNS
// feature. It is called before server.Start; it never performs a network lookup.
func (d *DefaultDispatcher) ConfigureHosts(mappings []*appdns.Config_HostMapping) error {
	hosts, err := appdns.NewStaticHosts(mappings)
	if err != nil {
		return err
	}
	d.hosts = hosts
	d.hostsOption = dns.IPOption{IPv4Enable: true, IPv6Enable: true}
	d.hostsSystem = false
	return nil
}

func (d *DefaultDispatcher) ConfigureDNS(config *appdns.Config) error {
	if err := d.ConfigureHosts(config.StaticHosts); err != nil {
		return err
	}
	switch config.QueryStrategy {
	case appdns.QueryStrategy_USE_IP4:
		d.hostsOption.IPv6Enable = false
	case appdns.QueryStrategy_USE_IP6:
		d.hostsOption.IPv4Enable = false
	case appdns.QueryStrategy_USE_SYS:
		d.hostsSystem = true
	}
	return nil
}

func (d *DefaultDispatcher) lookupHosts(domain string) ([]net.Address, error) {
	option := d.hostsOption
	if d.hostsSystem {
		option.IPv4Enable, option.IPv6Enable = utils.CheckRoutes()
	}
	return d.hosts.Lookup(strings.TrimSuffix(domain, "."), option)
}
