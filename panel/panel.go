package panel

import (
	"encoding/json"
	"log"
	"os"
	"sync"

	"github.com/wyx2685/XrayR/api/bunpanel"
	"github.com/wyx2685/XrayR/api/gov2panel"
	"github.com/wyx2685/XrayR/api/newV2board"
	"github.com/wyx2685/XrayR/app/mydispatcher"

	"dario.cat/mergo"
	"github.com/r3labs/diff/v2"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/wyx2685/XrayR/api"
	"github.com/wyx2685/XrayR/api/pmpanel"
	"github.com/wyx2685/XrayR/api/proxypanel"
	"github.com/wyx2685/XrayR/api/sspanel"
	"github.com/wyx2685/XrayR/api/v2raysocks"
	_ "github.com/wyx2685/XrayR/cmd/distro/all"
	"github.com/wyx2685/XrayR/common/corecompat"
	"github.com/wyx2685/XrayR/service"
	"github.com/wyx2685/XrayR/service/controller"
)

// Panel Structure
type Panel struct {
	access      sync.Mutex
	panelConfig *Config
	Server      *core.Instance
	Service     []service.Service
	Running     bool
}

func New(panelConfig *Config) *Panel {
	p := &Panel{panelConfig: panelConfig}
	return p
}

func (p *Panel) loadCore(panelConfig *Config) *core.Instance {
	// Log Config
	coreLogConfig := &conf.LogConfig{}
	logConfig := getDefaultLogConfig()
	if panelConfig.LogConfig != nil {
		if _, err := diff.Merge(logConfig, panelConfig.LogConfig, logConfig); err != nil {
			log.Panicf("Read Log config failed: %s", err)
		}
	}
	coreLogConfig.LogLevel = logConfig.Level
	coreLogConfig.AccessLog = logConfig.AccessPath
	coreLogConfig.ErrorLog = logConfig.ErrorPath

	// DNS config
	coreDnsConfig := &conf.DNSConfig{}
	if panelConfig.DnsConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.DnsConfigPath); err != nil {
			log.Panicf("Failed to read DNS config file at: %s", panelConfig.DnsConfigPath)
		} else {
			if err = json.Unmarshal(data, coreDnsConfig); err != nil {
				log.Panicf("Failed to unmarshal DNS config: %s", panelConfig.DnsConfigPath)
			}
		}
	}

	// init controller's DNS config
	// for _, config := range p.panelConfig.NodesConfig {
	// 	config.ControllerConfig.DNSConfig = coreDnsConfig
	// }

	dnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		log.Panicf("Failed to understand DNS config, Please check: https://xtls.github.io/config/dns.html for help: %s", err)
	}

	// Routing config
	coreRouterConfig := &conf.RouterConfig{}
	if panelConfig.RouteConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.RouteConfigPath); err != nil {
			log.Panicf("Failed to read Routing config file at: %s", panelConfig.RouteConfigPath)
		} else {
			if err = json.Unmarshal(data, coreRouterConfig); err != nil {
				log.Panicf("Failed to unmarshal Routing config: %s", panelConfig.RouteConfigPath)
			}
		}
	}
	routeConfig, err := coreRouterConfig.Build()
	if err != nil {
		log.Panicf("Failed to understand Routing config  Please check: https://xtls.github.io/config/routing.html for help: %s", err)
	}
	// Read raw transport settings before target conf structs can discard legacy fields.
	var inBoundConfig []*core.InboundHandlerConfig
	if panelConfig.InboundConfigPath != "" {
		data, err := os.ReadFile(panelConfig.InboundConfigPath)
		if err != nil {
			log.Panicf("Failed to read Custom Inbound config: %s", err)
		}
		inBoundConfig, err = corecompat.BuildInboundJSON(data)
		if err != nil {
			log.Panicf("Custom inbound compatibility: %s", err)
		}
	}
	var outBoundConfig []*core.OutboundHandlerConfig
	if panelConfig.OutboundConfigPath != "" {
		data, err := os.ReadFile(panelConfig.OutboundConfigPath)
		if err != nil {
			log.Panicf("Failed to read Custom Outbound config: %s", err)
		}
		outBoundConfig, err = corecompat.BuildOutboundJSON(data)
		if err != nil {
			log.Panicf("Custom outbound compatibility: %s", err)
		}
	}
	// Policy config
	levelPolicyConfig := parseConnectionConfig(panelConfig.ConnectionConfig)
	corePolicyConfig := &conf.PolicyConfig{}
	corePolicyConfig.Levels = map[uint32]*conf.Policy{0: levelPolicyConfig}
	policyConfig, _ := corePolicyConfig.Build()
	// Build Core Config
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(coreLogConfig.Build()),
			serial.ToTypedMessage(&mydispatcher.Config{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(policyConfig),
			serial.ToTypedMessage(dnsConfig),
			serial.ToTypedMessage(routeConfig),
		},
		Inbound:  inBoundConfig,
		Outbound: outBoundConfig,
	}
	server, err := core.New(config)
	if err != nil {
		log.Panicf("failed to create instance: %s", err)
	}
	if err := server.GetFeature(routing.DispatcherType()).(*mydispatcher.DefaultDispatcher).ConfigureDNS(dnsConfig); err != nil {
		server.Close()
		log.Panicf("failed to configure static hosts: %s", err)
	}
	log.Printf("Xray Core Version: %s", core.Version())

	return server
}

// Start the panel
func (p *Panel) Start() {
	p.access.Lock()
	defer p.access.Unlock()
	log.Print("Start the panel..")
	// Load Core
	server := p.loadCore(p.panelConfig)
	if err := server.Start(); err != nil {
		log.Panicf("Failed to start instance: %s", err)
	}
	p.Server = server

	// Load Nodes config
	for _, nodeConfig := range p.panelConfig.NodesConfig {
		var apiClient api.API
		switch nodeConfig.PanelType {
		case "SSpanel":
			apiClient = sspanel.New(nodeConfig.ApiConfig)
		case "NewV2board", "V2board":
			apiClient = newV2board.New(nodeConfig.ApiConfig)
		case "PMpanel":
			apiClient = pmpanel.New(nodeConfig.ApiConfig)
		case "Proxypanel":
			apiClient = proxypanel.New(nodeConfig.ApiConfig)
		case "V2RaySocks":
			apiClient = v2raysocks.New(nodeConfig.ApiConfig)
		case "GoV2Panel":
			apiClient = gov2panel.New(nodeConfig.ApiConfig)
		case "BunPanel":
			apiClient = bunpanel.New(nodeConfig.ApiConfig)
		default:
			log.Panicf("Unsupport panel type: %s", nodeConfig.PanelType)
		}
		var controllerService service.Service
		// Register controller service
		controllerConfig := getDefaultControllerConfig()
		if nodeConfig.ControllerConfig != nil {
			if err := mergo.Merge(controllerConfig, nodeConfig.ControllerConfig, mergo.WithOverride); err != nil {
				log.Panicf("Read Controller Config Failed")
			}
		}
		controllerService = controller.New(server, apiClient, controllerConfig, nodeConfig.PanelType)
		p.Service = append(p.Service, controllerService)

	}

	// Start all the service
	for _, s := range p.Service {
		err := s.Start()
		if err != nil {
			log.Panicf("Panel Start failed: %s", err)
		}
	}
	p.Running = true
	return
}

// Close the panel
func (p *Panel) Close() {
	p.access.Lock()
	defer p.access.Unlock()
	for _, s := range p.Service {
		err := s.Close()
		if err != nil {
			log.Panicf("Panel Close failed: %s", err)
		}
	}
	p.Service = nil
	p.Server.Close()
	p.Running = false
	return
}

func parseConnectionConfig(c *ConnectionConfig) (policy *conf.Policy) {
	connectionConfig := getDefaultConnectionConfig()
	if c != nil {
		if _, err := diff.Merge(connectionConfig, c, connectionConfig); err != nil {
			log.Panicf("Read ConnectionConfig failed: %s", err)
		}
	}
	policy = &conf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
		Handshake:         &connectionConfig.Handshake,
		ConnectionIdle:    &connectionConfig.ConnIdle,
		UplinkOnly:        &connectionConfig.UplinkOnly,
		DownlinkOnly:      &connectionConfig.DownlinkOnly,
		BufferSize:        &connectionConfig.BufferSize,
	}

	return
}
