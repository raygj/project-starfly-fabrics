package plugin

import (
	"fmt"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// PluginEndpoint configures a single gRPC plugin connection.
type PluginEndpoint struct {
	Address  string `yaml:"address"`
	Platform string `yaml:"platform"` // "mcp", "a2a", "watsonx", "custom"
}

// PluginConfig holds the config for all registered gRPC agent plugins.
type PluginConfig struct {
	Plugins []PluginEndpoint `yaml:"plugins"`
}

// DiscoverPlugins creates a PluginClient for each configured endpoint
// and returns a platform→provider map.
func DiscoverPlugins(cfg PluginConfig, opts ...ClientOption) (map[string]core.AgentIdentityProvider, error) {
	providers := make(map[string]core.AgentIdentityProvider, len(cfg.Plugins))

	for _, ep := range cfg.Plugins {
		if ep.Address == "" || ep.Platform == "" {
			return nil, fmt.Errorf("plugin: endpoint missing address or platform: %+v", ep)
		}

		client, err := NewPluginClient(ep.Address, opts...)
		if err != nil {
			return nil, fmt.Errorf("plugin: connecting to %s (%s): %w", ep.Platform, ep.Address, err)
		}
		providers[ep.Platform] = client
	}

	return providers, nil
}
