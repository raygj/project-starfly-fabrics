package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	starflyv1 "github.com/starfly-fabrics/starfly/pkg/operator/api/v1alpha1"
)

const (
	defaultNamespace = "starfly-system"
)

// Ensure StarflyProvider satisfies provider.Provider.
var _ provider.Provider = (*StarflyProvider)(nil)

type StarflyProvider struct {
	version string
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &StarflyProvider{version: version}
	}
}

func (p *StarflyProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "starfly"
	resp.Version = p.version
}

func (p *StarflyProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage Starfly fabrics declaratively. CRD resources use the Kubernetes API; " +
			"runtime resources use the Starfly HTTP API over mTLS.",
		Attributes: map[string]schema.Attribute{
			"kubeconfig_path": schema.StringAttribute{
				Optional:    true,
				Description: "Path to kubeconfig. Falls back to KUBECONFIG env var, then in-cluster config.",
			},
			"namespace": schema.StringAttribute{
				Optional:    true,
				Description: "Default namespace for Starfly resources.",
			},
			"endpoint": schema.StringAttribute{
				Optional:    true,
				Description: "Starfly API endpoint for runtime resources (e.g. https://starfly:8694). Falls back to STARFLY_ENDPOINT.",
			},
			"ca_cert": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "PEM-encoded CA certificate for Starfly API mTLS. File path or inline PEM. Falls back to STARFLY_CA_CERT.",
			},
			"client_cert": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "PEM-encoded client certificate for Starfly API mTLS. Falls back to STARFLY_CLIENT_CERT.",
			},
			"client_key": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "PEM-encoded client private key for Starfly API mTLS. Falls back to STARFLY_CLIENT_KEY.",
			},
			"jwt_token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "JWT bearer token for Starfly API auth (Phase 2 — not yet implemented). Falls back to STARFLY_JWT_TOKEN.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
		},
	}
}

type providerConfig struct {
	KubeconfigPath types.String `tfsdk:"kubeconfig_path"`
	Namespace      types.String `tfsdk:"namespace"`
	Endpoint       types.String `tfsdk:"endpoint"`
	CACert         types.String `tfsdk:"ca_cert"`
	ClientCert     types.String `tfsdk:"client_cert"`
	ClientKey      types.String `tfsdk:"client_key"`
	JWTToken       types.String `tfsdk:"jwt_token"`
}

func (p *StarflyProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerConfig
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	kubeconfigPath := firstNonEmpty(config.KubeconfigPath.ValueString(), os.Getenv("KUBECONFIG"))
	namespace := firstNonEmpty(config.Namespace.ValueString(), defaultNamespace)
	endpoint := firstNonEmpty(config.Endpoint.ValueString(), os.Getenv("STARFLY_ENDPOINT"))
	caCert := firstNonEmpty(config.CACert.ValueString(), os.Getenv("STARFLY_CA_CERT"))
	clientCert := firstNonEmpty(config.ClientCert.ValueString(), os.Getenv("STARFLY_CLIENT_CERT"))
	clientKey := firstNonEmpty(config.ClientKey.ValueString(), os.Getenv("STARFLY_CLIENT_KEY"))
	jwtToken := firstNonEmpty(config.JWTToken.ValueString(), os.Getenv("STARFLY_JWT_TOKEN"))

	if jwtToken != "" {
		tflog.Debug(ctx, "JWT auth enabled for Starfly API resources")
	}

	kubeConfig, err := loadKubeRESTConfig(kubeconfigPath)
	if err != nil {
		resp.Diagnostics.AddError("Unable to configure Kubernetes client", err.Error())
		return
	}

	httpClient, err := buildHTTPClient(caCert, clientCert, clientKey)
	if err != nil {
		resp.Diagnostics.AddError("Unable to configure Starfly HTTP client", err.Error())
		return
	}

	clients := &Clients{
		KubeConfig: kubeConfig,
		Namespace:  namespace,
		Endpoint:   endpoint,
		HTTPClient: httpClient,
		API:        newAPIClient(endpoint, httpClient, jwtToken),
	}

	tflog.Debug(ctx, "Configured Starfly provider", map[string]any{
		"namespace": namespace,
		"endpoint":  endpoint,
	})

	resp.DataSourceData = clients
	resp.ResourceData = clients
}

func (p *StarflyProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewFabricResource,
		NewMCPToolResource,
		NewSSFStreamResource,
		NewAgentIdentityResource,
		NewEncryptionKeyResource,
	}
}

func (p *StarflyProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func loadKubeRESTConfig(kubeconfigPath string) (*rest.Config, error) {
	if err := starflyv1.AddToScheme(scheme.Scheme); err != nil {
		return nil, fmt.Errorf("register starfly scheme: %w", err)
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		loadingRules.ExplicitPath = kubeconfigPath
	}

	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	restConfig, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	return restConfig, nil
}

func buildHTTPClient(caCert, clientCert, clientKey string) (*http.Client, error) {
	if caCert == "" && clientCert == "" && clientKey == "" {
		return &http.Client{Timeout: 30 * time.Second}, nil
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if caCert != "" {
		caPEM, err := loadPEM(caCert)
		if err != nil {
			return nil, fmt.Errorf("load ca_cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse ca_cert PEM")
		}
		tlsConfig.RootCAs = pool
	}

	if clientCert != "" || clientKey != "" {
		if clientCert == "" || clientKey == "" {
			return nil, fmt.Errorf("client_cert and client_key must both be set for mTLS")
		}
		certPEM, err := loadPEM(clientCert)
		if err != nil {
			return nil, fmt.Errorf("load client_cert: %w", err)
		}
		keyPEM, err := loadPEM(clientKey)
		if err != nil {
			return nil, fmt.Errorf("load client_key: %w", err)
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

func loadPEM(value string) ([]byte, error) {
	if data, err := os.ReadFile(value); err == nil {
		return data, nil
	}
	return []byte(value), nil
}

// Clients holds configured clients shared by resources.
type Clients struct {
	KubeConfig *rest.Config
	Namespace  string
	Endpoint   string
	HTTPClient *http.Client
	API        *APIClient
}

// NamespaceOrDefault returns the resource namespace or the provider default.
func (c *Clients) NamespaceOrDefault(ns string) string {
	if ns != "" {
		return ns
	}
	return c.Namespace
}

// DiagError converts an error into a diagnostic.
func DiagError(summary string, err error) diag.Diagnostics {
	var diags diag.Diagnostics
	diags.AddError(summary, err.Error())
	return diags
}
