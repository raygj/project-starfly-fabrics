package provider

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

var (
	acctestEnv        *envtest.Environment
	acctestKubeconfig string
	acctestHTTP       = &http.Client{Timeout: 10 * time.Second}
)

func TestMain(m *testing.M) {
	if os.Getenv("TF_ACC") == "" {
		os.Exit(m.Run())
	}

	_, thisFile, _, _ := runtime.Caller(0)
	crdPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "deploy", "helm", "crds")
	envCfg := &envtest.Environment{
		CRDDirectoryPaths:     []string{crdPath},
		ErrorIfCRDPathMissing: true,
	}
	if assets := os.Getenv("KUBEBUILDER_ASSETS"); assets != "" {
		envCfg.BinaryAssetsDirectory = assets
	}
	acctestEnv = envCfg

	cfg, err := acctestEnv.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envtest start: %v\n", err)
		os.Exit(1)
	}

	tmp, err := os.CreateTemp("", "starfly-kubeconfig-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "kubeconfig temp: %v\n", err)
		os.Exit(1)
	}
	tmp.Close()
	acctestKubeconfig = tmp.Name()

	if err := writeKubeconfig(cfg, acctestKubeconfig); err != nil {
		fmt.Fprintf(os.Stderr, "write kubeconfig: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	if err := acctestEnv.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "envtest stop: %v\n", err)
	}
	_ = os.Remove(acctestKubeconfig)
	os.Exit(code)
}

func writeKubeconfig(cfg *rest.Config, path string) error {
	config := api.NewConfig()
	config.Clusters["envtest"] = &api.Cluster{
		Server:                   cfg.Host,
		CertificateAuthorityData: cfg.CAData,
	}
	config.AuthInfos["envtest"] = &api.AuthInfo{
		ClientCertificateData: cfg.CertData,
		ClientKeyData:         cfg.KeyData,
	}
	config.Contexts["envtest"] = &api.Context{
		Cluster:  "envtest",
		AuthInfo: "envtest",
	}
	config.CurrentContext = "envtest"
	return clientcmd.WriteToFile(*config, path)
}

func acctestStarflyEndpoint() string {
	if v := os.Getenv("STARFLY_ENDPOINT"); v != "" {
		return v
	}
	return "http://localhost:8693"
}

func skipUnlessStarflyAPI(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC=1 to run acceptance tests")
	}
	api := newAPIClient(acctestStarflyEndpoint(), acctestHTTP, "")
	resp, _, err := api.request(t.Context(), "GET", "/v1/sys/health", nil)
	if err != nil || resp == nil || resp.StatusCode != 200 {
		t.Skipf("Starfly API not reachable at %s: %v", acctestStarflyEndpoint(), err)
	}
}
