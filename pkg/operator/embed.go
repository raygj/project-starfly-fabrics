package operator

import (
	"context"
	"fmt"
	"log/slog"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	v1alpha1 "github.com/starfly-fabrics/starfly/pkg/operator/api/v1alpha1"
	"github.com/starfly-fabrics/starfly/pkg/soul"
)

var embeddedScheme = runtime.NewScheme()

// embeddedFabricConn is wired by StartEmbedded; kept outside FabricReconciler so
// controller-runtime does not reflect-inject the connection field.
var embeddedFabricConn FabricConnection
var embeddedFabricConnRaw FabricConnection

func init() {
	utilruntime.Must(v1alpha1.AddToScheme(embeddedScheme))
}

// EmbeddedConfig configures the in-process CRD operator.
type EmbeddedConfig struct {
	Namespace      string
	Connection     FabricConnection
	LeaderElection bool
	LeaseName      string
}

// StartEmbedded runs the StarlightFabric controller against an in-process FabricConnection.
func StartEmbedded(ctx context.Context, cfg EmbeddedConfig) error {
	if cfg.Connection == nil {
		return fmt.Errorf("embedded operator requires FabricConnection")
	}
	if cfg.Namespace == "" {
		return fmt.Errorf("embedded operator requires namespace")
	}
	if cfg.LeaseName == "" {
		cfg.LeaseName = "starfly-operator-leader"
	}

	restCfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("kubernetes config: %w", err)
	}

	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                 embeddedScheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		LeaderElection:         cfg.LeaderElection,
		LeaderElectionID:       cfg.LeaseName,
	})
	if err != nil {
		return fmt.Errorf("creating manager: %w", err)
	}

	reconciler := &FabricReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}
	embeddedFabricConnRaw = cfg.Connection
	embeddedFabricConn = BridgeFabricConnection(cfg.Connection)
	if err := reconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup reconciler: %w", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("healthz: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("readyz: %w", err)
	}

	slog.Info("embedded starfly operator starting",
		"namespace", cfg.Namespace,
		"leader_election", cfg.LeaderElection,
	)
	return mgr.Start(ctx)
}

// desiredSpecSetter is implemented by connections that need the CRD desired manifest during ApplyAction.
type desiredSpecSetter interface {
	SetDesiredSpec(*soul.SoulManifest)
}

// setDesiredSpecOnConnection stores the desired manifest on connections that support runtime apply.
func setDesiredSpecOnConnection(_ FabricConnection, spec *soul.SoulManifest) {
	conn := embeddedFabricConnRaw
	if conn == nil {
		conn = embeddedFabricConn
	}
	if setter, ok := conn.(desiredSpecSetter); ok {
		setter.SetDesiredSpec(spec)
	}
}

var _ desiredSpecSetter = (*InProcessConnection)(nil)
