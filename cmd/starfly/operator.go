package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/starfly-fabrics/starfly/pkg/operator"
)

func runOperator(args []string) int {
	fs := flag.NewFlagSet("operator", flag.ExitOnError)
	var (
		leaderElect bool
		leaseName   string
	)
	fs.BoolVar(&leaderElect, "leader-elect", false, "enable leader election")
	fs.StringVar(&leaseName, "leader-elect-lease", "starfly-operator-leader", "leader election lease name")
	_ = fs.Parse(args)

	fmt.Fprintln(os.Stderr, `standalone operator mode requires a remote FabricConnection (not yet implemented).

Use embedded mode instead:
  - Helm: operator.enabled=true, operator.embedded=true (default)
  - Env:  STARFLY_OPERATOR_ENABLED=true on the starfly container

The embedded operator runs in-process with InProcessConnection and reconciles StarlightFabric CRs in STARFLY_NAMESPACE.`)
	return 1
}

// startEmbeddedOperatorIfEnabled launches the CRD reconciler inside the starfly process.
func startEmbeddedOperatorIfEnabled(ctx context.Context, cfg operator.EmbeddedConfig) {
	if os.Getenv("STARFLY_OPERATOR_ENABLED") != "true" {
		return
	}
	if cfg.Namespace == "" {
		cfg.Namespace = os.Getenv("STARFLY_NAMESPACE")
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "starfly-system"
	}
	if os.Getenv("STARFLY_OPERATOR_LEADER_ELECT") == "true" {
		cfg.LeaderElection = true
	}
	if cfg.LeaseName == "" {
		cfg.LeaseName = os.Getenv("STARFLY_OPERATOR_LEASE_NAME")
	}
	go func() {
		if err := operator.StartEmbeddedPoll(ctx, cfg); err != nil && ctx.Err() == nil {
			slog.Error("embedded operator stopped", "error", err)
		}
	}()
}
