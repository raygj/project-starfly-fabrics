package operator

import (
	"context"

	"github.com/starfly-fabrics/starfly/pkg/soul"
)

// bridgedConnection delegates to a FabricConnection without retaining the concrete
// implementation type. Storing *InProcessConnection (even behind an interface
// field) breaks controller-runtime StarlightFabric cache sync on some clusters.
type bridgedConnection struct {
	currentManifest func(context.Context) (*soul.SoulManifest, error)
	applyAction     func(context.Context, soul.ConvergenceAction) error
	applyPlan       func(context.Context, *soul.ConvergencePlan) (*ApplyResult, error)
	health          func(context.Context) (*HealthStatus, error)
}

// BridgeFabricConnection wraps conn for embedded operator use.
func BridgeFabricConnection(conn FabricConnection) FabricConnection {
	if conn == nil {
		return nil
	}
	if _, ok := conn.(bridgedConnection); ok {
		return conn
	}
	return bridgedConnection{
		currentManifest: conn.CurrentManifest,
		applyAction:     conn.ApplyAction,
		applyPlan:       conn.ApplyPlan,
		health:          conn.Health,
	}
}

func (b bridgedConnection) CurrentManifest(ctx context.Context) (*soul.SoulManifest, error) {
	return b.currentManifest(ctx)
}

func (b bridgedConnection) ApplyAction(ctx context.Context, action soul.ConvergenceAction) error {
	return b.applyAction(ctx, action)
}

func (b bridgedConnection) ApplyPlan(ctx context.Context, plan *soul.ConvergencePlan) (*ApplyResult, error) {
	return b.applyPlan(ctx, plan)
}

func (b bridgedConnection) Health(ctx context.Context) (*HealthStatus, error) {
	return b.health(ctx)
}
