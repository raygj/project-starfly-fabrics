package operator

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/dynamic"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/starfly-fabrics/starfly/pkg/operator/api/v1alpha1"
)

var starlightFabricGVR = schema.GroupVersionResource{
	Group:    v1alpha1.GroupName,
	Version:  v1alpha1.Version,
	Resource: "starlightfabrics",
}

const defaultPollInterval = 15 * time.Second

// StartEmbeddedPoll reconciles StarlightFabric CRs on an interval using a direct
// API client. This avoids controller-runtime informer cache sync, which times out
// when the operator runs inside the full starfly process on some clusters.
func StartEmbeddedPoll(ctx context.Context, cfg EmbeddedConfig) error {
	if cfg.Connection == nil {
		return fmt.Errorf("embedded operator requires FabricConnection")
	}
	if cfg.Namespace == "" {
		return fmt.Errorf("embedded operator requires namespace")
	}

	restCfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("kubernetes config: %w", err)
	}

	pollScheme := clientgoscheme.Scheme
	if err := v1alpha1.AddToScheme(pollScheme); err != nil {
		return fmt.Errorf("register starlightfabric types: %w", err)
	}

	k8s, err := client.New(restCfg, client.Options{Scheme: pollScheme})
	if err != nil {
		return fmt.Errorf("creating kubernetes client: %w", err)
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("creating dynamic client: %w", err)
	}

	embeddedFabricConnRaw = cfg.Connection
	embeddedFabricConn = BridgeFabricConnection(cfg.Connection)
	reconciler := &FabricReconciler{
		Client: k8s,
		Scheme: pollScheme,
		statusUpdater: func(ctx context.Context, fabric *v1alpha1.StarlightFabric) error {
			return updateFabricStatusDynamic(ctx, dyn, cfg.Namespace, fabric)
		},
	}

	slog.Info("embedded starfly operator polling",
		"namespace", cfg.Namespace,
		"interval", defaultPollInterval,
	)

	ticker := time.NewTicker(defaultPollInterval)
	defer ticker.Stop()

	reconcileAll := func() {
		list, err := dyn.Resource(starlightFabricGVR).Namespace(cfg.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			slog.Error("embedded operator list failed", "error", err)
			return
		}
		for i := range list.Items {
			item := list.Items[i]
			var fabric v1alpha1.StarlightFabric
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &fabric); err != nil {
				slog.Error("embedded operator decode failed", "name", item.GetName(), "error", err)
				continue
			}
			if _, err := reconciler.ReconcileFabric(ctx, &fabric); err != nil {
				slog.Error("embedded operator reconcile failed",
					"name", item.GetName(),
					"error", err,
				)
			}
		}
	}

	reconcileAll()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			reconcileAll()
		}
	}
}

func updateFabricStatusDynamic(ctx context.Context, dyn dynamic.Interface, namespace string, fabric *v1alpha1.StarlightFabric) error {
	ensureFabricGVK(fabric)
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(fabric)
	if err != nil {
		return err
	}
	_, err = dyn.Resource(starlightFabricGVR).Namespace(namespace).UpdateStatus(ctx, &unstructured.Unstructured{Object: obj}, metav1.UpdateOptions{})
	if err == nil {
		return nil
	}
	// On 409 Conflict the resourceVersion is stale (rapid spec edits). Re-fetch and retry once.
	if !isConflict(err) {
		return err
	}
	fresh, getErr := dyn.Resource(starlightFabricGVR).Namespace(namespace).Get(ctx, fabric.Name, metav1.GetOptions{})
	if getErr != nil {
		return err // return original conflict error
	}
	obj["metadata"] = fresh.Object["metadata"] // carry over fresh resourceVersion
	_, err = dyn.Resource(starlightFabricGVR).Namespace(namespace).UpdateStatus(ctx, &unstructured.Unstructured{Object: obj}, metav1.UpdateOptions{})
	return err
}

func isConflict(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "Conflict") || strings.Contains(err.Error(), "409")
}
