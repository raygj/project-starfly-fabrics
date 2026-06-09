package provider

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	starflyv1 "github.com/starfly-fabrics/starfly/pkg/operator/api/v1alpha1"
)

var starlightFabricGVR = schema.GroupVersionResource{
	Group:    starflyv1.GroupName,
	Version:  starflyv1.Version,
	Resource: "starlightfabrics",
}

var starlightFabricGVK = schema.GroupVersionKind{
	Group:   starflyv1.GroupName,
	Version: starflyv1.Version,
	Kind:    "StarlightFabric",
}

func newDynamicClient(cfg *rest.Config) (dynamic.Interface, error) {
	return dynamic.NewForConfig(cfg)
}

func fabricToUnstructured(fabric *starflyv1.StarlightFabric) (*unstructured.Unstructured, error) {
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(fabric)
	if err != nil {
		return nil, fmt.Errorf("convert fabric to unstructured: %w", err)
	}
	u := &unstructured.Unstructured{Object: obj}
	u.SetGroupVersionKind(starlightFabricGVK)
	return u, nil
}

func unstructuredToFabric(u *unstructured.Unstructured) (*starflyv1.StarlightFabric, error) {
	fabric := &starflyv1.StarlightFabric{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, fabric); err != nil {
		return nil, fmt.Errorf("convert unstructured to fabric: %w", err)
	}
	return fabric, nil
}

func createFabric(ctx context.Context, client dynamic.Interface, fabric *starflyv1.StarlightFabric) error {
	u, err := fabricToUnstructured(fabric)
	if err != nil {
		return err
	}
	_, err = client.Resource(starlightFabricGVR).Namespace(fabric.Namespace).Create(ctx, u, metav1.CreateOptions{})
	return err
}

func getFabric(ctx context.Context, client dynamic.Interface, namespace, name string) (*starflyv1.StarlightFabric, error) {
	u, err := client.Resource(starlightFabricGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return unstructuredToFabric(u)
}

func updateFabric(ctx context.Context, client dynamic.Interface, fabric *starflyv1.StarlightFabric) error {
	u, err := fabricToUnstructured(fabric)
	if err != nil {
		return err
	}
	_, err = client.Resource(starlightFabricGVR).Namespace(fabric.Namespace).Update(ctx, u, metav1.UpdateOptions{})
	return err
}

func deleteFabric(ctx context.Context, client dynamic.Interface, namespace, name string) error {
	return client.Resource(starlightFabricGVR).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{})
}
