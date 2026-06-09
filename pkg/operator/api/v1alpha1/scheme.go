package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// SchemeBuilder is used to add go types to the GroupVersionResource scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	gv := schema.GroupVersion{Group: GroupName, Version: Version}
	scheme.AddKnownTypes(gv,
		&StarlightFabric{},
		&StarlightFabricList{},
	)
	metav1.AddToGroupVersion(scheme, gv)
	return nil
}
