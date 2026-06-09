package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto copies all properties into another StarlightFabric.
func (in *StarlightFabric) DeepCopyInto(out *StarlightFabric) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy returns a deep copy of StarlightFabric.
func (in *StarlightFabric) DeepCopy() *StarlightFabric {
	if in == nil {
		return nil
	}
	out := new(StarlightFabric)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject returns a deep copy as runtime.Object.
func (in *StarlightFabric) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

// DeepCopyInto copies spec fields.
func (in *StarlightFabricSpec) DeepCopyInto(out *StarlightFabricSpec) {
	*out = *in
	if in.TrustDomains != nil {
		out.TrustDomains = make([]TrustDomainSpec, len(in.TrustDomains))
		copy(out.TrustDomains, in.TrustDomains)
	}
	if in.SigningKeys != nil {
		out.SigningKeys = make([]SigningKeySpec, len(in.SigningKeys))
		copy(out.SigningKeys, in.SigningKeys)
	}
	if in.SSFStreams != nil {
		out.SSFStreams = make([]SSFStreamSpec, len(in.SSFStreams))
		for i := range in.SSFStreams {
			in.SSFStreams[i].DeepCopyInto(&out.SSFStreams[i])
		}
	}
	if in.Anchor != nil {
		out.Anchor = new(AnchorSpec)
		*out.Anchor = *in.Anchor
	}
	if in.Policy != nil {
		out.Policy = new(PolicySpec)
		*out.Policy = *in.Policy
	}
	if in.Federation != nil {
		out.Federation = new(FederationSpec)
		in.Federation.DeepCopyInto(out.Federation)
	}
}

// DeepCopyInto copies FederationSpec fields.
func (in *FederationSpec) DeepCopyInto(out *FederationSpec) {
	*out = *in
	if in.Peers != nil {
		out.Peers = make([]FederationPeerSpec, len(in.Peers))
		copy(out.Peers, in.Peers)
	}
}

// DeepCopy returns a deep copy of StarlightFabricSpec.
func (in *StarlightFabricSpec) DeepCopy() *StarlightFabricSpec {
	if in == nil {
		return nil
	}
	out := new(StarlightFabricSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies SSFStreamSpec fields.
func (in *SSFStreamSpec) DeepCopyInto(out *SSFStreamSpec) {
	*out = *in
	if in.EventsRequested != nil {
		out.EventsRequested = make([]string, len(in.EventsRequested))
		copy(out.EventsRequested, in.EventsRequested)
	}
}

// DeepCopyInto copies status fields.
func (in *StarlightFabricStatus) DeepCopyInto(out *StarlightFabricStatus) {
	*out = *in
	if in.LastConvergence != nil {
		out.LastConvergence = in.LastConvergence.DeepCopy()
	}
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
}

// DeepCopy returns a deep copy of StarlightFabricStatus.
func (in *StarlightFabricStatus) DeepCopy() *StarlightFabricStatus {
	if in == nil {
		return nil
	}
	out := new(StarlightFabricStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies list fields.
func (in *StarlightFabricList) DeepCopyInto(out *StarlightFabricList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]StarlightFabric, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy returns a deep copy of StarlightFabricList.
func (in *StarlightFabricList) DeepCopy() *StarlightFabricList {
	if in == nil {
		return nil
	}
	out := new(StarlightFabricList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject returns a deep copy as runtime.Object.
func (in *StarlightFabricList) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}
