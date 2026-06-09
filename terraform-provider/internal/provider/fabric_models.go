package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	starflyv1 "github.com/starfly-fabrics/starfly/pkg/operator/api/v1alpha1"
)

type fabricModel struct {
	ID                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Namespace          types.String `tfsdk:"namespace"`
	Labels             types.Map    `tfsdk:"labels"`
	Annotations        types.Map    `tfsdk:"annotations"`
	TrustDomains       types.List   `tfsdk:"trust_domains"`
	SigningKeys        types.List   `tfsdk:"signing_keys"`
	SSFStreams         types.List   `tfsdk:"ssf_streams"`
	Anchor             types.Object `tfsdk:"anchor"`
	Policy             types.Object `tfsdk:"policy"`
	Federation         types.Object `tfsdk:"federation"`
	SpecHash           types.String `tfsdk:"spec_hash"`
	Phase              types.String `tfsdk:"phase"`
	SoulSequence       types.Int64  `tfsdk:"soul_sequence"`
	TrustDomainsActive types.Int64  `tfsdk:"trust_domains_active"`
	SigningKeysActive  types.Int64  `tfsdk:"signing_keys_active"`
	SSFStreamsActive   types.Int64  `tfsdk:"ssf_streams_active"`
	LastConvergence    types.String `tfsdk:"last_convergence"`
	WaitForConverged   types.Bool   `tfsdk:"wait_for_converged"`
	Timeouts           timeouts.Value `tfsdk:"timeouts"`
}

func (m fabricModel) waitForConverged(ctx context.Context) bool {
	if m.WaitForConverged.IsNull() || m.WaitForConverged.IsUnknown() {
		return true
	}
	return m.WaitForConverged.ValueBool()
}

func (m fabricModel) toStarlightFabric(clients *Clients) *starflyv1.StarlightFabric {
	namespace := clients.NamespaceOrDefault(m.Namespace.ValueString())
	labels := stringMapFromTypes(m.Labels)
	annotations := stringMapFromTypes(m.Annotations)

	spec := starflyv1.StarlightFabricSpec{
		TrustDomains: trustDomainsFromList(m.TrustDomains),
		SigningKeys:  signingKeysFromList(m.SigningKeys),
		SSFStreams:   ssfStreamsFromList(m.SSFStreams),
		Anchor:       anchorFromObject(m.Anchor),
		Policy:       policyFromObject(m.Policy),
		Federation:   federationFromObject(m.Federation),
	}

	return &starflyv1.StarlightFabric{
		TypeMeta: metav1.TypeMeta{
			APIVersion: starflyv1.SchemeGroupVersion.String(),
			Kind:       "StarlightFabric",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        m.Name.ValueString(),
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: spec,
	}
}

func fabricModelFromCRD(fabric *starflyv1.StarlightFabric, defaultNamespace string) (fabricModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	specHash, err := hashStarlightFabricSpec(fabric.Spec)
	if err != nil {
		diags.AddError("Compute spec_hash", err.Error())
	}

	namespace := fabric.Namespace
	if namespace == "" {
		namespace = defaultNamespace
	}

	trustDomains, d := trustDomainsToList(fabric.Spec.TrustDomains)
	diags.Append(d...)
	signingKeys, d := signingKeysToList(fabric.Spec.SigningKeys)
	diags.Append(d...)
	ssfStreams, d := ssfStreamsToList(fabric.Spec.SSFStreams)
	diags.Append(d...)
	anchor, d := anchorToObject(fabric.Spec.Anchor)
	diags.Append(d...)
	policy, d := policyToObject(fabric.Spec.Policy)
	diags.Append(d...)
	federation, d := federationToObject(fabric.Spec.Federation)
	diags.Append(d...)

	lastConvergence := types.StringNull()
	if fabric.Status.LastConvergence != nil {
		lastConvergence = types.StringValue(fabric.Status.LastConvergence.Time.Format(timeRFC3339))
	}

	model := fabricModel{
		ID:                 types.StringValue(fmt.Sprintf("%s/%s", fabric.Namespace, fabric.Name)),
		Name:               types.StringValue(fabric.Name),
		Namespace:          types.StringValue(namespace),
		Labels:             stringMapToTypes(fabric.Labels),
		Annotations:        stringMapToTypes(fabric.Annotations),
		TrustDomains:       trustDomains,
		SigningKeys:        signingKeys,
		SSFStreams:         ssfStreams,
		Anchor:             anchor,
		Policy:             policy,
		Federation:         federation,
		SpecHash:           types.StringValue(specHash),
		Phase:              types.StringValue(fabric.Status.Phase),
		SoulSequence:       types.Int64Value(fabric.Status.SoulSequence),
		TrustDomainsActive: types.Int64Value(int64(fabric.Status.TrustDomainsActive)),
		SigningKeysActive:  types.Int64Value(int64(fabric.Status.SigningKeysActive)),
		SSFStreamsActive:   types.Int64Value(int64(fabric.Status.SSFStreamsActive)),
		LastConvergence:    lastConvergence,
	}

	return model, diags
}

const timeRFC3339 = "2006-01-02T15:04:05Z07:00"

func trustDomainAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"name":      schema.StringAttribute{Required: true},
		"type":      schema.StringAttribute{Required: true},
		"issuer":    schema.StringAttribute{Optional: true},
		"jwks_uri":  schema.StringAttribute{Optional: true},
		"enabled":   schema.BoolAttribute{Optional: true},
	}
}

func signingKeyAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"kid":               schema.StringAttribute{Required: true},
		"algorithm":         schema.StringAttribute{Required: true},
		"kms_key_id":        schema.StringAttribute{Required: true},
		"rotation_policy":   schema.StringAttribute{Optional: true},
		"status":            schema.StringAttribute{Optional: true},
	}
}

func ssfStreamAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"stream_id":         schema.StringAttribute{Required: true},
		"transmitter":       schema.StringAttribute{Required: true},
		"events_requested":  schema.ListAttribute{ElementType: types.StringType, Optional: true},
	}
}

func anchorAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"type":   schema.StringAttribute{Optional: true},
		"bucket": schema.StringAttribute{Optional: true},
		"prefix": schema.StringAttribute{Optional: true},
		"path":   schema.StringAttribute{Optional: true},
	}
}

func policyAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"bundle_path": schema.StringAttribute{Optional: true},
	}
}

func federationAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"peers": schema.ListNestedAttribute{
			Optional: true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: map[string]schema.Attribute{
					"fabric_id":            schema.StringAttribute{Required: true},
					"jwks_endpoint":        schema.StringAttribute{Required: true},
					"mtls_secret":          schema.StringAttribute{Optional: true},
					"refresh_interval":     schema.StringAttribute{Optional: true},
					"staleness_threshold":  schema.StringAttribute{Optional: true},
				},
			},
		},
	}
}

func stringMapFromTypes(m types.Map) map[string]string {
	if m.IsNull() || m.IsUnknown() {
		return nil
	}
	out := make(map[string]string, len(m.Elements()))
	for k, v := range m.Elements() {
		if s, ok := v.(basetypes.StringValue); ok {
			out[k] = s.ValueString()
		}
	}
	return out
}

func stringMapToTypes(in map[string]string) types.Map {
	if len(in) == 0 {
		return types.MapNull(types.StringType)
	}
	elems := make(map[string]attr.Value, len(in))
	for k, v := range in {
		elems[k] = types.StringValue(v)
	}
	return types.MapValueMust(types.StringType, elems)
}

func trustDomainsFromList(list types.List) []starflyv1.TrustDomainSpec {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var models []trustDomainModel
	_ = list.ElementsAs(context.Background(), &models, false)
	out := make([]starflyv1.TrustDomainSpec, 0, len(models))
	for _, m := range models {
		out = append(out, starflyv1.TrustDomainSpec{
			Name:    m.Name.ValueString(),
			Type:    m.Type.ValueString(),
			Issuer:  m.Issuer.ValueString(),
			JWKSURI: m.JWKSURI.ValueString(),
			Enabled: boolOrDefault(m.Enabled, true),
		})
	}
	return out
}

func trustDomainsToList(in []starflyv1.TrustDomainSpec) (types.List, diag.Diagnostics) {
	if len(in) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: trustDomainAttrTypes()}), nil
	}
	models := make([]trustDomainModel, 0, len(in))
	for _, td := range in {
		models = append(models, trustDomainModel{
			Name:     types.StringValue(td.Name),
			Type:     types.StringValue(td.Type),
			Issuer:   types.StringValue(td.Issuer),
			JWKSURI:  types.StringValue(td.JWKSURI),
			Enabled:  types.BoolValue(td.Enabled),
		})
	}
	list, diags := types.ListValueFrom(context.Background(), types.ObjectType{AttrTypes: trustDomainAttrTypes()}, models)
	return list, diags
}

type trustDomainModel struct {
	Name    types.String `tfsdk:"name"`
	Type    types.String `tfsdk:"type"`
	Issuer  types.String `tfsdk:"issuer"`
	JWKSURI types.String `tfsdk:"jwks_uri"`
	Enabled types.Bool   `tfsdk:"enabled"`
}

func trustDomainAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"name": types.StringType, "type": types.StringType,
		"issuer": types.StringType, "jwks_uri": types.StringType, "enabled": types.BoolType,
	}
}

func signingKeysFromList(list types.List) []starflyv1.SigningKeySpec {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var models []signingKeyModel
	_ = list.ElementsAs(context.Background(), &models, false)
	out := make([]starflyv1.SigningKeySpec, 0, len(models))
	for _, m := range models {
		out = append(out, starflyv1.SigningKeySpec{
			KID:            m.KID.ValueString(),
			Algorithm:      m.Algorithm.ValueString(),
			KMSKeyID:       m.KMSKeyID.ValueString(),
			RotationPolicy: m.RotationPolicy.ValueString(),
			Status:         m.Status.ValueString(),
		})
	}
	return out
}

func signingKeysToList(in []starflyv1.SigningKeySpec) (types.List, diag.Diagnostics) {
	if len(in) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: signingKeyAttrTypes()}), nil
	}
	models := make([]signingKeyModel, 0, len(in))
	for _, sk := range in {
		models = append(models, signingKeyModel{
			KID:            types.StringValue(sk.KID),
			Algorithm:      types.StringValue(sk.Algorithm),
			KMSKeyID:       types.StringValue(sk.KMSKeyID),
			RotationPolicy: types.StringValue(sk.RotationPolicy),
			Status:         types.StringValue(sk.Status),
		})
	}
	list, diags := types.ListValueFrom(context.Background(), types.ObjectType{AttrTypes: signingKeyAttrTypes()}, models)
	return list, diags
}

type signingKeyModel struct {
	KID            types.String `tfsdk:"kid"`
	Algorithm      types.String `tfsdk:"algorithm"`
	KMSKeyID       types.String `tfsdk:"kms_key_id"`
	RotationPolicy types.String `tfsdk:"rotation_policy"`
	Status         types.String `tfsdk:"status"`
}

func signingKeyAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"kid": types.StringType, "algorithm": types.StringType, "kms_key_id": types.StringType,
		"rotation_policy": types.StringType, "status": types.StringType,
	}
}

func ssfStreamsFromList(list types.List) []starflyv1.SSFStreamSpec {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var models []ssfStreamModel
	_ = list.ElementsAs(context.Background(), &models, false)
	out := make([]starflyv1.SSFStreamSpec, 0, len(models))
	for _, m := range models {
		out = append(out, starflyv1.SSFStreamSpec{
			StreamID:        m.StreamID.ValueString(),
			Transmitter:     m.Transmitter.ValueString(),
			EventsRequested: stringListFromTypes(m.EventsRequested),
		})
	}
	return out
}

func ssfStreamsToList(in []starflyv1.SSFStreamSpec) (types.List, diag.Diagnostics) {
	if len(in) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: ssfStreamAttrTypes()}), nil
	}
	models := make([]ssfStreamModel, 0, len(in))
	for _, s := range in {
		events, _ := types.ListValueFrom(context.Background(), types.StringType, s.EventsRequested)
		models = append(models, ssfStreamModel{
			StreamID:         types.StringValue(s.StreamID),
			Transmitter:      types.StringValue(s.Transmitter),
			EventsRequested:  events,
		})
	}
	list, diags := types.ListValueFrom(context.Background(), types.ObjectType{AttrTypes: ssfStreamAttrTypes()}, models)
	return list, diags
}

type ssfStreamModel struct {
	StreamID        types.String `tfsdk:"stream_id"`
	Transmitter     types.String `tfsdk:"transmitter"`
	EventsRequested types.List   `tfsdk:"events_requested"`
}

func ssfStreamAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"stream_id": types.StringType, "transmitter": types.StringType, "events_requested": types.ListType{ElemType: types.StringType},
	}
}

func anchorFromObject(obj types.Object) *starflyv1.AnchorSpec {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var m anchorModel
	_ = obj.As(context.Background(), &m, basetypes.ObjectAsOptions{})
	return &starflyv1.AnchorSpec{
		Type:   m.Type.ValueString(),
		Bucket: m.Bucket.ValueString(),
		Prefix: m.Prefix.ValueString(),
		Path:   m.Path.ValueString(),
	}
}

func anchorToObject(in *starflyv1.AnchorSpec) (types.Object, diag.Diagnostics) {
	attrTypes := anchorAttrTypes()
	if in == nil {
		return types.ObjectNull(attrTypes), nil
	}
	model := anchorModel{
		Type:   types.StringValue(in.Type),
		Bucket: types.StringValue(in.Bucket),
		Prefix: types.StringValue(in.Prefix),
		Path:   types.StringValue(in.Path),
	}
	obj, diags := types.ObjectValueFrom(context.Background(), attrTypes, model)
	return obj, diags
}

type anchorModel struct {
	Type   types.String `tfsdk:"type"`
	Bucket types.String `tfsdk:"bucket"`
	Prefix types.String `tfsdk:"prefix"`
	Path   types.String `tfsdk:"path"`
}

func anchorAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"type": types.StringType, "bucket": types.StringType, "prefix": types.StringType, "path": types.StringType,
	}
}

func policyFromObject(obj types.Object) *starflyv1.PolicySpec {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var m policyModel
	_ = obj.As(context.Background(), &m, basetypes.ObjectAsOptions{})
	return &starflyv1.PolicySpec{BundlePath: m.BundlePath.ValueString()}
}

func policyToObject(in *starflyv1.PolicySpec) (types.Object, diag.Diagnostics) {
	attrTypes := policyAttrTypes()
	if in == nil {
		return types.ObjectNull(attrTypes), nil
	}
	model := policyModel{BundlePath: types.StringValue(in.BundlePath)}
	obj, diags := types.ObjectValueFrom(context.Background(), attrTypes, model)
	return obj, diags
}

type policyModel struct {
	BundlePath types.String `tfsdk:"bundle_path"`
}

func policyAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{"bundle_path": types.StringType}
}

func federationFromObject(obj types.Object) *starflyv1.FederationSpec {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var m federationModel
	_ = obj.As(context.Background(), &m, basetypes.ObjectAsOptions{})
	return &starflyv1.FederationSpec{Peers: federationPeersFromList(m.Peers)}
}

func federationToObject(in *starflyv1.FederationSpec) (types.Object, diag.Diagnostics) {
	attrTypes := federationAttrTypes()
	if in == nil {
		return types.ObjectNull(attrTypes), nil
	}
	peers, d := federationPeersToList(in.Peers)
	obj, diags := types.ObjectValue(attrTypes, map[string]attr.Value{"peers": peers})
	diags.Append(d...)
	return obj, diags
}

type federationModel struct {
	Peers types.List `tfsdk:"peers"`
}

func federationAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"peers": types.ListType{ElemType: types.ObjectType{AttrTypes: federationPeerAttrTypes()}},
	}
}

func federationPeersFromList(list types.List) []starflyv1.FederationPeerSpec {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var models []federationPeerModel
	_ = list.ElementsAs(context.Background(), &models, false)
	out := make([]starflyv1.FederationPeerSpec, 0, len(models))
	for _, m := range models {
		out = append(out, starflyv1.FederationPeerSpec{
			FabricID:           m.FabricID.ValueString(),
			JWKSEndpoint:       m.JWKSEndpoint.ValueString(),
			MTLSSecret:         m.MTLSSecret.ValueString(),
			RefreshInterval:    m.RefreshInterval.ValueString(),
			StalenessThreshold: m.StalenessThreshold.ValueString(),
		})
	}
	return out
}

func federationPeersToList(in []starflyv1.FederationPeerSpec) (types.List, diag.Diagnostics) {
	if len(in) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: federationPeerAttrTypes()}), nil
	}
	models := make([]federationPeerModel, 0, len(in))
	for _, p := range in {
		models = append(models, federationPeerModel{
			FabricID:           types.StringValue(p.FabricID),
			JWKSEndpoint:       types.StringValue(p.JWKSEndpoint),
			MTLSSecret:         types.StringValue(p.MTLSSecret),
			RefreshInterval:    types.StringValue(p.RefreshInterval),
			StalenessThreshold: types.StringValue(p.StalenessThreshold),
		})
	}
	list, diags := types.ListValueFrom(context.Background(), types.ObjectType{AttrTypes: federationPeerAttrTypes()}, models)
	return list, diags
}

type federationPeerModel struct {
	FabricID           types.String `tfsdk:"fabric_id"`
	JWKSEndpoint       types.String `tfsdk:"jwks_endpoint"`
	MTLSSecret         types.String `tfsdk:"mtls_secret"`
	RefreshInterval    types.String `tfsdk:"refresh_interval"`
	StalenessThreshold types.String `tfsdk:"staleness_threshold"`
}

func federationPeerAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"fabric_id": types.StringType, "jwks_endpoint": types.StringType, "mtls_secret": types.StringType,
		"refresh_interval": types.StringType, "staleness_threshold": types.StringType,
	}
}

func stringListFromTypes(list types.List) []string {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var out []string
	_ = list.ElementsAs(context.Background(), &out, false)
	return out
}

func boolOrDefault(v types.Bool, def bool) bool {
	if v.IsNull() || v.IsUnknown() {
		return def
	}
	return v.ValueBool()
}
