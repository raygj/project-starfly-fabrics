package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"

	starflyv1 "github.com/starfly-fabrics/starfly/pkg/operator/api/v1alpha1"
)

const defaultFabricTimeout = 5 * time.Minute

var (
	_ resource.Resource                = (*fabricResource)(nil)
	_ resource.ResourceWithConfigure   = (*fabricResource)(nil)
)

type fabricResource struct {
	clients *Clients
}

func NewFabricResource() resource.Resource {
	return &fabricResource{}
}

func (r *fabricResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fabric"
}

func (r *fabricResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a StarlightFabric CRD — the declarative desired state of a Starfly fabric.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Namespace/name identifier.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Fabric resource name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"namespace": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Kubernetes namespace. Defaults to provider namespace.",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Kubernetes labels.",
			},
			"annotations": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Kubernetes annotations.",
			},
			"spec_hash": schema.StringAttribute{
				Computed:    true,
				Description: "SHA256 of the canonical fabric spec JSON. Use for immutability checks.",
			},
			"phase": schema.StringAttribute{
				Computed:    true,
				Description: "Current fabric phase from CRD status.",
			},
			"soul_sequence": schema.Int64Attribute{
				Computed:    true,
				Description: "Current soul sequence from CRD status.",
			},
			"trust_domains_active": schema.Int64Attribute{
				Computed:    true,
				Description: "Active trust domains from CRD status.",
			},
			"signing_keys_active": schema.Int64Attribute{
				Computed:    true,
				Description: "Active signing keys from CRD status.",
			},
			"ssf_streams_active": schema.Int64Attribute{
				Computed:    true,
				Description: "Active SSF streams from CRD status.",
			},
			"last_convergence": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of last successful convergence (RFC3339).",
			},
			"wait_for_converged": schema.BoolAttribute{
				Optional:    true,
				Description: "Wait for status.phase == Converged after create/update. Default true.",
			},
			"timeouts": timeouts.Attributes(ctx, timeouts.Opts{
				Create: true,
				Update: true,
			}),
		},
		Blocks: map[string]schema.Block{
			"trust_domains": schema.ListNestedBlock{
				MarkdownDescription: "Identity trust domains the fabric accepts.",
				NestedObject: schema.NestedBlockObject{
					Attributes: trustDomainAttributes(),
				},
			},
			"signing_keys": schema.ListNestedBlock{
				MarkdownDescription: "KMS-backed signing keys for token issuance.",
				NestedObject: schema.NestedBlockObject{
					Attributes: signingKeyAttributes(),
				},
			},
			"ssf_streams": schema.ListNestedBlock{
				MarkdownDescription: "SSF stream subscriptions.",
				NestedObject: schema.NestedBlockObject{
					Attributes: ssfStreamAttributes(),
				},
			},
			"anchor": schema.SingleNestedBlock{
				MarkdownDescription: "External soul manifest anchor.",
				Attributes:          anchorAttributes(),
			},
			"policy": schema.SingleNestedBlock{
				MarkdownDescription: "OPA policy configuration.",
				Attributes:          policyAttributes(),
			},
			"federation": schema.SingleNestedBlock{
				MarkdownDescription: "Multi-cluster JWKS federation peers.",
				Blocks: map[string]schema.Block{
					"peers": schema.ListNestedBlock{
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"fabric_id":           schema.StringAttribute{Required: true},
								"jwks_endpoint":       schema.StringAttribute{Required: true},
								"mtls_secret":         schema.StringAttribute{Optional: true},
								"refresh_interval":    schema.StringAttribute{Optional: true},
								"staleness_threshold": schema.StringAttribute{Optional: true},
							},
						},
					},
				},
			},
		},
	}
}

func (r *fabricResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	clients, ok := req.ProviderData.(*Clients)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("Expected *provider.Clients, got %T", req.ProviderData),
		)
		return
	}
	r.clients = clients
}

func (r *fabricResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan fabricModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	k8sClient, err := newDynamicClient(r.clients.KubeConfig)
	if err != nil {
		resp.Diagnostics.Append(DiagError("Create Kubernetes client", err)...)
		return
	}

	fabric := plan.toStarlightFabric(r.clients)
	if err := createFabric(ctx, k8sClient, fabric); err != nil {
		resp.Diagnostics.Append(DiagError("Create StarlightFabric", err)...)
		return
	}

	if plan.waitForConverged(ctx) {
		if err := r.waitForConverged(ctx, k8sClient, fabric.Namespace, fabric.Name, plan.Timeouts); err != nil {
			resp.Diagnostics.Append(DiagError("Wait for Converged", err)...)
			return
		}
	}

	fabric, err = getFabric(ctx, k8sClient, fabric.Namespace, fabric.Name)
	if err != nil {
		resp.Diagnostics.Append(DiagError("Read StarlightFabric after create", err)...)
		return
	}

	state, diags := fabricModelFromCRD(fabric, r.clients.Namespace)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.WaitForConverged = plan.WaitForConverged
	state.Timeouts = plan.Timeouts

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *fabricResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state fabricModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	k8sClient, err := newDynamicClient(r.clients.KubeConfig)
	if err != nil {
		resp.Diagnostics.Append(DiagError("Create Kubernetes client", err)...)
		return
	}

	fabric, err := getFabric(ctx, k8sClient, r.clients.NamespaceOrDefault(state.Namespace.ValueString()), state.Name.ValueString())
	if err != nil {
		if apierrors.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(DiagError("Read StarlightFabric", err)...)
		return
	}

	newState, diags := fabricModelFromCRD(fabric, r.clients.Namespace)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	newState.WaitForConverged = state.WaitForConverged
	newState.Timeouts = state.Timeouts

	resp.Diagnostics.Append(resp.State.Set(ctx, &newState)...)
}

func (r *fabricResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan fabricModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	k8sClient, err := newDynamicClient(r.clients.KubeConfig)
	if err != nil {
		resp.Diagnostics.Append(DiagError("Create Kubernetes client", err)...)
		return
	}

	ns := r.clients.NamespaceOrDefault(plan.Namespace.ValueString())
	existing, err := getFabric(ctx, k8sClient, ns, plan.Name.ValueString())
	if err != nil {
		resp.Diagnostics.Append(DiagError("Read StarlightFabric for update", err)...)
		return
	}

	updated := plan.toStarlightFabric(r.clients)
	updated.ResourceVersion = existing.ResourceVersion
	if err := updateFabric(ctx, k8sClient, updated); err != nil {
		resp.Diagnostics.Append(DiagError("Update StarlightFabric", err)...)
		return
	}

	if plan.waitForConverged(ctx) {
		if err := r.waitForConverged(ctx, k8sClient, updated.Namespace, updated.Name, plan.Timeouts); err != nil {
			resp.Diagnostics.Append(DiagError("Wait for Converged", err)...)
			return
		}
	}

	updated, err = getFabric(ctx, k8sClient, updated.Namespace, updated.Name)
	if err != nil {
		resp.Diagnostics.Append(DiagError("Read StarlightFabric after update", err)...)
		return
	}

	state, diags := fabricModelFromCRD(updated, r.clients.Namespace)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.WaitForConverged = plan.WaitForConverged
	state.Timeouts = plan.Timeouts

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *fabricResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state fabricModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	k8sClient, err := newDynamicClient(r.clients.KubeConfig)
	if err != nil {
		resp.Diagnostics.Append(DiagError("Create Kubernetes client", err)...)
		return
	}

	if err := deleteFabric(ctx, k8sClient, r.clients.NamespaceOrDefault(state.Namespace.ValueString()), state.Name.ValueString()); err != nil && !apierrors.IsNotFound(err) {
		resp.Diagnostics.Append(DiagError("Delete StarlightFabric", err)...)
	}
}

func (r *fabricResource) waitForConverged(ctx context.Context, k8sClient dynamic.Interface, namespace, name string, modelTimeouts timeouts.Value) error {
	timeout, diags := modelTimeouts.Create(ctx, defaultFabricTimeout)
	if diags.HasError() {
		return fmt.Errorf("parse create timeout: %s", diags.Errors()[0].Summary())
	}

	tflog.Info(ctx, "Waiting for fabric convergence", map[string]any{
		"namespace": namespace,
		"name":      name,
		"timeout":   timeout.String(),
	})

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return wait.PollUntilContextCancel(ctx, 2*time.Second, true, func(ctx context.Context) (bool, error) {
		fabric, err := getFabric(ctx, k8sClient, namespace, name)
		if err != nil {
			return false, err
		}
		return fabric.Status.Phase == starflyv1.PhaseConverged, nil
	})
}
