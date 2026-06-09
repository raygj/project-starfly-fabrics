package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource              = (*agentIdentityResource)(nil)
	_ resource.ResourceWithConfigure = (*agentIdentityResource)(nil)
)

type agentIdentityResource struct {
	clients *Clients
}

func NewAgentIdentityResource() resource.Resource {
	return &agentIdentityResource{}
}

func (r *agentIdentityResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agent_identity"
}

func (r *agentIdentityResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Issues an agent WIMSE identity via POST /v1/identity/agent.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Workload ID of the issued identity.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"agent_name": schema.StringAttribute{
				Required:    true,
				Description: "Agent name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"platform": schema.StringAttribute{
				Required:    true,
				Description: "Agent platform: mcp, a2a, watsonx, custom.",
			},
			"capabilities": schema.ListAttribute{
				ElementType: types.StringType,
				Required:    true,
				Description: "Agent capabilities.",
			},
			"on_behalf_of": schema.StringAttribute{
				Optional:    true,
				Description: "Delegation subject.",
			},
			"max_blast_radius": schema.StringAttribute{
				Optional:    true,
				Description: "Maximum blast radius.",
			},
			"metadata": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Additional metadata.",
			},
			"delegation_depth": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum delegation hops.",
			},
			"workload_id": schema.StringAttribute{
				Computed:    true,
				Description: "Issued WIMSE workload ID.",
			},
			"token": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "Issued WIMSE JWT.",
			},
			"spiffe_id": schema.StringAttribute{
				Computed:    true,
				Description: "SPIFFE ID if configured.",
			},
		},
	}
}

func (r *agentIdentityResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	clients, ok := req.ProviderData.(*Clients)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	r.clients = clients
}

func (r *agentIdentityResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan agentIdentityModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	api := r.clients.API
	if api == nil {
		resp.Diagnostics.AddError("Starfly API not configured", "Set provider endpoint for API resources")
		return
	}

	payload := plan.toPayload()
	respBody, err := api.expectStatus(ctx, "POST", "/v1/identity/agent", payload, 200)
	if err != nil {
		resp.Diagnostics.Append(DiagError("Issue agent identity", err)...)
		return
	}

	var issued agentIdentityResponse
	if err := json.Unmarshal(respBody, &issued); err != nil {
		resp.Diagnostics.Append(DiagError("Decode agent identity response", err)...)
		return
	}

	plan.ID = types.StringValue(issued.WorkloadID)
	plan.WorkloadID = types.StringValue(issued.WorkloadID)
	plan.Token = types.StringValue(issued.Token)
	plan.SpiffeID = types.StringValue(issued.SpiffeID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *agentIdentityResource) Read(_ context.Context, _ resource.ReadRequest, resp *resource.ReadResponse) {
	// Starfly does not expose a read endpoint for issued identities — state is authoritative after create.
}

func (r *agentIdentityResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"Update not supported",
		"Agent identities are immutable. Change agent_name to force replacement.",
	)
}

func (r *agentIdentityResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No revoke HTTP endpoint yet — destroy removes TF state only.
}

type agentIdentityModel struct {
	ID               types.String `tfsdk:"id"`
	AgentName        types.String `tfsdk:"agent_name"`
	Platform         types.String `tfsdk:"platform"`
	Capabilities     types.List   `tfsdk:"capabilities"`
	OnBehalfOf       types.String `tfsdk:"on_behalf_of"`
	MaxBlastRadius   types.String `tfsdk:"max_blast_radius"`
	Metadata         types.Map    `tfsdk:"metadata"`
	DelegationDepth  types.Int64  `tfsdk:"delegation_depth"`
	WorkloadID       types.String `tfsdk:"workload_id"`
	Token            types.String `tfsdk:"token"`
	SpiffeID         types.String `tfsdk:"spiffe_id"`
}

func (m agentIdentityModel) toPayload() agentIdentityPayload {
	depth := int64(0)
	if !m.DelegationDepth.IsNull() && !m.DelegationDepth.IsUnknown() {
		depth = m.DelegationDepth.ValueInt64()
	}
	return agentIdentityPayload{
		AgentName:       m.AgentName.ValueString(),
		Platform:        m.Platform.ValueString(),
		Capabilities:    stringListFromTypes(m.Capabilities),
		OnBehalfOf:      m.OnBehalfOf.ValueString(),
		MaxBlastRadius:  m.MaxBlastRadius.ValueString(),
		Metadata:        stringMapFromTypes(m.Metadata),
		DelegationDepth: int(depth),
	}
}
