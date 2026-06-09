package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource              = (*mcpToolResource)(nil)
	_ resource.ResourceWithConfigure = (*mcpToolResource)(nil)
)

type mcpToolResource struct {
	clients *Clients
}

func NewMCPToolResource() resource.Resource {
	return &mcpToolResource{}
}

func (r *mcpToolResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_mcp_tool"
}

func (r *mcpToolResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Registers an MCP tool with Starfly via POST /v1/mcp/tools.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Tool ID.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"tool_id": schema.StringAttribute{
				Required:    true,
				Description: "Unique MCP tool identifier.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Human-readable tool name.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Tool description.",
			},
			"resource_uri": schema.StringAttribute{
				Optional:    true,
				Description: "RFC 8707 resource indicator for audience matching.",
			},
			"required_capabilities": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Capabilities a token must have to call this tool.",
			},
			"max_blast_radius": schema.StringAttribute{
				Optional:    true,
				Description: "Maximum blast radius scope allowed.",
			},
			"requires_execution": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the tool requires execution-scoped tokens.",
				Default:     booldefault.StaticBool(false),
			},
			"allowed_operations": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Allowed exec_act values.",
			},
			"allowed_targets": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Allowed target resource URIs.",
			},
			"owner_commune": schema.StringAttribute{
				Optional:    true,
				Description: "Commune that owns this tool.",
			},
			"server_id": schema.StringAttribute{
				Optional:    true,
				Description: "MCP server hosting this tool.",
			},
		},
	}
}

func (r *mcpToolResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *mcpToolResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan mcpToolModel
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
	if _, err := api.expectStatus(ctx, "POST", "/v1/mcp/tools", payload, 201); err != nil {
		resp.Diagnostics.Append(DiagError("Register MCP tool", err)...)
		return
	}

	plan.ID = plan.ToolID
	plan.RequiresExecution = types.BoolValue(false)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *mcpToolResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state mcpToolModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	api := r.clients.API
	if api == nil {
		resp.Diagnostics.AddError("Starfly API not configured", "Set provider endpoint for API resources")
		return
	}

	_, respBody, err := api.request(ctx, "GET", "/v1/mcp/tools", nil)
	if err != nil {
		resp.Diagnostics.Append(DiagError("List MCP tools", err)...)
		return
	}

	var listed mcpToolListResponse
	if err := json.Unmarshal(respBody, &listed); err != nil {
		resp.Diagnostics.Append(DiagError("Decode MCP tool list", err)...)
		return
	}

	for _, tool := range listed.Tools {
		if tool.ToolID == state.ToolID.ValueString() {
			state.fromPayload(tool)
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			return
		}
	}

	resp.State.RemoveResource(ctx)
}

func (r *mcpToolResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// MCP registry treats duplicate tool_id as conflict — replace via destroy/create on tool_id change only.
	var plan mcpToolModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	api := r.clients.API
	if _, _, err := api.request(ctx, "DELETE", "/v1/mcp/tools?tool_id="+url.QueryEscape(plan.ToolID.ValueString()), nil); err != nil {
		resp.Diagnostics.Append(DiagError("Deregister MCP tool for update", err)...)
		return
	}

	payload := plan.toPayload()
	if _, err := api.expectStatus(ctx, "POST", "/v1/mcp/tools", payload, 201); err != nil {
		resp.Diagnostics.Append(DiagError("Re-register MCP tool", err)...)
		return
	}

	plan.ID = plan.ToolID
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *mcpToolResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state mcpToolModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	api := r.clients.API
	if api == nil {
		return
	}

	path := "/v1/mcp/tools?tool_id=" + url.QueryEscape(state.ToolID.ValueString())
	if _, _, err := api.request(ctx, "DELETE", path, nil); err != nil {
		resp.Diagnostics.Append(DiagError("Deregister MCP tool", err)...)
	}
}

type mcpToolModel struct {
	ID                   types.String `tfsdk:"id"`
	ToolID               types.String `tfsdk:"tool_id"`
	Name                 types.String `tfsdk:"name"`
	Description          types.String `tfsdk:"description"`
	ResourceURI          types.String `tfsdk:"resource_uri"`
	RequiredCapabilities types.List   `tfsdk:"required_capabilities"`
	MaxBlastRadius       types.String `tfsdk:"max_blast_radius"`
	RequiresExecution    types.Bool   `tfsdk:"requires_execution"`
	AllowedOperations    types.List   `tfsdk:"allowed_operations"`
	AllowedTargets       types.List   `tfsdk:"allowed_targets"`
	OwnerCommune         types.String `tfsdk:"owner_commune"`
	ServerID             types.String `tfsdk:"server_id"`
}

func (m *mcpToolModel) toPayload() mcpToolPayload {
	return mcpToolPayload{
		ToolID:               m.ToolID.ValueString(),
		Name:                 m.Name.ValueString(),
		Description:          m.Description.ValueString(),
		ResourceURI:          m.ResourceURI.ValueString(),
		RequiredCapabilities: stringListFromTypes(m.RequiredCapabilities),
		MaxBlastRadius:       m.MaxBlastRadius.ValueString(),
		RequiresExecution:    boolOrDefault(m.RequiresExecution, false),
		AllowedOperations:    stringListFromTypes(m.AllowedOperations),
		AllowedTargets:       stringListFromTypes(m.AllowedTargets),
		OwnerCommune:         m.OwnerCommune.ValueString(),
		ServerID:             m.ServerID.ValueString(),
	}
}

func (m *mcpToolModel) fromPayload(p mcpToolPayload) {
	m.ID = types.StringValue(p.ToolID)
	m.ToolID = types.StringValue(p.ToolID)
	m.Name = types.StringValue(p.Name)
	m.Description = optionalString(p.Description)
	m.ResourceURI = optionalString(p.ResourceURI)
	m.MaxBlastRadius = optionalString(p.MaxBlastRadius)
	m.RequiresExecution = types.BoolValue(p.RequiresExecution)
	m.OwnerCommune = optionalString(p.OwnerCommune)
	m.ServerID = optionalString(p.ServerID)
	m.RequiredCapabilities = optionalStringList(p.RequiredCapabilities)
	m.AllowedOperations = optionalStringList(p.AllowedOperations)
	m.AllowedTargets = optionalStringList(p.AllowedTargets)
}

func optionalString(v string) types.String {
	if v == "" {
		return types.StringNull()
	}
	return types.StringValue(v)
}

func optionalStringList(v []string) types.List {
	if len(v) == 0 {
		return types.ListNull(types.StringType)
	}
	list, diags := types.ListValueFrom(context.Background(), types.StringType, v)
	if diags.HasError() {
		return types.ListNull(types.StringType)
	}
	return list
}
