package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource              = (*ssfStreamResource)(nil)
	_ resource.ResourceWithConfigure = (*ssfStreamResource)(nil)
)

type ssfStreamResource struct {
	clients *Clients
}

func NewSSFStreamResource() resource.Resource {
	return &ssfStreamResource{}
}

func (r *ssfStreamResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ssf_stream"
}

func (r *ssfStreamResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an SSF stream subscription via POST/DELETE /v1/signals/stream.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Stream ID returned by Starfly.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"issuer": schema.StringAttribute{
				Required:    true,
				Description: "SSF stream issuer (iss).",
			},
			"audience": schema.StringAttribute{
				Required:    true,
				Description: "SSF stream audience (aud).",
			},
			"events_requested": schema.ListAttribute{
				ElementType: types.StringType,
				Required:    true,
				Description: "CAEP/SSF event types to subscribe to.",
			},
			"delivery_method": schema.StringAttribute{
				Required:    true,
				Description: "Delivery method: push or poll.",
			},
			"endpoint_url": schema.StringAttribute{
				Optional:    true,
				Description: "Webhook endpoint URL for push delivery.",
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "Current stream status.",
			},
		},
	}
}

func (r *ssfStreamResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ssfStreamResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ssfStreamAPIModel
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
	respBody, err := api.expectStatus(ctx, "POST", "/v1/signals/stream", payload, 201)
	if err != nil {
		resp.Diagnostics.Append(DiagError("Create SSF stream", err)...)
		return
	}

	var created streamPayload
	if err := json.Unmarshal(respBody, &created); err != nil {
		resp.Diagnostics.Append(DiagError("Decode SSF stream response", err)...)
		return
	}

	plan.ID = types.StringValue(created.ID)
	plan.Status = types.StringValue(created.Status)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ssfStreamResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ssfStreamAPIModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	api := r.clients.API
	if api == nil {
		resp.Diagnostics.AddError("Starfly API not configured", "Set provider endpoint for API resources")
		return
	}

	path := "/v1/signals/status?stream_id=" + url.QueryEscape(state.ID.ValueString())
	_, respBody, err := api.request(ctx, "GET", path, nil)
	if err != nil {
		resp.Diagnostics.Append(DiagError("Read SSF stream status", err)...)
		return
	}

	var status streamStatusPayload
	if err := json.Unmarshal(respBody, &status); err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state.Status = types.StringValue(status.Status)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ssfStreamResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// SSF streams are replaced on config change.
	var plan ssfStreamAPIModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state ssfStreamAPIModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	api := r.clients.API
	deletePath := "/v1/signals/stream?stream_id=" + url.QueryEscape(state.ID.ValueString())
	if _, _, err := api.request(ctx, "DELETE", deletePath, nil); err != nil {
		resp.Diagnostics.Append(DiagError("Delete SSF stream for update", err)...)
		return
	}

	respBody, err := api.expectStatus(ctx, "POST", "/v1/signals/stream", plan.toPayload(), 201)
	if err != nil {
		resp.Diagnostics.Append(DiagError("Recreate SSF stream", err)...)
		return
	}

	var created streamPayload
	if err := json.Unmarshal(respBody, &created); err != nil {
		resp.Diagnostics.Append(DiagError("Decode SSF stream response", err)...)
		return
	}

	plan.ID = types.StringValue(created.ID)
	plan.Status = types.StringValue(created.Status)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ssfStreamResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ssfStreamAPIModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	api := r.clients.API
	if api == nil {
		return
	}

	path := "/v1/signals/stream?stream_id=" + url.QueryEscape(state.ID.ValueString())
	if _, _, err := api.request(ctx, "DELETE", path, nil); err != nil {
		resp.Diagnostics.Append(DiagError("Delete SSF stream", err)...)
	}
}

type ssfStreamAPIModel struct {
	ID              types.String `tfsdk:"id"`
	Issuer          types.String `tfsdk:"issuer"`
	Audience        types.String `tfsdk:"audience"`
	EventsRequested types.List   `tfsdk:"events_requested"`
	DeliveryMethod  types.String `tfsdk:"delivery_method"`
	EndpointURL     types.String `tfsdk:"endpoint_url"`
	Status          types.String `tfsdk:"status"`
}

func (m ssfStreamAPIModel) toPayload() streamConfigPayload {
	return streamConfigPayload{
		Issuer:          m.Issuer.ValueString(),
		Audience:        m.Audience.ValueString(),
		EventsRequested: stringListFromTypes(m.EventsRequested),
		DeliveryMethod:  m.DeliveryMethod.ValueString(),
		EndpointURL:     m.EndpointURL.ValueString(),
	}
}
