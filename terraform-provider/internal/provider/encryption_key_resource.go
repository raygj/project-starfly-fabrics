package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource              = (*encryptionKeyResource)(nil)
	_ resource.ResourceWithConfigure = (*encryptionKeyResource)(nil)
)

type encryptionKeyResource struct {
	clients *Clients
}

func NewEncryptionKeyResource() resource.Resource {
	return &encryptionKeyResource{}
}

func (r *encryptionKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_encryption_key"
}

func (r *encryptionKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Registers a workload encryption public key via POST /v1/identity/agent/encryption-key. Requires JWT auth.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Workload subject from the JWT.",
			},
			"public_key": schema.StringAttribute{
				Required:    true,
				Description: "JWK public key JSON (EC P-256/P-384/P-521 or OKP X25519/Ed25519).",
			},
			"workload_id": schema.StringAttribute{
				Computed:    true,
				Description: "Workload ID bound from the bearer token subject.",
			},
		},
	}
}

func (r *encryptionKeyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *encryptionKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan encryptionKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	api := r.clients.API
	if api == nil {
		resp.Diagnostics.AddError("Starfly API not configured", "Set provider endpoint for API resources")
		return
	}
	if api.jwtToken == "" {
		resp.Diagnostics.AddError("JWT required", "encryption_key requires provider jwt_token (WIMSE bearer)")
		return
	}

	raw := []byte(plan.PublicKey.ValueString())
	if !json.Valid(raw) {
		resp.Diagnostics.AddError("Invalid public_key JSON", "public_key must be valid JWK JSON")
		return
	}

	payload := encryptionKeyPayload{PublicKey: raw}
	if _, err := api.expectStatus(ctx, "POST", "/v1/identity/agent/encryption-key", payload, 200); err != nil {
		resp.Diagnostics.Append(DiagError("Register encryption key", err)...)
		return
	}

	// Subject comes from JWT — agents should set workload_id output from agent_identity.token chain.
	plan.ID = types.StringValue("registered")
	plan.WorkloadID = types.StringValue("from-jwt-subject")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *encryptionKeyResource) Read(_ context.Context, _ resource.ReadRequest, resp *resource.ReadResponse) {
	// No read endpoint — state is authoritative.
}

func (r *encryptionKeyResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "Replace the resource to register a new key.")
}

func (r *encryptionKeyResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No delete endpoint.
}

type encryptionKeyModel struct {
	ID         types.String `tfsdk:"id"`
	PublicKey  types.String `tfsdk:"public_key"`
	WorkloadID types.String `tfsdk:"workload_id"`
}
