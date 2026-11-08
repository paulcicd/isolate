package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type IsolateProvider struct{ version string }
type providerModel struct {
	Endpoint  types.String `tfsdk:"endpoint"`
	TokenFile types.String `tfsdk:"token_file"`
	CAFile    types.String `tfsdk:"ca_file"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &IsolateProvider{version: version} }
}
func (p *IsolateProvider) Metadata(_ context.Context, _ provider.MetadataRequest, response *provider.MetadataResponse) {
	response.TypeName = "isolate"
	response.Version = p.version
}
func (p *IsolateProvider) Schema(_ context.Context, _ provider.SchemaRequest, response *provider.SchemaResponse) {
	response.Schema = schema.Schema{Description: "Manage Isolate inventory and permanent grants through its authenticated, revision-checked control API. No target keys or tokens enter resource state.", Attributes: map[string]schema.Attribute{
		"endpoint":   schema.StringAttribute{Optional: true, Description: "HTTPS control API base URL; defaults to ISOLATE_ENDPOINT."},
		"token_file": schema.StringAttribute{Optional: true, Description: "Protected file containing a short-lived bearer token; defaults to ISOLATE_TOKEN_FILE, otherwise ISOLATE_TOKEN is read for every request. Token content must not be placed in HCL."},
		"ca_file":    schema.StringAttribute{Optional: true, Description: "Optional trusted PEM CA bundle. Verification is always enabled."},
	}}
}
func (p *IsolateProvider) Configure(ctx context.Context, request provider.ConfigureRequest, response *provider.ConfigureResponse) {
	var model providerModel
	response.Diagnostics.Append(request.Config.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	if model.Endpoint.IsUnknown() || model.TokenFile.IsUnknown() || model.CAFile.IsUnknown() {
		response.Diagnostics.AddError("Unknown provider configuration", "Resolve endpoint and credential paths before configuring Isolate.")
		return
	}
	endpoint := model.Endpoint.ValueString()
	if endpoint == "" {
		endpoint = os.Getenv("ISOLATE_ENDPOINT")
	}
	tokenFile := model.TokenFile.ValueString()
	if tokenFile == "" {
		tokenFile = os.Getenv("ISOLATE_TOKEN_FILE")
	}
	client, err := newClient(endpoint, tokenFile, model.CAFile.ValueString())
	if err != nil {
		response.Diagnostics.AddError("Invalid Isolate configuration", err.Error())
		return
	}
	if _, err = client.token(); err != nil {
		response.Diagnostics.AddError("Isolate credentials unavailable", err.Error())
		return
	}
	response.ResourceData = client
}
func (p *IsolateProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{NewHostResource, NewGrantResource}
}
func (p *IsolateProvider) DataSources(_ context.Context) []func() datasource.DataSource { return nil }
