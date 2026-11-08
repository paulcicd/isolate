package provider

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type managedResource struct {
	kind, plural string
	client       *Client
}

func NewHostResource() resource.Resource  { return &managedResource{kind: "host", plural: "hosts"} }
func NewGrantResource() resource.Resource { return &managedResource{kind: "grant", plural: "grants"} }
func (r *managedResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_" + r.kind
}
func optionalString(description string) schema.StringAttribute {
	return schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: description}
}
func requiredString(description string) schema.StringAttribute {
	return schema.StringAttribute{Required: true, Description: description}
}
func (r *managedResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	attributes := map[string]schema.Attribute{
		"id":       schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}, Description: "Server-assigned numeric ID; supports terraform import."},
		"revision": schema.StringAttribute{Computed: true, Description: "Opaque current revision used for If-Match updates and deletion."},
	}
	if r.kind == "host" {
		attributes["project_name"] = requiredString("Canonical inventory project name.")
		attributes["server_name"] = requiredString("Canonical lowercase inventory name.")
		attributes["server_ip"] = requiredString("Pinned target IPv4/IPv6 address, not a DNS override.")
		attributes["server_user"] = requiredString("Inventory default Unix account; a separate grant still chooses actual access.")
		attributes["server_port"] = schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(22)}
		attributes["server_nosudo"] = schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false)}
		attributes["server_note"] = optionalString("Public resource note. Do not store secrets.")
		attributes["server_services"] = optionalString("Configured service labels.")
		attributes["proxy_id"] = optionalString("Inventory jump host ID, or empty to remove the jump.")
		attributes["resource_owner"] = schema.StringAttribute{Optional: true, Computed: true, Description: "Resource owner; defaults to the server/tag-derived value when omitted."}
		attributes["environment"] = schema.StringAttribute{Optional: true, Computed: true, Description: "Environment; defaults to the server/tag-derived value when omitted."}
		attributes["tags"] = schema.MapAttribute{Optional: true, Computed: true, ElementType: types.StringType, Default: mapdefault.StaticValue(types.MapValueMust(types.StringType, map[string]attr.Value{}))}
	} else {
		attributes["subject"] = requiredString("Explicit user, group, role or service subject type.")
		attributes["name"] = requiredString("Subject name/client ID.")
		attributes["project"] = requiredString("Exact project selector. Broader selectors require an explicitly global administrative identity.")
		attributes["remote_user"] = requiredString("Policy-selected target Unix account.")
		attributes["sudo_mode"] = schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("none")}
		attributes["host"] = optionalString("Optional inventory host selector.")
		attributes["subject_id"] = optionalString("Optional stable subject binding for a user grant; the API compatibility field is keycloak_sub.")
		attributes["allowed_actions"] = schema.SetAttribute{Required: true, ElementType: types.StringType, Description: "Explicit permitted protocol/operation actions. This provider never manages one-use approvals."}
	}
	response.Schema = schema.Schema{Description: "Desired state managed through the Isolate administration API. Create is explicitly confirmed; mutations are revision-checked. Credentials are never stored in this resource.", Attributes: attributes}
}
func (r *managedResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	if request.ProviderData == nil {
		return
	}
	client, ok := request.ProviderData.(*Client)
	if !ok {
		response.Diagnostics.AddError("Provider configuration error", "Unexpected Isolate client type.")
		return
	}
	r.client = client
}
func (r *managedResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	if !numericID.MatchString(request.ID) {
		response.Diagnostics.AddError("Invalid import ID", "Import an exact numeric Isolate resource ID.")
		return
	}
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

type modelSource interface {
	Get(context.Context, interface{}) diag.Diagnostics
}
type managedModel interface {
	identifier() string
	revision() string
	payload(context.Context) (map[string]any, error)
	remote(context.Context, map[string]any) error
}
type hostModel struct {
	ID          types.String `tfsdk:"id"`
	Revision    types.String `tfsdk:"revision"`
	Project     types.String `tfsdk:"project_name"`
	Name        types.String `tfsdk:"server_name"`
	Address     types.String `tfsdk:"server_ip"`
	User        types.String `tfsdk:"server_user"`
	Port        types.Int64  `tfsdk:"server_port"`
	NoSudo      types.Bool   `tfsdk:"server_nosudo"`
	Note        types.String `tfsdk:"server_note"`
	Services    types.String `tfsdk:"server_services"`
	Proxy       types.String `tfsdk:"proxy_id"`
	Owner       types.String `tfsdk:"resource_owner"`
	Environment types.String `tfsdk:"environment"`
	Tags        types.Map    `tfsdk:"tags"`
}
type grantModel struct {
	ID        types.String `tfsdk:"id"`
	Revision  types.String `tfsdk:"revision"`
	Subject   types.String `tfsdk:"subject"`
	Name      types.String `tfsdk:"name"`
	Project   types.String `tfsdk:"project"`
	User      types.String `tfsdk:"remote_user"`
	Sudo      types.String `tfsdk:"sudo_mode"`
	Host      types.String `tfsdk:"host"`
	SubjectID types.String `tfsdk:"subject_id"`
	Actions   types.Set    `tfsdk:"allowed_actions"`
}

func (m *hostModel) identifier() string  { return m.ID.ValueString() }
func (m *hostModel) revision() string    { return m.Revision.ValueString() }
func (m *grantModel) identifier() string { return m.ID.ValueString() }
func (m *grantModel) revision() string   { return m.Revision.ValueString() }

var numericID = regexp.MustCompile(`^[0-9]{1,20}$`)
var revisionID = regexp.MustCompile(`^[a-f0-9]{64}$`)

func text(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}
func revision(record map[string]any) error {
	if !revisionID.MatchString(text(record["_revision"])) {
		return fmt.Errorf("API omitted a valid revision; unsafe mutation is refused")
	}
	return nil
}
func (m *hostModel) payload(ctx context.Context) (map[string]any, error) {
	tags := map[string]string{}
	if !m.Tags.IsUnknown() && !m.Tags.IsNull() {
		if d := m.Tags.ElementsAs(ctx, &tags, false); d.HasError() {
			return nil, fmt.Errorf("invalid tags")
		}
	}
	value := map[string]any{"project_name": m.Project.ValueString(), "server_name": m.Name.ValueString(), "server_ip": m.Address.ValueString(), "server_user": m.User.ValueString(), "server_port": m.Port.ValueInt64(), "server_nosudo": m.NoSudo.ValueBool(), "server_note": m.Note.ValueString(), "server_services": m.Services.ValueString(), "proxy_id": m.Proxy.ValueString(), "tags": tags}
	if !m.Owner.IsNull() && !m.Owner.IsUnknown() {
		value["resource_owner"] = m.Owner.ValueString()
	}
	if !m.Environment.IsNull() && !m.Environment.IsUnknown() {
		value["environment"] = m.Environment.ValueString()
	}
	return value, nil
}
func (m *grantModel) payload(ctx context.Context) (map[string]any, error) {
	actions := []string{}
	if d := m.Actions.ElementsAs(ctx, &actions, false); d.HasError() {
		return nil, fmt.Errorf("invalid allowed_actions")
	}
	if len(actions) == 0 {
		return nil, fmt.Errorf("at least one allowed action is required")
	}
	sort.Strings(actions)
	value := map[string]any{"subject": m.Subject.ValueString(), "name": m.Name.ValueString(), "project": m.Project.ValueString(), "remote_user": m.User.ValueString(), "sudo_mode": m.Sudo.ValueString(), "allowed_actions": actions, "host": m.Host.ValueString()}
	if m.SubjectID.ValueString() != "" {
		value["keycloak_sub"] = m.SubjectID.ValueString()
	}
	return value, nil
}
func (m *hostModel) remote(ctx context.Context, value map[string]any) error {
	if err := revision(value); err != nil {
		return err
	}
	id := text(value["server_id"])
	if !numericID.MatchString(id) {
		return fmt.Errorf("API omitted a valid host ID")
	}
	m.ID = types.StringValue(id)
	m.Revision = types.StringValue(text(value["_revision"]))
	m.Project = types.StringValue(text(value["project_name"]))
	m.Name = types.StringValue(text(value["server_name"]))
	m.Address = types.StringValue(text(value["server_ip"]))
	m.User = types.StringValue(text(value["server_user"]))
	port, ok := value["server_port"].(float64)
	if !ok {
		port = 22
	}
	m.Port = types.Int64Value(int64(port))
	flag, _ := value["server_nosudo"].(bool)
	m.NoSudo = types.BoolValue(flag)
	m.Note = types.StringValue(text(value["server_note"]))
	m.Services = types.StringValue(text(value["server_services"]))
	m.Proxy = types.StringValue(text(value["proxy_id"]))
	m.Owner = types.StringValue(text(value["resource_owner"]))
	m.Environment = types.StringValue(text(value["environment"]))
	tags := map[string]string{}
	if items, ok := value["tags"].(map[string]any); ok {
		for k, v := range items {
			tags[k] = text(v)
		}
	}
	converted, d := types.MapValueFrom(ctx, types.StringType, tags)
	if d.HasError() {
		return fmt.Errorf("API returned invalid tags")
	}
	m.Tags = converted
	return nil
}
func (m *grantModel) remote(ctx context.Context, value map[string]any) error {
	if err := revision(value); err != nil {
		return err
	}
	id := text(value["id"])
	if !numericID.MatchString(id) {
		return fmt.Errorf("API omitted a valid grant ID")
	}
	m.ID = types.StringValue(id)
	m.Revision = types.StringValue(text(value["_revision"]))
	m.Subject = types.StringValue(text(value["subject"]))
	m.Name = types.StringValue(text(value["name"]))
	m.Project = types.StringValue(text(value["project"]))
	m.User = types.StringValue(text(value["remote_user"]))
	m.Sudo = types.StringValue(text(value["sudo_mode"]))
	m.Host = types.StringValue(text(value["host"]))
	m.SubjectID = types.StringValue(text(value["keycloak_sub"]))
	actions := []string{}
	if items, ok := value["allowed_actions"].([]any); ok {
		for _, item := range items {
			actions = append(actions, text(item))
		}
	}
	converted, d := types.SetValueFrom(ctx, types.StringType, actions)
	if d.HasError() {
		return fmt.Errorf("API returned invalid actions")
	}
	m.Actions = converted
	return nil
}
func (r *managedResource) model(ctx context.Context, source modelSource) (managedModel, diag.Diagnostics) {
	var model managedModel
	if r.kind == "host" {
		model = &hostModel{}
	} else {
		model = &grantModel{}
	}
	return model, source.Get(ctx, model)
}
func (r *managedResource) resourcePath(id string) (string, error) {
	if !numericID.MatchString(id) {
		return "", fmt.Errorf("resource ID must be numeric")
	}
	return "/api/v1/admin/" + r.plural + "/" + id, nil
}
func (r *managedResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	model, d := r.model(ctx, request.Plan)
	response.Diagnostics.Append(d...)
	if response.Diagnostics.HasError() {
		return
	}
	payload, err := model.payload(ctx)
	if err != nil {
		response.Diagnostics.AddError("Invalid resource", err.Error())
		return
	}
	key, err := newIdempotencyKey()
	if err != nil {
		response.Diagnostics.AddError("Cannot allocate create operation", "Secure randomness is unavailable.")
		return
	}
	result := map[string]map[string]any{}
	err = r.client.request(ctx, http.MethodPost, "/api/v1/admin/"+r.plural, map[string]any{r.kind: payload, "confirm": true}, "", key, &result)
	if err == nil {
		err = model.remote(ctx, result[r.kind])
	}
	if err != nil {
		response.Diagnostics.AddError("Isolate create failed", err.Error())
		return
	}
	response.Diagnostics.Append(response.State.Set(ctx, model)...)
}
func (r *managedResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	model, d := r.model(ctx, request.State)
	response.Diagnostics.Append(d...)
	if response.Diagnostics.HasError() {
		return
	}
	uri, err := r.resourcePath(model.identifier())
	if err != nil {
		response.Diagnostics.AddError("Invalid resource ID", err.Error())
		return
	}
	result := map[string]map[string]any{}
	err = r.client.request(ctx, http.MethodGet, uri, nil, "", "", &result)
	if isNotFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err == nil {
		err = model.remote(ctx, result[r.kind])
	}
	if err != nil {
		response.Diagnostics.AddError("Isolate read failed", err.Error())
		return
	}
	response.Diagnostics.Append(response.State.Set(ctx, model)...)
}
func (r *managedResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	model, d := r.model(ctx, request.Plan)
	response.Diagnostics.Append(d...)
	previous, d := r.model(ctx, request.State)
	response.Diagnostics.Append(d...)
	if response.Diagnostics.HasError() {
		return
	}
	uri, err := r.resourcePath(previous.identifier())
	if err != nil {
		response.Diagnostics.AddError("Invalid resource ID", err.Error())
		return
	}
	if !revisionID.MatchString(previous.revision()) {
		response.Diagnostics.AddError("Missing resource revision", "Refresh the resource before updating; blind writes are refused.")
		return
	}
	payload, err := model.payload(ctx)
	if err != nil {
		response.Diagnostics.AddError("Invalid resource", err.Error())
		return
	}
	result := map[string]map[string]any{}
	err = r.client.request(ctx, http.MethodPut, uri, map[string]any{r.kind: payload, "confirm": true}, previous.revision(), "", &result)
	if err == nil {
		err = model.remote(ctx, result[r.kind])
	}
	if err != nil {
		response.Diagnostics.AddError("Isolate update failed", err.Error())
		return
	}
	response.Diagnostics.Append(response.State.Set(ctx, model)...)
}
func (r *managedResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	model, d := r.model(ctx, request.State)
	response.Diagnostics.Append(d...)
	if response.Diagnostics.HasError() {
		return
	}
	uri, err := r.resourcePath(model.identifier())
	if err != nil {
		response.Diagnostics.AddError("Invalid resource ID", err.Error())
		return
	}
	if !revisionID.MatchString(model.revision()) {
		response.Diagnostics.AddError("Missing resource revision", "Refresh the resource before deleting; blind deletion is refused.")
		return
	}
	err = r.client.request(ctx, http.MethodDelete, uri, map[string]any{"confirm": true}, model.revision(), "", nil)
	if err != nil && !isNotFound(err) {
		response.Diagnostics.AddError("Isolate delete failed", err.Error())
	}
}

func (r *managedResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	model, d := r.model(ctx, request.Config)
	response.Diagnostics.Append(d...)
	if response.Diagnostics.HasError() {
		return
	}
	check := func(name string, value types.String) {
		if !value.IsNull() && !value.IsUnknown() && (value.ValueString() == "" || value.ValueString() != strings.TrimSpace(value.ValueString())) {
			response.Diagnostics.AddAttributeError(path.Root(name), "Invalid value", "Use a nonempty canonical value without surrounding whitespace.")
		}
	}
	if m, ok := model.(*hostModel); ok {
		check("project_name", m.Project)
		check("server_name", m.Name)
		check("server_ip", m.Address)
		check("server_user", m.User)
		for name, value := range map[string]types.String{"project_name": m.Project, "server_name": m.Name} {
			if !value.IsUnknown() && value.ValueString() != strings.ToLower(value.ValueString()) {
				response.Diagnostics.AddAttributeError(path.Root(name), "Noncanonical inventory name", "Use lowercase inventory names to match server normalization.")
			}
		}
	} else {
		m := model.(*grantModel)
		check("subject", m.Subject)
		check("name", m.Name)
		check("project", m.Project)
		check("remote_user", m.User)
		if !m.Subject.IsUnknown() && !m.Subject.IsNull() {
			switch m.Subject.ValueString() {
			case "user", "group", "role", "service":
			default:
				response.Diagnostics.AddAttributeError(path.Root("subject"), "Invalid subject", "Use user, group, role or service.")
			}
		}
		if !m.Sudo.IsNull() && !m.Sudo.IsUnknown() && m.Sudo.ValueString() != "none" && m.Sudo.ValueString() != "sudo-i" {
			response.Diagnostics.AddAttributeError(path.Root("sudo_mode"), "Invalid privilege mode", "Use none or sudo-i.")
		}
		if !m.Actions.IsNull() && !m.Actions.IsUnknown() && len(m.Actions.Elements()) == 0 {
			response.Diagnostics.AddAttributeError(path.Root("allowed_actions"), "Empty actions", "Specify at least one permitted action.")
		}
	}
}
