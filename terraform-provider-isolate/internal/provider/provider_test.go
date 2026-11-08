package provider

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

func tlsClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ISOLATE_TOKEN", "fixture-token")
	client, err := newClient(server.URL, "", ca)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestProtocolSchema(t *testing.T) {
	server := providerserver.NewProtocol6(New("test")())()
	response, err := server.GetProviderSchema(context.Background(), &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, diagnostic := range response.Diagnostics {
		if diagnostic.Severity == tfprotov6.DiagnosticSeverityError {
			t.Fatal(diagnostic)
		}
	}
	if len(response.ResourceSchemas) != 2 {
		t.Fatalf("expected actual host and grant resources: %#v", response.ResourceSchemas)
	}
	for _, attribute := range response.Provider.Block.Attributes {
		if attribute.Name == "token" || attribute.Name == "insecure" {
			t.Fatalf("unsafe provider configuration %s", attribute.Name)
		}
	}
}

func TestSecureTransportAndTokenRotation(t *testing.T) {
	var seen []string
	client, server := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		if r.Header.Get("If-Match") != strings.Repeat("a", 64) || r.Header.Get("Idempotency-Key") != "intent-1234567890" {
			t.Error("missing mutation guards")
		}
		w.WriteHeader(204)
	})
	file := filepath.Join(t.TempDir(), "token")
	client.tokenFile = file
	for _, token := range []string{"first-token", "rotated-token"} {
		if err := os.WriteFile(file, []byte(token+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := client.request(context.Background(), "PUT", "/api/v1/admin/hosts/1", map[string]any{"confirm": true}, strings.Repeat("a", 64), "intent-1234567890", nil); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(seen, ",") != "Bearer first-token,Bearer rotated-token" {
		t.Fatalf("tokens not reloaded: %v", seen)
	}
	untrusted, err := newClient(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err = untrusted.request(context.Background(), "GET", "/", nil, "", "", nil); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
	for _, endpoint := range []string{"http://example.test", "https://user:secret@example.test", "https://example.test?q=1", "https://example.test/#fragment"} {
		if _, err := newClient(endpoint, "", ""); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(file, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := client.token(); err == nil {
			t.Fatal("world-readable token file accepted")
		}
	}
}

func TestNoRedirectRetryOrErrorBodyLeak(t *testing.T) {
	requests := 0
	client, _ := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Location", "https://attacker.invalid/")
		w.WriteHeader(302)
		fmt.Fprint(w, "secret-token-do-not-expose")
	})
	err := client.request(context.Background(), "POST", "/", map[string]any{}, "", "idempotent-intent", nil)
	if requests != 1 || err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("unsafe failure: %d %v", requests, err)
	}
}

func TestResourceLifecycleWithHTTPFixture(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"host", "grant"} {
		t.Run(kind, func(t *testing.T) {
			var record map[string]any
			revisionValue := strings.Repeat("a", 64)
			var methods []string
			client, _ := tlsClient(t, func(w http.ResponseWriter, req *http.Request) {
				methods = append(methods, req.Method)
				if req.Header.Get("Authorization") != "Bearer fixture-token" {
					t.Error("missing bearer")
				}
				if req.Method != "GET" {
					var envelope map[string]json.RawMessage
					if err := json.NewDecoder(req.Body).Decode(&envelope); err != nil {
						t.Fatal(err)
					}
					if string(envelope["confirm"]) != "true" {
						t.Error("mutation not confirmed")
					}
					if req.Method == "POST" {
						if !strings.HasPrefix(req.Header.Get("Idempotency-Key"), "terraform-") {
							t.Error("create lacks intent key")
						}
					} else if req.Header.Get("If-Match") != revisionValue {
						w.WriteHeader(409)
						return
					}
					if req.Method == "DELETE" {
						record = nil
						w.WriteHeader(204)
						return
					}
					if err := json.Unmarshal(envelope[kind], &record); err != nil {
						t.Fatal(err)
					}
					id := "id"
					if kind == "host" {
						id = "server_id"
					}
					record[id], record["_revision"] = "17", revisionValue
				}
				if record == nil {
					w.WriteHeader(404)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{kind: record})
			})
			r := &managedResource{kind: kind, plural: kind + "s", client: client}
			var schemaResponse resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
			var desired managedModel
			if kind == "host" {
				desired = &hostModel{ID: types.StringUnknown(), Revision: types.StringUnknown(), Project: types.StringValue("stage"), Name: types.StringValue("api"), Address: types.StringValue("192.0.2.10"), User: types.StringValue("support"), Port: types.Int64Value(22), NoSudo: types.BoolValue(false), Note: types.StringValue(""), Services: types.StringValue(""), Proxy: types.StringValue(""), Owner: types.StringValue("ops"), Environment: types.StringValue("stage"), Tags: types.MapNull(types.StringType)}
			} else {
				actions, _ := types.SetValueFrom(ctx, types.StringType, []string{"ssh"})
				desired = &grantModel{ID: types.StringUnknown(), Revision: types.StringUnknown(), Subject: types.StringValue("group"), Name: types.StringValue("Support"), Project: types.StringValue("stage"), User: types.StringValue("support"), Sudo: types.StringValue("none"), Host: types.StringValue(""), SubjectID: types.StringValue(""), Actions: actions}
			}
			state := tfsdk.State{Schema: schemaResponse.Schema}
			if d := state.Set(ctx, desired); d.HasError() {
				t.Fatal(d)
			}
			created := resource.CreateResponse{State: tfsdk.State{Schema: schemaResponse.Schema}}
			r.Create(ctx, resource.CreateRequest{Plan: tfsdk.Plan{Schema: schemaResponse.Schema, Raw: state.Raw}}, &created)
			if created.Diagnostics.HasError() {
				t.Fatal(created.Diagnostics)
			}
			read := resource.ReadResponse{State: created.State}
			r.Read(ctx, resource.ReadRequest{State: created.State}, &read)
			if read.Diagnostics.HasError() {
				t.Fatal(read.Diagnostics)
			}
			updated := resource.UpdateResponse{State: read.State}
			r.Update(ctx, resource.UpdateRequest{State: read.State, Plan: tfsdk.Plan{Schema: schemaResponse.Schema, Raw: read.State.Raw}}, &updated)
			if updated.Diagnostics.HasError() {
				t.Fatal(updated.Diagnostics)
			}
			// An independent edit must fail closed rather than overwrite newer state.
			revisionValue = strings.Repeat("b", 64)
			conflict := resource.UpdateResponse{State: updated.State}
			r.Update(ctx, resource.UpdateRequest{State: updated.State, Plan: tfsdk.Plan{Schema: schemaResponse.Schema, Raw: updated.State.Raw}}, &conflict)
			if !conflict.Diagnostics.HasError() {
				t.Fatal("concurrent edit overwritten")
			}
			revisionValue = strings.Repeat("a", 64)
			deleted := resource.DeleteResponse{State: updated.State}
			r.Delete(ctx, resource.DeleteRequest{State: updated.State}, &deleted)
			if deleted.Diagnostics.HasError() {
				t.Fatal(deleted.Diagnostics)
			}
			missing := resource.ReadResponse{State: updated.State}
			r.Read(ctx, resource.ReadRequest{State: updated.State}, &missing)
			if missing.Diagnostics.HasError() || !missing.State.Raw.IsNull() {
				t.Fatal("deleted resource not removed on refresh")
			}
			if strings.Join(methods, ",") != "POST,GET,PUT,PUT,DELETE,GET" {
				t.Fatalf("unexpected lifecycle: %v", methods)
			}
			imported := resource.ImportStateResponse{State: read.State}
			r.ImportState(ctx, resource.ImportStateRequest{ID: "17"}, &imported)
			if imported.Diagnostics.HasError() {
				t.Fatal(imported.Diagnostics)
			}
			var id string
			imported.State.GetAttribute(ctx, path.Root("id"), &id)
			if id != "17" {
				t.Fatal("import lost ID")
			}
		})
	}
}
