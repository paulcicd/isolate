terraform {
  required_providers {
    isolate = {
      source = "isolate/isolate"
    }
  }
}

# ISOLATE_ENDPOINT=https://bastion.example
# ISOLATE_TOKEN_FILE=/run/secrets/isolate-api-token
# Refresh that protected file using your IdP/CI credential broker.
provider "isolate" {}

resource "isolate_host" "api" {
  project_name   = "stage"
  server_name    = "api-01"
  server_ip      = "192.0.2.10"
  server_user    = "support"
  server_port    = 22
  server_nosudo  = true
  server_note    = "Managed by Terraform"
  resource_owner = "platform"
  environment    = "stage"
  tags = {
    team = "platform"
  }
}

resource "isolate_grant" "support" {
  subject         = "group"
  name            = "Support"
  project         = isolate_host.api.project_name
  host            = isolate_host.api.server_name
  remote_user     = "support"
  sudo_mode       = "none"
  allowed_actions = ["ssh", "webssh"]
}
