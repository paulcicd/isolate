package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"isolate.local/terraform-provider-isolate/internal/provider"
)

var version = "dev"

func main() {
	debug := flag.Bool("debug", false, "serve with Terraform reattach configuration")
	flag.Parse()
	if err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/isolate/isolate", Debug: *debug,
	}); err != nil {
		log.Fatal(err)
	}
}
