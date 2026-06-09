package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func protoV6ProviderFactories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"starfly": providerserver.NewProtocol6WithError(New("test")()),
	}
}

func TestAccFabricResourceLifecycle(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC=1 to run acceptance tests")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
provider "starfly" {
  kubeconfig_path = %q
  namespace       = "default"
}

resource "starfly_fabric" "test" {
  name = "tf-acc-fabric"

  trust_domains {
    name     = "k8s-default"
    type     = "oidc"
    issuer   = "https://keycloak.example.com/realms/starfly"
    jwks_uri = "https://keycloak.example.com/realms/starfly/protocol/openid-connect/certs"
    enabled  = true
  }

  wait_for_converged = false
}
`, acctestKubeconfig),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("starfly_fabric.test", "name", "tf-acc-fabric"),
					resource.TestCheckResourceAttrSet("starfly_fabric.test", "spec_hash"),
				),
			},
			{
				Config: fmt.Sprintf(`
provider "starfly" {
  kubeconfig_path = %q
  namespace       = "default"
}

resource "starfly_fabric" "test" {
  name = "tf-acc-fabric"

  trust_domains {
    name     = "k8s-default"
    type     = "oidc"
    issuer   = "https://keycloak.example.com/realms/starfly"
    jwks_uri = "https://keycloak.example.com/realms/starfly/protocol/openid-connect/certs"
    enabled  = false
  }

  wait_for_converged = false
}
`, acctestKubeconfig),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("starfly_fabric.test", "name", "tf-acc-fabric"),
				),
			},
		},
	})
}

func TestAccMCPToolLifecycle(t *testing.T) {
	token := skipUnlessBearerAuthWorks(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
provider "starfly" {
  endpoint  = %q
  jwt_token = %q
}

resource "starfly_mcp_tool" "test" {
  tool_id     = "tf-acc-tool"
  name        = "TF Acc Tool"
  description = "registered by terraform acceptance test"
}
`, acctestStarflyEndpoint(), token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("starfly_mcp_tool.test", "tool_id", "tf-acc-tool"),
					resource.TestCheckResourceAttr("starfly_mcp_tool.test", "name", "TF Acc Tool"),
				),
			},
		},
	})
}

func TestAccAgentIdentityLifecycle(t *testing.T) {
	token := skipUnlessBearerAuthWorks(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
provider "starfly" {
  endpoint  = %q
  jwt_token = %q
}

resource "starfly_agent_identity" "test" {
  agent_name   = "tf-acc-agent"
  platform     = "mcp"
  capabilities = ["read", "write"]
}
`, acctestStarflyEndpoint(), token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("starfly_agent_identity.test", "agent_name", "tf-acc-agent"),
					resource.TestCheckResourceAttrSet("starfly_agent_identity.test", "token"),
					resource.TestCheckResourceAttrSet("starfly_agent_identity.test", "workload_id"),
				),
			},
		},
	})
}

func TestAccSSFStreamLifecycle(t *testing.T) {
	skipUnlessStarflyAPI(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
provider "starfly" {
  endpoint = %q
}

resource "starfly_ssf_stream" "test" {
  issuer           = "https://starfly.example.com"
  audience         = "https://receiver.example.com"
  events_requested = ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"]
  delivery_method  = "poll"
}
`, acctestStarflyEndpoint()),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("starfly_ssf_stream.test", "id"),
					resource.TestCheckResourceAttrSet("starfly_ssf_stream.test", "status"),
				),
			},
		},
	})
}

func TestAccEncryptionKeyLifecycle(t *testing.T) {
	t.Skip("encryption_key acc: JWK body encoding from Terraform string attribute needs fix (OP-001 follow-up)")
	token := skipUnlessBearerAuthWorks(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
provider "starfly" {
  endpoint  = %q
  jwt_token = %q
}

resource "starfly_encryption_key" "test" {
  public_key = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SR32vgKOCeraNOJ9gaTd4Ukrc_5XFOIME3XIiIdDanrCjD\"}"
}
`, acctestStarflyEndpoint(), token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("starfly_encryption_key.test", "id"),
				),
			},
		},
	})
}
