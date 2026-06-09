variable "wait_for_converged" {
  type        = bool
  description = "Wait for StarlightFabric status.phase == Converged (requires operator)."
  default     = true
}

variable "values_file" {
  type        = string
  description = "Helm values file relative to this module (e.g. values-pinned.yaml or values-home-lab.yaml)."
  default     = "values-pinned.yaml"
}

variable "kubeconfig_path" {
  type        = string
  description = "Path to kubeconfig."
  default     = "~/.kube/config"
}

variable "namespace" {
  type        = string
  description = "Namespace for Starfly."
  default     = "starfly-system"
}

variable "fabric_name" {
  type        = string
  description = "StarlightFabric resource name."
  default     = "prod"
}

variable "chart_version" {
  type        = string
  description = "Pinned Helm chart version."
  default     = "0.4.0"
}

variable "starfly_endpoint" {
  type        = string
  description = "Starfly API endpoint for runtime resources."
  default     = ""
}

variable "starfly_ca_cert" {
  type        = string
  description = "CA cert path or PEM for Starfly API mTLS."
  default     = ""
  sensitive   = true
}

variable "starfly_client_cert" {
  type        = string
  description = "Client cert path or PEM for Starfly API mTLS."
  default     = ""
  sensitive   = true
}

variable "starfly_client_key" {
  type        = string
  description = "Client key path or PEM for Starfly API mTLS."
  default     = ""
  sensitive   = true
}

variable "oidc_issuer" {
  type        = string
  description = "OIDC issuer URL for trust domain."
  default     = "https://keycloak.example.com/realms/starfly"
}

variable "oidc_jwks_uri" {
  type        = string
  description = "OIDC JWKS URI for trust domain."
  default     = "https://keycloak.example.com/realms/starfly/protocol/openid-connect/certs"
}
