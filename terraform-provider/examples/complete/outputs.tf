output "namespace" {
  description = "Starfly namespace."
  value       = kubernetes_namespace.starfly.metadata[0].name
}

output "helm_release_version" {
  description = "Pinned Helm chart version."
  value       = helm_release.starfly.version
}

output "values_hash" {
  description = "SHA256 of pinned Helm values — agents compare on every plan."
  value       = sha256(file("${path.module}/${var.values_file}"))
}

output "fabric_id" {
  description = "StarlightFabric identifier."
  value       = starfly_fabric.main.id
}

output "spec_hash" {
  description = "SHA256 of canonical fabric spec."
  value       = starfly_fabric.main.spec_hash
}

output "fabric_phase" {
  description = "Current fabric phase."
  value       = starfly_fabric.main.phase
}

output "health_endpoint" {
  description = "Agent-readable health check URL (plaintext port in dev)."
  value       = "http://starfly.${kubernetes_namespace.starfly.metadata[0].name}.svc:8693/v1/sys/health"
}

output "jwks_url" {
  description = "JWKS endpoint for issued tokens."
  value       = "http://starfly.${kubernetes_namespace.starfly.metadata[0].name}.svc:8693/v1/identity/jwks"
}
