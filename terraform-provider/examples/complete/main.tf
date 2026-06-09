terraform {
  required_version = ">= 1.6.0"

  required_providers {
    starfly = {
      source  = "starfly-fabrics/starfly"
      version = "0.1.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.17"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.35"
    }
  }
}

provider "kubernetes" {
  config_path = var.kubeconfig_path
}

provider "helm" {
  kubernetes {
    config_path = var.kubeconfig_path
  }
}

provider "starfly" {
  kubeconfig_path = var.kubeconfig_path
  namespace       = kubernetes_namespace.starfly.metadata[0].name
  endpoint        = var.starfly_endpoint
  ca_cert         = var.starfly_ca_cert
  client_cert     = var.starfly_client_cert
  client_key      = var.starfly_client_key
}

resource "kubernetes_namespace" "starfly" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }
}

resource "helm_release" "starfly" {
  name       = "starfly"
  chart      = "${path.module}/../../../deploy/helm"
  version    = var.chart_version
  namespace  = kubernetes_namespace.starfly.metadata[0].name
  values     = [file("${path.module}/${var.values_file}")]

  depends_on = [kubernetes_namespace.starfly]
}

resource "starfly_fabric" "main" {
  name      = var.fabric_name
  namespace = kubernetes_namespace.starfly.metadata[0].name

  trust_domains {
    name    = "k8s-default"
    type    = "oidc"
    issuer  = var.oidc_issuer
    jwks_uri = var.oidc_jwks_uri
    enabled = true
  }

  policy {
    bundle_path = "/etc/starfly/policies/"
  }

  wait_for_converged = var.wait_for_converged

  depends_on = [helm_release.starfly]
}
