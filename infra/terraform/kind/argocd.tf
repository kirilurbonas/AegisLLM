# ---------------------------------------------------------------------------
# ArgoCD — the only thing permitted to change cluster state.
#
# Nothing in this platform is deployed with `kubectl apply` by a human; the
# cluster reconciles what is in git. That is what makes the deployment path
# auditable, and in Pillar 2 it is what a Kyverno admission policy gets to
# gate: git says what should run, policy says what may run.
# ---------------------------------------------------------------------------

provider "helm" {
  kubernetes {
    host                   = kind_cluster.aegis.endpoint
    client_certificate     = kind_cluster.aegis.client_certificate
    client_key             = kind_cluster.aegis.client_key
    cluster_ca_certificate = kind_cluster.aegis.cluster_ca_certificate
  }
}

provider "kubernetes" {
  host                   = kind_cluster.aegis.endpoint
  client_certificate     = kind_cluster.aegis.client_certificate
  client_key             = kind_cluster.aegis.client_key
  cluster_ca_certificate = kind_cluster.aegis.cluster_ca_certificate
}

resource "helm_release" "argocd" {
  name             = "argocd"
  namespace        = "argocd"
  create_namespace = true
  repository       = "https://argoproj.github.io/argo-helm"
  chart            = "argo-cd"
  version          = var.argocd_chart_version
  wait             = true
  timeout          = 900

  # Local dev only: TLS is terminated at the port-forward, so insecure mode
  # avoids the redirect loop. A real cluster would front this with the mesh.
  values = [yamlencode({
    configs = {
      params = {
        "server.insecure" = true
      }
    }
    server = {
      service = {
        type         = "NodePort"
        nodePortHttp = 30080
      }
    }
    dex           = { enabled = false }
    notifications = { enabled = false }
  })]

  depends_on = [kind_cluster.aegis]
}
