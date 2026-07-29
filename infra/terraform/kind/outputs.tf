output "cluster_name" {
  value = kind_cluster.aegis.name
}

output "kubeconfig_path" {
  description = "Path to the kubeconfig kind wrote"
  value       = kind_cluster.aegis.kubeconfig_path
}

output "registry" {
  description = "Push signed models here (AEGIS_REGISTRY)"
  value       = "localhost:${var.registry_port}"
}

output "argocd_url" {
  description = "ArgoCD UI"
  value       = "http://localhost:30080"
}

output "argocd_admin_password_command" {
  value = "kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d"
}
