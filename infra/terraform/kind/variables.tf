variable "cluster_name" {
  description = "Name of the local kind cluster"
  type        = string
  default     = "aegis"
}

variable "node_image" {
  description = "kind node image (pin this — cluster version is part of provenance)"
  type        = string
  default     = "kindest/node:v1.31.0"
}

variable "registry_name" {
  description = "Container name of the internal Zot OCI registry"
  type        = string
  default     = "aegis-registry"
}

variable "registry_port" {
  description = "Host port the internal registry is published on"
  type        = number
  default     = 5001
}

variable "zot_image" {
  description = "Zot registry image"
  type        = string
  default     = "ghcr.io/project-zot/zot-linux-arm64:latest"
}

variable "argocd_chart_version" {
  description = "argo-cd Helm chart version"
  type        = string
  default     = "7.6.12"
}
