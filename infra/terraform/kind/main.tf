terraform {
  required_version = ">= 1.6"

  required_providers {
    kind = {
      source  = "tehcyx/kind"
      version = "~> 0.9"
    }
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }
  }
}

provider "docker" {}

# ---------------------------------------------------------------------------
# Internal OCI registry (Zot)
#
# This is the air-gap boundary made concrete: signed models and container images
# land here, and the cluster is configured to resolve them from here. Zot is
# chosen over Harbor deliberately — one container, no database, natively
# OCI-compliant including the referrers API that carries our signatures.
# ---------------------------------------------------------------------------

resource "docker_image" "zot" {
  name = var.zot_image
}

resource "docker_volume" "registry_data" {
  name = "${var.registry_name}-data"
}

resource "docker_container" "registry" {
  name     = var.registry_name
  image    = docker_image.zot.image_id
  restart  = "unless-stopped"
  must_run = true

  # Without this, recreating the container silently empties the registry and
  # every published model has to be rebuilt and re-signed.
  volumes {
    volume_name    = docker_volume.registry_data.name
    container_path = "/var/lib/registry"
  }

  ports {
    internal = 5000
    external = var.registry_port
    ip       = "127.0.0.1"
  }

  networks_advanced {
    name = "kind"
  }

  depends_on = [kind_cluster.aegis]
}

# ---------------------------------------------------------------------------
# Local Kubernetes cluster
#
# containerd is pointed at the Zot registry via a mirror config, so an in-cluster
# image reference like localhost:5001/... resolves to the internal registry
# rather than escaping to Docker Hub.
# ---------------------------------------------------------------------------

resource "kind_cluster" "aegis" {
  name           = var.cluster_name
  node_image     = var.node_image
  wait_for_ready = true

  kind_config {
    kind        = "Cluster"
    api_version = "kind.x-k8s.io/v1alpha4"

    containerd_config_patches = [
      <<-TOML
        [plugins."io.containerd.grpc.v1.cri".registry]
          config_path = "/etc/containerd/certs.d"
      TOML
    ]

    node {
      role = "control-plane"

      kubeadm_config_patches = [
        <<-YAML
          kind: InitConfiguration
          nodeRegistration:
            kubeletExtraArgs:
              node-labels: "ingress-ready=true"
        YAML
      ]

      extra_port_mappings {
        container_port = 30080
        host_port      = 30080
      }
    }
  }
}

# containerd needs a hosts.toml telling it where localhost:5001 actually lives
# from inside the node's network namespace.
resource "null_resource" "registry_mirror" {
  triggers = {
    cluster  = kind_cluster.aegis.id
    registry = docker_container.registry.id
  }

  provisioner "local-exec" {
    command = <<-EOT
      set -euo pipefail
      dir="/etc/containerd/certs.d/localhost:${var.registry_port}"
      for node in $(kind get nodes --name ${var.cluster_name}); do
        docker exec "$node" mkdir -p "$dir"
        docker exec -i "$node" sh -c "cat > $dir/hosts.toml" <<'TOML'
[host."http://${var.registry_name}:5000"]
  capabilities = ["pull", "resolve"]
  skip_verify = true
TOML
      done
    EOT
  }
}
