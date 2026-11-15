terraform {
  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "= 0.9.9"
    }
    talos = {
      source  = "siderolabs/talos"
      version = "= 0.12.0"
    }
  }
}

provider "libvirt" {
  uri = "qemu:///system"
}

variable "image_name" {
  type = string
}

variable "node_count" {
  type = number
}

variable "platform" {
  type    = string
  default = "ubuntu26"

  validation {
    condition = contains(
      ["ubuntu24", "ubuntu25", "ubuntu26", "talos"], var.platform
    )
    error_message = "Unsupported VM platform."
  }
}

variable "talos_version" {
  type = string
}

resource "libvirt_pool" "test" {
  name = "cni-test"
  type = "dir"
  target = {
    path = abspath(path.root)
  }
  create = {
    build     = false
    start     = true
    autostart = false
  }
  destroy = {
    delete = false
  }
}

module "ubuntu" {
  source = "./modules/ubuntu"
  count  = startswith(var.platform, "ubuntu") ? 1 : 0

  pool_name  = libvirt_pool.test.name
  work_dir   = abspath(path.root)
  image_name = var.image_name
  node_count = var.node_count
}

module "talos" {
  source = "./modules/talos"
  count  = var.platform == "talos" ? 1 : 0

  pool_name     = libvirt_pool.test.name
  work_dir      = abspath(path.root)
  image_name    = var.image_name
  node_count    = var.node_count
  talos_version = var.talos_version
}

output "node_ips" {
  value = one(concat(
    module.ubuntu[*].node_ips,
    module.talos[*].node_ips
  ))
}

output "kubeconfig" {
  value     = one(module.talos[*].kubeconfig)
  sensitive = true
}

output "talosconfig" {
  value     = one(module.talos[*].talosconfig)
  sensitive = true
}
