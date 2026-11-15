terraform {
  required_providers {
    libvirt = {
      source = "dmacvicar/libvirt"
    }
    talos = {
      source = "siderolabs/talos"
    }
  }
}

variable "pool_name" {
  type = string
}

variable "work_dir" {
  type = string
}

variable "image_name" {
  type = string
}

variable "node_count" {
  type = number
}

variable "talos_version" {
  type = string
}

locals {
  node_ips = [
    for node in data.libvirt_domain_interface_addresses.node :
    one(flatten([
      for interface in node.interfaces : [
        for address in interface.addrs :
        address.addr if address.type == "ipv4"
      ]
    ]))
  ]
  node_subnets = [
    for node in data.libvirt_domain_interface_addresses.node :
    one(flatten([
      for interface in node.interfaces : [
        for address in interface.addrs :
        cidrsubnet("${address.addr}/${address.prefix}", 0, 0)
        if address.type == "ipv4"
      ]
    ]))
  ]
}

resource "libvirt_volume" "talos_iso" {
  name = "cni-test-talos.iso"
  pool = var.pool_name
  target = {
    format = { type = "iso" }
  }
  create = {
    content = {
      url = "${var.work_dir}/${var.image_name}"
    }
  }
}

resource "talos_machine_secrets" "cluster" {
  talos_version = var.talos_version
}

data "talos_machine_configuration" "node" {
  count = var.node_count

  cluster_name       = "cni-test"
  machine_type       = "controlplane"
  cluster_endpoint   = "https://${local.node_ips[0]}:6443"
  machine_secrets    = talos_machine_secrets.cluster.machine_secrets
  talos_version      = var.talos_version
  kubernetes_version = "1.37.0"

  config_patches = [
    templatefile("${path.module}/talos.yaml.tftpl", {
      hostname      = "cni-test-${count.index}"
      node_subnet   = local.node_subnets[count.index]
      talos_version = var.talos_version
    })
  ]
}

resource "talos_machine_configuration_apply" "node" {
  count = var.node_count

  node = local.node_ips[count.index]
  client_configuration = (
    talos_machine_secrets.cluster.client_configuration
  )
  machine_configuration_input = (
    data.talos_machine_configuration.node[count.index].machine_configuration
  )
}

resource "talos_machine_bootstrap" "cluster" {
  depends_on = [talos_machine_configuration_apply.node]

  node = local.node_ips[0]
  client_configuration = (
    talos_machine_secrets.cluster.client_configuration
  )
}

resource "talos_cluster_kubeconfig" "cluster" {
  depends_on = [talos_machine_bootstrap.cluster]

  node = local.node_ips[0]
  client_configuration = (
    talos_machine_secrets.cluster.client_configuration
  )
}

data "talos_client_configuration" "cluster" {
  cluster_name = "cni-test"
  client_configuration = (
    talos_machine_secrets.cluster.client_configuration
  )
  endpoints = [local.node_ips[0]]
  nodes     = local.node_ips
}

resource "libvirt_volume" "node" {
  count = var.node_count

  name       = "cni-test-${count.index}.qcow2"
  pool       = var.pool_name
  capacity   = 30 * 1024 * 1024 * 1024
  allocation = 0
  target = {
    format = { type = "qcow2" }
  }
}

resource "libvirt_domain" "node" {
  count = var.node_count

  name        = "cni-test-${count.index}"
  type        = "kvm"
  memory      = 4096
  memory_unit = "MiB"
  vcpu        = 2
  running     = true

  cpu = {
    mode = "host-model"
  }

  os = {
    type         = "hvm"
    type_arch    = "x86_64"
    type_machine = "q35"
    boot_devices = [{ dev = "hd" }, { dev = "cdrom" }]
  }

  features = {
    acpi = true
    apic = {}
  }

  devices = {
    graphics = [{
      spice = {
        auto_port = true
        listen    = "127.0.0.1"
      }
    }]
    videos = [{
      model = { type = "vga" }
    }]
    disks = [
      {
        device = "disk"
        driver = { name = "qemu", type = "qcow2" }
        source = {
          file = { file = libvirt_volume.node[count.index].path }
        }
        target = { dev = "vda", bus = "virtio" }
      },
      {
        device    = "cdrom"
        read_only = true
        driver    = { name = "qemu", type = "raw" }
        source = {
          file = {
            file = libvirt_volume.talos_iso.path
          }
        }
        target = { dev = "sda", bus = "sata" }
      }
    ]
    interfaces = [{
      model = { type = "virtio" }
      source = {
        network = { network = "default" }
      }
      wait_for_ip = {
        source  = "lease"
        network = "0.0.0.0/0"
        timeout = 100
      }
    }]
  }

  destroy = {
    graceful = false
  }
}

data "libvirt_domain_interface_addresses" "node" {
  count = var.node_count

  domain = libvirt_domain.node[count.index].uuid
  source = "lease"
}

output "node_ips" {
  value = local.node_ips
}

output "kubeconfig" {
  value     = talos_cluster_kubeconfig.cluster.kubeconfig_raw
  sensitive = true
}

output "talosconfig" {
  value     = data.talos_client_configuration.cluster.talos_config
  sensitive = true
}
