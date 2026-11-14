terraform {
  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "= 0.9.9"
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

resource "libvirt_cloudinit_disk" "node" {
  count = var.node_count

  name = "cni-test-${count.index}-seed"
  meta_data = yamlencode({
    instance-id    = "cni-test-${count.index}"
    local-hostname = "cni-test-${count.index}"
  })
  user_data = format("#cloud-config\n%s", yamlencode({
    hostname = "cni-test-${count.index}"
    users = [{
      name                = "ubuntu"
      sudo                = "ALL=(ALL) NOPASSWD:ALL"
      shell               = "/bin/bash"
      ssh_authorized_keys = [trimspace(file("${path.root}/id-cni-test.pub"))]
    }]
    package_update = true
    packages       = ["curl"]
  }))
}

resource "libvirt_volume" "seed" {
  count = var.node_count

  name = "cni-test-${count.index}-seed.iso"
  pool = libvirt_pool.test.name
  target = {
    format = { type = "raw" }
  }
  create = {
    content = {
      url = libvirt_cloudinit_disk.node[count.index].path
    }
  }
}

resource "libvirt_volume" "node" {
  count = var.node_count

  name       = "cni-test-${count.index}.qcow2"
  pool       = libvirt_pool.test.name
  capacity   = 30 * 1024 * 1024 * 1024
  allocation = 0
  target = {
    format = { type = "qcow2" }
  }
  backing_store = {
    path   = "${abspath(path.root)}/${var.image_name}"
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

  metadata = {
    xml = <<-XML
      <libosinfo:libosinfo xmlns:libosinfo="http://libosinfo.org/xmlns/libvirt/domain/1.0">
        <libosinfo:os id="http://ubuntu.com/ubuntu/25.10"/>
      </libosinfo:libosinfo>
    XML
  }

  os = {
    type         = "hvm"
    type_arch    = "x86_64"
    boot_devices = [{ dev = "hd" }]
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
            file = libvirt_volume.seed[count.index].path
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
  value = [
    for node in data.libvirt_domain_interface_addresses.node :
    one(flatten([
      for interface in node.interfaces : [
        for address in interface.addrs :
        address.addr if address.type == "ipv4"
      ]
    ]))
  ]
}
