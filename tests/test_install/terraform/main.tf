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
            file = "${abspath(path.root)}/cni-test-${count.index}-seed.iso"
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
    }]
  }

  destroy = {
    graceful = false
  }
}
