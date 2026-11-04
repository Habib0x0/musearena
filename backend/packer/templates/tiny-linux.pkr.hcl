# MuseArena tiny Linux guest image (AnomalyLab packer layout, tiny scope).
# Builds the Alpine minirootfs initramfs used by provisioner/images.ts.
# When packer is unavailable, `npm run build` in backend still produces the
# identical guest via ensureGuestRootfs() — packer is the versioned recipe.
packer {
  required_plugins {
    qemu = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

variable "alpine_version" { type = string, default = "3.20" }

source "qemu" "tiny-linux" {
  iso_url          = "https://dl-cdn.alpinelinux.org/alpine/v${var.alpine_version}/releases/aarch64/alpine-virt-${var.alpine_version}.0-aarch64.iso"
  output_directory = "output-tiny-linux"
  disk_size        = "512M"
  memory           = 256
  format           = "qcow2"
  headless         = true
}

build {
  sources = ["source.qemu.tiny-linux"]
  provisioner "shell" {
    script = "../scripts/verify-base.sh"
  }
}
