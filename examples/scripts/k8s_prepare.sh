#!/bin/bash


function apt-run() {
    for i in `seq 60`; do {
        sudo apt-get "$@" && return 0
        sleep 1
    } done
    exit -1
}

sudo swapoff -a
sudo sed -i 's!^/swap!#/swap!' /etc/fstab

# kernel modules
sudo modprobe overlay
sudo modprobe br_netfilter
sudo tee /etc/modules-load.d/k8s.conf <<EOF
overlay
br_netfilter
vrf
EOF

# sysctl
sudo tee /etc/sysctl.d/k8s.conf <<EOF
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF
sudo sysctl --system

# docker
apt-run update
apt-run install -y docker.io containerd
sudo systemctl enable --now docker

# containerd
sudo mkdir /etc/containerd
sudo sh -c "containerd config default > /etc/containerd/config.toml"
sudo sed -i 's/ SystemdCgroup = false/ SystemdCgroup = true/' /etc/containerd/config.toml
sudo systemctl enable --now containerd

sudo systemctl restart docker
sudo systemctl restart containerd

# extra kernel modules for VRF
apt-run install -y linux-modules-extra-`uname -r`

# kubernetes
apt-run install curl ca-certificates apt-transport-https  -y
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.36/deb/Release.key |\
    sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.36/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list

apt-run update
apt-run install -y kubelet kubeadm kubectl
