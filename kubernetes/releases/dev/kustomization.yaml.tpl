apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - ../../base/0.2

images:
  - name: ghcr.io/svinota/pyroute2-cni
    newTag: {cni_image}
  - name: ghcr.io/svinota/pyroute2-frr
    newTag: {frr_image}


labels:
  - pairs:
      app.kubernetes.io/part-of: pyroute2-cni
      app.kubernetes.io/version: "{cni_version}"
