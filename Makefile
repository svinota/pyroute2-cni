noxboot ?= ~/.venv-boot

define nox
        {\
		which nox 2>/dev/null || {\
		    test -d ${noxboot} && \
				{\
					. ${noxboot}/bin/activate;\
				} || {\
					python -m venv ${noxboot};\
					. ${noxboot}/bin/activate;\
					pip install --upgrade pip;\
					pip install nox;\
				};\
		};\
		nox $(1) -- '${noxconfig}';\
	}
endef


.PHONY: clean
clean:
	rm -rf dist
	rm -rf *egg-info
	rm -rf __pycache__

.PHONY: image-clean
image-clean:
	for i in `podman images | awk '/pyroute2-cni/ {print($$1":"$$2)}'`; do podman rmi $$i; done

.PHONY: version
version:
	echo `cat VERSION | awk -F . '{print($$1"."$$2"."$$3 + 1)}'` >VERSION

.PHONY: build
build: clean version
	make -C pyroute2_plugin
	$(call nox,-e build)
	podman build -t ghcr.io/svinota/pyroute2-cni:`cat VERSION` .
	podman push ghcr.io/svinota/pyroute2-cni:`cat VERSION`


.PHONY: patch
patch:
	sed -i "s/\(pyroute2-cni:\)v[0-9.]\+/\\1$$(cat VERSION)/" kubernetes/pyroute2-cni.yaml learning/Dockerfile
	kubectl -n pyroute2-cni \
		patch daemonset pyroute2-cni \
		--type='json' \
		-p='[{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": "ghcr.io/svinota/pyroute2-cni:'$$(cat VERSION)'"}]'

.PHONY: deploy
deploy: build patch
