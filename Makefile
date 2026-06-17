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

define render_dev_kustomization
	{\
		cat kubernetes/releases/dev/kustomization.yaml.tpl |\
		sed "\
			s/{cni_image}/$$(cat images/cni/VERSION)/;\
			s/{frr_image}/$$(cat images/frr/VERSION)/;\
			s/{cni_version}/$$(cat VERSION)/;\
		" >kubernetes/releases/dev/kustomization.yaml;\
	}
endef


.PHONY: clean
clean:
	rm -rf dist
	rm -rf *egg-info
	rm -rf __pycache__
	./tests/test_install/cleanup.sh

.PHONY: image-clean
image-clean:
	for i in `podman images | awk '/pyroute2-cni/ {print($$1":"$$2)}'`; do podman rmi $$i; done

.PHONY: ghcr-clean
ghcr-clean:
	for i in `gh api -H 'Accept: application/vnd.github+json' /user/packages/container/pyroute2-cni/versions --jq '.[] | [.id, .metadata.container.tags[0]] | @csv' | awk -F, 'NR==FNR {tags[$$1]; next} {tag=$$2; gsub(/"/, "", tag); if (!(tag in tags)) print($$1":"tag)}' tags -`; do echo -n "DEL `echo $$i | sed 's/.*://'`: "; gh api -H 'Accept: application/vnd.github+json' -X DELETE /user/packages/container/pyroute2-cni/versions/`echo $$i | sed 's/:.*//'`; echo $$?; done

.PHONY: frr-image-version
frr-image-version:
	echo `cat images/frr/VERSION | awk -F . '{print($$1"."$$2"."$$3 + 1)}'` >images/frr/VERSION

.PHONY: frr-image-build
frr-image-build: frr-image-version
	pushd images/frr; \
		podman build -t ghcr.io/svinota/pyroute2-frr:`cat VERSION` .; \
		podman push ghcr.io/svinota/pyroute2-frr:`cat VERSION`; \
		popd

.PHONY: cni-image-version
cni-image-version:
	echo `cat images/cni/VERSION | awk -F . '{print($$1"."$$2"."$$3 + 1)}'` >images/cni/VERSION

.PHONY: cni-image-build
cni-image-build: clean cni-image-version
	make -C pyroute2_plugin
	$(call nox,-e build)
	podman build -t ghcr.io/svinota/pyroute2-cni:`cat images/cni/VERSION` .
	podman push ghcr.io/svinota/pyroute2-cni:`cat images/cni/VERSION`

.PHONY: render-kustomization
render-kustomization:
	$(call render_dev_kustomization,)


.PHONY: deploy
deploy: cni-image-build render-kustomization
	kubectl apply -k kubernetes/releases/dev/

.PHONY: test nox
test nox:
	$(call nox,-e ${session})

.PHONY: format
format:
	$(call nox,-e linter)

.PHONY: docs
docs:
	$(call nox,-e docs)
