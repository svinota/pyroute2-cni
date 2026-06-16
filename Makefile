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
			s/{cni_version}/$$(cat VERSION)/;\
		" >kubernetes/releases/dev/kustomization.yaml;\
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

.PHONY: ghcr-clean
ghcr-clean:
	for i in `gh api -H 'Accept: application/vnd.github+json' /user/packages/container/pyroute2-cni/versions --jq '.[] | [.id, .metadata.container.tags[0]] | @csv' | awk -F, 'NR==FNR {tags[$$1]; next} {tag=$$2; gsub(/"/, "", tag); if (!(tag in tags)) print($$1":"tag)}' tags -`; do echo -n "DEL `echo $$i | sed 's/.*://'`: "; gh api -H 'Accept: application/vnd.github+json' -X DELETE /user/packages/container/pyroute2-cni/versions/`echo $$i | sed 's/:.*//'`; echo $$?; done

.PHONY: version
version:
	echo `cat images/cni/VERSION | awk -F . '{print($$1"."$$2"."$$3 + 1)}'` >images/cni/VERSION

.PHONY: build
build: clean version
	make -C pyroute2_plugin
	$(call nox,-e build)
	podman build -t ghcr.io/svinota/pyroute2-cni:`cat images/cni/VERSION` .
	podman push ghcr.io/svinota/pyroute2-cni:`cat images/cni/VERSION`
	$(call render_dev_kustomization,)


.PHONY: deploy
deploy: build
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
