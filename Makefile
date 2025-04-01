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

.PHONY: dist
dist: clean
	$(call nox,-e build)
