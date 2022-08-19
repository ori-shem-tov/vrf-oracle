SRCPATH     := $(shell pwd)
ARCH        := $(shell ./scripts/archtype.sh)
OS_TYPE     := $(shell ./scripts/ostype.sh)

.PHONY: build-libsodium lint lint-fix go-lint python-lint go-lint-fix test fmt cloudbuild vendor

# build our fork of libsodium, placing artifacts into lib/ and include/
build-libsodium: libs/$(OS_TYPE)/$(ARCH)/lib/libsodium.a

lint: python-lint go-lint

lint-fix: python-lint go-lint-fix

python-lint:
	pylint --rcfile pyteal/.pylintrc pyteal/*.py

go-lint:
	golangci-lint run
	gosec ./...

go-lint-fix:
	golangci-lint run --fix
	gosec ./...

test:
	go test ./...

fmt:
	for f in $$(go list ./... | grep -v /vendor/); do gofmt -s -w $${f#github.com/ori-shem-tov/vrf-oracle/}; done

vendor:
	go mod vendor

libs/$(OS_TYPE)/$(ARCH)/lib/libsodium.a:
	mkdir -p copies/$(OS_TYPE)/$(ARCH)
	cp -R libsodium copies/$(OS_TYPE)/$(ARCH)/libsodium
	cd copies/$(OS_TYPE)/$(ARCH)/libsodium && \
		./autogen.sh --prefix $(SRCPATH)/libs/$(OS_TYPE)/$(ARCH) && \
		./configure --disable-shared --prefix="$(SRCPATH)/libs/$(OS_TYPE)/$(ARCH)" && \
		$(MAKE) && \
		$(MAKE) install

clean:
	rm -rf libs/$(OS_TYPE)/$(ARCH)/lib/libsodium.a copies/$(OS_TYPE)/$(ARCH)/libsodium
