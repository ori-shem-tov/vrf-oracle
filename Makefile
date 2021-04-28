SRCPATH     := $(shell pwd)
ARCH        := $(shell ./scripts/archtype.sh)
OS_TYPE     := $(shell ./scripts/ostype.sh)

.PHONY: build-libsodium

# build our fork of libsodium, placing artifacts into lib/ and include/
build-libsodium: libs/$(OS_TYPE)/$(ARCH)/lib/libsodium.a

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
