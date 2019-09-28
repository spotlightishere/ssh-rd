SDK_ROOT=$(shell xcrun --show-sdk-path)
CFLAGS=-force_cpusubtype_ALL \
	-F$(SDK_ROOT)/System/Library/Frameworks -DMUX_BUILD=1
LD_FLAGS=-L$(shell pwd)/idevicerestore_root/lib -limobiledevice -lidevicerestore \
	-install_name @loader_path/$(LIB)
TOOL=fuzzy_patcher
LIB=mux_redux.jnilib
SOURCES=mux.c itmd.c

$(LIB): $(SOURCES)
	gcc -dynamiclib -o $(LIB) $(CFLAGS) $(LD_FLAGS) $(SOURCES)

all: fix_idevicerestore
	$(LIB)

fix_idevicerestore:
	# If we've not applied the patch already, go ahead and do that.
	if [ ! -f idevicerestore/src/libidevicerestore.c ]; \
	then \
	  cd idevicerestore && git apply ../idevicerestore-make-library.patch; \
	fi

	# If we've not configured for this system yet, go ahead with that as well.
	if [ ! -f idevicerestore/config.h ]; \
	then \
		cd idevicerestore && bash autogen.sh --prefix=$(shell pwd)/idevicerestore_root; \
	fi

	make -C idevicerestore install
	mkdir -p idevicerestore_root/include/libidevicerestore && cp idevicerestore/src/*.h idevicerestore_root/include/libidevicerestore

clean:
	rm $(LIB)

.DEFAULT_GOAL := all
