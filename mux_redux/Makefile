SDK_ROOT=$(shell xcrun --show-sdk-path)
CFLAGS=-force_cpusubtype_ALL -mmacosx-version-min=10.6 -arch x86_64 \
	-F$(SDK_ROOT)/System/Library/Frameworks -DMUX_BUILD=1 \
	-F$(SDK_ROOT)/System/Library/PrivateFrameworks
LD_FLAGS=-framework CoreFoundation -framework MobileDevice \
	-install_name @loader_path/$(LIB)
TOOL=fuzzy_patcher
LIB=mux_redux.jnilib
SOURCES=mux.c itmd.c

$(LIB): $(SOURCES)
	gcc -dynamiclib -o $(LIB) $(CFLAGS) $(LD_FLAGS) $(SOURCES)

all: $(LIB)

clean:
	rm $(LIB)
