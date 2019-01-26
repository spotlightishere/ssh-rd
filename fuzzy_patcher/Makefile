BOOST=$(shell brew --prefix boost)
CFLAGS=-force_cpusubtype_ALL -arch x86_64 -I$(BOOST)/include -L$(BOOST)/lib
TOOL=fuzzy_patcher
LIB=fuzzy_patcher.a

$(LIB):
	g++ -c $(CFLAGS) patcher.cpp
	libtool -static -o $(LIB) patcher.o

$(TOOL): $(LIB)
	g++ $(CFLAGS) -o $(TOOL) main.cpp $(LIB)

all: $(TOOL) $(LIB)
