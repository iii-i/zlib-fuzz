# Required environment variables:
# - ZLIB: path to a zlib build directory configured with libFuzzer
# - ZLIB_AFL: path to a (different) zlib build directory configured with AFL
# Required programs in $PATH:
# - afl-clang-fast++
# - clang++

O?=
ifeq ($(O),)
	OUTPUT=./
else
	OUTPUT=$(O)/
endif

CXX=clang++
AFLCXX=afl-clang-fast++
PROTOBUF_PATH=$(OUTPUT)libprotobuf-mutator/build/external.protobuf
PROTOC=$(PROTOBUF_PATH)/bin/protoc
override CXXFLAGS:=-std=c++17 -fPIC -Wall -Wextra -Werror -O2 -g -isystem libprotobuf-mutator -isystem $(PROTOBUF_PATH)/include $(CXXFLAGS)
override LDFLAGS:=-L$(OUTPUT)libprotobuf-mutator/build/src -L$(OUTPUT)libprotobuf-mutator/build/src/libfuzzer -L$(PROTOBUF_PATH)/lib $(LDFLAGS)
LIBZ_A:=$(ZLIB)/libz.a
LIBZ_A_AFL:=$(ZLIB_AFL)/libz.a

.PHONY: all
all: $(OUTPUT)fuzz $(OUTPUT)fuzz_libprotobuf_mutator $(OUTPUT)fuzz_afl

$(OUTPUT)fuzz: $(OUTPUT)fuzz_target.o $(OUTPUT)fuzz_target.pb.o $(LIBZ_A)
	$(CXX) $(LDFLAGS) -fsanitize=address,fuzzer $(OUTPUT)fuzz_target.o $(OUTPUT)fuzz_target.pb.o -o $@ $(LIBZ_A) -lprotobuf

$(OUTPUT)fuzz_libprotobuf_mutator: $(OUTPUT)fuzz_target_libprotobuf_mutator.o $(OUTPUT)fuzz_target.pb.o $(LIBZ_A)
	$(CXX) $(LDFLAGS) -fsanitize=address,fuzzer $(OUTPUT)fuzz_target_libprotobuf_mutator.o $(OUTPUT)fuzz_target.pb.o -o $@ $(LIBZ_A) -lprotobuf-mutator-libfuzzer -lprotobuf-mutator -lprotobuf

# For building for afl, run
# make ZLIB=path/to/zlib AFL=path/to/AFLplusplus afl
.PHONY: afl
afl: $(OUTPUT)fuzz_afl
	@echo "Now kick off afl as follows:"
	@echo "$ afl-fuzz -m none -i in -o out ./$^"
	@echo
	@echo "where"
	@echo "  -m disables the memory limit (required for ASAN)"
	@echo "  -i in is the directory with the starting corpus"
	@echo "  -o out is afl's run state and output directory"
	@echo
	@echo "Note: to resume a previous session, specify '-i -' as input directory"

$(OUTPUT)fuzz_afl: $(OUTPUT)fuzz_target_afl.o $(OUTPUT)fuzz_target.pb_afl.o $(OUTPUT)afl_driver.o $(LIBZ_A_AFL)
	$(AFLCXX) $(LDFLAGS) -o $@ $^ -lprotobuf

$(LIBZ_A): $(foreach file,$(shell git -C $(ZLIB) ls-files),$(ZLIB)/$(file))
	cd $(ZLIB) && $(MAKE) libz.a

$(LIBZ_A_AFL): $(foreach file,$(shell git -C $(ZLIB_AFL) ls-files),$(ZLIB_AFL)/$(file))
	cd $(ZLIB_AFL) && $(MAKE) libz.a

$(OUTPUT)fuzz_target.o: fuzz_target.cpp $(OUTPUT)fuzz_target.pb.h | fmt
	$(CXX) $(CXXFLAGS) -fsanitize=address,fuzzer -DZLIB_CONST -I$(OUTPUT) -c fuzz_target.cpp -o $@

$(OUTPUT)fuzz_target_libprotobuf_mutator.o: fuzz_target.cpp $(OUTPUT)fuzz_target.pb.h | fmt
	$(CXX) $(CXXFLAGS) -fsanitize=address,fuzzer -DUSE_LIBPROTOBUF_MUTATOR -DZLIB_CONST -I$(OUTPUT) -c fuzz_target.cpp -o $@

$(OUTPUT)fuzz_target_afl.o: fuzz_target.cpp $(OUTPUT)fuzz_target.pb.h | fmt
	$(AFLCXX) $(CXXFLAGS) -DZLIB_CONST -I$(OUTPUT) -c fuzz_target.cpp -o $@

$(OUTPUT)fuzz_target.pb.o: $(OUTPUT)fuzz_target.pb.cc $(OUTPUT)fuzz_target.pb.h
	$(CXX) $(CXXFLAGS) -c $(OUTPUT)fuzz_target.pb.cc -o $@

$(OUTPUT)fuzz_target.pb_afl.o: $(OUTPUT)fuzz_target.pb.cc $(OUTPUT)fuzz_target.pb.h
	$(AFLCXX) $(CXXFLAGS) -c $(OUTPUT)fuzz_target.pb.cc -o $@

$(OUTPUT)fuzz_target.pb.cc $(OUTPUT)fuzz_target.pb.h: fuzz_target.proto $(PROTOC)
	$(PROTOC) --cpp_out=$(OUTPUT) fuzz_target.proto

$(OUTPUT)afl_driver.o: afl_driver.cpp
	$(CXX) $(CXXFLAGS) -c $^ -o $@

$(OUTPUT)libprotobuf-mutator/build/Makefile: libprotobuf-mutator/CMakeLists.txt
	mkdir -p $(OUTPUT)libprotobuf-mutator/build && \
		cmake \
			-S libprotobuf-mutator \
			-B $(OUTPUT)libprotobuf-mutator/build \
			-DCMAKE_C_COMPILER=clang \
			-DCMAKE_CXX_COMPILER=clang++ \
			-DCMAKE_BUILD_TYPE=RelWithDebInfo \
			-DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON

$(PROTOC): $(OUTPUT)libprotobuf-mutator/build/Makefile
	cd $(OUTPUT)libprotobuf-mutator/build && $(MAKE)

$(OUTPUT)zlib-ng/build-libfuzzer/Makefile: zlib-ng/CMakeLists.txt
	mkdir -p $(OUTPUT)zlib-ng/build-libfuzzer && \
		cmake \
			-S zlib-ng \
			-B $(OUTPUT)zlib-ng/build-libfuzzer \
			-DCMAKE_C_COMPILER=clang \
			-DCMAKE_C_FLAGS=-fsanitize=address,fuzzer-no-link \
			-DCMAKE_BUILD_TYPE=RelWithDebInfo \
			-DZLIB_COMPAT=ON

$(OUTPUT)zlib-ng/build-libfuzzer/libz.a: \
		$(OUTPUT)zlib-ng/build-libfuzzer/Makefile \
		$(foreach file,$(shell git -C zlib-ng ls-files),zlib-ng/$(file))
	cd $(OUTPUT)zlib-ng/build-libfuzzer && $(MAKE)

.PHONY: fmt
fmt:
	clang-format -i -style=llvm fuzz_target.cpp
