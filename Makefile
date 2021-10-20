# Required environment variables:
# - ZLIB: path to a zlib build directory configured with libFuzzer
# - ZLIB_AFL: path to a (different) zlib build directory configured with AFL
# - ZLIB_SYMCC: path to a (yet another) zlib build directory configured with SymCC
# Required programs in $PATH:
# - clang
# - clang++

O?=
ifeq ($(O),)
	OUTPUT=./
else
	OUTPUT=$(O)/
endif
ABS_OUTPUT_1=$(shell mkdir -p $(OUTPUT) && cd $(OUTPUT) && pwd)
ABS_OUTPUT=$(realpath $(ABS_OUTPUT_1))/

CC=clang
CXX=clang++
AFLCC=$(ABS_OUTPUT)AFLplusplus/afl-clang-fast
AFLCXX=$(ABS_OUTPUT)AFLplusplus/afl-clang-fast++
AFL_FUZZ=$(ABS_OUTPUT)AFLplusplus/afl-fuzz
PROTOBUF_PATH=$(OUTPUT)libprotobuf-mutator/build/external.protobuf
PROTOC=$(PROTOBUF_PATH)/bin/protoc
C_CXX_FLAGS=-fPIC -Wall -Wextra -Werror -O2 -g
override CFLAGS:=$(C_CXX_FLAGS) -std=c11 $(CFLAGS)
override CXXFLAGS:=$(C_CXX_FLAGS) -std=c++17 -isystem libprotobuf-mutator -isystem $(PROTOBUF_PATH)/include $(CXXFLAGS)
override LDFLAGS:=-L$(OUTPUT)libprotobuf-mutator/build/src -L$(OUTPUT)libprotobuf-mutator/build/src/libfuzzer -L$(PROTOBUF_PATH)/lib $(LDFLAGS)
ZLIB?=$(OUTPUT)zlib-ng/build-libfuzzer
ZLIB_AFL?=$(OUTPUT)zlib-ng/build-afl
ZLIB_SYMCC?=$(OUTPUT)zlib-ng/build-symcc
LIBZ_A:=$(ZLIB)/libz.a
LIBZ_A_AFL:=$(ZLIB_AFL)/libz.a
LIBZ_A_SYMCC:=$(ZLIB_SYMCC)/libz.a
override ZLIB_NG_CMFLAGS:=-DCMAKE_BUILD_TYPE=RelWithDebInfo -DZLIB_COMPAT=ON $(ZLIB_NG_CMFLAGS)
SYMCC=$(ABS_OUTPUT)symcc/build/symcc

.PHONY: all
all: $(OUTPUT)fuzz $(OUTPUT)fuzz_libprotobuf_mutator $(OUTPUT)fuzz_afl $(OUTPUT)fuzz_symcc

$(OUTPUT)fuzz: $(OUTPUT)fuzz_target.o $(LIBZ_A)
	$(CXX) $(LDFLAGS) -fsanitize=address,fuzzer $(OUTPUT)fuzz_target.o -o $@ $(LIBZ_A)

$(OUTPUT)fuzz_libprotobuf_mutator: $(OUTPUT)fuzz_target_libprotobuf_mutator.o $(OUTPUT)fuzz_target.pb.o $(LIBZ_A)
	$(CXX) $(LDFLAGS) -fsanitize=address,fuzzer $(OUTPUT)fuzz_target_libprotobuf_mutator.o $(OUTPUT)fuzz_target.pb.o -o $@ $(LIBZ_A) -lprotobuf-mutator-libfuzzer -lprotobuf-mutator -lprotobuf

.PHONY: afl
afl: $(OUTPUT)fuzz_afl $(AFL_FUZZ)
	$(AFL_FUZZ) -i in -o out $(OUTPUT)fuzz_afl

FUZZ_AFL_OBJS=$(OUTPUT)fuzz_target_afl.o $(OUTPUT)afl_driver.o $(LIBZ_A_AFL)

$(OUTPUT)fuzz_afl: $(FUZZ_AFL_OBJS) $(AFLCXX)
	AFL_USE_ASAN=1 $(AFLCXX) $(LDFLAGS) -o $@ $(FUZZ_AFL_OBJS)

$(LIBZ_A): $(foreach file,$(shell git -C $(ZLIB) ls-files),$(ZLIB)/$(file))
	cd $(ZLIB) && $(MAKE) libz.a

$(LIBZ_A_AFL): $(foreach file,$(shell git -C $(ZLIB_AFL) ls-files),$(ZLIB_AFL)/$(file))
	cd $(ZLIB_AFL) && $(MAKE) libz.a

$(LIBZ_A_SYMCC): $(foreach file,$(shell git -C $(ZLIB_SYMCC) ls-files),$(ZLIB_SYMCC)/$(file))
	cd $(ZLIB_SYMCC) && $(MAKE) libz.a

$(OUTPUT)fuzz_target.o: fuzz_target.cpp $(OUTPUT)fuzz_target.pb.h | fmt
	$(CC) $(CFLAGS) -x c -fsanitize=address,fuzzer -DZLIB_CONST -I$(OUTPUT) -c fuzz_target.cpp -o $@

$(OUTPUT)fuzz_target_libprotobuf_mutator.o: fuzz_target.cpp $(OUTPUT)fuzz_target.pb.h | fmt
	$(CXX) $(CXXFLAGS) -fsanitize=address,fuzzer -DUSE_LIBPROTOBUF_MUTATOR -DZLIB_CONST -I$(OUTPUT) -c fuzz_target.cpp -o $@

$(OUTPUT)fuzz_target_afl.o: fuzz_target.cpp $(AFLCC) | fmt
	AFL_USE_ASAN=1 $(AFLCC) $(CFLAGS) -x c -DZLIB_CONST -I$(OUTPUT) -c fuzz_target.cpp -o $@

$(OUTPUT)fuzz_target_symcc.o: fuzz_target.cpp $(SYMCC) | fmt
	$(SYMCC) $(CFLAGS) -x c -DZLIB_CONST -I$(OUTPUT) -c fuzz_target.cpp -o $@

$(OUTPUT)symcc_driver.o: symcc_driver.c $(SYMCC) | fmt
	$(SYMCC) $(CFLAGS) -c $^ -o $@

FUZZ_SYMCC_OBJS=$(OUTPUT)fuzz_target_symcc.o $(OUTPUT)symcc_driver.o $(LIBZ_A_SYMCC)

$(OUTPUT)fuzz_symcc: $(FUZZ_SYMCC_OBJS) $(SYMCC)
	$(SYMCC) $(LDFLAGS) -o $@ $(FUZZ_SYMCC_OBJS)

$(OUTPUT)fuzz_target.pb.o: $(OUTPUT)fuzz_target.pb.cc $(OUTPUT)fuzz_target.pb.h
	$(CXX) $(CXXFLAGS) -c $(OUTPUT)fuzz_target.pb.cc -o $@

$(OUTPUT)fuzz_target.pb.cc $(OUTPUT)fuzz_target.pb.h: fuzz_target.proto $(PROTOC)
	$(PROTOC) --cpp_out=$(OUTPUT) fuzz_target.proto

$(OUTPUT)afl_driver.o: afl_driver.cpp
	$(CXX) $(CXXFLAGS) -c $^ -o $@

$(OUTPUT)libprotobuf-mutator/build/Makefile: libprotobuf-mutator/CMakeLists.txt
	mkdir -p $(OUTPUT)libprotobuf-mutator/build && \
		cmake \
			-S libprotobuf-mutator \
			-B $(OUTPUT)libprotobuf-mutator/build \
			-DCMAKE_C_COMPILER=$(CC) \
			-DCMAKE_CXX_COMPILER=$(CXX) \
			-DCMAKE_BUILD_TYPE=RelWithDebInfo \
			-DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON

$(PROTOC): $(OUTPUT)libprotobuf-mutator/build/Makefile
	cd $(OUTPUT)libprotobuf-mutator/build && $(MAKE)

$(OUTPUT)zlib-ng/build-libfuzzer/Makefile: zlib-ng/CMakeLists.txt
	mkdir -p $(OUTPUT)zlib-ng/build-libfuzzer && \
		cmake \
			-S zlib-ng \
			-B $(OUTPUT)zlib-ng/build-libfuzzer \
			-DCMAKE_C_COMPILER=$(CC) \
			-DCMAKE_C_FLAGS=-fsanitize=address,fuzzer-no-link \
			$(ZLIB_NG_CMFLAGS)

$(OUTPUT)zlib-ng/build-libfuzzer/libz.a: \
		$(OUTPUT)zlib-ng/build-libfuzzer/Makefile \
		$(foreach file,$(shell git -C zlib-ng ls-files),zlib-ng/$(file))
	cd $(OUTPUT)zlib-ng/build-libfuzzer && $(MAKE)

$(AFLCC) $(AFLCXX) $(AFL_FUZZ): \
		$(foreach file,$(shell git -C AFLplusplus ls-files),AFLplusplus/$(file))
	rsync --archive AFLplusplus $(OUTPUT)
	cd $(OUTPUT)AFLplusplus && $(MAKE)

$(OUTPUT)zlib-ng/build-afl/Makefile: \
		zlib-ng/CMakeLists.txt \
		$(AFLCC)
	mkdir -p $(OUTPUT)zlib-ng/build-afl && \
		AFL_USE_ASAN=1 cmake \
			-S zlib-ng \
			-B $(OUTPUT)zlib-ng/build-afl \
			-DCMAKE_C_COMPILER=$(AFLCC) \
			$(ZLIB_NG_CMFLAGS)

$(OUTPUT)zlib-ng/build-afl/libz.a: \
		$(OUTPUT)zlib-ng/build-afl/Makefile \
		$(foreach file,$(shell git -C zlib-ng ls-files),zlib-ng/$(file))
	cd $(OUTPUT)zlib-ng/build-afl && AFL_USE_ASAN=1 $(MAKE)

$(OUTPUT)symcc/build/Makefile: symcc/CMakeLists.txt
	mkdir -p $(OUTPUT)symcc/build && \
		cmake -S symcc \
		-B $(OUTPUT)symcc/build \
		-DQSYM_BACKEND=ON \
		-DZ3_TRUST_SYSTEM_VERSION=ON \
		$(SYMCC_CMFLAGS)

$(SYMCC): \
		$(OUTPUT)symcc/build/Makefile \
		$(foreach file,$(shell git -C symcc ls-files),symcc/$(file))
	cd $(OUTPUT)symcc/build && $(MAKE)

$(OUTPUT)zlib-ng/build-symcc/Makefile: \
		zlib-ng/CMakeLists.txt \
		$(SYMCC)
	mkdir -p $(OUTPUT)zlib-ng/build-symcc && \
		cmake \
			-S zlib-ng \
			-B $(OUTPUT)zlib-ng/build-symcc \
			-DCMAKE_C_COMPILER=$(SYMCC) \
			-DWITH_SSE2=OFF \
			-DWITH_CRC32_VX=OFF \
			$(ZLIB_NG_CMFLAGS)

$(OUTPUT)zlib-ng/build-symcc/libz.a: \
		$(OUTPUT)zlib-ng/build-symcc/Makefile \
		$(foreach file,$(shell git -C zlib-ng ls-files),zlib-ng/$(file))
	cd $(OUTPUT)zlib-ng/build-symcc && $(MAKE)

$(OUTPUT)symcc/build/bin/symcc_fuzzing_helper: \
		$(foreach file,$(shell git -C symcc/util/symcc_fuzzing_helper ls-files),symcc/util/symcc_fuzzing_helper/$(file))
	cargo install --root $(OUTPUT)symcc/build --path symcc/util/symcc_fuzzing_helper

.PHONY: fmt
fmt:
	clang-format -i -style=llvm fuzz_target.cpp symcc_driver.c
