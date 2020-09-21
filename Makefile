# Required environment variables:
# - ZLIB: path to a zlib build directory configured with libFuzzer
# - ZLIB_AFL: path to a (different) zlib build directory configured with AFL
# Required programs in $PATH:
# - afl-clang-fast++
# - clang++

CXX=clang++
AFLCXX=afl-clang-fast++
PROTOBUF_PATH=libprotobuf-mutator/build/external.protobuf
PROTOC=$(PROTOBUF_PATH)/bin/protoc
override CXXFLAGS:=-std=c++17 -fPIC -Wall -Wextra -Werror -O2 -g -isystem libprotobuf-mutator -isystem $(PROTOBUF_PATH)/include $(CXXFLAGS)
override LDFLAGS:=-Llibprotobuf-mutator/build/src -Llibprotobuf-mutator/build/src/libfuzzer -L$(PROTOBUF_PATH)/lib64 $(LDFLAGS)
LIBZ_A:=$(ZLIB)/libz.a
LIBZ_A_AFL:=$(ZLIB_AFL)/libz.a

all: fuzz fuzz_libprotobuf_mutator fuzz_afl

fuzz: fuzz_target.o fuzz_target.pb.o $(LIBZ_A)
	$(CXX) $(LDFLAGS) -fsanitize=fuzzer fuzz_target.o fuzz_target.pb.o -o $@ $(LIBZ_A) -lprotobufd

fuzz_libprotobuf_mutator: fuzz_target_libprotobuf_mutator.o fuzz_target.pb.o $(LIBZ_A)
	$(CXX) $(LDFLAGS) -fsanitize=fuzzer fuzz_target_libprotobuf_mutator.o fuzz_target.pb.o -o $@ $(LIBZ_A) -lprotobuf-mutator-libfuzzer -lprotobuf-mutator -lprotobufd

# For building for afl, run
# make ZLIB=path/to/zlib AFL=path/to/AFLplusplus afl
.PHONY: afl
afl: fuzz_afl
	@echo "Now kick off afl as follows:"
	@echo "$ afl-fuzz -m none -i in -o out ./$^"
	@echo
	@echo "where"
	@echo "  -m disables the memory limit (required for ASAN)"
	@echo "  -i in is the directory with the starting corpus"
	@echo "  -o out is afl's run state and output directory"
	@echo
	@echo "Note: to resume a previous session, specify '-i -' as input directory"

fuzz_afl: fuzz_target_afl.o fuzz_target.pb_afl.o afl_driver.o $(LIBZ_A_AFL)
	$(AFLCXX) $(LDFLAGS) -o $@ $^ -lprotobufd

$(LIBZ_A): $(foreach file,$(shell git -C $(ZLIB) ls-files),$(ZLIB)/$(file))
	cd $(ZLIB) && $(MAKE) libz.a

$(LIBZ_A_AFL): $(foreach file,$(shell git -C $(ZLIB_AFL) ls-files),$(ZLIB_AFL)/$(file))
	cd $(ZLIB_AFL) && $(MAKE) libz.a

fuzz_target.o: fuzz_target.cpp fuzz_target.pb.h | fmt
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -DZLIB_CONST -c fuzz_target.cpp -o $@

fuzz_target_libprotobuf_mutator.o: fuzz_target.cpp fuzz_target.pb.h | fmt
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -DUSE_LIBPROTOBUF_MUTATOR -DZLIB_CONST -c fuzz_target.cpp -o $@

fuzz_target_afl.o: fuzz_target.cpp fuzz_target.pb.h | fmt
	$(AFLCXX) $(CXXFLAGS) -DZLIB_CONST -c fuzz_target.cpp -o $@

fuzz_target.pb.o: fuzz_target.pb.cc fuzz_target.pb.h
	$(CXX) $(CXXFLAGS) -c fuzz_target.pb.cc

fuzz_target.pb_afl.o: fuzz_target.pb.cc fuzz_target.pb.h
	$(AFLCXX) $(CXXFLAGS) -c fuzz_target.pb.cc -o $@

fuzz_target.pb.cc fuzz_target.pb.h: fuzz_target.proto $(PROTOC)
	$(PROTOC) --cpp_out=. fuzz_target.proto

libprotobuf-mutator/CMakeLists.txt: libprotobuf-mutator.commit
	mkdir -p libprotobuf-mutator && \
		cd libprotobuf-mutator && \
		git init && \
		git fetch https://github.com/iii-i/libprotobuf-mutator.git refs/heads/issue-131 && \
		git checkout $(shell cat libprotobuf-mutator.commit)

libprotobuf-mutator/build/Makefile: libprotobuf-mutator/CMakeLists.txt
	mkdir -p libprotobuf-mutator/build && \
		cd libprotobuf-mutator/build && \
		cmake \
			.. \
			-DCMAKE_C_COMPILER=clang \
			-DCMAKE_CXX_COMPILER=clang++ \
			-DCMAKE_BUILD_TYPE=Debug \
			-DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON

$(PROTOC): libprotobuf-mutator/build/Makefile
	cd libprotobuf-mutator/build && $(MAKE)

.PHONY: fmt
fmt:
	clang-format -i -style=llvm fuzz_target.cpp
