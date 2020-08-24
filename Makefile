CXX=clang++
AFLCC=$(AFL)/afl-clang-fast
AFLCXX=$(AFL)/afl-clang-fast++
override CXXFLAGS:=-std=c++17 -fPIC -Wall -Wextra -Werror -O2 -g $(CXXFLAGS)
LIBZ_A:=$(ZLIB)/libz.a
LIBZ_A_AFL:=$(ZLIB)/libz_afl.a
LIBZ_SOURCES:=$(foreach file,$(shell git -C $(ZLIB) ls-files),$(ZLIB)/$(file))
LIBPROTOBUF=protobuf

all: fuzz fuzz_libprotobuf_mutator

fuzz: fuzz_target.o fuzz_target.pb.o $(LIBZ_A)
	$(CXX) $(LDFLAGS) -fsanitize=fuzzer fuzz_target.o fuzz_target.pb.o -o $@ $(LIBZ_A) -l$(LIBPROTOBUF)

fuzz_libprotobuf_mutator: fuzz_target_libprotobuf_mutator.o fuzz_target.pb.o $(LIBZ_A)
	$(CXX) $(LDFLAGS) -fsanitize=fuzzer fuzz_target_libprotobuf_mutator.o fuzz_target.pb.o -o $@ $(LIBZ_A) -lprotobuf-mutator-libfuzzer -lprotobuf-mutator -l$(LIBPROTOBUF)

# For building for afl, run
# make ZLIB=path/to/zlib AFL=path/to/AFLplusplus afl
.PHONY: afl
afl: a.out_afl
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
	$(AFLCXX) $(LDFLAGS) -o $@ $^ -l$(LIBPROTOBUF)

$(LIBZ_A): $(LIBZ_SOURCES)
	cd $(ZLIB) && $(MAKE) libz.a

$(LIBZ_A_AFL): $(LIBZ_SOURCES)
	cd $(ZLIB) && $(MAKE) libz.a CC=$(AFLCC)
	cd $(ZLIB) && mv libz.a $@

fuzz_target.o: fuzz_target.cpp fuzz_target.pb.h | fmt
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -DZLIB_CONST -c fuzz_target.cpp -o $@

fuzz_target_libprotobuf_mutator.o: fuzz_target.cpp fuzz_target.pb.h | fmt
	$(CXX) $(CXXFLAGS) -fsanitize=fuzzer -DUSE_LIBPROTOBUF_MUTATOR -DZLIB_CONST -c fuzz_target.cpp -o $@

fuzz_target_afl.o: fuzz_target.cpp fuzz_target.pb.h
	$(AFLCXX) $(CXXFLAGS) -DZLIB_CONST -c fuzz_target.cpp -o $@

fuzz_target.pb.o: fuzz_target.pb.cc fuzz_target.pb.h
	$(CXX) $(CXXFLAGS) -c fuzz_target.pb.cc

fuzz_target.pb_afl.o: fuzz_target.pb.cc fuzz_target.pb.h
	$(AFLCXX) $(CXXFLAGS) -c fuzz_target.pb.cc -o $@

fuzz_target.pb.cc fuzz_target.pb.h: fuzz_target.proto
	protoc --cpp_out=. fuzz_target.proto

.PHONY: fmt
fmt:
	clang-format -i -style=llvm fuzz_target.cpp
