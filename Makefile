CXX=clang++
CXXFLAGS=-std=c++17 -fPIC -Wall -Wextra -Werror -O2 -g
LIBZ_A:=$(ZLIB)/libz.a
LIBZ_SOURCES:=$(foreach file,$(shell git -C $(ZLIB) ls-files),$(ZLIB)/$(file))

a.out: fuzz_target.o fuzz_target.pb.o $(LIBZ_A)
	$(CXX) -fsanitize=address,fuzzer fuzz_target.o fuzz_target.pb.o $(LIBZ_A) -lprotobuf

$(LIBZ_A): $(LIBZ_SOURCES)
	cd $(ZLIB) && $(MAKE) libz.a

fuzz_target.o: fuzz_target.cpp fuzz_target.pb.h
	$(CXX) $(CXXFLAGS) -fsanitize=address,fuzzer -DZLIB_CONST -c fuzz_target.cpp

fuzz_target.pb.o: fuzz_target.pb.cc fuzz_target.pb.h
	$(CXX) $(CXXFLAGS) -c fuzz_target.pb.cc

fuzz_target.pb.cc fuzz_target.pb.h: fuzz_target.proto
	protoc --cpp_out=. fuzz_target.proto

.PHONY: fmt
fmt:
	clang-format -i -style=llvm fuzz_target.cpp
