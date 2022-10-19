# zlib-fuzz

libFuzzer fuzz target for zlib(-ng), which focuses not on a single function
call, but rather on sequences thereof. It can work both stand-alone and with
libprotobuf-mutator.

# Example: fuzzing zlib-ng with libFuzzer

```
$ git submodule update --init --recursive
$ make O=build fuzz -j"$(nproc)"
```

# Example: fuzzing zlib with libFuzzer

```
$ git submodule update --init --recursive
$ make O=build ZLIB=build/zlib/build-libfuzzer fuzz -j"$(nproc)"
```

# Example: fuzzing zlib-ng with libprotobuf-mutator

```
$ git submodule update --init --recursive
$ make O=build build/fuzz_libprotobuf_mutator -j"$(nproc)"
$ build/fuzz_libprotobuf_mutator
```

# Example: fuzzing zlib-ng with AFL

```
$ git submodule update --init --recursive
$ AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 \
  PATH=/usr/lib/llvm-13/bin:$PATH \
  make O=build afl -j"$(nproc)"
```

# Example: fuzzing zlib-ng with SymCC

```
$ git submodule update --init --recursive
$ AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 \
  PATH=/usr/lib/llvm-11/bin:$PATH \
  make O=build symcc -j"$(nproc)"
```
