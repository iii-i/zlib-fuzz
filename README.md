# zlib-fuzz

libFuzzer fuzz target for zlib(-ng), which focuses not on a single function
call, but rather on sequences thereof. It can work both stand-alone and with
libprotobuf-mutator. Requires C++17.

# Example: fuzzing zlib-ng with libFuzzer

```
$ git submodule update --init --recursive
$ make O=build ZLIB=build/zlib-ng/build-libfuzzer build/fuzz -j"$(nproc)"
$ build/fuzz
```
# Example: fuzzing zlib-ng with AFL

```
$ git submodule update --init --recursive
$ make O=build ZLIB_AFL=build/zlib-ng/build-afl afl -j"$(nproc)"
```
