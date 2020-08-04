LIBZ_A:=$(ZLIB)/libz.a

a.out: fuzz_target.c $(LIBZ_A)
	clang -fsanitize=address,fuzzer -DZLIB_CONST -fPIC -Wall -Wextra -Werror -O2 -g $< -o $@ $(LIBZ_A)

.PHONY: fmt
fmt:
	clang-format -i -style=llvm fuzz_target.c
