#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

static uint8_t InputBuf[1 << 20];

int main(void) {
  ssize_t BytesRead = read(0, InputBuf, sizeof(InputBuf));
  if (BytesRead >= 0) {
    uint8_t *Copy = malloc(BytesRead);
    assert(Copy);
    memcpy(Copy, InputBuf, BytesRead);
    LLVMFuzzerTestOneInput(Copy, BytesRead);
    free(Copy);
  }
}
