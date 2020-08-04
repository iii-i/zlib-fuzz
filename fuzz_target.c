#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zlib.h"

enum OpKind {
  OpDeflate,
  OpDeflateParams,
};

struct Op {
  enum OpKind Kind;
  uInt AvailIn;
  uInt AvailOut;
  union {
    struct {
      int Flush;
    } Deflate;
    struct {
      int Level;
      int Strategy;
    } DeflateParams;
  };
};

static void RunOp(z_stream *Strm, struct Op *Op, size_t i, size_t OpCount) {
  uInt AvailIn0 = Strm->avail_in;
  uInt AvailIn1 = AvailIn0 < Op->AvailIn ? AvailIn0 : Op->AvailIn;
  if (AvailIn1 == 0)
    return;
  uInt AvailOut0 = Strm->avail_out;
  uInt AvailOut1 = AvailOut0 < Op->AvailOut ? AvailOut0 : Op->AvailOut;
  if (AvailOut1 == 0)
    return;
  Strm->avail_in = AvailIn1;
  Strm->avail_out = AvailOut1;
  switch (Op->Kind) {
  case OpDeflate: {
    int Err = deflate(Strm, Op->Deflate.Flush);
    if (Err != Z_OK) {
      fprintf(stderr, "deflate(%i) returned %i\n", Op->Deflate.Flush, Err);
      assert(0);
    }
    break;
  }
  case OpDeflateParams: {
    int Err = deflateParams(Strm, Op->DeflateParams.Level,
                            Op->DeflateParams.Strategy);
    if (Err != Z_OK && Err != Z_BUF_ERROR) {
      fprintf(stderr, "deflateParams(%i, %i) returned %i\n",
              Op->DeflateParams.Level, Op->DeflateParams.Strategy, Err);
      assert(0);
    }
    break;
  }
  default:
    fprintf(stderr, "Unexpected Ops[%zu/%zu].Kind: %i\n", i, OpCount, Op->Kind);
    assert(0);
  }
  uInt ConsumedIn = AvailIn1 - Strm->avail_in;
  Strm->avail_in = AvailIn0 - ConsumedIn;
  uInt ConsumedOut = AvailOut1 - Strm->avail_out;
  Strm->avail_out = AvailOut0 - ConsumedOut;
}

static int ChooseLevel(uint8_t Choice) {
  if (Choice < 128)
    return (Choice % 11) - 1;
  else
    return Z_BEST_SPEED;
}

#define WB_RAW -15
#define WB_ZLIB 15
#define WB_GZIP 31

static int ChooseWindowBits(uint8_t Choice) {
  if (Choice < 85)
    return WB_RAW;
  else if (Choice < 170)
    return WB_ZLIB;
  else
    return WB_GZIP;
}

static int ChooseStrategy(uint8_t Choice) {
  if (Choice < 43)
    return Z_FILTERED;
  else if (Choice < 86)
    return Z_HUFFMAN_ONLY;
  else if (Choice < 128)
    return Z_RLE;
  else if (Choice < 196)
    return Z_FIXED;
  else
    return Z_DEFAULT_STRATEGY;
}

static int ChooseDeflateFlush(uint8_t Choice) {
  if (Choice < 32)
    return Z_PARTIAL_FLUSH;
  else if (Choice < 64)
    return Z_SYNC_FLUSH;
  else if (Choice < 96)
    return Z_FULL_FLUSH;
  else if (Choice < 128)
    return Z_BLOCK;
  else
    return Z_NO_FLUSH;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
#define POP(X)                                                                 \
  if (Size == 0)                                                               \
    return 0;                                                                  \
  (X) = *Data;                                                                 \
  Data++;                                                                      \
  Size--;

  uint8_t InitialLevelChoice;
  POP(InitialLevelChoice);
  int InitialLevel = ChooseLevel(InitialLevelChoice);
  uint8_t WindowBitsChoice;
  POP(WindowBitsChoice);
  int WindowBits = ChooseWindowBits(WindowBitsChoice);
  uint8_t MemLevelChoice;
  POP(MemLevelChoice);
  int MemLevel = (MemLevelChoice % 9) + 1;
  uint8_t InitialStrategyChoice;
  POP(InitialStrategyChoice);
  int InitialStrategy = ChooseStrategy(InitialStrategyChoice);

  const uint8_t *Dict = NULL;
  size_t DictLen;
  if (WindowBits != WB_GZIP) {
    POP(DictLen);
    if (DictLen > 0 && DictLen < 128) {
      size_t MaxDictLen = Size / 4;
      if (DictLen > MaxDictLen)
        DictLen = MaxDictLen;
      Dict = Data;
      Data += DictLen;
      Size -= DictLen;
    }
  }

  size_t OpCount;
  POP(OpCount);
  OpCount++;
  size_t MaxOpCount = Size / 2;
  if (OpCount > MaxOpCount)
    OpCount = MaxOpCount;
  struct Op Ops[OpCount];
  uInt AvailInDivisor = 0;
  uInt AvailOutDivisor = 0;
  for (size_t i = 0; i < OpCount; i++) {
    POP(Ops[i].AvailIn);
    Ops[i].AvailIn++;
    AvailInDivisor += Ops[i].AvailIn;
    POP(Ops[i].AvailOut);
    Ops[i].AvailOut++;
    AvailOutDivisor += Ops[i].AvailOut;
    uint8_t KindChoice;
    POP(KindChoice);
    if (KindChoice < 32) {
      Ops[i].Kind = OpDeflateParams;
      uint8_t LevelChoice;
      POP(LevelChoice);
      Ops[i].DeflateParams.Level = ChooseLevel(LevelChoice);
      uint8_t StrategyChoice;
      POP(StrategyChoice);
      Ops[i].DeflateParams.Strategy = ChooseStrategy(StrategyChoice);
    } else {
      Ops[i].Kind = OpDeflate;
      uint8_t FlushChoice;
      POP(FlushChoice);
      Ops[i].Deflate.Flush = ChooseDeflateFlush(FlushChoice);
    }
  }
#undef POP
  if (AvailInDivisor == 0 || AvailOutDivisor == 0)
    return 0;
  size_t CompressedSize = Size * 2 + OpCount * 128;
  for (size_t i = 0; i < OpCount; i++) {
    Ops[i].AvailIn = (Ops[i].AvailIn * Size) / AvailInDivisor;
    Ops[i].AvailOut = (Ops[i].AvailOut * CompressedSize) / AvailOutDivisor;
  }

  uint8_t *Compressed = malloc(CompressedSize);
  assert(Compressed);
  z_stream Strm;
  memset(&Strm, 0, sizeof(Strm));
  int Err = deflateInit2(&Strm, InitialLevel, Z_DEFLATED, WindowBits, MemLevel,
                         InitialStrategy);
  assert(Err == Z_OK);
  if (Dict) {
    Err = deflateSetDictionary(&Strm, Dict, DictLen);
    assert(Err == Z_OK);
  }
  Strm.next_in = Data;
  Strm.avail_in = Size;
  Strm.next_out = Compressed;
  Strm.avail_out = CompressedSize;
  for (size_t i = 0; i < OpCount; i++)
    RunOp(&Strm, &Ops[i], i, OpCount);
  Err = deflate(&Strm, Z_FINISH);
  assert(Err == Z_STREAM_END);
  assert(Strm.avail_in == 0);
  int ActualCompressedSize = CompressedSize - Strm.avail_out;
  Err = deflateEnd(&Strm);
  assert(Err == Z_OK);

  uint8_t *Uncompressed = malloc(Size);
  assert(Uncompressed);
  Err = inflateInit2(&Strm, WindowBits);
  assert(Err == Z_OK);
  if (Dict && WindowBits == WB_RAW) {
    Err = inflateSetDictionary(&Strm, Dict, DictLen);
    assert(Err == Z_OK);
  }
  Strm.next_in = Compressed;
  Strm.avail_in = ActualCompressedSize;
  Strm.next_out = Uncompressed;
  Strm.avail_out = Size;
  Err = inflate(&Strm, Z_NO_FLUSH);
  if (Dict && WindowBits == WB_ZLIB) {
    assert(Err == Z_NEED_DICT);
    Err = inflateSetDictionary(&Strm, Dict, DictLen);
    assert(Err == Z_OK);
    Err = inflate(&Strm, Z_NO_FLUSH);
  }
  assert(Err == Z_STREAM_END);
  assert(Strm.avail_in == 0);
  assert(Strm.avail_out == 0);
  assert(memcmp(Uncompressed, Data, Size) == 0);
  Err = inflateEnd(&Strm);
  assert(Err == Z_OK);
  free(Uncompressed);
  free(Compressed);
  return 0;
}
