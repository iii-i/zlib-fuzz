#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zlib.h"

static int Debug;

__attribute__((constructor)) static void Init() {
  const char *Env = getenv("DEBUG");
  if (Env && !strcmp(Env, "1"))
    Debug = 1;
}

static void HexDump(FILE *stream, const void *Data, size_t Size) {
  for (size_t i = 0; i < Size; i++)
    fprintf(stream, "\\x%02x", ((const uint8_t *)Data)[i]);
}

enum OpKind {
  OpDeflate,
  OpDeflateParams,
  OpInflate,
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
    struct {
      int Flush;
    } Inflate;
  };
};

static int DeflateSetDictionary(z_stream *Strm, const void *Dict,
                                size_t DictLen) {
  if (Debug) {
    fprintf(stderr, "deflateSetDictionary(&Strm, \"");
    HexDump(stderr, Dict, DictLen);
    fprintf(stderr, "\", %zu) = ", DictLen);
  }
  int Err = deflateSetDictionary(Strm, Dict, DictLen);
  if (Debug)
    fprintf(stderr, "%i;\n", Err);
  return Err;
}

static int Deflate(z_stream *Strm, int Flush) {
  if (Debug)
    fprintf(stderr, "avail_in = %u; avail_out = %u; deflate(&Strm, %i) = ",
            Strm->avail_in, Strm->avail_out, Flush);
  int Err = deflate(Strm, Flush);
  if (Debug)
    fprintf(stderr, "%i;\n", Err);
  return Err;
}

static int InflateSetDictionary(z_stream *Strm, const void *Dict,
                                size_t DictLen) {
  if (Debug) {
    fprintf(stderr, "inflateSetDictionary(&Strm, \"");
    HexDump(stderr, Dict, DictLen);
    fprintf(stderr, "\", %zu) = ", DictLen);
  }
  int Err = inflateSetDictionary(Strm, Dict, DictLen);
  if (Debug)
    fprintf(stderr, "%i;\n", Err);
  return Err;
}

static int Inflate(z_stream *Strm, int Flush) {
  if (Debug)
    fprintf(stderr, "avail_in = %u; avail_out = %u; inflate(&Strm, %i) = ",
            Strm->avail_in, Strm->avail_out, Flush);
  int Err = inflate(Strm, Flush);
  if (Debug)
    fprintf(stderr, "%i;\n", Err);
  return Err;
}

static int RunOp(z_stream *Strm, struct Op *Op, size_t i, size_t OpCount) {
  uInt AvailIn0 = Strm->avail_in;
  uInt AvailIn1 = AvailIn0 < Op->AvailIn ? AvailIn0 : Op->AvailIn;
  uInt AvailOut0 = Strm->avail_out;
  uInt AvailOut1 = AvailOut0 < Op->AvailOut ? AvailOut0 : Op->AvailOut;
  Strm->avail_in = AvailIn1;
  Strm->avail_out = AvailOut1;
  int Err;
  switch (Op->Kind) {
  case OpDeflate:
    Err = Deflate(Strm, Op->Deflate.Flush);
    assert(Err == Z_OK || Err == Z_BUF_ERROR);
    break;
  case OpDeflateParams:
    if (Debug)
      fprintf(stderr,
              "avail_in = %u; avail_out = %u; deflateParams(&Strm, %i, %i) = ",
              Strm->avail_in, Strm->avail_out, Op->DeflateParams.Level,
              Op->DeflateParams.Strategy);
    Err = deflateParams(Strm, Op->DeflateParams.Level,
                        Op->DeflateParams.Strategy);
    if (Debug)
      fprintf(stderr, "%i;\n", Err);
    assert(Err == Z_OK || Err == Z_BUF_ERROR);
    break;
  case OpInflate:
    Err = Inflate(Strm, Op->Inflate.Flush);
    assert(Err == Z_OK || Err == Z_STREAM_END || Err == Z_NEED_DICT ||
           Err == Z_BUF_ERROR);
    break;
  default:
    fprintf(stderr, "Unexpected Ops[%zu/%zu].Kind: %i\n", i, OpCount, Op->Kind);
    assert(0);
  }
  uInt ConsumedIn = AvailIn1 - Strm->avail_in;
  Strm->avail_in = AvailIn0 - ConsumedIn;
  uInt ConsumedOut = AvailOut1 - Strm->avail_out;
  Strm->avail_out = AvailOut0 - ConsumedOut;
  return Err;
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

  size_t DeflateOpCount;
  POP(DeflateOpCount);
  DeflateOpCount++;
  size_t MaxDeflateOpCount = Size / 2;
  if (DeflateOpCount > MaxDeflateOpCount)
    DeflateOpCount = MaxDeflateOpCount;
  struct Op DeflateOps[DeflateOpCount];
  uInt DeflateAvailInDivisor = 0;
  uInt DeflateAvailOutDivisor = 0;
  if (Debug)
    fprintf(stderr, "n_deflate_ops = %zu;\n", DeflateOpCount);
  for (size_t i = 0; i < DeflateOpCount; i++) {
    uint8_t KindChoice;
    POP(KindChoice);
    if (KindChoice < 32) {
      DeflateOps[i].Kind = OpDeflateParams;
      uint8_t LevelChoice;
      POP(LevelChoice);
      DeflateOps[i].DeflateParams.Level = ChooseLevel(LevelChoice);
      uint8_t StrategyChoice;
      POP(StrategyChoice);
      DeflateOps[i].DeflateParams.Strategy = ChooseStrategy(StrategyChoice);
    } else {
      DeflateOps[i].Kind = OpDeflate;
      uint8_t FlushChoice;
      POP(FlushChoice);
      DeflateOps[i].Deflate.Flush = ChooseDeflateFlush(FlushChoice);
    }
    POP(DeflateOps[i].AvailIn);
    DeflateOps[i].AvailIn++;
    DeflateAvailInDivisor += DeflateOps[i].AvailIn;
    POP(DeflateOps[i].AvailOut);
    DeflateOps[i].AvailOut++;
    DeflateAvailOutDivisor += DeflateOps[i].AvailOut;
  }
  if (DeflateAvailInDivisor == 0 || DeflateAvailOutDivisor == 0)
    return 0;
  size_t CompressedSize = Size * 2 + DeflateOpCount * 128;
  for (size_t i = 0; i < DeflateOpCount; i++) {
    DeflateOps[i].AvailIn =
        (DeflateOps[i].AvailIn * Size) / DeflateAvailInDivisor;
    DeflateOps[i].AvailOut =
        (DeflateOps[i].AvailOut * CompressedSize) / DeflateAvailOutDivisor;
  }

  size_t InflateOpCount;
  POP(InflateOpCount);
  InflateOpCount++;
  size_t MaxInflateOpCount = CompressedSize / 2;
  if (InflateOpCount > MaxInflateOpCount)
    InflateOpCount = MaxInflateOpCount;
  struct Op InflateOps[InflateOpCount];
  uInt InflateAvailInDivisor = 0;
  uInt InflateAvailOutDivisor = 0;
  if (Debug)
    fprintf(stderr, "n_inflate_ops = %zu;\n", InflateOpCount);
  for (size_t i = 0; i < InflateOpCount; i++) {
    InflateOps[i].Kind = OpInflate;
    InflateOps[i].Inflate.Flush = Z_NO_FLUSH;
    POP(InflateOps[i].AvailIn);
    InflateOps[i].AvailIn++;
    InflateAvailInDivisor += InflateOps[i].AvailIn;
    POP(InflateOps[i].AvailOut);
    InflateOps[i].AvailOut++;
    InflateAvailOutDivisor += InflateOps[i].AvailOut;
  }
  if (InflateAvailInDivisor == 0 || InflateAvailOutDivisor == 0)
    return 0;
#undef POP

  uint8_t *Compressed = malloc(CompressedSize);
  assert(Compressed);
  z_stream Strm;
  memset(&Strm, 0, sizeof(Strm));
  int Err = deflateInit2(&Strm, InitialLevel, Z_DEFLATED, WindowBits, MemLevel,
                         InitialStrategy);
  if (Debug)
    fprintf(stderr, "deflateInit2(&Strm, %i, Z_DEFLATED, %i, %i, %i) = %i;\n",
            InitialLevel, WindowBits, MemLevel, InitialStrategy, Err);
  assert(Err == Z_OK);
  if (Dict) {
    Err = DeflateSetDictionary(&Strm, Dict, DictLen);
    assert(Err == Z_OK);
  }
  Strm.next_in = Data;
  Strm.avail_in = Size;
  Strm.next_out = Compressed;
  Strm.avail_out = CompressedSize;
  if (Debug) {
    fprintf(stderr, "char next_in[%zu] = \"", Size);
    HexDump(stderr, Data, Size);
    fprintf(stderr, "\";\nchar next_out[%zu];\n", CompressedSize);
  }
  for (size_t i = 0; i < DeflateOpCount; i++)
    RunOp(&Strm, &DeflateOps[i], i, DeflateOpCount);
  Err = Deflate(&Strm, Z_FINISH);
  assert(Err == Z_STREAM_END);
  assert(Strm.avail_in == 0);
  uInt ActualCompressedSize = CompressedSize - Strm.avail_out;
  assert(ActualCompressedSize == Strm.total_out);
  if (Debug)
    fprintf(stderr, "total_out = %i;\n", ActualCompressedSize);
  Err = deflateEnd(&Strm);
  assert(Err == Z_OK);

  for (size_t i = 0; i < InflateOpCount; i++) {
    InflateOps[i].AvailIn =
        (InflateOps[i].AvailIn * ActualCompressedSize) / InflateAvailInDivisor;
    InflateOps[i].AvailOut =
        (InflateOps[i].AvailOut * Size) / InflateAvailOutDivisor;
  }

  uint8_t *Uncompressed = malloc(Size);
  assert(Uncompressed);
  Err = inflateInit2(&Strm, WindowBits);
  if (Debug)
    fprintf(stderr, "inflateInit2(&Strm, %i) = %i;\n", WindowBits, Err);
  assert(Err == Z_OK);
  if (Dict && WindowBits == WB_RAW) {
    Err = InflateSetDictionary(&Strm, Dict, DictLen);
    assert(Err == Z_OK);
  }
  Strm.next_in = Compressed;
  Strm.avail_in = ActualCompressedSize;
  Strm.next_out = Uncompressed;
  Strm.avail_out = Size;
  for (size_t i = 0; i < InflateOpCount; i++) {
    Err = RunOp(&Strm, &InflateOps[i], i, InflateOpCount);
    if (Err == Z_STREAM_END)
      assert(i == InflateOpCount - 1);
    if (Err == Z_NEED_DICT) {
      assert(Dict && WindowBits == WB_ZLIB);
      Err = InflateSetDictionary(&Strm, Dict, DictLen);
      assert(Err == Z_OK);
    }
  }
  if (Err != Z_STREAM_END) {
    Err = Inflate(&Strm, Z_NO_FLUSH);
    if (Err == Z_NEED_DICT) {
      assert(Dict && WindowBits == WB_ZLIB);
      Err = InflateSetDictionary(&Strm, Dict, DictLen);
      assert(Err == Z_OK);
      Err = Inflate(&Strm, Z_NO_FLUSH);
    }
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
