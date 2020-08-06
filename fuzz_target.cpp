#include <assert.h>
#include <memory>
#include <optional>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#include "fuzz_target.pb.h"

static_assert(PB_Z_NO_FLUSH == Z_NO_FLUSH);
static_assert(PB_Z_PARTIAL_FLUSH == Z_PARTIAL_FLUSH);
static_assert(PB_Z_SYNC_FLUSH == Z_SYNC_FLUSH);
static_assert(PB_Z_FULL_FLUSH == Z_FULL_FLUSH);
static_assert(PB_Z_FINISH == Z_FINISH);
static_assert(PB_Z_BLOCK == Z_BLOCK);
static_assert(PB_Z_TREES == Z_TREES);
static_assert(PB_Z_NO_COMPRESSION == Z_NO_COMPRESSION);
static_assert(PB_Z_BEST_SPEED == Z_BEST_SPEED);
static_assert(PB_Z_BEST_COMPRESSION == Z_BEST_COMPRESSION);
static_assert(PB_Z_DEFAULT_COMPRESSION == Z_DEFAULT_COMPRESSION);
static_assert(PB_Z_DEFAULT_STRATEGY == Z_DEFAULT_STRATEGY);
static_assert(PB_Z_FILTERED == Z_FILTERED);
static_assert(PB_Z_HUFFMAN_ONLY == Z_HUFFMAN_ONLY);
static_assert(PB_Z_RLE == Z_RLE);
static_assert(PB_Z_FIXED == Z_FIXED);

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

static int DeflateSetDictionary(z_stream *Strm, const Bytef *Dict,
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

static int InflateSetDictionary(z_stream *Strm, const Bytef *Dict,
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

static int RunOp(z_stream *Strm, const Op &Op, size_t i, size_t OpCount) {
  uInt AvailIn0 = Strm->avail_in;
  uInt AvailIn1 =
      AvailIn0 < (uInt)Op.avail_in() ? AvailIn0 : (uInt)Op.avail_in();
  uInt AvailOut0 = Strm->avail_out;
  uInt AvailOut1 =
      AvailOut0 < (uInt)Op.avail_out() ? AvailOut0 : (uInt)Op.avail_out();
  Strm->avail_in = AvailIn1;
  Strm->avail_out = AvailOut1;
  int Err;
  if (Op.has_deflate()) {
    Err = Deflate(Strm, Op.deflate().flush());
    assert(Err == Z_OK || Err == Z_BUF_ERROR);
  } else if (Op.has_deflate_params()) {
    if (Debug)
      fprintf(stderr,
              "avail_in = %u; avail_out = %u; deflateParams(&Strm, %i, %i) = ",
              Strm->avail_in, Strm->avail_out, Op.deflate_params().level(),
              Op.deflate_params().strategy());
    Err = deflateParams(Strm, Op.deflate_params().level(),
                        Op.deflate_params().strategy());
    if (Debug)
      fprintf(stderr, "%i;\n", Err);
    assert(Err == Z_OK || Err == Z_BUF_ERROR);
  } else if (Op.has_inflate()) {
    Err = Inflate(Strm, Op.inflate().flush());
    assert(Err == Z_OK || Err == Z_STREAM_END || Err == Z_NEED_DICT ||
           Err == Z_BUF_ERROR);
  } else {
    fprintf(stderr, "Unexpected Ops[%zu/%zu].op_case() = %i\n", i, OpCount,
            Op.op_case());
    assert(0);
  }
  uInt ConsumedIn = AvailIn1 - Strm->avail_in;
  Strm->avail_in = AvailIn0 - ConsumedIn;
  uInt ConsumedOut = AvailOut1 - Strm->avail_out;
  Strm->avail_out = AvailOut0 - ConsumedOut;
  return Err;
}

static Level ChooseLevel(uint8_t Choice) {
  if (Choice < 128)
    return (Level)((Choice % 11) - 1);
  else
    return PB_Z_BEST_SPEED;
}

static WindowBits ChooseWindowBits(uint8_t Choice) {
  if (Choice < 85)
    return WB_RAW;
  else if (Choice < 170)
    return WB_ZLIB;
  else
    return WB_GZIP;
}

static MemLevel ChooseMemLevel(uint8_t Choice) {
  return (MemLevel)((Choice % 9) + 1);
}

static Strategy ChooseStrategy(uint8_t Choice) {
  if (Choice < 43)
    return PB_Z_FILTERED;
  else if (Choice < 86)
    return PB_Z_HUFFMAN_ONLY;
  else if (Choice < 128)
    return PB_Z_RLE;
  else if (Choice < 196)
    return PB_Z_FIXED;
  else
    return PB_Z_DEFAULT_STRATEGY;
}

static Flush ChooseDeflateFlush(uint8_t Choice) {
  if (Choice < 32)
    return PB_Z_PARTIAL_FLUSH;
  else if (Choice < 64)
    return PB_Z_SYNC_FLUSH;
  else if (Choice < 96)
    return PB_Z_FULL_FLUSH;
  else if (Choice < 128)
    return PB_Z_BLOCK;
  else
    return PB_Z_NO_FLUSH;
}

template <typename OpsT>
static bool NormalizeOps(OpsT &Ops, uInt TotalIn, uInt TotalOut) {
  uInt InDivisor = 0;
  uInt OutDivisor = 0;
  for (Op &Op : Ops) {
    InDivisor += Op.avail_in();
    OutDivisor += Op.avail_out();
  }
  if (InDivisor == 0 || OutDivisor == 0)
    return false;
  for (Op &Op : Ops) {
    Op.set_avail_in((Op.avail_in() * TotalIn) / InDivisor);
    Op.set_avail_out((Op.avail_out() * TotalOut) / OutDivisor);
  }
  return true;
}

static bool GeneratePlan(Plan &Plan, size_t &CompressedSize,
                         const uint8_t *&Dict, const uint8_t *&Data,
                         size_t &Size) {
#define POP(X)                                                                 \
  if (Size == 0)                                                               \
    return false;                                                              \
  (X) = *Data;                                                                 \
  Data++;                                                                      \
  Size--;

  uint8_t InitialLevelChoice;
  POP(InitialLevelChoice);
  Plan.set_level(ChooseLevel(InitialLevelChoice));
  uint8_t WindowBitsChoice;
  POP(WindowBitsChoice);
  Plan.set_window_bits(ChooseWindowBits(WindowBitsChoice));
  uint8_t MemLevelChoice;
  POP(MemLevelChoice);
  Plan.set_mem_level(ChooseMemLevel(MemLevelChoice));
  uint8_t InitialStrategyChoice;
  POP(InitialStrategyChoice);
  Plan.set_strategy(ChooseStrategy(InitialStrategyChoice));

  Dict = NULL;
  if (Plan.window_bits() != WB_GZIP) {
    size_t DictLen;
    POP(DictLen);
    if (DictLen > 0 && DictLen < 128) {
      size_t MaxDictLen = Size / 4;
      if (DictLen > MaxDictLen)
        DictLen = MaxDictLen;
      Dict = Data;
      Data += DictLen;
      Size -= DictLen;
      Plan.set_dict_len(DictLen);
    }
  }

  size_t DeflateOpCount;
  POP(DeflateOpCount);
  DeflateOpCount++;
  size_t MaxDeflateOpCount = Size / 2;
  if (DeflateOpCount > MaxDeflateOpCount)
    DeflateOpCount = MaxDeflateOpCount;
  if (Debug)
    fprintf(stderr, "n_deflate_ops = %zu;\n", DeflateOpCount);
  for (size_t i = 0; i < DeflateOpCount; i++) {
    Op *Op = Plan.add_deflate_ops();
    uint8_t KindChoice;
    POP(KindChoice);
    if (KindChoice < 32) {
      std::unique_ptr<class DeflateParams> DeflateParams =
          std::make_unique<class DeflateParams>();
      uint8_t LevelChoice;
      POP(LevelChoice);
      DeflateParams->set_level(ChooseLevel(LevelChoice));
      uint8_t StrategyChoice;
      POP(StrategyChoice);
      DeflateParams->set_strategy(ChooseStrategy(StrategyChoice));
      Op->set_allocated_deflate_params(DeflateParams.release());
    } else {
      std::unique_ptr<class Deflate> Deflate =
          std::make_unique<class Deflate>();
      uint8_t FlushChoice;
      POP(FlushChoice);
      Deflate->set_flush(ChooseDeflateFlush(FlushChoice));
      Op->set_allocated_deflate(Deflate.release());
    }
    uint8_t AvailIn;
    POP(AvailIn);
    AvailIn++;
    Op->set_avail_in(AvailIn);
    uint8_t AvailOut;
    POP(AvailOut);
    AvailOut++;
    Op->set_avail_out(AvailOut);
  }
  CompressedSize = Size * 2 + DeflateOpCount * 128;
  if (!NormalizeOps(*Plan.mutable_deflate_ops(), Size, CompressedSize))
    return false;

  size_t InflateOpCount;
  POP(InflateOpCount);
  InflateOpCount++;
  size_t MaxInflateOpCount = CompressedSize / 2;
  if (InflateOpCount > MaxInflateOpCount)
    InflateOpCount = MaxInflateOpCount;
  if (Debug)
    fprintf(stderr, "n_inflate_ops = %zu;\n", InflateOpCount);
  for (size_t i = 0; i < InflateOpCount; i++) {
    Op *Op = Plan.add_inflate_ops();
    std::unique_ptr<class Inflate> Inflate = std::make_unique<class Inflate>();
    Inflate->set_flush(PB_Z_NO_FLUSH);
    Op->set_allocated_inflate(Inflate.release());
    uint8_t AvailIn;
    POP(AvailIn);
    AvailIn++;
    Op->set_avail_in(AvailIn);
    uint8_t AvailOut;
    POP(AvailOut);
    AvailOut++;
    Op->set_avail_out(AvailOut);
  }

  size_t TailSize;
  POP(TailSize);
  Plan.set_tail_size(TailSize);
#undef POP

  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  Plan Plan;
  size_t CompressedSize;
  const uint8_t *Dict;
  if (!GeneratePlan(Plan, CompressedSize, Dict, Data, Size))
    return 0;

  std::unique_ptr<uint8_t[]> Compressed(new uint8_t[CompressedSize]);
  z_stream Strm;
  memset(&Strm, 0, sizeof(Strm));
  int Err = deflateInit2(&Strm, Plan.level(), Z_DEFLATED, Plan.window_bits(),
                         Plan.mem_level(), Plan.strategy());
  if (Debug)
    fprintf(stderr, "deflateInit2(&Strm, %i, Z_DEFLATED, %i, %i, %i) = %i;\n",
            Plan.level(), Plan.window_bits(), Plan.mem_level(), Plan.strategy(),
            Err);
  assert(Err == Z_OK);
  if (Dict) {
    Err = DeflateSetDictionary(&Strm, Dict, Plan.dict_len());
    assert(Err == Z_OK);
  }
  Strm.next_in = Data;
  Strm.avail_in = Size;
  Strm.next_out = Compressed.get();
  Strm.avail_out = CompressedSize;
  if (Debug) {
    fprintf(stderr, "char next_in[%zu] = \"", Size);
    HexDump(stderr, Data, Size);
    fprintf(stderr, "\";\nchar next_out[%zu];\n", CompressedSize);
  }
  for (int i = 0; i < Plan.deflate_ops_size(); i++)
    RunOp(&Strm, Plan.deflate_ops(i), i, Plan.deflate_ops_size());
  Err = Deflate(&Strm, Z_FINISH);
  assert(Err == Z_STREAM_END);
  assert(Strm.avail_in == 0);
  uInt ActualCompressedSize = CompressedSize - Strm.avail_out;
  assert(ActualCompressedSize == Strm.total_out);
  if (Debug)
    fprintf(stderr, "total_out = %i;\n", ActualCompressedSize);
  Err = deflateEnd(&Strm);
  assert(Err == Z_OK);

  if (!NormalizeOps(*Plan.mutable_inflate_ops(), ActualCompressedSize, Size))
    return 0;

  std::unique_ptr<uint8_t[]> Uncompressed(new uint8_t[Size]);
  Err = inflateInit2(&Strm, Plan.window_bits());
  if (Debug)
    fprintf(stderr, "inflateInit2(&Strm, %i) = %i;\n", Plan.window_bits(), Err);
  assert(Err == Z_OK);
  if (Dict && Plan.window_bits() == WB_RAW) {
    Err = InflateSetDictionary(&Strm, Dict, Plan.dict_len());
    assert(Err == Z_OK);
  }
  Strm.next_in = Compressed.get();
  Strm.avail_in = ActualCompressedSize;
  Strm.next_out = Uncompressed.get();
  Strm.avail_out = Size + Plan.tail_size();
  for (int i = 0; i < Plan.inflate_ops_size(); i++) {
    Err = RunOp(&Strm, Plan.inflate_ops(i), i, Plan.inflate_ops_size());
    if (Err == Z_NEED_DICT) {
      assert(Dict && Plan.window_bits() == WB_ZLIB);
      Err = InflateSetDictionary(&Strm, Dict, Plan.dict_len());
      assert(Err == Z_OK);
    }
  }
  if (Err != Z_STREAM_END) {
    Err = Inflate(&Strm, Z_NO_FLUSH);
    if (Err == Z_NEED_DICT) {
      assert(Dict && Plan.window_bits() == WB_ZLIB);
      Err = InflateSetDictionary(&Strm, Dict, Plan.dict_len());
      assert(Err == Z_OK);
      Err = Inflate(&Strm, Z_NO_FLUSH);
    }
  }
  assert(Err == Z_STREAM_END);
  assert(Strm.avail_in == 0);
  assert(Strm.avail_out == (uInt)Plan.tail_size());
  assert(memcmp(Uncompressed.get(), Data, Size) == 0);
  Err = inflateEnd(&Strm);
  assert(Err == Z_OK);
  return 0;
}
