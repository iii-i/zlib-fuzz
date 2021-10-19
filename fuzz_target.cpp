#include <assert.h>
#include <memory>
#include <optional>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_LIBPROTOBUF_MUTATOR
#include <src/libfuzzer/libfuzzer_macro.h>
#endif
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

static void HexDumpStr(FILE *stream, const void *Data, size_t Size) {
  const size_t ChunkSize = 16;
  for (size_t i = 0; i < Size; i += ChunkSize) {
    if (i == 0)
      fprintf(stream, "\"");
    else
      fprintf(stream, " \"");
    HexDump(stream, ((const uint8_t *)Data) + i,
            (Size - i) < ChunkSize ? (Size - i) : ChunkSize);
    fprintf(stream, "\"");
  }
}

static const char *StrategyStr(int Strategy) {
  switch (Strategy) {
  case Z_FILTERED:
    return "Z_FILTERED";
  case Z_HUFFMAN_ONLY:
    return "Z_HUFFMAN_ONLY";
  case Z_RLE:
    return "Z_RLE";
  case Z_FIXED:
    return "Z_FIXED";
  case Z_DEFAULT_STRATEGY:
    return "Z_DEFAULT_STRATEGY";
  default:
    return "<unknown>";
  }
}

static const char *FlushStr(int Flush) {
  switch (Flush) {
  case Z_NO_FLUSH:
    return "Z_NO_FLUSH";
  case Z_PARTIAL_FLUSH:
    return "Z_PARTIAL_FLUSH";
  case Z_SYNC_FLUSH:
    return "Z_SYNC_FLUSH";
  case Z_FULL_FLUSH:
    return "Z_FULL_FLUSH";
  case Z_FINISH:
    return "Z_FINISH";
  case Z_BLOCK:
    return "Z_BLOCK";
  case Z_TREES:
    return "Z_TREES";
  default:
    return "<unknown>";
  }
}

static const char *ErrStr(int Err) {
  switch (Err) {
  case Z_OK:
    return "Z_OK";
    break;
  case Z_STREAM_END:
    return "Z_STREAM_END";
    break;
  case Z_NEED_DICT:
    return "Z_NEED_DICT";
    break;
  case Z_ERRNO:
    return "Z_ERRNO";
    break;
  case Z_STREAM_ERROR:
    return "Z_STREAM_ERROR";
    break;
  case Z_DATA_ERROR:
    return "Z_DATA_ERROR";
    break;
  case Z_MEM_ERROR:
    return "Z_MEM_ERROR";
    break;
  case Z_BUF_ERROR:
    return "Z_BUF_ERROR";
    break;
  case Z_VERSION_ERROR:
    return "Z_VERSION_ERROR";
    break;
  default:
    return "<unknown>";
  }
}

static int DeflateSetDictionary(z_stream *Strm, const Bytef *Dict,
                                size_t DictLen) {
  if (Debug) {
    fprintf(stderr, "assert(deflateSetDictionary(&Strm, ");
    HexDumpStr(stderr, Dict, DictLen);
    fprintf(stderr, ", %zu) == ", DictLen);
  }
  int Err = deflateSetDictionary(Strm, Dict, DictLen);
  if (Debug)
    fprintf(stderr, "%s);\n", ErrStr(Err));
  return Err;
}

static int Deflate(z_stream *Strm, int Flush) {
  if (Debug)
    fprintf(stderr,
            "Strm.avail_in = %u; Strm.avail_out = %u; assert(deflate(&Strm, "
            "%s) == ",
            Strm->avail_in, Strm->avail_out, FlushStr(Flush));
  int Err = deflate(Strm, Flush);
  if (Debug)
    fprintf(stderr, "%s);\n", ErrStr(Err));
  return Err;
}

static int InflateSetDictionary(z_stream *Strm, const Bytef *Dict,
                                size_t DictLen) {
  if (Debug) {
    fprintf(stderr, "assert(inflateSetDictionary(&Strm, ");
    HexDumpStr(stderr, Dict, DictLen);
    fprintf(stderr, ", %zu) == ", DictLen);
  }
  int Err = inflateSetDictionary(Strm, Dict, DictLen);
  if (Debug)
    fprintf(stderr, "%s);\n", ErrStr(Err));
  return Err;
}

static int Inflate(z_stream *Strm, int Flush) {
  if (Debug)
    fprintf(stderr,
            "Strm.avail_in = %u; Strm.avail_out = %u; assert(inflate(&Strm, "
            "%s) == ",
            Strm->avail_in, Strm->avail_out, FlushStr(Flush));
  int Err = inflate(Strm, Flush);
  if (Debug)
    fprintf(stderr, "%s);\n", ErrStr(Err));
  return Err;
}

struct Avail {
  z_stream *const Strm;
  const uInt AvailIn0;
  const uInt AvailIn1;
  const uInt AvailOut0;
  const uInt AvailOut1;

  Avail(z_stream *Strm, uInt MaxAvailIn, uInt MaxAvailOut)
      : Strm(Strm), AvailIn0(Strm->avail_in),
        AvailIn1(AvailIn0 < MaxAvailIn ? AvailIn0 : MaxAvailIn),
        AvailOut0(Strm->avail_out),
        AvailOut1(AvailOut0 < MaxAvailOut ? AvailOut0 : MaxAvailOut) {
    Strm->avail_in = AvailIn1;
    Strm->avail_out = AvailOut1;
  }

  template <typename OpT>
  Avail(z_stream *Strm, const OpT &Op)
      : Avail(Strm, (uInt)Op.avail_in(), (uInt)Op.avail_out()) {}

  ~Avail() {
    uInt ConsumedIn = AvailIn1 - Strm->avail_in;
    Strm->avail_in = AvailIn0 - ConsumedIn;
    uInt ConsumedOut = AvailOut1 - Strm->avail_out;
    Strm->avail_out = AvailOut0 - ConsumedOut;
  }
};

struct OpRunner {
  z_stream *const Strm;
  const bool Check;

  OpRunner(z_stream *Strm, bool Check) : Strm(Strm), Check(Check) {}

  int operator()(const class Deflate &Op) const {
    Avail Avail(Strm, Op);
    int Err = Deflate(Strm, Op.flush());
    if (Check)
      assert(Err == Z_OK || Err == Z_BUF_ERROR);
    return Err;
  }

  int operator()(const class DeflateParams &Op) const {
    Avail Avail(Strm, Op);
    if (Debug)
      fprintf(stderr,
              "Strm.avail_in = %u; Strm.avail_out = %u; "
              "assert(deflateParams(&Strm, %i, %s) = ",
              Strm->avail_in, Strm->avail_out, Op.level(),
              StrategyStr(Op.strategy()));
    int Err = deflateParams(Strm, Op.level(), Op.strategy());
    if (Debug)
      fprintf(stderr, "%s);\n", ErrStr(Err));
    if (Check)
      assert(Err == Z_OK || Err == Z_BUF_ERROR);
    return Err;
  }

  int operator()(const class Inflate &Op) const {
    Avail Avail(Strm, Op);
    int Err = Inflate(Strm, Op.flush());
    if (Check)
      assert(Err == Z_OK || Err == Z_STREAM_END || Err == Z_NEED_DICT ||
             Err == Z_BUF_ERROR);
    return Err;
  }
};

template <typename V>
static int VisitOp(const DeflateOp &Op, const V &Visitor) {
  if (Op.has_deflate())
    return Visitor(Op.deflate());
  else if (Op.has_deflate_params())
    return Visitor(Op.deflate_params());
  else {
    fprintf(stderr, "Unexpected DeflateOp.op_case() = %i\n", Op.op_case());
    assert(0);
  }
}

template <typename V>
static int VisitMutableOp(DeflateOp &Op, const V &Visitor) {
  if (Op.has_deflate())
    return Visitor(Op.mutable_deflate());
  else if (Op.has_deflate_params())
    return Visitor(Op.mutable_deflate_params());
  else {
    fprintf(stderr, "Unexpected DeflateOp.op_case() = %i\n", Op.op_case());
    assert(0);
  }
}

template <typename V>
static int VisitOp(const InflateOp &Op, const V &Visitor) {
  if (Op.has_inflate())
    return Visitor(Op.inflate());
  else {
    fprintf(stderr, "Unexpected InflateOp.op_case() = %i\n", Op.op_case());
    assert(0);
  }
}

template <typename V>
static int VisitMutableOp(InflateOp &Op, const V &Visitor) {
  if (Op.has_inflate())
    return Visitor(Op.mutable_inflate());
  else {
    fprintf(stderr, "Unexpected InflateOp.op_case() = %i\n", Op.op_case());
    assert(0);
  }
}

template <typename OpsT>
static void NormalizeOps(OpsT *Ops, uInt TotalIn, uInt TotalOut) {
  uInt InDivisor = 0;
  uInt OutDivisor = 0;
  for (typename OpsT::value_type &Op : *Ops) {
    VisitOp(Op, [&InDivisor](auto &Op) {
      InDivisor += Op.avail_in();
      return 0;
    });
    VisitOp(Op, [&OutDivisor](auto &Op) {
      OutDivisor += Op.avail_out();
      return 0;
    });
  }
  if (InDivisor != 0)
    for (typename OpsT::value_type &Op : *Ops)
      VisitMutableOp(Op, [TotalIn, InDivisor](auto *Op) {
        Op->set_avail_in((Op->avail_in() * TotalIn) / InDivisor);
        return 0;
      });
  if (OutDivisor != 0)
    for (typename OpsT::value_type &Op : *Ops)
      VisitMutableOp(Op, [TotalOut, OutDivisor](auto *Op) {
        Op->set_avail_out((Op->avail_out() * TotalOut) / OutDivisor);
        return 0;
      });
}

#ifndef USE_LIBPROTOBUF_MUTATOR
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

static bool GeneratePlan(Plan &Plan, const uint8_t *&Data, size_t &Size) {
#define POP(X)                                                                 \
  if (Size < sizeof(X))                                                        \
    return false;                                                              \
  memcpy(&X, Data, sizeof(X));                                                 \
  Data += sizeof(X);                                                           \
  Size -= sizeof(X);

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

  if (Plan.window_bits() != WB_GZIP) {
    uint8_t DictLen;
    POP(DictLen);
    if (DictLen > 0 && DictLen < 128) {
      size_t MaxDictLen = Size / 4;
      if (DictLen > MaxDictLen)
        DictLen = MaxDictLen;
      Plan.set_dict(Data, DictLen);
      Data += DictLen;
      Size -= DictLen;
    }
  }

  uint8_t DeflateOpCount;
  POP(DeflateOpCount);
  size_t MaxDeflateOpCount = Size / 2;
  if (DeflateOpCount > MaxDeflateOpCount)
    DeflateOpCount = MaxDeflateOpCount;
  for (size_t i = 0; i < DeflateOpCount; i++) {
    DeflateOp *Op = Plan.add_deflate_ops();
    uint8_t AvailIn;
    POP(AvailIn);
    AvailIn++;
    uint8_t AvailOut;
    POP(AvailOut);
    AvailOut++;
    uint8_t KindChoice;
    POP(KindChoice);
    if (KindChoice < 32) {
      std::unique_ptr<class DeflateParams> DeflateParams =
          std::make_unique<class DeflateParams>();
      DeflateParams->set_avail_in(AvailIn);
      DeflateParams->set_avail_out(AvailOut);
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
      Deflate->set_avail_in(AvailIn);
      Deflate->set_avail_out(AvailOut);
      uint8_t FlushChoice;
      POP(FlushChoice);
      Deflate->set_flush(ChooseDeflateFlush(FlushChoice));
      Op->set_allocated_deflate(Deflate.release());
    }
  }

  uint8_t FinishCount;
  POP(FinishCount);
  for (size_t i = 0; i < FinishCount; i++) {
    uint8_t AvailOut;
    POP(AvailOut);
    Plan.add_finish_avail_outs(AvailOut);
  }

  uint8_t InflateOpCount;
  POP(InflateOpCount);
  size_t MaxInflateOpCount = MaxDeflateOpCount * 2;
  if (InflateOpCount > MaxInflateOpCount)
    InflateOpCount = MaxInflateOpCount;
  for (size_t i = 0; i < InflateOpCount; i++) {
    InflateOp *Op = Plan.add_inflate_ops();
    uint8_t AvailIn;
    POP(AvailIn);
    AvailIn++;
    uint8_t AvailOut;
    POP(AvailOut);
    AvailOut++;
    std::unique_ptr<class Inflate> Inflate = std::make_unique<class Inflate>();
    Inflate->set_avail_in(AvailIn);
    Inflate->set_avail_out(AvailOut);
    Inflate->set_flush(PB_Z_NO_FLUSH);
    Op->set_allocated_inflate(Inflate.release());
  }

  uint8_t TailSize;
  POP(TailSize);
  Plan.set_tail_size(TailSize);

  uint8_t BitFlipCount;
  POP(BitFlipCount);
  for (size_t i = 0; i < BitFlipCount; i++) {
    uint16_t Index;
    POP(Index);
    Plan.add_bit_flips(Index);
  }

#undef POP

  Plan.set_data(Data, Size);

  return true;
}
#endif

static void RunInflate(const Plan &Plan, const uint8_t *Compressed,
                       uInt ActualCompressedSize, bool Check) {
  if (Debug) {
    fprintf(stderr, "/* n_inflate_ops == %i; */\n", Plan.inflate_ops_size());
    fprintf(stderr, "Strm.next_in = Compressed;\n");
    fprintf(stderr, "Strm.next_out = Plain;\n");
  }
  z_stream Strm;
  memset(&Strm, 0, sizeof(Strm));
  int Err = inflateInit2(&Strm, Plan.window_bits());
  if (Debug)
    fprintf(stderr, "assert(inflateInit2(&Strm, %i) == %s);\n",
            Plan.window_bits(), ErrStr(Err));
  assert(Err == Z_OK);
  if (Plan.dict().size() > 0 && Plan.window_bits() == WB_RAW) {
    Err = InflateSetDictionary(&Strm, (const Bytef *)Plan.dict().c_str(),
                               Plan.dict().size());
    assert(Err == Z_OK);
  }
  std::unique_ptr<uint8_t[]> Uncompressed(
      new uint8_t[Plan.data().size() + Plan.tail_size()]);
  Strm.next_in = Compressed;
  Strm.avail_in = ActualCompressedSize;
  Strm.next_out = Uncompressed.get();
  Strm.avail_out = Plan.data().size() + Plan.tail_size();
  for (int i = 0; i < Plan.inflate_ops_size(); i++) {
    Err = VisitOp(Plan.inflate_ops(i), OpRunner(&Strm, Check));
    if (Err == Z_NEED_DICT) {
      if (Check)
        assert(Plan.dict().size() > 0 && Plan.window_bits() == WB_ZLIB);
      Err = InflateSetDictionary(&Strm, (const Bytef *)Plan.dict().c_str(),
                                 Plan.dict().size());
      if (Check)
        assert(Err == Z_OK);
    }
  }
  if (Err != Z_STREAM_END) {
    Err = Inflate(&Strm, Z_NO_FLUSH);
    if (Err == Z_NEED_DICT) {
      if (Check)
        assert(Plan.dict().size() > 0 && Plan.window_bits() == WB_ZLIB);
      Err = InflateSetDictionary(&Strm, (const Bytef *)Plan.dict().c_str(),
                                 Plan.dict().size());
      if (Check)
        assert(Err == Z_OK);
      Err = Inflate(&Strm, Z_NO_FLUSH);
    }
  }
  if (Check) {
    assert(Err == Z_STREAM_END);
    assert(Strm.avail_in == 0);
    assert(Strm.avail_out == (uInt)Plan.tail_size());
    assert(memcmp(Uncompressed.get(), Plan.data().c_str(),
                  Plan.data().size()) == 0);
  }
  Err = inflateEnd(&Strm);
  if (Debug)
    fprintf(stderr, "assert(inflateEnd(&Strm) == %s);\n", ErrStr(Err));
  assert(Err == Z_OK);
}

static void RunPlan(Plan &Plan) {
  size_t CompressedSize =
      Plan.data().size() * 2 + (Plan.deflate_ops_size() + 1) * 128;
  NormalizeOps(Plan.mutable_deflate_ops(), Plan.data().size(), CompressedSize);
  if (Debug) {
    fprintf(stderr, "z_stream Strm;\n");
    fprintf(stderr, "/* n_deflate_ops == %i; */\n", Plan.deflate_ops_size());
    fprintf(stderr, "memset(&Strm, 0, sizeof(Strm));\n");
  }

  std::unique_ptr<uint8_t[]> Compressed(new uint8_t[CompressedSize]);
  z_stream Strm;
  memset(&Strm, 0, sizeof(Strm));
  int Err = deflateInit2(&Strm, Plan.level(), Z_DEFLATED, Plan.window_bits(),
                         Plan.mem_level(), Plan.strategy());
  if (Debug)
    fprintf(stderr,
            "assert(deflateInit2(&Strm, %i, Z_DEFLATED, %i, %i, %s) == %s);\n",
            Plan.level(), Plan.window_bits(), Plan.mem_level(),
            StrategyStr(Plan.strategy()), ErrStr(Err));
  assert(Err == Z_OK);
  if (Plan.dict().size() > 0) {
    Err = DeflateSetDictionary(&Strm, (const Bytef *)Plan.dict().c_str(),
                               Plan.dict().size());
    assert(Err == Z_OK);
  }
  Strm.next_in = (const Bytef *)Plan.data().c_str();
  Strm.avail_in = Plan.data().size();
  Strm.next_out = Compressed.get();
  Strm.avail_out = CompressedSize;
  if (Debug) {
    fprintf(stderr, "unsigned char Plain[%zu] = ", Plan.data().size());
    HexDumpStr(stderr, Plan.data().c_str(), Plan.data().size());
    fprintf(stderr, ";\nStrm.next_in = Plain;\n");
    fprintf(stderr, "unsigned char Compressed[%zu];\n", CompressedSize);
    fprintf(stderr, "Strm.next_out = Compressed;\n");
  }
  for (int i = 0; i < Plan.deflate_ops_size(); i++)
    VisitOp(Plan.deflate_ops(i), OpRunner(&Strm, true));
  int FinishCount = Plan.finish_avail_outs_size();
  uInt FinishAvailOutDenominator = 0;
  for (int i = 0; i < FinishCount; i++)
    FinishAvailOutDenominator += Plan.finish_avail_outs(i);
  if (FinishAvailOutDenominator == 0) {
    Err = Z_OK;
  } else {
    uInt FinishAvailOutNumerator = Strm.avail_out;
    for (int i = 0; i < FinishCount; i++) {
      Avail Avail(&Strm, Strm.avail_in,
                  (Plan.finish_avail_outs(i) * FinishAvailOutNumerator) /
                      FinishAvailOutDenominator);
      Err = Deflate(&Strm, Z_FINISH);
      if (Err == Z_STREAM_END)
        break;
      assert(Err == Z_OK || Err == Z_BUF_ERROR);
    }
  }
  if (Err != Z_STREAM_END) {
    Err = Deflate(&Strm, Z_FINISH);
    assert(Err == Z_STREAM_END);
  }
  assert(Strm.avail_in == 0);
  uInt ActualCompressedSize = CompressedSize - Strm.avail_out;
  assert(ActualCompressedSize == Strm.total_out);
  if (Debug)
    fprintf(stderr, "/* total_out == %i; */\n", ActualCompressedSize);
  Err = deflateEnd(&Strm);
  if (Debug)
    fprintf(stderr, "assert(deflateEnd(&Strm) == %s);\n", ErrStr(Err));
  assert(Err == Z_OK);

  NormalizeOps(Plan.mutable_inflate_ops(), ActualCompressedSize,
               Plan.data().size());

  RunInflate(Plan, Compressed.get(), ActualCompressedSize, true);

  if (Debug)
    fprintf(stderr, "/* n_bit_flips == %i; */\n", Plan.bit_flips_size());
  for (int i = 0; i < Plan.bit_flips_size(); i++) {
    int bit_index = Plan.bit_flips(i) % (ActualCompressedSize * 8);
    int byte_index = bit_index / 8;
    int mask = 1 << (bit_index % 8);
    Compressed[byte_index] ^= mask;
    if (Debug)
      fprintf(stderr, "Compressed[%d] ^= 0x%02x;\n", byte_index, mask);
  }
  RunInflate(Plan, Compressed.get(), ActualCompressedSize, false);
}

#ifdef USE_LIBPROTOBUF_MUTATOR
static void FixupOp(DeflateOp *Op) {
  if (Op->has_deflate() && (Op->deflate().flush() == PB_Z_FINISH ||
                            Op->deflate().flush() == PB_Z_TREES))
    Op->mutable_deflate()->set_flush(PB_Z_NO_FLUSH);
}

static void FixupOp(InflateOp *Op) {
  if (Op->has_inflate())
    Op->mutable_inflate()->set_flush(PB_Z_NO_FLUSH);
}

template <typename OpsT> static void FixupOps(OpsT *Ops) {
  int Pos = 0;
  for (int i = 0, size = Ops->size(); i < size; i++) {
    typename OpsT::value_type &Op = (*Ops)[i];
    if (Op.op_case() == 0)
      continue;
    FixupOp(&Op);
    Ops->SwapElements(Pos, i);
    Pos++;
  }
  Ops->DeleteSubrange(Pos, Ops->size() - Pos);
}

static protobuf_mutator::libfuzzer::PostProcessorRegistration<Plan> reg = {
    [](Plan *Plan, unsigned int /* Seed */) {
      if (Plan->window_bits() == WB_DEFAULT)
        Plan->set_window_bits(WB_ZLIB);
      if (Plan->mem_level() == MEM_LEVEL_DEFAULT)
        Plan->set_mem_level(MEM_LEVEL8);
      FixupOps(Plan->mutable_deflate_ops());
      FixupOps(Plan->mutable_inflate_ops());
      if (Plan->window_bits() == WB_GZIP)
        Plan->clear_dict();
      Plan->set_tail_size(Plan->tail_size() & 0xff);
    }};

DEFINE_PROTO_FUZZER(const Plan &Plan) {
  class Plan PlanCopy = Plan;
  RunPlan(PlanCopy);
}
#else
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  Plan Plan;
  if (GeneratePlan(Plan, Data, Size))
    RunPlan(Plan);
  return 0;
}
#endif
