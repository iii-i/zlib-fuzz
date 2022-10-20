#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_LIBPROTOBUF_MUTATOR
#include <src/libfuzzer/libfuzzer_macro.h>
#endif
#include <zlib.h>

#ifdef USE_LIBPROTOBUF_MUTATOR
#include "fuzz_target.pb.h"
#endif

#ifdef __cplusplus
#define EXTERN_C extern "C"
#else
#define EXTERN_C
#endif

/* Constants. */

#define MEM_LEVEL_DEFAULT 0
#define MEM_LEVEL8 8

#ifdef USE_LIBPROTOBUF_MUTATOR
static_assert(PB_DEFLATE_Z_NO_FLUSH == Z_NO_FLUSH);
static_assert(PB_DEFLATE_Z_PARTIAL_FLUSH == Z_PARTIAL_FLUSH);
static_assert(PB_DEFLATE_Z_SYNC_FLUSH == Z_SYNC_FLUSH);
static_assert(PB_DEFLATE_Z_FULL_FLUSH == Z_FULL_FLUSH);
static_assert(PB_DEFLATE_Z_BLOCK == Z_BLOCK);
static_assert(PB_INFLATE_Z_NO_FLUSH == Z_NO_FLUSH);
static_assert(PB_Z_NO_COMPRESSION == Z_NO_COMPRESSION);
static_assert(PB_Z_BEST_SPEED == Z_BEST_SPEED);
static_assert(PB_Z_BEST_COMPRESSION == Z_BEST_COMPRESSION);
static_assert(PB_Z_DEFAULT_COMPRESSION == Z_DEFAULT_COMPRESSION);
static_assert(PB_Z_DEFAULT_STRATEGY == Z_DEFAULT_STRATEGY);
static_assert(PB_Z_FILTERED == Z_FILTERED);
static_assert(PB_Z_HUFFMAN_ONLY == Z_HUFFMAN_ONLY);
static_assert(PB_Z_RLE == Z_RLE);
static_assert(PB_Z_FIXED == Z_FIXED);
static_assert(PB_MEM_LEVEL_DEFAULT == MEM_LEVEL_DEFAULT);
static_assert(PB_MEM_LEVEL8 == MEM_LEVEL8);
#endif

/* Window size utilities. */

static bool IsWbRaw(int WindowBits) {
  return WindowBits >= -15 && WindowBits <= -9;
}

static bool IsWbZlib(int WindowBits) {
  return WindowBits >= 9 && WindowBits <= 15;
}

static bool IsWbGzip(int WindowBits) {
  return WindowBits >= (16 + 9) && WindowBits <= (16 + 15);
}

static int FixupWindowBits(int WindowBits) {
  if (IsWbRaw(WindowBits) || IsWbZlib(WindowBits) || IsWbGzip(WindowBits))
    return WindowBits;
  else
    return 15;
}

/* Dumping. */

static int Debug;

__attribute__((constructor)) static void Init() {
  const char *Env = getenv("DEBUG");
  if (Env)
    Debug = atoi(Env);
}

static int Indent = 0;

static void Print(FILE *Stream, const char *Fmt, ...) {
  va_list VaList;
  va_start(VaList, Fmt);
  fprintf(Stream, "%*s", Indent * 2, "");
  vfprintf(Stream, Fmt, VaList);
  va_end(VaList);
}

static void HexDump(FILE *Stream, const void *Data, size_t Size) {
  for (size_t i = 0; i < Size; i++)
    fprintf(Stream, "\\x%02x", ((const uint8_t *)Data)[i]);
}

static void HexDumpCStr(FILE *Stream, const void *Data, size_t Size) {
  if (Size == 0) {
    fprintf(Stream, "\"\"");
    return;
  }
  const size_t ChunkSize = 16;
  bool IndentIncremented = false;
  for (size_t i = 0; i < Size; i += ChunkSize) {
    if (i == 0)
      fprintf(Stream, "\"");
    else {
      fprintf(Stream, "\n");
      if (!IndentIncremented) {
        Indent++;
        IndentIncremented = true;
      }
      Print(Stream, "\"");
    }
    HexDump(Stream, ((const uint8_t *)Data) + i,
            (Size - i) < ChunkSize ? (Size - i) : ChunkSize);
    fprintf(Stream, "\"");
  }
  if (IndentIncremented)
    Indent--;
}

static void Dump(FILE *Stream, const char *Name, const void *Data,
                 size_t Size) {
  Print(Stream, "unsigned char %s[%zu]", Name, Size);
  if (Debug & 2) {
    FILE *File = fopen(Name, "wb");
    assert(File);
    assert(fwrite(Data, 1, Size, File) == Size);
    assert(fclose(File) == 0);
    fprintf(Stream, ";\n");
    Print(Stream, "{\n");
    Indent++;
    Print(Stream, "FILE *File = fopen(\"%s\", \"rb\");\n", Name);
    Print(Stream, "assert(File);\n");
    Print(Stream, "assert(fread(%s, 1, %zu, File) == %zu);\n", Name, Size,
          Size);
    Print(Stream, "assert(fclose(File) == 0);\n");
    Indent--;
    Print(Stream, "}\n");
  } else {
    fprintf(Stream, " = ");
    HexDumpCStr(Stream, Data, Size);
    fprintf(Stream, ";\n");
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

static int DeflateInit2(z_stream *Strm, size_t *Idx, int Level, int Method,
                        int WindowBits, int MemLevel, int Strategy) {
  if (Debug)
    Print(stderr,
          "assert(deflateInit2(&Strm[%zu], %i, %i, %i, %i, %s) == ", *Idx,
          Level, Method, WindowBits, MemLevel, StrategyStr(Strategy));
  int Err =
      deflateInit2(&Strm[*Idx], Level, Method, WindowBits, MemLevel, Strategy);
  if (Debug)
    fprintf(stderr, "%s);\n", ErrStr(Err));
  return Err;
}

static int DeflateSetDictionary(z_stream *Strm, size_t *Idx, const Bytef *Dict,
                                size_t DictLen) {
  if (Debug)
    Print(stderr,
          "assert(deflateSetDictionary(&Strm[%zu], Dict, %zu) == ", *Idx,
          DictLen);
  int Err = deflateSetDictionary(&Strm[*Idx], Dict, DictLen);
  if (Debug)
    fprintf(stderr, "%s);\n", ErrStr(Err));
  return Err;
}

static int Deflate(z_stream *Strm, size_t *Idx, int Flush) {
  if (Debug)
    Print(stderr,
          "Strm[%zu].avail_in = %u; Strm[%zu].avail_out = %u; "
          "assert(deflate(&Strm[%zu], "
          "%s) == ",
          *Idx, Strm->avail_in, *Idx, Strm->avail_out, *Idx, FlushStr(Flush));
  int Err = deflate(&Strm[*Idx], Flush);
  if (Debug)
    fprintf(stderr, "%s);\n", ErrStr(Err));
  return Err;
}

static int DeflateParams(z_stream *Strm, size_t *Idx, int Level, int Strategy) {
  if (Debug)
    Print(stderr,
          "Strm[%zu].avail_in = %u; Strm[%zu].avail_out = %u; "
          "assert(deflateParams(&Strm[%zu], %i, %s) == ",
          *Idx, Strm[*Idx].avail_in, *Idx, Strm[*Idx].avail_out, *Idx, Level,
          StrategyStr(Strategy));
  int Err = deflateParams(&Strm[*Idx], Level, Strategy);
  if (Debug)
    fprintf(stderr, "%s);\n", ErrStr(Err));
  return Err;
}

static int DeflateCopy(z_stream *Strm, size_t *Idx) {
  if (Debug)
    Print(stderr, "assert(deflateCopy(&Strm[%zu], &Strm[%zu]) == ", 1 - *Idx,
          *Idx);
  int Err = deflateCopy(&Strm[1 - *Idx], &Strm[*Idx]);
  if (Debug) {
    fprintf(stderr, "%s);\n", ErrStr(Err));
    Print(stderr, "deflateEnd(&Strm[%zu]);\n", *Idx);
  }
  deflateEnd(&Strm[*Idx]);
  *Idx = 1 - *Idx;
  return Err;
}

static int InflateSetDictionary(z_stream *Strm, size_t *Idx, const Bytef *Dict,
                                size_t DictLen) {
  if (Debug) {
    Print(stderr,
          "assert(inflateSetDictionary(&Strm[%zu], Dict, %zu) == ", *Idx,
          DictLen);
  }
  int Err = inflateSetDictionary(&Strm[*Idx], Dict, DictLen);
  if (Debug)
    fprintf(stderr, "%s);\n", ErrStr(Err));
  return Err;
}

static int Inflate(z_stream *Strm, size_t *Idx, int Flush) {
  if (Debug)
    Print(stderr,
          "Strm[%zu].avail_in = %u; Strm[%zu].avail_out = %u; "
          "assert(inflate(&Strm[%zu], "
          "%s) == ",
          *Idx, Strm[*Idx].avail_in, *Idx, Strm[*Idx].avail_out, *Idx,
          FlushStr(Flush));
  int Err = inflate(&Strm[*Idx], Flush);
  if (Debug)
    fprintf(stderr, "%s);\n", ErrStr(Err));
  return Err;
}

static int InflateCopy(z_stream *Strm, size_t *Idx) {
  if (Debug)
    Print(stderr, "assert(inflateCopy(&Strm[%zu], &Strm[%zu]) == ", 1 - *Idx,
          *Idx);
  int Err = inflateCopy(&Strm[1 - *Idx], &Strm[*Idx]);
  if (Debug) {
    fprintf(stderr, "%s);\n", ErrStr(Err));
    Print(stderr, "inflateEnd(&Strm[%zu]);\n", *Idx);
  }
  inflateEnd(&Strm[*Idx]);
  *Idx = 1 - *Idx;
  return Err;
}

/* Restricting avail_in / avail_out. */

struct Avail {
  z_stream *Strm;
  uInt AvailIn0;
  uInt AvailIn1;
  uInt AvailOut0;
  uInt AvailOut1;
};

void AvailInit(struct Avail *Self, z_stream *Strm, uInt MaxAvailIn,
               uInt MaxAvailOut) {
  Self->Strm = Strm;
  Self->AvailIn0 = Strm->avail_in;
  Self->AvailIn1 = Self->AvailIn0 < MaxAvailIn ? Self->AvailIn0 : MaxAvailIn;
  Self->AvailOut0 = Strm->avail_out;
  Self->AvailOut1 =
      Self->AvailOut0 < MaxAvailOut ? Self->AvailOut0 : MaxAvailOut;
  Strm->avail_in = Self->AvailIn1;
  Strm->avail_out = Self->AvailOut1;
}

void AvailEnd(struct Avail *Self) {
  uInt ConsumedIn = Self->AvailIn1 - Self->Strm->avail_in;
  Self->Strm->avail_in = Self->AvailIn0 - ConsumedIn;
  uInt ConsumedOut = Self->AvailOut1 - Self->Strm->avail_out;
  Self->Strm->avail_out = Self->AvailOut0 - ConsumedOut;
}

/* libprotobuf-mutator and libFuzzer adapters. */

enum DeflateOpType {
  DeflateOpTypeNone,
  DeflateOpTypeDeflate,
  DeflateOpTypeDeflateParams,
  DeflateOpTypeDeflateCopy,
  DeflateOpTypeMax,
};

enum InflateOpType {
  InflateOpTypeNone,
  InflateOpTypeInflate,
  InflateOpTypeInflateCopy,
  InflateOpTypeMax,
};

#ifdef USE_LIBPROTOBUF_MUTATOR
struct PlanExecution {
  const PbPlan *Plan;
  size_t DeflateDictPieceIdx;
  size_t DeflateOpIdx;
  size_t InflateDictPieceIdx;
  size_t InflateOpIdx;
  size_t FinishOpIdx;
  size_t BitFlipIdx;
};

static void PlanExecutionInit(struct PlanExecution *PE, const PbPlan *Plan) {
  PE->Plan = Plan;
  PE->DeflateDictPieceIdx = 0;
  PE->DeflateOpIdx = 0;
  PE->InflateDictPieceIdx = 0;
  PE->InflateOpIdx = 0;
  PE->FinishOpIdx = 0;
  PE->BitFlipIdx = 0;
}

static const char *GetPlainData(struct PlanExecution *PE) {
  return PE->Plan->data().c_str();
}

static size_t GetPlainDataSize(struct PlanExecution *PE) {
  return PE->Plan->data().size();
}

static int GetInitialLevel(struct PlanExecution *PE) {
  return PE->Plan->level();
}

static int GetWindowBits(struct PlanExecution *PE) {
  return PE->Plan->window_bits();
}

static int GetMemLevel(struct PlanExecution *PE) {
  return PE->Plan->mem_level();
}

static int GetInitialStrategy(struct PlanExecution *PE) {
  return PE->Plan->strategy();
}

static const char *GetDict(struct PlanExecution *PE) {
  return PE->Plan->dict().c_str();
}

static size_t GetDictSize(struct PlanExecution *PE) {
  return PE->Plan->dict().size();
}

static size_t GetDeflateDictPiecesCount(struct PlanExecution *PE) {
  return PE->Plan->deflate_dict_pieces_size();
}

static uInt GetDeflateDictPiece(struct PlanExecution *PE) {
  return PE->Plan->deflate_dict_pieces(PE->DeflateDictPieceIdx++);
}

static size_t GetDeflateOpCount(struct PlanExecution *PE) {
  return PE->Plan->deflate_ops_size();
}

static void NextDeflateOp(struct PlanExecution *PE) { PE->DeflateOpIdx++; }

static enum DeflateOpType GetDeflateOpType(struct PlanExecution *PE) {
  int op_case = PE->Plan->deflate_ops(PE->DeflateOpIdx).op_case();
  switch (op_case) {
  case PbDeflateOp::OP_NOT_SET:
    return DeflateOpTypeNone;
  case PbDeflateOp::kDeflate:
    return DeflateOpTypeDeflate;
  case PbDeflateOp::kDeflateParams:
    return DeflateOpTypeDeflateParams;
  case PbDeflateOp::kDeflateCopy:
    return DeflateOpTypeDeflateCopy;
  default:
    fprintf(stderr, "Unexpected PbDeflateOp->op_case: %i\n", op_case);
    assert(0);
  }
}

static uInt GetDeflateAvailIn(struct PlanExecution *PE) {
  return PE->Plan->deflate_ops(PE->DeflateOpIdx).deflate().avail_in();
}

static uInt GetDeflateAvailOut(struct PlanExecution *PE) {
  return PE->Plan->deflate_ops(PE->DeflateOpIdx).deflate().avail_out();
}

static int GetDeflateFlush(struct PlanExecution *PE) {
  return PE->Plan->deflate_ops(PE->DeflateOpIdx).deflate().flush();
}

static uInt GetDeflateParamsAvailIn(struct PlanExecution *PE) {
  return PE->Plan->deflate_ops(PE->DeflateOpIdx).deflate_params().avail_in();
}

static uInt GetDeflateParamsAvailOut(struct PlanExecution *PE) {
  return PE->Plan->deflate_ops(PE->DeflateOpIdx).deflate_params().avail_out();
}

static int GetDeflateParamsLevel(struct PlanExecution *PE) {
  return PE->Plan->deflate_ops(PE->DeflateOpIdx).deflate_params().level();
}

static int GetDeflateParamsStrategy(struct PlanExecution *PE) {
  return PE->Plan->deflate_ops(PE->DeflateOpIdx).deflate_params().strategy();
}

static size_t GetFinishOpCount(struct PlanExecution *PE) {
  return PE->Plan->finish_avail_outs().size();
}

static void NextFinishOp(struct PlanExecution *PE) { PE->FinishOpIdx++; }

static uInt GetFinishAvailOut(struct PlanExecution *PE) {
  return PE->Plan->finish_avail_outs(PE->FinishOpIdx);
}

static void ResetInflateDictPieces(struct PlanExecution *PE) {
  PE->InflateDictPieceIdx = 0;
}

static size_t GetInflateDictPiecesCount(struct PlanExecution *PE) {
  return PE->Plan->inflate_dict_pieces_size();
}

static uInt GetInflateDictPiece(struct PlanExecution *PE) {
  return PE->Plan->inflate_dict_pieces(PE->InflateDictPieceIdx++);
}

static void ResetInflateOps(struct PlanExecution *PE) { PE->InflateOpIdx = 0; }

static size_t GetInflateOpCount(struct PlanExecution *PE) {
  return PE->Plan->inflate_ops_size();
}

static void NextInflateOp(struct PlanExecution *PE) { PE->InflateOpIdx++; }

static enum InflateOpType GetInflateOpType(struct PlanExecution *PE) {
  int op_case = PE->Plan->inflate_ops(PE->InflateOpIdx).op_case();
  switch (op_case) {
  case PbInflateOp::OP_NOT_SET:
    return InflateOpTypeNone;
  case PbInflateOp::kInflate:
    return InflateOpTypeInflate;
  case PbInflateOp::kInflateCopy:
    return InflateOpTypeInflateCopy;
  default:
    fprintf(stderr, "Unexpected PbInflateOp->op_case: %i\n", op_case);
    assert(0);
  }
}

static uInt GetInflateAvailIn(struct PlanExecution *PE) {
  return PE->Plan->inflate_ops(PE->InflateOpIdx).inflate().avail_in();
}

static uInt GetInflateAvailOut(struct PlanExecution *PE) {
  return PE->Plan->inflate_ops(PE->InflateOpIdx).inflate().avail_out();
}

static int GetInflateFlush(struct PlanExecution *PE) {
  return PE->Plan->inflate_ops(PE->InflateOpIdx).inflate().flush();
}

static int GetTailSize(struct PlanExecution *PE) {
  return PE->Plan->tail_size();
}

static size_t GetBitFlipCount(struct PlanExecution *PE) {
  return PE->Plan->bit_flips().size();
}

static void NextBitFlip(struct PlanExecution *PE) { PE->BitFlipIdx++; }

static uInt GetBitFlip(struct PlanExecution *PE) {
  return PE->Plan->bit_flips(PE->BitFlipIdx);
}
#else
struct PlanExecution {
  const uint8_t *Data;
  size_t Size;
  const char *PlainData;
  size_t PlainDataSize;
  int WindowBits;
  const char *Dict;
  size_t DictSize;
};

#define POP(PE, Type, Default)                                                 \
  ({                                                                           \
    Type __Result;                                                             \
    if ((PE)->Size < sizeof(__Result)) {                                       \
      __Result = (Default);                                                    \
    } else {                                                                   \
      memcpy(&__Result, (PE)->Data, sizeof(__Result));                         \
      (PE)->Data += sizeof(__Result);                                          \
      (PE)->Size -= sizeof(__Result);                                          \
    }                                                                          \
    __Result;                                                                  \
  })

static int ChooseLevel(uint8_t Choice) {
  if (Choice < 128)
    return (Choice % 11) - 1;
  else
    return Z_BEST_SPEED;
}

static int ChooseMemLevel(uint8_t Choice) { return (Choice % 9) + 1; }

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

static enum DeflateOpType ChooseDeflateOp(uint8_t Choice) {
  if (Choice < 120)
    return DeflateOpTypeDeflate;
  else if (Choice < 240)
    return DeflateOpTypeDeflateParams;
  else
    return DeflateOpTypeDeflateCopy;
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

static void PlanExecutionInit(struct PlanExecution *PE, const uint8_t *Data,
                              size_t Size) {
  if (Debug)
    Print(stderr, "/* size == %zu; */\n", Size);

  PE->Data = Data;
  PE->Size = Size;

  uint16_t Choice = POP(PE, uint16_t, 0);
  PE->PlainData = (const char *)PE->Data;
  PE->PlainDataSize = PE->Size * (Choice + 0x2000) / 0x10000;
  if (PE->PlainDataSize > PE->Size)
    PE->PlainDataSize = PE->Size;
  PE->Data += PE->PlainDataSize;
  PE->Size -= PE->PlainDataSize;

  PE->WindowBits = FixupWindowBits(POP(PE, int8_t, 0));

  PE->Dict = NULL;
  PE->DictSize = 0;
  if (!IsWbGzip(PE->WindowBits)) {
    size_t DictSize = POP(PE, uint8_t, 0);
    if (DictSize > 0 && DictSize < 128) {
      size_t MaxDictSize = PE->Size / 4;
      if (DictSize > MaxDictSize)
        DictSize = MaxDictSize;
      PE->Dict = (const char *)PE->Data;
      PE->DictSize = DictSize;
      PE->Data += DictSize;
      PE->Size -= DictSize;
    }
  }
}

static const char *GetPlainData(struct PlanExecution *PE) {
  return PE->PlainData;
}

static size_t GetPlainDataSize(struct PlanExecution *PE) {
  return PE->PlainDataSize;
}

static int GetInitialLevel(struct PlanExecution *PE) {
  return ChooseLevel(POP(PE, uint8_t, 0));
}

static int GetWindowBits(struct PlanExecution *PE) { return PE->WindowBits; }

static int GetMemLevel(struct PlanExecution *PE) {
  return ChooseMemLevel(POP(PE, uint8_t, 0));
}

static int GetInitialStrategy(struct PlanExecution *PE) {
  return ChooseStrategy(POP(PE, uint8_t, 0));
}

static const char *GetDict(struct PlanExecution *PE) { return PE->Dict; }

static size_t GetDictSize(struct PlanExecution *PE) { return PE->DictSize; }

static size_t GetDeflateDictPiecesCount(struct PlanExecution *PE) {
  return POP(PE, uint8_t, 0);
}

static uInt GetDeflateDictPiece(struct PlanExecution *PE) {
  return POP(PE, uint16_t, 0);
}

static size_t GetDeflateOpCount(struct PlanExecution *PE) {
  return POP(PE, uint8_t, 0);
}

static void NextDeflateOp(struct PlanExecution *PE) { (void)PE; }

static enum DeflateOpType GetDeflateOpType(struct PlanExecution *PE) {
  return ChooseDeflateOp(POP(PE, uint8_t, 0));
}

static uInt GetDeflateAvailIn(struct PlanExecution *PE) {
  return POP(PE, uint8_t, 0);
}

static uInt GetDeflateAvailOut(struct PlanExecution *PE) {
  return POP(PE, uint8_t, 0);
}

static int GetDeflateFlush(struct PlanExecution *PE) {
  return ChooseDeflateFlush(POP(PE, uint8_t, 0xff));
}

static uInt GetDeflateParamsAvailIn(struct PlanExecution *PE) {
  return POP(PE, uint8_t, 0);
}

static uInt GetDeflateParamsAvailOut(struct PlanExecution *PE) {
  return POP(PE, uint8_t, 0);
}

static int GetDeflateParamsLevel(struct PlanExecution *PE) {
  return ChooseLevel(POP(PE, uint8_t, 0xff));
}

static int GetDeflateParamsStrategy(struct PlanExecution *PE) {
  return ChooseStrategy(POP(PE, uint8_t, 0xff));
}

static size_t GetFinishOpCount(struct PlanExecution *PE) {
  return POP(PE, uint8_t, 0);
}

static void NextFinishOp(struct PlanExecution *PE) { (void)PE; }

static uInt GetFinishAvailOut(struct PlanExecution *PE) {
  return POP(PE, uint8_t, 0);
}

static void ResetInflateDictPieces(struct PlanExecution *PE) { (void)PE; }

static size_t GetInflateDictPiecesCount(struct PlanExecution *PE) {
  return POP(PE, uint8_t, 0);
}

static uInt GetInflateDictPiece(struct PlanExecution *PE) {
  return POP(PE, uint16_t, 0);
}

static void ResetInflateOps(struct PlanExecution *PE) { (void)PE; }

static size_t GetInflateOpCount(struct PlanExecution *PE) {
  return POP(PE, uint8_t, 0);
}

static void NextInflateOp(struct PlanExecution *PE) { (void)PE; }

static enum InflateOpType GetInflateOpType(struct PlanExecution *PE) {
  return (enum InflateOpType)(POP(PE, uint8_t, 0) % InflateOpTypeMax);
}

static uInt GetInflateAvailIn(struct PlanExecution *PE) {
  return POP(PE, uint8_t, 0);
}

static uInt GetInflateAvailOut(struct PlanExecution *PE) {
  return POP(PE, uint8_t, 0);
}

static int GetInflateFlush(struct PlanExecution *PE) {
  (void)PE;
  return Z_NO_FLUSH;
}

static int GetTailSize(struct PlanExecution *PE) { return POP(PE, uint8_t, 0); }

static size_t GetBitFlipCount(struct PlanExecution *PE) {
  return POP(PE, uint8_t, 0);
}

static void NextBitFlip(struct PlanExecution *PE) { (void)PE; }

static uInt GetBitFlip(struct PlanExecution *PE) {
  return POP(PE, uint16_t, 0);
}
#endif

/* Common fuzzing logic. */

static int RunDeflateOp(z_stream *Strm, size_t *Idx, struct PlanExecution *PE,
                        bool Check) {
  switch (GetDeflateOpType(PE)) {
  case DeflateOpTypeNone:
    return 0;
  case DeflateOpTypeDeflate: {
    struct Avail Avail;
    AvailInit(&Avail, &Strm[*Idx], GetDeflateAvailIn(PE),
              GetDeflateAvailOut(PE));
    int Err = Deflate(Strm, Idx, GetDeflateFlush(PE));
    AvailEnd(&Avail);
    if (Check)
      assert(Err == Z_OK || Err == Z_BUF_ERROR);
    return Err;
  }
  case DeflateOpTypeDeflateParams: {
    struct Avail Avail;
    AvailInit(&Avail, &Strm[*Idx], GetDeflateParamsAvailIn(PE),
              GetDeflateParamsAvailOut(PE));
    int Err = DeflateParams(Strm, Idx, GetDeflateParamsLevel(PE),
                            GetDeflateParamsStrategy(PE));
    AvailEnd(&Avail);
    if (Check)
      assert(Err == Z_OK || Err == Z_BUF_ERROR);
    return Err;
  }
  case DeflateOpTypeDeflateCopy: {
    int Err = DeflateCopy(Strm, Idx);
    if (Check)
      assert(Err == Z_OK);
    return Err;
  }
  default:
    fprintf(stderr, "Unexpected DeflateOp\n");
    assert(0);
  }
}

static int RunInflateOp(z_stream *Strm, size_t *Idx, struct PlanExecution *PE,
                        bool Check) {
  switch (GetInflateOpType(PE)) {
  case InflateOpTypeNone:
    return 0;
  case InflateOpTypeInflate: {
    struct Avail Avail;
    AvailInit(&Avail, &Strm[*Idx], GetInflateAvailIn(PE),
              GetInflateAvailOut(PE));
    int Err = Inflate(Strm, Idx, GetInflateFlush(PE));
    AvailEnd(&Avail);
    if (Check)
      assert(Err == Z_OK || Err == Z_STREAM_END || Err == Z_NEED_DICT ||
             Err == Z_BUF_ERROR);
    return Err;
  }
  case InflateOpTypeInflateCopy: {
    int Err = InflateCopy(Strm, Idx);
    if (Check)
      assert(Err == Z_OK);
    return Err;
  }
  default:
    fprintf(stderr, "Unexpected InflateOp\n");
    assert(0);
  }
}

static void ExecutePlanInflate(struct PlanExecution *PE,
                               const uint8_t *Compressed,
                               uInt ActualCompressedSize, bool Check) {
  ResetInflateDictPieces(PE);
  ResetInflateOps(PE);
  int InflateOpCount = GetInflateOpCount(PE);
  z_stream Strm[2];
  size_t Idx = 0;
  if (Debug) {
    Print(stderr, "/* n_inflate_ops == %i; */\n", InflateOpCount);
    Print(stderr, "Strm[%zu].next_in = Compressed;\n", Idx);
    Print(stderr, "Strm[%zu].next_out = Plain;\n", Idx);
  }
  memset(&Strm, 0, sizeof(Strm));
  int WindowBits = FixupWindowBits(GetWindowBits(PE));
  int Err = inflateInit2(&Strm[Idx], WindowBits);
  if (Debug)
    Print(stderr, "assert(inflateInit2(&Strm[%zu], %i) == %s);\n", Idx,
          WindowBits, ErrStr(Err));
  assert(Err == Z_OK);
  if (GetDictSize(PE) > 0 && IsWbRaw(WindowBits)) {
    size_t PiecesCount = GetInflateDictPiecesCount(PE);
    size_t Offset = 0;
    for (size_t i = 0; i <= PiecesCount && Offset < GetDictSize(PE); i++) {
      uInt Piece;
      if (i < PiecesCount) {
        Piece = GetInflateDictPiece(PE);
        if (Offset + Piece > GetDictSize(PE))
          Piece = GetDictSize(PE) - Offset;
      } else {
        Piece = GetDictSize(PE) - Offset;
      }
      int Err = InflateSetDictionary(
          Strm, &Idx, (const Bytef *)GetDict(PE) + Offset, Piece);
      if (Check)
        assert(Err == Z_OK);
      Offset += Piece;
    }
    assert(Offset == GetDictSize(PE));
  }
  size_t TailSize = GetTailSize(PE) & 0xff;
  uint8_t *Uncompressed = (uint8_t *)malloc(GetPlainDataSize(PE) + TailSize);
  assert(Uncompressed);
  Strm[Idx].next_in = Compressed;
  Strm[Idx].avail_in = ActualCompressedSize;
  Strm[Idx].next_out = Uncompressed;
  Strm[Idx].avail_out = GetPlainDataSize(PE) + TailSize;
  for (int i = 0; i < InflateOpCount; i++, NextInflateOp(PE)) {
    Err = RunInflateOp(Strm, &Idx, PE, Check);
    if (Err == Z_NEED_DICT) {
      if (Check)
        assert(GetDictSize(PE) > 0 && IsWbZlib(WindowBits));
      Err = InflateSetDictionary(Strm, &Idx, (const Bytef *)GetDict(PE),
                                 GetDictSize(PE));
      if (Check)
        assert(Err == Z_OK);
    }
  }
  if (Err != Z_STREAM_END) {
    Err = Inflate(Strm, &Idx, Z_NO_FLUSH);
    if (Err == Z_NEED_DICT) {
      if (Check)
        assert(GetDictSize(PE) > 0 && IsWbZlib(WindowBits));
      Err = InflateSetDictionary(Strm, &Idx, (const Bytef *)GetDict(PE),
                                 GetDictSize(PE));
      if (Check)
        assert(Err == Z_OK);
      Err = Inflate(Strm, &Idx, Z_NO_FLUSH);
    }
  }
  if (Check) {
    assert(Err == Z_STREAM_END);
    if (Debug)
      Print(stderr, "assert(Strm[%zu].avail_in == %u);\n", Idx,
            Strm[Idx].avail_in);
    assert(Strm[Idx].avail_in == 0);
    if (Debug)
      Print(stderr, "assert(Strm[%zu].avail_out == %u);\n", Idx,
            Strm[Idx].avail_out);
    assert(Strm[Idx].avail_out == TailSize);
    assert(memcmp(Uncompressed, GetPlainData(PE), GetPlainDataSize(PE)) == 0);
  }
  Err = inflateEnd(&Strm[Idx]);
  if (Debug)
    Print(stderr, "assert(inflateEnd(&Strm[%zu]) == %s);\n", Idx, ErrStr(Err));
  assert(Err == Z_OK);
  free(Uncompressed);
}

static void ExecutePlan(struct PlanExecution *PE) {
  if (Debug) {
    Print(stderr, "#include <assert.h>\n");
    Print(stderr, "#include <stdio.h>\n");
    Print(stderr, "#include <string.h>\n");
    Print(stderr, "#include <zlib.h>\n");
    Print(stderr, "int main(void) {\n");
    Indent++;
  }
  size_t DeflateOpCount = GetDeflateOpCount(PE);
  size_t CompressedSize = GetPlainDataSize(PE) * 2 + (DeflateOpCount + 1) * 128;
  if (Debug) {
    Dump(stderr, "Dict", GetDict(PE), GetDictSize(PE));
    Dump(stderr, "Plain", GetPlainData(PE), GetPlainDataSize(PE));
    Print(stderr, "z_stream Strm[2];\n");
    Print(stderr, "/* n_deflate_ops == %zu; */\n", DeflateOpCount);
    Print(stderr, "memset(&Strm, 0, sizeof(Strm));\n");
  }

  uint8_t *Compressed = (uint8_t *)malloc(CompressedSize);
  assert(Compressed);
  z_stream Strm[2];
  size_t Idx = 0;
  memset(&Strm, 0, sizeof(Strm));
  int WindowBits = FixupWindowBits(GetWindowBits(PE));
  int MemLevel = GetMemLevel(PE);
  if (MemLevel == MEM_LEVEL_DEFAULT)
    MemLevel = MEM_LEVEL8;
  int Strategy = GetInitialStrategy(PE);
  int Err = DeflateInit2(Strm, &Idx, GetInitialLevel(PE), Z_DEFLATED,
                         WindowBits, MemLevel, Strategy);
  assert(Err == Z_OK);
  int Bound = deflateBound(&Strm[Idx], GetPlainDataSize(PE));
  if (Debug)
    Print(stderr, "int Bound = deflateBound(&Strm[%zu], %zu);\n", Idx,
          GetPlainDataSize(PE));
  if (GetDictSize(PE) > 0 && !IsWbGzip(WindowBits)) {
    size_t PiecesCount = GetDeflateDictPiecesCount(PE);
    size_t Offset = 0;
    for (size_t i = 0; i < PiecesCount && Offset < GetDictSize(PE); i++) {
      uInt Piece = GetDeflateDictPiece(PE);
      if (Offset + Piece > GetDictSize(PE))
        Piece = GetDictSize(PE) - Offset;
      Err = DeflateSetDictionary(Strm, &Idx,
                                 (const Bytef *)GetDict(PE) + Offset, Piece);
      assert(Err == Z_OK);
      Offset += Piece;
    }
    if (Offset < GetDictSize(PE)) {
      Err =
          DeflateSetDictionary(Strm, &Idx, (const Bytef *)GetDict(PE) + Offset,
                               GetDictSize(PE) - Offset);
      assert(Err == Z_OK);
    }
  }
  Strm[Idx].next_in = (const Bytef *)GetPlainData(PE);
  Strm[Idx].avail_in = GetPlainDataSize(PE);
  Strm[Idx].next_out = Compressed;
  Strm[Idx].avail_out = CompressedSize;
  if (Debug) {
    Print(stderr, "Strm[%zu].next_in = Plain;\n", Idx);
    Print(stderr, "unsigned char Compressed[%zu];\n", CompressedSize);
    Print(stderr, "Strm[%zu].next_out = Compressed;\n", Idx);
  }
  for (size_t i = 0; i < DeflateOpCount; i++, NextDeflateOp(PE))
    RunDeflateOp(Strm, &Idx, PE, true);
  size_t FinishOpCount = GetFinishOpCount(PE);
  if (Debug)
    Print(stderr, "/* n_finish_ops == %zu; */\n", FinishOpCount);
  for (size_t i = 0; i < FinishOpCount; i++, NextFinishOp(PE)) {
    struct Avail Avail;
    AvailInit(&Avail, &Strm[Idx], Strm[Idx].avail_in, GetFinishAvailOut(PE));
    Err = Deflate(Strm, &Idx, Z_FINISH);
    AvailEnd(&Avail);
    if (Err == Z_STREAM_END)
      break;
    assert(Err == Z_OK || Err == Z_BUF_ERROR);
  }
  if (Err != Z_STREAM_END) {
    Err = Deflate(Strm, &Idx, Z_FINISH);
    assert(Err == Z_STREAM_END);
  }
  if (Debug)
    Print(stderr, "assert(Strm[%zu].avail_in == %u);\n", Idx,
          Strm[Idx].avail_in);
  assert(Strm[Idx].avail_in == 0);
  uInt ActualCompressedSize = CompressedSize - Strm[Idx].avail_out;
  assert(ActualCompressedSize == Strm[Idx].total_out);
  if (Debug)
    Dump(stderr, "ActualCompressed", Compressed, ActualCompressedSize);
  Err = deflateEnd(&Strm[Idx]);
  if (Debug)
    Print(stderr, "assert(deflateEnd(&Strm[%zu]) == %s);\n", Idx, ErrStr(Err));
  assert(Err == Z_OK);
  if (Strategy == Z_DEFAULT_STRATEGY && GetDictSize(PE) == 0 &&
      DeflateOpCount == 0 && FinishOpCount == 0) {
    if (Debug)
      Print(stderr, "assert(Bound >= %u);\n", ActualCompressedSize);
    assert((unsigned long)Bound >= (unsigned long)ActualCompressedSize);
  }

  ExecutePlanInflate(PE, Compressed, ActualCompressedSize, true);

  size_t BitFlipCount = GetBitFlipCount(PE);
  if (Debug)
    Print(stderr, "/* n_bit_flips == %zu; */\n", BitFlipCount);
  for (size_t i = 0; i < BitFlipCount; i++, NextBitFlip(PE)) {
    int bit_index = GetBitFlip(PE) % (ActualCompressedSize * 8);
    int byte_index = bit_index / 8;
    int mask = 1 << (bit_index % 8);
    Compressed[byte_index] ^= mask;
    if (Debug)
      Print(stderr, "Compressed[%d] ^= 0x%02x;\n", byte_index, mask);
  }
  ExecutePlanInflate(PE, Compressed, ActualCompressedSize, false);
  free(Compressed);
  if (Debug) {
    Indent--;
    Print(stderr, "}\n");
  }
}

/* Entry points. */

#ifdef USE_LIBPROTOBUF_MUTATOR
DEFINE_PROTO_FUZZER(const PbPlan &Plan) {
  struct PlanExecution PE;
  PlanExecutionInit(&PE, &Plan);
  ExecutePlan(&PE);
}
#else
EXTERN_C int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  struct PlanExecution PE;
  PlanExecutionInit(&PE, Data, Size);
  ExecutePlan(&PE);
  return 0;
}
#endif
