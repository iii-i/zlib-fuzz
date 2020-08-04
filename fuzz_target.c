#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zlib.h"

enum DeflateOpKind {
	DeflateOpDeflate,
	DeflateOpDeflateParams,
};

struct DeflateOp {
	enum DeflateOpKind Kind;
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

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	if (Size == 0)
		return 0;
	size_t DeflateOpCount = *Data + 1;
	Data++;
	Size--;
	struct DeflateOp DeflateOps[DeflateOpCount];
	uInt AvailInDivisor = 0;
	uInt AvailOutDivisor = 0;
	for (size_t i = 0; i < DeflateOpCount; i++) {
		if (Size == 0)
			return 0;
		DeflateOps[i].AvailIn = *Data + 1;
		AvailInDivisor += DeflateOps[i].AvailIn;
		Data++;
		Size--;
		if (Size == 0)
			return 0;
		DeflateOps[i].AvailOut = (*Data >> 3) + 1;
		AvailOutDivisor += DeflateOps[i].AvailOut;
		if ((*Data & 0x7) == 0x7) {
			Data++;
			Size--;
			DeflateOps[i].Kind = DeflateOpDeflateParams;
			if (Size == 0)
				return 0;
			if (*Data < 128) DeflateOps[i].DeflateParams.Level = (*Data % 11) - 1;
			else DeflateOps[i].DeflateParams.Level = Z_BEST_SPEED;
			Data++;
			Size--;
			if (Size == 0)
				return 0;
			if (*Data < 43) DeflateOps[i].DeflateParams.Strategy = Z_FILTERED;
			else if (*Data < 86) DeflateOps[i].DeflateParams.Strategy = Z_HUFFMAN_ONLY;
			else if (*Data < 128) DeflateOps[i].DeflateParams.Strategy = Z_RLE;
			else if (*Data < 196) DeflateOps[i].DeflateParams.Strategy = Z_FIXED;
			else DeflateOps[i].DeflateParams.Strategy = Z_DEFAULT_STRATEGY;
			Data++;
			Size--;
		} else {
			DeflateOps[i].Kind = DeflateOpDeflate;
			switch (*Data & 0x7) {
			case 0: DeflateOps[i].Deflate.Flush = Z_PARTIAL_FLUSH; break;
			case 1: DeflateOps[i].Deflate.Flush = Z_SYNC_FLUSH; break;
			case 2: DeflateOps[i].Deflate.Flush = Z_FULL_FLUSH; break;
			case 3: DeflateOps[i].Deflate.Flush = Z_BLOCK; break;
			default: DeflateOps[i].Deflate.Flush = Z_NO_FLUSH; break;
			}
			Data++;
			Size--;
		}
	}
	if (AvailInDivisor == 0 || AvailOutDivisor == 0)
		return 0;
	size_t CompressedSize = Size * 2 + DeflateOpCount * 128;
	for (size_t i = 0; i < DeflateOpCount; i++) {
		DeflateOps[i].AvailIn = (DeflateOps[i].AvailIn * Size) / AvailInDivisor;
		DeflateOps[i].AvailOut = (DeflateOps[i].AvailOut * Size) / AvailOutDivisor;
	}

	uint8_t *Compressed = malloc(CompressedSize);
	assert(Compressed);
	z_stream Strm;
	memset(&Strm, 0, sizeof(Strm));
	int Err = deflateInit(&Strm, Z_BEST_SPEED);
	assert(Err == Z_OK);
	Strm.next_in = Data;
	Strm.avail_in = Size;
	Strm.next_out = Compressed;
	Strm.avail_out = CompressedSize;
	for (size_t i = 0; i < DeflateOpCount; i++) {
		uInt AvailIn0 = Strm.avail_in;
		uInt AvailIn1 = AvailIn0 < DeflateOps[i].AvailIn ? AvailIn0 : DeflateOps[i].AvailIn;
		if (AvailIn1 == 0)
			continue;
		uInt AvailOut0 = Strm.avail_out;
		uInt AvailOut1 = AvailOut0 < DeflateOps[i].AvailOut ? AvailOut0 : DeflateOps[i].AvailOut;
		if (AvailOut1 == 0)
			continue;
		Strm.avail_in = AvailIn1;
		Strm.avail_out = AvailOut1;
		switch (DeflateOps[i].Kind) {
		case DeflateOpDeflate:
			Err = deflate(&Strm, DeflateOps[i].Deflate.Flush);
			if (Err != Z_OK) {
				fprintf(stderr, "deflate(%i) returned %i\n", DeflateOps[i].Deflate.Flush, Err);
				assert(0);
			}
			break;
		case DeflateOpDeflateParams:
			Err = deflateParams(&Strm, DeflateOps[i].DeflateParams.Level, DeflateOps[i].DeflateParams.Strategy);
			if (Err != Z_OK) {
				fprintf(stderr, "deflateParams(%i, %i) returned %i\n", DeflateOps[i].DeflateParams.Level, DeflateOps[i].DeflateParams.Strategy, Err);
				assert(0);
			}
			break;
		default:
			fprintf(stderr, "Unexpected DeflateOps[%zu/%zu].Kind: %i\n", i, DeflateOpCount, DeflateOps[i].Kind);
			assert(0);
		}
		uInt ConsumedIn = AvailIn1 - Strm.avail_in;
		Strm.avail_in = AvailIn0 - ConsumedIn;
		uInt ConsumedOut = AvailOut1 - Strm.avail_out;
		Strm.avail_out = AvailOut0 - ConsumedOut;
	}
	Err = deflate(&Strm, Z_FINISH);
	assert(Err == Z_STREAM_END);
	assert(Strm.avail_in == 0);
	int ActualCompressedSize = CompressedSize - Strm.avail_out;
	Err = deflateEnd(&Strm);
	assert(Err == Z_OK);

	uint8_t *Uncompressed = malloc(Size);
	assert(Uncompressed);
	Err = inflateInit(&Strm);
	assert(Err == Z_OK);
	Strm.next_in = Compressed;
	Strm.avail_in = ActualCompressedSize;
	Strm.next_out = Uncompressed;
	Strm.avail_out = Size;
	Err = inflate(&Strm, Z_NO_FLUSH);
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
