#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;


#define C1 0x1010104
#define C2 0x1010101

struct gost_ctx_t {
	u32  sbox_x[4][256];
	u32  key[8];
	u32  n1;
	u32  n2;
	u32  n3;
	u32  n4;
	u8   encrypt;
};

/*
 * RFC 4357 section 11.2
 */
const u8 sbox[8][16] = {
	{  4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3 },
	{ 14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9 },
	{  5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11 },
	{  7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3 },
	{  6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2 },
	{  4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14 },
	{ 13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12 },
	{  1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12 }
};

void init_sbox_x(const u8 sbox[8][16], u32 sbox_x[4][256])
{
	u8 i;
	u8 j;
	u16 k;

	for (i = 0, j = 0; i < 4; i++, j += 2) {
		for (k = 0; k < 256; k++) {
			sbox_x[i][k] = (sbox[j][k & 0x0f] | sbox[j+1][k>>4] << 4) << (j*4);
			sbox_x[i][k] = sbox_x[i][k] << 11 | sbox_x[i][k] >> (32-11);
		}
	}
}

u32 f(u32 word, struct gost_ctx_t *ctx)
{
	return ctx->sbox_x[3][word >> 24] ^
		ctx->sbox_x[2][(word & 0x00ff0000) >> 16] ^
		ctx->sbox_x[1][(word & 0x0000ff00) >>  8] ^
		ctx->sbox_x[0][(word & 0x000000ff)];
}

void swap32(u32 *a, u32 *b)
{
	u32 tmp = *a;

	*a = *b;
	*b = tmp;
}

void encrypt_block(u32 *l, u32 *r, struct gost_ctx_t *ctx)
{
	u8 i;

	for (i = 0; i < 23; i += 2) {
		*l ^= f(*r + ctx->key[i % 8], ctx);
		*r ^= f(*l + ctx->key[(i+1) % 8], ctx);
	}

	for (i = 24; i < 31; i += 2) {
		*l ^= f(*r + ctx->key[31-i], ctx);
		*r ^= f(*l + ctx->key[31-(i+1)], ctx);
	}

	swap32(l, r);
}

void decrypt_block(u32 *l, u32 *r, struct gost_ctx_t *ctx)
{
	u8 i;

	for (i = 0; i < 7; i += 2) {
		*l ^= f(*r + ctx->key[i], ctx);
		*r ^= f(*l + ctx->key[i+1], ctx);
	}

	for (i = 8; i < 31; i += 2) {
		*l ^= f(*r + ctx->key[(31-i) % 8], ctx);
		*r ^= f(*l + ctx->key[(31-(i+1)) % 8], ctx);
	}

	swap32(l, r);
}
