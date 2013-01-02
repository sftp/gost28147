#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/*
 * RFC 4357 section 11.2
 */
static const u8 sbox[8][16] = {
	{  4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3 },
	{ 14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9 },
	{  5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11 },
	{  7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3 },
	{  6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2 },
	{  4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14 },
	{ 13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12 },
	{  1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12 }
};

static u8 sbox_x[4][256];

void init_sbox_x(void)
{
	u8 i;
	u8 j;
	u16 k;

	for (i = 0, j = 0; i < 4; i++, j += 2) {
		for (k = 0; k < 256; k++) {
			sbox_x[i][k] = sbox[j][k & 0x0f] | sbox[j+1][k>>4] << 4;
		}
	}
}

u32 f(u32 word)
{
	word = (word & 0x00ffffff) | (sbox_x[3][word >> 24] << 24);
	word = (word & 0xff00ffff) | (sbox_x[2][(word & 0x00ff0000) >> 16] << 16);
	word = (word & 0xffff00ff) | (sbox_x[1][(word & 0x0000ff00) >>  8] <<  8);
	word = (word & 0xffffff00) | (sbox_x[0][(word & 0x000000ff)]);

	return word << 11 | word >> (32-11);
}

void swap32(u32 *a, u32 *b)
{
	u32 tmp = *a;

	*a = *b;
	*b = tmp;
}

void encrypt_block(u32 *l, u32 *r, u32 *key)
{
	u8 i;

	for (i = 0; i < 23; i += 2) {
		*l ^= f(*r + key[i % 8]);
		*r ^= f(*l + key[(i+1) % 8]);
	}

	for (i = 24; i < 31; i += 2) {
		*l ^= f(*r + key[31-i]);
		*r ^= f(*l + key[31-(i+1)]);
	}

	swap32(l, r);
}

void decrypt_block(u32 *l, u32 *r, u32 *key)
{
	u8 i;

	for (i = 0; i < 7; i += 2) {
		*l ^= f(*r + key[i]);
		*r ^= f(*l + key[i+1]);
	}

	for (i = 8; i < 31; i += 2) {
		*l ^= f(*r + key[(31-i) % 8]);
		*r ^= f(*l + key[(31-(i+1)) % 8]);
	}

	swap32(l, r);
}
