#include "gost28147.h"

void ecb_crypt(u32 *buff, u64 size, u32 *key, u8 encrypt)
{
	u64 i;

	u64 subblocks = size / 4;

	if (encrypt) {
		for (i = 0; i < subblocks; i += 2)
			encrypt_block(&(buff[i+1]), &(buff[i]), key);
	} else {
		for (i = 0; i < subblocks; i += 2)
			decrypt_block(&(buff[i+1]), &(buff[i]), key);
	}
}

void init_gamma(u32 *n1, u32 *n2, u32 *n3, u32 *n4, u32 *key)
{
	encrypt_block(n2, n1, key);

	*n3 = *n1;
	*n4 = *n2;
}

void gen_gamma(u32 *n1, u32 *n2, u32 *n3, u32 *n4, u32 *key)
{
	*n4 = *n4 + C1;
	*n3 = (*n3 + C2 - 1) % 0xffffffff + 1;

	*n1 = *n3;
	*n2 = *n4;

	encrypt_block(n2, n1, key);
}

void cnt_crypt(u32 *buff, u64 size, u32 *n1, u32 *n2, u32 *n3, u32 *n4,
               u32 *key)
{
	u64 i;

	u64 subblocks = size / 4;

	u8 rem = size % 8;

	printf("size=%lu, subblocks_bytes=%lu, rem=%d\n", size, subblocks*4, rem);

	for (i = 0; i < subblocks; i += 2) {
		gen_gamma(n1, n2, n3, n4, key);

		buff[i]   = *n1 ^ buff[i];
		buff[i+1] = *n2 ^ buff[i+1];
	}

	if (rem > 4) {
		gen_gamma(n1, n2, n3, n4, key);

		buff[i]   = *n1 ^ buff[i];
		buff[i+1] = (*n2 & ~(0xffffff00<<((rem-1)*8))) ^ buff[i+1];
	}

	if (rem > 0) {
		gen_gamma(n1, n2, n3, n4, key);

		buff[i]   = (*n1 & ~(0xffffff00<<((rem-1)*8))) ^ buff[i];
		buff[i+1] = 0;
	}	
}
