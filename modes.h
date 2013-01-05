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
