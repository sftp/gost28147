#include "gost28147.h"

void ecb_crypt(FILE *src, FILE *dst, u32 *key, int size, u8 encrypt)
{
	if(size % 8 != 0) {
		printf("In ECB mode sourse file size should be multiple of 8\n");
		exit(-1);
	}

	int i;

	u32 blocks = size / 8;

	u32 l;
	u32 r;

	if (encrypt){
		for(i = 0; i < blocks; i++) {
			fread(&r, 4, 1, src);
			fread(&l, 4, 1, src);

			encrypt_block(&l, &r, key);

			fwrite(&r, 4, 1, dst);
			fwrite(&l, 4, 1, dst);
		}
	} else {
		for(i = 0; i < blocks; i++) {
			fread(&r, 4, 1, src);
			fread(&l, 4, 1, src);

			decrypt_block(&l, &r, key);

			fwrite(&r, 4, 1, dst);
			fwrite(&l, 4, 1, dst);
		}
	}
}
