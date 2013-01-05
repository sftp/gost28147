#include "modes.h"

#define BUFF_SIZE (8*1024)

void ecb_crypt_file(FILE *src, FILE *dst, u32 *key, u64 size, u8 encrypt)
{
	u32 *buffer = malloc(BUFF_SIZE);

	if (size % 8 != 0) {
		printf("In ECB mode sourse file size should be multiple of 8\n");
		exit(-1);
	}
	
	while (size) {
		if (size > BUFF_SIZE) {
			fread(buffer, 1, BUFF_SIZE, src);
			ecb_crypt(buffer, BUFF_SIZE, key, encrypt);
			fwrite(buffer, 1, BUFF_SIZE, dst);

			size -= BUFF_SIZE;
		} else {
			fread(buffer, 1, size, src);
			ecb_crypt(buffer, size, key, encrypt);
			fwrite(buffer, 1, size, dst);
			
			size = 0;
		}
	}
}

