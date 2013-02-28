#include "modes.h"

#define BUFF_SIZE (8*1024)

void ecb_crypt_file(FILE *src, FILE *dst, u32 *key, u64 size, u8 encrypt)
{
	u32 *buffer = malloc(BUFF_SIZE);

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

void cnt_crypt_file(FILE *src, FILE *dst, u32 *key, u64 *iv, u64 size)
{
	u32 *buffer = malloc(BUFF_SIZE);

	u32 n1 = (u32) *iv;
	u32 n2 = (u32) (*iv >> 32);
	u32 n3 = 0;
	u32 n4 = 0;

	init_gamma(&n1, &n2, key);

	n3 = n1;
	n4 = n2;

	while (size) {
		if (size > BUFF_SIZE) {
			fread(buffer, 1, BUFF_SIZE, src);
			cnt_crypt(buffer, BUFF_SIZE, &n1, &n2, &n3, &n4, key);
			fwrite(buffer, 1, BUFF_SIZE, dst);

			size -= BUFF_SIZE;
		} else {
			fread(buffer, 1, size, src);
			cnt_crypt(buffer, size, &n1, &n2, &n3, &n4, key);
			fwrite(buffer, 1, size, dst);

			size = 0;
		}
	}
}

void cfb_crypt_file(FILE *src, FILE *dst, u32 *key, u64 *iv, u64 size, u8 encrypt)
{
	u32 *buffer = malloc(BUFF_SIZE);

	u32 n1 = (u32) *iv;
	u32 n2 = (u32) (*iv >> 32);

	while (size) {
		if (size > BUFF_SIZE) {
			fread(buffer, 1, BUFF_SIZE, src);
			cfb_crypt(buffer, BUFF_SIZE, &n1, &n2, key, encrypt);
			fwrite(buffer, 1, BUFF_SIZE, dst);

			size -= BUFF_SIZE;
		} else {
			fread(buffer, 1, size, src);
			cfb_crypt(buffer, size, &n1, &n2, key, encrypt);
			fwrite(buffer, 1, size, dst);

			size = 0;
		}
	}
}
