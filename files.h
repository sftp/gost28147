#include "modes.h"

#define BUFF_SIZE (8*1024)

void ecb_crypt_file(FILE *src, FILE *dst, struct gost_ctx_t *ctx, u64 size)
{
	u32 *buffer = malloc(BUFF_SIZE);

	while (size) {
		if (size > BUFF_SIZE) {
			fread(buffer, 1, BUFF_SIZE, src);
			ecb_crypt(buffer, BUFF_SIZE, ctx);
			fwrite(buffer, 1, BUFF_SIZE, dst);

			size -= BUFF_SIZE;
		} else {
			fread(buffer, 1, size, src);
			ecb_crypt(buffer, size, ctx);
			fwrite(buffer, 1, size, dst);

			size = 0;
		}
	}
}

void cnt_crypt_file(FILE *src, FILE *dst, struct gost_ctx_t *ctx, u64 size)
{
	u32 *buffer = malloc(BUFF_SIZE);

	u32 n1 = ctx->iv[0];
	u32 n2 = ctx->iv[1];
	u32 n3 = 0;
	u32 n4 = 0;

	init_gamma(&n1, &n2, ctx);

	n3 = n1;
	n4 = n2;

	while (size) {
		if (size > BUFF_SIZE) {
			fread(buffer, 1, BUFF_SIZE, src);
			cnt_crypt(buffer, BUFF_SIZE, &n1, &n2, &n3, &n4, ctx);
			fwrite(buffer, 1, BUFF_SIZE, dst);

			size -= BUFF_SIZE;
		} else {
			fread(buffer, 1, size, src);
			cnt_crypt(buffer, size, &n1, &n2, &n3, &n4, ctx);
			fwrite(buffer, 1, size, dst);

			size = 0;
		}
	}
}

void cfb_crypt_file(FILE *src, FILE *dst, struct gost_ctx_t *ctx, u64 size)
{
	u32 *buffer = malloc(BUFF_SIZE);

	u32 n1 = ctx->iv[0];
	u32 n2 = ctx->iv[1];

	while (size) {
		if (size > BUFF_SIZE) {
			fread(buffer, 1, BUFF_SIZE, src);
			cfb_crypt(buffer, BUFF_SIZE, &n1, &n2, ctx);
			fwrite(buffer, 1, BUFF_SIZE, dst);

			size -= BUFF_SIZE;
		} else {
			fread(buffer, 1, size, src);
			cfb_crypt(buffer, size, &n1, &n2, ctx);
			fwrite(buffer, 1, size, dst);

			size = 0;
		}
	}
}
