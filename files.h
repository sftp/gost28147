#include "modes.h"
#include "mem.h"

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

	wipememory(buffer, BUFF_SIZE);
}

void cnt_crypt_file(FILE *src, FILE *dst, struct gost_ctx_t *ctx, u64 size)
{
	u32 *buffer = malloc(BUFF_SIZE);

	init_gamma(ctx);

	ctx->n3 = ctx->n1;
	ctx->n4 = ctx->n2;

	while (size) {
		if (size > BUFF_SIZE) {
			fread(buffer, 1, BUFF_SIZE, src);
			cnt_crypt(buffer, BUFF_SIZE, ctx);
			fwrite(buffer, 1, BUFF_SIZE, dst);

			size -= BUFF_SIZE;
		} else {
			fread(buffer, 1, size, src);
			cnt_crypt(buffer, size, ctx);
			fwrite(buffer, 1, size, dst);

			size = 0;
		}
	}

	wipememory(buffer, BUFF_SIZE);
}

void cfb_crypt_file(FILE *src, FILE *dst, struct gost_ctx_t *ctx, u64 size)
{
	u32 *buffer = malloc(BUFF_SIZE);

	while (size) {
		if (size > BUFF_SIZE) {
			fread(buffer, 1, BUFF_SIZE, src);
			cfb_crypt(buffer, BUFF_SIZE, ctx);
			fwrite(buffer, 1, BUFF_SIZE, dst);

			size -= BUFF_SIZE;
		} else {
			fread(buffer, 1, size, src);
			cfb_crypt(buffer, size, ctx);
			fwrite(buffer, 1, size, dst);

			size = 0;
		}
	}

	wipememory(buffer, BUFF_SIZE);
}
