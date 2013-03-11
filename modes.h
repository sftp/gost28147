#include "gost28147.h"

void ecb_crypt(u32 *buff, u64 size, struct gost_ctx_t *ctx)
{
	u64 i;

	u64 subblocks = size / 4;

	if (ctx->encrypt) {
		for (i = 0; i < subblocks; i += 2)
			encrypt_block(&(buff[i+1]), &(buff[i]), ctx);
	} else {
		for (i = 0; i < subblocks; i += 2)
			decrypt_block(&(buff[i+1]), &(buff[i]), ctx);
	}
}

void init_gamma(u32 *n1, u32 *n2, struct gost_ctx_t *ctx)
{
	encrypt_block(n2, n1, ctx);
}

void gen_gamma(u32 *n1, u32 *n2, u32 *n3, u32 *n4, struct gost_ctx_t *ctx)
{
	*n4 = *n4 + C1;
	*n3 = ((u64) *n3 + C2) % 0xffffffff;

	*n1 = *n3;
	*n2 = *n4;

	encrypt_block(n2, n1, ctx);
}

void cnt_crypt(u32 *buff, u64 size, u32 *n1, u32 *n2, u32 *n3, u32 *n4,
               struct gost_ctx_t *ctx)
{
	u64 i;

	u64 subblocks = (size + size % 8) / 4;

	for (i = 0; i < subblocks; i += 2) {
		gen_gamma(n1, n2, n3, n4, ctx);

		buff[i]   ^= *n1;
		buff[i+1] ^= *n2;
	}
}

void cfb_crypt(u32 *buff, u64 size, u32 *n1, u32 *n2, struct gost_ctx_t *ctx)
{
	u64 i;

	u64 subblocks = (size + size % 8) / 4;

	if (ctx->encrypt) {
		for (i = 0; i < subblocks; i += 2) {
			init_gamma(n1, n2, ctx);

			buff[i]   ^= *n1;
			buff[i+1] ^= *n2;
			
			*n1 = buff[i];
			*n2 = buff[i+1];
		}
	} else {
		for (i = 0; i < subblocks; i += 2) {
			init_gamma(n1, n2, ctx);

			buff[i]   ^= *n1;
			buff[i+1] ^= *n2;

			*n1 ^= buff[i];
			*n2 ^= buff[i+1];
		}
	}
}
