#include "gost28147.h"

void ecb_crypt(u32 *buff, u64 size, struct gost_ctx_t *ctx)
{
	u64 i;

	u64 subblocks = size / 4;

	if (ctx->encrypt) {
		if (ctx->mac) {
			for (i = 0; i < subblocks; i += 2) {
				ctx->mac_l ^= buff[i+1];
				ctx->mac_r ^= buff[i];
				calc_mac(&ctx->mac_l, &ctx->mac_r, ctx);

				encrypt_block(&(buff[i+1]), &(buff[i]), ctx);
			}
		} else {
			for (i = 0; i < subblocks; i += 2)
				encrypt_block(&(buff[i+1]), &(buff[i]), ctx);
		}
	} else {
		if (ctx->mac) {
			for (i = 0; i < subblocks; i += 2) {
				decrypt_block(&(buff[i+1]), &(buff[i]), ctx);

				ctx->mac_l ^= buff[i+1];
				ctx->mac_r ^= buff[i];
				calc_mac(&ctx->mac_l, &ctx->mac_r, ctx);
			}
		} else {
			for (i = 0; i < subblocks; i += 2)
				decrypt_block(&(buff[i+1]), &(buff[i]), ctx);
		}
	}
}

void init_gamma(struct gost_ctx_t *ctx)
{
	encrypt_block(&ctx->n2, &ctx->n1, ctx);
}

void gen_gamma(struct gost_ctx_t *ctx)
{
	u64 value;

	//
	// GOST 28147-89 (addendum 4.2)
	//
	//   a + b (mod 2^32) ::= { a + b, if (a + b) < 2^32; a + b - 2^32, elsewhere }
	//   a + b (mod 2^32 - 1) ::= { a + b, if (a + b) < 2^32; a + b - 2^32 + 1, elsewhere }
	//

	// ADD C1 (mod 2^32)
	ctx->n4 = (u32)C1 + ctx->n4;

	// ADD C2 (mod 2^32 - 1)
	  value = (u64)C2 + ctx->n3;
	ctx->n3 = (u32)(value + (value >> 32));

	ctx->n1 = ctx->n3;
	ctx->n2 = ctx->n4;

	encrypt_block(&ctx->n2, &ctx->n1, ctx);
}

void cnt_crypt(u32 *buff, u64 size, struct gost_ctx_t *ctx)
{
	u64 i;

	u64 subblocks = size / 4 + !!(size % 4);

	if (ctx->mac) {
		if (ctx->encrypt) {
			for (i = 0; i < subblocks; i += 2) {
				ctx->mac_l ^= buff[i+1];
				ctx->mac_r ^= buff[i];
				calc_mac(&ctx->mac_l, &ctx->mac_r, ctx);

				gen_gamma(ctx);

				buff[i]   ^= ctx->n1;
				buff[i+1] ^= ctx->n2;
			}
		} else {
			for (i = 0; i < subblocks; i += 2) {
				gen_gamma(ctx);

				buff[i]   ^= ctx->n1;
				buff[i+1] ^= ctx->n2;

				ctx->mac_l ^= buff[i+1];
				ctx->mac_r ^= buff[i];
				calc_mac(&ctx->mac_l, &ctx->mac_r, ctx);
			}
		}
	} else {
		for (i = 0; i < subblocks; i += 2) {
			gen_gamma(ctx);

			buff[i]   ^= ctx->n1;
			buff[i+1] ^= ctx->n2;
		}
	}
}

void cfb_crypt(u32 *buff, u64 size, struct gost_ctx_t *ctx)
{
	u64 i;

	u64 subblocks = size / 4 + !!(size % 4);

	if (ctx->encrypt) {
		if (ctx->mac) {
			for (i = 0; i < subblocks; i += 2) {
				ctx->mac_l ^= buff[i+1];
				ctx->mac_r ^= buff[i];
				calc_mac(&ctx->mac_l, &ctx->mac_r, ctx);

				init_gamma(ctx);

				buff[i]   ^= ctx->n1;
				buff[i+1] ^= ctx->n2;

				ctx->n1 = buff[i];
				ctx->n2 = buff[i+1];
			}
		} else {
			for (i = 0; i < subblocks; i += 2) {
				init_gamma(ctx);

				buff[i]   ^= ctx->n1;
				buff[i+1] ^= ctx->n2;

				ctx->n1 = buff[i];
				ctx->n2 = buff[i+1];
			}
		}
	} else {
		if (ctx->mac) {
			for (i = 0; i < subblocks; i += 2) {
				init_gamma(ctx);

				buff[i]   ^= ctx->n1;
				buff[i+1] ^= ctx->n2;

				ctx->n1 ^= buff[i];
				ctx->n2 ^= buff[i+1];

				ctx->mac_l ^= buff[i+1];
				ctx->mac_r ^= buff[i];
				calc_mac(&ctx->mac_l, &ctx->mac_r, ctx);
			}
		} else {
			for (i = 0; i < subblocks; i += 2) {
				init_gamma(ctx);

				buff[i]   ^= ctx->n1;
				buff[i+1] ^= ctx->n2;

				ctx->n1 ^= buff[i];
				ctx->n2 ^= buff[i+1];
			}
		}
	}
}
