#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <error.h>
#include <err.h>

#include "files.h"

static const char *usage = 
	"usage: gost28147 -a [-m mode] -i ivfile -k keyfile -d|-e srcfile -o outfile";

struct args_t {
	u8 help;

	u8 mode;

	u8 key;
	const char *keypath;

	u64 iv;
	const char *ivpath;

	u8 encrypt;
	u8 decrypt;
	const char *srcpath;

	u8 mac;

	u8 out;
	const char *outpath;
} args;

int parse_args(int argc, char *argv[])
{
	args.help    = 0;
	args.mode    = 0;
	args.key     = 0;
	args.keypath = NULL;
	args.iv      = 0;
	args.ivpath  = NULL;
	args.encrypt = 0;
	args.decrypt = 0;
	args.srcpath = NULL;
	args.mac     = 0;
	args.out     = 0;
	args.outpath = NULL;

	int opt;

	while ((opt = getopt(argc,argv, "m:k:i:d:e:ao:")) != -1) {
		switch (opt) {
		case 'm':
			if (strcmp(optarg, "ecb") == 0) {
				args.mode = 0;
			} else if (strcmp(optarg, "cnt") == 0) {
				args.mode = 1;
			} else if (strcmp(optarg, "cfb") == 0) {
				args.mode = 2;
			} else {
				printf("No such mode: %s\n", optarg);
				return 0;
			}
			break;

		case 'k':
			args.key = 1;
			args.keypath = optarg;
			break;

		case 'i':
			args.iv = 1;
			args.ivpath = optarg;
			break;

		case 'e':
			args.encrypt = 1;
			args.srcpath = optarg;
			break;

		case 'd':
			args.decrypt = 1;
			args.srcpath = optarg;
			break;

		case 'a':
			args.mac = 1;
			break;

		case 'o':
			args.out = 1;
			args.outpath = optarg;
			break;

		default:
		case 'h':
		case '?':
			args.help = 1;
			break;
		};
	}

	if (args.key && (args.encrypt != args.decrypt) && args.out && !args.help)
		return 1;
	else
		return 0;
}

u64 test_file(FILE *f)
{
	u64 size;

	fseek(f, 0, SEEK_END);

	size = ftell(f);

	fseek(f, 0, SEEK_SET);

	return size;
}


int main(int argc, char *argv[])
{
	struct gost_ctx_t ctx;

	if (!parse_args(argc, argv))
		errx(EINVAL, "%s", usage);

	if (args.iv) {
		FILE *iv_fd = fopen(args.ivpath, "r");

		if (test_file(iv_fd) != 8) {
			printf("IV size must be 8 bytes\n");
			fclose(iv_fd);

			return -1;
		}

		fread(&ctx.n1, 4, 1, iv_fd);
		fread(&ctx.n2, 4, 1, iv_fd);

		fclose(iv_fd);
	} else {
		ctx.n1 = 0;
		ctx.n2 = 0;
	}

	FILE *s_fd = fopen(args.srcpath, "r");

	if (!s_fd)
		error(errno, errno, "%s", args.srcpath);

	u64 srclen = test_file(s_fd);

	if (srclen == 0) {
		printf("Nothing to do, file %s is empty\n", args.srcpath);
		fclose(s_fd);
		return -1;
	}

	if (args.mode == 0 && srclen % 8 != 0) {
		printf("In ECB mode source file size should be multiple of 8\n");
		fclose(s_fd);
		return -1;
	}

	FILE *o_fd = fopen(args.outpath, "w");

	if (!o_fd)
		error(errno, errno, "%s", args.outpath);

	ctx.encrypt = args.encrypt;
	ctx.mac = args.mac;

	init_sbox_x(sbox, ctx.sbox_x);

	ctx.mac_l = 0;
	ctx.mac_r = 0;

	FILE *k_fd = fopen(args.keypath, "r");

	if (!k_fd)
		error(errno, errno, "%s", args.keypath);

	if (test_file(k_fd) != 32) {
		printf("Key size must be 32 bytes\n");
		fclose(k_fd);
		return -1;
	}

	u8 i;

	for (i = 0; i < 8; i++)
		fread(&ctx.key[i], 4, 1, k_fd);

	fclose(k_fd);


	switch (args.mode) {
	case 2:
		cfb_crypt_file(s_fd, o_fd, &ctx, srclen);
		break;
	case 1:
		cnt_crypt_file(s_fd, o_fd, &ctx, srclen);
		break;
	case 0:
		ecb_crypt_file(s_fd, o_fd, &ctx, srclen);
		break;
	}

	wipememory(ctx.key, KEY_SIZE);

	if (args.mac)
		printf("mac = 0x%08x%08x\n", ctx.mac_l, ctx.mac_r);

	fclose(s_fd);
	fclose(o_fd);

	return 0;
}
