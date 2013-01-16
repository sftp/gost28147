#include <unistd.h>
#include <string.h>

#include "files.h"

void help(void) {
	printf("Usage: gost28147 [-m mode] -k /path/to/key [-d|-e] /path/to/srcfile -o /path/to/outfile\n");
}

struct args_t {
	u8 help;

	u8 mode;

	u8 key;
	const char *keypath;

	u8 encrypt;
	u8 decrypt;
	const char *srcpath;

	u8 out;
	const char *outpath;
} args;

void parse_args(int argc, char *argv[])
{
	args.help    = 0;
	args.mode    = 0;
	args.key     = 0;
	args.keypath = NULL;
	args.encrypt = 0;
	args.decrypt = 0;
	args.srcpath = NULL;
	args.out     = 0;
	args.outpath = NULL;

	int opt;

	while ((opt = getopt(argc,argv, "m:k:d:e:o:")) != -1) {
		switch (opt) {
		case 'm':
			if (strcmp(optarg, "ecb") == 0) {
				args.mode = 0;
			} else if (strcmp(optarg, "cnt") == 0) {
				args.mode = 1;
			} else {
				printf("No such mode: %s\n", optarg);
				exit(-1);
			}
			break;

		case 'k':
			args.key = 1;
			args.keypath = optarg;
			break;

		case 'e':
			args.encrypt = 1;
			args.srcpath = optarg;
			break;

		case 'd':
			args.decrypt = 1;
			args.srcpath = optarg;
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

	if (args.key && (args.encrypt != args.decrypt) && args.out && !args.help) {
		return;
	} else {
		help();
		exit(0);
	}

}

u64 test_file(FILE *f)
{
	u64 size;

	fseek(f, 0, SEEK_END);

	size = ftell(f);

	fseek(f, 0, SEEK_SET);

	return size;
}


int main (int argc, char *argv[])
{
	parse_args(argc, argv);

	u32 key[8];

	FILE *k_fd = fopen(args.keypath, "r");

	if (test_file(k_fd) != 32) {
		printf("Key size must be 32 bytes\n");
		return -1;
	}

	u8 i;

	for (i = 0; i < 8; i++)
		fread(&key[i], 4, 1, k_fd);

	fclose(k_fd);

	FILE *s_fd = fopen(args.srcpath, "r");

	if (!s_fd) {
		printf("No such file: %s\n", args.srcpath);
		return -1;
	}

	u64 srclen = test_file(s_fd);

	if (srclen == 0) {
		printf("Nothing to do, file %s is empty\n", args.srcpath);
		fclose(s_fd);
		return -1;
	}

	if (args.mode == 0 && srclen % 8 != 0) {
		printf("In ECB mode source file size should be multiple of 8\n");
		return -1;
	}

	FILE *o_fd = fopen(args.outpath, "w");

	init_sbox_x();

	switch (args.mode) {
	case 1:
		cnt_crypt_file(s_fd, o_fd, key, srclen);
		break;
	case 0:
		ecb_crypt_file(s_fd, o_fd, key, srclen, (u8) args.encrypt);
		break;
	}

	fclose(s_fd);
	fclose(o_fd);

	return 0;
}
