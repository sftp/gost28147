#include <unistd.h>

#include "modes.h"

void help(void) {
	printf("Usage: gost28147 -k /path/to/key [-d|-e] /path/to/srcfile -o /path/to/outfile\n");
}

struct args_t {

	u8 help;

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
	args.key     = 0;
	args.keypath = NULL;
	args.encrypt = 0;
	args.decrypt = 0;
	args.srcpath = NULL;
	args.out     = 0;
	args.outpath = NULL;

	u32 opt;

	while ((opt = getopt(argc,argv, "k:d:e:o:")) != -1) {
		switch (opt)
		{
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

	if(args.key && (args.encrypt != args.decrypt) && args.out && !args.help) {
		return;
	} else {
		help();
		exit(0);
	}

}

int test_file(FILE *f, const char *path){

	if (!f) {
		printf("No such file: %s\n", path);
		exit(-1);
	}

	u32 size;

	fseek(f, 0, SEEK_END);

	size = ftell(f);

	fseek(f, 0, SEEK_SET);

	return size;
}


int main (int argc, char *argv[])
{
	parse_args(argc, argv);

	u32 l;
	u32 r;

	u32 key[8];

	FILE *k_fd = fopen(args.keypath, "r");

	if(test_file(k_fd, args.keypath) != 32) {
		printf("Key size must be 32 bytes\n");
		return -1;
	}

	u8 i;

	for(i = 0; i < 8; i++)
		fread(&key[i], 4, 1, k_fd);

	fclose(k_fd);

	FILE *s_fd = fopen(args.srcpath, "r");

	u32 srclen = test_file(s_fd, args.srcpath);

	if(srclen == 0) {
		printf("Nothing to do, file %s is empty\n", args.srcpath);
		fclose(s_fd);
		return -1;
	}

	FILE *o_fd = fopen(args.outpath, "w");

	ecb_crypt(s_fd, o_fd, key, srclen, (u8) args.encrypt);

	fclose(s_fd);
	fclose(o_fd);

	return 0;
}
