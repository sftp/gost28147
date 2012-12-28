#include <unistd.h>

#include "gost28147.h"

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

int parse_args(int argc, char *argv[])
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
		return 1;
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

	u32 r = 0x87654321;
	u32 l = 0xfedcba98;

	u32 key[8];

	FILE *f = fopen(args.keypath, "r");

	if(test_file(f, args.keypath) != 32) {
		printf("Key size must be 32 bytes\n");
		return -1;
	}

	u8 i;

	for(i = 0; i < 8; i++)
		fread(&key[i], 4, 1, f);

	fclose(f);

	printf("key = ");
	for (i = 0; i < 8; i++)
		printf("0x%08x ", key[i]);
	putchar('\n');

	printf("l = 0x%08x\t"
	       "r = 0x%08x\n",
	       l, r);

	encrypt_block(&l, &r, key);

	printf("l = 0x%08x\t"
	       "r = 0x%08x\n",
	       l, r);

	decrypt_block(&l, &r, key);

	printf("l = 0x%08x\t"
	       "r = 0x%08x\n",
	       l, r);

	return 0;
}
