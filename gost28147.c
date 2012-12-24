#include "gost28147.h"

int main (int argc, char *argv[])
{
	u32 r = 0x87654321;
	u32 l = 0xfedcba98;
	u32 key[8] = {0x33206D54, 0x326C6568, 0x20657369, 0x626E7373,
		      0x79676120, 0x74746769, 0x65686573, 0x733D2C20};

	u8 i;

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
