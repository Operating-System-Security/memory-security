#include <stdio.h>
#include <string.h>
#include <err.h>
#include <stdlib.h>

int main()
{
	char buf[2048];
	int len = 0;
	if (!fgets(buf, sizeof(buf), stdin))
		err(1, "Too long input");

	// a few info for debugging
	while (buf[len++] != '\n');
	printf("> shellcode length: %d\n", len);
	printf("> shellcode content:\n");
	for (int i = 0; i < len; i += 1) {
		if (i % 16 == 0)
			printf("\t%04X: ", i);
		printf("%02X ", (unsigned char)buf[i]);
		if (i % 16 == 15)
			printf("\n");
	}
	printf("\n");

	(*(void (*)()) buf)();
}
