#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	char buf[128];		// buf == ebp - 0x88
	char input[2048];
	printf("%p\n", buf);
	printf("%p\n", input);

	if (!fgets(input, sizeof(input), stdin))
		return -1;

	strcpy(buf, input);
}
