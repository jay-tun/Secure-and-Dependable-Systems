#include <stdint.h>
#include <stddef.h>


static int memcmp(void *s1, const void *s2, size_t n)
{
	unsigned char *a = (unsigned char *) s1;
	unsigned char *b = (unsigned char *) s2;
	
	for (int i = 0; i < n; i++) {
		if (a[i] < b[i]) {
			return -1;
		}

		if (a[i] > b[i]) {
			return 1;
		}
	}
	return 0;
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *msg = "FUZZ";
	(void) memcmp(msg, data, size);
	return 0;
}

