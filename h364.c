typedef struct {
	uint64_t low;
	uint32_t high;
} u96;

unsigned char rodata[] = {0x04,0x07,0x01,0x0D,0x15,0x25,0x44,0x06,0x03,0x09,0x1D,0x35,0x64,0x47,0x00,0x0F,0x11,0x2D,0x54,0x26,0x42,0x0A,0x1B,0x39,0x7C,0x77,0x61,0x4D,0x14,0x27,0x40,0x0E,0x13,0x29,0x5C,0x36,0x62,0x4B,0x18,0x3F,0x70,0x6F,0x51,0x2C,0x56,0x22,0x4A,0x1A,0x3B,0x78,0x7F,0x71,0x6D,0x55,0x24,0x46,0x02,0x0B,0x19,0x3D,0x74,0x67,0x41,0x0C,0x17,0x21,0x4C,0x16,0x23,0x48,0x1E,0x33,0x68,0x5F,0x30,0x6E,0x53,0x28,0x5E,0x32,0x6A,0x5B,0x38,0x7E,0x73,0x69,0x5D,0x34,0x66,0x43,0x08,0x1F,0x31,0x6C,0x57,0x20,0x4E,0x12,0x2B,0x58,0x3E,0x72,0x6B,0x59};
unsigned char salt[32];
char prefix[16];

void ROTL(u96* dst, u96* src, char n) {
	if (n > 32) {
		dst->high = src->low >> 32;
		src->low = src->low << 32 | src->high;
		src->high = dst->high;
		n -= 32;
	}
	dst->low = src->low << n | src->high >> (32 - n);
	dst->high = src->high << n | src->low >> (64 - n);
}

u96 AND(u96 X1, u96 X2) {
	u96 X0;
	X0.low = X1.low & X2.low;
	X0.high = X1.high & X2.high;
	return X0;
}

u96 OR(u96* X1, u96* X2) {
	u96 X0;
	X0.low = X1->low | X2->low;
	X0.high = X1->high | X2->high;
	return X0;
}

u96 NOT(u96* X1) {
	u96 X0;
	X0.low = ~X1->low;
	X0.high = ~X1->high;
	return X0;
}

void XOR(u96* X0, u96 X1, u96 X2) {
	X0->low = X1.low ^ X2.low;
	X0->high = X1.high ^ X2.high;
}

//0:X8,1:X10,2:X15,3:X9,4:X12,5:X13
void sponge(u96* array) {
	for (char i = 0; i < 104; i++) {
		array[0].low ^= rodata[i];
		XOR(array + 3, NOT(array + 5), *array);
		XOR(array + 2, OR(array + 1, array + 4), array[3]);
		XOR(array + 4, AND(array[1], NOT(array)), array[4]);
		*array = AND(array[3], array[4]);
		XOR(array + 3, array[1], array[5]);
		XOR(array, *array, array[3]);
		XOR(array + 3, AND(array[2], array[3]), array[4]);
		XOR(array + 4, array[4], array[5]);

		ROTL(array + 5, array + 4, 55);
		ROTL(array + 4, array + 2, 8);
		ROTL(array + 1, array + 3, 1);
	}
}

void hash(unsigned char* output, char* buf, uint8_t len) {
	unsigned char* input = (unsigned char*) buf;
	u96 array[6];
	memset(array, 0, 6 * sizeof(u96));
	uint64_t block;
	uint8_t n = 0;
	while (n + 6 <= len)
	{
		block = *(uint64_t*)(input + n) & 0xFFFFFFFFFFFF;
		array[0].low ^= block;
		sponge(array);
		n += 6;
	}
	block = 0;
	len -= n;
	input += n;
	for (n = 0; n < len; n++)
		block |= (uint64_t) input[n] << 8 * n;
	block |= 4LL << 8 * len;
	array[0].low ^= block;

	sponge(array);
	*(u96*) output = array[0];
	*(u96*)(output + 12) = array[1];
	sponge(array);
	*(u96*)(output + 24) = array[0];
	*(u96*)(output + 36) = array[1];
}

void sign(char *body, char *endpoint) {
	char input[192];
	unsigned char output[104];
	uint64_t timestamp = getTimestamp();
	*(uint64_t*) input = timestamp;
	*(uint64_t*) output = timestamp;

	uint8_t len = 0;
	if (body) {
		len = strlen(body);
		memcpy(input + 8, body, len);
	}
	len += 8;

	memcpy(input + len, salt, 32);
	hash(output + 8, input, len + 32);

    sprintf(input + len, "%s%s", prefix, endpoint);
	len = len + strlen(input + len);
	memcpy(input + len, salt, 32);
	hash(output + 56, input, len + 32);

	EVP_EncodeBlock(endpoint, output, sizeof output);
}

int main() {
	char localPrefix[] = "/";
	strcpy(prefix, localPrefix);
	char localSalt[] = {};
	memcpy(salt, localSalt, 32);
	char endpoint[256];
	strcpy(endpoint, "/sdfh/28/auth/login");
	sign("grant_t", endpoint);
	printf("%s\n", endpoint);
	
}
