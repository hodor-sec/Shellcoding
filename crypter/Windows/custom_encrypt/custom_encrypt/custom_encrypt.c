#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <conio.h> 

#define MAX_RETRIES 16
#define AES_KEY_SIZE 32  // 256 bits for AES-256
#define AES_BLOCK_SIZE 16

/* Output encrypted and decrypted */
void print_data(const char* title, const void* data, int len, int is_oneliner, unsigned char* badChars, int badCharsLen);

/* Read contents of a file as argument */
char* readFile(const char* filename, int* fileSize);

/* Check if any bad character is in the encrypted data */
int contains_bad_characters(const unsigned char* data, int len, unsigned char* badChars, int badCharsLen);

/* Secure password input for Windows */
unsigned char* secure_getpass(const char* prompt);

/* Print Help Message */
void print_help(const char* prog_name);

int main(int argc, char** argv)
{
    // If no arguments are provided, print the help message and exit
    if (argc < 2) {
        print_help(argv[0]);
        return 0;
    }

    // Variables
    int lenBits = AES_KEY_SIZE * 8;  // AES-256 (256 bits)
    char* shell_in;     // Entered input
    int lenShell;       // Length of shellcode
    unsigned char* badChars = NULL;
    int badCharsLen = 0;

    // Process -b argument for bad characters
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            // Parse bad characters from the argument
            size_t len = strlen(argv[i + 1]);
            badCharsLen = len / 4;  // Each bad byte is specified as \xNN (4 chars)
            badChars = malloc(badCharsLen);
            for (int j = 0; j < badCharsLen; j++) {
                // Update to use sscanf_s instead of sscanf
                sscanf_s(argv[i + 1] + j * 4 + 2, "%2hhx", &badChars[j], (unsigned)_countof(badChars));  // Skipping "\x"
            }
            break;
        }
    }

    // Read shellcode from file
    if (!(shell_in = readFile(argv[1], &lenShell))) {
        printf("Unable to read given file, does it exist?\n\n");
        exit(-1);
    }

    // Password input using secure_getpass (Windows alternative to getpass)
    unsigned char* key = secure_getpass("Enter password to encrypt: ");
    int lenKey = strlen((char*)key);

    // Cryptographic context and key handle
    HCRYPTPROV hCryptProv = 0;
    HCRYPTKEY hKey = 0;

    // Acquire a cryptographic context
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) == 0) {
        printf("Error during CryptAcquireContext: %lu\n", GetLastError());
        exit(-1);  // Exit if we cannot acquire context
    }

    // Generate AES key (AES-256)
    if (CryptGenKey(hCryptProv, CALG_AES_256, CRYPT_EXPORTABLE, &hKey) == 0) {
        printf("Error during CryptGenKey: %lu\n", GetLastError());
        exit(-1);  // Exit if key generation fails
    }

    // Buffers for encryption
    DWORD dwDataLen = lenShell;  // Length of data to encrypt
    BYTE* encryptedData = malloc(dwDataLen + AES_BLOCK_SIZE);  // Ensure extra space for padding
    memset(encryptedData, 0, dwDataLen + AES_BLOCK_SIZE);  // Clear memory before use

    // Generate a random IV
    BYTE iv[AES_BLOCK_SIZE];
    if (CryptGenRandom(hCryptProv, AES_BLOCK_SIZE, iv) == 0) {
        printf("Error during IV generation: %lu\n", GetLastError());
        exit(-1);
    }

    // Generate a random salt
    BYTE salt[16];
    if (CryptGenRandom(hCryptProv, sizeof(salt), salt) == 0) {
        printf("Error during salt generation: %lu\n", GetLastError());
        exit(-1);
    }

    // Perform encryption
    if (CryptEncrypt(hKey, 0, TRUE, 0, encryptedData, &dwDataLen, dwDataLen + AES_BLOCK_SIZE) == 0) {
        printf("Error during encryption: %lu\n", GetLastError());
        exit(-1);  // Exit if encryption fails
    }

    // Output encrypted data
    print_data("\nENCRYPTED", encryptedData, dwDataLen, 1, badChars, badCharsLen);

    // Print shellcode length
    printf("\nShellcode length:\n");
    printf("%d", lenShell);
    printf("\n");

    // Print IV, salt, and password in \x format
    printf("\nIV used for encryption:\n");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("\\x%02X", iv[i]);
    }
    printf("\n");

    printf("\nSalt used for encryption:\n");
    for (int i = 0; i < sizeof(salt); i++) {
        printf("\\x%02X", salt[i]);
    }
    printf("\n");

    printf("\nPassword used for encryption:\n");
    for (int i = 0; i < lenKey; i++) {
        printf("\\x%02X", key[i]);
    }
    printf("\n");

    // Clean up sensitive information
    memset(key, 0, lenKey);  // Clear the key after use
    free(encryptedData);
    free(badChars);
    CryptDestroyKey(hKey);
    CryptReleaseContext(hCryptProv, 0);

    return 0;
}

char* readFile(const char* fileName, int* fileSize) {
    FILE* file = fopen(fileName, "rb");
    if (!file) {
        perror("Error opening file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* data = malloc(size + 1);
    if (!data) {
        perror("malloc failed");
        fclose(file);
        return NULL;
    }

    size_t readSize = fread(data, 1, size, file);
    if (readSize != size) {
        perror("Error reading file");
        free(data);
        fclose(file);
        return NULL;
    }

    data[size] = '\0';
    *fileSize = size;
    fclose(file);
    return data;
}

int contains_bad_characters(const unsigned char* data, int len, unsigned char* badChars, int badCharsLen) {
    if (badChars == NULL || badCharsLen == 0) {
        return 0;  // No bad characters to check
    }

    for (int i = 0; i < len; i++) {
        for (int j = 0; j < badCharsLen; j++) {
            if (data[i] == badChars[j]) {
                return 1;  // Bad character found
            }
        }
    }

    return 0;  // No bad characters found
}

void print_data(const char* title, const void* data, int len, int is_oneliner, unsigned char* badChars, int badCharsLen)
{
    printf("%s:\n", title);
    unsigned char* p = (unsigned char*)data;

    if (is_oneliner) {
        printf("\"");
        for (int i = 0; i < len; i++) {
            int isBadChar = 0;
            for (int j = 0; j < badCharsLen; j++) {
                if (p[i] == badChars[j]) {
                    isBadChar = 1;
                    break;
                }
            }
            if (isBadChar) {
                printf("\033[31m\\x%02X\033[0m", p[i]);  // Red color for bad char
            }
            else {
                printf("\\x%02X", p[i]);
            }
        }
        printf("\"\n");
    }
    else {
        printf("  ");
        for (int i = 0; i < len; i++) {
            int isBadChar = 0;
            for (int j = 0; j < badCharsLen; j++) {
                if (p[i] == badChars[j]) {
                    isBadChar = 1;
                    break;
                }
            }
            if (isBadChar) {
                printf("\033[31m\\x%02X\033[0m", p[i]);  // Red color for bad char
            }
            else {
                printf("\\x%02X", p[i]);
            }
        }
        printf("\n");
    }
}

unsigned char* secure_getpass(const char* prompt) {
    printf("%s", prompt);

    unsigned char* pass = malloc(128);
    int i = 0;

    while (1) {
        char ch = _getch();
        if (ch == '\r' || ch == '\n') {
            pass[i] = '\0';  // Null terminate the string
            break;
        }
        else if (ch == '\b' && i > 0) {
            i--;
            printf("\b \b");  // Remove last character
        }
        else {
            pass[i++] = ch;
            printf("*");  // Display '*' for each typed character
        }
    }

    printf("\n");
    return pass;
}

void print_help(const char* prog_name) {
    printf("Usage: %s <shellcode_file> [-b \"<bad_characters>\"]\n", prog_name);
    printf("\nArguments:\n");
    printf("  <shellcode_file>    The path to the file containing the shellcode to be encrypted.\n");
    printf("  -b \"<bad_characters>\"    (Optional) A list of bad characters that should not appear in the encrypted data.\n");
    printf("\nExamples:\n");
    printf("  %s shellcode.bin\n", prog_name);
    printf("  %s shellcode.bin -b \"\\x00\\x01\\x02\"\n", prog_name);
    printf("\nThis program will encrypt the shellcode in the given file with AES-256 using a password.\n");
}
