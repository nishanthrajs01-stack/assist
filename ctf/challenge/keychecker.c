/*
 * keychecker.c
 *
 * Stage 4 of the CTF challenge.
 * Compiled with: gcc -o keychecker keychecker.c -no-pie -fno-stack-protector
 *
 * The binary accepts a key on stdin and unlocks a secret.
 * The correct key is XOR-obfuscated inside the binary.
 * Use `reverse keychecker` to decompile and recover the key.
 */
#include <stdio.h>
#include <string.h>

/* "w3b_v4ult_k3y" XOR 0x55 */
static const unsigned char ENC_KEY[] = {
    0x22, 0x66, 0x37, 0x0a, 0x23, 0x61, 0x20, 0x39,
    0x21, 0x0a, 0x3e, 0x66, 0x2c, 0x00
};

/* "PORT=9191 PASS=unlocked" XOR 0x55 */
static const unsigned char ENC_MSG[] = {
    0x05, 0x1a, 0x07, 0x01, 0x68, 0x6c, 0x64, 0x6c,
    0x64, 0x75, 0x05, 0x14, 0x06, 0x06, 0x68, 0x20,
    0x3b, 0x39, 0x3a, 0x36, 0x3e, 0x30, 0x31, 0x00
};

#define XOR_BYTE 0x55

void decode_xor(const unsigned char *in, char *out, int len) {
    for (int i = 0; i < len; i++) {
        out[i] = (char)(in[i] ^ XOR_BYTE);
    }
}

int main(void) {
    char input[64] = {0};
    char key[32]   = {0};
    char msg[64]   = {0};

    decode_xor(ENC_KEY, key, sizeof(ENC_KEY) - 1);
    decode_xor(ENC_MSG, msg, sizeof(ENC_MSG) - 1);

    printf("=== Key Checker ===\n");
    printf("Enter the key: ");
    fflush(stdout);

    if (!fgets(input, sizeof(input), stdin)) {
        printf("Error reading input.\n");
        return 1;
    }

    /* strip newline */
    size_t len = strlen(input);
    if (len > 0 && input[len-1] == '\n') input[--len] = '\0';

    if (strcmp(input, key) == 0) {
        printf("\n[+] Access GRANTED!\n");
        printf("[+] %s\n", msg);
        printf("[+] The web service is live. Use webrecon to discover the flag endpoint.\n");
    } else {
        printf("\n[-] Access DENIED. Wrong key.\n");
        printf("[-] Hint: decompile this binary with `reverse keychecker` to recover the key.\n");
        return 1;
    }
    return 0;
}
