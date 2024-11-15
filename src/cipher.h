#ifndef _CIPHER_H
#define _CIPHER_H

#define CIPHER_KEY_LEN 16
#define CIPHER_IV_LEN 16

int aes_encrypt(const char* key, const char* in, int in_len, char** out, int* out_len);
int aes_decrypt(const char* key, const char* in, int in_len, char** out, int* out_len);
void pwd2key(char* key, int ken_len, const char* pwd, int pwd_len);

#endif /* CIPHER_H */