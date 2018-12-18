#define AES_KEY_SIZE	16
#define BYTE_SIZE		8

BOOL EncryptionBlockAES(char* key, char* data, int dataSize, char** enc_out);
BOOL DecryptionBlockAES(unsigned char* key, unsigned char* encData, int dataSize, char** outputData);


void SecurFree(char* ptr, int sizePtr);

BOOL SaveSecretKey(char** pSecretAesKey, char* tempPath);
BOOL GetSecretKey(char** pData, char* privKeyPath);