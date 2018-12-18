#include <windows.h>
#include <stdio.h>


#include <openssl/rand.h>
#include <openssl/aes.h> 
#include <openssl/rsa.h>
#include <openssl/pem.h>

#pragma warning(disable:4996)
#include <openssl/applink.c>			// create error => error C4996: '_open'

#include "mgEncryption.h"

unsigned char iv[AES_BLOCK_SIZE] = { 0xCA, 0x6A, 0xD3, 0xCD, 0x8A, 0xCD, 0xCE, 0x7A,  
									 0x14, 0xFD, 0xC0, 0x98, 0x35, 0x85, 0x6C, 0x0F };

BOOL EncryptionBlockAES(char* key, char* data, int dataSize, char** enc_out) { // EncryptionBlockAES
	AES_KEY encKey;

	*enc_out = (char*)calloc(dataSize +1 + 100, 1);
	if (*enc_out != NULL) {
		AES_set_encrypt_key(key, 128, &encKey); //  AES_BLOCK_SIZE * BYTE_SIZE
		AES_cbc_encrypt(data, *enc_out, dataSize, &encKey, iv, AES_ENCRYPT);
		//AES_encrypt(data, *enc_out, &enc_key);
		return TRUE;
	}
	return FALSE;
}
BOOL DecryptionBlockAES(unsigned char* key, unsigned char* encData, int dataSize, char** outputData) {//DecryptionBlockAES
	AES_KEY decKey;
	*outputData = (char*)calloc(dataSize + 1, 1);
	if (*outputData != NULL) {
		AES_set_decrypt_key(key, 128, &decKey); //  AES_BLOCK_SIZE * BYTE_SIZE
		AES_cbc_encrypt(encData, *outputData, dataSize, &decKey, iv, AES_DECRYPT);
		//AES_decrypt(encData, *outputData, &dec_key);
		return TRUE;
	}
	return FALSE;
}












RSA* ReadPrivKeyFromFile(char* filename, char* pass) {
	FILE* pFile;
	RSA *rsaKey = NULL;

	if (fopen_s(&pFile, filename, "r") == 0) {
		rsaKey = PEM_read_RSAPrivateKey(pFile, NULL, NULL, pass);
		fclose(pFile);
	}
	return rsaKey;
}

RSA* ReadPubKeyFromFile(char* filename) {
	FILE* pFile;
	RSA *rsaKey = NULL;

	if (fopen_s(&pFile, filename, "r") == 0) {
		rsaKey = PEM_read_RSAPublicKey(pFile, NULL, NULL, NULL);
		fclose(pFile);
	}
	return rsaKey;
}




int EncryptionRSA(unsigned char* data, int size, unsigned char** dataEncrypted) {
	RSA* evpPubKey = ReadPubKeyFromFile("PutKey.crt");
	if (evpPubKey == NULL) {
		printf("Fail to open PutKey.crt\n");
		return FALSE;
	}

	char *encryptData = calloc(RSA_size(evpPubKey), 1);
	if (encryptData == NULL)
		return FALSE;
	int encryptLen = RSA_public_encrypt(size + 1, data, encryptData, evpPubKey, RSA_PKCS1_OAEP_PADDING);

	*dataEncrypted = encryptData;
	RSA_free(evpPubKey);
	return encryptLen;
}
int DecryptionRSA(unsigned char* data, int size, unsigned char** dataDecryption, char* privKeyPath) {
	RSA* evpPrivKey = ReadPrivKeyFromFile(privKeyPath, NULL);
	if (evpPrivKey == NULL) {
		printf("Fail to open %s\n", privKeyPath);
		return FALSE;
	}

	char *decryptData = calloc(RSA_size(evpPrivKey), 1);
	if (decryptData == NULL)
		return FALSE;
	int decryptLen = RSA_private_decrypt(size, data, decryptData, evpPrivKey, RSA_PKCS1_OAEP_PADDING);

	*dataDecryption = decryptData;
	RSA_free(evpPrivKey);
	return decryptLen;
}



int GetFileSizeF(FILE* pFile) {
	fseek(pFile, 0L, SEEK_END);
	int sz = ftell(pFile);
	fseek(pFile, 0L, SEEK_SET);
	return sz;
}



BOOL SaveSecretKey(char** pSecretAesKey, char* tempPath) {
	FILE* pFile;
	// tempPath
	char* keyAeaPath = (char*)calloc(MAX_PATH,1);
	if(keyAeaPath != NULL){
		sprintf_s(keyAeaPath, MAX_PATH,"%saes.key", tempPath);
		if (fopen_s(&pFile, keyAeaPath, "wb+") == 0 && pFile != NULL) {
			char* secretAesKey = (char*)calloc(AES_KEY_SIZE, 1);
			if (secretAesKey != NULL) {
				char* dataEncrypted;
				int sizeData;

				RAND_bytes(secretAesKey, AES_KEY_SIZE);

				sizeData = EncryptionRSA(secretAesKey, AES_KEY_SIZE, &dataEncrypted);
				if (sizeData > 0) {
					size_t size = fwrite(dataEncrypted, 1, sizeData, pFile);
					*pSecretAesKey = secretAesKey;
					free(dataEncrypted);
					fclose(pFile);
					free(keyAeaPath);
					return size > 0;
				}
				else if (dataEncrypted != NULL)
					free(dataEncrypted);
				fclose(pFile);
			}
		}
		free(keyAeaPath);
	}
	return FALSE;
}
BOOL GetSecretKey(char** pSecretAesKey, char* privKeyPath) {
	FILE* pFile;
	if (fopen_s(&pFile, "aes.key", "rb") == 0 && pFile != NULL) {
		int fileSize = GetFileSizeF(pFile);
		if (fileSize > 0) {
			char* secretAesKeyEnc = calloc(fileSize + 1, 1);
			if (secretAesKeyEnc != NULL) {
				size_t size = fread(secretAesKeyEnc, 1, fileSize, pFile);
				char* secretAesKey;

				if (DecryptionRSA(secretAesKeyEnc, (int)size, &secretAesKey, privKeyPath) - 1 == AES_KEY_SIZE) {
					*pSecretAesKey = secretAesKey;
					free(secretAesKeyEnc);
					fclose(pFile);
					return TRUE;
				}else if (secretAesKey != NULL)
					free(secretAesKey);

				printf("DecryptionRSA FAIL!\n");

				free(secretAesKeyEnc);
				fclose(pFile);
				return FALSE;
			}
		}
	}else
		printf("Fail to open aes.key\n");
	return FALSE;
}


void SecurFree(char* ptr, int sizePtr) {
	if (ptr != NULL) {
		if (sizePtr > 0) {
			char* rand = (char*)calloc(sizePtr + 1, 1);
			if (rand != NULL) {
				RAND_bytes(rand, sizePtr);
				memcpy(ptr, rand, sizePtr);
				free(rand);
			}
		}
		free(ptr);
	}
}

