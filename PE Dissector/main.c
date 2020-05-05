#include <stdio.h>
#include <Windows.h>

BOOL isFileExecutable(LPCTSTR file);

LPTSTR fileName;
LPTSTR fileTitle;
HANDLE hFile;

int main(int argc, char* argv[])
{
	fileName = (LPTSTR)malloc(sizeof(TCHAR) * MAX_PATH);
	memset(fileName, 0, MAX_PATH);
	fileTitle = (LPTSTR)malloc(sizeof(TCHAR) * MAX_PATH);
	memset(fileTitle, 0, MAX_PATH);

	if (argc > 2)
	{
		printf("USAGE: %s <filename>\n", argv[0]);
		return EXIT_FAILURE;
	}
	else if (argc == 1)
	{
		OPENFILENAME openFileName;
		memset(&openFileName, 0, sizeof(OPENFILENAME));
		openFileName.lStructSize = sizeof(OPENFILENAME);
		openFileName.hwndOwner = NULL;
		openFileName.hInstance = NULL;
		openFileName.lpstrFilter = "All files (*.*)\0*.*\0All PE files (.exe;.dll;.sys;.drv;.ocx;.cpl;.scr)\0*.exe;*.dll;*.sys;*.drv;*.ocx;*.cpl;*.scr\0Exe files (.exe)\0*.exe\0Dll files (.dll)\0*.dll\0System files (.sys;.drv)\0*.sys;*.drv\0ActiveX control files (.ocx)\0*.ocx\0Control panel files (.cpl)\0*.cpl\0Screensaver files(.scr)\0*.scr\0\0";
		openFileName.lpstrCustomFilter = NULL;
		openFileName.nMaxCustFilter = NULL;
		openFileName.nFilterIndex = 2;
		openFileName.lpstrFile = fileName;
		openFileName.nMaxFile = MAX_PATH;
		openFileName.lpstrFileTitle = fileTitle;
		openFileName.nMaxFileTitle = MAX_PATH;
		openFileName.lpstrInitialDir = NULL;

		if (!GetOpenFileName(&openFileName))
		{
			printf("No file specified. Closing...\n");
			return EXIT_FAILURE;
		}
		printf("%s\n", fileName);

		hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			printf("Error while openning file : %s\nClosing...\n", fileName);
			return EXIT_FAILURE;
		}
	}
	else if (argc == 2)
	{
		if (strlen(argv[1]) >= MAX_PATH)
		{
			printf("Error : filename in argument 1 is too long (max 259 characters).\n");
			return EXIT_FAILURE;
		}

		strcpy_s(fileName, strlen(argv[1])+1, argv[1]);
		hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			printf("Error while openning file : %s\nClosing...\n", fileName);
			system("PAUSE");
			return EXIT_FAILURE;
		}
		if (GetFileTitle(fileName, fileTitle, MAX_PATH))
		{
			printf("Error while getting file title from : %s\nClosing...\n", fileName);
			return EXIT_FAILURE;
		}
	}
	if (!isFileExecutable(hFile))
	{
		printf("Error : %s is not an executable module.\nClosing...\n", fileTitle);
		return EXIT_FAILURE;
	}
	printf("Successfully opened the file : %s\n", fileTitle);


	free(fileName);
	free(fileTitle);
	system("PAUSE");
	return EXIT_SUCCESS;
}

BOOL isFileExecutable(HANDLE file)
{
	WORD magicNumber = 0;
	DWORD numberOfBytesRead = 0;
	if (!ReadFile(file, &magicNumber, 2, &numberOfBytesRead, NULL))
	{
		printf("Error while getting magic number from : %s\nClosing...\n", fileName);
		return EXIT_FAILURE;
	}
	return magicNumber == 0x5A4D && numberOfBytesRead == 2;
}