#include <stdio.h>
#include <Windows.h>
#include <winnt.h>

typedef struct _PE_HEADERS32
{
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS32 ntHeaders;
	IMAGE_SECTION_HEADER* sectionHeader;
	IMAGE_EXPORT_DIRECTORY exportDirectory;
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor;
	IMAGE_RESOURCE_DIRECTORY ressourceDirectory;
	IMAGE_DEBUG_DIRECTORY debugDirectory;
	IMAGE_TLS_DIRECTORY32 tlsDirectory;
	//IMAGE_DELAY_IMPORT_DESCRIPTOR
} PE_HEADERS32, *PPE_HEADERS32;

typedef struct _PE_HEADERS64
{
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS64 ntHeaders;
	IMAGE_EXPORT_DIRECTORY exportDirectory;
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor;
	IMAGE_RESOURCE_DIRECTORY ressourceDirectory;
	IMAGE_DEBUG_DIRECTORY debugDirectory;
	IMAGE_TLS_DIRECTORY64 tlsDirectory;
} PE_HEADERS64, *PPE_HEADERS64;

BOOL isFileExecutable(HANDLE file);
BOOL readPEHeaders32(HANDLE file, PPE_HEADERS32 peHeader32);

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

	PE_HEADERS32 peHeader32;
	if (!readPEHeaders32(hFile, &peHeader32))
	{
		printf("Error while reading pe headers.\nClosing...\n");
		return EXIT_FAILURE;
	}
	
	printf("TimeDateStamp : %x\n", peHeader32.ntHeaders.FileHeader.TimeDateStamp);

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

BOOL readPEHeaders32(HANDLE file, PPE_HEADERS32 peHeader32)
{
	DWORD numberOfBytesRead = 0;
	SetFilePointer(hFile, NULL, NULL, FILE_BEGIN);
	if (!ReadFile(hFile, &peHeader32->dosHeader, sizeof(IMAGE_DOS_HEADER), &numberOfBytesRead, NULL))
		return FALSE;

	numberOfBytesRead = 0;
	SetFilePointer(hFile, peHeader32->dosHeader.e_lfanew, NULL, FILE_BEGIN);
	if (!ReadFile(hFile, &peHeader32->ntHeaders, sizeof(IMAGE_DOS_HEADER), &numberOfBytesRead, NULL))
		return FALSE;

	// More to come

	return TRUE;
}