#include <stdio.h>
#include <Windows.h>
#include <winnt.h>

#include "PE Dissector.h"

int main(int argc, char* argv[])
{
	LPTSTR fileName;
	LPTSTR fileTitle;
	HANDLE hFile;

	fileName = (LPTSTR)malloc(sizeof(TCHAR) * MAX_PATH);
	memset(fileName, 0, MAX_PATH);
	fileTitle = (LPTSTR)malloc(sizeof(TCHAR) * MAX_PATH);
	memset(fileTitle, 0, MAX_PATH);

	if (argc == 1)
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
	else
	{
		printf("USAGE: %s <filename>\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (!isFileExecutable(hFile))
	{
		printf("Error : %s is not an executable module.\nClosing...\n", fileTitle);
		return EXIT_FAILURE;
	}
	printf("Successfully opened the file : %s\n", fileTitle);

	WORD architecture = getArchitecture(hFile);
	if (architecture != IMAGE_FILE_MACHINE_I386)
	{
		printf("Architecture not supported : 0x%x.\nClosing...\n", architecture);
		return EXIT_FAILURE;
	}

	PE_HEADERS32 peHeader32;
	if (!readPEHeaders32(hFile, &peHeader32))
	{
		printf("Error while parsing pe headers.\nClosing...\n");
		return EXIT_FAILURE;
	}
	
	// Test DOS header
	printf("Magic number : %.2s (0x%x)\n", (LPSTR)&peHeader32.dosHeader.e_magic, peHeader32.dosHeader.e_magic);
	// Test NT headers
	printf("Machine : %i Bits (%s)\n", peHeader32.ntHeaders.OptionalHeader.Magic == 0x010B ? 32 : 64, peHeader32.ntHeaders.OptionalHeader.Magic == 0x010B ? "PE32" : "PE32+");
	printf("TimeDateStamp : 0x%x\n", peHeader32.ntHeaders.FileHeader.TimeDateStamp);
	// Test section headers
	printf("Name of 3rd section : %.8s\n", peHeader32.sectionHeaders[2].Name);
	// Test export directory
	if (peHeader32.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress > 0)
		printf("TimeDateStamp of export directory : 0x%x\n", peHeader32.exportDirectory.TimeDateStamp);
	// Test import directory
	if (peHeader32.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress > 0)
	{
		WORD sectionNumber;
		if ((sectionNumber = getSectionOfRVA(peHeader32.importDescriptors[0].Name,
			peHeader32.ntHeaders.FileHeader.NumberOfSections, peHeader32.sectionHeaders)) != (WORD)-1)
		{
			DWORD numberOfBytesRead = 0;
			CHAR moduleName[MAX_PATH];
			SetFilePointer(hFile, (peHeader32.importDescriptors[0].Name - peHeader32.sectionHeaders[sectionNumber].VirtualAddress 
				+ peHeader32.sectionHeaders[sectionNumber].PointerToRawData), NULL, FILE_BEGIN);
			if (ReadFile(hFile, &moduleName, MAX_PATH, &numberOfBytesRead, NULL))
				printf("Module name of the first import descriptor : %s\n", moduleName);
		}
	}
	// Test resource directory
	if (peHeader32.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress > 0)
		printf("Number of ID entries in export directory : 0x%x\n", peHeader32.resourceDirectory.NumberOfIdEntries);
	// Test debug directory
	if (peHeader32.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress > 0)
		printf("Type of the debug directory : 0x%x\n", peHeader32.debugDirectory.Type);
	// Test TLS directory // Gonna assume it works because I can't find a PE sample with TLS directory in it...
	if (peHeader32.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress > 0)
		printf("Characteristics of the TLS directory : 0x%x\n", peHeader32.tlsDirectory.Characteristics);

	CloseHandle(hFile);
	free(fileName);
	free(fileTitle);
	system("PAUSE");
	return EXIT_SUCCESS;
}