#include "PE Dissector.h"

BOOL isFileExecutable(HANDLE file)
{
	WORD magicNumber = 0;
	DWORD numberOfBytesRead = 0;
	if (!ReadFile(file, &magicNumber, 2, &numberOfBytesRead, NULL))
	{
		perror("Error while getting magic number.\nClosing...\n");
		exit(EXIT_FAILURE);
	}
	return magicNumber == 0x5A4D && numberOfBytesRead == 2;
}

BOOL readPEHeaders32(HANDLE hFile, PPE_HEADERS32 peHeader32)
{
	// DOS HEADER
	DWORD numberOfBytesRead = 0;
	SetFilePointer(hFile, NULL, NULL, FILE_BEGIN);
	if (!ReadFile(hFile, &peHeader32->dosHeader, sizeof(IMAGE_DOS_HEADER), &numberOfBytesRead, NULL))
		return FALSE;

	// NT HEADERS
	numberOfBytesRead = 0;
	SetFilePointer(hFile, peHeader32->dosHeader.e_lfanew, NULL, FILE_BEGIN);
	if (!ReadFile(hFile, &peHeader32->ntHeaders, sizeof(IMAGE_NT_HEADERS32), &numberOfBytesRead, NULL))
		return FALSE;

	// SECTION HEADERS
	peHeader32->sectionHeaders = malloc(peHeader32->ntHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
	numberOfBytesRead = 0;
	if (!ReadFile(hFile, peHeader32->sectionHeaders, (peHeader32->ntHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)), &numberOfBytesRead, NULL))
		return FALSE;

	// More to come

	return TRUE;
}