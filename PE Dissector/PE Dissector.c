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
	memset(peHeader32, 0, sizeof(PE_HEADERS32));

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

	// EXPORT DIRECTORY
	DWORD exportDirectoryAdress = 0;
	WORD sectionNumber;
	// Check if there is an export directory and gets the index of the section it is in.
	if ((sectionNumber = getSectionOfRVA(peHeader32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
		peHeader32->ntHeaders.FileHeader.NumberOfSections, peHeader32->sectionHeaders)) != -1)
	{
		numberOfBytesRead = 0;
		SetFilePointer(hFile, (peHeader32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress 
			- peHeader32->sectionHeaders[sectionNumber].VirtualAddress + peHeader32->sectionHeaders[sectionNumber].PointerToRawData), 
			NULL, FILE_BEGIN);

		if (!ReadFile(hFile, &peHeader32->exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), &numberOfBytesRead, NULL))
			return FALSE;
	}

	// More to come

	return TRUE;
}

WORD getSectionOfRVA(QWORD RVA, WORD numberOfSections, PIMAGE_SECTION_HEADER sectionHeaders)
{
	WORD section = -1;
	for (int i = 0; i < numberOfSections; i++)
	{
		if (RVA > sectionHeaders[i].VirtualAddress && RVA < (sectionHeaders[i].VirtualAddress + sectionHeaders[i].Misc.VirtualSize))
		{
			section = i;
			break;
		}
	}
	return section;
}