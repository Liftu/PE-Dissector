#include "PE Dissector.h"

WORD getArchitecture(HANDLE hFile)
{
	WORD architecture = 0;
	DWORD lfanew;
	DWORD numberOfBytesRead = 0;
	SetFilePointer(hFile, 0x3C, NULL, FILE_BEGIN);
	if (!ReadFile(hFile, &lfanew, sizeof(DWORD), &numberOfBytesRead, NULL))
	{
		perror("Error while getting lfanew value.\nClosing...\n");
		exit(EXIT_FAILURE);
	}
	SetFilePointer(hFile, lfanew + 0x4, NULL, FILE_BEGIN);
	if (!ReadFile(hFile, &architecture, sizeof(WORD), &numberOfBytesRead, NULL))
	{
		perror("Error while getting architecture value in file header.\nClosing...\n");
		exit(EXIT_FAILURE);
	}
	return architecture;
}

BOOL isFileExecutable(HANDLE hFile)
{
	WORD magicNumber = 0;
	DWORD numberOfBytesRead = 0;
	SetFilePointer(hFile, (LONG)NULL, NULL, FILE_BEGIN);
	if (!ReadFile(hFile, &magicNumber, sizeof(WORD), &numberOfBytesRead, NULL))
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
	SetFilePointer(hFile, (LONG)NULL, NULL, FILE_BEGIN);
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
	WORD sectionNumber;
	// Check if there is an export directory and gets the index of the section it is in.
	if ((sectionNumber = getSectionOfRVA(peHeader32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
		peHeader32->ntHeaders.FileHeader.NumberOfSections, peHeader32->sectionHeaders)) != (WORD)-1)
	{
		numberOfBytesRead = 0;
		SetFilePointer(hFile, (peHeader32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
			- peHeader32->sectionHeaders[sectionNumber].VirtualAddress + peHeader32->sectionHeaders[sectionNumber].PointerToRawData),
			NULL, FILE_BEGIN);

		if (!ReadFile(hFile, &peHeader32->exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), &numberOfBytesRead, NULL))
			return FALSE;
	}

	// IMPORT DIRECTORY
	// Check if there is an import directory and gets the index of the section it is in.
	if ((sectionNumber = getSectionOfRVA(peHeader32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
		peHeader32->ntHeaders.FileHeader.NumberOfSections, peHeader32->sectionHeaders)) != (WORD)-1)
	{
		peHeader32->importDescriptors = malloc(peHeader32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
		numberOfBytesRead = 0;
		SetFilePointer(hFile, (peHeader32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
			- peHeader32->sectionHeaders[sectionNumber].VirtualAddress + peHeader32->sectionHeaders[sectionNumber].PointerToRawData),
			NULL, FILE_BEGIN);

		if (!ReadFile(hFile, peHeader32->importDescriptors, peHeader32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size, &numberOfBytesRead, NULL))
			return FALSE;
	}

	// RESSOURCE DIRECTORY
	// Check if there is an export directory and gets the index of the section it is in.
	if ((sectionNumber = getSectionOfRVA(peHeader32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress,
		peHeader32->ntHeaders.FileHeader.NumberOfSections, peHeader32->sectionHeaders)) != (WORD)-1)
	{
		numberOfBytesRead = 0;
		SetFilePointer(hFile, (peHeader32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress
			- peHeader32->sectionHeaders[sectionNumber].VirtualAddress + peHeader32->sectionHeaders[sectionNumber].PointerToRawData),
			NULL, FILE_BEGIN);

		if (!ReadFile(hFile, &peHeader32->resourceDirectory, sizeof(IMAGE_RESOURCE_DIRECTORY), &numberOfBytesRead, NULL))
			return FALSE;
	}

	// DEBUG DIRECTORY
	// Check if there is an export directory and gets the index of the section it is in.
	if ((sectionNumber = getSectionOfRVA(peHeader32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress,
		peHeader32->ntHeaders.FileHeader.NumberOfSections, peHeader32->sectionHeaders)) != (WORD)-1)
	{
		numberOfBytesRead = 0;
		SetFilePointer(hFile, (peHeader32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress
			- peHeader32->sectionHeaders[sectionNumber].VirtualAddress + peHeader32->sectionHeaders[sectionNumber].PointerToRawData),
			NULL, FILE_BEGIN);

		if (!ReadFile(hFile, &peHeader32->debugDirectory, sizeof(IMAGE_DEBUG_DIRECTORY), &numberOfBytesRead, NULL))
			return FALSE;
	}

	// TLS DIRECTORY // Gonna assume it works because I can't find a PE sample with TLS directory in it...
	// Check if there is an export directory and gets the index of the section it is in.
	if ((sectionNumber = getSectionOfRVA(peHeader32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress,
		peHeader32->ntHeaders.FileHeader.NumberOfSections, peHeader32->sectionHeaders)) != (WORD)-1)
	{
		numberOfBytesRead = 0;
		SetFilePointer(hFile, (peHeader32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress
			- peHeader32->sectionHeaders[sectionNumber].VirtualAddress + peHeader32->sectionHeaders[sectionNumber].PointerToRawData),
			NULL, FILE_BEGIN);

		if (!ReadFile(hFile, &peHeader32->tlsDirectory, sizeof(IMAGE_TLS_DIRECTORY32), &numberOfBytesRead, NULL))
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
		if (RVA >= sectionHeaders[i].VirtualAddress && RVA < (sectionHeaders[i].VirtualAddress + sectionHeaders[i].Misc.VirtualSize))
		{
			section = i;
			break;
		}
	}
	return section;
}