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

BOOL readPEHeaders32(HANDLE hFile, PPE_HEADERS32 peHeaders32)
{
	memset(peHeaders32, 0, sizeof(PE_HEADERS32));

	// DOS HEADER
	DWORD numberOfBytesRead = 0;
	SetFilePointer(hFile, (LONG)NULL, NULL, FILE_BEGIN);
	if (!ReadFile(hFile, &peHeaders32->dosHeader, sizeof(IMAGE_DOS_HEADER), &numberOfBytesRead, NULL))
		return FALSE;

	// NT HEADERS
	numberOfBytesRead = 0;
	SetFilePointer(hFile, peHeaders32->dosHeader.e_lfanew, NULL, FILE_BEGIN);
	if (!ReadFile(hFile, &peHeaders32->ntHeaders, sizeof(IMAGE_NT_HEADERS32), &numberOfBytesRead, NULL))
		return FALSE;

	// SECTION HEADERS
	peHeaders32->sectionHeaders = malloc(peHeaders32->ntHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
	numberOfBytesRead = 0;
	if (!ReadFile(hFile, peHeaders32->sectionHeaders, (peHeaders32->ntHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)), &numberOfBytesRead, NULL))
		return FALSE;

	// EXPORT DIRECTORY
	WORD sectionNumber;
	// Check if there is an export directory and gets the index of the section it is in.
	if ((sectionNumber = getSectionFromRVA(peHeaders32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
		peHeaders32->ntHeaders.FileHeader.NumberOfSections, peHeaders32->sectionHeaders)) != (WORD)-1)
	{
		numberOfBytesRead = 0;
		// I should use the new getFileOffsetFromRVA function for these.
		SetFilePointer(hFile, (peHeaders32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
			- peHeaders32->sectionHeaders[sectionNumber].VirtualAddress + peHeaders32->sectionHeaders[sectionNumber].PointerToRawData),
			NULL, FILE_BEGIN);

		if (!ReadFile(hFile, &peHeaders32->exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), &numberOfBytesRead, NULL))
			return FALSE;

		// Address of exported functions
		numberOfBytesRead = 0;
		peHeaders32->addressOfExportedFunctions = malloc(peHeaders32->exportDirectory.NumberOfFunctions * sizeof(DWORD));
		SetFilePointer(hFile, getFileOffsetFromRVA(peHeaders32->exportDirectory.AddressOfFunctions, peHeaders32), NULL, FILE_BEGIN);
		if (!ReadFile(hFile, peHeaders32->addressOfExportedFunctions, (peHeaders32->exportDirectory.NumberOfFunctions * sizeof(DWORD)), &numberOfBytesRead, NULL))
			return FALSE;

		// Address of exported name ordinals
		numberOfBytesRead = 0;
		peHeaders32->addressOfExportedNameOrdinals = malloc(peHeaders32->exportDirectory.NumberOfFunctions * sizeof(WORD));
		SetFilePointer(hFile, getFileOffsetFromRVA(peHeaders32->exportDirectory.AddressOfNameOrdinals, peHeaders32), NULL, FILE_BEGIN);
		if (!ReadFile(hFile, peHeaders32->addressOfExportedNameOrdinals, (peHeaders32->exportDirectory.NumberOfFunctions * sizeof(WORD)), &numberOfBytesRead, NULL))
			return FALSE;

		// Address of exported names
		numberOfBytesRead = 0;
		peHeaders32->addressOfExportedNames = malloc(peHeaders32->exportDirectory.NumberOfFunctions * sizeof(DWORD));
		SetFilePointer(hFile, getFileOffsetFromRVA(peHeaders32->exportDirectory.AddressOfNames, peHeaders32), NULL, FILE_BEGIN);
		if (!ReadFile(hFile, peHeaders32->addressOfExportedNames, (peHeaders32->exportDirectory.NumberOfFunctions * sizeof(DWORD)), &numberOfBytesRead, NULL))
			return FALSE;
	}

	// IMPORT DESCRIPTORS
	// Check if there is an import directory and gets the index of the section it is in.
	if ((sectionNumber = getSectionFromRVA(peHeaders32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
		peHeaders32->ntHeaders.FileHeader.NumberOfSections, peHeaders32->sectionHeaders)) != (WORD)-1)
	{
		peHeaders32->importDescriptors = malloc(peHeaders32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
		numberOfBytesRead = 0;
		SetFilePointer(hFile, (peHeaders32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
			- peHeaders32->sectionHeaders[sectionNumber].VirtualAddress + peHeaders32->sectionHeaders[sectionNumber].PointerToRawData),
			NULL, FILE_BEGIN);

		if (!ReadFile(hFile, peHeaders32->importDescriptors, peHeaders32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size, &numberOfBytesRead, NULL))
			return FALSE;

		// IMPORT DESCRIPTORS ENTRIES
		peHeaders32->importDescriptorsEntries = malloc((peHeaders32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / 0x14 - 1) * sizeof(IMPORT_DESCRIPTOR_ENTRY*));
		for (int moduleIndex = 0; moduleIndex < (peHeaders32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / 0x14 - 1); moduleIndex++)
		{
			int numberOfImports = 0;
			DWORD checkINT;
			do
			{
				numberOfBytesRead = 0;
				SetFilePointer(hFile, getFileOffsetFromRVA(peHeaders32->importDescriptors[moduleIndex].OriginalFirstThunk + numberOfImports * sizeof(DWORD), peHeaders32), NULL, FILE_BEGIN);
				ReadFile(hFile, &checkINT, sizeof(DWORD), &numberOfBytesRead, NULL);
				numberOfImports++;
			} while (checkINT);

			peHeaders32->importDescriptorsEntries[moduleIndex] = malloc(numberOfImports * sizeof(IMPORT_DESCRIPTOR_ENTRY));
			for (int functionIndex = 0; functionIndex < numberOfImports; functionIndex++)
			{
				IMPORT_DESCRIPTOR_ENTRY importDescriptorEntry;

				// Import Name Table (OFT)
				numberOfBytesRead = 0;
				SetFilePointer(hFile, getFileOffsetFromRVA(peHeaders32->importDescriptors[moduleIndex].OriginalFirstThunk + functionIndex * sizeof(DWORD), peHeaders32), NULL, FILE_BEGIN);
				ReadFile(hFile, &importDescriptorEntry.importNameTable, sizeof(importDescriptorEntry.importNameTable), &numberOfBytesRead, NULL);

				// Import Address Table (FT)
				numberOfBytesRead = 0;
				SetFilePointer(hFile, getFileOffsetFromRVA(peHeaders32->importDescriptors[moduleIndex].FirstThunk + functionIndex * sizeof(DWORD), peHeaders32), NULL, FILE_BEGIN);
				ReadFile(hFile, &importDescriptorEntry.importAddressTable, sizeof(importDescriptorEntry.importAddressTable), &numberOfBytesRead, NULL);

				if (importDescriptorEntry.importNameTable != 0 && importDescriptorEntry.importAddressTable)
				{
					// Hint
					numberOfBytesRead = 0;
					SetFilePointer(hFile, getFileOffsetFromRVA(importDescriptorEntry.importNameTable, peHeaders32), NULL, FILE_BEGIN);
					ReadFile(hFile, &importDescriptorEntry.hint, sizeof(importDescriptorEntry.hint), &numberOfBytesRead, NULL);

					// Name
					int numberOfCharacters = 0;
					BYTE byteRead;
					do
					{
						numberOfBytesRead = 0;
						SetFilePointer(hFile, getFileOffsetFromRVA(importDescriptorEntry.importNameTable + sizeof(importDescriptorEntry.hint) + numberOfCharacters, peHeaders32), NULL, FILE_BEGIN);
						ReadFile(hFile, &byteRead, sizeof(byteRead), &numberOfBytesRead, NULL);
						numberOfCharacters++;
					} while (byteRead);
					importDescriptorEntry.name = malloc(numberOfCharacters * sizeof(BYTE));
					numberOfBytesRead = 0;
					SetFilePointer(hFile, getFileOffsetFromRVA(importDescriptorEntry.importNameTable + sizeof(importDescriptorEntry.hint), peHeaders32), NULL, FILE_BEGIN);
					ReadFile(hFile, importDescriptorEntry.name, numberOfCharacters * sizeof(BYTE), &numberOfBytesRead, NULL);
				}
				else
				{
					importDescriptorEntry.hint = 0;
					importDescriptorEntry.name = 0;
				}

				peHeaders32->importDescriptorsEntries[moduleIndex][functionIndex] = importDescriptorEntry;
			}
		}
	}

	// RESSOURCE DIRECTORY
	// Check if there is an export directory and gets the index of the section it is in.
	if ((sectionNumber = getSectionFromRVA(peHeaders32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress,
		peHeaders32->ntHeaders.FileHeader.NumberOfSections, peHeaders32->sectionHeaders)) != (WORD)-1)
	{
		numberOfBytesRead = 0;
		SetFilePointer(hFile, (peHeaders32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress
			- peHeaders32->sectionHeaders[sectionNumber].VirtualAddress + peHeaders32->sectionHeaders[sectionNumber].PointerToRawData),
			NULL, FILE_BEGIN);

		if (!ReadFile(hFile, &peHeaders32->resourceDirectory, sizeof(IMAGE_RESOURCE_DIRECTORY), &numberOfBytesRead, NULL))
			return FALSE;
	}

	// DEBUG DIRECTORY
	// Check if there is a debug directory and gets the index of the section it is in.
	if ((sectionNumber = getSectionFromRVA(peHeaders32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress,
		peHeaders32->ntHeaders.FileHeader.NumberOfSections, peHeaders32->sectionHeaders)) != (WORD)-1)
	{
		numberOfBytesRead = 0;
		SetFilePointer(hFile, (peHeaders32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress
			- peHeaders32->sectionHeaders[sectionNumber].VirtualAddress + peHeaders32->sectionHeaders[sectionNumber].PointerToRawData),
			NULL, FILE_BEGIN);

		if (!ReadFile(hFile, &peHeaders32->debugDirectory, sizeof(IMAGE_DEBUG_DIRECTORY), &numberOfBytesRead, NULL))
			return FALSE;
	}

	// TLS DIRECTORY // Gonna assume it works because I can't find a PE sample with TLS directory in it...
	// Check if there is a tls directory and gets the index of the section it is in.
	if ((sectionNumber = getSectionFromRVA(peHeaders32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress,
		peHeaders32->ntHeaders.FileHeader.NumberOfSections, peHeaders32->sectionHeaders)) != (WORD)-1)
	{
		numberOfBytesRead = 0;
		SetFilePointer(hFile, (peHeaders32->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress
			- peHeaders32->sectionHeaders[sectionNumber].VirtualAddress + peHeaders32->sectionHeaders[sectionNumber].PointerToRawData),
			NULL, FILE_BEGIN);

		if (!ReadFile(hFile, &peHeaders32->tlsDirectory, sizeof(IMAGE_TLS_DIRECTORY32), &numberOfBytesRead, NULL))
			return FALSE;
	}

	// More to come

	return TRUE;
}

WORD getSectionFromRVA(QWORD RVA, WORD numberOfSections, PIMAGE_SECTION_HEADER sectionHeaders)
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

QWORD getFileOffsetFromRVA(QWORD RVA, PPE_HEADERS32 peHearders32)
{
	QWORD fileOffset = -1;
	WORD sectionNumber = getSectionFromRVA(RVA, peHearders32->ntHeaders.FileHeader.NumberOfSections, peHearders32->sectionHeaders);
	if (sectionNumber != (WORD)-1)
	{
		fileOffset = RVA - peHearders32->sectionHeaders[sectionNumber].VirtualAddress + peHearders32->sectionHeaders[sectionNumber].PointerToRawData;
	}
	return fileOffset;
}
