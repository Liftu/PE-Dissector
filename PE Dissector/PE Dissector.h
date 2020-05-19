#pragma once

#include <Windows.h>
#include <winnt.h>

// Don't know why, bu I had to define it myself.
typedef unsigned __int64 QWORD;

typedef struct _IMPORT_DESCRIPTOR_ENTRY
{
	DWORD importNameTable;
	DWORD importAddressTable;
	//IMAGE_IMPORT_BY_NAME importByName;
	WORD hint;
	LPCSTR name;
} IMPORT_DESCRIPTOR_ENTRY, *PIMPORT_DESCRIPTOR_ENTRY;

typedef struct _PE_HEADERS32
{
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS32 ntHeaders;
	IMAGE_SECTION_HEADER* sectionHeaders;
	IMAGE_EXPORT_DIRECTORY exportDirectory;
	DWORD* addressOfExportedFunctions;
	WORD*  addressOfExportedNameOrdinals;
	DWORD* addressOfExportedNames;
	IMAGE_IMPORT_DESCRIPTOR* importDescriptors;
	IMPORT_DESCRIPTOR_ENTRY** importDescriptorsEntries;
	IMAGE_RESOURCE_DIRECTORY resourceDirectory;
	IMAGE_DEBUG_DIRECTORY debugDirectory;
	IMAGE_TLS_DIRECTORY32 tlsDirectory;
	//IMAGE_DELAY_IMPORT_DESCRIPTOR
} PE_HEADERS32, *PPE_HEADERS32;

typedef struct _PE_HEADERS64
{
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS64 ntHeaders;
	IMAGE_SECTION_HEADER* sectionHeaders;
	IMAGE_EXPORT_DIRECTORY exportDirectory;
	DWORD* addressOfExportedFunctions;
	WORD*  addressOfExportedNameOrdinals;
	DWORD* addressOfExportedNames;
	IMPORT_DESCRIPTOR_ENTRY** importDescriptorsEntries;
	IMAGE_IMPORT_DESCRIPTOR* importDescriptors;
	IMAGE_RESOURCE_DIRECTORY resourceDirectory;
	IMAGE_DEBUG_DIRECTORY debugDirectory;
	IMAGE_TLS_DIRECTORY64 tlsDirectory;
} PE_HEADERS64, *PPE_HEADERS64;

BOOL isFileExecutable(HANDLE hFile);
WORD getArchitecture(HANDLE hFile);
BOOL readPEHeaders32(HANDLE hFile, PPE_HEADERS32 peHeaders32);
WORD getSectionFromRVA(QWORD RVA, WORD numberOfSections, PIMAGE_SECTION_HEADER sectionHeaders);
QWORD getFileOffsetFromRVA(QWORD RVA, PPE_HEADERS32 peHearders32);
