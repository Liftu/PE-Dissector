#pragma once

#include <Windows.h>
#include <winnt.h>

// Don't know why, bu I had to define it myself.
typedef unsigned __int64 QWORD;

typedef struct _PE_HEADERS32
{
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS32 ntHeaders;
	IMAGE_SECTION_HEADER* sectionHeaders;
	IMAGE_EXPORT_DIRECTORY exportDirectory;
	IMAGE_IMPORT_DESCRIPTOR* importDescriptors;
	IMAGE_RESOURCE_DIRECTORY ressourceDirectory;
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
	IMAGE_IMPORT_DESCRIPTOR* importDescriptors;
	IMAGE_RESOURCE_DIRECTORY ressourceDirectory;
	IMAGE_DEBUG_DIRECTORY debugDirectory;
	IMAGE_TLS_DIRECTORY64 tlsDirectory;
} PE_HEADERS64, *PPE_HEADERS64;

BOOL isFileExecutable(HANDLE file);
BOOL readPEHeaders32(HANDLE file, PPE_HEADERS32 peHeader32);
WORD getSectionOfRVA(QWORD RVA, WORD numberOfSections, PIMAGE_SECTION_HEADER sectionHeaders);