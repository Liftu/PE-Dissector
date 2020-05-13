#pragma once

#include <Windows.h>

struct headerMember
{
	const char* sizeTitle;
	int size;
	const char* name;
};

// DOS HEADER
const headerMember dosHeaderMembers[] = {
	headerMember{"WORD", sizeof(WORD), "e_magic"},
	headerMember{"WORD", sizeof(WORD), "e_cblp"},
	headerMember{"WORD", sizeof(WORD), "e_cp"},
	headerMember{"WORD", sizeof(WORD), "e_crlc"},
	headerMember{"WORD", sizeof(WORD), "e_cparhdr"},
	headerMember{"WORD", sizeof(WORD), "e_minalloc"},
	headerMember{"WORD", sizeof(WORD), "e_maxalloc"},
	headerMember{"WORD", sizeof(WORD), "e_ss"},
	headerMember{"WORD", sizeof(WORD), "e_sp"},
	headerMember{"WORD", sizeof(WORD), "e_csum"},
	headerMember{"WORD", sizeof(WORD), "e_ip"},
	headerMember{"WORD", sizeof(WORD), "e_cs"},
	headerMember{"WORD", sizeof(WORD), "e_lfarlc"},
	headerMember{"WORD", sizeof(WORD), "e_ovno"},
	headerMember{"WORD", sizeof(WORD), "e_res[4]"},
	headerMember{"WORD", sizeof(WORD), "e_oemid"},
	headerMember{"WORD", sizeof(WORD), "e_oeminfo"},
	headerMember{"WORD", sizeof(WORD), "e_res2[10]"},
	headerMember{"DWORD", sizeof(DWORD), "e_lfanew"},
	headerMember{"", 0, ""},
};

// NT HEADERS
const headerMember ntHeadersMembers[] = { 
	headerMember{"DWORD", sizeof(DWORD), "Signature"},
	headerMember{"", 0, ""},
};

// FILE HEADER
const headerMember fileHeaderMembers[] = {
	headerMember{"WORD", sizeof(WORD), "Machine"},
	headerMember{"WORD", sizeof(WORD), "NumberOfSections"},
	headerMember{"DWORD", sizeof(DWORD), "TimeDateStamp"},
	headerMember{"DWORD", sizeof(DWORD), "PointerToSymbolTable"},
	headerMember{"DWORD", sizeof(DWORD), "NumberOfSymbols"},
	headerMember{"WORD", sizeof(WORD), "SizeOfOptionalHeader"},
	headerMember{"WORD", sizeof(WORD), "Characteristics"},
	headerMember{"", 0, ""},
};

// OPTIONAL HEADER
const headerMember optionalHeader32Members[] = {
	headerMember{"WORD", sizeof(WORD), "Magic"},
	headerMember{"BYTE", sizeof(BYTE), "MajorLinkerVersion"},
	headerMember{"BYTE", sizeof(BYTE), "MinorLinkerVersion"},
	headerMember{"DWORD", sizeof(DWORD), "SizeOfCode"},
	headerMember{"DWORD", sizeof(DWORD), "SizeOfInitializedData"},
	headerMember{"DWORD", sizeof(DWORD), "SizeOfUninitializedData"},
	headerMember{"DWORD", sizeof(DWORD), "AddressOfEntryPoint"},
	headerMember{"DWORD", sizeof(DWORD), "BaseOfCode"},
	headerMember{"DWORD", sizeof(DWORD), "BaseOfData"},
	headerMember{"DWORD", sizeof(DWORD), "ImageBase"},
	headerMember{"DWORD", sizeof(DWORD), "SectionAlignment"},
	headerMember{"DWORD", sizeof(DWORD), "FileAlignment"},
	headerMember{"WORD", sizeof(WORD), "MajorOperatingSystemVersion"},
	headerMember{"WORD", sizeof(WORD), "MinorOperatingSystemVersion"},
	headerMember{"WORD", sizeof(WORD), "MajorImageVersion"},
	headerMember{"WORD", sizeof(WORD), "MinorImageVersion"},
	headerMember{"WORD", sizeof(WORD), "MajorSubsystemVersion"},
	headerMember{"WORD", sizeof(WORD), "MinorSubsystemVersion"},
	headerMember{"DWORD", sizeof(DWORD), "Win32VersionValue"},
	headerMember{"DWORD", sizeof(DWORD), "SizeOfImage"},
	headerMember{"DWORD", sizeof(DWORD), "SizeOfHeaders"},
	headerMember{"DWORD", sizeof(DWORD), "CheckSum"},
	headerMember{"WORD", sizeof(WORD), "Subsystem"},
	headerMember{"WORD", sizeof(WORD), "DllCharacteristics"},
	headerMember{"DWORD", sizeof(DWORD), "SizeOfStackReserve"},
	headerMember{"DWORD", sizeof(DWORD), "SizeOfStackCommit"},
	headerMember{"DWORD", sizeof(DWORD), "SizeOfHeapReserve"},
	headerMember{"DWORD", sizeof(DWORD), "SizeOfHeapCommit"},
	headerMember{"DWORD", sizeof(DWORD), "LoaderFlags"},
	headerMember{"DWORD", sizeof(DWORD), "NumberOfRvaAndSizes"},
	headerMember{"", 0, ""},
};

// OPTIONAL HEADER 64
const headerMember optionalHeader64Members[] = {
	headerMember{"WORD", sizeof(WORD), "Magic"},
	headerMember{"BYTE", sizeof(BYTE), "MajorLinkerVersion"},
	headerMember{"BYTE", sizeof(BYTE), "MinorLinkerVersion"},
	headerMember{"DWORD", sizeof(DWORD), "SizeOfCode"},
	headerMember{"DWORD", sizeof(DWORD), "SizeOfInitializedData"},
	headerMember{"DWORD", sizeof(DWORD), "SizeOfUninitializedData"},
	headerMember{"DWORD", sizeof(DWORD), "AddressOfEntryPoint"},
	headerMember{"DWORD", sizeof(DWORD), "BaseOfCode"},
	headerMember{"QWORD", sizeof(QWORD), "ImageBase"},
	headerMember{"DWORD", sizeof(DWORD), "SectionAlignment"},
	headerMember{"DWORD", sizeof(DWORD), "FileAlignment"},
	headerMember{"WORD", sizeof(WORD), "MajorOperatingSystemVersion"},
	headerMember{"WORD", sizeof(WORD), "MinorOperatingSystemVersion"},
	headerMember{"WORD", sizeof(WORD), "MajorImageVersion"},
	headerMember{"WORD", sizeof(WORD), "MinorImageVersion"},
	headerMember{"WORD", sizeof(WORD), "MajorSubsystemVersion"},
	headerMember{"WORD", sizeof(WORD), "MinorSubsystemVersion"},
	headerMember{"DWORD", sizeof(DWORD), "Win32VersionValue"},
	headerMember{"DWORD", sizeof(DWORD), "SizeOfImage"},
	headerMember{"DWORD", sizeof(DWORD), "SizeOfHeaders"},
	headerMember{"DWORD", sizeof(DWORD), "CheckSum"},
	headerMember{"WORD", sizeof(WORD), "Subsystem"},
	headerMember{"WORD", sizeof(WORD), "DllCharacteristics"},
	headerMember{"QWORD", sizeof(QWORD), "SizeOfStackReserve"},
	headerMember{"QWORD", sizeof(QWORD), "SizeOfHeapReserve"},
	headerMember{"QWORD", sizeof(QWORD), "SizeOfHeapCommit"},
	headerMember{"DWORD", sizeof(DWORD), "LoaderFlags"},
	headerMember{"DWORD", sizeof(DWORD), "NumberOfRvaAndSizes"},
	headerMember{"", 0, ""},
};

// DATA DIRECTORIES
const headerMember dataDirectoriesMembers[] = {
	headerMember{"DWORD", sizeof(DWORD), "Export Directory RVA"}, // VirtualAddress
	headerMember{"DWORD", sizeof(DWORD), "Export Directory Size"},
	headerMember{"DWORD", sizeof(DWORD), "Import Directory RVA"},
	headerMember{"DWORD", sizeof(DWORD), "Import Directory Size"},
	headerMember{"DWORD", sizeof(DWORD), "Resource Directory RVA"},
	headerMember{"DWORD", sizeof(DWORD), "Resource Directory Size"},
	headerMember{"DWORD", sizeof(DWORD), "Exception Directory RVA"},
	headerMember{"DWORD", sizeof(DWORD), "Exception Directory Size"},
	headerMember{"DWORD", sizeof(DWORD), "Security Directory RVA"},
	headerMember{"DWORD", sizeof(DWORD), "Security Directory Size"},
	headerMember{"DWORD", sizeof(DWORD), "Relocation Directory RVA"},
	headerMember{"DWORD", sizeof(DWORD), "Relocation Directory Size"},
	headerMember{"DWORD", sizeof(DWORD), "Debug Directory RVA"},
	headerMember{"DWORD", sizeof(DWORD), "Debug Directory Size"},
	headerMember{"DWORD", sizeof(DWORD), "Architecture Directory RVA"},
	headerMember{"DWORD", sizeof(DWORD), "Architecture Directory Size"},
	headerMember{"DWORD", sizeof(DWORD), "Global Ptr RVA"},
	headerMember{"DWORD", sizeof(DWORD), "Global Ptr Size"},
	headerMember{"DWORD", sizeof(DWORD), "TLS Directory RVA"},
	headerMember{"DWORD", sizeof(DWORD), "TLS Directory Size"},
	headerMember{"DWORD", sizeof(DWORD), "Configuration Directory RVA"},
	headerMember{"DWORD", sizeof(DWORD), "Configuration Directory Size"},
	headerMember{"DWORD", sizeof(DWORD), "Bound Import Directory RVA"},
	headerMember{"DWORD", sizeof(DWORD), "Bound Import Directory Size"},
	headerMember{"DWORD", sizeof(DWORD), "IAT Directory RVA"},
	headerMember{"DWORD", sizeof(DWORD), "IAT Directory Size"},
	headerMember{"DWORD", sizeof(DWORD), "Delay Directory RVA"},
	headerMember{"DWORD", sizeof(DWORD), "Delay Directory Size"},
	headerMember{"DWORD", sizeof(DWORD), "CLR Runtime Directory RVA"},
	headerMember{"DWORD", sizeof(DWORD), "CLR Runtime Directory Size"},
	headerMember{"DWORD", sizeof(DWORD), "Reserved"},
	headerMember{"DWORD", sizeof(DWORD), "Reserved"},
	headerMember{"", 0, ""},
};

// SECTION HEADER
const headerMember sectionHeaderMembers[] = {
	headerMember{"BYTE[8]", sizeof(BYTE[IMAGE_SIZEOF_SHORT_NAME]), "Name"},
	headerMember{"DWORD", sizeof(DWORD), "VirtualSize"},
	headerMember{"DWORD", sizeof(DWORD), "VirtualAddress"},
	headerMember{"DWORD", sizeof(DWORD), "SizeOfRawData"},
	headerMember{"DWORD", sizeof(DWORD), "PointerToRawData"},
	headerMember{"DWORD", sizeof(DWORD), "PointerToRelocations"},
	headerMember{"DWORD", sizeof(DWORD), "PointerToLinenumbers"},
	headerMember{"WORD", sizeof(WORD), "NumberOfRelocations"},
	headerMember{"WORD", sizeof(WORD), "NumberOfLinenumbers"},
	headerMember{"DWORD", sizeof(DWORD), "Characteristics"},
	headerMember{"", 0, ""},
};