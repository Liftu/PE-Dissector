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
	headerMember{"WORD", sizeof(WORD), "e_res[0]"},
	headerMember{"WORD", sizeof(WORD), "e_res[1]"},
	headerMember{"WORD", sizeof(WORD), "e_res[2]"},
	headerMember{"WORD", sizeof(WORD), "e_res[3]"},
	headerMember{"WORD", sizeof(WORD), "e_oemid"},
	headerMember{"WORD", sizeof(WORD), "e_oeminfo"},
	headerMember{"WORD", sizeof(WORD), "e_res2[0]"},
	headerMember{"WORD", sizeof(WORD), "e_res2[1]"},
	headerMember{"WORD", sizeof(WORD), "e_res2[2]"},
	headerMember{"WORD", sizeof(WORD), "e_res2[3]"},
	headerMember{"WORD", sizeof(WORD), "e_res2[4]"},
	headerMember{"WORD", sizeof(WORD), "e_res2[5]"},
	headerMember{"WORD", sizeof(WORD), "e_res2[6]"},
	headerMember{"WORD", sizeof(WORD), "e_res2[7]"},
	headerMember{"WORD", sizeof(WORD), "e_res2[8]"},
	headerMember{"WORD", sizeof(WORD), "e_res2[9]"},
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
	headerMember{"DWORD", sizeof(DWORD), "Delay Import Directory RVA"},
	headerMember{"DWORD", sizeof(DWORD), "Delay Import Directory Size"},
	headerMember{"DWORD", sizeof(DWORD), "CLR Runtime Directory RVA"},
	headerMember{"DWORD", sizeof(DWORD), "CLR Runtime Directory Size"},
	headerMember{"DWORD", sizeof(DWORD), "Reserved"},
	headerMember{"DWORD", sizeof(DWORD), "Reserved"},
	headerMember{"", 0, ""},
};

// SECTION HEADER
const headerMember sectionHeaderMembers[] = {
	headerMember{"BYTE[8]", sizeof(BYTE[8]), "Name"},
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

// EXPORT DIRECTORY
const headerMember exportDirectoryMembers[] = {
	headerMember{"DWORD", sizeof(DWORD), "Characteristics"},
	headerMember{"DWORD", sizeof(DWORD), "TimeDateStamp"},
	headerMember{"WORD", sizeof(WORD), "MajorVersion"},
	headerMember{"WORD", sizeof(WORD), "MinorVersion"},
	headerMember{"DWORD", sizeof(DWORD), "Name"},
	headerMember{"DWORD", sizeof(DWORD), "Base"},
	headerMember{"DWORD", sizeof(DWORD), "NumberOfFunctions"},
	headerMember{"DWORD", sizeof(DWORD), "NumberOfNames"},
	headerMember{"DWORD", sizeof(DWORD), "AddressOfFunctions"},
	headerMember{"DWORD", sizeof(DWORD), "AddressOfNames"},
	headerMember{"DWORD", sizeof(DWORD), "AddressOfNameOrdinals"},
	headerMember{"", 0, ""},
};

// IMPORT DESCRIPTOR
const headerMember importDescriptorMembers[] = {
	headerMember{"DWORD", sizeof(DWORD), "OriginalFirstThunk"},	// INT
	headerMember{"DWORD", sizeof(DWORD), "TimeDateStamp"},
	headerMember{"DWORD", sizeof(DWORD), "ForwarderChain"},
	headerMember{"DWORD", sizeof(DWORD), "Name"},
	headerMember{"DWORD", sizeof(DWORD), "FirstThunk"},			// IAT
	headerMember{"", 0, ""},
};

// IMPORT DESCRIPTOR ENTRY
const headerMember importDescriptorEntryMembers[] = {
	headerMember{"DWORD", sizeof(DWORD), "INT (OFT)"},	// INT
	headerMember{"DWORD", sizeof(DWORD), "IAT (FT)"},	// IAT
	headerMember{"WORD", sizeof(WORD), "Hint"},
	headerMember{"STRING", sizeof(CHAR), "Name"},
	headerMember{"", 0, ""},
};

// RESOURCE DIRECTORY
const headerMember resourceDirectoryMembers[] = {
	headerMember{"DWORD", sizeof(DWORD), "Characteristics"},
	headerMember{"DWORD", sizeof(DWORD), "TimeDateStamp"},
	headerMember{"WORD", sizeof(WORD), "MajorVersion"},
	headerMember{"WORD", sizeof(WORD), "MinorVersion"},
	headerMember{"WORD", sizeof(WORD), "NumberOfNamedEntries"},
	headerMember{"WORD", sizeof(WORD), "NumberOfIdEntries"},
	headerMember{"", 0, ""},
};

// DEBUG DIRECTORY
const headerMember debugDirectoryMembers[] = {
	headerMember{"DWORD", sizeof(DWORD), "Characteristics"},
	headerMember{"DWORD", sizeof(DWORD), "TimeDateStamp"},
	headerMember{"WORD", sizeof(WORD), "MajorVersion"},
	headerMember{"WORD", sizeof(WORD), "MinorVersion"},
	headerMember{"DWORD", sizeof(DWORD), "Type"},
	headerMember{"DWORD", sizeof(DWORD), "SizeOfData"},
	headerMember{"DWORD", sizeof(DWORD), "AddressOfRawData"},
	headerMember{"DWORD", sizeof(DWORD), "PointerToRawData"},
	headerMember{"", 0, ""},
};

// TLS DIRECTORY
const headerMember tlsDirectoryMembers[] = {
	headerMember{"DWORD", sizeof(DWORD), "StartAddressOfRawData"},
	headerMember{"DWORD", sizeof(DWORD), "EndAddressOfRawData"},
	headerMember{"DWORD", sizeof(DWORD), "AddressOfIndex"},
	headerMember{"DWORD", sizeof(DWORD), "AddressOfCallBacks"},
	headerMember{"DWORD", sizeof(DWORD), "SizeOfZeroFill"},
	headerMember{"DWORD", sizeof(DWORD), "Characteristics"},
	headerMember{"", 0, ""},
};