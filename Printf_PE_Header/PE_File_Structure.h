#if !defined(AFX_PEFILESTRUCTURE_H__2414D21D_2275_41D4_978A_84C4140F593D__INCLUDED_)
#define AFX_PEFILESTRUCTURE_H__2414D21D_2275_41D4_978A_84C4140F593D__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif 

#include <WINDOWS.H>

class CPEFileStructure{
public:
	CPEFileStructure();
	~CPEFileStructure();
};

#pragma pack(1)

struct PE_DOS_HEADER
{
	WORD   e_magic;
	WORD   e_cblp;
	WORD   e_cp;
	WORD   e_crlc;
	WORD   e_cparhdr;
	WORD   e_minalloc;
	WORD   e_maxalloc;
	WORD   e_ss;
	WORD   e_sp;
	WORD   e_csum;
	WORD   e_ip;
	WORD   e_cs;
	WORD   e_lfarlc;
	WORD   e_ovno;
	WORD   e_res[4];
	WORD   e_oemid;
	WORD   e_oeminfo;
	WORD   e_res2[10];
	DWORD  e_lfanew;

};

struct PE_FILE_HEADER
{
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
};

struct PE_OPTIONAL_HEADER
{
	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;
	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Win32VersionValue;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	WORD    Subsystem;
	WORD    DllCharacteristics;
	DWORD   SizeOfStackReserve;
	DWORD   SizeOfStackCommit;
	DWORD   SizeOfHeapReserve;
	DWORD   SizeOfHeapCommit;
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct PE_NT_HEADER
{
	DWORD Signature;
	PE_FILE_HEADER FileHeader;
	PE_OPTIONAL_HEADER OptionalHeader;
};

//PE文件Section头
#define IMAGE_SIZEOF_SHORT_NAME  8

struct PE_IMAGE_SECTION_HEADER
{
	BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD   PhysicalAddress;
		DWORD   VirtualSize;
	} Misc;
	DWORD   VirtualAddress;
	DWORD   SizeOfRawData;
	DWORD   PointerToRawData;
	DWORD   PointerToRelocations;
	DWORD   PointerToLinenumbers;
	WORD    NumberOfRelocations;
	WORD    NumberOfLinenumbers;
	DWORD   Characteristics;
};
#pragma pack()

//判断是否为有效的可执行文件
bool fnBlIsVailWindowsExecutiveFile(PE_DOS_HEADER* pPE_DOS_HEADER);

//打印PE_DOS_HEADER信息
void fnPrintPE_DOS_HEADER_Info(PE_DOS_HEADER* pPE_DOS_HEADER);

//判断是否为有效的NT头
bool fnBlVailNTHEADERAddress(PE_NT_HEADER* pPE_NT_HEADER);

//打印PE_NT_HEADER信息
void fnPrintPE_NT_HEADER_Info(PE_NT_HEADER* pPE_NT_HEADER);

//打印PE_FILE_HEADER信息
void fnPrintPE_FILE_HEADER_Info(PE_FILE_HEADER* pPE_FILE_HEADER);

//打印PE_OPTIONAL_HEADER信息
void fnPrintPE_OPTIONAL_HEADER_Info(PE_OPTIONAL_HEADER* pPE_OPTIONAL_HEADER);

void fnPrintPE_SECTION_HEADER_Info(PE_IMAGE_SECTION_HEADER* pPE_IMAGE_SECTION_HEADER, int nNumberOfSection);
#endif