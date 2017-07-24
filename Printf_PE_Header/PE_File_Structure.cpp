#include "stdAfx.h"
#include "PE_File_Structure.h"

CPEFileStructure::CPEFileStructure(){

}
CPEFileStructure::~CPEFileStructure(){

}

//判断是否为有效的可执行文件
bool fnBlIsVailWindowsExecutiveFile(PE_DOS_HEADER* pPE_DOS_HEADER){
	if (pPE_DOS_HEADER == NULL){
		if (__DEBUG){
			printf("pPE_DOS_HEADER为空！\r\n");
		}
		goto F;
	}

	if (pPE_DOS_HEADER->e_magic != 0x5a4d){
		if (__DEBUG){
			printf("不是有效的Windows Executive文件！\r\n");
		}
		goto F;
	}
	else{
		if (__DEBUG){
			printf("是有效的Windows Executive文件！\r\n");
		}
		goto T;
	}

T:
	return true;
F:
	return false;
}

//打印PE_DOS_HEADER信息
void fnPrintPE_DOS_HEADER_Info(PE_DOS_HEADER* pPE_DOS_HEADER){
	int nCount = 0;
	if (NULL == pPE_DOS_HEADER){
		if (__DEBUG){
			printf("PE_DOS_HEADER为空！\r\n");
		}
		goto RET;
	}

	printf("开始打印PE_DOS_HEADER:\r\n");
	//e_magic
	printf("e_magic:%x\r\n", pPE_DOS_HEADER->e_magic);
	//e_cblp
	printf("e_cblp:%x\r\n", pPE_DOS_HEADER->e_cblp);
	//e_cp
	printf("e_cp:%x\r\n", pPE_DOS_HEADER->e_cp);
	//e_crlc
	printf("e_crlc:%x\r\n", pPE_DOS_HEADER->e_crlc);
	//e_cparhdr
	printf("e_cparhdr:%x\r\n", pPE_DOS_HEADER->e_cparhdr);
	//e_minalloc          
	printf("e_minalloc:%x\r\n", pPE_DOS_HEADER->e_minalloc);
	//e_maxalloc                 
	printf("e_maxalloc:%x\r\n", pPE_DOS_HEADER->e_maxalloc);
	//e_ss
	printf("e_ss:%x\r\n", pPE_DOS_HEADER->e_ss);
	//e_sp
	printf("e_sp:%x\r\n", pPE_DOS_HEADER->e_sp);
	//e_csum
	printf("e_csum:%x\r\n", pPE_DOS_HEADER->e_csum);
	//e_ip
	printf("e_ip:%x\r\n", pPE_DOS_HEADER->e_ip);
	//e_cs
	printf("e_cs:%x\r\n", pPE_DOS_HEADER->e_cs);
	//e_lfarlc
	printf("e_lfarlc:%x\r\n", pPE_DOS_HEADER->e_lfarlc);
	//e_ovno;
	printf("e_ovno:%x\r\n", pPE_DOS_HEADER->e_ovno);
	//e_res[4]
	printf("e_res[4]:%x %x %x %x", pPE_DOS_HEADER->e_res[0], pPE_DOS_HEADER->e_res[1],
		pPE_DOS_HEADER->e_res[2], pPE_DOS_HEADER->e_res[3]);
	//e_oemid;
	printf("e_oemid:%x\r\n", pPE_DOS_HEADER->e_oemid);
	//e_oeminfo;
	printf("e_oeminfo:%x\r\n", pPE_DOS_HEADER->e_oeminfo);
	//e_res2[10];
	printf("e_res2[10]:\r\n");
	for (nCount = 0; nCount < 10; nCount++)
	{
		printf("%x ", pPE_DOS_HEADER->e_res2[nCount]);
	}
	printf("\r\n");
	//e_lfanew;  
	printf("e_lfanew:%x\r\n", pPE_DOS_HEADER->e_lfanew);

	//打印完成
	printf("PE_DOS_HEADER打印完成.\r\n");

RET:
	return;
}

//判断是否为有效的NT头
bool fnBlVailNTHEADERAddress(PE_NT_HEADER* pPE_NT_HEADER){
	if (NULL == pPE_NT_HEADER){
		if (__DEBUG){
			printf("PE_NT_HEADER为空！\r\n");
		}
		goto F;
	}

	if (pPE_NT_HEADER->Signature != 'EP'){
		if (__DEBUG){
			printf("不是有效的NT头地址，或者不是有效的PE文件。\r\n");
		}
		goto F;
	}
	else{
		if (__DEBUG){
			printf("是有效的NT头地址。\r\n");
		}
		goto T;
	}
F:
	return false;
T:
	return true;
}

//打印PE_NT_HEADER信息
void fnPrintPE_NT_HEADER_Info(PE_NT_HEADER* pPE_NT_HEADER){
	if (NULL == pPE_NT_HEADER){
		if (__DEBUG){
			printf("PE_NT_HEADER为空！\r\n");
		}
		goto RET;
	}

	//开始打印PE_NT_Header
	printf("开始打印PE_NT_Header\r\n");
	//Signature
	printf("Signature:%x\r\n", pPE_NT_HEADER->Signature);
	//PE_FILE_HEADER的信息和PE_OPTIONAL_HEADER的信息在其他函数中打印。
	printf("PE_FILE_HEADER的信息和PE_OPTIONAL_HEADER的信息在其他函数中打印。\r\n");
	//打印结束
	printf("PE_NT_Header打印结束。\r\n");
RET:
	return;
}

//打印PE_FILE_HEADER信息
void fnPrintPE_FILE_HEADER_Info(PE_FILE_HEADER* pPE_FILE_HEADER){
	if (NULL == pPE_FILE_HEADER){
		if (__DEBUG){
			printf("PE_FILE_HEADER为空！\r\n");
		}
		goto RET;
	}

	//开始打印PE_FILE_HEADER的信息
	printf("开始打印PE_FILE_HEADER的信息。\r\n");
	//Machine
	printf("Machine:%x\r\n", pPE_FILE_HEADER->Machine);
	//NumberOfSections
	printf("NumberOfSections:%x\r\n", pPE_FILE_HEADER->NumberOfSections);
	//TimeDateStamp
	printf("TimeDateStamp:%x\r\n", pPE_FILE_HEADER->TimeDateStamp);
	//PointerToSymbolTable
	printf("PointerToSymbolTable:%x\r\n", pPE_FILE_HEADER->PointerToSymbolTable);
	//NumberOfSymbols
	printf("NumberOfSymbols:%x\r\n", pPE_FILE_HEADER->NumberOfSymbols);
	//SizeOfOptionalHeader
	printf("SizeOfOptionalHeader:%x\r\n", pPE_FILE_HEADER->SizeOfOptionalHeader);
	//Characteristics
	printf("Characteristics:%x\r\n", pPE_FILE_HEADER->Characteristics);
	//打印完成
	printf("PE_FILE_HEADER信息打印完成。\r\n");

RET:
	return;
}

//打印PE_OPTIONAL_HEADER信息
void fnPrintPE_OPTIONAL_HEADER_Info(PE_OPTIONAL_HEADER* pPE_OPTIONAL_HEADER){
	if (NULL == pPE_OPTIONAL_HEADER){
		if (__DEBUG){
			printf("PE_OPTIONAL_HEADER为空！\r\n");
		}
		goto RET;
	}

	printf("开始打印PE_OPTIONAL_HEADER的信息。\r\n");
	//Magic
	printf("Magic:%x\r\n", pPE_OPTIONAL_HEADER->Magic);
	if (pPE_OPTIONAL_HEADER->Magic == 0x10B)
	{
		printf("该文件是32Bit PE文件.\r\n");
	}
	if (pPE_OPTIONAL_HEADER->Magic == 0x20B)
	{
		printf("该文件是64Bit PE文件.\r\n");
	}
	if ((pPE_OPTIONAL_HEADER->Magic != 0x10B) && (pPE_OPTIONAL_HEADER->Magic != 0x20B))
	{
		printf("该文件既不是32Bit PE文件也不是64Bit PE文件\r\n");
	}
	//MajorLinkerVersion
	printf("MajorLinkerVersion:%x\r\n", pPE_OPTIONAL_HEADER->MajorLinkerVersion);
	//MinorLinkerVersion
	printf("MinorLinkerVersion:%x\r\n", pPE_OPTIONAL_HEADER->MinorLinkerVersion);
	//SizeOfCode
	printf("SizeOfCode:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfCode);
	//SizeOfInitializedData
	printf("SizeOfInitializedData:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfInitializedData);
	//SizeOfUninitializedData
	printf("SizeOfUninitializedData:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfUninitializedData);
	//AddressOfEntryPoint
	printf("AddressOfEntryPoint:%x\r\n", pPE_OPTIONAL_HEADER->AddressOfEntryPoint);
	//BaseOfCode
	printf("BaseOfCode:%x\r\n", pPE_OPTIONAL_HEADER->BaseOfCode);
	//BaseOfData
	printf("BaseOfData:%x\r\n", pPE_OPTIONAL_HEADER->BaseOfData);
	//ImageBase
	printf("ImageBase:%x\r\n", pPE_OPTIONAL_HEADER->ImageBase);
	//SectionAlignment
	printf("SectionAlignment:%x\r\n", pPE_OPTIONAL_HEADER->SectionAlignment);
	//FileAlignment
	printf("FileAlignment:%x\r\n", pPE_OPTIONAL_HEADER->FileAlignment);
	//MajorOperatingSystemVersion
	printf("MajorOperatingSystemVersion:%x\r\n", pPE_OPTIONAL_HEADER->MajorOperatingSystemVersion);
	//MinorOperatingSystemVersion
	printf("MinorOperatingSystemVersion:%x\r\n", pPE_OPTIONAL_HEADER->MinorOperatingSystemVersion);
	//MajorImageVersion
	printf("MajorImageVersion:%x\r\n", pPE_OPTIONAL_HEADER->MajorImageVersion);
	//MinorImageVersion
	printf("MinorImageVersion:%x\r\n", pPE_OPTIONAL_HEADER->MinorImageVersion);
	//MajorSubsystemVersion
	printf("MajorSubsystemVersion:%x\r\n", pPE_OPTIONAL_HEADER->MajorSubsystemVersion);
	//MinorSubsystemVersion
	printf("MinorSubsystemVersion:%x\r\n", pPE_OPTIONAL_HEADER->MinorSubsystemVersion);
	//Win32VersionValue
	printf("Win32VersionValue:%x\r\n", pPE_OPTIONAL_HEADER->Win32VersionValue);
	//SizeOfImage
	printf("SizeOfImage:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfImage);
	//SizeOfHeaders
	printf("SizeOfHeaders:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfHeaders);
	//CheckSum
	printf("CheckSum:%x\r\n", pPE_OPTIONAL_HEADER->CheckSum);
	//Subsystem
	printf("Subsystem:%x\r\n", pPE_OPTIONAL_HEADER->Subsystem);
	//DllCharacteristics
	printf("DllCharacteristics:%x\r\n", pPE_OPTIONAL_HEADER->DllCharacteristics);
	//SizeOfStackReserve
	printf("SizeOfStackReserve:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfStackReserve);
	//SizeOfStackCommit
	printf("SizeOfStackCommit:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfStackCommit);
	//SizeOfHeapReserve
	printf("SizeOfHeapReserve:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfHeapReserve);
	//SizeOfHeapCommit
	printf("SizeOfHeapCommit:%x\r\n", pPE_OPTIONAL_HEADER->SizeOfHeapCommit);
	//LoaderFlags
	printf("LoaderFlags:%x\r\n", pPE_OPTIONAL_HEADER->LoaderFlags);
	//NumberOfRvaAndSizes
	printf("NumberOfRvaAndSizes:%x\r\n", pPE_OPTIONAL_HEADER->NumberOfRvaAndSizes);

RET:
	return;
}

void fnPrintPE_SECTION_HEADER_Info(PE_IMAGE_SECTION_HEADER* pPE_IMAGE_SECTION_HEADER, int nNumberOfSection){
	char szSectionName[9] = { 0 };
	int i = 0;
	int nTest = sizeof(PE_IMAGE_SECTION_HEADER);

	if (pPE_IMAGE_SECTION_HEADER == NULL)
	{
		if (__DEBUG)
		{
			printf("pPE_IMAGE_SECTION_HEADER为NULL.\r\n");
		}
		goto RET;
	}

	printf("**************************开始打印PE_IMAGE_SECTION_HEADER******************\r\n");
	
	for (i = 0; i < nNumberOfSection; pPE_IMAGE_SECTION_HEADER++, i++){
		printf("************SectionHeader %x*************\r\n", i + 1);
	
		memset((void*)szSectionName, 0x0, sizeof(szSectionName));
		//Name
		memcpy(szSectionName, pPE_IMAGE_SECTION_HEADER->Name, sizeof(pPE_IMAGE_SECTION_HEADER->Name));
		printf("Name:%s\r\n", szSectionName);
		//Misc
		printf("Misc:%x\r\n", pPE_IMAGE_SECTION_HEADER->Misc);
		//VirtualAddress
		printf("VirtualAddress:%x\r\n", pPE_IMAGE_SECTION_HEADER->VirtualAddress);
		//SizeOfRawData;
		printf("SizeOfRawData:%x\r\n", pPE_IMAGE_SECTION_HEADER->SizeOfRawData);
		//PointerToRawData;
		printf("PointerToRawData:%x\r\n", pPE_IMAGE_SECTION_HEADER->PointerToRawData);
		//PointerToRelocations;
		printf("PointerToRelocations:%x\r\n", pPE_IMAGE_SECTION_HEADER->PointerToRelocations);
		//PointerToLinenumbers;
		printf("PointerToLinenumbers:%x\r\n", pPE_IMAGE_SECTION_HEADER->PointerToLinenumbers);
		//NumberOfRelocations;
		printf("NumberOfRelocations:%x\r\n", pPE_IMAGE_SECTION_HEADER->NumberOfRelocations);
		//NumberOfLinenumbers;
		printf("NumberOfLinenumbers:%x\r\n", pPE_IMAGE_SECTION_HEADER->NumberOfLinenumbers);
		//Characteristics;
		printf("Characteristics:%x\r\n", pPE_IMAGE_SECTION_HEADER->Characteristics);

	}
	printf("**********************PE_IMAGE_SECTION_HEADER打印结束***************************\r\n");

RET:
	return;
}