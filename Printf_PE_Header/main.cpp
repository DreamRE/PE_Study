#include "stdAfx.h"
#include "File_Operation.h"
#include "PE_File_Structure.h"

//定义PE_DOS_HEADER
PE_DOS_HEADER* pPE_DOS_HEADER;

//定义PE_NT_HEADER
PE_NT_HEADER* pPE_NT_HEADER;

//定义PE_OPTIONAL_HEADER
PE_OPTIONAL_HEADER* pPE_OPTIONAL_HEADER;

//定义PE_FILE_HEADER
PE_FILE_HEADER* pPE_FILE_HEADER;

PE_IMAGE_SECTION_HEADER* pPE_IMAGE_SECTION_HEADER;

int main(int argc,char* argv[]){
	void* pFileBuffer = NULL;
	unsigned unFileSize = 0;
	bool blStatus = false;

	blStatus = fnReadFileToMemory("c:\\windows\\system32\\notepad.exe", NULL, &unFileSize);
	if (blStatus != true){
		if (__DEBUG){
			printf("得到FileBuffer失败。\r\n");;
		}
		goto RET;
	}
	pFileBuffer = malloc(unFileSize * sizeof(char));
	if (pFileBuffer == NULL){
		if (__DEBUG){
			printf("分配FileBuffer内存空间失败.\r\n");
		}
		goto RET;
	}

	memset(pFileBuffer, 0x0, unFileSize);

	blStatus = fnReadFileToMemory("C:\\windows\\system32\\notepad.exe", pFileBuffer, &unFileSize);

	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("读取文件失败。\r\n");
		}
		goto RET;
	}

	pPE_DOS_HEADER = (PE_DOS_HEADER*)pFileBuffer;
	blStatus = fnBlIsVailWindowsExecutiveFile(pPE_DOS_HEADER);
	if (blStatus != true){
		if (__DEBUG){
			printf("不是有效的PE文件。\r\n");
		}
		goto RET;
	}

	fnPrintPE_DOS_HEADER_Info(pPE_DOS_HEADER);

	pPE_NT_HEADER = (PE_NT_HEADER*)((int)pFileBuffer + pPE_DOS_HEADER->e_lfanew);


	blStatus = fnBlVailNTHEADERAddress(pPE_NT_HEADER);
	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("不是有效的NT头地址，或者不是有效的PE文件。\r\n");
		}
		goto RET;
	}
	//打印PE_FILE_HEADER的信息
	fnPrintPE_NT_HEADER_Info(pPE_NT_HEADER);

	//得到PE_FILE_HEADER的地址
	pPE_FILE_HEADER = (PE_FILE_HEADER*)((int)pPE_NT_HEADER + sizeof(DWORD));

	//打印PE_FILE_HEADER的信息
	fnPrintPE_FILE_HEADER_Info(pPE_FILE_HEADER);

	//得到PE_OPTIONAL_HEADER的信息
	pPE_OPTIONAL_HEADER = ( PE_OPTIONAL_HEADER *)((int)pPE_FILE_HEADER + (sizeof(DWORD)* 3 + sizeof(WORD)* 4));

	//打印PE_OPTIONAL_HEADER的信息
	fnPrintPE_OPTIONAL_HEADER_Info(pPE_OPTIONAL_HEADER);

	//获取SECTION_HEADER的初始地址
	pPE_IMAGE_SECTION_HEADER = (PE_IMAGE_SECTION_HEADER *)((int)(&pPE_NT_HEADER->OptionalHeader) + pPE_NT_HEADER->FileHeader.SizeOfOptionalHeader);
	//打印SECTION_HEADER的值
	fnPrintPE_SECTION_HEADER_Info(pPE_IMAGE_SECTION_HEADER, pPE_NT_HEADER->FileHeader.NumberOfSections);

RET:
	if (pFileBuffer != NULL)
	{
		free(pFileBuffer);
		pFileBuffer = NULL;
	}

	return 0;
}