#include "stdAfx.h"
#include "File_Operation.h"
#include "PE_File_Structure.h"

//����PE_DOS_HEADER
PE_DOS_HEADER* pPE_DOS_HEADER;

//����PE_NT_HEADER
PE_NT_HEADER* pPE_NT_HEADER;

//����PE_OPTIONAL_HEADER
PE_OPTIONAL_HEADER* pPE_OPTIONAL_HEADER;

//����PE_FILE_HEADER
PE_FILE_HEADER* pPE_FILE_HEADER;

PE_IMAGE_SECTION_HEADER* pPE_IMAGE_SECTION_HEADER;

int main(int argc,char* argv[]){
	void* pFileBuffer = NULL;
	unsigned unFileSize = 0;
	bool blStatus = false;

	blStatus = fnReadFileToMemory("c:\\windows\\system32\\notepad.exe", NULL, &unFileSize);
	if (blStatus != true){
		if (__DEBUG){
			printf("�õ�FileBufferʧ�ܡ�\r\n");;
		}
		goto RET;
	}
	pFileBuffer = malloc(unFileSize * sizeof(char));
	if (pFileBuffer == NULL){
		if (__DEBUG){
			printf("����FileBuffer�ڴ�ռ�ʧ��.\r\n");
		}
		goto RET;
	}

	memset(pFileBuffer, 0x0, unFileSize);

	blStatus = fnReadFileToMemory("C:\\windows\\system32\\notepad.exe", pFileBuffer, &unFileSize);

	if (blStatus != TRUE)
	{
		if (__DEBUG)
		{
			printf("��ȡ�ļ�ʧ�ܡ�\r\n");
		}
		goto RET;
	}

	pPE_DOS_HEADER = (PE_DOS_HEADER*)pFileBuffer;
	blStatus = fnBlIsVailWindowsExecutiveFile(pPE_DOS_HEADER);
	if (blStatus != true){
		if (__DEBUG){
			printf("������Ч��PE�ļ���\r\n");
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
			printf("������Ч��NTͷ��ַ�����߲�����Ч��PE�ļ���\r\n");
		}
		goto RET;
	}
	//��ӡPE_FILE_HEADER����Ϣ
	fnPrintPE_NT_HEADER_Info(pPE_NT_HEADER);

	//�õ�PE_FILE_HEADER�ĵ�ַ
	pPE_FILE_HEADER = (PE_FILE_HEADER*)((int)pPE_NT_HEADER + sizeof(DWORD));

	//��ӡPE_FILE_HEADER����Ϣ
	fnPrintPE_FILE_HEADER_Info(pPE_FILE_HEADER);

	//�õ�PE_OPTIONAL_HEADER����Ϣ
	pPE_OPTIONAL_HEADER = ( PE_OPTIONAL_HEADER *)((int)pPE_FILE_HEADER + (sizeof(DWORD)* 3 + sizeof(WORD)* 4));

	//��ӡPE_OPTIONAL_HEADER����Ϣ
	fnPrintPE_OPTIONAL_HEADER_Info(pPE_OPTIONAL_HEADER);

	//��ȡSECTION_HEADER�ĳ�ʼ��ַ
	pPE_IMAGE_SECTION_HEADER = (PE_IMAGE_SECTION_HEADER *)((int)(&pPE_NT_HEADER->OptionalHeader) + pPE_NT_HEADER->FileHeader.SizeOfOptionalHeader);
	//��ӡSECTION_HEADER��ֵ
	fnPrintPE_SECTION_HEADER_Info(pPE_IMAGE_SECTION_HEADER, pPE_NT_HEADER->FileHeader.NumberOfSections);

RET:
	if (pFileBuffer != NULL)
	{
		free(pFileBuffer);
		pFileBuffer = NULL;
	}

	return 0;
}