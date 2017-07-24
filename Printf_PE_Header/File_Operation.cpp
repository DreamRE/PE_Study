#include "stdAfx.h"
#include "File_Operation.h"

CFileOperation::CFileOperation(){

}

CFileOperation::~CFileOperation(){

}

bool fnReadFileToMemory(char* path,void* pReturnBuffer,unsigned int* punFileSize){
	FILE* stream;
	unsigned int unError = 0;
	void* pBuffer = NULL;

	//1.���ļ�
	stream = fopen(path, "rb");
	if (NULL == stream){
		if (__DEBUG){
			printf("���ļ�����");
		}
		return false;
	}
	//2.�ƶ��ļ�ָ�����ļ�β�������ļ���С
	unError = fseek(stream, 0, SEEK_END);
	if (unError != NULL){
		fclose(stream);
		if (__DEBUG){
			printf("Ѱ���ļ�β����\r\n");
		}
		return false;
	}
	
	(*punFileSize) = ftell(stream);
	if ((*punFileSize) < 0){
		fclose(stream);
		if (__DEBUG){
			printf("�õ��ļ���С���󣡴�����룺%d\r\n", (*punFileSize));
		}
		return false;
	}

	unError = fseek(stream, 0, SEEK_SET);
	if (unError != NULL){
		fclose(stream);
		if (__DEBUG != NULL){
			printf("Ѱ���ļ��״���\r\n");
		}
		return false;
	}

	//3.Ϊ����������ռ䲢��ʼ��
	pBuffer = malloc((*punFileSize) * sizeof(char));
	if (pBuffer == NULL){
		fclose(stream);
		if (__DEBUG){
			printf("�����ļ�ʧ�ܣ�\r\n");
		}
		return false;
	}
	memset(pBuffer, 0x0, *(punFileSize)* sizeof(char));

	//4.�������������ݶ����ڴ�
	unError = fread(pBuffer, sizeof(char), *(punFileSize), stream);

	if (unError != *(punFileSize)){
		free(pBuffer);
		fclose(stream);
		if (__DEBUG){
			printf("��ȡ�ļ����󣬴������Ϊ��%d\r\n",ferror(stream));
		}
		return false;
	}

	if (pReturnBuffer != NULL){
		memcpy(pReturnBuffer, pBuffer, *punFileSize);
	}

	//5.�ر��ļ���
	unError = fclose(stream);
	if (unError != NULL){
		free(pBuffer);
		if (__DEBUG){
			printf("�ر��ļ���ʧ�ܣ��������:%d.\r\n", unError);
		}
		return false;
	}

	free(pBuffer);
	stream = NULL;

	return true;
}

bool fnWriteFileFromMemory(char* path,void* pBuffer,unsigned int unFileSize){
	FILE* stream = NULL;
	unsigned int unError = 0;

	//1.���ļ�����������������
	stream = fopen(path, "w+b");
	if (stream == NULL){
		if (__DEBUG){
			printf("�����ļ�ʧ�ܣ�\r\n");
		}
		return false;
	}

	//2.��buffer������д���ļ�
	unError = fwrite(pBuffer, sizeof(char), unFileSize, stream);
	if (unError != unFileSize){
		if (__DEBUG){
			printf("д���ļ�ʧ�ܣ�\r\n");
		}
		return false;
	}

	//3.�ر��ļ�
	unError = fclose(stream);
	if (unError != NULL){
		free(pBuffer);
		if (__DEBUG){
			printf("�ر��ļ���ʧ�ܣ��������:%d.\r\n", unError);
		}
		return false;
	}

	free(pBuffer);
	return true;
}