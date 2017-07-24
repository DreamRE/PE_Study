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

	//1.打开文件
	stream = fopen(path, "rb");
	if (NULL == stream){
		if (__DEBUG){
			printf("打开文件出错！");
		}
		return false;
	}
	//2.移动文件指针至文件尾，计算文件大小
	unError = fseek(stream, 0, SEEK_END);
	if (unError != NULL){
		fclose(stream);
		if (__DEBUG){
			printf("寻找文件尾错误。\r\n");
		}
		return false;
	}
	
	(*punFileSize) = ftell(stream);
	if ((*punFileSize) < 0){
		fclose(stream);
		if (__DEBUG){
			printf("得到文件大小错误！错误代码：%d\r\n", (*punFileSize));
		}
		return false;
	}

	unError = fseek(stream, 0, SEEK_SET);
	if (unError != NULL){
		fclose(stream);
		if (__DEBUG != NULL){
			printf("寻找文件首错误！\r\n");
		}
		return false;
	}

	//3.为缓冲区分配空间并初始化
	pBuffer = malloc((*punFileSize) * sizeof(char));
	if (pBuffer == NULL){
		fclose(stream);
		if (__DEBUG){
			printf("分配文件失败！\r\n");
		}
		return false;
	}
	memset(pBuffer, 0x0, *(punFileSize)* sizeof(char));

	//4.将缓冲区中数据读入内存
	unError = fread(pBuffer, sizeof(char), *(punFileSize), stream);

	if (unError != *(punFileSize)){
		free(pBuffer);
		fclose(stream);
		if (__DEBUG){
			printf("读取文件错误，错误代码为：%d\r\n",ferror(stream));
		}
		return false;
	}

	if (pReturnBuffer != NULL){
		memcpy(pReturnBuffer, pBuffer, *punFileSize);
	}

	//5.关闭文件流
	unError = fclose(stream);
	if (unError != NULL){
		free(pBuffer);
		if (__DEBUG){
			printf("关闭文件流失败，错误代码:%d.\r\n", unError);
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

	//1.打开文件流，若不存在则建立
	stream = fopen(path, "w+b");
	if (stream == NULL){
		if (__DEBUG){
			printf("建立文件失败！\r\n");
		}
		return false;
	}

	//2.将buffer中内容写入文件
	unError = fwrite(pBuffer, sizeof(char), unFileSize, stream);
	if (unError != unFileSize){
		if (__DEBUG){
			printf("写入文件失败！\r\n");
		}
		return false;
	}

	//3.关闭文件
	unError = fclose(stream);
	if (unError != NULL){
		free(pBuffer);
		if (__DEBUG){
			printf("关闭文件流失败，错误代码:%d.\r\n", unError);
		}
		return false;
	}

	free(pBuffer);
	return true;
}