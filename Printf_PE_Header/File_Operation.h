#if !defined(AFX_FILEOPERATION_H__4A1D7CBE_E4D6_48E8_A883_2F2D369D790F__INCLUDED_)
#define AFX_FILEOPERATION_H__4A1D7CBE_E4D6_48E8_A883_2F2D369D790F__INCLUDED_

#if _MSC_VER > 1000
#pragma once 
#endif

#include <malloc.h>
#include <memory.h>
#include <stdio.h>

class CFileOperation{
public :
	CFileOperation();
	~CFileOperation();
};

bool fnReadFileToMemory(char* path,
	void* pReturnBuffer,
	unsigned int* punFileSize
	);

bool fnWriteFileFromMemory(char* path,
	void* pBuffer,
	unsigned int unFileSize
	);

#endif