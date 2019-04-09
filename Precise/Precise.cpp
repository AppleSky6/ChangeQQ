// Precise.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include "windows.h"

#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"Shell32.lib")

// ���ѷ�����ƫ�� bytes_reserved
/*	
	83C4 20 | add esp, 20 
	33FF    | xor edi, edi 
	897D F4 | mov dword ptr ss : [ebp - C], edi 
	8B06    | mov eax, dword ptr ds : [esi] 
*/
const unsigned char reserved_flag[10] = { 0x83, 0xC4, 0x20, 0x33, 0xFF, 0x89, 0x7D, 0xF4, 0x8B, 0x06 };

/*
	EB 06	| jmp im.6C07E815 �����ض�λ����
	90		| nop
	90		| nop
	90		| nop
	90		| nop
	90		| nop
	90		| nop
	33C0	| xor eax, eax   ����ֵ����Ϊ�ɹ�
*/
const unsigned char reserved_jmp[10] = { 0xEB, 0x06, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x33, 0xC0 };

// Ⱥ��Ϣ������ bytes_userdef
/*
	83C4 1C         | add esp,1C
	E9 9D000000     | jmp im.6B5AE6F1
	8B45 F0         | mov eax,dword ptr ss:[ebp-10]
	8D55 EC         | lea edx,dword ptr ss:[ebp-14]           |=
*/
const unsigned char userdef_flag[14] = { 0x83, 0xC4, 0x1C, 0xE9, 0x9D, 0x00, 0x00, 0x00, 0x8B, 0x45, 0xF0, 0x8D, 0x55, 0xEC };

/*
	EB 07	| jmp im.6B79E665 �����ض�λ����
	90		| nop
	90		| nop
	90		| nop
	90		| nop
	90		| nop
	90		| nop
	90		| nop
	90		| nop
	90		| nop
	90		| nop
	90		| nop
	33C0	| xor eax, eax ����ֵ����Ϊ�ɹ�
*/
const unsigned char userdef_jmp[15] = { 0xEB, 0x07, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x89, 0x5D, 0xEC, 0x90, 0x33, 0xC0 };

//  �����Ʋ���
int BinaryFind(const unsigned char * Dest, int DestLen,
	const unsigned char * Src, int SrcLen)
{
	int j = 0;
	for (int i = 0; i < DestLen; i++)
	{
		for (j = 0; j < SrcLen; j++)
			if (Dest[i + j] != Src[j])
				break;
		if (j == SrcLen)
			return i;	// �ҵ�������Dest�ľ���(��0��ʼ����)
	}
	return -1;		// δ�ҵ�����-1
}

BOOL read_path(const char* REGPath, char* strPath)//��ȡע���
{
	HKEY hKEY;//�����йصļ����ڲ�ѯ����ʱ�ر�  
	DWORD dwSize = 256;
	DWORD dwType = REG_SZ;

	//����ע���hKEY�򱣴�˺������򿪵ļ��ľ��  
	if (ERROR_SUCCESS == ::RegOpenKeyExA(HKEY_LOCAL_MACHINE, REGPath, 0, KEY_READ, &hKEY))
	{


		if (RegQueryValueExA(hKEY, "Install", 0, &dwType, (LPBYTE)strPath, &dwSize) != ERROR_SUCCESS)
		{
			RegCloseKey(hKEY);
			printf("[Dbg]��Get QQ path error \n");
			return FALSE;
		}
		::RegCloseKey(hKEY);
		return TRUE;
	}
	printf("[Dbg]��Get QQ path error \n");
	return FALSE;
}

BOOL path_qq(HANDLE hFILE)//path qq
{
	DWORD dwFileSize = NULL;
	byte* byQQBuf = nullptr;
	DWORD reserved_address = NULL;
	DWORD userdef_address = NULL;
	DWORD dwWrite = NULL;

	do
	{
		dwFileSize = GetFileSize(hFILE, NULL);
		if (dwFileSize == NULL)
		{
			printf("[Dbg]��GetFileSize error\n");
			break;
		}

		byQQBuf = (byte*)malloc(dwFileSize + 1024);
		if (byQQBuf == nullptr)
		{
			printf("[Dbg]��Get memory error\n");
			break;
		}

		if (!ReadFile(hFILE, byQQBuf, dwFileSize, &dwFileSize, NULL))
		{
			printf("[Dbg]��ReadFile error\n");
			break;
		}

		//���ѷ�����
		reserved_address = BinaryFind(byQQBuf, dwFileSize, reserved_flag, sizeof(reserved_flag));
		if (reserved_address == -1)
		{
			printf("[Dbg]��BinaryFind error\n");
			break;
		}

		if (SetFilePointer(hFILE, reserved_address + sizeof(reserved_flag), NULL, FILE_BEGIN) == -1)
		{
			printf("SetFilePointer error\n");
			break;
		}

		if (!WriteFile(hFILE, reserved_jmp, sizeof(reserved_jmp), &dwWrite, NULL))
		{
			printf("[Dbg]��WriteFile error\n");
			break;
		}

		//Ⱥ��Ϣ������
		userdef_address = BinaryFind(byQQBuf, dwFileSize, userdef_flag, sizeof(userdef_flag));
		if (userdef_address == -1)
		{
			printf("[Dbg]��BinaryFind error\n");
			break;
		}

		if (SetFilePointer(hFILE, userdef_address + sizeof(userdef_flag), NULL, FILE_BEGIN) == -1)
		{
			printf("SetFilePointer error\n");
			break;
		}

		if (!WriteFile(hFILE, userdef_jmp, sizeof(userdef_jmp), &dwWrite, NULL))
		{
			printf("[Dbg]��WriteFile error\n");
			break;
		}
		printf("[Dbg]��change IM.dll success\n");
		delete byQQBuf;
		return TRUE;

	} while (TRUE);

	delete byQQBuf;
	return FALSE;
}


int main(int argc, char *argv[])
{
	const char* QQREGPath = "SOFTWARE\\Tencent\\QQ2009";
	const char* TIMREGPath = "SOFTWARE\\Tencent\\TIM";

	char QQPath[MAX_PATH] = { 0 };
	char TIMPath[MAX_PATH] = { 0 };

	HANDLE hFILE = NULL;

	
	

	if (read_path(QQREGPath, QQPath))//��ȡQQע���
	{
		ShellExecuteA(NULL, "open", "taskkill.exe", "/im QQ.exe", NULL, SW_HIDE);

		strcat_s(QQPath, "\\Bin\\IM.dll");
		hFILE = CreateFileA(QQPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFILE == INVALID_HANDLE_VALUE)
		{
			printf("[Dbg]��CreateFile QQ error\n");
		}
		else
		{
			path_qq(hFILE);
			CloseHandle(hFILE);
		}
	}

	if (read_path(TIMREGPath, TIMPath))//��ȡTIMע���
	{
		ShellExecuteA(NULL, "open", "taskkill.exe", "/im TIM.exe", NULL, SW_HIDE);

		strcat_s(TIMPath, "\\Bin\\IM.dll");
		hFILE = CreateFileA(TIMPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFILE == INVALID_HANDLE_VALUE)
		{
			printf("[Dbg]��CreateFile TIM error\n");
		}
		else
		{
			path_qq(hFILE);
			CloseHandle(hFILE);
		}
	}

	return 0;
}

