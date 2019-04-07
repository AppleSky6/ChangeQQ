// Precise.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include "windows.h"

// 好友防撤回偏移 bytes_reserved
/*	
	83C4 20 | add esp, 20 
	33FF    | xor edi, edi 
	897D F4 | mov dword ptr ss : [ebp - C], edi 
	8B06    | mov eax, dword ptr ds : [esi] 
*/
const unsigned char reserved_flag[10] = { 0x83, 0xC4, 0x20, 0x33, 0xFF, 0x89, 0x7D, 0xF4, 0x8B, 0x06 };

/*
	EB 06	| jmp im.6C07E815 跳过重定位数据
	90		| nop
	90		| nop
	90		| nop
	90		| nop
	90		| nop
	90		| nop
	33C0	| xor eax, eax   返回值设置为成功
*/
const unsigned char reserved_jmp[10] = { 0xEB, 0x06, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x33, 0xC0 };

// 群消息防撤回 bytes_userdef
/*
	83C4 1C         | add esp,1C
	E9 9D000000     | jmp im.6B5AE6F1
	8B45 F0         | mov eax,dword ptr ss:[ebp-10]
	8D55 EC         | lea edx,dword ptr ss:[ebp-14]           |=
*/
const unsigned char userdef_flag[14] = { 0x83, 0xC4, 0x1C, 0xE9, 0x9D, 0x00, 0x00, 0x00, 0x8B, 0x45, 0xF0, 0x8D, 0x55, 0xEC };

/*
	EB 07	| jmp im.6B79E665 跳过重定位数据
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
	33C0	| xor eax, eax 返回值设置为成功
*/
const unsigned char userdef_jmp[15] = { 0xEB, 0x07, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x89, 0x5D, 0xEC, 0x90, 0x33, 0xC0 };

//  二进制查找
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
			return i;	// 找到返回离Dest的距离(从0开始计算)
	}
	return -1;		// 未找到返回-1
}


int main(int argc, char *argv[])
{
	DWORD dwFileSize = NULL;
	HANDLE hFILE = NULL;
	byte* byQQBuf = nullptr;
	DWORD reserved_address = NULL;
	DWORD userdef_address = NULL;
	DWORD dwWrite = NULL;

	do 
	{
		if (!strstr(argv[1], "IM.dll"))
		{
			printf("[Dbg]：INVALID QQ File,Please open IM.dll\n");
			break;
		}

		hFILE = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFILE == INVALID_HANDLE_VALUE)
		{
			printf("[Dbg]：CreateFile error\n");
			return 0;
		}

		dwFileSize = GetFileSize(hFILE, NULL);
		if (dwFileSize == NULL)
		{
			printf("[Dbg]：GetFileSize error\n");
			break;
		}

		byQQBuf = (byte*)malloc(dwFileSize + 1024);
		if (byQQBuf == nullptr)
		{
			printf("[Dbg]：Get memory error\n");
			break;
		}

		if (!ReadFile(hFILE, byQQBuf, dwFileSize, &dwFileSize, NULL))
		{
			printf("[Dbg]：ReadFile error\n");
			break;
		}

		//好友防撤回
		reserved_address = BinaryFind(byQQBuf, dwFileSize, reserved_flag, sizeof(reserved_flag));
		if (reserved_address == -1)
		{
			printf("[Dbg]：BinaryFind error\n");
			break;
		}

		if (SetFilePointer(hFILE, reserved_address + sizeof(reserved_flag), NULL, FILE_BEGIN) == -1)
		{
			printf("SetFilePointer error\n");
			break;
		}

		if (!WriteFile(hFILE, reserved_jmp, sizeof(reserved_jmp), &dwWrite, NULL))
		{
			printf("[Dbg]：WriteFile error\n");
			break;
		}

		//群消息防撤回
		userdef_address = BinaryFind(byQQBuf, dwFileSize, userdef_flag, sizeof(userdef_flag));
		if (userdef_address == -1)
		{
			printf("[Dbg]：BinaryFind error\n");
			break;
		}

		if (SetFilePointer(hFILE, userdef_address + sizeof(userdef_flag), NULL, FILE_BEGIN) == -1)
		{
			printf("SetFilePointer error\n");
			break;
		}

		if (!WriteFile(hFILE, userdef_jmp, sizeof(userdef_jmp), &dwWrite, NULL))
		{
			printf("[Dbg]：WriteFile error\n");
			break;
		}
		printf("[Dbg]：change IM.dll success\n");
		break;
	} while (TRUE);

	CloseHandle(hFILE);
	return 0;
}

