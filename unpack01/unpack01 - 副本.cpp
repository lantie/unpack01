// unpack01.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#include <iostream>
#include <windows.h>
#pragma comment(lib,"user32")

DWORD InitProcessData(HANDLE hProcess);
DWORD FindProcessOEP(HANDLE hProcess, BYTE* pbyCode, DWORD codeLen);

DWORD OnCreateThreadDebugEvent(const LPDEBUG_EVENT) { return DBG_CONTINUE; }
DWORD OnCreateProcessDebugEvent(const LPDEBUG_EVENT);
DWORD OnExitThreadDebugEvent(const LPDEBUG_EVENT) { return DBG_CONTINUE; }
DWORD OnExitProcessDebugEvent(const LPDEBUG_EVENT) { return DBG_CONTINUE; }
DWORD OnLoadDllDebugEvent(const LPDEBUG_EVENT) { return DBG_CONTINUE; }
DWORD OnUnloadDllDebugEvent(const LPDEBUG_EVENT) { return DBG_CONTINUE; }
DWORD OnOutputDebugStringEvent(const LPDEBUG_EVENT) { return DBG_CONTINUE; }
DWORD OnRipEvent(const LPDEBUG_EVENT) { return 0; }


HANDLE g_hThread;
HANDLE g_hProcess;
DWORD g_dwProcessId = 0;
DWORD g_dwThreadId = 0;
DWORD g_dwImageBase = 0;
DWORD g_dwCodeBase = 0;
DWORD g_dwCodeSize = 0;
BYTE g_byCode[] = { 0x6A,0x00,0x39,0xC4,0x75,0xFA,0x83,0xEC,0x80 };
DWORD g_codeLen = 9;
DWORD g_dwEP = 0;
DWORD g_dwOEP = 0;

typedef struct _DBG_REG6
{
	/*
	//     断点命中标志位，如果位于DR0~3的某个断点被命中，则进行异常处理前，对应
	// 的B0~3就会被置为1。
	*/
	unsigned B0 : 1;  // Dr0断点触发置位
	unsigned B1 : 1;  // Dr1断点触发置位
	unsigned B2 : 1;  // Dr2断点触发置位
	unsigned B3 : 1;  // Dr3断点触发置位
					  /*
					  // 保留字段
					  */
	unsigned Reserve1 : 9;
	/*
	// 其它状态字段
	*/
	unsigned BD : 1;  // 调制寄存器本身触发断点后，此位被置为1
	unsigned BS : 1;  // 单步异常被触发，需要与寄存器EFLAGS的TF联合使用
	unsigned BT : 1;  // 此位与TSS的T标志联合使用，用于接收CPU任务切换异常
					  /*
					  // 保留字段
					  */
	unsigned Reserve2 : 16;
}DBG_REG6, *PDBG_REG6;

typedef struct _DBG_REG7
{
	/*
	// 局部断点(L0~3)与全局断点(G0~3)的标记位
	*/
	unsigned L0 : 1;  // 对Dr0保存的地址启用 局部断点
	unsigned G0 : 1;  // 对Dr0保存的地址启用 全局断点
	unsigned L1 : 1;  // 对Dr1保存的地址启用 局部断点
	unsigned G1 : 1;  // 对Dr1保存的地址启用 全局断点
	unsigned L2 : 1;  // 对Dr2保存的地址启用 局部断点
	unsigned G2 : 1;  // 对Dr2保存的地址启用 全局断点
	unsigned L3 : 1;  // 对Dr3保存的地址启用 局部断点
	unsigned G3 : 1;  // 对Dr3保存的地址启用 全局断点
					  /*
					  // 【以弃用】用于降低CPU频率，以方便准确检测断点异常
					  */
	unsigned LE : 1;
	unsigned GE : 1;
	/*
	// 保留字段
	*/
	unsigned Reserve1 : 3;
	/*
	// 保护调试寄存器标志位，如果此位为1，则有指令修改条是寄存器时会触发异常
	*/
	unsigned GD : 1;
	/*
	// 保留字段
	*/
	unsigned Reserve2 : 2;
	/*
	// 保存Dr0~Dr3地址所指向位置的断点类型(RW0~3)与断点长度(LEN0~3)，状态描述如下：
	*/
	unsigned RW0 : 2;  // 设定Dr0指向地址的断点类型
	unsigned LEN0 : 2;  // 设定Dr0指向地址的断点长度
	unsigned RW1 : 2;  // 设定Dr1指向地址的断点类型
	unsigned LEN1 : 2;  // 设定Dr1指向地址的断点长度
	unsigned RW2 : 2;  // 设定Dr2指向地址的断点类型
	unsigned LEN2 : 2;  // 设定Dr2指向地址的断点长度
	unsigned RW3 : 2;  // 设定Dr3指向地址的断点类型
	unsigned LEN3 : 2;  // 设定Dr3指向地址的断点长度
}DBG_REG7, *PDBG_REG7;
void SetBits(DWORD_PTR& dw, int lowBit, int bits, int newValue)
{
	DWORD_PTR mask = (1 << bits) - 1;
	dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
}
HANDLE SetHardwareBreakpoint(HANDLE hThread, void* s)
{
	int j = 0;
	int y = 0;
	CONTEXT ct = { 0 };
	int iReg = 0;

	//hThread = OpenThread(THREAD_ALL_ACCESS, 0, g_dwThreadId);
	// 挂起线程
	//j = SuspendThread(hThread);   
	//y = GetLastError();

	// 获取上下文环境
	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
	if (!GetThreadContext(hThread, &ct))
	{
		y = GetLastError();
		MessageBox(NULL, L"Fail", L"1", 1);
	}
	int FlagBit = 0;
	// 判断是否有设置断点
	bool Dr0Busy = ct.Dr0 != 0 ? true : false;
	bool Dr1Busy = ct.Dr1 != 0 ? true : false;
	bool Dr2Busy = ct.Dr2 != 0 ? true : false;
	bool Dr3Busy = ct.Dr3 != 0 ? true : false;
	if (ct.Dr7 & 1) //0位  0 local
		Dr0Busy = true;
	if (ct.Dr7 & 4) //2位  1 local
		Dr1Busy = true;
	if (ct.Dr7 & 16)//4位  2 local
		Dr2Busy = true;
	if (ct.Dr7 & 64)//6位  3 local
		Dr3Busy = true;

	if (!Dr0Busy)
	{
		iReg = 0;
		ct.Dr0 = (DWORD_PTR)s;  //地址
		Dr0Busy = true;
	}
	else if (!Dr1Busy)
	{
		iReg = 1;
		ct.Dr1 = (DWORD_PTR)s;
		Dr1Busy = true;
	}
	else if (!Dr2Busy)
	{
		iReg = 2;
		ct.Dr2 = (DWORD_PTR)s;
		Dr2Busy = true;
	}
	else if (!Dr3Busy)
	{
		iReg = 3;
		ct.Dr3 = (DWORD_PTR)s;
		Dr3Busy = true;
	}
	else
	{
		j = ResumeThread(hThread);
		y = GetLastError();
		return 0;
	}
	//ct.Dr6 = 0;
	int bpType = 0; // 执行断点
	
	int bpLen = 1;

	// 设置长度
	SetBits(ct.Dr7, 18 + iReg * 4, 2, bpLen);
	// 设置断点类型
	SetBits(ct.Dr7, 16 + iReg * 4, 2, bpType);
	// 设置断点存在标志
	SetBits(ct.Dr7, iReg * 2, 1, 1);

	// 设置断点
	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
	if (!SetThreadContext(hThread, &ct))
	{
		y = GetLastError();
		MessageBox(NULL, L"Fail", L"1", 1);
	}

	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
	if (!GetThreadContext(hThread, &ct))
	{
		y = GetLastError();
		MessageBox(NULL, L"Fail", L"1", 1);
	}

	//CloseHandle(hThread);

	// 恢复线程
	//j = ResumeThread(hThread);

	//y = GetLastError();
	return 0;
}
HANDLE DelHardwareBreakpoint(HANDLE hThread, DWORD dwAddr)
{
	int j = 0;
	int y = 0;
	CONTEXT ct = { 0 };
	int iReg = 0;

	// 挂起线程
	j = SuspendThread(hThread);
	y = GetLastError();

	// 获取上下文环境
	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
	if (!GetThreadContext(hThread, &ct))
	{
		y = GetLastError();
		MessageBox(NULL, L"Fail", L"1", 1);
	}
	int FlagBit = 0;
	// 判断是否有设置断点
	bool Dr0Busy = ct.Dr0 == dwAddr ? true : false;
	bool Dr1Busy = ct.Dr1 == dwAddr ? true : false;
	bool Dr2Busy = ct.Dr2 == dwAddr ? true : false;
	bool Dr3Busy = ct.Dr3 == dwAddr ? true : false;

	// 清空寄存器
	if (Dr0Busy)
	{
		iReg = 0;
		ct.Dr0 = 0;  //地址
		Dr0Busy = false;
	}
	else if (Dr1Busy)
	{
		iReg = 1;
		ct.Dr1 = 0;
		Dr1Busy = false;
	}
	else if (Dr2Busy)
	{
		iReg = 2;
		ct.Dr2 = 0;
		Dr2Busy = true;
	}
	else if (Dr3Busy)
	{
		iReg = 3;
		ct.Dr3 = 0;
		Dr3Busy = true;
	}
	else
	{
		j = ResumeThread(hThread);
		y = GetLastError();
		return 0;
	}
	//ct.Dr6 = 0;
	int bpType = 0; // 执行断点

	int bpLen = 0;

	// 设置长度
	SetBits(ct.Dr7, 18 + iReg * 4, 2, bpLen);
	// 设置断点类型
	SetBits(ct.Dr7, 16 + iReg * 4, 2, bpType);
	// 设置断点存在标志
	SetBits(ct.Dr7, iReg * 2, 1, 0);

	// 设置断点
	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
	if (!SetThreadContext(hThread, &ct))
	{
		y = GetLastError();
		MessageBox(NULL, L"Fail", L"1", 1);
	}

	// 恢复线程
	j = ResumeThread(hThread);

	y = GetLastError();
	return 0;
}



DWORD OnCreateProcessDebugEvent(const LPDEBUG_EVENT pEvent) 
{ 
	// 对程序入口点设置断点
	g_dwEP = (DWORD)(pEvent->u.CreateProcessInfo.lpStartAddress);
	g_hThread = pEvent->u.CreateProcessInfo.hThread;
	g_hProcess = pEvent->u.CreateProcessInfo.hProcess;
	g_dwImageBase = (DWORD)pEvent->u.CreateProcessInfo.lpBaseOfImage;

	InitProcessData(g_hProcess);
	g_dwOEP = FindProcessOEP(g_hProcess, g_byCode, g_codeLen);
	//g_dwOEP = 0x00409376;
	SetHardwareBreakpoint(g_hThread, (void*)g_dwEP);
	SetHardwareBreakpoint(g_hThread, (void*)g_dwOEP);

	return DBG_CONTINUE; 
}

DWORD OnExceptionSingleStep(const LPDEBUG_EVENT pEvent)
{
	DWORD dwExceptionAddr = (DWORD)(pEvent->u.Exception.ExceptionRecord.ExceptionAddress);

	if (g_dwEP == dwExceptionAddr) {
		DelHardwareBreakpoint(g_hThread, dwExceptionAddr);
	}
	else if (g_dwOEP == dwExceptionAddr) {
		DelHardwareBreakpoint(g_hThread, dwExceptionAddr);
	}
	return DBG_CONTINUE;
}

DWORD InitProcessData(HANDLE hProcess)
{
	DWORD dwAddr = 0;
	DWORD dwRead = 0;
	BYTE* pBuffer = new BYTE[0x400];
	memset(pBuffer, 0, 0x400);
	BOOL bRet = ReadProcessMemory(hProcess, (void*)g_dwImageBase, pBuffer, 0x400, &dwRead);
	if (bRet == -1) {
		MessageBox(NULL, L"Fail", L"1", 1);
		return 0;
	}
	// 解析结构体
	IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *)pBuffer;      //DOS头
	IMAGE_NT_HEADERS *pNtHeader = (IMAGE_NT_HEADERS *)(pBuffer+pDosHeader->e_lfanew);      //NT头
	IMAGE_OPTIONAL_HEADER32 *pOptionalHead = (IMAGE_OPTIONAL_HEADER32 *)(&pNtHeader->OptionalHeader);    //可选头
	//IMAGE_SECTION_HEADER *pSectonInfo = (IMAGE_SECTION_HEADER *)((LPBYTE)pOptionalHead + pNtHeader->FileHeader.SizeOfOptionalHeader);
	
	g_dwCodeBase = g_dwImageBase+ pOptionalHead->BaseOfCode;
	g_dwCodeSize = pOptionalHead->SizeOfCode;

	delete[] pBuffer;
	return 0;
}

// 6A0039C475FA83EC80 E9 4DE5FCFF
DWORD FindProcessOEP(HANDLE hProcess, BYTE* pbyCode, DWORD codeLen)
{
	DWORD dwAddr = 0;
	DWORD dwRead = 0;
	BYTE* pBuffer = new BYTE[g_dwCodeSize];
	memset(pBuffer,0, g_dwCodeSize);
	BOOL bRet = ReadProcessMemory(hProcess, (void*)g_dwCodeBase, pBuffer, g_dwCodeSize, &dwRead);
	if (bRet == -1) {
		MessageBox(NULL, L"Fail", L"1", 1);
		return 0;
	}
	DWORD dwOffset = 0;
	for (size_t i = 0; i < g_dwCodeSize; i++)
	{
		BOOL bFind = TRUE;
		DWORD j = 0;
		for (; j < codeLen; j++)
		{
			if (pBuffer[i+j] != pbyCode[j]) {
				bFind = FALSE;
			}
		}
		if (bFind) {
			dwOffset = i+ j;
			break;
		}
	}

	if (dwOffset)
	{
		DWORD dwEIP = g_dwCodeBase + dwOffset;
		DWORD dwData = *(DWORD*)(pBuffer + dwOffset+1);
		DWORD dwOEP = dwEIP + dwData + 5;

		delete[] pBuffer;
		return dwOEP;
	}

	delete[] pBuffer;
	return 0;
}


void EnterDebugLoop(const LPDEBUG_EVENT DebugEv)
{
	DWORD dwContinueStatus = DBG_CONTINUE; // exception continuation 

	for (;;)
	{
		// Wait for a debugging event to occur. The second parameter indicates
		// that the function does not return until a debugging event occurs. 

		WaitForDebugEvent(DebugEv, INFINITE);

		// Process the debugging event code. 

		switch (DebugEv->dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			// Process the exception code. When handling 
			// exceptions, remember to set the continuation 
			// status parameter (dwContinueStatus). This value 
			// is used by the ContinueDebugEvent function. 

			switch (DebugEv->u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_ACCESS_VIOLATION:
				// First chance: Pass this on to the system. 
				// Last chance: Display an appropriate error. 
				printf("EXCEPTION_ACCESS_VIOLATION\r\n");
				break;

			case EXCEPTION_BREAKPOINT:
				// First chance: Display the current 
				// instruction and register values. 
				printf("EXCEPTION_BREAKPOINT ExceptionAddress=%p\r\n", DebugEv->u.Exception.ExceptionRecord.ExceptionAddress);
				
				break;

			case EXCEPTION_DATATYPE_MISALIGNMENT:
				// First chance: Pass this on to the system. 
				// Last chance: Display an appropriate error. 
				printf("EXCEPTION_DATATYPE_MISALIGNMENT\r\n");
				break;

			case EXCEPTION_SINGLE_STEP:
				// First chance: Update the display of the 
				// current instruction and register values. 
				printf("EXCEPTION_BREAKPOINT  ExceptionAddress=%p\r\n", DebugEv->u.Exception.ExceptionRecord.ExceptionAddress);
				OnExceptionSingleStep(DebugEv);

				break;

			case DBG_CONTROL_C:
				// First chance: Pass this on to the system. 
				// Last chance: Display an appropriate error. 
				printf("DBG_CONTROL_C\r\n");
				break;

			default:
				// Handle other exceptions. 
				break;
			}

			break;

		case CREATE_THREAD_DEBUG_EVENT:
			// As needed, examine or change the thread's registers 
			// with the GetThreadContext and SetThreadContext functions; 
			// and suspend and resume thread execution with the 
			// SuspendThread and ResumeThread functions. 

			dwContinueStatus = OnCreateThreadDebugEvent(DebugEv);
			printf("CREATE_THREAD_DEBUG_EVENT\r\n");
			break;

		case CREATE_PROCESS_DEBUG_EVENT:
			// As needed, examine or change the registers of the
			// process's initial thread with the GetThreadContext and
			// SetThreadContext functions; read from and write to the
			// process's virtual memory with the ReadProcessMemory and
			// WriteProcessMemory functions; and suspend and resume
			// thread execution with the SuspendThread and ResumeThread
			// functions. Be sure to close the handle to the process image
			// file with CloseHandle.

			dwContinueStatus = OnCreateProcessDebugEvent(DebugEv);
			printf("CREATE_PROCESS_DEBUG_EVENT\r\n");
			break;

		case EXIT_THREAD_DEBUG_EVENT:
			// Display the thread's exit code. 

			dwContinueStatus = OnExitThreadDebugEvent(DebugEv);
			printf("EXIT_THREAD_DEBUG_EVENT\r\n");
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			// Display the process's exit code. 

			dwContinueStatus = OnExitProcessDebugEvent(DebugEv);
			printf("EXIT_PROCESS_DEBUG_EVENT\r\n");
			break;

		case LOAD_DLL_DEBUG_EVENT:
			// Read the debugging information included in the newly 
			// loaded DLL. Be sure to close the handle to the loaded DLL 
			// with CloseHandle.

			dwContinueStatus = OnLoadDllDebugEvent(DebugEv);

			//printf("LOAD_DLL_DEBUG_EVENT\r\n");
			break;

		case UNLOAD_DLL_DEBUG_EVENT:
			// Display a message that the DLL has been unloaded. 

			dwContinueStatus = OnUnloadDllDebugEvent(DebugEv);

			//printf("UNLOAD_DLL_DEBUG_EVENT\r\n");
			break;

		case OUTPUT_DEBUG_STRING_EVENT:
			// Display the output debugging string. 

			dwContinueStatus = OnOutputDebugStringEvent(DebugEv);
			break;

		case RIP_EVENT:
			dwContinueStatus = OnRipEvent(DebugEv);
			break;
		}

		// Resume executing the thread that reported the debugging event. 

		ContinueDebugEvent(DebugEv->dwProcessId,
			DebugEv->dwThreadId,
			dwContinueStatus);
	}
}

int main()
{
	DEBUG_EVENT DebugEv = {0};

	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi = { 0 };

	if (CreateProcess(
		TEXT("hello15pb-1.exe"),
		NULL,
		NULL,
		NULL,
		FALSE,
		DEBUG_ONLY_THIS_PROCESS | DEBUG_PROCESS,
		NULL,
		NULL,
		&si,
		&pi) == FALSE) {

		printf("CreateProcess failed\r\n");
		return -1;
	}
	g_hThread = pi.hThread;
	g_hProcess = pi.hProcess;
	g_dwProcessId = pi.dwProcessId;
	g_dwThreadId = pi.dwThreadId;
	EnterDebugLoop(&DebugEv);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

    return 0;
}

