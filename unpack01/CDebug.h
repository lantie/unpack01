#pragma once

#include <windows.h>

class CDebug
{
public:
	CDebug();
	CDebug(char* pStrPath);
	~CDebug();

	void StartDebugLoop();

	void DumpMemory();
	void EnterDebugLoop(const LPDEBUG_EVENT DebugEv);

	DWORD FindProcessOEP(HANDLE hProcess, BYTE* pbyCode, DWORD codeLen);
	bool SaveFile(byte * buf, int len, const char * filename);

	BOOL SetHardwareBreakpoint(HANDLE hThread, DWORD dwAddr, DWORD dwDrIndex, UINT nType, UINT nLen);
	DWORD OnCreateProcessDebugEvent(const LPDEBUG_EVENT pEvent);
	DWORD OnExceptionSingleStep(const LPDEBUG_EVENT pEvent);
	DWORD InitProcessData(HANDLE hProcess);


	DEBUG_EVENT DebugEv = { 0 };

	STARTUPINFOA si = { 0 };

	PROCESS_INFORMATION pi = { 0 };

	char szDumpPath[MAX_PATH] = {0};
	char szStrPath[MAX_PATH] = {0};


	HANDLE m_hThread;
	HANDLE m_hProcess;
	DWORD m_dwProcessId = 0;
	DWORD m_dwThreadId = 0;
	DWORD m_dwImageBase = 0;
	DWORD m_dwCodeBase = 0;
	DWORD m_dwCodeSize = 0;
	DWORD m_dwImageSize = 0;
	BYTE m_byCode[9] = { 0x6A,0x00,0x39,0xC4,0x75,0xFA,0x83,0xEC,0x80 };// upx oepÌØÕ÷
	//BYTE m_byCode[11] = {0x61, 0x75, 0x08, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc2, 0x0c, 0x00 };// aspack oepÌØÕ÷

	DWORD m_codeLen = sizeof(m_byCode);
	DWORD m_dwEP = 0;
	DWORD m_dwOEP = 0;

};

