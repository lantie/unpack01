#include "CDebug.h"
#include "CFixImport.h"
#include <iostream>
#pragma comment(lib,"user32")

/************************************************************************
SetHardwareBreakpoint:
�����߳�Ӳ���ϵ�
hThread:    �߳̾��
dwAddr:     �ϵ��ַ
dwDrIndex:  Ӳ���Ĵ���(0~3)
nType:      �ϵ�����(0:ִ��,1:��ȡ,2:д��)
nLen:       ��д�ϵ����ݳ���(1,2,4)
/************************************************************************/
BOOL CDebug::SetHardwareBreakpoint(HANDLE hThread, DWORD dwAddr, DWORD dwDrIndex = 0, UINT nType = 0, UINT nLen = 1)
{
	BOOL bResult = FALSE;

	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (::GetThreadContext(hThread, &context))
	{
		DWORD dwDrFlags = context.Dr7;


		// ����drX�Ĵ���Ϊ�ϵ��ַ
		memcpy(((BYTE *)&context) + 4 + dwDrIndex * 4, &dwAddr, 4);

		// ����drX�Ĵ�����־��L0,L1,L2,L3
		dwDrFlags |= (DWORD)0x1 << (2 * dwDrIndex);

		// ��OD��д�ϵ�ʱ �����λ��,ִ��û��(��λҲ����-_-)
		dwDrFlags |= 0x100;

		//�Ƚ���Ӧ�Ĵ�����Ӧ4������λ����(�Ȼ�,�����,���������÷�����)[/COLOR] =.= ���ߵ�Сѧ��
		dwDrFlags |= (DWORD)0xF << (16 + 4 * dwDrIndex);
		dwDrFlags ^= (DWORD)0xF << (16 + 4 * dwDrIndex);


		//���öϵ�����,ִ��:00 ��ȡ:11 д��:01
		//��֪�ι�,����ʱ���ֲ�����11����01,��д����ʱ���������
		if (nType == 1)
			dwDrFlags |= (DWORD)0x3 << (16 + 4 * dwDrIndex);  //��ȡ
		else if (nType == 2)
			dwDrFlags |= (DWORD)0x1 << (16 + 4 * dwDrIndex);  //д��
															  //else if(nType==0) 													  //���ö�д�ϵ�ʱ���ݳ���
		if (nType != 0)
		{
			if (nLen == 2 && dwAddr % 2 == 0)
				dwDrFlags |= (DWORD)0x1 << (18 + 4 * dwDrIndex);  //2�ֽ�
			else if (nLen == 4 && dwAddr % 4 == 0)
				dwDrFlags |= (DWORD)0x3 << (18 + 4 * dwDrIndex);  //4�ֽ�
		}

		context.Dr7 = dwDrFlags;
		if (::SetThreadContext(hThread, &context)) bResult = TRUE;
	}
	return bResult;
}

DWORD CDebug::OnCreateProcessDebugEvent(const LPDEBUG_EVENT pEvent)
{
	// �Գ�����ڵ����öϵ�
	m_dwEP = (DWORD)(pEvent->u.CreateProcessInfo.lpStartAddress);
	m_hThread = pEvent->u.CreateProcessInfo.hThread;
	m_hProcess = pEvent->u.CreateProcessInfo.hProcess;
	m_dwImageBase = (DWORD)pEvent->u.CreateProcessInfo.lpBaseOfImage;

	// ��ȡOEP
	InitProcessData(m_hProcess);
	m_dwOEP = FindProcessOEP(m_hProcess, m_byCode, m_codeLen);
	if (m_dwOEP) {
		printf("Find OEP %08x\r\n", m_dwOEP);
	}
	else {
		printf("Not not Fount OEP %08x\r\n", m_dwOEP);
		ExitProcess(0);
	}
	//m_dwOEP = 0x00409376;
	//SetHardwareBreakpoint(m_hThread, m_dwEP);
	SetHardwareBreakpoint(m_hThread, m_dwOEP);

	return DBG_CONTINUE;
}

DWORD CDebug::OnExceptionSingleStep(const LPDEBUG_EVENT pEvent)
{
	DWORD dwExceptionAddr = (DWORD)(pEvent->u.Exception.ExceptionRecord.ExceptionAddress);

	if (m_dwEP == dwExceptionAddr) {
		//DelHardwareBreakpoint(m_hThread, dwExceptionAddr);
		printf("DelHardwareBreakpoint\r\n");
	}
	else if (m_dwOEP == dwExceptionAddr) {
		//DelHardwareBreakpoint(m_hThread, dwExceptionAddr);
		printf("Dump memory\r\n");
		DumpMemory();
		
		printf("Fix Dump memory\r\n");
		CFixImport obj(szDumpPath);
		obj.FixDump(m_dwProcessId, m_dwImageBase, m_dwImageSize, m_dwOEP);

		DeleteFileA(szDumpPath);
		ExitProcess(0);
	}
	return DBG_CONTINUE;
}

DWORD CDebug::InitProcessData(HANDLE hProcess)
{
	DWORD dwAddr = 0;
	DWORD dwRead = 0;
	BYTE* pBuffer = new BYTE[0x400];
	memset(pBuffer, 0, 0x400);
	BOOL bRet = ReadProcessMemory(hProcess, (void*)m_dwImageBase, pBuffer, 0x400, &dwRead);
	if (bRet == -1) {
		MessageBox(NULL, L"Fail", L"1", 1);
		return 0;
	}
	// �����ṹ��
	IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *)pBuffer;      //DOSͷ
	IMAGE_NT_HEADERS *pNtHeader = (IMAGE_NT_HEADERS *)(pBuffer + pDosHeader->e_lfanew);      //NTͷ
	IMAGE_OPTIONAL_HEADER32 *pOptionalHead = (IMAGE_OPTIONAL_HEADER32 *)(&pNtHeader->OptionalHeader);    //��ѡͷ
																										 //IMAGE_SECTION_HEADER *pSectonInfo = (IMAGE_SECTION_HEADER *)((LPBYTE)pOptionalHead + pNtHeader->FileHeader.SizeOfOptionalHeader);

	m_dwCodeBase = m_dwImageBase + pOptionalHead->BaseOfCode;
	m_dwCodeSize = pOptionalHead->SizeOfCode;
	m_dwImageSize = pOptionalHead->SizeOfImage;

	delete[] pBuffer;
	return 0;
}

// 6A0039C475FA83EC80 E9 4DE5FCFF
DWORD CDebug::FindProcessOEP(HANDLE hProcess, BYTE* pbyCode, DWORD codeLen)
{
	DWORD dwSize = m_dwImageSize;
	DWORD dwAddr = 0;
	DWORD dwRead = 0;
	BYTE* pBuffer = new BYTE[dwSize];
	memset(pBuffer, 0, dwSize);
	BOOL bRet = ReadProcessMemory(hProcess, (void*)m_dwImageBase, pBuffer, dwSize, &dwRead);
	int nErr = GetLastError();
	if (bRet == -1) {
		MessageBox(NULL, L"Fail", L"1", 1);
		return 0;
	}
	DWORD dwOffset = 0;
	for (size_t i = 0; i < dwSize; i++)
	{
		BOOL bFind = TRUE;
		DWORD j = 0;
		for (; j < codeLen; j++)
		{
			if (pBuffer[i + j] != pbyCode[j]) {
				bFind = FALSE;
			}
		}
		if (bFind) {
			dwOffset = i + j;
			break;
		}
	}

	if (dwOffset)
	{
		DWORD dwEIP = m_dwImageBase + dwOffset;
		BYTE byCode = *(BYTE*)(pBuffer + dwOffset);
		// upx ��ȡ OEP��ַ  jmp xxxx
		DWORD dwOEP;
		if (byCode == 0xE9) {
			DWORD dwData = *(DWORD*)(pBuffer + dwOffset + 1);
			dwOEP = dwEIP + dwData + 5;
		}
		/*else if (byCode == 0x68) {
			DWORD dwData = *(DWORD*)(pBuffer + dwOffset + 1);
			dwOEP = dwData;
		}*/
		delete[] pBuffer;
		return dwOEP;
	}

	delete[] pBuffer;
	return 0;
}

bool CDebug::SaveFile(byte * buf, int len, const char * filename)
{
	//�������
	HANDLE hfile = CreateFileA(filename,
		GENERIC_READ | GENERIC_WRITE, //�����д����
		FILE_SHARE_WRITE | FILE_SHARE_READ, //�������д����
		NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hfile == INVALID_HANDLE_VALUE)
	{
		printf("Can't open\r\n");
		return false;
	}
	//�����ָ���ļ���
	SetFilePointer(hfile, 0, 0, FILE_BEGIN);
	DWORD dwWritten;     //����д�˶����ֽڵ��ļ���
	WriteFile(hfile, buf, len, &dwWritten, 0);
	//������д���ļ� 
	CloseHandle(hfile);
	return   true;
}

void CDebug::DumpMemory() {
	DWORD dwAddr = 0;
	DWORD dwRead = 0;
	BYTE* pBuffer = new BYTE[m_dwImageSize];
	memset(pBuffer, 0, m_dwImageSize);
	BOOL bRet = ReadProcessMemory(m_hProcess, (void*)m_dwImageBase, pBuffer, m_dwImageSize, &dwRead);
	if (bRet == -1) {
		MessageBox(NULL, L"DumpMemory Fail", L"1", 1);
		return;
	}
	// �����ṹ��
	IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *)pBuffer;      //DOSͷ
	IMAGE_NT_HEADERS *pNtHeader = (IMAGE_NT_HEADERS *)(pBuffer + pDosHeader->e_lfanew);      //NTͷ
	IMAGE_OPTIONAL_HEADER32 *pOptionalHead = (IMAGE_OPTIONAL_HEADER32 *)(&pNtHeader->OptionalHeader);    //��ѡͷ
	IMAGE_SECTION_HEADER *pSectonInfo = (IMAGE_SECTION_HEADER *)((LPBYTE)pOptionalHead + pNtHeader->FileHeader.SizeOfOptionalHeader);

	// 1. �޸��ļ���С���ڴ��Сһ��(dump֮���ļ�����Ҳ��0x1000)
	int i = 0;
	while (pSectonInfo[i].Name[0] != 0)
	{
		pSectonInfo[i].SizeOfRawData = pSectonInfo[i].Misc.VirtualSize;
		pSectonInfo[i].PointerToRawData = pSectonInfo[i].VirtualAddress;
		i++;
	}

	// 2. �޸�OEP
	pNtHeader->OptionalHeader.AddressOfEntryPoint = m_dwOEP - m_dwImageBase;
	// 3. ȥ�������ַ
	pOptionalHead->DllCharacteristics &= 0x81;

	// 3. д�ļ������ڴ�����
	memset(szDumpPath,0,MAX_PATH);;
	strcpy(szDumpPath, szStrPath);

	const char * extension = 0;
	char* dot = strchr(szDumpPath, '.');
	if (dot)
	{
		*dot = L'\0';
		extension = szStrPath + (dot - szDumpPath); //wcsrchr(selectedFilePath, L'.');
	}

	strcat_s(szDumpPath, "_dmp");

	SaveFile(pBuffer, m_dwImageSize, szDumpPath);

	delete[] pBuffer;
}

void CDebug::EnterDebugLoop(const LPDEBUG_EVENT DebugEv)
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
				//printf("EXCEPTION_BREAKPOINT ExceptionAddress=%p\r\n", DebugEv->u.Exception.ExceptionRecord.ExceptionAddress);

				break;

			case EXCEPTION_DATATYPE_MISALIGNMENT:
				// First chance: Pass this on to the system. 
				// Last chance: Display an appropriate error. 
				printf("EXCEPTION_DATATYPE_MISALIGNMENT\r\n");
				break;

			case EXCEPTION_SINGLE_STEP:
				// First chance: Update the display of the 
				// current instruction and register values. 
				//printf("EXCEPTION_SINGLE_STEP  ExceptionAddress=%p\r\n", DebugEv->u.Exception.ExceptionRecord.ExceptionAddress);
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

			//dwContinueStatus = OnCreateThreadDebugEvent(DebugEv);
			//printf("CREATE_THREAD_DEBUG_EVENT\r\n");
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
			//printf("CREATE_PROCESS_DEBUG_EVENT\r\n");
			break;

		case EXIT_THREAD_DEBUG_EVENT:
			// Display the thread's exit code. 

			//dwContinueStatus = OnExitThreadDebugEvent(DebugEv);
			//printf("EXIT_THREAD_DEBUG_EVENT\r\n");
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			// Display the process's exit code. 

			//dwContinueStatus = OnExitProcessDebugEvent(DebugEv);
			//printf("EXIT_PROCESS_DEBUG_EVENT\r\n");
			break;

		case LOAD_DLL_DEBUG_EVENT:
			// Read the debugging information included in the newly 
			// loaded DLL. Be sure to close the handle to the loaded DLL 
			// with CloseHandle.

			//dwContinueStatus = OnLoadDllDebugEvent(DebugEv);

			//printf("LOAD_DLL_DEBUG_EVENT\r\n");
			break;

		case UNLOAD_DLL_DEBUG_EVENT:
			// Display a message that the DLL has been unloaded. 

			//dwContinueStatus = OnUnloadDllDebugEvent(DebugEv);

			//printf("UNLOAD_DLL_DEBUG_EVENT\r\n");
			break;

		case OUTPUT_DEBUG_STRING_EVENT:
			// Display the output debugging string. 

			//dwContinueStatus = OnOutputDebugStringEvent(DebugEv);
			break;

		case RIP_EVENT:
			//dwContinueStatus = OnRipEvent(DebugEv);
			break;
		}

		// Resume executing the thread that reported the debugging event. 
		ContinueDebugEvent(DebugEv->dwProcessId,
			DebugEv->dwThreadId,
			dwContinueStatus);
	}
}

CDebug::CDebug()
{
}

CDebug::CDebug(char* pStrPath) {

	strcpy(szStrPath, pStrPath);


	si.cb = sizeof(si);

	if (CreateProcessA(
		pStrPath,
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
		return;
	}
	m_hThread = pi.hThread;
	m_hProcess = pi.hProcess;
	m_dwProcessId = pi.dwProcessId;
	m_dwThreadId = pi.dwThreadId;
}


CDebug::~CDebug()
{
}

void CDebug::StartDebugLoop() {

	EnterDebugLoop(&DebugEv);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
}

