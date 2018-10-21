#include "CFixImport.h"

#include "ImportRebuilder.h"

CFixImport::CFixImport()
{
}


CFixImport::~CFixImport()
{
}

CFixImport::CFixImport(char* pStrPath) {

	strcpy(szDumpPath, pStrPath);



}

void CFixImport::FixDump(DWORD dwPID, DWORD_PTR imageBase, DWORD imageSize,DWORD dwOEP) {
	// 1. �򿪽��̡���ȡ���̾��
	if (!ProcessAccessHelp::openProcessHandle(dwPID))
	{
		printf("Error: Cannot open process handle.");
		return;
	}
	// 2. ��ȡ��������ģ��
	ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);
	// 3. ��ȡ����ģ��ĵ�������API
	apiReader.readApisFromModuleList();

	ProcessAccessHelp::targetImageBase = imageBase;
	ProcessAccessHelp::targetSizeOfImage = imageSize;
	DWORD_PTR searchAddress = 0;
	DWORD_PTR addressIAT = 0, addressIATAdv = 0;
	DWORD sizeIAT = 0, sizeIATAdv = 0;
	ImportsHandling importsHandling;
	IATReferenceScan iatReferenceScan;
	IATSearch iatSearch;
	
	// 4. ��OEP��ʼ������ȷ��IAT�������ʼ��ַ�������ַ
	// 4.1.1 ��ȡ�ڴ����ݣ��������룬һ��һ���ж��Ƿ���call[] jmp[] ��Ѱ�� FF25 �� FF15
	// 4.1.2 �ҵ�֮�󣬶�ȡ���еĵ�ַ����IAT�����ַ
	// 4.1.3 ��IAT�����ַ�ж�ȡAPI������ַ���жϵ�ַ�Ƿ���Ч
	// 4.1.4 �����Ч��ͨ�������ַ����Ѱ����Ч��ַ�Լ�����Ѱ�ң���ȡIAT���鷶Χ
	if (iatSearch.searchImportAddressTableInProcess(dwOEP, &addressIAT, &sizeIAT, false))
	{
		printf("Found IAT\r\n");

		if (addressIAT && sizeIAT)
		{
			// 5. ����IAT����ȡIAT API����Ϣ������dll name,apiname��
			apiReader.readAndParseIAT(addressIAT, sizeIAT, importsHandling.moduleList);
			USES_CONVERSION;
			WCHAR *pszdumpPath = A2W(szDumpPath);
			ImportRebuilder importRebuild(pszdumpPath);

			WCHAR newFilePath[MAX_PATH] = {0};
			wcscpy_s(newFilePath, pszdumpPath);

			const WCHAR * extension = 0;

			WCHAR* dot = wcsrchr(newFilePath, L'.');
			if (dot)
			{
				*dot = L'\0';
				extension = pszdumpPath + (dot - newFilePath); //wcsrchr(selectedFilePath, L'.');
			}

			wcscat_s(newFilePath, L"_PB.exe");

			printf("RebuildImportTable FixIAT\r\n");

			// 6. �ؽ�������޸�IAT
			// 6.1 ����IAT�����漰�Ĵ�С�����������
			// 6.2 �ؽ������д��������
			// 6.3 �޸�IAT��ΪRVA
			if (importRebuild.rebuildImportTable(newFilePath, importsHandling.moduleList))
			{
				wprintf(L"Import Rebuild success %s", newFilePath);
				getchar();
			}
			else
			{
				printf("Import Rebuild failed \r\n");
				
			}
		}
	}
	else
	{
		printf("Error: Cannot Not Find.");
	}

}