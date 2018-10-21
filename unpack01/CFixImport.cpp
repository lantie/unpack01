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
	// 1. 打开进程、获取进程句柄
	if (!ProcessAccessHelp::openProcessHandle(dwPID))
	{
		printf("Error: Cannot open process handle.");
		return;
	}
	// 2. 获取进程所有模块
	ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);
	// 3. 获取所有模块的导出函数API
	apiReader.readApisFromModuleList();

	ProcessAccessHelp::targetImageBase = imageBase;
	ProcessAccessHelp::targetSizeOfImage = imageSize;
	DWORD_PTR searchAddress = 0;
	DWORD_PTR addressIAT = 0, addressIATAdv = 0;
	DWORD sizeIAT = 0, sizeIATAdv = 0;
	ImportsHandling importsHandling;
	IATReferenceScan iatReferenceScan;
	IATSearch iatSearch;
	
	// 4. 从OEP开始搜索，确定IAT数组的起始地址与结束地址
	// 4.1.1 读取内存数据，反汇编代码，一条一条判断是否是call[] jmp[] 即寻找 FF25 或 FF15
	// 4.1.2 找到之后，读取其中的地址，即IAT数组地址
	// 4.1.3 从IAT数组地址中读取API函数地址，判断地址是否有效
	// 4.1.4 如果有效，通过这个地址向上寻找有效地址以及向下寻找，获取IAT数组范围
	if (iatSearch.searchImportAddressTableInProcess(dwOEP, &addressIAT, &sizeIAT, false))
	{
		printf("Found IAT\r\n");

		if (addressIAT && sizeIAT)
		{
			// 5. 解析IAT，获取IAT API的信息，包括dll name,apiname等
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

			// 6. 重建导入表，修复IAT
			// 6.1 计算IAT函数涉及的大小，添加新区段
			// 6.2 重建导入表，写入新区段
			// 6.3 修复IAT表为RVA
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