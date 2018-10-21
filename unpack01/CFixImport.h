#pragma once

#include "ApiReader.h"
#include "ImportsHandling.h"
#include "IATReferenceScan.h"
#include "IATSearch.h"

class CFixImport
{
public:
	CFixImport();
	CFixImport(char* pStrPath);
	~CFixImport();

	void FixDump(DWORD dwPID, DWORD_PTR imageBase, DWORD imageSize, DWORD dwOEP);

	ApiReader apiReader;

	char szDumpPath[MAX_PATH] = { 0 };
};

