// unpack01.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "CDebug.h"


int main()
{
	char szPath[MAX_PATH] = {0};
	printf("please input file name: ");
	scanf_s("%s",szPath, MAX_PATH);

	CDebug debug(szPath);

	debug.StartDebugLoop();


    return 0;
}

