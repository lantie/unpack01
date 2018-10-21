#include "IATReferenceScan.h"
//#include "Scylla.h"
#include "Architecture.h"
#include <set>

//#define DEBUG_COMMENTS

int IATReferenceScan::numberOfFoundDirectImports()
{
	return (int)iatDirectImportList.size();
}

int IATReferenceScan::numberOfFoundUniqueDirectImports()
{
	std::set<DWORD_PTR> apiPointers;
	for (std::vector<IATReference>::iterator iter = iatDirectImportList.begin(); iter != iatDirectImportList.end(); iter++)
	{
		IATReference * ref = &(*iter);
		apiPointers.insert(ref->targetAddressInIat);
	}

	return (int)apiPointers.size();
}

int IATReferenceScan::numberOfDirectImportApisNotInIat()
{
	std::set<DWORD_PTR> apiPointers;
	for (std::vector<IATReference>::iterator iter = iatDirectImportList.begin(); iter != iatDirectImportList.end(); iter++)
	{
		IATReference * ref = &(*iter);

		if (ref->targetPointer == 0)
		{
			apiPointers.insert(ref->targetAddressInIat);
		}
	}

	return (int)apiPointers.size();
}

int IATReferenceScan::getSizeInBytesOfJumpTableInSection()
{
	return (numberOfFoundUniqueDirectImports() * 6); //for x86 and x64 the same size, FF25 00000000
}

void IATReferenceScan::startScan(DWORD_PTR imageBase, DWORD imageSize, DWORD_PTR iatAddress, DWORD iatSize)
{
	MEMORY_BASIC_INFORMATION memBasic = {0};

	IatAddressVA = iatAddress;
	IatSize = iatSize;
	ImageBase = imageBase;
	ImageSize = imageSize;

	if (ScanForNormalImports)
	{
		iatReferenceList.clear();
		iatReferenceList.reserve(200);
	}
	if (ScanForDirectImports)
	{
		iatDirectImportList.clear();
		iatDirectImportList.reserve(50);
	}



	DWORD_PTR section = imageBase;

	do
	{
		if (!VirtualQueryEx(ProcessAccessHelp::hProcess, (LPCVOID)section, &memBasic, sizeof(MEMORY_BASIC_INFORMATION)))
		{
#ifdef DEBUG_COMMENTS
			Scylla::debugLog.log(L"VirtualQueryEx failed %d", GetLastError());
#endif

			break;
		}
		else
		{
			if (ProcessAccessHelp::isPageExecutable(memBasic.Protect))
			{
				//do read and scan
				scanMemoryPage(memBasic.BaseAddress, memBasic.RegionSize);
			}
		}

		section = (DWORD_PTR)((SIZE_T)section + memBasic.RegionSize);

	} while (section < (imageBase + imageSize));


}

//void IATReferenceScan::patchNewIatBaseMemory(DWORD_PTR newIatBaseAddress)
//{
//	NewIatAddressVA = newIatBaseAddress;
//
//	for (std::vector<IATReference>::iterator iter = iatReferenceList.begin(); iter != iatReferenceList.end(); iter++)
//	{
//		patchReferenceInMemory(&(*iter));
//	}
//}
//
//void IATReferenceScan::patchNewIatBaseFile(DWORD_PTR newIatBaseAddress)
//{
//	NewIatAddressVA = newIatBaseAddress;
//
//	for (std::vector<IATReference>::iterator iter = iatReferenceList.begin(); iter != iatReferenceList.end(); iter++)
//	{
//		patchReferenceInFile(&(*iter));
//	}
//}

void IATReferenceScan::patchDirectImportsMemory( bool junkByteAfterInstruction )
{
	JunkByteAfterInstruction = junkByteAfterInstruction;
	for (std::vector<IATReference>::iterator iter = iatDirectImportList.begin(); iter != iatDirectImportList.end(); iter++)
	{
		patchDirectImportInMemory(&(*iter));
	}
}

void IATReferenceScan::scanMemoryPage( PVOID BaseAddress, SIZE_T RegionSize )
{
	BYTE * dataBuffer = (BYTE *)calloc(RegionSize, 1);
	BYTE * currentPos = dataBuffer;
	int currentSize = (int)RegionSize;
	DWORD_PTR currentOffset = (DWORD_PTR)BaseAddress;
	_DecodeResult res;
	unsigned int instructionsCount = 0, next = 0;

	if (!dataBuffer)
		return;

	if (ProcessAccessHelp::readMemoryFromProcess((DWORD_PTR)BaseAddress, RegionSize, (LPVOID)dataBuffer))
	{
		while (1)
		{
			ZeroMemory(&ProcessAccessHelp::decomposerCi, sizeof(_CodeInfo));
			ProcessAccessHelp::decomposerCi.code = currentPos;
			ProcessAccessHelp::decomposerCi.codeLen = currentSize;
			ProcessAccessHelp::decomposerCi.dt = ProcessAccessHelp::dt;
			ProcessAccessHelp::decomposerCi.codeOffset = currentOffset;

			instructionsCount = 0;

			res = distorm_decompose(&ProcessAccessHelp::decomposerCi, ProcessAccessHelp::decomposerResult, sizeof(ProcessAccessHelp::decomposerResult)/sizeof(ProcessAccessHelp::decomposerResult[0]), &instructionsCount);

			if (res == DECRES_INPUTERR)
			{
				break;
			}

			for (unsigned int i = 0; i < instructionsCount; i++) 
			{
				if (ProcessAccessHelp::decomposerResult[i].flags != FLAG_NOT_DECODABLE)
				{
					analyzeInstruction(&ProcessAccessHelp::decomposerResult[i]);
				}
			}

			if (res == DECRES_SUCCESS) break; // All instructions were decoded.
			else if (instructionsCount == 0) break;

			next = (unsigned long)(ProcessAccessHelp::decomposerResult[instructionsCount-1].addr - ProcessAccessHelp::decomposerResult[0].addr);

			if (ProcessAccessHelp::decomposerResult[instructionsCount-1].flags != FLAG_NOT_DECODABLE)
			{
				next += ProcessAccessHelp::decomposerResult[instructionsCount-1].size;
			}

			currentPos += next;
			currentOffset += next;
			currentSize -= next;
		}
	}

	free(dataBuffer);
}

void IATReferenceScan::analyzeInstruction( _DInst * instruction )
{
	if (ScanForNormalImports)
	{
		findNormalIatReference(instruction);
	}
	
	if (ScanForDirectImports)
	{
		findDirectIatReferenceMov(instruction);
		
#ifndef _WIN64
		findDirectIatReferenceCallJmp(instruction);
		findDirectIatReferenceLea(instruction);
		findDirectIatReferencePush(instruction);
#endif
	}
}

void IATReferenceScan::findNormalIatReference( _DInst * instruction )
{
#ifdef DEBUG_COMMENTS
	_DecodedInst inst;
#endif

	IATReference ref;


	if (META_GET_FC(instruction->meta) == FC_CALL || META_GET_FC(instruction->meta) == FC_UNC_BRANCH)
	{
		if (instruction->size >= 5)
		{
			if (META_GET_FC(instruction->meta) == FC_CALL)
			{
				ref.type = IAT_REFERENCE_PTR_CALL;
			}
			else
			{
				ref.type = IAT_REFERENCE_PTR_JMP;
			}
			ref.addressVA = (DWORD_PTR)instruction->addr;
			ref.instructionSize = instruction->size;

#ifdef _WIN64
			if (instruction->flags & FLAG_RIP_RELATIVE)
			{

#ifdef DEBUG_COMMENTS
				distorm_format(&ProcessAccessHelp::decomposerCi, instruction, &inst);
				Scylla::debugLog.log(PRINTF_DWORD_PTR_FULL L" " PRINTF_DWORD_PTR_FULL L" %S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL, (DWORD_PTR)instruction->addr, ImageBase, inst.mnemonic.p, inst.operands.p, instruction->ops[0].type, instruction->size, INSTRUCTION_GET_RIP_TARGET(instruction));
#endif

				if (INSTRUCTION_GET_RIP_TARGET(instruction) >= IatAddressVA && INSTRUCTION_GET_RIP_TARGET(instruction) < (IatAddressVA + IatSize))
				{
					ref.targetPointer = INSTRUCTION_GET_RIP_TARGET(instruction);

					getIatEntryAddress(&ref);

					//Scylla::debugLog.log(L"iat entry "PRINTF_DWORD_PTR_FULL,ref.targetAddressInIat);

					iatReferenceList.push_back(ref);
				}
			}
#else

			if (instruction->ops[0].type == O_DISP)
			{
				//jmp dword ptr || call dword ptr
#ifdef DEBUG_COMMENTS
				distorm_format(&ProcessAccessHelp::decomposerCi, instruction, &inst);
				Scylla::debugLog.log(PRINTF_DWORD_PTR_FULL L" " PRINTF_DWORD_PTR_FULL L" %S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL, (DWORD_PTR)instruction->addr, ImageBase, inst.mnemonic.p, inst.operands.p, instruction->ops[0].type, instruction->size, instruction->disp);
#endif
				
				if (instruction->disp >= IatAddressVA && instruction->disp < (IatAddressVA + IatSize))
				{
					ref.targetPointer = (DWORD_PTR)instruction->disp;
					
					getIatEntryAddress(&ref);

					//Scylla::debugLog.log(L"iat entry "PRINTF_DWORD_PTR_FULL,ref.targetAddressInIat);

					iatReferenceList.push_back(ref);
				}
			}
#endif
		}
	}
}

void IATReferenceScan::getIatEntryAddress( IATReference * ref )
{
	if (!ProcessAccessHelp::readMemoryFromProcess(ref->targetPointer, sizeof(DWORD_PTR), &ref->targetAddressInIat))
	{
		ref->targetAddressInIat = 0;
	}
}

bool IATReferenceScan::isAddressValidImageMemory( DWORD_PTR address )
{
	MEMORY_BASIC_INFORMATION memBasic = {0};

	if (!VirtualQueryEx(ProcessAccessHelp::hProcess, (LPCVOID)address, &memBasic, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		return false;
	}

	return (memBasic.Type == MEM_IMAGE && ProcessAccessHelp::isPageExecutable(memBasic.Protect));
}

void IATReferenceScan::patchReferenceInMemory( IATReference * ref )
{
	DWORD_PTR newIatAddressPointer = ref->targetPointer - IatAddressVA + NewIatAddressRVA;

	DWORD patchBytes = 0;

#ifdef _WIN64
	patchBytes = (DWORD)(newIatAddressPointer - ref->addressVA - 6);
#else
	patchBytes = newIatAddressPointer;
#endif
	ProcessAccessHelp::writeMemoryToProcess(ref->addressVA + 2, sizeof(DWORD), &patchBytes);
}

void IATReferenceScan::patchDirectImportInMemory( IATReference * ref )
{
	DWORD patchBytes = 0;
	BYTE patchPreBytes[2];

	if (ref->targetPointer)
	{
		patchPreBytes[0] = 0xFF;

		if (ref->type == IAT_REFERENCE_DIRECT_CALL) //FF15
		{
			patchPreBytes[1] = 0x15;
		}
		else if (ref->type == IAT_REFERENCE_DIRECT_JMP) //FF25
		{
			patchPreBytes[1] = 0x25;
		}
		else
		{
			return;
		}

		if (!JunkByteAfterInstruction)
		{
			ref->addressVA -= 1;
		}

		ProcessAccessHelp::writeMemoryToProcess(ref->addressVA, 2, patchPreBytes);

#ifdef _WIN64
		patchBytes = (DWORD)(ref->targetPointer - ref->addressVA - 6);
#else
		patchBytes = ref->targetPointer;
#endif
		ProcessAccessHelp::writeMemoryToProcess(ref->addressVA + 2, sizeof(DWORD), &patchBytes);
	}
}

DWORD_PTR IATReferenceScan::lookUpIatForPointer( DWORD_PTR addr )
{
	if (!iatBackup)
	{
		iatBackup = (DWORD_PTR *)calloc(IatSize + sizeof(DWORD_PTR), 1);
		if (!iatBackup)
		{
			return 0;
		}
		if (!ProcessAccessHelp::readMemoryFromProcess(IatAddressVA, IatSize, iatBackup))
		{
			free(iatBackup);
			iatBackup = 0;
			return 0;
		}
	}

	for (int i = 0; i < ((int)IatSize / (int)sizeof(DWORD_PTR));i++)
	{
		if (iatBackup[i] == addr)
		{
			return (DWORD_PTR)&iatBackup[i] - (DWORD_PTR)iatBackup + IatAddressVA;
		}
	}

	return 0;
}

void IATReferenceScan::patchNewIat(DWORD_PTR stdImagebase, DWORD_PTR newIatBaseAddress, PeParser * peParser)
{
	NewIatAddressRVA = newIatBaseAddress;
	DWORD patchBytes = 0;

	for (std::vector<IATReference>::iterator iter = iatReferenceList.begin(); iter != iatReferenceList.end(); iter++)
	{
		IATReference * ref = &(*iter);

		DWORD_PTR newIatAddressPointer = (ref->targetPointer - IatAddressVA) + NewIatAddressRVA + stdImagebase;

#ifdef _WIN64
		patchBytes = (DWORD)(newIatAddressPointer - (ref->addressVA - ImageBase + stdImagebase) - 6);
#else
		patchBytes = newIatAddressPointer;
#endif
		DWORD_PTR patchOffset = peParser->convertRVAToOffsetRelative(ref->addressVA - ImageBase);
		int index = peParser->convertRVAToOffsetVectorIndex(ref->addressVA - ImageBase);
		BYTE * memory = peParser->getSectionMemoryByIndex(index);
		DWORD memorySize = peParser->getSectionMemorySizeByIndex(index);


		if (memorySize < (DWORD)(patchOffset + 6))
		{
			//printf("Error - Cannot fix IAT reference RVA: " PRINTF_DWORD_PTR_FULL, ref->addressVA - ImageBase);
		}
		else
		{
			memory += patchOffset + 2;		

			*((DWORD *)memory) = patchBytes;
		}
		//Scylla::debugLog.log(L"address %X old %X new %X",ref->addressVA, ref->targetPointer, newIatAddressPointer);

	}
}

void IATReferenceScan::printDirectImportLog()
{
	//int count = 0;
	//bool isSuspect = false;

	//for (std::vector<IATReference>::iterator iter = iatDirectImportList.begin(); iter != iatDirectImportList.end(); iter++)
	//{
	//	IATReference * ref = &(*iter);
	//	
	//	ApiInfo * apiInfo = apiReader->getApiByVirtualAddress(ref->targetAddressInIat, &isSuspect);

	//	count++;
	//	WCHAR *type = L"U";

	//	if (ref->type == IAT_REFERENCE_DIRECT_CALL)
	//	{
	//		type = L"CALL";
	//	}
	//	else if (ref->type == IAT_REFERENCE_DIRECT_JMP)
	//	{
	//		type = L"JMP";
	//	}
	//	else if (ref->type == IAT_REFERENCE_DIRECT_MOV)
	//	{
	//		type = L"MOV";
	//	}
	//	else if (ref->type == IAT_REFERENCE_DIRECT_PUSH)
	//	{
	//		type = L"PUSH";
	//	}
	//	else if (ref->type == IAT_REFERENCE_DIRECT_LEA)
	//	{
	//		type = L"LEA";
	//	}

	//	//IATReferenceScan::directImportLog.log(L"%04d AddrVA " PRINTF_DWORD_PTR_FULL L" Type %s Value " PRINTF_DWORD_PTR_FULL L" IatRefPointer " PRINTF_DWORD_PTR_FULL L" Api %s %S", count, ref->addressVA, type, ref->targetAddressInIat, ref->targetPointer,apiInfo->module->getFilename(), apiInfo->name);

	//}

	//IATReferenceScan::directImportLog.log(L"------------------------------------------------------------");
}

void IATReferenceScan::findDirectIatReferenceCallJmp( _DInst * instruction )
{
	IATReference ref;

	if (META_GET_FC(instruction->meta) == FC_CALL || META_GET_FC(instruction->meta) == FC_UNC_BRANCH)
	{
		if ((instruction->size >= 5) && (instruction->ops[0].type == O_PC)) //CALL/JMP 0x00000000
		{
			if (META_GET_FC(instruction->meta) == FC_CALL)
			{
				ref.type = IAT_REFERENCE_DIRECT_CALL;
			}
			else
			{
				ref.type = IAT_REFERENCE_DIRECT_JMP;
			}
			
			ref.targetAddressInIat = (DWORD_PTR)INSTRUCTION_GET_TARGET(instruction);

			checkMemoryRangeAndAddToList(&ref, instruction);
		}
	}
}

void IATReferenceScan::findDirectIatReferenceMov( _DInst * instruction )
{
	IATReference ref;
	ref.type = IAT_REFERENCE_DIRECT_MOV;

	if (instruction->opcode == I_MOV)
	{
#ifdef _WIN64
		if (instruction->size >= 7) //MOV REGISTER, 0xFFFFFFFFFFFFFFFF
#else
		if (instruction->size >= 5) //MOV REGISTER, 0xFFFFFFFF
#endif
		{
			if (instruction->ops[0].type == O_REG && instruction->ops[1].type == O_IMM)
			{
				ref.targetAddressInIat = (DWORD_PTR)instruction->imm.qword;

				checkMemoryRangeAndAddToList(&ref, instruction);
			}
		}
	}
}

void IATReferenceScan::findDirectIatReferencePush( _DInst * instruction )
{
	IATReference ref;
	ref.type = IAT_REFERENCE_DIRECT_PUSH;

	if (instruction->size >= 5 && instruction->opcode == I_PUSH)
	{
		ref.targetAddressInIat = (DWORD_PTR)instruction->imm.qword;

		checkMemoryRangeAndAddToList(&ref, instruction);
	}
}

void IATReferenceScan::findDirectIatReferenceLea( _DInst * instruction )
{
	IATReference ref;
	ref.type = IAT_REFERENCE_DIRECT_LEA;

	if (instruction->size >= 5 && instruction->opcode == I_LEA)
	{
		if (instruction->ops[0].type == O_REG && instruction->ops[1].type == O_DISP) //LEA EDX, [0xb58bb8]
		{
			ref.targetAddressInIat = (DWORD_PTR)instruction->disp;

			checkMemoryRangeAndAddToList(&ref, instruction);
		}
	}
}

void IATReferenceScan::checkMemoryRangeAndAddToList( IATReference * ref, _DInst * instruction )
{
#ifdef DEBUG_COMMENTS
	_DecodedInst inst;
#endif

	if (ref->targetAddressInIat > 0x000FFFFF && ref->targetAddressInIat != (DWORD_PTR)-1)
	{
		if ((ref->targetAddressInIat < ImageBase) || (ref->targetAddressInIat > (ImageBase+ImageSize))) //outside pe image
		{
			//if (isAddressValidImageMemory(ref->targetAddressInIat))
			{
				bool isSuspect = false;
				if (apiReader->getApiByVirtualAddress(ref->targetAddressInIat, &isSuspect) != 0)
				{
					ref->addressVA = (DWORD_PTR)instruction->addr;
					ref->instructionSize = instruction->size;
					ref->targetPointer = lookUpIatForPointer(ref->targetAddressInIat);

#ifdef DEBUG_COMMENTS
					distorm_format(&ProcessAccessHelp::decomposerCi, instruction, &inst);
					Scylla::debugLog.log(PRINTF_DWORD_PTR_FULL L" " PRINTF_DWORD_PTR_FULL L" %S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL,(DWORD_PTR)instruction->addr, ImageBase, inst.mnemonic.p, inst.operands.p, instruction->ops[0].type, instruction->size, ref->targetAddressInIat);
#endif
					iatDirectImportList.push_back(*ref);
				}
			}
		}
	}
}

void IATReferenceScan::patchDirectJumpTableEntry(DWORD_PTR targetIatPointer, DWORD_PTR stdImagebase, DWORD directImportsJumpTableRVA, PeParser * peParser, BYTE * jmpTableMemory, DWORD newIatBase )
{
	DWORD patchBytes = 0;
	for (std::vector<IATReference>::iterator iter = iatDirectImportList.begin(); iter != iatDirectImportList.end(); iter++)
	{
		IATReference * ref = &(*iter);

		//only one jmp in table for different direct imports with same iat address
		if (ref->targetPointer == targetIatPointer)
		{
			//patch dump
			DWORD patchOffset = (DWORD)peParser->convertRVAToOffsetRelative(ref->addressVA - ImageBase);
			int index = peParser->convertRVAToOffsetVectorIndex(ref->addressVA - ImageBase);
			BYTE * memory = peParser->getSectionMemoryByIndex(index);
			DWORD memorySize = peParser->getSectionMemorySizeByIndex(index);
			DWORD sectionRVA = peParser->getSectionAddressRVAByIndex(index);

			if (ref->type == IAT_REFERENCE_DIRECT_CALL || ref->type == IAT_REFERENCE_DIRECT_JMP)
			{
#ifndef _WIN64
				if (ref->instructionSize == 5)
				{
					patchBytes = directImportsJumpTableRVA - (ref->addressVA - ImageBase) - 5;
					patchDirectImportInDump32(1, 5, patchBytes, memory, memorySize, false, patchOffset, sectionRVA);
				}
#endif
			}
			else if (ref->type == IAT_REFERENCE_DIRECT_PUSH || ref->type == IAT_REFERENCE_DIRECT_MOV)
			{
#ifndef _WIN64
				if (ref->instructionSize == 5) //for x86
				{
					patchBytes = directImportsJumpTableRVA + stdImagebase;
					patchDirectImportInDump32(1, 5, patchBytes, memory, memorySize, true, patchOffset, sectionRVA);				
				}
#else
				if (ref->instructionSize == 10) //for x64
				{
					DWORD_PTR patchBytes64 = directImportsJumpTableRVA + stdImagebase;
					patchDirectImportInDump64(2, 10, patchBytes64, memory, memorySize, true, patchOffset, sectionRVA);
				}
#endif
			}
			else if (ref->type == IAT_REFERENCE_DIRECT_LEA)
			{
#ifndef _WIN64
				if (ref->instructionSize == 6)
				{
					patchBytes = directImportsJumpTableRVA + stdImagebase;
					patchDirectImportInDump32(2, 6, patchBytes, memory, memorySize, true, patchOffset, sectionRVA);
				}
#endif
			}
		}
	}
}

void IATReferenceScan::patchDirectJumpTable( DWORD_PTR stdImagebase, DWORD directImportsJumpTableRVA, PeParser * peParser, BYTE * jmpTableMemory, DWORD newIatBase )
{

	std::set<DWORD_PTR> apiPointers;
	for (std::vector<IATReference>::iterator iter = iatDirectImportList.begin(); iter != iatDirectImportList.end(); iter++)
	{
		IATReference * ref = &(*iter);
		apiPointers.insert(ref->targetPointer);
	}

	DWORD patchBytes;

	for (std::set<DWORD_PTR>::iterator apiIter = apiPointers.begin(); apiIter != apiPointers.end(); apiIter++)
	{
		DWORD_PTR refTargetPointer = *apiIter;
		if (newIatBase) //create new iat in section
		{
			refTargetPointer = (*apiIter - IatAddressVA) + newIatBase + ImageBase;
		}
		//create jump table in section
		DWORD_PTR newIatAddressPointer = refTargetPointer - ImageBase + stdImagebase;

#ifdef _WIN64
		patchBytes = (DWORD)(newIatAddressPointer - (directImportsJumpTableRVA + stdImagebase) - 6);
#else
		patchBytes = newIatAddressPointer;
		DWORD relocOffset = (directImportsJumpTableRVA + 2);
		//directImportLog.log(L"Relocation direct imports fix: Base RVA %08X Type HIGHLOW Offset %04X RelocTableEntry %04X", relocOffset & 0xFFFFF000, relocOffset & 0x00000FFF, (IMAGE_REL_BASED_HIGHLOW << 12) + (relocOffset & 0x00000FFF));
#endif
		jmpTableMemory[0] = 0xFF;
		jmpTableMemory[1] = 0x25;
		*((DWORD *)&jmpTableMemory[2]) = patchBytes;

		patchDirectJumpTableEntry(*apiIter, stdImagebase, directImportsJumpTableRVA, peParser, jmpTableMemory, newIatBase);

		jmpTableMemory += 6;
		directImportsJumpTableRVA += 6;
	}
}

void IATReferenceScan::patchDirectImportInDump32( int patchPreFixBytes, int instructionSize, DWORD patchBytes, BYTE * memory, DWORD memorySize, bool generateReloc, DWORD patchOffset, DWORD sectionRVA )
{
	if (memorySize < (DWORD)(patchOffset + instructionSize))
	{
		//Scylla::debugLog.log(L"Error - Cannot fix direct import reference RVA: %X", sectionRVA + patchOffset);
	}
	else
	{
		memory += patchOffset + patchPreFixBytes;
		if (generateReloc)
		{
			DWORD relocOffset = sectionRVA + patchOffset+ patchPreFixBytes;
			//directImportLog.log(L"Relocation direct imports fix: Base RVA %08X Type HIGHLOW Offset %04X RelocTableEntry %04X", relocOffset & 0xFFFFF000, relocOffset & 0x00000FFF, (IMAGE_REL_BASED_HIGHLOW << 12) + (relocOffset & 0x00000FFF));
		}

		*((DWORD *)memory) = patchBytes;
	}
}

void IATReferenceScan::patchDirectImportInDump64( int patchPreFixBytes, int instructionSize, DWORD_PTR patchBytes, BYTE * memory, DWORD memorySize, bool generateReloc, DWORD patchOffset, DWORD sectionRVA )
{
	if (memorySize < (DWORD)(patchOffset + instructionSize))
	{
		//Scylla::debugLog.log(L"Error - Cannot fix direct import reference RVA: %X", sectionRVA + patchOffset);
	}
	else
	{
		memory += patchOffset + patchPreFixBytes;
		if (generateReloc)
		{
			DWORD relocOffset = sectionRVA + patchOffset+ patchPreFixBytes;
			//directImportLog.log(L"Relocation direct imports fix: Base RVA %08X Type DIR64 Offset %04X RelocTableEntry %04X", relocOffset & 0xFFFFF000, relocOffset & 0x00000FFF, (IMAGE_REL_BASED_DIR64 << 12) + (relocOffset & 0x00000FFF));
		}

		*((DWORD_PTR *)memory) = patchBytes;
	}
}

DWORD IATReferenceScan::addAdditionalApisToList()
{
	std::set<DWORD_PTR> apiPointers;

	for (std::vector<IATReference>::iterator iter = iatDirectImportList.begin(); iter != iatDirectImportList.end(); iter++)
	{
		IATReference * ref = &(*iter);

		if (ref->targetPointer == 0)
		{
			apiPointers.insert(ref->targetAddressInIat);
		}
	}

	DWORD_PTR iatAddy = IatAddressVA + IatSize;
	DWORD newIatSize = IatSize;

	bool isSuspect = false;
	for (std::set<DWORD_PTR>::iterator apiIter = apiPointers.begin(); apiIter != apiPointers.end(); apiIter++)
	{
		for (std::vector<IATReference>::iterator iter = iatDirectImportList.begin(); iter != iatDirectImportList.end(); iter++)
		{
			IATReference * ref = &(*iter);

			if (ref->targetPointer == 0  && ref->targetAddressInIat == *apiIter)
			{
				ref->targetPointer = iatAddy;
				ApiInfo * apiInfo = apiReader->getApiByVirtualAddress(ref->targetAddressInIat, &isSuspect);
				apiReader->addFoundApiToModuleList(iatAddy, apiInfo, true, isSuspect);
			}
		}

		iatAddy += sizeof(DWORD_PTR);
		newIatSize += sizeof(DWORD_PTR);
	}

	return newIatSize;
}


