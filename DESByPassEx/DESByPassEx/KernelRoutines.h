#pragma once
#include <Windows.h>
#include <inttypes.h>
#include <iostream>
#include <vector>
#include "NtDefines.h"

struct KernelContext
{
	HMODULE NtLib;
	uint64_t NtBase;
	uint64_t CIBase;

	template<typename T = fnFreeCall>
	T GetProcAddress( const char* Proc )
	{
		FARPROC LocProc = ::GetProcAddress( this->NtLib, Proc );

		if ( !LocProc )
			return ( T ) ( nullptr );

		uint32_t Delta = ( uintptr_t ) ( LocProc ) - ( uintptr_t ) ( this->NtLib );

		return ( T ) ( this->NtBase + Delta );
	}
};



static KernelContext* Kr_InitContext()
{
	KernelContext* Kc = new KernelContext;

	std::vector<BYTE> Buffer( 1024 * 1024 );

	ULONG ReqSize = 0;

	do
	{
		if ( !NtQuerySystemInformation( SystemModuleInformation, Buffer.data(), Buffer.size(), &ReqSize ) )
			break;

		Buffer.resize( ReqSize * 2 );
	}
	while ( ReqSize > Buffer.size() );

	SYSTEM_MODULE_INFORMATION* ModuleInfo = ( SYSTEM_MODULE_INFORMATION* ) Buffer.data();

	char* KernelFileName = ( char* ) ModuleInfo->Module[ 0 ].FullPathName + ModuleInfo->Module[ 0 ].OffsetToFileName;

	Kc->NtBase = (uint64_t) ModuleInfo->Module[ 0 ].ImageBase;
	Kc->NtLib = LoadLibraryA( KernelFileName );

	if ( !Kc->NtBase || !Kc->NtLib )
	{
		delete Kc;
		printf( "[+] Failed to get kernel module information!\n" );
		return 0;
	}

	printf( "[+] Kernel: %s @ %16llx\n", KernelFileName, Kc->NtBase );

	ULONG i, k;
	for (i = 0; i < ModuleInfo->Count; i++) {
		k = ModuleInfo->Module[i].OffsetToFileName;
		if (lstrcmpiA(
			(CONST CHAR*)&ModuleInfo->Module[i].FullPathName[k],
			"ci.dll") == 0)
		{
			Kc->CIBase = (ULONG_PTR)ModuleInfo->Module[i].ImageBase;
			break;
		}
	}
	printf("[+] CI.dll: %s @ %16llx\n", "ci.dll", Kc->CIBase);

	return Kc;
}

static void Kr_FreeContext( KernelContext* Ctx )
{
	delete Ctx;
}