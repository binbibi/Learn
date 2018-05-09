#pragma once

#define WINXP2600               512600   
#define WIN77600                617600  
#define WIN77601                617601  
#define WIN89200                629200  
#define WIN819600               639600   
#define WIN1010240              10010240  
#define WIN1010586              10010586  
#define WIN1014393              10014393
#define WIN1015063              10015063
#define WIN1016299              10016299
#define WIN1017134              10017134

typedef LONG(WINAPI *fnRtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);


extern DWORD m_osver;


ULONG_PTR FindCiOptionsOffset();


/*
* ControlDSE
*
* Purpose:
*
* Change ntoskrnl.exe g_CiEnabled or CI.dll g_CiOptions state.
*
*/
BOOL ControlDSE(_In_ BOOL EnableDSE);
