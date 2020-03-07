/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            ntoskrnl/mm/ARM3/syscache.c
 * PURPOSE:         ARM Memory Manager System Cache Support
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
//#define NDEBUG
#include <debug.h>

#include <mm/ARM3/miarm.h>

/* GLOBALS ********************************************************************/

#if (_MI_PAGING_LEVELS == 2)
ULONG MiMaximumWorkingSet = ((ULONG_PTR)MI_USER_PROBE_ADDRESS / PAGE_SIZE); // 0x7FFF0
#else
 #error FIXME
#endif

PMMPTE MmFirstFreeSystemCache;
PMMPTE MmLastFreeSystemCache;
PMMPTE MmSystemCachePteBase;

PMMWSLE MmSystemCacheWsle;

/* PRIVATE FUNCTIONS **********************************************************/

NTSTATUS
NTAPI
MmMapViewInSystemCache(IN PVOID SectionObject,
                       IN OUT PVOID * BaseAddress,
                       IN PLARGE_INTEGER SectionOffset,
                       IN PULONG CapturedViewSize)
{
    DPRINT("MmMapViewInSystemCache: Section %p, BaseAddress [%p], Offset [%I64X], Size [%X]\n", Section, (BaseAddress ? *BaseAddress : NULL), (SectionOffset ? SectionOffset->QuadPart : 0), (CapturedViewSize ? *CapturedViewSize : 0));
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

VOID
NTAPI
MiInitializeSystemCache(IN ULONG MinimumWorkingSetSize,
                        IN ULONG MaximumWorkingSetSize)
{
    PMMPTE CacheWsListPte;
    PMMPTE CachePte;
    MMPTE TempPte;
    PFN_NUMBER PageFrameIndex;
    ULONG_PTR HashStart;
    ULONG VacbCount;
    ULONG MinWsSize;
    ULONG WsleIndex;
    ULONG Color;
    ULONG Count;
    ULONG Size;
    ULONG ix;
    KIRQL OldIrql;

    DPRINT("MiInitializeSystemCache: Minimum %X, Maximum %X, MmSystemCacheStart %p, MmSystemCacheEnd %p\n", MinimumWorkingSetSize, MaximumWorkingSetSize, MmSystemCacheStart, MmSystemCacheEnd);

    Color = MI_GET_NEXT_COLOR();
    TempPte.u.Long = ValidKernelPte.u.Long;
    CacheWsListPte = MiAddressToPte(MmSystemCacheWorkingSetList);

    DPRINT("MiInitializeSystemCache: MmSystemCacheWorkingSetList %p, CacheWsListPte %p\n", MmSystemCacheWorkingSetList, CacheWsListPte);
    ASSERT(CacheWsListPte->u.Long == 0);

    OldIrql = MiLockPfnDb(APC_LEVEL);

    PageFrameIndex = MiRemoveZeroPage(Color);
    TempPte.u.Hard.PageFrameNumber = PageFrameIndex;

    MiInitializePfnAndMakePteValid(PageFrameIndex, CacheWsListPte, TempPte);
    MmResidentAvailablePages--;

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    /* Initialize the Working Set */

    MmSystemCacheWs.VmWorkingSetList = MmSystemCacheWorkingSetList;
    MmSystemCacheWs.WorkingSetSize = 0;

#if (_MI_PAGING_LEVELS == 2)
    MmSystemCacheWsle = (PMMWSLE)&MmSystemCacheWorkingSetList->UsedPageTableEntries[0];
#else
 #error FIXME
#endif

    MmSystemCacheWorkingSetList->Wsle = MmSystemCacheWsle;

    MmSystemCacheWorkingSetList->FirstFree = 1;
    MmSystemCacheWorkingSetList->FirstDynamic = 1;
    MmSystemCacheWorkingSetList->NextSlot = 1;

    MmSystemCacheWorkingSetList->HashTable = NULL;
    MmSystemCacheWorkingSetList->HashTableSize = 0;

#if (_MI_PAGING_LEVELS == 2)
    WsleIndex = (((ULONGLONG)1 << 32) / PAGE_SIZE) - MiMaximumWorkingSet;
    HashStart = (ULONG_PTR)PAGE_ALIGN(&MmSystemCacheWorkingSetList->Wsle[WsleIndex]) + PAGE_SIZE;
    MmSystemCacheWorkingSetList->HashTableStart = (PVOID)HashStart;
#else
 #error FIXME
#endif

    MmSystemCacheWorkingSetList->HighestPermittedHashAddress = MmSystemCacheStart;

    Count = (((ULONG_PTR)MmSystemCacheWorkingSetList + PAGE_SIZE) - (ULONG_PTR)MmSystemCacheWsle) / sizeof(PMMWSLE);
    MinWsSize = Count - 1;

    MmSystemCacheWorkingSetList->LastEntry = MinWsSize;
    MmSystemCacheWorkingSetList->LastInitializedWsle = MinWsSize;

    if (MaximumWorkingSetSize <= MinWsSize)
    {
        MaximumWorkingSetSize = MinWsSize + (PAGE_SIZE / sizeof(PMMWSLE));
    }

    MmSystemCacheWs.MinimumWorkingSetSize = MinWsSize;
    MmSystemCacheWs.MaximumWorkingSetSize = MaximumWorkingSetSize;

    // FIXME init Wsles

    /* Add the Cache Ptes in list */

#if defined(_X86_)
    Size = ((ULONG_PTR)MmSystemCacheEnd - (ULONG_PTR)MmSystemCacheStart + 1);
    VacbCount = COMPUTE_PAGES_SPANNED(MmSystemCacheStart, Size);
    VacbCount /= MM_PAGES_PER_VACB;
#else
 #error FIXME
#endif

    MmSystemCachePteBase = MI_SYSTEM_PTE_BASE;

    CachePte = MiAddressToPte(MmSystemCacheStart);
    MmFirstFreeSystemCache = CachePte;

    DPRINT("MiInitializeSystemCache: MmFirstFreeSystemCache %p [%p], VacbCount %X\n", MmFirstFreeSystemCache, MmFirstFreeSystemCache->u.Long, VacbCount);

    for (ix = 0; ix < VacbCount; ix++)
    {
        CachePte->u.List.NextEntry = (ULONG)((CachePte + MM_PAGES_PER_VACB) - MmSystemCachePteBase);
        CachePte += MM_PAGES_PER_VACB; // (256K / 4K)
    }

    CachePte -= MM_PAGES_PER_VACB;
    CachePte->u.List.NextEntry = MM_EMPTY_PTE_LIST;

    MmLastFreeSystemCache = CachePte;

    //FIXME MiAllowWorkingSetExpansion(&MmSystemCacheWs);
}

/* PUBLIC FUNCTIONS ***********************************************************/


/* EOF */
