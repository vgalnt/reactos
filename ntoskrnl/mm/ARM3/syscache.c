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
    PSECTION Section = SectionObject;
    PCONTROL_AREA ControlArea;
    PSUBSECTION SubSection;
    ULONGLONG OffsetInPages;
    ULONGLONG LastPage;
    ULONG SizeInPages;
    PMMPTE Pte;
    PMMPTE LastPte;
    PMMPTE SectionProto;
    PMMPTE LastProto;
    MMPTE ProtoPte;
    NTSTATUS Status;
    KIRQL OldIrql;

    DPRINT("MmMapViewInSystemCache: Section %p, BaseAddress [%p], Offset [%I64X], Size [%X]\n", Section, (BaseAddress ? *BaseAddress : NULL), (SectionOffset ? SectionOffset->QuadPart : 0), (CapturedViewSize ? *CapturedViewSize : 0));

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    ASSERT(*CapturedViewSize <= VACB_MAPPING_GRANULARITY);
    ASSERT((SectionOffset->LowPart & (VACB_MAPPING_GRANULARITY - 1)) == 0);

    if (Section->u.Flags.Image)
    {
        DPRINT1("MmMapViewInSystemCache: return STATUS_NOT_MAPPED_DATA\n");
        return STATUS_NOT_MAPPED_DATA;
    }

    ASSERT(*CapturedViewSize != 0);

    ControlArea = Section->Segment->ControlArea;
    ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);

    if (ControlArea->u.Flags.Rom)
    {
        SubSection = (PSUBSECTION)((PLARGE_CONTROL_AREA)ControlArea + 1);
    }
    else
    {
        SubSection = (PSUBSECTION)((PCONTROL_AREA)ControlArea + 1);
    }

    OffsetInPages = SectionOffset->QuadPart / PAGE_SIZE;
    SizeInPages = BYTES_TO_PAGES(*CapturedViewSize);
    LastPage = OffsetInPages + SizeInPages;

    while (OffsetInPages >= (ULONGLONG)SubSection->PtesInSubsection)
    {
        OffsetInPages -= SubSection->PtesInSubsection;
        LastPage -= SubSection->PtesInSubsection;
        SubSection = SubSection->NextSubsection;
        DPRINT("MmMapViewInSystemCache: OffsetInPages %I64X, LastPage %I64X\n", OffsetInPages, LastPage);
    }

    OldIrql = MiLockPfnDb(APC_LEVEL);

    ASSERT(ControlArea->u.Flags.BeingCreated == 0);
    ASSERT(ControlArea->u.Flags.BeingDeleted == 0);
    ASSERT(ControlArea->u.Flags.BeingPurged == 0);

    if (MmFirstFreeSystemCache == (PMMPTE)MM_EMPTY_LIST)
    {
        DPRINT1("MmMapViewInSystemCache: return STATUS_NO_MEMORY\n");
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        return STATUS_NO_MEMORY;
    }

    Pte = MmFirstFreeSystemCache;
    ASSERT(Pte->u.Hard.Valid == 0);

    MmFirstFreeSystemCache = MmSystemCachePteBase + Pte->u.List.NextEntry;
    ASSERT(MmFirstFreeSystemCache <= MiAddressToPte(MmSystemCacheEnd));

    ControlArea->NumberOfMappedViews++;
    ControlArea->NumberOfSystemCacheViews++;

    ASSERT(ControlArea->NumberOfSectionReferences != 0);

    if (ControlArea->FilePointer)
    {
        ULONG dummy;

        Status = MiAddViewsForSection((PMSUBSECTION)SubSection, LastPage, OldIrql, &dummy);

        ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

        if (!NT_SUCCESS (Status))
        {
            Pte->u.List.NextEntry = MM_EMPTY_PTE_LIST;
            Pte[1].u.List.NextEntry = KiTbFlushTimeStamp;

            OldIrql = MiLockPfnDb(APC_LEVEL);

            MmLastFreeSystemCache->u.List.NextEntry = Pte - MmSystemCachePteBase;
            MmLastFreeSystemCache = Pte;

            ControlArea->NumberOfMappedViews--;
            ControlArea->NumberOfSystemCacheViews--;

            MiCheckControlArea(ControlArea, OldIrql);

            return Status;
        }
    }
    else
    {
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
    }

    if (Pte->u.List.NextEntry == MM_EMPTY_PTE_LIST)
    {
        DPRINT1("FIXME KeBugCheckEx()\n");
        ASSERT(FALSE);
    }

    DPRINT("MmMapViewInSystemCache: FIXME Flush Tb\n");

    *BaseAddress = MiPteToAddress(Pte);
    DPRINT("MmMapViewInSystemCache: Pte %p, *BaseAddress %p\n", Pte, *BaseAddress);

    Pte[1].u.List.NextEntry = 0;
    LastPte = &Pte[SizeInPages];

    SectionProto = &SubSection->SubsectionBase[OffsetInPages];
    LastProto = &SubSection->SubsectionBase[SubSection->PtesInSubsection];

    for (; Pte < LastPte; Pte++, SectionProto++)
    {
        if (SectionProto >= LastProto)
        {
            if (SubSection->NextSubsection == NULL)
            {
                DPRINT("MmMapViewInSystemCache: SubSection %p\n", SubSection);
                break;
            }

            SubSection = SubSection->NextSubsection;

            SectionProto = SubSection->SubsectionBase;
            LastProto = &SectionProto[SubSection->PtesInSubsection];
        }

        MI_MAKE_PROTOTYPE_PTE(&ProtoPte, SectionProto);
        MI_WRITE_INVALID_PTE(Pte, ProtoPte);
    }

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
