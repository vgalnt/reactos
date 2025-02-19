
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "miarm.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

ULONG MmFrontOfList;

PMMPTE MmFirstFreeSystemCache;
PMMPTE MmLastFreeSystemCache;
PMMPTE MmSystemCachePteBase;
PMMWSLE MmSystemCacheWsle;

extern MI_PFN_CACHE_ATTRIBUTE MiPlatformCacheAttributes[2][MmMaximumCacheType];
extern PVOID MmSystemCacheStart;
extern PVOID MmSystemCacheEnd;
extern ULONG MmSecondaryColorMask;
extern PMMWSL MmSystemCacheWorkingSetList;
extern volatile LONG KiTbFlushTimeStamp;
extern ULONG MiMaximumWorkingSet;

/* FUNCTIONS ******************************************************************/

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(INIT, MiInitializeSystemCache)
#endif

CODE_SEG("INIT")
VOID
NTAPI
MiInitializeSystemCache(
    _In_ ULONG MinimumWorkingSetSize,
    _In_ ULONG MaximumWorkingSetSize)
{
    PMMPTE CacheWsListPte;
    PMMPTE CachePte;
    MMPTE TempPte;
    PMMWSLE Wsle;
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

    DPRINT("MiInitializeSystemCache: Minimum %X, Maximum %X, MmSystemCacheStart %p, MmSystemCacheEnd %p\n",
           MinimumWorkingSetSize, MaximumWorkingSetSize, MmSystemCacheStart, MmSystemCacheEnd);

    /* Initialize the PTE and PFN for Working Set */

    Color = MI_GET_NEXT_COLOR();

    TempPte.u.Long = ValidKernelPte.u.Long;
    CacheWsListPte = MiAddressToPte(MmSystemCacheWorkingSetList);

    DPRINT("MiInitializeSystemCache: MmSystemCacheWorkingSetList %p, CacheWsListPte %p\n",
           MmSystemCacheWorkingSetList, CacheWsListPte);

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
    WsleIndex = (MI_MAX_PAGES - MiMaximumWorkingSet);
    HashStart = ((ULONG_PTR)PAGE_ALIGN(&MmSystemCacheWorkingSetList->Wsle[WsleIndex]) + PAGE_SIZE);
    MmSystemCacheWorkingSetList->HashTableStart = (PVOID)HashStart;
#else
 #error FIXME
#endif

    MmSystemCacheWorkingSetList->HighestPermittedHashAddress = MmSystemCacheStart;

    Count = ((ULONG_PTR)MmSystemCacheWorkingSetList + PAGE_SIZE - (ULONG_PTR)MmSystemCacheWsle);
    Count /= sizeof(PMMWSLE);
    MinWsSize = Count - 1;

    MmSystemCacheWorkingSetList->LastEntry = MinWsSize;
    MmSystemCacheWorkingSetList->LastInitializedWsle = MinWsSize;

    if (MaximumWorkingSetSize <= MinWsSize)
        MaximumWorkingSetSize = (MinWsSize + (PAGE_SIZE / sizeof(PMMWSLE)));

    MmSystemCacheWs.MinimumWorkingSetSize = MinWsSize;
    MmSystemCacheWs.MaximumWorkingSetSize = MaximumWorkingSetSize;

    Wsle = (MmSystemCacheWsle + 1);

    for (ix = 1; ix < Count; ix++, Wsle++)
        Wsle->u1.Long = ((ix + 1) * 0x10);

    Wsle--;
    Wsle->u1.Long = 0xFFFFFFF0; // (WSLE_NULL_INDEX * 0x10)

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
        CachePte += MM_PAGES_PER_VACB;
    }

    CachePte -= MM_PAGES_PER_VACB;
    CachePte->u.List.NextEntry = MM_EMPTY_PTE_LIST;

    MmLastFreeSystemCache = CachePte;

    MiAllowWorkingSetExpansion(&MmSystemCacheWs);
}

NTSTATUS
NTAPI
MmMapViewInSystemCache(
    _In_ PVOID SectionObject,
    _Out_ PVOID* OutBase,
    _In_ PLARGE_INTEGER SectionOffset,
    _In_ PULONG CapturedViewSize)
{
    PSECTION Section = SectionObject;
    PCONTROL_AREA ControlArea;
    PSUBSECTION Subsection;
    ULONGLONG OffsetInPages;
    ULONGLONG LastPage;
    PMMPTE Pte;
    PMMPTE LastPte;
    PMMPTE SectionProto;
    PMMPTE LastProto;
    MMPTE ProtoPte;
    ULONG SizeInPages;
    ULONG PteStamp;
    ULONG StampDiff;
    KIRQL OldIrql;
    NTSTATUS Status;

    DPRINT("MmMapViewInSystemCache: %p, [%p], [%I64X], [%X]\n", Section, (OutBase ? *OutBase : NULL),
           (SectionOffset ? SectionOffset->QuadPart : 0), (CapturedViewSize ? *CapturedViewSize : 0));

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
        Subsection = (PSUBSECTION)((PLARGE_CONTROL_AREA)ControlArea + 1);
    else
        Subsection = (PSUBSECTION)((PCONTROL_AREA)ControlArea + 1);

    OffsetInPages = (SectionOffset->QuadPart / PAGE_SIZE);
    SizeInPages = BYTES_TO_PAGES(*CapturedViewSize);
    LastPage = (OffsetInPages + SizeInPages);

    while (OffsetInPages >= (ULONGLONG)Subsection->PtesInSubsection)
    {
        OffsetInPages -= Subsection->PtesInSubsection;
        LastPage -= Subsection->PtesInSubsection;
        Subsection = Subsection->NextSubsection;

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

    MmFirstFreeSystemCache = (MmSystemCachePteBase + Pte->u.List.NextEntry);
    ASSERT(MmFirstFreeSystemCache <= MiAddressToPte(MmSystemCacheEnd));

    ControlArea->NumberOfMappedViews++;
    ControlArea->NumberOfSystemCacheViews++;

    ASSERT(ControlArea->NumberOfSectionReferences != 0);

    if (ControlArea->FilePointer)
    {
        Status = MiAddViewsForSection((PMSUBSECTION)Subsection, LastPage, OldIrql);

        ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

        if (!NT_SUCCESS(Status))
        {
            Pte->u.List.NextEntry = MM_EMPTY_PTE_LIST;
            Pte[1].u.List.NextEntry = KiTbFlushTimeStamp;

            OldIrql = MiLockPfnDb(APC_LEVEL);

            MmLastFreeSystemCache->u.List.NextEntry = (Pte - MmSystemCachePteBase);
            MmLastFreeSystemCache = Pte;

            ControlArea->NumberOfMappedViews--;
            ControlArea->NumberOfSystemCacheViews--;

            MiCheckControlArea(ControlArea, OldIrql);

            DPRINT("MmMapViewInSystemCache: return %X\n", Status);
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

    PteStamp = Pte[1].u.List.NextEntry;

    while (TRUE)
    {
        KeMemoryBarrier();

        StampDiff = ((KiTbFlushTimeStamp - PteStamp) & 0xFFFFF);

        if (StampDiff > 2 || (!(PteStamp & 1) && StampDiff >= 2))
            break;

        if (!(KiTbFlushTimeStamp & 1))
        {
            //MiFlushType[7]++;
            KeFlushEntireTb(TRUE, TRUE);
            break;
        }

        KeMemoryBarrier();

        while (KiTbFlushTimeStamp & 1)
            YieldProcessor();
    }

    *OutBase = MiPteToAddress(Pte);
    DPRINT("MmMapViewInSystemCache: Pte %p, *OutBase %p\n", Pte, *OutBase);

    Pte[1].u.List.NextEntry = 0;
    LastPte = &Pte[SizeInPages];

    SectionProto = &Subsection->SubsectionBase[OffsetInPages];
    LastProto = &Subsection->SubsectionBase[Subsection->PtesInSubsection];

    for (; Pte < LastPte; Pte++, SectionProto++)
    {
        if (SectionProto >= LastProto)
        {
            if (!Subsection->NextSubsection)
            {
                DPRINT("MmMapViewInSystemCache: Subsection %p\n", Subsection);
                break;
            }

            Subsection = Subsection->NextSubsection;

            SectionProto = Subsection->SubsectionBase;
            LastProto = &SectionProto[Subsection->PtesInSubsection];
        }

        MI_MAKE_PROTOTYPE_PTE(&ProtoPte, SectionProto);
        MI_WRITE_INVALID_PTE(Pte, ProtoPte);
    }

    return STATUS_SUCCESS;
}

BOOLEAN
NTAPI
MmCheckCachedPageState(
    _In_ PVOID CacheAddress,
    _In_ BOOLEAN Param2)
{
    PSUBSECTION Subsection;
    PETHREAD Thread;
    PMMPFN CachePfn;
    PMMPFN ProtoPfn;
    PMMPTE CachePte;
    PMMPTE SectionProto;
    PMMPTE ProtoPte;
    PMMPTE CachePde;
    MMPTE TempProto;
    MMPTE TempPte;
    MMWSLE TempWsle;
    PFN_NUMBER ProtoPageNumber;
    ULONG Protection;
    KIRQL OldIrql;

    DPRINT("MmCheckCachedPageState: CacheAddress %p, Param2 %X\n", CacheAddress, Param2);

    CachePte = MiAddressToPte(CacheAddress);

    if (CachePte->u.Hard.Valid)
    {
        DPRINT("MmCheckCachedPageState: return TRUE\n");
        return TRUE;
    }

    Thread = PsGetCurrentThread();
    MiLockWorkingSet(Thread, &MmSystemCacheWs);

    if (CachePte->u.Hard.Valid)
    {
        MiUnlockWorkingSet(Thread, &MmSystemCacheWs);
        DPRINT("MmCheckCachedPageState: return TRUE\n");
        return TRUE;
    }

    ASSERT(CachePte->u.Soft.Prototype == 1);

    SectionProto = MiGetProtoPtr(CachePte);
    ProtoPte = MiAddressToPte(SectionProto);

    OldIrql = MiLockPfnDb(APC_LEVEL);

    ASSERT(CachePte->u.Hard.Valid == 0);
    ASSERT(CachePte->u.Soft.Prototype == 1);

    if (!ProtoPte->u.Hard.Valid)
    {
        DPRINT1("MmCheckCachedPageState: FIXME\n");
        ASSERT(FALSE);
    }

    TempProto.u.Long = SectionProto->u.Long;
    ProtoPageNumber = TempProto.u.Hard.PageFrameNumber;

    if (SectionProto->u.Hard.Valid)
    {
        ProtoPfn = MI_PFN_ELEMENT(ProtoPageNumber);
        TempPte.u.Long = TempProto.u.Long;
    }
    else if (TempProto.u.Soft.Transition && !TempProto.u.Soft.Prototype)
    {
        ProtoPfn = MI_PFN_ELEMENT(ProtoPageNumber);

        if (ProtoPfn->u3.e1.ReadInProgress || ProtoPfn->u4.InPageError)
        {
            DPRINT("MmCheckCachedPageState: return TRUE\n");
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            MiUnlockWorkingSet(Thread, &MmSystemCacheWs);
            return TRUE;
        }

        if (MmAvailablePages < 0x80)
        {
            if (!PsGetCurrentThread()->MemoryMaker || !MmAvailablePages)
            {
                DPRINT("MmCheckCachedPageState: return TRUE\n");
                MiUnlockPfnDb(OldIrql, APC_LEVEL);
                MiUnlockWorkingSet(Thread, &MmSystemCacheWs);
                return TRUE;
            }
        }

        MiUnlinkPageFromList(ProtoPfn);
        InterlockedIncrement16((PSHORT)&ProtoPfn->u3.e2.ReferenceCount);
        ProtoPfn->u3.e1.PageLocation = ActiveAndValid;

        Protection = ProtoPfn->OriginalPte.u.Soft.Protection;
        Protection &= ~(MM_NOCACHE | MM_WRITECOMBINE);

        if (ProtoPfn->u3.e1.CacheAttribute != MiCached)
        {
            if (ProtoPfn->u3.e1.CacheAttribute == MiNonCached)
                Protection |= MM_NOCACHE;
            else if (ProtoPfn->u3.e1.CacheAttribute == MiWriteCombined)
                Protection |= MM_WRITECOMBINE;
        }

        MI_MAKE_HARDWARE_PTE_KERNEL(&TempPte, (MiHighestUserPte + 1), Protection, ProtoPageNumber);
        MI_WRITE_VALID_PTE(SectionProto, TempPte);

        CachePfn = MI_PFN_ELEMENT(ProtoPfn->u4.PteFrame);
    }
    else
    {
        if (!Param2 || MmAvailablePages < 0x80)
        {
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            MiUnlockWorkingSet(Thread, &MmSystemCacheWs);

            MmAccessFault(0, CacheAddress, KernelMode, NULL);

            DPRINT("MmCheckCachedPageState: return FALSE\n");
            return FALSE;
        }

        Subsection = MiSubsectionPteToSubsection(SectionProto);
        Subsection->ControlArea->NumberOfPfnReferences++;

        ProtoPageNumber = MiRemoveZeroPage(MiGetColor());
        ProtoPfn = MI_PFN_ELEMENT(ProtoPageNumber);

        MiInitializePfn(ProtoPageNumber, SectionProto, 1);

        ProtoPfn->u2.ShareCount = 0;
        ProtoPfn->u3.e1.PrototypePte = 1;

        MI_MAKE_HARDWARE_PTE_KERNEL(&TempPte,
                                    (MiHighestUserPte + 1),
                                    ProtoPfn->OriginalPte.u.Soft.Protection,
                                    ProtoPageNumber);

        MI_WRITE_VALID_PTE(SectionProto, TempPte);
    }

    ProtoPfn->u2.ShareCount++;

    CachePde = MiAddressToPte(CachePte);

    CachePfn = MI_PFN_ELEMENT(CachePde->u.Hard.PageFrameNumber);
    CachePfn->u2.ShareCount++;

    TempPte.u.Hard.Owner = 0;
    MI_WRITE_VALID_PTE(CachePte, TempPte);

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    TempWsle.u1.Long = 0;

    if (!MiAllocateWsle(&MmSystemCacheWs, CachePte, ProtoPfn, TempWsle))
    {
        ASSERT(ProtoPfn->u3.e1.PrototypePte == 1);
        ASSERT(SectionProto == ProtoPfn->PteAddress);

        DPRINT1("MmCheckCachedPageState: FIXME MiTrimPte()\n");
        ASSERT(FALSE);
    }

    MiUnlockWorkingSet(Thread, &MmSystemCacheWs);

    DPRINT("MmCheckCachedPageState: return TRUE\n");
    return TRUE;
}

VOID
NTAPI
MmUnmapViewInSystemCache(
    _In_ PVOID BaseAddress,
    _In_ PVOID SectionObject,
    _In_ ULONG FrontOfList)
{
    MMPTE CacheChunkPte[MM_PAGES_PER_VACB];
    PSECTION Section = SectionObject;
    PFILE_OBJECT FileObject;
    PCONTROL_AREA ControlArea;
    PMSUBSECTION Subsection = NULL;
    PETHREAD Thread;
    PMMPTE Pte;
    PMMPTE StartPte;
    PMMPTE LastPte;
    PMMPTE SectionProto = NULL;
    PMMPTE ProtoPde;
    MMPTE TempPte;
    MMPTE TempProto;
    PMMPFN StartPfn;
    PMMPFN Pfn;
    PFN_NUMBER StartPageNumber;
    PFN_NUMBER PageNumber;
    ULONG Idx;
    ULONG ix;
    BOOLEAN IsLocked = FALSE;
    KIRQL OldIrql;

    DPRINT("MmUnmapViewInSystemCache: BaseAddress %p, Section %p, FrontOfList %X\n", BaseAddress, Section, FrontOfList);

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    Thread = PsGetCurrentThread();

    StartPte = MiAddressToPte(BaseAddress);
    LastPte = (StartPte + MM_PAGES_PER_VACB);

    DPRINT("MmUnmapViewInSystemCache: StartPte %p, LastPte %p\n", StartPte, LastPte);

    StartPageNumber = MiAddressToPte(StartPte)->u.Hard.PageFrameNumber;
    StartPfn = MI_PFN_ELEMENT(StartPageNumber);

    ControlArea = Section->Segment->ControlArea;
    FileObject = ControlArea->FilePointer;

    ASSERT((ControlArea->u.Flags.Image == 0) &&
           (ControlArea->u.Flags.PhysicalMemory == 0) &&
           (ControlArea->u.Flags.GlobalOnlyPerSession == 0));

    for (Pte = StartPte, Idx = 0; Pte < LastPte; )
    {
        TempPte.u.Long = Pte->u.Long;
        CacheChunkPte[Idx] = TempPte;

        if (TempPte.u.Hard.Valid)
        {
            if (!IsLocked)
            {
                IsLocked = TRUE;
                MiLockWorkingSet(Thread, &MmSystemCacheWs);
                continue;
            }

            Pfn = MI_PFN_ELEMENT(TempPte.u.Hard.PageFrameNumber);

            MiTerminateWsle(BaseAddress, &MmSystemCacheWs, Pfn->u1.WsIndex);

            if (FileObject)
            {
                ASSERT(Pfn->u3.e1.PrototypePte);
                ASSERT(Pfn->OriginalPte.u.Soft.Prototype);

                SectionProto = Pfn->PteAddress;

                if (!Subsection)
                    Subsection = (PMSUBSECTION)MiSubsectionPteToSubsection(&Pfn->OriginalPte);
            }

            goto Next;
        }

        if (!TempPte.u.Soft.Prototype)
        {
            ULONG size = ((LastPte - Pte) * sizeof(MMPTE));

            ASSERT(TempPte.u.Long == 0);
            ASSERT(RtlCompareMemoryUlong(Pte, size, 0) == size);

            break;
        }

        if (!FileObject)
            goto Next;

        SectionProto = MiGetProtoPtr(&TempPte);

        if (Subsection)
            goto Next;

        ProtoPde = MiAddressToPte(SectionProto);

        OldIrql = MiLockPfnDb(APC_LEVEL);

        if (!ProtoPde->u.Hard.Valid)
        {
            if (IsLocked)
            {
                DPRINT1("MmUnmapViewInSystemCache: FIXME MiMakeSystemAddressValidPfnSystemWs \n");
                ASSERT(FALSE);
            }
            else
            {
                DPRINT1("MmUnmapViewInSystemCache: FIXME MiMakeSystemAddressValidPfn \n");
                ASSERT(FALSE);
            }
        }

        TempProto.u.Long = SectionProto->u.Long;

        if (TempProto.u.Hard.Valid)
        {
            PageNumber = TempProto.u.Hard.PageFrameNumber;
            Pfn = MI_PFN_ELEMENT(PageNumber);
            SectionProto = &Pfn->OriginalPte;
        }
        else if (TempProto.u.Soft.Transition && !TempProto.u.Soft.Prototype)
        {
            PageNumber = TempProto.u.Trans.PageFrameNumber;
            Pfn = MI_PFN_ELEMENT(PageNumber);
            SectionProto = &Pfn->OriginalPte;
        }
        else
        {
            ASSERT(TempProto.u.Soft.Prototype == 1);
        }

        Subsection = (PMSUBSECTION)MiSubsectionPteToSubsection(SectionProto);

        MiUnlockPfnDb(OldIrql, APC_LEVEL);
Next:
        MI_ERASE_PTE(Pte);

        BaseAddress = Add2Ptr(BaseAddress, PAGE_SIZE);
        Idx++;
        Pte++;
    }

    if (IsLocked)
        MiUnlockWorkingSet(Thread, &MmSystemCacheWs);

    StartPte->u.List.NextEntry = MM_EMPTY_PTE_LIST;
    StartPte[1].u.List.NextEntry = KiTbFlushTimeStamp;

    if (Subsection && Subsection->ControlArea != ControlArea)
    {
        DPRINT1("MmUnmapViewInSystemCache: FIXME KeBugCheckEx()\n");
        ASSERT(FALSE);
    }

    OldIrql = MiLockPfnDb(APC_LEVEL);

    MmLastFreeSystemCache->u.List.NextEntry = (StartPte - MmSystemCachePteBase);
    MmLastFreeSystemCache = StartPte;

    MmFrontOfList = FrontOfList;

    for (ix = 0; ix < Idx; ix++)
    {
        if (!CacheChunkPte[ix].u.Hard.Valid)
            continue;

        PageNumber = CacheChunkPte[ix].u.Hard.PageFrameNumber;
        Pfn = MI_PFN_ELEMENT(PageNumber);

        ASSERT(KeGetCurrentIrql() > APC_LEVEL);

        if (!Pfn->u3.e1.Modified &&
            CacheChunkPte[ix].u.Hard.Dirty)
        {
            ASSERT(Pfn->u3.e1.Rom == 0);
            Pfn->u3.e1.Modified = 1;

            if (!Pfn->OriginalPte.u.Soft.Prototype &&
                !Pfn->u3.e1.WriteInProgress)
            {
                DPRINT1("MmUnmapViewInSystemCache: FIXME MiReleasePageFileSpace \n");
                ASSERT(FALSE);
                Pfn->OriginalPte.u.Soft.PageFileHigh = 0;
            }
        }

        MiDecrementPfnShare(StartPfn, StartPageNumber);

        if (ControlArea->NumberOfMappedViews == 1)
        {
            ASSERT(Pfn->u2.ShareCount == 1);
        }

        MiDecrementPfnShare(Pfn, PageNumber);
    }

    MmFrontOfList = 0;

    while (Subsection)
    {
        ASSERT(SectionProto != NULL);
        ASSERT((Subsection->NumberOfMappedViews >= 1) ||
               (Subsection->u.SubsectionFlags.SubsectionStatic == 1));

        MiRemoveViewsFromSection(Subsection, Subsection->PtesInSubsection);

        if (SectionProto >= Subsection->SubsectionBase &&
            SectionProto < &Subsection->SubsectionBase[Subsection->PtesInSubsection])
        {
            break;
        }

        Subsection = (PMSUBSECTION)Subsection->NextSubsection;
        if (!Subsection)
        {
            DPRINT1("MmUnmapViewInSystemCache: FIXME KeBugCheckEx()\n");
            ASSERT(FALSE);
        }

        ASSERT(Subsection->ControlArea == ControlArea);
    }

    ControlArea->NumberOfMappedViews--;
    ControlArea->NumberOfSystemCacheViews--;

    MiCheckControlArea(ControlArea, OldIrql);
}

NTSTATUS
NTAPI
MmCopyToCachedPage(
    _In_ PVOID SystemCacheAddress,
    _In_ PVOID InBuffer,
    _In_ ULONG Offset,
    _In_ ULONG CountInBytes,
    _In_ BOOLEAN IsNeedZeroPage)
{
    PETHREAD CurrentThread = PsGetCurrentThread();
    PMI_PAGE_SUPPORT_BLOCK PageBlock = NULL;
    MI_PFN_CACHE_ATTRIBUTE CacheAttribute;
    PCONTROL_AREA ControlArea;
    PSUBSECTION Subsection;
    PMMPFN LockedProtoPfn;
    PMMPFN Pfn = NULL;
    PMMPFN pfn;
    PMMPTE Pte;
    PMMPTE Proto = NULL;
    PMMPTE ProtoPte;
    PMMPTE CopyPte;
    MMPTE TempPte;
    MMPTE TempProto;
    MMWSLE TempWsle;
    PVOID CopyBuffer;
    PVOID StartVa;
    PVOID Buffer;
    PFN_NUMBER PageNumber;
    ULONG Color;
    ULONG OldReadClusterSize;
    UCHAR OldForwardClusterOnly;
    BOOLEAN IsForceIrpComplete = FALSE;
    BOOLEAN NewPage = FALSE;
    BOOLEAN IsFlush;
    KIRQL OldIrql;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("MmCopyToCachedPage: %p, %p, %X, %X, %X\n", SystemCacheAddress, InBuffer, Offset, CountInBytes, IsNeedZeroPage);

    ASSERT(((ULONG_PTR)SystemCacheAddress & (PAGE_SIZE - 1)) == 0);
    ASSERT((CountInBytes + Offset) <= PAGE_SIZE);
    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    Pte = MiAddressToPte(SystemCacheAddress);
    if (Pte->u.Hard.Valid)
        goto Finish;

    _SEH2_TRY
    {
        *(volatile CHAR *)InBuffer;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
        DPRINT1("MmCopyToCachedPage: Status %X\n", Status);
        return Status;
    }
    _SEH2_END;

    MiLockWorkingSet(CurrentThread, &MmSystemCacheWs);

    if (Pte->u.Hard.Valid)
    {
        MiUnlockWorkingSet(CurrentThread, &MmSystemCacheWs);
        goto Finish;
    }

    ASSERT(Pte->u.Soft.Prototype == 1);

    Proto = MiGetProtoPtr(Pte);
    ProtoPte = MiAddressToPte(Proto);

    OldIrql = MiLockPfnDb(APC_LEVEL);

    ASSERT(Pte->u.Hard.Valid == 0);

    while (TRUE)
    {
        if (Pte->u.Hard.Valid)
        {
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            MiUnlockWorkingSet(CurrentThread, &MmSystemCacheWs);
            goto Finish;
        }

        ASSERT(Pte->u.Soft.Prototype == 1);

        if (!ProtoPte->u.Hard.Valid)
        {
            DPRINT1("MmCopyToCachedPage: FIXME\n");
            ASSERT(FALSE);

            //MiMakeSystemAddressValidPfnSystemWs(..);

            if (Pte->u.Hard.Valid)
            {
                MiUnlockPfnDb(OldIrql, APC_LEVEL);
                MiUnlockWorkingSet(CurrentThread, &MmSystemCacheWs);
                goto Finish;
            }
        }

        TempProto = *Proto;
        DPRINT("MmCopyToCachedPage: %p, %p\n", Proto, TempProto);

        if (TempProto.u.Hard.Valid)
            break;

        if (TempProto.u.Soft.Transition && !TempProto.u.Soft.Prototype)
        {
            ASSERT((SPFN_NUMBER)MmAvailablePages >= 0);

            if (MmAvailablePages >= 2 || !MiEnsureAvailablePageOrWait(NULL, OldIrql))
                break;
        }
        else
        {
            if (MmAvailablePages < 0x80 && MiEnsureAvailablePageOrWait(NULL, OldIrql))
                continue;

            if (IsNeedZeroPage)
                break;

            PageBlock = MiGetInPageSupportBlock(OldIrql, &Status);
            if (PageBlock)
                break;

            Status = STATUS_SUCCESS;
        }
    }

    if (TempProto.u.Hard.Valid)
    {
        DPRINT1("MmCopyToCachedPage: FIXME\n");
        ASSERT(FALSE);
    }
    else if (TempProto.u.Soft.Transition && !TempProto.u.Soft.Prototype)
    {
        ULONG Protection;

        PageNumber = TempProto.u.Trans.PageFrameNumber;
        Pfn = MI_PFN_ELEMENT(PageNumber);

        if (Pfn->u3.e1.ReadInProgress || Pfn->u4.InPageError)
        {
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            MiUnlockWorkingSet(CurrentThread, &MmSystemCacheWs);
            goto Finish;
        }

        ASSERT(MmAvailablePages >= 2);

        MiUnlinkPageFromList(Pfn);
        InterlockedIncrement16((PSHORT)&Pfn->u3.e2.ReferenceCount);
        Pfn->u3.e1.PageLocation = ActiveAndValid;

        ASSERT(Pfn->u3.e1.Rom == 0);
        Pfn->u3.e1.Modified = 1;

        ASSERT(Pfn->u2.ShareCount == 0);
        Pfn->u2.ShareCount++;

        Protection = (Pfn->OriginalPte.u.Soft.Protection & ~(MM_NOCACHE | MM_WRITECOMBINE));

        if (Pfn->u3.e1.CacheAttribute == MiNonCached)
            Protection |= MM_NOCACHE;
        else if (Pfn->u3.e1.CacheAttribute == MiWriteCombined)
            Protection |= MM_WRITECOMBINE;

        MI_MAKE_HARDWARE_PTE(&TempPte, NULL, Protection, PageNumber);
        MI_MAKE_DIRTY_PAGE(&TempPte);
        MI_WRITE_VALID_PTE(Proto, TempPte);
    }
    else
    {
        if (IsNeedZeroPage)
        {
            Color = MiGetColor();

            PageNumber = MiRemoveZeroPageSafe(Color);
            if (!PageNumber)
            {
                PageNumber = MiRemoveAnyPage(Color);
                MiZeroPhysicalPage(PageNumber);
            }
                
            Pfn = MI_PFN_ELEMENT(PageNumber);

            ASSERT(Pfn->u2.ShareCount == 0);
            ASSERT(Pfn->u3.e2.ReferenceCount == 0);

            MiInitializePfn(PageNumber, Proto, 1);
    
            Pfn->u3.e1.PrototypePte = 1;
            Pfn->u1.Event = NULL;

            Subsection = MiSubsectionPteToSubsection(Proto);

            ControlArea = Subsection->ControlArea;
            ControlArea->NumberOfPfnReferences++;
    
            MI_MAKE_HARDWARE_PTE(&TempPte, NULL, Pfn->OriginalPte.u.Soft.Protection, PageNumber);

            MI_MAKE_DIRTY_PAGE(&TempPte);
            MI_WRITE_VALID_PTE(Proto, TempPte);

            ASSERT(PageBlock == NULL);
            ASSERT(NewPage == FALSE);
        }
        else
        {
            PKTHREAD kThread = &CurrentThread->Tcb;

            LockedProtoPfn = MI_PFN_ELEMENT(ProtoPte->u.Hard.PageFrameNumber);
            MiReferenceUsedPageAndBumpLockCount(LockedProtoPfn);
            ASSERT(LockedProtoPfn->u3.e2.ReferenceCount > 1);

            Subsection = MiSubsectionPteToSubsection(Proto);
            ControlArea = Subsection->ControlArea;
            Subsection->ControlArea->NumberOfPfnReferences++;

            DPRINT("MmCopyToCachedPage: %p, %p, %p, %p\n", PageBlock, LockedProtoPfn, Proto, ControlArea);

            PageNumber = MiRemoveAnyPage(MiGetColor());
            Pfn = MI_PFN_ELEMENT(PageNumber);

            ASSERT(Pfn->u2.ShareCount == 0);
            ASSERT(Pfn->u3.e2.ReferenceCount == 0);

            MiInitializeTransitionPfn(PageNumber, Proto);

            ASSERT(Pfn->u2.ShareCount == 0);
            ASSERT(Pfn->u3.e2.ReferenceCount == 0);
            ASSERT(Pfn->u3.e1.PrototypePte == 1);

            MiReferenceUnusedPageAndBumpLockCount(Pfn);

            Pfn->u4.InPageError = 0;
            Pfn->u3.e1.ReadInProgress = 1;
            Pfn->u1.Event = &PageBlock->Event;
            PageBlock->Pfn = Pfn;

            if ((TempProto.u.Soft.Protection & MM_WRITECOMBINE) == MM_WRITECOMBINE &&
                TempProto.u.Soft.Protection & MM_PROTECT_ACCESS)
            {
                CacheAttribute = MiPlatformCacheAttributes[0][MmWriteCombined];
            }
            else if ((TempProto.u.Soft.Protection & MM_NOCACHE) == MM_NOCACHE)
            {
                CacheAttribute = MiPlatformCacheAttributes[0][MmNonCached];
            }
            else
            {
                CacheAttribute = MiCached;
            }

            if (Pfn->u3.e1.CacheAttribute != CacheAttribute)
            {
                Pfn->u3.e1.CacheAttribute = CacheAttribute;
                IsFlush = TRUE;
            }
            else
            {
                IsFlush = FALSE;
            }

            ASSERT(CurrentThread->ActiveFaultCount <= 1);
            CurrentThread->ActiveFaultCount++;

            MI_MAKE_HARDWARE_PTE(&TempPte, NULL, Pfn->OriginalPte.u.Soft.Protection, PageNumber);
            MI_MAKE_DIRTY_PAGE(&TempPte);

            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            KeEnterCriticalRegionThread(kThread);
            MiUnlockWorkingSet(CurrentThread, &MmSystemCacheWs);

            if (IsFlush)
            {
                //MiFlushTbForAttributeChange++;
                KeFlushEntireTb(TRUE, TRUE);

                if (CacheAttribute != MiCached)
                {
                    //MiFlushCacheForAttributeChange++;
                    KeInvalidateAllCaches();
                }
            }

            CopyPte = MiReserveSystemPtes(1, SystemPteSpace);

            if (CopyPte)
            {
                ASSERT(CopyPte > MiHighestUserPte);
                ASSERT(!MI_IS_SESSION_PTE (CopyPte));
                ASSERT((CopyPte < (PMMPTE)PDE_BASE) || (CopyPte > (PMMPTE)PDE_TOP));

                TempPte.u.Long = 0;
                TempPte.u.Hard.Valid = 1;
                TempPte.u.Hard.Accessed = 1;
                TempPte.u.Hard.PageFrameNumber = PageNumber;
                //TempPte.u.Long |= MmPteGlobal.u.Long;
                TempPte.u.Long |= MmProtectToPteMask[MM_READWRITE];
                MI_MAKE_DIRTY_PAGE(&TempPte);

                ASSERT(CopyPte->u.Hard.Valid == 0);
                ASSERT(TempPte.u.Hard.Valid == 1);
                *CopyPte = TempPte;

                StartVa = MiPteToAddress(CopyPte);

                if (Offset)
                    RtlZeroMemory(StartVa, Offset);

                Buffer = Add2Ptr(StartVa, Offset);

                if ((Offset + CountInBytes) != PAGE_SIZE)
                    RtlZeroMemory(Add2Ptr(Buffer, CountInBytes), (PAGE_SIZE - (Offset + CountInBytes)));

                /* Save previous values */
                OldForwardClusterOnly = CurrentThread->ForwardClusterOnly;
                OldReadClusterSize = CurrentThread->ReadClusterSize;

                CurrentThread->ForwardClusterOnly = 1;
                CurrentThread->ReadClusterSize = 0;

                //_SEH2_TRY
                {
                    RtlCopyBytes(Buffer, InBuffer, CountInBytes);
                }
                //_SEH2_EXCEPT()
                {
                    //FIXME
                }
                //_SEH2_END;

                /* Restore claster variables */
                CurrentThread->ForwardClusterOnly = OldForwardClusterOnly;
                CurrentThread->ReadClusterSize = OldReadClusterSize;

                MiReleaseSystemPtes(CopyPte, 1, SystemPteSpace);

                NewPage = 1;
            }
            else
            {
                DPRINT1("MmCopyToCachedPage: STATUS_INSUFFICIENT_RESOURCES\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
            }

            MiLockWorkingSet(CurrentThread, &MmSystemCacheWs);
            KeLeaveCriticalRegionThread(kThread);
            OldIrql = MiLockPfnDb(APC_LEVEL);

            ASSERT(Pfn->u3.e1.PrototypePte == 1);
            ASSERT(Pfn->u3.e2.ReferenceCount >= 1);
            ASSERT(Pfn->u3.e1.Modified == 0);

            ASSERT(Pfn->u3.e1.ReadInProgress == 1);
            Pfn->u3.e1.ReadInProgress = 0;

            ASSERT(Pfn->u2.ShareCount == 0);
            ASSERT(Pfn->u4.PteFrame != MI_MAGIC_AWE_PTEFRAME);

            ASSERT(PageBlock->u1.e1.InPageComplete == 0);
            ASSERT(Pfn->u1.Event == &PageBlock->Event);
            Pfn->u1.Event = NULL;

            if (!NT_SUCCESS(Status))
            {
                Pfn->u4.InPageError = 1;
                Pfn->u1.ReadStatus = Status;

                DPRINT1("MmCopyToCachedPage: Status %X\n", Status);

                MiDereferencePfnAndDropLockCount(Pfn);

                if (!Pfn->u3.e2.ReferenceCount)
                {
                    ASSERT(Pfn->u3.e1.PageLocation == StandbyPageList);
                    Pfn->u4.InPageError = 0;

                    MiUnlinkPageFromList(Pfn);
                    MiRestoreTransitionPte(Pfn);
                    MiInsertPageInFreeList(PageNumber);
                }
            }
            else
            {
                MiDropLockCount(Pfn);
                Pfn->u3.e1.PageLocation = ActiveAndValid;

                ASSERT(Pfn->u3.e1.Rom == 0);
                Pfn->u3.e1.Modified = 1;
                Pfn->u2.ShareCount++;

                MI_MAKE_HARDWARE_PTE(&TempPte, NULL, Pfn->OriginalPte.u.Soft.Protection, PageNumber);
                MI_MAKE_DIRTY_PAGE(&TempPte);
                //TempPte.u.Long &= ~MmPteGlobal.u.Long;
                MI_WRITE_VALID_PTE(Proto, TempPte);
                DPRINT("MmCopyToCachedPage: Proto %p, TempPte %X\n", Proto, TempPte);
            }

            if (PageBlock->WaitCount != 1)
            {
                PageBlock->u1.e1.InPageComplete = 1;
                PageBlock->IoStatus.Status = Status;
                PageBlock->IoStatus.Information = 0;

                KeSetEvent(&PageBlock->Event, 0, FALSE);
            }

            ASSERT(CurrentThread->ActiveFaultCount <= 3);
            ASSERT(CurrentThread->ActiveFaultCount != 0);

            CurrentThread->ActiveFaultCount--;

            if (CurrentThread->ApcNeeded == 1 && !CurrentThread->ActiveFaultCount)
            {
                IsForceIrpComplete = TRUE;
                CurrentThread->ApcNeeded = 0;
            }

            ASSERT(LockedProtoPfn->u3.e2.ReferenceCount >= 1);
            MiDereferencePfnAndDropLockCount(LockedProtoPfn);

            if (!NT_SUCCESS(Status))
            {
                MiUnlockPfnDb(OldIrql, APC_LEVEL);
                MiUnlockWorkingSet(CurrentThread, &MmSystemCacheWs);

                DPRINT1("MmCopyToCachedPage: FIXME\n");
                ASSERT(FALSE);
            }
        }
    }

    pfn = MI_PFN_ELEMENT(MiAddressToPte(Pte)->u.Hard.PageFrameNumber);
    pfn->u2.ShareCount++;

    TempPte.u.Hard.Owner = 0;
    //TempPte.u.Long |= MmPteGlobal.u.Long;
    MI_WRITE_VALID_PTE(Pte, TempPte);

    DPRINT("MmCopyToCachedPage: Proto %p, TempPte %X\n", Proto, TempPte);

    ASSERT(Pfn->u3.e2.ReferenceCount != 0);
    ASSERT(Pfn->PteAddress == Proto);

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    TempWsle.u1.Long = 0;
    if (!MiAllocateWsle(&MmSystemCacheWs, Pte, Pfn, TempWsle))
    {
        ASSERT(Pfn->u3.e1.PrototypePte == 1);
        ASSERT(Proto == Pfn->PteAddress);

        DPRINT1("MmCopyToCachedPage: FIXME MiTrimPte()\n");
        ASSERT(FALSE);
    }

    MiUnlockWorkingSet(CurrentThread, &MmSystemCacheWs);

    if (!PageBlock)
        goto Finish;

    MiFreeInPageSupportBlock(PageBlock);

    if (IsForceIrpComplete)
    {
        ASSERT(OldIrql == PASSIVE_LEVEL);
        ASSERT(CurrentThread->ActiveFaultCount == 0);

        DPRINT1("MmCopyToCachedPage: FIXME IoRetryIrpCompletions()\n");
        ASSERT(FALSE);
    }

    if (Status == STATUS_INSUFFICIENT_RESOURCES)
    {
        ASSERT(NewPage == FALSE);
        Status = STATUS_SUCCESS;
    }

Finish:

    if (!NewPage)
    {
        /* Save previous values */
        OldForwardClusterOnly = CurrentThread->ForwardClusterOnly;
        OldReadClusterSize = CurrentThread->ReadClusterSize;

        CurrentThread->ForwardClusterOnly = 1;
        CurrentThread->ReadClusterSize = 0;

        CopyBuffer = Add2Ptr(SystemCacheAddress, Offset);
        ASSERT(Status == STATUS_SUCCESS);

        //_SEH2_TRY
        {
            RtlCopyBytes(CopyBuffer, InBuffer, CountInBytes);
        }
        //_SEH2_EXCEPT()
        {
            //FIXME
        }
        //_SEH2_END;
    
        /* Restore claster variables */
        CurrentThread->ForwardClusterOnly = OldForwardClusterOnly;
        CurrentThread->ReadClusterSize = OldReadClusterSize;
    }

    DPRINT("MmCopyToCachedPage: Status %X\n", Status);
    return Status;
}

/* EOF */
