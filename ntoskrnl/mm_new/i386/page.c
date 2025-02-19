
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>
#include <mm_new/ARM3/miarm.h>

/* GLOBALS ********************************************************************/

const
ULONG
MmProtectToPteMask[32] =
{
    //
    // These are the base MM_ protection flags
    //
    0,
    PTE_READONLY            | PTE_ENABLE_CACHE,
    PTE_EXECUTE             | PTE_ENABLE_CACHE,
    PTE_EXECUTE_READ        | PTE_ENABLE_CACHE,
    PTE_READWRITE           | PTE_ENABLE_CACHE,
    PTE_WRITECOPY           | PTE_ENABLE_CACHE,
    PTE_EXECUTE_READWRITE   | PTE_ENABLE_CACHE,
    PTE_EXECUTE_WRITECOPY   | PTE_ENABLE_CACHE,
    //
    // These OR in the MM_NOCACHE flag
    //
    0,
    PTE_READONLY            | PTE_DISABLE_CACHE,
    PTE_EXECUTE             | PTE_DISABLE_CACHE,
    PTE_EXECUTE_READ        | PTE_DISABLE_CACHE,
    PTE_READWRITE           | PTE_DISABLE_CACHE,
    PTE_WRITECOPY           | PTE_DISABLE_CACHE,
    PTE_EXECUTE_READWRITE   | PTE_DISABLE_CACHE,
    PTE_EXECUTE_WRITECOPY   | PTE_DISABLE_CACHE,
    //
    // These OR in the MM_DECOMMIT flag, which doesn't seem supported on x86/64/ARM
    //
    0,
    PTE_READONLY            | PTE_ENABLE_CACHE,
    PTE_EXECUTE             | PTE_ENABLE_CACHE,
    PTE_EXECUTE_READ        | PTE_ENABLE_CACHE,
    PTE_READWRITE           | PTE_ENABLE_CACHE,
    PTE_WRITECOPY           | PTE_ENABLE_CACHE,
    PTE_EXECUTE_READWRITE   | PTE_ENABLE_CACHE,
    PTE_EXECUTE_WRITECOPY   | PTE_ENABLE_CACHE,
    //
    // These OR in the MM_NOACCESS flag, which seems to enable WriteCombining?
    //
    0,
    PTE_READONLY            | PTE_WRITECOMBINED_CACHE,
    PTE_EXECUTE             | PTE_WRITECOMBINED_CACHE,
    PTE_EXECUTE_READ        | PTE_WRITECOMBINED_CACHE,
    PTE_READWRITE           | PTE_WRITECOMBINED_CACHE,
    PTE_WRITECOPY           | PTE_WRITECOMBINED_CACHE,
    PTE_EXECUTE_READWRITE   | PTE_WRITECOMBINED_CACHE,
    PTE_EXECUTE_WRITECOPY   | PTE_WRITECOMBINED_CACHE,
};

const
ULONG MmProtectToValue[32] =
{
    PAGE_NOACCESS,
    PAGE_READONLY,
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_READWRITE,
    PAGE_WRITECOPY,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
    PAGE_NOACCESS,
    PAGE_NOCACHE | PAGE_READONLY,
    PAGE_NOCACHE | PAGE_EXECUTE,
    PAGE_NOCACHE | PAGE_EXECUTE_READ,
    PAGE_NOCACHE | PAGE_READWRITE,
    PAGE_NOCACHE | PAGE_WRITECOPY,
    PAGE_NOCACHE | PAGE_EXECUTE_READWRITE,
    PAGE_NOCACHE | PAGE_EXECUTE_WRITECOPY,
    PAGE_NOACCESS,
    PAGE_GUARD | PAGE_READONLY,
    PAGE_GUARD | PAGE_EXECUTE,
    PAGE_GUARD | PAGE_EXECUTE_READ,
    PAGE_GUARD | PAGE_READWRITE,
    PAGE_GUARD | PAGE_WRITECOPY,
    PAGE_GUARD | PAGE_EXECUTE_READWRITE,
    PAGE_GUARD | PAGE_EXECUTE_WRITECOPY,
    PAGE_NOACCESS,
    PAGE_WRITECOMBINE | PAGE_READONLY,
    PAGE_WRITECOMBINE | PAGE_EXECUTE,
    PAGE_WRITECOMBINE | PAGE_EXECUTE_READ,
    PAGE_WRITECOMBINE | PAGE_READWRITE,
    PAGE_WRITECOMBINE | PAGE_WRITECOPY,
    PAGE_WRITECOMBINE | PAGE_EXECUTE_READWRITE,
    PAGE_WRITECOMBINE | PAGE_EXECUTE_WRITECOPY
};

extern ULONG MmProcessColorSeed;
extern ULONG MmSecondaryColorMask;
extern MMPTE ValidKernelPteLocal;
extern LIST_ENTRY MmProcessList;
extern PVOID MmHyperSpaceEnd;
extern MMPDE ValidPdePde;
extern SIZE_T MmProcessCommit;

/* FUNCTIONS ******************************************************************/

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(INIT, MmInitGlobalKernelPageDirectory)
#endif

ULONG
NTAPI
MmGetPageProtect(PEPROCESS Process, PVOID Address)
{
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

VOID
NTAPI
MmSetPageProtect(PEPROCESS Process, PVOID Address, ULONG flProtect)
{
    UNIMPLEMENTED_DBGBREAK();
}

CODE_SEG("INIT")
VOID
NTAPI
MmInitGlobalKernelPageDirectory(VOID)
{
    ;/* Nothing to do here */
}

BOOLEAN
NTAPI
MmCreateProcessAddressSpace(
    _In_ ULONG MinWs,
    _In_ PEPROCESS Process,
    _Out_ PULONG_PTR DirectoryTableBase)
{
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    PFN_NUMBER PdeIndex;
    PFN_NUMBER HyperIndex;
    PFN_NUMBER WsIndex;
    PFN_NUMBER VadBitmapIndex;
    PMMPDE SystemTable;
    PMMPDE HyperTable;
    PMMPTE systemPte;
    MMPDE TempPde;
    PMMPFN Pfn;
    ULONG PdeOffset;
    ULONG Color;
    KIRQL OldIrql;
    BOOLEAN IsFlushTb;

    DPRINT("MmCreateProcessAddressSpace: MinWs %X, Process %p (%X)\n", MinWs, Process, MmTotalCommittedPages);

    if (!MiChargeCommitment(4, NULL))
    {
        DPRINT1("MmCreateProcessAddressSpace: MiChargeCommitment() failed\n");
        return FALSE;
    }

    /* Choose a process color */
    Process->NextPageColor = (USHORT)RtlRandom(&MmProcessColorSeed);

    /* Setup the hyperspace lock */
    KeInitializeSpinLock(&Process->HyperSpaceLock);

    /* Lock PFN database */
    OldIrql = MiLockPfnDb(APC_LEVEL);

    if ((PFN_NUMBER)MinWs >= (MmResidentAvailablePages - MmSystemLockPagesCount))
    {
        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        ASSERT(MmTotalCommittedPages >= 4);
        InterlockedExchangeAddSizeT(&MmTotalCommittedPages, -4);

        DPRINT1("MmCreateProcessAddressSpace: %X, %IX, %IX\n", MinWs, MmResidentAvailablePages, MmSystemLockPagesCount);
        return FALSE;
    }

    InterlockedExchangeAddSizeT(&MmResidentAvailablePages, -MinWs);

    if (MmAvailablePages < 0x80)
        MiEnsureAvailablePageOrWait(NULL, OldIrql);

    /* Get a zero page for the PDE, if possible */
    Color = MI_GET_NEXT_PROCESS_COLOR(CurrentProcess);
    MI_SET_USAGE(MI_USAGE_PAGE_DIRECTORY);

    PdeIndex = MiRemoveZeroPageSafe(Color);
    if (!PdeIndex)
    {
        /* No zero pages, grab a free one */
        PdeIndex = MiRemoveAnyPage(Color);

        /* Zero it outside the PFN lock */
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        MiZeroPhysicalPage(PdeIndex);
        OldIrql = MiLockPfnDb(APC_LEVEL);
    }

    Pfn = MiGetPfnEntry(PdeIndex);
    if (Pfn->u3.e1.CacheAttribute != MiCached)
    {
        Pfn->u3.e1.CacheAttribute = MiCached;
        IsFlushTb = TRUE;
    }

    if (MmAvailablePages < 0x80)
        MiEnsureAvailablePageOrWait(NULL, OldIrql);

    /* Get a zero page for hyperspace, if possible */
    MI_SET_USAGE(MI_USAGE_PAGE_DIRECTORY);
    Color = MI_GET_NEXT_PROCESS_COLOR(CurrentProcess);

    HyperIndex = MiRemoveZeroPageSafe(Color);
    if (!HyperIndex)
    {
        /* No zero pages, grab a free one */
        HyperIndex = MiRemoveAnyPage(Color);

        /* Zero it outside the PFN lock */
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        MiZeroPhysicalPage(HyperIndex);
        OldIrql = MiLockPfnDb(APC_LEVEL);
    }

    Pfn = MiGetPfnEntry(HyperIndex);
    if (Pfn->u3.e1.CacheAttribute != MiCached)
    {
        Pfn->u3.e1.CacheAttribute = MiCached;
        IsFlushTb = TRUE;
    }

    if (MmAvailablePages < 0x80)
        MiEnsureAvailablePageOrWait(NULL, OldIrql);

    /* Get a zero page for VadBitmap, if possible */
    MI_SET_USAGE(MI_USAGE_PAGE_DIRECTORY);
    Color = MI_GET_NEXT_PROCESS_COLOR(CurrentProcess);

    VadBitmapIndex = MiRemoveZeroPageSafe(Color);
    if (!VadBitmapIndex)
    {
        /* No zero pages, grab a free one */
        VadBitmapIndex = MiRemoveAnyPage(Color);

        /* Zero it outside the PFN lock */
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        MiZeroPhysicalPage(VadBitmapIndex);
        OldIrql = MiLockPfnDb(APC_LEVEL);
    }

    Pfn = MiGetPfnEntry(VadBitmapIndex);
    if (Pfn->u3.e1.CacheAttribute != MiCached)
    {
        Pfn->u3.e1.CacheAttribute = MiCached;
        IsFlushTb = TRUE;
    }

    if (MmAvailablePages < 0x80)
        MiEnsureAvailablePageOrWait(NULL, OldIrql);

    /* Get a zero page for the woring set list, if possible */
    MI_SET_USAGE(MI_USAGE_PAGE_TABLE);
    Color = MI_GET_NEXT_PROCESS_COLOR(CurrentProcess);

    WsIndex = MiRemoveZeroPageSafe(Color);
    if (!WsIndex)
    {
        /* No zero pages, grab a free one */
        WsIndex = MiRemoveAnyPage(Color);

        /* Zero it outside the PFN lock */
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        MiZeroPhysicalPage(WsIndex);
        OldIrql = MiLockPfnDb(APC_LEVEL);
    }

    Pfn = MiGetPfnEntry(WsIndex);
    if (Pfn->u3.e1.CacheAttribute != MiCached)
    {
        Pfn->u3.e1.CacheAttribute = MiCached;
        IsFlushTb = TRUE;
    }

    /* Release the PFN lock */
    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    if (IsFlushTb)
    {
        //MiFlushTbForAttributeChange++;
        //MiFlushType[0x23]++;
        KeFlushEntireTb(TRUE, TRUE);
    }

    /* Switch to phase 1 initialization */
    ASSERT(Process->AddressSpaceInitialized == 0);
    InterlockedOr((PLONG)&Process->Flags, PSF_ADDRESS_SPACE_INITIALIZED_BIT);
    ASSERT(Process->AddressSpaceInitialized == 1);

    Process->Vm.MinimumWorkingSetSize = MinWs;
    Process->WorkingSetPage = WsIndex;

    /* Set the base directory pointers */
    DirectoryTableBase[0] = (PdeIndex * PAGE_SIZE);
    DirectoryTableBase[1] = (HyperIndex * PAGE_SIZE);

    /* Get a PTE to map hyperspace */
    systemPte = MiReserveSystemPtes(1, SystemPteSpace);
    if (systemPte)
    {
        /* Build it */
        MI_MAKE_HARDWARE_PTE_KERNEL(&TempPde, systemPte, MM_READWRITE, HyperIndex);

        /* Set it dirty and map it */
        MI_MAKE_DIRTY_PAGE(&TempPde);
        MI_WRITE_VALID_PTE(systemPte, TempPde);

        /* Now get hyperspace's page table */
        HyperTable = MiPteToAddress(systemPte);
    }
    else
    {
        HyperTable = MiMapPageInHyperSpace(CurrentProcess, HyperIndex, &OldIrql);
    }

    /* Write the PTE/PDE entry for the Vad bitmap index */
    TempPde = ValidPdePde;
    TempPde.u.Long &= ~MmPteGlobal.u.Long;
    TempPde.u.Hard.PageFrameNumber = VadBitmapIndex;
    PdeOffset = MiAddressToPteOffset(MI_VAD_BITMAP);
    HyperTable[PdeOffset] = TempPde;

    DPRINT("MmCreateProcessAddressSpace: [%X] MI_VAD_BITMAP %p\n", PdeOffset, MI_VAD_BITMAP);

    /* Now write the PTE/PDE entry for the working set list index itself */
    TempPde.u.Hard.PageFrameNumber = WsIndex;
    PdeOffset = MiAddressToPteOffset(MmWorkingSetList);
    HyperTable[PdeOffset] = TempPde;

    DPRINT("MmCreateProcessAddressSpace: [%X] MmWorkingSetList %p\n", PdeOffset, MmWorkingSetList);

    if (systemPte)
        /* Let go of the system PTE */
        MiReleaseSystemPtes(systemPte, 1, SystemPteSpace);
    else
        MiUnmapPageInHyperSpace(CurrentProcess, HyperTable, OldIrql);

    /* Save the PTE address of the page directory itself */
    Pfn = MiGetPfnEntry(PdeIndex);
    Pfn->PteAddress = (PMMPTE)PDE_BASE;

    ASSERT(Process->Pcb.DirectoryTableBase[0] == 0);

    /* Insert us into the Mm process list */
    OldIrql = MiAcquireExpansionLock();
    InsertTailList(&MmProcessList, &Process->MmProcessLinks);
    MiReleaseExpansionLock(OldIrql);

    /* Get a PTE to map the page directory */
    systemPte = MiReserveSystemPtes(1, SystemPteSpace);

    if (systemPte)
    {
        /* Build it */
        MI_MAKE_HARDWARE_PTE_KERNEL(&TempPde, systemPte, MM_READWRITE, PdeIndex);

        /* Set it dirty and map it */
        MI_MAKE_DIRTY_PAGE(&TempPde);
        MI_WRITE_VALID_PTE(systemPte, TempPde);

        /* Now get the page directory (which we'll double map, so call it a page table */
        SystemTable = MiPteToAddress(systemPte);
    }
    else
    {
        SystemTable = MiMapPageInHyperSpace(CurrentProcess, PdeIndex, &OldIrql);
    }

    /* Copy all the kernel mappings */
    PdeOffset = MiAddressToPdeOffset(MmSystemRangeStart);
    DPRINT("MmCreateProcessAddressSpace: [%X] MmSystemRangeStart %p\n", PdeOffset, MmSystemRangeStart);

    RtlCopyMemory(&SystemTable[PdeOffset],
                  MiAddressToPde(MmSystemRangeStart),
                  PAGE_SIZE - PdeOffset * sizeof(MMPTE));

    /* Now write the PTE/PDE entry for hyperspace itself */
    TempPde = ValidPdePde;
    TempPde.u.Long &= ~MmPteGlobal.u.Long;
    TempPde.u.Hard.PageFrameNumber = HyperIndex;
    PdeOffset = MiAddressToPdeOffset(HYPER_SPACE);
    SystemTable[PdeOffset] = TempPde;

    DPRINT("MmCreateProcessAddressSpace: [%X] HYPER_SPACE %p\n", PdeOffset, HYPER_SPACE);

    /* Sanity check */
    PdeOffset++;
    ASSERT(MiAddressToPdeOffset(MmHyperSpaceEnd) >= PdeOffset);

    RtlZeroMemory(&SystemTable[PdeOffset],
                  ((MiAddressToPdeOffset(MmHyperSpaceEnd) - (PdeOffset - 1)) * sizeof(MMPTE)));

    /* Now do the x86 trick of making the PDE a page table itself */
    TempPde.u.Hard.PageFrameNumber = PdeIndex;
    PdeOffset = MiAddressToPdeOffset(PTE_BASE);
    SystemTable[PdeOffset] = TempPde;

    DPRINT("MmCreateProcessAddressSpace: [%X] PTE_BASE %p\n", PdeOffset, PTE_BASE);

    if (systemPte)
        /* Let go of the system PTE */
        MiReleaseSystemPtes(systemPte, 1, SystemPteSpace);
    else
        MiUnmapPageInHyperSpace(CurrentProcess, SystemTable, OldIrql);

    InterlockedExchangeAddSizeT(&MmProcessCommit, 4);

    /* Add the process to the session */
    MiSessionAddProcess(Process);

    DPRINT("MmCreateProcessAddressSpace: return TRUE\n");
    return TRUE;
}

/* EOF */
