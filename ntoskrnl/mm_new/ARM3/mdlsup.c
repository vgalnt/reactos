
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "miarm.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

ULONG MiCacheOverride[MiNotMapped + 1];
BOOLEAN MmTrackPtes;
BOOLEAN MmTrackLockedPages;

extern MI_PFN_CACHE_ATTRIBUTE MiPlatformCacheAttributes[2][MmMaximumCacheType];
extern PMMPTE MmSystemPtesStart[MaximumPtePoolTypes];
extern PMMPTE MmSystemPtesEnd[MaximumPtePoolTypes];

/* FUNCTIONS ******************************************************************/

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(PAGELK, MiUnmapLockedPagesInUserSpace)
  #pragma alloc_text(PAGE, MmAllocatePagesForMdl)
  #pragma alloc_text(PAGE, MmAllocatePagesForMdlEx)
  #pragma alloc_text(PAGELK, MmFreePagesFromMdl)
  #pragma alloc_text(PAGE, MmPrefetchPages)
  #pragma alloc_text(PAGE, MmProbeAndLockProcessPages)
#endif

PVOID
NTAPI
MiMapLockedPagesInUserSpace(
    _In_ PMDL Mdl,
    _In_ PVOID StartVa,
    _In_ MEMORY_CACHING_TYPE CacheType,
    _In_opt_ PVOID BaseAddress)
{
    PEPROCESS Process = PsGetCurrentProcess();
    PETHREAD Thread = PsGetCurrentThread();
    TABLE_SEARCH_RESULT Result;
    MI_PFN_CACHE_ATTRIBUTE CacheAttribute;
    MI_PFN_CACHE_ATTRIBUTE EffectiveCacheAttribute;
    BOOLEAN IsIoMapping;
    KIRQL OldIrql;
    ULONG_PTR StartingVa;
    ULONG_PTR EndingVa;
    PMMADDRESS_NODE Parent;
    PMMVAD_LONG Vad;
    ULONG NumberOfPages;
    PMMPTE Pte;
    PMMPDE Pde;
    MMPTE TempPte;
    PPFN_NUMBER MdlPages;
    PMMPFN Pfn;
    BOOLEAN AddressSpaceLocked = FALSE;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("MiMapLockedPagesInUserSpace(%p, %p, %X, %p)\n", Mdl, StartVa, CacheType, BaseAddress);

    NumberOfPages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(StartVa, MmGetMdlByteCount(Mdl));
    MdlPages = MmGetMdlPfnArray(Mdl);

    ASSERT(CacheType <= MmWriteCombined);

    IsIoMapping = ((Mdl->MdlFlags & MDL_IO_SPACE) != 0);
    CacheAttribute = MiPlatformCacheAttributes[IsIoMapping][CacheType];

    /* Large pages are always cached, make sure we're not asking for those */
    if (CacheAttribute != MiCached)
    {
        DPRINT1("MiMapLockedPagesInUserSpace: FIXME! Need to check for large pages\n");
    }

    /* Allocate a VAD for our mapped region */
    Vad = ExAllocatePoolWithTag(NonPagedPool, sizeof(MMVAD_LONG), 'ldaV');
    if (!Vad)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Error;
    }

    /* Initialize PhysicalMemory VAD */
    RtlZeroMemory(Vad, sizeof(*Vad));

    Vad->u2.VadFlags2.LongVad = 1;
    Vad->u.VadFlags.VadType = VadDevicePhysicalMemory;
    Vad->u.VadFlags.Protection = MM_READWRITE;
    Vad->u.VadFlags.PrivateMemory = 1;

    /* Did the caller specify an address? */
    if (!BaseAddress)
    {
        /* We get to pick the address */
        MmLockAddressSpace(&Process->Vm);
        AddressSpaceLocked = TRUE;

        if (Process->VmDeleted)
        {
            Status = STATUS_PROCESS_IS_TERMINATING;
            goto Error;
        }

        Result = MiFindEmptyAddressRangeInTree((NumberOfPages * PAGE_SIZE),
                                               MM_VIRTMEM_GRANULARITY,
                                               &Process->VadRoot,
                                               &Parent,
                                               &StartingVa);
        if (Result == TableFoundNode)
        {
            Status = STATUS_NO_MEMORY;
            goto Error;
        }

        EndingVa = (StartingVa + (NumberOfPages * PAGE_SIZE) - 1);
        BaseAddress = (PVOID)StartingVa;
    }
    else
    {
        /* Caller specified a base address */
        StartingVa = (ULONG_PTR)BaseAddress;
        EndingVa = (StartingVa + (NumberOfPages * PAGE_SIZE) - 1);

        /* Make sure it's valid */
        if (BYTE_OFFSET(StartingVa) ||
            EndingVa <= StartingVa ||
            EndingVa > (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS)
        {
            Status = STATUS_INVALID_ADDRESS;
            goto Error;
        }

        MmLockAddressSpace(&Process->Vm);
        AddressSpaceLocked = TRUE;

        if (Process->VmDeleted)
        {
            Status = STATUS_PROCESS_IS_TERMINATING;
            goto Error;
        }

        DPRINT1("MiMapLockedPagesInUserSpace: FIXME\n");
        ASSERT(FALSE);
    }

    Vad->StartingVpn = (StartingVa / PAGE_SIZE);
    Vad->EndingVpn = (EndingVa / PAGE_SIZE);

    MiLockProcessWorkingSetUnsafe(Process, Thread);

    ASSERT(Vad->EndingVpn >= Vad->StartingVpn);

    MiInsertVad((PMMVAD)Vad, &Process->VadRoot);

    /* Check if this is uncached */
    if (CacheAttribute != MiCached)
    {
        /* Flush all caches */
        KeFlushEntireTb(TRUE, TRUE);
        KeInvalidateAllCaches();
    }

    Pte = MiAddressToPte(BaseAddress);

    while (NumberOfPages && *MdlPages != LIST_HEAD)
    {
        Pde = MiPteToPde(Pte);
        MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);

        ASSERT(Pte->u.Hard.Valid == 0);

        /* Add a PDE reference for each page */
        MiIncrementPageTableReferences(BaseAddress);

        DPRINT1("MiMapLockedPagesInUserSpace: [%X] Address %p, RefCount %X\n",
                MiAddressToPdeOffset(BaseAddress), BaseAddress, MiQueryPageTableReferences(BaseAddress));

        /* Set up our basic user PTE */
        MI_MAKE_HARDWARE_PTE_USER(&TempPte, Pte, MM_READWRITE, *MdlPages);

        EffectiveCacheAttribute = CacheAttribute;

        /* We need to respect the PFN's caching information in some cases */
        Pfn = MiGetPfnEntry(*MdlPages);
        if (Pfn)
        {
            ASSERT(Pfn->u3.e2.ReferenceCount != 0);

            switch (Pfn->u3.e1.CacheAttribute)
            {
                case MiNonCached:
                    if (CacheAttribute != MiNonCached)
                    {
                        MiCacheOverride[1]++;
                        EffectiveCacheAttribute = MiNonCached;
                    }
                    break;

                case MiCached:
                    if (CacheAttribute != MiCached)
                    {
                        MiCacheOverride[0]++;
                        EffectiveCacheAttribute = MiCached;
                    }
                    break;

                case MiWriteCombined:
                    if (CacheAttribute != MiWriteCombined)
                    {
                        MiCacheOverride[2]++;
                        EffectiveCacheAttribute = MiWriteCombined;
                    }
                    break;

                default:
                    /* We don't support AWE magic (MiNotMapped) */
                    DPRINT1("MiMapLockedPagesInUserSpace: FIXME! MiNotMapped is not supported\n");
                    ASSERT(FALSE);
                    break;
            }
        }

        /* Configure caching */
        switch (EffectiveCacheAttribute)
        {
            case MiNonCached:
                MI_PAGE_DISABLE_CACHE(&TempPte);
                MI_PAGE_WRITE_THROUGH(&TempPte);
                break;

            case MiCached:
                break;

            case MiWriteCombined:
                MI_PAGE_DISABLE_CACHE(&TempPte);
                MI_PAGE_WRITE_COMBINED(&TempPte);
                break;

            default:
                ASSERT(FALSE);
                break;
        }

        /* Make the page valid */
        MI_WRITE_VALID_PTE(Pte, TempPte);

        /* Acquire a share count */
        Pfn = MI_PFN_ELEMENT(Pde->u.Hard.PageFrameNumber);

        OldIrql = MiLockPfnDb(APC_LEVEL);
        Pfn->u2.ShareCount++;
        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        /* Next page */
        MdlPages++;
        Pte++;
        NumberOfPages--;
        BaseAddress = (PVOID)((ULONG_PTR)BaseAddress + PAGE_SIZE);
    }

    MiUnlockProcessWorkingSetUnsafe(Process, Thread);
    ASSERT(AddressSpaceLocked);
    MmUnlockAddressSpace(&Process->Vm);

    ASSERT(StartingVa != 0);
    return (PVOID)((ULONG_PTR)StartingVa + MmGetMdlByteOffset(Mdl));

Error:

    if (AddressSpaceLocked)
        MmUnlockAddressSpace(&Process->Vm);

    if (Vad)
        ExFreePoolWithTag(Vad, 'ldaV');

    ExRaiseStatus(Status);
}

CODE_SEG("PAGELK")
VOID
NTAPI
MiUnmapLockedPagesInUserSpace(
    _In_ PVOID BaseAddress,
    _In_ PMDL Mdl)
{
    PEPROCESS Process = PsGetCurrentProcess();
    PETHREAD Thread = PsGetCurrentThread();
    PMMVAD Vad;
    PMMPTE Pte;
    PMMPDE Pde;
    KIRQL OldIrql;
    ULONG NumberOfPages;
    PPFN_NUMBER MdlPages;
    PFN_NUMBER PageTablePage;

    DPRINT("MiUnmapLockedPagesInUserSpace: %p, %p\n", BaseAddress, Mdl);

    NumberOfPages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(Mdl), MmGetMdlByteCount(Mdl));
    ASSERT(NumberOfPages != 0);

    MdlPages = MmGetMdlPfnArray(Mdl);

    /* Find the VAD */
    MmLockAddressSpace(&Process->Vm);

    Vad = MiLocateAddress(BaseAddress);
    if (!Vad || Vad->u.VadFlags.VadType != VadDevicePhysicalMemory)
    {
        DPRINT1("MiUnmapLockedPagesInUserSpace: invalid for %p\n", BaseAddress);
        MmUnlockAddressSpace(&Process->Vm);
        return;
    }

    MiLockProcessWorkingSetUnsafe(Process, Thread);

    /* Remove it from the process VAD tree */
    ASSERT(Process->VadRoot.NumberGenericTableElements >= 1);
    MiRemoveNode((PMMADDRESS_NODE)Vad, &Process->VadRoot);

    /* MiRemoveNode should have removed us if we were the hint */
    ASSERT(Process->VadRoot.NodeHint != Vad);

    Pte = MiAddressToPte(BaseAddress);
    OldIrql = MiLockPfnDb(APC_LEVEL);

    while (NumberOfPages && *MdlPages != LIST_HEAD)
    {
        ASSERT(MiAddressToPte(Pte)->u.Hard.Valid == 1);
        ASSERT(Pte->u.Hard.Valid == 1);

        /* Dereference the page */
        MiDecrementPageTableReferences(BaseAddress);

        DPRINT1("MiUnmapLockedPagesInUserSpace: [%X] Address %p, RefCount %X\n",
                MiAddressToPdeOffset(BaseAddress), BaseAddress, MiQueryPageTableReferences(BaseAddress));

        /* Invalidate it */
        MI_ERASE_PTE(Pte);

        /* We invalidated this PTE, so dereference the PDE */
        Pde = MiAddressToPde(BaseAddress);
        PageTablePage = Pde->u.Hard.PageFrameNumber;

        MiDecrementShareCount(MiGetPfnEntry(PageTablePage), PageTablePage);

        /* Next page */
        Pte++;
        NumberOfPages--;
        BaseAddress = (PVOID)((ULONG_PTR)BaseAddress + PAGE_SIZE);
        MdlPages++;

        /* Moving to a new PDE? */
        if (Pde != MiAddressToPde(BaseAddress))
        {
            /* See if we should delete it */
            KeFlushProcessTb();

            Pde = MiPteToPde(Pte - 1);
            ASSERT(Pde->u.Hard.Valid == 1);

            if (!MiQueryPageTableReferences(BaseAddress))
            {
                ASSERT(Pde->u.Long != 0);

                DPRINT1("MiUnmapLockedPagesInUserSpace: FIXME\n");
                ASSERT(FALSE);
                //MiDeletePte(Pde, MiPteToAddress(Pde), Process, NULL);
            }
        }
    }

    KeFlushProcessTb();

    MiUnlockPfnDb(OldIrql, APC_LEVEL);
    MiUnlockProcessWorkingSetUnsafe(Process, Thread);
    MmUnlockAddressSpace(&Process->Vm);

    ExFreePoolWithTag(Vad, 'ldaV');
}

/* PUBLIC FUNCTIONS ***********************************************************/

NTSTATUS
NTAPI
MmAdvanceMdl(
    _In_ PMDL Mdl,
    _In_ ULONG NumberOfBytes)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

CODE_SEG("PAGE")
PMDL
NTAPI
MmAllocatePagesForMdl(
    _In_ PHYSICAL_ADDRESS LowAddress,
    _In_ PHYSICAL_ADDRESS HighAddress,
    _In_ PHYSICAL_ADDRESS SkipBytes,
    _In_ SIZE_T TotalBytes)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

CODE_SEG("PAGE")
PMDL
NTAPI
MmAllocatePagesForMdlEx(
    _In_ PHYSICAL_ADDRESS LowAddress,
    _In_ PHYSICAL_ADDRESS HighAddress,
    _In_ PHYSICAL_ADDRESS SkipBytes,
    _In_ SIZE_T TotalBytes,
    _In_ MEMORY_CACHING_TYPE CacheType,
    _In_ ULONG Flags)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

VOID
NTAPI
MmBuildMdlForNonPagedPool(
    _In_ PMDL Mdl)
{
    PVOID Base;
    PMMPTE Pte;
    PPFN_NUMBER MdlPages;
    PPFN_NUMBER EndPage;
    PFN_NUMBER Pfn;
    PFN_NUMBER PageCount;

    /* Sanity checks */
    ASSERT(Mdl->ByteCount != 0);
    ASSERT((Mdl->MdlFlags & (MDL_PAGES_LOCKED | MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL | MDL_PARTIAL)) == 0);

    /* We know the MDL isn't associated to a process now */
    Mdl->Process = NULL;

    /* Get page and VA information */
    MdlPages = (PPFN_NUMBER)(Mdl + 1);
    Base = Mdl->StartVa;

    /* Set the system address and now get the page count */
    Mdl->MappedSystemVa = (PVOID)((ULONG_PTR)Base + Mdl->ByteOffset);

    PageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(Mdl->MappedSystemVa, Mdl->ByteCount);
    ASSERT(PageCount != 0);

    /* Loop the PTEs */
    Pte = MiAddressToPte(Base);
    EndPage = (MdlPages + PageCount);

    do
    {
        /* Write the PFN */
        Pfn = PFN_FROM_PTE(Pte++);
        *MdlPages++ = Pfn;
    }
    while (MdlPages < EndPage);

    /* Set the nonpaged pool flag */
    Mdl->MdlFlags |= MDL_SOURCE_IS_NONPAGED_POOL;

    /* Check if this is an I/O mapping */
    if (!MiGetPfnEntry(Pfn))
        Mdl->MdlFlags |= MDL_IO_SPACE;
}

PMDL
NTAPI
MmCreateMdl(
    _In_ PMDL Mdl,
    _In_ PVOID Base,
    _In_ SIZE_T Length)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

CODE_SEG("PAGELK")
VOID
NTAPI
MmFreePagesFromMdl(
    _In_ PMDL Mdl)
{
    UNIMPLEMENTED_DBGBREAK();
}

PVOID
NTAPI
MmMapLockedPages(
    _In_ PMDL Mdl,
    _In_ KPROCESSOR_MODE AccessMode)
{
    /* Call the extended version */
    return MmMapLockedPagesSpecifyCache(Mdl, AccessMode, MmCached, NULL, TRUE, HighPagePriority);
}

PVOID
NTAPI
MmMapLockedPagesSpecifyCache(
    _In_ PMDL Mdl,
    _In_ KPROCESSOR_MODE AccessMode,
    _In_ MEMORY_CACHING_TYPE CacheType,
    _In_ PVOID BaseAddress,
    _In_ ULONG BugCheckOnFailure,
    _In_ MM_PAGE_PRIORITY Priority)
{
    MI_PFN_CACHE_ATTRIBUTE CacheAttribute;
    PVOID Base;
    PMMPTE Pte;
    MMPTE TempPte;
    PPFN_NUMBER MdlPages;
    PPFN_NUMBER LastPage;
    PFN_COUNT PageCount;
    BOOLEAN IsIoMapping;

    /* Sanity check */
    ASSERT(Mdl->ByteCount != 0);

    /* Get the base */
    Base = (PVOID)((ULONG_PTR)Mdl->StartVa + Mdl->ByteOffset);

    /* Handle kernel case first */
    if (AccessMode == KernelMode)
    {
        /* Get the list of pages and count */
        MdlPages = (PPFN_NUMBER)(Mdl + 1);
        PageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(Base, Mdl->ByteCount);
        LastPage = (MdlPages + PageCount);

        /* Sanity checks */
        ASSERT((Mdl->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA |
                                 MDL_SOURCE_IS_NONPAGED_POOL |
                                 MDL_PARTIAL_HAS_BEEN_MAPPED)) == 0);

        ASSERT((Mdl->MdlFlags & (MDL_PAGES_LOCKED | MDL_PARTIAL)) != 0);

        /* Get the correct cache type */
        IsIoMapping = ((Mdl->MdlFlags & MDL_IO_SPACE) != 0);
        CacheAttribute = MiPlatformCacheAttributes[IsIoMapping][CacheType];

        /* Reserve the PTEs */
        Pte = MiReserveSystemPtes(PageCount, SystemPteSpace);
        if (!Pte)
        {
            /* If it can fail, return NULL */
            if (Mdl->MdlFlags & MDL_MAPPING_CAN_FAIL)
                return NULL;

            /* Should we bugcheck? */
            if (!BugCheckOnFailure)
                return NULL;

            /* Yes, crash the system */
            KeBugCheckEx(NO_MORE_SYSTEM_PTES, 0, PageCount, 0, 0);
        }

        /* Get the mapped address */
        Base = (PVOID)((ULONG_PTR)MiPteToAddress(Pte) + Mdl->ByteOffset);

        /* Get the template */
        TempPte = ValidKernelPte;

        switch (CacheAttribute)
        {
            case MiNonCached:
                /* Disable caching */
                MI_PAGE_DISABLE_CACHE(&TempPte);
                MI_PAGE_WRITE_THROUGH(&TempPte);
                break;

            case MiWriteCombined:
                /* Enable write combining */
                MI_PAGE_DISABLE_CACHE(&TempPte);
                MI_PAGE_WRITE_COMBINED(&TempPte);
                break;

            default:
                /* Nothing to do */
                break;
        }

        /* Loop all PTEs */
        do
        {
            /* We're done here */
            if (*MdlPages == LIST_HEAD)
                break;

            /* Write the PTE */
            TempPte.u.Hard.PageFrameNumber = *MdlPages;
            MI_WRITE_VALID_PTE(Pte++, TempPte);
        }
        while (++MdlPages < LastPage);

        /* Mark it as mapped */
        ASSERT((Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA) == 0);

        Mdl->MappedSystemVa = Base;
        Mdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;

        /* Check if it was partial */
        if (Mdl->MdlFlags & MDL_PARTIAL)
            /* Write the appropriate flag here too */
            Mdl->MdlFlags |= MDL_PARTIAL_HAS_BEEN_MAPPED;

        /* Return the mapped address */
        return Base;
    }

    return MiMapLockedPagesInUserSpace(Mdl, Base, CacheType, BaseAddress);
}

PVOID
NTAPI
MmMapLockedPagesWithReservedMapping(
    _In_ PVOID MappingAddress,
    _In_ ULONG PoolTag,
    _In_ PMDL MemoryDescriptorList,
    _In_ MEMORY_CACHING_TYPE CacheType)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

VOID
NTAPI
MmMapMemoryDumpMdl(
    _In_ PMDL Mdl)
{
    UNIMPLEMENTED_DBGBREAK();
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmPrefetchPages(
    _In_ ULONG NumberOfLists,
    _In_ PREAD_LIST* ReadLists)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
MmProbeAndLockPages(
    _In_ PMDL Mdl,
    _In_ KPROCESSOR_MODE AccessMode,
    _In_ LOCK_OPERATION Operation)
{
    PEPROCESS CurrentProcess;
    PVOID Base;
    PVOID Address;
    PVOID StartAddress;
    PVOID LastAddress;
    PMMPDE Pde;
    PMMPTE Pte;
    PMMPTE LastPte;
    PMMPFN Pfn;
    PFN_NUMBER PageFrameIndex;
    PPFN_NUMBER MdlPages;
    ULONG LockPages;
    ULONG TotalPages;
    BOOLEAN UsePfnLock;
    KIRQL OldIrql;
    NTSTATUS ProbeStatus;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("MmProbeAndLockPages: Mdl %p\n", Mdl);

    /* Sanity checks */
    ASSERT(Mdl->ByteCount != 0);
    ASSERT(((ULONG)Mdl->ByteOffset & ~(PAGE_SIZE - 1)) == 0);
    ASSERT(((ULONG_PTR)Mdl->StartVa & (PAGE_SIZE - 1)) == 0);

    ASSERT((Mdl->MdlFlags & (MDL_PAGES_LOCKED | MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL | MDL_PARTIAL | MDL_IO_SPACE)) == 0);

    /* Get page and base information */
    MdlPages = (PPFN_NUMBER)(Mdl + 1);
    Base = Mdl->StartVa;

    /* Get the addresses and how many pages we span (and need to lock) */
    Address = (PVOID)((ULONG_PTR)Base + Mdl->ByteOffset);
    LastAddress = (PVOID)((ULONG_PTR)Address + Mdl->ByteCount);
    LockPages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(Address, Mdl->ByteCount);
    ASSERT(LockPages != 0);

    /* Block invalid access */
    if ((AccessMode != KernelMode) &&
        (LastAddress > (PVOID)MM_USER_PROBE_ADDRESS || Address >= LastAddress))
    {
        /* Caller should be in SEH, raise the error */
        *MdlPages = LIST_HEAD;
        ExRaiseStatus(STATUS_ACCESS_VIOLATION);
    }

    /* Get the process */
    if (Address <= MM_HIGHEST_USER_ADDRESS)
        /* Get the process */
        CurrentProcess = PsGetCurrentProcess();
    else
        /* No process */
        CurrentProcess = NULL;

    /* Save the number of pages we'll have to lock, and the start address */
    TotalPages = LockPages;
    StartAddress = Address;

    /* Large pages not supported */
    ASSERT(!MI_IS_PHYSICAL_ADDRESS(Address));

    /* Now probe them */
    ProbeStatus = STATUS_SUCCESS;

    _SEH2_TRY
    {
        /* Enter probe loop */
        do
        {
            /* Assume failure */
            *MdlPages = LIST_HEAD;

            /* Read */
            *(volatile CHAR*)Address;

            /* Check if this is write access (only probe for user-mode) */
            if (Operation != IoReadAccess && Address <= MM_HIGHEST_USER_ADDRESS)
                /* Probe for write too */
                ProbeForWriteChar(Address);

            /* Next address... */
            Address = PAGE_ALIGN((ULONG_PTR)Address + PAGE_SIZE);

            /* Next page... */
            LockPages--;
            MdlPages++;
        }
        while (Address < LastAddress);

        /* Reset back to the original page */
        ASSERT(LockPages == 0);
        MdlPages = (PPFN_NUMBER)(Mdl + 1);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* Oops :( */
        ProbeStatus = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    /* So how did that go? */
    if (ProbeStatus != STATUS_SUCCESS)
    {
        /* Fail */
        DPRINT1("MmProbeAndLockPages: MDL PROBE FAILED!\n");
        Mdl->Process = NULL;
        ExRaiseStatus(ProbeStatus);
    }

    /* Get the PTE and PDE */
    Pte = MiAddressToPte(StartAddress);
    Pde = MiAddressToPde(StartAddress);

    /* Sanity check */
    ASSERT(MdlPages == (PPFN_NUMBER)(Mdl + 1));

    /* Check what kind of operation this is */
    if (Operation != IoReadAccess)
        /* Set the write flag */
        Mdl->MdlFlags |= MDL_WRITE_OPERATION;
    else
        /* Remove the write flag */
        Mdl->MdlFlags &= ~(MDL_WRITE_OPERATION);

    /* Mark the MDL as locked *now* */
    Mdl->MdlFlags |= MDL_PAGES_LOCKED;

    /* Check if this came from kernel mode */
    if (Base > MM_HIGHEST_USER_ADDRESS)
    {
        /* We should not have a process */
        ASSERT(CurrentProcess == NULL);
        Mdl->Process = NULL;

        /* In kernel mode, we don't need to check for write access */
        Operation = IoReadAccess;

        /* Use the PFN lock */
        UsePfnLock = TRUE;
        OldIrql = MiLockPfnDb(DISPATCH_LEVEL);
    }
    else
    {
        /* Sanity checks */
        ASSERT(TotalPages != 0);
        ASSERT(CurrentProcess == PsGetCurrentProcess());

        /* Track locked pages */
        InterlockedExchangeAddSizeT(&CurrentProcess->NumberOfLockedPages, TotalPages);

        /* Save the process */
        Mdl->Process = CurrentProcess;

        /* Lock the process working set */
        MiLockProcessWorkingSet(CurrentProcess, PsGetCurrentThread());
        UsePfnLock = FALSE;
        OldIrql = MM_NOIRQL;
    }

    /* Get the last PTE */
    LastPte = MiAddressToPte((PVOID)((ULONG_PTR)LastAddress - 1));

    /* Loop the pages */
    do
    {
        /* Assume failure and check for non-mapped pages */
        *MdlPages = LIST_HEAD;

        while (!Pde->u.Hard.Valid || !Pte->u.Hard.Valid)
        {
            /* What kind of lock were we using? */
            if (UsePfnLock)
                /* Release PFN lock */
                MiUnlockPfnDb(OldIrql, DISPATCH_LEVEL);
            else
                /* Release process working set */
                MiUnlockProcessWorkingSet(CurrentProcess, PsGetCurrentThread());

            /* Access the page */
            Address = MiPteToAddress(Pte);

            /* HACK: Pass a placeholder TrapInformation so the fault handler knows we're unlocked */
            Status = MmAccessFault(FALSE, Address, KernelMode, (PVOID)(ULONG_PTR)0xBADBADA3BADBADA3ULL);
            if (!NT_SUCCESS(Status))
            {
                /* Fail */
                DPRINT1("MmProbeAndLockPages: Access fault failed\n");
                goto Cleanup;
            }

            /* What lock should we use? */
            if (UsePfnLock)
                /* Grab the PFN lock */
                OldIrql = MiLockPfnDb(DISPATCH_LEVEL);
            else
                /* Lock the process working set */
                MiLockProcessWorkingSet(CurrentProcess, PsGetCurrentThread());
        }

        /* Check if this was a write or modify */
        if (Operation != IoReadAccess)
        {
            /* Check if the PTE is not writable */
            if (!(Pte->u.Long & PTE_READWRITE))
            {
                /* Check if it's copy on write */
                if (MI_IS_PAGE_COPY_ON_WRITE(Pte))
                {
                    /* Get the base address and allow a change for user-mode */
                    Address = MiPteToAddress(Pte);

                    if (Address <= MM_HIGHEST_USER_ADDRESS)
                    {
                        /* What kind of lock were we using? */
                        if (UsePfnLock)
                            /* Release PFN lock */
                            MiUnlockPfnDb(OldIrql, DISPATCH_LEVEL);
                        else
                            /* Release process working set */
                            MiUnlockProcessWorkingSet(CurrentProcess, PsGetCurrentThread());

                        /* Access the page */

                        /* HACK: Pass a placeholder TrapInformation so the fault handler knows we're unlocked */
                        Status = MmAccessFault(TRUE, Address, KernelMode, (PVOID)(ULONG_PTR)0xBADBADA3BADBADA3ULL);
                        if (!NT_SUCCESS(Status))
                        {
                            /* Fail */
                            DPRINT1("MmProbeAndLockPages: Access fault failed\n");
                            goto Cleanup;
                        }

                        /* Re-acquire the lock */
                        if (UsePfnLock)
                            /* Grab the PFN lock */
                            OldIrql = MiLockPfnDb(DISPATCH_LEVEL);
                        else
                            /* Lock the process working set */
                            MiLockProcessWorkingSet(CurrentProcess, PsGetCurrentThread());

                        /* Start over */
                        continue;
                    }
                }

                /* Fail, since we won't allow this */
                Status = STATUS_ACCESS_VIOLATION;
                goto CleanupWithLock;
            }
        }

        /* Grab the PFN */
        PageFrameIndex = PFN_FROM_PTE(Pte);
        Pfn = MiGetPfnEntry(PageFrameIndex);

        if (Pfn)
        {
            /* Either this is for kernel-mode, or the working set is held */
            ASSERT((CurrentProcess == NULL) || (UsePfnLock == FALSE));

            /* No Physical VADs supported yet */
            //if (CurrentProcess) ASSERT(CurrentProcess->PhysicalVadRoot == NULL);

            /* This address should already exist and be fully valid */
            MiReferenceProbedPageAndBumpLockCount(Pfn);
        }
        else
        {
            /* For I/O addresses, just remember this */
            Mdl->MdlFlags |= MDL_IO_SPACE;
        }

        /* Write the page and move on */
        *MdlPages++ = PageFrameIndex;
        Pte++;

        /* Check if we're on a PDE boundary */
        if (MiIsPteOnPdeBoundary(Pte))
            Pde++;
    }
    while (Pte <= LastPte);

    /* What kind of lock were we using? */
    if (UsePfnLock)
        /* Release PFN lock */
        MiUnlockPfnDb(OldIrql, DISPATCH_LEVEL);
    else
        /* Release process working set */
        MiUnlockProcessWorkingSet(CurrentProcess, PsGetCurrentThread());

    /* Sanity check */
    ASSERT((Mdl->MdlFlags & MDL_DESCRIBES_AWE) == 0);
    return;

CleanupWithLock:

    /* This is the failure path */
    ASSERT(!NT_SUCCESS(Status));

    /* What kind of lock were we using? */
    if (UsePfnLock)
        /* Release PFN lock */
        MiUnlockPfnDb(OldIrql, DISPATCH_LEVEL);
    else
        /* Release process working set */
        MiUnlockProcessWorkingSet(CurrentProcess, PsGetCurrentThread());

Cleanup:

    /* Pages must be locked so MmUnlock can work */
    ASSERT(Mdl->MdlFlags & MDL_PAGES_LOCKED);
    MmUnlockPages(Mdl);

    /* Raise the error */
    ExRaiseStatus(Status);
}

CODE_SEG("PAGE")
VOID
NTAPI
MmProbeAndLockProcessPages(
    _Inout_ PMDL MemoryDescriptorList,
    _In_ PEPROCESS Process,
    _In_ KPROCESSOR_MODE AccessMode,
    _In_ LOCK_OPERATION Operation)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
MmProbeAndLockSelectedPages(
    _Inout_ PMDL MemoryDescriptorList,
    _In_ LARGE_INTEGER PageList[],
    _In_ KPROCESSOR_MODE AccessMode,
    _In_ LOCK_OPERATION Operation)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
MmProtectMdlSystemAddress(
    _In_ PMDL MemoryDescriptorList,
    _In_ ULONG NewProtect)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

SIZE_T
NTAPI
MmSizeOfMdl(
    _In_ PVOID Base,
    _In_ SIZE_T Length)
{
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

VOID
NTAPI
MmUnlockPages(
    _In_ PMDL Mdl)
{
    PPFN_NUMBER MdlPages;
    PPFN_NUMBER LastPage;
    PEPROCESS Process;
    PMMPFN Pfn;
    PVOID Base;
    ULONG Flags;
    ULONG PageCount;
    KIRQL OldIrql;

    DPRINT("MmUnlockPages: Mdl %p\n", Mdl);

    /* Sanity checks */
    ASSERT((Mdl->MdlFlags & MDL_PAGES_LOCKED) != 0);
    ASSERT((Mdl->MdlFlags & MDL_SOURCE_IS_NONPAGED_POOL) == 0);
    ASSERT((Mdl->MdlFlags & MDL_PARTIAL) == 0);
    ASSERT(Mdl->ByteCount != 0);

    /* Get the process associated and capture the flags which are volatile */
    Process = Mdl->Process;
    Flags = Mdl->MdlFlags;

    /* Automagically undo any calls to MmGetSystemAddressForMdl's for this MDL */
    if (Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA)
        /* Unmap the pages from system space */
        MmUnmapLockedPages(Mdl->MappedSystemVa, Mdl);

    /* Get the page count */
    MdlPages = (PPFN_NUMBER)(Mdl + 1);
    Base = (PVOID)((ULONG_PTR)Mdl->StartVa + Mdl->ByteOffset);

    PageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(Base, Mdl->ByteCount);
    ASSERT(PageCount != 0);

    /* We don't support AWE */
    if (Flags & MDL_DESCRIBES_AWE)
        ASSERT(FALSE);

    /* Check if the buffer is mapped I/O space */
    if (Flags & MDL_IO_SPACE)
    {
        /* Acquire PFN lock */
        OldIrql = MiLockPfnDb(DISPATCH_LEVEL);

        /* Loop every page */
        LastPage = MdlPages + PageCount;
        do
        {
            /* Last page, break out */
            if (*MdlPages == LIST_HEAD)
                break;

            /* Check if this page is in the PFN database */
            Pfn = MiGetPfnEntry(*MdlPages);
            if (Pfn)
                MiDereferencePfnAndDropLockCount(Pfn);
        }
        while (++MdlPages < LastPage);

        /* Release the lock */
        MiUnlockPfnDb(OldIrql, DISPATCH_LEVEL);

        /* Check if we have a process */
        if (Process)
        {
            /* Handle the accounting of locked pages */
            ASSERT(Process->NumberOfLockedPages > 0);
            InterlockedExchangeAddSizeT(&Process->NumberOfLockedPages, -(LONG_PTR)PageCount);
        }

        /* We're done */
        Mdl->MdlFlags &= ~MDL_IO_SPACE;
        Mdl->MdlFlags &= ~MDL_PAGES_LOCKED;

        return;
    }

    /* Check if we have a process */
    if (Process)
    {
        /* Handle the accounting of locked pages */
        ASSERT(Process->NumberOfLockedPages > 0);
        InterlockedExchangeAddSizeT(&Process->NumberOfLockedPages, -(LONG_PTR)PageCount);
    }

    /* Loop every page */
    LastPage = MdlPages + PageCount;
    do
    {
        /* Last page reached */
        if (*MdlPages == LIST_HEAD)
        {
            /* Were there no pages at all? */
            if (MdlPages == (PPFN_NUMBER)(Mdl + 1))
            {
                /* We're already done */
                Mdl->MdlFlags &= ~MDL_PAGES_LOCKED;
                return;
            }

            /* Otherwise, stop here */
            LastPage = MdlPages;
            break;
        }

        /* Save the PFN entry instead for the secondary loop */
        *MdlPages = (PFN_NUMBER)MiGetPfnEntry(*MdlPages);
        ASSERT(*MdlPages != 0);
    }
    while (++MdlPages < LastPage);

    /* Reset pointer */
    MdlPages = (PPFN_NUMBER)(Mdl + 1);

    /* Now grab the PFN lock for the actual unlock and dereference */
    OldIrql = MiLockPfnDb(DISPATCH_LEVEL);

    do
    {
        /* Get the current entry and reference count */
        Pfn = (PMMPFN)*MdlPages;
        MiDereferencePfnAndDropLockCount(Pfn);
    }
    while (++MdlPages < LastPage);

    /* Release the lock */
    MiUnlockPfnDb(OldIrql, DISPATCH_LEVEL);

    /* We're done */
    Mdl->MdlFlags &= ~MDL_PAGES_LOCKED;
}

VOID
NTAPI
MmUnmapLockedPages(
    _In_ PVOID BaseAddress,
    _In_ PMDL Mdl)
{
    PPFN_NUMBER MdlPages;
    PMMPTE Pte;
    PVOID Base;
    PFN_COUNT PageCount;
    PFN_COUNT ExtraPageCount;

    /* Sanity check */
    ASSERT(Mdl->ByteCount != 0);

    /* Check if this is a kernel request */
    if (BaseAddress <= MM_HIGHEST_USER_ADDRESS)
    {
        MiUnmapLockedPagesInUserSpace(BaseAddress, Mdl);
        return;
    }

    /* Get base and count information */
    Base = (PVOID)((ULONG_PTR)Mdl->StartVa + Mdl->ByteOffset);
    PageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(Base, Mdl->ByteCount);

    /* Sanity checks */
    ASSERT((Mdl->MdlFlags & MDL_PARENT_MAPPED_SYSTEM_VA) == 0);
    ASSERT(PageCount != 0);
    ASSERT(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);

    /* Get the PTE */
    Pte = MiAddressToPte(BaseAddress);

    /* This should be a resident system PTE */
    ASSERT(Pte >= MmSystemPtesStart[SystemPteSpace]);
    ASSERT(Pte <= MmSystemPtesEnd[SystemPteSpace]);
    ASSERT(Pte->u.Hard.Valid == 1);

    /* Check if the caller wants us to free advanced pages */
    if (Mdl->MdlFlags & MDL_FREE_EXTRA_PTES)
    {
        /* Get the MDL page array */
        MdlPages = MmGetMdlPfnArray(Mdl);

        /* Number of extra pages stored after the PFN array */
        ExtraPageCount = (PFN_COUNT)*(MdlPages + PageCount);

        /* Do the math */
        PageCount += ExtraPageCount;
        Pte -= ExtraPageCount;

        ASSERT(Pte >= MmSystemPtesStart[SystemPteSpace]);
        ASSERT(Pte <= MmSystemPtesEnd[SystemPteSpace]);

        /* Get the new base address */
        BaseAddress = (PVOID)((ULONG_PTR)BaseAddress - (ExtraPageCount * PAGE_SIZE));
    }

    /* Remove flags */
    Mdl->MdlFlags &= ~(MDL_MAPPED_TO_SYSTEM_VA | MDL_PARTIAL_HAS_BEEN_MAPPED | MDL_FREE_EXTRA_PTES);

    /* Release the system PTEs */
    MiReleaseSystemPtes(Pte, PageCount, SystemPteSpace);
}

VOID
NTAPI
MmUnmapReservedMapping(
    _In_ PVOID BaseAddress,
    _In_ ULONG PoolTag,
    _In_ PMDL MemoryDescriptorList)
{
    UNIMPLEMENTED_DBGBREAK();
}

/* EOF */
