
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "miarm.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

LONG MiDelayPageFaults;

extern MI_PFN_CACHE_ATTRIBUTE MiPlatformCacheAttributes[2][MmMaximumCacheType];
extern PPHYSICAL_MEMORY_DESCRIPTOR MmPhysicalMemoryBlock;
extern PVOID MmNonPagedPoolStart;
extern SIZE_T MmSizeOfNonPagedPoolInBytes;
extern PVOID MmNonPagedPoolExpansionStart;
extern ULONG ExpInitializationPhase;

/* FUNCTIONS ******************************************************************/

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(PAGE, MiFindContiguousMemory)
#endif

PVOID
NTAPI
MiCheckForContiguousMemory(
    _In_ PVOID BaseAddress,
    _In_ PFN_NUMBER BaseAddressPages,
    _In_ PFN_NUMBER SizeInPages,
    _In_ PFN_NUMBER LowestPfn,
    _In_ PFN_NUMBER HighestPfn,
    _In_ PFN_NUMBER BoundaryPfn,
    _In_ MI_PFN_CACHE_ATTRIBUTE CacheAttribute)
{
    PMMPTE StartPte;
    PMMPTE EndPte;
    PFN_NUMBER PreviousPage = 0;
    PFN_NUMBER Page;
    PFN_NUMBER HighPage;
    PFN_NUMBER BoundaryMask;
    PFN_NUMBER Pages = 0;

    /* Okay, first of all check if the PFNs match our restrictions */
    if (LowestPfn > HighestPfn)
        return NULL;

    if ((LowestPfn + SizeInPages) <= LowestPfn)
        return NULL;

    if ((LowestPfn + SizeInPages - 1) > HighestPfn)
        return NULL;

    if (BaseAddressPages < SizeInPages)
        return NULL;

    /* This is the last page we need to get to and the boundary requested */
    HighPage = (HighestPfn + 1 - SizeInPages);
    BoundaryMask = ~(BoundaryPfn - 1);

    /* And here's the PTEs for this allocation. Let's go scan them. */
    StartPte = MiAddressToPte(BaseAddress);
    EndPte = (StartPte + BaseAddressPages);

    for (; StartPte < EndPte; StartPte++)
    {
        /* Get this PTE's page number */
        ASSERT(StartPte->u.Hard.Valid == 1);
        Page = PFN_FROM_PTE(StartPte);

        /* Is this the beginning of our adventure? */
        if (!Pages)
        {
            /* Check if this PFN is within our range */
            if (Page >= LowestPfn && Page <= HighPage)
            {
                /* It is! Do you care about boundary (alignment)? */
                if (!BoundaryPfn || !((Page ^ (Page + SizeInPages - 1)) & BoundaryMask))
                    /* You don't care, or you do care but we deliver */
                    Pages++;
            }

            /* Have we found all the pages we need by now?
               Incidently, this means you only wanted one page.
            */
            if (Pages == SizeInPages)
                /* Mission complete */
                return MiPteToAddress(StartPte);
        }
        else
        {
            /* Have we found a page that doesn't seem to be contiguous? */
            if (Page != (PreviousPage + 1))
            {
                /* Ah crap, we have to start over */
                Pages = 0;
                continue;
            }

            /* Otherwise, we're still in the game. Do we have all our pages? */
            if (++Pages == SizeInPages)
                /* We do! This entire range was contiguous, so we'll return it! */
                return MiPteToAddress(StartPte - Pages + 1);
        }

        /* Try with the next PTE, remember this PFN */
        PreviousPage = Page;
    }

    /* All good returns are within the loop... */
    return NULL;
}

PFN_NUMBER
NTAPI
MiFindContiguousPages(
    _In_ PFN_NUMBER LowestPfn,
    _In_ PFN_NUMBER HighestPfn,
    _In_ PFN_NUMBER BoundaryPfn,
    _In_ PFN_NUMBER SizeInPages,
    _In_ MEMORY_CACHING_TYPE CacheType)
{
    PMMPTE PteAddress;
    PMMPFN Pfn;
    PMMPFN EndPfn;
    PFN_NUMBER Page;
    PFN_NUMBER PageCount;
    PFN_NUMBER LastPage;
    PFN_NUMBER Length;
    PFN_NUMBER BoundaryMask;
    ULONG CacheAttribute;
    ULONG ix;
    ULONG nx;
    KIRQL OldIrql;
    BOOLEAN IsFlush;

    DPRINT1("MiFindContiguousPages: %X, %X, %X, %X, %X\n", LowestPfn, HighestPfn, BoundaryPfn, SizeInPages, CacheType);
    PAGED_CODE();

    ASSERT(SizeInPages != 0);
    ASSERT(CacheType <= MmWriteCombined);

    CacheAttribute = MiPlatformCacheAttributes[0][CacheType];
    PteAddress = MiAddressToPte(MmNonPagedPoolExpansionStart);

    /* Convert the boundary PFN into an alignment mask */
    BoundaryMask = ~(BoundaryPfn - 1);

    /* Disable APCs */
    KeEnterGuardedRegion();
    //FIXME MmDynamicMemoryLock

    if (!MiChargeCommitmentCantExpand(SizeInPages, 0))
    {
        DPRINT1("MiFindContiguousPages: MiChargeCommitmentCantExpand(%IX) failed\n", SizeInPages);
        //FIXME MmDynamicMemoryLock
        KeLeaveGuardedRegion();
        return 0;
    }

    /* Acquire the PFN lock */
    OldIrql = MiLockPfnDb(APC_LEVEL);
    // ? MiDeferredUnlockPages(1);

    if ((SPFN_NUMBER)SizeInPages > (MmResidentAvailablePages - MmSystemLockPagesCount))
    {
        DPRINT1("MiFindContiguousPages: %IX, %IX, %IX\n", SizeInPages, MmResidentAvailablePages, MmSystemLockPagesCount);
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        goto ErrorExit;
    }

    if ((SPFN_NUMBER)SizeInPages > (SPFN_NUMBER)(MmAvailablePages - 0x80))
    {
        DPRINT1("MiFindContiguousPages: %IX, %IX\n", SizeInPages, MmAvailablePages);
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        goto ErrorExit;
    }

    InterlockedExchangeAddSizeT(&MmResidentAvailablePages, -SizeInPages);

    /* Release the PFN lock */
    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    for (nx = 4; ; --nx)
    {
        ix = 0;

        /* Loop all the physical memory blocks */
        do
        {
            /* Capture the base page and length of this memory block */
            Page = MmPhysicalMemoryBlock->Run[ix].BasePage;
            PageCount = MmPhysicalMemoryBlock->Run[ix].PageCount;

            /* Check how far this memory block will go */
            LastPage = (Page + PageCount);

            /* Trim it down to only the PFNs we're actually interested in */
            if (LastPage > (HighestPfn + 1))
                LastPage = (HighestPfn + 1);

            if (Page < LowestPfn)
                Page = LowestPfn;

            /* Skip this run if it's empty or fails to contain all the pages we need */
            if (!PageCount || (Page + SizeInPages) > LastPage)
            {
                ix++;
                continue;
            }

            Length = 0;

            /* Now scan all the relevant PFNs in this run */
            for (Pfn = MI_PFN_ELEMENT(Page); Page < LastPage; Page++, Pfn++)
            {
                /* If this PFN is in use, ignore it */
                if (MiIsPfnInUse(Pfn))
                {
                    Length = 0;
                    continue;
                }

                /* If we haven't chosen a start PFN yet and the caller specified an alignment,
                   make sure the page matches the alignment restriction
                */
                if (!Length && BoundaryPfn && ((Page ^ (Page + SizeInPages - 1)) & BoundaryMask))
                    /* It does not, so bail out */
                    continue;

                /* Increase the number of valid pages, and check if we have enough */
                if (++Length != SizeInPages)
                    continue;

                /* It appears we've amassed enough legitimate pages, rollback */
                Pfn -= (Length - 1);
                Page -= (Length - 1);

                /* Acquire the PFN lock */
                OldIrql = MiLockPfnDb(APC_LEVEL);

                /* Things might've changed for us. Is the page still free? */
                while (!MiIsPfnInUse(Pfn) && (CacheAttribute == MiCached || !Pfn->u4.MustBeCached))
                {
                    /* So far so good. Is this the last confirmed valid page? */
                    if (--Length)
                    {
                        /* Keep going.
                           The purpose of this loop is to reconfirm that after acquiring the PFN lock these pages are still usable.
                        */
                        Page++;
                        Pfn++;
                        continue;
                    }

                    /* Sanity check that we didn't go out of bounds */
                    ASSERT(ix != MmPhysicalMemoryBlock->NumberOfRuns);

                    if ((SPFN_NUMBER)SizeInPages > (SPFN_NUMBER)(MmAvailablePages - 0x80))
                    {
                        DPRINT1("MiFindContiguousPages: %IX, %IX\n", SizeInPages, MmAvailablePages);
                        MiUnlockPfnDb(OldIrql, APC_LEVEL);

                        InterlockedExchangeAddSizeT(&MmResidentAvailablePages, SizeInPages);

                        ASSERT((SSIZE_T)(SizeInPages) >= 0);
                        ASSERT(MmTotalCommittedPages >= (SizeInPages));
                        InterlockedExchangeAddSizeT(&MmTotalCommittedPages, -SizeInPages);

                        goto ErrorExit;
                    }

                    IsFlush = FALSE;
                    EndPfn = (Pfn - (SizeInPages - 1));

                    /* Loop until all PFN entries have been processed */
                    while (TRUE)
                    {
                        /* This PFN is now a used page, set it up */
                        MI_SET_USAGE(MI_USAGE_CONTINOUS_ALLOCATION);
                        MI_SET_PROCESS2("Kernel Driver");

                        if (Pfn->u3.e1.PageLocation == StandbyPageList)
                        {
                            MiUnlinkPageFromList(Pfn);
                            ASSERT(Pfn->u3.e2.ReferenceCount == 0);
                            MiRestoreTransitionPte(Pfn);
                        }
                        else
                        {
                            MiUnlinkFreeOrZeroedPage(Pfn);
                        }

                        Pfn->u3.e2.ReferenceCount = 1;
                        Pfn->u2.ShareCount = 1;

                        if ((Pfn->u3.e1.CacheAttribute != CacheAttribute) && !IsFlush)
                        {
                            //MiFlushTbForAttributeChange++;
                            KeFlushEntireTb(TRUE, TRUE);

                            if (CacheAttribute != MiCached)
                            {
                                //MiFlushCacheForAttributeChange++;
                                KeInvalidateAllCaches();
                            }

                            IsFlush = TRUE;
                        }

                        Pfn->u3.e1.CacheAttribute = CacheAttribute;
                        Pfn->u3.e1.PageLocation = ActiveAndValid;
                        Pfn->u3.e1.StartOfAllocation = 0;
                        Pfn->u3.e1.EndOfAllocation = 0;
                        Pfn->u3.e1.PrototypePte = 0;
                        Pfn->u4.VerifierAllocation = 0;

                        Pfn->PteAddress = PteAddress;
                        MI_MAKE_SOFTWARE_PTE(&Pfn->OriginalPte, MM_READWRITE);

                        /* Check if this is the last PFN, otherwise go on */
                        if (Pfn == EndPfn)
                            break;

                        Pfn--;
                    }

                    /* Mark the first and last PFN so we can find them later */
                    Pfn->u3.e1.StartOfAllocation = 1;
                    (Pfn + SizeInPages - 1)->u3.e1.EndOfAllocation = 1;

                    /* Now it's safe to let go of the PFN lock */
                    MiUnlockPfnDb(OldIrql, APC_LEVEL);

                    /* Quick sanity check that the last PFN is consistent */
                    EndPfn = (Pfn + SizeInPages);
                    ASSERT(EndPfn == MI_PFN_ELEMENT(Page + 1));

                    /* Compute the first page, and make sure it's consistent */
                    Page = (Page - (SizeInPages - 1));
                    ASSERT(Pfn == MI_PFN_ELEMENT(Page));
                    ASSERT(Page != 0);

                    /* Enable APCs and return the page */
                    //FIXME MmDynamicMemoryLock
                    KeLeaveGuardedRegion();
                    return Page;
                }

                /* If we got here, something changed while we hadn't acquired the PFN lock yet,
                   so we'll have to restart.
                */
                MiUnlockPfnDb(OldIrql, APC_LEVEL);
                Length = 0;
            }
        }
        while (++ix != MmPhysicalMemoryBlock->NumberOfRuns);

        if (!ExpInitializationPhase)
            break;

        InterlockedExchangeAddSizeT(&MiDelayPageFaults, 1);

        DPRINT1("MiFindContiguousPages: (%X) %IX\n", nx, SizeInPages);

        /* Start from 4 to 1*/
        switch (nx)
        {
            case 1:
                DPRINT1("MiFindContiguousPages: FIXME\n");
                ASSERT(FALSE);
                break;

            case 2:
                DPRINT1("MiFindContiguousPages: FIXME\n");
                ASSERT(FALSE);
                break;

            case 3:
                DPRINT1("MiFindContiguousPages: FIXME\n");
                ASSERT(FALSE);
                break;

            case 4:
                DPRINT1("MiFindContiguousPages: FIXME\n");
                ASSERT(FALSE);
                break;
        }

        InterlockedExchangeAddSizeT(&MiDelayPageFaults, -1);

        if (!nx)
            goto ErrorExit;
    }

    InterlockedExchangeAddSizeT(&MmResidentAvailablePages, SizeInPages);

ErrorExit:

    /* And if we get here, it means no suitable physical memory runs were found */
    //FIXME MmDynamicMemoryLock
    KeLeaveGuardedRegion();

    ASSERT((SSIZE_T)(SizeInPages) >= 0);
    ASSERT(MmTotalCommittedPages >= (SizeInPages));
    InterlockedExchangeAddSizeT(&MmTotalCommittedPages, -SizeInPages);

    return 0;
}

CODE_SEG("PAGE")
PVOID
NTAPI
MiFindContiguousMemory(
    _In_ PFN_NUMBER LowestPfn,
    _In_ PFN_NUMBER HighestPfn,
    _In_ PFN_NUMBER BoundaryPfn,
    _In_ PFN_NUMBER SizeInPages,
    _In_ MEMORY_CACHING_TYPE CacheType)
{
    PHYSICAL_ADDRESS PhysicalAddress;
    PVOID BaseAddress;
    PMMPFN Pfn;
    PMMPFN EndPfn;
    PMMPTE Pte;
    PFN_NUMBER Page;

    PAGED_CODE();
    ASSERT(SizeInPages != 0);

    /* Our last hope is to scan the free page list for contiguous pages */
    Page = MiFindContiguousPages(LowestPfn, HighestPfn, BoundaryPfn, SizeInPages, CacheType);
    if (!Page)
        return NULL;

    /* We'll just piggyback on the I/O memory mapper */
    PhysicalAddress.QuadPart = (Page << PAGE_SHIFT);

    BaseAddress = MmMapIoSpace(PhysicalAddress, (SizeInPages << PAGE_SHIFT), CacheType);
    ASSERT(BaseAddress);

    /* Loop the PFN entries */
    Pfn = MiGetPfnEntry(Page);
    EndPfn = (Pfn + SizeInPages);

    Pte = MiAddressToPte(BaseAddress);
    do
    {
        /* Write the PTE address */
        Pfn->PteAddress = Pte;
        Pfn->u4.PteFrame = PFN_FROM_PTE(MiAddressToPte(Pte++));
    }
    while (++Pfn < EndPfn);

    /* Return the address */
    return BaseAddress;
}

PVOID
NTAPI
MiAllocateContiguousMemory(
    _In_ SIZE_T NumberOfBytes,
    _In_ PFN_NUMBER LowestAcceptablePfn,
    _In_ PFN_NUMBER HighestAcceptablePfn,
    _In_ PFN_NUMBER BoundaryPfn,
    _In_ MEMORY_CACHING_TYPE CacheType)
{
    PVOID BaseAddress;
    PFN_NUMBER SizeInPages;
    MI_PFN_CACHE_ATTRIBUTE CacheAttribute;

    /* Verify count and cache type */
    ASSERT(NumberOfBytes != 0);
    ASSERT(CacheType <= MmWriteCombined);

    /* Compute size requested */
    SizeInPages = BYTES_TO_PAGES(NumberOfBytes);

    /* Convert the cache attribute and check for cached requests */
    CacheAttribute = MiPlatformCacheAttributes[FALSE][CacheType];
    if (CacheAttribute == MiCached)
    {
        /* Because initial nonpaged pool is supposed to be contiguous,
           go ahead and try making a nonpaged pool allocation first.
        */
        BaseAddress = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, NumberOfBytes, 'mCmM');
        if (BaseAddress)
        {
            /* Now make sure it's actually contiguous (if it came from expansion it might not be). */
            if (MiCheckForContiguousMemory(BaseAddress,
                                           SizeInPages,
                                           SizeInPages,
                                           LowestAcceptablePfn,
                                           HighestAcceptablePfn,
                                           BoundaryPfn,
                                           CacheAttribute))
            {
                /* Sweet, we're in business! */
                return BaseAddress;
            }

            /* No such luck */
            ExFreePoolWithTag(BaseAddress, 'mCmM');
        }
    }

    /* According to MSDN, the system won't try anything else if you're higher than APC level. */
    if (KeGetCurrentIrql() > APC_LEVEL)
        return NULL;

    /* Otherwise, we'll go try to find some */
    BaseAddress = MiFindContiguousMemory(LowestAcceptablePfn,
                                         HighestAcceptablePfn,
                                         BoundaryPfn,
                                         SizeInPages,
                                         CacheType);
    if (!BaseAddress)
    {
        DPRINT1("Unable to allocate contiguous memory for %d bytes (%d pages), out of memory!\n",
                NumberOfBytes, SizeInPages);
    }

    return BaseAddress;
}

VOID
NTAPI
MiFreeContiguousMemory(
    _In_ PVOID BaseAddress)
{
    PMMPFN Pfn;
    PMMPFN StartPfn;
    PMMPTE Pte;
    PFN_NUMBER PageFrameIndex;
    PFN_NUMBER LastPage;
    PFN_NUMBER PageCount;
    PVOID EndAddress;
    KIRQL OldIrql;

    PAGED_CODE();

    /* First, check if the memory came from initial nonpaged pool, or expansion */
    EndAddress = (PVOID)((ULONG_PTR)MmNonPagedPoolStart + MmSizeOfNonPagedPoolInBytes);

    if ((BaseAddress >= MmNonPagedPoolStart && BaseAddress < EndAddress) ||
        (BaseAddress >= MmNonPagedPoolExpansionStart && BaseAddress < MmNonPagedPoolEnd))
    {
        /* It did, so just use the pool to free this */
        ExFreePoolWithTag(BaseAddress, 'mCmM');
        return;
    }

    /* Get the PTE and frame number for the allocation*/
    Pte = MiAddressToPte(BaseAddress);
    PageFrameIndex = PFN_FROM_PTE(Pte);

    /* Now get the PFN entry for this, and make sure it's the correct one */
    Pfn = MiGetPfnEntry(PageFrameIndex);

    if (!Pfn || !Pfn->u3.e1.StartOfAllocation)
    {
        /* This probably means you did a free on an address that was in between */
        KeBugCheckEx(BAD_POOL_CALLER, 0x60, (ULONG_PTR)BaseAddress, 0, 0);
    }

    /* Now this PFN isn't the start of any allocation anymore, it's going out */
    StartPfn = Pfn;
    Pfn->u3.e1.StartOfAllocation = 0;

    /* Loop the PFNs until we find the one that marks the end of the allocation */
    do
    {
        /* Make sure these are the pages we setup in the allocation routine */
        ASSERT(Pfn->u3.e2.ReferenceCount == 1);
        ASSERT(Pfn->u2.ShareCount == 1);
        ASSERT(Pfn->PteAddress == Pte);
        ASSERT(Pfn->u3.e1.PageLocation == ActiveAndValid);
        ASSERT(Pfn->u4.VerifierAllocation == 0);
        ASSERT(Pfn->u3.e1.PrototypePte == 0);

        /* Set the special pending delete marker */
        MI_SET_PFN_DELETED(Pfn);

        /* Keep going for assertions */
        Pte++;
    }
    while (Pfn++->u3.e1.EndOfAllocation == 0);

    /* Found it, unmark it */
    Pfn--;
    Pfn->u3.e1.EndOfAllocation = 0;

    /* Now compute how many pages this represents */
    PageCount = (ULONG)(Pfn - StartPfn + 1);

    /* So we can know how much to unmap (recall we piggyback on I/O mappings) */
    MmUnmapIoSpace(BaseAddress, (PageCount << PAGE_SHIFT));

    /* Lock the PFN database */
    OldIrql = MiLockPfnDb(APC_LEVEL);

    /* Loop all the pages */
    LastPage = (PageFrameIndex + PageCount);
    Pfn = MiGetPfnEntry(PageFrameIndex);
    do
    {
        /* Decrement the share count and move on */
        MiDecrementShareCount(Pfn++, PageFrameIndex++);
    }
    while (PageFrameIndex < LastPage);

    /* Release the PFN lock */
    MiUnlockPfnDb(OldIrql, APC_LEVEL);
}

/* PUBLIC FUNCTIONS ***********************************************************/

PVOID
NTAPI
MmAllocateContiguousMemory(
    _In_ SIZE_T NumberOfBytes,
    _In_ PHYSICAL_ADDRESS HighestAcceptableAddress)
{
    PFN_NUMBER HighestPfn;

    /* Verify byte count */
    ASSERT(NumberOfBytes != 0);

    /* Convert and normalize the highest address into a PFN */
    HighestPfn = (PFN_NUMBER)(HighestAcceptableAddress.QuadPart >> PAGE_SHIFT);
    if (HighestPfn > MmHighestPhysicalPage)
        HighestPfn = MmHighestPhysicalPage;

    /* Let the contiguous memory allocator handle it */
    return MiAllocateContiguousMemory(NumberOfBytes, 0, HighestPfn, 0, MmCached);
}

PVOID
NTAPI
MmAllocateContiguousMemorySpecifyCache(
    _In_ SIZE_T NumberOfBytes,
    _In_ PHYSICAL_ADDRESS LowestAcceptableAddress OPTIONAL,
    _In_ PHYSICAL_ADDRESS HighestAcceptableAddress,
    _In_ PHYSICAL_ADDRESS BoundaryAddressMultiple OPTIONAL,
    _In_ MEMORY_CACHING_TYPE CacheType OPTIONAL)
{
    PFN_NUMBER LowestPfn;
    PFN_NUMBER HighestPfn;
    PFN_NUMBER BoundaryPfn;

    /* Verify count and cache type */
    ASSERT(NumberOfBytes != 0);
    ASSERT(CacheType <= MmWriteCombined);

    /* Convert the lowest address into a PFN */
    LowestPfn = (PFN_NUMBER)(LowestAcceptableAddress.QuadPart / PAGE_SIZE);

    if (BYTE_OFFSET(LowestAcceptableAddress.LowPart))
        LowestPfn++;

    /* Convert and validate the boundary address into a PFN */
    if (BYTE_OFFSET(BoundaryAddressMultiple.LowPart))
        return NULL;

    BoundaryPfn = (PFN_NUMBER)(BoundaryAddressMultiple.QuadPart / PAGE_SIZE);

    /* Convert the highest address into a PFN */
    HighestPfn = (PFN_NUMBER)(HighestAcceptableAddress.QuadPart / PAGE_SIZE);

    if (HighestPfn > MmHighestPhysicalPage)
        HighestPfn = MmHighestPhysicalPage;

    /* Validate the PFN bounds */
    if (LowestPfn > HighestPfn)
        return NULL;

    /* Let the contiguous memory allocator handle it */
    return MiAllocateContiguousMemory(NumberOfBytes, LowestPfn, HighestPfn, BoundaryPfn, CacheType);
}

VOID
NTAPI
MmFreeContiguousMemory(
    _In_ PVOID BaseAddress)
{
    /* Let the contiguous memory allocator handle it */
    MiFreeContiguousMemory(BaseAddress);
}

VOID
NTAPI
MmFreeContiguousMemorySpecifyCache(
    _In_ PVOID BaseAddress,
    _In_ SIZE_T NumberOfBytes,
    _In_ MEMORY_CACHING_TYPE CacheType)
{
    MmFreeContiguousMemory(BaseAddress);
}

/* EOF */
