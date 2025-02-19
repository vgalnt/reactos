
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "miarm.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

MM_PAGED_POOL_INFO MmPagedPoolInfo;
KGUARDED_MUTEX MmPagedPoolMutex;
SIZE_T MmAllocatedNonPagedPool;
ULONG MmConsumedPoolPercentage;
LIST_ENTRY MmNonPagedPoolFreeListHead[MI_MAX_FREE_PAGE_LISTS];
PFN_COUNT MmNumberOfFreeNonPagedPool;
PFN_COUNT MiExpansionPoolPagesInitialCharge;
PVOID MmNonPagedPoolEnd0;
PFN_NUMBER MiStartOfInitialPoolFrame;
PFN_NUMBER MiEndOfInitialPoolFrame;
SLIST_HEADER MiNonPagedPoolSListHead;
ULONG MiNonPagedPoolSListMaximum = 4;
SLIST_HEADER MiPagedPoolSListHead;
ULONG MiPagedPoolSListMaximum = 8;
BOOLEAN MmProtectFreedNonPagedPool;

extern PVOID MmNonPagedPoolStart;
extern PVOID MmPagedPoolEnd;
extern SIZE_T MmSizeOfNonPagedPoolInBytes;
extern PVOID MmNonPagedPoolExpansionStart;
extern SIZE_T MmMaximumNonPagedPoolInBytes;
extern PFN_NUMBER MmMaximumNonPagedPoolInPages;
extern PFN_NUMBER MiLowNonPagedPoolThreshold;
extern PFN_NUMBER MiHighNonPagedPoolThreshold;
extern MMPDE ValidKernelPde;
extern MMPDE ValidKernelPte;
extern ULONG MmSecondaryColorMask;
extern ULONG MmSystemPageColor;
extern PFN_NUMBER MmSizeOfPagedPoolInPages;
extern PFN_NUMBER MiLowPagedPoolThreshold;
extern PFN_NUMBER MiHighPagedPoolThreshold;
extern PKEVENT MiLowPagedPoolEvent;
extern PKEVENT MiHighPagedPoolEvent;
extern PKEVENT MiLowNonPagedPoolEvent;
extern PKEVENT MiHighNonPagedPoolEvent;
extern PMM_SESSION_SPACE MmSessionSpace;
extern PVOID MiSessionPoolStart;
extern PVOID MiSessionPoolEnd;
extern SIZE_T MmSessionPoolSize;

/* FUNCTIONS ******************************************************************/


#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(INIT, MiInitializeNonPagedPool)
  #pragma alloc_text(INIT, MiInitializeNonPagedPoolThresholds)
  #pragma alloc_text(INIT, MiInitializePoolEvents)
  #pragma alloc_text(PAGE, MiInitializeSessionPool)
  #pragma alloc_text(PAGE, MmAllocateMappingAddress)
  #pragma alloc_text(PAGE, MmFreeMappingAddress)
#endif

CODE_SEG("INIT")
VOID
NTAPI
MiInitializeNonPagedPool(VOID)
{
    PMMFREE_POOL_ENTRY FreeEntry;
    PMMFREE_POOL_ENTRY FirstEntry;
    PFN_COUNT PoolPages;
    PMMPTE Pte;
    ULONG ix;

    PAGED_CODE();

    /* Initialize the pool S-LISTs as well as their maximum count.
       In general, we'll allow 8 times the default on a 2GB system, and two times the default on a 1GB system.
    */
    InitializeSListHead(&MiPagedPoolSListHead);
    InitializeSListHead(&MiNonPagedPoolSListHead);

    if (MmNumberOfPhysicalPages >= ((2 * _1GB) /PAGE_SIZE))
    {
        MiNonPagedPoolSListMaximum *= 8;
        MiPagedPoolSListMaximum *= 8;
    }
    else if (MmNumberOfPhysicalPages >= (_1GB /PAGE_SIZE))
    {
        MiNonPagedPoolSListMaximum *= 2;
        MiPagedPoolSListMaximum *= 2;
    }

    /* However if debugging options for the pool are enabled,
       turn off the S-LIST to reduce the risk of messing things up even more
    */
    if (MmProtectFreedNonPagedPool)
    {
        MiNonPagedPoolSListMaximum = 0;
        MiPagedPoolSListMaximum = 0;
    }

    /* We keep 4 lists of free pages (4 lists help avoid contention) */
    for (ix = 0; ix < MI_MAX_FREE_PAGE_LISTS; ix++)
        /* Initialize each of them */
        InitializeListHead(&MmNonPagedPoolFreeListHead[ix]);

    /* Calculate how many pages the initial nonpaged pool has */
    PoolPages = (PFN_COUNT)BYTES_TO_PAGES(MmSizeOfNonPagedPoolInBytes);
    MmNumberOfFreeNonPagedPool = PoolPages;

    /* Initialize the first free entry */
    FreeEntry = MmNonPagedPoolStart;
    FirstEntry = FreeEntry;
    FreeEntry->Size = PoolPages;
    FreeEntry->Signature = MM_FREE_POOL_SIGNATURE;
    FreeEntry->Owner = FirstEntry;

    /* Insert it into the last list */
    InsertHeadList(&MmNonPagedPoolFreeListHead[MI_MAX_FREE_PAGE_LISTS - 1], &FreeEntry->List);

    /* Now create free entries for every single other page */
    while (PoolPages-- > 1)
    {
        /* Link them all back to the original entry */
        FreeEntry = (PMMFREE_POOL_ENTRY)((ULONG_PTR)FreeEntry + PAGE_SIZE);
        FreeEntry->Owner = FirstEntry;
        FreeEntry->Signature = MM_FREE_POOL_SIGNATURE;
    }

    /* Validate and remember first allocated pool page */
    Pte = MiAddressToPte(MmNonPagedPoolStart);
    ASSERT(Pte->u.Hard.Valid == 1);
    MiStartOfInitialPoolFrame = PFN_FROM_PTE(Pte);

    /* Keep track of where initial nonpaged pool ends */
    MmNonPagedPoolEnd0 = (PVOID)((ULONG_PTR)MmNonPagedPoolStart + MmSizeOfNonPagedPoolInBytes);

    /* Validate and remember last allocated pool page */
    Pte = MiAddressToPte((PVOID)((ULONG_PTR)MmNonPagedPoolEnd0 - 1));
    ASSERT(Pte->u.Hard.Valid == 1);
    MiEndOfInitialPoolFrame = PFN_FROM_PTE(Pte);

    /* Validate the first nonpaged pool expansion page (which is a guard page) */
    Pte = MiAddressToPte(MmNonPagedPoolExpansionStart);
    ASSERT(Pte->u.Hard.Valid == 0);

    /* Calculate the size of the expansion region alone */
    MiExpansionPoolPagesInitialCharge = (PFN_COUNT)
    BYTES_TO_PAGES(MmMaximumNonPagedPoolInBytes - MmSizeOfNonPagedPoolInBytes);

    /* Remove 2 pages, since there's a guard page on top and on the bottom */
    MiExpansionPoolPagesInitialCharge -= 2;

    /* Now initialize the nonpaged pool expansion PTE space.
       Remember there's a guard page on top so make sure to skip it.
       The bottom guard page will be guaranteed by the fact our size is off by one.
    */
    MiInitializeSystemPtes((Pte + 1), MiExpansionPoolPagesInitialCharge, NonPagedPoolExpansion);
}

CODE_SEG("INIT")
VOID
NTAPI
MiInitializeNonPagedPoolThresholds(VOID)
{
    PFN_NUMBER Size = MmMaximumNonPagedPoolInPages;

    /* Default low threshold of 8MB or one third of nonpaged pool */
    MiLowNonPagedPoolThreshold = ((8 * _1MB) >> PAGE_SHIFT);
    MiLowNonPagedPoolThreshold = min(MiLowNonPagedPoolThreshold, (Size / 3));

    /* Default high threshold of 20MB or 50% */
    MiHighNonPagedPoolThreshold = ((20 * _1MB) >> PAGE_SHIFT);
    MiHighNonPagedPoolThreshold = min(MiHighNonPagedPoolThreshold, (Size / 2));

    ASSERT(MiLowNonPagedPoolThreshold < MiHighNonPagedPoolThreshold);
}

BOOLEAN
NTAPI
MiUnProtectFreeNonPagedPool(
    _In_ PVOID VirtualAddress,
    _In_ ULONG PageCount)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

VOID
NTAPI
MiProtectedPoolRemoveEntryList(
    _In_ PLIST_ENTRY Entry)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
MiProtectedPoolInsertList(
    _In_ PLIST_ENTRY ListHead,
    _In_ PLIST_ENTRY Entry,
    _In_ BOOLEAN Critical)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
MiProtectFreeNonPagedPool(
    _In_ PVOID VirtualAddress,
    _In_ ULONG PageCount)
{
    UNIMPLEMENTED_DBGBREAK();
}

PVOID
NTAPI
MiAllocatePoolPages(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T SizeInBytes)
{
    PMMFREE_POOL_ENTRY FreeEntry;
    PFN_NUMBER PageFrameNumber;
    PFN_COUNT PageTableCount;
    PFN_COUNT SizeInPages;
    PLIST_ENTRY NextEntry;
    PLIST_ENTRY NextHead;
    PLIST_ENTRY LastHead;
    PVOID BaseVaStart;
    PVOID BaseVa;
    PMMPTE StartPte;
    PMMPDE Pde;
    PMMPTE Pte;
    MMPTE TempPte;
    MMPDE TempPde;
    PMMPFN Pfn;
    ULONG EndAllocation;
    ULONG ix;
    KIRQL OldIrql;

    /* Figure out how big the allocation is in pages */
    SizeInPages = (PFN_COUNT)BYTES_TO_PAGES(SizeInBytes);

    /* Check for overflow */
    if (SizeInPages == 0)
        /* Fail */
        return NULL;

    /* Handle paged pool */
    if ((PoolType & BASE_POOL_TYPE_MASK) == PagedPool)
    {
        /* If only one page is being requested, try to grab it from the S-LIST */
        if (SizeInPages == 1 && ExQueryDepthSList(&MiPagedPoolSListHead))
        {
            BaseVa = InterlockedPopEntrySList(&MiPagedPoolSListHead);
            if (BaseVa)
                return BaseVa;
        }

        /* Lock the paged pool mutex */
        KeAcquireGuardedMutex(&MmPagedPoolMutex);

        /* Find some empty allocation space */
        ix = RtlFindClearBitsAndSet(MmPagedPoolInfo.PagedPoolAllocationMap,
                                    SizeInPages,
                                    MmPagedPoolInfo.PagedPoolHint);
        if (ix == 0xFFFFFFFF)
        {
            /* Get the page bit count */
            ix = ((SizeInPages - 1) / PTE_PER_PAGE) + 1;
            DPRINT("Paged pool expansion: %lu %x\n", ix, SizeInPages);

            /* Check if there is enougn paged pool expansion space left */
            if (MmPagedPoolInfo.NextPdeForPagedPoolExpansion > (PMMPDE)MiAddressToPte(MmPagedPoolInfo.LastPteForPagedPool))
            {
                /* Out of memory! */
                DPRINT1("FAILED to allocate %Iu bytes from paged pool\n", SizeInBytes);
                KeReleaseGuardedMutex(&MmPagedPoolMutex);
                return NULL;
            }

            /* Check if we'll have to expand past the last PTE we have available */
            if (((ix - 1) + MmPagedPoolInfo.NextPdeForPagedPoolExpansion) > (PMMPDE)MiAddressToPte(MmPagedPoolInfo.LastPteForPagedPool))
            {
                /* We can only support this much then */
                Pde = MiPteToPde(MmPagedPoolInfo.LastPteForPagedPool);
                PageTableCount = (PFN_COUNT)(Pde + 1 - MmPagedPoolInfo.NextPdeForPagedPoolExpansion);
                ASSERT(PageTableCount < ix);
                ix = PageTableCount;
            }
            else
            {
                /* Otherwise, there is plenty of space left for this expansion */
                PageTableCount = ix;
            }

            /* Get the template PDE we'll use to expand */
            TempPde = ValidKernelPde;

            /* Get the first PTE in expansion space */
            Pde = MmPagedPoolInfo.NextPdeForPagedPoolExpansion;
            BaseVa = MiPdeToPte(Pde);
            BaseVaStart = BaseVa;

            /* Lock the PFN database and loop pages */
            OldIrql = MiLockPfnDb(APC_LEVEL);

            do
            {
                /* It should not already be valid */
                ASSERT(Pde->u.Hard.Valid == 0);

                /* Request a page */
                MI_SET_USAGE(MI_USAGE_PAGED_POOL);
                MI_SET_PROCESS2("Kernel");
                PageFrameNumber = MiRemoveAnyPage(MiGetColor());
                TempPde.u.Hard.PageFrameNumber = PageFrameNumber;

              #if (_MI_PAGING_LEVELS >= 3)
                /* On PAE/x64 systems, there's no double-buffering */
                /* Initialize the PFN entry for it */
                MiInitializePfnForOtherProcess(PageFrameNumber,
                                               (PMMPTE)Pde,
                                               PFN_FROM_PTE(MiAddressToPte(Pde)));

                /* Write the actual PDE now */
                MI_WRITE_VALID_PDE(Pde, TempPde);
              #else
                /* Save it into our double-buffered system page directory */
                MmSystemPagePtes[MiGetPdeOffset(Pde)] = TempPde;

                /* Initialize the PFN */
                MiInitializePfnForOtherProcess(PageFrameNumber,
                                               (PMMPTE)Pde,
                                               MmSystemPageDirectory[MiGetPdIndex(Pde)]);
              #endif

                /* Move on to the next expansion address */
                Pde++;
                BaseVa = (PVOID)((ULONG_PTR)BaseVa + PAGE_SIZE);
                ix--;
            } while (ix > 0);

            /* Release the PFN database lock */
            MiUnlockPfnDb(OldIrql, APC_LEVEL);

            /* These pages are now available, clear their availablity bits */
            EndAllocation = (ULONG)(MmPagedPoolInfo.NextPdeForPagedPoolExpansion - (PMMPDE)MiAddressToPte(MmPagedPoolInfo.FirstPteForPagedPool)) * PTE_PER_PAGE;

            RtlClearBits(MmPagedPoolInfo.PagedPoolAllocationMap, EndAllocation, (PageTableCount * PTE_PER_PAGE));

            /* Update the next expansion location */
            MmPagedPoolInfo.NextPdeForPagedPoolExpansion += PageTableCount;

            /* Zero out the newly available memory */
            RtlZeroMemory(BaseVaStart, (PageTableCount * PAGE_SIZE));

            /* Now try consuming the pages again */
            ix = RtlFindClearBitsAndSet(MmPagedPoolInfo.PagedPoolAllocationMap,
                                       SizeInPages,
                                       0);
            if (ix == 0xFFFFFFFF)
            {
                /* Out of memory! */
                DPRINT1("FAILED to allocate %Iu bytes from paged pool\n", SizeInBytes);
                KeReleaseGuardedMutex(&MmPagedPoolMutex);
                return NULL;
            }
        }

        /* Update the pool hint if the request was just one page */
        if (SizeInPages == 1)
            MmPagedPoolInfo.PagedPoolHint = (ix + 1);

        /* Update the end bitmap so we know the bounds of this allocation when the time comes to free it */
        EndAllocation = (ix + SizeInPages - 1);
        RtlSetBit(MmPagedPoolInfo.EndOfPagedPoolBitmap, EndAllocation);

        /* Now we can release the lock (it mainly protects the bitmap) */
        KeReleaseGuardedMutex(&MmPagedPoolMutex);

        /* Now figure out where this allocation starts */
        BaseVa = (PVOID)((ULONG_PTR)MmPagedPoolStart + (ix << PAGE_SHIFT));

        /* Flush the TLB */
        KeFlushEntireTb(TRUE, TRUE);

        /* Setup a demand-zero writable PTE */
        MI_MAKE_SOFTWARE_PTE(&TempPte, MM_READWRITE);

        /* Find the first and last PTE, then loop them all */
        Pte = MiAddressToPte(BaseVa);
        StartPte = Pte + SizeInPages;
        do
        {
            /* Write the demand zero PTE and keep going */
            MI_WRITE_INVALID_PTE(Pte, TempPte);
        } while (++Pte < StartPte);

        /* Return the allocation address to the caller */
        return BaseVa;
    }

    /* If only one page is being requested, try to grab it from the S-LIST */
    if ((SizeInPages == 1) && (ExQueryDepthSList(&MiNonPagedPoolSListHead)))
    {
        BaseVa = InterlockedPopEntrySList(&MiNonPagedPoolSListHead);
        if (BaseVa)
            return BaseVa;
    }

    /* Allocations of less than 4 pages go into their individual buckets */
    ix = SizeInPages - 1;
    if (ix >= MI_MAX_FREE_PAGE_LISTS)
        ix = MI_MAX_FREE_PAGE_LISTS - 1;

    /* Loop through all the free page lists based on the page index */
    NextHead = &MmNonPagedPoolFreeListHead[ix];
    LastHead = &MmNonPagedPoolFreeListHead[MI_MAX_FREE_PAGE_LISTS];

    /* Acquire the nonpaged pool lock */
    OldIrql = KeAcquireQueuedSpinLock(LockQueueMmNonPagedPoolLock);
    do
    {
        /* Now loop through all the free page entries in this given list */
        NextEntry = NextHead->Flink;
        while (NextEntry != NextHead)
        {
            /* Is freed non paged pool enabled */
            if (MmProtectFreedNonPagedPool)
                /* We need to be able to touch this page, unprotect it */
                MiUnProtectFreeNonPagedPool(NextEntry, 0);

            /* Grab the entry and see if it can handle our allocation */
            FreeEntry = CONTAINING_RECORD(NextEntry, MMFREE_POOL_ENTRY, List);
            ASSERT(FreeEntry->Signature == MM_FREE_POOL_SIGNATURE);

            if (FreeEntry->Size >= SizeInPages)
            {
                /* It does, so consume the pages from here */
                FreeEntry->Size -= SizeInPages;

                /* The allocation will begin in this free page area */
                BaseVa = (PVOID)((ULONG_PTR)FreeEntry + (FreeEntry->Size  << PAGE_SHIFT));

                /* Remove the item from the list, depending if pool is protected */
                if (MmProtectFreedNonPagedPool)
                    MiProtectedPoolRemoveEntryList(&FreeEntry->List);
                else
                    RemoveEntryList(&FreeEntry->List);

                /* However, check if its' still got space left */
                if (FreeEntry->Size != 0)
                {
                    /* Check which list to insert this entry into */
                    ix = FreeEntry->Size - 1;
                    if (ix >= MI_MAX_FREE_PAGE_LISTS)
                        ix = MI_MAX_FREE_PAGE_LISTS - 1;

                    /* Insert the entry into the free list head, check for prot. pool */
                    if (MmProtectFreedNonPagedPool)
                        MiProtectedPoolInsertList(&MmNonPagedPoolFreeListHead[ix], &FreeEntry->List, TRUE);
                    else
                        InsertTailList(&MmNonPagedPoolFreeListHead[ix], &FreeEntry->List);

                    /* Is freed non paged pool protected? */
                    if (MmProtectFreedNonPagedPool)
                        /* Protect the freed pool! */
                        MiProtectFreeNonPagedPool(FreeEntry, FreeEntry->Size);
                }

                /* Grab the PTE for this allocation */
                Pte = MiAddressToPte(BaseVa);
                ASSERT(Pte->u.Hard.Valid == 1);

                /* Grab the PFN NextEntry and index */
                Pfn = MiGetPfnEntry(PFN_FROM_PTE(Pte));

                /* Now mark it as the beginning of an allocation */
                ASSERT(Pfn->u3.e1.StartOfAllocation == 0);
                Pfn->u3.e1.StartOfAllocation = 1;

                /* Mark it as special pool if needed */
                ASSERT(Pfn->u4.VerifierAllocation == 0);
                if (PoolType & VERIFIER_POOL_MASK)
                    Pfn->u4.VerifierAllocation = 1;

                /* Check if the allocation is larger than one page */
                if (SizeInPages != 1)
                {
                    /* Navigate to the last PFN entry and PTE */
                    Pte += SizeInPages - 1;
                    ASSERT(Pte->u.Hard.Valid == 1);
                    Pfn = MiGetPfnEntry(Pte->u.Hard.PageFrameNumber);
                }

                /* Mark this PFN as the last (might be the same as the first) */
                ASSERT(Pfn->u3.e1.EndOfAllocation == 0);
                Pfn->u3.e1.EndOfAllocation = 1;

                /* Release the nonpaged pool lock, and return the allocation */
                KeReleaseQueuedSpinLock(LockQueueMmNonPagedPoolLock, OldIrql);
                return BaseVa;
            }

            /* Try the next free page entry */
            NextEntry = FreeEntry->List.Flink;

            /* Is freed non paged pool protected? */
            if (MmProtectFreedNonPagedPool)
                /* Protect the freed pool! */
                MiProtectFreeNonPagedPool(FreeEntry, FreeEntry->Size);
        }
    } while (++NextHead < LastHead);

    /* If we got here, we're out of space. Start by releasing the lock */
    KeReleaseQueuedSpinLock(LockQueueMmNonPagedPoolLock, OldIrql);

    /* Allocate some system PTEs */
    StartPte = MiReserveSystemPtes(SizeInPages, NonPagedPoolExpansion);
    Pte = StartPte;
    if (StartPte == NULL)
    {
        /* Ran out of memory */
        DPRINT1("Out of NP Expansion Pool\n");
        return NULL;
    }

    /* Acquire the pool lock now */
    OldIrql = KeAcquireQueuedSpinLock(LockQueueMmNonPagedPoolLock);

    /* Lock the PFN database too */
    MiAcquirePfnLockAtDpcLevel();

    /* Loop the pages */
    TempPte = ValidKernelPte;
    do
    {
        /* Allocate a page */
        MI_SET_USAGE(MI_USAGE_PAGED_POOL);
        MI_SET_PROCESS2("Kernel");
        PageFrameNumber = MiRemoveAnyPage(MiGetColor());

        /* Get the PFN entry for it and fill it out */
        Pfn = MiGetPfnEntry(PageFrameNumber);
        Pfn->u3.e2.ReferenceCount = 1;
        Pfn->u2.ShareCount = 1;
        Pfn->PteAddress = Pte;
        Pfn->u3.e1.PageLocation = ActiveAndValid;
        Pfn->u4.VerifierAllocation = 0;

        /* Write the PTE for it */
        TempPte.u.Hard.PageFrameNumber = PageFrameNumber;
        MI_WRITE_VALID_PTE(Pte++, TempPte);
    } while (--SizeInPages > 0);

    /* This is the last page */
    Pfn->u3.e1.EndOfAllocation = 1;

    /* Get the first page and mark it as such */
    Pfn = MiGetPfnEntry(StartPte->u.Hard.PageFrameNumber);
    Pfn->u3.e1.StartOfAllocation = 1;

    /* Mark it as a verifier allocation if needed */
    ASSERT(Pfn->u4.VerifierAllocation == 0);

    if (PoolType & VERIFIER_POOL_MASK)
        Pfn->u4.VerifierAllocation = 1;

    /* Release the PFN and nonpaged pool lock */
    MiReleasePfnLockFromDpcLevel();
    KeReleaseQueuedSpinLock(LockQueueMmNonPagedPoolLock, OldIrql);

    /* Return the address */
    return MiPteToAddress(StartPte);
}

ULONG
NTAPI
MiFreePoolPages(
    _In_ PVOID StartingVa)
{
    PMMFREE_POOL_ENTRY FreeEntry;
    PMMFREE_POOL_ENTRY NextEntry;
    PMMFREE_POOL_ENTRY LastEntry;
    PMMPTE Pte;
    PMMPTE StartPte;
    PMMPFN Pfn;
    PMMPFN StartPfn;
    PFN_COUNT FreePages;
    PFN_COUNT NumberOfPages;
    ULONG_PTR Offset;
    ULONG ix;
    ULONG End;
    KIRQL OldIrql;

    /* Handle paged pool */
    if ((StartingVa >= MmPagedPoolStart) && (StartingVa <= MmPagedPoolEnd))
    {
        /* Calculate the offset from the beginning of paged pool, and convert it into pages */
        Offset = ((ULONG_PTR)StartingVa - (ULONG_PTR)MmPagedPoolStart);
        ix = (ULONG)(Offset >> PAGE_SHIFT);
        End = ix;

        /* Now use the end bitmap to scan until we find a set bit, meaning that this allocation finishes here */
        while (!RtlTestBit(MmPagedPoolInfo.EndOfPagedPoolBitmap, End))
            End++;

        /* Now calculate the total number of pages this allocation spans.
           If it's only one page, add it to the S-LIST instead of freeing it.
        */
        NumberOfPages = (End - ix + 1);

        if ((NumberOfPages == 1) &&
            (ExQueryDepthSList(&MiPagedPoolSListHead) < MiPagedPoolSListMaximum))
        {
            InterlockedPushEntrySList(&MiPagedPoolSListHead, StartingVa);
            return 1;
        }

        /* Delete the actual pages */
        Pte = (MmPagedPoolInfo.FirstPteForPagedPool + ix);
        FreePages = MiDeleteSystemPageableVm(Pte, NumberOfPages, 0, NULL);
        ASSERT(FreePages == NumberOfPages);

        /* Acquire the paged pool lock */
        KeAcquireGuardedMutex(&MmPagedPoolMutex);

        /* Clear the allocation and free bits */
        RtlClearBit(MmPagedPoolInfo.EndOfPagedPoolBitmap, End);
        RtlClearBits(MmPagedPoolInfo.PagedPoolAllocationMap, ix, NumberOfPages);

        /* Update the hint if we need to */
        if (ix < MmPagedPoolInfo.PagedPoolHint)
            MmPagedPoolInfo.PagedPoolHint = ix;

        /* Release the lock protecting the bitmaps */
        KeReleaseGuardedMutex(&MmPagedPoolMutex);

        /* And finally return the number of pages freed */
        return NumberOfPages;
    }

    /* Get the first PTE and its corresponding PFN entry.
       If this is also the last PTE, meaning that this allocation was only for one page,
       push it into the S-LIST instead of freeing it.
    */
    StartPte = Pte = MiAddressToPte(StartingVa);
    StartPfn = Pfn = MiGetPfnEntry(Pte->u.Hard.PageFrameNumber);

    if ((Pfn->u3.e1.EndOfAllocation == 1) &&
        (ExQueryDepthSList(&MiNonPagedPoolSListHead) < MiNonPagedPoolSListMaximum))
    {
        InterlockedPushEntrySList(&MiNonPagedPoolSListHead, StartingVa);
        return 1;
    }

    /* Loop until we find the last PTE */
    while (Pfn->u3.e1.EndOfAllocation == 0)
    {
        /* Keep going */
        Pte++;
        Pfn = MiGetPfnEntry(Pte->u.Hard.PageFrameNumber);
    }

    /* Now we know how many pages we have */
    NumberOfPages = (PFN_COUNT)(Pte - StartPte + 1);

    /* Acquire the nonpaged pool lock */
    OldIrql = KeAcquireQueuedSpinLock(LockQueueMmNonPagedPoolLock);

    /* Mark the first and last PTEs as not part of an allocation anymore */
    StartPfn->u3.e1.StartOfAllocation = 0;
    Pfn->u3.e1.EndOfAllocation = 0;

    /* Assume we will free as many pages as the allocation was */
    FreePages = NumberOfPages;

    /* Peek one page past the end of the allocation */
    Pte++;

    /* Guard against going past initial nonpaged pool */
    if (MiGetPfnEntryIndex(Pfn) == MiEndOfInitialPoolFrame)
    {
        /* This page is on the outskirts of initial nonpaged pool, so ignore it */
        Pfn = NULL;
    }
    else
    {
        /* Sanity check */
        ASSERT(((ULONG_PTR)StartingVa + NumberOfPages) <= (ULONG_PTR)MmNonPagedPoolEnd);

        /* Check if protected pool is enabled */
        if (MmProtectFreedNonPagedPool)
            /* The freed block will be merged, it must be made accessible */
            MiUnProtectFreeNonPagedPool(MiPteToAddress(Pte), 0);

        /* Otherwise, our entire allocation must've fit within the initial non paged pool,
           or the expansion nonpaged pool, so get the PFN entry of the next allocation.
        */
        if (Pte->u.Hard.Valid)
            /* It's either expansion or initial: get the PFN entry */
            Pfn = MiGetPfnEntry(Pte->u.Hard.PageFrameNumber);
        else
            /* This means we've reached the guard page that protects the end of the expansion nonpaged pool */
            Pfn = NULL;
    }

    /* Check if this allocation actually exists */
    if (Pfn && !Pfn->u3.e1.StartOfAllocation)
    {
        /* It doesn't, so we should actually locate a free entry descriptor */
        FreeEntry = (PMMFREE_POOL_ENTRY)((ULONG_PTR)StartingVa + (NumberOfPages << PAGE_SHIFT));

        ASSERT(FreeEntry->Signature == MM_FREE_POOL_SIGNATURE);
        ASSERT(FreeEntry->Owner == FreeEntry);

        /* Consume this entry's pages */
        FreePages += FreeEntry->Size;

        /* Remove the item from the list, depending if pool is protected */
        if (MmProtectFreedNonPagedPool)
            MiProtectedPoolRemoveEntryList(&FreeEntry->List);
        else
            RemoveEntryList(&FreeEntry->List);
    }

    /* Now get the official free entry we'll create for the caller's allocation */
    FreeEntry = StartingVa;

    /* Check if the our allocation is the very first page */
    if (MiGetPfnEntryIndex(StartPfn) == MiStartOfInitialPoolFrame)
    {
        /* Then we can't do anything or we'll risk underflowing */
        Pfn = NULL;
    }
    else
    {
        /* Otherwise, get the PTE for the page right before our allocation */
        Pte -= (NumberOfPages + 1);

        /* Check if protected pool is enabled */
        if (MmProtectFreedNonPagedPool)
            /* The freed block will be merged, it must be made accessible */
            MiUnProtectFreeNonPagedPool(MiPteToAddress(Pte), 0);

        /* Check if this is valid pool, or a guard page */
        if (Pte->u.Hard.Valid)
            /* It's either expansion or initial nonpaged pool, get the PFN entry */
            Pfn = MiGetPfnEntry(Pte->u.Hard.PageFrameNumber);
        else
            /* We must've reached the guard page, so don't risk touching it */
            Pfn = NULL;
    }

    /* Check if there is a valid PFN entry for the page before the allocation
       and then check if this page was actually the end f an allocation.
       If it wasn't, then we know for sure it's a free page.
    */
    if (Pfn && !Pfn->u3.e1.EndOfAllocation)
    {
        /* Get the free entry descriptor for that given page range */
        FreeEntry = (PMMFREE_POOL_ENTRY)((ULONG_PTR)StartingVa - PAGE_SIZE);
        ASSERT(FreeEntry->Signature == MM_FREE_POOL_SIGNATURE);
        FreeEntry = FreeEntry->Owner;

        /* Check if protected pool is enabled */
        if (MmProtectFreedNonPagedPool)
            /* The freed block will be merged, it must be made accessible */
            MiUnProtectFreeNonPagedPool(FreeEntry, 0);

        /* Check if the entry is small enough to be indexed on a free list.
           If it is, we'll want to re-insert it, since we're about to
           collapse our pages on top of it, which will change its count.
        */
        if (FreeEntry->Size < (MI_MAX_FREE_PAGE_LISTS - 1))
        {
            /* Remove the item from the list, depending if pool is protected */
            if (MmProtectFreedNonPagedPool)
                MiProtectedPoolRemoveEntryList(&FreeEntry->List);
            else
                RemoveEntryList(&FreeEntry->List);

            /* Update its size */
            FreeEntry->Size += FreePages;

            /* And now find the new appropriate list to place it in */
            ix = (ULONG)(FreeEntry->Size - 1);

            if (ix >= MI_MAX_FREE_PAGE_LISTS)
                ix = (MI_MAX_FREE_PAGE_LISTS - 1);

            /* Insert the entry into the free list head, check for prot. pool */
            if (MmProtectFreedNonPagedPool)
                MiProtectedPoolInsertList(&MmNonPagedPoolFreeListHead[ix], &FreeEntry->List, TRUE);
            else
                InsertTailList(&MmNonPagedPoolFreeListHead[ix], &FreeEntry->List);
        }
        else
        {
            /* Otherwise, just combine our free pages into this entry */
            FreeEntry->Size += FreePages;
        }
    }

    /* Check if we were unable to do any compaction, and we'll stick with this */
    if (FreeEntry == StartingVa)
    {
        /* Well, now we are a free entry. At worse we just have our newly freed pages,
           at best we have our pages plus whatever entry came after us.
        */
        FreeEntry->Size = FreePages;

        /* Find the appropriate list we should be on */
        ix = (FreeEntry->Size - 1);

        if (ix >= MI_MAX_FREE_PAGE_LISTS)
            ix = (MI_MAX_FREE_PAGE_LISTS - 1);

        /* Insert the entry into the free list head, check for prot. pool */
        if (MmProtectFreedNonPagedPool)
            MiProtectedPoolInsertList(&MmNonPagedPoolFreeListHead[ix], &FreeEntry->List, TRUE);
        else
            InsertTailList(&MmNonPagedPoolFreeListHead[ix], &FreeEntry->List);
    }

    /* Just a sanity check */
    ASSERT(FreePages != 0);

    /* Get all the pages between our allocation and its end. These will all now become free page chunks. */
    NextEntry = StartingVa;
    LastEntry = (PMMFREE_POOL_ENTRY)((ULONG_PTR)NextEntry + (FreePages << PAGE_SHIFT));
    do
    {
        /* Link back to the parent free entry, and keep going */
        NextEntry->Owner = FreeEntry;
        NextEntry->Signature = MM_FREE_POOL_SIGNATURE;
        NextEntry = (PMMFREE_POOL_ENTRY)((ULONG_PTR)NextEntry + PAGE_SIZE);
    }
    while (NextEntry != LastEntry);

    /* Is freed non paged pool protected? */
    if (MmProtectFreedNonPagedPool)
        /* Protect the freed pool! */
        MiProtectFreeNonPagedPool(FreeEntry, FreeEntry->Size);

    /* We're done, release the lock and let the caller know how much we freed */
    KeReleaseQueuedSpinLock(LockQueueMmNonPagedPoolLock, OldIrql);

    return NumberOfPages;
}

POOL_TYPE
NTAPI
MmDeterminePoolType(
    _In_ PVOID PoolAddress)
{
    /* Use a simple bounds check */
    if (PoolAddress >= MmPagedPoolStart && PoolAddress <= MmPagedPoolEnd)
        return PagedPool;

    if (PoolAddress >= MmNonPagedPoolStart && PoolAddress <= MmNonPagedPoolEnd)
        return NonPagedPool;

    KeBugCheckEx(BAD_POOL_CALLER, 0x42, (ULONG_PTR)PoolAddress, 0, 0);
}

CODE_SEG("INIT")
VOID
NTAPI
MiInitializePoolEvents(VOID)
{
    PFN_NUMBER FreePoolInPages;
    KIRQL OldIrql;

    /* Lock paged pool */
    KeAcquireGuardedMutex(&MmPagedPoolMutex);

    /* Total size of the paged pool minus the allocated size, is free */
    FreePoolInPages = (MmSizeOfPagedPoolInPages - MmPagedPoolInfo.AllocatedPagedPool);

    /* Check the initial state high state */
    if (FreePoolInPages >= MiHighPagedPoolThreshold)
        /* We have plenty of pool */
        KeSetEvent(MiHighPagedPoolEvent, 0, FALSE);
    else
        /* We don't */
        KeClearEvent(MiHighPagedPoolEvent);

    /* Check the initial low state */
    if (FreePoolInPages <= MiLowPagedPoolThreshold)
        /* We're very low in free pool memory */
        KeSetEvent(MiLowPagedPoolEvent, 0, FALSE);
    else
        /* We're not */
        KeClearEvent(MiLowPagedPoolEvent);

    /* Release the paged pool lock */
    KeReleaseGuardedMutex(&MmPagedPoolMutex);

    /* Now it's time for the nonpaged pool lock */
    OldIrql = KeAcquireQueuedSpinLock(LockQueueMmNonPagedPoolLock);

    /* Free pages are the maximum minus what's been allocated */
    FreePoolInPages = (MmMaximumNonPagedPoolInPages - MmAllocatedNonPagedPool);

    /* Check if we have plenty */
    if (FreePoolInPages >= MiHighNonPagedPoolThreshold)
        /* We do, set the event */
        KeSetEvent(MiHighNonPagedPoolEvent, 0, FALSE);
    else
        /* We don't, clear the event */
        KeClearEvent(MiHighNonPagedPoolEvent);

    /* Check if we have very little */
    if (FreePoolInPages <= MiLowNonPagedPoolThreshold)
        /* We do, set the event */
        KeSetEvent(MiLowNonPagedPoolEvent, 0, FALSE);
    else
        /* We don't, clear it */
        KeClearEvent(MiLowNonPagedPoolEvent);

    /* We're done, release the nonpaged pool lock */
    KeReleaseQueuedSpinLock(LockQueueMmNonPagedPoolLock, OldIrql);
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MiInitializeSessionPool(VOID)
{
    PMM_PAGED_POOL_INFO PagedPoolInfo;
    PMM_SESSION_SPACE SessionGlobal;
    PPOOL_DESCRIPTOR PoolDescriptor;
    PMMPDE Pde;
    PMMPDE LastPde;
    PMMPTE Pte;
    PMMPTE LastPte;
    PFN_NUMBER PageFrameIndex;
    PFN_NUMBER PdeCount;
    ULONG BitmapSize;
    ULONG PoolSize;
    ULONG Index;
    NTSTATUS Status;

    DPRINT("MiInitializeSessionPool()\n");
    PAGED_CODE();

    /* Lock session pool */
    SessionGlobal = MmSessionSpace->GlobalVirtualAddress;
    KeInitializeGuardedMutex(&SessionGlobal->PagedPoolMutex);

    /* Setup a valid pool descriptor */
    PoolDescriptor = &MmSessionSpace->PagedPool;
    ExInitializePoolDescriptor(PoolDescriptor, PagedPoolSession, 0, 0, &SessionGlobal->PagedPoolMutex);

    /* Setup the pool addresses */
    MmSessionSpace->PagedPoolStart = (PVOID)MiSessionPoolStart;
    MmSessionSpace->PagedPoolEnd = (PVOID)((ULONG_PTR)MiSessionPoolEnd - 1);

    DPRINT1("MiInitializeSessionPool: Start %p, End %p\n", MmSessionSpace->PagedPoolStart, MmSessionSpace->PagedPoolEnd);

    /* Reset all the counters */
    PagedPoolInfo = &MmSessionSpace->PagedPoolInfo;
    PagedPoolInfo->PagedPoolCommit = 0;
    PagedPoolInfo->PagedPoolHint = 0;
    PagedPoolInfo->AllocatedPagedPool = 0;

    /* Compute PDE and PTE addresses */
    Pde = MiAddressToPde(MmSessionSpace->PagedPoolStart);
    Pte = MiAddressToPte(MmSessionSpace->PagedPoolStart);
    LastPde = MiAddressToPde(MmSessionSpace->PagedPoolEnd);
    LastPte = MiAddressToPte(MmSessionSpace->PagedPoolEnd);

    /* Write them down */
    MmSessionSpace->PagedPoolBasePde = Pde;

    PagedPoolInfo->FirstPteForPagedPool = Pte;
    PagedPoolInfo->LastPteForPagedPool = LastPte;
    PagedPoolInfo->NextPdeForPagedPoolExpansion = Pde + 1;

    /* Zero the PDEs */
    PdeCount = LastPde - Pde;
    RtlZeroMemory(Pde, ((PdeCount + 1) * sizeof(MMPTE)));

    /* Initialize the PFN for the PDE */
    Status = MiInitializeAndChargePfn(&PageFrameIndex, Pde, MmSessionSpace->SessionPageDirectoryIndex, TRUE);
    ASSERT(NT_SUCCESS(Status) == TRUE);

  #ifndef _M_AMD64 // FIXME
    /* Initialize the first page table */
    Index = (MiAddressToPdeOffset(MmSessionSpace->PagedPoolStart) - MiAddressToPdeOffset(MmSessionBase));
    ASSERT(MmSessionSpace->PageTables[Index].u.Long == 0);
    MmSessionSpace->PageTables[Index] = *Pde;
  #endif

    /* Bump up counters */
    InterlockedIncrementSizeT(&MmSessionSpace->NonPageablePages);
    InterlockedIncrementSizeT(&MmSessionSpace->CommittedPages);

    /* Compute the size of the pool in pages, and of the bitmap for it */
    PoolSize = MmSessionPoolSize >> PAGE_SHIFT;
    BitmapSize = (sizeof(RTL_BITMAP) + ((PoolSize + (0x20 - 1)) / 0x20) * sizeof(ULONG));

    /* Allocate and initialize the bitmap to track allocations */
    PagedPoolInfo->PagedPoolAllocationMap = ExAllocatePoolWithTag(NonPagedPool, BitmapSize, TAG_MM);
    ASSERT(PagedPoolInfo->PagedPoolAllocationMap != NULL);

    RtlInitializeBitMap(PagedPoolInfo->PagedPoolAllocationMap, (PULONG)(PagedPoolInfo->PagedPoolAllocationMap + 1), PoolSize);

    /* Set all bits, but clear the first page table's worth */
    RtlSetAllBits(PagedPoolInfo->PagedPoolAllocationMap);
    RtlClearBits(PagedPoolInfo->PagedPoolAllocationMap, 0, PTE_PER_PAGE);

    /* Allocate and initialize the bitmap to track free space */
    PagedPoolInfo->EndOfPagedPoolBitmap = ExAllocatePoolWithTag(NonPagedPool, BitmapSize, TAG_MM);
    ASSERT(PagedPoolInfo->EndOfPagedPoolBitmap != NULL);

    RtlInitializeBitMap(PagedPoolInfo->EndOfPagedPoolBitmap, (PULONG)(PagedPoolInfo->EndOfPagedPoolBitmap + 1), PoolSize);

    /* Clear all the bits and return success */
    RtlClearAllBits(PagedPoolInfo->EndOfPagedPoolBitmap);

    return STATUS_SUCCESS;
}

/* PUBLIC FUNCTIONS ***********************************************************/

CODE_SEG("PAGE")
PVOID
NTAPI
MmAllocateMappingAddress(
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG PoolTag)
{
    PMMPTE Pte;
    PVOID Va;
    PVOID CallersCaller;
    PVOID CallersAddress;
    ULONG NumberOfPtes;
    SIZE_T Pages;

    DPRINT("MmAllocateMappingAddress: NumberOfBytes %X, PoolTag %X\n", NumberOfBytes, PoolTag);

    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (!NumberOfBytes)
    {
        RtlGetCallersAddress(&CallersAddress, &CallersCaller);

        DPRINT1("KeBugCheckEx()\n");ASSERT(FALSE);
        KeBugCheckEx(0xDA, 0x100, 0, PoolTag, (ULONG_PTR)CallersAddress);
    }

    if (!PoolTag)
    {
        DPRINT1("MmAllocateMappingAddress: NumberOfBytes %X, PoolTag %X\n", NumberOfBytes, PoolTag);
        return NULL;
    }

    Pages = ((NumberOfBytes + (PAGE_SIZE - 1)) / PAGE_SIZE);
    NumberOfPtes = (Pages + 2);

    Pte = MiReserveSystemPtes(NumberOfPtes, 0);
    if (!Pte)
    {
        DPRINT1("MmAllocateMappingAddress: NumberOfBytes %X, PoolTag %X\n", NumberOfBytes, PoolTag);
        return NULL;
    }

    Pte[0].u.Long = (NumberOfPtes * 2);
    Pte[1].u.Long = (PoolTag & ~1);

    RtlZeroMemory(&Pte[2], (Pages * 4));

    Va = MiPteToAddress(&Pte[2]);

    return Va;
}

CODE_SEG("PAGE")
VOID
NTAPI
MmFreeMappingAddress(
    _In_ PVOID BaseAddress,
    _In_ ULONG PoolTag)
{
    UNIMPLEMENTED_DBGBREAK();
}

/* EOF */
