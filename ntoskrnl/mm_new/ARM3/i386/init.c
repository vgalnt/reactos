
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>
#include <mm_new/ARM3/miarm.h>

/* GLOBALS ********************************************************************/

MMPTE MmPteGlobal = {{ 0 }};

/* FIXME: These should be PTE_GLOBAL */
MMPDE ValidKernelPde = {{ PTE_VALID | PTE_READWRITE | PTE_DIRTY | PTE_ACCESSED }};
MMPTE ValidKernelPte = {{ PTE_VALID | PTE_READWRITE | PTE_DIRTY | PTE_ACCESSED }};

/* The same, but for local pages */
MMPDE ValidKernelPdeLocal = {{ PTE_VALID | PTE_READWRITE | PTE_DIRTY | PTE_ACCESSED }};
MMPTE ValidKernelPteLocal = {{ PTE_VALID | PTE_READWRITE | PTE_DIRTY | PTE_ACCESSED }};

MMPDE ValidPdePde = {{ PTE_VALID | PTE_READWRITE | PTE_DIRTY | PTE_ACCESSED }};
MMPTE ValidPtePte = {{ PTE_VALID | PTE_READWRITE | PTE_DIRTY | PTE_ACCESSED }};

/* Template PDE for a demand-zero page */
MMPDE DemandZeroPde  = {{ (MM_READWRITE << MM_PTE_SOFTWARE_PROTECTION_BITS) }};
MMPTE DemandZeroPte  = {{ (MM_READWRITE << MM_PTE_SOFTWARE_PROTECTION_BITS) }};

/* Template PTE for prototype page */
MMPTE PrototypePte = {{(MM_READWRITE << MM_PTE_SOFTWARE_PROTECTION_BITS) | PTE_PROTOTYPE | (MI_PTE_LOOKUP_NEEDED << PAGE_SHIFT)}};

/* Template PTE for decommited page */
MMPTE MmDecommittedPte = {{MM_DECOMMIT << MM_PTE_SOFTWARE_PROTECTION_BITS}};

MMPTE NoAccessPte = {{ MM_PROTECT_SPECIAL << MM_PTE_SOFTWARE_PROTECTION_BITS }};

extern PMMCOLOR_TABLES MmFreePagesByColor[FreePageList + 1];
extern PMEMORY_ALLOCATION_DESCRIPTOR MxFreeDescriptor;
extern MEMORY_ALLOCATION_DESCRIPTOR MxOldFreeDescriptor;
extern PMM_SESSION_SPACE MmSessionSpace;
extern PMMPTE MiSessionImagePteStart;
extern PMMPTE MiSessionImagePteEnd;
extern PMMPTE MiSessionBasePte;
extern PMMPTE MiSessionLastPte;
extern PVOID MmSessionBase;
extern PVOID MiSessionImageStart;
extern PVOID MiSessionImageEnd;
extern PVOID MiSessionPoolEnd;     // 0xBE000000
extern PVOID MiSessionPoolStart;   // 0xBD000000
extern PVOID MiSessionViewStart;   // 0xBE000000
extern PVOID MiSessionSpaceWs;
extern PVOID MiSessionSpaceEnd;
extern SIZE_T MmSessionSize;
extern SIZE_T MmSessionImageSize;
extern SIZE_T MmSessionViewSize;
extern SIZE_T MmSessionPoolSize;
extern SIZE_T MmSystemViewSize;
extern PVOID MiSystemViewStart;
extern PFN_NUMBER MiNumberOfFreePages;
extern PVOID MmNonPagedPoolStart;
extern SIZE_T MmMaximumNonPagedPoolInBytes;
extern SIZE_T MmSizeOfNonPagedPoolInBytes;
extern ULONG MmNumberOfSystemPtes;
extern PVOID MmNonPagedSystemStart;
extern PVOID MmNonPagedPoolExpansionStart;
extern SIZE_T MmSizeOfPagedPoolInBytes;
extern ULONG_PTR MxPfnAllocation;
extern PFN_NUMBER MmMaximumNonPagedPoolInPages;
extern PMMPTE MmFirstReservedMappingPte;
extern PMMPTE MmLastReservedMappingPte;
extern PMMPTE MiFirstReservedZeroingPte;
extern PMMWSL MmWorkingSetList;
extern PMMWSL MmSystemCacheWorkingSetList;
extern ULONG MiLastVadBit;
extern ULONG MmSecondaryColors;
extern PVOID MmHyperSpaceEnd;
extern SIZE_T MmMinimumNonPagedPoolSize;
extern ULONG MmMinAdditionNonPagedPoolPerMb;
extern ULONG MmMaximumNonPagedPoolPercent;
extern SIZE_T MmDefaultMaximumNonPagedPool;
extern ULONG MmMaxAdditionNonPagedPoolPerMb;
extern PFN_NUMBER MmLowestPhysicalPage;

/* FUNCTIONS ******************************************************************/

//INIT_FUNCTION
VOID
NTAPI
MiInitializeSessionSpaceLayout(VOID)
{
    /* Set the size of session view, pool, and image */
    MmSessionSize = MI_SESSION_SIZE;
    MmSessionViewSize = MI_SESSION_VIEW_SIZE;
    MmSessionPoolSize = MI_SESSION_POOL_SIZE;
    MmSessionImageSize = MI_SESSION_IMAGE_SIZE;

    /* Set the size of system view */
    MmSystemViewSize = MI_SYSTEM_VIEW_SIZE;

    /* This is where it all ends */
    MiSessionImageEnd = (PVOID)PTE_BASE;

    /* This is where we will load Win32k.sys and the video driver */
    MiSessionImageStart = (PVOID)((ULONG_PTR)MiSessionImageEnd - MmSessionImageSize);

    /* So the view starts right below the session working set (itself below the image area) */
    MiSessionViewStart = (PVOID)((ULONG_PTR)MiSessionImageEnd -
                                 MmSessionImageSize -
                                 MI_SESSION_WORKING_SET_SIZE -
                                 MmSessionViewSize);
    /* Session pool follows */
    MiSessionPoolEnd = MiSessionViewStart;
    MiSessionPoolStart = (PVOID)((ULONG_PTR)MiSessionPoolEnd - MmSessionPoolSize);

    /* And it all begins here */
    MmSessionBase = MiSessionPoolStart;

    /* Sanity check that our math is correct */
    ASSERT((ULONG_PTR)MmSessionBase + MmSessionSize == PTE_BASE);

    /* Session space ends wherever image session space ends */
    MiSessionSpaceEnd = MiSessionImageEnd;

    /* System view space ends at session space, so now that we know where this is,
       we can compute the base address of system view space itself.
    */
    MiSystemViewStart = (PVOID)((ULONG_PTR)MmSessionBase - MmSystemViewSize);

    /* Compute the PTE addresses for all the addresses we carved out */
    MiSessionImagePteStart = MiAddressToPte(MiSessionImageStart);
    MiSessionImagePteEnd = MiAddressToPte(MiSessionImageEnd);
    MiSessionBasePte = MiAddressToPte(MmSessionBase);
    MiSessionSpaceWs = (PVOID)((ULONG_PTR)MiSessionViewStart + MmSessionViewSize);
    MiSessionLastPte = MiAddressToPte(MiSessionSpaceEnd);

    /* Initialize session space */
    MmSessionSpace = (PMM_SESSION_SPACE)((ULONG_PTR)MmSessionBase +
                                         MmSessionSize -
                                         MmSessionImageSize -
                                         MM_ALLOCATION_GRANULARITY);
}

//INIT_FUNCTION
VOID
NTAPI
MiComputeNonPagedPoolVa(
    _In_ ULONG FreePages)
{
    PFN_NUMBER PoolPages;

    /* Check if this is a machine with less than 256MB of RAM, and no overide */
    if ((MmNumberOfPhysicalPages <= MI_MIN_PAGES_FOR_NONPAGED_POOL_TUNING) &&
        !(MmSizeOfNonPagedPoolInBytes))
    {
        /* Force the non paged pool to be 2MB so we can reduce RAM usage */
        MmSizeOfNonPagedPoolInBytes = (2 * _1MB);
    }

    /* Hyperspace ends here */
    MmHyperSpaceEnd = (PVOID)((ULONG_PTR)MmSystemCacheWorkingSetList - 1);

    /* Check if the user gave a ridicuously large nonpaged pool RAM size */
    if ((MmSizeOfNonPagedPoolInBytes >> PAGE_SHIFT) > (FreePages * 7 / 8))
        /* More than 7/8ths of RAM was dedicated to nonpaged pool, ignore! */
        MmSizeOfNonPagedPoolInBytes = 0;

    /* Check if no registry setting was set, or if the setting was too low */
    if (MmSizeOfNonPagedPoolInBytes < MmMinimumNonPagedPoolSize)
    {
        /* Start with the minimum (256 KB) and add 32 KB for each MB above 4 */
        MmSizeOfNonPagedPoolInBytes = MmMinimumNonPagedPoolSize;
        MmSizeOfNonPagedPoolInBytes += ((FreePages - 1024) / 256 * MmMinAdditionNonPagedPoolPerMb);
    }

    /* Check if the registy setting or our dynamic calculation was too high */
    if (MmSizeOfNonPagedPoolInBytes > MI_MAX_INIT_NONPAGED_POOL_SIZE)
        /* Set it to the maximum */
        MmSizeOfNonPagedPoolInBytes = MI_MAX_INIT_NONPAGED_POOL_SIZE;

    /* Check if a percentage cap was set through the registry */
    if (MmMaximumNonPagedPoolPercent)
        UNIMPLEMENTED;

    /* Page-align the nonpaged pool size */
    MmSizeOfNonPagedPoolInBytes &= ~(PAGE_SIZE - 1);

    /* Now, check if there was a registry size for the maximum size */
    if (!MmMaximumNonPagedPoolInBytes)
    {
        /* Start with the default (1MB) */
        MmMaximumNonPagedPoolInBytes = MmDefaultMaximumNonPagedPool;

        /* Add space for PFN database */
        MmMaximumNonPagedPoolInBytes += (ULONG)PAGE_ALIGN((MmHighestPhysicalPage +  1) * sizeof(MMPFN));

        /* Check if the machine has more than 512MB of free RAM */
        if (FreePages >= 0x1F000)
        {
            /* Add 200KB for each MB above 4 */
            MmMaximumNonPagedPoolInBytes += ((FreePages - 1024) / 256 * (MmMaxAdditionNonPagedPoolPerMb / 2));

            if (MmMaximumNonPagedPoolInBytes < MI_MAX_NONPAGED_POOL_SIZE)
                /* Make it at least 128MB since this machine has a lot of RAM */
                MmMaximumNonPagedPoolInBytes = MI_MAX_NONPAGED_POOL_SIZE;
        }
        else
        {
            /* Add 400KB for each MB above 4 */
            MmMaximumNonPagedPoolInBytes += ((FreePages - 1024) / 256 * MmMaxAdditionNonPagedPoolPerMb);
        }
    }

    /* Make sure there's at least 16 pages + the PFN available for expansion */
    PoolPages = (MmSizeOfNonPagedPoolInBytes + (16 * PAGE_SIZE));
    PoolPages += ((ULONG)PAGE_ALIGN(MmHighestPhysicalPage + 1) * sizeof(MMPFN));

    if (MmMaximumNonPagedPoolInBytes < PoolPages)
        /* The maximum should be at least high enough to cover all the above */
        MmMaximumNonPagedPoolInBytes = PoolPages;

    /* Systems with 2GB of kernel address space get double the size */
    PoolPages = (MI_MAX_NONPAGED_POOL_SIZE * 2);

    /* On the other hand, make sure that PFN + nonpaged pool doesn't get too big */
    if (MmMaximumNonPagedPoolInBytes > PoolPages)
        /* Trim it down to the maximum architectural limit (256MB) */
        MmMaximumNonPagedPoolInBytes = PoolPages;

    /* Check if this is a system with > 128MB of non paged pool */
    if (MmMaximumNonPagedPoolInBytes <= MI_MAX_NONPAGED_POOL_SIZE)
        return;

    /* Check if the initial size is less than the extra 128MB boost */
    if (MmSizeOfNonPagedPoolInBytes >= (MmMaximumNonPagedPoolInBytes - MI_MAX_NONPAGED_POOL_SIZE))
        return;

    /* FIXME: Should check if the initial pool can be expanded */

    /* Assume no expansion possible, check ift he maximum is too large */
    if (MmMaximumNonPagedPoolInBytes > (MmSizeOfNonPagedPoolInBytes + MI_MAX_NONPAGED_POOL_SIZE))
        /* Set it to the initial value plus the boost */
        MmMaximumNonPagedPoolInBytes = (MmSizeOfNonPagedPoolInBytes + MI_MAX_NONPAGED_POOL_SIZE);
}

//INIT_FUNCTION
VOID
NTAPI
MiMapPfnDatabase(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    PMEMORY_ALLOCATION_DESCRIPTOR MdBlock;
    MMPTE TempPte = ValidKernelPte;
    PMMPTE Pte;
    PMMPTE LastPte;
    PFN_NUMBER FreePage;
    PFN_NUMBER FreePageCount;
    PFN_NUMBER PagesLeft;
    PFN_NUMBER BasePage;
    PFN_NUMBER PageCount;
    PLIST_ENTRY NextEntry;

    /* Get current page data, since we won't be using MxGetNextPage as it would corrupt our state */
    FreePage = MxFreeDescriptor->BasePage;
    FreePageCount = MxFreeDescriptor->PageCount;
    PagesLeft = 0;

    /* Loop the memory descriptors */
    for (NextEntry = LoaderBlock->MemoryDescriptorListHead.Flink;
         NextEntry != &LoaderBlock->MemoryDescriptorListHead;
         NextEntry = MdBlock->ListEntry.Flink)
    {
        /* Get the descriptor */
        MdBlock = CONTAINING_RECORD(NextEntry, MEMORY_ALLOCATION_DESCRIPTOR, ListEntry);

        if ((MdBlock->MemoryType == LoaderFirmwarePermanent) ||
            (MdBlock->MemoryType == LoaderBBTMemory) ||
            (MdBlock->MemoryType == LoaderSpecialMemory))
        {
            /* These pages are not part of the PFN database */
            NextEntry = MdBlock->ListEntry.Flink;
            continue;
        }

        /* Next, check if this is our special free descriptor we've found */
        if (MdBlock == MxFreeDescriptor)
        {
            /* Use the real numbers instead */
            BasePage = MxOldFreeDescriptor.BasePage;
            PageCount = MxOldFreeDescriptor.PageCount;
        }
        else
        {
            /* Use the descriptor's numbers */
            BasePage = MdBlock->BasePage;
            PageCount = MdBlock->PageCount;
        }

        /* Get the PTEs for this range */
        Pte = MiAddressToPte(&MmPfnDatabase[BasePage]);
        LastPte = MiAddressToPte(((ULONG_PTR)&MmPfnDatabase[BasePage + PageCount]) - 1);

        DPRINT("MiMapPfnDatabase: [%02X] Base %X, Count %X\n", MdBlock->MemoryType, BasePage, PageCount);

        /* Loop them */
        for (; Pte <= LastPte; Pte++)
        {
            /* We'll only touch PTEs that aren't already valid */
            if (Pte->u.Hard.Valid)
                continue;

            /* Use the next free page */
            TempPte.u.Hard.PageFrameNumber = FreePage;
            ASSERT(FreePageCount != 0);

            /* Consume free pages */
            FreePage++;
            FreePageCount--;

            if (!FreePageCount)
            {
                /* Out of memory */
                KeBugCheckEx(INSTALL_MORE_MEMORY,
                             MmNumberOfPhysicalPages,
                             FreePageCount,
                             MxOldFreeDescriptor.PageCount,
                             1);
            }

            /* Write out this PTE */
            PagesLeft++;
            MI_WRITE_VALID_PTE(Pte, TempPte);

            /* Zero this page */
            RtlZeroMemory(MiPteToAddress(Pte), PAGE_SIZE);
        }
    }

    /* Now update the free descriptors to consume the pages we used up during the PFN allocation loop */
    MxFreeDescriptor->BasePage = FreePage;
    MxFreeDescriptor->PageCount = FreePageCount;
}

//INIT_FUNCTION
VOID
NTAPI
MiInitializeColorTables(VOID)
{
    MMPTE TempPte = ValidKernelPte;
    PMMPTE Pte;
    PMMPTE LastPte;
    ULONG ix;

    /* The color table starts after the ARM3 PFN database */
    MmFreePagesByColor[0] = (PMMCOLOR_TABLES)&MmPfnDatabase[MmHighestPhysicalPage + 1];

    /* Loop the PTEs. We have two color tables for each secondary color */
    Pte = MiAddressToPte(&MmFreePagesByColor[0][0]);
    LastPte = MiAddressToPte((ULONG_PTR)MmFreePagesByColor[0] + (MmSecondaryColors * 2 * sizeof(MMCOLOR_TABLES)) - 1);

    for (; Pte <= LastPte; Pte++)
    {
        /* Check for valid PTE */
        if (Pte->u.Hard.Valid)
            continue;

        /* Get a page and map it */
        TempPte.u.Hard.PageFrameNumber = MxGetNextPage(1);
        MI_WRITE_VALID_PTE(Pte, TempPte);

        /* Zero out the page */
        RtlZeroMemory(MiPteToAddress(Pte), PAGE_SIZE);
    }

    /* Now set the address of the next list, right after this one */
    MmFreePagesByColor[1] = &MmFreePagesByColor[0][MmSecondaryColors];

    /* Now loop the lists to set them up */
    for (ix = 0; ix < MmSecondaryColors; ix++)
    {
        /* Set both free and zero lists for each color */
        MmFreePagesByColor[ZeroedPageList][ix].Flink = LIST_HEAD;
        MmFreePagesByColor[ZeroedPageList][ix].Blink = (PVOID)LIST_HEAD;
        MmFreePagesByColor[ZeroedPageList][ix].Count = 0;

        MmFreePagesByColor[FreePageList][ix].Flink = LIST_HEAD;
        MmFreePagesByColor[FreePageList][ix].Blink = (PVOID)LIST_HEAD;
        MmFreePagesByColor[FreePageList][ix].Count = 0;
    }
}

//INIT_FUNCTION
BOOLEAN
NTAPI
MiIsRegularMemory(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock,
    _In_ PFN_NUMBER Pfn)
{
    PLIST_ENTRY NextEntry;
    PMEMORY_ALLOCATION_DESCRIPTOR MdBlock;

    /* Loop the memory descriptors */
    
    for (NextEntry = LoaderBlock->MemoryDescriptorListHead.Flink;
         NextEntry != &LoaderBlock->MemoryDescriptorListHead;
         NextEntry = MdBlock->ListEntry.Flink)
    {
        /* Get the memory descriptor */
        MdBlock = CONTAINING_RECORD(NextEntry, MEMORY_ALLOCATION_DESCRIPTOR, ListEntry);

        /* Check if this PFN could be part of the block */
        if (Pfn < (MdBlock->BasePage))
            /* Blocks are ordered, so if it's not here, it doesn't exist */
            break;

        /* Check if it really is part of the block */
        if (Pfn < (MdBlock->BasePage + MdBlock->PageCount))
        {
            /* Check if the block is actually memory we don't map */
            if ((MdBlock->MemoryType == LoaderFirmwarePermanent) ||
                (MdBlock->MemoryType == LoaderBBTMemory) ||
                (MdBlock->MemoryType == LoaderSpecialMemory))
            {
                /* We don't need PFN database entries for this memory */
                break;
            }

            /* This is memory we want to map */
            return TRUE;
        }
    }

    /* Check if this PFN is actually from our free memory descriptor */
    if ((Pfn >= MxOldFreeDescriptor.BasePage) &&
        (Pfn < MxOldFreeDescriptor.BasePage + MxOldFreeDescriptor.PageCount))
    {
        /* We use these pages for initial mappings, so we do want to count them */
        return TRUE;
    }

    /* Otherwise this isn't memory that we describe or care about */
    return FALSE;
}

//INIT_FUNCTION
VOID
NTAPI
MiBuildPfnDatabaseFromPages(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    ULONG_PTR BaseAddress = 0;
    PFN_NUMBER PageFrameIndex;
    PFN_NUMBER StartupPdIndex;
    PFN_NUMBER PtePageIndex;
    PMMPDE Pde;
    PMMPTE Pte;
    PMMPFN Pfn1;
    PMMPFN Pfn2;
    ULONG Count;
    ULONG ix;
    ULONG jx;

    /* PFN of the startup page directory */
    StartupPdIndex = PFN_FROM_PTE(MiAddressToPde(PDE_BASE));

    /* Start with the first PDE and scan them all */
    Pde = MiAddressToPde(NULL);
    Count = (PD_COUNT * PDE_PER_PAGE);

    for (ix = 0; ix < Count; ix++, Pde++)
    {
        /* Check for valid PDE */
        if (Pde->u.Hard.Valid != 1)
        {
            /* Next PDE mapped address */
            BaseAddress += PDE_MAPPED_VA;
            continue;
        }

        /* Get the PFN from it */
        PageFrameIndex = PFN_FROM_PTE(Pde);

        /* Do we want a PFN entry for this page? */
        if (MiIsRegularMemory(LoaderBlock, PageFrameIndex))
        {
            /* Yes we do, set it up */
            Pfn1 = MiGetPfnEntry(PageFrameIndex);
            Pfn1->u4.PteFrame = StartupPdIndex;
            Pfn1->PteAddress = (PMMPTE)Pde;
            Pfn1->u2.ShareCount++;
            Pfn1->u3.e2.ReferenceCount = 1;
            Pfn1->u3.e1.PageLocation = ActiveAndValid;
            Pfn1->u3.e1.CacheAttribute = MiNonCached;
          #if MI_TRACE_PFNS
            Pfn1->PfnUsage = MI_USAGE_INIT_MEMORY;
            memcpy(Pfn1->ProcessName, "Initial PDE", 16);
          #endif
        }
        else
        {
            /* No PFN entry */
            Pfn1 = NULL;
        }

        /* Now get the PTE and scan the pages */
        Pte = MiAddressToPte(BaseAddress);

        for (jx = 0; jx < PTE_PER_PAGE; jx++)
        {
            /* Check for a valid PTE */
            if (Pte->u.Hard.Valid != 1)
                goto NextPTE;

            /* Increase the shared count of the PFN entry for the PDE */
            ASSERT(Pfn1 != NULL);
            Pfn1->u2.ShareCount++;

            /* Now check if the PTE is valid memory too */
            PtePageIndex = PFN_FROM_PTE(Pte);

            if (!MiIsRegularMemory(LoaderBlock, PtePageIndex))
                goto NextPTE;

            /* Only add pages above the end of system code or pages that are part of nonpaged pool */
            if ((BaseAddress >= 0xA0000000) ||
                ((BaseAddress >= (ULONG_PTR)MmNonPagedPoolStart) &&
                 (BaseAddress < (ULONG_PTR)MmNonPagedPoolStart + MmSizeOfNonPagedPoolInBytes)))
            {
                /* Get the PFN entry and make sure it too is valid */
                Pfn2 = MiGetPfnEntry(PtePageIndex);

                if ((MmIsAddressValid(Pfn2)) && (MmIsAddressValid(Pfn2 + 1)))
                {
                    /* Setup the PFN entry */
                    Pfn2->u4.PteFrame = PageFrameIndex;
                    Pfn2->PteAddress = Pte;
                    Pfn2->u2.ShareCount++;
                    Pfn2->u3.e2.ReferenceCount = 1;
                    Pfn2->u3.e1.PageLocation = ActiveAndValid;
                    Pfn2->u3.e1.CacheAttribute = MiNonCached;
                  #if MI_TRACE_PFNS
                    Pfn2->PfnUsage = MI_USAGE_INIT_MEMORY;
                    memcpy(Pfn1->ProcessName, "Initial PTE", 16);
                  #endif
                }
            }
NextPTE:
            Pte++;
            BaseAddress += PAGE_SIZE;
        }
    }
}

//INIT_FUNCTION
VOID
NTAPI
MiBuildPfnDatabaseZeroPage(VOID)
{
    PMMPFN Pfn;
    PMMPDE Pde;

    if (MmLowestPhysicalPage)
        return;

    /* Grab the lowest page and check if it has no real references */
    Pfn = MiGetPfnEntry(MmLowestPhysicalPage);

    if (Pfn->u3.e2.ReferenceCount)
        return;

    /* Make it a bogus page to catch errors */
    Pde = MiAddressToPde(0xFFFFFFFF);
    Pfn->u4.PteFrame = PFN_FROM_PTE(Pde);
    Pfn->PteAddress = (PMMPTE)Pde;
    Pfn->u2.ShareCount++;
    Pfn->u3.e2.ReferenceCount = 0xFFF0;
    Pfn->u3.e1.PageLocation = ActiveAndValid;
    Pfn->u3.e1.CacheAttribute = MiNonCached;
}

//INIT_FUNCTION
VOID
NTAPI
MiBuildPfnDatabaseFromLoaderBlock(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    PMEMORY_ALLOCATION_DESCRIPTOR MdBlock;
    PLIST_ENTRY NextEntry;
    PFN_NUMBER PageCount = 0;
    PFN_NUMBER PageFrameIndex;
    PMMPFN Pfn;
    PMMPTE Pte;
    PMMPDE Pde;
    KIRQL OldIrql;

    /* Now loop through the descriptors */
    for (NextEntry = LoaderBlock->MemoryDescriptorListHead.Flink;
         NextEntry != &LoaderBlock->MemoryDescriptorListHead;
         NextEntry = MdBlock->ListEntry.Flink)
    {
        /* Get the current descriptor */
        MdBlock = CONTAINING_RECORD(NextEntry, MEMORY_ALLOCATION_DESCRIPTOR, ListEntry);

        /* Read its data */
        PageCount = MdBlock->PageCount;
        PageFrameIndex = MdBlock->BasePage;

        /* Don't allow memory above what the PFN database is mapping */
        if (PageFrameIndex > MmHighestPhysicalPage)
            /* Since they are ordered, everything past here will be larger */
            break;

        /* On the other hand, the end page might be higher up... */
        if ((PageFrameIndex + PageCount) > (MmHighestPhysicalPage + 1))
        {
            /* In which case we'll trim the descriptor to go as high as we can */
            PageCount = (MmHighestPhysicalPage + 1 - PageFrameIndex);
            MdBlock->PageCount = PageCount;

            /* But if there's nothing left to trim, we got too high, so quit */
            if (!PageCount)
                break;
        }

        /* Now check the descriptor type */
        switch (MdBlock->MemoryType)
        {
            /* Check for bad RAM */
            case LoaderBad:
                DPRINT1("You either have specified /BURNMEMORY or damaged RAM modules.\n");
                break;

            /* Check for free RAM */
            case LoaderFree:
            case LoaderLoadedProgram:
            case LoaderFirmwareTemporary:
            case LoaderOsloaderStack:
            {
                /* Get the last page of this descriptor. Note we loop backwards */
                PageFrameIndex += (PageCount - 1);
                Pfn = MiGetPfnEntry(PageFrameIndex);

                /* Lock the PFN Database */
                OldIrql = MiLockPfnDb(APC_LEVEL);

                while (PageCount--)
                {
                    /* If the page really has no references, mark it as free */
                    if (!Pfn->u3.e2.ReferenceCount)
                    {
                        /* Add it to the free list */
                        Pfn->u3.e1.CacheAttribute = MiNonCached;
                        MiInsertPageInFreeList(PageFrameIndex);
                    }

                    /* Go to the next page */
                    Pfn--;
                    PageFrameIndex--;
                }

                /* Release PFN database */
                MiUnlockPfnDb(OldIrql, APC_LEVEL);

                /* Done with this block */
                break;
            }
            /* Check for pages that are invisible to us */
            case LoaderFirmwarePermanent:
            case LoaderSpecialMemory:
            case LoaderBBTMemory:
                /* And skip them */
                break;

            default:
            {
                /* Map these pages with the KSEG0 mapping that adds 0x80000000 */
                Pte = MiAddressToPte(KSEG0_BASE + (PageFrameIndex << PAGE_SHIFT));

                Pfn = MiGetPfnEntry(PageFrameIndex);
                while (PageCount--)
                {
                    /* Check if the page is really unused */
                    Pde = MiAddressToPde(KSEG0_BASE + (PageFrameIndex << PAGE_SHIFT));

                    if (!Pfn->u3.e2.ReferenceCount)
                    {
                        /* Mark it as being in-use */
                        Pfn->u4.PteFrame = PFN_FROM_PTE(Pde);
                        Pfn->PteAddress = Pte;
                        Pfn->u2.ShareCount++;
                        Pfn->u3.e2.ReferenceCount = 1;
                        Pfn->u3.e1.PageLocation = ActiveAndValid;
                        Pfn->u3.e1.CacheAttribute = MiNonCached;
                      #if MI_TRACE_PFNS
                        Pfn->PfnUsage = MI_USAGE_BOOT_DRIVER;
                      #endif

                        /* Check for RAM disk page */
                        if (MdBlock->MemoryType == LoaderXIPRom)
                        {
                            /* Make it a pseudo-I/O ROM mapping */
                            Pfn->u1.Flink = 0;
                            Pfn->u2.ShareCount = 0;
                            Pfn->u3.e2.ReferenceCount = 0;
                            Pfn->u3.e1.PageLocation = 0;
                            Pfn->u3.e1.Rom = 1;
                            Pfn->u4.InPageError = 0;
                            Pfn->u3.e1.PrototypePte = 1;
                        }
                    }

                    /* Advance page structures */
                    Pfn++;
                    PageFrameIndex++;
                    Pte++;
                }

                break;
            }
        }
    }
}

//INIT_FUNCTION
VOID
NTAPI
MiBuildPfnDatabaseSelf(VOID)
{
    PMMPTE Pte;
    PMMPTE LastPte;
    PMMPFN Pfn;

    /* Loop the PFN database page */
    Pte = MiAddressToPte(MiGetPfnEntry(MmLowestPhysicalPage));
    LastPte = MiAddressToPte(MiGetPfnEntry(MmHighestPhysicalPage));

    for (; Pte <= LastPte; Pte++)
    {
        /* Make sure the page is valid */
        if (Pte->u.Hard.Valid != 1)
            continue;

        /* Get the PFN entry and just mark it referenced */
        Pfn = MiGetPfnEntry(Pte->u.Hard.PageFrameNumber);
        Pfn->u2.ShareCount = 1;
        Pfn->u3.e2.ReferenceCount = 1;
      #if MI_TRACE_PFNS
        Pfn->PfnUsage = MI_USAGE_PFN_DATABASE;
      #endif
    }
}

//INIT_FUNCTION
VOID
NTAPI
MiInitializePfnDatabase(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    /* Scan memory and start setting up PFN entries */
    MiBuildPfnDatabaseFromPages(LoaderBlock);

    /* Add the zero page */
    MiBuildPfnDatabaseZeroPage();

    /* Scan the loader block and build the rest of the PFN database */
    MiBuildPfnDatabaseFromLoaderBlock(LoaderBlock);

    /* Finally add the pages for the PFN database itself */
    MiBuildPfnDatabaseSelf();
}

//INIT_FUNCTION
NTSTATUS
NTAPI
MiInitMachineDependent(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    PVOID NonPagedPoolExpansionVa;
    PFN_NUMBER PageFrameIndex;
    PMMPTE StartPde;
    PMMPTE EndPde;
    PMMPTE Pte;
    PMMPTE LastPte;
    MMPTE TempPde;
    MMPTE TempPte;
    PMMPFN Pfn;
    SIZE_T NonPagedSystemSize;
    ULONG Flags;
    KIRQL OldIrql;

  #if defined(_GLOBAL_PAGES_ARE_AWESOME_)
    /* Check for global bit */
    if (KeFeatureBits & KF_GLOBAL_PAGE)
    {
        /* Set it on the template PTE and PDE */
        ValidKernelPte.u.Hard.Global = TRUE;
        ValidKernelPde.u.Hard.Global = TRUE;
    }
  #endif

    /* Now templates are ready */
    TempPte = ValidKernelPte;
    TempPde = ValidKernelPde;

    /* Set CR3 for the system process */
    Pte = MiAddressToPde(PDE_BASE);
    PageFrameIndex = (PFN_FROM_PTE(Pte) << PAGE_SHIFT);
    PsGetCurrentProcess()->Pcb.DirectoryTableBase[0] = PageFrameIndex;

    /* Blow away user-mode */
    StartPde = MiAddressToPde(0);
    EndPde = MiAddressToPde(KSEG0_BASE);
    RtlZeroMemory(StartPde, ((EndPde - StartPde) * sizeof(MMPTE)));

    /* Compute non paged pool limits and size */
    MiComputeNonPagedPoolVa(MiNumberOfFreePages);

    /* Now calculate the nonpaged pool expansion VA region */
    MmNonPagedPoolStart = (PVOID)((ULONG_PTR)MmNonPagedPoolEnd - MmMaximumNonPagedPoolInBytes + MmSizeOfNonPagedPoolInBytes);
    MmNonPagedPoolStart = (PVOID)PAGE_ALIGN(MmNonPagedPoolStart);

    DPRINT("NP Pool has been tuned to: %lu bytes and %lu bytes\n",
           MmSizeOfNonPagedPoolInBytes, MmMaximumNonPagedPoolInBytes);

    NonPagedPoolExpansionVa = MmNonPagedPoolStart;

    /* Now calculate the nonpaged system VA region,
       which includes the nonpaged pool expansion (above) and the system PTEs.
       Note that it is then aligned to a PDE boundary (4MB).
    */
    NonPagedSystemSize = ((MmNumberOfSystemPtes + 1) * PAGE_SIZE);
    MmNonPagedSystemStart = (PVOID)((ULONG_PTR)MmNonPagedPoolStart - NonPagedSystemSize);
    MmNonPagedSystemStart = (PVOID)((ULONG_PTR)MmNonPagedSystemStart & ~(PDE_MAPPED_VA - 1));

    /* Don't let it go below the minimum */
    if (MmNonPagedSystemStart < (PVOID)0xEB000000)
    {
        /* This is a hard-coded limit in the Windows NT address space */
        MmNonPagedSystemStart = (PVOID)0xEB000000;

        /* Reduce the amount of system PTEs to reach this point */
        MmNumberOfSystemPtes = ((ULONG_PTR)MmNonPagedPoolStart - (ULONG_PTR)MmNonPagedSystemStart) >> PAGE_SHIFT;
        MmNumberOfSystemPtes--;

        ASSERT(MmNumberOfSystemPtes > 1000);
    }

    /* Check if size of the paged pool is so large that it overflows into nonpaged pool */
    if (MmSizeOfPagedPoolInBytes > ((ULONG_PTR)MmNonPagedSystemStart - (ULONG_PTR)MmPagedPoolStart))
    {
        /* We need some recalculations here */
        DPRINT1("Paged pool is too big!\n");
    }

    /* Normally, the PFN database should start after the loader images.
       This is already the case in ReactOS, but for now we want to co-exist with the old memory manager,
       so we'll create a "Shadow PFN Database" instead, and arbitrarly start it at 0xB0000000.
    */
    MmPfnDatabase = (PVOID)0xB0000000;
    ASSERT(((ULONG_PTR)MmPfnDatabase & (PDE_MAPPED_VA - 1)) == 0);

    /* Non paged pool comes after the PFN database */
    MmNonPagedPoolStart = (PVOID)((ULONG_PTR)MmPfnDatabase + (MxPfnAllocation << PAGE_SHIFT));

    /* Now we actually need to get these many physical pages.
       Nonpaged pool is actually also physically contiguous (but not the expansion)
    */
    PageFrameIndex = MxGetNextPage(MxPfnAllocation + (MmSizeOfNonPagedPoolInBytes >> PAGE_SHIFT));
    ASSERT(PageFrameIndex != 0);

    DPRINT("PFN DB PA PFN begins at: %lx\n", PageFrameIndex);
    DPRINT("NP PA PFN begins at: %lx\n", (PageFrameIndex + MxPfnAllocation));

    /* Convert nonpaged pool size from bytes to pages */
    MmMaximumNonPagedPoolInPages = (MmMaximumNonPagedPoolInBytes >> PAGE_SHIFT);

    /* Now we need some pages to create the page tables
       for the NP system VA which includes system PTEs and expansion NP
    */
    StartPde = MiAddressToPde(MmNonPagedSystemStart);
    EndPde = MiAddressToPde((PVOID)((ULONG_PTR)MmNonPagedPoolEnd - 1));

    while (StartPde <= EndPde)
    {
        /* Get a page */
        TempPde.u.Hard.PageFrameNumber = MxGetNextPage(1);
        MI_WRITE_VALID_PTE(StartPde, TempPde);

        /* Zero out the page table */
        Pte = MiPteToAddress(StartPde);
        RtlZeroMemory(Pte, PAGE_SIZE);

        StartPde++;
    }

    /* Now we need pages for the page tables which will map initial NP */
    StartPde = MiAddressToPde(MmPfnDatabase);
    EndPde = MiAddressToPde((PVOID)((ULONG_PTR)MmNonPagedPoolStart + MmSizeOfNonPagedPoolInBytes - 1));
    while (StartPde <= EndPde)
    {
        /* Get a page */
        TempPde.u.Hard.PageFrameNumber = MxGetNextPage(1);
        MI_WRITE_VALID_PTE(StartPde, TempPde);

        /* Zero out the page table */
        Pte = MiPteToAddress(StartPde);
        RtlZeroMemory(Pte, PAGE_SIZE);

        StartPde++;
    }

    MmSubsectionBase = (ULONG_PTR)MmNonPagedPoolStart;

    /* Now remember where the expansion starts */
    MmNonPagedPoolExpansionStart = NonPagedPoolExpansionVa;

    /* Last step is to actually map the nonpaged pool */
    Pte = MiAddressToPte(MmNonPagedPoolStart);
    LastPte = MiAddressToPte((PVOID)((ULONG_PTR)MmNonPagedPoolStart + MmSizeOfNonPagedPoolInBytes - 1));

    while (Pte <= LastPte)
    {
        /* Use one of our contigous pages */
        TempPte.u.Hard.PageFrameNumber = PageFrameIndex++;
        MI_WRITE_VALID_PTE(Pte++, TempPte);
    }

    /* Sanity check: make sure we have properly defined the system PTE space */
    ASSERT(MiAddressToPte(MmNonPagedSystemStart) < MiAddressToPte(MmNonPagedPoolExpansionStart));

    /* Now go ahead and initialize the nonpaged pool */
    MiInitializeNonPagedPool();
    MiInitializeNonPagedPoolThresholds();

    /* Map the PFN database pages */
    MiMapPfnDatabase(LoaderBlock);

    /* Initialize the color tables */
    MiInitializeColorTables();

    /* Build the PFN Database */
    MiInitializePfnDatabase(LoaderBlock);
    MmInitializeBalancer(MmAvailablePages, 0);

    /* Reset the descriptor back so we can create the correct memory blocks */
    *MxFreeDescriptor = MxOldFreeDescriptor;

    /* Initialize the nonpaged pool */
    InitializePool(NonPagedPool, 0);

    /* We PDE-aligned the nonpaged system start VA, so haul some extra PTEs! */
    Pte = MiAddressToPte(MmNonPagedSystemStart);

    MmNumberOfSystemPtes = (MiAddressToPte(MmNonPagedPoolExpansionStart) - Pte);
    MmNumberOfSystemPtes--;

    DPRINT("Final System PTE count: %lu (%lu bytes)\n", MmNumberOfSystemPtes, MmNumberOfSystemPtes * PAGE_SIZE);

    /* Create the system PTE space */
    MiInitializeSystemPtes(Pte, MmNumberOfSystemPtes, SystemPteSpace);

    /* Get the PDE For hyperspace */
    StartPde = MiAddressToPde(HYPER_SPACE);

    /* Lock PFN database */
    OldIrql = MiLockPfnDb(APC_LEVEL);

    /* Allocate a page for hyperspace and create it */
    MI_SET_USAGE(MI_USAGE_PAGE_TABLE);
    MI_SET_PROCESS2("Kernel");
    PageFrameIndex = MiRemoveAnyPage(0);
    TempPde = ValidKernelPdeLocal;
    TempPde.u.Hard.PageFrameNumber = PageFrameIndex;
    MI_WRITE_VALID_PTE(StartPde, TempPde);

    /* Flush the TLB */
    KeFlushCurrentTb();

    /* Release the lock */
    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    /* Zero out the page table now */
    Pte = MiAddressToPte(HYPER_SPACE);
    RtlZeroMemory(Pte, PAGE_SIZE);

    /* Setup the mapping PTEs */
    MmFirstReservedMappingPte = MiAddressToPte(MI_MAPPING_RANGE_START);
    MmLastReservedMappingPte = MiAddressToPte(MI_MAPPING_RANGE_END);
    MmFirstReservedMappingPte->u.Hard.PageFrameNumber = MI_HYPERSPACE_PTES;

    /* Set the working set address */
    MmWorkingSetList = (PVOID)MI_WORKING_SET_LIST;

    /* Reserve system PTEs for zeroing PTEs and clear them */
    MiFirstReservedZeroingPte = MiReserveSystemPtes(MI_ZERO_PTES + 1, SystemPteSpace);
    RtlZeroMemory(MiFirstReservedZeroingPte, (MI_ZERO_PTES + 1) * sizeof(MMPTE));

    /* Set the counter to maximum to boot with */
    MiFirstReservedZeroingPte->u.Hard.PageFrameNumber = MI_ZERO_PTES;

    /* Lock PFN database */
    OldIrql = MiLockPfnDb(APC_LEVEL);

    /* Reset the ref/share count so that MmInitializeProcessAddressSpace works */
    Pfn = MiGetPfnEntry(PFN_FROM_PTE(MiAddressToPde(PDE_BASE)));
    Pfn->u2.ShareCount = 0;
    Pfn->u3.e2.ReferenceCount = 0;

    /* Get a page for the working set list */
    MI_SET_USAGE(MI_USAGE_PAGE_TABLE);
    MI_SET_PROCESS2("Kernel WS List");
    PageFrameIndex = MiRemoveAnyPage(0);
    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    TempPte = ValidKernelPteLocal;
    TempPte.u.Hard.PageFrameNumber = PageFrameIndex;

    /* Map the working set list */
    Pte = MiAddressToPte(MmWorkingSetList);
    MI_WRITE_VALID_PTE(Pte, TempPte);

    /* Zero it out, and save the frame index */
    RtlZeroMemory(MiPteToAddress(Pte), PAGE_SIZE);
    PsGetCurrentProcess()->WorkingSetPage = PageFrameIndex;

    /* Map the VAD bitmap */
    Pte = MiAddressToPte(MI_VAD_BITMAP);

    /* Lock PFN database */
    OldIrql = MiLockPfnDb(APC_LEVEL);
    PageFrameIndex = MiRemoveAnyPage(0);
    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    TempPte = ValidKernelPteLocal;
    TempPte.u.Hard.PageFrameNumber = PageFrameIndex;
    MI_WRITE_VALID_PTE(Pte, TempPte);

    /* Zero it out, and save maximal bit index */
    RtlZeroMemory(MI_VAD_BITMAP, PAGE_SIZE);
    MiLastVadBit = ((ULONG_PTR)MM_HIGHEST_VAD_ADDRESS / (64 * _1KB));

    /* Check for Pentium LOCK errata */
    if (KiI386PentiumLockErrataPresent)
    {
        /* Mark the 1st IDT page as Write-Through to prevent a lockup on a F00F instruction.
           See http://www.rcollins.org/Errata/Dec97/F00FBug.html
        */
        Pte = MiAddressToPte(KeGetPcr()->IDT);
        Pte->u.Hard.WriteThrough = 1;
    }

    /* Initialize the bogus address space */
    Flags = 0;
    MmInitializeProcessAddressSpace(PsGetCurrentProcess(), NULL, NULL, &Flags, NULL);

    /* Make sure the color lists are valid */
    ASSERT(MmFreePagesByColor[0] < (PMMCOLOR_TABLES)PTE_BASE);

    StartPde = MiAddressToPde(MmFreePagesByColor[0]);
    ASSERT(StartPde->u.Hard.Valid == 1);

    Pte = MiAddressToPte(MmFreePagesByColor[0]);
    ASSERT(Pte->u.Hard.Valid == 1);

    LastPte = MiAddressToPte((ULONG_PTR)&MmFreePagesByColor[1][MmSecondaryColors] - 1);
    ASSERT(LastPte->u.Hard.Valid == 1);

    /* Loop the color list PTEs */
    for (; Pte <= LastPte; Pte++)
    {
        /* Get the PFN entry */
        Pfn = MiGetPfnEntry(PFN_FROM_PTE(Pte));
        if (Pfn->u3.e2.ReferenceCount)
            continue;

        /* Fill it out */
        Pfn->u4.PteFrame = PFN_FROM_PTE(StartPde);
        Pfn->PteAddress = Pte;
        Pfn->u2.ShareCount++;
        Pfn->u3.e2.ReferenceCount = 1;
        Pfn->u3.e1.PageLocation = ActiveAndValid;
        Pfn->u3.e1.CacheAttribute = MiCached;
    }

    return STATUS_SUCCESS;
}

/* EOF */
