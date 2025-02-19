
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "miarm.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

/* Each architecture has its own caching attributes for both I/O and Physical memory mappings.
   This describes the attributes for the x86 architecture.
   It eventually needs to go in the appropriate i386 directory.
*/
MI_PFN_CACHE_ATTRIBUTE MiPlatformCacheAttributes[2][MmMaximumCacheType] =
{
    /* RAM */
    { MiNonCached, MiCached, MiWriteCombined, MiCached, MiNonCached, MiWriteCombined },

    /* Device Memory */
    { MiNonCached, MiCached, MiWriteCombined, MiCached, MiNonCached, MiWriteCombined },
};

/* FUNCTIONS ******************************************************************/


/* PUBLIC FUNCTIONS ***********************************************************/

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(PAGE, MmMapVideoDisplay)
  #pragma alloc_text(PAGE, MmUnmapVideoDisplay)
#endif

LOGICAL
NTAPI
MmIsIoSpaceActive(
    _In_ PHYSICAL_ADDRESS StartAddress,
    _In_ SIZE_T NumberOfBytes)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

PVOID
NTAPI
MmMapIoSpace(
    _In_ PHYSICAL_ADDRESS PhysicalAddress,
    _In_ SIZE_T NumberOfBytes,
    _In_ MEMORY_CACHING_TYPE CacheType)
{
    PVOID BaseAddress;
    PMMPFN Pfn = NULL;
    PMMPTE Pte;
    MMPTE TempPte;
    MI_PFN_CACHE_ATTRIBUTE CacheAttribute;
    PFN_NUMBER PageFrameIndex;
    PFN_COUNT PageCount;
    BOOLEAN IsIoMapping;

    /* Must be called with a non-zero count */
    ASSERT(NumberOfBytes != 0);

    /* Make sure the upper bits are 0 if this system can't describe more than 4 GB of physical memory.
       FIXME: This doesn't respect PAE, but we currently don't define a PAE build flag since there is no such build.
    */
  #if !defined(_M_AMD64)
    ASSERT(PhysicalAddress.HighPart == 0);
  #endif

    /* Normalize and validate the caching attributes */
    CacheType &= 0xFF;
    if (CacheType >= MmMaximumCacheType)
        return NULL;

    /* Calculate page count */
    PageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(PhysicalAddress.LowPart, NumberOfBytes);

    /* Compute the PFN and check if it's a known I/O mapping.
       Also translate the cache attribute.
    */
    PageFrameIndex = (PFN_NUMBER)(PhysicalAddress.QuadPart >> PAGE_SHIFT);
    Pfn = MiGetPfnEntry(PageFrameIndex);
    IsIoMapping = ((Pfn == NULL) ? TRUE : FALSE);
    CacheAttribute = MiPlatformCacheAttributes[IsIoMapping][CacheType];

    /* Now allocate system PTEs for the mapping, and get the VA */
    Pte = MiReserveSystemPtes(PageCount, SystemPteSpace);
    if (!Pte)
        return NULL;

    BaseAddress = MiPteToAddress(Pte);

    /* Check if this is uncached */
    if (CacheAttribute != MiCached)
    {
        /* Flush all caches */
        KeFlushEntireTb(TRUE, TRUE);
        KeInvalidateAllCaches();
    }

    /* Now compute the VA offset */
    BaseAddress = (PVOID)((ULONG_PTR)BaseAddress + BYTE_OFFSET(PhysicalAddress.LowPart));

    /* Get the template and configure caching */
    TempPte = ValidKernelPte;

    switch (CacheAttribute)
    {
        case MiNonCached:
            /* Disable the cache */
            MI_PAGE_DISABLE_CACHE(&TempPte);
            MI_PAGE_WRITE_THROUGH(&TempPte);
            break;

        case MiCached:
            /* Leave defaults */
            break;

        case MiWriteCombined:
            /* Disable the cache and allow combined writing */
            MI_PAGE_DISABLE_CACHE(&TempPte);
            MI_PAGE_WRITE_COMBINED(&TempPte);
            break;

        default:
            /* Should never happen */
            ASSERT(FALSE);
            break;
    }

    /* Sanity check and re-flush */
    PageFrameIndex = (PFN_NUMBER)(PhysicalAddress.QuadPart >> PAGE_SHIFT);
    ASSERT((Pfn == MiGetPfnEntry(PageFrameIndex)) || (Pfn == NULL));

    KeFlushEntireTb(TRUE, TRUE);
    KeInvalidateAllCaches();

    /* Do the mapping */
    do
    {
        /* Write the PFN */
        TempPte.u.Hard.PageFrameNumber = PageFrameIndex++;
        MI_WRITE_VALID_PTE(Pte++, TempPte);
    }
    while (--PageCount);

    return BaseAddress;
}

CODE_SEG("PAGE")
PVOID
NTAPI
MmMapVideoDisplay(
    _In_ PHYSICAL_ADDRESS PhysicalAddress,
    _In_ SIZE_T NumberOfBytes,
    _In_ MEMORY_CACHING_TYPE CacheType)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

VOID
NTAPI
MmUnmapIoSpace(
    _In_ PVOID BaseAddress,
    _In_ SIZE_T NumberOfBytes)
{
    PMMPTE Pte;
    PFN_NUMBER Pfn;
    PFN_COUNT PageCount;

    /* Sanity check */
    ASSERT(NumberOfBytes != 0);

    /* Get the page count */
    PageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(BaseAddress, NumberOfBytes);

    /* Get the PTE and PFN */
    Pte = MiAddressToPte(BaseAddress);
    Pfn = PFN_FROM_PTE(Pte);

    /* Is this an I/O mapping? */
    if (!MiGetPfnEntry(Pfn))
    {
        /* Destroy the PTE */
        RtlZeroMemory(Pte, (PageCount * sizeof(MMPTE)));

        /* Blow the TLB */
        KeFlushEntireTb(TRUE, TRUE);
    }

    /* Release the PTEs */
    MiReleaseSystemPtes(Pte, PageCount, 0);
}

CODE_SEG("PAGE")
VOID
NTAPI
MmUnmapVideoDisplay(
    _In_ PVOID BaseAddress,
    _In_ SIZE_T NumberOfBytes)
{
    UNIMPLEMENTED_DBGBREAK();
}

/* EOF */
