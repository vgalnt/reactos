
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "miarm.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PMMPTE MmFirstReservedMappingPte;
PMMPTE MmLastReservedMappingPte;
PMMPTE MiFirstReservedZeroingPte;

extern MMPTE ValidKernelPteLocal;
extern BOOLEAN MiWriteCombiningPtes;

/* FUNCTIONS ******************************************************************/

PVOID
NTAPI
MiMapPageInHyperSpace(
    _In_ PEPROCESS Process,
    _In_ PFN_NUMBER Page,
    _In_ PKIRQL OldIrql)
{
    MMPTE TempPte;
    PMMPTE Pte;
    PMMPFN Pfn;
    PFN_NUMBER Offset;

    DPRINT("MiMapPageInHyperSpace: %p, %X, %X\n", Process, Page, *OldIrql);

    /* Never accept page 0 or non-physical pages */
    ASSERT(Page != 0);
    ASSERT(MiGetPfnEntry(Page) != NULL);

    /* Build the PTE */
    TempPte = ValidKernelPteLocal;
    TempPte.u.Hard.PageFrameNumber = Page;

    Pfn = MI_PFN_ELEMENT(Page);

    if (Pfn->u3.e1.CacheAttribute == MiWriteCombined)
    {
        if (MiWriteCombiningPtes)
        {
            TempPte.u.Hard.CacheDisable = 0;
            TempPte.u.Hard.WriteThrough = 1;
        }
        else
        {
            TempPte.u.Hard.CacheDisable = 1;
            TempPte.u.Hard.WriteThrough = 0;
        }
    }
    else if (Pfn->u3.e1.CacheAttribute == MiNonCached)
    {
        TempPte.u.Hard.CacheDisable = 1;
        TempPte.u.Hard.WriteThrough = 1;
    }

    /* Pick the first hyperspace PTE */
    Pte = MmFirstReservedMappingPte;

    /* Acquire the hyperlock */
    ASSERT(Process == PsGetCurrentProcess());
    KeAcquireSpinLock(&Process->HyperSpaceLock, OldIrql);

    /* Now get the first free PTE */
    Offset = PFN_FROM_PTE(Pte);
    if (!Offset)
    {
        /* Reset the PTEs */
        Offset = MI_HYPERSPACE_PTES;
        KeFlushProcessTb();
    }

    /* Prepare the next PTE */
    Pte->u.Hard.PageFrameNumber = Offset - 1;

    /* Write the current PTE */
    Pte += Offset;
    MI_WRITE_VALID_PTE(Pte, TempPte);

    /* Return the address */
    return MiPteToAddress(Pte);
}

PVOID
NTAPI
MiMapPageInHyperSpaceAtDpc(
    _In_ PEPROCESS Process,
    _In_ PFN_NUMBER PageNumber)
{
    MMPTE TempPte;
    PMMPTE Pte;
    PMMPFN Pfn;
    PFN_NUMBER Offset;

    DPRINT("MiMapPageInHyperSpaceAtDpc: %p, %X\n", Process, PageNumber);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    /* Never accept page 0 or non-physical pages */
    ASSERT(PageNumber != 0);
    ASSERT(MiGetPfnEntry(PageNumber) != NULL);

    /* Build the PTE */
    TempPte = ValidKernelPteLocal;
    TempPte.u.Hard.PageFrameNumber = PageNumber;

    Pfn = MI_PFN_ELEMENT(PageNumber);

    if (Pfn->u3.e1.CacheAttribute == MiWriteCombined)
    {
        if (MiWriteCombiningPtes)
        {
            TempPte.u.Hard.CacheDisable = 0;
            TempPte.u.Hard.WriteThrough = 1;
        }
        else
        {
            TempPte.u.Hard.CacheDisable = 1;
            TempPte.u.Hard.WriteThrough = 0;
        }
    }
    else if (Pfn->u3.e1.CacheAttribute == MiNonCached)
    {
        TempPte.u.Hard.CacheDisable = 1;
        TempPte.u.Hard.WriteThrough = 1;
    }

    /* Acquire the hyperlock */
    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(Process == PsGetCurrentProcess());
    KeAcquireSpinLockAtDpcLevel(&Process->HyperSpaceLock);

    /* Pick the first hyperspace PTE */
    Pte = MmFirstReservedMappingPte;

    /* Now get the first free PTE */
    Offset = PFN_FROM_PTE(Pte);
    if (!Offset)
    {
        /* Reset the PTEs */
        Offset = MI_HYPERSPACE_PTES;
        KeFlushProcessTb();
    }

    /* Prepare the next PTE */
    Pte->u.Hard.PageFrameNumber = (Offset - 1);

    /* Write the current PTE */
    Pte += Offset;
    MI_WRITE_VALID_PTE(Pte, TempPte);

    /* Return the address */
    return MiPteToAddress(Pte);
}

VOID
NTAPI
MiUnmapPageInHyperSpace(
    _In_ PEPROCESS Process,
    _In_ PVOID Address,
    _In_ KIRQL OldIrql)
{
    ASSERT(Process == PsGetCurrentProcess());

    /* Blow away the mapping */
    MiAddressToPte(Address)->u.Long = 0;

    /* Release the hyperlock */
    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    KeReleaseSpinLock(&Process->HyperSpaceLock, OldIrql);
}

VOID
NTAPI
MiUnmapPageInHyperSpaceFromDpc(
    _In_ PEPROCESS Process,
    _In_ PVOID Address)
{
    ASSERT(Process == PsGetCurrentProcess());
    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    /* Blow away the mapping */
    MiAddressToPte(Address)->u.Long = 0;

    /* Release the hyperlock */
    KeReleaseSpinLockFromDpcLevel(&Process->HyperSpaceLock);
}

PVOID
NTAPI
MiMapPagesInZeroSpace(
    _In_ PMMPFN Pfn,
    _In_ PFN_NUMBER NumberOfPages)
{
    PMMPTE Pte;
    MMPTE TempPte;
    PFN_NUMBER Offset;
    PFN_NUMBER PageFrameIndex;

    /* Sanity checks */
    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    ASSERT(NumberOfPages != 0);
    ASSERT(NumberOfPages <= (MI_ZERO_PTES - 1));

    /* Pick the first zeroing PTE */
    Pte = MiFirstReservedZeroingPte;

    /* Now get the first free PTE */
    Offset = PFN_FROM_PTE(Pte);

    if (NumberOfPages > Offset)
    {
        /* Reset the PTEs */
        Offset = (MI_ZERO_PTES - 1);
        Pte->u.Hard.PageFrameNumber = Offset;

        KeFlushProcessTb();
    }

    /* Prepare the next PTE */
    Pte->u.Hard.PageFrameNumber = (Offset - NumberOfPages);

    /* Choose the correct PTE to use, and which template */
    Pte += (Offset + 1);
    TempPte = ValidKernelPte;

    /* Make sure the list isn't empty and loop it */
    ASSERT(Pfn != (PVOID)LIST_HEAD);

    while (Pfn != (PVOID)LIST_HEAD)
    {
        /* Get the page index for this PFN */
        PageFrameIndex = MiGetPfnEntryIndex(Pfn);

        /* Write the PFN */
        TempPte.u.Hard.PageFrameNumber = PageFrameIndex;

        /* Set the correct PTE to write to, and set its new value */
        Pte--;
        MI_WRITE_VALID_PTE(Pte, TempPte);

        /* Move to the next PFN */
        Pfn = (PMMPFN)Pfn->u1.Flink;
    }

    /* Return the address */
    return MiPteToAddress(Pte);
}

VOID
NTAPI
MiUnmapPagesInZeroSpace(
    _In_ PVOID VirtualAddress,
    _In_ PFN_NUMBER NumberOfPages)
{
    PMMPTE Pte;

    /* Sanity checks */
    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    ASSERT (NumberOfPages != 0);
    ASSERT (NumberOfPages <= (MI_ZERO_PTES - 1));

    /* Get the first PTE for the mapped zero VA */
    Pte = MiAddressToPte(VirtualAddress);

    /* Blow away the mapped zero PTEs */
    RtlZeroMemory(Pte, (NumberOfPages * sizeof(MMPTE)));
}

/* EOF */
