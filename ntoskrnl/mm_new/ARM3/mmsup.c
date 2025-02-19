
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "miarm.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

extern MM_SYSTEMSIZE MmSystemSize;
extern ULONG MmProductType;
extern PMMWSL MmSystemCacheWorkingSetList;
extern PVOID MmPagedPoolEnd;
extern PVOID MmSpecialPoolStart;
extern PVOID MmSpecialPoolEnd;

/* FUNCTIONS ******************************************************************/

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(PAGELK, MmCreateMirror)
  #pragma alloc_text(PAGELK, MmMapUserAddressesToPage)
  #pragma alloc_text(PAGE, MmSetBankedSection)
#endif

BOOLEAN
NTAPI
MiIsAddressValid(
    _In_ PVOID Address)
{
    PMMPDE Pde;
    PMMPTE Pte;

    Pde = MiAddressToPde(Address);

    if (!Pde->u.Hard.Valid)
    {
        DPRINT("MiIsAddressValid: Address %p not valid\n", Address);
        return FALSE;
    }

    if (Pde->u.Hard.LargePage)
    {
        DPRINT1("MiIsAddressValid: Address %p valid\n", Address);
        return TRUE;
    }

    Pte = MiAddressToPte(Address);

    if (!Pte->u.Hard.Valid)
    {
        DPRINT("MiIsAddressValid: Address %p not valid\n", Address);
        return FALSE;
    }

    if (Pte->u.Hard.LargePage)
    {
        DPRINT("MiIsAddressValid: Address %p not valid\n", Address);
        return FALSE;
    }

    DPRINT("MiIsAddressValid: Address %p valid\n", Address);
    return TRUE;
}

VOID
FASTCALL
MiRestoreTransitionPte(
    _In_ PMMPFN Pfn)
{
    PEPROCESS Process = NULL;
    PCONTROL_AREA ControlArea;
    PSUBSECTION Subsection;
    PMMPFN RestorePfn;
    PMMPTE Pte;
    PMMPTE pte;
    PFN_NUMBER PageTableFrameIndex;

    DPRINT("MiRestoreTransitionPte: Pfn %p\n", Pfn);

    ASSERT(Pfn->u3.e1.PageLocation == StandbyPageList);

    if (Pfn->u3.e1.PrototypePte)
    {
        ASSERT((((ULONG_PTR)Pfn->PteAddress >= (ULONG_PTR)MmPagedPoolStart) && ((ULONG_PTR)Pfn->PteAddress <= (ULONG_PTR)MmPagedPoolEnd)) ||
                (((ULONG_PTR)Pfn->PteAddress >= (ULONG_PTR)MmSpecialPoolStart) && ((ULONG_PTR)Pfn->PteAddress <= (ULONG_PTR)MmSpecialPoolEnd)));

        ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
        ASSERT(MmPfnOwner == KeGetCurrentThread());

        pte = MiAddressToPte(Pfn->PteAddress);

        if (pte->u.Hard.Valid)
        {
            ASSERT(MI_IS_PAGE_LARGE(pte) == FALSE);
            Pte = Pfn->PteAddress;
        }
        else
        {
            Process = PsGetCurrentProcess();

            DPRINT1("MiRestoreTransitionPte: FIXME\n");
            ASSERT(FALSE);Pte = 0;
        }

        ASSERT(Pte->u.Hard.Valid == 0);
        ASSERT(Pte->u.Trans.PageFrameNumber == (((ULONG_PTR)Pfn - (ULONG_PTR)MmPfnDatabase) / sizeof(MMPFN)));

        if (Pfn->OriginalPte.u.Soft.Prototype)
        {
            Subsection = MiSubsectionPteToSubsection(&Pfn->OriginalPte);
            ControlArea = Subsection->ControlArea;

            ControlArea->NumberOfPfnReferences--;
            ASSERT((LONG)ControlArea->NumberOfPfnReferences >= 0);

            MiCheckForControlAreaDeletion(ControlArea);
        }
    }
    else
    {
        Pte = Pfn->PteAddress;

        if (Pte < MiAddressToPte(MmSystemCacheWorkingSetList) || MI_IS_SESSION_PTE(Pte))
        {
            Process = PsGetCurrentProcess();

            DPRINT1("MiRestoreTransitionPte: FIXME\n");
            ASSERT(FALSE);
        }

        ASSERT(Pte->u.Hard.Valid == 0);
        ASSERT(Pte->u.Trans.PageFrameNumber == (((ULONG_PTR)Pfn - (ULONG_PTR)MmPfnDatabase) / sizeof(MMPFN)));

        DPRINT1("MiRestoreTransitionPte: FIXME\n");
        ASSERT(FALSE);
    }

    ASSERT(Pfn->OriginalPte.u.Hard.Valid == 0);
    ASSERT(!((Pfn->OriginalPte.u.Soft.Prototype == 0) && (Pfn->OriginalPte.u.Soft.Transition == 1)));

    MI_WRITE_INVALID_PTE(Pte, Pfn->OriginalPte);

    if (Process)
    {
        DPRINT1("MiRestoreTransitionPte: FIXME\n");
        ASSERT(FALSE);
    }

    Pfn->u4.Priority = 3;

    PageTableFrameIndex = Pfn->u4.PteFrame;
    RestorePfn = MI_PFN_ELEMENT(PageTableFrameIndex);
    MiDecrementPfnShare(RestorePfn, PageTableFrameIndex);
}

/* PUBLIC FUNCTIONS ***********************************************************/

CODE_SEG("PAGELK")
NTSTATUS
NTAPI
MmCreateMirror(VOID)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;    
}

BOOLEAN
NTAPI
MmIsAddressValid(
    _In_ PVOID VirtualAddress)
{
  #if _MI_PAGING_LEVELS >= 3
    #error FIXME
  #endif

  #if _MI_PAGING_LEVELS >= 2
    /* Check if the PDE is valid */
    if (!MiAddressToPde(VirtualAddress)->u.Hard.Valid)
        return FALSE;
  #endif

    /* Check if the PTE is valid */
    if (!MiAddressToPte(VirtualAddress)->u.Hard.Valid)
        return FALSE;

    /* This address is valid now, but it will only stay so if the caller holds the PFN lock */
    return TRUE;
}

BOOLEAN
NTAPI
MmIsNonPagedSystemAddressValid(
    _In_ PVOID VirtualAddress)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

BOOLEAN
NTAPI
MmIsRecursiveIoFault(VOID)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

BOOLEAN
NTAPI
MmIsThisAnNtAsSystem(VOID)
{
    /* Return if this is a server system */
    return (MmProductType & 0xFF);
}

CODE_SEG("PAGELK")
NTSTATUS
NTAPI
MmMapUserAddressesToPage(
    _In_ PVOID BaseAddress,
    _In_ SIZE_T NumberOfBytes,
    _In_ PVOID PageAddress)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;    
}

MM_SYSTEMSIZE
NTAPI
MmQuerySystemSize(VOID)
{
    /* Return the low, medium or high memory system type */
    return MmSystemSize;
}

BOOLEAN
NTAPI
MmSetAddressRangeModified(
    _In_ PVOID Address,
    _In_ SIZE_T Length)
{
    PMMPFN Pfn;
    PMMPTE Pte;
    PMMPTE LastPte;
    MMPTE TempPte;
    ULONG Number = 0;
    KIRQL OldIrql;
    BOOLEAN Result = FALSE;

    DPRINT("MmSetAddressRangeModified: Address %p, Length %p\n", Address, Length);

    Pte = MiAddressToPte(Address);
    LastPte = MiAddressToPte(Add2Ptr(Address, (Length - 1)));

    OldIrql = MiLockPfnDb(APC_LEVEL);

    do
    {
        TempPte.u.Long = Pte->u.Long;

        if (!TempPte.u.Hard.Valid)
            goto Next;

        Pfn = MI_PFN_ELEMENT(TempPte.u.Hard.PageFrameNumber);

        ASSERT(Pfn->u3.e1.Rom == 0);
        Pfn->u3.e2.ShortFlags |= 1;

        if (!Pfn->OriginalPte.u.Soft.Prototype &&
            !Pfn->u3.e1.WriteInProgress)
        {
            DPRINT1("MmSetAddressRangeModified: FIXME MiReleasePageFileSpace()\n");
            ASSERT(FALSE);
        }

        if (MI_IS_PAGE_DIRTY(&TempPte))
            Result = TRUE;

        MI_MAKE_CLEAN_PAGE(&TempPte);

        ASSERT(Pte->u.Hard.Valid == 1);
        ASSERT(TempPte.u.Hard.Valid == 1);
        ASSERT(Pte->u.Hard.PageFrameNumber == TempPte.u.Hard.PageFrameNumber);

        Pte->u.Long = TempPte.u.Long;

        if (Number != 0x21)
        {
            Number++;
            //FIXME: FlushArray
        }
Next:
        Address = Add2Ptr(Address, PAGE_SIZE);
        Pte++;
    }
    while (Pte <= LastPte);

    if (Number == 0)
    {
        ;
    }
    else if (Number == 1)
    {
        /* Flush the TLB */
        //FIXME: Use KeFlushSingleTb() instead
        KeFlushEntireTb(TRUE, TRUE);
    }
    else if (Number == 0x21)
    {
        //FIXME: MiFlushType
        //FIXME: KxFlushEntireTb();
        KeFlushEntireTb(TRUE, TRUE);
    }
    else
    {
        //FIXME: KeFlushMultipleTb(Number, FlushArray, 1);
        KeFlushEntireTb(TRUE, TRUE);
    }

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    return Result;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmSetBankedSection(    
    _In_ HANDLE ProcessHandle,
    _In_ PVOID VirtualAddress,
    _In_ ULONG BankLength,
    _In_ BOOLEAN ReadWriteBank,
    _In_ PVOID BankRoutine,
    _In_ PVOID Context)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;    
}

/* EOF */
