
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "miarm.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

#define MI_MAPPED_COPY_PAGES  0xE // 14
#define MI_POOL_COPY_BYTES    0x200
#define MI_MAX_TRANSFER_SIZE  (0x40 * _1KB) // 64 Kb

extern MI_PFN_CACHE_ATTRIBUTE MiPlatformCacheAttributes[2][MmMaximumCacheType];
extern BOOLEAN MiWriteCombiningPtes;
extern PVOID MmPagedPoolEnd;
extern KGUARDED_MUTEX MmSectionCommitMutex;
extern SIZE_T MmSharedCommit;
extern MMPTE MmDecommittedPte;
extern MMPTE PrototypePte;
extern PMM_SESSION_SPACE MmSessionSpace;
extern volatile LONG KiTbFlushTimeStamp;
extern PVOID MmSystemCacheStart;
extern PVOID MmSystemCacheEnd;
extern PMMWSL MmSystemCacheWorkingSetList;

/* FUNCTIONS ******************************************************************/

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(PAGE, MiGetExceptionInfo)
  #pragma alloc_text(PAGE, MiDoMappedCopy)
  #pragma alloc_text(PAGE, MiDoPoolCopy)
  #pragma alloc_text(PAGE, MmCopyVirtualMemory)
  #pragma alloc_text(PAGELK, MiResetVirtualMemory)
  #pragma alloc_text(PAGE, MmSecureVirtualMemory)
  #pragma alloc_text(PAGE, MmUnsecureVirtualMemory)
  #pragma alloc_text(PAGE, NtReadVirtualMemory)
  #pragma alloc_text(PAGE, NtWriteVirtualMemory)
  #pragma alloc_text(PAGE, NtFlushInstructionCache)
  #pragma alloc_text(PAGE, NtProtectVirtualMemory)
  #pragma alloc_text(PAGE, NtFlushVirtualMemory)
#endif

CODE_SEG("PAGE")
LONG
MiGetExceptionInfo(
    _In_ PEXCEPTION_POINTERS ExceptionInfo,
    _Out_ PBOOLEAN HaveBadAddress,
    _Out_ PULONG_PTR BadAddress)
{
    PEXCEPTION_RECORD ExceptionRecord;

    PAGED_CODE();

    /* Assume default */
    *HaveBadAddress = FALSE;

    /* Get the exception record */
    ExceptionRecord = ExceptionInfo->ExceptionRecord;

    /* Look at the exception code */
    if (ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION ||
        ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION ||
        ExceptionRecord->ExceptionCode == STATUS_IN_PAGE_ERROR)
    {
        /* We can tell the address if we have more than one parameter */
        if (ExceptionRecord->NumberParameters > 1)
        {
            /* Return the address */
            *HaveBadAddress = TRUE;
            *BadAddress = ExceptionRecord->ExceptionInformation[1];
        }
    }

    /* Continue executing the next handler */
    return EXCEPTION_EXECUTE_HANDLER;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MiDoMappedCopy(
    _In_ PEPROCESS SourceProcess,
    _In_ PVOID SourceAddress,
    _In_ PEPROCESS TargetProcess,
    _Out_ PVOID TargetAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T ReturnSize)
{
    PFN_NUMBER MdlBuffer[(sizeof(MDL) / sizeof(PFN_NUMBER)) + MI_MAPPED_COPY_PAGES + 1];
    PMDL Mdl = (PMDL)MdlBuffer;
    volatile PVOID MdlAddress = NULL;
    PVOID CurrentAddress = SourceAddress;
    PVOID CurrentTargetAddress = TargetAddress;
    ULONG_PTR BadAddress;
    SIZE_T TotalSize;
    SIZE_T CurrentSize;
    SIZE_T RemainingSize;
    KAPC_STATE ApcState;
    BOOLEAN HaveBadAddress;
    volatile BOOLEAN FailedInProbe = FALSE;
    volatile BOOLEAN PagesLocked = FALSE;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    /* Calculate the maximum amount of data to move */
    TotalSize = (MI_MAPPED_COPY_PAGES * PAGE_SIZE);

    if (BufferSize <= TotalSize)
        TotalSize = BufferSize;

    CurrentSize = TotalSize;
    RemainingSize = BufferSize;

    /* Loop as long as there is still data */
    while (RemainingSize > 0)
    {
        /* Check if this transfer will finish everything off */
        if (RemainingSize < CurrentSize)
            CurrentSize = RemainingSize;

        /* Attach to the source address space */
        KeStackAttachProcess(&SourceProcess->Pcb, &ApcState);

        /* Check state for this pass */
        ASSERT(MdlAddress == NULL);
        ASSERT(PagesLocked == FALSE);
        ASSERT(FailedInProbe == FALSE);

        /* Protect user-mode copy */
        _SEH2_TRY
        {
            /* If this is our first time, probe the buffer */
            if (CurrentAddress == SourceAddress && PreviousMode != KernelMode)
            {
                /* Catch a failure here */
                FailedInProbe = TRUE;

                /* Do the probe */
                ProbeForRead(SourceAddress, BufferSize, sizeof(CHAR));

                /* Passed */
                FailedInProbe = FALSE;
            }

            /* Initialize and probe and lock the MDL */
            MmInitializeMdl(Mdl, CurrentAddress, CurrentSize);
            MmProbeAndLockPages(Mdl, PreviousMode, IoReadAccess);

            PagesLocked = TRUE;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END

        /* Detach from source process */
        KeUnstackDetachProcess(&ApcState);

        if (Status != STATUS_SUCCESS)
        {
            DPRINT1("MiDoMappedCopy: Status %X\n", Status);
            goto Exit;
        }

        /* Now map the pages */
        MdlAddress = MmMapLockedPagesSpecifyCache(Mdl,
                                                  KernelMode,
                                                  MmCached,
                                                  NULL,
                                                  FALSE,
                                                  HighPagePriority);
        if (!MdlAddress)
        {
            DPRINT1("MiDoMappedCopy: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        /* Grab to the target process */
        KeStackAttachProcess(&TargetProcess->Pcb, &ApcState);

        _SEH2_TRY
        {
            /* Check if this is our first time through */
            if (CurrentTargetAddress == TargetAddress && PreviousMode != KernelMode)
            {
                /* Catch a failure here */
                FailedInProbe = TRUE;

                /* Do the probe */
                ProbeForWrite(TargetAddress, BufferSize, sizeof(CHAR));

                /* Passed */
                FailedInProbe = FALSE;
            }

            /* Now do the actual move */
            RtlCopyMemory(CurrentTargetAddress, MdlAddress, CurrentSize);
        }
        _SEH2_EXCEPT(MiGetExceptionInfo(_SEH2_GetExceptionInformation(),
                                        &HaveBadAddress,
                                        &BadAddress))
        {
            *ReturnSize = BufferSize - RemainingSize;

            /* Check if we failed during the probe */
            if (FailedInProbe)
            {
                /* Exit */
                Status = _SEH2_GetExceptionCode();
            }
            else
            {
                /* Othewise we failed during the move.
                   Check if we know exactly where we stopped copying
                */
                if (HaveBadAddress)
                    /* Return the exact number of bytes copied */
                    *ReturnSize = (BadAddress - (ULONG_PTR)SourceAddress);

                /* Return partial copy */
                Status = STATUS_PARTIAL_COPY;
            }
        }
        _SEH2_END;

        /* Detach from target process */
        KeUnstackDetachProcess(&ApcState);

        /* Check for SEH status */
        if (Status != STATUS_SUCCESS)
        {
            DPRINT1("MiDoMappedCopy: Status %X\n", Status);
            goto Exit;
        }

        /* Unmap and unlock */
        MmUnmapLockedPages(MdlAddress, Mdl);
        MdlAddress = NULL;
        MmUnlockPages(Mdl);
        PagesLocked = FALSE;

        /* Update location and size */
        RemainingSize -= CurrentSize;
        CurrentAddress = (PVOID)((ULONG_PTR)CurrentAddress + CurrentSize);
        CurrentTargetAddress = (PVOID)((ULONG_PTR)CurrentTargetAddress + CurrentSize);
    }

Exit:
    if (MdlAddress)
        MmUnmapLockedPages(MdlAddress, Mdl);

    if (PagesLocked)
        MmUnlockPages(Mdl);

    /* All bytes read */
    if (Status == STATUS_SUCCESS)
        *ReturnSize = BufferSize;

    return Status;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MiDoPoolCopy(
    _In_ PEPROCESS SourceProcess,
    _In_ PVOID SourceAddress,
    _In_ PEPROCESS TargetProcess,
    _Out_ PVOID TargetAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T ReturnSize)
{
    UCHAR StackBuffer[MI_POOL_COPY_BYTES];
    PVOID CurrentAddress = SourceAddress;
    PVOID CurrentTargetAddress = TargetAddress;
    PVOID PoolAddress;
    ULONG_PTR BadAddress;
    SIZE_T TotalSize;
    SIZE_T CurrentSize;
    SIZE_T RemainingSize;
    volatile BOOLEAN FailedInProbe = FALSE;
    volatile BOOLEAN HavePoolAddress = FALSE;
    BOOLEAN HaveBadAddress;
    KAPC_STATE ApcState;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    DPRINT("MiDoPoolCopy: %X, %p, %p, %p, %p\n",
           BufferSize, SourceProcess, SourceAddress, TargetProcess, TargetAddress);

    /* Calculate the maximum amount of data to move */
    TotalSize = MI_MAX_TRANSFER_SIZE;

    if (BufferSize <= MI_MAX_TRANSFER_SIZE)
        TotalSize = BufferSize;

    CurrentSize = TotalSize;
    RemainingSize = BufferSize;

    /* Check if we can use the stack */
    if (BufferSize <= MI_POOL_COPY_BYTES)
    {
        /* Use it */
        PoolAddress = (PVOID)StackBuffer;
    }
    else
    {
        /* Allocate pool */
        PoolAddress = ExAllocatePoolWithTag(NonPagedPool, TotalSize, 'VmRw');
        if (!PoolAddress)
        {
            DPRINT1("MiDoPoolCopy: FIXME while (TotalSize / 2)\n");
            ASSERT(FALSE);
        }

        HavePoolAddress = TRUE;
    }

    /* Loop as long as there is still data */
    while (RemainingSize > 0)
    {
        /* Check if this transfer will finish everything off */
        if (RemainingSize < CurrentSize)
            CurrentSize = RemainingSize;

        /* Attach to the source address space */
        KeStackAttachProcess(&SourceProcess->Pcb, &ApcState);

        /* Check that state is sane */
        ASSERT(FailedInProbe == FALSE);
        ASSERT(Status == STATUS_SUCCESS);

        /* Protect user-mode copy */
        _SEH2_TRY
        {
            /* If this is our first time, probe the buffer */
            if (CurrentAddress == SourceAddress && PreviousMode != KernelMode)
            {
                /* Catch a failure here */
                FailedInProbe = TRUE;

                /* Do the probe */
                ProbeForRead(SourceAddress, BufferSize, sizeof(CHAR));

                /* Passed */
                FailedInProbe = FALSE;
            }

            /* Do the copy */
            RtlCopyMemory(PoolAddress, CurrentAddress, CurrentSize);
        }
        _SEH2_EXCEPT(MiGetExceptionInfo(_SEH2_GetExceptionInformation(),
                                        &HaveBadAddress,
                                        &BadAddress))
        {
            *ReturnSize = BufferSize - RemainingSize;

            /* Check if we failed during the probe */
            if (FailedInProbe)
            {
                /* Exit */
                Status = _SEH2_GetExceptionCode();
            }
            else
            {
                /* We failed during the move.
                   Check if we know exactly where we stopped copying
                */
                if (HaveBadAddress)
                    /* Return the exact number of bytes copied */
                    *ReturnSize = BadAddress - (ULONG_PTR)SourceAddress;

                /* Return partial copy */
                Status = STATUS_PARTIAL_COPY;
            }
        }
        _SEH2_END

        /* Let go of the source */
        KeUnstackDetachProcess(&ApcState);

        if (Status != STATUS_SUCCESS)
        {
            DPRINT1("MiDoPoolCopy: Status %X\n", Status);
            goto Exit;
        }

        /* Grab the target process */
        KeStackAttachProcess(&TargetProcess->Pcb, &ApcState);

        _SEH2_TRY
        {
            /* Check if this is our first time through */
            if ((CurrentTargetAddress == TargetAddress) && (PreviousMode != KernelMode))
            {
                /* Catch a failure here */
                FailedInProbe = TRUE;

                /* Do the probe */
                ProbeForWrite(TargetAddress, BufferSize, sizeof(CHAR));

                /* Passed */
                FailedInProbe = FALSE;
            }

            /* Now do the actual move */
            RtlCopyMemory(CurrentTargetAddress, PoolAddress, CurrentSize);
        }
        _SEH2_EXCEPT(MiGetExceptionInfo(_SEH2_GetExceptionInformation(),
                                        &HaveBadAddress,
                                        &BadAddress))
        {
            *ReturnSize = BufferSize - RemainingSize;

            /* Check if we failed during the probe */
            if (FailedInProbe)
            {
                /* Exit */
                Status = _SEH2_GetExceptionCode();
            }
            else
            {
                /* Otherwise we failed during the move.
                   Check if we know exactly where we stopped copying
                */
                if (HaveBadAddress)
                    /* Return the exact number of bytes copied */
                    *ReturnSize = BadAddress - (ULONG_PTR)SourceAddress;

                /* Return partial copy */
                Status = STATUS_PARTIAL_COPY;
            }
        }
        _SEH2_END;

        /* Detach from target */
        KeUnstackDetachProcess(&ApcState);

        /* Check for SEH status */
        if (Status != STATUS_SUCCESS)
        {
            DPRINT1("MiDoPoolCopy: Status %X\n", Status);
            goto Exit;
        }

        /* Update location and size */
        RemainingSize -= CurrentSize;
        CurrentAddress = (PVOID)((ULONG_PTR)CurrentAddress + CurrentSize);
        CurrentTargetAddress = (PVOID)((ULONG_PTR)CurrentTargetAddress + CurrentSize);
    }

Exit:

    /* Check if we had allocated pool */
    if (HavePoolAddress)
        ExFreePoolWithTag(PoolAddress, 'VmRw');

    /* All bytes read */
    if (Status == STATUS_SUCCESS)
        *ReturnSize = BufferSize;

    return Status;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmCopyVirtualMemory(
    _In_ PEPROCESS SourceProcess,
    _In_ PVOID SourceAddress,
    _In_ PEPROCESS TargetProcess,
    _Out_ PVOID TargetAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T ReturnSize)
{
    NTSTATUS Status;
    PEPROCESS Process = SourceProcess;

    /* Don't accept zero-sized buffers */
    if (!BufferSize)
        return STATUS_SUCCESS;

    /* If we are copying from ourselves, lock the target instead */
    if (SourceProcess == PsGetCurrentProcess())
        Process = TargetProcess;

    /* Acquire rundown protection */
    if (!ExAcquireRundownProtection(&Process->RundownProtect))
    {
        /* Fail */
        DPRINT1("MmCopyVirtualMemory: STATUS_PROCESS_IS_TERMINATING\n");
        return STATUS_PROCESS_IS_TERMINATING;
    }

    /* See if we should use the pool copy */
    if (BufferSize > MI_POOL_COPY_BYTES)
    {
        /* Use MDL-copy */
        Status = MiDoMappedCopy(SourceProcess,
                                SourceAddress,
                                TargetProcess,
                                TargetAddress,
                                BufferSize,
                                PreviousMode,
                                ReturnSize);
    }
    else
    {
        *ReturnSize = 0;

        /* Do pool copy */
        Status = MiDoPoolCopy(SourceProcess,
                              SourceAddress,
                              TargetProcess,
                              TargetAddress,
                              BufferSize,
                              PreviousMode,
                              ReturnSize);
    }

    /* Release the lock */
    ExReleaseRundownProtection(&Process->RundownProtect);

    return Status;
}

PFN_COUNT
NTAPI
MiDeleteSystemPageableVm(
    _In_ PMMPTE Pte,
    _In_ PFN_NUMBER PageCount,
    _In_ ULONG Flags,
    _Out_ PFN_COUNT* OutPages)
{
    PETHREAD CurrentThread = PsGetCurrentThread();
    PMMSUPPORT WorkingSet;
    MMPTE TempPte;
    PMMPFN Pfn;
    PMMPFN PteFramePfn;
    PFN_NUMBER PageFrameIndex;
    PFN_NUMBER PageTableIndex;
    PFN_COUNT ActualPages = 0;
    PFN_COUNT ValidPages = 0;
    ULONG TbFlushEnties = 0;
    ULONG WsIndex;
    KIRQL OldIrql;
    BOOLEAN IsLocked = FALSE;

    DPRINT("MiDeleteSystemPageableVm: Pte %p, PageCount %X, Flags %X\n", Pte, PageCount, Flags);

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    if (MI_IS_SESSION_PTE(Pte))
        WorkingSet = &MmSessionSpace->GlobalVirtualAddress->Vm;
    else
        WorkingSet = &MmSystemCacheWs;

    /* Loop all pages */
    while (PageCount)
    {
        TempPte = *Pte;

        /* Make sure there's some data about the page */
        if (!TempPte.u.Long)
            goto Next;

        if (TempPte.u.Hard.Valid)
        {
            /* Normally this is one possibility -- freeing a valid page */
            if (!IsLocked)
            {
                /* Lock the system working set */
                MiLockWorkingSet(CurrentThread, WorkingSet);
                IsLocked = TRUE;
            }

            TempPte = *Pte;
            if (!TempPte.u.Hard.Valid)
                continue;

            /* Get the page PFN */
            PageFrameIndex = (TempPte.u.Hard.PageFrameNumber);
            Pfn = MI_PFN_ELEMENT(PageFrameIndex);

            WsIndex = Pfn->u1.WsIndex;
            if (!WsIndex)
            {
                ValidPages++;

                if (WorkingSet != &MmSystemCacheWs)
                {
                    DPRINT1("MiDeleteSystemPageableVm: FIXME\n");
                    ASSERT(FALSE);
                }
            }
            else if (WorkingSet == &MmSystemCacheWs)
            {
                MiRemoveWsle(WsIndex, MmSystemCacheWorkingSetList);
                MiReleaseWsle(WsIndex, &MmSystemCacheWs);
            }
            else
            {
                /* Should not have any working set data yet */
                DPRINT1("MiDeleteSystemPageableVm: FIXME\n");
                ASSERT(FALSE);
            }

            if (Pfn->u3.e1.PrototypePte)
            {
                ASSERT(WorkingSet != &MmSystemCacheWs);

                DPRINT1("MiDeleteSystemPageableVm: FIXME\n");
                ASSERT(FALSE);
            }
            else
            {
                /* Get the page table entry */
                PageTableIndex = Pfn->u4.PteFrame;
                PteFramePfn = MI_PFN_ELEMENT(PageTableIndex);

                /* Lock the PFN database */
                OldIrql = MiLockPfnDb(APC_LEVEL);

                /* Delete it the page */
                MI_SET_PFN_DELETED(Pfn);
            }

            MiDecrementPfnShare(PteFramePfn, PageTableIndex);
            MiDecrementShareCount(Pfn, PageFrameIndex);

            /* Release the PFN database */
            MiUnlockPfnDb(OldIrql, APC_LEVEL);

            /* Zero out the PTE */
            Pte->u.Long = 0;

            if ((Flags & 1) && TbFlushEnties != 0x21)
            {
                DPRINT1("MiDeleteSystemPageableVm: FIXME. TbFlushEnties %X\n", TbFlushEnties);
                ASSERT(FALSE);
                TbFlushEnties++;
            }

            /* Actual legitimate pages */
            ActualPages++;
            goto Next;

            Pte->u.Soft.PageFileHigh = KiTbFlushTimeStamp;
            if (!Pte->u.Soft.PageFileHigh && TbFlushEnties != 0x21)
            {
                DPRINT1("MiDeleteSystemPageableVm: FIXME. TbFlushEnties %X\n", TbFlushEnties);
                ASSERT(FALSE);
                TbFlushEnties++;
            }

            /* Actual legitimate pages */
            ActualPages++;
            goto Next;
        }

        if (TempPte.u.Soft.Prototype)
        {
            /* Prototype PTE */
            ASSERT(WorkingSet != &MmSystemCacheWs);

            /* Zero out the PTE */
            Pte->u.Long = 0;

            /* Actual legitimate pages */
            ActualPages++;
            goto Next;
        }

        if (!TempPte.u.Soft.Transition)
        {
            /* Demand zero page? */
            if (TempPte.u.Soft.PageFileHigh)
            {
                OldIrql = MiLockPfnDb(APC_LEVEL);
                MiReleasePageFileSpace(TempPte);
                MiUnlockPfnDb(OldIrql, APC_LEVEL);
            }

            /* Zero out the PTE */
            Pte->u.Long = 0;

            /* Actual legitimate pages */
            ActualPages++;
            goto Next;
        }

        /* Lock the PFN database */
        OldIrql = MiLockPfnDb(APC_LEVEL);

        TempPte = *Pte;
        if (!TempPte.u.Soft.Transition)
        {
            /* Release the PFN database */
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            continue;
        }

        /* Transition PTE */
        DPRINT1("MiDeleteSystemPageableVm: FIXME for transition PTE\n");
        ASSERT(FALSE);

Next:
        PageCount--;
        Pte++;
    }

    /* Release the working set */
    if (IsLocked)
        MiUnlockWorkingSet(CurrentThread, WorkingSet);

    /* Flush data */
    if (TbFlushEnties)
    {
        DPRINT1("MiDeleteSystemPageableVm: FIXME\n");
        ASSERT(FALSE);
    }

    /* Actual valid, legitimate, pages */
    if (OutPages)
        *OutPages = ValidPages;

    return ActualPages;
}

ULONG
NTAPI
MiMakeSystemAddressValid(
    _In_ PVOID PageTableVirtualAddress,
    _In_ PEPROCESS CurrentProcess)
{
    PETHREAD CurrentThread = PsGetCurrentThread();
    BOOLEAN WsShared = FALSE;
    BOOLEAN WsSafe = FALSE;
    BOOLEAN LockChange = FALSE;
    NTSTATUS Status;

    /* Must be a non-pool page table, since those are double-mapped already */
    ASSERT(PageTableVirtualAddress > MM_HIGHEST_USER_ADDRESS);
    ASSERT(PageTableVirtualAddress < MmPagedPoolStart || PageTableVirtualAddress > MmPagedPoolEnd);

    /* Working set lock or PFN lock should be held */
    ASSERT(KeAreAllApcsDisabled() == TRUE);

    /* Check if the page table is valid */
    while (!MmIsAddressValid(PageTableVirtualAddress))
    {
        /* Release the working set lock */
        MiUnlockProcessWorkingSetForFault(CurrentProcess, CurrentThread, &WsSafe, &WsShared);

        /* Fault it in */
        Status = MmAccessFault(FALSE, PageTableVirtualAddress, KernelMode, NULL);
        if (!NT_SUCCESS(Status))
        {
            /* This should not fail */
            ASSERT(FALSE);
            KeBugCheckEx(KERNEL_DATA_INPAGE_ERROR,
                         1,
                         Status,
                         (ULONG_PTR)CurrentProcess,
                         (ULONG_PTR)PageTableVirtualAddress);
        }

        /* Lock the working set again */
        MiLockProcessWorkingSetForFault(CurrentProcess, CurrentThread, WsSafe, WsShared);

        /* This flag will be useful later when we do better locking */
        LockChange = TRUE;
    }

    /* Let caller know what the lock state is */
    return LockChange;
}

VOID
NTAPI
MiMakePdeExistAndMakeValid(
    _In_ PMMPDE Pde,
    _In_ PEPROCESS TargetProcess,
    _In_ KIRQL OldIrql)
{
   PMMPTE Pte;
   PMMPTE Ppe;
   PMMPTE Pxe;

   /* Sanity checks.
      The latter is because we only use this function with the PFN lock not held, so it may go away in the future.
   */
   ASSERT(KeAreAllApcsDisabled() == TRUE);
   ASSERT(OldIrql == MM_NOIRQL);

   /* Also get the PPE and PXE.
     This is okay not to #ifdef because they will return the same address as the PDE on 2-level page table systems.

      If everything is already valid, there is nothing to do.
   */
   Ppe = MiAddressToPte(Pde);
   Pxe = MiAddressToPde(Pde);

   if (Pxe->u.Hard.Valid &&
       Ppe->u.Hard.Valid &&
       Pde->u.Hard.Valid)
   {
       return;
   }

   /* At least something is invalid, so begin by getting the PTE for the PDE itself and then lookup each additional level.
      We must do it in this precise order because the pagfault.c code (as well as in Windows)
      depends that the next level up (higher) must be valid when faulting a lower level
   */
   Pte = MiPteToAddress(Pde);

   do
   {
       /* Make sure APCs continued to be disabled */
       ASSERT(KeAreAllApcsDisabled() == TRUE);

       /* First, make the PXE valid if needed */
       if (!Pxe->u.Hard.Valid)
       {
           MiMakeSystemAddressValid(Ppe, TargetProcess);
           ASSERT(Pxe->u.Hard.Valid == 1);
       }

       /* Next, the PPE */
       if (!Ppe->u.Hard.Valid)
       {
           MiMakeSystemAddressValid(Pde, TargetProcess);
           ASSERT(Ppe->u.Hard.Valid == 1);
       }

       /* And finally, make the PDE itself valid. */
       MiMakeSystemAddressValid(Pte, TargetProcess);

       /* This should've worked the first time so the loop is really just for show -- ASSERT
          that we're actually NOT going to be looping.
       */
       ASSERT(Pxe->u.Hard.Valid == 1);
       ASSERT(Ppe->u.Hard.Valid == 1);
       ASSERT(Pde->u.Hard.Valid == 1);
   }
   while (!Pxe->u.Hard.Valid || !Ppe->u.Hard.Valid || !Pde->u.Hard.Valid);
}

ULONG
NTAPI
MiDeletePte(
    _In_ PMMPTE Pte,
    _In_ PVOID Va,
    _In_ BOOLEAN IsNotTerminateWsle,
    _In_ PEPROCESS CurrentProcess,
    _In_ PMMPTE Proto,
    _In_ PMMPTE_FLUSH_LIST FlushList,
    _In_ KIRQL OldIrql)
{
    PMMPFN Pfn;
    PMMPFN PteFramePfn;
    PMMPDE Pde = NULL;
    MMPTE TempPte;
    PFN_NUMBER PageFrameIndex;
    PFN_NUMBER PageNumber;
    ULONG WsIndex;

    DPRINT("MiDeletePte: Pte %p [%p], Va %p, Proto %p [%p], OldIrql %X\n",
           Pte, (Pte ? Pte->u.Long : 0), Va, Proto, (Proto ? Proto->u.Long : 0), OldIrql);

    /* PFN lock must be held */
    MI_ASSERT_PFN_LOCK_HELD();

    /* Capture the PTE */
    TempPte = *Pte;

    /* See if the PTE is valid */
    if (TempPte.u.Hard.Valid)
    {
        /* Get the PFN entry */
        PageFrameIndex = PFN_FROM_PTE(&TempPte);
        Pfn = MiGetPfnEntry(PageFrameIndex);
        WsIndex = Pfn->u1.WsIndex;

        /* Check if this is a valid, prototype PTE */
        if (Pfn->u3.e1.PrototypePte)
        {
            ASSERT(KeGetCurrentIrql() > APC_LEVEL);

            if (!Pfn->u3.e1.Modified && Pte->u.Hard.Dirty)
            {
                ASSERT(Pfn->u3.e1.Rom == 0);
                Pfn->u3.e1.Modified = 1;

                if (!Pfn->OriginalPte.u.Soft.Prototype && !Pfn->u3.e1.WriteInProgress)
                {
                    DPRINT1("MiDeletePte: FIXME\n");
                    ASSERT(FALSE);
                }
            }

            /* Get the PDE and make sure it's faulted in */
            Pde = MiPteToPde(Pte);

            /* Could be paged pool access from a new process -- synchronize the page directories */
            if (!Pde->u.Hard.Valid && !NT_SUCCESS(MiCheckPdeForPagedPool(Va)))
            {
                /* The PDE must be valid at this point */
                KeBugCheckEx(MEMORY_MANAGEMENT, 0x61940, (ULONG_PTR)Pte, Pte->u.Long, (ULONG_PTR)Va);
            }

            /* Drop the share count on the page table */
            PageNumber = Pde->u.Hard.PageFrameNumber;
            DPRINT("MiDeletePte: Pde %p, PageNumber %X\n", Pde, PageNumber);

            MiDecrementShareCount(MiGetPfnEntry(PageNumber), PageNumber);

            /* Drop the share count */
            MiDecrementShareCount(Pfn, PageFrameIndex);

            /* Either a fork, or this is the shared user data page */
            if (Pte <= MiHighestUserPte && Proto != Pfn->PteAddress)
            {
                /* If it's not the shared user page, then crash, since there's no fork() yet */
                if (PAGE_ALIGN(Va) != (PVOID)USER_SHARED_DATA ||
                    MmHighestUserAddress <= (PVOID)USER_SHARED_DATA)
                {
                    DPRINT1("MiDeletePte: Pte %p [%p], Va %p, Proto %p, Pfn %p, Pfn->PteAddress %p, OldIrql %X\n", Pte, TempPte.u.Long, Va, Proto, Pfn, Pfn->PteAddress, OldIrql);
                    ASSERT(FALSE);
                    /* Must be some sort of memory corruption */
                    KeBugCheckEx(MEMORY_MANAGEMENT, 0x400, (ULONG_PTR)Pte, (ULONG_PTR)Proto, (ULONG_PTR)Pfn->PteAddress);
                }
            }
        }
        else
        {
            /* Make sure the saved PTE address is valid */
            if ((PMMPTE)((ULONG_PTR)Pfn->PteAddress & ~0x1) != Pte)
            {
                /* The PFN entry is illegal, or invalid */
                KeBugCheckEx(MEMORY_MANAGEMENT, 0x401, (ULONG_PTR)Pte, Pte->u.Long, (ULONG_PTR)Pfn->PteAddress);
            }

            /* There should only be 1 shared reference count */
            ASSERT(Pfn->u2.ShareCount == 1);
    
            /* Drop the reference on the page table. */
            DPRINT("MiDeletePte: Pfn->u4.PteFrame %X\n", Pfn->u4.PteFrame);
            MiDecrementShareCount(MiGetPfnEntry(Pfn->u4.PteFrame), Pfn->u4.PteFrame);
    
            /* Mark the PFN for deletion and dereference what should be the last ref */
            MI_SET_PFN_DELETED(Pfn);
            MiDecrementShareCount(Pfn, PageFrameIndex);

            /* We should eventually do this */
            CurrentProcess->NumberOfPrivatePages--;
        }

        if (!IsNotTerminateWsle)
        {
            MiTerminateWsle(Va, &CurrentProcess->Vm, WsIndex);
        }

        /* Erase it */
        MI_ERASE_PTE(Pte);

        if (!FlushList)
        {
            /* Flush the TLB */
            KeFlushSingleTb(Va, FALSE);
        }
        else if (FlushList->Count != 0x21)
        {
            ASSERT(FlushList->Count < (0x21 - 1));

            FlushList->FlushVa[FlushList->Count] = Va;
            FlushList->Count++;
        }

        if (!IsNotTerminateWsle && CurrentProcess->CloneRoot)
        {
            DPRINT1("MiDeletePte: FIXME\n");
            ASSERT(FALSE);
        }
    }
    else if (TempPte.u.Soft.Prototype)
    {
        DPRINT1("MiDeletePte: FIXME\n");
        ASSERT(FALSE);
    }
    else if (TempPte.u.Soft.Transition)
    {
        Pfn = MiGetPfnEntry(TempPte.u.Trans.PageFrameNumber);

        if ((PMMPTE)((ULONG_PTR)Pfn->PteAddress & ~1) != Pte)
        {
            DPRINT1("MiDeletePte: FIXME KeBugCheckEx()\n");
            ASSERT(FALSE);
        }

        Pfn->PteAddress = (PMMPTE)((ULONG_PTR)Pfn->PteAddress | 1);

        PageNumber = Pfn->u4.PteFrame;
        PteFramePfn = MiGetPfnEntry(PageNumber);
        MiDecrementPfnShare(PteFramePfn, PageNumber);

        if (!Pfn->u3.e2.ReferenceCount)
        {
            MiUnlinkPageFromList(Pfn);
            MiReleasePageFileSpace(Pfn->OriginalPte);
            MiInsertPageInFreeList(TempPte.u.Trans.PageFrameNumber);
        }

        CurrentProcess->NumberOfPrivatePages--;

        Pte->u.Long = 0;
    }
    else
    {
        if (TempPte.u.Soft.PageFileHigh != 0xFFFFF)
        {
            if (MiReleasePageFileSpace(TempPte))
                CurrentProcess->NumberOfPrivatePages--;
        }

        MI_ERASE_PTE(Pte);
    }

    DPRINT("MiDeletePte: return 0\n");
    return 0; // FIXME
}

VOID
NTAPI
MiDeleteVirtualAddresses(
    _In_ ULONG_PTR Va,
    _In_ ULONG_PTR EndingAddress,
    _In_ PMMVAD Vad)
{
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    PSUBSECTION Subsection;
    PVOID AddressForReferences;
    PVOID VirtualAddress; 
    PMMPDE Pde;
    PMMPTE Pte;
    PMMPTE EndPte;
    PMMPTE CurrentPte; 
    PMMPTE Proto;
    PMMPTE LastProto;
    MMPTE TempPte;
    KIRQL OldIrql = MM_NOIRQL;
    BOOLEAN AddressGap = FALSE;
    BOOLEAN IsTerminateWsle;
    BOOLEAN IsLocked = FALSE;

    //DPRINT1("MiDeleteVirtualAddresses: Va %p, EndingAddress %p, Vad %p\n", Va, EndingAddress, Vad);

    /* Grab the PTE/PDE for the address being deleted */
    Pde = MiAddressToPde(Va);
    Pte = MiAddressToPte(Va);

    DPRINT("MiDeleteVirtualAddresses: (%p, %p) Vad %p, Pde %p, Pte %p\n", Va, EndingAddress, Vad, Pde, Pte);

    /* Check if this is a section VAD or a VM VAD */
    if (Vad && !Vad->u.VadFlags.PrivateMemory && Vad->FirstPrototypePte)
    {
        /* Get the prototype PTE */
        Proto = Vad->FirstPrototypePte;
        LastProto = ULongToPtr(4);
    }
    else
    {
        /* Don't worry about prototypes */
        Proto = LastProto = NULL;
    }

    if (!CurrentProcess->CloneRoot)
        IsTerminateWsle = TRUE;
    else
        IsTerminateWsle = FALSE;

    /* Loop the PTE for each VA */
    while (TRUE)
    {
        /* First keep going until we find a valid PDE */
        while (TRUE)
        {
            ASSERT(KeAreAllApcsDisabled() == TRUE);

            if (Pde->u.Long)
            {
                /* Now check if the PDE is mapped in */
                if (!Pde->u.Hard.Valid)
                {
                    /* It isn't, so map it in */
                    MiMakeSystemAddressValid(MiPteToAddress(Pde), CurrentProcess);

                    /* Now we should have a valid PDE */
                    ASSERT(Pde->u.Hard.Valid == 1);
                }

                break;
            }

            /* There are gaps in the address space */
            AddressGap = TRUE;

            /* Still no valid PDE, try the next 4MB (or whatever) */
            Pde++;

            /* Update the PTE on this new boundary */
            Pte = MiPteToAddress(Pde);

            /* Check if all the PDEs are invalid, so there's nothing to free */
            Va = (ULONG_PTR)MiPteToAddress(Pte);
            if (Va > EndingAddress)
                return;
        }

        /* We should have a valid VA */
        ASSERT(Va <= EndingAddress);
        AddressForReferences = (PVOID)Va;

        /* Check if this is a section VAD with gaps in it */
        if (AddressGap && LastProto)
        {
            /* We need to skip to the next correct prototype PTE */
            Proto = MI_GET_PROTOTYPE_PTE_FOR_VPN(Vad, (Va / PAGE_SIZE));

            /* And we need the subsection to skip to the next last prototype PTE */
            Subsection = MiLocateSubsection(Vad, (Va / PAGE_SIZE));

            if (Subsection)
                /* Found it! */
                LastProto = &Subsection->SubsectionBase[Subsection->PtesInSubsection];
            else
                /* No more subsections, we are done with prototype PTEs */
                LastProto = NULL;
        }

        if (IsTerminateWsle)
        {
            ASSERT(CurrentProcess->CloneRoot == NULL);

            EndPte = MiAddressToPte(EndingAddress);
            CurrentPte = (PMMPTE)(((ULONG_PTR)Pte | (PAGE_SIZE - 1)) - (sizeof(MMPTE) - 1));

            if (CurrentPte > EndPte)
                CurrentPte = EndPte;

            VirtualAddress = MiPteToAddress(CurrentPte);
            do
            {
                TempPte.u.Long = CurrentPte->u.Long;

                if (TempPte.u.Hard.Valid)
                {
                  #if !defined(ONE_CPU)
                    if (TempPte.u.Hard.Writable)
                    {
                        ASSERT(TempPte.u.Hard.Dirty == 1);
                    }
                  #endif

                    MiTerminateWsle(VirtualAddress,
                                    &CurrentProcess->Vm,
                                    (MI_PFN_ELEMENT(TempPte.u.Hard.PageFrameNumber))->u1.WsIndex);
                }

                CurrentPte--;
                VirtualAddress = (PVOID)((ULONG_PTR)VirtualAddress - PAGE_SIZE);
            }
            while (CurrentPte >= Pte);
        }

        do
        {
            /* Capture the PTE */
            TempPte = *Pte;

            if (TempPte.u.Long)
            {
                MiDecrementPageTableReferences(AddressForReferences);

                /* Check if the PTE is actually mapped in */
                if (MI_IS_MAPPED_PTE(&TempPte))
                {
                    /* Are we dealing with section VAD? */
                    if (LastProto && Proto >= LastProto)
                    {
                        /* We need to skip to the next correct prototype PTE */
                        Proto = MI_GET_PROTOTYPE_PTE_FOR_VPN(Vad, (Va / PAGE_SIZE));

                        /* And we need the subsection to skip to the next last prototype PTE */
                        Subsection = MiLocateSubsection(Vad, (Va / PAGE_SIZE));

                        if (Subsection)
                            /* Found it! */
                            LastProto = &Subsection->SubsectionBase[Subsection->PtesInSubsection];
                        else
                            /* No more subsections, we are done with prototype PTEs */
                            LastProto = NULL;
                    }

                    /* Check for prototype PTE */
                    if (!TempPte.u.Hard.Valid && TempPte.u.Soft.Prototype &&
                        IsTerminateWsle)
                    {
                        ASSERT(CurrentProcess->CloneRoot == NULL);

                        /* Just nuke it */
                        //DPRINT("MiDeleteVirtualAddresses: prototype Pte %p [%p] not Valid\n", Pte, TempPte.u.Long);
                        MI_ERASE_PTE(Pte);
                    }
                    else
                    {
                        if (!IsLocked)
                        {
                            /* Lock the PFN Database while we delete the PTEs */
                            OldIrql = MiLockPfnDb(APC_LEVEL);
                            IsLocked = TRUE;
                        }

                        //DPRINT1("MiDeleteVirtualAddresses: Pte %p [%p], Va %p, Proto %p, OldIrql %X\n", Pte, TempPte.u.Long, Va, Proto, OldIrql);

                        /* Delete the PTE proper */
                        MiDeletePte(Pte, (PVOID)Va, IsTerminateWsle, CurrentProcess, Proto, NULL, OldIrql);
                    }
                }
                else
                {
                    /* The PTE was never mapped, just nuke it here */
                    //DPRINT("MiDeleteVirtualAddresses: Pte %p [%p] was never mapped\n", Pte, TempPte.u.Long);
                    MI_ERASE_PTE(Pte);
                }
            }
            else
            {
                ;//DPRINT("MiDeleteVirtualAddresses: content Pte %p is null\n", Pte);
            }

            /* Update the address and PTE for it */
            Va += PAGE_SIZE;
            Pte++;
            Proto++;

            /* Making sure the PDE is still valid */
            ASSERT(Pde->u.Hard.Valid == 1);
        }
        while ((Va & (PDE_MAPPED_VA - 1)) && Va <= EndingAddress);

        /* The PDE should still be valid at this point */
        ASSERT(Pde->u.Hard.Valid == 1);

        /* Check remaining PTE count (go back 1 page due to above loop) */
        if (!MiQueryPageTableReferences(AddressForReferences))
        {
            if (Pde->u.Long)
            {
                if (!IsLocked)
                {
                    /* Lock the PFN Database while we delete the PTEs */
                    OldIrql = MiLockPfnDb(APC_LEVEL);
                    IsLocked = TRUE;
                }

                 /* Delete the PTE proper */
                MiDeletePte(Pde, MiPteToAddress(Pde), FALSE, CurrentProcess, NULL, NULL, OldIrql);

                ASSERT(OldIrql != MM_NOIRQL);
                MiUnlockPfnDb(OldIrql, APC_LEVEL);
                IsLocked = FALSE;
            }
        }

        /* Release the lock and get out if we're done */
        if (IsLocked)
        {
            ASSERT(OldIrql != MM_NOIRQL);
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            IsLocked = FALSE;
        }

        if (Va > EndingAddress)
            return;

        /* Otherwise, we exited because we hit a new PDE boundary, so start over */
        Pde = MiAddressToPde(Va);
        AddressGap = FALSE;
    }
}

BOOLEAN
NTAPI
MiMakeSystemAddressValidPfn(
    _In_ PVOID VirtualAddress,
    _In_ KIRQL OldIrql)
{
    BOOLEAN Result = FALSE;
    NTSTATUS Status;
  
    DPRINT("MiMakeSystemAddressValidPfn: VA %p (%X)\n", VirtualAddress, OldIrql);

    ASSERT("VirtualAddress > MM_HIGHEST_USER_ADDRESS");

    while (!MiIsAddressValid(VirtualAddress))
    {
        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        Status = MmAccessFault(0, VirtualAddress, KernelMode, NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("MiMakeSystemAddressValidPfn: VirtualAddress %p, Status %X\n", VirtualAddress, Status);
            KeBugCheckEx(0x7A, 3, Status, (ULONG_PTR)VirtualAddress, 0);
        }

        OldIrql = MiLockPfnDb(APC_LEVEL);

        Result = TRUE;
    }

    DPRINT("MiMakeSystemAddressValidPfn: Result %X\n", Result);

    return Result;
}

ULONG
NTAPI
MiGetPageProtection(
    _In_ PMMPTE Pte)
{
    PEPROCESS CurrentProcess;
    PETHREAD CurrentThread;
    PMMPTE Pde;
    PMMPFN Pfn;
    PMMPTE Proto;
    MMPTE PteContents;
    ULONG Protect;
    BOOLEAN WsShared = 0;
    BOOLEAN WsSafe = 0;
    KIRQL OldIrql;

    ASSERT(Pte < (PMMPTE)PTE_TOP);

    PteContents.u.Long = Pte->u.Long;
    ASSERT(PteContents.u.Long != 0);

    DPRINT("MiGetPageProtection: Pte %p [%X]\n", Pte, PteContents.u.Long);

    if (PteContents.u.Soft.Valid || !PteContents.u.Soft.Prototype)
    {
        if (!PteContents.u.Hard.Valid)
            return MmProtectToValue[PteContents.u.Soft.Protection];

        Pfn = MI_PFN_ELEMENT(PteContents.u.Hard.PageFrameNumber);

        if (Pfn->u3.e1.PrototypePte)
        {
            DPRINT("MiGetPageProtection: FIXME MiLocateWsle()\n");
            return MmProtectToValue[Pfn->OriginalPte.u.Soft.Protection];
        }

        if (!Pfn->u4.AweAllocation)
            return MmProtectToValue[Pfn->OriginalPte.u.Soft.Protection];

        if (!PteContents.u.Hard.Owner)
            return PAGE_NOACCESS;

        if (PteContents.u.Hard.Write)
            return PAGE_READWRITE;

        return PAGE_READONLY;
    }

    if (PteContents.u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED)
        return MmProtectToValue[PteContents.u.Soft.Protection];

    CurrentThread = PsGetCurrentThread();
    CurrentProcess = PsGetCurrentProcess();

    MiUnlockProcessWorkingSetForFault(CurrentProcess, CurrentThread, &WsSafe, &WsShared);

    Proto = MiGetProtoPtr(&PteContents);
    PteContents.u.Long = Proto->u.Long;

    if (PteContents.u.Hard.Valid)
    {
        Pde = MiAddressToPde(Proto);

        OldIrql = MiLockPfnDb(APC_LEVEL);

        if (!Pde->u.Hard.Valid)
            MiMakeSystemAddressValidPfn(Proto, OldIrql);

        PteContents.u.Long = Proto->u.Long;
        ASSERT(PteContents.u.Long != 0);

        if (PteContents.u.Hard.Valid)
        {
            Pfn = MI_PFN_ELEMENT(PteContents.u.Hard.PageFrameNumber);
            Protect = MmProtectToValue[Pfn->OriginalPte.u.Soft.Protection];
        }
        else
        {
            Protect = MmProtectToValue[PteContents.u.Soft.Protection];
        }

        MiUnlockPfnDb(OldIrql, APC_LEVEL);
    }
    else
    {
        Protect = MmProtectToValue[PteContents.u.Soft.Protection];
    }

    MiLockProcessWorkingSetForFault(CurrentProcess, CurrentThread, WsSafe, WsShared);

    return Protect;
}

VOID
NTAPI
MiFlushTbAndCapture(
    _In_ PMMVAD Vad,
    _In_ PMMPTE Pte,
    _In_ ULONG ProtectionMask,
    _In_ PMMPFN Pfn,
    _In_ BOOLEAN UpdateDirty)
{
    //PVOID Address; 
    MMPTE PreviousPte;
    MMPTE TempPte;
    PFN_NUMBER PageNumber;
    ULONG CacheAttribute;
    ULONG CacheType;
    KIRQL OldIrql;

    DPRINT("MiFlushTbAndCapture: %p, %p, %X, Pfn %p, %X\n", Vad, Pte, ProtectionMask, Pfn, UpdateDirty);

     /* User for sanity checking later on */
    ASSERT(Pte <= MiHighestUserPte);
    //Address = MiPteToAddress(Pte);

    PageNumber = Pte->u.Hard.PageFrameNumber;

    /* Build the PTE and acquire the PFN lock */
    MI_MAKE_HARDWARE_PTE_USER(&TempPte, Pte, ProtectionMask, PageNumber);

    /* Lock the PFN database */
    OldIrql = MiLockPfnDb(APC_LEVEL);

    PreviousPte = *Pte;

    if (!Pfn)
    {
        if (ProtectionMask >> 3 == 1)
        {
            CacheType = MmNonCached;
        }
        else if (ProtectionMask >> 3 == 3 && (ProtectionMask & 7))
        {
            CacheType = MmWriteCombined;
        }
        else
        {
            CacheType = MmCached;
        }

        CacheAttribute = MiPlatformCacheAttributes[1][CacheType];

        if (CacheAttribute == MiNonCached)
        {
            TempPte.u.Hard.WriteThrough = 1;
            TempPte.u.Hard.CacheDisable = 1;
        }
        else if (CacheAttribute == MiCached)
        {
            TempPte.u.Hard.WriteThrough = 0;
            TempPte.u.Hard.CacheDisable = 0;
        }
        else if (CacheAttribute == MiWriteCombined)
        {
            if (MiWriteCombiningPtes)
            {
                TempPte.u.Hard.WriteThrough = 1;
                TempPte.u.Hard.CacheDisable = 0;
            }
            else
            {
                TempPte.u.Hard.WriteThrough = 0;
                TempPte.u.Hard.CacheDisable = 1;
            }
        }

        if (ProtectionMask & 4)
            MI_MAKE_DIRTY_PAGE(&TempPte);
    }
    else
    {
        if (Pfn->u3.e1.CacheAttribute == MiNonCached)
        {
            if ((ProtectionMask & 0x18) != MM_NOCACHE)
            {
                ProtectionMask &= ~0x10;
                ProtectionMask |= MM_NOCACHE;
                MI_MAKE_HARDWARE_PTE_USER(&TempPte, Pte, ProtectionMask, PageNumber);
            }
        }
        else if (Pfn->u3.e1.CacheAttribute == MiCached)
        {
            if (ProtectionMask & 0x18)
            {
                ProtectionMask &= ~0x18;
                MI_MAKE_HARDWARE_PTE_USER(&TempPte, Pte, ProtectionMask, PageNumber);
            }
        }
        else if (Pfn->u3.e1.CacheAttribute == MiWriteCombined)
        {
            if ((ProtectionMask & MM_WRITECOMBINE) != MM_WRITECOMBINE)
            {
                ProtectionMask |= MM_WRITECOMBINE;
                MI_MAKE_HARDWARE_PTE_USER(&TempPte, Pte, ProtectionMask, PageNumber);
            }
        }
    }

    MI_UPDATE_VALID_PTE(Pte, TempPte);

    /* Flush the TLB */
    ASSERT(PreviousPte.u.Hard.Valid == 1);
    //FIXME should be:
    //KeFlushSingleTb(Address, 0);
    KeFlushCurrentTb();
    ASSERT(PreviousPte.u.Hard.Valid == 1);

    if (UpdateDirty)
    {
        ASSERT(Pfn != NULL);
        ASSERT(KeGetCurrentIrql() > APC_LEVEL);

        if (!Pfn->u3.e1.Modified && PreviousPte.u.Hard.Dirty)
        {
            ASSERT(Pfn->u3.e1.Rom == 0);
            Pfn->u3.e1.Modified = 1;

            if (!Pfn->OriginalPte.u.Soft.Prototype &&
                !Pfn->u3.e1.WriteInProgress)
            {
                DPRINT1("MiFlushTbAndCapture: FIXME MiReleasePageFileSpace()\n");
                ASSERT(FALSE);
            }
        }
    }

    if (Vad->u.VadFlags.VadType == VadWriteWatch)
    {
        ASSERT((PsGetCurrentProcess()->Flags & PSF_WRITE_WATCH_BIT) != 0);
        ASSERT(Pfn->u3.e1.PrototypePte == 0);

        if (PreviousPte.u.Hard.Dirty)
        {
            DPRINT1("MiFlushTbAndCapture: FIXME MiCaptureWriteWatchDirtyBit()\n");
            ASSERT(FALSE);
        }
    }

    /* Release the PFN lock */
    MiUnlockPfnDb(OldIrql, APC_LEVEL);
}

NTSTATUS
NTAPI
MiSetProtectionOnSection(
    _In_ PEPROCESS Process,
    _In_ PMMVAD FoundVad,
    _In_ ULONG_PTR StartingAddress,
    _In_ ULONG_PTR EndingAddress,
    _In_ ULONG NewProtect,
    _Out_ ULONG* OutProtection,
    _In_ ULONG DontCharge,
    _Out_ BOOLEAN* OutLocked)
{
    PETHREAD Thread = PsGetCurrentThread();
    PMMPDE Pde;
    PMMPTE Pte;
    PMMPTE LastPte;
    PMMPTE Proto;
    PMMPTE ProtoPte;
    MMPTE TempPte;
    MMPTE PteContents;
    PMMPFN Pfn;
    ULONG_PTR VirtualAddress;
    ULONG ProtectionMask;
    ULONG ProtectionMask1;
    ULONG ProtectionMask2;
    ULONG QuotaCharge = 0;
    BOOLEAN IsWriteCopy = FALSE;
    BOOLEAN UpdateDirty;
    KIRQL OldIrql;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("MiSetProtectionOnSection: %p, %p, %p, %X, %X\n", Process, StartingAddress, EndingAddress, NewProtect, DontCharge);

    /* Tell caller nothing is being locked */
    *OutLocked = FALSE;

    /* This function should only be used for section VADs. Windows ASSERT */
    ASSERT(FoundVad->u.VadFlags.PrivateMemory == 0);

    if (FoundVad->u.VadFlags.VadType == VadImageMap ||
        FoundVad->u2.VadFlags2.CopyOnWrite)
    {
        if (NewProtect & PAGE_READWRITE)
        {
            NewProtect &= ~PAGE_READWRITE;
            NewProtect |= PAGE_WRITECOPY;
        }

        if (NewProtect & PAGE_EXECUTE_READWRITE)
        {
            NewProtect &= ~PAGE_EXECUTE_READWRITE;
            NewProtect |= PAGE_EXECUTE_WRITECOPY;
        }
    }

    /* Convert and validate the protection mask */
    ProtectionMask = MiMakeProtectionMask(NewProtect);
    if (ProtectionMask == MM_INVALID_PROTECTION)
    {
        DPRINT1("MiSetProtectionOnSection: Invalid section protect\n");
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    ProtectionMask1 = ProtectionMask;
    if ((ProtectionMask & MM_WRITECOPY) == MM_WRITECOPY)
    {
        IsWriteCopy = TRUE;
        ProtectionMask1 = (ProtectionMask1 & ~1);
        DPRINT("MiSetProtectionOnSection: IsWriteCopy, ProtectionMask1 %X\n", ProtectionMask1);
    }

    /* Get the PTE and PDE for the address, as well as the final PTE */
    Pde = MiAddressToPde(StartingAddress);
    Pte = MiAddressToPte(StartingAddress);
    LastPte = MiAddressToPte(EndingAddress);

    DPRINT("MiSetProtectionOnSection: Pde %p, Pte %p, LastPte %p\n", Pde, Pte, LastPte);

    MiLockProcessWorkingSetUnsafe(Process, Thread);

    /* Make the PDE valid, and check the status of the first PTE */
    MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);

    if (Pte->u.Long)
    {
        if (FoundVad->u.VadFlags.VadType == VadRotatePhysical)
        {
            /* Not supported in ARM3 */
            ASSERT(FoundVad->u.VadFlags.VadType != VadRotatePhysical);
        }
        else
        {
            /* Capture the page protection and make the PDE valid */
            *OutProtection = MiGetPageProtection(Pte);
            MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);
        }
    }
    else
    {
        /* Grab the old protection from the VAD itself */
        *OutProtection = MmProtectToValue[FoundVad->u.VadFlags.Protection];

        if (FoundVad->u.VadFlags.VadType != VadImageMap)
        {
            /* Grab the old protection from the VAD itself */
            *OutProtection = MmProtectToValue[FoundVad->u.VadFlags.Protection];
        }
        else
        {
            VirtualAddress = (ULONG_PTR)MiPteToAddress(Pte);
            Proto = MI_GET_PROTOTYPE_PTE_FOR_VPN(FoundVad, (VirtualAddress / PAGE_SIZE));

            MiUnlockProcessWorkingSetUnsafe(Process, Thread);

            TempPte = *Proto;

            if (!TempPte.u.Hard.Valid)
            {
                *OutProtection = MmProtectToValue[TempPte.u.Soft.Protection];
            }
            else
            {
                OldIrql = MiLockPfnDb(APC_LEVEL);
                DPRINT1("MiSetProtectionOnSection: VA %p, Proto %p, TempPte %p\n", VirtualAddress, Proto, TempPte);

                ProtoPte = MiAddressToPte(Proto);

                if (!ProtoPte->u.Hard.Valid)
                    MiMakeSystemAddressValidPfn(Proto, OldIrql);

                TempPte = *Proto;

                ASSERT(TempPte.u.Long != 0);

                if (TempPte.u.Hard.Valid)
                {
                    PMMPFN pfn = MI_PFN_ELEMENT(TempPte.u.Hard.PageFrameNumber);

                    *OutProtection = MmProtectToValue[pfn->OriginalPte.u.Soft.Protection];
                }
                else
                {
                    *OutProtection = MmProtectToValue[TempPte.u.Soft.Protection];
                }

                MiUnlockPfnDb(OldIrql, APC_LEVEL);
            }

            MiLockProcessWorkingSetUnsafe(Process, Thread);
            MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);
        }
    }

    if (IsWriteCopy)
    {
        ASSERT(FoundVad->u.VadFlags.VadType != VadRotatePhysical);

        for (; Pte <= LastPte; Pte++)
        {
            if (MiIsPteOnPdeBoundary(Pte))
            {
                PMMPTE OldPte;
                ULONG LockChange;

                Pde = MiPteToPde(Pte);
                DPRINT("MiSetProtectionOnSection: IsWriteCopy\n");

                do
                {
                    LockChange = 0;

                    while (TRUE)
                    {
                        ASSERT(KeAreAllApcsDisabled() == TRUE);

                        if (Pde->u.Long)
                        {
                            if (!Pde->u.Hard.Valid)
                                LockChange += MiMakeSystemAddressValid(MiPteToAddress(Pde), Process);

                            break;
                        }

                        OldPte = Pte;
                        Pde++;
                        Pte = MiPteToAddress(Pde);

                        if (Pte > LastPte)
                        {
                            QuotaCharge += ((LastPte - OldPte) + 1);
                            goto EndWriteCopy;
                        }

                        QuotaCharge += (Pte - OldPte);
                    }
                }
                while (LockChange);
            }

            TempPte = *Pte;

            if (!TempPte.u.Long)
            {
                QuotaCharge++;
            }
            else if (TempPte.u.Hard.Valid)
            {
                if (!TempPte.u.Hard.CopyOnWrite)
                {
                    Pfn = MI_PFN_ELEMENT(TempPte.u.Hard.PageFrameNumber);
                    if (Pfn->u3.e1.PrototypePte)
                        QuotaCharge++;
                }
            }
            else
            {
                if (TempPte.u.Soft.Prototype)
                {
                    if (TempPte.u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED)
                    {
                        if (!((TempPte.u.Soft.Protection & MM_WRITECOPY) != MM_WRITECOPY))
                            QuotaCharge++;
                    }
                    else
                    {
                        QuotaCharge++;
                    }
                }
            }
        }

EndWriteCopy:

        if (!DontCharge && QuotaCharge > 0)
        {
            MiUnlockProcessWorkingSetUnsafe(Process, Thread);

            Status = PsChargeProcessPageFileQuota(Process, QuotaCharge);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("MiSetProtectionOnSection: STATUS_PAGEFILE_QUOTA_EXCEEDED\n");
                return STATUS_PAGEFILE_QUOTA_EXCEEDED;
            }

            if (Process->CommitChargeLimit &&
                Process->CommitChargeLimit < (Process->CommitCharge + QuotaCharge))
            {
                DPRINT1("MiSetProtectionOnSection: FIXME\n");
                ASSERT(FALSE);
            }

            if (Process->JobStatus & 0x10)
            {
                DPRINT1("MiSetProtectionOnSection: FIXME\n");
                ASSERT(FALSE);
            }

            if (!MiChargeCommitment(QuotaCharge, 0))
            {
                DPRINT1("MiSetProtectionOnSection: FIXME\n");
                ASSERT(FALSE);
            }

            FoundVad->u.VadFlags.CommitCharge += QuotaCharge;
            Process->CommitCharge += QuotaCharge;

            if (Process->CommitChargePeak < Process->CommitCharge)
                Process->CommitChargePeak = Process->CommitCharge;

            MiLockProcessWorkingSetUnsafe(Process, Thread);
        }
    }

    /* Loop all the PTEs now */
    Pde = MiAddressToPde(StartingAddress);
    Pte = MiAddressToPte(StartingAddress);

    MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);

    QuotaCharge = 0;

    while (Pte <= LastPte)
    {
        /* Check if we've crossed a PDE boundary and make the new PDE valid too */
        if (MiIsPteOnPdeBoundary(Pte))
        {
            Pde = MiPteToPde(Pte);
            MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);
        }

        /* Capture the PTE and see what we're dealing with */
        PteContents = *Pte;

        if (!PteContents.u.Long)
        {
            /* This used to be a zero PTE and it no longer is, so we must add a reference to the pagetable. */
            MiIncrementPageTableReferences(MiPteToAddress(Pte));

            /* Create the demand-zero prototype PTE */
            TempPte = PrototypePte;
            TempPte.u.Soft.Protection = ProtectionMask;
            MI_WRITE_INVALID_PTE(Pte, TempPte);
        }
        else if (PteContents.u.Hard.Valid)
        {
            ProtectionMask2 = ProtectionMask;

            /* Get the PFN entry */
            Pfn = MiGetPfnEntry(PFN_FROM_PTE(&PteContents));

            if (NewProtect & (PAGE_NOACCESS | PAGE_GUARD))
            {
                ASSERT(FoundVad->u.VadFlags.VadType != VadRotatePhysical);

                DPRINT1("MiSetProtectionOnSection: FIXME MiRemovePageFromWorkingSet()\n");
                ASSERT(FALSE);
                *OutLocked = FALSE;
                continue;
            }

            UpdateDirty = TRUE;

            if (FoundVad->u.VadFlags.VadType == VadRotatePhysical)
            {
                DPRINT1("MiSetProtectionOnSection: FIXME\n");
                ASSERT(FALSE);
            }
            else if (Pfn->u3.e1.PrototypePte)
            {
                VirtualAddress = (ULONG_PTR)MiPteToAddress(Pte);

                Proto = MI_GET_PROTOTYPE_PTE_FOR_VPN(FoundVad, (VirtualAddress / PAGE_SIZE));

                if (Pfn->PteAddress != Proto)
                {
                    if (MiCopyOnWrite((PVOID)VirtualAddress, Pte))
                    {
                        if (IsWriteCopy && !PteContents.u.Hard.CopyOnWrite)
                            QuotaCharge++;
                    }

                    MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);
                    continue;
                }

                if (!IsWriteCopy && PteContents.u.Hard.CopyOnWrite)
                    QuotaCharge++;

                DPRINT("MiSetProtectionOnSection: FIXME MiLocateWsle()\n");
            }
            else
            {
                /* Write the protection mask */
                Pfn->OriginalPte.u.Soft.Protection = ProtectionMask1;
                ProtectionMask2 = ProtectionMask1;
            }

            /* TLB flush */
            MiFlushTbAndCapture(FoundVad, Pte, ProtectionMask2, Pfn, UpdateDirty);

            if (FoundVad->u.VadFlags.VadType == VadRotatePhysical)
            {
                DPRINT1("MiSetProtectionOnSection: FIXME\n");
                ASSERT(FALSE);
            }
        }
        else if (PteContents.u.Soft.Prototype)
        {
            VirtualAddress = (ULONG_PTR)MiPteToAddress(Pte);

            if (PteContents.u.Soft.PageFileHigh != MI_PTE_LOOKUP_NEEDED &&
                MiGetProtoPtr(Pte) != MI_GET_PROTOTYPE_PTE_FOR_VPN(FoundVad, (VirtualAddress / PAGE_SIZE)))
            {
                DPRINT1("MiSetProtectionOnSection: FIXME\n");
                ASSERT(FALSE);
            }
            else
            {
                if (!IsWriteCopy && PteContents.u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED)
                {
                    if ((PteContents.u.Soft.Protection & MM_WRITECOPY) != MM_WRITECOPY)
                        QuotaCharge++;
                }

                MI_WRITE_INVALID_PTE(Pte, PrototypePte);
                Pte->u.Soft.Protection = ProtectionMask;
            }
        }
        else
        {
            ASSERT(FoundVad->u.VadFlags.VadType != VadRotatePhysical);

            DPRINT1("MiSetProtectionOnSection: FIXME\n");
            ASSERT(FALSE);
        }

        Pte++;
    }

    /* Unlock the working set and update quota charges if needed, then return */
    MiUnlockProcessWorkingSetUnsafe(Process, Thread);

    if (QuotaCharge > 0 && !DontCharge)
    {
        ASSERT((SSIZE_T)(QuotaCharge) >= 0);
        ASSERT(MmTotalCommittedPages >= (QuotaCharge));
        InterlockedExchangeAddSizeT(&MmTotalCommittedPages, -QuotaCharge);

        PsReturnProcessPageFileQuota(Process, QuotaCharge);

        if (QuotaCharge > FoundVad->u.VadFlags.CommitCharge)
        {
            DPRINT1("MiSetProtectionOnSection: %p, %p, %X, %X\n", Process, FoundVad, FoundVad->u.VadFlags.CommitCharge, QuotaCharge);
            DbgBreakPoint();
        }

        if (Process->JobStatus & 0x10)
        {
            DPRINT1("MiSetProtectionOnSection: FIXME\n");
            ASSERT(FALSE);
        }

        Process->CommitCharge -= QuotaCharge;
    }

    return STATUS_SUCCESS;
}

BOOLEAN
NTAPI
MiIsEntireRangeCommitted(
    _In_ ULONG_PTR StartingAddress,
    _In_ ULONG_PTR EndingAddress,
    _In_ PMMVAD Vad,
    _In_ PEPROCESS Process)
{
    PMMPDE Pde;
    PMMPTE Pte;
    PMMPTE LastPte;
    BOOLEAN OnBoundary = TRUE;

    PAGED_CODE();

    /* Get the PDE and PTE addresses */
    Pde = MiAddressToPde(StartingAddress);
    Pte = MiAddressToPte(StartingAddress);
    LastPte = MiAddressToPte(EndingAddress);

    /* Loop all the PTEs */
    while (Pte <= LastPte)
    {
        /* Check if we've hit an new PDE boundary */
        if (OnBoundary)
        {
            /* Is this PDE demand zero? */
            Pde = MiPteToPde(Pte);

            if (Pde->u.Long)
            {
                /* It isn't -- is it valid? */
                if (!Pde->u.Hard.Valid)
                    /* Nope, fault it in */
                    MiMakeSystemAddressValid(Pte, Process);
            }
            else
            {
                /* The PTE was already valid, so move to the next one */
                Pde++;
                Pte = MiPdeToPte(Pde);

                /* Is the entire VAD committed? If not, fail */
                if (!Vad->u.VadFlags.MemCommit)
                    return FALSE;

                /* New loop iteration with our new, on-boundary PTE. */
                continue;
            }
        }

        /* Is the PTE demand zero? */
        if (!Pte->u.Long)
        {
            /* Is the entire VAD committed? If not, fail */
            if (!Vad->u.VadFlags.MemCommit)
                return FALSE;
        }
        /* It isn't -- is it a decommited, invalid, or faulted PTE? */
        else if (Pte->u.Soft.Protection == MM_DECOMMIT &&
                 !Pte->u.Hard.Valid &&
                 (!Pte->u.Soft.Prototype || Pte->u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED))
        {
            /* Then part of the range is decommitted, so fail */
            return FALSE;
        }

        /* Move to the next PTE */
        Pte++;
        OnBoundary = MiIsPteOnPdeBoundary(Pte);
    }

    /* All PTEs seem valid, and no VAD checks failed, the range is okay */
    return TRUE;
}

NTSTATUS
NTAPI
MiProtectVirtualMemory(
    _In_ PEPROCESS Process,
    _Inout_ PVOID* OutBase,
    _Inout_ SIZE_T* OutSize,
    _In_ ULONG NewProtection,
    _Out_ ULONG* OutProtection OPTIONAL)
{
    PETHREAD Thread = PsGetCurrentThread();
    PMMSUPPORT AddressSpace;
    PMMPDE Pde;
    PMMPTE Pte;
    PMMPTE LastPte;
    PMMPTE Proto;
    PMMPTE LastProto;
    MMPTE PteContents;
    PMMVAD Vad;
    PMMPFN Pfn;
    ULONG_PTR StartingAddress;
    ULONG_PTR EndingAddress;
    ULONG ProtectionMask;
    ULONG OldProtect;
    BOOLEAN Committed;
    BOOLEAN IsLock = FALSE;

    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("MiProtectVirtualMemory: %p, %X, %X\n", Process, NewProtection, (OutProtection ? *OutProtection : 0));

    /* Calculate the protection mask and make sure it's valid */
    ProtectionMask = MiMakeProtectionMask(NewProtection);
    if (ProtectionMask == MM_INVALID_PROTECTION)
    {
        DPRINT1("MiProtectVirtualMemory: Invalid protection mask\n");
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    /* Calculate base address for the VAD */
    StartingAddress = (ULONG_PTR)PAGE_ALIGN(*OutBase);
    EndingAddress = (((ULONG_PTR)*OutBase + *OutSize - 1) | (PAGE_SIZE - 1));

    /* Lock the address space and make sure the process isn't already dead */
    AddressSpace = MmGetCurrentAddressSpace();
    MmLockAddressSpace(AddressSpace);

    if (Process->VmDeleted)
    {
        DPRINT1("MiProtectVirtualMemory: Process is dying\n");
        Status = STATUS_PROCESS_IS_TERMINATING;
        goto ErrorExit;
    }

    /* Get the VAD for this address range, and make sure it exists */
    Vad = (PMMVAD)MiCheckForConflictingNode((StartingAddress / PAGE_SIZE),
                                            (EndingAddress / PAGE_SIZE),
                                            &Process->VadRoot);
    if (!Vad)
    {
        DPRINT("MiProtectVirtualMemory: Could not find a VAD for this allocation\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto ErrorExit;
    }

    /* Make sure the address is within this VAD's boundaries */
    if (((ULONG_PTR)StartingAddress / PAGE_SIZE) < Vad->StartingVpn ||
        ((ULONG_PTR)EndingAddress / PAGE_SIZE) > Vad->EndingVpn)
    {
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto ErrorExit;
    }

    if (Vad->u.VadFlags.VadType == VadLargePages)
    {
        if (ProtectionMask == Vad->u.VadFlags.Protection)
        {
            DPRINT1("MiProtectVirtualMemory: FIXME\n");
            ASSERT(FALSE);
        }

        DPRINT1("MiProtectVirtualMemory: STATUS_CONFLICTING_ADDRESSES\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto ErrorExit;
    }

    if (Vad->u.VadFlags.VadType == VadAwe)
    {
        if (ProtectionMask == 0x18 ||
            ProtectionMask == MM_READONLY ||
            ProtectionMask == MM_READWRITE)
        {
            DPRINT1("MiProtectVirtualMemory: FIXME MiProtectAweRegion()\n");
            ASSERT(FALSE);
        }

        DPRINT1("MiProtectVirtualMemory: STATUS_CONFLICTING_ADDRESSES\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto ErrorExit;
    }

    /* This kind of VADs are not supported */
    if (Vad->u.VadFlags.VadType == VadDevicePhysicalMemory)
    {
        DPRINT1("MiProtectVirtualMemory: Illegal VAD for attempting to set protection\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto ErrorExit;
    }

    /* Check for a VAD whose protection can't be changed */
    if (Vad->u.VadFlags.NoChange)
    {
        DPRINT1("MiProtectVirtualMemory: FIXME MiCheckSecuredVad()\n");
        ASSERT(FALSE);
    }

    /* Is this section, or private memory? */
    if (!Vad->u.VadFlags.PrivateMemory)
    {
        if (Vad->u.VadFlags.VadType == VadLargePageSection)
        {
            if (ProtectionMask == Vad->u.VadFlags.Protection)
            {
                /* Not yet supported */
                DPRINT1("MiProtectVirtualMemory: FIXME\n");
                ASSERT(FALSE);
            }

            DPRINT1("MiProtectVirtualMemory: Illegal VAD for attempting to set protection\n");
            Status = STATUS_CONFLICTING_ADDRESSES;
            goto ErrorExit;
        }

        if (Vad->u.VadFlags.VadType == VadRotatePhysical)
        {
            if ((NewProtection & PAGE_EXECUTE_WRITECOPY) ||
                (NewProtection & PAGE_WRITECOPY) ||
                (NewProtection & PAGE_NOACCESS) ||
                (NewProtection & PAGE_GUARD))
            {
                DPRINT1("MiProtectVirtualMemory: Illegal VAD for attempting to set protection\n");
                Status = STATUS_INVALID_PAGE_PROTECTION;
                goto ErrorExit;
            }
        }
        else
        {
            /* Not valid on section files */
            if (NewProtection & (PAGE_NOCACHE | PAGE_WRITECOMBINE))
            {
                DPRINT1("MiProtectVirtualMemory: Invalid protection flags for section\n");
                Status = STATUS_INVALID_PARAMETER_4;
                goto ErrorExit;
            }

            /* Check if data or page file mapping protection PTE is compatible */
            if (!Vad->ControlArea->u.Flags.Image)
            {
                if (!MiIsPteProtectionCompatible(Vad->u.VadFlags.Protection, NewProtection))
                {
                    Status = STATUS_SECTION_PROTECTION;
                    goto ErrorExit;
                }
            }
        }

        DPRINT("MiProtectVirtualMemory: Section protection\n");

        if (!Vad->ControlArea->u.Flags.File || Vad->ControlArea->u.Flags.Image)
        {
            if (Vad->u.VadFlags.VadType == VadImageMap)
            {
                DPRINT("MiProtectVirtualMemory: FIXME for large pages\n");
            }

            Proto = MI_GET_PROTOTYPE_PTE_FOR_VPN(Vad, (StartingAddress / PAGE_SIZE));
            LastProto = MI_GET_PROTOTYPE_PTE_FOR_VPN(Vad, (EndingAddress / PAGE_SIZE));

            KeAcquireGuardedMutexUnsafe(&MmSectionCommitMutex);

            for (; Proto <= LastProto; Proto++)
            {
                if (!Proto->u.Long)
                {
                    KeReleaseGuardedMutexUnsafe(&MmSectionCommitMutex);
                    Status = STATUS_NOT_COMMITTED;
                    goto ErrorExit;
                }
            }

            KeReleaseGuardedMutexUnsafe (&MmSectionCommitMutex);
        }

        Status = MiSetProtectionOnSection(Process,
                                          Vad,
                                          StartingAddress,
                                          EndingAddress,
                                          NewProtection,
                                          &OldProtect,
                                          FALSE,
                                          &IsLock);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("MiProtectVirtualMemory: Status %X\n", Status);
            goto ErrorExit;
        }
    }
    else
    {
        /* Private memory, check protection flags */
        if (NewProtection & PAGE_WRITECOPY ||
            NewProtection & PAGE_EXECUTE_WRITECOPY)
        {
            DPRINT1("MiProtectVirtualMemory: Invalid protection flags for private memory\n");
            Status = STATUS_INVALID_PARAMETER_4;
            goto ErrorExit;
        }

        /* Lock the working set */
        MiLockProcessWorkingSetUnsafe(Process, Thread);

        /* Check if all pages in this range are committed */
        Committed = MiIsEntireRangeCommitted(StartingAddress, EndingAddress, Vad, Process);
        if (!Committed)
        {
            MiUnlockProcessWorkingSetUnsafe(Process, Thread);

            DPRINT1("MiProtectVirtualMemory: The entire range is not committed\n");
            Status = STATUS_NOT_COMMITTED;
            goto ErrorExit;
        }

        /* Compute starting and ending PTE and PDE addresses */
        Pde = MiAddressToPde(StartingAddress);
        Pte = MiAddressToPte(StartingAddress);
        LastPte = MiAddressToPte(EndingAddress);

        /* Make this PDE valid */
        MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);

        /* Save protection of the first page */
        if (Pte->u.Long)
        {
            /* Capture the page protection and make the PDE valid */
            OldProtect = MiGetPageProtection(Pte);
            MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);
        }
        else
        {
            /* Grab the old protection from the VAD itself */
            OldProtect = MmProtectToValue[Vad->u.VadFlags.Protection];
        }

        /* Loop all the PTEs now */
        while (Pte <= LastPte)
        {
            /* Check if we've crossed a PDE boundary and make the new PDE valid too */
            if (MiIsPteOnPdeBoundary(Pte))
            {
                Pde = MiPteToPde(Pte);
                MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);
            }

            /* Capture the PTE and check if it was empty */
            PteContents = *Pte;
            if (!PteContents.u.Long)
            {
                /* This used to be a zero PTE and it no longer is,
                   so we must add a reference to the pagetable.
                */
                MiIncrementPageTableReferences(MiPteToAddress(Pte));
            }

            /* Check what kind of PTE we are dealing with */
            if (PteContents.u.Hard.Valid)
            {
                /* Get the PFN entry */
                Pfn = MiGetPfnEntry(PFN_FROM_PTE(&PteContents));

                if (Pfn->u3.e1.PrototypePte)
                {
                    /* We don't support this yet */
                    ASSERT(Pfn->u3.e1.PrototypePte == 0);
                }

                /* Check if the page should not be accessible at all */
                if ((NewProtection & PAGE_NOACCESS) || (NewProtection & PAGE_GUARD))
                {
                    MiRemovePageFromWorkingSet(Pte, Pfn, &Process->Vm);
                    continue;
                }

                /* Write the protection mask and write it with a TLB flush */
                Pfn->OriginalPte.u.Soft.Protection = ProtectionMask;
                MiFlushTbAndCapture(Vad, Pte, ProtectionMask, Pfn, TRUE);
            }
            else if (PteContents.u.Soft.Prototype)
            {
                /* We don't support these cases yet */
                ASSERT(PteContents.u.Soft.Prototype == 0);
            }
            else if (PteContents.u.Soft.Prototype)
            {
                /* We don't support these cases yet */
                ASSERT(PteContents.u.Soft.Transition == 0);
            }
            else
            {
                /* The PTE is already demand-zero, just update the protection mask */
                PteContents.u.Soft.Protection = ProtectionMask;
                MI_WRITE_INVALID_PTE(Pte, PteContents);
                ASSERT(Pte->u.Long != 0);
            }

            /* Move to the next PTE */
            Pte++;
        }

        /* Unlock the working set */
        MiUnlockProcessWorkingSetUnsafe(Process, Thread);
    }

    /* Unlock the address space */
    MmUnlockAddressSpace(AddressSpace);

    /* Return parameters and success */
    *OutSize = (EndingAddress - StartingAddress + 1);
    *OutBase = (PVOID)StartingAddress;
    *OutProtection = OldProtect;

    return STATUS_SUCCESS;

ErrorExit:

    /* Unlock the address space and return the failure code */
    MmUnlockAddressSpace(AddressSpace);
    return Status;
}

ULONG
NTAPI
MiQueryAddressState(
    _In_ PVOID Va,
    _In_ PMMVAD Vad,
    _In_ PEPROCESS TargetProcess,
    _Out_ ULONG* ReturnedProtect,
    _Out_ PVOID* NextVa)
{
    PMMPTE Pte;
    PMMPTE Proto;
    PMMPDE Pde;
    MMPTE TempPte;
    MMPTE TempProto;
    ULONG State = MEM_RESERVE;
    ULONG Protect = 0;
    BOOLEAN DemandZeroPte = TRUE;
    BOOLEAN ValidPte = FALSE;
    KIRQL OldIrql;

    ASSERT((Vad->StartingVpn <= ((ULONG_PTR)Va >> PAGE_SHIFT)) &&
           (Vad->EndingVpn >= ((ULONG_PTR)Va >> PAGE_SHIFT)));

    DPRINT("MiQueryAddressState: Va %p, Vad %p, VadType %X\n", Va, Vad, Vad->u.VadFlags.VadType);

    /* Get the PDE and PTE for the address */
    Pde = MiAddressToPde(Va);
    Pte = MiAddressToPte(Va);

    /* Return the next range */
    *NextVa = (PVOID)((ULONG_PTR)Va + PAGE_SIZE);

    do
    {
        /* Does the PDE exist? */
        if (!Pde->u.Long)
        {
            /* It does not, next range starts at the next PDE */
            *NextVa = MiPdeToAddress(Pde + 1);
            break;
        }

        /* Is the PDE valid? */
        if (!Pde->u.Hard.Valid)
            /* Is isn't, fault it in (make the PTE accessible) */
            MiMakeSystemAddressValid(Pte, TargetProcess);

        /* We have a PTE that we can access now! */
        ValidPte = TRUE;

    } while (FALSE);

    /* Is it safe to try reading the PTE? */
    if (ValidPte)
    {
        /* FIXME: watch out for large pages */
        ASSERT(Pde->u.Hard.LargePage == FALSE);

        /* Capture the PTE */
        TempPte = *Pte;
        if (TempPte.u.Long)
        {
            /* The PTE is valid, so it's not zeroed out */
            DemandZeroPte = FALSE;

            /* Is it a decommited, invalid, or faulted PTE? */
            if (TempPte.u.Soft.Protection == MM_DECOMMIT &&
                !TempPte.u.Hard.Valid &&
                (!TempPte.u.Soft.Prototype || TempPte.u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED))
            {
                /* Otherwise our defaults should hold */
                ASSERT(Protect == 0);
                ASSERT(State == MEM_RESERVE);
            }
            else
            {
                /* This means it's committed */
                State = MEM_COMMIT;

                /* We don't support these */
                ASSERT(Vad->u.VadFlags.VadType != VadDevicePhysicalMemory);
                ASSERT(Vad->u.VadFlags.VadType != VadRotatePhysical);
                ASSERT(Vad->u.VadFlags.VadType != VadAwe);

                /* Get protection state of this page */
                Protect = MiGetPageProtection(Pte);

                /* Check if this is an image-backed VAD */
                if (!TempPte.u.Soft.Valid &&
                    TempPte.u.Soft.Prototype &&
                    !Vad->u.VadFlags.PrivateMemory &&
                    Vad->ControlArea)
                {
                    Proto = MI_GET_PROTOTYPE_PTE_FOR_VPN(Vad, ((ULONG_PTR)Va / PAGE_SIZE));

                    if (Proto)
                    {
                        PETHREAD Thread = PsGetCurrentThread();

                        MiUnlockProcessWorkingSetShared(TargetProcess, Thread);
                        TempProto = *Proto;
                        MiLockProcessWorkingSetShared(TargetProcess, Thread);
                    }
                    else
                    {
                        TempProto.u.Long = 0;
                    }

                    if (!TempProto.u.Long)
                    {
                        State = MEM_RESERVE;
                        Protect = 0;
                    }
                }
            }
        }
    }

    /* Check if this was a demand-zero PTE, since we need to find the state */
    if (!DemandZeroPte)
        goto Exit;

    /* Not yet handled */
    ASSERT(Vad->u.VadFlags.VadType != VadDevicePhysicalMemory);
    ASSERT(Vad->u.VadFlags.VadType != VadAwe);

    /* Check if this is private commited memory, or an section-backed VAD */
    if (Vad->u.VadFlags.PrivateMemory || !Vad->ControlArea)
    {
        if (!Vad->u.VadFlags.MemCommit)
        {
            /* This is committed memory */
            State = MEM_COMMIT;

            /* Convert the protection */
            Protect = MmProtectToValue[Vad->u.VadFlags.Protection];
        }

        goto Exit;
    }

    /* Tell caller about the next range */
    *NextVa = (PVOID)((ULONG_PTR)Va + PAGE_SIZE);

    /* Get the prototype PTE for this VAD */
    Proto = MI_GET_PROTOTYPE_PTE_FOR_VPN(Vad, (ULONG_PTR)Va >> PAGE_SHIFT);
    if (!Proto)
        goto Exit;

    /* We should unlock the working set, but it's not being held! */

    /* Is the prototype PTE actually valid (committed)? */
    TempProto = *Proto;
    if (!TempProto.u.Long)
        goto Exit;

    /* Unless this is a memory-mapped file, handle it like private VAD */
    State = MEM_COMMIT;

    if (Vad->u.VadFlags.VadType != VadImageMap)
    {
        Protect = MmProtectToValue[Vad->u.VadFlags.Protection];
        goto Exit;
    }

    if (!TempProto.u.Hard.Valid)
    {
        Protect = MmProtectToValue[TempProto.u.Soft.Protection];
        goto Exit;
    }

    Pde = MiAddressToPde(Proto);

    OldIrql = MiLockPfnDb(APC_LEVEL);

    if (!Pde->u.Hard.Valid)
        MiMakeSystemAddressValidPfn(Proto, OldIrql);

    TempProto = *Proto;
    ASSERT(TempProto.u.Long != 0);

    if (TempProto.u.Hard.Valid)
    {
        PMMPFN pfn;

        pfn = MI_PFN_ELEMENT(TempProto.u.Hard.PageFrameNumber);
        Protect = MmProtectToValue[pfn->OriginalPte.u.Soft.Protection];
    }
    else
    {
        Protect = MmProtectToValue[TempProto.u.Soft.Protection];
    }

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    /* We should re-lock the working set */

Exit:

    /* Return the protection code */
    *ReturnedProtect = Protect;
    return State;
}

NTSTATUS
NTAPI
MiQueryMemoryBasicInformation(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _Out_ PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_ SIZE_T* ReturnLength)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    MEMORY_BASIC_INFORMATION MemoryInfo;
    PEPROCESS TargetProcess;
    PMMVAD Vad = NULL;
    PVOID Address;
    PVOID NextAddress;
    ULONG_PTR BaseVpn;
    ULONG NewProtect;
    ULONG NewState;
    KAPC_STATE ApcState;
    BOOLEAN Found = FALSE;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("MiQueryMemoryBasicInformation: BaseAddress %p\n", BaseAddress);

    /* Check for illegal addresses in user-space, or the shared memory area */
    if (BaseAddress > MM_HIGHEST_VAD_ADDRESS ||
        PAGE_ALIGN(BaseAddress) == (PVOID)MM_SHARED_USER_DATA_VA)
    {
        Address = PAGE_ALIGN(BaseAddress);

        /* Make up an info structure describing this range */
        MemoryInfo.BaseAddress = Address;
        MemoryInfo.AllocationProtect = PAGE_READONLY;
        MemoryInfo.Type = MEM_PRIVATE;

        /* Special case for shared data */
        if (Address == (PVOID)MM_SHARED_USER_DATA_VA)
        {
            MemoryInfo.AllocationBase = (PVOID)MM_SHARED_USER_DATA_VA;
            MemoryInfo.State = MEM_COMMIT;
            MemoryInfo.Protect = PAGE_READONLY;
            MemoryInfo.RegionSize = PAGE_SIZE;
        }
        else
        {
            MemoryInfo.AllocationBase = ((PCHAR)MM_HIGHEST_VAD_ADDRESS + 1);
            MemoryInfo.State = MEM_RESERVE;
            MemoryInfo.Protect = PAGE_NOACCESS;
            MemoryInfo.RegionSize = ((ULONG_PTR)MM_HIGHEST_USER_ADDRESS + 1 - (ULONG_PTR)Address);
        }

        /* Return the data, NtQueryInformation already probed it*/
        if (PreviousMode != KernelMode)
        {
            _SEH2_TRY
            {
                *(PMEMORY_BASIC_INFORMATION)MemoryInformation = MemoryInfo;

                if (ReturnLength)
                    *ReturnLength = sizeof(MEMORY_BASIC_INFORMATION);
            }
             _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
        }
        else
        {
            *(PMEMORY_BASIC_INFORMATION)MemoryInformation = MemoryInfo;

            if (ReturnLength)
                *ReturnLength = sizeof(MEMORY_BASIC_INFORMATION);
        }

        return Status;
    }

    /* Check if this is for a local or remote process */
    if (ProcessHandle == NtCurrentProcess())
    {
        TargetProcess = PsGetCurrentProcess();
    }
    else
    {
        /* Reference the target process */
        Status = ObReferenceObjectByHandle(ProcessHandle,
                                           PROCESS_QUERY_INFORMATION,
                                           PsProcessType,
                                           ExGetPreviousMode(),
                                           (PVOID *)&TargetProcess,
                                           NULL);
        if (!NT_SUCCESS(Status))
            return Status;

        /* Attach to it now */
        KeStackAttachProcess(&TargetProcess->Pcb, &ApcState);
    }

    /* Lock the address space and make sure the process isn't already dead */
    MmLockAddressSpace(&TargetProcess->Vm);

    if (TargetProcess->VmDeleted)
    {
        /* Unlock the address space of the process */
        MmUnlockAddressSpace(&TargetProcess->Vm);

        /* Check if we were attached */
        if (ProcessHandle != NtCurrentProcess())
        {
            /* Detach and dereference the process */
            KeUnstackDetachProcess(&ApcState);
            ObDereferenceObject(TargetProcess);
        }

        /* Bail out */
        DPRINT1("Process is dying\n");
        return STATUS_PROCESS_IS_TERMINATING;
    }

    /* Loop the VADs */
    ASSERT(TargetProcess->VadRoot.NumberGenericTableElements);

    if (TargetProcess->VadRoot.NumberGenericTableElements)
    {
        /* Scan on the right */
        Vad = (PMMVAD)TargetProcess->VadRoot.BalancedRoot.RightChild;
        BaseVpn = ((ULONG_PTR)BaseAddress / PAGE_SIZE);

        while (Vad)
        {
            /* Check if this VAD covers the allocation range */
            if (BaseVpn >= Vad->StartingVpn && BaseVpn <= Vad->EndingVpn)
            {
                /* We're done */
                Found = TRUE;
                break;
            }

            /* Check if this VAD is too high */
            if (BaseVpn < Vad->StartingVpn)
            {
                /* Stop if there is no left child */
                if (!Vad->LeftChild)
                    break;

                /* Search on the left next */
                Vad = Vad->LeftChild;
            }
            else
            {
                /* Then this VAD is too low, keep searching on the right */
                ASSERT(BaseVpn > Vad->EndingVpn);

                /* Stop if there is no right child */
                if (!Vad->RightChild)
                    break;

                /* Search on the right next */
                Vad = Vad->RightChild;
            }
        }
    }

    /* Was a VAD found? */
    if (!Found)
    {
        Address = PAGE_ALIGN(BaseAddress);

        /* Calculate region size */
        if (Vad)
        {
            if (Vad->StartingVpn >= BaseVpn)
            {
                /* Region size is the free space till the start of that VAD */
                MemoryInfo.RegionSize = ((ULONG_PTR)(Vad->StartingVpn * PAGE_SIZE) - (ULONG_PTR)Address);
            }
            else
            {
                /* Get the next VAD */
                Vad = (PMMVAD)MiGetNextNode((PMMADDRESS_NODE)Vad);

                if (Vad)
                {
                    /* Region size is the free space till the start of that VAD */
                    MemoryInfo.RegionSize = ((ULONG_PTR)(Vad->StartingVpn * PAGE_SIZE) - (ULONG_PTR)Address);
                }
                else
                {
                    /* Maximum possible region size with that base address */
                    MemoryInfo.RegionSize = ((PCHAR)MM_HIGHEST_VAD_ADDRESS + 1 - (PCHAR)Address);
                }
            }
        }
        else
        {
            /* Maximum possible region size with that base address */
            MemoryInfo.RegionSize = ((PCHAR)MM_HIGHEST_VAD_ADDRESS + 1 - (PCHAR)Address);
        }

        /* Unlock the address space of the process */
        MmUnlockAddressSpace(&TargetProcess->Vm);

        /* Check if we were attached */
        if (ProcessHandle != NtCurrentProcess())
        {
            /* Detach and derefernece the process */
            KeUnstackDetachProcess(&ApcState);
            ObDereferenceObject(TargetProcess);
        }

        /* Build the rest of the initial information block */
        MemoryInfo.BaseAddress = Address;
        MemoryInfo.AllocationBase = NULL;
        MemoryInfo.AllocationProtect = 0;
        MemoryInfo.State = MEM_FREE;
        MemoryInfo.Protect = PAGE_NOACCESS;
        MemoryInfo.Type = 0;

        /* Return the data, NtQueryInformation already probed it*/
        if (PreviousMode != KernelMode)
        {
            _SEH2_TRY
            {
                *(PMEMORY_BASIC_INFORMATION)MemoryInformation = MemoryInfo;

                if (ReturnLength)
                    *ReturnLength = sizeof(MEMORY_BASIC_INFORMATION);
            }
             _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
        }
        else
        {
            *(PMEMORY_BASIC_INFORMATION)MemoryInformation = MemoryInfo;

            if (ReturnLength)
                *ReturnLength = sizeof(MEMORY_BASIC_INFORMATION);
        }

        return Status;
    }

    /* Set the correct memory type based on what kind of VAD this is */
    if (Vad->u.VadFlags.PrivateMemory || Vad->u.VadFlags.VadType == VadRotatePhysical)
        MemoryInfo.Type = MEM_PRIVATE;
    else if (Vad->u.VadFlags.VadType == VadImageMap)
        MemoryInfo.Type = MEM_IMAGE;
    else
        MemoryInfo.Type = MEM_MAPPED;

    /* Build the initial information block */
    Address = PAGE_ALIGN(BaseAddress);
    MemoryInfo.BaseAddress = Address;
    MemoryInfo.AllocationBase = (PVOID)(Vad->StartingVpn * PAGE_SIZE);
    MemoryInfo.AllocationProtect = MmProtectToValue[Vad->u.VadFlags.Protection];
    MemoryInfo.Type = MEM_PRIVATE;

    /* Acquire the working set lock (shared is enough) */
    MiLockProcessWorkingSetShared(TargetProcess, PsGetCurrentThread());

    /* Find the largest chunk of memory which has the same state and protection mask */
    MemoryInfo.State = MiQueryAddressState(Address,
                                           Vad,
                                           TargetProcess,
                                           &MemoryInfo.Protect,
                                           &NextAddress);
    for (Address = NextAddress;
         ((ULONG_PTR)Address / PAGE_SIZE) <= Vad->EndingVpn;
         Address = NextAddress)
    {
        /* Keep going unless the state or protection mask changed */
        NewState = MiQueryAddressState(Address, Vad, TargetProcess, &NewProtect, &NextAddress);

        if (NewState != MemoryInfo.State || NewProtect != MemoryInfo.Protect)
            break;
    }

    /* Release the working set lock */
    MiUnlockProcessWorkingSetShared(TargetProcess, PsGetCurrentThread());

    /* Check if we went outside of the VAD */
     if (((ULONG_PTR)Address / PAGE_SIZE) > Vad->EndingVpn)
        /* Set the end of the VAD as the end address */
        Address = (PVOID)((Vad->EndingVpn + 1) * PAGE_SIZE);

    /* Now that we know the last VA address, calculate the region size */
    MemoryInfo.RegionSize = ((ULONG_PTR)Address - (ULONG_PTR)MemoryInfo.BaseAddress);

    /* Unlock the address space of the process */
    MmUnlockAddressSpace(&TargetProcess->Vm);

    /* Check if we were attached */
    if (ProcessHandle != NtCurrentProcess())
    {
        /* Detach and derefernece the process */
        KeUnstackDetachProcess(&ApcState);
        ObDereferenceObject(TargetProcess);
    }

    /* Return the data, NtQueryInformation already probed it */
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            *(PMEMORY_BASIC_INFORMATION)MemoryInformation = MemoryInfo;

            if (ReturnLength)
                *ReturnLength = sizeof(MEMORY_BASIC_INFORMATION);
        }
         _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;
    }
    else
    {
        *(PMEMORY_BASIC_INFORMATION)MemoryInformation = MemoryInfo;

        if (ReturnLength)
            *ReturnLength = sizeof(MEMORY_BASIC_INFORMATION);
    }

    /* All went well */
    DPRINT("Base %p, AllocBase %p, AllocProtect %X, Protect %X, State %X, Type %X, Size %X\n",
           MemoryInfo.BaseAddress, MemoryInfo.AllocationBase, MemoryInfo.AllocationProtect,
           MemoryInfo.Protect, MemoryInfo.State, MemoryInfo.Type, MemoryInfo.RegionSize);

    return Status;
}

VOID
NTAPI
MiProcessValidPteList(
    _Inout_ PMMPTE* ValidPteList,
    _In_ ULONG Count)
{
    PMMPFN Pfn;
    MMPTE TempPte;
    PFN_NUMBER PageFrameIndex;
    ULONG ix;
    KIRQL OldIrql;

    /* Acquire the PFN lock and loop all the PTEs in the list */
    OldIrql = MiLockPfnDb(APC_LEVEL);

    for (ix = 0; ix != Count; ix++)
    {
        /* The PTE must currently be valid */
        TempPte = *ValidPteList[ix];
        ASSERT(TempPte.u.Hard.Valid == 1);

        /* Get the PFN entry for the page itself */
        PageFrameIndex = PFN_FROM_PTE(&TempPte);
        Pfn = MiGetPfnEntry(PageFrameIndex);

        /* Decrement the share count on the page table, and then on the page itself */
        MiDecrementShareCount(MiGetPfnEntry(Pfn->u4.PteFrame), Pfn->u4.PteFrame);
        MI_SET_PFN_DELETED(Pfn);
        MiDecrementShareCount(Pfn, PageFrameIndex);

        /* Make the page decommitted */
        MI_WRITE_INVALID_PTE(ValidPteList[ix], MmDecommittedPte);
    }

    /* All the PTEs have been dereferenced and made invalid,
       flush the TLB now and then release the PFN lock
    */
    KeFlushCurrentTb();
    MiUnlockPfnDb(OldIrql, APC_LEVEL);
}

ULONG
NTAPI
MiDecommitPages(
    _In_ PVOID StartingAddress,
    _In_ PMMPTE EndingPte,
    _In_ PEPROCESS Process,
    _In_ PMMVAD Vad)
{
    PETHREAD CurrentThread = PsGetCurrentThread();
    PMMPTE ValidPteList[0x100];
    PMMPTE CommitPte;
    PMMPTE Pde;
    PMMPTE Pte;
    PMMPFN Pfn;
    MMPTE PteContents;
    PMMWSLE MmWsle;
    MMWSLE WsleContents;
    ULONG WsIndex;
    ULONG CommitReduction = 0;
    ULONG PteCount = 0;
    KIRQL OldIrql;

    /* Get the PTE and PTE for the address, and lock the working set
       If this was a VAD for a MEM_COMMIT allocation,
       also figure out where the commited range ends so that we can do the right accounting.
    */
    Pde = MiAddressToPde(StartingAddress);
    Pte = MiAddressToPte(StartingAddress);

    if (Vad->u.VadFlags.MemCommit)
        CommitPte = (MiAddressToPte(Vad->EndingVpn * PAGE_SIZE));
    else
        CommitPte = NULL;

    MiLockProcessWorkingSetUnsafe(Process, CurrentThread);

    /* Make the PDE valid, and now loop through each page's worth of data */
    MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);

    while (Pte <= EndingPte)
    {
        /* Check if we've crossed a PDE boundary */
        if (MiIsPteOnPdeBoundary(Pte))
        {
            /* Get the new PDE and flush the valid PTEs we had built up until now.
               This helps reduce the amount of TLB flushing we have to do.
               Note that Windows does a much better job using timestamps and such,
               and does not flush the entire TLB all the time,
               but right now we have bigger problems to worry about than TLB flushing.
            */
            Pde = MiAddressToPde(StartingAddress);
            if (PteCount)
            {
                MiProcessValidPteList(ValidPteList, PteCount);
                PteCount = 0;
            }

            /* Make this PDE valid */
            MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);
        }

        /* Read this PTE. It might be active or still demand-zero. */
        PteContents = *Pte;
        if (PteContents.u.Long)
        {
            /* The PTE is active. It might be valid and in a working set,
               or it might be a prototype PTE or paged out or even in transition.
            */
            if (Pte->u.Long == MmDecommittedPte.u.Long)
            {
                /* It's already decommited, so there's nothing for us to do here */
                CommitReduction++;
            }
            else
            {
                /* Remove it from the counters, and check if it was valid or not */
                Process->NumberOfPrivatePages--;

                if (PteContents.u.Hard.Valid)
                {
                    /* It's valid. At this point make sure that it is not a ROS PFN.
                       Also, we don't support ProtoPTEs in this code path.
                    */
                    Pfn = MI_PFN_ELEMENT(PteContents.u.Hard.PageFrameNumber);

                    if (Pfn->u3.e1.PrototypePte)
                    {
                        if (PteCount)
                        {
                            MiProcessValidPteList(&ValidPteList[0], PteCount);
                            PteCount = 0;
                        }

                        OldIrql = MiLockPfnDb(APC_LEVEL);
                        MiDeletePte(Pte, StartingAddress, FALSE, Process, NULL, NULL, OldIrql);
                        MiUnlockPfnDb(OldIrql, APC_LEVEL);

                        Process->NumberOfPrivatePages++;
                        MI_WRITE_INVALID_PTE(Pte, MmDecommittedPte);
                    }
                    else
                    {
                        if (PteCount == 0x100)
                        {
                            MiProcessValidPteList(&ValidPteList[0], PteCount);
                            PteCount = 0;
                        }

                        ValidPteList[PteCount] = Pte;
                        PteCount++;

                        WsIndex = Pfn->u1.WsIndex;
                        MmWsle = (PMMWSLE)(MmWorkingSetList + 1);
                        ASSERT(PAGE_ALIGN(MmWsle[WsIndex].u1.VirtualAddress) == StartingAddress);

                        WsleContents = MmWsle[WsIndex];

                        MiRemoveWsle(WsIndex, MmWorkingSetList);
                        MiReleaseWsle(WsIndex, &Process->Vm);

                        if (WsleContents.u1.e1.LockedInWs || WsleContents.u1.e1.LockedInMemory)
                        {
                            MmWorkingSetList->FirstDynamic--;
                            if (WsIndex != MmWorkingSetList->FirstDynamic)
                            {
                                ASSERT(MmWsle[MmWorkingSetList->FirstDynamic].u1.e1.Valid);
                                MiSwapWslEntries(MmWorkingSetList->FirstDynamic, WsIndex, &Process->Vm, FALSE);
                            }
                        }
                    }
                }
                else if (PteContents.u.Soft.Prototype)
                {
                    if (PteCount)
                    {
                        MiProcessValidPteList(&ValidPteList[0], PteCount);
                        PteCount = 0;
                    }

                    OldIrql = MiLockPfnDb(APC_LEVEL);
                    MiDeletePte(Pte, StartingAddress, FALSE, Process, NULL, NULL, OldIrql);
                    MiUnlockPfnDb(OldIrql, APC_LEVEL);

                    Process->NumberOfPrivatePages++;
                    MI_WRITE_INVALID_PTE(Pte, MmDecommittedPte);
                }
                else if (PteContents.u.Soft.Transition)
                {
                    OldIrql = MiLockPfnDb(APC_LEVEL);

                    PteContents = *Pte;
                    if (PteContents.u.Soft.Transition)
                    {
                        Pfn = MI_PFN_ELEMENT(PteContents.u.Trans.PageFrameNumber);

                        MI_SET_PFN_DELETED(Pfn);
                        MiDecrementPfnShare(MI_PFN_ELEMENT(Pfn->u4.PteFrame), Pfn->u4.PteFrame);

                        if (!Pfn->u3.e2.ReferenceCount)
                        {
                            MiUnlinkPageFromList(Pfn);
                            MiReleasePageFileSpace(Pfn->OriginalPte);
                            MiInsertPageInFreeList(PteContents.u.Trans.PageFrameNumber);
                        }
                    }
                    else
                    {
                        ASSERT(PteContents.u.Soft.Valid == 0);
                        ASSERT(PteContents.u.Soft.Prototype == 0);
                        ASSERT(PteContents.u.Soft.PageFileHigh != 0);

                        MiReleasePageFileSpace(PteContents);
                    }

                    MI_WRITE_INVALID_PTE(Pte, MmDecommittedPte);
                    MiUnlockPfnDb(OldIrql, APC_LEVEL);
                }
                else if (PteContents.u.Soft.PageFileHigh)
                {
                    OldIrql = MiLockPfnDb(APC_LEVEL);
                    MiReleasePageFileSpace(PteContents);
                    MiUnlockPfnDb(OldIrql, APC_LEVEL);

                    MI_WRITE_INVALID_PTE(Pte, MmDecommittedPte);
                }
                else
                {
                    Process->NumberOfPrivatePages++;
                    MI_WRITE_INVALID_PTE(Pte, MmDecommittedPte);
                }
            }

            goto NextPte;
        }
        else
        {
            /* This used to be a zero PTE and it no longer is, so we must add a reference to the pagetable. */
            MiIncrementPageTableReferences(StartingAddress);

            DPRINT("MiDecommitPages: [%d] Address %p, RefCount %X\n",
                   MiAddressToPdeOffset(StartingAddress), StartingAddress, MiQueryPageTableReferences(StartingAddress));

            /* Next, we account for decommitted PTEs and make the PTE as such */
            if (Pte > CommitPte)
                CommitReduction++;

            MI_WRITE_INVALID_PTE(Pte, MmDecommittedPte);
        }

NextPte:
        /* Move to the next PTE and the next address */
        Pte++;
        StartingAddress = (PVOID)((ULONG_PTR)StartingAddress + PAGE_SIZE);
    }

    /* Flush any dangling PTEs from the loop in the last page table,
       and then release the working set and return the commit reduction accounting.
    */
    if (PteCount)
        MiProcessValidPteList(ValidPteList, PteCount);

    MiUnlockProcessWorkingSetUnsafe(Process, CurrentThread);

    return CommitReduction;
}

ULONG
NTAPI
MiCalculatePageCommitment(
    _In_ ULONG_PTR StartingAddress,
    _In_ ULONG_PTR EndingAddress,
    _In_ PMMVAD Vad,
    _In_ PEPROCESS Process)
{
    PMMPDE Pde;
    PMMPTE Pte;
    PMMPTE LastPte;
    ULONG CommittedPages;

    /* Compute starting and ending PTE and PDE addresses */
    Pde = MiAddressToPde(StartingAddress);
    Pte = MiAddressToPte(StartingAddress);
    LastPte = MiAddressToPte(EndingAddress);

    /* Handle commited pages first */
    if (Vad->u.VadFlags.MemCommit)
    {
        /* This is a committed VAD, so Assume the whole range is committed */
        CommittedPages = (ULONG)BYTES_TO_PAGES(EndingAddress - StartingAddress);

        /* Is the PDE demand-zero? */
        Pde = MiPteToPde(Pte);
        if (Pde->u.Long)
        {
            /* It is not. Is it valid? */
            if (!Pde->u.Hard.Valid)
            {
                /* Fault it in */
                Pte = MiPteToAddress(Pde);
                MiMakeSystemAddressValid(Pte, Process);
            }
        }
        else
        {
            /* It is, skip it and move to the next PDE, unless we're done */
            Pde++;

            Pte = MiPteToAddress(Pde);
            if (Pte > LastPte)
                return CommittedPages;
        }

        /* Now loop all the PTEs in the range */
        while (Pte <= LastPte)
        {
            /* Have we crossed a PDE boundary? */
            if (MiIsPteOnPdeBoundary(Pte))
            {
                /* Is this PDE demand zero? */
                Pde = MiPteToPde(Pte);
                if (Pde->u.Long)
                {
                    /* It isn't -- is it valid? */
                    if (!Pde->u.Hard.Valid)
                    {
                        /* Nope, fault it in */
                        Pte = MiPteToAddress(Pde);
                        MiMakeSystemAddressValid(Pte, Process);
                    }
                }
                else
                {
                    /* It is, skip it and move to the next PDE */
                    Pde++;
                    Pte = MiPteToAddress(Pde);
                    continue;
                }
            }

            /* Is this PTE demand zero? */
            if (Pte->u.Long)
            {
                /* It isn't -- is it a decommited, invalid, or faulted PTE? */
                if (Pte->u.Soft.Protection == MM_DECOMMIT &&
                    !Pte->u.Hard.Valid &&
                    (!Pte->u.Soft.Prototype || Pte->u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED))
                {
                    /* It is, so remove it from the count of commited pages */
                    CommittedPages--;
                }
            }

            /* Move to the next PTE */
            Pte++;
        }

        /* Return how many committed pages there still are */
        return CommittedPages;
    }

    /* This is a non-commited VAD, so assume none of it is committed */
    CommittedPages = 0;

    /* Is the PDE demand-zero? */
    Pde = MiPteToPde(Pte);
    if (Pde->u.Long)
    {
        /* It isn't -- is it invalid? */
        if (!Pde->u.Hard.Valid)
        {
            /* It is, so page it in */
            Pte = MiPteToAddress(Pde);
            MiMakeSystemAddressValid(Pte, Process);
        }
    }
    else
    {
        /* It is, so skip it and move to the next PDE */
        Pde++;

        Pte = MiPteToAddress(Pde);
        if (Pte > LastPte)
            return CommittedPages;
    }

    /* Loop all the PTEs in this PDE */
    while (Pte <= LastPte)
    {
        /* Have we crossed a PDE boundary? */
        if (MiIsPteOnPdeBoundary(Pte))
        {
            /* Is this new PDE demand-zero? */
            Pde = MiPteToPde(Pte);
            if (Pde->u.Long)
            {
                /* It isn't. Is it valid? */
                if (!Pde->u.Hard.Valid)
                {
                    /* It isn't, so make it valid */
                    Pte = MiPteToAddress(Pde);
                    MiMakeSystemAddressValid(Pte, Process);
                }
            }
            else
            {
                /* It is, so skip it and move to the next one */
                Pde++;
                Pte = MiPteToAddress(Pde);
                continue;
            }
        }

        /* Is this PTE demand-zero? */
        if (Pte->u.Long)
        {
            /* Nope. Is it a valid, non-decommited, non-paged out PTE? */
            if (Pte->u.Soft.Protection != MM_DECOMMIT ||
                Pte->u.Hard.Valid ||
                (Pte->u.Soft.Prototype && Pte->u.Soft.PageFileHigh != MI_PTE_LOOKUP_NEEDED))
            {
                /* It is! So we'll treat this as a committed page */
                CommittedPages++;
            }
        }

        /* Move to the next PTE */
        Pte++;
    }

    /* Return how many committed pages we found in this VAD */
    return CommittedPages;
}

NTSTATUS
NTAPI
MmFlushVirtualMemory(
    _In_ PEPROCESS Process,
    _Inout_ PVOID* BaseAddress,
    _Inout_ SIZE_T* RegionSize,
    _Out_ IO_STATUS_BLOCK* OutIoStatusBlock)
{
    PETHREAD Thread = PsGetCurrentThread();
    PVOID StartAddress;
    PVOID EndAddress;
    PMMVAD Vad;
    KAPC_STATE ApcState;
    //BOOLEAN IsAttached = FALSE;
    BOOLEAN IsNullSize;
    NTSTATUS Status;

    DPRINT1("MmFlushVirtualMemory: %p, %p, %IX\n", Process, (BaseAddress ? *BaseAddress : NULL), (RegionSize ? *RegionSize : 0));
    PAGED_CODE();

    ASSERT(!MI_IS_SESSION_ADDRESS(*BaseAddress));
    //ASSERT(!MI_IS_SYSTEM_CACHE_ADDRESS(*BaseAddress));
    ASSERT(!(*BaseAddress >= MmSystemCacheStart && *BaseAddress <= MmSystemCacheEnd));
    //ASSERT(!(*BaseAddress >= MiSystemCacheStartExtra && *BaseAddress <= MiSystemCacheEndExtra));

    StartAddress = (PVOID)(((ULONG_PTR)*BaseAddress) & ~(PAGE_SIZE - 1));
    EndAddress = Add2Ptr(*BaseAddress, (*RegionSize - 1));
    EndAddress = (PVOID)((ULONG_PTR)EndAddress | (PAGE_SIZE - 1));

    *BaseAddress = StartAddress;

    if (Process != CONTAINING_RECORD((Thread->Tcb.ApcState.Process), EPROCESS, Pcb))
    {
        KeStackAttachProcess(&Process->Pcb, &ApcState);
        //IsAttached = 1;
    }

    /* Lock the process address space */
    MmLockAddressSpace(&Process->Vm);

    if (Process->VmDeleted)
    {
        DPRINT1("MmFlushVirtualMemory: STATUS_PROCESS_IS_TERMINATING\n");
        Status = STATUS_PROCESS_IS_TERMINATING;
        goto Exit;
    }

    Vad = MiLocateAddress(StartAddress);
    if (!Vad)
    {
        DPRINT1("MmFlushVirtualMemory: STATUS_NOT_MAPPED_VIEW\n");
        Status = STATUS_NOT_MAPPED_VIEW;
        goto Exit;
    }

    if (*RegionSize)
    {
        IsNullSize = FALSE;
    }
    else
    {
        DPRINT1("MmFlushVirtualMemory: FIXME\n");
        ASSERT(FALSE);
        IsNullSize = TRUE;
    }
    DPRINT1("MmFlushVirtualMemory: IsNullSize %X\n", IsNullSize);

    if (Vad->u.VadFlags.PrivateMemory)
    {
        DPRINT1("MmFlushVirtualMemory: STATUS_NOT_MAPPED_VIEW\n");
        Status = STATUS_NOT_MAPPED_VIEW;
        goto Exit;
    }

    if (Vad->EndingVpn < ((ULONG_PTR)EndAddress / PAGE_SIZE))
    {
        DPRINT1("MmFlushVirtualMemory: STATUS_NOT_MAPPED_VIEW\n");
        Status = STATUS_NOT_MAPPED_VIEW;
        goto Exit;
    }

    if (!Vad->ControlArea->FilePointer)
    {
        DPRINT1("MmFlushVirtualMemory: STATUS_NOT_MAPPED_DATA\n");
        Status = STATUS_NOT_MAPPED_DATA;
        goto Exit;
    }

    if (Vad->u.VadFlags.VadType == VadImageMap)
    {
        DPRINT1("MmFlushVirtualMemory: STATUS_NOT_MAPPED_DATA\n");
        Status = STATUS_NOT_MAPPED_DATA;
        goto Exit;
    }


    DPRINT1("MmFlushVirtualMemory: FIXME\n");
    ASSERT(FALSE);
    Status = STATUS_NOT_IMPLEMENTED;

Exit:

    /* Unlock the address space */
    MmUnlockAddressSpace(&Process->Vm);

    return Status;
}

CODE_SEG("PAGELK")
NTSTATUS
NTAPI
MiResetVirtualMemory(
    IN ULONG_PTR StartingAddress,
    IN ULONG_PTR EndingAddress,
    IN PMMVAD Vad,
    IN PEPROCESS Process)
{
    PETHREAD Thread = PsGetCurrentThread();
    MMPTE_FLUSH_LIST PteFlushList;
    PMMPFN Pfn;
    PMMPDE Pde;
    PMMPTE Pte;
    PMMPTE LastPte;
    PMMPTE Proto;
    MMPTE TempPte;
    PFN_NUMBER PageNumber;
    ULONG ix;
    BOOLEAN IsFirst = TRUE;
    KIRQL OldIrql = MM_NOIRQL;

    DPRINT("MiResetVirtualMemory: (%IX:%IX) %p, %p\n", StartingAddress, EndingAddress, Vad, Process);

    if (!Vad->u.VadFlags.PrivateMemory && Vad->ControlArea->FilePointer)
    {
        DPRINT1("MiResetVirtualMemory: STATUS_USER_MAPPED_FILE\n");
        return STATUS_USER_MAPPED_FILE;
    }

    Pte = MiAddressToPte(StartingAddress);
    LastPte = MiAddressToPte(EndingAddress);

    PteFlushList.Count = 0;

    //FIXME:
    //MmLockPagableSectionByHandle(ExPageLockHandle);
    MiLockProcessWorkingSetUnsafe(Process, Thread);

    while (Pte <= LastPte)
    {
        if (MiIsPteOnPdeBoundary(Pte) || IsFirst)
        {
            if (PteFlushList.Count)
            {
                if (PteFlushList.Count == 1)
                {
                    //FIXME:
                    //KeFlushSingleTb(PteFlushList.FlushVa[0], FALSE);

                    //HACK:
                    __invlpg(PteFlushList.FlushVa[0]);
                }
                else if (PteFlushList.Count >= 0x21)
                {
                    KeFlushProcessTb();
                }
                else
                {
                    //FIXME:
                    //KeFlushMultipleTb(PteFlushList.Count, PteFlushList.FlushVa, FALSE);

                    //HACK:
                    for (ix = 0; ix < PteFlushList.Count; ix++)
                        __invlpg(PteFlushList.FlushVa[ix]);
                }

                PteFlushList.Count = 0;
            }

            IsFirst = FALSE;

            Pde = MiAddressToPte(Pte);

            ASSERT(KeAreAllApcsDisabled() == TRUE);

            if (!Pde->u.Long)
            {
                Pde++;
                Pte = MiPteToAddress(Pde);
                continue;
            }

            if (!Pde->u.Hard.Valid)
            {
                if (OldIrql != MM_NOIRQL)
                {
                    MiUnlockPfnDb(OldIrql, APC_LEVEL);
                    ASSERT(KeAreAllApcsDisabled() == TRUE);
                }

                MiMakeSystemAddressValid(MiPteToAddress(Pde), Process);

                if (OldIrql != MM_NOIRQL)
                    OldIrql = MiLockPfnDb(APC_LEVEL);
            }

            if (Pde->u.Hard.LargePage)
            {
                Pde++;
                Pte = MiPteToAddress(Pde);
                continue;
            }
        }

        TempPte = *Pte;
        Proto = NULL;

        if (!TempPte.u.Hard.Valid && TempPte.u.Soft.Prototype)
        {
            DPRINT1("MiResetVirtualMemory: FIXME\n");
            ASSERT(FALSE);
        }

        if (TempPte.u.Hard.Valid)
        {
            PageNumber = TempPte.u.Hard.PageFrameNumber;

            if (Vad->u.VadFlags.VadType == VadRotatePhysical)
            {
                DPRINT1("MiResetVirtualMemory: FIXME\n");
                ASSERT(FALSE);
            }

            Pfn = MI_PFN_ELEMENT(PageNumber);

            if (!Proto && TempPte.u.Hard.Accessed)
            {
                //PMMWSLE MmWsle = (PMMWSLE)(MmWorkingSetList + 1);
                ULONG WsIndex;

                Pte->u.Hard.Accessed = 0;

                WsIndex = MiLocateWsle(MiPteToAddress(Pte), MmWorkingSetList, Pfn->u1.Flink, 0);
                ASSERT(WsIndex != WSLE_NULL_INDEX);
                //MmWsle[WsIndex].u1.e1.Age = 3;
            }

            if (OldIrql == MM_NOIRQL)
            {
                ASSERT(PteFlushList.Count == 0);
                OldIrql = MiLockPfnDb(APC_LEVEL);
                ASSERT(OldIrql != MM_NOIRQL);
                continue;
            }

            if (Pfn->u3.e2.ReferenceCount == 1)
            {
                ASSERT(Pfn->u3.e1.Rom == 0);
                Pfn->u3.e1.Modified = 0;

                MiReleasePageFileSpace(Pfn->OriginalPte);
                Pfn->OriginalPte.u.Soft.PageFileHigh = 0;
            }

            if (!Proto && TempPte.u.Hard.Dirty)
            {
                TempPte.u.Hard.Accessed = 0;
                MI_MAKE_CLEAN_PAGE(&TempPte);
                MI_UPDATE_VALID_PTE(Pte, TempPte);

                if (PteFlushList.Count < 0x21)
                {
                    PteFlushList.FlushVa[PteFlushList.Count] = MiPteToAddress(Pte);
                    PteFlushList.Count++;
                }
            }
        }
        else if (TempPte.u.Soft.Transition)
        {
            DPRINT1("MiResetVirtualMemory: FIXME\n");
            ASSERT(FALSE);
        }
        else
        {
            if (TempPte.u.Soft.PageFileHigh)
            {
                DPRINT1("MiResetVirtualMemory: FIXME\n");
                ASSERT(FALSE);
            }
            else
            {
                if (OldIrql != MM_NOIRQL)
                {
                    if (PteFlushList.Count)
                    {
                        if (PteFlushList.Count == 1)
                        {
                            //FIXME:
                            //KeFlushSingleTb(PteFlushList.FlushVa[0], FALSE);

                            //HACK:
                            __invlpg(PteFlushList.FlushVa[0]);
                        }
                        else if (PteFlushList.Count >= 0x21)
                        {
                            KeFlushProcessTb();
                        }
                        else
                        {
                            //FIXME:
                            //KeFlushMultipleTb(PteFlushList.Count, PteFlushList.FlushVa, FALSE);

                            //HACK:
                            for (ix = 0; ix < PteFlushList.Count; ix++)
                                __invlpg(PteFlushList.FlushVa[ix]);
                        }

                        PteFlushList.Count = 0;
                    }

                    MiUnlockPfnDb(OldIrql, APC_LEVEL);
                    OldIrql = MM_NOIRQL;
                }
            }
        }

        Pte++;
    }

    if (OldIrql != MM_NOIRQL)
    {
        if (PteFlushList.Count)
        {
            if (PteFlushList.Count == 1)
            {
                //FIXME:
                //KeFlushSingleTb(PteFlushList.FlushVa[0], FALSE);

                //HACK:
                __invlpg(PteFlushList.FlushVa[0]);
            }
            else if (PteFlushList.Count >= 0x21)
            {
                KeFlushProcessTb();
            }
            else
            {
                //FIXME:
                //KeFlushMultipleTb(PteFlushList.Count, PteFlushList.FlushVa, FALSE);

                //HACK:
                for (ix = 0; ix < PteFlushList.Count; ix++)
                    __invlpg(PteFlushList.FlushVa[ix]);
            }

            PteFlushList.Count = 0;
        }

        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        OldIrql = MM_NOIRQL;
    }
    else
    {
        ASSERT(PteFlushList.Count == 0);
    }

    MiUnlockProcessWorkingSetUnsafe(Process, Thread);
    //FIXME:
    //MmUnlockPagableImageSection(ExPageLockHandle);

    return STATUS_SUCCESS;
}

/* PUBLIC FUNCTIONS ***********************************************************/

PHYSICAL_ADDRESS
NTAPI
MmGetPhysicalAddress(
    PVOID Address)
{
    PHYSICAL_ADDRESS PhysicalAddress;
    MMPDE TempPde;
    MMPTE TempPte;

    TempPde = *MiAddressToPde(Address);

    /* Check if the PXE/PPE/PDE is valid */
    if (!TempPde.u.Hard.Valid)
    {
        //KeRosDumpStackFrames(NULL, 20);
        DPRINT1("MM:MmGetPhysicalAddress: Failed base address was %p\n", Address);
        ASSERT(FALSE);

        PhysicalAddress.QuadPart = 0;
    }
    /* Check for large pages */
    else if (TempPde.u.Hard.LargePage)
    {
        /* Physical address is base page + large page offset */
        PhysicalAddress.QuadPart = ((ULONG64)TempPde.u.Hard.PageFrameNumber << PAGE_SHIFT);
        PhysicalAddress.QuadPart += ((ULONG_PTR)Address & (PAGE_SIZE * PTE_PER_PAGE - 1));
    }
    else
    {
        /* Check if the PTE is valid */
        TempPte = *MiAddressToPte(Address);
        if (TempPte.u.Hard.Valid)
        {
            /* Physical address is base page + page offset */
            PhysicalAddress.QuadPart = ((ULONG64)TempPte.u.Hard.PageFrameNumber << PAGE_SHIFT);
            PhysicalAddress.QuadPart += ((ULONG_PTR)Address & (PAGE_SIZE - 1));
        }
    }

    return PhysicalAddress;
}

PVOID
NTAPI
MmGetVirtualForPhysical(
    _In_ PHYSICAL_ADDRESS PhysicalAddress)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

CODE_SEG("PAGE")
PVOID
NTAPI
MmSecureVirtualMemory(
    _In_ PVOID Address,
    _In_ SIZE_T Length,
    _In_ ULONG Mode)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

CODE_SEG("PAGE")
VOID
NTAPI
MmUnsecureVirtualMemory(
    _In_ HANDLE SecureHandle)
{
    DPRINT1("MmUnsecureVirtualMemory: SecureHandle %p\n", SecureHandle);
    //UNIMPLEMENTED_DBGBREAK();
    UNIMPLEMENTED;
}

/* SYSTEM CALLS ***************************************************************/

CODE_SEG("PAGE")
NTSTATUS
NTAPI
NtReadVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _Out_ PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToRead,
    _Out_ PSIZE_T NumberOfBytesRead OPTIONAL)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PEPROCESS Process;
    SIZE_T BytesRead = 0;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    /* Check if we came from user mode */
    if (PreviousMode != KernelMode)
    {
        /* Validate the read addresses */
        if ((((ULONG_PTR)BaseAddress + NumberOfBytesToRead) < (ULONG_PTR)BaseAddress) ||
            (((ULONG_PTR)Buffer + NumberOfBytesToRead) < (ULONG_PTR)Buffer) ||
            (((ULONG_PTR)BaseAddress + NumberOfBytesToRead) > MmUserProbeAddress) ||
            (((ULONG_PTR)Buffer + NumberOfBytesToRead) > MmUserProbeAddress))
        {
            /* Don't allow to write into kernel space */
            return STATUS_ACCESS_VIOLATION;
        }

        /* Enter SEH for probe */
        _SEH2_TRY
        {
            /* Probe the output value */
            if (NumberOfBytesRead)
                ProbeForWriteSize_t(NumberOfBytesRead);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Get exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Don't do zero-byte transfers */
    if (NumberOfBytesToRead)
    {
        /* Reference the process */
        Status = ObReferenceObjectByHandle(ProcessHandle,
                                           PROCESS_VM_READ,
                                           PsProcessType,
                                           PreviousMode,
                                           (PVOID *)(&Process),
                                           NULL);
        if (NT_SUCCESS(Status))
        {
            /* Do the copy */
            Status = MmCopyVirtualMemory(Process,
                                         BaseAddress,
                                         PsGetCurrentProcess(),
                                         Buffer,
                                         NumberOfBytesToRead,
                                         PreviousMode,
                                         &BytesRead);

            /* Dereference the process */
            ObDereferenceObject(Process);
        }
    }

    /* Check if the caller sent this parameter */
    if (!NumberOfBytesRead)
        return Status;

    /* Enter SEH to guard write */
    _SEH2_TRY
    {
        /* Return the number of bytes read */
        *NumberOfBytesRead = BytesRead;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
    }
    _SEH2_END;

    return Status;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
NtWriteVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_ PSIZE_T NumberOfBytesWritten OPTIONAL)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PEPROCESS Process;
    SIZE_T BytesWritten = 0;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    /* Check if we came from user mode */
    if (PreviousMode != KernelMode)
    {
        /* Validate the read addresses */
        if ((((ULONG_PTR)BaseAddress + NumberOfBytesToWrite) < (ULONG_PTR)BaseAddress) ||
            (((ULONG_PTR)Buffer + NumberOfBytesToWrite) < (ULONG_PTR)Buffer) ||
            (((ULONG_PTR)BaseAddress + NumberOfBytesToWrite) > MmUserProbeAddress) ||
            (((ULONG_PTR)Buffer + NumberOfBytesToWrite) > MmUserProbeAddress))
        {
            /* Don't allow to write into kernel space */
            return STATUS_ACCESS_VIOLATION;
        }

        /* Enter SEH for probe */
        _SEH2_TRY
        {
            /* Probe the output value */
            if (NumberOfBytesWritten)
                ProbeForWriteSize_t(NumberOfBytesWritten);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Get exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Don't do zero-byte transfers */
    if (NumberOfBytesToWrite)
    {
        /* Reference the process */
        Status = ObReferenceObjectByHandle(ProcessHandle,
                                           PROCESS_VM_WRITE,
                                           PsProcessType,
                                           PreviousMode,
                                           (PVOID *)&Process,
                                           NULL);
        if (NT_SUCCESS(Status))
        {
            /* Do the copy */
            Status = MmCopyVirtualMemory(PsGetCurrentProcess(),
                                         Buffer,
                                         Process,
                                         BaseAddress,
                                         NumberOfBytesToWrite,
                                         PreviousMode,
                                         &BytesWritten);

            /* Dereference the process */
            ObDereferenceObject(Process);
        }
    }

    /* Check if the caller sent this parameter */
    if (NumberOfBytesWritten)
    {
        /* Enter SEH to guard write */
        _SEH2_TRY
        {
            /* Return the number of bytes written */
            *NumberOfBytesWritten = BytesWritten;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
        }
        _SEH2_END;
    }

    return Status;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
NtFlushInstructionCache(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ SIZE_T FlushSize)
{
    PKPROCESS Process;
    KAPC_STATE ApcState;
    NTSTATUS Status;

    PAGED_CODE();

    /* Is a base address given? */
    if (BaseAddress)
    {
        /* If the requested size is 0, there is nothing to do */
        if (!FlushSize)
            return STATUS_SUCCESS;

        /* Is this a user mode call? */
        if (ExGetPreviousMode() != KernelMode)
        {
            /* Make sure the base address is in user space */
            if (BaseAddress > MmHighestUserAddress)
            {
                DPRINT1("Invalid BaseAddress 0x%p\n", BaseAddress);
                return STATUS_ACCESS_VIOLATION;
            }
        }
    }

    /* Is another process requested? */
    if (ProcessHandle != NtCurrentProcess())
    {
        /* Reference the process */
        Status = ObReferenceObjectByHandle(ProcessHandle,
                                           PROCESS_VM_WRITE,
                                           PsProcessType,
                                           ExGetPreviousMode(),
                                           (PVOID *)&Process,
                                           NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Failed to reference the process %p\n", ProcessHandle);
            return Status;
        }

        /* Attach to the process */
        KeStackAttachProcess(Process, &ApcState);
    }

    /* Forward to Ke */
    KeSweepICache(BaseAddress, FlushSize);

    /* Check if we attached */
    if (ProcessHandle != NtCurrentProcess())
    {
        /* Detach from the process and dereference it */
        KeUnstackDetachProcess(&ApcState);
        ObDereferenceObject(Process);
    }

    /* All done, return to caller */
    return STATUS_SUCCESS;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
NtProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* OutBase,
    _Inout_ SIZE_T* OutSize,
    _In_ ULONG NewProtection,
    _Out_ ULONG* OutProtection)
{
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PEPROCESS Process;
    PVOID BaseAddress = NULL;
    ULONG OldProtection;
    ULONG ProtectionMask;
    SIZE_T Size;
    KAPC_STATE ApcState;
    BOOLEAN Attached = FALSE;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("NtProtectVirtualMemory: %p, %X, %X\n", ProcessHandle, NewProtection, (OutProtection ? *OutProtection : 0));

    /* Check for valid protection flags */
    ProtectionMask = MiMakeProtectionMask(NewProtection);
    if (ProtectionMask == MM_INVALID_PROTECTION)
    {
        DPRINT("NtProtectVirtualMemory: STATUS_INVALID_PAGE_PROTECTION\n");
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    /* Check if we came from user mode */
    if (PreviousMode != KernelMode)
    {
        /* Enter SEH for probing */
        _SEH2_TRY
        {
            /* Validate all outputs */
            ProbeForWritePointer(OutBase);
            ProbeForWriteSize_t(OutSize);
            ProbeForWriteUlong(OutProtection);

            /* Capture them */
            BaseAddress = *OutBase;
            Size = *OutSize;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Get exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        /* Capture directly */
        BaseAddress = *OutBase;
        Size = *OutSize;
    }

    /* Catch illegal base address */
    if (BaseAddress > MM_HIGHEST_USER_ADDRESS)
    {
        DPRINT("NtProtectVirtualMemory: STATUS_INVALID_PARAMETER_2\n");
        return STATUS_INVALID_PARAMETER_2;
    }

    /* Catch illegal region size */
    if (((ULONG_PTR)BaseAddress + Size) > MmUserProbeAddress)
    {
        /* Fail */
        DPRINT("NtProtectVirtualMemory: STATUS_INVALID_PARAMETER_3\n");
        return STATUS_INVALID_PARAMETER_3;
    }

    /* 0 is also illegal */
    if (!Size)
    {
        DPRINT("NtProtectVirtualMemory: STATUS_INVALID_PARAMETER_3\n");
        return STATUS_INVALID_PARAMETER_3;
    }

    /* Get a reference to the process */
    Status = ObReferenceObjectByHandle(ProcessHandle,
                                       PROCESS_VM_OPERATION,
                                       PsProcessType,
                                       PreviousMode,
                                       (PVOID *)&Process,
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtProtectVirtualMemory: Status %X\n", Status);
        return Status;
    }

    /* Check if we should attach */
    if (CurrentProcess != Process)
    {
        /* Do it */
        KeStackAttachProcess(&Process->Pcb, &ApcState);
        Attached = TRUE;
    }

    /* Do the actual work */
    Status = MiProtectVirtualMemory(Process, &BaseAddress, &Size, NewProtection, &OldProtection);

    /* Detach if needed */
    if (Attached)
        KeUnstackDetachProcess(&ApcState);

    /* Release reference */
    ObDereferenceObject(Process);

    /* Enter SEH to return data */
    _SEH2_TRY
    {
        /* Return data to user */
        *OutProtection = OldProtection;
        *OutBase = BaseAddress;
        *OutSize = Size;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        ;
    }
    _SEH2_END;

    return Status;
}

NTSTATUS
NTAPI
NtLockVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T NumberOfBytesToLock,
    _In_ ULONG MapType)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
NtUnlockVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T NumberOfBytesToUnlock,
    _In_ ULONG MapType)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
NtFlushVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T NumberOfBytesToFlush,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    IO_STATUS_BLOCK LocalStatusBlock;
    PEPROCESS Process;
    PVOID CapturedBaseAddress;
    SIZE_T CapturedBytesToFlush;
    NTSTATUS Status;

    PAGED_CODE();

    /* Check if we came from user mode */
    if (PreviousMode != KernelMode)
    {
        /* Enter SEH for probing */
        _SEH2_TRY
        {
            /* Validate all outputs */
            ProbeForWritePointer(BaseAddress);
            ProbeForWriteSize_t(NumberOfBytesToFlush);
            ProbeForWriteIoStatusBlock(IoStatusBlock);

            /* Capture them */
            CapturedBaseAddress = *BaseAddress;
            CapturedBytesToFlush = *NumberOfBytesToFlush;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Get exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        /* Capture directly */
        CapturedBaseAddress = *BaseAddress;
        CapturedBytesToFlush = *NumberOfBytesToFlush;
    }

    /* Catch illegal base address */
    if (CapturedBaseAddress > MM_HIGHEST_USER_ADDRESS)
    {
        DPRINT1("NtFlushVirtualMemory: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    /* Catch illegal region size */
    if (CapturedBytesToFlush > (MmUserProbeAddress - (ULONG_PTR)CapturedBaseAddress))
    {
        /* Fail */
        DPRINT1("NtFlushVirtualMemory: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    /* Get a reference to the process */
    Status = ObReferenceObjectByHandle(ProcessHandle,
                                       PROCESS_VM_OPERATION,
                                       PsProcessType,
                                       PreviousMode,
                                       (PVOID *)(&Process),
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtFlushVirtualMemory: Status %X\n", Status);
        return Status;
    }

    /* Do it */
    Status = MmFlushVirtualMemory(Process,
                                  &CapturedBaseAddress,
                                  &CapturedBytesToFlush,
                                  &LocalStatusBlock);

    /* Release reference */
    ObDereferenceObject(Process);

    /* Enter SEH to return data */
    _SEH2_TRY
    {
        /* Return data to user */
        *BaseAddress = PAGE_ALIGN(CapturedBaseAddress);
        *NumberOfBytesToFlush = 0;
        *IoStatusBlock = LocalStatusBlock;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
    }
    _SEH2_END;

    return Status;
}

NTSTATUS
NTAPI
NtGetWriteWatch(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG Flags,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ PVOID* UserAddressArray,
    _Out_ PULONG_PTR EntriesInUserAddressArray,
    _Out_ PULONG Granularity)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
NtResetWriteWatch(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
NtQueryVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_ PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_ PSIZE_T ReturnLength)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("NtQueryVirtualMemory: %p, %X\n", BaseAddress, MemoryInformationClass);

    /* Bail out if the address is invalid */
    if (BaseAddress > MM_HIGHEST_USER_ADDRESS)
        return STATUS_INVALID_PARAMETER;

    /* Probe return buffer */
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            ProbeForWrite(MemoryInformation, MemoryInformationLength, sizeof(ULONG_PTR));

            if (ReturnLength)
                ProbeForWriteSize_t(ReturnLength);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("NtQueryVirtualMemory: Status %X\n", Status);
            return Status;
        }
    }

    switch(MemoryInformationClass)
    {
        case MemoryBasicInformation:
        {
            /* Validate the size information of the class */
            if (MemoryInformationLength < sizeof(MEMORY_BASIC_INFORMATION))
                /* The size is invalid */
                return STATUS_INFO_LENGTH_MISMATCH;

            Status = MiQueryMemoryBasicInformation(ProcessHandle,
                                                   BaseAddress,
                                                   MemoryInformation,
                                                   MemoryInformationLength,
                                                   ReturnLength);
            break;
        }
        case MemorySectionName:
        {
            /* Validate the size information of the class */
            if (MemoryInformationLength < sizeof(MEMORY_SECTION_NAME))
                /* The size is invalid */
                return STATUS_INFO_LENGTH_MISMATCH;

            Status = MiQueryMemorySectionName(ProcessHandle,
                                              BaseAddress,
                                              MemoryInformation,
                                              MemoryInformationLength,
                                              ReturnLength);
            break;
        }
        case MemoryWorkingSetList:
        case MemoryBasicVlmInformation:
        default:
            DPRINT1("Unhandled memory information class %d\n", MemoryInformationClass);
            break;
    }

    return Status;
}

NTSTATUS
NTAPI
NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* UBaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T URegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect)
{
    PETHREAD CurrentThread = PsGetCurrentThread();
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
    PMMSUPPORT AddressSpace;
    PEPROCESS Process;
    ULONG ProtectionMask;
    PVOID PBaseAddress;
    PMMVAD Vad;
    PMMVAD FoundVad;
    PMMPDE Pde;
    PMMPTE Pte;
    PMMPTE StartPte;
    PMMPTE LastPte;
    PMMPTE EndVpnPte;
    MMPTE TempPte;
    ULONG_PTR PRegionSize;
    ULONG_PTR StartingAddress;
    ULONG_PTR EndingAddress;
    ULONG_PTR HighestAddress = (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS;
    ULONG_PTR Alignment;
    SIZE_T CommitCharge = 0;
    SIZE_T QuotaCharge = 0;
    SIZE_T QuotaFree;
    SIZE_T QuotaCopyOnWrite;
    SIZE_T ExcessCharge = 0;
    ULONG OldProtect;
    KAPC_STATE ApcState;
    BOOLEAN Attached = FALSE;
    BOOLEAN IsReturnQuota = FALSE;
    BOOLEAN IsChangeProtection = FALSE;
    BOOLEAN Locked;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("NtAllocateVirtualMemory: Handle %p, Base %X, ZeroBits %X, Size %X, AllocType %X, Protect %X\n",
           ProcessHandle, (UBaseAddress ? *UBaseAddress : 0), ZeroBits, (URegionSize ? *URegionSize : 0), AllocationType, Protect);

    /* Check for valid Zero bits */
    if (ZeroBits > MI_MAX_ZERO_BITS)
    {
        DPRINT1("NtAllocateVirtualMemory: Too many zero bits\n");
        return STATUS_INVALID_PARAMETER_3;
    }

    /* Check for valid Allocation Types */
    if ((AllocationType & !(MEM_LARGE_PAGES | MEM_PHYSICAL | MEM_WRITE_WATCH | MEM_TOP_DOWN | MEM_RESET | MEM_RESERVE | MEM_COMMIT)))
    {
        DPRINT1("NtAllocateVirtualMemory: Invalid Allocation Type\n");
        return STATUS_INVALID_PARAMETER_5;
    }

    /* Check for at least one of these Allocation Types to be set */
    if (!(AllocationType & (MEM_COMMIT | MEM_RESERVE | MEM_RESET)))
    {
        DPRINT1("NtAllocateVirtualMemory: No memory allocation base type\n");
        return STATUS_INVALID_PARAMETER_5;
    }

    /* MEM_RESET is an exclusive flag, make sure that is valid too */
    if ((AllocationType & MEM_RESET) && (AllocationType != MEM_RESET))
    {
        DPRINT1("NtAllocateVirtualMemory: Invalid use of MEM_RESET\n");
        return STATUS_INVALID_PARAMETER_5;
    }

    if (AllocationType & (MEM_LARGE_PAGES | MEM_PHYSICAL | MEM_WRITE_WATCH))
    {
        /* Check if large pages are being used */
        if (AllocationType & MEM_LARGE_PAGES)
        {
            /* Large page allocations MUST be committed */
            if (!(AllocationType & MEM_COMMIT))
            {
                DPRINT1("NtAllocateVirtualMemory: Must supply MEM_COMMIT with MEM_LARGE_PAGES\n");
                return STATUS_INVALID_PARAMETER_5;
            }

            /* These flags are not allowed with large page allocations */
            if (AllocationType & (MEM_PHYSICAL | MEM_RESET | MEM_WRITE_WATCH))
            {
                DPRINT1("NtAllocateVirtualMemory: Using illegal flags with MEM_LARGE_PAGES\n");
                return STATUS_INVALID_PARAMETER_5;
            }
        }
        /* Check for valid MEM_WRITE_WATCH usage */
        else if (AllocationType & MEM_WRITE_WATCH)
        {
            if (AllocationType & MEM_PHYSICAL)
            {
                return STATUS_INVALID_PARAMETER_5;
            }

            if (!(AllocationType & MEM_RESERVE))
            {
                DPRINT1("NtAllocateVirtualMemory: MEM_WRITE_WATCH used without MEM_RESERVE\n");
                return STATUS_INVALID_PARAMETER_5;
            }
        }
        /* Check for valid MEM_PHYSICAL usage */
        else if (AllocationType & MEM_PHYSICAL)
        {
            ASSERT((AllocationType & (MEM_LARGE_PAGES | MEM_WRITE_WATCH)) == 0);

            /* MEM_PHYSICAL can only be used if MEM_RESERVE is also used */
            if (!(AllocationType & MEM_RESERVE))
            {
                DPRINT1("NtAllocateVirtualMemory: MEM_PHYSICAL used without MEM_RESERVE\n");
                return STATUS_INVALID_PARAMETER_5;
            }

            /* Only these flags are allowed with MEM_PHYSIAL */
            if (AllocationType & ~(MEM_RESERVE | MEM_TOP_DOWN | MEM_PHYSICAL))
            {
                DPRINT1("NtAllocateVirtualMemory: Using illegal flags with MEM_PHYSICAL\n");
                return STATUS_INVALID_PARAMETER_5;
            }

            /* Then make sure PAGE_READWRITE is used */
            if (Protect != PAGE_READWRITE)
            {
                DPRINT1("NtAllocateVirtualMemory: MEM_PHYSICAL used without PAGE_READWRITE\n");
                return STATUS_INVALID_PARAMETER_6;
            }
        }
    }

    /* Calculate the protection mask and make sure it's valid */
    ProtectionMask = MiMakeProtectionMask(Protect);
    if (ProtectionMask == MM_INVALID_PROTECTION)
    {
        DPRINT1("NtAllocateVirtualMemory: Invalid protection mask\n");
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    /* Enter SEH */
    _SEH2_TRY
    {
        /* Check for user-mode parameters */
        if (PreviousMode != KernelMode)
        {
            /* Make sure they are writable */
            ProbeForWritePointer(UBaseAddress);
            ProbeForWriteSize_t(URegionSize);
        }

        /* Capture their values */
        PBaseAddress = *UBaseAddress;
        PRegionSize = *URegionSize;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* Return the exception code */
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    /* Make sure the allocation isn't past the VAD area */
    if (PBaseAddress > MM_HIGHEST_VAD_ADDRESS)
    {
        DPRINT1("NtAllocateVirtualMemory: Virtual allocation base above User Space\n");
        return STATUS_INVALID_PARAMETER_2;
    }

    /* Make sure the allocation wouldn't overflow past the VAD area */
    if ((((ULONG_PTR)MM_HIGHEST_VAD_ADDRESS + 1) - (ULONG_PTR)PBaseAddress) < PRegionSize)
    {
        DPRINT1("NtAllocateVirtualMemory: Region size would overflow into kernel-memory\n");
        return STATUS_INVALID_PARAMETER_4;
    }

    /* Make sure there's a size specified */
    if (!PRegionSize)
    {
        DPRINT1("NtAllocateVirtualMemory: Region size is invalid (zero)\n");
        return STATUS_INVALID_PARAMETER_4;
    }

    /* If this is for the current process, just use PsGetCurrentProcess */
    if (ProcessHandle == NtCurrentProcess())
    {
        Process = CurrentProcess;
    }
    else
    {
        /* Otherwise, reference the process with VM rights and attach to it if this isn't the current process.
           We must attach because we'll be touching PTEs and PDEs that belong to user-mode memory,
           and also touching the Working Set which is stored in Hyperspace.
        */
        Status = ObReferenceObjectByHandle(ProcessHandle,
                                           PROCESS_VM_OPERATION,
                                           PsProcessType,
                                           PreviousMode,
                                           (PVOID *)&Process,
                                           NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("NtAllocateVirtualMemory: Status %X\n", Status);
            return Status;
        }

    }

    DPRINT("NtAllocateVirtualMemory: %p, %p, %X, %X, %X, %X\n",
           Process, PBaseAddress, ZeroBits, PRegionSize, AllocationType, Protect);

    /* Check for large page allocations and make sure that the required privilege is being held,
       before attempting to handle them.
    */
    if ((AllocationType & MEM_LARGE_PAGES) && !SeSinglePrivilegeCheck(SeLockMemoryPrivilege, PreviousMode))
    {
        /* Fail without it */
        DPRINT1("NtAllocateVirtualMemory: Privilege not held for MEM_LARGE_PAGES\n");
        Status = STATUS_PRIVILEGE_NOT_HELD;
        goto ErrorExit;
    }

    if (CurrentProcess != Process)
    {
        KeStackAttachProcess(&Process->Pcb, &ApcState);
        Attached = TRUE;
    }

    /* Check if the caller is reserving memory, or committing memory and letting us pick the base address */
    if (!PBaseAddress || (AllocationType & MEM_RESERVE))
    {
        /*  Do not allow COPY_ON_WRITE through this API */
        if (Protect & (PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY))
        {
            DPRINT1("NtAllocateVirtualMemory: Copy on write not allowed through this path\n");
            Status = STATUS_INVALID_PAGE_PROTECTION;
            goto ErrorExit;
        }

        Alignment = 0x10000;

        /* Does the caller have an address in mind, or is this a blind commit? */
        if (!PBaseAddress)
        {
            /* This is a blind commit, all we need is the region size */
            PRegionSize = ROUND_TO_PAGES(PRegionSize);

            /* Check if ZeroBits were specified */
            if (ZeroBits)
            {
                /* Calculate the highest address and check if it's valid */
                HighestAddress = (MAXULONG_PTR >> ZeroBits);

                if (HighestAddress > (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS)
                {
                    Status = STATUS_INVALID_PARAMETER_3;
                    goto ErrorExit;
                }
            }

            if (Process->VmTopDown)
                AllocationType |= MEM_TOP_DOWN;

            StartingAddress = 0;
            EndingAddress = 0;

            CommitCharge = BYTES_TO_PAGES(PRegionSize);

            if (AllocationType & MEM_LARGE_PAGES)
            {
                DPRINT1("NtAllocateVirtualMemory: FIXME\n");
                ASSERT(FALSE);
                Alignment = 0x400000;
            }
        }
        else
        {
            /* This is a reservation, so compute the starting address on the expected 64KB granularity,
               and see where the ending address will fall based on the aligned address and the passed in region size
            */
            EndingAddress = (((ULONG_PTR)PBaseAddress + PRegionSize - 1) | (PAGE_SIZE - 1));

            if (AllocationType & MEM_LARGE_PAGES)
            {
                DPRINT1("NtAllocateVirtualMemory: FIXME\n");
                ASSERT(FALSE);
            }
            else
            {
                StartingAddress = ((ULONG_PTR)PBaseAddress & ~(0x10000 - 1));
            }

            CommitCharge = BYTES_TO_PAGES(EndingAddress - StartingAddress);
        }

        /* Allocate and initialize the VAD */
        Vad = ExAllocatePoolWithTag (NonPagedPool, sizeof(MMVAD_SHORT), 'SdaV');
        if (!Vad)
        {
            DPRINT1("NtAllocateVirtualMemory: Failed to allocate a VAD!\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto ErrorExit;
        }

        Vad->u.LongFlags = 0;

        if (AllocationType & MEM_COMMIT)
        {
            Vad->u.VadFlags.MemCommit = 1;
            Vad->u.VadFlags.CommitCharge = CommitCharge;
        }
        else
        {
            Vad->u.VadFlags.CommitCharge = 0;
        }

        Vad->u.VadFlags.Protection = ProtectionMask;
        Vad->u.VadFlags.PrivateMemory = 1;

        if (AllocationType & (MEM_PHYSICAL | MEM_LARGE_PAGES))
        {
            ASSERT((AllocationType & MEM_WRITE_WATCH) == 0);

            DPRINT1("NtAllocateVirtualMemory: FIXME\n");
            ASSERT(FALSE);
        }
        else if (AllocationType & MEM_WRITE_WATCH)
        {
            ASSERT(AllocationType & MEM_RESERVE);

            DPRINT1("NtAllocateVirtualMemory: FIXME\n");
            ASSERT(FALSE);
        }

        /* Lock the address space and make sure the process isn't already dead */
        AddressSpace = MmGetCurrentAddressSpace();
        MmLockAddressSpace(AddressSpace);

        if (Process->VmDeleted)
        {
            DPRINT1("NtAllocateVirtualMemory: STATUS_PROCESS_IS_TERMINATING. FIXME MiFreeAweInfo()\n");
            Status = STATUS_PROCESS_IS_TERMINATING;
            goto ErrorVadExit;
        }

        // FIXME ? MiInsertAweInfo()

        if (!PBaseAddress)
        {
            if (AllocationType & 0x00100000)
                Status = MiFindEmptyAddressRangeDownTree(PRegionSize, HighestAddress, Alignment, &Process->VadRoot, &StartingAddress);
            else
                Status = MiFindEmptyAddressRange(PRegionSize, Alignment, ZeroBits, &StartingAddress);

            if (!NT_SUCCESS(Status))
            {
                DPRINT1("NtAllocateVirtualMemory: Status %X\n", Status);
                goto ErrorVadExit;
            }

            EndingAddress = (StartingAddress + PRegionSize - 1) | (PAGE_SIZE - 1);

            if (EndingAddress > HighestAddress)
            {
                DPRINT1("NtAllocateVirtualMemory: STATUS_NO_MEMORY. EndingAddress > HighestAddress!\n");
                Status = STATUS_NO_MEMORY;
                goto ErrorVadExit;
            }
        }
        else
        {
            if (MiCheckForConflictingVadExistence(Process, StartingAddress, EndingAddress)) 
            {
                DPRINT1("NtAllocateVirtualMemory: STATUS_CONFLICTING_ADDRESSES\n");
                Status = STATUS_CONFLICTING_ADDRESSES;
                goto ErrorVadExit;
            }
        }

        Vad->StartingVpn = (StartingAddress / PAGE_SIZE);
        Vad->EndingVpn = (EndingAddress / PAGE_SIZE);

        Status = MiInsertVadCharges(Vad, Process);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("NtAllocateVirtualMemory: Status %X\n", Status);
            goto ErrorVadExit;
        }

        MiLockProcessWorkingSetUnsafe(Process, CurrentThread);
        MiInsertVad(Vad, &Process->VadRoot);

        if (AllocationType & (MEM_PHYSICAL | MEM_LARGE_PAGES))
        {
            DPRINT1("NtAllocateVirtualMemory: FIXME\n");
            ASSERT(FALSE);
        }

        MiUnlockProcessWorkingSetUnsafe(Process, CurrentThread);

        PRegionSize = (EndingAddress - StartingAddress + 1);
        Process->VirtualSize += PRegionSize;

        if (Process->VirtualSize > Process->PeakVirtualSize)
            Process->PeakVirtualSize = Process->VirtualSize;

        /* Unlock the address space */
        MmUnlockAddressSpace(AddressSpace);

        /* Detach and dereference the target process if it was different from the current process */
        if (Attached)
            KeUnstackDetachProcess(&ApcState);

        if (ProcessHandle != NtCurrentProcess())
            ObDereferenceObject(Process);

        /* Use SEH to write back the base address and the region size.
           In the case of an exception, we do not return back the exception code, as the memory *has* been allocated.
           The caller would now have to call VirtualQuery or
           do some other similar trick to actually find out where its memory allocation ended up
        */
        _SEH2_TRY
        {
            *URegionSize = PRegionSize;
            *UBaseAddress = (PVOID)StartingAddress;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Ignore exception! */
            DPRINT1("NtAllocateVirtualMemory: Ignore exception!\n");
            //ASSERT(FALSE);
        }
        _SEH2_END;

        DPRINT("NtAllocateVirtualMemory: Reserved %X bytes at %p\n", PRegionSize, StartingAddress);
        return STATUS_SUCCESS;

ErrorVadExit:

        DPRINT1("NtAllocateVirtualMemory: ErrorVadExit\n");

        MmUnlockAddressSpace(AddressSpace);
        ExFreePool(Vad);

        if (AllocationType & (MEM_PHYSICAL | MEM_LARGE_PAGES))
        {
            DPRINT1("NtAllocateVirtualMemory: FIXME\n");
            ASSERT(FALSE);
        }
        else if (AllocationType & MEM_WRITE_WATCH)
        {
            DPRINT1("NtAllocateVirtualMemory: FIXME\n");
            ASSERT(FALSE);
        }

        goto ErrorExit;
    }

    /* This is a MEM_COMMIT on top of an existing address which must have been MEM_RESERVED already.
       Compute the start and ending base addresses based on the user input,
       and then compute the actual region size once all the alignments have been done.
    */
    if (AllocationType == MEM_RESET)
    {
        EndingAddress = ((ULONG_PTR)PAGE_ALIGN((ULONG_PTR)PBaseAddress + PRegionSize) - 1);
        StartingAddress = (ULONG_PTR)PAGE_ALIGN((PUCHAR)PBaseAddress + PAGE_SIZE - 1);

        if (StartingAddress > EndingAddress)
        {
            DPRINT1("NtAllocateVirtualMemory: FIXME\n");
            ASSERT(FALSE);
            Status = STATUS_CONFLICTING_ADDRESSES;
            goto ErrorExit;
        }
    }
    else
    {
        StartingAddress = (ULONG_PTR)PAGE_ALIGN(PBaseAddress);
        EndingAddress = (((ULONG_PTR)PBaseAddress + PRegionSize - 1) | (PAGE_SIZE - 1));
    }

    PRegionSize = (EndingAddress - StartingAddress + 1);

    /* Lock the address space and make sure the process isn't already dead */
    AddressSpace = MmGetCurrentAddressSpace();
    MmLockAddressSpace(AddressSpace);

    if (Process->VmDeleted)
    {
        DPRINT1("NtAllocateVirtualMemory: STATUS_PROCESS_IS_TERMINATING\n");
        Status = STATUS_PROCESS_IS_TERMINATING;
        goto ErrorExit1;
    }

    /* Get the VAD for this address range, and make sure it exists */
    FoundVad = (PMMVAD)MiCheckForConflictingNode((StartingAddress / PAGE_SIZE),
                                                 (EndingAddress / PAGE_SIZE),
                                                 &Process->VadRoot);
    if (!FoundVad)
    {
        DPRINT1("NtAllocateVirtualMemory: STATUS_CONFLICTING_ADDRESSES\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto ErrorExit1;
    }

    DPRINT("NtAllocateVirtualMemory: FoundVad %p, Start %X, End %X\n", FoundVad, StartingAddress, EndingAddress);

    /* These kinds of VADs are illegal for this Windows function when trying to commit an existing range */
    if (FoundVad->u.VadFlags.VadType == VadAwe ||
        FoundVad->u.VadFlags.VadType == VadDevicePhysicalMemory ||
        FoundVad->u.VadFlags.VadType == VadLargePages)
    {
        DPRINT1("NtAllocateVirtualMemory: STATUS_CONFLICTING_ADDRESSES\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto ErrorExit1;
    }

    /* Make sure that this address range actually fits within the VAD for it */
    if ((StartingAddress / PAGE_SIZE) < FoundVad->StartingVpn ||
        (EndingAddress / PAGE_SIZE) > FoundVad->EndingVpn)
    {
        DPRINT1("NtAllocateVirtualMemory: STATUS_CONFLICTING_ADDRESSES\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto ErrorExit1;
    }

    if (FoundVad->u.VadFlags.CommitCharge == 0x7FFFF)
    {
        DPRINT("NtAllocateVirtualMemory: STATUS_CONFLICTING_ADDRESSES\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto ErrorExit1;
    }

    if (AllocationType == MEM_RESET)
    {
        Status = MiResetVirtualMemory(StartingAddress, EndingAddress, FoundVad, Process);
        KeReleaseGuardedMutex(&Process->AddressCreationLock);
        goto Exit;
    }

    /* Is this a previously reserved section being committed? If so, enter the special section path */
    if (!FoundVad->u.VadFlags.PrivateMemory)
    {
        /* You cannot commit large page sections through this API */
        if (FoundVad->u.VadFlags.VadType == VadLargePageSection)
        {
            DPRINT1("NtAllocateVirtualMemory: Large page sections cannot be VirtualAlloc'd\n");
            Status = STATUS_INVALID_PAGE_PROTECTION;
            goto ErrorExit1;
        }

        /* You can only use caching flags on a rotate VAD */
        if ((Protect & (PAGE_NOCACHE | PAGE_WRITECOMBINE)) &&
            FoundVad->u.VadFlags.VadType != VadRotatePhysical)
        {
            DPRINT1("NtAllocateVirtualMemory: Cannot use caching flags with anything but rotate VADs\n");
            Status = STATUS_INVALID_PAGE_PROTECTION;
            goto ErrorExit1;
        }

        /* We should make sure that the section's permissions aren't being messed with */
        if (FoundVad->u.VadFlags.NoChange)
        {
            /* Make sure it's okay to touch it
               Note: The Windows 2003 kernel has a bug here,
               passing the unaligned base address together with the aligned size,
               potentially covering a region larger than the actual allocation.
               Might be exposed through NtGdiCreateDIBSection w/ section handle.
               For now we keep this behavior.
               TODO: analyze possible implications, create test case
            */
            Status = MiCheckSecuredVad(FoundVad, PBaseAddress, PRegionSize, ProtectionMask);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("NtAllocateVirtualMemory: Secured VAD being messed around with. Status %X\n", Status);
                goto ErrorExit1;
            }
        }

        if (FoundVad->ControlArea->FilePointer)
        {
            /* ARM3 does not support file-backed sections, only shared memory */
            ASSERT(FoundVad->ControlArea->FilePointer == NULL);

            DPRINT1("NtAllocateVirtualMemory: FIXME\n");
            ASSERT(FALSE);
        }

        /* Compute PTE addresses and the quota charge, then grab the commit lock */
        StartPte = MI_GET_PROTOTYPE_PTE_FOR_VPN(FoundVad, (StartingAddress / PAGE_SIZE));
        LastPte = MI_GET_PROTOTYPE_PTE_FOR_VPN(FoundVad, (EndingAddress / PAGE_SIZE));

        QuotaCharge = (ULONG)(LastPte - StartPte + 1);
        Pte = StartPte;

        DPRINT("NtAllocateVirtualMemory: StartingAddress %p, EndingAddress %p, StartPte %p, LastPte %p\n", StartingAddress, EndingAddress, StartPte, LastPte);

        QuotaCopyOnWrite = 0;

        /* Rotate VADs cannot be guard pages or inaccessible, nor copy on write */
        if (FoundVad->u.VadFlags.VadType == VadRotatePhysical)
        {
            if ((Protect & (PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY | PAGE_NOACCESS | PAGE_GUARD)))
            {
                DPRINT1("NtAllocateVirtualMemory: Invalid page protection for rotate VAD\n");
                Status = STATUS_INVALID_PAGE_PROTECTION;
                goto ErrorExit1;
            }
        }
        else if ((ProtectionMask & 5) == 5)
        {
            QuotaCopyOnWrite = QuotaCharge;
        }

        if (QuotaCopyOnWrite);
        {
            Status = PsChargeProcessPageFileQuota(Process, QuotaCopyOnWrite);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("NtAllocateVirtualMemory: FIXME\n");
                ASSERT(FALSE);
                goto ErrorExit;
            }

            if (Process->CommitChargeLimit)
            {
                if ((Process->CommitCharge + QuotaCopyOnWrite) > Process->CommitChargeLimit)
                {
                    if (Process->Job)
                    {
                        DPRINT1("NtAllocateVirtualMemory: FIXME\n");
                        ASSERT(FALSE);
                    }

                    DPRINT1("NtAllocateVirtualMemory: FIXME\n");
                    ASSERT(FALSE);

                    Status = STATUS_COMMITMENT_LIMIT;
                    goto ErrorExit;
                }
            }

            if (Process->JobStatus & 0x10)
            {
                DPRINT1("NtAllocateVirtualMemory: FIXME\n");
                ASSERT(FALSE);
            }
        }

        KeAcquireGuardedMutexUnsafe(&MmSectionCommitMutex);

        if (!MiChargeCommitment((QuotaCharge + QuotaCopyOnWrite), NULL))
        {
            DPRINT1("NtAllocateVirtualMemory: FIXME\n");
            ASSERT(FALSE);
        }

        /* Get the segment template PTE and start looping each page */
        TempPte = FoundVad->ControlArea->Segment->SegmentPteTemplate;
        ASSERT(TempPte.u.Long != 0);

        QuotaFree = 0;

        while (Pte <= LastPte)
        {
            /* For each non-already-committed page, write the invalid template PTE */
            if (!Pte->u.Long)
                MI_WRITE_INVALID_PTE(Pte, TempPte);
            else
                QuotaFree++;

            Pte++;
        }

        /* Now do the commit accounting and release the lock */
        if (!IsReturnQuota)
        {
            ASSERT(QuotaCharge >= QuotaFree);
            QuotaCharge -= QuotaFree;
        }
        else
        {
            QuotaFree = 0;
        }

        if (QuotaCharge)
        {
            FoundVad->ControlArea->Segment->NumberOfCommittedPages += QuotaCharge;
            InterlockedExchangeAdd((PLONG)&MmSharedCommit, QuotaCharge);
        }

        KeReleaseGuardedMutexUnsafe(&MmSectionCommitMutex);

        if (QuotaCopyOnWrite)
        {
            FoundVad->u.VadFlags.CommitCharge += QuotaCopyOnWrite;
            Process->CommitCharge += QuotaCopyOnWrite;

            if (Process->CommitCharge > Process->CommitChargePeak)
                Process->CommitChargePeak = Process->CommitCharge;
        }

        MiSetProtectionOnSection(Process,
                                 FoundVad,
                                 StartingAddress,
                                 EndingAddress,
                                 Protect,
                                 &OldProtect,
                                 TRUE,
                                 &Locked);
    
        /* Unlock the address space */
        MmUnlockAddressSpace(AddressSpace);

        if (QuotaFree)
        {
            DPRINT1("NtAllocateVirtualMemory: FIXME\n");
            ASSERT(FALSE);
        }

        if (Attached)
            KeUnstackDetachProcess(&ApcState);

        if (ProcessHandle != NtCurrentProcess())
            ObDereferenceObject(Process);

        /* Use SEH to write back the base address and the region size.
           In the case of an exception, we strangely do return back the exception code,
           even though the memory *has* been allocated.
           This mimics Windows behavior and there is not much we can do about it.
        */
        _SEH2_TRY
        {
            *URegionSize = PRegionSize;
            *UBaseAddress = (PVOID)StartingAddress;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = _SEH2_GetExceptionCode();
        }
        _SEH2_END;

        return STATUS_SUCCESS;
    }

    // FoundVad->u.VadFlags.PrivateMemory

    /* While this is an actual Windows check */
    ASSERT(FoundVad->u.VadFlags.VadType != VadRotatePhysical);

    /* Throw out attempts to use copy-on-write through this API path */
    if ((Protect & PAGE_WRITECOPY) || (Protect & PAGE_EXECUTE_WRITECOPY))
    {
        DPRINT1("NtAllocateVirtualMemory: STATUS_INVALID_PAGE_PROTECTION\n");
        Status = STATUS_INVALID_PAGE_PROTECTION;
        goto ErrorExit1;
    }

    /* Initialize a demand-zero PTE */
    TempPte.u.Long = 0;
    TempPte.u.Soft.Protection = ProtectionMask;
    ASSERT(TempPte.u.Long != 0);

    /* Get the PTE, PDE and the last PTE for this address range */
    Pde = MiAddressToPde(StartingAddress);
    Pte = MiAddressToPte(StartingAddress);
    LastPte = MiAddressToPte(EndingAddress);

    QuotaCharge = (SIZE_T)(LastPte - Pte + 1);

    if (FoundVad->u.VadFlags.MemCommit)
        EndVpnPte = MiAddressToPte(FoundVad->EndingVpn * PAGE_SIZE);
    else
        EndVpnPte = NULL;

    if (Process->CommitChargeLimit &&
        Process->CommitChargeLimit < (Process->CommitCharge + QuotaCharge))
    {
        DPRINT1("NtAllocateVirtualMemory: FIXME\n");
        ASSERT(FALSE);
        goto ErrorExit1;
    }

    if (Process->JobStatus & 0x10)
    {
        DPRINT1("NtAllocateVirtualMemory: FIXME\n");
        ASSERT(FALSE);
    }

    Status = PsChargeProcessPageFileQuota(Process, QuotaCharge);
    if (!NT_SUCCESS (Status))
    {
        DPRINT1("NtAllocateVirtualMemory: FIXME\n");
        ASSERT(FALSE);
        goto ErrorExit1;
    }

    if (!MiChargeCommitment(QuotaCharge, NULL))
    {
        DPRINT1("NtAllocateVirtualMemory: FIXME\n");
        ASSERT(FALSE);
    }

    /* Update the commit charge in the VAD as well as in the process,
       and check if this commit charge was now higher than the last recorded peak,
       in which case we also update the peak
    */
    FoundVad->u.VadFlags.CommitCharge += QuotaCharge;
    Process->CommitCharge += QuotaCharge;

    if (Process->CommitChargePeak < Process->CommitCharge)
        Process->CommitChargePeak = Process->CommitCharge;

    QuotaFree = 0;

    if (!IsReturnQuota)
        /* Lock the working set while we play with user pages and page tables */
        MiLockProcessWorkingSetUnsafe(Process, CurrentThread);

    /* Make the current page table valid, and then loop each page within it */
    MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);

    while (Pte <= LastPte)
    {
        /* Have we crossed into a new page table? */
        if (MiIsPteOnPdeBoundary(Pte))
        {
            /* Get the PDE and now make it valid too */
            Pde = MiPteToPde(Pte);
            MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);
        }

        /* Is this a zero PTE as expected? */
        if (!Pte->u.Long)
        {
            if (Pte <= EndVpnPte)
                QuotaFree++;

            /* First increment the count of pages in the page table for this process */
            MiIncrementPageTableReferences(MiPteToAddress(Pte));

            /* And now write the invalid demand-zero PTE as requested */
            MI_WRITE_INVALID_PTE(Pte, TempPte);
        }
        else if (Pte->u.Long == MmDecommittedPte.u.Long)
        {
            MI_WRITE_INVALID_PTE(Pte, TempPte);
        }
        else
        {
            /* We don't handle these scenarios yet */
            if (!IsChangeProtection)
            {
                if (!Pte->u.Soft.Valid &&
                    Pte->u.Soft.Prototype &&
                    Pte->u.Soft.PageFileHigh != MI_PTE_LOOKUP_NEEDED)
                {
                    if (Protect != MiGetPageProtection(Pte))
                        IsChangeProtection = TRUE;

                    MiMakePdeExistAndMakeValid (Pde, Process, MM_NOIRQL);
                }
                else
                {
                    if (Protect != MiGetPageProtection(Pte))
                        IsChangeProtection = TRUE;
                }
            }

            QuotaFree++;
        }

        /* Move to the next PTE */
        Pte++;
    }

    /* Release the working set lock */
    MiUnlockProcessWorkingSetUnsafe(Process, CurrentThread);

    if (!IsReturnQuota && QuotaFree)
        ExcessCharge = QuotaFree;

    if (ExcessCharge)
    {
        if (!IsReturnQuota)
        {
            FoundVad->u.VadFlags.CommitCharge -= ExcessCharge;
            ASSERT((LONG_PTR)FoundVad->u.VadFlags.CommitCharge >= 0);
            Process->CommitCharge -= ExcessCharge;
        }

        /* Unlock the address space */
        MmUnlockAddressSpace(AddressSpace);

        if (!IsReturnQuota)
        {
            ASSERT((SSIZE_T)(ExcessCharge) >= 0);
            ASSERT(MmTotalCommittedPages >= (ExcessCharge));
            InterlockedExchangeAddSizeT(&MmTotalCommittedPages, -ExcessCharge);
        }

        PsReturnProcessPageFileQuota(Process, ExcessCharge);

        if (Process->JobStatus & 0x10)
        {
            DPRINT1("NtAllocateVirtualMemory: FIXME\n");
            ASSERT(FALSE);
        }
    }
    else
    {
        /* Unlock the address space */
        MmUnlockAddressSpace(AddressSpace);
    }

Exit:

    /* Check if we need to update the protection */
    if (IsChangeProtection)
    {
        DPRINT1("NtAllocateVirtualMemory: FIXME\n");
        ASSERT(FALSE);
    }

    if (Attached)
        KeUnstackDetachProcess(&ApcState);

    if (ProcessHandle != NtCurrentProcess())
        ObDereferenceObject(Process);

    /* Use SEH to write back the base address and the region size.
       In the case of an exception, we strangely do return back the exception code,
       even though the memory *has* been allocated.
       This mimics Windows behavior and there is not much we can do about it.
    */
    _SEH2_TRY
    {
        *URegionSize = PRegionSize;
        *UBaseAddress = (PVOID)StartingAddress;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    return Status;

ErrorExit1:

    /* Unlock the address space */
    MmUnlockAddressSpace(AddressSpace);

ErrorExit:

    if (Attached)
        KeUnstackDetachProcess (&ApcState);

    if (ProcessHandle != NtCurrentProcess())
        ObDereferenceObject (Process);

    return Status;
}

NTSTATUS
NTAPI
NtFreeVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID* OutBase,
    _In_ SIZE_T* OutSize,
    _In_ ULONG FreeType)
{
    PETHREAD CurrentThread = PsGetCurrentThread();
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
    PMMADDRESS_NODE PreviousNode;
    PMMADDRESS_NODE NextNode;
    PMMSUPPORT AddressSpace;
    PEPROCESS Process;
    PMMPTE StartPte;
    PMMPTE EndPte;
    PMMVAD Vad;
    PMMVAD vad = NULL;
    PVOID BaseAddress;
    LONG_PTR AlreadyDecommitted;
    LONG_PTR CommitReduction = 0;
    ULONG_PTR StartingAddress;
    ULONG_PTR EndingAddress;
    SIZE_T RegionSize;
    KAPC_STATE ApcState;
    BOOLEAN Attached = FALSE;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("NtFreeVirtualMemory: %p, %p, %X, %X\n",
           ProcessHandle, (OutBase ? *OutBase : 0), (OutSize ? *OutSize : 0), FreeType);

    if (FreeType & ~(MEM_RELEASE | MEM_DECOMMIT))
    {
        DPRINT1("NtFreeVirtualMemory: return STATUS_INVALID_PARAMETER_4\n");
        return STATUS_INVALID_PARAMETER_4;
    }

    if (!(FreeType & (MEM_RELEASE | MEM_DECOMMIT)))
    {
        DPRINT1("NtFreeVirtualMemory: return STATUS_INVALID_PARAMETER_4\n");
        return STATUS_INVALID_PARAMETER_4;
    }

    if ((FreeType & (MEM_RELEASE | MEM_DECOMMIT)) == (MEM_RELEASE | MEM_DECOMMIT))
    {
        DPRINT1("NtFreeVirtualMemory: return STATUS_INVALID_PARAMETER_4\n");
        return STATUS_INVALID_PARAMETER_4;
    }

    /* Enter SEH for probe and capture. On failure, return back to the caller with an exception violation. */
    _SEH2_TRY
    {
        /* Check for user-mode parameters and make sure that they are writeable */
        if (PreviousMode != KernelMode)
        {
            ProbeForWritePointer(OutBase);
            ProbeForWriteUlong(OutSize);
        }

        /* Capture the current values */
        BaseAddress = *OutBase;
        RegionSize = *OutSize;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    /* Make sure the allocation wouldn't overflow past the user area */
    if (((ULONG_PTR)MM_HIGHEST_USER_ADDRESS - (ULONG_PTR)BaseAddress) < RegionSize)
    {
        DPRINT1("NtFreeVirtualMemory: return STATUS_INVALID_PARAMETER_3\n");
        return STATUS_INVALID_PARAMETER_3;
    }

    /* If this is for the current process, just use PsGetCurrentProcess */
    if (ProcessHandle == NtCurrentProcess())
    {
        Process = CurrentProcess;
    }
    else
    {
        /* Otherwise, reference the process with VM rights and attach to it if this isn't the current process.
           We must attach because we'll be touching PTEs and PDEs that belong to user-mode memory,
           and also touching the Working Set which is stored in Hyperspace.
        */
        Status = ObReferenceObjectByHandle(ProcessHandle,
                                           PROCESS_VM_OPERATION,
                                           PsProcessType,
                                           PreviousMode,
                                           (PVOID *)&Process,
                                           NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("NtFreeVirtualMemory: Status %X\n", Status);
            return Status;
        }

        if (CurrentProcess != Process)
        {
            KeStackAttachProcess(&Process->Pcb, &ApcState);
            Attached = TRUE;
        }
    }

    DPRINT("NtFreeVirtualMemory: %p, %p, %IX, %X\n", Process, BaseAddress, RegionSize, FreeType);

    /* Lock the address space */
    AddressSpace = MmGetCurrentAddressSpace();
    MmLockAddressSpace(AddressSpace);

    /* If the address space is being deleted, fail the de-allocation since it's too late to do anything about it */
    if (Process->VmDeleted)
    {
        DPRINT1("NtFreeVirtualMemory: Process is dead\n");
        Status = STATUS_PROCESS_IS_TERMINATING;
        goto ErrorExit;
    }

    /* Compute start and end addresses, and locate the VAD */
    StartingAddress = (ULONG_PTR)PAGE_ALIGN(BaseAddress);
    EndingAddress = (((ULONG_PTR)BaseAddress + RegionSize - 1) | (PAGE_SIZE - 1));

    Vad = MiLocateAddress((PVOID)StartingAddress);
    if (!Vad)
    {
        DPRINT1("NtFreeVirtualMemory: Unable to find VAD for %p\n", StartingAddress);
        Status = STATUS_MEMORY_NOT_ALLOCATED;
        goto ErrorExit;
    }

    /* If the range exceeds the VAD's ending VPN, fail this request */
    if (Vad->EndingVpn < (EndingAddress / PAGE_SIZE))
    {
        DPRINT1("NtFreeVirtualMemory: Address %p is beyond the VAD\n", EndingAddress);
        Status = STATUS_UNABLE_TO_FREE_VM;
        goto ErrorExit;
    }

    /* Only private memory (except rotate VADs) can be freed through here */
    if ((!Vad->u.VadFlags.PrivateMemory && Vad->u.VadFlags.VadType != VadRotatePhysical) ||
        Vad->u.VadFlags.VadType == VadDevicePhysicalMemory)
    {
        DPRINT1("NtFreeVirtualMemory: Attempt to free section memory\n");
        Status = STATUS_UNABLE_TO_DELETE_SECTION;
        goto ErrorExit;
    }

    /* ARM3 does not yet handle protected VM */
    if (Vad->u.VadFlags.NoChange)
    {
        ASSERT(Vad->u.VadFlags.NoChange == 0);

        if (FreeType & MEM_RELEASE)
        {
            DPRINT1("NtFreeVirtualMemory: FIXME\n");
            ASSERT(FALSE);
        }
        else
        {
            DPRINT1("NtFreeVirtualMemory: FIXME\n");
            ASSERT(FALSE);
        }
    }

    PreviousNode = MiGetPreviousNode((PMMADDRESS_NODE)Vad);
    NextNode = MiGetNextNode((PMMADDRESS_NODE)Vad);

    /* Now we can try the operation. First check if this is a RELEASE or a DECOMMIT */
    if (FreeType & MEM_RELEASE)
    {
        /* ARM3 only supports this VAD in this path */
        ASSERT(Vad->u.VadFlags.VadType == VadNone);

        /* Is the caller trying to remove the whole VAD,
           or remove only a portion of it? If no region size is specified,
           then the assumption is that the whole VAD is to be destroyed
        */
        if (!RegionSize)
        {
            /* The caller must specify the base address identically to the range that is stored in the VAD. */
            if (((ULONG_PTR)BaseAddress / PAGE_SIZE) != Vad->StartingVpn)
            {
                DPRINT1("NtFreeVirtualMemory: Address 0x%p does not match the VAD\n", BaseAddress);
                Status = STATUS_FREE_VM_NOT_AT_BASE;
                goto ErrorExit;
            }

            /* Now compute the actual start/end addresses based on the VAD */
            StartingAddress = (Vad->StartingVpn * PAGE_SIZE);
            EndingAddress = ((Vad->EndingVpn * PAGE_SIZE) | (PAGE_SIZE - 1));

            if (Vad->u.VadFlags.VadType == VadRotatePhysical)
            {
                DPRINT1("NtFreeVirtualMemory: FIXME\n");
                ASSERT(FALSE);
                goto ReleaseFinish;
            }
            else if (Vad->u.VadFlags.VadType == VadLargePages)
            {
                DPRINT1("NtFreeVirtualMemory: FIXME\n");
                ASSERT(FALSE);
            }
            if (Vad->u.VadFlags.VadType == VadAwe)
            {
                DPRINT1("NtFreeVirtualMemory: FIXME\n");
                ASSERT(FALSE);
            }
            else if (Vad->u.VadFlags.VadType == VadWriteWatch)
            {
                DPRINT1("NtFreeVirtualMemory: FIXME\n");
                ASSERT(FALSE);
            }
            else
            {
                /* Lock the working set */
                MiLockProcessWorkingSetUnsafe(Process, CurrentThread);
            }

            /* Finally remove the VAD from the VAD tree */
            ASSERT(Process->VadRoot.NumberGenericTableElements >= 1);
            vad = Vad;
            MiRemoveNode((PMMADDRESS_NODE)Vad, &Process->VadRoot);
        }
        else
        {
            /* This means the caller wants to release a specific region within the range.
               We have to find out which range this is -- the following possibilities exist plus their union (CASE D):

               STARTING ADDRESS                                   ENDING ADDRESS
               [<========][========================================][=========>]
                 CASE A                  CASE B                       CASE C

               First, check for case A or D
            */
            if ((StartingAddress / PAGE_SIZE) == Vad->StartingVpn)
            {
                /* Check for case D */
                if ((EndingAddress / PAGE_SIZE) == Vad->EndingVpn)
                {
                    /* This is the easiest one to handle -- it is identical to the code path above
                       when the caller sets a zero region size and the whole VAD is destroyed
                    */
                    if (Vad->u.VadFlags.VadType == VadRotatePhysical)
                    {
                        DPRINT1("NtFreeVirtualMemory: FIXME\n");
                        ASSERT(FALSE);
                        goto ReleaseFinish;
                    }

                    if (Vad->u.VadFlags.VadType == VadLargePages)
                    {
                        DPRINT1("NtFreeVirtualMemory: FIXME\n");
                        ASSERT(FALSE);
                    }
                    else if (Vad->u.VadFlags.VadType == VadAwe)
                    {
                        DPRINT1("NtFreeVirtualMemory: FIXME\n");
                        ASSERT(FALSE);
                    }
                    else if (Vad->u.VadFlags.VadType == VadWriteWatch)
                    {
                        DPRINT1("NtFreeVirtualMemory: FIXME\n");
                        ASSERT(FALSE);
                    }
                    else
                    {
                        /* Lock the working set */
                        MiLockProcessWorkingSetUnsafe(Process, CurrentThread);
                    }

                    /* Finally remove the VAD from the VAD tree */
                    ASSERT(Process->VadRoot.NumberGenericTableElements >= 1);
                    vad = Vad;
                    MiRemoveNode((PMMADDRESS_NODE)Vad, &Process->VadRoot);
                }
                else
                {
                    /* This case is pretty easy too -- we compute a bunch of pages to decommit,
                       and then push the VAD's starting address a bit further down, then decrement the commit charge

                       NOT YET IMPLEMENTED IN ARM3.
                    */
                    if (Vad->u.VadFlags.VadType == VadAwe || 
                        Vad->u.VadFlags.VadType == VadLargePages ||
                        Vad->u.VadFlags.VadType == VadRotatePhysical ||
                        Vad->u.VadFlags.VadType == VadWriteWatch)
                    {
                        DPRINT1("NtFreeVirtualMemory: Case A not handled\n");
                        Status = STATUS_FREE_VM_NOT_AT_BASE;
                        goto ErrorExit;
                    }

                    DPRINT1("NtFreeVirtualMemory: FIXME\n");
                    ASSERT(FALSE);

                    /* After analyzing the VAD, set it to NULL so that we don't free it in the exit path */
                    NextNode = (PMMADDRESS_NODE)Vad;
                    Vad = NULL;
                }
            }
            else
            {
                /* This is case B or case C. First check for case C */
                if (Vad->u.VadFlags.VadType == VadAwe || 
                    Vad->u.VadFlags.VadType == VadLargePages ||
                    Vad->u.VadFlags.VadType == VadRotatePhysical ||
                    Vad->u.VadFlags.VadType == VadWriteWatch)
                {
                    Status = STATUS_FREE_VM_NOT_AT_BASE;
                    goto ErrorExit;
                }

                if ((EndingAddress / PAGE_SIZE) == Vad->EndingVpn)
                {
                    /* This is pretty easy and similar to case A.
                       We compute the amount of pages to decommit,
                       update the VAD's commit charge and then change the ending address of the VAD to be a bit smaller.
                    */

                    /* Lock the working set */
                    MiLockProcessWorkingSetUnsafe(Process, CurrentThread);

                    CommitReduction = MiCalculatePageCommitment(StartingAddress, EndingAddress, Vad, Process);
                    Vad->u.VadFlags.CommitCharge -= CommitReduction;

                    Vad->EndingVpn = ((StartingAddress - 1) / PAGE_SIZE);
                    PreviousNode = (PMMADDRESS_NODE)Vad;
                }
                else
                {
                    /*  This is case B and the hardest one.
                        Because we are removing a chunk of memory from the very middle of the VAD,
                        we must actually split the VAD into two new VADs
                        and compute the commit charges for each of them, and reinsert new charges.

                       NOT YET IMPLEMENTED IN ARM3.
                    */
                    DPRINT1("NtFreeVirtualMemory: Case B not handled\n");
                    ASSERT(FALSE);
                    //PreviousNode = (PMMADDRESS_NODE)Vad;
                    //NextNode = (PMMADDRESS_NODE)NewVad;
                }

                /* After analyzing the VAD, set it to NULL so that we don't free it in the exit path */
                Vad = NULL;
            }
        }

        DPRINT("NtFreeVirtualMemory: FIXME MiDeletePageTablesForPhysicalRange()\n");

        /* Now we have a range of pages to dereference,
           so call the right API to do that and then release the working set,
           since we're done messing around with process pages.
        */
        MiDeleteVirtualAddresses(StartingAddress, EndingAddress, NULL);
        MiUnlockProcessWorkingSetUnsafe(Process, CurrentThread);

        MiReturnPageTablePageCommitment(StartingAddress, EndingAddress, Process, PreviousNode, NextNode);

        if (vad)
            MiRemoveVadCharges(vad, Process);

        RegionSize = ((PCHAR)EndingAddress - (PCHAR)StartingAddress + 1);

        Process->VirtualSize -= RegionSize;
        Process->CommitCharge -= CommitReduction;

        Status = STATUS_SUCCESS;

ReleaseFinish:

        /* Unlock the address space and free the VAD in failure cases.
           Next, detach from the target process so we can write the region size and the base address
           to the correct source process, and dereference the target process.
        */
        MmUnlockAddressSpace(AddressSpace);

        if (CommitReduction)
        {
            ASSERT(Vad == NULL);

            PsReturnProcessPageFileQuota(Process, CommitReduction);

            ASSERT((SSIZE_T)(CommitReduction) >= 0);
            ASSERT(MmTotalCommittedPages >= (CommitReduction));
            InterlockedExchangeAddSizeT(&MmTotalCommittedPages, -CommitReduction);

            if (Process->JobStatus & 0x10)
            {
                DPRINT1("NtFreeVirtualMemory: FIXME\n");
                ASSERT(FALSE);
            }
        }
        else if (Vad)
        {
            ExFreePool(Vad);
        }

        if (Attached)
            KeUnstackDetachProcess(&ApcState);

        if (ProcessHandle != NtCurrentProcess())
            ObDereferenceObject(Process);

        /* Use SEH to safely return the region size and the base address of the deallocation.
           If we get an access violation, don't return a failure code as the deallocation *has* happened.
           The caller will just have to figure out another way to find out where it is (such as VirtualQuery).
        */
        _SEH2_TRY
        {
            *OutSize = RegionSize;
            *OutBase = (PVOID)StartingAddress;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
        }
        _SEH2_END;

        DPRINT("NtFreeVirtualMemory: Status %X\n", Status);
        return Status;
    }

    /* This is the decommit path. You cannot decommit from the following VADs in Windows, so fail the vall */
    if (Vad->u.VadFlags.VadType == VadAwe)
    {
        Status = STATUS_MEMORY_NOT_ALLOCATED;
        goto ErrorExit;
    }

    if (Vad->u.VadFlags.VadType == VadLargePages ||
        Vad->u.VadFlags.VadType == VadRotatePhysical)
    {
        Status = STATUS_MEMORY_NOT_ALLOCATED;
        goto ErrorExit;
    }

    /* If the caller did not specify a region size,
       first make sure that this region is actually committed.
       If it is, then compute the ending address based on the VAD.
    */
    if (!RegionSize)
    {
        if (((ULONG_PTR)BaseAddress / PAGE_SIZE) != Vad->StartingVpn)
        {
            DPRINT1("NtFreeVirtualMemory: Decomitting non-committed memory\n");
            Status = STATUS_FREE_VM_NOT_AT_BASE;
            goto ErrorExit;
        }

        EndingAddress = ((Vad->EndingVpn * PAGE_SIZE) | (PAGE_SIZE - 1));
    }

    /* Decommit the PTEs for the range plus the actual backing pages for the range,
       then reduce that amount from the commit charge in the VAD
    */
    StartPte = MiAddressToPte(StartingAddress);
    EndPte = MiAddressToPte(EndingAddress);

    AlreadyDecommitted = MiDecommitPages((PVOID)StartingAddress, EndPte, Process, Vad);
    CommitReduction = ((EndPte - StartPte) + 1 - AlreadyDecommitted);

    ASSERT(CommitReduction >= 0);
    ASSERT(Vad->u.VadFlags.CommitCharge >= CommitReduction);

    Vad->u.VadFlags.CommitCharge -= CommitReduction;

    /* We are done, go to the exit path without freeing the VAD
       as it remains valid since we have not released the allocation.
    */
    Vad = NULL;
    Status = STATUS_SUCCESS;

    /* Update the process counters */
    RegionSize = (EndingAddress - StartingAddress + 1);
    Process->CommitCharge -= CommitReduction;

    if (FreeType & MEM_RELEASE)
        Process->VirtualSize -= RegionSize;

    /* Unlock the address space and free the VAD in failure cases.
       Next, detach from the target process so we can write the region size and the base address
      to the correct source process, and dereference the target process.
    */
    MmUnlockAddressSpace(AddressSpace);

    if (CommitReduction)
    {
        PsReturnProcessPageFileQuota(Process, CommitReduction);

        ASSERT((SSIZE_T)(CommitReduction) >= 0);
        ASSERT(MmTotalCommittedPages >= (CommitReduction));
        InterlockedExchangeAddSizeT(&MmTotalCommittedPages, -CommitReduction);

        if (Process->JobStatus & 0x10)
        {
            DPRINT1("NtFreeVirtualMemory: FIXME\n");
            ASSERT(FALSE);
        }
    }
    else if (Vad)
    {
        ExFreePool(Vad);
    }

    if (Vad)
        ExFreePool(Vad);

    if (Attached)
        KeUnstackDetachProcess(&ApcState);

    if (ProcessHandle != NtCurrentProcess())
        ObDereferenceObject(Process);

    /* Use SEH to safely return the region size and the base address of the deallocation.
       If we get an access violation, don't return a failure code as the deallocation *has* happened.
       The caller will just have to figure out another way to find out where it is (such as VirtualQuery).
    */
    _SEH2_TRY
    {
        *OutSize = RegionSize;
        *OutBase = (PVOID)StartingAddress;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
    }
    _SEH2_END;

    return Status;


    /* In the failure path, we detach and derefernece the target process,
       and return whatever failure code was sent.
    */

ErrorExit:

    MmUnlockAddressSpace(AddressSpace);

    if (Attached)
        KeUnstackDetachProcess(&ApcState);

    if (ProcessHandle != NtCurrentProcess())
        ObDereferenceObject(Process);

    return Status;
}

/* EOF */
