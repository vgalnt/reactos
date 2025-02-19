
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "miarm.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

ULONG MmDataClusterSize;
ULONG MmCodeClusterSize;
ULONG MmInPageSupportMinimum = 4;
ULONG MiInPageSinglePages = 0;
PFN_NUMBER MmFreeGoal = 100;
SIZE_T MmSystemLockPagesCount = 0; //FIXME: #if !defined(ONE_CPU) - SIZE_T MmSystemLockPagesCount[32] = {0};

static CHAR MmMakeProtectNotWriteCopy[32] =
{
    0x18, 0x01, 0x02, 0x03, 0x04, 0x04, 0x06, 0x06,
    0x18, 0x09, 0x0A, 0x0B, 0x0C, 0x0C, 0x0E, 0x0E,
    0x18, 0x11, 0x12, 0x13, 0x14, 0x14, 0x16, 0x16,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1C, 0x1E, 0x1E
};

extern MI_PFN_CACHE_ATTRIBUTE MiPlatformCacheAttributes[2][MmMaximumCacheType];
extern PMMPTE MiSessionLastPte;
extern PMM_SESSION_SPACE MmSessionSpace;
extern PVOID MmHyperSpaceEnd;
extern PVOID MiSessionImageStart;
extern PVOID MiSessionImageEnd;
extern PVOID MiSessionViewStart;   // 0xBE000000
extern PVOID MiSessionSpaceWs;
extern ULONG MmSecondaryColorMask;
extern BOOLEAN MmProtectFreedNonPagedPool;
extern PVOID MmNonPagedPoolStart;
extern SIZE_T MmSizeOfNonPagedPoolInBytes;
extern PVOID MmNonPagedPoolExpansionStart;
extern MMPTE PrototypePte;
extern MMPTE DemandZeroPte;
extern MMPDE DemandZeroPde;
extern PMMPTE MmSharedUserDataPte;
extern MM_PAGED_POOL_INFO MmPagedPoolInfo;
extern RTL_BITMAP MiPfnBitMap;
extern SLIST_HEADER MmInPageSupportSListHead;
extern PVOID MmPagedPoolEnd;
extern PVOID MmSpecialPoolStart;
extern PVOID MmSpecialPoolEnd;
extern LARGE_INTEGER MmShortTime;
extern LARGE_INTEGER Mm30Milliseconds;
extern LARGE_INTEGER MmHalfSecond;
extern LONG MiDelayPageFaults;
extern BOOLEAN MiWriteCombiningPtes;

/* FUNCTIONS ******************************************************************/

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(PAGE, MmGetExecuteOptions)
  #pragma alloc_text(PAGE, MiCheckForUserStackOverflow)
#endif

FORCEINLINE
BOOLEAN
MiIsAccessAllowed(
    _In_ ULONG ProtectionMask,
    _In_ BOOLEAN Write,
    _In_ BOOLEAN Execute)
{
    #define _BYTE_MASK(Bit0, Bit1, Bit2, Bit3, Bit4, Bit5, Bit6, Bit7) \
        (Bit0)|(Bit1 << 1)|(Bit2 << 2)|(Bit3 << 3)|(Bit4 << 4)|(Bit5 << 5)|(Bit6 << 6)|(Bit7 << 7)

    static const UCHAR AccessAllowedMask[2][2] =
    {
        {   // Protect 0  1  2  3  4  5  6  7
            _BYTE_MASK(0, 1, 1, 1, 1, 1, 1, 1), // READ
            _BYTE_MASK(0, 0, 1, 1, 0, 0, 1, 1), // EXECUTE READ
        },
        {
            _BYTE_MASK(0, 0, 0, 0, 1, 1, 1, 1), // WRITE
            _BYTE_MASK(0, 0, 0, 0, 0, 0, 1, 1), // EXECUTE WRITE
        }
    };

    /* We want only the lower access bits */
    ProtectionMask &= MM_PROTECT_ACCESS;

    /* Look it up in the table */
    return (((AccessAllowedMask[Write != 0][Execute != 0] >> ProtectionMask) & 1) == 1);
}

NTSTATUS
NTAPI
MiAccessCheck(
    _In_ PMMPTE Pte,
    _In_ BOOLEAN StoreInstruction,
    _In_ KPROCESSOR_MODE PreviousMode,
    _In_ ULONG_PTR ProtectionMask,
    _In_ PVOID TrapFrame,
    _In_ BOOLEAN LockHeld)
{
    MMPTE TempPte;

    /* Check for invalid user-mode access */
    if (PreviousMode == UserMode && Pte > MiHighestUserPte)
    {
        DPRINT1("MiAccessCheck: STATUS_ACCESS_VIOLATION\n");
        return STATUS_ACCESS_VIOLATION;
    }

    /* Capture the PTE -- is it valid? */
    TempPte = *Pte;

    if (TempPte.u.Hard.Valid)
    {
        /* Was someone trying to write to it? */
        if (StoreInstruction)
        {
            /* Is it writable?*/
            if ((TempPte.u.Long & PTE_READWRITE) ||
                MI_IS_PAGE_COPY_ON_WRITE(&TempPte))
            {
                /* Then there's nothing to worry about */
                return STATUS_SUCCESS;
            }

            /* Oops! This isn't allowed */
            DPRINT1("MiAccessCheck: STATUS_ACCESS_VIOLATION\n");
            return STATUS_ACCESS_VIOLATION;
        }

        /* Someone was trying to read from a valid PTE, that's fine too */
        return STATUS_SUCCESS;
    }

    /* Check if the protection on the page allows what is being attempted */
    if (!MiIsAccessAllowed(ProtectionMask, StoreInstruction, FALSE))
    {
        DPRINT1("MiAccessCheck: STATUS_ACCESS_VIOLATION\n");
        return STATUS_ACCESS_VIOLATION;
    }

    /* Check if this is a guard page */
    if ((ProtectionMask & MM_PROTECT_SPECIAL) != MM_GUARDPAGE)
        /* Nothing to do */
        return STATUS_SUCCESS;

    /* Attached processes can't expand their stack */
    if (KeIsAttachedProcess())
    {
        DPRINT1("MiAccessCheck: STATUS_ACCESS_VIOLATION\n");
        return STATUS_ACCESS_VIOLATION;
    }

    if (KeInvalidAccessAllowed(TrapFrame))
    {
        DPRINT1("MiAccessCheck: STATUS_ACCESS_VIOLATION\n");
        return STATUS_ACCESS_VIOLATION;
    }

    if (!TempPte.u.Soft.Transition || TempPte.u.Soft.Prototype)
        goto Exit;

    DPRINT1("MiAccessCheck: FIXME\n");
    ASSERT(FALSE);

Exit:

    Pte->u.Soft.Protection = (ProtectionMask & ~MM_GUARDPAGE);

    return STATUS_GUARD_PAGE_VIOLATION;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmGetExecuteOptions(
    _In_ PULONG ExecuteOptions)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
MmSetExecuteOptions(
    _In_ ULONG ExecuteOptions)
{
    PKPROCESS CurrentProcess = &PsGetCurrentProcess()->Pcb;
    KLOCK_QUEUE_HANDLE ProcessLock;
    NTSTATUS Status = STATUS_ACCESS_DENIED;

    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    /* Only accept valid flags */
    if (ExecuteOptions & ~MEM_EXECUTE_OPTION_VALID_FLAGS)
    {
        /* Fail */
        DPRINT1("Invalid no-execute options\n");
        return STATUS_INVALID_PARAMETER;
    }

    /* Change the NX state in the process lock */
    //KiAcquireProcessLock(CurrentProcess, &ProcessLock);
    KiAcquireProcessLockRaiseToSynch(CurrentProcess, &ProcessLock);

    /* Don't change anything if the permanent flag was set */
    if (!CurrentProcess->Flags.Permanent)
    {
        /* Start by assuming it's not disabled */
        CurrentProcess->Flags.ExecuteDisable = FALSE;

        /* Now process each flag and turn the equivalent bit on */
        if (ExecuteOptions & MEM_EXECUTE_OPTION_DISABLE)
        {
            CurrentProcess->Flags.ExecuteDisable = TRUE;
        }
        if (ExecuteOptions & MEM_EXECUTE_OPTION_ENABLE)
        {
            CurrentProcess->Flags.ExecuteEnable = TRUE;
        }
        if (ExecuteOptions & MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION)
        {
            CurrentProcess->Flags.DisableThunkEmulation = TRUE;
        }
        if (ExecuteOptions & MEM_EXECUTE_OPTION_PERMANENT)
        {
            CurrentProcess->Flags.Permanent = TRUE;
        }
        if (ExecuteOptions & MEM_EXECUTE_OPTION_EXECUTE_DISPATCH_ENABLE)
        {
            CurrentProcess->Flags.ExecuteDispatchEnable = TRUE;
        }
        if (ExecuteOptions & MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE)
        {
            CurrentProcess->Flags.ImageDispatchEnable = TRUE;
        }

        /* These are turned on by default if no-execution is also eanbled */
        if (CurrentProcess->Flags.ExecuteEnable)
        {
            CurrentProcess->Flags.ExecuteDispatchEnable = TRUE;
            CurrentProcess->Flags.ImageDispatchEnable = TRUE;
        }

        /* All good */
        Status = STATUS_SUCCESS;
    }

    /* Release the lock and return status */
    KiReleaseProcessLock(&ProcessLock);
    return Status;
}

#if !defined(ONE_CPU)
BOOLEAN
NTAPI
MiSetDirtyBit(
    _In_ PVOID Address,
    _In_ PMMPTE Pte,
    _In_ BOOLEAN IsSetPfn)
{
    PFN_NUMBER PageFrameNumber;
    MMPTE TempPte;
    PMMPFN Pfn;

    //DPRINT("MiSetDirtyBit: Address %p, Pte %p [%p], IsSetPfn %X\n", Address, Pte, (Pte?Pte->u.Long:0), IsSetPfn);

    TempPte.u.Long = Pte->u.Long;
    PageFrameNumber = TempPte.u.Hard.PageFrameNumber;

    if (PageFrameNumber > MmHighestPhysicalPage) // should be MmHighestPossiblePhysicalPage
        return FALSE;

    if (!((MiPfnBitMap.Buffer[PageFrameNumber / 0x20] >> (PageFrameNumber & (0x20 - 1))) & 1))
        return FALSE;

    TempPte.u.Hard.Dirty = 1;
    TempPte.u.Hard.Accessed = 1;
    TempPte.u.Hard.Writable = 1;

    ASSERT((Pte)->u.Hard.Valid == 1);
    ASSERT((TempPte).u.Hard.Valid == 1);
    ASSERT((Pte)->u.Hard.PageFrameNumber == (TempPte).u.Hard.PageFrameNumber);

    Pte->u.Long = TempPte.u.Long;

    if (!IsSetPfn)
        goto Exit;

    Pfn = MI_PFN_ELEMENT(PageFrameNumber);

    if (!Pfn->OriginalPte.u.Soft.Prototype && !Pfn->u3.e1.WriteInProgress)
    {
        MiReleasePageFileSpace(Pfn->OriginalPte);
        Pfn->OriginalPte.u.Soft.PageFileHigh = 0;
    }

    ASSERT(Pfn->u3.e1.Rom == 0);
    Pfn->u3.e1.Modified = 1;

Exit:

    KeInvalidateTlbEntry(Address);
    return TRUE;
}
#endif

CODE_SEG("PAGE")
NTSTATUS
FASTCALL
MiCheckForUserStackOverflow(
    _In_ PVOID Address)
{
    PETHREAD CurrentThread = PsGetCurrentThread();
    PTEB Teb = CurrentThread->Tcb.Teb;
    PVOID StackBase;
    PVOID DeallocationStack;
    PVOID NextStackAddress;
    SIZE_T GuaranteedSize;
    NTSTATUS Status;

    /* Do we own the address space lock? */
    if (CurrentThread->AddressSpaceOwner)
    {
        /* This isn't valid */
        DPRINT1("MiCheckForUserStackOverflow: Process owns address space lock\n");
        ASSERT(KeAreAllApcsDisabled() == TRUE);
        return STATUS_GUARD_PAGE_VIOLATION;
    }

    /* Are we attached? */
    if (KeIsAttachedProcess())
    {
        /* This isn't valid */
        DPRINT1("MiCheckForUserStackOverflow: Process is attached\n");
        return STATUS_GUARD_PAGE_VIOLATION;
    }

    /* Read the current settings */
    StackBase = Teb->NtTib.StackBase;
    DeallocationStack = Teb->DeallocationStack;
    GuaranteedSize = Teb->GuaranteedStackBytes;

    DPRINT("MiCheckForUserStackOverflow: StackBase %p, DeallocationStack %p, GuaranteedSize %X\n",
            StackBase, DeallocationStack, GuaranteedSize);

    /* Guarantees make this code harder, for now, assume there aren't any */
    ASSERT(GuaranteedSize == 0);

    /* So allocate only the minimum guard page size */
    GuaranteedSize = PAGE_SIZE;

    /* Does this faulting stack address actually exist in the stack? */
    if (Address >= StackBase || Address < DeallocationStack)
    {
        /* That's odd... */
        DPRINT1("Faulting address outside of stack bounds. Address %p, StackBase %p, DeallocationStack %p\n",
                Address, StackBase, DeallocationStack);

        return STATUS_GUARD_PAGE_VIOLATION;
    }

    /* This is where the stack will start now */
    NextStackAddress = (PVOID)((ULONG_PTR)PAGE_ALIGN(Address) - GuaranteedSize);

    /* Do we have at least one page between here and the end of the stack? */
    if (((ULONG_PTR)NextStackAddress - PAGE_SIZE) <= (ULONG_PTR)DeallocationStack)
    {
        /* We don't -- Trying to make this guard page valid now */
        DPRINT1("MiCheckForUserStackOverflow: Close to our death...\n");

        /* Calculate the next memory address */
        NextStackAddress = (PVOID)((ULONG_PTR)PAGE_ALIGN(DeallocationStack) + GuaranteedSize);

        /* Allocate the memory */
        Status = ZwAllocateVirtualMemory(NtCurrentProcess(),
                                         &NextStackAddress,
                                         0,
                                         &GuaranteedSize,
                                         MEM_COMMIT,
                                         PAGE_READWRITE);
        if (NT_SUCCESS(Status))
        {
            /* Success! */
            Teb->NtTib.StackLimit = NextStackAddress;
            return STATUS_STACK_OVERFLOW;
        }

        DPRINT1("MiCheckForUserStackOverflow: Failed to allocate memory\n");
        return STATUS_STACK_OVERFLOW;
    }

    /* Don't handle this flag yet */
    ASSERT((PsGetCurrentProcess()->Peb->NtGlobalFlag & FLG_DISABLE_STACK_EXTENSION) == 0);

    /* Update the stack limit */
    Teb->NtTib.StackLimit = (PVOID)((ULONG_PTR)NextStackAddress + GuaranteedSize);

    /* Now move the guard page to the next page */
    Status = ZwAllocateVirtualMemory(NtCurrentProcess(),
                                     &NextStackAddress,
                                     0,
                                     &GuaranteedSize,
                                     MEM_COMMIT,
                                     (PAGE_READWRITE | PAGE_GUARD));

    if (NT_SUCCESS(Status) || Status == STATUS_ALREADY_COMMITTED)
    {
        /* We did it! */
        DPRINT("MiCheckForUserStackOverflow: Guard page handled successfully for %p\n", Address);
        return STATUS_PAGE_FAULT_GUARD_PAGE;
    }

    /* Fail, we couldn't move the guard page */
    DPRINT1("MiCheckForUserStackOverflow: Guard page failure: %X\n", Status);
    ASSERT(FALSE);

    return STATUS_STACK_OVERFLOW;
}

VOID
NTAPI
MiZeroPfn(
    _In_ PFN_NUMBER PageFrameNumber)
{
    PMMPTE ZeroPte;
    MMPTE TempPte;
    PMMPFN Pfn;
    PVOID ZeroAddress;

    /* Get the PFN for this page */
    Pfn = MI_PFN_ELEMENT(PageFrameNumber);
    ASSERT(Pfn);

    /* Grab a system PTE we can use to zero the page */
    ZeroPte = MiReserveSystemPtes(1, SystemPteSpace);
    ASSERT(ZeroPte);

    /* Initialize the PTE for it */
    TempPte = ValidKernelPte;
    TempPte.u.Hard.PageFrameNumber = PageFrameNumber;

    /* Setup caching */
    if (Pfn->u3.e1.CacheAttribute == MiWriteCombined)
    {
        /* Write combining, no caching */
        if (MiWriteCombiningPtes)
        {
            MI_PAGE_NO_DISABLE_CACHE(&TempPte);
            MI_PAGE_WRITE_THROUGH(&TempPte);
        }
        else
        {
            MI_PAGE_DISABLE_CACHE(&TempPte);
            MI_PAGE_WRITE_COMBINED(&TempPte);
        }
    }
    else if (Pfn->u3.e1.CacheAttribute == MiNonCached)
    {
        /* Write through, no caching */
        MI_PAGE_DISABLE_CACHE(&TempPte);
        MI_PAGE_WRITE_THROUGH(&TempPte);
    }

    /* Make the system PTE valid with our PFN */
    MI_WRITE_VALID_PTE(ZeroPte, TempPte);

    /* Get the address it maps to, and zero it out */
    ZeroAddress = MiPteToAddress(ZeroPte);
    KeZeroPages(ZeroAddress, PAGE_SIZE);

    /* Now get rid of it */
    MiReleaseSystemPtes(ZeroPte, 1, SystemPteSpace);
}

PMMPTE
NTAPI
MiCheckVirtualAddress(
    _In_ PVOID VirtualAddress,
    _Out_ ULONG* OutProtectCode,
    _Out_ PMMVAD* OutProtoVad)
{
    PMMVAD Vad;
    PMMVAD_LONG VadLong;
    PMMPTE SectionProto;
    UINT64 CommittedSize;
    ULONG_PTR Vpn;
    ULONG_PTR Count;

    /* No prototype/section support for now */
    *OutProtoVad = NULL;

    /* User or kernel fault? */
    if (VirtualAddress <= MM_HIGHEST_USER_ADDRESS)
    {
        /* Special case for shared data */
        if (PAGE_ALIGN(VirtualAddress) == (PVOID)MM_SHARED_USER_DATA_VA)
        {
            /* It's a read-only page */
            *OutProtectCode = MM_READONLY;
            return MmSharedUserDataPte;
        }

        /* Find the VAD, it might not exist if the address is bogus */
        Vad = MiLocateAddress(VirtualAddress);
        if (!Vad)
        {
            /* Bogus virtual address */
            *OutProtectCode = MM_NOACCESS;
            return NULL;
        }

        /* ReactOS does not handle physical memory VADs yet */
        ASSERT(Vad->u.VadFlags.VadType != VadDevicePhysicalMemory);

        /* Check if it's a section, or just an allocation */
        if (Vad->u.VadFlags.PrivateMemory)
        {
            /* ReactOS does not handle AWE VADs yet */
            ASSERT(Vad->u.VadFlags.VadType != VadAwe);

            /* This must be a TEB/PEB VAD */
            if (Vad->u.VadFlags.MemCommit)
                /* It's committed, so return the VAD protection */
                *OutProtectCode = (ULONG)Vad->u.VadFlags.Protection;
            else
                /* It has not yet been committed, so return no access */
                *OutProtectCode = MM_NOACCESS;

            /* In both cases, return no PTE */
            return NULL;
        }

        Vpn = ((ULONG_PTR)VirtualAddress / PAGE_SIZE);

        if (Vad->u.VadFlags.VadType == VadImageMap)
        {
            *OutProtectCode = 0x100;
        }
        else
        {
            /* Return the Prototype PTE and the protection for the page mapping */
            *OutProtectCode = Vad->u.VadFlags.Protection;

            if (!Vad->u2.VadFlags2.ExtendableFile)
                /* Return the proto VAD */
                *OutProtoVad = Vad;
        }

        /* Get the section proto for this page */
        SectionProto = MI_GET_PROTOTYPE_PTE_FOR_VPN(Vad, Vpn);
        if (!SectionProto)
            *OutProtectCode = MM_NOACCESS;

        if (!Vad->u2.VadFlags2.ExtendableFile)
            return SectionProto;

        Count = (Vpn - Vad->StartingVpn);
        VadLong = (PMMVAD_LONG)Vad;
        CommittedSize = (VadLong->u4.ExtendedInfo->CommittedSize - 1);

        if (Count > (ULONG_PTR)(CommittedSize / PAGE_SIZE))
            *OutProtectCode = MM_NOACCESS;

        return SectionProto;
    }

    if (MI_IS_PAGE_TABLE_ADDRESS(VirtualAddress))
    {
        /* This should never happen, as these addresses are handled by the double-maping */
        if ((PMMPTE)VirtualAddress >= MiAddressToPte(MmPagedPoolStart) &&
            (PMMPTE)VirtualAddress <= MmPagedPoolInfo.LastPteForPagedPool)
        {
            /* Fail such access */
            *OutProtectCode = MM_NOACCESS;
            return NULL;
        }

        /* Return full access rights */
        *OutProtectCode = MM_READWRITE;
        return NULL;
    }

    if (!MI_IS_SESSION_ADDRESS(VirtualAddress))
    {
        *OutProtectCode = MM_NOACCESS;
        return NULL;
    }

    if (&MmSessionSpace->Vm == &MmSystemCacheWs)
    {
        ASSERT((PsGetCurrentThread()->OwnsSystemWorkingSetExclusive) ||
               (PsGetCurrentThread()->OwnsSystemWorkingSetShared));
    }
    else if (MmSessionSpace->Vm.Flags.SessionSpace)
    {
        ASSERT((PsGetCurrentThread()->OwnsSessionWorkingSetExclusive) ||
               (PsGetCurrentThread()->OwnsSessionWorkingSetShared));
    }
    else
    {
        ASSERT((PsGetCurrentThread()->OwnsProcessWorkingSetExclusive) ||
               (PsGetCurrentThread()->OwnsProcessWorkingSetShared));
    }

    *OutProtectCode = MM_NOACCESS;

    SectionProto = NULL;

    while (MmSessionSpace->ImageList.Flink != &MmSessionSpace->ImageList)
    {
        /* ReactOS does not have an image list yet, so bail out to failure case */
        DPRINT1("MiCheckVirtualAddress: FIXME MmSessionSpace->ImageList\n");
        ASSERT(IsListEmpty(&MmSessionSpace->ImageList));
        break;
    }

    return SectionProto;
}

VOID
NTAPI
MiInitializeCopyOnWritePfn(
    _In_ PFN_NUMBER PageNumber,
    _In_ PMMPTE Pte,
    _In_ ULONG WsIndex,
    _In_ PMMWSL WsList)
{
    PMMPFN Pfn;
    PMMPFN NewPfn;
    PMMWSLE wsle;
    PMMPDE Pde;
    ULONG Protection;
    ULONG NewProtection;

    DPRINT("MiInitializeCopyOnWritePfn: %X, %p [%I64X], %X, %p\n",
           PageNumber, Pte, MiGetPteContents(Pte), WsIndex, WsList);

    ASSERT(Pte->u.Hard.Valid == 1);

    Pfn = MI_PFN_ELEMENT(Pte->u.Hard.PageFrameNumber);

    NewPfn = MI_PFN_ELEMENT(PageNumber);
    NewPfn->PteAddress = Pte;
    NewPfn->OriginalPte.u.Long = 0;

    wsle = &WsList->Wsle[WsIndex];

    if (!wsle->u1.e1.Protection)
        Protection = Pfn->OriginalPte.u.Soft.Protection;
    else
        Protection = wsle->u1.e1.Protection;

    NewProtection = MmMakeProtectNotWriteCopy[Protection];

    NewPfn->OriginalPte.u.Soft.Protection = NewProtection;
    wsle->u1.e1.Protection = NewProtection;

    ASSERT(NewPfn->u3.e2.ReferenceCount == 0);

    NewPfn->u2.ShareCount++;
    NewPfn->u3.e2.ReferenceCount++;
    NewPfn->u3.e1.PageLocation = ActiveAndValid;

    if (NewPfn->u3.e1.CacheAttribute != Pfn->u3.e1.CacheAttribute)
    {
        //MiFlushType[0x21]++;
        KeFlushEntireTb(TRUE, TRUE);

        if (Pfn->u3.e1.CacheAttribute != MiCached)
        {
            //MiFlushCacheForAttributeChange++;
            KeInvalidateAllCaches();
        }

        NewPfn->u3.e1.CacheAttribute = Pfn->u3.e1.CacheAttribute;
    }

    NewPfn->u1.WsIndex = WsIndex;

    Pde = MiAddressToPte(Pte);
    if (!Pde->u.Hard.Valid)
    {
        if (!NT_SUCCESS(MiCheckPdeForPagedPool(Pte)))
        {
            DPRINT1("MiInitializeCopyOnWritePfn: KeBugCheckEx()\n");
            DbgBreakPoint();//ASSERT(FALSE);
            KeBugCheckEx(0x1A, 0x61940, (ULONG_PTR)Pte, (ULONG_PTR)Pde->u.Long, (ULONG_PTR)MiPteToAddress(Pte));
        }
    }

    ASSERT(Pde->u.Hard.PageFrameNumber != 0);
    NewPfn->u4.PteFrame = Pde->u.Hard.PageFrameNumber;

    ASSERT(NewPfn->u3.e1.Rom == 0);
    NewPfn->u3.e1.Modified = 1;
}

BOOLEAN
NTAPI
MiCopyOnWrite(
    _In_ PVOID Address,
    _In_ PMMPTE Pte)
{
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    PMM_SESSION_SPACE Session;
    PVOID MappingAddress;
    PMMWSL WsList;
    PMMPFN Pfn;
    PMMPTE MappingPte;
    MMPTE TempPte;
    ULONG Color;
    ULONG WsIndex;
    PFN_NUMBER PageNumber;
    PFN_NUMBER CopyPageNumber;
    KIRQL OldIrql;
    BOOLEAN IsNotCopyOnWrite = FALSE;

    DPRINT("MiCopyOnWrite: Address %p, Pte %p [%p]\n", Address, Pte, (Pte ? Pte->u.Long : 0));

    TempPte.u.Long = Pte->u.Long;
    ASSERT(TempPte.u.Hard.Valid == 1);

    PageNumber = TempPte.u.Hard.PageFrameNumber;
    Pfn = MI_PFN_ELEMENT(PageNumber);

    if (Address >= MmSessionBase)
    {
        DPRINT1("MiCopyOnWrite: FIXME\n");
        ASSERT(FALSE);
    }
    else
    {
        WsList = MmWorkingSetList;
        Session = NULL;

        if (CurrentProcess->ForkInProgress)
        {
            DPRINT1("MiCopyOnWrite: FIXME\n");
            ASSERT(FALSE);
        }

        if (!TempPte.u.Hard.CopyOnWrite)
            IsNotCopyOnWrite = TRUE;
    }

    WsIndex = MiLocateWsle(Address, WsList, Pfn->u1.WsIndex, FALSE);

    OldIrql = MiLockPfnDb(APC_LEVEL);

    if (MmAvailablePages < 0x80)
    {
        PEPROCESS process;

        if (Session)
            process = HYDRA_PROCESS;
        else
            process = CurrentProcess;

        if (MiEnsureAvailablePageOrWait(process, OldIrql))
        {
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            return FALSE;
        }
    }

    ASSERT(Pfn->u3.e1.PrototypePte == 1);

    if (Session)
    {
        DPRINT1("MiCopyOnWrite: FIXME\n");
        ASSERT(FALSE);
    }
    else
    {
        ASSERT(KeGetCurrentIrql() > APC_LEVEL);

        if (!Pfn->u3.e1.Modified && Pte->u.Hard.Dirty)
        {
            ASSERT(Pfn->u3.e1.Rom == 0);
            Pfn->u3.e1.Modified = 1;

            if (!Pfn->OriginalPte.u.Soft.Prototype &&
                !Pfn->u3.e1.WriteInProgress)
            {
                DPRINT1("MiCopyOnWrite: FIXME\n");
                ASSERT(FALSE);
            }
        }

        Color = MI_GET_NEXT_PROCESS_COLOR(CurrentProcess);
        CopyPageNumber = MiRemoveAnyPage(Color);
    }

    MiInitializeCopyOnWritePfn(CopyPageNumber, Pte, WsIndex, WsList);

    MiUnlockPfnDb(OldIrql, APC_LEVEL);
    InterlockedIncrement(&KeGetCurrentPrcb()->MmCopyOnWriteCount);

    MappingPte = MiReserveSystemPtes(1, SystemPteSpace);

    if (MappingPte)
    {
        MMPTE tempPte;

        MI_MAKE_HARDWARE_PTE_KERNEL(&tempPte, MappingPte, MM_READWRITE, CopyPageNumber);
        MI_MAKE_DIRTY_PAGE(&tempPte);

        if (Pfn->u3.e1.CacheAttribute == MiNonCached)
        {
            tempPte.u.Hard.CacheDisable = 1;
            tempPte.u.Hard.WriteThrough = 1;
        }
        else if (Pfn->u3.e1.CacheAttribute == MiWriteCombined)
        {
            if (MiWriteCombiningPtes)
            {
                tempPte.u.Hard.CacheDisable = 0;
                tempPte.u.Hard.WriteThrough = 1;
            }
            else
            {
                tempPte.u.Hard.CacheDisable = 1;
                tempPte.u.Hard.WriteThrough = 0;
            }
        }

        MI_WRITE_VALID_PTE(MappingPte, tempPte);

        MappingAddress = MiPteToAddress(MappingPte);
    }
    else
    {
        MappingAddress = MiMapPageInHyperSpace(CurrentProcess, CopyPageNumber, &OldIrql);
    }

    RtlCopyMemory(MappingAddress, (PVOID)((ULONG_PTR)Address & ~(PAGE_SIZE - 1)), PAGE_SIZE);

    if (!MappingPte)
    {
        DPRINT1("MiCopyOnWrite: FIXME\n");
        ASSERT(FALSE);
    }
    else
    {
        MiReleaseSystemPtes(MappingPte, 1, SystemPteSpace);
    }

    if (!IsNotCopyOnWrite)
    {
        MI_MAKE_DIRTY_PAGE(&TempPte);
        TempPte.u.Hard.Write = 1;
        MI_MAKE_ACCESSED_PAGE(&TempPte);
        TempPte.u.Hard.CopyOnWrite = 0;
    }

    TempPte.u.Hard.PageFrameNumber = CopyPageNumber;

    ASSERT(Pte->u.Hard.Valid == 1);
    ASSERT(TempPte.u.Hard.Valid == 1);
    ASSERT(Pte->u.Hard.PageFrameNumber != TempPte.u.Hard.PageFrameNumber);
    Pte->u.Long = TempPte.u.Long;

    if (!Session)
    {
        KeFlushSingleTb(Address, FALSE);
        CurrentProcess->NumberOfPrivatePages++;
    }
    else
    {
        KeFlushSingleTb(Address, TRUE);
        ASSERT(Pfn->u3.e1.PrototypePte == 1);
    }

    OldIrql = MiLockPfnDb(APC_LEVEL);

    MiDecrementShareCount(Pfn, PageNumber);

    if (!Session && CurrentProcess->CloneRoot)
    {
        DPRINT1("MiCopyOnWrite: FIXME\n");
        ASSERT(FALSE);
    }

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    return TRUE;
}

VOID
NTAPI
MiTrimPte(
    _In_ PVOID VirtualAddress,
    _Inout_ PMMPTE Pte,
    _In_ PMMPFN Pfn,
    _In_ PEPROCESS Process,
    _In_ MMPTE NewPteContents)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
MiResolveDemandZeroFault(
    _In_ PVOID Address,
    _In_ PMMPTE Pte,
    _In_ PEPROCESS Process,
    _In_ KIRQL OldIrql)
{
    PFN_NUMBER PageFrameNumber;
    MMPTE TempPte;
    PMMPFN Pfn;
    MMWSLE TempWsle;
    ULONG Color;
    BOOLEAN IsNeedAnyPage = FALSE;
    BOOLEAN HaveLock = FALSE;
    BOOLEAN IsZeroPage = FALSE;

    DPRINT("MiResolveDemandZeroFault: (%p) Pte %p [%I64X], %X, %p, %X\n",
           Address, Pte, MiGetPteContents(Pte), Process, OldIrql);

    /* Must currently only be called by paging path */
    if (Process > HYDRA_PROCESS && OldIrql == MM_NOIRQL)
    {
        /* Sanity check */
        ASSERT(MI_IS_PAGE_TABLE_ADDRESS(Pte));

        if (Process->ForkInProgress)
        {
            /* No forking yet */
            DPRINT1("MiResolveDemandZeroFault: FIXME MiWaitForForkToComplete()\n");
            ASSERT(FALSE);
        }

        /* Get process color */
        Color = MI_GET_NEXT_PROCESS_COLOR(Process);
        ASSERT(Color != 0xFFFFFFFF);

        /* We'll need a zero page */
    }
    else
    {
        /* Check if we not need a zero page */
        if (OldIrql == MM_NOIRQL)
        {
            /* Non session-backed image views must be not zeroed */
            if (Process != HYDRA_PROCESS ||
                (!MI_IS_SESSION_IMAGE_ADDRESS(Address) &&
                 (Address < (PVOID)MiSessionViewStart || Address >= (PVOID)MiSessionSpaceWs)))
            {
                IsNeedAnyPage = TRUE;
            }
        }

        /* Hardcode unknown color */
        Color = 0xFFFFFFFF;
    }

    /* Check if the PFN database should be acquired */
    if (OldIrql == MM_NOIRQL)
    {
        /* Acquire it and remember we should release it after */
        OldIrql = MiLockPfnDb(APC_LEVEL);
        HaveLock = TRUE;
    }

    /* We either manually locked the PFN DB, or already came with it locked */
    MI_ASSERT_PFN_LOCK_HELD();
    ASSERT(MmPfnOwner == KeGetCurrentThread());
    ASSERT(Pte->u.Hard.Valid == 0);

    /* Assert we have enough pages */
    if (MmAvailablePages < 0x80 && MiEnsureAvailablePageOrWait(Process, OldIrql))
    {
        if (HaveLock)
            MiUnlockPfnDb(OldIrql, APC_LEVEL);

        return 0xC7303001;
    }

    /* Do we need a zero page? */
    if (Color != 0xFFFFFFFF)
    {
        /* Try to get one, if we couldn't grab a free page and zero it */
        PageFrameNumber = MiRemoveZeroPageSafe(Color);
        if (!PageFrameNumber)
        {
            /* We'll need a free page and zero it manually */
            PageFrameNumber = MiRemoveAnyPage(Color);
            IsZeroPage = TRUE;
        }
    }
    else
    {
        /* Get a color, and see if we should grab a zero or non-zero page */
        Color = MiGetColor();

        if (IsNeedAnyPage)
            /* Process or system doesn't want a zero page, grab anything */
            PageFrameNumber = MiRemoveAnyPage(Color);
        else
            /* System wants a zero page, obtain one */
            PageFrameNumber = MiRemoveZeroPage(Color);
    }

    /* Initialize it */
    MiInitializePfn(PageFrameNumber, Pte, TRUE);

    /* Do we have the lock? */
    if (HaveLock)
    {
        /* Release it */
            MiUnlockPfnDb(OldIrql, APC_LEVEL);

        /* Update performance counters */
        if (Process > HYDRA_PROCESS)
            Process->NumberOfPrivatePages++;
    }

    /* Increment demand zero faults */
    InterlockedIncrement(&KeGetCurrentPrcb()->MmDemandZeroCount);

    /* Get the PFN entry */
    Pfn = MI_PFN_ELEMENT(PageFrameNumber);

    /* Zero the page if need be */
    if (IsZeroPage)
        MiZeroPfn(PageFrameNumber);

    /* Fault on user PDE, or fault on user PTE? */
    if (Pte <= MiHighestUserPte)
        /* User fault, build a user PTE */
        MI_MAKE_HARDWARE_PTE_USER(&TempPte, Pte, Pte->u.Soft.Protection, PageFrameNumber);
    else
        /* This is a user-mode PDE, create a kernel PTE for it */
        MI_MAKE_HARDWARE_PTE(&TempPte, Pte, Pte->u.Soft.Protection, PageFrameNumber);

    /* Set it dirty if it's a writable page */
    if (TempPte.u.Long & PTE_READWRITE)
        MI_MAKE_DIRTY_PAGE(&TempPte);

    /* Write it */
    MI_WRITE_VALID_PTE(Pte, TempPte);

    /* Did we manually acquire the lock */
    if (HaveLock)
    {
        /* Windows does these sanity checks */
        ASSERT(Pfn->u1.Event == 0);
        ASSERT(Pfn->u3.e1.PrototypePte == 0);

        TempWsle.u1.Long = 0;
        if (!MiAddValidPageToWorkingSet(Address, Pte, Pfn, TempWsle))
        {
            DPRINT1("MiResolveDemandZeroFault: FIXME MiTrimPte()\n");
            ASSERT(FALSE);
            return STATUS_NO_MEMORY;
        }
    }

    /* It's all good now */
    DPRINT("MiResolveDemandZeroFault: Demand zero page has now been paged in\n");
    return STATUS_PAGE_FAULT_DEMAND_ZERO;
}

NTSTATUS
NTAPI
MiCompleteProtoPteFault(
    _In_ BOOLEAN StoreInstruction,
    _In_ PVOID Address,
    _In_ PMMPTE Pte,
    _In_ PMMPTE SectionProto,
    _In_ KIRQL OldIrql,
    _In_ PMMPFN* LockedProtoPfn)
{
    PMMPTE OriginalPte;
    PMMPFN Pfn;
    MMPTE TempPte;
    ULONG_PTR Protection;
    PFN_NUMBER PageFrameIndex;
    MMWSLE ProtoProtect;
    BOOLEAN OriginalProtection;
    BOOLEAN DirtyPage;
    NTSTATUS Status;

    DPRINT("MiCompleteProtoPteFault: %X, %p, %p [%I64X], %p [%I64X], %X\n",
           StoreInstruction, Address, Pte, MiGetPteContents(Pte), SectionProto, MiGetPteContents(SectionProto), OldIrql);

    /* Must be called with an valid prototype PTE, with the PFN lock held */
    MI_ASSERT_PFN_LOCK_HELD();
    ASSERT(MmPfnOwner == KeGetCurrentThread());
    ASSERT(SectionProto->u.Hard.Valid == 1);

    /* Increment the share count for the page table */
    Pfn = MI_PFN_ELEMENT((MiAddressToPte(Pte))->u.Hard.PageFrameNumber);
    Pfn->u2.ShareCount++;

    /* Get the page */
    PageFrameIndex = PFN_FROM_PTE(SectionProto);

    /* Get the PFN entry and set it as a prototype PTE */
    Pfn = MI_PFN_ELEMENT(PageFrameIndex);
    Pfn->u3.e1.PrototypePte = 1;

    OriginalPte = &Pfn->OriginalPte;

    /* Check where we should be getting the protection information from */
    if (Pte->u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED)
    {
        /* Get the protection from the PTE, there's no real Proto PTE data */
        Protection = Pte->u.Soft.Protection;

        /* Remember that we did not use the proto protection */
        OriginalProtection = FALSE;
    }
    else
    {
        /* Get the protection from the original PTE link */
        Protection = OriginalPte->u.Soft.Protection;

        /* Remember that we used the original protection */
        OriginalProtection = TRUE;

        /* Check if this was a write on a read only proto */
        if (StoreInstruction && !(Protection & MM_READWRITE))
            /* Clear the flag */
            StoreInstruction = 0;
    }

    /* Check if this was a write on a non-COW page */
    DirtyPage = FALSE;

    if (StoreInstruction && ((Protection & MM_WRITECOPY) != MM_WRITECOPY))
    {
        /* Then the page should be marked dirty */
        DirtyPage = TRUE;

        ASSERT(Pfn->u3.e1.Rom == 0);
        Pfn->u3.e1.Modified = 1;

        DPRINT("MiCompleteProtoPteFault: OriginalPte %X\n", OriginalPte->u.Long);

        if (!OriginalPte->u.Soft.Prototype && !Pfn->u3.e1.WriteInProgress)
        {
            ULONG PageFileHigh = OriginalPte->u.Soft.PageFileHigh;

            if (PageFileHigh && PageFileHigh != MI_PTE_LOOKUP_NEEDED)
            {
                DPRINT1("MiCompleteProtoPteFault: FIXME. PageFileHigh %X\n", PageFileHigh);
                ASSERT(FALSE);
            }

            OriginalPte->u.Soft.PageFileHigh = 0;
        }
    }

    /* Did we get a locked incoming PFN? */
    if (*LockedProtoPfn)
    {
        /* Drop a reference */
        ASSERT((*LockedProtoPfn)->u3.e2.ReferenceCount >= 1);
        MiDereferencePfnAndDropLockCount(*LockedProtoPfn);
        *LockedProtoPfn = NULL;
    }

    /* Release the PFN lock */
    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    /* Remove special/caching bits */
    ProtoProtect.u1.Long = 0;
    ProtoProtect.u1.e1.Protection = Protection;
    Protection &= MM_PROTECT_ACCESS;

    /* Setup caching */
    if (Pfn->u3.e1.CacheAttribute == MiWriteCombined)
        /* Write combining, no caching */
        Protection |= MM_WRITECOMBINE;
    else if (Pfn->u3.e1.CacheAttribute == MiNonCached)
        /* Write through, no caching */
        Protection |= MM_NOCACHE;

    /* Check if this is a kernel or user address */
    if (Address < MmSystemRangeStart)
        /* Build the user PTE */
        MI_MAKE_HARDWARE_PTE_USER(&TempPte, Pte, Protection, PageFrameIndex);
    else
        /* Build the kernel PTE */
        MI_MAKE_HARDWARE_PTE(&TempPte, Pte, Protection, PageFrameIndex);

    /* Set the dirty flag if needed */
    if (DirtyPage)
        MI_MAKE_DIRTY_PAGE(&TempPte);

    /* Write the PTE */
    MI_WRITE_VALID_PTE(Pte, TempPte);

    /* Reset the protection if needed */
    if (OriginalProtection)
        ProtoProtect.u1.e1.Protection = MM_ZERO_ACCESS;

    if (MiAddValidPageToWorkingSet(Address, Pte, Pfn, ProtoProtect))
    {
        Status = STATUS_SUCCESS;
        goto Exit;
    }

    DPRINT1("MiCompleteProtoPteFault: FIXME MiTrimPte()\n");
    ASSERT(FALSE);

    Status = STATUS_NO_MEMORY;

Exit:

    DPRINT("MiCompleteProtoPteFault: FIXME CcPfNumActiveTraces\n");

    /* Return success */
    ASSERT(Pte == MiAddressToPte(Address));

    return Status;
}

PMI_PAGE_SUPPORT_BLOCK
NTAPI
MiGetInPageSupportBlock(
    _In_ KIRQL OldIrql,
    _Out_ NTSTATUS* OutStatus)
{
    PMI_PAGE_SUPPORT_BLOCK Support;
    PSINGLE_LIST_ENTRY Entry;

    DPRINT("MiGetInPageSupportBlock: OldIrql %X\n", OldIrql);

    if (OldIrql != MM_NOIRQL)
    {
        ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
        ASSERT(MmPfnOwner == KeGetCurrentThread());
    }
    else
    {
        ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
    }

    if (ExQueryDepthSList(&MmInPageSupportSListHead))
    {
        Entry = InterlockedPopEntrySList(&MmInPageSupportSListHead);
        if (Entry)
        {
            Support = CONTAINING_RECORD(Entry, MI_PAGE_SUPPORT_BLOCK, ListEntry);
            DPRINT("MiGetInPageSupportBlock: Support %p\n", Support);
            goto Exit;
        }
    }

    if (OldIrql != MM_NOIRQL)
        MiUnlockPfnDb(OldIrql, APC_LEVEL);

    Support = ExAllocatePoolWithTag(NonPagedPool, sizeof(MI_PAGE_SUPPORT_BLOCK), 'nImM');
    if (!Support)
    {
        DPRINT1("MiGetInPageSupportBlock: STATUS_INSUFFICIENT_RESOURCES\n");
        *OutStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }

    KeInitializeEvent(&Support->Event, NotificationEvent, FALSE);
 
    Support->WaitCount = 1;
    Support->u1.LongFlags = 0;
    Support->CurrentThread = NULL;

    ASSERT(KeReadStateEvent(&Support->Event) == 0);

    if (OldIrql != MM_NOIRQL)
    {
        InterlockedPushEntrySList(&MmInPageSupportSListHead, &Support->ListEntry);

        DPRINT1("MiGetInPageSupportBlock: 0xC7303001\n");
        *OutStatus = 0xC7303001; // ?
        goto ErrorExit;
    }

    DPRINT("MiGetInPageSupportBlock: Support %p\n", Support);

Exit:

    ASSERT(Support->WaitCount == 1);
    ASSERT(Support->u1.e1.PrefetchMdlHighBits == 0);
    ASSERT(Support->u1.LongFlags == 0);
    ASSERT(KeReadStateEvent(&Support->Event) == 0);

    Support->CurrentThread = PsGetCurrentThread();
    Support->ListEntry.Next = NULL;

    return Support;

ErrorExit:

    if (OldIrql != MM_NOIRQL)
        OldIrql = MiLockPfnDb(APC_LEVEL);

    DPRINT("MiGetInPageSupportBlock: return NULL\n");
    return NULL;
}

VOID
NTAPI
MiInitializeReadInProgressPfn(
    _In_ PMDL Mdl,
    _In_ PMMPTE BasePte,
    _In_ PKEVENT Event,
    _In_ BOOLEAN IsProto)
{
    PFN_NUMBER* MdlPages;
    PMMPTE Pte = NULL;
    PMMPFN Pfn;
    MMPTE TempPte;
    PFN_NUMBER PageNumber = 0;
    LONG ByteCount;
    ULONG CacheAttribute;
    BOOLEAN IsFlush = FALSE;

    DPRINT("MiInitializeReadInProgressPfn: %p %p, %X\n", Mdl, BasePte, IsProto);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(MmPfnOwner == KeGetCurrentThread());

    MdlPages = MmGetMdlPfnArray(Mdl);

    for (ByteCount = Mdl->ByteCount; ByteCount > 0; ByteCount -= PAGE_SIZE)
    {
        Pfn = &MmPfnDatabase[*MdlPages];
        Pfn->u1.Event = Event;
        Pfn->PteAddress = BasePte;
        Pfn->OriginalPte.u.Long = BasePte->u.Long;

        if (IsProto)
            Pfn->u3.e1.PrototypePte = 1;

        DPRINT("MiInitializeReadInProgressPfn: %X, %p, %p, %p\n", *MdlPages, Pfn, BasePte, BasePte->u.Long);

        ASSERT(Pfn->u3.e2.ReferenceCount == 0);

        MiReferenceUnusedPageAndBumpLockCount(Pfn);

        Pfn->u3.e1.ReadInProgress = 1;
        Pfn->u2.ShareCount = 0;

        if ((BasePte->u.Soft.Protection & MM_WRITECOMBINE) == MM_WRITECOMBINE &&
            BasePte->u.Soft.Protection & MM_PROTECT_ACCESS)
        {
            CacheAttribute = MiPlatformCacheAttributes[0][MmWriteCombined];
        }
        else if ((BasePte->u.Soft.Protection & MM_NOCACHE) == MM_NOCACHE)
        {
            CacheAttribute = MiPlatformCacheAttributes[0][MmNonCached];
        }
        else
        {
            CacheAttribute = MiCached;
        }

        if (Pfn->u3.e1.CacheAttribute != CacheAttribute)
        {
            IsFlush = TRUE;
            Pfn->u3.e1.CacheAttribute = CacheAttribute;
        }

        Pfn->u4.InPageError = 0;

        if (!PageNumber || MiIsPteOnPdeBoundary(BasePte))
        {
            if (!PageNumber)
            {
                Pte = MiAddressToPte(BasePte);
            }
            else
            {
                Pte++;
                ASSERT(Pte == MiAddressToPte(BasePte));
            }

            if (!Pte->u.Hard.Valid)
            {
                if (!NT_SUCCESS(MiCheckPdeForPagedPool(BasePte)))
                {
                    DPRINT1("KeBugCheckEx()\n");
                    ASSERT(FALSE);
                    //KeBugCheckEx();
                }
            }

            PageNumber = Pte->u.Hard.PageFrameNumber;
            ASSERT(PageNumber != 0);
        }

        Pfn->u4.PteFrame = PageNumber;

        MI_MAKE_TRANSITION_PTE(&TempPte, *MdlPages, BasePte->u.Soft.Protection);
        MI_WRITE_INVALID_PTE(BasePte, TempPte);

        ASSERT(PageNumber != 0);
        MmPfnDatabase[PageNumber].u2.ShareCount++;

        DPRINT("MiInitializeReadInProgressPfn: %X, %X, %p, %p\n", ByteCount, PageNumber, Pte, BasePte);

        MdlPages++;
        BasePte++;
    }

    if (IsFlush)
    {
        KeFlushEntireTb(TRUE, TRUE);

        if (CacheAttribute != 1)
            KeInvalidateAllCaches();
    }
}

NTSTATUS
NTAPI
MiResolveMappedFileFault(
    _In_ PMMPTE Pte,
    _Out_ PMI_PAGE_SUPPORT_BLOCK* OutPageBlock,
    _In_ PEPROCESS Process,
    _In_ KIRQL OldIrql)
{
    PKPRCB Prcb = KeGetCurrentPrcb();
    PMI_PAGE_SUPPORT_BLOCK PageBlock;
    PCONTROL_AREA ControlArea;
    PETHREAD CurrentThread;
    PSUBSECTION Subsection;
    PPFN_NUMBER StartMdlPage;
    PPFN_NUMBER CurrentMdlPage;
    PPFN_NUMBER EndMdlPage;
    PPFN_NUMBER MdlPage;
    PMMPTE StartProto;
    PMMPTE NextProto;
    PMDL Mdl;
    LARGE_INTEGER StartingOffset;
    LARGE_INTEGER TempOffset;
    //ULONGLONG Size;
    PFN_NUMBER PageFrameIndex;
    ULONG AvailablePages;
    ULONG ClusterSize = 0;
    ULONG ReadSize;
    ULONG PageColor;
    NTSTATUS Status;

    DPRINT("MiResolveMappedFileFault: %p, %p [%p], %X\n", Process, Pte, Pte->u.Long, OldIrql);

    ASSERT(Pte->u.Soft.Prototype == 1);

    if (MmAvailablePages < 0x80 && MiEnsureAvailablePageOrWait(Process, OldIrql))
        return 0xC7303001;

    Subsection = MiSubsectionPteToSubsection(Pte);
    ControlArea = Subsection->ControlArea;

    DPRINT("MiResolveMappedFileFault: Subsection %p, ControlArea %p\n", Subsection, ControlArea);

    if (ControlArea->u.Flags.FailAllIo)
    {
        DPRINT1("MiResolveMappedFileFault: STATUS_IN_PAGE_ERROR\n");
        return STATUS_IN_PAGE_ERROR;
    }

    if (Pte >= &Subsection->SubsectionBase[Subsection->PtesInSubsection])
    {
        DPRINT1("MiResolveMappedFileFault: STATUS_ACCESS_VIOLATION\n");
        return STATUS_ACCESS_VIOLATION;
    }

    DPRINT("MiResolveMappedFileFault: ControlArea->u.LongFlags %X\n", ControlArea->u.LongFlags);

    if (ControlArea->u.Flags.Rom)
    {
        //ASSERT(XIPConfigured == TRUE);

        /* Don't handle yet */
        DPRINT1("MiResolveMappedFileFault: FIXME\n");
        ASSERT(FALSE);
        return STATUS_PAGE_FAULT_TRANSITION;
    }

    CurrentThread = PsGetCurrentThread();

    PageBlock = MiGetInPageSupportBlock(OldIrql, &Status);
    if (!PageBlock)
    {
        DPRINT("MiResolveMappedFileFault: return %X\n", Status);
        ASSERT(!NT_SUCCESS(Status));
        return Status;
    }

    *OutPageBlock = PageBlock;

    StartMdlPage = &PageBlock->MdlPages[0];
    RtlFillMemoryUlong(StartMdlPage, (0x10 * sizeof(PFN_NUMBER)), 0xF1F1F1F1);

    if (MiInPageSinglePages)
    {
        AvailablePages = 0;
        MiInPageSinglePages--;
    }
    else
    {
        AvailablePages = MmAvailablePages;
    }

    CurrentMdlPage = StartMdlPage;
    StartProto = Pte;
    ReadSize = PAGE_SIZE;

    if (!CurrentThread->DisablePageFaultClustering)
    {
        if (!ControlArea->u.Flags.NoModifiedWriting &&
            (AvailablePages > (2 * MmFreeGoal) ||
             (AvailablePages > 0x80 && (ControlArea->u.Flags.Image || CurrentThread->ForwardClusterOnly))))
        {
            ASSERT(AvailablePages > (MM_MAXIMUM_READ_CLUSTER_SIZE + 16));

            if (ControlArea->u.Flags.Image)
            {
                if (Subsection->u.SubsectionFlags.Protection & MM_EXECUTE)
                    ClusterSize = MmCodeClusterSize;
                else
                    ClusterSize = MmDataClusterSize;
            }
            else
            {
                ASSERT(CurrentThread->ReadClusterSize <= MM_MAXIMUM_READ_CLUSTER_SIZE);
                ClusterSize = CurrentThread->ReadClusterSize;
            }

            EndMdlPage = &PageBlock->MdlPages[ClusterSize];

            DPRINT("MiResolveMappedFileFault: StartMdlPage %p, EndMdlPage %p\n", StartMdlPage, EndMdlPage);

            for (NextProto = &Pte[1];
                 NextProto < &Subsection->SubsectionBase[Subsection->PtesInSubsection];
                 NextProto++, CurrentMdlPage++)
            {
                if (MiIsPteOnPdeBoundary(NextProto) ||
                    CurrentMdlPage >= EndMdlPage ||
                    NextProto->u.Long != StartProto->u.Long)
                {
                    break;
                }

                ControlArea->NumberOfPfnReferences++;
                ReadSize += PAGE_SIZE;
            }

            if (CurrentMdlPage < EndMdlPage && !CurrentThread->ForwardClusterOnly)
            {
                for (NextProto = (Pte - 1);
                     NextProto >= &Subsection->SubsectionBase[0];
                     NextProto--, CurrentMdlPage++)
                {
                    if (BYTE_OFFSET(NextProto) == (PAGE_SIZE - sizeof(MMPTE)) ||
                        CurrentMdlPage >= EndMdlPage ||
                        NextProto->u.Long != StartProto->u.Long)
                    {
                        break;
                    }

                    ControlArea->NumberOfPfnReferences++;
                    ReadSize += PAGE_SIZE;
                }

                StartProto = (NextProto + 1);
            }
        }
    }
    else
    {
        DPRINT("MiResolveMappedFileFault: CurrentMdlPage %p\n", CurrentMdlPage);
    }

    if (ControlArea->u.Flags.Image)
    {
        StartingOffset.QuadPart = (StartProto - Subsection->SubsectionBase);
        StartingOffset.QuadPart *= PAGE_SIZE;
        StartingOffset.QuadPart += (Subsection->StartingSector * 0x200LL);

        TempOffset.QuadPart = ((ULONGLONG)Subsection->StartingSector + Subsection->NumberOfFullSectors);
        TempOffset.QuadPart *= 0x200;
    }
    else
    {
        ASSERT(Subsection->SubsectionBase != NULL);

        TempOffset.LowPart = Subsection->StartingSector;
        TempOffset.HighPart = Subsection->u.SubsectionFlags.StartingSector4132;

        StartingOffset.QuadPart = TempOffset.QuadPart;
        StartingOffset.QuadPart += (StartProto - Subsection->SubsectionBase);
        StartingOffset.QuadPart *= PAGE_SIZE;

        TempOffset.QuadPart += Subsection->NumberOfFullSectors;
        TempOffset.QuadPart *= PAGE_SIZE;
    }

    TempOffset.QuadPart += Subsection->u.SubsectionFlags.SectorEndOffset;

    ASSERT(StartingOffset.QuadPart < TempOffset.QuadPart);
    DPRINT("MiResolveMappedFileFault: StartingOffset %I64X, TempOffset %I64X\n", StartingOffset.QuadPart, TempOffset.QuadPart);

    for (MdlPage = StartMdlPage; MdlPage < CurrentMdlPage; MdlPage++)
    {
        if (Process == HYDRA_PROCESS)
        {
            MmSessionSpace->Color++;
            PageColor = (MmSessionSpace->Color & MmSecondaryColorMask);
        }
        else if (Process)
        {
            Process->NextPageColor++;
            PageColor = (Process->NextPageColor & MmSecondaryColorMask);
        }
        else
        {
            Prcb->PageColor++;
            PageColor = (Prcb->PageColor & Prcb->SecondaryColorMask);
            PageColor |= Prcb->NodeShiftedColor;
        }

        *MdlPage = MiRemoveAnyPage(PageColor);
    }

    if (Process == HYDRA_PROCESS)
    {
        MmSessionSpace->Color++;
        PageColor = (MmSessionSpace->Color & MmSecondaryColorMask);
    }
    else if (Process)
    {
        Process->NextPageColor++;
        PageColor = (Process->NextPageColor & MmSecondaryColorMask);
    }
    else
    {
        Prcb->PageColor++;
        PageColor = (Prcb->PageColor & Prcb->SecondaryColorMask);
        PageColor |= Prcb->NodeShiftedColor;
    }

    InterlockedIncrement(&Prcb->MmPageReadIoCount);
    InterlockedExchangeAdd(&Prcb->MmPageReadCount, (ReadSize / PAGE_SIZE));

    if (ControlArea->u.Flags.Image &&
        (StartingOffset.QuadPart > (TempOffset.QuadPart - ReadSize)))
    {
        ASSERT((ULONG)(TempOffset.QuadPart - StartingOffset.QuadPart) > (ReadSize - PAGE_SIZE));
        ReadSize = ALIGN_UP_BY((TempOffset.LowPart - StartingOffset.LowPart), MM_SECTOR_SIZE);
        PageFrameIndex = MiRemoveZeroPage(PageColor);
    }
    else
    {
        PageFrameIndex = MiRemoveAnyPage(PageColor);
    }

    ControlArea->NumberOfPfnReferences++;

    *CurrentMdlPage = PageFrameIndex;

    Mdl = &PageBlock->Mdl;
    MmInitializeMdl(Mdl, MiPteToAddress(StartProto), ReadSize);
    Mdl->MdlFlags |= (MDL_IO_PAGE_READ | MDL_PAGES_LOCKED);

    if (ReadSize > ((ClusterSize + 1) * PAGE_SIZE))
    {
        DPRINT1("KeBugCheckEx()\n");
        ASSERT(FALSE);
        KeBugCheckEx(0x1A, 0x777, (ULONG_PTR)Mdl, (ULONG_PTR)Subsection, TempOffset.LowPart);
    }

    MiInitializeReadInProgressPfn(Mdl, StartProto, &PageBlock->Event, TRUE);

    PageBlock->StartingOffset.QuadPart = StartingOffset.QuadPart;
    PageBlock->FilePointer = ControlArea->FilePointer;
    PageBlock->Pfn = MI_PFN_ELEMENT(PageBlock->MdlPages[Pte - StartProto]);
    PageBlock->StartProto = StartProto;

    return 0xC0033333;
}

VOID
NTAPI
MiCompleteInPage(
    _In_ PVOID FaultAddress,
    _In_ PMI_PAGE_SUPPORT_BLOCK PageBlock,
    _In_ PMDL Mdl)
{
    PPFN_NUMBER ReadEndPage;
    PPFN_NUMBER MdlEndPage;
    ULONG ReadBytes;
    ULONG ReadPageCount;
    ULONG ReadOffset;
    ULONG MdlPageCount;

    DPRINT("MiCompleteInPage: ReadBytes %X, Mdl->ByteCount %X\n", PageBlock->IoStatus.Information, Mdl->ByteCount);

    ReadBytes = PageBlock->IoStatus.Information;
    ASSERT(ReadBytes);

    if (!PageBlock->Pfn->OriginalPte.u.Soft.Prototype)
    {
        DPRINT1("MiCompleteInPage: KeBugCheckEx()\n");
        ASSERT(FALSE);
        KeBugCheckEx(0x7A, 4, (ULONG_PTR)FaultAddress, (ULONG_PTR)PageBlock, 0);
    }

    ReadPageCount = ((ReadBytes - 1) / PAGE_SIZE);
    ReadEndPage = (MmGetMdlPfnArray(Mdl) + ReadPageCount);

    ReadOffset = BYTE_OFFSET(ReadBytes);
    if (ReadOffset)
    {
        PEPROCESS process = PsGetCurrentProcess();
        PVOID startAddress;
        PVOID endAddress;

        ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

        startAddress = MiMapPageInHyperSpaceAtDpc(process, *ReadEndPage);
        endAddress = (PVOID)((ULONG_PTR)startAddress + ReadOffset);

        RtlZeroMemory(endAddress, (PAGE_SIZE - ReadOffset));

        MiUnmapPageInHyperSpaceFromDpc(process, startAddress);
    }

    MdlPageCount = ((Mdl->ByteCount - 1) / PAGE_SIZE);
    MdlEndPage = (MmGetMdlPfnArray(Mdl) + MdlPageCount);

    while (TRUE)
    {
        ReadEndPage++;
        if (ReadEndPage > MdlEndPage)
            break;

        MiZeroPhysicalPage(*ReadEndPage);
    }
}

PMMPTE
NTAPI
MiFindActualFaultingPte(
    _In_ PVOID Address)
{
    PMMPDE Pde;
    PMMPTE Pte;
    PMMPTE FaultingProto;
    PMMPTE FaultingPte;

    DPRINT("MiFindActualFaultingPte: Address %p\n", Address);

    if (MI_IS_PHYSICAL_ADDRESS(Address))
        return NULL;

    Pde = MiAddressToPde(Address);
    if (!Pde->u.Hard.Valid)
        return Pde;

    Pte = MiAddressToPte(Address);
    if (Pte->u.Hard.Valid)
        return NULL;

    if (!Pte->u.Soft.Prototype)
        return Pte;

    if (Pte->u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED)
    {
        ULONG dummyProtection;
        PMMVAD dummyProtoVad;

        FaultingProto = MiCheckVirtualAddress(Address, &dummyProtection, &dummyProtoVad);
        if (!FaultingProto)
            return NULL;
    }
    else
    {
        FaultingProto = MiGetProtoPtr(Pte);
    }

    FaultingPte = MiFindActualFaultingPte(FaultingProto);

    if (!FaultingPte)
        return Pte;

    return FaultingPte;
}

NTSTATUS
NTAPI
MiWaitForInPageComplete(
    _In_ PMMPFN InPfn,
    _In_ PMMPTE ReadPte,
    _In_ PVOID Address,
    _In_ PMMPTE OriginalPte,
    _In_ PMI_PAGE_SUPPORT_BLOCK PageBlock,
    _In_ PEPROCESS Process)
{
    PETHREAD Thread = PsGetCurrentThread();
    PMMPTE Pte;
    PMMPTE SectionProto;
    PMDL Mdl;
    NTSTATUS Status;

    DPRINT("MiWaitForInPageComplete: %p, %p, %p, %p, %p, %p\n", InPfn, ReadPte, Address, OriginalPte, PageBlock, Process);

    KeWaitForSingleObject(&PageBlock->Event, WrPageIn, KernelMode, FALSE, NULL);

    if (Process == HYDRA_PROCESS)
    {
        DPRINT1("MiWaitForInPageComplete: FIXME! Process == HYDRA_PROCESS\n");
        ASSERT(FALSE);
    }
    else if (Process == (PEPROCESS)2)
    {
        DPRINT1("MiWaitForInPageComplete: FIXME! Process == (PEPROCESS)2\n");
        ASSERT(FALSE);
    }
    else if (Process)
    {
        MiLockWorkingSet(Thread, &Process->Vm);
    }
    else
    {
        MiLockWorkingSet(Thread, &MmSystemCacheWs);
    }

    MiLockPfnDb(APC_LEVEL);

    ASSERT(InPfn->u3.e2.ReferenceCount != 0);

    if (InPfn != PageBlock->Pfn)
    {
        ASSERT(InPfn->u4.PteFrame != 0x1FFEDCB);
        InPfn->u3.e1.ReadInProgress = 0;
    }

    if (InPfn->u4.InPageError)
    {
        DPRINT1("MiWaitForInPageComplete: InPfn->u1.ReadStatus %X\n", InPfn->u1.ReadStatus);

        ASSERT(!NT_SUCCESS(InPfn->u1.ReadStatus));
        Status = InPfn->u1.ReadStatus;

        if (Status == STATUS_INSUFFICIENT_RESOURCES ||
            Status == STATUS_WORKING_SET_QUOTA ||
            Status == STATUS_NO_MEMORY)
        {
            Status = 0xC7303001;
        }

        return Status;
    }

    if (!PageBlock->u1.e1.InPageComplete)
    {
        NTSTATUS ReadStatus;

        ASSERT((PageBlock->Pfn->u3.e1.ReadInProgress == 1) ||
               (PageBlock->Pfn->PteAddress == (PMMPTE)0x23452345));

        PageBlock->u1.e1.InPageComplete = 1;

        if (PageBlock->u1.e1.PrefetchMdlHighBits)
            Mdl = (PMDL)((ULONG_PTR)PageBlock->u1.e1.PrefetchMdlHighBits << 3);
        else
            Mdl = &PageBlock->Mdl;

        if (Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA)
            MmUnmapLockedPages(Mdl->MappedSystemVa, Mdl);

        ASSERT(PageBlock->Pfn->u4.PteFrame != 0x1FFEDCB);

        PageBlock->Pfn->u3.e1.ReadInProgress = 0;
        PageBlock->Pfn->u1.Event = NULL;

        ReadStatus = PageBlock->IoStatus.Status;

        if (!NT_SUCCESS(ReadStatus))
        {
            if (ReadStatus != STATUS_END_OF_FILE)
            {
                Status = ReadStatus;
                DPRINT1("MiWaitForInPageComplete: FIXME! ReadStatus %X\n", ReadStatus);
                ASSERT(FALSE);
                return Status;
            }

            /* ReadStatus == STATUS_END_OF_FILE */
            DPRINT1("MiWaitForInPageComplete: FIXME! ReadStatus == STATUS_END_OF_FILE\n");
            ASSERT(FALSE);
        }
        else if (PageBlock->IoStatus.Information != Mdl->ByteCount)
        {
            MiCompleteInPage(Address, PageBlock, Mdl);
        }
    }

    if (Process == (PEPROCESS)2)
        return STATUS_SUCCESS;

    Pte = MiFindActualFaultingPte(Address);
    if (!Pte)
    {
        DPRINT("MiWaitForInPageComplete: Address %X\n", Address);
        return 0x87303000;
    }

    if (Pte == ReadPte)
    {
        if (Pte->u.Long != OriginalPte->u.Long)
        {
            DPRINT1("MiWaitForInPageComplete: %X - %X\n", Pte->u.Long, OriginalPte->u.Long);
            return 0x87303000;
        }

        return STATUS_SUCCESS;
    }

    if (!Pte->u.Soft.Prototype)
    {
        DPRINT("MiWaitForInPageComplete: Pte->u.Soft.Prototype %X\n", Pte->u.Soft.Prototype);
        return 0x87303000;
    }

    if (Pte->u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED)
    {
        ULONG dummyProtection;
        PMMVAD dummyProtoVad;

        SectionProto = MiCheckVirtualAddress(Address, &dummyProtection, &dummyProtoVad);
    }
    else
    {
        SectionProto = MiGetProtoPtr(Pte);
    }

    if (SectionProto != ReadPte)
    {
        DPRINT("MiWaitForInPageComplete: SectionProto %X, ReadPte %X\n", SectionProto, ReadPte);
        return 0x87303000;
    }

    if (SectionProto->u.Long != OriginalPte->u.Long)
    {
        DPRINT("MiWaitForInPageComplete: %X - %X\n", SectionProto->u.Long, OriginalPte->u.Long);
        return 0x87303000;
    }

    return STATUS_SUCCESS;
}

VOID
NTAPI
MiFreeInPageSupportBlock(
    _In_ PMI_PAGE_SUPPORT_BLOCK Support)
{
    PMDL Mdl;

    DPRINT("MiFreeInPageSupportBlock: Support %p\n", Support);

    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
    ASSERT(Support->CurrentThread != NULL);
    ASSERT(Support->WaitCount != 0);

    ASSERT((Support->ListEntry.Next == NULL) ||
           (Support->u1.e1.PrefetchMdlHighBits != 0));

    if (InterlockedDecrement((PLONG)&Support->WaitCount))
    {
        DPRINT("MiFreeInPageSupportBlock: Support->WaitCount %X\n", Support->WaitCount);
        return;
    }

    if (Support->u1.e1.PrefetchMdlHighBits)
    {
        Mdl = (PMDL)(Support->u1.e1.PrefetchMdlHighBits << 3);

        if (Mdl != &Support->Mdl)
            ExFreePool(Mdl);
    }

    if (MmInPageSupportSListHead.Depth >= MmInPageSupportMinimum)
    {
        ExFreePoolWithTag(Support, 'nImM');
        return;
    }

    Support->WaitCount = 1;
    Support->u1.LongFlags = 0;

    KeClearEvent(&Support->Event);

    Support->CurrentThread = NULL;

    InterlockedPushEntrySList(&MmInPageSupportSListHead, &Support->ListEntry);
}

NTSTATUS
NTAPI
MiResolveTransitionFault(
    _In_ PVOID Address,
    _In_ PMMPTE Pte,
    _In_ PEPROCESS CurrentProcess,
    _In_ KIRQL OldIrql,
    _Out_ PMI_PAGE_SUPPORT_BLOCK* OutPageBlock)
{
    PMMPFN Pfn;
    MMPTE TempPte;
    MMPTE tempPte;
    PFN_NUMBER PageFrameIndex;
    BOOLEAN IsNeedUnlock;
    BOOLEAN IsNeedUnlockThread = FALSE;
    NTSTATUS Status;

    DPRINT("MiResolveTransitionFault: Address %p, PTE %p [%p], Process %s\n",
           Address, Pte, Pte->u.Long, ((CurrentProcess > (PEPROCESS)2) ? CurrentProcess->ImageFileName : " "));

    /* Windowss does this check */
    if (OutPageBlock && *OutPageBlock)
    {
        DPRINT1("MiResolveTransitionFault: OutPageBlock %p [%p]\n", OutPageBlock, *OutPageBlock);
        ASSERT(*OutPageBlock == NULL);
    }

    /* Capture the PTE and make sure it's in transition format */
    if (OldIrql != MM_NOIRQL)
    {
        IsNeedUnlock = FALSE;

        /* Capture the PTE and make sure it's in transition format */
        TempPte.u.Long = Pte->u.Long;

        ASSERT((TempPte.u.Soft.Valid == 0) &&
               (TempPte.u.Soft.Prototype == 0) &&
               (TempPte.u.Soft.Transition == 1));

        /* Get the PFN and the PFN entry */
        PageFrameIndex = TempPte.u.Trans.PageFrameNumber;
        Pfn = MI_PFN_ELEMENT(PageFrameIndex);
    }
    else
    {
        IsNeedUnlock = TRUE;

        /* Capture the PTE */
        tempPte = *Pte;

        /* Get the PFN and the PFN entry */
        PageFrameIndex = tempPte.u.Hard.PageFrameNumber;
        Pfn = MI_PFN_ELEMENT(PageFrameIndex);

        OldIrql = MiLockPfnDb(APC_LEVEL);

        /* Capture the PTE */
        TempPte = *Pte;

        if (TempPte.u.Soft.Valid ||
            TempPte.u.Soft.Prototype ||
            !TempPte.u.Soft.Transition)
        {
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            DPRINT1("MiResolveTransitionFault: PTE is not transition\n");
            return 0xC7303001;
        }

        if (tempPte.u.Long != TempPte.u.Long)
        {
            /* Get the PFN and the PFN entry */
            PageFrameIndex = TempPte.u.Trans.PageFrameNumber;
            Pfn = MI_PFN_ELEMENT(PageFrameIndex);
        }
    }

    /* One more transition fault! */
    InterlockedIncrement(&KeGetCurrentPrcb()->MmTransitionCount);

    if (Pfn->u4.InPageError)
    {
        DPRINT1("MiResolveTransitionFault: FIXME\n");
        ASSERT(FALSE);
    }

    /* See if we should wait before terminating the fault */
    if (Pfn->u3.e1.ReadInProgress)
    {
        PETHREAD Thread = PsGetCurrentThread();
        PMI_PAGE_SUPPORT_BLOCK PageBlock;

        PageBlock = CONTAINING_RECORD(Pfn->u1.Event, MI_PAGE_SUPPORT_BLOCK, Event);

        if (PageBlock->CurrentThread == Thread)
        {
            ASSERT(Thread->ActiveFaultCount >= 1);
            Thread->ApcNeeded = 1;

            if (IsNeedUnlock)
                MiUnlockPfnDb(OldIrql, APC_LEVEL);

            return STATUS_MULTIPLE_FAULT_VIOLATION;
        }

        ASSERT(Pfn->u2.ShareCount == 0);
        ASSERT(Pfn->u3.e2.ReferenceCount != 0);

        InterlockedIncrement16((PSHORT)&Pfn->u3.e2.ReferenceCount);
        InterlockedIncrement((PLONG)&PageBlock->WaitCount);

        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        Thread->ActiveFaultCount++;

        if (CurrentProcess != HYDRA_PROCESS)
        {
            if (CurrentProcess)
            {
                KeEnterCriticalRegion();
                MiUnlockWorkingSet(Thread, &CurrentProcess->Vm);
                IsNeedUnlockThread = TRUE;
            }
            else
            {
                MiUnlockWorkingSet(Thread, &MmSystemCacheWs);
            }
        }
        else
        {
            MiUnlockWorkingSet(Thread, &MmSessionSpace->GlobalVirtualAddress->Vm);
        }

        *OutPageBlock = PageBlock;

        Status = MiWaitForInPageComplete(Pfn, Pte, (PVOID)Address, &TempPte, PageBlock, CurrentProcess);

        Thread->ActiveFaultCount--;
        ASSERT(Pfn->u3.e1.ReadInProgress == 0);

        if (IsNeedUnlockThread)
            KeLeaveCriticalRegion();

        if (Status != STATUS_SUCCESS)
        {
            NTSTATUS ReadStatus = Pfn->u1.ReadStatus;

            MiDereferencePfnAndDropLockCount(Pfn);

            if (Pfn->u4.InPageError)
            {
                ASSERT(!NT_SUCCESS(ReadStatus));

                if (!Pfn->u3.e2.ReferenceCount)
                {
                    Pfn->u4.InPageError = 0;

                    if (Pfn->u3.e1.PageLocation != FreePageList)
                    {
                        ASSERT(Pfn->u3.e1.PageLocation == StandbyPageList);
                        MiUnlinkPageFromList(Pfn);

                        ASSERT(Pfn->u3.e2.ReferenceCount == 0);

                        MiRestoreTransitionPte(Pfn);
                        MiInsertPageInFreeList(PageFrameIndex);
                    }
                }
            }

            if (IsNeedUnlock)
                MiUnlockPfnDb(OldIrql, APC_LEVEL);

            DPRINT("MiResolveTransitionFault: 0xC7303001\n");
            return 0xC7303001;
        }
    }
    else
    {
        ASSERT((SPFN_NUMBER)MmAvailablePages >= 0);

        if (MmAvailablePages < 0x80)
        {
            if (!MmAvailablePages || !PsGetCurrentThread()->MemoryMaker)
            {
                if (MiEnsureAvailablePageOrWait(CurrentProcess, OldIrql))
                {
                    if (IsNeedUnlock)
                        MiUnlockPfnDb(OldIrql, APC_LEVEL);

                    DPRINT1("MiResolveTransitionFault: STATUS_NO_MEMORY\n");
                    return STATUS_NO_MEMORY;
                }
            }
        }

        ASSERT(Pfn->u4.InPageError == 0);

        /* Was this a transition page in the valid list, or free/zero list? */
        if (Pfn->u3.e1.PageLocation == ActiveAndValid)
        {
            /* All Windows does here is a bunch of sanity checks */
            ASSERT(((Pfn->PteAddress >= MiAddressToPte(MmPagedPoolStart)) &&
                    (Pfn->PteAddress <= MiAddressToPte(MmPagedPoolEnd))) ||
                   ((Pfn->PteAddress >= MiAddressToPte(MmSpecialPoolStart)) &&
                    (Pfn->PteAddress <= MiAddressToPte(MmSpecialPoolEnd))));

            ASSERT(Pfn->u2.ShareCount != 0);
            ASSERT(Pfn->u3.e2.ReferenceCount != 0);
        }
        else
        {
            /* Otherwise, the page is removed from its list */
            MiUnlinkPageFromList(Pfn);
            MiReferenceUnusedPageAndBumpLockCount(Pfn);
        }
    }

    /* At this point, there should no longer be any in-page errors */
    ASSERT(Pfn->u4.InPageError == 0);

    /* Check if this was a PFN with no more share references */
    if (!Pfn->u2.ShareCount)
        MiDropLockCount(Pfn);

    /* Bump the share count and make the page valid */
    Pfn->u2.ShareCount++;
    Pfn->u3.e1.PageLocation = ActiveAndValid;

    if (Address >= MmSystemRangeStart)
    {
        /* Check if this is a paged pool PTE in transition state */
        TempPte = *(MiAddressToPte(Pte));

        if (!TempPte.u.Hard.Valid && TempPte.u.Soft.Transition)
        {
            /* This isn't yet supported */
            DPRINT1("MiResolveTransitionFault: Double transition fault not yet supported\n");
            ASSERT(FALSE);
        }
    }

    /* Build the final PTE */
    ASSERT(Pte->u.Hard.Valid == 0);
    ASSERT(Pte->u.Trans.Prototype == 0);
    ASSERT(Pte->u.Trans.Transition == 1);

    TempPte.u.Long = (Pte->u.Long & ~0xFFF) |
                     (MmProtectToPteMask[Pte->u.Trans.Protection]) |
                     MiDetermineUserGlobalPteMask(Pte);

    /* Is the PTE writeable? */
    if (Pfn->u3.e1.Modified && (TempPte.u.Long & PTE_READWRITE) && !MI_IS_PAGE_COPY_ON_WRITE(&TempPte))
        /* Make it dirty */
        MI_MAKE_DIRTY_PAGE(&TempPte);
    else
        /* Make it clean */
        MI_MAKE_CLEAN_PAGE(&TempPte);

    /* Write the valid PTE */
    MI_WRITE_VALID_PTE(Pte, TempPte);

    if (IsNeedUnlock)
    {
        MMWSLE TempWsle;

        ASSERT(Pfn->u3.e1.PrototypePte == 0);
        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        TempWsle.u1.Long = 0;
        if (!MiAddValidPageToWorkingSet(Address, Pte, Pfn, TempWsle))
        {
            DPRINT("MiResolveTransitionFault: FIXME MiTrimPte()\n");
            ASSERT(FALSE);
            return STATUS_NO_MEMORY;
        }
    }

    /* Return success */
    DPRINT("MiResolveTransitionFault: STATUS_PAGE_FAULT_TRANSITION\n");
    return STATUS_PAGE_FAULT_TRANSITION;
}

NTSTATUS
NTAPI
MiResolveProtoPteFault(
    _In_ BOOLEAN StoreInstruction,
    _In_ PVOID Address,
    _In_ PMMPTE Pte,
    _In_ PMMPTE SectionProto,
    _Inout_ PMMPFN* LockedProtoPfn,
    _Out_ PMI_PAGE_SUPPORT_BLOCK* OutPageBlock,
    _Out_ PMMPTE PteValue,
    _In_ PEPROCESS Process,
    _In_ KIRQL OldIrql,
    _In_ PVOID TrapInformation)
{
    PMI_PAGE_SUPPORT_BLOCK PageBlock;
    PLIST_ENTRY Entry;
    PMMPFN Pfn;
    MMPTE TempProto;
    MMPTE TempPte;
    PFN_NUMBER PageFrameIndex;
    ULONG Protection;
    BOOLEAN IsLocked = TRUE;
    NTSTATUS Status;

    DPRINT("MiResolveProtoPteFault: %p, %p, %p [%p], %X, %X\n",
           Address, Pte, SectionProto, SectionProto->u.Long, Process, OldIrql);

    /* Must be called with an invalid, prototype PTE, with the PFN lock held */
    MI_ASSERT_PFN_LOCK_HELD();
    ASSERT(Pte->u.Hard.Valid == 0);
    ASSERT(Pte->u.Soft.Prototype == 1);

    /* Read the prototype PTE and check if it's valid */
    TempProto = *SectionProto;

    if (TempProto.u.Hard.Valid)
    {
        /* One more user of this mapped page */
        PageFrameIndex = PFN_FROM_PTE(&TempProto);
        Pfn = MiGetPfnEntry(PageFrameIndex);
        Pfn->u2.ShareCount++;

        /* Call it a transition */
        InterlockedIncrement(&KeGetCurrentPrcb()->MmTransitionCount);

        /* Complete the prototype PTE fault -- this will release the PFN lock */
        Status = MiCompleteProtoPteFault(StoreInstruction, Address, Pte, SectionProto, OldIrql, LockedProtoPfn);
        return Status;
    }

    /* Make sure there's some protection mask */
    if (!TempProto.u.Long)
    {
        /* Release the lock */
        DPRINT1("MiResolveProtoPteFault: Access on reserved section?\n");
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        return STATUS_ACCESS_VIOLATION;
    }

    PageBlock = NULL;

    /* Check for access rights on the PTE proper */
    TempPte = *Pte;

    if (TempPte.u.Soft.PageFileHigh != MI_PTE_LOOKUP_NEEDED)
    {
        if (TempPte.u.Proto.ReadOnly)
        {
            Protection = MM_READONLY;
        }
        else
        {
            Status = MiAccessCheck(SectionProto,
                                   StoreInstruction,
                                   KernelMode,
                                   TempProto.u.Soft.Protection,
                                   TrapInformation,
                                   TRUE);

            if (Status != STATUS_SUCCESS)
            {
                DPRINT("MiResolveProtoPteFault: Status %X\n", Status);

                if (StoreInstruction &&
                    Address >= MmSessionBase && Address < MiSessionSpaceEnd &&
                    MmSessionSpace->ImageLoadingCount)
                {
                    for (Entry = MmSessionSpace->ImageList.Flink;
                         Entry != &MmSessionSpace->ImageList;
                         Entry = Entry->Flink)
                    {
                        DPRINT1("MiResolveProtoPteFault: FIXME\n");
                        ASSERT(FALSE);
                    }
                }

                MiUnlockPfnDb(OldIrql, APC_LEVEL);
                return Status;
            }

            DPRINT("MiResolveProtoPteFault: Status %X\n", Status);

            Protection = TempProto.u.Soft.Protection;
        }
    }
    else
    {
        Protection = TempPte.u.Soft.Protection;
    }

    if (Pte <= MiHighestUserPte &&
        Process > (PEPROCESS)2 &&
        Process->CloneRoot)
    {
        DPRINT1("MiResolveProtoPteFault: FIXME\n");
        ASSERT(FALSE);
        Protection = MM_WRITECOPY;
    }

    /* Check for writing copy on write page */
    if (!MI_IS_MAPPED_PTE(&TempProto) && ((Protection & MM_WRITECOPY) == MM_WRITECOPY))
    {
        MMPTE NewPte;

        DPRINT("MiResolveProtoPteFault: DemandZero page with Protection protection\n");

        ASSERT(Process != NULL);
        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        NewPte = DemandZeroPte;

        ASSERT(TempPte.u.Hard.Valid == 0);

        if (TempPte.u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED)
        {
            if (TempPte.u.Soft.Protection & MM_EXECUTE)
                NewPte.u.Soft.Protection = MM_EXECUTE_READWRITE;
        }
        else
        {
            if (TempProto.u.Soft.Protection & MM_EXECUTE)
                NewPte.u.Soft.Protection = MM_EXECUTE_READWRITE;
        }

        Pte->u.Long = NewPte.u.Long;

        Status = MiResolveDemandZeroFault(Address, Pte, Process, MM_NOIRQL);

        DPRINT("MiResolveProtoPteFault: Status %X\n", Status);
        return Status;
    }

    if (TempProto.u.Soft.Prototype)
    {
        /* This is mapped file fault */
        Status = MiResolveMappedFileFault(SectionProto, OutPageBlock, Process, OldIrql);
        if (Status == 0xC0033333)
        {
            *PteValue = *SectionProto;

            ASSERT(PteValue->u.Hard.Valid == 0);
            ASSERT(PteValue->u.Soft.Prototype == 0);
            ASSERT(PteValue->u.Soft.Transition == 1);
        }
    }
    else if (TempProto.u.Soft.Transition)
    {
        ASSERT(OldIrql != MM_NOIRQL);

        /* Resolve the transition fault */
        Status = MiResolveTransitionFault(Address, SectionProto, Process, OldIrql, &PageBlock);
    }
    else if (TempProto.u.Soft.PageFileHigh)
    {
        /* We don't support paged out pages */
        DPRINT1("MiResolveProtoPteFault: FIXME\n");
        ASSERT(FALSE);

        Status = STATUS_NOT_IMPLEMENTED;//MiResolvePageFileFault (Address, SectionProto, PteValue, OutPageBlock, Process, OldIrql);

        if (Status == 0xC0033333)
        {
            ASSERT(PteValue->u.Hard.Valid == 0);
            ASSERT(PteValue->u.Soft.Prototype == 0);
            ASSERT(PteValue->u.Soft.Transition == 1);
        }

        ASSERT(KeAreAllApcsDisabled() == TRUE);
        IsLocked = FALSE;
    }
    else
    {
        ASSERT(OldIrql != MM_NOIRQL);

        /* Resolve the demand zero fault */
        Status = MiResolveDemandZeroFault(Address, SectionProto, Process, OldIrql);
    }

    if (NT_SUCCESS(Status))
    {
        ASSERT(Pte->u.Hard.Valid == 0);

        /* Complete the prototype PTE fault -- this will release the PFN lock */
        Status = MiCompleteProtoPteFault(StoreInstruction, Address, Pte, SectionProto, OldIrql, LockedProtoPfn);
    }
    else
    {
        if (IsLocked)
            MiUnlockPfnDb(OldIrql, APC_LEVEL);

        ASSERT(KeAreAllApcsDisabled() == TRUE);
    }

    if (PageBlock)
        MiFreeInPageSupportBlock(PageBlock);

    return Status;
}

NTSTATUS
NTAPI
MiDispatchFault(
    _In_ ULONG FaultCode,
    _In_ PVOID Address,
    _In_ PMMPTE Pte,
    _In_ PMMPTE SectionProto,
    _In_ BOOLEAN Recursive,
    _In_ PEPROCESS Process,
    _In_ PVOID TrapInformation,
    _In_ PMMVAD Vad)
{
    PETHREAD CurrentThread = PsGetCurrentThread();
    PMI_PAGE_SUPPORT_BLOCK PageBlock;
    PMI_PAGE_SUPPORT_BLOCK pageBlock;
    PMMPFN LockedProtoPfn = NULL;
    PMMPFN PfnClusterPage;
    PMMPFN PfnForPde;
    PMMPFN Pfn;
    PMMSUPPORT SessionWs = NULL;
    PPFN_NUMBER MdlPages;
    PMMPTE SectionProtoPte;
    PMMPTE ReadPte = NULL;
    PMMPTE StartProto;
    MMPTE TempPte;
    MMPTE TempProto;
    MMPTE OriginalPte;
    MMPTE PteContents;
    MMPTE NewPteContents;
    MMWSLE ProtoProtect;
    PFN_NUMBER PageFrameIndex;
    PFN_NUMBER PageNumber = -1;
    PFN_COUNT ProcessedPtes;
    PFN_COUNT PteCount;
    ULONG CacheAttribute;
    ULONG MdlPageCount;
    ULONG Flags = 0;
    ULONG Index;
    ULONG WsIndex;
    ULONG ix;
    ULONG jx;
    KIRQL OldIrql;
    KIRQL LockIrql = MM_NOIRQL;
    NTSTATUS Status;

    DPRINT("MiDispatchFault: %X, %p, %p, %X, %X, %p, %p, %X\n",
           FaultCode, Address, Pte, SectionProto, Recursive, Process, TrapInformation, Vad);

    /* Make sure APCs are off and we're not at dispatch */
    OldIrql = KeGetCurrentIrql();
    ASSERT(OldIrql <= APC_LEVEL);
    ASSERT(KeAreAllApcsDisabled() == TRUE);

    OriginalPte.u.Long = -1;
    ProtoProtect.u1.Long = 0;

    /* Do we have a prototype PTE? */
    if (SectionProto)
    {
        /* This should never happen */
        ASSERT(!MI_IS_PHYSICAL_ADDRESS(SectionProto));

        /* Check if this is a kernel-mode address */
        SectionProtoPte = MiAddressToPte(SectionProto);

        if (Address >= MmSystemRangeStart)
        {
            /* Lock the PFN database */
            LockIrql = MiLockPfnDb(APC_LEVEL);

            /* Has the PTE been made valid yet? */
            if (!SectionProtoPte->u.Hard.Valid)
            {
                ASSERT((Process == NULL) || (Process == HYDRA_PROCESS));

                /* Unlock the PFN database */
                MiUnlockPfnDb(LockIrql, APC_LEVEL);

                Address = SectionProto;
                Pte = SectionProtoPte;
                SectionProto = NULL;

                if (Process == HYDRA_PROCESS)
                {
                    DPRINT1("MiDispatchFault: FIXME! Process == HYDRA_PROCESS. SectionProto %X\n", SectionProto);
                    ASSERT(FALSE);
                }

                goto OtherPteTypes;
            }
            else
            {
                if (Pte->u.Hard.Valid)
                {
                    /* Release the lock and leave*/
                    MiUnlockPfnDb(LockIrql, APC_LEVEL);
                    return STATUS_SUCCESS;
                }
            }
        }
        else
        {
            /* This is a user fault */

            PteCount = 1;

            if (Pte->u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED || Pte->u.Proto.ReadOnly)
            {
                /* Is there a non-image VAD? */
                if (Vad &&
                    Vad->u.VadFlags.VadType != VadImageMap &&
                    !Vad->u2.VadFlags2.ExtendableFile &&
                    MmAvailablePages > 20000 &&
                    (!Process->Vm.Flags.MaximumWorkingSetHard || Process->Vm.MaximumWorkingSetSize >= (Process->Vm.WorkingSetSize + 8)) &&
                    !Recursive)
                {
                    PteCount = 8; // MmMaxTransitionCluster

                    if (SectionProto >= Vad->FirstPrototypePte &&
                        SectionProto <= Vad->LastContiguousPte)
                    {
                        ix = (Vad->LastContiguousPte - SectionProto + 1);
                    }
                    else
                    {
                        PSUBSECTION Subsection = (PSUBSECTION)&Vad->ControlArea[1];

                        //DPRINT1("MiDispatchFault: %p (%p:%p)\n", SectionProto, Vad->FirstPrototypePte, Vad->LastContiguousPte);

                        ix = 1;

                        for (; Subsection; Subsection = Subsection->NextSubsection)
                        {
                            if (!Subsection->SubsectionBase)
                                continue;

                            if (SectionProto < Subsection->SubsectionBase)
                                continue;

                            if (SectionProto >= &Subsection->SubsectionBase[Subsection->PtesInSubsection])
                                continue;

                            ix = (&Subsection->SubsectionBase[Subsection->PtesInSubsection] - SectionProto);
                            //DPRINT1("MiDispatchFault: ix %X\n", ix);

                            break;
                        }
                    }

                    if (ix < 8) // MmMaxTransitionCluster
                        PteCount = ix;

                    if (PteCount > (PAGE_SIZE - ((ULONG_PTR)Pte & (PAGE_SIZE - 1))) / 4)
                        PteCount = (PAGE_SIZE - ((ULONG_PTR)Pte & (PAGE_SIZE - 1))) / 4;

                    if (PteCount > (PAGE_SIZE - ((ULONG_PTR)SectionProto & (PAGE_SIZE - 1))) / 4)
                        PteCount = (PAGE_SIZE - ((ULONG_PTR)SectionProto & (PAGE_SIZE - 1))) / 4;

                    if (PteCount > (Vad->EndingVpn - ((ULONG_PTR)Address / PAGE_SIZE) + 1))
                        PteCount = (Vad->EndingVpn - ((ULONG_PTR)Address / PAGE_SIZE) + 1);

                    ix = 1;
                    Index = MmWorkingSetList->FirstFree;

                    if (PteCount > 1 && Index != 0x0FFFFFFF)
                    {
                        PMMWSLE MmWsle = (PMMWSLE)(MmWorkingSetList + 1);

                        do
                        {
                            if (MmWsle[Index].u1.Long == 0xFFFFFFF0)
                                break;

                            Index = (MmWsle[Index].u1.Long >> 4);

                            ix++;
                        }
                        while (ix < PteCount);
                    }

                    if (PteCount > ix)
                        PteCount = ix;

                    ASSERT(Address <= MM_HIGHEST_USER_ADDRESS);

                    for (jx = 1; jx < PteCount && !Pte[jx].u.Long; jx++)
                        MI_WRITE_INVALID_PTE(&Pte[jx], *Pte);

                    PteCount = jx;

                    if (PteCount > 1)
                    {
                        MiAddPageTableReferences(Address, (PteCount - 1));
                        ProtoProtect.u1.e1.Protection = Pte->u.Soft.Protection;
    
                        MI_MAKE_HARDWARE_PTE_USER(&PteContents, Pte, ProtoProtect.u1.e1.Protection, 0);

                        if (MI_IS_WRITE_ACCESS(FaultCode) && ((ProtoProtect.u1.e1.Protection & 5) != 5))
                        {
                            MI_MAKE_DIRTY_PAGE(&PteContents);
                            Flags |= 0x01;
                        }

                        PfnForPde = MI_PFN_ELEMENT((MiAddressToPte(Pte))->u.Hard.PageFrameNumber);
                    }
                }
            }
            else
            {
                Flags = 0x04; // FIXME
            }

            ProcessedPtes = 0;
            Flags |= 0x02;

            /* Lock the PFN database */
            LockIrql = MiLockPfnDb(APC_LEVEL);

            /* We only handle the valid path */
            if (!SectionProtoPte->u.Hard.Valid)
            {
                DPRINT1("MiDispatchFault: FIXME! SectionProtoPte %X\n", SectionProtoPte);
                ASSERT(FALSE);
            }

            /* Capture the PTE */
            TempProto = *SectionProto;

            if (Recursive)
            {
                DPRINT1("MiDispatchFault: FIXME!\n");
                ASSERT(FALSE);
            }

            if (!(Flags & 0x04))
            {
                while (TRUE)
                {
                    ULONG Protection;

                    if (TempProto.u.Hard.Valid == 1)
                    {
                        /* Bump the share count on the PTE */
                        PageFrameIndex = PFN_FROM_PTE(&TempProto);
                        Pfn = MI_PFN_ELEMENT(PageFrameIndex);
                        Pfn->u2.ShareCount++;
                    }
                    else if (!TempProto.u.Soft.Prototype && TempProto.u.Soft.Transition)
                    {
                        DPRINT("MiDispatchFault: TempProto.u.Long %X, LockIrql %X\n", TempProto.u.Long, LockIrql);

                        /* This is a standby page, bring it back from the cache */
                        PageFrameIndex = TempProto.u.Trans.PageFrameNumber;
                        Pfn = MI_PFN_ELEMENT(PageFrameIndex);
                        ASSERT(Pfn->u3.e1.PageLocation != ActiveAndValid);

                        if (Pfn->u3.e1.ReadInProgress || Pfn->u4.InPageError || (MmAvailablePages < 0x80))
                            break;

                        /* Get the page */
                        MiUnlinkPageFromList(Pfn);

                        /* Bump its reference count */
                        ASSERT(Pfn->u2.ShareCount == 0);
                        InterlockedIncrement16((PSHORT)&Pfn->u3.e2.ReferenceCount);
                        Pfn->u2.ShareCount++;

                        /* Make it valid again */
                        /* This looks like another macro.... */
                        Pfn->u3.e1.PageLocation = ActiveAndValid;

                        ASSERT(SectionProto->u.Hard.Valid == 0);
                        ASSERT(SectionProto->u.Trans.Prototype == 0);
                        ASSERT(SectionProto->u.Trans.Transition == 1);

                        TempPte.u.Long = (SectionProto->u.Long & ~(PAGE_SIZE - 1)) |
                                         MmProtectToPteMask[SectionProto->u.Trans.Protection];

                        TempPte.u.Hard.Valid = 1;
                        MI_MAKE_ACCESSED_PAGE(&TempPte);

                        /* Is the PTE writeable? */
                        if (Pfn->u3.e1.Modified && TempPte.u.Hard.Write && !TempPte.u.Hard.CopyOnWrite)
                            /* Make it dirty */
                            MI_MAKE_DIRTY_PAGE(&TempPte);
                        else
                            /* Make it clean */
                            MI_MAKE_CLEAN_PAGE(&TempPte);

                        /* Write the valid PTE */
                        MI_WRITE_VALID_PTE(SectionProto, TempPte);
                        ASSERT(Pte->u.Hard.Valid == 0);
                    }
                    else
                    {
                        /* Page is invalid, get out of the loop */
                        DPRINT("MiDispatchFault: TempProto.u.Long %X, LockIrql %X\n", TempProto.u.Long, LockIrql);
                        break;
                    }

                    /* One more done, was it the last? */
                    ProcessedPtes++;
                    if (ProcessedPtes == PteCount)
                    {
                        /* Complete the fault */
                        MiCompleteProtoPteFault(MI_IS_WRITE_ACCESS(FaultCode),
                                                Address,
                                                Pte,
                                                SectionProto,
                                                LockIrql,
                                                &LockedProtoPfn);
                        Flags &= ~0x02;
                        break;
                    }

                    ASSERT(SectionProto->u.Hard.Valid == 1);

                    Pfn->u3.e1.PrototypePte = 1;
                    PfnForPde->u2.ShareCount++;

                    NewPteContents.u.Long = PteContents.u.Long;
                    ASSERT(NewPteContents.u.Long != 0);

                    if (Pfn->u3.e1.CacheAttribute == MiNonCached)
                    {
                        Protection = ProtoProtect.u1.e1.Protection;
                        Protection &= ~(MM_NOCACHE | MM_WRITECOMBINE);
                        Protection |= MM_NOCACHE;
                        NewPteContents.u.Long = 0;
                    }
                    else if (Pfn->u3.e1.CacheAttribute == MiWriteCombined)
                    {
                        Protection = ProtoProtect.u1.e1.Protection;
                        Protection &= ~(MM_NOCACHE | MM_WRITECOMBINE);
                        Protection |= MM_WRITECOMBINE;
                        NewPteContents.u.Long = 0;
                    }

                    if (!NewPteContents.u.Long)
                    {
                        MI_MAKE_HARDWARE_PTE_USER(&NewPteContents, Pte, Protection, 0);//u.Hard.Accessed = 1

                        if (MI_IS_WRITE_ACCESS(FaultCode) && ((Protection & 5) != 5))
                            MI_MAKE_DIRTY_PAGE(&NewPteContents);
                    }

                    NewPteContents.u.Hard.PageFrameNumber = PageFrameIndex;

                    if (Flags & 0x01)
                    {
                        OriginalPte = Pfn->OriginalPte;

                        ASSERT(Pfn->u3.e1.Rom == 0);
                        Pfn->u3.e1.Modified = 1;

                        if (!OriginalPte.u.Soft.Prototype && !Pfn->u3.e1.WriteInProgress)
                        {
                            ULONG PageFileHigh = OriginalPte.u.Soft.PageFileHigh;

                            if (PageFileHigh && PageFileHigh != MI_PTE_LOOKUP_NEEDED)
                            {
                                DPRINT1("MiCompleteProtoPteFault: FIXME. PageFileHigh %X\n", PageFileHigh);
                                ASSERT(FALSE);
                            }

                            Pfn->OriginalPte.u.Soft.PageFileHigh = 0;
                        }
                    }

                    ASSERT(Pte == MiAddressToPte(Address));

                    MI_WRITE_VALID_PTE(Pte, NewPteContents);

                    SectionProto++;
                    TempProto = *SectionProto;

                    Pte++;
                    Address = (PVOID)((ULONG_PTR)Address + PAGE_SIZE);
                }
            }

            /* Did we resolve the fault? */
            if (ProcessedPtes)
            {
                if (Flags & 0x02)
                {
                    MiUnlockPfnDb(LockIrql, APC_LEVEL);
                    InterlockedExchangeAddSizeT(&KeGetCurrentPrcb()->MmTransitionCount, ProcessedPtes);
                }
                else
                {
                    /* Bump the transition count */
                    InterlockedExchangeAddSizeT(&KeGetCurrentPrcb()->MmTransitionCount, ProcessedPtes);
                    ProcessedPtes--;

                }

                while (ProcessedPtes)
                {
                    SectionProto--;
                    Pte--;
                    Address = (PVOID)((ULONG_PTR)Address - PAGE_SIZE);
                    ProcessedPtes--;

                    PageFrameIndex = PFN_FROM_PTE(Pte);
                    Pfn = MI_PFN_ELEMENT(PageFrameIndex);

                    ASSERT(ProtoProtect.u1.e1.Protection != MM_ZERO_ACCESS);
                    ASSERT(MI_IS_PAGE_TABLE_ADDRESS(Pte));
                    ASSERT(Pte->u.Hard.Valid == 1);

                    WsIndex = MiAllocateWsle(&Process->Vm, Pte, Pfn, ProtoProtect);
                    ASSERT(WsIndex != 0);

                    if (Pfn->OriginalPte.u.Soft.Prototype)
                    {
                        DPRINT("MiDispatchFault: FIXME CcPfNumActiveTraces\n");
                        //ASSERT(FALSE);
                    }
                }

                ASSERT(OldIrql == KeGetCurrentIrql());
                ASSERT(OldIrql <= APC_LEVEL);
                ASSERT(KeAreAllApcsDisabled() == TRUE);

                DPRINT("MiDispatchFault: return STATUS_PAGE_FAULT_TRANSITION\n");
                return STATUS_PAGE_FAULT_TRANSITION;
            }

            ASSERT(Flags & 0x02);

            /* We did not -- PFN lock is still held, prepare to resolve prototype PTE fault */
            LockedProtoPfn = MI_PFN_ELEMENT(SectionProtoPte->u.Hard.PageFrameNumber);
            MiReferenceUsedPageAndBumpLockCount(LockedProtoPfn);

            ASSERT(LockedProtoPfn->u3.e2.ReferenceCount > 1);
            ASSERT(Pte->u.Hard.Valid == 0);
        }

        /* Resolve the fault -- this will release the PFN lock */
        Status = MiResolveProtoPteFault(MI_IS_WRITE_ACCESS(FaultCode),
                                        Address,
                                        Pte,
                                        SectionProto,
                                        &LockedProtoPfn,
                                        &PageBlock,
                                        &OriginalPte,
                                        Process,
                                        LockIrql,
                                        TrapInformation);
        ReadPte = SectionProto;

        ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
        goto Finish;
    }

OtherPteTypes:

    TempPte = *Pte;

    ASSERT(TempPte.u.Hard.Valid == 0);
    ASSERT(TempPte.u.Soft.Prototype == 0);
    ASSERT(TempPte.u.Long != 0);

    if (TempPte.u.Soft.Transition)
    {
        pageBlock = NULL;

        Status = MiResolveTransitionFault(Address, Pte, Process, MM_NOIRQL, &pageBlock);

        if (pageBlock)
            MiFreeInPageSupportBlock(pageBlock);
    }
    else if (TempPte.u.Soft.PageFileHigh)
    {
        DPRINT1("MiDispatchFault: FIXME! TempPte.u.Soft.PageFileHigh %X\n", TempPte.u.Soft.PageFileHigh);
        ASSERT(FALSE);Status = STATUS_NOT_IMPLEMENTED;
    }
    else
    {
        Status = MiResolveDemandZeroFault(Address, Pte, Process, MM_NOIRQL);
    }

Finish:

    ASSERT(KeAreAllApcsDisabled() == TRUE);

    if (NT_SUCCESS(Status))
    {
        if (LockedProtoPfn)
        {
            ASSERT(SectionProto != NULL);

            /* Lock the PFN database */
            LockIrql = MiLockPfnDb(APC_LEVEL);

            ASSERT(LockedProtoPfn->u3.e2.ReferenceCount >= 1);
            MiDereferencePfnAndDropLockCount(LockedProtoPfn);

            /* Unlock the PFN database */
            MiUnlockPfnDb(LockIrql, APC_LEVEL);
        }

        if (SessionWs)
        {
            DPRINT1("MiDispatchFault: FIXME! SessionWs %X\n", SessionWs);
            ASSERT(FALSE);
        }

        ASSERT(OldIrql == KeGetCurrentIrql());
        ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

        return Status;
    }

    if (Status == 0xC0033333)
    {
        PMMPFN PageBlockPfn;

        ASSERT(ReadPte != NULL);
        ASSERT(PageBlock != NULL);

        if (SectionProto)
        {
            ASSERT(OriginalPte.u.Hard.Valid == 0);
            ASSERT(OriginalPte.u.Soft.Prototype == 0);
            ASSERT(OriginalPte.u.Soft.Transition == 1);
        }
        else
        {
            OriginalPte.u.Long = ReadPte->u.Long;
        }

        pageBlock = (PMI_PAGE_SUPPORT_BLOCK)PageBlock->Pfn->u1.Event;

        CurrentThread->ActiveFaultCount++;

        if (Process == HYDRA_PROCESS)
        {
            MiUnlockWorkingSet(CurrentThread, &MmSessionSpace->GlobalVirtualAddress->Vm);

            ASSERT(KeGetCurrentIrql () <= APC_LEVEL);
            ASSERT(KeAreAllApcsDisabled () == TRUE);
        }
        else if (Process)
        {
            KeEnterCriticalRegion();
            MiUnlockWorkingSet(CurrentThread, &Process->Vm);
            Flags |= 0x10;
        }
        else
        {
            MiUnlockWorkingSet(CurrentThread, &MmSystemCacheWs);
            ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
            ASSERT(KeAreAllApcsDisabled() == TRUE);
        }

        ASSERT(PageBlock->u1.e1.PrefetchMdlHighBits == 0);

        Status = IoPageRead(PageBlock->FilePointer,
                            &PageBlock->Mdl,
                            &PageBlock->StartingOffset,
                            &PageBlock->Event,
                            &PageBlock->IoStatus);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("MiDispatchFault: Status %X\n", Status);
            PageBlock->IoStatus.Status = Status;
            PageBlock->IoStatus.Information = 0;

            KeSetEvent(&PageBlock->Event, 0, FALSE);
        }

        Status = MiWaitForInPageComplete(PageBlock->Pfn, ReadPte, Address, &OriginalPte, pageBlock, Process);
        DPRINT("MiDispatchFault: Status %X\n", Status);

        CurrentThread->ActiveFaultCount--;

        if (Flags & 0x10)
            KeLeaveCriticalRegion();

        PageBlockPfn = PageBlock->Pfn;
        MdlPages = PageBlock->MdlPages;
        StartProto = PageBlock->StartProto;

        if ((LONG)PageBlock->Mdl.ByteCount > 0)
        {
            for (MdlPageCount = (((PageBlock->Mdl.ByteCount - 1) / PAGE_SIZE) + 1);
                 MdlPageCount;
                 MdlPageCount--, MdlPages++, StartProto++)
            {
                DPRINT("MiDispatchFault: PageNumber %X\n", *MdlPages);

                if (StartProto == ReadPte)
                {
                    PageNumber = *MdlPages;
                    continue;
                }

                PfnClusterPage = MI_PFN_ELEMENT(*MdlPages);
                ASSERT(PfnClusterPage->u4.PteFrame == PageBlockPfn->u4.PteFrame);

                if (PfnClusterPage->u4.InPageError)
                {
                    ASSERT(Status != STATUS_SUCCESS);
                }

                if (PfnClusterPage->u3.e1.ReadInProgress)
                {
                    ASSERT(PfnClusterPage->u4.PteFrame != 0x1FFEDCB);
                    PfnClusterPage->u3.e1.ReadInProgress = 0;

                    if (!PfnClusterPage->u4.InPageError)
                        PfnClusterPage->u1.Event = NULL;
                }

                MiDereferencePfnAndDropLockCount(PfnClusterPage);
            }
        }

        if (Status != STATUS_SUCCESS)
        {
            DPRINT("MiDispatchFault: PageNumber %X, Status %X\n", PageNumber, Status);

            MiDereferencePfnAndDropLockCount(MI_PFN_ELEMENT(PageNumber));

            if (Status != 0x87303000)
            {
                MdlPages = PageBlock->MdlPages;

                if ((LONG)PageBlock->Mdl.ByteCount > 0)
                {
                    for (MdlPageCount = (((PageBlock->Mdl.ByteCount - 1) / PAGE_SIZE) + 1);
                         MdlPageCount;
                         MdlPageCount--, MdlPages++)
                    {
                        PfnClusterPage = MI_PFN_ELEMENT(*MdlPages);

                        if (!PfnClusterPage->u4.InPageError)
                            continue;

                        if (PfnClusterPage->u3.e2.ReferenceCount)
                            continue;

                        PfnClusterPage->u4.InPageError = 0;

                        if (PfnClusterPage->u3.e1.PageLocation != FreePageList)
                        {
                            DPRINT1("MiDispatchFault: FIXME\n");
                            ASSERT(FALSE);
                        }
                    }
                }
            }

            if (LockedProtoPfn)
            {
                ASSERT(SectionProto != NULL);
                ASSERT(LockedProtoPfn->u3.e2.ReferenceCount >= 1);
                MiDereferencePfnAndDropLockCount(LockedProtoPfn);
            }

            /* Unlock the PFN database */
            MiUnlockPfnDb(LockIrql, APC_LEVEL);

            if (SessionWs)
            {
                DPRINT1("MiDispatchFault: FIXME\n");
                ASSERT(FALSE);
            }

            MiFreeInPageSupportBlock(pageBlock);

            if (Status == 0x87303000)
                Status = STATUS_SUCCESS;
            else if (Status == 0xC7303001)
                Status = STATUS_NO_MEMORY;

            ASSERT(OldIrql == KeGetCurrentIrql());

            DPRINT("MiDispatchFault: return Status %X\n", Status);
            return Status;
        }

        ASSERT(PageBlockPfn->u4.InPageError == 0);

        if (!PageBlockPfn->u2.ShareCount)
            MiDropLockCount(PageBlockPfn);

        PageBlockPfn->u2.ShareCount++;
        PageBlockPfn->u3.e1.PageLocation = ActiveAndValid;

        /* Is MEMORY mapping */
        if (((ReadPte->u.Soft.Protection & MM_WRITECOMBINE) == MM_WRITECOMBINE) &&
            (ReadPte->u.Soft.Protection & MM_PROTECT_ACCESS))
        {
            CacheAttribute = MiPlatformCacheAttributes[0][MmWriteCombined];
        }
        else if ((ReadPte->u.Soft.Protection & MM_NOCACHE) == MM_NOCACHE)
        {
            CacheAttribute = MiPlatformCacheAttributes[0][MmNonCached];
        }
        else
        {
            CacheAttribute = MiCached;
        }

        if (PageBlockPfn->u3.e1.CacheAttribute != CacheAttribute)
        {
            DPRINT("MiDispatchFault: FIXME Flushing\n");
            ASSERT(FALSE);
            PageBlockPfn->u3.e1.CacheAttribute = CacheAttribute;
        }

        /* ReadPte is Transition PTE. Do it valid */
        ASSERT((ReadPte->u.Hard.Valid == 0) &&
               (ReadPte->u.Trans.Prototype == 0) &&
               (ReadPte->u.Trans.Transition == 1));

        MI_MAKE_HARDWARE_PTE(&TempPte,
                             ReadPte,
                             ReadPte->u.Trans.Protection,
                             ReadPte->u.Trans.PageFrameNumber);

        if (MI_IS_WRITE_ACCESS(FaultCode) && TempPte.u.Hard.Write)
            MI_MAKE_DIRTY_PAGE(&TempPte);

        MI_WRITE_VALID_PTE(ReadPte, TempPte);

        if (SectionProto)
        {
            ASSERT(Pte->u.Hard.Valid == 0);

            Status = MiCompleteProtoPteFault(MI_IS_WRITE_ACCESS(FaultCode),
                                             Address,
                                             Pte,
                                             SectionProto,
                                             LockIrql,
                                             &LockedProtoPfn);

            ASSERT(KeAreAllApcsDisabled() == TRUE);
        }
        else
        {
            DPRINT1("MiDispatchFault: FIXME MiAddValidPageToWorkingSet()\n");
            ASSERT(FALSE);
        }

        MiFreeInPageSupportBlock(pageBlock);

        if (Status == STATUS_SUCCESS)
            Status = STATUS_PAGE_FAULT_PAGING_FILE;
    }

    if (Status == 0xC7303001 || Status == 0x87303000)
        Status = STATUS_SUCCESS;

    ASSERT(KeAreAllApcsDisabled() == TRUE);

    if (SessionWs)
    {
        DPRINT1("MiDispatchFault: FIXME! SessionWs %X\n", SessionWs);
        ASSERT(FALSE);
    }

    if (LockedProtoPfn)
    {
        ASSERT(SectionProto != NULL);

        /* Lock the PFN database */
        LockIrql = MiLockPfnDb(APC_LEVEL);

        ASSERT(LockedProtoPfn->u3.e2.ReferenceCount >= 1);
        MiDereferencePfnAndDropLockCount(LockedProtoPfn);

        /* Unlock the PFN database */
        MiUnlockPfnDb(LockIrql, APC_LEVEL);
    }

    ASSERT(OldIrql == KeGetCurrentIrql());
    ASSERT(KeAreAllApcsDisabled() == TRUE);

    DPRINT("MiDispatchFault: return Status %X\n", Status);
    return Status;
}

#if (_MI_PAGING_LEVELS == 2)
static
NTSTATUS
FASTCALL
MiCheckPdeForSessionSpace(
    _In_ PVOID Address)
{
    MMPTE TempPde;
    PMMPDE Pde;
    PVOID SessionAddress;
    ULONG Index;

    /* Is this a session PTE? */
    if (MI_IS_SESSION_PTE(Address))
    {
        /* Make sure the PDE for session space is valid */
        Pde = MiAddressToPde(MmSessionSpace);
        if (!Pde->u.Hard.Valid)
        {
            /* This means there's no valid session, bail out */
            DbgPrint("MiCheckPdeForSessionSpace: No current session for PTE %p\n", Address);
            ASSERT(FALSE); // MiDbgBreakPointEx(); 
            return STATUS_ACCESS_VIOLATION;
        }

        /* Now get the session-specific page table for this address */
        SessionAddress = MiPteToAddress(Address);
        Pde = MiAddressToPte(Address);
        if (Pde->u.Hard.Valid)
            return STATUS_WAIT_1;

        /* It's not valid, so find it in the page table array */
        Index = ((ULONG_PTR)SessionAddress - (ULONG_PTR)MmSessionBase) >> 22;

        TempPde.u.Long = MmSessionSpace->PageTables[Index].u.Long;
        if (TempPde.u.Hard.Valid)
        {
            /* The copy is valid, so swap it in */
            InterlockedExchange((PLONG)Pde, TempPde.u.Long);
            return STATUS_WAIT_1;
        }

        /* We don't seem to have allocated a page table for this address yet? */
        DbgPrint("MiCheckPdeForSessionSpace: No Session PDE for PTE %p, %p\n", Pde->u.Long, SessionAddress);
        ASSERT(FALSE); // MiDbgBreakPointEx(); 
        return STATUS_ACCESS_VIOLATION;
    }

    /* Is the address also a session address? If not, we're done */
    if (!MI_IS_SESSION_ADDRESS(Address))
        return STATUS_SUCCESS;

    /* It is, so again get the PDE for session space */
    Pde = MiAddressToPde(MmSessionSpace);
    if (!Pde->u.Hard.Valid)
    {
        /* This means there's no valid session, bail out */
        DbgPrint("MiCheckPdeForSessionSpace: No current session for VA %p\n", Address);
        ASSERT(FALSE); // MiDbgBreakPointEx(); 
        return STATUS_ACCESS_VIOLATION;
    }

    /* Now get the PDE for the address itself */
    Pde = MiAddressToPde(Address);
    if (!Pde->u.Hard.Valid)
    {
        /* Do the swap, we should be good to go */
        Index = ((ULONG_PTR)Address - (ULONG_PTR)MmSessionBase) >> 22;
        Pde->u.Long = MmSessionSpace->PageTables[Index].u.Long;
        if (Pde->u.Hard.Valid)
            return STATUS_WAIT_1;

        /* We had not allocated a page table for this session address yet, fail! */
        DbgPrint("MiCheckPdeForSessionSpace: No Session PDE for VA %p, %p\n", Pde->u.Long, Address);
        ASSERT(FALSE); // MiDbgBreakPointEx(); 
        return STATUS_ACCESS_VIOLATION;
    }

    /* It's valid, so there's nothing to do */
    return STATUS_SUCCESS;
}

NTSTATUS
FASTCALL
MiCheckPdeForPagedPool(
    _In_ PVOID Address)
{
    PMMPDE Pde;
    NTSTATUS Status = STATUS_SUCCESS;

    /* Check session PDE */
    if (MI_IS_SESSION_ADDRESS(Address))
        return MiCheckPdeForSessionSpace(Address);

    if (MI_IS_SESSION_PTE(Address))
        return MiCheckPdeForSessionSpace(Address);

    /* Check if this is a fault while trying to access the page table itself */
    if (MI_IS_SYSTEM_PAGE_TABLE_ADDRESS(Address))
    {
        /* Send a hint to the page fault handler that this is only a valid fault
           if we already detected this was access within the page table range.
        */
        Pde = (PMMPDE)MiAddressToPte(Address);
        Status = STATUS_WAIT_1;
    }
    else if (Address < MmSystemRangeStart)
    {
        /* This is totally illegal */
        DPRINT1("MiCheckPdeForPagedPool: STATUS_ACCESS_VIOLATION. Address %p\n", Address);
        //ASSERT(FALSE); // MiDbgBreakPointEx(); 
        return STATUS_ACCESS_VIOLATION;
    }
    else
    {
        /* Get the PDE for the address */
        Pde = MiAddressToPde(Address);
    }

    /* Check if it's not valid */
    if (!Pde->u.Hard.Valid)
        /* Copy it from our double-mapped system page directory */
        InterlockedExchangePte(Pde, MmSystemPagePtes[MiGetPdeOffset(Pde)].u.Long);

    return Status;
}
#else
  #error FIXME
#endif

NTSTATUS
NTAPI
MmAccessFault(
    _In_ ULONG FaultCode,
    _In_ PVOID Address,
    _In_ KPROCESSOR_MODE Mode,
    _In_ PVOID TrapInformation)
{
    PMMPDE Pde = MiAddressToPde(Address);
    PMMPTE Pte = MiAddressToPte(Address);
    PMMPTE SectionProto = NULL;
    PETHREAD CurrentThread;
    PEPROCESS CurrentProcess;
    PEPROCESS Process;
    PMMSUPPORT WorkingSet;
    PMMVAD Vad = NULL;
    PMMPFN Pfn;
    MMPTE TempPte;
    PFN_NUMBER PageFrameIndex;
    ULONG ProtectionCode;
    ULONG PagesCount;
    ULONG Color;
    BOOLEAN IsSessionAddress;
    BOOLEAN IsForceIrpComplete = FALSE;
    KIRQL OldIrql;
    KIRQL PfnLockIrql;
    KIRQL WsLockIrql = MM_NOIRQL;
    NTSTATUS Status;

    DPRINT("MmAccessFault: %X, %p, %X, %p\n", FaultCode, Address, Mode, TrapInformation);

    OldIrql = KeGetCurrentIrql();

    /* Check for page fault on high IRQL */
    if (OldIrql > APC_LEVEL)
    {
      #if (_MI_PAGING_LEVELS < 3)
        /* Could be a page table for paged pool, which we'll allow */
        if (MI_IS_SYSTEM_PAGE_TABLE_ADDRESS(Address))
            MiSynchronizeSystemPde((PMMPDE)Pte);

        DPRINT("MiCheckPdeForPagedPool(Address %p)\n", Address);
        MiCheckPdeForPagedPool(Address);
      #endif

        /* Check if any of the top-level pages are invalid */
        if (!Pde->u.Hard.Valid || !Pte->u.Hard.Valid)
        {
            /* This fault is not valid, print out some debugging help */
            DbgPrint("MM:***PAGE FAULT AT IRQL > 1  Va %p, IRQL %lx\n", Address, OldIrql);

            if (TrapInformation)
            {
                PKTRAP_FRAME TrapFrame = TrapInformation;
                DbgPrint("MM:***EIP %p, EFL %p\n", TrapFrame->Eip, TrapFrame->EFlags);
                DbgPrint("MM:***EAX %p, ECX %p EDX %p\n", TrapFrame->Eax, TrapFrame->Ecx, TrapFrame->Edx);
                DbgPrint("MM:***EBX %p, ESI %p EDI %p\n", TrapFrame->Ebx, TrapFrame->Esi, TrapFrame->Edi);
            }

            /* Tell the trap handler to fail */
            DPRINT1("MmAccessFault: return %X\n", (STATUS_IN_PAGE_ERROR | 0x10000000));
            DbgBreakPoint();//ASSERT(FALSE);
            return (STATUS_IN_PAGE_ERROR | 0x10000000);
        }

        /* Not yet implemented in ReactOS */
        ASSERT(MI_IS_PAGE_LARGE(Pde) == FALSE);
        ASSERT((!MI_IS_NOT_PRESENT_FAULT(FaultCode) && MI_IS_PAGE_COPY_ON_WRITE(Pte)) == FALSE);

        /* Check if this was a write */
        if (MI_IS_WRITE_ACCESS(FaultCode))
        {
            /* Was it to a read-only page? */
            Pfn = MI_PFN_ELEMENT(Pte->u.Hard.PageFrameNumber);

            if (!(Pte->u.Long & PTE_READWRITE) &&
                !(Pfn->OriginalPte.u.Soft.Protection & MM_READWRITE))
            {
                /* Crash with distinguished bugcheck code */
                KeBugCheckEx(ATTEMPTED_WRITE_TO_READONLY_MEMORY,
                             (ULONG_PTR)Address,
                             Pte->u.Long,
                             (ULONG_PTR)TrapInformation,
                             10);
            }
        }

      #if !defined(ONE_CPU)
        if (MI_IS_WRITE_ACCESS(FaultCode) && !Pte->u.Hard.Dirty)
            MiSetDirtyBit(Address, Pte, FALSE);
      #endif

        /* Nothing is actually wrong */
        DPRINT("Fault at IRQL %u is ok (%p)\n", OldIrql, Address);
        return STATUS_SUCCESS;
    }

    /* Check for kernel fault address */
    if (Address >= MmSystemRangeStart)
    {
        /* Bail out, if the fault came from user mode */
        if (Mode == UserMode)
        {
            DPRINT1("MmAccessFault: return STATUS_ACCESS_VIOLATION\n");
            return STATUS_ACCESS_VIOLATION;
        }

        /* Check if the higher page table entries are invalid */
        if (!Pde->u.Hard.Valid)
        {
            DPRINT("MiCheckPdeForPagedPool(Address %p)\n", Address);
            MiCheckPdeForPagedPool(Address);

            if (!Pde->u.Hard.Valid)
            {
                if (KeInvalidAccessAllowed(TrapInformation))
                {
                    DPRINT1("MmAccessFault: return STATUS_ACCESS_VIOLATION\n");
                    return STATUS_ACCESS_VIOLATION;
                }

                /* PDE (still) not valid, kill the system */
                KeBugCheckEx(PAGE_FAULT_IN_NONPAGED_AREA,
                             (ULONG_PTR)Address,
                             FaultCode,
                             (ULONG_PTR)TrapInformation,
                             2);
            }
        }
        else if (MI_IS_PAGE_LARGE(Pde))
        {
            DPRINT1("MmAccessFault: FIXME! MI_IS_PAGE_LARGE(Pde) %p\n", Pde);
            ASSERT(FALSE);//DbgBreakPoint();
            return STATUS_SUCCESS;
        }

        /* Session faults? */
        IsSessionAddress = MI_IS_SESSION_ADDRESS(Address);

        /* The PDE is valid, so read the PTE */
        TempPte = *Pte;
        if (TempPte.u.Hard.Valid)
        {
            /* Check if this was system space or session space */
            if (!IsSessionAddress)
            {
                /* Check if the PTE is still valid under PFN lock */
                PfnLockIrql = MiLockPfnDb(APC_LEVEL);
                TempPte = *Pte;

                if (TempPte.u.Hard.Valid)
                {
                    /* Check if this was a write */
                    if (MI_IS_WRITE_ACCESS(FaultCode))
                    {
                        /* Was it to a read-only page? */
                        Pfn = MI_PFN_ELEMENT(TempPte.u.Hard.PageFrameNumber);

                        if (!(TempPte.u.Long & PTE_READWRITE) &&
                            !(Pfn->OriginalPte.u.Soft.Protection & MM_READWRITE))
                        {
                            /* Crash with distinguished bugcheck code */
                            KeBugCheckEx(ATTEMPTED_WRITE_TO_READONLY_MEMORY,
                                         (ULONG_PTR)Address,
                                         (ULONG_PTR)TempPte.u.Long,
                                         (ULONG_PTR)TrapInformation,
                                         11);
                        }
                    }

                  #if !defined(ONE_CPU)
                    if (MI_IS_WRITE_ACCESS(FaultCode) && !Pte->u.Hard.Dirty)
                        MiSetDirtyBit(Address, Pte, TRUE);
                  #endif
                }

                /* Release PFN lock and return all good */
                MiUnlockPfnDb(PfnLockIrql, APC_LEVEL);
                DPRINT("MmAccessFault: return STATUS_SUCCESS\n");
                return STATUS_SUCCESS;
            }
        }

        /* Check if this was a session PTE that needs to remap the session PDE */
        if (MI_IS_SESSION_PTE(Address))
        {
            Status = MiCheckPdeForSessionSpace(Address);
            if (!NT_SUCCESS (Status))
            {
                if (KeInvalidAccessAllowed(TrapInformation))
                {
                    DPRINT("MmAccessFault: return STATUS_ACCESS_VIOLATION\n");
                    return STATUS_ACCESS_VIOLATION;
                }

                DPRINT1("KeBugCheckEx()\n");
                DbgBreakPoint();//ASSERT(FALSE);
            }
        }

        /* Check for a fault on the page table or hyperspace */
        if (MI_IS_PAGE_TABLE_OR_HYPER_ADDRESS(Address))
        {
            DPRINT("MmAccessFault: call MiCheckPdeForPagedPool(%p)\n", Address);

            if (MiCheckPdeForPagedPool(Address) == STATUS_WAIT_1)
            {
                DPRINT("MmAccessFault: return STATUS_SUCCESS\n");
                return STATUS_SUCCESS;
            }

            goto UserFault;
        }

        /* Get the current thread */
        CurrentThread = PsGetCurrentThread();

        /* What kind of address is this */
        if (!IsSessionAddress)
        {
            /* Use the system working set */
            WorkingSet = &MmSystemCacheWs;
            Process = NULL;
        }
        else
        {
            /* Use the session process and working set */
            WorkingSet = &MmSessionSpace->GlobalVirtualAddress->Vm;
            Process = HYDRA_PROCESS;
        }

        /* Acquire the working set lock */
        KeRaiseIrql(APC_LEVEL, &WsLockIrql);
        MiLockWorkingSet(CurrentThread, WorkingSet);

        /* Re-read PTE now that we own the lock */
        TempPte = *Pte;
        if (TempPte.u.Hard.Valid)
        {
            if (MI_IS_WRITE_ACCESS(FaultCode) &&
                !(TempPte.u.Long & PTE_READWRITE) &&
                !TempPte.u.Hard.CopyOnWrite)
            {
                DPRINT1("MmAccessFault: FIXME\n");
                ASSERT(FALSE);//DbgBreakPoint();
            }

            if (IsSessionAddress &&
                MI_IS_WRITE_ACCESS(FaultCode) && !TempPte.u.Hard.Write)
            {
                DPRINT1("MmAccessFault: FIXME\n");
                ASSERT(FALSE);//DbgBreakPoint();
            }
            else
            {
              #if !defined(ONE_CPU)
                PfnLockIrql = MiLockPfnDb(APC_LEVEL);

                if (MI_IS_WRITE_ACCESS(FaultCode) && !Pte->u.Hard.Dirty)
                    MiSetDirtyBit(Address, Pte, TRUE);

                MiUnlockPfnDb(PfnLockIrql, APC_LEVEL);
              #endif
            }

            MiUnlockWorkingSet(CurrentThread, WorkingSet);
            ASSERT(WsLockIrql != MM_NOIRQL);
            KeLowerIrql(WsLockIrql);

            DPRINT("MmAccessFault: return STATUS_SUCCESS\n");
            return STATUS_SUCCESS;
        }

        /* Check one kind of prototype PTE */
        if (TempPte.u.Soft.Prototype)
        {
            /* Make sure protected pool is on, and that this is a pool address */
            if (MmProtectFreedNonPagedPool &&
                ((Address >= MmNonPagedPoolStart && Address < (PVOID)((ULONG_PTR)MmNonPagedPoolStart + MmSizeOfNonPagedPoolInBytes)) ||
                 (Address >= MmNonPagedPoolExpansionStart && Address < MmNonPagedPoolEnd)))
            {
                if (KeInvalidAccessAllowed(TrapInformation))
                {
                    DPRINT1("MmAccessFault: return STATUS_ACCESS_VIOLATION\n");
                    ASSERT(FALSE); // DbgBreakPoint();
                    return STATUS_ACCESS_VIOLATION;
                }

                /* Bad boy, bad boy, whatcha gonna do, whatcha gonna do when ARM3 comes for you! */
                DPRINT1("KeBugCheckEx()\n");ASSERT(FALSE);//DbgBreakPoint();
                KeBugCheckEx(DRIVER_CAUGHT_MODIFYING_FREED_POOL, (ULONG_PTR) Address, FaultCode, Mode, 4);
            }

            /* Get the prototype PTE! */
            SectionProto = MiGetProtoPtr(&TempPte);

            /* Do we need to locate the prototype PTE in session space? */
            if (IsSessionAddress &&
                TempPte.u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED)
            {
                /* Yep, go find it as well as the VAD for it */
                SectionProto = MiCheckVirtualAddress(Address, &ProtectionCode, &Vad);
                if (!SectionProto)
                {
                    DPRINT1("MmAccessFault: FIXME!\n"); ASSERT(FALSE);//DbgBreakPoint();
                    return (STATUS_IN_PAGE_ERROR | 0x10000000);
                }
            }
        }
        else if (!TempPte.u.Soft.Transition && !TempPte.u.Soft.Protection)
        {
            if (KeInvalidAccessAllowed(TrapInformation))
            {
                DPRINT1("MmAccessFault: return STATUS_ACCESS_VIOLATION\n");
                return STATUS_ACCESS_VIOLATION;
            }

            DPRINT1("KeBugCheckEx()\n");
            ASSERT(FALSE);
            //KeBugCheckEx();
        }
        else if (TempPte.u.Soft.Protection == MM_NOACCESS)
        {
            DPRINT1("MmAccessFault: FIXME! Protection == MM_NOACCESS\n");
            ASSERT(FALSE);//DbgBreakPoint();
        }

        if (MI_IS_WRITE_ACCESS(FaultCode) &&
            !SectionProto &&
            !IsSessionAddress &&
            !TempPte.u.Hard.Valid)
        {
            ULONG protectionCode;

            /* Get the protection code */
            if (TempPte.u.Soft.Transition)
                protectionCode = (ULONG)TempPte.u.Trans.Protection;
            else
                protectionCode = (ULONG)TempPte.u.Soft.Protection;
                
            if (!(protectionCode & MM_READWRITE))
            {
                /* Bugcheck the system! */
                KeBugCheckEx(ATTEMPTED_WRITE_TO_READONLY_MEMORY,
                             (ULONG_PTR)Address,
                             TempPte.u.Long,
                             (ULONG_PTR)TrapInformation,
                             14);
            }
        }

        /* Now do the real fault handling */
        Status = MiDispatchFault(FaultCode,
                                 Address,
                                 Pte,
                                 SectionProto,
                                 FALSE,
                                 Process,
                                 TrapInformation,
                                 NULL);

        /* Release the working set */
        ASSERT(KeAreAllApcsDisabled() == TRUE);

        if (WorkingSet->Flags.GrowWsleHash)
            MiGrowWsleHash(WorkingSet);

        MiUnlockWorkingSet(CurrentThread, WorkingSet);
        ASSERT(WsLockIrql != MM_NOIRQL);
        KeLowerIrql(WsLockIrql);

        if (!(WorkingSet->PageFaultCount & 0xFFF) && (MmAvailablePages < 1024))
        {
            if (!PsGetCurrentThread()->MemoryMaker)
                KeDelayExecutionThread(KernelMode, FALSE, &MmShortTime);
        }

        /* We are done! */
        goto Exit1;
    }

    /* This is a user fault */
UserFault:

    CurrentThread = PsGetCurrentThread();
    CurrentProcess = (PEPROCESS)CurrentThread->Tcb.ApcState.Process;

    if (MiDelayPageFaults ||
        (MmAvailablePages < 0x100 && CurrentProcess->ModifiedPageCount > 0x10))
    {
        PLARGE_INTEGER Interval;

        if (CurrentProcess->Pcb.BasePriority < 9)
            Interval = &MmHalfSecond;
        else
            Interval = &Mm30Milliseconds;

        KeDelayExecutionThread(KernelMode, FALSE, Interval);
        CurrentProcess->ModifiedPageCount = 0;
    }

    /* Lock the working set */
    MiLockProcessWorkingSet(CurrentProcess, CurrentThread);

    /* Check if the PDE is invalid */
    if (!Pde->u.Hard.Valid)
    {
        /* Right now, we only handle scenarios where the PDE is totally empty */
        if (!Pde->u.Long)
        {
            ULONG protectionCode;

            MiCheckVirtualAddress(Address, &protectionCode, &Vad);

            if (protectionCode == MM_NOACCESS)
            {
                Status = STATUS_ACCESS_VIOLATION;

                DPRINT1("MmAccessFault: MiCheckPdeForPagedPool(%p)\n", Address);
                MiCheckPdeForPagedPool(Address);

                if (Pde->u.Hard.Valid == 1)
                    Status = STATUS_SUCCESS;

                if (Status == STATUS_ACCESS_VIOLATION)
                {
                    DPRINT1("MmAccessFault: STATUS_ACCESS_VIOLATION\n");
                }

                goto Exit2;
            }

            MI_WRITE_INVALID_PTE(Pde, DemandZeroPde);
        }

        /* Dispatch the fault */
        Status = MiDispatchFault(1,
                                 Pte,
                                 Pde,
                                 NULL,
                                 FALSE,
                                 CurrentProcess,
                                 TrapInformation,
                                 NULL);

        ASSERT(KeAreAllApcsDisabled() == TRUE);

        if (!Pde->u.Hard.Valid)
            goto Exit3;

      #if !defined(ONE_CPU)
        if (Pde->u.Hard.Dirty)
            MiSetDirtyBit(Pte, Pde, FALSE);
      #endif
    }
    else if (MI_IS_PAGE_LARGE(Pde))
    {
        DPRINT1("MmAccessFault: FIXME\n");
        ASSERT(FALSE);
        Status = STATUS_SUCCESS;
        goto Exit3;
    }

    TempPte = *Pte;

    if (TempPte.u.Hard.Valid)
    {
        if (MI_IS_PAGE_LARGE(&TempPte))
        {
            DPRINT1("KeBugCheckEx()\n");
            ASSERT(FALSE);//DbgBreakPoint();
            KeBugCheckEx(PAGE_FAULT_IN_NONPAGED_AREA, (ULONG_PTR)Address, FaultCode, (ULONG_PTR)TrapInformation, 8);
        }

        Status = STATUS_SUCCESS;

        if (!TempPte.u.Hard.Owner && Address <= MmHighestUserAddress)
        {
            DPRINT1("MmAccessFault: STATUS_ACCESS_VIOLATION\n");
            ASSERT(FALSE);
            Status = STATUS_ACCESS_VIOLATION;
            goto Exit2;
        }

        if (MI_IS_WRITE_ACCESS(FaultCode) && TempPte.u.Hard.CopyOnWrite)
        {
            MiCopyOnWrite(Address, Pte);
            Status = STATUS_PAGE_FAULT_COPY_ON_WRITE;
            goto Exit2;
        }

        if (MI_IS_WRITE_ACCESS(FaultCode) && !TempPte.u.Hard.Write)
        {
            DPRINT("MmAccessFault: STATUS_ACCESS_VIOLATION\n");
            Status = STATUS_ACCESS_VIOLATION;
            goto Exit2;
        }

        if (CurrentProcess->AweInfo)
        {
            DPRINT1("MmAccessFault: FIXME\n");
            ASSERT(FALSE);
            goto Exit2;
        }

      #if !defined(ONE_CPU)
        if (MI_IS_WRITE_ACCESS(FaultCode) && !TempPte.u.Hard.Dirty)
        {
            if (!MiSetDirtyBit(Address, Pte, FALSE))
            {
                DPRINT1("MmAccessFault: STATUS_ACCESS_VIOLATION\n");
                ASSERT(FALSE);
                Status = STATUS_ACCESS_VIOLATION;
            }
        }
      #endif

        goto Exit2;
    }

    if (TempPte.u.Long == (MM_READWRITE << MM_PTE_SOFTWARE_PROTECTION_BITS))
    {
        /* Resolve the fault */
        MiResolveDemandZeroFault(Address, Pte, CurrentProcess, MM_NOIRQL);

        /* Return the status */
        DPRINT("MmAccessFault: return STATUS_PAGE_FAULT_DEMAND_ZERO\n");
        Status = STATUS_PAGE_FAULT_DEMAND_ZERO;
        goto Exit3;
    }

    Vad = NULL;

    if (!TempPte.u.Long)
    {
        /* Check if this address range belongs to a valid allocation (VAD) */
        SectionProto = MiCheckVirtualAddress(Address, &ProtectionCode, &Vad);

        if (ProtectionCode == MM_NOACCESS)
        {
            Status = STATUS_ACCESS_VIOLATION;

            /* Could be a page table for paged pool */
            MiCheckPdeForPagedPool(Address);

            /* Has the code above changed anything -- is this now a valid PTE? */
            if (Pte->u.Hard.Valid)
                Status = STATUS_SUCCESS;

            if (Status == STATUS_ACCESS_VIOLATION)
            {
                DPRINT1("MmAccessFault: STATUS_ACCESS_VIOLATION\n");
            }

            goto Exit2;
        }

        if ((ProtectionCode & MM_PROTECT_SPECIAL) == MM_GUARDPAGE)
        {
            if (KeInvalidAccessAllowed(TrapInformation))
            {
                DPRINT("MmAccessFault: STATUS_ACCESS_VIOLATION\n");
                Status = STATUS_ACCESS_VIOLATION;
                goto Exit2;
            }
        }

        /* Check if this is a real user-mode address or actually a kernel-mode page table for a user mode address */
        if (Address <= MM_HIGHEST_USER_ADDRESS)
            /* Add an additional page table reference */
            MiIncrementPageTableReferences(Address);

        /* Is this a guard page? */
        if ((ProtectionCode & MM_PROTECT_SPECIAL) == MM_GUARDPAGE)
        {
            /* Remove the bit */
            Pte->u.Soft.Protection = (ProtectionCode & ~0x10);

            if (SectionProto)
            {
                Pte->u.Soft.PageFileHigh = MI_PTE_LOOKUP_NEEDED;
                Pte->u.Soft.Prototype = 1;
            }

            if (CurrentThread->ApcNeeded && !CurrentThread->ActiveFaultCount)
            {
                CurrentThread->ApcNeeded = 0;
                IsForceIrpComplete = TRUE;
            }

            /* Drop the working set lock */
            MiUnlockProcessWorkingSet(CurrentProcess, CurrentThread);
            ASSERT(KeGetCurrentIrql() == OldIrql);

            if (IsForceIrpComplete)
            {
                ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
                DPRINT1("MmAccessFault: FIXME IoRetryIrpCompletions()\n");
                ASSERT(FALSE);
            }

            /* Handle stack expansion */
            Status = MiCheckForUserStackOverflow(Address);
            return Status;
        }

        /* Did we get a prototype PTE back? */
        if (!SectionProto)
        {
            MMWSLE TempWsle;

            /* Is this PTE actually part of the PDE-PTE self-mapping directory? */
            if (Pde == MiAddressToPde(PTE_BASE))
            {
                /* Then it's really a demand-zero PDE (on behalf of user-mode) */
                MI_WRITE_INVALID_PTE(Pte, DemandZeroPde);
                DPRINT("MmAccessFault: Pte->u.Long %X\n", Pte->u.Long);
            }
            else
            {
                /* No, create a new PTE. First, write the protection */
                TempPte.u.Soft.Protection = ProtectionCode;
                MI_WRITE_INVALID_PTE(Pte, TempPte);
                DPRINT("MmAccessFault: Pte->u.Long %X\n", Pte->u.Long);
            }

            /* Lock the PFN database since we're going to grab a page */
            PfnLockIrql = MiLockPfnDb(APC_LEVEL);

            /* Make sure we have enough pages */
            if (MmAvailablePages < 0x80 && MiEnsureAvailablePageOrWait(CurrentProcess, PfnLockIrql))
            {
                MiUnlockPfnDb(PfnLockIrql, APC_LEVEL);
                DPRINT("MmAccessFault: return STATUS_PAGE_FAULT_DEMAND_ZERO\n");
                Status = STATUS_PAGE_FAULT_DEMAND_ZERO;
                goto Exit3;
            }

            /* Try to get a zero page */
            MI_SET_USAGE(MI_USAGE_PEB_TEB);
            MI_SET_PROCESS2(CurrentProcess->ImageFileName);

            Color = MI_GET_NEXT_PROCESS_COLOR(CurrentProcess);

            PageFrameIndex = MiRemoveZeroPageSafe(Color);
            if (!PageFrameIndex)
            {
                /* Grab a page out of there. Later we should grab a colored zero page */
                PageFrameIndex = MiRemoveAnyPage(Color);
                ASSERT(PageFrameIndex);

                /* Release the lock since we need to do some zeroing */
                MiUnlockPfnDb(PfnLockIrql, APC_LEVEL);

                /* Zero out the page, since it's for user-mode */
                MiZeroPfn(PageFrameIndex);

                /* Grab the lock again so we can initialize the PFN entry */
                PfnLockIrql = MiLockPfnDb(APC_LEVEL);
            }

            /* Initialize the PFN entry now */
            Pfn = MI_PFN_ELEMENT(PageFrameIndex);
            MiInitializePfn(PageFrameIndex, Pte, 1);

            /* And we're done with the lock */
            MiUnlockPfnDb(PfnLockIrql, APC_LEVEL);

            /* Increment the count of pages in the process */
            CurrentProcess->NumberOfPrivatePages++;

            /* One more demand-zero fault */
            InterlockedIncrement(&KeGetCurrentPrcb()->MmDemandZeroCount);

            /* Fault on user PDE, or fault on user PTE? */
            if (Pte <= MiHighestUserPte)
                /* User fault, build a user PTE */
                MI_MAKE_HARDWARE_PTE_USER(&TempPte, Pte, Pte->u.Soft.Protection, PageFrameIndex);
            else
                /* This is a user-mode PDE, create a kernel PTE for it */
                MI_MAKE_HARDWARE_PTE(&TempPte, Pte, Pte->u.Soft.Protection, PageFrameIndex);

            /* Write the dirty bit for writeable pages */
            if (TempPte.u.Long & PTE_READWRITE)
                MI_MAKE_DIRTY_PAGE(&TempPte);

            /* And now write down the PTE, making the address valid */
            MI_WRITE_VALID_PTE(Pte, TempPte);
            ASSERT(Pfn->u1.Event == NULL);

            TempWsle.u1.Long = 0;

            if (!MiAllocateWsle(&CurrentProcess->Vm, Pte, Pfn, TempWsle))
            {
                DPRINT1("MmAccessFault: FIXME MiTrimPte()\n");
                ASSERT(Pfn->u3.e1.PrototypePte == 0);
                ASSERT(FALSE);
            }

            DPRINT("MmAccessFault: return STATUS_PAGE_FAULT_DEMAND_ZERO\n");
            Status = STATUS_PAGE_FAULT_DEMAND_ZERO;
            goto Exit3;
        }

        if (ProtectionCode == 0x100)
        {
            MI_MAKE_PROTOTYPE_PTE(&TempPte, SectionProto);
        }
        else
        {
            /* Write the prototype PTE */
            TempPte = PrototypePte;
            TempPte.u.Soft.Protection = ProtectionCode;
        }

        /* Write the prototype PTE */
        ASSERT(TempPte.u.Long != 0);
        MI_WRITE_INVALID_PTE(Pte, TempPte);
    }
    else
    {
        /* Get the protection code and check if this is a proto PTE */
        ProtectionCode = (ULONG)TempPte.u.Soft.Protection;

        if (TempPte.u.Soft.Prototype)
        {
            /* Do we need to go find the real PTE? */
            if (TempPte.u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED)
            {
                /* Get the prototype pte and VAD for it */
                SectionProto = MiCheckVirtualAddress(Address, &ProtectionCode, &Vad);
                if (!SectionProto)
                {
                    DPRINT1("MmAccessFault: STATUS_ACCESS_VIOLATION\n");
                    ASSERT(FALSE);
                    Status = STATUS_ACCESS_VIOLATION;
                    goto Exit3;
                }
            }
            else
            {
                /* Get the prototype PTE! */
                SectionProto = MiGetProtoPtr(&TempPte);

                /* Is it read-only */
                if (TempPte.u.Proto.ReadOnly)
                {
                    /* Set read-only code */
                    ProtectionCode = MM_READONLY;
                }
                else
                {
                    /* Set unknown protection */
                    ProtectionCode = 0x100;

                    if (CurrentProcess->CloneRoot)
                    {
                        DPRINT1("MmAccessFault: CurrentProcess->CloneRoot %X\n", CurrentProcess->CloneRoot);
                        ASSERT(CurrentProcess->CloneRoot == NULL);
                    }
                }
            }
        }
    }

    /* Do we have a valid protection code? */
    if (ProtectionCode != 0x100)
    {
        /* Run a software access check first, including to detect guard pages */
        Status = MiAccessCheck(Pte,
                               MI_IS_WRITE_ACCESS(FaultCode),
                               Mode,
                               ProtectionCode,
                               TrapInformation,
                               FALSE);

        if (Status != STATUS_SUCCESS)
        {
            if (Status == STATUS_ACCESS_VIOLATION)
            {
                DPRINT1("MmAccessFault: %X, %p, %X, %p\n", FaultCode, Address, Mode, TrapInformation);
                DPRINT1("MmAccessFault: %p [%p], %p [%p]\n", Pde, Pde->u.Long, Pte, TempPte.u.Long);
                DPRINT1("MmAccessFault: STATUS_ACCESS_VIOLATION\n");
                ASSERT(FALSE);
            }

            /* Not supported */
            if (CurrentThread->ApcNeeded && !CurrentThread->ActiveFaultCount)
            {
                DPRINT1("MmAccessFault: FIXME\n");
                ASSERT(FALSE);
            }

            /* Drop the working set lock */
            MiUnlockProcessWorkingSet(CurrentProcess, CurrentThread);
            ASSERT(KeGetCurrentIrql() == OldIrql);

            /* Did we hit a guard page? */
            if (Status == STATUS_GUARD_PAGE_VIOLATION)
            {
                /* Handle stack expansion */
                Status = MiCheckForUserStackOverflow(Address);
                DPRINT("MmAccessFault: return %X\n", Status);
                return Status;
            }

            /* Otherwise, fail back to the caller directly */
            DPRINT("MmAccessFault: return %X\n", Status);
            return Status;
        }
    }

    Status = MiDispatchFault(FaultCode,
                             Address,
                             Pte,
                             SectionProto,
                             FALSE,
                             CurrentProcess,
                             TrapInformation,
                             Vad);
Exit3:

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    if (CurrentProcess->Vm.Flags.GrowWsleHash)
        MiGrowWsleHash(&CurrentProcess->Vm);

Exit2:

    PagesCount = (CurrentProcess->Vm.WorkingSetSize - CurrentProcess->Vm.MinimumWorkingSetSize);

    if (CurrentThread->ApcNeeded)
    {
        ASSERT(CurrentThread->ApcNeeded == 0);
    }

    MiUnlockProcessWorkingSet(CurrentProcess, CurrentThread);

    ASSERT(KeGetCurrentIrql() == OldIrql);

    if (MmAvailablePages < 0x400 &&
        PagesCount > 0x64 &&
        KeGetCurrentThread()->Priority >= 0x10)
    {
        DPRINT1("MmAccessFault: FIXME\n");
        ASSERT(FALSE);
    }

Exit1:

    if (Status == STATUS_SUCCESS)
        return Status;

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MmAccessFault: Status %X\n", Status);

        if (Status == STATUS_INSUFFICIENT_RESOURCES ||
            Status == STATUS_WORKING_SET_QUOTA ||
            Status == STATUS_NO_MEMORY)
        {
            DPRINT("MmAccessFault: Status: %X\n", Status);
            KeDelayExecutionThread(KernelMode, FALSE, &MmShortTime);
            Status = STATUS_SUCCESS;
        }
    }

    if (Status != STATUS_SUCCESS)
    {
        DPRINT("MmAccessFault: fixeme NotifyRoutine. Status %X\n", Status);
    }

    DPRINT("MmAccessFault: return Status %X\n", Status);
    return Status;
}

/* EOF */
