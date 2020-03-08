/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            ntoskrnl/mm/ARM3/pagfault.c
 * PURPOSE:         ARM Memory Manager Page Fault Handling
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
//#define NDEBUG
#include <debug.h>

#define MODULE_INVOLVED_IN_ARM3
#include <mm/ARM3/miarm.h>

/* GLOBALS ********************************************************************/

#define HYDRA_PROCESS (PEPROCESS)1
#if MI_TRACE_PFNS
BOOLEAN UserPdeFault = FALSE;
#endif

ULONG MmDataClusterSize;
ULONG MmCodeClusterSize;

ULONG MmInPageSupportMinimum = 4;

/* PRIVATE FUNCTIONS **********************************************************/

static
NTSTATUS
NTAPI
MiCheckForUserStackOverflow(IN PVOID Address,
                            IN PVOID TrapInformation)
{
    PETHREAD CurrentThread = PsGetCurrentThread();
    PTEB Teb = CurrentThread->Tcb.Teb;
    PVOID StackBase, DeallocationStack, NextStackAddress;
    SIZE_T GuaranteedSize;
    NTSTATUS Status;

    /* Do we own the address space lock? */
    if (CurrentThread->AddressSpaceOwner == 1)
    {
        /* This isn't valid */
        DPRINT1("Process owns address space lock\n");
        ASSERT(KeAreAllApcsDisabled() == TRUE);
        return STATUS_GUARD_PAGE_VIOLATION;
    }

    /* Are we attached? */
    if (KeIsAttachedProcess())
    {
        /* This isn't valid */
        DPRINT1("Process is attached\n");
        return STATUS_GUARD_PAGE_VIOLATION;
    }

    /* Read the current settings */
    StackBase = Teb->NtTib.StackBase;
    DeallocationStack = Teb->DeallocationStack;
    GuaranteedSize = Teb->GuaranteedStackBytes;
    DPRINT("Handling guard page fault with Stacks Addresses 0x%p and 0x%p, guarantee: %lx\n",
            StackBase, DeallocationStack, GuaranteedSize);

    /* Guarantees make this code harder, for now, assume there aren't any */
    ASSERT(GuaranteedSize == 0);

    /* So allocate only the minimum guard page size */
    GuaranteedSize = PAGE_SIZE;

    /* Does this faulting stack address actually exist in the stack? */
    if ((Address >= StackBase) || (Address < DeallocationStack))
    {
        /* That's odd... */
        DPRINT1("Faulting address outside of stack bounds. Address=%p, StackBase=%p, DeallocationStack=%p\n",
                Address, StackBase, DeallocationStack);
        return STATUS_GUARD_PAGE_VIOLATION;
    }

    /* This is where the stack will start now */
    NextStackAddress = (PVOID)((ULONG_PTR)PAGE_ALIGN(Address) - GuaranteedSize);

    /* Do we have at least one page between here and the end of the stack? */
    if (((ULONG_PTR)NextStackAddress - PAGE_SIZE) <= (ULONG_PTR)DeallocationStack)
    {
        /* We don't -- Trying to make this guard page valid now */
        DPRINT1("Close to our death...\n");

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
        }
        else
        {
            DPRINT1("Failed to allocate memory\n");
        }

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
                                     PAGE_READWRITE | PAGE_GUARD);
    if ((NT_SUCCESS(Status) || (Status == STATUS_ALREADY_COMMITTED)))
    {
        /* We did it! */
        DPRINT("Guard page handled successfully for %p\n", Address);
        return STATUS_PAGE_FAULT_GUARD_PAGE;
    }

    /* Fail, we couldn't move the guard page */
    DPRINT1("Guard page failure: %lx\n", Status);
    ASSERT(FALSE);
    return STATUS_STACK_OVERFLOW;
}

FORCEINLINE
BOOLEAN
MiIsAccessAllowed(
    _In_ ULONG ProtectionMask,
    _In_ BOOLEAN Write,
    _In_ BOOLEAN Execute)
{
    #define _BYTE_MASK(Bit0, Bit1, Bit2, Bit3, Bit4, Bit5, Bit6, Bit7) \
        (Bit0) | ((Bit1) << 1) | ((Bit2) << 2) | ((Bit3) << 3) | \
        ((Bit4) << 4) | ((Bit5) << 5) | ((Bit6) << 6) | ((Bit7) << 7)
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
    return (AccessAllowedMask[Write != 0][Execute != 0] >> ProtectionMask) & 1;
}

static
NTSTATUS
NTAPI
MiAccessCheck(IN PMMPTE Pte,
              IN BOOLEAN StoreInstruction,
              IN KPROCESSOR_MODE PreviousMode,
              IN ULONG_PTR ProtectionMask,
              IN PVOID TrapFrame,
              IN BOOLEAN LockHeld)
{
    MMPTE TempPte;

    /* Check for invalid user-mode access */
    if ((PreviousMode == UserMode) && (Pte > MiHighestUserPte))
    {
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
            if (MI_IS_PAGE_WRITEABLE(&TempPte) ||
                MI_IS_PAGE_COPY_ON_WRITE(&TempPte))
            {
                /* Then there's nothing to worry about */
                return STATUS_SUCCESS;
            }

            /* Oops! This isn't allowed */
            return STATUS_ACCESS_VIOLATION;
        }

        /* Someone was trying to read from a valid PTE, that's fine too */
        return STATUS_SUCCESS;
    }

    /* Check if the protection on the page allows what is being attempted */
    if (!MiIsAccessAllowed(ProtectionMask, StoreInstruction, FALSE))
    {
        return STATUS_ACCESS_VIOLATION;
    }

    /* Check if this is a guard page */
    if ((ProtectionMask & MM_PROTECT_SPECIAL) == MM_GUARDPAGE)
    {
        ASSERT(ProtectionMask != MM_DECOMMIT);

        /* Attached processes can't expand their stack */
        if (KeIsAttachedProcess()) return STATUS_ACCESS_VIOLATION;

        /* No support for prototype PTEs yet */
        ASSERT(TempPte.u.Soft.Prototype == 0);

        /* Remove the guard page bit, and return a guard page violation */
        TempPte.u.Soft.Protection = ProtectionMask & ~MM_GUARDPAGE;
        ASSERT(TempPte.u.Long != 0);
        MI_WRITE_INVALID_PTE(Pte, TempPte);
        return STATUS_GUARD_PAGE_VIOLATION;
    }

    /* Nothing to do */
    return STATUS_SUCCESS;
}

static
PMMPTE
NTAPI
MiCheckVirtualAddress(IN PVOID VirtualAddress,
                      OUT PULONG ProtectCode,
                      OUT PMMVAD *ProtoVad)
{
    PMMVAD Vad;
    PMMPTE Pte;

    /* No prototype/section support for now */
    *ProtoVad = NULL;

    /* User or kernel fault? */
    if (VirtualAddress <= MM_HIGHEST_USER_ADDRESS)
    {
        /* Special case for shared data */
        if (PAGE_ALIGN(VirtualAddress) == (PVOID)MM_SHARED_USER_DATA_VA)
        {
            /* It's a read-only page */
            *ProtectCode = MM_READONLY;
            return MmSharedUserDataPte;
        }

        /* Find the VAD, it might not exist if the address is bogus */
        Vad = MiLocateAddress(VirtualAddress);
        if (!Vad)
        {
            /* Bogus virtual address */
            *ProtectCode = MM_NOACCESS;
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
            {
                /* It's committed, so return the VAD protection */
                *ProtectCode = (ULONG)Vad->u.VadFlags.Protection;
            }
            else
            {
                /* It has not yet been committed, so return no access */
                *ProtectCode = MM_NOACCESS;
            }

            /* In both cases, return no PTE */
            return NULL;
        }
        else
        {
            /* ReactOS does not supoprt these VADs yet */
            ASSERT(Vad->u.VadFlags.VadType != VadImageMap);
            ASSERT(Vad->u2.VadFlags2.ExtendableFile == 0);

            /* Return the proto VAD */
            *ProtoVad = Vad;

            /* Get the prototype PTE for this page */
            Pte = (((ULONG_PTR)VirtualAddress >> PAGE_SHIFT) - Vad->StartingVpn) + Vad->FirstPrototypePte;
            ASSERT(Pte != NULL);
            ASSERT(Pte <= Vad->LastContiguousPte);

            /* Return the Prototype PTE and the protection for the page mapping */
            *ProtectCode = (ULONG)Vad->u.VadFlags.Protection;
            return Pte;
        }
    }
    else if (MI_IS_PAGE_TABLE_ADDRESS(VirtualAddress))
    {
        /* This should never happen, as these addresses are handled by the double-maping */
        if (((PMMPTE)VirtualAddress >= MiAddressToPte(MmPagedPoolStart)) &&
            ((PMMPTE)VirtualAddress <= MmPagedPoolInfo.LastPteForPagedPool))
        {
            /* Fail such access */
            *ProtectCode = MM_NOACCESS;
            return NULL;
        }

        /* Return full access rights */
        *ProtectCode = MM_READWRITE;
        return NULL;
    }
    else if (MI_IS_SESSION_ADDRESS(VirtualAddress))
    {
        /* ReactOS does not have an image list yet, so bail out to failure case */
        ASSERT(IsListEmpty(&MmSessionSpace->ImageList));
    }

    /* Default case -- failure */
    *ProtectCode = MM_NOACCESS;
    return NULL;
}

#if (_MI_PAGING_LEVELS == 2)
static
NTSTATUS
FASTCALL
MiCheckPdeForSessionSpace(IN PVOID Address)
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
            DbgPrint("MiCheckPdeForSessionSpace: No current session for PTE %p\n",
                     Address);
            DbgBreakPoint();
            return STATUS_ACCESS_VIOLATION;
        }

        /* Now get the session-specific page table for this address */
        SessionAddress = MiPteToAddress(Address);
        Pde = MiAddressToPte(Address);
        if (Pde->u.Hard.Valid) return STATUS_WAIT_1;

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
        DbgPrint("MiCheckPdeForSessionSpace: No Session PDE for PTE %p, %p\n",
                 Pde->u.Long, SessionAddress);
        DbgBreakPoint();
        return STATUS_ACCESS_VIOLATION;
    }

    /* Is the address also a session address? If not, we're done */
    if (!MI_IS_SESSION_ADDRESS(Address)) return STATUS_SUCCESS;

    /* It is, so again get the PDE for session space */
    Pde = MiAddressToPde(MmSessionSpace);
    if (!Pde->u.Hard.Valid)
    {
        /* This means there's no valid session, bail out */
        DbgPrint("MiCheckPdeForSessionSpace: No current session for VA %p\n",
                    Address);
        DbgBreakPoint();
        return STATUS_ACCESS_VIOLATION;
    }

    /* Now get the PDE for the address itself */
    Pde = MiAddressToPde(Address);
    if (!Pde->u.Hard.Valid)
    {
        /* Do the swap, we should be good to go */
        Index = ((ULONG_PTR)Address - (ULONG_PTR)MmSessionBase) >> 22;
        Pde->u.Long = MmSessionSpace->PageTables[Index].u.Long;
        if (Pde->u.Hard.Valid) return STATUS_WAIT_1;

        /* We had not allocated a page table for this session address yet, fail! */
        DbgPrint("MiCheckPdeForSessionSpace: No Session PDE for VA %p, %p\n",
                 Pde->u.Long, Address);
        DbgBreakPoint();
        return STATUS_ACCESS_VIOLATION;
    }

    /* It's valid, so there's nothing to do */
    return STATUS_SUCCESS;
}

NTSTATUS
FASTCALL
MiCheckPdeForPagedPool(IN PVOID Address)
{
    PMMPDE Pde;
    NTSTATUS Status = STATUS_SUCCESS;

    /* Check session PDE */
    if (MI_IS_SESSION_ADDRESS(Address)) return MiCheckPdeForSessionSpace(Address);
    if (MI_IS_SESSION_PTE(Address)) return MiCheckPdeForSessionSpace(Address);

    //
    // Check if this is a fault while trying to access the page table itself
    //
    if (MI_IS_SYSTEM_PAGE_TABLE_ADDRESS(Address))
    {
        //
        // Send a hint to the page fault handler that this is only a valid fault
        // if we already detected this was access within the page table range
        //
        Pde = (PMMPDE)MiAddressToPte(Address);
        Status = STATUS_WAIT_1;
    }
    else if (Address < MmSystemRangeStart)
    {
        //
        // This is totally illegal
        //
        return STATUS_ACCESS_VIOLATION;
    }
    else
    {
        //
        // Get the PDE for the address
        //
        Pde = MiAddressToPde(Address);
    }

    //
    // Check if it's not valid
    //
    if (Pde->u.Hard.Valid == 0)
    {
        //
        // Copy it from our double-mapped system page directory
        //
        InterlockedExchangePte(Pde,
                               MmSystemPagePtes[MiGetPdeOffset(Pde)].u.Long);
    }

    //
    // Return status
    //
    return Status;
}
#else
NTSTATUS
FASTCALL
MiCheckPdeForPagedPool(IN PVOID Address)
{
    return STATUS_ACCESS_VIOLATION;
}
#endif

VOID
NTAPI
MiZeroPfn(IN PFN_NUMBER PageFrameNumber)
{
    PMMPTE ZeroPte;
    MMPTE TempPte;
    PMMPFN Pfn1;
    PVOID ZeroAddress;

    /* Get the PFN for this page */
    Pfn1 = MiGetPfnEntry(PageFrameNumber);
    ASSERT(Pfn1);

    /* Grab a system PTE we can use to zero the page */
    ZeroPte = MiReserveSystemPtes(1, SystemPteSpace);
    ASSERT(ZeroPte);

    /* Initialize the PTE for it */
    TempPte = ValidKernelPte;
    TempPte.u.Hard.PageFrameNumber = PageFrameNumber;

    /* Setup caching */
    if (Pfn1->u3.e1.CacheAttribute == MiWriteCombined)
    {
        /* Write combining, no caching */
        MI_PAGE_DISABLE_CACHE(&TempPte);
        MI_PAGE_WRITE_COMBINED(&TempPte);
    }
    else if (Pfn1->u3.e1.CacheAttribute == MiNonCached)
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

VOID
NTAPI
MiCopyPfn(
    _In_ PFN_NUMBER DestPage,
    _In_ PFN_NUMBER SrcPage)
{
    PMMPTE SysPtes;
    MMPTE TempPte;
    PMMPFN DestPfn, SrcPfn;
    PVOID DestAddress;
    const VOID* SrcAddress;

    /* Get the PFNs */
    DestPfn = MiGetPfnEntry(DestPage);
    ASSERT(DestPfn);
    SrcPfn = MiGetPfnEntry(SrcPage);
    ASSERT(SrcPfn);

    /* Grab 2 system PTEs */
    SysPtes = MiReserveSystemPtes(2, SystemPteSpace);
    ASSERT(SysPtes);

    /* Initialize the destination PTE */
    TempPte = ValidKernelPte;
    TempPte.u.Hard.PageFrameNumber = DestPage;

    /* Setup caching */
    if (DestPfn->u3.e1.CacheAttribute == MiWriteCombined)
    {
        /* Write combining, no caching */
        MI_PAGE_DISABLE_CACHE(&TempPte);
        MI_PAGE_WRITE_COMBINED(&TempPte);
    }
    else if (DestPfn->u3.e1.CacheAttribute == MiNonCached)
    {
        /* Write through, no caching */
        MI_PAGE_DISABLE_CACHE(&TempPte);
        MI_PAGE_WRITE_THROUGH(&TempPte);
    }

    /* Make the system PTE valid with our PFN */
    MI_WRITE_VALID_PTE(&SysPtes[0], TempPte);

    /* Initialize the source PTE */
    TempPte = ValidKernelPte;
    TempPte.u.Hard.PageFrameNumber = SrcPage;

    /* Setup caching */
    if (SrcPfn->u3.e1.CacheAttribute == MiNonCached)
    {
        MI_PAGE_DISABLE_CACHE(&TempPte);
    }

    /* Make the system PTE valid with our PFN */
    MI_WRITE_VALID_PTE(&SysPtes[1], TempPte);

    /* Get the addresses and perform the copy */
    DestAddress = MiPteToAddress(&SysPtes[0]);
    SrcAddress = MiPteToAddress(&SysPtes[1]);
    RtlCopyMemory(DestAddress, SrcAddress, PAGE_SIZE);

    /* Now get rid of it */
    MiReleaseSystemPtes(SysPtes, 2, SystemPteSpace);
}

static
NTSTATUS
NTAPI
MiResolveDemandZeroFault(IN PVOID Address,
                         IN PMMPTE Pte,
                         IN ULONG Protection,
                         IN PEPROCESS Process,
                         IN KIRQL OldIrql)
{
    PFN_NUMBER PageFrameNumber = 0;
    MMPTE TempPte;
    BOOLEAN NeedZero = FALSE, HaveLock = FALSE;
    ULONG Color;
    PMMPFN Pfn1;

    DPRINT("MiResolveDemandZeroFault: Address %p, Pte %p [%I64X], Protection %p, Process %p, OldIrql %X\n", Address, Pte, MiGetPteContents(Pte), Protection, Process, OldIrql);

    /* Must currently only be called by paging path */
    if ((Process > HYDRA_PROCESS) && (OldIrql == MM_NOIRQL))
    {
        /* Sanity check */
        ASSERT(MI_IS_PAGE_TABLE_ADDRESS(Pte));

        /* No forking yet */
        ASSERT(Process->ForkInProgress == NULL);

        /* Get process color */
        Color = MI_GET_NEXT_PROCESS_COLOR(Process);
        ASSERT(Color != 0xFFFFFFFF);

        /* We'll need a zero page */
        NeedZero = TRUE;
    }
    else
    {
        /* Check if we need a zero page */
        NeedZero = (OldIrql != MM_NOIRQL);

        /* Session-backed image views must be zeroed */
        if ((Process == HYDRA_PROCESS) &&
            ((MI_IS_SESSION_IMAGE_ADDRESS(Address)) ||
             ((Address >= MiSessionViewStart) && (Address < MiSessionSpaceWs))))
        {
            NeedZero = TRUE;
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
    ASSERT(Pte->u.Hard.Valid == 0);

    /* Assert we have enough pages */
    ASSERT(MmAvailablePages >= 32);

#if MI_TRACE_PFNS
    if (UserPdeFault) MI_SET_USAGE(MI_USAGE_PAGE_TABLE);
    if (!UserPdeFault) MI_SET_USAGE(MI_USAGE_DEMAND_ZERO);
#endif
    if (Process == HYDRA_PROCESS) MI_SET_PROCESS2("Hydra");
    else if (Process) MI_SET_PROCESS2(Process->ImageFileName);
    else MI_SET_PROCESS2("Kernel Demand 0");

    /* Do we need a zero page? */
    if (Color != 0xFFFFFFFF)
    {
        /* Try to get one, if we couldn't grab a free page and zero it */
        PageFrameNumber = MiRemoveZeroPageSafe(Color);
        if (!PageFrameNumber)
        {
            /* We'll need a free page and zero it manually */
            PageFrameNumber = MiRemoveAnyPage(Color);
            NeedZero = TRUE;
        }
    }
    else
    {
        /* Get a color, and see if we should grab a zero or non-zero page */
        Color = MI_GET_NEXT_COLOR();
        if (!NeedZero)
        {
            /* Process or system doesn't want a zero page, grab anything */
            PageFrameNumber = MiRemoveAnyPage(Color);
        }
        else
        {
            /* System wants a zero page, obtain one */
            PageFrameNumber = MiRemoveZeroPage(Color);
        }
    }

    /* Initialize it */
    MiInitializePfn(PageFrameNumber, Pte, TRUE);

    /* Increment demand zero faults */
    KeGetCurrentPrcb()->MmDemandZeroCount++;

    /* Do we have the lock? */
    if (HaveLock)
    {
        /* Release it */
        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        /* Update performance counters */
        if (Process > HYDRA_PROCESS) Process->NumberOfPrivatePages++;
    }

    /* Zero the page if need be */
    if (NeedZero) MiZeroPfn(PageFrameNumber);

    /* Fault on user PDE, or fault on user PTE? */
    if (Pte <= MiHighestUserPte)
    {
        /* User fault, build a user PTE */
        MI_MAKE_HARDWARE_PTE_USER(&TempPte,
                                  Pte,
                                  Protection,
                                  PageFrameNumber);
    }
    else
    {
        /* This is a user-mode PDE, create a kernel PTE for it */
        MI_MAKE_HARDWARE_PTE(&TempPte,
                             Pte,
                             Protection,
                             PageFrameNumber);
    }

    /* Set it dirty if it's a writable page */
    if (MI_IS_PAGE_WRITEABLE(&TempPte)) MI_MAKE_DIRTY_PAGE(&TempPte);

    /* Write it */
    MI_WRITE_VALID_PTE(Pte, TempPte);

    /* Did we manually acquire the lock */
    if (HaveLock)
    {
        /* Get the PFN entry */
        Pfn1 = MI_PFN_ELEMENT(PageFrameNumber);

        /* Windows does these sanity checks */
        ASSERT(Pfn1->u1.Event == 0);
        ASSERT(Pfn1->u3.e1.PrototypePte == 0);
    }

    //
    // It's all good now
    //
    DPRINT("MiResolveDemandZeroFault: Demand zero page has now been paged in\n");
    return STATUS_PAGE_FAULT_DEMAND_ZERO;
}

static
NTSTATUS
NTAPI
MiCompleteProtoPteFault(IN BOOLEAN StoreInstruction,
                        IN PVOID Address,
                        IN PMMPTE Pte,
                        IN PMMPTE SectionProto,
                        IN KIRQL OldIrql,
                        IN PMMPFN* LockedProtoPfn)
{
    MMPTE TempPte;
    PMMPTE OriginalPte, PageTablePte;
    ULONG_PTR Protection;
    PFN_NUMBER PageFrameIndex;
    PMMPFN Pfn1, Pfn2;
    BOOLEAN OriginalProtection, DirtyPage;

    DPRINT("MiCompleteProtoPteFault: Store %X, Address %p, Pte %p [%I64X], Proto %p [%I64X], OldIrql %X\n", StoreInstruction, Address, Pte, MiGetPteContents(Pte), SectionProto, MiGetPteContents(SectionProto), OldIrql);

    /* Must be called with an valid prototype PTE, with the PFN lock held */
    MI_ASSERT_PFN_LOCK_HELD();
    ASSERT(SectionProto->u.Hard.Valid == 1);

    /* Get the page */
    PageFrameIndex = PFN_FROM_PTE(SectionProto);

    /* Get the PFN entry and set it as a prototype PTE */
    Pfn1 = MiGetPfnEntry(PageFrameIndex);
    Pfn1->u3.e1.PrototypePte = 1;

    /* Increment the share count for the page table */
    PageTablePte = MiAddressToPte(Pte);
    Pfn2 = MiGetPfnEntry(PageTablePte->u.Hard.PageFrameNumber);
    Pfn2->u2.ShareCount++;

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
        OriginalPte = &Pfn1->OriginalPte;
        Protection = OriginalPte->u.Soft.Protection;

        /* Remember that we used the original protection */
        OriginalProtection = TRUE;

        /* Check if this was a write on a read only proto */
        if ((StoreInstruction) && !(Protection & MM_READWRITE))
        {
            /* Clear the flag */
            StoreInstruction = 0;
        }
    }

    /* Check if this was a write on a non-COW page */
    DirtyPage = FALSE;
    if ((StoreInstruction) && ((Protection & MM_WRITECOPY) != MM_WRITECOPY))
    {
        /* Then the page should be marked dirty */
        DirtyPage = TRUE;

        /* ReactOS check */
        ASSERT(Pfn1->OriginalPte.u.Soft.Prototype != 0);
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
    Protection &= ~MM_PROTECT_SPECIAL;

    /* Setup caching */
    if (Pfn1->u3.e1.CacheAttribute == MiWriteCombined)
    {
        /* Write combining, no caching */
        MI_PAGE_DISABLE_CACHE(&TempPte);
        MI_PAGE_WRITE_COMBINED(&TempPte);
    }
    else if (Pfn1->u3.e1.CacheAttribute == MiNonCached)
    {
        /* Write through, no caching */
        MI_PAGE_DISABLE_CACHE(&TempPte);
        MI_PAGE_WRITE_THROUGH(&TempPte);
    }

    /* Check if this is a kernel or user address */
    if (Address < MmSystemRangeStart)
    {
        /* Build the user PTE */
        MI_MAKE_HARDWARE_PTE_USER(&TempPte, Pte, Protection, PageFrameIndex);
    }
    else
    {
        /* Build the kernel PTE */
        MI_MAKE_HARDWARE_PTE(&TempPte, Pte, Protection, PageFrameIndex);
    }

    /* Set the dirty flag if needed */
    if (DirtyPage) MI_MAKE_DIRTY_PAGE(&TempPte);

    /* Write the PTE */
    MI_WRITE_VALID_PTE(Pte, TempPte);

    /* Reset the protection if needed */
    if (OriginalProtection) Protection = MM_ZERO_ACCESS;

    /* Return success */
    ASSERT(Pte == MiAddressToPte(Address));
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
MiResolvePageFileFault(_In_ BOOLEAN StoreInstruction,
                       _In_ PVOID FaultingAddress,
                       _In_ PMMPTE Pte,
                       _Out_ MMPTE * PteValue,
                       _Out_ PMI_PAGE_SUPPORT_BLOCK * OutPageBlock,
                       _In_ PEPROCESS CurrentProcess,
                       _Inout_ KIRQL *OldIrql)
{
    ULONG Color;
    PFN_NUMBER Page;
    NTSTATUS Status;
    MMPTE TempPte = *Pte;
    PMMPFN Pfn1;
    ULONG PageFileIndex = TempPte.u.Soft.PageFileLow;
    ULONG_PTR PageFileOffset = TempPte.u.Soft.PageFileHigh;
    ULONG Protection = TempPte.u.Soft.Protection;

    ASSERT(FALSE);

    /* Things we don't support yet */
    ASSERT(CurrentProcess > HYDRA_PROCESS);
    ASSERT(*OldIrql != MM_NOIRQL);

    /* We must hold the PFN lock */
    MI_ASSERT_PFN_LOCK_HELD();

    /* Some sanity checks */
    ASSERT(TempPte.u.Hard.Valid == 0);
    ASSERT(TempPte.u.Soft.PageFileHigh != 0);
    ASSERT(TempPte.u.Soft.PageFileHigh != MI_PTE_LOOKUP_NEEDED);

    /* Get any page, it will be overwritten */
    Color = MI_GET_NEXT_PROCESS_COLOR(CurrentProcess);
    Page = MiRemoveAnyPage(Color);

    /* Initialize this PFN */
    MiInitializePfn(Page, Pte, StoreInstruction);

    /* Sets the PFN as being in IO operation */
    Pfn1 = MI_PFN_ELEMENT(Page);
    ASSERT(Pfn1->u1.Event == NULL);
    ASSERT(Pfn1->u3.e1.ReadInProgress == 0);
    ASSERT(Pfn1->u3.e1.WriteInProgress == 0);
    Pfn1->u3.e1.ReadInProgress = 1;

    /* We must write the PTE now as the PFN lock will be released while performing the IO operation */
    MI_MAKE_TRANSITION_PTE(&TempPte, Page, Protection);

    MI_WRITE_INVALID_PTE(Pte, TempPte);

    /* Release the PFN lock while we proceed */
    MiReleasePfnLock(*OldIrql);

    /* Do the paging IO */
    Status = MiReadPageFile(Page, PageFileIndex, PageFileOffset);

    /* Lock the PFN database again */
    *OldIrql = MiLockPfnDb(APC_LEVEL);

    /* Nobody should have changed that while we were not looking */
    ASSERT(Pfn1->u3.e1.ReadInProgress == 1);
    ASSERT(Pfn1->u3.e1.WriteInProgress == 0);

    if (!NT_SUCCESS(Status))
    {
        /* Malheur! */
        ASSERT(FALSE);
        Pfn1->u4.InPageError = 1;
        Pfn1->u1.ReadStatus = Status;
    }

    /* And the PTE can finally be valid */
    MI_MAKE_HARDWARE_PTE(&TempPte, Pte, Protection, Page);
    MI_WRITE_VALID_PTE(Pte, TempPte);

    Pfn1->u3.e1.ReadInProgress = 0;
    /* Did someone start to wait on us while we proceeded ? */
    if (Pfn1->u1.Event)
    {
        /* Tell them we're done */
        KeSetEvent(Pfn1->u1.Event, IO_NO_INCREMENT, FALSE);
    }

    return Status;
}

static
NTSTATUS
NTAPI
MiResolveTransitionFault(IN BOOLEAN StoreInstruction,
                         IN PVOID FaultingAddress,
                         IN PMMPTE Pte,
                         IN PEPROCESS CurrentProcess,
                         IN KIRQL OldIrql,
                         OUT PMI_PAGE_SUPPORT_BLOCK * OutPageBlock)
{
    PFN_NUMBER PageFrameIndex;
    PMMPFN Pfn1;
    MMPTE TempPte;
    PMMPTE PointerToPteForProtoPage;

    DPRINT("MiResolveTransitionFault: Address %p, PTE %p [%p], Process %s\n", FaultingAddress, Pte, Pte->u.Long, ((CurrentProcess>(PEPROCESS)2)?CurrentProcess->ImageFileName:" "));

    /* Windowss does this check */
    ASSERT(*OutPageBlock == NULL);

    /* ARM3 doesn't support this path */
    ASSERT(OldIrql != MM_NOIRQL);

    /* Capture the PTE and make sure it's in transition format */
    TempPte = *Pte;
    ASSERT((TempPte.u.Soft.Valid == 0) &&
           (TempPte.u.Soft.Prototype == 0) &&
           (TempPte.u.Soft.Transition == 1));

    /* Get the PFN and the PFN entry */
    PageFrameIndex = TempPte.u.Trans.PageFrameNumber;
    DPRINT("MiResolveTransitionFault:  PageFrameIndex %lx\n", PageFrameIndex);
    Pfn1 = MiGetPfnEntry(PageFrameIndex);

    /* One more transition fault! */
    InterlockedIncrement(&KeGetCurrentPrcb()->MmTransitionCount);

    /* This is from ARM3 -- Windows normally handles this here */
    ASSERT(Pfn1->u4.InPageError == 0);

    /* See if we should wait before terminating the fault */
    if ((Pfn1->u3.e1.ReadInProgress == 1)
            || ((Pfn1->u3.e1.WriteInProgress == 1) && StoreInstruction))
    {
        DPRINT1("MiResolveTransitionFault: The page is currently in a page transition !\n");
        if (Pte == Pfn1->PteAddress)
        {
            DPRINT1("MiResolveTransitionFault: And this if for this particular PTE.\n");
            /* The PTE will be made valid by the thread serving the fault */
            return STATUS_SUCCESS; // FIXME: Maybe something more descriptive
        }
    }

    /* Windows checks there's some free pages and this isn't an in-page error */
    ASSERT(MmAvailablePages > 0);
    ASSERT(Pfn1->u4.InPageError == 0);

    /* ReactOS checks for this */
    ASSERT(MmAvailablePages > 32);

    /* Was this a transition page in the valid list, or free/zero list? */
    if (Pfn1->u3.e1.PageLocation == ActiveAndValid)
    {
        /* All Windows does here is a bunch of sanity checks */
        DPRINT("MiResolveTransitionFault: Transition in active list\n");
        ASSERT((Pfn1->PteAddress >= MiAddressToPte(MmPagedPoolStart)) &&
               (Pfn1->PteAddress <= MiAddressToPte(MmPagedPoolEnd)));
        ASSERT(Pfn1->u2.ShareCount != 0);
        ASSERT(Pfn1->u3.e2.ReferenceCount != 0);
    }
    else
    {
        /* Otherwise, the page is removed from its list */
        DPRINT("MiResolveTransitionFault: Transition page in free/zero list\n");
        MiUnlinkPageFromList(Pfn1);
        MiReferenceUnusedPageAndBumpLockCount(Pfn1);
    }

    /* At this point, there should no longer be any in-page errors */
    ASSERT(Pfn1->u4.InPageError == 0);

    /* Check if this was a PFN with no more share references */
    if (Pfn1->u2.ShareCount == 0) MiDropLockCount(Pfn1);

    /* Bump the share count and make the page valid */
    Pfn1->u2.ShareCount++;
    Pfn1->u3.e1.PageLocation = ActiveAndValid;

    /* Prototype PTEs are in paged pool, which itself might be in transition */
    if (FaultingAddress >= MmSystemRangeStart)
    {
        /* Check if this is a paged pool PTE in transition state */
        PointerToPteForProtoPage = MiAddressToPte(Pte);
        TempPte = *PointerToPteForProtoPage;
        if ((TempPte.u.Hard.Valid == 0) && (TempPte.u.Soft.Transition == 1))
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
    if ((Pfn1->u3.e1.Modified) &&
        MI_IS_PAGE_WRITEABLE(&TempPte) &&
        !MI_IS_PAGE_COPY_ON_WRITE(&TempPte))
    {
        /* Make it dirty */
        MI_MAKE_DIRTY_PAGE(&TempPte);
    }
    else
    {
        /* Make it clean */
        MI_MAKE_CLEAN_PAGE(&TempPte);
    }

    /* Write the valid PTE */
    MI_WRITE_VALID_PTE(Pte, TempPte);

    /* Return success */
    return STATUS_PAGE_FAULT_TRANSITION;
}

PMI_PAGE_SUPPORT_BLOCK
NTAPI
MiGetInPageSupportBlock(IN KIRQL OldIrql,
                        OUT NTSTATUS * OutStatus)
{
    PMI_PAGE_SUPPORT_BLOCK Support;
    PSINGLE_LIST_ENTRY Entry;
    KIRQL CurrentIrql;

    DPRINT("MiGetInPageSupportBlock: OldIrql %X\n", OldIrql);

    if (OldIrql != MM_NOIRQL)
    {
        CurrentIrql = KeGetCurrentIrql();
        ASSERT(CurrentIrql == DISPATCH_LEVEL);
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

            ASSERT(Support->WaitCount == 1);
            ASSERT(Support->u1.e1.PrefetchMdlHighBits == 0);
            ASSERT(Support->u1.LongFlags == 0);
            ASSERT(KeReadStateEvent(&Support->Event) == 0);
          #ifdef _M_AMD64
            ASSERT(Support->UsedPageTableEntries == 0);
          #endif

            Support->CurrentThread = PsGetCurrentThread();
            Support->ListEntry.Next = NULL;

            return Support;
        }
    }

    if (OldIrql != MM_NOIRQL)
    {
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
    }

    Support = ExAllocatePoolWithTag(NonPagedPool, sizeof(MI_PAGE_SUPPORT_BLOCK), 'nImM');
    if (!Support)
    {
        DPRINT("MiGetInPageSupportBlock: STATUS_INSUFFICIENT_RESOURCES\n");
        *OutStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    DPRINT("MiGetInPageSupportBlock: Support %p\n", Support);

    KeInitializeEvent(&Support->Event, NotificationEvent, FALSE);
 
    Support->WaitCount = 1;
    Support->u1.LongFlags = 0;
    Support->CurrentThread = NULL;

    ASSERT(KeReadStateEvent(&Support->Event) == 0);

    if (OldIrql == MM_NOIRQL)
    {
        DPRINT("MiGetInPageSupportBlock: return NULL\n");
        return NULL;
    }

    InterlockedPushEntrySList(&MmInPageSupportSListHead, &Support->ListEntry);

    *OutStatus = 0xC7303001; // ?

Exit:

    if (OldIrql != MM_NOIRQL)
    {
        OldIrql = MiLockPfnDb(APC_LEVEL);
    }

    DPRINT("MiGetInPageSupportBlock: return NULL\n");
    return NULL;
}

VOID
NTAPI
MiFreeInPageSupportBlock(PMI_PAGE_SUPPORT_BLOCK Support)
{
    PMDL Mdl;

    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
    ASSERT(Support->CurrentThread != NULL);
    ASSERT(Support->WaitCount != 0);
    ASSERT((Support->ListEntry.Next == NULL) ||
           (Support->u1.e1.PrefetchMdlHighBits != 0));
  
    DPRINT("MiFreeInPageSupportBlock: Support %p\n", Support);

    if (InterlockedDecrement((PLONG)&Support->WaitCount))
    {
        DPRINT("MiFreeInPageSupportBlock: Support->WaitCount %X\n", Support->WaitCount);
        return;
    }

    if (Support->u1.e1.PrefetchMdlHighBits)
    {
        Mdl = (PMDL)(Support->u1.e1.PrefetchMdlHighBits << 3);
        if (Mdl != &Support->Mdl)
        {
            ExFreePool(Mdl);
        }
    }

    if (MmInPageSupportSListHead.Depth >= MmInPageSupportMinimum)
    {
        ExFreePoolWithTag(Support, 'nImM');
        return;
    }

    Support->WaitCount = 1;
    Support->u1.LongFlags = 0;
    Support->CurrentThread = NULL;

    KeClearEvent(&Support->Event);

    InterlockedPushEntrySList(&MmInPageSupportSListHead, &Support->ListEntry);
}

static
NTSTATUS
NTAPI
MiResolveProtoPteFault(IN BOOLEAN StoreInstruction,
                       IN PVOID Address,
                       IN PMMPTE Pte,
                       IN PMMPTE SectionProto,
                       IN OUT PMMPFN *LockedProtoPfn,
                       OUT PMI_PAGE_SUPPORT_BLOCK *OutPageBlock,
                       OUT PMMPTE PteValue,
                       IN PEPROCESS Process,
                       IN KIRQL OldIrql,
                       IN PVOID TrapInformation)
{
    MMPTE TempProto, PteContents;
    PMMPFN Pfn1;
    PFN_NUMBER PageFrameIndex;
    NTSTATUS Status;
    ULONG Protection;
    PMI_PAGE_SUPPORT_BLOCK PageBlock = NULL;
    BOOLEAN IsLocked = TRUE;

    DPRINT("MiResolveProtoPteFault: Store %X, Address %p, Pte %p, Proto %p [%p], Process %p, OldIrql %X, TrapInfo %p\n", StoreInstruction, Address, Pte, SectionProto, SectionProto->u.Long, Process, OldIrql, TrapInformation);

    /* Must be called with an invalid, prototype PTE, with the PFN lock held */
    MI_ASSERT_PFN_LOCK_HELD();
    ASSERT(Pte->u.Hard.Valid == 0);
    ASSERT(Pte->u.Soft.Prototype == 1);

    /* Read the prototype PTE and check if it's valid */
    TempProto = *SectionProto;
    if (TempProto.u.Hard.Valid == 1)
    {
        /* One more user of this mapped page */
        PageFrameIndex = PFN_FROM_PTE(&TempProto);
        Pfn1 = MiGetPfnEntry(PageFrameIndex);
        Pfn1->u2.ShareCount++;

        /* Call it a transition */
        InterlockedIncrement(&KeGetCurrentPrcb()->MmTransitionCount);

        /* Complete the prototype PTE fault -- this will release the PFN lock */
        return MiCompleteProtoPteFault(StoreInstruction,
                                       Address,
                                       Pte,
                                       SectionProto,
                                       OldIrql,
                                       LockedProtoPfn);
    }

    /* Make sure there's some protection mask */
    if (TempProto.u.Long == 0)
    {
        /* Release the lock */
        DPRINT1("MiResolveProtoPteFault: Access on reserved section?\n");
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        return STATUS_ACCESS_VIOLATION;
    }

    /* There is no such thing as a decommitted prototype PTE */
    ASSERT(TempProto.u.Long != MmDecommittedPte.u.Long);

    /* Check for access rights on the PTE proper */
    PteContents = *Pte;
    if (PteContents.u.Soft.PageFileHigh != MI_PTE_LOOKUP_NEEDED)
    {
        if (PteContents.u.Proto.ReadOnly)
        {
            Protection = MM_READONLY;
        }
        else
        {
            /* Check for page acess in software */
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
                    Address >= MmSessionBase &&
                    Address < MiSessionSpaceEnd &&
                    MmSessionSpace->ImageLoadingCount)
                {
                    PLIST_ENTRY Entry;
                    for (Entry = MmSessionSpace->ImageList.Flink;
                         Entry != &MmSessionSpace->ImageList;
                         Entry = Entry->Flink)
                    {
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
        Protection = PteContents.u.Soft.Protection;
    }

    if ((Pte <= MiHighestUserPte) &&
        (Process > (PEPROCESS)2) &&
        (Process->CloneRoot))
    {
        ASSERT(FALSE);
        Protection = MM_WRITECOPY;
    }

    /* Check for writing copy on write page */
    if (!MI_IS_MAPPED_PTE(&TempProto) && ((Protection & MM_WRITECOPY) == MM_WRITECOPY))
    {
        MMPTE NewPte;

        ASSERT(Process != NULL);
        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        DPRINT1("MiResolveProtoPteFault: DemandZero page with CopyOnWrite protection\n");

        NewPte = DemandZeroPte;

        ASSERT(PteContents.u.Hard.Valid == 0);

        if (PteContents.u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED)//0xFFFFF
        {
            if (PteContents.u.Soft.Protection & MM_EXECUTE)
            {
                NewPte.u.Soft.Protection = MM_EXECUTE_READWRITE;
            }
        }
        else
        {
            if (TempProto.u.Soft.Protection & MM_EXECUTE)
            {
                NewPte.u.Soft.Protection = MM_EXECUTE_READWRITE;
            }
        }

        Pte->u.Long = NewPte.u.Long;

        Status = MiResolveDemandZeroFault(Address, Pte, Protection, Process, MM_NOIRQL);

        DPRINT("MiResolveProtoPteFault: Status %X\n", Status);
        return Status;
    }

    if (TempProto.u.Soft.Prototype)
    {
        ASSERT(FALSE);
        /* This is mapped file fault */
/*
        Status = MiResolveMappedFileFault(SectionProto,
                                          OutPageBlock,
                                          Process,
                                          OldIrql);
        if (Status == 0xC0033333)
        {
            *PteValue = *SectionProto;

            ASSERT(PteValue->u.Hard.Valid == 0);
            ASSERT(PteValue->u.Soft.Prototype == 0);
            ASSERT(PteValue->u.Soft.Transition == 1);
        }
*/
    }
    else if (TempProto.u.Soft.Transition == 1)
    {
        /* Resolve the transition fault */
        ASSERT(OldIrql != MM_NOIRQL);
        Status = MiResolveTransitionFault(StoreInstruction,
                                          Address,
                                          SectionProto,
                                          Process,
                                          OldIrql,
                                          &PageBlock);
        ASSERT(NT_SUCCESS(Status));
    }
    else if (TempProto.u.Soft.PageFileHigh)
    {
        /* We don't support paged out pages */
        ASSERT(TempProto.u.Soft.PageFileHigh == 0);
        ASSERT(FALSE);
/*
        Status = MiResolvePageFileFault(Address,
                                        SectionProto,
                                        PteValue,
                                        OutPageBlock,
                                        Process,
                                        OldIrql);
*/
        IsLocked = FALSE;

        if (Status == 0xC0033333)
        {
            ASSERT(PteValue->u.Hard.Valid == 0);
            ASSERT(PteValue->u.Soft.Prototype == 0);
            ASSERT(PteValue->u.Soft.Transition == 1);
        }

        ASSERT(KeAreAllApcsDisabled() == TRUE);
    }
    else
    {
        /* Resolve the demand zero fault */
        Status = MiResolveDemandZeroFault(Address,
                                          SectionProto,
                                          (ULONG)TempProto.u.Soft.Protection,
                                          Process,
                                          OldIrql);
        DPRINT("MiResolveProtoPteFault: Status %X\n", Status);
        ASSERT(NT_SUCCESS(Status));
    }

    if (NT_SUCCESS(Status))
    {
        DPRINT("MiResolveProtoPteFault: Pte %p [%p]\n", Pte, Pte->u.Long);
        ASSERT(Pte->u.Hard.Valid == 0);

        /* Complete the prototype PTE fault -- this will release the PFN lock */
        Status = MiCompleteProtoPteFault(StoreInstruction,
                                         Address,
                                         Pte,
                                         SectionProto,
                                         OldIrql,
                                         LockedProtoPfn);
    }
    else
    {
        if (IsLocked)
        {
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
        }

        ASSERT(KeAreAllApcsDisabled() == TRUE);
    }

    if (PageBlock)
    {
        MiFreeInPageSupportBlock(PageBlock);
    }

    return Status;
}

NTSTATUS
NTAPI
MiDispatchFault(IN ULONG FaultCode,
                IN PVOID Address,
                IN PMMPTE Pte,
                IN PMMPTE SectionProto,
                IN BOOLEAN Recursive,
                IN PEPROCESS Process,
                IN PVOID TrapInformation,
                IN PMMVAD Vad)
{
    MMPTE TempPte;
    MMPTE OriginalPte;
    KIRQL OldIrql, LockIrql;
    NTSTATUS Status;
    PMMPTE SuperProtoPte;
    PMMPFN Pfn1, LockedProtoPfn = NULL;
    PFN_NUMBER PageFrameIndex;
    PFN_COUNT PteCount, ProcessedPtes;
    PMI_PAGE_SUPPORT_BLOCK PageBlock;

    DPRINT("MiDispatchFault: FaultCode %X, Address %p, Pte %p [%p], Proto %p [%I64X], Recursive %X, Process %p, TrapInfo %p, Vad %p\n", FaultCode, Address, Pte, Pte->u.Long, SectionProto, MiGetPteContents(SectionProto), Recursive, Process, TrapInformation, Vad);

    /* Make sure the addresses are ok */
    ASSERT(Pte == MiAddressToPte(Address));

    //
    // Make sure APCs are off and we're not at dispatch
    //
    OldIrql = KeGetCurrentIrql();
    ASSERT(OldIrql <= APC_LEVEL);
    ASSERT(KeAreAllApcsDisabled() == TRUE);

    //
    // Grab a copy of the PTE
    //
    TempPte = *Pte;

    OriginalPte.u.Long = -1;

    /* Do we have a prototype PTE? */
    if (SectionProto)
    {
        /* This should never happen */
        ASSERT(!MI_IS_PHYSICAL_ADDRESS(SectionProto));

        /* Check if this is a kernel-mode address */
        SuperProtoPte = MiAddressToPte(SectionProto);
        if (Address >= MmSystemRangeStart)
        {
            /* Lock the PFN database */
            LockIrql = MiLockPfnDb(APC_LEVEL);

            /* Has the PTE been made valid yet? */
            if (!SuperProtoPte->u.Hard.Valid)
            {
                ASSERT(FALSE);
            }
            else if (Pte->u.Hard.Valid == 1)
            {
                ASSERT(FALSE);
            }

            /* Resolve the fault -- this will release the PFN lock */
            Status = MiResolveProtoPteFault(!MI_IS_NOT_PRESENT_FAULT(FaultCode),
                                            Address,
                                            Pte,
                                            SectionProto,
                                            &LockedProtoPfn,
                                            &PageBlock,
                                            &OriginalPte,
                                            Process,
                                            LockIrql,
                                            TrapInformation);
            ASSERT(Status == STATUS_SUCCESS);

            /* Complete this as a transition fault */
            ASSERT(OldIrql == KeGetCurrentIrql());
            ASSERT(OldIrql <= APC_LEVEL);
            ASSERT(KeAreAllApcsDisabled() == TRUE);
            return Status;
        }
        else
        {
            /* We only handle the lookup path */
            ASSERT(Pte->u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED);

            /* Is there a non-image VAD? */
            if ((Vad) &&
                (Vad->u.VadFlags.VadType != VadImageMap) &&
                !(Vad->u2.VadFlags2.ExtendableFile))
            {
                /* One day, ReactOS will cluster faults */
                ASSERT(Address <= MM_HIGHEST_USER_ADDRESS);
                DPRINT("MiDispatchFault: Should cluster fault, but won't\n");
            }

            /* Only one PTE to handle for now */
            PteCount = 1;
            ProcessedPtes = 0;

            /* Lock the PFN database */
            LockIrql = MiLockPfnDb(APC_LEVEL);

            /* We only handle the valid path */
            ASSERT(SuperProtoPte->u.Hard.Valid == 1);

            /* Capture the PTE */
            TempPte = *SectionProto;

            /* Loop to handle future case of clustered faults */
            while (TRUE)
            {
                /* For our current usage, this should be true */
                if (TempPte.u.Hard.Valid == 1)
                {
                    /* Bump the share count on the PTE */
                    PageFrameIndex = PFN_FROM_PTE(&TempPte);
                    Pfn1 = MI_PFN_ELEMENT(PageFrameIndex);
                    Pfn1->u2.ShareCount++;
                }
                else if ((TempPte.u.Soft.Prototype == 0) &&
                         (TempPte.u.Soft.Transition == 1))
                {
                    /* This is a standby page, bring it back from the cache */
                    PageFrameIndex = TempPte.u.Trans.PageFrameNumber;
                    DPRINT("MiDispatchFault: oooh, shiny, a soft fault! 0x%lx\n", PageFrameIndex);
                    Pfn1 = MI_PFN_ELEMENT(PageFrameIndex);
                    ASSERT(Pfn1->u3.e1.PageLocation != ActiveAndValid);

                    /* Should not yet happen in ReactOS */
                    ASSERT(Pfn1->u3.e1.ReadInProgress == 0);
                    ASSERT(Pfn1->u4.InPageError == 0);

                    /* Get the page */
                    MiUnlinkPageFromList(Pfn1);

                    /* Bump its reference count */
                    ASSERT(Pfn1->u2.ShareCount == 0);
                    InterlockedIncrement16((PSHORT)&Pfn1->u3.e2.ReferenceCount);
                    Pfn1->u2.ShareCount++;

                    /* Make it valid again */
                    /* This looks like another macro.... */
                    Pfn1->u3.e1.PageLocation = ActiveAndValid;
                    ASSERT(SectionProto->u.Hard.Valid == 0);
                    ASSERT(SectionProto->u.Trans.Prototype == 0);
                    ASSERT(SectionProto->u.Trans.Transition == 1);
                    TempPte.u.Long = (SectionProto->u.Long & ~0xFFF) |
                                     MmProtectToPteMask[SectionProto->u.Trans.Protection];
                    TempPte.u.Hard.Valid = 1;
                    MI_MAKE_ACCESSED_PAGE(&TempPte);

                    /* Is the PTE writeable? */
                    if ((Pfn1->u3.e1.Modified) &&
                        MI_IS_PAGE_WRITEABLE(&TempPte) &&
                        !MI_IS_PAGE_COPY_ON_WRITE(&TempPte))
                    {
                        /* Make it dirty */
                        MI_MAKE_DIRTY_PAGE(&TempPte);
                    }
                    else
                    {
                        /* Make it clean */
                        MI_MAKE_CLEAN_PAGE(&TempPte);
                    }

                    /* Write the valid PTE */
                    MI_WRITE_VALID_PTE(SectionProto, TempPte);
                    ASSERT(Pte->u.Hard.Valid == 0);
                }
                else
                {
                    /* Page is invalid, get out of the loop */
                    break;
                }

                /* One more done, was it the last? */
                if (++ProcessedPtes == PteCount)
                {
                    /* Complete the fault */
                    MiCompleteProtoPteFault(!MI_IS_NOT_PRESENT_FAULT(FaultCode),
                                            Address,
                                            Pte,
                                            SectionProto,
                                            LockIrql,
                                            &LockedProtoPfn);

                    /* THIS RELEASES THE PFN LOCK! */
                    break;
                }

                /* No clustered faults yet */
                ASSERT(FALSE);
            }

            /* Did we resolve the fault? */
            if (ProcessedPtes)
            {
                /* Bump the transition count */
                InterlockedExchangeAddSizeT(&KeGetCurrentPrcb()->MmTransitionCount, ProcessedPtes);
                ProcessedPtes--;

                /* Loop all the processing we did */
                ASSERT(ProcessedPtes == 0);

                /* Complete this as a transition fault */
                ASSERT(OldIrql == KeGetCurrentIrql());
                ASSERT(OldIrql <= APC_LEVEL);
                ASSERT(KeAreAllApcsDisabled() == TRUE);
                return STATUS_PAGE_FAULT_TRANSITION;
            }

            /* We did not -- PFN lock is still held, prepare to resolve prototype PTE fault */
            LockedProtoPfn = MI_PFN_ELEMENT(SuperProtoPte->u.Hard.PageFrameNumber);
            MiReferenceUsedPageAndBumpLockCount(LockedProtoPfn);
            ASSERT(LockedProtoPfn->u3.e2.ReferenceCount > 1);
            ASSERT(Pte->u.Hard.Valid == 0);

            /* Resolve the fault -- this will release the PFN lock */
            Status = MiResolveProtoPteFault(!MI_IS_NOT_PRESENT_FAULT(FaultCode),
                                            Address,
                                            Pte,
                                            SectionProto,
                                            &LockedProtoPfn,
                                            &PageBlock,
                                            &OriginalPte,
                                            Process,
                                            LockIrql,
                                            TrapInformation);
            //ASSERT(Status != STATUS_ISSUE_PAGING_IO);
            //ASSERT(Status != STATUS_REFAULT);
            //ASSERT(Status != STATUS_PTE_CHANGED);

            /* Did the routine clean out the PFN or should we? */
            if (LockedProtoPfn)
            {
                /* We had a locked PFN, so acquire the PFN lock to dereference it */
                ASSERT(SectionProto != NULL);
                OldIrql = MiLockPfnDb(APC_LEVEL);

                /* Dereference the locked PFN */
                MiDereferencePfnAndDropLockCount(LockedProtoPfn);
                ASSERT(LockedProtoPfn->u3.e2.ReferenceCount >= 1);

                /* And now release the lock */
                MiUnlockPfnDb(OldIrql, APC_LEVEL);
            }

            /* Complete this as a transition fault */
            ASSERT(OldIrql == KeGetCurrentIrql());
            ASSERT(OldIrql <= APC_LEVEL);
            ASSERT(KeAreAllApcsDisabled() == TRUE);
            return Status;
        }
    }

    /* Is this a transition PTE */
    if (TempPte.u.Soft.Transition)
    {
        PKEVENT* InPageBlock = NULL;
        PKEVENT PreviousPageEvent;
        KEVENT CurrentPageEvent;

        ASSERT(FALSE);

        /* Lock the PFN database */
        LockIrql = MiLockPfnDb(APC_LEVEL);

        /* Resolve */
        Status = MiResolveTransitionFault(!MI_IS_NOT_PRESENT_FAULT(FaultCode), Address, Pte, Process, LockIrql, &PageBlock);

        ASSERT(NT_SUCCESS(Status));

        if (InPageBlock != NULL)
        {
            /* Another thread is reading or writing this page. Put us into the waiting queue. */
            KeInitializeEvent(&CurrentPageEvent, NotificationEvent, FALSE);
            PreviousPageEvent = *InPageBlock;
            *InPageBlock = &CurrentPageEvent;
        }

        /* And now release the lock and leave*/
        MiUnlockPfnDb(LockIrql, APC_LEVEL);

        if (InPageBlock != NULL)
        {
            KeWaitForSingleObject(&CurrentPageEvent, WrPageIn, KernelMode, FALSE, NULL);

            /* Let's the chain go on */
            if (PreviousPageEvent)
            {
                KeSetEvent(PreviousPageEvent, IO_NO_INCREMENT, FALSE);
            }
        }

        ASSERT(OldIrql == KeGetCurrentIrql());
        ASSERT(OldIrql <= APC_LEVEL);
        ASSERT(KeAreAllApcsDisabled() == TRUE);
        return Status;
    }

    /* Should we page the data back in ? */
    if (TempPte.u.Soft.PageFileHigh != 0)
    {
        /* Lock the PFN database */
        LockIrql = MiLockPfnDb(APC_LEVEL);

        /* Resolve */
        Status = MiResolvePageFileFault(!MI_IS_NOT_PRESENT_FAULT(FaultCode),
                                        Address,
                                        Pte,
                                        &OriginalPte,
                                        &PageBlock,
                                        Process,
                                        &LockIrql);

        /* And now release the lock and leave*/
        MiUnlockPfnDb(LockIrql, APC_LEVEL);

        ASSERT(OldIrql == KeGetCurrentIrql());
        ASSERT(OldIrql <= APC_LEVEL);
        ASSERT(KeAreAllApcsDisabled() == TRUE);
        return Status;
    }

    //
    // The PTE must be invalid but not completely empty. It must also not be a
    // prototype a transition or a paged-out PTE as those scenarii should've been handled above.
    // These are all Windows checks
    //
    ASSERT(TempPte.u.Hard.Valid == 0);
    ASSERT(TempPte.u.Soft.Prototype == 0);
    ASSERT(TempPte.u.Soft.Transition == 0);
    ASSERT(TempPte.u.Soft.PageFileHigh == 0);
    ASSERT(TempPte.u.Long != 0);

    //
    // If we got this far, the PTE can only be a demand zero PTE, which is what
    // we want. Go handle it!
    //
    Status = MiResolveDemandZeroFault(Address,
                                      Pte,
                                      (ULONG)TempPte.u.Soft.Protection,
                                      Process,
                                      MM_NOIRQL);
    ASSERT(KeAreAllApcsDisabled() == TRUE);
    if (NT_SUCCESS(Status))
    {
        //
        // Make sure we're returning in a sane state and pass the status down
        //
        ASSERT(OldIrql == KeGetCurrentIrql());
        ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
        return Status;
    }

    //
    // Generate an access fault
    //
    return STATUS_ACCESS_VIOLATION;
}

extern BOOLEAN Mmi386MakeKernelPageTableGlobal(PVOID Address);

NTSTATUS
NTAPI
MmAccessFault(IN ULONG FaultCode,
              IN PVOID Address,
              IN KPROCESSOR_MODE Mode,
              IN PVOID TrapInformation)
{
    KIRQL OldIrql = KeGetCurrentIrql(), WsLockIrql;
    KIRQL PfnLockIrql;
    PMMPTE SectionProto = NULL;
    PMMPTE Pte = MiAddressToPte(Address);
    PMMPDE Pde = MiAddressToPde(Address);
#if (_MI_PAGING_LEVELS >= 3)
    PMMPDE PointerPpe = MiAddressToPpe(Address);
#if (_MI_PAGING_LEVELS == 4)
    PMMPDE PointerPxe = MiAddressToPxe(Address);
#endif
#endif
    MMPTE TempPte;
    PETHREAD CurrentThread;
    PEPROCESS CurrentProcess;
    NTSTATUS Status;
    PMMSUPPORT WorkingSet;
    ULONG ProtectionCode;
    PMMVAD Vad = NULL;
    PFN_NUMBER PageFrameIndex;
    ULONG Color;
    BOOLEAN IsSessionAddress;
    PMMPFN Pfn1;
    ULONG PagesCount;

    DPRINT("MmAccessFault: Code %X, Address %p, Pde %p [%p], Pte %p [%p], Mode %X, TrapInfo %p\n", FaultCode, Address, Pde, Pde->u.Long, Pte, Pte->u.Long, Mode, TrapInformation);

    /* Cute little hack for ROS */
    if ((ULONG_PTR)Address >= (ULONG_PTR)MmSystemRangeStart)
    {
#ifdef _M_IX86
        /* Check for an invalid page directory in kernel mode */
        if (Mmi386MakeKernelPageTableGlobal(Address))
        {
            /* All is well with the world */
            ASSERT(0);return STATUS_SUCCESS;
        }
#endif
    }

    /* Check for page fault on high IRQL */
    if (OldIrql > APC_LEVEL)
    {
#if (_MI_PAGING_LEVELS < 3)
        /* Could be a page table for paged pool, which we'll allow */
        if (MI_IS_SYSTEM_PAGE_TABLE_ADDRESS(Address)) MiSynchronizeSystemPde((PMMPDE)Pte);
        MiCheckPdeForPagedPool(Address);
#endif
        /* Check if any of the top-level pages are invalid */
        if (
#if (_MI_PAGING_LEVELS == 4)
            (PointerPxe->u.Hard.Valid == 0) ||
#endif
#if (_MI_PAGING_LEVELS >= 3)
            (PointerPpe->u.Hard.Valid == 0) ||
#endif
            (Pde->u.Hard.Valid == 0) ||
            (Pte->u.Hard.Valid == 0))
        {
            /* This fault is not valid, print out some debugging help */
            DbgPrint("MM:***PAGE FAULT AT IRQL > 1  Va %p, IRQL %lx\n",
                     Address,
                     OldIrql);
            if (TrapInformation)
            {
                PKTRAP_FRAME TrapFrame = TrapInformation;
#ifdef _M_IX86
                DbgPrint("MM:***EIP %p, EFL %p\n", TrapFrame->Eip, TrapFrame->EFlags);
                DbgPrint("MM:***EAX %p, ECX %p EDX %p\n", TrapFrame->Eax, TrapFrame->Ecx, TrapFrame->Edx);
                DbgPrint("MM:***EBX %p, ESI %p EDI %p\n", TrapFrame->Ebx, TrapFrame->Esi, TrapFrame->Edi);
#elif defined(_M_AMD64)
                DbgPrint("MM:***RIP %p, EFL %p\n", TrapFrame->Rip, TrapFrame->EFlags);
                DbgPrint("MM:***RAX %p, RCX %p RDX %p\n", TrapFrame->Rax, TrapFrame->Rcx, TrapFrame->Rdx);
                DbgPrint("MM:***RBX %p, RSI %p RDI %p\n", TrapFrame->Rbx, TrapFrame->Rsi, TrapFrame->Rdi);
#elif defined(_M_ARM)
                DbgPrint("MM:***PC %p\n", TrapFrame->Pc);
                DbgPrint("MM:***R0 %p, R1 %p R2 %p, R3 %p\n", TrapFrame->R0, TrapFrame->R1, TrapFrame->R2, TrapFrame->R3);
                DbgPrint("MM:***R11 %p, R12 %p SP %p, LR %p\n", TrapFrame->R11, TrapFrame->R12, TrapFrame->Sp, TrapFrame->Lr);
#endif
            }

            /* Tell the trap handler to fail */
            DPRINT1("MmAccessFault: return %X\n", STATUS_IN_PAGE_ERROR | 0x10000000);
            return STATUS_IN_PAGE_ERROR | 0x10000000;
        }

        /* Not yet implemented in ReactOS */
        ASSERT(MI_IS_PAGE_LARGE(Pde) == FALSE);
        ASSERT((!MI_IS_NOT_PRESENT_FAULT(FaultCode) && MI_IS_PAGE_COPY_ON_WRITE(Pte)) == FALSE);

        /* Check if this was a write */
        if (MI_IS_WRITE_ACCESS(FaultCode))
        {
            /* Was it to a read-only page? */
            Pfn1 = MI_PFN_ELEMENT(Pte->u.Hard.PageFrameNumber);
            if (!(Pte->u.Long & PTE_READWRITE) &&
                !(Pfn1->OriginalPte.u.Soft.Protection & MM_READWRITE))
            {
                /* Crash with distinguished bugcheck code */
                KeBugCheckEx(ATTEMPTED_WRITE_TO_READONLY_MEMORY,
                             (ULONG_PTR)Address,
                             Pte->u.Long,
                             (ULONG_PTR)TrapInformation,
                             10);
            }
        }

        /* Nothing is actually wrong */
        DPRINT1("Fault at IRQL %u is ok (%p)\n", OldIrql, Address);
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

#if (_MI_PAGING_LEVELS == 2)
        if (MI_IS_SYSTEM_PAGE_TABLE_ADDRESS(Address)) MiSynchronizeSystemPde((PMMPDE)Pte);
        MiCheckPdeForPagedPool(Address);
#endif

        /* Check if the higher page table entries are invalid */
        if (
#if (_MI_PAGING_LEVELS == 4)
            /* AMD64 system, check if PXE is invalid */
            (PointerPxe->u.Hard.Valid == 0) ||
#endif
#if (_MI_PAGING_LEVELS >= 3)
            /* PAE/AMD64 system, check if PPE is invalid */
            (PointerPpe->u.Hard.Valid == 0) ||
#endif
            /* Always check if the PDE is valid */
            (Pde->u.Hard.Valid == 0))
        {
            /* PXE/PPE/PDE (still) not valid, kill the system */
            KeBugCheckEx(PAGE_FAULT_IN_NONPAGED_AREA,
                         (ULONG_PTR)Address,
                         FaultCode,
                         (ULONG_PTR)TrapInformation,
                         2);
        }

        /* Not handling session faults yet */
        IsSessionAddress = MI_IS_SESSION_ADDRESS(Address);

        /* The PDE is valid, so read the PTE */
        TempPte = *Pte;
        if (TempPte.u.Hard.Valid == 1)
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
                        Pfn1 = MI_PFN_ELEMENT(Pte->u.Hard.PageFrameNumber);
                        if (!(Pte->u.Long & PTE_READWRITE) &&
                            !(Pfn1->OriginalPte.u.Soft.Protection & MM_READWRITE))
                        {
                            /* Crash with distinguished bugcheck code */
                            KeBugCheckEx(ATTEMPTED_WRITE_TO_READONLY_MEMORY,
                                         (ULONG_PTR)Address,
                                         Pte->u.Long,
                                         (ULONG_PTR)TrapInformation,
                                         11);
                        }
                    }

                    /* Check for execution of non-executable memory */
                    if (MI_IS_INSTRUCTION_FETCH(FaultCode) &&
                        !MI_IS_PAGE_EXECUTABLE(&TempPte))
                    {
                        KeBugCheckEx(ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY,
                                     (ULONG_PTR)Address,
                                     (ULONG_PTR)TempPte.u.Long,
                                     (ULONG_PTR)TrapInformation,
                                     1);
                    }
                }

                /* Release PFN lock and return all good */
                MiUnlockPfnDb(PfnLockIrql, APC_LEVEL);
                DPRINT("MmAccessFault: return STATUS_SUCCESS\n");
                return STATUS_SUCCESS;
            }
        }
#if (_MI_PAGING_LEVELS == 2)
        /* Check if this was a session PTE that needs to remap the session PDE */
        if (MI_IS_SESSION_PTE(Address))
        {
            /* Do the remapping */
            Status = MiCheckPdeForSessionSpace(Address);
            if (!NT_SUCCESS(Status))
            {
                /* It failed, this address is invalid */
                KeBugCheckEx(PAGE_FAULT_IN_NONPAGED_AREA,
                             (ULONG_PTR)Address,
                             FaultCode,
                             (ULONG_PTR)TrapInformation,
                             6);
            }
        }
#else

_WARN("Session space stuff is not implemented yet!")

#endif

        /* Check for a fault on the page table or hyperspace */
        if (MI_IS_PAGE_TABLE_OR_HYPER_ADDRESS(Address))
        {
#if (_MI_PAGING_LEVELS < 3)
            /* Windows does this check but I don't understand why -- it's done above! */
            ASSERT(MiCheckPdeForPagedPool(Address) != STATUS_WAIT_1);
#endif
            /* Handle this as a user mode fault */
            goto UserFault;
        }

        /* Get the current thread */
        CurrentThread = PsGetCurrentThread();

        /* What kind of address is this */
        if (!IsSessionAddress)
        {
            /* Use the system working set */
            WorkingSet = &MmSystemCacheWs;
            CurrentProcess = NULL;

            /* Make sure we don't have a recursive working set lock */
            if ((CurrentThread->OwnsProcessWorkingSetExclusive) ||
                (CurrentThread->OwnsProcessWorkingSetShared) ||
                (CurrentThread->OwnsSystemWorkingSetExclusive) ||
                (CurrentThread->OwnsSystemWorkingSetShared) ||
                (CurrentThread->OwnsSessionWorkingSetExclusive) ||
                (CurrentThread->OwnsSessionWorkingSetShared))
            {
                /* Fail */
                DPRINT1("MmAccessFault: return %X\n", STATUS_IN_PAGE_ERROR | 0x10000000);
                return STATUS_IN_PAGE_ERROR | 0x10000000;
            }
        }
        else
        {
            /* Use the session process and working set */
            CurrentProcess = HYDRA_PROCESS;
            WorkingSet = &MmSessionSpace->GlobalVirtualAddress->Vm;

            /* Make sure we don't have a recursive working set lock */
            if ((CurrentThread->OwnsSessionWorkingSetExclusive) ||
                (CurrentThread->OwnsSessionWorkingSetShared))
            {
                /* Fail */
                DPRINT1("MmAccessFault: return %X\n", STATUS_IN_PAGE_ERROR | 0x10000000);
                return STATUS_IN_PAGE_ERROR | 0x10000000;
            }
        }

        /* Acquire the working set lock */
        KeRaiseIrql(APC_LEVEL, &WsLockIrql);
        MiLockWorkingSet(CurrentThread, WorkingSet);

        /* Re-read PTE now that we own the lock */
        TempPte = *Pte;
        if (TempPte.u.Hard.Valid == 1)
        {
            /* Check if this was a write */
            if (MI_IS_WRITE_ACCESS(FaultCode))
            {
                /* Was it to a read-only page that is not copy on write? */
                Pfn1 = MI_PFN_ELEMENT(Pte->u.Hard.PageFrameNumber);
                if (!(TempPte.u.Long & PTE_READWRITE) &&
                    !(Pfn1->OriginalPte.u.Soft.Protection & MM_READWRITE) &&
                    !MI_IS_PAGE_COPY_ON_WRITE(&TempPte))
                {
                    /* Case not yet handled */
                    ASSERT(!IsSessionAddress);

                    /* Crash with distinguished bugcheck code */
                    KeBugCheckEx(ATTEMPTED_WRITE_TO_READONLY_MEMORY,
                                 (ULONG_PTR)Address,
                                 TempPte.u.Long,
                                 (ULONG_PTR)TrapInformation,
                                 12);
                }
            }

            /* Check for execution of non-executable memory */
            if (MI_IS_INSTRUCTION_FETCH(FaultCode) &&
                !MI_IS_PAGE_EXECUTABLE(&TempPte))
            {
                KeBugCheckEx(ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY,
                             (ULONG_PTR)Address,
                             (ULONG_PTR)TempPte.u.Long,
                             (ULONG_PTR)TrapInformation,
                             2);
            }

            /* Check for read-only write in session space */
            if ((IsSessionAddress) &&
                MI_IS_WRITE_ACCESS(FaultCode) &&
                !MI_IS_PAGE_WRITEABLE(&TempPte))
            {
                /* Sanity check */
                ASSERT(MI_IS_SESSION_IMAGE_ADDRESS(Address));

                /* Was this COW? */
                if (!MI_IS_PAGE_COPY_ON_WRITE(&TempPte))
                {
                    /* Then this is not allowed */
                    KeBugCheckEx(ATTEMPTED_WRITE_TO_READONLY_MEMORY,
                                 (ULONG_PTR)Address,
                                 (ULONG_PTR)TempPte.u.Long,
                                 (ULONG_PTR)TrapInformation,
                                 13);
                }

                /* Otherwise, handle COW */
                ASSERT(FALSE);
            }

            /* Release the working set */
            MiUnlockWorkingSet(CurrentThread, WorkingSet);
            KeLowerIrql(WsLockIrql);

            /* Otherwise, the PDE was probably invalid, and all is good now */
            DPRINT("MmAccessFault: return STATUS_SUCCESS\n");
            return STATUS_SUCCESS;
        }

        /* Check one kind of prototype PTE */
        if (TempPte.u.Soft.Prototype)
        {
            /* Make sure protected pool is on, and that this is a pool address */
            if ((MmProtectFreedNonPagedPool) &&
                (((Address >= MmNonPagedPoolStart) &&
                  (Address < (PVOID)((ULONG_PTR)MmNonPagedPoolStart +
                                     MmSizeOfNonPagedPoolInBytes))) ||
                 ((Address >= MmNonPagedPoolExpansionStart) &&
                  (Address < MmNonPagedPoolEnd))))
            {
                /* Bad boy, bad boy, whatcha gonna do, whatcha gonna do when ARM3 comes for you! */
                KeBugCheckEx(DRIVER_CAUGHT_MODIFYING_FREED_POOL,
                             (ULONG_PTR)Address,
                             FaultCode,
                             Mode,
                             4);
            }

            /* Get the prototype PTE! */
            SectionProto = MiGetProtoPtr(&TempPte);

            /* Do we need to locate the prototype PTE in session space? */
            if ((IsSessionAddress) &&
                (TempPte.u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED))
            {
                /* Yep, go find it as well as the VAD for it */
                SectionProto = MiCheckVirtualAddress(Address,
                                                     &ProtectionCode,
                                                     &Vad);
                ASSERT(SectionProto != NULL);
            }
        }
        else
        {
            /* We don't implement transition PTEs */
            ASSERT(TempPte.u.Soft.Transition == 0);

            /* Check for no-access PTE */
            if (TempPte.u.Soft.Protection == MM_NOACCESS)
            {
                /* Bugcheck the system! */
                KeBugCheckEx(PAGE_FAULT_IN_NONPAGED_AREA,
                             (ULONG_PTR)Address,
                             FaultCode,
                             (ULONG_PTR)TrapInformation,
                             1);
            }

            /* Check for no protecton at all */
            if (TempPte.u.Soft.Protection == MM_ZERO_ACCESS)
            {
                /* Bugcheck the system! */
                KeBugCheckEx(PAGE_FAULT_IN_NONPAGED_AREA,
                             (ULONG_PTR)Address,
                             FaultCode,
                             (ULONG_PTR)TrapInformation,
                             0);
            }
        }

        /* Check for demand page */
        if (MI_IS_WRITE_ACCESS(FaultCode) &&
            !(SectionProto) &&
            !(IsSessionAddress) &&
            !(TempPte.u.Hard.Valid))
        {
            /* Get the protection code */
            ASSERT(TempPte.u.Soft.Transition == 0);
            if (!(TempPte.u.Soft.Protection & MM_READWRITE))
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
                                 CurrentProcess,
                                 TrapInformation,
                                 NULL);

        /* Release the working set */
        ASSERT(KeAreAllApcsDisabled() == TRUE);
        MiUnlockWorkingSet(CurrentThread, WorkingSet);
        KeLowerIrql(WsLockIrql);

        /* We are done! */
        DPRINT("MmAccessFault: Fault resolved with status: %lx\n", Status);
        goto Exit1;
    }

    /* This is a user fault */
UserFault:
    CurrentThread = PsGetCurrentThread();
    CurrentProcess = (PEPROCESS)CurrentThread->Tcb.ApcState.Process;

    ASSERT(MmAvailablePages >= 256);

    /* Lock the working set */
    MiLockProcessWorkingSet(CurrentProcess, CurrentThread);

    ProtectionCode = MM_INVALID_PROTECTION;

#if (_MI_PAGING_LEVELS == 4)
    /* Check if the PXE is valid */
    if (PointerPxe->u.Hard.Valid == 0)
    {
        /* Right now, we only handle scenarios where the PXE is totally empty */
        ASSERT(PointerPxe->u.Long == 0);

        /* This is only possible for user mode addresses! */
        ASSERT(Pte <= MiHighestUserPte);

        /* Check if we have a VAD */
        MiCheckVirtualAddress(Address, &ProtectionCode, &Vad);
        if (ProtectionCode == MM_NOACCESS)
        {
            MiUnlockProcessWorkingSet(CurrentProcess, CurrentThread);
            DPRINT1("MmAccessFault: return STATUS_ACCESS_VIOLATION\n");
            return STATUS_ACCESS_VIOLATION;
        }

        /* Resolve a demand zero fault */
        MiResolveDemandZeroFault(PointerPpe,
                                 PointerPxe,
                                 MM_READWRITE,
                                 CurrentProcess,
                                 MM_NOIRQL);

        /* We should come back with a valid PXE */
        ASSERT(PointerPxe->u.Hard.Valid == 1);
    }
#endif

#if (_MI_PAGING_LEVELS >= 3)
    /* Check if the PPE is valid */
    if (PointerPpe->u.Hard.Valid == 0)
    {
        /* Right now, we only handle scenarios where the PPE is totally empty */
        ASSERT(PointerPpe->u.Long == 0);

        /* This is only possible for user mode addresses! */
        ASSERT(Pte <= MiHighestUserPte);

        /* Check if we have a VAD, unless we did this already */
        if (ProtectionCode == MM_INVALID_PROTECTION)
        {
            MiCheckVirtualAddress(Address, &ProtectionCode, &Vad);
        }

        if (ProtectionCode == MM_NOACCESS)
        {
            MiUnlockProcessWorkingSet(CurrentProcess, CurrentThread);
            DPRINT1("MmAccessFault: STATUS_ACCESS_VIOLATION\n");
            return STATUS_ACCESS_VIOLATION;
        }

        /* Resolve a demand zero fault */
        MiResolveDemandZeroFault(Pde,
                                 PointerPpe,
                                 MM_READWRITE,
                                 CurrentProcess,
                                 MM_NOIRQL);

        /* We should come back with a valid PPE */
        ASSERT(PointerPpe->u.Hard.Valid == 1);
    }
#endif

    /* Check if the PDE is invalid */
    if (Pde->u.Hard.Valid == 0)
    {
        /* Right now, we only handle scenarios where the PDE is totally empty */
        ASSERT(Pde->u.Long == 0);

        /* And go dispatch the fault on the PDE. This should handle the demand-zero */
#if MI_TRACE_PFNS
        UserPdeFault = TRUE;
#endif
        /* Check if we have a VAD, unless we did this already */
        if (ProtectionCode == MM_INVALID_PROTECTION)
        {
            MiCheckVirtualAddress(Address, &ProtectionCode, &Vad);
        }

        if (ProtectionCode == MM_NOACCESS)
        {
#if (_MI_PAGING_LEVELS == 2)
            /* Could be a page table for paged pool */
            MiCheckPdeForPagedPool(Address);
#endif
            /* Has the code above changed anything -- is this now a valid PTE? */
            Status = (Pde->u.Hard.Valid == 1) ? STATUS_SUCCESS : STATUS_ACCESS_VIOLATION;

            /* Either this was a bogus VA or we've fixed up a paged pool PDE */
            MiUnlockProcessWorkingSet(CurrentProcess, CurrentThread);
            DPRINT1("MmAccessFault: return Status %X\n", Status);
            return Status;
        }

        /* Resolve a demand zero fault */
        MiResolveDemandZeroFault(Pte,
                                 Pde,
                                 MM_READWRITE,
                                 CurrentProcess,
                                 MM_NOIRQL);
#if MI_TRACE_PFNS
        UserPdeFault = FALSE;
#endif
        /* We should come back with APCs enabled, and with a valid PDE */
        ASSERT(KeAreAllApcsDisabled() == TRUE);
        ASSERT(Pde->u.Hard.Valid == 1);
    }
    else
    {
        /* Not yet implemented in ReactOS */
        ASSERT(MI_IS_PAGE_LARGE(Pde) == FALSE);
    }

    /* Now capture the PTE. */
    TempPte = *Pte;
    DPRINT("MmAccessFault: Pte %p [%p]\n", Pte, TempPte);

    /* Check if the PTE is valid */
    if (TempPte.u.Hard.Valid)
    {
        ASSERT(FALSE);

        goto Exit2;
    }

    /* Quick check for demand-zero */
    if (TempPte.u.Long == (MM_READWRITE << MM_PTE_SOFTWARE_PROTECTION_BITS))
    {
        /* Resolve the fault */
        MiResolveDemandZeroFault(Address,
                                 Pte,
                                 MM_READWRITE,
                                 CurrentProcess,
                                 MM_NOIRQL);

        /* Return the status */
        DPRINT1("MmAccessFault: return STATUS_PAGE_FAULT_DEMAND_ZERO\n");
        Status = STATUS_PAGE_FAULT_DEMAND_ZERO;
        goto Exit3;
    }

    /* Check for zero PTE */
    if (TempPte.u.Long == 0)
    {
        /* Check if this address range belongs to a valid allocation (VAD) */
        SectionProto = MiCheckVirtualAddress(Address, &ProtectionCode, &Vad);
        DPRINT("MmAccessFault: SectionProto %p, ProtectionCode %X\n", SectionProto, ProtectionCode);

        if (ProtectionCode == MM_NOACCESS)
        {
#if (_MI_PAGING_LEVELS == 2)
            /* Could be a page table for paged pool */
            MiCheckPdeForPagedPool(Address);
#endif
            /* Has the code above changed anything -- is this now a valid PTE? */
            Status = (Pte->u.Hard.Valid == 1) ? STATUS_SUCCESS : STATUS_ACCESS_VIOLATION;

            /* Either this was a bogus VA or we've fixed up a paged pool PDE */
            DPRINT1("MmAccessFault: return Status %X\n", Status);
            goto Exit2;
        }

        if ((ProtectionCode & MM_PROTECT_SPECIAL) == MM_GUARDPAGE)
        {
            if (KeInvalidAccessAllowed(TrapInformation))
            {
                Status = STATUS_ACCESS_VIOLATION;
                goto Exit2;
            }
        }

        /*
         * Check if this is a real user-mode address or actually a kernel-mode
         * page table for a user mode address
         */
        if (Address <= MM_HIGHEST_USER_ADDRESS)
        {
            /* Add an additional page table reference */
            MiIncrementPageTableReferences(Address);
        }

        /* Is this a guard page? */
        if ((ProtectionCode & MM_PROTECT_SPECIAL) == MM_GUARDPAGE)
        {
            /* The VAD protection cannot be MM_DECOMMIT! */
            ASSERT(ProtectionCode != MM_DECOMMIT);

            /* Remove the bit */
            TempPte.u.Soft.Protection = ProtectionCode & ~MM_GUARDPAGE;
            MI_WRITE_INVALID_PTE(Pte, TempPte);

            /* Not supported */
            ASSERT(SectionProto == NULL);
            ASSERT(CurrentThread->ApcNeeded == 0);

            /* Drop the working set lock */
            MiUnlockProcessWorkingSet(CurrentProcess, CurrentThread);
            ASSERT(KeGetCurrentIrql() == OldIrql);

            /* Handle stack expansion */
            Status = MiCheckForUserStackOverflow(Address, TrapInformation);
            DPRINT1("MmAccessFault: return Status %X\n", Status);
            return Status;
        }

        /* Did we get a prototype PTE back? */
        if (!SectionProto)
        {
            /* Is this PTE actually part of the PDE-PTE self-mapping directory? */
            if (Pde == MiAddressToPde(PTE_BASE))
            {
                /* Then it's really a demand-zero PDE (on behalf of user-mode) */
#ifdef _M_ARM
                _WARN("This is probably completely broken!");
                MI_WRITE_INVALID_PDE((PMMPDE)Pte, DemandZeroPde);
#else
                MI_WRITE_INVALID_PTE(Pte, DemandZeroPde);
#endif
            }
            else
            {
                /* No, create a new PTE. First, write the protection */
                TempPte.u.Soft.Protection = ProtectionCode;
                MI_WRITE_INVALID_PTE(Pte, TempPte);
            }

            /* Lock the PFN database since we're going to grab a page */
            PfnLockIrql = MiLockPfnDb(APC_LEVEL);

            /* Make sure we have enough pages */
            ASSERT(MmAvailablePages >= 32);

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
            MiInitializePfn(PageFrameIndex, Pte, 1);

            /* Increment the count of pages in the process */
            CurrentProcess->NumberOfPrivatePages++;

            /* One more demand-zero fault */
            KeGetCurrentPrcb()->MmDemandZeroCount++;

            /* And we're done with the lock */
            MiUnlockPfnDb(PfnLockIrql, APC_LEVEL);

            /* Fault on user PDE, or fault on user PTE? */
            if (Pte <= MiHighestUserPte)
            {
                /* User fault, build a user PTE */
                MI_MAKE_HARDWARE_PTE_USER(&TempPte,
                                          Pte,
                                          Pte->u.Soft.Protection,
                                          PageFrameIndex);
            }
            else
            {
                /* This is a user-mode PDE, create a kernel PTE for it */
                MI_MAKE_HARDWARE_PTE(&TempPte,
                                     Pte,
                                     Pte->u.Soft.Protection,
                                     PageFrameIndex);
            }

            /* Write the dirty bit for writeable pages */
            if (MI_IS_PAGE_WRITEABLE(&TempPte)) MI_MAKE_DIRTY_PAGE(&TempPte);

            /* And now write down the PTE, making the address valid */
            MI_WRITE_VALID_PTE(Pte, TempPte);
            Pfn1 = MI_PFN_ELEMENT(PageFrameIndex);
            ASSERT(Pfn1->u1.Event == NULL);

            /* Demand zero */
            ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
            MiUnlockProcessWorkingSet(CurrentProcess, CurrentThread);
            DPRINT1("MmAccessFault: return STATUS_PAGE_FAULT_DEMAND_ZERO\n");
            return STATUS_PAGE_FAULT_DEMAND_ZERO;
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
        DPRINT("MmAccessFault: TempPte %p, ProtectionCode %X\n", TempPte.u.Long, ProtectionCode);

        if (TempPte.u.Soft.Prototype)
        {
            /* Do we need to go find the real PTE? */
            if (TempPte.u.Soft.PageFileHigh == MI_PTE_LOOKUP_NEEDED)
            {
                /* Get the prototype pte and VAD for it */
                SectionProto = MiCheckVirtualAddress(Address,
                                                     &ProtectionCode,
                                                     &Vad);
                if (!SectionProto)
                {
                    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
                    MiUnlockProcessWorkingSet(CurrentProcess, CurrentThread);
                    DPRINT1("MmAccessFault: return STATUS_ACCESS_VIOLATION\n");
                    return STATUS_ACCESS_VIOLATION;
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
                    ASSERT(CurrentProcess->CloneRoot != NULL);
                }
            }
        }
    }

    /* Do we have a valid protection code? */
    if (ProtectionCode != 0x100)
    {
        /* Run a software access check first, including to detect guard pages */
        Status = MiAccessCheck(Pte,
                               !MI_IS_NOT_PRESENT_FAULT(FaultCode),
                               Mode,
                               ProtectionCode,
                               TrapInformation,
                               FALSE);
        if (Status != STATUS_SUCCESS)
        {
            /* Not supported */
            ASSERT(CurrentThread->ApcNeeded == 0);

            /* Drop the working set lock */
            MiUnlockProcessWorkingSet(CurrentProcess, CurrentThread);
            ASSERT(KeGetCurrentIrql() == OldIrql);

            /* Did we hit a guard page? */
            if (Status == STATUS_GUARD_PAGE_VIOLATION)
            {
                /* Handle stack expansion */
                Status = MiCheckForUserStackOverflow(Address, TrapInformation);
                DPRINT1("MmAccessFault: return Status %X\n", Status);
                return Status;
            }

            /* Otherwise, fail back to the caller directly */
            DPRINT1("MmAccessFault: return Status %X\n", Status);
            return Status;
        }
    }

    /* Dispatch the fault */
    Status = MiDispatchFault(FaultCode,
                             Address,
                             Pte,
                             SectionProto,
                             FALSE,
                             CurrentProcess,
                             TrapInformation,
                             Vad);

    /* Return the status */
    DPRINT1("MmAccessFault: return Status %X\n", Status);

Exit3:

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    if (CurrentProcess->Vm.Flags.GrowWsleHash == 1)
    {
        DPRINT1("MmAccessFault: FIXME MiGrowWsleHash\n");
        ASSERT(FALSE);
    }

Exit2:

    PagesCount = (CurrentProcess->Vm.WorkingSetSize - CurrentProcess->Vm.MinimumWorkingSetSize);
    ASSERT(CurrentThread->ApcNeeded == 0);

    MiUnlockProcessWorkingSet(CurrentProcess, CurrentThread);

    ASSERT(KeGetCurrentIrql() == OldIrql);

    if (MmAvailablePages < 1024 &&
        PagesCount > 100 &&
        KeGetCurrentThread()->Priority >= 16)
    {
        KeDelayExecutionThread(KernelMode, FALSE, &MmShortTime);
    }

Exit1:

    if (Status == STATUS_SUCCESS)
    {
        return Status;
    }

    if (!NT_SUCCESS(Status))
    {
        if (Status == STATUS_INSUFFICIENT_RESOURCES ||
            Status == STATUS_WORKING_SET_QUOTA ||
            Status == STATUS_NO_MEMORY)
        {
            DPRINT1("MmAccessFault: Status: %X\n", Status);
            KeDelayExecutionThread(KernelMode, FALSE, &MmShortTime);
            Status = STATUS_SUCCESS;
        }
    }

    if (Status != STATUS_SUCCESS)
    {
        DPRINT("MmAccessFault: FIXME MmPageFaultNotifyRoutine\n");
    }

    return Status;
}

NTSTATUS
NTAPI
MmGetExecuteOptions(IN PULONG ExecuteOptions)
{
    PKPROCESS CurrentProcess = &PsGetCurrentProcess()->Pcb;
    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    *ExecuteOptions = 0;

    if (CurrentProcess->Flags.ExecuteDisable)
    {
        *ExecuteOptions |= MEM_EXECUTE_OPTION_DISABLE;
    }

    if (CurrentProcess->Flags.ExecuteEnable)
    {
        *ExecuteOptions |= MEM_EXECUTE_OPTION_ENABLE;
    }

    if (CurrentProcess->Flags.DisableThunkEmulation)
    {
        *ExecuteOptions |= MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION;
    }

    if (CurrentProcess->Flags.Permanent)
    {
        *ExecuteOptions |= MEM_EXECUTE_OPTION_PERMANENT;
    }

    if (CurrentProcess->Flags.ExecuteDispatchEnable)
    {
        *ExecuteOptions |= MEM_EXECUTE_OPTION_EXECUTE_DISPATCH_ENABLE;
    }

    if (CurrentProcess->Flags.ImageDispatchEnable)
    {
        *ExecuteOptions |= MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
MmSetExecuteOptions(IN ULONG ExecuteOptions)
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
    KiAcquireProcessLock(CurrentProcess, &ProcessLock);

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

/* EOF */
