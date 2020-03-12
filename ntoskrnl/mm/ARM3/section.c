/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            ntoskrnl/mm/ARM3/section.c
 * PURPOSE:         ARM Memory Manager Section Support
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
//#define NDEBUG
#include <debug.h>

#define MODULE_INVOLVED_IN_ARM3
#include <mm/ARM3/miarm.h>

/* GLOBALS ********************************************************************/

ACCESS_MASK MmMakeSectionAccess[8] =
{
    SECTION_MAP_READ,
    SECTION_MAP_READ,
    SECTION_MAP_EXECUTE,
    SECTION_MAP_EXECUTE | SECTION_MAP_READ,
    SECTION_MAP_WRITE,
    SECTION_MAP_READ,
    SECTION_MAP_EXECUTE | SECTION_MAP_WRITE,
    SECTION_MAP_EXECUTE | SECTION_MAP_READ
};

ACCESS_MASK MmMakeFileAccess[8] =
{
    FILE_READ_DATA,
    FILE_READ_DATA,
    FILE_EXECUTE,
    FILE_EXECUTE | FILE_READ_DATA,
    FILE_WRITE_DATA | FILE_READ_DATA,
    FILE_READ_DATA,
    FILE_EXECUTE | FILE_WRITE_DATA | FILE_READ_DATA,
    FILE_EXECUTE | FILE_READ_DATA
};

CHAR MmUserProtectionToMask1[16] =
{
    0,
    MM_NOACCESS,
    MM_READONLY,
    (CHAR)MM_INVALID_PROTECTION,
    MM_READWRITE,
    (CHAR)MM_INVALID_PROTECTION,
    (CHAR)MM_INVALID_PROTECTION,
    (CHAR)MM_INVALID_PROTECTION,
    MM_WRITECOPY,
    (CHAR)MM_INVALID_PROTECTION,
    (CHAR)MM_INVALID_PROTECTION,
    (CHAR)MM_INVALID_PROTECTION,
    (CHAR)MM_INVALID_PROTECTION,
    (CHAR)MM_INVALID_PROTECTION,
    (CHAR)MM_INVALID_PROTECTION,
    (CHAR)MM_INVALID_PROTECTION
};

CHAR MmUserProtectionToMask2[16] =
{
    0,
    MM_EXECUTE,
    MM_EXECUTE_READ,
    (CHAR)MM_INVALID_PROTECTION,
    MM_EXECUTE_READWRITE,
    (CHAR)MM_INVALID_PROTECTION,
    (CHAR)MM_INVALID_PROTECTION,
    (CHAR)MM_INVALID_PROTECTION,
    MM_EXECUTE_WRITECOPY,
    (CHAR)MM_INVALID_PROTECTION,
    (CHAR)MM_INVALID_PROTECTION,
    (CHAR)MM_INVALID_PROTECTION,
    (CHAR)MM_INVALID_PROTECTION,
    (CHAR)MM_INVALID_PROTECTION,
    (CHAR)MM_INVALID_PROTECTION,
    (CHAR)MM_INVALID_PROTECTION
};

ULONG MmCompatibleProtectionMask[8] =
{
    PAGE_NOACCESS,

    PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY,

    PAGE_NOACCESS | PAGE_EXECUTE,

    PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY | PAGE_EXECUTE |
    PAGE_EXECUTE_READ,

    PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY | PAGE_READWRITE,

    PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY,

    PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY | PAGE_READWRITE |
    PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
    PAGE_EXECUTE_WRITECOPY,

    PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY | PAGE_EXECUTE |
    PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY
};

MMSESSION MmSession;
KGUARDED_MUTEX MmSectionCommitMutex;
MM_AVL_TABLE MmSectionBasedRoot;
KGUARDED_MUTEX MmSectionBasedMutex;
PVOID MmHighSectionBase;
ULONG MmUnusedSegmentCount = 0;
ULONG MmUnusedSubsectionCount = 0;
ULONG MmUnusedSubsectionCountPeak = 0;
SIZE_T MiUnusedSubsectionPagedPool;
LIST_ENTRY MmUnusedSubsectionList;

/* PRIVATE FUNCTIONS **********************************************************/

BOOLEAN
NTAPI
MiIsProtectionCompatible(IN ULONG SectionPageProtection,
                         IN ULONG NewSectionPageProtection)
{
    ULONG ProtectionMask, CompatibleMask;

    DPRINT("MiIsProtectionCompatible: Protection %X, NewProtection %X\n", SectionPageProtection, NewSectionPageProtection);

    /* Calculate the protection mask and make sure it's valid */
    ProtectionMask = MiMakeProtectionMask(SectionPageProtection);
    if (ProtectionMask == MM_INVALID_PROTECTION)
    {
        DPRINT1("Invalid protection mask\n");
        return FALSE;
    }

    /* Calculate the compatible mask */
    CompatibleMask = MmCompatibleProtectionMask[ProtectionMask & 0x7] |
                     PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;

    /* See if the mapping protection is compatible with the create protection */
    return ((CompatibleMask | NewSectionPageProtection) == CompatibleMask);
}

ACCESS_MASK
NTAPI
MiArm3GetCorrectFileAccessMask(IN ACCESS_MASK SectionPageProtection)
{
    ULONG ProtectionMask;

    ASSERT(FALSE);

    /* Calculate the protection mask and make sure it's valid */
    ProtectionMask = MiMakeProtectionMask(SectionPageProtection);
    if (ProtectionMask == MM_INVALID_PROTECTION)
    {
        DPRINT1("Invalid protection mask\n");
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    /* Now convert it to the required file access */
    return MmMakeFileAccess[ProtectionMask & 0x7];
}

ULONG
NTAPI
MiMakeProtectionMask(IN ULONG Protect)
{
    ULONG Mask1, Mask2, ProtectMask;

    DPRINT("MiMakeProtectionMask: Protect %X\n", Protect);

    /* PAGE_EXECUTE_WRITECOMBINE is theoretically the maximum */
    if (Protect >= (PAGE_WRITECOMBINE * 2)) return MM_INVALID_PROTECTION;

    /*
     * Windows API protection mask can be understood as two bitfields, differing
     * by whether or not execute rights are being requested
     */
    Mask1 = Protect & 0xF;
    Mask2 = (Protect >> 4) & 0xF;

    /* Check which field is there */
    if (!Mask1)
    {
        /* Mask2 must be there, use it to determine the PTE protection */
        if (!Mask2) return MM_INVALID_PROTECTION;
        ProtectMask = MmUserProtectionToMask2[Mask2];
    }
    else
    {
        /* Mask2 should not be there, use Mask1 to determine the PTE mask */
        if (Mask2) return MM_INVALID_PROTECTION;
        ProtectMask = MmUserProtectionToMask1[Mask1];
    }

    /* Make sure the final mask is a valid one */
    if (ProtectMask == MM_INVALID_PROTECTION) return MM_INVALID_PROTECTION;

    /* Check for PAGE_GUARD option */
    if (Protect & PAGE_GUARD)
    {
        /* It's not valid on no-access, nocache, or writecombine pages */
        if ((ProtectMask == MM_NOACCESS) ||
            (Protect & (PAGE_NOCACHE | PAGE_WRITECOMBINE)))
        {
            /* Fail such requests */
            return MM_INVALID_PROTECTION;
        }

        /* This actually turns on guard page in this scenario! */
        ProtectMask |= MM_GUARDPAGE;
    }

    /* Check for nocache option */
    if (Protect & PAGE_NOCACHE)
    {
        /* The earlier check should've eliminated this possibility */
        ASSERT((Protect & PAGE_GUARD) == 0);

        /* Check for no-access page or write combine page */
        if ((ProtectMask == MM_NOACCESS) || (Protect & PAGE_WRITECOMBINE))
        {
            /* Such a request is invalid */
            return MM_INVALID_PROTECTION;
        }

        /* Add the PTE flag */
        ProtectMask |= MM_NOCACHE;
    }

    /* Check for write combine option */
    if (Protect & PAGE_WRITECOMBINE)
    {
        /* The two earlier scenarios should've caught this */
        ASSERT((Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0);

        /* Don't allow on no-access pages */
        if (ProtectMask == MM_NOACCESS) return MM_INVALID_PROTECTION;

        /* This actually turns on write-combine in this scenario! */
        ProtectMask |= MM_NOACCESS;
    }

    /* Return the final MM PTE protection mask */
    return ProtectMask;
}

BOOLEAN
NTAPI
MiInitializeSystemSpaceMap(IN PMMSESSION InputSession OPTIONAL)
{
    SIZE_T AllocSize, BitmapSize, Size;
    PVOID ViewStart;
    PMMSESSION Session;

    DPRINT("MiInitializeSystemSpaceMap: InputSession %p\n", InputSession);

    /* Check if this a session or system space */
    if (InputSession)
    {
        /* Use the input session */
        Session = InputSession;
        ViewStart = MiSessionViewStart;
        Size = MmSessionViewSize;
    }
    else
    {
        /* Use the system space "session" */
        Session = &MmSession;
        ViewStart = MiSystemViewStart;
        Size = MmSystemViewSize;
    }

    /* Initialize the system space lock */
    Session->SystemSpaceViewLockPointer = &Session->SystemSpaceViewLock;
    KeInitializeGuardedMutex(Session->SystemSpaceViewLockPointer);

    /* Set the start address */
    Session->SystemSpaceViewStart = ViewStart;

    /* Create a bitmap to describe system space */
    BitmapSize = sizeof(RTL_BITMAP) + ((((Size / MI_SYSTEM_VIEW_BUCKET_SIZE) + 31) / 32) * sizeof(ULONG));
    Session->SystemSpaceBitMap = ExAllocatePoolWithTag(NonPagedPool,
                                                       BitmapSize,
                                                       TAG_MM);
    ASSERT(Session->SystemSpaceBitMap);
    RtlInitializeBitMap(Session->SystemSpaceBitMap,
                        (PULONG)(Session->SystemSpaceBitMap + 1),
                        (ULONG)(Size / MI_SYSTEM_VIEW_BUCKET_SIZE));

    /* Set system space fully empty to begin with */
    RtlClearAllBits(Session->SystemSpaceBitMap);

    /* Set default hash flags */
    Session->SystemSpaceHashSize = 31;
    Session->SystemSpaceHashKey = Session->SystemSpaceHashSize - 1;
    Session->SystemSpaceHashEntries = 0;

    /* Calculate how much space for the hash views we'll need */
    AllocSize = sizeof(MMVIEW) * Session->SystemSpaceHashSize;
    ASSERT(AllocSize < PAGE_SIZE);

    /* Allocate and zero the view table */
    Session->SystemSpaceViewTable = ExAllocatePoolWithTag(Session == &MmSession ?
                                                          NonPagedPool :
                                                          PagedPool,
                                                          AllocSize,
                                                          TAG_MM);
    ASSERT(Session->SystemSpaceViewTable != NULL);
    RtlZeroMemory(Session->SystemSpaceViewTable, AllocSize);

    /* Success */
    return TRUE;
}

PVOID
NTAPI
MiInsertInSystemSpace(IN PMMSESSION Session,
                      IN ULONG Buckets,
                      IN PCONTROL_AREA ControlArea)
{
    PVOID Base;
    ULONG Entry, Hash, i, HashSize;
    PMMVIEW OldTable;
    PAGED_CODE();

    DPRINT("MiInsertInSystemSpace: Session %p, Buckets %X, ControlArea %p\n", Session, Buckets, ControlArea);

    /* Stay within 4GB */
    ASSERT(Buckets < MI_SYSTEM_VIEW_BUCKET_SIZE);

    /* Lock system space */
    KeAcquireGuardedMutex(Session->SystemSpaceViewLockPointer);

    /* Check if we're going to exhaust hash entries */
    if ((Session->SystemSpaceHashEntries + 8) > Session->SystemSpaceHashSize)
    {
        /* Double the hash size */
        HashSize = Session->SystemSpaceHashSize * 2;

        /* Save the old table and allocate a new one */
        OldTable = Session->SystemSpaceViewTable;
        Session->SystemSpaceViewTable = ExAllocatePoolWithTag(Session ==
                                                              &MmSession ?
                                                              NonPagedPool :
                                                              PagedPool,
                                                              HashSize *
                                                              sizeof(MMVIEW),
                                                              TAG_MM);
        if (!Session->SystemSpaceViewTable)
        {
            /* Failed to allocate a new table, keep the old one for now */
            Session->SystemSpaceViewTable = OldTable;
        }
        else
        {
            /* Clear the new table and set the new ahsh and key */
            RtlZeroMemory(Session->SystemSpaceViewTable, HashSize * sizeof(MMVIEW));
            Session->SystemSpaceHashSize = HashSize;
            Session->SystemSpaceHashKey = Session->SystemSpaceHashSize - 1;

            /* Loop the old table */
            for (i = 0; i < Session->SystemSpaceHashSize / 2; i++)
            {
                /* Check if the entry was valid */
                if (OldTable[i].Entry)
                {
                    /* Re-hash the old entry and search for space in the new table */
                    Hash = (OldTable[i].Entry >> 16) % Session->SystemSpaceHashKey;
                    while (Session->SystemSpaceViewTable[Hash].Entry)
                    {
                        /* Loop back at the beginning if we had an overflow */
                        if (++Hash >= Session->SystemSpaceHashSize) Hash = 0;
                    }

                    /* Write the old entry in the new table */
                    Session->SystemSpaceViewTable[Hash] = OldTable[i];
                }
            }

            /* Free the old table */
            ExFreePool(OldTable);
        }
    }

    /* Check if we ran out */
    if (Session->SystemSpaceHashEntries == Session->SystemSpaceHashSize)
    {
        DPRINT1("Ran out of system view hash entries\n");
        KeReleaseGuardedMutex(Session->SystemSpaceViewLockPointer);
        return NULL;
    }

    /* Find space where to map this view */
    i = RtlFindClearBitsAndSet(Session->SystemSpaceBitMap, Buckets, 0);
    if (i == 0xFFFFFFFF)
    {
        /* Out of space, fail */
        Session->BitmapFailures++;
        DPRINT1("Out of system view space\n");
        KeReleaseGuardedMutex(Session->SystemSpaceViewLockPointer);
        return NULL;
    }

    /* Compute the base address */
    Base = (PVOID)((ULONG_PTR)Session->SystemSpaceViewStart + (i * MI_SYSTEM_VIEW_BUCKET_SIZE));

    /* Get the hash entry for this allocation */
    Entry = ((ULONG_PTR)Base & ~(MI_SYSTEM_VIEW_BUCKET_SIZE - 1)) + Buckets;
    Hash = (Entry >> 16) % Session->SystemSpaceHashKey;

    /* Loop hash entries until a free one is found */
    while (Session->SystemSpaceViewTable[Hash].Entry)
    {
        /* Unless we overflow, in which case loop back at hash o */
        if (++Hash >= Session->SystemSpaceHashSize) Hash = 0;
    }

    /* Add this entry into the hash table */
    Session->SystemSpaceViewTable[Hash].Entry = Entry;
    Session->SystemSpaceViewTable[Hash].ControlArea = ControlArea;

    /* Hash entry found, increment total and return the base address */
    Session->SystemSpaceHashEntries++;
    KeReleaseGuardedMutex(Session->SystemSpaceViewLockPointer);
    return Base;
}

NTSTATUS
NTAPI
MiAddViewsForSection(IN PMSUBSECTION StartMappedSubsection,
                     IN ULONGLONG LastPteOffset,
                     IN KIRQL OldIrql)
{
    PMSUBSECTION MappedSubsection;
    ULONG SubsectionPagedPool;
    MMPTE ProtoTemplate;
    PVOID SectionProtos;

    DPRINT("MiAddViewsForSection: StartMappedSubsection %p, LastPteOffset %I64X\n", StartMappedSubsection, LastPteOffset);

    ASSERT((StartMappedSubsection->ControlArea->u.Flags.Image == 0) &&
           (StartMappedSubsection->ControlArea->FilePointer != NULL) &&
           (StartMappedSubsection->ControlArea->u.Flags.PhysicalMemory == 0));

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(MmPfnOwner == KeGetCurrentThread());

    for (MappedSubsection = StartMappedSubsection;
         MappedSubsection;
         MappedSubsection = (PMSUBSECTION)MappedSubsection->NextSubsection)
    {
        ASSERT(MappedSubsection->ControlArea->DereferenceList.Flink == NULL);

        if (MappedSubsection->SubsectionBase)
        {
            MappedSubsection->NumberOfMappedViews++;

            if (MappedSubsection->DereferenceList.Flink)
            {
                RemoveEntryList(&MappedSubsection->DereferenceList);
                AlloccatePoolForSubsectionPtes(MappedSubsection->PtesInSubsection + MappedSubsection->UnusedPtes);
                MappedSubsection->DereferenceList.Flink = NULL;
            }

            MappedSubsection->u2.SubsectionFlags2.SubsectionAccessed = 1;
        }
        else
        {
            ASSERT(MappedSubsection->u.SubsectionFlags.SubsectionStatic == 0);
            ASSERT(MappedSubsection->NumberOfMappedViews == 0);

            MiUnlockPfnDb(OldIrql, APC_LEVEL);

            SubsectionPagedPool = (MappedSubsection->PtesInSubsection + MappedSubsection->UnusedPtes) * sizeof(MMPTE);
            ASSERT(SubsectionPagedPool != 0);

            SectionProtos = ExAllocatePoolWithTag(PagedPool, SubsectionPagedPool, 'tSmM');
            if (!SectionProtos)
            {
                OldIrql = MiLockPfnDb(APC_LEVEL);

                if (StartMappedSubsection != MappedSubsection)
                {
                    do
                    {
                        ASSERT((LONG_PTR)StartMappedSubsection->NumberOfMappedViews >= 1);
                        StartMappedSubsection->NumberOfMappedViews--;

                        ASSERT(StartMappedSubsection->u.SubsectionFlags.SubsectionStatic == 0);
                        ASSERT(StartMappedSubsection->DereferenceList.Flink == NULL);

                        if (!StartMappedSubsection->NumberOfMappedViews)
                        {
                            InsertHeadList(&MmUnusedSubsectionList, &StartMappedSubsection->DereferenceList);
                            FreePoolForSubsectionPtes(MappedSubsection->PtesInSubsection + MappedSubsection->UnusedPtes);
                        }

                        StartMappedSubsection = (PMSUBSECTION)StartMappedSubsection->NextSubsection;
                    }
                    while ((PMSUBSECTION)StartMappedSubsection->NextSubsection != MappedSubsection);
                }

                MiUnlockPfnDb(OldIrql, APC_LEVEL);

                return STATUS_INSUFFICIENT_RESOURCES;
            }

            MI_MAKE_SUBSECTION_PTE(&ProtoTemplate, MappedSubsection);

            ProtoTemplate.u.Soft.Prototype = 1;
            ProtoTemplate.u.Soft.Protection = MappedSubsection->ControlArea->Segment->SegmentPteTemplate.u.Soft.Protection;
            DPRINT("MiAddViewsForSection: ProtoTemplate.u.Soft.Protection %X\n", ProtoTemplate.u.Soft.Protection);

            RtlFillMemoryUlong(SectionProtos, SubsectionPagedPool, ProtoTemplate.u.Long);

            OldIrql = MiLockPfnDb(APC_LEVEL);

            MappedSubsection->NumberOfMappedViews++;
            MappedSubsection->u2.SubsectionFlags2.SubsectionAccessed = 1;

            if (MappedSubsection->SubsectionBase)
            {
                if (MappedSubsection->DereferenceList.Flink)
                {
                    ASSERT(MappedSubsection->NumberOfMappedViews == 1);
                    RemoveEntryList(&MappedSubsection->DereferenceList);
                    AlloccatePoolForSubsectionPtes(MappedSubsection->PtesInSubsection + MappedSubsection->UnusedPtes);
                    MappedSubsection->DereferenceList.Flink = NULL;
                }
                else
                {
                    ASSERT(MappedSubsection->NumberOfMappedViews > 1);
                }

                MiUnlockPfnDb(OldIrql, APC_LEVEL);
                ExFreePoolWithTag(SectionProtos, 'tSmM');
                OldIrql = MiLockPfnDb(APC_LEVEL);
            }
            else
            {
                ASSERT(MappedSubsection->NumberOfMappedViews == 1);
                MappedSubsection->SubsectionBase = (PMMPTE)SectionProtos;
            }
        }

        if (LastPteOffset)
        {
            ASSERT((LONG)MappedSubsection->PtesInSubsection > 0);
            ASSERT((UINT64)LastPteOffset > 0);

            if (LastPteOffset <= MappedSubsection->PtesInSubsection)
            {
                break;
            }

            LastPteOffset -= MappedSubsection->PtesInSubsection;
        }
    }

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
MiAddViewsForSectionWithPfn(PMSUBSECTION StartMappedSubsection,
                            ULONGLONG LastPteOffset)
{
    DPRINT("MiAddViewsForSectionWithPfn: StartMappedSubsection %p, LastPteOffset %I64X\n", StartMappedSubsection, LastPteOffset);
    ASSERT(FALSE);
    return 0;
}

NTSTATUS
NTAPI
MiAddMappedPtes(IN PMMPTE FirstPte,
                IN PFN_NUMBER PteCount,
                IN PCONTROL_AREA ControlArea)
{
    MMPTE TempPte;
    PMMPTE Pte, SectionProto, LastProto, LastPte;
    PSUBSECTION Subsection;
    NTSTATUS Status;

    DPRINT("MiAddMappedPtes: FirstPte %X, PteCount %X\n", FirstPte, PteCount);

    if ((ControlArea->u.Flags.GlobalOnlyPerSession == 0) &&
        (ControlArea->u.Flags.Rom == 0))
    {
        Subsection = (PSUBSECTION)&ControlArea[1];
    }
    else
    {
        Subsection = (PSUBSECTION)((PLARGE_CONTROL_AREA)ControlArea + 1);
    }

    /* Sanity checks */
    ASSERT(PteCount != 0);
    ASSERT(ControlArea->NumberOfMappedViews >= 1);
    ASSERT(ControlArea->NumberOfUserReferences >= 1);
    ASSERT(ControlArea->NumberOfSectionReferences != 0);
    ASSERT(ControlArea->u.Flags.BeingCreated == 0);
    ASSERT(ControlArea->u.Flags.BeingDeleted == 0);
    ASSERT(ControlArea->u.Flags.BeingPurged == 0);

    if ((ControlArea->FilePointer != NULL) &&
        (ControlArea->u.Flags.Image == 0) &&
        (ControlArea->u.Flags.PhysicalMemory == 0))
    {
        Status = MiAddViewsForSectionWithPfn((PMSUBSECTION)Subsection, PteCount);
        if (!NT_SUCCESS (Status))
        {
            DPRINT1("MiAddMappedPtes: Status %X\n", Status);
            return Status;
        }
    }

    /* Get the PTEs for the actual mapping */
    Pte = FirstPte;
    LastPte = FirstPte + PteCount;

    /* Get the section protos that desribe the section mapping in the subsection */
    SectionProto = Subsection->SubsectionBase;
    LastProto = &Subsection->SubsectionBase[Subsection->PtesInSubsection];

    /* Loop the PTEs for the mapping */
    while (Pte < LastPte)
    {
        /* We may have run out of section protos in this subsection */
        if (SectionProto >= LastProto)
        {
            Subsection = Subsection->NextSubsection;
            SectionProto = Subsection->SubsectionBase;
            LastProto = &Subsection->SubsectionBase[Subsection->PtesInSubsection];
        }

        /* The PTE should be completely clear */
        ASSERT(Pte->u.Long == 0);

        /* Build the section proto and write it */
        MI_MAKE_PROTOTYPE_PTE(&TempPte, SectionProto);
        MI_WRITE_INVALID_PTE(Pte, TempPte);

        /* Keep going */
        Pte++;
        SectionProto++;
    }

    /* No failure path */
    return STATUS_SUCCESS;
}

VOID
NTAPI
MiFillSystemPageDirectory(IN PVOID Base,
                          IN SIZE_T NumberOfBytes)
{
    PMMPDE Pde, LastPde, SystemMapPde;
#if (_MI_PAGING_LEVELS <= 3)
    PFN_NUMBER ParentPage;
#endif
    MMPDE TempPde;
    PFN_NUMBER PageFrameIndex;
    KIRQL OldIrql;

    PAGED_CODE();
    DPRINT("MiFillSystemPageDirectory: Base %p, NumberOfBytes %X\n", Base, NumberOfBytes);

    /* Find the PDEs needed for this mapping */
    Pde = MiAddressToPde(Base);
    LastPde = MiAddressToPde((PVOID)((ULONG_PTR)Base + NumberOfBytes - 1));

#if (_MI_PAGING_LEVELS <= 3)
    /* Find the system double-mapped PDE that describes this mapping */
    SystemMapPde = &MmSystemPagePtes[MiGetPdeOffset(Pde)];
#else
    /* We don't have a double mapping */
    SystemMapPde = Pde;
#endif

    /* Use the PDE template and loop the PDEs */
    TempPde = ValidKernelPde;
    while (Pde <= LastPde)
    {
        /* Check if we don't already have this PDE mapped */
        if (SystemMapPde->u.Hard.Valid)
        {
            goto Next;
        }

        /* Lock the PFN database */
        OldIrql = MiLockPfnDb(APC_LEVEL);

        /* Check if we don't already have this PDE mapped */
        if (SystemMapPde->u.Hard.Valid)
        {
            /* Release the lock and keep going with the next PDE */
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            goto Next;
        }

        if (MmAvailablePages < 128)
        {
            DPRINT1("MiFillSystemPageDirectory: MmAvailablePages %X\n", MmAvailablePages);
            DPRINT1("MiFillSystemPageDirectory: FIXME MiEnsureAvailablePageOrWait()\n");
            ASSERT(FALSE);
        }

        //DPRINT("MiFillSystemPageDirectory: FIXME MiChargeCommitmentCantExpand()\n");

        MI_SET_USAGE(MI_USAGE_PAGE_TABLE);
        MI_SET_PROCESS2(PsGetCurrentProcess()->ImageFileName);

        /* Grab a page for it */
        PageFrameIndex = MiRemoveZeroPage(MI_GET_NEXT_COLOR());
        ASSERT(PageFrameIndex);
        TempPde.u.Hard.PageFrameNumber = PageFrameIndex;

#if (_MI_PAGING_LEVELS <= 3)
        /* Initialize its PFN entry, with the parent system page directory page table */
        ParentPage = MmSystemPageDirectory[MiGetPdIndex(Pde)];
        MiInitializePfnForOtherProcess(PageFrameIndex,
                                       (PMMPTE)Pde,
                                       ParentPage);
#else
        MiInitializePfnAndMakePteValid(PageFrameIndex, Pde, TempPde);
#endif
        /* Make the system PDE entry valid */
        MI_WRITE_VALID_PDE(SystemMapPde, TempPde);

        /* The system PDE entry might be the PDE itself, so check for this */
        if (Pde->u.Hard.Valid == 0)
        {
            /* It's different, so make the real PDE valid too */
            MI_WRITE_VALID_PDE(Pde, TempPde);
        }

        /* Release the lock and keep going with the next PDE */
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
Next:
        SystemMapPde++;
        Pde++;
    }
}

NTSTATUS
NTAPI
MiCheckPurgeAndUpMapCount(IN PCONTROL_AREA ControlArea,
                          IN BOOLEAN FailIfSystemViews)
{
    NTSTATUS Status;
    KIRQL OldIrql;

    DPRINT("MiCheckPurgeAndUpMapCount: ControlArea %p, FailIfSystemViews %X\n", ControlArea, FailIfSystemViews);

    if (FailIfSystemViews)
    {
        ASSERT(ControlArea->u.Flags.Image != 0);
    }

    /* Lock the PFN database */
    OldIrql = MiLockPfnDb(APC_LEVEL);

    /* State not yet supported */
    if (ControlArea->u.Flags.BeingPurged)
    {
        DPRINT("MiCheckPurgeAndUpMapCount: FIXME! ControlArea->u.Flags.BeingPurged\n");
        ASSERT(FALSE);
    }

    /* Increase the reference counts */
    ControlArea->NumberOfMappedViews++;
    ControlArea->NumberOfUserReferences++;
    ASSERT(ControlArea->NumberOfSectionReferences != 0);

    if (FailIfSystemViews &&
        ControlArea->u.Flags.ImageMappedInSystemSpace &&
        KeGetPreviousMode() != KernelMode)
    {
        /* Release the PFN lock and return success */
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        DPRINT1("MiCheckPurgeAndUpMapCount: STATUS_CONFLICTING_ADDRESSES\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
    }
    else
    {
        /* Increase the reference counts */
        ControlArea->NumberOfMappedViews++;
        ControlArea->NumberOfUserReferences++;
        ASSERT(ControlArea->NumberOfSectionReferences != 0);

        /* Release the PFN lock and return success */
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        Status = STATUS_SUCCESS;
    }

    /* Release the PFN lock and return success */
    MiReleasePfnLock(OldIrql);
    return Status;
}

PSUBSECTION
NTAPI
MiLocateSubsection(IN PMMVAD Vad,
                   IN ULONG_PTR Vpn)
{
    PSUBSECTION Subsection;
    PCONTROL_AREA ControlArea;
    ULONG_PTR PteOffset;

    ASSERT(FALSE);

    /* Get the control area */
    ControlArea = Vad->ControlArea;
    ASSERT(ControlArea->u.Flags.Rom == 0);
    ASSERT(ControlArea->u.Flags.Image == 0);
    ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);

    /* Get the subsection */
    Subsection = (PSUBSECTION)(ControlArea + 1);

    /* We only support single-subsection segments */
    ASSERT(Subsection->SubsectionBase != NULL);
    ASSERT(Vad->FirstPrototypePte >= Subsection->SubsectionBase);
    ASSERT(Vad->FirstPrototypePte < &Subsection->SubsectionBase[Subsection->PtesInSubsection]);

    /* Compute the PTE offset */
    PteOffset = Vpn - Vad->StartingVpn;
    PteOffset += Vad->FirstPrototypePte - Subsection->SubsectionBase;

    /* Again, we only support single-subsection segments */
    ASSERT(PteOffset < 0xF0000000);
    ASSERT(PteOffset < Subsection->PtesInSubsection);

    /* Return the subsection */
    return Subsection;
}

VOID
NTAPI
MiSegmentDelete(IN PSEGMENT Segment)
{
    PCONTROL_AREA ControlArea;
    SEGMENT_FLAGS SegmentFlags;
    PSUBSECTION Subsection;
    PMMPTE Pte, LastPte, PteForProto;
    PMMPFN Pfn1;
    PFN_NUMBER PageFrameIndex;
    MMPTE TempPte;
    KIRQL OldIrql;

    ASSERT(FALSE);

    /* Capture data */
    SegmentFlags = Segment->SegmentFlags;
    ControlArea = Segment->ControlArea;

    /* Make sure control area is on the right delete path */
    ASSERT(ControlArea->u.Flags.BeingDeleted == 1);
    ASSERT(ControlArea->WritableUserReferences == 0);

    /* These things are not supported yet */
    ASSERT(ControlArea->DereferenceList.Flink == NULL);
    ASSERT(!(ControlArea->u.Flags.Image) && !(ControlArea->u.Flags.File));
    ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);
    ASSERT(ControlArea->u.Flags.Rom == 0);

    /* Get the subsection and PTEs for this segment */
    Subsection = (PSUBSECTION)(ControlArea + 1);
    Pte = Subsection->SubsectionBase;
    LastPte = Pte + Segment->NonExtendedPtes;

    /* Lock the PFN database */
    OldIrql = MiAcquirePfnLock();

    /* Check if the master PTE is invalid */
    PteForProto = MiAddressToPte(Pte);
    if (!PteForProto->u.Hard.Valid)
    {
        /* Fault it in */
        MiMakeSystemAddressValidPfn(Pte, OldIrql);
    }

    /* Loop all the segment PTEs */
    while (Pte < LastPte)
    {
        /* Check if it's time to switch master PTEs if we passed a PDE boundary */
        if (MiIsPteOnPdeBoundary(Pte) &&
            (Pte != Subsection->SubsectionBase))
        {
            /* Check if the master PTE is invalid */
            PteForProto = MiAddressToPte(Pte);
            if (!PteForProto->u.Hard.Valid)
            {
                /* Fault it in */
                MiMakeSystemAddressValidPfn(Pte, OldIrql);
            }
        }

        /* This should be a prototype PTE */
        TempPte = *Pte;
        ASSERT(SegmentFlags.LargePages == 0);
        ASSERT(TempPte.u.Hard.Valid == 0);

        /* See if we should clean things up */
        if (!(ControlArea->u.Flags.Image) && !(ControlArea->u.Flags.File))
        {
            /*
             * This is a section backed by the pagefile. Now that it doesn't exist anymore,
             * we can give everything back to the system.
             */
            ASSERT(TempPte.u.Soft.Prototype == 0);

            if (TempPte.u.Soft.Transition == 1)
            {
                /* We can give the page back for other use */
                DPRINT("Releasing page for transition PTE %p\n", Pte);
                PageFrameIndex = PFN_FROM_PTE(&TempPte);
                Pfn1 = MI_PFN_ELEMENT(PageFrameIndex);

                /* As this is a paged-backed section, nobody should reference it anymore (no cache or whatever) */
                ASSERT(Pfn1->u3.ReferenceCount == 0);

                /* And it should be in standby or modified list */
                ASSERT((Pfn1->u3.e1.PageLocation == ModifiedPageList) || (Pfn1->u3.e1.PageLocation == StandbyPageList));

                /* Unlink it and put it back in free list */
                MiUnlinkPageFromList(Pfn1);

                /* Temporarily mark this as active and make it free again */
                Pfn1->u3.e1.PageLocation = ActiveAndValid;
                MI_SET_PFN_DELETED(Pfn1);

                MiInsertPageInFreeList(PageFrameIndex);
            }
            else if (TempPte.u.Soft.PageFileHigh != 0)
            {
                /* Should not happen for now */
                ASSERT(FALSE);
            }
        }
        else
        {
            /* unsupported for now */
            ASSERT(FALSE);

            /* File-backed section must have prototype PTEs */
            ASSERT(TempPte.u.Soft.Prototype == 1);
        }

        /* Zero the PTE and keep going */
        Pte->u.Long = 0;
        Pte++;
    }

    /* Release the PFN lock */
    MiReleasePfnLock(OldIrql);

    /* Free the structures */
    ExFreePool(ControlArea);
    ExFreePool(Segment);
}

VOID
NTAPI
MiRemoveViewsFromSection(PMSUBSECTION MappedSubsection,
                         ULONGLONG PtesInSubsection)
{
    DPRINT("MiRemoveViewsFromSection: MappedSubsection %p, PtesInSubsection %X\n", MappedSubsection, PtesInSubsection);

    ASSERT((MappedSubsection->ControlArea->u.Flags.Image == 0) &&
           (MappedSubsection->ControlArea->FilePointer != NULL) &&
           (MappedSubsection->ControlArea->u.Flags.PhysicalMemory == 0));

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(MmPfnOwner == KeGetCurrentThread());

    for (;
         MappedSubsection;
         MappedSubsection = (PMSUBSECTION)MappedSubsection->NextSubsection)
    {
        ASSERT(MappedSubsection->ControlArea->DereferenceList.Flink == NULL);
        ASSERT(MappedSubsection->SubsectionBase != NULL);
        ASSERT(MappedSubsection->DereferenceList.Flink == NULL);

        ASSERT(((LONG_PTR)MappedSubsection->NumberOfMappedViews >= 1) ||
               (MappedSubsection->u.SubsectionFlags.SubsectionStatic == 1));

        MappedSubsection->NumberOfMappedViews--;

        if (!MappedSubsection->NumberOfMappedViews &&
            !MappedSubsection->u.SubsectionFlags.SubsectionStatic)
        {
            InsertTailList(&MmUnusedSubsectionList, &MappedSubsection->DereferenceList);
            FreePoolForSubsectionPtes(MappedSubsection->PtesInSubsection + MappedSubsection->UnusedPtes);
        }

        if (PtesInSubsection)
        {
            if (PtesInSubsection <= (ULONGLONG)MappedSubsection->PtesInSubsection)
            {
                break;
            }

            PtesInSubsection -= MappedSubsection->PtesInSubsection;
        }
    }
}

VOID
NTAPI
MiCheckControlArea(IN PCONTROL_AREA ControlArea,
                   IN KIRQL OldIrql)
{
    PEVENT_COUNTER PurgeEvent = NULL;
    ULONG CheckFlag = 0;

    DPRINT("MiCheckControlArea: ControlArea %p, OldIrql %X\n", ControlArea, OldIrql);

    MI_ASSERT_PFN_LOCK_HELD();
    ASSERT(MmPfnOwner == KeGetCurrentThread());

    /* Check if this is the last reference or view */
    if (!ControlArea->NumberOfMappedViews &&
        !ControlArea->NumberOfSectionReferences)
    {
        /* There should be no more user references either */
        ASSERT(ControlArea->NumberOfUserReferences == 0);

        if (ControlArea->FilePointer)
        {
            if (ControlArea->NumberOfPfnReferences)
            {
                if (!ControlArea->DereferenceList.Flink)
                {
                    MI_ASSERT_PFN_LOCK_HELD();
                    ASSERT(MmPfnOwner == KeGetCurrentThread());

                    if (!ControlArea->u.Flags.Image &&
                        ControlArea->FilePointer &&
                        !ControlArea->u.Flags.PhysicalMemory)
                    {
                        /* Not yet supported */
                        DPRINT1("MiCheckControlArea: FIXME MiConvertStaticSubsections\n");
                        ASSERT(FALSE);
                    }

                    /* Not yet supported */
                    DPRINT1("MiCheckControlArea: FIXME MmUnusedSegmentList\n");
                    ASSERT(FALSE);

                    MmUnusedSegmentCount++;
                }

                if (ControlArea->u.Flags.DeleteOnClose)
                {
                    CheckFlag = 1;
                }

                if (ControlArea->u.Flags.GlobalMemory)
                {
                    ASSERT(ControlArea->u.Flags.Image == 1);

                    ControlArea->u.Flags.BeingPurged = 1;
                    ControlArea->NumberOfMappedViews = 1;

                    /* Not yet supported */
                    DPRINT1("MiCheckControlArea: FIXME MiPurgeImageSection\n");
                    ASSERT(FALSE);

                    ControlArea->u.Flags.BeingPurged = 0;

                    ControlArea->NumberOfMappedViews--;

                    if (!ControlArea->NumberOfMappedViews &&
                        !ControlArea->NumberOfSectionReferences &&
                        !ControlArea->NumberOfPfnReferences)
                    {
                        CheckFlag |= 2;

                        ControlArea->u.Flags.BeingDeleted = 1;
                        ControlArea->u.Flags.FilePointerNull = 1;

                        /* Not yet supported */
                        DPRINT1("MiCheckControlArea: FIXME MiRemoveImageSectionObject\n");
                        ASSERT(FALSE);
                    }
                    else
                    {
                        PurgeEvent = ControlArea->WaitingForDeletion;
                        ControlArea->WaitingForDeletion = 0;
                    }
                }

                if (CheckFlag == 1)
                {
                    ControlArea->u.Flags.BeingDeleted = 1;
                    ControlArea->NumberOfMappedViews = 1;
                }
            }
            else
            {
                ControlArea->u.Flags.BeingDeleted = 1;

                CheckFlag = 2;

                ASSERT(ControlArea->u.Flags.FilePointerNull == 0);
                ControlArea->u.Flags.FilePointerNull = 1;

                if (ControlArea->u.Flags.Image)
                {
                    /* Not yet supported */
                    DPRINT1("MiCheckControlArea: FIXME MiRemoveImageSectionObject\n");
                    ASSERT(FALSE);
                }
                else
                {
                    ASSERT(((PCONTROL_AREA)(ControlArea->FilePointer->SectionObjectPointer->DataSectionObject)) != NULL);
                    ControlArea->FilePointer->SectionObjectPointer->DataSectionObject = NULL;
                }
            }
        }
        else
        {
            ControlArea->u.Flags.BeingDeleted = 1;
            CheckFlag = 2;
        }
    }
    else
    {
        /* Check if waiting for deletion */
        if (ControlArea->WaitingForDeletion)
        {
            /* Get event */
            PurgeEvent = ControlArea->WaitingForDeletion;
            ControlArea->WaitingForDeletion = NULL;
        }
    }

    /* Release the PFN lock */
    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    if (!CheckFlag)
    {
        if (PurgeEvent)
        {
            KeSetEvent(&PurgeEvent->Event, 0, FALSE);
        }

        /* Not yet supported */
        DPRINT1("MiCheckControlArea: FIXME MmUnusedSegmentCleanup\n");
        ASSERT(FALSE);
        return;
    }

    /* No more user write references at all */
    ASSERT(ControlArea->WritableUserReferences == 0);
    ASSERT(PurgeEvent == NULL);

    if (CheckFlag & 2)
    {
        /* Delete the segment if needed */
        MiSegmentDelete(ControlArea->Segment);
    }
    else
    {
        /* Clean the section */
        /* Not yet supported */
        DPRINT1("MiCheckControlArea: FIXME MiCleanSection\n");
        ASSERT(FALSE);
    }
}

VOID
NTAPI
MiDereferenceControlArea(IN PCONTROL_AREA ControlArea)
{
    KIRQL OldIrql;

    ASSERT(FALSE);

    /* Lock the PFN database */
    OldIrql = MiAcquirePfnLock();

    /* Drop reference counts */
    ControlArea->NumberOfMappedViews--;
    ControlArea->NumberOfUserReferences--;

    /* Check if it's time to delete the CA. This releases the lock */
    MiCheckControlArea(ControlArea, OldIrql);
}

VOID
NTAPI
MiDecrementSubsections(PSUBSECTION FirstSubsection,
                       PSUBSECTION LastSubsection)
{
    PMSUBSECTION MappedSubsection;

    DPRINT("MiDecrementSubsections: FirstSubsection %p, LastSubsection %p\n", FirstSubsection, LastSubsection);

    ASSERT((FirstSubsection->ControlArea->u.Flags.Image == 0) &&
           (FirstSubsection->ControlArea->FilePointer != NULL) &&
           (FirstSubsection->ControlArea->u.Flags.PhysicalMemory == 0));

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(MmPfnOwner == KeGetCurrentThread());

    for (MappedSubsection = (PMSUBSECTION)FirstSubsection;
         ;
         MappedSubsection = (PMSUBSECTION)MappedSubsection->NextSubsection)
    {
        ASSERT(MappedSubsection->DereferenceList.Flink == NULL);
        ASSERT(((LONG_PTR)MappedSubsection->NumberOfMappedViews >= 1) ||
               (MappedSubsection->u.SubsectionFlags.SubsectionStatic == 1));

        MappedSubsection->NumberOfMappedViews--;

        if (!MappedSubsection->NumberOfMappedViews &&
            !MappedSubsection->u.SubsectionFlags.SubsectionStatic)
        {
            InsertTailList(&MmUnusedSubsectionList, &MappedSubsection->DereferenceList);
            FreePoolForSubsectionPtes(MappedSubsection->PtesInSubsection + MappedSubsection->UnusedPtes);
        }

        if ((LastSubsection && FirstSubsection == LastSubsection) ||
            !MappedSubsection->NextSubsection)
        {
            break;
        }
    }
}

VOID
NTAPI
MiRemoveMappedView(IN PEPROCESS Process,
                   IN PMMVAD Vad)
{
    KIRQL OldIrql;
    PCONTROL_AREA ControlArea;
    PETHREAD CurrentThread = PsGetCurrentThread();
    PMMEXTEND_INFO ExtendedInfo;
    PSUBSECTION LastSubsection;
    PSUBSECTION FirstSubsection;
    PVOID UsedAddress;
    PMMPTE Pde;
    PMMPTE Pte;
    PMMPTE LastPte;
    PMMPFN Pfn;
    PFN_NUMBER PdePage;

    DPRINT("MiRemoveMappedView: Process %p, Vad %p\n", Process, Vad);

    /* Get the control area */
    ControlArea = Vad->ControlArea;

    /* If view of the physical section */
    if (Vad->u.VadFlags.VadType == VadDevicePhysicalMemory)
    {
        if (((PMMVAD_LONG)Vad)->u4.Banked != NULL)
        {
            DPRINT1("MiRemoveMappedView: FIXME\n");
            ASSERT(FALSE);
        }

        /* Remove Physical View */
        MiPhysicalViewRemover(Process, Vad);

        Pde = MiAddressToPde(Vad->StartingVpn * PAGE_SIZE);
        ASSERT(Pde->u.Hard.Valid == 1);

        Pte = MiAddressToPte(Vad->StartingVpn * PAGE_SIZE);
        LastPte = MiAddressToPte(Vad->EndingVpn * PAGE_SIZE);

        if (!Pde->u.Hard.LargePage)
        {
            PdePage = Pde->u.Hard.PageFrameNumber;
            UsedAddress = (PVOID)(Vad->StartingVpn * PAGE_SIZE);

            /* Lock the PFN database */
            OldIrql = MiLockPfnDb(APC_LEVEL);

            while (Pte <= LastPte)
            {
                /* Check if we're on a PDE boundary */
                if (MiIsPteOnPdeBoundary(Pte))
                {
                    Pde = MiAddressToPte(Pte);
                    PdePage = Pde->u.Hard.PageFrameNumber;
                    UsedAddress = MiPteToAddress(Pte);
                }

                /* Add an additional page table reference */
                MiDecrementPageTableReferences(UsedAddress);

                Pte->u.Long = 0;
                Pfn = &MmPfnDatabase[PdePage];

                if (Pfn->u2.ShareCount != 1)
                {
                    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
                    ASSERT(MmPfnOwner == KeGetCurrentThread());
                    ASSERT(PdePage > 0);
                    ASSERT(MiGetPfnEntry(PdePage) != NULL);
                    ASSERT(&MmPfnDatabase[PdePage] == Pfn);
                    ASSERT(Pfn->u2.ShareCount != 0);

                    if (Pfn->u3.e1.PageLocation != ActiveAndValid &&
                        Pfn->u3.e1.PageLocation != StandbyPageList)
                    {
                        DPRINT1("MiRemoveMappedView: FIXME\n");
                        ASSERT(FALSE);
                    }

                    /* Just decrease share count */
                    Pfn->u2.ShareCount--;
                    ASSERT(Pfn->u2.ShareCount < 0xF000000);
                }
                else
                {
                    /* Decrement the share count on the page */
                    MiDecrementShareCount(Pfn, PdePage);
                }

                /* See if we should delete it */
                if (!MiQueryPageTableReferences(UsedAddress))
                {
                    PVOID VirtualAddress = MiPdeToPte(Pde);
                    MiDeletePte(Pde, VirtualAddress, Process, NULL);
                    Process->NumberOfPrivatePages++;
                }

                Pte++;
            }

            KeFlushProcessTb();

            /* Release the PFN lock */
            MiUnlockPfnDb(OldIrql, APC_LEVEL);

            /* Release the working set */
            MiUnlockProcessWorkingSetUnsafe(Process, CurrentThread);

            /* Lock the PFN database */
            OldIrql = MiLockPfnDb(APC_LEVEL);
        }
        else
        {
            /* Not supported yet */
            DPRINT1("MiRemoveMappedView: FIXME\n");
            ASSERT(FALSE);

            /* Release the working set */
            MiUnlockProcessWorkingSetUnsafe(Process, CurrentThread);

            /* Lock the PFN database */
            OldIrql = MiLockPfnDb(APC_LEVEL);
        }
    }
    else
    {
        if (Vad->u2.VadFlags2.ExtendableFile)
        {
            PMMVAD_LONG VadLong = (PMMVAD_LONG)Vad;

            /* Release the working set */
            MiUnlockProcessWorkingSetUnsafe(Process, CurrentThread);

            ExtendedInfo = NULL;

            /* Acquire the lock */
            KeAcquireGuardedMutexUnsafe(&MmSectionBasedMutex);

            ASSERT(VadLong->ControlArea->Segment->ExtendInfo == VadLong->u4.ExtendedInfo);
            VadLong->u4.ExtendedInfo->ReferenceCount--;

            if (!VadLong->u4.ExtendedInfo->ReferenceCount)
            {
                ExtendedInfo = VadLong->u4.ExtendedInfo;
                VadLong->ControlArea->Segment->ExtendInfo = NULL;
            }

            /* Now that we're done, release the lock */
            KeReleaseGuardedMutexUnsafe (&MmSectionBasedMutex);

            if (ExtendedInfo)
            {
                ExFreePoolWithTag(ExtendedInfo, 'xCmM');
            }

            /* Lock the working set */
            MiLockProcessWorkingSetUnsafe(Process, CurrentThread);
        }

        FirstSubsection = 0;
        LastSubsection = 0;

        if (Vad->u.VadFlags.VadType == VadImageMap)
        {
            Pde = MiAddressToPde(Vad->StartingVpn * PAGE_SIZE);

            if (Pde->u.Hard.Valid && Pde->u.Hard.LargePage)
            {
                DPRINT1("MiRemoveMappedView: FIXME\n");
                ASSERT(FALSE);

                /* Lock the PFN database */
                OldIrql = MiLockPfnDb(APC_LEVEL);
    
                /* Increase the reference counts */
                ControlArea->NumberOfMappedViews--;
                ControlArea->NumberOfUserReferences--;

                /* Check if it should be destroyed and return*/
                MiCheckControlArea(ControlArea, OldIrql);
                return;
            }
        }
        else
        {
            if (ControlArea->FilePointer)
            {
                if ((Vad->u.VadFlags.Protection == MM_READWRITE) ||
                    (Vad->u.VadFlags.Protection == MM_EXECUTE_READWRITE))
                {
                    /* Add a reference */
                    InterlockedDecrement ((volatile PLONG)&ControlArea->WritableUserReferences);
                }

                FirstSubsection = MiLocateSubsection(Vad, Vad->StartingVpn);
                ASSERT(FirstSubsection != NULL);
                LastSubsection = MiLocateSubsection(Vad, Vad->EndingVpn);
                DPRINT("MiRemoveMappedView: FirstSubsection %p, LastSubsection %p\n", FirstSubsection, LastSubsection);
            }
        }

        if (Vad->u.VadFlags.VadType == VadLargePageSection)
        {
            DPRINT1("MiRemoveMappedView: FIXME\n");
            ASSERT(FALSE);
        }
        else
        {
            /* Delete the actual virtual memory pages */
            MiDeleteVirtualAddresses(Vad->StartingVpn << PAGE_SHIFT,
                                     (Vad->EndingVpn << PAGE_SHIFT) | (PAGE_SIZE - 1),
                                     Vad);
        }

        /* Release the working set */
        MiUnlockProcessWorkingSetUnsafe(Process, CurrentThread);

        /* Lock the PFN database */
        OldIrql = MiLockPfnDb(APC_LEVEL);

        if (FirstSubsection)
        {
            DPRINT("MiUnmapViewOfSection: FIXME MiDecrementSubsections\n");
            ASSERT(FALSE);
            //MiDecrementSubsections(FirstSubsection, LastSubsection);
        }
    }

    if (ControlArea)
    {
        /* Decrease the reference counts */
        ControlArea->NumberOfMappedViews--;
        ControlArea->NumberOfUserReferences--;

        /* Check if it should be destroyed and return */
        MiCheckControlArea(ControlArea, OldIrql);
        return;
    }

    /* Release the PFN lock and return */
    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    ASSERT(Vad->u.VadFlags.VadType == VadDevicePhysicalMemory);
    ASSERT(((PMMVAD_LONG)Vad)->u4.Banked == NULL);
    ASSERT(Vad->ControlArea == NULL);
    ASSERT(Vad->FirstPrototypePte == NULL);
}

NTSTATUS
NTAPI
MiUnmapViewOfSection(IN PEPROCESS Process,
                     IN PVOID BaseAddress,
                     IN ULONG Flags)
{
    BOOLEAN Attached = FALSE;
    KAPC_STATE ApcState;
    PMMVAD Vad;
    PMMVAD PreviousVad;
    PMMVAD NextVad;
    PVOID DbgBase = NULL;
    SIZE_T RegionSize;
    NTSTATUS Status;
    PETHREAD CurrentThread = PsGetCurrentThread();
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    ULONG_PTR StartingAddress;
    ULONG_PTR EndingAddress;

    PAGED_CODE();
    DPRINT("MiUnmapViewOfSection: Process %p, BaseAddress %p, Flags %X\n", Process, BaseAddress, Flags);

    /* Check if we should attach to the process */
    if (CurrentProcess != Process)
    {
        /* The process is different, do an attach */
        KeStackAttachProcess(&Process->Pcb, &ApcState);
        Attached = TRUE;
    }

    /* Check if we need to lock the address space */
    if (!(Flags & 1))
    {
        MmLockAddressSpace(&Process->Vm);
    }

    /* Check if the process is already daed */
    if (Process->VmDeleted)
    {
        /* Fail the call */
        DPRINT1("MiUnmapViewOfSection: STATUS_PROCESS_IS_TERMINATING\n");

        if (!(Flags & 1))
        {
            MmUnlockAddressSpace(&Process->Vm);
        }

        Status = STATUS_PROCESS_IS_TERMINATING;
        goto Exit;
    }

    /* Find the VAD for the address and make sure it's a section VAD */
    Vad = MiLocateAddress(BaseAddress);

    if (!Vad || Vad->u.VadFlags.PrivateMemory)
    {
        /* Couldn't find it, or invalid VAD, fail */
        DPRINT1("MiUnmapViewOfSection: No VAD or invalid VAD\n");

        if (!(Flags & 1))
        {
            MmUnlockAddressSpace(&Process->Vm);
        }

        Status = STATUS_NOT_MAPPED_VIEW;
        goto Exit;
    }

    /* We should be attached */
    ASSERT(Process == PsGetCurrentProcess());

    StartingAddress = Vad->StartingVpn * PAGE_SIZE;
    EndingAddress = (Vad->EndingVpn * PAGE_SIZE) | 0xFFF;

    /* We need the base address for the debugger message on image-backed VADs */
    if (Vad->u.VadFlags.VadType == VadImageMap)
    {
        DbgBase = (PVOID)StartingAddress;
    }

    /* Compute the size of the VAD region */
    RegionSize = (Vad->EndingVpn - Vad->StartingVpn + 1) * PAGE_SIZE;

    /* For SEC_NO_CHANGE sections, we need some extra checks */
    if (Vad->u.VadFlags.NoChange == 1)
    {
        /* Are we allowed to mess with this VAD? */
        Status = MiCheckSecuredVad(Vad,
                                   (PVOID)StartingAddress,
                                   RegionSize,
                                   MM_DELETE_CHECK);
        if (!NT_SUCCESS(Status))
        {
            /* We failed */
            DPRINT1("MiUnmapViewOfSection: Trying to unmap protected VAD! Status %X\n", Status);

            if (!(Flags & 1))
            {
                MmUnlockAddressSpace(&Process->Vm);
            }
 
            goto Exit1;
        }
    }

    /* Get previous and next nodes */
    PreviousVad = (PMMVAD)MiGetPreviousNode((PMMADDRESS_NODE)Vad);
    NextVad = (PMMVAD)MiGetNextNode((PMMADDRESS_NODE)Vad);

    if (Vad->u.VadFlags.VadType != VadRotatePhysical)
    {
        /* Remove VAD charges */
        MiRemoveVadCharges(Vad, Process);

        /* Lock the working set */
        MiLockProcessWorkingSetUnsafe(Process, CurrentThread);
    }
    else
    {
        if (Flags & 2)
        {
            /* Remove VAD charges */
            MiRemoveVadCharges(Vad, Process);

            /* Lock the working set */
            MiLockProcessWorkingSetUnsafe(Process, CurrentThread);

            /* Remove Physical View */
            DPRINT("MiUnmapViewOfSection: FIXME MiPhysicalViewRemover\n");
            ASSERT(FALSE);
            //MiPhysicalViewRemover(Process, Vad);
        }
        else
        {
            if (!(Flags & 1))
            {
                MmUnlockAddressSpace(&Process->Vm);
            }

            Status = STATUS_NOT_MAPPED_VIEW;
            DPRINT1("MiUnmapViewOfSection: STATUS_NOT_MAPPED_VIEW\n");
            goto Exit1;
        }
    }

    /* Remove the VAD */
    ASSERT(Process == PsGetCurrentProcess());
    ASSERT(Process->VadRoot.NumberGenericTableElements >= 1);

    MiRemoveNode((PMMADDRESS_NODE)Vad, &Process->VadRoot);

    if (Process->VadRoot.NodeHint == Vad)
    {
        Process->VadRoot.NodeHint = Process->VadRoot.BalancedRoot.RightChild;

        if (Process->VadRoot.NumberGenericTableElements == 0)
        {
            Process->VadRoot.NodeHint = NULL;
        }
    }

    /* Remove the PTEs for this view, which also releases the working set lock */
    MiRemoveMappedView(Process, Vad);

    /* Remove commitment */
    MiReturnPageTablePageCommitment(StartingAddress, EndingAddress, Process, PreviousVad, NextVad);

    /* Update performance counter and release the lock */
    Process->VirtualSize -= RegionSize;

    if (!(Flags & 1))
    {
        MmUnlockAddressSpace(&Process->Vm);
    }

    /* Destroy the VAD and return success */
    ExFreePool(Vad);
    Status = STATUS_SUCCESS;

    /* Failure and success case -- send debugger message, detach, and return */

Exit1:

    if (DbgBase)
    {
        DbgkUnMapViewOfSection(DbgBase);
    }

Exit:

    if (Attached)
    {
        KeUnstackDetachProcess(&ApcState);
    }

    return Status;
}

NTSTATUS
NTAPI
MiSessionCommitPageTables(IN PVOID StartVa,
                          IN PVOID EndVa)
{
    KIRQL OldIrql;
    ULONG Color, Index;
    PMMPDE StartPde, EndPde;
    MMPDE TempPde = ValidKernelPdeLocal;
    PMMPFN Pfn1;
    PFN_NUMBER PageCount = 0, ActualPages = 0, PageFrameNumber;

    ASSERT(FALSE);

    /* Windows sanity checks */
    ASSERT(StartVa >= (PVOID)MmSessionBase);
    ASSERT(EndVa < (PVOID)MiSessionSpaceEnd);
    ASSERT(PAGE_ALIGN(EndVa) == EndVa);

    /* Get the start and end PDE, then loop each one */
    StartPde = MiAddressToPde(StartVa);
    EndPde = MiAddressToPde((PVOID)((ULONG_PTR)EndVa - 1));
    Index = ((ULONG_PTR)StartVa - (ULONG_PTR)MmSessionBase) >> 22;
    while (StartPde <= EndPde)
    {
#ifndef _M_AMD64
        /* If we don't already have a page table for it, increment count */
        if (MmSessionSpace->PageTables[Index].u.Long == 0) PageCount++;
#endif
        /* Move to the next one */
        StartPde++;
        Index++;
    }

    /* If there's no page tables to create, bail out */
    if (PageCount == 0) return STATUS_SUCCESS;

    /* Reset the start PDE and index */
    StartPde = MiAddressToPde(StartVa);
    Index = ((ULONG_PTR)StartVa - (ULONG_PTR)MmSessionBase) >> 22;

    /* Loop each PDE while holding the working set lock */
//  MiLockWorkingSet(PsGetCurrentThread(),
//                   &MmSessionSpace->GlobalVirtualAddress->Vm);
#ifdef _M_AMD64
_WARN("MiSessionCommitPageTables halfplemented for amd64")
    DBG_UNREFERENCED_LOCAL_VARIABLE(OldIrql);
    DBG_UNREFERENCED_LOCAL_VARIABLE(Color);
    DBG_UNREFERENCED_LOCAL_VARIABLE(TempPde);
    DBG_UNREFERENCED_LOCAL_VARIABLE(Pfn1);
    DBG_UNREFERENCED_LOCAL_VARIABLE(PageFrameNumber);
    ASSERT(FALSE);
#else
    while (StartPde <= EndPde)
    {
        /* Check if we already have a page table */
        if (MmSessionSpace->PageTables[Index].u.Long == 0)
        {
            /* We don't, so the PDE shouldn't be ready yet */
            ASSERT(StartPde->u.Hard.Valid == 0);

            /* ReactOS check to avoid MiEnsureAvailablePageOrWait */
            ASSERT(MmAvailablePages >= 32);

            /* Acquire the PFN lock and grab a zero page */
            OldIrql = MiAcquirePfnLock();
            MI_SET_USAGE(MI_USAGE_PAGE_TABLE);
            MI_SET_PROCESS2(PsGetCurrentProcess()->ImageFileName);
            Color = (++MmSessionSpace->Color) & MmSecondaryColorMask;
            PageFrameNumber = MiRemoveZeroPage(Color);
            TempPde.u.Hard.PageFrameNumber = PageFrameNumber;
            MI_WRITE_VALID_PDE(StartPde, TempPde);

            /* Write the page table in session space structure */
            ASSERT(MmSessionSpace->PageTables[Index].u.Long == 0);
            MmSessionSpace->PageTables[Index] = TempPde;

            /* Initialize the PFN */
            MiInitializePfnForOtherProcess(PageFrameNumber,
                                           StartPde,
                                           MmSessionSpace->SessionPageDirectoryIndex);

            /* And now release the lock */
            MiReleasePfnLock(OldIrql);

            /* Get the PFN entry and make sure there's no event for it */
            Pfn1 = MI_PFN_ELEMENT(PageFrameNumber);
            ASSERT(Pfn1->u1.Event == NULL);

            /* Increment the number of pages */
            ActualPages++;
        }

        /* Move to the next PDE */
        StartPde++;
        Index++;
    }
#endif

    /* Make sure we didn't do more pages than expected */
    ASSERT(ActualPages <= PageCount);

    /* Release the working set lock */
//  MiUnlockWorkingSet(PsGetCurrentThread(),
//                     &MmSessionSpace->GlobalVirtualAddress->Vm);


    /* If we did at least one page... */
    if (ActualPages)
    {
        /* Update the performance counters! */
        InterlockedExchangeAddSizeT(&MmSessionSpace->NonPageablePages, ActualPages);
        InterlockedExchangeAddSizeT(&MmSessionSpace->CommittedPages, ActualPages);
    }

    /* Return status */
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
MiMapViewInSystemSpace(IN PVOID SectionPointer,
                       IN PMMSESSION Session,
                       OUT PVOID *MappedBase,
                       IN OUT PSIZE_T ViewSize)
{
    PSECTION Section = SectionPointer;
    PVOID Base;
    PCONTROL_AREA ControlArea;
    ULONG Buckets, SectionSize;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("MiMapViewInSystemSpace: Section %p, Session %p, MappedBase %p, ViewSize %I64X\n", Section, Session, ((MappedBase == NULL) ? NULL : *MappedBase), ((ViewSize == 0) ? 0 : (ULONGLONG)*ViewSize));

    /* Get the control area */
    ControlArea = Section->Segment->ControlArea;

    /* Increase the reference and map count on the control area, no purges yet */
    Status = MiCheckPurgeAndUpMapCount(ControlArea, FALSE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MiMapViewInSystemSpace: Status %X\n", Status);
        return Status;
    }

    /* Get the section size at creation time */
    SectionSize = Section->SizeOfSection.LowPart;

    /* If the caller didn't specify a view size, assume the whole section */
    if (*ViewSize)
    {
        /* Check if the caller wanted a larger section than the view */
        if (*ViewSize > SectionSize)
        {
            /* Fail */
            DPRINT1("MiMapViewInSystemSpace: View is too large\n");
            ASSERT(0);
            MiDereferenceControlArea(ControlArea);
            return STATUS_INVALID_VIEW_SIZE;
        }
    }
    else
    {
        DPRINT("MiMapViewInSystemSpace: SectionSize %X\n", SectionSize);
        ASSERT(SectionSize != 0);
        *ViewSize = SectionSize;
    }

    /* Get the number of 64K buckets required for this mapping */
    Buckets = (ULONG)(*ViewSize / MI_SYSTEM_VIEW_BUCKET_SIZE);
    if (*ViewSize & (MI_SYSTEM_VIEW_BUCKET_SIZE - 1)) Buckets++;

    /* Check if the view is more than 4GB large */
    if (Buckets >= MI_SYSTEM_VIEW_BUCKET_SIZE)
    {
        /* Fail */
        DPRINT1("MiMapViewInSystemSpace: View is too large\n");
        MiDereferenceControlArea(ControlArea);
        return STATUS_INVALID_VIEW_SIZE;
    }

    /* Insert this view into system space and get a base address for it */
    Base = MiInsertInSystemSpace(Session, Buckets, ControlArea);
    if (!Base)
    {
        /* Fail */
        DPRINT1("MiMapViewInSystemSpace: Out of system space\n");
        MiDereferenceControlArea(ControlArea);
        return STATUS_NO_MEMORY;
    }

    /* What's the underlying session? */
    if (Session == &MmSession)
    {
        /* Create the PDEs needed for this mapping, and double-map them if needed */
        MiFillSystemPageDirectory(Base, Buckets * MI_SYSTEM_VIEW_BUCKET_SIZE);
    }
    else
    {
        /* Create the PDEs needed for this mapping */
        Status = MiSessionCommitPageTables(Base,
                                           (PVOID)((ULONG_PTR)Base +
                                           Buckets * MI_SYSTEM_VIEW_BUCKET_SIZE));
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("MiMapViewInSystemSpace: Status %X\n", Status);
            goto ErrorExit;
        }
    }

    /* Create the actual prototype PTEs for this mapping */
    Status = MiAddMappedPtes(MiAddressToPte(Base),
                             BYTES_TO_PAGES(*ViewSize),
                             ControlArea);
    if (NT_SUCCESS(Status))
    {
        *MappedBase = Base;
        return STATUS_SUCCESS;
    }

    DPRINT1("MiMapViewInSystemSpace: Status %X\n", Status);

ErrorExit:

    ASSERT(FALSE);
    MiDereferenceControlArea(ControlArea);
    return Status;
}

VOID
NTAPI
MiSetControlAreaSymbolsLoaded(IN PCONTROL_AREA ControlArea)
{
    KIRQL OldIrql;

    ASSERT(FALSE);

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    OldIrql = MiAcquirePfnLock();
    ControlArea->u.Flags.DebugSymbolsLoaded |= 1;

    ASSERT(OldIrql <= APC_LEVEL);
    MiReleasePfnLock(OldIrql);
    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
}

VOID
NTAPI
MiLoadUserSymbols(IN PCONTROL_AREA ControlArea,
                  IN PVOID BaseAddress,
                  IN PEPROCESS Process)
{
    NTSTATUS Status;
    ANSI_STRING FileNameA;
    PLIST_ENTRY NextEntry;
    PUNICODE_STRING FileName;
    PIMAGE_NT_HEADERS NtHeaders;
    PLDR_DATA_TABLE_ENTRY LdrEntry;

    ASSERT(FALSE);

    FileName = &ControlArea->FilePointer->FileName;
    if (FileName->Length == 0)
    {
        return;
    }

    /* Acquire module list lock */
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&PsLoadedModuleResource, TRUE);

    /* Browse list to try to find current module */
    for (NextEntry = MmLoadedUserImageList.Flink;
         NextEntry != &MmLoadedUserImageList;
         NextEntry = NextEntry->Flink)
    {
        /* Get the entry */
        LdrEntry = CONTAINING_RECORD(NextEntry,
                                     LDR_DATA_TABLE_ENTRY,
                                     InLoadOrderLinks);

        /* If already in the list, increase load count */
        if (LdrEntry->DllBase == BaseAddress)
        {
            ++LdrEntry->LoadCount;
            break;
        }
    }

    /* Not in the list, we'll add it */
    if (NextEntry == &MmLoadedUserImageList)
    {
        /* Allocate our element, taking to the name string and its null char */
        LdrEntry = ExAllocatePoolWithTag(NonPagedPool, FileName->Length + sizeof(UNICODE_NULL) + sizeof(*LdrEntry), 'bDmM');
        if (LdrEntry)
        {
            memset(LdrEntry, 0, FileName->Length + sizeof(UNICODE_NULL) + sizeof(*LdrEntry));

            _SEH2_TRY
            {
                /* Get image checksum and size */
                NtHeaders = RtlImageNtHeader(BaseAddress);
                if (NtHeaders)
                {
                    LdrEntry->SizeOfImage = NtHeaders->OptionalHeader.SizeOfImage;
                    LdrEntry->CheckSum = NtHeaders->OptionalHeader.CheckSum;
                }
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                ExFreePoolWithTag(LdrEntry, 'bDmM');
                _SEH2_YIELD(return);
            }
            _SEH2_END;

            /* Fill all the details */
            LdrEntry->DllBase = BaseAddress;
            LdrEntry->FullDllName.Buffer = (PVOID)((ULONG_PTR)LdrEntry + sizeof(*LdrEntry));
            LdrEntry->FullDllName.Length = FileName->Length;
            LdrEntry->FullDllName.MaximumLength = FileName->Length + sizeof(UNICODE_NULL);
            memcpy(LdrEntry->FullDllName.Buffer, FileName->Buffer, FileName->Length);
            LdrEntry->FullDllName.Buffer[LdrEntry->FullDllName.Length / sizeof(WCHAR)] = UNICODE_NULL;
            LdrEntry->LoadCount = 1;

            /* Insert! */
            InsertHeadList(&MmLoadedUserImageList, &LdrEntry->InLoadOrderLinks);
        }
    }

    /* Release locks */
    ExReleaseResourceLite(&PsLoadedModuleResource);
    KeLeaveCriticalRegion();

    /* Load symbols */
    Status = RtlUnicodeStringToAnsiString(&FileNameA, FileName, TRUE);
    if (NT_SUCCESS(Status))
    {
        DbgLoadImageSymbols(&FileNameA, BaseAddress, (ULONG_PTR)Process->UniqueProcessId);
        RtlFreeAnsiString(&FileNameA);
    }
}

NTSTATUS
NTAPI
MiMapViewOfDataSection(IN PCONTROL_AREA ControlArea,
                       IN PEPROCESS Process,
                       IN OUT PVOID *BaseAddress,
                       IN OUT PLARGE_INTEGER SectionOffset,
                       IN OUT PSIZE_T ViewSize,
                       IN PSECTION Section,
                       IN SECTION_INHERIT InheritDisposition,
                       IN ULONG ProtectionMask,
                       IN SIZE_T CommitSize,
                       IN ULONG_PTR ZeroBits,
                       IN ULONG AllocationType)
{
    PETHREAD Thread;
    PMMVAD Vad;
    ULONG_PTR StartAddress;
    ULONG_PTR EndAddress;
    ULONG_PTR HighestAddress;
    PSUBSECTION Subsection;
    PSEGMENT Segment;
    ULONGLONG PteOffset;
    ULONGLONG LastPteOffset;
    NTSTATUS Status;
    ULONG QuotaCharge = 0;
    ULONG QuotaExcess = 0;
    ULONG VadSize;
    PMMPTE Pte;
    PMMPTE LastPte;
    MMPTE TempPte;
    ULONG Granularity = MM_ALLOCATION_GRANULARITY;
    PMMEXTEND_INFO ExtendInfo;
    PMMADDRESS_NODE Parent;
    LARGE_INTEGER TotalNumberOfPtes;
    BOOLEAN IsLargePages;
    BOOLEAN IsFindEnabled;

    DPRINT("MiMapViewOfDataSection: Section %p, ControlArea %p, Process %p, ZeroBits %X, CommitSize %X, AllocType %X, ProtectionMask %X\n", Section, ControlArea, Process, ZeroBits, CommitSize, AllocationType, ProtectionMask);

    /* Get the segment for this section */
    Segment = ControlArea->Segment;

    /* One can only reserve a file-based mapping, not shared memory! */
    if ((AllocationType & MEM_RESERVE) && !(ControlArea->FilePointer))
    {
        DPRINT1("MiMapViewOfDataSection: STATUS_INVALID_PARAMETER_9\n");
        return STATUS_INVALID_PARAMETER_9;
    }

    if (AllocationType & MEM_DOS_LIM)
    {
        /* ALlow being less restrictive */
        if ((*BaseAddress == NULL) || (AllocationType & MEM_RESERVE))
        {
            DPRINT1("MiMapViewOfDataSection: STATUS_INVALID_PARAMETER_3\n");
            return STATUS_INVALID_PARAMETER_3;
        }

        Granularity = PAGE_SIZE;
    }

    /* First, increase the map count. No purging is supported yet */
    Status = MiCheckPurgeAndUpMapCount(ControlArea, FALSE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MiMapViewOfDataSection: Status %X\n", Status);
        return Status;
    }

    /* Check if the caller specified the view size */
    if (*ViewSize)
    {
        /* A size was specified. Align it. */
        *ViewSize += SectionOffset->LowPart & (Granularity - 1);

        /* Align the offset as well to make this an aligned map */
        SectionOffset->LowPart &= ~(Granularity - 1);
    }
    else
    {
        /* The caller did not, so pick aligned view size based on the offset */
        SectionOffset->LowPart &= ~(Granularity - 1);
        *ViewSize = (SIZE_T)(Section->SizeOfSection.QuadPart - SectionOffset->QuadPart);
    }

    /* We must be dealing with aligned offset. This is a Windows ASSERT */
    ASSERT((SectionOffset->LowPart & (Granularity - 1)) == 0);

    /* It's illegal to try to map more than overflows a LONG_PTR */
    if (*ViewSize >= MAXLONG_PTR)
    {
        MiDereferenceControlArea(ControlArea);
        return STATUS_INVALID_VIEW_SIZE;
    }

    /* Windows ASSERTs for this flag */
    ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);

    /* Get the subsection. */
    if (ControlArea->u.Flags.Rom == 0)
    {
        Subsection = (PSUBSECTION)(ControlArea + 1);
    }
    else
    {
        Subsection = (PSUBSECTION)((PLARGE_CONTROL_AREA)ControlArea + 1);
    }

    /* Within this section, figure out which PTEs will describe the view */
    PteOffset = SectionOffset->QuadPart / PAGE_SIZE;

    TotalNumberOfPtes.LowPart = Segment->TotalNumberOfPtes;
    TotalNumberOfPtes.HighPart = Segment->SegmentFlags.TotalNumberOfPtes4132;

    /* The offset must be in this segment's PTE chunk and it must be valid. */
    if (PteOffset >= (ULONGLONG)TotalNumberOfPtes.QuadPart)
    {
        MiDereferenceControlArea(ControlArea);
        return STATUS_INVALID_VIEW_SIZE;
    }

    LastPteOffset = ((SectionOffset->QuadPart + *ViewSize + (PAGE_SIZE - 1)) / PAGE_SIZE);
    ASSERT(LastPteOffset >= PteOffset);

    /* Subsection must contain these PTEs */
    while (PteOffset >= (ULONGLONG)Subsection->PtesInSubsection)
    {
        PteOffset -= Subsection->PtesInSubsection;
        LastPteOffset -= Subsection->PtesInSubsection;
        Subsection = Subsection->NextSubsection;
        ASSERT(Subsection != NULL);
    }

    if (ControlArea->FilePointer != NULL)
    {
        Status = MiAddViewsForSectionWithPfn((PMSUBSECTION)Subsection, LastPteOffset);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("MiMapViewOfDataSection: Status %X\n", Status);
            MiDereferenceControlArea(ControlArea);
            return Status;
        }
    }

    /* Windows ASSERTs for this too -- there must be a subsection base address */
    ASSERT(Subsection->SubsectionBase != NULL);

    /* Compute how much commit space the segment will take */
    if (!ControlArea->FilePointer &&
        (CommitSize) && (Segment->NumberOfCommittedPages < (ULONGLONG)TotalNumberOfPtes.QuadPart))
    {
        /* Charge for the maximum pages */
        QuotaCharge = BYTES_TO_PAGES(CommitSize);
    }

    /* ARM3 does not currently support large pages */
    ASSERT(Segment->SegmentFlags.LargePages == 0);
    if (Segment->SegmentFlags.LargePages &&
        (*ViewSize & (0x400000 - 1)) == 0 &&
        !(AllocationType & MEM_RESERVE) &&
        (KeFeatureBits & KF_LARGE_PAGE) &&
        (ProtectionMask & MM_PROTECT_SPECIAL) != MM_GUARDPAGE &&
        ProtectionMask != MM_NOACCESS &&
        (ProtectionMask & MM_WRITECOPY) != MM_WRITECOPY)
    {
        IsLargePages = TRUE;
    }
    else
    {
        IsLargePages = FALSE;
    }

    /* Is it SEC_BASED, or did the caller manually specify an address? */
    if (*BaseAddress || Section->Address.StartingVpn)
    {
        if (*BaseAddress)
        {
            /* Just align what the caller gave us */
            StartAddress = ALIGN_DOWN_BY(*BaseAddress, Granularity);
        }
        else
        {
            /* It is a SEC_BASED mapping, use the address that was generated */
            StartAddress = Section->Address.StartingVpn + SectionOffset->LowPart;
        }

        if ((ULONG_PTR)StartAddress & (0x400000 - 1))
        {
            IsLargePages = FALSE;
        }

        EndAddress = ((*ViewSize + StartAddress - 1) | (PAGE_SIZE - 1));

        if (MiCheckForConflictingVadExistence(Process, StartAddress, EndAddress))
        {
            Status = STATUS_CONFLICTING_ADDRESSES;
            DPRINT1("MiMapViewOfDataSection: STATUS_CONFLICTING_ADDRESSES\n");
            goto ErrorExit;
        }
    }
    else
    {
        /* No StartAddress. Find empty address range. */

        IsFindEnabled = TRUE;

        if ((AllocationType & MEM_TOP_DOWN) || (Process->VmTopDown))
        {
            HighestAddress = (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS;

            if (ZeroBits)
            {
                HighestAddress = ((ULONG_PTR)MI_HIGHEST_SYSTEM_ADDRESS >> ZeroBits);
                if (HighestAddress > (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS)
                {
                    HighestAddress = (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS;
                }
            }

            if (IsLargePages)
            {
                ASSERT(FALSE);
                Status = MiFindEmptyAddressRangeDownTree(*ViewSize, HighestAddress, 0x400000, &Process->VadRoot, &StartAddress, &Parent);
                if (!NT_SUCCESS (Status))
                {
                    DPRINT1("MiMapViewOfDataSection: Status %X\n", Status);
                    IsLargePages = FALSE;
                }
                else
                {
                    IsFindEnabled = FALSE;
                }
            }

            if (IsFindEnabled)
            {
                Status = MiFindEmptyAddressRangeDownTree(*ViewSize, HighestAddress, Granularity, &Process->VadRoot, &StartAddress, &Parent);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT1("MiMapViewOfDataSection: Status %X\n", Status);
                    goto ErrorExit;
                }
            }
        }
        else
        {
            if (IsLargePages)
            {
                Status = MiFindEmptyAddressRange(*ViewSize, 0x400000, ZeroBits, &StartAddress);
                if (!NT_SUCCESS (Status))
                {
                    DPRINT1("MiMapViewOfDataSection: Status %X\n", Status);
                    IsLargePages = FALSE;
                }
                else
                {
                    IsFindEnabled = FALSE;
                }
            }

            if (IsFindEnabled)
            {
                Status = MiFindEmptyAddressRange(*ViewSize, Granularity, ZeroBits, &StartAddress);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT1("MiMapViewOfDataSection: Status %X\n", Status);
                    goto ErrorExit;
                }
            }
        }

        EndAddress = ((*ViewSize + StartAddress - 1) | (PAGE_SIZE - 1));

        if (ZeroBits &&
            (EndAddress > ((ULONG_PTR)MI_HIGHEST_SYSTEM_ADDRESS >> ZeroBits)))
        {
            DPRINT1("MiMapViewOfDataSection: STATUS_NO_MEMORY\n");
            Status = STATUS_NO_MEMORY;
            goto ErrorExit;
        }
    }

    /* A VAD can now be allocated. Do so and zero it out */
    if (AllocationType & MEM_RESERVE)
    {
        VadSize = sizeof(MMVAD_LONG);
        Vad = ExAllocatePoolWithTag(NonPagedPool, VadSize, 'ldaV');
    }
    else
    {
        VadSize = sizeof(MMVAD);
        Vad = ExAllocatePoolWithTag(NonPagedPool, VadSize, ' daV');
    }

    if (Vad == NULL)
    {
        DPRINT1("MiMapViewOfDataSection: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }

    RtlZeroMemory(Vad, VadSize);

    /* Write all the data required in the VAD for handling a fault */
    Vad->ControlArea = ControlArea;
    Vad->u.VadFlags.Protection = ProtectionMask;
    Vad->u2.VadFlags2.FileOffset = (ULONG)(SectionOffset->QuadPart >> 16);
    Vad->u2.VadFlags2.Inherit = (InheritDisposition == ViewShare);
    Vad->u2.VadFlags2.CopyOnWrite = Section->u.Flags.CopyOnWrite;

    if ((AllocationType & SEC_NO_CHANGE) || (Section->u.Flags.NoChange))
    {
        /* Setting the flag */
        Vad->u.VadFlags.NoChange = 1;
        Vad->u2.VadFlags2.SecNoChange = 1;
    }

    if (AllocationType & MEM_RESERVE)
    {
        Vad->u2.VadFlags2.LongVad = 1;

        KeAcquireGuardedMutexUnsafe(&MmSectionBasedMutex);

        ExtendInfo = Segment->ExtendInfo;
        if (ExtendInfo)
        {
            ExtendInfo->ReferenceCount++;
        }
        else
        {
            ExtendInfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(MMEXTEND_INFO), 'xCmM');
            if (ExtendInfo == NULL)
            {
                KeReleaseGuardedMutexUnsafe(&MmSectionBasedMutex);

                DPRINT1("MiMapViewOfDataSection: STATUS_INSUFFICIENT_RESOURCES\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto ErrorExit;
            }

            ExtendInfo->ReferenceCount = 1;
            ExtendInfo->CommittedSize = Segment->SizeOfSegment;
            Segment->ExtendInfo = ExtendInfo;
        }

        if (ExtendInfo->CommittedSize < (ULONGLONG)Section->SizeOfSection.QuadPart)
        {
            ExtendInfo->CommittedSize = (ULONGLONG)Section->SizeOfSection.QuadPart;
        }

        KeReleaseGuardedMutexUnsafe(&MmSectionBasedMutex);

        Vad->u2.VadFlags2.ExtendableFile = 1;

        ASSERT(((PMMVAD_LONG)Vad)->u4.ExtendedInfo == NULL);
        ((PMMVAD_LONG)Vad)->u4.ExtendedInfo = ExtendInfo;
    }

    if ((ProtectionMask & MM_WRITECOPY) == MM_WRITECOPY)
    {
        Vad->u.VadFlags.CommitCharge = BYTES_TO_PAGES(EndAddress - StartAddress);
    }

    /* Finally, write down the first and last prototype PTE */
    Vad->StartingVpn = StartAddress / PAGE_SIZE;
    Vad->EndingVpn = EndAddress / PAGE_SIZE;

    Vad->FirstPrototypePte = &Subsection->SubsectionBase[PteOffset];

    PteOffset += (Vad->EndingVpn - Vad->StartingVpn);

    if (PteOffset >= Subsection->PtesInSubsection)
    {
        Vad->LastContiguousPte = &Subsection->SubsectionBase[Subsection->PtesInSubsection - 1 + Subsection->UnusedPtes];
    }
    else
    {
        Vad->LastContiguousPte = &Subsection->SubsectionBase[PteOffset];
    }

    /* Make sure the prototype PTE ranges make sense, this is a Windows ASSERT */
    ASSERT(Vad->FirstPrototypePte <= Vad->LastContiguousPte);

    /* Check if anything was committed */
    if (QuotaCharge)
    {
        DPRINT1("MiMapViewOfDataSection: FIXME MiChargeCommitment()\n");
        ASSERT(FALSE);
    }


    /* Insert the VAD charges */
    Status = MiInsertVadCharges(Vad, Process);
    if (!NT_SUCCESS(Status))
    {
        if (ControlArea->FilePointer)
        {
            DPRINT1("MiMapViewOfDataSection: FIXME MiRemoveViewsFromSectionWithPfn()\n");
            ASSERT(FALSE);
        }

        MiDereferenceControlArea(ControlArea);

        if (AllocationType & MEM_RESERVE)
        {
            ExFreePoolWithTag(Vad, 'ldaV');
        }
        else
        {
            ExFreePoolWithTag(Vad, ' daV');
        }

        if (QuotaCharge)
        {
            ASSERT((SSIZE_T)(QuotaCharge) >= 0);
            ASSERT(MmTotalCommittedPages >= (QuotaCharge));
            InterlockedExchangeAdd((volatile PLONG)&MmTotalCommittedPages, -QuotaCharge);
        }

        DPRINT1("MiMapViewOfDataSection: Status %X\n", Status);
        return Status;
    }

    /* Insert the VAD */
    Thread = PsGetCurrentThread();
    MiLockProcessWorkingSetUnsafe(Process, Thread);
    MiInsertVad(Vad, &Process->VadRoot);
    MiUnlockProcessWorkingSetUnsafe(Process, Thread);

    if (IsLargePages == TRUE)
    {
        DPRINT1("MiMapViewOfDataSection: FIXME MiMapLargePageSection()\n");
        ASSERT(FALSE);
    }

    /* Windows stores this for accounting purposes, do so as well */
    if (!ControlArea->FilePointer)
    {
        if (!Segment->u2.FirstMappedVa)
        {
            Segment->u2.FirstMappedVa = (PVOID)StartAddress;
        }
    }

    if (AllocationType & MEM_RESERVE)
    {
        ASSERT((EndAddress - StartAddress) <= 
               (((ULONGLONG)Segment->SizeOfSegment + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1)));
    }

    /* Check if anything was committed */
    if (QuotaCharge)
    {
        /* Set the start and end PTE addresses, and pick the template PTE */
        Pte = Vad->FirstPrototypePte;
        LastPte = Pte + BYTES_TO_PAGES(CommitSize);
        TempPte = Segment->SegmentPteTemplate;

        /* Acquire the commit lock and loop all prototype PTEs to be committed */
        KeAcquireGuardedMutexUnsafe(&MmSectionCommitMutex);
        while (Pte < LastPte)
        {
            /* Make sure the PTE is already invalid */
            if (Pte->u.Long == 0)
            {
                /* And write the invalid PTE */
                MI_WRITE_INVALID_PTE(Pte, TempPte);
            }
            else
            {
                /* The PTE is valid, so skip it */
                QuotaExcess++;
            }

            /* Move to the next PTE */
            Pte++;
        }

        /* Now check how many pages exactly we committed, and update accounting */
        ASSERT(QuotaCharge >= QuotaExcess);
        QuotaCharge -= QuotaExcess;
        Segment->NumberOfCommittedPages += QuotaCharge;
        ASSERT(Segment->NumberOfCommittedPages <= (ULONGLONG)TotalNumberOfPtes.QuadPart);

        /* Now that we're done, release the lock */
        KeReleaseGuardedMutexUnsafe(&MmSectionCommitMutex);

        InterlockedExchangeAdd((volatile PLONG)&MmSharedCommit, QuotaCharge);

        if (QuotaExcess)
        {
            ASSERT((SSIZE_T)(QuotaCharge) >= 0);
            ASSERT(MmTotalCommittedPages >= (QuotaCharge));
            InterlockedExchangeAdd((volatile PLONG)&MmTotalCommittedPages, -QuotaExcess);
        }
    }

    /* Finally, let the caller know where, and for what size, the view was mapped */
    *ViewSize = EndAddress - StartAddress + 1;
    *BaseAddress = (PVOID)StartAddress;

    Process->VirtualSize += *ViewSize;
    if (Process->VirtualSize > Process->PeakVirtualSize)
    {
        Process->PeakVirtualSize = Process->VirtualSize;
    }

    if ((ProtectionMask == MM_READWRITE || ProtectionMask == MM_EXECUTE_READWRITE) &&
        ControlArea->FilePointer)
    {
        InterlockedIncrement((volatile PLONG)&ControlArea->WritableUserReferences);
    }

    return STATUS_SUCCESS;

ErrorExit:

    if (ControlArea->FilePointer)
    {
        DPRINT1("MiMapViewOfDataSection: FIXME MiRemoveViewsFromSectionWithPfn()\n");
        ASSERT(FALSE);
    }

    MiDereferenceControlArea(ControlArea);

    if (Vad)
    {
        if (AllocationType & MEM_RESERVE)
        {
            ExFreePoolWithTag(Vad, 'ldaV');
        }
        else
        {
            ExFreePoolWithTag(Vad, ' daV');
        }
    }

    DPRINT("MiMapViewOfDataSection: *BaseAddress %p, *ViewSize %p, Status %X\n", *BaseAddress, *ViewSize, Status);
    return Status;
}

VOID
NTAPI
MiSubsectionConsistent(PSUBSECTION Subsection)
{
    ULONG NumberOfFullSectors;

    NumberOfFullSectors = Subsection->NumberOfFullSectors;
    DPRINT("MiSubsectionConsistent: Subsection %p, NumberOfFullSectors %X\n", Subsection, NumberOfFullSectors);

    if (Subsection->u.SubsectionFlags.SectorEndOffset)
    {
        NumberOfFullSectors++;
    }

    /* Therefore, then number of PTEs should be equal to the number of sectors */
    if (NumberOfFullSectors != Subsection->PtesInSubsection)
    {
        DPRINT1("Subsection inconsistent (%X vs %X)\n",
                NumberOfFullSectors, Subsection->PtesInSubsection);
        DbgBreakPoint();
    }
}

NTSTATUS
NTAPI
MiCreateDataFileMap(IN PFILE_OBJECT File,
                    OUT PSEGMENT *OutSegment,
                    IN PSIZE_T MaximumSize,
                    IN ULONG SectionPageProtection,
                    IN ULONG AllocationAttributes,
                    IN BOOLEAN IgnoreFileSizing)
{
    LARGE_INTEGER fileSize;
    ULONGLONG FileSize;
    ULONGLONG TotalNumberOfPtes;
    ULONGLONG CurrentSize;
    ULONGLONG CurrentPtes;
    PCONTROL_AREA ControlArea;
    PMAPPED_FILE_SEGMENT Segment;
    PMSUBSECTION NewSubsection;
    PMSUBSECTION Subsection;
    PMSUBSECTION LastSubsection;
    ULONG NumberOfNewSubsections;
    ULONG SubsectionSize;
    MMPTE ProtoTemplate;
    NTSTATUS Status;
    ULONGLONG maximum;
    PULONGLONG maximumSize;

    PAGED_CODE();
    DPRINT("MiCreateDataFileMap: File %p, Protection %X, AllocAttrib %X, IgnoreFileSizing %X\n", File, SectionPageProtection, AllocationAttributes, IgnoreFileSizing);

    if (MaximumSize)
    {
         maximum = *MaximumSize;
         maximumSize = &maximum;
         DPRINT("MiCreateDataFileMap: maximumSize %I64X\n", maximum);
    }

    if (IgnoreFileSizing)
    {
        /* CC is caller */
        FileSize = *maximumSize;
    }
    else
    {
        /* Get size via fs */
        Status = FsRtlGetFileSize(File, &fileSize);

        if (Status == STATUS_FILE_IS_A_DIRECTORY)
        {
            DPRINT1("MiCreateDataFileMap: STATUS_FILE_IS_A_DIRECTORY\n");
            return STATUS_INVALID_FILE_FOR_SECTION;
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("MiCreateDataFileMap: Status %X\n", Status);
            return Status;
        }

        FileSize = (ULONGLONG)fileSize.QuadPart;

        if (!FileSize && *maximumSize == 0)
        {
            DPRINT1("MiCreateDataFileMap: STATUS_MAPPED_FILE_SIZE_ZERO\n");
            return STATUS_MAPPED_FILE_SIZE_ZERO;
        }

        DPRINT("MiCreateDataFileMap: FileSize %I64X\n", FileSize);

        if (*maximumSize > FileSize)
        {
            if (!(SectionPageProtection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
            {
                DPRINT1("MiCreateDataFileMap: STATUS_SECTION_TOO_BIG\n");
                return STATUS_SECTION_TOO_BIG;
            }

            fileSize.QuadPart = (LONGLONG)*maximumSize;

            DPRINT1("MiCreateDataFileMap: FsRtlSetFileSize\n");
            ASSERT(FALSE);
            Status = 0;//FsRtlSetFileSize(File, &fileSize);
            if (!NT_SUCCESS(Status))
            {
                DPRINT("MiCreateDataFileMap: Status %X\n", Status);
                return Status;
            }
        }
    }

    if (FileSize >= ((16 * _1PB) & ~(PAGE_SIZE - 1)))
    {
        DPRINT1("MiCreateDataFileMap: STATUS_SECTION_TOO_BIG\n");
        return STATUS_SECTION_TOO_BIG;
    }

    TotalNumberOfPtes = (FileSize + (PAGE_SIZE - 1)) / PAGE_SIZE;

    Segment = ExAllocatePoolWithTag(PagedPool, sizeof(MAPPED_FILE_SEGMENT), 'mSmM');
    if (!Segment)
    {
        DPRINT1("MiCreateDataFileMap: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DPRINT("MiCreateDataFileMap: MmAllocationFragment %X\n", MmAllocationFragment);
    ASSERT(BYTE_OFFSET(MmAllocationFragment) == 0);
    ASSERT(MmAllocationFragment >= PAGE_SIZE);

    ControlArea = (PCONTROL_AREA)File->SectionObjectPointer->DataSectionObject;

    NumberOfNewSubsections = 0;
    SubsectionSize = MmAllocationFragment;

    NewSubsection = NULL;
    LastSubsection = NULL;

    /* Split file on parts sizeof MmAllocationFragment */
    for (CurrentSize = TotalNumberOfPtes * sizeof(MMPTE);
         CurrentSize != 0;
         CurrentSize -= SubsectionSize)
    {
        if (CurrentSize < MmAllocationFragment)
        {
            CurrentSize = PAGE_ROUND_UP(CurrentSize);
            SubsectionSize = CurrentSize;
        }

        /* Allocate subsections */
        if (NewSubsection)
        {
            NewSubsection = ExAllocatePoolWithTag(NonPagedPool, sizeof(MSUBSECTION), 'cSmM');
            if (!NewSubsection)
            {
                PMSUBSECTION NextSubsection;

                DPRINT1("MiCreateDataFileMap: STATUS_INSUFFICIENT_RESOURCES\n");

                ExFreePoolWithTag(Segment, 'mSmM');

                for (NewSubsection = (PMSUBSECTION)((PMSUBSECTION)&ControlArea[1])->NextSubsection;
                     NewSubsection != NULL;
                     NewSubsection = NextSubsection)
                {
                    NextSubsection = (PMSUBSECTION)NewSubsection->NextSubsection;
                    ExFreePoolWithTag(NewSubsection, 'cSmM');
                }

                return STATUS_INSUFFICIENT_RESOURCES;
            }

            RtlZeroMemory(NewSubsection, sizeof(MSUBSECTION));
            LastSubsection->NextSubsection = (PSUBSECTION)NewSubsection;
        }
        else
        {
            /* First Subsection */
            NewSubsection = (PMSUBSECTION)&ControlArea[1];
        }

        LastSubsection = NewSubsection;
        NumberOfNewSubsections++;

        NewSubsection->PtesInSubsection = (SubsectionSize / sizeof(MMPTE));
    }

    RtlZeroMemory(Segment, sizeof(MAPPED_FILE_SEGMENT));
    *OutSegment = (PSEGMENT)Segment;

    Segment->LastSubsectionHint = LastSubsection;

    ControlArea->Segment = (PSEGMENT)Segment;
    ControlArea->NumberOfSectionReferences = 1;

    if (IgnoreFileSizing)
    {
        /* CC is caller */
        ControlArea->u.Flags.WasPurged = 1;
    }
    else
    {
        ControlArea->NumberOfUserReferences = 1;
    }

    ControlArea->u.Flags.BeingCreated = 1;
    ControlArea->u.Flags.File = 1;

    if (File->DeviceObject->Characteristics & FILE_REMOTE_DEVICE)
    {
        ControlArea->u.Flags.Networked = 1;
    }

    if (AllocationAttributes & SEC_NOCACHE)
    {
        ControlArea->u.Flags.NoCache = 1;
    }

    ControlArea->FilePointer = File;
    ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);

    Subsection = (PMSUBSECTION)&ControlArea[1];

    MI_MAKE_SUBSECTION_PTE(&ProtoTemplate, Subsection);
    ProtoTemplate.u.Soft.Prototype = 1;
    ProtoTemplate.u.Soft.Protection = MM_EXECUTE_READWRITE;
    Segment->SegmentPteTemplate = ProtoTemplate;

    Segment->ControlArea = ControlArea;
    Segment->SizeOfSegment = FileSize;
    DPRINT("MiCreateDataFileMap: Segment->SizeOfSegment %I64X\n", Segment->SizeOfSegment);

    Segment->TotalNumberOfPtes = (ULONG)TotalNumberOfPtes;

    if (TotalNumberOfPtes >= (1ull << 32))
    {
        Segment->SegmentFlags.TotalNumberOfPtes4132 = (TotalNumberOfPtes >> 32);
    }

    if (Subsection->NextSubsection)
    {
        Segment->NonExtendedPtes = (Subsection->PtesInSubsection & ~(((ULONG)MmAllocationFragment / PAGE_SIZE) - 1));
    }
    else
    {
        Segment->NonExtendedPtes = Segment->TotalNumberOfPtes;
    }

    Subsection->PtesInSubsection = Segment->NonExtendedPtes;

    CurrentPtes = 0;

    for (;
         Subsection != NULL;
         Subsection = (PMSUBSECTION)Subsection->NextSubsection)
    {
        Subsection->StartingSector = (ULONG)CurrentPtes;
        Subsection->u.SubsectionFlags.StartingSector4132 = (CurrentPtes >> 32);

        Subsection->ControlArea = ControlArea;

        if (Subsection->NextSubsection)
        {
            Subsection->NumberOfFullSectors = Subsection->PtesInSubsection;
        }
        else
        {
            Subsection->NumberOfFullSectors = (FileSize / PAGE_SIZE) - (ULONG)CurrentPtes;
            Subsection->u.SubsectionFlags.SectorEndOffset = BYTE_OFFSET(FileSize);

            Subsection->UnusedPtes = Subsection->PtesInSubsection - (TotalNumberOfPtes - CurrentPtes);
            Subsection->PtesInSubsection -= Subsection->UnusedPtes;
        }

        MiSubsectionConsistent((PSUBSECTION)Subsection);

        CurrentPtes += (ULONGLONG)Subsection->PtesInSubsection;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
MiCreatePagingFileMap(OUT PSEGMENT *Segment,
                      IN PULONGLONG MaximumSize,
                      IN ULONG ProtectionMask,
                      IN ULONG AllocationAttributes)
{
    ULONGLONG SizeLimit;
    PFN_COUNT ProtoCount;
    PMMPTE SectionProto;
    MMPTE TempPte;
    PCONTROL_AREA ControlArea;
    PSEGMENT NewSegment;
    PSUBSECTION Subsection;

    PAGED_CODE();
    DPRINT("MiCreatePagingFileMap: MaximumSize %I64X, Protection %X, AllocAttributes %X\n", ((MaximumSize == NULL) ? 0ull : (*MaximumSize)), ProtectionMask, AllocationAttributes);

    /* Pagefile-backed sections need a known size */
    if (!(*MaximumSize))
    {
        DPRINT1("MiCreatePagingFileMap: STATUS_INVALID_PARAMETER_4 \n");
        return STATUS_INVALID_PARAMETER_4;
    }

    /* Calculate the maximum size possible, given the section protos we'll need */
    SizeLimit = MAXULONG_PTR - sizeof(SEGMENT);
    SizeLimit /= sizeof(MMPTE);
    SizeLimit <<= PAGE_SHIFT;

    /* Fail if this size is too big */
    if (*MaximumSize > SizeLimit)
    {
        DPRINT1("MiCreatePagingFileMap: SizeLimit %I64X, STATUS_SECTION_TOO_BIG\n", SizeLimit);
        return STATUS_SECTION_TOO_BIG;
    }

    /* Calculate how many section protos will be needed */
    ProtoCount = (PFN_COUNT)((*MaximumSize + PAGE_SIZE - 1) >> PAGE_SHIFT);

    if (AllocationAttributes & SEC_COMMIT)
    {
        /* For commited memory, we must have a valid protection mask */
        ASSERT(ProtectionMask != 0);

        DPRINT1("MiCreatePagingFileMap: FIXME MiChargeCommitment \n");

        /* No large pages in ARM3 yet */
        if (AllocationAttributes & SEC_LARGE_PAGES)
        {
            if (!(KeFeatureBits & KF_LARGE_PAGE))
            {
                DPRINT1("MiCreatePagingFileMap: STATUS_NOT_SUPPORTED \n");
                return STATUS_NOT_SUPPORTED;
            }

            DPRINT1("MiCreatePagingFileMap: AllocationAttributes & SEC_LARGE_PAGES\n");
            ASSERT(FALSE);
        }
    }

    /* The segment contains all the section protos, allocate it in paged pool */
    NewSegment = ExAllocatePoolWithTag(PagedPool,
                                       sizeof(SEGMENT) +
                                       sizeof(MMPTE) * (ProtoCount - 1),
                                       'tSmM');
    if (!NewSegment)
    {
        DPRINT1("MiCreatePagingFileMap: STATUS_INSUFFICIENT_RESOURCES \n");
        ASSERT(FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    *Segment = NewSegment;

    /* Now allocate the control area, which has the subsection structure */
    ControlArea = ExAllocatePoolWithTag(NonPagedPool,
                                        sizeof(CONTROL_AREA) + sizeof(SUBSECTION),
                                        'aCmM');
    if (!ControlArea)
    {
        DPRINT1("MiCreatePagingFileMap: STATUS_INSUFFICIENT_RESOURCES \n");
        ExFreePoolWithTag(NewSegment, 'tSmM');
        ASSERT(FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* And zero it out, filling the basic segmnet pointer and reference fields */
    RtlZeroMemory(ControlArea, sizeof(CONTROL_AREA) + sizeof(SUBSECTION));
    ControlArea->Segment = NewSegment;
    ControlArea->NumberOfSectionReferences = 1;
    ControlArea->NumberOfUserReferences = 1;

    /* Convert allocation attributes to control area flags */
    if (AllocationAttributes & SEC_BASED) ControlArea->u.Flags.Based = 1;
    if (AllocationAttributes & SEC_RESERVE) ControlArea->u.Flags.Reserve = 1;
    if (AllocationAttributes & SEC_COMMIT) ControlArea->u.Flags.Commit = 1;

    /* The subsection follows, write the mask, PTE count and point back to the CA */
    Subsection = (PSUBSECTION)(ControlArea + 1);
    Subsection->ControlArea = ControlArea;
    Subsection->PtesInSubsection = ProtoCount;
    Subsection->u.SubsectionFlags.Protection = ProtectionMask;

    /* Zero out the segment's section protos, and link it with the control area */
    SectionProto = &NewSegment->ThePtes[0];
    RtlZeroMemory(NewSegment, sizeof(SEGMENT));
    NewSegment->PrototypePte = SectionProto;
    NewSegment->ControlArea = ControlArea;

    /* Save some extra accounting data for the segment as well */
    NewSegment->u1.CreatingProcess = PsGetCurrentProcess();
    NewSegment->SizeOfSegment = ProtoCount * PAGE_SIZE;
    NewSegment->TotalNumberOfPtes = ProtoCount;
    NewSegment->NonExtendedPtes = ProtoCount;

    /* The subsection's base address is the first section proto in the segment */
    Subsection->SubsectionBase = SectionProto;

    /* Start with an empty PTE, unless this is a commit operation */
    TempPte.u.Long = 0;

    if (AllocationAttributes & SEC_COMMIT)
    {
        /* In which case, write down the protection mask in the section protos */
        TempPte.u.Soft.Protection = ProtectionMask;

        /* For accounting, also mark these pages as being committed */
        NewSegment->NumberOfCommittedPages = ProtoCount;
        InterlockedExchangeAdd((volatile PLONG)&MmSharedCommit, ProtoCount);

        if (AllocationAttributes & SEC_LARGE_PAGES)
        {
            /* No large pages in ARM3 yet */
            DPRINT1("MiCreatePagingFileMap: AllocationAttributes & SEC_LARGE_PAGES\n");
            ASSERT(FALSE);
        }
    }

    /* The template PTE itself for the segment should also have the mask set */
    NewSegment->SegmentPteTemplate.u.Soft.Protection = ProtectionMask;

    /* Write out the section protos, for now they're simply demand zero */
    if (!(AllocationAttributes & SEC_LARGE_PAGES))
    {
        /* Write out the section protos, for now they're simply demand zero */
#if defined (_WIN64) || defined (_X86PAE_)
        RtlFillMemoryUlonglong(SectionProto, ProtoCount * sizeof(MMPTE), TempPte.u.Long);
#else
        RtlFillMemoryUlong(SectionProto, ProtoCount * sizeof(MMPTE), TempPte.u.Long);
#endif
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
MiCreateImageFileMap(PFILE_OBJECT FileObject,
                     PSEGMENT *OutSegment)
{
    LARGE_INTEGER fileSize;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("MiCreateImageFileMap: FileObject %p\n", FileObject);

    Status = FsRtlGetFileSize(FileObject, &fileSize);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MiCreateImageFileMap: Status %X, File '%wZ'\n", Status, &FileObject->FileName);

        if (Status != STATUS_FILE_IS_A_DIRECTORY)
        {
            ASSERT(FALSE);
            return Status;
        }

        ASSERT(FALSE);
        return STATUS_INVALID_FILE_FOR_SECTION;
    }

    if (fileSize.HighPart)
    {
        DPRINT1("MiCreateImageFileMap: return STATUS_INVALID_FILE_FOR_SECTION, File '%wZ'\n", Status, &FileObject->FileName);
        ASSERT(FALSE);
        return STATUS_INVALID_FILE_FOR_SECTION;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
MiGetFileObjectForSectionAddress(
    IN PVOID Address,
    OUT PFILE_OBJECT *FileObject)
{
    PMMVAD Vad;
    PCONTROL_AREA ControlArea;

    ASSERT(FALSE);

    /* Get the VAD */
    Vad = MiLocateAddress(Address);
    if (Vad == NULL)
    {
        /* Fail, the address does not exist */
        DPRINT1("Invalid address\n");
        return STATUS_INVALID_ADDRESS;
    }

    /* Check if this is a RosMm memory area */
    if (Vad->u.VadFlags.Spare != 0)
    {
        PMEMORY_AREA MemoryArea = (PMEMORY_AREA)Vad;
        PROS_SECTION_OBJECT Section;

        /* Check if it's a section view (RosMm section) */
        if (MemoryArea->Type == MEMORY_AREA_SECTION_VIEW)
        {
            /* Get the section pointer to the SECTION_OBJECT */
            Section = MemoryArea->Data.SectionData.Section;
            *FileObject = Section->FileObject;
        }
        else
        {
            ASSERT(MemoryArea->Type == MEMORY_AREA_CACHE);
            DPRINT1("Address is a cache section!\n");
            return STATUS_SECTION_NOT_IMAGE;
        }
    }
    else
    {
        /* Make sure it's not a VM VAD */
        if (Vad->u.VadFlags.PrivateMemory == 1)
        {
            DPRINT1("Address is not a section\n");
            return STATUS_SECTION_NOT_IMAGE;
        }

        /* Get the control area */
        ControlArea = Vad->ControlArea;
        if (!(ControlArea) || !(ControlArea->u.Flags.Image))
        {
            DPRINT1("Address is not a section\n");
            return STATUS_SECTION_NOT_IMAGE;
        }

        /* Get the file object */
        *FileObject = ControlArea->FilePointer;
    }

    /* Return success */
    return STATUS_SUCCESS;
}

PFILE_OBJECT
NTAPI
MmGetFileObjectForSection(IN PVOID SectionObject)
{
    PSECTION_OBJECT Section;
    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    ASSERT(SectionObject != NULL);

    ASSERT(FALSE);

    /* Check if it's an ARM3, or ReactOS section */
    if (MiIsRosSectionObject(SectionObject) == FALSE)
    {
        /* Return the file pointer stored in the control area */
        Section = SectionObject;
        return Section->Segment->ControlArea->FilePointer;
    }

    /* Return the file object */
    return ((PROS_SECTION_OBJECT)SectionObject)->FileObject;
}

static
PFILE_OBJECT
MiGetFileObjectForVad(
    _In_ PMMVAD Vad)
{
    PCONTROL_AREA ControlArea;
    PFILE_OBJECT FileObject;

    ASSERT(FALSE);

    /* Check if this is a RosMm memory area */
    if (Vad->u.VadFlags.Spare != 0)
    {
        PMEMORY_AREA MemoryArea = (PMEMORY_AREA)Vad;
        PROS_SECTION_OBJECT Section;

        /* Check if it's a section view (RosMm section) */
        if (MemoryArea->Type == MEMORY_AREA_SECTION_VIEW)
        {
            /* Get the section pointer to the SECTION_OBJECT */
            Section = MemoryArea->Data.SectionData.Section;
            FileObject = Section->FileObject;
        }
        else
        {
            ASSERT(MemoryArea->Type == MEMORY_AREA_CACHE);
            DPRINT1("VAD is a cache section!\n");
            return NULL;
        }
    }
    else
    {
        /* Make sure it's not a VM VAD */
        if (Vad->u.VadFlags.PrivateMemory == 1)
        {
            DPRINT1("VAD is not a section\n");
            return NULL;
        }

        /* Get the control area */
        ControlArea = Vad->ControlArea;
        if ((ControlArea == NULL) || !ControlArea->u.Flags.Image)
        {
            DPRINT1("Address is not a section\n");
            return NULL;
        }

        /* Get the file object */
        FileObject = ControlArea->FilePointer;
    }

    /* Return the file object */
    return FileObject;
}

VOID
NTAPI
MmGetImageInformation (OUT PSECTION_IMAGE_INFORMATION ImageInformation)
{
    PSECTION_OBJECT SectionObject;

    ASSERT(FALSE);

    /* Get the section object of this process*/
    SectionObject = PsGetCurrentProcess()->SectionObject;
    ASSERT(SectionObject != NULL);
    ASSERT(MiIsRosSectionObject(SectionObject) == TRUE);

    /* Return the image information */
    *ImageInformation = ((PROS_SECTION_OBJECT)SectionObject)->ImageSection->ImageInformation;
}

NTSTATUS
NTAPI
MmGetFileNameForFileObject(IN PFILE_OBJECT FileObject,
                           OUT POBJECT_NAME_INFORMATION *ModuleName)
{
    POBJECT_NAME_INFORMATION ObjectNameInfo;
    NTSTATUS Status;
    ULONG ReturnLength;

    ASSERT(FALSE);

    /* Allocate memory for our structure */
    ObjectNameInfo = ExAllocatePoolWithTag(PagedPool, 1024, TAG_MM);
    if (!ObjectNameInfo) return STATUS_NO_MEMORY;

    /* Query the name */
    Status = ObQueryNameString(FileObject,
                               ObjectNameInfo,
                               1024,
                               &ReturnLength);
    if (!NT_SUCCESS(Status))
    {
        /* Failed, free memory */
        DPRINT1("Name query failed\n");
        ExFreePoolWithTag(ObjectNameInfo, TAG_MM);
        *ModuleName = NULL;
        return Status;
    }

    /* Success */
    *ModuleName = ObjectNameInfo;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
MmGetFileNameForSection(IN PVOID Section,
                        OUT POBJECT_NAME_INFORMATION *ModuleName)
{
    PFILE_OBJECT FileObject;

    ASSERT(FALSE);

    /* Make sure it's an image section */
    if (MiIsRosSectionObject(Section) == FALSE)
    {
        /* Check ARM3 Section flag */
        if (((PSECTION)Section)->u.Flags.Image == 0)
        {
            /* It's not, fail */
            DPRINT1("Not an image section\n");
            return STATUS_SECTION_NOT_IMAGE;
        }
    }
    else if (!(((PROS_SECTION_OBJECT)Section)->AllocationAttributes & SEC_IMAGE))
    {
        /* It's not, fail */
        DPRINT1("Not an image section\n");
        return STATUS_SECTION_NOT_IMAGE;
    }

    /* Get the file object */
    FileObject = MmGetFileObjectForSection(Section);
    return MmGetFileNameForFileObject(FileObject, ModuleName);
}

NTSTATUS
NTAPI
MmGetFileNameForAddress(IN PVOID Address,
                        OUT PUNICODE_STRING ModuleName)
{
    POBJECT_NAME_INFORMATION ModuleNameInformation;
    PVOID AddressSpace;
    NTSTATUS Status;
    PMMVAD Vad;
    PFILE_OBJECT FileObject = NULL;

    ASSERT(FALSE);

    /* Lock address space */
    AddressSpace = MmGetCurrentAddressSpace();
    MmLockAddressSpace(AddressSpace);

    /* Get the VAD */
    Vad = MiLocateAddress(Address);
    if (Vad == NULL)
    {
        /* Fail, the address does not exist */
        DPRINT1("No VAD at address %p\n", Address);
        MmUnlockAddressSpace(AddressSpace);
        return STATUS_INVALID_ADDRESS;
    }

    /* Get the file object pointer for the VAD */
    FileObject = MiGetFileObjectForVad(Vad);
    if (FileObject == NULL)
    {
        DPRINT1("Failed to get file object for Address %p\n", Address);
        MmUnlockAddressSpace(AddressSpace);
        return STATUS_SECTION_NOT_IMAGE;
    }

    /* Reference the file object */
    ObReferenceObject(FileObject);

    /* Unlock address space */
    MmUnlockAddressSpace(AddressSpace);

    /* Get the filename of the file object */
    Status = MmGetFileNameForFileObject(FileObject, &ModuleNameInformation);

    /* Dereference the file object */
    ObDereferenceObject(FileObject);

    /* Check if we were able to get the file object name */
    if (NT_SUCCESS(Status))
    {
        /* Init modulename */
        RtlCreateUnicodeString(ModuleName, ModuleNameInformation->Name.Buffer);

        /* Free temp taged buffer from MmGetFileNameForFileObject() */
        ExFreePoolWithTag(ModuleNameInformation, TAG_MM);
        DPRINT("Found ModuleName %S by address %p\n", ModuleName->Buffer, Address);
    }

   /* Return status */
   return Status;
}

NTSTATUS
NTAPI
MiQueryMemorySectionName(IN HANDLE ProcessHandle,
                         IN PVOID BaseAddress,
                         OUT PVOID MemoryInformation,
                         IN SIZE_T MemoryInformationLength,
                         OUT PSIZE_T ReturnLength)
{
    PEPROCESS Process;
    NTSTATUS Status;
    UNICODE_STRING ModuleFileName;
    PMEMORY_SECTION_NAME SectionName = NULL;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();

    ASSERT(FALSE);

    Status = ObReferenceObjectByHandle(ProcessHandle,
                                       PROCESS_QUERY_INFORMATION,
                                       NULL,
                                       PreviousMode,
                                       (PVOID*)(&Process),
                                       NULL);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("MiQueryMemorySectionName: ObReferenceObjectByHandle returned %x\n",Status);
        return Status;
    }

    Status = MmGetFileNameForAddress(BaseAddress, &ModuleFileName);

    if (NT_SUCCESS(Status))
    {
        SectionName = MemoryInformation;
        if (PreviousMode != KernelMode)
        {
            _SEH2_TRY
            {
                RtlInitEmptyUnicodeString(&SectionName->SectionFileName,
                                          (PWSTR)(SectionName + 1),
                                          MemoryInformationLength - sizeof(MEMORY_SECTION_NAME));
                RtlCopyUnicodeString(&SectionName->SectionFileName, &ModuleFileName);

                if (ReturnLength) *ReturnLength = ModuleFileName.Length + sizeof(MEMORY_SECTION_NAME);

            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;
        }
        else
        {
            RtlInitEmptyUnicodeString(&SectionName->SectionFileName,
                                      (PWSTR)(SectionName + 1),
                                      MemoryInformationLength - sizeof(MEMORY_SECTION_NAME));
            RtlCopyUnicodeString(&SectionName->SectionFileName, &ModuleFileName);

            if (ReturnLength) *ReturnLength = ModuleFileName.Length + sizeof(MEMORY_SECTION_NAME);

        }

        RtlFreeUnicodeString(&ModuleFileName);
    }
    ObDereferenceObject(Process);
    return Status;
}

VOID
NTAPI
MiFlushTbAndCapture(IN PMMVAD FoundVad,
                    IN PMMPTE Pte,
                    IN ULONG ProtectionMask,
                    IN PMMPFN Pfn1,
                    IN BOOLEAN UpdateDirty)
{
    MMPTE TempPte, PreviousPte;
    KIRQL OldIrql;
    BOOLEAN RebuildPte = FALSE;

    ASSERT(FALSE);

    //
    // User for sanity checking later on
    //
    PreviousPte = *Pte;

    //
    // Build the PTE and acquire the PFN lock
    //
    MI_MAKE_HARDWARE_PTE_USER(&TempPte,
                              Pte,
                              ProtectionMask,
                              PreviousPte.u.Hard.PageFrameNumber);
    OldIrql = MiAcquirePfnLock();

    //
    // We don't support I/O mappings in this path yet
    //
    ASSERT(Pfn1 != NULL);
    ASSERT(Pfn1->u3.e1.CacheAttribute != MiWriteCombined);

    //
    // Make sure new protection mask doesn't get in conflict and fix it if it does
    //
    if (Pfn1->u3.e1.CacheAttribute == MiCached)
    {
        //
        // This is a cached PFN
        //
        if (ProtectionMask & (MM_NOCACHE | MM_NOACCESS))
        {
            RebuildPte = TRUE;
            ProtectionMask &= ~(MM_NOCACHE | MM_NOACCESS);
        }
    }
    else if (Pfn1->u3.e1.CacheAttribute == MiNonCached)
    {
        //
        // This is a non-cached PFN
        //
        if ((ProtectionMask & (MM_NOCACHE | MM_NOACCESS)) != MM_NOCACHE)
        {
            RebuildPte = TRUE;
            ProtectionMask &= ~MM_NOACCESS;
            ProtectionMask |= MM_NOCACHE;
        }
    }

    if (RebuildPte)
    {
        MI_MAKE_HARDWARE_PTE_USER(&TempPte,
                                  Pte,
                                  ProtectionMask,
                                  PreviousPte.u.Hard.PageFrameNumber);
    }

    //
    // Write the new PTE, making sure we are only changing the bits
    //
    MI_UPDATE_VALID_PTE(Pte, TempPte);

    //
    // Flush the TLB
    //
    ASSERT(PreviousPte.u.Hard.Valid == 1);
    KeFlushCurrentTb();
    ASSERT(PreviousPte.u.Hard.Valid == 1);

    //
    // Windows updates the relevant PFN1 information, we currently don't.
    //
    if (UpdateDirty && PreviousPte.u.Hard.Dirty)
    {
        if (!Pfn1->u3.e1.Modified)
        {
            DPRINT1("FIXME: Mark PFN as dirty\n");
        }
    }

    //
    // Not supported in ARM3
    //
    ASSERT(FoundVad->u.VadFlags.VadType != VadWriteWatch);

    //
    // Release the PFN lock, we are done
    //
    MiReleasePfnLock(OldIrql);
}

//
// NOTE: This function gets a lot more complicated if we want Copy-on-Write support
//
NTSTATUS
NTAPI
MiSetProtectionOnSection(IN PEPROCESS Process,
                         IN PMMVAD FoundVad,
                         IN PVOID StartingAddress,
                         IN PVOID EndingAddress,
                         IN ULONG NewProtect,
                         OUT PULONG CapturedOldProtect,
                         IN ULONG DontCharge,
                         OUT PULONG Locked)
{
    PMMPTE Pte, LastPte;
    MMPTE TempPte, PteContents;
    PMMPDE Pde;
    PMMPFN Pfn1;
    ULONG ProtectionMask, QuotaCharge = 0;
    PETHREAD Thread = PsGetCurrentThread();
    PAGED_CODE();

    ASSERT(FALSE);

    //
    // Tell caller nothing is being locked
    //
    *Locked = FALSE;

    //
    // This function should only be used for section VADs. Windows ASSERT */
    //
    ASSERT(FoundVad->u.VadFlags.PrivateMemory == 0);

    //
    // We don't support these features in ARM3
    //
    ASSERT(FoundVad->u.VadFlags.VadType != VadImageMap);
    ASSERT(FoundVad->u2.VadFlags2.CopyOnWrite == 0);

    //
    // Convert and validate the protection mask
    //
    ProtectionMask = MiMakeProtectionMask(NewProtect);
    if (ProtectionMask == MM_INVALID_PROTECTION)
    {
        DPRINT1("Invalid section protect\n");
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    //
    // Get the PTE and PDE for the address, as well as the final PTE
    //
    MiLockProcessWorkingSetUnsafe(Process, Thread);
    Pde = MiAddressToPde(StartingAddress);
    Pte = MiAddressToPte(StartingAddress);
    LastPte = MiAddressToPte(EndingAddress);

    //
    // Make the PDE valid, and check the status of the first PTE
    //
    MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);
    if (Pte->u.Long)
    {
        //
        // Not supported in ARM3
        //
        ASSERT(FoundVad->u.VadFlags.VadType != VadRotatePhysical);

        //
        // Capture the page protection and make the PDE valid
        //
        *CapturedOldProtect = MiGetPageProtection(Pte);
        MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);
    }
    else
    {
        //
        // Only pagefile-backed section VADs are supported for now
        //
        ASSERT(FoundVad->u.VadFlags.VadType != VadImageMap);

        //
        // Grab the old protection from the VAD itself
        //
        *CapturedOldProtect = MmProtectToValue[FoundVad->u.VadFlags.Protection];
    }

    //
    // Loop all the PTEs now
    //
    MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);
    while (Pte <= LastPte)
    {
        //
        // Check if we've crossed a PDE boundary and make the new PDE valid too
        //
        if (MiIsPteOnPdeBoundary(Pte))
        {
            Pde = MiPteToPde(Pte);
            MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);
        }

        //
        // Capture the PTE and see what we're dealing with
        //
        PteContents = *Pte;
        if (PteContents.u.Long == 0)
        {
            //
            // This used to be a zero PTE and it no longer is, so we must add a
            // reference to the pagetable.
            //
            MiIncrementPageTableReferences(MiPteToAddress(Pte));

            //
            // Create the demand-zero prototype PTE
            //
            TempPte = PrototypePte;
            TempPte.u.Soft.Protection = ProtectionMask;
            MI_WRITE_INVALID_PTE(Pte, TempPte);
        }
        else if (PteContents.u.Hard.Valid == 1)
        {
            //
            // Get the PFN entry
            //
            Pfn1 = MiGetPfnEntry(PFN_FROM_PTE(&PteContents));

            //
            // We don't support these yet
            //
            ASSERT((NewProtect & (PAGE_NOACCESS | PAGE_GUARD)) == 0);
            ASSERT(Pfn1->u3.e1.PrototypePte == 0);

            //
            // Write the protection mask and write it with a TLB flush
            //
            Pfn1->OriginalPte.u.Soft.Protection = ProtectionMask;
            MiFlushTbAndCapture(FoundVad,
                                Pte,
                                ProtectionMask,
                                Pfn1,
                                TRUE);
        }
        else
        {
            //
            // We don't support these cases yet
            //
            ASSERT(PteContents.u.Soft.Prototype == 0);
            ASSERT(PteContents.u.Soft.Transition == 0);

            //
            // The PTE is already demand-zero, just update the protection mask
            //
            Pte->u.Soft.Protection = ProtectionMask;
        }

        Pte++;
    }

    //
    // Unlock the working set and update quota charges if needed, then return
    //
    MiUnlockProcessWorkingSetUnsafe(Process, Thread);
    if ((QuotaCharge > 0) && (!DontCharge))
    {
        FoundVad->u.VadFlags.CommitCharge -= QuotaCharge;
        Process->CommitCharge -= QuotaCharge;
    }
    return STATUS_SUCCESS;
}

VOID
NTAPI
MiRemoveMappedPtes(IN PVOID BaseAddress,
                   IN ULONG NumberOfPtes,
                   IN PCONTROL_AREA ControlArea,
                   IN PMMSUPPORT Ws)
{
    PMMPTE Pte, ProtoPte;//, FirstPte;
    PMMPDE Pde, SystemMapPde;
    PMMPFN Pfn1, Pfn2;
    MMPTE PteContents;
    KIRQL OldIrql;
    DPRINT("Removing mapped view at: 0x%p\n", BaseAddress);

    ASSERT(FALSE);

    ASSERT(Ws == NULL);

    /* Get the PTE and loop each one */
    Pte = MiAddressToPte(BaseAddress);
    //FirstPte = Pte;
    while (NumberOfPtes)
    {
        /* Check if the PTE is already valid */
        PteContents = *Pte;
        if (PteContents.u.Hard.Valid == 1)
        {
            /* Get the PFN entry */
            Pfn1 = MiGetPfnEntry(PFN_FROM_PTE(&PteContents));

            /* Get the PTE */
            Pde = MiPteToPde(Pte);

            /* Lock the PFN database and make sure this isn't a mapped file */
            OldIrql = MiAcquirePfnLock();
            ASSERT(((Pfn1->u3.e1.PrototypePte) && (Pfn1->OriginalPte.u.Soft.Prototype)) == 0);

            /* Mark the page as modified accordingly */
            if (MI_IS_PAGE_DIRTY(&PteContents))
                Pfn1->u3.e1.Modified = 1;

            /* Was the PDE invalid */
            if (Pde->u.Long == 0)
            {
#if (_MI_PAGING_LEVELS == 2)
                /* Find the system double-mapped PDE that describes this mapping */
                SystemMapPde = &MmSystemPagePtes[MiGetPdeOffset(Pde)];

                /* Make it valid */
                ASSERT(SystemMapPde->u.Hard.Valid == 1);
                MI_WRITE_VALID_PDE(Pde, *SystemMapPde);
#else
                DBG_UNREFERENCED_LOCAL_VARIABLE(SystemMapPde);
                ASSERT(FALSE);
#endif
            }

            /* Dereference the PDE and the PTE */
            Pfn2 = MiGetPfnEntry(PFN_FROM_PTE(Pde));
            MiDecrementShareCount(Pfn2, PFN_FROM_PTE(Pde));
            DBG_UNREFERENCED_LOCAL_VARIABLE(Pfn2);
            MiDecrementShareCount(Pfn1, PFN_FROM_PTE(&PteContents));

            /* Release the PFN lock */
            MiReleasePfnLock(OldIrql);
        }
        else
        {
            /* Windows ASSERT */
            ASSERT((PteContents.u.Long == 0) || (PteContents.u.Soft.Prototype == 1));

            /* Check if this is a prototype pointer PTE */
            if (PteContents.u.Soft.Prototype == 1)
            {
                /* Get the prototype PTE */
                ProtoPte = MiGetProtoPtr(&PteContents);

                /* We don't support anything else atm */
                ASSERT(ProtoPte->u.Long == 0);
            }
        }

        /* Make the PTE into a zero PTE */
        Pte->u.Long = 0;

        /* Move to the next PTE */
        Pte++;
        NumberOfPtes--;
    }

    /* Flush the TLB */
    KeFlushCurrentTb();

    /* Acquire the PFN lock */
    OldIrql = MiAcquirePfnLock();

    /* Decrement the accounting counters */
    ControlArea->NumberOfUserReferences--;
    ControlArea->NumberOfMappedViews--;

    /* Check if we should destroy the CA and release the lock */
    MiCheckControlArea(ControlArea, OldIrql);
}

ULONG
NTAPI
MiRemoveFromSystemSpace(IN PMMSESSION Session,
                        IN PVOID Base,
                        OUT PCONTROL_AREA *ControlArea)
{
    ULONG Hash, Size, Count = 0;
    ULONG_PTR Entry;
    PAGED_CODE();

    ASSERT(FALSE);

    /* Compute the hash for this entry and loop trying to find it */
    Entry = (ULONG_PTR)Base >> 16;
    Hash = Entry % Session->SystemSpaceHashKey;
    while ((Session->SystemSpaceViewTable[Hash].Entry >> 16) != Entry)
    {
        /* Check if we overflew past the end of the hash table */
        if (++Hash >= Session->SystemSpaceHashSize)
        {
            /* Reset the hash to zero and keep searching from the bottom */
            Hash = 0;
            if (++Count == 2)
            {
                /* But if we overflew twice, then this is not a real mapping */
                KeBugCheckEx(DRIVER_UNMAPPING_INVALID_VIEW,
                             (ULONG_PTR)Base,
                             1,
                             0,
                             0);
            }
        }
    }

    /* One less entry */
    Session->SystemSpaceHashEntries--;

    /* Extract the size and clear the entry */
    Size = Session->SystemSpaceViewTable[Hash].Entry & 0xFFFF;
    Session->SystemSpaceViewTable[Hash].Entry = 0;

    /* Return the control area and the size */
    *ControlArea = Session->SystemSpaceViewTable[Hash].ControlArea;
    return Size;
}

NTSTATUS
NTAPI
MiUnmapViewInSystemSpace(IN PMMSESSION Session,
                         IN PVOID MappedBase)
{
    ULONG Size;
    PCONTROL_AREA ControlArea;
    PAGED_CODE();

    ASSERT(FALSE);

    /* Remove this mapping */
    KeAcquireGuardedMutex(Session->SystemSpaceViewLockPointer);
    Size = MiRemoveFromSystemSpace(Session, MappedBase, &ControlArea);

    /* Clear the bits for this mapping */
    RtlClearBits(Session->SystemSpaceBitMap,
                 (ULONG)(((ULONG_PTR)MappedBase - (ULONG_PTR)Session->SystemSpaceViewStart) >> 16),
                 Size);

    /* Convert the size from a bit size into the actual size */
    Size = Size * (_64K >> PAGE_SHIFT);

    /* Remove the PTEs now */
    MiRemoveMappedPtes(MappedBase, Size, ControlArea, NULL);
    KeReleaseGuardedMutex(Session->SystemSpaceViewLockPointer);

    /* Return success */
    return STATUS_SUCCESS;
}

BOOLEAN
NTAPI
MiCheckControlAreaStatus(IN ULONG Type,
                         IN PSECTION_OBJECT_POINTERS SectionObjectPointer,
                         IN BOOLEAN IsDeleteOnClose,
                         OUT PCONTROL_AREA * OutControlArea,
                         OUT KIRQL * OutOldIrql)
{
    PCONTROL_AREA ControlArea;
    ULONG NumberOfReferences;
    KIRQL OldIrql;

    DPRINT("MiCheckControlAreaStatus: Type %X, SectionPointers %p, IsDeleteOnClose %X\n", Type, SectionObjectPointer, IsDeleteOnClose);

    *OutControlArea = NULL;

    // FIXME SegmentEvent!

    OldIrql = MiLockPfnDb(APC_LEVEL);
    
    if (Type == 1) // ImageSection
    {
        ControlArea = (PCONTROL_AREA)SectionObjectPointer->ImageSectionObject;
    }
    else
    {
        ControlArea = (PCONTROL_AREA)SectionObjectPointer->DataSectionObject;
    }

    DPRINT("MiCheckControlAreaStatus: ControlArea %p\n", ControlArea);

    if (ControlArea)
    {
        if (Type == 2) // UserReferences
        {
            NumberOfReferences = ControlArea->NumberOfUserReferences;
        }
        else
        {
            NumberOfReferences = ControlArea->NumberOfSectionReferences;
        }
    }
    else if (Type == 3) // ImageSection + UserReferences
    {
        ControlArea = (PCONTROL_AREA)SectionObjectPointer->ImageSectionObject;
        if (!ControlArea)
        {
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            DPRINT("MiCheckControlAreaStatus: FIXME SegmentEvent! return TRUE\n");
            return TRUE;
        }
        NumberOfReferences = ControlArea->NumberOfSectionReferences;
    }
    else
    {
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        DPRINT("MiCheckControlAreaStatus: FIXME SegmentEvent! return TRUE\n");
        return TRUE;
    }

    DPRINT("MiCheckControlAreaStatus: NumberOfReferences %X\n", NumberOfReferences);

    if (NumberOfReferences ||
        ControlArea->NumberOfMappedViews ||
        ControlArea->u.Flags.BeingCreated)
    {
        if (IsDeleteOnClose)
        {
            ControlArea->u.Flags.DeleteOnClose = 1;
        }

        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        DPRINT("MiCheckControlAreaStatus: FIXME SegmentEvent! return FALSE\n");
        return FALSE;
    }

    if (!ControlArea->u.Flags.BeingDeleted)
    {
        *OutControlArea = ControlArea;
        *OutOldIrql = OldIrql;

        DPRINT("MiCheckControlAreaStatus: FIXME SegmentEvent! return FALSE\n");
        return FALSE;
    }

    ASSERT(FALSE);

    return TRUE;
}

BOOLEAN
NTAPI
MmFlushImageSection(IN PSECTION_OBJECT_POINTERS SectionObjectPointer,
                    IN MMFLUSH_TYPE FlushType)
{
    PCONTROL_AREA ControlArea;
    BOOLEAN Result;
    KIRQL OldIrql;

    DPRINT("MmFlushImageSection: SectionPointers %p, FlushType %X\n", SectionObjectPointer, FlushType);

    if (FlushType == MmFlushForDelete)
    {
        ASSERT(FALSE);
    }

    Result = MiCheckControlAreaStatus(1, SectionObjectPointer, FALSE, &ControlArea, &OldIrql);
    if (!ControlArea)
    {
        return Result;
    }

    ASSERT(FALSE);

    return TRUE;
}

BOOLEAN
NTAPI
MiCanFileBeTruncatedInternal(IN PSECTION_OBJECT_POINTERS SectionObjectPointer,
                             IN OUT PLARGE_INTEGER FileOffset,
                             IN BOOLEAN IsNotCheckUserReferences,
                             OUT KIRQL * OutOldIrql)
{
    PCONTROL_AREA ControlArea;
    PSUBSECTION Subsection;
    LARGE_INTEGER TempOffset;
    KIRQL OldIrql;

    DPRINT("MiCanFileBeTruncatedInternal: SectionPointers %p, IsNotCheckUserReferences %X\n", SectionObjectPointer, IsNotCheckUserReferences);

    if (!MmFlushImageSection(SectionObjectPointer, MmFlushForWrite))
    {
        DPRINT("MiCanFileBeTruncatedInternal: return FALSE\n");
        return FALSE;
    }

    OldIrql = MiLockPfnDb(APC_LEVEL);

    ControlArea = (PCONTROL_AREA)SectionObjectPointer->DataSectionObject;
    if (!ControlArea)
    {
        DPRINT("MiCanFileBeTruncatedInternal: ControlArea == NULL\n");
        *OutOldIrql = OldIrql;
        return TRUE;
    }

    if (ControlArea->u.Flags.BeingCreated ||
        ControlArea->u.Flags.BeingDeleted ||
        ControlArea->u.Flags.Rom)
    {
        goto Exit;
    }

    if (!ControlArea->NumberOfUserReferences ||
        (IsNotCheckUserReferences && !ControlArea->NumberOfMappedViews))
    {
        DPRINT("MiCanFileBeTruncatedInternal: return TRUE\n");
        *OutOldIrql = OldIrql;
        return TRUE;
    }

    if (!FileOffset)
    {
        goto Exit;
    }

    ASSERT(ControlArea->u.Flags.Image == 0);
    ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);

    Subsection = (PSUBSECTION)&ControlArea[1];

    if (ControlArea->FilePointer)
    {
        PSEGMENT Segment = ControlArea->Segment;

        if (MiIsAddressValid(ControlArea->Segment))
        {
            if (Segment->u1.ImageCommitment)
            {
                Subsection = (PSUBSECTION)Segment->u1.ImageCommitment;
            }
        }
    }

    while (Subsection->NextSubsection)
    {
        Subsection = Subsection->NextSubsection;
    }

    ASSERT(Subsection->ControlArea == ControlArea);

    if (Subsection->ControlArea->u.Flags.Image)
    {
        TempOffset.QuadPart = (Subsection->StartingSector + Subsection->NumberOfFullSectors);
        TempOffset.QuadPart *= MM_SECTOR_SIZE;
    }
    else
    {
        TempOffset.HighPart = Subsection->u.SubsectionFlags.StartingSector4132;
        TempOffset.LowPart = Subsection->StartingSector;

        TempOffset.QuadPart += Subsection->NumberOfFullSectors;
        TempOffset.QuadPart *= PAGE_SIZE;
    }

    TempOffset.QuadPart += Subsection->u.SubsectionFlags.SectorEndOffset;

    if (FileOffset->QuadPart >= TempOffset.QuadPart)
    {
        TempOffset.QuadPart += PAGE_SIZE - 1;
        TempOffset.LowPart &= ~(PAGE_SIZE - 1);

        if ((ULONGLONG)FileOffset->QuadPart < (ULONGLONG)TempOffset.QuadPart)
        {
            *FileOffset = TempOffset;
        }

        DPRINT("MiCanFileBeTruncatedInternal: return TRUE\n");
        *OutOldIrql = OldIrql;
        return TRUE;
    }

Exit:

    DPRINT("MiCanFileBeTruncatedInternal: return FALSE\n");
    MiUnlockPfnDb(OldIrql, APC_LEVEL);
    return FALSE;
}

VOID
NTAPI
MiInsertPhysicalViewAndRefControlArea(IN PEPROCESS Process,
                                      IN PCONTROL_AREA ControlArea,
                                      IN PMM_PHYSICAL_VIEW PhysicalView)
{
    KIRQL OldIrql;

    DPRINT("MiInsertPhysicalViewAndRefControlArea: Process %p, ControlArea %p, PhysicalView %p\n", Process, ControlArea, PhysicalView);

    ASSERT(PhysicalView->Vad->u.VadFlags.VadType == VadDevicePhysicalMemory);
    ASSERT(Process->PhysicalVadRoot != NULL);

    MiInsertVad((PMMVAD)PhysicalView, Process->PhysicalVadRoot);

    OldIrql = MiLockPfnDb(APC_LEVEL);

    ControlArea->NumberOfMappedViews++;
    ControlArea->NumberOfUserReferences++;

    ASSERT(ControlArea->NumberOfSectionReferences != 0);

    MiUnlockPfnDb(OldIrql, APC_LEVEL);
}

NTSTATUS
NTAPI
MiMapViewOfPhysicalSection(IN PCONTROL_AREA ControlArea,
                           IN PEPROCESS Process,
                           IN OUT PVOID * BaseAddress,
                           IN PLARGE_INTEGER SectionOffset,
                           IN OUT PSIZE_T ViewSize,
                           IN ULONG ProtectionMask,
                           IN ULONG_PTR ZeroBits,
                           IN ULONG AllocationType)
{
    PMM_PHYSICAL_VIEW PhysicalView;
    PMMADDRESS_NODE Parent;
    PETHREAD Thread;
    PMMVAD_LONG VadLong;
    ULONG_PTR StartingAddress;
    ULONG_PTR EndingAddress;
    ULONG_PTR TmpStartingAddress;
    ULONG_PTR HighestAddress;
    PMMPTE Pde;
    PMMPTE LastPte;
    PMMPTE Pte;
    MMPTE TempPte;
    PFN_NUMBER StartPageNumber;
    PFN_NUMBER CurrentPageNumber;
    PFN_COUNT PagesCount;
    PMMPFN Pfn;
    PVOID UsedAddress;
    MI_PFN_CACHE_ATTRIBUTE CacheAttribute;
    MEMORY_CACHING_TYPE InputCacheType;
    ULONG SizeOfRange;
    ULONG Offset;
    NTSTATUS Status;
    BOOLEAN IsIoMapping;
    KIRQL OldIrql;

    DPRINT("MiMapViewOfPhysicalSection: ControlArea %p, Process %p, BaseAddress [%p], SectionOffset [%I64X], ViewSize [%I64X], ProtectMask %X, ZeroBits %X, AllocType %X\n", ControlArea, Process, (BaseAddress?*BaseAddress:NULL), (SectionOffset?SectionOffset->QuadPart:0), (ViewSize?(ULONGLONG)*ViewSize:0), ProtectionMask, ZeroBits, AllocationType);

    if (AllocationType & (MEM_RESERVE | MEM_LARGE_PAGES))
    {
        DPRINT1("MiMapViewOfPhysicalSection: STATUS_INVALID_PARAMETER_9\n");
        return STATUS_INVALID_PARAMETER_9;
    }

    if ((ProtectionMask & MM_PROTECT_SPECIAL) == MM_GUARDPAGE ||
        ProtectionMask == MM_NOACCESS)
    {
        DPRINT1("MiMapViewOfPhysicalSection: STATUS_INVALID_PAGE_PROTECTION\n");
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    Offset = SectionOffset->LowPart & (MM_ALLOCATION_GRANULARITY - 1);

    if (*BaseAddress)
    {
        StartingAddress = ALIGN_DOWN_BY(*BaseAddress, MM_ALLOCATION_GRANULARITY) + Offset;
        EndingAddress = ((StartingAddress + *ViewSize - 1) | (PAGE_SIZE - 1));

        DPRINT("MiMapViewOfPhysicalSection: Base %p, StartingAddress %p, EndingAddress %p\n", *BaseAddress, StartingAddress, EndingAddress);

        if (MiCheckForConflictingVadExistence(Process, StartingAddress, EndingAddress))
        {
            DPRINT1("MiMapViewOfPhysicalSection: STATUS_CONFLICTING_ADDRESSES\n");
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }
    else
    {
        ASSERT(SectionOffset->HighPart == 0);

        SizeOfRange = Offset + *ViewSize;

        if ((AllocationType & MEM_TOP_DOWN) || Process->VmTopDown)
        {
            if (ZeroBits)
            {
                HighestAddress = ((ULONG_PTR)MI_HIGHEST_SYSTEM_ADDRESS >> ZeroBits);
                if (HighestAddress > (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS)
                {
                    HighestAddress = (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS;
                }
            }
            else
            {
                HighestAddress = (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS;
            }

            Status = MiFindEmptyAddressRangeDownTree(SizeOfRange, HighestAddress, MM_ALLOCATION_GRANULARITY, &Process->VadRoot, &TmpStartingAddress, &Parent);
        }
        else
        {
            Status = MiFindEmptyAddressRange(SizeOfRange, MM_ALLOCATION_GRANULARITY, ZeroBits, &TmpStartingAddress);
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("MiMapViewOfPhysicalSection: Status %X\n", Status);
            return Status;
        }

        StartingAddress = TmpStartingAddress + Offset;
        EndingAddress = (StartingAddress + *ViewSize - 1) | (PAGE_SIZE - 1);

        DPRINT1("MiMapViewOfPhysicalSection: TmpStartingAddress %X, StartingAddress %X, EndingAddress %X\n", TmpStartingAddress, StartingAddress, EndingAddress);

        if (ZeroBits && (EndingAddress > ((ULONG_PTR)MI_HIGHEST_SYSTEM_ADDRESS >> ZeroBits)))
        {
            DPRINT1("MiMapViewOfPhysicalSection: STATUS_NO_MEMORY\n");
            return STATUS_NO_MEMORY;
        }
    }

    Pde = MiAddressToPde((PVOID)StartingAddress);
    Pte = MiAddressToPte((PVOID)StartingAddress);
    LastPte = MiAddressToPte((PVOID)EndingAddress);

    StartPageNumber = (PFN_NUMBER)(SectionOffset->QuadPart / PAGE_SIZE);
    MI_MAKE_HARDWARE_PTE_USER(&TempPte, Pte, ProtectionMask, StartPageNumber);

    if (TempPte.u.Hard.Write)
    {
        MI_MAKE_DIRTY_PAGE(&TempPte);
    }

    /* Is IO mapping */
    IsIoMapping = TRUE;

    if (StartPageNumber <= MmHighestPhysicalPage) // should be MmHighestPossiblePhysicalPage
    {
        if (MiGetPfnEntry(StartPageNumber) != NULL)
        {
            /* Is MEMORY mapping */
            IsIoMapping = FALSE;
        }
    }

    InputCacheType = MmCached;

    if (((ProtectionMask & MM_WRITECOMBINE) == MM_WRITECOMBINE) &&
        ((ProtectionMask & MM_PROTECT_ACCESS) != 0))
    {
        InputCacheType = MmWriteCombined;
    }
    else if ((ProtectionMask & MM_NOCACHE) == MM_NOCACHE)
    {
        InputCacheType = MmNonCached;
    }

    ASSERT(InputCacheType <= MmWriteCombined);

    if (IsIoMapping)
    {
        CacheAttribute = MiPlatformCacheAttributes[IsIoMapping][InputCacheType];
    }
    else
    {
        CacheAttribute = MiPlatformCacheAttributes[IsIoMapping][InputCacheType];
    }

    PagesCount = LastPte - Pte + 1;

    if (CacheAttribute != MiCached)
    {
        if (CacheAttribute == MiWriteCombined)
        {
            //ASSERT(MiWriteCombiningPtes);
            TempPte.u.Hard.CacheDisable = 1;
            TempPte.u.Hard.WriteThrough = 0;
        }
        else if (CacheAttribute == MiNonCached)
        {
            TempPte.u.Hard.CacheDisable = 1;
            TempPte.u.Hard.WriteThrough = 1;
        }

        for (CurrentPageNumber = StartPageNumber;
             CurrentPageNumber < (StartPageNumber + PagesCount);
             CurrentPageNumber++)
        {
            DPRINT1("MiMapViewOfPhysicalSection: FIXME MiMustFrameBeCached\n");
            ASSERT(FALSE);
        }
    }

    if (Process->PhysicalVadRoot == NULL)
    {
        if (!MiCreatePhysicalVadRoot(Process, FALSE))
        {
            DPRINT1("MiMapViewOfPhysicalSection: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    PhysicalView = ExAllocatePoolWithTag(NonPagedPool, sizeof(MM_PHYSICAL_VIEW), 'vpmM');
    if (PhysicalView == NULL)
    {
        DPRINT1("MiMapViewOfPhysicalSection: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    VadLong = ExAllocatePoolWithTag(NonPagedPool, sizeof(MMVAD_LONG), 'ldaV');
    if (!VadLong)
    {
        DPRINT1("MiMapViewOfPhysicalSection: STATUS_INSUFFICIENT_RESOURCES\n");
        ExFreePoolWithTag(PhysicalView, 'vpmM');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(VadLong, sizeof(MMVAD_LONG));

    VadLong->ControlArea = ControlArea;
    VadLong->StartingVpn = StartingAddress / PAGE_SIZE;
    VadLong->EndingVpn = EndingAddress / PAGE_SIZE;

    VadLong->u.VadFlags.VadType = VadDevicePhysicalMemory;
    VadLong->u.VadFlags.Protection = ProtectionMask;

    VadLong->u2.VadFlags2.Inherit = 0;
    VadLong->u2.VadFlags2.LongVad = 1;

    VadLong->LastContiguousPte = (PMMPTE)StartPageNumber;
    VadLong->FirstPrototypePte = (PMMPTE)StartPageNumber;

    PhysicalView->Vad = (PMMVAD)VadLong;
    PhysicalView->StartingVpn = VadLong->StartingVpn;
    PhysicalView->EndingVpn = VadLong->EndingVpn;
    PhysicalView->VadType = VadDevicePhysicalMemory;

    DPRINT1("MiMapViewOfPhysicalSection: FIXME MiCheckCacheAttributes\n");
    //ASSERT(FALSE);

    Thread = PsGetCurrentThread();

    Status = MiInsertVadCharges((PMMVAD)VadLong, Process);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MiMapViewOfPhysicalSection: Status %X\n", Status);
        ExFreePoolWithTag(PhysicalView, 'vpmM');
        ExFreePoolWithTag(VadLong, 'ldaV');
        return Status;
    }

    MiLockProcessWorkingSetUnsafe(Process, Thread);

    MiInsertVad((PMMVAD)VadLong, &Process->VadRoot);

    if (CacheAttribute != MiCached)
    {
        DPRINT1("MiMapViewOfPhysicalSection: FIXME\n");
        //MiFlushType[32]++;
        KeFlushEntireTb(TRUE, TRUE);
        KeInvalidateAllCaches();
    }

    MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);

    Pfn = MI_PFN_ELEMENT(Pde->u.Hard.PageFrameNumber);
    UsedAddress = (PVOID)StartingAddress;

    while (Pte <= LastPte)
    {
        if (!MiIsPteOnPdeBoundary(Pte))
        {
            Pde = MiAddressToPte(Pte);
            MiMakePdeExistAndMakeValid (Pde, Process, MM_NOIRQL);

            Pfn = MI_PFN_ELEMENT(Pde->u.Hard.PageFrameNumber);
            UsedAddress = MiPteToAddress(Pte);
        }

        MiIncrementPageTableReferences(UsedAddress);

        ASSERT(Pte->u.Long == 0);
        MI_WRITE_VALID_PTE(Pte, TempPte);

        OldIrql = MiLockPfnDb(APC_LEVEL);
        Pfn->u2.ShareCount++;
        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        Pte++;
        TempPte.u.Hard.PageFrameNumber++;
    }

    MiInsertPhysicalViewAndRefControlArea(Process, ControlArea, PhysicalView);

    MiUnlockProcessWorkingSetUnsafe(Process, Thread);

    *BaseAddress = (PVOID)StartingAddress;
    *ViewSize = EndingAddress - StartingAddress + 1;
    DPRINT1("MiMapViewOfPhysicalSection: Base %p, ViewSize %p\n", *BaseAddress, *ViewSize);

    Process->VirtualSize += *ViewSize;
    if (Process->VirtualSize > Process->PeakVirtualSize)
    {
        Process->PeakVirtualSize = Process->VirtualSize;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
MiMapViewOfImageSection(IN PCONTROL_AREA ControlArea,
                        IN PEPROCESS Process,
                        IN OUT PVOID * OutBaseAddress,
                        IN OUT LARGE_INTEGER * OutSectionOffset,
                        IN OUT SIZE_T * OutViewSize,
                        IN PSECTION Section,
                        IN SECTION_INHERIT InheritDisposition,
                        IN ULONG ZeroBits,
                        IN ULONG AllocationType,
                        IN SIZE_T ImageCommitment)
{
    DPRINT("MiMapViewOfImageSection: ControlArea %p, Process %p, OutBase [%p], Offset [%I64X], ViewSize [%p], Section %p, ZeroBits %X, AllocType %X, ImageCommitment %X\n", ControlArea, Process, (OutBaseAddress?*OutBaseAddress:NULL), (OutSectionOffset?OutSectionOffset->QuadPart:0), (OutViewSize?*OutViewSize:0), Section, ZeroBits, AllocationType, ImageCommitment);
    ASSERT(FALSE); return 0;
}

PCONTROL_AREA
NTAPI
MiFindImageSectionObject(IN PFILE_OBJECT FileObject,
                         IN BOOLEAN IsLocked,
                         OUT BOOLEAN * OutIsGlobal)
{
    PLARGE_CONTROL_AREA LargeControlArea;
    ULONG SessionId;
    PLIST_ENTRY Header;
    PLIST_ENTRY Entry;
    KIRQL OldIrql = PASSIVE_LEVEL;

    DPRINT("MiFindImageSectionObject: File %p\n", FileObject);

    *OutIsGlobal = FALSE;

    if (!IsLocked)
    {
        OldIrql = MiLockPfnDb(APC_LEVEL);
    }
    else
    {
        ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
        ASSERT(MmPfnOwner == KeGetCurrentThread());
    }

    if (!FileObject->SectionObjectPointer->ImageSectionObject)
    {
        goto Exit;
    }

    LargeControlArea = FileObject->SectionObjectPointer->ImageSectionObject;

    if (!LargeControlArea->u.Flags.GlobalOnlyPerSession)
    {
        goto Exit;
    }

    SessionId = MmGetSessionId(PsGetCurrentProcess());

    if (LargeControlArea->SessionId == SessionId)
    {
        goto Exit;
    }

    Header = &LargeControlArea->UserGlobalList;

    for (Entry = LargeControlArea->UserGlobalList.Flink;
         Entry != Header;
         Entry = Entry->Flink)
    {
        LargeControlArea = CONTAINING_RECORD(Entry, LARGE_CONTROL_AREA, UserGlobalList);

        ASSERT(LargeControlArea->u.Flags.GlobalOnlyPerSession == 1);

        if (LargeControlArea->SessionId == SessionId)
        {
            goto Exit;
        }
    }

    LargeControlArea = NULL;
    *OutIsGlobal = TRUE;

Exit:

    if (!IsLocked)
    {
         MiUnlockPfnDb(OldIrql, APC_LEVEL);
    }

    return (PCONTROL_AREA)LargeControlArea;
}

VOID
NTAPI
MiInsertImageSectionObject(IN PFILE_OBJECT FileObject,
                           IN PLARGE_CONTROL_AREA ControlArea)
{
    PLARGE_CONTROL_AREA NextControlArea;
    PLIST_ENTRY Header;
    PLIST_ENTRY Entry;
    ULONG SessionId;

    DPRINT("MiFindImageSectionObject: File %p, ControlArea %p\n", FileObject, ControlArea);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(MmPfnOwner == KeGetCurrentThread());

    if (!FileObject->SectionObjectPointer->ImageSectionObject &&
        !ControlArea->u.Flags.GlobalOnlyPerSession)
    {
        goto Exit;
    }

    ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 1);

    SessionId = MmGetSessionId(PsGetCurrentProcess());
    ControlArea->SessionId = SessionId;

    if (!FileObject->SectionObjectPointer->ImageSectionObject)
    {
        InitializeListHead(&ControlArea->UserGlobalList);
        goto Exit;
    }

    ASSERT(ControlArea->u.Flags.BeingDeleted ||
           ControlArea->u.Flags.BeingCreated ||
           ControlArea->SessionId != (ULONG)-1);

    Header = &(((PLARGE_CONTROL_AREA)FileObject->SectionObjectPointer->ImageSectionObject)->UserGlobalList);

    for (Entry = Header->Flink;
         Entry != Header;
         Entry = Entry->Flink)
    {
        NextControlArea = CONTAINING_RECORD(Entry, LARGE_CONTROL_AREA, UserGlobalList);
        ASSERT(NextControlArea->SessionId != (ULONG)-1 && NextControlArea->SessionId != ControlArea->SessionId);
    }

    InsertTailList(Header, &ControlArea->UserGlobalList);

Exit:

    FileObject->SectionObjectPointer->ImageSectionObject = ControlArea;
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * @implemented
 */
NTSTATUS
NTAPI
MmCreateSection(OUT PVOID *SectionObject,
                IN ACCESS_MASK DesiredAccess,
                IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
                IN PLARGE_INTEGER InputMaximumSize,
                IN ULONG SectionPageProtection,
                IN ULONG AllocationAttributes,
                IN HANDLE FileHandle OPTIONAL,
                IN PFILE_OBJECT FileObject OPTIONAL)
{
    SECTION Section;
    PSECTION NewSection;
    PSUBSECTION Subsection;
    PSEGMENT Segment = NULL;
    PSEGMENT NewSegment = NULL;
    PEVENT_COUNTER event;
    NTSTATUS Status;
    PCONTROL_AREA ControlArea;
    PVOID NewControlArea = NULL;
    ULONG ProtectionMask, ControlAreaSize;
    ULONG SubsectionSize, NonPagedCharge, PagedCharge;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    BOOLEAN FileLock = FALSE;
    KIRQL OldIrql;
    PFILE_OBJECT File;
    LARGE_INTEGER FileSize;
    BOOLEAN UserRefIncremented = FALSE;
    PVOID PreviousSectionPointer = NULL;
    BOOLEAN IgnoreFileSizing = FALSE; // TRUE if CC call (FileObject != NULL)
    BOOLEAN IsSectionSizeChanged = FALSE;

    DPRINT("MmCreateSection: Access %X, ObjAttributes %X, MaxSize %I64X, Protection %X, AllocAttributes %X, FileHandle %p, FileObject %p\n",
           DesiredAccess, ObjectAttributes, InputMaximumSize->QuadPart, SectionPageProtection, AllocationAttributes, FileHandle, FileObject);

    /* Make the same sanity checks that the Nt interface should've validated */
    ASSERT((AllocationAttributes & ~(SEC_COMMIT | SEC_RESERVE | SEC_BASED |
                                     SEC_LARGE_PAGES | SEC_IMAGE | SEC_NOCACHE |
                                     SEC_NO_CHANGE)) == 0);
    ASSERT((AllocationAttributes & (SEC_COMMIT | SEC_RESERVE | SEC_IMAGE)) != 0);
    ASSERT(!((AllocationAttributes & SEC_IMAGE) &&
             (AllocationAttributes & (SEC_COMMIT | SEC_RESERVE |
                                      SEC_NOCACHE | SEC_NO_CHANGE))));
    ASSERT(!((AllocationAttributes & SEC_COMMIT) && (AllocationAttributes & SEC_RESERVE)));
    ASSERT(!((SectionPageProtection & PAGE_NOCACHE) ||
             (SectionPageProtection & PAGE_WRITECOMBINE) ||
             (SectionPageProtection & PAGE_GUARD) ||
             (SectionPageProtection & PAGE_NOACCESS)));

    /* Convert section flag to page flag */
    if (AllocationAttributes & SEC_NOCACHE) SectionPageProtection |= PAGE_NOCACHE;

    /* Check to make sure the protection is correct. Nt* does this already */
    ProtectionMask = MiMakeProtectionMask(SectionPageProtection);
    if (ProtectionMask == MM_INVALID_PROTECTION)
    {
        DPRINT1("MmCreateSection: STATUS_INVALID_PAGE_PROTECTION\n");
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    /* Check if this is going to be a data or image backed file section */
    if ((FileHandle) || (FileObject))
    {
        /* These cannot be mapped with large pages */
        if (AllocationAttributes & SEC_LARGE_PAGES)
        {
            DPRINT1("MmCreateSection: STATUS_INVALID_PARAMETER_6\n");
            return STATUS_INVALID_PARAMETER_6;
        }

        DPRINT("MmCreateSection: FileHandle %p, FileObject %p\n", FileHandle, FileObject);

        if (FileHandle)
        {
            /* This is the file-mapped section. */
            ASSERT(!FileObject);

            /* Reference the file handle to get the object */
            Status = ObReferenceObjectByHandle(FileHandle,
                                               MmMakeFileAccess[ProtectionMask],
                                               IoFileObjectType,
                                               PreviousMode,
                                               (PVOID*)&File,
                                               NULL);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("MmCreateSection: Status %X\n", Status);
                return Status;
            }

            /* Make sure Cc has been doing its job */
            if (!File->SectionObjectPointer)
            {
                /* This is not a valid system-based file, fail */
                DPRINT1("MmCreateSection: STATUS_INVALID_FILE_FOR_SECTION\n");
                ObDereferenceObject(File);
                return STATUS_INVALID_FILE_FOR_SECTION;
            }
        }
        else
        {
            /* This is the section used by the CC. */
            ASSERT(!FileHandle);

            IgnoreFileSizing = TRUE;
            File = FileObject;

            if (File->SectionObjectPointer->DataSectionObject)
            {
                OldIrql = MiLockPfnDb(APC_LEVEL);

                ControlArea = (PCONTROL_AREA)(File->SectionObjectPointer->DataSectionObject);

                if (ControlArea &&
                    !ControlArea->u.Flags.BeingDeleted &&
                    !ControlArea->u.Flags.BeingCreated)
                {
                    ASSERT(FALSE);
                }

                MiUnlockPfnDb(OldIrql, APC_LEVEL);
            }

            ObReferenceObject(File);
        }

        /* Compute the size of the control area */
        if (AllocationAttributes & SEC_IMAGE)
        {
            /* Image-file backed section */
            ControlAreaSize = sizeof(LARGE_CONTROL_AREA) + sizeof(SUBSECTION);
            CcWaitForUninitializeCacheMap(File);
        }
        else
        {
            /* Data-file backed section */
            ControlAreaSize = sizeof(CONTROL_AREA) + sizeof(MSUBSECTION);
        }

        /* Alocate the control area */
        NewControlArea = ExAllocatePoolWithTag(NonPagedPool, ControlAreaSize, 'aCmM');
        if (!NewControlArea)
        {
            DPRINT1("MmCreateSection: return STATUS_INSUFFICIENT_RESOURCES\n");
            ObDereferenceObject(File);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        /* Zero it out */
        RtlZeroMemory(NewControlArea, ControlAreaSize);

        /* Did we get a handle, or an object? */
        if (FileHandle)
        {
            /* We got a file handle so we have to lock down the file */
#if 0
            Status = FsRtlAcquireToCreateMappedSection(File, SectionPageProtection);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("MmCreateSection: Status %X\n", Status);
                ExFreePoolWithTag(NewControlArea, 'aCmM');
                ObDereferenceObject(File);
                return Status;
            }
#else
            /* ReactOS doesn't support this API yet, so do nothing */
            DPRINT("MmCreateSection: FIXME FsRtlAcquireToCreateMappedSection\n");
            Status = STATUS_SUCCESS;
#endif
            /* Update the top-level IRP so that drivers know what's happening */
            IoSetTopLevelIrp((PIRP)FSRTL_FSP_TOP_LEVEL_IRP);
            FileLock = TRUE;
        }

        while (TRUE)
        {
            /* Lock the PFN database while we play with the section pointers */
            OldIrql = MiLockPfnDb(APC_LEVEL);

            if (AllocationAttributes & SEC_IMAGE)
            {
                /* Find control area for image-file backed section */
                DPRINT1("MmCreateSection: FIXME MiFindImageSectionObject \n");
                ASSERT(FALSE);
                ControlArea = NULL;//MiFindImageSectionObject(File, TRUE, &IsGlobal);
            }
            else
            {
                /* Get control area from file */
                ControlArea = (PCONTROL_AREA)File->SectionObjectPointer->DataSectionObject;
            }

            if (!ControlArea)
            {
                /* Write down that this CA is being created, and set it */
                ControlArea = NewControlArea;
                ControlArea->u.Flags.BeingCreated = 1;

                if (AllocationAttributes & SEC_IMAGE)
                {
                    DPRINT1("MmCreateSection: FIXME MiInsertImageSectionObject \n");
                    ASSERT(FALSE);//MiInsertImageSectionObject(File, (PLARGE_CONTROL_AREA)NewControlArea);
                }
                else
                {
                    PreviousSectionPointer = File->SectionObjectPointer;
                    File->SectionObjectPointer->DataSectionObject = ControlArea;
                }

                DPRINT("MmCreateSection: break\n");
                break;
            }
            else
            {
                if ((ControlArea->u.Flags.BeingDeleted) ||
                    (ControlArea->u.Flags.BeingCreated))
                {
                    if (ControlArea->WaitingForDeletion)
                    {
                        event = ControlArea->WaitingForDeletion;
                        event->RefCount++;
                    }
                    else
                    {
                         DPRINT1("MmCreateSection: FIXME\n");
                         ASSERT(FALSE);
                    }

                    MiUnlockPfnDb(OldIrql, APC_LEVEL);

                    /* Check if we locked and set the IRP */
                    if (FileLock)
                    {
                        /* Reset the top-level IRP and release the lock */
                        IoSetTopLevelIrp(NULL);
                        //FsRtlReleaseFile(File);
                    }

                    KeWaitForSingleObject(&event->Event, WrVirtualMemory, KernelMode, FALSE, NULL);

                    DPRINT1("MmCreateSection: FIXME MiFreeEventCounter \n");
                    ASSERT(FALSE);
                    //MiFreeEventCounter(event);

                    /* Check if we locked and set the IRP */
                    if (FileLock)
                    {
                        /* We got a file handle so we have to lock down the file */
#if 0
                        Status = FsRtlAcquireToCreateMappedSection(File, SectionPageProtection);
                        if (!NT_SUCCESS(Status))
                        {
                            DPRINT1("MmCreateSection: Status %X\n", Status);
                            ExFreePoolWithTag(NewControlArea, 'aCmM');
                            ObDereferenceObject(File);
                            return Status;
                        }
#else
                        /* ReactOS doesn't support this API yet, so do nothing */
                        DPRINT("MmCreateSection: FIXME FsRtlAcquireToCreateMappedSection\n");
                        Status = STATUS_SUCCESS;
#endif
                        /* Update the top-level IRP so that drivers know what's happening */
                        IoSetTopLevelIrp((PIRP)FSRTL_FSP_TOP_LEVEL_IRP);
                    }

                    DPRINT("MmCreateSection: continue\n");
                    continue;
                }
                else
                {
                    if (ControlArea->u.Flags.ImageMappedInSystemSpace &&
                        (AllocationAttributes & SEC_IMAGE) &&
                        KeGetCurrentThread()->PreviousMode != KernelMode)
                    {
                        MiUnlockPfnDb(OldIrql, APC_LEVEL);

                        /* Check if we locked and set the IRP */
                        if (FileLock)
                        {
                            /* Reset the top-level IRP and release the lock */
                            IoSetTopLevelIrp(NULL);
                            //FsRtlReleaseFile(File);
                        }

                        DPRINT1("MmCreateSection: STATUS_CONFLICTING_ADDRESSES\n");
                        ExFreePoolWithTag(NewControlArea, 'aCmM');
                        ObDereferenceObject(File);
                        return STATUS_CONFLICTING_ADDRESSES;
                    }

                    NewSegment = ControlArea->Segment;

                    ControlArea->u.Flags.Accessed = 1;
                    ControlArea->NumberOfSectionReferences++;

                    if (ControlArea->DereferenceList.Flink)
                    {
                        RemoveEntryList(&ControlArea->DereferenceList);

                        ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
                        ASSERT(MmPfnOwner == KeGetCurrentThread());
                        MmUnusedSegmentCount--;

                        ControlArea->DereferenceList.Flink = NULL;
                        ControlArea->DereferenceList.Blink = NULL;
                    }

                    UserRefIncremented = TRUE;

                    if (!IgnoreFileSizing)
                    {
                        ControlArea->NumberOfUserReferences++;
                    }

                    DPRINT("MmCreateSection: break\n");
                    break;
                }
            }
        }

        /* We can release the PFN lock now */
        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        if ((AllocationAttributes & SEC_IMAGE) && File && (File->FileName.Length > 4))
        {
            DPRINT("MmCreateSection: File %p '%wZ' \n", File, &File->FileName);
        }

        if (!NewSegment)
        {
            if (AllocationAttributes & SEC_IMAGE)
            {
                /* Create image-file backed sections */
                DPRINT1("MmCreateSection: FIXME MiInsertImageSectionObject \n");
                ASSERT(FALSE);
                Status = 0;//MiCreateImageFileMap(File, &Segment);
            }
            else
            {
                /* So create a data file map */
                Status = MiCreateDataFileMap(File,
                                             &Segment,
                                             (PSIZE_T)InputMaximumSize,
                                             SectionPageProtection,
                                             AllocationAttributes,
                                             IgnoreFileSizing);
                /*We expect this */
                ASSERT(PreviousSectionPointer == File->SectionObjectPointer);
            }

            if (!NT_SUCCESS(Status))
            {
                /* Lock the PFN database while we undo */
                OldIrql = MiLockPfnDb(APC_LEVEL);

                /* Reset the waiting-for-deletion event */
                event = ControlArea->WaitingForDeletion;
                ControlArea->WaitingForDeletion = NULL;

                /* Set the file pointer NULL flag */
                ASSERT(ControlArea->u.Flags.FilePointerNull == 0);
                ControlArea->u.Flags.FilePointerNull = 1;

                /* Delete the section object */
                if (AllocationAttributes & SEC_IMAGE)
                {
                    DPRINT1("MmCreateSection: FIXME MiRemoveImageSectionObject \n");
                    ASSERT(FALSE);
                    //MiRemoveImageSectionObject(File, (PLARGE_CONTROL_AREA)ControlArea);
                }
                else
                {
                    File->SectionObjectPointer->DataSectionObject = NULL;
                }

                /* No longer being created */
                ControlArea->u.Flags.BeingCreated = 0;

                /* We can release the PFN lock now */
                MiUnlockPfnDb(OldIrql, APC_LEVEL);

                /* Check if we locked and set the IRP */
                if (FileLock)
                {
                    /* Reset the top-level IRP and release the lock */
                    IoSetTopLevelIrp(NULL);
                    //FsRtlReleaseFile(File);
                }

                /* Free the control area and de-ref the file object */
                ExFreePoolWithTag(NewControlArea, 'aCmM');
                ObDereferenceObject(File);

                if (event)
                {
                    KeSetEvent(&event->Event, 0, FALSE);
                }

                /* All done */
                DPRINT1("MmCreateSection: Status %X\n", Status);
                return Status;
            }

            /* Check if a maximum size was specified */
            if (!InputMaximumSize->QuadPart)
            {
                /* Nope, use the segment size */
                Section.SizeOfSection.QuadPart = (LONGLONG)Segment->SizeOfSegment;
                DPRINT("MmCreateSection: Section.SizeOfSection.QuadPart %I64X\n", Section.SizeOfSection.QuadPart);
            }
            else
            {
                /* Yep, use the entered size */
                Section.SizeOfSection.QuadPart = InputMaximumSize->QuadPart;
                DPRINT("MmCreateSection: Section.SizeOfSection.QuadPart %I64X\n", Section.SizeOfSection.QuadPart);
            }
        }
        else
        {
            /* This is a previously mapped file. */
            if (AllocationAttributes & SEC_IMAGE)
            {
                DPRINT1("MmCreateSection: FIXME MiFlushDataSection \n");
                //MiFlushDataSection(File);
            }

            /* Free the new control area */
            ExFreePoolWithTag(NewControlArea, 'aCmM');

            if (IgnoreFileSizing || ControlArea->u.Flags.Image)
            {
                /* If it CC or image-file section get size from Segment */
                FileSize.QuadPart = NewSegment->SizeOfSegment;
            }
            else
            {
                /* For data-file section get size from file */
                Status = FsRtlGetFileSize(File, &FileSize);

                if (!NT_SUCCESS(Status))
                {
                    DPRINT1("MmCreateSection: Status %X\n", Status);

                    /* Check if we locked and set the IRP */
                    if (FileLock)
                    {
                        /* Reset the top-level IRP and release the lock */
                        IoSetTopLevelIrp(NULL);
                        //FsRtlReleaseFile(File);
                        FileLock = FALSE;
                    }

                    /* De-ref the file object */
                    ObDereferenceObject(File);
                    goto ErrorExit;
                }

                if (!FileSize.QuadPart && !InputMaximumSize->QuadPart)
                {
                    DPRINT1("MmCreateSection: STATUS_MAPPED_FILE_SIZE_ZERO\n");

                    /* Check if we locked and set the IRP */
                    if (FileLock)
                    {
                        /* Reset the top-level IRP and release the lock */
                        IoSetTopLevelIrp(NULL);
                        //FsRtlReleaseFile(File);
                        FileLock = FALSE;
                    }

                    ObDereferenceObject(File);
                    Status = STATUS_MAPPED_FILE_SIZE_ZERO;
                    goto ErrorExit;
                }
            }

            /* Check if we locked and set the IRP */
            if (FileLock)
            {
                /* Reset the top-level IRP and release the lock */
                IoSetTopLevelIrp(NULL);
                //FsRtlReleaseFile( File);
                FileLock = FALSE;
            }

            /* De-ref the file object */
            ObDereferenceObject(File);

            /* Set sizeof for the section */
            if (InputMaximumSize->QuadPart == 0)
            {
                Section.SizeOfSection.QuadPart = FileSize.QuadPart;
                DPRINT("MmCreateSection: Section.SizeOfSection.QuadPart %I64X\n", Section.SizeOfSection.QuadPart);
                IsSectionSizeChanged = TRUE;
            }
            else
            {
                Section.SizeOfSection.QuadPart = InputMaximumSize->QuadPart;
                DPRINT("MmCreateSection: Section.SizeOfSection.QuadPart %I64X\n", Section.SizeOfSection.QuadPart);

                if (FileSize.QuadPart < InputMaximumSize->QuadPart)
                {
                    if (!(SectionPageProtection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
                    {
                        Status = STATUS_SECTION_TOO_BIG;
                        goto ErrorExit;
                    }
                }
                else
                {
                    IsSectionSizeChanged = TRUE;
                }
            }
        }
    }
    else
    {
        /* If FileHandle and FileObject are null, then this is a pagefile-backed section. */
        if (AllocationAttributes & SEC_IMAGE)
        {
            /* A handle must be supplied with SEC_IMAGE, as this is the no-handle path */
            DPRINT1("MmCreateSection: STATUS_INVALID_FILE_FOR_SECTION\n");
            return STATUS_INVALID_FILE_FOR_SECTION;
        }

        /* Not yet supported */
        ASSERT((AllocationAttributes & SEC_LARGE_PAGES) == 0);
        if (AllocationAttributes & SEC_LARGE_PAGES)
        {
            if (!(AllocationAttributes & SEC_COMMIT))
            {
                DPRINT1("MmCreateSection: STATUS_INVALID_PARAMETER_6\n");
                return STATUS_INVALID_PARAMETER_6;
            }

            if (!SeSinglePrivilegeCheck(SeLockMemoryPrivilege, KeGetCurrentThread()->PreviousMode))
            {
                DPRINT1("MmCreateSection: STATUS_PRIVILEGE_NOT_HELD\n");
                return STATUS_PRIVILEGE_NOT_HELD;
            }
        }

        /* So this must be a pagefile-backed section, create the mappings needed */
        Status = MiCreatePagingFileMap(&NewSegment,
                                       (PULONGLONG)InputMaximumSize,
                                       ProtectionMask,
                                       AllocationAttributes);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("MmCreateSection: Status %X\n", Status);
            return Status;
        }

        /* Set the size here, and read the control area */
        Section.SizeOfSection.QuadPart = NewSegment->SizeOfSegment;
        DPRINT("MmCreateSection: Section.SizeOfSection.QuadPart %I64X\n", Section.SizeOfSection.QuadPart);

        ControlArea = NewSegment->ControlArea;

        /* MiCreatePagingFileMap increments user references */
        UserRefIncremented = TRUE;
    }

    DPRINT("MmCreateSection: NewSegment %p\n", NewSegment);

    /* Did we already have a segment? */
    if (!NewSegment)
    {
        /* This must be the file path and we created a segment */
        NewSegment = Segment;
        ASSERT(File != NULL);

        /* Acquire the PFN lock while we set control area */
        OldIrql = MiLockPfnDb(APC_LEVEL);

        /* Reset the waiting-for-deletion event */
        event = ControlArea->WaitingForDeletion;
        ControlArea->WaitingForDeletion = NULL;

        if (AllocationAttributes & SEC_IMAGE)
        {
            /* Image-file backed section*/
            DPRINT1("MmCreateSection: FIXME MiRemoveImageSectionObject \n");
            ASSERT(FALSE);
            DPRINT1("MmCreateSection: FIXME MiInsertImageSectionObject \n");
            ASSERT(FALSE);
            ControlArea = NewSegment->ControlArea;
        }
        else if (NewSegment->ControlArea->u.Flags.Rom)
        {
            /* ROM image sections */
            ASSERT(File->SectionObjectPointer->DataSectionObject == NewControlArea);
            File->SectionObjectPointer->DataSectionObject = NewSegment->ControlArea;
            ControlArea = NewSegment->ControlArea;
        }

        /* Take off the being created flag, and then release the lock */
        ControlArea->u.Flags.BeingCreated = 0;
        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        if ((AllocationAttributes & SEC_IMAGE) ||
            NewSegment->ControlArea->u.Flags.Rom == 1)
        {
            /* Free the new control area */
            ExFreePoolWithTag(NewControlArea, 'aCmM');
        }

        if (event)
        {
            KeSetEvent(&event->Event, 0, FALSE);
        }
    }

    /* Check if we locked the file earlier */
    if (FileLock)
    {
        /* Reset the top-level IRP and release the lock */
        IoSetTopLevelIrp(NULL);
        //FsRtlReleaseFile(File);
        FileLock = FALSE;
    }

    /* Set the initial section object data */
    Section.InitialPageProtection = SectionPageProtection;

    /* The mapping created a control area and segment, save the flags */
    Section.Segment = NewSegment;
    Section.u.LongFlags = ControlArea->u.LongFlags;

    /* Check if this is a user-mode read-write non-image file mapping */
    if (!(FileObject) &&
        (SectionPageProtection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
        !(ControlArea->u.Flags.Image) &&
        (ControlArea->FilePointer))
    {
        /* Add a reference and set the flag */
        Section.u.Flags.UserWritable = 1;
        InterlockedIncrement((volatile PLONG)&ControlArea->WritableUserReferences);
    }

    /* Check for image mappings or page file mappings */
    if ((ControlArea->u.Flags.Image) || !(ControlArea->FilePointer))
    {
        /* Charge the segment size, and allocate a subsection */
        PagedCharge = sizeof(SECTION) + NewSegment->TotalNumberOfPtes * sizeof(MMPTE);
        SubsectionSize = sizeof(SUBSECTION);
    }
    else
    {
        /* Charge nothing, and allocate a mapped subsection */
        PagedCharge = 0;
        SubsectionSize = sizeof(MSUBSECTION);
    }

    /* Check type and charge a CA and the get subsection pointer */
    if (ControlArea->u.Flags.GlobalOnlyPerSession || ControlArea->u.Flags.Rom)
    {
        NonPagedCharge = sizeof(LARGE_CONTROL_AREA);
        Subsection = (PSUBSECTION)((PLARGE_CONTROL_AREA)ControlArea + 1);
    }
    else
    {
        NonPagedCharge = sizeof(CONTROL_AREA);
        Subsection = (PSUBSECTION)(ControlArea + 1);
    }

    do
    {
        NonPagedCharge += SubsectionSize;
        Subsection = Subsection->NextSubsection;
    }
    while (Subsection);

    /* Create the actual section object, with enough space for the prototypes */
    Status = ObCreateObject(PreviousMode,
                            MmSectionObjectType,
                            ObjectAttributes,
                            PreviousMode,
                            NULL,
                            sizeof(SECTION),
                            PagedCharge,
                            NonPagedCharge,
                            (PVOID*)&NewSection);
    DPRINT("MmCreateSection: Status %X\n", Status);
    if (!NT_SUCCESS(Status))
    {
        /* Check if this is a user-mode read-write non-image file mapping */
        if (!(FileObject) &&
            (SectionPageProtection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
            !(ControlArea->u.Flags.Image) &&
            (ControlArea->FilePointer))
        {
            /* Remove a reference and check the flag */
            ASSERT(Section.u.Flags.UserWritable == 1);
            InterlockedDecrement((volatile PLONG)&ControlArea->WritableUserReferences);
        }

ErrorExit:

        /* Check if we locked and set the IRP */
        if (FileLock)
        {
            /* Reset the top-level IRP and release the lock */
            IoSetTopLevelIrp(NULL);
            //FsRtlReleaseFile(File);
        }

        /* Check if a user reference was added */
        if (UserRefIncremented)
        {
            /* Acquire the PFN lock while we change counters */
            OldIrql = MiLockPfnDb(APC_LEVEL);

            /* Decrement the accounting counters */
            ControlArea->NumberOfSectionReferences--;

            if (!IgnoreFileSizing)
            {
                ASSERT((LONG)ControlArea->NumberOfUserReferences > 0);
                ControlArea->NumberOfUserReferences--;
            }

            /* Check if we should destroy the CA and release the lock */
            MiCheckControlArea(ControlArea, OldIrql);
        }

        /* Return the failure code */
        DPRINT1("MmCreateSection: Status %X\n", Status);
        return Status;
    }

    /* NOTE: Past this point, all failures will be handled by Ob upon ref->0 */

    /* Now copy the local section object from the stack into this new object */
    RtlCopyMemory(NewSection, &Section, sizeof(SECTION));
    NewSection->Address.StartingVpn = 0;

    if (!IgnoreFileSizing)
    {
        /* Not CC call */
        NewSection->u.Flags.UserReference = 1;

        if (AllocationAttributes & SEC_NO_CHANGE)
        {
            NewSection->u.Flags.NoChange = 1;
        }

        if (!(SectionPageProtection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
        {
            NewSection->u.Flags.CopyOnWrite = 1;
        }

        /* Is this a "based" allocation, in which all mappings are identical? */
        if (AllocationAttributes & SEC_BASED)
        {
            NTSTATUS status;

            NewSection->u.Flags.Based = 1;

            if ((ULONGLONG)NewSection->SizeOfSection.QuadPart > (ULONG_PTR)MmHighSectionBase)
            {
                DPRINT1("MmCreateSection: return STATUS_NO_MEMORY\n");
                ObDereferenceObject(NewSection);
                return STATUS_NO_MEMORY;
            }

            /* Lock the VAD tree during the search */
            KeAcquireGuardedMutex(&MmSectionBasedMutex);

            /* Then we must find a global address, top-down */
            status = MiFindEmptyAddressRangeDownBasedTree(NewSection->SizeOfSection.LowPart,
                                                          (ULONG_PTR)MmHighSectionBase,
                                                          _64K,
                                                          &MmSectionBasedRoot,
                                                          &NewSection->Address.StartingVpn);
            if (!NT_SUCCESS(status))
            {
                /* No way to find a valid range. */
                DPRINT1("MmCreateSection: status %X\n", status);
                KeReleaseGuardedMutex(&MmSectionBasedMutex);
                ObDereferenceObject(NewSection);
                return status;
            }

            /* Compute the ending address and insert it into the VAD tree */
            NewSection->Address.EndingVpn = NewSection->Address.StartingVpn +
                                            NewSection->SizeOfSection.LowPart - 1;

            MiInsertBasedSection(NewSection);
            KeReleaseGuardedMutex(&MmSectionBasedMutex);
        }
    }

    /* Write flag if this a CC call */
    ControlArea->u.Flags.WasPurged |= IgnoreFileSizing;

    if ((ControlArea->u.Flags.WasPurged && !IgnoreFileSizing) &&
        (!IsSectionSizeChanged ||
         ((ULONGLONG)NewSection->SizeOfSection.QuadPart > NewSection->Segment->SizeOfSegment)))
    {
        DPRINT1("MmCreateSection: FIXME MmExtendSection \n");
        ASSERT(FALSE);
    }

    /* Return the object and the creation status */
    *SectionObject = NewSection;

    DPRINT("MmCreateSection: NewSection %p NewSegment %p\n", NewSection, NewSegment);
    return Status;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
MmMapViewOfSection(IN PVOID SectionObject,
                   IN PEPROCESS Process,
                   IN OUT PVOID *BaseAddress,
                   IN ULONG_PTR ZeroBits,
                   IN SIZE_T CommitSize,
                   IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
                   IN OUT PSIZE_T ViewSize,
                   IN SECTION_INHERIT InheritDisposition,
                   IN ULONG AllocationType,
                   IN ULONG Protect)
{
    KAPC_STATE ApcState;
    BOOLEAN Attached = FALSE;
    PSECTION Section;
    PCONTROL_AREA ControlArea;
    ULONG ProtectionMask;
    NTSTATUS Status;
    ULONG64 CalculatedViewSize;

    PAGED_CODE();
    DPRINT("MmMapViewOfSection: Section %p, Process %p, ZeroBits %X, CommitSize %X, AllocType %X, Protect %X\n", SectionObject, Process, ZeroBits, CommitSize, AllocationType, Protect);

    /* Get Section */
    Section = (PSECTION)SectionObject;

    if (Section->u.Flags.Image == 0)
    {
        if (!MiIsProtectionCompatible(Section->InitialPageProtection, Protect))
        {
            DPRINT1("MmMapViewOfSection: return STATUS_SECTION_PROTECTION\n");
            return STATUS_SECTION_PROTECTION;
        }
    }


    /* Check if the offset and size would cause an overflow */
    if (((ULONG64)SectionOffset->QuadPart + *ViewSize) < (ULONG64)SectionOffset->QuadPart)
    {
        DPRINT1("MmMapViewOfSection: Section offset overflows\n");
        return STATUS_INVALID_VIEW_SIZE;
    }

    /* Check if the offset and size are bigger than the section itself */
    if (((ULONG64)SectionOffset->QuadPart + *ViewSize) > (ULONG64)Section->SizeOfSection.QuadPart &&
        !(AllocationType & MEM_RESERVE))
    {
        DPRINT1("MmMapViewOfSection: Section offset is larger than section\n");
        return STATUS_INVALID_VIEW_SIZE;
    }

    /* Check if the caller did not specify a view size */
    if (!(*ViewSize))
    {
        /* Compute it for the caller */
        CalculatedViewSize = Section->SizeOfSection.QuadPart - SectionOffset->QuadPart;

        /* Check if it's larger than 4GB or overflows into kernel-mode */
        if (!NT_SUCCESS(RtlULongLongToSIZET(CalculatedViewSize, ViewSize)) ||
            (((ULONG_PTR)MM_HIGHEST_VAD_ADDRESS - (ULONG_PTR)*BaseAddress) < CalculatedViewSize))
        {
            DPRINT1("MmMapViewOfSection: Section view won't fit\n");
            return STATUS_INVALID_VIEW_SIZE;
        }
    }

    /* Check if the commit size is larger than the view size */
    if (CommitSize > *ViewSize && (AllocationType & MEM_RESERVE) == 0)
    {
        DPRINT1("MmMapViewOfSection: Attempting to commit more than the view itself\n");
        return STATUS_INVALID_PARAMETER_5;
    }

    /* Check if the view size is larger than the section */
    if (*ViewSize > (ULONG64)Section->SizeOfSection.QuadPart && !(AllocationType & MEM_RESERVE))
    {
        DPRINT1("MmMapViewOfSection: The view is larger than the section\n");
        return STATUS_INVALID_VIEW_SIZE;
    }

    /* Compute and validate the protection */
    if (AllocationType & MEM_RESERVE &&
        (!(Section->InitialPageProtection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))))
    {
        DPRINT1("MmMapViewOfSection: STATUS_SECTION_PROTECTION\n");
        return STATUS_SECTION_PROTECTION;
    }

    if (Section->u.Flags.NoCache)
    {
        Protect = (Protect & ~PAGE_WRITECOMBINE) | PAGE_NOCACHE;
    }

    if (Section->u.Flags.WriteCombined)
    {
        Protect = (Protect & ~PAGE_NOCACHE) | PAGE_WRITECOMBINE;
    }

    /* Compute and validate the protection mask */
    ProtectionMask = MiMakeProtectionMask(Protect);
    if (ProtectionMask == MM_INVALID_PROTECTION)
    {
        DPRINT1("MmMapViewOfSection: The protection is invalid\n");
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    /* Get the control area */
    ControlArea = Section->Segment->ControlArea;

    /* Start by attaching to the current process if needed */
    if (PsGetCurrentProcess() != Process)
    {
        KeStackAttachProcess(&Process->Pcb, &ApcState);
        Attached = TRUE;
    }

    /* Lock the process address space */
    KeAcquireGuardedMutex(&Process->AddressCreationLock);

    if (Process->VmDeleted)
    {
        DPRINT1("MmMapViewOfSection: STATUS_PROCESS_IS_TERMINATING\n");
        Status = STATUS_PROCESS_IS_TERMINATING;
        goto Exit;
    }

    /* Do the actual mapping */

    if (ControlArea->u.Flags.PhysicalMemory)
    {
        Status = MiMapViewOfPhysicalSection(ControlArea,
                                            Process,
                                            BaseAddress,
                                            SectionOffset,
                                            ViewSize,
                                            ProtectionMask,
                                            ZeroBits,
                                            AllocationType);
        goto Exit;
    }

    if (ControlArea->u.Flags.Image)
    {
        if (AllocationType & MEM_RESERVE)
        {
            DPRINT1("MmMapViewOfSection: STATUS_INVALID_PARAMETER_9\n");
            Status = STATUS_INVALID_PARAMETER_9;
            goto Exit;
        }

        if (Protect & PAGE_WRITECOMBINE)
        {
            DPRINT1("MmMapViewOfSection: STATUS_INVALID_PARAMETER_10\n");
            Status = STATUS_INVALID_PARAMETER_10;
            goto Exit;
        }

        Status = MiMapViewOfImageSection(ControlArea,
                                         Process,
                                         BaseAddress,
                                         SectionOffset,
                                         ViewSize,
                                         Section,
                                         InheritDisposition,
                                         ZeroBits,
                                         AllocationType,
                                         Section->Segment->u1.ImageCommitment);
        goto Exit;
    }

    if (Protect & PAGE_WRITECOMBINE)
    {
        DPRINT1("MmMapViewOfSection: STATUS_INVALID_PARAMETER_10\n");
        Status = STATUS_INVALID_PARAMETER_10;
        goto Exit;
    }

    Status = MiMapViewOfDataSection(ControlArea,
                                    Process,
                                    BaseAddress,
                                    SectionOffset,
                                    ViewSize,
                                    Section,
                                    InheritDisposition,
                                    ProtectionMask,
                                    CommitSize,
                                    ZeroBits,
                                    AllocationType);
Exit:

    /* Detach if needed, then return status */
    if (Attached)
    {
        KeUnstackDetachProcess(&ApcState);
    }

    /* Release the address space lock */
    KeReleaseGuardedMutex(&Process->AddressCreationLock);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MmMapViewOfSection: Status %X\n", Status);
    }

    return Status;
}

/*
 * @unimplemented
 */
BOOLEAN
NTAPI
MmDisableModifiedWriteOfSection(IN PSECTION_OBJECT_POINTERS SectionObjectPointer)
{
   UNIMPLEMENTED;
   return FALSE;
}

/*
 * @unimplemented
 */
BOOLEAN
NTAPI
MmForceSectionClosed(IN PSECTION_OBJECT_POINTERS SectionObjectPointer,
                     IN BOOLEAN DelayClose)
{
   UNIMPLEMENTED;
   return FALSE;
}

NTSTATUS
NTAPI
MmMapViewInSystemSpace(IN PVOID Section,
                       OUT PVOID * MappedBase,
                       OUT PSIZE_T ViewSize)
{
    PAGED_CODE();
    DPRINT("MmMapViewInSystemSpace: Section %p, MappedBase %p, ViewSize %I64X\n", Section, (MappedBase?*MappedBase:0), (ViewSize?(ULONGLONG)(*ViewSize):0ull));
    return MiMapViewInSystemSpace((PSECTION)Section, &MmSession, MappedBase, ViewSize);
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
MmMapViewInSessionSpace(IN PVOID Section,
                        OUT PVOID *MappedBase,
                        IN OUT PSIZE_T ViewSize)
{
    PAGED_CODE();

    ASSERT(FALSE);

    // HACK
    if (MiIsRosSectionObject(Section))
    {
        return MmMapViewInSystemSpace(Section, MappedBase, ViewSize);
    }

    /* Process must be in a session */
    if (PsGetCurrentProcess()->ProcessInSession == FALSE)
    {
        DPRINT1("Process is not in session\n");
        return STATUS_NOT_MAPPED_VIEW;
    }

    /* Use the system space API, but with the session view instead */
    ASSERT(MmIsAddressValid(MmSessionSpace) == TRUE);
    return MiMapViewInSystemSpace(Section,
                                  &MmSessionSpace->Session,
                                  MappedBase,
                                  ViewSize);
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
MmUnmapViewInSessionSpace(IN PVOID MappedBase)
{
    PAGED_CODE();

    ASSERT(FALSE);

    // HACK
    if (!MI_IS_SESSION_ADDRESS(MappedBase))
    {
        return MmUnmapViewInSystemSpace(MappedBase);
    }

    /* Process must be in a session */
    if (PsGetCurrentProcess()->ProcessInSession == FALSE)
    {
        DPRINT1("Proess is not in session\n");
        return STATUS_NOT_MAPPED_VIEW;
    }

    /* Use the system space API, but with the session view instead */
    ASSERT(MmIsAddressValid(MmSessionSpace) == TRUE);
    return MiUnmapViewInSystemSpace(&MmSessionSpace->Session,
                                    MappedBase);
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
MmUnmapViewOfSection(IN PEPROCESS Process,
                     IN PVOID BaseAddress)
{
    ASSERT(FALSE);
    return MiUnmapViewOfSection(Process, BaseAddress, 0);
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
MmUnmapViewInSystemSpace(IN PVOID MappedBase)
{
    PMEMORY_AREA MemoryArea;
    PAGED_CODE();

    ASSERT(FALSE);

    /* Was this mapped by RosMm? */
    MemoryArea = MmLocateMemoryAreaByAddress(MmGetKernelAddressSpace(), MappedBase);
    if ((MemoryArea) && (MemoryArea->Type != MEMORY_AREA_OWNED_BY_ARM3))
    {
        return MiRosUnmapViewInSystemSpace(MappedBase);
    }

    /* It was not, call the ARM3 routine */
    return MiUnmapViewInSystemSpace(&MmSession, MappedBase);
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
MmCommitSessionMappedView(IN PVOID MappedBase,
                          IN SIZE_T ViewSize)
{
    ULONG_PTR StartAddress, EndingAddress, Base;
    ULONG Hash, Count = 0, Size, QuotaCharge;
    PMMSESSION Session;
    PMMPTE LastProtoPte, Pte, ProtoPte;
    PCONTROL_AREA ControlArea;
    PSEGMENT Segment;
    PSUBSECTION Subsection;
    MMPTE TempPte;
    PAGED_CODE();

    ASSERT(FALSE);

    /* Make sure the base isn't past the session view range */
    if ((MappedBase < MiSessionViewStart) ||
        (MappedBase >= (PVOID)((ULONG_PTR)MiSessionViewStart + MmSessionViewSize)))
    {
        DPRINT1("Base outside of valid range\n");
        return STATUS_INVALID_PARAMETER_1;
    }

    /* Make sure the size isn't past the session view range */
    if (((ULONG_PTR)MiSessionViewStart + MmSessionViewSize -
        (ULONG_PTR)MappedBase) < ViewSize)
    {
        DPRINT1("Size outside of valid range\n");
        return STATUS_INVALID_PARAMETER_2;
    }

    /* Sanity check */
    ASSERT(ViewSize != 0);

    /* Process must be in a session */
    if (PsGetCurrentProcess()->ProcessInSession == FALSE)
    {
        DPRINT1("Process is not in session\n");
        return STATUS_NOT_MAPPED_VIEW;
    }

    /* Compute the correctly aligned base and end addresses */
    StartAddress = (ULONG_PTR)PAGE_ALIGN(MappedBase);
    EndingAddress = ((ULONG_PTR)MappedBase + ViewSize - 1) | (PAGE_SIZE - 1);

    /* Sanity check and grab the session */
    ASSERT(MmIsAddressValid(MmSessionSpace) == TRUE);
    Session = &MmSessionSpace->Session;

    /* Get the hash entry for this allocation */
    Hash = (StartAddress >> 16) % Session->SystemSpaceHashKey;

    /* Lock system space */
    KeAcquireGuardedMutex(Session->SystemSpaceViewLockPointer);

    /* Loop twice so we can try rolling over if needed */
    while (TRUE)
    {
        /* Extract the size and base addresses from the entry */
        Base = Session->SystemSpaceViewTable[Hash].Entry & ~0xFFFF;
        Size = Session->SystemSpaceViewTable[Hash].Entry & 0xFFFF;

        /* Convert the size to bucket chunks */
        Size *= MI_SYSTEM_VIEW_BUCKET_SIZE;

        /* Bail out if this entry fits in here */
        if ((StartAddress >= Base) && (EndingAddress < (Base + Size))) break;

        /* Check if we overflew past the end of the hash table */
        if (++Hash >= Session->SystemSpaceHashSize)
        {
            /* Reset the hash to zero and keep searching from the bottom */
            Hash = 0;
            if (++Count == 2)
            {
                /* But if we overflew twice, then this is not a real mapping */
                KeBugCheckEx(DRIVER_UNMAPPING_INVALID_VIEW,
                             Base,
                             2,
                             0,
                             0);
            }
        }
    }

    /* Make sure the view being mapped is not file-based */
    ControlArea = Session->SystemSpaceViewTable[Hash].ControlArea;
    if (ControlArea->FilePointer != NULL)
    {
        /* It is, so we have to bail out */
        DPRINT1("Only page-filed backed sections can be commited\n");
        KeReleaseGuardedMutex(Session->SystemSpaceViewLockPointer);
        return STATUS_ALREADY_COMMITTED;
    }

    /* Get the subsection. We don't support LARGE_CONTROL_AREA in ARM3 */
    ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);
    ASSERT(ControlArea->u.Flags.Rom == 0);
    Subsection = (PSUBSECTION)(ControlArea + 1);

    /* Get the start and end PTEs -- make sure the end PTE isn't past the end */
    ProtoPte = Subsection->SubsectionBase + ((StartAddress - Base) >> PAGE_SHIFT);
    QuotaCharge = MiAddressToPte(EndingAddress) - MiAddressToPte(StartAddress) + 1;
    LastProtoPte = ProtoPte + QuotaCharge;
    if (LastProtoPte >= Subsection->SubsectionBase + Subsection->PtesInSubsection)
    {
        DPRINT1("PTE is out of bounds\n");
        KeReleaseGuardedMutex(Session->SystemSpaceViewLockPointer);
        return STATUS_INVALID_PARAMETER_2;
    }

    /* Acquire the commit lock and count all the non-committed PTEs */
    KeAcquireGuardedMutexUnsafe(&MmSectionCommitMutex);
    Pte = ProtoPte;
    while (Pte < LastProtoPte)
    {
        if (Pte->u.Long) QuotaCharge--;
        Pte++;
    }

    /* Was everything committed already? */
    if (!QuotaCharge)
    {
        /* Nothing to do! */
        KeReleaseGuardedMutexUnsafe(&MmSectionCommitMutex);
        KeReleaseGuardedMutex(Session->SystemSpaceViewLockPointer);
        return STATUS_SUCCESS;
    }

    /* Pick the segment and template PTE */
    Segment = ControlArea->Segment;
    TempPte = Segment->SegmentPteTemplate;
    ASSERT(TempPte.u.Long != 0);

    /* Loop all prototype PTEs to be committed */
    Pte = ProtoPte;
    while (Pte < LastProtoPte)
    {
        /* Make sure the PTE is already invalid */
        if (Pte->u.Long == 0)
        {
            /* And write the invalid PTE */
            MI_WRITE_INVALID_PTE(Pte, TempPte);
        }

        /* Move to the next PTE */
        Pte++;
    }

    /* Check if we had at least one page charged */
    if (QuotaCharge)
    {
        /* Update the accounting data */
        Segment->NumberOfCommittedPages += QuotaCharge;
        InterlockedExchangeAddSizeT(&MmSharedCommit, QuotaCharge);
    }

    /* Release all */
    KeReleaseGuardedMutexUnsafe(&MmSectionCommitMutex);
    KeReleaseGuardedMutex(Session->SystemSpaceViewLockPointer);
    return STATUS_SUCCESS;
}

VOID
NTAPI
MiDeleteARM3Section(PVOID ObjectBody)
{
    PSECTION SectionObject;
    PCONTROL_AREA ControlArea;
    KIRQL OldIrql;

    ASSERT(FALSE);

    SectionObject = (PSECTION)ObjectBody;

    if (SectionObject->u.Flags.Based == 1)
    {
        /* Remove the node from the global section address tree */
        KeAcquireGuardedMutex(&MmSectionBasedMutex);
        MiRemoveNode(&SectionObject->Address, &MmSectionBasedRoot);
        KeReleaseGuardedMutex(&MmSectionBasedMutex);
    }

    /* Lock the PFN database */
    OldIrql = MiAcquirePfnLock();

    ASSERT(SectionObject->Segment);
    ASSERT(SectionObject->Segment->ControlArea);

    ControlArea = SectionObject->Segment->ControlArea;

    /* Dereference */
    ControlArea->NumberOfSectionReferences--;
    ControlArea->NumberOfUserReferences--;

    ASSERT(ControlArea->u.Flags.BeingDeleted == 0);

    /* Check it. It will delete it if there is no more reference to it */
    MiCheckControlArea(ControlArea, OldIrql);
}

ULONG
NTAPI
MmDoesFileHaveUserWritableReferences(IN PSECTION_OBJECT_POINTERS SectionPointer)
{
    UNIMPLEMENTED;
    return 0;
}

BOOLEAN
NTAPI
MiReferenceSubsection(PMSUBSECTION MappedSubsection)
{
    DPRINT("MiReferenceSubsection: MappedSubsection %p, %p\n", MappedSubsection, MappedSubsection->SubsectionBase);

    ASSERT((MappedSubsection->ControlArea->u.Flags.Image == 0) &&
           (MappedSubsection->ControlArea->FilePointer != NULL) &&
           (MappedSubsection->ControlArea->u.Flags.PhysicalMemory == 0));

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(MmPfnOwner == KeGetCurrentThread());

    if (!MappedSubsection->SubsectionBase)
    {
        return FALSE;
    }

    MappedSubsection->NumberOfMappedViews++;

    if (!MappedSubsection->DereferenceList.Flink)
    {
        goto Exit;
    }

    RemoveEntryList(&MappedSubsection->DereferenceList);
    AlloccatePoolForSubsectionPtes(MappedSubsection->PtesInSubsection + MappedSubsection->UnusedPtes);

    MappedSubsection->DereferenceList.Flink = NULL;

Exit:

    MappedSubsection->u2.SubsectionFlags2.SubsectionAccessed = 1;
    return TRUE;
}

BOOLEAN
NTAPI
MiCheckProtoPtePageState(PMMPTE SectionProto,
                         KIRQL OldIrql,
                         BOOLEAN * OutIsLock)
{
    PMMPTE ProtoPte;
    MMPTE TempPte;
    PMMPFN Pfn;

    DPRINT("MiCheckProtoPtePageState: SectionProto %p, OldIrql %X\n", SectionProto, OldIrql);

    *OutIsLock = FALSE;

    ProtoPte = MiAddressToPte(SectionProto);

    if (!ProtoPte->u.Hard.Valid)
    {
        MiCheckPdeForPagedPool(SectionProto);
    }

    TempPte.u.Long = ProtoPte->u.Long;

    if (TempPte.u.Hard.Valid)
    {
        Pfn = MI_PFN_ELEMENT(TempPte.u.Hard.PageFrameNumber);

        if (Pfn->u2.ShareCount == 1)
        {
            return FALSE;
        }

        return TRUE;
    }

    if (!TempPte.u.Soft.Prototype &&
        TempPte.u.Soft.Transition)
    {
        return FALSE;
    }

    Pfn = MI_PFN_ELEMENT(TempPte.u.Trans.PageFrameNumber);

    if (Pfn->u3.e1.PageLocation < ActiveAndValid)
    {
        return FALSE;
    }

    if (OldIrql != MM_NOIRQL)
    {
        MiMakeSystemAddressValidPfn(SectionProto, OldIrql);
        *OutIsLock = TRUE;
    }

    return TRUE;
}

BOOLEAN
NTAPI
MmPurgeSection(IN PSECTION_OBJECT_POINTERS SectionObjectPointer,
               IN PLARGE_INTEGER FileOffset,
               IN SIZE_T Length,
               IN BOOLEAN IsFullPurge)
{
    LARGE_INTEGER offset;
    PLARGE_INTEGER fileOffset;
    PCONTROL_AREA ControlArea;
    PSUBSECTION Subsection;
    PSUBSECTION FirstSubsection;
    PSUBSECTION LastSubsection;
    PSUBSECTION TempSubsection;
    PSUBSECTION LastTempSubsection;
    PMSUBSECTION MappedSubsection;
    PMMPTE SectionProto;
    PMMPTE LastProto;
    PMMPTE FinishProto;
    PMMPTE ProtoPte;
    MMPTE TempProto;
    ULONG LastPteOffset;
    ULONGLONG PteOffset;
    PMMPFN ProtoPfn;
    PMMPFN Pfn;
    PFN_NUMBER PageTableFrameIndex;
    KIRQL OldIrql;
    BOOLEAN IsLock;
    BOOLEAN Result;

    DPRINT("MmPurgeSection: SectionPointers %p, FileOffset %I64X, Length %X, IsFullPurge %X\n", SectionObjectPointer, (FileOffset?FileOffset->QuadPart:0), Length, IsFullPurge);

    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    if (FileOffset)
    {
        offset = *FileOffset;
        fileOffset = &offset;
    }
    else
    {
        fileOffset = NULL;
    }

    if (!MiCanFileBeTruncatedInternal(SectionObjectPointer, fileOffset, TRUE, &OldIrql))
    {
        DPRINT("MmPurgeSection: return FALSE\n");
        return FALSE;
    }

    ControlArea = SectionObjectPointer->DataSectionObject;

    if (!ControlArea || ControlArea->u.Flags.Rom)
    {
          MiUnlockPfnDb(OldIrql, APC_LEVEL);
          DPRINT("MmPurgeSection: return TRUE\n");
          return TRUE;
    }

    if (!IsFullPurge && ControlArea->NumberOfSystemCacheViews)
    {
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        DPRINT("MmPurgeSection: return FALSE\n");
        return FALSE;
    }

    ASSERT(ControlArea->u.Flags.BeingDeleted == 0);
    ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);

    Subsection = (PSUBSECTION)&ControlArea[1];

    if (fileOffset)
    {
        for (PteOffset = fileOffset->QuadPart / PAGE_SIZE;
             PteOffset >= Subsection->PtesInSubsection;
             PteOffset -= Subsection->PtesInSubsection)
        {
            Subsection = Subsection->NextSubsection;

            if (!Subsection)
            {
                MiUnlockPfnDb(OldIrql, APC_LEVEL);
                DPRINT("MmPurgeSection: return TRUE\n");
                return TRUE;
            }
        }

        ASSERT(PteOffset < (ULONGLONG)Subsection->PtesInSubsection);
    }
    else
    {
        PteOffset = 0;
    }

    if (fileOffset && Length)
    {
        LastPteOffset = PteOffset + (((Length + BYTE_OFFSET(fileOffset->LowPart)) - 1) / PAGE_SIZE);

        for (LastSubsection = Subsection;
             (ULONGLONG)LastSubsection->PtesInSubsection <= LastPteOffset;
             LastSubsection = LastSubsection->NextSubsection)
        {
            if (!LastSubsection->NextSubsection)
            {
                LastPteOffset = LastSubsection->PtesInSubsection - 1;
                break;
            }
        }

        ASSERT(LastPteOffset < (ULONGLONG)LastSubsection->PtesInSubsection);
    }
    else
    {
        LastSubsection = Subsection;

        if (MiIsAddressValid(ControlArea->Segment))
        {
            PMAPPED_FILE_SEGMENT Segment;

            Segment = (PMAPPED_FILE_SEGMENT)ControlArea->Segment;

            if (Segment->LastSubsectionHint)
            {
                LastSubsection = (PSUBSECTION)Segment->LastSubsectionHint;
            }
        }

        while (LastSubsection->NextSubsection)
        {
            LastSubsection = LastSubsection->NextSubsection;
        }

        LastPteOffset = LastSubsection->PtesInSubsection - 1;
    }

    if (!MiReferenceSubsection((PMSUBSECTION)Subsection))
    {
        while (TRUE)
        {
            if (Subsection == LastSubsection)
            {
                MiUnlockPfnDb(OldIrql, APC_LEVEL);
                DPRINT("MmPurgeSection: return TRUE\n");
                return TRUE;
            }

            Subsection = Subsection->NextSubsection;

            if (!Subsection)
            {
                MiUnlockPfnDb(OldIrql, APC_LEVEL);
                DPRINT("MmPurgeSection: return TRUE\n");
                return TRUE;
            }

            if (!MiReferenceSubsection((PMSUBSECTION)Subsection))
            {
                continue;
            }

            SectionProto = Subsection->SubsectionBase;
            break;
        }
    }
    else
    {
        SectionProto = &Subsection->SubsectionBase[PteOffset];
    }

    FirstSubsection = Subsection;
    ASSERT(Subsection->SubsectionBase != NULL);

    if (!MiReferenceSubsection((PMSUBSECTION)LastSubsection))
    {
        ASSERT(Subsection != LastSubsection);

        ASSERT(FALSE);

        TempSubsection = Subsection->NextSubsection;
        LastTempSubsection = NULL;

        while (TempSubsection != LastSubsection)
        {
            ASSERT(TempSubsection != NULL);

            if ((PMSUBSECTION)TempSubsection->SubsectionBase)
            {
                LastTempSubsection = TempSubsection;
            }

            TempSubsection = TempSubsection->NextSubsection;
        }

        if (LastTempSubsection == NULL)
        {
            ASSERT(Subsection != NULL);
            ASSERT(Subsection->SubsectionBase != NULL);

            TempSubsection = Subsection;
        }
        else
        {
            TempSubsection = LastTempSubsection;
        }

        if (!MiReferenceSubsection((PMSUBSECTION)TempSubsection))
        {
            ASSERT(FALSE);
        }

        ASSERT(TempSubsection->SubsectionBase != NULL);

        LastSubsection = TempSubsection;
        LastPteOffset = LastSubsection->PtesInSubsection - 1;
    }

    FinishProto = &LastSubsection->SubsectionBase[LastPteOffset + 1];

    ControlArea->NumberOfMappedViews++;

    ControlArea->u.Flags.BeingPurged = 1;
    ControlArea->u.Flags.WasPurged = 1;

    Result = TRUE;

    while (TRUE)
    {
        DPRINT("MmPurgeSection: SectionProto %p\n", SectionProto);

        if (OldIrql == MM_NOIRQL)
        {
            OldIrql = MiLockPfnDb(APC_LEVEL);
        }

        if (Subsection == LastSubsection)
        {
            LastProto = FinishProto;
        }
        else
        {
            LastProto = &Subsection->SubsectionBase[Subsection->PtesInSubsection];
        }

        if (!Subsection->SubsectionBase)
        {
            ASSERT(OldIrql != MM_NOIRQL);
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            goto Next;
        }

        MappedSubsection = (PMSUBSECTION)Subsection;
        MappedSubsection->NumberOfMappedViews++;

        if (MappedSubsection->DereferenceList.Flink)
        {
            RemoveEntryList(&MappedSubsection->DereferenceList);
            AlloccatePoolForSubsectionPtes(MappedSubsection->PtesInSubsection + MappedSubsection->UnusedPtes);

            MappedSubsection->DereferenceList.Flink = NULL;
        }

        MappedSubsection->u2.SubsectionFlags2.SubsectionAccessed = 1;

        if (!MiCheckProtoPtePageState(SectionProto, OldIrql, &IsLock))
        {
            SectionProto = (PMMPTE)(((ULONG_PTR)SectionProto | (PAGE_SIZE - 1)) + 1);
        }

        while (SectionProto < LastProto)
        {
            if (MiIsPteOnPdeBoundary(SectionProto) &&
                !MiCheckProtoPtePageState(SectionProto, OldIrql, &IsLock))
            {
                SectionProto += PTE_PER_PAGE;
                continue;
            }

            TempProto.u.Long = SectionProto->u.Long;

            if (TempProto.u.Hard.Valid)
            {
                Result = FALSE;
                break;
            }

            if (!TempProto.u.Soft.Prototype && TempProto.u.Soft.Transition)
            {
                if (OldIrql == MM_NOIRQL)
                {
                    ProtoPte = MiAddressToPte(SectionProto);
                    OldIrql = MiLockPfnDb(APC_LEVEL);

                    if (!ProtoPte->u.Hard.Valid)
                    {
                        MiMakeSystemAddressValidPfn(SectionProto, OldIrql);
                    }

                    continue;
                }

                ProtoPfn = &MmPfnDatabase[TempProto.u.Hard.PageFrameNumber];

                if (!ProtoPfn->OriginalPte.u.Soft.Prototype ||
                    ProtoPfn->OriginalPte.u.Hard.Valid ||
                    ProtoPfn->PteAddress != SectionProto)
                {
                    ASSERT(FALSE);
                }

                if (ProtoPfn->u3.e1.WriteInProgress)
                {
                    ASSERT(FALSE);
                    continue;
                }

                if (ProtoPfn->u3.e1.ReadInProgress)
                {
                    Result = FALSE;
                    break;
                }

                ASSERT(!((ProtoPfn->OriginalPte.u.Soft.Prototype == 0) &&
                       (ProtoPfn->OriginalPte.u.Soft.Transition == 1)));

                MI_WRITE_INVALID_PTE(SectionProto, ProtoPfn->OriginalPte);
                ASSERT(ProtoPfn->OriginalPte.u.Hard.Valid == 0);

                ControlArea->NumberOfPfnReferences--;
                ASSERT((LONG)ControlArea->NumberOfPfnReferences >= 0);

                MiUnlinkPageFromList(ProtoPfn);
                MI_SET_PFN_DELETED(ProtoPfn);

                PageTableFrameIndex = ProtoPfn->u4.PteFrame;
                Pfn = MI_PFN_ELEMENT(PageTableFrameIndex);

                if (Pfn->u2.ShareCount != 1)
                {
                    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
                    ASSERT(MmPfnOwner == KeGetCurrentThread());
                    ASSERT(PageTableFrameIndex > 0);

                    ASSERT(MI_PFN_ELEMENT(PageTableFrameIndex) == Pfn);
                    ASSERT(Pfn->u2.ShareCount != 0);

                    if (Pfn->u3.e1.PageLocation != ActiveAndValid &&
                        Pfn->u3.e1.PageLocation != StandbyPageList)
                    {
                        ASSERT(FALSE);
                    }

                    Pfn->u2.ShareCount--;
                    ASSERT(Pfn->u2.ShareCount < 0xF000000);
                }
                else
                {
                    MiDecrementShareCount(Pfn, PageTableFrameIndex);
                }

                if (!ProtoPfn->u3.e2.ReferenceCount)
                {
                    DPRINT("MmPurgeSection: FIXME MiReleasePageFileSpace \n");
                    MiInsertPageInFreeList(TempProto.u.Trans.PageFrameNumber);
                }
            }

            SectionProto++;

            if (MiIsPteOnPdeBoundary(SectionProto) && OldIrql != MM_NOIRQL)
            {
                MiUnlockPfnDb(OldIrql, APC_LEVEL);
                OldIrql = MM_NOIRQL;
            }
        }

        if (OldIrql == MM_NOIRQL)
        {
            OldIrql = MiLockPfnDb(APC_LEVEL);
        }

        ASSERT(MappedSubsection->DereferenceList.Flink == NULL);
        ASSERT(((LONG_PTR)MappedSubsection->NumberOfMappedViews >= 1) ||
                (MappedSubsection->u.SubsectionFlags.SubsectionStatic == 1));

        MappedSubsection->NumberOfMappedViews--;

        if (!MappedSubsection->NumberOfMappedViews &&
            !MappedSubsection->u.SubsectionFlags.SubsectionStatic)
        {
            InsertTailList(&MmUnusedSubsectionList, &MappedSubsection->DereferenceList);
            FreePoolForSubsectionPtes(MappedSubsection->PtesInSubsection + MappedSubsection->UnusedPtes);
        }

        ASSERT(OldIrql != MM_NOIRQL);
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
Next:
        OldIrql = MM_NOIRQL;

        if (LastSubsection != Subsection && Result)
        {
            Subsection = Subsection->NextSubsection;
            SectionProto = Subsection->SubsectionBase;
            continue;
        }

        break;
    }

    OldIrql = MiLockPfnDb(APC_LEVEL);

    MiDecrementSubsections(FirstSubsection, FirstSubsection);
    MiDecrementSubsections(LastSubsection, LastSubsection);

    ASSERT((LONG)ControlArea->NumberOfMappedViews >= 1);

    ControlArea->NumberOfMappedViews--;
    ControlArea->u.Flags.BeingPurged = 0;

    MiCheckControlArea(ControlArea, OldIrql);

    DPRINT("MmPurgeSection: return %X\n", Result);
    return Result;
}

/* SYSTEM CALLS ***************************************************************/

NTSTATUS
NTAPI
NtAreMappedFilesTheSame(IN PVOID File1MappedAsAnImage,
                        IN PVOID File2MappedAsFile)
{
    PVOID AddressSpace;
    PMMVAD Vad1, Vad2;
    PFILE_OBJECT FileObject1, FileObject2;
    NTSTATUS Status;

    ASSERT(FALSE);

    /* Lock address space */
    AddressSpace = MmGetCurrentAddressSpace();
    MmLockAddressSpace(AddressSpace);

    /* Get the VAD for Address 1 */
    Vad1 = MiLocateAddress(File1MappedAsAnImage);
    if (Vad1 == NULL)
    {
        /* Fail, the address does not exist */
        DPRINT1("No VAD at address 1 %p\n", File1MappedAsAnImage);
        Status = STATUS_INVALID_ADDRESS;
        goto Exit;
    }

    /* Get the VAD for Address 2 */
    Vad2 = MiLocateAddress(File2MappedAsFile);
    if (Vad2 == NULL)
    {
        /* Fail, the address does not exist */
        DPRINT1("No VAD at address 2 %p\n", File2MappedAsFile);
        Status = STATUS_INVALID_ADDRESS;
        goto Exit;
    }

    /* Get the file object pointer for VAD 1 */
    FileObject1 = MiGetFileObjectForVad(Vad1);
    if (FileObject1 == NULL)
    {
        DPRINT1("Failed to get file object for Address 1 %p\n", File1MappedAsAnImage);
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto Exit;
    }

    /* Get the file object pointer for VAD 2 */
    FileObject2 = MiGetFileObjectForVad(Vad2);
    if (FileObject2 == NULL)
    {
        DPRINT1("Failed to get file object for Address 2 %p\n", File2MappedAsFile);
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto Exit;
    }

    /* Make sure Vad1 is an image mapping */
    if (Vad1->u.VadFlags.VadType != VadImageMap)
    {
        DPRINT1("Address 1 (%p) is not an image mapping\n", File1MappedAsAnImage);
        Status = STATUS_NOT_SAME_DEVICE;
        goto Exit;
    }

    /* SectionObjectPointer is equal if the files are equal */
    if (FileObject1->SectionObjectPointer == FileObject2->SectionObjectPointer)
    {
        Status = STATUS_SUCCESS;
    }
    else
    {
        Status = STATUS_NOT_SAME_DEVICE;
    }

Exit:
    /* Unlock address space */
    MmUnlockAddressSpace(AddressSpace);
    return Status;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
NtCreateSection(OUT PHANDLE SectionHandle,
                IN ACCESS_MASK DesiredAccess,
                IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
                IN PLARGE_INTEGER MaximumSize OPTIONAL,
                IN ULONG SectionPageProtection OPTIONAL,
                IN ULONG AllocationAttributes,
                IN HANDLE FileHandle OPTIONAL)
{
    LARGE_INTEGER SafeMaximumSize;
    PSECTION SectionObject;
    HANDLE Handle;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PCONTROL_AREA ControlArea;
    PFILE_OBJECT FileObject;
    ULONG MaximumRetry = 3;
    ULONG ix;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("NtCreateSection: Access %X, ObjAttributes %X, MaximumSize %p [%I64X], Protection %X, AllocAttributes %X, FileHandle %p\n",
           DesiredAccess, ObjectAttributes, MaximumSize, (MaximumSize ? MaximumSize->QuadPart : 0), SectionPageProtection, AllocationAttributes, FileHandle);

    /* Check for non-existing flags */
    if (AllocationAttributes & ~(SEC_COMMIT | SEC_RESERVE | SEC_BASED |
                                 SEC_LARGE_PAGES | SEC_IMAGE | SEC_NOCACHE |
                                 SEC_NO_CHANGE))
    {
        DPRINT1("NtCreateSection: Bogus allocation attribute %X\n", AllocationAttributes);
        return STATUS_INVALID_PARAMETER_6;
    }
    /* Check for no allocation type */
    if (!(AllocationAttributes & (SEC_COMMIT | SEC_RESERVE | SEC_IMAGE)))
    {
        DPRINT1("NtCreateSection: Missing allocation type in allocation attributes\n");
        return STATUS_INVALID_PARAMETER_6;
    }

    /* Check for image allocation with invalid attributes */
    if ((AllocationAttributes & SEC_IMAGE) &&
        (AllocationAttributes & (SEC_COMMIT | SEC_RESERVE | SEC_LARGE_PAGES |
                                 SEC_NOCACHE | SEC_NO_CHANGE)))
    {
        DPRINT1("NtCreateSection: Image allocation with invalid attributes\n");
        return STATUS_INVALID_PARAMETER_6;
    }

    /* Check for allocation type is both commit and reserve */
    if ((AllocationAttributes & SEC_COMMIT) && (AllocationAttributes & SEC_RESERVE))
    {
        DPRINT1("NtCreateSection: Commit and reserve in the same time\n");
        return STATUS_INVALID_PARAMETER_6;
    }

    /* Now check for valid protection */
    if ((SectionPageProtection & PAGE_NOCACHE) ||
        (SectionPageProtection & PAGE_WRITECOMBINE) ||
        (SectionPageProtection & PAGE_GUARD) ||
        (SectionPageProtection & PAGE_NOACCESS))
    {
        DPRINT1("NtCreateSection: Sections don't support these protections\n");
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    /* Use a maximum size of zero, if none was specified */
    if (MaximumSize == NULL)
    {
        SafeMaximumSize.QuadPart = 0;
    }

    /* Check for user-mode caller */
    if (PreviousMode != KernelMode)
    {
        /* Enter SEH */
        _SEH2_TRY
        {
            /* Safely check user-mode parameters */
            if (MaximumSize)
            {
                SafeMaximumSize = ProbeForReadLargeInteger(MaximumSize);
            }

            MaximumSize = &SafeMaximumSize;
            ProbeForWriteHandle(SectionHandle);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        if (MaximumSize)
        {
            SafeMaximumSize.QuadPart = MaximumSize->QuadPart;
        }
    }

    for (ix = 0; ; ix++)
    {
        ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

        /* Try create the section */
        Status = MmCreateSection((PVOID *)&SectionObject,
                                 DesiredAccess,
                                 ObjectAttributes,
                                 &SafeMaximumSize,
                                 SectionPageProtection,
                                 AllocationAttributes,
                                 FileHandle,
                                 NULL);

        ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

        if (NT_SUCCESS(Status))
        {
            break;
        }

        if (Status == STATUS_FILE_LOCK_CONFLICT && ix < MaximumRetry)
        {
            DPRINT1("NtCreateSection: ix %X\n", ix);
            KeDelayExecutionThread(KernelMode, FALSE, &MmHalfSecond);
            continue;
        }

        DPRINT1("NtCreateSection: ix %X, Status %X\n", ix, Status);
        return Status;
    }

    ControlArea = SectionObject->Segment->ControlArea;
    if (ControlArea)
    {
        FileObject = ControlArea->FilePointer;
        if (FileObject)
        {
            DPRINT1("NtCreateSection: FIXME CcZeroEndOfLastPage!\n");
            //CcZeroEndOfLastPage(FileObject);
        }
    }

    /* Now insert the object */
    Status = ObInsertObject(SectionObject,
                            NULL,
                            DesiredAccess,
                            0,
                            NULL,
                            &Handle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtCreateSection: Status %X\n", Status);
        return Status;
    }

    /* Enter SEH */
    _SEH2_TRY
    {
        /* Return the handle safely */
        *SectionHandle = Handle;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* Nothing here */
    }
    _SEH2_END;

    /* Return the status */
    return Status;
}

NTSTATUS
NTAPI
NtOpenSection(OUT PHANDLE SectionHandle,
              IN ACCESS_MASK DesiredAccess,
              IN POBJECT_ATTRIBUTES ObjectAttributes)
{
    HANDLE Handle;
    NTSTATUS Status;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PAGED_CODE();

    DPRINT("NtOpenSection: Access %X, ObjectName '%wZ'\n", DesiredAccess, ObjectAttributes->ObjectName);

    /* Check for user-mode caller */
    if (PreviousMode != KernelMode)
    {
        /* Enter SEH */
        _SEH2_TRY
        {
            /* Safely check user-mode parameters */
            ProbeForWriteHandle(SectionHandle);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Try opening the object */
    Status = ObOpenObjectByName(ObjectAttributes,
                                MmSectionObjectType,
                                PreviousMode,
                                NULL,
                                DesiredAccess,
                                NULL,
                                &Handle);

    /* Enter SEH */
    _SEH2_TRY
    {
        /* Return the handle safely */
        *SectionHandle = Handle;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* Nothing here */
    }
    _SEH2_END;

    /* Return the status */
    return Status;
}

NTSTATUS
NTAPI
NtMapViewOfSection(IN HANDLE SectionHandle,
                   IN HANDLE ProcessHandle,
                   IN OUT PVOID* BaseAddress,
                   IN ULONG_PTR ZeroBits,
                   IN SIZE_T CommitSize,
                   IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
                   IN OUT PSIZE_T ViewSize,
                   IN SECTION_INHERIT InheritDisposition,
                   IN ULONG AllocationType,
                   IN ULONG Protect)
{
    PVOID SafeBaseAddress;
    LARGE_INTEGER SafeSectionOffset;
    SIZE_T SafeViewSize;
    PSECTION Section;
    PEPROCESS Process;
    NTSTATUS Status;
    ACCESS_MASK DesiredAccess;
    ULONG ProtectionMask;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
#if defined(_M_IX86) || defined(_M_AMD64)
    static const ULONG ValidAllocationType = (MEM_TOP_DOWN | MEM_LARGE_PAGES |
            MEM_DOS_LIM | SEC_NO_CHANGE | MEM_RESERVE);
#else
    static const ULONG ValidAllocationType = (MEM_TOP_DOWN | MEM_LARGE_PAGES |
            SEC_NO_CHANGE | MEM_RESERVE);
#endif

    DPRINT("NtMapViewOfSection: SectionHandle %p, ProcessHandle %p, ZeroBits %p, CommitSize %X, AllocationType %X, Protect %X\n", SectionHandle, ProcessHandle, ZeroBits, CommitSize, AllocationType, Protect);

    /* Check for invalid inherit disposition */
    if ((InheritDisposition > ViewUnmap) || (InheritDisposition < ViewShare))
    {
        DPRINT1("Invalid inherit disposition\n");
        return STATUS_INVALID_PARAMETER_8;
    }

    /* Allow only valid allocation types */
    if (AllocationType & ~ValidAllocationType)
    {
        DPRINT1("Invalid allocation type\n");
        return STATUS_INVALID_PARAMETER_9;
    }

    /* Convert the protection mask, and validate it */
    ProtectionMask = MiMakeProtectionMask(Protect);
    if (ProtectionMask == MM_INVALID_PROTECTION)
    {
        DPRINT1("Invalid page protection\n");
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    /* Now convert the protection mask into desired section access mask */
    DesiredAccess = MmMakeSectionAccess[ProtectionMask & 0x7];

    /* Assume no section offset */
    SafeSectionOffset.QuadPart = 0;

    /* Enter SEH */
    _SEH2_TRY
    {
        /* Check for unsafe parameters */
        if (PreviousMode != KernelMode)
        {
            /* Probe the parameters */
            ProbeForWritePointer(BaseAddress);
            ProbeForWriteSize_t(ViewSize);
        }

        /* Check if a section offset was given */
        if (SectionOffset)
        {
            /* Check for unsafe parameters and capture section offset */
            if (PreviousMode != KernelMode) ProbeForWriteLargeInteger(SectionOffset);
            SafeSectionOffset = *SectionOffset;
        }

        /* Capture the other parameters */
        SafeBaseAddress = *BaseAddress;
        SafeViewSize = *ViewSize;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* Return the exception code */
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    /* Check for kernel-mode address */
    if (SafeBaseAddress > MM_HIGHEST_VAD_ADDRESS)
    {
        DPRINT1("Kernel base not allowed\n");
        return STATUS_INVALID_PARAMETER_3;
    }

    /* Check for range entering kernel-mode */
    if (((ULONG_PTR)MM_HIGHEST_VAD_ADDRESS - (ULONG_PTR)SafeBaseAddress) < SafeViewSize)
    {
        DPRINT1("Overflowing into kernel base not allowed\n");
        return STATUS_INVALID_PARAMETER_3;
    }

    /* Check for invalid zero bits */
    if (ZeroBits)
    {
        if (ZeroBits > MI_MAX_ZERO_BITS)
        {
            DPRINT1("Invalid zero bits\n");
            return STATUS_INVALID_PARAMETER_4;
        }

        if ((((ULONG_PTR)SafeBaseAddress << ZeroBits) >> ZeroBits) != (ULONG_PTR)SafeBaseAddress)
        {
            DPRINT1("Invalid zero bits\n");
            return STATUS_INVALID_PARAMETER_4;
        }

        if (((((ULONG_PTR)SafeBaseAddress + SafeViewSize) << ZeroBits) >> ZeroBits) != ((ULONG_PTR)SafeBaseAddress + SafeViewSize))
        {
            DPRINT1("Invalid zero bits\n");
            return STATUS_INVALID_PARAMETER_4;
        }
    }

    /* Reference the process */
    Status = ObReferenceObjectByHandle(ProcessHandle,
                                       PROCESS_VM_OPERATION,
                                       PsProcessType,
                                       PreviousMode,
                                       (PVOID*)&Process,
                                       NULL);
    if (!NT_SUCCESS(Status)) return Status;

    /* Reference the section */
    Status = ObReferenceObjectByHandle(SectionHandle,
                                       DesiredAccess,
                                       MmSectionObjectType,
                                       PreviousMode,
                                       (PVOID*)&Section,
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        ObDereferenceObject(Process);
        return Status;
    }

    if (Section->Segment->ControlArea->u.Flags.PhysicalMemory)
    {
        SafeSectionOffset.LowPart = (ULONG)PAGE_ALIGN(SafeSectionOffset.LowPart);
        if (PreviousMode == UserMode &&
            SafeSectionOffset.QuadPart + SafeViewSize > MmHighestPhysicalPage << PAGE_SHIFT)
        {
            DPRINT1("Denying map past highest physical page.\n");
            ObDereferenceObject(Section);
            ObDereferenceObject(Process);
            return STATUS_INVALID_PARAMETER_6;
        }
    }
    else if (!(AllocationType & MEM_DOS_LIM))
    {
        /* Check for non-allocation-granularity-aligned BaseAddress */
        if (SafeBaseAddress != ALIGN_DOWN_POINTER_BY(SafeBaseAddress, MM_ALLOCATION_GRANULARITY))
        {
            DPRINT("BaseAddress is not at 64-kilobyte address boundary.\n");
            ObDereferenceObject(Section);
            ObDereferenceObject(Process);
            return STATUS_MAPPED_ALIGNMENT;
        }

        /* Do the same for the section offset */
        if (SafeSectionOffset.LowPart != ALIGN_DOWN_BY(SafeSectionOffset.LowPart, MM_ALLOCATION_GRANULARITY))
        {
            DPRINT("SectionOffset is not at 64-kilobyte address boundary.\n");
            ObDereferenceObject(Section);
            ObDereferenceObject(Process);
            return STATUS_MAPPED_ALIGNMENT;
        }
    }

    /* Now do the actual mapping */
    Status = MmMapViewOfSection(Section,
                                Process,
                                &SafeBaseAddress,
                                ZeroBits,
                                CommitSize,
                                &SafeSectionOffset,
                                &SafeViewSize,
                                InheritDisposition,
                                AllocationType,
                                Protect);

    /* Return data only on success */
    if (NT_SUCCESS(Status))
    {
        /* Check if this is an image for the current process */
        if (Section->Segment->ControlArea->u.Flags.Image &&
            (Process == PsGetCurrentProcess()) &&
            (Status != STATUS_IMAGE_NOT_AT_BASE))
        {
            /* Notify the debugger */
            DbgkMapViewOfSection(Section,
                                 SafeBaseAddress,
                                 SafeSectionOffset.LowPart,
                                 SafeViewSize);
        }

        /* Enter SEH */
        _SEH2_TRY
        {
            /* Return parameters to user */
            *BaseAddress = SafeBaseAddress;
            *ViewSize = SafeViewSize;
            if (SectionOffset) *SectionOffset = SafeSectionOffset;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Nothing to do */
        }
        _SEH2_END;
    }

    /* Dereference all objects and return status */
    ObDereferenceObject(Section);
    ObDereferenceObject(Process);
    return Status;
}

NTSTATUS
NTAPI
NtUnmapViewOfSection(IN HANDLE ProcessHandle,
                     IN PVOID BaseAddress)
{
    PEPROCESS Process;
    NTSTATUS Status;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();

    DPRINT("NtUnmapViewOfSection: BaseAddress %p\n", BaseAddress);

    /* Don't allowing mapping kernel views */
    if ((PreviousMode == UserMode) && (BaseAddress > MM_HIGHEST_USER_ADDRESS))
    {
        DPRINT1("Trying to unmap a kernel view\n");
        return STATUS_NOT_MAPPED_VIEW;
    }

    /* Reference the process */
    Status = ObReferenceObjectByHandle(ProcessHandle,
                                       PROCESS_VM_OPERATION,
                                       PsProcessType,
                                       PreviousMode,
                                       (PVOID*)&Process,
                                       NULL);
    if (!NT_SUCCESS(Status)) return Status;

    /* Unmap the view */
    Status = MiUnmapViewOfSection(Process, BaseAddress, 0);

    /* Dereference the process and return status */
    ObDereferenceObject(Process);
    return Status;
}

NTSTATUS
NTAPI
NtExtendSection(IN HANDLE SectionHandle,
                IN OUT PLARGE_INTEGER NewMaximumSize)
{
    LARGE_INTEGER SafeNewMaximumSize;
    PROS_SECTION_OBJECT Section;
    NTSTATUS Status;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();

    ASSERT(FALSE);

    /* Check for user-mode parameters */
    if (PreviousMode != KernelMode)
    {
        /* Enter SEH */
        _SEH2_TRY
        {
            /* Probe and capture the maximum size, it's both read and write */
            ProbeForWriteLargeInteger(NewMaximumSize);
            SafeNewMaximumSize = *NewMaximumSize;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        /* Just read the size directly */
        SafeNewMaximumSize = *NewMaximumSize;
    }

    /* Reference the section */
    Status = ObReferenceObjectByHandle(SectionHandle,
                                       SECTION_EXTEND_SIZE,
                                       MmSectionObjectType,
                                       PreviousMode,
                                       (PVOID*)&Section,
                                       NULL);
    if (!NT_SUCCESS(Status)) return Status;

    /* Really this should go in MmExtendSection */
    if (!(Section->AllocationAttributes & SEC_FILE))
    {
        DPRINT1("Not extending a file\n");
        ObDereferenceObject(Section);
        return STATUS_SECTION_NOT_EXTENDED;
    }

    /* FIXME: Do the work */

    /* Dereference the section */
    ObDereferenceObject(Section);

    /* Enter SEH */
    _SEH2_TRY
    {
        /* Write back the new size */
        *NewMaximumSize = SafeNewMaximumSize;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* Nothing to do */
    }
    _SEH2_END;

    /* Return the status */
    return STATUS_NOT_IMPLEMENTED;
}

/* EOF */
