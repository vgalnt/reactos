
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "cc.h"
#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PVACB CcVacbs;
PVACB CcBeyondVacbs;
LIST_ENTRY CcVacbLru;
LIST_ENTRY CcVacbFreeList;
PVOID* CcVacbLevelFreeList = NULL;
ULONG CcVacbLevelEntries = 0;
PVOID* CcVacbLevelWithBcbsFreeList = NULL;
ULONG CcVacbLevelWithBcbsEntries = 0;
ULONG CcMaxVacbLevelsSeen = 1;

extern SHARED_CACHE_MAP_LIST_CURSOR CcDirtySharedCacheMapList;
extern ULONG CcTotalDirtyPages;
extern LAZY_WRITER LazyWriter;
extern LARGE_INTEGER CcFirstDelay;

/* FUNCTIONS ******************************************************************/

VOID
NTAPI
CcDrainVacbLevelZone(VOID)
{
    PVOID VacbArray;
    KIRQL OldIrql;

    while (CcVacbLevelEntries > (4 * CcMaxVacbLevelsSeen) ||
           CcVacbLevelWithBcbsEntries > 2)
    {
        VacbArray = 0;

        OldIrql = KeAcquireQueuedSpinLock(LockQueueVacbLock);

        if (CcVacbLevelEntries <= (4 * CcMaxVacbLevelsSeen))
        {
            if (CcVacbLevelWithBcbsEntries > 2)
            {
                VacbArray = CcVacbLevelWithBcbsFreeList;
                CcVacbLevelWithBcbsFreeList = *CcVacbLevelWithBcbsFreeList;
                CcVacbLevelWithBcbsEntries--;
            }
        }
        else
        {
            VacbArray = CcVacbLevelFreeList;
            CcVacbLevelFreeList = *CcVacbLevelFreeList;
            CcVacbLevelEntries--;
        }

        KeReleaseQueuedSpinLock(LockQueueVacbLock, OldIrql);

        if (VacbArray)
            ExFreePool(VacbArray);
    }
}

PLIST_ENTRY
NTAPI
CcGetBcbListHeadLargeOffset(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ LONGLONG FileOffset,
    _In_ BOOLEAN Flag3)
{
    PVACB* CurrentVacbs;
    PVACB* NextVacbs;
    PVACB* VacbsArray[7];
    ULONG IndexArray[7];
    ULONG VacbShift;
    ULONG Index;
    ULONG Level = 0;
    ULONG ix = 0;
    ULONG Idx;

    CurrentVacbs = SharedMap->Vacbs;
    VacbShift = 0x19;

    ASSERT(SharedMap->SectionSize.QuadPart > 0x2000000);//VACB_SIZE_OF_FIRST_LEVEL

    do
    {
        VacbShift += 7;
        Level++;
    }
    while (SharedMap->SectionSize.QuadPart > (1LL << VacbShift));

    if (FileOffset >= (1LL << VacbShift))
        return &SharedMap->BcbList;

    VacbShift -= 7;

    while (TRUE)
    {
        Level--;

        Index = (FileOffset >> VacbShift);
        ASSERT(Index <= 0x7F);//VACB_LAST_INDEX_FOR_LEVEL

        NextVacbs = (PVACB *)CurrentVacbs[Index];
        if (NextVacbs)
            goto Next;

        while (TRUE)
        {
            if (Flag3)
            {
                if (Index != 0x7F)
                {
                    do
                    {
                        if (Index == 0x7F)
                            break;

                        Index++;
                    }
                    while (!CurrentVacbs[Index]);

                    NextVacbs = (PVACB *)CurrentVacbs[Index];
                    if (NextVacbs)
                    {
                        FileOffset = 0;
                        break;
                    }
                }
            }
            else if (Index)
            {
                do
                {
                    if (!Index)
                        break;

                    Index--;
                }
                while (!CurrentVacbs[Index]);

                NextVacbs = (PVACB *)CurrentVacbs[Index];
                if (NextVacbs)
                {
                    FileOffset = 0x7FFFFFFFFFFFFFFF;
                    break;
                }
            }
            if (!ix)
                return &SharedMap->BcbList;

            Level++;

            ix--;
            Index = IndexArray[ix];
            CurrentVacbs = VacbsArray[ix];
        }
Next:
        Idx = ix++;
        VacbsArray[Idx] = CurrentVacbs;
        IndexArray[Idx] = Index;

        CurrentVacbs = NextVacbs;

        FileOffset &= ((1LL << VacbShift) - 1);
        VacbShift -= 7;

        if (!Level)
            break;
    }

    return Add2Ptr(&CurrentVacbs[(FileOffset >> VacbShift) & 0xFFFFFFFE], 0x200);
}

PLIST_ENTRY
NTAPI
CcGetBcbListHead(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ LONGLONG FileOffset,
    _In_ BOOLEAN Flag3)
{
    PLIST_ENTRY BcbLists;
    ULONG SizeOfVacbs;

    DPRINT("CcGetBcbListHead: %p, [%I64X], %X\n", SharedMap, FileOffset, Flag3);

    if (SharedMap->SectionSize.QuadPart <= 0x200000)
        return &SharedMap->BcbList;

    if (!(SharedMap->Flags & SHARE_FL_MODIFIED_NO_WRITE))
        return &SharedMap->BcbList;

    if (SharedMap->SectionSize.QuadPart > CACHE_OVERALL_SIZE)
        return CcGetBcbListHeadLargeOffset(SharedMap, FileOffset, Flag3);

    if (SharedMap->SectionSize.QuadPart <= FileOffset)
        return &SharedMap->BcbList;

    SizeOfVacbs = ((SharedMap->SectionSize.LowPart / VACB_MAPPING_GRANULARITY) * sizeof(PVACB));

    BcbLists = Add2Ptr(SharedMap->Vacbs, SizeOfVacbs);

    return &BcbLists[FileOffset / BCB_MAPPING_GRANULARITY];
}

VOID
NTAPI
CcInitializeVacbs(VOID)
{
    PVACB CurrentVacb;
    ULONG CcNumberVacbs;
    ULONG SizeOfVacbs;

    CcNumberVacbs = ((MmSizeOfSystemCacheInPages / (VACB_MAPPING_GRANULARITY / PAGE_SIZE)) - 2);
    SizeOfVacbs = (CcNumberVacbs * sizeof(VACB));

    DPRINT("CcInitializeVacbs: MmSizeOfSystemCacheInPages %X, CcNumberVacbs %X\n",
           MmSizeOfSystemCacheInPages, CcNumberVacbs);

    CcVacbs = ExAllocatePoolWithTag(NonPagedPool, SizeOfVacbs, 'aVcC');
    if (!CcVacbs)
    {
        DPRINT1("CcInitializeVacbs: allocate VACBs failed\n");
        return;
    }

    RtlZeroMemory(CcVacbs, SizeOfVacbs);

    CcBeyondVacbs = &CcVacbs[CcNumberVacbs];

    InitializeListHead(&CcVacbLru);
    InitializeListHead(&CcVacbFreeList);

    for (CurrentVacb = CcVacbs; CurrentVacb < CcBeyondVacbs; CurrentVacb++)
        InsertTailList(&CcVacbFreeList, &CurrentVacb->LruList);
}

PVACB
NTAPI
CcGetVacbLargeOffset(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ LONGLONG FileOffset)
{
    PVACB* Vacbs = SharedMap->Vacbs;
    PVACB Vacb;
    ULONG Level = 0;
    ULONG Bits;

    DPRINT("CcGetVacbLargeOffset: SharedMap %p, FileOffset %I64X\n", SharedMap, FileOffset);

    ASSERT(SharedMap->SectionSize.QuadPart > CACHE_OVERALL_SIZE);

    Bits = (VACB_OFFSET_SHIFT + VACB_LEVEL_SHIFT);

    do
    {
        Level++;
        Bits += VACB_LEVEL_SHIFT;
    }
    while ((1LL << Bits) < SharedMap->SectionSize.QuadPart);

    Bits -= VACB_LEVEL_SHIFT;

    Vacb = Vacbs[FileOffset >> Bits];

    for (; Vacb && Level; Level--)
    {
        FileOffset &= ((1LL << Bits) - 1);
        Bits -= VACB_LEVEL_SHIFT;

        Vacbs = (PVACB *)Vacb;
        Vacb = Vacbs[FileOffset >> Bits];
    }

    if (Vacb)
    {
        ASSERT((Vacb >= CcVacbs) && (Vacb < CcBeyondVacbs));
    }

    return Vacb;
}

NTSTATUS
NTAPI
CcCreateVacbArray(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ LARGE_INTEGER AllocationSize)
{
    PVACB* NewVacbs;
    PLIST_ENTRY BcbEntry;
    ULONG NewSize;
    ULONG AllocSize;
    ULONG Level;
    ULONG Bits;
    BOOLEAN IsExtended = FALSE;
    BOOLEAN IsBcbList = FALSE;

    DPRINT("CcCreateVacbArray: SharedMap %p AllocationSize %I64X\n", SharedMap, AllocationSize.QuadPart);

    if ((ULONGLONG)AllocationSize.QuadPart >= (16ull * _1TB)) // 0x00001000 00000000
    {
        DPRINT1("CcCreateVacbArray: STATUS_SECTION_TOO_BIG\n");
        return STATUS_SECTION_TOO_BIG;
    }

    if ((ULONGLONG)AllocationSize.QuadPart >= (4ull * _1GB))
    {
        NewSize = 0xFFFFFFFF;
        DPRINT("CcCreateVacbArray: NewSize %X\n", NewSize);
    }
    else if (AllocationSize.LowPart <= (VACB_MAPPING_GRANULARITY * sizeof(PVACB))) // <= 1 Mb
    {
        NewSize = (CC_DEFAULT_NUMBER_OF_VACBS * sizeof(PVACB));
        DPRINT("CcCreateVacbArray: NewSize %X\n", NewSize);
    }
    else // 1 Mb - 4 Gb
    {
        NewSize = ((AllocationSize.LowPart / VACB_MAPPING_GRANULARITY) * sizeof(PVACB));
        DPRINT("CcCreateVacbArray: NewSize %X\n", NewSize);
    }

    AllocSize = NewSize;

    if (NewSize == (CC_DEFAULT_NUMBER_OF_VACBS * sizeof(PVACB))) // <= 1 Mb
    {
        NewVacbs = SharedMap->InitialVacbs;
    }
    else
    {
        if (NewSize <= 0x200)
        {
            if ((SharedMap->Flags & SHARE_FL_MODIFIED_NO_WRITE) && AllocationSize.QuadPart > 0x200000)
            {
                /* Add size for BcbLists */
                AllocSize += ((AllocSize + (sizeof(LIST_ENTRY) - 1)) & ~(sizeof(LIST_ENTRY) - 1));
                IsBcbList = TRUE;
            }

            if (NewSize == 0x200)
            {
                AllocSize += sizeof(CC_VACB_REFERENCE);
                IsExtended = TRUE;
            }
        }
        else // > 32 Mb
        {
            NewSize = VACB_LEVEL_BLOCK_SIZE;
            AllocSize = (NewSize + sizeof(CC_VACB_REFERENCE));

            Level = 0;
            Bits = (VACB_OFFSET_SHIFT + VACB_LEVEL_SHIFT);

            do
            {
                Level++;
                Bits += VACB_LEVEL_SHIFT;
            }
            while ((1LL << Bits) < AllocationSize.QuadPart);

            if (Level >= CcMaxVacbLevelsSeen)
            {
                ASSERT(Level <= VACB_NUMBER_OF_LEVELS);
                CcMaxVacbLevelsSeen = (Level + 1);
            }

            IsExtended = TRUE;
        }

        NewVacbs = ExAllocatePoolWithTag(NonPagedPool, AllocSize, 'pVcC');
        if (!NewVacbs)
        {
            DPRINT1("CcCreateVacbArray: STATUS_INSUFFICIENT_RESOURCES\n");
            SharedMap->Status = STATUS_INSUFFICIENT_RESOURCES;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    RtlZeroMemory(NewVacbs, NewSize);

    if (IsExtended)
    {
        AllocSize -= sizeof(CC_VACB_REFERENCE);
        RtlZeroMemory(Add2Ptr(NewVacbs, AllocSize), sizeof(CC_VACB_REFERENCE));
    }

    if (IsBcbList)
    {
        DPRINT1("CcCreateVacbArray: NewSize %X, AllocSize %X\n", NewSize, AllocSize);

        for (BcbEntry = Add2Ptr(NewVacbs, NewSize);
             BcbEntry < (PLIST_ENTRY)Add2Ptr(NewVacbs, AllocSize);
             BcbEntry++)
        {
            InsertHeadList(&SharedMap->BcbList, BcbEntry);
        }
    }

    SharedMap->SectionSize.QuadPart = AllocationSize.QuadPart;
    SharedMap->Vacbs = NewVacbs;

    return STATUS_SUCCESS;
}

PVOID*
NTAPI
CcAllocateVacbLevel(
    _In_ BOOLEAN WithBcbs)
{
    PVOID* ReturnEntry;

    if (WithBcbs)
    {
        ReturnEntry = CcVacbLevelWithBcbsFreeList;

        CcVacbLevelWithBcbsFreeList = CcVacbLevelWithBcbsFreeList[0];
        CcVacbLevelWithBcbsEntries--;
    }
    else
    {
        ReturnEntry = CcVacbLevelFreeList;

        CcVacbLevelFreeList = CcVacbLevelFreeList[0];
        CcVacbLevelEntries--;
    }

    ReturnEntry[0] = NULL;

    ASSERT(RtlCompareMemory(ReturnEntry, (ReturnEntry + 1),
           (VACB_LEVEL_BLOCK_SIZE - sizeof(PVACB))) == (VACB_LEVEL_BLOCK_SIZE - sizeof(PVACB)));

    return ReturnEntry;
}

VOID
NTAPI
CcDeallocateVacbLevel(
    _In_ PVOID* Entry,
    _In_ BOOLEAN WithBcbs)
{
    if (WithBcbs)
    {
        *Entry = CcVacbLevelWithBcbsFreeList;
        CcVacbLevelWithBcbsFreeList = Entry;

        CcVacbLevelWithBcbsEntries++;
    }
    else
    {
        *Entry = CcVacbLevelFreeList;
        CcVacbLevelFreeList = Entry;

        CcVacbLevelEntries++;
    }
}

PCC_VACB_REFERENCE
NTAPI
VacbLevelReference(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ PVACB* Vacbs,
    _In_ ULONG Level)
{
    PCC_VACB_REFERENCE VacbReference;
    ULONG Offset = VACB_LEVEL_BLOCK_SIZE;

    if (!Level && (SharedMap->Flags & SHARE_FL_MODIFIED_NO_WRITE))
        Offset += VACB_LEVEL_BLOCK_SIZE;

    VacbReference = Add2Ptr(Vacbs, Offset);

    return VacbReference;
}

VOID
NTAPI
ReferenceVacbLevel(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ PVACB* Vacbs,
    _In_ ULONG Level,
    _In_ LONG Amount,
    _In_ BOOLEAN Special)
{
    PCC_VACB_REFERENCE VacbReference;

    VacbReference = VacbLevelReference(SharedMap, Vacbs, Level);

    if (Amount <= 0)
    {
        if (!Special)
        {
            ASSERT(VacbReference->Reference >= (0 - Amount));
        }
        else
        {
            ASSERT(VacbReference->SpecialReference >= (0 - Amount));
        }
    }

    if (!Special)
        VacbReference->Reference += Amount;
    else
        VacbReference->SpecialReference += Amount;
}

ULONG
NTAPI
IsVacbLevelReferenced(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ PVACB* Vacbs,
    _In_ ULONG Level)
{
    PCC_VACB_REFERENCE VacbReference;

    VacbReference = VacbLevelReference(SharedMap, Vacbs, Level);

    return (VacbReference->Reference | VacbReference->SpecialReference);
}

VOID
NTAPI
CcSetVacbLargeOffset(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ LONGLONG FileOffset,
    _In_ PVACB Vacb)
{
    PVACB* vacbs[VACB_NUMBER_OF_LEVELS];
    ULONG indexes[VACB_NUMBER_OF_LEVELS];
    LONGLONG fileOffset = FileOffset;
    PVACB* Vacbs = SharedMap->Vacbs;
    PVACB* NextVacbs;
    PLIST_ENTRY PreviousList;
    PLIST_ENTRY NextList;
    PLIST_ENTRY Entry;
    PCC_BCB Bcb;
    ULONG Level = 0;
    ULONG Bits;
    ULONG Index;
    ULONG ix = 0;
    ULONG jx;
    BOOLEAN IsAllocWithBcbs;
    BOOLEAN Special;

    DPRINT("CcSetVacbLargeOffset: %p, %I64X, %p\n", SharedMap, FileOffset, Vacb);

    ASSERT(SharedMap->SectionSize.QuadPart > CACHE_OVERALL_SIZE);

    Bits = (VACB_OFFSET_SHIFT + VACB_LEVEL_SHIFT);

    do
    {
        Level++;
        Bits += VACB_LEVEL_SHIFT;
    }
    while ((1LL << Bits) < SharedMap->SectionSize.QuadPart);

    Bits -= VACB_LEVEL_SHIFT;

    do
    {
        Level--;

        Index = (FileOffset >> Bits);
        ASSERT(Index <= VACB_LAST_INDEX_FOR_LEVEL);

        indexes[ix] = Index;
        vacbs[ix] = Vacbs;

        ix++;

        NextVacbs = (PVACB *)Vacbs[Index];
        if (!NextVacbs)
        {
            ASSERT(Vacb != VACB_SPECIAL_DEREFERENCE);
            ASSERT(Vacb != NULL);

            IsAllocWithBcbs = (((SharedMap->Flags & SHARE_FL_MODIFIED_NO_WRITE) != 0) && !Level);

            NextVacbs = (PVACB *)CcAllocateVacbLevel(IsAllocWithBcbs);

            if (IsAllocWithBcbs)
            {
                PreviousList = CcGetBcbListHeadLargeOffset(SharedMap, fileOffset, FALSE);

                while (TRUE)
                {
                    Bcb = CONTAINING_RECORD(PreviousList->Blink, CC_BCB, Link);
                    if (Bcb->NodeTypeCode != 0x2FD)
                        break;

                    PreviousList = PreviousList->Blink;
                }

                NextList = PreviousList->Blink;
                PreviousList->Blink = Entry = (PLIST_ENTRY)(NextVacbs + 0x80);
                Entry->Flink = PreviousList;

                for (jx = 0; jx < 0x3F; jx++)
                {
                    Entry->Blink = (Entry + 1);
                    Entry++;
                    Entry->Flink = (Entry - 1);
                }

                Entry->Blink = NextList;
                NextList->Flink = Entry;
            }

            Vacbs[Index] = (PVACB)NextVacbs;
            ReferenceVacbLevel(SharedMap, Vacbs, (Level + 1), 1, FALSE);
        }

        Vacbs = NextVacbs;

        FileOffset &= ((1LL << Bits) - 1);
        Bits -= VACB_LEVEL_SHIFT;
    }
    while (Level);

    if (Vacb < VACB_SPECIAL_DEREFERENCE)
    {
        Index = (FileOffset >> Bits);
        Vacbs[Index] = Vacb;

        Special = FALSE;
    }
    else
    {
        if (Vacb == VACB_SPECIAL_DEREFERENCE)
            Vacb = NULL;

        Special = TRUE;
    }

    if (Vacb)
    {
        ReferenceVacbLevel(SharedMap, Vacbs, Level, 1, Special);
        return;
    }

    while (TRUE)
    {
        ReferenceVacbLevel(SharedMap, Vacbs, Level, -1, Special);

        Special = FALSE;

        if (IsVacbLevelReferenced(SharedMap, Vacbs, Level))
            break;

        if (!ix)
            break;

        ix--;

        if (!Level && (SharedMap->Flags & SHARE_FL_MODIFIED_NO_WRITE))
        {
            PLIST_ENTRY List1 = (PLIST_ENTRY)Vacbs[0x80];
            PLIST_ENTRY List2 = (PLIST_ENTRY)Vacbs[0xFF];

            List1->Blink = List2;
            List2->Flink = List1;

            IsAllocWithBcbs = TRUE;
        }
        else
        {
            IsAllocWithBcbs = FALSE;
        }

        Level++;

        CcDeallocateVacbLevel((PVOID *)Vacbs, IsAllocWithBcbs);

        Index = indexes[ix];
        Vacbs = vacbs[ix];

        Vacbs[Index] = NULL;
    }
}

VOID
NTAPI
SetVacb(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ LARGE_INTEGER SectionOffset,
    _In_ PVACB Vacb)
{
    DPRINT("SetVacb: %p, %I64X, %p\n", SharedMap, SectionOffset.QuadPart, Vacb);

    if (SharedMap->SectionSize.QuadPart <= CACHE_OVERALL_SIZE)
    {
        SharedMap->Vacbs[SectionOffset.LowPart / VACB_MAPPING_GRANULARITY] = Vacb;
        return;
    }

    CcSetVacbLargeOffset(SharedMap, SectionOffset.QuadPart, Vacb);
}

VOID
NTAPI
CcUnmapVacb(
    _In_ PVACB Vacb,
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ BOOLEAN FrontOfList)
{
    ASSERT(SharedMap != NULL);
    ASSERT(Vacb->BaseAddress != NULL);

    DPRINT("CcUnmapVacb: Vacb %p, SharedMap %p, FrontOfList %X\n", Vacb, SharedMap, FrontOfList);

    if (FrontOfList && (SharedMap->Flags & SHARE_FL_SEQUENTIAL_ONLY))
        FrontOfList = TRUE;
    else
        FrontOfList = FALSE;

    MmUnmapViewInSystemCache(Vacb->BaseAddress, SharedMap->Section, FrontOfList);

    Vacb->BaseAddress = NULL;
}

BOOLEAN
NTAPI
CcUnmapVacbArray(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ PLARGE_INTEGER FileOffset,
    _In_ ULONG Length,
    _In_ BOOLEAN FrontOfList)
{
    KLOCK_QUEUE_HANDLE LockHandle;
    LARGE_INTEGER Start;
    LARGE_INTEGER End;
    PVACB Vacb;
    BOOLEAN LockMode = FALSE;

    DPRINT("CcUnmapVacbArray: %p, %I64X, %X, %X\n", SharedMap, (FileOffset ? FileOffset->QuadPart : 0), Length, FrontOfList);

    if (!SharedMap->Vacbs)
        return TRUE;

    if (FileOffset)
    {
        Start.QuadPart = FileOffset->QuadPart & ~(VACB_MAPPING_GRANULARITY - 1);

        if (Length)
            End.QuadPart = (FileOffset->QuadPart + Length);
        else
            End.QuadPart = SharedMap->SectionSize.QuadPart;
    }
    else
    {
        Start.QuadPart = 0;
        End.QuadPart = SharedMap->SectionSize.QuadPart;
    }

    if (SharedMap->SectionSize.QuadPart > (2 * _1MB) &&
        (SharedMap->Flags & SHARE_FL_MODIFIED_NO_WRITE))
    {
        LockMode = TRUE;
    }

    ExAcquirePushLockShared((PEX_PUSH_LOCK)&SharedMap->VacbPushLock);

    if (LockMode)
    {
        KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, &LockHandle);
        KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
    }
    else
    {
        LockHandle.OldIrql = KeAcquireQueuedSpinLock(LockQueueVacbLock);
    }

    while (Start.QuadPart < End.QuadPart)
    {
        DPRINT("CcUnmapVacbArray: Start %I64X, End %I64X\n", Start.QuadPart, End.QuadPart);

        if (Start.QuadPart < SharedMap->SectionSize.QuadPart)
        {
            if (SharedMap->SectionSize.QuadPart <= CACHE_OVERALL_SIZE)
                Vacb = SharedMap->Vacbs[Start.LowPart / VACB_MAPPING_GRANULARITY];
            else
                Vacb = CcGetVacbLargeOffset(SharedMap, Start.QuadPart);

            if (Vacb)
            {
                if (Vacb->Overlay.ActiveCount)
                {
                    if (LockMode)
                    {
                        KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
                        KeReleaseInStackQueuedSpinLock(&LockHandle);
                    }
                    else
                    {
                        KeReleaseQueuedSpinLock(LockQueueVacbLock, LockHandle.OldIrql);
                    }

                    ExReleasePushLockShared((PEX_PUSH_LOCK)&SharedMap->VacbPushLock);
                    return FALSE;
                }

                SetVacb(SharedMap, Start, NULL);

                Vacb->Overlay.ActiveCount++;
                Vacb->SharedCacheMap = NULL;

                if (!LockMode)
                {
                    KeReleaseQueuedSpinLock(LockQueueVacbLock, LockHandle.OldIrql);
                }
                else
                {
                    KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
                    KeReleaseInStackQueuedSpinLock(&LockHandle);
                }

                CcUnmapVacb(Vacb, SharedMap, FrontOfList);

                if (LockMode)
                {
                    KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, &LockHandle);
                    KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
                }
                else
                {
                    LockHandle.OldIrql = KeAcquireQueuedSpinLock(LockQueueVacbLock);
                }

                Vacb->Overlay.ActiveCount--;

                RemoveEntryList(&Vacb->LruList);
                InsertHeadList(&CcVacbFreeList, &Vacb->LruList);
            }
            else
            {
                DPRINT("CcUnmapVacbArray: Vacb == NULL\n");
            }
        }

        Start.QuadPart += VACB_MAPPING_GRANULARITY;
    }

    if (LockMode)
    {
        KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
        KeReleaseInStackQueuedSpinLock(&LockHandle);
    }
    else
    {
        KeReleaseQueuedSpinLock(LockQueueVacbLock, LockHandle.OldIrql);
    }

    ExReleasePushLockShared((PEX_PUSH_LOCK)&SharedMap->VacbPushLock);

    DPRINT("CcUnmapVacbArray: FIXME CcDrainVacbLevelZone()\n");

    return TRUE;
}

BOOLEAN
NTAPI
CcPrefillVacbLevelZone(
    _In_ ULONG ToLevel,
    _Out_ PKLOCK_QUEUE_HANDLE OutLockHandle,
    _In_ BOOLEAN IsModifiedNoWrite,
    _In_ BOOLEAN LockMode,
    _In_ PSHARED_CACHE_MAP SharedMap)
{
    PVOID* NewLevelEntry;
    ULONG Size;

    DPRINT("CcPrefillVacbLevelZone: ToLevel %X (%X)\n", ToLevel, IsModifiedNoWrite);

    if (LockMode)
    {
        ASSERT(SharedMap != NULL);
        KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, OutLockHandle);
        KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
    }
    else
    {
        OutLockHandle->OldIrql = KeAcquireQueuedSpinLock(LockQueueVacbLock);
    }

    while (ToLevel > CcVacbLevelEntries ||
           (IsModifiedNoWrite && !CcVacbLevelWithBcbsFreeList))
    {
        if (LockMode)
        {
            KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
            KeReleaseInStackQueuedSpinLock(OutLockHandle);
        }
        else
        {
            KeReleaseQueuedSpinLock(LockQueueVacbLock, OutLockHandle->OldIrql);
        }

        if (IsModifiedNoWrite && !CcVacbLevelWithBcbsFreeList)
        {
            Size = ((2 * (0x80 * sizeof(PVOID))) + 8);

            NewLevelEntry = ExAllocatePoolWithTag(NonPagedPool, Size, 'lVcC');
            if (!NewLevelEntry)
            {
                DPRINT1("CcPrefillVacbLevelZone: Allocate failed\n");
                return FALSE;
            }

            RtlZeroMemory(NewLevelEntry, Size);

            if (LockMode)
            {
                ASSERT(SharedMap != NULL);
                KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, OutLockHandle);
                KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
            }
            else
            {
                OutLockHandle->OldIrql = KeAcquireQueuedSpinLock(LockQueueVacbLock);
            }

            NewLevelEntry[0] = CcVacbLevelWithBcbsFreeList;
            CcVacbLevelWithBcbsFreeList = NewLevelEntry;

            CcVacbLevelWithBcbsEntries++;
        }
        else
        {
            Size = ((0x80 * sizeof(PVOID)) + 8);

            NewLevelEntry = ExAllocatePoolWithTag(NonPagedPool, Size, 'lVcC');
            if (!NewLevelEntry)
            {
                DPRINT1("CcPrefillVacbLevelZone: Allocate failed\n");
                return FALSE;
            }

            RtlZeroMemory(NewLevelEntry, Size);

            if (LockMode)
            {
                ASSERT(SharedMap != NULL);
                KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, OutLockHandle);
                KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
            }
            else
            {
                OutLockHandle->OldIrql = KeAcquireQueuedSpinLock(LockQueueVacbLock);
            }

            NewLevelEntry[0] = CcVacbLevelFreeList;
            CcVacbLevelFreeList = NewLevelEntry;

            CcVacbLevelEntries++;
        }
    }

    return TRUE;
}

PVACB
NTAPI
CcGetVacbMiss(
     _In_ PSHARED_CACHE_MAP SharedMap,
     _In_ LARGE_INTEGER FileOffset,
     _In_ PKLOCK_QUEUE_HANDLE LockHandle,
     _In_ BOOLEAN LockMode)
{
    PSHARED_CACHE_MAP VacbSharedMap;
    PVACB Vacb;
    PVACB OutVacb;
    PVACB ActiveVacb = NULL;
    LARGE_INTEGER ViewSize;
    LARGE_INTEGER SectionOffset;
    PLIST_ENTRY Entry;
    ULONG ActivePage;
    BOOLEAN IsVacbLocked;
    NTSTATUS Status;

    DPRINT("CcGetVacbMiss: %p, %I64X, %X\n", SharedMap, FileOffset.QuadPart, LockMode);

    SectionOffset = FileOffset;
    SectionOffset.LowPart -= (FileOffset.LowPart & (VACB_MAPPING_GRANULARITY - 1));

    if (!(SharedMap->Flags & SHARE_FL_RANDOM_ACCESS) &&
        !(SectionOffset.LowPart & (0x80000 - 1)) &&
        SectionOffset.QuadPart >= CC_VACBS_DEFAULT_MAPPING_SIZE)
    {
        if (LockMode)
        {
            KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
            KeReleaseInStackQueuedSpinLock(LockHandle);
        }
        else
        {
            KeReleaseQueuedSpinLock(LockQueueVacbLock, LockHandle->OldIrql);
        }

        ExReleasePushLockShared((PEX_PUSH_LOCK)&SharedMap->VacbPushLock);
        
        ViewSize.QuadPart = (SectionOffset.QuadPart - CC_VACBS_DEFAULT_MAPPING_SIZE);
        CcUnmapVacbArray(SharedMap, &ViewSize, CC_VACBS_DEFAULT_MAPPING_SIZE, TRUE);

        ExAcquirePushLockShared((PEX_PUSH_LOCK)&SharedMap->VacbPushLock);

        if (LockMode)
        {
            KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, LockHandle);
            KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
        }
        else
        {
            LockHandle->OldIrql = KeAcquireQueuedSpinLock(LockQueueVacbLock);
        }
    }

    if (!IsListEmpty(&CcVacbFreeList))
    {
        Vacb = CONTAINING_RECORD(CcVacbFreeList.Flink, VACB, LruList);

        RemoveEntryList(&Vacb->LruList);
        InsertTailList(&CcVacbLru, &Vacb->LruList);
    }
    else
    {
        Entry = CcVacbLru.Flink;

        while (TRUE)
        {
            Vacb = CONTAINING_RECORD(Entry, VACB, LruList);
            VacbSharedMap = Vacb->SharedCacheMap;

            if (!Vacb->Overlay.ActiveCount ||
                (!ActiveVacb && VacbSharedMap && VacbSharedMap->ActiveVacb == Vacb))
            {
                if (!Vacb->BaseAddress)
                    break;

                if (Vacb->Overlay.ActiveCount)
                {
                    KeAcquireSpinLockAtDpcLevel(&VacbSharedMap->ActiveVacbSpinLock);

                    ActiveVacb = Vacb->SharedCacheMap->ActiveVacb;
                    if (ActiveVacb)
                    {
                        ActivePage = Vacb->SharedCacheMap->ActivePage;
                        Vacb->SharedCacheMap->ActiveVacb = 0;
                        IsVacbLocked = ((Vacb->SharedCacheMap->Flags & SHARE_FL_VACB_LOCKED) != 0);
                    }

                    KeReleaseSpinLockFromDpcLevel(&Vacb->SharedCacheMap->ActiveVacbSpinLock);
                }
                else
                {
                    KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueMasterLock]);

                    if (Vacb->SharedCacheMap->FileObject->SectionObjectPointer->SharedCacheMap == Vacb->SharedCacheMap)
                    {
                        Vacb->SharedCacheMap->OpenCount++;
                        KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueMasterLock]);
                        break;
                    }

                    KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueMasterLock]);
                }
            }

            Entry = Vacb->LruList.Flink;

            if (Entry != &CcVacbLru)
                continue;

            if (LockMode)
            {
                KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
                KeReleaseInStackQueuedSpinLock(LockHandle);
            }
            else
            {
                KeReleaseQueuedSpinLock(LockQueueVacbLock, LockHandle->OldIrql);
            }

            if (!ActiveVacb)
            {
                ExReleasePushLockShared((PEX_PUSH_LOCK)&SharedMap->VacbPushLock);
                ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
            }
            else
            {
                CcFreeActiveVacb(ActiveVacb->SharedCacheMap, ActiveVacb, ActivePage, IsVacbLocked);
                ActiveVacb = NULL;

                if (LockMode)
                {
                    KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, LockHandle);
                    KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
                }
                else
                {
                    LockHandle->OldIrql = KeAcquireQueuedSpinLock(LockQueueVacbLock);
                }

                Entry = CcVacbLru.Flink;
            }
        }
    }

    if (Vacb->SharedCacheMap)
    {
        SetVacb(Vacb->SharedCacheMap, Vacb->Overlay.FileOffset, NULL);
        Vacb->SharedCacheMap = NULL;
    }

    Vacb->Overlay.ActiveCount = 1;
    SharedMap->VacbActiveCount++;

    if (LockMode)
    {
        KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
        KeReleaseInStackQueuedSpinLock(LockHandle);
    }
    else
    {
        KeReleaseQueuedSpinLock(LockQueueVacbLock, LockHandle->OldIrql);
    }

    if (Vacb->BaseAddress)
    {
        CcDrainVacbLevelZone();
        CcUnmapVacb(Vacb, VacbSharedMap, FALSE);

        LockHandle->OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

        VacbSharedMap->OpenCount--;

        if (!VacbSharedMap->OpenCount &&
            !(VacbSharedMap->Flags & SHARE_FL_WRITE_QUEUED) &&
            !VacbSharedMap->DirtyPages)
        {
            RemoveEntryList(&VacbSharedMap->SharedCacheMapLinks);
            InsertTailList(&CcDirtySharedCacheMapList.SharedCacheMapLinks, &VacbSharedMap->SharedCacheMapLinks);

            LazyWriter.OtherWork = 1;

            if (!LazyWriter.ScanActive)
                CcScheduleLazyWriteScan(FALSE);
        }

        KeReleaseQueuedSpinLock(LockQueueMasterLock, LockHandle->OldIrql);
    }

    ViewSize.QuadPart = (SharedMap->SectionSize.QuadPart - SectionOffset.QuadPart);

    if (ViewSize.HighPart || (ViewSize.LowPart > VACB_MAPPING_GRANULARITY))
        ViewSize.LowPart = VACB_MAPPING_GRANULARITY;

    _SEH2_TRY
    {
        Status = MmMapViewInSystemCache(SharedMap->Section,
                                        &Vacb->BaseAddress,
                                        &SectionOffset,
                                        &ViewSize.LowPart);
        if (ActiveVacb)
            CcFreeActiveVacb(ActiveVacb->SharedCacheMap, ActiveVacb, ActivePage, IsVacbLocked);

        if (!NT_SUCCESS(Status))
        {
            Vacb->BaseAddress = NULL;
            Status = FsRtlNormalizeNtstatus(Status, STATUS_UNEXPECTED_MM_MAP_ERROR);
            ExRaiseStatus(Status);
        }

        if (SharedMap->SectionSize.QuadPart <= CACHE_OVERALL_SIZE)
        {
            if (LockMode)
            {
                KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, LockHandle);
                KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
            }
            else
            {
                LockHandle->OldIrql = KeAcquireQueuedSpinLock(LockQueueVacbLock);
            }
        }
        else
        {
            if (!CcPrefillVacbLevelZone((CcMaxVacbLevelsSeen - 1),
                                        LockHandle,
                                        ((SharedMap->Flags & SHARE_FL_MODIFIED_NO_WRITE) != 0),
                                        LockMode,
                                        SharedMap))
            {
                ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
            }
        }
    }
    _SEH2_FINALLY
    {
        if (_SEH2_AbnormalTermination())
        {
            if (Vacb->BaseAddress)
            {
                DPRINT1("CcGetVacbMiss: FIXME CcUnmapVacb()\n");
                ASSERT(FALSE);
            }

            ExReleasePushLockShared((PEX_PUSH_LOCK)&SharedMap->VacbPushLock);
            LockHandle->OldIrql = KeAcquireQueuedSpinLock(LockQueueVacbLock);

            ASSERT((Vacb->Overlay.ActiveCount) != 0);
            Vacb->Overlay.ActiveCount--;

            ASSERT((SharedMap->VacbActiveCount) != 0);
            SharedMap->VacbActiveCount--;

            if (SharedMap->WaitOnActiveCount)
                KeSetEvent(SharedMap->WaitOnActiveCount, 0, FALSE);

            ASSERT(Vacb->SharedCacheMap == NULL);

            RemoveEntryList(&Vacb->LruList);
            InsertHeadList(&CcVacbFreeList, &Vacb->LruList);

            KeReleaseQueuedSpinLock(LockQueueVacbLock, LockHandle->OldIrql);
        }
    }
    _SEH2_END;

    if (SharedMap->SectionSize.QuadPart <= CACHE_OVERALL_SIZE)
        OutVacb = SharedMap->Vacbs[SectionOffset.LowPart / VACB_MAPPING_GRANULARITY];
    else
        OutVacb = CcGetVacbLargeOffset(SharedMap, SectionOffset.QuadPart);

    if (!OutVacb)
    {
        OutVacb = Vacb;
        OutVacb->SharedCacheMap = SharedMap;

        OutVacb->Overlay.FileOffset.QuadPart = SectionOffset.QuadPart;
        OutVacb->Overlay.ActiveCount = 1;

        SetVacb(SharedMap, SectionOffset, OutVacb);

        return OutVacb;
    }

    if (!OutVacb->Overlay.ActiveCount)
        SharedMap->VacbActiveCount++;

    OutVacb->Overlay.ActiveCount++;

    if (LockMode)
    {
        KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
        KeReleaseInStackQueuedSpinLock(LockHandle);
    }
    else
    {
        KeReleaseQueuedSpinLock(LockQueueVacbLock, LockHandle->OldIrql);
    }

    CcUnmapVacb(Vacb, SharedMap, FALSE);

    if (LockMode)
    {
        KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, LockHandle);
        KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
    }
    else
    {
        LockHandle->OldIrql = KeAcquireQueuedSpinLock(LockQueueVacbLock);
    }

    ASSERT((Vacb->Overlay.ActiveCount) != 0);
    Vacb->Overlay.ActiveCount--;

    ASSERT((SharedMap->VacbActiveCount) != 0);
    SharedMap->VacbActiveCount--;

    Vacb->SharedCacheMap = NULL;

    RemoveEntryList(&Vacb->LruList);
    InsertHeadList(&CcVacbFreeList, &Vacb->LruList);

    DPRINT("CcGetVacbMiss: return %p\n", OutVacb);
    return OutVacb;
}

PVOID
NTAPI
CcGetVirtualAddress(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ LARGE_INTEGER FileOffset,
    _Out_ PVACB* OutVacb,
    _Out_ ULONG* OutReceivedLength)
{
    PVACB Vacb;
    KLOCK_QUEUE_HANDLE LockHandle;
    ULONG VacbOffset;
    BOOLEAN LockMode = FALSE;

    DPRINT("CcGetVirtualAddress: SharedMap %p, Offset %I64X\n", SharedMap, FileOffset.QuadPart);

    /* Calculate the offset in VACB */
    VacbOffset = (FileOffset.LowPart & (VACB_MAPPING_GRANULARITY - 1));

    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    /* Lock */
    ExAcquirePushLockShared((PEX_PUSH_LOCK)&SharedMap->VacbPushLock);

    if (SharedMap->Flags & SHARE_FL_MODIFIED_NO_WRITE)
    {
        LockMode = TRUE;
        KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, &LockHandle);
        KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
    }
    else
    {
        LockHandle.OldIrql = KeAcquireQueuedSpinLock(LockQueueVacbLock);
    }

    ASSERT(FileOffset.QuadPart <= SharedMap->SectionSize.QuadPart);

    /* Get pointer to Vacb */
    if (SharedMap->SectionSize.QuadPart <= CACHE_OVERALL_SIZE)
        /* Size of file < 32 MB*/
        Vacb = SharedMap->Vacbs[FileOffset.LowPart / VACB_MAPPING_GRANULARITY];
    else
        /* This file is large (more than 32 MB) */
        Vacb = CcGetVacbLargeOffset(SharedMap, FileOffset.QuadPart);

    if (Vacb)
    {
        /* Increment counters */
        if (!Vacb->Overlay.ActiveCount)
            SharedMap->VacbActiveCount++;

        Vacb->Overlay.ActiveCount++;
    }
    else
    {
        /* Vacb not found */
        Vacb = CcGetVacbMiss(SharedMap, FileOffset, &LockHandle, LockMode);
    }

    /* Updating lists */
    RemoveEntryList(&Vacb->LruList);
    InsertTailList(&CcVacbLru, &Vacb->LruList);

    /* Unlock */
    if (!LockMode)
    {
        KeReleaseQueuedSpinLock(LockQueueVacbLock, LockHandle.OldIrql);
    }
    else
    {
        KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
        KeReleaseInStackQueuedSpinLock(&LockHandle);
    }

    ExReleasePushLockShared((PEX_PUSH_LOCK)&SharedMap->VacbPushLock);

    *OutVacb = Vacb;
    *OutReceivedLength = (VACB_MAPPING_GRANULARITY - VacbOffset);

    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
    ASSERT(Vacb->BaseAddress != NULL);

    /* Add an offset to the base and return the virtual address */
    return (PVOID)((ULONG_PTR)Vacb->BaseAddress + VacbOffset);
}

PVOID
NTAPI
CcGetVirtualAddressIfMapped(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ LONGLONG FileOffset,
    _Out_ PVACB* OutVacb,
    _Out_ ULONG* OutLength)
{
    PVOID Address = NULL;
    PVACB Vacb;
    ULONG VacbOffset;
    KIRQL OldIrql;

    DPRINT("CcGetVirtualAddressIfMapped: SharedMap %p, Offset %I64X\n", SharedMap, FileOffset);

    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    /* Calculate the offset in VACB */
    VacbOffset = (FileOffset & (VACB_MAPPING_GRANULARITY - 1));

    *OutLength = (VACB_MAPPING_GRANULARITY - VacbOffset);

    /* Lock */
    ExAcquirePushLockExclusive((PEX_PUSH_LOCK)&SharedMap->VacbPushLock);
    OldIrql = KeAcquireQueuedSpinLock(LockQueueVacbLock);

    ASSERT(FileOffset <= SharedMap->SectionSize.QuadPart);

    /* Get pointer to Vacb */
    if ((SharedMap->SectionSize.QuadPart <= CACHE_OVERALL_SIZE))
        /* Size of file < 32 MB*/
        Vacb = SharedMap->Vacbs[(ULONG)FileOffset >> VACB_OFFSET_SHIFT];
    else
        /* This file is large (more than 32 MB) */
        Vacb = CcGetVacbLargeOffset(SharedMap, FileOffset);

    *OutVacb = Vacb;

    if (Vacb)
    {
        /* Increment counters */
        if (!(Vacb->Overlay.ActiveCount))
            SharedMap->VacbActiveCount++;

        Vacb->Overlay.ActiveCount++;

        /* Updating lists */
        RemoveEntryList(&Vacb->LruList);
        InsertTailList(&CcVacbLru, &Vacb->LruList);

        /* Add an offset to the base */
        Address = Add2Ptr(Vacb->BaseAddress, VacbOffset);
    }

    /* Unlock */
    KeReleaseQueuedSpinLock(LockQueueVacbLock, OldIrql);
    ExReleasePushLockExclusive((PEX_PUSH_LOCK)&SharedMap->VacbPushLock);

    /* Return the virtual address */
    return Address;
}

VOID
NTAPI
CcFreeVirtualAddress(
    _In_ PVACB Vacb)
{
    PSHARED_CACHE_MAP SharedMap;
    KIRQL OldIrql;

    DPRINT("CcFreeVirtualAddress: Vacb %p\n", Vacb);

    OldIrql = KeAcquireQueuedSpinLock(LockQueueVacbLock);

    ASSERT((Vacb->Overlay.ActiveCount) != 0);
    Vacb->Overlay.ActiveCount--;

    if (Vacb->Overlay.ActiveCount)
        goto Finish;

    SharedMap = Vacb->SharedCacheMap;
    if (!SharedMap)
    {
        ASSERT(Vacb->BaseAddress == NULL);

        RemoveEntryList(&Vacb->LruList);
        InsertHeadList(&CcVacbFreeList, &Vacb->LruList);

        KeReleaseQueuedSpinLock(LockQueueVacbLock, OldIrql);
        return;
    }

    ASSERT((SharedMap->VacbActiveCount) != 0);
    SharedMap->VacbActiveCount--;

    if (SharedMap->WaitOnActiveCount)
        KeSetEvent(SharedMap->WaitOnActiveCount, 0, FALSE);

Finish:

    RemoveEntryList(&Vacb->LruList);
    InsertTailList(&CcVacbLru, &Vacb->LruList);

    KeReleaseQueuedSpinLock(LockQueueVacbLock, OldIrql);
    return;
}

VOID
NTAPI
CcGetActiveVacb(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _Out_ PVACB* OutVacb,
    _Out_ ULONG* OutActivePage,
    _Out_ BOOLEAN* OutIsVacbLocked)
{
    KIRQL OldIrql;

    KeAcquireSpinLock(&SharedMap->ActiveVacbSpinLock, &OldIrql);

    *OutVacb = SharedMap->ActiveVacb;
    DPRINT("CcGetActiveVacb: ActiveVacb %p\n", SharedMap->ActiveVacb);

    if (*OutVacb)
    {
        SharedMap->ActiveVacb = NULL;

        *OutActivePage = SharedMap->ActivePage;
        *OutIsVacbLocked = ((SharedMap->Flags & SHARE_FL_VACB_LOCKED) == SHARE_FL_VACB_LOCKED);
    }

    KeReleaseSpinLock(&SharedMap->ActiveVacbSpinLock, OldIrql);
}

VOID
NTAPI
CcSetActiveVacb(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _Inout_ PVACB* OutVacb,
    _In_ ULONG ActivePage,
    _In_ BOOLEAN IsVacbLocked)
{
    KIRQL OldIrql;

    DPRINT("CcSetActiveVacb: %p, %p, %X, %X\n", SharedMap, *OutVacb, ActivePage, IsVacbLocked);

    if (IsVacbLocked)
    {
        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
        KeAcquireSpinLockAtDpcLevel(&SharedMap->ActiveVacbSpinLock);
    }
    else
    {
        KeAcquireSpinLock(&SharedMap->ActiveVacbSpinLock, &OldIrql);
    }

    DPRINT("CcSetActiveVacb: ActiveVacb %p\n", SharedMap->ActiveVacb);

    if (SharedMap->ActiveVacb)
        goto Exit;

    if (IsVacbLocked == ((SharedMap->Flags & SHARE_FL_VACB_LOCKED) != 0))
    {
        SharedMap->ActiveVacb = *OutVacb;
        SharedMap->ActivePage = ActivePage;

        *OutVacb = NULL;
        goto Exit;
    }

    if (!IsVacbLocked)
       goto Exit;

    SharedMap->ActiveVacb = *OutVacb;
    SharedMap->ActivePage = ActivePage;

    *OutVacb = NULL;

    SharedMap->Flags |= SHARE_FL_VACB_LOCKED;

    CcTotalDirtyPages++;
    SharedMap->DirtyPages++;

    if (SharedMap->DirtyPages != 1)
       goto Exit;

    RemoveEntryList(&SharedMap->SharedCacheMapLinks);
    InsertTailList(&CcDirtySharedCacheMapList.SharedCacheMapLinks, &SharedMap->SharedCacheMapLinks);

    if (!LazyWriter.ScanActive)
    {
        LazyWriter.ScanActive = 1;

        KeReleaseSpinLockFromDpcLevel(&SharedMap->ActiveVacbSpinLock);
        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
        KeSetTimer(&LazyWriter.ScanTimer, CcFirstDelay, &LazyWriter.ScanDpc);

        return;
    }

Exit:

    if (IsVacbLocked)
    {
        KeReleaseSpinLockFromDpcLevel(&SharedMap->ActiveVacbSpinLock);
        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
    }
    else
    {
        KeReleaseSpinLock(&SharedMap->ActiveVacbSpinLock, OldIrql);
    }

    if (*OutVacb)
        CcFreeActiveVacb(SharedMap, *OutVacb, ActivePage, IsVacbLocked);
}

VOID
NTAPI
CcFreeActiveVacb(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ PVACB Vacb,
    _In_ ULONG ActivePage,
    _In_ BOOLEAN IsVacbLocked)
{
    PVOID NeedToZero;
    PVACB NeedToZeroVacb;
    LARGE_INTEGER Offset;
    ULONG Size;
    KIRQL OldIrql;

    DPRINT("CcFreeActiveVacb: %p, %X, %X, %X\n", SharedMap, Vacb, ActivePage, IsVacbLocked);

    if (SharedMap->NeedToZero)
    {
        KeAcquireSpinLock(&SharedMap->ActiveVacbSpinLock, &OldIrql);
        NeedToZero = SharedMap->NeedToZero;

        if (NeedToZero)
        {
            Size = (PAGE_SIZE - ((((ULONG_PTR)NeedToZero - 1) & (PAGE_SIZE - 1)) + 1));
            RtlZeroMemory(NeedToZero, Size);

            NeedToZeroVacb = SharedMap->NeedToZeroVacb;
            ASSERT(NeedToZeroVacb != NULL);

            SharedMap->NeedToZero = NULL;
        }
        else
        {
            NeedToZeroVacb = Vacb;
        }

        KeReleaseSpinLock(&SharedMap->ActiveVacbSpinLock, OldIrql);

        if (NeedToZero)
        {
            DPRINT("CcFreeActiveVacb: FIXME MmUnlockCachedPage\n");
            ASSERT(FALSE);
        }
    }

    if (!Vacb)
        return;

    if (!IsVacbLocked)
    {
        CcFreeVirtualAddress(Vacb);
        return;
    }

    Offset.QuadPart = (ActivePage * PAGE_SIZE);
    CcSetDirtyInMask(SharedMap, &Offset, PAGE_SIZE);

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
    KeAcquireSpinLockAtDpcLevel(&SharedMap->ActiveVacbSpinLock);

    if (!SharedMap->ActiveVacb && (SharedMap->Flags & SHARE_FL_VACB_LOCKED))
    {
        SharedMap->Flags &= ~SHARE_FL_VACB_LOCKED;

        CcTotalDirtyPages--;
        SharedMap->DirtyPages--;
    }

    KeReleaseSpinLockFromDpcLevel(&SharedMap->ActiveVacbSpinLock);
    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    CcFreeVirtualAddress(Vacb);
}

VOID
NTAPI
CcCalculateVacbLevelLockCount(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ PVACB* Vacbs,
    _In_ ULONG Level)
{
    PCC_VACB_REFERENCE VacbReference;
    PVACB* vacbs = Vacbs;
    PVACB Vacb;
    PCC_BCB Bcb;
    PLIST_ENTRY Entry;
    LONG Reference = 0;
    ULONG ix;

    DPRINT("CcCalculateVacbLevelLockCount: SharedMap %p, Vacbs %p, Level %X\n", SharedMap, Vacbs, Level);

    for (ix = 0x80; ix; ix--)
    {
        Vacb = *vacbs;
        if (Vacb)
            Reference++;

        vacbs++;
    }

    if (!(SharedMap->Flags & SHARE_FL_MODIFIED_NO_WRITE) || Level)
        goto Exit;

    Entry = (PLIST_ENTRY)vacbs;
    Bcb = CONTAINING_RECORD(Entry->Blink, CC_BCB, Link);

    ix = 0;
    do
    {
        if (Bcb->NodeTypeCode == NODE_TYPE_BCB)
            Reference++;
        else
            ix++;

        Bcb = CONTAINING_RECORD(Bcb->Link.Blink, CC_BCB, Link);
    }
    while (ix <= 0x3F);

Exit:

    VacbReference = VacbLevelReference(SharedMap, Vacbs, Level);
    VacbReference->Reference = Reference;
}

NTSTATUS
NTAPI
CcExtendVacbArray(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ LARGE_INTEGER AllocationSize)
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PVACB* OldVacbs;
    PVACB* NewVacbs;
    PVACB* Vacbs;
    PLIST_ENTRY HeadList;
    PLIST_ENTRY OldEntry;
    PLIST_ENTRY BcbEntry;
    LARGE_INTEGER SectionNewSize;
    LARGE_INTEGER Size;
    ULONG AllocSize;
    ULONG NewVacbsSize;
    ULONG OldVacbsSize;
    ULONG Bits;
    ULONG Level;
    ULONG NewLevel;
    BOOLEAN IsExtendSection = FALSE;
    BOOLEAN IsBcbList = FALSE;

    DPRINT("CcExtendVacbArray: SharedMap %p, AllocationSize %I64X\n", SharedMap, AllocationSize.QuadPart);

    if ((ULONGLONG)AllocationSize.QuadPart >= (16ull * _1TB)) // 0x00001000 00000000
    {
        DPRINT1("CcExtendVacbArray: STATUS_SECTION_TOO_BIG\n");
        return STATUS_SECTION_TOO_BIG;
    }

    if ((SharedMap->Flags & SHARE_FL_MODIFIED_NO_WRITE) && AllocationSize.QuadPart > 0x200000)
        IsBcbList = TRUE;

    DPRINT("CcExtendVacbArray: SectionSize %I64X, IsBcbList %X\n", SharedMap->SectionSize.QuadPart, IsBcbList);

    if (AllocationSize.QuadPart <= SharedMap->SectionSize.QuadPart)
        return STATUS_SUCCESS;

    if (SharedMap->SectionSize.QuadPart < CACHE_OVERALL_SIZE)
    {
        if (AllocationSize.QuadPart >= CACHE_OVERALL_SIZE)
        {
            SectionNewSize.QuadPart = CACHE_OVERALL_SIZE;
            IsExtendSection = TRUE;
        }
        else
        {
            SectionNewSize.QuadPart = AllocationSize.QuadPart;
        }

        if (SectionNewSize.HighPart)
            NewVacbsSize = 0xFFFFFFFF;
        else if (SectionNewSize.LowPart <= CC_VACBS_DEFAULT_MAPPING_SIZE)
            NewVacbsSize = (CC_DEFAULT_NUMBER_OF_VACBS * sizeof(PVACB));
        else
            NewVacbsSize = ((SectionNewSize.LowPart / VACB_MAPPING_GRANULARITY) * sizeof(PVACB));

        if (SharedMap->SectionSize.HighPart)
            OldVacbsSize = 0xFFFFFFFF;
        else if (SharedMap->SectionSize.LowPart <= CC_VACBS_DEFAULT_MAPPING_SIZE)
            OldVacbsSize = (CC_DEFAULT_NUMBER_OF_VACBS * sizeof(PVACB));
        else
            OldVacbsSize = ((SharedMap->SectionSize.LowPart / VACB_MAPPING_GRANULARITY) * sizeof(PVACB));

        if (NewVacbsSize > OldVacbsSize)
        {
            KIRQL OldIrql;

            AllocSize = NewVacbsSize;

            if (IsBcbList)
            {
                /* Add size for BcbLists */
                AllocSize += ((AllocSize + (sizeof(LIST_ENTRY) - 1)) & ~(sizeof(LIST_ENTRY) - 1));
                DPRINT("CcExtendVacbArray: NewVacbsSize %X, AllocSize %X\n", NewVacbsSize, AllocSize);
            }

            if (IsExtendSection)
                AllocSize += sizeof(LIST_ENTRY);

            NewVacbs = ExAllocatePoolWithTag(NonPagedPool, AllocSize, 'pVcC');
            if (!NewVacbs)
            {
                DPRINT1("CcExtendVacbArray: STATUS_INSUFFICIENT_RESOURCES\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            if (IsBcbList)
            {
                KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, &LockHandle);
                KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
            }
            else
            {
                OldIrql = KeAcquireQueuedSpinLock(LockQueueVacbLock);
            }

            if (SharedMap->Vacbs)
                memcpy(NewVacbs, SharedMap->Vacbs, OldVacbsSize);
            else
                OldVacbsSize = 0;

            RtlZeroMemory(Add2Ptr(NewVacbs, OldVacbsSize), (NewVacbsSize - OldVacbsSize));

            if (IsExtendSection)
            {
                AllocSize -= sizeof(LIST_ENTRY);
                RtlZeroMemory((PVOID)((ULONG_PTR)NewVacbs + AllocSize), sizeof(LIST_ENTRY));
            }

            if (IsBcbList)
            {
                Size.QuadPart = 0;
                BcbEntry = Add2Ptr(NewVacbs, NewVacbsSize);

                if (SharedMap->SectionSize.QuadPart > 0x200000 && SharedMap->Vacbs)
                {
                    OldEntry = Add2Ptr(SharedMap->Vacbs, OldVacbsSize);

                    while (Size.QuadPart < SharedMap->SectionSize.QuadPart)
                    {
                        HeadList = OldEntry->Flink;

                        RemoveEntryList(OldEntry);
                        InsertTailList(HeadList, BcbEntry);

                        Size.QuadPart += BCB_MAPPING_GRANULARITY;
                        OldEntry++;
                        BcbEntry++;
                    }
                }
                else
                {
                    PCC_BCB Bcb;

                    for (HeadList = SharedMap->BcbList.Blink;
                         HeadList != &SharedMap->BcbList;
                         HeadList = HeadList->Blink)
                    {
                        while (TRUE)
                        {
                            Bcb = CONTAINING_RECORD(HeadList, CC_BCB, Link);

                            if (Size.QuadPart > Bcb->FileOffset.QuadPart)
                                break;

                            InsertHeadList(HeadList, BcbEntry);

                            Size.QuadPart += BCB_MAPPING_GRANULARITY;
                            BcbEntry++;
                        }
                    }
                }

                while (Size.QuadPart < SectionNewSize.QuadPart)
                {
                    InsertHeadList(&SharedMap->BcbList, BcbEntry);
                    Size.QuadPart += BCB_MAPPING_GRANULARITY;
                    BcbEntry++;
                }
            }

            OldVacbs = SharedMap->Vacbs;
            SharedMap->Vacbs = NewVacbs;
            SharedMap->SectionSize.QuadPart = SectionNewSize.QuadPart;

            if (IsBcbList)
            {
                KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
                KeReleaseInStackQueuedSpinLock(&LockHandle);
            }
            else
            {
                KeReleaseQueuedSpinLock(LockQueueVacbLock, OldIrql);
            }

            if (OldVacbs != SharedMap->InitialVacbs && OldVacbs)
                ExFreePool(OldVacbs);
        }

        SharedMap->SectionSize.QuadPart = SectionNewSize.QuadPart;
    }

    if (AllocationSize.QuadPart <= SharedMap->SectionSize.QuadPart)
        return STATUS_SUCCESS;

    Level = 1;

    for (Bits = (VACB_OFFSET_SHIFT + VACB_LEVEL_SHIFT); ; Bits += VACB_LEVEL_SHIFT)
    {
        if ((1LL << Bits) >= SharedMap->SectionSize.QuadPart)
            break;

        Level++;
    }

    NewLevel = Level;

    while ((AllocationSize.QuadPart - 1) >> Bits)
    {
        NewLevel++;
        Bits += VACB_LEVEL_SHIFT;
    }

    if (NewLevel <= Level)
        goto Exit;

    if (NewLevel >= CcMaxVacbLevelsSeen)
    {
        ASSERT(NewLevel <= VACB_NUMBER_OF_LEVELS);
        CcMaxVacbLevelsSeen = (NewLevel + 1);
    }

    if (!CcPrefillVacbLevelZone((NewLevel - Level), &LockHandle, FALSE, IsBcbList, SharedMap))
    {
        DPRINT1("CcExtendVacbArray: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (Level == 1)
        CcCalculateVacbLevelLockCount(SharedMap, SharedMap->Vacbs, 0);

    if (IsVacbLevelReferenced(SharedMap, SharedMap->Vacbs, (Level - 1)))
    {
        while (NewLevel > Level)
        {
            ASSERT(CcVacbLevelEntries != 0);
            Vacbs = (PVACB *)CcAllocateVacbLevel(FALSE);

            Vacbs[0] = (PVACB)SharedMap->Vacbs;

            Level++;
            ReferenceVacbLevel(SharedMap, Vacbs, Level, 1, FALSE);

            SharedMap->Vacbs = Vacbs;
        }

        SharedMap->SectionSize.QuadPart = AllocationSize.QuadPart;

        if (IsBcbList)
        {
            KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
            KeReleaseInStackQueuedSpinLock(&LockHandle);
        }
        else
        {
            KeReleaseQueuedSpinLock(LockQueueVacbLock, LockHandle.OldIrql);
        }

        goto Exit;
    }

    if (Level == 1 && (SharedMap->Flags & SHARE_FL_MODIFIED_NO_WRITE))
    {
        DPRINT1("CcExtendVacbArray: FIXME\n");
        ASSERT(FALSE);
    }

    SharedMap->SectionSize.QuadPart = AllocationSize.QuadPart;

    if (IsBcbList)
    {
        KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
        KeReleaseInStackQueuedSpinLock(&LockHandle);
    }
    else
    {
        KeReleaseQueuedSpinLock(LockQueueVacbLock, LockHandle.OldIrql);
    }

Exit:

    SharedMap->SectionSize.QuadPart = AllocationSize.QuadPart;

    return STATUS_SUCCESS;
}

VOID
NTAPI
CcAdjustVacbLevelLockCount(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ LONGLONG FileOffset,
    _In_ LONG AdjustLevel)
{
    PCC_VACB_REFERENCE VacbReference;
    PVACB* Vacbs = SharedMap->Vacbs;
    LONGLONG fileOffset = FileOffset;
    ULONG Level = 0;
    ULONG Bits;

    DPRINT("CcAdjustVacbLevelLockCount: SharedMap %p, FileOffset %I64X\n", SharedMap, FileOffset);

    ASSERT(SharedMap->SectionSize.QuadPart > CACHE_OVERALL_SIZE);

    Bits = (VACB_OFFSET_SHIFT + VACB_LEVEL_SHIFT);

    do
    {
        Level++;
        Bits += VACB_LEVEL_SHIFT;
    }
    while ((1LL << Bits) < SharedMap->SectionSize.QuadPart);

    Bits -= VACB_LEVEL_SHIFT;

    do
    {
        Vacbs = (PVACB *)Vacbs[FileOffset >> Bits];

        FileOffset &= ((1LL << Bits) - 1);

        Bits -= VACB_LEVEL_SHIFT;
        Level--;
    }
    while (Level);

    ReferenceVacbLevel(SharedMap, Vacbs, 0, AdjustLevel, FALSE);

    if (IsVacbLevelReferenced(SharedMap, Vacbs, 0))
        return;

    VacbReference = VacbLevelReference(SharedMap, Vacbs, 0);
    VacbReference->SpecialReference++;

    fileOffset = (fileOffset & ~(CACHE_OVERALL_SIZE - 1));

    CcSetVacbLargeOffset(SharedMap, fileOffset, VACB_SPECIAL_DEREFERENCE);
}

/* EOF */
