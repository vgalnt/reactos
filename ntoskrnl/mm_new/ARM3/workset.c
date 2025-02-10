
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>
#include "miarm.h"

/* GLOBALS ********************************************************************/

#if (_MI_PAGING_LEVELS == 2)
  ULONG MiMaximumWorkingSet = ((ULONG_PTR)MI_USER_PROBE_ADDRESS / PAGE_SIZE);
#else
 #error FIXME
#endif

SIZE_T MmMinimumWorkingSetSize = 0x14;
SIZE_T MmMaximumWorkingSetSize;
SIZE_T MmPagesAboveWsMinimum;

ULONG MmPagedPoolPage;
ULONG MmSystemCachePage;
ULONG MmSystemCodePage;
ULONG MmSystemDriverPage;

ULONG MmNumberOfInserts;

extern PVOID MmHyperSpaceEnd;
extern LIST_ENTRY MmWorkingSetExpansionHead;
extern ULONG MmTransitionSharedPages;
extern ULONG MmTransitionSharedPagesPeak;
extern PVOID MmSystemCacheStart;
extern PVOID MmSystemCacheEnd;
extern PMMWSL MmSystemCacheWorkingSetList;
extern PMMWSLE MmSystemCacheWsle;
extern PMM_SESSION_SPACE MmSessionSpace;
extern PVOID MmPagedPoolStart;
extern PVOID MmPagedPoolEnd;
extern PVOID MmSpecialPoolStart;
extern PVOID MmSpecialPoolEnd;
extern ULONG MmStandbyRePurposed;

/* FUNCTIONS ******************************************************************/

BOOLEAN
NTAPI
MiEliminateWorkingSetEntry(
    _In_ ULONG WsIndex,
    _In_ PMMPTE Pte,
    _In_ PMMPFN InPfn,
    _In_ PMMSUPPORT WorkSet,
    _In_ BOOLEAN IsNotCheckRefs)
{
    PEPROCESS Process;
    PMMWSLE Wsle;
    PMMPDE Pde;
    PMMPFN Pfn;
    MMWSLE WsleContents;
    MMPTE TempPte;
    MMPTE OldPteContents;
    PFN_NUMBER PdeFrameNumber;
    PFN_NUMBER PteFrameNumber;
    KIRQL OldIrql;
    BOOLEAN AllProcesors;

    DPRINT("MiEliminateWorkingSetEntry: %X, %p [%X], %p, %p, %X\n", WsIndex, Pte, *Pte, InPfn, WorkSet, IsNotCheckRefs);

    Wsle = WorkSet->VmWorkingSetList->Wsle;
    WsleContents.u1.Long = Wsle[WsIndex].u1.Long;

    AllProcesors = (Wsle != (PMMWSLE)&MmWorkingSetList[1]);

    TempPte.u.Long = Pte->u.Long;
    ASSERT(TempPte.u.Hard.Valid == 1);
    PteFrameNumber = TempPte.u.Hard.PageFrameNumber;

    ASSERT(InPfn == MI_PFN_ELEMENT(PteFrameNumber));
    ASSERT(MI_IS_PFN_DELETED(InPfn) == 0);

  #if !defined(ONE_CPU)
    if (TempPte.u.Hard.Writable)
    {
        ASSERT(TempPte.u.Hard.Dirty == 1);
    }
  #endif

    if (InPfn->u3.e1.PrototypePte)
    {
        if (WsleContents.u1.e1.Protection != MM_ZERO_ACCESS)
        {
            TempPte.u.Long = 0;
            TempPte.u.Soft.Prototype = 1;
            TempPte.u.Soft.Protection = WsleContents.u1.e1.Protection;
            TempPte.u.Soft.PageFileHigh = MI_PTE_LOOKUP_NEEDED;
        }
        else
        {
            MI_MAKE_PROTOTYPE_PTE(&TempPte, InPfn->PteAddress);
        }

        Pde = MiAddressToPte(Pte);
        if (!Pde->u.Hard.Valid && !NT_SUCCESS(MiCheckPdeForPagedPool(Pte)))
        {
            DPRINT1("MiEliminateWorkingSetEntry: KeBugCheckEx()\n");
            ASSERT(FALSE);
            KeBugCheckEx(0x1A, 0x61940, (ULONG_PTR)Pte, Pde->u.Long, (ULONG_PTR)MiPteToAddress(Pte));
        }

        PdeFrameNumber = Pde->u.Hard.PageFrameNumber;
        Pfn = MI_PFN_ELEMENT(PdeFrameNumber);
    }
    else
    {
        ASSERT((InPfn->u2.ShareCount == 1) || (WsleContents.u1.VirtualAddress > (PVOID)MM_HIGHEST_USER_ADDRESS));

        TempPte.u.Soft.Valid = 0;
        TempPte.u.Soft.Prototype = 0;
        TempPte.u.Soft.Transition = 1;
        TempPte.u.Soft.Protection = InPfn->OriginalPte.u.Soft.Protection;

        PdeFrameNumber = 0;
        Pfn = NULL;
    }

    OldIrql = MiLockPfnDb(APC_LEVEL);

    if (!IsNotCheckRefs)
    {
        if (WorkSet != &MmSystemCacheWs)
        {
            if (InPfn->u2.ShareCount > 1 && !InPfn->u3.e1.PrototypePte)
            {
                if (WorkSet->Flags.SessionSpace)
                {
                    ASSERT(MI_IS_SESSION_ADDRESS(WsleContents.u1.VirtualAddress));
                }
                else
                {
                    ASSERT((WsleContents.u1.VirtualAddress >= (PVOID)0xC0000000) &&
                           (WsleContents.u1.VirtualAddress <= (PVOID)0xC03FFFFF));
                }

                MiUnlockPfnDb(OldIrql, APC_LEVEL);
                return FALSE;
            }
        }
        else if (InPfn->u3.ReferenceCount > 1)
        {
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            return FALSE;
        }
    }

    if (InPfn->u3.e1.PrototypePte)
    {
        MiDecrementPfnShare(Pfn, PdeFrameNumber);
    }
    else
    {
        ASSERT(InPfn->u1.WsIndex != 0);
        InPfn->u1.WsIndex = 0;
    }

    OldPteContents = *Pte;
    ASSERT(OldPteContents.u.Hard.Valid == 1);
    MI_WRITE_INVALID_PTE(Pte, TempPte);

    KeFlushSingleTb(WsleContents.u1.VirtualAddress, AllProcesors);

    ASSERT(KeGetCurrentIrql() > APC_LEVEL);

    if (!InPfn->u3.e1.Modified && OldPteContents.u.Hard.Dirty)
    {
        ASSERT(InPfn->u3.e1.Rom == 0);
        InPfn->u3.e1.Modified = 1;

        if (!InPfn->OriginalPte.u.Soft.Prototype && !InPfn->u3.e1.WriteInProgress)
        {
            MiReleasePageFileSpace(InPfn->OriginalPte);
            InPfn->OriginalPte.u.Soft.PageFileHigh = 0;
        }
    }

    if (!InPfn->u3.e1.PrototypePte && OldPteContents.u.Hard.Dirty)
    {
        Process = PsGetCurrentProcess();

        if (Process->Flags & 0x8000)
        {
            DPRINT1("MiEliminateWorkingSetEntry: FIXME\n");
            ASSERT(FALSE);
            //MiCaptureWriteWatchDirtyBit(Process, MiPteToAddress(Pte));
        }
    }

    MiDecrementPfnShare(InPfn, PteFrameNumber);
    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    return TRUE;
}

ULONG
NTAPI
MiFreeWsle(
    IN ULONG WsIndex,
    IN PMMSUPPORT WorkSet,
    IN PMMPTE Pte)
{
    DPRINT1("MiFreeWsle: WsIndex %p, WorkSet %p, Pte %p\n", WsIndex, WorkSet, Pte);
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

VOID
NTAPI
MiDoReplacement(
    _In_ PMMSUPPORT WorkSet,
    _In_ ULONG InFlags)
{
    PMMWSL WsList;
    ULONG TrimmedCount = 0;
    ULONG Growth = 1;
    ULONG flags = (InFlags & ~2);
    KIRQL OldIrql;

    DPRINT("MiDoReplacement: WorkSet %p, InFlags %X\n", WorkSet, InFlags);

    if (WorkSet->WorkingSetSize < WorkSet->MinimumWorkingSetSize)
    {
        goto Exit;
    }

    WsList = WorkSet->VmWorkingSetList;

    while (WorkSet->Flags.ForceTrim && InFlags != 2)
    {
        DPRINT1("MiDoReplacement: FIXME\n");
        ASSERT(FALSE);
    }

    ASSERT(WorkSet->WorkingSetSize <= (WsList->LastInitializedWsle + 1));

    if (WorkSet->Flags.MaximumWorkingSetHard &&
        WorkSet->WorkingSetSize >= WorkSet->MaximumWorkingSetSize)
    {
        DPRINT1("MiDoReplacement: FIXME MiReplaceWorkingSetEntry()\n");
        ASSERT(FALSE);
        return;
    }

    if (flags != 1)
    {
        if (MmAvailablePages >= 10000)
            goto Exit;

        if (MmAvailablePages)
        {
            if (WorkSet->GrowthSinceLastEstimate <= (((0x1E * MmAvailablePages * MmAvailablePages) / 0x1000) + 1))
                goto Exit;

            if (PsGetCurrentThread()->MemoryMaker)
                goto Exit;
        }
    }
   
    //MiReplacing = 1;

    if (flags != 1 && PsGetCurrentThread()->MemoryMaker)
    {
        if (TrimmedCount > 1)
        {
            OldIrql = MiAcquireExpansionLock();
            WorkSet->Flags.ForceTrim = 1;
            MiReleaseExpansionLock(OldIrql);
        }

        goto Exit;
    }

    DPRINT1("MiDoReplacement: FIXME MiReplaceWorkingSetEntry()\n");
    ASSERT(FALSE);

    Growth = 0;

Exit:

    WorkSet->GrowthSinceLastEstimate += Growth;
}

VOID
NTAPI
MiCheckWsleHash(
    _In_ PMMWSL WsList)
{
    PMMWSLE Wsle;
    PMMWSLE_HASH Table;
    ULONG Count = 0;
    ULONG ix;

    Wsle = WsList->Wsle;

    for (ix = 0; ix < WsList->HashTableSize; ix++)
    {
        Table = WsList->HashTable;
        if (!Table[ix].Key)
            continue;

        Count++;

        ASSERT(Table[ix].Key == (PVOID)(Wsle[Table[ix].Index].u1.Long & (0xFFFFF000 | 1)));
    }

    if (Count > WsList->NonDirectCount)
    {
        DPRINT1("MiCheckWsleHash: Count %X, NonDirectCount %X\n", Count, WsList->NonDirectCount);
        DbgBreakPoint();
    }
}

VOID
FASTCALL
MiInsertWsleHash(
    _In_ ULONG InWsIndex,
    _In_ PMMSUPPORT WorkSet)
{
    PMMWSL WsList;
    PMMWSLE Wsle;
    MMWSLE WsleContents;
    PMMWSLE_HASH Table;
    PMMWSLE_HASH TableEnd;
    PMMWSLE_HASH HashEntry;
    PMMWSLE_HASH OldHashEntry = NULL;
    ULONG Count;
    ULONG HashIndex;
    ULONG WsIndex;
    ULONG OldWsIndex;
    ULONG Accessed = 0;
    ULONG Tries = 0;
    ULONG ix;
    BOOLEAN FindOldEntry = TRUE;

    WsList = WorkSet->VmWorkingSetList;
    Wsle = WsList->Wsle;

    DPRINT("MiInsertWsleHash: %X, %p, %p, %p\n", InWsIndex, WorkSet, WsList, Wsle);

    ASSERT(Wsle[InWsIndex].u1.e1.Valid == 1);
    ASSERT(Wsle[InWsIndex].u1.e1.Direct != 1);
    ASSERT(Wsle[InWsIndex].u1.e1.Hashed == 0);

    if (!WsList->HashTable)
        return;

    MmNumberOfInserts++;

    Count = WsList->HashTableSize;
    HashIndex = ((Wsle[InWsIndex].u1.e1.VirtualPageNumber * 4) % (Count - 1));

    Table = WsList->HashTable;
    TableEnd = &Table[Count];

    if (Count < (WsList->NonDirectCount + (Count / 16) + 10))
    {
        if ((PVOID)&TableEnd[0x400] <= WsList->HighestPermittedHashAddress)
            WorkSet->Flags.GrowWsleHash = 1;

        if (Count < WsList->NonDirectCount + (Count / 16))
        {
            if (Count < 16)
                ix = Count;
            else
                ix = 16;

            WsleContents.u1.Long = 0;

            HashEntry = &Table[HashIndex];
            if (!HashEntry->Key)
                goto Finish;

            /* Looking for the oldest hash entry */

            while (TRUE)
            {
                WsIndex = HashEntry->Index;

                ASSERT(Wsle[WsIndex].u1.e1.Direct == 0);
                ASSERT(Wsle[WsIndex].u1.e1.Valid == 1);

                ASSERT(HashEntry->Key == (PVOID)(Wsle[WsIndex].u1.Long & (0xFFFFF000 | 1)));

                if (!OldHashEntry)
                {
                    WsleContents.u1.Long = Wsle[WsIndex].u1.Long;
                    Accessed = (MiAddressToPte(HashEntry->Key))->u.Hard.Accessed;

                    if (WsIndex < WsList->FirstDynamic)
                        FindOldEntry = FALSE;

                    OldHashEntry = HashEntry;
                }
                else if (WsIndex < WsList->FirstDynamic)
                {
                    ;
                }
                else if (!FindOldEntry)
                {
                    WsleContents.u1.Long = Wsle[WsIndex].u1.Long;
                    Accessed = (MiAddressToPte(HashEntry->Key))->u.Hard.Accessed;

                    FindOldEntry = TRUE;
                    OldHashEntry = HashEntry;
                }
                else if (Wsle[WsIndex].u1.e1.Age > WsleContents.u1.e1.Age)
                {
                    WsleContents.u1.Long = Wsle[WsIndex].u1.Long;
                    Accessed = (MiAddressToPte(HashEntry->Key))->u.Hard.Accessed;

                    FindOldEntry = TRUE;
                    OldHashEntry = HashEntry;
                }
                else if (Wsle[WsIndex].u1.e1.Age == WsleContents.u1.e1.Age &&
                         Accessed &&
                         !(MiAddressToPte(HashEntry->Key)->u.Hard.Accessed))
                {
                    WsleContents.u1.Long = Wsle[WsIndex].u1.Long;
                    Accessed = 0;

                    FindOldEntry = TRUE;
                    OldHashEntry = HashEntry;
                }

                ix--;
                if (!ix)
                {
                    OldWsIndex = OldHashEntry->Index;

                    if (FindOldEntry)
                    {
                        if (MiFreeWsle(OldWsIndex, WorkSet, MiAddressToPte(OldHashEntry->Key)))
                        {
                            HashEntry = OldHashEntry;
                            ASSERT(HashEntry->Key == 0);
                        }
                        else
                        {
                            ASSERT(Wsle[OldWsIndex].u1.e1.Hashed == 1);
                            Wsle[OldWsIndex].u1.e1.Hashed = 0;

                            HashEntry = OldHashEntry;
                            OldHashEntry->Key = 0;
                        }
                    }

                    goto Finish;
                }

                HashEntry++;

                if (HashEntry >= TableEnd)
                {
                    HashEntry = Table;

                    ASSERT(Tries == 0);
                    Tries = 1;
                }

                if (!HashEntry->Key)
                    goto Finish;
            }
        }
    }

    Tries = 0;
    HashEntry = &Table[HashIndex];

    while (HashEntry->Key)
    {
        HashEntry++;

        if (HashEntry >= TableEnd)
        {
            HashEntry = &Table[0];

            ASSERT(Tries == 0);
            Tries = 1;
        }

        if (HashEntry == &Table[HashIndex])
        {
            ASSERT(Wsle[InWsIndex].u1.e1.Hashed == 0);
            return;
        }
    }

Finish:

    ASSERT(HashEntry->Key == 0);
    ASSERT(HashEntry < TableEnd);

    Wsle[InWsIndex].u1.e1.Hashed = 1;

    HashEntry->Key = (PVOID)(Wsle[InWsIndex].u1.Long & (0xFFFFF000 | 1));
    HashEntry->Index = InWsIndex;

    if (!(MmNumberOfInserts % 1000))
        MiCheckWsleHash(WsList);

    return;
}

VOID
NTAPI
MiRemoveWsleFromFreeList(
    _In_ ULONG WsIndex,
    _In_ PMMWSLE Wsle,
    _In_ PMMWSL WsList)
{
    ULONG CurrentIdx;
    ULONG PreviosIdx;
    ULONG Idx;

    DPRINT("MiRemoveWsleFromFreeList: %X, %p, %p\n", WsIndex, Wsle, WsList);

    if (WsIndex == WsList->FirstFree)
    {
        ASSERT(((Wsle[WsIndex].u1.Long >> MM_FREE_WSLE_SHIFT) <= WsList->LastInitializedWsle) ||
               ((Wsle[WsIndex].u1.Long >> MM_FREE_WSLE_SHIFT) == WSLE_NULL_INDEX));

        WsList->FirstFree = Wsle[WsIndex].u1.Long >> MM_FREE_WSLE_SHIFT;
        goto Exit;
    }

    if (WsIndex && Wsle[WsIndex - 1].u1.e1.Valid)
    {
        if ((Wsle[WsIndex - 1].u1.Long >> MM_FREE_WSLE_SHIFT) != WsIndex)
        {
            Idx = -1;
        }
        else
        {
            Idx = (WsIndex - 1);
        }
    }
    else if (WsIndex == WsList->LastInitializedWsle)
    {
        Idx = -1;
    }
    else if (Wsle[WsIndex + 1].u1.e1.Valid)
    {
        Idx = -1;
    }
    else if ((Wsle[WsIndex + 1].u1.Long >> MM_FREE_WSLE_SHIFT) != WsIndex)
    {
        Idx = -1;
    }
    else
    {
        Idx = (WsIndex + 1);
    }

    if (Idx != -1)
    {
        Wsle[Idx].u1.Long = Wsle[WsIndex].u1.Long;
        goto Exit;
    }

    CurrentIdx = WsList->FirstFree;
    while (CurrentIdx != WsIndex)
    {
        PreviosIdx = CurrentIdx;
        ASSERT(Wsle[CurrentIdx].u1.e1.Valid == 0);
        CurrentIdx = Wsle[CurrentIdx].u1.Long >> MM_FREE_WSLE_SHIFT;
    }

    Wsle[PreviosIdx].u1.Long = Wsle[WsIndex].u1.Long;

Exit:

    ASSERT((WsList->FirstFree <= WsList->LastInitializedWsle) ||
           (WsList->FirstFree == WSLE_NULL_INDEX));
}

VOID
NTAPI
MiRepointWsleHashIndex(
    MMWSLE WsleEntry,
    PMMWSL WsList,
    ULONG WsIndex)
{
    PMMWSLE_HASH Table;
    ULONG HashIndex;
    ULONG StartIndex;
    LONG Tries = 0;

    Table = WsList->HashTable;

    DPRINT("MiRepointWsleHashIndex: %X, %p, %X, %p\n", WsleEntry.u1.Long, WsList, WsIndex, Table);

    if (!WsleEntry.u1.e1.Hashed)
    {
        if (Table)
        {
            for (HashIndex = 0; HashIndex < WsList->HashTableSize; HashIndex++)
            {
                ASSERT(Table[HashIndex].Key != (PVOID)(WsleEntry.u1.Long & (0xFFFFF000 | 1)));
            }
        }

        return;
    }

    HashIndex = StartIndex = ((WsleEntry.u1.e1.VirtualPageNumber * 4) % (WsList->HashTableSize - 1));

    while (Table[HashIndex].Key != (PVOID)(WsleEntry.u1.Long & (0xFFFFF000 | 1)))
    {
        HashIndex++;

        if (HashIndex >= WsList->HashTableSize)
        {
            HashIndex = 0;
            ASSERT(Tries == 0);
            Tries = 1;
        }

        if (StartIndex == HashIndex)
            return;
    }

    Table[HashIndex].Index = WsIndex;
}

VOID
NTAPI
MiSwapWslEntries(
    _In_ ULONG WsIndex1,
    _In_ ULONG WsIndex2,
    _In_ PMMSUPPORT WorkSet,
    _In_ BOOLEAN Param4)
{
    PVOID Address;
    PMMPTE Pte;
    PMMPFN Pfn;
    PMMWSL WsList;
    PMMWSLE Wsle;
    PMMWSLE_HASH Table;
    MMWSLE Wsle1;
    MMWSLE Wsle2;
    ULONG Hash;
    NTSTATUS Status;

    DPRINT("MiSwapWslEntries: %X, %X, %p, %X\n", WsIndex1, WsIndex2, WorkSet, Param4);

    WsList = WorkSet->VmWorkingSetList;
    Wsle = WsList->Wsle;
    Table = WsList->HashTable;

    Wsle1 = Wsle[WsIndex1];
    ASSERT(Wsle1.u1.e1.Valid != 0);

    Wsle2 = Wsle[WsIndex2];
    if (!Wsle2.u1.e1.Valid)
    {
        MiRemoveWsleFromFreeList(WsIndex2, Wsle, WsList);

        Wsle[WsIndex2].u1.Long = Wsle1.u1.Long;

        Pte = MiAddressToPte(Wsle1.u1.VirtualAddress);
        if (!(Pte->u.Hard.Valid))
        {
            Status = MiCheckPdeForPagedPool(Wsle1.u1.VirtualAddress);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("KeBugCheckEx()\n");
                ASSERT(FALSE);
            }

            ASSERT(Pte->u.Hard.Valid == 1);
        }

        if (Wsle1.u1.e1.Direct)
        {
            Pfn = MI_PFN_ELEMENT(Pte->u.Hard.PageFrameNumber);
            ASSERT(Pfn->u1.WsIndex == WsIndex1);
            Pfn->u1.WsIndex = WsIndex2;
        }
        else if (Table)
        {
            MiRepointWsleHashIndex(Wsle1, WsList, WsIndex2);
        }

        ASSERT((WsList->FirstFree <= WsList->LastInitializedWsle) || (WsList->FirstFree == WSLE_NULL_INDEX));

        Wsle[WsIndex1].u1.Long = (WsList->FirstFree << MM_FREE_WSLE_SHIFT);
        WsList->FirstFree = WsIndex1;

        ASSERT((WsList->FirstFree <= WsList->LastInitializedWsle) || (WsList->FirstFree == WSLE_NULL_INDEX));

        return;
    }

    Wsle[WsIndex1].u1.Long = Wsle2.u1.Long;

    Pte = MiAddressToPte(Wsle2.u1.VirtualAddress);
    if (!Pte->u.Hard.Valid)
    {
        Status = MiCheckPdeForPagedPool(Wsle2.u1.VirtualAddress);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("KeBugCheckEx()\n");
            ASSERT(FALSE);
        }

        ASSERT(Pte->u.Hard.Valid == 1);
    }

    if (Wsle2.u1.e1.Direct)
    {
        Pfn = MI_PFN_ELEMENT(Pte->u.Hard.PageFrameNumber);
        ASSERT(Pfn->u1.WsIndex == WsIndex2);
        Pfn->u1.WsIndex = WsIndex1;
    }
    else if (Table)
    {
        if (Param4)
        {
            Address = (PVOID)(Wsle2.u1.Long & (0xFFFFF000 | 0x1));

            for (Hash = 0; Hash < WsList->HashTableSize; Hash++)
            {
                ASSERT(Table[Hash].Key != Address);
            }
        }
        else
        {
            MiRepointWsleHashIndex(Wsle2, WsList, WsIndex1);
        }
    }

    Wsle[WsIndex2].u1.Long = Wsle1.u1.Long;

    Pte = MiAddressToPte(Wsle1.u1.VirtualAddress);
    if (!Pte->u.Hard.Valid)
    {
        Status = MiCheckPdeForPagedPool(Wsle1.u1.VirtualAddress);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("KeBugCheckEx()\n");
            ASSERT(FALSE);
        }

        ASSERT(Pte->u.Hard.Valid == 1);
    }

    if (Wsle1.u1.e1.Direct)
    {
        Pfn = MI_PFN_ELEMENT(Pte->u.Hard.PageFrameNumber);
        ASSERT(Pfn->u1.WsIndex == WsIndex1);
        Pfn->u1.WsIndex = WsIndex2;
    }
    else if (Table)
    {
        MiRepointWsleHashIndex(Wsle1, WsList, WsIndex2);
    }
}

VOID
NTAPI
MiUpdateWsle(
    _Out_ ULONG* OutWsIndex,
    _In_ PVOID Address,
    _In_ PMMSUPPORT WorkSet,
    _In_ PMMPFN Pfn,
    _In_ MMWSLE InWsle)
{
    PMMWSL WsList;
    PMMWSLE Wsle;
    MMWSLE OldWsle;
    ULONG WsIndex;
    ULONG PfnIndex;
    ULONG FreeIndex = 0;

    DPRINT("MiUpdateWsle: %p, %p, %p, %X, %X\n", OutWsIndex, Address, WorkSet, Pfn, InWsle);

    if (WorkSet == &MmSystemCacheWs)
    {
        ASSERT((PsGetCurrentThread()->OwnsSystemWorkingSetExclusive) ||
               (PsGetCurrentThread()->OwnsSystemWorkingSetShared));
    }
    else if (WorkSet->Flags.SessionSpace)
    {
        ASSERT((PsGetCurrentThread()->OwnsSessionWorkingSetExclusive) ||
               (PsGetCurrentThread()->OwnsSessionWorkingSetShared));
    }
    else
    {
        ASSERT((PsGetCurrentThread()->OwnsProcessWorkingSetExclusive) ||
               (PsGetCurrentThread()->OwnsProcessWorkingSetShared));
    }

    WsList = WorkSet->VmWorkingSetList;
    WsIndex = *OutWsIndex;

    //DPRINT1("MiUpdateWsle: %p, %p, %p, %X, %p, %X\n", Address, WorkSet, Pfn, InWsle, WsList, WsIndex);

    ASSERT(WsIndex >= WsList->FirstDynamic);
    Wsle = WsList->Wsle;

    if (WsList == MmSystemCacheWorkingSetList) // MM_SYSTEM_SPACE_START
    {
        ASSERT((Address < (PVOID)0xC0000000) || (Address >= (PVOID)MmSystemCacheWorkingSetList));

        if (Address >= MmPagedPoolStart && Address <= MmPagedPoolEnd)
        {
            MmPagedPoolPage++;
        }
        else if ((Address >= MmSystemCacheStart && Address <= MmSystemCacheEnd)) // || (Address >= MiSystemCacheStartExtra && Address <= MiSystemCacheEndExtra))
        {
            MmSystemCachePage++;
        }
        else if (Address <= MmSpecialPoolEnd && Address >= MmSpecialPoolStart)
        {
            MmPagedPoolPage++;
        }
        //else if (Address < MiLowestSystemPteVirtualAddress)
        //    MmSystemCodePage++;
        //else
        //    MmSystemDriverPage++;
    }
    else
    {
        ASSERT((Address < (PVOID)MmSystemCacheWorkingSetList) || (MI_IS_SESSION_ADDRESS(Address)));
    }

    if (Pfn->u1.WsIndex <= WsList->LastInitializedWsle)
    {
        ASSERT((PAGE_ALIGN(Address) != PAGE_ALIGN(Wsle[Pfn->u1.WsIndex].u1.VirtualAddress)) ||
               (Wsle[Pfn->u1.WsIndex].u1.e1.Valid == 0));
    }

    if (!Pfn->u1.WsIndex)
    {
        if (!Pfn->u3.e1.PrototypePte)
            Pfn->u1.WsIndex = WsIndex;

        if (!Pfn->u3.e1.PrototypePte || !InterlockedCompareExchange((PLONG)&Pfn->u1.WsIndex, WsIndex, 0))
        {
            Wsle[WsIndex].u1.VirtualAddress = PAGE_ALIGN(Address);
            Wsle[WsIndex].u1.Long |= InWsle.u1.Long;
            Wsle[WsIndex].u1.e1.Valid = 1;
            Wsle[WsIndex].u1.e1.Direct = 1;
            return;
        }
    }

    Wsle[WsIndex].u1.VirtualAddress = PAGE_ALIGN(Address);
    Wsle[WsIndex].u1.e1.Valid = 1;

    PfnIndex = Pfn->u1.WsIndex;

    if (PfnIndex >= WsList->LastInitializedWsle ||
        PfnIndex <= WsList->FirstDynamic ||
        PfnIndex == WsIndex)
    {
        goto Exit;
    }

    if (Wsle[PfnIndex].u1.e1.Valid)
    {
        if (Wsle[PfnIndex].u1.e1.Direct)
        {
            MiSwapWslEntries(PfnIndex, WsIndex, WorkSet, 1);
            WsIndex = PfnIndex;
        }

        goto Exit1;
    }

    ASSERT(WsList->FirstFree >= WsList->FirstDynamic);
    ASSERT(WsIndex >= WsList->FirstDynamic);

    if (WsList->FirstFree == PfnIndex)
    {
        WsList->FirstFree = WsIndex;
        OldWsle.u1.Long = Wsle[WsIndex].u1.Long;
        Wsle[WsIndex].u1.Long = Wsle[PfnIndex].u1.Long;
        Wsle[PfnIndex].u1.Long = OldWsle.u1.Long;

        WsIndex = PfnIndex;

        ASSERT(((Wsle[WsList->FirstFree].u1.Long >> MM_FREE_WSLE_SHIFT) <= WsList->LastInitializedWsle) ||
               ((Wsle[WsList->FirstFree].u1.Long >> MM_FREE_WSLE_SHIFT) == WSLE_NULL_INDEX));

        goto Exit1;
    }

    if (Wsle[PfnIndex - 1].u1.e1.Valid)
    {
        if (!Wsle[PfnIndex + 1].u1.e1.Valid && (Wsle[PfnIndex + 1].u1.Long >> MM_FREE_WSLE_SHIFT) == PfnIndex)
            FreeIndex = (PfnIndex + 1);
    }
    else
    {
        if ((Wsle[PfnIndex - 1].u1.Long >> MM_FREE_WSLE_SHIFT) == PfnIndex)
            FreeIndex = (PfnIndex - 1);
    }

    if (!FreeIndex)
        goto Exit1;

    OldWsle.u1.Long = Wsle[WsIndex].u1.Long;
    Wsle[FreeIndex].u1.Long = WsIndex << MM_FREE_WSLE_SHIFT;
    Wsle[WsIndex].u1.Long = Wsle[PfnIndex].u1.Long;
    Wsle[PfnIndex].u1.Long = OldWsle.u1.Long;

    WsIndex = PfnIndex;

    ASSERT(((Wsle[FreeIndex].u1.Long >> MM_FREE_WSLE_SHIFT) <= WsList->LastInitializedWsle) ||
           ((Wsle[FreeIndex].u1.Long >> MM_FREE_WSLE_SHIFT) == WSLE_NULL_INDEX));

Exit1:

    *OutWsIndex = WsIndex;

    if (WsIndex > WsList->LastEntry)
        WsList->LastEntry = WsIndex;

Exit:

    ASSERT(Wsle[WsIndex].u1.e1.Valid == 1);
    ASSERT(Wsle[WsIndex].u1.e1.Direct != 1);

    Wsle[WsIndex].u1.Long |= InWsle.u1.Long;
    Wsle[WsIndex].u1.e1.Hashed = 0;

    WsList->NonDirectCount++;

    if (WsIndex == Pfn->u1.WsIndex)
        return;

    if (WsList->HashTable)
        MiInsertWsleHash(WsIndex, WorkSet);
}

BOOLEAN
NTAPI
MiAddWorkingSetPage(
    _In_ PMMSUPPORT WorkSet)
{
    PVOID NextWsleArray;
    PMMWSL WsList;
    PMMWSLE Wsle;
    PMMWSLE CurrentWsle;
    PMMPFN Pfn;
    PMMPTE Pte;
    MMPTE TempPte;
    MMWSLE dummy;
    PFN_NUMBER PageFrameNumber;
    ULONG NumberOfEntriesMapped;
    ULONG WsIndex1;
    ULONG WsIndex2;
    ULONG WsIndex;
    ULONG Idx;
    KIRQL OldIrql;

    WsList = WorkSet->VmWorkingSetList;
    Wsle = WsList->Wsle;

    DPRINT("MiAddWorkingSetPage: %p, %p, %p\n", WorkSet, WsList, Wsle);

    if (WorkSet == &MmSystemCacheWs)
    {
        ASSERT((PsGetCurrentThread()->OwnsSystemWorkingSetExclusive) ||
               (PsGetCurrentThread()->OwnsSystemWorkingSetShared));
    }
    else if (WorkSet->Flags.SessionSpace)
    {
        ASSERT((PsGetCurrentThread()->OwnsSessionWorkingSetExclusive) ||
               (PsGetCurrentThread()->OwnsSessionWorkingSetShared));
    }
    else
    {
        ASSERT((PsGetCurrentThread()->OwnsProcessWorkingSetExclusive) ||
               (PsGetCurrentThread()->OwnsProcessWorkingSetShared));
    }

    Pte = MiAddressToPte(&Wsle[WsList->LastInitializedWsle]);
    ASSERT(Pte->u.Hard.Valid == 1);

    Pte++;

    NextWsleArray = MiPteToAddress(Pte);

    if (NextWsleArray >= WsList->HashTableStart)
        return FALSE;

    if (!MiChargeCommitmentCantExpand(1, FALSE))
        return FALSE;

    MI_MAKE_SOFTWARE_PTE(&TempPte, MM_READWRITE);
    ASSERT(Pte->u.Hard.Valid == 0);

    OldIrql = MiLockPfnDb(APC_LEVEL);

    if (MmAvailablePages < 0x80 || (MmResidentAvailablePages - MmSystemLockPagesCount) < 0x80) // MmSystemLockPagesCount[0]
    {
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        ASSERT(MmTotalCommittedPages >= 1);
        InterlockedDecrementSizeT(&MmTotalCommittedPages);
        return FALSE;
    }

    InterlockedDecrementSizeT(&MmResidentAvailablePages);
    //InterlockedIncrementSizeT(&MmResTrack[48]);

    PageFrameNumber = MiRemoveZeroPage(MiGetColor());
    MI_WRITE_INVALID_PTE(Pte, TempPte);

    MiInitializePfn(PageFrameNumber, Pte, 1);
    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    MI_MAKE_HARDWARE_PTE(&TempPte, Pte, MM_READWRITE, PageFrameNumber);
    MI_MAKE_DIRTY_PAGE(&TempPte);
    MI_WRITE_VALID_PTE(Pte, TempPte);

    NumberOfEntriesMapped = ((((ULONG_PTR)NextWsleArray - (ULONG_PTR)Wsle) + PAGE_SIZE) / sizeof(PMMWSLE));

    if (WorkSet->Flags.SessionSpace)
    {
        InterlockedIncrementSizeT(&MmSessionSpace->NonPageablePages);//NonPagablePages
        InterlockedIncrementSizeT(&MmSessionSpace->CommittedPages);
    }

    WsIndex = (WsList->LastInitializedWsle + 1);
    ASSERT(NumberOfEntriesMapped > WsIndex);

    CurrentWsle = &Wsle[WsIndex - 1];

    for (Idx = WsIndex; Idx < NumberOfEntriesMapped; Idx++)
    {
        CurrentWsle++;
        CurrentWsle->u1.Long = ((Idx + 1) << MM_FREE_WSLE_SHIFT);
    }

    CurrentWsle->u1.Long = WsList->FirstFree << MM_FREE_WSLE_SHIFT;


    ASSERT(WsIndex >= WsList->FirstDynamic);

    WsList->FirstFree = WsIndex;
    WsList->LastInitializedWsle = (NumberOfEntriesMapped - 1);

    ASSERT((WsList->FirstFree <= WsList->LastInitializedWsle) || (WsList->FirstFree == WSLE_NULL_INDEX));

    Pfn = MI_PFN_ELEMENT(Pte->u.Hard.PageFrameNumber);
    Pfn->u1.WsIndex = 0;

    ASSERT(WorkSet->WorkingSetSize <= (WsList->LastInitializedWsle + 1));
    WorkSet->WorkingSetSize++;

    ASSERT(WsList->FirstFree != WSLE_NULL_INDEX);
    ASSERT(WsList->FirstFree >= WsList->FirstDynamic);

    WsIndex1 = WsList->FirstFree;
    WsList->FirstFree = (Wsle[WsList->FirstFree].u1.Long >> MM_FREE_WSLE_SHIFT);

    ASSERT((WsList->FirstFree <= WsList->LastInitializedWsle) || (WsList->FirstFree == WSLE_NULL_INDEX));

    if (WorkSet->WorkingSetSize > WorkSet->MinimumWorkingSetSize)
        InterlockedIncrementSizeT(&MmPagesAboveWsMinimum);

    if (WsIndex1 > WsList->LastEntry)
        WsList->LastEntry = WsIndex1;

    dummy.u1.Long = 0;
    MiUpdateWsle(&WsIndex1, NextWsleArray, WorkSet, Pfn, dummy);

    WsIndex2 = WsList->FirstDynamic;
    if (WsIndex1 >= WsIndex2)
    {
        if (WsIndex1 != WsIndex2)
            MiSwapWslEntries(WsIndex1, WsIndex2, WorkSet, 0);

        WsList->FirstDynamic++;

        Wsle[WsIndex2].u1.e1.LockedInWs = 1;
        ASSERT(Wsle[WsIndex2].u1.e1.Valid == 1);
    }

    ASSERT((MiAddressToPte(&Wsle[WsList->LastInitializedWsle]))->u.Hard.Valid == 1);

    if (!WsList->HashTable && MmAvailablePages > 0x80)
        WorkSet->Flags.GrowWsleHash = 1;

    return TRUE;
}

ULONG
NTAPI
MiAllocateWsle(
    _In_ PMMSUPPORT WorkSet,
    _In_ PMMPTE Pte,
    _In_ PMMPFN Pfn,
    _In_ MMWSLE InWsle)
{
    PMMWSL WsList;
    PMMWSLE Wsle;
    PVOID Address;
    ULONG WsIndex;

    DPRINT("MiAllocateWsle: WorkSet %p, Pte %p, Pfn %X, InWsle %X\n", WorkSet, Pte, Pfn, InWsle);

    WsList = WorkSet->VmWorkingSetList;
    ASSERT(WsList != NULL);

    Wsle = WsList->Wsle;
    ASSERT(Wsle != NULL);

    //DPRINT("MiAllocateWsle: %p, %p, %X, %X, %X\n", WsList, Wsle, WsList->FirstFree, WsList->FirstDynamic, WsList->LastInitializedWsle);

    WorkSet->PageFaultCount++;
    InterlockedIncrement(&KeGetCurrentPrcb()->MmPageFaultCount);

    if ((ULONG_PTR)Pfn & 1)
    {
        MiDoReplacement(WorkSet, 2);

        if (WsList->FirstFree == WSLE_NULL_INDEX)
        {
            return 0;
        }

        Pfn = (PMMPFN)((ULONG_PTR)Pfn & ~1);
    }
    else
    {
        MiDoReplacement(WorkSet, 0);

        if (WsList->FirstFree == WSLE_NULL_INDEX)
        {
            if (!MiAddWorkingSetPage(WorkSet))
            {
                MiDoReplacement(WorkSet, 1);

                if (WsList->FirstFree == WSLE_NULL_INDEX)
                {
                    //MiWsleFailures++;
                    return 0;
                }
            }
        }
    }

    ASSERT(WsList->FirstFree <= WsList->LastInitializedWsle);
    ASSERT(WsList->FirstFree >= WsList->FirstDynamic);

    WsIndex = WsList->FirstFree;
    WsList->FirstFree = (Wsle[WsIndex].u1.Long / 0x10);

    ASSERT((WsList->FirstFree <= WsList->LastInitializedWsle) || (WsList->FirstFree == WSLE_NULL_INDEX));
    ASSERT(WorkSet->WorkingSetSize <= (WsList->LastInitializedWsle + 1));

    WorkSet->WorkingSetSize++;

    if (WorkSet->WorkingSetSize > WorkSet->MinimumWorkingSetSize)
        InterlockedIncrementSizeT(&MmPagesAboveWsMinimum);

    if (WorkSet->PeakWorkingSetSize < WorkSet->WorkingSetSize)
        WorkSet->PeakWorkingSetSize = WorkSet->WorkingSetSize;

    if (WorkSet == &MmSystemCacheWs)
    {
        if (MmTransitionSharedPagesPeak < (WorkSet->WorkingSetSize + MmTransitionSharedPages))
            MmTransitionSharedPagesPeak = (WorkSet->WorkingSetSize + MmTransitionSharedPages);
    }

    if (WsIndex > WsList->LastEntry)
        WsList->LastEntry = WsIndex;

    ASSERT(Wsle[WsIndex].u1.e1.Valid == 0);

    Address = MiPteToAddress(Pte);

    MiUpdateWsle(&WsIndex, Address, WorkSet, Pfn, InWsle);

    if (InWsle.u1.Long)
        Wsle[WsIndex].u1.Long |= InWsle.u1.Long;

    if ((Address >= MmSystemCacheStart && Address <= MmSystemCacheEnd))
        //FIXME: || (Address >= MiSystemCacheStartExtra && Address <= MiSystemCacheEndExtra))
    {
        ASSERT(MmSystemCacheWsle[WsIndex].u1.e1.Protection == MM_ZERO_ACCESS);
    }

    return WsIndex;
}

VOID
FASTCALL 
MiReleaseWsle(
    _In_ ULONG WsIndex,
    _In_ PMMSUPPORT WorkSet)
{
    PMMWSL WsList;
    PMMWSLE Wsle;

    DPRINT("MiReleaseWsle: WsIndex %X, WorkSet %p\n", WsIndex, WorkSet);

    WsList = WorkSet->VmWorkingSetList;
    Wsle = WsList->Wsle;

    if (WorkSet == &MmSystemCacheWs)
    {
        ASSERT(PsGetCurrentThread()->OwnsSystemWorkingSetExclusive ||
               PsGetCurrentThread()->OwnsSystemWorkingSetShared);
    }
    else if (WorkSet->Flags.SessionSpace)
    {
        ASSERT(PsGetCurrentThread()->OwnsSessionWorkingSetExclusive ||
               PsGetCurrentThread()->OwnsSessionWorkingSetShared);
    }
    else
    {
        ASSERT(PsGetCurrentThread()->OwnsProcessWorkingSetExclusive ||
               PsGetCurrentThread()->OwnsProcessWorkingSetShared);
    }

    ASSERT(WsIndex <= WsList->LastInitializedWsle);

    ASSERT((WsList->FirstFree <= WsList->LastInitializedWsle) ||
           (WsList->FirstFree == WSLE_NULL_INDEX));

    Wsle[WsIndex].u1.Long = (WsList->FirstFree * 0x10);
    WsList->FirstFree = WsIndex;

    ASSERT((WsList->FirstFree <= WsList->LastInitializedWsle) ||
           (WsList->FirstFree == WSLE_NULL_INDEX));

    if (WorkSet->WorkingSetSize > WorkSet->MinimumWorkingSetSize)
        InterlockedDecrementSizeT(&MmPagesAboveWsMinimum);

    WorkSet->WorkingSetSize--;
}

VOID
FASTCALL 
MiRemoveWsle(
    _In_ ULONG WsIndex,
    _In_ PMMWSL WsList)
{
    PMMWSLE Wsle;
    PVOID Address;
    PMMWSLE_HASH Table;
    ULONG ix;
    ULONG Hash;
    ULONG Tries;
    MMWSLE WsleContents;

    DPRINT("MiRemoveWsle: WsIndex %X, WsList %p\n", WsIndex, WsList);

    if (WsIndex > WsList->LastInitializedWsle)
    {
        DPRINT1("MiRemoveWsle: KeBugCheckEx()\n");
        ASSERT(FALSE);
    }

    Wsle = &WsList->Wsle[WsIndex];

    WsleContents.u1.Long = Wsle->u1.Long;
    ASSERT(WsleContents.u1.e1.Valid == 1);

    Address = PAGE_ALIGN(WsleContents.u1.VirtualAddress);

    if (WsList == MmSystemCacheWorkingSetList)
    {
        if (Address >= MmPagedPoolStart && Address <= MmPagedPoolEnd)
        {
            MmPagedPoolPage--;
        }
        else if ((Address >= MmSystemCacheStart && Address <= MmSystemCacheEnd)) // || (Address >= MiSystemCacheStartExtra && Address <= MiSystemCacheEndExtra))
        {
            MmSystemCachePage--;
        }
        else if (Address <= MmSpecialPoolEnd && Address >= MmSpecialPoolStart)
        {
            MmPagedPoolPage--;
        }
        //else if (Address < MiLowestSystemPteVirtualAddress)
        //    MmSystemCodePage--;
        //else
        //    MmSystemDriverPage--;
    }

    Wsle->u1.e1.Valid = 0;
    WsleContents.u1.e1.Valid = 0;

    if (WsleContents.u1.e1.Direct)
        return;

    WsList->NonDirectCount--;

    if (!WsleContents.u1.e1.Hashed)
    {
        Table = WsList->HashTable;
        if (!Table)
            return;

        Address = (PVOID)((ULONG_PTR)Address | 1);

        for (ix = 0; ix < WsList->HashTableSize; ix++)
        {
            ASSERT(Table[ix].Key != Address);
        }

        return;
    }

    Table = WsList->HashTable;
    if (!Table)
        return;

    Hash = ((WsleContents.u1.e1.VirtualPageNumber * 4) % (WsList->HashTableSize - 1));

    Address = (PVOID)((ULONG_PTR)Address | 1);
    Tries = 0;

    for (ix = Hash; Table[ix].Key != Address; )
    {
        ix++;

        if (ix >= WsList->HashTableSize)
        {
            ASSERT(Tries == 0);
            ix = 0;
            Tries = 1;
        }

        if (ix == Hash)
        {
            ASSERT(WsleContents.u1.e1.Hashed == 0);
            return;
        }
    }

    ASSERT(WsleContents.u1.e1.Hashed == 1);
    Table[ix].Key = 0;
}

ULONG
NTAPI
MiLocateWsle(
    _In_ PVOID Address,
    _In_ PMMWSL WsList,
    _In_ ULONG InWsIndex,
    _In_ BOOLEAN IsResetHash)
{
    PMMWSLE Wsle;
    PMMWSLE LastWsle;
    PMMWSLE_HASH Table;
    ULONG WsIndex;
    ULONG Hash;
    ULONG Tries;
    ULONG ix;

    DPRINT("MiLocateWsle: %p, %p, %X, %X\n", Address, WsList, InWsIndex, IsResetHash);

    Wsle = WsList->Wsle;
    Address = (PVOID)((ULONG_PTR)PAGE_ALIGN(Address) | 1);

    if (InWsIndex <= WsList->LastInitializedWsle &&
        (Wsle[InWsIndex].u1.Long & (0xFFFFF000 | 1)) == (ULONG_PTR)Address)
    {
        return InWsIndex;
    }

    Table = WsList->HashTable;
    if (Table)
    {
        Tries = 0;
        ix = Hash = (((ULONG_PTR)Address * 4) % (WsList->HashTableSize - 1));

        while (Table[ix].Key != Address)
        {
            ix++;

            if (ix >= WsList->HashTableSize)
            {
                ix = 0;

                ASSERT(Tries == 0);
                Tries = 1;
            }

            if (ix == Hash)
            {
                Tries = 2;
                break;
            }
        }

        if (Tries < 2)
        {
            WsIndex = Table[ix].Index;

            ASSERT(Wsle[WsIndex].u1.e1.Hashed == 1);
            ASSERT(Wsle[WsIndex].u1.e1.Direct == 0);
            ASSERT((Wsle[WsIndex].u1.Long & (0xFFFFF000 | 1)) == (ULONG_PTR)Table[ix].Key);

            if (IsResetHash)
            {
                Wsle[WsIndex].u1.e1.Hashed = 0;
                Table[ix].Key = 0;
            }

            return WsIndex;
        }
    }

    LastWsle = &Wsle[WsList->LastInitializedWsle];

    while ((Wsle->u1.Long & (0xFFFFF000 | 1)) != (ULONG_PTR)Address)
    {
        Wsle++;

        if (Wsle > LastWsle)
        {
            DPRINT1("MiLocateWsle: KeBugCheckEx()\n");
            DbgBreakPoint();//ASSERT(FALSE);
        }
    }

    ASSERT((Wsle->u1.e1.Hashed == 0) || (WsList->HashTable == NULL));
    ASSERT(Wsle->u1.e1.Direct == 0);

    return (Wsle - WsList->Wsle);
}

VOID
NTAPI
MiTerminateWsle(
    _In_ PVOID Address,
    _In_ PMMSUPPORT WorkSet,
    _In_ ULONG InWsIndex)
{
    PMMWSL WsList;
    ULONG WsIndex;
    MMWSLE WsleContents;

    WsList = WorkSet->VmWorkingSetList;

    DPRINT("MiTerminateWsle: %p, %p, %p, %X\n", Address, WorkSet, WsList, InWsIndex);

    WsIndex = MiLocateWsle(Address, WorkSet->VmWorkingSetList, InWsIndex, TRUE);
    ASSERT(WsIndex != WSLE_NULL_INDEX);

    WsleContents.u1.Long = WsList->Wsle[WsIndex].u1.Long;

    ASSERT(PAGE_ALIGN(Address) == PAGE_ALIGN(WsleContents.u1.VirtualAddress));
    ASSERT(WsleContents.u1.e1.Valid == 1);

    MiRemoveWsle(WsIndex, WsList);
    MiReleaseWsle(WsIndex, WorkSet);

    if (!WsleContents.u1.e1.LockedInWs && !WsleContents.u1.e1.LockedInMemory)
    {
        ASSERT(WsIndex >= WsList->FirstDynamic);
        return;
    }

    ASSERT(WsIndex < WsList->FirstDynamic);
    WsList->FirstDynamic--;

    if (WsIndex == WsList->FirstDynamic)
        return;

    ASSERT(WsList->Wsle[WsList->FirstDynamic].u1.e1.Valid);
    MiSwapWslEntries(WsList->FirstDynamic, WsIndex, WorkSet, FALSE);
}

BOOLEAN
NTAPI
MiAddWsleHash(
    _In_ PMMSUPPORT WorkSet,
    _In_ PMMPTE Pte)
{
    PMMPFN Pfn;
    PMMWSLE Wsle;
    PMMWSL WsList;
    PFN_NUMBER PageFrameNumber;
    MMPTE TempPte;
    MMWSLE TempWsle;
    ULONG WsIndex;
    ULONG SwapEntry;
    KIRQL OldIrql;

    DPRINT("MiAddWsleHash: %p, %p, %p, %p\n", WorkSet, Pte, WorkSet->VmWorkingSetList, WsList->Wsle);

    if (!MiChargeCommitmentCantExpand(1, FALSE))
    {
        DPRINT1("MiAddWsleHash: MiChargeCommitmentCantExpand() failed\n");
        return FALSE;
    }

    WsList = WorkSet->VmWorkingSetList;
    Wsle = WsList->Wsle;

    ASSERT(Pte->u.Hard.Valid == 0);

    OldIrql = MiLockPfnDb(APC_LEVEL);

    if (MmAvailablePages < 0x80)
    {
        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        ASSERT(MmTotalCommittedPages >= 1);
        InterlockedDecrementSizeT(&MmTotalCommittedPages);
        return FALSE;
    }

    if (MmResidentAvailablePages - MmSystemLockPagesCount < 0x80) // MmSystemLockPagesCount[0]
    {
        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        ASSERT(MmTotalCommittedPages >= 1);
        InterlockedDecrementSizeT(&MmTotalCommittedPages);
        return FALSE;
    }

    InterlockedDecrementSizeT(&MmResidentAvailablePages);
    //InterlockedIncrementSizeT(&MmResTrack[70]);

    MI_MAKE_SOFTWARE_PTE(&TempPte, MM_READWRITE);
    MI_WRITE_INVALID_PTE(Pte, TempPte);

    PageFrameNumber = MiRemoveZeroPage(MiGetColor());
    MiInitializePfn(PageFrameNumber, Pte, TRUE);

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    MI_MAKE_HARDWARE_PTE(&TempPte, Pte, MM_READWRITE, PageFrameNumber);
    MI_MAKE_DIRTY_PAGE(&TempPte);
    MI_WRITE_VALID_PTE(Pte, TempPte);

    Pfn = MI_PFN_ELEMENT(PageFrameNumber);
    Pfn->u1.WsIndex = 0;

    TempWsle.u1.Long = 0;

    WsIndex = MiAllocateWsle(WorkSet, Pte, (PMMPFN)((ULONG_PTR)Pfn | 1), TempWsle);
    if (!WsIndex)
    {
        ASSERT(Pfn->u3.e1.PrototypePte == 0);

        DPRINT1("MiAddWsleHash: FIXME MiTrimPte()\n");
        ASSERT(FALSE);

        return FALSE;
    }

    SwapEntry = WsList->FirstDynamic;

    if (WsIndex >= SwapEntry)
    {
        if (WsIndex != SwapEntry)
            MiSwapWslEntries(WsIndex, SwapEntry, WorkSet, FALSE);

        WsList->FirstDynamic++;

        Wsle[SwapEntry].u1.e1.LockedInWs = 1;
        ASSERT(Wsle[SwapEntry].u1.e1.Valid == 1);
    }

    if (WorkSet->Flags.SessionSpace)
    {
        InterlockedIncrementSizeT(&MmSessionSpace->NonPageablePages);//NonPagablePages
        InterlockedIncrementSizeT(&MmSessionSpace->CommittedPages);
    }

    return TRUE;
}

VOID
NTAPI
MiFillWsleHash(
    _In_ PMMWSL WsList)
{
    PMMWSLE CurrentWsle;
    PMMWSLE FirstWsle;
    PMMWSLE_HASH Table;
    PMMWSLE_HASH EndTable;
    PMMWSLE_HASH StartHash;
    PMMWSLE_HASH CurrentHash;
    PMMPTE Pte;
    ULONG WsIndex = 0;
    ULONG HashIndex;
    ULONG Count;

    FirstWsle = WsList->Wsle;
    Table = WsList->HashTable;
    EndTable = &Table[WsList->HashTableSize];
    Count = WsList->NonDirectCount;

    DPRINT("MiFillWsleHash: %p, %p, %X, %X\n", WsList, Table, WsList->HashTableSize, Count);

    for (CurrentWsle = FirstWsle; TRUE; CurrentWsle++, WsIndex++)
    {
        ASSERT(CurrentWsle <= &FirstWsle[WsList->LastEntry]);

        if (!CurrentWsle->u1.e1.Valid)
            continue;

        if (CurrentWsle->u1.e1.Direct)
        {
            ASSERT((CurrentWsle->u1.e1.Hashed == 0) ||
                   (CurrentWsle->u1.e1.LockedInWs == 1) ||
                   (CurrentWsle->u1.e1.LockedInMemory == 1));

            continue;
        }

        CurrentWsle->u1.e1.Hashed = 0;

        Pte = MiAddressToPte(CurrentWsle->u1.VirtualAddress);
        ASSERT(Pte->u.Hard.Valid);

        if ((MI_PFN_ELEMENT(Pte->u.Hard.PageFrameNumber))->u1.WsIndex != WsIndex)
        {
            HashIndex = ((CurrentWsle->u1.e1.VirtualPageNumber * 4) % (WsList->HashTableSize - 1));
            CurrentHash = StartHash = &Table[HashIndex];

            while (TRUE)
            {
                if (!CurrentHash->Key)
                {
                    CurrentHash->Key = (PVOID)(CurrentWsle->u1.Long & (0xFFFFF000 | 1));
                    CurrentHash->Index = WsIndex;

                    CurrentWsle->u1.e1.Hashed = 1;
                    break;
                }

                CurrentHash++;
                ASSERT(CurrentHash <= EndTable);

                if (CurrentHash == EndTable)
                    CurrentHash = Table;

                if (CurrentHash == StartHash)
                {
                    do
                    {
                        ASSERT(CurrentWsle <= &FirstWsle[WsList->LastEntry]);

                        if (CurrentWsle->u1.e1.Valid && !CurrentWsle->u1.e1.Direct)
                        {
                            Count--;
                            CurrentWsle->u1.e1.Hashed = 0;
                        }

                        CurrentWsle++;
                    }
                    while (Count);

                    return;
                }
            }
        }

        Count--;
        if (!Count)
        {
            //MiCheckWsleHash(WsList);
            return;
        }
    }

    return;
}

VOID
NTAPI
MiGrowWsleHash(
    _In_ PMMSUPPORT WorkSet)
{
    PMMWSL WsList;
    PMMWSLE_HASH Table;
    PMMWSLE_HASH NewTable;
    PMMPDE AllocatedPde;
    PMMPDE Pde;
    PMMPTE FirstPte;
    PMMPTE LastPte;
    PMMPTE Pte;
    PVOID TableEnd;
    PVOID Address;
    ULONG BytesOfGrow;
    ULONG OldCount;
    LONG BytesLeft;
    BOOLEAN IsLocatePde;

    WsList = WorkSet->VmWorkingSetList;
    NewTable = Table = WsList->HashTable;
    OldCount = WsList->HashTableSize;

    DPRINT("MiGrowWsleHash: %p, %p, %p, %X\n", WorkSet, WsList, Table, OldCount);

    if (Table)
    {
        BytesOfGrow = ((WsList->NonDirectCount / 4) * sizeof(MMWSLE_HASH));
        BytesOfGrow = (BytesOfGrow + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);

        if (BytesOfGrow < 0x4000)
            BytesOfGrow = 0x4000;

        if (BytesOfGrow / PAGE_SIZE >= (WsList->LastInitializedWsle - WorkSet->WorkingSetSize))
            BytesOfGrow = PAGE_SIZE;
    }
    else
    {
        BytesOfGrow = (2 * (WsList->NonDirectCount + 1) * sizeof(MMWSLE_HASH));
        BytesOfGrow = ((BytesOfGrow + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1));

        if (OldCount && BytesOfGrow < ((OldCount * sizeof(MMWSLE_HASH)) + PAGE_SIZE))
        {
            WorkSet->Flags.GrowWsleHash = 0;
            return;
        }

        NewTable = WsList->HashTableStart;
        WsList->HashTableSize = 0;
    }

    TableEnd = &NewTable[OldCount];

    if ((ULONG_PTR)TableEnd + BytesOfGrow > (ULONG_PTR)WsList->HighestPermittedHashAddress)
    {
        BytesOfGrow = ((ULONG_PTR)WsList->HighestPermittedHashAddress - (ULONG_PTR)TableEnd);
        if (!BytesOfGrow)
        {
            if (!Table)
                WsList->HashTableSize = OldCount;

            WorkSet->Flags.GrowWsleHash = 0;
            return;
        }
    }

    ASSERT((TableEnd == WsList->HighestPermittedHashAddress) ||
           (MiAddressToPde(TableEnd)->u.Hard.Valid == 0) ||
           (MiAddressToPte(TableEnd)->u.Hard.Valid == 0));

    Pte = FirstPte = MiAddressToPte(TableEnd);
    LastPte = &Pte[BytesOfGrow / PAGE_SIZE];

    Pde = AllocatedPde = NULL;
    IsLocatePde = TRUE;

    BytesLeft = BytesOfGrow;

    do
    {
        if (!IsLocatePde && !MiIsPteOnPdeBoundary(Pte))
        {
            AllocatedPde = NULL;
        }
        else
        {
            Pde = MiAddressToPte(Pte);
            if (!Pde->u.Hard.Valid)
            {
                if (!MiAddWsleHash(WorkSet, Pde))
                    break;

                AllocatedPde = Pde;
            }

            IsLocatePde = FALSE;
        }

        if (!Pte->u.Hard.Valid && !MiAddWsleHash(WorkSet, Pte))
            break;

        BytesLeft -= PAGE_SIZE;
        Pte++;
    }
    while (BytesLeft > 0);

    if (Pte != LastPte)
    {
        if (AllocatedPde)
        {
            ASSERT(AllocatedPde->u.Hard.Valid == 1);

            if (WorkSet->VmWorkingSetList == MmWorkingSetList)
            {
                DPRINT1("MiGrowWsleHash: FIXME MiDeletePte()\n");
                ASSERT(FALSE);
            }
            else
            {
                DPRINT1("MiGrowWsleHash: FIXME MiDeleteValidSystemPte()\n");
                ASSERT(FALSE);
            }
        }

        if (Pte == FirstPte)
        {
            if (!Table)
                WsList->HashTableSize = OldCount;

            WorkSet->Flags.GrowWsleHash = 0;
            return;
        }
    }

    Address = MiPteToAddress(Pte);
    ASSERT((Address == WsList->HighestPermittedHashAddress) || (MiIsAddressValid(Address) == FALSE));

    BytesOfGrow = (((Pte - FirstPte) * PAGE_SIZE));
    WsList->HashTableSize = (OldCount + (BytesOfGrow / sizeof(MMWSLE_HASH)));
    WsList->HashTable = NewTable;

    Address = &NewTable[WsList->HashTableSize];
    ASSERT((Address == WsList->HighestPermittedHashAddress) || (MiIsAddressValid(Address) == FALSE));

    if (OldCount)
        RtlZeroMemory(NewTable, OldCount * sizeof(MMWSLE_HASH));

    WorkSet->Flags.GrowWsleHash = 0;

    if (WsList->NonDirectCount)
        MiFillWsleHash(WsList);
}

ULONG
NTAPI
MiAddValidPageToWorkingSet(
    _In_ PVOID Address,
    _In_ PMMPTE Pte,
    _In_ PMMPFN Pfn,
    _In_ MMWSLE Wsle)
{
    PMMSUPPORT WorkSet;

    ASSERT(MI_IS_PAGE_TABLE_ADDRESS(Pte));
    ASSERT(Pte->u.Hard.Valid == 1);

    if ((Address < MmSessionBase || Address >= MiSessionSpaceEnd) &&
        (Address < (PVOID)MiSessionBasePte || Address >= (PVOID)MiSessionLastPte))
    {
        if (Address <= MmHighestUserAddress ||
            (Address >= (PVOID)PTE_BASE && Address <= MmHyperSpaceEnd))
        {
            WorkSet = &PsGetCurrentProcess()->Vm;
        }
        else
        {
            WorkSet = &MmSystemCacheWs;
        }
    }
    else
    {
        WorkSet = &MmSessionSpace->Vm;
    }

    return MiAllocateWsle(WorkSet, Pte, Pfn, Wsle);
}

VOID
NTAPI
MiAllowWorkingSetExpansion(
    _In_ PMMSUPPORT WorkSet)
{
    KIRQL OldIrql;

    DPRINT("MiAllowWorkingSetExpansion: %p\n", WorkSet);

    ASSERT(WorkSet->WorkingSetExpansionLinks.Flink == NULL);
    ASSERT(WorkSet->WorkingSetExpansionLinks.Blink == NULL);

  #if defined(ONE_CPU)
    OldIrql = KeRaiseIrqlToDpcLevel();
  #else
    OldIrql = MiAcquireExpansionLock();
  #endif

    InsertTailList(&MmWorkingSetExpansionHead, &WorkSet->WorkingSetExpansionLinks);

  #if defined(ONE_CPU)
    KeLowerIrql(OldIrql);
  #else
    MiReleaseExpansionLock(OldIrql);
  #endif

}

VOID
NTAPI
MiUnlinkWorkingSet(
    _In_ PMMSUPPORT WorkSet)
{
    KEVENT Event;
    KIRQL OldIrql;

    OldIrql = MiAcquireExpansionLock();

    if (WorkSet->WorkingSetExpansionLinks.Flink == MM_WS_NOT_LISTED)
    {
        MiReleaseExpansionLock(OldIrql);
        return;
    }

    if (WorkSet->WorkingSetExpansionLinks.Flink != (PLIST_ENTRY)1)
    {
        RemoveEntryList(&WorkSet->WorkingSetExpansionLinks);
        WorkSet->WorkingSetExpansionLinks.Flink = MM_WS_NOT_LISTED;
        MiReleaseExpansionLock(OldIrql);
        return;
    }

    //WorkSet->WorkingSetExpansionLinks.Flink == 1

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    WorkSet->WorkingSetExpansionLinks.Blink = (PLIST_ENTRY)&Event;

    KeEnterCriticalRegion();
    MiReleaseExpansionLock(OldIrql);
    KeWaitForSingleObject(&Event, WrVirtualMemory, KernelMode, FALSE, NULL);
    KeLeaveCriticalRegion();

    ASSERT(WorkSet->WorkingSetExpansionLinks.Flink == MM_WS_NOT_LISTED);
}

BOOLEAN
NTAPI
MiRemovePageFromWorkingSet(
    _In_ PMMPTE Pte,
    _In_ PMMPFN Pfn,
    _In_ PMMSUPPORT WorkSet)
{
    PMMWSL WsList;
    PMMWSLE Wsle;
    PVOID Address1;
    MMWSLE WsleContents;
    ULONG WsIndex1;
    ULONG WsIndex2;

    WsList = WorkSet->VmWorkingSetList;
    Wsle = WsList->Wsle;

    WsIndex2 = MiLocateWsle(MiPteToAddress(Pte), WorkSet->VmWorkingSetList, Pfn->u1.WsIndex, TRUE);
    ASSERT(WsIndex2 != WSLE_NULL_INDEX);

    MiEliminateWorkingSetEntry(WsIndex2, Pte, Pfn, WorkSet, TRUE);

    WsleContents = Wsle[WsIndex2];

    MiRemoveWsle(WsIndex2, WsList);
    MiReleaseWsle(WsIndex2, WorkSet);

    if (!WsleContents.u1.e1.LockedInWs && !WsleContents.u1.e1.LockedInMemory)
    {
        ASSERT(WsIndex2 >= WsList->FirstDynamic);
        return FALSE;
    }

    WsList->FirstDynamic--;
    WsIndex1 = WsList->FirstDynamic;

    if (WsIndex1 == WsIndex2)
        return TRUE;

    Address1 = PAGE_ALIGN(Wsle[WsIndex1].u1.VirtualAddress);
    Pfn = MI_PFN_ELEMENT((MiAddressToPte(Address1))->u.Hard.PageFrameNumber);

    ASSERT(WsIndex1 == MiLocateWsle(Address1, WsList, Pfn->u1.WsIndex, FALSE));
    MiSwapWslEntries(WsIndex1, WsIndex2, WorkSet, FALSE);

    return TRUE;
}

NTSTATUS
NTAPI
MiEmptyWorkingSet(
    _In_ PMMSUPPORT WorkingSet,
    _In_ BOOLEAN IsParam2)
{
    if (WorkingSet->VmWorkingSetList == MmWorkingSetList &&
        PsGetCurrentProcess()->VmDeleted)
    {
        DPRINT("MiEmptyWorkingSet: STATUS_PROCESS_IS_TERMINATING. %p, %X\n", WorkingSet, IsParam2);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    UNIMPLEMENTED;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
MmAdjustWorkingSetSizeEx(
    SIZE_T WorkingSetMinimumInBytes,
    SIZE_T WorkingSetMaximumInBytes,
    BOOLEAN IsSystemCache,
    BOOLEAN IsIncreaseOkay,
    ULONG Flags,
    BOOLEAN* OutIsAddMinSize)
{
    PETHREAD Thread = PsGetCurrentThread();
    PEPROCESS Process;
    PMMSUPPORT WorkingSet;
    PMMWSL WorkingSetList;
    SIZE_T MinWorkingSetSize;
    SIZE_T MaxWorkingSetSize;
    SSIZE_T Delta;
    ULONG TrimAge;
    BOOLEAN LimitIsGood = TRUE;
    KIRQL OldIrql;
    NTSTATUS Status;

    DPRINT("MmAdjustWorkingSetSizeEx: %IX, %IX, %X\n", WorkingSetMinimumInBytes, WorkingSetMaximumInBytes, IsSystemCache);

    *OutIsAddMinSize = FALSE;

    if (IsSystemCache)
    {
        Process = NULL;
        WorkingSet = &MmSystemCacheWs;
    }
    else
    {
        Process = (PEPROCESS)Thread->Tcb.ApcState.Process;
        WorkingSet = &Process->Vm;
    }

    /* Check for special case: empty the working set */
    if (WorkingSetMinimumInBytes == -1 && WorkingSetMaximumInBytes == -1)
        return MiEmptyWorkingSet(WorkingSet, TRUE);

    /* Assume success */
    Status = STATUS_SUCCESS;

    //MmLockPagableSectionByHandle(ExPageLockHandle);

    /* Lock the working set */
    if (IsSystemCache)
    {
        DPRINT1("MmAdjustWorkingSetSizeEx: FIXME\n");
        ASSERT(FALSE);
    }
    else
    {
        MiLockProcessWorkingSet(Process, Thread);

        if (Process->VmDeleted)
        {
            DPRINT1("MmAdjustWorkingSetSizeEx: STATUS_PROCESS_IS_TERMINATING\n");
            Status = STATUS_PROCESS_IS_TERMINATING;
            goto Cleanup;
        }
    }

    /* Calculate the actual minimum and maximum working set size to set */
    if (WorkingSetMinimumInBytes)
        MinWorkingSetSize = (WorkingSetMinimumInBytes / PAGE_SIZE);
    else
        MinWorkingSetSize = WorkingSet->MinimumWorkingSetSize;

    if (WorkingSetMaximumInBytes)
        MaxWorkingSetSize = (WorkingSetMaximumInBytes / PAGE_SIZE);
    else
        MaxWorkingSetSize = WorkingSet->MaximumWorkingSetSize;

    /* Check if the new minimum exceeds the new maximum */
    if (MinWorkingSetSize > MaxWorkingSetSize)
    {
        DPRINT1("MmAdjustWorkingSetSizeEx: STATUS_BAD_WORKING_SET_LIMIT. %IX, %IX\n", MinWorkingSetSize, MaxWorkingSetSize);
        Status = STATUS_BAD_WORKING_SET_LIMIT;
        goto Cleanup;
    }

    /* Check if the new maximum exceeds the global maximum */
    if (MaxWorkingSetSize > MmMaximumWorkingSetSize)
    {
        DPRINT1("MmAdjustWorkingSetSizeEx: STATUS_WORKING_SET_LIMIT_RANGE\n");
        MaxWorkingSetSize = MmMaximumWorkingSetSize;
        Status = STATUS_WORKING_SET_LIMIT_RANGE;
    }

    /* Check if the new minimum is below the global minimum */
    if (MinWorkingSetSize < MmMinimumWorkingSetSize)
    {
        DPRINT1("MmAdjustWorkingSetSizeEx: STATUS_WORKING_SET_LIMIT_RANGE\n");
        MinWorkingSetSize = MmMinimumWorkingSetSize;
        Status = STATUS_WORKING_SET_LIMIT_RANGE;
    }

    /* Check if the new minimum exceeds the new maximum */
    if (MinWorkingSetSize > MmMaximumWorkingSetSize)
    {
        DPRINT1("MmAdjustWorkingSetSizeEx: STATUS_WORKING_SET_LIMIT_RANGE\n");
        MinWorkingSetSize = MmMaximumWorkingSetSize;
        Status = STATUS_WORKING_SET_LIMIT_RANGE;
    }

    WorkingSetList = WorkingSet->VmWorkingSetList;

    if (MaxWorkingSetSize <= (WorkingSetList->FirstDynamic + 8))
    {
        DPRINT1("MmAdjustWorkingSetSizeEx: STATUS_BAD_WORKING_SET_LIMIT\n");
        Status = STATUS_BAD_WORKING_SET_LIMIT;
        goto Cleanup;
    }

    if ((Flags & 4) ||
        (WorkingSet->Flags.MinimumWorkingSetHard && !(Flags & 8)) ||
        (Flags & 1) ||
        (WorkingSet->Flags.MaximumWorkingSetHard && !(Flags & 2)))
    {
        if (MaxWorkingSetSize <= (MinWorkingSetSize + 8) ||
            (IsSystemCache && MaxWorkingSetSize < 0x1000))
        {
            DPRINT1("MmAdjustWorkingSetSizeEx: STATUS_BAD_WORKING_SET_LIMIT\n");
            Status = STATUS_BAD_WORKING_SET_LIMIT;
            goto Cleanup;
        }
    }

    /* Calculate the minimum WS size adjustment and check if we increase */
    Delta = (MinWorkingSetSize - WorkingSet->MinimumWorkingSetSize);

    OldIrql = MiLockPfnDb(APC_LEVEL);

    if (Delta > 0)
    {
        *OutIsAddMinSize = TRUE;

        /* Is increasing ok? */
        if (!IsIncreaseOkay)
        {
            DPRINT1("MmAdjustWorkingSetSizeEx: Privilege for WS size increase not held\n");
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            Status = STATUS_PRIVILEGE_NOT_HELD;
            goto Cleanup;
        }

        /* Check if the number of available pages is large enough */
        if ((SPFN_NUMBER)((Delta / (PAGE_SIZE / sizeof(ULONG)))) > (SPFN_NUMBER)(MmAvailablePages - 0x80))
        {
            DPRINT1("MmAdjustWorkingSetSizeEx: Not enough available pages\n");
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        /* Check if there are enough resident available pages */
        if (Delta > (MmResidentAvailablePages - MmSystemLockPagesCount - 0x100))
        {
            DPRINT1("MmAdjustWorkingSetSizeEx: Not enough resident pages\n");
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
    }

    /* Update resident available pages */
    if (Delta)
        InterlockedExchangeAddSizeT(&MmResidentAvailablePages, -Delta);

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    if (MaxWorkingSetSize < WorkingSetList->LastInitializedWsle &&
        MaxWorkingSetSize < WorkingSet->WorkingSetSize)
    {
        if (WorkingSetList->FirstDynamic + 8 >= MaxWorkingSetSize)
        {
            DPRINT1("MmAdjustWorkingSetSizeEx: STATUS_BAD_WORKING_SET_LIMIT\n");
            InterlockedExchangeAddSizeT(&MmResidentAvailablePages, Delta);
            Status = STATUS_BAD_WORKING_SET_LIMIT;
            goto Cleanup;
        }

        for (TrimAge = 2; ; TrimAge--)
        {
            ASSERT(TrimAge <= 2); // MI_PASS0_TRIM_AGE

            DPRINT1("MmAdjustWorkingSetSizeEx: FIXME MiTrimWorkingSet()\n");
            ASSERT(FALSE);
            //MiTrimWorkingSet((WorkingSet->WorkingSetSize - MaxWorkingSetSize), WorkingSet, TrimAge);

            if (WorkingSet->WorkingSetSize <= MaxWorkingSetSize)
                break;

            if (!TrimAge)
            {
                DPRINT1("MmAdjustWorkingSetSizeEx: STATUS_BAD_WORKING_SET_LIMIT\n");
                LimitIsGood = FALSE;
                Status = STATUS_BAD_WORKING_SET_LIMIT;
                break;
            }
        }
    }

    if ((LONG)WorkingSet->WorkingSetSize > (LONG)WorkingSet->MinimumWorkingSetSize)
        InterlockedExchangeAddSizeT(&MmPagesAboveWsMinimum, -((LONG)WorkingSet->WorkingSetSize - (LONG)WorkingSet->MinimumWorkingSetSize));

    if ((LONG)WorkingSet->WorkingSetSize > (LONG)MinWorkingSetSize)
        InterlockedExchangeAddSizeT(&MmPagesAboveWsMinimum, ((LONG)WorkingSet->WorkingSetSize - (LONG)MinWorkingSetSize));

    if (LimitIsGood)
    {
        WorkingSet->MaximumWorkingSetSize = MaxWorkingSetSize;
        WorkingSet->MinimumWorkingSetSize = MinWorkingSetSize;

        if (Flags)
        {
            OldIrql = MiAcquireExpansionLock();

            if (Flags & 4)
                WorkingSet->Flags.MinimumWorkingSetHard = 1;
            else if (Flags & 8)
                WorkingSet->Flags.MinimumWorkingSetHard = 0;

            if (Flags & 1)
                WorkingSet->Flags.MaximumWorkingSetHard = 1;
            else if (Flags & 2)
                WorkingSet->Flags.MaximumWorkingSetHard = 0;

            MiReleaseExpansionLock(OldIrql);
        }
    }
    else
    {
        InterlockedExchangeAddSizeT(&MmResidentAvailablePages, Delta);
    }

    ASSERT((WorkingSetList->FirstFree <= WorkingSetList->LastInitializedWsle) || (WorkingSetList->FirstFree == WSLE_NULL_INDEX));

Cleanup:

    if (IsSystemCache)
    {
        DPRINT1("MmAdjustWorkingSetSizeEx: FIXME\n");
        ASSERT(FALSE);
    }
    else
    {
        MiUnlockProcessWorkingSet(Process, Thread);
    }

    //MmUnlockPagableImageSection(ExPageLockHandle);
    return Status;
}

VOID
NTAPI
MiInitializeWorkingSetList(
    _In_ PEPROCESS CurrentProcess)
{
    PMMWSLE FirstWsle;
    PMMWSLE CurrentWsle;
    PMMPFN Pfn;
    ULONG WorkSetSize;
    ULONG WsleCount;
    ULONG ix;

    DPRINT("MiInitializeWorkingSetList: %p, %p, %p, %p\n", CurrentProcess, &CurrentProcess->Vm, CurrentProcess->Vm.VmWorkingSetList, MmWorkingSetList);

    CurrentWsle = FirstWsle = Add2Ptr(MmWorkingSetList, sizeof(MMWSL));

    MmWorkingSetList->LastEntry = CurrentProcess->Vm.MinimumWorkingSetSize;
    MmWorkingSetList->Wsle = FirstWsle;
    MmWorkingSetList->VadBitMapHint = 1;
    MmWorkingSetList->NumberOfImageWaiters = 0;
    MmWorkingSetList->HashTable = NULL;
    MmWorkingSetList->HashTableSize = 0;
    MmWorkingSetList->HashTableStart = (PVOID)((PCHAR)PAGE_ALIGN(&FirstWsle[MiMaximumWorkingSet]) + PAGE_SIZE);
    MmWorkingSetList->HighestPermittedHashAddress = Add2Ptr(MmHyperSpaceEnd, 1);

    CurrentWsle->u1.VirtualAddress = (PVOID)(PDE_BASE);
    CurrentWsle->u1.e1.Valid = 1;
    CurrentWsle->u1.e1.LockedInWs = 1;
    CurrentWsle->u1.e1.Direct = 1;

    Pfn = MiGetPfnEntry(MiAddressToPte((PVOID)PDE_BASE)->u.Hard.PageFrameNumber);

    ASSERT(Pfn->u1.WsIndex == 0);
    ASSERT(Pfn->u4.PteFrame == (ULONG_PTR)MiGetPfnEntryIndex(Pfn));

    Pfn->u1.Event = (PVOID)CurrentProcess;
    Pfn->u1.WsIndex = (CurrentWsle - FirstWsle);

    CurrentWsle++;

    CurrentWsle->u1.VirtualAddress = (PVOID)(MiAddressToPte(HYPER_SPACE));
    CurrentWsle->u1.e1.Valid = 1;
    CurrentWsle->u1.e1.LockedInWs = 1;
    CurrentWsle->u1.e1.Direct = 1;

    Pfn = MiGetPfnEntry(MiAddressToPte(CurrentWsle->u1.VirtualAddress)->u.Hard.PageFrameNumber);
    ASSERT(Pfn->u1.WsIndex == 0);
    Pfn->u1.WsIndex = (CurrentWsle - FirstWsle);

    CurrentWsle++;

    CurrentWsle->u1.VirtualAddress = (PVOID)(MI_VAD_BITMAP);
    CurrentWsle->u1.e1.Valid = 1;
    CurrentWsle->u1.e1.LockedInWs = 1;
    CurrentWsle->u1.e1.Direct = 1;

    Pfn = MiGetPfnEntry(MiAddressToPte((PVOID)(MI_VAD_BITMAP))->u.Hard.PageFrameNumber);
    ASSERT(Pfn->u1.WsIndex == 0);
    Pfn->u1.WsIndex = (CurrentWsle - FirstWsle);

    CurrentWsle++;

    CurrentWsle->u1.VirtualAddress = (PVOID)(MmWorkingSetList);
    CurrentWsle->u1.e1.Valid = 1;
    CurrentWsle->u1.e1.LockedInWs = 1;
    CurrentWsle->u1.e1.Direct = 1;

    Pfn = MiGetPfnEntry(MiAddressToPte((PVOID)(MmWorkingSetList))->u.Hard.PageFrameNumber);
    ASSERT(Pfn->u1.WsIndex == 0);
    Pfn->u1.WsIndex = (CurrentWsle - FirstWsle);

    CurrentWsle++;

    WsleCount = ((PAGE_SIZE - BYTE_OFFSET(FirstWsle)) / sizeof(MMWSLE));

    WorkSetSize = (CurrentWsle - FirstWsle);
    CurrentProcess->Vm.WorkingSetSize = WorkSetSize;

    MmWorkingSetList->FirstFree = WorkSetSize;
    MmWorkingSetList->FirstDynamic = WorkSetSize;
    MmWorkingSetList->NextSlot = WorkSetSize;

    ix = (WorkSetSize + 1);
    do
    {
        CurrentWsle->u1.Long = (ix * 0x10);
        CurrentWsle++;
        ix++;
    }
    while (ix <= WsleCount);

    CurrentWsle--;
    CurrentWsle->u1.Long = 0xFFFFFFF0;

    MmWorkingSetList->LastInitializedWsle = (WsleCount - 1);
    DPRINT("MiInitializeWorkingSetList: FirstFree %X, LastInitializedWsle %X\n", MmWorkingSetList->FirstFree, MmWorkingSetList->LastInitializedWsle);
}

VOID
NTAPI
MmQuerySystemCacheWorkingSetInformation(
    _Out_ SYSTEM_FILECACHE_INFORMATION* OutSci)
{
    PETHREAD Thread = PsGetCurrentThread();

    DPRINT("MmQuerySystemCacheWorkingSetInformation: OutSci %p\n", OutSci);

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    OutSci->Flags = 0;

    MiLockWorkingSet(Thread, &MmSystemCacheWs);

    OutSci->CurrentSize = (MmSystemCacheWs.WorkingSetSize * PAGE_SIZE);
    OutSci->PeakSize = (MmSystemCacheWs.PeakWorkingSetSize * PAGE_SIZE);

    OutSci->MinimumWorkingSet = MmSystemCacheWs.MinimumWorkingSetSize;
    OutSci->MaximumWorkingSet = MmSystemCacheWs.MaximumWorkingSetSize;

    OutSci->CurrentSizeIncludingTransitionInPages = (MmSystemCacheWs.WorkingSetSize + MmTransitionSharedPages);
    OutSci->PeakSizeIncludingTransitionInPages = MmTransitionSharedPagesPeak;

    OutSci->PageFaultCount = MmSystemCacheWs.PageFaultCount;
    OutSci->TransitionRePurposeCount = MmStandbyRePurposed;

    if (MmSystemCacheWs.Flags.MinimumWorkingSetHard)
        OutSci->Flags |= 4;

    if (MmSystemCacheWs.Flags.MaximumWorkingSetHard)
        OutSci->Flags |= 1;

    MiUnlockWorkingSet(Thread, &MmSystemCacheWs);
}

/* PUBLIC FUNCTIONS ***********************************************************/

NTSTATUS
NTAPI
MmAdjustWorkingSetSize(
    _In_ SIZE_T WorkingSetMinimumInBytes,
    _In_ SIZE_T WorkingSetMaximumInBytes,
    _In_ ULONG SystemCache,
    _In_ BOOLEAN IncreaseOkay)
{
    BOOLEAN dummy;

    return MmAdjustWorkingSetSizeEx(WorkingSetMinimumInBytes,
                                    WorkingSetMaximumInBytes,
                                    SystemCache,
                                    IncreaseOkay,
                                    0,
                                    &dummy);
}

/* EOF */
