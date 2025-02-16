
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "cc.h"
#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

ULONG CcDataFlushes;
ULONG CcDataPages;
ULONG CcFastMdlReadNotPossible;
ULONG CcFastMdlReadWait;
ULONG CcFastReadNotPossible;
ULONG CcFastReadNoWait;
ULONG CcFastReadResourceMiss;
ULONG CcFastReadWait;
ULONG CcLazyWriteIos;
ULONG CcLazyWritePages;
ULONG CcLazyWriteHotSpots;
ULONG CcMapDataWait;
ULONG CcMapDataNoWait;
ULONG CcPinMappedDataCount;
ULONG CcPinReadWait;
ULONG CcPinReadNoWait;
ULONG CcIdleDelayTick;

extern SHARED_CACHE_MAP_LIST_CURSOR CcDirtySharedCacheMapList;
extern LIST_ENTRY CcExpressWorkQueue;
extern LARGE_INTEGER CcNoDelay;
extern ULONG CcTotalDirtyPages;
extern LAZY_WRITER LazyWriter;
extern LIST_ENTRY CcDeferredWrites;
extern ULONG CcPagesYetToWrite;
extern LIST_ENTRY CcCleanSharedCacheMapList;

/* FUNCTIONS ******************************************************************/

BOOLEAN
NTAPI
CcFindBcb(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ PLARGE_INTEGER FileOffset,
    _In_ PLARGE_INTEGER EndFileOffset,
    _Out_ PCC_BCB* OutBcb)
{
    PLIST_ENTRY NextBcbList;
    PCC_BCB Bcb;
    BOOLEAN Result = FALSE;

    DPRINT("CcFindBcb: %p, [%I64X], [%I64X]\n",
           SharedMap, (FileOffset ? FileOffset->QuadPart : 0ll), (EndFileOffset ? EndFileOffset->QuadPart : 0ll));

    NextBcbList = CcGetBcbListHead(SharedMap, (FileOffset->QuadPart + BCB_MAPPING_GRANULARITY), TRUE);

    DPRINT("CcFindBcb: NextBcbList %p\n", NextBcbList);

    Bcb = CONTAINING_RECORD(NextBcbList->Flink, CC_BCB, Link);

    DPRINT("CcFindBcb: Bcb %p, NodeTypeCode %X\n", Bcb, Bcb->NodeTypeCode);

    if (!FileOffset->HighPart && !Bcb->BeyondLastByte.HighPart)
    {
        while (Bcb->NodeTypeCode == NODE_TYPE_BCB)
        {
            if (FileOffset->LowPart >= Bcb->BeyondLastByte.LowPart)
                break;

            if (FileOffset->LowPart >= Bcb->FileOffset.LowPart)
            {
                Result = TRUE;
                break;
            }

            if (EndFileOffset->LowPart >= Bcb->FileOffset.LowPart)
                EndFileOffset->LowPart = Bcb->FileOffset.LowPart;

            Bcb = CONTAINING_RECORD(Bcb->Link.Flink, CC_BCB, Link);
        }
    }
    else
    {
        while (Bcb->NodeTypeCode == NODE_TYPE_BCB)
        {
            if (FileOffset->QuadPart >= Bcb->BeyondLastByte.QuadPart)
                break;

            DPRINT1("CcFindBcb: FIXME\n");
            ASSERT(FALSE);
        }
    }

    *OutBcb = Bcb;

    return Result;
}

VOID
NTAPI
CcDeallocateBcb(
    _In_ PCC_BCB Bcb)
{
    if (Bcb->NodeTypeCode == NODE_TYPE_BCB)
        ExDeleteResourceLite(&Bcb->BcbResource);

    ExFreePool(Bcb);
}

PCC_BCB
NTAPI
CcAllocateInitializeBcb(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ PCC_BCB NextBcb,
    _In_ PLARGE_INTEGER FileOffset,
    _In_ PLARGE_INTEGER Length)
{
    PCC_BCB Bcb;

    DPRINT("CcAllocateInitializeBcb: %p, [%I64X]\n", SharedMap, (FileOffset ? FileOffset->QuadPart : 0ll));

    Bcb = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Bcb), 'cBcC');
    if (!Bcb)
    {
        DPRINT1("CcAllocateInitializeBcb: ExAllocatePoolWithTag() failed\n");
        return NULL;
    }

    RtlZeroMemory(Bcb, sizeof(*Bcb));

    if (!SharedMap)
        return Bcb;

    Bcb->NodeTypeCode = NODE_TYPE_BCB;
    Bcb->PinCount++;

    Bcb->Length = Length->LowPart;
    Bcb->FileOffset.QuadPart = FileOffset->QuadPart;
    Bcb->BeyondLastByte.QuadPart = (FileOffset->QuadPart + Length->QuadPart);

    ExInitializeResourceLite(&Bcb->BcbResource);
    Bcb->SharedCacheMap = SharedMap;

    KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);

    InsertTailList(&NextBcb->Link, &Bcb->Link);

    ASSERT((SharedMap->SectionSize.QuadPart < CACHE_OVERALL_SIZE) ||
           (CcFindBcb(SharedMap, FileOffset, &Bcb->BeyondLastByte, &NextBcb) && (Bcb == NextBcb)));

    if (SharedMap->SectionSize.QuadPart > CACHE_OVERALL_SIZE &&
        (SharedMap->Flags & SHARE_FL_MODIFIED_NO_WRITE))
    {
        CcAdjustVacbLevelLockCount(SharedMap, FileOffset->QuadPart, 1);
    }

    KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[4]);

    if (SharedMap->Flags & 2)
    {
        DPRINT1("CcAllocateInitializeBcb: FIXME\n");
        ASSERT(FALSE);
    }

    return Bcb;
}

PBITMAP_RANGE
NTAPI
CcFindBitmapRangeToClean(
    _In_ PMBCB Mbcb,
    _In_ LONGLONG DirtyPage)
{
    PBITMAP_RANGE CurrentRange;

    DPRINT("CcFindBitmapRangeToClean: Mbcb %p, DirtyPage %I64X\n", Mbcb, DirtyPage);

    CurrentRange = CONTAINING_RECORD(Mbcb->BitmapRanges.Flink, BITMAP_RANGE, Links);

    do
    {
        if (&CurrentRange->Links == &Mbcb->BitmapRanges)
        {
            ASSERT(DirtyPage != 0);
            DirtyPage = 0;
        }
        else if (DirtyPage <= (CurrentRange->BasePage + CurrentRange->LastDirtyPage))
        {
            if (CurrentRange->DirtyPages)
                return CurrentRange;
        }

        CurrentRange = CONTAINING_RECORD(CurrentRange->Links.Flink, BITMAP_RANGE, Links);
    }
    while (TRUE);
}

BOOLEAN
NTAPI
CcAcquireByteRangeForWrite(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ PLARGE_INTEGER Offset,
    _In_ ULONG Length,
    _Out_ PLARGE_INTEGER OutFileOffset,
    _Out_ ULONG* OutLength,
    _Out_ PVOID* OutBcb)
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PBITMAP_RANGE BitmapRange;
    PLARGE_INTEGER FileOffset;
    LARGE_INTEGER EndFileOffset;
    LONGLONG CurrentPage;
    LONGLONG LastPage = 0x7FFFFFFFFFFFFFFF;
    PULONG pBitmap;
    PULONG pEndBitmap;
    PCC_BCB Bcb;
    PMBCB Mbcb;
    ULONG BitMask;
    ULONG OriginalFirstDirtyPage;
    BOOLEAN FindType = FALSE;
    BOOLEAN Result = FALSE;

    DPRINT("CcAcquireByteRangeForWrite: SharedMap %p, Length %X\n", SharedMap, Length);

    OutFileOffset->QuadPart = 0;
    *OutLength = 0;

    KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, &LockHandle);

    Mbcb = SharedMap->Mbcb;

    if (Mbcb && Mbcb->DirtyPages && (Mbcb->PagesToWrite || Length))
    {
        DPRINT("CcAcquireByteRangeForWrite: Mbcb %p, OutLength %X\n", Mbcb, Length);

        if (Offset)
        {
            CurrentPage = (Offset->QuadPart / PAGE_SIZE);
            LastPage = ((Offset->QuadPart + Length - 1) / PAGE_SIZE);

            BitmapRange = CcFindBitmapRangeToClean(Mbcb, CurrentPage);

            if (LastPage < (BitmapRange->BasePage + BitmapRange->FirstDirtyPage) ||
                CurrentPage > (BitmapRange->BasePage + BitmapRange->LastDirtyPage))
            {
                goto FindBcb;
            }

            if (LastPage < (BitmapRange->BasePage + BitmapRange->LastDirtyPage))
            {
                pEndBitmap = &BitmapRange->Bitmap[(ULONG)(LastPage - BitmapRange->BasePage) / 32];
                DPRINT("CcAcquireByteRangeForWrite: pEndBitmap %p\n", pEndBitmap);
            }
            else
            {
                pEndBitmap = &BitmapRange->Bitmap[BitmapRange->LastDirtyPage / 32];
                DPRINT("CcAcquireByteRangeForWrite: pEndBitmap %p\n", pEndBitmap);
            }
        }
        else
        {
            if (!Length)
                CurrentPage = Mbcb->ResumeWritePage;
            else
                CurrentPage = 0;

            BitmapRange = CcFindBitmapRangeToClean(Mbcb, CurrentPage);

            if (CurrentPage > (BitmapRange->BasePage + BitmapRange->LastDirtyPage))
                CurrentPage = (BitmapRange->BasePage + BitmapRange->FirstDirtyPage);

            pEndBitmap = &BitmapRange->Bitmap[BitmapRange->LastDirtyPage / 32];
            DPRINT("CcAcquireByteRangeForWrite: pEndBitmap %p\n", pEndBitmap);
        }

        if (CurrentPage < (BitmapRange->BasePage + BitmapRange->FirstDirtyPage))
            CurrentPage = (BitmapRange->BasePage + BitmapRange->FirstDirtyPage);

        pBitmap = &BitmapRange->Bitmap[(ULONG)(CurrentPage - BitmapRange->BasePage) / 32];
        BitMask = (-1 << (CurrentPage % 32));

        OriginalFirstDirtyPage = (ULONG)(CurrentPage - BitmapRange->BasePage);

        if (!(*pBitmap & BitMask))
        {
            BitMask = 0xFFFFFFFF;
            CurrentPage &= ~0x1F;

            do
            {
                pBitmap++;
                CurrentPage += 32;

                if (pBitmap <= pEndBitmap)
                    continue;

                if (!Length)
                {
                    ASSERT(OriginalFirstDirtyPage >= BitmapRange->FirstDirtyPage);
                    BitmapRange->LastDirtyPage = (OriginalFirstDirtyPage - 1);
                }

                do
                {
                    BitmapRange = CONTAINING_RECORD(BitmapRange->Links.Flink, BITMAP_RANGE, Links);

                    if (&BitmapRange->Links == &Mbcb->BitmapRanges)
                    {
                        if (Length)
                            goto FindBcb;

                        BitmapRange = CONTAINING_RECORD(BitmapRange->Links.Flink, BITMAP_RANGE, Links);
                    }
                }
                while (!BitmapRange->DirtyPages);

                if ((LastPage < (BitmapRange->BasePage + BitmapRange->FirstDirtyPage)) ||
                    (CurrentPage > (BitmapRange->BasePage + BitmapRange->LastDirtyPage)))
                {
                    goto FindBcb;
                }

                pBitmap = &BitmapRange->Bitmap[BitmapRange->FirstDirtyPage / 32];
                pEndBitmap = &BitmapRange->Bitmap[BitmapRange->LastDirtyPage / 32];

                CurrentPage = (BitmapRange->BasePage + (BitmapRange->FirstDirtyPage & ~0x1F));
                OriginalFirstDirtyPage = BitmapRange->FirstDirtyPage;
            }
            while (!(*pBitmap));
        }

        BitMask = (~BitMask + 1);

        while (!(*pBitmap & BitMask))
        {
            BitMask <<= 1;
            CurrentPage++;
        }

        if (!Offset)
            goto Finish;

        if (CurrentPage >= ((Offset->QuadPart + Length + (PAGE_SIZE - 1)) / PAGE_SIZE))
            goto FindBcb;

        if (IsListEmpty(&SharedMap->BcbList))
            goto Finish;

        FindType = TRUE;
        goto FindBcb;
    }

FindBcb:

    while (TRUE)
    {
        Bcb = CONTAINING_RECORD(SharedMap->BcbList.Blink, CC_BCB, Link);

        if (SharedMap->Flags & SHARE_FL_MODIFIED_NO_WRITE)
        {
            if (Offset)
                FileOffset = Offset;
            else
                FileOffset = (PLARGE_INTEGER)&SharedMap->BeyondLastFlush;

            if (FileOffset->QuadPart)
            {
                EndFileOffset.QuadPart = (FileOffset->QuadPart + PAGE_SIZE);

                if (!CcFindBcb(SharedMap, FileOffset, &EndFileOffset, &Bcb))
                    Bcb = CONTAINING_RECORD(Bcb->Link.Blink, CC_BCB, Link);
            }
        }

        while (&Bcb->Link != &SharedMap->BcbList)
        {
            if (Bcb->NodeTypeCode != NODE_TYPE_BCB)
            {
                Bcb = CONTAINING_RECORD(Bcb->Link.Blink, CC_BCB, Link);
                continue;
            }

            if (Offset && ((Offset->QuadPart + Length) <= Bcb->FileOffset.QuadPart))
                break;

            if (*OutLength)
            {
                if (!Bcb->Reserved1[0] ||
                    Bcb->FileOffset.QuadPart != (OutFileOffset->QuadPart + *OutLength) ||
                    (*OutLength + Bcb->Length) > 0x10000 ||
                    Bcb->PinCount ||
                    !(Bcb->FileOffset.QuadPart & (0x2000000 - 1)))
                {
                    break;
                }
            }
            else if (!Bcb->Reserved1[0] ||
                     (Offset && Offset->QuadPart >= Bcb->BeyondLastByte.QuadPart) ||
                     (!Offset && Bcb->FileOffset.QuadPart < SharedMap->BeyondLastFlush))
            {
                Bcb = CONTAINING_RECORD(Bcb->Link.Blink, CC_BCB, Link);
                continue;
            }
            else if (FindType && CurrentPage <= (ULONG)(Bcb->FileOffset.QuadPart / PAGE_SIZE))
            {
                goto Finish;
            }

            Bcb->PinCount++;

            KeReleaseInStackQueuedSpinLock(&LockHandle);

            if ((SharedMap->Flags & SHARE_FL_MODIFIED_NO_WRITE) && !(SharedMap->Flags & 0x2))
            {
                if (!ExAcquireResourceExclusiveLite(&Bcb->BcbResource, (*OutLength == 0)))
                {
                    CcUnpinFileDataEx(Bcb, TRUE, 0);
                    KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, &LockHandle);
                    break;
                }

                KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, &LockHandle);

                if (!Bcb->Reserved1[0])
                {
                    KeReleaseInStackQueuedSpinLock(&LockHandle);
                    CcUnpinFileDataEx(Bcb, FALSE, 0);
                    KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, &LockHandle);

                    if (*OutLength)
                        break;

                    Bcb = CONTAINING_RECORD(SharedMap->BcbList.Blink, CC_BCB, Link);
                    continue;
                }
            }
            else
            {
                CcUnpinFileDataEx(Bcb, TRUE, 2);
                KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, &LockHandle);
            }

            FindType = FALSE;

            if (!(*OutLength))
                *OutFileOffset = Bcb->FileOffset;

            *OutBcb = Bcb;
            *OutLength += Bcb->Length;

            if (SharedMap->FlushToLsnRoutine)
            {
                DPRINT1("CcAcquireByteRangeForWrite: FIXME\n");
                ASSERT(FALSE);
            }

            Bcb = CONTAINING_RECORD(Bcb->Link.Blink, CC_BCB, Link);
        }

        if (FindType)
        {
            ASSERT(*OutLength == 0);
            goto Finish;
        }

        if (*OutLength)
        {
            if (Offset)
                break;

            SharedMap->BeyondLastFlush = (*OutLength + OutFileOffset->QuadPart);

            if (SharedMap->PagesToWrite > (*OutLength / PAGE_SIZE))
                SharedMap->PagesToWrite -= (*OutLength / PAGE_SIZE);
            else
                SharedMap->PagesToWrite = 0;

            break;
        }

        if (!SharedMap->BeyondLastFlush || Offset)
            break;

        SharedMap->BeyondLastFlush = 0;
    }

    KeReleaseInStackQueuedSpinLock(&LockHandle);

    if (*OutLength)
        Result = TRUE;

    return Result;

Finish:

    while (*pBitmap & BitMask)
    {
        if (*OutLength >= 0x10)
            break;

        if (Offset && ((*OutLength + CurrentPage) >= (ULONG)((Offset->QuadPart + Length + (PAGE_SIZE - 1)) / PAGE_SIZE)))
            break;

        ASSERT(pBitmap <= (&BitmapRange->Bitmap[BitmapRange->LastDirtyPage / 32]));
        *pBitmap -= BitMask;

        *OutLength = (*OutLength + 1);

        BitMask <<= 1;
        if (BitMask)
            continue;

        BitMask = 1;

        pBitmap++;
        if (pBitmap > pEndBitmap)
            break;
    }

    if (Mbcb->PagesToWrite > *OutLength)
        Mbcb->PagesToWrite -= *OutLength;
    else
        Mbcb->PagesToWrite = 0;

    ASSERT(Mbcb->DirtyPages >= *OutLength);

    Mbcb->DirtyPages -= *OutLength;
    BitmapRange->DirtyPages -= *OutLength;

    KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueMasterLock]);

    CcTotalDirtyPages -= (*OutLength);
    SharedMap->DirtyPages -= (*OutLength);

    if (CcPagesYetToWrite > *OutLength)
        CcPagesYetToWrite -= *OutLength;
    else
        CcPagesYetToWrite = 0;

    if (!SharedMap->DirtyPages)
    {
        RemoveEntryList(&SharedMap->SharedCacheMapLinks);

        if (KdDebuggerEnabled && !KdDebuggerNotPresent &&
            !SharedMap->OpenCount &&
            !SharedMap->DirtyPages)
        {
            DPRINT1("CC: SharedMap->OpenCount == 0 && DirtyPages == 0 && going onto CleanList!\n");
            DbgBreakPoint();
        }

        InsertTailList(&CcCleanSharedCacheMapList, &SharedMap->SharedCacheMapLinks);
    }

    KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueMasterLock]);

    if (!BitmapRange->DirtyPages)
    {
        BitmapRange->FirstDirtyPage = 0xFFFFFFFF;
        BitmapRange->LastDirtyPage = 0;

        Mbcb->ResumeWritePage = (BitmapRange->BasePage + PAGE_SIZE);
    }
    else
    {
        if (BitmapRange->FirstDirtyPage == OriginalFirstDirtyPage)
            BitmapRange->FirstDirtyPage = ((ULONG)(CurrentPage - BitmapRange->BasePage) + *OutLength);

        if (!Length)
            Mbcb->ResumeWritePage = (CurrentPage + *OutLength);
    }

    if (IsListEmpty(&SharedMap->BcbList))
        SharedMap->PagesToWrite = Mbcb->PagesToWrite;

    KeReleaseInStackQueuedSpinLock(&LockHandle);

    OutFileOffset->QuadPart = ((LONGLONG)CurrentPage * PAGE_SIZE);

    *OutLength *= PAGE_SIZE;
    *OutBcb = NULL;

    return TRUE;
}

BOOLEAN
NTAPI
CcMapAndRead(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ PLARGE_INTEGER FileOffset,
    _In_ ULONG Length,
    _In_ ULONG Flags,
    _In_ BOOLEAN SkipNotCached,
    _In_ PVOID BaseAddress)
{
    PETHREAD Thread = PsGetCurrentThread();
    ULONG ReadPages;
    ULONG Mask = 1;
    ULONG OldReadClusterSize;
    UCHAR OldForwardClusterOnly;
    BOOLEAN Result = FALSE;

    DPRINT("CcMapAndRead: SharedMap %p, Length %X\n", SharedMap, Length);

    /* Save previous values */
    OldForwardClusterOnly = Thread->ForwardClusterOnly;
    OldReadClusterSize = Thread->ReadClusterSize;

    //_SEH2_TRY
    {
        ReadPages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(BaseAddress, Length);

        while (ReadPages)
        {
            Thread->ForwardClusterOnly = 1;

            if (ReadPages <= 0x10)
               Thread->ReadClusterSize = (ReadPages - 1);
            else
               Thread->ReadClusterSize = 0xF;

            if (!(Flags & Mask) || !MmCheckCachedPageState(BaseAddress, TRUE))
            {
                if (!MmCheckCachedPageState(BaseAddress, FALSE) && !SkipNotCached)
                {
                    Result = FALSE;
                    goto Exit;
                }
            }

            BaseAddress = Add2Ptr(BaseAddress, PAGE_SIZE);
            ReadPages--;

            if (ReadPages == 1)
                Mask = 4;
            else
                Mask = 2;
        }

        Result = TRUE;

Exit:
        ;
    }
    //_SEH2_FINALLY
    {
        /* Restore claster variables */
        Thread->ForwardClusterOnly = OldForwardClusterOnly;
        Thread->ReadClusterSize = OldReadClusterSize;
    }
    //_SEH2_END;

    return Result;
}

VOID
NTAPI
CcReleaseByteRangeFromWrite(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ PLARGE_INTEGER FileOffset,
    _In_ ULONG Length,
    _In_ PCC_BCB FirstBcb,
    _In_ BOOLEAN IsSetDirty)
{
    LARGE_INTEGER CurrentOffset;
    PCC_BCB CurrentBcb;
    PCC_BCB NextBcb;
    BOOLEAN IsNoWrite;

    DPRINT("CcReleaseByteRangeFromWrite: FirstBcb %p, IsSetDirty %X\n", FirstBcb, IsSetDirty);

    if (!FirstBcb)
    {
        ASSERT(Length != 0);

        if (IsSetDirty)
            CcSetDirtyInMask(SharedMap, FileOffset, Length);

        return;
    }

    ASSERT(FirstBcb->NodeTypeCode == NODE_TYPE_BCB);

    CurrentBcb = FirstBcb;

    do
    {
        NextBcb = CONTAINING_RECORD(CurrentBcb->Link.Flink, CC_BCB, Link);

        if (CurrentBcb->NodeTypeCode == NODE_TYPE_BCB)
        {
            CurrentOffset = CurrentBcb->FileOffset;

            if (SharedMap->Flags & SHARE_FL_MODIFIED_NO_WRITE)
            {
                IsNoWrite = ((SharedMap->Flags & 0x2) != 0);
                CcUnpinFileDataEx(CurrentBcb, IsNoWrite, 2);
            }

            if (IsSetDirty)
                CcSetDirtyPinnedData(CurrentBcb, NULL);

            CcUnpinFileDataEx(CurrentBcb, TRUE, 0);
        }

        CurrentBcb = NextBcb;
    }
    while (FileOffset->QuadPart != CurrentOffset.QuadPart);
}

/* PUBLIC FUNCTIONS ***********************************************************/

VOID
NTAPI
CcFlushCache(
    _In_ PSECTION_OBJECT_POINTERS SectionObjectPointers,
    _In_ PLARGE_INTEGER FileOffset OPTIONAL,
    _In_ ULONG Length,
    _Out_ IO_STATUS_BLOCK* OutIoStatus OPTIONAL)
{
    PSHARED_CACHE_MAP SharedMap;
    IO_STATUS_BLOCK ioStatus;
    LARGE_INTEGER fileSize;
    LARGE_INTEGER TickCount;
    LARGE_INTEGER EndTickCount;
    PFSRTL_COMMON_FCB_HEADER FcbHeader;
    PVACB Vacb = NULL;
    ULONG TotalFlushed = 0;
    ULONG Flags;
    ULONG Size;
    ULONG ActivePage;
    ULONG Start = 0;
    ULONG End = 0xFFFFFFFF;
    BOOLEAN IsSaveStatus = FALSE;
    BOOLEAN IsLazyWrite = FALSE;
    BOOLEAN PendingTeardown = FALSE;
    BOOLEAN IsFreeVacb = FALSE;
    BOOLEAN IsNotSuccess = FALSE;
    BOOLEAN IsVacbLocked;
    KIRQL OldIrql;
    NTSTATUS Status;

    if (!OutIoStatus)
        OutIoStatus = &ioStatus;

    OutIoStatus->Status = STATUS_SUCCESS;
    OutIoStatus->Information = 0;

    if (FileOffset == &CcNoDelay)
    {
        FileOffset = NULL;
        IsLazyWrite = TRUE;
        OutIoStatus->Status = STATUS_VERIFY_REQUIRED;
        Flags = 2;
    }
    else
    {
        Flags = 1;
    }

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    SharedMap = SectionObjectPointers->SharedCacheMap;

    DPRINT("CcFlushCache: %p, %I64X, %X\n", SharedMap, (FileOffset?FileOffset->QuadPart:0), Length);

    if (SharedMap)
    {
        if (IsLazyWrite && (SharedMap->Flags & SHARE_FL_WAITING_TEARDOWN))
        {
            Flags &= ~2;
            PendingTeardown = TRUE;
        }

        if (SharedMap->Flags & 0x2000)
        {
            if (!((ULONG_PTR)FileOffset & 1))
            {
                KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
                return;
            }

            FileOffset = (PLARGE_INTEGER)((ULONG_PTR)FileOffset ^ 1);
        }

        if (SharedMap->FileObject->DeviceObject &&
            SharedMap->FileObject->DeviceObject->DeviceType == FILE_DEVICE_CD_ROM)
        {
            Flags &= ~2;
        }
    }

    if (FileOffset && !Length)
    {
        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
        return;
    }

    if (SharedMap)
    {
        SharedMap->OpenCount++;

        if (SharedMap->NeedToZero || SharedMap->ActiveVacb)
        {
            if (FileOffset)
            {
                Start = (FileOffset->QuadPart / PAGE_SIZE);
                End = ((FileOffset->QuadPart + Length - 1) / PAGE_SIZE);
            }

            if (SharedMap->ValidDataGoal.QuadPart < ((End + 1LL) * PAGE_SIZE) ||
                (SharedMap->NeedToZero && SharedMap->NeedToZeroPage >= Start && SharedMap->NeedToZeroPage <= End) ||
                (SharedMap->ActiveVacb && SharedMap->ActivePage >= Start && SharedMap->ActivePage <= End))
            {
                KeAcquireSpinLockAtDpcLevel(&SharedMap->ActiveVacbSpinLock);

                Vacb = SharedMap->ActiveVacb;
                if (Vacb)
                {
                    ActivePage = SharedMap->ActivePage;
                    SharedMap->ActiveVacb = NULL;
                    IsVacbLocked = ((SharedMap->Flags & SHARE_FL_VACB_LOCKED) != 0);
                }

                KeReleaseSpinLockFromDpcLevel(&SharedMap->ActiveVacbSpinLock);

                IsFreeVacb = TRUE;
            }
        }
    }

    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    if (IsFreeVacb)
        CcFreeActiveVacb(SharedMap, Vacb, ActivePage, IsVacbLocked);

    if (SharedMap)
        FcbHeader = SharedMap->FileObject->FsContext;

    if (!SharedMap ||
        (FcbHeader->Flags & FSRTL_FLAG_USER_MAPPED_FILE) ||
        (SharedMap->Flags & 0x20000))
    {
        if (!IsLazyWrite)
        {
            MmFlushSection(SectionObjectPointers, FileOffset, Length, OutIoStatus, 1);

            ASSERT(OutIoStatus->Status != STATUS_ENCOUNTERED_WRITE_IN_PROGRESS);

            if (!NT_SUCCESS(OutIoStatus->Status) &&
                OutIoStatus->Status != STATUS_VERIFY_REQUIRED &&
                OutIoStatus->Status != STATUS_FILE_LOCK_CONFLICT &&
                OutIoStatus->Status != STATUS_ENCOUNTERED_WRITE_IN_PROGRESS)
            {
                IsSaveStatus = TRUE;
                Status = OutIoStatus->Status;
            }
        }
    }

    if (!SharedMap)
        goto Exit;

    if (!IsLazyWrite && !FileOffset)
        SharedMap->ValidDataLength = SharedMap->ValidDataGoal;

    if (FileOffset)
        fileSize.QuadPart = FileOffset->QuadPart;

    if (Length)
        Size = Length;
    else
        Size = 1;

    if (IsLazyWrite)
    {
        KeQueryTickCount(&EndTickCount);
        EndTickCount.QuadPart += CcIdleDelayTick;
    }

    while (TRUE)
    {
        PLARGE_INTEGER offset;
        PVOID Address;
        PVOID Bcb;
        LARGE_INTEGER OffsetForFlush;
        ULONG MappedLength;
        ULONG HotSpot;
        ULONG length;
        ULONG size;
        BOOLEAN IsHotSpot;
        BOOLEAN IsSetDirty;

        if (!SharedMap->PagesToWrite && IsLazyWrite && !PendingTeardown)
            break;

        if (!SharedMap->FileSize.QuadPart && !(SharedMap->Flags & SHARE_FL_PIN_ACCESS))
            break;

        if (IsNotSuccess)
            break;

        if (!IsLazyWrite || PendingTeardown)
            length = Size;
        else
            length = 0;

        if (!IsLazyWrite || PendingTeardown)
            offset = (FileOffset ? &fileSize : NULL);
        else
            offset = NULL;

        if (!CcAcquireByteRangeForWrite(SharedMap, offset, length, &OffsetForFlush, &Size, &Bcb))
            break;

        size = Size;
        HotSpot = 0;

        do
        {
            Address = CcGetVirtualAddressIfMapped(SharedMap,
                                                  (OffsetForFlush.QuadPart + Size - size),
                                                  &Vacb,
                                                  &MappedLength);
            if (Address)
            {
                if (MappedLength > size)
                    MappedLength = size;

                IsHotSpot = ((MmSetAddressRangeModified(Address, MappedLength) || HotSpot) &&
                             SharedMap->ValidDataLength.QuadPart > (OffsetForFlush.QuadPart + Size) &&
                             (SharedMap->LazyWritePassCount & 0xF) &&
                             IsLazyWrite &&
                             !PendingTeardown &&
                             !(SharedMap->Flags & 0x200));

                HotSpot = (ULONG)IsHotSpot;

                CcFreeVirtualAddress(Vacb);
            }
            else if (MappedLength > size)
            {
                MappedLength = size;
            }

            size -= MappedLength;
        }
        while (size);

        CcLazyWriteHotSpots += HotSpot;

        if (!HotSpot)
        {
            ULONG CurrentSize;

            MmFlushSection(SharedMap->FileObject->SectionObjectPointer, &OffsetForFlush, Size, OutIoStatus, Flags);

            if (!NT_SUCCESS(OutIoStatus->Status))
            {
                DPRINT1("CcFlushCache: SharedMap %p, Status %X\n", SharedMap, OutIoStatus->Status);

                CurrentSize = Size;

                if (OutIoStatus->Status == STATUS_ENCOUNTERED_WRITE_IN_PROGRESS)
                {
                    IsSetDirty = TRUE;
                }
                else if (OutIoStatus->Status == STATUS_VERIFY_REQUIRED ||
                         OutIoStatus->Status == STATUS_FILE_LOCK_CONFLICT)
                {
                    IsNotSuccess = TRUE;
                    IsSetDirty = TRUE;
                }
                else
                {
                    do
                    {
                        MmFlushSection(SharedMap->FileObject->SectionObjectPointer, &OffsetForFlush, PAGE_SIZE, OutIoStatus, Flags);

                        if (NT_SUCCESS(OutIoStatus->Status))
                        {
                            OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
                            SharedMap->Flags |= 0x400;
                            KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
                        }
                        else if (OutIoStatus->Status != STATUS_VERIFY_REQUIRED &&
                                 OutIoStatus->Status != STATUS_FILE_LOCK_CONFLICT &&
                                 OutIoStatus->Status != STATUS_ENCOUNTERED_WRITE_IN_PROGRESS)
                        {
                            DPRINT1("CcFlushCache: SharedMap %p, Status %X\n", SharedMap, OutIoStatus->Status);
                            IsSaveStatus = TRUE;
                            Status = OutIoStatus->Status;
                        }

                        if (!IsNotSuccess)
                        {
                            if (OutIoStatus->Status == STATUS_VERIFY_REQUIRED ||
                                OutIoStatus->Status == STATUS_FILE_LOCK_CONFLICT ||
                                OutIoStatus->Status == STATUS_ENCOUNTERED_WRITE_IN_PROGRESS)
                            {
                                IsNotSuccess = TRUE;
                            }
                        }

                        OffsetForFlush.QuadPart += PAGE_SIZE;
                        CurrentSize -= PAGE_SIZE;
                    }
                    while (CurrentSize);

                    if (IsNotSuccess)
                        IsSetDirty = TRUE;
                    else
                        IsSetDirty = FALSE;
                }
            }
            else
            {
                if (!(SharedMap->Flags & 0x400))
                {
                    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
                    SharedMap->Flags |= 0x400;
                    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
                }

                if (IsLazyWrite)
                {
                    CcLazyWriteIos++;
                    CcLazyWritePages += (Size + (PAGE_SIZE - 1)) / PAGE_SIZE;
                }

                IsSetDirty = FALSE;
            }
        }
        else
        {
            IsSetDirty = TRUE;
        }

        CcReleaseByteRangeFromWrite(SharedMap, &OffsetForFlush, Size, Bcb, IsSetDirty);

        TotalFlushed += Size;

        if (TotalFlushed >= 0x40000 && !IsListEmpty(&CcDeferredWrites))
        {
            CcPostDeferredWrites();
            TotalFlushed = 0;
        }

        if (IsLazyWrite && !PendingTeardown)
        {
            KeQueryTickCount(&TickCount);

            if (TickCount.QuadPart > EndTickCount.QuadPart)
            {
                OutIoStatus->Information = 0x8A5E;
                break;
            }
        }

        if (FileOffset)
        {
            DPRINT1("CcFlushCache: FIXME\n");
            ASSERT(FALSE);
        }
    }

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    SharedMap->OpenCount--;

    if (!SharedMap->OpenCount &&
        !(SharedMap->Flags & SHARE_FL_WRITE_QUEUED) &&
        !SharedMap->DirtyPages)
    {
        RemoveEntryList(&SharedMap->SharedCacheMapLinks);
        InsertTailList(&CcDirtySharedCacheMapList.SharedCacheMapLinks, &SharedMap->SharedCacheMapLinks);

        LazyWriter.OtherWork = TRUE;

        if (!LazyWriter.ScanActive)
            CcScheduleLazyWriteScan(FALSE);
    }

    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

Exit:

    if (IsSaveStatus)
        OutIoStatus->Status = Status;
}

LARGE_INTEGER
NTAPI
CcGetFlushedValidData(
    _In_ PSECTION_OBJECT_POINTERS SectionObjectPointers,
    _In_ BOOLEAN CcInternalCaller)
{
    LARGE_INTEGER ValidDataLength;
    PSHARED_CACHE_MAP SharedMap;
    PBITMAP_RANGE BitmapRange;
    PCC_BCB Bcb;
    PMBCB Mbcb;

    DPRINT("CcGetFlushedValidData: %p, %X\n", SectionObjectPointers, CcInternalCaller);

    if (CcInternalCaller)
    {
        SharedMap = SectionObjectPointers->SharedCacheMap;
    }
    else
    {
        DPRINT1("CcGetFlushedValidData: FIXME\n");
        ASSERT(FALSE);
    }

    ASSERT(SharedMap != NULL);

    ValidDataLength.QuadPart = SharedMap->ValidDataGoal.QuadPart;

    if (SharedMap->DirtyPages)
    {
        Mbcb = SharedMap->Mbcb;

        if (Mbcb && Mbcb->DirtyPages)
        {
            BitmapRange = CcFindBitmapRangeToClean(Mbcb, 0);
            ASSERT(BitmapRange->FirstDirtyPage != MAXULONG);

            ValidDataLength.QuadPart = ((BitmapRange->BasePage + BitmapRange->FirstDirtyPage) * PAGE_SIZE);
        }

        for (Bcb = CONTAINING_RECORD(SharedMap->BcbList.Flink, CC_BCB, Link);
             &Bcb->Link != &SharedMap->BcbList;
             Bcb = CONTAINING_RECORD(Bcb->Link.Flink, CC_BCB, Link))
        {
            if (Bcb->NodeTypeCode == NODE_TYPE_BCB && Bcb->Reserved1[0])
                break;
        }

        if (&Bcb->Link != &SharedMap->BcbList)
        {
            if (ValidDataLength.QuadPart > Bcb->FileOffset.QuadPart)
                ValidDataLength.QuadPart = Bcb->FileOffset.QuadPart;
        }
    }

    if (CcInternalCaller)
        return ValidDataLength;

    DPRINT1("CcGetFlushedValidData: FIXME\n");
    ASSERT(FALSE);

    return ValidDataLength;
}

PVOID
NTAPI
CcRemapBcb(IN PVOID Bcb)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

VOID
NTAPI
CcRepinBcb(
    _In_ PVOID InBcb)
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PCC_BCB Bcb = InBcb;

    KeAcquireInStackQueuedSpinLock(&Bcb->SharedCacheMap->BcbSpinLock, &LockHandle);
    Bcb->PinCount++;
    KeReleaseInStackQueuedSpinLock(&LockHandle);
}

VOID
NTAPI
CcScheduleReadAhead(
    _In_ PFILE_OBJECT FileObject,
    _In_ PLARGE_INTEGER FileOffset,
    _In_ ULONG Length)
{
    PSHARED_CACHE_MAP SharedMap;
    PPRIVATE_CACHE_MAP PrivateMap;
    PWORK_QUEUE_ENTRY WorkItem;
    PGENERAL_LOOKASIDE LookasideList;
    PKPRCB Prcb;
    LARGE_INTEGER NewOffset;
    LARGE_INTEGER EndNewOffset;
    LARGE_INTEGER FileOffset1;
    LARGE_INTEGER FileOffset2;
    ULONG ReadAheadLength;
    KIRQL OldIrql;
    BOOLEAN IsSchedule = FALSE;

    DPRINT("CcScheduleReadAhead: %p, [%p], %X\n", FileObject, (FileOffset ? FileOffset->QuadPart : 0), Length);

    SharedMap = FileObject->SectionObjectPointer->SharedCacheMap;
    PrivateMap = FileObject->PrivateCacheMap;

    /* If file isn't cached, or if read ahead is disabled, this is no op */
    if (!PrivateMap)
    {
        DPRINT("CcScheduleReadAhead: PrivateMap is NULL\n");
        return;
    }

    if (!SharedMap)
    {
        DPRINT("CcScheduleReadAhead: SharedMap is NULL\n");
        return;
    }

    if (SharedMap->Flags & READAHEAD_DISABLED)
    {
        DPRINT("CcScheduleReadAhead: READAHEAD_DISABLED\n");
        return;
    }

    /* Compute the offset we'll reach */
    NewOffset.QuadPart = FileOffset->QuadPart;
    EndNewOffset.QuadPart = FileOffset->QuadPart + (LONGLONG)Length;

    /* Round read length with read ahead mask */
    ReadAheadLength = (Length + PrivateMap->ReadAheadMask) & ~PrivateMap->ReadAheadMask;

    FileOffset2.QuadPart = EndNewOffset.QuadPart + (LONGLONG)ReadAheadLength;
    FileOffset2.LowPart &= ~PrivateMap->ReadAheadMask;

    /* Lock read ahead spin lock */
    KeAcquireSpinLock(&PrivateMap->ReadAheadSpinLock, &OldIrql);

    if (FileObject->Flags & FO_SEQUENTIAL_ONLY)
    {
        /* Easy case: the file is sequentially read */
        if (FileOffset2.QuadPart >= PrivateMap->ReadAheadOffset[1].QuadPart)
        {
            if (!FileOffset->QuadPart &&
                PrivateMap->ReadAheadMask > (PAGE_SIZE - 1) &&
                PrivateMap->ReadAheadMask >= (Length + (PAGE_SIZE - 1)))
            {
                FileOffset1.QuadPart = ROUND_TO_PAGES(Length);
                FileOffset2.QuadPart = ReadAheadLength;

                PrivateMap->ReadAheadOffset[0] = FileOffset1;
                PrivateMap->ReadAheadLength[0] = (ReadAheadLength - FileOffset1.LowPart);

                PrivateMap->ReadAheadOffset[1] = FileOffset2;
                PrivateMap->ReadAheadLength[1] = ReadAheadLength;
            }
            else
            {
                FileOffset1.QuadPart = (PrivateMap->ReadAheadOffset[1].QuadPart + ReadAheadLength);

                if (FileOffset1.QuadPart < FileOffset2.QuadPart)
                    FileOffset1 = FileOffset2;

                PrivateMap->ReadAheadOffset[0] = FileOffset1;
                PrivateMap->ReadAheadLength[0] = ReadAheadLength;

                PrivateMap->ReadAheadOffset[1] = FileOffset2;
                PrivateMap->ReadAheadLength[1] = ReadAheadLength;

                FileOffset2.QuadPart = (FileOffset1.QuadPart + ReadAheadLength);
            }

            IsSchedule = TRUE;
        }
    }
    else
    {
        /* Other cases: try to find some logic in that mess... */
        if (NewOffset.HighPart == PrivateMap->BeyondLastByte2.HighPart &&
            (NewOffset.LowPart & ~7) == (PrivateMap->BeyondLastByte2.LowPart & ~7) &&
            PrivateMap->FileOffset2.HighPart == PrivateMap->BeyondLastByte1.HighPart &&
            (PrivateMap->FileOffset2.LowPart & ~7) == (PrivateMap->BeyondLastByte1.LowPart & ~7))
        {
            if (!FileOffset->QuadPart &&
                PrivateMap->ReadAheadMask > (PAGE_SIZE - 1) &&
                PrivateMap->ReadAheadMask >= (Length + (PAGE_SIZE - 1)))
            {
                FileOffset2.QuadPart = ROUND_TO_PAGES(Length);
            }
            else
            {
                FileOffset2.QuadPart = (EndNewOffset.QuadPart + ReadAheadLength);
                FileOffset2.LowPart &= ~PrivateMap->ReadAheadMask;
            }

            if (FileOffset2.QuadPart != PrivateMap->ReadAheadOffset[1].QuadPart)
            {
                ASSERT(FileOffset2.HighPart >= 0);

                PrivateMap->ReadAheadOffset[1] = FileOffset2;
                PrivateMap->ReadAheadLength[1] = ReadAheadLength;

                IsSchedule = TRUE;
            }
        }
        else if ((NewOffset.QuadPart - PrivateMap->FileOffset2.QuadPart) ==
                 (PrivateMap->FileOffset2.QuadPart - PrivateMap->FileOffset1.QuadPart))
        {
            LARGE_INTEGER offset;

            offset.QuadPart = ((NewOffset.QuadPart * 2) - PrivateMap->FileOffset2.QuadPart);

            if (offset.HighPart >= 0)
            {
                PrivateMap->ReadAheadLength[1] = ROUND_TO_PAGES(Length + (offset.LowPart & (PAGE_SIZE - 1)));

                PrivateMap->ReadAheadOffset[1].HighPart = offset.HighPart;
                PrivateMap->ReadAheadOffset[1].LowPart = (offset.LowPart & ~(PAGE_SIZE - 1));

                IsSchedule = TRUE;
            }
        }
    }

    /*  Have a job at the moment? */
    if (!IsSchedule)
    {
        /* No */
        KeReleaseSpinLock(&PrivateMap->ReadAheadSpinLock, OldIrql);
        return;
    }

    /* If read ahead is active now */
    if (PrivateMap->Flags.ReadAheadActive)
    {
        /* Done */
        KeReleaseSpinLock(&PrivateMap->ReadAheadSpinLock, OldIrql);
        return;
    }

    RtlInterlockedSetBits(&PrivateMap->UlongFlags, PRIVATE_CACHE_MAP_READ_AHEAD_ACTIVE);
    KeReleaseSpinLock(&PrivateMap->ReadAheadSpinLock, OldIrql);

    Prcb = KeGetCurrentPrcb();

    LookasideList = Prcb->PPLookasideList[5].P;
    LookasideList->TotalAllocates++;

    /* Get a work item */
    WorkItem = (PWORK_QUEUE_ENTRY)InterlockedPopEntrySList(&LookasideList->ListHead);
    if (!WorkItem)
    {
        LookasideList->AllocateMisses++;

        LookasideList = Prcb->PPLookasideList[5].L;
        LookasideList->TotalAllocates++;

        WorkItem = (PWORK_QUEUE_ENTRY)InterlockedPopEntrySList(&LookasideList->ListHead);
        if (!WorkItem)
        {
            LookasideList->AllocateMisses++;
            WorkItem = LookasideList->Allocate(LookasideList->Type, LookasideList->Size, LookasideList->Tag);
        }
    }

    if (!WorkItem) 
    {
        /* Fail path: lock again, and revert read ahead active */
        KeAcquireSpinLock(&PrivateMap->ReadAheadSpinLock, &OldIrql);
        RtlInterlockedAndBits(&PrivateMap->UlongFlags, ~PRIVATE_CACHE_MAP_READ_AHEAD_ACTIVE);
        KeReleaseSpinLock(&PrivateMap->ReadAheadSpinLock, OldIrql);

        DPRINT1("CcScheduleReadAhead: WorkItem is NULL\n");
        return;
    }

    /* Reference our FO so that it doesn't go in between */
    ObReferenceObject(FileObject);

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
    SharedMap->OpenCount++;
    SharedMap->Flags |= SHARE_FL_READ_AHEAD;
    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    /* We want to do read ahead! */
    WorkItem->Function = ReadAhead;
    WorkItem->Parameters.Read.FileObject = FileObject;

    /* Queue in the read ahead dedicated queue */
    CcPostWorkQueue(WorkItem, &CcExpressWorkQueue);
}

VOID
NTAPI
CcSetDirtyPinnedData(
    _In_ PVOID BcbVoid,
    _In_ PLARGE_INTEGER Lsn OPTIONAL)
{
    PSHARED_CACHE_MAP SharedMap;
    KLOCK_QUEUE_HANDLE LockHandle;
    PCC_BCB Bcbs[2];
    PCC_BCB* pBcbs;
    ULONG DirtyPages;

    DPRINT("CcSetDirtyPinnedData: BcbVoid %p\n", BcbVoid);

    Bcbs[0] = BcbVoid;
    Bcbs[1] = NULL;

    if (Bcbs[0]->NodeTypeCode != 0x02FA)
    {
        pBcbs = Bcbs;
    }
    else
    {
        DPRINT1("CcSetDirtyPinnedData: FIXME\n");
        ASSERT(FALSE);
    }

    while (*pBcbs)
    {
        Bcbs[0] = *(pBcbs++);

        ASSERT(((ULONG_PTR)Bcbs[0] & 1) != 1);

        SharedMap = Bcbs[0]->SharedCacheMap;

        KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, &LockHandle);

        if (!Bcbs[0]->Reserved1[0])
        {
            DirtyPages = (Bcbs[0]->Length / PAGE_SIZE);

            Bcbs[0]->Reserved1[0] = 1;

            if (Lsn)
            {
                DPRINT1("CcSetDirtyPinnedData: FIXME\n");
                ASSERT(FALSE);
            }

            KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueMasterLock]);

            if (!SharedMap->DirtyPages && !(SharedMap->Flags & 0x2))
            {
                if (!LazyWriter.ScanActive)
                    CcScheduleLazyWriteScan(FALSE);

                RemoveEntryList(&SharedMap->SharedCacheMapLinks);
                InsertTailList(&CcDirtySharedCacheMapList.SharedCacheMapLinks, &SharedMap->SharedCacheMapLinks);
            }
            
            CcTotalDirtyPages += DirtyPages;
            SharedMap->DirtyPages += DirtyPages;

            KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueMasterLock]);
        }

        if (Lsn)
        {
            DPRINT1("CcSetDirtyPinnedData: FIXME\n");
            ASSERT(FALSE);
        }

        if (Bcbs[0]->BeyondLastByte.QuadPart > SharedMap->ValidDataGoal.QuadPart)
            SharedMap->ValidDataGoal = Bcbs[0]->BeyondLastByte;

        KeReleaseInStackQueuedSpinLock(&LockHandle);
    }
}

VOID
NTAPI
CcSetReadAheadGranularity(
    _In_ PFILE_OBJECT FileObject,
    _In_ ULONG Granularity)
{
    PPRIVATE_CACHE_MAP PrivateMap;

    PrivateMap = FileObject->PrivateCacheMap;
    PrivateMap->ReadAheadMask = (Granularity - 1);
}

VOID
NTAPI
CcUnpinRepinnedBcb(
    _In_ PVOID InBcb,
    _In_ BOOLEAN WriteThrough,
    _Out_ PIO_STATUS_BLOCK IoStatus)
{
    PCC_BCB Bcb = InBcb;
    PSHARED_CACHE_MAP SharedMap;

    SharedMap = Bcb->SharedCacheMap;
    IoStatus->Status = STATUS_SUCCESS;

    if (!WriteThrough)
    {
        CcUnpinFileDataEx(Bcb, TRUE, 0);
        IoStatus->Status = STATUS_SUCCESS;
        return;
    }

    if (SharedMap->Flags & 0x200)
        ExAcquireResourceExclusiveLite(&Bcb->BcbResource, TRUE);

    if (!Bcb->Reserved1[0])
    {
        CcUnpinFileDataEx(Bcb, FALSE, 0);
        return;
    }

    ASSERT(Bcb->BaseAddress != NULL);

    MmSetAddressRangeModified(Bcb->BaseAddress, Bcb->Length);

    CcUnpinFileDataEx(Bcb, TRUE, 2);

    MmFlushSection(Bcb->SharedCacheMap->FileObject->SectionObjectPointer, &Bcb->FileOffset, Bcb->Length, IoStatus, 1);

    ASSERT(IoStatus->Status != STATUS_ENCOUNTERED_WRITE_IN_PROGRESS);

    if (IoStatus->Status == STATUS_VERIFY_REQUIRED ||
        IoStatus->Status == STATUS_FILE_LOCK_CONFLICT ||
        IoStatus->Status == STATUS_ENCOUNTERED_WRITE_IN_PROGRESS)
    {
        CcSetDirtyPinnedData(Bcb, NULL);
    }

    CcUnpinFileDataEx(Bcb, FALSE, 0);

    if (!IsListEmpty(&CcDeferredWrites))
        CcPostDeferredWrites();
}

//INIT_FUNCTION
VOID
NTAPI
CcPfInitializePrefetcher(VOID)
{
    DPRINT1("CcPfInitializePrefetcher: FIXME \n");

    /* Notify debugger */
    //DbgPrintEx(DPFLTR_PREFETCHER_ID, DPFLTR_TRACE_LEVEL, "CCPF: InitializePrefetecher()\n");

    /* Setup the Prefetcher Data */
    //InitializeListHead(&CcPfGlobals.ActiveTraces);
    //InitializeListHead(&CcPfGlobals.CompletedTraces);
    //ExInitializeFastMutex(&CcPfGlobals.CompletedTracesLock);

    /* FIXME: Setup the rest of the prefetecher */
    //ASSERT(FALSE);
}

#if DBG && defined(KDBG)
BOOLEAN
ExpKdbgExtFileCache(ULONG Argc, PCHAR Argv[])
{
    DPRINT1("ExpKdbgExtFileCache: ... \n");
    UNIMPLEMENTED;
    return FALSE;
}

BOOLEAN
ExpKdbgExtDefWrites(ULONG Argc, PCHAR Argv[])
{
    DPRINT1("ExpKdbgExtDefWrites: ... \n");
    UNIMPLEMENTED;
    return FALSE;
}
#endif

/* EOF */
