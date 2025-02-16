
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "cc.h"
#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

SHARED_CACHE_MAP_LIST_CURSOR CcDirtySharedCacheMapList;
SHARED_CACHE_MAP_LIST_CURSOR CcLazyWriterCursor;
GENERAL_LOOKASIDE CcTwilightLookasideList;
MM_SYSTEMSIZE CcCapturedSystemSize;
KSPIN_LOCK CcDeferredWriteSpinLock;
LIST_ENTRY CcDeferredWrites;
LIST_ENTRY CcCleanSharedCacheMapList;
ULONG CcNumberWorkerThreads;
ULONG CcDirtyPageThreshold;
ULONG CcDirtyPageTarget;
LONG CcAggressiveZeroCount;
LONG CcAggressiveZeroThreshold;

extern LIST_ENTRY CcRegularWorkQueue;
extern LIST_ENTRY CcExpressWorkQueue;
extern LIST_ENTRY CcFastTeardownWorkQueue;
extern LIST_ENTRY CcPostTickWorkQueue;
extern LARGE_INTEGER CcCollisionDelay;
extern LAZY_WRITER LazyWriter;
extern LIST_ENTRY CcIdleWorkerThreadList;
extern ULONG CcIdleDelayTick;
extern ULONG CcTotalDirtyPages;

/* FUNCTIONS ******************************************************************/

PSHARED_CACHE_MAP
NTAPI
CcCreateSharedCacheMap(
    _In_ PFILE_OBJECT FileObject,
    _In_ PCC_FILE_SIZES FileSizes,
    _In_ BOOLEAN PinAccess,
    _In_ PCACHE_MANAGER_CALLBACKS Callbacks,
    _In_ PVOID LazyWriteContext)
{
    PSHARED_CACHE_MAP SharedMap;

    SharedMap = ExAllocatePoolWithTag(NonPagedPool, sizeof(SHARED_CACHE_MAP), 'cScC');
    if (!SharedMap)
    {
        DPRINT1("CcCreateSharedCacheMap: STATUS_INSUFFICIENT_RESOURCES\n");
        return SharedMap;
    }

    RtlZeroMemory(SharedMap, sizeof(SHARED_CACHE_MAP));

    SharedMap->NodeTypeCode = NODE_TYPE_SHARED_MAP;
    SharedMap->NodeByteSize = sizeof(SHARED_CACHE_MAP);
    SharedMap->FileObject = FileObject;

    /* Set new file size for the file */
    SharedMap->FileSize.QuadPart = FileSizes->FileSize.QuadPart;

    /* Set new valid data length for the file */
    SharedMap->ValidDataLength.QuadPart = FileSizes->ValidDataLength.QuadPart;
    SharedMap->ValidDataGoal.QuadPart = FileSizes->ValidDataLength.QuadPart;

    KeInitializeSpinLock(&SharedMap->ActiveVacbSpinLock);
    KeInitializeSpinLock(&SharedMap->BcbSpinLock);
    ExInitializePushLock((PEX_PUSH_LOCK)&SharedMap->VacbPushLock);

    if (PinAccess)
        SharedMap->Flags |= SHARE_FL_PIN_ACCESS;

    if (FileObject->Flags & FO_SEQUENTIAL_ONLY)
        SharedMap->Flags |= SHARE_FL_SEQUENTIAL_ONLY;

    SharedMap->Callbacks = Callbacks;
    SharedMap->LazyWriteContext = LazyWriteContext;

    InitializeListHead(&SharedMap->BcbList);
    InitializeListHead(&SharedMap->PrivateList);

    return SharedMap;
}

VOID
NTAPI
CcUnmapAndPurge(
    _In_ PSHARED_CACHE_MAP SharedMap)
{
    DPRINT("CcUnmapAndPurge: SharedMap %p\n", SharedMap);

    if (SharedMap->Vacbs)
        CcUnmapVacbArray(SharedMap, NULL, 0, FALSE);

    if (SharedMap->Flags & SHARE_FL_TRUNCATE_SIZE)
        CcPurgeCacheSection(SharedMap->FileObject->SectionObjectPointer, NULL, 0, FALSE);
}

VOID
NTAPI
CcDeleteMbcb(
    _In_ PSHARED_CACHE_MAP SharedMap)
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PBITMAP_RANGE BitmapRange;
    PLIST_ENTRY Entry;
    LIST_ENTRY list;
    PMBCB Mbcb;
    BOOLEAN IsDrainLevel = FALSE;

    DPRINT("CcDeleteMbcb: SharedMap %p\n", SharedMap);

    InitializeListHead(&list);

    KeAcquireInStackQueuedSpinLock(&SharedMap->BcbSpinLock, &LockHandle);

    Mbcb = SharedMap->Mbcb;
    if (!Mbcb)
    {
        KeReleaseInStackQueuedSpinLock(&LockHandle);
        goto Exit;
    }

    KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueMasterLock]);
    CcTotalDirtyPages -= Mbcb->DirtyPages;
    SharedMap->DirtyPages -= Mbcb->DirtyPages;
    KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueMasterLock]);

    while (!IsListEmpty(&Mbcb->BitmapRanges))
    {
        BitmapRange = CONTAINING_RECORD(Mbcb->BitmapRanges.Flink, BITMAP_RANGE, Links);

        RemoveEntryList(&BitmapRange->Links);

        if (BitmapRange->Bitmap &&
            BitmapRange->Bitmap != (PULONG)&Mbcb->BitmapRange2)
        {
            IsDrainLevel = TRUE;

            if (BitmapRange->DirtyPages)
                RtlZeroMemory(BitmapRange->Bitmap, VACB_LEVEL_BLOCK_SIZE);

            KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
            CcDeallocateVacbLevel((PVOID *)BitmapRange->Bitmap, FALSE);
            KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
        }

        if (BitmapRange < (PBITMAP_RANGE)Mbcb ||
            BitmapRange >= (PBITMAP_RANGE)((PCHAR)Mbcb + sizeof(MBCB)))
        {
            InsertTailList(&list, &BitmapRange->Links);
        }
    }

    SharedMap->Mbcb = NULL;

    KeReleaseInStackQueuedSpinLock(&LockHandle);

    while (!IsListEmpty(&list))
    {
        Entry = RemoveHeadList(&list);
        BitmapRange = CONTAINING_RECORD(Entry, BITMAP_RANGE, Links);
        ExFreePool(BitmapRange);
    }

    CcDeallocateBcb((PCC_BCB)Mbcb);

Exit:

    if (IsDrainLevel)
        CcDrainVacbLevelZone();
}

VOID
NTAPI
CcDeleteBcbs(
    _In_ PSHARED_CACHE_MAP SharedCacheMap)
{
    PLIST_ENTRY Entry;
    PCC_BCB Bcb;
    KIRQL OldIrql;

    DPRINT("CcDeleteBcbs: SharedCacheMap %p\n", SharedCacheMap);

    for (Entry = SharedCacheMap->BcbList.Flink;
         Entry != &SharedCacheMap->BcbList;
         )
    {
        Bcb = CONTAINING_RECORD(Entry, CC_BCB, Link);

        Entry = Entry->Flink;

        if (Bcb->NodeTypeCode != NODE_TYPE_BCB)
            continue;

        ASSERT(Bcb->PinCount == 0);

        RemoveEntryList(&Bcb->Link);

        if (SharedCacheMap->SectionSize.QuadPart > 0x2000000 &&
            (SharedCacheMap->Flags & SHARE_FL_MODIFIED_NO_WRITE))
        {
            CcAdjustVacbLevelLockCount(SharedCacheMap, Bcb->FileOffset.QuadPart, -1);
        }

        if (Bcb->BaseAddress)
            CcFreeVirtualAddress(Bcb->Vacb);

        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

        if (Bcb->Reserved1[0])
        {
            CcTotalDirtyPages -= (Bcb->Length / PAGE_SIZE);
            SharedCacheMap->DirtyPages -= (Bcb->Length / PAGE_SIZE);
        }

        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

        CcDeallocateBcb(Bcb);
    }
}

VOID
NTAPI
CcWaitOnActiveCount(
    _In_ PSHARED_CACHE_MAP SharedMap)
{
    PKEVENT Event;
    KIRQL OldIrql;

    OldIrql = KeAcquireQueuedSpinLock(LockQueueVacbLock);

    if (!SharedMap->VacbActiveCount)
    {
        KeReleaseQueuedSpinLock(LockQueueVacbLock, OldIrql);
        return;
    }

    Event = SharedMap->WaitOnActiveCount;

    if (Event)
    {
        KeClearEvent(Event);
    }
    else
    {
        Event = &SharedMap->Event;
        KeInitializeEvent(Event, NotificationEvent, FALSE);
        SharedMap->WaitOnActiveCount = Event;
    }

    KeReleaseQueuedSpinLock(LockQueueVacbLock, OldIrql);

    KeWaitForSingleObject(Event, Executive, KernelMode, FALSE, NULL);
}

VOID
NTAPI
CcDeleteSharedCacheMap(
    _In_ PSHARED_CACHE_MAP SharedMap,
    _In_ KIRQL OldIrql,
    _In_ BOOLEAN IsReleaseFile)
{
    PVACB ActiveVacb;
    LIST_ENTRY list;
    ULONG ActivePage;

    DPRINT("CcDeleteSharedCacheMap: SharedMap %p\n", SharedMap);

    RemoveEntryList(&SharedMap->SharedCacheMapLinks);

    SharedMap->FileObject->SectionObjectPointer->SharedCacheMap = NULL;
    SharedMap->Flags |= 0x20;

    if (SharedMap->VacbActiveCount || SharedMap->NeedToZero)
    {
        InitializeListHead(&list);
        InsertTailList(&list, &SharedMap->SharedCacheMapLinks);

        KeAcquireSpinLockAtDpcLevel(&SharedMap->ActiveVacbSpinLock);

        ActiveVacb = SharedMap->ActiveVacb;
        ASSERT(ActiveVacb);

        ActivePage = SharedMap->ActivePage;
        SharedMap->ActiveVacb = NULL;

        KeReleaseSpinLockFromDpcLevel(&SharedMap->ActiveVacbSpinLock);
        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

        CcFreeActiveVacb(SharedMap, ActiveVacb, ActivePage, FALSE);

        while (SharedMap->VacbActiveCount)
        {
            CcWaitOnActiveCount(SharedMap);
        }

        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

        RemoveEntryList(&SharedMap->SharedCacheMapLinks);
    }

    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    if (!IsListEmpty(&SharedMap->BcbList))
        CcDeleteBcbs(SharedMap);

    CcUnmapAndPurge(SharedMap);

    if (IsReleaseFile)
        FsRtlReleaseFile(SharedMap->FileObject);

    if (SharedMap->Section)
        ObDereferenceObject(SharedMap->Section);

    ObDereferenceObject(SharedMap->FileObject);

    if (SharedMap->Mbcb)
        CcDeleteMbcb(SharedMap);

    if (SharedMap->UninitializeEvent)
    {
        PCACHE_UNINITIALIZE_EVENT event;
        PCACHE_UNINITIALIZE_EVENT NextEvent;

        for (event = SharedMap->UninitializeEvent; event; event = NextEvent)
        {
            NextEvent = event->Next;

            event = (PCACHE_UNINITIALIZE_EVENT)((ULONG_PTR)event & ~1);
            KeSetEvent(&event->Event, 0, FALSE);
        }
    }

    if (SharedMap->Vacbs != SharedMap->InitialVacbs && SharedMap->Vacbs)
    {
        if (SharedMap->SectionSize.QuadPart > CACHE_OVERALL_SIZE)
        {
            ASSERT(!IsVacbLevelReferenced(SharedMap, SharedMap->Vacbs, 1));
        } 

        ExFreePool(SharedMap->Vacbs);
    }

    if (SharedMap->CreateEvent && SharedMap->CreateEvent != &SharedMap->Event)
        ExFreePool(SharedMap->CreateEvent);

    if (SharedMap->WaitOnActiveCount && SharedMap->WaitOnActiveCount != &SharedMap->Event)
        ExFreePool(SharedMap->WaitOnActiveCount);

    ExFreePool(SharedMap);
}

VOID
NTAPI
CcWaitForUninitializeCacheMap(
    _In_ PFILE_OBJECT FileObject)
{
    PSHARED_CACHE_MAP SharedMap;
    CACHE_UNINITIALIZE_EVENT event;
    PCACHE_UNINITIALIZE_EVENT Event;
    LARGE_INTEGER Timeout;
    BOOLEAN IsWait = FALSE;
    KIRQL OldIrql;
    NTSTATUS Status;

    DPRINT("CcWaitForUninitializeCacheMap: FileObject %p\n", FileObject);

    if (!FileObject->SectionObjectPointer->SharedCacheMap)
        return;

    KeInitializeEvent(&event.Event, NotificationEvent, FALSE);

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    SharedMap = FileObject->SectionObjectPointer->SharedCacheMap;

    if (SharedMap && 
        (!SharedMap->OpenCount || IsListEmpty(&SharedMap->PrivateList)))
    {
        SharedMap->Flags |= 0x10000;
        event.Next = SharedMap->UninitializeEvent;
        SharedMap->UninitializeEvent = (PCACHE_UNINITIALIZE_EVENT)((ULONG_PTR)&event | 1);

        IsWait = TRUE; 
        CcScheduleLazyWriteScanEx(TRUE, TRUE);
    }

    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    if (!IsWait)
        return;

    Timeout.QuadPart = 600 * (-10000ll * 1000); // 600 seconds (10 m)

    Status = KeWaitForSingleObject(&event.Event,  Executive, KernelMode, FALSE, &Timeout);
    if (Status != STATUS_TIMEOUT)
        return;

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    SharedMap = FileObject->SectionObjectPointer->SharedCacheMap;
    if (!SharedMap)
    {
        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
        KeWaitForSingleObject(&event.Event,  Executive, KernelMode, FALSE, NULL);
        return;
    }

    Event = CONTAINING_RECORD(&SharedMap->UninitializeEvent, CACHE_UNINITIALIZE_EVENT, Next);

    while (Event->Next != NULL)
    {
        if (Event->Next == (PCACHE_UNINITIALIZE_EVENT)((ULONG_PTR)&event | 1))
        {
            Event->Next = event.Next;
            break;
        }

        Event = (PCACHE_UNINITIALIZE_EVENT)((ULONG_PTR)(Event->Next) & ~1);
    }

    SharedMap->Flags &= ~0x10000;
    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
}

/* PUBLIC FUNCTIONS ***********************************************************/

BOOLEAN
NTAPI
CcIsThereDirtyData(
    _In_ PVPB Vpb)
{
    PSHARED_CACHE_MAP SharedMap;
    ULONG ix = 0;
    KIRQL OldIrql;

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    for (SharedMap = CONTAINING_RECORD(CcDirtySharedCacheMapList.SharedCacheMapLinks.Flink, SHARED_CACHE_MAP, SharedCacheMapLinks);
         ;
         SharedMap = CONTAINING_RECORD(SharedMap->SharedCacheMapLinks.Flink, SHARED_CACHE_MAP, SharedCacheMapLinks))
    {
        if (&SharedMap->SharedCacheMapLinks == &CcDirtySharedCacheMapList.SharedCacheMapLinks)
        {
            KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
            return FALSE;
        }

        if (!(SharedMap->Flags & 0x800))
        {
            if (SharedMap->FileObject->Vpb == Vpb &&
                SharedMap->DirtyPages &&
                !(SharedMap->FileObject->Flags & 0x8000))
            {
                break;
            }
        }

        ix++;

        if (ix >= 20 && !(SharedMap->Flags & (0x800 | 0x20)))
        {
            SharedMap->DirtyPages++;
            SharedMap->Flags |= 0x20;
            KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

            ix = 0;

            OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
            SharedMap->Flags &= ~0x20;
            SharedMap->DirtyPages--;
        }
    }

    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
    return TRUE;
}

PFILE_OBJECT
NTAPI
CcGetFileObjectFromBcb(PVOID Bcb)
{
    return ((PCC_BCB)Bcb)->SharedCacheMap->FileObject;
}

PFILE_OBJECT
NTAPI
CcGetFileObjectFromSectionPtrs(IN PSECTION_OBJECT_POINTERS SectionObjectPointer)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

VOID
NTAPI
CcInitializeCacheMap(
    _In_ PFILE_OBJECT FileObject,
    _In_ PCC_FILE_SIZES FileSizes,
    _In_ BOOLEAN PinAccess,
    _In_ PCACHE_MANAGER_CALLBACKS Callbacks,
    _In_ PVOID LazyWriteContext)
{
    PCACHE_UNINITIALIZE_EVENT Event;
    PCACHE_UNINITIALIZE_EVENT NextEvent;
    PSHARED_CACHE_MAP NewSharedMap = NULL;
    PSHARED_CACHE_MAP SharedMap;
    PPRIVATE_CACHE_MAP PrivateMap;
    CC_FILE_SIZES fileSizes;
    PVOID NewMap = NULL;
    BOOLEAN IsLocked = FALSE;
    BOOLEAN IsNewSharedMap = FALSE;
    BOOLEAN IsSectionInit = FALSE;
    BOOLEAN IsReferenced = FALSE;
    KIRQL OldIrql;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("CcInitializeCacheMap: File %p, '%wZ'\n", FileObject, &FileObject->FileName);

    RtlCopyMemory(&fileSizes, FileSizes, sizeof(fileSizes));

    DPRINT("CcInitializeCacheMap: AllocationSize %I64X, FileSize %I64X, ValidDataLength %I64X\n",
           fileSizes.AllocationSize.QuadPart, fileSizes.FileSize.QuadPart, fileSizes.ValidDataLength.QuadPart);

    if (!fileSizes.AllocationSize.QuadPart)
        fileSizes.AllocationSize.QuadPart = 1;

    if (FileObject->WriteAccess)
    {
        fileSizes.AllocationSize.QuadPart += (CC_VACBS_DEFAULT_MAPPING_SIZE - 1);
        fileSizes.AllocationSize.LowPart &= ~(CC_VACBS_DEFAULT_MAPPING_SIZE - 1);
    }
    else
    {
        fileSizes.AllocationSize.QuadPart += (VACB_MAPPING_GRANULARITY - 1);
        fileSizes.AllocationSize.LowPart &= ~(VACB_MAPPING_GRANULARITY - 1);
    }

    while (TRUE)
    {
        if (!FileObject->SectionObjectPointer->SharedCacheMap)
        {
            NewSharedMap = CcCreateSharedCacheMap(FileObject, &fileSizes, PinAccess, Callbacks, LazyWriteContext);
            if (!NewSharedMap)
            {
                DPRINT1("CcInitializeCacheMap: STATUS_INSUFFICIENT_RESOURCES\n");
                RtlRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
                return;
            }

            NewMap = NewSharedMap;
        }

        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

        if (FileObject->PrivateCacheMap)
        {
            KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

            if (NewSharedMap)
                ExFreePoolWithTag(NewSharedMap, 'cScC');

            return;
        }

        SharedMap = FileObject->SectionObjectPointer->SharedCacheMap;

        if (SharedMap)
        {
            if (!(FileObject->Flags & FO_SEQUENTIAL_ONLY))
                SharedMap->Flags &= ~SHARE_FL_SEQUENTIAL_ONLY;

            break;
        }
        else if (NewSharedMap)
        {
            InsertTailList(&CcCleanSharedCacheMapList, &NewSharedMap->SharedCacheMapLinks);

            IsNewSharedMap = TRUE;
            SharedMap = NewSharedMap;
            NewMap = NULL;

            FileObject->SectionObjectPointer->SharedCacheMap = SharedMap;
            ObReferenceObject(FileObject);
            break;
        }
        else
        {
            KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
        }
    }

    if (FileObject->Flags & FO_RANDOM_ACCESS)
        SharedMap->Flags |= SHARE_FL_RANDOM_ACCESS;

    SharedMap->Flags &= ~0x10;

    if (SharedMap->Vacbs)
    {
        if (!(SharedMap->Flags & SHARE_FL_SECTION_INIT))
        {
            SharedMap->OpenCount++;
            KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
            IsLocked = FALSE;
            IsReferenced = TRUE;
        }
    }
    else if (!(SharedMap->Flags & SHARE_FL_SECTION_INIT)) // SharedMap->Vacbs == NULL
    {
        SharedMap->OpenCount++;
        SharedMap->Flags |= SHARE_FL_SECTION_INIT;

        if (SharedMap->CreateEvent)
            KeInitializeEvent(SharedMap->CreateEvent, NotificationEvent, FALSE);

        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
        IsLocked = FALSE;

        IsReferenced = TRUE;
        IsSectionInit = TRUE;

        if (SharedMap->Section)
        {
            if (fileSizes.AllocationSize.QuadPart > SharedMap->SectionSize.QuadPart)
            {
                NTSTATUS status;

                DPRINT1("CcInitializeCacheMap: FIXME MmExtendSection()\n");
                ASSERT(FALSE);
                status = STATUS_NOT_IMPLEMENTED;//MmExtendSection(SharedMap->Section, &fileSizes.AllocationSize, 1);
                if (!NT_SUCCESS(status))
                {
                    DPRINT1("CcInitializeCacheMap: Status %X\n", Status);
                    Status = FsRtlNormalizeNtstatus(status, STATUS_UNEXPECTED_MM_EXTEND_ERR);
                    goto Finish;
                }
            }

            DPRINT1("CcInitializeCacheMap: FIXME CcExtendVacbArray()\n");
            ASSERT(FALSE);
            Status = STATUS_NOT_IMPLEMENTED;//CcExtendVacbArray(SharedMap, fileSizes.AllocationSize);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("CcInitializeCacheMap: Status %X\n", Status);
                goto Finish;
            }
        }
        else
        {
            PFSRTL_COMMON_FCB_HEADER Fcb;

            SharedMap->Status = MmCreateSection(&SharedMap->Section,
                                                (SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ),
                                                NULL,
                                                &fileSizes.AllocationSize,
                                                PAGE_READWRITE,
                                                SEC_COMMIT,
                                                NULL,
                                                FileObject);
            if (!NT_SUCCESS(SharedMap->Status))
            {
                DPRINT1("CcInitializeCacheMap: SharedMap->Status %X\n", SharedMap->Status);
                SharedMap->Section = NULL;
                Status = FsRtlNormalizeNtstatus(SharedMap->Status, STATUS_UNEXPECTED_MM_CREATE_ERR);
                goto Finish;
            }

            ObDeleteCapturedInsertInfo(SharedMap->Section);

            Fcb = FileObject->FsContext;

            /* If the FsContext2 is non-NULL,
               the file stream represents an open instance of a file or a directory,
               and FSRTL_FLAG2_DO_MODIFIED_WRITE is ignored.

               If the FsContext2 is NULL, and FSRTL_FLAG2_DO_MODIFIED_WRITE is not set,
               the file object is a stream file object, and the stream is a modified-no-write (MNW) stream.

               If the FsContext2 is NULL, and FSRTL_FLAG2_DO_MODIFIED_WRITE is set,
               the file object is a stream file object, and the stream is writable.
            */
            if (!(Fcb->Flags2 & FSRTL_FLAG2_DO_MODIFIED_WRITE) && !FileObject->FsContext2)
            {
                MmDisableModifiedWriteOfSection(FileObject->SectionObjectPointer);

                OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
                SharedMap->Flags |= SHARE_FL_MODIFIED_NO_WRITE;
                KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
            }

            Status = CcCreateVacbArray(SharedMap, fileSizes.AllocationSize);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("CcInitializeCacheMap: Status %X\n", Status);
                goto Finish;
            }
        }

        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

        SharedMap->Flags &= ~SHARE_FL_SECTION_INIT;

        if (SharedMap->CreateEvent)
            KeSetEvent(SharedMap->CreateEvent, 0, FALSE);

        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

        IsSectionInit = FALSE;
    }
    else // !(SharedMap->Vacbs) && (SharedMap->Flags & SHARE_FL_SECTION_INIT)
    {
        if (!SharedMap->CreateEvent)
        {
            SharedMap->CreateEvent = ExAllocatePoolWithTag(NonPagedPool, sizeof(KEVENT), 'vEcC');
            if (!SharedMap->CreateEvent)
            {
                KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
                IsLocked = FALSE;

                DPRINT1("CcInitializeCacheMap: STATUS_INSUFFICIENT_RESOURCES\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto Finish;
            }

            KeInitializeEvent(SharedMap->CreateEvent, NotificationEvent, FALSE);
        }

        SharedMap->OpenCount++;

        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
        IsLocked = FALSE;
        IsReferenced = TRUE;

        KeWaitForSingleObject(SharedMap->CreateEvent, Executive, KernelMode, FALSE, NULL);
        if (!NT_SUCCESS(SharedMap->Status))
        {
            DPRINT1("CcInitializeCacheMap: SharedMap->Status %X\n", SharedMap->Status);
            Status = FsRtlNormalizeNtstatus(SharedMap->Status, STATUS_UNEXPECTED_MM_CREATE_ERR);
            goto Finish;
        }
    }

    if (NewMap)
    {
        ExFreePoolWithTag(NewMap, 'cScC');
        NewMap = NULL;
    }

    PrivateMap = &SharedMap->PrivateCacheMap;
    if (PrivateMap->NodeTypeCode)
    {
        NewMap = ExAllocatePoolWithTag(NonPagedPool, sizeof(PRIVATE_CACHE_MAP), 'cPcC');
        if (!NewMap)
        {
            DPRINT1("CcInitializeCacheMap: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Finish;
        }
    }

    while (TRUE)
    {
        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
        IsLocked = TRUE;

        if (FileObject->PrivateCacheMap)
        {
            ASSERT(SharedMap->OpenCount > 1);
            SharedMap->OpenCount--;
            SharedMap = NULL;
            IsReferenced = FALSE;
            break;
        }

        if (PrivateMap->NodeTypeCode)
        {
            if (!NewMap)
            {
                KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
                IsLocked = FALSE;

                NewMap = ExAllocatePoolWithTag(NonPagedPool, sizeof(PRIVATE_CACHE_MAP), 'cPcC');
                if (!NewMap)
                {
                    DPRINT1("CcInitializeCacheMap: STATUS_INSUFFICIENT_RESOURCES\n");
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    break;
                }

                continue;
            }

            PrivateMap = NewMap;
            NewMap = NULL;
        }

        RtlZeroMemory(PrivateMap, sizeof(*PrivateMap));

        PrivateMap->NodeTypeCode = NODE_TYPE_PRIVATE_MAP;
        PrivateMap->FileObject = FileObject;
        FileObject->PrivateCacheMap = PrivateMap;

        PrivateMap->ReadAheadMask = (PAGE_SIZE - 1);
        KeInitializeSpinLock(&PrivateMap->ReadAheadSpinLock);

        InsertTailList(&SharedMap->PrivateList, &PrivateMap->PrivateLinks);
        IsReferenced = FALSE;

        break;
    }

Finish:

    if (IsReferenced)
    {
        if (!IsLocked)
            OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

        if (IsSectionInit)
        {
            if (SharedMap->CreateEvent)
                KeSetEvent(SharedMap->CreateEvent, 0, FALSE);

            SharedMap->Flags &= ~SHARE_FL_SECTION_INIT;
        }

        SharedMap->OpenCount--;

        if (!SharedMap->OpenCount &&
            !(SharedMap->Flags & SHARE_FL_WRITE_QUEUED) &&
            !SharedMap->DirtyPages)
        {
            DPRINT1("CcInitializeCacheMap: FIXME CcDeleteSharedCacheMap()\n");
            ASSERT(FALSE);
            //CcDeleteSharedCacheMap(SharedMap, OldIrql, FALSE);
        }
        else
        {
            KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
        }

        IsLocked = FALSE;
        goto Exit;
    }

    if (!SharedMap)
        goto Exit;

    if (!IsLocked)
    {
        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
        IsLocked = TRUE;
    }

    if (!IsNewSharedMap &&
        !SharedMap->DirtyPages &&
        SharedMap->OpenCount)
    {
        if (KdDebuggerEnabled && !KdDebuggerNotPresent &&
            !SharedMap->OpenCount &&
            !SharedMap->DirtyPages)
        {
            DPRINT1("CC: SharedMap->OpenCount == 0 && DirtyPages == 0 && going onto CleanList!\n");
            DbgBreakPoint();
        }

        RemoveEntryList(&SharedMap->SharedCacheMapLinks);
        InsertTailList(&CcCleanSharedCacheMapList, &SharedMap->SharedCacheMapLinks);
    }

    for (Event = SharedMap->UninitializeEvent; Event; Event = NextEvent)
    {
        Event = (PCACHE_UNINITIALIZE_EVENT)((ULONG_PTR)Event & ~(1));
        NextEvent = Event->Next;
        KeSetEvent(&Event->Event, 0, FALSE);
    }

    SharedMap->Flags &= ~SHARE_FL_WAITING_TEARDOWN;
    SharedMap->UninitializeEvent = NULL;

Exit:

    if (IsLocked)
        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    if (NewMap)
        ExFreePoolWithTag(NewMap, 'cScC');

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CcInitializeCacheMap: Status %X\n", Status);
        RtlRaiseStatus(Status);
    }
}

BOOLEAN
NTAPI
CcPurgeCacheSection(
    _In_ PSECTION_OBJECT_POINTERS SectionObjectPointer,
    _In_ OPTIONAL PLARGE_INTEGER FileOffset,
    _In_ ULONG Length,
    _In_ BOOLEAN UninitializeCacheMaps)
{
    PSHARED_CACHE_MAP SharedMap;
    PPRIVATE_CACHE_MAP PrivateMap;
    PVACB Vacb = NULL;
    ULONG ActivePage;
    BOOLEAN IsFullPurge;
    BOOLEAN Result;
    BOOLEAN IsVacbLocked;
    KIRQL OldIrql;

    DPRINT("CcPurgeCacheSection: %p, %p, %X, %X\n", SectionObjectPointer, FileOffset, Length, UninitializeCacheMaps);

    ASSERT(!UninitializeCacheMaps || (Length == 0) || (Length >= (2 * PAGE_SIZE)));

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    SharedMap = SectionObjectPointer->SharedCacheMap;
    if (SharedMap)
    {
        if (SharedMap->Flags & 0x2000)
        {
            if (!((ULONG_PTR)FileOffset & 1))
            {
                KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
                return TRUE;
            }

            FileOffset = (PLARGE_INTEGER)((ULONG_PTR)FileOffset ^ 1);
        }

        SharedMap->OpenCount++;
        KeAcquireSpinLockAtDpcLevel(&SharedMap->ActiveVacbSpinLock);

        Vacb = SharedMap->ActiveVacb;
        if (Vacb)
        {
            ActivePage = SharedMap->ActivePage;
            SharedMap->ActiveVacb = NULL;
            IsVacbLocked = ((SharedMap->Flags & SHARE_FL_VACB_LOCKED) != 0);
        }

        KeReleaseSpinLockFromDpcLevel(&SharedMap->ActiveVacbSpinLock);
    }

    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    if (Vacb)
        CcFreeActiveVacb(SharedMap, Vacb, ActivePage, IsVacbLocked);

    if (SharedMap)
    {
        if (UninitializeCacheMaps)
        {
            while (!IsListEmpty(&SharedMap->PrivateList))
            {
                PrivateMap = CONTAINING_RECORD(SharedMap->PrivateList.Flink, PRIVATE_CACHE_MAP, PrivateLinks);
                CcUninitializeCacheMap(PrivateMap->FileObject, NULL, NULL);
            }
        }

        while (SharedMap->Vacbs && !CcUnmapVacbArray(SharedMap, FileOffset, Length, FALSE))
        {
            DPRINT1("CcPurgeCacheSection: FIXME\n");
            ASSERT(FALSE);
        }
    }

    while (TRUE)
    {
        if (SharedMap && FileOffset)
            IsFullPurge = TRUE;
        else
            IsFullPurge = FALSE;

        Result = MmPurgeSection(SectionObjectPointer, FileOffset, Length, IsFullPurge);
        if (Result)
            break;

        if (Length)
            break;

        if (!MmCanFileBeTruncated(SectionObjectPointer, FileOffset))
            break;

        KeDelayExecutionThread(KernelMode, FALSE, &CcCollisionDelay);
    }

    if (SharedMap)
    {
        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

        SharedMap->OpenCount--;

        if (!SharedMap->OpenCount &&
            !(SharedMap->Flags & SHARE_FL_WRITE_QUEUED) &&
            !SharedMap->DirtyPages)
        {
            RemoveEntryList(&SharedMap->SharedCacheMapLinks);
            InsertTailList(&CcDirtySharedCacheMapList.SharedCacheMapLinks, &SharedMap->SharedCacheMapLinks);

            LazyWriter.OtherWork = 1;

            if (!LazyWriter.ScanActive)
                CcScheduleLazyWriteScan(FALSE);
        }

        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
    }

    return Result;
}

VOID
NTAPI
CcSetDirtyPageThreshold(IN PFILE_OBJECT FileObject,
                        IN ULONG DirtyPageThreshold)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
CcPurgeAndClearCacheSection(
    PSHARED_CACHE_MAP SharedMap,
    PLARGE_INTEGER FileSize)
{
    IO_STATUS_BLOCK IoStatus;
    LARGE_INTEGER FileOffset;
    PVACB Vacb;
    PVOID Address;
    ULONG LengthForZero;
    ULONG ReceivedLength;
    BOOLEAN IsHandle = TRUE;

    DPRINT("CcPurgeAndClearCacheSection: SharedMap %p, FileSize %I64x\n", SharedMap, (FileSize ? FileSize->QuadPart : 0));

    if (SharedMap->Flags & 0x2000)
    {
        if (!((ULONG_PTR)FileSize & 1))
            return;

        FileSize = (PLARGE_INTEGER)((ULONG_PTR)FileSize ^ 1);
    }

    if (!(FileSize->LowPart & (PAGE_SIZE - 1)))
        goto Finish;

    FileOffset.QuadPart = FileSize->QuadPart;
    FileSize = &FileOffset;

    if (!SharedMap->Section || !SharedMap->Vacbs)
    {
        MmFlushSection(SharedMap->FileObject->SectionObjectPointer, FileSize, 1, &IoStatus, 0);
        ASSERT(IoStatus.Status != STATUS_ENCOUNTERED_WRITE_IN_PROGRESS);
        goto Finish;
    }

    LengthForZero = (PAGE_SIZE - (FileOffset.LowPart & (PAGE_SIZE - 1)));
    Address = CcGetVirtualAddress(SharedMap, FileOffset, &Vacb, &ReceivedLength);

    _SEH2_TRY
    {
        RtlZeroMemory(Address, LengthForZero);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT1("CcPurgeAndClearCacheSection: FIXME\n");
        ASSERT(FALSE);
    }
    _SEH2_END;

    if (IsHandle)
    {
        if (FileOffset.QuadPart > SharedMap->ValidDataGoal.QuadPart)
            MmSetAddressRangeModified(Address, 1);
        else
            CcSetDirtyInMask(SharedMap, &FileOffset, LengthForZero);

        FileOffset.QuadPart += LengthForZero;
    }

    CcFreeVirtualAddress(Vacb);

Finish:
    CcPurgeCacheSection(SharedMap->FileObject->SectionObjectPointer, FileSize, 0, FALSE);
}

VOID
NTAPI
CcSetFileSizes(
    _In_ PFILE_OBJECT FileObject,
    _In_ PCC_FILE_SIZES FileSizes)
{
    PSHARED_CACHE_MAP SharedMap;
    LARGE_INTEGER ValidDataLength;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER FileSize;
    IO_STATUS_BLOCK IoStatus;
    PVACB ActiveVacb;
    ULONG ActivePage;
    BOOLEAN IsVacbLocked;
    KIRQL OldIrql;
    NTSTATUS Status;

    DPRINT("CcSetFileSizes: FileObject %p FileSizes %X\n", FileObject, FileSizes);

    FileSize = FileSizes->FileSize;
    AllocationSize = FileSizes->AllocationSize;
    ValidDataLength = FileSizes->ValidDataLength;

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    SharedMap = FileObject->SectionObjectPointer->SharedCacheMap;

    if (!SharedMap || !SharedMap->Section)
    {
        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

        if (BYTE_OFFSET(FileSize.LowPart))
        {
            MmFlushSection(FileObject->SectionObjectPointer, &FileSize, 1, &IoStatus, 0);
            ASSERT(IoStatus.Status != STATUS_ENCOUNTERED_WRITE_IN_PROGRESS);
        }

        CcPurgeCacheSection(FileObject->SectionObjectPointer, &FileSize, 0, FALSE);
        return;
    }

    if (AllocationSize.QuadPart > SharedMap->SectionSize.QuadPart)
    {
        SharedMap->OpenCount++;
        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

        AllocationSize.QuadPart += (CC_VACBS_DEFAULT_MAPPING_SIZE - 1);
        AllocationSize.LowPart &= ~(CC_VACBS_DEFAULT_MAPPING_SIZE - 1);

        Status = MmExtendSection((PSECTION)SharedMap->Section, &AllocationSize, 1);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("CcSetFileSizes: Status %X\n", Status);
            Status = FsRtlNormalizeNtstatus(Status, STATUS_UNEXPECTED_MM_EXTEND_ERR);
        }
        else
        {
            Status = CcExtendVacbArray(SharedMap, AllocationSize);
        }

        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
        SharedMap->OpenCount--;

        if (!SharedMap->OpenCount &&
            !(SharedMap->Flags & SHARE_FL_WRITE_QUEUED) &&
            !SharedMap->DirtyPages)
        {
            RemoveEntryList(&SharedMap->SharedCacheMapLinks);
            InsertTailList(&CcDirtySharedCacheMapList.SharedCacheMapLinks, &SharedMap->SharedCacheMapLinks);

            LazyWriter.OtherWork = 1;

            if (!LazyWriter.ScanActive)
                CcScheduleLazyWriteScan(FALSE);
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("CcSetFileSizes: Status %X\n", Status);
            KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
            RtlRaiseStatus(Status);
        }

        SharedMap = FileObject->SectionObjectPointer->SharedCacheMap;
        if (!SharedMap)
        {
            KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
            return;
        }
    }

    SharedMap->OpenCount++;

    if (FileSize.QuadPart < SharedMap->ValidDataGoal.QuadPart ||
        FileSize.QuadPart < SharedMap->FileSize.QuadPart)
    {
        KeAcquireSpinLockAtDpcLevel(&SharedMap->ActiveVacbSpinLock);

        ActiveVacb = SharedMap->ActiveVacb;

        if (SharedMap->ActiveVacb)
        {
            ActivePage = SharedMap->ActivePage;
            SharedMap->ActiveVacb = NULL;
            IsVacbLocked = ((SharedMap->Flags & SHARE_FL_VACB_LOCKED) != 0);
        }

        KeReleaseSpinLockFromDpcLevel(&SharedMap->ActiveVacbSpinLock);

        if (ActiveVacb || SharedMap->NeedToZero)
        {
            KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
            CcFreeActiveVacb(SharedMap, ActiveVacb, ActivePage, IsVacbLocked);
            OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
        }
    }

    if (SharedMap->ValidDataLength.QuadPart != MAXLONGLONG)
    {
        if (SharedMap->ValidDataLength.QuadPart > FileSize.QuadPart)
            SharedMap->ValidDataLength.QuadPart = FileSize.QuadPart;

        SharedMap->ValidDataGoal.QuadPart = ValidDataLength.QuadPart;
    }

    if (FileSize.QuadPart < SharedMap->FileSize.QuadPart &&
        !(SharedMap->Flags & SHARE_FL_PIN_ACCESS) &&
        !SharedMap->VacbActiveCount)
    {
        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

        if (!FileSize.QuadPart)
        {
            if (SharedMap->Mbcb)
                CcDeleteMbcb(SharedMap);

            if (!IsListEmpty(&SharedMap->BcbList))
                CcDeleteBcbs(SharedMap);
        }

        CcPurgeAndClearCacheSection(SharedMap, &FileSize);

        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
    }

    SharedMap->OpenCount--;
    SharedMap->FileSize.QuadPart = FileSize.QuadPart;

    if (!SharedMap->OpenCount &&
        !(SharedMap->Flags & SHARE_FL_WRITE_QUEUED) &&
        !SharedMap->DirtyPages)
    {
        RemoveEntryList(&SharedMap->SharedCacheMapLinks);
        InsertTailList(&CcDirtySharedCacheMapList.SharedCacheMapLinks, &SharedMap->SharedCacheMapLinks);

        LazyWriter.OtherWork = 1;

        if (!LazyWriter.ScanActive)
            CcScheduleLazyWriteScan(FALSE);
    }

    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
}

BOOLEAN
NTAPI
CcUninitializeCacheMap(
    _In_ PFILE_OBJECT FileObject,
    _In_ PLARGE_INTEGER TruncateSize OPTIONAL,
    _In_ PCACHE_UNINITIALIZE_EVENT Event OPTIONAL)
{
    PSHARED_CACHE_MAP SharedMap;
    PPRIVATE_CACHE_MAP PrivateMap;
    PVACB Vacb = NULL;
    ULONG ActivePage;
    BOOLEAN Result = FALSE;
    KIRQL OldIrql;

    DPRINT("CcUninitializeCacheMap: %p [%wZ], %p\n", FileObject, &FileObject->FileName, FileObject->SectionObjectPointer);

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    SharedMap = FileObject->SectionObjectPointer->SharedCacheMap;
    PrivateMap = FileObject->PrivateCacheMap;

    if (PrivateMap)
    {
        ASSERT(PrivateMap->FileObject == FileObject);

        SharedMap->OpenCount--;
        RemoveEntryList(&PrivateMap->PrivateLinks);

        if (PrivateMap == &SharedMap->PrivateCacheMap)
        {
            PrivateMap->NodeTypeCode = 0;
            PrivateMap = NULL;
        }

        FileObject->PrivateCacheMap = NULL;
    }

    if (!SharedMap)
    {
        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

        if (TruncateSize &&
            !TruncateSize->QuadPart &&
            FileObject->SectionObjectPointer->DataSectionObject)
        {
            CcPurgeCacheSection(FileObject->SectionObjectPointer, TruncateSize, 0, FALSE);
        }

        if (Event)
            KeSetEvent(&Event->Event, 0, FALSE);

        goto Exit;
    }

    if (TruncateSize)
    {
        if (!TruncateSize->QuadPart && SharedMap->FileSize.QuadPart)
            SharedMap->Flags |= SHARE_FL_TRUNCATE_SIZE;
        else if (IsListEmpty(&SharedMap->PrivateList))
            SharedMap->FileSize.QuadPart = TruncateSize->QuadPart;
    }

    if (SharedMap->OpenCount)
    {
        if (Event)
        {
            if (IsListEmpty(&SharedMap->PrivateList))
            {
                Event->Next = SharedMap->UninitializeEvent;
                SharedMap->UninitializeEvent = Event;
            }
            else
            {
                KeSetEvent(&Event->Event, 0, FALSE);
            }
        }

        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

        Result = FALSE;
        goto Exit;
    }

    if (SharedMap->Flags & 0x2000)
    {
        SharedMap->Flags = (SharedMap->Flags & ~(0x2000 | 0x2));

        DPRINT1("CcUninitializeCacheMap: FIXME MmEnableModifiedWriteOfSection()\n");
        ASSERT(FALSE);
    }

    ASSERT(IsListEmpty(&SharedMap->PrivateList));

    if (Event)
    {
        Event->Next = SharedMap->UninitializeEvent;
        SharedMap->UninitializeEvent = Event;
    }

    if ((SharedMap->Flags & SHARE_FL_PIN_ACCESS) || Event)
    {
        if (!(SharedMap->Flags & SHARE_FL_WRITE_QUEUED) &&
            !SharedMap->DirtyPages &&
            !(SharedMap->Flags & 0x8000))
        {
            CcDeleteSharedCacheMap(SharedMap, OldIrql, FALSE);
            Result = TRUE;
            goto Exit;
        }
    }

    if (!(SharedMap->Flags & SHARE_FL_WRITE_QUEUED))
    {
        RemoveEntryList(&SharedMap->SharedCacheMapLinks);
        InsertTailList(&CcDirtySharedCacheMapList.SharedCacheMapLinks, &SharedMap->SharedCacheMapLinks);
    }

    LazyWriter.OtherWork = 1;

    if (!LazyWriter.ScanActive)
        CcScheduleLazyWriteScan(FALSE);

    KeAcquireSpinLockAtDpcLevel(&SharedMap->ActiveVacbSpinLock);

    Vacb = SharedMap->ActiveVacb;
    if (Vacb)
    {
        SharedMap->ActiveVacb = NULL;
        ActivePage = SharedMap->ActivePage;
    }

    KeReleaseSpinLockFromDpcLevel(&SharedMap->ActiveVacbSpinLock);
    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    DPRINT("CcUninitializeCacheMap: SharedMap %p, Vacb %p\n", SharedMap, Vacb);

    if (Vacb)
    {
        BOOLEAN IsVacbLocked = ((SharedMap->Flags & SHARE_FL_VACB_LOCKED) != 0);
        CcFreeActiveVacb(Vacb->SharedCacheMap, Vacb, ActivePage, IsVacbLocked);
    }

Exit:

    if (PrivateMap)
        ExFreePoolWithTag(PrivateMap, 'cPcC');

    return Result;
}

BOOLEAN
NTAPI
CcZeroData(IN PFILE_OBJECT FileObject,
           IN PLARGE_INTEGER StartOffset,
           IN PLARGE_INTEGER EndOffset,
           IN BOOLEAN Wait)
{
    PDEVICE_OBJECT DeviceObject;
    IO_STATUS_BLOCK IoStatus;
    PPFN_NUMBER MdlPage;
    PVOID ZeroBuffer = NULL;
    PCC_BCB Bcb = NULL;
    PMDL Mdl = NULL;
    PVOID PinBuffer;
    LARGE_INTEGER FileOffset;
    LARGE_INTEGER DataSize;
    LARGE_INTEGER RemainSize;
    LARGE_INTEGER NextOffset;
    KEVENT Event;
    ULONG CurrentSize;
    ULONG ZeroBufferSize;
    ULONG ByteCount = 0;
    ULONG OldByteCount;
    ULONG SectorMask;
    ULONG PinLength;
    ULONG ZeroSize;
    ULONG ix;
    UCHAR OldClustering = 0;
    BOOLEAN IsWriteThrough;
    BOOLEAN IsAggressiveZero = FALSE;
    BOOLEAN Result;
    NTSTATUS Status;

    DPRINT("CcZeroData: %p, %I64X, %I64X, %X\n",
           FileObject, (StartOffset ? StartOffset->QuadPart : 0LL), (EndOffset ? EndOffset->QuadPart : 0LL), Wait);

    IsWriteThrough = ((FileObject->Flags & FO_WRITE_THROUGH) != 0 || !FileObject->PrivateCacheMap);

    if (IsWriteThrough && !Wait)
        return FALSE;

    DeviceObject = IoGetRelatedDeviceObject(FileObject);
    SectorMask = (DeviceObject->SectorSize - 1);

    FileOffset.QuadPart = StartOffset->QuadPart;
    DataSize.QuadPart = (EndOffset->QuadPart - StartOffset->QuadPart);

    ASSERT(DataSize.QuadPart <= 0x2000 ||
           ((DataSize.LowPart & SectorMask) == 0  && (FileOffset.LowPart & SectorMask) == 0));

    if (DataSize.QuadPart <= 0x2000 || MmAvailablePages >= 0x40)
    {
        if (!IsWriteThrough)
        {
            //_SEH2_TRY

            CurrentSize = 0x10000;
            Result = TRUE;

            while (CurrentSize)
            {
                if (CurrentSize >= DataSize.QuadPart)
                {
                    CurrentSize = DataSize.LowPart;
                }
                else if (!Wait)
                {
                    Result = FALSE;
                    break;
                }

                if (!CcPinFileData(FileObject,
                                   &FileOffset,
                                   CurrentSize,
                                   FALSE,
                                   TRUE,
                                   Wait,
                                   &Bcb,
                                   &PinBuffer,
                                   &NextOffset))
                {
                    Result = FALSE;
                    break;
                }

                PinLength = (NextOffset.QuadPart - FileOffset.QuadPart);

                Mdl = IoAllocateMdl(PinBuffer, PinLength, FALSE, FALSE, NULL);
                if (!Mdl)
                {
                    DPRINT1("CcZeroData: STATUS_INSUFFICIENT_RESOURCES\n");
                    ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
                }

                OldClustering = (PsGetCurrentThread()->DisablePageFaultClustering + 2);
                PsGetCurrentThread()->DisablePageFaultClustering = 1;

                MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);

                PsGetCurrentThread()->DisablePageFaultClustering = (OldClustering - 2);
                OldClustering = 0;

                FileOffset = NextOffset;

                if (CurrentSize > PinLength)
                    CurrentSize -= PinLength;
                else
                    CurrentSize = 0;

                MmSetAddressRangeModified(PinBuffer, PinLength);

                CcSetDirtyPinnedData(Bcb, NULL);
                CcUnpinFileDataEx(Bcb, FALSE, 0);
                Bcb = NULL;

                MmUnlockPages(Mdl);
                IoFreeMdl(Mdl);
                Mdl = NULL;
            }

            //_SEH2_FINALLY

            if (OldClustering)
                PsGetCurrentThread()->DisablePageFaultClustering = (OldClustering - 2);

            if (Bcb)
                CcUnpinFileDataEx(Bcb, FALSE, 0);

            if (Mdl)
                IoFreeMdl(Mdl);

            //_SEH2_END;

            if (!Result)
                return FALSE;

            if (FileOffset.QuadPart >= EndOffset->QuadPart)
                return TRUE;
        }
    }

    ASSERT((FileOffset.LowPart & SectorMask) == 0);

    FileOffset.QuadPart = ((FileOffset.QuadPart + SectorMask) & ~SectorMask);

    RemainSize.QuadPart = ((EndOffset->QuadPart + SectorMask) & ~SectorMask);
    RemainSize.QuadPart -= FileOffset.QuadPart;

    ASSERT((FileOffset.LowPart & SectorMask) == 0);
    ASSERT((RemainSize.LowPart & SectorMask) == 0);

    if (!RemainSize.QuadPart)
        return TRUE;

    //_SEH2_TRY

    if (!RemainSize.HighPart && RemainSize.LowPart < PAGE_SIZE)
        ZeroBufferSize = RemainSize.LowPart;
    else
        ZeroBufferSize = PAGE_SIZE;

    ZeroBuffer = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, ZeroBufferSize, 'eZcC');
    if (!ZeroBuffer)
    {
        DPRINT1("CcZeroData: FIXME STATUS_INSUFFICIENT_RESOURCES\n");
        ASSERT(FALSE);
        ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
    }

    if (!RemainSize.HighPart && RemainSize.LowPart < 0x80000)
    {
        ZeroSize = RemainSize.LowPart;
    }
    else if (InterlockedIncrement(&CcAggressiveZeroCount) > CcAggressiveZeroThreshold)
    {
        InterlockedDecrement(&CcAggressiveZeroCount);
        ZeroSize = 0x10000;
    }
    else
    {
        IsAggressiveZero = TRUE;
        ZeroSize = 0x80000;
    }

    while (TRUE)
    {
        Mdl = IoAllocateMdl(ZeroBuffer, ZeroSize, FALSE, FALSE, NULL);

        if (!Mdl && ZeroSize != ZeroBufferSize)
            goto Continue;

        if (!Mdl)
        {
            DPRINT1("CcZeroData: STATUS_INSUFFICIENT_RESOURCES\n");
            ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
        }

        if (ZeroSize == ZeroBufferSize)
        {
            MmBuildMdlForNonPagedPool(Mdl);
            break;
        }

        OldByteCount = Mdl->ByteCount;
        Mdl->ByteCount = ZeroBufferSize;

        MmBuildMdlForNonPagedPool(Mdl);

        Mdl->MappedSystemVa = NULL;
        Mdl->ByteCount = OldByteCount;

        Mdl->MdlFlags = (Mdl->MdlFlags & ~MDL_SOURCE_IS_NONPAGED_POOL) | MDL_PAGES_LOCKED;

        MdlPage = MmGetMdlPfnArray(Mdl);

        for (ix = 1; ix < ((OldByteCount + (PAGE_SIZE - 1)) / PAGE_SIZE); ix++)
        {
            MdlPage[ix] = MdlPage[ix - 1];
        }

        if (MmGetSystemAddressForMdlSafe(Mdl, LowPagePriority))
            break;

        IoFreeMdl(Mdl);

Continue:

        ZeroSize = ((ZeroSize / 2) & ~SectorMask);

        if (ZeroSize < ZeroBufferSize)
            ZeroSize = ZeroBufferSize;

        ASSERT((ZeroSize & SectorMask) == 0 && ZeroSize != 0);
    }

    RtlZeroMemory(ZeroBuffer, ZeroBufferSize);

    ASSERT(MmGetSystemAddressForMdl(Mdl));
    ByteCount = Mdl->ByteCount;

    ASSERT(ZeroSize != 0);
    ASSERT((ZeroSize & SectorMask) == 0);
    ASSERT((RemainSize.LowPart & SectorMask) == 0);

    while (RemainSize.QuadPart)
    {
        if (ZeroSize > RemainSize.QuadPart)
            ZeroSize = RemainSize.LowPart;

        KeInitializeEvent(&Event, NotificationEvent, FALSE);

        Mdl->ByteCount = ZeroSize;

        Status = IoSynchronousPageWrite(FileObject, Mdl, &FileOffset, &Event, &IoStatus);

        if (Status == STATUS_PENDING)
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("CcZeroData: Status %X\n", Status);
            ExRaiseStatus(Status);
        }

        if (!NT_SUCCESS(IoStatus.Status))
        {
            DPRINT1("CcZeroData: Status %X\n", Status);
            ExRaiseStatus(IoStatus.Status);
        }

        FileOffset.QuadPart += ZeroSize;
        RemainSize.QuadPart -= ZeroSize;
    }

    //_SEH2_FINALLY

    if (Mdl)
    {
        if (ByteCount && !(Mdl->MdlFlags & MDL_SOURCE_IS_NONPAGED_POOL))
        {
            Mdl->ByteCount = ByteCount;
            MmUnmapLockedPages(Mdl->MappedSystemVa, Mdl);
        }

        IoFreeMdl(Mdl);
    }

    if (IsAggressiveZero)
        InterlockedDecrement(&CcAggressiveZeroCount);

    if (ZeroBuffer)
        ExFreePoolWithTag(ZeroBuffer, 'eZcC');

    //_SEH2_END;

    return TRUE;
}

VOID
NTAPI
CcZeroEndOfLastPage(
    _In_ PFILE_OBJECT FileObject)
{
    PFSRTL_ADVANCED_FCB_HEADER Fcb;
    PSHARED_CACHE_MAP SharedMap;
    IO_STATUS_BLOCK IoStatus;
    PVOID NeedToZero = NULL;
    PVACB ActiveVacb = NULL;
    ULONG ActivePage;
    BOOLEAN IsActiveVacbOrNeedZero = FALSE;
    BOOLEAN IsVacbLocked;
    KIRQL OldIrql;

    DPRINT("CcZeroEndOfLastPage: %p\n", FileObject);

    FsRtlAcquireFileExclusive(FileObject);
    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    SharedMap = FileObject->SectionObjectPointer->SharedCacheMap;

    if (SharedMap)
    {
        NeedToZero = SharedMap->NeedToZero;

        if (SharedMap->ActiveVacb || NeedToZero)
        {
            SharedMap->OpenCount++;
            IsActiveVacbOrNeedZero = TRUE;

            KeAcquireSpinLockAtDpcLevel(&SharedMap->ActiveVacbSpinLock);

            ActiveVacb = SharedMap->ActiveVacb;
            if (ActiveVacb)
            {
                ActivePage = SharedMap->ActivePage;
                SharedMap->ActiveVacb = NULL;
                IsVacbLocked = ((SharedMap->Flags & 0x80) != 0);
            }

            KeReleaseSpinLockFromDpcLevel(&SharedMap->ActiveVacbSpinLock);
        }
    }

    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);

    Fcb = (PFSRTL_ADVANCED_FCB_HEADER)FileObject->FsContext;

    if (Fcb->Flags & FSRTL_FLAG_ADVANCED_HEADER)
    {
        ExAcquireFastMutex(Fcb->FastMutex);
        Fcb->Flags |= FSRTL_FLAG_USER_MAPPED_FILE;
        ExReleaseFastMutex(Fcb->FastMutex);
    }
    else
    {
        Fcb->Flags |= FSRTL_FLAG_USER_MAPPED_FILE;
    }

    if (ActiveVacb || NeedToZero)
        CcFreeActiveVacb(SharedMap, ActiveVacb, ActivePage, IsVacbLocked);

    if (Fcb->Flags2 & FSRTL_FLAG2_PURGE_WHEN_MAPPED)
    {
        SharedMap = FileObject->SectionObjectPointer->SharedCacheMap;
        ASSERT(((PSHARED_CACHE_MAP)(FileObject->SectionObjectPointer->SharedCacheMap))->VacbActiveCount == 0);

        CcFlushCache(FileObject->SectionObjectPointer, NULL, 0, &IoStatus);

        if (IoStatus.Status == STATUS_SUCCESS)
            CcPurgeCacheSection(FileObject->SectionObjectPointer, NULL, 0, FALSE);

        SharedMap = FileObject->SectionObjectPointer->SharedCacheMap;
        ASSERT(((PSHARED_CACHE_MAP)(FileObject->SectionObjectPointer->SharedCacheMap))->VacbActiveCount == 0);
    }

    FsRtlReleaseFile(FileObject);

    if (!IsActiveVacbOrNeedZero)
        return;

    OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

    SharedMap->OpenCount--;

    if (!SharedMap->OpenCount &&
        !(SharedMap->Flags & SHARE_FL_WRITE_QUEUED) &&
        !SharedMap->DirtyPages)
    {
        RemoveEntryList(&SharedMap->SharedCacheMapLinks);
        InsertTailList(&CcDirtySharedCacheMapList.SharedCacheMapLinks, &SharedMap->SharedCacheMapLinks);

        LazyWriter.OtherWork = 1;

        if (!LazyWriter.ScanActive)
            CcScheduleLazyWriteScan(FALSE);
    }

    KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
}

//INIT_FUNCTION
BOOLEAN
NTAPI
CcInitializeCacheManager(VOID)
{
    PGENERAL_LOOKASIDE LookasideList;
    PWORK_QUEUE_ITEM WorkItem;
    PKPRCB Prcb;
    ULONG ix;
    USHORT MaximumDepth;

    DPRINT("CcInitializeCacheManager()\n");

    CcIdleDelayTick = (10000000 / KeQueryTimeIncrement());

    InitializeListHead(&CcCleanSharedCacheMapList);

    InitializeListHead(&CcDirtySharedCacheMapList.SharedCacheMapLinks);
    CcDirtySharedCacheMapList.Flags = 0x800;

    InsertTailList(&CcDirtySharedCacheMapList.SharedCacheMapLinks, &CcLazyWriterCursor.SharedCacheMapLinks);
    CcLazyWriterCursor.Flags = 0x800;

    InitializeListHead(&CcIdleWorkerThreadList);
    InitializeListHead(&CcFastTeardownWorkQueue);
    InitializeListHead(&CcExpressWorkQueue);
    InitializeListHead(&CcRegularWorkQueue);
    InitializeListHead(&CcPostTickWorkQueue);

    CcCapturedSystemSize = MmQuerySystemSize();

    if (!CcNumberWorkerThreads)
    {
        if (CcCapturedSystemSize == MmSmallSystem)
        {
            CcNumberWorkerThreads = (ExCriticalWorkerThreads - 1);
            CcDirtyPageThreshold = (MmNumberOfPhysicalPages / 8);
            CcAggressiveZeroThreshold = 1;
        }
        else if (CcCapturedSystemSize == MmMediumSystem)
        {
            CcNumberWorkerThreads = (ExCriticalWorkerThreads - 1);
            CcDirtyPageThreshold = (MmNumberOfPhysicalPages / 4);
            CcAggressiveZeroThreshold = 2;
        }
        else if (CcCapturedSystemSize == MmLargeSystem)
        {
            CcNumberWorkerThreads = (ExCriticalWorkerThreads - 2);

            if (MmSystemCacheWs.MaximumWorkingSetSize <= 0x400)
            {
                CcDirtyPageThreshold = (MmNumberOfPhysicalPages / 8) + (MmNumberOfPhysicalPages / 4);
            }
            else if ((MmSystemCacheWs.MaximumWorkingSetSize - 0x200) > (MmNumberOfPhysicalPages / 2))
            {
                CcDirtyPageThreshold = (MmNumberOfPhysicalPages / 2);
            }
            else
            {
                CcDirtyPageThreshold = (MmSystemCacheWs.MaximumWorkingSetSize - 0x200);
            }

            CcAggressiveZeroThreshold = 4;
        }
        else
        {
            CcNumberWorkerThreads = 1;
            CcDirtyPageThreshold = MmNumberOfPhysicalPages / 8;
        }

        CcDirtyPageTarget = (CcDirtyPageThreshold / 2) + (CcDirtyPageThreshold / 4);
    }

    CcAggressiveZeroCount = 0;

    for (ix = 0; ix < CcNumberWorkerThreads; ix++)
    {
        WorkItem = ExAllocatePoolWithTag(NonPagedPool, sizeof(*WorkItem), 'qWcC');
        if (!WorkItem)
        {
            ASSERT(FALSE);
            KeBugCheckEx(0x34, 0x400E0, 0, 0, 0);
        }

        ExInitializeWorkItem(WorkItem, CcWorkerThread, WorkItem);
        InsertTailList(&CcIdleWorkerThreadList, &WorkItem->List);
    }

    RtlZeroMemory(&LazyWriter, sizeof(LazyWriter));

    InitializeListHead(&LazyWriter.WorkQueue);
    KeInitializeDpc(&LazyWriter.ScanDpc, CcScanDpc, NULL);
    KeInitializeTimer(&LazyWriter.ScanTimer);

    if (CcCapturedSystemSize == MmSmallSystem)
    {
        MaximumDepth = 0x20;
    }
    else if (CcCapturedSystemSize == MmMediumSystem)
    {
        MaximumDepth = 0x40;
    }
    else if (CcCapturedSystemSize == MmLargeSystem)
    {
        if (MmIsThisAnNtAsSystem())
            MaximumDepth = 0x100;
        else
            MaximumDepth = 0x80;
    }

    ExInitializeSystemLookasideList(&CcTwilightLookasideList,
                                    NonPagedPool,
                                    0x10,
                                    'kWcC',
                                    MaximumDepth,
                                    &ExSystemLookasideListHead);

    for (ix = 0; ix < KeNumberProcessors; ix++)
    {
        Prcb = KiProcessorBlock[ix];
        Prcb->PPLookasideList[5].L = &CcTwilightLookasideList;

        LookasideList = ExAllocatePoolWithTag(NonPagedPool, sizeof(*LookasideList), 'KWcC');

        if (LookasideList)
            ExInitializeSystemLookasideList(LookasideList,
                                            NonPagedPool,
                                            0x10,
                                            'KWcC',
                                            MaximumDepth,
                                            &ExSystemLookasideListHead);
        else
            LookasideList = &CcTwilightLookasideList;

        Prcb->PPLookasideList[5].P = LookasideList;
    }

    KeInitializeSpinLock(&CcDeferredWriteSpinLock);
    InitializeListHead(&CcDeferredWrites);

    CcInitializeVacbs();

    return TRUE;
}

/* EOF */
