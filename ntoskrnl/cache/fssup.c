/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Kernel
 * FILE:            ntoskrnl/cache/fssup.c
 * PURPOSE:         Logging and configuration routines
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 *                  Art Yerkes
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "newcc.h"
#include "section/newmm.h"
//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PFSN_PREFETCHER_GLOBALS CcPfGlobals;
extern LONG CcOutstandingDeletes;
extern KEVENT CcpLazyWriteEvent;
extern KEVENT CcFinalizeEvent;
extern VOID NTAPI CcpUnmapThread(PVOID Unused);
extern VOID NTAPI CcpLazyWriteThread(PVOID Unused);
HANDLE CcUnmapThreadHandle, CcLazyWriteThreadHandle;
CLIENT_ID CcUnmapThreadId, CcLazyWriteThreadId;
FAST_MUTEX GlobalPageOperation;

/*

A note about private cache maps.

CcInitializeCacheMap and CcUninitializeCacheMap are not meant to be paired,
although they can work that way.

The actual operation I've gleaned from reading both jan kratchovil's writing
and real filesystems is this:

CcInitializeCacheMap means:

Make the indicated FILE_OBJECT have a private cache map if it doesn't already
and make it have a shared cache map if it doesn't already.

CcUninitializeCacheMap means:

Take away the private cache map from this FILE_OBJECT.  If it's the last
private cache map corresponding to a specific shared cache map (the one that
was present in the FILE_OBJECT when it was created), then delete that too,
flusing all cached information.

Using these simple semantics, filesystems can do all the things they actually
do:

- Copy out the shared cache map pointer from a newly initialized file object
and store it in the fcb cache.
- Copy it back into any file object and call CcInitializeCacheMap to make
that file object be associated with the caching of all the other siblings.
- Call CcUninitializeCacheMap on a FILE_OBJECT many times, but have only the
first one count for each specific FILE_OBJECT.
- Have the actual last call to CcUninitializeCacheMap (that is, the one that
causes zero private cache maps to be associated with a shared cache map) to
delete the cache map and flush.

So private cache map here is a light weight structure that just remembers
what shared cache map it associates with.

 */
typedef struct _NOCC_PRIVATE_CACHE_MAP
{
    LIST_ENTRY ListEntry;
    PFILE_OBJECT FileObject;
    PNOCC_CACHE_MAP Map;
} NOCC_PRIVATE_CACHE_MAP, *PNOCC_PRIVATE_CACHE_MAP;

LIST_ENTRY CcpAllSharedCacheMaps;
LIST_ENTRY CcCleanSharedCacheMapList;

/* FUNCTIONS ******************************************************************/

BOOLEAN
NTAPI
CcInitializeCacheManager(VOID)
{
    DPRINT("CcInitializeCacheManager()\n");

    InitializeListHead(&CcCleanSharedCacheMapList);

    CcInitializeVacbs();

    return TRUE;
}

VOID
NTAPI
CcPfInitializePrefetcher(VOID)
{
    /* Notify debugger */
    DbgPrintEx(DPFLTR_PREFETCHER_ID,
               DPFLTR_TRACE_LEVEL,
               "CCPF: InitializePrefetecher()\n");

    /* Setup the Prefetcher Data */
    InitializeListHead(&CcPfGlobals.ActiveTraces);
    InitializeListHead(&CcPfGlobals.CompletedTraces);
    ExInitializeFastMutex(&CcPfGlobals.CompletedTracesLock);

    /* FIXME: Setup the rest of the prefetecher */
}

BOOLEAN
NTAPI
CcpAcquireFileLock(PNOCC_CACHE_MAP Map)
{
    DPRINT("Calling AcquireForLazyWrite: %x\n", Map->LazyContext);
    return Map->Callbacks.AcquireForLazyWrite(Map->LazyContext, TRUE);
}

VOID
NTAPI
CcpReleaseFileLock(PNOCC_CACHE_MAP Map)
{
    DPRINT("Releasing Lazy Write %x\n", Map->LazyContext);
    Map->Callbacks.ReleaseFromLazyWrite(Map->LazyContext);
}

/*

Cc functions are required to treat alternate streams of a file as the same
for the purpose of caching, meaning that we must be able to find the shared
cache map associated with the ``real'' stream associated with a stream file
object, if one exists.  We do that by identifying a private cache map in
our gamut that has the same volume, device and fscontext as the stream file
object we're holding.  It's heavy but it does work.  This can probably be
improved, although there doesn't seem to be any real association between
a stream file object and a sibling file object in the file object struct
itself.

 */

/* Must have CcpLock() */
PFILE_OBJECT CcpFindOtherStreamFileObject(PFILE_OBJECT FileObject)
{
    PLIST_ENTRY Entry, Private;
    for (Entry = CcpAllSharedCacheMaps.Flink;
         Entry != &CcpAllSharedCacheMaps;
         Entry = Entry->Flink)
    {
        /* 'Identical' test for other stream file object */
        PNOCC_CACHE_MAP Map = CONTAINING_RECORD(Entry, NOCC_CACHE_MAP, Entry);
        for (Private = Map->PrivateCacheMaps.Flink;
             Private != &Map->PrivateCacheMaps;
             Private = Private->Flink)
        {
            PNOCC_PRIVATE_CACHE_MAP PrivateMap = CONTAINING_RECORD(Private,
                                                                   NOCC_PRIVATE_CACHE_MAP,
                                                                   ListEntry);

            if (PrivateMap->FileObject->Flags & FO_STREAM_FILE &&
                PrivateMap->FileObject->DeviceObject == FileObject->DeviceObject &&
                PrivateMap->FileObject->Vpb == FileObject->Vpb &&
                PrivateMap->FileObject->FsContext == FileObject->FsContext &&
                PrivateMap->FileObject->FsContext2 == FileObject->FsContext2 &&
                1)
            {
                return PrivateMap->FileObject;
            }
        }
    }
    return 0;
}

VOID
NTAPI
CcWaitForUninitializeCacheMap(IN PFILE_OBJECT FileObject)
{
    DPRINT("CcWaitForUninitializeCacheMap: FileObject %p\n", FileObject);
    ASSERT(FALSE);
}

/*

This function is used by NewCC's MM to determine whether any section objects
for a given file are not cache sections.  If that's true, we're not allowed
to resize the file, although nothing actually prevents us from doing ;-)

 */

ULONG
NTAPI
CcpCountCacheSections(IN PNOCC_CACHE_MAP Map)
{
    PLIST_ENTRY Entry;
    ULONG Count;

    for (Count = 0, Entry = Map->AssociatedBcb.Flink;
         Entry != &Map->AssociatedBcb;
         Entry = Entry->Flink, Count++);

    return Count;
}

BOOLEAN
NTAPI
CcUninitializeCacheMap(IN PFILE_OBJECT FileObject,
                       IN OPTIONAL PLARGE_INTEGER TruncateSize,
                       IN OPTIONAL PCACHE_UNINITIALIZE_EVENT UninitializeEvent)
{
    BOOLEAN LastMap = FALSE;
    PNOCC_CACHE_MAP Map = (PNOCC_CACHE_MAP)FileObject->SectionObjectPointer->SharedCacheMap;
    PNOCC_PRIVATE_CACHE_MAP PrivateCacheMap = FileObject->PrivateCacheMap;

    DPRINT("Uninitializing file object for %wZ SectionObjectPointer %x\n",
           &FileObject->FileName,
           FileObject->SectionObjectPointer);

    ASSERT(FALSE);

    ASSERT(UninitializeEvent == NULL);

    /* It may not be strictly necessary to flush here, but we do just for
       kicks. */
    if (Map)
        CcpFlushCache(Map, NULL, 0, NULL, FALSE);

    CcpLock();
    /* We have a private cache map, so we've been initialized and haven't been
     * uninitialized. */
    if (PrivateCacheMap)
    {
        ASSERT(!Map || Map == PrivateCacheMap->Map);
        ASSERT(PrivateCacheMap->FileObject == FileObject);

        RemoveEntryList(&PrivateCacheMap->ListEntry);
        /* That was the last private cache map.  It's time to delete all
           cache stripes and all aspects of caching on the file. */
        if (IsListEmpty(&PrivateCacheMap->Map->PrivateCacheMaps))
        {
            /* Get rid of all the cache stripes. */
            while (!IsListEmpty(&PrivateCacheMap->Map->AssociatedBcb))
            {
                PNOCC_BCB Bcb = CONTAINING_RECORD(PrivateCacheMap->Map->AssociatedBcb.Flink,
                                                  NOCC_BCB,
                                                  ThisFileList);

                DPRINT("Evicting cache stripe #%x\n", Bcb - CcCacheSections);
                Bcb->RefCount = 1;
                CcpDereferenceCache(Bcb - CcCacheSections, TRUE);
            }
            RemoveEntryList(&PrivateCacheMap->Map->Entry);
            ExFreePool(PrivateCacheMap->Map);
            FileObject->SectionObjectPointer->SharedCacheMap = NULL;
            LastMap = TRUE;
        }
        ObDereferenceObject(PrivateCacheMap->FileObject);
        FileObject->PrivateCacheMap = NULL;
        ExFreePool(PrivateCacheMap);
    }
    CcpUnlock();

    DPRINT("Uninit complete\n");

    /* The return from CcUninitializeCacheMap means that 'caching was stopped'. */
    return LastMap;
}

/*

CcSetFileSizes is used to tell the cache manager that the file changed
size.  In our case, we use the internal Mm method MmExtendCacheSection
to notify Mm that our section potentially changed size, which may mean
truncating off data.

 */
VOID
NTAPI
CcSetFileSizes(IN PFILE_OBJECT FileObject,
               IN PCC_FILE_SIZES FileSizes)
{
    PNOCC_CACHE_MAP Map = (PNOCC_CACHE_MAP)FileObject->SectionObjectPointer->SharedCacheMap;
    PNOCC_BCB Bcb;

    ASSERT(FALSE);

    if (!Map) return;
    Map->FileSizes = *FileSizes;
    Bcb = Map->AssociatedBcb.Flink == &Map->AssociatedBcb ?
        NULL : CONTAINING_RECORD(Map->AssociatedBcb.Flink, NOCC_BCB, ThisFileList);
    if (!Bcb) return;
    MmExtendCacheSection(Bcb->SectionObject, &FileSizes->FileSize, FALSE);
    DPRINT("FileSizes->FileSize %x\n", FileSizes->FileSize.LowPart);
    DPRINT("FileSizes->AllocationSize %x\n", FileSizes->AllocationSize.LowPart);
    DPRINT("FileSizes->ValidDataLength %x\n", FileSizes->ValidDataLength.LowPart);
}

BOOLEAN
NTAPI
CcGetFileSizes(IN PFILE_OBJECT FileObject,
               IN PCC_FILE_SIZES FileSizes)
{
    PNOCC_CACHE_MAP Map = (PNOCC_CACHE_MAP)FileObject->SectionObjectPointer->SharedCacheMap;
    if (!Map) return FALSE;
    *FileSizes = Map->FileSizes;
    return TRUE;
}

BOOLEAN
NTAPI
CcPurgeCacheSection(IN PSECTION_OBJECT_POINTERS SectionObjectPointer,
                    IN OPTIONAL PLARGE_INTEGER FileOffset,
                    IN ULONG Length,
                    IN BOOLEAN UninitializeCacheMaps)
{
    PNOCC_CACHE_MAP Map = (PNOCC_CACHE_MAP)SectionObjectPointer->SharedCacheMap;

    ASSERT(FALSE);

    if (!Map) return TRUE;
    CcpFlushCache(Map, NULL, 0, NULL, TRUE);
    return TRUE;
}

VOID
NTAPI
CcSetDirtyPageThreshold(IN PFILE_OBJECT FileObject,
                        IN ULONG DirtyPageThreshold)
{
    UNIMPLEMENTED_DBGBREAK();
}

/*

This could be implemented much more intelligently by mapping instances
of a CoW zero page into the affected regions.  We just RtlZeroMemory
for now.

*/
BOOLEAN
NTAPI
CcZeroData(IN PFILE_OBJECT FileObject,
           IN PLARGE_INTEGER StartOffset,
           IN PLARGE_INTEGER EndOffset,
           IN BOOLEAN Wait)
{
    PNOCC_BCB Bcb = NULL;
    PLIST_ENTRY ListEntry = NULL;
    LARGE_INTEGER LowerBound = *StartOffset;
    LARGE_INTEGER UpperBound = *EndOffset;
    LARGE_INTEGER Target, End;
    PVOID PinnedBcb, PinnedBuffer;
    PNOCC_CACHE_MAP Map = FileObject->SectionObjectPointer->SharedCacheMap;

    DPRINT("S %I64x E %I64x\n",
           StartOffset->QuadPart,
           EndOffset->QuadPart);

    ASSERT(FALSE);

    if (!Map)
    {
        NTSTATUS Status;
        IO_STATUS_BLOCK IOSB;
        PCHAR ZeroBuf = ExAllocatePool(PagedPool, PAGE_SIZE);
        ULONG ToWrite;

        if (!ZeroBuf) RtlRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
        DPRINT1("RtlZeroMemory(%x,%x)\n", ZeroBuf, PAGE_SIZE);
        RtlZeroMemory(ZeroBuf, PAGE_SIZE);

        Target.QuadPart = PAGE_ROUND_DOWN(LowerBound.QuadPart);
        End.QuadPart = PAGE_ROUND_UP(UpperBound.QuadPart);

        // Handle leading page
        if (LowerBound.QuadPart != Target.QuadPart)
        {
            ToWrite = MIN(UpperBound.QuadPart - LowerBound.QuadPart,
                          (PAGE_SIZE - LowerBound.QuadPart) & (PAGE_SIZE - 1));

            DPRINT("Zero last half %I64x %lx\n",
                   Target.QuadPart,
                   ToWrite);

            Status = MiSimpleRead(FileObject,
                                  &Target,
                                  ZeroBuf,
                                  PAGE_SIZE,
                                  TRUE,
                                  &IOSB);

            if (!NT_SUCCESS(Status))
            {
                ExFreePool(ZeroBuf);
                RtlRaiseStatus(Status);
            }

            DPRINT1("RtlZeroMemory(%p, %lx)\n",
                    ZeroBuf + LowerBound.QuadPart - Target.QuadPart,
                    ToWrite);

            RtlZeroMemory(ZeroBuf + LowerBound.QuadPart - Target.QuadPart,
                          ToWrite);

            Status = MiSimpleWrite(FileObject,
                                   &Target,
                                   ZeroBuf,
                                   MIN(PAGE_SIZE,
                                       UpperBound.QuadPart-Target.QuadPart),
                                   &IOSB);

            if (!NT_SUCCESS(Status))
            {
                ExFreePool(ZeroBuf);
                RtlRaiseStatus(Status);
            }
            Target.QuadPart += PAGE_SIZE;
        }

        DPRINT1("RtlZeroMemory(%x,%x)\n", ZeroBuf, PAGE_SIZE);
        RtlZeroMemory(ZeroBuf, PAGE_SIZE);

        while (UpperBound.QuadPart - Target.QuadPart > PAGE_SIZE)
        {
            DPRINT("Zero full page %I64x\n",
                   Target.QuadPart);

            Status = MiSimpleWrite(FileObject,
                                   &Target,
                                   ZeroBuf,
                                   PAGE_SIZE,
                                   &IOSB);

            if (!NT_SUCCESS(Status))
            {
                ExFreePool(ZeroBuf);
                RtlRaiseStatus(Status);
            }
            Target.QuadPart += PAGE_SIZE;
        }

        if (UpperBound.QuadPart > Target.QuadPart)
        {
            ToWrite = UpperBound.QuadPart - Target.QuadPart;
            DPRINT("Zero first half %I64x %lx\n",
                   Target.QuadPart,
                   ToWrite);

            Status = MiSimpleRead(FileObject,
                                  &Target,
                                  ZeroBuf,
                                  PAGE_SIZE,
                                  TRUE,
                                  &IOSB);

            if (!NT_SUCCESS(Status))
            {
                ExFreePool(ZeroBuf);
                RtlRaiseStatus(Status);
            }
            DPRINT1("RtlZeroMemory(%x,%x)\n", ZeroBuf, ToWrite);
            RtlZeroMemory(ZeroBuf, ToWrite);
            Status = MiSimpleWrite(FileObject,
                                   &Target,
                                   ZeroBuf,
                                   MIN(PAGE_SIZE,
                                       UpperBound.QuadPart-Target.QuadPart),
                                   &IOSB);
            if (!NT_SUCCESS(Status))
            {
                ExFreePool(ZeroBuf);
                RtlRaiseStatus(Status);
            }
            Target.QuadPart += PAGE_SIZE;
        }

        ExFreePool(ZeroBuf);
        return TRUE;
    }

    CcpLock();
    ListEntry = Map->AssociatedBcb.Flink;

    while (ListEntry != &Map->AssociatedBcb)
    {
        Bcb = CONTAINING_RECORD(ListEntry, NOCC_BCB, ThisFileList);
        CcpReferenceCache(Bcb - CcCacheSections);

        if (Bcb->FileOffset.QuadPart + Bcb->Length >= LowerBound.QuadPart &&
            Bcb->FileOffset.QuadPart < UpperBound.QuadPart)
        {
            DPRINT("Bcb #%x (@%I64x)\n",
                   Bcb - CcCacheSections,
                   Bcb->FileOffset.QuadPart);

            Target.QuadPart = MAX(Bcb->FileOffset.QuadPart,
                                  LowerBound.QuadPart);

            End.QuadPart = MIN(Map->FileSizes.ValidDataLength.QuadPart,
                               UpperBound.QuadPart);

            End.QuadPart = MIN(End.QuadPart,
                               Bcb->FileOffset.QuadPart + Bcb->Length);

            CcpUnlock();

            if (!CcPreparePinWrite(FileObject,
                                   &Target,
                                   End.QuadPart - Target.QuadPart,
                                   TRUE,
                                   Wait,
                                   &PinnedBcb,
                                   &PinnedBuffer))
            {
                return FALSE;
            }

            ASSERT(PinnedBcb == Bcb);

            CcpLock();
            ListEntry = ListEntry->Flink;
            /* Return from pin state */
            CcpUnpinData(PinnedBcb, TRUE);
        }

        CcpUnpinData(Bcb, TRUE);
    }

    CcpUnlock();

    return TRUE;
}

PFILE_OBJECT
NTAPI
CcGetFileObjectFromSectionPtrs(IN PSECTION_OBJECT_POINTERS SectionObjectPointer)
{
    PFILE_OBJECT Result = NULL;
    PNOCC_CACHE_MAP Map = SectionObjectPointer->SharedCacheMap;

    ASSERT(FALSE);

    CcpLock();
    if (!IsListEmpty(&Map->AssociatedBcb))
    {
        PNOCC_BCB Bcb = CONTAINING_RECORD(Map->AssociatedBcb.Flink,
                                          NOCC_BCB,
                                          ThisFileList);

        Result = MmGetFileObjectForSection((PROS_SECTION_OBJECT)Bcb->SectionObject);
    }
    CcpUnlock();
    return Result;
}

PFILE_OBJECT
NTAPI
CcGetFileObjectFromBcb(PVOID Bcb)
{
    PNOCC_BCB RealBcb = (PNOCC_BCB)Bcb;
    DPRINT("BCB #%x\n", RealBcb - CcCacheSections);

    ASSERT(FALSE);

    return MmGetFileObjectForSection((PROS_SECTION_OBJECT)RealBcb->SectionObject);
}

/* PUBLIC FUNCTIONS ***********************************************************/

/* Thanks: http://windowsitpro.com/Windows/Articles/ArticleID/3864/pg/2/2.html */

PSHARED_CACHE_MAP
NTAPI
CcCreateSharedCacheMap(IN PFILE_OBJECT FileObject,
                       IN PCC_FILE_SIZES FileSizes,
                       IN BOOLEAN PinAccess,
                       IN PCACHE_MANAGER_CALLBACKS Callbacks,
                       IN PVOID LazyWriteContext)
{
    PSHARED_CACHE_MAP SharedMap;

    SharedMap = ExAllocatePoolWithTag(NonPagedPool, sizeof(SHARED_CACHE_MAP), 'cScC');
    if (!SharedMap)
    {
        DPRINT1("CcCreateSharedCacheMap: STATUS_INSUFFICIENT_RESOURCES\n");
        return SharedMap;
    }

    RtlZeroMemory(SharedMap, sizeof(SHARED_CACHE_MAP));

    SharedMap->NodeTypeCode = CC_TYPE_SHARED_MAP;
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
    {
        SharedMap->Flags |= SHARE_FL_PIN_ACCESS;
    }

    if (FileObject->Flags & FO_SEQUENTIAL_ONLY)
    {
        SharedMap->Flags |= SHARE_FL_SEQUENTIAL_ONLY;
    }

    SharedMap->Callbacks = Callbacks;
    SharedMap->LazyWriteContext = LazyWriteContext;

    InitializeListHead(&SharedMap->BcbList);
    InitializeListHead(&SharedMap->PrivateList);

    return SharedMap;
}

VOID
NTAPI
CcInitializeCacheMap(IN PFILE_OBJECT FileObject,
                     IN PCC_FILE_SIZES FileSizes,
                     IN BOOLEAN PinAccess,
                     IN PCACHE_MANAGER_CALLBACKS Callbacks,
                     IN PVOID LazyWriteContext)
{
    PSHARED_CACHE_MAP SharedMap;
    PSHARED_CACHE_MAP NewSharedMap = NULL;
    PPRIVATE_CACHE_MAP PrivateMap;
    PCACHE_UNINITIALIZE_EVENT UninitializeEvent;
    PCACHE_UNINITIALIZE_EVENT NextUninitializeEvent;
    PKEVENT CreateEvent;
    CC_FILE_SIZES fileSizes;
    PVOID NewMap = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    BOOLEAN IsLocked;
    BOOLEAN IsNewSharedMap = FALSE;
    BOOLEAN IsSectionInit = FALSE;
    BOOLEAN IsReferenced = FALSE;
    KIRQL OldIrql;

    DPRINT("CcInitializeCacheMap: File %p, '%wZ'\n", FileObject, &FileObject->FileName);

    RtlCopyMemory(&fileSizes, FileSizes, sizeof(fileSizes));

    DPRINT("CcInitializeCacheMap: AllocationSize %I64X, FileSize %I64X, ValidDataLength %I64X\n", fileSizes.AllocationSize.QuadPart, fileSizes.FileSize.QuadPart, fileSizes.ValidDataLength.QuadPart);

    if (!fileSizes.AllocationSize.QuadPart)
    {
        fileSizes.AllocationSize.QuadPart = 1;
    }

    if (FileObject->WriteAccess)
    {
        fileSizes.AllocationSize.QuadPart += (0x100000 - 1);
        fileSizes.AllocationSize.LowPart &= ~(0x100000 - 1);
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
            NewSharedMap = CcCreateSharedCacheMap(FileObject,
                                                  &fileSizes,
                                                  PinAccess,
                                                  Callbacks,
                                                  LazyWriteContext);
            if (!NewSharedMap)
            {
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
            {
                ExFreePoolWithTag(NewSharedMap, 'cScC');
            }

            return;
        }

        SharedMap = FileObject->SectionObjectPointer->SharedCacheMap;
        if (SharedMap)
        {
            if (!(FileObject->Flags & FO_SEQUENTIAL_ONLY))
            {
                SharedMap->Flags &= ~SHARE_FL_SEQUENTIAL_ONLY;
            }
            break;
        }

        if (NewSharedMap)
        {
            InsertTailList(&CcCleanSharedCacheMapList, &NewSharedMap->SharedCacheMapLinks);

            IsNewSharedMap = TRUE;
            SharedMap = NewSharedMap;
            NewMap = NULL;

            FileObject->SectionObjectPointer->SharedCacheMap = SharedMap;
            ObReferenceObject(FileObject);
            break;
        }

        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
    }

    if (FileObject->Flags & FO_RANDOM_ACCESS)
    {
        SharedMap->Flags |= SHARE_FL_RANDOM_ACCESS;
    }

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
    else if (!(SharedMap->Flags & SHARE_FL_SECTION_INIT)) // SharedMap->Vacbs == 0
    {
        SharedMap->OpenCount++;
        SharedMap->Flags |= SHARE_FL_SECTION_INIT;

        if (SharedMap->CreateEvent)
        {
            KeInitializeEvent(SharedMap->CreateEvent, NotificationEvent, FALSE);
        }

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
                status = 0;//MmExtendSection(SharedMap->Section, &fileSizes.AllocationSize, 1);
                if (!NT_SUCCESS(status))
                {
                    Status = FsRtlNormalizeNtstatus(status, STATUS_UNEXPECTED_MM_EXTEND_ERR);
                    goto ErrorExit;
                }
            }

            DPRINT1("CcInitializeCacheMap: FIXME CcExtendVacbArray()\n");
            ASSERT(FALSE);
            Status = 0;//CcExtendVacbArray(SharedMap, fileSizes.AllocationSize);
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
                SharedMap->Section = NULL;
                Status = FsRtlNormalizeNtstatus(SharedMap->Status, STATUS_UNEXPECTED_MM_CREATE_ERR);
                goto ErrorExit;
            }

            ObDeleteCapturedInsertInfo(SharedMap->Section);

            Fcb = FileObject->FsContext;

            if (!(Fcb->Flags2 & FSRTL_FLAG2_DO_MODIFIED_WRITE) && !FileObject->FsContext2)
            {
                DPRINT1("CcInitializeCacheMap: FIXME MmDisableModifiedWriteOfSection()\n");
                ASSERT(FALSE);
                //MmDisableModifiedWriteOfSection(FileObject->SectionObjectPointer);
                OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
                SharedMap->Flags |= SHARE_FL_MODIFIED_NO_WRITE;
                KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
            }

            DPRINT1("CcInitializeCacheMap: FIXME CcCreateVacbArray()\n");
            ASSERT(FALSE);
            Status = 0;//CcCreateVacbArray(SharedMap, fileSizes.AllocationSize);
        }

        if (!NT_SUCCESS(Status))
        {
            goto ErrorExit;
        }

        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

        SharedMap->Flags &= ~SHARE_FL_SECTION_INIT;

        CreateEvent = SharedMap->CreateEvent;
        if (CreateEvent)
        {
            KeSetEvent(CreateEvent, 0, FALSE);
        }

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

                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto Exit;
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
            Status = FsRtlNormalizeNtstatus(SharedMap->Status, STATUS_UNEXPECTED_MM_CREATE_ERR);
            OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);
            goto ErrorExit;
        }
    }

    if (NewMap)
    {
        ExFreePoolWithTag(NewMap, 'cScC');
        NewMap = NULL;
    }

    PrivateMap = &SharedMap->PrivateCacheMap;
    if (SharedMap->PrivateCacheMap.NodeTypeCode)
    {
        NewMap = ExAllocatePoolWithTag(NonPagedPool, sizeof(PRIVATE_CACHE_MAP), 'cPcC');
        if (!NewMap)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
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
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    break;
                }

                continue;
            }

            PrivateMap = NewMap;
            NewMap = NULL;
        }

        RtlZeroMemory(PrivateMap, sizeof(*PrivateMap));

        PrivateMap->NodeTypeCode = CC_TYPE_PRIVATE_MAP;
        PrivateMap->FileObject = FileObject;
        FileObject->PrivateCacheMap = PrivateMap;

        PrivateMap->ReadAheadMask = (PAGE_SIZE - 1);
        KeInitializeSpinLock(&PrivateMap->ReadAheadSpinLock);

        InsertTailList(&SharedMap->PrivateList, &PrivateMap->PrivateLinks);

        IsReferenced = FALSE;
        break;
    }

Exit:

    if (IsReferenced)
    {
        if (IsLocked)
        {
            goto ErrorExitLocked;
        }

ErrorExit:

        OldIrql = KeAcquireQueuedSpinLock(LockQueueMasterLock);

ErrorExitLocked:

        if (IsSectionInit)
        {
            CreateEvent = SharedMap->CreateEvent;
            if (CreateEvent)
            {
                KeSetEvent(CreateEvent, 0, FALSE);
            }
            SharedMap->Flags &= ~SHARE_FL_SECTION_INIT;
        }

        SharedMap->OpenCount--;

        if (SharedMap->OpenCount == 0 &&
            !(SharedMap->Flags & SHARE_FL_WRITE_QUEUED) &&
            !SharedMap->DirtyPages)
        {
            DPRINT1("CcInitializeCacheMap: FIXME CcDeleteSharedCacheMap()\n");
            ASSERT(FALSE);//CcDeleteSharedCacheMap(SharedMap, OldIrql, FALSE);
        }
        else
        {
            KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
        }

        if (NewMap)
        {
            ExFreePoolWithTag(NewMap, 'cScC');
        }

        if (!NT_SUCCESS(Status))
        {
            RtlRaiseStatus(Status);
        }
    }

    if (SharedMap)
    {
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

        {
            for (UninitializeEvent = SharedMap->UninitializeEvent;
                 UninitializeEvent;
                 UninitializeEvent = NextUninitializeEvent)
            {
                UninitializeEvent = (PCACHE_UNINITIALIZE_EVENT)((ULONG_PTR)UninitializeEvent & ~(1));
                NextUninitializeEvent = UninitializeEvent->Next;

                KeSetEvent(&UninitializeEvent->Event, 0, FALSE);
            }
        }

        SharedMap->Flags &= ~SHARE_FL_WAITING_TEARDOWN;
        SharedMap->UninitializeEvent = NULL;
    }

    if (IsLocked)
    {
        KeReleaseQueuedSpinLock(LockQueueMasterLock, OldIrql);
    }

    if (NewMap)
    {
        ExFreePoolWithTag(NewMap, 'cScC');
    }

    if (!NT_SUCCESS(Status))
    {
        RtlRaiseStatus(Status);
    }
}

/* EOF */
