
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "miarm.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

#define MI_PE_HEADER_MAX_PAGES 2
#define MI_MAX_IMAGE_SECTIONS  16

#define MI_PE_HEADER_MAX_SIZE (sizeof(IMAGE_NT_HEADERS) + MI_MAX_IMAGE_SECTIONS * sizeof(IMAGE_SECTION_HEADER))

typedef struct _MI_PE_HEADER_MDL
{
    MDL Mdl;
    PFN_NUMBER PageNumber[MI_PE_HEADER_MAX_PAGES];
} MI_PE_HEADER_MDL, *PMI_PE_HEADER_MDL;

ERESOURCE MmSectionExtendResource;
ERESOURCE MmSectionExtendSetResource;
KGUARDED_MUTEX MmSectionCommitMutex;
KGUARDED_MUTEX MmSectionBasedMutex;
KEVENT MmCollidedFlushEvent;
PVOID MmHighSectionBase;
KSEMAPHORE MiDereferenceSegmentSemaphore;
LIST_ENTRY MiDereferenceSegmentList;
LIST_ENTRY MmUnusedSubsectionList;
LIST_ENTRY MmUnusedSegmentList;
MMSESSION MmSession;
MM_AVL_TABLE MmSectionBasedRoot;
ULONG MmUnusedSegmentCount = 0;
ULONG MmUnusedSubsectionCount = 0;
ULONG MmUnusedSubsectionCountPeak = 0;
SIZE_T MiUnusedSubsectionPagedPool;
//SIZE_T MiUnusedSubsectionPagedPoolPeak;
KEVENT MmUnusedSegmentCleanup;

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
    PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ,
    PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY | PAGE_READWRITE,
    PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY,
    PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE,
    PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY
};

CHAR MmImageProtectionArray[16] =
{
    MM_NOACCESS,
    MM_EXECUTE,
    MM_READONLY,
    MM_EXECUTE_READ,
    MM_WRITECOPY,
    MM_EXECUTE_WRITECOPY,
    MM_WRITECOPY,
    MM_EXECUTE_WRITECOPY,
    MM_NOACCESS,
    MM_EXECUTE,
    MM_READONLY,
    MM_EXECUTE_READ,
    MM_READWRITE,
    MM_EXECUTE_READWRITE,
    MM_READWRITE,
    MM_EXECUTE_READWRITE
};

static GENERIC_MAPPING MmpSectionMapping =
{
    STANDARD_RIGHTS_READ | SECTION_MAP_READ | SECTION_QUERY,
    STANDARD_RIGHTS_WRITE | SECTION_MAP_WRITE,
    STANDARD_RIGHTS_EXECUTE | SECTION_MAP_EXECUTE,
    SECTION_ALL_ACCESS
};

extern MI_PFN_CACHE_ATTRIBUTE MiPlatformCacheAttributes[2][MmMaximumCacheType];
extern PVOID MiSessionViewStart;   // 0xBE000000
extern SIZE_T MmSessionViewSize;
extern PVOID MiSystemViewStart;
extern SIZE_T MmSystemViewSize;
extern LARGE_INTEGER MmOneSecond;
extern LARGE_INTEGER MmHalfSecond;
extern LARGE_INTEGER MmShortTime;
extern LARGE_INTEGER Mm30Milliseconds;
extern SIZE_T MmSharedCommit;
extern MMPDE ValidKernelPde;
extern MMPTE NoAccessPte;
extern ULONG MmSecondaryColorMask;
extern SIZE_T MmAllocationFragment;
extern ULONG MmVirtualBias;
extern PMM_SESSION_SPACE MmSessionSpace;
extern MMPTE ValidKernelPdeLocal;
extern BOOLEAN MiWriteCombiningPtes;
extern SLIST_HEADER MmEventCountSListHead;
extern MM_PAGED_POOL_INFO MmPagedPoolInfo;
extern SIZE_T MmAllocatedNonPagedPool;
extern SIZE_T MmSizeOfPagedPoolInBytes;
extern PFN_NUMBER MmMaximumNonPagedPoolInPages;
extern ULONG MmConsumedPoolPercentage;

/* FUNCTIONS ******************************************************************/

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(PAGE, MiGetEventCounter)
  #pragma alloc_text(PAGE, MiFreeEventCounter)
  #pragma alloc_text(PAGE, MmGetFileNameForAddress)
  #pragma alloc_text(PAGE, MmGetFileNameForSection)
  #pragma alloc_text(PAGE, MmGetFileObjectForSection)
  #pragma alloc_text(PAGE, MmGetImageInformation)
  #pragma alloc_text(PAGE, MiInitializeSystemSpaceMap)
  #pragma alloc_text(PAGE, MiCreatePagingFileMap)
  #pragma alloc_text(PAGE, MiInsertInSystemSpace)
  #pragma alloc_text(PAGE, MiAddMappedPtes)
  #pragma alloc_text(PAGE, MiMapViewInSystemSpace)
  #pragma alloc_text(PAGE, MiGetImageProtection)
  #pragma alloc_text(PAGE, MiCreateImageFileMap)
  #pragma alloc_text(PAGE, MmExtendSection)
  #pragma alloc_text(INIT, MmInitSectionImplementation)
  #pragma alloc_text(INIT, MmCreatePhysicalMemorySection)
  #pragma alloc_text(PAGE, MmCommitSessionMappedView)
  #pragma alloc_text(PAGE, MmMapViewInSessionSpace)
  #pragma alloc_text(PAGE, MmMapViewInSystemSpace)
  #pragma alloc_text(PAGE, MmMapViewOfSection)
  #pragma alloc_text(PAGE, MiUnmapViewInSystemSpace)
  #pragma alloc_text(PAGE, MmUnmapViewInSessionSpace)
  #pragma alloc_text(PAGE, MmUnmapViewInSystemSpace)
  #pragma alloc_text(PAGE, NtAreMappedFilesTheSame)
  #pragma alloc_text(PAGE, NtCreateSection)
  #pragma alloc_text(PAGE, NtOpenSection)
  #pragma alloc_text(PAGE, NtMapViewOfSection)
  #pragma alloc_text(PAGE, NtUnmapViewOfSection)
  #pragma alloc_text(PAGE, NtExtendSection)
  #pragma alloc_text(PAGE, NtQuerySection)
#endif

CODE_SEG("PAGE")
PEVENT_COUNTER
NTAPI
MiGetEventCounter(VOID)
{
    PEVENT_COUNTER EventCounter;
    PSINGLE_LIST_ENTRY Entry;

    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    if (ExQueryDepthSList(&MmEventCountSListHead))
    {
        Entry = InterlockedPopEntrySList(&MmEventCountSListHead);
        if (Entry)
        {
            EventCounter = CONTAINING_RECORD(Entry, EVENT_COUNTER, ListEntry);

            ASSERT(EventCounter->RefCount == 0);
            EventCounter->RefCount = 1;

            KeClearEvent(&EventCounter->Event);
            EventCounter->ListEntry.Next = NULL;

            return EventCounter;
        }
    }

    EventCounter = ExAllocatePoolWithTag(NonPagedPool, sizeof(EVENT_COUNTER), 'xEmM');
    if (!EventCounter)
    {
        DPRINT1("MiGetEventCounter: Allocate failed\n");
        return NULL;
    }

    KeInitializeEvent(&EventCounter->Event, NotificationEvent, FALSE);

    EventCounter->RefCount = 1;
    EventCounter->ListEntry.Next = NULL;

    return EventCounter;
}

CODE_SEG("PAGE")
VOID
NTAPI
MiFreeEventCounter(
    _In_ PEVENT_COUNTER EventCounter)
{
    PSINGLE_LIST_ENTRY Entry;

    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
    ASSERT(EventCounter->RefCount != 0);
    ASSERT(EventCounter->ListEntry.Next == NULL);

    if (!InterlockedDecrement((PLONG)&EventCounter->RefCount))
    {
        if (MmEventCountSListHead.Depth < 4)
        {
            InterlockedPushEntrySList(&MmEventCountSListHead, &EventCounter->ListEntry);
            return;
        }

        ExFreePoolWithTag(EventCounter, 'xEmM');
    }

    do
    {
        if (MmEventCountSListHead.Depth <= 4)
            return;

        Entry = InterlockedPopEntrySList(&MmEventCountSListHead);
        EventCounter = CONTAINING_RECORD(Entry, EVENT_COUNTER, ListEntry);

        ExFreePoolWithTag(EventCounter, 'xEmM');
    }
    while (!Entry);
}

ULONG
NTAPI
MiMakeProtectionMask(IN ULONG Protect)
{
    ULONG Mask1;
    ULONG Mask2;
    ULONG ProtectMask;

    DPRINT("MiMakeProtectionMask: Protect %X\n", Protect);

    /* PAGE_EXECUTE_WRITECOMBINE is theoretically the maximum */
    if (Protect >= (PAGE_WRITECOMBINE * 2))
        return MM_INVALID_PROTECTION;

    /* Windows API protection mask can be understood as two bitfields,
       differing by whether or not execute rights are being requested
    */
    Mask1 = Protect & 0xF;
    Mask2 = (Protect >> 4) & 0xF;

    /* Check which field is there */
    if (!Mask1)
    {
        /* Mask2 must be there, use it to determine the PTE protection */
        if (!Mask2)
            return MM_INVALID_PROTECTION;

        ProtectMask = MmUserProtectionToMask2[Mask2];
    }
    else
    {
        /* Mask2 should not be there, use Mask1 to determine the PTE mask */
        if (Mask2)
            return MM_INVALID_PROTECTION;

        ProtectMask = MmUserProtectionToMask1[Mask1];
    }

    /* Make sure the final mask is a valid one */
    if (ProtectMask == MM_INVALID_PROTECTION)
        return MM_INVALID_PROTECTION;

    /* Check for PAGE_GUARD option */
    if (Protect & PAGE_GUARD)
    {
        /* It's not valid on no-access, nocache, or writecombine pages */
        if (ProtectMask == MM_NOACCESS || (Protect & (PAGE_NOCACHE | PAGE_WRITECOMBINE)))
            /* Fail such requests */
            return MM_INVALID_PROTECTION;

        /* This actually turns on guard page in this scenario! */
        ProtectMask |= MM_GUARDPAGE;
    }

    /* Check for nocache option */
    if (Protect & PAGE_NOCACHE)
    {
        /* The earlier check should've eliminated this possibility */
        ASSERT((Protect & PAGE_GUARD) == 0);

        /* Check for no-access page or write combine page */
        if (ProtectMask == MM_NOACCESS || (Protect & PAGE_WRITECOMBINE))
            /* Such a request is invalid */
            return MM_INVALID_PROTECTION;

        /* Add the PTE flag */
        ProtectMask |= MM_NOCACHE;
    }

    /* Check for write combine option */
    if (Protect & PAGE_WRITECOMBINE)
    {
        /* The two earlier scenarios should've caught this */
        ASSERT((Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0);

        /* Don't allow on no-access pages */
        if (ProtectMask == MM_NOACCESS)
            return MM_INVALID_PROTECTION;

        /* This actually turns on write-combine in this scenario! */
        ProtectMask |= MM_NOACCESS;
    }

    /* Return the final MM PTE protection mask */
    return ProtectMask;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmGetFileNameForAddress(
    _In_ PVOID Address,
    _Out_ UNICODE_STRING* OutFileName)
{
    POBJECT_NAME_INFORMATION ObjectNameInfo;
    PCONTROL_AREA ControlArea;
    PFILE_OBJECT FileObject;
    PVOID AddressSpace;
    PMMVAD Vad;
    ULONG Length;
    ULONG ReturnLength;
    NTSTATUS Status;

    PAGED_CODE ();
    DPRINT("MmGetFileNameForAddress: Address %p\n", Address);

    /* Lock address space */
    AddressSpace = MmGetCurrentAddressSpace();
    MmLockAddressSpace(AddressSpace);

    /* Get the VAD */
    Vad = MiLocateAddress(Address);
    if (!Vad)
    {
        DPRINT1("MmGetFileNameForAddress: STATUS_INVALID_ADDRESS (%p)\n", Address);
        MmUnlockAddressSpace(AddressSpace);
        return STATUS_INVALID_ADDRESS;
    }

    if (Vad->u.VadFlags.PrivateMemory)
    {
        DPRINT1("MmGetFileNameForAddress: STATUS_SECTION_NOT_IMAGE (%p)\n", Address);
        MmUnlockAddressSpace(AddressSpace);
        return STATUS_SECTION_NOT_IMAGE;
    }

    ControlArea = Vad->ControlArea;
    if (!ControlArea)
    {
        DPRINT1("MmGetFileNameForAddress: STATUS_SECTION_NOT_IMAGE (%p)\n", Address);
        MmUnlockAddressSpace(AddressSpace);
        return STATUS_SECTION_NOT_IMAGE;
    }

    if (!ControlArea->u.Flags.Image)
    {
        DPRINT1("MmGetFileNameForAddress: STATUS_SECTION_NOT_IMAGE (%p)\n", Address);
        MmUnlockAddressSpace(AddressSpace);
        return STATUS_SECTION_NOT_IMAGE;
    }

    /* Get the file object pointer for the VAD */
    FileObject = ControlArea->FilePointer;
    ASSERT(FileObject != NULL);

    /* Reference the file object */
    ObReferenceObject(FileObject);

    /* Unlock address space */
    MmUnlockAddressSpace(AddressSpace);

    /* Get the filename of the file object */
    for (Length = 0x408; ; Length = ReturnLength)
    {
        ObjectNameInfo = ExAllocatePoolWithTag(PagedPool, Length, TAG_MM);
        if (!ObjectNameInfo)
        {
            DPRINT1("MmGetFileNameForAddress: STATUS_NO_MEMORY (%p)\n", Address);
            ObDereferenceObject(FileObject);
            return STATUS_NO_MEMORY;
        }

        ReturnLength = 0;

        /* Query the name */
        Status = ObQueryNameString(FileObject, ObjectNameInfo, Length, &ReturnLength);
        if (NT_SUCCESS(Status))
            /* If success then exit from the loop */
            break;

        ExFreePoolWithTag(ObjectNameInfo, TAG_MM);

        if (ReturnLength <= Length)
        {
            DPRINT1("MmGetFileNameForAddress: ReturnLength %X, Length %X\n", ReturnLength, Length);
            ObDereferenceObject(FileObject);
            return Status;
        }
    }

    /* Init modulename */
    OutFileName->Length = ObjectNameInfo->Name.Length;
    OutFileName->MaximumLength = ObjectNameInfo->Name.Length;
    OutFileName->Buffer = (PWSTR)ObjectNameInfo;

    RtlMoveMemory(OutFileName->Buffer, ObjectNameInfo->Name.Buffer, OutFileName->Length);

    /* Dereference the file object */
    ObDereferenceObject(FileObject);
    return Status;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmGetFileNameForSection(
    _In_ PVOID SectionObject,
    _Out_ POBJECT_NAME_INFORMATION* OutFileNameInfo)
{
    PSECTION Section = SectionObject;
    POBJECT_NAME_INFORMATION FileNameInfo;
    PFILE_OBJECT File;
    ULONG Length;
    ULONG ReturnLength;
    NTSTATUS Status;

    DPRINT("MmGetFileNameForSection: Section %p\n", Section);

    *OutFileNameInfo = 0;

    if (!Section->u.Flags.Image)
    {
        DPRINT1("MmGetFileNameForSection: STATUS_SECTION_NOT_IMAGE (%p)\n", Section);
        return STATUS_SECTION_NOT_IMAGE;
    }

    /* Allocate memory for our structure */
    *OutFileNameInfo = FileNameInfo = ExAllocatePoolWithTag(PagedPool, 0x400, TAG_MM);
    if (!FileNameInfo)
    {
        DPRINT1("MmGetFileNameForSection: STATUS_NO_MEMORY (%p)\n", Section);
        return STATUS_NO_MEMORY;
    }

    File = Section->Segment->ControlArea->FilePointer;

    /* Query the name */
    Status = ObQueryNameString(File, FileNameInfo, 0x400, &ReturnLength);
    if (NT_SUCCESS(Status))
        /* If success then return */
        return STATUS_SUCCESS;

    /* Free previos structure */
    ExFreePoolWithTag(*OutFileNameInfo, TAG_MM);

    if (Status != STATUS_INFO_LENGTH_MISMATCH)
    {
        DPRINT1("MmGetFileNameForSection: Status %X\n", Status);
        *OutFileNameInfo = NULL;
        return Status;
    }

    /* Increase size */
    Length = (ULONG)(ReturnLength + 0x100);

    /* Allocate memory with new Length for our structure */
    *OutFileNameInfo = FileNameInfo = ExAllocatePoolWithTag(PagedPool, Length, TAG_MM);
    if (!FileNameInfo)
    {
        DPRINT1("MmGetFileNameForSection: STATUS_NO_MEMORY (%p)\n", Section);
        return STATUS_NO_MEMORY;
    }

    /* Query the name with new Length */
    Status = ObQueryNameString(File, FileNameInfo, Length, &ReturnLength);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MmGetFileNameForSection: Status %X\n", Status);
        ExFreePoolWithTag(*OutFileNameInfo, TAG_MM);
        *OutFileNameInfo = NULL;
        return Status;
    }

    return STATUS_SUCCESS;
}

CODE_SEG("PAGE")
PFILE_OBJECT
NTAPI
MmGetFileObjectForSection(
    _In_ PVOID SectionObject)
{
    PSECTION Section = SectionObject;

    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    ASSERT(Section != NULL);

    return Section->Segment->ControlArea->FilePointer;
}

CODE_SEG("PAGE")
VOID
NTAPI
MmGetImageInformation(
    _Out_ PSECTION_IMAGE_INFORMATION ImageInformation)
{
    UNIMPLEMENTED_DBGBREAK();
}

CODE_SEG("PAGE")
BOOLEAN
NTAPI
MiInitializeSystemSpaceMap(
    _In_ PMMSESSION InputSession OPTIONAL)
{
    PMMSESSION Session;
    PVOID ViewStart;
    SIZE_T AllocSize;
    SIZE_T BitmapSize;
    SIZE_T Size;
    POOL_TYPE PoolType;

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
    BitmapSize = sizeof(RTL_BITMAP);
    BitmapSize += ((((Size / MI_SYSTEM_VIEW_BUCKET_SIZE) + 0x1F) / 0x20) * sizeof(ULONG));

    Session->SystemSpaceBitMap = ExAllocatePoolWithTag(NonPagedPool, BitmapSize, TAG_MM);
    ASSERT(Session->SystemSpaceBitMap);

    RtlInitializeBitMap(Session->SystemSpaceBitMap,
                        (PULONG)(Session->SystemSpaceBitMap + 1),
                        (ULONG)(Size / MI_SYSTEM_VIEW_BUCKET_SIZE));

    /* Set system space fully empty to begin with */
    RtlClearAllBits(Session->SystemSpaceBitMap);

    /* Set default hash flags */
    Session->SystemSpaceHashSize = 0x1F;
    Session->SystemSpaceHashKey = (Session->SystemSpaceHashSize - 1);
    Session->SystemSpaceHashEntries = 0;

    /* Calculate how much space for the hash views we'll need */
    AllocSize = (sizeof(MMVIEW) * Session->SystemSpaceHashSize);
    ASSERT(AllocSize < PAGE_SIZE);

    /* Allocate and zero the view table */
    PoolType = (Session == &MmSession ? NonPagedPool : PagedPool);

    Session->SystemSpaceViewTable = ExAllocatePoolWithTag(PoolType, AllocSize, TAG_MM);
    ASSERT(Session->SystemSpaceViewTable != NULL);

    RtlZeroMemory(Session->SystemSpaceViewTable, AllocSize);

    return TRUE;
}

VOID
NTAPI
MiConvertStaticSubsections(
    _In_ PCONTROL_AREA ControlArea)
{
    PMSUBSECTION MappedSubsection;

    DPRINT("MiConvertStaticSubsections: ControlArea %p\n", ControlArea);

    ASSERT(ControlArea->u.Flags.Image == 0);
    ASSERT(ControlArea->FilePointer != NULL);
    ASSERT(ControlArea->u.Flags.PhysicalMemory == 0);

    if (ControlArea->u.Flags.Rom)
        MappedSubsection = (PMSUBSECTION)((PLARGE_CONTROL_AREA)ControlArea + 1);
    else
        MappedSubsection = (PMSUBSECTION)(ControlArea + 1);

    while (MappedSubsection)
    {
        if (MappedSubsection->DereferenceList.Flink)
            goto Next;

        if (MappedSubsection->u.SubsectionFlags.SubsectionStatic)
        {
            MappedSubsection->u.SubsectionFlags.SubsectionStatic = 0;
            MappedSubsection->u2.SubsectionFlags2.SubsectionConverted = 1;

            MappedSubsection->NumberOfMappedViews = 1;

            MiRemoveViewsFromSection(MappedSubsection, MappedSubsection->PtesInSubsection);

            DPRINT1("MiConvertStaticSubsections: FIXME MiSubsectionsConvertedToDynamic\n");
        }
        else if (MappedSubsection->SubsectionBase)
        {
            DPRINT("MiConvertStaticSubsections: FIXME\n");
            ASSERT(FALSE);
            goto Next;
        }

Next:
        MappedSubsection = (PMSUBSECTION)MappedSubsection->NextSubsection;
    }
}

VOID
NTAPI
MiSegmentDelete(
    _In_ PSEGMENT Segment)
{
    SEGMENT_FLAGS SegmentFlags = Segment->SegmentFlags;
    PCONTROL_AREA ControlArea = Segment->ControlArea;
    PSUBSECTION Subsection;
    PMSUBSECTION MappedSubsection;
    PEVENT_COUNTER Event;
    PMMPTE Proto;
    PMMPTE LastProto;
    PMMPTE ProtoPte;
    MMPTE TempProto;
    PMMPFN Pfn;
    PMMPFN Pfn2;
    PFN_NUMBER PageNumber;
    SIZE_T NumberOfCommittedPages;
    KIRQL OldIrql;

    DPRINT("MiSegmentDelete: Segment %p, SegmentFlags %X\n", Segment, SegmentFlags);

    ASSERT(ControlArea->u.Flags.BeingDeleted == 1);
    ASSERT(ControlArea->WritableUserReferences == 0);

    OldIrql = MiLockPfnDb(APC_LEVEL);

    if (ControlArea->DereferenceList.Flink)
    {
        RemoveEntryList(&ControlArea->DereferenceList);
        MmUnusedSegmentCount--;
    }

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    if (ControlArea->u.Flags.Image || ControlArea->u.Flags.File)
    {
        if (ControlArea->u.Flags.DebugSymbolsLoaded)
        {
            DPRINT1("MiSegmentDelete: FIXME\n");
            ASSERT(FALSE);
        }
        else
        {
            OldIrql = MiLockPfnDb(APC_LEVEL);
        }

        Event = ControlArea->WaitingForDeletion;
        ControlArea->WaitingForDeletion = NULL;

        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        if (Event)
            KeSetEvent(&Event->Event, 0, FALSE);

        if (!ControlArea->u.Flags.BeingCreated)
            ObDereferenceObject(ControlArea->FilePointer);

        if (!ControlArea->u.Flags.Image)
        {
            if (!ControlArea->u.Flags.Rom)
                Subsection = (PSUBSECTION)(ControlArea + 1);
            else
                Subsection = (PSUBSECTION)((PLARGE_CONTROL_AREA)ControlArea + 1);

            ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);

            if (ControlArea->FilePointer)
            {
                MappedSubsection = (PMSUBSECTION)Subsection;

                OldIrql = MiLockPfnDb(APC_LEVEL);

                while (MappedSubsection)
                {
                    if (MappedSubsection->DereferenceList.Flink)
                    {
                        RemoveEntryList(&MappedSubsection->DereferenceList);
                        FreePoolForSubsectionPtes(MappedSubsection->PtesInSubsection + MappedSubsection->UnusedPtes);
                    }

                    MappedSubsection = (PMSUBSECTION)MappedSubsection->NextSubsection;
                }

                MiUnlockPfnDb(OldIrql, APC_LEVEL);

                if (Subsection->SubsectionBase)
                    ExFreePool(Subsection->SubsectionBase);
            }

            Subsection = Subsection->NextSubsection;

            while (Subsection)
            {
                PSUBSECTION NextSubsection;

                if (Subsection->SubsectionBase)
                    ExFreePool(Subsection->SubsectionBase);

                NextSubsection = Subsection->NextSubsection;
                ExFreePool(Subsection);
                Subsection = NextSubsection;
            }

            NumberOfCommittedPages = Segment->NumberOfCommittedPages;
            if (NumberOfCommittedPages)
            {
                DPRINT1("MiSegmentDelete: FIXME\n");
                ASSERT(FALSE);
            }

            ExFreePool(ControlArea);
            ExFreePool(Segment);

            return;
        }
    }

    if (!ControlArea->u.Flags.GlobalOnlyPerSession && !ControlArea->u.Flags.Rom)
        Subsection = (PSUBSECTION)(ControlArea + 1);
    else
        Subsection = (PSUBSECTION)((PLARGE_CONTROL_AREA)ControlArea + 1);

    Proto = Subsection->SubsectionBase;
    LastProto = (Proto + Segment->NonExtendedPtes);

    ProtoPte = MiAddressToPte(Proto);

    *(volatile PMMPTE)Proto;

    OldIrql = MiLockPfnDb(APC_LEVEL);

    if (!ProtoPte->u.Hard.Valid)
        MiMakeSystemAddressValidPfn(Proto, OldIrql);

    for (; Proto < LastProto; Proto++)
    {
        if (MiIsPteOnPdeBoundary(Proto) && Proto != Subsection->SubsectionBase)
        {
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            ProtoPte = MiAddressToPte(Proto);
            OldIrql = MiLockPfnDb(APC_LEVEL);

            if (!ProtoPte->u.Hard.Valid)
                MiMakeSystemAddressValidPfn(Proto, OldIrql);
        }

        TempProto.u.Long = Proto->u.Long;

        if (TempProto.u.Hard.Valid)
        {
            DPRINT1("MiSegmentDelete: FIXME\n");
            ASSERT(FALSE);
        }
        else if (!TempProto.u.Soft.Prototype)
        {
            ASSERT(SegmentFlags.LargePages == 0);

            if (TempProto.u.Soft.Transition)
            {
                Pfn = MI_PFN_ELEMENT(TempProto.u.Trans.PageFrameNumber);
                Pfn->PteAddress = (PMMPTE)(((ULONG_PTR)(Pfn->PteAddress)) | 0x1);

                PageNumber = Pfn->u4.PteFrame;
                Pfn2 = MI_PFN_ELEMENT(PageNumber);
                MiDecrementPfnShare(Pfn2, PageNumber);

                if (!Pfn->u3.e2.ReferenceCount)
                {
                    MiUnlinkPageFromList(Pfn);
                    MiReleasePageFileSpace(Pfn->OriginalPte);
                    MiInsertPageInFreeList(TempProto.u.Trans.PageFrameNumber);
                }
            }
            else if (MI_IS_MAPPED_PTE(&TempProto))
            {
                MiReleasePageFileSpace(TempProto);
            }
        }
        else
        {
            ASSERT(SegmentFlags.LargePages == 0);
        }
    }

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    NumberOfCommittedPages = Segment->NumberOfCommittedPages;
    if (NumberOfCommittedPages)
    {
        ASSERT((SSIZE_T)(NumberOfCommittedPages) >= 0);
        ASSERT(MmTotalCommittedPages >= (NumberOfCommittedPages));
        InterlockedExchangeAddSizeT(&MmTotalCommittedPages, -NumberOfCommittedPages);

        InterlockedExchangeAddSizeT(&MmSharedCommit, -NumberOfCommittedPages);
    }

    ExFreePool(ControlArea);
    ExFreePool(Segment);
}

VOID
NTAPI
MiRemoveImageSectionObject(
    _In_ PFILE_OBJECT FileObject,
    _In_ PLARGE_CONTROL_AREA ControlArea)
{
    PLARGE_CONTROL_AREA Current;
    PLARGE_CONTROL_AREA Next;

    DPRINT("MiRemoveImageSectionObject: FileObject %p, ControlArea %p\n", FileObject, ControlArea);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(MmPfnOwner == KeGetCurrentThread());

    Current = FileObject->SectionObjectPointer->ImageSectionObject;

    if (!Current->u.Flags.GlobalOnlyPerSession)
    {
        ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);
        FileObject->SectionObjectPointer->ImageSectionObject = NULL;
        return;
    }

    if (Current != ControlArea)
    {
        RemoveEntryList(&ControlArea->UserGlobalList);
        return;
    }

    if (IsListEmpty(&Current->UserGlobalList))
    {
        Next = NULL;
    }
    else
    {
        Next = CONTAINING_RECORD(Current->UserGlobalList.Flink, LARGE_CONTROL_AREA, UserGlobalList);
        ASSERT(Next->u.Flags.GlobalOnlyPerSession == 1);

        RemoveEntryList(&Current->UserGlobalList);
    }

    FileObject->SectionObjectPointer->ImageSectionObject = Next;

    return;
}

VOID
NTAPI
MiPurgeImageSection(
    _In_ PCONTROL_AREA ControlArea,
    _In_ KIRQL OldIrql)
{
    PSUBSECTION Subsection;
    PMMPTE LastPte;
    PMMPTE Pte;
    MMPTE TempPte;
    MMPTE TempProto;
    MMPTE PteContents;
    PMMPFN Pfn;
    ULONG SubsectionSize;
    ULONG CurrentSize;
    ULONG Protection;

    DPRINT1("MiPurgeImageSection: ControlArea %p, OldIrql %X\n", ControlArea, OldIrql);

    ASSERT(ControlArea->u.Flags.Image != 0);

    if (ControlArea->u.Flags.GlobalOnlyPerSession || ControlArea->u.Flags.Rom)
        Subsection = (PSUBSECTION)((PLARGE_CONTROL_AREA)ControlArea + 1);
    else
        Subsection = (PSUBSECTION)(ControlArea + 1);

    do
    {
        if (!Subsection->u.SubsectionFlags.GlobalMemory)
        {
            Subsection = Subsection->NextSubsection;
            continue;
        }

        TempProto.u.Long = 0;
        PteContents.u.Long = 0;
        SubsectionSize = 0;
        CurrentSize = 0;

        if (Subsection->StartingSector)
        {
            MI_MAKE_SUBSECTION_PTE(&TempProto, Subsection);

            SubsectionSize = (Subsection->NumberOfFullSectors * MM_SECTOR_SIZE);
            SubsectionSize |= Subsection->u.SubsectionFlags.SectorEndOffset;
        }

        Protection = Subsection->u.SubsectionFlags.Protection;
        TempProto.u.Soft.Protection = Protection;
        PteContents.u.Soft.Protection = Protection;

        Pte = Subsection->SubsectionBase;
        LastPte = &Subsection->SubsectionBase[Subsection->PtesInSubsection];

        ControlArea = Subsection->ControlArea;

        if (!MiAddressToPte(Pte)->u.Hard.Valid)
            MiMakeSystemAddressValidPfn(Pte, OldIrql);

        while (Pte < LastPte)
        {
            if (MiIsPteOnPdeBoundary(Pte) && !MiAddressToPte(Pte)->u.Hard.Valid)
                MiMakeSystemAddressValidPfn(Pte, OldIrql);

            TempPte.u.Long = Pte->u.Long;
            if (!TempPte.u.Long)
                break;

            ASSERT(TempPte.u.Hard.Valid == 0);

            if (TempPte.u.Soft.Prototype || !TempPte.u.Soft.Transition)
            {
                if (!TempPte.u.Soft.Prototype && TempPte.u.Long != NoAccessPte.u.Long)
                {
                    MiReleasePageFileSpace(TempPte);
                    Pte->u.Long = PteContents.u.Long;
                }

                goto NextPte;
            }

            Pfn = MiGetPfnEntry(TempPte.u.Trans.PageFrameNumber);

            if (!Pfn->u3.e1.Modified && Pfn->OriginalPte.u.Soft.Prototype)
                goto NextPte;

            ASSERT(Pfn->OriginalPte.u.Hard.Valid == 0);

            if (Pfn->u3.e2.ReferenceCount)
            {
                DPRINT1("MiPurgeImageSection: FIXME\n");
                ASSERT(FALSE);
            }

            ASSERT(!((Pfn->OriginalPte.u.Soft.Prototype == 0) && (Pfn->OriginalPte.u.Soft.Transition == 1)));

            MI_WRITE_INVALID_PTE(Pte, Pfn->OriginalPte);
            ASSERT(Pfn->OriginalPte.u.Hard.Valid == 0);

            if (Pfn->OriginalPte.u.Soft.Prototype)
            {
                ControlArea->NumberOfPfnReferences--;
                ASSERT((LONG)ControlArea->NumberOfPfnReferences >= 0);
            }

            MiUnlinkPageFromList(Pfn);
            MI_SET_PFN_DELETED(Pfn);

            MiDecrementPfnShare(MiGetPfnEntry(Pfn->u4.PteFrame), Pfn->u4.PteFrame);

            if (!Pfn->u3.e2.ReferenceCount)
            {
                MiReleasePageFileSpace(Pfn->OriginalPte);
                MiInsertPageInFreeList(TempPte.u.Trans.PageFrameNumber);
            }

            MI_WRITE_INVALID_PTE(Pte, TempProto);

NextPte:
            Pte++;
            CurrentSize += PAGE_SIZE;

            if (CurrentSize >= SubsectionSize)
                TempProto.u.Long = PteContents.u.Long;
        }

        Subsection = Subsection->NextSubsection;
    }
    while (Subsection);
}

VOID
NTAPI
MiCheckControlArea(
    _In_ PCONTROL_AREA ControlArea,
    _In_ KIRQL OldIrql)
{
    PEVENT_COUNTER EventCounter = NULL;
    ULONG NonPagedPoolPercentage;
    ULONG PagedPoolPercentage;
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
                        MiConvertStaticSubsections(ControlArea);
                    }

                    InsertTailList(&MmUnusedSegmentList, &ControlArea->DereferenceList);
                    MmUnusedSegmentCount++;
                }

                if (ControlArea->u.Flags.DeleteOnClose)
                    CheckFlag = 1;

                if (ControlArea->u.Flags.GlobalMemory)
                {
                    ASSERT(ControlArea->u.Flags.Image == 1);

                    ControlArea->u.Flags.BeingPurged = 1;
                    ControlArea->NumberOfMappedViews = 1;

                    MiPurgeImageSection(ControlArea, OldIrql);

                    ControlArea->u.Flags.BeingPurged = 0;
                    ControlArea->NumberOfMappedViews--;

                    if (!ControlArea->NumberOfMappedViews &&
                        !ControlArea->NumberOfSectionReferences &&
                        !ControlArea->NumberOfPfnReferences)
                    {
                        CheckFlag |= 2;

                        ControlArea->u.Flags.BeingDeleted = 1;
                        ControlArea->u.Flags.FilePointerNull = 1;

                        MiRemoveImageSectionObject(ControlArea->FilePointer, (PLARGE_CONTROL_AREA)ControlArea);
                    }
                    else
                    {
                        EventCounter = ControlArea->WaitingForDeletion;
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
                    MiRemoveImageSectionObject(ControlArea->FilePointer, (PLARGE_CONTROL_AREA)ControlArea);
                }
                else
                {
                    ASSERT(((PCONTROL_AREA)(ControlArea->FilePointer->SectionObjectPointer->DataSectionObject)) != NULL);
                    ControlArea->FilePointer->SectionObjectPointer->DataSectionObject = 0;
                }
            }
        }
        else
        {
            ControlArea->u.Flags.BeingDeleted = 1;
            CheckFlag = 2;
        }
    }
    else if (ControlArea->WaitingForDeletion)
    {
        /* Get event */
        EventCounter = ControlArea->WaitingForDeletion;
        ControlArea->WaitingForDeletion = NULL;
    }

    /* Release the PFN lock */
    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    if (CheckFlag)
    {
        /* No more user write references at all */
        ASSERT(ControlArea->WritableUserReferences == 0);
        ASSERT(EventCounter == NULL);

        if (CheckFlag & 2)
        {
            /* Delete the segment if needed */
            MiSegmentDelete(ControlArea->Segment);
            return;
        }

        /* Clean the section */
        MiCleanSection(ControlArea, 1);
        return;
    }

    if (EventCounter)
        KeSetEvent(&EventCounter->Event, 0, FALSE);

    NonPagedPoolPercentage = (100 * MmAllocatedNonPagedPool / MmMaximumNonPagedPoolInPages);
    PagedPoolPercentage = (100 * MmPagedPoolInfo.AllocatedPagedPool / (MmSizeOfPagedPoolInBytes / PAGE_SIZE));

    if (PagedPoolPercentage > MmConsumedPoolPercentage ||
        NonPagedPoolPercentage > MmConsumedPoolPercentage)
    {
        KeSetEvent(&MmUnusedSegmentCleanup, 0, FALSE);
    }
}

VOID
NTAPI
MiDereferenceControlAreaBySection(
    _In_ PCONTROL_AREA ControlArea,
    _In_ ULONG UserReference)
{
    KIRQL OldIrql;

    DPRINT("MiDereferenceControlAreaBySection: %p, %X\n", ControlArea, UserReference);

    /* Lock the PFN database */
    OldIrql = MiLockPfnDb(APC_LEVEL);

    ControlArea->NumberOfSectionReferences--;
    ControlArea->NumberOfUserReferences -= UserReference;

    MiCheckControlArea(ControlArea, OldIrql);
}

PMMPTE
NTAPI
MiGetProtoPteAddressExtended(
    _In_ PMMVAD Vad,
    _In_ ULONG_PTR Vpn)
{
    PCONTROL_AREA ControlArea;
    PSUBSECTION Subsection;
    ULONG_PTR PteOffset;

    ControlArea = Vad->ControlArea;

    if (ControlArea->u.Flags.GlobalOnlyPerSession)
        Subsection = (PSUBSECTION)((PLARGE_CONTROL_AREA)ControlArea + 1);
    else
        Subsection = (PSUBSECTION)&ControlArea[1];

    while (TRUE)
    {
        if (Subsection->SubsectionBase)
        {
            if (Vad->FirstPrototypePte >= Subsection->SubsectionBase &&
                Vad->FirstPrototypePte < &Subsection->SubsectionBase[Subsection->PtesInSubsection])
            {
                break;
            }
        }

        Subsection = Subsection->NextSubsection;
        if (!Subsection)
        {
            DPRINT1("MiGetProtoPteAddressExtended: return NULL\n");
            return NULL;
        }
    }

    ASSERT(Subsection->SubsectionBase != NULL);

    PteOffset = (Vpn + Vad->FirstPrototypePte - Subsection->SubsectionBase - Vad->StartingVpn - Subsection->PtesInSubsection);

    ASSERT(PteOffset < 0xF0000000);

    PteOffset += Subsection->PtesInSubsection;

    while (PteOffset >= Subsection->PtesInSubsection)
    {
        PteOffset -= Subsection->PtesInSubsection;

        Subsection = Subsection->NextSubsection;
        if (!Subsection)
        {
            DPRINT1("MiGetProtoPteAddressExtended: return NULL\n");
            return NULL;
        }
    }

    ASSERT(Subsection->SubsectionBase != NULL);
    ASSERT(PteOffset < Subsection->PtesInSubsection);

    return &Subsection->SubsectionBase[PteOffset];
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MiCreatePagingFileMap(
    _Out_ PSEGMENT* Segment,
    _In_ PLARGE_INTEGER InputMaximumSize,
    _In_ ULONG ProtectionMask,
    _In_ ULONG AllocationAttributes)
{
    PCONTROL_AREA ControlArea;
    PSEGMENT NewSegment;
    PSUBSECTION Subsection;
    PMMPTE SectionProto;
    MMPTE TempPte;
    ULONGLONG MaximumSize = InputMaximumSize->QuadPart;
    ULONGLONG SizeLimit;
    PFN_COUNT ProtoCount;

    PAGED_CODE();
    DPRINT("MiCreatePagingFileMap: MaximumSize %I64X, Protection %X, AllocAttributes %X\n",
           MaximumSize, ProtectionMask, AllocationAttributes);

    /* Pagefile-backed sections need a known size */
    if (!MaximumSize)
    {
        DPRINT1("MiCreatePagingFileMap: STATUS_INVALID_PARAMETER_4 \n");
        return STATUS_INVALID_PARAMETER_4;
    }

    /* Calculate the maximum size possible, given the section protos we'll need */
    SizeLimit = (((MAXULONG_PTR - sizeof(SEGMENT)) / sizeof(MMPTE)) * PAGE_SIZE);

    /* Fail if this size is too big */
    if (MaximumSize > SizeLimit)
    {
        DPRINT1("MiCreatePagingFileMap: SizeLimit %I64X, STATUS_SECTION_TOO_BIG\n", SizeLimit);
        return STATUS_SECTION_TOO_BIG;
    }

    /* Calculate how many section protos will be needed */
    ProtoCount = (PFN_COUNT)((MaximumSize + (PAGE_SIZE - 1)) / PAGE_SIZE);

    if (AllocationAttributes & SEC_COMMIT)
    {
        /* For commited memory, we must have a valid protection mask */
        ASSERT(ProtectionMask != 0);

        if (!MiChargeCommitment(ProtoCount, NULL))
        {
            DPRINT1("MiCreatePagingFileMap: STATUS_COMMITMENT_LIMIT\n");
            return STATUS_COMMITMENT_LIMIT;
        }

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
    NewSegment = ExAllocatePoolWithTag(PagedPool, (sizeof(SEGMENT) + (ProtoCount - 1) * sizeof(MMPTE)), 'tSmM');
    if (!NewSegment)
    {
        DPRINT1("MiCreatePagingFileMap: STATUS_INSUFFICIENT_RESOURCES \n");
        ASSERT(FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    *Segment = NewSegment;

    /* Now allocate the control area, which has the subsection structure */
    ControlArea = ExAllocatePoolWithTag(NonPagedPool, (sizeof(CONTROL_AREA) + sizeof(SUBSECTION)), 'aCmM');
    if (!ControlArea)
    {
        DPRINT1("MiCreatePagingFileMap: STATUS_INSUFFICIENT_RESOURCES \n");
        ExFreePoolWithTag(NewSegment, 'tSmM');
        ASSERT(FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* And zero it out, filling the basic segmnet pointer and reference fields */
    RtlZeroMemory(ControlArea, (sizeof(CONTROL_AREA) + sizeof(SUBSECTION)));

    ControlArea->Segment = NewSegment;
    ControlArea->NumberOfSectionReferences = 1;
    ControlArea->NumberOfUserReferences = 1;

    /* Convert allocation attributes to control area flags */
    if (AllocationAttributes & SEC_BASED)
        ControlArea->u.Flags.Based = 1;

    if (AllocationAttributes & SEC_RESERVE)
        ControlArea->u.Flags.Reserve = 1;

    if (AllocationAttributes & SEC_COMMIT)
        ControlArea->u.Flags.Commit = 1;

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
    NewSegment->SizeOfSegment = (ProtoCount * PAGE_SIZE);
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

        InterlockedExchangeAddSizeT(&MmSharedCommit, ProtoCount);

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
    if (AllocationAttributes & SEC_LARGE_PAGES)
        return STATUS_SUCCESS;

    /* Write out the section protos, for now they're simply demand zero */
  #if defined (_WIN64) || defined (_X86PAE_)
    RtlFillMemoryUlonglong(SectionProto, (ProtoCount * sizeof(MMPTE)), TempPte.u.Long);
  #else
    RtlFillMemoryUlong(SectionProto, (ProtoCount * sizeof(MMPTE)), TempPte.u.Long);
  #endif

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
MiCheckPurgeAndUpMapCount(
    _In_ PCONTROL_AREA ControlArea,
    _In_ BOOLEAN FailIfSystemViews)
{
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

    if (FailIfSystemViews &&
        ControlArea->u.Flags.ImageMappedInSystemSpace &&
        KeGetPreviousMode() != KernelMode)
    {
        /* Release the PFN lock */
        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        DPRINT1("MiCheckPurgeAndUpMapCount: STATUS_CONFLICTING_ADDRESSES\n");
        return STATUS_CONFLICTING_ADDRESSES;
    }

    /* Increase the reference counts */
    ControlArea->NumberOfMappedViews++;
    ControlArea->NumberOfUserReferences++;

    ASSERT(ControlArea->NumberOfSectionReferences != 0);

    /* Release the PFN lock */
    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    return STATUS_SUCCESS;
}

VOID
NTAPI
MiDereferenceControlArea(
     _In_ PCONTROL_AREA ControlArea)
{
    KIRQL OldIrql;

    DPRINT("MiDereferenceControlArea: ControlArea %p\n", ControlArea);

    /* Lock the PFN database */
    OldIrql = MiLockPfnDb(APC_LEVEL);

    /* Drop reference counts */
    ControlArea->NumberOfMappedViews--;
    ControlArea->NumberOfUserReferences--;

    /* Check if it's time to delete the CA. This releases the lock */
    MiCheckControlArea(ControlArea, OldIrql);
}

CODE_SEG("PAGE")
PVOID
NTAPI
MiInsertInSystemSpace(
    _In_ PMMSESSION Session,
    _In_ ULONG Buckets,
    _In_ PCONTROL_AREA ControlArea)
{
    PMMVIEW OldTable;
    PVOID Base;
    POOL_TYPE PoolType;
    ULONG Entry;
    ULONG Hash;
    ULONG HashSize;
    ULONG ix;

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
        HashSize = (Session->SystemSpaceHashSize * 2);

        /* Save the old table and allocate a new one */
        OldTable = Session->SystemSpaceViewTable;
        PoolType = (Session == &MmSession ? NonPagedPool : PagedPool);

        Session->SystemSpaceViewTable = ExAllocatePoolWithTag(PoolType, (HashSize * sizeof(MMVIEW)), TAG_MM);

        if (!Session->SystemSpaceViewTable)
        {
            /* Failed to allocate a new table, keep the old one for now */
            Session->SystemSpaceViewTable = OldTable;
        }
        else
        {
            /* Clear the new table and set the new ahsh and key */
            RtlZeroMemory(Session->SystemSpaceViewTable, (HashSize * sizeof(MMVIEW)));

            Session->SystemSpaceHashSize = HashSize;
            Session->SystemSpaceHashKey = (Session->SystemSpaceHashSize - 1);

            /* Loop the old table */
            for (ix = 0; ix < (Session->SystemSpaceHashSize / 2); ix++)
            {
                /* Check if the entry was valid */
                if (OldTable[ix].Entry)
                {
                    /* Re-hash the old entry and search for space in the new table */
                    Hash = ((OldTable[ix].Entry >> 16) % Session->SystemSpaceHashKey);

                    while (Session->SystemSpaceViewTable[Hash].Entry)
                    {
                        /* Loop back at the beginning if we had an overflow */
                        if (++Hash >= Session->SystemSpaceHashSize)
                            Hash = 0;
                    }

                    /* Write the old entry in the new table */
                    Session->SystemSpaceViewTable[Hash] = OldTable[ix];
                }
            }

            /* Free the old table */
            ExFreePool(OldTable);
        }
    }

    /* Check if we ran out */
    if (Session->SystemSpaceHashEntries == Session->SystemSpaceHashSize)
    {
        DPRINT1("MiInsertInSystemSpace: Ran out of system view hash entries\n");
        KeReleaseGuardedMutex(Session->SystemSpaceViewLockPointer);
        return NULL;
    }

    /* Find space where to map this view */
    ix = RtlFindClearBitsAndSet(Session->SystemSpaceBitMap, Buckets, 0);
    if (ix == 0xFFFFFFFF)
    {
        /* Out of space, fail */
        DPRINT1("MiInsertInSystemSpace: Out of system view space\n");
        Session->BitmapFailures++;
        KeReleaseGuardedMutex(Session->SystemSpaceViewLockPointer);
        return NULL;
    }

    /* Compute the base address */
    Base = (PVOID)((ULONG_PTR)Session->SystemSpaceViewStart + (ix * MI_SYSTEM_VIEW_BUCKET_SIZE));

    /* Get the hash entry for this allocation */
    Entry = (((ULONG_PTR)Base & ~(MI_SYSTEM_VIEW_BUCKET_SIZE - 1)) + Buckets);
    Hash = ((Entry >> 16) % Session->SystemSpaceHashKey);

    /* Loop hash entries until a free one is found */
    while (Session->SystemSpaceViewTable[Hash].Entry)
    {
        /* Unless we overflow, in which case loop back at hash o */
        if (++Hash >= Session->SystemSpaceHashSize)
            Hash = 0;
    }

    /* Add this entry into the hash table */
    Session->SystemSpaceViewTable[Hash].Entry = Entry;
    Session->SystemSpaceViewTable[Hash].ControlArea = ControlArea;

    /* Hash entry found, increment total and return the base address */
    Session->SystemSpaceHashEntries++;

    KeReleaseGuardedMutex(Session->SystemSpaceViewLockPointer);
    return Base;
}

VOID
NTAPI
MiFillSystemPageDirectory(
    _In_ PVOID Base,
    _In_ SIZE_T NumberOfBytes)
{
  #if (_MI_PAGING_LEVELS <= 2)
    PFN_NUMBER PageDirectoryPageNumber;
  #endif
    PMMPDE Pde;
    PMMPDE LastPde;
    PMMPDE SystemMapPde;
    MMPTE TempPde;
    PFN_NUMBER PageFrameIndex;
    KIRQL OldIrql;

    PAGED_CODE();
    DPRINT("MiFillSystemPageDirectory: Base %p, NumberOfBytes %X\n", Base, NumberOfBytes);

    /* Find the PDEs needed for this mapping */
    Pde = MiAddressToPde(Base);
    LastPde = MiAddressToPde((PVOID)((ULONG_PTR)Base + NumberOfBytes - 1));

  #if (_MI_PAGING_LEVELS <= 2)
    /* Find the system double-mapped PDE that describes this mapping */
    SystemMapPde = &MmSystemPagePtes[MiGetPdeOffset(Pde)];
  #else
    /* We don't have a double mapping */
    #error FIXME
  #endif

    /* Loop the PDEs */
    do
    {
        /* Check if we don't already have this PDE mapped */
        if (SystemMapPde->u.Hard.Valid)
            goto NextPde;

        /* Lock the PFN database */
        OldIrql = MiLockPfnDb(APC_LEVEL);

        /* Check if we don't already have this PDE mapped */
        if (SystemMapPde->u.Hard.Valid)
        {
            /* Release the lock and keep going with the next PDE */
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            goto NextPde;
        }

        if (MmAvailablePages < 0x80 && MiEnsureAvailablePageOrWait(NULL, OldIrql))
        {
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            continue;
        }

        MiChargeCommitmentCantExpand(1, TRUE);

        /* Grab a page for it */
        PageFrameIndex = MiRemoveZeroPage(MiGetColor());

        /* Use the PDE template */
        TempPde = ValidKernelPde;
        TempPde.u.Hard.PageFrameNumber = PageFrameIndex;

      #if (_MI_PAGING_LEVELS <= 2)
        /* Initialize its PFN entry, with PageFrameNumber of the page directory page entry */
        PageDirectoryPageNumber = MmSystemPageDirectory[MiGetPdIndex(Pde)];
        MiInitializePfnForOtherProcess(PageFrameIndex, (PMMPTE)Pde, PageDirectoryPageNumber);
      #else
        #error FIXME
      #endif

        /* Make the system PDE entry valid */
        MI_WRITE_VALID_PDE(SystemMapPde, TempPde);

        /* The system PDE entry might be the PDE itself, so check for this */
        if (Pde->u.Hard.Valid)
        {
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            goto NextPde;
        }

        /* It's different, so make the real PDE valid too */
        MI_WRITE_VALID_PDE(Pde, TempPde);

        /* Release the lock and keep going with the next PDE */
        MiUnlockPfnDb(OldIrql, APC_LEVEL);

NextPde:

        SystemMapPde++;
        Pde++;
    }
    while (Pde <= LastPde);
}

NTSTATUS
NTAPI
MiSessionCommitPageTables(
    _In_ PVOID StartVa,
    _In_ PVOID EndVa)
{
    MMPDE TempPde = ValidKernelPdeLocal;
    PMMPDE StartPde;
    PMMPDE EndPde;
    PMMPDE Pde;
    PMMPFN Pfn;
    PMMWSL WsList;
    PVOID SessionPte;
    PFN_NUMBER PageCount = 0;
    PFN_NUMBER ActualPages = 0;
    PFN_NUMBER PageFrameNumber;
    MMWSLE TempWsle;
    ULONG StartIndex;
    ULONG Index;
    ULONG WsIndex1;
    ULONG WsIndex2;
    KIRQL OldIrql;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("MiSessionCommitPageTables: StartVa %p, EndVa %p\n", StartVa, EndVa);

    /* Windows sanity checks */
    ASSERT(StartVa >= (PVOID)MmSessionBase);
    ASSERT(EndVa < (PVOID)MiSessionSpaceEnd);
    ASSERT(PAGE_ALIGN(EndVa) == EndVa);

    /* Get the start and end PDE, then loop each one */
    Pde = StartPde = MiAddressToPde(StartVa);
    EndPde = MiAddressToPde((PVOID)((ULONG_PTR)EndVa - 1));

    Index = StartIndex = (((ULONG_PTR)StartVa - (ULONG_PTR)MmSessionBase) >> 22);

    while (Pde <= EndPde)
    {
        /* If we don't already have a page table for it, increment count */
        if (!MmSessionSpace->PageTables[Index].u.Long)
            PageCount++;

        /* Move to the next one */
        Pde++;
        Index++;
    }

    /* If there's no page tables to create, bail out */
    if (!PageCount)
        return Status;

    if (!MiChargeCommitment(PageCount, NULL))
    {
        DPRINT1("MiSessionCommitPageTables: STATUS_NO_MEMORY\n");
        return STATUS_NO_MEMORY;
    }

    /* Acquire the PFN lock */
    OldIrql = MiLockPfnDb(APC_LEVEL);

    if ((SPFN_NUMBER)PageCount > (MmResidentAvailablePages - MmSystemLockPagesCount - 20)) // MmSystemLockPagesCount[0]
    {
        DPRINT1("MiSessionCommitPageTables: STATUS_NO_MEMORY\n");

        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        ASSERT((SSIZE_T)(PageCount) >= 0);
        ASSERT(MmTotalCommittedPages >= (PageCount));
        InterlockedExchangeAddSizeT(&MmTotalCommittedPages, -PageCount);
        //MmSessionFailureCauses[2]++;

        return STATUS_NO_MEMORY;
    }

    InterlockedExchangeAddSizeT(&MmResidentAvailablePages, -PageCount);
    //InterlockedExchangeAddSizeT(&MmResTrack[44], PageCount);

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    WsList = MmSessionSpace->Vm.VmWorkingSetList;

    /* Reset the start PDE and index */
    Pde = StartPde;
    Index = StartIndex;

    /* Loop each PDE while holding the working set lock */
    MiLockWorkingSet(PsGetCurrentThread(), &MmSessionSpace->GlobalVirtualAddress->Vm);

    while (Pde <= EndPde)
    {
        /* Check if we already have a page table */
        if (MmSessionSpace->PageTables[Index].u.Long)
        {
            /* Move to the next PDE */
            Pde++;
            Index++;
            continue;
        }

        /* We don't, so the PDE shouldn't be ready yet */
        ASSERT(Pde->u.Hard.Valid == 0);

        /* Acquire the PFN lock and grab a zero page */
        OldIrql = MiLockPfnDb(APC_LEVEL);

        if (MiEnsureAvailablePageOrWait(HYDRA_PROCESS, OldIrql))
        {
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            continue;
        }

        MmSessionSpace->Color++;
        PageFrameNumber = MiRemoveZeroPage(MI_GET_PAGE_COLOR(MmSessionSpace->Color));

        TempPde.u.Hard.PageFrameNumber = PageFrameNumber;
        MI_WRITE_VALID_PDE(Pde, TempPde);

        /* Write the page table in session space structure */
        ASSERT(MmSessionSpace->PageTables[Index].u.Long == 0);
        MmSessionSpace->PageTables[Index] = TempPde;

        /* Initialize the PFN */
        MiInitializePfnForOtherProcess(PageFrameNumber, Pde, MmSessionSpace->SessionPageDirectoryIndex);

        /* And now release the lock */
        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        /* Get the PFN entry and make sure there's no event for it */
        Pfn = MI_PFN_ELEMENT(PageFrameNumber);
        ASSERT(Pfn->u1.WsIndex == 0);

        SessionPte = MiPteToAddress(Pde);
        TempWsle.u1.Long = 0;

        WsIndex1 = MiAddValidPageToWorkingSet(SessionPte, Pde, Pfn, TempWsle);
        if (!WsIndex1)
        {
            MMPDE ZeroPde = {{ 0 }};

            DPRINT1("MiSessionCommitPageTables: STATUS_NO_MEMORY\n");

            OldIrql = MiLockPfnDb(APC_LEVEL);
            MI_SET_PFN_DELETED(Pfn);
            MiUnlockPfnDb(OldIrql, APC_LEVEL);

            MiTrimPte(SessionPte, Pde, Pfn, HYDRA_PROCESS, ZeroPde);

            ASSERT(MmSessionSpace->PageTables[Index].u.Long != 0);
            MmSessionSpace->PageTables[Index].u.Long = 0;

            Status = STATUS_NO_MEMORY;
            break;
        }

        /* Increment the number of pages */
        ActualPages++;

        ASSERT(WsIndex1 == MiLocateWsle(SessionPte, WsList, Pfn->u1.WsIndex, FALSE));

        WsIndex2 = WsList->FirstDynamic;

        if (WsIndex2 > WsIndex1)
        {
            WsIndex2 = WsIndex1;
        }
        else
        {
            if (WsIndex2 != WsIndex1)
                MiSwapWslEntries(WsIndex1, WsIndex2, &MmSessionSpace->Vm, FALSE);

            WsList->FirstDynamic++;
        }

        MmSessionSpace->Wsle[WsIndex2].u1.e1.LockedInWs = 1;

        /* Move to the next PDE */
        Pde++;
        Index++;
    }

    /* Make sure we didn't do more pages than expected */
    ASSERT(ActualPages <= PageCount);

    /* Release the working set lock */
    MiUnlockWorkingSet(PsGetCurrentThread(), &MmSessionSpace->GlobalVirtualAddress->Vm);

    /* If we did at least one page... */
    if (ActualPages)
    {
        /* Update the performance counters! */
        InterlockedExchangeAddSizeT(&MmSessionSpace->NonPageablePages, ActualPages); // NonPagablePages
        InterlockedExchangeAddSizeT(&MmSessionSpace->CommittedPages, ActualPages);
    }

    if (ActualPages < PageCount)
    {
        ASSERT((SSIZE_T)(PageCount - ActualPages) >= 0);
        ASSERT(MmTotalCommittedPages >= (PageCount - ActualPages));

        InterlockedExchangeAddSizeT(&MmTotalCommittedPages, (ActualPages - PageCount));
        InterlockedExchangeAddSizeT(&MmResidentAvailablePages, (PageCount - ActualPages));
        //InterlockedExchangeAddSizeT(&MmResTrack[73], PageCount - ActualPages);
    }

    /* Return status */
    return Status;
}

NTSTATUS
NTAPI
MiAddViewsForSectionWithPfn(
    _In_ PMSUBSECTION StartMappedSubsection,
    _In_ ULONGLONG LastPteOffset)
{
    KIRQL OldIrql;
    NTSTATUS Status;

    DPRINT("MiAddViewsForSectionWithPfn: StartMappedSubsection %p, LastPteOffset %I64X\n", StartMappedSubsection, LastPteOffset);

    OldIrql = MiLockPfnDb(APC_LEVEL);
    Status = MiAddViewsForSection(StartMappedSubsection, LastPteOffset, OldIrql);
    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    return Status;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MiAddMappedPtes(
    _In_ PMMPTE FirstPte,
    _In_ PFN_NUMBER PteCount,
    _In_ PCONTROL_AREA ControlArea)
{
    PSUBSECTION Subsection;
    PMMPTE Pte;
    PMMPTE LastPte;
    PMMPTE SectionProto;
    PMMPTE LastProto;
    MMPTE TempPte;
    NTSTATUS Status;

    DPRINT("MiAddMappedPtes: FirstPte %X, PteCount %X\n", FirstPte, PteCount);

    if (!ControlArea->u.Flags.GlobalOnlyPerSession && !ControlArea->u.Flags.Rom)
        Subsection = (PSUBSECTION)&ControlArea[1];
    else
        Subsection = (PSUBSECTION)((PLARGE_CONTROL_AREA)ControlArea + 1);

    /* Sanity checks */
    ASSERT(PteCount != 0);
    ASSERT(ControlArea->NumberOfMappedViews >= 1);
    ASSERT(ControlArea->NumberOfUserReferences >= 1);
    ASSERT(ControlArea->NumberOfSectionReferences != 0);
    ASSERT(ControlArea->u.Flags.BeingCreated == 0);
    ASSERT(ControlArea->u.Flags.BeingDeleted == 0);
    ASSERT(ControlArea->u.Flags.BeingPurged == 0);

    if (ControlArea->FilePointer &&
        !ControlArea->u.Flags.Image &&
        !ControlArea->u.Flags.PhysicalMemory)
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
    LastPte = (FirstPte + PteCount);

    /* Get the section protos that desribe the section mapping in the subsection */
    SectionProto = Subsection->SubsectionBase;
    LastProto = &Subsection->SubsectionBase[Subsection->PtesInSubsection];

    /* Loop the PTEs for the mapping */
    for (; Pte < LastPte; Pte++, SectionProto++)
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
    }

    /* No failure path */
    return STATUS_SUCCESS;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MiMapViewInSystemSpace(
    _In_ PVOID SectionObject,
    _In_ PMMSESSION Session,
    _Out_ PVOID* MappedBase,
    _Out_ PSIZE_T ViewSize)
{
    PSECTION Section = SectionObject;
    PCONTROL_AREA ControlArea;
    PVOID Base;
    ULONG Buckets;
    ULONG SectionSize;
    SIZE_T SizeOfBuckets;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("MiMapViewInSystemSpace: Section %p, Session %p, MappedBase %p, ViewSize %I64X\n",
           Section, Session, (!MappedBase ? NULL : *MappedBase), (!ViewSize ? 0 : (ULONGLONG)*ViewSize));

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
            ASSERT(FALSE);
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
    Buckets = (ULONG)(*ViewSize / MM_ALLOCATION_GRANULARITY);

    if (*ViewSize & (MM_ALLOCATION_GRANULARITY - 1))
        Buckets++;

    /* Check if the view is more than 4GB large */
    if (Buckets >= MM_ALLOCATION_GRANULARITY)
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

    SizeOfBuckets = (Buckets * MM_ALLOCATION_GRANULARITY);

    /* What's the underlying session? */
    if (Session == &MmSession)
    {
        /* Create the PDEs needed for this mapping, and double-map them if needed */
        MiFillSystemPageDirectory(Base, SizeOfBuckets);
    }
    else
    {
        /* Create the PDEs needed for this mapping */
        Status = MiSessionCommitPageTables(Base, (PVOID)((ULONG_PTR)Base + SizeOfBuckets));
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("MiMapViewInSystemSpace: Status %X\n", Status);
            goto ErrorExit;
        }
    }

    /* Create the actual section protos for this mapping */
    Status = MiAddMappedPtes(MiAddressToPte(Base), BYTES_TO_PAGES(*ViewSize), ControlArea);
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

BOOLEAN
NTAPI
MiIsProtectionCompatible(
    _In_ ULONG SectionPageProtection,
    _In_ ULONG NewSectionPageProtection)
{
    ULONG ProtectionMask;
    ULONG CompatibleMask;

    DPRINT("MiIsProtectionCompatible: %X, %X\n", SectionPageProtection, NewSectionPageProtection);

    /* Calculate the protection mask and make sure it's valid */
    ProtectionMask = MiMakeProtectionMask(SectionPageProtection);
    if (ProtectionMask == MM_INVALID_PROTECTION)
    {
        DPRINT1("MiIsProtectionCompatible: ProtectionMask == MM_INVALID_PROTECTION\n");
        return FALSE;
    }

    /* Calculate the compatible mask */
    CompatibleMask = MmCompatibleProtectionMask[ProtectionMask & 0x7] |
                     PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;

    /* See if the mapping protection is compatible with the create protection */
    return ((CompatibleMask | NewSectionPageProtection) == CompatibleMask);
}

BOOLEAN
NTAPI
MiIsPteProtectionCompatible(
    _In_ ULONG PteProtection,
    _In_ ULONG NewProtection)
{
    ULONG CompatibleMask;

    DPRINT("MiIsProtectionCompatible: %X, %X\n", PteProtection, NewProtection);

    /* Calculate the compatible mask */
    CompatibleMask = MmCompatibleProtectionMask[PteProtection & 0x7] |
                     PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;

    /* See if the mapping protection is compatible with the create protection */
    return ((CompatibleMask | NewProtection) == CompatibleMask);
}

VOID
NTAPI
MiInsertPhysicalViewAndRefControlArea(
    _In_ PEPROCESS Process,
    _In_ PCONTROL_AREA ControlArea,
    _In_ PMM_PHYSICAL_VIEW PhysicalView)
{
    KIRQL OldIrql;

    DPRINT("MiInsertPhysicalViewAndRefControlArea: %p, %p, %p\n", Process, ControlArea, PhysicalView);

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
MiSetPageModified(
    _In_ PMMVAD Vad,
    _In_ PVOID Address)
{
    PETHREAD CurrentThread = PsGetCurrentThread();
    PEPROCESS CurrentProcess;
    PMMPTE Pte;
    PMMPDE Pde;
    PMMPFN Pfn;
    MMPTE PteContents;
    KIRQL OldIrql;
    BOOLEAN IsReturnQuota = FALSE;
    BOOLEAN IsMemoryUsage = FALSE;
    NTSTATUS Status;

    DPRINT("MiSetPageModified: Vad %p, Address %p\n", Vad, Address);

    ASSERT((CurrentThread) == PsGetCurrentThread());
    CurrentProcess = (PEPROCESS)CurrentThread->Tcb.ApcState.Process;

    Status = PsChargeProcessPageFileQuota(CurrentProcess, 1);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MiSetPageModified: Status %X\n", Status);
        return STATUS_COMMITMENT_LIMIT;
    }

    if (CurrentProcess->CommitChargeLimit &&
        CurrentProcess->CommitChargeLimit < (CurrentProcess->CommitCharge + 1))
    {
        if (CurrentProcess->Job)
        {
            DPRINT1("MiSetPageModified: FIXME\n");
            ASSERT(FALSE);
        }

        PsReturnProcessPageFileQuota(CurrentProcess, 1);

        DPRINT1("MiSetPageModified: STATUS_COMMITMENT_LIMIT\n");
        return STATUS_COMMITMENT_LIMIT;
    }

    if (CurrentProcess->JobStatus & 0x10)
    {
        DPRINT1("MiSetPageModified: FIXME\n");
        ASSERT(FALSE);
        IsMemoryUsage = TRUE;
    }

    if (!MiChargeCommitment(1, NULL))
    {
        DPRINT1("MiSetPageModified: FIXME\n");
        ASSERT(FALSE);
    }

    CurrentProcess->CommitCharge++;

    if (CurrentProcess->CommitCharge > CurrentProcess->CommitChargePeak)
        CurrentProcess->CommitChargePeak = CurrentProcess->CommitCharge;

    Pte = MiAddressToPte(Address);
    Pde = MiAddressToPde(Address);

    while (TRUE)
    {
        _SEH2_TRY
        {
            ProbeForReadChar(Address);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            DPRINT1("MiSetPageModified: FIXME\n");
            ASSERT(FALSE);
            return _SEH2_GetExceptionCode();
        }
        _SEH2_END;

        MiLockProcessWorkingSetUnsafe(CurrentProcess, CurrentThread);

        if (Pde->u.Hard.Valid && Pte->u.Hard.Valid)
            break;

        MiUnlockProcessWorkingSetUnsafe(CurrentProcess, CurrentThread);
    }

    PteContents.u.Long = Pte->u.Long;
    ASSERT(PteContents.u.Hard.Valid == 1);

    Pfn = MI_PFN_ELEMENT(PteContents.u.Hard.PageFrameNumber);

    OldIrql = MiLockPfnDb(APC_LEVEL);

    ASSERT(Pfn->u3.e1.Rom == 0);
    Pfn->u3.e1.Modified = 1;

    if (!Pfn->OriginalPte.u.Soft.Prototype)
    {
        if (!Pfn->u3.e1.WriteInProgress)
        {
            DPRINT1("MiSetPageModified: FIXME\n");
            ASSERT(FALSE);
        }

        IsReturnQuota = TRUE;
    }

    MI_MAKE_CLEAN_PAGE(&PteContents);

    ASSERT(Pte->u.Hard.Valid == 1);
    Pte->u.Long = PteContents.u.Long;

    //FIXME: Use "KeFlushSingleTb(Address, 0);" instead
    KeFlushCurrentTb();

    MiUnlockPfnDb(OldIrql, APC_LEVEL);
    MiUnlockProcessWorkingSetUnsafe(CurrentProcess, CurrentThread);

    if (!IsReturnQuota)
    {
        ASSERT(Vad->u.VadFlags.CommitCharge != 0x7FFFF);
        Vad->u.VadFlags.CommitCharge++;
        return STATUS_SUCCESS;
    }

    CurrentProcess->CommitCharge--;

    if (IsMemoryUsage)
    {
        DPRINT1("MiSetPageModified: FIXME\n");
        ASSERT(FALSE);
    }

    ASSERT(MmTotalCommittedPages >= 1);
    InterlockedDecrementSizeT(&MmTotalCommittedPages);

    PsReturnProcessPageFileQuota(CurrentProcess, 1);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
MiMapViewOfPhysicalSection(
    _In_ PCONTROL_AREA ControlArea,
    _In_ PEPROCESS Process,
    _Inout_ PVOID* BaseAddress,
    _In_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ ULONG ProtectionMask,
    _In_ ULONG_PTR ZeroBits,
    _In_ ULONG AllocationType)
{
    PMM_PHYSICAL_VIEW PhysicalView;
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
    BOOLEAN IsIoMapping;
    KIRQL OldIrql;
    NTSTATUS Status;

    DPRINT("MiMapViewOfPhysicalSection: %p, %p, Base [%p], Offset [%I64X], ViewSize [%I64X], %X, %X, %X\n",
           ControlArea, Process, (BaseAddress ? *BaseAddress : NULL), (SectionOffset ? SectionOffset->QuadPart : 0),
           (ViewSize ? (ULONGLONG)*ViewSize : 0), ProtectionMask, ZeroBits, AllocationType);

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
        StartingAddress = (ALIGN_DOWN_BY(*BaseAddress, MM_ALLOCATION_GRANULARITY) + Offset);
        EndingAddress = ((StartingAddress + *ViewSize - 1) | (PAGE_SIZE - 1));

        DPRINT("MiMapViewOfPhysicalSection: %p, %p, %p\n", *BaseAddress, StartingAddress, EndingAddress);

        if (MiCheckForConflictingVadExistence(Process, StartingAddress, EndingAddress))
        {
            DPRINT1("MiMapViewOfPhysicalSection: STATUS_CONFLICTING_ADDRESSES\n");
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }
    else
    {
        ASSERT(SectionOffset->HighPart == 0);

        SizeOfRange = (Offset + *ViewSize);

        if ((AllocationType & MEM_TOP_DOWN) || Process->VmTopDown)
        {
            if (ZeroBits)
            {
                HighestAddress = ((ULONG_PTR)MI_HIGHEST_SYSTEM_ADDRESS >> ZeroBits);

                if (HighestAddress > (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS)
                    HighestAddress = (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS;
            }
            else
            {
                HighestAddress = (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS;
            }

            Status = MiFindEmptyAddressRangeDownTree(SizeOfRange,
                                                     HighestAddress,
                                                     MM_ALLOCATION_GRANULARITY,
                                                     &Process->VadRoot,
                                                     &TmpStartingAddress);
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

        StartingAddress = (TmpStartingAddress + Offset);
        EndingAddress = (StartingAddress + *ViewSize - 1) | (PAGE_SIZE - 1);

        DPRINT1("MiMapViewOfPhysicalSection: %p, %p, %p\n", TmpStartingAddress, StartingAddress, EndingAddress);

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
        MI_MAKE_DIRTY_PAGE(&TempPte);

    /* Is IO mapping */
    IsIoMapping = TRUE;

    if (StartPageNumber <= MmHighestPhysicalPage) // should be MmHighestPossiblePhysicalPage
    {
        if (MiGetPfnEntry(StartPageNumber))
            /* Is MEMORY mapping */
            IsIoMapping = FALSE;
    }

    InputCacheType = MmCached;

    if ((ProtectionMask & MM_WRITECOMBINE) == MM_WRITECOMBINE && (ProtectionMask & MM_PROTECT_ACCESS))
        InputCacheType = MmWriteCombined;
    else if ((ProtectionMask & MM_NOCACHE) == MM_NOCACHE)
        InputCacheType = MmNonCached;

    ASSERT(InputCacheType <= MmWriteCombined);

    if (IsIoMapping)
        CacheAttribute = MiPlatformCacheAttributes[IsIoMapping][InputCacheType];
    else
        CacheAttribute = MiPlatformCacheAttributes[IsIoMapping][InputCacheType];

    PagesCount = (LastPte - Pte + 1);

    if (CacheAttribute != MiCached)
    {
        if (CacheAttribute == MiWriteCombined)
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

    if (!Process->PhysicalVadRoot)
    {
        if (!MiCreatePhysicalVadRoot(Process, FALSE))
        {
            DPRINT1("MiMapViewOfPhysicalSection: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    PhysicalView = ExAllocatePoolWithTag(NonPagedPool, sizeof(MM_PHYSICAL_VIEW), 'vpmM');
    if (!PhysicalView)
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
    VadLong->StartingVpn = (StartingAddress / PAGE_SIZE);
    VadLong->EndingVpn = (EndingAddress / PAGE_SIZE);

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
            MiMakePdeExistAndMakeValid(Pde, Process, MM_NOIRQL);

            Pfn = MI_PFN_ELEMENT(Pde->u.Hard.PageFrameNumber);
            UsedAddress = MiPteToAddress(Pte);
        }

        MiIncrementPageTableReferences(UsedAddress);

        DPRINT("MiMapViewOfPhysicalSection: [%d] Address %p, RefCount %X\n",
               MiAddressToPdeOffset(UsedAddress), UsedAddress, MiQueryPageTableReferences(UsedAddress));

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
    *ViewSize = (EndingAddress - StartingAddress + 1);

    DPRINT("MiMapViewOfPhysicalSection: Base %p, ViewSize %p\n", *BaseAddress, *ViewSize);

    Process->VirtualSize += *ViewSize;

    if (Process->VirtualSize > Process->PeakVirtualSize)
        Process->PeakVirtualSize = Process->VirtualSize;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
MiMapViewOfImageSection(
    _In_ PCONTROL_AREA ControlArea,
    _In_ PEPROCESS Process,
    _Inout_ PVOID* OutBaseAddress,
    _Inout_ LARGE_INTEGER* OutSectionOffset,
    _Inout_ SIZE_T* OutViewSize,
    _In_ PSECTION Section,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG ZeroBits,
    _In_ ULONG AllocationType,
    _In_ SIZE_T ImageCommitment)
{
    //PSECTION_IMAGE_INFORMATION ImageInfo;
    PSUBSECTION Subsection;
    PSUBSECTION CurrentSubsection;
    PVOID BasedAddress;
    PETHREAD Thread;
    PMMVAD Vad;
    ULONG_PTR StartingAddress;
    ULONG_PTR EndingAddress;
    ULONG_PTR BoundaryAddress;
    SIZE_T ViewSize;
    BOOLEAN IsConflictingVad;
    BOOLEAN IsLargePages;
    NTSTATUS status;
    NTSTATUS Status;

    DPRINT("MiMapViewOfImageSection: %p, %p, [%p], [%I64X], [%p], %p, %X, %X, %X\n",
           ControlArea, Process, (OutBaseAddress?*OutBaseAddress:0), (OutSectionOffset?OutSectionOffset->QuadPart:0),
           (OutViewSize?*OutViewSize:0), Section, ZeroBits, AllocationType, ImageCommitment);

    if (ControlArea->u.Flags.GlobalOnlyPerSession || ControlArea->u.Flags.Rom)
        Subsection = (PSUBSECTION)((PLARGE_CONTROL_AREA)ControlArea + 1);
    else
        Subsection = (PSUBSECTION)(ControlArea + 1);

    status = MiCheckPurgeAndUpMapCount(ControlArea, 1);
    if (!NT_SUCCESS(status))
    {
        DPRINT1("MiMapViewOfImageSection: status %X\n", status);
        return status;
    }

    BasedAddress = ControlArea->Segment->BasedAddress;

    if (!(*OutViewSize))
        *OutViewSize = (SIZE_T)(Section->SizeOfSection.QuadPart - OutSectionOffset->QuadPart);

    IsLargePages = FALSE;

    if ((AllocationType & MEM_LARGE_PAGES) &&
        !OutSectionOffset->QuadPart &&
        (KeFeatureBits & KF_LARGE_PAGE) &&
        SeSinglePrivilegeCheck(SeLockMemoryPrivilege, KeGetPreviousMode()))
    {
        CurrentSubsection = Subsection;

        do
        {
            if (CurrentSubsection->u.SubsectionFlags.GlobalMemory)
                break;

            CurrentSubsection = CurrentSubsection->NextSubsection;
        }
        while (CurrentSubsection);

        if (!CurrentSubsection)
            IsLargePages = TRUE;
    }

    while (TRUE)
    {
        Status = STATUS_SUCCESS;

        if (!(*OutBaseAddress))
        {
            if ((PVOID)*OutViewSize > MM_HIGHEST_VAD_ADDRESS)
            {
                MiDereferenceControlArea(ControlArea);
                return STATUS_NO_MEMORY;
            }

            StartingAddress = (ULONG_PTR)BasedAddress + (OutSectionOffset->LowPart & ~(MM_ALLOCATION_GRANULARITY - 1));
            EndingAddress = (StartingAddress + *OutViewSize - 1) | (PAGE_SIZE - 1);

            if (IsLargePages)
            {
                DPRINT1("MiMapViewOfImageSection: FIXME\n");
                ASSERT(FALSE);
            }

            IsConflictingVad = TRUE;

            if (StartingAddress >= MM_ALLOCATION_GRANULARITY &&
                StartingAddress <= (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS &&
                ((ULONG_PTR)MM_HIGHEST_VAD_ADDRESS - StartingAddress + 1) >= *OutViewSize &&
                EndingAddress <= (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS)
            {
                IsConflictingVad = MiCheckForConflictingVadExistence(Process, StartingAddress, EndingAddress);
            }

            if (IsConflictingVad)
            {
                if (MmVirtualBias)
                {
                    DPRINT1("MiMapViewOfImageSection: FIXME\n");
                    ASSERT(MmVirtualBias == 0);

                    if (ZeroBits)
                        ZeroBits = 1;
                }

                Status = STATUS_IMAGE_NOT_AT_BASE;

                if (Process->VmTopDown)
                {
                    if (!ZeroBits)
                    {
                        BoundaryAddress = (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS;
                    }
                    else
                    {
                        BoundaryAddress = ((ULONG_PTR)MI_HIGHEST_SYSTEM_ADDRESS >> ZeroBits);

                        if (BoundaryAddress > (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS)
                            BoundaryAddress = (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS;
                    }

                    status = MiFindEmptyAddressRangeDownTree(*OutViewSize,
                                                             BoundaryAddress,
                                                             MM_ALLOCATION_GRANULARITY,
                                                             &Process->VadRoot,
                                                             &StartingAddress);
                }
                else
                {
                    status = MiFindEmptyAddressRange(*OutViewSize,
                                                     MM_ALLOCATION_GRANULARITY,
                                                     ZeroBits,
                                                     (PULONG_PTR)&StartingAddress);
                }

                if (!NT_SUCCESS(status))
                {
                    MiDereferenceControlArea(ControlArea);
                    return status;
                }

                EndingAddress = (StartingAddress + *OutViewSize - 1) | (PAGE_SIZE - 1);
            }
        }
        else
        {
            DPRINT1("MiMapViewOfImageSection: FIXME\n");
            ASSERT(FALSE);
        }

        Thread = PsGetCurrentThread();

        Vad = ExAllocatePoolWithTag(NonPagedPool, sizeof(MMVAD), ' daV');
        if (!Vad)
        {
            if (IsLargePages)
            {
                DPRINT1("MiMapViewOfImageSection: FIXME\n");
                ASSERT(FALSE);
            }

            MiDereferenceControlArea(ControlArea);

            DPRINT1("MiMapViewOfImageSection: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(Vad, sizeof(MMVAD));

        Vad->StartingVpn = (StartingAddress / PAGE_SIZE);
        Vad->EndingVpn = (EndingAddress / PAGE_SIZE);

        Vad->u2.VadFlags2.Inherit = (InheritDisposition == ViewShare);
        Vad->u.VadFlags.VadType = VadImageMap;
        Vad->u.VadFlags.Protection = MM_EXECUTE_WRITECOPY;

        Vad->ControlArea = ControlArea;

        OutSectionOffset->LowPart &= ~(MM_ALLOCATION_GRANULARITY - 1);

        Vad->FirstPrototypePte = &Subsection->SubsectionBase[OutSectionOffset->QuadPart / PAGE_SIZE];
        Vad->LastContiguousPte = (PMMPTE)-4;

        Vad->u.VadFlags.CommitCharge = ImageCommitment;
        ASSERT(Vad->FirstPrototypePte <= Vad->LastContiguousPte);

        status = MiInsertVadCharges(Vad, Process);
        if (!NT_SUCCESS(status))
        {
            DPRINT1("MiMapViewOfImageSection: status %X\n", status);
            MiDereferenceControlArea(ControlArea);

            if (IsLargePages)
            {
                DPRINT1("MiMapViewOfImageSection: FIXME\n");
                ASSERT(FALSE);
            }

            ExFreePoolWithTag(Vad, ' daV');
            return status;
        }

        MiLockProcessWorkingSetUnsafe(Process, Thread);
        MiInsertVad(Vad, &Process->VadRoot);
        MiUnlockProcessWorkingSetUnsafe(Process, Thread);

        ViewSize = (EndingAddress - StartingAddress + 1);
        Process->VirtualSize += ViewSize;

        if (Process->VirtualSize > Process->PeakVirtualSize)
            Process->PeakVirtualSize = Process->VirtualSize;

        if (!IsLargePages)
        {
            if (ControlArea->u.Flags.FloppyMedia)
            {
                PMMPTE proto = Vad->FirstPrototypePte;
                ULONG_PTR address = StartingAddress;

                while (address < EndingAddress)
                {
                    if (proto->u.Hard.Valid ||
                        ((proto->u.Soft.Prototype || proto->u.Soft.Transition) && (proto->u.Soft.Protection != MM_NOACCESS)))
                    {
                        status = MiSetPageModified(Vad, (PVOID)address);

                        if (!NT_SUCCESS(status) && ControlArea->u.Flags.Networked)
                        {
                            DPRINT1("MiMapViewOfImageSection: FIXME MiUnmapViewOfSection()\n");
                            ASSERT(FALSE);

                            return status;
                        }
                    }

                    proto++;
                    address += PAGE_SIZE;
                }
            }

            break;
        }
        else
        {
            DPRINT1("MiMapViewOfImageSection: FIXME\n");
            ASSERT(FALSE);
        }
    }

    *OutViewSize = ViewSize;
    *OutBaseAddress = (PVOID)StartingAddress;

    DPRINT("MiMapViewOfImageSection: %p, %p, %I64X, %IX\n",
           Section, *OutBaseAddress, (OutSectionOffset?OutSectionOffset->QuadPart:0), *OutViewSize);

    ASSERT(NT_SUCCESS(Status));

    DPRINT("MiMapViewOfImageSection: FIXME\n");
    //ImageInfo = ControlArea->Segment->u2.ImageInformation;
    //...

    if (PsImageNotifyEnabled &&
        StartingAddress < (ULONG_PTR)MmHighestUserAddress &&
        Process->UniqueProcessId &&
        Process != PsInitialSystemProcess)
    {
        DPRINT("MiMapViewOfImageSection: FIXME PsCallImageNotifyRoutines\n");
        //ASSERT(FALSE);
    }

    ASSERT(ControlArea->u.Flags.Image);

    if ((NtGlobalFlag & FLG_ENABLE_KDEBUG_SYMBOL_LOAD) &&
        Status != STATUS_IMAGE_NOT_AT_BASE &&
        !ControlArea->u.Flags.DebugSymbolsLoaded)
    {
        DPRINT("MiMapViewOfImageSection: FIXME load user symbols\n");

      #if 0
        if (MiCacheImageSymbols(StartingAddress))
        {
            MiSetControlAreaSymbolsLoaded(ControlArea);
            MiLoadUserSymbols(ControlArea, StartingAddress, Process);
        }
      #endif
    }

    return Status;
}

NTSTATUS
NTAPI
MiMapViewOfDataSection(
    _In_ PCONTROL_AREA ControlArea,
    _In_ PEPROCESS Process,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ PSECTION Section,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG ProtectionMask,
    _In_ SIZE_T CommitSize,
    _In_ ULONG_PTR ZeroBits,
    _In_ ULONG AllocationType)
{
    PSEGMENT Segment = ControlArea->Segment;
    PMMEXTEND_INFO ExtendInfo;
    PSUBSECTION Subsection;
    PETHREAD Thread;
    PMMVAD Vad;
    PMMPTE Pte;
    PMMPTE LastPte;
    MMPTE TempPte;
    ULONGLONG PteOffset;
    ULONGLONG LastPteOffset;
    LARGE_INTEGER TotalNumberOfPtes;
    ULONG_PTR StartAddress;
    ULONG_PTR EndAddress;
    ULONG_PTR HighestAddress;
    ULONG Granularity = MM_ALLOCATION_GRANULARITY;
    ULONG VadSize;
    ULONG QuotaCharge = 0;
    ULONG QuotaExcess = 0;
    BOOLEAN IsLargePages;
    BOOLEAN IsFindEnabled;
    NTSTATUS Status;

    DPRINT("MiMapViewOfDataSection: %p, %I64X, %IX, %p, %p, %X, %X, %X, %X\n",
           Section, (SectionOffset ? SectionOffset->QuadPart : 0), (ViewSize ? *ViewSize : 0),
           ControlArea, Process, ZeroBits, CommitSize, AllocationType, ProtectionMask);

    /* One can only reserve a file-based mapping, not shared memory! */
    if ((AllocationType & MEM_RESERVE) && !ControlArea->FilePointer)
    {
        DPRINT1("MiMapViewOfDataSection: STATUS_INVALID_PARAMETER_9\n");
        return STATUS_INVALID_PARAMETER_9;
    }

    /* ALlow being less restrictive */
    if (AllocationType & MEM_DOS_LIM)
    {
        if (!(*BaseAddress) || (AllocationType & MEM_RESERVE))
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
        /* A size was specified, align it */
        *ViewSize += (SectionOffset->LowPart & (Granularity - 1));

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
        DPRINT1("MiMapViewOfDataSection: STATUS_INVALID_VIEW_SIZE\n");
        MiDereferenceControlArea(ControlArea);
        return STATUS_INVALID_VIEW_SIZE;
    }

    /* Windows ASSERTs for this flag */
    ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);

    /* Get the subsection. */
    if (ControlArea->u.Flags.Rom)
    {
        Subsection = (PSUBSECTION)((PLARGE_CONTROL_AREA)ControlArea + 1);
        DPRINT("MiMapViewOfDataSection: Subsection %X\n", Subsection);
    }
    else
    {
        Subsection = (PSUBSECTION)(ControlArea + 1);
        DPRINT("MiMapViewOfDataSection: Subsection %X\n", Subsection);
    }

    /* Within this section, figure out which PTEs will describe the view */
    TotalNumberOfPtes.LowPart = Segment->TotalNumberOfPtes;
    TotalNumberOfPtes.HighPart = Segment->SegmentFlags.TotalNumberOfPtes4132;

    /* The offset must be in this segment's PTE chunk and it must be valid. */
    PteOffset = (SectionOffset->QuadPart / PAGE_SIZE);
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

    if (ControlArea->FilePointer)
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
        CommitSize &&
        Segment->NumberOfCommittedPages < (ULONGLONG)TotalNumberOfPtes.QuadPart)
    {
        DPRINT1("MiMapViewOfDataSection: FIXME. CommitSize %X\n", CommitSize);
        ASSERT(FALSE);
    }

    if (Segment->SegmentFlags.LargePages)
    {
        /* ARM3 does not currently support large pages */
        ASSERT(Segment->SegmentFlags.LargePages == 0);
        IsLargePages = TRUE;
        DbgBreakPoint();
    }
    else
    {
        IsLargePages = FALSE;
    }

    /* Is it SEC_BASED, or did the caller manually specify an address? */
    if (*BaseAddress || Section->Address.StartingVpn)
    {
        if (*BaseAddress)
            /* Just align what the caller gave us */
            StartAddress = ALIGN_DOWN_BY(*BaseAddress, Granularity);
        else
            /* It is a SEC_BASED mapping, use the address that was generated */
            StartAddress = (Section->Address.StartingVpn + SectionOffset->LowPart);

        if ((ULONG_PTR)StartAddress & (0x400000 - 1))
            IsLargePages = FALSE;

        EndAddress = ((StartAddress + *ViewSize - 1) | (PAGE_SIZE - 1));

        if (MiCheckForConflictingVadExistence(Process, StartAddress, EndAddress))
        {
            DPRINT1("MiMapViewOfDataSection: STATUS_CONFLICTING_ADDRESSES\n");
            Status = STATUS_CONFLICTING_ADDRESSES;
            goto ErrorExit;
        }
    }
    else
    {
        /* No StartAddress. Find empty address range. */
        IsFindEnabled = TRUE;

        if ((AllocationType & MEM_TOP_DOWN) || Process->VmTopDown)
        {
            HighestAddress = (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS;

            if (ZeroBits)
            {
                HighestAddress = ((ULONG_PTR)MI_HIGHEST_SYSTEM_ADDRESS >> ZeroBits);
                if (HighestAddress > (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS)
                    HighestAddress = (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS;
            }

            if (IsLargePages)
            {
                DPRINT1("MiMapViewOfDataSection: FIXME. IsLargePages TRUE\n");
                ASSERT(FALSE);

                Status = MiFindEmptyAddressRangeDownTree(*ViewSize,
                                                         HighestAddress,
                                                         0x400000,
                                                         &Process->VadRoot,
                                                         &StartAddress);

                if (!NT_SUCCESS(Status))
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
                Status = MiFindEmptyAddressRangeDownTree(*ViewSize,
                                                         HighestAddress,
                                                         Granularity,
                                                         &Process->VadRoot,
                                                         &StartAddress);
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

                if (!NT_SUCCESS(Status))
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

        EndAddress = ((StartAddress + *ViewSize - 1) | (PAGE_SIZE - 1));

        if (ZeroBits && (EndAddress > ((ULONG_PTR)MI_HIGHEST_SYSTEM_ADDRESS >> ZeroBits)))
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

    if (!Vad)
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

    if ((AllocationType & SEC_NO_CHANGE) || Section->u.Flags.NoChange)
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
            if (!ExtendInfo)
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
            ExtendInfo->CommittedSize = (ULONGLONG)Section->SizeOfSection.QuadPart;

        KeReleaseGuardedMutexUnsafe(&MmSectionBasedMutex);

        Vad->u2.VadFlags2.ExtendableFile = 1;

        ASSERT(((PMMVAD_LONG)Vad)->u4.ExtendedInfo == NULL);
        ((PMMVAD_LONG)Vad)->u4.ExtendedInfo = ExtendInfo;
    }

    if ((ProtectionMask & MM_WRITECOPY) == MM_WRITECOPY)
        Vad->u.VadFlags.CommitCharge = BYTES_TO_PAGES(EndAddress - StartAddress);

    /* Finally, write down the first and last prototype PTE */
    Vad->StartingVpn = (StartAddress / PAGE_SIZE);
    Vad->EndingVpn = (EndAddress / PAGE_SIZE);

    Vad->FirstPrototypePte = &Subsection->SubsectionBase[PteOffset];

    PteOffset += (Vad->EndingVpn - Vad->StartingVpn);

    if (PteOffset >= Subsection->PtesInSubsection)
        Vad->LastContiguousPte = &Subsection->SubsectionBase[Subsection->PtesInSubsection - 1 + Subsection->UnusedPtes];
    else
        Vad->LastContiguousPte = &Subsection->SubsectionBase[PteOffset];

    /* Make sure the prototype PTE ranges make sense, this is a Windows ASSERT */
    ASSERT(Vad->FirstPrototypePte <= Vad->LastContiguousPte);

    /* Check if anything was committed */
    if (QuotaCharge)
    {
        DPRINT1("MiMapViewOfDataSection: FIXME MiChargeCommitment()\n");
        ASSERT(FALSE);
    }

    ASSERT(Vad->FirstPrototypePte <= Vad->LastContiguousPte);
    Thread = PsGetCurrentThread();

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
            ExFreePoolWithTag(Vad, 'ldaV');
        else
            ExFreePoolWithTag(Vad, ' daV');

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
    MiLockProcessWorkingSetUnsafe(Process, Thread);
    MiInsertVad(Vad, &Process->VadRoot);
    MiUnlockProcessWorkingSetUnsafe(Process, Thread);

    if (IsLargePages)
    {
        DPRINT1("MiMapViewOfDataSection: FIXME MiMapLargePageSection()\n");
        ASSERT(FALSE);
    }

    /* Windows stores this for accounting purposes, do so as well */
    if (!ControlArea->FilePointer && !Segment->u2.FirstMappedVa)
        Segment->u2.FirstMappedVa = (PVOID)StartAddress;

    if (AllocationType & MEM_RESERVE)
    {
        ASSERT((EndAddress - StartAddress) <= (((ULONGLONG)Segment->SizeOfSegment + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1)));
    }

    /* Check if anything was committed */
    if (QuotaCharge)
    {
        /* Set the start and end PTE addresses, and pick the template PTE */
        Pte = Vad->FirstPrototypePte;
        LastPte = (Pte + BYTES_TO_PAGES(CommitSize));
        TempPte = Segment->SegmentPteTemplate;

        /* Acquire the commit lock and loop all prototype PTEs to be committed */
        KeAcquireGuardedMutexUnsafe(&MmSectionCommitMutex);

        for (; Pte < LastPte; Pte++)
        {
            /* Test the PTE */
            if (Pte->u.Long)
                /* The PTE is valid, so skip it */
                QuotaExcess++;
            else
                /* Write the invalid PTE */
                MI_WRITE_INVALID_PTE(Pte, TempPte);
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
    *ViewSize = (EndAddress - StartAddress + 1);
    *BaseAddress = (PVOID)StartAddress;

    Process->VirtualSize += *ViewSize;

    if (Process->VirtualSize > Process->PeakVirtualSize)
        Process->PeakVirtualSize = Process->VirtualSize;

    if ((ProtectionMask == MM_READWRITE || ProtectionMask == MM_EXECUTE_READWRITE) && ControlArea->FilePointer)
        InterlockedIncrement((volatile PLONG)&ControlArea->WritableUserReferences);

    DPRINT("MiMapViewOfDataSection: %p,  %p, %I64X, %IX\n",
           Section, *BaseAddress, (SectionOffset ? SectionOffset->QuadPart : 0), *ViewSize);

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
            ExFreePoolWithTag(Vad, 'ldaV');
        else
            ExFreePoolWithTag(Vad, ' daV');
    }

    DPRINT("MiMapViewOfDataSection: *BaseAddress %p, *ViewSize %p, Status %X\n", *BaseAddress, *ViewSize, Status);
    return Status;
}

PSUBSECTION
NTAPI
MiLocateSubsection(
    _In_ PMMVAD Vad,
    _In_ ULONG_PTR Vpn)
{
    PSUBSECTION Subsection;
    PCONTROL_AREA ControlArea;
    ULONG_PTR PteOffset;

    //DPRINT("MiLocateSubsection: Vad %p, Vpn %p\n", Vad, Vpn);

    /* Get the control area */
    ControlArea = Vad->ControlArea;

    /* Get the subsection */
    if (ControlArea->u.Flags.Rom)
        Subsection = (PSUBSECTION)&((PLARGE_CONTROL_AREA)ControlArea)[1];
    else
        Subsection = (PSUBSECTION)&ControlArea[1];

    if (ControlArea->u.Flags.Image)
    {
        if (ControlArea->u.Flags.GlobalOnlyPerSession)
            Subsection = (PSUBSECTION)&((PLARGE_CONTROL_AREA)ControlArea)[1];

        return Subsection;
    }

    ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);

    while (TRUE)
    {
        if (Subsection->SubsectionBase &&
            Vad->FirstPrototypePte >= Subsection->SubsectionBase &&
            Vad->FirstPrototypePte < &Subsection->SubsectionBase[Subsection->PtesInSubsection])
        {
            break;
        }

        Subsection = Subsection->NextSubsection;
        if (!Subsection)
            return NULL;
    }

    ASSERT(Subsection->SubsectionBase != NULL);

    /* Compute the PTE offset */
    PteOffset = (Vpn - Vad->StartingVpn);
    PteOffset += (Vad->FirstPrototypePte - Subsection->SubsectionBase);

    ASSERT(PteOffset < 0xF0000000);

    while (PteOffset >= Subsection->PtesInSubsection)
    {
        PteOffset -= Subsection->PtesInSubsection;

        Subsection = Subsection->NextSubsection;
        if (!Subsection)
            return NULL;

        ASSERT(Subsection->SubsectionBase != NULL);
    }

    ASSERT(Subsection->SubsectionBase != NULL);

    /* Return the subsection */
    return Subsection;
}

VOID
NTAPI
MiDecrementSubsections(
    _In_ PSUBSECTION FirstSubsection,
    _In_ PSUBSECTION LastSubsection)
{
    PMSUBSECTION MappedSubsection;
    PSUBSECTION subsection;

    DPRINT("MiDecrementSubsections: FirstSubsection %p, LastSubsection %p\n", FirstSubsection, LastSubsection);

    ASSERT((FirstSubsection->ControlArea->u.Flags.Image == 0) &&
           (FirstSubsection->ControlArea->FilePointer != NULL) &&
           (FirstSubsection->ControlArea->u.Flags.PhysicalMemory == 0));

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(MmPfnOwner == KeGetCurrentThread());

    for (subsection = FirstSubsection; ; subsection = subsection->NextSubsection)
    {
        MappedSubsection = (PMSUBSECTION)subsection;

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

        if ((LastSubsection && subsection == LastSubsection) ||
            !subsection->NextSubsection)
        {
            break;
        }
    }
}

VOID
NTAPI
MiRemoveMappedView(
    _In_ PEPROCESS Process,
    _In_ PMMVAD Vad)
{
    PETHREAD CurrentThread = PsGetCurrentThread();
    PCONTROL_AREA ControlArea;
    PMMEXTEND_INFO ExtendedInfo;
    PSUBSECTION LastSubsection;
    PSUBSECTION FirstSubsection;
    PVOID UsedAddress;
    PMMPTE Pde;
    PMMPTE Pte;
    PMMPTE LastPte;
    PMMPFN Pfn;
    PFN_NUMBER PdePage;
    KIRQL OldIrql;

    DPRINT("MiRemoveMappedView: Process %p, Vad %p\n", Process, Vad);

    /* Get the control area */
    ControlArea = Vad->ControlArea;

    /* If view of the physical section */
    if (Vad->u.VadFlags.VadType == VadDevicePhysicalMemory)
    {
        if (((PMMVAD_LONG)Vad)->u4.Banked)
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
                MiDecrementPfnShare(Pfn, PdePage);

                /* See if we should delete it */
                if (!MiQueryPageTableReferences(UsedAddress))
                {
                    DPRINT1("MiRemoveMappedView: FIXME\n");
                    ASSERT(FALSE);
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
                ExFreePoolWithTag(ExtendedInfo, 'xCmM');

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
    
                /* Decrease the reference counts */
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
                if (Vad->u.VadFlags.Protection == MM_READWRITE ||
                    Vad->u.VadFlags.Protection == MM_EXECUTE_READWRITE)
                {
                    /* Add a reference */
                    InterlockedDecrement ((volatile PLONG)&ControlArea->WritableUserReferences);
                }

                FirstSubsection = MiLocateSubsection(Vad, Vad->StartingVpn);
                LastSubsection = MiLocateSubsection(Vad, Vad->EndingVpn);

                ASSERT(FirstSubsection != NULL);

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
            MiDeleteVirtualAddresses((Vad->StartingVpn * PAGE_SIZE),
                                     ((Vad->EndingVpn * PAGE_SIZE) | (PAGE_SIZE - 1)),
                                     Vad);
        }

        /* Release the working set */
        MiUnlockProcessWorkingSetUnsafe(Process, CurrentThread);

        /* Lock the PFN database */
        OldIrql = MiLockPfnDb(APC_LEVEL);

        if (FirstSubsection)
            MiDecrementSubsections(FirstSubsection, LastSubsection);
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
MiUnmapViewOfSection(
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress,
    _In_ ULONG Flags)
{
    PETHREAD CurrentThread = PsGetCurrentThread();
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    PMMADDRESS_NODE PreviousNode;
    PMMADDRESS_NODE NextNode;
    PMMVAD Vad;
    PVOID DbgBase = NULL;
    SIZE_T RegionSize;
    ULONG_PTR StartingAddress;
    ULONG_PTR EndingAddress;
    KAPC_STATE ApcState;
    BOOLEAN Attached = FALSE;
    NTSTATUS Status;

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
    if (!(Flags & 0x01))
        MmLockAddressSpace(&Process->Vm);

    /* Check if the process is already daed */
    if (Process->VmDeleted)
    {
        /* Fail the call */
        DPRINT1("MiUnmapViewOfSection: STATUS_PROCESS_IS_TERMINATING\n");

        if (!(Flags & 0x01))
            MmUnlockAddressSpace(&Process->Vm);

        Status = STATUS_PROCESS_IS_TERMINATING;
        goto Exit;
    }

    /* Find the VAD for the address and make sure it's a section VAD */
    Vad = MiLocateAddress(BaseAddress);

    if (!Vad || Vad->u.VadFlags.PrivateMemory)
    {
        /* Couldn't find it, or invalid VAD, fail */
        DPRINT1("MiUnmapViewOfSection: No VAD or invalid VAD\n");

        if (!(Flags & 0x01))
            MmUnlockAddressSpace(&Process->Vm);

        Status = STATUS_NOT_MAPPED_VIEW;
        goto Exit;
    }

    /* We should be attached */
    ASSERT(Process == PsGetCurrentProcess());

    StartingAddress = (Vad->StartingVpn * PAGE_SIZE);
    EndingAddress = ((Vad->EndingVpn * PAGE_SIZE) | 0xFFF);

    /* We need the base address for the debugger message on image-backed VADs */
    if (Vad->u.VadFlags.VadType == VadImageMap)
    {
        DbgBase = (PVOID)StartingAddress;
    }

    /* Compute the size of the VAD region */
    RegionSize = ((Vad->EndingVpn - Vad->StartingVpn + 1) * PAGE_SIZE);

    /* For SEC_NO_CHANGE sections, we need some extra checks */
    if (Vad->u.VadFlags.NoChange)
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

            if (!(Flags & 0x01))
                MmUnlockAddressSpace(&Process->Vm);
 
            goto Exit1;
        }
    }

    PreviousNode = MiGetPreviousNode((PMMADDRESS_NODE)Vad);
    NextNode = MiGetNextNode((PMMADDRESS_NODE)Vad);

    if (Vad->u.VadFlags.VadType != VadRotatePhysical)
    {
        /* Remove VAD charges */
        MiRemoveVadCharges(Vad, Process);

        /* Lock the working set */
        MiLockProcessWorkingSetUnsafe(Process, CurrentThread);
    }
    else
    {
        if (Flags & 0x02)
        {
            /* Remove VAD charges */
            MiRemoveVadCharges(Vad, Process);

            /* Lock the working set */
            MiLockProcessWorkingSetUnsafe(Process, CurrentThread);

            /* Remove Physical View */
            MiPhysicalViewRemover(Process, Vad);
        }
        else
        {
            if (!(Flags & 0x01))
                MmUnlockAddressSpace(&Process->Vm);

            DPRINT1("MiUnmapViewOfSection: STATUS_NOT_MAPPED_VIEW\n");
            Status = STATUS_NOT_MAPPED_VIEW;
            goto Exit1;
        }
    }

    ASSERT(Process == PsGetCurrentProcess());
    ASSERT(Process->VadRoot.NumberGenericTableElements >= 1);

    /* Remove the VAD */
    MiRemoveNode((PMMADDRESS_NODE)Vad, &Process->VadRoot);

    if (Process->VadRoot.NodeHint == Vad)
    {
        Process->VadRoot.NodeHint = Process->VadRoot.BalancedRoot.RightChild;

        if(!Process->VadRoot.NumberGenericTableElements)
            Process->VadRoot.NodeHint = NULL;
    }

    /* Remove the PTEs for this view, which also releases the working set lock */
    MiRemoveMappedView(Process, Vad);

    /* Remove commitment */
    MiReturnPageTablePageCommitment(StartingAddress, EndingAddress, Process, PreviousNode, NextNode);

    /* Update performance counter and release the lock */
    Process->VirtualSize -= RegionSize;

    if (!(Flags & 0x01))
        MmUnlockAddressSpace(&Process->Vm);

    /* Destroy the VAD and return success */
    ExFreePool(Vad);

    Status = STATUS_SUCCESS;

    /* Failure and success case -- send debugger message, detach, and return */

Exit1:

    if (DbgBase)
        DbgkUnMapViewOfSection(DbgBase);

Exit:

    if (Attached)
        KeUnstackDetachProcess(&ApcState);

    return Status;
}

PCONTROL_AREA
NTAPI
MiFindImageSectionObject(
    _In_ PFILE_OBJECT FileObject,
    _In_ BOOLEAN IsLocked,
    _Out_ BOOLEAN* OutIsGlobal)
{
    PLARGE_CONTROL_AREA ControlArea;
    PLIST_ENTRY Header;
    PLIST_ENTRY Entry;
    ULONG SessionId;
    KIRQL OldIrql = PASSIVE_LEVEL;

    DPRINT("MiFindImageSectionObject: FileObject %p\n", FileObject);

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

    ControlArea = FileObject->SectionObjectPointer->ImageSectionObject;
    if (!ControlArea)
        goto Exit;

    if (!ControlArea->u.Flags.GlobalOnlyPerSession)
        goto Exit;

    SessionId = MmGetSessionId(PsGetCurrentProcess());

    if (ControlArea->SessionId == SessionId)
        goto Exit;

    Header = &ControlArea->UserGlobalList;

    for (Entry = ControlArea->UserGlobalList.Flink;
         Entry != Header;
         Entry = Entry->Flink)
    {
        ControlArea = CONTAINING_RECORD(Entry, LARGE_CONTROL_AREA, UserGlobalList);

        ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 1);

        if (ControlArea->SessionId == SessionId)
            goto Exit;
    }

    ControlArea = NULL;
    *OutIsGlobal = TRUE;

Exit:

    if (!IsLocked)
         MiUnlockPfnDb(OldIrql, APC_LEVEL);

    return (PCONTROL_AREA)ControlArea;
}

VOID
NTAPI
MiInsertImageSectionObject(
    _In_ PFILE_OBJECT FileObject,
    _In_ PLARGE_CONTROL_AREA ControlArea)
{
    PLARGE_CONTROL_AREA NextControlArea;
    PLARGE_CONTROL_AREA controlArea;
    PLIST_ENTRY Header;
    PLIST_ENTRY Entry;
    ULONG SessionId;

    DPRINT("MiInsertImageSectionObject: FileObject %p, ControlArea %p\n", FileObject, ControlArea);

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

    controlArea = FileObject->SectionObjectPointer->ImageSectionObject;
    Header = &controlArea->UserGlobalList;

    for (Entry = Header->Flink;
         Entry != Header;
         Entry = Entry->Flink)
    {
        NextControlArea = CONTAINING_RECORD(Entry, LARGE_CONTROL_AREA, UserGlobalList);

        ASSERT(NextControlArea->SessionId != (ULONG)-1 &&
               NextControlArea->SessionId != ControlArea->SessionId);
    }

    InsertTailList(Header, &ControlArea->UserGlobalList);

Exit:

    FileObject->SectionObjectPointer->ImageSectionObject = ControlArea;
}

VOID
NTAPI
MiSubsectionConsistent(
    _In_ PSUBSECTION Subsection)
{
    ULONG NumberOfFullSectors = Subsection->NumberOfFullSectors;

    DPRINT("MiSubsectionConsistent: Subsection %p, NumberOfFullSectors %X\n", Subsection, NumberOfFullSectors);

    if (Subsection->u.SubsectionFlags.SectorEndOffset)
        NumberOfFullSectors++;

    /* Therefore, then number of PTEs should be equal to the number of sectors */
    if (NumberOfFullSectors == Subsection->PtesInSubsection)
        return;

    DPRINT1("MiSubsectionConsistent: Subsection inconsistent (%X vs %X)\n",
            NumberOfFullSectors, Subsection->PtesInSubsection);

    DbgBreakPoint();
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MiCreateDataFileMap(
    _In_ PFILE_OBJECT File,
    _Out_ PSEGMENT* OutSegment,
    _In_ PLARGE_INTEGER InputMaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_ BOOLEAN IgnoreFileSizing)
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
    DPRINT("MiCreateDataFileMap: %p '%wZ', %I64X, %X, %X, %X\n", File, &File->FileName, InputMaximumSize, SectionPageProtection, AllocationAttributes, IgnoreFileSizing);

    if (InputMaximumSize)
    {
         maximum = (ULONGLONG)InputMaximumSize->QuadPart;
         maximumSize = &maximum;
         //DPRINT("MiCreateDataFileMap: maximumSize %I64X\n", maximum);
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
        if (!NT_SUCCESS(Status))
        {
            if (Status == STATUS_FILE_IS_A_DIRECTORY)
            {
                DPRINT1("MiCreateDataFileMap: STATUS_FILE_IS_A_DIRECTORY\n");
                return STATUS_INVALID_FILE_FOR_SECTION;
            }

            DPRINT1("MiCreateDataFileMap: Status %X\n", Status);
            return Status;
        }

        FileSize = (ULONGLONG)fileSize.QuadPart;

        if (!FileSize && !(*maximumSize))
        {
            DPRINT1("MiCreateDataFileMap: STATUS_MAPPED_FILE_SIZE_ZERO\n");
            return STATUS_MAPPED_FILE_SIZE_ZERO;
        }

        //DPRINT("MiCreateDataFileMap: FileSize %I64X\n", FileSize);

        if (*maximumSize > FileSize)
        {
            if (!(SectionPageProtection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
            {
                DPRINT1("MiCreateDataFileMap: STATUS_SECTION_TOO_BIG\n");
                return STATUS_SECTION_TOO_BIG;
            }

            fileSize.QuadPart = (LONGLONG)*maximumSize;

            Status = FsRtlSetFileSize(File, &fileSize);
            if (!NT_SUCCESS(Status))
            {
                DPRINT("MiCreateDataFileMap: Status %X\n", Status);
                return Status;
            }

            FileSize = (ULONGLONG)fileSize.QuadPart;
        }
    }

    if (FileSize >= ((16 * _1PB) - PAGE_SIZE))
    {
        DPRINT1("MiCreateDataFileMap: STATUS_SECTION_TOO_BIG\n");
        return STATUS_SECTION_TOO_BIG;
    }

    TotalNumberOfPtes = ((FileSize + (PAGE_SIZE - 1)) / PAGE_SIZE);

    Segment = ExAllocatePoolWithTag(PagedPool, sizeof(MAPPED_FILE_SEGMENT), 'mSmM');
    if (!Segment)
    {
        DPRINT1("MiCreateDataFileMap: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ASSERT(BYTE_OFFSET(MmAllocationFragment) == 0);
    ASSERT(MmAllocationFragment >= PAGE_SIZE);

    ControlArea = (PCONTROL_AREA)File->SectionObjectPointer->DataSectionObject;

    NumberOfNewSubsections = 0;
    SubsectionSize = MmAllocationFragment;

    NewSubsection = NULL;
    LastSubsection = NULL;

    /* Split file on parts sizeof MmAllocationFragment */
    for (CurrentSize = (TotalNumberOfPtes * sizeof(MMPTE));
         CurrentSize;
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
                     NewSubsection;
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
        /* CC is caller */
        ControlArea->u.Flags.WasPurged = 1;
    else
        ControlArea->NumberOfUserReferences = 1;

    ControlArea->u.Flags.BeingCreated = 1;
    ControlArea->u.Flags.File = 1;

    if (File->DeviceObject->Characteristics & FILE_REMOTE_DEVICE)
        ControlArea->u.Flags.Networked = 1;

    if (AllocationAttributes & SEC_NOCACHE)
        ControlArea->u.Flags.NoCache = 1;

    ControlArea->FilePointer = File;
    ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);

    Subsection = (PMSUBSECTION)&ControlArea[1];

    MI_MAKE_SUBSECTION_PTE(&ProtoTemplate, Subsection);
    ProtoTemplate.u.Soft.Prototype = 1;
    ProtoTemplate.u.Soft.Protection = MM_EXECUTE_READWRITE;
    Segment->SegmentPteTemplate = ProtoTemplate;

    Segment->ControlArea = ControlArea;
    Segment->SizeOfSegment = FileSize;
    Segment->TotalNumberOfPtes = (ULONG)TotalNumberOfPtes;

    DPRINT("MiCreateDataFileMap: Segment->SizeOfSegment %I64X\n", Segment->SizeOfSegment);

    if (TotalNumberOfPtes >= (1ull << 32))
        Segment->SegmentFlags.TotalNumberOfPtes4132 = (TotalNumberOfPtes >> 32);

    if (Subsection->NextSubsection)
        Segment->NonExtendedPtes = (Subsection->PtesInSubsection & ~(((ULONG)MmAllocationFragment / PAGE_SIZE) - 1));
    else
        Segment->NonExtendedPtes = Segment->TotalNumberOfPtes;

    Subsection->PtesInSubsection = Segment->NonExtendedPtes;

    CurrentPtes = 0;

    for (; Subsection; Subsection = (PMSUBSECTION)Subsection->NextSubsection)
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

BOOLEAN
NTAPI
MiCheckProtoPtePageState(
    _In_ PMMPTE SectionProto,
    _In_ KIRQL OldIrql,
    _Out_ BOOLEAN* OutIsLock)
{
    PMMPTE ProtoPte;
    MMPTE TempPte;
    PMMPFN Pfn;

    DPRINT("MiCheckProtoPtePageState: SectionProto %p, OldIrql %X\n", SectionProto, OldIrql);

    *OutIsLock = FALSE;

    ProtoPte = MiAddressToPte(SectionProto);

    if (!ProtoPte->u.Hard.Valid)
        MiCheckPdeForPagedPool(SectionProto);

    TempPte.u.Long = ProtoPte->u.Long;

    if (TempPte.u.Hard.Valid)
    {
        Pfn = MI_PFN_ELEMENT(TempPte.u.Hard.PageFrameNumber);

        if (Pfn->u2.ShareCount == 1)
            return FALSE;

        return TRUE;
    }

    if (TempPte.u.Soft.Prototype || TempPte.u.Soft.Transition)
        return FALSE;

    Pfn = MI_PFN_ELEMENT(TempPte.u.Trans.PageFrameNumber);

    if (Pfn->u3.e1.PageLocation < ActiveAndValid)
        return FALSE;

    if (OldIrql != MM_NOIRQL)
    {
        MiMakeSystemAddressValidPfn(SectionProto, OldIrql);
        *OutIsLock = TRUE;
    }

    return TRUE;
}

BOOLEAN
NTAPI
MiReferenceSubsection(
    _In_ PMSUBSECTION MappedSubsection)
{
    DPRINT("MiReferenceSubsection: %p, %p\n", MappedSubsection, MappedSubsection->SubsectionBase);

    ASSERT((MappedSubsection->ControlArea->u.Flags.Image == 0) &&
           (MappedSubsection->ControlArea->FilePointer != NULL) &&
           (MappedSubsection->ControlArea->u.Flags.PhysicalMemory == 0));

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(MmPfnOwner == KeGetCurrentThread());

    if (!MappedSubsection->SubsectionBase)
        return FALSE;

    MappedSubsection->NumberOfMappedViews++;

    if (!MappedSubsection->DereferenceList.Flink)
        goto Exit;

    RemoveEntryList(&MappedSubsection->DereferenceList);
    AlloccatePoolForSubsectionPtes(MappedSubsection->PtesInSubsection + MappedSubsection->UnusedPtes);

    MappedSubsection->DereferenceList.Flink = NULL;

Exit:

    MappedSubsection->u2.SubsectionFlags2.SubsectionAccessed = 1;
    return TRUE;
}

NTSTATUS
NTAPI 
MiFlushSectionInternal(
    _In_ PMMPTE StartPte,
    _In_ PMMPTE EndPte,
    _In_ PSUBSECTION StartSubsection,
    _In_ PSUBSECTION LastSubsection,
    _In_ ULONG Flags,
    _Out_ IO_STATUS_BLOCK* OutIoStatus)
{
    PFN_NUMBER MdlBuffer[(sizeof(MDL) / sizeof(PFN_NUMBER)) + 17];
    PMDL Mdl = (PMDL)MdlBuffer;
    PCONTROL_AREA ControlArea;
    PFILE_OBJECT FilePointer;
    PSUBSECTION subsection;
    PMSUBSECTION MappedSubsection;
    PVOID FlushData = NULL;
    PPFN_NUMBER MdlPage;
    PPFN_NUMBER LastMdlPage;
    PMMPTE Pte;
    PMMPTE LastPte;
    PMMPTE FirstWrittenPte;
    PMMPTE LastWrittenPte;
    MMPTE TempPte;
    PMMPFN Pfn;
    KEVENT event;
    LARGE_INTEGER StartOffset;
    LARGE_INTEGER EndOffset;
    PFN_NUMBER PageNumber;
    ULONG ClusterSize;
    ULONG RetryCount;
    BOOLEAN IsSingleFlush;
    BOOLEAN IsLocked;
    BOOLEAN IsAlowWrite;
    BOOLEAN IsWriteInProgress;
    BOOLEAN IsDereferenceSegment = FALSE;
    KIRQL OldIrql;
    NTSTATUS Status;

    DPRINT("MiFlushSectionInternal: Ptes %p:%p, Subsections %X:%X, Flags %X\n",
           StartPte, EndPte, StartSubsection, LastSubsection, Flags);

    if (Flags & 0x4)
        IsSingleFlush = FALSE;
    else
        IsSingleFlush = TRUE;

    if (Flags & 0x8)
    {
        DPRINT1("MiFlushSectionInternal: FIXME\n");
        ASSERT(FALSE);
        //FlushData = ExAllocatePoolWithTag();
    }

    if (Flags & 0x80000000)
    {
        IsDereferenceSegment = TRUE;

        DPRINT1("MiFlushSectionInternal: FIXME\n");
        ASSERT(FALSE);
    }

    EndPte++;

    while (TRUE)
    {
        IsAlowWrite = FALSE;
        IsWriteInProgress = FALSE;

        OutIoStatus->Status = STATUS_SUCCESS;
        OutIoStatus->Information = 0;

        if (!FlushData)
        {
            KeInitializeEvent(&event, NotificationEvent, FALSE);
        }
        else
        {
            DPRINT1("MiFlushSectionInternal: FIXME\n");
            ASSERT(FALSE);
        }

        ControlArea = StartSubsection->ControlArea;
        FilePointer = ControlArea->FilePointer;

        subsection = StartSubsection;
        MappedSubsection = NULL;

        Pte = StartPte;

        FirstWrittenPte = NULL;
        LastWrittenPte = NULL;

        StartOffset.QuadPart = 0;
        LastMdlPage = NULL;

        ClusterSize = 0x10; // MmModifiedWriteClusterSize;

        ASSERT((ControlArea->u.Flags.Image == 0) &&
               (FilePointer != NULL) &&
               (ControlArea->u.Flags.PhysicalMemory == 0));

        OldIrql = MiLockPfnDb(APC_LEVEL);

        ASSERT(ControlArea->u.Flags.Image == 0);

        if (!ControlArea->NumberOfPfnReferences)
        {
            MiUnlockPfnDb(OldIrql, APC_LEVEL);

            if (FlushData)
                ExFreePool(FlushData);

            return STATUS_SUCCESS;
        }

        while (IsSingleFlush && ControlArea->FlushInProgressCount)
        {
            ControlArea->u.Flags.CollidedFlush = 1;

            MiUnlockPfnWithWait(APC_LEVEL);
            KeWaitForSingleObject(&MmCollidedFlushEvent, WrPageOut, KernelMode, FALSE, &MmOneSecond);
            KeLowerIrql(OldIrql);
            OldIrql = MiLockPfnDb(APC_LEVEL);
        }

        ControlArea->FlushInProgressCount++;

        while (TRUE)
        {
            if (LastSubsection != subsection)
                LastPte = &subsection->SubsectionBase[subsection->PtesInSubsection];
            else
                LastPte = EndPte;

            if (!subsection->SubsectionBase)
            {
                if (LastWrittenPte)
                {
                    ASSERT(MappedSubsection != NULL);

                    IsAlowWrite = TRUE;
                    goto StartFlush;
                }

                if (LastSubsection == subsection)
                    break;

                subsection = subsection->NextSubsection;
                Pte = subsection->SubsectionBase;

                continue;
            }

            MappedSubsection = (PMSUBSECTION)subsection;
            MappedSubsection->NumberOfMappedViews++;

            if (MappedSubsection->DereferenceList.Flink)
            {
                RemoveEntryList(&MappedSubsection->DereferenceList);
                AlloccatePoolForSubsectionPtes(MappedSubsection->PtesInSubsection + MappedSubsection->UnusedPtes);
                MappedSubsection->DereferenceList.Flink = NULL;
            }

            if (!IsDereferenceSegment)
                MappedSubsection->u2.SubsectionFlags2.SubsectionAccessed = 1;

            if (!MiCheckProtoPtePageState(Pte, OldIrql, &IsLocked))
                Pte = (PMMPTE)(((ULONG_PTR)Pte | (PAGE_SIZE - 1)) + 1);

            while (Pte < LastPte)
            {
                if (MiIsPteOnPdeBoundary(Pte) &&
                    !MiCheckProtoPtePageState(Pte, OldIrql, &IsLocked))
                {
                    Pte = Add2Ptr(Pte, PAGE_SIZE);

                    if (LastWrittenPte)
                    {
                        IsAlowWrite = TRUE;
                        goto StartFlush;
                    }

                    continue;
                }

                TempPte = *Pte;
                //DPRINT("MiFlushSectionInternal: Pte %p [%p], LastPte %p\n", Pte, TempPte, LastPte);

                if (TempPte.u.Hard.Valid ||
                    (!TempPte.u.Soft.Prototype && TempPte.u.Soft.Transition))
                {
                    PageNumber = TempPte.u.Hard.PageFrameNumber;
                    Pfn = MI_PFN_ELEMENT(PageNumber);

                    ASSERT(Pfn->OriginalPte.u.Soft.Prototype == 1);
                    ASSERT(Pfn->OriginalPte.u.Hard.Valid == 0);

                    if (IsDereferenceSegment && Pfn->u3.e2.ReferenceCount)
                    {
                        DPRINT1("MiFlushSectionInternal: FIXME\n");
                        ASSERT(FALSE);

                        if (TempPte.u.Hard.Valid &&
                            !MappedSubsection->u2.SubsectionFlags2.SubsectionAccessed &&
                            !ControlArea->u.Flags.Accessed)
                        {
                            DbgPrintEx(DPFLTR_MM_ID, DPFLTR_ERROR_LEVEL, "MM: flushing valid proto, %p %p\n", Pfn, Pte);
                            ASSERT(FALSE);
                        }

                        Pte = LastPte;
                        IsWriteInProgress = TRUE;

                        if (LastWrittenPte)
                            IsAlowWrite = TRUE;

                        goto StartFlush;
                    }

                    if (Pfn->u3.e1.Modified || Pfn->u3.e1.WriteInProgress)
                    {
                        if ((Flags & 0x2) && Pfn->u3.e1.WriteInProgress)
                        {
                            DPRINT1("MiFlushSectionInternal: FIXME\n");
                            ASSERT(FALSE);
                        }

                        if (!LastWrittenPte)
                        {
                            LastMdlPage = MmGetMdlPfnArray(Mdl);

                            ASSERT(subsection->SubsectionBase != NULL);
                            StartOffset.QuadPart = ((Pfn->PteAddress - subsection->SubsectionBase) * PAGE_SIZE);

                            if (subsection->ControlArea->u.Flags.Image)
                            {
                                StartOffset.QuadPart += (subsection->StartingSector * MM_SECTOR_SIZE);
                            }
                            else
                            {
                                LARGE_INTEGER TmpSize;

                                TmpSize.LowPart = subsection->StartingSector;
                                TmpSize.HighPart = subsection->u.SubsectionFlags.StartingSector4132;

                                StartOffset.QuadPart += (TmpSize.QuadPart * PAGE_SIZE);
                            }

                            Mdl->Next = NULL;
                            Mdl->Size = (sizeof(MDL) + (sizeof(PFN_NUMBER) * ClusterSize));
                            Mdl->MdlFlags = MDL_PAGES_LOCKED;
                            Mdl->StartVa = ULongToPtr(Pfn->u3.e1.PageColor * PAGE_SIZE);
                            Mdl->ByteCount = 0;
                            Mdl->ByteOffset = 0;

                            FirstWrittenPte = Pte;
                        }

                        LastWrittenPte = Pte;
                        Mdl->ByteCount += PAGE_SIZE;

                        if (Mdl->ByteCount == (ClusterSize * PAGE_SIZE))
                            IsAlowWrite = TRUE;

                        if (!TempPte.u.Hard.Valid)
                        {
                            MiUnlinkPageFromList(Pfn);
                            MiReferenceUnusedPageAndBumpLockCount(Pfn);
                        }
                        else
                        {
                            MiReferenceUsedPageAndBumpLockCount(Pfn);
                        }

                        ASSERT(Pfn->u3.e1.Rom == 0);
                        Pfn->u3.e1.Modified = 0;

                        *LastMdlPage = PageNumber;
                        LastMdlPage++;
                    }
                    else if (LastWrittenPte)
                    {
                        IsAlowWrite = TRUE;
                    }
                }
                else if (LastWrittenPte)
                {
                    IsAlowWrite = TRUE;
                }

                Pte++;
StartFlush:
                if (!IsAlowWrite && (Pte != LastPte || !LastWrittenPte))
                    continue;

                DPRINT("MiFlushSectionInternal: IsAlowWrite %X, LastWrittenPte %X\n", IsAlowWrite, LastWrittenPte);

                MiUnlockPfnDb(OldIrql, APC_LEVEL);

                IsAlowWrite = FALSE;

                if (subsection->ControlArea->u.Flags.Image)
                {
                    EndOffset.QuadPart = (subsection->StartingSector + subsection->NumberOfFullSectors);
                    EndOffset.QuadPart *= MM_SECTOR_SIZE;
                }
                else
                {
                    EndOffset.LowPart = subsection->StartingSector;
                    EndOffset.HighPart = subsection->u.SubsectionFlags.StartingSector4132;

                    EndOffset.QuadPart += subsection->NumberOfFullSectors;
                    EndOffset.QuadPart *= PAGE_SIZE;
                }

                EndOffset.QuadPart += subsection->u.SubsectionFlags.SectorEndOffset;

                if (EndOffset.QuadPart < (StartOffset.QuadPart + Mdl->ByteCount))
                {
                    ASSERT((ULONG_PTR)(EndOffset.QuadPart - StartOffset.QuadPart) > (Mdl->ByteCount - PAGE_SIZE));
                    Mdl->ByteCount = (EndOffset.QuadPart - StartOffset.QuadPart);
                }

                RetryCount = 0;

                if (!FlushData)
                {
                    while (TRUE)
                    {
                        KeClearEvent(&event);

                        Status = IoSynchronousPageWrite(FilePointer, Mdl, &StartOffset, &event, OutIoStatus);

                        if (!NT_SUCCESS(Status))
                        {
                            DPRINT1("MiFlushSectionInternal: Status %X\n", Status);
                            OutIoStatus->Status = Status;
                        }
                        else
                        {
                            KeWaitForSingleObject(&event, WrPageOut, KernelMode, FALSE, NULL);
                        }

                        if (Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA)
                            MmUnmapLockedPages(Mdl->MappedSystemVa, Mdl);

                        if (OutIoStatus->Status != STATUS_INSUFFICIENT_RESOURCES &&
                            OutIoStatus->Status != STATUS_WORKING_SET_QUOTA &&
                            OutIoStatus->Status != STATUS_NO_MEMORY)
                        {
                            break;
                        }

                        RetryCount--;

                        if (!(RetryCount & 0x1F))
                            break;

                        KeDelayExecutionThread(KernelMode, FALSE, &Mm30Milliseconds);
                    }

                    MdlPage = MmGetMdlPfnArray(Mdl);

                    OldIrql = MiLockPfnDb(APC_LEVEL);

                    if (!MiIsPteOnPdeBoundary(Pte) && !(MiAddressToPte(Pte)->u.Hard.Valid))
                        MiMakeSystemAddressValidPfn(Pte, OldIrql);

                    if (!NT_SUCCESS(OutIoStatus->Status))
                    {
                        NTSTATUS sts = OutIoStatus->Status;
                        PMMPFN pfn;

                        DPRINT1("MiFlushSectionInternal: OutIoStatus->Status %X\n", sts);

                        OutIoStatus->Information = 0;

                        while (MdlPage < LastMdlPage)
                        {
                            pfn = MI_PFN_ELEMENT(*MdlPage);

                            ASSERT(pfn->u3.e1.Rom == 0);
                            pfn->u3.e1.Modified = 1;

                            MiDereferencePfnAndDropLockCount(pfn);
                            MdlPage++;
                        }

                        if ((sts != STATUS_INSUFFICIENT_RESOURCES && sts != STATUS_WORKING_SET_QUOTA && sts != STATUS_NO_MEMORY) ||
                            ClusterSize == 1 ||
                            Mdl->ByteCount <= PAGE_SIZE)
                        {
                            OutIoStatus->Information += (((LastWrittenPte - StartPte) * PAGE_SIZE) - Mdl->ByteCount);
                            LastWrittenPte = NULL;
                            subsection = LastSubsection;
                            break;
                        }

                        ASSERT(FirstWrittenPte != NULL);
                        ASSERT(LastWrittenPte != NULL);
                        ASSERT(FirstWrittenPte != LastWrittenPte);

                        Pte = FirstWrittenPte;

                        if (!(MiAddressToPte(Pte)->u.Hard.Valid))
                            MiMakeSystemAddressValidPfn(Pte, OldIrql);

                        ClusterSize = 1;
                    }
                    else
                    {
                        for (; MdlPage < LastMdlPage; MdlPage++)
                            MiDereferencePfnAndDropLockCount(MI_PFN_ELEMENT(*MdlPage));
                    }
                }
                else
                {
                    DPRINT1("MiFlushSectionInternal: FIXME\n");
                    ASSERT(FALSE);
                }

                LastWrittenPte = NULL;
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

            if (IsWriteInProgress || subsection == LastSubsection)
                break;

            subsection = subsection->NextSubsection;
            Pte = subsection->SubsectionBase;
        }

        ASSERT(LastWrittenPte == NULL);

        ControlArea->FlushInProgressCount--;

        if (ControlArea->u.Flags.CollidedFlush && !ControlArea->FlushInProgressCount)
        {
            ControlArea->u.Flags.CollidedFlush = 0;
            KePulseEvent(&MmCollidedFlushEvent, 0, FALSE);
        }

        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        if (!FlushData)
        {
            if (IsWriteInProgress)
                OutIoStatus->Status = 0xC0000433;

            return OutIoStatus->Status;
        }

        DPRINT1("MiFlushSectionInternal: FIXME\n");
        ASSERT(FALSE);
    }

    DPRINT("MiFlushSectionInternal: Mdl %X\n", Mdl);

    DPRINT1("MiFlushSectionInternal: FIXME\n");
    ASSERT(FALSE);

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI 
MmFlushSection(
    _In_ PSECTION_OBJECT_POINTERS SectionPointers,
    _In_ PLARGE_INTEGER FileOffset,
    _In_ ULONG Length,
    _Out_ IO_STATUS_BLOCK* OutIoStatus,
    _In_ ULONG Flags)
{
    PMAPPED_FILE_SEGMENT Segment;
    PCONTROL_AREA ControlArea;
    PSUBSECTION Subsection;
    PSUBSECTION LastSubsection;
    PSUBSECTION TempSubsection;
    PSUBSECTION LastTempSubsection;
    PMMPTE SectionProto;
    PMMPTE LastProto;
    PETHREAD Thread;
    UINT64 PteOffset;
    UINT64 LastPteOffset;
    LARGE_INTEGER fileOffset;
    ULONG ix;
    UCHAR OldForwardClusterOnly;
    KIRQL OldIrql;
    NTSTATUS Status;

    DPRINT("MmFlushSection: %p, %I64X, %X, %X\n",
           SectionPointers, (FileOffset ? FileOffset->QuadPart : 0), Length, Flags);

    if (FileOffset)
    {
        fileOffset = *FileOffset;
        FileOffset = &fileOffset;
    }

    OutIoStatus->Status = STATUS_SUCCESS;
    OutIoStatus->Information = Length;

    OldIrql = MiLockPfnDb(APC_LEVEL);

    ControlArea = SectionPointers->DataSectionObject;
    ASSERT((ControlArea == NULL) || (ControlArea->u.Flags.Image == 0));

    if (!ControlArea)
    {
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        return STATUS_SUCCESS;
    }

    if (ControlArea->u.Flags.BeingDeleted ||
        ControlArea->u.Flags.BeingCreated ||
        ControlArea->u.Flags.Rom)
    {
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        return STATUS_SUCCESS;
    }

    if (!ControlArea->NumberOfPfnReferences)
    {
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        return STATUS_SUCCESS;
    }

    ASSERT(ControlArea->u.Flags.Image == 0);
    ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);
    ASSERT(ControlArea->u.Flags.PhysicalMemory == 0);

    Subsection = (PSUBSECTION)&ControlArea[1];

    if (FileOffset)
    {
        PteOffset = (UINT64)(FileOffset->QuadPart / PAGE_SIZE);

        while (PteOffset >= (UINT64)Subsection->PtesInSubsection)
        {
            PteOffset -= Subsection->PtesInSubsection;

            if (!Subsection->NextSubsection)
            {
                MiUnlockPfnDb(OldIrql, APC_LEVEL);
                return STATUS_SUCCESS;
            }

            Subsection = Subsection->NextSubsection;
        }

        ASSERT(PteOffset < (UINT64)Subsection->PtesInSubsection);

        LastPteOffset = (PteOffset + (((Length + BYTE_OFFSET(FileOffset->LowPart)) - 1) / PAGE_SIZE));
        LastSubsection = Subsection;

        while (LastPteOffset >= (UINT64)LastSubsection->PtesInSubsection)
        {
            LastPteOffset -= LastSubsection->PtesInSubsection;

            if (!LastSubsection->NextSubsection)
            {
                LastPteOffset = (LastSubsection->PtesInSubsection - 1);
                break;
            }

            LastSubsection = LastSubsection->NextSubsection;
        }

        ASSERT(LastPteOffset < LastSubsection->PtesInSubsection);
    }
    else
    {
        ASSERT(ControlArea->FilePointer != NULL);

        PteOffset = 0;
        LastSubsection = Subsection;

        Segment = (PMAPPED_FILE_SEGMENT)ControlArea->Segment;

        if (MiIsAddressValid(Segment) && Segment->LastSubsectionHint)
            LastSubsection = (PSUBSECTION)Segment->LastSubsectionHint;

        while (LastSubsection->NextSubsection)
            LastSubsection = LastSubsection->NextSubsection;

        LastPteOffset = (LastSubsection->PtesInSubsection - 1);
    }

    if (!MiReferenceSubsection((PMSUBSECTION)Subsection))
    {
        DPRINT1("MmFlushSection: FIXME\n");
        ASSERT(FALSE);
    }
    else
    {
        SectionProto = &Subsection->SubsectionBase[PteOffset];
        DPRINT("MmFlushSection: SectionProto %p\n", SectionProto);
    }

    ASSERT(Subsection->SubsectionBase != NULL);

    if (!MiReferenceSubsection((PMSUBSECTION)LastSubsection))
    {
        ASSERT(Subsection != LastSubsection);

        TempSubsection = Subsection->NextSubsection;
        LastTempSubsection = NULL;

        while (TempSubsection != LastSubsection)
        {
            ASSERT(TempSubsection != NULL);

            if ((PMSUBSECTION)TempSubsection->SubsectionBase)
                LastTempSubsection = TempSubsection;

            TempSubsection = TempSubsection->NextSubsection;
        }

        if (!LastTempSubsection)
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
            DPRINT1("MmFlushSection: FIXME\n");
            ASSERT(FALSE);
        }

        ASSERT(TempSubsection->SubsectionBase != NULL);

        LastSubsection = TempSubsection;
        LastPteOffset = (LastSubsection->PtesInSubsection - 1);
    }

    ControlArea->NumberOfMappedViews++;

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    Thread = PsGetCurrentThread();
    OldForwardClusterOnly = Thread->ForwardClusterOnly;
    Thread->ForwardClusterOnly = 1;

    LastProto = &LastSubsection->SubsectionBase[LastPteOffset];

    if (Flags & 1)
    {
        for (ix = 0; ix < 5; ix++)
        {
            Status = FsRtlAcquireFileForCcFlushEx(ControlArea->FilePointer);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("MmFlushSection: Status %X\n", Status);
                break;
            }

            Status = MiFlushSectionInternal(SectionProto, LastProto, Subsection, LastSubsection, Flags, OutIoStatus);

            FsRtlReleaseFileForCcFlush(ControlArea->FilePointer);

            if (Status != STATUS_FILE_LOCK_CONFLICT)
                break;

            KeDelayExecutionThread(KernelMode, FALSE, &MmShortTime);
        }
    }
    else
    {
        Status = MiFlushSectionInternal(SectionProto, LastProto, Subsection, LastSubsection, Flags, OutIoStatus);
    }

    Thread->ForwardClusterOnly = OldForwardClusterOnly;

    OldIrql = MiLockPfnDb(APC_LEVEL);

    MiDecrementSubsections(Subsection, Subsection);
    MiDecrementSubsections(LastSubsection, LastSubsection);

    ASSERT((LONG)ControlArea->NumberOfMappedViews >= 1);
    ControlArea->NumberOfMappedViews--;

    MiCheckControlArea(ControlArea, OldIrql);

    return Status;
}

BOOLEAN
NTAPI
MiFlushDataSection(
    _In_ PFILE_OBJECT FileObject)
{
    PCONTROL_AREA ControlArea;
    IO_STATUS_BLOCK IoStatusBlock;
    BOOLEAN IsDataSectionUsed;
    KIRQL OldIrql;

    DPRINT("MiFlushDataSection: FileObject %p\n", FileObject);

    OldIrql = MiLockPfnDb(APC_LEVEL);

    ControlArea = FileObject->SectionObjectPointer->DataSectionObject;
    if (!ControlArea)
    {
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        return FALSE;
    }

    if (ControlArea->NumberOfSectionReferences || ControlArea->NumberOfMappedViews)
        IsDataSectionUsed = TRUE;
    else
        IsDataSectionUsed = FALSE;

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    if (ControlArea->NumberOfSystemCacheViews)
        CcFlushCache(FileObject->SectionObjectPointer, NULL, 0, &IoStatusBlock);
    else
        MmFlushSection(FileObject->SectionObjectPointer, NULL, 0, &IoStatusBlock, 1);

    if (IsDataSectionUsed)
    {
        if (FileObject->FileName.Length > 4 && KeGetCurrentIrql() <= APC_LEVEL)
        {
            DPRINT1("MiFlushDataSection: %p '%wZ', %p (%X, %X)\n", FileObject, &FileObject->FileName, ControlArea, ControlArea->NumberOfSectionReferences, ControlArea->NumberOfMappedViews);
        }
        else
        {
            DPRINT1("MiFlushDataSection: %p, %p (%X, %X)\n", FileObject, ControlArea, ControlArea->NumberOfSectionReferences, ControlArea->NumberOfMappedViews);
        }
    }

    return IsDataSectionUsed;
}

PFN_NUMBER
NTAPI
MiGetPageForHeader(
    _In_ BOOLEAN IsZeroPage)
{
    PFN_NUMBER PageNumber;
    PMMPFN PeHeaderPfn;
    ULONG Color;
    BOOLEAN IsFlush = FALSE;
    KIRQL OldIrql;

    DPRINT("MiGetPageForHeader: IsZeroPage %X\n", IsZeroPage);

    Color = MI_GET_NEXT_PROCESS_COLOR(PsGetCurrentProcess());

    OldIrql = MiLockPfnDb(APC_LEVEL);

    if (MmAvailablePages < 0x80)
        MiEnsureAvailablePageOrWait(NULL, OldIrql);

    if (IsZeroPage)
        PageNumber = MiRemoveZeroPage(Color);
    else
        PageNumber = MiRemoveAnyPage(Color);

    PeHeaderPfn = &MmPfnDatabase[PageNumber];
    PeHeaderPfn->u3.ReferenceCount++;

    if (PeHeaderPfn->u3.e1.CacheAttribute != MiCached)
    {
        PeHeaderPfn->u3.e1.CacheAttribute = MiCached;
        IsFlush = TRUE;
    }

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    ASSERT(PeHeaderPfn->u1.Flink == 0);
    ASSERT(PeHeaderPfn->u2.Blink == 0);

    PeHeaderPfn->OriginalPte.u.Long = 0;
    PeHeaderPfn->PteAddress = (PMMPTE)0x10001;

    if (IsFlush)
        KeFlushEntireTb(TRUE, TRUE);

    return PageNumber;
}

PVOID
NTAPI
MiCopyHeaderIfResident(
    _In_ PFILE_OBJECT FileObject,
    _In_ PFN_NUMBER PageNumber)
{
    PSECTION_OBJECT_POINTERS SectionPointers;
    PCONTROL_AREA ControlArea;
    PSUBSECTION Subsection;
    PEPROCESS Process;
    PVOID ImageHeader;
    PMMPTE ImagePte;
    PMMPTE BasePte;
    PMMPDE Pde;
    MMPTE PteContents;
    PFN_NUMBER PageFrameIndex;
    KIRQL OldIrql;

    DPRINT("MiCopyHeaderIfResident: FileObject %p, PageNumber %X\n", FileObject, PageNumber);

    SectionPointers = FileObject->SectionObjectPointer;
  
    if (!SectionPointers)
        return NULL;

    if (!SectionPointers->DataSectionObject)
        return NULL;

    ImagePte = MiReserveSystemPtes(1, SystemPteSpace);
    if (!ImagePte)
        return NULL;

    ImageHeader = MiPteToAddress(ImagePte);
    ASSERT(ImagePte->u.Hard.Valid == 0);

    PteContents = ValidKernelPte;
    PteContents.u.Hard.PageFrameNumber = PageNumber;

    MI_WRITE_VALID_PTE(ImagePte, PteContents);

    OldIrql = MiLockPfnDb(APC_LEVEL);

    SectionPointers = FileObject->SectionObjectPointer;
    if (!SectionPointers)
        goto ErrorExit;

    ControlArea = SectionPointers->DataSectionObject;
    if (!ControlArea)
        goto ErrorExit;

    if (ControlArea->u.Flags.BeingCreated || ControlArea->u.Flags.BeingDeleted)
        goto ErrorExit;

    if (ControlArea->u.Flags.Rom)
        Subsection = (PSUBSECTION)((PLARGE_CONTROL_AREA)ControlArea + 1);
    else
        Subsection = (PSUBSECTION)(ControlArea + 1);

    BasePte = Subsection->SubsectionBase;
    if (!BasePte)
        goto ErrorExit;

    Pde = MiAddressToPte(BasePte);
    if (!Pde->u.Hard.Valid)
        goto ErrorExit;

    PteContents.u.Long = BasePte->u.Long;

    if (!PteContents.u.Hard.Valid &&
        (PteContents.u.Soft.Prototype || !PteContents.u.Soft.Transition))
    {
        goto ErrorExit;
    }

    if (!PteContents.u.Hard.Valid)
    {
        PageFrameIndex = PteContents.u.Trans.PageFrameNumber;

        if (MI_PFN_ELEMENT(PageFrameIndex)->u3.e1.ReadInProgress)
            goto ErrorExit;
    }
    else
    {
        PageFrameIndex = PteContents.u.Hard.PageFrameNumber;
    }

    Process = PsGetCurrentProcess();
    ImagePte = MiMapPageInHyperSpaceAtDpc(Process, PageFrameIndex);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    RtlCopyMemory(ImageHeader, ImagePte, PAGE_SIZE);

    MiUnmapPageInHyperSpaceFromDpc(Process, ImagePte);

    MiUnlockPfnDb(OldIrql, APC_LEVEL);
    return ImageHeader;

ErrorExit:

    MiUnlockPfnDb(OldIrql, APC_LEVEL);
    MiReleaseSystemPtes(ImagePte, 1, SystemPteSpace);

    return NULL;
}

NTSTATUS
NTAPI
MiReadPeHeader(
    _In_ PFILE_OBJECT FileObject,
    _In_ PKEVENT Event,
    _In_ PMI_PE_HEADER_MDL HeaderMdl,
    _Out_ ULONGLONG* OutFileSize,
    _Out_ BOOLEAN* OutIsDataSectionUsed,
    _Out_ PVOID* OutPeHeader,
    _Out_ ULONG* OutPeHeaderSize,
    _Out_ PIMAGE_DOS_HEADER* OutDosHeader,
    _Out_ PIMAGE_NT_HEADERS* OutNtHeader,
    _Out_ ULONG* OutNtHeaderSize)
{
    PMMPFN PeHeaderPfn;
    PPFN_NUMBER MdlPages;
    PVOID PeHeader;
    PMMPTE BasePte = NULL;
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER Offset = {{0, 0}};
    LARGE_INTEGER fileSize;
    ULONGLONG FileSize;
    PFN_NUMBER PageFrameNumber;
    MMPTE TempPte;
    ULONG PeHeaderSize;
    NTSTATUS Status;

    DPRINT("MiReadPeHeader: FileObject %p\n", FileObject);

    /* Retrieve the file size for a file */
    Status = FsRtlGetFileSize(FileObject, &fileSize);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MiReadPeHeader: Status %X, File '%wZ'\n", Status, &FileObject->FileName);

        if (Status != STATUS_FILE_IS_A_DIRECTORY)
        {
            ASSERT(FALSE);
            return Status;
        }

        DPRINT1("MiReadPeHeader: STATUS_INVALID_FILE_FOR_SECTION\n");
        ASSERT(FALSE);
        return STATUS_INVALID_FILE_FOR_SECTION;
    }

    if (fileSize.HighPart)
    {
        DPRINT1("MiReadPeHeader: File '%wZ'\n", &FileObject->FileName);
        ASSERT(FALSE);

        DPRINT1("MiReadPeHeader: STATUS_INVALID_FILE_FOR_SECTION\n");
        return STATUS_INVALID_FILE_FOR_SECTION;
    }

    FileSize = (ULONGLONG)fileSize.QuadPart;

    *OutFileSize = FileSize;

    /* Initialize MDL to read the first page of the PE header */
    MmInitializeMdl(&HeaderMdl->Mdl, NULL, PAGE_SIZE);
    HeaderMdl->Mdl.MdlFlags |= MDL_PAGES_LOCKED;

    /* Allocate one zero page for the first page of the PE header */
    PageFrameNumber = MiGetPageForHeader(TRUE);
    ASSERT(PageFrameNumber != 0);

    PeHeaderPfn = &MmPfnDatabase[PageFrameNumber];
    ASSERT(PeHeaderPfn->u1.Flink == 0);

    /* Setup Mdl */
    MdlPages = MmGetMdlPfnArray(&HeaderMdl->Mdl);
    MdlPages[0] = PageFrameNumber;

    CcZeroEndOfLastPage(FileObject);

    *OutIsDataSectionUsed = MiFlushDataSection(FileObject);

    PeHeader = MiCopyHeaderIfResident(FileObject, PageFrameNumber);

    /* Is the header resident in memory? */
    if (PeHeader)
    {
        PeHeaderSize = PAGE_SIZE;
        IoStatusBlock.Information = PAGE_SIZE;
        BasePte = MiAddressToPte(PeHeader);
    }
    else
    {
        ASSERT(HeaderMdl->Mdl.MdlFlags & MDL_PAGES_LOCKED);

        /* Read the first page of the PE header */
        Status = IoPageRead(FileObject, &HeaderMdl->Mdl, &Offset, Event, &IoStatusBlock);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject (Event, WrPageIn, KernelMode, FALSE, NULL);
            Status = IoStatusBlock.Status;
        }

        if (HeaderMdl->Mdl.MdlFlags & MDL_MAPPED_TO_SYSTEM_VA)
        {
            MmUnmapLockedPages(HeaderMdl->Mdl.MappedSystemVa, &HeaderMdl->Mdl);
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("MiReadPeHeader: Status %X, File '%wZ'\n", Status, &FileObject->FileName);

            if (Status != STATUS_FILE_LOCK_CONFLICT &&
                Status != STATUS_FILE_IS_OFFLINE)
            {
                Status = STATUS_INVALID_FILE_FOR_SECTION;
            }

            goto Exit;
        }

        /* Allocate one system PTE for the first page of the PE header */
        BasePte = MiReserveSystemPtes(1, SystemPteSpace);
        if (!BasePte)
        {
            DPRINT1("MiReadPeHeader: Status %X, File '%wZ'\n", Status, &FileObject->FileName);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        ASSERT(BasePte->u.Hard.Valid == 0);

        /* Calculate Va for this system PTE */
        PeHeader = MiPteToAddress(BasePte);

        /* Fill tmp PTE with ValidKernelPte contents */
        TempPte = ValidKernelPte;

        /* Save number page of the PE header in tmp PTE */
        TempPte.u.Hard.PageFrameNumber = PageFrameNumber;

        /* Copy the tmp PTE to the PTE for the PE header and make it valid */
        MI_WRITE_VALID_PTE(BasePte, TempPte);

        /* Get size for the header */
        PeHeaderSize = IoStatusBlock.Information;

        /* Check size of the header */
        if (PeHeaderSize != PAGE_SIZE)
        {
            if (PeHeaderSize < sizeof(IMAGE_DOS_HEADER))
            {
                DPRINT1("MiReadPeHeader: PeHeaderSize %X, File '%wZ'\n", PeHeaderSize, &FileObject->FileName);
                Status = STATUS_INVALID_IMAGE_NOT_MZ;
                goto Exit;
            }

            /* Zero end of page */
            RtlZeroMemory((PVOID)((ULONG_PTR)PeHeader + PeHeaderSize), (PAGE_SIZE - PeHeaderSize));
        }
    }

Exit:

    *OutPeHeader = PeHeader;
    *OutPeHeaderSize = PeHeaderSize;

    return Status;
}

NTSTATUS
NTAPI
MiValidateDosHeader(
    _In_ PIMAGE_DOS_HEADER DosHeader,
    _In_ ULONGLONG FileSize,
    _In_ ULONG PeHeaderSize)
{
    DPRINT("MiValidateDosHeader: %p, FileSize %I64X, PeHeaderSize %X\n", DosHeader, FileSize, PeHeaderSize);

    if (DosHeader->e_magic != 0x5A4D)
    {
        DPRINT1("MiValidateDosHeader: STATUS_INVALID_IMAGE_NOT_MZ (%X)\n", DosHeader->e_magic);
        DPRINT1("MiValidateDosHeader: %p, %I64X, %X\n", DosHeader, FileSize, PeHeaderSize);
        return STATUS_INVALID_IMAGE_NOT_MZ;
    }

    if ((ULONG)DosHeader->e_lfanew > (ULONG)FileSize)
    {
        DPRINT1("MiValidateDosHeader: STATUS_INVALID_IMAGE_PROTECT\n");
        ASSERT(FALSE);
        return STATUS_INVALID_IMAGE_PROTECT;
    }

    if ((ULONG)(DosHeader->e_lfanew + MI_PE_HEADER_MAX_SIZE) <= DosHeader->e_lfanew)
    {
        DPRINT1("MiValidateDosHeader: STATUS_INVALID_IMAGE_PROTECT\n");
        ASSERT(FALSE);
        return STATUS_INVALID_IMAGE_PROTECT;
    }

    return STATUS_SUCCESS;
}

VOID
NTAPI
MiRemoveImageHeaderPage(
    _In_ PFN_NUMBER PageFrameNumber)
{
    PMMPFN Pfn;
    KIRQL OldIrql;

    DPRINT("MiRemoveImageHeaderPage: PageFrameNumber %p\n", PageFrameNumber);

    Pfn = MI_PFN_ELEMENT(PageFrameNumber);

    OldIrql = MiLockPfnDb(APC_LEVEL);
    MiDecrementReferenceCount(Pfn, PageFrameNumber);
    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    return;
}

CODE_SEG("PAGE")
CHAR
NTAPI
MiGetImageProtection(
    _In_ ULONG Characteristics)
{
    ULONG Index = 0;

    PAGED_CODE();

    if (Characteristics & IMAGE_SCN_MEM_EXECUTE)
        Index = 1;

    if (Characteristics & IMAGE_SCN_MEM_READ)
        Index |= 2;

    if (Characteristics & IMAGE_SCN_MEM_WRITE)
        Index |= 4;

    if (Characteristics & IMAGE_SCN_MEM_SHARED)
        Index |= 8;

    return MmImageProtectionArray[Index];
}

VOID
NTAPI
MiInitializeTransitionPfn(
    _In_ PFN_NUMBER PageNumber,
    _In_ OUT PMMPTE SectionProto)
{
    PMMPTE ProtoPte;
    MMPTE TempPte;
    PMMPFN Pfn;
    PFN_NUMBER ProtoPtePageNumber;

    DPRINT("MiInitializeTransitionPfn: PageNumber %X, SectionProto %p\n", PageNumber, SectionProto);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(MmPfnOwner == KeGetCurrentThread());

    Pfn = MI_PFN_ELEMENT(PageNumber);
    Pfn->u1.Event = NULL;
    Pfn->PteAddress = SectionProto;
    Pfn->OriginalPte.u.Long = SectionProto->u.Long;

    ASSERT(!((Pfn->OriginalPte.u.Soft.Prototype == 0) &&
             (Pfn->OriginalPte.u.Soft.Transition == 1)));

    Pfn->u3.e1.PrototypePte = 1;
    Pfn->u3.e1.PageLocation = TransitionPage;
    Pfn->u2.ShareCount = 0;

    ProtoPte = MiAddressToPte(SectionProto);

    if (!ProtoPte->u.Hard.Valid)
    {
        if (!NT_SUCCESS(MiCheckPdeForPagedPool(SectionProto)))
        {
            DPRINT1("KeBugCheckEx()\n");
            ASSERT(FALSE);
            KeBugCheckEx(0x1A,
                         0x61940,
                         (ULONG_PTR)SectionProto,
                         ProtoPte->u.Long,
                         (ULONG_PTR)MiPteToAddress(SectionProto));
        }
    }

    ProtoPtePageNumber = ProtoPte->u.Hard.PageFrameNumber;

    Pfn->u4.PteFrame = ProtoPtePageNumber;

    MI_MAKE_TRANSITION_PTE(&TempPte, PageNumber, SectionProto->u.Soft.Protection);
    MI_WRITE_INVALID_PTE(SectionProto, TempPte);

    DPRINT("MiInitializeTransitionPfn: SectionProto %X, [%p]\n", SectionProto, SectionProto->u.Long);

    ASSERT(ProtoPtePageNumber != 0);
    MI_PFN_ELEMENT(ProtoPtePageNumber)->u2.ShareCount++;
}

VOID
NTAPI
MiUpdateImageHeaderPage(
    _In_ PMMPTE SectionProto,
    _In_ PFN_NUMBER PageNumber,
    _In_ PCONTROL_AREA ControlArea,
    _In_ BOOLEAN IsModified)
{
    PMMPFN Pfn;
    PMMPTE ProtoPte;
    KIRQL OldIrql;

    DPRINT("MiUpdateImageHeaderPage: SectionProto %p, PageNumber %X\n", SectionProto, PageNumber);

    Pfn = MI_PFN_ELEMENT(PageNumber);

    OldIrql = MiLockPfnDb(APC_LEVEL);

    ProtoPte = MiAddressToPte(SectionProto);

    if (!ProtoPte->u.Hard.Valid)
    {
        DPRINT("MiUpdateImageHeaderPage: FIXME MiMakeSystemAddressValidPfn()\n");
        ASSERT(FALSE);
        //MiMakeSystemAddressValidPfn(SectionProto, OldIrql);
    }

    MiInitializeTransitionPfn(PageNumber, SectionProto);

    if (IsModified)
    {
        ASSERT((Pfn)->u3.e1.Rom == 0);
        Pfn->u3.e1.Modified = 1;
    }

    if (Pfn->OriginalPte.u.Soft.Prototype)
        ControlArea->NumberOfPfnReferences++;

    MiDecrementReferenceCount(Pfn, PageNumber);

    MiUnlockPfnDb(OldIrql, APC_LEVEL);
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MiCreateImageFileMap(
    _In_ PFILE_OBJECT FileObject,
    _Out_ PSEGMENT* OutSegment)
{
    ULONG PeHeaderBufferMaxSize = (MI_PE_HEADER_MAX_PAGES * PAGE_SIZE);
    LARGE_INTEGER Offset = {{0, 0}};
    IO_STATUS_BLOCK IoStatusBlock;
    ULONGLONG FileSize;
    KEVENT Event;
    MI_PE_HEADER_MDL HeaderMdl;
#if 1
    PSEGMENT Segment = NULL;
    PLARGE_CONTROL_AREA NewControlArea;
    PCONTROL_AREA ControlArea = NULL;
    PSUBSECTION Subsection;
    PSUBSECTION NewSubsection;
    PSUBSECTION PreviousSubsection;
    PVOID PeHeader;
    PVOID PeHeaderBuffer = NULL;
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeader;
    PIMAGE_OPTIONAL_HEADER OptionalHeader;
    PIMAGE_SECTION_HEADER SectionHeaders = NULL;
    PSECTION_IMAGE_INFORMATION ImageInfo;
    ULONG_PTR ImageBase;
    ULONG_PTR VirtualAddress;
    MMPTE ProtoTemplate;
    MMPTE TempPteDemandZero;
    PMMPTE BasePte = NULL;
    PMMPTE Pte;
    PMMPTE SectionProto;
    PMMPFN CurrentPfn;
    PMMPFN PeHeaderPfn;
    PMMPFN NextPfn;
    //PFN_NUMBER PageFrameNumber;
    SIZE_T CommitCharged = 0;
    ULONG SizeOfImage;
    ULONG SizeOfHeaders;
    ULONG SizeOfSectionHeaders;
    ULONG NtHeaderSize;
    ULONG PeHeaderSize;
    ULONG ImageSize;
    ULONG SectionVirtualSize;
    ULONG CurrentSize;
    ULONG OffsetToNtHeader;
    ULONG OffsetToSectionHeaders;
    ULONG NumberOfSections;
    ULONG SubsectionCount;
    ULONG ImageAlignment;
    ULONG FileAlignment;
    ULONG AlignedSectionEnd;
    ULONG TotalNumberOfPtes;
    ULONG PtesInSubsection;
    ULONG LoaderFlags;
    ULONG size;
    ULONG ix;
    ULONG jx;
    BOOLEAN IsImageContainsCode;
    BOOLEAN IsModified = TRUE;
    BOOLEAN IsSubsectionCommitted;
    BOOLEAN IsZeroHeaderEnd = FALSE;
    BOOLEAN IsImageCommitted;
    BOOLEAN IsSingleSubsection;
    BOOLEAN IsDataSectionUsed;
    BOOLEAN IsGlobalMemory;
    NTSTATUS Status;
#endif

    DPRINT("MiCreateImageFileMap: FileObject %p\n", FileObject);
    PAGED_CODE();

    /* Initialize a notification event for page read operations */
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Status = MiReadPeHeader(FileObject,
                            &Event,
                            &HeaderMdl,
                            &FileSize,
                            &IsDataSectionUsed,
                            &PeHeader,
                            &PeHeaderSize,
                            &DosHeader,
                            &NtHeader,
                            &NtHeaderSize);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MiCreateImageFileMap: Status %X\n", Status);
        return Status;
    }

    if (IsDataSectionUsed)
    {
        DPRINT1("MiCreateImageFileMap: FileObject %p, ControlArea %p\n", FileObject, FileObject->SectionObjectPointer->DataSectionObject);
        ASSERT(FALSE);
    }

    /* Calculate PTE and PFN for the PE header */
    BasePte = MiAddressToPte(PeHeader);
    PeHeaderPfn = MI_PFN_ELEMENT(BasePte->u.Hard.PageFrameNumber);

    DosHeader = (PIMAGE_DOS_HEADER)PeHeader;

    DPRINT("MiCreateImageFileMap: DosHeader %p, FileSize %I64X, PeHeaderSize %X\n", DosHeader, FileSize, PeHeaderSize);

    Status = MiValidateDosHeader(DosHeader, FileSize, PeHeaderSize);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MiCreateImageFileMap: Status %X\n", Status);
        goto ErrorExit1;
    }

    if ((ULONG)(DosHeader->e_lfanew + MI_PE_HEADER_MAX_SIZE) <= PAGE_SIZE)
    {
        if (DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > PeHeaderSize)
        {
            DPRINT1("MiCreateImageFileMap: STATUS_INVALID_IMAGE_PROTECT. '%wZ'\n", &FileObject->FileName);
            Status = STATUS_INVALID_IMAGE_PROTECT;
            ASSERT(FALSE);
            goto ErrorExit1;
        }

        /* The size of the PE header does not exceed one page */
        NtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)DosHeader + DosHeader->e_lfanew);
        NtHeaderSize = (PeHeaderSize - DosHeader->e_lfanew);
    }
    else
    {
        /* PE header size is more than one page */
        PeHeaderBuffer = ExAllocatePoolWithTag(NonPagedPool, PeHeaderBufferMaxSize, 'xxmM');
        if (!PeHeaderBuffer)
        {
            DPRINT1("MiCreateImageFileMap: STATUS_INSUFFICIENT_RESOURCES. '%wZ'\n", &FileObject->FileName);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto ErrorExit1;
        }

        MmInitializeMdl(&HeaderMdl.Mdl, PeHeaderBuffer, PeHeaderBufferMaxSize);
        MmBuildMdlForNonPagedPool(&HeaderMdl.Mdl);

        KeClearEvent(&Event);

        Offset.LowPart = (ULONG)(ULONG_PTR)PAGE_ALIGN(DosHeader->e_lfanew);

        Status = IoPageRead(FileObject, &HeaderMdl.Mdl, &Offset, &Event, &IoStatusBlock);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, WrPageIn, KernelMode, FALSE, NULL);
            Status = IoStatusBlock.Status;
        }

        if (HeaderMdl.Mdl.MdlFlags & MDL_MAPPED_TO_SYSTEM_VA)
            MmUnmapLockedPages(HeaderMdl.Mdl.MappedSystemVa, &HeaderMdl.Mdl);

        if (!NT_SUCCESS(Status))
        {
            if (Status != STATUS_FILE_LOCK_CONFLICT && Status != STATUS_FILE_IS_OFFLINE)
                Status = STATUS_INVALID_FILE_FOR_SECTION;

            goto ErrorExit2;
        }

        PeHeaderSize = IoStatusBlock.Information;
        OffsetToNtHeader = BYTE_OFFSET(DosHeader->e_lfanew);

        if (PeHeaderSize != PeHeaderBufferMaxSize &&
            PeHeaderSize < (OffsetToNtHeader + sizeof(IMAGE_NT_HEADERS)))
        {
            DPRINT1("MiCreateImageFileMap: STATUS_INVALID_IMAGE_PROTECT. '%wZ'\n", &FileObject->FileName);
            Status = STATUS_INVALID_IMAGE_PROTECT;
            goto ErrorExit1;
        }

        NtHeader = Add2Ptr(PeHeaderBuffer, OffsetToNtHeader);
        NtHeaderSize = (PeHeaderSize - OffsetToNtHeader);
    }

    DPRINT("MiCreateImageFileMap: FIXME MiVerifyImageHeader\n");

    Status = 0;//MiVerifyImageHeader(NtHeader, DosHeader, NtHeaderSize);
    if (Status != STATUS_SUCCESS)
    {
        DPRINT1("MiCreateImageFileMap: ErrorExit2. Status %X, File '%wZ'\n", Status, &FileObject->FileName);
        goto ErrorExit2;
    }

    OptionalHeader = &NtHeader->OptionalHeader;

    SizeOfImage = OptionalHeader->SizeOfImage;
    ImageAlignment = OptionalHeader->SectionAlignment;
    FileAlignment = (OptionalHeader->FileAlignment - 1);
    LoaderFlags = OptionalHeader->LoaderFlags;
    ImageBase = OptionalHeader->ImageBase;
    SizeOfHeaders = OptionalHeader->SizeOfHeaders;

    TotalNumberOfPtes = BYTES_TO_PAGES(SizeOfImage);
    if (!TotalNumberOfPtes)
    {
        DPRINT1("MiCreateImageFileMap: STATUS_INVALID_IMAGE_FORMAT. '%wZ'\n", &FileObject->FileName);
        Status = STATUS_INVALID_IMAGE_FORMAT;
        goto ErrorExit1;
    }

    if (OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress &&
        OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size)
    {
        LoaderFlags |= 1;
    }

    NumberOfSections = NtHeader->FileHeader.NumberOfSections;

    DPRINT("MiCreateImageFileMap: NumberOfSections %X\n", NumberOfSections);

    if (ImageAlignment >= PAGE_SIZE)
    {
        SubsectionCount = (NumberOfSections + 1);
        IsSingleSubsection = FALSE;

        size = (sizeof(CONTROL_AREA) + ((NumberOfSections + 1) * sizeof(SUBSECTION)));
        ControlArea = ExAllocatePoolWithTag(NonPagedPool, size, 'iCmM');
    }
    else
    {
        DPRINT("MiCreateImageFileMap: IsSingleSubsection\n");
        SubsectionCount = 1;
        IsSingleSubsection = TRUE;

        size = (sizeof(CONTROL_AREA) + sizeof(SUBSECTION));
        ControlArea = ExAllocatePoolWithTag(NonPagedPool, size, 'aCmM');
    }

    if (!ControlArea)
    {
        DPRINT1("MiCreateImageFileMap: STATUS_INSUFFICIENT_RESOURCES. '%wZ'\n", &FileObject->FileName);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit1;
    }

    RtlZeroMemory(ControlArea, (sizeof(CONTROL_AREA) + sizeof(SUBSECTION)));

    ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);

    Subsection = (PSUBSECTION)&ControlArea[1];

    size = (sizeof(SEGMENT) + sizeof(SECTION_IMAGE_INFORMATION) + (TotalNumberOfPtes - 1) * sizeof(MMPTE));

    Segment = ExAllocatePoolWithTag((PagedPool + 0x80000000), size, 'tSmM');
    if (!Segment)
    {
        DPRINT1("MiCreateImageFileMap: STATUS_INSUFFICIENT_RESOURCES. '%wZ'\n", &FileObject->FileName);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit2;
    }

    *OutSegment = Segment;

    RtlZeroMemory(Segment, sizeof(SEGMENT));

    Segment->ControlArea = ControlArea;
    Segment->TotalNumberOfPtes = TotalNumberOfPtes;
    Segment->NonExtendedPtes = TotalNumberOfPtes;
    Segment->SizeOfSegment = (TotalNumberOfPtes * PAGE_SIZE);

    RtlZeroMemory(Segment->ThePtes, (TotalNumberOfPtes * sizeof(MMPTE)));
    Segment->PrototypePte = Segment->ThePtes;
    PeHeaderPfn->u2.Blink = (PFN_NUMBER)Segment->PrototypePte;

    ImageInfo = (PSECTION_IMAGE_INFORMATION)&Segment->ThePtes[TotalNumberOfPtes + 1];
    RtlZeroMemory(ImageInfo, sizeof(SECTION_IMAGE_INFORMATION));

    ImageInfo->ImageFileSize = FileSize;
    ImageInfo->TransferAddress = (PVOID)(ImageBase + OptionalHeader->AddressOfEntryPoint);
    ImageInfo->MaximumStackSize = OptionalHeader->SizeOfStackReserve;
    ImageInfo->CommittedStackSize = OptionalHeader->SizeOfStackCommit;
    ImageInfo->SubSystemType = OptionalHeader->Subsystem;
    ImageInfo->SubSystemMajorVersion = OptionalHeader->MajorSubsystemVersion;
    ImageInfo->SubSystemMinorVersion = OptionalHeader->MinorSubsystemVersion;
    ImageInfo->DllCharacteristics = OptionalHeader->DllCharacteristics;
    //HACK!   
    {
        /* Since we don't really implement SxS yet and LD doesn't supoprt /ALLOWISOLATION:NO, hard-code this flag here,
           which will prevent the loader and other code from doing any .manifest or SxS magic to any binary.

           This will break applications that depend on SxS when running with real Windows Kernel32/SxS/etc but honestly that's not tested.
           It will also break them when running no ReactOS once we implement the SxS support -- at which point, duh, this should be removed.

           But right now, any app depending on SxS is already broken anyway, so this flag only helps.
        */
        ImageInfo->DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_NO_ISOLATION;
    }
    //end HACK!
    ImageInfo->ImageCharacteristics = NtHeader->FileHeader.Characteristics;
    ImageInfo->Machine = NtHeader->FileHeader.Machine;
    ImageInfo->LoaderFlags = LoaderFlags;

    Segment->u2.ImageInformation = ImageInfo;

    IsImageContainsCode = ((OptionalHeader->SizeOfCode != 0) || (OptionalHeader->AddressOfEntryPoint != 0));
    ImageInfo->ImageContainsCode = IsImageContainsCode;

    ControlArea->Segment = Segment;
    ControlArea->NumberOfSectionReferences = 1;
    ControlArea->NumberOfUserReferences = 1;

    ControlArea->u.Flags.BeingCreated = 1;
    ControlArea->u.Flags.Image = 1;
    ControlArea->u.Flags.File = 1;

    DPRINT("MiCreateImageFileMap: FIXME IoIsDeviceEjectable\n");
    if (IsDataSectionUsed ||
//        (IoIsDeviceEjectable(FileObject->DeviceObject)) || 
        ((NtHeader->FileHeader.Characteristics & 0x400) && (FileObject->DeviceObject->Characteristics & 1)) ||
        ((NtHeader->FileHeader.Characteristics & 0x800) && (FileObject->DeviceObject->Characteristics & 0x10)))
    {
        DPRINT1("MiCreateImageFileMap: (%X), %X,%X\n", IsDataSectionUsed, NtHeader->FileHeader.Characteristics, FileObject->DeviceObject->Characteristics);

        if (IsDataSectionUsed)
        {
            ASSERT(FALSE);
        }

        ControlArea->u.Flags.FloppyMedia = 1;
    }

    DPRINT("MiCreateImageFileMap: FIXME MiMakeImageFloppy\n");

    if (FileObject->DeviceObject->Characteristics & 0x10)
        ControlArea->u.Flags.Networked = 1;

    ControlArea->FilePointer = FileObject;
    Subsection->ControlArea = ControlArea;
    VirtualAddress = ImageBase;

    if (ImageBase & (0x10000 - 1))
    {
        DPRINT1("MiCreateImageFileMap: STATUS_INVALID_IMAGE_FORMAT. '%wZ'\n", &FileObject->FileName);
        Status = STATUS_INVALID_IMAGE_FORMAT;
        goto ErrorExit2;
    }

    Segment->BasedAddress = (PVOID)ImageBase;

    DPRINT("MiCreateImageFileMap: FIXME MiMatchSectionBase\n");

    if (SizeOfHeaders >= SizeOfImage)
    {
        DPRINT1("MiCreateImageFileMap: STATUS_INVALID_IMAGE_FORMAT. '%wZ'\n", &FileObject->FileName);
        Status = STATUS_INVALID_IMAGE_FORMAT;
        goto ErrorExit2;
    }

    MI_MAKE_SUBSECTION_PTE(&ProtoTemplate, Subsection);

    ProtoTemplate.u.Soft.Prototype = 1;
    Segment->SegmentPteTemplate = ProtoTemplate;

    CurrentSize = 0;

    if (IsSingleSubsection)
    {
        Pte = Segment->PrototypePte;

        Subsection->SubsectionBase = Pte;
        Subsection->PtesInSubsection = TotalNumberOfPtes;

        if ((ULONGLONG)SizeOfImage >= FileSize)
        {
            Subsection->NumberOfFullSectors = (ULONG)(FileSize / MM_SECTOR_SIZE);
            ASSERT((FileSize & 0xFFFFF00000000000) == 0);
            Subsection->u.SubsectionFlags.SectorEndOffset = ((ULONG)FileSize & (MM_SECTOR_SIZE - 1));
        }
        else
        {
            Subsection->NumberOfFullSectors = (SizeOfImage / MM_SECTOR_SIZE);
            Subsection->u.SubsectionFlags.SectorEndOffset = (SizeOfImage & (MM_SECTOR_SIZE - 1));
        }

        Subsection->u.SubsectionFlags.Protection = MM_EXECUTE_WRITECOPY;
        ProtoTemplate.u.Soft.Protection = MM_EXECUTE_WRITECOPY;

        Segment->SegmentPteTemplate = ProtoTemplate;

        TempPteDemandZero.u.Long = 0;
        TempPteDemandZero.u.Soft.Protection = MM_EXECUTE_WRITECOPY;

        for (jx = TotalNumberOfPtes; jx; jx--)
        {
            if (CurrentSize >= (ULONG)FileSize)
                MI_WRITE_INVALID_PTE(Pte, TempPteDemandZero);
            else
                MI_WRITE_INVALID_PTE(Pte, ProtoTemplate);

            CurrentSize += PAGE_SIZE;
            Pte++;
        }

        Segment->u1.ImageCommitment = TotalNumberOfPtes;
    }
    else
    {
        PtesInSubsection = ((SizeOfHeaders + (ImageAlignment - 1)) / PAGE_SIZE) & (~(ImageAlignment - 1) / PAGE_SIZE);

        Subsection->PtesInSubsection = PtesInSubsection;

        //DPRINT("MiCreateImageFileMap: Subsection %p, Subsection->NextSubsection %p\n", Subsection, Subsection->NextSubsection);
        //DPRINT("MiCreateImageFileMap: UnusedPtes %X, PtesInSubsection %X\n", Subsection->UnusedPtes, PtesInSubsection);

        Pte = Segment->PrototypePte;
        Subsection->SubsectionBase = Pte;

        //DPRINT("MiCreateImageFileMap: Subsection->SubsectionBase %p\n", Subsection->SubsectionBase);

        if (!SizeOfHeaders)
        {
            DPRINT1("MiCreateImageFileMap: STATUS_INVALID_IMAGE_FORMAT. '%wZ'\n", &FileObject->FileName);
            Status = STATUS_INVALID_IMAGE_FORMAT;
            goto ErrorExit2;
        }

        if ((SizeOfHeaders + ImageAlignment - 1) <= SizeOfHeaders)
        {
            DPRINT1("MiCreateImageFileMap: STATUS_INVALID_IMAGE_FORMAT. '%wZ'\n", &FileObject->FileName);
            Status = STATUS_INVALID_IMAGE_FORMAT;
            goto ErrorExit2;
        }

        if (PtesInSubsection > TotalNumberOfPtes)
        {
            DPRINT1("MiCreateImageFileMap: STATUS_INVALID_IMAGE_FORMAT. '%wZ'\n", &FileObject->FileName);
            Status = STATUS_INVALID_IMAGE_FORMAT;
            goto ErrorExit2;
        }

        TotalNumberOfPtes -= PtesInSubsection;

        Subsection->NumberOfFullSectors = (SizeOfHeaders / MM_SECTOR_SIZE);

        Subsection->u.SubsectionFlags.SectorEndOffset = (SizeOfHeaders & (MM_SECTOR_SIZE - 1));
        Subsection->u.SubsectionFlags.ReadOnly = 1;
        Subsection->u.SubsectionFlags.Protection = MM_READONLY;

        ProtoTemplate.u.Soft.Protection = MM_READONLY;
        Segment->SegmentPteTemplate.u.Long = ProtoTemplate.u.Long;

        for (ix = 0; ix < PtesInSubsection; ix++)
        {
            if (CurrentSize >= SizeOfHeaders)
                Pte->u.Long = 0;
            else
                MI_WRITE_INVALID_PTE(Pte, ProtoTemplate);

            CurrentSize += PAGE_SIZE;
            Pte++;
        }

        VirtualAddress = (ImageBase + (ix * PAGE_SIZE));
    }

    SizeOfSectionHeaders = (NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    OffsetToSectionHeaders = (FIELD_OFFSET(IMAGE_NT_HEADERS, FileHeader) + sizeof(IMAGE_FILE_HEADER) + NtHeader->FileHeader.SizeOfOptionalHeader);

    if (NtHeaderSize >= (BYTE_OFFSET(NtHeader) + OffsetToSectionHeaders + SizeOfSectionHeaders + sizeof(IMAGE_SECTION_HEADER)))
    {
        SectionHeaders = Add2Ptr(NtHeader, OffsetToSectionHeaders);
    }
    else if (PeHeaderBuffer)
    {
        if (NtHeaderSize < OffsetToSectionHeaders + SizeOfSectionHeaders)
            SectionHeaders = NULL;
        else
            SectionHeaders = Add2Ptr(NtHeader, OffsetToSectionHeaders);
    }

    if (!SectionHeaders)
    {
        if ((ULONG)((ULONG)DosHeader->e_lfanew + OffsetToSectionHeaders + SizeOfSectionHeaders) <= (ULONG)DosHeader->e_lfanew)
        {
            DPRINT1("MiCreateImageFileMap: STATUS_INVALID_IMAGE_FORMAT. '%wZ'\n", &FileObject->FileName);
            Status = STATUS_INVALID_IMAGE_FORMAT;
            goto ErrorExit2;
        }

        if ((BYTE_OFFSET((ULONG)DosHeader->e_lfanew + OffsetToSectionHeaders) + SizeOfSectionHeaders) > PeHeaderBufferMaxSize)
        {
            DPRINT1("MiCreateImageFileMap: STATUS_INVALID_IMAGE_FORMAT. '%wZ'\n", &FileObject->FileName);
            Status = STATUS_INVALID_IMAGE_FORMAT;
            goto ErrorExit2;
        }

        if (!PeHeaderBuffer)
        {
            PeHeaderBuffer = ExAllocatePoolWithTag(NonPagedPool, PeHeaderBufferMaxSize, 'xxmM');
            if (!PeHeaderBuffer)
            {
                DPRINT1("MiCreateImageFileMap: STATUS_INSUFFICIENT_RESOURCES. '%wZ'\n", &FileObject->FileName);
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto ErrorExit2;
            }

            MmInitializeMdl(&HeaderMdl.Mdl, PeHeaderBuffer, PeHeaderBufferMaxSize);
            MmBuildMdlForNonPagedPool(&HeaderMdl.Mdl);
        }

        SectionHeaders = Add2Ptr(PeHeaderBuffer, BYTE_OFFSET((ULONG)DosHeader->e_lfanew + OffsetToSectionHeaders));
        Offset.LowPart = (ULONG)(ULONG_PTR)(PAGE_ALIGN((ULONG)DosHeader->e_lfanew + OffsetToSectionHeaders));

        KeClearEvent(&Event);

        Status = IoPageRead(FileObject, &HeaderMdl.Mdl, &Offset, &Event, &IoStatusBlock);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, WrPageIn, KernelMode, FALSE, NULL);
            Status = IoStatusBlock.Status;
        }

        if (HeaderMdl.Mdl.MdlFlags & MDL_MAPPED_TO_SYSTEM_VA)
            MmUnmapLockedPages(HeaderMdl.Mdl.MappedSystemVa, &HeaderMdl.Mdl);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("MiCreateImageFileMap: Status %X, '%wZ'\n", Status, &FileObject->FileName);

            if (Status != STATUS_FILE_LOCK_CONFLICT && Status != STATUS_FILE_IS_OFFLINE)
                Status = STATUS_INVALID_FILE_FOR_SECTION;

            goto ErrorExit2;
        }

        PeHeaderSize = IoStatusBlock.Information;

        if (PeHeaderSize < (BYTE_OFFSET((ULONG)DosHeader->e_lfanew + OffsetToSectionHeaders) + SizeOfSectionHeaders))
        {
            DPRINT1("MiCreateImageFileMap: STATUS_INVALID_IMAGE_FORMAT. '%wZ'\n", &FileObject->FileName);
            Status = STATUS_INVALID_IMAGE_FORMAT;
            goto ErrorExit2;
        }
    }

    if (IsSingleSubsection)
    {
        for (; NumberOfSections > 0; NumberOfSections--)
        {
            if (SectionHeaders->Misc.VirtualSize)
                SectionVirtualSize = SectionHeaders->Misc.VirtualSize;
            else
                SectionVirtualSize = SectionHeaders->SizeOfRawData;

            if ((SectionHeaders->SizeOfRawData + SectionHeaders->PointerToRawData) < SectionHeaders->PointerToRawData)
            {
                DPRINT1("MiCreateImageFileMap: STATUS_INVALID_IMAGE_FORMAT. '%wZ'\n", &FileObject->FileName);
                Status = STATUS_INVALID_IMAGE_FORMAT;
                goto ErrorExit2;
            }

            if (SectionHeaders->PointerToRawData != SectionHeaders->VirtualAddress ||
                SectionVirtualSize > SectionHeaders->SizeOfRawData)
            {
                DPRINT1("MiCreateImageFileMap: RawData %X, Va %X, SectionSize %X, RawSize %X\n", SectionHeaders->PointerToRawData, SectionHeaders->VirtualAddress, SectionVirtualSize, SectionHeaders->SizeOfRawData);
                DPRINT1("MiCreateImageFileMap: invalid BSS/Trailingzero '%wZ'\n", &FileObject->FileName);
                Status = STATUS_INVALID_IMAGE_FORMAT;
                goto ErrorExit2;
            }

            SectionHeaders++;
        }
    }
    else
    {
        ImageSize = (FileSize + 1);

        for (; NumberOfSections > 0; NumberOfSections--)
        {
            if (SectionHeaders->Misc.VirtualSize)
                SectionVirtualSize = SectionHeaders->Misc.VirtualSize;
            else
                SectionVirtualSize = SectionHeaders->SizeOfRawData;

            NtHeader = (PIMAGE_NT_HEADERS)SectionVirtualSize;

            if (!SectionHeaders->SizeOfRawData)
                SectionHeaders->PointerToRawData = 0;

            if ((ULONG)(SectionHeaders->PointerToRawData + SectionHeaders->SizeOfRawData) < SectionHeaders->PointerToRawData)
            {
                DPRINT1("MiCreateImageFileMap: STATUS_INVALID_IMAGE_FORMAT. '%wZ'\n", &FileObject->FileName);
                Status = STATUS_INVALID_IMAGE_FORMAT;
                goto ErrorExit2;
            }

            Subsection->NextSubsection = (Subsection + 1);
            Subsection++;

            Subsection->ControlArea = ControlArea;
            Subsection->NextSubsection = NULL;
            Subsection->UnusedPtes = 0;

            if (VirtualAddress != (ImageBase + SectionHeaders->VirtualAddress) || !SectionVirtualSize)
            {
                DPRINT1("MiCreateImageFileMap: STATUS_INVALID_IMAGE_FORMAT. '%wZ'\n", &FileObject->FileName);
                Status = STATUS_INVALID_IMAGE_FORMAT;
                goto ErrorExit2;
            }

            if ((ULONG)(SectionVirtualSize + ImageAlignment - 1) <= SectionVirtualSize)
            {
                DPRINT1("MiCreateImageFileMap: STATUS_INVALID_IMAGE_FORMAT. '%wZ'\n", &FileObject->FileName);
                Status = STATUS_INVALID_IMAGE_FORMAT;
                goto ErrorExit2;
            }

            Subsection->PtesInSubsection = (((ULONG)(SectionVirtualSize + ImageAlignment - 1)) / PAGE_SIZE) & (~(ImageAlignment - 1) / PAGE_SIZE);
            if (Subsection->PtesInSubsection > TotalNumberOfPtes)
            {
                DPRINT1("MiCreateImageFileMap: STATUS_INVALID_IMAGE_FORMAT. '%wZ'\n", &FileObject->FileName);
                Status = STATUS_INVALID_IMAGE_FORMAT;
                goto ErrorExit2;
            }

            Subsection->u.LongFlags = 0;
            TotalNumberOfPtes -= Subsection->PtesInSubsection;

            Subsection->StartingSector = SectionHeaders->PointerToRawData / MM_SECTOR_SIZE;
            AlignedSectionEnd = (SectionHeaders->PointerToRawData + SectionHeaders->SizeOfRawData + FileAlignment) & ~FileAlignment;

            if ((ULONG)AlignedSectionEnd < SectionHeaders->PointerToRawData)
            {
                DPRINT1("MiCreateImageFileMap: STATUS_INVALID_IMAGE_FORMAT. '%wZ'\n", &FileObject->FileName);
                Status = STATUS_INVALID_IMAGE_FORMAT;
                goto ErrorExit2;
            }

            Subsection->NumberOfFullSectors = ((AlignedSectionEnd / MM_SECTOR_SIZE) - Subsection->StartingSector);
            Subsection->u.SubsectionFlags.SectorEndOffset = (AlignedSectionEnd & 0x1FF);

            Subsection->SubsectionBase = Pte;

            ImageSize = (SectionHeaders->PointerToRawData + SectionHeaders->SizeOfRawData);

            ProtoTemplate.u.Long = 0;
            MI_MAKE_SUBSECTION_PTE(&ProtoTemplate, Subsection);
            ProtoTemplate.u.Soft.Prototype = 1;
            ProtoTemplate.u.Soft.Protection = MiGetImageProtection(SectionHeaders->Characteristics);

            TempPteDemandZero.u.Long = 0;
            TempPteDemandZero.u.Soft.Protection = ProtoTemplate.u.Soft.Protection;

            if (!SectionHeaders->PointerToRawData)
                ProtoTemplate = TempPteDemandZero;

            Subsection->u.SubsectionFlags.ReadOnly = 1;
            Subsection->u.SubsectionFlags.Protection = ProtoTemplate.u.Soft.Protection;

            IsImageCommitted = FALSE;
            IsSubsectionCommitted = FALSE;

            if (ProtoTemplate.u.Soft.Protection & 4)
            {
                if ((ProtoTemplate.u.Soft.Protection & 5) == 5)
                {
                    IsImageCommitted = TRUE;
                }
                else
                {
                    Subsection->u.SubsectionFlags.GlobalMemory = 1;
                    ControlArea->u.Flags.GlobalMemory = 1;
                    IsSubsectionCommitted = TRUE;
                }
            }

            DPRINT("MiCreateImageFileMap: [%p], [%p]\n", ProtoTemplate.u.Long, TempPteDemandZero.u.Long);

            Segment->SegmentPteTemplate = ProtoTemplate;
            CurrentSize = 0;

            for (ix= 0; ix < Subsection->PtesInSubsection; ix++)
            {
                if (CurrentSize >= (ULONG)NtHeader)
                {
                    Pte->u.Long = 0;
                    DPRINT("MiCreateImageFileMap: Pte %p, [%p]\n", Pte, Pte->u.Long);
                }
                else
                {
                    if (IsSubsectionCommitted)
                        Segment->NumberOfCommittedPages++;

                    if (IsImageCommitted)
                        Segment->u1.ImageCommitment++;

                    if (CurrentSize >= SectionHeaders->SizeOfRawData)
                        MI_WRITE_INVALID_PTE(Pte, TempPteDemandZero);
                    else
                        MI_WRITE_INVALID_PTE(Pte, ProtoTemplate);
                }

                CurrentSize += PAGE_SIZE;
                VirtualAddress += PAGE_SIZE;
                Pte++;
            }

            SectionHeaders++;
        }

        ASSERT((Pte > Segment->PrototypePte) && (Pte <= Segment->PrototypePte + Segment->TotalNumberOfPtes));
        ASSERT((ImageAlignment >= PAGE_SIZE));

        if (ImageSize > (ULONG)FileSize)
        {
            DbgPrint("MMCREASECT: invalid image size - file size %lx - image size %lx\n %wZ\n", FileSize, ImageSize, &FileObject->FileName);
            Status = STATUS_INVALID_IMAGE_FORMAT;
            goto ErrorExit2;
        }

        if (TotalNumberOfPtes >= ImageAlignment / PAGE_SIZE)
        {
            DbgPrint("MMCREASECT: invalid image - PTE left %lx, image name %wZ\n", TotalNumberOfPtes, &FileObject->FileName);
            Status = STATUS_INVALID_IMAGE_FORMAT;
            goto ErrorExit2;
        }

        if (TotalNumberOfPtes)
            RtlZeroMemory(Pte, (TotalNumberOfPtes * sizeof(MMPTE)));

        if (!PeHeaderBuffer && SizeOfHeaders < PAGE_SIZE)
        {
            RtlZeroMemory(Add2Ptr(PeHeader, SizeOfHeaders), (PAGE_SIZE - SizeOfHeaders));
            IsZeroHeaderEnd = TRUE;
        }

        CommitCharged = Segment->NumberOfCommittedPages;
        if (CommitCharged)
        {
            if (!MiChargeCommitment(CommitCharged, NULL))
            {
                DPRINT1("MiCreateImageFileMap: STATUS_COMMITMENT_LIMIT. '%wZ'\n", &FileObject->FileName);
                CommitCharged = 0;
                Status = STATUS_COMMITMENT_LIMIT;
                goto ErrorExit2;
            }

            InterlockedExchangeAddSizeT(&MmSharedCommit, CommitCharged);
        }
    }

    if (ControlArea->u.Flags.GlobalMemory && !(LoaderFlags & 0x01000000))
        IsGlobalMemory = TRUE;
    else
        IsGlobalMemory = FALSE;

    if (IsGlobalMemory)
    {
        size = (sizeof(LARGE_CONTROL_AREA) + (SubsectionCount * sizeof(SUBSECTION)));

        NewControlArea = ExAllocatePoolWithTag(NonPagedPool, size, 'iCmM');
        if (!NewControlArea)
        {
            DPRINT1("MiCreateImageFileMap: STATUS_INSUFFICIENT_RESOURCES. '%wZ'\n", &FileObject->FileName);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto ErrorExit2;
        }

        RtlCopyMemory(NewControlArea, ControlArea, sizeof(*ControlArea));

        ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);

        {
            Subsection = (PSUBSECTION)&ControlArea[1];
            NewSubsection = (PSUBSECTION)&NewControlArea[1];

            for (ix = 0; ix < SubsectionCount; ix++)
            {
                RtlCopyMemory(NewSubsection, Subsection, sizeof(SUBSECTION));

                NewSubsection->ControlArea = (PCONTROL_AREA)NewControlArea;
                NewSubsection->NextSubsection = (NewSubsection + 1);

                Pte = Segment->PrototypePte;

                MI_MAKE_SUBSECTION_PTE(&ProtoTemplate, NewSubsection);
                ProtoTemplate.u.Soft.Prototype = 1;

                for (jx = 0; jx < Segment->TotalNumberOfPtes; jx++)
                {
                    ASSERT(Pte->u.Hard.Valid == 0);

                    if (Pte->u.Soft.Prototype &&
                        MiSubsectionPteToSubsection(Pte) == Subsection)
                    {
                        ProtoTemplate.u.Soft.Protection = Pte->u.Soft.Protection;
                        MI_WRITE_INVALID_PTE(Pte, ProtoTemplate);
                    }

                    Pte++;
                }

                Subsection++;
                PreviousSubsection = NewSubsection;
                NewSubsection++;
            }

            PreviousSubsection->NextSubsection = NULL;

            Segment->ControlArea = (PCONTROL_AREA)NewControlArea;

            if (IsGlobalMemory)
            {
                NewControlArea->u.Flags.GlobalOnlyPerSession = 1;
                NewControlArea->SessionId = 0;

                InitializeListHead(&NewControlArea->UserGlobalList);
            }

            if (IsSingleSubsection)
                ExFreePoolWithTag(ControlArea, 'aCmM');
            else
                ExFreePoolWithTag(ControlArea, 'iCmM');

            ControlArea = (PCONTROL_AREA)NewControlArea;
        }
    }

    if (BasePte)
        MiReleaseSystemPtes(BasePte, 1, 0);

    CurrentPfn = PeHeaderPfn;
    do
    {
        NextPfn = (PMMPFN)CurrentPfn->u1.Flink;
        SectionProto = (PMMPTE)CurrentPfn->u2.Blink;

        if (!NextPfn)
        {
            ASSERT(SectionProto == Segment->PrototypePte);

            if (!IsZeroHeaderEnd)
                IsModified = FALSE;
        }

        ASSERT(SectionProto >= Segment->PrototypePte);
        ASSERT(SectionProto < (Segment->PrototypePte + Segment->TotalNumberOfPtes));

        MiUpdateImageHeaderPage(SectionProto, (CurrentPfn - &MmPfnDatabase[0]), ControlArea, IsModified);

        CurrentPfn = NextPfn;
    }
    while (CurrentPfn);

    if (PeHeaderBuffer)
        ExFreePoolWithTag(PeHeaderBuffer, 'xxmM');

    return STATUS_SUCCESS;


ErrorExit2:

    ASSERT(!NT_SUCCESS(Status));
    ASSERT((ControlArea == NULL) || (ControlArea->NumberOfPfnReferences == 0));

    if (Segment)
    {
        if (CommitCharged)
        {
            ASSERT(CommitCharged == Segment->NumberOfCommittedPages);

            ASSERT((SSIZE_T)CommitCharged >= 0);
            ASSERT(MmTotalCommittedPages >= CommitCharged);
            InterlockedExchangeAddSizeT(&MmSharedCommit, -CommitCharged);
        }

        if (Segment->SegmentFlags.ExtraSharedWowSubsections == 0)
        {
            MMPTE TempPte;

            for (ix = 0; ix < Segment->TotalNumberOfPtes; ix++)
            {
                TempPte.u.Long = Segment->PrototypePte[ix].u.Long;

                ASSERT(TempPte.u.Hard.Valid == 0);
                ASSERT((TempPte.u.Soft.Prototype == 1) || (TempPte.u.Soft.Transition == 0));
            }
        }
    }

    ASSERT((ControlArea == NULL) || (ControlArea->NumberOfPfnReferences == 0));

ErrorExit1:

    if (BasePte)
        MiReleaseSystemPtes(BasePte, 1, 0);

    CurrentPfn = PeHeaderPfn;
    do
    {
        NextPfn = (PMMPFN)CurrentPfn->u1.Flink;
        CurrentPfn->u2.Blink = 0;
        MiRemoveImageHeaderPage(CurrentPfn - MmPfnDatabase);
        CurrentPfn = NextPfn;
    }
    while (CurrentPfn);

    ASSERT((ControlArea == NULL) || (ControlArea->NumberOfPfnReferences == 0));

    if (Segment)
        ExFreePoolWithTag(Segment, 'tSmM');

    if (ControlArea)
    {
        if (IsSingleSubsection)
            ExFreePoolWithTag(ControlArea, 'aCmM');
        else
            ExFreePoolWithTag(ControlArea, 'iCmM');
    }

    if (PeHeaderBuffer)
        ExFreePoolWithTag(PeHeaderBuffer, 'xxmM');

    DPRINT("MiCreateImageFileMap: return %X, File '%wZ'\n", Status, &FileObject->FileName);
    return Status;
}

NTSTATUS
NTAPI
MiAddViewsForSection(
    _In_ PMSUBSECTION StartMappedSubsection,
    _In_ ULONGLONG LastPteOffset,
    _In_ KIRQL OldIrql)
{
    PMSUBSECTION MappedSubsection;
    PVOID SectionProtos;
    MMPTE ProtoTemplate;
    ULONG SubsectionPoolSize;
    ULONG PteCount;

    DPRINT("MiAddViewsForSection: %p, %I64X\n", StartMappedSubsection, LastPteOffset);

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
                MappedSubsection->DereferenceList.Flink = NULL;

                PteCount = (MappedSubsection->PtesInSubsection + MappedSubsection->UnusedPtes);
                AlloccatePoolForSubsectionPtes(PteCount);
            }

            MappedSubsection->u2.SubsectionFlags2.SubsectionAccessed = 1;
        }
        else
        {
            ASSERT(MappedSubsection->u.SubsectionFlags.SubsectionStatic == 0);
            ASSERT(MappedSubsection->NumberOfMappedViews == 0);

            MiUnlockPfnDb(OldIrql, APC_LEVEL);

            PteCount = (MappedSubsection->PtesInSubsection + MappedSubsection->UnusedPtes);
            SubsectionPoolSize = (PteCount * sizeof(MMPTE));
            ASSERT(SubsectionPoolSize != 0);

            SectionProtos = ExAllocatePoolWithTag(PagedPool, SubsectionPoolSize, 'tSmM'); // ? POOL_TYPE == 0x80000001
            if (!SectionProtos)
            {
                OldIrql = MiLockPfnDb(APC_LEVEL);

                while (StartMappedSubsection != MappedSubsection);
                {
                    ASSERT((LONG_PTR)StartMappedSubsection->NumberOfMappedViews >= 1);
                    StartMappedSubsection->NumberOfMappedViews--;

                    ASSERT(StartMappedSubsection->u.SubsectionFlags.SubsectionStatic == 0);
                    ASSERT(StartMappedSubsection->DereferenceList.Flink == NULL);

                    if (!StartMappedSubsection->NumberOfMappedViews)
                    {
                        InsertHeadList(&MmUnusedSubsectionList, &StartMappedSubsection->DereferenceList);

                        PteCount = (MappedSubsection->PtesInSubsection + MappedSubsection->UnusedPtes);
                        FreePoolForSubsectionPtes(PteCount);
                    }

                    StartMappedSubsection = (PMSUBSECTION)StartMappedSubsection->NextSubsection;
                }

                MiUnlockPfnDb(OldIrql, APC_LEVEL);

                DPRINT1("MiAddViewsForSection: return STATUS_INSUFFICIENT_RESOURCES\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            MI_MAKE_SUBSECTION_PTE(&ProtoTemplate, MappedSubsection);

            ProtoTemplate.u.Soft.Prototype = 1;
            ProtoTemplate.u.Soft.Protection = MappedSubsection->ControlArea->Segment->SegmentPteTemplate.u.Soft.Protection;

            RtlFillMemoryUlong(SectionProtos, SubsectionPoolSize, ProtoTemplate.u.Long); // FIXME for 64 bit

            OldIrql = MiLockPfnDb(APC_LEVEL);

            MappedSubsection->NumberOfMappedViews++;
            MappedSubsection->u2.SubsectionFlags2.SubsectionAccessed = 1;

            if (MappedSubsection->SubsectionBase)
            {
                if (MappedSubsection->DereferenceList.Flink)
                {
                    ASSERT(MappedSubsection->NumberOfMappedViews == 1);

                    RemoveEntryList(&MappedSubsection->DereferenceList);
                    MappedSubsection->DereferenceList.Flink = NULL;

                    PteCount = (MappedSubsection->PtesInSubsection + MappedSubsection->UnusedPtes);
                    AlloccatePoolForSubsectionPtes(PteCount);
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
                break;

            LastPteOffset -= MappedSubsection->PtesInSubsection;
        }
    }

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    DPRINT("MiAddViewsForSection: return STATUS_SUCCESS\n");
    return STATUS_SUCCESS;
}

VOID
NTAPI
MiRemoveViewsFromSection(
    _In_ PMSUBSECTION MappedSubsection,
    _In_ ULONGLONG PteCount)
{
    DPRINT("MiRemoveViewsFromSection: MappedSubsection %p, PteCount %X\n", MappedSubsection, PteCount);

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

            //if (MiUnusedSubsectionPagedPoolPeak < MiUnusedSubsectionPagedPool)
            //    MiUnusedSubsectionPagedPoolPeak = MiUnusedSubsectionPagedPool;
        }

        if (!PteCount)
            continue;

        if (PteCount <= (ULONGLONG)MappedSubsection->PtesInSubsection)
            break;

        PteCount -= MappedSubsection->PtesInSubsection;
    }
}

BOOLEAN
NTAPI
MiCanFileBeTruncatedInternal(
    _In_ PSECTION_OBJECT_POINTERS SectionPointers,
    _In_ OUT PLARGE_INTEGER FileOffset,
    _In_ BOOLEAN IsNotCheckUserReferences,
    _Out_ KIRQL* OutOldIrql)
{
    PCONTROL_AREA ControlArea;
    PSUBSECTION Subsection;
    PMAPPED_FILE_SEGMENT Segment;
    LARGE_INTEGER Offset;
    KIRQL OldIrql;

    DPRINT("MiCanFileBeTruncatedInternal: %p, %X\n", SectionPointers, IsNotCheckUserReferences);

    if (!MmFlushImageSection(SectionPointers, MmFlushForWrite))
    {
        DPRINT("MiCanFileBeTruncatedInternal: return FALSE\n");
        return FALSE;
    }

    OldIrql = MiLockPfnDb(APC_LEVEL);

    ControlArea = SectionPointers->DataSectionObject;
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
        goto Exit;

    ASSERT(ControlArea->u.Flags.Image == 0);
    ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);

    Subsection = (PSUBSECTION)&ControlArea[1];

    if (ControlArea->FilePointer)
    {
        Segment = (PMAPPED_FILE_SEGMENT)ControlArea->Segment;

        if (MiIsAddressValid(Segment) && Segment->LastSubsectionHint)
            Subsection = (PSUBSECTION)Segment->LastSubsectionHint;
    }

    while (Subsection->NextSubsection)
        Subsection = Subsection->NextSubsection;

    ASSERT(Subsection->ControlArea == ControlArea);

    if (Subsection->ControlArea->u.Flags.Image)
    {
        Offset.QuadPart = (Subsection->StartingSector + Subsection->NumberOfFullSectors);
        Offset.QuadPart *= MM_SECTOR_SIZE;
    }
    else
    {
        Offset.HighPart = Subsection->u.SubsectionFlags.StartingSector4132;
        Offset.LowPart = Subsection->StartingSector;

        Offset.QuadPart += Subsection->NumberOfFullSectors;
        Offset.QuadPart *= PAGE_SIZE;
    }

    Offset.QuadPart += Subsection->u.SubsectionFlags.SectorEndOffset;

    if (FileOffset->QuadPart >= Offset.QuadPart)
    {
        Offset.QuadPart += (PAGE_SIZE - 1);
        Offset.LowPart &= ~(PAGE_SIZE - 1);

        if (FileOffset->QuadPart < Offset.QuadPart)
            *FileOffset = Offset;

        *OutOldIrql = OldIrql;

        DPRINT("MiCanFileBeTruncatedInternal: return TRUE\n");
        return TRUE;
    }

Exit:

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    DPRINT("MiCanFileBeTruncatedInternal: return FALSE\n");
    return FALSE;
}

BOOLEAN
NTAPI
MmPurgeSection(
    _In_ PSECTION_OBJECT_POINTERS SectionPointer,
    _In_ PLARGE_INTEGER FileOffset,
    _In_ SIZE_T Length,
    _In_ BOOLEAN IsFullPurge)
{
    PCONTROL_AREA ControlArea;
    PMAPPED_FILE_SEGMENT Segment;
    PSUBSECTION Subsection;
    PSUBSECTION FirstSubsection;
    PSUBSECTION LastSubsection;
    PSUBSECTION TempSubsection;
    PSUBSECTION LastTempSubsection;
    PMSUBSECTION MappedSubsection;
    PLARGE_INTEGER fileOffset;
    PMMPTE SectionProto;
    PMMPTE LastProto;
    PMMPTE lastProto;
    PMMPTE ProtoPte;
    MMPTE TempProto;
    PMMPFN ProtoPfn;
    PMMPFN Pfn;
    LARGE_INTEGER offset;
    ULONGLONG PteOffset;
    ULONG LastPteOffset;
    PFN_NUMBER PageNumber;
    KIRQL OldIrql;
    BOOLEAN IsLock;
    BOOLEAN Result;

    DPRINT("MmPurgeSection: %p, %I64X, %X, %X\n", SectionPointer, (FileOffset?FileOffset->QuadPart:0), Length, IsFullPurge);

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

    if (!MiCanFileBeTruncatedInternal(SectionPointer, fileOffset, TRUE, &OldIrql))
    {
        DPRINT("MmPurgeSection: return FALSE\n");
        return FALSE;
    }

    ControlArea = SectionPointer->DataSectionObject;

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
        for (PteOffset = (fileOffset->QuadPart / PAGE_SIZE);
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
            LastPteOffset -= LastSubsection->PtesInSubsection;

            if (!LastSubsection->NextSubsection)
            {
                LastPteOffset = (LastSubsection->PtesInSubsection - 1);
                break;
            }
        }

        ASSERT(LastPteOffset < (ULONGLONG)LastSubsection->PtesInSubsection);
    }
    else
    {
        LastSubsection = Subsection;
        Segment = (PMAPPED_FILE_SEGMENT)ControlArea->Segment;

        if (MiIsAddressValid(Segment) &&
            Segment->LastSubsectionHint)
        {
            LastSubsection = (PSUBSECTION)Segment->LastSubsectionHint;
        }

        while (LastSubsection->NextSubsection)
            LastSubsection = LastSubsection->NextSubsection;

        LastPteOffset = (LastSubsection->PtesInSubsection - 1);
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

            if (MiReferenceSubsection((PMSUBSECTION)Subsection))
            {
                SectionProto = Subsection->SubsectionBase;
                break;
            }
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

        TempSubsection = Subsection->NextSubsection;
        LastTempSubsection = NULL;

        while (TempSubsection != LastSubsection)
        {
            ASSERT(TempSubsection != NULL);

            if ((PMSUBSECTION)TempSubsection->SubsectionBase)
                LastTempSubsection = TempSubsection;

            TempSubsection = TempSubsection->NextSubsection;
        }

        if (!LastTempSubsection)
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
            DPRINT1("MmPurgeSection: FIXME\n");
            ASSERT(FALSE);
        }

        ASSERT(TempSubsection->SubsectionBase != NULL);

        LastSubsection = TempSubsection;
        LastPteOffset = LastSubsection->PtesInSubsection - 1;
    }

    lastProto = &LastSubsection->SubsectionBase[LastPteOffset + 1];

    ControlArea->NumberOfMappedViews++;

    ControlArea->u.Flags.BeingPurged = 1;
    ControlArea->u.Flags.WasPurged = 1;

    Result = TRUE;

    while (TRUE)
    {
        DPRINT("MmPurgeSection: SectionProto %p\n", SectionProto);

        if (OldIrql == MM_NOIRQL)
            OldIrql = MiLockPfnDb(APC_LEVEL);

        if (Subsection == LastSubsection)
            LastProto = lastProto;
        else
            LastProto = &Subsection->SubsectionBase[Subsection->PtesInSubsection];

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
            SectionProto = (PMMPTE)(((ULONG_PTR)SectionProto | (PAGE_SIZE - 1)) + 1);

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
                        DPRINT1("MmPurgeSection: FIXME\n");
                        ASSERT(FALSE);
                        //MiMakeSystemAddressValidPfn(SectionProto, OldIrql);
                    }

                    continue;
                }

                ProtoPfn = MI_PFN_ELEMENT(TempProto.u.Hard.PageFrameNumber);

                if (!ProtoPfn->OriginalPte.u.Soft.Prototype ||
                    ProtoPfn->OriginalPte.u.Hard.Valid ||
                    ProtoPfn->PteAddress != SectionProto)
                {
                    DPRINT1("MmPurgeSection: FIXME KeBugCheckEx()\n");
                    ASSERT(FALSE);
                }

                if (ProtoPfn->u3.e1.WriteInProgress)
                {
                    DPRINT1("MmPurgeSection: FIXME\n");
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

                PageNumber = ProtoPfn->u4.PteFrame;
                Pfn = MI_PFN_ELEMENT(PageNumber);
                MiDecrementPfnShare(Pfn, PageNumber);

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
            OldIrql = MiLockPfnDb(APC_LEVEL);

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

        if (LastSubsection == Subsection || !Result)
            break;

        Subsection = Subsection->NextSubsection;
        SectionProto = Subsection->SubsectionBase;
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

BOOLEAN
NTAPI
MiCheckControlAreaStatus(
    _In_ ULONG Type,
    _In_ PSECTION_OBJECT_POINTERS SectionPointers,
    _In_ BOOLEAN IsDeleteOnClose,
    _Out_ PCONTROL_AREA* OutControlArea,
    _Out_ KIRQL* OutOldIrql)
{
    PCONTROL_AREA ControlArea;
    ULONG NumberOfReferences;
    KIRQL OldIrql;

    DPRINT("MiCheckControlAreaStatus: %X, %p, %X\n", Type, SectionPointers, IsDeleteOnClose);

    *OutControlArea = NULL;

    // FIXME SegmentEvent

    OldIrql = MiLockPfnDb(APC_LEVEL);

    if (Type == 1)
        ControlArea = SectionPointers->ImageSectionObject;
    else
        ControlArea = SectionPointers->DataSectionObject;

    DPRINT("MiCheckControlAreaStatus: ControlArea %p\n", ControlArea);

    if (ControlArea)
    {
        if (Type == 2)
            NumberOfReferences = ControlArea->NumberOfUserReferences;
        else
            NumberOfReferences = ControlArea->NumberOfSectionReferences;
    }
    else
    {
        if (Type == 3)
        {
            ControlArea = SectionPointers->ImageSectionObject;
            if (!ControlArea)
            {
                MiUnlockPfnDb(OldIrql, APC_LEVEL);
                // FIXME SegmentEvent
                return TRUE;
            }

            NumberOfReferences = ControlArea->NumberOfSectionReferences;
        }
        else
        {
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            // FIXME SegmentEvent
            return TRUE;
        }
    }

    if (NumberOfReferences ||
        ControlArea->NumberOfMappedViews ||
        ControlArea->u.Flags.BeingCreated)
    {
        if (IsDeleteOnClose)
            ControlArea->u.Flags.DeleteOnClose = 1;

        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        // FIXME SegmentEvent
        return FALSE;
    }

    // FIXME SegmentEvent

    if (ControlArea->u.Flags.BeingDeleted)
    {
        DPRINT1("MiCheckControlAreaStatus: FIXME\n");
        ASSERT(FALSE);
        return TRUE;
    }

    DPRINT("MiCheckControlAreaStatus: FIXME EventCounter\n");
    //ASSERT(FALSE);

    *OutControlArea = ControlArea;
    *OutOldIrql = OldIrql;

    return FALSE;
}

NTSTATUS
NTAPI
MiQueryMemorySectionName(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _Out_ PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_ SIZE_T* ReturnLength)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

BOOLEAN
NTAPI
MiAppendSubsectionChain(
    _In_ PMSUBSECTION LastSubsection,
    _In_ PMSUBSECTION ExtendedSubsectionHead)
{
    PMSUBSECTION NewSubsection;
    KIRQL OldIrql;

    DPRINT("MiAppendSubsectionChain()\n");

    ASSERT(ExtendedSubsectionHead->NextSubsection != NULL);
    ASSERT(ExtendedSubsectionHead->u.SubsectionFlags.SectorEndOffset == 0);

    NewSubsection = (PMSUBSECTION)ExtendedSubsectionHead->NextSubsection;

    OldIrql = MiLockPfnDb(APC_LEVEL);

    if (!NewSubsection->SubsectionBase)
    {
        if (!LastSubsection->ControlArea->NumberOfUserReferences)
            goto Finish;

        ASSERT(NewSubsection->u.SubsectionFlags.SubsectionStatic == 0);
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        return FALSE;
    }

    if (LastSubsection->ControlArea->NumberOfUserReferences)
        goto Finish;

    while (NewSubsection);
    {
        ASSERT(NewSubsection->u.SubsectionFlags.SubsectionStatic == 1);

        NewSubsection->u.SubsectionFlags.SubsectionStatic = 0;
        NewSubsection->u2.SubsectionFlags2.SubsectionConverted = 1;
        NewSubsection->NumberOfMappedViews = 1;

        MiRemoveViewsFromSection(NewSubsection, NewSubsection->PtesInSubsection);

        NewSubsection = (PMSUBSECTION)NewSubsection->NextSubsection;
    }

Finish:

    LastSubsection->u.SubsectionFlags.SectorEndOffset = 0;
    LastSubsection->NumberOfFullSectors = ExtendedSubsectionHead->NumberOfFullSectors;
    LastSubsection->NextSubsection = ExtendedSubsectionHead->NextSubsection;

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    return TRUE;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmExtendSection(
    _In_ PSECTION Section,
    _Inout_ LARGE_INTEGER* OutSectionSize,
    _In_ BOOLEAN IgnoreFileSizeChecking)
{
    PKTHREAD CurrentThread = KeGetCurrentThread();
    PSEGMENT Segment = Section->Segment;
    PCONTROL_AREA ControlArea = Segment->ControlArea;
    MSUBSECTION FirstExtendSubsection;
    PMSUBSECTION LastExtendSubsection;
    PMSUBSECTION ExtendSubsection;
    PSUBSECTION Subsection;
    PSUBSECTION LastSubsection;
    PMMPTE SectionProtos;
    MMPTE TempPte;
    LARGE_INTEGER SegmentPages;
    LARGE_INTEGER Last4KChunk;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER Start1;
    LARGE_INTEGER Start2;
    UINT64 AllocationSize;
    UINT64 NeedPages;
    UINT64 TotalPtes;
    UINT64 NewPages;
    UINT64 Size;
    SIZE_T AllocationFragment;
    ULONG FragmentSize;
    ULONG UnusedPtes;
    ULONG UsedPtes;
    BOOLEAN Appended;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("MmExtendSection: Section %X, OutSectionSize %I64X, IgnoreFileSizeChecking %X\n",
           Section, OutSectionSize->QuadPart, IgnoreFileSizeChecking);

    if (ControlArea->u.Flags.PhysicalMemory)
    {
        DPRINT1("MmExtendSection: STATUS_SECTION_NOT_EXTENDED\n");
        return STATUS_SECTION_NOT_EXTENDED;
    }

    if (ControlArea->u.Flags.Image)
    {
        DPRINT1("MmExtendSection: STATUS_SECTION_NOT_EXTENDED\n");
        return STATUS_SECTION_NOT_EXTENDED;
    }

    if (!ControlArea->FilePointer)
    {
        DPRINT1("MmExtendSection: STATUS_SECTION_NOT_EXTENDED\n");
        return STATUS_SECTION_NOT_EXTENDED;
    }

    KeEnterCriticalRegionThread(CurrentThread);
    ExAcquireResourceExclusiveLite(&MmSectionExtendResource, TRUE);

    if (OutSectionSize->QuadPart > ((16 * _1PB) - PAGE_SIZE)) // 0x003FFFFF FFFFF000
    {
        ExReleaseResourceLite(&MmSectionExtendResource);
        KeLeaveCriticalRegionThread(CurrentThread);

        DPRINT1("MmExtendSection: STATUS_SECTION_TOO_BIG\n");
        return STATUS_SECTION_TOO_BIG;
    }

    NeedPages = ((OutSectionSize->QuadPart + (PAGE_SIZE - 1)) / PAGE_SIZE);

    if (!ControlArea->u.Flags.WasPurged &&
        OutSectionSize->QuadPart <= Section->SizeOfSection.QuadPart)
    {
        OutSectionSize->QuadPart = Section->SizeOfSection.QuadPart;

        ExReleaseResourceLite(&MmSectionExtendResource);
        KeLeaveCriticalRegionThread(CurrentThread);
        return STATUS_SUCCESS;
    }

    if (!IgnoreFileSizeChecking)
    {
        ExReleaseResourceLite(&MmSectionExtendResource);
        ExAcquireResourceExclusiveLite(&MmSectionExtendSetResource, TRUE);

        Status = FsRtlGetFileSize(ControlArea->FilePointer, &FileSize);
        if (!NT_SUCCESS(Status))
        {
            ExReleaseResourceLite(&MmSectionExtendSetResource);
            KeLeaveCriticalRegionThread(CurrentThread);

            DPRINT1("MmExtendSection: Status %X\n", Status);
            return Status;
        }

        if (OutSectionSize->QuadPart > FileSize.QuadPart)
        {
            if (!((Section->InitialPageProtection & PAGE_READWRITE) |
                  (Section->InitialPageProtection & PAGE_EXECUTE_READWRITE)))
            {
                ExReleaseResourceLite(&MmSectionExtendSetResource);
                KeLeaveCriticalRegionThread(CurrentThread);

                DPRINT1("MmExtendSection: STATUS_SECTION_NOT_EXTENDED\n");
                return STATUS_SECTION_NOT_EXTENDED;
            }

            FileSize.QuadPart = OutSectionSize->QuadPart;

            Status = FsRtlSetFileSize(ControlArea->FilePointer, &FileSize);
            if (!NT_SUCCESS(Status))
            {
                ExReleaseResourceLite(&MmSectionExtendSetResource);
                KeLeaveCriticalRegionThread(CurrentThread);

                DPRINT1("MmExtendSection: Status %X\n", Status);
                return Status;
            }
        }

        if (Segment->ExtendInfo)
        {
            KeAcquireGuardedMutex(&MmSectionBasedMutex);

            if (Segment->ExtendInfo)
                Segment->ExtendInfo->CommittedSize = FileSize.QuadPart;

            KeReleaseGuardedMutex(&MmSectionBasedMutex);
        }

        ExReleaseResourceLite(&MmSectionExtendSetResource);
        ExAcquireResourceExclusiveLite(&MmSectionExtendResource, TRUE);
    }

    ASSERT(ControlArea->u.Flags.GlobalOnlyPerSession == 0);

    if (((PMAPPED_FILE_SEGMENT)Segment)->LastSubsectionHint)
        LastSubsection = (PSUBSECTION)((PMAPPED_FILE_SEGMENT)Segment)->LastSubsectionHint;
    else if (ControlArea->u.Flags.Rom)
        LastSubsection = (PSUBSECTION)((PLARGE_CONTROL_AREA)ControlArea + 1);
    else
        LastSubsection = (PSUBSECTION)(ControlArea + 1);

    while (LastSubsection->NextSubsection)
    {
        ASSERT(LastSubsection->UnusedPtes == 0);
        LastSubsection = LastSubsection->NextSubsection;
    }

    MiSubsectionConsistent(LastSubsection);

    TotalPtes = ((((ULONGLONG)Segment->SegmentFlags.TotalNumberOfPtes4132) << 32) | Segment->TotalNumberOfPtes);

    if (NeedPages <= TotalPtes)
    {
        Section->SizeOfSection.QuadPart = OutSectionSize->QuadPart;

        if (Segment->SizeOfSegment < OutSectionSize->QuadPart)
        {
            Segment->SizeOfSegment = OutSectionSize->QuadPart;

            Start1.LowPart = LastSubsection->StartingSector;
            Start1.HighPart = LastSubsection->u.SubsectionFlags.StartingSector4132;

            Last4KChunk.QuadPart = ((OutSectionSize->QuadPart / PAGE_SIZE) - Start1.QuadPart);
            ASSERT(Last4KChunk.HighPart == 0);

            LastSubsection->NumberOfFullSectors = Last4KChunk.LowPart;
            LastSubsection->u.SubsectionFlags.SectorEndOffset = (OutSectionSize->LowPart & (PAGE_SIZE - 1));

            MiSubsectionConsistent(LastSubsection);
        }

        ExReleaseResourceLite(&MmSectionExtendResource);
        KeLeaveCriticalRegionThread(CurrentThread);
        return STATUS_SUCCESS;
    }

    NewPages = (NeedPages - TotalPtes);

    if (NewPages >= LastSubsection->UnusedPtes)
    {
        UsedPtes = LastSubsection->UnusedPtes;
        NewPages -= UsedPtes;
    }
    else
    {
        UsedPtes = NewPages;
        NewPages = 0;
    }

    LastSubsection->PtesInSubsection += UsedPtes;
    LastSubsection->UnusedPtes -= UsedPtes;

    Segment->SizeOfSegment += (UsedPtes * PAGE_SIZE);

    TotalPtes += UsedPtes;
    Segment->TotalNumberOfPtes = TotalPtes;

    if (TotalPtes >= 0x100000000)
        Segment->SegmentFlags.TotalNumberOfPtes4132 = (TotalPtes >> 32);

    if (!NewPages)
    {
        Start1.LowPart = LastSubsection->StartingSector;
        Start1.HighPart = LastSubsection->u.SubsectionFlags.StartingSector4132;

        Last4KChunk.QuadPart = ((OutSectionSize->QuadPart / PAGE_SIZE) - Start1.QuadPart);
        ASSERT(Last4KChunk.HighPart == 0);

        LastSubsection->NumberOfFullSectors = Last4KChunk.LowPart;

        LastSubsection->u.SubsectionFlags.SectorEndOffset = (OutSectionSize->LowPart & (PAGE_SIZE - 1));
        MiSubsectionConsistent(LastSubsection);

        Segment->SizeOfSegment = OutSectionSize->QuadPart;
        Section->SizeOfSection.QuadPart = OutSectionSize->QuadPart;

        ExReleaseResourceLite(&MmSectionExtendResource);
        KeLeaveCriticalRegionThread(CurrentThread);
        return STATUS_SUCCESS;
    }

    SegmentPages.QuadPart = (Segment->SizeOfSegment / PAGE_SIZE);

    AllocationSize = (((NewPages * sizeof(MMPTE)) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1));
    AllocationFragment = MmAllocationFragment;

    RtlCopyMemory(&FirstExtendSubsection, LastSubsection, sizeof(FirstExtendSubsection));

    LastExtendSubsection = &FirstExtendSubsection;
    ASSERT(LastExtendSubsection->NextSubsection == NULL);

    Size = 0;

    do
    {
        ExtendSubsection = ExAllocatePoolWithTag(NonPagedPool, sizeof(MSUBSECTION), 'dSmM');
        if (!ExtendSubsection)
        {
            DPRINT1("MmExtendSection: STATUS_INSUFFICIENT_RESOURCES\n");
            goto ErrorExit;
        }

        ExtendSubsection->SubsectionBase = NULL;
        ExtendSubsection->NextSubsection = NULL;

        LastExtendSubsection->NextSubsection = (PSUBSECTION)ExtendSubsection;

        ASSERT(ControlArea->FilePointer != NULL);

        if (AllocationSize - Size > AllocationFragment)
            FragmentSize = (ULONG)AllocationFragment;
        else
            FragmentSize = (ULONG)(AllocationSize - Size);

        ExtendSubsection->u.LongFlags = 0;
        ExtendSubsection->ControlArea = ControlArea;
        ExtendSubsection->PtesInSubsection = FragmentSize / sizeof(MMPTE);
        ExtendSubsection->UnusedPtes = 0;

        Size += FragmentSize;

        if (Size > (NewPages * sizeof(MMPTE)))
        {
            UnusedPtes = (Size / sizeof(MMPTE) - NewPages);
            ExtendSubsection->PtesInSubsection -= UnusedPtes;
            ExtendSubsection->UnusedPtes = UnusedPtes;
        }

        ExtendSubsection->u.SubsectionFlags.Protection = Segment->SegmentPteTemplate.u.Soft.Protection;

        ExtendSubsection->DereferenceList.Flink = NULL;
        ExtendSubsection->DereferenceList.Blink = NULL;
        ExtendSubsection->NumberOfMappedViews = 0;
        ExtendSubsection->u2.LongFlags2 = 0;

        if (LastExtendSubsection == &FirstExtendSubsection)
        {
            Start1.LowPart = LastExtendSubsection->StartingSector;
            Start1.HighPart = LastExtendSubsection->u.SubsectionFlags.StartingSector4132;

            Last4KChunk.QuadPart = (SegmentPages.QuadPart - Start1.QuadPart);

            if (LastExtendSubsection->u.SubsectionFlags.SectorEndOffset)
                Last4KChunk.QuadPart++;

            ASSERT(Last4KChunk.HighPart == 0);
            LastExtendSubsection->u.SubsectionFlags.SectorEndOffset = 0;

            LastExtendSubsection->NumberOfFullSectors = Last4KChunk.LowPart;

            MiSubsectionConsistent((PSUBSECTION)LastExtendSubsection);

            Start1.QuadPart += LastExtendSubsection->NumberOfFullSectors;
            Start2.QuadPart = Start1.QuadPart;
        }
        else
        {
            Start2.QuadPart += LastExtendSubsection->NumberOfFullSectors;
        }

        ExtendSubsection->StartingSector = Start2.LowPart;
        ExtendSubsection->u.SubsectionFlags.StartingSector4132 = (Start2.HighPart & (0x400 - 1));

        if (Size >= AllocationSize)
        {
            Last4KChunk.QuadPart = ((OutSectionSize->QuadPart / PAGE_SIZE) - Start2.QuadPart);
            ASSERT(Last4KChunk.HighPart == 0);

            ExtendSubsection->NumberOfFullSectors = Last4KChunk.LowPart;
            ExtendSubsection->u.SubsectionFlags.SectorEndOffset = (OutSectionSize->LowPart & (PAGE_SIZE - 1));
        }
        else
        {
            ExtendSubsection->NumberOfFullSectors = (FragmentSize / sizeof(MMPTE));
            ExtendSubsection->u.SubsectionFlags.SectorEndOffset = 0;
        }

        MiSubsectionConsistent((PSUBSECTION)ExtendSubsection);
        LastExtendSubsection = ExtendSubsection;
    }
    while (Size < AllocationSize);

    if (!ControlArea->NumberOfUserReferences)
    {
        ASSERT(IgnoreFileSizeChecking == TRUE);
    }

    Appended = MiAppendSubsectionChain((PMSUBSECTION)LastSubsection, &FirstExtendSubsection);

    if (!Appended)
    {
        Size = 0;

        Subsection = (PSUBSECTION)&FirstExtendSubsection;

        do
        {
            if (AllocationSize - Size > AllocationFragment)
                FragmentSize = (ULONG)AllocationFragment;
            else
                FragmentSize = (ULONG)(AllocationSize - Size);

            Size += FragmentSize;

            SectionProtos = ExAllocatePoolWithTag(PagedPool, FragmentSize, 'tSmM'); // (PagedPool | 0x80000000)
            if (!SectionProtos)
            {
                DPRINT1("MmExtendSection: STATUS_INSUFFICIENT_RESOURCES\n");
                goto ErrorExit;
            }

            Subsection = Subsection->NextSubsection;

            Subsection->SubsectionBase = SectionProtos;
            Subsection->u.SubsectionFlags.SubsectionStatic = 1;

            MI_MAKE_SUBSECTION_PTE(&TempPte, Subsection);

            TempPte.u.Soft.Prototype = 1;
            TempPte.u.Soft.Protection = Segment->SegmentPteTemplate.u.Soft.Protection;

            RtlFillMemoryUlong(SectionProtos, FragmentSize, TempPte.u.Long);
        }
        while (Size < AllocationSize);

        ASSERT(ControlArea->DereferenceList.Flink == NULL);

        Appended = MiAppendSubsectionChain((PMSUBSECTION)LastSubsection, &FirstExtendSubsection);
        ASSERT(Appended == TRUE);
    }

    TotalPtes += NewPages;

    Segment->TotalNumberOfPtes = (ULONG)TotalPtes;

    if (TotalPtes >= 0x100000000)
        Segment->SegmentFlags.TotalNumberOfPtes4132 = (TotalPtes >> 32);

    if (LastExtendSubsection != &FirstExtendSubsection)
        ((PMAPPED_FILE_SEGMENT)Segment)->LastSubsectionHint = LastExtendSubsection;

    Segment->SizeOfSegment = *(PULONGLONG)OutSectionSize;
    Section->SizeOfSection = *OutSectionSize;

    ExReleaseResourceLite(&MmSectionExtendResource);
    KeLeaveCriticalRegionThread(CurrentThread);
    return STATUS_SUCCESS;

ErrorExit:

    LastSubsection->PtesInSubsection -= UsedPtes;
    LastSubsection->UnusedPtes += UsedPtes;

    TotalPtes -= UsedPtes;
    Segment->SegmentFlags.TotalNumberOfPtes4132 = 0;

    Segment->TotalNumberOfPtes = TotalPtes;

    if (TotalPtes >= 0x100000000)
        Segment->SegmentFlags.TotalNumberOfPtes4132 = (TotalPtes >> 32);

    Segment->SizeOfSegment -= (UsedPtes * PAGE_SIZE);
    LastSubsection = FirstExtendSubsection.NextSubsection;

    while (LastSubsection)
    {
        Subsection = LastSubsection->NextSubsection;

        if (LastSubsection->SubsectionBase)
            ExFreePool(LastSubsection->SubsectionBase);

        ExFreePool(LastSubsection);

        LastSubsection = Subsection;
    }

    ExReleaseResourceLite(&MmSectionExtendResource);
    KeLeaveCriticalRegionThread(CurrentThread);

    return STATUS_INSUFFICIENT_RESOURCES;
}

VOID
NTAPI
MiCheckForControlAreaDeletion(
    _In_ PCONTROL_AREA ControlArea)
{
    DPRINT("MiCheckForControlAreaDeletion: ControlArea %p\n", ControlArea);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(MmPfnOwner == KeGetCurrentThread());

    if (ControlArea->NumberOfPfnReferences ||
        ControlArea->NumberOfMappedViews ||
        ControlArea->NumberOfSectionReferences)
    {
        return;
    }

    ControlArea->u.Flags.BeingDeleted = 1;

    ASSERT(ControlArea->u.Flags.FilePointerNull == 0);
    ControlArea->u.Flags.FilePointerNull = 1;

    if (ControlArea->u.Flags.Image)
        MiRemoveImageSectionObject(ControlArea->FilePointer, (PLARGE_CONTROL_AREA)ControlArea);
    else
        ControlArea->FilePointer->SectionObjectPointer->DataSectionObject = NULL;

    if (ControlArea->DereferenceList.Flink)
    {
        RemoveEntryList(&ControlArea->DereferenceList);
        MmUnusedSegmentCount--;
    }

    DPRINT("MiCheckForControlAreaDeletion: FIXME MmDereferenceSegmentHeader (paging)\n");
}

VOID
NTAPI
MmpDeleteSection(
    _In_ PVOID ObjectBody)
{
    PSECTION Section = ObjectBody;
    PCONTROL_AREA ControlArea;

    DPRINT("MmpDeleteSection: Section %p\n", Section);

    if (!Section->Segment)
    {
        DPRINT("MmpDeleteSection: Segment is NULL\n");
        return;
    }

    ControlArea = Section->Segment->ControlArea;

    if (Section->Address.StartingVpn)
    {
        DPRINT1("MmpDeleteSection: FIXME! Section %p\n", Section);
        ASSERT(FALSE);
#if 0
        KeAcquireGuardedMutex(&MmSectionBasedMutex);
        MiRemoveNode(&Section->Address, &MmSectionBasedRoot);
        KeReleaseGuardedMutex(&MmSectionBasedMutex);
#endif
    }

    if (Section->u.Flags.UserWritable &&
        !ControlArea->u.Flags.Image &&
        ControlArea->FilePointer)
    {
        ASSERT(Section->InitialPageProtection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE));
        InterlockedDecrement((PLONG)&ControlArea->WritableUserReferences);
    }

    MiDereferenceControlAreaBySection(ControlArea, Section->u.Flags.UserReference);
}

VOID
NTAPI
MmpCloseSection(
    _In_ PEPROCESS Process OPTIONAL,
    _In_ PVOID Object,
    _In_ ACCESS_MASK GrantedAccess,
    _In_ ULONG ProcessHandleCount,
    _In_ ULONG SystemHandleCount)
{
    DPRINT("MmpCloseSection(OB %p, HC %lu)\n", Object, ProcessHandleCount);
}

CODE_SEG("INIT")
NTSTATUS
NTAPI
MmCreatePhysicalMemorySection(VOID)
{
    UNICODE_STRING PhysicalMemoryName = RTL_CONSTANT_STRING(L"\\Device\\PhysicalMemory");
    OBJECT_ATTRIBUTES ObjectAttributes;
    PCONTROL_AREA ControlArea;
    PSECTION PhysSection;
    PSEGMENT Segment;
    HANDLE Handle;
    NTSTATUS Status;

    DPRINT("MmCreatePhysicalMemorySection()\n");

    /* Create the section mapping physical memory */
    Segment = ExAllocatePoolWithTag(PagedPool, sizeof(*Segment), 'gSmM');
    if (!Segment)
    {
        DPRINT1("MmCreatePhysicalMemorySection: allocate failed!\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ControlArea = ExAllocatePoolWithTag(NonPagedPool, sizeof(*ControlArea), 'aCmM');
    if (!ControlArea)
    {
        DPRINT1("MmCreatePhysicalMemorySection: allocate failed!\n");
        ExFreePoolWithTag(Segment, 'gSmM');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Segment, sizeof(*Segment));
    RtlZeroMemory(ControlArea, sizeof(*ControlArea));

    ControlArea->Segment = Segment;
    ControlArea->NumberOfSectionReferences = 1;
    ControlArea->u.Flags.PhysicalMemory = 1;

    Segment->ControlArea = ControlArea;
    Segment->SegmentPteTemplate.u.Long = 0;

    InitializeObjectAttributes(&ObjectAttributes,
                               &PhysicalMemoryName,
                               (OBJ_KERNEL_EXCLUSIVE | OBJ_PERMANENT),
                               NULL,
                               NULL);

    Status = ObCreateObject(KernelMode,
                            MmSectionObjectType,
                            &ObjectAttributes,
                            KernelMode,
                            NULL,
                            sizeof(*PhysSection),
                            sizeof(*PhysSection),
                            0,
                            (PVOID *)&PhysSection);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MmCreatePhysicalMemorySection: Status %X\n", Status);
        ExFreePoolWithTag(ControlArea, 'aCmM');
        ExFreePoolWithTag(Segment, 'gSmM');
        return Status;
    }

  #ifdef _WIN64
    #error FIXME
  #else
    PhysSection->SizeOfSection.QuadPart = 0xFFFFFFFF;
  #endif

    PhysSection->Segment = Segment;
    PhysSection->u.LongFlags = 0;
    PhysSection->InitialPageProtection = PAGE_EXECUTE_READWRITE;

    Status = ObInsertObject(PhysSection,
                            NULL,
                            SECTION_MAP_READ,
                            0,
                            NULL,
                            &Handle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MmCreatePhysicalMemorySection: Status %X\n", Status);
        return Status;
    }

    Status = NtClose(Handle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MmCreatePhysicalMemorySection: Status %X\n", Status);
    }

    return Status;
}

VOID
NTAPI
MiDereferenceSegmentThread(
    _In_ PVOID StartContext)
{
    UNIMPLEMENTED;
}

CODE_SEG("INIT")
NTSTATUS
NTAPI
MmInitSectionImplementation(VOID)
{
    OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING SectionName = RTL_CONSTANT_STRING(L"Section");
    HANDLE ThreadHandle;
    NTSTATUS Status;

    DPRINT("MmInitSectionImplementation: Creating Section Object Type\n");

    /* Initialize the section based root */
    ASSERT(MmSectionBasedRoot.NumberGenericTableElements == 0);
    MmSectionBasedRoot.BalancedRoot.u1.Parent = &MmSectionBasedRoot.BalancedRoot;

    /* Initialize the Section object type  */
    RtlZeroMemory(&ObjectTypeInitializer, sizeof(ObjectTypeInitializer));

    ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
    ObjectTypeInitializer.DefaultPagedPoolCharge = sizeof(SECTION);
    ObjectTypeInitializer.PoolType = PagedPool;
    ObjectTypeInitializer.UseDefaultObject = TRUE;
    ObjectTypeInitializer.GenericMapping = MmpSectionMapping;
    ObjectTypeInitializer.DeleteProcedure = MmpDeleteSection;
    ObjectTypeInitializer.CloseProcedure = MmpCloseSection;
    ObjectTypeInitializer.ValidAccessMask = SECTION_ALL_ACCESS;
    ObjectTypeInitializer.InvalidAttributes = OBJ_OPENLINK;

    Status = ObCreateObjectType(&SectionName, &ObjectTypeInitializer, NULL, &MmSectionObjectType);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MmInitSectionImplementation: Status %X\n", Status);
        return Status;
    }

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    Status = PsCreateSystemThread(&ThreadHandle,
                                  THREAD_ALL_ACCESS,
                                  &ObjectAttributes,
                                  0,
                                  NULL,
                                  MiDereferenceSegmentThread,
                                  NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MmInitSectionImplementation: Status %X\n", Status);
        return Status;
    }

    ZwClose(ThreadHandle);

    Status = MmCreatePhysicalMemorySection();
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MmInitSectionImplementation: Status %X\n", Status);
    }

    return Status;
}

/* PUBLIC FUNCTIONS ***********************************************************/

BOOLEAN
NTAPI
MmCanFileBeTruncated(
    _In_ PSECTION_OBJECT_POINTERS SectionPointers,
    _In_ PLARGE_INTEGER NewFileSize)
{
    LARGE_INTEGER fileSize;
    KIRQL OldIrql;

    DPRINT("MmCanFileBeTruncated: %p, [%I64X]\n", SectionPointers, (NewFileSize ? NewFileSize->QuadPart : 0LL));

    if (NewFileSize)
    {
        fileSize.QuadPart = NewFileSize->QuadPart;
        NewFileSize = &fileSize;
    }

    if (MiCanFileBeTruncatedInternal(SectionPointers, NewFileSize, FALSE, &OldIrql))
    {
        MiUnlockPfnDb(OldIrql, APC_LEVEL);
        DPRINT("MmCanFileBeTruncated: return TRUE\n");
        return TRUE;
    }

    DPRINT("MmCanFileBeTruncated: return FALSE\n");
    return FALSE;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmCommitSessionMappedView(
    _In_ PVOID MappedBase,
    _In_ SIZE_T ViewSize)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
MmCreateSection(
    _Out_ PVOID* SectionObject,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    _In_ PLARGE_INTEGER InputMaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_ HANDLE FileHandle OPTIONAL,
    _In_ PFILE_OBJECT FileObject OPTIONAL)
{
    PVOID PreviousSectionPointer = NULL;
    PVOID NewControlArea = NULL;
    PCONTROL_AREA ControlArea;
    PSEGMENT NewSegment = NULL;
    PSEGMENT Segment = NULL;
    PSUBSECTION Subsection;
    PEVENT_COUNTER EventCounter;
    PEVENT_COUNTER NewEventCounter = NULL;
    SECTION Section;
    PSECTION NewSection;
    PFILE_OBJECT File;
    PFILE_OBJECT ControlAreaFile;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER NewSectionSize;
    ULONG ControlAreaSize;
    ULONG ProtectionMask;
    ULONG SubsectionSize;
    ULONG NonPagedCharge;
    ULONG PagedCharge;
    KIRQL OldIrql;
    BOOLEAN UserRefIncremented = FALSE;
    BOOLEAN FileLock = FALSE;
    BOOLEAN IgnoreFileSizing = FALSE; // TRUE if CC call (FileObject != NULL)
    BOOLEAN IsSectionSizeChanged = FALSE;
    BOOLEAN IsGlobal;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    NTSTATUS Status;

    DPRINT("MmCreateSection: %X, %X, %I64X, %X, %X, %p, %p\n", DesiredAccess, ObjectAttributes,
           InputMaximumSize->QuadPart, SectionPageProtection, AllocationAttributes, FileHandle, FileObject);

    /* Make the same sanity checks that the Nt interface should've validated */
    ASSERT((AllocationAttributes & ~(SEC_COMMIT | SEC_RESERVE | SEC_BASED | SEC_LARGE_PAGES |
                                     SEC_IMAGE | SEC_NOCACHE | SEC_NO_CHANGE)) == 0);

    ASSERT((AllocationAttributes & (SEC_COMMIT | SEC_RESERVE | SEC_IMAGE)) != 0);

    ASSERT(!((AllocationAttributes & SEC_IMAGE) &&
             (AllocationAttributes & (SEC_COMMIT | SEC_RESERVE | SEC_NOCACHE | SEC_NO_CHANGE))));

    ASSERT(!((AllocationAttributes & SEC_COMMIT) && (AllocationAttributes & SEC_RESERVE)));

    ASSERT(!((SectionPageProtection & PAGE_NOCACHE) ||
             (SectionPageProtection & PAGE_WRITECOMBINE) ||
             (SectionPageProtection & PAGE_GUARD) ||
             (SectionPageProtection & PAGE_NOACCESS)));

    /* Convert section flag to page flag */
    if (AllocationAttributes & SEC_NOCACHE)
        SectionPageProtection |= PAGE_NOCACHE;

    /* Check to make sure the protection is correct. Nt* does this already */
    ProtectionMask = MiMakeProtectionMask(SectionPageProtection);
    if (ProtectionMask == MM_INVALID_PROTECTION)
    {
        DPRINT1("MmCreateSection: STATUS_INVALID_PAGE_PROTECTION\n");
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    /* Check if this is going to be a data or image backed file section */
    if (FileHandle || FileObject)
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
                ControlAreaFile = NULL;

                OldIrql = MiLockPfnDb(APC_LEVEL);

                ControlArea = (PCONTROL_AREA)(File->SectionObjectPointer->DataSectionObject);

                if (ControlArea &&
                    !ControlArea->u.Flags.BeingDeleted &&
                    !ControlArea->u.Flags.BeingCreated)
                {
                    NewSegment = ControlArea->Segment;

                    if (!ControlArea->NumberOfSectionReferences &&
                        !ControlArea->NumberOfMappedViews &&
                        !ControlArea->ModifiedWriteCount)
                    {
                        ASSERT(ControlArea->FilePointer != NULL);

                        ControlAreaFile = ControlArea->FilePointer;
                        ControlArea->FilePointer = FileObject;
                    }

                    ControlArea->u.Flags.Accessed = 1;
                    ControlArea->NumberOfSectionReferences++;

                    if (ControlArea->DereferenceList.Flink)
                    {
                        RemoveEntryList(&ControlArea->DereferenceList);

                        DPRINT("MmCreateSection: FIXME MmUnusedSegmentCount\n");

                        ControlArea->DereferenceList.Flink = NULL;
                        ControlArea->DereferenceList.Blink = NULL;
                    }

                    MiUnlockPfnDb(OldIrql, APC_LEVEL);

                    if (ControlAreaFile)
                    {
                        ObDereferenceObjectDeferDelete(ControlAreaFile);
                        ObReferenceObject(FileObject);
                    }

                    UserRefIncremented = TRUE;
                    Section.SizeOfSection.QuadPart = InputMaximumSize->QuadPart;

                    goto Finish;
                }

                MiUnlockPfnDb(OldIrql, APC_LEVEL);
            }

            ObReferenceObject(FileObject);
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
                /* Find control area for image-file backed section */
                ControlArea = MiFindImageSectionObject(File, TRUE, &IsGlobal);
            else
                /* Get control area from file */
                ControlArea = (PCONTROL_AREA)File->SectionObjectPointer->DataSectionObject;

            if (!ControlArea)
            {
                /* Write down that this CA is being created, and set it */
                ControlArea = NewControlArea;
                ControlArea->u.Flags.BeingCreated = 1;

                if (AllocationAttributes & SEC_IMAGE)
                {
                    if (IsGlobal)
                        ControlArea->u.Flags.GlobalOnlyPerSession = 1;

                    MiInsertImageSectionObject(File, (PLARGE_CONTROL_AREA)NewControlArea);
                }
                else
                {
                    PreviousSectionPointer = File->SectionObjectPointer;
                    File->SectionObjectPointer->DataSectionObject = ControlArea;
                }

                break;
            }
            else
            {
                if (ControlArea->u.Flags.BeingDeleted || ControlArea->u.Flags.BeingCreated)
                {
                    if (ControlArea->WaitingForDeletion)
                    {
                        EventCounter = ControlArea->WaitingForDeletion;
                        EventCounter->RefCount++;
                    }
                    else
                    {
                        if (!NewEventCounter)
                        {
                            /* Unlock the PFN database */
                            MiUnlockPfnDb(OldIrql, APC_LEVEL);

                            NewEventCounter = MiGetEventCounter();
                            if (!NewEventCounter)
                            {
                                DPRINT1("MmCreateSection: Allocate failed\n");

                                if (FileLock)
                                {
                                    IoSetTopLevelIrp(NULL);
                                    //FsRtlReleaseFile(File);
                                }

                                ExFreePoolWithTag(NewControlArea, 'aCmM');
                                ObDereferenceObject(File);
                                return STATUS_INSUFFICIENT_RESOURCES;
                            }

                            continue;
                        }

                        EventCounter = NewEventCounter;
                        NewEventCounter = NULL;

                        ControlArea->WaitingForDeletion = EventCounter;
                    }

                    /* Unlock the PFN database */
                    MiUnlockPfnDb(OldIrql, APC_LEVEL);

                    /* Check if we locked and set the IRP */
                    if (FileLock)
                    {
                        /* Reset the top-level IRP and release the lock */
                        IoSetTopLevelIrp(NULL);
                        //FsRtlReleaseFile(File);
                    }

                    KeWaitForSingleObject(&EventCounter->Event, WrVirtualMemory, KernelMode, FALSE, NULL);
                    MiFreeEventCounter(EventCounter);

                    /* Check if we locked */
                    if (FileLock)
                    {
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
                        Status = STATUS_SUCCESS;
                        DPRINT("MmCreateSection: FIXME FsRtlAcquireToCreateMappedSection\n");
                      #endif

                        /* Update the top-level IRP so that drivers know what's happening */
                        IoSetTopLevelIrp((PIRP)FSRTL_FSP_TOP_LEVEL_IRP);
                    }

                    continue;
                }

                if (ControlArea->u.Flags.ImageMappedInSystemSpace &&
                    (AllocationAttributes & SEC_IMAGE) &&
                    KeGetCurrentThread()->PreviousMode != KernelMode)
                {
                    MiUnlockPfnDb(OldIrql, APC_LEVEL);

                    if (NewEventCounter)
                        MiFreeEventCounter(NewEventCounter);

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
                    ControlArea->NumberOfUserReferences++;

                break;
            }
        }

        /* We can release the PFN lock now */
        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        if (NewEventCounter)
            MiFreeEventCounter(NewEventCounter);

        if ((AllocationAttributes & SEC_IMAGE) && File && (File->FileName.Length > 4))
        {
            DPRINT("MmCreateSection: File %p '%wZ' \n", File, &File->FileName);
        }

        if (!NewSegment)
        {
            if (AllocationAttributes & SEC_IMAGE)
            {
                /* Create image-file backed sections */
                Status = MiCreateImageFileMap(File, &Segment);
            }
            else
            {
                /* So create a data file map */
                Status = MiCreateDataFileMap(File,
                                             &Segment,
                                             InputMaximumSize,
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
                EventCounter = ControlArea->WaitingForDeletion;
                ControlArea->WaitingForDeletion = NULL;

                /* Set the file pointer NULL flag */
                ASSERT(ControlArea->u.Flags.FilePointerNull == 0);
                ControlArea->u.Flags.FilePointerNull = 1;

                /* Delete the section object */
                if (AllocationAttributes & SEC_IMAGE)
                {
                    MiRemoveImageSectionObject(File, (PLARGE_CONTROL_AREA)ControlArea);
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

                if (EventCounter)
                    KeSetEvent(&EventCounter->Event, 0, FALSE);

                /* All done */
                DPRINT1("MmCreateSection: Status %X\n", Status);
                return Status;
            }

            /* Check if a maximum size was specified */
            if (!InputMaximumSize->QuadPart)
            {
                /* Nope, use the segment size */
                Section.SizeOfSection.QuadPart = (LONGLONG)Segment->SizeOfSegment;
                //DPRINT("MmCreateSection: Section.SizeOfSection.QuadPart %I64X\n", Section.SizeOfSection.QuadPart);
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
                MiFlushDataSection(File);

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

                Section.SizeOfSection.QuadPart = InputMaximumSize->QuadPart;
                DPRINT("MmCreateSection: Section.SizeOfSection.QuadPart %I64X\n", Section.SizeOfSection.QuadPart);
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

        if (AllocationAttributes & SEC_LARGE_PAGES)
        {
            /* Not yet supported */
            ASSERT((AllocationAttributes & SEC_LARGE_PAGES) == 0);

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
        Status = MiCreatePagingFileMap(&NewSegment, InputMaximumSize, ProtectionMask, AllocationAttributes);
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
        EventCounter = ControlArea->WaitingForDeletion;
        ControlArea->WaitingForDeletion = NULL;

        if (AllocationAttributes & SEC_IMAGE)
        {
            /* Image-file backed section */
            MiRemoveImageSectionObject(File, (PLARGE_CONTROL_AREA)NewControlArea);
            ControlArea = NewSegment->ControlArea;
            MiInsertImageSectionObject(File, (PLARGE_CONTROL_AREA)ControlArea);
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

        if ((AllocationAttributes & SEC_IMAGE) || NewSegment->ControlArea->u.Flags.Rom)
            /* Free the new control area */
            ExFreePoolWithTag(NewControlArea, 'aCmM');

        if (EventCounter)
            KeSetEvent(&EventCounter->Event, 0, FALSE);
    }

    /* Check if we locked the file earlier */
    if (FileLock)
    {
        /* Reset the top-level IRP and release the lock */
        IoSetTopLevelIrp(NULL);
        FileLock = FALSE;
    }

Finish:

    /* Set the initial section object data */
    Section.InitialPageProtection = SectionPageProtection;

    /* The mapping created a control area and segment, save the flags */
    Section.Segment = NewSegment;
    Section.u.LongFlags = ControlArea->u.LongFlags;

    /* Check if this is a user-mode read-write non-image file mapping */
    if (!FileObject &&
        (SectionPageProtection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
        !ControlArea->u.Flags.Image &&
        ControlArea->FilePointer)
    {
        /* Add a reference and set the flag */
        Section.u.Flags.UserWritable = 1;
        InterlockedIncrement((volatile PLONG)&ControlArea->WritableUserReferences);
    }

    /* Check for image mappings or page file mappings */
    if (ControlArea->u.Flags.Image || !ControlArea->FilePointer)
    {
        /* Charge the segment size, and allocate a subsection */
        PagedCharge = (sizeof(SECTION) + NewSegment->TotalNumberOfPtes * sizeof(MMPTE));
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
    if (!NT_SUCCESS(Status))
    {
        /* Check if this is a user-mode read-write non-image file mapping */
        if (!FileObject &&
            (SectionPageProtection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
            !ControlArea->u.Flags.Image &&
            ControlArea->FilePointer)
        {
            /* Remove a reference and check the flag */
            ASSERT(Section.u.Flags.UserWritable == 1);
            InterlockedDecrement((volatile PLONG)&ControlArea->WritableUserReferences);
        }

ErrorExit:

        /* Check if we locked and set the IRP */
        if (FileLock)
        {
            ASSERT(FALSE);
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
            NewSection->u.Flags.NoChange = 1;

        if (!(SectionPageProtection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
            NewSection->u.Flags.CopyOnWrite = 1;

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
            NewSection->Address.EndingVpn = (NewSection->Address.StartingVpn + 
                                             NewSection->SizeOfSection.LowPart - 1);

            MiInsertBasedSection(NewSection);
            KeReleaseGuardedMutex(&MmSectionBasedMutex);
        }
    }

    /* Write flag if this a CC call */
    ControlArea->u.Flags.WasPurged |= IgnoreFileSizing;

    if ((ControlArea->u.Flags.WasPurged && !IgnoreFileSizing && !IsSectionSizeChanged) ||
        ((ULONGLONG)NewSection->SizeOfSection.QuadPart > NewSection->Segment->SizeOfSegment))
    {
        NewSectionSize.QuadPart = NewSection->SizeOfSection.QuadPart;
        NewSection->SizeOfSection.QuadPart = (LONGLONG)NewSection->Segment->SizeOfSegment;

        if (NewSection->InitialPageProtection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))
        {
            Status = MmExtendSection(NewSection, &NewSectionSize, IgnoreFileSizing);
        }
        else
        {
            RtlCopyMemory(&Section, NewSection, sizeof(Section));
            Status = MmExtendSection(&Section, &NewSectionSize, IgnoreFileSizing);
            NewSection->SizeOfSection.QuadPart = Section.SizeOfSection.QuadPart;
        }

        if (!NT_SUCCESS(Status))
        {
            ObDereferenceObject(NewSection);
            DPRINT1("MmCreateSection: Status %X\n", Status);
            return Status;
        }
    }

    /* Return the object and the creation status */
    *SectionObject = NewSection;

    DPRINT("MmCreateSection: NewSection %p NewSegment %p\n", NewSection, NewSegment);
    return Status;
}

BOOLEAN
NTAPI
MmDisableModifiedWriteOfSection(
    _In_ PSECTION_OBJECT_POINTERS SectionObjectPointer)
{
    PCONTROL_AREA ControlArea;
    KIRQL OldIrql;
    BOOLEAN Result = TRUE;

    DPRINT("MmDisableModifiedWriteOfSection: SectionObjectPointer %p\n", SectionObjectPointer);

    OldIrql = MiLockPfnDb(APC_LEVEL);

    ControlArea = SectionObjectPointer->DataSectionObject;

    if (ControlArea)
    {
        if (ControlArea->NumberOfMappedViews)
            Result = (ControlArea->u.Flags.NoModifiedWriting == 1);
        else
            ControlArea->u.Flags.NoModifiedWriting = 1;
    }
    else
    {
        Result = FALSE;
    }

    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    return Result;
}

ULONG
NTAPI
MmDoesFileHaveUserWritableReferences(
    _In_ PSECTION_OBJECT_POINTERS SectionPointer)
{
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

VOID
NTAPI
MiCleanSection(
    _In_ PCONTROL_AREA ControlArea,
    _In_ BOOLEAN Parameter2)
{
    KEVENT Event;
    PSUBSECTION Subsection;
    PMMPTE LastWritten = NULL;
    PMMPTE Proto;
    PMMPTE LastProto;
    PMMPFN Pfn;
    MMPTE TempProto;
    BOOLEAN IsImageSection;
    BOOLEAN WriteIsAlow = FALSE;
    BOOLEAN IsLock;
    BOOLEAN IsFirst;
    KIRQL OldIrql;

    DPRINT("MiCleanSection: %p, %X\n", ControlArea, Parameter2);

    ASSERT(ControlArea->FilePointer);

    if (ControlArea->u.Flags.GlobalOnlyPerSession || ControlArea->u.Flags.Rom)
        Subsection = (PSUBSECTION)((PLARGE_CONTROL_AREA)ControlArea + 1);
    else
        Subsection = (PSUBSECTION)(ControlArea + 1);

    if (ControlArea->u.Flags.Image)
    {
        Proto = Subsection->SubsectionBase;
        LastProto = &Proto[ControlArea->Segment->NonExtendedPtes];
        IsImageSection = TRUE;
    }
    else
    {
        Proto = NULL;
        LastProto = NULL;
        IsImageSection = FALSE;
    }

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    //ASSERT(MmModifiedWriteClusterSize == MM_MAXIMUM_WRITE_CLUSTER);

    OldIrql = MiLockPfnDb(APC_LEVEL);

    ControlArea->u.Flags.NoModifiedWriting = 1;

    while (ControlArea->ModifiedWriteCount)
    {
        DPRINT1("MiCleanSection: FIXME. ControlArea %p\n", ControlArea);
        ASSERT(FALSE);
    }

    if (!IsImageSection)
    {
        while (!Subsection->SubsectionBase)
        {
            Subsection = Subsection->NextSubsection;
            if (!Subsection)
                goto Finish;
        }

        Proto = Subsection->SubsectionBase;
        LastProto = &Proto[Subsection->PtesInSubsection];
    }

    while (TRUE)
    {
        IsFirst = TRUE;

        while (Proto < LastProto)
        {
            if (!MiIsPteOnPdeBoundary(Proto) || IsFirst)
            {
                IsFirst = FALSE;

                if (!IsImageSection && !MiCheckProtoPtePageState(Proto, 0x21, &IsLock))
                {
                    Proto = (PMMPTE)(((ULONG_PTR)Proto | 0xFFF) + 1);

                    if (LastWritten)
                        WriteIsAlow = TRUE;

                    goto WriteClaster;
                }

                MiMakeSystemAddressValidPfn(Proto, OldIrql);
            }

            TempProto.u.Long = Proto->u.Long;

            if (TempProto.u.Hard.Valid)
            {
                DPRINT1("MiCleanSection: FIXME KeBugCheckEx(). TempProto %p\n", TempProto.u.Long);
                ASSERT(FALSE);
            }

            if (TempProto.u.Soft.Prototype)
            {
                if (LastWritten)
                    WriteIsAlow = TRUE;
            }
            else if (TempProto.u.Soft.Transition)
            {
                Pfn = MI_PFN_ELEMENT(TempProto.u.Trans.PageFrameNumber);

                if (Pfn->u3.e2.ReferenceCount)
                {
                    DPRINT1("MiCleanSection: FIXME. Pfn %p\n", Pfn);
                    ASSERT(FALSE);
                }

                if (Pfn->OriginalPte.u.Soft.Prototype)
                {
                    if (Pfn->u3.e1.Modified && !IsImageSection)
                    {
                        DPRINT1("MiCleanSection: FIXME. Modified %X\n", Pfn->u3.e1.Modified);
                        ASSERT(FALSE);
                    }
                    else
                    {
                        Pfn->PteAddress = (PMMPTE)((ULONG_PTR)Pfn->PteAddress | 1);

                        ControlArea->NumberOfPfnReferences--;
                        ASSERT((LONG)ControlArea->NumberOfPfnReferences >= 0);

                        MiDecrementPfnShare(MI_PFN_ELEMENT(Pfn->u4.PteFrame), Pfn->u4.PteFrame);

                        if (!Pfn->u3.e2.ReferenceCount && Pfn->u3.e1.PageLocation != FreePageList)
                        {
                            MiUnlinkPageFromList(Pfn);
                            MiReleasePageFileSpace(Pfn->OriginalPte);
                            MiInsertPageInFreeList(TempProto.u.Trans.PageFrameNumber);
                        }

                        Proto->u.Long = 0;

                        if (LastWritten)
                            WriteIsAlow = TRUE;
                    }
                }
                else
                {
                    DPRINT1("MiCleanSection: FIXME. OriginalPte %p\n", Pfn->OriginalPte.u.Long);
                    ASSERT(FALSE);
                }
            }
            else
            {
                if (MI_IS_MAPPED_PTE(&TempProto))
                    MiReleasePageFileSpace(TempProto);

                Proto->u.Long = 0;

                if (LastWritten)
                    WriteIsAlow = TRUE;
            }

            Proto++;

WriteClaster:

            if (!WriteIsAlow && (Proto != LastProto || !LastWritten))
                continue;


            DPRINT1("MiCleanSection: FIXME. Subsection %p\n", Subsection);
            ASSERT(FALSE);
        }

        if (!Subsection->NextSubsection)
            break;

        Subsection = Subsection->NextSubsection;
        if (!IsImageSection)
        {
            while (!Subsection->SubsectionBase)
            {
                Subsection = Subsection->NextSubsection;
                if (!Subsection)
                    goto Finish;
            }
        }

        Proto = Subsection->SubsectionBase;
        LastProto = &Proto[Subsection->PtesInSubsection];
    }

Finish:

    ControlArea->NumberOfMappedViews = 0;
    ASSERT(ControlArea->NumberOfPfnReferences == 0);

    if (ControlArea->u.Flags.FilePointerNull)
        goto Exit;

    ControlArea->u.Flags.FilePointerNull = 1;

    if (ControlArea->u.Flags.Image)
    {
        MiRemoveImageSectionObject(ControlArea->FilePointer, (PLARGE_CONTROL_AREA)ControlArea);
        goto Exit;
    }

    ASSERT(((PCONTROL_AREA)(ControlArea->FilePointer->SectionObjectPointer->DataSectionObject)) != NULL);
    ControlArea->FilePointer->SectionObjectPointer->DataSectionObject = 0;

Exit:

    MiUnlockPfnDb(OldIrql, APC_LEVEL);
    MiSegmentDelete(ControlArea->Segment);
}

BOOLEAN
NTAPI
MmFlushImageSection(
    _In_ PSECTION_OBJECT_POINTERS SectionPointer,
    _In_ MMFLUSH_TYPE FlushType)
{
    PLARGE_CONTROL_AREA LargeControlArea;
    PCONTROL_AREA ControlArea;
    KIRQL OldIrql;
    BOOLEAN Result;

    DPRINT("MmFlushImageSection: SectionPointers %p, FlushType %X\n", SectionPointer, FlushType);

    if (FlushType == MmFlushForDelete)
    {
        OldIrql = MiLockPfnDb(APC_LEVEL);

        ControlArea = SectionPointer->DataSectionObject;

        if (ControlArea &&
            (ControlArea->NumberOfUserReferences || ControlArea->u.Flags.BeingCreated))
        {
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
            return FALSE;
        }

        MiUnlockPfnDb(OldIrql, APC_LEVEL);
    }

    Result = MiCheckControlAreaStatus(1, SectionPointer, FALSE, &ControlArea, &OldIrql);

    while (ControlArea)
    {
        ControlArea->u.Flags.BeingDeleted = 1;
        ControlArea->NumberOfMappedViews = 1;

        LargeControlArea = NULL;
        DPRINT("NumberOfMappedViews: %p, %X\n", ControlArea, ControlArea->NumberOfMappedViews);

        if (ControlArea->u.Flags.GlobalOnlyPerSession)
        {
            DPRINT1("MmFlushImageSection: FIXME. ControlArea %p\n", ControlArea);
            ASSERT(FALSE);
        }

        MiUnlockPfnDb(OldIrql, APC_LEVEL);

        MiCleanSection(ControlArea, TRUE);

        if (!LargeControlArea)
        {
            Result = TRUE;
            break;
        }

        DPRINT1("MmFlushImageSection: FIXME. ControlArea %p\n", ControlArea);
        ASSERT(FALSE);
    }

    return Result;
}

BOOLEAN
NTAPI
MmForceSectionClosed(
    _In_ PSECTION_OBJECT_POINTERS SectionObjectPointer,
    _In_ BOOLEAN DelayClose)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmMapViewInSessionSpace(
    _In_ PVOID Section,
    _Out_ PVOID* MappedBase,
    _Inout_ PSIZE_T ViewSize)
{
    PAGED_CODE();
    DPRINT("MmMapViewInSessionSpace: Section %p, MappedBase %p, ViewSize %I64X\n", Section, (MappedBase?*MappedBase:NULL), (ViewSize?(ULONGLONG)(*ViewSize):0ull));

    /* Process must be in a session */
    if (PsGetCurrentProcess()->ProcessInSession == FALSE)
    {
        DPRINT1("Process is not in session\n");
        return STATUS_NOT_MAPPED_VIEW;
    }

    /* Use the system space API, but with the session view instead */
    ASSERT(MmIsAddressValid(MmSessionSpace) == TRUE);

    return MiMapViewInSystemSpace(Section, &MmSessionSpace->Session, MappedBase, ViewSize);
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmMapViewInSystemSpace(
    _In_ PVOID Section,
    _Out_ PVOID* MappedBase,
    _Out_ PSIZE_T ViewSize)
{
    PAGED_CODE();
    DPRINT("MmMapViewInSystemSpace: Section %p, MappedBase %p, ViewSize %I64X\n",
           Section, (MappedBase ? *MappedBase : 0), (ViewSize ? (ULONGLONG)(*ViewSize) : 0ull));

    return MiMapViewInSystemSpace((PSECTION)Section, &MmSession, MappedBase, ViewSize);
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmMapViewOfSection(
    _In_ PVOID SectionObject,
    _In_ PEPROCESS Process,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_ PLARGE_INTEGER SectionOffset OPTIONAL,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect)
{
    ULONG64 CalculatedViewSize;
    PCONTROL_AREA ControlArea;
    PSECTION Section;
    ULONG ProtectionMask;
    KAPC_STATE ApcState;
    BOOLEAN Attached = FALSE;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("MmMapViewOfSection: %p, %p, %X, %X, %X, %X\n",
           SectionObject, Process, ZeroBits, CommitSize, AllocationType, Protect);

    /* Get Section */
    Section = (PSECTION)SectionObject;

    if (!Section->u.Flags.Image)
    {
        if (!MiIsProtectionCompatible(Section->InitialPageProtection, Protect))
        {
            DPRINT1("MmMapViewOfSection: return STATUS_SECTION_PROTECTION\n");
            ASSERT(FALSE); // MiDbgBreakPointEx();
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
        CalculatedViewSize = (Section->SizeOfSection.QuadPart - SectionOffset->QuadPart);

        /* Check if it's larger than 4GB or overflows into kernel-mode */
        if (!NT_SUCCESS(RtlULongLongToSIZET(CalculatedViewSize, ViewSize)) ||
            (((ULONG_PTR)MM_HIGHEST_VAD_ADDRESS - (ULONG_PTR)*BaseAddress) < CalculatedViewSize))
        {
            DPRINT1("MmMapViewOfSection: Section view won't fit\n");
            return STATUS_INVALID_VIEW_SIZE;
        }
    }

    /* Check if the commit size is larger than the view size */
    if (CommitSize > *ViewSize && !(AllocationType & MEM_RESERVE))
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
        Protect = ((Protect & ~PAGE_WRITECOMBINE) | PAGE_NOCACHE);

    if (Section->u.Flags.WriteCombined)
        Protect = ((Protect & ~PAGE_NOCACHE) | PAGE_WRITECOMBINE);

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

    /* Release the address space lock */
    KeReleaseGuardedMutex(&Process->AddressCreationLock);

    /* Detach if needed, then return status */
    if (Attached)
        KeUnstackDetachProcess(&ApcState);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MmMapViewOfSection: Status %X\n", Status);
    }

    return Status;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MiUnmapViewInSystemSpace(
    _In_ PMMSESSION Session,
    _In_ PVOID MappedBase)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmUnmapViewInSessionSpace(
    _In_ PVOID MappedBase)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmUnmapViewInSystemSpace(
    _In_ PVOID MappedBase)
{
    PAGED_CODE();
    return MiUnmapViewInSystemSpace(&MmSession, MappedBase);
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmUnmapViewOfSection(
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress)
{
    DPRINT("MmUnmapViewOfSection: Process %p, BaseAddress %p\n", Process, BaseAddress);
    return MiUnmapViewOfSection(Process, BaseAddress, 0);
}

/* SYSTEM CALLS ***************************************************************/

CODE_SEG("PAGE")
NTSTATUS
NTAPI
NtAreMappedFilesTheSame(
    _In_ PVOID File1MappedAsAnImage,
    _In_ PVOID File2MappedAsFile)
{
    PCONTROL_AREA ControlArea;
    PVOID AddressSpace;
    PMMVAD Vad1;
    PMMVAD Vad2;
    BOOLEAN IsGlobal;
    NTSTATUS Status;

    DPRINT("NtAreMappedFilesTheSame: %p, %p\n", File1MappedAsAnImage, File2MappedAsFile);

    /* Lock address space */
    AddressSpace = MmGetCurrentAddressSpace();
    MmLockAddressSpace(AddressSpace);

    /* Get the VAD for Address 1 */
    Vad1 = MiLocateAddress(File1MappedAsAnImage);
    if (!Vad1)
    {
        /* Fail, the address does not exist */
        DPRINT1("NtAreMappedFilesTheSame: No VAD at address 1 %p\n", File1MappedAsAnImage);
        Status = STATUS_INVALID_ADDRESS;
        goto Exit;
    }

    /* Get the VAD for Address 2 */
    Vad2 = MiLocateAddress(File2MappedAsFile);
    if (!Vad2)
    {
        /* Fail, the address does not exist */
        DPRINT1("NtAreMappedFilesTheSame: No VAD at address 2 %p\n", File2MappedAsFile);
        Status = STATUS_INVALID_ADDRESS;
        goto Exit;
    }

    if (Vad1->u.VadFlags.PrivateMemory || Vad2->u.VadFlags.PrivateMemory)
    {
        DPRINT1("NtAreMappedFilesTheSame: STATUS_CONFLICTING_ADDRESSES\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto Exit;
    }

    if (!Vad1->ControlArea || !Vad2->ControlArea)
    {
        DPRINT1("NtAreMappedFilesTheSame: STATUS_CONFLICTING_ADDRESSES\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto Exit;
    }
    
    if (!Vad1->ControlArea->FilePointer || !Vad2->ControlArea->FilePointer)
    {
        DPRINT1("NtAreMappedFilesTheSame: STATUS_CONFLICTING_ADDRESSES\n");
        Status = STATUS_CONFLICTING_ADDRESSES;
        goto Exit;
    }

    if (Vad1->ControlArea == Vad2->ControlArea->FilePointer->SectionObjectPointer->ImageSectionObject)
    {
        Status = STATUS_SUCCESS;
        goto Exit;
    }

    if (!Vad1->ControlArea->u.Flags.GlobalOnlyPerSession)
    {    
        DPRINT1("NtAreMappedFilesTheSame: STATUS_CONFLICTING_ADDRESSES\n");
        Status = STATUS_NOT_SAME_DEVICE;
        goto Exit;
    }

    ControlArea = MiFindImageSectionObject(Vad2->ControlArea->FilePointer, FALSE, &IsGlobal);
    if (ControlArea != Vad1->ControlArea)
    {    
        DPRINT1("NtAreMappedFilesTheSame: STATUS_CONFLICTING_ADDRESSES\n");
        Status = STATUS_NOT_SAME_DEVICE;
        goto Exit;
    }

    Status = STATUS_SUCCESS;

Exit:

    /* Unlock address space */
    MmUnlockAddressSpace(AddressSpace);
    return Status;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
NtCreateSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    _In_ PLARGE_INTEGER MaximumSize OPTIONAL,
    _In_ ULONG SectionPageProtection OPTIONAL,
    _In_ ULONG AllocationAttributes,
    _In_ HANDLE FileHandle OPTIONAL)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    LARGE_INTEGER SafeMaximumSize;
    PCONTROL_AREA ControlArea;
    PSECTION SectionObject;
    HANDLE Handle;
    ULONG MaximumRetry = 3;
    ULONG ix;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("NtCreateSection: %X, %X, %p [%I64X], %X, %X, %p\n", DesiredAccess, ObjectAttributes, MaximumSize,
           (MaximumSize ? MaximumSize->QuadPart : 0), SectionPageProtection, AllocationAttributes, FileHandle);

    /* Check for non-existing flags */
    if (AllocationAttributes & ~(SEC_COMMIT | SEC_RESERVE | SEC_BASED | SEC_LARGE_PAGES |
                                 SEC_IMAGE | SEC_NOCACHE | SEC_NO_CHANGE))
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
        (AllocationAttributes & (SEC_COMMIT | SEC_RESERVE | SEC_LARGE_PAGES | SEC_NOCACHE | SEC_NO_CHANGE)))
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
    if (!MaximumSize)
        SafeMaximumSize.QuadPart = 0;

    /* Check for user-mode caller */
    if (PreviousMode != KernelMode)
    {
        /* Enter SEH */
        _SEH2_TRY
        {
            /* Safely check user-mode parameters */
            if (MaximumSize)
                SafeMaximumSize = ProbeForReadLargeInteger(MaximumSize);

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
            SafeMaximumSize.QuadPart = MaximumSize->QuadPart;
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
            break;

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

    if (ControlArea && ControlArea->FilePointer)
        CcZeroEndOfLastPage(ControlArea->FilePointer);

    /* Now insert the object */
    Status = ObInsertObject(SectionObject, NULL, DesiredAccess, 0, NULL, &Handle);
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

CODE_SEG("PAGE")
NTSTATUS
NTAPI
NtOpenSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    HANDLE Handle;
    NTSTATUS Status;

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

CODE_SEG("PAGE")
NTSTATUS
NTAPI
NtMapViewOfSection(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_ PLARGE_INTEGER SectionOffset OPTIONAL,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect)
{
    PEPROCESS CurrentProcess;
    PEPROCESS Process;
    PSECTION Section;
    PVOID SafeBaseAddress;
    LARGE_INTEGER SafeSectionOffset;
    SIZE_T SafeViewSize;
    ACCESS_MASK DesiredAccess;
    ULONG ProtectionMask;
    KPROCESSOR_MODE PreviousMode;
    NTSTATUS Status;
#if defined(_M_IX86) || defined(_M_AMD64)
    static const ULONG ValidAllocationType = (MEM_TOP_DOWN | MEM_LARGE_PAGES | MEM_DOS_LIM | SEC_NO_CHANGE | MEM_RESERVE);
#else
    static const ULONG ValidAllocationType = (MEM_TOP_DOWN | MEM_LARGE_PAGES | SEC_NO_CHANGE | MEM_RESERVE);
#endif

    DPRINT("NtMapViewOfSection: SectionHandle %p, ProcessHandle %p, ZeroBits %X, CommitSize %X, AllocationType %X, Protect %X\n",
           SectionHandle, ProcessHandle, ZeroBits, CommitSize, AllocationType, Protect);

    if (ZeroBits > MI_MAX_ZERO_BITS)
    {
        DPRINT1("NtMapViewOfSection: Invalid zero bits\n");
        return STATUS_INVALID_PARAMETER_4;
    }

    /* Check for invalid inherit disposition */
    if (InheritDisposition > ViewUnmap || InheritDisposition < ViewShare)
    {
        DPRINT1("NtMapViewOfSection: Invalid inherit disposition\n");
        return STATUS_INVALID_PARAMETER_8;
    }

    /* Allow only valid allocation types */
    if (AllocationType & ~ValidAllocationType)
    {
        DPRINT1("NtMapViewOfSection: Invalid allocation type\n");
        return STATUS_INVALID_PARAMETER_9;
    }

    /* Convert the protection mask, and validate it */
    ProtectionMask = MiMakeProtectionMask(Protect);
    if (ProtectionMask == MM_INVALID_PROTECTION)
    {
        DPRINT1("NtMapViewOfSection: Invalid page protection\n");
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    /* Now convert the protection mask into desired section access mask */
    DesiredAccess = MmMakeSectionAccess[ProtectionMask & 0x7];

    CurrentProcess = (PEPROCESS)PsGetCurrentThread()->Tcb.ApcState.Process;
    PreviousMode = PsGetCurrentThread()->Tcb.PreviousMode;

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
            if (PreviousMode != KernelMode)
                ProbeForWriteLargeInteger(SectionOffset);

            SafeSectionOffset = *SectionOffset;
        }
        else
        {
            SafeSectionOffset.QuadPart = 0;
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
        DPRINT1("NtMapViewOfSection: Kernel base not allowed\n");
        return STATUS_INVALID_PARAMETER_3;
    }

    /* Check for range entering kernel-mode */
    if (((ULONG_PTR)MM_HIGHEST_VAD_ADDRESS - (ULONG_PTR)SafeBaseAddress) < SafeViewSize)
    {
        DPRINT1("NtMapViewOfSection: Overflowing into kernel base not allowed\n");
        return STATUS_INVALID_PARAMETER_3;
    }

    /* Check for invalid zero bits */
    if (((ULONG_PTR)SafeBaseAddress + SafeViewSize) > (0xFFFFFFFF >> ZeroBits)) // FIXME
    {
        DPRINT1("NtMapViewOfSection: Invalid zero bits\n");
        return STATUS_INVALID_PARAMETER_4;
    }

    /* Reference the process */
    Status = ObReferenceObjectByHandle(ProcessHandle,
                                       PROCESS_VM_OPERATION,
                                       PsProcessType,
                                       PreviousMode,
                                       (PVOID *)&Process,
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtMapViewOfSection: Status %X\n", Status);
        return Status;
    }

    /* Reference the section */
    Status = ObReferenceObjectByHandle(SectionHandle,
                                       DesiredAccess,
                                       MmSectionObjectType,
                                       PreviousMode,
                                       (PVOID *)&Section,
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtMapViewOfSection: Status %X\n", Status);
        ObDereferenceObject(Process);
        return Status;
    }

    if (Section->Segment->ControlArea->u.Flags.PhysicalMemory)
    {
        SafeSectionOffset.LowPart = (ULONG)PAGE_ALIGN(SafeSectionOffset.LowPart);

        if (PreviousMode == UserMode &&
            (SafeSectionOffset.QuadPart + SafeViewSize) > ((ULONGLONG)MmHighestPhysicalPage * PAGE_SIZE))
        {
            DPRINT1("NtMapViewOfSection: Denying map past highest physical page.\n");
            Status = STATUS_INVALID_PARAMETER_6;
            goto Exit;
        }
    }
    else if (!(AllocationType & MEM_DOS_LIM))
    {
        /* Check for non-allocation-granularity-aligned BaseAddress */
        if ((ULONG_PTR)SafeBaseAddress & (MM_ALLOCATION_GRANULARITY - 1))
        {
            DPRINT1("NtMapViewOfSection: BaseAddress is not at 64-kilobyte address boundary.\n");
            Status = STATUS_MAPPED_ALIGNMENT;
            goto Exit;
        }

        /* Do the same for the section offset */
        if (SectionOffset && (SafeSectionOffset.LowPart & (MM_ALLOCATION_GRANULARITY - 1)))
        {
            DPRINT1("NtMapViewOfSection: SectionOffset is not at 64-kilobyte address boundary.\n");
            Status = STATUS_MAPPED_ALIGNMENT;
            goto Exit;
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
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtMapViewOfSection: Status %X\n", Status);

        if (Status == STATUS_CONFLICTING_ADDRESSES &&
            Section->Segment->ControlArea->u.Flags.Image &&
            Process == CurrentProcess)
        {
            DbgkMapViewOfSection(Section,
                                 SafeBaseAddress,
                                 SafeSectionOffset.LowPart,
                                 SafeViewSize);
        }
        goto Exit;
    }

    /* Check if this is an image for the current process */
    if (Section->Segment->ControlArea->u.Flags.Image &&
        Process == CurrentProcess &&
        Status != STATUS_IMAGE_NOT_AT_BASE)
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

        if (SectionOffset)
            *SectionOffset = SafeSectionOffset;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* Nothing to do */
    }
    _SEH2_END;

Exit:

    /* Dereference all objects and return status */
    ObDereferenceObject(Section);
    ObDereferenceObject(Process);

    return Status;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
NtUnmapViewOfSection(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    PEPROCESS Process;
    NTSTATUS Status;

    DPRINT("NtUnmapViewOfSection: BaseAddress %p\n", BaseAddress);

    /* Don't allowing mapping kernel views */
    if (PreviousMode == UserMode && BaseAddress > MM_HIGHEST_USER_ADDRESS)
    {
        DPRINT1("Trying to unmap a kernel view\n");
        return STATUS_NOT_MAPPED_VIEW;
    }

    /* Reference the process */
    Status = ObReferenceObjectByHandle(ProcessHandle,
                                       PROCESS_VM_OPERATION,
                                       PsProcessType,
                                       PreviousMode,
                                       (PVOID *)&Process,
                                       NULL);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtUnmapViewOfSection: Status %X\n", Status);
        return Status;
    }

    /* Unmap the view */
    Status = MiUnmapViewOfSection(Process, BaseAddress, 0);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtUnmapViewOfSection: Status %X\n", Status);
    }

    /* Dereference the process and return status */
    ObDereferenceObject(Process);

    return Status;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
NtExtendSection(
    _In_ HANDLE SectionHandle,
    _Inout_ PLARGE_INTEGER NewMaximumSize)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* Queries the information of a section object.
 
   SectionHandle
         Handle to the section object. It must be opened with SECTION_QUERY access.

   SectionInformationClass
         Index to a certain information structure.
         Can be either SectionBasicInformation or SectionImageInformation.
         The latter is valid only for sections that were created with the SEC_IMAGE flag.

   SectionInformation
         Caller supplies storage for resulting information.

   Length
         Size of the supplied storage.

   ResultLength
         Data written.

*/
CODE_SEG("PAGE")
NTSTATUS
NTAPI
NtQuerySection(
    _In_ HANDLE SectionHandle,
    _In_ SECTION_INFORMATION_CLASS SectionInformationClass,
    _Out_ PVOID SectionInformation,
    _In_ SIZE_T SectionInformationLength,
    _Out_opt_ PSIZE_T ResultLength)
{
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    SECTION_BASIC_INFORMATION Sbi;
    PSECTION Section;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("NtQuerySection: %p, %X, %X\n", SectionHandle, SectionInformationClass, SectionInformationLength);

    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            ProbeForWrite(SectionInformation, SectionInformationLength, __alignof(ULONG));

            if (ResultLength)
                ProbeForWrite(ResultLength, sizeof(*ResultLength), __alignof(SIZE_T));
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    if (SectionInformationClass == SectionBasicInformation)
    {
        if (SectionInformationLength < sizeof(SECTION_BASIC_INFORMATION))
        {
            DPRINT1("NtQuerySection: STATUS_INFO_LENGTH_MISMATCH\n");
            return STATUS_INFO_LENGTH_MISMATCH;
        }
    }
    else if (SectionInformationClass == SectionImageInformation)
    {
        if (SectionInformationLength < sizeof(SECTION_IMAGE_INFORMATION))
        {
            DPRINT1("NtQuerySection: STATUS_INFO_LENGTH_MISMATCH\n");
            return STATUS_INFO_LENGTH_MISMATCH;
        }
    }
    else
    {
        DPRINT1("NtQuerySection: STATUS_INVALID_INFO_CLASS\n");
        return STATUS_INVALID_INFO_CLASS;
    }

    Status = ObReferenceObjectByHandle(SectionHandle,
                                       SECTION_QUERY,
                                       MmSectionObjectType,
                                       PreviousMode,
                                       (PVOID *)&Section,
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtQuerySection: Failed to reference section. %X\n", Status);
        return Status;
    }

    switch(SectionInformationClass)
    {
        case SectionBasicInformation:
        {
            Sbi.Size = Section->SizeOfSection;
            Sbi.Attributes = 0;
            Sbi.BaseAddress = (PVOID)Section->Address.StartingVpn;

            if (Section->u.Flags.Image)
                Sbi.Attributes |= SEC_IMAGE;
            if (Section->u.Flags.Commit)
                Sbi.Attributes |= SEC_COMMIT;
            if (Section->u.Flags.Reserve)
                Sbi.Attributes |= SEC_RESERVE;
            if (Section->u.Flags.File)
                Sbi.Attributes |= SEC_FILE;
            if (Section->u.Flags.Image)
                Sbi.Attributes |= SEC_IMAGE;
            if (Section->u.Flags.Based)
                Sbi.Attributes |= SEC_BASED;
            if (Section->u.Flags.NoCache) 
                Sbi.Attributes |= SEC_NOCACHE;
            if (Section->Segment->ControlArea->u.Flags.GlobalMemory)
                Sbi.Attributes |= 0x20000000; /* FIXME */

            _SEH2_TRY
            {
                *((SECTION_BASIC_INFORMATION*)SectionInformation) = Sbi;

                if (ResultLength)
                    *ResultLength = sizeof(Sbi);
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            break;
        }
        case SectionImageInformation:
        {
            if (!Section->u.Flags.Image)
            {
                DPRINT1("NtQuerySection: STATUS_SECTION_NOT_IMAGE\n");
                Status = STATUS_SECTION_NOT_IMAGE;
                break;
            }

            /* Copy image information */
            RtlCopyMemory(SectionInformation,
                          Section->Segment->u2.ImageInformation,
                          sizeof(SECTION_IMAGE_INFORMATION));

            if (ResultLength)
                *ResultLength = sizeof(SECTION_IMAGE_INFORMATION);

            break;
        }
    }

    ObDereferenceObject(Section);

    return(Status);
}

/* EOF */
