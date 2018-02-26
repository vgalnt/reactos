/*
 * PROJECT:     ReactOS Universal Serial Bus Human Interface Device Driver
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        drivers/hid/hidclass/hidclass.c
 * PURPOSE:     HID Class Driver
 * PROGRAMMERS:
 *              Michael Martin (michael.martin@reactos.org)
 *              Johannes Anderwald (johannes.anderwald@reactos.org)
 */

#include "precomp.h"

#define NDEBUG
#include <debug.h>

static LPWSTR ClientIdentificationAddress = L"HIDCLASS";
static ULONG HidClassDeviceNumber;
LIST_ENTRY DriverExtList;
FAST_MUTEX DriverExtListMutex;

NTSTATUS
NTAPI
DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath)
{
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
DllInitialize(
    IN PUNICODE_STRING RegistryPath)
{
    DPRINT("DllInitialize: ... \n");

    InitializeListHead(&DriverExtList);
    ExInitializeFastMutex(&DriverExtListMutex);
    HidClassDeviceNumber = 0;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
DllUnload(VOID)
{
    DPRINT("DllUnload: ... \n");
    return STATUS_SUCCESS;
}

PHIDCLASS_DRIVER_EXTENSION
NTAPI
GetDriverExtension(
    IN PDRIVER_OBJECT DriverObject,
    OUT PLIST_ENTRY * OutEntry)
{
    PHIDCLASS_DRIVER_EXTENSION DriverExtension = NULL;
    PHIDCLASS_DRIVER_EXTENSION driverExtension;
    PLIST_ENTRY Entry;

    ExAcquireFastMutex(&DriverExtListMutex);

    Entry = DriverExtList.Flink;

    while (Entry != &DriverExtList)
    {
        driverExtension = CONTAINING_RECORD(Entry,
                                            HIDCLASS_DRIVER_EXTENSION,
                                            DriverExtLink.Flink);

        if (driverExtension->DriverObject == DriverObject)
        {
            DriverExtension = driverExtension;
            break;
        }

        Entry = Entry->Flink;
    }

    ExReleaseFastMutex(&DriverExtListMutex);

    if (OutEntry)
    {
        *OutEntry = Entry;
    }

    return DriverExtension;
}

PHIDCLASS_DRIVER_EXTENSION
NTAPI
RefDriverExt(
    IN PDRIVER_OBJECT DriverObject)
{
    PHIDCLASS_DRIVER_EXTENSION DriverExtension;

    if (IsListEmpty(&DriverExtList))
    {
        DPRINT("RefDriverExt: DriverExtList is empty\n");
        return NULL;
    }

    DriverExtension = GetDriverExtension(DriverObject, NULL);

    if (DriverExtension)
    {
        //
        // increments the reference count
        //
        DriverExtension->RefCount++;
    }

    DPRINT("RefDriverExt: DriverObject - %p, DriverExtension - %p\n",
           DriverObject,
           DriverExtension);

    return DriverExtension;
}

PHIDCLASS_DRIVER_EXTENSION
NTAPI
DerefDriverExt(
    IN PDRIVER_OBJECT DriverObject)
{
    PHIDCLASS_DRIVER_EXTENSION DriverExtension = NULL;
    PLIST_ENTRY Entry;

    if (IsListEmpty(&DriverExtList))
    {
        DPRINT("DerefDriverExt: DriverExtList is empty\n");
        return NULL;
    }

    DriverExtension = GetDriverExtension(DriverObject, &Entry);

    if (DriverExtension)
    {
        //
        // decrements the reference count
        //
        DriverExtension->RefCount--;
    }

    //
    // if reference count < 0
    // then remove given driver object extension's link
    //
    if (DriverExtension->RefCount < 0)
    {
        RemoveEntryList(Entry);
    }

    DPRINT("DerefDriverExt: DriverObject - %p, DriverExtension - %p\n",
           DriverObject,
           DriverExtension);

    return DriverExtension;
}

NTSTATUS
NTAPI
HidClassAddDevice(
    IN PDRIVER_OBJECT DriverObject,
    IN PDEVICE_OBJECT PhysicalDeviceObject)
{
    WCHAR CharDeviceName[64];
    NTSTATUS Status;
    UNICODE_STRING DeviceName;
    PDEVICE_OBJECT NewDeviceObject;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    ULONG DeviceExtensionSize;
    PHIDCLASS_DRIVER_EXTENSION DriverExtension;
    PHID_DEVICE_EXTENSION HidDeviceExtension;

    //
    // increment device number
    //
    InterlockedIncrement((PLONG)&HidClassDeviceNumber);

    //
    // construct device name
    //
    swprintf(CharDeviceName, L"\\Device\\_HID%08x", HidClassDeviceNumber);

    //
    // initialize device name
    //
    RtlInitUnicodeString(&DeviceName, CharDeviceName);

    //
    // get driver object extension
    //
    DriverExtension = RefDriverExt(DriverObject);

    if (!DriverExtension)
    {
        //
        // device removed
        //
        ASSERT(FALSE);
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    ASSERT(DriverObject == DriverExtension->DriverObject);

    //
    // calculate device extension size
    //
    DeviceExtensionSize = sizeof(HIDCLASS_FDO_EXTENSION) +
                                 DriverExtension->DeviceExtensionSize;

    //
    // now create the device
    //
    Status = IoCreateDevice(DriverObject,
                            DeviceExtensionSize,
                            &DeviceName,
                            FILE_DEVICE_UNKNOWN,
                            0,
                            FALSE,
                            &NewDeviceObject);

    if (!NT_SUCCESS(Status))
    {
        //
        // failed to create device object
        //
        DPRINT1("IoCreateDevice failed. Status - %x", Status);
        ASSERT(FALSE);
        DerefDriverExt(DriverObject);
        return Status;
    }

    DPRINT("HidClassAddDevice: added FDO IoCreateDevice (%p)\n", NewDeviceObject);
    ObReferenceObject(NewDeviceObject);

    ASSERT(DriverObject->DeviceObject == NewDeviceObject);
    ASSERT(NewDeviceObject->DriverObject == DriverObject);

    //
    // get device extension
    //
    FDODeviceExtension = NewDeviceObject->DeviceExtension;

    //
    // zero device extension
    //
    RtlZeroMemory(FDODeviceExtension, DeviceExtensionSize);

    HidDeviceExtension = &FDODeviceExtension->Common.HidDeviceExtension;

    //
    // initialize device extension
    //
    FDODeviceExtension->Common.IsFDO = TRUE;
    FDODeviceExtension->Common.DriverExtension = DriverExtension;
    HidDeviceExtension->PhysicalDeviceObject = PhysicalDeviceObject;
    FDODeviceExtension->FDODeviceObject = NewDeviceObject;
    FDODeviceExtension->OutstandingRequests = 0;
    FDODeviceExtension->BusNumber = HidClassDeviceNumber;

    //
    // initialize FDO flags
    //
    FDODeviceExtension->IsNotifyPresence = TRUE;
    FDODeviceExtension->IsRelationsOn = TRUE;
    FDODeviceExtension->IsDeviceResourcesAlloceted = FALSE;

    //
    // initialize SpinLocks
    //
    KeInitializeSpinLock(&FDODeviceExtension->HidRelationSpinLock);
    KeInitializeSpinLock(&FDODeviceExtension->HidRemoveDeviceSpinLock);

    //
    // initialize remove lock for FDO
    //
    IoInitializeRemoveLock(&FDODeviceExtension->HidRemoveLock,
                           HIDCLASS_REMOVE_LOCK_TAG,
                           HIDCLASS_FDO_MAX_LOCKED_MINUTES,
                           HIDCLASS_FDO_HIGH_WATERMARK);

    //
    // calculate and save pointer to minidriver-specific portion device extension
    //
    HidDeviceExtension->MiniDeviceExtension = (PVOID)((ULONG_PTR)FDODeviceExtension +
                                                      sizeof(HIDCLASS_FDO_EXTENSION));

    ASSERT((PhysicalDeviceObject->Flags & DO_DEVICE_INITIALIZING) == 0);

    //
    // attach new FDO to stack
    //
    HidDeviceExtension->NextDeviceObject = IoAttachDeviceToDeviceStack(NewDeviceObject,
                                                                       PhysicalDeviceObject);

    if (HidDeviceExtension->NextDeviceObject == NULL)
    {
        DPRINT1("HidClassAddDevice: Attach failed. IoDeleteDevice (%p)\n",
                NewDeviceObject);

        IoDeleteDevice(NewDeviceObject);
        return STATUS_DEVICE_REMOVED;
    }

    //
    // increment stack size
    //
    NewDeviceObject->StackSize++;

    //
    // FDO state is not initialized
    //
    FDODeviceExtension->HidFdoState = HIDCLASS_STATE_NOT_INIT;

    //
    // init device object
    //
    NewDeviceObject->Flags |= DO_DIRECT_IO;
    NewDeviceObject->Flags |= PhysicalDeviceObject->Flags & DO_POWER_PAGABLE;
    NewDeviceObject->Flags  &= ~DO_DEVICE_INITIALIZING;

    //
    // now call driver provided add device routine
    //
    ASSERT(DriverExtension->AddDevice != 0);
    Status = DriverExtension->AddDevice(DriverObject, NewDeviceObject);

    if (NT_SUCCESS(Status))
    {
        return STATUS_SUCCESS;
    }

    DPRINT1("HidClassAddDevice: Failed with %x, IoDeleteDevice(%p)\n",
            Status,
            NewDeviceObject);

    IoDetachDevice(HidDeviceExtension->NextDeviceObject);
    ObDereferenceObject(NewDeviceObject);
    IoDeleteDevice(NewDeviceObject);

    DerefDriverExt(DriverObject);

    return Status;
}

VOID
NTAPI
HidClassDriverUnload(
    IN PDRIVER_OBJECT DriverObject)
{
    PHIDCLASS_DRIVER_EXTENSION DriverExtension;

    DPRINT("HidClassDriverUnload: ... \n");

    DriverExtension = DerefDriverExt(DriverObject);
    DriverExtension->DriverUnload(DriverObject);
}

BOOLEAN
NTAPI
HidClassPrivilegeCheck(
    IN PIRP Irp)
{
    LUID PrivilegeValue;

    PrivilegeValue = RtlConvertLongToLuid(SE_TCB_PRIVILEGE);
    return SeSinglePrivilegeCheck(PrivilegeValue, Irp->RequestorMode);
}

NTSTATUS
NTAPI
HidClass_Create(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    NTSTATUS Status;
    PIO_STACK_LOCATION IoStack;
    PHIDCLASS_COMMON_DEVICE_EXTENSION CommonDeviceExtension;
    PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    PHIDCLASS_FILEOP_CONTEXT FileContext;
    PHIDCLASS_COLLECTION HidCollection;
    //ULONG SessionId;
    ULONG HidFdoState;
    ULONG HidPdoState;
    BOOLEAN IsPrivilege;
    KIRQL OldIrql;

    DPRINT("HidClass_Create: Irp - %p\n", Irp);

    Status = STATUS_SUCCESS;// IoGetRequestorSessionId(Irp, &SessionId); FIXME

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HidClass_Create: unable to get requestor SessionId\n");
        goto Exit;
    }

    //
    // get common extension
    //
    CommonDeviceExtension = DeviceObject->DeviceExtension;

    if (CommonDeviceExtension->IsFDO)
    {
        DPRINT1("HidClass_Create: only supported for PDO\n");
        Status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    //
    // get device extensions
    //
    PDODeviceExtension = DeviceObject->DeviceExtension;
    FDODeviceExtension = PDODeviceExtension->FDODeviceExtension;

    //
    // get stack location
    //
    IoStack = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(IoStack->FileObject);

    Irp->IoStatus.Information = 0;

    //
    // get collection
    //
    HidCollection = GetHidclassCollection(FDODeviceExtension,
                                          PDODeviceExtension->CollectionNumber);

    if (!HidCollection)
    {
        DPRINT1("HidClass_Create: couldn't find collection\n");
        Status = STATUS_DEVICE_NOT_CONNECTED;
        goto Exit;
    }

    //
    // check privilege
    //
    IsPrivilege = HidClassPrivilegeCheck(Irp);

    DPRINT("ShareAccess %x\n", IoStack->Parameters.Create.ShareAccess);
    DPRINT("Options %x\n", IoStack->Parameters.Create.Options);
    DPRINT("DesiredAccess %x\n", IoStack->Parameters.Create.SecurityContext->DesiredAccess);

    KeAcquireSpinLock(&HidCollection->CollectSpinLock, &OldIrql);

    //
    // validate parameters
    //
    if (PDODeviceExtension->RestrictionsForAnyOpen ||
        (PDODeviceExtension->OpenCount && !IoStack->Parameters.Create.ShareAccess))
    {
        DPRINT1("HidClass_Create: STATUS_SHARING_VIOLATION \n");
        Status = STATUS_SHARING_VIOLATION;
        goto UnlockExit;
    }

    if (((IoStack->Parameters.Create.SecurityContext->DesiredAccess & FILE_READ_DATA) &&
          PDODeviceExtension->RestrictionsForRead) ||
        ((IoStack->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_DATA) &&
          PDODeviceExtension->RestrictionsForWrite))
    {
        DPRINT1("HidClass_Create: STATUS_SHARING_VIOLATION \n");
        Status = STATUS_SHARING_VIOLATION;
        goto UnlockExit;
    }

    if ((PDODeviceExtension->OpensForRead > 0 &&
         !(IoStack->Parameters.Create.ShareAccess & FILE_SHARE_READ)) ||
        (PDODeviceExtension->OpensForWrite > 0 &&
         !(IoStack->Parameters.Create.ShareAccess & FILE_SHARE_WRITE)))
    {
        DPRINT1("HidClass_Create: STATUS_SHARING_VIOLATION \n");
        Status = STATUS_SHARING_VIOLATION;
        goto UnlockExit;
    }

    if (IoStack->Parameters.Create.Options & 1) // FIXME const.
    {
        DPRINT1("HidClass_Create: STATUS_NOT_A_DIRECTORY \n");
        Status = STATUS_NOT_A_DIRECTORY;
        goto UnlockExit;
    }

    //
    // get PnP states
    //
    HidFdoState = FDODeviceExtension->HidFdoState;
    HidPdoState = PDODeviceExtension->HidPdoState;

    DPRINT("HidClass_Create: HidFdoState - %X, HidPdoState - %X\n",
           HidFdoState,
           HidPdoState);

    //
    // validate PnP states
    //
    if ((HidFdoState != HIDCLASS_STATE_STARTED &&
         HidFdoState != HIDCLASS_STATE_STOPPING &&
         HidFdoState != HIDCLASS_STATE_DISABLED) ||
        (HidPdoState != HIDCLASS_STATE_STARTED &&
         HidPdoState != HIDCLASS_STATE_FAILED &&
         HidPdoState != HIDCLASS_STATE_STOPPING))
    {
        DPRINT1("HidClass_Create: STATUS_DEVICE_NOT_CONNECTED \n");
        Status = STATUS_DEVICE_NOT_CONNECTED;
        goto UnlockExit;
    }

    //
    // allocate file context
    //
    FileContext = ExAllocatePoolWithTag(NonPagedPool,
                                        sizeof(HIDCLASS_FILEOP_CONTEXT),
                                        HIDCLASS_TAG);

    if (!FileContext)
    {
        DPRINT1("HidClass_Create: Allocate context failed\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto UnlockExit;
    }

    //
    // initialize file context
    //
    RtlZeroMemory(FileContext, sizeof(HIDCLASS_FILEOP_CONTEXT));

    FileContext->DeviceExtension = PDODeviceExtension;
    FileContext->FileObject = IoStack->FileObject;

    KeInitializeSpinLock(&FileContext->Lock);
    InitializeListHead(&FileContext->InterruptReadIrpList);
    InitializeListHead(&FileContext->ReportList);

//InitializeListHead(&FileContext->ReadPendingIrpListHead);
//InitializeListHead(&FileContext->IrpCompletedListHead);
//KeInitializeEvent(&FileContext->IrpReadComplete, NotificationEvent, FALSE);

    FileContext->MaxReportQueueSize = HIDCLASS_MAX_REPORT_QUEUE_SIZE;
    FileContext->PendingReports = 0;
    FileContext->RetryReads = 0;

    InsertTailList(&HidCollection->InterruptReportList,
                   &FileContext->InterruptReportLink);

    FileContext->FileAttributes = IoStack->Parameters.Create.FileAttributes;
    FileContext->DesiredAccess = IoStack->Parameters.Create.SecurityContext->DesiredAccess;
    FileContext->ShareAccess = IoStack->Parameters.Create.ShareAccess;

    FileContext->IsMyPrivilegeTrue = IsPrivilege;
    //FileContext->SessionId = SessionId; FIXME

    //
    // store pointer to file context
    //
    IoStack->FileObject->FsContext = FileContext;

    //
    // increment open counters
    //
    InterlockedExchangeAdd(&FDODeviceExtension->OpenCount, 1);
    InterlockedExchangeAdd(&PDODeviceExtension->OpenCount, 1);

    if (IoStack->Parameters.Create.SecurityContext->DesiredAccess & FILE_READ_DATA)
    {
        PDODeviceExtension->OpensForRead++;
    }

    if (IoStack->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_DATA)
    {
        PDODeviceExtension->OpensForWrite++;
    }

    if (!(IoStack->Parameters.Create.ShareAccess & FILE_SHARE_READ))
    {
        PDODeviceExtension->RestrictionsForRead++;
    }

    if (!(IoStack->Parameters.Create.ShareAccess & FILE_SHARE_WRITE))
    {
        PDODeviceExtension->RestrictionsForWrite++;
    }

    if (!IoStack->Parameters.Create.ShareAccess)
    {
        PDODeviceExtension->RestrictionsForAnyOpen++;
    }

UnlockExit:
    KeReleaseSpinLock(&HidCollection->CollectSpinLock, OldIrql);

Exit:
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    DPRINT("HidClass_Create: exit - %x\n", Status);
    return Status;
}

VOID
NTAPI
HidClassCompleteReadsForFileContext(
    IN PHIDCLASS_COLLECTION HidCollection,
    IN PHIDCLASS_FILEOP_CONTEXT FileContext)
{
    KIRQL OldIrql;
    PIRP Irp;
    PLIST_ENTRY Entry;
    LIST_ENTRY List;

    DPRINT("HidClassCompleteReadsForFileContext: ... \n");

    InitializeListHead(&List);

    KeAcquireSpinLock(&FileContext->Lock, &OldIrql);

    while (TRUE)
    {
        Irp = HidClassDequeueInterruptReadIrp(HidCollection, FileContext);

        if (!Irp)
        {
            break;
        }

        InsertTailList(&List, &Irp->Tail.Overlay.ListEntry);
    }

    KeReleaseSpinLock(&FileContext->Lock, OldIrql);

    while (TRUE)
    {
        if (IsListEmpty(&List))
        {
            break;
        }

        Entry = RemoveHeadList(&List);

        Irp = CONTAINING_RECORD(Entry,
                                IRP,
                                Tail.Overlay.ListEntry);

        Irp->IoStatus.Status = STATUS_DEVICE_NOT_CONNECTED;

        DPRINT("HidClassCompleteReadsForFileContext: Irp - %p\n", Irp);

        IoCompleteRequest(Irp, IO_KEYBOARD_INCREMENT);
    }
}

VOID
NTAPI
HidClassFlushReportQueue(
    IN PHIDCLASS_FILEOP_CONTEXT FileContext)
{
    KIRQL OldIrql;
    PHIDCLASS_INT_REPORT_HEADER Header;

    KeAcquireSpinLock(&FileContext->Lock, &OldIrql);

    while (TRUE)
    {
        Header = HidClassDequeueInterruptReport(FileContext, MAXULONG);

        if (!Header)
        {
            break;
        }

        ExFreePoolWithTag(Header, HIDCLASS_TAG);
    }

    KeReleaseSpinLock(&FileContext->Lock, OldIrql);
}

VOID
NTAPI
HidClassDestroyFileContext(
    IN PHIDCLASS_COLLECTION HidCollection,
    IN PHIDCLASS_FILEOP_CONTEXT FileContext)
{
    DPRINT("HidClassDestroyFileContext: FileContext - %p\n", FileContext);

    HidClassFlushReportQueue(FileContext); 
    HidClassCompleteReadsForFileContext(HidCollection, FileContext);
    ExFreePoolWithTag(FileContext, HIDCLASS_TAG);
}

NTSTATUS
NTAPI
HidClass_Close(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    NTSTATUS Status;
    PIO_STACK_LOCATION IoStack;
    PHIDCLASS_COMMON_DEVICE_EXTENSION CommonDeviceExtension;
    PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    PHIDCLASS_FILEOP_CONTEXT IrpContext;
    PHIDCLASS_COLLECTION HidCollection;
    KIRQL OldIrql;

    DPRINT("HidClass_Close: Irp - %p\n", Irp);

    //
    // get device extension
    //
    CommonDeviceExtension = DeviceObject->DeviceExtension;

    //
    // is it a FDO request
    //
    if (CommonDeviceExtension->IsFDO)
    {
        DPRINT1("HidClass_Close: Error ... \n");
        // how did the request get there
        Status = STATUS_INVALID_PARAMETER_1;
        goto Exit;
    }

    Irp->IoStatus.Information = 0;

    //
    // get device extensions
    //
    PDODeviceExtension = DeviceObject->DeviceExtension;
    FDODeviceExtension = PDODeviceExtension->FDODeviceExtension;

    //
    // get stack location
    //
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    //
    // sanity checks
    //
    ASSERT(IoStack->FileObject);
    ASSERT(IoStack->FileObject->FsContext);

    //
    // get irp context
    //
    IrpContext = IoStack->FileObject->FsContext;

    if (!IrpContext)
    {
        DPRINT1("HidClass_Close: Error ... \n");
        Status = STATUS_DEVICE_NOT_CONNECTED;
        goto Exit;
    }

    InterlockedExchangeAdd(&FDODeviceExtension->OpenCount, -1);

    HidCollection = GetHidclassCollection(FDODeviceExtension,
                                          PDODeviceExtension->CollectionNumber);

    if (!HidCollection)
    {
        DPRINT1("HidClass_Close: Error ... \n");
        Status = STATUS_DATA_ERROR;
        goto Exit;
    }

    if (FDODeviceExtension->HidFdoState == HIDCLASS_STATE_DELETED)
    {
        KeAcquireSpinLock(&HidCollection->CollectSpinLock, &OldIrql);
        RemoveEntryList(&IrpContext->InterruptReportLink);
        KeReleaseSpinLock(&HidCollection->CollectSpinLock, OldIrql);

        if (IrpContext->IsMyPrivilegeTrue)
        {
            KeAcquireSpinLock(&HidCollection->CollectCloseSpinLock, &OldIrql);

            while (IrpContext->CloseCounter)
            {
                IrpContext->CloseCounter--;
                HidCollection->CloseFlag--;
            }

            IrpContext->CloseCounter--;

            KeReleaseSpinLock(&HidCollection->CollectCloseSpinLock, OldIrql);
        }

        HidClassDestroyFileContext(HidCollection, IrpContext);

        DPRINT1("HidClass_Close: FIXME RemoveLock support\n");
        ASSERT(FALSE);

        if (0)//IoAcquireRemoveLock(&FDODeviceExtension->HidRemoveLock, 0))
        {
            HidClassCleanUpFDO(FDODeviceExtension);
        }
    }
    else
    {
        KeAcquireSpinLock(&HidCollection->CollectSpinLock, &OldIrql);
        InterlockedExchangeAdd(&PDODeviceExtension->OpenCount, -1);

        if (IrpContext->DesiredAccess & FILE_READ_DATA)
        {
            PDODeviceExtension->OpensForRead--;
        }

        if (IrpContext->DesiredAccess & FILE_WRITE_DATA)
        {
            PDODeviceExtension->OpensForWrite--;
        }

        if (!(IrpContext->ShareAccess & FILE_SHARE_READ))
        {
            PDODeviceExtension->RestrictionsForRead--;
        }

        if (!(IrpContext->ShareAccess & FILE_SHARE_WRITE))
        {
            PDODeviceExtension->RestrictionsForWrite--;
        }

        if (!IrpContext->ShareAccess)
        {
            PDODeviceExtension->RestrictionsForAnyOpen--;
        }

        RemoveEntryList(&IrpContext->InterruptReportLink);
        KeReleaseSpinLock(&HidCollection->CollectSpinLock, OldIrql);

        if (IrpContext->IsMyPrivilegeTrue)
        {
            KeAcquireSpinLock(&HidCollection->CollectCloseSpinLock, &OldIrql);

            while (IrpContext->CloseCounter)
            {
                IrpContext->CloseCounter--;
                HidCollection->CloseFlag--;
            }

            IrpContext->CloseCounter--;

            KeReleaseSpinLock(&HidCollection->CollectCloseSpinLock, OldIrql);
        }

        HidClassDestroyFileContext(HidCollection, IrpContext);
    }

    Status = STATUS_SUCCESS;

Exit:

    //
    // complete request
    //
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

VOID
NTAPI
HidClassCompleteIrpAsynchronously(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context)
{
    PHIDCLASS_COMPLETION_WORKITEM CompletionWorkItem;

    DPRINT("HidClassCompleteIrpAsynchronously: ... \n");

    CompletionWorkItem = (PHIDCLASS_COMPLETION_WORKITEM)Context;
    IoCompleteRequest(CompletionWorkItem->Irp, 0);
    IoFreeWorkItem(CompletionWorkItem->CompleteWorkItem);
    ExFreePoolWithTag(CompletionWorkItem, HIDCLASS_TAG);
}

NTSTATUS
NTAPI
HidClass_Read(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PHIDCLASS_COMMON_DEVICE_EXTENSION CommonDeviceExtension;
    PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    PIO_STACK_LOCATION IoStack;
    PFILE_OBJECT FileObject;
    PHIDCLASS_COLLECTION HidCollection;
    PHIDP_COLLECTION_DESC HidCollectionDesc;
    PHIDCLASS_FILEOP_CONTEXT FileContext;
    PHIDCLASS_INT_REPORT_HEADER Header;
    PHIDCLASS_COMPLETION_WORKITEM CompletionWorkItem;
    ULONG HidFdoState;
    ULONG HidPdoState;
    ULONG Length;
    PVOID VAddress;
    PVOID StartVAddress;
    ULONG ReportSize;
    ULONG BufferRemaining;
    PVOID InputReportBuffer;
    NTSTATUS Status;
    ULONG ix;
    CCHAR Increment;
    BOOLEAN IsNotRunning;
    KIRQL OldIrql;

    DPRINT("HidClass_Read: Irp - %p\n", Irp);

    //
    // get device extensions
    //
    CommonDeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(CommonDeviceExtension->IsFDO == FALSE);
    PDODeviceExtension = DeviceObject->DeviceExtension;
    FDODeviceExtension = PDODeviceExtension->FDODeviceExtension;

    //
    // get current stack location
    //
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    FileObject = IoStack->FileObject;

    if (!FileObject)
    {
        DPRINT1("HidClass_Read: error ... \n");
        Irp->IoStatus.Status = STATUS_PRIVILEGE_NOT_HELD;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_PRIVILEGE_NOT_HELD;
    }

    FileContext = FileObject->FsContext;

    if (!FileContext)
    {
        DPRINT1("HidClass_Read: error ... \n");
        Irp->IoStatus.Status = STATUS_PRIVILEGE_NOT_HELD;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_PRIVILEGE_NOT_HELD;
    }

    ASSERT(IoStack->FileObject->Type == IO_TYPE_FILE);

    HidFdoState = FDODeviceExtension->HidFdoState;
    HidPdoState = PDODeviceExtension->HidPdoState;

    if (((HidFdoState != HIDCLASS_STATE_STARTED) &&
         (HidFdoState != HIDCLASS_STATE_STOPPING) &&
         (HidFdoState != HIDCLASS_STATE_DISABLED)) ||
        ((HidPdoState != HIDCLASS_STATE_STARTED) &&
         (HidPdoState != HIDCLASS_STATE_FAILED) &&
         (HidPdoState != HIDCLASS_STATE_STOPPING)))
    {
        DPRINT1("HidClass_Read: Not valid state. FdoState - %x, PdoState - %x\n",
                HidFdoState,
                HidPdoState);

        Status = STATUS_DEVICE_NOT_CONNECTED;
        goto Exit;
    }

    if (HidFdoState == HIDCLASS_STATE_DISABLED ||
        HidFdoState == HIDCLASS_STATE_STOPPING ||
        HidPdoState == HIDCLASS_STATE_FAILED ||
        HidPdoState == HIDCLASS_STATE_STOPPING)
    {
        IsNotRunning = TRUE;
    }
    else
    {
        IsNotRunning = FALSE;
    }

    Irp->IoStatus.Information = 0;

    HidCollection = GetHidclassCollection(FDODeviceExtension,
                                          PDODeviceExtension->CollectionNumber);

    HidCollectionDesc = GetCollectionDesc(FDODeviceExtension,
                                          PDODeviceExtension->CollectionNumber);

    if (!HidCollection || !HidCollectionDesc)
    {
        DPRINT1("HidClass_Read: error ... \n");
        Status = STATUS_DEVICE_NOT_CONNECTED;

        if (Status == STATUS_PENDING)
        {
            return STATUS_PENDING;
        }

        goto Exit;
    }

    Length = IoStack->Parameters.Read.Length;

    if (Length < HidCollectionDesc->InputLength)
    {
        DPRINT1("HidClass_Read: error ... \n");
        Status = STATUS_INVALID_BUFFER_SIZE;

        if (Status == STATUS_PENDING)
        {
            return STATUS_PENDING;
        }

        goto Exit;
    }

    DPRINT("HidClass_Read: Polled - %x\n", HidCollection->HidCollectInfo.Polled);

    if (!HidCollection->HidCollectInfo.Polled)
    {
        KeAcquireSpinLock(&FileContext->Lock, &OldIrql);

        //
        // FIXME: PowerState implement
        //
        if (IsNotRunning /*|| (FDODeviceExtension->DevicePowerState != PowerDeviceD0)*/)
        {
            Status = HidClassEnqueueInterruptReadIrp(HidCollection, FileContext, Irp);
        }
        else
        {
            BufferRemaining = IoStack->Parameters.Read.Length;

            VAddress = MmGetSystemAddressForMdlSafe(Irp->MdlAddress,
                                                    NormalPagePriority);

            StartVAddress = VAddress;

            if (!VAddress)
            {
                DPRINT1("HidClass_Read: Invalid buffer address\n");
                Status = STATUS_INVALID_USER_BUFFER;
                KeReleaseSpinLock(&FileContext->Lock, OldIrql);

                if (Status == STATUS_PENDING)
                {
                    return STATUS_PENDING;
                }

                goto Exit;
            }

            Status = STATUS_SUCCESS;

            if (BufferRemaining > 0)
            {
                for (ix = 0; BufferRemaining; ix++)
                {
                    ReportSize = BufferRemaining;
                    Header = HidClassDequeueInterruptReport(FileContext, ReportSize);

                    if (!Header)
                    {
                        break;
                    }

                    InputReportBuffer = (PVOID)((ULONG_PTR)Header +
                                                sizeof(HIDCLASS_INT_REPORT_HEADER));

                    Status = HidClassCopyInputReportToUser(FileContext,
                                                           InputReportBuffer,
                                                           &ReportSize,
                                                           VAddress);

                    ExFreePoolWithTag(Header, HIDCLASS_TAG);

                    if (!NT_SUCCESS(Status))
                    {
                        KeReleaseSpinLock(&FileContext->Lock, OldIrql);

                        if (Status == STATUS_PENDING)
                        {
                            return STATUS_PENDING;
                        }

                        goto Exit;
                    }

                    VAddress = (PVOID)((ULONG_PTR)VAddress + ReportSize);
                    BufferRemaining -= ReportSize;
                }

                if (!NT_SUCCESS(Status))
                {
                    KeReleaseSpinLock(&FileContext->Lock, OldIrql);

                    if (Status == STATUS_PENDING)
                    {
                        return STATUS_PENDING;
                    }

                    goto Exit;
                }

                if (ix > 0)
                {
                    Irp->IoStatus.Information = (ULONG_PTR)VAddress -
                                                (ULONG_PTR)StartVAddress;

                    KeReleaseSpinLock(&FileContext->Lock, OldIrql);

                    if (Status == STATUS_PENDING)
                    {
                        return STATUS_PENDING;
                    }

                    goto Exit;
                }
            }

            Status = HidClassEnqueueInterruptReadIrp(HidCollection,
                                                     FileContext,
                                                     Irp);
        }

        KeReleaseSpinLock(&FileContext->Lock, OldIrql);

        if (Status == STATUS_PENDING)
        {
            return STATUS_PENDING;
        }
    }
    else
    {
        DPRINT("HidClass_Read: Polled collection not implemented. FIXME\n");
    }

Exit:

    Irp->IoStatus.Status = Status;

    if (FileContext->RetryReads > 1)
    {
        DPRINT("HidClass_Read: RetryReads - %x\n", FileContext->RetryReads);
    }

    if (InterlockedIncrement(&FileContext->RetryReads) > 4)
    {
        CompletionWorkItem = ExAllocatePoolWithTag(NonPagedPool,
                                                   sizeof(HIDCLASS_COMPLETION_WORKITEM),
                                                   HIDCLASS_TAG);

        if (CompletionWorkItem)
        {
            PIO_WORKITEM WorkItem;

            WorkItem = IoAllocateWorkItem(PDODeviceExtension->SelfDevice);
            CompletionWorkItem->CompleteWorkItem = WorkItem;

            CompletionWorkItem->Irp = Irp;
            IoMarkIrpPending(Irp);

            IoQueueWorkItem(CompletionWorkItem->CompleteWorkItem,
                            HidClassCompleteIrpAsynchronously,
                            DelayedWorkQueue,
                            CompletionWorkItem);

            InterlockedExchangeAdd(&FileContext->RetryReads, -1);
            return STATUS_PENDING;
        }

        Increment = IO_NO_INCREMENT;
    }
    else
    {
        Increment = IO_KEYBOARD_INCREMENT;
    }

    IoCompleteRequest(Irp, Increment);
    InterlockedExchangeAdd(&FileContext->RetryReads, -1);
    return Status;
}

NTSTATUS
NTAPI
HidClassInterruptWriteComplete(
    IN PDEVICE_OBJECT Device,
    IN PIRP Irp,
    IN PVOID Context)
{
    PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    PHIDP_COLLECTION_DESC HidCollectionDesc;
    NTSTATUS Status;

    DPRINT("HidClassInterruptWriteComplete: ... \n");

    PDODeviceExtension = (PHIDCLASS_PDO_DEVICE_EXTENSION)Context;
    Status = Irp->IoStatus.Status;

    ExFreePoolWithTag(Irp->UserBuffer, HIDCLASS_TAG);

    Irp->UserBuffer = NULL;

    if (NT_SUCCESS(Status))
    {
        FDODeviceExtension = PDODeviceExtension->FDODeviceExtension;

        HidCollectionDesc = GetCollectionDesc(FDODeviceExtension,
                                              PDODeviceExtension->CollectionNumber);

        if (HidCollectionDesc)
        {
            HidClassSetDeviceBusy(FDODeviceExtension);
            Irp->IoStatus.Information = HidCollectionDesc->OutputLength;
        }
    }

    if (Irp->PendingReturned)
    {
        IoMarkIrpPending(Irp);
    }

    return Status;
}

NTSTATUS
NTAPI
HidClass_Write(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PHIDCLASS_COMMON_DEVICE_EXTENSION CommonDeviceExtension;
    PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    PIO_STACK_LOCATION IoStack;
    PFILE_OBJECT FileObject;
    PVOID Report;
    PHIDP_REPORT_IDS ReportId;
    PHIDP_COLLECTION_DESC HidCollectionDesc;
    PHID_XFER_PACKET XferPacket;
    NTSTATUS Status;

    DPRINT("HidClass_Write: PDO - %p, Irp - %p\n", DeviceObject, Irp);

    //
    // get device extensions
    //
    CommonDeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(CommonDeviceExtension->IsFDO == FALSE);
    PDODeviceExtension = DeviceObject->DeviceExtension;
    FDODeviceExtension = PDODeviceExtension->FDODeviceExtension;

    if (PDODeviceExtension->HidPdoState != HIDCLASS_STATE_STARTED ||
        FDODeviceExtension->HidFdoState != HIDCLASS_STATE_STARTED)
    {
        Status = STATUS_DEVICE_NOT_CONNECTED;
        goto Exit;
    }

    //
    // get current stack location
    //
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    FileObject = IoStack->FileObject;

    if (FileObject && FileObject->FsContext == NULL)
    {
        Status = STATUS_PRIVILEGE_NOT_HELD;
        goto Exit;
    }

    //
    // FIXME CheckIdleState()
    //

    Report = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

    if (!Report)
    {
        Status = STATUS_INVALID_USER_BUFFER;
        goto Exit;
    }

    //
    // first byte of the buffer is the report ID for the report
    //
    ReportId = GetReportIdentifier(FDODeviceExtension, *(PUCHAR)Report);

    if (!ReportId || !ReportId->OutputLength)
    {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    HidCollectionDesc = GetCollectionDesc(FDODeviceExtension,
                                          PDODeviceExtension->CollectionNumber);

    if (!HidCollectionDesc)
    {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (IoStack->Parameters.Write.Length != HidCollectionDesc->OutputLength)
    {
        Status = STATUS_INVALID_BUFFER_SIZE;
        goto Exit;
    }

    XferPacket = ExAllocatePoolWithTag(NonPagedPool,
                                       sizeof(HID_XFER_PACKET),
                                       HIDCLASS_TAG);

    if (!XferPacket)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    XferPacket->reportBuffer = Report;
    XferPacket->reportBufferLen = ReportId->OutputLength;
    XferPacket->reportId = *XferPacket->reportBuffer;

    if (!CommonDeviceExtension->DeviceDescription.ReportIDs->ReportID)
    {
        XferPacket->reportBuffer++;
    }

    Irp->UserBuffer = XferPacket;

    IoStack = IoGetNextIrpStackLocation(Irp);

    IoStack->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
    IoStack->Parameters.DeviceIoControl.InputBufferLength = sizeof(HID_XFER_PACKET);
    IoStack->Parameters.DeviceIoControl.IoControlCode = IOCTL_HID_WRITE_REPORT;

    IoSetCompletionRoutine(Irp,
                           HidClassInterruptWriteComplete,
                           PDODeviceExtension,
                           TRUE,
                           TRUE,
                           TRUE);

    Status = HidClassFDO_DispatchRequest(FDODeviceExtension->FDODeviceObject,
                                         Irp);

    Irp = NULL;

Exit:

    if (Irp)
    {
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return Status;
}

NTSTATUS
NTAPI
HidClass_DeviceControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    PHIDCLASS_COMMON_DEVICE_EXTENSION CommonDeviceExtension;
    PHID_COLLECTION_INFORMATION CollectionInformation;
    PHIDP_COLLECTION_DESC CollectionDescription;
    PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension;

    //
    // get device extension
    //
    CommonDeviceExtension = DeviceObject->DeviceExtension;

    //
    // only PDO are supported
    //
    if (CommonDeviceExtension->IsFDO)
    {
        //
        // invalid request
        //
        DPRINT1("[HIDCLASS] DeviceControl Irp for FDO arrived\n");
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER_1;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_PARAMETER_1;
    }

    ASSERT(CommonDeviceExtension->IsFDO == FALSE);

    //
    // get pdo device extension
    //
    PDODeviceExtension = DeviceObject->DeviceExtension;

    //
    // get stack location
    //
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    switch (IoStack->Parameters.DeviceIoControl.IoControlCode)
    {
        case IOCTL_HID_GET_COLLECTION_INFORMATION:
        {
            //
            // check if output buffer is big enough
            //
            if (IoStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(HID_COLLECTION_INFORMATION))
            {
                //
                // invalid buffer size
                //
                Irp->IoStatus.Status = STATUS_INVALID_BUFFER_SIZE;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return STATUS_INVALID_BUFFER_SIZE;
            }

            //
            // get output buffer
            //
            CollectionInformation = Irp->AssociatedIrp.SystemBuffer;
            ASSERT(CollectionInformation);

            //
            // get collection description
            //
            CollectionDescription = HidClassPDO_GetCollectionDescription(&CommonDeviceExtension->DeviceDescription,
                                                                         PDODeviceExtension->CollectionNumber);
            ASSERT(CollectionDescription);

            //
            // init result buffer
            //
            CollectionInformation->DescriptorSize = CollectionDescription->PreparsedDataLength;
            CollectionInformation->Polled = CommonDeviceExtension->DriverExtension->DevicesArePolled;
            CollectionInformation->VendorID = CommonDeviceExtension->Attributes.VendorID;
            CollectionInformation->ProductID = CommonDeviceExtension->Attributes.ProductID;
            CollectionInformation->VersionNumber = CommonDeviceExtension->Attributes.VersionNumber;

            //
            // complete request
            //
            Irp->IoStatus.Information = sizeof(HID_COLLECTION_INFORMATION);
            Irp->IoStatus.Status = STATUS_SUCCESS;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }
        case IOCTL_HID_GET_COLLECTION_DESCRIPTOR:
        {
            //
            // get collection description
            //
            CollectionDescription = HidClassPDO_GetCollectionDescription(&CommonDeviceExtension->DeviceDescription,
                                                                         PDODeviceExtension->CollectionNumber);
            ASSERT(CollectionDescription);

            //
            // check if output buffer is big enough
            //
            if (IoStack->Parameters.DeviceIoControl.OutputBufferLength < CollectionDescription->PreparsedDataLength)
            {
                //
                // invalid buffer size
                //
                Irp->IoStatus.Status = STATUS_INVALID_BUFFER_SIZE;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return STATUS_INVALID_BUFFER_SIZE;
            }

            //
            // copy result
            //
            ASSERT(Irp->UserBuffer);
            RtlCopyMemory(Irp->UserBuffer, CollectionDescription->PreparsedData, CollectionDescription->PreparsedDataLength);

            //
            // complete request
            //
            Irp->IoStatus.Information = CollectionDescription->PreparsedDataLength;
            Irp->IoStatus.Status = STATUS_SUCCESS;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }
        case IOCTL_GET_SYS_BUTTON_CAPS:
        {
            DPRINT1("[HIDCLASS] IOCTL_GET_SYS_BUTTON_CAPS not implemented\n");
            Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_NOT_IMPLEMENTED;
        }
        default:
        {
            DPRINT1("[HIDCLASS] DeviceControl IoControlCode 0x%x not implemented\n",
                    IoStack->Parameters.DeviceIoControl.IoControlCode);

            Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_NOT_IMPLEMENTED;
        }
    }
}

NTSTATUS
NTAPI
HidClass_InternalDeviceControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    UNIMPLEMENTED;
    ASSERT(FALSE);
    Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
HidClass_Power(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PHIDCLASS_COMMON_DEVICE_EXTENSION CommonDeviceExtension;
    CommonDeviceExtension = DeviceObject->DeviceExtension;
 
    if (CommonDeviceExtension->IsFDO)
    {
        IoCopyCurrentIrpStackLocationToNext(Irp);
        return HidClassFDO_DispatchRequest(DeviceObject, Irp);
    }
    else
    {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        PoStartNextPowerIrp(Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
}

NTSTATUS
NTAPI
HidClass_PnP(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PHIDCLASS_COMMON_DEVICE_EXTENSION CommonDeviceExtension;

    //
    // get common device extension
    //
    CommonDeviceExtension = DeviceObject->DeviceExtension;

    //
    // check type of device object
    //
    if (CommonDeviceExtension->IsFDO)
    {
        //
        // handle request
        //
        return HidClassFDO_PnP(DeviceObject, Irp);
    }
    else
    {
        //
        // handle request
        //
        return HidClassPDO_PnP(DeviceObject, Irp);
    }
}

NTSTATUS
NTAPI
HidClass_SystemControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    DPRINT("HidClass_SystemControl: FIXME. DeviceObject - %p, Irp - %p\n",
           DeviceObject,
           Irp);

    UNIMPLEMENTED;
    //WmiSystemControl()
    return 0;
}

NTSTATUS
NTAPI
HidClass_DispatchDefault(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PHIDCLASS_COMMON_DEVICE_EXTENSION CommonDeviceExtension;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    PHID_DEVICE_EXTENSION HidDeviceExtension;
    NTSTATUS Status;

    DPRINT("DispatchDefault: DeviceObject - %p, Irp - %p\n", DeviceObject, Irp);

    //
    // get common device extension
    //
    CommonDeviceExtension = DeviceObject->DeviceExtension;

    if ( CommonDeviceExtension->IsFDO )
    {
        //
        // get device extensions
        //
        FDODeviceExtension = DeviceObject->DeviceExtension;
        HidDeviceExtension = &FDODeviceExtension->Common.HidDeviceExtension;

        //
        // copy current IRP stack location to next
        //
        IoCopyCurrentIrpStackLocationToNext(Irp);

        //
        // dispatch to lower PDO
        //
        Status = HidClassFDO_DispatchRequest(HidDeviceExtension->PhysicalDeviceObject,
                                             Irp);
    }
    else
    {
        Status = Irp->IoStatus.Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return Status;
}

NTSTATUS
NTAPI
HidClassDispatch(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;

    //
    // get current stack location
    //
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    DPRINT("[HIDCLASS] Dispatch Major %x Minor %x\n",
           IoStack->MajorFunction,
           IoStack->MinorFunction);

    //
    // dispatch request based on major function
    //
    switch (IoStack->MajorFunction)
    {
        case IRP_MJ_CREATE:
            return HidClass_Create(DeviceObject, Irp);

        case IRP_MJ_CLOSE:
            return HidClass_Close(DeviceObject, Irp);

        case IRP_MJ_READ:
            return HidClass_Read(DeviceObject, Irp);

        case IRP_MJ_WRITE:
            return HidClass_Write(DeviceObject, Irp);

        case IRP_MJ_DEVICE_CONTROL:
            return HidClass_DeviceControl(DeviceObject, Irp);

        case IRP_MJ_INTERNAL_DEVICE_CONTROL:
           return HidClass_InternalDeviceControl(DeviceObject, Irp);

        case IRP_MJ_POWER:
            return HidClass_Power(DeviceObject, Irp);

        case IRP_MJ_PNP:
            return HidClass_PnP(DeviceObject, Irp);

        case IRP_MJ_SYSTEM_CONTROL:
            return HidClass_SystemControl(DeviceObject, Irp);

        default:
            return HidClass_DispatchDefault(DeviceObject, Irp);
    }
}

BOOLEAN
NTAPI
InsertDriverExtList(
    IN PHIDCLASS_DRIVER_EXTENSION DriverExtension)
{
    BOOLEAN Result = TRUE;
    PLIST_ENTRY Entry;
    PHIDCLASS_DRIVER_EXTENSION driverExtension = NULL;

    DPRINT("InsertDriverExtList: DriverExtension - %p\n", DriverExtension);

    ExAcquireFastMutex(&DriverExtListMutex);

    //
    // add link for DriverExtension to end list
    //
    for (Entry = DriverExtList.Flink; ; Entry = Entry->Flink)
    {
        if (Entry == &DriverExtList)
        {
            InsertTailList(&DriverExtList, &DriverExtension->DriverExtLink);
            goto Exit;
        }

        driverExtension = CONTAINING_RECORD(Entry,
                                            HIDCLASS_DRIVER_EXTENSION,
                                            DriverExtLink.Flink);

        if (driverExtension == DriverExtension)
        {
            break;
        }
    }

    Result = FALSE;

Exit:
    ExReleaseFastMutex(&DriverExtListMutex);
    return Result;
}

NTSTATUS
NTAPI
HidRegisterMinidriver(
    IN PHID_MINIDRIVER_REGISTRATION MinidriverRegistration)
{
    NTSTATUS Status;
    PHIDCLASS_DRIVER_EXTENSION DriverExtension;
    PDRIVER_OBJECT MiniDriver;

    //
    // check if the version matches
    //
    if (MinidriverRegistration->Revision > HID_REVISION)
    {
        //
        // revision mismatch
        //
        DPRINT1("HIDCLASS revision is %d. Should be HID_REVISION (1)\n",
                MinidriverRegistration->Revision);

        ASSERT(FALSE);
        return STATUS_REVISION_MISMATCH;
    }

    MiniDriver = MinidriverRegistration->DriverObject;
    DPRINT("HidRegisterMinidriver: MiniDriver - %p\n", MiniDriver);

    //
    // now allocate the driver object extension
    //
    Status = IoAllocateDriverObjectExtension(MiniDriver,
                                             ClientIdentificationAddress,
                                             sizeof(HIDCLASS_DRIVER_EXTENSION),
                                             (PVOID *)&DriverExtension);
    if (!NT_SUCCESS(Status))
    {
        //
        // failed to allocate driver extension
        //
        DPRINT1("HidRegisterMinidriver: IoAllocateDriverObjectExtension failed %x\n",
                Status);

        ASSERT(FALSE);
        return Status;
    }

    //
    // zero driver extension
    //
    RtlZeroMemory(DriverExtension, sizeof(HIDCLASS_DRIVER_EXTENSION));

    //
    // initialize driver extension
    //
    DriverExtension->DriverObject = MiniDriver;
    DriverExtension->DeviceExtensionSize = MinidriverRegistration->DeviceExtensionSize;
    DriverExtension->DevicesArePolled = MinidriverRegistration->DevicesArePolled;

    //
    // copy driver dispatch routines
    //
    RtlCopyMemory(DriverExtension->MajorFunction,
                  MiniDriver->MajorFunction,
                  sizeof(PDRIVER_DISPATCH) * (IRP_MJ_MAXIMUM_FUNCTION + 1));

    MiniDriver->MajorFunction[IRP_MJ_CREATE] = HidClassDispatch;
    MiniDriver->MajorFunction[IRP_MJ_CLOSE] = HidClassDispatch;
    MiniDriver->MajorFunction[IRP_MJ_READ] = HidClassDispatch;
    MiniDriver->MajorFunction[IRP_MJ_WRITE] = HidClassDispatch;
    MiniDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HidClassDispatch;
    MiniDriver->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = HidClassDispatch;
    MiniDriver->MajorFunction[IRP_MJ_POWER] = HidClassDispatch;
    MiniDriver->MajorFunction[IRP_MJ_PNP] = HidClassDispatch;

    ASSERT(MiniDriver->DriverExtension->AddDevice);
    DriverExtension->AddDevice = MiniDriver->DriverExtension->AddDevice;
    MiniDriver->DriverExtension->AddDevice = HidClassAddDevice;

    ASSERT(MiniDriver->DriverUnload);
    DriverExtension->DriverUnload = MiniDriver->DriverUnload;
    MiniDriver->DriverUnload = HidClassDriverUnload;

    //
    // initialize reference counter
    //
    DriverExtension->RefCount = 0;

    //
    // add driver extension to list
    //
    if (!InsertDriverExtList(DriverExtension))
    {
        DPRINT1("HidRegisterMinidriver: InsertDriverExtList failed\n");
        Status = STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    return STATUS_SUCCESS;
}
