/*
 * PROJECT:     Partition manager driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Main file
 * COPYRIGHT:   Copyright 2018, 2019, 2023 Vadim Galyant <vgal@rambler.ru>
 */

#include "partmgr.h"

#define NDEBUG
#include <debug.h>

#ifdef ALLOC_PRAGMA
  #pragma alloc_text(INIT, DriverEntry)
#endif

#ifdef ALLOC_PRAGMA
  #pragma alloc_text(PAGE, PmAddDevice)
  #pragma alloc_text(PAGE, PmDeviceControl)
  #pragma alloc_text(PAGE, PmPower)
  #pragma alloc_text(PAGE, PmWmi)
  #pragma alloc_text(PAGE, PmPnp)
  #pragma alloc_text(PAGE, PmDriverReinit)
  #pragma alloc_text(PAGE, PmTableSignatureCompareRoutine)
  #pragma alloc_text(PAGE, PmTableGuidCompareRoutine)
  #pragma alloc_text(PAGE, PmTableAllocateRoutine)
  #pragma alloc_text(PAGE, PmTableFreeRoutine)
  #pragma alloc_text(PAGE, PmVolumeManagerNotification)
  #pragma alloc_text(PAGE, PmQueryDeviceRelations)
  #pragma alloc_text(PAGE, PmDetermineDeviceNameAndNumber)
  #pragma alloc_text(PAGE, PmReadPartitionTableEx)
  #pragma alloc_text(PAGE, LockDriverWithTimeout)
  #pragma alloc_text(PAGE, PmQueryDeviceId)
  #pragma alloc_text(PAGE, PmAddSignatures)
  #pragma alloc_text(PAGE, PmCheckAndUpdateSignature)
  #pragma alloc_text(PAGE, PmRegisterDevice)
  #pragma alloc_text(PAGE, PmStartPartition)
  #pragma alloc_text(PAGE, PmGivePartition)
#endif

/* GLOBALS *******************************************************************/

GUID VOLMGR_VOLUME_MANAGER_GUID = {0x53F5630E, 0xB6BF, 0x11D0, {0X94, 0XF2, 0X00, 0XA0, 0XC9, 0X1E, 0XFB, 0X8B}};
GUID PARTITION_BASIC_DATA_GUID  = {0xEBD0A0A2, 0xB9E5, 0x4433, {0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7}};

/* FUNCTIONS ****************************************************************/

NTSTATUS
NTAPI
PmSignalCompletion(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PKEVENT Event = Context;

    KeSetEvent(Event, 0, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
PmPassThrough(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PPM_DEVICE_EXTENSION DeviceExtension;

    DPRINT("PmPassThrough: %p, %p\n", DeviceObject, Irp);

    DeviceExtension = DeviceObject->DeviceExtension;
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(DeviceExtension->AttachedToDevice, Irp);
}

VOID
NTAPI
PmUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
PmAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT DiskPdo)
{
    PPM_DEVICE_EXTENSION Extension;
    PDEVICE_OBJECT PartitionFido;
    PDEVICE_OBJECT TopDevice;
    NTSTATUS Status;

    DPRINT("PmAddDevice: %p, %p\n", DriverObject, DiskPdo);

    TopDevice = IoGetAttachedDeviceReference(DiskPdo);
    if (TopDevice)
    {
        ObDereferenceObject(TopDevice);

        if (TopDevice->Characteristics & FILE_REMOVABLE_MEDIA)
            return STATUS_SUCCESS;
    }

    Status = IoCreateDevice(DriverObject,
                            sizeof(*Extension),
                            NULL,
                            FILE_DEVICE_UNKNOWN,
                            0,
                            FALSE,
                            &PartitionFido);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PmAddDevice: %p, %p\n", DriverObject, DiskPdo);
        return Status;
    }

    PartitionFido->Flags |= DO_DIRECT_IO;

    if (TopDevice->Flags & DO_POWER_INRUSH)
        PartitionFido->Flags |= DO_POWER_INRUSH;
    else
        PartitionFido->Flags |= DO_POWER_PAGABLE;

    Extension = PartitionFido->DeviceExtension;
    RtlZeroMemory(Extension, sizeof(*Extension));

    Extension->PartitionFido = PartitionFido;
    Extension->DriverExtension = IoGetDriverObjectExtension(DriverObject, PmAddDevice);

    Extension->AttachedToDevice = IoAttachDeviceToDeviceStack(PartitionFido, DiskPdo);
    if (!Extension->AttachedToDevice)
    {
        DPRINT1("PmAddDevice: AttachedToDevice is NULL! (%p, %p)\n", DriverObject, DiskPdo);
        IoDeleteDevice(PartitionFido);
        return STATUS_NO_SUCH_DEVICE;
    }

    Extension->WholeDiskPdo = DiskPdo;

    KeInitializeEvent(&Extension->Event, SynchronizationEvent, TRUE);

    InitializeListHead(&Extension->PartitionList);
    InitializeListHead(&Extension->ListOfSignatures);
    InitializeListHead(&Extension->ListOfGuids);

    KeWaitForSingleObject(&Extension->DriverExtension->Mutex, Executive, KernelMode, FALSE, NULL);
    InsertTailList(&Extension->DriverExtension->ExtensionList, &Extension->Link);
    KeReleaseMutex(&Extension->DriverExtension->Mutex, FALSE);

    PartitionFido->DeviceType = Extension->AttachedToDevice->DeviceType;
    PartitionFido->AlignmentRequirement = Extension->AttachedToDevice->AlignmentRequirement;

    Extension->NameString.Buffer = Extension->NameBuffer;

    PartitionFido->Flags &= ~DO_DEVICE_INITIALIZING;

    IoInitializeRemoveLock(&Extension->RemoveLock, 'rRcS', 2, 5); 

    DPRINT("PmAddDevice: STATUS_SUCCESS\n");

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PmVolumeManagerNotification(
    _In_ PVOID NotificationStructure,
    _In_ PVOID Context)
{
    PDEVICE_INTERFACE_CHANGE_NOTIFICATION InterfaceChange = NotificationStructure;
    PPM_DRIVER_EXTENSION DriverExtension = Context;
    PPM_NOTIFICATION_DATA PmNotify;
    PLIST_ENTRY Entry;
    PRKMUTEX Mutex;
    USHORT Size;

    DPRINT("PmVolumeManagerNotification: %p, %p\n", InterfaceChange, DriverExtension);

    Mutex = &DriverExtension->Mutex;
    KeWaitForSingleObject(&DriverExtension->Mutex, Executive, KernelMode, FALSE, NULL);

    if (IsEqualGUID(&InterfaceChange->Event, &GUID_DEVICE_INTERFACE_ARRIVAL))
    {
        for (Entry = DriverExtension->NotifyList.Flink;
             Entry != &DriverExtension->NotifyList;
             Entry = Entry->Flink)
        {
            PmNotify = CONTAINING_RECORD(Entry, PM_NOTIFICATION_DATA, Link);

            DPRINT("PmVolumeManagerNotification: SymbolicLinkName '%wZ'\n", InterfaceChange->SymbolicLinkName);
            DPRINT("PmVolumeManagerNotification: ObjectName '%wZ'\n", &PmNotify->ObjectName);

            if (RtlEqualUnicodeString(InterfaceChange->SymbolicLinkName, &PmNotify->ObjectName, FALSE))
            {
                /* SymbolicLinkName strings are equal */
                goto Exit;
            }
        }

        PmNotify = ExAllocatePoolWithTag(NonPagedPool, sizeof(*PmNotify), 'VRcS');
        if (!PmNotify)
        {
            DPRINT1("PmVolumeManagerNotification: Allocate failed\n");
            goto Exit;
        }

        Size = InterfaceChange->SymbolicLinkName->Length;

        PmNotify->ObjectName.Length = Size;
        PmNotify->ObjectName.MaximumLength = (Size + sizeof(WCHAR));

        PmNotify->ObjectName.Buffer = ExAllocatePoolWithTag(PagedPool, (Size + sizeof(WCHAR)), 'VRcS');
        if (!PmNotify->ObjectName.Buffer)
        {
            DPRINT1("PmVolumeManagerNotification: Allocate failed\n");
            ExFreePoolWithTag(PmNotify, 'VRcS');
            goto Exit;
        }

        RtlCopyMemory(PmNotify->ObjectName.Buffer, InterfaceChange->SymbolicLinkName->Buffer, PmNotify->ObjectName.Length);

        PmNotify->ObjectName.Buffer[PmNotify->ObjectName.Length / sizeof(WCHAR)] = 0;

        PmNotify->Counter = 0;

        PmNotify->DeviceObject = NULL;
        PmNotify->FileObject = NULL;

        InsertTailList(&DriverExtension->NotifyList, &PmNotify->Link);

        for (Entry = DriverExtension->ExtensionList.Flink;
             Entry != &DriverExtension->ExtensionList;
             Entry = Entry->Flink)
        {
            DPRINT1("PmVolumeManagerNotification: FIXME\n");
            ASSERT(FALSE);
        }
    }
    else if (IsEqualGUID(&InterfaceChange->Event, &GUID_DEVICE_INTERFACE_REMOVAL))
    {
        DPRINT1("PmVolumeManagerNotification: FIXME\n");
        ASSERT(FALSE);
    }

Exit:

    KeReleaseMutex(Mutex, FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PmDetermineDeviceNameAndNumber(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG* OutPartitionData)
{
    STORAGE_DEVICE_NUMBER DeviceNumberBuffer;
    PPM_DEVICE_EXTENSION Extension;
    IO_STATUS_BLOCK IoStatusBlock;
    KEVENT Event;
    PIRP Irp;
    ULONG PartitionData = 0;
    ULONG Size;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PmDetermineDeviceNameAndNumber: %p\n", DeviceObject);

    Extension = DeviceObject->DeviceExtension;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildDeviceIoControlRequest(IOCTL_STORAGE_GET_DEVICE_NUMBER,
                                        Extension->AttachedToDevice,
                                        NULL,
                                        0,
                                        &DeviceNumberBuffer,
                                        sizeof(DeviceNumberBuffer),
                                        FALSE,
                                        &Event,
                                        &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("PmDetermineDeviceNameAndNumber: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = IoCallDriver(Extension->AttachedToDevice, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PmDetermineDeviceNameAndNumber: Status %X\n", Status);
        return Status;
    }

    Extension->DeviceNumber = DeviceNumberBuffer.DeviceNumber;

    Extension->NameString.MaximumLength = sizeof(Extension->NameBuffer);
    Extension->NameString.Buffer = Extension->NameBuffer;

    Size = _snwprintf(Extension->NameBuffer,
                      (sizeof(Extension->NameBuffer) / sizeof(WCHAR)),
                      L"\\Device\\Harddisk%d\\Partition%d",
                      DeviceNumberBuffer.DeviceNumber,
                      DeviceNumberBuffer.PartitionNumber);

    Extension->NameString.Length = (Size * sizeof(WCHAR));

    if (!DeviceNumberBuffer.PartitionNumber)
        PartitionData = 0x110000;

    *OutPartitionData = PartitionData;

    return Status;
}

NTSTATUS
NTAPI
PmReadPartitionTableEx(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PDRIVE_LAYOUT_INFORMATION_EX* OutDriveLayout)
{
    IO_STATUS_BLOCK IoStatusBlock;
    PVOID IoCtlBuffer;
    KEVENT Event;
    PIRP Irp;
    ULONG IoCtlBufferSize;
    ULONG ix;
    NTSTATUS Status;

    DPRINT("PmReadPartitionTableEx: DeviceObject %p\n", DeviceObject);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    IoCtlBuffer = ExAllocatePoolWithTag(0, PAGE_SIZE, 'iRcS');
    if (!IoCtlBuffer)
    {
        DPRINT1("PmReadPartitionTableEx: Allocate failed\n");
        return IoReadPartitionTableEx(DeviceObject, OutDriveLayout);
    }

    IoCtlBufferSize = PAGE_SIZE;

    for (ix = 0; ix <= 0x20; ix++)
    {
        KeClearEvent(&Event);

        Irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                                            DeviceObject,
                                            NULL,
                                            0,
                                            IoCtlBuffer,
                                            IoCtlBufferSize,
                                            FALSE,
                                            &Event,
                                            &IoStatusBlock);
        if (!Irp)
        {
            DPRINT1("PmReadPartitionTableEx: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto ErrorExit;
        }

        Status = IoCallDriver(DeviceObject, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoStatusBlock.Status;
        }

        if (NT_SUCCESS(Status))
        {
            ASSERT(IoCtlBuffer && IoCtlBufferSize);
            *OutDriveLayout = IoCtlBuffer;
            return STATUS_SUCCESS;
        }

        if (Status != STATUS_BUFFER_TOO_SMALL)
        {
            DPRINT1("PmReadPartitionTableEx: Status %X\n", Status);
            goto ErrorExit;
        }

        ASSERT(IoCtlBuffer && IoCtlBufferSize);
        ExFreePoolWithTag(IoCtlBuffer, 'iRcS');

        IoCtlBufferSize *= 2;

        IoCtlBuffer = ExAllocatePoolWithTag(NonPagedPool, IoCtlBufferSize, 'iRcS');
        if (!IoCtlBuffer)
        {
            DPRINT1("PmReadPartitionTableEx: Allocate failed\n");
            return IoReadPartitionTableEx(DeviceObject, OutDriveLayout);
        }
    }

    Status = STATUS_UNSUCCESSFUL;
    DPRINT1("PmReadPartitionTableEx: STATUS_UNSUCCESSFUL\n");

ErrorExit:

    if (IoCtlBuffer)
    {
        ASSERT(IoCtlBufferSize);
        ExFreePoolWithTag(IoCtlBuffer, 'iRcS');
    }

    return IoReadPartitionTableEx(DeviceObject, OutDriveLayout);
}

BOOLEAN
NTAPI
LockDriverWithTimeout(
    _In_ PPM_DRIVER_EXTENSION DriverExtension)
{
    LARGE_INTEGER Timeout;
    NTSTATUS Status;

    Timeout.QuadPart = (-6000 * 10000ull);
    Status = KeWaitForSingleObject(&DriverExtension->Mutex, Executive, KernelMode, FALSE, &Timeout);
    return (Status != STATUS_TIMEOUT);
}

NTSTATUS
NTAPI
PmQueryDeviceId(
    _In_ PPM_DEVICE_EXTENSION Extension,
    _In_ PSTORAGE_DEVICE_DESCRIPTOR* OutDeviceId)
{
    STORAGE_PROPERTY_QUERY InputBuffer;
    STORAGE_DESCRIPTOR_HEADER OutputBuffer;
    PSTORAGE_DEVICE_DESCRIPTOR DeviceId;
    IO_STATUS_BLOCK IoStatusBlock;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    DPRINT("PmQueryDeviceId: Extension %p\n", Extension);

    *OutDeviceId = NULL;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    InputBuffer.PropertyId = StorageDeviceIdProperty;
    InputBuffer.QueryType = PropertyStandardQuery;

    Irp = IoBuildDeviceIoControlRequest(IOCTL_STORAGE_QUERY_PROPERTY,
                                        Extension->AttachedToDevice,
                                        &InputBuffer,
                                        sizeof(InputBuffer),
                                        &OutputBuffer,
                                        sizeof(OutputBuffer),
                                        FALSE,
                                        &Event,
                                        &IoStatusBlock);
    if (Irp)
    {
        Status = IoCallDriver(Extension->AttachedToDevice, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoStatusBlock.Status;
        }
    }
    else
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PmQueryDeviceId: Status %p\n", Status);
        return Status;
    }

    DeviceId = ExAllocatePoolWithTag(NonPagedPool, OutputBuffer.Size, 'iRcS');
    if (!DeviceId)
    {
        DPRINT1("PmQueryDeviceId: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    InputBuffer.PropertyId = StorageDeviceIdProperty;
    InputBuffer.QueryType = PropertyStandardQuery;

    Irp = IoBuildDeviceIoControlRequest(IOCTL_STORAGE_QUERY_PROPERTY,
                                        Extension->AttachedToDevice,
                                        &InputBuffer,
                                        sizeof(InputBuffer),
                                        DeviceId,
                                        OutputBuffer.Size,
                                        FALSE,
                                        &Event,
                                        &IoStatusBlock);
    if (Irp)
    {
        Status = IoCallDriver(Extension->AttachedToDevice, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoStatusBlock.Status;
        }
    }
    else
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PmQueryDeviceId: Status %p\n", Status);
        ExFreePoolWithTag(DeviceId, 'iRcS');
        return Status;
    }

    *OutDeviceId = DeviceId;

    return Status;
}

NTSTATUS
NTAPI
PmReadGptAttributesOnMbr(
    _In_ PPM_DEVICE_EXTENSION Extension,
    _In_ PVOID* OutInfo)
{
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER StartingOffset;
    DISK_GEOMETRY DiskGeometry;
    PVOID Info;
    PIRP Irp;
    KEVENT Event;
    NTSTATUS Status;

    DPRINT("PmReadGptAttributesOnMbr: %p\n", Extension);

    *OutInfo = NULL;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_DRIVE_GEOMETRY,
                                        Extension->AttachedToDevice,
                                        NULL,
                                        0,
                                        &DiskGeometry,
                                        sizeof(DiskGeometry),
                                        FALSE,
                                        &Event,
                                        &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("PmReadGptAttributesOnMbr: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = IoCallDriver(Extension->AttachedToDevice, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PmReadGptAttributesOnMbr: %X\n", Status);
        return Status;
    }

    Info = ExAllocatePoolWithTag(NonPagedPool, DiskGeometry.BytesPerSector, 'iRcS');
    if (!Info)
    {
        DPRINT1("PmReadGptAttributesOnMbr: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (DiskGeometry.BytesPerSector > 0x400)
        StartingOffset.QuadPart = DiskGeometry.BytesPerSector;
    else
        StartingOffset.QuadPart = 0x400;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ,
                                       Extension->AttachedToDevice,
                                       Info,
                                       DiskGeometry.BytesPerSector,
                                       &StartingOffset,
                                       &Event,
                                       &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("PmReadGptAttributesOnMbr: STATUS_INSUFFICIENT_RESOURCES\n");
        ExFreePoolWithTag(Info, 'iRcS');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = IoCallDriver(Extension->AttachedToDevice, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PmReadGptAttributesOnMbr: %X\n", Status);
        ExFreePoolWithTag(Info, 'iRcS');
        return Status;
    }

    if (!IsEqualGUID((PGUID)((ULONG_PTR)Info + 0), &PARTITION_BASIC_DATA_GUID))
    {
        DPRINT1("PmReadGptAttributesOnMbr: STATUS_NOT_FOUND\n");
        ExFreePoolWithTag(Info, 'iRcS');
        return STATUS_NOT_FOUND;
    }

    DPRINT1("PmAddSignatures: FIXME\n");
    ASSERT(FALSE);

    *OutInfo = Info;

    return Status;
}

VOID
NTAPI
PmAddSignatures(
    _In_ PPM_DEVICE_EXTENSION Extension,
    _In_ PDRIVE_LAYOUT_INFORMATION_EX DriveLayout)
{
    PPM_DRIVER_EXTENSION DriverExtension;
    TABLE_SEARCH_RESULT ResultSignatures;
    PSTORAGE_DEVICE_DESCRIPTOR DeviceId;
    PPM_SIGNATURE RetSignature;
    PM_SIGNATURE Signature;
    PVOID SignatureNode;
    PLIST_ENTRY Entry;
    NTSTATUS Status;

    DPRINT("PmAddSignatures: Extension %p, DriveLayout %p\n", Extension, DriveLayout);

    DriverExtension = Extension->DriverExtension;

    while (!IsListEmpty(&Extension->ListOfSignatures))
    {
        Entry = RemoveHeadList(&Extension->ListOfSignatures);
        RetSignature = CONTAINING_RECORD(Entry, PM_SIGNATURE, Link);
        RtlDeleteElementGenericTableAvl(&DriverExtension->TableSignature, RetSignature);
    }

    while (!IsListEmpty(&Extension->ListOfGuids))
    {
        DPRINT1("PmAddSignatures: FIXME\n");
        ASSERT(FALSE);
    }

    if (!DriveLayout)
        return;

    if (Extension->Reserved00)
        return;

    if (DriveLayout->PartitionStyle == 0) // PARTITION_STYLE_MBR
    {
        if (!DriveLayout->PartitionCount && !DriveLayout->Mbr.Signature)
            return;

        if (DriveLayout->PartitionCount &&
            DriveLayout->PartitionEntry[0].PartitionLength.QuadPart > 0 &&
            DriveLayout->PartitionEntry[0].StartingOffset.QuadPart == 0)
        {
            return;
        }

        if (!Extension->IsDeviceIdRequested)
        {
            DeviceId = NULL;

            Status = PmQueryDeviceId(Extension, &DeviceId);
            if (NT_SUCCESS(Status))
            {
                PVOID Info = NULL;

                Status = PmReadGptAttributesOnMbr(Extension, &Info);
                if (NT_SUCCESS(Status))
                {
                    DPRINT1("PmAddSignatures: FIXME\n");
                    ASSERT(FALSE);
                }

                if (Info)
                    ExFreePoolWithTag(Info, 'iRcS');
            }

            if (DeviceId)
                ExFreePoolWithTag(DeviceId, 'iRcS');

            Extension->IsDeviceIdRequested = TRUE;
        }

        Signature.Value = DriveLayout->Mbr.Signature;

        RetSignature = RtlLookupElementGenericTableFullAvl(&DriverExtension->TableSignature,
                                                           &Signature,
                                                           &SignatureNode,
                                                           &ResultSignatures);
        if (!RetSignature && Signature.Value)
        {
            goto FinishMbrStyle;
        }

        DPRINT1("PmAddSignatures: FIXME\n");
        ASSERT(FALSE);

FinishMbrStyle:

        RetSignature = RtlInsertElementGenericTableFullAvl(&DriverExtension->TableSignature,
                                                           &Signature,
                                                           sizeof(PM_SIGNATURE),
                                                           0,
                                                           SignatureNode,
                                                           ResultSignatures);
        if (RetSignature)
        {
            InsertTailList(&Extension->ListOfSignatures, &RetSignature->Link);
            RetSignature->DeviceExtension = Extension;
        }

        return;
    }

    if (DriveLayout->PartitionStyle != PARTITION_STYLE_GPT)
    {
        DPRINT1("PmAddSignatures: ? PARTITION_STYLE ? (%p, %p, %X)\n", Extension, DriveLayout, DriveLayout->PartitionStyle);
        ASSERT("Layout->PartitionStyle == PARTITION_STYLE_GPT");
        return;
    }

    DPRINT1("PmAddSignatures: PARTITION_STYLE_GPT. FIXME\n");
    ASSERT(FALSE);

}

NTSTATUS
NTAPI
PmCheckAndUpdateSignature(
    _In_ PPM_DEVICE_EXTENSION Extension,
    _In_ BOOLEAN Param2,
    _In_ BOOLEAN Param3)
{
    PDRIVE_LAYOUT_INFORMATION_EX DriveLayout;
    BOOLEAN IsFailed;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("PmCheckAndUpdateSignature: Extension %p, Param2 %X, Param3 %X\n", Extension, Param2, Param3);

    if (!Param3 && !Extension->IsPartitionNotFound)
        return Status;

    Status = PmReadPartitionTableEx(Extension->AttachedToDevice, &DriveLayout);

    if (!Param3 && !Extension->IsPartitionNotFound)
    {
        if (NT_SUCCESS(Status))
            ExFreePool(DriveLayout);

        return STATUS_SUCCESS;
    }

    if (!NT_SUCCESS(Status) && Extension->IsPartitionNotFound)
    {
        return Status;
    }

    if (!LockDriverWithTimeout(Extension->DriverExtension))
    {
        if (NT_SUCCESS(Status))
            ExFreePool(DriveLayout);

        return Status;
    }

    IsFailed = (NT_SUCCESS(Status) == FALSE);

    if (NT_SUCCESS(Status))
    {
        if (!Extension->Reserved00)
        {
            DPRINT("PmCheckAndUpdateSignature: FIXME PmSigCheckUpdateEpoch()\n");

            PmAddSignatures(Extension, DriveLayout);
            ExFreePool(DriveLayout);
        }

        //IsFailed = (NT_SUCCESS(Status) == FALSE);
    }

    Extension->IsPartitionNotFound = IsFailed;

    KeReleaseMutex(&Extension->DriverExtension->Mutex, FALSE);

    DPRINT("PmCheckAndUpdateSignature: FIXME PmSigCheckCompleteNotificationIrps()\n");

    return Status;
}

NTSTATUS
NTAPI
PmRegisterDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG PartitionData)
{
    PPM_DEVICE_EXTENSION Extension;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();
    DPRINT("PmRegisterDevice: DeviceObject %p, PartitionData %X\n", DeviceObject, PartitionData);

    Extension = DeviceObject->DeviceExtension;

    if (Extension->NameString.Length)
    {
        Status = IoWMIRegistrationControl(DeviceObject, (PartitionData | 1));
        if (NT_SUCCESS(Status))
        {
            DPRINT("PmRegisterDevice: FIXME PmWmiCounter...\n");
        }
    }

    return Status;
}

NTSTATUS
NTAPI
PmStartPartition(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PIO_STACK_LOCATION IoStack;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    DPRINT("PmStartPartition: %p\n", DeviceObject);

    Irp = IoAllocateIrp(DeviceObject->StackSize, 0);
    if (!Irp)
    {
        DPRINT1("PmStartPartition: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    IoStack = IoGetNextIrpStackLocation(Irp);
    IoStack->MajorFunction = IRP_MJ_PNP;
    IoStack->MinorFunction = IRP_MN_START_DEVICE;

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoSetCompletionRoutine(Irp, PmSignalCompletion, &Event, TRUE, TRUE, TRUE);

    IoCallDriver(DeviceObject, Irp);

    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

    Status = Irp->IoStatus.Status;
    IoFreeIrp(Irp);

    return Status;
}

NTSTATUS
NTAPI
PmGivePartition(
    _In_ PPM_NOTIFICATION_DATA NotifyData,
    _In_ PDEVICE_OBJECT PartitionPdo,
    _In_ PDEVICE_OBJECT WholeDiskPdo)
{
    IO_STATUS_BLOCK IoStatusBlock;
    PDEVICE_OBJECT InputBuffer[2];
    PFILE_OBJECT FileObject;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    DPRINT("PmGivePartition: %p, %X, %X\n", NotifyData, PartitionPdo, WholeDiskPdo);

    if (!NotifyData->Counter)
    {
        Status = IoGetDeviceObjectPointer(&NotifyData->ObjectName,
                                          FILE_READ_DATA,
                                          &NotifyData->FileObject,
                                          &NotifyData->DeviceObject);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PmGivePartition: Status %X\n", Status);
            return Status;
        }
    }

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    InputBuffer[0] = PartitionPdo;
    InputBuffer[1] = WholeDiskPdo;

    Irp = IoBuildDeviceIoControlRequest(0x760000,
                                        NotifyData->DeviceObject,
                                        InputBuffer,
                                        sizeof(InputBuffer),
                                        NULL,
                                        0,
                                        TRUE,
                                        &Event,
                                        &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("PmGivePartition: Build Irp failed\n");

        if (!NotifyData->Counter)
        {
            FileObject = NotifyData->FileObject;
            NotifyData->DeviceObject = NULL;
            ObDereferenceObject(FileObject);
            NotifyData->FileObject = NULL;
        }

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = IoCallDriver(NotifyData->DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }

    if (NT_SUCCESS(Status))
    {
        NotifyData->Counter++;
        return Status;
    }

    DPRINT1("PmGivePartition: Status %X\n", Status);

    if (!NotifyData->Counter)
    {
        FileObject = NotifyData->FileObject;
        NotifyData->DeviceObject = NULL;
        ObDereferenceObject(FileObject);
        NotifyData->FileObject = NULL;
    }

    return Status;
}

VOID
NTAPI
PmTakePartition(
    _In_ PPM_NOTIFICATION_DATA NotifyData,
    _In_ PDEVICE_OBJECT PartitionPdo,
    _In_ PDEVICE_OBJECT WholeDiskPdo)
{
    PDEVICE_OBJECT InputBuffer[2];
    IO_STATUS_BLOCK IoStatusBlock;
    KEVENT Event;
    PIRP Irp;

    DPRINT("PmTakePartition: %p, %p, %p\n", NotifyData, PartitionPdo, WholeDiskPdo);

    if (!NotifyData)
    {
        DPRINT("PmTakePartition: NotifyData is NULL\n");
        return;
    }

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    InputBuffer[0] = PartitionPdo;
    InputBuffer[1] = WholeDiskPdo;

    Irp = IoBuildDeviceIoControlRequest(0x760004,
                                        NotifyData->DeviceObject,
                                        InputBuffer,
                                        sizeof(InputBuffer),
                                        NULL,
                                        0,
                                        TRUE,
                                        &Event,
                                        &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("PmTakePartition: Irp is NULL!\n");
        return;
    }

    if (IoCallDriver(NotifyData->DeviceObject, Irp) == STATUS_PENDING)
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

    NotifyData->Counter--;
    if (NotifyData->Counter)
        return;

    NotifyData->DeviceObject = NULL;

    ObDereferenceObject(NotifyData->FileObject);
    NotifyData->FileObject = NULL;
}

NTSTATUS
NTAPI
PmRemovePartition(
    _In_ PPM_PARTITION_DATA PartitionData)
{
    PIO_STACK_LOCATION IoStack;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PmRemovePartition: %p\n", PartitionData);

    Irp = IoAllocateIrp(PartitionData->PartitionPdo->StackSize, 0);
    if (!Irp)
    {
        DPRINT1("PmRemovePartition: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    IoStack = IoGetNextIrpStackLocation(Irp);
    IoStack->MajorFunction = IRP_MJ_PNP;
    IoStack->MinorFunction = IRP_MN_REMOVE_DEVICE;

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoSetCompletionRoutine(Irp, PmSignalCompletion, &Event, TRUE, TRUE, TRUE);

    IoCallDriver(PartitionData->PartitionPdo, Irp);
    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

    Status = Irp->IoStatus.Status;
    IoFreeIrp(Irp);

    return Status;
}

NTSTATUS
NTAPI
PmQueryDeviceRelations(
    _In_ PPM_DEVICE_EXTENSION Extension,
    _In_ PIRP Irp)
{
    PPM_PARTITION_DATA PartitionData;
    PPM_NOTIFICATION_DATA NotifyData;
    PDEVICE_RELATIONS DeviceRelation;
    PLIST_ENTRY PrevEntry;
    PLIST_ENTRY Entry;
    KEVENT Event;
    ULONG ix;
    NTSTATUS Status;

    DPRINT("PmQueryDeviceRelations: Extension %p, Irp %p\n", Extension, Irp);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, PmSignalCompletion, &Event, TRUE, TRUE, TRUE);

    IoCallDriver(Extension->AttachedToDevice, Irp);
    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

    Status = Irp->IoStatus.Status;
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PmQueryDeviceRelations: Status %X\n", Status);
        return Status;
    }

    DeviceRelation = (PDEVICE_RELATIONS)Irp->IoStatus.Information;

    PmCheckAndUpdateSignature(Extension, TRUE, TRUE);

    KeWaitForSingleObject(&Extension->DriverExtension->Mutex, Executive, KernelMode, FALSE, NULL);

    for (Entry = Extension->PartitionList.Flink;
         Entry != &Extension->PartitionList;
         Entry = Entry->Flink)
    {
        PartitionData = CONTAINING_RECORD(Entry, PM_PARTITION_DATA, Link);

        for (ix = 0; ix < DeviceRelation->Count; ix++)
        {
            if (PartitionData->PartitionPdo == DeviceRelation->Objects[ix])
                break;
        }

        if (ix < DeviceRelation->Count)
            continue;

        PmTakePartition(PartitionData->NotifyData, PartitionData->PartitionPdo, PartitionData->WholeDiskPdo);
        PmRemovePartition(PartitionData);

        PrevEntry = Entry->Blink;
        RemoveEntryList(Entry);
        Entry = PrevEntry;

        ObDereferenceObject(PartitionData->PartitionPdo);
        ExFreePool(PartitionData);
    }

    DPRINT("PmQueryDeviceRelations: DeviceRelation->Count %X\n", DeviceRelation->Count);

    for (ix = 0; ix < DeviceRelation->Count; ix++)
    {
        for (Entry = Extension->PartitionList.Flink;
             Entry != &Extension->PartitionList;
             Entry = Entry->Flink)
        {
            PartitionData = CONTAINING_RECORD(Entry, PM_PARTITION_DATA, Link);

            if (DeviceRelation->Objects[ix] == PartitionData->PartitionPdo)
                break;
        }

        if (Entry != &Extension->PartitionList)
        {
            ObDereferenceObject(DeviceRelation->Objects[ix]);
            PmStartPartition(DeviceRelation->Objects[ix]);
            continue;
        }

        if (Extension->DriverExtension->IsReinitialized)
            DeviceRelation->Objects[ix]->Flags |= DO_DEVICE_INITIALIZING;

        Status = PmStartPartition(DeviceRelation->Objects[ix]);
        if (!NT_SUCCESS(Status))
        {
            continue;
        }

        PartitionData = ExAllocatePoolWithTag(NonPagedPool, sizeof(*PartitionData), 'pRcS');
        if (!PartitionData)
        {
            continue;
        }

        PartitionData->PartitionPdo = DeviceRelation->Objects[ix];
        PartitionData->WholeDiskPdo = Extension->WholeDiskPdo;
        PartitionData->NotifyData = NULL;

        InsertHeadList(&Extension->PartitionList, &PartitionData->Link);

        if (Extension->Reserved02)
            continue;

        for (Entry = Extension->DriverExtension->NotifyList.Flink;
             Entry != &Extension->DriverExtension->NotifyList;
             Entry = Entry->Flink)
        {
            NotifyData = CONTAINING_RECORD(Entry, PM_NOTIFICATION_DATA, Link);

            Status = PmGivePartition(NotifyData, PartitionData->PartitionPdo, PartitionData->WholeDiskPdo);
            if (NT_SUCCESS(Status))
            {
                PartitionData->NotifyData = NotifyData;
                break;
            }
        }
    }

    KeReleaseMutex(&Extension->DriverExtension->Mutex, FALSE);

    DeviceRelation->Count = 0;
    return Irp->IoStatus.Status;
}

NTSTATUS
NTAPI
PmQueryDiskSignature(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDRIVE_LAYOUT_INFORMATION_EX DriveLayout;
    PPM_DEVICE_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    PULONG OutDiskSignature;
    NTSTATUS Status;

    DPRINT("PmQueryDiskSignature: %p, %p\n", DeviceObject, Irp);

    Extension = DeviceObject->DeviceExtension;
    IoStack = Irp->Tail.Overlay.CurrentStackLocation;
    OutDiskSignature = Irp->AssociatedIrp.SystemBuffer;

    if (IoStack->Parameters.DeviceIoControl.OutputBufferLength < 4)
    {
        DPRINT1("PmQueryDiskSignature: OutputBufferLength %X\n", IoStack->Parameters.DeviceIoControl.OutputBufferLength);
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }

    Irp->IoStatus.Information = 4;

    if (Extension->MbrSignature)
    {
        *OutDiskSignature = Extension->MbrSignature;
        DPRINT("PmQueryDiskSignature: *OutDiskSignature - %X\n", *OutDiskSignature);
        return STATUS_SUCCESS;
    }

    Status = PmReadPartitionTableEx(Extension->AttachedToDevice, &DriveLayout);
    if (!NT_SUCCESS(Status))
    {
        Irp->IoStatus.Information = 0;
        return Status;
    }

    if (DriveLayout->PartitionStyle != 0) // not Mbr
    {
        DPRINT1("PmQueryDiskSignature: PartitionStyle %X\n", DriveLayout->PartitionStyle);
        ExFreePool(DriveLayout);
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    *OutDiskSignature = DriveLayout->Mbr.Signature;
    DPRINT("PmQueryDiskSignature: DiskSignature %X\n", *OutDiskSignature);

    ExFreePool(DriveLayout);

    if (IoStack->Parameters.DeviceIoControl.OutputBufferLength < 0xA)
    {
        DPRINT("PmQueryDiskSignature: OutputBufferLength %X\n", IoStack->Parameters.DeviceIoControl.OutputBufferLength);
        return Status;
    }

    DPRINT1("PmQueryDiskSignature: FIXME\n");
    ASSERT(FALSE);

    return Status;
}

/* AVL TABLE ROUTINES *******************************************************/

RTL_GENERIC_COMPARE_RESULTS
NTAPI
PmTableSignatureCompareRoutine(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID FirstStruct,
    _In_ PVOID SecondStruct)
{
    PPM_SIGNATURE First = FirstStruct;
    PPM_SIGNATURE Second = SecondStruct;
    ULONG FirstSignature;
    ULONG SecondSignature;
    RTL_GENERIC_COMPARE_RESULTS Result;

    FirstSignature = First->Value;
    SecondSignature = Second->Value;

    DPRINT("PmTableSignatureCompareRoutine: %X, %X\n", FirstSignature, SecondSignature);

    if (FirstSignature < SecondSignature)
    {
        Result = GenericLessThan;
    }
    else if (FirstSignature > SecondSignature)
    {
        Result = GenericGreaterThan;
    }
    else
    {
        Result = GenericEqual;
    }

    return Result;
}

RTL_GENERIC_COMPARE_RESULTS
NTAPI
PmTableGuidCompareRoutine(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID FirstStruct,
    _In_ PVOID SecondStruct)
{
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

PVOID
NTAPI
PmTableAllocateRoutine(
    _In_ PRTL_AVL_TABLE Table,
    _In_ CLONG ByteSize)
{
    return ExAllocatePoolWithTag(PagedPool, ByteSize, 'tRcS');
}

VOID
NTAPI
PmTableFreeRoutine(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer)
{
    ExFreePoolWithTag(Buffer, 'tRcS');
}

/* DRIVER DISPATCH ROUTINES *************************************************/

NTSTATUS
NTAPI
PmReadWrite(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PPM_DEVICE_EXTENSION Extension;

    //DPRINT("PmReadWrite: %p, %p\n", DeviceObject, Irp);

    Extension = DeviceObject->DeviceExtension;

    if (!Extension->Reserved01)
    {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(Extension->AttachedToDevice, Irp);
    }

    DPRINT1("PmReadWrite: FIXME\n");
    ASSERT(FALSE);

    return STATUS_PENDING;
}

NTSTATUS
NTAPI
PmDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PPM_DEVICE_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    KEVENT Event;
    BOOLEAN Param2;
    NTSTATUS Status;

    Extension = DeviceObject->DeviceExtension;
    IoStack = Irp->Tail.Overlay.CurrentStackLocation;

    if (Extension->AttachedToDevice->Characteristics & FILE_REMOVABLE_MEDIA)
    {
        DPRINT("PmDeviceControl: DeviceObject %p, Irp %p, Code %X\n", DeviceObject, Irp, IoStack->Parameters.DeviceIoControl.IoControlCode);
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(Extension->AttachedToDevice, Irp);
    }

    switch (IoStack->Parameters.DeviceIoControl.IoControlCode)
    {
        case IOCTL_DISK_GET_DRIVE_GEOMETRY:
        {
            DPRINT("PmDeviceControl: DeviceObject %p, Irp %p, Code %X\n", DeviceObject, Irp, IoStack->Parameters.DeviceIoControl.IoControlCode);
            if (!Extension->Reserved02 || Extension->DriverExtension->IsReinitialized)
            {
                IoSkipCurrentIrpStackLocation(Irp);
                return IoCallDriver(Extension->AttachedToDevice, Irp);
            }
            Status = STATUS_NO_SUCH_DEVICE;
            break;
        }
        case IOCTL_DISK_PERFORMANCE:
            DPRINT1("PmDeviceControl: FIXME\n");
            ASSERT(FALSE);Status=STATUS_NOT_IMPLEMENTED;
            break;

        case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
        case IOCTL_DISK_GET_DRIVE_LAYOUT:
        case 0x704008:
        {
            DPRINT("PmDeviceControl: DeviceObject %p, Irp %p, Code %X\n", DeviceObject, Irp, IoStack->Parameters.DeviceIoControl.IoControlCode);

            Status = PmCheckAndUpdateSignature(Extension, TRUE, FALSE);

            if (!NT_SUCCESS(Status) || IoStack->Parameters.DeviceIoControl.IoControlCode != 0x704008)
            {
                IoSkipCurrentIrpStackLocation(Irp);
                return IoCallDriver(Extension->AttachedToDevice, Irp);
            }

            Status = PmQueryDiskSignature(DeviceObject, Irp);
            break;
        }
        case IOCTL_DISK_PERFORMANCE_OFF:
            DPRINT1("PmDeviceControl: FIXME\n");
            ASSERT(FALSE);Status=STATUS_NOT_IMPLEMENTED;
            break;

        case IOCTL_DISK_UPDATE_PROPERTIES:
        case IOCTL_DISK_SET_DRIVE_LAYOUT:
        case IOCTL_DISK_CREATE_DISK:
        case IOCTL_DISK_DELETE_DRIVE_LAYOUT:
        case IOCTL_DISK_SET_DRIVE_LAYOUT_EX:
        {
            DPRINT("PmDeviceControl: DeviceObject %p, Irp %p, Code %X\n", DeviceObject, Irp, IoStack->Parameters.DeviceIoControl.IoControlCode);

            KeWaitForSingleObject(&Extension->DriverExtension->Mutex, Executive, KernelMode, FALSE, NULL);

            if (!Extension->IsPartitionNotFound ||
                IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_DISK_UPDATE_PROPERTIES)
            {
                Param2 = TRUE;
            }
            else
            {
                Param2 = FALSE;
            }

            Extension->IsPartitionNotFound = TRUE;

            KeReleaseMutex(&Extension->DriverExtension->Mutex, FALSE);
            KeInitializeEvent(&Event, NotificationEvent, FALSE);

            IoCopyCurrentIrpStackLocationToNext(Irp);
            IoSetCompletionRoutine(Irp, PmSignalCompletion, &Event, TRUE, TRUE, TRUE);

            IoCallDriver(Extension->AttachedToDevice, Irp);
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

            Status = Irp->IoStatus.Status;
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("PmDeviceControl: Status %X\n", Status);
                break;
            }

            Status = PmCheckAndUpdateSignature(Extension, Param2, TRUE);
            break;
        }
        case IOCTL_DISK_GROW_PARTITION:
            DPRINT1("PmDeviceControl: FIXME\n");
            ASSERT(FALSE);Status=STATUS_NOT_IMPLEMENTED;
            break;

        case 0x70400C:
            DPRINT1("PmDeviceControl: FIXME\n");
            ASSERT(FALSE);Status=STATUS_NOT_IMPLEMENTED;
            break;

        case 0x70C000:
            DPRINT1("PmDeviceControl: FIXME\n");
            ASSERT(FALSE);Status=STATUS_NOT_IMPLEMENTED;
            break;

        case 0x70C004:
            DPRINT1("PmDeviceControl: FIXME\n");
            ASSERT(FALSE);Status=STATUS_NOT_IMPLEMENTED;
            break;

        default:
            DPRINT("PmDeviceControl: DeviceObject %p, Irp %p, Code %X\n", DeviceObject, Irp, IoStack->Parameters.DeviceIoControl.IoControlCode);
            IoSkipCurrentIrpStackLocation(Irp);
            return IoCallDriver(Extension->AttachedToDevice, Irp);
    }

    DPRINT("PmDeviceControl: Code %X, Status %X\n", IoStack->Parameters.DeviceIoControl.IoControlCode, Status);

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
PmPowerCompletion(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    DPRINT1("PmPowerCompletion: %p, %p, %p\n", DeviceObject, Irp, Context);
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PmPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PPM_DEVICE_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    DPRINT1("PmPower: %p, %p\n", DeviceObject, Irp);

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Extension = DeviceObject->DeviceExtension;

    Status = IoAcquireRemoveLock(&Extension->RemoveLock, NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PmPower: Status %X\n", Status);

        PoStartNextPowerIrp(Irp);

        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return Status;
    }

    if (IoStack->MinorFunction == 2 && IoStack->Parameters.Power.Type == 1)
    {
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, PmPowerCompletion, NULL, TRUE, TRUE, TRUE);
        IoMarkIrpPending(Irp);

        PoCallDriver(Extension->AttachedToDevice, Irp);

        return STATUS_PENDING;
    }

    PoStartNextPowerIrp(Irp);
    IoSkipCurrentIrpStackLocation(Irp);

    Status = PoCallDriver(Extension->AttachedToDevice, Irp);

    IoReleaseRemoveLock(&Extension->RemoveLock, NULL);

    return Status;
}

NTSTATUS
NTAPI
PmWmi(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PmPnp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PPM_DEVICE_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    ULONG PartitionData;
    KEVENT Event;
    BOOLEAN IsRemoveInPath = FALSE;
    NTSTATUS Status = STATUS_NOT_SUPPORTED;

    DPRINT("PmPnp: DeviceObject %p, Irp %p\n", DeviceObject, Irp);

    Extension = DeviceObject->DeviceExtension;
    IoStack = Irp->Tail.Overlay.CurrentStackLocation;

    IoStack = IoGetCurrentIrpStackLocation(Irp);

  #if DBG
    switch (IoStack->MinorFunction)
    {
        case IRP_MN_START_DEVICE:
            DPRINT("IRP_MN_START_DEVICE\n");
            break;

        case IRP_MN_QUERY_REMOVE_DEVICE:
            DPRINT("IRP_MN_QUERY_REMOVE_DEVICE\n");
            break;

        case IRP_MN_REMOVE_DEVICE:
            DPRINT("USBPORT_FdoPnP: IRP_MN_REMOVE_DEVICE\n");
            break;

        case IRP_MN_CANCEL_REMOVE_DEVICE:
            DPRINT("IRP_MN_CANCEL_REMOVE_DEVICE\n");
            break;

        case IRP_MN_STOP_DEVICE:
            DPRINT("IRP_MN_STOP_DEVICE\n");
            break;

        case IRP_MN_QUERY_STOP_DEVICE:
            DPRINT("IRP_MN_QUERY_STOP_DEVICE\n");
            break;

        case IRP_MN_CANCEL_STOP_DEVICE:
            DPRINT("IRP_MN_CANCEL_STOP_DEVICE\n");
            break;

        case IRP_MN_QUERY_DEVICE_RELATIONS:
            DPRINT("IRP_MN_QUERY_DEVICE_RELATIONS\n");
            break;

        case IRP_MN_QUERY_INTERFACE:
            DPRINT("IRP_MN_QUERY_INTERFACE\n");
            break;

        case IRP_MN_QUERY_CAPABILITIES:
            DPRINT("IRP_MN_QUERY_CAPABILITIES\n");
            break;

        case IRP_MN_QUERY_RESOURCES:
            DPRINT("IRP_MN_QUERY_RESOURCES\n");
            break;

        case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
            DPRINT("IRP_MN_QUERY_RESOURCE_REQUIREMENTS\n");
            break;

        case IRP_MN_QUERY_DEVICE_TEXT:
            DPRINT("IRP_MN_QUERY_DEVICE_TEXT\n");
            break;

        case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
            DPRINT("IRP_MN_FILTER_RESOURCE_REQUIREMENTS\n");
            break;

        case IRP_MN_READ_CONFIG:
            DPRINT("IRP_MN_READ_CONFIG\n");
            break;

        case IRP_MN_WRITE_CONFIG:
            DPRINT("IRP_MN_WRITE_CONFIG\n");
            break;

        case IRP_MN_EJECT:
            DPRINT("IRP_MN_EJECT\n");
            break;

        case IRP_MN_SET_LOCK:
            DPRINT("IRP_MN_SET_LOCK\n");
            break;

        case IRP_MN_QUERY_ID:
            DPRINT("IRP_MN_QUERY_ID\n");
            break;

        case IRP_MN_QUERY_PNP_DEVICE_STATE:
            DPRINT("IRP_MN_QUERY_PNP_DEVICE_STATE\n");
            break;

        case IRP_MN_QUERY_BUS_INFORMATION:
            DPRINT("IRP_MN_QUERY_BUS_INFORMATION\n");
            break;

        case IRP_MN_DEVICE_USAGE_NOTIFICATION:
            DPRINT("IRP_MN_DEVICE_USAGE_NOTIFICATION\n");
            break;

        case IRP_MN_SURPRISE_REMOVAL:
            DPRINT1("IRP_MN_SURPRISE_REMOVAL\n");
            break;

        case IRP_MN_QUERY_LEGACY_BUS_INFORMATION:
            DPRINT("IRP_MN_QUERY_LEGACY_BUS_INFORMATION\n");
            break;

        default:
            DPRINT1("FtpPnpFdo: Unknown PNP IRP_MN_ (%X)\n", IoStack->MinorFunction);
            break;
    }
  #endif

    if (IoStack->MinorFunction == IRP_MN_DEVICE_USAGE_NOTIFICATION &&
        IoStack->Parameters.UsageNotification.Type == DeviceUsageTypePaging)
    {
        KeWaitForSingleObject(&Extension->Event, Executive, KernelMode, FALSE, NULL);

        if (!IoStack->Parameters.UsageNotification.InPath && !Extension->PagingPathCount)
        {
            if (!(DeviceObject->Flags & DO_POWER_INRUSH))
            {
                DeviceObject->Flags |= DO_POWER_PAGABLE;
                IsRemoveInPath = TRUE;
            }
        }

        KeInitializeEvent(&Event, NotificationEvent, FALSE);

        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, PmSignalCompletion, &Event, TRUE, TRUE, TRUE);

        Status = IoCallDriver(Extension->AttachedToDevice, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = Irp->IoStatus.Status;
        }

        if (!NT_SUCCESS(Status))
        {
            if (IsRemoveInPath)
            {
                DeviceObject->Flags &= ~DO_POWER_PAGABLE;
            }
        }
        else
        {
            if (IoStack->Parameters.UsageNotification.InPath)
            {
                InterlockedIncrement(&Extension->PagingPathCount);

                if (Extension->PagingPathCount == 1)
                    DeviceObject->Flags &= ~DO_POWER_PAGABLE;
            }
            else
            {
                InterlockedDecrement(&Extension->PagingPathCount);
            }
        }

        KeSetEvent(&Extension->Event, 0, FALSE);
        IoCompleteRequest(Irp, 0);
        return Status;
    }

    if (Extension->AttachedToDevice->Characteristics & FILE_REMOVABLE_MEDIA)
    {
        if (IoStack->MinorFunction == IRP_MN_REMOVE_DEVICE)
        {
            DPRINT1("PmPnp: FIXME\n");
            ASSERT(FALSE);
        }

        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(Extension->AttachedToDevice, Irp);
    }

    switch (IoStack->MinorFunction)
    {
        case IRP_MN_START_DEVICE:
        {
            KeInitializeEvent(&Event, NotificationEvent, FALSE);

            IoCopyCurrentIrpStackLocationToNext(Irp);
            IoSetCompletionRoutine(Irp, PmSignalCompletion, &Event, TRUE, TRUE, TRUE);

            IoCallDriver(Extension->AttachedToDevice, Irp);

            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

            Status = Irp->IoStatus.Status;
            if (NT_SUCCESS(Status) && !(Extension->AttachedToDevice->Characteristics & FILE_REMOVABLE_MEDIA))
            {
                PmDetermineDeviceNameAndNumber(DeviceObject, &PartitionData);

                KeWaitForSingleObject(&Extension->DriverExtension->Mutex, Executive, KernelMode, FALSE, NULL);
                Extension->IsDeviceRunning = TRUE;
                KeReleaseMutex(&Extension->DriverExtension->Mutex, FALSE);

                PmCheckAndUpdateSignature(Extension, TRUE, TRUE);
                PmRegisterDevice(DeviceObject, PartitionData);
            }

            break;
        }
        case IRP_MN_QUERY_REMOVE_DEVICE:
        case IRP_MN_CANCEL_REMOVE_DEVICE:
        case IRP_MN_STOP_DEVICE:
        case IRP_MN_QUERY_STOP_DEVICE:
        case IRP_MN_CANCEL_STOP_DEVICE:
        {
            DPRINT1("PmPnp: FIXME\n");
            ASSERT(FALSE);
            break;
        }
        case IRP_MN_REMOVE_DEVICE:
        case IRP_MN_SURPRISE_REMOVAL:
        {
            DPRINT1("PmPnp: FIXME\n");
            ASSERT(FALSE);

            IoSkipCurrentIrpStackLocation(Irp);
            return IoCallDriver(Extension->AttachedToDevice, Irp);
        }
        case IRP_MN_QUERY_DEVICE_RELATIONS:
        {
            if (IoStack->Parameters.QueryDeviceRelations.Type == BusRelations)
            {
                Status = PmQueryDeviceRelations(Extension, Irp);
            }
            else if (IoStack->Parameters.QueryDeviceRelations.Type == RemovalRelations)
            {
                DPRINT1("PmPnp: FIXME\n");
                ASSERT(FALSE);
            }
            else
            {
                IoSkipCurrentIrpStackLocation(Irp);
                return IoCallDriver(Extension->AttachedToDevice, Irp);
            }

            break;
        }
        default:
        {
            DPRINT("FtpPnpFdo: Unknown PNP IRP_MN_ (%X)\n", IoStack->MinorFunction);
            IoSkipCurrentIrpStackLocation(Irp);
            return IoCallDriver(Extension->AttachedToDevice, Irp);
        }
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    DPRINT("PmPnp: Status (%X)\n", Status);
    return Status;
}

/* REINITIALIZE DRIVER ROUTINES *********************************************/

VOID
NTAPI
PmDriverReinit(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PVOID Context,
    _In_ ULONG Count)
{
    PPM_DRIVER_EXTENSION DriverExtension = Context;
    PDRIVE_LAYOUT_INFORMATION_EX DriveLayout;
    PPM_PARTITION_DATA PartitionData;
    PPM_DEVICE_EXTENSION Extension;
    PLIST_ENTRY PartitionEntry;
    PLIST_ENTRY Entry;
    NTSTATUS Status;

    DPRINT1("PmDriverReinit: %p, %p, %X\n", DriverObject, Context, Count);

    KeWaitForSingleObject(&DriverExtension->Mutex, Executive, KernelMode, FALSE, NULL);

    InterlockedExchange(&DriverExtension->IsReinitialized, 1);

    Entry = DriverExtension->ExtensionList.Flink;
    while (Entry != &DriverExtension->ExtensionList)
    {
        Extension = CONTAINING_RECORD(Entry, PM_DEVICE_EXTENSION, Link);

        if (Extension->AttachedToDevice->Characteristics & FILE_REMOVABLE_MEDIA)
        {
            goto Next;
        }

        if (!Extension->IsDeviceRunning)
        {
            goto Next;
        }

        for (PartitionEntry = Extension->PartitionList.Flink;
             PartitionEntry != &Extension->PartitionList;
             PartitionEntry = PartitionEntry->Flink)
        {
            PartitionData = CONTAINING_RECORD(PartitionEntry, PM_PARTITION_DATA, Link);
            PartitionData->PartitionPdo->Flags |= DO_DEVICE_INITIALIZING;
        }

        Status = PmReadPartitionTableEx(Extension->AttachedToDevice, &DriveLayout);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PmDriverReinit: Status %X\n", Status);
            goto Next;
        }

        if (Extension->MbrSignature)
        {
            if (!DriveLayout->PartitionStyle)
            {
                DriveLayout->Mbr.Signature = Extension->MbrSignature;

                DPRINT1("PmDriverReinit: FIXME\n");
                ASSERT(FALSE);
            }

            Extension->MbrSignature = 0;
        }

        if (DriveLayout->PartitionStyle == 1)
            PmAddSignatures(Extension, DriveLayout);

        ExFreePool(DriveLayout);
Next:
        Entry = Entry->Flink;
    }

    KeReleaseMutex(&DriverExtension->Mutex, FALSE);
}

VOID
NTAPI
PmBootDriverReinit(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PVOID Context,
    _In_ ULONG Count)
{
    DPRINT("PmBootDriverReinit: %p, %p, %X\n", DriverObject, Context, Count);
    IoRegisterDriverReinitialization(DriverObject, PmDriverReinit, Context);
}

/* INIT DRIVER ROUTINES *****************************************************/

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    PPM_DRIVER_EXTENSION DriverExtension;
    ULONG size;
    ULONG ix;
    NTSTATUS Status;

    DPRINT("DriverEntry: %p, '%wZ'\n", DriverObject, RegistryPath);

    for (ix = 0; ix <= IRP_MJ_MAXIMUM_FUNCTION; ix++)
        DriverObject->MajorFunction[ix] = PmPassThrough;

    DriverObject->MajorFunction[IRP_MJ_READ] = PmReadWrite;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = PmReadWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PmDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_POWER] = PmPower;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = PmWmi;
    DriverObject->MajorFunction[IRP_MJ_PNP] = PmPnp;

    DriverObject->DriverExtension->AddDevice = PmAddDevice;
    DriverObject->DriverUnload = PmUnload;

    Status = IoAllocateDriverObjectExtension(DriverObject, PmAddDevice, sizeof(*DriverExtension), (PVOID *)&DriverExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("DriverEntry: Status %X\n", Status);
        return Status;
    }

    size = (RegistryPath->Length + 2);

    DriverExtension->RegistryPath.MaximumLength = size;
    DriverExtension->RegistryPath.Buffer = ExAllocatePoolWithTag(PagedPool, size, 'pRcS');

    if (DriverExtension->RegistryPath.Buffer)
    {
        RtlCopyUnicodeString(&DriverExtension->RegistryPath, RegistryPath);
    }
    else
    {
        DriverExtension->RegistryPath.Length = 0;
        DriverExtension->RegistryPath.MaximumLength = 0;
    }

    DriverExtension->SelfDriverObject = DriverObject;

    InitializeListHead(&DriverExtension->NotifyList);
    InitializeListHead(&DriverExtension->ExtensionList);
    KeInitializeMutex(&DriverExtension->Mutex, 0);

    DriverExtension->IsReinitialized = 0;

    RtlInitializeGenericTableAvl(&DriverExtension->TableSignature,
                                 PmTableSignatureCompareRoutine,
                                 PmTableAllocateRoutine,
                                 PmTableFreeRoutine,
                                 DriverExtension);

    RtlInitializeGenericTableAvl(&DriverExtension->TableGuid,
                                 PmTableGuidCompareRoutine,
                                 PmTableAllocateRoutine,
                                 PmTableFreeRoutine,
                                 DriverExtension);

    IoRegisterBootDriverReinitialization(DriverObject, PmBootDriverReinit, DriverExtension);

    Status = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange,
                                            PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
                                            &VOLMGR_VOLUME_MANAGER_GUID,
                                            DriverObject,
                                            PmVolumeManagerNotification,
                                            DriverExtension,
                                            &DriverExtension->NotificationEntry);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("DriverEntry: Status %X\n", Status);
        return Status;
    }

#if 0
    DriverExtension->RegistrySignature = PmQueryRegistrySignature();

    PmQueryRegistryGuid(DriverExtension);
    PmQueryRegistrySnapshotSettings(DriverExtension);

    PmQueryRegistryEpochMode(DriverExtension);
#endif

    DPRINT("DriverEntry: exit with STATUS_SUCCESS\n");
    return STATUS_SUCCESS;
}

/* EOF */
