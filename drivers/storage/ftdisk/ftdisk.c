/*
 * PROJECT:     Volume manager driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Main file
 * COPYRIGHT:   Copyright 2018, 2019, 2023 Vadim Galyant <vgal@rambler.ru>
 */

#include "ftdisk.h"

#define NDEBUG
#include <debug.h>

#ifdef ALLOC_PRAGMA
  #pragma alloc_text(INIT, DriverEntry)
  #pragma alloc_text(INIT, FtDiskAddDevice)
#endif

#ifdef ALLOC_PRAGMA
  #pragma alloc_text(PAGE, FtDiskUnload)
  #pragma alloc_text(PAGE, FtDiskDeviceControl)
  #pragma alloc_text(PAGE, FtWmi)
  #pragma alloc_text(PAGE, FtDiskPnp)
  #pragma alloc_text(PAGE, IoRegisterBootDriverReinitialization)
  #pragma alloc_text(PAGE, IoRegisterDriverReinitialization)
  #pragma alloc_text(PAGE, FtpQueryRootId)
  #pragma alloc_text(PAGE, FtpPartitionArrived)
  #pragma alloc_text(PAGE, FtpPartitionArrivedHelper)
  #pragma alloc_text(PAGE, FtpQueryPartitionInformation)
  #pragma alloc_text(PAGE, FtpCreateNewDevice)
  #pragma alloc_text(PAGE, FtpQueryDiskSignature)
  #pragma alloc_text(PAGE, FtpQueryDiskSignatureCache)
  #pragma alloc_text(PAGE, FtpCreateOldNameLinks)
  #pragma alloc_text(PAGE, FtpQueryId)
  #pragma alloc_text(PAGE, FtpQueryDeviceName)
  #pragma alloc_text(PAGE, FtpQueryUniqueIdBuffer)
  #pragma alloc_text(PAGE, FtpQueryUniqueId)
  #pragma alloc_text(PAGE, FtpQueryStableGuid)
  #pragma alloc_text(PAGE, FtpQueryDriveLetterFromRegistry)
  #pragma alloc_text(PAGE, FtpQuerySuggestedLinkName)
  #pragma alloc_text(PAGE, FtpLinkCreated)
  #pragma alloc_text(PAGE, FtpUniqueIdChangeNotify)
  #pragma alloc_text(PAGE, FtpGetGptAttributes)
  #pragma alloc_text(PAGE, FtpCheckOfflineOwner)
  #pragma alloc_text(PAGE, FtpBootDriverReinitialization)
  #pragma alloc_text(PAGE, FtpDriverReinitialization)
  #pragma alloc_text(PAGE, FtpQuerySystemVolumeNameQueryRoutine)
#endif

#ifdef ALLOC_PRAGMA
  #pragma alloc_text(PAGELK, FtpReadPartitionTableEx)
#endif

/* GLOBALS *******************************************************************/

GUID VOLMGR_VOLUME_MANAGER_GUID = {0x53F5630E, 0xB6BF, 0x11D0, {0X94, 0XF2, 0X00, 0XA0, 0XC9, 0X1E, 0XFB, 0X8B}};
GUID PARTITION_BASIC_DATA_GUID  = {0xEBD0A0A2, 0xB9E5, 0x4433, {0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7}};

/* FUNCTIONS ****************************************************************/

NTSTATUS
NTAPI
FtpSignalCompletion(
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
FtpRefCountCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PVOLUME_EXTENSION VolumeExtension = Context;

    ExReleaseRundownProtectionCacheAware(VolumeExtension->RundownCache);
    return STATUS_SUCCESS;
}

VOID
NTAPI
FtpVolumeOnlineCallback(PVOLUME_EXTENSION VolumeExtension)
{
    PKEVENT Event = VolumeExtension->ZeroRefContext;

    if (VolumeExtension->IsVolumeOffline)
    {
        VolumeExtension->IsVolumeOffline = FALSE;
        VolumeExtension->IsUnknown00 = FALSE;
    }

    KeSetEvent(Event, 0, FALSE);
}

VOID
NTAPI
FtpAcquire(
    _In_ PROOT_EXTENSION RootExtension)
{
    KeWaitForSingleObject(&RootExtension->RootSemaphore, Executive, KernelMode, FALSE, NULL);
}

VOID
NTAPI
FtpRelease(
    _In_ PROOT_EXTENSION RootExtension)
{
    KeReleaseSemaphore(&RootExtension->RootSemaphore, 0, 1, FALSE);
}

NTSTATUS
NTAPI
FtpAllSystemsGo(
    _In_ PVOLUME_EXTENSION VolumeExtension,
    _In_ PIRP Irp,
    _In_ BOOLEAN Param3,
    _In_ BOOLEAN Param4,
    _In_ BOOLEAN Param5)
{
    KIRQL OldIrql;

    DPRINT("FtpAllSystemsGo: %p, %p, %X, %X, %X\n", VolumeExtension, Irp, Param3, Param4, Param5);

    if (Param3)
    {
        Param4 = TRUE;
        Param5 = TRUE;
    }

     KeAcquireSpinLock(&VolumeExtension->SpinLock, &OldIrql);

    if ((Param4 && !VolumeExtension->PartitionPdo && !VolumeExtension->FtVolume) ||
        !VolumeExtension->IsStartCallback)
    {
        DPRINT1("FtpAllSystemsGo: STATUS_NO_SUCH_DEVICE\n");
        KeReleaseSpinLock(&VolumeExtension->SpinLock, OldIrql);
        return STATUS_NO_SUCH_DEVICE;
    }

    if (Param5 && VolumeExtension->IsVolumeOffline)
    {
        if (!(VolumeExtension->SelfDeviceObject->Flags & DO_SYSTEM_BOOT_PARTITION))
        {
            DPRINT("FtpAllSystemsGo: STATUS_DEVICE_OFF_LINE\n");
            KeReleaseSpinLock(&VolumeExtension->SpinLock, OldIrql);

            if (Irp)
                Irp->IoStatus.Information = 0;

            return STATUS_DEVICE_OFF_LINE;
        }

        VolumeExtension->IsVolumeOffline = FALSE;
    }

    if (VolumeExtension->ZeroRefCallback || VolumeExtension->IsUnknown02)
    {
        DPRINT("FtpAllSystemsGo: STATUS_PENDING\n");
        ASSERT(Irp);

        IoMarkIrpPending(Irp);
        InsertTailList(&VolumeExtension->IrpList, &Irp->Tail.Overlay.ListEntry);

        KeReleaseSpinLock(&VolumeExtension->SpinLock, OldIrql);
        return STATUS_PENDING;
    }

    if (VolumeExtension->PartitionPdo)
    {
        if (!ExAcquireRundownProtectionCacheAware(VolumeExtension->RundownCache))
        {
            DPRINT1("FtpAllSystemsGo: FIXME\n");
            ASSERT(FALSE);
        }

        if (!VolumeExtension->IsVolumeOffline)
            InterlockedExchange(&VolumeExtension->Lock, 1);

        KeReleaseSpinLock(&VolumeExtension->SpinLock, OldIrql);
        return STATUS_SUCCESS;
    }

    if (!Param3 || VolumeExtension->IsUnknown00)
    {
        if (!ExAcquireRundownProtectionCacheAware(VolumeExtension->RundownCache))
        {
            DPRINT1("FtpAllSystemsGo: FIXME\n");
            ASSERT(FALSE);
        }

        if (VolumeExtension->IsUnknown00 && Param4)
        {
            if (!VolumeExtension->IsVolumeOffline)
                InterlockedExchange(&VolumeExtension->Lock, 1);
        }

        KeReleaseSpinLock(&VolumeExtension->SpinLock, OldIrql);
        return STATUS_SUCCESS;
    }

    DPRINT1("FtpAllSystemsGo: FIXME\n");
    ASSERT(FALSE);

    DPRINT1("FtpAllSystemsGo: STATUS_NO_SUCH_DEVICE\n");
    return STATUS_NO_SUCH_DEVICE;
}

VOID
NTAPI
FtDiskUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
FtpCancelRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
    IoReleaseCancelSpinLock(Irp->CancelIrql);

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_CANCELLED;

    IoCompleteRequest(Irp, 0);
}

NTSTATUS
NTAPI
FtpDiskRegistryQueryRoutine(
    _In_ PWSTR ValueName,
    _In_ ULONG ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueLength,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID EntryContext)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_SUCCESS;
}

ULONG
NTAPI
FtpQueryDiskSignature(
    _In_ PDEVICE_OBJECT WholeDiskPdo)
{
    PDEVICE_OBJECT TopDeviceObject;
    PIRP Irp;
    NTSTATUS Status;
    KEVENT Event;
    IO_STATUS_BLOCK IoStatusBlock;
    ULONG DiskSignature;

    DPRINT("FtpQueryDiskSignature: WholeDiskPdo %p\n", WholeDiskPdo);

    TopDeviceObject = IoGetAttachedDeviceReference(WholeDiskPdo);
    if (!TopDeviceObject)
    {
        ASSERT(FALSE);
        return 0;
    }

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildDeviceIoControlRequest(0x704008,
                                        TopDeviceObject,
                                        NULL,
                                        0,
                                        &DiskSignature,
                                        sizeof(DiskSignature),
                                        FALSE,
                                        &Event,
                                        &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("FtpQueryDiskSignature: Build irp failed\n");
        ObDereferenceObject(TopDeviceObject);
        return 0;
    }

    Status = IoCallDriver(TopDeviceObject, Irp);

    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("FtpQueryDiskSignature: Status %X\n", Status);
        ObDereferenceObject(TopDeviceObject);
        return 0;
    }

    ObDereferenceObject(TopDeviceObject);

    DPRINT("FtpQueryDiskSignature: DiskSignature %X\n", DiskSignature);

    return DiskSignature;
}

ULONG
NTAPI
FtpQueryDiskSignatureCache(
    _In_ PVOLUME_EXTENSION VolumeExtension)
{
    if (!VolumeExtension->DiskSignature)
    {
        VolumeExtension->DiskSignature = FtpQueryDiskSignature(VolumeExtension->WholeDiskPdo);
    }

    return VolumeExtension->DiskSignature;
}

NTSTATUS
NTAPI
FtpQueryPartitionInformation(
    _In_ PROOT_EXTENSION RootExtension,
    _In_ PDEVICE_OBJECT PartitionPdo,
    _Out_ ULONG* OutDeviceNumber,
    _Out_ ULONGLONG* OutStartingOffset,
    _Out_ ULONG* OutPartitionNumber,
    _Out_ UCHAR* OutMbrPartitionType,
    _Out_ LONGLONG* OutPartitionLength,
    _Out_ GUID* OutGptPartitionType,
    _Out_ GUID* OutGptPartitionId,
    _Out_ UCHAR* OutIsGptPartition,
    _Out_ ULONGLONG* OutGptAttributes)
{
    PARTITION_INFORMATION_EX PartitionInfoEx;
    STORAGE_DEVICE_NUMBER OutputBuffer;
    IO_STATUS_BLOCK IoStatusBlock;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    DPRINT("FtpQueryPartitionInformation: %p, %p\n", RootExtension, PartitionPdo);

    if (OutDeviceNumber || OutPartitionNumber)
    {
        KeInitializeEvent(&Event, NotificationEvent, FALSE);

        Irp = IoBuildDeviceIoControlRequest(IOCTL_STORAGE_GET_DEVICE_NUMBER,
                                            PartitionPdo,
                                            NULL,
                                            0,
                                            &OutputBuffer,
                                            sizeof(OutputBuffer),
                                            FALSE,
                                            &Event,
                                            &IoStatusBlock);
        if (!Irp)
        {
            DPRINT1("FtpQueryPartitionInformation: Build irp failed\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status = IoCallDriver(PartitionPdo, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoStatusBlock.Status;
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("FtpQueryPartitionInformation: Status %X\n", Status);
            return Status;
        }

        if (OutDeviceNumber)
            *OutDeviceNumber = OutputBuffer.DeviceNumber;

        if (OutPartitionNumber)
            *OutPartitionNumber = OutputBuffer.PartitionNumber;
    }

    if (!OutStartingOffset &&
        !OutMbrPartitionType &&
        !OutPartitionLength &&
        !OutGptPartitionType &&
        !OutGptPartitionId &&
        !OutIsGptPartition &&
        !OutGptAttributes)
    {
        return STATUS_SUCCESS;
    }

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_PARTITION_INFO_EX,
                                        PartitionPdo,
                                        NULL,
                                        0,
                                        &PartitionInfoEx,
                                        sizeof(PartitionInfoEx),
                                        FALSE,
                                        &Event,
                                        &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("FtpQueryPartitionInformation: Build irp failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = IoCallDriver(PartitionPdo, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("FtpQueryPartitionInformation: Status %X\n", Status);
        return Status;
    }

    if (OutStartingOffset)
        *OutStartingOffset = PartitionInfoEx.StartingOffset.QuadPart;

    if (OutMbrPartitionType)
        *OutMbrPartitionType = ((PartitionInfoEx.PartitionStyle != 0) ? 0 : PartitionInfoEx.Mbr.PartitionType);

    if (OutPartitionLength)
        *OutPartitionLength = PartitionInfoEx.PartitionLength.QuadPart;

    if (OutGptPartitionType && PartitionInfoEx.PartitionStyle == 1)
        *OutGptPartitionType = PartitionInfoEx.Gpt.PartitionType;

    if (OutGptPartitionId && PartitionInfoEx.PartitionStyle == 1)
        *OutGptPartitionId = PartitionInfoEx.Gpt.PartitionId;

    if (OutIsGptPartition)
        *OutIsGptPartition = (PartitionInfoEx.PartitionStyle == 1);

    if (!OutGptAttributes)
        return STATUS_SUCCESS;

    if (PartitionInfoEx.PartitionStyle == 1)
        *OutGptAttributes = PartitionInfoEx.Gpt.Attributes;
    else
        *OutGptAttributes = 0;

    return STATUS_SUCCESS;
}

VOID
NTAPI
FtpCreateOldNameLinks(
    _In_ PVOLUME_EXTENSION VolumeExtension)
{
    PDEVICE_OBJECT PartitionPdo;
    UNICODE_STRING DeviceName;
    UNICODE_STRING SymbolicLinkName;
    WCHAR LinkBuffer[0x50]; // 80
    WCHAR DeviceBuffer[0x40]; // 64
    ULONG PartitionNumber;
    ULONG DeviceNumber;
    ULONG ix;
    NTSTATUS Status;

    DPRINT("FtpCreateOldNameLinks: VolumeExtension %p\n", VolumeExtension);

    swprintf(DeviceBuffer, L"\\Device\\HarddiskVolume%d", VolumeExtension->VolumeNumber);
    RtlInitUnicodeString(&DeviceName, DeviceBuffer);

    DPRINT("FtpCreateOldNameLinks: DeviceName '%wZ'\n", &DeviceName);

    PartitionPdo = VolumeExtension->PartitionPdo;
    if (!PartitionPdo)
    {
        DPRINT1("FtpCreateOldNameLinks: PartitionPdo is NULL\n");
        return;
    }

    Status = FtpQueryPartitionInformation(VolumeExtension->RootExtension,
                                          PartitionPdo,
                                          &DeviceNumber,
                                          NULL,
                                          &PartitionNumber,
                                          NULL,
                                          NULL,
                                          NULL,
                                          NULL,
                                          NULL,
                                          NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("FtpCreateOldNameLinks: Status %p\n", Status);
        return;
    }

    swprintf(LinkBuffer, L"\\Device\\Harddisk%d\\Partition%d", DeviceNumber, PartitionNumber);
    RtlInitUnicodeString(&SymbolicLinkName, LinkBuffer);

    DPRINT("FtpCreateOldNameLinks: SymbolicLinkName '%wZ'\n", &SymbolicLinkName);

    IoDeleteSymbolicLink(&SymbolicLinkName);

    for (ix = 0; ix < 0x3E8; ix++) // 1000
    {
        Status = IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
        if (NT_SUCCESS(Status))
            break;
    }
}

NTSTATUS
NTAPI
FtpQueryDeviceName(
    _In_ PVOLUME_EXTENSION VolumeExtension,
    _In_ PIRP Irp)
{
    UNICODE_STRING DestinationString;
    PMOUNTDEV_NAME MountDevName;
    PIO_STACK_LOCATION IoStack;
    WCHAR SourceString[0x64]; // 100
    ULONG Size;

    DPRINT("FtpQueryDeviceName: %p, %p\n", VolumeExtension, Irp);

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (IoStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(*MountDevName))
    {
        DPRINT1("FtpQueryDeviceName: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    swprintf(SourceString, L"\\Device\\HarddiskVolume%d", VolumeExtension->VolumeNumber);
    RtlInitUnicodeString(&DestinationString, SourceString);

    MountDevName = Irp->AssociatedIrp.SystemBuffer;
    MountDevName->NameLength = DestinationString.Length;

    Size = (DestinationString.Length + sizeof(WCHAR));
    Irp->IoStatus.Information = Size;

    if (IoStack->Parameters.DeviceIoControl.OutputBufferLength < Size)
    {
        DPRINT("FtpQueryDeviceName: STATUS_BUFFER_OVERFLOW\n");
        Irp->IoStatus.Information = sizeof(*MountDevName);
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlCopyMemory(MountDevName->Name, DestinationString.Buffer, MountDevName->NameLength);

    return STATUS_SUCCESS;
}

BOOLEAN
NTAPI
FtpQueryUniqueIdBuffer(
    _In_ PVOLUME_EXTENSION VolumeExtension,
    _Out_ UCHAR* OutDiskId,
    _Out_ USHORT* OutLength)
{
    PARTITION_INFORMATION_EX PartitionInfoEx;
    IO_STATUS_BLOCK IoStatusBlock;
    KEVENT Event;
    PIRP Irp;
    ULONG Signature;
    NTSTATUS Status;

    DPRINT("FtpQueryUniqueIdBuffer: %p\n", VolumeExtension);

    if (VolumeExtension->IsGptPartition)
    {
        *OutLength = 0x18;
    }
    else if (VolumeExtension->PartitionPdo)
    {
        *OutLength = 0xC;
    }
    else if (VolumeExtension->FtVolume)
    {
        *OutLength = 8;
    }
    else
    {
        DPRINT1("FtpQueryUniqueIdBuffer: return FALSE\n");
        return FALSE;
    }

    if (!OutDiskId)
        return TRUE;

    if (VolumeExtension->IsGptPartition)
    {
        RtlCopyMemory(OutDiskId, "DMIO:ID:", 8);
        RtlCopyMemory((OutDiskId + 8), &VolumeExtension->GptPartitionId, sizeof(GUID));
        return TRUE;
    }

    if (!VolumeExtension->PartitionPdo)
    {
        DPRINT1("FtpQueryUniqueIdBuffer:  FIXME\n");
        ASSERT(FALSE);
        return TRUE;
    }

    ASSERT(VolumeExtension->WholeDiskPdo);

    Signature = FtpQueryDiskSignatureCache(VolumeExtension);
    if (!Signature)
    {
        DPRINT1("FtpQueryUniqueIdBuffer: return FALSE\n");
        return FALSE;
    }

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_PARTITION_INFO_EX,
                                        VolumeExtension->PartitionPdo,
                                        NULL,
                                        0,
                                        &PartitionInfoEx,
                                        sizeof(PartitionInfoEx),
                                        FALSE,
                                        &Event,
                                        &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("FtpQueryUniqueIdBuffer: Build irp failed\n");
        return FALSE;
    }

    Status = IoCallDriver(VolumeExtension->PartitionPdo, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("FtpQueryUniqueIdBuffer: Status %X\n", Status);
        return FALSE;
    }

    *(ULONG *)OutDiskId = Signature;
    *(ULONGLONG *)((PULONG)OutDiskId + 1) = PartitionInfoEx.StartingOffset.QuadPart;

    return TRUE;
}

NTSTATUS
NTAPI
FtpQueryUniqueId(
    _In_ PVOLUME_EXTENSION VolumeExtension,
    _In_ PIRP Irp)
{
    PMOUNTDEV_UNIQUE_ID MountDevId;
    PIO_STACK_LOCATION IoStack;
    ULONG Size;

    DPRINT("FtpQueryUniqueId: %p, %p\n", VolumeExtension, Irp);

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (IoStack->Parameters.Read.Length < sizeof(*MountDevId))
    {
        DPRINT1("FtpQueryUniqueId: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    MountDevId = Irp->AssociatedIrp.SystemBuffer;

    if (VolumeExtension->IsSuperFloppy)
    {
        MountDevId->UniqueIdLength = VolumeExtension->DevnodeName.Length;
    }
    else if (!FtpQueryUniqueIdBuffer(VolumeExtension, NULL, Irp->AssociatedIrp.SystemBuffer))
    {
        DPRINT1("FtpQueryUniqueId: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    Size = (MountDevId->UniqueIdLength + sizeof(WCHAR));
    Irp->IoStatus.Information = Size;

    if (IoStack->Parameters.Read.Length < Size)
    {
        DPRINT("FtpQueryUniqueId: STATUS_BUFFER_OVERFLOW\n");
        Irp->IoStatus.Information = sizeof(*MountDevId);
        return STATUS_BUFFER_OVERFLOW;
    }

    if (VolumeExtension->IsSuperFloppy)
    {
        RtlCopyMemory(MountDevId->UniqueId, VolumeExtension->DevnodeName.Buffer, MountDevId->UniqueIdLength);
        return STATUS_SUCCESS;
    }

    if (!FtpQueryUniqueIdBuffer(VolumeExtension, MountDevId->UniqueId, (USHORT *)MountDevId))
    {
        DPRINT1("FtpQueryUniqueId: STATUS_INVALID_DEVICE_REQUEST\n");
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
FtpQueryStableGuid(
    _In_ PVOLUME_EXTENSION VolumeExtension,
    _In_ PIRP Irp)
{
    PMOUNTDEV_STABLE_GUID MountDevGuid;
    PIO_STACK_LOCATION IoStack;

    DPRINT("FtpQueryStableGuid: %p, %p\n", VolumeExtension, Irp);

    if (!VolumeExtension->IsGptPartition)
    {
        DPRINT("FtpQueryStableGuid: STATUS_UNSUCCESSFUL\n");
        return STATUS_UNSUCCESSFUL;
    }

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (IoStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MOUNTDEV_STABLE_GUID))
    {
        DPRINT1("FtpQueryStableGuid: STATUS_UNSUCCESSFUL\n");
        return STATUS_INVALID_PARAMETER;
    }

    MountDevGuid = Irp->AssociatedIrp.SystemBuffer;
    MountDevGuid->StableGuid = VolumeExtension->GptPartitionId;

    Irp->IoStatus.Information = sizeof(MOUNTDEV_STABLE_GUID);

    return STATUS_SUCCESS;
}

static
UCHAR
NTAPI
QueryDriveLetterFromRegistry(
    _In_ PROOT_EXTENSION RootExtension,
    _In_ PVOLUME_EXTENSION VolumeExtension,
    _In_ PDEVICE_OBJECT PartitionPdo,
    _In_ PDEVICE_OBJECT WholeDiskPdo,
    _In_ BOOLEAN Param5)
{
    PARTITION_INFORMATION_EX PartitionInfoEx;
    RTL_QUERY_REGISTRY_TABLE QueryTable[2];
    //PDISK_PARTITION DiskPartition;
    IO_STATUS_BLOCK IoStatusBlock;
    ULONGLONG StartingOffset = 0;
    PDISK_CONFIG_HEADER Context;
    UCHAR DriveLetter;
    ULONG ValueLength;
    ULONG Signature;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    DPRINT("QueryDriveLetterFromRegistry: %p, %X\n", VolumeExtension, Param5);

    RtlZeroMemory(QueryTable, sizeof(QueryTable));

    QueryTable[0].EntryContext = &ValueLength;
    QueryTable[0].QueryRoutine = FtpDiskRegistryQueryRoutine;
    QueryTable[0].Flags = 4;
    QueryTable[0].Name = L"Information";

    Status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\System\\DISK", QueryTable, &Context, NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("QueryDriveLetterFromRegistry: Status %X\n", Status);
        return 0;
    }

    ObReferenceObject(PartitionPdo);
    ObReferenceObject(WholeDiskPdo);

    FtpRelease(RootExtension);

    Signature = FtpQueryDiskSignatureCache(VolumeExtension);

    if (!Signature)
    {
        Status = STATUS_UNSUCCESSFUL;
    }
    else
    {
        KeInitializeEvent(&Event, NotificationEvent, FALSE);

        Irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_PARTITION_INFO_EX,
                                            PartitionPdo,
                                            NULL,
                                            0,
                                            &PartitionInfoEx,
                                            sizeof(PartitionInfoEx),
                                            FALSE,
                                            &Event,
                                            &IoStatusBlock);
        if (!Irp)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            Status = IoCallDriver(PartitionPdo, Irp);
            if (Status == STATUS_PENDING)
            {
                KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
                Status = IoStatusBlock.Status;
            }

            if (NT_SUCCESS(Status))
            {
                StartingOffset = PartitionInfoEx.StartingOffset.QuadPart;
                Status = STATUS_SUCCESS;
            }
        }
    }

    FtpAcquire(RootExtension);

    ObDereferenceObject(WholeDiskPdo);
    ObDereferenceObject(PartitionPdo);

    ExFreePoolWithTag(Context, 0);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("QueryDriveLetterFromRegistry: Status %X\n", Status);
        return 0;
    }

    RtlZeroMemory(QueryTable, sizeof(QueryTable));

    QueryTable[0].EntryContext = &ValueLength;
    QueryTable[0].QueryRoutine = FtpDiskRegistryQueryRoutine;
    QueryTable[0].Flags = 4;
    QueryTable[0].Name = L"Information";

    Status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\System\\DISK", QueryTable, &Context, NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("QueryDriveLetterFromRegistry: Status %X\n", Status);
        return 0;
    }

    DPRINT1("QueryDriveLetterFromRegistry: FIXME\n");
    ASSERT(FALSE);DriveLetter=0;if(StartingOffset){;}

    return DriveLetter;
}

UCHAR
NTAPI
FtpQueryDriveLetterFromRegistry(
    _In_ PVOLUME_EXTENSION VolumeExtension,
    _In_ BOOLEAN Param2)
{
    UCHAR DriveLetter;

    DPRINT("FtpQueryDriveLetterFromRegistry: %p, %X\n", VolumeExtension, Param2);

    if (!VolumeExtension->PartitionPdo)
        return 0;

    DriveLetter = QueryDriveLetterFromRegistry(VolumeExtension->RootExtension,
                                               VolumeExtension,
                                               VolumeExtension->PartitionPdo,
                                               VolumeExtension->WholeDiskPdo,
                                               Param2);
    return DriveLetter;
}

NTSTATUS
NTAPI
FtpQuerySuggestedLinkName(
    _In_ PVOLUME_EXTENSION VolumeExtension,
    _In_ PIRP Irp)
{
    PMOUNTDEV_SUGGESTED_LINK_NAME MountDevLinkName;
    PIO_STACK_LOCATION IoStack;
    UNICODE_STRING Name;
    WCHAR LinkString[0x1E]; // 30
    ULONG BufferLength;
    ULONG Size;
    UCHAR DriveLetter;

    DPRINT("FtpQuerySuggestedLinkName: %p, %p\n", VolumeExtension, Irp);

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    BufferLength = IoStack->Parameters.DeviceIoControl.OutputBufferLength;
    if (BufferLength < 6)
    {
        DPRINT1("FtpQuerySuggestedLinkName: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    DriveLetter = FtpQueryDriveLetterFromRegistry(VolumeExtension, (BufferLength >= 0x20));

    if (VolumeExtension->FtVolume)
    {
        DPRINT1("FtpQuerySuggestedLinkName: FIXME\n");
        ASSERT(FALSE);
    }

    if (!DriveLetter)
    {
        DPRINT("FtpQuerySuggestedLinkName: STATUS_NOT_FOUND\n");
        return STATUS_NOT_FOUND;
    }

    swprintf(LinkString, L"\\DosDevices\\%c:", DriveLetter);
    RtlInitUnicodeString(&Name, LinkString);

    MountDevLinkName = Irp->AssociatedIrp.SystemBuffer;
    MountDevLinkName->UseOnlyIfThereAreNoOtherLinks = TRUE;
    MountDevLinkName->NameLength = Name.Length;

    Size = (Name.Length + (2 * sizeof(WCHAR)));
    Irp->IoStatus.Information = Size;

    if (IoStack->Parameters.Read.Length < Size)
    {
        DPRINT("FtpQuerySuggestedLinkName: STATUS_BUFFER_OVERFLOW\n");
        Irp->IoStatus.Information = 6;
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlCopyMemory(MountDevLinkName->Name, Name.Buffer, MountDevLinkName->NameLength);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
FtpLinkCreated(
    _In_ PVOLUME_EXTENSION VolumeExtension,
    _In_ PIRP Irp)
{
    DPRINT("FtpLinkCreated: %p, %p\n", VolumeExtension, Irp);

    if (!VolumeExtension->FtVolume)
        return STATUS_SUCCESS;

    DPRINT1("FtpLinkCreated: FIXME\n");
    ASSERT(FALSE);


    return STATUS_SUCCESS;
}

VOID
NTAPI
FtpCancelChangeNotify(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PVOLUME_EXTENSION VolumeExtension;

    DPRINT("FtpCancelChangeNotify: %p, %p\n", DeviceObject, Irp);

    IoReleaseCancelSpinLock(Irp->CancelIrql);

    VolumeExtension = Irp->Tail.Overlay.DriverContext[0];

    FtpAcquire(VolumeExtension->RootExtension);
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
    FtpRelease(VolumeExtension->RootExtension);

    Irp->IoStatus.Status = STATUS_CANCELLED;

    IoCompleteRequest(Irp, 0);
}

NTSTATUS
NTAPI
FtpUniqueIdChangeNotify(
    _In_ PVOLUME_EXTENSION VolumeExtension,
    _In_ PIRP Irp)
{
    PMOUNTDEV_UNIQUE_ID MountDevId;
    PIO_STACK_LOCATION IoStack;
    UCHAR IdBuffer[0x34]; // 52
    ULONG Size;

    DPRINT("FtpUniqueIdChangeNotify: %p, %p\n", VolumeExtension, Irp);

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Size = IoStack->Parameters.DeviceIoControl.InputBufferLength;

    if (Size < sizeof(*MountDevId))
    {
        DPRINT1("FtpUniqueIdChangeNotify: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (!VolumeExtension->PartitionPdo && !VolumeExtension->FtVolume)
    {
        DPRINT1("FtpUniqueIdChangeNotify: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (VolumeExtension->IsSuperFloppy)
    {
        DPRINT1("FtpUniqueIdChangeNotify: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    MountDevId = Irp->AssociatedIrp.SystemBuffer;

    if (Size < (MountDevId->UniqueIdLength + sizeof(WCHAR)))
    {
        DPRINT1("FtpUniqueIdChangeNotify: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (!IsListEmpty(&VolumeExtension->UniqueIdNotifyList))
    {
        DPRINT1("FtpUniqueIdChangeNotify: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (!FtpQueryUniqueIdBuffer(VolumeExtension, &IdBuffer[2], (PUSHORT)IdBuffer))
    {
        DPRINT1("FtpUniqueIdChangeNotify: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    Irp->Tail.Overlay.DriverContext[0] = VolumeExtension;

    IoSetCancelRoutine(Irp, FtpCancelChangeNotify);

    if (Irp->Cancel && !IoSetCancelRoutine(Irp, NULL))
    {
        DPRINT1("FtpUniqueIdChangeNotify: STATUS_CANCELLED\n");
        return STATUS_CANCELLED;
    }

    IoMarkIrpPending(Irp);

    InsertTailList(&VolumeExtension->UniqueIdNotifyList, &Irp->Tail.Overlay.ListEntry);

    if (MountDevId->UniqueIdLength != *(PUSHORT)IdBuffer ||
        RtlCompareMemory(MountDevId->UniqueId, &IdBuffer[2], MountDevId->UniqueIdLength) != MountDevId->UniqueIdLength)
    {
        DPRINT1("FtpUniqueIdChangeNotify: FIXME\n");
        ASSERT(FALSE);
    }

    return STATUS_PENDING;
}

NTSTATUS
NTAPI
FtpGetGptAttributes(
    _In_ PVOLUME_EXTENSION VolumeExtension,
    _In_ PIRP Irp)
{
    PVOLUME_GET_GPT_ATTRIBUTES_INFORMATION  GptAttributesInfo;
    PIO_STACK_LOCATION IoStack;
    ULONGLONG GptAttributes;
    GUID Guid;
    UCHAR PartitionType;
    NTSTATUS Status;

    DPRINT("FtpGetGptAttributes: %p, %p\n", VolumeExtension, Irp);

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    GptAttributesInfo = Irp->AssociatedIrp.SystemBuffer;
    Irp->IoStatus.Information = sizeof(VOLUME_GET_GPT_ATTRIBUTES_INFORMATION);

    if (IoStack->Parameters.DeviceIoControl.OutputBufferLength < Irp->IoStatus.Information)
    {
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    if (!VolumeExtension->PartitionPdo)
    {
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    Status = FtpQueryPartitionInformation(VolumeExtension->RootExtension,
                                          VolumeExtension->PartitionPdo,
                                          NULL,
                                          NULL,
                                          NULL,
                                          &PartitionType,
                                          NULL,
                                          &Guid,
                                          NULL,
                                          NULL,
                                          &GptAttributes);
    if (!NT_SUCCESS(Status))
    {
        Irp->IoStatus.Information = 0;
        return Status;
    }

    if (VolumeExtension->IsGptPartition)
    {
        if (!IsEqualGUID(&Guid, &PARTITION_BASIC_DATA_GUID))
        {
            Irp->IoStatus.Information = 0;
            return STATUS_INVALID_PARAMETER;
        }

        GptAttributesInfo->GptAttributes = GptAttributes;
        return STATUS_SUCCESS;
    }

    if (!IsRecognizedPartition_(PartitionType))
    {
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    DPRINT("FtpGetGptAttributes: HACK!!! FIXME for GPT partitions\n");

    //LogicalDiskInfo = FindLogicalDiskInformation(...);
    //if (!LogicalDiskInfo)
    if (TRUE)
    {
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    //GptAttributesInfo->GptAttributes = GetGptAttributes(LogicalDiskInfo);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
FtpCheckOfflineOwner(
    _In_ PVOLUME_EXTENSION VolumeExtension,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;

    DPRINT("FtpCheckOfflineOwner: %p, %p\n", VolumeExtension, Irp);

    if (!VolumeExtension->OfflineOwner)
        return STATUS_SUCCESS;

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(GUID))
    {
        DPRINT1("FtpCheckOfflineOwner: STATUS_FILE_LOCK_CONFLICT\n");
        return STATUS_FILE_LOCK_CONFLICT;
    }

    if (!IsEqualGUID((PGUID)Irp->AssociatedIrp.SystemBuffer, (PGUID)VolumeExtension->OfflineOwner))
    {
        DPRINT1("FtpCheckOfflineOwner: STATUS_FILE_LOCK_CONFLICT\n");
        return STATUS_FILE_LOCK_CONFLICT;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
FtpReadPartitionTableEx(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PDRIVE_LAYOUT_INFORMATION_EX* OutDriveLayout)
{
    IO_STATUS_BLOCK IoStatusBlock;
    PVOID DriveLayoutBuffer;
    KEVENT Event;
    PIRP Irp;
    SIZE_T IoCtlBufferSize;
    SIZE_T NumberOfBytes;
    ULONG ix = 0;
    NTSTATUS Status;

    DPRINT("FtpReadPartitionTableEx: %p\n", DeviceObject);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    DriveLayoutBuffer = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'iFcS');
    if (!DriveLayoutBuffer)
    {
        ASSERT(FALSE);
        return IoReadPartitionTableEx(DeviceObject, OutDriveLayout);
    }

    IoCtlBufferSize = PAGE_SIZE;
    KeClearEvent(&Event);

    for (Irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                                              DeviceObject,
                                              NULL,
                                              0,
                                              DriveLayoutBuffer,
                                              PAGE_SIZE,
                                              0,
                                              &Event,
                                              &IoStatusBlock);
          ;
          Irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                                              DeviceObject,
                                              NULL,
                                              0,
                                              DriveLayoutBuffer,
                                              NumberOfBytes,
                                              0,
                                              &Event,
                                              &IoStatusBlock))
    {
        if (!Irp)
        {
            DPRINT1("FtpReadPartitionTableEx: Ipr not created!\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        Status = IoCallDriver(DeviceObject, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoStatusBlock.Status;
        }

        if (NT_SUCCESS(Status))
        {
            ASSERT(DriveLayoutBuffer && IoCtlBufferSize);
            *OutDriveLayout = DriveLayoutBuffer;
            return STATUS_SUCCESS;
        }

        if (Status != STATUS_BUFFER_TOO_SMALL)
        {
            DPRINT1("FtpReadPartitionTableEx: Status %X\n", Status);
            break;
        }

        ASSERT(DriveLayoutBuffer && IoCtlBufferSize);
        ExFreePoolWithTag(DriveLayoutBuffer, 'iFcS');

        NumberOfBytes = (2 * IoCtlBufferSize);
        ASSERT(NumberOfBytes != 0);

        DriveLayoutBuffer = ExAllocatePoolWithTag(NonPagedPool, NumberOfBytes, 'iFcS');
        if (!DriveLayoutBuffer)
        {
            DPRINT1("FtpReadPartitionTableEx: DriveLayoutBuffer not created!\n");
            return IoReadPartitionTableEx(DeviceObject, OutDriveLayout);
        }

        IoCtlBufferSize = NumberOfBytes;

        ix++;
        if (ix > 0x20)
        {
            DPRINT1("FtpReadPartitionTableEx: ix %X\n", ix);
            Status = STATUS_UNSUCCESSFUL;
            break;
        }

        KeClearEvent(&Event);
    }

    if (DriveLayoutBuffer)
    {
        ASSERT(IoCtlBufferSize);
        ExFreePoolWithTag(DriveLayoutBuffer, 'iFcS');
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("FtpReadPartitionTableEx: Status %X\n", Status);
        return IoReadPartitionTableEx(DeviceObject, OutDriveLayout);
    }

    return Status;
}

BOOLEAN
NTAPI
FtpCreateNewDevice(
    _In_ PROOT_EXTENSION RootExtension,
    _In_ PDEVICE_OBJECT PartitionPdo,
    _In_ PVOID FtVolume, // FT_VOLUME*
    _In_ PDEVICE_OBJECT WholeDiskPdo,
    _In_ ULONG Alignment,
    _In_ BOOLEAN IsEmptyDevice,
    _In_ BOOLEAN IsHidenPartition,
    _In_ BOOLEAN IsReadOnlyPartition,
    _In_ BOOLEAN IsSystemPartition,
    _In_ ULONGLONG GptAttributes)
{
    PARTITION_INFORMATION_EX PartitionInfo;
    PVOLUME_EXTENSION VolumeExtension;
    PVOLUME_EXTENSION CurrentExtension;
    PDEVICE_OBJECT NewDeviceObject;
    IO_STATUS_BLOCK IoStatusBlock;
    UNICODE_STRING VolumeName;
    GUID GptPartitionId;
    WCHAR SourceString[0x1E]; // 30
    PLIST_ENTRY Entry;
    PWSTR NameBuffer;
    KEVENT Event;
    PIRP Irp;
    ULONG SizeOfRundownCache;
    ULONG Signature;
    LONG IsDifferentVolumes;
    BOOLEAN IsGptPartition;
    NTSTATUS Status;

    DPRINT("FtpCreateNewDevice: %p, %p, %p, %p, %X, %X, %X, %X, %X\n",
           RootExtension, PartitionPdo, FtVolume, WholeDiskPdo, Alignment, IsEmptyDevice, IsHidenPartition, IsReadOnlyPartition, IsSystemPartition);

    ASSERT(!(PartitionPdo && FtVolume));
    ASSERT(!PartitionPdo || WholeDiskPdo);
    ASSERT(PartitionPdo || FtVolume);

    swprintf(SourceString, L"\\Device\\HarddiskVolume%d", RootExtension->VolumeCounter);
    RtlInitUnicodeString(&VolumeName, SourceString);

    SizeOfRundownCache = ExSizeOfRundownProtectionCacheAware();

    Status = IoCreateDevice(RootExtension->DriverObject,
                            (sizeof(*VolumeExtension) + SizeOfRundownCache),
                            &VolumeName,
                            FILE_DEVICE_DISK,
                            0,
                            FALSE,
                            &NewDeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("FtpCreateNewDevice: Status %X\n", Status);
        return FALSE;
    }

    VolumeExtension = NewDeviceObject->DeviceExtension;
    RtlZeroMemory(NewDeviceObject->DeviceExtension, sizeof(*VolumeExtension));

    VolumeExtension->DeviceExtensionType = 1;
    VolumeExtension->RootExtension = RootExtension;

    VolumeExtension->SelfDeviceObject = NewDeviceObject;
    VolumeExtension->PartitionPdo = PartitionPdo;
    VolumeExtension->FtVolume = FtVolume;

    KeInitializeSpinLock(&VolumeExtension->SpinLock);

    VolumeExtension->RundownCache = &VolumeExtension[1];
    ExInitializeRundownProtectionCacheAware(VolumeExtension->RundownCache, SizeOfRundownCache);

    InitializeListHead(&VolumeExtension->IrpList);
    InitializeListHead(&VolumeExtension->UniqueIdNotifyList);

    VolumeExtension->IsStartCallback = FALSE;
    VolumeExtension->IsVolumeOffline = TRUE;

    VolumeExtension->IsHidenPartition = IsHidenPartition;
    VolumeExtension->IsReadOnlyPartition = IsReadOnlyPartition;
    VolumeExtension->IsSystemPartition = IsSystemPartition;

    VolumeExtension->VolumeNumber = RootExtension->VolumeCounter++;
    VolumeExtension->GptAttributes = GptAttributes;

    //DPRINT("FtpCreateNewDevice: FIXME TRANSFER_PACKET_new\n");

    NameBuffer = ExAllocatePoolWithTag(PagedPool, 0xA0, 'tFcS'); // (160 = 80 * 2)
    if (!NameBuffer)
    {
        DPRINT1("FtpCreateNewDevice: Allocate failed\n");
        goto ExitError;
    }

    if (PartitionPdo)
    {
        VolumeExtension->WholeDiskPdo = WholeDiskPdo;

        VolumeExtension->WholeDiskDevice = IoGetAttachedDeviceReference(WholeDiskPdo);
        ObDereferenceObject(VolumeExtension->WholeDiskDevice);

        KeInitializeEvent(&Event, NotificationEvent, FALSE);

        Irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_PARTITION_INFO_EX,
                                            PartitionPdo,
                                            NULL,
                                            0,
                                            &PartitionInfo,
                                            sizeof(PartitionInfo),
                                            FALSE,
                                            &Event,
                                            &IoStatusBlock);
        if (!Irp)
        {
            DPRINT1("FtpCreateNewDevice: Build irp failed\n");
            goto ExitError;
        }

        Status = IoCallDriver(PartitionPdo, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoStatusBlock.Status;
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("FtpCreateNewDevice: Status %X\n", Status);
            goto ExitError;
        }

        if (PartitionInfo.PartitionStyle == 1)
        {
            GptPartitionId = PartitionInfo.Gpt.PartitionId;
            IsGptPartition = TRUE;
        }
        else
        {
            IsGptPartition = FALSE;
        }

        VolumeExtension->StartingOffset = PartitionInfo.StartingOffset.QuadPart;
        VolumeExtension->PartitionLength = PartitionInfo.PartitionLength.QuadPart;

        if (IsGptPartition)
        {
            VolumeExtension->IsGptPartition = TRUE;
            VolumeExtension->GptPartitionId = GptPartitionId;

            DPRINT1("FtpCreateNewDevice: FIXME\n");
            ASSERT(FALSE);
        }
        else
        {
            if (VolumeExtension->StartingOffset)
            {
                Signature = FtpQueryDiskSignatureCache(VolumeExtension);
                if (!Signature)
                {
                    DPRINT1("FtpCreateNewDevice: Signature is 0!\n");
                    goto ExitError;
                }

                swprintf(NameBuffer, L"Signature%XOffset%I64XLength%I64X", Signature, VolumeExtension->StartingOffset, VolumeExtension->PartitionLength);
            }
            else
            {
                DPRINT1("FtpCreateNewDevice: FIXME\n");
                ASSERT(FALSE);
            }
        }
    }
    else
    {
        DPRINT1("FtpCreateNewDevice: FIXME\n");
        ASSERT(FALSE);
    }

    RtlInitUnicodeString(&VolumeExtension->DevnodeName, NameBuffer);

    KeInitializeSemaphore(&VolumeExtension->ZeroRefSemaphore, 1, 1);
    KeInitializeSemaphore(&VolumeExtension->Semaphore, 1, 1);

    InsertTailList(&RootExtension->VolumeList, &VolumeExtension->Link);

    NewDeviceObject->Flags |= DO_DIRECT_IO;
    NewDeviceObject->AlignmentRequirement = Alignment;

    if (FtVolume)
    {
        DPRINT1("FtpCreateNewDevice: FIXME\n");
        ASSERT(FALSE);
    }
    else
    {
        NewDeviceObject->StackSize = (PartitionPdo->StackSize + 1);
    }

    if (IsEmptyDevice)
    {
        DPRINT1("FtpCreateNewDevice: FIXME\n");
        ASSERT(FALSE);
    }
    else
    {
        FtpCreateOldNameLinks(VolumeExtension);
    }

    if (!IsEmptyDevice && RootExtension->EmptyDeviceCount)
    {
        IsDifferentVolumes = 1;

        for (Entry = RootExtension->VolumeList.Flink;
             Entry != &RootExtension->VolumeList;
             Entry = Entry->Flink)
        {
            CurrentExtension = CONTAINING_RECORD(Entry, VOLUME_EXTENSION, Link);

            if (CurrentExtension != VolumeExtension && !CurrentExtension->IsEmptyVolume)
            {
                IsDifferentVolumes = RtlCompareUnicodeString(&CurrentExtension->DevnodeName, &VolumeExtension->DevnodeName, TRUE);
                if (!IsDifferentVolumes)
                    break;
            }
        }

        if (!IsDifferentVolumes)
        {
            DPRINT1("FtpCreateNewDevice: FIXME\n");
            ASSERT(FALSE);
        }
    }

    NewDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return TRUE;

ExitError:

    DPRINT1("FtpCreateNewDevice: FIXME\n");
    ASSERT(FALSE);
    IoDeleteDevice(NewDeviceObject);
    return FALSE;
}

NTSTATUS
NTAPI
FtpPartitionArrivedHelper(
    _In_ PROOT_EXTENSION RootExtension,
    _In_ PDEVICE_OBJECT PartitionPdo,
    _In_ PDEVICE_OBJECT WholeDiskPdo)
{
    GUID GptPartitionId;
    GUID GptPartitionType;
    ULONGLONG GptAttributes;
    ULONGLONG StartingOffset;
    ULONG DeviceNumber;
    UCHAR PartitionType;
    BOOLEAN IsSystemPartition;
    BOOLEAN IsReadOnlyPartition;
    BOOLEAN IsHidenPartition;
    BOOLEAN IsGptPartition;
    BOOLEAN Result;
    NTSTATUS Status;

    DPRINT("FtpPartitionArrivedHelper: %p, %p, %p\n", RootExtension, PartitionPdo, WholeDiskPdo);

    Status = FtpQueryPartitionInformation(RootExtension,
                                          PartitionPdo,
                                          &DeviceNumber,
                                          &StartingOffset,
                                          NULL,
                                          &PartitionType,
                                          NULL,
                                          &GptPartitionType,
                                          &GptPartitionId,
                                          &IsGptPartition,
                                          &GptAttributes);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("FtpPartitionArrivedHelper: Status %X\n", Status);
        return Status;
    }

    IsHidenPartition = FALSE;
    IsReadOnlyPartition = FALSE;

    if (IsGptPartition)
    {
        DPRINT1("FtpPartitionArrivedHelper: FIXME\n");
        ASSERT(FALSE);
    }
    else
    {
        if (PartitionType == PARTITION_LDM)
        {
            DPRINT1("FtpPartitionArrivedHelper: STATUS_INVALID_PARAMETER\n");
            return STATUS_INVALID_PARAMETER;
        }

        if (!IsRecognizedPartition_(PartitionType))
            IsHidenPartition = TRUE;

        IsSystemPartition = FALSE;
    }

    Result = FtpCreateNewDevice(RootExtension,
                                PartitionPdo,
                                NULL,
                                WholeDiskPdo,
                                PartitionPdo->AlignmentRequirement,
                                FALSE,
                                IsHidenPartition,
                                IsReadOnlyPartition,
                                IsSystemPartition,
                                GptAttributes);
    if (!Result)
    {
        DPRINT1("FtpPartitionArrivedHelper: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    IoInvalidateDeviceRelations(RootExtension->VolControlRootPdo, BusRelations);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
FtpPartitionArrived(
    _In_ PROOT_EXTENSION RootExtension,
    _In_ PIRP Irp)
{
    PFT_PARTITION_ARRIVED Partitions;
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    DPRINT("FtpPartitionArrived: RootExtension %p, Irp %p\n", RootExtension, Irp);

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(*Partitions))
    {
        DPRINT1("FtpPartitionArrived: STATUS_INVALID_PARAMETER (%X)\n", IoStack->Parameters.DeviceIoControl.InputBufferLength);
        return STATUS_INVALID_PARAMETER;
    }

    Partitions = Irp->AssociatedIrp.SystemBuffer;

    DPRINT("FtpPartitionArrived: %p, %p\n", Partitions->PartitionPdo, Partitions->WholeDiskPdo);

    Status = FtpPartitionArrivedHelper(RootExtension, Partitions->PartitionPdo, Partitions->WholeDiskPdo);

    DPRINT("FtpPartitionArrived: Status %X\n", Status);

    return Status;
}

NTSTATUS
NTAPI
FtpQueryId(
    _In_ PVOLUME_EXTENSION VolumeExtension,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    UNICODE_STRING IdString;
    PWSTR IdBuffer;
    ULONG IdType;

    DPRINT("FtpQueryId: %p, %p\n", VolumeExtension, Irp);

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    IdType = IoStack->Parameters.QueryId.IdType;

    if (IdType == 0)
    {
        RtlInitUnicodeString(&IdString, L"STORAGE\\Volume");
    }
    else if (IdType == 1)
    {
        RtlInitUnicodeString(&IdString, L"STORAGE\\Volume");
    }
    else if (IdType == 3)
    {
        IdString = VolumeExtension->DevnodeName;
    }
    else
    {
        DPRINT("FtpQueryId: not supported IdType %X for (%p, %p)\n", IdType, VolumeExtension, Irp);
        return STATUS_NOT_SUPPORTED;
    }

    IdBuffer = ExAllocatePoolWithTag(PagedPool, (IdString.Length + (2 * sizeof(WCHAR))), 'tFcS');
    if (!IdBuffer)
    {
        DPRINT1("FtpQueryId: Allocate failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(IdBuffer, IdString.Buffer, IdString.Length);

    IdBuffer[IdString.Length / sizeof(WCHAR)] = 0;
    IdBuffer[IdString.Length / sizeof(WCHAR) + 1] = 0;

    Irp->IoStatus.Information = (ULONG)IdBuffer;

    return STATUS_SUCCESS;
}

VOID
NTAPI
FtpZeroRefCallback(
    _In_ PVOLUME_EXTENSION VolumeExtension,
    _In_ VOID (NTAPI* ZeroRefCallback)(PVOLUME_EXTENSION),
    _In_ PVOID ZeroRefContext)
{
    KIRQL OldIrql;
    BOOLEAN IsIrpListNotEmpty;

    DPRINT("FtpZeroRefCallback: %p, %p\n", VolumeExtension, ZeroRefContext);

    KeWaitForSingleObject(&VolumeExtension->ZeroRefSemaphore, Executive, KernelMode, FALSE, NULL);

    KeAcquireSpinLock(&VolumeExtension->SpinLock, &OldIrql);
    InterlockedExchange(&VolumeExtension->Lock, 0);

    ASSERT(!VolumeExtension->ZeroRefCallback);

    VolumeExtension->ZeroRefCallback = ZeroRefCallback;
    VolumeExtension->ZeroRefContext = ZeroRefContext;

    KeReleaseSpinLock(&VolumeExtension->SpinLock, OldIrql);

    if (VolumeExtension->FtVolume)
    {
        DPRINT1("FtpZeroRefCallback: FIXME (%p, %p)\n", VolumeExtension, VolumeExtension->FtVolume);
        ASSERT(FALSE);
    }

    ExWaitForRundownProtectionReleaseCacheAware(VolumeExtension->RundownCache);

    KeAcquireSpinLock(&VolumeExtension->SpinLock, &OldIrql);
    if (!VolumeExtension->ZeroRefCallback)
    {
        KeReleaseSpinLock(&VolumeExtension->SpinLock, OldIrql);
        return;
    }

    VolumeExtension->ZeroRefCallback(VolumeExtension);
    VolumeExtension->ZeroRefCallback = NULL;

    ExReInitializeRundownProtectionCacheAware(VolumeExtension->RundownCache);

    if (VolumeExtension->FtVolume)
    {
        DPRINT1("FtpZeroRefCallback: FIXME (%p, %p)\n", VolumeExtension, VolumeExtension->FtVolume);
        ASSERT(FALSE);
    }

    if (IsListEmpty(&VolumeExtension->IrpList))
    {
        IsIrpListNotEmpty = FALSE;
    }
    else
    {
        IsIrpListNotEmpty = TRUE;

        DPRINT1("FtpZeroRefCallback: FIXME\n");
        ASSERT(FALSE);
    }

    KeReleaseSpinLock(&VolumeExtension->SpinLock, OldIrql);
    KeReleaseSemaphore(&VolumeExtension->ZeroRefSemaphore, 0, 1, FALSE);

    if (!IsIrpListNotEmpty)
        return;

    ASSERT(FALSE);

}

VOID
NTAPI
FtpStartCallback(
    _In_ PVOLUME_EXTENSION VolumeExtension)
{
    PRKEVENT Event = VolumeExtension->ZeroRefContext;

    VolumeExtension->IsStartCallback = TRUE;
    KeSetEvent(Event, 0, FALSE);
}

VOID
NTAPI
FtpVolumeOfflineCallback(
    _In_ PVOLUME_EXTENSION VolumeExtension)
{
    PRKEVENT Event = VolumeExtension->ZeroRefContext;

    if (!VolumeExtension->IsVolumeOffline)
    {
        VolumeExtension->IsVolumeOffline = TRUE;

        if (VolumeExtension->FtVolume)
        {
            DPRINT1("FtpVolumeOfflineCallback: FIXME (%p)\n", VolumeExtension);
            ASSERT(FALSE);
        }
    }

    KeSetEvent(Event, 0, FALSE);
}

/* DRIVER DISPATCH ROUTINES *************************************************/

NTSTATUS
NTAPI
FtDiskCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    DPRINT("FtDiskCreate: %p, %p\n", DeviceObject, Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, 0);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
FtDiskReadWrite(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PVOLUME_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    LONGLONG ByteOffset;
    ULONG Length;
    NTSTATUS Status;

    //DPRINT("FtDiskReadWrite: %p, %p\n", DeviceObject, Irp);

    Extension = DeviceObject->DeviceExtension;
    if (Extension->DeviceExtensionType != 1)
    {
        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
        IoCompleteRequest(Irp, 0);

        return STATUS_NO_SUCH_DEVICE;
    }

    if (ExAcquireRundownProtectionCacheAware(Extension->RundownCache))
    {
        if (!Extension->Lock)
            ExReleaseRundownProtectionCacheAware(Extension->RundownCache);
    }

    if (!Extension->Lock)
    {
        Status = FtpAllSystemsGo(Extension, Irp, TRUE, TRUE, TRUE);
        if (Status == STATUS_PENDING)
            return STATUS_PENDING;

        if (!NT_SUCCESS(Status))
        {
            Irp->IoStatus.Information = 0;
            Irp->IoStatus.Status = Status;
            IoCompleteRequest(Irp, 0);

            return Status;
        }
    }

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (Extension->IsReadOnlyPartition && IoStack->MajorFunction == IRP_MJ_WRITE)
    {
        ExReleaseRundownProtectionCacheAware(Extension->RundownCache);

        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, 0);

        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (!Extension->PartitionPdo)
    {
        DPRINT1("FtDiskReadWrite: FIXME\n");
        ASSERT(Extension->FtVolume);
        ASSERT(FALSE);

        return STATUS_PENDING;
    }

    IoCopyCurrentIrpStackLocationToNext(Irp);

    if (!Extension->WholeDiskDevice)
    {
        IoSetCompletionRoutine(Irp, FtpRefCountCompletionRoutine, Extension, TRUE, TRUE, TRUE);
        IoMarkIrpPending(Irp);

        IoCallDriver(Extension->PartitionPdo, Irp);

        return STATUS_PENDING;
    }

    IoStack = IoGetNextIrpStackLocation(Irp);

    ByteOffset = IoStack->Parameters.Read.ByteOffset.QuadPart;
    Length = IoStack->Parameters.Read.Length;

    if (ByteOffset < 0 || (ByteOffset + Length) > Extension->PartitionLength)
    {
        ExReleaseRundownProtectionCacheAware(Extension->RundownCache);

        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        IoCompleteRequest(Irp, 0);

        return STATUS_INVALID_PARAMETER;
    }

    IoStack->Parameters.Read.ByteOffset.QuadPart += Extension->StartingOffset;

    IoSetCompletionRoutine(Irp, FtpRefCountCompletionRoutine, Extension, TRUE, TRUE, TRUE);
    IoMarkIrpPending(Irp);

    IoCallDriver(Extension->WholeDiskDevice, Irp);

    return STATUS_PENDING;
}

NTSTATUS
NTAPI
FtDiskDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PVOLUME_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    ULONG ControlCode;
    KEVENT Event;
    BOOLEAN IsRootExt;
    NTSTATUS Status;

    Extension = DeviceObject->DeviceExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);
    ControlCode = IoStack->Parameters.DeviceIoControl.IoControlCode;

    Irp->IoStatus.Information = 0;

    IsRootExt = (Extension->DeviceExtensionType == 0);
    if (IsRootExt)
    {
        DPRINT("FtDiskDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);

        switch (ControlCode)
        {
            case 0x760000:
                DPRINT1("FtDiskDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);
                ASSERT(FALSE);
                Status = STATUS_INVALID_DEVICE_REQUEST;
                break;

            case 0x760004:
                DPRINT1("FtDiskDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);
                ASSERT(FALSE);
                Status = STATUS_INVALID_DEVICE_REQUEST;
                break;

            case 0x760008:
                DPRINT1("FtDiskDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);
                ASSERT(FALSE);
                Status = STATUS_INVALID_DEVICE_REQUEST;
                break;

            case 0x76000C:
                DPRINT1("FtDiskDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);
                ASSERT(FALSE);
                Status = STATUS_INVALID_DEVICE_REQUEST;
                break;

            case 0x760018:
                DPRINT1("FtDiskDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);
                ASSERT(FALSE);
                Status = STATUS_INVALID_DEVICE_REQUEST;
                break;

            case 0x76001C:
                DPRINT1("FtDiskDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);
                ASSERT(FALSE);
                Status = STATUS_INVALID_DEVICE_REQUEST;
                break;

            case 0x760020:
                DPRINT1("FtDiskDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);
                ASSERT(FALSE);
                Status = STATUS_INVALID_DEVICE_REQUEST;
                break;

            case 0x760024:
                DPRINT1("FtDiskDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);
                ASSERT(FALSE);
                Status = STATUS_INVALID_DEVICE_REQUEST;
                break;

            case 0x760028:
                DPRINT1("FtDiskDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);
                ASSERT(FALSE);
                Status = STATUS_INVALID_DEVICE_REQUEST;
                break;

            default:
                DPRINT1("FtDiskDeviceControl: not supported %X (%p, %p)\n", ControlCode, DeviceObject, Irp);
                //ASSERT(FALSE);
                Status = STATUS_INVALID_DEVICE_REQUEST;
                break;
        }
    }

    switch (ControlCode)
    {
        case IOCTL_DISK_GET_DRIVE_GEOMETRY:
            DPRINT("FtDiskDeviceControl: IOCTL_DISK_GET_DRIVE_GEOMETRY\n");
            Status = FtpAllSystemsGo(Extension, Irp, TRUE, TRUE, TRUE);
            break;

        case IOCTL_DISK_IS_WRITABLE:
            DPRINT("FtDiskDeviceControl: IOCTL_DISK_IS_WRITABLE\n");
            if (Extension->IsReadOnlyPartition)
                Status = STATUS_MEDIA_WRITE_PROTECTED;
            else
                Status = FtpAllSystemsGo(Extension, Irp, TRUE, TRUE, TRUE);
            break;

        case IOCTL_DISK_GET_PARTITION_INFO_EX:
            DPRINT("FtDiskDeviceControl: IOCTL_DISK_GET_PARTITION_INFO_EX\n");
            Status = FtpAllSystemsGo(Extension, Irp, FALSE, TRUE, FALSE);
            break;

        case IOCTL_DISK_GET_PARTITION_INFO:
            DPRINT("FtDiskDeviceControl: IOCTL_DISK_GET_PARTITION_INFO\n");
            Status = FtpAllSystemsGo(Extension, Irp, FALSE, TRUE, FALSE);
            break;

        case IOCTL_DISK_GET_LENGTH_INFO:
            DPRINT("FtDiskDeviceControl: IOCTL_DISK_GET_LENGTH_INFO\n");
            Status = FtpAllSystemsGo(Extension, Irp, TRUE, TRUE, TRUE);
            break;

        case IOCTL_DISK_CHECK_VERIFY:
            DPRINT("FtDiskDeviceControl: IOCTL_DISK_CHECK_VERIFY\n");
            Status = FtpAllSystemsGo(Extension, Irp, TRUE, TRUE, TRUE);
            break;

        case IOCTL_STORAGE_GET_HOTPLUG_INFO:
            DPRINT("FtDiskDeviceControl: IOCTL_STORAGE_GET_HOTPLUG_INFO\n");
            Status = FtpAllSystemsGo(Extension, Irp, TRUE, TRUE, TRUE);
            break;

        case IOCTL_STORAGE_QUERY_PROPERTY:
            DPRINT("FtDiskDeviceControl: IOCTL_STORAGE_QUERY_PROPERTY\n");
            Status = FtpAllSystemsGo(Extension, Irp, TRUE, TRUE, TRUE);
            break;

        case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
        {
            DPRINT("FtDiskDeviceControl: IOCTL_MOUNTDEV_QUERY_UNIQUE_ID\n");

            Status = FtpAllSystemsGo(Extension, Irp, FALSE, TRUE, FALSE);
            if (Status == STATUS_PENDING)
                return Status;

            if (NT_SUCCESS(Status))
            {
                Status = FtpQueryUniqueId(Extension, Irp);
                ExReleaseRundownProtectionCacheAware(Extension->RundownCache);
            }

            Irp->IoStatus.Status = Status;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);

            return Status;
        }
        case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
        {
            DPRINT("FtDiskDeviceControl: IOCTL_MOUNTDEV_QUERY_DEVICE_NAME\n");

            Status = FtpAllSystemsGo(Extension, Irp, FALSE, FALSE, FALSE);
            if (Status == STATUS_PENDING)
                return Status;

            if (NT_SUCCESS(Status))
            {
                Status = FtpQueryDeviceName(Extension, Irp);
                ExReleaseRundownProtectionCacheAware(Extension->RundownCache);
            }

            Irp->IoStatus.Status = Status;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);

            return Status;
        }
        case IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME:
        {
            DPRINT("FtDiskDeviceControl: IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME\n");

            FtpAcquire(Extension->RootExtension);
            Status = FtpQuerySuggestedLinkName(Extension, Irp);
            FtpRelease(Extension->RootExtension);

            Irp->IoStatus.Status = Status;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);

            return Status;
        }
        case 0x4DC010: // IOCTL_MOUNTDEV_LINK_CREATED
        {
            DPRINT("FtDiskDeviceControl: IOCTL_MOUNTDEV_LINK_CREATED\n");
            Status = FtpAllSystemsGo(Extension, Irp, FALSE, TRUE, TRUE);
            if (Status == STATUS_PENDING)
                return Status;

            if (NT_SUCCESS(Status))
            {
                Status = FtpLinkCreated(Extension, Irp);
                ExReleaseRundownProtectionCacheAware(Extension->RundownCache);
            }

            Irp->IoStatus.Status = Status;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);

            return Status;
        }
        case 0x4D0010: // ?? IOCTL_MOUNTDEV_LINK_CREATED -- ??
            DPRINT("FtDiskDeviceControl: 0x4D0010\n");
            Status = FtpAllSystemsGo(Extension, Irp, TRUE, TRUE, TRUE);
            break;

        case IOCTL_MOUNTDEV_QUERY_STABLE_GUID:
        {
            DPRINT("FtDiskDeviceControl: IOCTL_MOUNTDEV_QUERY_STABLE_GUID\n");

            Status = FtpAllSystemsGo(Extension, Irp, FALSE, TRUE, FALSE);
            if (Status == STATUS_PENDING)
                return Status;

            if (NT_SUCCESS(Status))
            {
                Status = FtpQueryStableGuid(Extension, Irp);
                ExReleaseRundownProtectionCacheAware(Extension->RundownCache);
            }

            Irp->IoStatus.Status = Status;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);

            return Status;
        }
        case 0x4DC004: // ? error ? IOCTL_MOUNTDEV_UNIQUE_ID_CHANGE_NOTIFY 
        {
            FtpAcquire(Extension->RootExtension);
            Status = FtpUniqueIdChangeNotify(Extension, Irp);
            FtpRelease(Extension->RootExtension);

            if (Status != STATUS_PENDING)
            {
                Irp->IoStatus.Status = Status;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
            }

            return Status;
        }
        case IOCTL_VOLUME_GET_GPT_ATTRIBUTES:
        {
            DPRINT("FtDiskDeviceControl: IOCTL_VOLUME_GET_GPT_ATTRIBUTES\n");

            KeEnterCriticalRegion();
            FtpAcquire(Extension->RootExtension);

            Status = FtpGetGptAttributes(Extension, Irp);

            FtpRelease(Extension->RootExtension);
            KeLeaveCriticalRegion();

            Irp->IoStatus.Status = Status;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);

            return Status;
        }
        case IOCTL_VOLUME_ONLINE:
        {
            DPRINT("FtDiskDeviceControl: IOCTL_VOLUME_ONLINE\n");

            FtpAcquire(Extension->RootExtension);

            Status = FtpAllSystemsGo(Extension, Irp, FALSE, TRUE, FALSE);
            if (Status == STATUS_PENDING)
            {
                FtpRelease(Extension->RootExtension);
                return STATUS_PENDING;
            }

            if (!NT_SUCCESS(Status))
            {
                FtpRelease(Extension->RootExtension);
                Irp->IoStatus.Status = Status;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return Status;
            }

            Status = FtpCheckOfflineOwner(Extension, Irp);
            if (!NT_SUCCESS(Status))
            {
                ExReleaseRundownProtectionCacheAware(Extension->RundownCache);
                FtpRelease(Extension->RootExtension);
                Irp->IoStatus.Status = Status;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return Status;
            }

            if (Extension->FtVolume)
            {
                DPRINT1("FtDiskDeviceControl: FIXME\n");
                ASSERT(FALSE);
            }

            KeInitializeEvent(&Event, NotificationEvent, FALSE);
            ExReleaseRundownProtectionCacheAware(Extension->RundownCache);

            FtpZeroRefCallback(Extension, FtpVolumeOnlineCallback, &Event);
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

            FtpRelease(Extension->RootExtension);

            Irp->IoStatus.Status = STATUS_SUCCESS;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);

            return STATUS_SUCCESS;
        }
        case FT_BALANCED_READ_MODE:
            DPRINT("FtDiskDeviceControl: FT_BALANCED_READ_MODE\n");
            Status = FtpAllSystemsGo(Extension, Irp, TRUE, TRUE, TRUE);
            break;

        default:
            DPRINT1("FtDiskDeviceControl: not supported %X (%p, %p)\n", ControlCode, DeviceObject, Irp);
            //ASSERT(FALSE);
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    if (Status == STATUS_PENDING)
        return Status;

    if (!NT_SUCCESS(Status))
    {
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Status;
    }

    if (Extension->PartitionPdo)
    {
        if (ControlCode == 0x67C194)
        {
            DPRINT("FtDiskDeviceControl: FIXME\n");
            ASSERT(FALSE);
        }

        if (ControlCode == IOCTL_DISK_UPDATE_PROPERTIES ||
            ControlCode == IOCTL_DISK_GROW_PARTITION)
        {
            DPRINT("FtDiskDeviceControl: FIXME\n");
            ASSERT(FALSE);
        }

        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, FtpRefCountCompletionRoutine, Extension, TRUE, TRUE, TRUE);
        IoMarkIrpPending(Irp);

        IoCallDriver(Extension->PartitionPdo, Irp);

        return STATUS_PENDING;
    }

    DPRINT("FtDiskDeviceControl: FIXME\n");
    ASSERT(Extension->FtVolume);
    ASSERT(FALSE);


    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
FtDiskInternalDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PVOLUME_EXTENSION Extension;
    PROOT_EXTENSION RootExtension;
    PIO_STACK_LOCATION IoStack;
    ULONG ControlCode;
    NTSTATUS Status;

    DPRINT("FtDiskInternalDeviceControl: %p, %p\n", DeviceObject, Irp);

    Extension = DeviceObject->DeviceExtension;
    RootExtension = Extension->RootExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    Irp->IoStatus.Information = 0;

    FtpAcquire(RootExtension);

    if (Extension->DeviceExtensionType != 0)
    {
        DPRINT1("FtDiskInternalDeviceControl: STATUS_INVALID_PARAMETER\n");
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    ControlCode = IoStack->Parameters.DeviceIoControl.IoControlCode;

    switch (ControlCode)
    {
        case 0x760000:
            Status = FtpPartitionArrived(RootExtension, Irp);
            break;

        case 0x760004:
            DPRINT1("FtDiskInternalDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);
            ASSERT(FALSE);
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;

        case 0x760008:
            DPRINT1("FtDiskInternalDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);
            ASSERT(FALSE);
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;

        case 0x76000C:
            DPRINT1("FtDiskInternalDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);
            ASSERT(FALSE);
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;

        case 0x760018:
            DPRINT1("FtDiskInternalDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);
            ASSERT(FALSE);
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;

        case 0x76001C:
            DPRINT1("FtDiskInternalDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);
            ASSERT(FALSE);
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;

        case 0x760020:
            DPRINT1("FtDiskInternalDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);
            ASSERT(FALSE);
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;

        case 0x760024:
            ASSERT(FALSE);
            Status = 0;//FtpPmWmiCounterLibContext(RootExtension, Irp);
            break;

        case 0x760028:
            DPRINT1("FtDiskInternalDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);
            ASSERT(FALSE);
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;

        default:
            DPRINT1("FtDiskInternalDeviceControl: %p, %p, %X\n", DeviceObject, Irp, ControlCode);
            ASSERT(FALSE);
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

Exit:

    FtpRelease(RootExtension);
    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, 0);
    return Status;
}

NTSTATUS
NTAPI
FtDiskShutdownFlush(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PROOT_EXTENSION RootExtension;
    PVOLUME_EXTENSION Extension;
    PVOLUME_EXTENSION* VolumeArray;
    PIO_STACK_LOCATION IoStack;
    PLIST_ENTRY Head;
    PLIST_ENTRY Entry;
    ULONG Count = 0;
    ULONG Size;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("FtDiskShutdownFlush: %p, %p\n", DeviceObject, Irp);

    Extension = DeviceObject->DeviceExtension;

    if (Extension->DeviceExtensionType)
    {
        Status = FtpAllSystemsGo(Extension, Irp, FALSE, TRUE, TRUE);
        if (Status == STATUS_PENDING)
            return STATUS_PENDING;

        if (!NT_SUCCESS(Status))
        {
            Irp->IoStatus.Information = 0;
            Irp->IoStatus.Status = Status;
            IoCompleteRequest(Irp, 0);
            return Status;
        }

        if (!Extension->PartitionPdo)
        {
            ASSERT(Extension->FtVolume);

            IoMarkIrpPending(Irp);

            IoStack = IoGetCurrentIrpStackLocation(Irp);
            IoStack->DeviceObject = DeviceObject;

            DPRINT1("FtDiskShutdownFlush: FIXME\n");
            ASSERT(FALSE);

            return STATUS_PENDING;
        }

        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, FtpRefCountCompletionRoutine, Extension, TRUE, TRUE, TRUE);
        IoMarkIrpPending(Irp);

        IoCallDriver(Extension->PartitionPdo, Irp);

        return STATUS_PENDING;
    }

    RootExtension = DeviceObject->DeviceExtension;

    FtpAcquire(RootExtension);

    Size = (RootExtension->VolumeCounter * sizeof(PVOLUME_EXTENSION));

    VolumeArray = ExAllocatePoolWithTag(PagedPool, Size, 'tFcS');
    if (!VolumeArray)
    {
        Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        IoCompleteRequest(Irp, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Head = &RootExtension->VolumeList;
    Entry = Head->Flink;

    if (Entry != Head)
    {
        while (TRUE)
        {
            Extension = CONTAINING_RECORD(Entry, VOLUME_EXTENSION, Link);

            KeWaitForSingleObject(&Extension->Semaphore, Executive, KernelMode, FALSE, NULL);
            KeWaitForSingleObject(&Extension->ZeroRefSemaphore, Executive, KernelMode, FALSE, NULL);

            Status = FtpAllSystemsGo(Extension, NULL, FALSE, TRUE, TRUE);

            KeReleaseSemaphore(&Extension->ZeroRefSemaphore, 0, 1, FALSE);
            KeReleaseSemaphore(&Extension->Semaphore, 0, 1, FALSE);

            if (NT_SUCCESS(Status))
            {
                if (Extension->FtVolume)
                {
                    VolumeArray[Count++] = Extension;
                }
                else
                {
                    ExReleaseRundownProtectionCacheAware(Extension->RundownCache);
                }
            }

            Entry = Entry->Flink;

            if (Entry == Head)
                break;
        }
    }

    FtpRelease(RootExtension);

    if (!Count)
    {
        ExFreePoolWithTag(VolumeArray, 'tFcS');

        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, 0);

        return STATUS_SUCCESS;
    }

    DPRINT1("FtDiskShutdownFlush: FIXME\n");
    ASSERT(FALSE);

    return STATUS_PENDING;
}

NTSTATUS
NTAPI
FtDiskCleanup(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PROOT_EXTENSION RootExtension;
    PVOLUME_EXTENSION VolumeExtension;
    PIO_STACK_LOCATION IoStack;
    PIO_STACK_LOCATION CancelIrpStack;
    ULONG DeviceExtensionType;
    PLIST_ENTRY Entry;
    PIRP CancelIrp;
    KIRQL OldIrql;

    DPRINT("FtDiskCleanup: %p, %p\n", DeviceObject, Irp);

    RootExtension = DeviceObject->DeviceExtension;
    VolumeExtension = DeviceObject->DeviceExtension;
    DeviceExtensionType = VolumeExtension->DeviceExtensionType;

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    if (DeviceExtensionType == 1) // DEVICE_EXTENSION_VOLUME
    {
        IoCompleteRequest(Irp, 0);
        return STATUS_SUCCESS;
    }

    ASSERT(RootExtension->DeviceExtensionType == 0);

    IoAcquireCancelSpinLock(&OldIrql);

    while (TRUE)
    {
        for (Entry = RootExtension->ChangeNotifyIrpList.Flink;
             Entry != &RootExtension->ChangeNotifyIrpList;
             Entry = Entry->Flink)
        {
            CancelIrp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);
            CancelIrpStack = IoGetCurrentIrpStackLocation(CancelIrp);

            if (CancelIrpStack->FileObject == IoStack->FileObject)
                break;
        }

        if (Entry == &RootExtension->ChangeNotifyIrpList)
            break;

        CancelIrp->Cancel = TRUE;
        CancelIrp->CancelIrql = OldIrql;
        CancelIrp->CancelRoutine = NULL;

        FtpCancelRoutine(DeviceObject, CancelIrp);
        IoAcquireCancelSpinLock(&OldIrql);
    }

    IoReleaseCancelSpinLock(OldIrql);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, 0);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
FtDiskPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
FtWmi(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* PNP */

static
NTSTATUS
FASTCALL
FtpPnpPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;
    PDEVICE_CAPABILITIES Capabilities;
    PIO_STACK_LOCATION IoStack;
    PDEVICE_RELATIONS DeviceRelation;
    KEVENT Event;
    BOOLEAN IsStarted;
    NTSTATUS Status;

    DPRINT("FtpPnpPdo: %p, %p\n", DeviceObject, Irp);

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
            DPRINT1("FtpPnpPdo: Unknown PNP IRP_MN_ (%X)\n", IoStack->MinorFunction);
            break;
    }
  #endif

    switch (IoStack->MinorFunction)
    {
        case IRP_MN_START_DEVICE:
        {
            FtpAcquire(VolumeExtension->RootExtension);

            KeInitializeEvent(&Event, NotificationEvent, FALSE);

            FtpZeroRefCallback(VolumeExtension, FtpStartCallback, &Event);
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

            IsStarted = FALSE;

            if (VolumeExtension->RootExtension->IsBootReinitialized)
            {
                ULONG PropertyBuffer;
                ULONG ResultLength;

                Status = IoGetDeviceProperty(VolumeExtension->SelfDeviceObject,
                                             DevicePropertyInstallState,
                                             sizeof(PropertyBuffer),
                                             &PropertyBuffer,
                                             &ResultLength);
                if (NT_SUCCESS(Status))
                {
                    if (!PropertyBuffer)
                    {
                        DPRINT1("FtpPnpPdo: FIXME\n");
                        ASSERT(FALSE);
                    }
                    else
                    {
                        Status = STATUS_UNSUCCESSFUL;
                    }
                }

                IsStarted = TRUE;
            }
            else
            {
                if (!VolumeExtension->IsEmptyVolume && !VolumeExtension->IsHidenPartition)
                {
                    Status = IoRegisterDeviceInterface(VolumeExtension->SelfDeviceObject,
                                                       &MOUNTDEV_MOUNTED_DEVICE_GUID,
                                                       NULL,
                                                       &VolumeExtension->SymbolicLinkName);
                }
                else
                {
                    IsStarted = TRUE;
                    Status = STATUS_UNSUCCESSFUL;
                }
            }

            if (NT_SUCCESS(Status))
            {
                KeInitializeEvent(&Event, NotificationEvent, FALSE);

                FtpZeroRefCallback(VolumeExtension, FtpVolumeOfflineCallback, &Event);
                KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

                Status = IoSetDeviceInterfaceState(&VolumeExtension->SymbolicLinkName, TRUE);
            }

            if (!NT_SUCCESS(Status))
            {
                if (VolumeExtension->SymbolicLinkName.Buffer)
                {
                    ExFreePool(VolumeExtension->SymbolicLinkName.Buffer);
                    VolumeExtension->SymbolicLinkName.Buffer = NULL;
                }

                KeInitializeEvent(&Event, NotificationEvent, FALSE);

                FtpZeroRefCallback(VolumeExtension, FtpVolumeOnlineCallback, &Event);
                KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            }

            if (!VolumeExtension->IsHidenPartition)
            {
                DPRINT("FtpPnpPdo: FIXME FtRegisterDevice()\n");
                //ASSERT(FALSE);
                //FtRegisterDevice(DeviceObject);
            }

            FtpRelease(VolumeExtension->RootExtension);

            if (IsStarted)
                Status = STATUS_SUCCESS;

            break;
        }
        case IRP_MN_QUERY_REMOVE_DEVICE:
            DPRINT1("FtpPnpPdo: FIXME\n");
            ASSERT(FALSE);
            break;

        case IRP_MN_REMOVE_DEVICE:
            DPRINT1("FtpPnpPdo: FIXME\n");
            ASSERT(FALSE);
            break;

        case IRP_MN_CANCEL_REMOVE_DEVICE:
            DPRINT1("FtpPnpPdo: FIXME\n");
            ASSERT(FALSE);
            break;

        case IRP_MN_STOP_DEVICE:
            DPRINT1("FtpPnpPdo: FIXME\n");
            ASSERT(FALSE);
            break;

        case IRP_MN_QUERY_STOP_DEVICE: 
            DPRINT1("FtpPnpPdo: FIXME\n");
            ASSERT(FALSE);
            break;

        case IRP_MN_CANCEL_STOP_DEVICE:
        case IRP_MN_QUERY_RESOURCES:
        case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
            Status = STATUS_SUCCESS;
            break;

        case IRP_MN_QUERY_DEVICE_RELATIONS:
        {
            if (IoStack->Parameters.QueryDeviceRelations.Type == TargetDeviceRelation)
            {
                DeviceRelation = ExAllocatePoolWithTag(PagedPool, sizeof(DEVICE_RELATIONS), 'tFcS');

                if (!DeviceRelation)
                {
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                }
                else
                {
                    ObReferenceObject(DeviceObject);

                    DeviceRelation->Count = 1;
                    DeviceRelation->Objects[0] = DeviceObject;

                    Irp->IoStatus.Information = (ULONG_PTR)DeviceRelation;
                    Status = STATUS_SUCCESS;
                }
            }
            else
            {
                Status = STATUS_NOT_SUPPORTED;
            }

            break;
        }
        case IRP_MN_QUERY_INTERFACE:
            DPRINT1("FtpPnpPdo: FIXME\n");
            ASSERT(FALSE);
            break;

        case IRP_MN_QUERY_CAPABILITIES:
        {
            Capabilities = IoStack->Parameters.DeviceCapabilities.Capabilities;

            Capabilities->SilentInstall = 1;
            Capabilities->RawDeviceOK = 1;
            Capabilities->SurpriseRemovalOK = 1;

            Capabilities->Address = VolumeExtension->VolumeNumber;

            Status = STATUS_SUCCESS;
            break;
        }
        case IRP_MN_QUERY_DEVICE_TEXT:
            Status = STATUS_NOT_SUPPORTED;
            break;

        case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
            Status = STATUS_NOT_SUPPORTED;
            break;

        case IRP_MN_READ_CONFIG:
            DPRINT1("FtpPnpPdo: FIXME\n");
            ASSERT(FALSE);
            break;

        case IRP_MN_WRITE_CONFIG:
            DPRINT1("FtpPnpPdo: FIXME\n");
            ASSERT(FALSE);
            break;

        case IRP_MN_EJECT:
            DPRINT1("FtpPnpPdo: FIXME\n");
            ASSERT(FALSE);
            break;

        case IRP_MN_SET_LOCK:
            DPRINT1("FtpPnpPdo: FIXME\n");
            ASSERT(FALSE);
            break;

        case IRP_MN_QUERY_ID:
            Status = FtpQueryId(VolumeExtension, Irp);
            break;

        case IRP_MN_QUERY_PNP_DEVICE_STATE:
        {
            Irp->IoStatus.Information = PNP_DEVICE_DONT_DISPLAY_IN_UI;

            if (VolumeExtension->SelfDeviceObject->Flags & DO_SYSTEM_BOOT_PARTITION)
            {
                Irp->IoStatus.Information |= PNP_DEVICE_NOT_DISABLEABLE;
            }

            Status = STATUS_SUCCESS;
            break;
        }
        case IRP_MN_QUERY_BUS_INFORMATION:
            Status = STATUS_NOT_SUPPORTED;
            break;

        case IRP_MN_DEVICE_USAGE_NOTIFICATION:
            DPRINT1("FtpPnpPdo: FIXME\n");
            ASSERT(FALSE);
            break;

        case IRP_MN_SURPRISE_REMOVAL:
            DPRINT1("FtpPnpPdo: FIXME\n");
            ASSERT(FALSE);
            break;

        case IRP_MN_QUERY_LEGACY_BUS_INFORMATION:
            Status = STATUS_NOT_SUPPORTED;
            break;

        default:
            DPRINT1("FtDiskPdoPnp: Unknown PNP IRP_MN - %X\n", IoStack->MinorFunction);
            ASSERT(FALSE);
            break;
    }

    if (Status != STATUS_NOT_SUPPORTED)
        Irp->IoStatus.Status = Status;
    else
        Status = Irp->IoStatus.Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS
NTAPI
FtpQueryRootId(
    _In_ PROOT_EXTENSION RootExtension,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    UNICODE_STRING IdString;
    ULONG IdType;
    PWSTR RootId;

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    IdType = IoStack->Parameters.QueryId.IdType;

    DPRINT("FtpQueryRootId: %p, %p, IdType %X\n", RootExtension, Irp, IdType);

    if (IdType == BusQueryDeviceID)
    {
        RtlInitUnicodeString(&IdString, L"ROOT\\FTDISK");
    }
    else if (IdType == BusQueryHardwareIDs)
    {
        RtlInitUnicodeString(&IdString, L"ROOT\\FTDISK");
    }
    else if (IdType == BusQueryInstanceID)
    {
        RtlInitUnicodeString(&IdString, L"0000");
    }
    else
    {
        DPRINT("FtpQueryRootId: STATUS_NOT_SUPPORTED\n");
        return STATUS_NOT_SUPPORTED;
    }

    RootId = ExAllocatePoolWithTag(PagedPool, (IdString.Length + 2 * sizeof(WCHAR)), 'tFcS');
    if (!RootId)
    {
        DPRINT1("FtpQueryRootId: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(RootId, IdString.Buffer, IdString.Length);

    RootId[IdString.Length / 2] = 0;
    RootId[(IdString.Length / 2) + 1] = 0;

    Irp->IoStatus.Information = (ULONG_PTR)RootId;
    DPRINT("FtpQueryRootId: %p, %p, '%S'\n", RootExtension, Irp, Irp->IoStatus.Information);

    return STATUS_SUCCESS;
}

static
NTSTATUS
FASTCALL
FtpPnpFdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_OBJECT AttachedToDevice;
    PROOT_EXTENSION RootExtension;
    PVOLUME_EXTENSION VolumeExtension;
    PIO_STACK_LOCATION IoStack;
    PDEVICE_RELATIONS DeviceRelation;
    PDEVICE_CAPABILITIES Capabilities;
    PLIST_ENTRY Entry;
    KEVENT Event;
    ULONG size;
    ULONG ix;
    NTSTATUS Status = STATUS_NOT_SUPPORTED;

    DPRINT("FtpPnpFdo: DeviceObject %p, Irp %p\n", DeviceObject, Irp);

    RootExtension = DeviceObject->DeviceExtension;
    AttachedToDevice = RootExtension->AttachedToDevice;

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

    switch (IoStack->MinorFunction)
    {
        case IRP_MN_START_DEVICE:
        case IRP_MN_CANCEL_REMOVE_DEVICE:
        case IRP_MN_CANCEL_STOP_DEVICE:
        case IRP_MN_QUERY_RESOURCES:
        case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
        {
            Irp->IoStatus.Status = STATUS_SUCCESS;
            IoSkipCurrentIrpStackLocation(Irp);
            return IoCallDriver(AttachedToDevice, Irp);
        }
        case IRP_MN_QUERY_REMOVE_DEVICE:
        case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        {
            DPRINT("FtpPnpFdo: STATUS_INVALID_DEVICE_REQUEST\n");
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
        case IRP_MN_REMOVE_DEVICE:
        case IRP_MN_SURPRISE_REMOVAL:
        {
            DPRINT1("FtpPnpFdo: FIXME\n");
            ASSERT(FALSE);
            break;
        }
        case IRP_MN_QUERY_DEVICE_RELATIONS:
        {
            if (IoStack->Parameters.QueryDeviceRelations.Type != BusRelations)
            {
                IoSkipCurrentIrpStackLocation(Irp);
                return IoCallDriver(AttachedToDevice, Irp);
            }

            FtpAcquire(RootExtension);

            ix = 0;

            for (Entry = RootExtension->VolumeList.Flink;
                 Entry != &RootExtension->VolumeList;
                 Entry = Entry->Flink)
            {
                ix++;
            }

            size = (sizeof(DEVICE_RELATIONS) - sizeof(PDEVICE_OBJECT));
            size += (ix * sizeof(PDEVICE_OBJECT));

            DeviceRelation = ExAllocatePoolWithTag(PagedPool, size, 'tFcS');
            if (!DeviceRelation)
            {
                FtpRelease(RootExtension);

                Irp->IoStatus.Information = 0;
                Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;

                IoCompleteRequest(Irp, 0);

                return STATUS_INSUFFICIENT_RESOURCES;
            }

            DeviceRelation->Count = ix;
            ix = 0;

            for (Entry = RootExtension->VolumeList.Flink;
                 Entry != &RootExtension->VolumeList;
                 Entry = Entry->Flink)
            {
                VolumeExtension = CONTAINING_RECORD(Entry, VOLUME_EXTENSION, Link);

                DeviceRelation->Objects[ix] = VolumeExtension->SelfDeviceObject;
                ObReferenceObject(DeviceRelation->Objects[ix]);

                ix++;
            }

            while (!IsListEmpty(&RootExtension->EmptyVolumesList))
            {
                ASSERT(FALSE);
                //Entry = RemoveHeadList(&RootExtension->EmptyVolumesList);
                //VolumeExtension = CONTAINING_RECORD(Entry, VOLUME_EXTENSION, Link);
                //VolumeExtension->VolExt31 = 1;
            }

            FtpRelease(RootExtension);

            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = (ULONG_PTR)DeviceRelation;

            IoSkipCurrentIrpStackLocation(Irp);

            return IoCallDriver(AttachedToDevice, Irp);
        }
        case IRP_MN_QUERY_CAPABILITIES:
        {
              KeInitializeEvent(&Event, NotificationEvent, FALSE);

              IoCopyCurrentIrpStackLocationToNext(Irp);
              IoSetCompletionRoutine(Irp, FtpSignalCompletion, &Event, TRUE, TRUE, TRUE);

              IoCallDriver(AttachedToDevice, Irp);

              KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

              Capabilities = IoStack->Parameters.DeviceCapabilities.Capabilities;

              Capabilities->RawDeviceOK = 1;
              Capabilities->SilentInstall = 1;

              return Irp->IoStatus.Status;
        }
        case IRP_MN_QUERY_ID:
        {
            Status = FtpQueryRootId(RootExtension, Irp);
            if (NT_SUCCESS(Status))
            {
                Irp->IoStatus.Status = Status;
                IoSkipCurrentIrpStackLocation(Irp);

                Status = IoCallDriver(AttachedToDevice, Irp);
                DPRINT("FtpPnpFdo: Status (%X)\n", Status);
                return Status;
            }

            if (Status == STATUS_NOT_SUPPORTED)
            {
                IoSkipCurrentIrpStackLocation(Irp);
                Status = IoCallDriver(AttachedToDevice, Irp);
                DPRINT("FtpPnpFdo: Status (%X)\n", Status);
                return Status;
            }

            break;
        }
        case IRP_MN_QUERY_PNP_DEVICE_STATE:
        {
            KeInitializeEvent(&Event, NotificationEvent, FALSE);

            IoCopyCurrentIrpStackLocationToNext(Irp);
            IoSetCompletionRoutine(Irp, FtpSignalCompletion, &Event, TRUE, TRUE, TRUE);

            IoCallDriver(AttachedToDevice, Irp);
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

            Status = Irp->IoStatus.Status;

            /* Do not show device in device manager. */
            if (!NT_SUCCESS(Status))
            {
                Status = STATUS_SUCCESS;
                Irp->IoStatus.Information = (PNP_DEVICE_DONT_DISPLAY_IN_UI | PNP_DEVICE_NOT_DISABLEABLE);
            }
            else
            {
                Irp->IoStatus.Information |= (PNP_DEVICE_DONT_DISPLAY_IN_UI | PNP_DEVICE_NOT_DISABLEABLE);
            }

            break;
        }
        case IRP_MN_QUERY_STOP_DEVICE:
        {
            IoSkipCurrentIrpStackLocation(Irp);
            return IoCallDriver(AttachedToDevice, Irp);
        }
        default:
        {
            DPRINT1("FtpPnpFdo: Unknown PNP IRP_MN_ (%X)\n", IoStack->MinorFunction);
            ASSERT(FALSE);
            IoSkipCurrentIrpStackLocation(Irp);
            return IoCallDriver(AttachedToDevice, Irp);
        }
    }

    if (Status != STATUS_NOT_SUPPORTED)
        Irp->IoStatus.Status = Status;
    else
        Status = Irp->IoStatus.Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    DPRINT("FtpPnpFdo: Status (%X)\n", Status);
    return Status;
}

NTSTATUS
NTAPI
FtDiskPnp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PROOT_EXTENSION Extension;
    NTSTATUS Status;

    DPRINT("FtDiskPnp: %p, %p\n", DeviceObject, Irp);

    Extension = DeviceObject->DeviceExtension;

    if (Extension->DeviceExtensionType == 0) // ROOT
    {
        Status = FtpPnpFdo(DeviceObject, Irp);
        DPRINT("FtDiskPnp: %p, %p, %X\n", DeviceObject, Irp, Status);
        return Status;
    }

    if (Extension->DeviceExtensionType == 1) // VOLUME
    {
        Status = FtpPnpPdo(DeviceObject, Irp);
        DPRINT("FtDiskPnp: %p, %p, %X\n", DeviceObject, Irp, Status);
        return Status;
    }

    DPRINT("FtDiskPnp: %p, %p, DeviceExtensionType %X\n", DeviceObject, Irp, Extension->DeviceExtensionType);

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;

    IoCompleteRequest(Irp, 0);

    return STATUS_INVALID_DEVICE_REQUEST;
}

/* REINITIALIZE DRIVER ROUTINES *********************************************/

NTSTATUS
NTAPI
FtpQuerySystemVolumeNameQueryRoutine(
    _In_ PWSTR ValueName,
    _In_ ULONG ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueLength,
    _In_ PVOID Context,
    _In_ PVOID EntryContext)
{
    PUNICODE_STRING SystemPartition = Context;
    UNICODE_STRING string;
    USHORT Size;

    if (ValueType != REG_SZ)
        return STATUS_SUCCESS;

    RtlInitUnicodeString(&string, ValueData);
    Size = string.Length;

    SystemPartition->Length = Size;
    SystemPartition->MaximumLength = (Size + sizeof(WCHAR));

    SystemPartition->Buffer = ExAllocatePoolWithTag(PagedPool, SystemPartition->MaximumLength, 'tFcS');
    if (!SystemPartition->Buffer)
        return STATUS_SUCCESS;

    RtlCopyMemory(SystemPartition->Buffer, ValueData, SystemPartition->Length);

    SystemPartition->Buffer[SystemPartition->Length / sizeof(WCHAR)] = 0;

    return STATUS_SUCCESS;
}

VOID
NTAPI
FtpDriverReinitialization(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PVOID Context,
    _In_ ULONG Count)
{
    PROOT_EXTENSION RootExtension = Context;
    PVOLUME_EXTENSION VolumeExtension;
    RTL_QUERY_REGISTRY_TABLE QueryTable[2];
    UNICODE_STRING SystemPartition;
    UNICODE_STRING Name;
    WCHAR bufferString[0x64]; // 100
    PLIST_ENTRY Entry;

    DPRINT("FtpDriverReinitialization: %p, %p, %X\n", DriverObject, Context, Count);

    RtlZeroMemory(QueryTable, sizeof(QueryTable));

    QueryTable[0].QueryRoutine = FtpQuerySystemVolumeNameQueryRoutine;
    QueryTable[0].Flags = 4;
    QueryTable[0].Name = L"SystemPartition";

    SystemPartition.Buffer = NULL;
    RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\System\\Setup", QueryTable, &SystemPartition, NULL);

    FtpAcquire(RootExtension);

    Entry = RootExtension->VolumeList.Flink;

    while (Entry != &RootExtension->VolumeList)
    {
        VolumeExtension = CONTAINING_RECORD(Entry, VOLUME_EXTENSION, Link);

        if (VolumeExtension->IsSystemPartition)
        {
            swprintf(bufferString, L"\\Device\\HarddiskVolume%d", VolumeExtension->VolumeNumber);
            RtlInitUnicodeString(&Name, bufferString);

            if (SystemPartition.Buffer && RtlEqualUnicodeString(&Name, &SystemPartition, TRUE))
            {
                DPRINT1("FtpDriverReinitialization: FIXME\n");
                ASSERT(FALSE);
            }

            DPRINT1("FtpDriverReinitialization: FIXME FtpApplyESPProtection()\n");
        }

        Entry = Entry->Flink;
    }

    RootExtension->IsReinitialized = TRUE;

    FtpRelease(RootExtension);

    if (SystemPartition.Buffer)
        ExFreePool(SystemPartition.Buffer);
}

VOID
NTAPI
FtpBootDriverReinitialization(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PVOID Context,
    _In_ ULONG Count)
{
    PROOT_EXTENSION RootExtension = Context;
    PVOLUME_EXTENSION VolumeExtension;
    PLIST_ENTRY Entry;
    BOOTDISK_INFORMATION BootDiskInfo;
    BOOLEAN IsBootAndSystem = TRUE;
    BOOLEAN IsNoBootInfo = FALSE;
    BOOLEAN IsNoSystemInfo = FALSE;
    NTSTATUS Status;

    DPRINT("FtpBootDriverReinitialization: %p, %p, %X\n", DriverObject, Context, Count);

    Status = IoGetBootDiskInformation(&BootDiskInfo, sizeof(BootDiskInfo));
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("FtpBootDriverReinitialization: Status %X\n", Status);
        return;
    }

    if (BootDiskInfo.BootDeviceSignature != BootDiskInfo.SystemDeviceSignature)
    {
        IsBootAndSystem = FALSE;
    }

    if (BootDiskInfo.BootPartitionOffset != BootDiskInfo.SystemPartitionOffset)
    {
        IsBootAndSystem = FALSE;
    }

    if (!BootDiskInfo.BootDeviceSignature || !BootDiskInfo.BootPartitionOffset)
    {
        IsNoSystemInfo = TRUE;
    }

    if (!BootDiskInfo.SystemDeviceSignature || !BootDiskInfo.SystemPartitionOffset)
    {
        IsNoBootInfo = TRUE;
    }

    if (IsNoSystemInfo && IsNoBootInfo)
        return;

    FtpAcquire(RootExtension);
    Entry = RootExtension->VolumeList.Flink;

    while (Entry != &RootExtension->VolumeList)
    {
        VolumeExtension = CONTAINING_RECORD(Entry, VOLUME_EXTENSION, Link);

        if (VolumeExtension->FtVolume)
        {
            DPRINT1("FtpBootDriverReinitialization: FIXME\n");
            ASSERT(FALSE);if(IsBootAndSystem){;}
        }

        Entry = Entry->Flink;
    }

    RootExtension->IsBootReinitialized = TRUE;
    FtpRelease(RootExtension);
}

/* INIT DRIVER ROUTINES *****************************************************/

NTSTATUS
NTAPI
FtDiskAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT VolControlRootPdo,
    _In_ PUNICODE_STRING RegistryPath)
{
    PROOT_EXTENSION RootExtension;
    PDEVICE_OBJECT RootFdo;
    UNICODE_STRING NameString;
    UNICODE_STRING SymbolicLinkName;
    USHORT Size;
    NTSTATUS Status;

    DPRINT("FtDiskAddDevice: %p, %p, '%wZ'\n", DriverObject, VolControlRootPdo, RegistryPath);

    RtlInitUnicodeString(&NameString, L"\\Device\\FtControl");

    Status = IoCreateDevice(DriverObject,
                            sizeof(*RootExtension),
                            &NameString,
                            FILE_DEVICE_NETWORK,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &RootFdo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("FtDiskAddDevice: Status %X\n", Status);
        return Status;
    }

    RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\FtControl");
    IoCreateSymbolicLink(&SymbolicLinkName, &NameString);

    RootExtension = RootFdo->DeviceExtension;
    RtlZeroMemory(RootExtension, sizeof(*RootExtension));

    DPRINT("FtDiskAddDevice: RootFdo %p, %p\n", RootFdo, RootExtension);

    RootExtension->DriverObject = DriverObject;
    RootExtension->SelfDeviceObject = RootFdo;
    RootExtension->RootExtension = RootExtension;

    RootExtension->DeviceExtensionType = 0; // Root ext.

    KeInitializeSpinLock(&RootExtension->SpinLock);

    RootExtension->AttachedToDevice = IoAttachDeviceToDeviceStack(RootFdo, VolControlRootPdo);
    if (!RootExtension->AttachedToDevice)
    {
        DPRINT1("FtDiskAddDevice: AttachedToDevice is NULL!\n");
        IoDeleteSymbolicLink(&SymbolicLinkName);
        IoDeleteDevice(RootFdo);
        return STATUS_NO_SUCH_DEVICE;
    }

    DPRINT("FtDiskAddDevice: RootPdo %p, RootFdo attached to %p\n", VolControlRootPdo, RootExtension->AttachedToDevice);

    RootExtension->VolControlRootPdo = VolControlRootPdo;

    InitializeListHead(&RootExtension->VolumeList);
    InitializeListHead(&RootExtension->EmptyVolumesList);

    RootExtension->VolumeCounter = 1;

    RootExtension->LogicalDiskInfoSet = ExAllocatePoolWithTag(NonPagedPool, sizeof(*RootExtension->LogicalDiskInfoSet), 'tFcS');
    if (!RootExtension->LogicalDiskInfoSet)
    {
        DPRINT1("FtDiskAddDevice: STATUS_INSUFFICIENT_RESOURCES\n");
        IoDeleteSymbolicLink(&SymbolicLinkName);
        IoDetachDevice(RootExtension->AttachedToDevice);
        IoDeleteDevice(RootFdo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(RootExtension->LogicalDiskInfoSet, sizeof(*RootExtension->LogicalDiskInfoSet));

    InitializeListHead(&RootExtension->WorkerQueue);
    InitializeListHead(&RootExtension->ChangeNotifyIrpList);
    KeInitializeSemaphore(&RootExtension->RootSemaphore, 1, 1);

    Size = (RegistryPath->Length + sizeof(WCHAR));
    RootExtension->RegistryPath.MaximumLength = Size;

    RootExtension->RegistryPath.Buffer = ExAllocatePoolWithTag(PagedPool, Size, 'tFcS');
    if (!RootExtension->RegistryPath.Buffer)
    {
        DPRINT1("FtDiskAddDevice: STATUS_INSUFFICIENT_RESOURCES\n");

        if (RootExtension->LogicalDiskInfoSet)
            ExFreePoolWithTag(RootExtension->LogicalDiskInfoSet, 'tFcS');

        IoDeleteSymbolicLink(&SymbolicLinkName);
        IoDetachDevice(RootExtension->AttachedToDevice);
        IoDeleteDevice(RootFdo);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyUnicodeString(&RootExtension->RegistryPath, RegistryPath);

    Status = IoRegisterShutdownNotification(RootFdo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("FtDiskAddDevice: Status %X\n", Status);

        ExFreePoolWithTag(RootExtension->RegistryPath.Buffer, 'tFcS');

        if (RootExtension->LogicalDiskInfoSet)
            ExFreePoolWithTag(RootExtension->LogicalDiskInfoSet, 'tFcS');

        IoDeleteSymbolicLink(&SymbolicLinkName);
        IoDetachDevice(RootExtension->AttachedToDevice);
        IoDeleteDevice(RootFdo);

        return Status;
    }

    RootFdo->Flags &= ~DO_DEVICE_INITIALIZING;

    DPRINT("FtDiskAddDevice: return STATUS_SUCCESS\n");
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    PDEVICE_OBJECT VolControlRootPdo = NULL;
    PDEVICE_OBJECT AttachedToDevice;
    PROOT_EXTENSION RootExtension;
    NTSTATUS Status;

    DPRINT("DriverEntry: %p, '%wZ'\n", DriverObject, RegistryPath);

    DriverObject->DriverUnload = FtDiskUnload;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = FtDiskCreate;
    DriverObject->MajorFunction[IRP_MJ_READ] = FtDiskReadWrite;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = FtDiskReadWrite;
    DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = FtDiskShutdownFlush;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FtDiskDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = FtDiskInternalDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = FtDiskShutdownFlush;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = FtDiskCleanup;
    DriverObject->MajorFunction[IRP_MJ_POWER] = FtDiskPower;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = FtWmi;
    DriverObject->MajorFunction[IRP_MJ_PNP] = FtDiskPnp;

    ObReferenceObject(DriverObject);

    Status = IoReportDetectedDevice(DriverObject, InterfaceTypeUndefined, -1, -1, NULL, NULL, TRUE, &VolControlRootPdo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("DriverEntry: Status %X\n", Status);
        return Status;
    }

    Status = FtDiskAddDevice(DriverObject, VolControlRootPdo, RegistryPath);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("DriverEntry: Status %X\n", Status);
        return Status;
    }

    AttachedToDevice = IoGetAttachedDeviceReference(VolControlRootPdo);
    ObDereferenceObject(AttachedToDevice);

    RootExtension = AttachedToDevice->DeviceExtension;

    Status = IoRegisterDeviceInterface(RootExtension->VolControlRootPdo,
                                       &VOLMGR_VOLUME_MANAGER_GUID,
                                       NULL,
                                       &RootExtension->SymbolicLinkName);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("DriverEntry: Status %X\n", Status);
        RootExtension->SymbolicLinkName.Buffer = NULL;
    }
    else
    {
        IoSetDeviceInterfaceState(&RootExtension->SymbolicLinkName, TRUE);
    }

    IoRegisterBootDriverReinitialization(DriverObject, FtpBootDriverReinitialization, RootExtension);
    IoRegisterDriverReinitialization(DriverObject, FtpDriverReinitialization, RootExtension);

    //FtpQueryRegistryRevertEntries(...);

    RtlDeleteRegistryValue(0, RegistryPath->Buffer, L"GptAttributeRevertEntries");

    IoInvalidateDeviceState(RootExtension->VolControlRootPdo);

    DPRINT("DriverEntry: exit with STATUS_SUCCESS\n");

    return STATUS_SUCCESS;
}

/* EOF */
