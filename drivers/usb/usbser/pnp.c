/*
 * PROJECT:     Universal serial bus modem driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     USB modem driver pnp functions.
 * COPYRIGHT:   Copyright 2022 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES ******************************************************************/

#include "usbser.h"

//#define NDEBUG
#include <debug.h>

/* DATA ***********************************************************************/

/* GLOBALS ********************************************************************/

/* FUNCTIONS *****************************************************************/

NTSTATUS
NTAPI
UsbSerDoExternalNaming(IN PUSBSER_DEVICE_EXTENSION Extension)
{
    UNICODE_STRING SymLinkName;
    PWSTR RegSymbolicName;
    HANDLE KeyHandle;
    USHORT MaxLength;
    USHORT MaximumSize;
    NTSTATUS Status;

    DPRINT("UsbSerDoExternalNaming: Extension %p\n", Extension);
    PAGED_CODE();

    MaxLength = (USBSER_MAX_SYMBOLIC_NAME_LENGTH * sizeof(WCHAR));
    MaximumSize = (MaxLength + sizeof(WCHAR));

    SymLinkName.Length = 0;
    SymLinkName.MaximumLength = MaxLength;

    SymLinkName.Buffer = ExAllocatePoolWithTag(PagedPool, MaximumSize, USBSER_TAG);
    if (!SymLinkName.Buffer)
    {
        DPRINT1("UsbSerDoExternalNaming: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }
    RtlZeroMemory(SymLinkName.Buffer, MaximumSize);

    RegSymbolicName = ExAllocatePoolWithTag(PagedPool, MaximumSize, USBSER_TAG);
    if (!RegSymbolicName)
    {
        DPRINT1("UsbSerDoExternalNaming: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }

    Status = IoOpenDeviceRegistryKey(Extension->PhysicalDevice,
                                     PLUGPLAY_REGKEY_DEVICE,
                                     STANDARD_RIGHTS_READ,
                                     &KeyHandle);
    if (Status != STATUS_SUCCESS)
    {
        DPRINT("UsbSerDoExternalNaming: Status %p\n", Status);
        goto ErrorExit;
    }

    Status = UsbSerGetRegistryKeyValue(KeyHandle,
                                       L"PortName",
                                       sizeof(L"PortName"),
                                       RegSymbolicName,
                                       MaxLength);
    if (Status != STATUS_SUCCESS)
    {
        DPRINT("UsbSerDoExternalNaming: Status %p\n", Status);

        Status = UsbSerGetRegistryKeyValue(KeyHandle,
                                           L"Identifier",
                                           sizeof(L"Identifier"),
                                           RegSymbolicName,
                                           MaxLength);
        if (Status != STATUS_SUCCESS)
        {
            DPRINT("UsbSerDoExternalNaming: Status %p\n", Status);
            ZwClose(KeyHandle);
            goto ErrorExit;
        }
    }

    ZwClose(KeyHandle);

    DPRINT("UsbSerDoExternalNaming: FIXME WmiId\n");

    RtlAppendUnicodeToString(&SymLinkName, L"\\");
    RtlAppendUnicodeToString(&SymLinkName, L"DosDevices");
    RtlAppendUnicodeToString(&SymLinkName, L"\\");
    RtlAppendUnicodeToString(&SymLinkName, RegSymbolicName);

    MaxLength = (SymLinkName.Length + sizeof(WCHAR));
    Extension->SymLinkName.MaximumLength = MaxLength;

    Extension->SymLinkName.Buffer = ExAllocatePoolWithTag(PagedPool, MaxLength, USBSER_TAG);
    if (!Extension->SymLinkName.Buffer)
    {
        DPRINT1("UsbSerDoExternalNaming: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }
    RtlZeroMemory(Extension->SymLinkName.Buffer, MaxLength);

    RtlAppendUnicodeStringToString(&Extension->SymLinkName, &SymLinkName);

    Status = IoCreateSymbolicLink(&Extension->SymLinkName, &Extension->DeviceName);
    if (Status != STATUS_SUCCESS)
    {
        DPRINT1("UsbSerDoExternalNaming: Status %p\n", Status);
        goto ErrorExit;
    }

    Extension->IsSymLinkCreated = TRUE;

    MaxLength = (USBSER_MAX_DOS_NAME_LENGTH * sizeof(WCHAR));
    MaximumSize = (MaxLength + sizeof(WCHAR));

    Extension->DosName.Buffer = ExAllocatePoolWithTag(PagedPool, MaximumSize, USBSER_TAG);
    if (!Extension->DosName.Buffer)
    {
        DPRINT1("UsbSerDoExternalNaming: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }
    RtlZeroMemory(Extension->DosName.Buffer, MaxLength);

    Extension->DosName.Length = 0;
    Extension->DosName.MaximumLength = MaximumSize;
    Extension->DosName.Buffer[USBSER_MAX_DOS_NAME_LENGTH] = 0;

    RtlAppendUnicodeToString(&Extension->DosName, RegSymbolicName);
    Extension->DosName.Buffer[Extension->DosName.Length] = 0;

    Status = RtlWriteRegistryValue(RTL_REGISTRY_DEVICEMAP,
                                   L"SERIALCOMM",
                                   Extension->DeviceName.Buffer,
                                   REG_SZ,
                                   Extension->DosName.Buffer,
                                   Extension->DosName.Length + sizeof(WCHAR));
    if (Status == STATUS_SUCCESS)
        goto Exit;

    DPRINT1("UsbSerDoExternalNaming: Status %p\n", Status);

ErrorExit:

    if (Extension->DosName.Buffer)
    {
        ExFreePoolWithTag(Extension->DosName.Buffer, USBSER_TAG);
        Extension->DosName.Buffer = NULL;
    }

    if (Extension->IsSymLinkCreated)
    {
        IoDeleteSymbolicLink(&Extension->SymLinkName);
        Extension->IsSymLinkCreated = FALSE;
    }

    if (Extension->SymLinkName.Buffer)
    {
        ExFreePoolWithTag(Extension->SymLinkName.Buffer, USBSER_TAG);
        Extension->SymLinkName.Buffer = NULL;
    }

    if (Extension->DeviceName.Buffer)
        RtlDeleteRegistryValue(RTL_REGISTRY_DEVICEMAP, L"SERIALCOMM", Extension->DeviceName.Buffer);

Exit:

    if (SymLinkName.Buffer)
        ExFreePoolWithTag(SymLinkName.Buffer, USBSER_TAG);

    if (RegSymbolicName)
        ExFreePoolWithTag(RegSymbolicName, USBSER_TAG);

    return Status;
}

NTSTATUS
NTAPI
StartDevice(IN PDEVICE_OBJECT DeviceObject,
            IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    KEVENT Event;
    NTSTATUS Status;

    DPRINT("StartDevice: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Extension = DeviceObject->DeviceExtension;

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, UsbSerSyncCompletion, &Event, TRUE, TRUE, TRUE);

    Status = IoCallDriver(Extension->LowerDevice, Irp);
    DPRINT("StartDevice: Status %X\n", Status);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Suspended, KernelMode, FALSE, NULL);
    }

    if (!NT_SUCCESS(Irp->IoStatus.Status))
    {
        DPRINT1("StartDevice: Status %X\n", Irp->IoStatus.Status);
        goto Exit;
    }

    Status = GetDeviceDescriptor(DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("StartDevice: Status %X\n", Status);
        goto Exit;
    }

    Status = ConfigureDevice(DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("StartDevice: Status %X\n", Status);
        goto Exit;
    }

    ResetDevice(DeviceObject);

    UsbSerDoExternalNaming(Extension);

    SetClrDtr(DeviceObject, FALSE);
    ClrRts(Extension);

    StartRead(Extension);
    StartNotifyRead(Extension);

    DPRINT("StartDevice: Device %p is started\n", DeviceObject);

Exit:

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS
NTAPI
RemoveDevice(IN PDEVICE_OBJECT DeviceObject,
             IN PIRP Irp)
{
    UNIMPLEMENTED;
    ASSERT(FALSE);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
StopDevice(IN PDEVICE_OBJECT DeviceObject,
           IN PIRP Irp)
{
    UNIMPLEMENTED;
    ASSERT(FALSE);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
QueryCapabilities(IN PDEVICE_OBJECT DeviceObject,
                  IN PIRP Irp)
{
    UNIMPLEMENTED;
    ASSERT(FALSE);
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
SurpriseRemoval(IN PDEVICE_OBJECT DeviceObject,
                IN PIRP Irp)
{
    UNIMPLEMENTED;
    ASSERT(FALSE);
    return;
}

NTSTATUS
NTAPI
UsbSerPnP(IN PDEVICE_OBJECT DeviceObject,
          IN PIRP Irp)
{
    PUSBSER_DEVICE_EXTENSION Extension;
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    DPRINT("UsbSerPnP: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();

    Extension = DeviceObject->DeviceExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    switch (IoStack->MinorFunction)
    {
        case IRP_MN_START_DEVICE:
            DPRINT("UsbSerPnP: IRP_MN_START_DEVICE\n");
            Status = StartDevice(DeviceObject, Irp);
            goto Exit;

        case IRP_MN_QUERY_REMOVE_DEVICE:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_REMOVE_DEVICE\n");
            break;

        case IRP_MN_REMOVE_DEVICE:
            DPRINT("UsbSerPnP: IRP_MN_REMOVE_DEVICE\n");
            DPRINT1("UsbSerPnP: FIXME IoWMIRegistrationControl()\n");
            //IoWMIRegistrationControl(DeviceObject, WMIREG_ACTION_DEREGISTER);
            Status = RemoveDevice(DeviceObject, Irp);
            goto Exit;

        case IRP_MN_CANCEL_REMOVE_DEVICE:
            DPRINT("UsbSerPnP: IRP_MN_CANCEL_REMOVE_DEVICE\n");
            break;

        case IRP_MN_STOP_DEVICE:
            DPRINT("UsbSerPnP: IRP_MN_STOP_DEVICE\n");
            StopDevice(DeviceObject, Irp);
            break;

        case IRP_MN_QUERY_STOP_DEVICE:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_STOP_DEVICE\n");
            break;

        case IRP_MN_CANCEL_STOP_DEVICE:
            DPRINT("UsbSerPnP: IRP_MN_CANCEL_STOP_DEVICE\n");
            break;

        case IRP_MN_QUERY_DEVICE_RELATIONS:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_DEVICE_RELATIONS\n");
            break;

        case IRP_MN_QUERY_INTERFACE:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_INTERFACE\n");
            break;

        case IRP_MN_QUERY_CAPABILITIES:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_CAPABILITIES\n");
            Status = QueryCapabilities(DeviceObject, Irp);
            goto Exit;

        case IRP_MN_QUERY_RESOURCES:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_RESOURCES\n");
            break;

        case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_RESOURCE_REQUIREMENTS\n");
            break;

        case IRP_MN_QUERY_DEVICE_TEXT:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_DEVICE_TEXT\n");
            break;

        case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
            DPRINT("UsbSerPnP: IRP_MN_FILTER_RESOURCE_REQUIREMENTS\n");
            break;

        case IRP_MN_READ_CONFIG:
            DPRINT("UsbSerPnP: IRP_MN_READ_CONFIG\n");
            break;

        case IRP_MN_WRITE_CONFIG:
            DPRINT("UsbSerPnP: IRP_MN_WRITE_CONFIG\n");
            break;

        case IRP_MN_EJECT:
            DPRINT("UsbSerPnP: IRP_MN_EJECT\n");
            break;

        case IRP_MN_SET_LOCK:
            DPRINT("UsbSerPnP: IRP_MN_SET_LOCK\n");
            break;

        case IRP_MN_QUERY_ID:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_ID\n");
            break;

        case IRP_MN_QUERY_PNP_DEVICE_STATE:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_PNP_DEVICE_STATE\n");
            break;

        case IRP_MN_QUERY_BUS_INFORMATION:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_BUS_INFORMATION\n");
            break;

        case IRP_MN_DEVICE_USAGE_NOTIFICATION:
            DPRINT("UsbSerPnP: IRP_MN_DEVICE_USAGE_NOTIFICATION\n");
            break;

        case IRP_MN_SURPRISE_REMOVAL:
            DPRINT("UsbSerPnP: IRP_MN_SURPRISE_REMOVAL\n");
            SurpriseRemoval(DeviceObject, Irp);
            break;

        case IRP_MN_QUERY_LEGACY_BUS_INFORMATION:
            DPRINT("UsbSerPnP: IRP_MN_QUERY_LEGACY_BUS_INFORMATION\n");
            break;

        default:
            DPRINT1("UsbSerPnP: Unknown MinorFunction %X\n", IoStack->MinorFunction);
            break;
    }

    IoCopyCurrentIrpStackLocationToNext(Irp);
    Status = IoCallDriver(Extension->LowerDevice, Irp);

Exit:

    return Status;
}


/* EOF */
