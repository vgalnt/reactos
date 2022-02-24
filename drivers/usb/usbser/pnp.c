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
