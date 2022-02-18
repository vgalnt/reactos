/*
 * PROJECT:     Universal serial bus modem driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     USB modem driver main functions.
 * COPYRIGHT:   2022 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES *******************************************************************/

#include "usbser.h"

//#define NDEBUG
#include <debug.h>

/* DATA ***********************************************************************/

/* GLOBALS ********************************************************************/

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
UsbSerCreate(IN PDEVICE_OBJECT DeviceObject,
             IN PIRP Irp)
{
    DPRINT("UsbSerCreate: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerClose(IN PDEVICE_OBJECT DeviceObject,
            IN PIRP Irp)
{
    DPRINT("UsbSerClose: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerRead(IN PDEVICE_OBJECT DeviceObject,
           IN PIRP Irp)
{
    DPRINT("UsbSerRead: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI 
UsbSerWrite(IN PDEVICE_OBJECT DeviceObject,
            IN PIRP Irp)
{
    DPRINT("UsbSerWrite: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerMajorNotSupported(IN PDEVICE_OBJECT DeviceObject,
                        IN PIRP Irp)
{
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);

    DPRINT("UsbSerMajorNotSupported: Device %p, Irp %p, Major %X\n", Device, Irp, IoStack->MajorFunction);
    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
    IofCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerFlush(IN PDEVICE_OBJECT DeviceObject,
            IN PIRP Irp)
{
    DPRINT("UsbSerFlush: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerDispatch(IN PDEVICE_OBJECT DeviceObject,
               IN PIRP Irp)
{
    DPRINT("UsbSerDispatch: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerCleanup(IN PDEVICE_OBJECT DeviceObject,
              IN PIRP Irp)
{
    DPRINT("UsbSerCleanup: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerProcessPowerIrp(IN PDEVICE_OBJECT DeviceObject,
                      IN PIRP Irp)
{
    DPRINT("UsbSerProcessPowerIrp: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerSystemControlDispatch(IN PDEVICE_OBJECT DeviceObject,
                            IN PIRP Irp)
{
    DPRINT("UsbSerSystemControlDispatch: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerPnP(IN PDEVICE_OBJECT DeviceObject,
          IN PIRP Irp)
{
    DPRINT("UsbSerPnP: DeviceObject %p, Irp %p\n", DeviceObject, Irp);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
UsbSerUnload(IN PDRIVER_OBJECT DriverObject)
{
    DPRINT("UsbSerUnload: DriverObject %p\n", DriverObject);
    PAGED_CODE();
}

NTSTATUS
NTAPI
UsbSerPnPAddDevice(IN PDRIVER_OBJECT DriverObject,
                   IN PDEVICE_OBJECT TargetDevice)
{
    DPRINT("UsbSerPnPAddDevice: DriverObject %p, TargetDevice %p\n", DriverObject, TargetDevice);
    PAGED_CODE();
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DriverEntry(IN PDRIVER_OBJECT DriverObject,
            IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT1("DriverEntry: USB modem driver\n");

    PAGED_CODE();
    DPRINT("DriverEntry: DriverObject %p, RegistryPath %wZ\n", DriverObject, RegistryPath);

    DriverObject->DriverUnload = UsbSerUnload;
    DriverObject->DriverExtension->AddDevice = UsbSerPnPAddDevice;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = UsbSerCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = UsbSerClose;
    DriverObject->MajorFunction[IRP_MJ_READ] = UsbSerRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = UsbSerWrite;
    DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = UsbSerMajorNotSupported;
    DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = UsbSerMajorNotSupported;
    DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = UsbSerFlush;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = UsbSerDispatch;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = UsbSerDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = UsbSerCleanup;
    DriverObject->MajorFunction[IRP_MJ_POWER] = UsbSerProcessPowerIrp;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = UsbSerSystemControlDispatch;
    DriverObject->MajorFunction[IRP_MJ_PNP] = UsbSerPnP;

    return Status;
}

/* EOF */
