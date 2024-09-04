/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         Parallel Port Function Driver
 * FILE:            drivers/parallel/parport/pdo.c
 * PURPOSE:         PDO functions
 */

#include "parport.h"

/* FUNCTIONS ****************************************************************/

NTSTATUS
NTAPI
PdoCreate(IN PDEVICE_OBJECT DeviceObject,
          IN PIRP Irp)
{
    PPDO_DEVICE_EXTENSION DeviceExtension;
    PIO_STACK_LOCATION Stack;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("PdoCreate()\n");

    Stack = IoGetCurrentIrpStackLocation(Irp);
    DeviceExtension = (PPDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    if (Stack->Parameters.Create.Options & FILE_DIRECTORY_FILE)
    {
        DPRINT1("Not a directory\n");
        Status = STATUS_NOT_A_DIRECTORY;
        goto done;
    }

    DPRINT("Open LPT%lu: successful\n", DeviceExtension->LptPort);
    DeviceExtension->OpenCount++;

done:
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}


NTSTATUS
NTAPI
PdoClose(IN PDEVICE_OBJECT DeviceObject,
         IN PIRP Irp)
{
    PPDO_DEVICE_EXTENSION pDeviceExtension;

    DPRINT("PdoClose()\n");

    pDeviceExtension = (PPDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    pDeviceExtension->OpenCount--;

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
PdoCleanup(IN PDEVICE_OBJECT DeviceObject,
           IN PIRP Irp)
{
    DPRINT("PdoCleanup()\n");

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
PdoRead(IN PDEVICE_OBJECT DeviceObject,
        IN PIRP Irp)
{
    DPRINT("PdoRead()\n");

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
PdoWrite(IN PDEVICE_OBJECT DeviceObject,
         IN PIRP Irp)
{
    PPDO_DEVICE_EXTENSION PdoDeviceExtension;
    PFDO_DEVICE_EXTENSION FdoDeviceExtension;
    PIO_STACK_LOCATION IoStack;
    PUCHAR Buffer;
    ULONG i;
    UCHAR PortStatus;
    ULONG ulCount;

    DPRINT("PdoWrite()\n");

    PdoDeviceExtension = (PPDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    FdoDeviceExtension = (PFDO_DEVICE_EXTENSION)PdoDeviceExtension->AttachedFdo->DeviceExtension;

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    Buffer = GetUserBuffer(Irp);
    DPRINT("Length: %lu\n", IoStack->Parameters.Write.Length);
    DPRINT("Buffer: %p\n", Buffer);

    for (i = 0; i < IoStack->Parameters.Write.Length; i++)
    {
        ulCount = 0;

        do
        {
            KeStallExecutionProcessor(10);
            PortStatus = READ_PORT_UCHAR(UlongToPtr(FdoDeviceExtension->BaseAddress + 1));
            ulCount++;
        }
        while (ulCount < 500000 && !(PortStatus & LP_PBUSY));

        if (ulCount == 500000)
        {
            DPRINT("Timed out\n");

            Irp->IoStatus.Information = 0;
            Irp->IoStatus.Status = STATUS_TIMEOUT;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);

            return STATUS_TIMEOUT;
        }

        /* Write character */
        WRITE_PORT_UCHAR(UlongToPtr(FdoDeviceExtension->BaseAddress), Buffer[i]);

        KeStallExecutionProcessor(10);

        WRITE_PORT_UCHAR(UlongToPtr(FdoDeviceExtension->BaseAddress + 2), (LP_PSELECP | LP_PINITP | LP_PSTROBE));

        KeStallExecutionProcessor(10);

        WRITE_PORT_UCHAR(UlongToPtr(FdoDeviceExtension->BaseAddress + 2), (LP_PSELECP | LP_PINITP));
    }

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
PdoPnp(IN PDEVICE_OBJECT DeviceObject,
       IN PIRP Irp)
{
    PIO_STACK_LOCATION Stack;
    UCHAR MinorFunction;
    NTSTATUS Status;

    DPRINT("PdoPnp()\n");Status = Irp->IoStatus.Status;

    Stack = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = Stack->MinorFunction;

    switch (MinorFunction)
    {
        case IRP_MN_START_DEVICE: // 0x00 PptPdoStartDevice
            UNIMPLEMENTED;
            break;

        case IRP_MN_QUERY_REMOVE_DEVICE: // 0x01 PptPdoQueryRemove
            UNIMPLEMENTED;
            break;

        case IRP_MN_REMOVE_DEVICE: // 0x02 PptPdoRemoveDevice
            UNIMPLEMENTED;
            break;

        case IRP_MN_CANCEL_REMOVE_DEVICE: // 0x03 PptPdoCancelRemove
            UNIMPLEMENTED;
            break;

        case IRP_MN_STOP_DEVICE: // 0x04 PptPdoStopDevice
            UNIMPLEMENTED;
            break;

        case IRP_MN_QUERY_STOP_DEVICE: // 0x05 PptPdoQueryStop
            UNIMPLEMENTED;
            break;

        case IRP_MN_CANCEL_STOP_DEVICE: // 0x06 PptPdoCancelStop
            UNIMPLEMENTED;
            break;

        case IRP_MN_QUERY_DEVICE_RELATIONS: // 0x07 PptPdoQueryDeviceRelations
            UNIMPLEMENTED;
            break;

        case IRP_MN_QUERY_CAPABILITIES: // 0x09 PptPdoQueryCapabilities
            UNIMPLEMENTED;
            break;

        case IRP_MN_QUERY_DEVICE_TEXT: // 0x0C PptPdoQueryDeviceText
            UNIMPLEMENTED;
            break;

        case IRP_MN_QUERY_ID: // 0x13 PptPdoQueryId
            UNIMPLEMENTED;Status = STATUS_INSUFFICIENT_RESOURCES;
            //break;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return Status;

        case IRP_MN_QUERY_PNP_DEVICE_STATE: //  PptPdoQueryPnpDeviceState
            UNIMPLEMENTED;
            break;

        case IRP_MN_QUERY_BUS_INFORMATION: //  PptPdoQueryBusInformation
            UNIMPLEMENTED;
            break;

        case IRP_MN_SURPRISE_REMOVAL: // 0x17 PptPdoSurpriseRemoval
            UNIMPLEMENTED;
            break;

        default:
            UNIMPLEMENTED;
            break;
    }

    Status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS
NTAPI
PdoPower(IN PDEVICE_OBJECT DeviceObject,
         IN PIRP Irp)
{
    NTSTATUS Status;
    PIO_STACK_LOCATION IoStack;

    DPRINT("PdoPower()\n");

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    switch (IoStack->MinorFunction)
    {
        case IRP_MN_SET_POWER:
        case IRP_MN_QUERY_POWER:
            Irp->IoStatus.Status = STATUS_SUCCESS;
            break;
    }

    Status = Irp->IoStatus.Status;
    PoStartNextPowerIrp(Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

/* EOF */
