/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/dispatch.c
 * PURPOSE:         WDM Dispatch Routines
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

#define NDEBUG
#include <debug.h>

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
PciSetEventCompletion(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PKEVENT Event = Context;
    ASSERT(Event);

    DPRINT("PciSetEventCompletion: %p, %p, %p\n", DeviceObject, Irp, Context);

    /* Set the event and return the appropriate status code */
    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
PciCallDownIrpStack(
    _In_ PPCI_FDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    NTSTATUS Status;
    KEVENT Event;

    PAGED_CODE();
    DPRINT("PciCallDownIrpStack: %p, %p\n", PciCallDownIrpStack, Irp);

    ASSERT_FDO(FdoExtension);

    /* Initialize the wait event */
    KeInitializeEvent(&Event, SynchronizationEvent, 0);

    /* Setup a completion routine */
    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, PciSetEventCompletion, &Event, TRUE, TRUE, TRUE);

    /* Call the attached device */
    Status = IoCallDriver(FdoExtension->AttachedDeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        /* Wait for it to complete the request, and get its status */
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    /* Return that status back to the caller */
    return Status;
}

NTSTATUS
NTAPI
PciPassIrpFromFdoToPdo(
    _In_ PPCI_FDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    DPRINT("PciPassIrpFromFdoToPdo: %p, %p\n", FdoExtension, Irp);

    /* Get the stack location to check which function this is */
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (IoStack->MajorFunction == IRP_MJ_POWER)
    {
        /* Power IRPs are special since we have to notify the Power Manager */
        IoCopyCurrentIrpStackLocationToNext(Irp);
        PoStartNextPowerIrp(Irp);
        Status = PoCallDriver(FdoExtension->AttachedDeviceObject, Irp);
    }
    else
    {
        /* For a normal IRP, just call the next driver in the stack */
        IoSkipCurrentIrpStackLocation(Irp);
        Status = IoCallDriver(FdoExtension->AttachedDeviceObject, Irp);
    }

    /* Return the status back to the caller */
    return Status;
}

NTSTATUS
NTAPI
PciDispatchIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PCI_DISPATCH_FUNCTION DispatchFunction;
    PPCI_MJ_DISPATCH_TABLE IrpDispatchTable;
    PPCI_MN_DISPATCH_TABLE TableArray;
    PPCI_MN_DISPATCH_TABLE Table;
    PCI_DISPATCH_STYLE DispatchStyle;
    PPCI_FDO_EXTENSION DeviceExtension;
    PIO_STACK_LOCATION IoStackLocation;
    USHORT MaxMinor;
    BOOLEAN PassToPdo;
    NTSTATUS Status;

    DPRINT("PciDispatchIrp: %p, %p\n", DeviceObject, Irp);

    /* Get the extension and I/O stack location for this IRP */
    DeviceExtension = DeviceObject->DeviceExtension;
    IoStackLocation = IoGetCurrentIrpStackLocation(Irp);

    ASSERT((DeviceExtension->ExtensionType == PciPdoExtensionType) ||
           (DeviceExtension->ExtensionType == PciFdoExtensionType));

    /* Deleted extensions don't respond to IRPs */
    if (DeviceExtension->DeviceState == PciDeleted)
    {
        /* Fail this IRP */
        DPRINT1("PciDispatchIrp: STATUS_NO_SUCH_DEVICE\n");
        Status = STATUS_NO_SUCH_DEVICE;
        PassToPdo = FALSE;
        goto Finish;
    }

    /* Otherwise, get the dispatch table for the extension */
    IrpDispatchTable = DeviceExtension->IrpDispatchTable;

    /* And choose which function table to use */
    switch (IoStackLocation->MajorFunction)
    {
        case IRP_MJ_POWER:

            /* Power Manager IRPs */
            TableArray = IrpDispatchTable->PowerIrpDispatchTable;
            MaxMinor = IrpDispatchTable->PowerIrpMaximumMinorFunction;
            break;

        case IRP_MJ_PNP:

            /* Plug-and-Play Manager IRPs */
            TableArray = IrpDispatchTable->PnpIrpDispatchTable;
            MaxMinor = IrpDispatchTable->PnpIrpMaximumMinorFunction;
            break;

        case IRP_MJ_SYSTEM_CONTROL:

            /* WMI IRPs */
            DispatchFunction = IrpDispatchTable->SystemControlIrpDispatchFunction;
            DispatchStyle = IrpDispatchTable->SystemControlIrpDispatchStyle;
            MaxMinor = 0xFFFF;
            break;

        default:

            DPRINT("PciDispatchIrp: Other IRPs, MajorFunction %X\n", IoStackLocation->MajorFunction);
            DispatchFunction = IrpDispatchTable->OtherIrpDispatchFunction;
            DispatchStyle = IrpDispatchTable->OtherIrpDispatchStyle;
            MaxMinor = 0xFFFF;
            break;
    }

    /* Only deal with recognized IRPs */
    if (MaxMinor != 0xFFFF)
    {
        /* Make sure the function is recognized */
        if (IoStackLocation->MinorFunction > MaxMinor)
            /* Pick the terminator, which should return unrecognized */
            Table = &TableArray[MaxMinor + 1];
        else
            /* Pick the appropriate table for this function */
            Table = &TableArray[IoStackLocation->MinorFunction];

        /* From that table, get the function code and dispatch style */
        DispatchStyle = Table->DispatchStyle;
        DispatchFunction = Table->DispatchFunction;
    }

    /* Print out debugging information, and see if we should break */
    if (PciDebugIrpDispatchDisplay(IoStackLocation, DeviceExtension, MaxMinor))
    {
        /* The developer/user wants us to break for this IRP, do it */
        DbgBreakPoint();
    }

    /* Check if this IRP should be sent up the stack first */
    if (DispatchStyle == IRP_UPWARD)
        /* Do it now before handling it ourselves */
        PciCallDownIrpStack(DeviceExtension, Irp);

    /* Call the our driver's handler for this IRP and deal with the IRP */
    Status = DispatchFunction(Irp, IoStackLocation, DeviceExtension);

    switch (DispatchStyle)
    {
        /* Complete IRPs are completely immediately by our driver */
        case IRP_COMPLETE:
            PassToPdo = FALSE;
            break;

        /* Downward IRPs are send to the attached FDO */
        case IRP_DOWNWARD:
            PassToPdo = TRUE;
            break;

        /* Upward IRPs are completed immediately by our driver */
        case IRP_UPWARD:
            PassToPdo = FALSE;
            break;

        /* Dispatch IRPs are immediately returned */
        case IRP_DISPATCH:
            return Status;

        /* There aren't any other dispatch styles! */
        default:
            DPRINT1("PciDispatchIrp: unknown DispatchStyle %X\n", DispatchStyle);
            ASSERT(FALSE);
            return Status;
    }

    /* Pending IRPs are returned immediately */
    if (Status == STATUS_PENDING)
        return Status;

Finish:

    /* Handled IRPs return their status in the status block */
    if (Status != STATUS_NOT_SUPPORTED)
        Irp->IoStatus.Status = Status;

    /* Successful, or unhandled IRPs that are "DOWNWARD" are sent to the PDO */
    if (PassToPdo && (NT_SUCCESS(Status) || Status == STATUS_NOT_SUPPORTED))
        /* Let the PDO deal with it */
        return PciPassIrpFromFdoToPdo(DeviceExtension, Irp);

    /* Power IRPs need to notify the Power Manager that the next IRP can go */
    if (IoStackLocation->MajorFunction == IRP_MJ_POWER)
        PoStartNextPowerIrp(Irp);

    /* And now this IRP can be completed */
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Irp->IoStatus.Status;
}

NTSTATUS
NTAPI
PciIrpNotSupported(IN PIRP Irp,
                   IN PIO_STACK_LOCATION IoStackLocation,
                   IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    /* Not supported */
    DPRINT("WARNING: PCI received unsupported IRP!\n");
    //DbgBreakPoint();
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
PciIrpInvalidDeviceRequest(IN PIRP Irp,
                           IN PIO_STACK_LOCATION IoStackLocation,
                           IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    /* Not supported */
    return STATUS_INVALID_DEVICE_REQUEST;
}

/* EOF */
