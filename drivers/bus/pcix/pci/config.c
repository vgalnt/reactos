/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/pci/config.c
 * PURPOSE:         PCI Configuration Space Routines
 * PROGRAMMERS:     ReactOS Portable Systems Group
 *                  Copyright 2023 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

BOOLEAN PciAssignBusNumbers;

/* FUNCTIONS ******************************************************************/

UCHAR
NTAPI
PciGetAdjustedInterruptLine(IN PPCI_PDO_EXTENSION PdoExtension)
{
    UCHAR InterruptLine = 0, PciInterruptLine;
    ULONG Length;

    /* Does the device have an interrupt pin? */
    if (PdoExtension->InterruptPin)
    {
        /* Find the associated line on the parent bus */
        Length = HalGetBusDataByOffset(PCIConfiguration,
                                       PdoExtension->ParentFdoExtension->BaseBus,
                                       PdoExtension->Slot.u.AsULONG,
                                       &PciInterruptLine,
                                       FIELD_OFFSET(PCI_COMMON_HEADER,
                                                    u.type0.InterruptLine),
                                       sizeof(UCHAR));
        if (Length) InterruptLine = PciInterruptLine;
    }

    /* Either keep the original interrupt line, or the one on the master bus */
    return InterruptLine ? PdoExtension->RawInterruptLine : InterruptLine;
}

VOID
NTAPI
PciReadWriteConfigSpace(
    _In_ PPCI_FDO_EXTENSION ParentFdoExt,
    _In_ PCI_SLOT_NUMBER Slot,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length,
    _In_ BOOLEAN IsRead)
{
    PPCI_BUS_INTERFACE_STANDARD PciInterface;
    PBUS_HANDLER BusHandler;
    PPCIBUSDATA BusData;
    PciReadWriteConfig HalFunction;
    PCI_READ_WRITE_CONFIG InterfaceFunction;
    ULONG RetLength;

    DPRINT("PciReadWriteConfigSpace: %X, %X, %X, %X\n", Slot.u.AsULONG, Offset, Length, IsRead);

    /* Only the root FDO can access configuration space */
    ASSERT(PCI_IS_ROOT_FDO(ParentFdoExt->BusRootFdoExtension));

    /* Get the ACPI-compliant PCI interface */
    PciInterface = ParentFdoExt->BusRootFdoExtension->PciBusInterface;
    if (!PciInterface)
    {
        /* Make sure there's a registered HAL bus handler */
        ASSERT(ParentFdoExt->BusHandler);

        /* PCI Bus Number assignment is only valid on ACPI systems */
        ASSERT(!PciAssignBusNumbers);

        /* Grab the HAL PCI Bus Handler data */
        BusHandler = (PBUS_HANDLER)ParentFdoExt->BusHandler;
        BusData = (PPCIBUSDATA)BusHandler->BusData;

        /* Choose the appropriate read or write function, and call it */
        HalFunction = (IsRead ? BusData->ReadConfig : BusData->WriteConfig);
        HalFunction(BusHandler, Slot, Buffer, Offset, Length);

        return;
    }

    if (IsRead)
        InterfaceFunction = PciInterface->ReadConfig;
    else
        InterfaceFunction = PciInterface->WriteConfig;

    RetLength = InterfaceFunction(PciInterface->Context, ParentFdoExt->BaseBus, Slot.u.AsULONG, Buffer, Offset, Length);
    if (RetLength == Length)
        return;

    DPRINT1("PciReadWriteConfigSpace: KeBugCheckEx(..)! %X, %X, %X, %X\n", Slot.u.AsULONG, Offset, Length, IsRead);
    KeBugCheckEx(0xC0, ParentFdoExt->BaseBus, Slot.u.AsULONG, Offset, IsRead);
}

VOID
NTAPI
PciWriteDeviceConfig(IN PPCI_PDO_EXTENSION DeviceExtension,
                     IN PVOID Buffer,
                     IN ULONG Offset,
                     IN ULONG Length)
{
    /* Call the generic worker function */
    PciReadWriteConfigSpace(DeviceExtension->ParentFdoExtension,
                            DeviceExtension->Slot,
                            Buffer,
                            Offset,
                            Length,
                            FALSE);
}

VOID
NTAPI
PciReadDeviceConfig(IN PPCI_PDO_EXTENSION DeviceExtension,
                    IN PVOID Buffer,
                    IN ULONG Offset,
                    IN ULONG Length)
{
    /* Call the generic worker function */
    PciReadWriteConfigSpace(DeviceExtension->ParentFdoExtension,
                            DeviceExtension->Slot,
                            Buffer,
                            Offset,
                            Length,
                            TRUE);
}

VOID
NTAPI
PciReadSlotConfig(IN PPCI_FDO_EXTENSION DeviceExtension,
                  IN PCI_SLOT_NUMBER Slot,
                  IN PVOID Buffer,
                  IN ULONG Offset,
                  IN ULONG Length)
{
    /* Call the generic worker function */
    PciReadWriteConfigSpace(DeviceExtension, Slot, Buffer, Offset, Length, TRUE);
}

NTSTATUS
NTAPI
PciQueryForPciBusInterface(IN PPCI_FDO_EXTENSION FdoExtension)
{
    PDEVICE_OBJECT AttachedDevice;
    IO_STATUS_BLOCK IoStatusBlock;
    KEVENT Event;
    NTSTATUS Status;
    PIRP Irp;
    PIO_STACK_LOCATION IoStackLocation;
    PPCI_BUS_INTERFACE_STANDARD PciInterface;
    PAGED_CODE();
    ASSERT(PCI_IS_ROOT_FDO(FdoExtension));

    /* Allocate space for the interface */
    PciInterface = ExAllocatePoolWithTag(NonPagedPool,
                                         sizeof(PCI_BUS_INTERFACE_STANDARD),
                                         PCI_POOL_TAG);
    if (!PciInterface) return STATUS_INSUFFICIENT_RESOURCES;

    /* Get the device the PDO is attached to, should be the Root (ACPI) */
    AttachedDevice = IoGetAttachedDeviceReference(FdoExtension->PhysicalDeviceObject);

    /* Build an IRP for this request */
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                       AttachedDevice,
                                       NULL,
                                       0,
                                       NULL,
                                       &Event,
                                       &IoStatusBlock);
    if (Irp)
    {
        /* Initialize the default PnP response */
        Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
        Irp->IoStatus.Information = 0;

        /* Make it a Query Interface IRP */
        IoStackLocation = IoGetNextIrpStackLocation(Irp);
        ASSERT(IoStackLocation->MajorFunction == IRP_MJ_PNP);
        IoStackLocation->MinorFunction = IRP_MN_QUERY_INTERFACE;
        IoStackLocation->Parameters.QueryInterface.InterfaceType = &GUID_PCI_BUS_INTERFACE_STANDARD;
        IoStackLocation->Parameters.QueryInterface.Size = sizeof(PCI_BUS_INTERFACE_STANDARD);
        IoStackLocation->Parameters.QueryInterface.Version = PCI_BUS_INTERFACE_STANDARD_VERSION;
        IoStackLocation->Parameters.QueryInterface.Interface = (PINTERFACE)PciInterface;
        IoStackLocation->Parameters.QueryInterface.InterfaceSpecificData = NULL;

        /* Send it to the root PDO */
        Status = IoCallDriver(AttachedDevice, Irp);
        if (Status == STATUS_PENDING)
        {
            /* Wait for completion */
            KeWaitForSingleObject(&Event,
                                  Executive,
                                  KernelMode,
                                  FALSE,
                                  NULL);
            Status = Irp->IoStatus.Status;
        }

        /* Check if an interface was returned */
        if (!NT_SUCCESS(Status))
        {
            /* No interface was returned by the root PDO */
            FdoExtension->PciBusInterface = NULL;
            ExFreePoolWithTag(PciInterface, 0);
        }
        else
        {
            /* An interface was returned, save it */
            FdoExtension->PciBusInterface = PciInterface;
        }

        /* Dereference the device object because we took a reference earlier */
        ObDereferenceObject(AttachedDevice);
    }
    else
    {
        /* Failure path, dereference the device object and set failure code */
        if (AttachedDevice) ObDereferenceObject(AttachedDevice);
        ExFreePoolWithTag(PciInterface, 0);
        Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Return status code to caller */
    return Status;
}

NTSTATUS
NTAPI
PciGetConfigHandlers(IN PPCI_FDO_EXTENSION FdoExtension)
{
    PBUS_HANDLER BusHandler;
    NTSTATUS Status;
    ASSERT(FdoExtension->BusHandler == NULL);

    /* Check if this is the FDO for the root bus */
    if (PCI_IS_ROOT_FDO(FdoExtension))
    {
        /* Query the PCI Bus Interface that ACPI exposes */
        ASSERT(FdoExtension->PciBusInterface == NULL);
        Status = PciQueryForPciBusInterface(FdoExtension);
        if (!NT_SUCCESS(Status))
        {
            /* No ACPI, so Bus Numbers should be maintained by BIOS */
            ASSERT(!PciAssignBusNumbers);
        }
        else
        {
            /* ACPI detected, PCI Bus Driver will reconfigure bus numbers*/
            PciAssignBusNumbers = TRUE;
        }
    }
    else
    {
        /* Check if the root bus already has the interface set up */
        if (FdoExtension->BusRootFdoExtension->PciBusInterface)
        {
            /* Nothing for this FDO to do */
            return STATUS_SUCCESS;
        }

        /* Fail into case below so we can query the HAL interface */
        Status = STATUS_NOT_SUPPORTED;
    }

    /* If the ACPI PCI Bus Interface couldn't be obtained, try the HAL */
    if (!NT_SUCCESS(Status))
    {
        /* Bus number assignment should be static */
        ASSERT(Status == STATUS_NOT_SUPPORTED);
        ASSERT(!PciAssignBusNumbers);

        /* Call the HAL to obtain the bus handler for PCI */
        BusHandler = HalReferenceHandlerForBus(PCIBus, FdoExtension->BaseBus);
        FdoExtension->BusHandler = BusHandler;

        /* Fail if the HAL does not have a PCI Bus Handler for this bus */
        if (!BusHandler) return STATUS_INVALID_DEVICE_REQUEST;
    }

    /* Appropriate interface was obtained */
    return STATUS_SUCCESS;
}

/* EOF */
