/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/pdo.c
 * PURPOSE:         PDO Device Management
 * PROGRAMMERS:     ReactOS Portable Systems Group
 *                  Copyright 2023 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

LONG PciPdoSequenceNumber;

C_ASSERT(FIELD_OFFSET(PCI_FDO_EXTENSION, DeviceState) == FIELD_OFFSET(PCI_PDO_EXTENSION, DeviceState));
C_ASSERT(FIELD_OFFSET(PCI_FDO_EXTENSION, TentativeNextState) == FIELD_OFFSET(PCI_PDO_EXTENSION, TentativeNextState));
C_ASSERT(FIELD_OFFSET(PCI_FDO_EXTENSION, List) == FIELD_OFFSET(PCI_PDO_EXTENSION, Next));

PCI_MN_DISPATCH_TABLE PciPdoDispatchPowerTable[] =
{
    {IRP_DISPATCH, (PCI_DISPATCH_FUNCTION)PciPdoWaitWake},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoSetPowerState},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpQueryPower},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported}
};

PCI_MN_DISPATCH_TABLE PciPdoDispatchPnpTable[] =
{
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpStartDevice},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpQueryRemoveDevice},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpRemoveDevice},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpCancelRemoveDevice},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpStopDevice},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpQueryStopDevice},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpCancelStopDevice},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpQueryDeviceRelations},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpQueryInterface},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpQueryCapabilities},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpQueryResources},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpQueryResourceRequirements},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpQueryDeviceText},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpReadConfig},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpWriteConfig},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpQueryId},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpQueryDeviceState},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpQueryBusInformation},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpDeviceUsageNotification},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpSurpriseRemoval},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpQueryLegacyBusInformation},
    {IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported}
};

PCI_MJ_DISPATCH_TABLE PciPdoDispatchTable =
{
    IRP_MN_QUERY_LEGACY_BUS_INFORMATION,
    PciPdoDispatchPnpTable,
    IRP_MN_QUERY_POWER,
    PciPdoDispatchPowerTable,
    IRP_COMPLETE,
    (PCI_DISPATCH_FUNCTION)PciIrpNotSupported,
    IRP_COMPLETE,
    (PCI_DISPATCH_FUNCTION)PciIrpInvalidDeviceRequest
};

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
PciPdoIrpStartDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_PDO_EXTENSION PdoExtension)
{
    POWER_STATE PowerState;
    BOOLEAN Changed;
    BOOLEAN DoReset = FALSE;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciPdoIrpStartDevice: %p\n", Irp);

    /* Begin entering the start phase */
    Status = PciBeginStateTransition((PVOID)PdoExtension, PciStarted);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciPdoIrpStartDevice: Status %X\n", Status);
        return Status;
    }

    /* Check if this is a VGA device */
    if ((PdoExtension->BaseClass == PCI_CLASS_PRE_20 && PdoExtension->SubClass == PCI_SUBCLASS_PRE_20_VGA) ||
        (PdoExtension->BaseClass == PCI_CLASS_DISPLAY_CTLR && PdoExtension->SubClass == PCI_SUBCLASS_VID_VGA_CTLR))
    {
        /* Always force it on */
        PdoExtension->CommandEnables |= (PCI_ENABLE_IO_SPACE | PCI_ENABLE_MEMORY_SPACE);
    }

    /* Check if native IDE is enabled and it owns the I/O ports */
    if (PdoExtension->IoSpaceUnderNativeIdeControl)
        /* Then don't allow I/O access */
        PdoExtension->CommandEnables &= ~PCI_ENABLE_IO_SPACE;

    /* Always enable bus mastering */
    PdoExtension->CommandEnables |= PCI_ENABLE_BUS_MASTER;

    /* Check if the OS assigned resources differ from the PCI configuration */
    Changed = PciComputeNewCurrentSettings(PdoExtension, IoStack->Parameters.StartDevice.AllocatedResources);

    if (Changed)
    {
        /* Remember this for later */
        PdoExtension->MovedDevice = TRUE;
    }
    else
    {
        /* All good */
        DPRINT("PciPdoIrpStartDevice: START not changing resource settings.\n");
    }

    /* Check if the device was sleeping */
    if (PdoExtension->PowerState.CurrentDeviceState != PowerDeviceD0)
    {
        /* Power it up */
        Status = PciSetPowerManagedDevicePowerState(PdoExtension, PowerDeviceD0, FALSE);
        if (!NT_SUCCESS(Status))
        {
            /* Powerup fail, fail the request */
            DPRINT1("PciPdoIrpStartDevice: Status %X\n", Status);
            PciCancelStateTransition((PVOID)PdoExtension, PciStarted);
            return STATUS_DEVICE_POWER_FAILURE;
        }

        /* Tell the power manager that the device is powered up */
        PowerState.DeviceState = PowerDeviceD0;
        PoSetPowerState(PdoExtension->PhysicalDeviceObject, DevicePowerState, PowerState);

        /* Update internal state */
        PdoExtension->PowerState.CurrentDeviceState = PowerDeviceD0;

        /* This device's resources and decodes will need to be reset */
        DoReset = TRUE;
    }

    /* Update resource information now that the device is powered up and active */
    Status = PciSetResources(PdoExtension, DoReset, TRUE);
    if (!NT_SUCCESS(Status))
    {
        /* That failed, so cancel the transition */
        DPRINT1("PciPdoIrpStartDevice: Status %X\n", Status);
        PciCancelStateTransition((PVOID)PdoExtension, PciStarted);
        return Status;
    }

    /* Fully commit, as the device is now started up and ready to go */
    PciCommitStateTransition((PVOID)PdoExtension, PciStarted);

    /* Return the result of the start request */
    return Status;
}

NTSTATUS
NTAPI
PciPdoIrpQueryRemoveDevice(IN PIRP Irp,
                           IN PIO_STACK_LOCATION IoStackLocation,
                           IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
PciPdoIrpRemoveDevice(IN PIRP Irp,
                      IN PIO_STACK_LOCATION IoStackLocation,
                      IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
PciPdoIrpCancelRemoveDevice(IN PIRP Irp,
                            IN PIO_STACK_LOCATION IoStackLocation,
                            IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
PciPdoIrpStopDevice(IN PIRP Irp,
                    IN PIO_STACK_LOCATION IoStackLocation,
                    IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
PciPdoIrpQueryStopDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_PDO_EXTENSION PdoExtension)
{
    PAGED_CODE();
    DPRINT("PciPdoIrpQueryStopDevice: %p\n", PdoExtension);

    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStack);

    if (PdoExtension->PowerState.Hibernate ||
        PdoExtension->PowerState.Paging ||
        PdoExtension->PowerState.CrashDump ||
        PdoExtension->OnDebugPath)
    {
        DPRINT1("PciPdoIrpQueryStopDevice: STATUS_DEVICE_BUSY\n");
        return STATUS_DEVICE_BUSY;
    }

    if (PdoExtension->BaseClass == 6 &&
        (PdoExtension->SubClass == 4 || PdoExtension->SubClass == 7))
    {
        DPRINT("PciPdoIrpQueryStopDevice: STATUS_INVALID_DEVICE_REQUEST\n");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (PdoExtension->LegacyDriver)
    {
        DPRINT1("PciPdoIrpQueryStopDevice: STATUS_INVALID_DEVICE_REQUEST\n");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (!PciCanDisableDecodes(PdoExtension, NULL, 0, FALSE))
    {
        DPRINT("PciPdoIrpQueryStopDevice: STATUS_INVALID_DEVICE_REQUEST\n");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    return PciBeginStateTransition((PVOID)PdoExtension, PciStopped);
}

NTSTATUS
NTAPI
PciPdoIrpCancelStopDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_PDO_EXTENSION PdoExtension)
{
    PAGED_CODE();
    DPRINT("PciPdoIrpCancelStopDevice: %p\n", PdoExtension);

    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStack);

    PciCancelStateTransition((PVOID)PdoExtension, PciStopped);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciPdoIrpQueryInterface(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_PDO_EXTENSION PdoExtension)
{
    PPCI_FDO_EXTENSION FdoExtension;
    NTSTATUS Status;

    DPRINT("PciPdoIrpQueryInterface: %p\n", Irp);

    PAGED_CODE();
    UNREFERENCED_PARAMETER(Irp);

    Status = PciQueryInterface((PVOID)PdoExtension,
                               IoStack->Parameters.QueryInterface.InterfaceType,
                               IoStack->Parameters.QueryInterface.Size,
                               IoStack->Parameters.QueryInterface.Version,
                               IoStack->Parameters.QueryInterface.InterfaceSpecificData,
                               IoStack->Parameters.QueryInterface.Interface,
                               0);
    if (NT_SUCCESS(Status))
        return Status;

    FdoExtension = PdoExtension->BridgeFdoExtension;
    if (!FdoExtension)
    {
        DPRINT("PciPdoIrpQueryInterface: Status %X\n", Status);
        return Status;
    }

    if (FdoExtension->Fake != 1)
    {
        DPRINT("PciPdoIrpQueryInterface: Status %X\n", Status);
        return Status;
    }

    ASSERT((PdoExtension->BaseClass == PCI_CLASS_BRIDGE_DEV) && (PdoExtension->SubClass == PCI_SUBCLASS_BR_CARDBUS));

    Status = PciQueryInterface(FdoExtension,
                               IoStack->Parameters.QueryInterface.InterfaceType,
                               IoStack->Parameters.QueryInterface.Size,
                               IoStack->Parameters.QueryInterface.Version,
                               IoStack->Parameters.QueryInterface.InterfaceSpecificData,
                               IoStack->Parameters.QueryInterface.Interface,
                               0);
    return Status;
}

NTSTATUS
NTAPI
PciPdoIrpQueryDeviceRelations(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_PDO_EXTENSION PdoExtension)
{
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciPdoIrpQueryDeviceRelations: %p, %p, %p\n", Irp, IoStack, PdoExtension);

    /* Are ejection relations being queried? */
    if (IoStack->Parameters.QueryDeviceRelations.Type == EjectionRelations)
        /* Call the worker function */
        return PciQueryEjectionRelations(PdoExtension,(PDEVICE_RELATIONS*)&Irp->IoStatus.Information);

    if (IoStack->Parameters.QueryDeviceRelations.Type != TargetDeviceRelation)
    {
        /* All other relations are unsupported */
        DPRINT("PciPdoIrpQueryDeviceRelations: STATUS_NOT_SUPPORTED\n");
        return STATUS_NOT_SUPPORTED;
    }

    /* The only other relation supported is the target device relation */
    Status = PciQueryTargetDeviceRelations(PdoExtension, (PDEVICE_RELATIONS*)&Irp->IoStatus.Information);

    /* Return either the result of the worker function, or unsupported status */
    return Status;
}

NTSTATUS
NTAPI
PciPdoIrpQueryCapabilities(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_PDO_EXTENSION PdoExtension)
{
    PAGED_CODE();
    DPRINT("PciPdoIrpQueryCapabilities: %p, %p, %p\n", Irp, IoStack, PdoExtension);

    /* Call the worker function */
    return PciQueryCapabilities(PdoExtension, IoStack->Parameters.DeviceCapabilities.Capabilities);
}

NTSTATUS
NTAPI
PciPdoIrpQueryResources(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_PDO_EXTENSION PdoExtension)
{
    PAGED_CODE();
    DPRINT("PciPdoIrpQueryResources: %p, %p, %p\n", Irp, IoStack, PdoExtension);

    /* Call the worker function */
    return PciQueryResources(PdoExtension, (PCM_RESOURCE_LIST*)&Irp->IoStatus.Information);
}

NTSTATUS
NTAPI
PciPdoIrpQueryResourceRequirements(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_PDO_EXTENSION PdoExtension)
{
    PAGED_CODE();
    DPRINT("PciPdoIrpQueryResourceRequirements: %p, %p, %p\n", Irp, IoStack, PdoExtension);

    /* Call the worker function */
    return PciQueryRequirements(PdoExtension, (PIO_RESOURCE_REQUIREMENTS_LIST*)&Irp->IoStatus.Information);
}

NTSTATUS
NTAPI
PciPdoIrpQueryDeviceText(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_PDO_EXTENSION PdoExtension)
{
    PAGED_CODE();
    DPRINT("PciPdoIrpQueryDeviceText: %p, %p, %p\n", Irp, IoStack, PdoExtension);

    /* Call the worker function */
    return PciQueryDeviceText(PdoExtension,
                              IoStack->Parameters.QueryDeviceText.DeviceTextType,
                              IoStack->Parameters.QueryDeviceText.LocaleId,
                              (PWCHAR*)&Irp->IoStatus.Information);
}

NTSTATUS
NTAPI
PciPdoIrpQueryId(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_PDO_EXTENSION PdoExtension)
{
    PAGED_CODE();
    DPRINT("PciPdoCreate: %p, %p, %p\n", Irp, IoStack, PdoExtension);

    /* Call the worker function */
    return PciQueryId(PdoExtension, IoStack->Parameters.QueryId.IdType, (PWCHAR*)&Irp->IoStatus.Information);
}

NTSTATUS
NTAPI
PciPdoIrpQueryBusInformation(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_PDO_EXTENSION PdoExtension)
{
    PAGED_CODE();
    DPRINT("PciPdoIrpQueryResourceRequirements: %p, %p, %p\n", Irp, IoStack, PdoExtension);

    /* Call the worker function */
    return PciQueryBusInformation(PdoExtension,(PPNP_BUS_INFORMATION*)&Irp->IoStatus.Information);
}

NTSTATUS
NTAPI
PciPdoIrpReadConfig(IN PIRP Irp,
                    IN PIO_STACK_LOCATION IoStackLocation,
                    IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
PciPdoIrpWriteConfig(IN PIRP Irp,
                     IN PIO_STACK_LOCATION IoStackLocation,
                     IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

BOOLEAN
NTAPI
PciIsOnVGAPath(
    _In_ PPCI_PDO_EXTENSION PdoExtension)
{
    DPRINT("PciIsOnVGAPath: %p\n", PdoExtension);

    if (!PdoExtension->BaseClass)
    {
        if (PdoExtension->SubClass != 1)
            return FALSE;

        return TRUE;
    }

    if (PdoExtension->BaseClass != 3)
    {
        if (PdoExtension->BaseClass != 6)
            return FALSE;

        if (PdoExtension->SubClass != 4 && PdoExtension->SubClass != 7)
            return FALSE;

        if (!PdoExtension->Dependent.type1.VgaBitSet)
            return FALSE;

        return TRUE;
    }

    if (PdoExtension->SubClass != 0)
        return FALSE;

    return TRUE;
}

NTSTATUS
NTAPI
PciPdoIrpQueryDeviceState(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_PDO_EXTENSION PdoExtension)
{
    PAGED_CODE();
    DPRINT("PciPdoIrpQueryDeviceState: %p\n", PdoExtension);

    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStack);

    if (PdoExtension->BaseClass == 6 && !PdoExtension->SubClass)
        Irp->IoStatus.Information |= 0x20;

    if (PdoExtension->HeaderType == 1 && PciIsOnVGAPath(PdoExtension))
        Irp->IoStatus.Information |= 0x20;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciPdoIrpDeviceUsageNotification(IN PIRP Irp,
                                 IN PIO_STACK_LOCATION IoStackLocation,
                                 IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
PciPdoIrpSurpriseRemoval(IN PIRP Irp,
                         IN PIO_STACK_LOCATION IoStackLocation,
                         IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
PciPdoIrpQueryLegacyBusInformation(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_PDO_EXTENSION PdoExtension)
{
    PLEGACY_BUS_INFORMATION BusInfo;

    PAGED_CODE();
    DPRINT("PciPdoIrpQueryLegacyBusInformation: %p, %p, %p\n", Irp, IoStack, PdoExtension);

    if (PciClassifyDeviceType(PdoExtension) != PciTypeCardbusBridge)
    {
        DPRINT("PciPdoIrpQueryLegacyBusInformation: STATUS_NOT_SUPPORTED\n");
        return STATUS_NOT_SUPPORTED;
    }

    BusInfo = ExAllocatePoolWithTag(PagedPool, sizeof(*BusInfo), 'BicP');
    if (!BusInfo)
    {
        DPRINT1("PciPdoIrpQueryLegacyBusInformation: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(&BusInfo->BusTypeGuid, &GUID_BUS_TYPE_PCI, sizeof(GUID));

    BusInfo->LegacyBusType = PCIBus;
    BusInfo->BusNumber = PdoExtension->Dependent.type1.SecondaryBus;

    Irp->IoStatus.Information = (ULONG_PTR)BusInfo;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciPdoCreate(
    _In_ PPCI_FDO_EXTENSION FdoExtension,
    _In_ PCI_SLOT_NUMBER Slot,
    _Out_ PDEVICE_OBJECT* OutPdo)
{
    PPCI_PDO_EXTENSION PdoExtension;
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING DeviceString;
    ULONG SequenceNumber;
    WCHAR DeviceName[32];
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciPdoCreate: %p, %X\n", FdoExtension, Slot.u.AsULONG);

    /* Pick an atomically unique sequence number for this device */
    SequenceNumber = InterlockedIncrement(&PciPdoSequenceNumber);

    /* Create the standard PCI device name for a PDO */
    swprintf(DeviceName, L"\\Device\\NTPNP_PCI%04d", SequenceNumber);
    RtlInitUnicodeString(&DeviceString, DeviceName);

    /* Create the actual device now */
    Status = IoCreateDevice(FdoExtension->FunctionalDeviceObject->DriverObject,
                            sizeof(PCI_PDO_EXTENSION),
                            &DeviceString,
                            FILE_DEVICE_BUS_EXTENDER,
                            0,
                            0,
                            &DeviceObject);
    ASSERT(NT_SUCCESS(Status));

    /* Get the extension for it */
    PdoExtension = DeviceObject->DeviceExtension;

    DPRINT("PciPdoCreate: New PDO (b %X, d %X, f %X) %p (%p)\n", FdoExtension->BaseBus,
           Slot.u.bits.DeviceNumber, Slot.u.bits.FunctionNumber, DeviceObject, DeviceObject->DeviceExtension);

    /* Configure the extension */
    PdoExtension->ExtensionType = PciPdoExtensionType;
    PdoExtension->IrpDispatchTable = &PciPdoDispatchTable;
    PdoExtension->PhysicalDeviceObject = DeviceObject;
    PdoExtension->Slot = Slot;
    PdoExtension->PowerState.CurrentSystemState = PowerDeviceD0;
    PdoExtension->PowerState.CurrentDeviceState = PowerDeviceD0;
    PdoExtension->ParentFdoExtension = FdoExtension;

    /* Initialize the lock for arbiters and other interfaces */
    KeInitializeEvent(&PdoExtension->SecondaryExtLock, SynchronizationEvent, TRUE);

    /* Initialize the state machine */
    PciInitializeState((PVOID)PdoExtension);

    /* Add the PDO to the parent's list */
    PdoExtension->Next = NULL;
    PciInsertEntryAtTail((PVOID)&FdoExtension->ChildPdoList, (PVOID)PdoExtension, &FdoExtension->ChildListLock);

    /* And finally return it to the caller */
    *OutPdo = DeviceObject;
    return STATUS_SUCCESS;
}

/* EOF */
