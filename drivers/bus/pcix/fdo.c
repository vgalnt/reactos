/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/fdo.c
 * PURPOSE:         FDO Device Management
 * PROGRAMMERS:     ReactOS Portable Systems Group
 *                  Copyright 2023 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

SINGLE_LIST_ENTRY PciFdoExtensionListHead;
BOOLEAN PciBreakOnDefault;

PCI_MN_DISPATCH_TABLE PciFdoDispatchPowerTable[] =
{
    {IRP_DISPATCH, (PCI_DISPATCH_FUNCTION)PciFdoWaitWake},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoSetPowerState},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoIrpQueryPower},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported}
};

PCI_MN_DISPATCH_TABLE PciFdoDispatchPnpTable[] =
{
    {IRP_UPWARD,   (PCI_DISPATCH_FUNCTION)PciFdoIrpStartDevice},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoIrpQueryRemoveDevice},
    {IRP_DISPATCH, (PCI_DISPATCH_FUNCTION)PciFdoIrpRemoveDevice},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoIrpCancelRemoveDevice},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoIrpStopDevice},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoIrpQueryStopDevice},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoIrpCancelStopDevice},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoIrpQueryDeviceRelations},
    {IRP_DISPATCH, (PCI_DISPATCH_FUNCTION)PciFdoIrpQueryInterface},
    {IRP_UPWARD,   (PCI_DISPATCH_FUNCTION)PciFdoIrpQueryCapabilities},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported},
    {IRP_UPWARD,   (PCI_DISPATCH_FUNCTION)PciFdoIrpDeviceUsageNotification},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoIrpSurpriseRemoval},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoIrpQueryLegacyBusInformation},
    {IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported}
};

PCI_MJ_DISPATCH_TABLE PciFdoDispatchTable =
{
    IRP_MN_QUERY_LEGACY_BUS_INFORMATION,
    PciFdoDispatchPnpTable,
    IRP_MN_QUERY_POWER,
    PciFdoDispatchPowerTable,
    IRP_DOWNWARD,
    (PCI_DISPATCH_FUNCTION)PciIrpNotSupported,
    IRP_DOWNWARD,
    (PCI_DISPATCH_FUNCTION)PciIrpNotSupported
};

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
PciFdoIrpStartDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_FDO_EXTENSION FdoExtension)
{
    PPCI_PDO_EXTENSION PdoExtension = NULL;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PIO_RESOURCE_DESCRIPTOR IoDescriptor;
    PCM_RESOURCE_LIST CmResource;
    UCHAR Types[2] = {0};
    ULONG ix;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciFdoIrpStartDevice: %p, %p, %p\n", Irp, IoStack, FdoExtension);

    /* The device stack must be starting the FDO in a success path */
    if (!NT_SUCCESS(Irp->IoStatus.Status))
    {
        DPRINT1("PciFdoIrpStartDevice: Status %X\n", Irp->IoStatus.Status);
        return STATUS_NOT_SUPPORTED;
    }

    /* Attempt to switch the state machine to the started state */
    Status = PciBeginStateTransition(FdoExtension, PciStarted);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciFdoIrpStartDevice: Status %X\n", Status);
        return Status;
    }

    /* Check for any boot-provided resources */
    CmResource = IoStack->Parameters.StartDevice.AllocatedResources;
    if (CmResource && !PCI_IS_ROOT_FDO(FdoExtension))
    {
        ASSERT(CmResource->Count == 1);

        PdoExtension = FdoExtension->PhysicalDeviceObject->DeviceExtension;

        if (PdoExtension->Resources && PdoExtension->HeaderType == PCI_BRIDGE_TYPE)
        {
            CmDescriptor = CmResource->List[0].PartialResourceList.PartialDescriptors;

            for (ix = 0; ix < 2; ix++)
            {
                IoDescriptor = &PdoExtension->Resources->Limit[ix];
                if (IoDescriptor->Type == CmResourceTypeNull)
                    continue;

                ASSERT(CmDescriptor->Type == IoDescriptor->Type);

                Types[ix] = CmDescriptor->Type;
                CmDescriptor->Type = 0;

                ASSERT((CmDescriptor+1)->Type == CmResourceTypeDevicePrivate);
                CmDescriptor += 2;
            }
        }
    }

    /* Initialize the arbiter for this FDO */
    Status = PciInitializeArbiterRanges(FdoExtension, CmResource);
    if (!NT_SUCCESS(Status))
    {
        /* Cancel the transition if this failed */
        PciCancelStateTransition(FdoExtension, PciStarted);
        return Status;
    }

    /* Again, check for boot-provided resources for non-root FDO */
    if (CmResource && !PCI_IS_ROOT_FDO(FdoExtension) && PdoExtension->Resources)
    {
        CmDescriptor = CmResource->List[0].PartialResourceList.PartialDescriptors;

        for (ix = 0; ix < 2; ix++)
        {
            if (Types[ix] == CmResourceTypeNull)
                continue;

            CmDescriptor->Type = Types[ix];

            ASSERT((CmDescriptor+1)->Type == CmResourceTypeDevicePrivate);
            CmDescriptor += 2;
        }
    }

    /* Commit the transition to the started state */
    PciCommitStateTransition(FdoExtension, PciStarted);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciFdoIrpQueryRemoveDevice(IN PIRP Irp,
                           IN PIO_STACK_LOCATION IoStackLocation,
                           IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
PciFdoIrpRemoveDevice(IN PIRP Irp,
                      IN PIO_STACK_LOCATION IoStackLocation,
                      IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
PciFdoIrpCancelRemoveDevice(IN PIRP Irp,
                            IN PIO_STACK_LOCATION IoStackLocation,
                            IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
PciFdoIrpStopDevice(IN PIRP Irp,
                    IN PIO_STACK_LOCATION IoStackLocation,
                    IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
PciFdoIrpQueryStopDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_FDO_EXTENSION FdoExtension)
{
    PAGED_CODE();
    DPRINT("PciFdoIrpQueryStopDevice: %p\n", FdoExtension);

    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStack);

    PciBeginStateTransition((PVOID)FdoExtension, PciStopped);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciFdoIrpCancelStopDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_FDO_EXTENSION FdoExtension)
{
    PAGED_CODE();
    DPRINT("PciFdoIrpCancelStopDevice: %p\n", FdoExtension);

    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStack);

    PciCancelStateTransition((PVOID)FdoExtension, PciStopped);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciFdoIrpQueryDeviceRelations(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_FDO_EXTENSION FdoExtension)
{
    PAGED_CODE();
    DPRINT("PciFdoIrpQueryDeviceRelations: %p, %p %p\n", Irp, IoStack, FdoExtension);

    /* Are bus relations being queried? */
    if (IoStack->Parameters.QueryDeviceRelations.Type != BusRelations)
        /* The FDO is a bus, so only bus relations can be obtained */
        return STATUS_NOT_SUPPORTED;

    /* Scan the PCI bus and build the device relations for the caller */
    return PciQueryDeviceRelations(FdoExtension, (PDEVICE_RELATIONS*)&Irp->IoStatus.Information);
}

NTSTATUS
NTAPI
PciFdoIrpQueryInterface(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_FDO_EXTENSION FdoExtension)
{
    NTSTATUS Status;

    DPRINT("PciFdoIrpQueryInterface: %p\n", Irp);

    PAGED_CODE();
    ASSERT(FdoExtension->ExtensionType == PciFdoExtensionType);

    /* Deleted extensions don't respond to IRPs */
    if (FdoExtension->DeviceState == PciDeleted)
        /* Hand it back to try to deal with it */
        return PciPassIrpFromFdoToPdo(FdoExtension, Irp);

    /* Query our driver for this interface */
    Status = PciQueryInterface(FdoExtension,
                               IoStack->Parameters.QueryInterface.InterfaceType,
                               IoStack->Parameters.QueryInterface.Size,
                               IoStack->Parameters.QueryInterface.Version,
                               IoStack->Parameters.QueryInterface.InterfaceSpecificData,
                               IoStack->Parameters.QueryInterface.Interface,
                               FALSE);
    if (NT_SUCCESS(Status))
    {
        /* We found it, let the PDO handle it */
        Irp->IoStatus.Status = Status;
        return PciPassIrpFromFdoToPdo(FdoExtension, Irp);
    }

    if (Status == STATUS_NOT_SUPPORTED)
    {
        /* Otherwise, we can't handle it, let someone else down the stack try */
        Status = PciCallDownIrpStack(FdoExtension, Irp);
        if (Status == STATUS_NOT_SUPPORTED)
        {
            /* They can't either, try a last-resort interface lookup */
            Status = PciQueryInterface(FdoExtension,
                                       IoStack->Parameters.QueryInterface.InterfaceType,
                                       IoStack->Parameters.QueryInterface.Size,
                                       IoStack->Parameters.QueryInterface.Version,
                                       IoStack->Parameters.QueryInterface.InterfaceSpecificData,
                                       IoStack->Parameters.QueryInterface.Interface,
                                       TRUE);
        }
    }

    /* Has anyone claimed this interface yet? */
    if (Status == STATUS_NOT_SUPPORTED)
        /* No, return the original IRP status */
        Status = Irp->IoStatus.Status;
    else
        /* Yes, set the new IRP status */
        Irp->IoStatus.Status = Status;

    /* Complete this IRP */
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS
NTAPI
PciFdoIrpQueryCapabilities(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_FDO_EXTENSION FdoExtension)
{
    PDEVICE_CAPABILITIES Capabilities;

    DPRINT("PciFdoIrpQueryCapabilities: %p, %p %p\n", Irp, IoStack, FdoExtension);
    PAGED_CODE();

    ASSERT_FDO(FdoExtension);

    /* Get the capabilities */
    Capabilities = IoStack->Parameters.DeviceCapabilities.Capabilities;

    /* Inherit wake levels and power mappings from the higher-up capabilities */
    FdoExtension->PowerState.SystemWakeLevel = Capabilities->SystemWake;
    FdoExtension->PowerState.DeviceWakeLevel = Capabilities->DeviceWake;

    RtlCopyMemory(FdoExtension->PowerState.SystemStateMapping,
                  Capabilities->DeviceState,
                  sizeof(FdoExtension->PowerState.SystemStateMapping));

    /* Dump the capabilities and return success */
    PciDebugDumpQueryCapabilities(Capabilities);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciFdoIrpDeviceUsageNotification(IN PIRP Irp,
                                 IN PIO_STACK_LOCATION IoStackLocation,
                                 IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
PciFdoIrpSurpriseRemoval(IN PIRP Irp,
                         IN PIO_STACK_LOCATION IoStackLocation,
                         IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
PciFdoIrpQueryLegacyBusInformation(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PPCI_FDO_EXTENSION FdoExtension)
{
    PLEGACY_BUS_INFORMATION BusInfo;

    DPRINT("PciFdoIrpQueryLegacyBusInformation: %p\n", Irp);

    PAGED_CODE();
    UNREFERENCED_PARAMETER(IoStack);

    BusInfo = ExAllocatePoolWithTag(PagedPool, sizeof(*BusInfo), 'BicP'); // POOL_TYPE 0x101
    if (!BusInfo)
    {
        ASSERT(BusInfo != NULL);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(&BusInfo->BusTypeGuid, &GUID_BUS_TYPE_PCI, sizeof(GUID));

    BusInfo->LegacyBusType = PCIBus;
    BusInfo->BusNumber = FdoExtension->BaseBus;

    Irp->IoStatus.Information = (ULONG_PTR)BusInfo;

    return STATUS_SUCCESS;
}

VOID
NTAPI
PciGetHotPlugParameters(
    _In_ PPCI_FDO_EXTENSION FdoExtension)
{
    ACPI_EVAL_INPUT_BUFFER InputBuffer;
    PACPI_EVAL_OUTPUT_BUFFER OutputBuffer;
    ULONG Argument;
    ULONG Length;
    ULONG ix;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciGetHotPlugParameters: %p\n", FdoExtension);

    /* We should receive 4 parameters, per the HPP specification */
    Length = (sizeof(ACPI_EVAL_OUTPUT_BUFFER) + 4 * sizeof(ACPI_METHOD_ARGUMENT));

    /* Allocate the buffer to hold the parameters */
    OutputBuffer = ExAllocatePoolWithTag(PagedPool, Length, PCI_POOL_TAG);
    if (!OutputBuffer)
    {
        DPRINT1("PciGetHotPlugParameters: allocate failed\n");
        return;
    }

    /* Initialize the output and input buffers. The method is _HPP */
    RtlZeroMemory(OutputBuffer, Length);

    *(PULONG)InputBuffer.MethodName = 'PPH_';
    InputBuffer.Signature = ACPI_EVAL_INPUT_BUFFER_SIGNATURE;

    do
    {
        /* Send the IOCTL to the ACPI driver */
        Status = PciSendIoctl(FdoExtension->PhysicalDeviceObject,
                              IOCTL_ACPI_EVAL_METHOD,
                              &InputBuffer,
                              sizeof(InputBuffer),
                              OutputBuffer,
                              Length);

        if (!NT_SUCCESS(Status))
        {
            DPRINT("PciGetHotPlugParameters: Status %X\n", Status);

            /* The method failed, check if we can salvage data from parent */
            if (!PCI_IS_ROOT_FDO(FdoExtension))
                /* Copy the root bus' hot plug parameters */
                FdoExtension->HotPlugParameters = FdoExtension->ParentFdoExtension->HotPlugParameters;

            /* Nothing more to do on this path */
            break;
        }

        /* ACPI sent back some data. 4 parameters are expected in the output */
        if (OutputBuffer->Count != 4)
            break;

        for (ix = 0; ix < 4; ix++)
        {
            if (OutputBuffer->Argument[ix].Type)
                goto Exit;

            Argument = OutputBuffer->Argument[ix].Argument;

            if (ix == 0 || ix == 1)
            {
                if (Argument <= 0xFF)
                    break;

                goto Exit;
            }
            else if (ix == 2 || ix == 3)
            {
                if (Argument <= 1)
                    break;

                goto Exit;
            }
        }

        FdoExtension->HotPlugParameters.CacheLineSize = (OutputBuffer->Argument[0].Argument & 0xFF);
        FdoExtension->HotPlugParameters.LatencyTimer = (OutputBuffer->Argument[1].Argument & 0xFF);
        FdoExtension->HotPlugParameters.EnableSERR = (OutputBuffer->Argument[2].Argument & 1);
        FdoExtension->HotPlugParameters.EnablePERR = (OutputBuffer->Argument[3].Argument & 1);
        FdoExtension->HotPlugParameters.Acquired = TRUE;
    }
    while (FALSE);

Exit:
    /* Free the buffer and return */
    ExFreePoolWithTag(OutputBuffer, PCI_POOL_TAG);
}

VOID
NTAPI
PciInitializeFdoExtensionCommonFields(
    _In_ PPCI_FDO_EXTENSION FdoExtension,
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PDEVICE_OBJECT Pdo)
{
    DPRINT("PciInitializeFdoExtensionCommonFields: %p, %p, %p\n", FdoExtension, Fdo, Pdo);

    /* Initialize the extension */
    RtlZeroMemory(FdoExtension, sizeof(PCI_FDO_EXTENSION));

    /* Setup the common fields */
    FdoExtension->PhysicalDeviceObject = Pdo;
    FdoExtension->FunctionalDeviceObject = Fdo;
    FdoExtension->ExtensionType = PciFdoExtensionType;
    FdoExtension->PowerState.CurrentSystemState = PowerSystemWorking;
    FdoExtension->PowerState.CurrentDeviceState = PowerDeviceD0;
    FdoExtension->IrpDispatchTable = &PciFdoDispatchTable;

    /* Initialize the extension locks */
    KeInitializeEvent(&FdoExtension->SecondaryExtLock, SynchronizationEvent, TRUE);
    KeInitializeEvent(&FdoExtension->ChildListLock, SynchronizationEvent, TRUE);

    /* Initialize the default state */
    PciInitializeState(FdoExtension);
}

PCM_PARTIAL_RESOURCE_DESCRIPTOR
NTAPI
PciGetNextCmPartialDescriptor(
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR NextDescriptor;

    DPRINT("PciGetNextCmPartialDescriptor: %p\n", CmDescriptor);

    /* Assume the descriptors are the fixed size ones */
    NextDescriptor = (CmDescriptor + 1);

    /* But check if this is actually a variable-sized descriptor */
    if (CmDescriptor->Type == CmResourceTypeDeviceSpecific)
        /* Add the size of the variable section as well */
        NextDescriptor = (PVOID)((ULONG_PTR)NextDescriptor + CmDescriptor->u.DeviceSpecificData.DataSize);

    /* Now the correct pointer has been computed, return it */
    return NextDescriptor;
}

PCM_PARTIAL_RESOURCE_DESCRIPTOR
NTAPI
PciFindDescriptorInCmResourceList(
    _In_ CM_RESOURCE_TYPE DescriptorType,
    _In_ PCM_RESOURCE_LIST CmResource)
{
    PCM_FULL_RESOURCE_DESCRIPTOR FullList;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    ULONG ix;
    ULONG jx;

    if (!CmResource)
    {
        DPRINT("PciFindDescriptorInCmResourceList: CmResource == NULL\n");
        return NULL;
    }

    if (!CmResource->Count)
    {
        DPRINT("PciFindDescriptorInCmResourceList: CmResource->Count == 0\n");
        return NULL;
    }

    DPRINT("PciFindDescriptorInCmResourceList: FullList Count %x\n", CmResource->Count);

    FullList = &CmResource->List[0];

    for (ix = 0; ix < CmResource->Count; ix++)
    {
        DPRINT("List #%X Iface %X Bus #%X Ver.%X Rev.%X Count %X\n",
                ix,
                FullList->InterfaceType,
                FullList->BusNumber,
                FullList->PartialResourceList.Version,
                FullList->PartialResourceList.Revision,
                FullList->PartialResourceList.Count);

        CmDescriptor = FullList->PartialResourceList.PartialDescriptors;

        for (jx = 0; jx < FullList->PartialResourceList.Count; jx++)
        {
            if (CmDescriptor->Type == DescriptorType)
            {
                DPRINT("[%p:%X:%X] BUS: Start %X Len %X Reserv %X\n", CmDescriptor, CmDescriptor->ShareDisposition, CmDescriptor->Flags,
                       CmDescriptor->u.BusNumber.Start, CmDescriptor->u.BusNumber.Length, CmDescriptor->u.BusNumber.Reserved);

                return CmDescriptor;
            }

            CmDescriptor = PciGetNextCmPartialDescriptor(CmDescriptor);
        }

        FullList = (PCM_FULL_RESOURCE_DESCRIPTOR)CmDescriptor;
    }

    return NULL;
}

NTSTATUS
NTAPI
PciAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT PhysicalDeviceObject)
{
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION ValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PPCI_FDO_EXTENSION FdoExtension = NULL;
    PPCI_FDO_EXTENSION ParentExtension;
    PPCI_PDO_EXTENSION PdoExtension = NULL;
    PDEVICE_OBJECT DeviceObject = NULL;
    PDEVICE_OBJECT AttachedTo = NULL;
    PCM_RESOURCE_LIST CmList;
    UNICODE_STRING ValueName;
    HANDLE KeyHandle;
    ULONG ResultLength;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciAddDevice: %p, '%wZ'\n", PhysicalDeviceObject, &PhysicalDeviceObject->DriverObject->DriverName);

    /* Zero out variables so failure path knows what to do */

    do
    {
        /* Check if there's already a device extension for this bus */
        ParentExtension = PciFindParentPciFdoExtension(PhysicalDeviceObject, &PciGlobalLock);
        if (ParentExtension)
        {
            /* Make sure we find a real PDO */
            PdoExtension = PhysicalDeviceObject->DeviceExtension;
            ASSERT_PDO(PdoExtension);

            /* Make sure it's a PCI-to-PCI bridge */
            if (PdoExtension->BaseClass != PCI_CLASS_BRIDGE_DEV ||
                PdoExtension->SubClass != PCI_SUBCLASS_BR_PCI_TO_PCI)
            {
                /* This should never happen */
                DPRINT1("PCI - PciAddDevice for Non-Root/Non-PCI-PCI bridge,\n      Class %02x, SubClass %02x, will not add.\n", PdoExtension->BaseClass, PdoExtension->SubClass);

                ASSERT((PdoExtension->BaseClass == PCI_CLASS_BRIDGE_DEV) &&
                       (PdoExtension->SubClass == PCI_SUBCLASS_BR_PCI_TO_PCI));

                /* Enter the failure path */
                Status = STATUS_INVALID_DEVICE_REQUEST;
                break;
            }

            /* Subordinate bus on the bridge */
            DPRINT("PCI - AddDevice (new bus is child of bus 0x%x).\n", ParentExtension->BaseBus);

            /* Make sure PCI bus numbers are configured */
            if (!PciAreBusNumbersConfigured(PdoExtension))
            {
                /* This is a critical failure */
                DPRINT1("PCI - Bus numbers not configured for bridge (0x%x.0x%x.0x%x)\n", ParentExtension->BaseBus, PdoExtension->Slot.u.bits.DeviceNumber, PdoExtension->Slot.u.bits.FunctionNumber);

                /* Enter the failure path */
                Status = STATUS_INVALID_DEVICE_REQUEST;
                break;
            }
        }

        /* Create the FDO for the bus */
        Status = IoCreateDevice(DriverObject, sizeof(PCI_FDO_EXTENSION), NULL, FILE_DEVICE_BUS_EXTENDER, 0, 0, &DeviceObject);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PciAddDevice: Status %X\n", Status);
            break;
        }

        /* Initialize the extension for the FDO */
        FdoExtension = DeviceObject->DeviceExtension;
        PciInitializeFdoExtensionCommonFields(DeviceObject->DeviceExtension, DeviceObject, PhysicalDeviceObject);

        /* Attach to the root PDO */
        Status = STATUS_NO_SUCH_DEVICE;

        AttachedTo = IoAttachDeviceToDeviceStack(DeviceObject, PhysicalDeviceObject);
        ASSERT(AttachedTo != NULL);
        if (!AttachedTo)
        {
            DPRINT1("PciAddDevice: Status %X\n", Status);
            break;
        }

        FdoExtension->AttachedDeviceObject = AttachedTo;

        /* Check if this is a child bus, or the root */
        if (ParentExtension)
        {
            /* The child inherits root data */
            FdoExtension->BaseBus = PdoExtension->Dependent.type1.SecondaryBus;
            FdoExtension->BusRootFdoExtension = ParentExtension->BusRootFdoExtension;
            PdoExtension->BridgeFdoExtension = FdoExtension;
            FdoExtension->ParentFdoExtension = ParentExtension;
        }
        else
        {
            /* Query the boot configuration */
            Status = PciGetDeviceProperty(PhysicalDeviceObject, DevicePropertyBootConfiguration, (PVOID*)&CmList);
            if (!NT_SUCCESS(Status))
            {
                /* No configuration has been set */
                DPRINT1("PciAddDevice: Status %X\n", Status);
                CmDescriptor = NULL;
            }
            else
            {
                CmDescriptor = PciFindDescriptorInCmResourceList(CmResourceTypeBusNumber, CmList);
            }

            if (CmDescriptor)
            {
                DPRINT("PciAddDevice: CmDescriptor %p\n", CmDescriptor);

                ASSERT(CmDescriptor->u.BusNumber.Start <= 0xFF);
                ASSERT((CmDescriptor->u.BusNumber.Start + CmDescriptor->u.BusNumber.Length - 1) <= 0xFF);

                FdoExtension->BaseBus = (UCHAR)CmDescriptor->u.BusNumber.Start;
                FdoExtension->MaxSubordinateBus = (UCHAR)(CmDescriptor->u.BusNumber.Start + CmDescriptor->u.BusNumber.Length - 1);

                DPRINT("PciAddDevice: Root Bus # %X->%X\n", FdoExtension->BaseBus, FdoExtension->MaxSubordinateBus);
            }
            else
            {
                /* Default configuration isn't the normal path on Windows */
                if (PciBreakOnDefault)
                {
                    /* If a second bus is found and there's still no data, crash */
                    DPRINT1("PciAddDevice: KeBugCheckEx(..)\n");
                    ASSERT(FALSE);
                    KeBugCheckEx(PCI_BUS_DRIVER_INTERNAL, 0xDEAD0010u, (ULONG_PTR)DeviceObject, 0, 0);
                }

                /* Warn that a default configuration will be used, and set bus 0 */
                DPRINT1("PciAddDevice: Will use default configuration.\n");
                PciBreakOnDefault = TRUE;
                FdoExtension->BaseBus = 0;
            }

            /* This is the root bus */
            FdoExtension->BusRootFdoExtension = FdoExtension;
        }

        /* Get the HAL or ACPI Bus Handler Callbacks for Configuration Access */
        Status = PciGetConfigHandlers(FdoExtension);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PciAddDevice: Status %X\n", Status);
            break;
        }

        /* Initialize all the supported PCI arbiters */
        Status = PciInitializeArbiters(FdoExtension);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PciAddDevice: Status %X\n", Status);
            break;
        }

        /* This is a real FDO, insert it into the list */
        FdoExtension->Fake = FALSE;
        PciInsertEntryAtTail(&PciFdoExtensionListHead, FdoExtension, &PciGlobalLock);

        /* Open the device registry key so that we can query the errata flags */
        IoOpenDeviceRegistryKey(DeviceObject, PLUGPLAY_REGKEY_DEVICE, KEY_ALL_ACCESS, &KeyHandle),

        /* Open the value that contains errata flags for this bus instance */
        RtlInitUnicodeString(&ValueName, L"HackFlags");

        Status = ZwQueryValueKey(KeyHandle, &ValueName, KeyValuePartialInformation, ValueInfo, sizeof(Buffer), &ResultLength);
        ZwClose(KeyHandle);
        if (NT_SUCCESS(Status))
        {
            /* Make sure the data is of expected type and size */
            if (ValueInfo->Type == REG_DWORD &&
                ValueInfo->DataLength == sizeof(ULONG))
            {
                /* Read the flags for this bus */
                FdoExtension->BusHackFlags = *(PULONG)&ValueInfo->Data;
            }
        }

        /* Query ACPI for PCI HotPlug Support */
        PciGetHotPlugParameters(FdoExtension);

        /* The Bus FDO is now initialized */
        DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

        return STATUS_SUCCESS;
    }
    while (FALSE);

    /* This is the failure path */
    ASSERT(!NT_SUCCESS(Status));

    /* Check if the FDO extension exists */
    if (FdoExtension)
    {
        DPRINT1("Should destroy secondaries\n");
    }

    /* Delete device objects */
    if (AttachedTo)
        IoDetachDevice(AttachedTo);

    if (DeviceObject)
        IoDeleteDevice(DeviceObject);

    return Status;
}

/* EOF */
