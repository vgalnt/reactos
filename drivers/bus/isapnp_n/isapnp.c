/*
 * PROJECT:     ISA PnP Bus driver for NT 5.x
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Driver code
 * COPYRIGHT:   Copyright 2019, 2023 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES *******************************************************************/

#include <isapnp.h>

//#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

PISAPNP_BUS_EXTENSION PipBusExtension;
PISAPNP_DEVICE_INFO PipRDPNode;
PDRIVER_OBJECT PipDriverObject;
UNICODE_STRING PipRegistryPath;
KEVENT PipDeviceTreeLock;
KEVENT IsaBusNumberLock;
ULONG BusNumberBuffer[0x40];
ULONG ActiveIsaCount;
RTL_BITMAP BusNumBMHeader;
PRTL_BITMAP BusNumBM;
BOOLEAN PipFirstInit;
BOOLEAN PipIsolationDisabled;

ULONG PipState = 1;

PUCHAR PipReadDataPort;

ULONG ADDRESS_PORT = 0x0279;
ULONG COMMAND_PORT = 0x0A79;

PDRIVER_DISPATCH PiPnpDispatchTableFdo[] =
{
    PiStartFdo,
    PiQueryRemoveStopFdo,
    PiRemoveFdo,
    PiCancelRemoveStopFdo,
    PiStopFdo,
    PiQueryRemoveStopFdo,
    PiCancelRemoveStopFdo,
    PiQueryDeviceRelationsFdo,
    PiQueryInterfaceFdo,
    PipPassIrp,
    PipPassIrp,
    PipPassIrp,
    PipPassIrp,
    PipPassIrp,
    PipPassIrp,
    PipPassIrp,
    PipPassIrp,
    PipPassIrp,
    PipPassIrp,
    PipPassIrp,
    PiQueryPnpDeviceState,
    PipPassIrp,
    PipPassIrp,
    PiSurpriseRemoveFdo,
    PiQueryLegacyBusInformationFdo
};

PDRIVER_DISPATCH PiPnpDispatchTablePdo[] =
{
    PiStartPdo,
    PiQueryRemoveStopPdo,
    PiRemovePdo,
    PiCancelRemoveStopPdo,
    PiStopPdo,
    PiQueryRemoveStopPdo,
    PiCancelRemoveStopPdo,
    PiQueryDeviceRelationsPdo,
    PiIrpNotSupported,
    PiQueryCapabilitiesPdo,
    PiQueryResourcesPdo,
    PiQueryResourceRequirementsPdo,
    PiQueryDeviceTextPdo,
    PiFilterResourceRequirementsPdo,
    PiIrpNotSupported,
    PiIrpNotSupported,
    PiIrpNotSupported,
    PiIrpNotSupported,
    PiIrpNotSupported,
    PiQueryIdPdo,
    PiQueryDeviceState,
    PiQueryBusInformationPdo,
    PiDeviceUsageNotificationPdo,
    PiSurpriseRemovePdo,
    PiIrpNotSupported
};

/* FUNCTIONS ******************************************************************/

VOID
NTAPI
PipLockDeviceDatabase(VOID)
{
    KeWaitForSingleObject(&PipDeviceTreeLock, Executive, KernelMode, FALSE, NULL);
}

VOID
NTAPI
PipUnlockDeviceDatabase(VOID)
{
    KeSetEvent(&PipDeviceTreeLock, IO_NO_INCREMENT, FALSE);
}

VOID
NTAPI
PipCompleteRequest(
    _In_ PIRP Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

NTSTATUS
NTAPI
PipGetRegistryValue(
    _In_ HANDLE KeyHandle,
    _In_ PWSTR NameString,
    _Out_ PKEY_VALUE_FULL_INFORMATION* OutValueInfo)
{
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    UNICODE_STRING ValueName;
    ULONG ResultLength;
    NTSTATUS Status;
  
    PAGED_CODE();
    DPRINT("PipGetRegistryValue: %p, '%S'\n", KeyHandle, NameString);

    *OutValueInfo = NULL;

    RtlInitUnicodeString(&ValueName, NameString);

    Status = ZwQueryValueKey(KeyHandle, &ValueName, KeyValueFullInformation, NULL, 0, &ResultLength);

    if (Status != STATUS_BUFFER_OVERFLOW &&
        Status != STATUS_BUFFER_TOO_SMALL)
    {
        DPRINT1("PipGetRegistryValue: Status %X\n", Status);
        return Status;
    }

    ValueInfo = ExAllocatePoolWithTag(NonPagedPool, ResultLength, 'pasI');
    if (!ValueInfo)
    {
        DPRINT1("PipGetRegistryValue: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = ZwQueryValueKey(KeyHandle, &ValueName, KeyValueFullInformation, ValueInfo, ResultLength, &ResultLength);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PipGetRegistryValue: Status %X\n", Status);
        ExFreePoolWithTag(ValueInfo, 'pasI');
        return Status;
    }

    *OutValueInfo = ValueInfo;

    return STATUS_SUCCESS;
}

/* FDO PNP FUNCTIONS ********************************************************/

NTSTATUS
NTAPI
PipPassIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PISAPNP_FDO_EXTENSION FdoExtension;

    DPRINT("PipPassIrp: %p, %p\n", DeviceObject, Irp);

    IoSkipCurrentIrpStackLocation(Irp);

    FdoExtension = DeviceObject->DeviceExtension;

    return IoCallDriver(FdoExtension->AttachedToDevice, Irp);
}

NTSTATUS
NTAPI
PiPnPFdoCompletion(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PKEVENT Event = Context;
    KeSetEvent(Event, EVENT_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
PiDeferProcessingFdo(
    _In_ PISAPNP_FDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    KEVENT Event;
    NTSTATUS Status;

    DPRINT("PiDeferProcessingFdo: %p, %p\n", FdoExtension, Irp);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, PiPnPFdoCompletion, &Event, TRUE, TRUE, TRUE);

    Status = IoCallDriver(FdoExtension->AttachedToDevice, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    return Status;
}

NTSTATUS
NTAPI
PiStartFdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PISAPNP_FDO_EXTENSION FdoExtension;
    NTSTATUS Status;

    DPRINT("PiStartFdo: %p, %p\n", DeviceObject, Irp);

    FdoExtension = DeviceObject->DeviceExtension;

    Status = PiDeferProcessingFdo(FdoExtension, Irp);
    if (NT_SUCCESS(Status))
    {
        FdoExtension->SystemPowerState = PowerSystemWorking;
        FdoExtension->DevicePowerState = PowerDeviceD0;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PiStartFdo: Status %p\n", Status);
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

NTSTATUS
NTAPI
PiQueryRemoveStopFdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiRemoveFdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiCancelRemoveStopFdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiStopFdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PipCreateReadDataPortBootResources(
    _In_ PISAPNP_DEVICE_INFO DeviceInfo)
{
    PCM_RESOURCE_LIST CmResources;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    ULONG Size;
    ULONG ix;

    DPRINT("PipCreateReadDataPortBootResources: %p\n", DeviceInfo);

    Size = (sizeof(CM_RESOURCE_LIST) + sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));

    CmResources = ExAllocatePoolWithTag(PagedPool, Size, 'pasI');
    if (!CmResources)
    {
         DPRINT1("PipCreateReadDataPortBootResources: STATUS_INSUFFICIENT_RESOURCES\n");
         return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(CmResources, Size);

    CmResources->Count = 1;

    CmResources->List[0].PartialResourceList.Version = 0;
    CmResources->List[0].PartialResourceList.Revision = 0x3000;
    CmResources->List[0].PartialResourceList.Count = 2;

    CmDescriptor = CmResources->List[0].PartialResourceList.PartialDescriptors;

    for (ix = 0; ix < 2; ix++, CmDescriptor++)
    {
        CmDescriptor->Type = CmResourceTypePort;
        CmDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
        CmDescriptor->Flags = CM_RESOURCE_PORT_16_BIT_DECODE;

        if (ix)
            CmDescriptor->u.Port.Start.LowPart = ADDRESS_PORT;
        else
            CmDescriptor->u.Port.Start.LowPart = COMMAND_PORT;

        CmDescriptor->u.Port.Length = 1;
    }

    DeviceInfo->BootResources = CmResources;
    DeviceInfo->BootResourcesSize = Size;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PipCreateReadDataPort(
    _In_ PISAPNP_FDO_EXTENSION FdoExtension)
{
    PISAPNP_DEVICE_INFO DeviceInfo;
    PDEVICE_OBJECT ReadDataPortDO;
    NTSTATUS Status;

    DPRINT("PipCreateReadDataPort: %p\n", FdoExtension);

    Status = IoCreateDevice(PipDriverObject,
                            sizeof(DeviceInfo),
                            NULL,
                            FILE_DEVICE_BUS_EXTENDER,
                            (FILE_AUTOGENERATED_DEVICE_NAME | FILE_DEVICE_SECURE_OPEN),
                            FALSE,
                            &ReadDataPortDO);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PipCreateReadDataPort: Status %X\n", Status);
        return Status;
    }

    DeviceInfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(*DeviceInfo), 'iPnP');
    if (!DeviceInfo)
    {
        DPRINT1("PipCreateReadDataPort: STATUS_INSUFFICIENT_RESOURCES\n");
        IoDeleteDevice(ReadDataPortDO);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(DeviceInfo, sizeof(*DeviceInfo));

    DeviceInfo->Flags = 0x00000004;

    Status = PipCreateReadDataPortBootResources(DeviceInfo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PipCreateReadDataPort: Status %X\n", Status);
        IoDeleteDevice(ReadDataPortDO);
        ExFreePoolWithTag(DeviceInfo, 'iPnP');
        return Status;
    }

    DeviceInfo->Flags &= ~0x00000004;
    DeviceInfo->Flags |= (0x40000000 | 0x00000008);

    DeviceInfo->FdoExtension = FdoExtension;

    DeviceInfo->ReadDataPortDO = ReadDataPortDO;
    DeviceInfo->ReadDataPortDO->DeviceExtension = DeviceInfo;

    PipRDPNode = DeviceInfo;

    PipLockDeviceDatabase();

    DeviceInfo->Link.Next = FdoExtension->DeviceList.Next;
    FdoExtension->DeviceList.Next = &DeviceInfo->Link;

    PipUnlockDeviceDatabase();

    DeviceInfo->ReadDataPortDO->Flags &= ~DO_DEVICE_INITIALIZING;

    return Status;
}

NTSTATUS
NTAPI
PipQueryDeviceRelations(
    _In_ PISAPNP_FDO_EXTENSION FdoExtension,
    _Out_ PDEVICE_RELATIONS* OutDeviceRelations,
    _In_ BOOLEAN IsSkipNode)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiQueryDeviceRelationsFdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PISAPNP_FDO_EXTENSION FdoExtension;
    PDEVICE_RELATIONS DeviceRelations;
    PISAPNP_DEVICE_INFO DeviceInfo;
    PSINGLE_LIST_ENTRY Entry;
    DEVICE_RELATION_TYPE Type;
    BOOLEAN IsRdpPresent = FALSE;
    BOOLEAN IsRescan;
    NTSTATUS Status;

    DPRINT("PiQueryDeviceRelationsFdo: %p, %p\n", DeviceObject, Irp);

    Type = IoGetCurrentIrpStackLocation(Irp)->Parameters.QueryDeviceRelations.Type;
    if (Type != BusRelations)
    {
        DPRINT1("PiQueryDeviceRelationsFdo: FIXME\n");
        ASSERT(FALSE);
        return PipPassIrp(DeviceObject, Irp);
    }

    /* BusRelations */

    if (PipIsolationDisabled)
    {
        DPRINT1("PiQueryDeviceRelationsFdo: FIXME\n");
        ASSERT(FALSE);
        return PipPassIrp(DeviceObject, Irp);
    }

    FdoExtension = DeviceObject->DeviceExtension;
    if (FdoExtension->BusNumber)
        return PipPassIrp(DeviceObject, Irp);

    if (PipRDPNode && (PipRDPNode->Flags & (0x0080 | 0x0010)))
        IsRdpPresent = TRUE;

    if (!PipReadDataPort && !IsRdpPresent && !PipRDPNode)
    {
        Status = PipCreateReadDataPort(FdoExtension);
        if (!NT_SUCCESS(Status))
        {
            PipCompleteRequest(Irp, Status, 0);
            return Status;
        }

        IsRdpPresent = TRUE;
    }

    if ((PipRDPNode && (PipRDPNode->Flags & 0x0002)) ||
        (PipRDPNode && IsRdpPresent && !(PipRDPNode->Flags & 0x0010)))
    {
        DeviceRelations = ExAllocatePoolWithTag(PagedPool, sizeof(DEVICE_RELATIONS), 'pasI');
        if (!DeviceRelations)
        {
            PipCompleteRequest(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        PipLockDeviceDatabase();

        for (Entry = FdoExtension->DeviceList.Next; Entry; Entry = Entry->Next)
        {
            DeviceInfo = CONTAINING_RECORD(Entry, ISAPNP_DEVICE_INFO, Link);

            if (!(DeviceInfo->Flags & 0x40000000))
                DeviceInfo->Flags &= ~0x00000008;
        }

        PipUnlockDeviceDatabase();

        DeviceRelations->Count = 1;

        DPRINT("PiQueryDeviceRelationsFdo handing back the FDO\n");

        ObReferenceObject(PipRDPNode->ReadDataPortDO);
        DeviceRelations->Objects[0] = PipRDPNode->ReadDataPortDO;

        Irp->IoStatus.Information = (ULONG_PTR)DeviceRelations;
        Irp->IoStatus.Status = STATUS_SUCCESS;

        return PipPassIrp(DeviceObject, Irp);
    }

    PipLockDeviceDatabase();

    if ((PipRDPNode->Flags & (0x0020 | 0x0010)) == 0x0010)
    {
        DPRINT1("PiQueryDeviceRelationsFdo: FIXME\n");
        ASSERT(FALSE);
    }
    else
    {
        IsRescan = FALSE;
    }

    if (PipRDPNode->Flags & 0x1000)
    {
        DPRINT("PiQueryDeviceRelationsFdo: Force rescan\n");
        PipRDPNode->Flags &= ~0x1000;
        IsRescan = TRUE;
    }

    if (IsRescan)
    {
        DPRINT1("PiQueryDeviceRelationsFdo: FIXME\n");
        ASSERT(FALSE);
    }
    else
    {
        DPRINT("PiQueryDeviceRelationsFdo: Using cached data\n");
    }

    Status = PipQueryDeviceRelations(FdoExtension, (PDEVICE_RELATIONS *)&Irp->IoStatus.Information, 0);

    PipUnlockDeviceDatabase();

    Irp->IoStatus.Status = Status;

    if (NT_SUCCESS(Status))
        return PipPassIrp(DeviceObject, Irp);

    DPRINT1("PiQueryDeviceRelationsFdo: Status %X\n", Status);

    PipCompleteRequest(Irp, Status, 0);
    return Status;
}

NTSTATUS
NTAPI
FindInterruptTranslator(
    _In_ PISAPNP_FDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    CM_RESOURCE_TYPE ResourceType;
    PIO_STACK_LOCATION IoStack;
    ULONG BusType;
    ULONG BusNumber;
    ULONG DummyLength;
    ULONG DummyBridgeBusNumber;

    DPRINT("FindInterruptTranslator: %p, %p\n", FdoExtension, Irp);

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    ResourceType = PtrToUlong(IoStack->Parameters.QueryInterface.InterfaceSpecificData);

    if (ResourceType != CmResourceTypeInterrupt)
        return STATUS_NOT_SUPPORTED;

    IoGetDeviceProperty(FdoExtension->AttachToPdo, DevicePropertyLegacyBusType, sizeof(BusType), &BusType, &DummyLength);
    IoGetDeviceProperty(FdoExtension->AttachToPdo, DevicePropertyBusNumber, sizeof(BusNumber), &BusNumber, &DummyLength);

    return HalGetInterruptTranslator(BusType,
                                     BusNumber,
                                     Isa,
                                     IoStack->Parameters.QueryInterface.Size,
                                     IoStack->Parameters.QueryInterface.Version,
                                     (PTRANSLATOR_INTERFACE)IoStack->Parameters.QueryInterface.Interface,
                                     &DummyBridgeBusNumber);
}

NTSTATUS
NTAPI
PiQueryInterface(
    _In_ PISAPNP_FDO_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    PAGED_CODE();
    DPRINT("PiQueryInterface: %p, %p\n", FdoExtension, Irp);

    if (IsEqualGUIDAligned(IoGetCurrentIrpStackLocation(Irp)->Parameters.QueryInterface.InterfaceType,
                           &GUID_TRANSLATOR_INTERFACE_STANDARD))
    {
        return FindInterruptTranslator(FdoExtension, Irp);
    }

    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
PiQueryInterfaceFdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    NTSTATUS Status;

    DPRINT("PiQueryInterfaceFdo: %p, %p\n", DeviceObject, Irp);

    Status = PiQueryInterface(DeviceObject->DeviceExtension, Irp);
    if (NT_SUCCESS(Status))
    {
        Irp->IoStatus.Information = 0;
        Irp->IoStatus.Status = Status;

        return PipPassIrp(DeviceObject, Irp);
    }

    DPRINT1("PiQueryInterfaceFdo: Status %p\n", Status);

    if (Status == STATUS_NOT_SUPPORTED)
        return PipPassIrp(DeviceObject, Irp);

    PipCompleteRequest(Irp, Status, 0);

    return Status;
}

NTSTATUS
NTAPI
PiQueryPnpDeviceState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    Irp->IoStatus.Information |= 0x20;
    Irp->IoStatus.Status = STATUS_SUCCESS;

    return PipPassIrp(DeviceObject, Irp);
}

NTSTATUS
NTAPI
PiSurpriseRemoveFdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiQueryLegacyBusInformationFdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PISAPNP_FDO_EXTENSION FdoExtension;
    PLEGACY_BUS_INFORMATION BusInfo;
    NTSTATUS Status;

    DPRINT("PiQueryLegacyBusInformationFdo: %p, %p\n", DeviceObject, Irp);

    BusInfo = ExAllocatePoolWithTag(PagedPool, sizeof(*BusInfo), 'pasI');
    if (!BusInfo)
    {
        DPRINT1("PiQueryLegacyBusInformationFdo: STATUS_INSUFFICIENT_RESOURCES\n");
        PipCompleteRequest(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    FdoExtension = DeviceObject->DeviceExtension;

    BusInfo->BusTypeGuid = GUID_BUS_TYPE_ISAPNP;
    BusInfo->LegacyBusType = Isa;
    BusInfo->BusNumber = FdoExtension->BusNumber;

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = (ULONG_PTR)BusInfo;

    Status = PipPassIrp(DeviceObject, Irp);

    return Status;
}

NTSTATUS
NTAPI
PiDispatchPnpFdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UCHAR MinorFunction;
    NTSTATUS Status;
  
    PAGED_CODE();

    MinorFunction = IoGetCurrentIrpStackLocation(Irp)->MinorFunction;

    DPRINT("PiDispatchPnpFdo: %p, %p, %X\n", DeviceObject, Irp, MinorFunction);

    if (MinorFunction <= IRP_MN_QUERY_LEGACY_BUS_INFORMATION)
        Status = PiPnpDispatchTableFdo[MinorFunction](DeviceObject, Irp);
    else
        Status = PipPassIrp(DeviceObject, Irp);

    return Status;
}

/* PDO PNP FUNCTIONS ********************************************************/

PISAPNP_DEVICE_INFO
NTAPI
PipReferenceDeviceInformation(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ BOOLEAN IsWakeAndSelectDevice)
{
    PISAPNP_DEVICE_INFO DeviceInfo;

    DeviceInfo = DeviceObject->DeviceExtension;

    if ((!DeviceInfo || (DeviceInfo->Flags & 0x00000001)) ||
        ((DeviceInfo->Flags & 0x00000004) && IsWakeAndSelectDevice))
    {
        DeviceInfo = NULL;
    }
    else if (!(DeviceInfo->Flags & 0x40000000))
    {
        if (IsWakeAndSelectDevice)
        {
            DPRINT1("PipReferenceDeviceInformation: FIXME\n");
            ASSERT(FALSE);
        }
    }

    return DeviceInfo;
}

VOID
NTAPI
PipDereferenceDeviceInformation(
    _In_ PISAPNP_DEVICE_INFO DeviceInfo,
    _In_ BOOLEAN IsWait)
{
    if (DeviceInfo && !(DeviceInfo->Flags & 0x40000000) && IsWait && PipState != 1)
    {
        DPRINT1("PipDereferenceDeviceInformation: FIXME\n");
        ASSERT(FALSE);
    }
}

NTSTATUS
NTAPI
PiStartPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiQueryRemoveStopPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiRemovePdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiCancelRemoveStopPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiStopPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiQueryDeviceRelationsPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiQueryCapabilitiesPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_CAPABILITIES Capabilities;

    DPRINT("PiQueryCapabilitiesPdo: %p, %p\n", DeviceObject, Irp);

    Capabilities = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceCapabilities.Capabilities;

    Capabilities->SystemWake = 0;
    Capabilities->DeviceWake = 0;
    Capabilities->LockSupported = 0;
    Capabilities->EjectSupported = 0;
    Capabilities->Removable = 0;
    Capabilities->DockDevice = 0;
    Capabilities->UniqueID = 1;

    RtlFillMemory(Capabilities->DeviceState, 7, PowerDeviceD3);

    Capabilities->DeviceState[PowerSystemWorking] = PowerDeviceD0;

    if (PipRDPNode && PipRDPNode->ReadDataPortDO == DeviceObject)
    {
        Capabilities->SilentInstall = 1;
        Capabilities->RawDeviceOK = 1;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PiQueryResourcesPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiQueryResourceRequirementsPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiQueryDeviceTextPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiFilterResourceRequirementsPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PipQueryDeviceId(
    _In_ PISAPNP_DEVICE_INFO DeviceInfo,
    _Out_ PWSTR* OutId,
    _Out_ ULONG* OutIdSize)
{
    ULONG IdSize;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("PipQueryDeviceId: %p\n", DeviceInfo);

    if (DeviceInfo->Flags & 0x40000000)
    {
        IdSize = 0x2C; // FIXME

        *OutId = ExAllocatePoolWithTag(PagedPool, IdSize, 'pasI');
        if (!(*OutId))
        {
            DPRINT1("PipQueryDeviceId: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        *OutIdSize = IdSize;

        StringCbPrintfW(*OutId, IdSize, L"ISAPNP\\%s", L"ReadDataPort");

        return STATUS_SUCCESS;
    }

    DPRINT1("PipQueryDeviceId: FIXME\n");
    ASSERT(FALSE);

    return Status;
}

NTSTATUS
NTAPI
PipGetCompatibleDeviceId(
    _In_ PUCHAR DeviceData,
    _In_ LONG Idx,
    _Out_ PWSTR* OutId,
    _Out_ ULONG* OutIdSize)
{
    PWSTR Id;

    DPRINT("PipGetCompatibleDeviceId: %p, %X\n", DeviceData, Idx);

    if (Idx == 0xFFFFFFFF)
    {
        *OutId = Id = ExAllocatePoolWithTag(PagedPool, 4, 'pasI');
        if (!Id)
        {
            DPRINT1("PipGetCompatibleDeviceId: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        *OutIdSize = 4;

        Id[0] = 0;
        Id[1] = 0;

        return STATUS_SUCCESS;
    }

    DPRINT1("PipGetCompatibleDeviceId: FIXME\n");
    ASSERT(FALSE);

    return STATUS_INVALID_PARAMETER;
}

NTSTATUS
NTAPI
PipQueryDeviceUniqueId(
    _In_ PISAPNP_DEVICE_INFO DeviceInfo,
    _Out_ PWSTR* OutId,
    _Out_ ULONG* OutIdSize)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiQueryIdPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PISAPNP_DEVICE_INFO DeviceInfo;
    PIO_STACK_LOCATION IoStack;
    PWSTR CompatibleDeviceId;
    PWSTR DeviceId = NULL;
    PWSTR IdString = NULL;
    PWSTR IdStringEnd;
    PWSTR CurrentId;
    size_t DeviceIdSize;
    size_t CompatibleIdSize;
    size_t Remaining;
    ULONG MaxCompatibleIdSize;
    ULONG DeviceIdLength;
    ULONG DummyLength;
    ULONG IdType;
    ULONG IdSize;
    ULONG ix;
    NTSTATUS Status;

    DPRINT("PiQueryIdPdo: %p, %p\n", DeviceObject, Irp);

    IoStack = Irp->Tail.Overlay.CurrentStackLocation;

    DeviceInfo = PipReferenceDeviceInformation(DeviceObject, FALSE);
    if (!DeviceInfo)
    {
        DPRINT1("PiQueryIdPdo: STATUS_NO_SUCH_DEVICE\n");
        return STATUS_NO_SUCH_DEVICE;
    }

    IdType = IoStack->Parameters.QueryId.IdType;

    if (IdType == BusQueryDeviceID)
    {
        DPRINT("PiQueryIdPdo: BusQueryDeviceID\n");
        Status = PipQueryDeviceId(DeviceInfo, &DeviceId, &DummyLength);
        Irp->IoStatus.Information = (ULONG_PTR)DeviceId;
        goto Exit;
    }

    if (IdType == BusQueryHardwareIDs)
    {
        DPRINT("PiQueryIdPdo: BusQueryHardwareIDs\n");

        if (DeviceInfo->Flags & 0x40000000)
        {
            Status = PipGetCompatibleDeviceId(DeviceInfo->DeviceData, -1, &CompatibleDeviceId, &MaxCompatibleIdSize);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("PiQueryIdPdo: Status %X\n", Status);
                goto Exit;
            }
        }
        else
        {
            Status = PipGetCompatibleDeviceId(DeviceInfo->DeviceData, 0, &CompatibleDeviceId, &MaxCompatibleIdSize);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("PiQueryIdPdo: Status %X\n", Status);
                goto Exit;
            }
        }

        if (CompatibleDeviceId)
        {
            Status = PipQueryDeviceId(DeviceInfo, &DeviceId, &DeviceIdLength);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("PiQueryIdPdo: Status %X\n", Status);
                goto Exit;
            }

            Status = StringCbLengthW(CompatibleDeviceId, MaxCompatibleIdSize, &CompatibleIdSize);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("PiQueryIdPdo: Status %X\n", Status);
                Status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            Status = StringCbLengthW(DeviceId, DeviceIdLength, &DeviceIdSize);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("PiQueryIdPdo: Status %X\n", Status);
                Status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            IdSize = (CompatibleIdSize + DeviceIdSize + 6);

            IdString = ExAllocatePoolWithTag(PagedPool, IdSize, 'pasI');
            if (!IdString)
            {
                Irp->IoStatus.Information = (ULONG_PTR)CompatibleDeviceId;

                if (DeviceId)
                    ExFreePool(DeviceId);

                goto Exit;
            }

            Status = StringCbCopyExW(IdString, IdSize, DeviceId, &IdStringEnd, &Remaining, 0);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("PiQueryIdPdo: Status %X\n", Status);
                ASSERT(FALSE);
                Status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            Status = StringCbCopyExW((IdStringEnd + 1), IdSize, CompatibleDeviceId, &IdStringEnd, &Remaining, 0);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("PiQueryIdPdo: Status %X\n", Status);
                ASSERT(FALSE);
                Status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            IdStringEnd[1] = 0;

            ExFreePool(CompatibleDeviceId);

            Irp->IoStatus.Information = (ULONG_PTR)IdString;

            if (DeviceId)
                ExFreePool(DeviceId);
        }

        goto Exit;
    }

    if (IdType == BusQueryCompatibleIDs)
    {
        DPRINT("PiQueryIdPdo: BusQueryCompatibleIDs\n");

        IdSize = 0x400;

        IdString = ExAllocatePoolWithTag(PagedPool, IdSize, 'pasI');
        if (!IdString)
        {
            DPRINT1("PiQueryIdPdo: allocate failed (BusQueryCompatibleIDs)\n");
            Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;
            goto Exit;
        }

        CurrentId = IdString;

        for (ix = 1; ; ix++)
        {
            ASSERT(ix < 0x100);

            if (DeviceInfo->Flags & 0x40000000)
                ix = -1;

            Status = PipGetCompatibleDeviceId(DeviceInfo->DeviceData, ix, &CompatibleDeviceId, &MaxCompatibleIdSize);
            if (!NT_SUCCESS(Status) || !CompatibleDeviceId)
                break;

            Status = StringCbLengthW(CompatibleDeviceId, MaxCompatibleIdSize, &CompatibleIdSize);
            if (!NT_SUCCESS(Status))
            {
                ASSERT(FALSE);
                break;
            }

            if ((CompatibleIdSize + 4) > IdSize)
            {
                ExFreePoolWithTag(CompatibleDeviceId, 'pasI');
                break;
            }

            Status = StringCbCopyExW(CurrentId, IdSize, CompatibleDeviceId, &IdStringEnd, &Remaining, 0);
            if (!NT_SUCCESS(Status))
            {
                ASSERT(FALSE);
                break;
            }

            CurrentId = (IdStringEnd + 1);
            IdSize = (Remaining - 2);

            ExFreePoolWithTag(CompatibleDeviceId, 'pasI');

            if (ix == -1)
                break;
        }

        if (IdSize == 0x400)
        {
            ExFreePoolWithTag(IdString, 'pasI');
            IdString = NULL;
        }
        else
        {
            *CurrentId = 0;
        }

        Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = (ULONG_PTR)IdString;
        goto Exit;
    }

    if (IdType == BusQueryInstanceID)
    {
        Status = PipQueryDeviceUniqueId(DeviceInfo, &IdString, &DummyLength);
        Irp->IoStatus.Information = (ULONG_PTR)IdString;
        goto Exit;
    }

    DPRINT1("PiQueryIdPdo: IdType %X\n", IdType);
    Status = STATUS_NOT_SUPPORTED;

Exit:

    PipDereferenceDeviceInformation(DeviceInfo, FALSE);

    return Status;
}

NTSTATUS
NTAPI
PiQueryDeviceState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiQueryBusInformationPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiDeviceUsageNotificationPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiSurpriseRemovePdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiIrpNotSupported(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiDispatchPnpPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UCHAR MinorFunction;
    NTSTATUS Status;

    PAGED_CODE();

    MinorFunction = IoGetCurrentIrpStackLocation(Irp)->MinorFunction;

    DPRINT("PiDispatchPnpPdo: %p, %p, %X\n", DeviceObject, Irp, MinorFunction);

    if (MinorFunction > IRP_MN_QUERY_LEGACY_BUS_INFORMATION)
    {
        DPRINT1("PiDispatchPnpPdo: (%p, %p) unknown minor %X\n", DeviceObject, Irp, MinorFunction);
        Status = Irp->IoStatus.Status;
        goto Finish;
    }

    Status = PiPnpDispatchTablePdo[MinorFunction](DeviceObject, Irp);

    if (Status == STATUS_NOT_SUPPORTED)
        Status = Irp->IoStatus.Status;
    else
        Irp->IoStatus.Status = Status;

Finish:

    ASSERT(Status == Irp->IoStatus.Status);

    PipCompleteRequest(Irp, Status, Irp->IoStatus.Information);

    return Status;
}

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
PipOpenRegistryKey(
    _Out_ HANDLE* OutHandle,
    _In_ HANDLE RootDirectory,
    _In_ PUNICODE_STRING ObjectName,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ BOOLEAN IsCreateKey)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    ULONG Disposition;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PipOpenRegistryKey: %p, '%wZ'\n", RootDirectory, ObjectName);

    InitializeObjectAttributes(&ObjectAttributes, ObjectName, OBJ_CASE_INSENSITIVE, RootDirectory, NULL);

    if (IsCreateKey)
        Status = ZwCreateKey(OutHandle, DesiredAccess, &ObjectAttributes, 0, NULL, REG_OPTION_VOLATILE, &Disposition);
    else
        Status = ZwOpenKey(OutHandle, DesiredAccess, &ObjectAttributes);

    return Status;
}

BOOLEAN
NTAPI
PipIsIsolationDisabled(VOID)
{
    PKEY_VALUE_FULL_INFORMATION KeyInfo;
    UNICODE_STRING ObjectName;
    HANDLE KeyHandle;
    HANDLE Handle;
    BOOLEAN Result;
    NTSTATUS Status;

    DPRINT("PipIsIsolationDisabled()\n");

    Status = PipOpenRegistryKey(&Handle, NULL, &PipRegistryPath, KEY_READ, FALSE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PipIsIsolationDisabled: Status %X\n", Status);
        return FALSE;
    }

    RtlInitUnicodeString(&ObjectName, L"Parameters");

    Status = PipOpenRegistryKey(&KeyHandle, Handle, &ObjectName, KEY_READ, FALSE);
    ZwClose(Handle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PipIsIsolationDisabled: Status %X\n", Status);
        return FALSE;
    }

    Status = PipGetRegistryValue(KeyHandle, L"IsolationDisabled", &KeyInfo);
    ZwClose(KeyHandle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PipIsIsolationDisabled: Status %X\n", Status);
        return FALSE;
    }

    if (KeyInfo->Type == REG_DWORD &&
        KeyInfo->DataLength >= sizeof(ULONG) &&
        *(ULONG *)Add2Ptr(KeyInfo, KeyInfo->DataOffset))
    {
        Result = TRUE;
    }
    else
    {
        Result = FALSE;
    }

    ExFreePool(KeyInfo);

    return Result;
}

NTSTATUS
NTAPI
PiDispatchPnp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PISAPNP_FDO_EXTENSION DeviceExtension;
    UCHAR MinorFunction;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PiDispatchPnp: %p, %p\n", DeviceObject, Irp);

    DeviceExtension = DeviceObject->DeviceExtension;
    if (DeviceExtension->Flags & 0x80000000)
    {
        /* FDO */

        if (DeviceExtension->AttachedToDevice)
            return PiDispatchPnpFdo(DeviceObject, Irp);

        PipCompleteRequest(Irp, STATUS_NO_SUCH_DEVICE, 0);

        return STATUS_NO_SUCH_DEVICE;
    }

    /* PDO */

    MinorFunction = IoGetCurrentIrpStackLocation(Irp)->MinorFunction;

    if (DeviceExtension->Flags & 1)
    {
        Status = (MinorFunction == IRP_MN_REMOVE_DEVICE ? STATUS_SUCCESS : STATUS_NO_SUCH_DEVICE);
        PipCompleteRequest(Irp, Status, 0);
        return Status;
    }

    return PiDispatchPnpPdo(DeviceObject, Irp);
}

NTSTATUS
NTAPI
PiDispatchPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiDispatchDevCtl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
PiUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNIMPLEMENTED_DBGBREAK();
}

BOOLEAN
NTAPI
PiNeedDeferISABridge(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT AttachToPdo)
{
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    HANDLE Handle;
    NTSTATUS Status;
    BOOLEAN Result;

    DPRINT("PiNeedDeferISABridge: %p, %p\n", DriverObject, AttachToPdo);

    Status = IoOpenDeviceRegistryKey(AttachToPdo, 1, KEY_READ, &Handle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PiNeedDeferISABridge: Status %p\n", Status);
        return FALSE;
    }

    Status = PipGetRegistryValue(Handle, L"DeferBridge", &ValueInfo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PiNeedDeferISABridge: Status %p\n", Status);
    }

    if (NT_SUCCESS(Status) &&
        ValueInfo->Type == REG_DWORD &&
        ValueInfo->DataLength >= sizeof(ULONG) &&
        *(ULONG *)Add2Ptr(ValueInfo, ValueInfo->DataOffset))
    {
        Result = TRUE;
    }
    else
    {
        Result = FALSE;
    }

    ZwClose(Handle);

    return Result;
}

VOID
NTAPI
PipResetGlobals(VOID)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
PiAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT AttachToPdo)
{
    PISAPNP_FDO_EXTENSION FdoExtension;
    PISAPNP_BUS_EXTENSION BusExtension;
    PISAPNP_BUS_EXTENSION BusEntry;
    PDEVICE_OBJECT Fdo;
    ULONG BusNumber;
    NTSTATUS Status;
 
    PAGED_CODE();
    DPRINT("PiAddDevice: %p, %p\n", DriverObject, AttachToPdo);

    KeWaitForSingleObject(&IsaBusNumberLock, Executive, KernelMode, FALSE, NULL);

    ActiveIsaCount++;

    Status = IoCreateDevice(DriverObject,
                            sizeof(*FdoExtension),
                            NULL,
                            FILE_DEVICE_BUS_EXTENDER,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &Fdo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PiAddDevice: Status %X\n", Status);
        goto Exit;
    }

    FdoExtension = Fdo->DeviceExtension;

    FdoExtension->Flags = 0x80000000; // FDO bit
    FdoExtension->Fdo = Fdo;
    FdoExtension->AttachedToDevice = IoAttachDeviceToDeviceStack(Fdo, AttachToPdo);
    FdoExtension->AttachToPdo = AttachToPdo;

    if (PiNeedDeferISABridge(DriverObject, AttachToPdo))
    {
        BusNumber = RtlFindClearBitsAndSet(BusNumBM, 1, 1);
        ASSERT(BusNumber != 0);
    }
    else
    {
        BusNumber = RtlFindClearBitsAndSet(BusNumBM, 1, 0);
    }

    ASSERT(BusNumber != 0xFFFFFFFF);

    FdoExtension->Rdp = NULL;

    if (ActiveIsaCount != 1)
    {
        ASSERT(PipDriverObject);
        ASSERT(PipBusExtension);

        for (BusExtension = PipBusExtension; BusExtension->Next; BusExtension = BusExtension->Next)
            ;

        BusExtension->Next = BusEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(*BusEntry), 'pasI');
        if (BusEntry)
        {
            BusEntry->BusExtension = FdoExtension;
            BusEntry->Next = NULL;

            goto Finish;
        }

        DPRINT1("PiAddDevice: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (PipFirstInit)
        PipResetGlobals();

    PipDriverObject = DriverObject;

    ASSERT(PipBusExtension == NULL);

    PipBusExtension = BusEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(*BusEntry), 'pasI');
    if (!BusEntry)
    {
        DPRINT1("PiAddDevice: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    BusEntry->BusExtension = FdoExtension;
    PipBusExtension->Next = NULL;

    PipFirstInit = TRUE;

Finish:

    FdoExtension->BusNumber = BusNumber;
    Fdo->Flags &= ~DO_DEVICE_INITIALIZING;

Exit:

    KeSetEvent(&IsaBusNumberLock, IO_NO_INCREMENT, FALSE);
    return Status;
}

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    DPRINT("ISAPNP: DriverEntry(%p, '%wZ')\n", DriverObject, RegistryPath);

    PipDriverObject = DriverObject;

    DriverObject->MajorFunction[IRP_MJ_PNP] = PiDispatchPnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = PiDispatchPower;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PiDispatchDevCtl;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = PiDispatchDevCtl;

    DriverObject->DriverUnload = PiUnload;
    DriverObject->DriverExtension->AddDevice = PiAddDevice;

    PipRegistryPath.Length = RegistryPath->Length;
    PipRegistryPath.MaximumLength = RegistryPath->MaximumLength;

    PipRegistryPath.Buffer = ExAllocatePoolWithTag(PagedPool, PipRegistryPath.MaximumLength, 'pasI');
    if (!PipRegistryPath.Buffer)
    {
        DPRINT1("DriverEntry: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(PipRegistryPath.Buffer, RegistryPath->Buffer, RegistryPath->MaximumLength);

    KeInitializeEvent(&PipDeviceTreeLock, SynchronizationEvent, TRUE);
    KeInitializeEvent(&IsaBusNumberLock, SynchronizationEvent, TRUE);

    BusNumBM = &BusNumBMHeader;

    RtlInitializeBitMap(&BusNumBMHeader, BusNumberBuffer, 0x40);
    RtlClearAllBits(BusNumBM);

    PipIsolationDisabled = PipIsIsolationDisabled();

    return STATUS_SUCCESS;
}

/* EOF */
