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
BOOLEAN PipFailStartPdo;
BOOLEAN PipFailStartRdp;
BOOLEAN PipIsolationDisabled;

ULONG PipState = 1;
UCHAR CurrentCsn = 0x00;
UCHAR CurrentDev = 0xFF;

PUCHAR PipReadDataPort;
PUCHAR PipAddressPort;
PUCHAR PipCommandPort;

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

ISAPNP_RDP_RANGE PipReadDataPortRanges[6] =
{
    {0x0274, 0x0277, 4, 0x00},
    {0x03E4, 0x03E7, 4, 0x00},
    {0x0204, 0x0207, 4, 0x00},
    {0x02E4, 0x02E7, 4, 0x00},
    {0x0354, 0x0357, 4, 0x00},
    {0x02F4, 0x02F7, 4, 0x00}
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
PipReportStateChange(
    _In_ ULONG NewState)
{
    DPRINT("PipReportStateChange: State transition: %X to %X\n", PipState, NewState);
    PipState = NewState;
}

VOID
NTAPI
PipWaitForKey(VOID)
{
    DPRINT("PipWaitForKey()\n");

    ASSERT((PipState == 4) || // PiSConfig
           (PipState == 3) || // PiSIsolation
           (PipState == 2));  // PiSSleep

    WRITE_PORT_UCHAR(PipAddressPort, 2);
    WRITE_PORT_UCHAR(PipCommandPort, 2);

    PipReportStateChange(1);

    CurrentCsn = 0x00;
    CurrentDev = 0xFF;
}

VOID
NTAPI
PipDereferenceDeviceInformation(
    _In_ PISAPNP_DEVICE_INFO DeviceInfo,
    _In_ BOOLEAN IsWait)
{
    if (DeviceInfo && !(DeviceInfo->Flags & 0x40000000) && IsWait && PipState != 1)
        PipWaitForKey();
}

ULONG
NTAPI
PipDetermineResourceListSize(
    _In_ PCM_RESOURCE_LIST ResourceList)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptor;
    PCM_FULL_RESOURCE_DESCRIPTOR FullDescriptor;
    ULONG PartialSize;
    ULONG FinalSize;
    ULONG EntrySize;
    ULONG ix;
    ULONG jx;

    /* If we don't have one, that's easy */
    if (!ResourceList)
        return 0;

    /* Start with the minimum size possible */
    FinalSize = FIELD_OFFSET(CM_RESOURCE_LIST, List);

    /* Loop each full descriptor */
    FullDescriptor = ResourceList->List;

    for (ix = 0; ix < ResourceList->Count; ix++)
    {
        /* Start with the minimum size possible */
        PartialSize = FIELD_OFFSET(CM_FULL_RESOURCE_DESCRIPTOR, PartialResourceList) +
        FIELD_OFFSET(CM_PARTIAL_RESOURCE_LIST, PartialDescriptors);

        /* Loop each partial descriptor */
        PartialDescriptor = FullDescriptor->PartialResourceList.PartialDescriptors;

        for (jx = 0; jx < FullDescriptor->PartialResourceList.Count; jx++)
        {
            /* Start with the minimum size possible */
            EntrySize = sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);

            /* Check if there is extra data */
            if (PartialDescriptor->Type == CmResourceTypeDeviceSpecific)
                /* Add that data */
                EntrySize += PartialDescriptor->u.DeviceSpecificData.DataSize;

            /* The size of partial descriptors is bigger */
            PartialSize += EntrySize;

            /* Go to the next partial descriptor */
            PartialDescriptor = Add2Ptr(PartialDescriptor, EntrySize);
        }

        /* The size of full descriptors is bigger */
        FinalSize += PartialSize;

        /* Go to the next full descriptor */
        FullDescriptor = Add2Ptr(FullDescriptor, PartialSize);
    }

    /* Return the final size */
    return FinalSize;
}

PVOID
NTAPI
PipGetMappedAddress(
    _In_ INTERFACE_TYPE InterfaceType,
    _In_ ULONG BusNumber,
    _In_ PHYSICAL_ADDRESS MapAddress,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG AddressSpace,
    _Out_ BOOLEAN* OutIsMapped)
{
    PVOID MappedAddress;
    PHYSICAL_ADDRESS TranslatedAddress;

    PAGED_CODE();

    DPRINT("PipGetMappedAddress: %X, %X, %I64X, %X, %X\n",
           InterfaceType, BusNumber, MapAddress.QuadPart, NumberOfBytes, AddressSpace);

    if (!HalTranslateBusAddress(InterfaceType, BusNumber, MapAddress, &AddressSpace, &TranslatedAddress))
    {
        DPRINT1("PipGetMappedAddress: fail translate %X, %X, %I64X, %X, %X\n",
                InterfaceType, BusNumber, MapAddress.QuadPart, NumberOfBytes, AddressSpace);

        *OutIsMapped = FALSE;
        return NULL;
    }

    if (AddressSpace)
    {
        *OutIsMapped = FALSE;
        return (PVOID)TranslatedAddress.LowPart;
    }

     MappedAddress = MmMapIoSpace(TranslatedAddress, NumberOfBytes, 0);

     *OutIsMapped = (MappedAddress != NULL);

    return MappedAddress;
}

NTSTATUS
NTAPI
PipMapAddressAndCmdPort(
    _In_ PISAPNP_FDO_EXTENSION FdoExtension)
{
    PHYSICAL_ADDRESS PhAddress;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("PipMapAddressAndCmdPort: %p\n", FdoExtension);

    if (!PipAddressPort)
    {
        PhAddress.QuadPart = ADDRESS_PORT;
        FdoExtension->AddressPort = PipAddressPort = PipGetMappedAddress(Isa,
                                                                         0,
                                                                         PhAddress,
                                                                         1,
                                                                         1,
                                                                         &FdoExtension->IsAddressPortMapped);
        if (!PipAddressPort)
        {
            DPRINT1("PipMapAddressAndCmdPort: FIXME\n");
            ASSERT(FALSE);
            //PipLogError(..);
            Status = STATUS_UNSUCCESSFUL;
        }
    }

    if (!PipCommandPort)
    {
        PhAddress.QuadPart = COMMAND_PORT;
        FdoExtension->CommandPort = PipCommandPort = PipGetMappedAddress(Isa,
                                                                         0,
                                                                         PhAddress,
                                                                         1,
                                                                         1,
                                                                         &FdoExtension->IsCommandPortMapped);
        if (!PipCommandPort)
        {
            DPRINT1("PipMapAddressAndCmdPort: FIXME\n");
            ASSERT(FALSE);
            //PipLogError(..);
            Status = STATUS_UNSUCCESSFUL;
        }
    }

    return Status;
}

NTSTATUS
NTAPI
PipMapReadDataPort(
    _In_ PISAPNP_FDO_EXTENSION FdoExtension,
    _In_ PHYSICAL_ADDRESS MapAddress,
    _In_ SIZE_T NumberOfBytes)
{
    PAGED_CODE();
    DPRINT("PipMapReadDataPort: %p, %I64X, %X\n", FdoExtension, MapAddress.QuadPart, NumberOfBytes);

    if (FdoExtension->Rdp && FdoExtension->IsRdpMapped)
    {
        MmUnmapIoSpace((PipReadDataPort - 3), 4);

        FdoExtension->Rdp = NULL;
        PipReadDataPort = NULL;
        FdoExtension->IsRdpMapped = FALSE;
    }

    PipReadDataPort = PipGetMappedAddress(Isa, 0, MapAddress, NumberOfBytes, 1, &FdoExtension->IsRdpMapped);
    if (!PipReadDataPort)
    {
        DPRINT1("PipMapReadDataPort: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PipReadDataPort += 3;
    FdoExtension->Rdp = PipReadDataPort;

    DPRINT("PipMapReadDataPort: ReadDataPort is at %p\n", PipReadDataPort);

    return STATUS_SUCCESS;
}

/* Plug and Play ISA Specification. Version 1.0a May 5, 1994
   Appendix B.1. Initiation LFSR Function
*/
VOID
NTAPI
PipLFSRInitiation(VOID)
{
    ULONG ix;
    UCHAR Value = 0x6A;

    ASSERT(PipState == 1); // PiSWaitForKey

    WRITE_PORT_UCHAR(PipAddressPort, 0);
    WRITE_PORT_UCHAR(PipAddressPort, 0);

    ix = 0x20;
    do
    {
        WRITE_PORT_UCHAR(PipAddressPort, Value);
        Value = ((Value >> 1) | (((UCHAR)(2 * Value) ^ (UCHAR)(Value & 0xFE)) << 6));
        ix--;
    }
    while (ix);

    DPRINT("PipLFSRInitiation: Sent initiation key\n");
    PipReportStateChange(2);
}

VOID
NTAPI
PipIsolation(VOID)
{
    ASSERT((PipState == 4) || // PiSConfig
           (PipState == 3) || // PiSIsolation
           (PipState == 2));  // PiSSleep

    WRITE_PORT_UCHAR(PipAddressPort, 3);
    WRITE_PORT_UCHAR(PipCommandPort, 0);

    CurrentCsn = 0x00;
    CurrentDev = 0xFF;

    DPRINT("PipIsolation: Isolate cards w/o CSN\n");

    PipReportStateChange(3);
}

VOID
NTAPI
PipSleep(VOID)
{
    ASSERT((PipState == 4) || // PiSConfig
           (PipState == 3));  // PiSIsolation

    WRITE_PORT_UCHAR(PipAddressPort, 3);
    WRITE_PORT_UCHAR(PipCommandPort, 0);

    CurrentCsn = 0x00;
    CurrentDev = 0xFF;

    DPRINT("PipSleep: Putting all cards to sleep (we think)\n");

    PipReportStateChange(2);
}

/* Plug and Play ISA Specification. Version 1.0a May 5, 1994
   6. Plug and Play Resources
   6.1. s_serialidSerial Identifier
   Appendix B. LFSR Definition
*/
VOID
NTAPI
PipIsolateCards(
    _Out_ UCHAR* OutNumberOfCards)
{
    ULONG ix;
    USHORT BitIdx;
    UCHAR Checksum;
    UCHAR NumberOfCards = 0;
    UCHAR PnpHeader[9]; // The serial identifier of all Plug and Play ISA cards (Table 2. Plug and Play Header)
    UCHAR Test1;
    UCHAR Test2;
    UCHAR CurrentBit;

    DPRINT("PipIsolateCards()\n");

    PipLFSRInitiation();

    WRITE_PORT_UCHAR(PipAddressPort, 2);
    WRITE_PORT_UCHAR(PipCommandPort, 6);

    DPRINT("PipIsolateCards: Reset CSNs, going to WaitForKey\n");

    PipReportStateChange(1);

    *OutNumberOfCards = 0;

    KeStallExecutionProcessor(2000);
    PipLFSRInitiation();
    PipIsolation();
    KeStallExecutionProcessor(1000);

    DPRINT("PipIsolateCards: Wake all cards without CSN, Isolation\n");

    WRITE_PORT_UCHAR(PipAddressPort, 0);
    WRITE_PORT_UCHAR(PipCommandPort, ((ULONG_PTR)PipReadDataPort >> 2));

    DPRINT("PipIsolateCards: Set RDP to %X\n", PipReadDataPort);

    PipIsolation();

    while (TRUE)
    {
        WRITE_PORT_UCHAR(PipAddressPort, 1);
        KeStallExecutionProcessor(1000);

        RtlZeroMemory(PnpHeader, 9);

        /* Appendix B.2. LFSR Checksum Functions */
        Checksum = 0x6A;

        for (BitIdx = 0; BitIdx < 0x48; BitIdx++) // 72 = 8bit * 9(number of bytes for PnpHeader)
        {
            Test1 = READ_PORT_UCHAR(PipReadDataPort);
            Test2 = READ_PORT_UCHAR(PipReadDataPort);

            CurrentBit = (Test1 == 0x55 && Test2 == 0xAA);
            PnpHeader[BitIdx / 8] |= (CurrentBit << (BitIdx % 8));

            if (BitIdx < 0x40) // 64 = 8bit * 8(PnpHeader minus Checksum (one byte))
            {
                Checksum = ((Checksum >> 1) | ((((Checksum & 2) >> 1) ^ (Checksum & 1) ^ (CurrentBit)) << 7));
            }

            KeStallExecutionProcessor(250);
        }

        DPRINT("PipIsolateCards: Card Bytes: %X %X %X %X %X %X %X %X %X\n",
               PnpHeader[0], PnpHeader[1], PnpHeader[2], PnpHeader[3],
               PnpHeader[4], PnpHeader[5], PnpHeader[6], PnpHeader[7], PnpHeader[8]);

        if (PnpHeader[8] && Checksum != PnpHeader[8])
        {
            DPRINT("PipIsolateCards: invalid read during isolation\n");
            break;
        }

        Test1 = 0;

        for (ix = 0; ix < 9; ix++)
            Test1 |= PnpHeader[ix];

        if (!Test1)
            break;

        if (!(PnpHeader[0] & 0x7F) || !PnpHeader[1])
            break;

        DPRINT("PipIsolateCards: Assigning NumberOfCards %d\n", (NumberOfCards + 1));

        WRITE_PORT_UCHAR(PipAddressPort, 6);

        NumberOfCards++;
        WRITE_PORT_UCHAR(PipCommandPort, NumberOfCards);

        if (READ_PORT_UCHAR(PipReadDataPort) != NumberOfCards)
        {
            NumberOfCards--;

            DPRINT1("PipIsolateCards: Assigning NumberOfCards %X FAILED, bailing!\n", (NumberOfCards + 1));

            PipIsolation();
            PipSleep();

            *OutNumberOfCards = NumberOfCards;

            return;
        }

        PipIsolation();

        DPRINT("PipIsolateCards: Put card in Sleep, other in Isolation\n");
    }

    PipSleep();

    *OutNumberOfCards = NumberOfCards;
}

VOID
NTAPI
PipCleanupAcquiredResources(
    _In_ PISAPNP_FDO_EXTENSION FdoExtension)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
PipStartAndSelectRdp(
    _In_ PISAPNP_DEVICE_INFO DeviceInfo,
    _In_ PISAPNP_FDO_EXTENSION FdoExtension,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PCM_RESOURCE_LIST CmResources)
{
    LONG FinishIdx = -1;
    ULONG RangeIdx;
    ULONG ix;
    UCHAR NumberOfCards;
    NTSTATUS Status;

    DPRINT("PipStartAndSelectRdp: %X\n", DeviceInfo);

    Status = PipMapAddressAndCmdPort(FdoExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PipStartAndSelectRdp: failed to map the address and command ports\n");
        return Status;
    }

    if (CmResources->List[0].PartialResourceList.Count <= 2)
    {
        PipCleanupAcquiredResources(FdoExtension);
        return STATUS_CONFLICTING_ADDRESSES;
    }

    for (ix = 2, RangeIdx = 0; ix < CmResources->List[0].PartialResourceList.Count; ix++, RangeIdx++)
    {
        PipReadDataPortRanges[RangeIdx].NumberOfCards = 0;

        if (!CmResources->List[0].PartialResourceList.PartialDescriptors[ix].u.Port.Length)
            continue;

        Status = PipMapReadDataPort(FdoExtension,
                                    CmResources->List[0].PartialResourceList.PartialDescriptors[ix].u.Port.Start,
                                    CmResources->List[0].PartialResourceList.PartialDescriptors[ix].u.Port.Length);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PipStartAndSelectRdp: failed to map RDP range\n");
            continue;
        }
    
        FinishIdx = ix;

        PipIsolateCards(&NumberOfCards);

        DPRINT("PipStartAndSelectRdp: Found %d cards at RDP %X\n", NumberOfCards, FdoExtension->Rdp);

        PipReadDataPortRanges[RangeIdx].NumberOfCards = NumberOfCards;

        PipWaitForKey();
    }

    if (FinishIdx == -1)
    {
        PipCleanupAcquiredResources(FdoExtension);
        return STATUS_CONFLICTING_ADDRESSES;
    }

    ASSERT((DeviceInfo->Flags & 0x00000080) == 0); // DF_PROCESSING_RDP
    DeviceInfo->Flags |= (0x00000800 | 0x00000080);

    PipCleanupAcquiredResources(FdoExtension);

    IoInvalidateDeviceState(DeviceObject);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PipStartReadDataPort(
    _In_ PISAPNP_DEVICE_INFO DeviceInfo,
    _In_ PISAPNP_FDO_EXTENSION FdoExtension,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PCM_RESOURCE_LIST CmResources)
{
    DPRINT("PipStartReadDataPort: %X\n", DeviceInfo);

    if (!CmResources)
    {
        DPRINT1("PipStartReadDataPort: Start RDP with no resources?\n");
        ASSERT(FALSE);
        return STATUS_UNSUCCESSFUL;
    }

    if (CmResources->List[0].PartialResourceList.Count < 2)
    {
        DPRINT1("PipStartReadDataPort: Start RDP with insufficient resources?\n");
        ASSERT(FALSE);
        return STATUS_UNSUCCESSFUL;
    }

    if (CmResources->List[0].PartialResourceList.Count > 3)
        return PipStartAndSelectRdp(DeviceInfo, FdoExtension, DeviceObject, CmResources);

    /* CmResources->List[0].PartialResourceList.Count == 3 */

    DPRINT1("PipStartReadDataPort: Starting RDP as port %X\n",
           (CmResources->List[0].PartialResourceList.PartialDescriptors[2].u.Port.Start.LowPart + 3));

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiStartPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PISAPNP_DEVICE_INFO DeviceInfo;
    PCM_RESOURCE_LIST CmResources;
    PIO_STACK_LOCATION IoStack;
    SIZE_T Size;
    NTSTATUS Status;

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    CmResources = IoStack->Parameters.StartDevice.AllocatedResources;
    if (!CmResources)
    {
        DPRINT("PiStartPdo: irp with empty CmResourceList\n");
    }

    DPRINT("PiStartPdo: irp received PDO: %X\n", DeviceObject);

    DeviceInfo = PipReferenceDeviceInformation(DeviceObject, TRUE);
    if (!DeviceInfo)
    {
        DPRINT("PiStartPdo: STATUS_NO_SUCH_DEVICE\n");
        return STATUS_NO_SUCH_DEVICE;
    }

    if (!(DeviceInfo->Flags & 0x40000000))
    {
        DPRINT1("PiStartPdo: FIXME\n");
        ASSERT(FALSE);

        goto Exit;
    }

    /* (DeviceInfo->Flags & 0x40000000) == 0x40000000 */

    if (PipFailStartRdp)
    {
        PipDereferenceDeviceInformation(DeviceInfo, TRUE);
        return STATUS_UNSUCCESSFUL;
    }

    Size = PipDetermineResourceListSize(CmResources);

    if (!(DeviceInfo->Flags & 0x00000002) &&
        (DeviceInfo->Flags & 0x00000100) &&
        Size == PipDetermineResourceListSize(DeviceInfo->AllocatedResources) &&
        Size == RtlCompareMemory(DeviceInfo->AllocatedResources, CmResources, Size))
    {
        DeviceInfo->Flags &= ~0x00000100;
        Status = STATUS_SUCCESS;
        IoInvalidateDeviceRelations(DeviceInfo->FdoExtension->AttachToPdo, BusRelations);
    }
    else
    {
        Status = PipStartReadDataPort(DeviceInfo, DeviceInfo->FdoExtension, DeviceObject, CmResources);
        if (NT_SUCCESS(Status) || Status == STATUS_NO_SUCH_DEVICE)
        {
            Status = STATUS_SUCCESS;
            IoInvalidateDeviceRelations(DeviceInfo->FdoExtension->AttachToPdo, BusRelations);
        }

        DeviceInfo->Flags &= ~(0x00000100 | 0x00000040 | 0x00000002);
    }

    DeviceInfo->Flags |= 0x00000010;

    PipDereferenceDeviceInformation(DeviceInfo, TRUE);

Exit:

    DPRINT("PiStartPdo: ret %X\n", Status);
    return Status;
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
PipQueryDeviceResources(
    _In_ PISAPNP_DEVICE_INFO DeviceInfo,
    _Out_ PCM_RESOURCE_LIST* OutCmResources,
    _Out_ ULONG* OutCmResourcesSize)
{
    DPRINT("PipQueryDeviceResources: %p\n", DeviceInfo);

    *OutCmResources = NULL;
    *OutCmResourcesSize = 0;

    if (!DeviceInfo->BootResources)
        return STATUS_SUCCESS;

    *OutCmResources = ExAllocatePoolWithTag(PagedPool, DeviceInfo->BootResourcesSize, 'pasI');
    if (!(*OutCmResources))
    {
        DPRINT1("PipQueryDeviceResources: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(*OutCmResources, DeviceInfo->BootResources, DeviceInfo->BootResourcesSize);

    *OutCmResourcesSize = DeviceInfo->BootResourcesSize;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PiQueryResourcesPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PCM_RESOURCE_LIST CmResources = NULL;
    PISAPNP_DEVICE_INFO DeviceInfo;
    ULONG DummySize;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("PiQueryResourcesPdo: %p, %p\n", DeviceObject, Irp);

    DeviceInfo = PipReferenceDeviceInformation(DeviceObject, FALSE);
    if (!DeviceInfo)
    {
        DPRINT1("PiQueryResourcesPdo: STATUS_NO_SUCH_DEVICE\n");
        Status = STATUS_NO_SUCH_DEVICE;
        goto Exit;
    }

    if (DeviceInfo->Flags & 0x40000000 || (DeviceInfo->Flags & (0x00000008 | 0x00000002)) == 0x00000008)
        Status = PipQueryDeviceResources(DeviceInfo, &CmResources, &DummySize);

    PipDereferenceDeviceInformation(DeviceInfo, FALSE);

    Irp->IoStatus.Information = (ULONG_PTR)CmResources;

Exit:

    DPRINT("PiQueryResourcesPdo: ret Status %X\n", Status);
    return Status;
}

NTSTATUS
NTAPI
PipBuildRDPResources(
    _Out_ PIO_RESOURCE_REQUIREMENTS_LIST* OutIoResources,
    _In_ ULONG Flags)
{
    PIO_RESOURCE_REQUIREMENTS_LIST IoResources;
    PISAPNP_RDP_RANGE RdpRange;
    ULONG CountRequirements;
    ULONG Size;
    ULONG Idx;
    ULONG ix;
    ULONG jx;
    ULONG kx = 0;
    UCHAR MaximumCards = 0;
    UCHAR Count;

    DPRINT("PipBuildRDPResources: Flags %X\n", Flags);

    ASSERT(Flags & 0x40000000); // DF_READ_DATA_PORT

    if (Flags & 0x800)
    {
        CountRequirements = 0;

        for (ix = 0; ix < 6; ix++)
        {
            Count = PipReadDataPortRanges[ix].NumberOfCards;

            if (MaximumCards < Count)
            {
                MaximumCards = Count;
                CountRequirements = 1;
            }
            else if (MaximumCards == Count)
            {
                CountRequirements++;
            }
        }
    }
    else
    {
        CountRequirements = 0xC;
    }

    Size = (sizeof(IO_RESOURCE_LIST) + (3 * sizeof(IO_RESOURCE_REQUIREMENTS_LIST)) +
            (CountRequirements * sizeof(IO_RESOURCE_REQUIREMENTS_LIST)));

    *OutIoResources = IoResources = ExAllocatePoolWithTag(PagedPool, Size, 'pasI');
    if (!IoResources)
    {
        DPRINT1("PipBuildRDPResources: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(*OutIoResources, Size);

    IoResources->BusNumber = 0;
    IoResources->AlternativeLists = 1;

    IoResources->List[0].Count = (CountRequirements + 4);
    IoResources->List[0].Version = 1;
    IoResources->List[0].Revision = 1;

    IoResources->List[0].Descriptors[kx].Type = CM_RESOURCE_PORT_IO;
    IoResources->List[0].Descriptors[kx].ShareDisposition = 1;
    IoResources->List[0].Descriptors[kx].Flags = 0x10;
    IoResources->List[0].Descriptors[kx].u.Port.MinimumAddress.LowPart = COMMAND_PORT;
    IoResources->List[0].Descriptors[kx].u.Port.MaximumAddress.LowPart = COMMAND_PORT;
    IoResources->List[0].Descriptors[kx].u.Port.Length = 1;
    IoResources->List[0].Descriptors[kx].u.Port.Alignment = 1;

    kx++;

    IoResources->List[0].Descriptors[kx].Option = 8;
    IoResources->List[0].Descriptors[kx].Type = CM_RESOURCE_PORT_IO;
    IoResources->List[0].Descriptors[kx].ShareDisposition = 1;
    IoResources->List[0].Descriptors[kx].Flags = 0x10;
    IoResources->List[0].Descriptors[kx].u.Port.MinimumAddress.QuadPart = 0;
    IoResources->List[0].Descriptors[kx].u.Port.MaximumAddress.QuadPart = 0;
    IoResources->List[0].Descriptors[kx].u.Port.Length = 0;
    IoResources->List[0].Descriptors[kx].u.Port.Alignment  = 1;

    kx++;

    IoResources->List[0].Descriptors[kx].Type = CM_RESOURCE_PORT_IO;
    IoResources->List[0].Descriptors[kx].ShareDisposition = 1;
    IoResources->List[0].Descriptors[kx].Flags = 0x10;
    IoResources->List[0].Descriptors[kx].u.Port.MinimumAddress.LowPart = ADDRESS_PORT;
    IoResources->List[0].Descriptors[kx].u.Port.MaximumAddress.LowPart = ADDRESS_PORT;
    IoResources->List[0].Descriptors[kx].u.Port.Length = 1;
    IoResources->List[0].Descriptors[kx].u.Port.Alignment = 1;

    kx++;

    IoResources->List[0].Descriptors[kx].Option = 8;
    IoResources->List[0].Descriptors[kx].Type = CM_RESOURCE_PORT_IO;
    IoResources->List[0].Descriptors[kx].ShareDisposition = 1;
    IoResources->List[0].Descriptors[kx].Flags = 0x10;
    IoResources->List[0].Descriptors[kx].u.Port.MinimumAddress.QuadPart = 0;
    IoResources->List[0].Descriptors[kx].u.Port.MaximumAddress.QuadPart = 0;
    IoResources->List[0].Descriptors[kx].u.Port.Length = 0;
    IoResources->List[0].Descriptors[kx].u.Port.Alignment  = 1;

    kx++;

    RdpRange = PipReadDataPortRanges;

    if (Flags & 0x800)
    {
        for (ix = 0, jx = 0; ix < 6; ix++)
        {
            if (RdpRange->NumberOfCards != MaximumCards)
                continue;

            Idx = (kx + jx);

            IoResources->List[0].Descriptors[Idx].Option = 8;
            IoResources->List[0].Descriptors[Idx].Type = CM_RESOURCE_PORT_IO;
            IoResources->List[0].Descriptors[Idx].ShareDisposition = 1;
            IoResources->List[0].Descriptors[Idx].Flags = 0x10;
            IoResources->List[0].Descriptors[Idx].u.Port.MinimumAddress.LowPart = RdpRange->MinimumAddress;
            IoResources->List[0].Descriptors[Idx].u.Port.MaximumAddress.LowPart = RdpRange->MaximumAddress;
            IoResources->List[0].Descriptors[Idx].u.Port.Length = (RdpRange->MaximumAddress - RdpRange->MinimumAddress + 1);
            IoResources->List[0].Descriptors[Idx].u.Port.Alignment = 1;

            RdpRange++;
            jx++;
        }

        IoResources->List[0].Descriptors[4].Option = 0;
    }
    else
    {
        for (ix = 0; ix < (CountRequirements / 2); ix++)
        {
            Idx = (kx + ix * 2);

            IoResources->List[0].Descriptors[Idx].Type = CM_RESOURCE_PORT_IO;
            IoResources->List[0].Descriptors[Idx].ShareDisposition = 1;
            IoResources->List[0].Descriptors[Idx].Flags = 0x10;
            IoResources->List[0].Descriptors[Idx].u.Port.MinimumAddress.LowPart = RdpRange->MinimumAddress;
            IoResources->List[0].Descriptors[Idx].u.Port.MaximumAddress.LowPart = RdpRange->MaximumAddress;
            IoResources->List[0].Descriptors[Idx].u.Port.Length = (RdpRange->MaximumAddress - RdpRange->MinimumAddress + 1);
            IoResources->List[0].Descriptors[Idx].u.Port.Alignment = 1;

            IoResources->List[0].Descriptors[Idx + 1].Option = 8;
            IoResources->List[0].Descriptors[Idx + 1].Type = CM_RESOURCE_PORT_IO;
            IoResources->List[0].Descriptors[Idx + 1].ShareDisposition = 1;
            IoResources->List[0].Descriptors[Idx + 1].Flags = 0x10;
            IoResources->List[0].Descriptors[Idx + 1].u.Port.MinimumAddress.QuadPart = 0;
            IoResources->List[0].Descriptors[Idx + 1].u.Port.MaximumAddress.QuadPart = 0;
            IoResources->List[0].Descriptors[Idx + 1].u.Port.Length = 0;
            IoResources->List[0].Descriptors[Idx + 1].u.Port.Alignment = 1;

            RdpRange++;
        }
    }

    IoResources->ListSize = Size;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PiQueryResourceRequirementsPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_RESOURCE_REQUIREMENTS_LIST IoResources = NULL;
    PISAPNP_DEVICE_INFO DeviceInfo;
    NTSTATUS Status;

    DPRINT("PiQueryResourceRequirementsPdo: %p, %p\n", DeviceObject, Irp);

    DeviceInfo = PipReferenceDeviceInformation(DeviceObject, FALSE);
    if (!DeviceInfo)
    {
        DPRINT1("PiQueryResourceRequirementsPdo: STATUS_NO_SUCH_DEVICE\n");
        Status = STATUS_NO_SUCH_DEVICE;
        goto Exit;
    }

    Status = STATUS_SUCCESS;

    if (DeviceInfo->Flags & 0x40000000)
    {
        Status = PipBuildRDPResources(&IoResources, DeviceInfo->Flags);
        goto Finish;
    }

    DPRINT1("PiQueryResourceRequirementsPdo: FIXME\n");
    ASSERT(FALSE);

Finish:

    Irp->IoStatus.Information = (ULONG_PTR)IoResources;
    PipDereferenceDeviceInformation(DeviceInfo, FALSE);

Exit:

    DPRINT("PiQueryResourceRequirementsPdo: ret Status %X\n", Status);
    return Status;
}

NTSTATUS
NTAPI
PipGetFunctionIdentifier(
    _In_ PVOID DeviceData,
    _Out_ PWSTR* OutDeviceText,
    _Out_ ULONG* OutDeviceTextSize)
{
    DPRINT("PipGetFunctionIdentifier: %p\n", DeviceData);

    *OutDeviceText = NULL;
    *OutDeviceTextSize = 0;

    if (!DeviceData)
        return STATUS_SUCCESS;

    DPRINT1("PipGetFunctionIdentifier: FIXME \n");
    ASSERT(FALSE);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiQueryDeviceTextPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PISAPNP_DEVICE_INFO DeviceInfo;
    PWSTR DeviceText;
    ULONG DeviceTextSize;
    NTSTATUS Status;

    DPRINT("PiQueryDeviceTextPdo: %p, %p\n", DeviceObject, Irp);

    DeviceInfo = PipReferenceDeviceInformation(DeviceObject, FALSE);
    if (!DeviceInfo)
    {
        DPRINT1("PiQueryDeviceTextPdo: STATUS_NO_SUCH_DEVICE\n");
        return STATUS_NO_SUCH_DEVICE;
    }

    if (IoGetCurrentIrpStackLocation(Irp)->Parameters.QueryDeviceText.DeviceTextType != DeviceTextDescription)
    {
        Status = STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    Status = STATUS_SUCCESS;

    PipGetFunctionIdentifier(DeviceInfo->DeviceData, &DeviceText, &DeviceTextSize);
    if (DeviceText)
    {
        Irp->IoStatus.Information = (ULONG_PTR)DeviceText;
        goto Exit;
    }

    if (!DeviceInfo->CardInfo)
    {
        Irp->IoStatus.Information = 0;
        goto Exit;
    }

    DPRINT1("PiQueryDeviceTextPdo: FIXME \n");
    ASSERT(FALSE);

    Irp->IoStatus.Information = (ULONG_PTR)DeviceText;

Exit:

    PipDereferenceDeviceInformation(DeviceInfo, FALSE);
    return Status;
}

NTSTATUS
NTAPI
PiFilterResourceRequirementsPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_RESOURCE_REQUIREMENTS_LIST IoResources;
    PISAPNP_DEVICE_INFO DeviceInfo;
    NTSTATUS Status;

    DPRINT("PiFilterResourceRequirementsPdo: %p, %p\n", DeviceObject, Irp);

    DeviceInfo = PipReferenceDeviceInformation(DeviceObject, FALSE);
    if (!DeviceInfo)
        return STATUS_NO_SUCH_DEVICE;

    if (!(DeviceInfo->Flags & 0x40000000))
    {
        IoResources = (PVOID)Irp->IoStatus.Information;

        if (!IoResources || IoResources->AlternativeLists != 1)
        {
            DPRINT1("PiFilterResourceRequirementsPdo: STATUS_NOT_SUPPORTED\n");
            Status = STATUS_NOT_SUPPORTED;
            goto Exit;
        }

        DPRINT1("PiFilterResourceRequirementsPdo: FIXME\n");
        ASSERT(FALSE);

        Irp->IoStatus.Information = (ULONG_PTR)IoResources;

        goto Exit;
    }

    DPRINT("PiFilterResourceRequirementsPdo: Filtering resource requirements for RDP\n");

    Status = PipBuildRDPResources(&IoResources, DeviceInfo->Flags);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PiFilterResourceRequirementsPdo: Status %X\n", Status);
        goto Exit;
    }

    if (Irp->IoStatus.Information)
        ExFreePool((PVOID)Irp->IoStatus.Information);

    Irp->IoStatus.Information = (ULONG_PTR)IoResources;

Exit:

    PipDereferenceDeviceInformation(DeviceInfo, FALSE);
    return Status;
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
    PWCHAR Id;
    ULONG IdSize;

    DPRINT("PipQueryDeviceUniqueId: %p\n", DeviceInfo);

    IdSize = 0x12;

    *OutId = Id = ExAllocatePoolWithTag(PagedPool, IdSize, 'pasI');
    if (!Id)
    {
        DPRINT1("PipQueryDeviceUniqueId: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (DeviceInfo->Flags & 0x40000000)
    {
        StringCbPrintfW(Id, IdSize, L"0");
        goto Finish;
    }

    DPRINT1("PipQueryDeviceUniqueId: FIXME\n");
    ASSERT(FALSE);

Finish:

    *OutIdSize = IdSize;

    return STATUS_SUCCESS;
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
    PISAPNP_FDO_EXTENSION FdoExtension;
    PPNP_BUS_INFORMATION BusInfo;
    NTSTATUS Status;

    DPRINT("PiQueryBusInformationPdo: %p, %p\n", DeviceObject, Irp);

    FdoExtension = DeviceObject->DeviceExtension;

    BusInfo = ExAllocatePoolWithTag(PagedPool, sizeof(*BusInfo), 'pasI');
    if (!BusInfo)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        BusInfo = NULL;
        goto Finish;
    }

    BusInfo->BusTypeGuid = GUID_BUS_TYPE_ISAPNP;
    BusInfo->LegacyBusType = 1;
    BusInfo->BusNumber = FdoExtension->BusNumber;

    Status = STATUS_SUCCESS;

Finish:

    Irp->IoStatus.Information = (ULONG_PTR)BusInfo;
    return Status;
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
    return STATUS_NOT_SUPPORTED;
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
