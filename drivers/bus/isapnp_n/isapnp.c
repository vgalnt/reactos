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

/* FUNCTIONS ******************************************************************/

VOID
NTAPI
PipLockDeviceDatabase(VOID)
{
    KeWaitForSingleObject(&PipDeviceTreeLock, Executive, KernelMode, FALSE, NULL);
}

VOID
NTAPI
PipCompleteRequest(
    _In_ PIRP Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information)
{
    UNIMPLEMENTED_DBGBREAK();
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
PiQueryDeviceRelationsFdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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

NTSTATUS
NTAPI
PiDispatchPnpPdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
