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
KEVENT IsaBusNumberLock;
ULONG BusNumberBuffer[0x40];
ULONG ActiveIsaCount;
RTL_BITMAP BusNumBMHeader;
PRTL_BITMAP BusNumBM;
BOOLEAN PipFirstInit;

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
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiStartFdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
PiQueryInterfaceFdo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiQueryPnpDeviceState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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

    //KeInitializeEvent(&PipDeviceTreeLock, SynchronizationEvent, TRUE);
    KeInitializeEvent(&IsaBusNumberLock, SynchronizationEvent, TRUE);

    BusNumBM = &BusNumBMHeader;

    RtlInitializeBitMap(&BusNumBMHeader, BusNumberBuffer, 0x40);
    RtlClearAllBits(BusNumBM);

    //PipIsolationDisabled = PipIsIsolationDisabled();

    return STATUS_SUCCESS;
}

/* EOF */
