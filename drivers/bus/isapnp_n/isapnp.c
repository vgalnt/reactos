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

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
PipGetRegistryValue(
    _In_ HANDLE KeyHandle,
    _In_ PWSTR NameString,
    _Out_ PKEY_VALUE_FULL_INFORMATION* OutValueInfo)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiDispatchPnp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
