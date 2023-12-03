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

PDRIVER_OBJECT PipDriverObject;
UNICODE_STRING PipRegistryPath;

ULONG BusNumberBuffer[0x40];
RTL_BITMAP BusNumBMHeader;
PRTL_BITMAP BusNumBM;

/* FUNCTIONS ******************************************************************/

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

NTSTATUS
NTAPI
PiAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT TargetDevice)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
    //KeInitializeEvent(&IsaBusNumberLock, SynchronizationEvent, TRUE);

    BusNumBM = &BusNumBMHeader;

    RtlInitializeBitMap(&BusNumBMHeader, BusNumberBuffer, 0x40);
    RtlClearAllBits(BusNumBM);

    //PipIsolationDisabled = PipIsIsolationDisabled();

    return STATUS_SUCCESS;
}
/* EOF */
