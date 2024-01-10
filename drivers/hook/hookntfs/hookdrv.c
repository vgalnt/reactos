/*
 * PROJECT:     Hot-patch hooking.
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Common bus driver.
 * COPYRIGHT:   Copyright 2019-2024 Vadim Galyant <vgal@rambler.ru>
 */

#include "hookdrv.h"

#define NDEBUG
#include <debug.h>

NTSTATUS
NTAPI
HkdFdoStartCompletionRoutine(
     _In_ PDEVICE_OBJECT DeviceObject,
     _In_ PIRP Irp,
     _In_ PVOID Context)
{
    PKEVENT Event = Context;

    if (Irp->PendingReturned)
        KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
HkdFdoPnP(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpStack,
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    PDEVICE_RELATIONS Relations;
    PDEVICE_RELATIONS InRelations;
    POWER_STATE PowerState;
    KEVENT Event;
    ULONG Length;
    ULONG InCount;
    ULONG PdoCount;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("HkdFdoPnP: %p, %p, %X\n", FdoExtension, Irp, IrpStack->MinorFunction);

    switch (IrpStack->MinorFunction)
    {
        case IRP_MN_START_DEVICE:
        {
            KeInitializeEvent(&Event, NotificationEvent, FALSE);

            IoCopyCurrentIrpStackLocationToNext(Irp);
            IoSetCompletionRoutine(Irp, HkdFdoStartCompletionRoutine, &Event, TRUE, TRUE, TRUE);

            Status = IoCallDriver(FdoExtension->LowerDevice, Irp);
            if (Status == STATUS_PENDING)
            {
                KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
                Status = Irp->IoStatus.Status;
            }

            if (NT_SUCCESS(Status))
            {
                PowerState.DeviceState = PowerDeviceD0;
                PoSetPowerState(FdoExtension->SelfDevice, DevicePowerState, PowerState);
            }

            Irp->IoStatus.Status = Status;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);

            return Status;
        }
        case IRP_MN_QUERY_DEVICE_RELATIONS:
        {
            if (IrpStack->Parameters.QueryDeviceRelations.Type != BusRelations)
                break;

            ExAcquireFastMutex(&FdoExtension->Lock);

            InRelations = (PDEVICE_RELATIONS)Irp->IoStatus.Information;

            if (InRelations && !FdoExtension->PdoCount)
            {
                ExReleaseFastMutex(&FdoExtension->Lock);
                break;
            }

            InCount = (InRelations ? InRelations->Count : 0);
            PdoCount = 0;

            Length = (sizeof(DEVICE_RELATIONS) + ((InCount + PdoCount) * sizeof(PDEVICE_OBJECT)));

            Relations = ExAllocatePoolWithTag(PagedPool, Length, HOOKDRV_POOL_TAG);
            if (!Relations)
            {
                DPRINT1("HkdFdoPnP: STATUS_INSUFFICIENT_RESOURCES\n");
                HkDbgBreakPoint();
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            if (InCount)
                RtlCopyMemory(Relations->Objects, InRelations->Objects, (InCount * sizeof(PDEVICE_OBJECT)));

            Relations->Count = (InCount + PdoCount);
            Irp->IoStatus.Information = (ULONG_PTR)Relations;

            DPRINT("HkdFdoPnP: %X, %X\n",  FdoExtension->PdoCount, Relations->Count);

            if (InRelations)
                ExFreePool(InRelations);

            ExReleaseFastMutex(&FdoExtension->Lock);

            Irp->IoStatus.Status = STATUS_SUCCESS;

            break;
        }
        default:
        {
            DPRINT("HkdFdoPnP: %p, %p, %X\n", FdoExtension, Irp, IrpStack->MinorFunction);
            break;
        }
    }

    IoSkipCurrentIrpStackLocation(Irp);

    return IoCallDriver(FdoExtension->LowerDevice, Irp);
}

NTSTATUS
NTAPI
HkdPnP(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PCOMMON_DEVICE_EXTENSION DevExtension;
    PIO_STACK_LOCATION IoStack;

    PAGED_CODE();
    DPRINT("HkdFdoPnP: %p, %p\n", DeviceObject, Irp);

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(IoStack->MajorFunction == IRP_MJ_PNP);

    DevExtension = DeviceObject->DeviceExtension;
    if (DevExtension->IsFdo)
        return HkdFdoPnP(DeviceObject, Irp, IoStack, DeviceObject->DeviceExtension);

    DPRINT1("HkdPnP: STATUS_NOT_IMPLEMENTED (%p, %p)\n", DeviceObject, Irp);
    HkDbgBreakPoint();

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
HkdFdoPower(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    PoStartNextPowerIrp(Irp);
    IoSkipCurrentIrpStackLocation(Irp);

    return PoCallDriver(FdoExtension->LowerDevice, Irp);
}

NTSTATUS
NTAPI
HkdPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PCOMMON_DEVICE_EXTENSION DevExtension;
    PIO_STACK_LOCATION IoStack;

    DPRINT("HkdPower: %p, %p\n", DeviceObject, Irp);

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(IoStack->MajorFunction == IRP_MJ_POWER);

    DevExtension = DeviceObject->DeviceExtension;

    if (DevExtension->IsFdo)
        return HkdFdoPower(DeviceObject->DeviceExtension, Irp);

    DPRINT1("HkdPower: STATUS_NOT_IMPLEMENTED (%p, %p)\n", DeviceObject, Irp);
    HkDbgBreakPoint();

    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
HkdDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    DPRINT1("HkdDriverUnload: FIXME\n");
    HkDbgBreakPoint();
}

NTSTATUS
NTAPI
HkdAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT LowerPdo)
{
    PFDO_DEVICE_EXTENSION FdoExtension = NULL;
    PDEVICE_OBJECT Fdo = NULL;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("HkdAddDevice: %p, %p\n", DriverObject, LowerPdo);

    Status = IoCreateDevice(DriverObject,
                            sizeof(FDO_DEVICE_EXTENSION),
                            NULL,
                            FILE_DEVICE_BUS_EXTENDER,
                            FILE_DEVICE_SECURE_OPEN,
                            TRUE,
                            &Fdo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HkdAddDevice: Status %X\n", Status);
        goto Finish;
    }

    FdoExtension = Fdo->DeviceExtension;
    RtlZeroMemory(FdoExtension, sizeof(FDO_DEVICE_EXTENSION));

    DPRINT("HkdAddDevice: Fdo %p, FdoExtension %p\n", Fdo, FdoExtension);

    FdoExtension->IsFdo = TRUE;

    FdoExtension->SelfDevice = Fdo;
    FdoExtension->LowerPdo = LowerPdo;

    FdoExtension->LowerDevice = IoAttachDeviceToDeviceStack(Fdo, LowerPdo);
    if (!FdoExtension->LowerDevice)
    {
        DPRINT1("HkdAddDevice: STATUS_NO_SUCH_DEVICE\n");
        Status = STATUS_NO_SUCH_DEVICE;
        goto Finish;
    }

    ExInitializeFastMutex(&FdoExtension->Lock);

    Fdo->Flags |= DO_POWER_PAGABLE;
    Fdo->Flags &= ~DO_DEVICE_INITIALIZING;

Finish:

    if (NT_SUCCESS(Status))
        return Status;

    if (!Fdo)
        return Status;

    if (FdoExtension && FdoExtension->LowerDevice)
        IoDetachDevice(FdoExtension->LowerDevice);

    IoDeleteDevice(Fdo);

    return Status;
}

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    DPRINT("DriverEntry: %p, '%wZ'\n", DriverObject, RegistryPath);

  #if _X86_
    HookMain(RegistryPath);
  #else
    #error FIXME!
  #endif

    DriverObject->MajorFunction[IRP_MJ_PNP] = HkdPnP;
    DriverObject->MajorFunction[IRP_MJ_POWER] = HkdPower;
    //DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HkdDeviceControl;
    //DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = HkdSystemControl;

    DriverObject->DriverUnload = HkdDriverUnload;
    DriverObject->DriverExtension->AddDevice = HkdAddDevice;

    return STATUS_SUCCESS;
}

/* EOF */
