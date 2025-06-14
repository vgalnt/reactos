/*
 * PROJECT:     ReactOS USB Hub Driver
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     USBHub power handling functions
 * COPYRIGHT:   Copyright 2017 Vadim Galyant <vgal@rambler.ru>
 */

#include "usbhub.h"

#define NDEBUG
#include <debug.h>

#define NDEBUG_USBHUB_POWER
#include "dbg_uhub.h"

VOID
NTAPI
USBH_CompletePowerIrp(IN PUSBHUB_FDO_EXTENSION HubExtension,
                      IN PIRP Irp,
                      IN NTSTATUS NtStatus)
{
    DPRINT("USBH_CompletePowerIrp: HubExtension - %p, Irp - %p, NtStatus - %lX\n",
           HubExtension,
           Irp,
           NtStatus);

    Irp->IoStatus.Status = NtStatus;

    PoStartNextPowerIrp(Irp);

    if (!InterlockedDecrement(&HubExtension->PendingRequestCount))
    {
        KeSetEvent(&HubExtension->PendingRequestEvent,
                   EVENT_INCREMENT,
                   FALSE);
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

VOID
NTAPI
USBH_HubCancelWakeIrp(IN PUSBHUB_FDO_EXTENSION HubExtension,
                      IN PIRP Irp)
{
    DPRINT("USBH_HubCancelWakeIrp: HubExtension - %p, Irp - %p\n",
           HubExtension,
           Irp);

    IoCancelIrp(Irp);

    if (InterlockedExchange((PLONG)&HubExtension->FdoWaitWakeLock, 1))
    {
        PoStartNextPowerIrp(Irp);
        Irp->IoStatus.Status = STATUS_CANCELLED;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }
}

VOID
NTAPI
USBH_HubESDRecoverySetD3Completion(IN PDEVICE_OBJECT DeviceObject,
                                   IN UCHAR MinorFunction,
                                   IN POWER_STATE PowerState,
                                   IN PVOID Context,
                                   IN PIO_STATUS_BLOCK IoStatus)
{
    DPRINT("USBH_HubESDRecoverySetD3Completion ... \n");

    KeSetEvent((PRKEVENT)Context,
               EVENT_INCREMENT,
               FALSE);
}

NTSTATUS
NTAPI
USBH_HubSetD0(IN PUSBHUB_FDO_EXTENSION HubExtension)
{
    PUSBHUB_FDO_EXTENSION RootHubDevExt;
    NTSTATUS Status;
    KEVENT Event;
    POWER_STATE PowerState;

    DPRINT("USBH_HubSetD0: HubExtension - %p\n", HubExtension);

    RootHubDevExt = USBH_GetRootHubExtension(HubExtension);

    if (RootHubDevExt->SystemPowerState.SystemState != PowerSystemWorking)
    {
        Status = STATUS_INVALID_DEVICE_STATE;
        return Status;
    }

    if (HubExtension->HubFlags & USBHUB_FDO_FLAG_WAIT_IDLE_REQUEST)
    {
        DPRINT("USBH_HubSetD0: HubFlags - %lX\n", HubExtension->HubFlags);

        KeWaitForSingleObject(&HubExtension->IdleEvent,
                              Suspended,
                              KernelMode,
                              FALSE,
                              NULL);
    }

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    PowerState.DeviceState = PowerDeviceD0;

    Status = PoRequestPowerIrp(HubExtension->LowerPDO,
                               IRP_MN_SET_POWER,
                               PowerState,
                               USBH_HubESDRecoverySetD3Completion,
                               &Event,
                               NULL);

    if (Status == STATUS_PENDING)
    {
       Status = KeWaitForSingleObject(&Event,
                                      Suspended,
                                      KernelMode,
                                      FALSE,
                                      NULL);
    }

    while (HubExtension->HubFlags & USBHUB_FDO_FLAG_WAKEUP_START)
    {
        USBH_Wait(10);
    }

    return Status;
}

VOID
NTAPI
USBH_IdleCancelPowerHubWorker(IN PUSBHUB_FDO_EXTENSION HubExtension,
                              IN PVOID Context)
{
    PUSBHUB_IDLE_PORT_CANCEL_CONTEXT WorkItemIdlePower;
    PIRP Irp;

    DPRINT("USBH_IdleCancelPowerHubWorker: ... \n");

    WorkItemIdlePower = Context;

    if (HubExtension &&
        HubExtension->CurrentPowerState.DeviceState != PowerDeviceD0 &&
        HubExtension->HubFlags & USBHUB_FDO_FLAG_DEVICE_STARTED)
    {
        USBH_HubSetD0(HubExtension);
    }

    Irp = WorkItemIdlePower->Irp;
    Irp->IoStatus.Status = STATUS_CANCELLED;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

VOID
NTAPI
USBH_HubQueuePortWakeIrps(IN PUSBHUB_FDO_EXTENSION HubExtension,
                          IN PLIST_ENTRY ListIrps)
{
    PDEVICE_OBJECT PortDevice;
    PUSBHUB_PORT_PDO_EXTENSION PortExtension;
    USHORT NumPorts;
    USHORT Port;
    PIRP WakeIrp;
    KIRQL OldIrql;

    DPRINT("USBH_HubQueuePortWakeIrps ... \n");

    NumPorts = HubExtension->HubDescriptor->bNumberOfPorts;

    InitializeListHead(ListIrps);

    IoAcquireCancelSpinLock(&OldIrql);

    for (Port = 0; Port < NumPorts; ++Port)
    {
        PortDevice = HubExtension->PortData[Port].DeviceObject;

        if (PortDevice)
        {
            PortExtension = PortDevice->DeviceExtension;

            WakeIrp = PortExtension->PdoWaitWakeIrp;
            PortExtension->PdoWaitWakeIrp = NULL;

            if (WakeIrp)
            {
                IoSetCancelRoutine(WakeIrp, NULL);

                PortExtension->PortPdoFlags &= ~0x20;
                InterlockedDecrement(&HubExtension->WaitWakeCouter);

                InsertTailList(ListIrps, &WakeIrp->Tail.Overlay.ListEntry);
            }
        }
    }

    IoReleaseCancelSpinLock(OldIrql);
}

VOID
NTAPI
USBH_HubCompleteQueuedPortWakeIrps(IN PUSBHUB_FDO_EXTENSION HubExtension,
                                   IN PLIST_ENTRY ListIrps,
                                   IN NTSTATUS NtStatus)
{
    PLIST_ENTRY Entry;
    PIRP Irp;

    DPRINT("USBH_HubCompleteQueuedPortWakeIrps: %p\n", HubExtension);

    while (!IsListEmpty(ListIrps))
    {
        Entry = RemoveHeadList(ListIrps);
        Irp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);

        USBH_CompletePowerIrp(HubExtension, Irp, NtStatus);
    }
}

VOID
NTAPI
USBH_HubCompletePortWakeIrps(IN PUSBHUB_FDO_EXTENSION HubExtension,
                             IN NTSTATUS NtStatus)
{
    LIST_ENTRY ListIrps;

    DPRINT("USBH_HubCompletePortWakeIrps: NtStatus - %x\n", NtStatus);

    if (HubExtension->HubFlags & USBHUB_FDO_FLAG_DEVICE_STARTED)
    {
        USBH_HubQueuePortWakeIrps(HubExtension, &ListIrps);

        USBH_HubCompleteQueuedPortWakeIrps(HubExtension,
                                           &ListIrps,
                                           NtStatus);
    }
}

VOID
NTAPI
USBH_FdoPoRequestD0Completion(IN PDEVICE_OBJECT DeviceObject,
                              IN UCHAR MinorFunction,
                              IN POWER_STATE PowerState,
                              IN PVOID Context,
                              IN PIO_STATUS_BLOCK IoStatus)
{
    PUSBHUB_FDO_EXTENSION HubExtension;

    DPRINT("USBH_FdoPoRequestD0Completion ... \n");

    HubExtension = Context;

    USBH_HubCompletePortWakeIrps(HubExtension, STATUS_SUCCESS);

    HubExtension->HubFlags &= ~USBHUB_FDO_FLAG_WAKEUP_START;

    if (!InterlockedDecrement(&HubExtension->PendingRequestCount))
    {
        KeSetEvent(&HubExtension->PendingRequestEvent,
                   EVENT_INCREMENT,
                   FALSE);
    }
}

VOID
NTAPI
USBH_CompletePortWakeIrpsWorker(IN PUSBHUB_FDO_EXTENSION HubExtension,
                                IN PVOID Context)
{
    DPRINT1("USBH_CompletePortWakeIrpsWorker: UNIMPLEMENTED. FIXME\n");
    DbgBreakPoint();
}

NTSTATUS
NTAPI
USBH_FdoWWIrpIoCompletion(IN PDEVICE_OBJECT DeviceObject,
                          IN PIRP Irp,
                          IN PVOID Context)
{
    PUSBHUB_FDO_EXTENSION HubExtension;
    NTSTATUS Status;
    KIRQL OldIrql;
    POWER_STATE PowerState;
    PIRP WakeIrp;

    DPRINT("USBH_FdoWWIrpIoCompletion: DeviceObject - %p, Irp - %p\n",
            DeviceObject,
            Irp);

    HubExtension = Context;

    Status = Irp->IoStatus.Status;

    IoAcquireCancelSpinLock(&OldIrql);

    HubExtension->HubFlags &= ~USBHUB_FDO_FLAG_PENDING_WAKE_IRP;

    WakeIrp = InterlockedExchangePointer((PVOID *)&HubExtension->PendingWakeIrp,
                                         NULL);

    if (!InterlockedDecrement(&HubExtension->PendingRequestCount))
    {
        KeSetEvent(&HubExtension->PendingRequestEvent,
                   EVENT_INCREMENT,
                   FALSE);
    }

    IoReleaseCancelSpinLock(OldIrql);

    DPRINT("USBH_FdoWWIrpIoCompletion: Status - %lX\n", Status);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("USBH_FdoWWIrpIoCompletion: DbgBreakPoint() \n");
        DbgBreakPoint();
    }
    else
    {
        PowerState.DeviceState = PowerDeviceD0;

        HubExtension->HubFlags |= USBHUB_FDO_FLAG_WAKEUP_START;
        InterlockedIncrement(&HubExtension->PendingRequestCount);

        Status = STATUS_SUCCESS;

        PoRequestPowerIrp(HubExtension->LowerPDO,
                          IRP_MN_SET_POWER,
                          PowerState,
                          USBH_FdoPoRequestD0Completion,
                          (PVOID)HubExtension,
                          NULL);
    }

    if (!WakeIrp)
    {
        if (!InterlockedExchange(&HubExtension->FdoWaitWakeLock, 1))
        {
            Status = STATUS_MORE_PROCESSING_REQUIRED;
        }
    }

    DPRINT("USBH_FdoWWIrpIoCompletion: Status - %lX\n", Status);

    if (Status != STATUS_MORE_PROCESSING_REQUIRED)
    {
        PoStartNextPowerIrp(Irp);
    }

    return Status;
}

NTSTATUS
NTAPI
USBH_PowerIrpCompletion(IN PDEVICE_OBJECT DeviceObject,
                        IN PIRP Irp,
                        IN PVOID Context)
{
    PUSBHUB_FDO_EXTENSION HubExtension;
    PIO_STACK_LOCATION IoStack;
    DEVICE_POWER_STATE OldDeviceState;
    NTSTATUS Status;
    POWER_STATE PowerState;

    DPRINT("USBH_PowerIrpCompletion: DeviceObject - %p, Irp - %p\n",
           DeviceObject,
           Irp);

    HubExtension = Context;

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    PowerState = IoStack->Parameters.Power.State;

    Status = Irp->IoStatus.Status;
    DPRINT("USBH_PowerIrpCompletion: Status - %lX\n", Status);

    if (!NT_SUCCESS(Status))
    {
        if (PowerState.DeviceState == PowerDeviceD0)
        {
            PoStartNextPowerIrp(Irp);
            HubExtension->HubFlags &= ~USBHUB_FDO_FLAG_SET_D0_STATE;
        }
    }
    else if (PowerState.DeviceState == PowerDeviceD0)
    {
        HubExtension->HubFlags &= ~USBHUB_FDO_FLAG_SET_D0_STATE;

        OldDeviceState = HubExtension->CurrentPowerState.DeviceState;
        HubExtension->CurrentPowerState.DeviceState = PowerDeviceD0;

        DPRINT("USBH_PowerIrpCompletion: OldDeviceState - %x\n", OldDeviceState);

        if (HubExtension->HubFlags & USBHUB_FDO_FLAG_HIBERNATE_STATE)
        {
            DPRINT1("USBH_PowerIrpCompletion: USBHUB_FDO_FLAG_HIBERNATE_STATE. FIXME\n");
            DbgBreakPoint();
        }

        HubExtension->HubFlags &= ~USBHUB_FDO_FLAG_HIBERNATE_STATE;

        if (OldDeviceState == PowerDeviceD3)
        {
            DPRINT1("USBH_PowerIrpCompletion: PowerDeviceD3. FIXME\n");
            DbgBreakPoint();
        }

        if (!(HubExtension->HubFlags & USBHUB_FDO_FLAG_DEVICE_STOPPED) &&
            HubExtension->HubFlags & USBHUB_FDO_FLAG_DO_ENUMERATION)
        {
            USBH_SubmitStatusChangeTransfer(HubExtension);
        }

        DPRINT("USBH_PowerIrpCompletion: Status - %lX\n", Status);

        if (Status != STATUS_MORE_PROCESSING_REQUIRED)
        {
            PoStartNextPowerIrp(Irp);
            return Status;
        }
    }

    return Status;
}

VOID
NTAPI
USBH_FdoDeferPoRequestCompletion(IN PDEVICE_OBJECT DeviceObject,
                                 IN UCHAR MinorFunction,
                                 IN POWER_STATE PowerState,
                                 IN PVOID Context,
                                 IN PIO_STATUS_BLOCK IoStatus)
{
    PUSBHUB_FDO_EXTENSION Extension;
    PUSBHUB_FDO_EXTENSION HubExtension = NULL;
    PIRP PowerIrp;
    PIO_STACK_LOCATION IoStack;

    DPRINT("USBH_FdoDeferPoRequestCompletion ... \n");

    Extension = Context;

    PowerIrp = Extension->PowerIrp;

    if (Extension->Common.ExtensionType == USBH_EXTENSION_TYPE_HUB)
    {
        HubExtension = Context;
    }

    IoStack = IoGetCurrentIrpStackLocation(PowerIrp);

    if (IoStack->Parameters.Power.State.SystemState == PowerSystemWorking &&
        HubExtension && HubExtension->LowerPDO == HubExtension->RootHubPdo)
    {
        HubExtension->SystemPowerState.SystemState = PowerSystemWorking;
        USBH_CheckIdleDeferred(HubExtension);
    }

    IoCopyCurrentIrpStackLocationToNext(PowerIrp);
    PoStartNextPowerIrp(PowerIrp);
    PoCallDriver(Extension->LowerDevice, PowerIrp);
}

NTSTATUS
NTAPI
USBH_FdoPower(IN PUSBHUB_FDO_EXTENSION HubExtension,
              IN PIRP Irp,
              IN UCHAR Minor)
{
    NTSTATUS Status;
    PIO_STACK_LOCATION IoStack;
    POWER_STATE PowerState;
    POWER_STATE DevicePwrState;
    BOOLEAN IsAllPortsD3;
    PUSBHUB_PORT_DATA PortData;
    PDEVICE_OBJECT PdoDevice;
    PUSBHUB_PORT_PDO_EXTENSION PortExtension;
    ULONG Port;

    DPRINT_PWR("USBH_FdoPower: HubExtension - %p, Irp - %p, Minor - %X\n",
               HubExtension,
               Irp,
               Minor);

    switch (Minor)
    {
        case IRP_MN_WAIT_WAKE:
            DPRINT_PWR("USBH_FdoPower: IRP_MN_WAIT_WAKE\n");

            IoCopyCurrentIrpStackLocationToNext(Irp);

            IoSetCompletionRoutine(Irp,
                                   USBH_FdoWWIrpIoCompletion,
                                   HubExtension,
                                   TRUE,
                                   TRUE,
                                   TRUE);

            PoStartNextPowerIrp(Irp);
            IoMarkIrpPending(Irp);
            PoCallDriver(HubExtension->LowerDevice, Irp);

            return STATUS_PENDING;

        case IRP_MN_POWER_SEQUENCE:
            DPRINT_PWR("USBH_FdoPower: IRP_MN_POWER_SEQUENCE\n");
            break;

        case IRP_MN_SET_POWER:
            DPRINT_PWR("USBH_FdoPower: IRP_MN_SET_POWER\n");

            IoStack = IoGetCurrentIrpStackLocation(Irp);
            DPRINT_PWR("USBH_FdoPower: IRP_MN_SET_POWER/DevicePowerState\n");
            PowerState = IoStack->Parameters.Power.State;

            if (IoStack->Parameters.Power.Type == DevicePowerState)
            {
                DPRINT_PWR("USBH_FdoPower: PowerState - %x\n",
                           PowerState.DeviceState);

                if (HubExtension->CurrentPowerState.DeviceState == PowerState.DeviceState)
                {
                    IoCopyCurrentIrpStackLocationToNext(Irp);

                    PoStartNextPowerIrp(Irp);
                    IoMarkIrpPending(Irp);
                    PoCallDriver(HubExtension->LowerDevice, Irp);

                    return STATUS_PENDING;
                }

                switch (PowerState.DeviceState)
                {
                    case PowerDeviceD0:
                        if (!(HubExtension->HubFlags & USBHUB_FDO_FLAG_SET_D0_STATE))
                        {
                            HubExtension->HubFlags &= ~(USBHUB_FDO_FLAG_NOT_D0_STATE |
                                                        USBHUB_FDO_FLAG_DEVICE_STOPPING);

                            HubExtension->HubFlags |= USBHUB_FDO_FLAG_SET_D0_STATE;

                            IoCopyCurrentIrpStackLocationToNext(Irp);

                            IoSetCompletionRoutine(Irp,
                                                   USBH_PowerIrpCompletion,
                                                   HubExtension,
                                                   TRUE,
                                                   TRUE,
                                                   TRUE);
                        }
                        else
                        {
                            IoCopyCurrentIrpStackLocationToNext(Irp);
                            PoStartNextPowerIrp(Irp);
                        }

                        IoMarkIrpPending(Irp);
                        PoCallDriver(HubExtension->LowerDevice, Irp);
                        return STATUS_PENDING;

                    case PowerDeviceD1:
                    case PowerDeviceD2:
                    case PowerDeviceD3:
                        if (HubExtension->ResetRequestCount)
                        {
                            IoCancelIrp(HubExtension->ResetPortIrp);

                            KeWaitForSingleObject(&HubExtension->ResetEvent,
                                                  Executive,
                                                  KernelMode,
                                                  FALSE,
                                                  NULL);
                        }

                        if (!(HubExtension->HubFlags & USBHUB_FDO_FLAG_DEVICE_STOPPED))
                        {
                            HubExtension->HubFlags |= (USBHUB_FDO_FLAG_NOT_D0_STATE |
                                                       USBHUB_FDO_FLAG_DEVICE_STOPPING);

                            IoCancelIrp(HubExtension->SCEIrp);

                            KeWaitForSingleObject(&HubExtension->StatusChangeEvent,
                                                  Executive,
                                                  KernelMode,
                                                  FALSE,
                                                  NULL);
                        }

                        HubExtension->CurrentPowerState.DeviceState = PowerState.DeviceState;

                        if (HubExtension->HubFlags & USBHUB_FDO_FLAG_DO_SUSPENSE &&
                            USBH_CheckIdleAbort(HubExtension, TRUE, TRUE) == TRUE)
                        {
                            HubExtension->HubFlags &= ~(USBHUB_FDO_FLAG_NOT_D0_STATE |
                                                        USBHUB_FDO_FLAG_DEVICE_STOPPING);

                            HubExtension->CurrentPowerState.DeviceState = PowerDeviceD0;

                            USBH_SubmitStatusChangeTransfer(HubExtension);

                            PoStartNextPowerIrp(Irp);

                            Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
                            IoCompleteRequest(Irp, IO_NO_INCREMENT);

                            HubExtension->HubFlags &= ~USBHUB_FDO_FLAG_DO_SUSPENSE;

                            KeReleaseSemaphore(&HubExtension->IdleSemaphore,
                                               LOW_REALTIME_PRIORITY,
                                               1,
                                               FALSE);

                            return STATUS_UNSUCCESSFUL;
                        }

                        IoCopyCurrentIrpStackLocationToNext(Irp);

                        IoSetCompletionRoutine(Irp,
                                               USBH_PowerIrpCompletion,
                                               HubExtension,
                                               TRUE,
                                               TRUE,
                                               TRUE);

                        PoStartNextPowerIrp(Irp);
                        IoMarkIrpPending(Irp);
                        PoCallDriver(HubExtension->LowerDevice, Irp);

                        if (HubExtension->HubFlags & USBHUB_FDO_FLAG_DO_SUSPENSE)
                        {
                            HubExtension->HubFlags &= ~USBHUB_FDO_FLAG_DO_SUSPENSE;

                            KeReleaseSemaphore(&HubExtension->IdleSemaphore,
                                               LOW_REALTIME_PRIORITY,
                                               1,
                                               FALSE);
                        }

                        return STATUS_PENDING;

                    default:
                        DPRINT1("USBH_FdoPower: Unsupported PowerState.DeviceState\n");
                        DbgBreakPoint();
                        break;
                }
            }
            else
            {
                if (PowerState.SystemState != PowerSystemWorking)
                {
                    USBH_GetRootHubExtension(HubExtension)->SystemPowerState.SystemState =
                                                            PowerState.SystemState;
                }

                if (PowerState.SystemState == PowerSystemHibernate)
                {
                    HubExtension->HubFlags |= USBHUB_FDO_FLAG_HIBERNATE_STATE;
                }

                PortData = HubExtension->PortData;

                IsAllPortsD3 = TRUE;

                if (PortData && HubExtension->HubDescriptor)
                {
                    for (Port = 0;
                         Port < HubExtension->HubDescriptor->bNumberOfPorts;
                         Port++)
                    {
                        PdoDevice = PortData[Port].DeviceObject;

                        if (PdoDevice)
                        {
                            PortExtension = PdoDevice->DeviceExtension;

                            if (PortExtension->CurrentPowerState.DeviceState != PowerDeviceD3)
                            {
                                IsAllPortsD3 = FALSE;
                                break;
                            }
                        }
                    }
                }

                if (PowerState.SystemState == PowerSystemWorking)
                {
                    DevicePwrState.DeviceState = PowerDeviceD0;
                }
                else if (HubExtension->HubFlags & USBHUB_FDO_FLAG_PENDING_WAKE_IRP ||
                         !IsAllPortsD3)
                {
                    DevicePwrState.DeviceState = HubExtension->DeviceState[PowerState.SystemState];

                    if (DevicePwrState.DeviceState == PowerDeviceUnspecified)
                    {
                        goto Exit;
                    }
                }
                else
                {
                    DevicePwrState.DeviceState = PowerDeviceD3;
                }

                if (DevicePwrState.DeviceState != HubExtension->CurrentPowerState.DeviceState &&
                    HubExtension->HubFlags & USBHUB_FDO_FLAG_DEVICE_STARTED)
                {
                    HubExtension->PowerIrp = Irp;

                    IoMarkIrpPending(Irp);

                    if (PoRequestPowerIrp(HubExtension->LowerPDO,
                                          IRP_MN_SET_POWER,
                                          DevicePwrState,
                                          USBH_FdoDeferPoRequestCompletion,
                                          (PVOID)HubExtension,
                                          NULL) == STATUS_PENDING)
                    {
                        return STATUS_PENDING;
                    }

                    IoCopyCurrentIrpStackLocationToNext(Irp);
                    PoStartNextPowerIrp(Irp);
                    PoCallDriver(HubExtension->LowerDevice, Irp);

                    return STATUS_PENDING;
                }

            Exit:

                HubExtension->SystemPowerState.SystemState = PowerState.SystemState;

                if (PowerState.SystemState == PowerSystemWorking)
                {
                    USBH_CheckIdleDeferred(HubExtension);
                }

                IoCopyCurrentIrpStackLocationToNext(Irp);
                PoStartNextPowerIrp(Irp);

                return PoCallDriver(HubExtension->LowerDevice, Irp);
            }

            break;

        case IRP_MN_QUERY_POWER:
            DPRINT_PWR("USBH_FdoPower: IRP_MN_QUERY_POWER\n");
            break;

        default:
            DPRINT1("USBH_FdoPower: unknown IRP_MN_POWER!\n");
            break;
    }

    IoCopyCurrentIrpStackLocationToNext(Irp);
    PoStartNextPowerIrp(Irp);
    Status = PoCallDriver(HubExtension->LowerDevice, Irp);

    return Status;
}

VOID
NTAPI
USBH_WaitWakeCancel(IN PDEVICE_OBJECT DeviceObject,
                    IN PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
USBH_PdoWaitWake(IN PUSBHUB_PORT_PDO_EXTENSION PortExtension,
                 IN PIRP Irp)
{
    PUSBHUB_FDO_EXTENSION HubExtension;
    PDRIVER_CANCEL CancelRoutine;
    LONG WaitWakeCouter;
    KIRQL Irql;

    DPRINT("USBH_PdoWaitWake: %p, %p\n", PortExtension, Irp);

    HubExtension = PortExtension->HubExtension;

    if (PortExtension->CurrentPowerState.DeviceState != PowerDeviceD0 ||
        (HubExtension->HubFlags & 4))
    {
        DPRINT1("USBH_PdoWaitWake: STATUS_INVALID_DEVICE_STATE\n");
        USBH_CompletePowerIrp(HubExtension, Irp, STATUS_INVALID_DEVICE_STATE);
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (!(PortExtension->PortPdoFlags & 0x10))
    {
        DPRINT1("USBH_PdoWaitWake: STATUS_NOT_SUPPORTED\n");
        USBH_CompletePowerIrp(HubExtension, Irp, STATUS_NOT_SUPPORTED);
        return STATUS_NOT_SUPPORTED;
    }

    IoAcquireCancelSpinLock(&Irql);

    if (PortExtension->PdoWaitWakeIrp)
    {
        DPRINT1("USBH_PdoWaitWake: STATUS_DEVICE_BUSY\n");
        IoReleaseCancelSpinLock(Irql);
        USBH_CompletePowerIrp(HubExtension, Irp, STATUS_DEVICE_BUSY);
        return STATUS_DEVICE_BUSY;
    }

    CancelRoutine = IoSetCancelRoutine(Irp, USBH_WaitWakeCancel);
    ASSERT(CancelRoutine == NULL);

    if (Irp->Cancel)
    {
        DPRINT1("USBH_PdoWaitWake: Irp->Cancel FIXME\n");
        UNIMPLEMENTED_DBGBREAK();
        return STATUS_PENDING;
    }

    PortExtension->PortPdoFlags |= 0x20;
    PortExtension->PdoWaitWakeIrp = Irp;

    Irp->IoStatus.Information = (ULONG_PTR)PortExtension;
    IoMarkIrpPending(Irp);

    WaitWakeCouter = InterlockedIncrement(&HubExtension->WaitWakeCouter);

    IoReleaseCancelSpinLock(Irql);

    if (WaitWakeCouter == 1 && !(HubExtension->HubFlags & 0x80))
    {
        DPRINT1("USBH_PdoWaitWake: %p, %p\n", HubExtension, PortExtension);
        USBH_FdoSubmitWaitWakeIrp(HubExtension);
    }

    return STATUS_PENDING;
}

NTSTATUS
NTAPI
USBH_SyncSuspendPort(IN PUSBHUB_FDO_EXTENSION HubExtension,
                     IN USHORT PortNumber)
{
    PUSBHUB_PORT_DATA PortData;
    BM_REQUEST_TYPE RequestType;
    NTSTATUS Status;

    DPRINT1("USBH_SyncSuspendPort: %p, %X\n", HubExtension, PortNumber);

    PortData = &HubExtension->PortData[PortNumber - 1];

    RequestType.B = 0x23;

    Status = USBH_Transact(HubExtension,
                           NULL,
                           0,
                           BMREQUEST_DEVICE_TO_HOST,
                           URB_FUNCTION_CLASS_OTHER,
                           RequestType,
                           USB_REQUEST_SET_FEATURE,
                           2,
                           PortNumber);

    if (NT_SUCCESS(Status))
        PortData->PortStatus.AsUlong32 |= 4;

    return Status;
}

VOID
NTAPI
USBH_SyncFeatureRequest(IN PDEVICE_OBJECT DeviceObject,
                        IN USHORT FeatureSelector,
                        IN USHORT Index,
                        IN USHORT Recipient,
                        IN BOOLEAN IsClearOrSet)
{
    PURB Urb;
    USHORT Function;

    DPRINT1("USBH_SyncFeatureRequest: %p, %X, %X, %X, %X\n",
            DeviceObject, FeatureSelector, IsClearOrSet, Index, Recipient);

    Urb = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Urb), 'BUHU');
    if (!Urb)
    {
        DPRINT1("USBH_SyncFeatureRequest: allocate failed\n");
        return;
    }

    if (IsClearOrSet)
    {
        if (Recipient == 0)
            Function = URB_FUNCTION_CLEAR_FEATURE_TO_DEVICE;
        else if (Recipient == 1)
            Function = URB_FUNCTION_CLEAR_FEATURE_TO_INTERFACE;
        else if (Recipient == 2)
            Function = URB_FUNCTION_CLEAR_FEATURE_TO_ENDPOINT;
        else
        {
            DPRINT1("USBH_SyncFeatureRequest: !? Recipient %X\n", Recipient);
            ASSERT(FALSE);
        }
    }
    else
    {
        if (Recipient == 0)
            Function = URB_FUNCTION_SET_FEATURE_TO_DEVICE;
        else if (Recipient == 1)
            Function = URB_FUNCTION_SET_FEATURE_TO_INTERFACE;
        else if (Recipient == 2)
            Function = URB_FUNCTION_SET_FEATURE_TO_ENDPOINT;
        else
        {
            DPRINT1("USBH_SyncFeatureRequest: !? Recipient %X\n", Recipient);
            ASSERT(FALSE);
        }
    }

    Urb->UrbHeader.Function = Function;
    Urb->UrbHeader.Length = sizeof(*Urb);

    Urb->UrbControlFeatureRequest.FeatureSelector = FeatureSelector;
    Urb->UrbControlFeatureRequest.Index = Index;

    Urb->UrbControlDescriptorRequest.UrbLink = NULL;

    USBH_SyncSubmitUrb(DeviceObject, Urb);

    ExFreePoolWithTag(Urb, 'BUHU');
}

NTSTATUS
NTAPI
USBH_SetPowerD1orD2(IN PIRP Irp,
                    IN PUSBHUB_PORT_PDO_EXTENSION PortExtension)
{
    PIO_STACK_LOCATION IoStack;
    PUSBHUB_FDO_EXTENSION HubExtension;
    NTSTATUS Status;

    HubExtension = PortExtension->HubExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (PortExtension->CurrentPowerState.DeviceState == PowerDeviceD1 ||
        PortExtension->CurrentPowerState.DeviceState == PowerDeviceD2)
    {
        InterlockedDecrement(&PortExtension->PendingDevicePoRequest);
        USBH_CompletePowerIrp(HubExtension, Irp, STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }

    if (PortExtension->PortPdoFlags & 0x20)
    {
        DPRINT1("USBH_SetPowerD1orD2: Device is Enabled for REMOTE WAKEUP\n");
        USBH_SyncFeatureRequest(PortExtension->Common.SelfDevice, 1, 0, 0, FALSE);
        PortExtension->PortPdoFlags |= 0x01000000;
    }

    Status = USBH_SyncSuspendPort(HubExtension, PortExtension->PortNumber);

    PortExtension->PortPdoFlags |= 0x2000;
    PortExtension->CurrentPowerState = IoStack->Parameters.Power.State;

    DPRINT1("USBH_SetPowerD1orD2: CurrentPowerState %X\n", PortExtension->CurrentPowerState);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("USBH_SetPowerD1orD2: Set D1/D2 Failure, Status %x\n", Status);
        Status = STATUS_SUCCESS;
    }

    DPRINT1("USBH_SetPowerD1orD2: Setting HU (%p) to D%d, Status %X\n",
           HubExtension->Common.SelfDevice, (PortExtension->CurrentPowerState.DeviceState - 1), Status);

    InterlockedDecrement(&PortExtension->PendingDevicePoRequest);

    DPRINT1("USBH_SetPowerD1orD2: (%p, %p) TransitCount %X\n", PortExtension, Irp, PortExtension->PendingDevicePoRequest);

    USBH_CompletePowerIrp(HubExtension, Irp, Status);
    return Status;
}

VOID
NTAPI
USBH_CompletePortIdleNotification(IN PUSBHUB_PORT_PDO_EXTENSION PortExtension)
{
    PIRP IdleNotificationIrp = NULL;
    KIRQL Irql;

    DPRINT1("USBH_CompletePortIdleNotification: %p\n", PortExtension);

    IoAcquireCancelSpinLock(&Irql);

    IdleNotificationIrp = PortExtension->IdleNotificationIrp;
    if (IdleNotificationIrp)
    {
        if (IoSetCancelRoutine(IdleNotificationIrp, NULL))
        {
            PortExtension->IdleNotificationIrp = NULL;
            PortExtension->PortPdoFlags &= ~0x40;
        }
    }

    IoReleaseCancelSpinLock(Irql);

    if (IdleNotificationIrp)
    {
        IdleNotificationIrp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(IdleNotificationIrp, 0);
    }
}

NTSTATUS
NTAPI
USBH_SyncResumePort(IN PUSBHUB_FDO_EXTENSION HubExtension,
                    IN USHORT Port)
{
    BM_REQUEST_TYPE RequestType;
    LARGE_INTEGER Timeout;
    KEVENT Event;
    NTSTATUS Status;

    DPRINT1("USBH_SyncResumePort: %p, %X\n", HubExtension, Port);

    InterlockedIncrement(&HubExtension->PendingRequestCount);

    KeWaitForSingleObject(&HubExtension->HubPortSemaphore, Executive, KernelMode, FALSE, NULL);
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    InterlockedExchangePointer((PVOID)&HubExtension->pResetPortEvent, &Event);

    RequestType.B = 0x23;
    Status = USBH_Transact(HubExtension, NULL, 0, TRUE, 0x1F, RequestType, 1, 2, Port);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("USBH_SyncResumePort: Status %X\n", Status);
        InterlockedExchangePointer((PVOID)&HubExtension->pResetPortEvent, NULL);
    }
    else
    {
        NTSTATUS status;

        Timeout.QuadPart = (-10000 * 5000);

        status = KeWaitForSingleObject(&Event, Suspended, KernelMode, FALSE, &Timeout);
        if (status == STATUS_TIMEOUT)
        {
            InterlockedExchangePointer((PVOID)&HubExtension->pResetPortEvent, NULL);
            Status = STATUS_DEVICE_DATA_ERROR;
        }
    }

    USBH_Wait(0xA);

    KeReleaseSemaphore(&HubExtension->HubPortSemaphore, LOW_REALTIME_PRIORITY, 1, FALSE);

    if (!InterlockedDecrement(&HubExtension->PendingRequestCount))
        KeSetEvent(&HubExtension->PendingRequestEvent, EVENT_INCREMENT, FALSE);

    return Status;
}

NTSTATUS
NTAPI
USBH_SetPowerD0(IN PIRP Irp,
                IN PUSBHUB_PORT_PDO_EXTENSION PortExtension)
{
    PUSBHUB_FDO_EXTENSION HubExtension;
    PIO_STACK_LOCATION IoStack;
    USB_PORT_STATUS_AND_CHANGE PortStatus;
    DEVICE_POWER_STATE DeviceState;
    USHORT Port;
    NTSTATUS Status = STATUS_SUCCESS;

    HubExtension = PortExtension->HubExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Port = PortExtension->PortNumber;

    DPRINT1("USBH_SetPowerD0: %p, %p, %X, %X\n",
            PortExtension, Irp, IoStack->Parameters.Power.Type, IoStack->Parameters.Power.State.DeviceState);

    if (HubExtension->CurrentPowerState.DeviceState != PowerDeviceD0 &&
        (HubExtension->HubFlags & 0x21))
    {
        USBH_HubSetD0(HubExtension);
    }

    DeviceState = PortExtension->CurrentPowerState.DeviceState;
    if (DeviceState == PowerDeviceD3)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    if (DeviceState != PowerDeviceD2 && DeviceState != PowerDeviceD1)
        goto Finish;

    Status = USBH_SyncGetPortStatus(HubExtension, Port, &PortStatus, 4);

    if (NT_SUCCESS(Status))
    {
        if (PortStatus.AsUlong32 & 8)
        {
            DPRINT1("USBH_SetPowerD0: STATUS_UNSUCCESSFUL\n");
            Status = STATUS_UNSUCCESSFUL;
        }
        else if (PortStatus.AsUlong32 & 4)
        {
            DPRINT1("USBH_SetPowerD0: Status %X\n", Status);
            Status = USBH_SyncResumePort(HubExtension, Port);
        }
        else
        {
            DPRINT1("USBH_SetPowerD0: STATUS_SUCCESS\n");
            Status = STATUS_SUCCESS;
        }
    }

    PortExtension->CurrentPowerState.DeviceState = IoStack->Parameters.Power.State.DeviceState;

    USBH_CompletePortIdleNotification(PortExtension);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("USBH_SetPowerD0: STATUS_SUCCESS\n");
        Status = STATUS_SUCCESS;
        goto Finish;
    }

    if (PortExtension->PortPdoFlags & 0x01000000)
    {
        DPRINT1("USBH_SetPowerD0: Status %X\n", Status);
        USBH_SyncFeatureRequest(PortExtension->Common.SelfDevice, 1, 0, 0, TRUE);
        PortExtension->PortPdoFlags &= ~0x01000000;
    }

Finish:

    PortExtension->CurrentPowerState = IoStack->Parameters.Power.State;
    InterlockedDecrement(&PortExtension->PendingDevicePoRequest);

    USBH_CompletePowerIrp(HubExtension, Irp, Status);

    return Status;
}

NTSTATUS
NTAPI
USBH_PdoSetPower(IN PUSBHUB_PORT_PDO_EXTENSION PortExtension,
                 IN PIRP Irp)
{
    PUSBHUB_FDO_EXTENSION HubExtension;
    PIO_STACK_LOCATION IoStack;
    DEVICE_POWER_STATE DeviceState;

    HubExtension = PortExtension->HubExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    DPRINT1("USBH_PdoSetPower: %p, %p, %X, %X\n",
            PortExtension, Irp, IoStack->Parameters.Power.Type, IoStack->Parameters.Power.State.DeviceState);

    if (IoStack->Parameters.Power.Type == SystemPowerState)
    {
        InterlockedDecrement(&PortExtension->PendingSystemPoRequest);
        USBH_CompletePowerIrp(HubExtension, Irp, STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }

    if (IoStack->Parameters.Power.Type != DevicePowerState)
    {
        DPRINT1("USBH_PdoSetPower: STATUS_INVALID_PARAMETER (%X)\n", IoStack->Parameters.Power.Type);
        USBH_CompletePowerIrp(HubExtension, Irp, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    DeviceState = IoStack->Parameters.Power.State.DeviceState;

    if (PortExtension->CurrentPowerState.DeviceState == DeviceState)
    {
        InterlockedDecrement(&PortExtension->PendingDevicePoRequest);
        USBH_CompletePowerIrp(HubExtension, Irp, STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }

    if (DeviceState == PowerDeviceD0)
        return USBH_SetPowerD0(Irp, PortExtension);

    if (DeviceState == PowerDeviceD1 || DeviceState == PowerDeviceD2)
        return USBH_SetPowerD1orD2(Irp, PortExtension);

    if (DeviceState == PowerDeviceD3)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    InterlockedDecrement(&PortExtension->PendingDevicePoRequest);

    DPRINT1("USBH_PdoSetPower: STATUS_INVALID_PARAMETER (%X)\n", DeviceState);
    USBH_CompletePowerIrp(HubExtension, Irp, STATUS_INVALID_PARAMETER);
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS
NTAPI
USBH_PdoPower(IN PUSBHUB_PORT_PDO_EXTENSION PortExtension,
              IN PIRP Irp,
              IN UCHAR MinorFunction)
{
    PUSBHUB_FDO_EXTENSION HubExtension;
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    DPRINT("USBH_PdoPower: %p, %p, %X\n", PortExtension, Irp, MinorFunction);

    HubExtension = PortExtension->HubExtension;
    if (!HubExtension)
    {
        DPRINT1("USBH_PdoPower: %p, %p, %X\n", PortExtension, Irp, MinorFunction);
        UNIMPLEMENTED_DBGBREAK();
    }

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    InterlockedIncrement(&HubExtension->PendingRequestCount);

    if (MinorFunction == 2 || MinorFunction == 3)
    {
        if (IoStack->Parameters.Power.Type == 0)
            InterlockedIncrement(&PortExtension->PendingSystemPoRequest);
        else if (IoStack->Parameters.Power.Type == 1)
            InterlockedIncrement(&PortExtension->PendingDevicePoRequest);
    }

    if (PortExtension->StateBehindD2)
    {
        if (PortExtension->StateBehindD2 == 1)
        {
            if (MinorFunction == 2 &&
                IoStack->Parameters.Power.Type == 1 &&
                IoStack->Parameters.Power.State.DeviceState == 3)
            {
                InterlockedCompareExchange(&PortExtension->StateBehindD2, 2, PortExtension->StateBehindD2);
            }
        }
        else if (PortExtension->StateBehindD2 == 2)
        {
            DPRINT1("USBH_PdoPower: %p, %p, %X, %X\n", PortExtension, Irp, MinorFunction, PortExtension->StateBehindD2);
            UNIMPLEMENTED_DBGBREAK();
        }
    }

    if (HubExtension->CurrentPowerState.DeviceState == 1 ||
        (MinorFunction != 2 && MinorFunction != 3))
    {
        if (MinorFunction == 0)
            return USBH_PdoWaitWake(PortExtension, Irp);

        if (MinorFunction == 2)
            return USBH_PdoSetPower(PortExtension, Irp);

        if (MinorFunction == 3)
        {
            DPRINT1("USBH_PdoPower: %X\n", HubExtension->CurrentPowerState.DeviceState);
            UNIMPLEMENTED_DBGBREAK();
        }

        Status = Irp->IoStatus.Status;
        USBH_CompletePowerIrp(HubExtension, Irp, Status);

        return Status;
    }

    DPRINT1("USBH_PdoPower: %X\n", HubExtension->CurrentPowerState.DeviceState);
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}
