
/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#include "../pnpio.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

extern PPNP_DEVICE_EVENT_LIST PpDeviceEventList;
extern KGUARDED_MUTEX PiNotificationInProgressLock;

extern KEVENT PiEventQueueEmpty;
extern BOOLEAN PpPnpShuttingDown;

/* DATA **********************************************************************/

BOOLEAN PiNotificationInProgress = FALSE;

/* FUNCTIONS *****************************************************************/

PVOID
NTAPI
PiAllocateCriticalMemory(
    _In_ PIP_TYPE_REMOVAL_DEVICE DeleteType,
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag)
{
    PVOID Block;
    LARGE_INTEGER Interval;

    PAGED_CODE();
    DPRINT("PiAllocateCriticalMemory: DeleteType - %X, NumberOfBytes - %X\n", DeleteType, NumberOfBytes);

    ASSERT(KeGetCurrentIrql() != DISPATCH_LEVEL);

    while (TRUE)
    {
        Block = ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);

        if (Block || DeleteType == PipQueryRemove || DeleteType == PipEject)
        {
            break;
        }

        Interval.QuadPart = -10000ll * 1; // 1 msec
        KeDelayExecutionThread(KernelMode, FALSE, &Interval);
    }

    return Block;
}

VOID
NTAPI
PpCompleteDeviceEvent(
    _In_ PPNP_DEVICE_EVENT_ENTRY EventEntry,
    _In_ NTSTATUS Status)
{
    PAGED_CODE();
    DPRINT("PpCompleteDeviceEvent: EventEntry - %p, Status - %X\n", EventEntry, Status);

    if (EventEntry->CallerEvent)
    {
        *EventEntry->Data.Result = Status;
        KeSetEvent(EventEntry->CallerEvent, IO_NO_INCREMENT, FALSE);
    }

    if (EventEntry->Callback)
    {
        DPRINT1("PpCompleteDeviceEvent: FIXME Callback\n");
        ASSERT(FALSE);
        //EventEntry->Callback(EventEntry->Context);
    }

    if (EventEntry->Data.DeviceObject)
    {
        ObDereferenceObject(EventEntry->Data.DeviceObject);
    }

    ExFreePoolWithTag(EventEntry, 'EEpP');
}

VOID
NTAPI
PiWalkDeviceList(
    _In_ PVOID Context)
{
    PPNP_DEVICE_EVENT_ENTRY EventEntry;
    UNICODE_STRING SymbolicLinkName;
    PWORK_QUEUE_ITEM WorkItem = Context;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PiWalkDeviceList: WorkItem - %p\n", WorkItem);

    Status = KeWaitForSingleObject(&PpDeviceEventList->EventQueueMutex,
                                   Executive,
                                   KernelMode,
                                   FALSE,
                                   NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("PiWalkDeviceList: Status - %X\n", Status);
        KeAcquireGuardedMutex(&PiNotificationInProgressLock);
        KeSetEvent(&PiEventQueueEmpty, IO_NO_INCREMENT, FALSE);
        PiNotificationInProgress = FALSE;
        KeReleaseGuardedMutex(&PiNotificationInProgressLock);
        return;
    }

    while (TRUE)
    {
        KeAcquireGuardedMutex(&PpDeviceEventList->Lock);

        if (IsListEmpty(&PpDeviceEventList->List))
        {
            DPRINT("PiWalkDeviceList: IsListEmpty(&PpDeviceEventList->List)\n");
            break;
        }

        EventEntry = CONTAINING_RECORD(RemoveHeadList(&PpDeviceEventList->List),
                                       PNP_DEVICE_EVENT_ENTRY,
                                       ListEntry);

        DPRINT("PiWalkDeviceList: EventEntry - %p, EventCategory - %X\n", EventEntry,
               EventEntry->Data.EventCategory);

        KeReleaseGuardedMutex(&PpDeviceEventList->Lock);

        if (EventEntry->Data.DeviceObject)
        {
            PDEVICE_NODE DeviceNode;

            DeviceNode = IopGetDeviceNode(EventEntry->Data.DeviceObject);
            if (!DeviceNode)
            {
                DPRINT("PiWalkDeviceList: continue. STATUS_NO_SUCH_DEVICE\n");
                PpCompleteDeviceEvent(EventEntry, STATUS_NO_SUCH_DEVICE);
                IopProcessDeferredRegistrations();
                continue;
            }
        }

        switch (EventEntry->Data.EventCategory)
        {
            case DeviceClassChangeEvent:
                DPRINT("PiWalkDeviceList: DeviceClassChangeEvent - kernel notifying\n");

                RtlInitUnicodeString(&SymbolicLinkName,
                                     EventEntry->Data.DeviceClass.SymbolicLinkName);

                IopNotifyDeviceClassChange(&EventEntry->Data,
                                           &EventEntry->Data.DeviceClass.ClassGuid,
                                           &SymbolicLinkName);

                DPRINT("PiWalkDeviceList: FIXME PiNotifyUserMode()\n");
                //PiNotifyUserMode(EventEntry);
                Status = STATUS_SUCCESS;
                break;

            case CustomDeviceEvent:
                DPRINT("PiWalkDeviceList: FIXME CustomDeviceEvent()\n");
                ASSERT(FALSE);
                break;

            case TargetDeviceChangeEvent:
                Status = PiProcessTargetDeviceEvent(&EventEntry);
                break;

            case DeviceInstallEvent:
                DPRINT("PiWalkDeviceList: FIXME DeviceInstallEvent\n");
                ASSERT(FALSE);
                break;

            case HardwareProfileChangeEvent:
                DPRINT("PiWalkDeviceList: FIXME HardwareProfileChangeEvent\n");
                ASSERT(FALSE);
                break;

            case PowerEvent:
            case VetoEvent:
            case BlockedDriverEvent:
            case InvalidIDEvent:
                ASSERT(FALSE);
                break;

            default:
                DPRINT("PiWalkDeviceList: EventEntry->Data.EventCategory - %X\n", EventEntry->Data.EventCategory);
                ASSERT(FALSE);
                Status = STATUS_UNSUCCESSFUL;
                break;
        }

        if (Status != STATUS_PENDING)
        {
            PpCompleteDeviceEvent(EventEntry, Status);
        }
        else
        {
            ASSERT(FALSE);
        }

        IopProcessDeferredRegistrations();
    }

    KeAcquireGuardedMutex(&PiNotificationInProgressLock);
    KeSetEvent(&PiEventQueueEmpty, IO_NO_INCREMENT, FALSE);
    PiNotificationInProgress = FALSE;
    IopProcessDeferredRegistrations();
    KeReleaseGuardedMutex(&PiNotificationInProgressLock);

    KeReleaseGuardedMutex(&PpDeviceEventList->Lock);

    if (WorkItem)
    {
        ExFreePoolWithTag(WorkItem, 'IWpP');
    }

    KeReleaseMutex(&PpDeviceEventList->EventQueueMutex, FALSE);

    DPRINT("PiWalkDeviceList: exit\n");
}

NTSTATUS
NTAPI
PiInsertEventInQueue(
    _In_ PPNP_DEVICE_EVENT_ENTRY EventEntry)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PWORK_QUEUE_ITEM WorkItem = NULL;

    PAGED_CODE();
    DPRINT("PiInsertEventInQueue: EventEntry - %p, EventCategory - %X\n", EventEntry, EventEntry->Data.EventCategory);

    KeAcquireGuardedMutex(&PpDeviceEventList->Lock);
    KeAcquireGuardedMutex(&PiNotificationInProgressLock);

    if (PiNotificationInProgress)
    {
        DPRINT("PiInsertEventInQueue: PiNotificationInProgress - TRUE\n");
    }
    else
    {
        WorkItem = ExAllocatePoolWithTag(NonPagedPool, sizeof(*WorkItem), 'IWpP');
        if (WorkItem)
        {
            PiNotificationInProgress = TRUE;
            KeClearEvent(&PiEventQueueEmpty);
        }
        else
        {
            DPRINT("PiInsertEventInQueue: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    InsertTailList(&PpDeviceEventList->List, &EventEntry->ListEntry);

    KeReleaseGuardedMutex(&PiNotificationInProgressLock);
    KeReleaseGuardedMutex(&PpDeviceEventList->Lock);

    if (WorkItem)
    {
        WorkItem->WorkerRoutine = PiWalkDeviceList;
        WorkItem->Parameter = WorkItem;
        WorkItem->List.Flink = NULL;

        ExQueueWorkItem(WorkItem, DelayedWorkQueue);

        DPRINT("PiInsertEventInQueue: queue WorkItem - %X\n", WorkItem);
    }

    return Status;
}

NTSTATUS
NTAPI
PpSynchronizeDeviceEventQueue(VOID)
{
    PPNP_DEVICE_EVENT_ENTRY EventEntry;
    NTSTATUS Status;
    KEVENT Event;
    NTSTATUS RetStatus;

    PAGED_CODE();
    DPRINT("PpSynchronizeDeviceEventQueue()\n");

    EventEntry = ExAllocatePoolWithTag(PagedPool, sizeof(*EventEntry), 'EEpP');
    if (!EventEntry)
    {
        DPRINT1("PpSynchronizeDeviceEventQueue: return STATUS_NO_MEMORY\n");
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(EventEntry, sizeof(*EventEntry));

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    EventEntry->CallerEvent = &Event;

    RtlCopyMemory(&EventEntry->Data.EventGuid, &GUID_DEVICE_NOOP, sizeof(GUID));

    EventEntry->Data.EventCategory = 1;
    EventEntry->Data.Result = (PULONG)&RetStatus;
    EventEntry->Data.TotalSize = sizeof(EventEntry->Data);

    Status = PiInsertEventInQueue(EventEntry);

    if (NT_SUCCESS(Status))
    {
        Status = KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
    }

    return Status;
}

NTSTATUS
NTAPI
PpSetDeviceClassChange(
    _In_ CONST GUID * EventGuid,
    _In_ GUID * ClassGuid,
    _In_ PUNICODE_STRING SymbolicLinkName)
{
    NTSTATUS Status;
    ULONG EventEntrySize;
    PPNP_DEVICE_EVENT_ENTRY EventEntry;
    ULONG DataTotalSize;
    ULONG Length;

    PAGED_CODE();
    DPRINT("PpSetDeviceClassChange: SymbolicLinkName - %wZ\n", SymbolicLinkName);

    if (PpPnpShuttingDown)
    {
        ASSERT(FALSE);
        return STATUS_TOO_LATE;
    }

    //_SEH2_TRY

    ASSERT(EventGuid != NULL);
    ASSERT(ClassGuid != NULL);
    ASSERT(SymbolicLinkName != NULL);

    Length = SymbolicLinkName->Length;
    DataTotalSize = Length + sizeof(PLUGPLAY_EVENT_BLOCK);
    EventEntrySize = Length + sizeof(PNP_DEVICE_EVENT_ENTRY);

    EventEntry = ExAllocatePoolWithTag(PagedPool, EventEntrySize, 'EEpP');
    if (!EventEntry)
    {
        DPRINT1("PpSetDeviceClassChange: return STATUS_NO_MEMORY\n");
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(EventEntry, EventEntrySize);

    EventEntry->Data.EventCategory = DeviceClassChangeEvent;
    EventEntry->Data.TotalSize = DataTotalSize;

    RtlCopyMemory(&EventEntry->Data.EventGuid, EventGuid, sizeof(GUID));
    RtlCopyMemory(&EventEntry->Data.DeviceClass.ClassGuid, ClassGuid, sizeof(GUID));
    RtlCopyMemory(EventEntry->Data.DeviceClass.SymbolicLinkName, SymbolicLinkName->Buffer, Length);

    EventEntry->Data.DeviceClass.SymbolicLinkName[Length / sizeof(WCHAR)] = UNICODE_NULL;

    Status = PiInsertEventInQueue(EventEntry);

    //_SEH2_END;

    return Status;
}

NTSTATUS
NTAPI
PpSetTargetDeviceRemove(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ BOOLEAN IsRemove,
    _In_ BOOLEAN IsNoRestart,
    _In_ BOOLEAN RemoveNoRestart,
    _In_ BOOLEAN IsEjectRequest,
    _In_ ULONG Problem,
    _In_ PKEVENT SyncEvent,
    _Out_ NTSTATUS * OutResult,
    _In_ PPNP_VETO_TYPE VetoType,
    _In_ PUNICODE_STRING VetoName)
{
    PPNP_DEVICE_EVENT_ENTRY EventEntry;
    PDEVICE_NODE DeviceNode;
    ULONG EventEntrySize;
    ULONG TotalSize;
    ULONG InstanceLength;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PpSetTargetDeviceRemove: DeviceObject - %p, IsRemove - %X, IsNoRestart - %X, RemoveNoRestart - %X, IsEjectRequest - %X, Problem - %X\n",
           DeviceObject, IsRemove, IsNoRestart, RemoveNoRestart, IsEjectRequest, Problem);

    ASSERT(DeviceObject != NULL);

    if (SyncEvent)
    {
        ASSERT(OutResult);
        *OutResult = STATUS_PENDING;
    }

    if (PpPnpShuttingDown)
    {
        DPRINT("PpSetTargetDeviceRemove: return STATUS_TOO_LATE\n");
        return STATUS_TOO_LATE;
    }

    ObReferenceObject(DeviceObject);
    DeviceNode = IopGetDeviceNode(DeviceObject);
    ASSERT(DeviceNode);

    InstanceLength = DeviceNode->InstancePath.Length;
    TotalSize = sizeof(PLUGPLAY_EVENT_BLOCK) + InstanceLength + sizeof(WCHAR);
    EventEntrySize = TotalSize + (sizeof(PNP_DEVICE_EVENT_ENTRY) - sizeof(PLUGPLAY_EVENT_BLOCK));

    EventEntry = ExAllocatePoolWithTag(PagedPool, EventEntrySize, 'EEpP');
    if (!EventEntry)
    {
        DPRINT("PpSetTargetDeviceRemove: return STATUS_INSUFFICIENT_RESOURCES\n");
        ObDereferenceObject(DeviceObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(EventEntry, EventEntrySize);

    EventEntry->CallerEvent = SyncEvent;
    EventEntry->VetoType = VetoType;
    EventEntry->Argument = Problem;
    EventEntry->VetoName = VetoName;

    if (IsEjectRequest)
    {
        RtlCopyMemory(&EventEntry->Data.EventGuid,
                      &GUID_DEVICE_EJECT,
                      sizeof(GUID));
    }
    else
    {
        RtlCopyMemory(&EventEntry->Data.EventGuid,
                      &GUID_DEVICE_QUERY_AND_REMOVE,
                      sizeof(GUID));
    }

    EventEntry->Data.EventCategory = TargetDeviceChangeEvent;
    EventEntry->Data.Result = (PVOID)OutResult;

    if (IsNoRestart)
    {
        EventEntry->Data.Flags |= 2;
    }
    if (IsRemove)
    {
        EventEntry->Data.Flags |= 4;
    }
    if (RemoveNoRestart)
    {
        ASSERT(IsNoRestart == FALSE);
        EventEntry->Data.Flags |= 8;
    }

    EventEntry->Data.TotalSize = TotalSize;
    EventEntry->Data.DeviceObject = DeviceObject;

    if (InstanceLength)
    {
        RtlCopyMemory(&EventEntry->Data.TargetDevice.DeviceIds,
                      DeviceNode->InstancePath.Buffer,
                      InstanceLength);
    }

    EventEntry->Data.TargetDevice.DeviceIds[InstanceLength / sizeof(WCHAR)] = UNICODE_NULL;

    Status = PiInsertEventInQueue(EventEntry);

    DPRINT("PpSetTargetDeviceRemove: return Status - %p\n", Status);
    return Status;
}

/* EOF */
