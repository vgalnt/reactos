
/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#include "../pnpio.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

/* DATA **********************************************************************/

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
