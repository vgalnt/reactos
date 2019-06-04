
/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#include "../pnpio.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

extern ULONG IopMaxDeviceNodeLevel; 

/* DATA **********************************************************************/

/* FUNCTIONS *****************************************************************/

PRELATION_LIST
NTAPI
IopAllocateRelationList(
    _In_ PIP_TYPE_REMOVAL_DEVICE RemovalType)
{
    PRELATION_LIST RelationsList;
    ULONG Size;

    PAGED_CODE();
    DPRINT("IopAllocateRelationList: RemovalType - %X, IopMaxDeviceNodeLevel - %X\n", RemovalType, IopMaxDeviceNodeLevel);

    Size = sizeof(RELATION_LIST) + IopMaxDeviceNodeLevel * sizeof(PRELATION_LIST_ENTRY);

    RelationsList = PiAllocateCriticalMemory(RemovalType, PagedPool, Size, 'rcpP');
    if (!RelationsList)
    {
        DPRINT1("IopAllocateRelationList: fail PiAllocateCriticalMemory()\n");
        ASSERT(FALSE);
        return RelationsList;
    }

    RtlZeroMemory(RelationsList, Size);
    RelationsList->MaxLevel = IopMaxDeviceNodeLevel;

    return RelationsList;
}

VOID
NTAPI
IopCompressRelationList(
    _In_ PRELATION_LIST * OutRelationList)
{
    PRELATION_LIST RelationsList;
    PRELATION_LIST_ENTRY Entry;
    PRELATION_LIST_ENTRY NewEntry;
    PRELATION_LIST NewRelationList;
    ULONG LowestLevel;
    ULONG HighestLevel;
    ULONG Size;
    ULONG ix;

    PAGED_CODE();

    RelationsList = *OutRelationList;

    LowestLevel = RelationsList->MaxLevel;
    HighestLevel = RelationsList->FirstLevel;

    DPRINT("IopCompressRelationList: RelationsList - %p, FirstLevel - %X, MaxLevel - %X\n",
           RelationsList, RelationsList->FirstLevel, RelationsList->MaxLevel);

    for (ix = 0;
         ix <= (RelationsList->MaxLevel - RelationsList->FirstLevel);
         ix++)
    {
        Entry = RelationsList->Entries[ix];
        if (!Entry)
        {
            continue;
        }

        if (LowestLevel > ix)
        {
            LowestLevel = ix;
        }

        if (HighestLevel < ix)
        {
            HighestLevel = ix;
        }

        if (Entry->Count >= Entry->MaxCount)
        {
            continue;
        }

        Size = FIELD_OFFSET(RELATION_LIST_ENTRY, Devices) +
               Entry->Count * sizeof(PDEVICE_OBJECT);

        NewEntry = ExAllocatePoolWithTag(PagedPool, Size, 'lrpP');
        if (!NewEntry)
        {
            DPRINT1("IopCompressRelationList: NewEntry == NULL\n");
            ASSERT(FALSE);
            continue;
        }

        NewEntry->Count = Entry->Count;
        NewEntry->MaxCount = Entry->Count;

        RtlCopyMemory(NewEntry->Devices,
                      Entry->Devices,
                      Entry->Count * sizeof(PDEVICE_OBJECT));

        RelationsList->Entries[ix] = NewEntry;

        ExFreePoolWithTag(Entry, 'lrpP');
    }

    ASSERT(LowestLevel <= HighestLevel);

    if (LowestLevel > HighestLevel)
    {
        LowestLevel = 0;
        HighestLevel = 0;
    }

    if (LowestLevel == RelationsList->FirstLevel &&
        HighestLevel == RelationsList->MaxLevel)
    {
        ASSERT(FALSE);
        return;
    }

    Size = sizeof(RELATION_LIST) +
           (HighestLevel - LowestLevel) * sizeof(PRELATION_LIST_ENTRY);

    NewRelationList = ExAllocatePoolWithTag(PagedPool, Size, 'lrpP');
    if (!NewRelationList)
    {
        DPRINT("IopCompressRelationList: ExAllocatePoolWithTag() failed\n");
        ASSERT(FALSE);
        return;
    }

    NewRelationList->Count = RelationsList->Count;
    NewRelationList->TagCount = RelationsList->TagCount;

    NewRelationList->FirstLevel = LowestLevel;
    NewRelationList->MaxLevel = HighestLevel;

    RtlCopyMemory(NewRelationList->Entries,
                  &RelationsList->Entries[LowestLevel],
                  (HighestLevel - LowestLevel + 1) * sizeof(PRELATION_LIST_ENTRY));

    ExFreePoolWithTag(RelationsList, 'rcpP');

    *OutRelationList = NewRelationList;
}

NTSTATUS
NTAPI
IopBuildRemovalRelationList(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIP_TYPE_REMOVAL_DEVICE RemovalType,
    _In_ PPNP_VETO_TYPE VetoType,
    _In_ PUNICODE_STRING VetoName,
    _Out_ PRELATION_LIST * OutRelationList)
{
    PDEVICE_NODE DeviceNode;
    PRELATION_LIST RelationsList;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IopBuildRemovalRelationList: DeviceObject - %p, RemovalType - %X\n",
           DeviceObject, RemovalType);

    *OutRelationList = NULL;
    DeviceNode = IopGetDeviceNode(DeviceObject);

    ASSERT(DeviceObject != IopRootDeviceNode->PhysicalDeviceObject);

    RelationsList = IopAllocateRelationList(RemovalType);
    if (!RelationsList)
    {
        DPRINT1("IopBuildRemovalRelationList: return STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = IopProcessRelation(DeviceNode,
                                RemovalType,
                                TRUE,
                                VetoType,
                                VetoName,
                                RelationsList);

    ASSERT(Status != STATUS_INVALID_DEVICE_REQUEST);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopBuildRemovalRelationList: Status - %X\n", Status);
        IopFreeRelationList(RelationsList);
        return Status;
    }

    IopCompressRelationList(&RelationsList);
    *OutRelationList = RelationsList;

    return Status;
}

NTSTATUS
PipRequestDeviceRemovalWorker(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ PVOID Context)
{
    PPNP_REMOVAL_WALK_CONTEXT RemovalContext = Context;
    PNP_DEVNODE_STATE AwaitingState;

    PAGED_CODE();
    DPRINT("PipRequestDeviceRemovalWorker: DeviceNode - %p, DeviceNode->State - %X, TreeDeletion - %X\n",
           DeviceNode, DeviceNode->State, RemovalContext->TreeDeletion);

    switch (DeviceNode->State)
    {
        case DeviceNodeInitialized:
        case DeviceNodeDriversAdded:
        case DeviceNodeStarted:
            break;

        case DeviceNodeUninitialized:
        case DeviceNodeResourcesAssigned:
        case DeviceNodeRemovePendingCloses:
        case DeviceNodeRemoved:
            ASSERT(RemovalContext->TreeDeletion);
            break;

        case DeviceNodeStartCompletion:
        case DeviceNodeStartPostWork:
        case DeviceNodeStopped:
        case DeviceNodeRestartCompletion:
            ASSERT(!RemovalContext->DescendantNode);
            ASSERT(!RemovalContext->TreeDeletion);
            break;

        case DeviceNodeAwaitingQueuedDeletion:
        case DeviceNodeAwaitingQueuedRemoval:
            ASSERT(RemovalContext->TreeDeletion);
            PipRestoreDevNodeState(DeviceNode);
            PipSetDevNodeState(DeviceNode, DeviceNodeAwaitingQueuedDeletion, NULL);
            return STATUS_SUCCESS;

        case DeviceNodeStartPending:
        case DeviceNodeQueryStopped:
        case DeviceNodeEnumeratePending:
        default:
            ASSERT(FALSE);
            break;
    }

    if (RemovalContext->TreeDeletion)
    {
        AwaitingState = DeviceNodeAwaitingQueuedDeletion;
    }
    else
    {
        AwaitingState = DeviceNodeAwaitingQueuedRemoval;
    }

    PipSetDevNodeState(DeviceNode, AwaitingState, NULL);

    RemovalContext->DescendantNode = TRUE;
    RemovalContext->TreeDeletion = TRUE;

    return STATUS_SUCCESS;
}

VOID
NTAPI
PipRequestDeviceRemoval(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ BOOLEAN TreeDeletion,
    _In_ ULONG Problem)
{
    DEVICETREE_TRAVERSE_CONTEXT Context;
    PNP_REMOVAL_WALK_CONTEXT RemovalContext;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PipRequestDeviceRemoval: DeviceNode - %p, TreeDeletion - %X, Problem - %X\n", DeviceNode, TreeDeletion, Problem);

    if (DeviceNode == NULL)
    {
        DPRINT("PipRequestDeviceRemoval: DeviceNode == NULL\n");
        ASSERT(DeviceNode);
        return;
    }

    if (DeviceNode->InstancePath.Length == 0)
    {
        DPRINT("PipRequestDeviceRemoval: Driver - %wZ, child DeviceNode - %p\n", &DeviceNode->Parent->ServiceName, DeviceNode);
        ASSERT(DeviceNode->InstancePath.Length != 0);
    }

    PpDevNodeAssertLockLevel(1);

    RemovalContext.TreeDeletion = TreeDeletion;
    RemovalContext.DescendantNode = FALSE;

    IopInitDeviceTreeTraverseContext(&Context,
                                     DeviceNode,
                                     PipRequestDeviceRemovalWorker,
                                     &RemovalContext);

    Status = IopTraverseDeviceTree(&Context);

    DPRINT("PipRequestDeviceRemoval: Status - %X\n", Status);
    ASSERT(NT_SUCCESS(Status));

    PpSetTargetDeviceRemove(DeviceNode->PhysicalDeviceObject,
                            TRUE,
                            TRUE,
                            FALSE,
                            FALSE,
                            Problem,
                            NULL,
                            NULL,
                            NULL,
                            NULL);
}

/* EOF */
