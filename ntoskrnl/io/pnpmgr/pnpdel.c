
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
