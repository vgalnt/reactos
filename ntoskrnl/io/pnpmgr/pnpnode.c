/*
 * PROJECT:         ReactOS Kernel
 * COPYRIGHT:       GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/pnpmgr/pnpnode.c
 * PURPOSE:         Device node handle code
 * PROGRAMMERS:     
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#include "../pnpio.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

extern KSPIN_LOCK IopPnPSpinLock;
extern ERESOURCE PiEngineLock;
extern ERESOURCE PiDeviceTreeLock;

/* DATA **********************************************************************/

/* FUNCTIONS *****************************************************************/

PDEVICE_NODE
FASTCALL
IopGetDeviceNode(PDEVICE_OBJECT DeviceObject)
{
   return ((PEXTENDED_DEVOBJ_EXTENSION)DeviceObject->DeviceObjectExtension)->DeviceNode;
}

PDEVICE_NODE
NTAPI
PipAllocateDeviceNode(IN PDEVICE_OBJECT PhysicalDeviceObject)
{
    PDEVICE_NODE DeviceNode;
    PAGED_CODE();

    /* Allocate it */
    DeviceNode = ExAllocatePoolWithTag(NonPagedPool, sizeof(DEVICE_NODE), TAG_IO_DEVNODE);
    if (!DeviceNode) return DeviceNode;

    /* Statistics */
    InterlockedIncrement(&IopNumberDeviceNodes);

    /* Set it up */
    RtlZeroMemory(DeviceNode, sizeof(DEVICE_NODE));
    DeviceNode->InterfaceType = InterfaceTypeUndefined;
    DeviceNode->BusNumber = -1;
    DeviceNode->ChildInterfaceType = InterfaceTypeUndefined;
    DeviceNode->ChildBusNumber = -1;
    DeviceNode->ChildBusTypeIndex = -1;
//    KeInitializeEvent(&DeviceNode->EnumerationMutex, SynchronizationEvent, TRUE);
    InitializeListHead(&DeviceNode->DeviceArbiterList);
    InitializeListHead(&DeviceNode->DeviceTranslatorList);
    InitializeListHead(&DeviceNode->TargetDeviceNotify);
    InitializeListHead(&DeviceNode->DockInfo.ListEntry);
    InitializeListHead(&DeviceNode->PendedSetInterfaceState);
    InitializeListHead(&DeviceNode->LegacyBusListEntry);

    /* Check if there is a PDO */
    if (PhysicalDeviceObject)
    {
        /* Link it and remove the init flag */
        DeviceNode->PhysicalDeviceObject = PhysicalDeviceObject;
        ((PEXTENDED_DEVOBJ_EXTENSION)PhysicalDeviceObject->DeviceObjectExtension)->DeviceNode = DeviceNode;
        PhysicalDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    }

    /* Return the node */
    return DeviceNode;
}

VOID
NTAPI
PpDevNodeLockTree(
    _In_ ULONG LockLevel)
{
    ULONG SharedCount;
    ULONG ix;

    PAGED_CODE();
    DPRINT("PpDevNodeLockTree: LockLevel - %X\n", LockLevel);

    KeEnterCriticalRegion();

    if (LockLevel == 0)
    {
        ExAcquireSharedWaitForExclusive(&PiDeviceTreeLock, TRUE);
        return;
    }

    if (LockLevel == 1)
    {
        ExAcquireResourceExclusiveLite(&PiEngineLock, TRUE);
        ExAcquireSharedWaitForExclusive(&PiDeviceTreeLock, TRUE);
        return;
    }

    if (LockLevel == 2)
    {
        ExAcquireResourceExclusiveLite(&PiEngineLock, TRUE);
        ExAcquireResourceExclusiveLite(&PiDeviceTreeLock, TRUE);
    }
    else if (LockLevel == 3)
    {
        ASSERT(ExIsResourceAcquiredExclusiveLite(&PiEngineLock));
        ASSERT(ExIsResourceAcquiredSharedLite(&PiDeviceTreeLock) &&
              (!ExIsResourceAcquiredExclusiveLite(&PiDeviceTreeLock)));

        SharedCount = ExIsResourceAcquiredSharedLite(&PiDeviceTreeLock);

        for (ix = 0; ix < SharedCount; ix++)
        {
            ExReleaseResourceLite(&PiDeviceTreeLock);
        }

        for (ix = 0; ix < SharedCount; ix++)
        {
            ExAcquireResourceExclusiveLite(&PiDeviceTreeLock, TRUE);
        }
    }
    else
    {
        ASSERT(FALSE);
    }

    DPRINT("PpDevNodeLockTree: Locked\n");
}

VOID
NTAPI
PpDevNodeUnlockTree(
    _In_ ULONG LockLevel)
{
    PAGED_CODE();
    DPRINT("PpDevNodeUnlockTree: LockLevel - %X\n", LockLevel);

    //PpDevNodeAssertLockLevel(LockLevel);

    if (LockLevel == 0)
    {
        ExReleaseResourceLite(&PiDeviceTreeLock);
    }
    else if (LockLevel == 1 || LockLevel == 2)
    {
        ExReleaseResourceLite(&PiDeviceTreeLock);
        ExReleaseResourceLite(&PiEngineLock);
    }
    else if (LockLevel == 3)
    {
        ASSERT(ExIsResourceAcquiredExclusiveLite(&PiDeviceTreeLock));
        ASSERT(ExIsResourceAcquiredExclusiveLite(&PiEngineLock));
        ExConvertExclusiveToSharedLite(&PiDeviceTreeLock);
    }
    else
    {
        ASSERT(FALSE);
    }

    KeLeaveCriticalRegion();
    DPRINT("PpDevNodeUnlockTree: UnLocked\n");
}

VOID
NTAPI
PipSetDevNodeState(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ PNP_DEVNODE_STATE NewState,
    _Out_ PNP_DEVNODE_STATE *OutPreviousState)
{
    PNP_DEVNODE_STATE PreviousState;
    KIRQL OldIrql;

    DPRINT("PipSetDevNodeState: DeviceNode - %p, NewState - %X\n",
           DeviceNode, NewState);

    ASSERT(NewState != DeviceNodeQueryStopped ||
           DeviceNode->State == DeviceNodeStarted);

    if (NewState == DeviceNodeDeleted ||
        NewState == DeviceNodeDeletePendingCloses)
    {
        ASSERT(!(DeviceNode->Flags & DNF_ENUMERATED));
    }

    KeAcquireSpinLock(&IopPnPSpinLock, &OldIrql);
    PreviousState = DeviceNode->State;

    if (PreviousState != NewState)
    {
        DeviceNode->State = NewState;
        DeviceNode->PreviousState = PreviousState;
        DeviceNode->StateHistory[DeviceNode->StateHistoryEntry] = PreviousState;
        DeviceNode->StateHistoryEntry = (DeviceNode->StateHistoryEntry + 1) % 20;
    }

    KeReleaseSpinLock(&IopPnPSpinLock, OldIrql);

    if (OutPreviousState)
    {
        DPRINT("PipSetDevNodeState: PreviousState - %X\n", PreviousState);
        *OutPreviousState = PreviousState;
    }

    if (NewState == DeviceNodeDeleted)
    {
        ASSERT(FALSE);
        //PpRemoveDeviceActionRequests(DeviceNode->PhysicalDeviceObject);
    }
}

VOID
NTAPI
PipSetDevNodeProblem(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ ULONG Problem)
{
    PAGED_CODE();

    ASSERT(Problem != 0);
    ASSERT(DeviceNode->State != DeviceNodeStarted);

    ASSERT(DeviceNode->State != DeviceNodeUninitialized ||
           (DeviceNode->Flags & DNF_ENUMERATED) == 0 ||
           Problem == CM_PROB_INVALID_DATA);

    DeviceNode->Flags |= DNF_HAS_PROBLEM;
    DeviceNode->Problem = Problem;
}

VOID
NTAPI
PipClearDevNodeProblem(
    _In_ PDEVICE_NODE DeviceNode)
{
    PAGED_CODE();
    DeviceNode->Flags &= ~DNF_HAS_PROBLEM;
    DeviceNode->Problem = 0;
}

/* EOF */
