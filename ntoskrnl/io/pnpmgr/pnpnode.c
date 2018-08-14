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


/* EOF */
