/*
 * PROJECT:         ReactOS Kernel
 * COPYRIGHT:       GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/pnpmgr/pnpenum.c
 * PURPOSE:         Device enumeration functions
 * PROGRAMMERS:     
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "../pnpio.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

extern KSPIN_LOCK IopPnPSpinLock;
extern LIST_ENTRY IopPnpEnumerationRequestList;
extern KEVENT PiEnumerationLock;

/* DATA **********************************************************************/

BOOLEAN PipEnumerationInProgress;
WORK_QUEUE_ITEM PipDeviceEnumerationWorkItem;

/* FUNCTIONS *****************************************************************/

VOID
NTAPI
PipEnumerationWorker(
    _In_ PVOID Context)
{
    PDEVICE_OBJECT DeviceObject;
    PDEVICE_NODE DeviceNode;
    PPIP_ENUM_REQUEST Request;
    BOOLEAN IsDereferenceObject;
    BOOLEAN IsBootProcess = FALSE;
    BOOLEAN IsAssignResources = FALSE;
    KIRQL OldIrql;
    NTSTATUS Status;

    PpDevNodeLockTree(1);

    while (TRUE)
    {
        Status = STATUS_SUCCESS;
        IsDereferenceObject = TRUE;

        KeAcquireSpinLock(&IopPnPSpinLock, &OldIrql);

        Request = CONTAINING_RECORD(IopPnpEnumerationRequestList.Flink,
                                    PIP_ENUM_REQUEST,
                                    RequestLink);

        if (IsListEmpty(&IopPnpEnumerationRequestList))
        {
            break;
        }

        RemoveHeadList(&IopPnpEnumerationRequestList);

Start:
        KeReleaseSpinLock(&IopPnPSpinLock, OldIrql);

        if (Request)
        {
            InitializeListHead(&Request->RequestLink);

            //FIXME: Check ShuttingDown\n");

            DeviceObject = Request->DeviceObject;
            ASSERT(DeviceObject);

            DeviceNode = IopGetDeviceNode(DeviceObject);
            ASSERT(DeviceNode);

            if (DeviceNode->State == DeviceNodeDeleted)
            {
                Status = STATUS_UNSUCCESSFUL;
            }
            else
            {
                DPRINT("PipEnumerationWorker: DeviceObject - %p, Request->RequestType - %X\n",
                       DeviceObject,
                       Request->RequestType);

                switch (Request->RequestType)
                {
                    case PipEnumDeviceOnly:
                    case PipEnumDeviceTree:
                    case PipEnumRootDevices:
                    case PipEnumSystemHiveLimitChange:
                        DPRINT("PipEnumerationWorker: Reenumeration ...\n");
                        Status = IopEnumerateDevice(Request->DeviceObject);//PiProcessReenumeration(Request);
                        IsDereferenceObject = FALSE;
                        break;

                    case PipEnumAddBootDevices:
                        DPRINT("PipEnumerationWorker: PipEnumAddBootDevices\n");
                        ASSERT(FALSE);
                        Status = 0;//PiProcessAddBootDevices(Request);
                        DPRINT("PipEnumerationWorker: end\n");
                        break;

                    case PipEnumBootDevices:
                        DPRINT("PipEnumerationWorker: PipEnumBootDevices\n");
                        ASSERT(FALSE);
                        IsBootProcess = TRUE;
                        Request = NULL;
                        goto Start;

                    case PipEnumAssignResources:
                        DPRINT("PipEnumerationWorker: PipEnumAssignResources\n");
                        ASSERT(FALSE);
                        IsAssignResources = TRUE;
                        Request = NULL;
                        goto Start;

                    case PipEnumGetSetDeviceStatus:
                        DPRINT("PipEnumerationWorker: PipEnumGetSetDeviceStatus\n");
                        ASSERT(FALSE);
                        break;

                    case PipEnumInvalidateRelationsInList:
                        DPRINT("PipEnumerationWorker: PipEnumInvalidateRelationsInList\n");
                        ASSERT(FALSE);
                        break;

                    case PipEnumClearProblem:
                        DPRINT("PipEnumerationWorker: PipEnumClearProblem\n");
                        ASSERT(FALSE);
                        break;

                    case PipEnumHaltDevice:
                        DPRINT("PipEnumerationWorker: PipEnumHaltDevice\n");
                        ASSERT(FALSE);
                        break;

                    case PipEnumInvalidateDeviceState:
                        DPRINT("PipEnumerationWorker: PipEnumInvalidateDeviceState\n");
                        ASSERT(FALSE);
                        Status = 0;//PiProcessRequeryDeviceState(Request);
                        break;

                    case PipEnumResetDevice:
                        DPRINT("PipEnumerationWorker: PipEnumResetDevice\n");
                        ASSERT(FALSE);
                        goto RestartDevice;

                    case PipEnumStartDevice:
                        DPRINT("PipEnumerationWorker: PipEnumStartDevice\n");
                        ASSERT(FALSE);
RestartDevice:
                        Status = 0;//PiRestartDevice(Request);
                        break;

                    case PipEnumIoResourceChanged:
                        DPRINT("PipEnumerationWorker: PipEnumIoResourceChanged\n");
                        ASSERT(FALSE);
                        Status = 0;//PiProcessResourceRequirementsChanged(Request);
                        if (!NT_SUCCESS(Status))
                        {
                            ASSERT(FALSE);
                            IsAssignResources = TRUE;
                            Status = STATUS_SUCCESS;
                            Request = NULL;
                            goto Start;
                        }
                        break;

                    case PipEnumSetProblem:
                        DPRINT("PipEnumerationWorker: PipEnumSetProblem\n");
                        ASSERT(FALSE);
                        break;

                    case PipEnumShutdownPnpDevices:
                        DPRINT("PipEnumerationWorker: PipEnumShutdownPnpDevices\n");
                        ASSERT(FALSE);
                        break;

                    case PipEnumStartSystemDevices:
                        DPRINT("PipEnumerationWorker: PipEnumStartSystemDevices\n");
                        ASSERT(FALSE);
                        Status = 0;//PiProcessStartSystemDevices(Request);
                        IsDereferenceObject = FALSE;
                        break;

                    default:
                        ASSERT(FALSE);
                        break;
                }
            }

            // ? Request->RequestListEntry ?

            if (Request->CompletionStatus)
                *Request->CompletionStatus = Status;
            if (Request->CompletionEvent)
                KeSetEvent(Request->CompletionEvent, IO_NO_INCREMENT, FALSE);
            if (IsDereferenceObject)
                ObDereferenceObject(Request->DeviceObject);

            ExFreePoolWithTag(Request, TAG_IO);
        }
        else if (IsAssignResources || IsBootProcess)
        {
            ASSERT(FALSE);
#if 0
            SERVICE_LOAD_TYPE DriverLoadType = DemandLoad;

            ObReferenceObject(IopRootDeviceNode->PhysicalDeviceObject);

            PipProcessDevNodeTree(IopRootDeviceNode,
                                  PnPBootDriversInitialized,
                                  IsAssignResources,
                                  0,
                                  FALSE,
                                  FALSE,
                                  &DriverLoadType,
                                  NULL);
#endif
            IsAssignResources = FALSE;
            IsBootProcess = FALSE;
        }
        else
        {
            ASSERT(FALSE);
        }
    }

    PipEnumerationInProgress = FALSE;
    KeSetEvent(&PiEnumerationLock, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&IopPnPSpinLock, OldIrql);
    PpDevNodeUnlockTree(1);
}

NTSTATUS
NTAPI
PipRequestDeviceAction(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIP_ENUM_TYPE RequestType,
    _In_ UCHAR ReorderingBarrier,
    _In_ ULONG_PTR RequestArgument,
    _In_ PKEVENT CompletionEvent,
    _Inout_ NTSTATUS * CompletionStatus)
{
    PPIP_ENUM_REQUEST Request;
    PDEVICE_OBJECT RequestDeviceObject;
    KIRQL OldIrql;

    DPRINT("PipRequestDeviceAction: DeviceObject - %p, RequestType - %X\n",
           DeviceObject,
           RequestType);

    //FIXME: check ShuttingDown

    Request = ExAllocatePoolWithTag(NonPagedPool,
                                    sizeof(PIP_ENUM_REQUEST),
                                    TAG_IO);
    if (!Request)
    {
        DPRINT1("PipRequestDeviceAction: error\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!DeviceObject)
    {
        RequestDeviceObject = IopRootDeviceNode->PhysicalDeviceObject;
    }
    else
    {
        RequestDeviceObject = DeviceObject;
    }

    ObReferenceObject(RequestDeviceObject);

    Request->DeviceObject = RequestDeviceObject;
    Request->RequestType = RequestType;
    Request->ReorderingBarrier = ReorderingBarrier;
    Request->RequestArgument = RequestArgument;
    Request->CompletionEvent = CompletionEvent;
    Request->CompletionStatus = CompletionStatus;

    InitializeListHead(&Request->RequestLink);

    KeAcquireSpinLock(&IopPnPSpinLock, &OldIrql);

    InsertTailList(&IopPnpEnumerationRequestList, &Request->RequestLink);
    DPRINT("PipRequestDeviceAction: Inserted Request - %p\n", Request);

    if (RequestType == PipEnumAddBootDevices ||
        RequestType == PipEnumBootDevices ||
        RequestType == PipEnumRootDevices)
    {
        ASSERT(!PipEnumerationInProgress);

        PipEnumerationInProgress = TRUE;
        KeClearEvent(&PiEnumerationLock);
        KeReleaseSpinLock(&IopPnPSpinLock, OldIrql);

        PipEnumerationWorker(Request);

        return STATUS_SUCCESS;
    }

#if 0 // Not implemented yet
    if (!PnPBootDriversLoaded)
    {
        DPRINT("PipRequestDeviceAction: PnPBootDriversLoaded - FALSE\n");
        KeReleaseSpinLock(&IopPnPSpinLock, OldIrql);
        return STATUS_SUCCESS;
    }
#endif

    if (PipEnumerationInProgress)
    {
        DPRINT("PipRequestDeviceAction: PipEnumerationInProgress\n");
        KeReleaseSpinLock(&IopPnPSpinLock, OldIrql);
        return STATUS_SUCCESS;
    }

    PipEnumerationInProgress = TRUE;
    KeClearEvent(&PiEnumerationLock);
    KeReleaseSpinLock(&IopPnPSpinLock, OldIrql);

    ExInitializeWorkItem(&PipDeviceEnumerationWorkItem,
                         PipEnumerationWorker,
                         Request);

    ExQueueWorkItem(&PipDeviceEnumerationWorkItem, DelayedWorkQueue);
    DPRINT("PipRequestDeviceAction: Queue &PipDeviceEnumerationWorkItem - %p\n",
           &PipDeviceEnumerationWorkItem);

    return STATUS_SUCCESS;
}

VOID
NTAPI
IoInvalidateDeviceRelations(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ DEVICE_RELATION_TYPE Type)
{
    PDEVICE_NODE DeviceNode = IopGetDeviceNode(DeviceObject);

    if (!DeviceObject || !DeviceNode ||
        DeviceNode->Flags & DNF_LEGACY_RESOURCE_DEVICENODE)
    {
        KeBugCheckEx(PNP_DETECTED_FATAL_ERROR,
                     0x2,
                     (ULONG_PTR)DeviceObject,
                     0x0,
                     0x0);
    }

    switch (Type)
    {
        case BusRelations:
            DPRINT("IoInvalidateDeviceRelations: PipEnumDeviceTree\n");
            PipRequestDeviceAction(DeviceObject,
                                   PipEnumDeviceTree,
                                   0,
                                   0,
                                   NULL,
                                   NULL);
            break;

        case PowerRelations:
            DPRINT1("IoInvalidateDeviceRelations: PowerRelations NOT_IMPLEMENTED FIXME!\n");
            //ASSERT(FALSE);//PoInvalidateDevicePowerRelations(DeviceObject);
            break;

        case SingleBusRelations:
            DPRINT("IoInvalidateDeviceRelations: PipEnumDeviceOnly\n");
            PipRequestDeviceAction(DeviceObject,
                                   PipEnumDeviceOnly,
                                   0,
                                   0,
                                   NULL,
                                   NULL);
            break;

        default:
          break;
    }
}

NTSTATUS
NTAPI
IoSynchronousInvalidateDeviceRelations(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ DEVICE_RELATION_TYPE Type)
{
    DPRINT1("IoSynchronousInvalidateDeviceRelations: ASSERT(0)\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

/* EOF */
