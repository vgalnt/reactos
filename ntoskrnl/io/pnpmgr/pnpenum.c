/*
 * PROJECT:         ReactOS Kernel
 * COPYRIGHT:       GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/pnpmgr/pnpenum.c
 * PURPOSE:         Device enumeration functions
 * PROGRAMMERS:     
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#include "../pnpio.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

extern KSPIN_LOCK IopPnPSpinLock;
extern LIST_ENTRY IopPnpEnumerationRequestList;
extern KEVENT PiEnumerationLock;
extern BOOLEAN PnPBootDriversLoaded;

/* DATA **********************************************************************/

WORK_QUEUE_ITEM PipDeviceEnumerationWorkItem;
BOOLEAN PipEnumerationInProgress;

/* FUNCTIONS *****************************************************************/

#define MAX_DEVICE_ID_LEN          200
#define MAX_SEPARATORS_INSTANCEID  0
#define MAX_SEPARATORS_DEVICEID    1
#define MAX_SEPARATORS_MULTI_SZ    -1

ULONG
NTAPI
PiFixupID(
    _In_ PWCHAR Id,
    _In_ ULONG MaxIdLen,
    _In_ BOOLEAN IsMultiSz,
    _In_ ULONG MaxSeparators,
    _In_ PUNICODE_STRING ServiceName)
{
    PWCHAR PtrPrevChar;
    PWCHAR PtrChar;
    PWCHAR StringEnd;
    WCHAR Char;
    ULONG SeparatorsCount;

    PAGED_CODE();
    DPRINT("PiFixupID: Id - %S\n", Id);

    SeparatorsCount = MAX_SEPARATORS_INSTANCEID;
    StringEnd = Id + MAX_DEVICE_ID_LEN;
    PtrPrevChar = NULL;

    for (PtrChar = Id; PtrChar < StringEnd; PtrChar++)
    {
        Char = *PtrChar;

        if (Char == UNICODE_NULL)
        {
            if (!IsMultiSz || (PtrPrevChar && PtrChar == PtrPrevChar + 1))
            {
                if (PtrChar < StringEnd &&
                    (MaxSeparators == MAX_SEPARATORS_MULTI_SZ ||
                     MaxSeparators == SeparatorsCount))
                {
                    return (PtrChar - Id) + 1;
                }

                break;
            }

            StringEnd += MAX_DEVICE_ID_LEN;
            PtrPrevChar = PtrChar;
        }
        else if (Char == ' ')
        {
            *PtrChar = '_';
        }
        else if (Char < ' ' || Char > 0x7Fu || Char == ',')
        {
            DPRINT("PiFixupID: Invalid character - %02X\n", *PtrChar);

            if (ServiceName)
            {
                DPRINT("PiFixupID: FIXME Log\n");
                ASSERT(FALSE);
                return 0;
            }

            return 0;
        }
        else if (Char == '\\')
        {
            SeparatorsCount++;

            if (SeparatorsCount > MaxSeparators)
            {
                DPRINT("PiFixupID: SeparatorsCount - %X, MaxSeparators - %X\n",
                       SeparatorsCount, MaxSeparators);

                if (ServiceName)
                {
                    DPRINT("PiFixupID: FIXME Log\n");
                    ASSERT(FALSE);
                }

                return 0;
            }
        }
    }

    DPRINT("PiFixupID: ID (%p) not valid\n", Id);

    if (ServiceName)
    {
        DPRINT("PiFixupID: FIXME Log\n");
        ASSERT(FALSE);
    }

    return 0;
}

VOID
NTAPI
PipEnumerationWorker(
    _In_ PVOID Context)
{
    DPRINT("PipEnumerationWorker()\n");
    ASSERT(FALSE);
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

    if (!PnPBootDriversLoaded)
    {
        DPRINT("PipRequestDeviceAction: PnPBootDriversLoaded - FALSE\n");
        KeReleaseSpinLock(&IopPnPSpinLock, OldIrql);
        return STATUS_SUCCESS;
    }

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

/* EOF */
