/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            ntoskrnl/po/poshtdwn.c
 * PURPOSE:         Power Manager Shutdown Code
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#ifdef NEWCC
#include <cache/newcc.h>
#endif

#define NDEBUG
#include <debug.h>

#include "inbv/logo.h"

/* GLOBALS *******************************************************************/

ULONG PopShutdownPowerOffPolicy;
KEVENT PopShutdownEvent;
PPOP_SHUTDOWN_WAIT_ENTRY PopShutdownThreadList;
LIST_ENTRY PopShutdownQueue;
KGUARDED_MUTEX PopShutdownListMutex;
ULONG PopCurrentLevel;
ULONG PopFullWake;
BOOLEAN PopShutdownListAvailable;
PDEVICE_OBJECT IopWarmEjectPdo = NULL;

extern POP_POWER_ACTION PopAction;
extern ULONG IoDeviceNodeTreeSequence;
extern ULONG PopCallSystemState;
extern ULONG PopSimulate;
extern KSPIN_LOCK PopWorkerLock;

/* PRIVATE FUNCTIONS *********************************************************/

VOID NTAPI IoFreePoDeviceNotifyList(_In_ PPO_DEVICE_NOTIFY_ORDER Order);

VOID
NTAPI
PopInitShutdownList(VOID)
{
    PAGED_CODE();

    /* Initialize the global shutdown event */
    KeInitializeEvent(&PopShutdownEvent, NotificationEvent, FALSE);

    /* Initialize the shutdown lists */
    PopShutdownThreadList = NULL;
    InitializeListHead(&PopShutdownQueue);

    /* Initialize the shutdown list lock */
    KeInitializeGuardedMutex(&PopShutdownListMutex);

    /* The list is available now */
    PopShutdownListAvailable = TRUE;
}

NTSTATUS
NTAPI
PoRequestShutdownWait(
    _In_ PETHREAD Thread)
{
    PPOP_SHUTDOWN_WAIT_ENTRY ShutDownWaitEntry;
    NTSTATUS Status;

    PAGED_CODE();

    /* Allocate a new shutdown wait entry */
    ShutDownWaitEntry = ExAllocatePoolWithTag(PagedPool, sizeof(*ShutDownWaitEntry), 'LSoP');
    if (!ShutDownWaitEntry)
    {
        DPRINT1("PoRequestShutdownWait: STATUS_NO_MEMORY\n");
        return STATUS_NO_MEMORY;
    }

    /* Reference the thread and save it in the wait entry */
    ObReferenceObject(Thread);
    ShutDownWaitEntry->Thread = Thread;

    /* Acquire the shutdown list lock */
    KeAcquireGuardedMutex(&PopShutdownListMutex);

    /* Check if the list is still available */
    if (PopShutdownListAvailable)
    {
        /* Insert the item in the list */
        ShutDownWaitEntry->NextEntry = PopShutdownThreadList;
        PopShutdownThreadList = ShutDownWaitEntry;

        /* We are successful */
        Status = STATUS_SUCCESS;
    }
    else
    {
        /* We cannot proceed, cleanup and return failure */
        DPRINT1("PoRequestShutdownWait: STATUS_UNSUCCESSFUL\n");
        ObDereferenceObject(Thread);
        ExFreePoolWithTag(ShutDownWaitEntry, 'LSoP');
        Status = STATUS_UNSUCCESSFUL;
    }

    /* Release the list lock */
    KeReleaseGuardedMutex(&PopShutdownListMutex);

    /* Return the status */
    return Status;
}

VOID
NTAPI
PopProcessShutDownLists(VOID)
{
    PPOP_SHUTDOWN_WAIT_ENTRY ShutDownWaitEntry;
    PWORK_QUEUE_ITEM WorkItem;
    PLIST_ENTRY ListEntry;

    /* First signal the shutdown event */
    KeSetEvent(&PopShutdownEvent, IO_NO_INCREMENT, FALSE);

    /* Acquire the shutdown list lock */
    KeAcquireGuardedMutex(&PopShutdownListMutex);

    /* Block any further attempts to register a shutdown event */
    PopShutdownListAvailable = FALSE;

    /* Release the list lock, since we are exclusively using the lists now */
    KeReleaseGuardedMutex(&PopShutdownListMutex);

    /* Process the shutdown queue */
    while (!IsListEmpty(&PopShutdownQueue))
    {
        /* Get the head entry */
        ListEntry = RemoveHeadList(&PopShutdownQueue);
        WorkItem = CONTAINING_RECORD(ListEntry, WORK_QUEUE_ITEM, List);

        /* Call the shutdown worker routine */
        WorkItem->WorkerRoutine(WorkItem->Parameter);
    }

    /* Now process the shutdown thread list */
    while (PopShutdownThreadList != NULL)
    {
        /* Get the top entry and remove it from the list */
        ShutDownWaitEntry = PopShutdownThreadList;
        PopShutdownThreadList = PopShutdownThreadList->NextEntry;

        /* Wait for the thread to finish and dereference it */
        KeWaitForSingleObject(ShutDownWaitEntry->Thread, 0, 0, 0, 0);
        ObDereferenceObject(ShutDownWaitEntry->Thread);

        /* Finally free the entry */
        ExFreePoolWithTag(ShutDownWaitEntry, 'LSoP');
    }
}

VOID
NTAPI
PopShutdownHandler(VOID)
{
    PUCHAR Logo1, Logo2;
    ULONG i;

    /* Stop all interrupts */
    KeRaiseIrqlToDpcLevel();
    _disable();

    /* Do we have boot video */
    if (InbvIsBootDriverInstalled())
    {
        /* Yes we do, cleanup for shutdown screen */
        if (!InbvCheckDisplayOwnership()) InbvAcquireDisplayOwnership();
        InbvResetDisplay();
        InbvSolidColorFill(0, 0, SCREEN_WIDTH - 1, SCREEN_HEIGHT - 1, BV_COLOR_BLACK);
        InbvEnableDisplayString(TRUE);
        InbvSetScrollRegion(0, 0, SCREEN_WIDTH - 1, SCREEN_HEIGHT - 1);

        /* Display shutdown logo and message */
        Logo1 = InbvGetResourceAddress(IDB_SHUTDOWN_MSG);
        Logo2 = InbvGetResourceAddress(IDB_LOGO_DEFAULT);
        if ((Logo1) && (Logo2))
        {
            InbvBitBlt(Logo1, VID_SHUTDOWN_MSG_LEFT, VID_SHUTDOWN_MSG_TOP);
            InbvBitBlt(Logo2, VID_SHUTDOWN_LOGO_LEFT, VID_SHUTDOWN_LOGO_TOP);
        }
    }
    else
    {
        /* Do it in text-mode */
        for (i = 0; i < 25; i++) InbvDisplayString("\r\n");
        InbvDisplayString("                       ");
        InbvDisplayString("The system may be powered off now.\r\n");
    }

    /* Hang the system */
    for (;;) HalHaltSystem();
}

VOID
NTAPI
PopShutdownSystem(
    _In_ POWER_ACTION SystemAction)
{
    /* Note should notify caller of NtPowerInformation(PowerShutdownNotification) */

    /* Unload symbols */
    DPRINT("PopShutdownSystem: It's the final countdown...%lx\n", SystemAction);
    DbgUnLoadImageSymbols(NULL, (PVOID)-1, 0);

    /* Run the thread on the boot processor */
    KeSetSystemAffinityThread(1);

    /* Now check what the caller wants */
    switch (SystemAction)
    {
        /* Reset */
        case PowerActionShutdownReset:
            DPRINT("PopShutdownSystem: PowerActionShutdownReset\n");

            /* Try platform driver first, then legacy */
            //PopInvokeSystemStateHandler(PowerStateShutdownReset, NULL);
            //PopSetSystemPowerState(PowerSystemShutdown, SystemAction);
            HalReturnToFirmware(HalRebootRoutine);
            break;

        case PowerActionShutdown:
            DPRINT("PopShutdownSystem: PowerActionShutdown\n");

            /* Check for group policy that says to use "it is now safe" screen */
            if (PopShutdownPowerOffPolicy)
            {
                DPRINT("PopShutdownSystem: FIXME - switch to legacy shutdown handler\n");
                //PopPowerStateHandlers[PowerStateShutdownOff].Handler = PopShutdownHandler;
            }

        case PowerActionShutdownOff:
            DPRINT("PopShutdownSystem: PowerActionShutdownOff\n");

            /* Call shutdown handler */
            //PopInvokeSystemStateHandler(PowerStateShutdownOff, NULL);
            PopShutdownHandler();

            /* If that didn't work, call the HAL */
            HalReturnToFirmware(HalPowerDownRoutine);
            break;

        default:
            break;
    }

    /* Anything else should not happen */
    KeBugCheckEx(INTERNAL_POWER_ERROR, 5, 0, 0, 0);
}

PWSTR
NTAPI
IopCaptureObjectName(
    _In_ PVOID Object)
{
    PWCHAR ObjectName = NULL;
    ULONG ReturnLength;
    WCHAR ObjectInfo[0x100];
    NTSTATUS Status;
    POBJECT_NAME_INFORMATION ObjectNameInfo = (POBJECT_NAME_INFORMATION)ObjectInfo;
    ULONG Size;

    //DPRINT("IopCaptureObjectName: Object %p\n", Object);

    if (!Object)
        return ObjectName;

    Status = ObQueryNameString(Object, ObjectNameInfo, 0x200, &ReturnLength);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IopCaptureObjectName: Status %X\n", Status);
        ASSERT(FALSE); // PoDbgBreakPointEx();
        return ObjectName;
    }

    if (!ObjectNameInfo->Name.Buffer)
        return ObjectName;

    Size = ObjectNameInfo->Name.Length;

    ObjectName = ExAllocatePoolWithTag(NonPagedPool, (Size + sizeof(WCHAR)), 'rwPD');
    if (!ObjectName)
    {
        DPRINT1("IopCaptureObjectName: Allocate failed\n");
        ASSERT(FALSE); // PoDbgBreakPointEx();
        return ObjectName;
    }

    RtlCopyMemory(ObjectName, ObjectNameInfo->Name.Buffer, Size);
    ObjectName[Size / sizeof(WCHAR)] = UNICODE_NULL;

    return ObjectName;
}

NTSTATUS
NTAPI
IoBuildPoDeviceNotifyList(
    _In_ PPO_DEVICE_NOTIFY_ORDER Order)
{
    PPO_DEVICE_NOTIFY notify;
    PDEVICE_NODE node;
    PDEVICE_NODE nextnode;
    PDEVICE_NODE NotifyNode;
    UCHAR OrderLevel;
    PLIST_ENTRY OrderHeader;
    PLIST_ENTRY Entry;
    LIST_ENTRY list;
    ULONG ix;
    LONG Level = -1;
    UCHAR MaxLevel;

    DPRINT("IoBuildPoDeviceNotifyList: Order %p IopRootDeviceNode %X\n", Order, IopRootDeviceNode);

    PiLockDeviceActionQueue();

    RtlZeroMemory(Order, sizeof(*Order));

    Order->DevNodeSequence = IoDeviceNodeTreeSequence;

    for (ix = 0; ix < 8; ix++)
    {
        KeInitializeEvent(&Order->OrderLevel[ix].LevelReady, NotificationEvent, FALSE);

        InitializeListHead(&Order->OrderLevel[ix].WaitSleep);
        InitializeListHead(&Order->OrderLevel[ix].ReadySleep);
        InitializeListHead(&Order->OrderLevel[ix].Pending);
        InitializeListHead(&Order->OrderLevel[ix].Complete);
        InitializeListHead(&Order->OrderLevel[ix].ReadyS0);
        InitializeListHead(&Order->OrderLevel[ix].WaitS0);
    }

    InitializeListHead(&list);

    for (nextnode = IopRootDeviceNode; ; Level++)
    {
        node = nextnode;

        nextnode = nextnode->Child;
        if (!nextnode)
            break;
    }

    MaxLevel = Level;

    while (node != IopRootDeviceNode)
    {
        notify = ExAllocatePoolWithTag(NonPagedPool, sizeof(*notify), 'rwPD');
        if (!notify)
        {
            DPRINT1("IoBuildPoDeviceNotifyList: STATUS_INSUFFICIENT_RESOURCES\n");
            Order->DevNodeSequence = 0;
            PiUnlockDeviceActionQueue();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(notify, sizeof(*notify));

        ASSERT(node->Notify == NULL);
        node->Notify = notify;
        notify->Node = node;

        notify->DeviceObject = node->PhysicalDeviceObject;
        notify->TargetDevice = IoGetAttachedDeviceReference(node->PhysicalDeviceObject);
        notify->DriverName = IopCaptureObjectName(notify->TargetDevice->DriverObject);
        notify->DeviceName = IopCaptureObjectName(notify->TargetDevice);

        ObReferenceObject(notify->DeviceObject);

        DPRINT("IoBuildPoDeviceNotifyList: node %p,  notify %p, DO %p, TargetDO %p, DriverName '%S', DeviceName '%S'\n",
               node, notify, notify->DeviceObject, notify->TargetDevice, notify->DriverName, notify->DeviceName);

        OrderLevel = 0;

        if (notify->TargetDevice->DeviceType != FILE_DEVICE_SCREEN &&
            notify->TargetDevice->DeviceType != FILE_DEVICE_VIDEO)
        {
            OrderLevel = 1;
        }

        if (notify->TargetDevice->Flags & DO_POWER_PAGABLE)
            OrderLevel |= 4;

        notify->OrderLevel = OrderLevel;

        DPRINT("IoBuildPoDeviceNotifyList: OrderLevel %X\n", OrderLevel);

        if (!Level && (node->InterfaceType != Internal) && !(node->Flags & DNF_HAL_NODE))
        {
            InsertHeadList(&list, &notify->Link);
            DPRINT("IoBuildPoDeviceNotifyList: [%X] [%X] &list %X, Entry %X, node %X\n",
                   Level, OrderLevel, &list, &notify->Link, node);
        }
        else
        {
            Order->OrderLevel[OrderLevel].DeviceCount++;

            if (node->Child)
            {
                OrderHeader = &Order->OrderLevel[OrderLevel].WaitSleep;

                DPRINT("IoBuildPoDeviceNotifyList: [%X] HeaderWaitSleep[%X] %X, Entry %X, node %X\n",
                       Level, OrderLevel, OrderHeader, notify, node);
            }
            else
            {
                OrderHeader = &Order->OrderLevel[OrderLevel].ReadySleep;

                DPRINT("IoBuildPoDeviceNotifyList: [%X] HeaderReadySleep[%X] %X, Entry %X, node %X\n",
                       Level, OrderLevel, OrderHeader, notify, node);
            }

            InsertHeadList(OrderHeader, &notify->Link);
        }

        if (!node->Sibling)
        {
            Level--;
            node = node->Parent;

            DPRINT("IoBuildPoDeviceNotifyList: [%X] node %p\n", Level, node);

            continue;
        }

        DPRINT("IoBuildPoDeviceNotifyList: [%X] node %p, nextnode %X\n", Level, node->Sibling, node->Sibling->Child);

        nextnode = node->Sibling->Child;
        node = node->Sibling;

        for (; nextnode; nextnode = nextnode->Child)
        {
            Level++;

            if (MaxLevel < Level)
                MaxLevel = Level;

            DPRINT("IoBuildPoDeviceNotifyList: [%X] node %p, nextnode %X\n", Level, nextnode, nextnode->Child);

            node = nextnode;
        }
    }

    DPRINT("\n");

    while (!IsListEmpty(&list))
    {
        Entry = RemoveHeadList(&list);
        notify = CONTAINING_RECORD(Entry, PO_DEVICE_NOTIFY, Link);

        notify->OrderLevel |= 2;
        Order->OrderLevel[notify->OrderLevel].DeviceCount++;

        NotifyNode = notify->Node;

        if (NotifyNode->Child)
        {
            OrderHeader = &Order->OrderLevel[notify->OrderLevel].WaitSleep;

            DPRINT("IoBuildPoDeviceNotifyList: [%X] HeaderWaitSleep[%X] %X, Entry %X, NotifyNode %X\n",
                   Level, notify->OrderLevel, OrderHeader, notify, NotifyNode);
        }
        else
        {
            OrderHeader = &Order->OrderLevel[notify->OrderLevel].ReadySleep;

            DPRINT("IoBuildPoDeviceNotifyList: [%X] HeaderReadySleep[%X] %X, Entry %X, NotifyNode %X\n",
                   Level, notify->OrderLevel, OrderHeader, notify, NotifyNode);
        }

        InsertHeadList(OrderHeader, &notify->Link);

        nextnode = NotifyNode->Child;
        if (!nextnode)
            continue;

        do
        {
            DPRINT("IoBuildPoDeviceNotifyList: [%X] node %p, nextnode %X\n", Level, nextnode, nextnode->Child);
            node = nextnode;
            nextnode = nextnode->Child;
        }
        while (nextnode);

        while (node != NotifyNode)
        {
            if (node->Notify)
            {
                RemoveEntryList(&node->Notify->Link);

                Order->OrderLevel[node->Notify->OrderLevel].DeviceCount--;
                node->Notify->OrderLevel |= 2;
                Order->OrderLevel[node->Notify->OrderLevel].DeviceCount++;

                if (node->Child)
                {
                    OrderHeader = &Order->OrderLevel[node->Notify->OrderLevel].WaitSleep;

                    DPRINT("IoBuildPoDeviceNotifyList: [%X] HeaderWaitSleep[%X] %X, Entry %X, node %X\n",
                           Level, OrderLevel, OrderHeader, notify, node);
                }
                else
                {
                    OrderHeader = &Order->OrderLevel[node->Notify->OrderLevel].ReadySleep;
                    DPRINT("IoBuildPoDeviceNotifyList: [%X] HeaderReadySleep[%X] %X, Entry %X, node %X\n",
                           Level, OrderLevel, OrderHeader, notify, node);
                }

                InsertHeadList(OrderHeader, &node->Notify->Link);
            }

            nextnode = node->Sibling;
            if (!nextnode)
            {
                node = node->Parent;
                continue;
            }

            for (; nextnode; nextnode = nextnode->Child)
            {
                DPRINT("IoBuildPoDeviceNotifyList: [%X] node %p, nextnode %X\n", Level, nextnode, nextnode->Child);
                node = nextnode;
            }
        }
    }

    DPRINT("\n");

    if (!IopRootDeviceNode->Child)
        goto Exit;

    nextnode = IopRootDeviceNode->Child;
    do
    {
        DPRINT("IoBuildPoDeviceNotifyList: [%X] node %p, nextnode %X\n", Level, nextnode, nextnode->Child);
        node = nextnode;
        nextnode = nextnode->Child;
    }
    while (nextnode);

    DPRINT("\n");

    while (node != IopRootDeviceNode)
    {
        if (node->Parent != IopRootDeviceNode)
        {
            notify = node->Parent->Notify;
            notify->ChildCount++;
            notify->ActiveChild++;

            DPRINT("IoBuildPoDeviceNotifyList: [%X] notify %p, ChildCount %X, ActiveChild %X\n",
                   notify->OrderLevel, notify, notify->ChildCount, notify->ActiveChild);

            if (notify->OrderLevel > node->Notify->OrderLevel)
            {
                RemoveEntryList(&notify->Link);

                DPRINT("IoBuildPoDeviceNotifyList: [%X] %X, [%X] %X\n",
                       notify->OrderLevel, (Order->OrderLevel[notify->OrderLevel].DeviceCount - 1), 
                       node->Notify->OrderLevel, (Order->OrderLevel[node->Notify->OrderLevel].DeviceCount + 1));

                Order->OrderLevel[notify->OrderLevel].DeviceCount--;
                notify->OrderLevel = node->Notify->OrderLevel;
                Order->OrderLevel[node->Notify->OrderLevel].DeviceCount++;

                InsertHeadList(&Order->OrderLevel[notify->OrderLevel].WaitSleep, &notify->Link);

                DPRINT("IoBuildPoDeviceNotifyList: [%X] [%X] %X, Entry %X, node %X\n",
                       Level, notify->OrderLevel, &Order->OrderLevel[notify->OrderLevel].WaitSleep, &notify->Link, node);
            }
        }

        nextnode = node->Sibling;
        if (!nextnode)
        {
            DPRINT("IoBuildPoDeviceNotifyList: node %p, node->Parent %X\n", node, node->Parent);
            node = node->Parent;

            DPRINT("\n");
            continue;
        }

        for (; nextnode; nextnode = nextnode->Child)
        {
            DPRINT("IoBuildPoDeviceNotifyList: node %p, nextnode %X\n", nextnode, nextnode->Child);
            node = nextnode;
        }

        DPRINT("\n");
    }

Exit:
    Order->WarmEjectPdoPointer = &IopWarmEjectPdo;
    return STATUS_SUCCESS;
}

PPO_DEVICE_NOTIFY
NTAPI
IoGetPoNotifyParent(
    _In_ PPO_DEVICE_NOTIFY Notify)
{
    PDEVICE_NODE DeviceNode;
    PDEVICE_NODE Parent;

    DeviceNode = Notify->Node;
    Parent = DeviceNode->Parent;

    if (DeviceNode == IopRootDeviceNode)
        return NULL;

    return Parent->Notify;
}

BOOLEAN
NTAPI
PopCheckSystemPowerIrpStatus(
    _In_ PPOP_DEVICE_SYS_STATE DevState,
    _In_ PIRP Irp,
    _In_ BOOLEAN Param3)
{
    NTSTATUS Status;

    DPRINT("PopCheckSystemPowerIrpStatus: DevState %p, Irp %X, Param3 %X\n", DevState, Irp, Param3);

    Status = Irp->IoStatus.Status;
    DPRINT("PopCheckSystemPowerIrpStatus: Status %X\n", Status);

    if (NT_SUCCESS(Status))
        return TRUE;

    if (DevState->IgnoreErrors)
        return TRUE;

    if (Status == STATUS_CANCELLED)
        return TRUE;

    if (Status == STATUS_NOT_SUPPORTED)
    {
        DPRINT1("PopCheckSystemPowerIrpStatus: STATUS_NOT_SUPPORTED\n");
        ASSERT(FALSE); // PoDbgBreakPointEx();
    }

    DPRINT("PopCheckSystemPowerIrpStatus: return FALSE \n");
    return FALSE;
}

NTSTATUS
NTAPI
PopCompleteSystemPowerIrp(
    _In_ PDEVICE_OBJECT TargetDevice,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PPOP_DEVICE_POWER_IRP PowerIrp = Context;
    PPOP_DEVICE_SYS_STATE DevState;
    PPO_NOTIFY_ORDER_LEVEL Level;
    PPO_DEVICE_NOTIFY Notify;
    PPO_DEVICE_NOTIFY ParentNotify;
    BOOLEAN IsFireEvent = FALSE;
    KIRQL OldIrql;

    DPRINT("PopCompleteSystemPowerIrp: TargetDevice %p, Irp %X, Context %X\n", TargetDevice, Irp, PowerIrp);

    DevState = PopAction.DevState;

    KeAcquireSpinLock(&DevState->SpinLock, &OldIrql);

    RemoveEntryList(&PowerIrp->Pending);
    PowerIrp->Pending.Flink = NULL;

    InsertTailList(&DevState->Head.Complete, &PowerIrp->Complete);

    Notify = PowerIrp->Notify;
    ASSERT(Notify->OrderLevel == PopCurrentLevel);

    Level = &DevState->Order.OrderLevel[Notify->OrderLevel];

    RemoveEntryList(&Notify->Link);
    InsertTailList(&Level->Complete, &Notify->Link);

    if (DevState->Waking)
    {
        DPRINT1("PopCompleteSystemPowerIrp: FIXME\n");
        Level->ActiveCount++;
        ASSERT(FALSE); // PoDbgBreakPointEx();
    }
    else if (NT_SUCCESS(Irp->IoStatus.Status) || DevState->IgnoreErrors)
    {
        Level->ActiveCount--;

        ParentNotify = IoGetPoNotifyParent(Notify);
        if (ParentNotify)
        {
            ASSERT(ParentNotify->ActiveChild > 0);

            ParentNotify->ActiveChild--;
            if (!ParentNotify->ActiveChild)
            {
                RemoveEntryList(&ParentNotify->Link);
                InsertTailList(&DevState->Order.OrderLevel[ParentNotify->OrderLevel].ReadySleep, &ParentNotify->Link);
            }
        }
    }

    if (DevState->WaitAny ||
        (DevState->WaitAll && IsListEmpty(&DevState->Head.Pending)))
    {
        IsFireEvent = TRUE;
    }

    if (!PopCheckSystemPowerIrpStatus(DevState, Irp, TRUE) && NT_SUCCESS(DevState->Status))
    {
        if (PopAction.Action != PowerActionWarmEject ||
            !DevState->FailedDevice ||
            (PowerIrp->Notify->DeviceObject != *DevState->Order.WarmEjectPdoPointer))
        {
            DevState->FailedDevice = PowerIrp->Notify->DeviceObject;
        }

        DevState->Status = Irp->IoStatus.Status;
        IsFireEvent = TRUE;
    }

    KeReleaseSpinLock(&DevState->SpinLock, OldIrql);

    if (IsFireEvent)
        KeSetEvent(&DevState->Event, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

VOID
NTAPI
PopWaitForSystemPowerIrp(
    _In_ PPOP_DEVICE_SYS_STATE DevState,
    _In_ BOOLEAN IsWaitAll)
{
    BOOLEAN IsCompleteList = FALSE;
    PPOP_DEVICE_POWER_IRP PowerIrp;
    PPO_DEVICE_NOTIFY Notify;
    LARGE_INTEGER Timeout;
    PLIST_ENTRY Entry;
    PIRP Irp;
    KIRQL OldIrql;
    NTSTATUS Status;

    DPRINT("PopWaitForSystemPowerIrp: DevState %p, IsWaitAll %X\n" , DevState, IsWaitAll);

    KeAcquireSpinLock(&DevState->SpinLock, &OldIrql);

Start:

    if (!IsListEmpty(&DevState->Head.Complete))
    {
        PEXTENDED_DEVOBJ_EXTENSION DeviceExtension;
        PEXTENDED_DEVOBJ_EXTENSION TargetDeviceExtension;
        POP_DEVICE_EXTENSION_POWER_FLAGS PowerFlags;
        POP_DEVICE_EXTENSION_POWER_FLAGS TargetPowerFlags;

        IsCompleteList = TRUE;

        do
        {
            Entry = DevState->Head.Complete.Flink;
            RemoveEntryList(Entry);
            Entry->Flink = NULL;

            PowerIrp = CONTAINING_RECORD(Entry, POP_DEVICE_POWER_IRP, Complete);

            Notify = PowerIrp->Notify;
            Irp = PowerIrp->Irp;

            DeviceExtension = IoGetDevObjExtension(Notify->DeviceObject);
            PowerFlags.AsULONG = DeviceExtension->PowerFlags;

            TargetDeviceExtension = IoGetDevObjExtension(Notify->TargetDevice);
            TargetPowerFlags.AsULONG = TargetDeviceExtension->PowerFlags;

            if (PowerFlags.SystemActive == 1 || TargetPowerFlags.SystemActive == 1)
            {
                KeReleaseSpinLock(&DevState->SpinLock, OldIrql);
                DPRINT1("PopWaitForSystemPowerIrp: KeBugCheckEx(0x9F)\n");
                ASSERT(FALSE); // PoDbgBreakPointEx();
                KeBugCheckEx(0x9F, 0x500, 2, (ULONG_PTR)Notify->TargetDevice, (ULONG_PTR)Notify->DeviceObject);
            }

            if (PopCheckSystemPowerIrpStatus(DevState, Irp, TRUE))
            {
                if (!PopCheckSystemPowerIrpStatus(DevState, Irp, FALSE))
                {
                    DPRINT1("PopWaitForSystemPowerIrp: ASSERT\n");
                    ASSERT(FALSE); // PoDbgBreakPointEx();
                }

                IoFreeIrp(Irp);

                PowerIrp->Irp = NULL;
                PowerIrp->Notify = NULL;

                PowerIrp->Free.Next = DevState->Head.Free.Next;
                DevState->Head.Free.Next = &PowerIrp->Free;
            }
            else
            {
                ASSERT(!DevState->Waking);
                InsertTailList(&DevState->Head.Failed, &PowerIrp->Failed);
            }
        }
        while (!IsListEmpty(&DevState->Head.Complete));
    }

    if (!(PopCallSystemState & 2))
    {
        KeReleaseSpinLock(&DevState->SpinLock, OldIrql);
        PopSystemIrpDispatchWorker(FALSE);
        KeAcquireSpinLock(&DevState->SpinLock, &OldIrql);
    }

    if (!NT_SUCCESS(DevState->Status) && DevState->Cancelled == FALSE && DevState->Waking == FALSE)
    {
        DevState->Cancelled = TRUE;

        for (Entry = DevState->Head.Pending.Flink;
             Entry != &DevState->Head.Pending;
             Entry = Entry->Flink)
        {
            PowerIrp = CONTAINING_RECORD(Entry, POP_DEVICE_POWER_IRP, Pending);
            InsertTailList(&DevState->Head.Abort, &PowerIrp->Abort);
        }

        KeReleaseSpinLock(&DevState->SpinLock, OldIrql);
        Entry = DevState->Head.Abort.Flink;

        if (!IsListEmpty(&DevState->Head.Abort))
        {
            while (TRUE)
            {
                PowerIrp = CONTAINING_RECORD(Entry, POP_DEVICE_POWER_IRP, Abort);
                IoCancelIrp(PowerIrp->Irp);

                Entry = Entry->Flink;
                if (Entry == &DevState->Head.Abort)
                    break;
            }
        }

        KeAcquireSpinLock(&DevState->SpinLock, &OldIrql);
        InitializeListHead(&DevState->Head.Abort);

        goto Start;
    }

    if ((!IsWaitAll && IsCompleteList) || IsListEmpty(&DevState->Head.Pending))
    {
        if (!DevState->Head.Free.Next && IsListEmpty(&DevState->Head.Failed))
        {
            PowerIrp = CONTAINING_RECORD(DevState->Head.Failed.Blink, POP_DEVICE_POWER_IRP, Failed);
            RemoveEntryList(DevState->Head.Failed.Blink);

            PowerIrp->Failed.Flink = NULL;
            PowerIrp->Irp = NULL;
            PowerIrp->Notify = NULL;

            PowerIrp->Free.Next = DevState->Head.Free.Next;
            DevState->Head.Free.Next = &PowerIrp->Free;
        }

        goto Exit;
    }

    DevState->WaitAll = TRUE;
    DevState->WaitAny = (IsWaitAll == FALSE);

    KeClearEvent(&DevState->Event);

    KeReleaseSpinLock(&DevState->SpinLock, OldIrql);
    Timeout.QuadPart = (-10000000ll * (DevState->Cancelled ? 5 : 30));
    Status = KeWaitForSingleObject(&DevState->Event, Suspended, KernelMode, FALSE, &Timeout);
    KeAcquireSpinLock(&DevState->SpinLock, &OldIrql);

    DevState->WaitAll = FALSE;
    DevState->WaitAny = FALSE;

    if (Status == STATUS_TIMEOUT)
    {
        for (Entry = DevState->Head.Pending.Flink;
             Entry != &DevState->Head.Pending;
             Entry = Entry->Flink)
        {
            PowerIrp = CONTAINING_RECORD(Entry, POP_DEVICE_POWER_IRP, Pending);
            InsertTailList(&DevState->Head.Abort, &PowerIrp->Abort);
        }

        KeReleaseSpinLock(&DevState->SpinLock, OldIrql);
        Entry = DevState->Head.Abort.Flink;

        if (!IsListEmpty(&DevState->Head.Abort))
        {
            while (TRUE)
            {
                Entry = Entry->Flink;
                if (Entry == &DevState->Head.Abort)
                    break;
            }
        }

        KeAcquireSpinLock(&DevState->SpinLock, &OldIrql);
        InitializeListHead(&DevState->Head.Abort);
    }

    goto Start;

Exit:
    KeReleaseSpinLock(&DevState->SpinLock, OldIrql);
}

POWER_ACTION
NTAPI
PopMapInternalActionToIrpAction(
    _In_ POWER_ACTION Action,
    _In_ SYSTEM_POWER_STATE SystemPowerState,
    _In_ BOOLEAN IsResetWarmEject)
{
    ASSERT(Action != PowerActionHibernate);

    if (Action == PowerActionWarmEject)
    {
        if (IsResetWarmEject)
            return (PowerActionSleep + (SystemPowerState == PowerSystemHibernate));

        ASSERT((SystemPowerState >= PowerSystemSleeping1) &&
               (SystemPowerState <= PowerSystemHibernate));

        return PowerActionWarmEject;
    }

    if (SystemPowerState == PowerSystemHibernate)
        return PowerActionHibernate;

    return Action;
}

VOID
NTAPI
PopNotifyDevice(
    _In_ PPOP_DEVICE_SYS_STATE DevState,
    _In_ PPO_DEVICE_NOTIFY Notify)
{
    PPOP_DEVICE_POWER_IRP PowerIrp;
    PIO_STACK_LOCATION IoStack;
    POWER_ACTION ShutdownType;
    PDEVICE_OBJECT Device;
    PIRP Irp;
    ULONG CallSystemState;
    BOOLEAN IsResetWarmEject;
    KIRQL OldIrql;

    DPRINT("PopNotifyDevice: DevState %p, Notify %X\n", DevState,  Notify);

    ASSERT(PopCurrentLevel == Notify->OrderLevel);

    if (!(Notify->OrderLevel & 4))
        CallSystemState = 3;
    else
        CallSystemState = 1;

    if (PopCallSystemState != CallSystemState)
    {
        KeAcquireSpinLock(&PopWorkerLock, &OldIrql);
        PopCallSystemState = CallSystemState;
        KeReleaseSpinLock(&PopWorkerLock, OldIrql);
    }

    while (TRUE)
    {
        PowerIrp = CONTAINING_RECORD(DevState->Head.Free.Next, POP_DEVICE_POWER_IRP, Free);
        if (PowerIrp)
            break;

        PopWaitForSystemPowerIrp(DevState, FALSE);
    }

    DevState->Head.Free.Next = PowerIrp->Free.Next;

    for (Device = Notify->TargetDevice; ; Device = Notify->TargetDevice)
    {
        Irp = IoAllocateIrp(Device->StackSize, FALSE);
        if (Irp)
            break;

        PopWaitForSystemPowerIrp(DevState, FALSE);
    }

    DPRINT("PopNotifyDevice: DevState->Waking %X\n", DevState->Waking);

    if (DevState->Waking)
    {
        Notify->WakeNeeded = FALSE;
    }
    else
    {
        if (DevState->Order.DevNodeSequence != IoDeviceNodeTreeSequence)
        {
            DPRINT1("PopNotifyDevice: DevState->Order.DevNodeSequence %X\n", DevState->Order.DevNodeSequence);
            ASSERT(FALSE); // PoDbgBreakPointEx();
        }

        if (!NT_SUCCESS(DevState->Status))
        {
            PowerIrp->Free.Next = DevState->Head.Free.Next;
            DevState->Head.Free.Next = &PowerIrp->Free;
            IoFreeIrp(Irp);
            return;
        }

        Notify->WakeNeeded = TRUE;
    }

    PowerIrp->Notify = Notify;
    PowerIrp->Irp = Irp;

    ExInterlockedInsertTailList(&DevState->Head.Pending, &PowerIrp->Pending, &DevState->SpinLock);

    IoStack = Irp->Tail.Overlay.CurrentStackLocation;

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    IoStack--;

    IoStack->MajorFunction = IRP_MJ_POWER;
    IoStack->MinorFunction = DevState->IrpMinor;

    IoStack->Parameters.Power.SystemContext = 0;
    IoStack->Parameters.Power.Type = SystemPowerState;
    IoStack->Parameters.Power.State.SystemState = DevState->SystemState;

    ASSERT(PopAction.Action != PowerActionHibernate);

    IsResetWarmEject = (DevState->Waking || (*DevState->Order.WarmEjectPdoPointer != Notify->DeviceObject));
    ShutdownType = PopMapInternalActionToIrpAction(PopAction.Action, DevState->SystemState, IsResetWarmEject);

    if (ShutdownType == PowerActionWarmEject &&
        *DevState->Order.WarmEjectPdoPointer == Notify->DeviceObject &&
        DevState->IrpMinor == IRP_MN_SET_POWER)
    {
        *DevState->Order.WarmEjectPdoPointer = NULL;
    }

    IoStack->Parameters.Power.ShutdownType = ShutdownType;

    IoSetCompletionRoutine(Irp, PopCompleteSystemPowerIrp, PowerIrp, TRUE, TRUE, TRUE);
    DPRINT("PopNotifyDevice: PowerIrp %X\n", PowerIrp);

    PoCallDriver(Notify->TargetDevice, Irp);

    DPRINT("PopNotifyDevice: exit\n");
}

BOOLEAN
NTAPI
IsHackingPdo(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PDEVICE_NODE DeviceNode = IopGetDeviceNode(DeviceObject);

    DPRINT1("IsHackingPdo: DeviceObject %p, DeviceNode %X\n", DeviceObject, DeviceNode);

  #if 1
    if (DeviceNode &&
        ((DeviceNode->ServiceName.Buffer && wcsstr(DeviceNode->ServiceName.Buffer, L"ftdisk")) ||
         (DeviceNode->InstancePath.Buffer && wcsstr(DeviceNode->InstancePath.Buffer, L"STORAGE\\Volume"))))
    {
        DPRINT1("IsHackingPdo: Skip ftdisk\n");
        return TRUE;
    }
  #endif

  #if 1
    if (DeviceNode &&
        ((DeviceNode->ServiceName.Buffer && wcsstr(DeviceNode->ServiceName.Buffer, L"partmgr")) ||
         (DeviceNode->InstancePath.Buffer && wcsstr(DeviceNode->InstancePath.Buffer, L"IDE"))))
    {
        DPRINT1("IsHackingPdo: Skip partmgr\n");
        return TRUE;
    }
  #endif

    return FALSE;
}

VOID
NTAPI
PopSleepDeviceList(
    _In_ PPOP_DEVICE_SYS_STATE DevState,
    _In_ PPO_NOTIFY_ORDER_LEVEL OrderLevel)
{
    PLIST_ENTRY Entry;
    PPO_DEVICE_NOTIFY Notify;
    PLIST_ENTRY ListHead;
    PLIST_ENTRY HeadComplete;
    KIRQL OldIrql;

    DPRINT("PopSleepDeviceList: DevState %p, OrderLevel %X\n", DevState,  OrderLevel);

    ASSERT(!DevState->Waking);
    ASSERT(IsListEmpty(&OrderLevel->Pending));
    ASSERT(IsListEmpty(&OrderLevel->ReadyS0));
    ASSERT(IsListEmpty(&OrderLevel->WaitS0));

    for (Entry = OrderLevel->ReadyS0.Flink;
         Entry != &OrderLevel->ReadyS0;
         )
    {
        Notify = CONTAINING_RECORD(Entry, PO_DEVICE_NOTIFY, Link);

        DPRINT("PopSleepDeviceList: Notify->ChildCount %X\n", Notify->ChildCount);
        if (Notify->ChildCount)
        {
            ListHead = &OrderLevel->WaitSleep;
        }
        else
        {
            ASSERT(Notify->ActiveChild == 0);
            ListHead = &OrderLevel->ReadySleep;
        }

        InsertHeadList(ListHead, Entry);
    }

    HeadComplete = &OrderLevel->Complete;

    while (!IsListEmpty(HeadComplete))
    {
        Notify = CONTAINING_RECORD(HeadComplete->Flink, PO_DEVICE_NOTIFY, Link);
        RemoveEntryList(HeadComplete);

        DPRINT("PopSleepDeviceList: Notify->ChildCount %X\n", Notify->ChildCount);

        if (Notify->ChildCount)
        {
            ListHead = &OrderLevel->WaitSleep;
        }
        else
        {
            ASSERT(Notify->ActiveChild == 0);
            ListHead = &OrderLevel->ReadySleep;
        }

        InsertHeadList(ListHead, &Notify->Link);
    }

    ASSERT(!IsListEmpty(&OrderLevel->ReadySleep));

    OrderLevel->ActiveCount = OrderLevel->DeviceCount;
    DPRINT("PopSleepDeviceList: OrderLevel->DeviceCount %X\n", OrderLevel->DeviceCount);

    while (TRUE)
    {
        KeAcquireSpinLock(&DevState->SpinLock, &OldIrql);

        if (!OrderLevel->ActiveCount || !NT_SUCCESS(DevState->Status))
            break;

        DPRINT("PopSleepDeviceList: IsListEmpty(&OrderLevel->ReadySleep) %X\n", IsListEmpty(&OrderLevel->ReadySleep));

        if (IsListEmpty(&OrderLevel->ReadySleep))
        {
            DPRINT("PopSleepDeviceList: OrderLevel->ActiveCount %X\n", OrderLevel->ActiveCount);

            if (OrderLevel->ActiveCount)
            {
                ASSERT(!IsListEmpty(&OrderLevel->Pending));
                KeReleaseSpinLock(&DevState->SpinLock, OldIrql);
                PopWaitForSystemPowerIrp(DevState, 0);
            }
        }
        else
        {
            PDEVICE_NODE DeviceNode;

            Notify = CONTAINING_RECORD(OrderLevel->ReadySleep.Flink, PO_DEVICE_NOTIFY, Link);
            DeviceNode = Notify->Node;

            DPRINT("PopSleepDeviceList: Notify %X, DeviceNode %X, Child %X\n", Notify, DeviceNode, DeviceNode->Child);

            RemoveHeadList(&OrderLevel->ReadySleep);

          #if 1
            if (IsHackingPdo(DeviceNode->PhysicalDeviceObject))
            {
                DPRINT("PopSleepDeviceList: IsHackingPdo(%p) ret TRUE\n", DeviceNode->PhysicalDeviceObject);
                KeReleaseSpinLock(&DevState->SpinLock, OldIrql);
                return;
            }
          #endif

            InsertTailList(&OrderLevel->Pending, &Notify->Link);
            KeReleaseSpinLock(&DevState->SpinLock, OldIrql);

            if (Notify->ActiveChild)
            {
                DPRINT("PopSleepDeviceList: ActiveChild %X, ChildCount %X\n", Notify->ActiveChild, Notify->ChildCount);
            }

            PopNotifyDevice(DevState, Notify);
        }
    }

    KeReleaseSpinLock(&DevState->SpinLock, OldIrql);
}

NTSTATUS
NTAPI
PopSetDevicesSystemState(
    _In_ BOOLEAN IsWaking)
{
    PPOP_DEVICE_SYS_STATE DevState;
    PPO_NOTIFY_ORDER_LEVEL OrderLevel;
    LONG ix;
    BOOLEAN DidIoMmShutdown = FALSE;
    BOOLEAN IsEventCallout;

    DPRINT("PopSetDevicesSystemState: IsWaking %X\n", IsWaking);

    ASSERT(PopAction.DevState);
    DevState = PopAction.DevState;

    DevState->IrpMinor = PopAction.IrpMinor;
    DevState->SystemState = PopAction.SystemState;
    DevState->Status = STATUS_SUCCESS;
    DevState->FailedDevice = NULL;
    DevState->Cancelled = FALSE;
    DevState->IgnoreErrors = FALSE;
    DevState->IgnoreNotImplemented = FALSE;
    DevState->Waking = IsWaking;

    DPRINT("PopSetDevicesSystemState: FIXME PPerfGlobalGroupMask\n");

    if (PopAction.IrpMinor == IRP_MN_SET_POWER && PopFullWake & 5)
        IsEventCallout = TRUE;
    else
        IsEventCallout = FALSE;

    if (PopAction.Shutdown)
    {
        DevState->IgnoreNotImplemented = TRUE;

        if (PopAction.IrpMinor == IRP_MN_SET_POWER)
            DevState->IgnoreErrors = TRUE;
    }

    ASSERT(DevState->Thread == KeGetCurrentThread());

    if (!IsWaking)
    {
        if (DevState->GetNewDeviceList)
        {
            DevState->GetNewDeviceList = FALSE;

            DPRINT("PopSetDevicesSystemState: FIXME PPerfGlobalGroupMask\n");

            IoFreePoDeviceNotifyList(&DevState->Order);
            DevState->Status = IoBuildPoDeviceNotifyList(&DevState->Order);

            DPRINT("PopSetDevicesSystemState: DevState->Status %X\n", DevState->Status);
        }
        else
        {
            DPRINT1("PopSetDevicesSystemState: DevState->GetNewDeviceList is FALSE\n");
            ASSERT(FALSE); // PoDbgBreakPointEx();
        }

        if (NT_SUCCESS(DevState->Status))
        {
            OrderLevel = &DevState->Order.OrderLevel[7];

            for (ix = 7; ix >= 0; ix--, OrderLevel--)
            {
                DPRINT("PopSetDevicesSystemState: ix %X\n", ix);

                if (OrderLevel->DeviceCount)
                {
                    if (IsEventCallout)
                    {
                        if (ix <= 4)
                        {
                            IsEventCallout = FALSE;
                            InterlockedExchange((PLONG)&PopFullWake, 0);

                            DPRINT1("PopSetDevicesSystemState: FIXME PopEventCallout()\n");
                            ASSERT(FALSE); // PoDbgBreakPointEx();
                        }
                    }

                    if (PopAction.Shutdown && !DidIoMmShutdown && PopAction.IrpMinor == IRP_MN_SET_POWER && ix < 4)
                    {
                        DPRINT1("PopSetDevicesSystemState: FIXME IoConfigureCrashDump\n");
                        //ASSERT(FALSE); // PoDbgBreakPointEx();

                        DPRINT1("PopSetDevicesSystemState: Mm shutdown phase 1\n");
                        MmShutdownSystem(1);

                        DidIoMmShutdown = 1;

                        //
                        // !- HACK -!
                        //
                        DPRINT1("PopSetDevicesSystemState: FIXFIX !- HACK -!\n");
                        break;
                        //
                        // !- HACK -!
                        //
                    }

                    DPRINT("PopSetDevicesSystemState: PopAction.Flags %X\n", PopAction.Flags);

                    if (PopAction.Flags & 0x80000000)
                    {
                        DPRINT("PopSetDevicesSystemState: DevState->Order.WarmEjectPdoPointer %X\n",
                               DevState->Order.WarmEjectPdoPointer);

                        ASSERT(DevState->Order.WarmEjectPdoPointer);

                        if (DevState->Order.WarmEjectPdoPointer)
                            *DevState->Order.WarmEjectPdoPointer = NULL;
                    }

                    PopCurrentLevel = ix;
                    PopSleepDeviceList(DevState, OrderLevel);
                    PopWaitForSystemPowerIrp(DevState, TRUE);
                }

                if (!NT_SUCCESS(DevState->Status))
                {
                    DPRINT1("PopSetDevicesSystemState: DevState->Status %X\n", DevState->Status);

                    IsWaking = TRUE;

                    DPRINT("PopSetDevicesSystemState: DevState->FailedDevice %X, PopAction.NextSystemState %X\n",
                           DevState->FailedDevice, PopAction.NextSystemState);

                    if (DevState->FailedDevice && PopAction.NextSystemState == PowerSystemWorking)
                    {
                        DPRINT1("PopSetDevicesSystemState: PopSimulate %X, PopAction.IrpMinor %X\n",
                                PopSimulate, PopAction.IrpMinor);
                        ASSERT(FALSE); // PoDbgBreakPointEx();
                    }

                    break;
                }
            }
        }

        DPRINT("PopSetDevicesSystemState: PopSimulate %X, PopAction.IrpMinor %X\n", PopSimulate, PopAction.IrpMinor);

        if ((PopSimulate & 0x00020000) && PopAction.IrpMinor == IRP_MN_SET_POWER)
        {
            DPRINT1("PopSetDevicesSystemState: POP_WAKE_DEVICE_AFTER_SLEEP enabled.\n");
            ASSERT(FALSE); // PoDbgBreakPointEx();
            IsWaking = TRUE;
            DevState->Status = STATUS_UNSUCCESSFUL;
        }
    }

    ASSERT((!PopAction.Shutdown) || (PopAction.IrpMinor != IRP_MN_SET_POWER) || DidIoMmShutdown);

    while (PopSimulate & 0x80)
    {
        DPRINT1("PopSetDevicesSystemState: PopSimulate & 0x80\n");
        ASSERT(FALSE); // PoDbgBreakPointEx();
    }

    DevState->Waking = IsWaking;

    if (IsWaking)
    {
        DPRINT1("PopSetDevicesSystemState: IsWaking\n");
        ASSERT(FALSE); // PoDbgBreakPointEx();
    }

    DPRINT("PopSetDevicesSystemState: FIXME PPerfGlobalGroupMask\n");

    return DevState->Status;
}

VOID
NTAPI
PopGracefulShutdown(
    _In_ PVOID Context)
{
    PEPROCESS Process = NULL;

    DPRINT1("PopGracefulShutdown: Context %p\n", Context);

  #if ROS_DBG_LOG_FILE
    DPRINT1("KdpStubCounter %lx, KdPrintRolloverCount %lx\n", KdpStubCounter, KdPrintRolloverCount);
    KdpWriteDebugToFile(FALSE, TRUE); // 'debug2.log' (will be overwritten)
  #endif

    /* Process the registered waits and work items */
    PopProcessShutDownLists();

    /* Loop every process */
    Process = PsGetNextProcess(Process);
    while (Process)
    {
        /* Make sure this isn't the idle or initial process */
        if ((Process != PsInitialSystemProcess) && (Process != PsIdleProcess))
        {
            DPRINT1("PopGracefulShutdown: %15s is still RUNNING (%p)\n", Process->ImageFileName, Process->UniqueProcessId);
        }

        Process = PsGetNextProcess(Process);
    }

    /* First, the HAL handles any "end of boot" special functionality */
    DPRINT("PopGracefulShutdown: HAL shutting down\n");

    if (!PopAction.ShutdownBugCode)
        HalEndOfBoot();
    else
        ASSERT(FALSE);

    /* Shut down the Shim cache if enabled */
    ApphelpCacheShutdown();

    /* In this step, the I/O manager does first-chance shutdown notification */
    DPRINT("PopGracefulShutdown: I/O manager shutting down in phase 0\n");
    IoShutdownSystem(0);

    /* In this step, all workers are killed and hives are flushed */
    DPRINT("PopGracefulShutdown: Configuration Manager shutting down\n");
    CmShutdownSystem();

    /* Shut down the Executive */
    DPRINT("PopGracefulShutdown: Executive shutting down\n");
    ExShutdownSystem();

    /* Note that modified pages should be written here (MiShutdownSystem) */
    DPRINT("PopGracefulShutdown: Mm shutdown phase 0\n");
    MmShutdownSystem(0);

    /* Flush all user files before we start shutting down IO */
    /* This is where modified pages are written back by the IO manager */
    DPRINT("PopGracefulShutdown: call CcWaitForCurrentLazyWriterActivity()\n");
    CcWaitForCurrentLazyWriterActivity();

    /* In this step, the I/O manager does last-chance shutdown notification */
    DPRINT("PopGracefulShutdown: I/O manager shutting down in phase 1\n");
    IoShutdownSystem(1);

    DPRINT("PopGracefulShutdown: call CcWaitForCurrentLazyWriterActivity()\n");
    CcWaitForCurrentLazyWriterActivity();

    PopFullWake = 0;

    ASSERT(PopAction.DevState);
    PopAction.DevState->Thread = KeGetCurrentThread();

    PopSetDevicesSystemState(FALSE);

    IoFreePoDeviceNotifyList(&PopAction.DevState->Order);

    /* In this step, the HAL disables any wake timers */
    DPRINT("PopGracefulShutdown: Disabling wake timers\n");
    HalSetWakeEnable(FALSE);

    if (PopAction.ShutdownBugCode)
    {
        ASSERT(FALSE);
        KeBugCheckEx(PopAction.ShutdownBugCode->Code,
                     PopAction.ShutdownBugCode->Parameter1,
                     PopAction.ShutdownBugCode->Parameter2,
                     PopAction.ShutdownBugCode->Parameter3,
                     PopAction.ShutdownBugCode->Parameter4);
    }

    DPRINT("PopGracefulShutdown: Mm shutdown phase 2\n");
    MmShutdownSystem(2);

    /* Note that here, we should broadcast the power IRP to devices */

    /* And finally the power request is sent */
    DPRINT("PopGracefulShutdown: Taking the system down\n");
    PopShutdownSystem(PopAction.Action);
}

VOID
NTAPI
PopReadShutdownPolicy(VOID)
{
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PVOID)Buffer;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KeyString;
    HANDLE KeyHandle;
    ULONG Length;
    NTSTATUS Status;

    /* Setup object attributes */
    RtlInitUnicodeString(&KeyString, L"\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows NT");

    InitializeObjectAttributes(&ObjectAttributes,
                               &KeyString,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    /* Open the key */
    Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PopReadShutdownPolicy: Status %X\n", Status);
        return;
    }

    /* Open the policy value and query it */
    RtlInitUnicodeString(&KeyString, L"DontPowerOffAfterShutdown");

    Status = ZwQueryValueKey(KeyHandle,
                             &KeyString,
                             KeyValuePartialInformation,
                             &Info,
                             sizeof(Info),
                             &Length);

    if ((NT_SUCCESS(Status)) && (Info->Type == REG_DWORD))
    {
        /* Read the policy */
        PopShutdownPowerOffPolicy = (*Info->Data == 1);
    }

    ZwClose(KeyHandle);
}

/* PUBLIC FUNCTIONS **********************************************************/

NTSTATUS
NTAPI
PoQueueShutdownWorkItem(
    _In_ PWORK_QUEUE_ITEM WorkItem)
{
    NTSTATUS Status;

    /* Acquire the shutdown list lock */
    KeAcquireGuardedMutex(&PopShutdownListMutex);

    /* Check if the list is (already/still) available */
    if (PopShutdownListAvailable)
    {
        /* Insert the item into the list */
        InsertTailList(&PopShutdownQueue, &WorkItem->List);
        Status = STATUS_SUCCESS;
    }
    else
    {
        /* We are already in shutdown */
        Status = STATUS_SYSTEM_SHUTDOWN;
    }

    /* Release the list lock */
    KeReleaseGuardedMutex(&PopShutdownListMutex);

    return Status;
}

NTSTATUS
NTAPI
PoRequestShutdownEvent(
    _Out_ PVOID* Event)
{
    NTSTATUS Status;
    PAGED_CODE();

    /* Initialize to NULL */
    if (Event)
        *Event = NULL;

    /* Request a shutdown wait */
    Status = PoRequestShutdownWait(PsGetCurrentThread());
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PoRequestShutdownEvent: Status %X\n", Status);
        return Status;
    }

    /* Return the global shutdown event */
    if (Event)
       *Event = &PopShutdownEvent;

    return STATUS_SUCCESS;
}

/* EOF */
