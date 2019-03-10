/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/po/power.c
 * PURPOSE:         Power Manager
 * PROGRAMMERS:     Casper S. Hornstrup (chorns@users.sourceforge.net)
 *                  Herv� Poussineau (hpoussin@reactos.com)
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

typedef struct _POWER_STATE_TRAVERSE_CONTEXT
{
    SYSTEM_POWER_STATE SystemPowerState;
    POWER_ACTION PowerAction;
    PDEVICE_OBJECT PowerDevice;
} POWER_STATE_TRAVERSE_CONTEXT, *PPOWER_STATE_TRAVERSE_CONTEXT;

typedef struct _SYSTEM_POWER_LEVEL
{
    BOOLEAN Enable;
    UCHAR Spare[3];
    ULONG BatteryLevel;
    POWER_ACTION_POLICY PowerPolicy;
    SYSTEM_POWER_STATE MinSystemState;
} SYSTEM_POWER_LEVEL, *PSYSTEM_POWER_LEVEL;

typedef struct _SYSTEM_POWER_POLICY
{
    ULONG Revision;
    POWER_ACTION_POLICY PowerButton;
    POWER_ACTION_POLICY SleepButton;
    POWER_ACTION_POLICY LidClose;
    SYSTEM_POWER_STATE LidOpenWake;
    ULONG Reserved;
    POWER_ACTION_POLICY Idle;
    ULONG IdleTimeout;
    UCHAR IdleSensitivity;
    UCHAR DynamicThrottle;
    UCHAR Spare2[2];
    SYSTEM_POWER_STATE MinSleep;
    SYSTEM_POWER_STATE MaxSleep;
    SYSTEM_POWER_STATE ReducedLatencySleep;
    ULONG WinLogonFlags;
    ULONG Spare3;
    ULONG DozeS4Timeout;
    ULONG BroadcastCapacityResolution;
    SYSTEM_POWER_LEVEL DischargePolicy[4];
    ULONG VideoTimeout;
    BOOLEAN VideoDimDisplay;
    UCHAR Pad[0x3];
    ULONG VideoReserved[3];
    ULONG SpindownTimeout;
    BOOLEAN OptimizeForPower;
    UCHAR FanThrottleTolerance;
    UCHAR ForcedThrottle;
    UCHAR MinThrottle;
    POWER_ACTION_POLICY OverThrottled;
} SYSTEM_POWER_POLICY, *PSYSTEM_POWER_POLICY;

PDEVICE_NODE PopSystemPowerDeviceNode = NULL;
BOOLEAN PopAcpiPresent = FALSE;
POP_POWER_ACTION PopAction;
WORK_QUEUE_ITEM PopShutdownWorkItem;

ERESOURCE PopPolicyLock;
PKTHREAD PopPolicyLockThread = NULL;

SYSTEM_POWER_POLICY PopAcPolicy;
SYSTEM_POWER_POLICY PopDcPolicy;
PSYSTEM_POWER_POLICY PopPolicy;

PIRP PopInrushIrpPointer;
ULONG PopInrushIrpReferenceCount;
BOOLEAN PopInrushPending;

BOOLEAN PopFailedHibernationAttempt = FALSE;
BOOLEAN IsFlushedVolumes;
BOOLEAN Pad0;

KSPIN_LOCK PopSubmitWorkerSpinLock;
KSPIN_LOCK PopIrpSerialSpinLock;
LIST_ENTRY PopIrpSerialList;
ULONG PopIrpSerialListLength;
ULONG PopCallSystemState;

KEVENT PopUnlockComplete;

ULONG PopSimulate = 0x00010000;
SYSTEM_POWER_CAPABILITIES PopCapabilities;

//PROCESSOR_POWER_POLICY PopAcProcessorPolicy;
//PROCESSOR_POWER_POLICY PopDcProcessorPolicy;
//PPROCESSOR_POWER_POLICY PopProcessorPolicy;

KSPIN_LOCK PopWorkerLock;
KSPIN_LOCK PopWorkerSpinLock;
ULONG PopWorkerPending = 0;

ULONG PopFullWake;

HANDLE PopHiberFile = NULL;

extern ULONG IoDeviceNodeTreeSequence;

/* PRIVATE FUNCTIONS *********************************************************/


VOID
NTAPI
PopAcquirePolicyLock(
    VOID
);

VOID
NTAPI
PopReleasePolicyLock(
    _In_ BOOLEAN IsQueuePolicyWorker
);

VOID
NTAPI
PopDefaultPolicy(
    _In_ PSYSTEM_POWER_POLICY Policy
);

NTSTATUS
NTAPI
PopSubmitIrp(
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PIRP Irp
);

static
NTSTATUS
NTAPI
PopRequestPowerIrpCompletion(IN PDEVICE_OBJECT DeviceObject,
                             IN PIRP Irp,
                             IN PVOID Context)
{
    PIO_STACK_LOCATION Stack;
    PREQUEST_POWER_COMPLETE CompletionRoutine;
    POWER_STATE PowerState;

    Stack = IoGetCurrentIrpStackLocation(Irp);
    CompletionRoutine = Context;

    PowerState.DeviceState = (ULONG_PTR)Stack->Parameters.Others.Argument3;
    CompletionRoutine(Stack->Parameters.Others.Argument1,
                      (UCHAR)(ULONG_PTR)Stack->Parameters.Others.Argument2,
                      PowerState,
                      Stack->Parameters.Others.Argument4,
                      &Irp->IoStatus);

    IoSkipCurrentIrpStackLocation(Irp);
    IoFreeIrp(Irp);
    ObDereferenceObject(DeviceObject);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

VOID
NTAPI
PopCleanupPowerState(IN PPOWER_STATE PowerState)
{
    //UNIMPLEMENTED;
}

BOOLEAN
NTAPI
INIT_FUNCTION
PoInitSystem(IN ULONG BootPhase)
{
    PVOID NotificationEntry;
    PCHAR CommandLine;
    BOOLEAN ForceAcpiDisable = FALSE;
    NTSTATUS Status = STATUS_SUCCESS;

    /* Check if this is phase 1 init */
    if (BootPhase == 1)
    {
        DPRINT("PoInitSystem: FIXME PopInitializePowerPolicySimulate()\n");
        //PopInitializePowerPolicySimulate();

        if (PopSimulate & 1) {
            ASSERT(FALSE);
        }

        if (PopSimulate & 2) {
            ASSERT(FALSE);
        }

        PopAcquirePolicyLock();

        DPRINT("PoInitSystem: FIXME read [Heuristics] key\n");
        DPRINT("PoInitSystem: FIXME read [PolicyOverrides] key\n");

        DPRINT("PoInitSystem: FIXME PopResetCurrentPolicies() - read xxxPolicy keys from registry \n");
        Status = 0;//PopResetCurrentPolicies();
        PopReleasePolicyLock(FALSE);

        DPRINT("PoInitSystem: FIXME PopIdleScanTimer \n");

        /* Register power button notification */
        IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange,
                                       PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
                                       (PVOID)&GUID_DEVICE_SYS_BUTTON,
                                       IopRootDeviceNode->
                                       PhysicalDeviceObject->DriverObject,
                                       PopAddRemoveSysCapsCallback,
                                       NULL,
                                       &NotificationEntry);

        /* Register lid notification */
        IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange,
                                       PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
                                       (PVOID)&GUID_DEVICE_LID,
                                       IopRootDeviceNode->
                                       PhysicalDeviceObject->DriverObject,
                                       PopAddRemoveSysCapsCallback,
                                       NULL,
                                       &NotificationEntry);
        return NT_SUCCESS(Status);
    }

    /* Get the Command Line */
    CommandLine = KeLoaderBlock->LoadOptions;

    /* Upcase it */
    _strupr(CommandLine);

    /* Check for ACPI disable */
    if (strstr(CommandLine, "NOACPI")) ForceAcpiDisable = TRUE;

    if (ForceAcpiDisable)
    {
        /* Set the ACPI State to False if it's been forced that way */
        PopAcpiPresent = FALSE;
    }
    else
    {
        /* Otherwise check if the LoaderBlock has a ACPI Table  */
        PopAcpiPresent = KeLoaderBlock->Extension->AcpiTable != NULL ? TRUE : FALSE;
    }


    KeInitializeSpinLock(&PopIrpSerialSpinLock);//PopIrpSerialLock
    PopIrpSerialListLength = 0; //PopIrpSerialListCount 
    InitializeListHead(&PopIrpSerialList);

    PopInrushPending = FALSE;
    PopInrushIrpPointer = NULL;
    PopInrushIrpReferenceCount = 0;

    PopCallSystemState = 0;

    KeInitializeEvent(&PopUnlockComplete, SynchronizationEvent, TRUE);

    /* Initialize support for shutdown waits and work-items */
    PopInitShutdownList();

    /* Initialize support for dope */
    KeInitializeSpinLock(&PopDopeGlobalLock);

    KeInitializeSpinLock(&PopSubmitWorkerSpinLock); //PopWorkerLock
    KeInitializeSpinLock(&PopWorkerSpinLock);

    ExInitializeResourceLite(&PopPolicyLock);

    /* Initialize volume support */
    KeInitializeGuardedMutex(&PopVolumeLock);
    InitializeListHead(&PopVolumeDevices);

    PopAction.Action = PowerActionNone;

    PopDefaultPolicy(&PopAcPolicy);
    PopDefaultPolicy(&PopDcPolicy);
    PopPolicy = &PopAcPolicy;

    PopFullWake = 5;

    return TRUE;
}

VOID
NTAPI
PopPerfIdle(PPROCESSOR_POWER_STATE PowerState)
{
    DPRINT1("PerfIdle function: %p\n", PowerState);
}

VOID
NTAPI
PopPerfIdleDpc(IN PKDPC Dpc,
               IN PVOID DeferredContext,
               IN PVOID SystemArgument1,
               IN PVOID SystemArgument2)
{
    /* Call the Perf Idle function */
    PopPerfIdle(&((PKPRCB)DeferredContext)->PowerState);
}

VOID
FASTCALL
PopIdle0(IN PPROCESSOR_POWER_STATE PowerState)
{
    /* FIXME: Extremly naive implementation */
    HalProcessorIdle();
}

VOID
NTAPI
INIT_FUNCTION
PoInitializePrcb(IN PKPRCB Prcb)
{
    /* Initialize the Power State */
    RtlZeroMemory(&Prcb->PowerState, sizeof(Prcb->PowerState));
    Prcb->PowerState.Idle0KernelTimeLimit = 0xFFFFFFFF;
    Prcb->PowerState.CurrentThrottle = 100;
    Prcb->PowerState.CurrentThrottleIndex = 0;
    Prcb->PowerState.IdleFunction = PopIdle0;

    /* Initialize the Perf DPC and Timer */
    KeInitializeDpc(&Prcb->PowerState.PerfDpc, PopPerfIdleDpc, Prcb);
    KeSetTargetProcessorDpc(&Prcb->PowerState.PerfDpc, Prcb->Number);
    KeInitializeTimerEx(&Prcb->PowerState.PerfTimer, SynchronizationTimer);
}

/* PUBLIC FUNCTIONS **********************************************************/

/*
 * @unimplemented
 */
NTSTATUS
NTAPI
PoCancelDeviceNotify(IN PVOID NotifyBlock)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * @unimplemented
 */
NTSTATUS
NTAPI
PoRegisterDeviceNotify(OUT PVOID Unknown0,
                       IN ULONG Unknown1,
                       IN ULONG Unknown2,
                       IN ULONG Unknown3,
                       IN PVOID Unknown4,
                       IN PVOID Unknown5)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * @unimplemented
 */
VOID
NTAPI
PoShutdownBugCheck(IN BOOLEAN LogError,
                   IN ULONG BugCheckCode,
                   IN ULONG_PTR BugCheckParameter1,
                   IN ULONG_PTR BugCheckParameter2,
                   IN ULONG_PTR BugCheckParameter3,
                   IN ULONG_PTR BugCheckParameter4)
{
    DPRINT1("PoShutdownBugCheck called\n");

    /* FIXME: Log error if requested */
    /* FIXME: Initiate a shutdown */

    /* Bugcheck the system */
    KeBugCheckEx(BugCheckCode,
                 BugCheckParameter1,
                 BugCheckParameter2,
                 BugCheckParameter3,
                 BugCheckParameter4);
}

/*
 * @unimplemented
 */
VOID
NTAPI
PoSetHiberRange(IN PVOID HiberContext,
                IN ULONG Flags,
                IN OUT PVOID StartPage,
                IN ULONG Length,
                IN ULONG PageTag)
{
    UNIMPLEMENTED;
    return;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
PoCallDriver(IN PDEVICE_OBJECT DeviceObject,
             IN OUT PIRP Irp)
{
    PEXTENDED_DEVOBJ_EXTENSION DeviceExtension;
    POP_DEVICE_EXTENSION_POWER_FLAGS PowerFlags;
    PIO_STACK_LOCATION IoStack;
    UCHAR MinorFunction;
    KIRQL OldIrql;

    ASSERT(DeviceObject);
    ASSERT(Irp);
    ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

    KeAcquireSpinLock(&PopIrpSerialSpinLock, &OldIrql);

    IoStack = IoGetNextIrpStackLocation(Irp);
    IoStack->DeviceObject = DeviceObject;

    ASSERT(IoStack->MajorFunction == IRP_MJ_POWER);
    MinorFunction = IoStack->MinorFunction;
    DPRINT1("PoCallDriver(%p, %p). Flags - %08X, Minor - %X, Context - %X, Type - %X, State - %X, ShutdownType - %X\n", DeviceObject, Irp, DeviceObject->Flags, MinorFunction, 
            IoStack->Parameters.Power.SystemContext,
            IoStack->Parameters.Power.Type,
            IoStack->Parameters.Power.State,
            IoStack->Parameters.Power.ShutdownType);

    if (DeviceObject->Flags & 0x8000)
    {
        /* 0x8000 ? DO_POWER_NOOP ? (https://www-user.tu-chemnitz.de/~heha/oney_wdm/ch08d.htm) */
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        KeReleaseSpinLock(&PopIrpSerialSpinLock, OldIrql);
        return STATUS_SUCCESS;
    }

    if (MinorFunction != IRP_MN_SET_POWER &&
        MinorFunction != IRP_MN_QUERY_POWER)
    {
        KeReleaseSpinLock(&PopIrpSerialSpinLock, OldIrql);
        return IoCallDriver(DeviceObject, Irp);
    }

    DeviceExtension = IoGetDevObjExtension(DeviceObject);
    PowerFlags.AsULONG = DeviceExtension->PowerFlags;

    if (MinorFunction == IRP_MN_SET_POWER)
    {
        if (IoStack->Parameters.Power.Type == DevicePowerState &&
            IoStack->Parameters.Power.State.DeviceState == PowerDeviceD0 &&
            (PowerFlags.DeviceState != 1) &&
            (DeviceObject->Flags & DO_POWER_INRUSH))
        {
            if (PopInrushIrpPointer == Irp)
            {
                ASSERT((IoStack->Parameters.Power.SystemContext & POP_INRUSH_CONTEXT) == POP_INRUSH_CONTEXT);

                PopInrushIrpReferenceCount++;
                if (PopInrushIrpReferenceCount > 256)
                {
                    DPRINT1("PoCallDriver: PopInrushIrpReferenceCount > 256 !!!\n");
                    /* A device has overrun its maximum number of reference counts. */
                    ASSERT(0);KeBugCheckEx(INTERNAL_POWER_ERROR, 0x400, 1, (ULONG_PTR)IoStack, (ULONG_PTR)DeviceObject);
                }
            }
            else
            {
                if (PopInrushIrpPointer || PopInrushPending)
                {
                    PowerFlags.DeviceSerialOn = 1;
                    IoStack->Parameters.Power.SystemContext = POP_INRUSH_CONTEXT;

                    InsertTailList(&PopIrpSerialList, &Irp->Tail.Overlay.ListEntry);
                    PopIrpSerialListLength++;

                    if (PopIrpSerialListLength > 10) {
                        DPRINT1("PoCallDriver: PopIrpSerialListLength > 10!\n");
                    }

                    if (PopIrpSerialListLength > 100)
                    {
                        DPRINT1("PoCallDriver: PopIrpSerialListLength > 100 !!!\n");
                        /* Too many inrush power IRPs have been queued. */
                        ASSERT(0);KeBugCheckEx(INTERNAL_POWER_ERROR, 0x401, 2, (ULONG_PTR)&PopIrpSerialList, (ULONG_PTR)DeviceObject);
                    }

                    PopInrushPending = 1;
                    KeReleaseSpinLock(&PopIrpSerialSpinLock, OldIrql);
                    return STATUS_PENDING;
                }
                else
                {
                    PopInrushIrpPointer = Irp;
                    PopInrushIrpReferenceCount = 1;
                    IoStack->Parameters.Power.SystemContext = POP_INRUSH_CONTEXT;
                }
            }
        }
    }

    if (IoStack->Parameters.Power.Type == SystemPowerState)
    {
        if (PowerFlags.SystemActive)
        {
            PowerFlags.SystemSerialOn = 1;

            InsertTailList(&PopIrpSerialList, &Irp->Tail.Overlay.ListEntry);
            PopIrpSerialListLength++;

            if (PopIrpSerialListLength > 10) {
                DPRINT1("PoCallDriver: PopIrpSerialListLength > 10!\n");
            }

            if (PopIrpSerialListLength > 100)
            {
                DPRINT1("PoCallDriver: PopIrpSerialListLength > 100 !!!\n");
                /* Too many inrush power IRPs have been queued. */
                ASSERT(0);KeBugCheckEx(INTERNAL_POWER_ERROR, 0x402, 3, (ULONG_PTR)&PopIrpSerialList, (ULONG_PTR)DeviceObject);
            }

            KeReleaseSpinLock(&PopIrpSerialSpinLock, OldIrql);
            return STATUS_PENDING;
        }
        else
        {
            PowerFlags.SystemActive = 1;
        }
    }

    if (IoStack->Parameters.Power.Type == DevicePowerState)
    {
        if (PowerFlags.DeviceActive == 1 ||
            PowerFlags.DeviceSerialOn == 1)
        {
            PowerFlags.DeviceSerialOn = 1;

            InsertTailList(&PopIrpSerialList, &Irp->Tail.Overlay.ListEntry);
            PopIrpSerialListLength++;

            if (PopIrpSerialListLength > 10)
                DPRINT1("PoCallDriver: PopIrpSerialListLength > 10!\n");

            if (PopIrpSerialListLength > 100)
            {
                DPRINT1("PoCallDriver: PopIrpSerialListLength > 100 !!!\n");
                /* Too many inrush power IRPs have been queued. */
                ASSERT(0);KeBugCheckEx(INTERNAL_POWER_ERROR, 0x403, 4, (ULONG_PTR)&PopIrpSerialList, (ULONG_PTR)DeviceObject);
            }

            KeReleaseSpinLock(&PopIrpSerialSpinLock, OldIrql);
            return STATUS_PENDING;
        }
        else
        {
            PowerFlags.DeviceActive = 1;// DeviceExtension->PowerFlags |= 0x400;
        }
    }

    ASSERT(PowerFlags.SystemActive | PowerFlags.DeviceActive);

    KeReleaseSpinLock(&PopIrpSerialSpinLock, OldIrql);

    return PopSubmitIrp(IoStack, Irp);
}

/*
 * @unimplemented
 */
PULONG
NTAPI
PoRegisterDeviceForIdleDetection(IN PDEVICE_OBJECT DeviceObject,
                                 IN ULONG ConservationIdleTime,
                                 IN ULONG PerformanceIdleTime,
                                 IN DEVICE_POWER_STATE State)
{
    UNIMPLEMENTED;
    return NULL;
}

/*
 * @unimplemented
 */
PVOID
NTAPI
PoRegisterSystemState(IN PVOID StateHandle,
                      IN EXECUTION_STATE Flags)
{
    UNIMPLEMENTED;
    return NULL;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
PoRequestPowerIrp(IN PDEVICE_OBJECT DeviceObject,
                  IN UCHAR MinorFunction,
                  IN POWER_STATE PowerState,
                  IN PREQUEST_POWER_COMPLETE CompletionFunction,
                  IN PVOID Context,
                  OUT PIRP *pIrp OPTIONAL)
{
    PDEVICE_OBJECT TopDeviceObject;
    PIO_STACK_LOCATION Stack;
    PIRP Irp;

    if (MinorFunction != IRP_MN_QUERY_POWER
        && MinorFunction != IRP_MN_SET_POWER
        && MinorFunction != IRP_MN_WAIT_WAKE)
        return STATUS_INVALID_PARAMETER_2;

    /* Always call the top of the device stack */
    TopDeviceObject = IoGetAttachedDeviceReference(DeviceObject);

    Irp = IoAllocateIrp(TopDeviceObject->StackSize + 2, FALSE);
    if (!Irp)
    {
        ObDereferenceObject(TopDeviceObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;

    IoSetNextIrpStackLocation(Irp);

    Stack = IoGetNextIrpStackLocation(Irp);
    Stack->Parameters.Others.Argument1 = DeviceObject;
    Stack->Parameters.Others.Argument2 = (PVOID)(ULONG_PTR)MinorFunction;
    Stack->Parameters.Others.Argument3 = (PVOID)(ULONG_PTR)PowerState.DeviceState;
    Stack->Parameters.Others.Argument4 = Context;
    Stack->DeviceObject = TopDeviceObject;
    IoSetNextIrpStackLocation(Irp);

    Stack = IoGetNextIrpStackLocation(Irp);
    Stack->MajorFunction = IRP_MJ_POWER;
    Stack->MinorFunction = MinorFunction;
    if (MinorFunction == IRP_MN_WAIT_WAKE)
    {
        Stack->Parameters.WaitWake.PowerState = PowerState.SystemState;
    }
    else
    {
        Stack->Parameters.Power.Type = DevicePowerState;
        Stack->Parameters.Power.State = PowerState;
    }

    if (pIrp != NULL)
        *pIrp = Irp;

    IoSetCompletionRoutine(Irp, PopRequestPowerIrpCompletion, CompletionFunction, TRUE, TRUE, TRUE);
    PoCallDriver(TopDeviceObject, Irp);

    /* Always return STATUS_PENDING. The completion routine
     * will call CompletionFunction and complete the Irp.
     */
    return STATUS_PENDING;
}

/*
 * @unimplemented
 */
POWER_STATE
NTAPI
PoSetPowerState(IN PDEVICE_OBJECT DeviceObject,
                IN POWER_STATE_TYPE Type,
                IN POWER_STATE State)
{
    POWER_STATE ps;

    ASSERT_IRQL_LESS_OR_EQUAL(DISPATCH_LEVEL);

    ps.SystemState = PowerSystemWorking;  // Fully on
    ps.DeviceState = PowerDeviceD0;       // Fully on

    return ps;
}

/*
 * @unimplemented
 */
VOID
NTAPI
PoSetSystemState(IN EXECUTION_STATE Flags)
{
    UNIMPLEMENTED;
}

/*
 * @unimplemented
 */
VOID
NTAPI
PoStartNextPowerIrp(IN PIRP Irp)
{
    UNIMPLEMENTED;
}

/*
 * @unimplemented
 */
VOID
NTAPI
PoUnregisterSystemState(IN PVOID StateHandle)
{
    UNIMPLEMENTED;
}

/*
 * @unimplemented
 */
NTSTATUS
NTAPI
NtInitiatePowerAction(IN POWER_ACTION SystemAction,
                      IN SYSTEM_POWER_STATE MinSystemState,
                      IN ULONG Flags,
                      IN BOOLEAN Asynchronous)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * @unimplemented
 */
NTSTATUS
NTAPI
NtPowerInformation(IN POWER_INFORMATION_LEVEL PowerInformationLevel,
                   IN PVOID InputBuffer  OPTIONAL,
                   IN ULONG InputBufferLength,
                   OUT PVOID OutputBuffer  OPTIONAL,
                   IN ULONG OutputBufferLength)
{
    NTSTATUS Status;
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();

    PAGED_CODE();

    DPRINT("NtPowerInformation(PowerInformationLevel 0x%x, InputBuffer 0x%p, "
           "InputBufferLength 0x%x, OutputBuffer 0x%p, OutputBufferLength 0x%x)\n",
           PowerInformationLevel,
           InputBuffer, InputBufferLength,
           OutputBuffer, OutputBufferLength);

    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            ProbeForRead(InputBuffer, InputBufferLength, 1);
            ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(ULONG));
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    switch (PowerInformationLevel)
    {
        case SystemBatteryState:
        {
            PSYSTEM_BATTERY_STATE BatteryState = (PSYSTEM_BATTERY_STATE)OutputBuffer;

            if (InputBuffer != NULL)
                return STATUS_INVALID_PARAMETER;
            if (OutputBufferLength < sizeof(SYSTEM_BATTERY_STATE))
                return STATUS_BUFFER_TOO_SMALL;

            _SEH2_TRY
            {
                /* Just zero the struct (and thus set BatteryState->BatteryPresent = FALSE) */
                RtlZeroMemory(BatteryState, sizeof(SYSTEM_BATTERY_STATE));
                BatteryState->EstimatedTime = MAXULONG;

                Status = STATUS_SUCCESS;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            break;
        }

        case SystemPowerCapabilities:
        {
            PSYSTEM_POWER_CAPABILITIES PowerCapabilities = (PSYSTEM_POWER_CAPABILITIES)OutputBuffer;

            if (InputBuffer != NULL)
                return STATUS_INVALID_PARAMETER;
            if (OutputBufferLength < sizeof(SYSTEM_POWER_CAPABILITIES))
                return STATUS_BUFFER_TOO_SMALL;

            _SEH2_TRY
            {
                /* Just zero the struct (and thus set PowerCapabilities->SystemBatteriesPresent = FALSE) */
                RtlZeroMemory(PowerCapabilities, sizeof(SYSTEM_POWER_CAPABILITIES));
                //PowerCapabilities->SystemBatteriesPresent = 0;

                Status = STATUS_SUCCESS;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            break;
        }

        case ProcessorInformation:
        {
            PPROCESSOR_POWER_INFORMATION PowerInformation = (PPROCESSOR_POWER_INFORMATION)OutputBuffer;

            if (InputBuffer != NULL)
                return STATUS_INVALID_PARAMETER;
            if (OutputBufferLength < sizeof(PROCESSOR_POWER_INFORMATION))
                return STATUS_BUFFER_TOO_SMALL;

            _SEH2_TRY
            {
                PowerInformation->Number = 0;
                PowerInformation->MaxMhz = 1000;
                PowerInformation->CurrentMhz = 1000;
                PowerInformation->MhzLimit = 1000;
                PowerInformation->MaxIdleState = 0;
                PowerInformation->CurrentIdleState = 0;

                Status = STATUS_SUCCESS;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                Status = _SEH2_GetExceptionCode();
            }
            _SEH2_END;

            break;
        }

        default:
            Status = STATUS_NOT_IMPLEMENTED;
            DPRINT1("PowerInformationLevel 0x%x is UNIMPLEMENTED! Have a nice day.\n",
                    PowerInformationLevel);
            break;
    }

    return Status;
}

NTSTATUS
NTAPI
NtGetDevicePowerState(IN HANDLE Device,
                      IN PDEVICE_POWER_STATE PowerState)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

BOOLEAN
NTAPI
NtIsSystemResumeAutomatic(VOID)
{
    UNIMPLEMENTED;
    return FALSE;
}

NTSTATUS
NTAPI
NtRequestWakeupLatency(IN LATENCY_TIME Latency)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
NtSetThreadExecutionState(IN EXECUTION_STATE esFlags,
                          OUT EXECUTION_STATE *PreviousFlags)
{
    PKTHREAD Thread = KeGetCurrentThread();
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
    EXECUTION_STATE PreviousState;
    PAGED_CODE();

    /* Validate flags */
    if (esFlags & ~(ES_CONTINUOUS | ES_USER_PRESENT))
    {
        /* Fail the request */
        return STATUS_INVALID_PARAMETER;
    }

    /* Check for user parameters */
    if (PreviousMode != KernelMode)
    {
        /* Protect the probes */
        _SEH2_TRY
        {
            /* Check if the pointer is valid */
            ProbeForWriteUlong(PreviousFlags);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* It isn't -- fail */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    /* Save the previous state, always masking in the continous flag */
    PreviousState = Thread->PowerState | ES_CONTINUOUS;

    /* Check if we need to update the power state */
    if (esFlags & ES_CONTINUOUS) Thread->PowerState = (UCHAR)esFlags;

    /* Protect the write back to user mode */
    _SEH2_TRY
    {
        /* Return the previous flags */
        *PreviousFlags = PreviousState;
    }
    _SEH2_EXCEPT(ExSystemExceptionFilter())
    {
        /* Something's wrong, fail */
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    /* All is good */
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
NtSetSystemPowerState(IN POWER_ACTION SystemAction,
                      IN SYSTEM_POWER_STATE MinSystemState,
                      IN ULONG Flags)
{
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
    POP_POWER_ACTION Action = {0};
    NTSTATUS Status;
    ULONG Dummy;

    /* Check for invalid parameter combinations */
    if ((MinSystemState >= PowerSystemMaximum) ||
        (MinSystemState <= PowerSystemUnspecified) ||
        (SystemAction > PowerActionWarmEject) ||
        (SystemAction < PowerActionReserved) ||
        (Flags & ~(POWER_ACTION_QUERY_ALLOWED  |
                   POWER_ACTION_UI_ALLOWED     |
                   POWER_ACTION_OVERRIDE_APPS  |
                   POWER_ACTION_LIGHTEST_FIRST |
                   POWER_ACTION_LOCK_CONSOLE   |
                   POWER_ACTION_DISABLE_WAKES  |
                   POWER_ACTION_CRITICAL)))
    {
        DPRINT1("NtSetSystemPowerState: Bad parameters!\n");
        DPRINT1("                       SystemAction: 0x%x\n", SystemAction);
        DPRINT1("                       MinSystemState: 0x%x\n", MinSystemState);
        DPRINT1("                       Flags: 0x%x\n", Flags);
        return STATUS_INVALID_PARAMETER;
    }

    /* Check for user caller */
    if (PreviousMode != KernelMode)
    {
        /* Check for shutdown permission */
        if (!SeSinglePrivilegeCheck(SeShutdownPrivilege, PreviousMode))
        {
            /* Not granted */
            DPRINT1("ERROR: Privilege not held for shutdown\n");
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        /* Do it as a kernel-mode caller for consistency with system state */
        return ZwSetSystemPowerState(SystemAction, MinSystemState, Flags);
    }

    /* Read policy settings (partial shutdown vs. full shutdown) */
    if (SystemAction == PowerActionShutdown) PopReadShutdownPolicy();

    /* Disable lazy flushing of registry */
    DPRINT("Stopping lazy flush\n");
    CmSetLazyFlushState(FALSE);

    /* Setup the power action */
    Action.Action = SystemAction;
    Action.Flags = Flags;

    /* Notify callbacks */
    DPRINT("Notifying callbacks\n");
    ExNotifyCallback(PowerStateCallback, (PVOID)3, NULL);

    /* Swap in any worker thread stacks */
    DPRINT("Swapping worker threads\n");
    ExSwapinWorkerThreads(FALSE);

    /* Make our action global */
    PopAction = Action;

    /* Start power loop */
    Status = STATUS_CANCELLED;
    while (TRUE)
    {
        /* Break out if there's nothing to do */
        if (Action.Action == PowerActionNone) break;

        /* Check for first-pass or restart */
        if (Status == STATUS_CANCELLED)
        {
            /* Check for shutdown action */
            if ((PopAction.Action == PowerActionShutdown) ||
                (PopAction.Action == PowerActionShutdownReset) ||
                (PopAction.Action == PowerActionShutdownOff))
            {
                /* Set the action */
                PopAction.Shutdown = TRUE;
            }

            /* Now we are good to go */
            Status = STATUS_SUCCESS;
        }

        /* Check if we're still in an invalid status */
        if (!NT_SUCCESS(Status)) break;

#ifndef NEWCC
        /* Flush dirty cache pages */
        /* XXX: Is that still mandatory? As now we'll wait on lazy writer to complete? */
        CcRosFlushDirtyPages(-1, &Dummy, FALSE, FALSE); //HACK: We really should wait here!
#else
        Dummy = 0;
#endif

        /* Flush all volumes and the registry */
        DPRINT("Flushing volumes, cache flushed %lu pages\n", Dummy);
        PopFlushVolumes(PopAction.Shutdown);

        /* Set IRP for drivers */
        PopAction.IrpMinor = IRP_MN_SET_POWER;
        if (PopAction.Shutdown)
        {
            DPRINT("Queueing shutdown thread\n");
            /* Check if we are running in the system context */
            if (PsGetCurrentProcess() != PsInitialSystemProcess)
            {
                /* We're not, so use a worker thread for shutdown */
                ExInitializeWorkItem(&PopShutdownWorkItem,
                                     &PopGracefulShutdown,
                                     NULL);

                ExQueueWorkItem(&PopShutdownWorkItem, CriticalWorkQueue);

                /* Spend us -- when we wake up, the system is good to go down */
                KeSuspendThread(KeGetCurrentThread());
                Status = STATUS_SYSTEM_SHUTDOWN;
                goto Exit;

            }
            else
            {
                /* Do the shutdown inline */
                PopGracefulShutdown(NULL);
            }
        }

        /* You should not have made it this far */
        // ASSERTMSG("System is still up and running?!\n", FALSE);
        DPRINT1("System is still up and running, you may not have chosen a yet supported power option: %u\n", PopAction.Action);
        break;
    }

Exit:
    /* We're done, return */
    return Status;
}

VOID
NTAPI
PopAcquirePolicyLock(VOID)
{
    PAGED_CODE();

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&PopPolicyLock, TRUE);

    ASSERT(PopPolicyLockThread == NULL);
    PopPolicyLockThread = KeGetCurrentThread();
}

VOID
NTAPI
PopReleasePolicyLock(
    _In_ BOOLEAN IsQueuePolicyWorker)
{
    KIRQL OldIrql;
  
    ASSERT(PopPolicyLockThread == KeGetCurrentThread());

    PopPolicyLockThread = NULL;
    ExReleaseResourceLite(&PopPolicyLock);

    if (IsQueuePolicyWorker)// && PopWorkerStatus & PopWorkerPending)
    {
        ASSERT(FALSE);
    }

    KeLeaveCriticalRegion();
}

VOID
NTAPI
PopDefaultPolicy(
    _In_ PSYSTEM_POWER_POLICY Policy)
{
    ULONG ix;

    RtlZeroMemory(Policy, sizeof(*Policy));

    Policy->Revision = 1;
    Policy->LidOpenWake = PowerSystemWorking;
    Policy->PowerButton.Action = PowerActionShutdownOff;
    Policy->SleepButton.Action = PowerActionSleep;
    Policy->LidClose.Action = PowerActionNone;
    Policy->MinSleep = PowerSystemSleeping1;
    Policy->MaxSleep = PowerActionShutdown;
    Policy->ReducedLatencySleep = PowerSystemSleeping1;
    Policy->WinLogonFlags = 0;
    Policy->FanThrottleTolerance = 100;
    Policy->ForcedThrottle = 100;
    Policy->OverThrottled.Action = PowerActionNone;
    Policy->BroadcastCapacityResolution = 25;

    for (ix = 0; ix < NUM_DISCHARGE_POLICIES; ix++) {
        Policy->DischargePolicy[ix].MinSystemState = PowerSystemSleeping1;
    }
}

NTSTATUS
NTAPI
PopSubmitIrp(
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PIRP Irp)
{
    PDEVICE_OBJECT DeviceObject;
    PWORK_QUEUE_ITEM PopCallWorkItem;
    NTSTATUS Status;
    BOOLEAN IsLowLevelDispatch = TRUE;
    KIRQL OldIrql;

    DPRINT("PopSubmitIrp: IoStack - %p, Irp - %p\n", IoStack, Irp);

    DeviceObject = IoStack->DeviceObject;
    ASSERT(IoStack->MajorFunction == IRP_MJ_POWER);

    if (IoStack->MinorFunction == IRP_MN_SET_POWER)
    {
        if (!(DeviceObject->Flags & DO_POWER_PAGABLE) ||
            (DeviceObject->Flags & DO_POWER_INRUSH))
        {
            if ((PopCallSystemState & 2) ||
                (IoStack->Parameters.Power.Type == DevicePowerState && IoStack->Parameters.Power.State.DeviceState == PowerDeviceD0) ||
                (IoStack->Parameters.Power.Type == SystemPowerState && IoStack->Parameters.Power.State.SystemState == PowerSystemWorking))
            {
                IsLowLevelDispatch = FALSE;
            }
        }
    }

    if (!IsLowLevelDispatch)
    {
        KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
        Status = IoCallDriver(IoStack->DeviceObject, Irp);
        KeLowerIrql(OldIrql);
        return Status;
    }

    if ((IoStack->Parameters.Power.SystemContext & POP_INRUSH_CONTEXT) == POP_INRUSH_CONTEXT)
    {
        DPRINT("PopSubmitIrp: inrush irp to passive level dispatch !!!\n");
        ASSERT(FALSE);KeBugCheckEx(INTERNAL_POWER_ERROR, 0x404, 5, (ULONG_PTR)IoStack, (ULONG_PTR)DeviceObject);
    }

    if (KeGetCurrentIrql() == PASSIVE_LEVEL)
    {
        Status = IoCallDriver(IoStack->DeviceObject, Irp);
        return Status;
    }

    IoStack->Control |= SL_PENDING_RETURNED;
    Status = STATUS_PENDING;

    KeAcquireSpinLock(&PopWorkerLock, &OldIrql);

    if (PopCallSystemState & 1)
    {
        ASSERT(FALSE);
        KeSetEvent(&PopAction.DevState->Event, IO_NO_INCREMENT, FALSE);
    }
    else
    {
        PopCallWorkItem = (PWORK_QUEUE_ITEM)Irp->Tail.Overlay.DriverContext;
        ExInitializeWorkItem(PopCallWorkItem, PopCallPassiveLevel, Irp);
        ExQueueWorkItem(PopCallWorkItem, DelayedWorkQueue);
    }

    KeReleaseSpinLock(&PopWorkerLock, OldIrql);

    return Status;
}

