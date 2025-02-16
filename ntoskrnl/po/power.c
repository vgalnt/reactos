/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/po/power.c
 * PURPOSE:         Power Manager
 * PROGRAMMERS:     Casper S. Hornstrup (chorns@users.sourceforge.net)
 *                  Hervé Poussineau (hpoussin@reactos.com)
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

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
BOOLEAN PopFailedHibernationAttempt = FALSE;
BOOLEAN PopAcpiPresent = FALSE;
BOOLEAN IsFlushedVolumes;
BOOLEAN PopInrushPending;
PIRP PopInrushIrpPointer;
ULONG PopInrushIrpReferenceCount;
POP_POWER_ACTION PopAction;
WORK_QUEUE_ITEM PopShutdownWorkItem;
SYSTEM_POWER_CAPABILITIES PopCapabilities;
ERESOURCE PopPolicyLock;
PKTHREAD PopPolicyLockThread = NULL;
SYSTEM_POWER_POLICY PopAcPolicy;
SYSTEM_POWER_POLICY PopDcPolicy;
PSYSTEM_POWER_POLICY PopPolicy;
POWER_STATE_HANDLER PopPowerStateHandlers[7];
KEVENT PopUnlockComplete;
HANDLE PopHiberFile = NULL;
KSPIN_LOCK PopSubmitWorkerSpinLock;
KSPIN_LOCK PopIrpSerialSpinLock;
KSPIN_LOCK PopWorkerSpinLock;
KSPIN_LOCK PopWorkerLock;
LIST_ENTRY PopIrpSerialList;
ULONG PopIrpSerialListLength;
ULONG PopSimulate = 0x00010000;
ULONG PopWorkerPending = 0;
ULONG PopCallSystemState;
ULONG PopFullWake;

extern KSPIN_LOCK IopPnPSpinLock;
extern LIST_ENTRY IopPnpEnumerationRequestList;
extern KEVENT PiEnumerationLock;
extern BOOLEAN PipEnumerationInProgress;

#ifdef MM_NEW
  extern PFN_NUMBER MmHighestPhysicalPage;
#endif

/* PRIVATE FUNCTIONS *********************************************************/

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
    ASSERT(PopPolicyLockThread == KeGetCurrentThread());

    PopPolicyLockThread = NULL;
    ExReleaseResourceLite(&PopPolicyLock);

    if (IsQueuePolicyWorker)
    {
        DPRINT("PopReleasePolicyLock: FIXME! IsQueuePolicyWorker is TRUE.\n");
        ASSERT(FALSE); // PoDbgBreakPointEx();
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

    for (ix = 0; ix < NUM_DISCHARGE_POLICIES; ix++)
        Policy->DischargePolicy[ix].MinSystemState = PowerSystemSleeping1;
}

static
NTSTATUS
NTAPI
PopCompleteRequestIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PREQUEST_POWER_COMPLETE CompletionRoutine = Context;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    POWER_STATE PowerState;

    if (CompletionRoutine)
    {
        PowerState.DeviceState = (ULONG_PTR)Stack->Parameters.Others.Argument3;

        CompletionRoutine(Stack->Parameters.Others.Argument1,
                          (UCHAR)(ULONG_PTR)Stack->Parameters.Others.Argument2,
                          PowerState,
                          Stack->Parameters.Others.Argument4,
                          &Irp->IoStatus);
    }

    IoSkipCurrentIrpStackLocation(Irp);
    Irp->CurrentLocation = (Irp->StackCount + 2);

    ObDereferenceObject(DeviceObject);
    IoFreeIrp(Irp);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

VOID
NTAPI
PopCleanupPowerState(
    _In_ PPOWER_STATE PowerState)
{
    //UNIMPLEMENTED;
}

//INIT_FUNCTION
BOOLEAN
NTAPI
PoInitSystem(
    _In_ ULONG BootPhase)
{
    PVOID NotificationEntry;
    NTSTATUS Status = STATUS_SUCCESS;

    /* Check if this is phase 1 init */
    if (BootPhase == 1)
    {
        DPRINT("PoInitSystem: FIXME PopInitializePowerPolicySimulate()\n");

        if (PopSimulate & 1)
        {
            PopCapabilities.SystemBatteriesPresent = TRUE;
            PopCapabilities.BatteryScale[0].Granularity = 100;
            PopCapabilities.BatteryScale[0].Capacity = 400;
            PopCapabilities.BatteryScale[1].Granularity = 10;
            PopCapabilities.BatteryScale[1].Capacity = 0xFFFF;
            PopCapabilities.RtcWake = 4;
            PopCapabilities.DefaultLowLatencyWake = 2;
        }

        if (PopSimulate & 2)
        {
            ASSERT(FALSE); // PoDbgBreakPointEx();

            PopCapabilities.PowerButtonPresent = TRUE;
            PopCapabilities.SleepButtonPresent = TRUE;
            PopCapabilities.LidPresent = TRUE;
            PopCapabilities.SystemS1 = TRUE;
            PopCapabilities.SystemS2 = TRUE;
            PopCapabilities.SystemS3 = TRUE;
            PopCapabilities.SystemS4 = TRUE;
        }

        PopAcquirePolicyLock();

        DPRINT("PoInitSystem: FIXME read [Heuristics] key\n");
        DPRINT("PoInitSystem: FIXME read [PolicyOverrides] key\n");

        DPRINT("PoInitSystem: FIXME PopResetCurrentPolicies() - read xxxPolicy keys from registry \n");
        Status = 0;//PopResetCurrentPolicies();
        PopReleasePolicyLock(0);

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

    KeInitializeSpinLock(&PopIrpSerialSpinLock);
    PopIrpSerialListLength = 0;
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

    KeInitializeSpinLock(&PopSubmitWorkerSpinLock);
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
PopPerfIdle(
    _In_ PPROCESSOR_POWER_STATE PowerState)
{
    DPRINT1("PerfIdle function: %p\n", PowerState);
}

VOID
NTAPI
PopPerfIdleDpc(
    _In_ PKDPC Dpc,
    _In_ PVOID DeferredContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2)
{
    /* Call the Perf Idle function */
    PopPerfIdle(&((PKPRCB)DeferredContext)->PowerState);
}

VOID
FASTCALL
PopIdle0(
    _In_ PPROCESSOR_POWER_STATE PowerState)
{
    /* FIXME: Extremly naive implementation */
    HalProcessorIdle();
}

//INIT_FUNCTION
VOID
NTAPI
PoInitializePrcb(
    _In_ PKPRCB Prcb)
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

VOID
NTAPI
PopResetActionDefaults(
    VOID)
{
    DPRINT("PopResetActionDefaults()\n");

    PopAction.Updates = 0;
    PopAction.Shutdown = FALSE;
    PopAction.Action = PowerActionNone;
    PopAction.LightestState = PowerSystemUnspecified;
    PopAction.Status = STATUS_SUCCESS;
    PopAction.IrpMinor = 0;
    PopAction.SystemState = PowerSystemUnspecified;
    PopAction.Flags = 0x10000003;
}

PCHAR
NTAPI
PopSystemStateString(
    _In_ SYSTEM_POWER_STATE SystemState)
{
    PCHAR String;

    if (SystemState == PowerSystemUnspecified)
    {
        String = "Unspecified";
        return String;
    }

    switch (SystemState)
    {
        case PowerSystemWorking:
            String = "Working";
            break;

        case PowerSystemSleeping1:
            String = "Sleeping1";
            break;

        case PowerSystemSleeping2:
            String = "Sleeping2";
            break;

        case PowerSystemSleeping3:
            String = "Sleeping3";
            break;

        case PowerSystemHibernate:
            String = "Hibernate";
            break;

        case PowerSystemShutdown:
            String = "Shutdown";
            break;

        default:
            String = "?";
            break;
    }

    return String;
}

PCHAR
NTAPI
PopPowerActionString(
    _In_ POWER_ACTION Action)
{
    PCHAR String;

    if (Action == PowerActionNone)
    {
        String = "None";
        return String;
    }

    switch (Action)
    {
        case PowerActionSleep:
            String = "Sleep";
            break;

        case PowerActionHibernate:
            String = "Hibernate";
            break;

        case PowerActionShutdown:
            String = "Shutdown";
            break;

        case PowerActionShutdownReset:
            String = "ShutdownReset";
            break;

        case PowerActionShutdownOff:
            String = "ShutdownOff";
            break;

        case PowerActionWarmEject:
            String = "WarmEject";
            break;

        default:
            String = "?";
            break;
    }

    return String;
}

VOID
NTAPI
PopAssertPolicyLockOwned(VOID)
{
    PAGED_CODE();
    ASSERT(PopPolicyLockThread == KeGetCurrentThread());
}

VOID
NTAPI
PopCompleteAction(
    _In_ PPOP_ACTION_TRIGGER ActionTrigger,
    _In_ NTSTATUS Status)
{
    DPRINT("PopCompleteAction: ActionTrigger %X, Status %X\n", ActionTrigger, Status);
  
    if (ActionTrigger->Flags & 0x20)
    {
        PPOP_TRIGGER_WAIT Wait;

        ActionTrigger->Flags &= ~0x20;

        Wait = ActionTrigger->Wait;
        Wait->Status = Status;

        KeSetEvent(&Wait->Event, IO_NO_INCREMENT, FALSE);
    }
}

VOID
NTAPI
PopVerifySystemPowerState(
    _In_ PSYSTEM_POWER_STATE pPowerState,
    _In_ ULONG SubstitutionPolicy)
{
    SYSTEM_POWER_STATE PowerState;
    BOOLEAN IsHibernate;

    PAGED_CODE();

    if (!pPowerState)
    {
        ASSERT(pPowerState);
        return;
    }

    PowerState = *pPowerState;

    DPRINT("PopVerifySystemPowerState: PowerState %X, SubstitutionPolicy %X\n", PowerState, SubstitutionPolicy);

    if (!PowerState || PowerState >= PowerSystemShutdown)
    {
        DPRINT1("PopVerifySystemPowerState: Invalid PowerState\n");
        ASSERT(FALSE); // PoDbgBreakPointEx();
        return;
    }

    if (PowerState == PowerSystemWorking)
        return;

    IsHibernate = 1;

    if (SubstitutionPolicy == 0 || SubstitutionPolicy == 1)
    {
        if (PowerState == PowerSystemHibernate)
        {
            if (PopCapabilities.SystemS4 && PopCapabilities.HiberFilePresent)
                goto Exit;

            PowerState = PowerSystemSleeping3;
        }

        if (PowerState == PowerSystemSleeping3)
        {
            if (PopCapabilities.SystemS3)
                goto Exit;

            PowerState = PowerSystemSleeping2;
        }

        if (PowerState == PowerSystemSleeping2)
        {
            if (PopCapabilities.SystemS2)
                goto Exit;

            PowerState = PowerSystemSleeping1;
        }

        if (PowerState == PowerSystemSleeping1)
        {
            if (PopCapabilities.SystemS1)
                goto Exit;

            PowerState = PowerSystemWorking;
        }

        if (PowerState != PowerSystemWorking || SubstitutionPolicy != 1)
            goto Exit;

        PowerState = PowerSystemSleeping1;

        IsHibernate = 0;
    }
    else if (SubstitutionPolicy != 2)
    {
        DPRINT1("PopVerifySystemPowerState: Invalid substitution policy\n");
        ASSERT(FALSE); // PoDbgBreakPointEx();
        goto Exit;
    }

    /* SubstitutionPolicy == 2 */

    if (PowerState == PowerSystemSleeping1)
    {
        if (PopCapabilities.SystemS1)
            goto Exit;

        PowerState = PowerSystemSleeping2;
    }

    if (PowerState == PowerSystemSleeping2)
    {
        if (PopCapabilities.SystemS2)
            goto Exit;

        PowerState = PowerSystemSleeping3;
    }

    if (PowerState == PowerSystemSleeping3)
    {
        if (PopCapabilities.SystemS3)
            goto Exit;

        PowerState = PowerSystemHibernate;

        if ((!IsHibernate || !PopCapabilities.SystemS4 || !PopCapabilities.HiberFilePresent))
            PowerState = PowerSystemWorking;

        goto Exit;
    }

    if (PowerState == PowerSystemHibernate)
    {
        if (!IsHibernate || !PopCapabilities.SystemS4 || !PopCapabilities.HiberFilePresent)
            PowerState = PowerSystemWorking;
    }

Exit:

    *pPowerState = PowerState;
    return;
}

VOID
NTAPI
PopFilterCapabilities(
    _In_ PSYSTEM_POWER_CAPABILITIES Capabilities,
    _Out_ PSYSTEM_POWER_CAPABILITIES OutCapabilities)
{
    DPRINT("PopFilterCapabilities: Capabilities %p, OutCapabilities %p\n", Capabilities, OutCapabilities);
    PAGED_CODE();

    RtlCopyMemory(OutCapabilities, Capabilities, sizeof(*OutCapabilities));

    DPRINT("PopFilterCapabilities: FIXME IoGetLegacyVetoList()\n");

    if (MmHighestPhysicalPage >= 0x00100000)
    {
        DPRINT1("PopFilterCapabilities: FIXME\n");
    }

    DPRINT("PopFilterCapabilities: FIXME PopFindLoadedModule(VGAPNP.SYS)\n");

    if (PopFailedHibernationAttempt)
    {
        OutCapabilities->SystemS4 = FALSE;
        DPRINT("PopFilterCapabilities: FIXME PopInsertLoggingEntry()\n");
    }
}

BOOLEAN
NTAPI
PopVerifyPowerActionPolicy(
    _In_ PPOWER_ACTION_POLICY ActionPolicy)
{
    SYSTEM_POWER_CAPABILITIES Capabilities;
    POWER_ACTION OldAction;
    ULONG Level;
    BOOLEAN IsNotHibernate;
    BOOLEAN Result = FALSE;

    DPRINT("PopVerifyPowerActionPolicy: ActionPolicy %X\n", ActionPolicy);
    PAGED_CODE();

    if (!ActionPolicy)
        return FALSE;

    if (ActionPolicy->Flags & ~(POWER_ACTION_QUERY_ALLOWED  |
                                POWER_ACTION_UI_ALLOWED     |
                                POWER_ACTION_OVERRIDE_APPS  |
                                POWER_ACTION_LIGHTEST_FIRST |
                                POWER_ACTION_LOCK_CONSOLE   |
                                POWER_ACTION_DISABLE_WAKES  |
                                POWER_ACTION_CRITICAL))
    {
        DPRINT1("PopVerifyPowerActionPolicy: Bad incoming Action\n");
        ASSERT(FALSE); // PoDbgBreakPointEx();
        return FALSE;
    }

    if (ActionPolicy->Flags & POWER_ACTION_CRITICAL)
    {
        ActionPolicy->Flags &= ~(POWER_ACTION_QUERY_ALLOWED | POWER_ACTION_UI_ALLOWED);
        ActionPolicy->Flags |= POWER_ACTION_OVERRIDE_APPS;
    }

    if (ActionPolicy->Action == PowerActionSleep ||
        ActionPolicy->Action == PowerActionHibernate)
    {
        DPRINT("PopVerifyPowerActionPolicy: FIXME IoGetLegacyVetoList()\n");
        ASSERT(FALSE); // PoDbgBreakPointEx();
    }

    PopFilterCapabilities(&PopCapabilities, &Capabilities);

    Level = 0;
    IsNotHibernate = FALSE;

    if (Capabilities.SystemS1)
        Level = 1;

    if (Capabilities.SystemS2)
        Level++;

    if (Capabilities.SystemS3)
        Level++;

    if (Capabilities.SystemS4 && Capabilities.HiberFilePresent)
        IsNotHibernate = TRUE;

    do
    {
        OldAction = ActionPolicy->Action;

        switch (ActionPolicy->Action)
        {
            case PowerActionReserved:
            {
                ActionPolicy->Action = PowerActionSleep;

                if (Level < 1)
                {
                    Result = 1;
                    ActionPolicy->Action = 0;
                }

                break;
            }
            case PowerActionSleep:
            {
                if (Level < 1)
                {
                    Result = 1;
                    ActionPolicy->Action = 0;
                }

                break;
            }
            case PowerActionHibernate:
            {
                if (IsNotHibernate)
                    break;

                ActionPolicy->Action = PowerActionSleep;

                if (Level < 1)
                {
                    Result = 1;
                    ActionPolicy->Action = 0;
                }

                break;
            }
            case PowerActionShutdownOff:
            {
                if (!Capabilities.SystemS5)
                    ActionPolicy->Action = PowerActionShutdown;

                break;
            }
            case PowerActionNone:
            case PowerActionShutdown:
            case PowerActionShutdownReset:
            case PowerActionWarmEject:
                break;

            default:
                ASSERT(FALSE); // PoDbgBreakPointEx();
                break;
        }
    }
    while (OldAction != ActionPolicy->Action);

    return Result;
}

LONG
NTAPI
PopCompareActions(
    _In_ POWER_ACTION Action1,
    _In_ POWER_ACTION Action2)
{
    if (Action1 == PowerActionWarmEject)
    {
        Action1 = PowerActionSleep;
    }
    else if (Action1 >= PowerActionSleep)
    {
        Action1++;
    }

    if (Action2 == PowerActionWarmEject)
    {
        Action2 = PowerActionSleep;
    }
    else if (Action2 >= PowerActionSleep)
    {
        Action2++;
    }

    return (Action1 - Action2);
}

VOID
NTAPI
PopPromoteActionFlag(
    _Out_ UCHAR* OutUpdates,
    _In_ UCHAR Updates,
    _In_ ULONG PolicyFlags,
    _In_ BOOLEAN Type,
    _In_ ULONG Flags)
{
    ULONG Mask;

    Mask = (!Type ? Flags : 0);
    PolicyFlags &= (Mask ^ Flags);

    if (~(PopAction.Flags & (Flags ^ Mask)) & PolicyFlags)
    {
        PopAction.Flags = ((PopAction.Flags | PolicyFlags) & ~Mask);
        *OutUpdates |= Updates;
    }
}

VOID
NTAPI
PopGetPolicyWorker(
    _In_ ULONG WorkerPending)
{
    KIRQL OldIrql;
  
    KeAcquireSpinLock(&PopWorkerSpinLock, &OldIrql);
    PopWorkerPending |= WorkerPending;
    KeReleaseSpinLock(&PopWorkerSpinLock, OldIrql);
}

VOID
NTAPI 
PopSetPowerAction(
    _In_ PPOP_ACTION_TRIGGER ActionTrigger,
    _In_ ULONG Param2,
    _In_ PPOWER_ACTION_POLICY ActionPolicy,
    _In_ SYSTEM_POWER_STATE LightestState,
    _In_ ULONG SubstitutionPolicy)
{
    ULONG PolicyFlags;
    BOOLEAN IsPromote = FALSE;
    UCHAR Updates;

    DPRINT("PopSetPowerAction: %X, %X, %X, %X, %X\n", ActionTrigger, Param2, ActionPolicy, LightestState, SubstitutionPolicy);

    PopAssertPolicyLockOwned();

    DPRINT("PopSetPowerAction: FIXME PPerfGlobalGroupMask\n");

    if (!(ActionTrigger->Flags & 0x80))
    {
        DPRINT("PopSetPowerAction: return\n");
        PopCompleteAction(ActionTrigger, 0);
        return;
    }

  #if DBG
    {
        PCHAR MinStateString;
        PCHAR ActionString;

        MinStateString = PopSystemStateString(LightestState);
        ActionString = PopPowerActionString(ActionPolicy->Action);

        DPRINT("PopSetPowerAction: Action '%s', Flags %X, Min '%s'\n", ActionString, ActionPolicy->Flags, MinStateString);
    }
  #endif

    PopVerifySystemPowerState(&LightestState, SubstitutionPolicy);

    if (PopVerifyPowerActionPolicy(ActionPolicy))
    {
        PopCompleteAction(ActionTrigger, STATUS_NOT_SUPPORTED);
        return;
    }

    if (!(ActionTrigger->Flags & 2))
    {
        ActionTrigger->Flags |= 2;
        PolicyFlags = ActionPolicy->Flags;

        if (PopAction.State == 0)
            PopResetActionDefaults();

        if (ActionPolicy->Action)
        {
            Updates = 0;

            if (ActionPolicy->Action == PowerActionWarmEject)
            {
                ASSERT(LightestState <= PowerSystemHibernate);
                PolicyFlags |= 0x10000000;
            }

            if (ActionPolicy->Action == PowerActionHibernate)
            {
                ASSERT(LightestState <= PowerSystemHibernate);
                LightestState = PowerSystemHibernate;
            }

            if (PopCompareActions(ActionPolicy->Action, PopAction.Action) >= 0)
            {
                PopPromoteActionFlag(&Updates, 1, PolicyFlags, FALSE, 0x00000001);
                PopPromoteActionFlag(&Updates, 1, PolicyFlags, FALSE, 0x00000002);
                PopPromoteActionFlag(&Updates, 4, PolicyFlags, FALSE, 0x10000000);

                if (ActionPolicy->Action == PowerActionSleep &&
                    LightestState < PopPolicy->MinSleep)
                {
                    LightestState = PopPolicy->MinSleep;
                }

                if (PopAction.LightestState < LightestState)
                {
                    Updates |= 4;
                    PopAction.LightestState = LightestState;
                }
            }

            PopPromoteActionFlag(&Updates, 1, PolicyFlags, TRUE, 0x00000004);
            PopPromoteActionFlag(&Updates, 5, PolicyFlags, TRUE, 0x80000000);
            PopPromoteActionFlag(&Updates, 0, PolicyFlags, TRUE, 0x40000000);

            if (PopCompareActions(ActionPolicy->Action, PopAction.Action) > 0)
            {
                ASSERT(PopCompareActions(PopAction.Action, PowerActionShutdownOff) < 0);

                if (PopCompareActions(ActionPolicy->Action, PowerActionHibernate) >= 0)
                {
                    Updates |= 2;
                }

                Updates |= 5;
                PopAction.Action = ActionPolicy->Action;
            }

            if (PopAction.Action == PowerActionHibernate)
                PopAction.Action = PowerActionSleep;

            if (Updates)
            {
                IsPromote = TRUE;

                if (PopAction.State == 0 || PopAction.State == 1)
                {
                    PopAction.Status = 0;
                    PopAction.State = 1;
                    PopGetPolicyWorker(4);
                }
                else
                {
                    PopAction.Updates |= Updates;
                    PopGetPolicyWorker(2);
                }
            }
        }
    }

    if (!(ActionTrigger->Flags & 1))
    {
        ActionTrigger->Flags |= 1;

        if (ActionPolicy->EventCode)
        {
            DPRINT1("PopSetPowerAction: ActionPolicy->EventCode %X\n", ActionPolicy->EventCode);
            ASSERT(FALSE); // PoDbgBreakPointEx();
        }

        DPRINT("PopSetPowerAction: FIXME PopSetNotificationWork()\n");
    }

    if (!(ActionTrigger->Flags & 0x20))
        return;

    if (IsPromote)
    {
        DPRINT1("PopSetPowerAction: FIXME\n");
        ASSERT(FALSE); // PoDbgBreakPointEx();
        return;
    }

    PopCompleteAction(ActionTrigger, 0);
    return;
}

VOID
NTAPI
PopAllocateDevState(
    VOID)
{
    PPOP_DEVICE_SYS_STATE DevState;
    ULONG ix;

    PAGED_CODE();
    ASSERT(PopAction.DevState == NULL);

    DevState = ExAllocatePoolWithTag(NonPagedPool, sizeof(*DevState), 'ssDP');
    if (!DevState)
    {
        DPRINT1("PopAllocateDevState: Allocate failed\n");
        ASSERT(FALSE); // PoDbgBreakPointEx();
        PopAction.DevState = NULL;
        return;
    }
    RtlZeroMemory(DevState, sizeof(*DevState));

    DevState->Thread = KeGetCurrentThread();
    DevState->GetNewDeviceList = TRUE;

    KeInitializeSpinLock(&DevState->SpinLock);
    KeInitializeEvent(&DevState->Event, SynchronizationEvent, FALSE);

    DevState->Head.Free.Next = NULL;

    InitializeListHead(&DevState->Head.Pending);
    InitializeListHead(&DevState->Head.Complete);
    InitializeListHead(&DevState->Head.Abort);
    InitializeListHead(&DevState->Head.Failed);
    InitializeListHead(&DevState->PresentIrpQueue);

    for (ix = 0; ix < 0x14; ix++)
    {
        DevState->PowerIrpState[ix].Irp = NULL;
        DevState->PowerIrpState[ix].Free.Next = DevState->Head.Free.Next;
        DevState->Head.Free.Next = &DevState->PowerIrpState[ix].Free;
    }

    for (ix = 0; ix < 8; ix++)
    {
        KeInitializeEvent(&DevState->Order.OrderLevel[ix].LevelReady, NotificationEvent, FALSE);

        InitializeListHead(&DevState->Order.OrderLevel[ix].WaitSleep);
        InitializeListHead(&DevState->Order.OrderLevel[ix].ReadySleep);
        InitializeListHead(&DevState->Order.OrderLevel[ix].Pending);
        InitializeListHead(&DevState->Order.OrderLevel[ix].Complete);
        InitializeListHead(&DevState->Order.OrderLevel[ix].ReadyS0);
        InitializeListHead(&DevState->Order.OrderLevel[ix].WaitS0);
    }

    PopAction.DevState = DevState;
}

VOID
NTAPI
PopActionRetrieveInitialState(
    _Out_ PSYSTEM_POWER_STATE OutMinState,
    _Out_ PSYSTEM_POWER_STATE OutMaxState,
    _Out_ PSYSTEM_POWER_STATE OutSystemState,
    _Out_ PBOOLEAN OutResult)
{
    DPRINT("PopActionRetrieveInitialState: *OutMinState %X, *OutMaxState %X, *OutSystemState %X, *OutResult %X\n",
           *OutMinState, *OutMaxState, *OutSystemState, *OutResult);

    if (PopAction.Action == PowerActionShutdown ||
        PopAction.Action == PowerActionShutdownReset ||
        PopAction.Action == PowerActionShutdownOff)
    {
        *OutMinState = PowerActionShutdownOff;
        *OutMaxState = PowerActionShutdownOff;
    }
    else if (PopAction.Action == PowerActionWarmEject)
    {
        *OutMaxState = PowerActionShutdownReset;
        PopVerifySystemPowerState(OutMaxState, 0);
    }
    else
    {
        DPRINT1("PopActionRetrieveInitialState: PopAction.Action %X\n", PopAction.Action);
        ASSERT(FALSE); // PoDbgBreakPointEx();
    }
  
    if (*OutMaxState < *OutMinState)
        *OutMaxState = *OutMinState;
  
    if ((PopAction.Flags & 0x80000000) && (*OutMinState == *OutMaxState))
        *OutResult = FALSE;
    else
        *OutResult = TRUE;
  
    if (PopAction.Flags & 0x10000000)
        *OutSystemState = *OutMinState;
    else
        *OutSystemState = *OutMaxState;
}

VOID
NTAPI
PopAdvanceSystemPowerState(
    _Inout_ PSYSTEM_POWER_STATE OutSystemState,
    _In_ ULONG Param2,
    _In_ SYSTEM_POWER_STATE MinState,
    _In_ ULONG MaxState)
{
    SYSTEM_POWER_STATE SystemState;
    ULONG SubstitutionPolicy;
  
    DPRINT("PopAdvanceSystemPowerState: *OutSystemState %X, Param2 %X, MinState %X, MaxState %X\n", *OutSystemState, Param2, MinState, MaxState);
    PAGED_CODE();

    if (!OutSystemState)
    {
        ASSERT(OutSystemState);
        return;
    }

    if (*OutSystemState < PowerSystemSleeping1)
    {
        DPRINT1("PopAdvanceSystemPowerState: *OutSystemState %X\n", *OutSystemState);
        ASSERT(FALSE); // PoDbgBreakPointEx();
        return;
    }

    if (*OutSystemState >= PowerSystemShutdown)
    {
        *OutSystemState = PowerSystemWorking;
        return;
    }

    SystemState = *OutSystemState;

    if (Param2)
    {
        if (Param2 == 1)
        {
            *OutSystemState = (SystemState - 1);
            PopVerifySystemPowerState(OutSystemState, 1);

            if (*OutSystemState == SystemState)
                *OutSystemState = PowerSystemWorking;

            goto Exit;
        }

        if (Param2 != 2)
        {
            DPRINT1("PopAdvanceSystemPowerState: Param2 %X\n", Param2);
            ASSERT(FALSE); // PoDbgBreakPointEx();
            goto Exit;
        }

        /* Param2 == 2 */

        if (SystemState == PowerSystemHibernate)
        {
            *OutSystemState = PowerSystemWorking;
            return;
        }

        *OutSystemState = (SystemState + 1);
        SubstitutionPolicy = 2;
    }
    else
    {
        *OutSystemState = (SystemState - 1);
        SubstitutionPolicy = 0;
    }

    PopVerifySystemPowerState(OutSystemState, SubstitutionPolicy);

Exit:

    if (*OutSystemState != PowerSystemWorking)
    {
        if (*OutSystemState < MinState || *OutSystemState > MaxState)
        {
            *OutSystemState = PowerSystemWorking;
        }
    }
}

VOID
NTAPI
PopCallPassiveLevel(
    _In_ PVOID Context)
{
    PIRP Irp;
    PIO_STACK_LOCATION IoStack;

    DPRINT1("PopCallPassiveLevel: Irp %p\n", Context);

    Irp = Context;
    IoStack = IoGetNextIrpStackLocation(Irp);
    IoCallDriver(IoStack->DeviceObject, Irp);
}

VOID
NTAPI
PopSystemIrpDispatchWorker(
    _In_ BOOLEAN IsResetState)
{
    PLIST_ENTRY Entry;
    PIRP Irp;
    KIRQL OldIrql;

    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
    DPRINT("PopSystemIrpDispatchWorker: IsResetState %X\n", IsResetState);

    KeAcquireSpinLock(&PopSubmitWorkerSpinLock, &OldIrql);

    if (PopAction.DevState)
    {
        while (!IsListEmpty(&PopAction.DevState->PresentIrpQueue))
        {
            Entry = RemoveHeadList(&PopAction.DevState->PresentIrpQueue);
            Irp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);

            KeReleaseSpinLock(&PopSubmitWorkerSpinLock, OldIrql);
            PopCallPassiveLevel(Irp);
            KeAcquireSpinLock(&PopSubmitWorkerSpinLock, &OldIrql);
        }
    }

    if (IsResetState)
        PopCallSystemState = 0;

    KeReleaseSpinLock(&PopSubmitWorkerSpinLock, OldIrql);
}

VOID
NTAPI
PopReportDevState(
    _In_ BOOLEAN IsAbort)
{
    UNIMPLEMENTED;
    //ASSERT(FALSE); // PoDbgBreakPointEx();
}

/* PUBLIC FUNCTIONS **********************************************************/

/* unimplemented */
NTSTATUS
NTAPI
PoCancelDeviceNotify(
    _In_ PVOID NotifyBlock)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

/* unimplemented */
NTSTATUS
NTAPI
PoRegisterDeviceNotify(
    _Out_ PVOID Unknown0,
    _In_ ULONG Unknown1,
    _In_ ULONG Unknown2,
    _In_ ULONG Unknown3,
    _In_ PVOID Unknown4,
    _In_ PVOID Unknown5)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

/* unimplemented */
VOID
NTAPI
PoShutdownBugCheck(
    _In_ BOOLEAN LogError,
    _In_ ULONG BugCheckCode,
    _In_ ULONG_PTR BugCheckParameter1,
    _In_ ULONG_PTR BugCheckParameter2,
    _In_ ULONG_PTR BugCheckParameter3,
    _In_ ULONG_PTR BugCheckParameter4)
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

/* unimplemented */
VOID
NTAPI
PoSetHiberRange(
    _In_ PVOID HiberContext,
    _In_ ULONG Flags,
    _Inout_ PVOID StartPage,
    _In_ ULONG Length,
    _In_ ULONG PageTag)
{
    UNIMPLEMENTED;
    return;
}

NTSTATUS
NTAPI
PopSubmitIrp(
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ PIRP Irp)
{
    PWORK_QUEUE_ITEM PopCallWorkItem;
    PDEVICE_OBJECT DeviceObject;
    BOOLEAN IsLowLevelDispatch = TRUE;
    KIRQL OldIrql;
    NTSTATUS Status;

    DPRINT("PopSubmitIrp: IoStack %p, Irp %p\n", IoStack, Irp);

    DeviceObject = IoStack->DeviceObject;
    ASSERT(IoStack->MajorFunction == IRP_MJ_POWER);

    if (IoStack->MinorFunction == IRP_MN_SET_POWER)
    {
        if (!(DeviceObject->Flags & DO_POWER_PAGABLE) ||
            (DeviceObject->Flags & DO_POWER_INRUSH))
        {
            if (PopCallSystemState & 2)
            {
                IsLowLevelDispatch = FALSE;
            }
            else
            {
                POWER_STATE State = IoStack->Parameters.Power.State;
                ULONG Type = IoStack->Parameters.Power.Type;

                if ((Type == DevicePowerState && State.DeviceState == PowerDeviceD0) ||
                    (Type == SystemPowerState && State.SystemState == PowerSystemWorking))
                {
                    IsLowLevelDispatch = FALSE;
                }
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
        DPRINT1("KeBugCheckEx(INTERNAL_POWER_ERROR)\n");
        ASSERT(FALSE); // PoDbgBreakPointEx();
        KeBugCheckEx(INTERNAL_POWER_ERROR, 0x404, 5, (ULONG_PTR)IoStack, (ULONG_PTR)DeviceObject);
    }

    if (!KeGetCurrentIrql())
    {
        Status = IoCallDriver(IoStack->DeviceObject, Irp);
        return Status;
    }

    IoStack->Control |= SL_PENDING_RETURNED;
    Status = STATUS_PENDING;

    KeAcquireSpinLock(&PopWorkerLock, &OldIrql);

    if (PopCallSystemState & 1)
    {
        InsertTailList(&PopAction.DevState->PresentIrpQueue, &Irp->Tail.Overlay.ListEntry);
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

NTSTATUS
NTAPI
PoCallDriver(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ _Out_ PIRP Irp)
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

    DPRINT("PoCallDriver(%p, %p). %08X, %X, %X, %X, %X, %X\n", DeviceObject, Irp, DeviceObject->Flags, MinorFunction, 
           IoStack->Parameters.Power.SystemContext, IoStack->Parameters.Power.Type,
           IoStack->Parameters.Power.State, IoStack->Parameters.Power.ShutdownType);

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
                    DPRINT1("KeBugCheckEx(INTERNAL_POWER_ERROR)\n");
                    ASSERT(FALSE); // PoDbgBreakPointEx();
                    KeBugCheckEx(INTERNAL_POWER_ERROR, 0x400, 1, (ULONG_PTR)IoStack, (ULONG_PTR)DeviceObject);
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

                    if (PopIrpSerialListLength > 10)
                    {
                        DPRINT1("PoCallDriver: PopIrpSerialListLength > 10!\n");
                    }

                    if (PopIrpSerialListLength > 100)
                    {
                        DPRINT1("PoCallDriver: PopIrpSerialListLength > 100 !!!\n");
                        /* Too many inrush power IRPs have been queued. */
                        DPRINT1("KeBugCheckEx(INTERNAL_POWER_ERROR)\n");
                        ASSERT(FALSE); // PoDbgBreakPointEx();
                        KeBugCheckEx(INTERNAL_POWER_ERROR, 0x401, 2, (ULONG_PTR)&PopIrpSerialList, (ULONG_PTR)DeviceObject);
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

            if (PopIrpSerialListLength > 10)
            {
                DPRINT1("PoCallDriver: PopIrpSerialListLength > 10!\n");
            }

            if (PopIrpSerialListLength > 100)
            {
                DPRINT1("PoCallDriver: PopIrpSerialListLength > 100 !!!\n");
                /* Too many inrush power IRPs have been queued. */
                DPRINT1("KeBugCheckEx(INTERNAL_POWER_ERROR)\n");
                ASSERT(FALSE); // PoDbgBreakPointEx();
                KeBugCheckEx(INTERNAL_POWER_ERROR, 0x402, 3, (ULONG_PTR)&PopIrpSerialList, (ULONG_PTR)DeviceObject);
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
                /* Too many inrush power IRPs have been queued. */
                DPRINT1("PoCallDriver: KeBugCheckEx(INTERNAL_POWER_ERROR). PopIrpSerialListLength > 100 !!!\n");
                ASSERT(FALSE); // PoDbgBreakPointEx();
                KeBugCheckEx(INTERNAL_POWER_ERROR, 0x403, 4, (ULONG_PTR)&PopIrpSerialList, (ULONG_PTR)DeviceObject);
            }

            KeReleaseSpinLock(&PopIrpSerialSpinLock, OldIrql);
            return STATUS_PENDING;
        }
        else
        {
            PowerFlags.DeviceActive = 1;
        }
    }

    ASSERT(PowerFlags.SystemActive | PowerFlags.DeviceActive);

    KeReleaseSpinLock(&PopIrpSerialSpinLock, OldIrql);
    return PopSubmitIrp(IoStack, Irp);
}

/* unimplemented */
PULONG
NTAPI
PoRegisterDeviceForIdleDetection(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG ConservationIdleTime,
    _In_ ULONG PerformanceIdleTime,
    _In_ DEVICE_POWER_STATE State)
{
    UNIMPLEMENTED;
    return NULL;
}

/* unimplemented */
PVOID
NTAPI
PoRegisterSystemState(
    _In_ PVOID StateHandle,
    _In_ EXECUTION_STATE Flags)
{
    UNIMPLEMENTED;
    return NULL;
}

NTSTATUS
NTAPI
PoRequestPowerIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ UCHAR MinorFunction,
    _In_ POWER_STATE PowerState,
    _In_ PREQUEST_POWER_COMPLETE CompletionFunction,
    _In_ PVOID Context,
    _Out_ PIRP* OutIrp OPTIONAL)
{
    PDEVICE_OBJECT TopDeviceObject;
    POWER_ACTION ShutdownType;
    PIO_STACK_LOCATION Stack;
    PIRP Irp;

    /* Always call the top of the device stack */
    ASSERT(DeviceObject);
    TopDeviceObject = IoGetAttachedDeviceReference(DeviceObject);

    Irp = IoAllocateIrp((TopDeviceObject->StackSize + 2), FALSE);
    if (!Irp)
    {
        DPRINT1("PoRequestPowerIrp: Failed IoAllocateIrp()\n");
        ObDereferenceObject(TopDeviceObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    IoSetNextIrpStackLocation(Irp);

    Stack = IoGetCurrentIrpStackLocation(Irp);
    Stack->Parameters.Others.Argument3 = Irp; // ?

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
    Stack->DeviceObject = TopDeviceObject;

    if (MinorFunction == IRP_MN_WAIT_WAKE)
    {
        Stack->Parameters.WaitWake.PowerState = PowerState.SystemState;
    }
    else if (MinorFunction == IRP_MN_SET_POWER || MinorFunction == IRP_MN_QUERY_POWER)
    {
        Stack->Parameters.Power.SystemContext = 3;
        Stack->Parameters.Power.Type = DevicePowerState;
        Stack->Parameters.Power.State = PowerState;

        ShutdownType = PopMapInternalActionToIrpAction(PopAction.Action, PopAction.SystemState, TRUE);
        Stack->Parameters.Power.ShutdownType = ShutdownType;
    }
    else
    {
        DPRINT1("PoRequestPowerIrp: Unsupported MinorFunction %X\n", MinorFunction);
        ObDereferenceObject(TopDeviceObject);
        IoFreeIrp(Irp);
        return STATUS_INVALID_PARAMETER_2;
    }

    if (OutIrp)
        *OutIrp = Irp;

    IoSetCompletionRoutine(Irp, PopCompleteRequestIrp, CompletionFunction, TRUE, TRUE, TRUE);
    PoCallDriver(TopDeviceObject, Irp);

    /* Always return STATUS_PENDING. The completion routine will call CompletionFunction and complete the Irp. */
    return STATUS_PENDING;
}

/* unimplemented */
POWER_STATE
NTAPI
PoSetPowerState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ POWER_STATE_TYPE Type,
    _In_ POWER_STATE State)
{
    POWER_STATE ps;
    //KIRQL OldIrql;

    ASSERT_IRQL_LESS_OR_EQUAL(DISPATCH_LEVEL);

    //KeAcquireSpinLock(&PopIrpSerialSpinLock, &OldIrql);
    ps.SystemState = PowerSystemWorking;  // Fully on
    ps.DeviceState = PowerDeviceD0;       // Fully on
    //KeReleaseSpinLock(&PopIrpSerialSpinLock, OldIrql);

    return ps;
}

/* @unimplemented */
VOID
NTAPI
PoSetSystemState(
    _In_ EXECUTION_STATE Flags)
{
    if (Flags & ~(ES_SYSTEM_REQUIRED |
                  ES_DISPLAY_REQUIRED |
                  ES_USER_PRESENT))
    {
        ASSERT(FALSE);
        return;
    }

    //UNIMPLEMENTED;
    //DPRINT("PoSetSystemState: Flags %X. UNIMPLEMENTED\n", Flags);
}

static
PIRP
NTAPI
PopFindIrpByDevice(IN PDEVICE_OBJECT DeviceObject,
                   IN POWER_STATE_TYPE Type)
{
    PIO_STACK_LOCATION IoStack;
    PLIST_ENTRY Entry;
    PIRP Irp;

    for (Entry = PopIrpSerialList.Flink;
         Entry != &PopIrpSerialList;
         Entry = Entry->Flink)
    {
        Irp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);
        IoStack = IoGetNextIrpStackLocation(Irp);

        if (IoStack->DeviceObject == DeviceObject && IoStack->Parameters.Power.Type == Type)
            return Irp;
    }

    return NULL;
}

static
PIRP
NTAPI
PopFindIrpByInrush()
{
    PIO_STACK_LOCATION IoStack;
    PLIST_ENTRY Entry;
    PIRP Irp;

    for (Entry = PopIrpSerialList.Flink;
         Entry != &PopIrpSerialList;
         Entry = Entry->Flink)
    {
        Irp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);
        IoStack = IoGetNextIrpStackLocation(Irp);

        if (IoStack->Parameters.Power.SystemContext == POP_INRUSH_CONTEXT)
            return Irp;
    }

    return NULL;
}

VOID
NTAPI
PoStartNextPowerIrp(IN PIRP Irp)
{
    PEXTENDED_DEVOBJ_EXTENSION DeviceExtension;
    PEXTENDED_DEVOBJ_EXTENSION NextDeviceExtension;
    PIO_STACK_LOCATION IoStack;
    PIO_STACK_LOCATION NextSp = NULL;
    PIO_STACK_LOCATION SecondSp = NULL;
    PDEVICE_OBJECT DeviceObject;
    PIRP SecondIrp = NULL;
    PIRP NextIrp = NULL;
    PIRP irp;
    ULONG Context;
    KIRQL OldIrql;

    DPRINT("PoStartNextPowerIrp: Irp %p\n", Irp);

    ASSERT(Irp);
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    ASSERT(IoStack->MajorFunction == IRP_MJ_POWER);
    ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

    DeviceObject = IoStack->DeviceObject;
    DeviceExtension = IoGetDevObjExtension(DeviceObject);

    KeAcquireSpinLock(&PopIrpSerialSpinLock, &OldIrql);

    if (PopInrushIrpPointer == Irp)
    {
        ASSERT((IoStack->Parameters.Power.SystemContext & POP_INRUSH_CONTEXT) == POP_INRUSH_CONTEXT);

        if (PopInrushIrpReferenceCount > 1)
        {
            PopInrushIrpReferenceCount--;
            ASSERT(PopInrushIrpReferenceCount >= 0);

            NextIrp = PopFindIrpByDevice(DeviceObject, DevicePowerState);

            if (!NextIrp)
            {
                DeviceExtension->PowerFlags &= ~0xC00;
            }
            else
            {
                NextSp = IoGetNextIrpStackLocation(NextIrp);
                Context = NextSp->Parameters.Power.SystemContext;

                if ((Context & POP_INRUSH_CONTEXT) == POP_INRUSH_CONTEXT)
                {
                    NextIrp = NULL;
                }
                else
                {
                    RemoveEntryList(&NextIrp->Tail.Overlay.ListEntry);
                    PopIrpSerialListLength--;
                }

                if (!NextIrp)
                    DeviceExtension->PowerFlags &= ~0xC00;
            }

            KeReleaseSpinLock(&PopIrpSerialSpinLock, OldIrql);

            if (NextIrp)
            {
                DeviceExtension = IoGetDevObjExtension(NextSp->DeviceObject);
                ASSERT(DeviceExtension->PowerFlags & 0x400); // POPF_DEVICE_ACTIVE
                PopSubmitIrp(NextSp, NextIrp);
            }

            return;
        }

        PopInrushIrpReferenceCount--;
        ASSERT(PopInrushIrpReferenceCount == 0);

        NextIrp = PopFindIrpByInrush();

        if (NextIrp)
        {
            ASSERT(PopInrushPending);

            NextSp = IoGetNextIrpStackLocation(NextIrp);
            NextDeviceExtension = IoGetDevObjExtension(NextSp->DeviceObject);

            irp = PopFindIrpByDevice(NextSp->DeviceObject, DevicePowerState);

            if (irp)
            {
                PopInrushIrpPointer = NULL;
                PopInrushIrpReferenceCount = 0;

                NextIrp = irp;
                NextSp = IoGetNextIrpStackLocation(irp);

                if (NextDeviceExtension->PowerFlags & 0x400)
                {
                    NextIrp = NULL;
                    NextSp = NULL;
                }
                else
                {
                    RemoveEntryList(&NextIrp->Tail.Overlay.ListEntry);

                    NextDeviceExtension->PowerFlags |= 0x400;
                    PopIrpSerialListLength--;
                }
            }
            else
            {
                RemoveEntryList(&NextIrp->Tail.Overlay.ListEntry);

                NextDeviceExtension->PowerFlags |= 0x400;
                PopIrpSerialListLength--;

                PopInrushIrpPointer = NextIrp;
                PopInrushIrpReferenceCount = 1;
            }
        }
        else
        {
            PopInrushIrpPointer = NULL;
            PopInrushIrpReferenceCount = 0;
        }

        if (NextSp && NextSp->DeviceObject == DeviceObject)
        {
            SecondIrp = NULL;
            SecondSp = NULL;
        }
        else
        {
            SecondIrp = PopFindIrpByDevice(DeviceObject, DevicePowerState);

            if (SecondIrp)
            {
                SecondSp = IoGetNextIrpStackLocation(SecondIrp);
                RemoveEntryList(&SecondIrp->Tail.Overlay.ListEntry);

                (IoGetDevObjExtension(SecondSp->DeviceObject))->PowerFlags |= 0x400;
                PopIrpSerialListLength--;
            }
            else
            {
                SecondSp = NULL;
                DeviceExtension->PowerFlags &= ~0xC00;
            }
        }
    }
    else if (IoStack->MinorFunction == IRP_MN_SET_POWER || IoStack->MinorFunction == IRP_MN_QUERY_POWER)
    {
        if (IoStack->Parameters.Power.Type == DevicePowerState)
        {
            if (!PopInrushIrpPointer && PopInrushPending)
            {
                NextIrp = PopFindIrpByInrush();

                if (!NextIrp)
                {
                    PopInrushPending = FALSE;
                    NextSp = NULL;
                }
                else
                {
                    NextSp = IoGetNextIrpStackLocation(NextIrp);
                    NextDeviceExtension = IoGetDevObjExtension(NextSp->DeviceObject);

                    if (!(NextDeviceExtension->PowerFlags & 0x400))
                    {
                        RemoveEntryList(&NextIrp->Tail.Overlay.ListEntry);

                        PopIrpSerialListLength--;
                        NextDeviceExtension->PowerFlags |= 0x400;

                        PopInrushIrpPointer = NextIrp;
                        PopInrushIrpReferenceCount = 1;
                    }
                    else
                    {
                        NextIrp = NULL;
                        NextSp = NULL;
                    }
                }
            }
            else
            {
                NextIrp = NULL;
                NextSp = NULL;
            }

            if (NextIrp && NextSp->DeviceObject == DeviceObject)
            {
                SecondIrp = NULL;
            }
            else
            {
                SecondIrp = PopFindIrpByDevice(DeviceObject, DevicePowerState);

                if (!SecondIrp)
                {
                    DeviceExtension->PowerFlags &= ~0xC00;
                }
                else
                {
                    SecondSp = IoGetNextIrpStackLocation(SecondIrp);
                    RemoveEntryList(&SecondIrp->Tail.Overlay.ListEntry);
                    PopIrpSerialListLength--;
                }
            }

        }
        else if (IoStack->Parameters.Power.Type == SystemPowerState)
        {
            NextSp = NULL;
            NextIrp = NULL;

            SecondIrp = PopFindIrpByDevice(DeviceObject, SystemPowerState);

            if (!SecondIrp)
            {
                DeviceExtension->PowerFlags &= ~0x300;
            }
            else
            {
                SecondSp = IoGetNextIrpStackLocation(SecondIrp);
                RemoveEntryList(&SecondIrp->Tail.Overlay.ListEntry);
                PopIrpSerialListLength--;
            }
        }
    }
    else
    {
        DPRINT1("PoStartNextPowerIrp: %p (%X:%X) (%p:%p)\n", Irp, IoStack->MinorFunction,
                IoStack->Parameters.Power.State.DeviceState, DeviceObject, DeviceObject->DeviceExtension);
    }

    KeReleaseSpinLock(&PopIrpSerialSpinLock, OldIrql);

    if (NextIrp)
    {
        NextDeviceExtension = IoGetDevObjExtension(DeviceObject);

        ASSERT(NextSp);
        ASSERT(NextDeviceExtension->PowerFlags & 0x500); // (POPF_DEVICE_ACTIVE | POPF_SYSTEM_ACTIVE)

        DPRINT1("PoStartNextPowerIrp: PopSubmitIrp(NextIrp %p)\n", NextIrp);
        PopSubmitIrp(NextSp, NextIrp);
    }

    if (SecondIrp)
    {
        DeviceExtension = IoGetDevObjExtension(DeviceObject);

        ASSERT(SecondSp);
        ASSERT(DeviceExtension->PowerFlags & 0x500); // (POPF_DEVICE_ACTIVE | POPF_SYSTEM_ACTIVE)

        DPRINT1("PoStartNextPowerIrp: PopSubmitIrp(SecondIrp %p)\n", SecondIrp);
        PopSubmitIrp(SecondSp, SecondIrp);
    }
}

/* unimplemented */
VOID
NTAPI
PoUnregisterSystemState(
    _In_ PVOID StateHandle)
{
    UNIMPLEMENTED;
}

/* unimplemented */
NTSTATUS
NTAPI
NtInitiatePowerAction(
    _In_ POWER_ACTION SystemAction,
    _In_ SYSTEM_POWER_STATE MinSystemState,
    _In_ ULONG Flags,
    _In_ BOOLEAN Asynchronous)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
PopChangeCapability(
    _In_ PBOOLEAN StateSupport,
    _In_ BOOLEAN IsSupport)
{
    DPRINT("PopChangeCapability: IsSupport %X\n", IsSupport);

    if (*StateSupport == IsSupport)
        return;

    DPRINT("PopChangeCapability: *StateSupport %X\n", *StateSupport);

    *StateSupport = IsSupport;

    DPRINT("PopChangeCapability: FIXME PopResetCurrentPolicies()\n");
    DPRINT("PopChangeCapability: FIXME PopSetNotificationWork()\n");
}

/* halfplemented */
NTSTATUS
NTAPI
NtPowerInformation(
    _In_ POWER_INFORMATION_LEVEL PowerInformationLevel,
    _In_ PVOID InputBuffer  OPTIONAL,
    _In_ ULONG InputBufferLength,
    _Out_ PVOID OutputBuffer  OPTIONAL,
    _In_ ULONG OutputBufferLength)
{
    NTSTATUS Status;
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
    SYSTEM_POWER_STATE State = PowerSystemUnspecified;
    PVOID LoggingInfo = NULL;
    BOOLEAN IsCheckForWork = FALSE;

    PAGED_CODE();

    DPRINT("NtPowerInformation: %X, %p, %X, %p, %X\n", PowerInformationLevel, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);

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

    PopAcquirePolicyLock();

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
//                BatteryState->AcOnLine = TRUE;

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
                RtlCopyMemory(PowerCapabilities, &PopCapabilities, sizeof(SYSTEM_POWER_CAPABILITIES));
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

            /* FIXME: return structures for all processors */

            _SEH2_TRY
            {
                /* FIXME: some values are hardcoded */
                PowerInformation->Number = 0;
                PowerInformation->MaxMhz = 1000;
                PowerInformation->CurrentMhz = KeGetCurrentPrcb()->MHz;
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
        case SystemPowerLoggingEntry:
        {
            UNIMPLEMENTED;
            break;
        }
        case SystemPowerStateHandler:
        {
            PPOWER_STATE_HANDLER PowerStateHandler = (PPOWER_STATE_HANDLER)InputBuffer;
            POWER_STATE_HANDLER_TYPE StateType = PowerStateHandler->Type;
            PBOOLEAN Capabilities = NULL;

            Status = STATUS_SUCCESS;

            if (PreviousMode != KernelMode)
            {
                Status = STATUS_ACCESS_DENIED;
                break;
            }

            if (OutputBuffer)
            {
                DPRINT1("NtPowerInformation: STATUS_INVALID_PARAMETER. OutputBuffer %p\n", OutputBuffer);
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (OutputBufferLength)
            {
                DPRINT1("NtPowerInformation: STATUS_INVALID_PARAMETER. OutputBufferLength %X\n", OutputBufferLength);
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (!InputBuffer)
            {
                DPRINT1("NtPowerInformation: STATUS_INVALID_PARAMETER. InputBuffer is NULL\n");
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (InputBufferLength < sizeof(*PowerStateHandler))
            {
                DPRINT1("NtPowerInformation: STATUS_INVALID_PARAMETER. InputBufferLength %X\n", InputBufferLength);
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (StateType >= PowerStateMaximum)
            {
                DPRINT1("NtPowerInformation: STATUS_INVALID_PARAMETER. StateType %X\n", StateType);
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (PopPowerStateHandlers[StateType].Handler)
            {
                DPRINT1("NtPowerInformation: FIXME PopShutdownHandler()\n");
                ASSERT(FALSE);
            }

            PopPowerStateHandlers[StateType].Type = StateType;
            PopPowerStateHandlers[StateType].RtcWake = PowerStateHandler->RtcWake;
            PopPowerStateHandlers[StateType].Handler = PowerStateHandler->Handler;
            PopPowerStateHandlers[StateType].Context = PowerStateHandler->Context;

            PopPowerStateHandlers[StateType].Spare[0] = 0;
            PopPowerStateHandlers[StateType].Spare[1] = 0;
            PopPowerStateHandlers[StateType].Spare[2] = 0;

            switch (StateType)
            {
                case PowerStateSleeping1:
                    DPRINT1("NtPowerInformation: FIXME PowerStateSleeping1\n");
                    State = PowerSystemSleeping1;
                    break;

                case PowerStateSleeping2:
                    DPRINT1("NtPowerInformation: FIXME PowerStateSleeping2\n");
                    State = PowerSystemSleeping2;
                    break;

                case PowerStateSleeping3:
                    DPRINT1("NtPowerInformation: FIXME PowerStateSleeping3\n");
                    State = PowerSystemSleeping3;
                    break;

                case PowerStateSleeping4:
                    DPRINT1("NtPowerInformation: FIXME PowerStateSleeping4\n");
                    State = PowerSystemHibernate;
                    break;

                case PowerStateShutdownOff:
                    DPRINT1("NtPowerInformation: PowerStateShutdownOff\n");
                    Capabilities = &PopCapabilities.SystemS5;
                    break;

                default:
                    DPRINT1("NtPowerInformation: Unsupported Type %X\n", StateType);
                    break;
            }

            if (!PopPowerStateHandlers[StateType].RtcWake)
                State = PowerSystemUnspecified;

            if (State > PopCapabilities.RtcWake)
                PopCapabilities.RtcWake = State;

            if (Capabilities)
                PopChangeCapability(Capabilities, TRUE);

            break;
        }
        default:
            Status = STATUS_NOT_IMPLEMENTED;
            DPRINT1("NtPowerInformation: Level %X is UNIMPLEMENTED\n", PowerInformationLevel);
            break;
    }

    if (IsCheckForWork == TRUE)
    {
        PopReleasePolicyLock(FALSE);
        DPRINT1("NtPowerInformation: FIXME PopCheckForWork()\n");
        ASSERT(FALSE);
        goto Exit;
    }

    //PopReleasePolicyLock(InputBuffer != NULL);
    if (InputBuffer != NULL)
    {
        DPRINT("NtPowerInformation: FIXME PopReleasePolicyLock(TRUE)\n");PopReleasePolicyLock(FALSE);
        //ASSERT(FALSE);
        //PopReleasePolicyLock(TRUE);
    }
    else
    {
        PopReleasePolicyLock(FALSE);
    }

Exit:

    if (LoggingInfo)
    {
        DPRINT1("NtPowerInformation: FIXME free LoggingInfo\n");
        ASSERT(FALSE);//ExFreePool(LoggingInfo);
    }

    return Status;
}

NTSTATUS
NTAPI
NtGetDevicePowerState(
    _In_ HANDLE Device,
    _In_ PDEVICE_POWER_STATE PowerState)
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
NtRequestWakeupLatency(
    _In_ LATENCY_TIME Latency)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
NtSetThreadExecutionState(
    _In_ EXECUTION_STATE esFlags,
    _Out_ EXECUTION_STATE *PreviousFlags)
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

VOID
NTAPI
PiLockDeviceActionQueue(VOID)
{
    KIRQL OldIrql;

    DPRINT("PiLockDeviceActionQueue()\n");

    PpDevNodeLockTree(1);
    KeAcquireSpinLock(&IopPnPSpinLock, &OldIrql);

    while (PipEnumerationInProgress)
    {
        KeReleaseSpinLock(&IopPnPSpinLock, OldIrql);
        PpDevNodeUnlockTree(1);

        DPRINT("PiLockDeviceActionQueue: call KeWaitForSingleObject()\n");
        KeWaitForSingleObject(&PiEnumerationLock, Executive, KernelMode, FALSE, NULL);
        DPRINT("PiLockDeviceActionQueue: end wait\n");

        PpDevNodeLockTree(1);
        KeAcquireSpinLock(&IopPnPSpinLock, &OldIrql);
    }

    KeClearEvent(&PiEnumerationLock);
    PipEnumerationInProgress = TRUE;

    KeReleaseSpinLock(&IopPnPSpinLock, OldIrql);

    DPRINT("PiLockDeviceActionQueue: Locked\n");
}

VOID
NTAPI
PiUnlockDeviceActionQueue(VOID)
{
    KIRQL OldIrql;
  
    DPRINT("PiUnlockDeviceActionQueue()\n");

    KeAcquireSpinLock(&IopPnPSpinLock, &OldIrql);

    if (IsListEmpty(&IopPnpEnumerationRequestList))
    {
        PipEnumerationInProgress = FALSE;
        KeSetEvent(&PiEnumerationLock, IO_NO_INCREMENT, FALSE);
    }
    else
    {
        DPRINT1("PiUnlockDeviceActionQueue: FIXME PipDeviceEnumerationWorkItem\n");
        ASSERT(FALSE); // PoDbgBreakPointEx();
    }

    KeReleaseSpinLock(&IopPnPSpinLock, OldIrql);
    PpDevNodeUnlockTree(1);

    DPRINT("PiUnlockDeviceActionQueue: Unlocked\n");
}

VOID
NTAPI
IopFreePoDeviceNotifyListHead(
    _In_ PLIST_ENTRY NotifyListHead)
{
    PPO_DEVICE_NOTIFY Notify;
    PDEVICE_NODE DeviceNode;

    //DPRINT("IopFreePoDeviceNotifyListHead: NotifyListHead %p\n", NotifyListHead);

    while (!IsListEmpty(NotifyListHead))
    {
        Notify = CONTAINING_RECORD(NotifyListHead->Flink, PO_DEVICE_NOTIFY, Link);

        NotifyListHead->Flink = NotifyListHead->Flink->Flink;
        NotifyListHead->Flink->Flink->Blink = NotifyListHead;

        DeviceNode = Notify->Node;
        DeviceNode->Notify = NULL;

        ObDereferenceObject(Notify->DeviceObject);
        ObDereferenceObject(Notify->TargetDevice);

        if (Notify->DeviceName)
            ExFreePool(Notify->DeviceName);

        if (Notify->DriverName)
            ExFreePool(Notify->DriverName);

        ExFreePool(Notify);
    }
}

VOID
NTAPI
IoFreePoDeviceNotifyList(
    _In_ PPO_DEVICE_NOTIFY_ORDER Order)
{
    ULONG ix;

    DPRINT("IoFreePoDeviceNotifyList: Order %p\n", Order);

    if (Order->DevNodeSequence)
    {
        Order->DevNodeSequence = 0;
        PiUnlockDeviceActionQueue();
    }

    for (ix = 0; ix < 8; ix++)
    {
        IopFreePoDeviceNotifyListHead(&Order->OrderLevel[ix].WaitSleep);
        IopFreePoDeviceNotifyListHead(&Order->OrderLevel[ix].ReadySleep);
        IopFreePoDeviceNotifyListHead(&Order->OrderLevel[ix].Pending);
        IopFreePoDeviceNotifyListHead(&Order->OrderLevel[ix].Complete);
        IopFreePoDeviceNotifyListHead(&Order->OrderLevel[ix].ReadyS0);
        IopFreePoDeviceNotifyListHead(&Order->OrderLevel[ix].WaitS0);
    }
}

NTSTATUS
NTAPI
NtSetSystemPowerState(
    _In_ POWER_ACTION SystemAction,
    _In_ SYSTEM_POWER_STATE MinSystemState,
    _In_ ULONG Flags)
{
    KPROCESSOR_MODE PreviousMode = KeGetPreviousMode();
    SYSTEM_POWER_STATE PopActionSystemState;
    SYSTEM_POWER_STATE MaxState;
    POWER_ACTION_POLICY ActionPolicy;
    POP_ACTION_TRIGGER ActionTrigger;
    BOOLEAN IsTimerRefreshLocked;
    BOOLEAN StatesIsNotEqual;
    BOOLEAN IsPolicyLock;
    ULONGLONG SleepTime = 0;
    ULONG FlagBits;
    NTSTATUS Status;

    DPRINT("NtSetSystemPowerState: [%X] SystemAction %X, MinSystemState %X, Flags %X\n", PreviousMode, SystemAction, MinSystemState, Flags);

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
        DPRINT1("                       SystemAction: %X\n", SystemAction);
        DPRINT1("                       MinSystemState: %X\n", MinSystemState);
        DPRINT1("                       Flags:  %X\n", Flags);
        return STATUS_INVALID_PARAMETER;
    }

    /* Check for user caller */
    if (PreviousMode != KernelMode)
    {
        /* Check for shutdown permission */
        if (!SeSinglePrivilegeCheck(SeShutdownPrivilege, PreviousMode))
        {
            /* Not granted */
            DPRINT1("NtSetSystemPowerState: ERROR - privilege not held for shutdown\n");
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        /* Do it as a kernel-mode caller for consistency with system state */
        return ZwSetSystemPowerState(SystemAction, MinSystemState, Flags);
    }

    /* Read policy settings (partial shutdown vs. full shutdown) */
    if (SystemAction == PowerActionShutdown)
        PopReadShutdownPolicy();

    /* Disable lazy flushing of registry */
    DPRINT("NtSetSystemPowerState: Stopping lazy flush\n");
    CmSetLazyFlushState(FALSE);

    IsTimerRefreshLocked = FALSE;
    IsFlushedVolumes = FALSE;

    ActionPolicy.Action = SystemAction;
    ActionPolicy.Flags = Flags;
    ActionPolicy.EventCode = 0;

    RtlZeroMemory(&ActionTrigger, sizeof(ActionTrigger));

    ActionTrigger.Battery.Level = 0;
    ActionTrigger.Type = PolicySetPowerStateAPI;
    ActionTrigger.Flags = 0x80;

    //ASSERT(ExPageLockHandle);
    KeWaitForSingleObject(&PopUnlockComplete, WrExecutive, KernelMode, FALSE, NULL);
    //MmLockPagableSectionByHandle(ExPageLockHandle);

    /* Notify callbacks */
    DPRINT("NtSetSystemPowerState: Notifying callbacks\n");
    ExNotifyCallback(PowerStateCallback, UlongToPtr(3), NULL);

    /* Swap in any worker thread stacks */
    DPRINT("NtSetSystemPowerState: Swapping worker threads\n");
    ExSwapinWorkerThreads(FALSE);

    PopAcquirePolicyLock();
    IsPolicyLock = TRUE;
    DPRINT("NtSetSystemPowerState: IsPolicyLock %X\n", IsPolicyLock);

    if (PopAction.State == 0)
    {
        PopResetActionDefaults();
    }
    else if (PopAction.State != 2)
    {
        DPRINT("NtSetSystemPowerState: already committed\n");

        PopReleasePolicyLock(FALSE);
        //MmUnlockPagableImageSection(ExPageLockHandle);
        ExSwapinWorkerThreads(TRUE);
        KeSetEvent(&PopUnlockComplete, IO_NO_INCREMENT, FALSE);

        ASSERT(FALSE); // PoDbgBreakPointEx();

        return STATUS_ALREADY_COMMITTED;
    }

    PopAction.State = 3;
    Status = STATUS_CANCELLED;

    //_SEH2_TRY
    PopSetPowerAction(&ActionTrigger, 0, &ActionPolicy, MinSystemState, 1);
    //_SEH2_END

    if (SystemAction == PowerActionShutdownOff)
        PopAction.Action = PowerActionShutdownOff;

    if (SystemAction == PowerActionShutdown ||
        SystemAction == PowerActionShutdownReset ||
        SystemAction == PowerActionShutdownOff)
    {
        if (PopHiberFile)
        {
            ASSERT(FALSE); // PoDbgBreakPointEx();
        }
    }

    PopAllocateDevState();

    if (!PopAction.DevState)
    {
        DPRINT1("NtSetSystemPowerState: STATUS_INSUFFICIENT_RESOURCES\n");
        PopAction.State = 0;

        PopReleasePolicyLock(0);
        //MmUnlockPagableImageSection(ExPageLockHandle);
        ExSwapinWorkerThreads(TRUE);
        KeSetEvent(&PopUnlockComplete, IO_NO_INCREMENT, FALSE);

        ASSERT(FALSE); // PoDbgBreakPointEx();

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DPRINT("NtSetSystemPowerState: PopAction.Action %X, PopAction.Flags %X\n", PopAction.Action, PopAction.Flags);

    /* Start power loop */
    Status = STATUS_CANCELLED;
    StatesIsNotEqual = FALSE;
    MaxState = PowerSystemUnspecified;

    while (TRUE)
    {
        DPRINT("NtSetSystemPowerState: PopAction.Action %X\n", PopAction.Action);

        if (!IsPolicyLock)
        {
            PopAcquirePolicyLock();
            IsPolicyLock = TRUE;
        }

        if (PopAction.Action == PowerActionNone)
            goto Exit;

        ASSERT(PopAction.Action != PowerActionHibernate);

        PopAction.Updates &= ~7;

        if (Status == STATUS_CANCELLED)
        {
            DPRINT("NtSetSystemPowerState: Status is STATUS_CANCELLED\n");

            if ((PopAction.Updates & 2) && // FIXME: ? PopAction.Updates always ~7
                !(PopAction.Flags & POWER_ACTION_CRITICAL) &&
                (PopAction.Flags & 3))
            {
                PopGetPolicyWorker(4);
Exit:
                if (NT_SUCCESS(Status))
                {
                    PopAction.SleepTime = SleepTime;
                    ASSERT(IsTimerRefreshLocked);
                    ExUpdateSystemTimeFromCmos(1, 1);
                }

                DPRINT1("NtSetSystemPowerState: Status %X\n", Status);
                ASSERT(FALSE); // PoDbgBreakPointEx();
                return Status;
            }

            PopActionRetrieveInitialState(&PopAction.LightestState, &MaxState, &PopAction.SystemState, &StatesIsNotEqual);

            DPRINT("NtSetSystemPowerState: %X, %X, %X, %X\n",
                   PopAction.LightestState, MaxState, PopAction.SystemState, StatesIsNotEqual);

            ASSERT(PopAction.SystemState != PowerSystemUnspecified);

            if (PopAction.Action == PowerActionShutdown ||
                PopAction.Action == PowerActionShutdownReset ||
                PopAction.Action == PowerActionShutdownOff)
            {
                PopAction.Shutdown = TRUE;
                DPRINT("NtSetSystemPowerState: PopAction.Shutdown - TRUE\n");
            }

            Status = STATUS_SUCCESS;
        }

        if (StatesIsNotEqual && PopAction.SystemState < PowerSystemShutdown)
        {
            PopActionSystemState = PopAction.SystemState;
            PopVerifySystemPowerState(&PopActionSystemState, 1);

            if (PopActionSystemState != PopAction.SystemState ||
                PopActionSystemState == PowerSystemWorking)
            {
                DPRINT1("KeBugCheckEx(INTERNAL_POWER_ERROR)\n");
                ASSERT(FALSE); // PoDbgBreakPointEx();
                KeBugCheckEx(INTERNAL_POWER_ERROR, 2, 0x602FB, 0, 0);
            }
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("NtSetSystemPowerState: Status %X\n", Status);
            ASSERT(FALSE); // PoDbgBreakPointEx();
            return Status;
        }

        PopReleasePolicyLock(0);
        IsPolicyLock = FALSE;

        DPRINT("NtSetSystemPowerState: FIXME PopInitializePowerPolicySimulate()\n");
        //ASSERT(FALSE); // PoDbgBreakPointEx();

        PopReportDevState(FALSE);

        PopAction.NextSystemState = PopAction.SystemState;
        FlagBits = ((PopAction.Flags >> 27) & 2);
        PopAdvanceSystemPowerState(&PopAction.NextSystemState, FlagBits, PopAction.LightestState, MaxState);

        DPRINT("NtSetSystemPowerState: Action %X, NextSystemState %X\n", PopAction.Action, PopAction.NextSystemState);

        PopAction.IrpMinor = IRP_MN_QUERY_POWER;

        if (StatesIsNotEqual)
        {
            ASSERT(FALSE); // PoDbgBreakPointEx();
            Status = STATUS_SUCCESS;
            continue;
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("NtSetSystemPowerState: Status %X\n", Status);
            continue;
        }

        PopSystemIrpDispatchWorker(TRUE);

        DPRINT1("NtSetSystemPowerState: FIXME RtlGetNtProductType()\n");
        //...
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("NtSetSystemPowerState: Status %X\n", Status);
            ASSERT(FALSE); // PoDbgBreakPointEx();
            continue;
        }

        if (PopAction.Updates & 6)
        {
            DPRINT1("NtSetSystemPowerState: PopAction.Updates %X\n", PopAction.Updates);
            ASSERT(FALSE); // PoDbgBreakPointEx();
            continue;
        }

        DPRINT("NtSetSystemPowerState: FIXME RtlLockBootStatusData()\n");

        /* Flush all volumes and the registry */
        if (!IsFlushedVolumes)
        {
            IsFlushedVolumes = TRUE;
            PopFlushVolumes(PopAction.Shutdown);
        }

        PopAction.IrpMinor = IRP_MN_SET_POWER;

        if (PopAction.Shutdown)
        {
            IoFreePoDeviceNotifyList(&PopAction.DevState->Order);
            PopAction.DevState->GetNewDeviceList = TRUE;

            DPRINT("NtSetSystemPowerState: Queueing shutdown thread\n");

            /* Check if we are running in the system context */
            if (PsGetCurrentProcess() == PsInitialSystemProcess)
            {
                /* Do the shutdown inline */
                PopGracefulShutdown(NULL);
            }
            else
            {
                /* We're not, so use a worker thread for shutdown */
                ExInitializeWorkItem(&PopShutdownWorkItem, &PopGracefulShutdown, NULL);
                ExQueueWorkItem(&PopShutdownWorkItem, CriticalWorkQueue);

                KeSuspendThread(KeGetCurrentThread());
                return STATUS_SYSTEM_SHUTDOWN;
            }
        }

        DPRINT1("NtSetSystemPowerState: PopAction.Shutdown is 0\n");
        ASSERT(FALSE); // PoDbgBreakPointEx();
    }

    /* We're done, return */
    return Status;
}

/* EOF */