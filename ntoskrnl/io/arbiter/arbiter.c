/*
 * PROJECT:         ReactOS Kernel
 * COPYRIGHT:       GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/arbiter/arbiter.c
 * PURPOSE:         Arbiter of hardware resources library
 * PROGRAMMERS:     
 */

/* INCLUDES *******************************************************************/

#include "../pnpio.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

/* DATA **********************************************************************/

static PCHAR ArbpActionStrings[] =
{
    "Arbiter Action TestAllocation",
    "Arbiter Action RetestAllocation",
    "Arbiter Action CommitAllocation",
    "Arbiter Action RollbackAllocation",
    "Arbiter Action QueryAllocatedResources",
    "Arbiter Action WriteReservedResources",
    "Arbiter Action QueryConflict",
    "Arbiter Action QueryArbitrate",
    "Arbiter Action AddReserved",
    "Arbiter Action BootAllocation"
};

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
ArbArbiterHandler(
    _In_ PVOID Context,
    _In_ ARBITER_ACTION Action,
    _Out_ PARBITER_PARAMETERS Params)
{
    PARBITER_INSTANCE Arbiter = Context;
    NTSTATUS Status=0;

    //PAGED_CODE();
    DPRINT("ArbArbiterHandler: Context %p, Action %X\n", Context, Action);

    ASSERT(Context);
    ASSERT(Arbiter->Signature == 'sbrA');

    ASSERT(Action >= ArbiterActionTestAllocation &&
           Action <= ArbiterActionBootAllocation);

    KeWaitForSingleObject(Arbiter->MutexEvent,
                          Executive,
                          KernelMode,
                          FALSE,
                          NULL);

    DPRINT("ArbArbiterHandler: %s %S\n",
           ArbpActionStrings[Action], Arbiter->Name);

    if (Action &&
        Action != ArbiterActionRetestAllocation &&
        Action != ArbiterActionBootAllocation)
    {
        if ((Action == ArbiterActionCommitAllocation ||
             Action == ArbiterActionRollbackAllocation))
        {
            ASSERT(Arbiter->TransactionInProgress);
        }
    }
    else if (Arbiter->TransactionInProgress)
    {
        ASSERT(!Arbiter->TransactionInProgress);
    }

    switch (Action)
    {
        case ArbiterActionTestAllocation:
            ASSERT(FALSE);
            break;
        case ArbiterActionRetestAllocation:
            ASSERT(FALSE);
            break;
        case ArbiterActionCommitAllocation:
            ASSERT(FALSE);
            break;
        case ArbiterActionRollbackAllocation:
            ASSERT(FALSE);
            break;
        case ArbiterActionBootAllocation:
            Status = Arbiter->BootAllocation(
                              Arbiter,
                              Params->Parameters.BootAllocation.ArbitrationList);
            break;
        case ArbiterActionQueryConflict:
            ASSERT(FALSE);
            break;
        case ArbiterActionQueryAllocatedResources:
        case ArbiterActionWriteReservedResources:
        case ArbiterActionQueryArbitrate:
        case ArbiterActionAddReserved:
            ASSERT(FALSE);
            Status = STATUS_NOT_IMPLEMENTED;
            return STATUS_NOT_IMPLEMENTED;
        default:
            ASSERT(FALSE);
            Status = STATUS_INVALID_PARAMETER;
            return Status;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT("ArbArbiterHandler: %s for %S failed. Status - %X\n",
               ArbpActionStrings[Action], Arbiter->Name, Status);

        ASSERT(FALSE);
        return Status;
    }

    if (Action && Action != ArbiterActionRetestAllocation)
    {
        if (Action == ArbiterActionCommitAllocation ||
            Action == ArbiterActionRollbackAllocation)
        {
          Arbiter->TransactionInProgress = FALSE;
        }
    }
    else
    {
        Arbiter->TransactionInProgress = TRUE;
    }

    KeSetEvent(Arbiter->MutexEvent, IO_NO_INCREMENT, FALSE);

    return Status;
}


NTSTATUS
NTAPI
ArbTestAllocation()
{
    DPRINT("ArbTestAllocation: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ArbRetestAllocation()
{
    DPRINT("ArbRetestAllocation: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ArbCommitAllocation()
{
    DPRINT("ArbCommitAllocation: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ArbRollbackAllocation()
{
    DPRINT("ArbRollbackAllocation: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ArbAddReserved()
{
    DPRINT("ArbAddReserved: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ArbPreprocessEntry()
{
    DPRINT("ArbPreprocessEntry: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ArbAllocateEntry()
{
    DPRINT("ArbAllocateEntry: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ArbGetNextAllocationRange()
{
    DPRINT("ArbGetNextAllocationRange: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ArbFindSuitableRange()
{
    DPRINT("ArbFindSuitableRange: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ArbAddAllocation()
{
    DPRINT("ArbAddAllocation: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ArbBacktrackAllocation()
{
    DPRINT("ArbBacktrackAllocation: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ArbOverrideConflict()
{
    DPRINT("ArbOverrideConflict: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ArbBootAllocation(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PLIST_ENTRY ArbitrationList)
{
    PRTL_RANGE_LIST OldAllocation;
    PARBITER_LIST_ENTRY Current;
    ARBITER_ALTERNATIVE Alternative;
    ARBITER_ALLOCATION_STATE ArbState;
    NTSTATUS Status;

    //PAGED_CODE();
    DPRINT("ArbBootAllocation: Arbiter - %p, ArbitrationList - %p\n",
           Arbiter, ArbitrationList);

    RtlZeroMemory(&ArbState, sizeof(ArbState));

    ArbState.AlternativeCount = 1;
    ArbState.Alternatives = &Alternative;
    ArbState.CurrentAlternative = &Alternative;
    ArbState.Flags = 2;
    ArbState.RangeAttributes = 1;

    RtlCopyRangeList(Arbiter->PossibleAllocation, Arbiter->Allocation);

    RtlZeroMemory(&Alternative, sizeof(Alternative));

    for (Current = CONTAINING_RECORD(ArbitrationList->Flink, ARBITER_LIST_ENTRY, ListEntry);
         &Current->ListEntry != ArbitrationList;
         Current = CONTAINING_RECORD(Current->ListEntry.Flink, ARBITER_LIST_ENTRY, ListEntry))
    {
        ASSERT(Current->AlternativeCount == 1);
        ASSERT(Current->PhysicalDeviceObject);

        ArbState.Entry = Current;

        Status = ArbpBuildAlternative(Arbiter, Current->Alternatives, &Alternative);
        ASSERT(NT_SUCCESS(Status));

        ASSERT(Alternative.Flags & (2|4)); // (ARBITER_ALTERNATIVE_FLAG_FIXED | ARBITER_ALTERNATIVE_FLAG_INVALID)

        ArbState.WorkSpace = 0;
        ArbState.Start = Alternative.Minimum;
        ArbState.End = Alternative.Maximum;
        ArbState.RangeAvailableAttributes = 0;

        if (Alternative.Length == 0||
            Alternative.Alignment == 0||
            Alternative.Maximum < Alternative.Minimum ||
            Alternative.Minimum % Alternative.Alignment ||
            (Alternative.Maximum - Alternative.Minimum + 1 != Alternative.Length))
        {
            DPRINT("ArbBootAllocation: Skipping invalid boot allocation [%I64X-%I64X], L - %X, A - %X, for PDO - %p\n",
                   Alternative.Minimum, Alternative.Maximum, Alternative.Length, Alternative.Alignment, Current->PhysicalDeviceObject);

            continue;
        }
        else
        {
            DPRINT("ArbBootAllocation: Boot allocation [%I64X-%I64X], L - %X, A - %X, for PDO - %p\n",
                   Alternative.Minimum, Alternative.Maximum, Alternative.Length, Alternative.Alignment, Current->PhysicalDeviceObject);
        }

        DPRINT("ArbBootAllocation: ArbState - %p, ArbState.Entry->PhysicalDeviceObject - %p\n",
               &ArbState, ArbState.Entry->PhysicalDeviceObject);

        Status = Arbiter->PreprocessEntry(Arbiter, &ArbState);

        if (!NT_SUCCESS(Status))
        {
            ASSERT(FALSE);
            RtlFreeRangeList(Arbiter->PossibleAllocation);
            return Status;
        }

        Arbiter->AddAllocation(Arbiter, &ArbState);

    }

    OldAllocation = Arbiter->Allocation;

    RtlFreeRangeList(Arbiter->Allocation);

    Arbiter->Allocation = Arbiter->PossibleAllocation;
    Arbiter->PossibleAllocation = OldAllocation;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ArbQueryConflict()
{
    DPRINT("ArbQueryConflict: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ArbStartArbiter()
{
    DPRINT("ArbStartArbiter: ...\n");
    ASSERT(FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ArbAddOrdering(
    _Out_ PARBITER_ORDERING_LIST OrderList,
    _In_ ULONGLONG MinimumAddress,
    _In_ ULONGLONG MaximumAddress)
{
    PARBITER_ORDERING NewOrderings;
    ULONG NewCount;

    //PAGED_CODE();
    //DPRINT("ArbAddOrdering: OrderList - %p, MinimumAddress - %I64X, MaximumAddress - %I64X\n",
    //       OrderList, MinimumAddress, MaximumAddress);

    if (MaximumAddress < MinimumAddress)
    {
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }

    if (OrderList->Count < OrderList->Maximum)
    {
        //DPRINT("ArbAddOrdering: OrderList->Count - %X, OrderList->Maximum - %X\n",
        //       OrderList->Count, OrderList->Maximum);
        goto Exit;
    }

    NewCount = (OrderList->Count + ARB_ORDERING_LIST_ADD_COUNT) *
               sizeof(ARBITER_ORDERING);

    NewOrderings = ExAllocatePoolWithTag(PagedPool, NewCount, 'LbrA');

    if (!NewOrderings)
    {
        ASSERT(FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (OrderList->Orderings)
    {
        RtlCopyMemory(NewOrderings,
                      OrderList->Orderings,
                      sizeof(ARBITER_ORDERING) * OrderList->Count);

        ExFreePoolWithTag(OrderList->Orderings, 'LbrA');
    }

    OrderList->Orderings = NewOrderings;
    OrderList->Maximum += ARB_ORDERING_LIST_ADD_COUNT;

Exit:

    OrderList->Orderings[OrderList->Count].Start = MinimumAddress;
    OrderList->Orderings[OrderList->Count].End = MaximumAddress;

    OrderList->Count++;
    ASSERT(OrderList->Count <= OrderList->Maximum);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ArbPruneOrdering(
    _Out_ PARBITER_ORDERING_LIST OrderingList,
    _In_ ULONGLONG MinimumAddress,
    _In_ ULONGLONG MaximumAddress)
{
    PARBITER_ORDERING Current;
    PARBITER_ORDERING Orderings;
    PARBITER_ORDERING NewOrderings;
    PARBITER_ORDERING TmpOrderings;
    ULONG TmpOrderingsSize;
    ULONG ix;
    USHORT Count;

    //PAGED_CODE();
    DPRINT("ArbPruneOrdering: OrderingList->Count - %X, MinimumAddress - %I64X, MaximumAddress - %I64X\n",
            OrderingList->Count, MinimumAddress, MaximumAddress);

    ASSERT(OrderingList);
    ASSERT(OrderingList->Orderings);

    if (MaximumAddress < MinimumAddress)
    {
        DPRINT("ArbPruneOrdering: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    TmpOrderingsSize = (2 * OrderingList->Count * sizeof(ARBITER_ORDERING)) +
                       sizeof(ARBITER_ORDERING);

    TmpOrderings = ExAllocatePoolWithTag(PagedPool,
                                         TmpOrderingsSize,
                                        'LbrA');
    if (!TmpOrderings)
    {
        DPRINT("ArbPruneOrdering: STATUS_INSUFFICIENT_RESOURCES\n");
        goto ErrorExit;
    }

    Current = TmpOrderings;
    Orderings = OrderingList->Orderings;

    for (ix = 0; ix < OrderingList->Count; ix++)
    {
        if (MaximumAddress < Orderings[0].Start ||
            MinimumAddress > Orderings[0].End)
        {
            Current->Start = Orderings[0].Start;
            Current->End = Orderings[0].End;
        }
        else if (MinimumAddress <= Orderings[0].Start)
        {
            if (MaximumAddress >= Orderings[0].End)
            {
                continue;
            }
            else
            {
                Current->Start = MaximumAddress + 1;
                Current->End = Orderings[0].End;
            }
        }
        else
        {
            if (MaximumAddress >= Orderings[0].End)
            {
                Current->Start = Orderings[0].Start;
                Current->End = MinimumAddress - 1;
            }
            else
            {
                Current->Start = MaximumAddress + 1;
                Current->End = Orderings[0].End;

                Current++;

                Current->Start = Orderings[0].Start;
                Current->End = MinimumAddress - 1;
            }
        }

        Current++;
    }

    Count = Current - TmpOrderings;
    ASSERT(Current - TmpOrderings >= 0);

    if (!Count)
    {
        ExFreePoolWithTag(TmpOrderings, 'LbrA');
        OrderingList->Count = Count;
        return STATUS_SUCCESS;
    }

    if (Count > OrderingList->Maximum)
    {
        NewOrderings = ExAllocatePoolWithTag(PagedPool,
                                             Count * sizeof(ARBITER_ORDERING),
                                             'LbrA');
        if (!NewOrderings)
        {
            DPRINT("ArbPruneOrdering: STATUS_INSUFFICIENT_RESOURCES\n");
            goto ErrorExit;
        }

        if (OrderingList->Orderings)
        {
            ExFreePoolWithTag(OrderingList->Orderings, 'LbrA');
        }

        OrderingList->Orderings = NewOrderings;
        OrderingList->Maximum = Count;
    }

    RtlCopyMemory(OrderingList->Orderings,
                  TmpOrderings,
                  Count * sizeof(ARBITER_ORDERING));

    OrderingList->Count = Count;

    ExFreePoolWithTag(TmpOrderings, 'LbrA');

    return STATUS_SUCCESS;

ErrorExit:

    if (TmpOrderings)
    {
        ExFreePoolWithTag(TmpOrderings, 'LbrA');
    }

    return STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS
NTAPI
ArbInitializeOrderingList(
    _Out_ PARBITER_ORDERING_LIST OrderList)
{
    NTSTATUS Status;

    //PAGED_CODE();

    ASSERT(OrderList);

    OrderList->Orderings = ExAllocatePoolWithTag(PagedPool,
                                                 ARB_ORDERING_LIST_DEFAULT_COUNT * sizeof(ARBITER_ORDERING),
                                                 'LbrA');
    OrderList->Count = 0;

    if (OrderList->Orderings)
    {
        OrderList->Maximum = ARB_ORDERING_LIST_DEFAULT_COUNT;
        Status = STATUS_SUCCESS;
    }
    else
    {
        OrderList->Maximum = 0;
        Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    return Status;
}

VOID
NTAPI
ArbFreeOrderingList(
    _Out_ PARBITER_ORDERING_LIST OrderList)
{
    //PAGED_CODE();

    if (OrderList->Orderings)
    {
        ASSERT(OrderList->Maximum);
        ExFreePoolWithTag(OrderList->Orderings, 'LbrA');
    }

    OrderList->Count = 0;
    OrderList->Maximum = 0;
    OrderList->Orderings = NULL;
}

NTSTATUS
NTAPI
ArbpGetRegistryValue(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR SourceString,
    _Out_ PKEY_VALUE_FULL_INFORMATION * OutValueInfo)
{
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    UNICODE_STRING DestinationString;
    ULONG ResultLength;
    NTSTATUS Status;

    //PAGED_CODE();
    DPRINT("ArbpGetRegistryValue: SourceString - %S\n", SourceString);

    RtlInitUnicodeString(&DestinationString, SourceString);

    Status = ZwQueryValueKey(KeyHandle,
                             &DestinationString,
                             KeyFullInformation | KeyNodeInformation,
                             NULL,
                             0,
                             &ResultLength);

    if (Status != STATUS_BUFFER_OVERFLOW &&
        Status != STATUS_BUFFER_TOO_SMALL)
    {
        DPRINT("ArbpGetRegistryValue: Status - %X\n", Status);
        return Status;
    }

    ValueInfo = ExAllocatePoolWithTag(PagedPool, ResultLength, 'MbrA');

    if (!ValueInfo)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        DPRINT("ArbpGetRegistryValue: Status - %X\n", Status);
        return Status;
    }

    Status = ZwQueryValueKey(KeyHandle,
                             &DestinationString,
                             KeyFullInformation|KeyNodeInformation,
                             ValueInfo,
                             ResultLength,
                             &ResultLength);
    if (NT_SUCCESS(Status))
    {
        *OutValueInfo = ValueInfo;
        Status = STATUS_SUCCESS;
    }
    else
    {
        DPRINT("ArbpGetRegistryValue: Status - %X\n", Status);
        ExFreePoolWithTag(ValueInfo, 'MbrA');
    }

    return Status;
}

NTSTATUS
NTAPI
ArbBuildAssignmentOrdering(
    _Inout_ PARBITER_INSTANCE ArbInstance,
    _In_ PCWSTR OrderName,
    _In_ PCWSTR ReservedOrderName,
    _In_ PARB_TRANSLATE_ORDERING TranslateOrderingFunction)
{
    UNICODE_STRING ArbitersKeyName = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Arbiters");
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    PKEY_VALUE_FULL_INFORMATION ReservedValueInfo = NULL;
    PIO_RESOURCE_REQUIREMENTS_LIST IoResources;
    PIO_RESOURCE_DESCRIPTOR IoDescriptor;
    IO_RESOURCE_DESCRIPTOR TranslatedIoDesc;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PARBITER_ORDERING Orderings;
    HANDLE ArbitersKeyHandle = NULL;
    HANDLE OrderingKeyHandle = NULL;
    ULONGLONG MinimumAddress;
    ULONGLONG MaximumAddress;
    PWCHAR ValueName;
    PCWSTR CurrentOrderName;
    ULONG Dummy1;
    ULONG Dummy2;
    ULONG ix;
    NTSTATUS Status;

    //PAGED_CODE();
    DPRINT("ArbBuildAssignmentOrdering: ArbInstance - %p, OrderName - %S, ReservedOrderName - %S, TranslateOrderingFunction - %p\n",
           ArbInstance, OrderName, ReservedOrderName, TranslateOrderingFunction);

    KeWaitForSingleObject(ArbInstance->MutexEvent,
                          Executive,
                          KernelMode,
                          FALSE,
                          NULL);

    ArbFreeOrderingList(&ArbInstance->OrderingList);
    ArbFreeOrderingList(&ArbInstance->ReservedList);

    Status = ArbInitializeOrderingList(&ArbInstance->OrderingList);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("ArbBuildAssignmentOrdering: Status - %X\n", Status);
        goto ErrorExit;
    }

    Status = ArbInitializeOrderingList(&ArbInstance->ReservedList);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("ArbBuildAssignmentOrdering: Status - %X\n", Status);
        goto ErrorExit;
    }

    InitializeObjectAttributes(&ObjectAttributes,
                               &ArbitersKeyName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    Status = ZwOpenKey(&ArbitersKeyHandle, KEY_READ, &ObjectAttributes);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("ArbBuildAssignmentOrdering: Status - %X\n", Status);
        goto ErrorExit;
    }

    // 0 - AllocationOrder, 1 - ReservedResources

    for (ix = 0; ix <= 1; ix++)
    {
        ValueInfo = NULL;

        if (ix == 0)
        {
            CurrentOrderName = OrderName;
            RtlInitUnicodeString(&ArbitersKeyName, L"AllocationOrder");
        }
        else
        {
            CurrentOrderName = ReservedOrderName;
            RtlInitUnicodeString(&ArbitersKeyName, L"ReservedResources");
        }

        InitializeObjectAttributes(&ObjectAttributes,
                                   &ArbitersKeyName,
                                   OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                   ArbitersKeyHandle,
                                   NULL);
        if (ix == 0)
        {
            Status = ZwOpenKey(&OrderingKeyHandle,
                               KEY_READ,
                               &ObjectAttributes);
        }
        else
        {
            Status = ZwCreateKey(&OrderingKeyHandle,
                                 KEY_READ,
                                 &ObjectAttributes,
                                 0,
                                 NULL,
                                 REG_OPTION_NON_VOLATILE,
                                 NULL);
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT("ArbBuildAssignmentOrdering: Status - %X\n", Status);
            goto ErrorExit;
        }

        Status = ArbpGetRegistryValue(OrderingKeyHandle,
                                      CurrentOrderName,
                                      &ValueInfo);

        if (!NT_SUCCESS(Status) || !ValueInfo)
        {
            DPRINT("ArbBuildAssignmentOrdering: Status - %X\n", Status);
            goto ErrorExit;
        }

        if (ix == 1 && ValueInfo->Type == REG_SZ)
        {
            // for "ReservedResources" key

            ValueName = (PWCHAR)((ULONG_PTR)ValueInfo + ValueInfo->DataOffset);
            DPRINT("ArbBuildAssignmentOrdering: ValueName - %S\n", ValueName);

            if (ValueName[(ValueInfo->DataLength / sizeof(WCHAR)) - 1])
            {
                DPRINT("ArbBuildAssignmentOrdering: ErrorExit\n");
                goto ErrorExit;
            }

            Status = ArbpGetRegistryValue(OrderingKeyHandle,
                                          ValueName,
                                          &ReservedValueInfo);
            if (!NT_SUCCESS(Status))
            {
                DPRINT("ArbBuildAssignmentOrdering: Status - %X\n", Status);
                goto ErrorExit;
            }

            ExFreePoolWithTag(ValueInfo, 'MbrA');
            ValueInfo = ReservedValueInfo;
        }

        ZwClose(OrderingKeyHandle);

        if (ValueInfo->Type != REG_RESOURCE_REQUIREMENTS_LIST)
        {
            DPRINT("ArbBuildAssignmentOrdering: Status - %X\n", Status);
            Status = STATUS_INVALID_PARAMETER;
            goto ErrorExit;
        }

        IoResources = (PIO_RESOURCE_REQUIREMENTS_LIST)
                      ((ULONG_PTR)ValueInfo + ValueInfo->DataOffset);

        ASSERT(IoResources->AlternativeLists == 1);
        IopDumpResourceRequirementsList(IoResources);

        for (IoDescriptor = &IoResources->List[0].Descriptors[0];
             IoDescriptor < &IoResources->List[0].Descriptors[0] + IoResources->List[0].Count;
             IoDescriptor++)
        {
            if (TranslateOrderingFunction)
            {
                Status = TranslateOrderingFunction(&TranslatedIoDesc,
                                                   IoDescriptor);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT("ArbBuildAssignmentOrdering: Status - %X\n", Status);
                    goto ErrorExit;
                }
            }
            else
            {
                RtlCopyMemory(&TranslatedIoDesc,
                              IoDescriptor,
                              sizeof(TranslatedIoDesc));
            }

            if (TranslatedIoDesc.Type == ArbInstance->ResourceType)
            {
                Status = ArbInstance->UnpackRequirement(&TranslatedIoDesc,
                                                        &MinimumAddress,
                                                        &MaximumAddress,
                                                        &Dummy1,
                                                        &Dummy2);
                if (!NT_SUCCESS(Status))
                {
                    DPRINT("ArbBuildAssignmentOrdering: Status - %X\n", Status);
                    goto ErrorExit;
                }

                if (ix == 0)
                {
                    Status = ArbAddOrdering(&ArbInstance->OrderingList,
                                            MinimumAddress,
                                            MaximumAddress);

                    if (!NT_SUCCESS(Status))
                    {
                        DPRINT("ArbBuildAssignmentOrdering: Status - %X\n", Status);
                        goto ErrorExit;
                    }
                }
                else
                {
                    Status = ArbAddOrdering(&ArbInstance->ReservedList,
                                            MinimumAddress,
                                            MaximumAddress);

                    if (!NT_SUCCESS(Status))
                    {
                        DPRINT("ArbBuildAssignmentOrdering: Status - %X\n", Status);
                        goto ErrorExit;
                    }

                    Status = ArbPruneOrdering(&ArbInstance->OrderingList,
                                              MinimumAddress,
                                              MaximumAddress);

                    if (!NT_SUCCESS(Status))
                    {
                        DPRINT("ArbBuildAssignmentOrdering: Status - %X\n", Status);
                        goto ErrorExit;
                    }
                }
            }
        }
    }

    ZwClose(ArbitersKeyHandle);

    Orderings = ArbInstance->OrderingList.Orderings;

    for (Orderings = &ArbInstance->OrderingList.Orderings[0];
         Orderings < &ArbInstance->OrderingList.Orderings[ArbInstance->OrderingList.Count];
         Orderings++)
    {
        DPRINT("ArbBuildAssignmentOrdering: OrderingList(%I64X - %I64X)\n",
               Orderings->Start, Orderings->End);
    }

    Orderings = ArbInstance->ReservedList.Orderings;

    for (Orderings = &ArbInstance->ReservedList.Orderings[0];
         Orderings < &ArbInstance->ReservedList.Orderings[ArbInstance->ReservedList.Count];
         Orderings++)
    {
        DPRINT("ArbBuildAssignmentOrdering: ReservedList(%I64X - %I64X)\n",
               Orderings->Start, Orderings->End);
    }

    KeSetEvent(ArbInstance->MutexEvent, IO_NO_INCREMENT, FALSE);

    return STATUS_SUCCESS;

ErrorExit:

    DPRINT("ArbBuildAssignmentOrdering: ErrorExit. Status - %X\n", Status);
    ASSERT(FALSE);

    if (ArbitersKeyHandle)
    {
        ZwClose(ArbitersKeyHandle);
    }

    if (OrderingKeyHandle)
    {
        ZwClose(OrderingKeyHandle);
    }

    if (ValueInfo)
    {
        ExFreePoolWithTag(ValueInfo, 'MbrA');
    }

    if (ReservedValueInfo)
    {
        ExFreePoolWithTag(ReservedValueInfo, 'MbrA');
    }

    if (ArbInstance->OrderingList.Orderings)
    {
        ExFreePoolWithTag(ArbInstance->OrderingList.Orderings, 'LbrA');
        ArbInstance->OrderingList.Count = 0;
        ArbInstance->OrderingList.Maximum = 0;
    }

    if (ArbInstance->ReservedList.Orderings)
    {
        ExFreePoolWithTag(ArbInstance->ReservedList.Orderings, 'LbrA');
        ArbInstance->ReservedList.Count = 0;
        ArbInstance->ReservedList.Maximum = 0;
    }

    KeSetEvent(ArbInstance->MutexEvent, IO_NO_INCREMENT, FALSE);

    return Status;
}

NTSTATUS
NTAPI
ArbInitializeArbiterInstance(
    _Inout_ PARBITER_INSTANCE Arbiter,
    _In_ PDEVICE_OBJECT BusDeviceObject,
    _In_ CM_RESOURCE_TYPE ResourceType,
    _In_ PWSTR ArbiterName,
    _In_ PCWSTR OrderName,
    _In_ PARB_TRANSLATE_ORDERING TranslateOrderingFunction)
{
    NTSTATUS Status;

    //PAGED_CODE();
    DPRINT("ArbInitializeArbiterInstance: Initializing %S Arbiter\n", ArbiterName);

    ASSERT(Arbiter->UnpackRequirement);
    ASSERT(Arbiter->PackResource);
    ASSERT(Arbiter->UnpackResource);
    ASSERT(Arbiter->MutexEvent == NULL &&
           Arbiter->Allocation == NULL &&
           Arbiter->PossibleAllocation == NULL &&
           Arbiter->AllocationStack == NULL);

    Arbiter->Signature = 'sbrA';
    Arbiter->BusDeviceObject = BusDeviceObject;

    Arbiter->MutexEvent = ExAllocatePoolWithTag(NonPagedPool,
                                                sizeof(KEVENT),
                                                'MbrA');
    if (Arbiter->MutexEvent == NULL)
    {
        ASSERT(FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeEvent(Arbiter->MutexEvent, SynchronizationEvent, TRUE);

    Arbiter->AllocationStack = ExAllocatePoolWithTag(PagedPool,
                                                     PAGE_SIZE,
                                                     'AbrA');
    if (!Arbiter->AllocationStack)
    {
        ASSERT(FALSE);
        ExFreePoolWithTag(Arbiter->MutexEvent, 'MbrA');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Arbiter->AllocationStackMaxSize = PAGE_SIZE;

    Arbiter->Allocation = ExAllocatePoolWithTag(PagedPool,
                                                sizeof(RTL_RANGE_LIST),
                                                'RbrA');
    if (!Arbiter->Allocation)
    {
        ASSERT(FALSE);
        ExFreePoolWithTag(Arbiter->AllocationStack, 'AbrA');
        ExFreePoolWithTag(Arbiter->MutexEvent, 'MbrA');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Arbiter->PossibleAllocation = ExAllocatePoolWithTag(PagedPool,
                                                        sizeof(RTL_RANGE_LIST),
                                                        'RbrA');
    if (!Arbiter->PossibleAllocation)
    {
        ASSERT(FALSE);
        ExFreePoolWithTag(Arbiter->Allocation, 'RbrA');
        ExFreePoolWithTag(Arbiter->AllocationStack, 'AbrA');
        ExFreePoolWithTag(Arbiter->MutexEvent, 'MbrA');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitializeRangeList(Arbiter->Allocation);
    RtlInitializeRangeList(Arbiter->PossibleAllocation);


    Arbiter->Name = ArbiterName;
    Arbiter->ResourceType = ResourceType;
    Arbiter->TransactionInProgress = FALSE;

    if (!Arbiter->TestAllocation)
        Arbiter->TestAllocation = ArbTestAllocation;
    if (!Arbiter->RetestAllocation)
        Arbiter->RetestAllocation = ArbRetestAllocation;
    if (!Arbiter->CommitAllocation)
        Arbiter->CommitAllocation = ArbCommitAllocation;
    if (!Arbiter->RollbackAllocation)
        Arbiter->RollbackAllocation = ArbRollbackAllocation;
    if (!Arbiter->AddReserved)
        Arbiter->AddReserved = ArbAddReserved;
    if (!Arbiter->PreprocessEntry)
        Arbiter->PreprocessEntry = ArbPreprocessEntry;
    if (!Arbiter->AllocateEntry)
        Arbiter->AllocateEntry = ArbAllocateEntry;
    if (!Arbiter->GetNextAllocationRange)
        Arbiter->GetNextAllocationRange = ArbGetNextAllocationRange;
    if (!Arbiter->FindSuitableRange)
        Arbiter->FindSuitableRange = ArbFindSuitableRange;
    if (!Arbiter->AddAllocation)
        Arbiter->AddAllocation = ArbAddAllocation;
    if (!Arbiter->BacktrackAllocation)
        Arbiter->BacktrackAllocation = ArbBacktrackAllocation;
    if (!Arbiter->OverrideConflict)
        Arbiter->OverrideConflict = ArbOverrideConflict;
    if (!Arbiter->BootAllocation)
        Arbiter->BootAllocation = ArbBootAllocation;
    if (!Arbiter->QueryConflict)
        Arbiter->QueryConflict = ArbQueryConflict;
    if (!Arbiter->StartArbiter)
        Arbiter->StartArbiter = ArbStartArbiter;

    Status = ArbBuildAssignmentOrdering(Arbiter,
                                        OrderName,
                                        OrderName,
                                        TranslateOrderingFunction);

    if (NT_SUCCESS(Status))
    {
        return STATUS_SUCCESS;
    }

    ASSERT(FALSE);

    if (Arbiter->MutexEvent)
    {
        ExFreePoolWithTag(Arbiter->MutexEvent, 'MbrA');
    }

    if (Arbiter->Allocation)
    {
        ExFreePoolWithTag(Arbiter->Allocation, 'RbrA');
    }

    if (Arbiter->PossibleAllocation)
    {
        ExFreePoolWithTag(Arbiter->PossibleAllocation, 'RbrA');
    }

    if (Arbiter->AllocationStack)
    {
        ExFreePoolWithTag(Arbiter->AllocationStack, 'AbrA');
    }

    return Status;
}

/* EOF */
