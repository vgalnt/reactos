/*
 * PROJECT:         ReactOS Kernel
 * COPYRIGHT:       GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/arbiter/arbiter.c
 * PURPOSE:         Arbiter of hardware resources library
 * PROGRAMMERS:     
 */

/* INCLUDES *******************************************************************/

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

/* FUNCTIONS ******************************************************************/

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
ArbBootAllocation()
{
    DPRINT("ArbBootAllocation: ...\n");
    ASSERT(FALSE);
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
ArbBuildAssignmentOrdering(
    _Inout_ PARBITER_INSTANCE ArbInstance,
    _In_ PCWSTR OrderName,
    _In_ PCWSTR ReservedOrderName,
    _In_ PARB_TRANSLATE_ORDERING TranslateOrderingFunction)
{
    //PAGED_CODE();
    DPRINT("ArbBuildAssignmentOrdering: ArbInstance - %p, OrderName - %S, ReservedOrderName - %S, TranslateOrderingFunction - %p\n",
           ArbInstance, OrderName, ReservedOrderName, TranslateOrderingFunction);

    ASSERT(FALSE);
    return 0;
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
