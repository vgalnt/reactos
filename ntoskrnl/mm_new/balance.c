
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
//#define NDEBUG
#include <debug.h>
#include "ARM3/miarm.h"

/* TYPES ********************************************************************/

typedef struct _MM_ALLOCATION_REQUEST
{
    PFN_NUMBER Page;
    LIST_ENTRY ListEntry;
    KEVENT Event;
} MM_ALLOCATION_REQUEST, *PMM_ALLOCATION_REQUEST;

/* GLOBALS ********************************************************************/

MM_MEMORY_CONSUMER MiMemoryConsumers[MC_MAXIMUM];

static ULONG MiMinimumAvailablePages;
static ULONG MiNrTotalPages;
static LIST_ENTRY AllocationListHead;
static KSPIN_LOCK AllocationListLock;
static ULONG MiMinimumPagesPerRun;

static CLIENT_ID MiBalancerThreadId;
static HANDLE MiBalancerThreadHandle = NULL;
static KEVENT MiBalancerEvent;
static KTIMER MiBalancerTimer;

/* FUNCTIONS ******************************************************************/

//INIT_FUNCTION
VOID
NTAPI
MmInitializeBalancer(
    ULONG NrAvailablePages,
    ULONG NrSystemPages)
{
    memset(MiMemoryConsumers, 0, sizeof(MiMemoryConsumers));

    InitializeListHead(&AllocationListHead);
    KeInitializeSpinLock(&AllocationListLock);

    MiNrTotalPages = NrAvailablePages;

    /* Set up targets. */
    MiMinimumAvailablePages = 0x100;
    MiMinimumPagesPerRun = 0x100;

    if ((NrAvailablePages + NrSystemPages) >= 0x2000)
    {
        MiMemoryConsumers[MC_CACHE].PagesTarget = (NrAvailablePages / 4 * 3);
    }
    else if ((NrAvailablePages + NrSystemPages) >= 0x1000)
    {
        MiMemoryConsumers[MC_CACHE].PagesTarget = (NrAvailablePages / 3 * 2);
    }
    else
    {
        MiMemoryConsumers[MC_CACHE].PagesTarget = (NrAvailablePages / 8);
    }

    MiMemoryConsumers[MC_USER].PagesTarget = (NrAvailablePages - MiMinimumAvailablePages);
}

//INIT_FUNCTION
VOID
NTAPI
MmInitializeMemoryConsumer(
    ULONG Consumer,
    PMM_MEMORY_CONSUMER_TRIM Trim)
{
    MiMemoryConsumers[Consumer].Trim = Trim;
}

BOOLEAN
MmRosNotifyAvailablePage(
    PFN_NUMBER Page)
{
    PLIST_ENTRY Entry;
    //PMM_ALLOCATION_REQUEST Request;
    //PMMPFN Pfn;

    /* Make sure the PFN lock is held */
    MI_ASSERT_PFN_LOCK_HELD();

    if (!MiMinimumAvailablePages)
    {
        /* Dirty way to know if we were initialized. */
        return FALSE;
    }

    Entry = ExInterlockedRemoveHeadList(&AllocationListHead, &AllocationListLock);
    if (!Entry)
        return FALSE;

    DPRINT1("MmRosNotifyAvailablePage: FIXME!\n");
    ASSERT(FALSE);
#if 0
    Request = CONTAINING_RECORD(Entry, MM_ALLOCATION_REQUEST, ListEntry);

    MiZeroPhysicalPage(Page);
    Request->Page = Page;

    Pfn = MiGetPfnEntry(Page);
    ASSERT(Pfn->u3.e2.ReferenceCount == 0);
    Pfn->u3.e2.ReferenceCount = 1;
    Pfn->u3.e1.PageLocation = ActiveAndValid;

    /* This marks the PFN as a ReactOS PFN */
    Pfn->u4.AweAllocation = TRUE;

    /* Allocate the extra ReactOS Data and zero it out */
    Pfn->u1.SwapEntry = 0;
    Pfn->RmapListHead = NULL;

    KeSetEvent(&Request->Event, IO_NO_INCREMENT, FALSE);
#endif
    return TRUE;
}

VOID
NTAPI
MmRebalanceMemoryConsumers(VOID)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
MmTrimUserMemory(
    ULONG Target,
    ULONG Priority,
    PULONG NrFreedPages)
{
    PFN_NUMBER CurrentPage;
    PFN_NUMBER NextPage;
    NTSTATUS Status;

    (*NrFreedPages) = 0;

    CurrentPage = MmGetLRUFirstUserPage();

    while (CurrentPage && Target > 0)
    {
        ASSERT(FALSE);
        Status = 0;//MmPageOutPhysicalAddress(CurrentPage);
        if (NT_SUCCESS(Status))
        {
            DPRINT("Succeeded\n");
            Target--;
            (*NrFreedPages)++;
        }

        NextPage = MmGetLRUNextUserPage(CurrentPage);
        if (NextPage <= CurrentPage)
            /* We wrapped around, so we're done */
            break;

        CurrentPage = NextPage;
    }

    return STATUS_SUCCESS;
}

//INIT_FUNCTION
VOID
NTAPI
MiInitBalancerThread(VOID)
{
    LARGE_INTEGER DueTime;
    KPRIORITY Priority;
    NTSTATUS Status;

    DueTime.QuadPart = (-10000 * 2000); /* 2 sec */

    KeInitializeEvent(&MiBalancerEvent, SynchronizationEvent, FALSE);
    KeInitializeTimerEx(&MiBalancerTimer, SynchronizationTimer);

    KeSetTimerEx(&MiBalancerTimer, DueTime, 2000, NULL);

    Status = PsCreateSystemThread(&MiBalancerThreadHandle,
                                  THREAD_ALL_ACCESS,
                                  NULL,
                                  NULL,
                                  &MiBalancerThreadId,
                                  MiBalancerThread,
                                  NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MiInitBalancerThread: Status %X\n", Status);
        KeBugCheck(MEMORY_MANAGEMENT);
    }

    Priority = (LOW_REALTIME_PRIORITY + 1);

    NtSetInformationThread(MiBalancerThreadHandle, ThreadPriority, &Priority, sizeof(Priority));
}

ULONG
NTAPI
MiTrimMemoryConsumer(
    ULONG Consumer,
    ULONG InitialTarget)
{
    ULONG Target = InitialTarget;
    ULONG NrFreedPages = 0;
    NTSTATUS Status;

    /* Make sure we can trim this consumer */
    if (!MiMemoryConsumers[Consumer].Trim)
        /* Return the unmodified initial target */
        return InitialTarget;

    if (MiMemoryConsumers[Consumer].PagesUsed > MiMemoryConsumers[Consumer].PagesTarget)
        /* Consumer page limit exceeded */
        Target = max(Target, (MiMemoryConsumers[Consumer].PagesUsed - MiMemoryConsumers[Consumer].PagesTarget));

    if (MmAvailablePages < MiMinimumAvailablePages)
        /* Global page limit exceeded */
        Target = (ULONG)max(Target, (MiMinimumAvailablePages - MmAvailablePages));

    if (!Target)
    {
        /* Initial target is zero and we don't have anything else to add */
        return 0;
    }

    if (!InitialTarget)
        /* If there was no initial target, swap at least MiMinimumPagesPerRun */
        Target = max(Target, MiMinimumPagesPerRun);

    /* Now swap the pages out */
    Status = MiMemoryConsumers[Consumer].Trim(Target, 0, &NrFreedPages);

    DPRINT("Trimming consumer %lu: Freed %lu pages with a target of %lu pages\n", Consumer, NrFreedPages, Target);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("MiTrimMemoryConsumer: Status %X\n", Status);
        KeBugCheck(MEMORY_MANAGEMENT);
    }

    /* Update the target */
    if (NrFreedPages < Target)
        Target -= NrFreedPages;
    else
        Target = 0;

    /* Return the remaining pages needed to meet the target */
    return Target;
}

static
BOOLEAN
MiIsBalancerThread(VOID)
{
    return (MiBalancerThreadHandle != NULL) && (PsGetCurrentThreadId() == MiBalancerThreadId.UniqueThread);
}

VOID
NTAPI
MiBalancerThread(
    PVOID Unused)
{
    PVOID WaitObjects[2];
    ULONG InitialTarget = 0;
    ULONG ix;
    NTSTATUS Status;

    WaitObjects[0] = &MiBalancerEvent;
    WaitObjects[1] = &MiBalancerTimer;

    while (TRUE)
    {
        Status = KeWaitForMultipleObjects(2, WaitObjects, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);

        if (Status != STATUS_WAIT_0 && Status != STATUS_WAIT_1)
        {
            DPRINT1("MiBalancerThread: Status %X\n", Status);
            KeBugCheck(MEMORY_MANAGEMENT);
            return;
        }

      #if (_MI_PAGING_LEVELS == 2)
        if (!MiIsBalancerThread())
        {
            KIRQL OldIrql = MiLockPfnDb(APC_LEVEL); /* Acquire PFN lock */
            //PEPROCESS Process = PsGetCurrentProcess();
            ULONG_PTR Address;
            PMMPDE pointerPde;

            /* Clean up the unused PDEs */
            for (Address = (ULONG_PTR)MI_LOWEST_VAD_ADDRESS;
                 Address < (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS;
                 Address += (PTE_PER_PAGE * PAGE_SIZE))
            {
                if (MiQueryPageTableReferences((PVOID)Address))
                    continue;

                pointerPde = MiAddressToPde(Address);
                if (pointerPde->u.Hard.Valid)
                {
                    DPRINT1("MiBalancerThread: FIXME! pointerPde %p\n", pointerPde);
                    ASSERT(FALSE);
                    //MiDeletePte(..);
                }

                ASSERT(pointerPde->u.Hard.Valid == 0);
            }

            /* Release lock */
            MiUnlockPfnDb(OldIrql, APC_LEVEL);
        }
      #endif

        do
        {
            ULONG OldTarget = InitialTarget;

            /* Trim each consumer */
            for (ix = 0; ix < MC_MAXIMUM; ix++)
                InitialTarget = MiTrimMemoryConsumer(ix, InitialTarget);

            /* No pages left to swap! */
            if (InitialTarget && InitialTarget == OldTarget)
            {
                /* Game over */
                DPRINT1("MiBalancerThread: InitialTarget %X\n", InitialTarget);
                KeBugCheck(NO_PAGES_AVAILABLE);
            }
        }
        while (InitialTarget != 0);
    }
}

/* EOF */
