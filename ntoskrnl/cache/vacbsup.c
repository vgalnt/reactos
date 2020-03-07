/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Kernel
 * FILE:            ntoskrnl/cache/vacbsup.c
 * PURPOSE:         Virtual Address Command Block (VACB) support
 * PROGRAMMERS:     
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "newcc.h"
#include "section/newmm.h"
//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

#define CC_DEFAULT_NUMBER_OF_VACBS 4

PVACB CcVacbs;
PVACB CcBeyondVacbs;
LIST_ENTRY CcVacbLru;
LIST_ENTRY CcVacbFreeList;

ULONG CcMaxVacbLevelsSeen = 1;

/* STRUCTURES *****************************************************************/

/* PRIVATE FUNCTIONS **********************************************************/

VOID
NTAPI
CcInitializeVacbs()
{
    PVACB CurrentVacb;
    ULONG CcNumberVacbs;
    ULONG SizeOfVacbs;

    CcNumberVacbs = (MmSizeOfSystemCacheInPages / 64) - 2;
    SizeOfVacbs = CcNumberVacbs * sizeof(VACB);

    DPRINT("CcInitializeVacbs: MmSizeOfSystemCacheInPages %X, CcNumberVacbs %X\n", MmSizeOfSystemCacheInPages, CcNumberVacbs);

    CcVacbs = ExAllocatePoolWithTag(NonPagedPool, SizeOfVacbs, 'aVcC');
    if (!CcVacbs)
    {
        DPRINT1("CcInitializeVacbs: allocate VACBs failed\n");
        return;
    }

    RtlZeroMemory(CcVacbs, SizeOfVacbs);

    CcBeyondVacbs = &CcVacbs[CcNumberVacbs];

    InitializeListHead(&CcVacbLru);
    InitializeListHead(&CcVacbFreeList);

    for (CurrentVacb = CcVacbs; CurrentVacb < CcBeyondVacbs; CurrentVacb++)
    {
        InsertTailList(&CcVacbFreeList, &CurrentVacb->LruList);
    }
}

NTSTATUS
NTAPI
CcCreateVacbArray(IN PSHARED_CACHE_MAP SharedCacheMap,
                  IN LARGE_INTEGER AllocationSize)
{
    PVACB * NewVacbs;
    ULONG SizeOfNewVacbs;

    DPRINT("CcCreateVacbArray: SharedCacheMap %p AllocationSize %I64X\n", SharedCacheMap, AllocationSize.QuadPart);

    if ((ULONGLONG)AllocationSize.QuadPart >= (4ull * _1GB))
    {
        SizeOfNewVacbs = 0xFFFFFFFF;
        DPRINT("CcCreateVacbArray: SizeOfNewVacbs %X\n", SizeOfNewVacbs);
    }
    else if (AllocationSize.LowPart <= (VACB_MAPPING_GRANULARITY * sizeof(PVACB)))
    {
        SizeOfNewVacbs = CC_DEFAULT_NUMBER_OF_VACBS * sizeof(PVACB);
        DPRINT("CcCreateVacbArray: SizeOfNewVacbs %X\n", SizeOfNewVacbs);
    }
    else
    {
        SizeOfNewVacbs = (AllocationSize.LowPart / VACB_MAPPING_GRANULARITY) * sizeof(PVACB);
        DPRINT("CcCreateVacbArray: SizeOfNewVacbs %X\n", SizeOfNewVacbs);
    }

    if ((ULONGLONG)AllocationSize.QuadPart >= (16 * _1TB))
    {
        DPRINT1("CcCreateVacbArray: STATUS_SECTION_TOO_BIG\n");
        return STATUS_SECTION_TOO_BIG;
    }

    if (SizeOfNewVacbs == CC_DEFAULT_NUMBER_OF_VACBS * sizeof(PVACB))
    {
        NewVacbs = SharedCacheMap->InitialVacbs;
    }
    else
    {
        DPRINT1("CcCreateVacbArray: FIXME! SizeOfNewVacbs %X\n", SizeOfNewVacbs);
        ASSERT(FALSE);
    }

    RtlZeroMemory(NewVacbs, SizeOfNewVacbs);

    SharedCacheMap->SectionSize.QuadPart = AllocationSize.QuadPart;
    SharedCacheMap->Vacbs = NewVacbs;

    return STATUS_SUCCESS;
}

PVOID
NTAPI
CcGetVirtualAddress(IN PSHARED_CACHE_MAP SharedCacheMap,
                    IN LARGE_INTEGER FileOffset,
                    OUT PVACB * OutVacb,
                    OUT ULONG * OutReceivedLength)
{
    PVACB TempVacb;
    KLOCK_QUEUE_HANDLE LockHandle;
    ULONG VacbOffset;
    BOOLEAN IsMmodifiedNoWrite = FALSE;

    DPRINT("CcGetVirtualAddress: SharedCacheMap %p, Offset %I64X\n", SharedCacheMap, FileOffset.QuadPart);

    /* Calculate the offset in VACB */
    VacbOffset = FileOffset.LowPart & (VACB_MAPPING_GRANULARITY - 1);

    /* Lock */
    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
    ExAcquirePushLockShared((PEX_PUSH_LOCK)&SharedCacheMap->VacbPushLock);

    if (SharedCacheMap->Flags & SHARE_FL_MODIFIED_NO_WRITE)
    {
        IsMmodifiedNoWrite = TRUE;
        KeAcquireInStackQueuedSpinLock(&SharedCacheMap->BcbSpinLock, &LockHandle);
        KeAcquireQueuedSpinLockAtDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
    }
    else
    {
        LockHandle.OldIrql = KeAcquireQueuedSpinLock(LockQueueVacbLock);
    }

    ASSERT(FileOffset.QuadPart <= SharedCacheMap->SectionSize.QuadPart);

    /* Get pointer to Vacb */
    if (SharedCacheMap->SectionSize.QuadPart <= CACHE_OVERALL_SIZE)
    {
        /* Size of file < 32 MB*/
        TempVacb = SharedCacheMap->Vacbs[FileOffset.LowPart / VACB_MAPPING_GRANULARITY];
    }
    else
    {
        /* This file is large (more than 32 MB) */
        DPRINT1("CcGetVirtualAddress: FIXME CcGetVacbLargeOffset\n");
        ASSERT(FALSE);
        TempVacb = 0;
    }

    if (TempVacb)
    {
        /* Increment counters */
        if (!TempVacb->Overlay.ActiveCount)
        {
            SharedCacheMap->VacbActiveCount++;
        }

        TempVacb->Overlay.ActiveCount++;
    }
    else
    {
        /* Vacb not found */
        DPRINT1("CcGetVirtualAddress: FIXME CcGetVacbMiss\n");
        ASSERT(FALSE);
        TempVacb = 0;
    }

    /* Updating lists */
    RemoveEntryList(&TempVacb->LruList);
    InsertTailList(&CcVacbLru, &TempVacb->LruList);

    /* Unlock */
    if (IsMmodifiedNoWrite == FALSE)
    {
        KeReleaseQueuedSpinLock(LockQueueVacbLock, LockHandle.OldIrql);
    }
    else
    {
        KeReleaseQueuedSpinLockFromDpcLevel(&KeGetCurrentPrcb()->LockQueue[LockQueueVacbLock]);
        KeReleaseInStackQueuedSpinLock(&LockHandle);
    }

    ExReleasePushLockShared((PEX_PUSH_LOCK)&SharedCacheMap->VacbPushLock);

    *OutVacb = TempVacb;
    *OutReceivedLength = VACB_MAPPING_GRANULARITY - VacbOffset;

    ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
    ASSERT(TempVacb->BaseAddress != NULL);

    /* Add an offset to the base and return the virtual address */
    return (PVOID)((ULONG_PTR)TempVacb->BaseAddress + VacbOffset);
}

/* EOF */
