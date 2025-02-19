
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "ARM3/miarm.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

#define ASSERT_IS_ROS_PFN(x)  ASSERT(MI_IS_ROS_PFN(x) == TRUE);

PMMPFN MmPfnDatabase;

PFN_NUMBER MmAvailablePages;
PFN_NUMBER MmResidentAvailablePages;
PFN_NUMBER MmResidentAvailableAtInit;

SIZE_T MmTotalCommittedPages;
SIZE_T MmSharedCommit;
SIZE_T MmDriverCommit;
SIZE_T MmProcessCommit;
SIZE_T MmPagedPoolCommit;
SIZE_T MmPeakCommitment;
SIZE_T MmtotalCommitLimitMaximum;

extern SIZE_T MmSystemCommitReserve;
extern SIZE_T MmTotalCommitLimitMaximum;

static RTL_BITMAP MiUserPfnBitMap;

/* FUNCTIONS ******************************************************************/

#ifdef ALLOC_PRAGMA
  #pragma alloc_text(INIT, MiInitializeUserPfnBitmap)
  #pragma alloc_text(INIT, MmGetLRUFirstUserPage)
  #pragma alloc_text(INIT, MmGetLRUNextUserPage)
#endif

CODE_SEG("INIT")
VOID
NTAPI
MiInitializeUserPfnBitmap(VOID)
{
    PVOID Bitmap;
    ULONG Size;

    /* Allocate enough buffer for the PFN bitmap and align it on 32-bits */
    Size = ((((MmHighestPhysicalPage + 1) + 0x1F) / 0x20) * 4);

    Bitmap = ExAllocatePoolWithTag(NonPagedPool, Size, TAG_MM);
    if (!Bitmap)
    {
        DPRINT1("MiInitializeUserPfnBitmap: Allocate failed\n");
        ASSERT(Bitmap);
    }

    /* Initialize it and clear all the bits to begin with */
    RtlInitializeBitMap(&MiUserPfnBitMap, Bitmap, ((ULONG)MmHighestPhysicalPage + 1));
    RtlClearAllBits(&MiUserPfnBitMap);
}

CODE_SEG("INIT")
PFN_NUMBER
NTAPI
MmGetLRUFirstUserPage(VOID)
{
    ULONG Position;
    KIRQL OldIrql;

    /* Find the first user page */
    OldIrql = MiLockPfnDb(APC_LEVEL);
    Position = RtlFindSetBits(&MiUserPfnBitMap, 1, 0);
    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    if (Position == 0xFFFFFFFF)
        return 0;

    /* Return it */
    ASSERT(Position != 0);
    ASSERT_IS_ROS_PFN(MiGetPfnEntry(Position));

    return Position;
}

CODE_SEG("INIT")
PFN_NUMBER
NTAPI
MmGetLRUNextUserPage(
    PFN_NUMBER PreviousPfn)
{
    ULONG Position;
    KIRQL OldIrql;

    /* Find the next user page */
    OldIrql = MiLockPfnDb(APC_LEVEL);
    Position = RtlFindSetBits(&MiUserPfnBitMap, 1, ((ULONG)PreviousPfn + 1));
    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    if (Position == 0xFFFFFFFF)
        return 0;

    /* Return it */
    ASSERT(Position != 0);
    ASSERT_IS_ROS_PFN(MiGetPfnEntry(Position));

    return Position;
}

BOOLEAN
NTAPI
MiIsPfnFree(
    _In_ PMMPFN Pfn)
{
    /* Must be a free or zero page, with no references, linked */
    return ((Pfn->u3.e1.PageLocation <= StandbyPageList) &&
            (Pfn->u1.Flink) &&
            (Pfn->u2.Blink) &&
            !(Pfn->u3.e2.ReferenceCount));
}

BOOLEAN
NTAPI
MiIsPfnInUse(
    _In_ PMMPFN Pfn)
{
    /* Standby list or higher, unlinked, and with references */
    return !MiIsPfnFree(Pfn);
}

BOOLEAN
NTAPI
MiChargeCommitment(
    _In_ SIZE_T QuotaCharge,
    _In_ PEPROCESS Process)
{
    SIZE_T OldMmTotalCommittedPages;
    ULONG ix;

    DPRINT("MiChargeCommitment: Process %p, QuotaCharge %IX\n", Process, QuotaCharge);

    ASSERT((SSIZE_T)QuotaCharge > 0);

    if (ExpInitializationPhase > 1)
    {
        for (ix = 0; ix < KeNumberProcessors; ix++)
        {
            ASSERT(KiProcessorBlock[ix]->IdleThread != &(PsGetCurrentThread()->Tcb));
        }
    }

    while (TRUE)
    {
        OldMmTotalCommittedPages = MmTotalCommittedPages;

        if ((MmTotalCommittedPages + QuotaCharge) <= (MmTotalCommitLimit - MmSystemCommitReserve))
            goto Compare;

        if ((MmTotalCommitLimitMaximum - MmTotalCommitLimit) <= 100)
        {
            DPRINT1("MiChargeCommitment: FIXME MiTrimSegmentCache()\n");
            ASSERT(FALSE);

            if (MmTotalCommitLimit >= MmTotalCommitLimitMaximum)
            {
                DPRINT1("MiChargeCommitment: FIXME MiCauseOverCommitPopup()\n");
                ASSERT(FALSE);
                return FALSE;
            }
        }

        DPRINT1("MiChargeCommitment: %IX, %IX, %IX\n", MmTotalCommittedPages, MmTotalCommitLimit, MmSystemCommitReserve);
        DPRINT1("MiChargeCommitment: FIXME MiIssuePageExtendRequest()\n");
        ASSERT(FALSE);

Compare:
        if (OldMmTotalCommittedPages == InterlockedCompareExchange((PLONG)&MmTotalCommittedPages,
                                                                   (MmTotalCommittedPages + QuotaCharge),
                                                                   MmTotalCommittedPages))
        {
            break;
        }
    }

    if (MmPeakCommitment < MmTotalCommittedPages)
        MmPeakCommitment = MmTotalCommittedPages;

    if (MmTotalCommittedPages <= ((MmTotalCommitLimit / 10) * 9))
        return TRUE;

    DPRINT1("MiChargeCommitment: %IX, %IX\n", MmTotalCommittedPages, MmTotalCommitLimit);

    if (MmTotalCommitLimit < MmTotalCommitLimitMaximum)
    {
        DPRINT1("MiChargeCommitment: FIXME MiIssuePageExtendRequestNoWait()\n");
        ASSERT(FALSE);
    }
    else if (MmTotalCommitLimit >= (MmTotalCommitLimitMaximum - 100))
    {
        DPRINT1("MiChargeCommitment: FIXME MiTrimSegmentCache()\n");
        ASSERT(FALSE);
    }

    return TRUE;
}

BOOLEAN
NTAPI
MiChargeCommitmentCantExpand(
    _In_ SIZE_T QuotaCharge,
    _In_ BOOLEAN IsParam2)
{
    SIZE_T OldMmTotalCommittedPages;
    SIZE_T ExtendQuota;

    DPRINT("MiChargeCommitmentCantExpand: QuotaCharge %IX (%X)\n", QuotaCharge, IsParam2);

    ASSERT((SSIZE_T)QuotaCharge > 0);
    ASSERT((QuotaCharge < 0x100000) || (QuotaCharge < MmTotalCommitLimit));

    while (TRUE)
    {
        OldMmTotalCommittedPages = MmTotalCommittedPages;

        if (MmTotalCommittedPages > (MmTotalCommitLimit - QuotaCharge) && !IsParam2)
        {
            if (MmTotalCommittedPages < (MmTotalCommittedPages - QuotaCharge))
            {
                DPRINT1("MiChargeCommitmentCantExpand: charge failure\n");
                ASSERT(FALSE);
                return FALSE;
            }

            if (MmTotalCommitLimit >= (MmTotalCommitLimitMaximum - 100))
            {
                DPRINT1("MiChargeCommitmentCantExpand: charge failure\n");
                ASSERT(FALSE);
                return FALSE;
            }

            DPRINT1("MiChargeCommitmentCantExpand: charge failure\n");
            //MiChargeCommitmentFailures++;

            DPRINT1("MiChargeCommitmentCantExpand: FIXME MiIssuePageExtendRequestNoWait()\n");
            ASSERT(FALSE);
            //MiIssuePageExtendRequestNoWait(0x200);
            return FALSE;
        }

        if (OldMmTotalCommittedPages == InterlockedCompareExchange((PLONG)&MmTotalCommittedPages,
                                                                   (MmTotalCommittedPages + QuotaCharge),
                                                                   MmTotalCommittedPages))
        {
            break;
        }
    }

    if (MmTotalCommittedPages > (9 * (MmTotalCommitLimit / 10)) &&
        MmTotalCommitLimit < MmTotalCommitLimitMaximum)
    {
        ExtendQuota = (MmTotalCommittedPages - (85 * (MmTotalCommitLimit / 100)));

        if (QuotaCharge > ExtendQuota)
            ExtendQuota = QuotaCharge;

        DPRINT1("MiChargeCommitmentCantExpand: FIXME MiIssuePageExtendRequestNoWait()\n");
        ASSERT(FALSE);
        //MiIssuePageExtendRequestNoWait(ExtendQuota);
    }

    return TRUE;
}

/* EOF */
