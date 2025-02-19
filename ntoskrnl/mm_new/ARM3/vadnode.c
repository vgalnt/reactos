
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "miarm.h"

#define NDEBUG
#include <debug.h>

/* Include Mm version of AVL support */
#include "miavl.h"
#include <sdk/lib/rtl/avlsupp.c>

/* GLOBALS ********************************************************************/

#define MAXINDEX 0xFFFFFFFF

CHAR MmReadWrite[32] =
{
    MM_NO_ACCESS_ALLOWED, MM_READ_ONLY_ALLOWED, MM_READ_ONLY_ALLOWED, MM_READ_ONLY_ALLOWED,
    MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED,

    MM_NO_ACCESS_ALLOWED, MM_READ_ONLY_ALLOWED, MM_READ_ONLY_ALLOWED, MM_READ_ONLY_ALLOWED,
    MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED,

    MM_NO_ACCESS_ALLOWED, MM_READ_ONLY_ALLOWED, MM_READ_ONLY_ALLOWED, MM_READ_ONLY_ALLOWED,
    MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED,

    MM_NO_ACCESS_ALLOWED, MM_READ_ONLY_ALLOWED, MM_READ_ONLY_ALLOWED, MM_READ_ONLY_ALLOWED,
    MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED,
};

extern ULONG MiLastVadBit;
extern SIZE_T MmSystemCommitReserve;
extern MM_AVL_TABLE MmSectionBasedRoot;

/* FUNCTIONS ******************************************************************/

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(PAGE, MiFindEmptyAddressRangeInTree)
  #pragma alloc_text(PAGE, MiFindEmptyAddressRangeDownTree)
  #pragma alloc_text(PAGE, MiFindEmptyAddressRangeDownBasedTree)
  #pragma alloc_text(PAGE, MiInsertVadCharges)
  #pragma alloc_text(PAGE, MiCheckSecuredVad)
  #pragma alloc_text(PAGE, MiRemoveVadCharges)
  #pragma alloc_text(PAGE, MiCheckForConflictingNode)
  #pragma alloc_text(PAGE, MiInsertBasedSection)
#endif

BOOLEAN
NTAPI
MiCheckForConflictingVadExistence(
    _In_ PEPROCESS Process,
    _In_ ULONG_PTR StartingAddress,
    _In_ ULONG_PTR EndingAddress)
{
    PMMADDRESS_NODE Node;
    ULONG_PTR StartVpn;
    ULONG_PTR EndVpn;

    StartVpn = (StartingAddress / PAGE_SIZE);
    EndVpn = (EndingAddress / PAGE_SIZE);

    DPRINT("MiCheckForConflictingVadExistence: Process %p, Start %p, End %p, (%X:%X)Vpn\n",
           Process, StartingAddress, EndingAddress, StartVpn, EndVpn);

    /* If the tree is empty, there is no conflict */
    if (!Process->VadRoot.NumberGenericTableElements)
        return FALSE;

    /* Start looping from the root node */
    Node = Process->VadRoot.BalancedRoot.RightChild;
    if (!Node)
    {
        /* If the tree is not empty, this should not be */
        ASSERT(Node != NULL);
        return FALSE;
    }

    while (Node)
    {
        DPRINT("MiCheckForConflictingVadExistence: Node %p, StartingVpn %p, EndingVpn %p\n",
               Node, Node->StartingVpn, Node->EndingVpn);

        /* This address comes after */
        if (StartVpn > Node->EndingVpn)
        {
            Node = Node->RightChild;
        }
        else if (EndVpn < Node->StartingVpn)
        {
            /* This address ends before the node starts, search on the left */
            Node = Node->LeftChild;
        }
        else
        {
            DPRINT("MiCheckForConflictingVadExistence: This address is part of this Node\n");
            return TRUE;
        }
    }

    /* There is no more child */
    return FALSE;
}

PMMADDRESS_NODE
NTAPI
MiGetNextNode(
    _In_ PMMADDRESS_NODE Node)
{
    PMMADDRESS_NODE Parent;

    /* Get the right child */
    if (RtlRightChildAvl(Node))
    {
        /* Get left-most child */
        Node = RtlRightChildAvl(Node);

        while (RtlLeftChildAvl(Node))
            Node = RtlLeftChildAvl(Node);

        return Node;
    }

    Parent = RtlParentAvl(Node);
    ASSERT(Parent != NULL);

    while (Parent != Node)
    {
        /* The parent should be a left child, return the real predecessor */
        if (RtlIsLeftChildAvl(Node))
            /* Return it */
            return Parent;

        /* Keep lopping until we find our parent */
        Node = Parent;
        Parent = RtlParentAvl(Node);
    }

    /* Nothing found */
    return NULL;
}

PMMADDRESS_NODE
NTAPI
MiGetPreviousNode(
    _In_ PMMADDRESS_NODE Node)
{
    PMMADDRESS_NODE Parent;

    /* Get the left child */
    if (RtlLeftChildAvl(Node))
    {
        /* Get right-most child */
        Node = RtlLeftChildAvl(Node);

        while (RtlRightChildAvl(Node))
            Node = RtlRightChildAvl(Node);

        return Node;
    }

    Parent = RtlParentAvl(Node);
    ASSERT(Parent != NULL);

    while (Parent != Node)
    {
        /* The parent should be a right child, return the real predecessor */
        if (RtlIsRightChildAvl(Node))
        {
            /* Return it unless it's the root */
            if (Parent == RtlParentAvl(Parent))
                Parent = NULL;

            return Parent;
        }

        /* Keep lopping until we find our parent */
        Node = Parent;
        Parent = RtlParentAvl(Node);
    }

    /* Nothing found */
    return NULL;
}

VOID
NTAPI
MiReturnPageTablePageCommitment(
    _In_ ULONG_PTR StartingAddress,
    _In_ ULONG_PTR EndingAddress,
    _In_ PEPROCESS Process,
    _In_ PMMADDRESS_NODE PreviousNode,
    _In_ PMMADDRESS_NODE NextNode)
{
    RTL_BITMAP BitMapHeader;
    SIZE_T NumberToClear;
    ULONG StartingIndex;
    ULONG EndingIndex;
    LONG StartPdeOffset;
    LONG EndPdeOffset;
    LONG PreviousPage;
    LONG NextPage;

    //DPRINT1("MiReturnPageTablePageCommitment: %X, %X, %p\n", StartingAddress, EndingAddress, Process);

    ASSERT(StartingAddress != EndingAddress);

    StartingIndex = (StartingAddress / 0x10000);
    EndingIndex = (EndingAddress / 0x10000);

    if (PreviousNode)
    {
        PreviousPage = MiAddressToPdeOffset(PreviousNode->EndingVpn * PAGE_SIZE);

        if (((PreviousNode->EndingVpn * PAGE_SIZE) & ~(0x10000 - 1)) == (StartingAddress & ~(0x10000 - 1)))
            StartingIndex++;
    }
    else
    {
        PreviousPage = -1;
    }

    if (NextNode)
    {
        NextPage = MiAddressToPdeOffset(NextNode->StartingVpn * PAGE_SIZE);

        if (((NextNode->StartingVpn * PAGE_SIZE) & ~(0x10000 - 1)) == (EndingAddress & ~(0x10000 - 1)))
            EndingIndex--;
    }
    else
    {
        NextPage = (MiAddressToPdeOffset(MmHighestUserAddress) + 1);
    }

    ASSERT(PreviousPage <= NextPage);

    StartPdeOffset = MiAddressToPdeOffset(StartingAddress);
    EndPdeOffset = MiAddressToPdeOffset(EndingAddress);

    if (PreviousPage == StartPdeOffset)
        StartPdeOffset++;

    if (NextPage == EndPdeOffset)
        EndPdeOffset--;

    if (StartingIndex <= EndingIndex)
    {
        BitMapHeader.SizeOfBitMap = (MiLastVadBit + 1);
        BitMapHeader.Buffer = MI_VAD_BITMAP;

        NumberToClear = (EndingIndex - StartingIndex + 1);
        RtlClearBits(&BitMapHeader, StartingIndex, NumberToClear);

        if (MmWorkingSetList->VadBitMapHint > StartingIndex)
            MmWorkingSetList->VadBitMapHint = StartingIndex;
    }

    if (StartPdeOffset > EndPdeOffset)
        return;

    NumberToClear = (EndPdeOffset - StartPdeOffset + 1);

    DPRINT("MiReturnPageTablePageCommitment: %X, %X, %X\n", StartPdeOffset, EndPdeOffset, NumberToClear);

    while (StartPdeOffset <= EndPdeOffset)
    {
        if (!(((ULONG)(MmWorkingSetList->CommittedPageTables[StartPdeOffset / 0x20]) >> (StartPdeOffset & (0x20 - 1))) & 1))
        {
            //test bit failed
            DPRINT1("MiReturnPageTablePageCommitment: %X\n", MmWorkingSetList->CommittedPageTables[StartPdeOffset / 0x20]);
            ASSERT(FALSE);
        }

        MmWorkingSetList->CommittedPageTables[StartPdeOffset / 0x20] &= ~(1 << (StartPdeOffset & (0x20 - 1)));
        StartPdeOffset++;
    }

    MmWorkingSetList->NumberOfCommittedPageTables -= NumberToClear;

    ASSERT((SSIZE_T)(NumberToClear) >= 0);
    ASSERT(MmTotalCommittedPages >= (NumberToClear));

    InterlockedExchangeAddSizeT(&MmTotalCommittedPages, -NumberToClear);

    PsReturnProcessPageFileQuota(Process, NumberToClear);

    if (Process->JobStatus & 0x10)
    {
        DPRINT1("MiReturnPageTablePageCommitment: FIXME\n");
        ASSERT(FALSE);
    }

    Process->CommitCharge -= NumberToClear;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MiFindEmptyAddressRangeInTree(
    _In_ SIZE_T Length,
    _In_ ULONG_PTR Alignment,
    _In_ PMM_AVL_TABLE Table,
    _Out_ PMMADDRESS_NODE* PreviousVad,
    _Out_ PULONG_PTR Base)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
MiFindEmptyAddressRange(
    _In_ SIZE_T Size,
    _In_ ULONG_PTR Alignment,
    _In_ ULONG ZeroBits,
    _Out_ PULONG_PTR OutBaseAddress)
{
    PEPROCESS Process = PsGetCurrentProcess();
    ULONG StartVadBitmapValue;
    ULONG StartBitIndex;
    RTL_BITMAP BitMapHeader;

    DPRINT("MiFindEmptyAddressRange: Size %X, Alignment %X, ZeroBits %X\n", Size, Alignment, ZeroBits);

    if (ZeroBits || Alignment != MM_ALLOCATION_GRANULARITY)
    {
        DPRINT1("MiFindEmptyAddressRange: goto FindInTree\n");
        goto FindInTree;
    }

    BitMapHeader.SizeOfBitMap = (MiLastVadBit + 1);
    BitMapHeader.Buffer = MI_VAD_BITMAP;

    /* Mask null bit */
    StartVadBitmapValue = *MI_VAD_BITMAP;
    *(PULONG)MI_VAD_BITMAP |= 1;

    /* Get starting bit index for a clear bit range of at least the requested size */
    StartBitIndex = RtlFindClearBits(&BitMapHeader,
                                     ((Size + (MM_ALLOCATION_GRANULARITY - 1)) / MM_ALLOCATION_GRANULARITY),
                                     MmWorkingSetList->VadBitMapHint);
    /* Unmask null bit */
    *(PULONG)MI_VAD_BITMAP &= (StartVadBitmapValue | (~1));

    if (StartBitIndex != MAXINDEX)
    {
        *OutBaseAddress = ((ULONG_PTR)StartBitIndex * MM_ALLOCATION_GRANULARITY);
        DPRINT("MiFindEmptyAddressRange: StartBitIndex %X, BaseAddress %X\n", StartBitIndex, *OutBaseAddress);
        return STATUS_SUCCESS;
    }

    /* Cannot find a range within the MI_VAD_BITMAP */
    DPRINT1("MiFindEmptyAddressRange: Size %X, Alignment %X, ZeroBits %X\n", Size, Alignment, ZeroBits);
    DPRINT1("MiFindEmptyAddressRange: StartBitIndex %X, BaseAddress %X\n", StartBitIndex, *OutBaseAddress);

    if (!Process->VadFreeHint)
    {
        DPRINT1("MiFindEmptyAddressRange: VadFreeHint == NULL\n");
        goto FindInTree;
    }

    DPRINT1("MiFindEmptyAddressRange: FIXME!\n");
    ASSERT(FALSE);

FindInTree:

    return MiFindEmptyAddressRangeInTree(Size,
                                         Alignment,
                                         &Process->VadRoot,
                                         (PMMADDRESS_NODE *)&Process->VadFreeHint,
                                         OutBaseAddress);
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MiFindEmptyAddressRangeDownTree(
    _In_ SIZE_T Length,
    _In_ ULONG_PTR BoundaryAddress,
    _In_ ULONG_PTR Alignment,
    _In_ PMM_AVL_TABLE Table,
    _Out_ ULONG_PTR* OutBase)
{
    PMMADDRESS_NODE Node;
    PMMADDRESS_NODE PreviousNode;
    ULONG_PTR BaseVpn;
    ULONG_PTR HighVpn;
    ULONG_PTR LowVpn;
    ULONG_PTR PagesForAlign;
    ULONG_PTR AlignedEnd;
    ULONG_PTR AlignedPreviousEnd;
    ULONG_PTR Base;
    ULONG_PTR AlignMask;
    SIZE_T PageCount;

    DPRINT("MiFindEmptyAddressRangeDownTree: %X, %X, %X, %p\n", Length, BoundaryAddress, Alignment, Table);

    /* Sanity checks */
    ASSERT(Table != &MmSectionBasedRoot);

    /* Calculate length */
    Length = (Length + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);

    if ((BoundaryAddress + 1) < Length)
        return STATUS_NO_MEMORY;

    ASSERT(BoundaryAddress != 0);
    ASSERT(BoundaryAddress <= ((ULONG_PTR)MmHighestUserAddress - 0x10000 + 1));

    AlignMask = (Alignment - 1);

    /* Calculate the initial upper margin */
    HighVpn = (BoundaryAddress / PAGE_SIZE);
    Base = ((BoundaryAddress - Length + 1) & ~AlignMask);

    if (!Table->NumberGenericTableElements)
    {
        *OutBase = Base;
        return STATUS_SUCCESS;
    }

    /* Starting from the root, follow the right children until we found a node that ends above the boundary */
    for (Node = Table->BalancedRoot.RightChild;
         Node->RightChild;
         )
    {
        Node = Node->RightChild;
    }

    AlignedEnd = ((((Node->EndingVpn * PAGE_SIZE) | (PAGE_SIZE - 1)) + AlignMask) & ~AlignMask);

    if (BoundaryAddress > AlignedEnd &&
        (BoundaryAddress - AlignedEnd) > Length)
    {
        Base = ((BoundaryAddress - Length) & ~AlignMask);
        *OutBase = Base;
        return STATUS_SUCCESS;
    }

    BaseVpn = (Base / PAGE_SIZE);
    PageCount = (Length / PAGE_SIZE);
    PagesForAlign = (Alignment / PAGE_SIZE);

    /* Now loop the Vad nodes */
    while (TRUE)
    {
        PreviousNode = MiGetPreviousNode(Node);
        if (!PreviousNode)
            break;

        if (BaseVpn > PreviousNode->EndingVpn)
        {
            AlignedPreviousEnd = ((PreviousNode->EndingVpn + PagesForAlign) & ~(PagesForAlign - 1));

            /* Check if the current bounds are suitable */
            if ((Node->StartingVpn - AlignedPreviousEnd) >= PageCount)
            {
                if (Node->StartingVpn > HighVpn)
                {
                    *OutBase = Base;
                    return STATUS_SUCCESS;
                }

                if (Node->StartingVpn > AlignedPreviousEnd)
                {
                    *OutBase = (((Node->StartingVpn * PAGE_SIZE) - Length) & ~AlignMask);
                    return STATUS_SUCCESS;
                }
            }
        }

        /* Remember the current node and go to the previous node */
        Node = PreviousNode;
    }

    /* Check if there's enough space before the lowest Vad */
    LowVpn = ((ULONG_PTR)MI_LOWEST_VAD_ADDRESS / PAGE_SIZE);

    if (Node->StartingVpn > LowVpn &&
        (Node->StartingVpn - PageCount) >= LowVpn)
    {
        if (Node->StartingVpn > HighVpn)
            *OutBase = Base;
        else
            *OutBase = (((Node->StartingVpn * PAGE_SIZE) - Length) & ~AlignMask);

        return STATUS_SUCCESS;
    }

    /* No address space left at all */
    return STATUS_NO_MEMORY;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MiFindEmptyAddressRangeDownBasedTree(
    _In_ SIZE_T Length,
    _In_ ULONG_PTR BoundaryAddress,
    _In_ ULONG_PTR Alignment,
    _In_ PMM_AVL_TABLE Table,
    _Out_ ULONG_PTR* OutBase)
{
    PMMADDRESS_NODE Node;
    PMMADDRESS_NODE LowestNode;
    ULONG_PTR LowVpn;
    ULONG_PTR BestVpn;

    DPRINT("MiFindEmptyAddressRangeDownBasedTree: %X, %X, %X, %p\n", Length, BoundaryAddress, Alignment, Table);

    /* Sanity checks */
    ASSERT(Table == &MmSectionBasedRoot);
    ASSERT(BoundaryAddress);
    ASSERT(BoundaryAddress <= ((ULONG_PTR)MM_HIGHEST_VAD_ADDRESS + 1));

    /* Compute page length, make sure the boundary address is valid */
    Length = ROUND_TO_PAGES(Length);

    if (Length > (BoundaryAddress + 1))
    {
        DPRINT1("MiFindEmptyAddressRangeDownBasedTree: STATUS_NO_MEMORY\n");
        return STATUS_NO_MEMORY;
    }

    /* Check if the table is empty */
    BestVpn = ROUND_DOWN((BoundaryAddress - Length + 1), Alignment);

    if (!Table->NumberGenericTableElements)
    {
        /* Tree is empty, the candidate address is already the best one */
        *OutBase = BestVpn;
        return STATUS_SUCCESS;
    }

    /* Go to the right-most node which should be the biggest address */
    Node = Table->BalancedRoot.RightChild;

    while (RtlRightChildAvl(Node))
        Node = RtlRightChildAvl(Node);

    /* Check if we can fit in here */
    LowVpn = ROUND_UP((Node->EndingVpn + 1), Alignment);

    if (LowVpn < BoundaryAddress && Length <= (BoundaryAddress - LowVpn))
    {
        /* Note: this is a compatibility hack that mimics a bug in the 2k3 kernel.
           It will can waste up to Alignment bytes of memory above the allocation.
           This bug was fixed in Windows Vista
        */
        *OutBase = ROUND_DOWN((BoundaryAddress - Length), Alignment);

        return STATUS_SUCCESS;
    }

    /* Now loop the Vad nodes */
    do
    {
        /* Break out if we've reached the last node */
        LowestNode = MiGetPreviousNode(Node);
        if (!LowestNode)
            break;

        /* Check if this node could contain the requested address */
        LowVpn = ROUND_UP((LowestNode->EndingVpn + 1), Alignment);

        if (LowestNode->EndingVpn < BestVpn &&
            LowVpn < Node->StartingVpn &&
            Length <= (Node->StartingVpn - LowVpn))
        {
            /* Check if we need to take BoundaryAddress into account */
            if (BoundaryAddress < Node->StartingVpn)
            {
                /* Return the optimal VPN address */
                *OutBase = BestVpn;
                return STATUS_SUCCESS;
            }
            else
            {
                /* The upper margin is given by the Node's starting address */
                *OutBase = ROUND_DOWN((Node->StartingVpn - Length), Alignment);
                return STATUS_SUCCESS;
            }
        }

        /* Move to the next node */
        Node = LowestNode;
    }
    while (TRUE);

    /* Check if there's enough space before the lowest Vad */
    if (Node->StartingVpn <= (ULONG_PTR)MI_LOWEST_VAD_ADDRESS)
    {
        /* No address space left at all */
        DPRINT1("MiFindEmptyAddressRangeDownBasedTree: STATUS_NO_MEMORY\n");
        return STATUS_NO_MEMORY;
    }

    if (Node->StartingVpn < (Length + (ULONG_PTR)MI_LOWEST_VAD_ADDRESS))
    {
        /* No address space left at all */
        DPRINT1("MiFindEmptyAddressRangeDownBasedTree: STATUS_NO_MEMORY\n");
        return STATUS_NO_MEMORY;
    }

    /* Check if it fits in perfectly */
    if (BoundaryAddress < Node->StartingVpn)
    {
        /* Return the optimal VPN address */
        *OutBase = BestVpn;
        return STATUS_SUCCESS;
    }

    /* Return an aligned base address within this node */
    *OutBase = ROUND_DOWN((Node->StartingVpn - Length), Alignment);

    return STATUS_SUCCESS;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MiInsertVadCharges(
    _In_ PMMVAD Vad,
    _In_ PEPROCESS Process)
{
    RTL_BITMAP BitMapHeader;
    PMMVAD VadFreeHint;
    ULONG StartingIndex;
    ULONG EndingIndex;
    ULONG StartPdeIndex;
    ULONG EndPdeIndex;
    ULONG PageCharge;
    ULONG PagesReallyCharged;
    ULONG RealCharge = 0;
    ULONG BitNumber;
    ULONG NumberToSet;
    BOOLEAN IsChangeJobMemoryUsage;
    NTSTATUS Status;

    DPRINT("MiInsertVadCharges: Vad %p, Process %p, StartingVpn %X, EndingVpn %X\n",
           Vad, Process, Vad->StartingVpn, Vad->EndingVpn);

    ASSERT(Vad->EndingVpn >= Vad->StartingVpn);
    ASSERT(Process == PsGetCurrentProcess());

    if (Vad->u.VadFlags.CommitCharge != 0x7FFFF) // ?
    {
        PageCharge = 0;
        PagesReallyCharged = 0;
        IsChangeJobMemoryUsage = FALSE;

        Status = PsChargeProcessNonPagedPoolQuota(Process, sizeof(MMVAD));
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("MiInsertVadCharges: STATUS_COMMITMENT_LIMIT\n");
            return STATUS_COMMITMENT_LIMIT;
        }

        if (!Vad->u.VadFlags.PrivateMemory && Vad->ControlArea)
        {
            PagesReallyCharged = ((Vad->EndingVpn - Vad->StartingVpn + 1) * sizeof(MMPTE));

            Status = PsChargeProcessPagedPoolQuota(Process, PagesReallyCharged);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("MiInsertVadCharges: Status %X\n", Status);
                PagesReallyCharged = 0;
                goto ErrorExit;
            }
        }

        StartPdeIndex = MiAddressToPdeOffset(Vad->StartingVpn * PAGE_SIZE);
        EndPdeIndex = MiAddressToPdeOffset(Vad->EndingVpn * PAGE_SIZE);

        DPRINT("MiInsertVadCharges: StartPdeIndex %X, EndPdeIndex %X\n", StartPdeIndex, EndPdeIndex);

      #if (_MI_PAGING_LEVELS == 2)

        RtlInitializeBitMap(&BitMapHeader,
                            MmWorkingSetList->CommittedPageTables,
                            (MI_USED_PAGE_TABLES_MAX / (8 * sizeof(ULONG)))); 

        for (BitNumber = StartPdeIndex; BitNumber <= EndPdeIndex; BitNumber++)
        {
            if (!RtlCheckBit(&BitMapHeader, BitNumber))
                PageCharge++;
        }

      #else
        #error FIXME
        ASSERT(FALSE);
      #endif

        RealCharge = (PageCharge + Vad->u.VadFlags.CommitCharge);
        if (RealCharge)
        {
            Status = PsChargeProcessPageFileQuota(Process, RealCharge);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("MiInsertVadCharges: Status %X\n", Status);
                RealCharge = 0;
                goto ErrorExit;
            }

            if (Process->CommitChargeLimit &&
                Process->CommitChargeLimit < (RealCharge + Process->CommitCharge))
            {
                DPRINT1("MiInsertVadCharges: error\n");
                if (Process->Job)
                {
                    ASSERT(FALSE);//PsReportProcessMemoryLimitViolation();
                }

                goto ErrorExit;
            }

            if (Process->JobStatus & 0x10)
            {
                DPRINT1("MiInsertVadCharges: FIXME\n");
                ASSERT(FALSE);
                IsChangeJobMemoryUsage = TRUE;
            }

            if (!MiChargeCommitment(RealCharge, NULL))
            {
                DPRINT1("MiInsertVadCharges: FIXME\n");
                ASSERT(FALSE);
            }

            Process->CommitCharge += RealCharge;

            if (Process->CommitCharge > Process->CommitChargePeak)
                Process->CommitChargePeak = Process->CommitCharge;

            ASSERT(RealCharge == (Vad->u.VadFlags.CommitCharge + PageCharge));
        }

        if (PageCharge)
        {
            PagesReallyCharged = 0;

          #if (_MI_PAGING_LEVELS == 2)

            for (BitNumber = StartPdeIndex; BitNumber <= EndPdeIndex; BitNumber++)
            {
                if (!RtlCheckBit(&BitMapHeader, BitNumber))
                {
                    RtlSetBit(&BitMapHeader, BitNumber);

                    MmWorkingSetList->NumberOfCommittedPageTables++;
                    ASSERT(MmWorkingSetList->NumberOfCommittedPageTables < (PD_COUNT * PDE_PER_PAGE));

                    PagesReallyCharged++;
                }
            }

          #else
            #error FIXME
            ASSERT(FALSE);
          #endif

            ASSERT(PageCharge == PagesReallyCharged);
        }
    }

    StartingIndex = ((Vad->StartingVpn * PAGE_SIZE) / MM_ALLOCATION_GRANULARITY);
    EndingIndex = ((Vad->EndingVpn * PAGE_SIZE) / MM_ALLOCATION_GRANULARITY);

    NumberToSet = (EndingIndex - StartingIndex + 1);
    DPRINT("MiInsertVadCharges: StartingIndex %X NumberToSet %X\n", StartingIndex, NumberToSet);

    RtlInitializeBitMap(&BitMapHeader, MI_VAD_BITMAP, (MiLastVadBit + 1)); 
    RtlSetBits(&BitMapHeader, StartingIndex, NumberToSet);

    DPRINT("MiInsertVadCharges: MI_VAD_BITMAP %X, *(PULONG)MI_VAD_BITMAP %X\n", MI_VAD_BITMAP, *(PULONG)MI_VAD_BITMAP);

    if (MmWorkingSetList->VadBitMapHint == StartingIndex)
        MmWorkingSetList->VadBitMapHint = (EndingIndex + 1);

    VadFreeHint = Process->VadFreeHint;

    if (VadFreeHint && (VadFreeHint->EndingVpn + (MM_ALLOCATION_GRANULARITY / PAGE_SIZE)) >= Vad->StartingVpn)
        Process->VadFreeHint = Vad;

    return STATUS_SUCCESS;

ErrorExit:

    PsReturnProcessNonPagedPoolQuota(Process, sizeof(MMVAD));

    if (PagesReallyCharged)
        PsReturnProcessPagedPoolQuota(Process, PagesReallyCharged);

    if (RealCharge)
        PsReturnProcessPageFileQuota(Process, RealCharge);

    if (IsChangeJobMemoryUsage)
    {
        DPRINT1("MiInsertVadCharges: FIXME PsChangeJobMemoryUsage()\n");
        ASSERT(FALSE);
    }

    DPRINT1("MiInsertVadCharges: STATUS_COMMITMENT_LIMIT\n");
    return STATUS_COMMITMENT_LIMIT;
}

VOID
NTAPI
MiInsertNode(
    _In_ PMM_AVL_TABLE Table,
    _In_ PMMADDRESS_NODE NewNode,
    _In_ PMMADDRESS_NODE Parent,
    _In_ TABLE_SEARCH_RESULT Result)
{
    DPRINT("MiInsertNode: NewNode %p, Table %p, StartingVpn %p, EndingVpn %p\n",
            NewNode, Table, NewNode->StartingVpn, NewNode->EndingVpn);

    /* Insert it into the tree */
    RtlpInsertAvlTreeNode(Table, NewNode, Parent, Result);

    DPRINT("MiInsertNode: Result %X\n", Result);
}

VOID
NTAPI
MiInsertVad(
    _In_ PMMVAD Vad,
    _In_ PMM_AVL_TABLE VadRoot)
{
    TABLE_SEARCH_RESULT Result;
    PMMADDRESS_NODE Parent = NULL;

    DPRINT("MiInsertVad: Vad %p, VadRoot %p\n", Vad, VadRoot);

    /* Validate the VAD and set it as the current hint */
    ASSERT(Vad->EndingVpn >= Vad->StartingVpn);

    VadRoot->NodeHint = Vad;

    /* Find the parent VAD and where this child should be inserted */
    Result = RtlpFindAvlTableNodeOrParent(VadRoot, (PVOID)Vad->StartingVpn, &Parent);

    ASSERT(Result != TableFoundNode);
    ASSERT((Parent != NULL) || (Result == TableEmptyTree));

    /* Do the actual insert operation */
    MiInsertNode(VadRoot, (PVOID)Vad, Parent, Result);
}

PMMVAD
NTAPI
MiLocateAddress(
    _In_ PVOID VirtualAddress)
{
    PMM_AVL_TABLE Table = &PsGetCurrentProcess()->VadRoot;
    PMMVAD FoundVad;
    TABLE_SEARCH_RESULT SearchResult;
    ULONG_PTR Vpn;

    /* Start with the the hint */
    FoundVad = (PMMVAD)Table->NodeHint;
    if (!FoundVad)
        return NULL;

    /* Check if this VPN is in the hint, if so, use it */
    Vpn = ((ULONG_PTR)VirtualAddress / PAGE_SIZE);

    if (Vpn >= FoundVad->StartingVpn && Vpn <= FoundVad->EndingVpn)
        return FoundVad;

    /* VAD hint didn't work, go look for it */
    SearchResult = RtlpFindAvlTableNodeOrParent(Table, (PVOID)Vpn, (PMMADDRESS_NODE *)&FoundVad);
    if (SearchResult != TableFoundNode)
        return NULL;

    /* We found it, update the hint */
    ASSERT(FoundVad != NULL);
    ASSERT((Vpn >= FoundVad->StartingVpn) && (Vpn <= FoundVad->EndingVpn));

    Table->NodeHint = FoundVad;

    return FoundVad;
}

PMM_AVL_TABLE
NTAPI
MiCreatePhysicalVadRoot(
    _In_ PEPROCESS Process,
    _In_ BOOLEAN IsLocked)
{
    PMM_AVL_TABLE PhysicalVadRoot;
    PETHREAD Thread;

    DPRINT("MiCreatePhysicalVadRoot: Process %p, IsLocked %X\n", Process, IsLocked);

    if (Process->PhysicalVadRoot)
    {
        DPRINT1("MiCreatePhysicalVadRoot: Process->PhysicalVadRoot %p\n", Process->PhysicalVadRoot);
        return Process->PhysicalVadRoot;
    }

    PhysicalVadRoot = ExAllocatePoolWithTag(NonPagedPool, sizeof(MM_AVL_TABLE), 'rpmM');
    if (!PhysicalVadRoot)
    {
        DPRINT1("MiCreatePhysicalVadRoot: allocate failed\n");
        return NULL;
    }

    RtlZeroMemory(PhysicalVadRoot, sizeof(MM_AVL_TABLE));

    ASSERT(PhysicalVadRoot->NumberGenericTableElements == 0);

    Thread = PsGetCurrentThread();

    PhysicalVadRoot->BalancedRoot.u1.Parent = &PhysicalVadRoot->BalancedRoot;

    if (!IsLocked)
        MiLockProcessWorkingSet(Process, Thread);

    if (Process->PhysicalVadRoot)
    {
        if (!IsLocked)
            MiUnlockProcessWorkingSet(Process, Thread);

        ExFreePoolWithTag(PhysicalVadRoot, 'rpmM');
    }
    else
    {
        Process->PhysicalVadRoot = PhysicalVadRoot;

        if (!IsLocked)
            MiUnlockProcessWorkingSet(Process, Thread);
    }

    return Process->PhysicalVadRoot;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MiCheckSecuredVad(
    _In_ PMMVAD Vad,
    _In_ PVOID Base,
    _In_ SIZE_T Size,
    _In_ ULONG ProtectionMask)
{
    ULONG_PTR StartAddress, EndAddress;

    /* Compute start and end address */
    StartAddress = (ULONG_PTR)Base;
    EndAddress = (StartAddress + Size - 1);

    /* Are we deleting/unmapping, or changing? */
    if (ProtectionMask < MM_DELETE_CHECK)
    {
        /* Changing... are we allowed to do so? */
        if (Vad->u.VadFlags.NoChange &&
            Vad->u2.VadFlags2.SecNoChange &&
            Vad->u.VadFlags.Protection != ProtectionMask)
        {
            /* Nope, bail out */
            DPRINT1("Trying to mess with a no-change VAD!\n");
            return STATUS_INVALID_PAGE_PROTECTION;
        }
    }
    else
    {
        /* This is allowed */
        ProtectionMask = 0;
    }

    /* ARM3 doesn't support this yet */
    ASSERT(Vad->u2.VadFlags2.MultipleSecured == 0);

    /* Is this a one-secured VAD, like a TEB or PEB? */
    if (!Vad->u2.VadFlags2.OneSecured)
        return STATUS_SUCCESS;

    /* Is this allocation being described by the VAD? */
    if (StartAddress <= ((PMMVAD_LONG)Vad)->u3.Secured.EndVpn &&
        EndAddress >= ((PMMVAD_LONG)Vad)->u3.Secured.StartVpn)
    {
        /* Guard page? */
        if (ProtectionMask & MM_DECOMMIT)
        {
            DPRINT1("Not allowed to change protection on guard page!\n");
            return STATUS_INVALID_PAGE_PROTECTION;
        }

        /* ARM3 doesn't have read-only VADs yet */
        ASSERT(Vad->u2.VadFlags2.ReadOnly == 0);

        /* Check if read-write protections are allowed */
        if (MmReadWrite[ProtectionMask] < MM_READ_WRITE_ALLOWED)
        {
            DPRINT1("Invalid protection mask for RW access!\n");
            return STATUS_INVALID_PAGE_PROTECTION;
        }
    }

    /* All good, allow the change */
    return STATUS_SUCCESS;
}

CODE_SEG("PAGE")
VOID
NTAPI
MiRemoveVadCharges(
    _In_ PMMVAD Vad,
    _In_ PEPROCESS Process)
{
    ULONG_PTR SizeVpn;
    ULONG RealCharge;

    DPRINT("MiRemoveVadCharges: Vad %p, Process %p\n", Vad, Process);

    ASSERT(!MM_ANY_WS_LOCK_HELD(PsGetCurrentThread()));
    ASSERT(Process == PsGetCurrentProcess());

    RealCharge = Vad->u.VadFlags.CommitCharge;

    if (RealCharge != 0x7FFFF)
    {
        PsReturnProcessNonPagedPoolQuota(Process, sizeof(MMVAD));

        if (!Vad->u.VadFlags.PrivateMemory && Vad->ControlArea)
        {
            SizeVpn = (Vad->EndingVpn - Vad->StartingVpn + 1);
            PsReturnProcessPagedPoolQuota(Process, (SizeVpn * sizeof(MMPTE)));
        }

        if (RealCharge)
        {
            PsReturnProcessPageFileQuota(Process, RealCharge);

            ASSERT((SSIZE_T)(RealCharge) >= 0);
            if (MmTotalCommittedPages < RealCharge)
            {
                DPRINT1("MiRemoveVadCharges: FIXME! (%p:%p) MmTotalCommittedPages %IX, RealCharge %IX\n", Vad, Process, MmTotalCommittedPages, RealCharge);
                ASSERT(MmTotalCommittedPages >= RealCharge);
            }
            else
            {
                InterlockedExchangeAddSizeT(&MmTotalCommittedPages, -RealCharge);
            }

            if (Process->JobStatus & 0x10) // ?
            {
                DPRINT1("MiRemoveVadCharges: FIXME PsChangeJobMemoryUsage()\n");
                ASSERT(FALSE);
            }

            Process->CommitCharge -= RealCharge;
        }
    }

    if (Vad->u.VadFlags.NoChange &&
        Vad->u2.VadFlags2.MultipleSecured)
    {
        DPRINT1("MiRemoveVadCharges: FIXME MultipleSecured\n");
        ASSERT(FALSE);
    }

    if (Process->VadFreeHint)
    {
        if (Vad == Process->VadFreeHint ||
            Vad->StartingVpn < ((PMMVAD)(Process->VadFreeHint))->StartingVpn)
        {
            Process->VadFreeHint = MiGetPreviousNode((PMMADDRESS_NODE)Vad);
        }
    }
}

VOID
NTAPI
MiRemoveNode(
    _In_ PMMADDRESS_NODE Node,
    _In_ PMM_AVL_TABLE Table)
{
    DPRINT("MiRemoveNode: Node %p, Table %p\n", Node, Table);

    /* Call the AVL code */
    RtlpDeleteAvlTreeNode(Table, Node);

    /* Decrease element count */
    Table->NumberGenericTableElements--;

    /* Check if this node was the hint */
    if (Table->NodeHint != Node)
        return;

    /* Get a new hint, unless we're empty now, in which case nothing */
    if (!Table->NumberGenericTableElements)
        Table->NodeHint = NULL;
    else
        Table->NodeHint = Table->BalancedRoot.RightChild;
}

TABLE_SEARCH_RESULT
NTAPI
MiFindNodeOrParent(
    _In_ PMM_AVL_TABLE Table,
    _In_ ULONG_PTR StartingVpn,
    _Out_ PMMADDRESS_NODE* OutNodeOrParent)
{
    PMMADDRESS_NODE Node;
    PMMADDRESS_NODE ChildNode;
    TABLE_SEARCH_RESULT SearchResult;
    ULONG NumberCompares = 0;

    if (!Table->NumberGenericTableElements)
        return TableEmptyTree;

    for (Node = Table->BalancedRoot.RightChild;
         ;
         Node = ChildNode)
    {
        NumberCompares++;
        ASSERT(NumberCompares <= Table->DepthOfTree);

        if (StartingVpn >= Node->StartingVpn)
        {
            if (StartingVpn <= Node->EndingVpn)
            {
                SearchResult = TableFoundNode;
                break;
            }

            ChildNode = Node->RightChild;
            if (ChildNode)
                continue;

            SearchResult = TableInsertAsRight;
            break;
        }

        ChildNode = Node->LeftChild;

        if (!ChildNode)
        {
            SearchResult = TableInsertAsLeft;
            break;
        }
    }

    *OutNodeOrParent = Node;

    return SearchResult;
}

VOID
NTAPI
MiPhysicalViewRemover(
    _In_ PEPROCESS Process,
    _In_ PMMVAD Vad)
{
    PMM_PHYSICAL_VIEW PhysicalView;
    TABLE_SEARCH_RESULT SearchResult;

    DPRINT("MiPhysicalViewRemover: Process %p, Vad %p\n", Process, Vad);

    ASSERT(Process->PhysicalVadRoot != NULL);

    SearchResult = MiFindNodeOrParent(Process->PhysicalVadRoot,
                                      Vad->StartingVpn,
                                      (PMMADDRESS_NODE *)&PhysicalView);

    ASSERT(SearchResult == TableFoundNode);
    ASSERT(PhysicalView->Vad == Vad);

    MiRemoveNode((PMMADDRESS_NODE)PhysicalView, Process->PhysicalVadRoot);

    if (Vad->u.VadFlags.VadType == VadWriteWatch)
    {
        DPRINT1("MiPhysicalViewRemover: VadType - VadWriteWatch\n");
        ASSERT(FALSE);
    }

    if (Vad->u.VadFlags.VadType == VadRotatePhysical)
    {
        DPRINT1("MiPhysicalViewRemover: VadType - VadRotatePhysical\n");
        ASSERT(FALSE);
    }

    ExFreePoolWithTag(PhysicalView, 'vpmM');
}

CODE_SEG("PAGE")
PMMADDRESS_NODE
NTAPI
MiCheckForConflictingNode(
    _In_ ULONG_PTR StartVpn,
    _In_ ULONG_PTR EndVpn,
    _In_ PMM_AVL_TABLE Table)
{
    PMMADDRESS_NODE CurrentNode;

    DPRINT("MiCheckForConflictingNode: StartVpn %X, EndVpn %X, Table %p\n", StartVpn, EndVpn, Table);

    if (!Table->NumberGenericTableElements)
        return NULL;

    CurrentNode = (PMMADDRESS_NODE)Table->BalancedRoot.RightChild;

    ASSERT(CurrentNode != NULL);

    while (CurrentNode)
    {
        if (StartVpn > CurrentNode->EndingVpn)
            CurrentNode = CurrentNode->RightChild;
        else if (EndVpn < CurrentNode->StartingVpn)
            CurrentNode = CurrentNode->LeftChild;
        else
            return CurrentNode;
    }

    return NULL;
}

CODE_SEG("PAGE")
VOID
NTAPI
MiInsertBasedSection(
    _In_ PSECTION Section)
{
    PMMADDRESS_NODE Parent = NULL;
    TABLE_SEARCH_RESULT Result;

    DPRINT("MiInsertBasedSection: Section %p\n", Section);

    ASSERT(Section->Address.EndingVpn >= Section->Address.StartingVpn);

    /* Find the parent VAD and where this child should be inserted */
    Result = RtlpFindAvlTableNodeOrParent(&MmSectionBasedRoot, (PVOID)Section->Address.StartingVpn, &Parent);

    ASSERT(Result != TableFoundNode);
    ASSERT((Parent != NULL) || (Result == TableEmptyTree));

    MiInsertNode(&MmSectionBasedRoot, &Section->Address, Parent, Result);
}

/* EOF */
