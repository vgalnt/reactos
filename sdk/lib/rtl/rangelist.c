/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS system libraries
 * FILE:              lib/rtl/rangelist.c
 * PURPOSE:           Range list implementation
 * PROGRAMMERS:       No programmer listed.
 */

/* INCLUDES *****************************************************************/

#include <rtl.h>

#define NDEBUG
#include <debug.h>

/* TYPES ********************************************************************/

typedef struct _RTL_RANGE_ENTRY
{
    LIST_ENTRY Entry;
    RTL_RANGE Range;
} RTL_RANGE_ENTRY, *PRTL_RANGE_ENTRY;

#define RTLP_RANGE_LIST_ENTRY_MERGED  1

/* FUNCTIONS ***************************************************************/

/**********************************************************************
 * NAME							EXPORTED
 * 	RtlAddRange
 *
 * DESCRIPTION
 *	Adds a range to a range list.
 *
 * ARGUMENTS
 *	RangeList		Range list.
 *	Start
 *	End
 *	Attributes
 *	Flags
 *	UserData
 *	Owner
 *
 * RETURN VALUE
 *	Status
 *
 * TODO:
 *   - Support shared ranges.
 *
 * @implemented
 */
NTSTATUS
NTAPI
RtlAddRange(IN OUT PRTL_RANGE_LIST RangeList,
            IN ULONGLONG Start,
            IN ULONGLONG End,
            IN UCHAR Attributes,
            IN ULONG Flags,
            IN PVOID UserData OPTIONAL,
            IN PVOID Owner OPTIONAL)
{
    PRTLP_RANGE_LIST_ENTRY RangeEntry;
    PRTLP_RANGE_LIST_ENTRY Current;
    PLIST_ENTRY Entry;
    NTSTATUS Status;

    PAGED_CODE_RTL();
    DPRINT("RtlAddRange: RangeList - %p [%I64X-%I64X], Count - %X, Attributes - %X, Flags - %X, UserData - %X, Owner - %X\n",
           RangeList, Start, End, RangeList->Count, Attributes, Flags, UserData, Owner);

    if (Start > End)
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* Create new range entry */
    RangeEntry = RtlpAllocateMemory(sizeof(RTLP_RANGE_LIST_ENTRY), 'elRR');
    //RangeEntry = ExAllocateFromPagedLookasideList(&RtlpRangeListEntryLookasideList); // FIXME

    if (RangeEntry == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RangeEntry->Start = Start;
    RangeEntry->End = End;

    RangeEntry->Allocated.UserData = UserData;
    RangeEntry->Allocated.Owner = Owner;

    RangeEntry->ListEntry.Flink = NULL;
    RangeEntry->ListEntry.Blink = NULL;

    RangeEntry->PublicFlags = 0;
    RangeEntry->PrivateFlags = 0;
    RangeEntry->Attributes = Attributes;

    if (Flags & RTL_RANGE_LIST_ADD_SHARED)
    {
        RangeEntry->PublicFlags |= RTL_RANGE_SHARED;
    }
  
    RangeEntry->PublicFlags &= ~RTL_RANGE_CONFLICT;

    /* Insert range entry */
    if (RangeList->Count == 0)
    {
        /* Insert tail */
        InsertTailList(&RangeList->ListHead, &RangeEntry->ListEntry);
        Status =  STATUS_SUCCESS;
    }
    else
    {
        for (Entry = RangeList->ListHead.Flink;
             Entry != &RangeList->ListHead;
             Entry = Entry->Flink)
        {
            Current = CONTAINING_RECORD(Entry, RTLP_RANGE_LIST_ENTRY, ListEntry);
            if (Current->Start > RangeEntry->End)
            {
                /* Insert before current */
                InsertHeadList(Current->ListEntry.Blink, &RangeEntry->ListEntry);
                Status = STATUS_SUCCESS;
                break;
            }

            if ((Current->Start <= RangeEntry->Start || Current->Start <= RangeEntry->End) &&
                (Current->Start > RangeEntry->Start || Current->End > RangeEntry->Start))
            {
                /* Intersecting ranges */
                DPRINT("RtlAddRange: Current [%I64X - %I64X], RangeEntry [%I64X - %I64X]\n",
                       Current->Start, Current->End, RangeEntry->Start, RangeEntry->End);

                ASSERT(FALSE);
                Status = 0;//RtlpAddIntersectingRanges(RangeList, Current, RangeEntry, Flags);
                break;
            }
        }
    }

    if (!NT_SUCCESS(Status))
    {
        ASSERT(FALSE);
        RtlpFreeMemory(RangeEntry, 'elRR');
        //ExFreeToPagedLookasideList(&RtlpRangeListEntryLookasideList, RangeEntry);
    }
    else
    {
        RangeList->Count++;
        RangeList->Stamp++;
    }

    return Status;
}

VOID
NTAPI
RtlpDeleteRangeListEntry(
    IN PRTLP_RANGE_LIST_ENTRY DelEntry)
{
    PRTLP_RANGE_LIST_ENTRY RangeListEntry;
    PRTLP_RANGE_LIST_ENTRY entry;

    PAGED_CODE_RTL();
    DPRINT("RtlpDeleteRangeListEntry: DelEntry - %p\n", DelEntry);

    if (!(DelEntry->PrivateFlags & RTLP_RANGE_LIST_ENTRY_MERGED))
    {
        goto Exit;
    }

    for (RangeListEntry = CONTAINING_RECORD(DelEntry->Merged.ListHead.Flink, RTLP_RANGE_LIST_ENTRY, ListEntry),
                  entry = CONTAINING_RECORD(RangeListEntry->ListEntry.Flink, RTLP_RANGE_LIST_ENTRY, ListEntry);
         &RangeListEntry->ListEntry != &DelEntry->Merged.ListHead;
         RangeListEntry = entry,
                  entry = CONTAINING_RECORD(RangeListEntry->ListEntry.Flink, RTLP_RANGE_LIST_ENTRY, ListEntry))
    {
        DPRINT("RtlpDeleteRangeListEntry: ExFree. RangeListEntry - %p, Start - %X, End - %X\n",
               RangeListEntry, RangeListEntry->Start, RangeListEntry->End);

        //ExFreeToPagedLookasideList(&RtlpRangeListEntryLookasideList, RangeListEntry);
        RtlpFreeMemory(RangeListEntry, 'elRR');
    }

Exit:

    DPRINT("RtlpDeleteRangeListEntry: ExFree. DelEntry - %p, Start - %X, End - %X\n",
           DelEntry, DelEntry->Start, DelEntry->End);

    //ExFreeToPagedLookasideList(&RtlpRangeListEntryLookasideList, DelEntry);
    RtlpFreeMemory(DelEntry, 'elRR');
}

PRTLP_RANGE_LIST_ENTRY
NTAPI
RtlpCopyRangeListEntry(PRTLP_RANGE_LIST_ENTRY listEntry)
{
    PRTLP_RANGE_LIST_ENTRY NewListEntry;
    PRTLP_RANGE_LIST_ENTRY mergedEntry;
    PRTLP_RANGE_LIST_ENTRY NewMergedEntry;

    PAGED_CODE_RTL();
    ASSERT (listEntry);

    NewListEntry = RtlpAllocateMemory(sizeof(RTLP_RANGE_LIST_ENTRY), 'elRR');
    //NewListEntry = ExAllocateFromPagedLookasideList(&RtlpRangeListEntryLookasideList);

    if (!NewListEntry)
    {
        ASSERT(FALSE);
        return NewListEntry;
    }

    DPRINT("RtlpCopyRangeListEntry: (ListEntry - %p) ==> (NewListEntry - %p) [%I64X-%I64X]\n",
           listEntry, NewListEntry, listEntry->Start, listEntry->End);

    RtlCopyMemory(NewListEntry, listEntry, sizeof(RTLP_RANGE_LIST_ENTRY));

    NewListEntry->ListEntry.Flink = NULL;
    NewListEntry->ListEntry.Blink = NULL;

    if (!(listEntry->PrivateFlags & RTLP_RANGE_LIST_ENTRY_MERGED))
    {
        DPRINT("RtlpCopyRangeListEntry: return NewListEntry - %p, !RTLP_RANGE_LIST_ENTRY_MERGED\n",
               NewListEntry);
        return NewListEntry;
    }

    InitializeListHead(&NewListEntry->Merged.ListHead);

    for (mergedEntry = CONTAINING_RECORD(listEntry->Merged.ListHead.Flink, RTLP_RANGE_LIST_ENTRY, ListEntry);
         &mergedEntry->ListEntry != &listEntry->Merged.ListHead;
         mergedEntry = CONTAINING_RECORD(mergedEntry->ListEntry.Flink, RTLP_RANGE_LIST_ENTRY, ListEntry))
    {
        NewMergedEntry = RtlpAllocateMemory(sizeof(RTLP_RANGE_LIST_ENTRY), 'elRR');
        //NewMergedEntry = ExAllocateFromPagedLookasideList(&RtlpRangeListEntryLookasideList);

        if (!NewMergedEntry)
        {
            RtlpDeleteRangeListEntry(NewListEntry);
            return NULL;
        }

        DPRINT("RtlpCopyRangeListEntry: RtlCopyMemory(NewMergedEntry - %p) <== (mergedEntry - %p) [%I64X-%I64X]\n",
               NewMergedEntry, mergedEntry, mergedEntry->Start, mergedEntry->End);

        RtlCopyMemory(NewMergedEntry, mergedEntry, sizeof(RTLP_RANGE_LIST_ENTRY));

        InsertTailList(&NewListEntry->Merged.ListHead, &NewMergedEntry->ListEntry);
    }

    return NewListEntry;
}

/**********************************************************************
 * NAME							EXPORTED
 * 	RtlCopyRangeList
 *
 * DESCRIPTION
 *	Copy a range list.
 *
 * ARGUMENTS
 *	CopyRangeList	Pointer to the destination range list.
 *	RangeList	Pointer to the source range list.
 *
 * RETURN VALUE
 *	Status
 *
 * @implemented
 */
NTSTATUS
NTAPI
RtlCopyRangeList(OUT PRTL_RANGE_LIST CopyRangeList,
                 IN PRTL_RANGE_LIST RangeList)
{
    PRTLP_RANGE_LIST_ENTRY listEntry;
    PRTLP_RANGE_LIST_ENTRY NewListEntry;

    PAGED_CODE_RTL();
    ASSERT(RangeList);
    ASSERT(CopyRangeList);

    DPRINT("RtlCopyRangeList: (CopyRangeList - %p) <== (RangeList - %p) [%X]\n",
           CopyRangeList, RangeList, RangeList->Count);

    if (CopyRangeList->Count)
    {
        DPRINT("RtlCopyRangeList: STATUS_INVALID_PARAMETER. CopyRangeList->Count - %X\n",
               CopyRangeList->Count);

        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }

    CopyRangeList->Flags = RangeList->Flags;
    CopyRangeList->Count = RangeList->Count;
    CopyRangeList->Stamp = RangeList->Stamp;

    for (listEntry = CONTAINING_RECORD(RangeList->ListHead.Flink, RTLP_RANGE_LIST_ENTRY, ListEntry);
         &listEntry->ListEntry!= &RangeList->ListHead;
         listEntry = CONTAINING_RECORD(listEntry->ListEntry.Flink, RTLP_RANGE_LIST_ENTRY, ListEntry))
    {
        //DPRINT("RtlCopyRangeList: ListEntry - %p [%I64X - %I64X], Attributes - %X, PublicFlags - %X, PrivateFlags - %X\n",
        //       listEntry, listEntry->Start, listEntry->End, listEntry->Attributes, listEntry->PublicFlags, listEntry->PrivateFlags);

        NewListEntry = RtlpCopyRangeListEntry(listEntry);

        if (!NewListEntry)
        {
            DPRINT("RtlCopyRangeList: STATUS_INSUFFICIENT_RESOURCES\n");
            ASSERT(FALSE);
            RtlFreeRangeList(CopyRangeList);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        InsertTailList(&CopyRangeList->ListHead, &NewListEntry->ListEntry);
    }

    return STATUS_SUCCESS;
}


/**********************************************************************
 * NAME							EXPORTED
 * 	RtlDeleteOwnersRanges
 *
 * DESCRIPTION
 *	Delete all ranges that belong to the given owner.
 *
 * ARGUMENTS
 *	RangeList	Pointer to the range list.
 *	Owner		User supplied value that identifies the owner
 *			of the ranges to be deleted.
 *
 * RETURN VALUE
 *	Status
 *
 * @implemented
 */
NTSTATUS
NTAPI
RtlDeleteOwnersRanges(
    _In_ PRTL_RANGE_LIST RangeList,
    _In_ PVOID Owner)
{
    PRTLP_RANGE_LIST_ENTRY RangeListEntry;
    PRTLP_RANGE_LIST_ENTRY entry;
    PRTLP_RANGE_LIST_ENTRY MergedListEntry;
    PRTLP_RANGE_LIST_ENTRY mergedentry;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE_RTL();
    ASSERT(RangeList);

    DPRINT("RtlDeleteOwnersRanges: RangeList - %p, Owner - %p, RangeList->Count - %X\n",
           RangeList, Owner, RangeList->Count);

    for (RangeListEntry = CONTAINING_RECORD(RangeList->ListHead.Flink, RTLP_RANGE_LIST_ENTRY, ListEntry),
                  entry = CONTAINING_RECORD(RangeListEntry->ListEntry.Flink, RTLP_RANGE_LIST_ENTRY, ListEntry);
         &RangeListEntry->ListEntry != &RangeList->ListHead;
         RangeListEntry = entry,
                  entry = CONTAINING_RECORD(RangeListEntry->ListEntry.Flink, RTLP_RANGE_LIST_ENTRY, ListEntry))
    {
        if (RangeListEntry->PrivateFlags & RTLP_RANGE_LIST_ENTRY_MERGED)
        {
            for (MergedListEntry = CONTAINING_RECORD(&RangeListEntry->Merged.ListHead.Flink, RTLP_RANGE_LIST_ENTRY, ListEntry),
                     mergedentry = CONTAINING_RECORD(MergedListEntry->ListEntry.Flink, RTLP_RANGE_LIST_ENTRY, ListEntry);
                 &MergedListEntry->ListEntry != &RangeListEntry->Merged.ListHead;
                 MergedListEntry = mergedentry,
                     mergedentry = CONTAINING_RECORD(MergedListEntry->ListEntry.Flink, RTLP_RANGE_LIST_ENTRY, ListEntry))
            {
                if (MergedListEntry->Allocated.Owner == Owner)
                {
                    ASSERT(FALSE);
                }
            }
        }
        else if (RangeListEntry->Allocated.Owner == Owner)
        {
            DPRINT("RtlDeleteOwnersRanges: Deleting range (Start - %I64X, End - %I64X)\n",
                   RangeListEntry->Start, RangeListEntry->End);

            RemoveEntryList(&RangeListEntry->ListEntry);
            //ExFreeToPagedLookasideList(&RtlpRangeListEntryLookasideList, RangeListEntry);
            RtlpFreeMemory(RangeListEntry, 'elRR');

            RangeList->Count--;
            RangeList->Stamp++;

            Status = STATUS_SUCCESS;
        }
    }

    return Status;
}

/**********************************************************************
 * NAME							EXPORTED
 * 	RtlDeleteRange
 *
 * DESCRIPTION
 *	Deletes a given range.
 *
 * ARGUMENTS
 *	RangeList	Pointer to the range list.
 *	Start		Start of the range to be deleted.
 *	End		End of the range to be deleted.
 *	Owner		Owner of the ranges to be deleted.
 *
 * RETURN VALUE
 *	Status
 *
 * @implemented
 */
NTSTATUS
NTAPI
RtlDeleteRange(IN OUT PRTL_RANGE_LIST RangeList,
               IN ULONGLONG Start,
               IN ULONGLONG End,
               IN PVOID Owner)
{
    PRTL_RANGE_ENTRY Current;
    PLIST_ENTRY Entry;

    Entry = RangeList->ListHead.Flink;
    while (Entry != &RangeList->ListHead)
    {
        Current = CONTAINING_RECORD(Entry, RTL_RANGE_ENTRY, Entry);
        if (Current->Range.Start == Start &&
            Current->Range.End == End &&
            Current->Range.Owner == Owner)
        {
            RemoveEntryList(Entry);

            RtlpFreeMemory(Current, 0);

            RangeList->Count--;
            RangeList->Stamp++;
            return STATUS_SUCCESS;
        }

        Entry = Entry->Flink;
    }

    return STATUS_RANGE_NOT_FOUND;
}


/**********************************************************************
 * NAME							EXPORTED
 * 	RtlFindRange
 *
 * DESCRIPTION
 *	Searches for an unused range.
 *
 * ARGUMENTS
 *	RangeList		Pointer to the range list.
 *	Minimum
 *	Maximum
 *	Length
 *	Alignment
 *	Flags
 *	AttributeAvailableMask
 *	Context
 *	Callback
 *	Start
 *
 * RETURN VALUE
 *	Status
 *
 * TODO
 *	Support shared ranges and callback.
 *
 * @implemented
 */
NTSTATUS
NTAPI
RtlFindRange(IN PRTL_RANGE_LIST RangeList,
             IN ULONGLONG Minimum,
             IN ULONGLONG Maximum,
             IN ULONG Length,
             IN ULONG Alignment,
             IN ULONG Flags,
             IN UCHAR AttributeAvailableMask,
             IN PVOID Context OPTIONAL,
             IN PRTL_CONFLICT_RANGE_CALLBACK Callback OPTIONAL,
             OUT PULONGLONG Start)
{
    PRTL_RANGE_ENTRY CurrentEntry;
    PRTL_RANGE_ENTRY NextEntry;
    PLIST_ENTRY Entry;
    ULONGLONG RangeMin;
    ULONGLONG RangeMax;

    if (Alignment == 0 || Length == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (IsListEmpty(&RangeList->ListHead))
    {
        *Start = ROUND_DOWN(Maximum - (Length - 1), Alignment);
        return STATUS_SUCCESS;
    }

    NextEntry = NULL;
    Entry = RangeList->ListHead.Blink;
    while (Entry != &RangeList->ListHead)
    {
        CurrentEntry = CONTAINING_RECORD(Entry, RTL_RANGE_ENTRY, Entry);

        RangeMax = NextEntry ? (NextEntry->Range.Start - 1) : Maximum;
        if (RangeMax + (Length - 1) < Minimum)
        {
            return STATUS_RANGE_NOT_FOUND;
        }

        RangeMin = ROUND_DOWN(RangeMax - (Length - 1), Alignment);
        if (RangeMin < Minimum ||
            (RangeMax - RangeMin) < (Length - 1))
        {
            return STATUS_RANGE_NOT_FOUND;
        }

        DPRINT("RangeMax: %I64x\n", RangeMax);
        DPRINT("RangeMin: %I64x\n", RangeMin);

        if (RangeMin > CurrentEntry->Range.End)
        {
            *Start = RangeMin;
            return STATUS_SUCCESS;
        }

        NextEntry = CurrentEntry;
        Entry = Entry->Blink;
    }

    RangeMax = NextEntry ? (NextEntry->Range.Start - 1) : Maximum;
    if (RangeMax + (Length - 1) < Minimum)
    {
        return STATUS_RANGE_NOT_FOUND;
    }

    RangeMin = ROUND_DOWN(RangeMax - (Length - 1), Alignment);
    if (RangeMin < Minimum ||
        (RangeMax - RangeMin) < (Length - 1))
    {
        return STATUS_RANGE_NOT_FOUND;
    }

    DPRINT("RangeMax: %I64x\n", RangeMax);
    DPRINT("RangeMin: %I64x\n", RangeMin);

    *Start = RangeMin;

    return STATUS_SUCCESS;
}


/**********************************************************************
 * NAME							EXPORTED
 * 	RtlFreeRangeList
 *
 * DESCRIPTION
 *	Deletes all ranges in a range list.
 *
 * ARGUMENTS
 *	RangeList	Pointer to the range list.
 *
 * RETURN VALUE
 *	None
 *
 * @implemented
 */
NTSYSAPI
VOID
NTAPI
RtlFreeRangeList(
    _In_ PRTL_RANGE_LIST RangeList)
{
    PRTLP_RANGE_LIST_ENTRY entry;
    PRTLP_RANGE_LIST_ENTRY RangeListEntry;

    PAGED_CODE_RTL();
    ASSERT(RangeList);

    DPRINT("RtlFreeRangeList: RangeList - %p, RangeList->Count - %X\n",
           RangeList, RangeList->Count);

    RangeList->Flags = 0;
    RangeList->Count = 0;

    for (RangeListEntry = CONTAINING_RECORD(RangeList->ListHead.Flink, RTLP_RANGE_LIST_ENTRY, ListEntry),
                  entry = CONTAINING_RECORD(RangeListEntry->ListEntry.Flink, RTLP_RANGE_LIST_ENTRY, ListEntry);
         &RangeListEntry->ListEntry != &RangeList->ListHead;
         RangeListEntry = entry,
                  entry = CONTAINING_RECORD(RangeListEntry->ListEntry.Flink, RTLP_RANGE_LIST_ENTRY, ListEntry))
    {
        RemoveEntryList(&RangeListEntry->ListEntry);
        RtlpDeleteRangeListEntry(RangeListEntry);
    }
}

/**********************************************************************
 * NAME							EXPORTED
 * 	RtlGetFirstRange
 *
 * DESCRIPTION
 *	Retrieves the first range of a range list.
 *
 * ARGUMENTS
 *	RangeList	Pointer to the range list.
 *	Iterator	Pointer to a user supplied list state buffer.
 *	Range		Pointer to the first range.
 *
 * RETURN VALUE
 *	Status
 *
 * @implemented
 */
NTSTATUS
NTAPI
RtlGetFirstRange(IN PRTL_RANGE_LIST RangeList,
                 OUT PRTL_RANGE_LIST_ITERATOR Iterator,
                 OUT PRTL_RANGE *Range)
{
    Iterator->RangeListHead = &RangeList->ListHead;
    Iterator->MergedHead = NULL;
    Iterator->Stamp = RangeList->Stamp;

    if (IsListEmpty(&RangeList->ListHead))
    {
        Iterator->Current = NULL;
        *Range = NULL;
        return STATUS_NO_MORE_ENTRIES;
    }

    Iterator->Current = RangeList->ListHead.Flink;
    *Range = &((PRTL_RANGE_ENTRY)Iterator->Current)->Range;

    return STATUS_SUCCESS;
}


/**********************************************************************
 * NAME							EXPORTED
 * 	RtlGetNextRange
 *
 * DESCRIPTION
 *	Retrieves the next (or previous) range of a range list.
 *
 * ARGUMENTS
 *	Iterator	Pointer to a user supplied list state buffer.
 *	Range		Pointer to the first range.
 *	MoveForwards	TRUE, get next range
 *			FALSE, get previous range
 *
 * RETURN VALUE
 *	Status
 *
 * @implemented
 */
NTSTATUS
NTAPI
RtlGetNextRange(IN OUT PRTL_RANGE_LIST_ITERATOR Iterator,
                OUT PRTL_RANGE *Range,
                IN BOOLEAN MoveForwards)
{
    PRTL_RANGE_LIST RangeList;
    PLIST_ENTRY Next;

    RangeList = CONTAINING_RECORD(Iterator->RangeListHead, RTL_RANGE_LIST, ListHead);
    if (Iterator->Stamp != RangeList->Stamp)
        return STATUS_INVALID_PARAMETER;

    if (MoveForwards)
    {
        Next = ((PRTL_RANGE_ENTRY)Iterator->Current)->Entry.Flink;
    }
    else
    {
        Next = ((PRTL_RANGE_ENTRY)Iterator->Current)->Entry.Blink;
    }

    if (Next == Iterator->RangeListHead)
        return STATUS_NO_MORE_ENTRIES;

    Iterator->Current = Next;
    *Range = &((PRTL_RANGE_ENTRY)Next)->Range;

    return STATUS_SUCCESS;
}


/**********************************************************************
 * NAME							EXPORTED
 * 	RtlInitializeRangeList
 *
 * DESCRIPTION
 *	Initializes a range list.
 *
 * ARGUMENTS
 *	RangeList	Pointer to a user supplied range list.
 *
 * RETURN VALUE
 *	None
 *
 * @implemented
 */
VOID
NTAPI
RtlInitializeRangeList(IN OUT PRTL_RANGE_LIST RangeList)
{
    InitializeListHead(&RangeList->ListHead);
    RangeList->Flags = 0;
    RangeList->Count = 0;
    RangeList->Stamp = 0;
}


/**********************************************************************
 * NAME							EXPORTED
 * 	RtlInvertRangeList
 *
 * DESCRIPTION
 *	Inverts a range list.
 *
 * ARGUMENTS
 *	InvertedRangeList	Inverted range list.
 *	RangeList		Range list.
 *
 * RETURN VALUE
 *	Status
 *
 * @implemented
 */
NTSTATUS
NTAPI
RtlInvertRangeList(OUT PRTL_RANGE_LIST InvertedRangeList,
                   IN PRTL_RANGE_LIST RangeList)
{
    PRTL_RANGE_ENTRY Previous;
    PRTL_RANGE_ENTRY Current;
    PLIST_ENTRY Entry;
    NTSTATUS Status;

    /* Add leading and intermediate ranges */
    Previous = NULL;
    Entry = RangeList->ListHead.Flink;
    while (Entry != &RangeList->ListHead)
    {
        Current = CONTAINING_RECORD(Entry, RTL_RANGE_ENTRY, Entry);

        if (Previous == NULL)
        {
            if (Current->Range.Start != (ULONGLONG)0)
            {
                Status = RtlAddRange(InvertedRangeList,
                                     (ULONGLONG)0,
                                     Current->Range.Start - 1,
                                     0,
                                     0,
                                     NULL,
                                     NULL);
                if (!NT_SUCCESS(Status))
                    return Status;
            }
        }
        else
        {
            if (Previous->Range.End + 1 != Current->Range.Start)
            {
                Status = RtlAddRange(InvertedRangeList,
                                     Previous->Range.End + 1,
                                     Current->Range.Start - 1,
                                     0,
                                     0,
                                     NULL,
                                     NULL);
                if (!NT_SUCCESS(Status))
                    return Status;
            }
        }

        Previous = Current;
        Entry = Entry->Flink;
    }

    /* Check if the list was empty */
    if (Previous == NULL)
    {
        /* We're done */
        return STATUS_SUCCESS;
    }

    /* Add trailing range */
    if (Previous->Range.End + 1 != (ULONGLONG)-1)
    {
        Status = RtlAddRange(InvertedRangeList,
                             Previous->Range.End + 1,
                             (ULONGLONG)-1,
                             0,
                             0,
                             NULL,
                             NULL);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    return STATUS_SUCCESS;
}


/**********************************************************************
 * NAME							EXPORTED
 * 	RtlIsRangeAvailable
 *
 * DESCRIPTION
 *	Checks whether a range is available or not.
 *
 * ARGUMENTS
 *	RangeList		Pointer to the range list.
 *	Start
 *	End
 *	Flags
 *	AttributeAvailableMask
 *	Context
 *	Callback
 *	Available
 *
 * RETURN VALUE
 *	Status
 *
 * TODO:
 *   - honor Flags and AttributeAvailableMask.
 *
 * @implemented
 */
NTSTATUS
NTAPI
RtlIsRangeAvailable(IN PRTL_RANGE_LIST RangeList,
                    IN ULONGLONG Start,
                    IN ULONGLONG End,
                    IN ULONG Flags,
                    IN UCHAR AttributeAvailableMask,
                    IN PVOID Context OPTIONAL,
                    IN PRTL_CONFLICT_RANGE_CALLBACK Callback OPTIONAL,
                    OUT PBOOLEAN Available)
{
    PRTL_RANGE_ENTRY Current;
    PLIST_ENTRY Entry;

    *Available = TRUE;

    Entry = RangeList->ListHead.Flink;
    while (Entry != &RangeList->ListHead)
    {
        Current = CONTAINING_RECORD (Entry, RTL_RANGE_ENTRY, Entry);

        if (!((Current->Range.Start >= End && Current->Range.End > End) ||
              (Current->Range.Start <= Start && Current->Range.End < Start &&
               (!(Flags & RTL_RANGE_SHARED) ||
                !(Current->Range.Flags & RTL_RANGE_SHARED)))))
        {
            if (Callback != NULL)
            {
                *Available = Callback(Context,
                                      &Current->Range);
            }
            else
            {
                *Available = FALSE;
            }
        }

        Entry = Entry->Flink;
    }

    return STATUS_SUCCESS;
}


/**********************************************************************
 * NAME							EXPORTED
 * 	RtlMergeRangeList
 *
 * DESCRIPTION
 *	Merges two range lists.
 *
 * ARGUMENTS
 *	MergedRangeList	Resulting range list.
 *	RangeList1	First range list.
 *	RangeList2	Second range list
 *	Flags
 *
 * RETURN VALUE
 *	Status
 *
 * @implemented
 */
NTSTATUS
NTAPI
RtlMergeRangeLists(OUT PRTL_RANGE_LIST MergedRangeList,
                   IN PRTL_RANGE_LIST RangeList1,
                   IN PRTL_RANGE_LIST RangeList2,
                   IN ULONG Flags)
{
    RTL_RANGE_LIST_ITERATOR Iterator;
    PRTL_RANGE Range;
    NTSTATUS Status;

    /* Copy range list 1 to the merged range list */
    Status = RtlCopyRangeList(MergedRangeList,
                              RangeList1);
    if (!NT_SUCCESS(Status))
        return Status;

    /* Add range list 2 entries to the merged range list */
    Status = RtlGetFirstRange(RangeList2,
                              &Iterator,
                              &Range);
    if (!NT_SUCCESS(Status))
        return (Status == STATUS_NO_MORE_ENTRIES) ? STATUS_SUCCESS : Status;

    while (TRUE)
    {
        Status = RtlAddRange(MergedRangeList,
                             Range->Start,
                             Range->End,
                             Range->Attributes,
                             Range->Flags | Flags,
                             Range->UserData,
                             Range->Owner);
        if (!NT_SUCCESS(Status))
            break;

        Status = RtlGetNextRange(&Iterator,
                                 &Range,
                                 TRUE);
        if (!NT_SUCCESS(Status))
            break;
    }

    return (Status == STATUS_NO_MORE_ENTRIES) ? STATUS_SUCCESS : Status;
}

/* EOF */
