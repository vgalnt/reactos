
/* INCLUDES *******************************************************************/

#include "ranges.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

static
ULONG
HalpRangeListOffset[5] = {
    FIELD_OFFSET(SUPPORTED_RANGES, IO),
    FIELD_OFFSET(SUPPORTED_RANGES, Memory),
    FIELD_OFFSET(SUPPORTED_RANGES, PrefetchMemory),
    FIELD_OFFSET(SUPPORTED_RANGES, Dma),
    0 
};

/* FUNCTIONS **********************************************************/

VOID
NTAPI
HalpConsolidateRanges(
    _In_ PSUPPORTED_RANGES Ranges)
{
    PSUPPORTED_RANGE FirstRange;
    PSUPPORTED_RANGE Range;
    PSUPPORTED_RANGE NextRange;
    LONGLONG SystemBase;
    LONGLONG Base;
    LONGLONG Limit;
    LONGLONG RangeLimit;
    ULONG SystemAddressSpace;
    ULONG ix;

    DPRINT("HalpConsolidateRanges: Ranges - %p\n", Ranges);

    ASSERT(Ranges != NULL);

    for (ix = 0; HalpRangeListOffset[ix]; ix++)
    {
        FirstRange = (PSUPPORTED_RANGE)((ULONG_PTR)Ranges + HalpRangeListOffset[ix]);

        DPRINT("HalpConsolidateRanges: HalpRangeListOffset[%X] - %X, FirstRange - %p\n",
               ix, HalpRangeListOffset[ix], FirstRange);

        for (Range = FirstRange; Range; Range = Range->Next)
        {
            for (NextRange = Range->Next;
                 NextRange;
                 NextRange = NextRange->Next)
            {
                if (NextRange->Base < Range->Base)
                {
                    SystemAddressSpace = Range->SystemAddressSpace;
                    SystemBase = Range->SystemBase;
                    Base = Range->Base;
                    Limit = Range->Limit;

                    Range->SystemAddressSpace = NextRange->SystemAddressSpace;
                    Range->SystemBase = NextRange->SystemBase;
                    Range->Base = NextRange->Base;
                    Range->Limit = NextRange->Limit;

                    NextRange->SystemAddressSpace = SystemAddressSpace;
                    NextRange->SystemBase = SystemBase;
                    NextRange->Base = Base;
                    NextRange->Limit = Limit;
                }
            }
        }

        for (Range = FirstRange;
             Range && Range->Next;
             Range = Range->Next)
        {
            DPRINT("HalpConsolidateRanges: Range - %p, SysAddr - %X, SysBase - %I64X, Base - %I64X, Limit - %I64X\n",
                   Range, Range->SystemAddressSpace, Range->SystemBase, Range->Base, Range->Limit);

            NextRange = Range->Next;

            if (Range->Limit < Range->Base)
            {
                *Range = *NextRange;
                DPRINT("HalpConsolidateRanges: ExFreePoolWithTag(NextRange - %p)\n", NextRange);
                ExFreePoolWithTag(NextRange, TAG_HAL);
                continue;
            }

            RangeLimit = Range->Limit + 1;

            if (RangeLimit > Range->Limit && RangeLimit > NextRange->Base)
            {
                Range->Next = NextRange->Next;

                if (NextRange->Limit > Range->Limit)
                {
                    Range->Limit = NextRange->Limit;
                    ASSERT(Range->SystemBase == NextRange->SystemBase);
                    ASSERT(Range->SystemAddressSpace == NextRange->SystemAddressSpace);
                }

                DPRINT("HalpConsolidateRanges: ExFreePoolWithTag(NextRange - %p)\n", NextRange);
                ExFreePoolWithTag(NextRange, TAG_HAL);
                continue;
            }
        }

        if (Range != FirstRange && Range->Limit < Range->Base)
        {
            for (NextRange = FirstRange;
                 NextRange != Range;
                 NextRange = NextRange->Next)
            {
                ;
            }

            NextRange->Next = NULL;
            DPRINT("HalpConsolidateRanges: ExFreePoolWithTag(Range - %p)\n", Range);
            ExFreePoolWithTag(Range, TAG_HAL);
        }
    }
}

PSUPPORTED_RANGES
NTAPI 
HalpAllocateNewRangeList()
{
    PSUPPORTED_RANGES NewRangeList;

    PAGED_CODE();

    NewRangeList = ExAllocatePoolWithTag(NonPagedPool, sizeof(SUPPORTED_RANGES), TAG_HAL);
    if (!NewRangeList)
    {
        ASSERT(FALSE);
        return NULL;
    }
    RtlZeroMemory(NewRangeList, sizeof(SUPPORTED_RANGES));

    DPRINT("HalpAllocateNewRangeList: NewRangeList- %p\n", NewRangeList);

    NewRangeList->Version = HAL_SUPPORTED_RANGE_VERSION;

    NewRangeList->IO.Base = 1;
    NewRangeList->Memory.Base = 1;
    NewRangeList->PrefetchMemory.Base = 1;
    NewRangeList->Dma.Base = 1;

    return NewRangeList;
}

VOID
NTAPI 
HalpMergeRangeList(
    _In_ PSUPPORTED_RANGE NewRange,
    _In_ PSUPPORTED_RANGE Range1,
    _In_ PSUPPORTED_RANGE Range2)
{
    PSUPPORTED_RANGE Entry1;
    PSUPPORTED_RANGE Entry2;
    LONGLONG Base;
    LONGLONG Limit;
    BOOLEAN IsFirstEntry = TRUE;

    DPRINT("HalpMergeRangeList: NewRange - %p, Range1 - %p, Range2 - %p\n",
           NewRange, Range1, Range2);

    for (Entry1 = Range1;
         Entry1;
         Entry1 = Entry1->Next)
    {
        for (Entry2 = Range2;
             Entry2;
             Entry2 = Entry2->Next)
        {
            if (Entry1->Base < Entry2->Base)
            {
                Base = Entry2->Base;
            }
            else
            {
                Base = Entry1->Base;
            }

            if (Entry1->Limit > Entry2->Limit)
            {
                Limit = Entry2->Limit;
            }
            else
            {
                Limit = Entry1->Limit;
            }

            if (Base > Limit)
            {
                continue;
            }

            if (IsFirstEntry)
            {
                NewRange->SystemAddressSpace = Entry2->SystemAddressSpace;
                NewRange->SystemBase = Entry2->SystemBase;
                NewRange->Base = Base;
                NewRange->Limit = Limit;

                IsFirstEntry = FALSE;
            }
            else
            {
                NewRange->Next = ExAllocatePoolWithTag(NonPagedPool,
                                                       sizeof(SUPPORTED_RANGE),
                                                       TAG_HAL);
                if (!NewRange->Next)
                {
                    ASSERT(FALSE);
                    return;
                }

                RtlZeroMemory(NewRange->Next, sizeof(SUPPORTED_RANGE));

                NewRange = NewRange->Next;
                NewRange->Next = NULL;
            }
        }
    }
}

VOID
NTAPI
HalpAddRange(
    _Out_ PSUPPORTED_RANGE Range,
    _In_ ULONG SystemAddressSpace,
    _In_ ULONGLONG SystemBase,
    _In_ ULONGLONG Base,
    _In_ ULONGLONG Limit)
{
    PSUPPORTED_RANGE NewRange;

    DPRINT("HalpAddRange: Range - %p, SystemAddressSpace - %X, SystemBase - %I64X, Base - %I64X, Limit - %I64X\n", Range, SystemAddressSpace, SystemBase, Base, Limit);

    NewRange = ExAllocatePoolWithTag(NonPagedPool, sizeof(SUPPORTED_RANGE), TAG_HAL);

    if (!NewRange)
    {
        ASSERT(FALSE);
        return;
    }

    RtlZeroMemory(NewRange, sizeof(SUPPORTED_RANGE));

    NewRange->Next = Range->Next;
    Range->Next = NewRange;

    NewRange->SystemAddressSpace = SystemAddressSpace;
    NewRange->SystemBase = SystemBase;
    NewRange->Base = Base;
    NewRange->Limit = Limit;
}

VOID
NTAPI 
HalpAddRangeList(
    _In_ PSUPPORTED_RANGE Range1,
    _In_ PSUPPORTED_RANGE Range2)
{
    PSUPPORTED_RANGE Range;

    DPRINT("HalpAddRangeList: Range1 - %p, Range2 - %p\n", Range1, Range2);

    for (Range = Range2; Range; Range = Range->Next)
    {
        HalpAddRange(Range1,
                     Range->SystemAddressSpace,
                     Range->SystemBase,
                     Range->Base,
                     Range->Limit);
    }
}

VOID
NTAPI 
HalpFreeRangeList(
    _In_ PSUPPORTED_RANGES List)
{
    PSUPPORTED_RANGE Range;
    PSUPPORTED_RANGE NextRange;

    DPRINT("HalpFreeRangeList: List - %p\n");

    for (Range = List->IO.Next; Range; Range = NextRange)
    {
        NextRange = Range->Next;
        ExFreePoolWithTag(Range, TAG_HAL);
    }

    for (Range = List->Memory.Next; Range; Range = NextRange)
    {
        NextRange = Range->Next;
        ExFreePoolWithTag(Range, TAG_HAL);
    }

    for (Range = List->PrefetchMemory.Next; Range; Range = NextRange)
    {
        NextRange = Range->Next;
        ExFreePoolWithTag(Range, TAG_HAL);
    }

    for (Range = List->Dma.Next; Range; Range = NextRange)
    {
        NextRange = Range->Next;
        ExFreePoolWithTag(Range, TAG_HAL);
    }

    ExFreePoolWithTag(List, TAG_HAL);
}

PSUPPORTED_RANGES
NTAPI 
HalpMergeRanges(
    _In_ PSUPPORTED_RANGES List1,
    _In_ PSUPPORTED_RANGES List2)
{
    PSUPPORTED_RANGES NewList;
    PSUPPORTED_RANGES TempList;

    DPRINT("HalpMergeRanges: List1 - %p, List2 - %p\n", List1, List2);

    NewList = HalpAllocateNewRangeList();

    if (!NewList)
    {
        ASSERT(FALSE);
        return NULL;
    }

    HalpMergeRangeList(&NewList->IO, &List1->IO, &List2->IO);
    HalpMergeRangeList(&NewList->Dma, &List1->Dma, &List2->Dma);
    HalpMergeRangeList(&NewList->Memory, &List1->Memory, &List2->Memory);

    TempList = HalpAllocateNewRangeList();

    if (!TempList)
    {
        ASSERT(FALSE);
        HalpFreeRangeList(NewList);
        return NULL;
    }

    HalpAddRangeList(&TempList->Memory, &List1->Memory);
    HalpAddRangeList(&TempList->Memory, &List1->PrefetchMemory);

    HalpMergeRangeList(&NewList->PrefetchMemory, &TempList->Memory, &List2->PrefetchMemory);

    HalpFreeRangeList(TempList);

    return NewList;
}

VOID
NTAPI 
HalpRemoveRange(
    _In_ PSUPPORTED_RANGE Range,
    _In_ LONGLONG Base,
    _In_ LONGLONG Limit)
{
    PSUPPORTED_RANGE Current;

    DPRINT("HalpRemoveRange: Range - %p, Base - %I64X, Limit - %I64X\n", Range, Base, Limit);

    if (Base > Limit)
    {
        return;
    }

    for (Current = Range; Current; Current = Current->Next)
    {
        if (Current->Base > Current->Limit)
        {
            continue;
        }

        if (Current->Base >= Base)
        {
            if (Current->Base <= Limit)
            {
                if (Current->Limit > Limit)
                {
                    Current->Base = Limit + 1;
                }
                else
                {
                    Current->Base = 1;
                    Current->Limit = 0;
                }
            }
        }
        else
        {
            /* Base > Current->Base */

            if (Current->Limit >= Base &&
                Current->Limit <= Limit)
            {
                Current->Limit = Base - 1;
            }

            if (Current->Limit > Limit)
            {
                HalpAddRange(Range,
                             Current->SystemAddressSpace,
                             Current->SystemBase,
                             Limit + 1,
                             Current->Limit);

                Current->Limit = Base - 1;
            }
        }
    }
}

/* EOF */
