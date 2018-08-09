
/* INCLUDES *******************************************************************/

#include "ranges.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

/* FUNCTIONS **********************************************************/

VOID
NTAPI
HalpConsolidateRanges(
    _In_ PSUPPORTED_RANGES Ranges)
{
    DPRINT("HalpConsolidateRanges: Ranges - %p\n", Ranges);
    ASSERT(FALSE);
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
    PSUPPORTED_RANGE Range,
    _In_ ULONG SystemAddressSpace,
    _In_ ULONGLONG SystemBase,
    _In_ ULONGLONG Base,
    _In_ ULONGLONG Limit)
{
    DPRINT("HalpAddRange: Range - %p, SystemAddressSpace - %X, SystemBase - %I64X, Base - %I64X, Limit - %I64X\n",
           Range, SystemAddressSpace, SystemBase, Base, Limit);
    ASSERT(FALSE);
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
    DPRINT("HalpFreeRangeList: List - %p\n", List);
    ASSERT(FALSE);
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
    DPRINT("HalpRemoveRange: Range - %p, Base - %I64X, Limit - %I64X\n", Range, Base, Limit);
    ASSERT(FALSE);
}

/* EOF */
