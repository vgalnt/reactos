
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
    PAGED_CODE();
    DPRINT("HalpAllocateNewRangeList()\n");
    ASSERT(FALSE);
    return NULL;
}

VOID
NTAPI 
HalpMergeRangeList(
    _In_ PSUPPORTED_RANGE NewRange,
    _In_ PSUPPORTED_RANGE Range1,
    _In_ PSUPPORTED_RANGE Range2)
{
    DPRINT("HalpMergeRangeList: NewRange - %p, Range1 - %p, Range2 - %p\n",
           NewRange, Range1, Range2);
    ASSERT(FALSE);
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
    DPRINT("HalpAddRangeList: Range1 - %p, Range2 - %p\n", Range1, Range2);
    ASSERT(FALSE);
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
    DPRINT("HalpMergeRanges: List1 - %p, List2 - %p\n", List1, List2);
    ASSERT(FALSE);
    return NULL;
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
