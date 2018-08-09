#ifndef HAL_RANGES_H
#define HAL_RANGES_H

#include <hal.h>

VOID
NTAPI 
HalpRemoveRange(
    _In_ PSUPPORTED_RANGE Range,
    _In_ LONGLONG Base,
    _In_ LONGLONG Limit
);

VOID
NTAPI
HalpConsolidateRanges(
    _In_ PSUPPORTED_RANGES Ranges
);

PSUPPORTED_RANGES
NTAPI 
HalpMergeRanges(
    _In_ PSUPPORTED_RANGES List1,
    _In_ PSUPPORTED_RANGES List2
);

VOID
NTAPI 
HalpFreeRangeList(
    _In_ PSUPPORTED_RANGES List
);

#endif // HAL_RANGES_H

