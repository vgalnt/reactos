
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "miarm.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/


/* FUNCTIONS ******************************************************************/


/* PUBLIC FUNCTIONS ***********************************************************/

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(PAGELK, MmAddPhysicalMemory)
  #pragma alloc_text(PAGELK, MmGetPhysicalMemoryRanges)
  #pragma alloc_text(PAGE, MmMarkPhysicalMemoryAsBad)
  #pragma alloc_text(PAGELK, MmMarkPhysicalMemoryAsGood)
  #pragma alloc_text(PAGE, MmRemovePhysicalMemory)
#endif

CODE_SEG("PAGELK")
NTSTATUS
NTAPI
MmAddPhysicalMemory(
    _In_ PPHYSICAL_ADDRESS StartAddress,
    _Inout_ PLARGE_INTEGER NumberOfBytes)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

CODE_SEG("PAGELK")
PPHYSICAL_MEMORY_RANGE
NTAPI
MmGetPhysicalMemoryRanges(VOID)
{
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmMarkPhysicalMemoryAsBad(
    _In_ PPHYSICAL_ADDRESS StartAddress,
    _Inout_ PLARGE_INTEGER NumberOfBytes)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

CODE_SEG("PAGELK")
NTSTATUS
NTAPI
MmMarkPhysicalMemoryAsGood(
    _In_ PPHYSICAL_ADDRESS StartAddress,
    _Inout_ PLARGE_INTEGER NumberOfBytes)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmRemovePhysicalMemory(
    _In_ PPHYSICAL_ADDRESS StartAddress,
    _Inout_ PLARGE_INTEGER NumberOfBytes)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* EOF */
