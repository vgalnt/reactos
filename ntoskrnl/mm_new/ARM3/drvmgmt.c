
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "miarm.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

MM_DRIVER_VERIFIER_DATA MmVerifierData;
LIST_ENTRY MiVerifierDriverAddedThunkListHead;
WCHAR MmVerifyDriverBuffer[512] = {0};
ULONG MmVerifyDriverBufferLength = sizeof(MmVerifyDriverBuffer);
ULONG MmVerifyDriverBufferType = REG_NONE;
ULONG MmVerifyDriverLevel = -1;
PVOID MmTriageActionTaken;
PVOID KernelVerifier;

/* FUNCTIONS ******************************************************************/

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(INIT, MiInitializeDriverVerifierList)
  #pragma alloc_text(PAGE, MmAddVerifierThunks)
  #pragma alloc_text(PAGE, MmIsVerifierEnabled)
  #pragma alloc_text(PAGE, MmLockPageableDataSection)
  #pragma alloc_text(PAGE, MmLockPageableSectionByHandle)
#endif

CODE_SEG("INIT")
VOID
NTAPI
MiInitializeDriverVerifierList(VOID)
{
    //FIXME
    InitializeListHead(&MiVerifierDriverAddedThunkListHead);
}

/* PUBLIC FUNCTIONS ***********************************************************/

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmAddVerifierThunks(
    _In_ PVOID ThunkBuffer,
    _In_ ULONG ThunkBufferSize)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

LOGICAL
NTAPI
MmIsDriverVerifying(
    _In_ PDRIVER_OBJECT DriverObject)
{
    PLDR_DATA_TABLE_ENTRY LdrEntry;

    /* Get the loader entry */
    LdrEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!LdrEntry)
        return FALSE;

    /* Check if we're verifying or not */
    return ((LdrEntry->Flags & LDRP_IMAGE_VERIFYING) ? TRUE: FALSE);
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
MmIsVerifierEnabled(
    _Out_ PULONG VerifierFlags)
{
    /* Check if we've actually added anything to the list */
    if (MiVerifierDriverAddedThunkListHead.Flink)
    {
        UNIMPLEMENTED;

        /* We have, read the verifier level */

        //*VerifierFlags = MmVerifierData.Level;
        //return STATUS_SUCCESS;
    }

    /* Otherwise, we're disabled */
    *VerifierFlags = 0;
    return STATUS_NOT_SUPPORTED;
}

CODE_SEG("PAGE")
PVOID
NTAPI
MmLockPageableDataSection(
    _In_ PVOID AddressWithinSection)
{
    /* We should just find the section and call MmLockPageableSectionByHandle */
    static ULONG Warn;

    if (!Warn++)
    {
        UNIMPLEMENTED;
    }

    return AddressWithinSection;
}

CODE_SEG("PAGE")
VOID
NTAPI
MmLockPageableSectionByHandle(
    _In_ PVOID ImageSectionHandle)
{
    UNIMPLEMENTED_DBGBREAK();
}

ULONG
NTAPI
MmTrimAllSystemPageableMemory(
    _In_ ULONG PurgeTransitionList)
{
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

VOID
NTAPI
MmUnlockPageableImageSection(
    _In_ PVOID ImageSectionHandle)
{
    static ULONG Warn;

    if (!Warn++)
    {
        UNIMPLEMENTED;
    }
}

/* EOF */
