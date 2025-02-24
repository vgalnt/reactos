/*
 * COPYRIGHT:       GPL, see COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            drivers/base/kdnet/kdnet.c
 * PURPOSE:         Functions for the kernel debugger over Net.
 * PROGRAMMER:      
 */

/* NTDDI_WINBLUE */
#include "kdnet.h"

/* GLOBALS ********************************************************************/

ULONG (*DbgPrint0)(_In_ const PCHAR Format, ...);
BOOLEAN IsDbgComInitialized = FALSE;

KD_NIC_DATA KdNicData;

LIST_ENTRY QueuedTxListHead;

/* PRIVATE FUNCTIONS **********************************************************/

VOID
NTAPI
KdNetNicInitialize(VOID)
{
    KdNicData.Version = 3;
    KdNicData.Size = sizeof(KD_NIC_DATA);

    KdNicData.Reserved0 = 0;
    KdNicData.LinkSpeed1 = 1000;

    KdNicData.Status = STATUS_ADAPTER_HARDWARE_ERROR;

    KdNicData.Reserved1 = 0;
    KdNicData.Reserved2 = 0;

    InitializeSListHead(&KdNicData.sListHead);
    InitializeSListHead(&KdNicData.sListHead1);
    InitializeSListHead(&KdNicData.sListHead2);

    KdNicData.LinkState = 0;
    KdNicData.Reserved3 = 0;
    KdNicData.LinkSpeed2 = 1000;

    InitializeListHead(&QueuedTxListHead);
}

/* PUBLIC FUNCTIONS ***********************************************************/

NTSTATUS
NTAPI
KdD0Transition(VOID)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdD0Transition: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
KdD3Transition(VOID)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdD3Transition: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
KdDebuggerInitialize0(
    _In_opt_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    if (!IsDbgComInitialized)
    {
        if (LoaderBlock->u.I386.CommonDataArea)
        {
            DbgPrint0 = LoaderBlock->u.I386.CommonDataArea;
            IsDbgComInitialized = TRUE;
        }
    }

    if (IsDbgComInitialized)
        DbgPrint0("KdDebuggerInitialize0: LoaderBlock %p\n", LoaderBlock);

    KeBugCheck(MANUALLY_INITIATED_CRASH);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
KdDebuggerInitialize1(
    _In_opt_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdDebuggerInitialize1: Unimplemented! LoaderBlock %p\n", LoaderBlock);

    KeBugCheck(MANUALLY_INITIATED_CRASH);
    return STATUS_NOT_IMPLEMENTED;
}

KDP_STATUS
NTAPI
KdReceivePacket(
    _In_ ULONG PacketType,
    _Out_ PSTRING MessageHeader,
    _Out_ PSTRING MessageData,
    _Out_ ULONG* OutDataLength,
    _Inout_ PKD_CONTEXT KdContext)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdReceivePacket: %X, %p, %p\n", PacketType, MessageHeader, MessageData);

    KeBugCheck(MANUALLY_INITIATED_CRASH);
    return 0;
}

NTSTATUS
NTAPI
KdRestore(
    _In_ BOOLEAN SleepTransition)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdRestore: SleepTransition %x\n", SleepTransition);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdSave(
    _In_ BOOLEAN SleepTransition)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdSave: SleepTransition %x\n", SleepTransition);
    return STATUS_SUCCESS;
}

VOID
NTAPI
KdSendPacket(
    _In_ ULONG PacketType,
    _In_ PSTRING MessageHeader,
    _In_ PSTRING MessageData,
    _Inout_ PKD_CONTEXT KdContext)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdSendPacket: %X, %p, %p\n", PacketType, MessageHeader, MessageData);
    KeBugCheck(MANUALLY_INITIATED_CRASH);
}

NTSTATUS
NTAPI
KdSetHiberRange(VOID)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdD0Transition: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
    return STATUS_NOT_IMPLEMENTED;
}

/* EOF */
