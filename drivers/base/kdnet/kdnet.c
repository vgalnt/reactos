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

KDNET_EXTENSIBILITY_EXPORT KdNetExports;
KD_NIC_DATA KdNicData;

LONG KdNetExtensibilityInitCount;

LIST_ENTRY QueuedTxListHead;
NTSTATUS KdNetExtensibilityInitStatus = STATUS_ALREADY_REGISTERED;
NTSTATUS KdNetErrorStatus;
PWSTR KdNetErrorString;
ULONG KdNetHardwareID;

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

ULONG
NTAPI
KdNetGetPciDataByOffset(
    _In_ ULONG Bus,
    _In_ ULONG Slot,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdNetGetPciDataByOffset: %X, %X, %p, %X, %X\n", Bus, Slot, Buffer, Offset, Length);

    if (IsDbgComInitialized)
        DbgPrint0("KdNetGetPciDataByOffset: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
    return 0;
}

ULONG
NTAPI
KdNetSetPciDataByOffset(
    _In_ ULONG Bus,
    _In_ ULONG Slot,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdNetSetPciDataByOffset: %X, %X, %p, %X, %X\n", Bus, Slot, Buffer, Offset, Length);

    if (IsDbgComInitialized)
        DbgPrint0("KdNetGetPciDataByOffset: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
    return 0;
}

VOID
NTAPI
KdStallExecutionProcessor(
    _In_ ULONG MicroSeconds)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdStallExecutionProcessor: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
}

VOID
NTAPI
KdNetSetHiberRange(
    _In_ PVOID MemoryMap,
    _In_ ULONG Flags,
    _In_ PVOID Address,
    _In_ ULONG_PTR Length,
    _In_ ULONG Tag)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdNetSetHiberRange: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
}

NTSTATUS
NTAPI
InitializeKdNetExtensibility(
    _In_ PCHAR LoaderOptions,
    _In_ PDEBUG_DEVICE_DESCRIPTOR PciDevice)
{
    if (IsDbgComInitialized)
        DbgPrint0("InitializeKdNetExtensibility: %X, %X\n", LoaderOptions, PciDevice);

    if (InterlockedIncrement(&KdNetExtensibilityInitCount) != 1)
    {
        if (IsDbgComInitialized)
            DbgPrint0("InitializeKdNetExtensibility: exit (KdNetExtensibilityInitCount %X)\n", KdNetExtensibilityInitCount);

        return KdNetExtensibilityInitStatus;
    }

    RtlZeroMemory(&KdNetExports, sizeof(KdNetExports));

    KdNetExports.FunctionCount = 24;

    KdNetExports.GetPciDataByOffset = KdNetGetPciDataByOffset;
    KdNetExports.SetPciDataByOffset = KdNetSetPciDataByOffset;
    KdNetExports.GetPhysicalAddress = MmGetPhysicalAddress;
    KdNetExports.StallExecutionProcessor = KdStallExecutionProcessor;
    KdNetExports.ReadRegisterUChar = READ_REGISTER_UCHAR;
    KdNetExports.ReadRegisterUShort = READ_REGISTER_USHORT;
    KdNetExports.ReadRegisterULong = READ_REGISTER_ULONG;
    KdNetExports.WriteRegisterUChar = WRITE_REGISTER_UCHAR;
    KdNetExports.WriteRegisterUShort = WRITE_REGISTER_USHORT;
    KdNetExports.WriteRegisterULong = WRITE_REGISTER_ULONG;
    KdNetExports.ReadPortUChar = READ_PORT_UCHAR;
    KdNetExports.ReadPortUShort = READ_PORT_USHORT;
    KdNetExports.ReadPortULong = READ_PORT_ULONG;
    KdNetExports.WritePortUChar = WRITE_PORT_UCHAR;
    KdNetExports.WritePortUShort = WRITE_PORT_USHORT;
    KdNetExports.WritePortULong = WRITE_PORT_ULONG;
    KdNetExports._KdNetErrorStatus = &KdNetErrorStatus;
    KdNetExports._KdNetErrorString = &KdNetErrorString;
    KdNetExports._KdNetHardwareID = &KdNetHardwareID;
    KdNetExports.SetHiberRange = KdNetSetHiberRange;

    KdNetExtensibilityInitStatus = KdInitializeLibrary((PVOID)&KdNetExports, LoaderOptions, PciDevice);

    if (IsDbgComInitialized)
        DbgPrint0("InitializeKdNetExtensibility: Status %X\n", KdNetExtensibilityInitStatus);

    return KdNetExtensibilityInitStatus;
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
