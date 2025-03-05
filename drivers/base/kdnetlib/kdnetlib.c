/*
 * COPYRIGHT:       GPL, see COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            drivers/base/kdnetlib/kdnetlib.c
 * PURPOSE:         Encryption library for the kernel debugger over Net.
 * PROGRAMMER:      
 */

#include "..\kdnet\kdnet.h"
#include "kdnetlib.h"

/* GLOBALS ********************************************************************/

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
InitializeEncryption(
    _In_ PKD_NET_DATA NetData,
    _In_ PKD_NET_PARAMETERS NetParameters)
{
    //if (IsDbgComInitialized)
    //    DbgPrint0("InitializeEncryption: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);

    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
EncryptKdPacket(
    _In_ PKD_NET_KD_HEADER KdPacket,
    _In_ ULONG* OutLength,
    _In_ PKD_NET_AES_CTX AesCtx,
    _In_ PVOID KeyToken,
    _In_ ULONGLONG Stamp,
    _In_ UCHAR Unknown2)
{
    //if (IsDbgComInitialized)
    //    DbgPrint0("EncryptKdPacket: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DecryptKdPacket(
    _In_ PKD_NET_DATA InNetData,
    _In_ PVOID* InOutPacket,
    _In_ ULONG* InOutLength)
{
    //if (IsDbgComInitialized)
    //    DbgPrint0("DecryptKdPacket: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);

    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
ParseEncryptionKey(
    PKD_NET_PARAMETERS KdNetParameters,
    PCHAR* OutStart,
    PCHAR* OutEnd,
    PCHAR* OutPtr,
    PLARGE_INTEGER Key,
    PLARGE_INTEGER Value)
{
    //if (IsDbgComInitialized)
    //    DbgPrint0("ParseEncryptionKey: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
}

VOID
NTAPI
CleanEncryptionKey(
    PCHAR* OutStart,
    PCHAR* OutEnd,
    PLARGE_INTEGER Key,
    PLARGE_INTEGER Value)
{
    //if (IsDbgComInitialized)
    //    DbgPrint0("CleanEncryptionKey: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
}

/* EOF */
