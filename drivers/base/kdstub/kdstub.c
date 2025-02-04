/*
 * COPYRIGHT:       GPL, see COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            drivers/base/kdnet/kdstub.c
 * PURPOSE:         Stubs for the kernel debugger over Net.
 * PROGRAMMER:      
 */

#include "kdstub.h"

/* GLOBALS ********************************************************************/

/* DEBUGGING ******************************************************************/

/* FUNCTIONS ******************************************************************/

PVOID
NTAPI
KdGetPacketAddress(
    _In_ PVOID Adapter,
    _In_ ULONG Handle)
{
    DbgPrint("KdGetPacketAddress: %X, %X\n", Adapter, Handle);
    return NULL;
}

ULONG
NTAPI
KdGetPacketLength(
     _In_ PVOID Adapter,
     _In_ ULONG Handle)
{
    DbgPrint("KdGetPacketLength: %X, %X\n", Adapter, Handle);
    return 0;
}

NTSTATUS
NTAPI
KdGetRxPacket(
    _In_ PVOID Adapter,
    _Out_ ULONG* Handle,
    _Out_ PVOID* Packet,
    _Out_ ULONG* Length)
{
    DbgPrint("KdGetRxPacket: %X\n", Adapter);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdGetTxPacket(
    _In_ PVOID Adapter,
    _Out_ ULONG* Handle)
{
    DbgPrint("KdGetTxPacket: %X\n", Adapter);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdInitializeController(
    _In_ PVOID NetData)
{
    DbgPrint("KdInitializeController: %X\n", NetData);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdInitializeLibrary(
    _In_ PKDNET_EXTENSIBILITY_IMPORTS ImportTable,
    _In_ PCHAR LoaderOptions,
    _Inout_ PDEBUG_DEVICE_DESCRIPTOR Device)
{
    DbgPrint("KdInitializeLibrary: %X, %X, %X\n", ImportTable, LoaderOptions, Device);
    return STATUS_SUCCESS;
}

VOID
NTAPI
KdReleaseRxPacket(
    _In_ PVOID Adapter,
    _In_ ULONG Handle)
{
    DbgPrint("KdReleaseRxPacket: %X, %X\n", Adapter, Handle);
}

NTSTATUS
NTAPI
KdSendTxPacket(
    _In_ PVOID Adapter,
    _In_ ULONG Handle,
    _In_ ULONG Length)
{
    DbgPrint("KdSendTxPacket: %X, %X, %X\n", Adapter, Handle, Length);
    return STATUS_SUCCESS;
}

VOID
NTAPI
KdSetHibernateRange(VOID)
{
    DbgPrint("KdSetHibernateRange()");
}

VOID
NTAPI
KdShutdownController(
    _In_ PVOID Adapter)
{
    DbgPrint("KdShutdownController: %X\n", Adapter);
}

/* EOF */
