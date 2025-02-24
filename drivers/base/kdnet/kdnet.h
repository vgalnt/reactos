/*
 * COPYRIGHT:       GPL, see COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            drivers/base/kdnet/kdnet.h
 * PURPOSE:         Base definitions for the kernel debugger over Net.
 * PROGRAMMER:      
 */

#ifndef _KDNET_H_
#define _KDNET_H_

/* NTDDI_WINBLUE */
#include <ntifs.h>
#include <windbgkd.h>
#include <arc/arc.h>

typedef enum
{
    KDP_PACKET_RECEIVED = 0,
    KDP_PACKET_TIMEOUT = 1,
    KDP_PACKET_RESEND = 2
} KDP_STATUS;

typedef struct _KD_NIC_DATA
{
    USHORT Version;
    USHORT Size;
    ULONG Reserved0;
    NTSTATUS Status;
    ULONG LinkSpeed1;
    ULONG Reserved1;
    ULONG Reserved2;
    SLIST_HEADER sListHead;
    SLIST_HEADER sListHead1;
    SLIST_HEADER sListHead2;
    UCHAR MacAddress[6];
    UCHAR LinkState;
    UCHAR Reserved3;
    ULONG LinkSpeed2;
    ULONG Reserved4;
} KD_NIC_DATA, *PKD_NIC_DATA;
C_ASSERT(sizeof(KD_NIC_DATA) == 0x40);

typedef
ULONG
(NTAPI* KDNET_GET_PCI_DATA_BY_OFFSET)(
    ULONG BusNumber,
    ULONG SlotNumber,
    PVOID Buffer,
    ULONG Offset,
    ULONG Length
);

typedef
ULONG
(NTAPI* KDNET_SET_PCI_DATA_BY_OFFSET)(
    ULONG BusNumber,
    ULONG SlotNumber,
    PVOID Buffer,
    ULONG Offset,
    ULONG Length
);

typedef
PHYSICAL_ADDRESS
(NTAPI* KDNET_GET_PHYSICAL_ADDRESS)(
    PVOID Va
);

typedef
void
(NTAPI* KDNET_STALL_EXECUTION_PROCESSOR)(
    ULONG Microseconds
);

typedef
UCHAR
(NTAPI* KDNET_READ_REGISTER_UCHAR)(
    PUCHAR Register
);

typedef
USHORT
(NTAPI* KDNET_READ_REGISTER_USHORT)(
    PUSHORT Register
);

typedef
ULONG
(NTAPI* KDNET_READ_REGISTER_ULONG)(
    PULONG Register
);

typedef
ULONG64
(NTAPI* KDNET_READ_REGISTER_ULONG64)(
    PULONG64 Register
);

typedef
void
(NTAPI* KDNET_WRITE_REGISTER_UCHAR)(
    PUCHAR Register,
    UCHAR Value
);

typedef
void
(NTAPI* KDNET_WRITE_REGISTER_USHORT)(
    PUSHORT Register,
    USHORT Value
);

typedef
void
(NTAPI* KDNET_WRITE_REGISTER_ULONG)(
    PULONG Register,
    ULONG Value
);

typedef
void
(NTAPI* KDNET_WRITE_REGISTER_ULONG64)(
    PULONG64 Register,
    ULONG64 Value
);

typedef
UCHAR
(NTAPI* KDNET_READ_PORT_UCHAR)(
    PUCHAR Port
);

typedef
USHORT
(NTAPI* KDNET_READ_PORT_USHORT)(
    PUSHORT Port
);

typedef
ULONG
(NTAPI* KDNET_READ_PORT_ULONG)(
    PULONG Port
);

typedef
ULONG
(NTAPI* KDNET_READ_PORT_ULONG64)(
    PULONG64 Port
);

typedef
void
(NTAPI* KDNET_WRITE_PORT_UCHAR)(
    PUCHAR Port,
    UCHAR Value
);

typedef
void
(NTAPI* KDNET_WRITE_PORT_USHORT)(
    PUSHORT Port,
    USHORT Value
);

typedef
void
(NTAPI* KDNET_WRITE_PORT_ULONG)(
    PULONG Port,
    ULONG Value
);

typedef
void
(NTAPI* KDNET_WRITE_PORT_ULONG64)(
    PULONG Port,
    ULONG64 Value
);

typedef
void
(NTAPI* KDNET_SET_HIBER_RANGE)(
    PVOID MemoryMap,
    ULONG Flags,
    PVOID Address,
    ULONG_PTR Length,
    ULONG Tag
);

typedef struct _KDNET_EXTENSIBILITY_EXPORT
{
    ULONG FunctionCount;
    KDNET_GET_PCI_DATA_BY_OFFSET GetPciDataByOffset;
    KDNET_SET_PCI_DATA_BY_OFFSET SetPciDataByOffset;
    KDNET_GET_PHYSICAL_ADDRESS GetPhysicalAddress;
    KDNET_STALL_EXECUTION_PROCESSOR StallExecutionProcessor;
    KDNET_READ_REGISTER_UCHAR ReadRegisterUChar;
    KDNET_READ_REGISTER_USHORT ReadRegisterUShort;
    KDNET_READ_REGISTER_ULONG ReadRegisterULong;
    KDNET_READ_REGISTER_ULONG64 ReadRegisterULong64;
    KDNET_WRITE_REGISTER_UCHAR WriteRegisterUChar;
    KDNET_WRITE_REGISTER_USHORT WriteRegisterUShort;
    KDNET_WRITE_REGISTER_ULONG WriteRegisterULong;
    KDNET_WRITE_REGISTER_ULONG64 WriteRegisterULong64;
    KDNET_READ_PORT_UCHAR ReadPortUChar;
    KDNET_READ_PORT_USHORT ReadPortUShort;
    KDNET_READ_PORT_ULONG ReadPortULong;
    KDNET_READ_PORT_ULONG64 ReadPortULong64;
    KDNET_WRITE_PORT_UCHAR WritePortUChar;
    KDNET_WRITE_PORT_USHORT WritePortUShort;
    KDNET_WRITE_PORT_ULONG WritePortULong;
    KDNET_WRITE_PORT_ULONG64 WritePortULong64;
    NTSTATUS* _KdNetErrorStatus;
    PWCHAR* _KdNetErrorString;
    ULONG* _KdNetHardwareID;
    KDNET_SET_HIBER_RANGE SetHiberRange;
} KDNET_EXTENSIBILITY_EXPORT, *PKDNET_EXTENSIBILITY_EXPORT;

PVOID
NTAPI
KdGetPacketAddress(
    _In_ PVOID Adapter,
    _In_ ULONG Handle
);

ULONG
NTAPI
KdGetPacketLength(
    _In_ PVOID Adapter,
    _In_ ULONG Handle
);

NTSTATUS
NTAPI
KdGetRxPacket(
    _In_ PVOID Adapter,
    _Out_ ULONG* Handle,
    _Out_ PVOID* Packet,
    _Out_ ULONG* Length
);

NTSTATUS
NTAPI
KdGetTxPacket(
    _In_ PVOID Adapter,
    _Out_ ULONG* Handle
);

NTSTATUS
NTAPI
KdInitializeController(
    _In_ PVOID NetData
);

NTSTATUS
NTAPI
KdInitializeLibrary(
    _In_ PVOID ImportTable, // PKDNET_EXTENSIBILITY_IMPORTS
    _In_ PCHAR LoaderOptions,
    _Inout_ PDEBUG_DEVICE_DESCRIPTOR Device
);

VOID
NTAPI
KdReleaseRxPacket(
    _In_ PVOID Adapter,
    _In_ ULONG Handle
);

NTSTATUS
NTAPI
KdSendTxPacket(
    _In_ PVOID Adapter,
    _In_ ULONG Handle,
    _In_ ULONG Length
);

VOID
NTAPI
KdSetHibernateRange(
    VOID
);

VOID
NTAPI
KdShutdownController(
    _In_ PVOID Adapter
);

#endif /* _KDNET_H_ */

/* EOF */
