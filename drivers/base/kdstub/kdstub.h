/*
 * COPYRIGHT:       GPL, see COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            drivers/base/kdnet/kdstub.h
 * PURPOSE:         Base definitions stubs for the kernel debugger over Net.
 * PROGRAMMER:      
 */

#ifndef _KDSTUB_H_
#define _KDNET_H_

#include <ntifs.h>

typedef
ULONG
(NTAPI* PKDNET_GET_PCI_DATA_BY_OFFSET)(
    ULONG BusNumber,
    ULONG SlotNumber,
    PVOID Buffer,
    ULONG Offset,
    ULONG Length
);

typedef
ULONG
(NTAPI* PKDNET_SET_PCI_DATA_BY_OFFSET)(
    ULONG BusNumber,
    ULONG SlotNumber,
    PVOID Buffer,
    ULONG Offset,
    ULONG Length
);

typedef
PHYSICAL_ADDRESS
(NTAPI* PKDNET_GET_PHYSICAL_ADDRESS)(
    PVOID Va
);

typedef
void
(NTAPI* PKDNET_STALL_EXECUTION_PROCESSOR)(
    ULONG Microseconds
);

typedef
UCHAR
(NTAPI* PKDNET_READ_REGISTER_UCHAR)(
    PUCHAR Register
);

typedef
USHORT
(NTAPI* PKDNET_READ_REGISTER_USHORT)(
    PUSHORT Register
);

typedef
ULONG
(NTAPI* PKDNET_READ_REGISTER_ULONG)(
    PULONG Register
);

typedef
ULONG64
(NTAPI* PKDNET_READ_REGISTER_ULONG64)(
    PULONG64 Register
);

typedef
void
(NTAPI* PKDNET_WRITE_REGISTER_UCHAR)(
    PUCHAR Register,
    UCHAR Value
);

typedef
void
(NTAPI* PKDNET_WRITE_REGISTER_USHORT)(
    PUSHORT Register,
    USHORT Value
);

typedef
void
(NTAPI* PKDNET_WRITE_REGISTER_ULONG)(
    PULONG Register,
    ULONG Value
);

typedef
void
(NTAPI* PKDNET_WRITE_REGISTER_ULONG64)(
    PULONG64 Register,
    ULONG64 Value
);

typedef
UCHAR
(NTAPI* PKDNET_READ_PORT_UCHAR)(
    PUCHAR Port
);

typedef
USHORT
(NTAPI* PKDNET_READ_PORT_USHORT)(
    PUSHORT Port
);

typedef
ULONG
(NTAPI* PKDNET_READ_PORT_ULONG)(
    PULONG Port
);

typedef
ULONG
(NTAPI* PKDNET_READ_PORT_ULONG64)(
    PULONG64 Port
);

typedef
void
(NTAPI* PKDNET_WRITE_PORT_UCHAR)(
    PUCHAR Port,
    UCHAR Value
);

typedef
void
(NTAPI* PKDNET_WRITE_PORT_USHORT)(
    PUSHORT Port,
    USHORT Value
);

typedef
void
(NTAPI* PKDNET_WRITE_PORT_ULONG)(
    PULONG Port,
    ULONG Value
);

typedef
void
(NTAPI* PKDNET_WRITE_PORT_ULONG64)(
    PULONG Port,
    ULONG64 Value
);

typedef
void
(NTAPI* PKDNET_SET_HIBER_RANGE)(
    PVOID MemoryMap,
    ULONG Flags,
    PVOID Address,
    ULONG_PTR Length,
    ULONG Tag
);

/* NTDDI_WINBLUE */
typedef struct _KDNET_EXTENSIBILITY_IMPORTS
{
    ULONG FunctionCount;
    PKDNET_GET_PCI_DATA_BY_OFFSET GetPciDataByOffset;
    PKDNET_SET_PCI_DATA_BY_OFFSET SetPciDataByOffset;
    PKDNET_GET_PHYSICAL_ADDRESS GetPhysicalAddress;
    PKDNET_STALL_EXECUTION_PROCESSOR StallExecutionProcessor;
    PKDNET_READ_REGISTER_UCHAR ReadRegisterUChar;
    PKDNET_READ_REGISTER_USHORT ReadRegisterUShort;
    PKDNET_READ_REGISTER_ULONG ReadRegisterULong;
    PKDNET_READ_REGISTER_ULONG64 ReadRegisterULong64;
    PKDNET_WRITE_REGISTER_UCHAR WriteRegisterUChar;
    PKDNET_WRITE_REGISTER_USHORT WriteRegisterUShort;
    PKDNET_WRITE_REGISTER_ULONG WriteRegisterULong;
    PKDNET_WRITE_REGISTER_ULONG64 WriteRegisterULong64;
    PKDNET_READ_PORT_UCHAR ReadPortUChar;
    PKDNET_READ_PORT_USHORT ReadPortUShort;
    PKDNET_READ_PORT_ULONG ReadPortULong;
    PKDNET_READ_PORT_ULONG64 ReadPortULong64;
    PKDNET_WRITE_PORT_UCHAR WritePortUChar;
    PKDNET_WRITE_PORT_USHORT WritePortUShort;
    PKDNET_WRITE_PORT_ULONG WritePortULong;
    PKDNET_WRITE_PORT_ULONG64 WritePortULong64;
    NTSTATUS* _KdNetErrorStatus;
    PWCHAR* _KdNetErrorString;
    ULONG* _KdNetHardwareID;
    PKDNET_SET_HIBER_RANGE SetHiberRange;
} KDNET_EXTENSIBILITY_IMPORTS, *PKDNET_EXTENSIBILITY_IMPORTS;

#endif /* _KDSTUB_H_ */

/* EOF */
