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
#include <ndk/halfuncs.h>
#include <arc/arc.h>
#include <stdlib.h>
#include <stdio.h>
#include <ntstrsafe.h>

/* 169.254.0.0 */
#define AUTOIP_NET              0xA9FE0000

/* 169.254.1.0 */
#define IP_RANGE_START          0x0100
#define AUTOIP_RANGE_START      (AUTOIP_NET | IP_RANGE_START)

/* 169.254.254.255 */
#define IP_RANGE_END            0xFEFF
#define AUTOIP_RANGE_END        (AUTOIP_NET | IP_RANGE_END)

#define ETHERNET_TYPE_IPV4        0x0800
#define ETHERNET_TYPE_ARP         0x0806
#define ETHERNET_TYPE_RARP        0x0835

#define IPPROTO_IP               0
#define IPPROTO_UDP              17 // 0x11

#ifndef Add2Ptr
  #define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#endif

#define UshortSwap(_x) _byteswap_ushort((USHORT)(_x))
#define UlongSwap(_x) _byteswap_ulong((_x))

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

#ifdef __REACTOS__
typedef struct _DEBUG_DEVICE_DESCRIPTOR_5x
{
    ULONG Bus;
    ULONG Slot;
    USHORT VendorID;
    USHORT DeviceID;
    UCHAR BaseClass;
    UCHAR SubClass;
    UCHAR ProgIf;
    BOOLEAN Initialized;
    DEBUG_DEVICE_ADDRESS BaseAddress[MAXIMUM_DEBUG_BARS];
    DEBUG_MEMORY_REQUIREMENTS Memory;
} DEBUG_DEVICE_DESCRIPTOR_5x, *PDEBUG_DEVICE_DESCRIPTOR_5x;
#endif

C_ASSERT(sizeof(DEBUG_DEVICE_DESCRIPTOR) == 0x98);

typedef struct _KD_NET_PARAMETERS
{
    DEBUG_DEVICE_DESCRIPTOR PciDevice;
    ULONG DebuggeeIp;
    USHORT DebuggeePort;
    USHORT Reserved0;
    ULONG HostIp1;
    USHORT HostPort1;
    USHORT Reserved1;
    ULONG HostIp2;
    USHORT HostPort2;
    UCHAR HostMac[6];
    BOOLEAN IsDebuggerActive;
    BOOLEAN IsEncryptionKey;
    BOOLEAN IsDhcp;
    BOOLEAN IsVerifyHostMac;
    ULONG DataChannel;
    ULONG Reserved2;
    LONGLONG DataStamp;
    ULONGLONG SequenceNumber;
    LARGE_INTEGER EncryptionKey[4];
    LARGE_INTEGER DataChannelKey[4];
    ULONGLONG Stamp;
    UCHAR BytesForNtoskrnl[0x20];
    UCHAR KdData[0x100];
    BOOLEAN IsSendKdStatus;
    UCHAR Reserved3[3];
    ULONG Reserved4;
} KD_NET_PARAMETERS, *PKD_NET_PARAMETERS;
C_ASSERT(sizeof(KD_NET_PARAMETERS) == 0x240);

typedef struct _KD_NET_AES_CTX
{
    UCHAR AesCtx[0x1D8]; // 472
} KD_NET_AES_CTX, *PKD_NET_AES_CTX;
C_ASSERT(sizeof(KD_NET_AES_CTX) == 0x1D8);

typedef struct _KDNET_SHARED_DATA
{
    PVOID Hardware;
    PDEBUG_DEVICE_DESCRIPTOR Device;
    PUCHAR TargetMacAddress;
    ULONG LinkSpeed;
    ULONG LinkDuplex;
    PUCHAR LinkState;
} KDNET_SHARED_DATA, *PKDNET_SHARED_DATA;
C_ASSERT(sizeof(KDNET_SHARED_DATA) == 0x18);

#pragma pack(1)

typedef struct _KD_NET_DATA
{
    KDNET_SHARED_DATA SharedData;
    PKD_NET_PARAMETERS NetParameters;
    PKD_NIC_DATA NicData;
    UCHAR KeyToken[0x20];
    KD_NET_AES_CTX AesCtx[2];
    ULONG TransactionId;
    USHORT SecondsElapsed;
    USHORT Reserved1;
    ULONG BroadcastIp;
    ULONG ClientIp;
    ULONG SubnetMask;
    ULONG GatewayIp;
    ULONG DhcpPacketType;
    ULONG RenewalTime;
    ULONG RebindingTime;
    ULONG LeaseTime;
    ULONG CurrentTime;
    ULONG DhcpPacketsCounter;
    UCHAR MacAddress0[6];
    UCHAR MacAddress[6];
    ULONG YourIp;
    USHORT VendorId;
    USHORT Reserved2;
} KD_NET_DATA, *PKD_NET_DATA;
C_ASSERT(sizeof(KD_NET_DATA) == 0x434);

typedef struct _KD_NET_ETH_HEADER
{
    UCHAR DestinationMac[6];
    UCHAR SourceMac[6];
    USHORT EtherType;
} KD_NET_ETH_HEADER, *PKD_NET_ETH_HEADER;
C_ASSERT(sizeof(KD_NET_ETH_HEADER) == 0x0E);

typedef struct _KD_NET_ARP_PACKET
{
    USHORT HardwareType;
    USHORT ProtocolType;
    UCHAR HardwareLen;
    UCHAR ProtocolLen;
    USHORT Operation;
    UCHAR SenderMac[6];
    ULONG SenderIp;
    UCHAR TargetMac[6];
    ULONG TargetIp;
} KD_NET_ARP_PACKET, *PKD_NET_ARP_PACKET;
C_ASSERT(sizeof(KD_NET_ARP_PACKET) == 0x1C);

typedef struct _KD_NET_ARP
{
    KD_NET_ETH_HEADER Header;
    KD_NET_ARP_PACKET Arp;
} KD_NET_ARP, *PKD_NET_ARP;
C_ASSERT(sizeof(KD_NET_ARP) == 0x2A);

typedef struct _KD_NET_IPv4_PACKET
{
    union
    {
        struct
        {
            USHORT Version: 4;
            USHORT InternetHdrLen :4; // (IHL)
            USHORT TypeOfService :6;  // Differentiated Services Code Point (DSCP)
            USHORT EcNotification :2; // Explicit Congestion Notification (ECN)
        };
        USHORT IpHdr0;
    };
    USHORT TotalLength;
    USHORT Identification;
    union
    {
        struct
        {
            USHORT Flags: 3;
            USHORT FragmentOffset: 13;
        };
        USHORT IpHdr1;
    };
    UCHAR TimeToLive; // (TTL)
    UCHAR Protocol;
    USHORT HeaderChecksum;
    ULONG SourceIp;
    ULONG DestinationIp;
} KD_NET_IPv4_PACKET, *PKD_NET_IPv4_PACKET;
C_ASSERT(sizeof(KD_NET_IPv4_PACKET) == 0x14);

typedef struct _KD_NET_IPv4
{
    KD_NET_ETH_HEADER Header;
    KD_NET_IPv4_PACKET Ipv4;
} KD_NET_IPv4, *PKD_NET_IPv4;
C_ASSERT(sizeof(KD_NET_IPv4) == 0x22);

typedef struct _KD_NET_UDP_PACKET
{
    USHORT SourcePort;
    USHORT DestinationPort;
    USHORT Length;
    USHORT Checksum;
} KD_NET_UDP_PACKET, *PKD_NET_UDP_PACKET;

typedef struct _KD_NET_UDP
{
    KD_NET_ETH_HEADER EthHeader;
    KD_NET_IPv4_PACKET Ipv4;
    KD_NET_UDP_PACKET Udp;
    UCHAR Data[0];
} KD_NET_UDP, *PKD_NET_UDP;
C_ASSERT(sizeof(KD_NET_UDP) == 0x2A);

typedef struct _KD_NET_KD_HEADER
{
    ULONG Tag;
    UCHAR Unknown1;
    UCHAR Unknown2;
    ULONGLONG Stamp;
} KD_NET_KD_HEADER, *PKD_NET_KD_HEADER;
C_ASSERT(sizeof(KD_NET_KD_HEADER) == 0x0E);

typedef struct _KD_NET_KD_DATA
{
    USHORT KdData0;
    UCHAR BytesForNtoskrnl[0x20];
    USHORT Reserved0;
    ULONG Reserved1;
    USHORT Reserved2;
    ULONG Unknown1;
    ULONG DebuggeeIp;
    USHORT DebuggeePort;
    ULONG Reserved3;
    ULONG Reserved4;
    ULONG Unknown2;
    ULONG HostIp1;
    USHORT HostPort1;
    USHORT Reserved5;
    ULONG Reserved6;
    USHORT Reserved7;
    ULONG Unknown3;
    ULONG HostIp2;
    USHORT Port2;
    UCHAR Data[0x100];
} KD_NET_KD_DATA, *PKD_NET_KD_DATA;
C_ASSERT(sizeof(KD_NET_KD_DATA) == 0x158);

#pragma pack()

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

/* Non EXPORT functions */
NTSTATUS
NTAPI
ProcessUnhandledPackets(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG PacketHandle
);

VOID
NTAPI
ReleaseRxPacket(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG PacketHandle
);

NTSTATUS
NTAPI
WaitForSpecificRxPacket(
    _In_ PKD_NET_DATA NetData,
    _In_ PULONG OutHandle,
    _Out_ PVOID* OutPacket,
    _Out_ ULONG* OutPacketLength,
    _Out_ ULONG* OutCycleCount,
    _In_ PUCHAR HostMac,
    _In_ PUCHAR MacAddress,
    _In_ PUSHORT EtherType
);

PVOID
NTAPI
GetPacketAddress(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG PacketHandle
);

NTSTATUS
NTAPI
ProcessControlChannelPacket(
    _In_ PKD_NET_DATA NetData,
    _In_ PVOID Packet,
    _In_ ULONG PacketLength,
    _In_ ULONGLONG SequenceNumber
);

#endif /* _KDNET_H_ */

/* EOF */
