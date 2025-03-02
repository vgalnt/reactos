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
KD_NET_PARAMETERS KdNetParameters;
KD_NIC_DATA KdNicData;
PKD_NET_DATA KdNetData;

LONG KdNetDebuggerInitialize0Count;
LONG KdNetExtensibilityInitCount;
LONG KdNetInitializeCount;
LONG KdNicSendEntered;
LONG KdNicSendReentered;
LONG KdNicReceiveEntered;
LONG KdNicReceiveReentered;

BOOLEAN KdNetInitialized;
BOOLEAN KdNicEnabled = TRUE;
BOOLEAN KdDbgLog = TRUE;

ULONG KdNetReconnectRunningTimeout;
LONGLONG KdNetReconnectTimestamp;

LIST_ENTRY QueuedTxListHead;
NTSTATUS KdNetExtensibilityInitStatus = STATUS_ALREADY_REGISTERED;
NTSTATUS KdNetErrorStatus;
NTSTATUS KdNetErrorStatusLog[8];
PWSTR KdNetErrorStringLog[8];
PWSTR KdNetErrorString;
ULONG KdNetInitializeController;
ULONG KdNetHardwareContextSize;
ULONG KdNetHardwareID;
ULONG KdTargetIP;
ULONG KdNetRetryCount = 3;
ULONG KdNetTxPacketId = 0;
ULONG KdNetRxPacketId = 0x80000000;

//extern BOOLEAN KdEnteredDebugger;
#ifndef _NTSYSTEM_
  __CREATE_NTOS_DATA_IMPORT_ALIAS(KdEnteredDebugger)
  extern PBOOLEAN KdEnteredDebugger;
#endif

/* PRIVATE FUNCTIONS **********************************************************/

static VOID KdNetDump(PVOID Ptr, unsigned Len)
{
    unsigned int ix, jx;
    CHAR Msg[128];
    PCHAR Hexof = "0123456789ABCDEF";
    PUCHAR x = Ptr;

    if (!IsDbgComInitialized)
    {
        return;
    }

    DbgPrint0("KdNetDump: Ptr %p, Len %X\n", Ptr, Len);

    for (ix = 0; ix < Len; ix += 0x10)
    {
        RtlStringCchPrintfA(Msg, sizeof(Msg),"%08x: ", ix);

        RtlFillMemory((Msg + 10), (3 * 0x10 + 1 + 0x10), ' ');

        for (jx = 0; jx < min(0x10, Len - ix); jx++)
        {
            Msg[10 + 3 * jx + 0] = Hexof[x[ix + jx] >> 4];
            Msg[10 + 3 * jx + 1] = Hexof[x[ix + jx] & 0x0F];
            Msg[10 + 3 * jx + 2] = ' ';

            if (x[ix + jx] >= 0x20 && x[ix + jx] < 0x7F)
            {
                Msg[10 + 3 * 0x10 + 1 + jx] = (x[ix + jx]);
            }
            else
            {
                Msg[10 + 3 * 0x10 + 1 + jx] = ('.');
            }
        }

        Msg[10 + 3 * 0x10] = ' ';
        Msg[10 + 3 * 0x10 + 1 + 0x10] = '\0';

        DbgPrint0("%s\n", Msg);
    }
}

VOID
NTAPI
KdNetNicInitialize(VOID)
{
    KdNicData.Version = 3;
    KdNicData.Size = sizeof(KD_NIC_DATA);

    KdNicData.Reserved0 = 0;
    KdNicData.LinkSpeed1 = 1000;

    KdNicData.Status = STATUS_ADAPTER_HARDWARE_ERROR;

    InitializeSListHead(&KdNicData.TxSListHead);
    InitializeSListHead(&KdNicData.sListHead);
    InitializeSListHead(&KdNicData.sListHead1);
    InitializeSListHead(&KdNicData.sListHead2);

    KdNicData.LinkState = 0;
    KdNicData.Reserved3 = 0;
    KdNicData.LinkSpeed2 = 1000;

    InitializeListHead(&QueuedTxListHead);
}

/* PCI Type 1 Configuration Register */
typedef struct _PCI_TYPE1_CFG_BITS
{
    union
    {
        struct
        {
            ULONG Reserved1:2;
            ULONG RegisterNumber:6;
            ULONG FunctionNumber:3;
            ULONG DeviceNumber:5;
            ULONG BusNumber:8;
            ULONG Reserved2:7;
            ULONG Enable:1;
        } bits;

        ULONG AsULONG;
    } u;
} PCI_TYPE1_CFG_BITS, *PPCI_TYPE1_CFG_BITS;

ULONG
NTAPI
KdNetGetPciDataByOffset(
    _In_ ULONG Bus,
    _In_ ULONG Slot,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length)
{
    PUCHAR BufferPtr = Buffer;
    PCI_SLOT_NUMBER PciSlot;
    PCI_TYPE1_CFG_BITS PciCfg;
    ULONG DataUlong;
    ULONG ByteOffset;
    UCHAR Data[4];

    if (IsDbgComInitialized)
        DbgPrint0("KdNetGetPciDataByOffset: %X, %X, %p, %X, %X\n", Bus, Slot, Buffer, Offset, Length);

    //ASSERT(!(Offset & ~0xff));
    //ASSERT(Length);
    //ASSERT((Offset + Length) <= 256);

    if ((Offset + Length) > 0x100)
    {
        if (Offset > 0x100)
            return 0;

        Length = (0x100 - Offset);
    }

    PciSlot.u.AsULONG = Slot;

    if (PciSlot.u.bits.FunctionNumber)
    {
        PciCfg.u.AsULONG = (ULONG_PTR)Buffer;

        PciCfg.u.bits.RegisterNumber = 3;
        PciCfg.u.bits.FunctionNumber = 0;
        PciCfg.u.bits.DeviceNumber = PciSlot.u.bits.DeviceNumber;
        PciCfg.u.bits.BusNumber = Bus;
        PciCfg.u.bits.Enable = 1;

        WRITE_PORT_ULONG((PULONG)0xCF8, PciCfg.u.AsULONG);

        DataUlong = READ_PORT_ULONG((PULONG)0xCFC);
        if (!(DataUlong & 0x800000))
        {
            if (Length)
                RtlFillMemory(Buffer, Length, 0xFF);

            return Length;
        }
    }

    PciCfg.u.AsULONG = (ULONG_PTR)Buffer;

    PciCfg.u.bits.RegisterNumber = ((Offset & 0xFC) >> 2);
    PciCfg.u.bits.FunctionNumber = PciSlot.u.bits.FunctionNumber;
    PciCfg.u.bits.DeviceNumber = PciSlot.u.bits.DeviceNumber;
    PciCfg.u.bits.BusNumber = Bus;
    PciCfg.u.bits.Enable = 1;

    ByteOffset = (Offset & 3);

    while (Length)
    {
        WRITE_PORT_ULONG((PULONG)0xCF8, PciCfg.u.AsULONG);
        *(PULONG)Data = READ_PORT_ULONG((PULONG)0xCFC);

        for (; ByteOffset < 4 && Length; ByteOffset++, Length--)
        {
            *BufferPtr = Data[ByteOffset];
            BufferPtr++;
        }

        ByteOffset = 0;

        PciCfg.u.bits.RegisterNumber++;
    }

    return Length;
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
    PCI_SLOT_NUMBER PciSlot;
    PCI_TYPE1_CFG_BITS PciCfg;
    ULONG ByteOffset;
    ULONG ByteLength;
    ULONG RetLength;
    PULONG BufferUlong = Buffer;
    UCHAR Data[4];

    if (IsDbgComInitialized)
        DbgPrint0("KdNetSetPciDataByOffset: %X, %X, %p, %X, %X\n", Bus, Slot, Buffer, Offset, Length);

    //ASSERT(!(Offset & ~0xff));
    //ASSERT(Length);
    //ASSERT((Offset + Length) <= 256);

    if ((Offset + Length) > 0x100)
    {
        if (Offset > 0x100)
            return 0;

        Length = 0x100 - Offset;
    }

    PciSlot.u.AsULONG = Slot;
    RetLength = Length;

    PciCfg.u.bits.BusNumber = Bus;
    PciCfg.u.bits.DeviceNumber = PciSlot.u.bits.DeviceNumber;
    PciCfg.u.bits.FunctionNumber = PciSlot.u.bits.FunctionNumber;
    PciCfg.u.bits.RegisterNumber = ((Offset & 0xFC) >> 2);
    PciCfg.u.bits.Enable = 1;

    ByteOffset = (Offset & 3);

    if (ByteOffset)
    {
        if ((4 - ByteOffset) > Length)
        {
            ByteLength = Length;
            Length = 0;
        }
        else
        {
            ByteLength = (4 - ByteOffset);
            Length -= ByteLength;
        }

        WRITE_PORT_ULONG((PULONG)0xCF8, PciCfg.u.AsULONG);
        *(PULONG)Data = READ_PORT_ULONG((PULONG)0xCFC);

        if (ByteLength)
        {
            RtlCopyMemory(&Data[ByteOffset], Buffer, ByteLength);
            BufferUlong = Add2Ptr(Buffer, ByteLength);
        }

        WRITE_PORT_ULONG((PULONG)0xCFC, *(PULONG)Data);

        PciCfg.u.bits.RegisterNumber++;
    }

    while (Length > 4)
    {
        WRITE_PORT_ULONG((PULONG)0xCF8, PciCfg.u.AsULONG);
        WRITE_PORT_ULONG((PULONG)0xCFC, *BufferUlong);

        PciCfg.u.bits.RegisterNumber++;

        BufferUlong++;
        Length -= 4;
    }


    if (Length)
    {
        WRITE_PORT_ULONG((PULONG)0xCF8, PciCfg.u.AsULONG);
        *(PULONG)Data = READ_PORT_ULONG((PULONG)0xCFC);

        RtlCopyMemory(Data, BufferUlong, Length);

        WRITE_PORT_ULONG((PULONG)0xCFC, *(PULONG)Data);
    }

    return RetLength;
}

VOID
NTAPI
KdStallExecutionProcessor(
    _In_ ULONG MicroSeconds)
{
    if (IsDbgComInitialized && MicroSeconds != 10)
        DbgPrint0("KdStallExecutionProcessor: %X\n", MicroSeconds);

    if (MicroSeconds >= 100)
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdStallExecutionProcessor: StallLimit is 100!\n");
    }

    KeStallExecutionProcessor(MicroSeconds);
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

#ifdef __REACTOS__
static
VOID
KdNetSetPciDeviceForNt5x(
    _In_ PDEBUG_DEVICE_DESCRIPTOR PciDevice,
    _Out_ PDEBUG_DEVICE_DESCRIPTOR_5x OutDevice)
{
    ULONG ix;

    OutDevice->Bus = PciDevice->Bus;
    OutDevice->Slot = PciDevice->Slot;
    OutDevice->VendorID = PciDevice->VendorID;
    OutDevice->DeviceID = PciDevice->DeviceID;
    OutDevice->BaseClass = PciDevice->BaseClass;
    OutDevice->SubClass = PciDevice->SubClass;
    OutDevice->ProgIf = PciDevice->ProgIf;
    OutDevice->Initialized = PciDevice->Initialized;

    for (ix = 0; ix < 6; ix++)
    {
        RtlCopyMemory(&OutDevice->BaseAddress[ix], &PciDevice->BaseAddress[ix], sizeof(DEBUG_DEVICE_ADDRESS));
    }

    RtlCopyMemory(&OutDevice->Memory, &PciDevice->Memory, sizeof(DEBUG_MEMORY_REQUIREMENTS));

}

static
VOID
KdNetGetPciDeviceForNt5x(
    _In_ PDEBUG_DEVICE_DESCRIPTOR_5x InPciDevice,
    _Out_ PDEBUG_DEVICE_DESCRIPTOR OutPciDevice)
{
    ULONG ix;

    OutPciDevice->Bus = InPciDevice->Bus;
    OutPciDevice->Slot = InPciDevice->Slot;
    OutPciDevice->VendorID = InPciDevice->VendorID;
    OutPciDevice->DeviceID = InPciDevice->DeviceID;
    OutPciDevice->BaseClass = InPciDevice->BaseClass;
    OutPciDevice->SubClass = InPciDevice->SubClass;
    OutPciDevice->ProgIf = InPciDevice->ProgIf;
    OutPciDevice->Initialized = InPciDevice->Initialized;

    for (ix = 0; ix < 6; ix++)
    {
        RtlCopyMemory(&OutPciDevice->BaseAddress[ix], &InPciDevice->BaseAddress[ix], sizeof(DEBUG_DEVICE_ADDRESS));
    }

    RtlCopyMemory(&OutPciDevice->Memory, &InPciDevice->Memory, sizeof(DEBUG_MEMORY_REQUIREMENTS));

}
#endif

#ifdef __REACTOS__
NTSTATUS
NTAPI
InitializeEncryption(
    _In_ PKD_NET_DATA NetData,
    _In_ PKD_NET_PARAMETERS NetParameters,
    _In_ PVOID PingCallback,
    _In_ PVOID SendOfferPacketCallBack
);

VOID
NTAPI
EncryptKdPacket(
    _In_ PKD_NET_KD_HEADER KdPacket,
    _In_ ULONG* OutLength,
    _In_ PKD_NET_AES_CTX AesCtx,
    _In_ PVOID KeyToken,
    _In_ ULONGLONG Stamp,
    _In_ UCHAR Unknown2
);

NTSTATUS
NTAPI
DecryptKdPacket(
    _In_ PKD_NET_DATA InNetData,
    _In_ PVOID* InOutPacket,
    _In_ ULONG* InOutLength
);
#else
NTSTATUS
NTAPI
InitializeEncryption(
    _In_ PKD_NET_DATA NetData,
    _In_ PKD_NET_PARAMETERS NetParameters)
{
    if (IsDbgComInitialized)
        DbgPrint0("InitializeEncryption: Unimplemented!\n");

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
    if (IsDbgComInitialized)
        DbgPrint0("KdHvInitializeController: Unimplemented!\n");

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
    if (IsDbgComInitialized)
        DbgPrint0("DecryptKdPacket: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);

    return STATUS_NOT_IMPLEMENTED;
}
#endif

ULONG
NTAPI
GetPacketLength(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG PacketHandle)
{
    ULONG PacketLength = 0;

    if (IsDbgComInitialized)
        DbgPrint0("GetPacketLength: %X\n", PacketHandle);

    if (!NetData)
    {
        if (IsDbgComInitialized)
            DbgPrint0("GetPacketLength: NetData is NULL\n");

        return 0;
    }

    if (NetData->VendorId == 0xFFFB)
    {
        if (IsDbgComInitialized)
            DbgPrint0("GetPacketLength: Unimplemented USB3GetPacketLength()!\n");

        //return USB3GetPacketLength(NetData->SharedData.Hardware, PacketHandle);
        KeBugCheck(MANUALLY_INITIATED_CRASH);

        return STATUS_NOT_IMPLEMENTED;
    }

    if (NetData->VendorId == 0xFFFC)
    {
        if (IsDbgComInitialized)
            DbgPrint0("GetPacketLength: Unimplemented KdVmGetPacketLength()!\n");

        //return KdVmGetPacketLength(NetData->SharedData.Hardware, PacketHandle);
        KeBugCheck(MANUALLY_INITIATED_CRASH);

        return STATUS_NOT_IMPLEMENTED;
    }

    if (NetData->VendorId == 0xFFFD)
    {
        if (IsDbgComInitialized)
            DbgPrint0("GetPacketLength: Unimplemented GetPacketLength()!\n");

        //return KdVmGetPacketLength(NetData->SharedData.Hardware, PacketHandle);
        KeBugCheck(MANUALLY_INITIATED_CRASH);

        return STATUS_NOT_IMPLEMENTED;
    }

    if (NetData->VendorId == 0xFFFE)
        return KdGetPacketLength(NetData->SharedData.Hardware, PacketHandle);

    if (IsDbgComInitialized)
        DbgPrint0("GetPacketLength: ! Unknown VendorId (%X)\n", NetData->VendorId);

    return PacketLength;
}

NTSTATUS
NTAPI
ProcessDhcpPacket(
    _In_ PKD_NET_DATA NetData,
    _In_ PVOID Packet,
    _In_ ULONG Length,
    _In_ UCHAR Param4)
{
    if (IsDbgComInitialized)
        DbgPrint0("HandleDhcp: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
HandleDhcp(
    _In_ PKD_NET_DATA NetData, ULONG PacketHandle)
{
    PKD_NET_UDP Packet;
    ULONG PacketLength;
    USHORT DhcpLength;
    USHORT UdpLength;
    NTSTATUS Status;

    if (IsDbgComInitialized)
        DbgPrint0("HandleDhcp: %X\n", PacketHandle);

    if (NetData->DhcpPacketType <= 5)
    {
        if (IsDbgComInitialized)
            DbgPrint0("HandleDhcp: STATUS_MORE_PROCESSING_REQUIRED DhcpPacketType %X\n", NetData->DhcpPacketType);

        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    PacketLength = GetPacketLength(NetData, PacketHandle);
    Packet = GetPacketAddress(NetData, PacketHandle);

    if (PacketLength < sizeof(KD_NET_ETH_HEADER) &&
        Packet->EthHeader.EtherType != sizeof(KD_NET_UDP_PACKET) ||
        !RtlEqualMemory(NetData->MacAddress, Packet->EthHeader.DestinationMac, 6))
    {
        if (IsDbgComInitialized)
            DbgPrint0("HandleDhcp: (1) STATUS_MORE_PROCESSING_REQUIRED (%X, %X)\n", PacketLength, Packet->EthHeader.EtherType);

        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    PacketLength -= sizeof(KD_NET_ETH_HEADER);

    if (PacketLength < sizeof(KD_NET_IPv4_PACKET) || Packet->Ipv4.Protocol != 0x11)
    {
        if (IsDbgComInitialized)
            DbgPrint0("HandleDhcp: (2) STATUS_MORE_PROCESSING_REQUIRED (%X, %X)\n", PacketLength, Packet->Ipv4.Protocol);

        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    PacketLength -= sizeof(KD_NET_IPv4_PACKET);

    if (PacketLength < sizeof(KD_NET_UDP_PACKET) ||
        Packet->Udp.SourcePort != 0x4300 ||
        Packet->Udp.DestinationPort != 0x4400)
    {
        if (IsDbgComInitialized)
            DbgPrint0("HandleDhcp: STATUS_MORE_PROCESSING_REQUIRED (%X, %X, %X)\n", PacketLength, Packet->Udp.SourcePort, Packet->Udp.DestinationPort);

        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    UdpLength = UshortSwap(Packet->Udp.Length);

    PacketLength -= sizeof(KD_NET_UDP_PACKET);

    if (UdpLength < sizeof(KD_NET_UDP_PACKET))
        UdpLength = sizeof(KD_NET_UDP_PACKET);

    DhcpLength = (UdpLength - sizeof(KD_NET_UDP_PACKET));

    if (DhcpLength > PacketLength)
        DhcpLength = PacketLength;

    Status = ProcessDhcpPacket(NetData, Add2Ptr(Packet, sizeof(*Packet)), DhcpLength, 5);
    if (Status == STATUS_DUPLICATE_NAME)
    {
        if (IsDbgComInitialized)
            DbgPrint0("HandleDhcp: STATUS_DUPLICATE_NAME\n");

        //KdNetDhcpPacketsHandled++;
        return 0;
    }

    if (NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("HandleDhcp: KdNetDhcpPacketsHandled++ (%X)\n", NetData->DhcpPacketsCounter);

        NetData->DhcpPacketsCounter++;
        //KdNetDhcpPacketsHandled++;
        return Status;
    }

    if (IsDbgComInitialized)
        DbgPrint0("HandleDhcp: Status %X\n", Status);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
HandleControlChannelPackets(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG PacketHandle)
{
    PKD_NET_UDP Packet;
    PKD_NET_KD_HEADER KdPacket;
    ULONG PacketLength;
    USHORT Length;
    USHORT UdpLength;
    NTSTATUS Status;

    if (IsDbgComInitialized)
        DbgPrint0("HandleControlChannelPackets: %X\n", PacketHandle);

    if (!NetData->NetParameters->IsEncryptionKey)
    {
        if (IsDbgComInitialized)
            DbgPrint0("HandleControlChannelPackets: IsEncryptionKey is FALSE\n");

        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    PacketLength = GetPacketLength(NetData, PacketHandle);
    Packet = GetPacketAddress(NetData, PacketHandle);

    if (PacketLength < sizeof(KD_NET_ETH_HEADER) &&
        Packet->EthHeader.EtherType != sizeof(KD_NET_UDP_PACKET) ||
        !RtlEqualMemory(NetData->MacAddress, Packet->EthHeader.DestinationMac, 6))
    {
        if (IsDbgComInitialized)
            DbgPrint0("HandleControlChannelPackets: (1) STATUS_MORE_PROCESSING_REQUIRED (%X, %X)\n", PacketLength, Packet->EthHeader.EtherType);

        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    PacketLength -= sizeof(KD_NET_ETH_HEADER);

    if (PacketLength < sizeof(KD_NET_IPv4_PACKET) || Packet->Ipv4.Protocol != 0x11)
    {
        if (IsDbgComInitialized)
            DbgPrint0("HandleControlChannelPackets: (2) STATUS_MORE_PROCESSING_REQUIRED (%X, %X)\n", PacketLength, Packet->Ipv4.Protocol);

        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    PacketLength -= sizeof(KD_NET_IPv4_PACKET);

    if (PacketLength < sizeof(KD_NET_UDP_PACKET))
    {
        if (IsDbgComInitialized)
            DbgPrint0("HandleDhcp: STATUS_MORE_PROCESSING_REQUIRED (%X)\n", PacketLength);

        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    if (Packet->Udp.DestinationPort != UshortSwap(NetData->NetParameters->DebuggeePort))
    {
        if (IsDbgComInitialized)
            DbgPrint0("HandleControlChannelPackets: (3) STATUS_MORE_PROCESSING_REQUIRED (%X, %X)\n", Packet->Udp.DestinationPort, UshortSwap(NetData->NetParameters->DebuggeePort));

        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    PacketLength -= sizeof(KD_NET_UDP_PACKET);

    UdpLength = UshortSwap(Packet->Udp.Length);

    if (UdpLength < sizeof(KD_NET_UDP_PACKET))
        UdpLength = sizeof(KD_NET_UDP_PACKET);

    Length = (UdpLength - sizeof(KD_NET_UDP_PACKET));

    if (Length > PacketLength)
        Length = PacketLength;

    KdPacket = Add2Ptr(Packet, sizeof(*Packet));

    if (Length < 0x26 || // FIXME
        KdPacket->Tag != 'GBDM' ||
        KdPacket->Unknown1 != 2 ||
        !(KdPacket->Unknown2 & 1))
    {
        if (IsDbgComInitialized)
            DbgPrint0("HandleControlChannelPackets: (3) STATUS_MORE_PROCESSING_REQUIRED (%X, %X, %X, %X)\n", Length, KdPacket->Tag, KdPacket->Unknown1, KdPacket->Unknown2);

        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    PacketLength = Length;

    Status = DecryptKdPacket(NetData, &Packet, &PacketLength);
    if (NT_SUCCESS(Status))
    {
        //KdNetControlChannelPacketsHandled++;
        return Status;
    }

    if (IsDbgComInitialized)
        DbgPrint0("HandleControlChannelPackets: KdNetControlChannelPacketsDropped++ (%X)\n", Status);

    //KdNetControlChannelPacketsDropped++;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdNicReceivePacket(
    _In_ PKD_NET_DATA NetData,
    _In_ PVOID Packet,
    _In_ ULONG PacketLength)
{
    NTSTATUS Status;

    if (IsDbgComInitialized)
        DbgPrint0("KdNicReceivePacket: %X\n", PacketLength);

    if (InterlockedIncrement(&KdNicReceiveEntered) > 1)
        InterlockedIncrement(&KdNicReceiveReentered);

    if (NetData->NicData != &KdNicData)
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdNicReceivePacket: STATUS_INVALID_PARAMETER\n");

        Status = STATUS_INVALID_PARAMETER;
        goto Finish;
    }

    Status = STATUS_UNSUCCESSFUL;

    if (!NetData->NicData->Reserved0)
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdNicReceivePacket: KdNicReceivePacketsIgnored++\n");

        //KdNicReceivePacketsIgnored++;

        goto Finish;
    }

    if (IsDbgComInitialized)
        DbgPrint0("KdNicReceivePacket: FIXME! (%X)\n", NetData->NicData->Reserved0);

    ASSERT(FALSE);


Finish:

    InterlockedDecrement(&KdNicReceiveEntered);

    return Status;
}

NTSTATUS
NTAPI
ProcessControlChannelPacket(
    _In_ PKD_NET_DATA NetData,
    _In_ PVOID Packet,
    _In_ ULONG PacketLength,
    _In_ ULONGLONG SequenceNumber)
{
    if (IsDbgComInitialized)
        DbgPrint0("ProcessControlChannelPacket: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
WaitForSpecificRxIpPacket(
    _In_ PKD_NET_DATA NetData,
    _In_ PULONG OutPacketHandle,
    _In_ PVOID* OutPacket,
    _In_ ULONG* OutPacketLength,
    _In_ ULONG* OutCycleCount,
    _In_ PUCHAR HostMac,
    _In_ PUCHAR MacAddress,
    _In_ ULONG HostIp,
    _In_ ULONG TargetIP,
    _In_ UCHAR Protocol)
{
    PKD_NET_IPv4_PACKET Packet;
    ULONG Length;
    USHORT HeaderLength;
    USHORT PacketLength;
    USHORT TotalLength;
    USHORT EtherType = ETHERNET_TYPE_IPV4;
    NTSTATUS Status;

    if (IsDbgComInitialized)
        DbgPrint0("WaitForSpecificRxIpPacket: %X, %X\n", HostIp, TargetIP);

    Status = WaitForSpecificRxPacket(NetData,
                                     OutPacketHandle,
                                     OutPacket,
                                     OutPacketLength,
                                     OutCycleCount,
                                     HostMac,
                                     MacAddress,
                                     &EtherType);
    if (!NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("WaitForSpecificRxIpPacket: (1) Status %X\n", Status);

        return Status;
    }

    while (TRUE)
    {
        if (*OutPacketLength < sizeof(KD_NET_IPv4_PACKET))
        {
            if (IsDbgComInitialized)
                DbgPrint0("WaitForSpecificRxIpPacket: KdNetRxPacketToSmallForIp++ (%X)\n", *OutPacketLength);

            //KdNetRxPacketToSmallForIp++;
        }
        else
        {
            Packet = *OutPacket;
            Length = (*OutPacketLength - sizeof(KD_NET_IPv4_PACKET));

            HostIp = UlongSwap(HostIp);
            TargetIP = UlongSwap(TargetIP);

            if ((!HostIp || HostIp == Packet->SourceIp) &&
                (!TargetIP || TargetIP == Packet->DestinationIp) &&
                (!Protocol || Protocol == Packet->Protocol))
            {
                break;
            }

            if (IsDbgComInitialized)
                DbgPrint0("WaitForSpecificRxIpPacket: KdNetRxIpPacketsHandedOff++ (%X)\n", Protocol);

            //KdNetRxIpPacketsHandedOff++;

            ProcessUnhandledPackets(NetData, *OutPacketHandle);
        }

        ReleaseRxPacket(NetData, *OutPacketHandle);

        Status = WaitForSpecificRxPacket(NetData,
                                         OutPacketHandle,
                                         OutPacket,
                                         OutPacketLength,
                                         OutCycleCount,
                                         HostMac,
                                         MacAddress,
                                         &EtherType);
        if (!NT_SUCCESS(Status))
        {
            if (IsDbgComInitialized)
                DbgPrint0("WaitForSpecificRxIpPacket: (2) Status %X\n", Status);

            return Status;
        }
    }

    *OutPacket = Add2Ptr(Packet, sizeof(*Packet));

    TotalLength = UshortSwap(Packet->TotalLength);

    if (TotalLength >= (Packet->Version * 4))
        HeaderLength = TotalLength;
    else
        HeaderLength = (Packet->Version * 4);

    PacketLength = (HeaderLength - (Packet->Version * 4));

    if (PacketLength > Length)
    {
        if (IsDbgComInitialized)
            DbgPrint0("WaitForSpecificRxIpPacket: KdNetRxIpPacketsHandedOff++ (%X, %X)\n", PacketLength, Length);

        //KdNetRxIpPacketsMalformed++;

        PacketLength = Length;
    }

    *OutPacketLength = PacketLength;

    if (IsDbgComInitialized)
        DbgPrint0("WaitForSpecificRxIpPacket: KdNetRxIpPacketsMatched++ (%X)\n", PacketLength);

    //KdNetRxIpPacketsMatched++;

    return Status;
}

NTSTATUS
NTAPI
WaitForSpecificRxUdpPacketEx(
    _In_ PKD_NET_DATA NetData,
    _In_ PULONG OutPacketHandle,
    _In_ PVOID* OutPacket,
    _In_ PULONG OutPacketLength,
    _In_ PULONG OutCycleCount,
    _In_ PUCHAR HostMac,
    _In_ PUCHAR MacAddress,
    _In_ ULONG HostIp,
    _In_ ULONG TargetIP,
    _In_ PUSHORT OutHostPort,
    _In_ PUSHORT OutDebuggeePort)
{
    PKD_NET_UDP_PACKET Packet;
    ULONG PacketLength;
    ULONG DataLength;
    USHORT UdpDataLength;
    USHORT UdpLength;
    USHORT DebuggeePort;
    USHORT HostPort;
    NTSTATUS Status;

    if (IsDbgComInitialized)
        DbgPrint0("WaitForSpecificRxUdpPacketEx: %X, %X\n", HostIp, TargetIP);

    Status = WaitForSpecificRxIpPacket(NetData,
                                       OutPacketHandle,
                                       OutPacket,
                                       OutPacketLength,
                                       OutCycleCount,
                                       HostMac,
                                       MacAddress,
                                       HostIp,
                                       TargetIP,
                                       0x11);
    if (!NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("WaitForSpecificRxUdpPacketEx: (1) Status %X\n", Status);

        return Status;
    }

    while (TRUE)
    {
        PacketLength = *OutPacketLength;

        if (PacketLength < sizeof(KD_NET_UDP_PACKET))
        {
            if (IsDbgComInitialized)
                DbgPrint0("WaitForSpecificRxUdpPacketEx: KdNetRxPacketToSmallForUdp++ (%X)\n", PacketLength);

            //KdNetRxPacketToSmallForUdp++;
        }
        else
        {
            DataLength = (PacketLength - sizeof(KD_NET_UDP_PACKET));

            DebuggeePort = UshortSwap(*OutDebuggeePort);
            HostPort = UshortSwap(*OutHostPort);

            Packet = *OutPacket;

            if ((!HostPort || HostPort == Packet->SourcePort) &&
                (!DebuggeePort || DebuggeePort == Packet->DestinationPort))
            {
                break;
            }

            //KdNetRxUdpPacketsHandedOff++;

            ProcessUnhandledPackets(NetData, *OutPacketHandle);
        }

        ReleaseRxPacket(NetData, *OutPacketHandle);

        Status = WaitForSpecificRxIpPacket(NetData,
                                           OutPacketHandle,
                                           OutPacket,
                                           OutPacketLength,
                                           OutCycleCount,
                                           HostMac,
                                           MacAddress,
                                           HostIp,
                                           TargetIP,
                                           0x11);
        if (!NT_SUCCESS(Status))
        {
            if (IsDbgComInitialized)
                DbgPrint0("WaitForSpecificRxUdpPacketEx: (2) Status %X\n", Status);

            return Status;
        }
    }

    *OutPacket = &Packet[1];

    UdpLength = UshortSwap(Packet->Length);

    if (UdpLength < sizeof(KD_NET_UDP_PACKET))
        UdpLength = sizeof(KD_NET_UDP_PACKET);

    UdpDataLength = (UdpLength - sizeof(KD_NET_UDP_PACKET));

    if (UdpDataLength > DataLength)
    {
        //KdNetRxUdpPacketsMalformed++;
        UdpDataLength = DataLength;
    }

    *OutPacketLength = UdpDataLength;

    //KdNetRxUdpPacketsMatched++;

    *OutHostPort = UshortSwap(Packet->SourcePort);
    *OutDebuggeePort = UshortSwap(Packet->DestinationPort);

    return Status;
}

NTSTATUS
NTAPI
WaitForResponsePacket(
    _In_ PKD_NET_DATA NetData,
    _In_ PUCHAR HostMac,
    _In_ ULONG HostIp,
    _In_ USHORT Port,
    _In_ ULONG* OutCycleCount)
{
    PVOID Packet;
    ULONG PacketLength;
    ULONG PacketHandle;
    NTSTATUS Status;

    if (IsDbgComInitialized)
        DbgPrint0("WaitForResponsePacket: %p, %X\n", NetData, HostIp);

    if (!NetData->NetParameters->IsVerifyHostMac && (NetData->YourIp & 0xFFFF0000) != AUTOIP_NET)
        HostMac = NULL;

    do
    {
        Status = WaitForSpecificRxUdpPacketEx(NetData,
                                              &PacketHandle,
                                              &Packet,
                                              &PacketLength,
                                              OutCycleCount,
                                              HostMac,
                                              NetData->MacAddress,
                                              HostIp,
                                              NetData->YourIp,
                                              &Port,
                                              &NetData->NetParameters->DebuggeePort);
        if (!NT_SUCCESS(Status))
        {
            if (IsDbgComInitialized)
                DbgPrint0("WaitForResponsePacket: Status %X\n", Status);

            break;
        }

        Status = DecryptKdPacket(NetData, &Packet, &PacketLength);
        if (!NT_SUCCESS(Status))
        {
            if (IsDbgComInitialized)
                DbgPrint0("WaitForResponsePacket: Decrypt Status %X\n", Status);

            //KdNetRxKdPacketsHandedOff++;

            ProcessUnhandledPackets(NetData, PacketHandle);
        }

        ReleaseRxPacket(NetData, PacketHandle);
    }
    while (!NetData->NetParameters->DataChannel);

    return Status;
}

NTSTATUS
NTAPI
USB3InitializeController(
    _In_ PVOID NetData)
{
    if (IsDbgComInitialized)
        DbgPrint0("USB3InitializeController: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
KdVmInitializeController(
    _In_ PVOID NetData)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdVmInitializeController: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
KdHvInitializeController(
    _In_ PVOID NetData)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdHvInitializeController: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);

    return STATUS_NOT_IMPLEMENTED;
}

PVOID
NTAPI
GetPacketAddress(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG PacketHandle)
{
    PVOID Packet = NULL;

    //if (IsDbgComInitialized)
    //    DbgPrint0("GetPacketAddress: %p, %X, %X\n", NetData, NetData->VendorId, PacketHandle);

    if (!NetData)
        return Add2Ptr(NetData, -PAGE_SIZE);

    if (NetData->VendorId == 0xFFFB)
    {
        if (IsDbgComInitialized)
            DbgPrint0("GetPacketAddress: Not implemented (%X)\n", NetData->VendorId);

        Packet = 0;//USB3GetPacketAddress(NetData->SharedData.Hardware, PacketHandle);

        KeBugCheck(MANUALLY_INITIATED_CRASH);
    }
    else if (NetData->VendorId == 0xFFFC)
    {
        if (IsDbgComInitialized)
            DbgPrint0("GetPacketAddress: Not implemented (%X)\n", NetData->VendorId);

        Packet = 0;//KdVmGetPacketAddress(NetData->SharedData.Hardware, PacketHandle);

        KeBugCheck(MANUALLY_INITIATED_CRASH);
    }
    else if (NetData->VendorId == 0xFFFD)
    {
        if (IsDbgComInitialized)
            DbgPrint0("GetPacketAddress: Not implemented (%X)\n", NetData->VendorId);

        Packet = 0;//KdVmGetPacketAddress(NetData->SharedData.Hardware, PacketHandle);

        KeBugCheck(MANUALLY_INITIATED_CRASH);
    }
    else if (NetData->VendorId == 0xFFFE)
    {
        Packet = KdGetPacketAddress(NetData->SharedData.Hardware, PacketHandle);
    }

    if (Packet)
        return Packet;

    return Add2Ptr(NetData, -PAGE_SIZE);
}

PVOID
NTAPI
GetPacketKdData(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG PacketHandle)
{
    PVOID Packet;

    Packet = GetPacketAddress(NetData, PacketHandle);
    Packet = Add2Ptr(Packet, sizeof(KD_NET_UDP));

    if (!NetData->NetParameters->IsEncryptionKey)
        return Packet;

    Packet = Add2Ptr(Packet, sizeof(KD_NET_KD_HEADER));

    return Packet;
}

#define HV_X64_MSR_TIME_REF_COUNT 0x40000020

ULONGLONG
NTAPI
KdNetReadCycleCounter(
    _In_ PKD_NET_DATA NetData)
{
    ULONGLONG TimeStampCounter;

    if (NetData->VendorId == 0xFFFD || NetData->VendorId == 0xFFFC)
        TimeStampCounter = __readmsr(HV_X64_MSR_TIME_REF_COUNT);
    else
        TimeStampCounter = __rdtsc();

    return TimeStampCounter;
}

USHORT
NTAPI
OnesComplementSum(
    _In_ PUCHAR Ptr,
    _In_ ULONG InSize)
{
    ULONG Size = InSize;
    ULONG Checksum = 0;
    ULONG Value;
    ULONG ix;

    if (InSize > 1)
    {
        ix = (((InSize - 2) / 2) + 1);

        do
        {
            Value = *(PUSHORT)Ptr + Checksum;
            Checksum = (((Value >> 16) + Value) & 0xFFFF);

            Size -= 2;
            Ptr += 2;
            ix--;
        }
        while (ix);
    }

    if (Size)
        Checksum = ((((*Ptr + Checksum) >> 16) + (*Ptr + Checksum)) & 0xFFFF);

    return Checksum;
}

VOID
NTAPI
SwapPacket(
    _In_ PVOID Packet,
    _In_ BOOLEAN IsSwapChecksum)
{
    PKD_NET_ETH_HEADER Header = Packet;
    PKD_NET_IPv4 Ip4Packet = Packet;
    PKD_NET_ARP ArpPacket = Packet;
    PKD_NET_UDP Udp = Packet;
    PKD_NET_IPv4_PACKET Ipv4;
    USHORT EtherType;

    //if (IsDbgComInitialized)
    //    DbgPrint0("SwapPacket: %p, %X\n", Packet, IsSwapChecksum);

    EtherType = Header->EtherType;

    Header->EtherType = UshortSwap(Header->EtherType);

    if (!IsSwapChecksum)
        EtherType = Header->EtherType;

    if (EtherType == ETHERNET_TYPE_IPV4)
    {
        Ipv4 = &Ip4Packet->Ipv4;

        Ipv4->TotalLength = UshortSwap(Ipv4->TotalLength);
        Ipv4->IpHdr1 = UshortSwap(Ipv4->IpHdr1);
        Ipv4->SourceIp = UlongSwap(Ipv4->SourceIp);
        Ipv4->DestinationIp = UlongSwap(Ipv4->DestinationIp);

        if (IsSwapChecksum && !Ipv4->HeaderChecksum)
            Ipv4->HeaderChecksum = ~OnesComplementSum((PUCHAR)Ipv4, sizeof(KD_NET_IPv4_PACKET));

        if (Ipv4->Protocol == IPPROTO_UDP)
        {
            Udp->Udp.SourcePort = UshortSwap(Udp->Udp.SourcePort);
            Udp->Udp.DestinationPort = UshortSwap(Udp->Udp.DestinationPort);
            Udp->Udp.Length = UshortSwap(Udp->Udp.Length);
        }

        return;
    }

    if (EtherType != ETHERNET_TYPE_ARP && EtherType != ETHERNET_TYPE_RARP)
        return;

    ArpPacket->Arp.HardwareType = UshortSwap(ArpPacket->Arp.HardwareType);
    ArpPacket->Arp.ProtocolType = UshortSwap(ArpPacket->Arp.ProtocolType);
    ArpPacket->Arp.Operation = UshortSwap(ArpPacket->Arp.Operation);

    if (ArpPacket->Arp.HardwareLen == 6 && ArpPacket->Arp.ProtocolLen == 4)
    {
        ArpPacket->Arp.SenderIp = UlongSwap(ArpPacket->Arp.SenderIp);
        ArpPacket->Arp.TargetIp = UlongSwap(ArpPacket->Arp.TargetIp);
    }
}

NTSTATUS
NTAPI
GetTxPacket(
    _In_ PKD_NET_DATA NetData,
    _Out_ ULONG* PacketHandle)
{
    NTSTATUS Status;

    //if (IsDbgComInitialized)
    //    DbgPrint0("GetTxPacket: %p\n", PacketHandle);

    if (!NetData)
    {
        if (IsDbgComInitialized)
            DbgPrint0("GetTxPacket: STATUS_INVALID_PARAMETER\n");

        return STATUS_INVALID_PARAMETER;
    }

    switch (NetData->VendorId)
    {
        case 0xFFFB:
            if (IsDbgComInitialized)
                DbgPrint0("GetTxPacket: STATUS_NOT_IMPLEMENTED (%X)\n", NetData->VendorId);

            //Status = USB3GetTxPacket(NetData->SharedData.Hardware, PacketHandle);

            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case 0xFFFC:
            if (IsDbgComInitialized)
                DbgPrint0("GetTxPacket: STATUS_NOT_IMPLEMENTED (%X)\n", NetData->VendorId);

            //Status = KdHvGetTxPacket(NetData->SharedData.Hardware, PacketHandle);

            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case 0xFFFD:
            if (IsDbgComInitialized)
                DbgPrint0("GetTxPacket: STATUS_NOT_IMPLEMENTED (%X)\n", NetData->VendorId);

            //Status = KdHvGetTxPacket(NetData->SharedData.Hardware, PacketHandle);

            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case 0xFFFE:
            Status = KdGetTxPacket(NetData->SharedData.Hardware, PacketHandle);
            break;

        default:
            if (IsDbgComInitialized)
                DbgPrint0("GetTxPacket: STATUS_NO_SUCH_DEVICE (%X)\n", NetData->VendorId);

            Status = STATUS_NO_SUCH_DEVICE;
            break;
    }

    return Status;
}

VOID
NTAPI
UpdateTargetRandom(
    _In_ PKD_NET_DATA NetData)
{
    if (NetData->VendorId != 0xFFFC)
        return;

    if (IsDbgComInitialized)
        DbgPrint0("UpdateTargetRandom: Unimplemented!\n");
}

NTSTATUS
NTAPI
SendTxPacket(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG PacketHandle,
    _In_ ULONG PacketLength)
{
    NTSTATUS Status;

    //if (IsDbgComInitialized)
    //    DbgPrint0("SendTxPacket: %p, %X, %X\n", NetData, PacketHandle, PacketLength);

    if (!NetData)
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendTxPacket: STATUS_INVALID_PARAMETER\n");

        //KdNetTxError++;

        return STATUS_INVALID_PARAMETER;
    }

    switch (NetData->VendorId)
    {
        case 0xFFFB:
            if (IsDbgComInitialized)
                DbgPrint0("SendTxPacket: STATUS_NOT_IMPLEMENTED (%X)\n", NetData->VendorId);
            //Status = USB3SendTxPacket(NetData->SharedData.Hardware, PacketHandle, PacketLength);
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case 0xFFFC:
            if (IsDbgComInitialized)
                DbgPrint0("SendTxPacket: STATUS_NOT_IMPLEMENTED (%X)\n", NetData->VendorId);
            //Status = KdVmSendTxPacket(NetData, PacketHandle, PacketLength);
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case 0xFFFD:
            if (IsDbgComInitialized)
                DbgPrint0("SendTxPacket: STATUS_NOT_IMPLEMENTED (%X)\n", NetData->VendorId);
            //Status = KdHvSendTxPacket(NetData->SharedData.Hardware, PacketHandle, PacketLength);
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case 0xFFFE:
            Status = KdSendTxPacket(NetData->SharedData.Hardware, PacketHandle, PacketLength);
            break;

        default:
            if (IsDbgComInitialized)
                DbgPrint0("SendTxPacket: STATUS_NO_SUCH_DEVICE (%X)\n", NetData->VendorId);
            //KdNetTxError++;
            return STATUS_NO_SUCH_DEVICE;
    }

    if (Status == STATUS_IO_TIMEOUT)
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendTxPacket: STATUS_IO_TIMEOUT (%X, %X)\n", PacketHandle, PacketLength);

        //KdNetTxTimeout++;
    }
    else if (Status == STATUS_CONNECTION_RESET)
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendTxPacket: STATUS_CONNECTION_RESET (%X, %X)\n", PacketHandle, PacketLength);

        UpdateTargetRandom(NetData);

        Status = STATUS_SUCCESS;
    }
    else if (Status == STATUS_SUCCESS)
    {
        ;//KdNetTxOk++;
    }
    else
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendTxPacket: ret Status %X (%X, %X)\n", Status, PacketHandle, PacketLength);

        //KdNetTxError++;
    }

    return Status;
}

NTSTATUS
NTAPI
SendEthernetPacket(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG PacketHandle,
    _In_ ULONG PacketLength,
    _In_ PUCHAR SourceMac,
    _In_ PUCHAR DestinationMac,
    _In_ USHORT EtherType)
{
    PKD_NET_ETH_HEADER Packet;
    NTSTATUS Status;

    if (IsDbgComInitialized)
        DbgPrint0("SendEthernetPacket: %X, %X\n", PacketHandle, PacketLength);

    if (!NetData)
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendEthernetPacket: STATUS_INVALID_PARAMETER, NetData is NULL\n");

        return STATUS_INVALID_PARAMETER;
    }

    if (!DestinationMac)
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendEthernetPacket: STATUS_INVALID_PARAMETER, DestinationMac is NULL\n");

        return STATUS_INVALID_PARAMETER;
    }

    if (!SourceMac)
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendEthernetPacket: STATUS_INVALID_PARAMETER, SourceMac is NULL\n");

        return STATUS_INVALID_PARAMETER;
    }

    Packet = GetPacketAddress(NetData, PacketHandle);

    RtlCopyMemory(Packet->DestinationMac, DestinationMac, 6);
    RtlCopyMemory(Packet->SourceMac, SourceMac, 6);

    Packet->EtherType = EtherType;

    SwapPacket(Packet, TRUE);

    Status = SendTxPacket(NetData, PacketHandle, (PacketLength + sizeof(KD_NET_ETH_HEADER)));

    return Status;
}

NTSTATUS
NTAPI
SendIPPacket(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG PacketHandle,
    _In_ PUCHAR SourceMac,
    _In_ PUCHAR DestinationMac,
    _In_ ULONG PacketLength,
    _In_ ULONG SourceIp,
    _In_ ULONG TargetIp,
    _In_ UCHAR Protocol,
    _In_ UCHAR DscpEcn,
    _In_ UCHAR Ttl)
{
    PKD_NET_UDP Packet;
    ULONG Length;
    NTSTATUS Status;

    if (IsDbgComInitialized)
        DbgPrint0("SendIPPacket: %X, %X\n", PacketHandle, PacketLength);

    if (PacketLength > 0xFFE3) // 65507
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendIPPacket: STATUS_INVALID_PARAMETER (%X, %X)\n", PacketHandle, PacketLength);

        return STATUS_INVALID_PARAMETER;
    }

    Length = (PacketLength + sizeof(KD_NET_IPv4_PACKET));

    Packet = GetPacketAddress(NetData, PacketHandle);

    Packet->Ipv4.IpHdr0 = 0;
    Packet->Ipv4.Version = 5;
    Packet->Ipv4.InternetHdrLen = 4; // IHL
    Packet->Ipv4.TypeOfService = (DscpEcn & 0x3F); // DSCP
    Packet->Ipv4.EcNotification = (((DscpEcn & 0xC0) >> 6) & 3); // ECN

    Packet->Ipv4.TotalLength = Length;
    Packet->Ipv4.Identification = 0;
    Packet->Ipv4.IpHdr1 = 0x4000;
    Packet->Ipv4.TimeToLive = Ttl; // Time to live
    Packet->Ipv4.Protocol = Protocol;
    Packet->Ipv4.HeaderChecksum = 0;
    Packet->Ipv4.SourceIp = SourceIp;
    Packet->Ipv4.DestinationIp = TargetIp;

    Status = SendEthernetPacket(NetData, PacketHandle, Length, SourceMac, DestinationMac, ETHERNET_TYPE_IPV4);

    return Status;
}

NTSTATUS
NTAPI
SendUDPPacketEx(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG PacketHandle,
    _In_ PUCHAR SourceMac,
    _In_ PUCHAR DestinationMac,
    _In_ ULONG SourceIp,
    _In_ ULONG TargetIp,
    _In_ UCHAR DscpEcn,
    _In_ UCHAR Ttl,
    _In_ ULONG PacketLength,
    _In_ USHORT SourcePort,
    _In_ USHORT DestinationPort)
{
    PKD_NET_UDP Packet;
    ULONG Length;
    NTSTATUS Status;

    if (IsDbgComInitialized)
        DbgPrint0("SendUDPPacketEx: %X, %X\n", PacketHandle, PacketLength);

    if (PacketLength > 0xFFE3) // 65507
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendUDPPacketEx: STATUS_INVALID_PARAMETER (%X, %X)\n", PacketHandle, PacketLength);

        return STATUS_INVALID_PARAMETER;
    }

    Length = (PacketLength + sizeof(KD_NET_UDP_PACKET));

    Packet = GetPacketAddress(NetData, PacketHandle);

    Packet->Udp.SourcePort = SourcePort;
    Packet->Udp.DestinationPort = DestinationPort;
    Packet->Udp.Length = Length;
    Packet->Udp.Checksum = 0;

    Status = SendIPPacket(NetData, PacketHandle, SourceMac, DestinationMac, Length, SourceIp, TargetIp, 0x11, DscpEcn, Ttl);

    return Status;
}

NTSTATUS
NTAPI
SendOfferPacketEx(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG PacketHandle,
    _In_ PUCHAR HostMac,
    _In_ ULONG HostIp,
    _In_ USHORT SendersPort)
{
    PKD_NET_KD_HEADER KdPacketHeader;
    PKD_NET_KD_DATA KdPacketData;
    PKD_NET_UDP Packet;

    ULONG HostIp2;
    ULONG PacketLength;
    BOOLEAN IsEnteredDebugger;
    NTSTATUS Status;

    Packet = GetPacketAddress(NetData, PacketHandle);
    KdPacketHeader = (PKD_NET_KD_HEADER)&Packet->Data[0];

    KdPacketData = GetPacketKdData(NetData, PacketHandle);
    RtlZeroMemory(KdPacketData, sizeof(KD_NET_KD_DATA));

    if (IsDbgComInitialized)
        DbgPrint0("SendOfferPacketEx: %d, %p, %p\n", SendersPort, Packet, KdPacketData);

  #if 0
    //FIXME BytesForNtoskrnl;
  #endif

    KdPacketData->KdData0 = 0x0101;
    KdPacketData->Unknown1 = UlongSwap(0xFFFF);
    KdPacketData->DebuggeeIp = UlongSwap(NetData->YourIp);
    KdPacketData->DebuggeePort = UshortSwap(NetData->NetParameters->DebuggeePort);
    KdPacketData->Unknown2 = UlongSwap(0xFFFF);
    KdPacketData->HostIp1 = UlongSwap(NetData->NetParameters->HostIp1);
    KdPacketData->HostPort1 = UshortSwap(NetData->NetParameters->HostPort1);

    if (NetData->NetParameters->DataChannel)
        HostIp2 = NetData->NetParameters->HostIp2;
    else
        HostIp2 = 0;

    KdPacketData->Unknown3 = UlongSwap(0xFFFF);
    KdPacketData->HostIp2 = UlongSwap(HostIp2);

    if (NetData->NetParameters->DataChannel)
        KdPacketData->Port2 = UshortSwap(NetData->NetParameters->HostPort2);

    if (NetData->NetParameters->DataChannel)
        RtlCopyMemory(KdPacketData->Data, NetData->NetParameters->KdData, sizeof(KdPacketData->Data));

    PacketLength = sizeof(KD_NET_KD_DATA);

    if (KdNetParameters.IsSendKdStatus && KdEnteredDebugger)
        IsEnteredDebugger = TRUE;
    else
        IsEnteredDebugger = FALSE;

    //if (IsDbgComInitialized)
    //    DbgPrint0("SendOfferPacketEx: %X, %X\n", KdPacketHeader, PacketLength);
    //KdNetDump(Packet, PacketLength + sizeof(KD_NET_UDP));

    EncryptKdPacket(KdPacketHeader, &PacketLength, NetData->AesCtx, NetData->KeyToken, NetData->NetParameters->Stamp, (IsEnteredDebugger?3:1));

    //if (IsDbgComInitialized)
    //    DbgPrint0("SendOfferPacketEx: %X, %X\n", KdPacketHeader, PacketLength);
    //KdNetDump(Packet, PacketLength + sizeof(KD_NET_UDP));

    Status = SendUDPPacketEx(NetData,
                             PacketHandle,
                             NetData->MacAddress,
                             HostMac,
                             NetData->YourIp,
                             HostIp,
                             0,
                             0x10,
                             PacketLength,
                             NetData->NetParameters->DebuggeePort,
                             SendersPort);
    if (NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendOfferPacketEx: KdNetOfferPacketSent++\n");
        //KdNetOfferPacketSent++;
    }
    else
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendOfferPacketEx: Status %X\n", Status);
    }

    return Status;
}

NTSTATUS
NTAPI
SendUDPPacket(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG PacketHandle,
    _In_ ULONG PacketLength,
    _In_ USHORT SourcePort,
    _In_ USHORT DestinationPort)
{
    return SendUDPPacketEx(NetData,
                           PacketHandle,
                           NetData->MacAddress,
                           NetData->NetParameters->HostMac,
                           NetData->YourIp,
                           NetData->NetParameters->HostIp2,
                           0,
                           0x10,
                           PacketLength,
                           SourcePort,
                           DestinationPort);
}

NTSTATUS
NTAPI
SendKdPacket(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG PacketHandle,
    _In_ ULONG PacketLength,
    _In_ USHORT SourcePort,
    _In_ USHORT DestinationPort)
{
    PKD_NET_KD_HEADER KdPacket;
    PLONGLONG DataStamp;
    ULONGLONG Stamp;
    LONGLONG OldDataStamp;

    if (!NetData->NetParameters->IsEncryptionKey)
        goto Finish;

    if (!NetData->NetParameters->DataChannel)
    {
        //KdNetSendKdPacketNoDataChannel++;

        SendOfferPacketEx(NetData,
                          PacketHandle,
                          NetData->NetParameters->HostMac,
                          NetData->NetParameters->HostIp2,
                          DestinationPort);

        return STATUS_LINK_FAILED;
    }

    KdPacket = Add2Ptr(GetPacketAddress(KdNetData, PacketHandle), sizeof(KD_NET_UDP));

    DataStamp = &NetData->NetParameters->DataStamp;

    do
    {
        OldDataStamp = *DataStamp;
    }
    while (InterlockedCompareExchange64(DataStamp, (*DataStamp + 1), *DataStamp) != OldDataStamp);

    Stamp = (OldDataStamp + 1);

    EncryptKdPacket(KdPacket, &PacketLength, &NetData->AesCtx[1], NetData->KeyToken, Stamp, 0);

Finish:

    return SendUDPPacket(KdNetData, PacketHandle, PacketLength, SourcePort, DestinationPort);
}

NTSTATUS
NTAPI
SendPingPacket(
    _In_ PKD_NET_DATA NetData)
{
    PKD_NET_PING_PACKET PingPacket;
    ULONG PacketHandle;
    NTSTATUS Status;

    Status = GetTxPacket(NetData, &PacketHandle);
    if (!NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendPingPacket: Status %X\n", Status);

        return Status;
    }

    PingPacket = GetPacketKdData(NetData, PacketHandle);

    PingPacket->SequenceNumber = NetData->NetParameters->SequenceNumber;
    PingPacket->HostIp = NetData->NetParameters->HostIp2;

    Status = SendKdPacket(NetData, PacketHandle, 0xC, NetData->NetParameters->DebuggeePort, NetData->NetParameters->HostPort2);

    return Status;
}

NTSTATUS
NTAPI
SendOfferPacket(
    _In_ ULONG PacketHandle,
    _In_ PKD_NET_DATA NetData,
    _In_ PUCHAR HostMac,
    _In_ ULONG HostIp,
    _In_ USHORT SendersPort)
{
    NTSTATUS Status;

    Status = GetTxPacket(NetData, &PacketHandle);
    if (NT_SUCCESS(Status))
    {
        Status = SendOfferPacketEx(NetData, PacketHandle, HostMac, HostIp, SendersPort);
    }
    else
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendOfferPacket: Status %X\n", Status);
    }

    return Status;
}

NTSTATUS
NTAPI
ProcessUnhandledPackets(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG PacketHandle)
{
    PVOID Packet;
    ULONG PacketLength;
    NTSTATUS Status;

    if (IsDbgComInitialized)
        DbgPrint0("ProcessUnhandledPackets: %X\n", PacketHandle);

    Status = HandleDhcp(NetData, PacketHandle);
    if (NT_SUCCESS(Status))
        return Status;

    Status = HandleControlChannelPackets(NetData, PacketHandle);
    if (NT_SUCCESS(Status))
        return Status;

    PacketLength = GetPacketLength(NetData, PacketHandle);
    Packet = GetPacketAddress(NetData, PacketHandle);

    Status = KdNicReceivePacket(NetData, Packet, PacketLength);
    if (!NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("ProcessUnhandledPackets: Status %X\n", Status);

        //KdNetRxPacketsDiscarded++;
    }

    return Status;
}

VOID
NTAPI
ReleaseRxPacket(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG PacketHandle)
{
    if (IsDbgComInitialized)
        DbgPrint0("ReleaseRxPacket: %X\n", NetData->VendorId);

    if (!NetData)
        return;

    switch (NetData->VendorId)
    {
        case 0xFFFB:
            if (IsDbgComInitialized)
                DbgPrint0("ReleaseRxPacket: Not implemented (%X)\n", NetData->VendorId);

            //USB3ReleaseRxPacket(NetData->SharedData.Hardware, PacketHandle);

            //KdNetRxPacketsReleased++;
            break;

        case 0xFFFC:
            if (IsDbgComInitialized)
                DbgPrint0("ReleaseRxPacket: Not implemented (%X)\n", NetData->VendorId);

            //KdHvReleaseRxPacket(NetData->SharedData.Hardware, PacketHandle);

            //KdNetRxPacketsReleased++;
            break;

        case 0xFFFD:
            if (IsDbgComInitialized)
                DbgPrint0("ReleaseRxPacket: Not implemented (%X)\n", NetData->VendorId);

            //KdHvReleaseRxPacket(NetData->SharedData.Hardware, PacketHandle);

            //KdNetRxPacketsReleased++;
            break;

        case 0xFFFE:
            KdReleaseRxPacket(NetData->SharedData.Hardware, PacketHandle);
            //KdNetRxPacketsReleased++;
            break;

        default:
            if (IsDbgComInitialized)
                DbgPrint0("ReleaseRxPacket: Not supported %X\n", NetData->VendorId);
            break;
    }
}

NTSTATUS
NTAPI
HandleArp(
    _In_ PKD_NET_DATA NetData,
    _In_ PKD_NET_ARP InPacket)
{
    PKD_NET_ARP Packet;
    ULONG PacketHandle;
    ULONG SenderIp;
    UCHAR SenderMac[6];
    NTSTATUS Status = STATUS_MORE_PROCESSING_REQUIRED;

    if (IsDbgComInitialized)
        DbgPrint0("HandleArp: %p\n", NetData);

    if (!NetData->YourIp)
    {
        if (IsDbgComInitialized)
            DbgPrint0("HandleArp: NetData->YourIp is 0\n");

        return Status;
    }

    SwapPacket(InPacket, FALSE);

    if (InPacket->Arp.HardwareType != 1 ||
        InPacket->Arp.ProtocolType != ETHERNET_TYPE_IPV4 ||
        InPacket->Arp.HardwareLen != 6 ||
        InPacket->Arp.ProtocolLen != 4 ||
        InPacket->Arp.Operation != 1 ||
        InPacket->Arp.TargetIp != NetData->YourIp)
    {
        if (IsDbgComInitialized)
            DbgPrint0("HandleArp: Not handled packet\n");

        SwapPacket(InPacket, TRUE);

        return Status;
    }

    RtlCopyMemory(&SenderMac, InPacket->Arp.SenderMac, 6);

    SenderIp = InPacket->Arp.SenderIp;

    Status = GetTxPacket(NetData, &PacketHandle);
    if (!NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("HandleArp: Status %X\n", Status);

        //KdNetArpPacketReplyFailures++;

        return Status;
    }

    Packet = (PKD_NET_ARP)GetPacketAddress(NetData, PacketHandle);

    if ((NetData->YourIp & 0xFFFF0000) == AUTOIP_NET)
        RtlFillMemory(Packet->Header.DestinationMac, 6, 0xFF);
    else
        RtlCopyMemory(Packet->Header.DestinationMac, InPacket->Arp.SenderMac, 6);

    RtlCopyMemory(Packet->Header.SourceMac, NetData->MacAddress, 6);

    Packet->Header.EtherType = ETHERNET_TYPE_ARP;

    Packet->Arp.HardwareType = 1;
    Packet->Arp.ProtocolType = ETHERNET_TYPE_IPV4;
    Packet->Arp.HardwareLen = 6;
    Packet->Arp.ProtocolLen = 4;
    Packet->Arp.Operation = 2;
    Packet->Arp.SenderIp = NetData->YourIp;
    Packet->Arp.TargetIp = SenderIp;

    RtlCopyMemory(Packet->Arp.SenderMac, NetData->MacAddress, 6);
    RtlCopyMemory(Packet->Arp.TargetMac, SenderMac, 6);

    SwapPacket(Packet, TRUE);

    Status = SendTxPacket(NetData, PacketHandle, sizeof(KD_NET_ARP));

    if (NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("HandleArp: KdNetArpPacketsHandled++\n");

        //KdNetArpPacketsHandled++;
    }
    else
    {
        if (IsDbgComInitialized)
            DbgPrint0("HandleArp: Status %X\n", Status);

        //KdNetArpPacketReplyFailures++;
    }

    return Status;
}

NTSTATUS
NTAPI
GetRxPacket(
    _In_ PKD_NET_DATA NetData,
    _Out_ PULONG OutHandle,
    _Out_ PVOID* OutPacket,
    _Out_ PULONG OutLength,
    _Inout_ ULONG* OutCycleCount)
{
    NTSTATUS Status;

    if (!NetData)
    {
        if (IsDbgComInitialized)
            DbgPrint0("GetRxPacket: STATUS_INVALID_PARAMETER\n");

        return STATUS_INVALID_PARAMETER;
    }

    if (IsDbgComInitialized)
        DbgPrint0("GetRxPacket: VendorId %X\n", NetData->VendorId);

    switch (NetData->VendorId)
    {
        case 0xFFFB:
            if (IsDbgComInitialized)
                DbgPrint0("GetRxPacket: STATUS_NOT_IMPLEMENTED (%X)\n", NetData->VendorId);
            Status = STATUS_NOT_IMPLEMENTED;
            //Status = USB3GetRxPacket(NetData->SharedData.Hardware, OutHandle, OutPacket, OutLength);
            break;

        case 0xFFFC:
            if (IsDbgComInitialized)
                DbgPrint0("GetRxPacket: STATUS_NOT_IMPLEMENTED (%X)\n", NetData->VendorId);
            Status = STATUS_NOT_IMPLEMENTED;
            //Status = KdVmGetRxPacket(NetData, OutHandle, OutPacket, OutLength, *OutCycleCount == 0);
            break;

        case 0xFFFD:
            if (IsDbgComInitialized)
                DbgPrint0("GetRxPacket: STATUS_NOT_IMPLEMENTED (%X)\n", NetData->VendorId);
            Status = STATUS_NOT_IMPLEMENTED;
            //Status = KdHvGetRxPacket(NetData->SharedData.Hardware, OutHandle, OutPacket, OutLength);
            break;

        case 0xFFFE:
            Status = KdGetRxPacket(NetData->SharedData.Hardware, OutHandle, OutPacket, OutLength);
            break;

        default:
            if (IsDbgComInitialized)
                DbgPrint0("GetRxPacket: STATUS_INVALID_PARAMETER (%X)\n", NetData->VendorId);
            return STATUS_NO_SUCH_DEVICE;
    }

    if (Status == STATUS_CONNECTION_RESET)
    {
        if (IsDbgComInitialized)
            DbgPrint0("GetRxPacket: STATUS_CONNECTION_RESET -> STATUS_IO_TIMEOUT\n");

        UpdateTargetRandom(NetData);
        Status = STATUS_IO_TIMEOUT;
    }

    //if (NT_SUCCESS(Status))
    //    KdNetRxPacketsReceived++;

    if (IsDbgComInitialized)
        DbgPrint0("GetRxPacket: ret Status %X\n", Status);

    return Status;
}

NTSTATUS
NTAPI
WaitForRxPacket(
    _In_ PKD_NET_DATA NetData,
    _Out_ PULONG OutHandle,
    _Out_ PVOID* OutPacket,
    _Out_ PULONG OutLength,
    _Inout_ ULONG* OutCycleCount)
{
    LARGE_INTEGER Counter;
    LARGE_INTEGER Tmp;
    ULONGLONG CurrentFactor;
    ULONGLONG StartCycle;
    ULONGLONG CycleCount;
    ULONGLONG Counter1;
    ULONGLONG Counter2;
    ULONG Factor;
    NTSTATUS Status;

    if (IsDbgComInitialized)
        DbgPrint0("WaitForRxPacket: %p\n", NetData);

    //KdNetWaitForRxPacketCalled++;

    Counter.QuadPart = 0;

    StartCycle = KdNetReadCycleCounter(NetData);

    if (NetData->VendorId == 0xFFFD || NetData->VendorId == 0xFFFC)
    {
        Factor = 0xA;

        Tmp.QuadPart = ((*OutCycleCount * Factor) + 1);

        Counter.LowPart = Tmp.HighPart;
        Counter.HighPart = Tmp.LowPart;
    }
    else
    {
        Factor = 1;
    }

    for (Status = GetRxPacket(NetData, OutHandle, OutPacket, OutLength, OutCycleCount);
         !NT_SUCCESS(Status);
         Status = GetRxPacket(NetData, OutHandle, OutPacket, OutLength, OutCycleCount))
    {
        if (IsDbgComInitialized)
            DbgPrint0("WaitForRxPacket: CycleCount %X\n", *OutCycleCount);

        if (!*OutCycleCount)
        {
            //KdNetWaitForRxPacketTimeouts++;
            break;
        }

        if (*OutCycleCount != 0xFFFFFFFF)
        {
            if (!Counter.QuadPart)
            {
                Counter1 = KdNetReadCycleCounter(NetData);
                KeStallExecutionProcessor(8);
                Counter2 = KdNetReadCycleCounter(NetData);

                CurrentFactor = ((Counter2 - Counter1) / 8);

                if (CurrentFactor > Factor)
                    Factor = CurrentFactor;

                Tmp.QuadPart = ((*OutCycleCount * CurrentFactor) + 1);

                Counter.LowPart = Tmp.HighPart;
                Counter.HighPart = Tmp.LowPart;
            }

            Counter1 = KdNetReadCycleCounter(NetData);

            Tmp.LowPart = Counter.HighPart;
            Tmp.HighPart = Counter.LowPart;

            if ((Counter1 - StartCycle) >= (ULONGLONG)Tmp.QuadPart)
            {
                *OutCycleCount = 0;
                continue;
            }
        }

        //KdNetWaitForRxPacketStalls++;

        KeStallExecutionProcessor(4);
    }

    if (*OutCycleCount && *OutCycleCount != 0xFFFFFFFF)
    {
        Counter1 = KdNetReadCycleCounter(NetData);
        CycleCount = ((Counter1 - StartCycle) / Factor);

        if (CycleCount < *OutCycleCount)
            *OutCycleCount -= CycleCount;
        else
            *OutCycleCount = 0;
    }

    if (IsDbgComInitialized)
        DbgPrint0("WaitForRxPacket: ret Status %X\n", Status);

    return Status;
}

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
    _In_ PUSHORT EtherType)
{
    PKD_NET_ETH_HEADER Header;
    NTSTATUS Status;

    if (IsDbgComInitialized)
        DbgPrint0("WaitForSpecificRxPacket()\n");

    for (Status = WaitForRxPacket(NetData, OutHandle, OutPacket, OutPacketLength, OutCycleCount);
         Status >= 0;
         Status = WaitForRxPacket(NetData, OutHandle, OutPacket, OutPacketLength, OutCycleCount))
    {
        if (IsDbgComInitialized)
            DbgPrint0("WaitForSpecificRxPacket: Status %X\n", Status);

        Header = *OutPacket;

        if ((!MacAddress || RtlEqualMemory(MacAddress, Header->DestinationMac, sizeof(Header->DestinationMac))) &&
            (!HostMac || RtlEqualMemory(HostMac, Header->SourceMac, sizeof(Header->SourceMac))) &&
            (!EtherType || *EtherType ==  UshortSwap(Header->EtherType)))
        {
            if (IsDbgComInitialized)
                DbgPrint0("WaitForSpecificRxPacket: KdNetRxPacketsMatched++\n");

            *OutPacket = Add2Ptr(Header, sizeof(*Header));
            *OutPacketLength -= sizeof(*Header);

            //KdNetRxPacketsMatched++;
            return Status;
        }

        if (UshortSwap(Header->EtherType) != ETHERNET_TYPE_ARP)
        {
            if (IsDbgComInitialized)
                DbgPrint0("WaitForSpecificRxPacket: KdNetRxEthernetPacketsHandedOff++ (%X)\n", UshortSwap(Header->EtherType));

            //KdNetRxEthernetPacketsHandedOff++;
            ProcessUnhandledPackets(NetData, *OutHandle);
        }
        else
        {
            Status = HandleArp(NetData, *OutPacket);

            if (Status == STATUS_MORE_PROCESSING_REQUIRED)
            {
                if (IsDbgComInitialized)
                    DbgPrint0("WaitForSpecificRxPacket: KdNetArpPacketsHandedOff++\n");

                //KdNetArpPacketsHandedOff++;
                ProcessUnhandledPackets(NetData, *OutHandle);
            }
        }

        ReleaseRxPacket(NetData, *OutHandle);
    }

    if (IsDbgComInitialized)
        DbgPrint0("WaitForSpecificRxPacket: ret Status %X\n", Status);

    return Status;
}

NTSTATUS
NTAPI
InitializeController(
    _In_ PKD_NET_DATA NetData,
    _In_ PKD_NET_PARAMETERS NetParameters)
{
    NTSTATUS Status;
    USHORT VendorId;
    PDEBUG_DEVICE_DESCRIPTOR PciDevice;

    if (IsDbgComInitialized)
        DbgPrint0("InitializeController: %p, %p\n", NetData, NetParameters);

    if (!NetData)
    {
        if (IsDbgComInitialized)
            DbgPrint0("InitializeController: STATUS_INVALID_PARAMETER, NetData is NULL\n");

        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (!NetParameters)
    {
        if (IsDbgComInitialized)
            DbgPrint0("InitializeController: STATUS_INVALID_PARAMETER, NetParameters is NULL\n");

        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    KdNetInitializeController++;

    NetData->VendorId = 0xFFFF;
    NetData->NetParameters = NetParameters;
    NetData->NicData = &KdNicData;

    NetData->SharedData.Device = &NetParameters->PciDevice;
    NetData->SharedData.Hardware = NetParameters->PciDevice.Memory.VirtualAddress;
    NetData->SharedData.TargetMacAddress = NetData->MacAddress;
    NetData->SharedData.LinkState = &KdNicData.LinkState;

    Status = STATUS_NO_SUCH_DEVICE;

    VendorId = NetParameters->PciDevice.VendorID;

    if (VendorId != 0xFFFD && VendorId != 0xFFFC)
    {
        Status = KdInitializeController(NetData);
        if (NT_SUCCESS(Status))
            VendorId = 0xFFFE;

        if (!NT_SUCCESS(Status))
        {
            if (IsDbgComInitialized)
                DbgPrint0("InitializeController: KdInitializeController() fail (%X)\n", Status);
        }
    }

    PciDevice = NetData->SharedData.Device;

    if (PciDevice->NameSpace == 0 && PciDevice->BaseClass == 0xC && PciDevice->SubClass == 3 && PciDevice->ProgIf == 0x30)
        VendorId = 0xFFFB;

    if (PciDevice->NameSpace == 1 && PciDevice->PortType == 0x8002 && PciDevice->PortSubtype == 0)
        VendorId = 0xFFFB;

    switch (VendorId)
    {
        case 0xFFFB:
            Status = USB3InitializeController(NetData);
            break;

        case 0xFFFC:
            Status = KdVmInitializeController(NetData);
            break;

        case 0xFFFD:
            Status = KdHvInitializeController(NetData);
            break;
    }

    if (!NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("InitializeController: Status %X\n", Status);

        goto Exit;
    }

    NetData->VendorId = VendorId;

    if (NetData->SharedData.LinkSpeed)
        NetData->NicData->LinkSpeed1 = NetData->SharedData.LinkSpeed;

    if (NetData->NicData->LinkSpeed1 > NetData->NicData->LinkSpeed2)
        NetData->NicData->LinkSpeed2 = NetData->NicData->LinkSpeed1;

Exit:

    KdDbgLog = FALSE;

    return Status;
}

NTSTATUS
NTAPI
GetTargetIPAddress(
    _In_ PKD_NET_DATA NetData)
{
    if (IsDbgComInitialized)
        DbgPrint0("GetTargetIPAddress: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
GetNodeMacAddress(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG SenderIp,
    _In_ ULONG TargetIp,
    _In_ UCHAR* OutSenderMac,
    _In_ ULONG RetryCount)
{
    PKD_NET_ARP Packet;
    PKD_NET_ARP RxPacket;
    ULONG CycleCount;
    ULONG PacketLength;
    ULONG PacketHandle;
    USHORT EtherType;
    NTSTATUS Status;

    if (IsDbgComInitialized)
        DbgPrint0("GetNodeMacAddress: %X, %X\n", SenderIp, TargetIp);

    Status = GetTxPacket(NetData, &PacketHandle);
    if (!NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("GetNodeMacAddress: (1) ret Status %X\n", Status);

        return Status;
    }

    while (TRUE)
    {
        Packet = GetPacketAddress(NetData, PacketHandle);

        PacketLength = sizeof(KD_NET_ARP);
        RtlZeroMemory(Packet, PacketLength);

        RtlFillMemory(Packet->Header.DestinationMac, sizeof(Packet->Header.DestinationMac), 0xFF);
        RtlCopyMemory(Packet->Header.SourceMac, NetData->MacAddress, sizeof(Packet->Header.SourceMac));

        Packet->Header.EtherType = ETHERNET_TYPE_ARP;

        Packet->Arp.HardwareType = 1;
        Packet->Arp.ProtocolType = ETHERNET_TYPE_IPV4;
        Packet->Arp.HardwareLen = 6;
        Packet->Arp.ProtocolLen = 4;
        Packet->Arp.Operation = 1;

        RtlCopyMemory(Packet->Arp.SenderMac, NetData->MacAddress, sizeof(Packet->Arp.SenderMac));

        Packet->Arp.SenderIp = SenderIp;
        Packet->Arp.TargetIp = TargetIp;

        SwapPacket(Packet, TRUE);

        Status = SendTxPacket(NetData, PacketHandle, PacketLength);
        if (!NT_SUCCESS(Status))
        {
            if (IsDbgComInitialized)
                DbgPrint0("GetNodeMacAddress: (2) ret Status %X\n", Status);

            break;
        }

        CycleCount = 100000;
        EtherType = 0x0806;

        while (TRUE)
        {
            Status = WaitForSpecificRxPacket(NetData,
                                             &PacketHandle,
                                             (PVOID *)&RxPacket,
                                             &PacketLength,
                                             &CycleCount,
                                             0,
                                             0,
                                             &EtherType);
            if (Status == STATUS_IO_TIMEOUT)
            {
                if (IsDbgComInitialized)
                    DbgPrint0("GetNodeMacAddress: STATUS_IO_TIMEOUT. RetryCount %X\n", RetryCount);

                if (RetryCount)
                    break;
            }

            if (!NT_SUCCESS(Status))
            {
                if (IsDbgComInitialized)
                    DbgPrint0("GetNodeMacAddress: (3) ret Status %X\n", Status);

                return Status;
            }

            RxPacket = CONTAINING_RECORD(RxPacket, KD_NET_ARP, Arp);

            SwapPacket(RxPacket, 0);

            if (RxPacket->Arp.HardwareType == 1 &&
                RxPacket->Arp.ProtocolType == ETHERNET_TYPE_IPV4 &&
                RxPacket->Arp.HardwareLen == 6 &&
                RxPacket->Arp.ProtocolLen == 4 &&
                RxPacket->Arp.SenderIp == TargetIp)
            {
                RtlCopyMemory(OutSenderMac, RxPacket->Arp.SenderMac, 6);
                ReleaseRxPacket(NetData, PacketHandle);
                return Status;
            }

            ReleaseRxPacket(NetData, PacketHandle);
        }

        RetryCount--;

        Status = GetTxPacket(NetData, &PacketHandle);
        if (!NT_SUCCESS(Status))
        {
            if (IsDbgComInitialized)
                DbgPrint0("GetNodeMacAddress: (4) ret Status %X\n", Status);

            break;
        }
    }

    return Status;
}

NTSTATUS
NTAPI
GenerateTargetIPAddress(
    _In_ PKD_NET_DATA NetData)
{
    UCHAR SenderMac[6];
    ULONG IpAddress;
    ULONG ix = 0x20;
    USHORT LowPartIp;
    NTSTATUS Status;

    if (IsDbgComInitialized)
        DbgPrint0("GenerateTargetIPAddress: %X, %X\n", NetData->NetParameters->DebuggeeIp, NetData->YourIp);

    if (NetData->NetParameters->DebuggeeIp)
        IpAddress = NetData->NetParameters->DebuggeeIp;
    else
        IpAddress = NetData->YourIp;

    LowPartIp = (USHORT)IpAddress;

    if (IsDbgComInitialized)
        DbgPrint0("GenerateTargetIPAddress: LowPartIp %X\n", LowPartIp);

    if (IpAddress)
        goto TryIp;

Start:

    LowPartIp = (__rdtsc() >> 4);

    if (IsDbgComInitialized)
        DbgPrint0("GenerateTargetIPAddress: LowPartIp %X\n", LowPartIp);

    while (TRUE)
    {
        if (LowPartIp < IP_RANGE_START || LowPartIp > IP_RANGE_END)
            LowPartIp = (0x8000 + (LowPartIp * 0x7F));

        IpAddress = (AUTOIP_NET | LowPartIp);

TryIp:
        Status = GetNodeMacAddress(NetData, 0, IpAddress, SenderMac, 2);

        if (IsDbgComInitialized)
            DbgPrint0("GenerateTargetIPAddress: (1) Status %X\n", Status);

        if (Status == STATUS_IO_TIMEOUT)
        {
            Status = STATUS_SUCCESS;

            if ((IpAddress & 0xFFFF0000) != AUTOIP_NET)
            {
                if (IsDbgComInitialized)
                    DbgPrint0("GenerateTargetIPAddress: IpAddress %X\n", IpAddress);
                break;
            }

            Status = GetNodeMacAddress(NetData, IpAddress, IpAddress, SenderMac, 1);

            if (IsDbgComInitialized)
                DbgPrint0("GenerateTargetIPAddress: (2) Status %X\n", Status);

            if (Status == STATUS_IO_TIMEOUT)
            {
                Status = STATUS_SUCCESS;
                break;
            }

            goto Start;
        }

        if (!NT_SUCCESS(Status))
        {
            if (IsDbgComInitialized)
                DbgPrint0("GenerateTargetIPAddress: (3) Status %X\n", Status);

            IpAddress = 0;
            break;
        }

        if (NetData->NetParameters->IsDhcp && NetData->YourIp == IpAddress)
        {
            if (IsDbgComInitialized)
                DbgPrint0("GenerateTargetIPAddress: Failed. Using APIPA.\n");

            KdNetErrorString = L"GenerateTargetIPAddress failed to validate the DHCP address. Using APIPA.";
            goto Start;
        }

        if (!ix)
        {
            if (IsDbgComInitialized)
                DbgPrint0("GenerateTargetIPAddress: ix is 0\n");

            Status = STATUS_UNSUCCESSFUL;
            IpAddress = 0;
            break;
        }

        if (NetData->NetParameters->DebuggeeIp)
        {
            if ((NetData->NetParameters->DebuggeeIp & 0xFFFF0000) != AUTOIP_NET)
            {
                if (IsDbgComInitialized)
                    DbgPrint0("GenerateTargetIPAddress: STATUS_UNSUCCESSFUL. DebuggeeIp %X\n", NetData->NetParameters->DebuggeeIp);

                Status = STATUS_UNSUCCESSFUL;
                IpAddress = 0;
                break;
            }
        }

        LowPartIp++;

        if (!(LowPartIp & 3))
        {
            ix--;
            goto Start;
        }
    }

    NetData->YourIp = IpAddress;

    return Status;
}

NTSTATUS
NTAPI
SendHostGratuitousArp(
    _In_ PKD_NET_DATA NetData)
{
    PKD_NET_ARP Packet;
    ULONG PacketHandle = 0;
    NTSTATUS Status = STATUS_INVALID_PARAMETER;

    if (!NetData)
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendHostGratuitousArp: NetData is NULL\n");

        return Status;
    }

    if (IsDbgComInitialized)
        DbgPrint0("SendHostGratuitousArp: %p, %p\n", NetData->NetParameters->DebuggeeIp, NetData->NetParameters->HostIp2);

    if (!NetData->YourIp)
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendHostGratuitousArp: NetData->YourIp is NULL\n");

        return Status;
    }

    if ((NetData->YourIp & 0xFFFF0000) != AUTOIP_NET)
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendHostGratuitousArp: TargetIP %p\n", NetData->YourIp);

        return Status;
    }

    if (!NetData->NetParameters->HostIp2)
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendHostGratuitousArp: HostIp2 is NULL\n");

        return Status;
    }

    if (NetData->NetParameters->HostMac[0] == 0 &&
        NetData->NetParameters->HostMac[1] == 0 &&
        NetData->NetParameters->HostMac[2] == 0 &&
        NetData->NetParameters->HostMac[3] == 0 &&
        NetData->NetParameters->HostMac[4] == 0 &&
        NetData->NetParameters->HostMac[5] == 0)
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendHostGratuitousArp: HostMac is 0\n");

        return Status;
    }

    Status = GetTxPacket(NetData, &PacketHandle);
    if (!NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendHostGratuitousArp: GetTxPacket() ret Status %X\n", Status);

        //KdNetGratuitousArpFailures++;

        return Status;
    }

    Packet = GetPacketAddress(NetData, PacketHandle);

    RtlCopyMemory(Packet->Header.DestinationMac, NetData->NetParameters->HostMac, 6);
    RtlCopyMemory(Packet->Header.SourceMac, NetData->MacAddress, 6);

    Packet->Header.EtherType = ETHERNET_TYPE_ARP;
    Packet->Arp.HardwareType = 1;
    Packet->Arp.ProtocolType = ETHERNET_TYPE_IPV4;
    Packet->Arp.HardwareLen = 6;
    Packet->Arp.ProtocolLen = 4;
    Packet->Arp.Operation = 2;
    Packet->Arp.SenderIp = NetData->YourIp;
    Packet->Arp.TargetIp = NetData->NetParameters->HostIp2;

    RtlCopyMemory(Packet->Arp.SenderMac, NetData->MacAddress, 6);
    RtlCopyMemory(Packet->Arp.TargetMac, NetData->NetParameters->HostMac, 6);

    SwapPacket(Packet, TRUE);

    Status = SendTxPacket(NetData, PacketHandle, sizeof(KD_NET_ARP));

    if (NT_SUCCESS(Status))
    {
        ;//KdNetGratuitousArpsSent++;
    }
    else
    {
        if (IsDbgComInitialized)
            DbgPrint0("SendHostGratuitousArp: KdNetGratuitousArpFailures++\n");

        //KdNetGratuitousArpFailures++;
    }

    return Status;
}

NTSTATUS
NTAPI
SendDhcpPacket(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG Param2,
    _In_ UCHAR Param3)
{
    if (IsDbgComInitialized)
        DbgPrint0("SendDhcpPacket: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);

    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
EnableHostReconnect(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG AddTimeOut)
{
    ULONG TimeOut;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if (IsDbgComInitialized)
        DbgPrint0("EnableHostReconnect: %d\n", AddTimeOut);

    TimeOut = (KdNetReconnectRunningTimeout + AddTimeOut);

    KdNetReconnectRunningTimeout = TimeOut;

    if (TimeOut >= 3000000)
    {
        Status = STATUS_SUCCESS;
        KdNetReconnectRunningTimeout = (TimeOut - 3000000);
    }

    if ((ULONGLONG)(*(LONGLONG*)&SharedUserData->InterruptTime - KdNetReconnectTimestamp) > 30000000)
        Status = STATUS_SUCCESS;

    if (!NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("EnableHostReconnect: Status %X (%I64X:%I64X)\n", Status, *(LONGLONG*)&SharedUserData->InterruptTime, KdNetReconnectTimestamp);

        return;
    }

    NetData->NetParameters->Stamp += 3;

    if (NetData->DhcpPacketType >= 5 && NetData->LeaseTime != 0xFFFFFFFF)
    {
        NetData->CurrentTime += 3;

        if (NetData->CurrentTime >= NetData->RebindingTime)
        {
            NetData->DhcpPacketType = 7;
            SendDhcpPacket(NetData, 7, 3);
        }
        else if (NetData->CurrentTime >= NetData->RenewalTime)
        {
            NetData->DhcpPacketType = 6;
            SendDhcpPacket(NetData, 6, 3);
        }
    }

    if (NetData->VendorId != 0xFFFC)
        SendHostGratuitousArp(NetData);

    if (NetData->NetParameters->DataChannel && !NetData->NetParameters->SequenceNumber)
    {
        SendPingPacket(NetData);
    }

    Status = SendOfferPacket(0,
                             NetData,
                             NetData->NetParameters->HostMac,
                             NetData->NetParameters->HostIp2,
                             NetData->NetParameters->HostPort2);
    if (!NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("EnableHostReconnect: SendOfferPacket() ret Status %X\n", Status);
    }

    KdNetReconnectTimestamp = *(LONGLONG*)&SharedUserData->InterruptTime;
    return;
}

NTSTATUS
NTAPI
InitializeNetwork(
    _In_ PKD_NET_DATA NetData)
{
    ULONG HostIp2;
    ULONG TargetIP;
    ULONG Timeout;
    NTSTATUS Status;
  
    if (IsDbgComInitialized)
        DbgPrint0("InitializeNetwork: %p\n", NetData);

    if (NetData->VendorId == 0xFFFC)
        return STATUS_SUCCESS;

    if (NetData->NetParameters->IsDhcp)
    {
        if (!NetData->NetParameters->DebuggeeIp)
        {
            Status = GetTargetIPAddress(NetData);
            if (!NT_SUCCESS(Status) && !KdNetErrorString)
            {
                if (IsDbgComInitialized)
                    DbgPrint0("InitializeNetwork: GetTargetIPAddress failed to acquire an IP address using DHCP.\n");

                KdNetErrorString = L"GetTargetIPAddress failed to acquire an IP address using DHCP.";
                KdNetErrorStatus = Status;
            }
        }
    }

    Status = GenerateTargetIPAddress(NetData);
    if (!NT_SUCCESS(Status))
    {
        if (!KdNetErrorString)
        {
            if (IsDbgComInitialized)
                DbgPrint0("InitializeNetwork: GenerateTargetIPAddress failed to acquire an unused IP address.\n");

            KdNetErrorString = L"GenerateTargetIPAddress failed to acquire an unused IP address.";
            KdNetErrorStatus = Status;
        }

        return Status;
    }

    HostIp2 = NetData->NetParameters->HostIp2;
    if (!HostIp2)
        return Status;

    TargetIP = NetData->YourIp;

    if ((NetData->YourIp & 0xFFFF0000) != 0xA9FE0000 && NetData->GatewayIp && ((HostIp2 ^ TargetIP) & NetData->SubnetMask))
        HostIp2 = NetData->GatewayIp;

    Status = GetNodeMacAddress(NetData, TargetIP, HostIp2, NetData->NetParameters->HostMac, 2);
    if (!NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("InitializeNetwork failed to get the ethernet address of the host debugger.\n");

        KdNetErrorString = L"InitializeNetwork failed to get the ethernet address of the host debugger.";

        if (HostIp2 == NetData->GatewayIp)
        {
            if (IsDbgComInitialized)
                DbgPrint0("InitializeNetwork failed to get the ethernet address of the router gateway.\n");

            KdNetErrorString = L"InitializeNetwork failed to get the ethernet address of the router gateway.";
        }

        return Status;
    }

    if (NetData->VendorId == 0xFFFC)
        return STATUS_SUCCESS;

    EnableHostReconnect(NetData, 3000000);

    Timeout = 125000;
    Status = WaitForResponsePacket(NetData,
                                   NetData->NetParameters->HostMac,
                                   NetData->NetParameters->HostIp2,
                                   NetData->NetParameters->HostPort2,
                                   &Timeout);
    if (NT_SUCCESS(Status))
        return STATUS_SUCCESS;

    EnableHostReconnect(NetData, 3000000);

    Timeout = 125000;
    WaitForResponsePacket(NetData,
                          NetData->NetParameters->HostMac,
                          NetData->NetParameters->HostIp2,
                          NetData->NetParameters->HostPort2,
                          &Timeout);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdNicUpdateStatus(
    _In_ PKD_NIC_DATA NicData,
    _In_ NTSTATUS* NicDataStatus,
    _In_ UCHAR* OutLinkState)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdNicUpdateStatus()\n");

    if (NicData != &KdNicData)
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdNicUpdateStatus: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (NicDataStatus)
        NicData->Status = *NicDataStatus;

    if (OutLinkState)
        NicData->LinkState = *OutLinkState;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdNetInitialize(
    _In_ PKD_NET_PARAMETERS NetParameters,
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    ULONG ContextSize;
    ULONG Idx;
    UCHAR LinkState = 0;
    BOOLEAN IsPciDeviceSetupOk = FALSE;
    NTSTATUS NetStatus;
    NTSTATUS Status = STATUS_ADAPTER_HARDWARE_ERROR;
  #ifdef __REACTOS__
    DEBUG_DEVICE_DESCRIPTOR_5x device5x;
  #endif

    if (IsDbgComInitialized)
        DbgPrint0("KdNetInitialize: (1) %p, %p\n", NetParameters, LoaderBlock);

    InterlockedIncrement(&KdNetInitializeCount);

    KdNetErrorString = NULL;

    NetParameters->PciDevice.Memory.Length = ContextSize = (KdNetHardwareContextSize + (2 * PAGE_SIZE));

    if (IsDbgComInitialized)
        DbgPrint0("KdNetInitialize: (2) %X, %X\n", ContextSize, NetParameters->PciDevice.VendorID);

    if (NetParameters->PciDevice.VendorID != 0xFFFD && NetParameters->PciDevice.VendorID != 0xFFFC)
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdNetInitialize: KdSetupPciDeviceForDebugging %X\n", KdSetupPciDeviceForDebugging);

        /* There are differences in the structures DEBUG_DEVICE_DESCRIPTOR for RoS and for WIN8 */
      #ifdef __REACTOS__
        KdNetSetPciDeviceForNt5x(&NetParameters->PciDevice, &device5x);
        NetStatus = KdSetupPciDeviceForDebugging(LoaderBlock, (PDEBUG_DEVICE_DESCRIPTOR)&device5x);
      #else
        NetStatus = KdSetupPciDeviceForDebugging(LoaderBlock, &NetParameters->PciDevice);
      #endif

        if (!NT_SUCCESS(NetStatus))
        {
            if (IsDbgComInitialized)
                DbgPrint0("KdNetInitialize: KdSetupPciDeviceForDebugging() ret %X\n", NetStatus);

            KdNetErrorString = L"KdSetupPciDeviceForDebugging failed.";
            goto Finish;
        }

      #ifdef __REACTOS__
        KdNetGetPciDeviceForNt5x(&device5x, &NetParameters->PciDevice);
      #endif

        IsPciDeviceSetupOk = 1;

        if (NetParameters->PciDevice.Memory.Start.HighPart ||
            (NetParameters->PciDevice.Memory.Start.LowPart & 0xFFF))
        {
            if (IsDbgComInitialized)
                DbgPrint0("KdNetInitialize: Kdnet debug data not page aligned.\n");

            KdNetErrorString = L"Kdnet debug data not page aligned.";
            NetStatus = STATUS_INSUFFICIENT_RESOURCES;
            goto Finish;
        }
    }

    if (NetParameters->PciDevice.Memory.Length > ContextSize)
    {
        ContextSize = NetParameters->PciDevice.Memory.Length;
        KdNetHardwareContextSize = (((NetParameters->PciDevice.Memory.Length - 0x434) & ~(PAGE_SIZE - 1)) - PAGE_SIZE);
    }

    RtlZeroMemory(NetParameters->PciDevice.Memory.VirtualAddress, ContextSize);

    KdNetData = Add2Ptr(NetParameters->PciDevice.Memory.VirtualAddress, (KdNetHardwareContextSize + PAGE_SIZE));

    if (IsDbgComInitialized)
        DbgPrint0("KdNetInitialize: Adapter %p, Size %X, KdNetData %p\n", NetParameters->PciDevice.Memory.VirtualAddress, KdNetHardwareContextSize, KdNetData);

    NetStatus = InitializeEncryption(KdNetData, NetParameters, SendPingPacket, SendOfferPacket);
    if (!NT_SUCCESS(NetStatus))
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdNetInitialize: (4) NetStatus %X\n", NetStatus);
        if (!KdNetErrorString)
        {
            KdNetErrorString = L"Encryption key initialization failed.";
        }
        goto Finish;
    }

    NetStatus = InitializeController(KdNetData, NetParameters);
    if (!NT_SUCCESS(NetStatus))
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdNetInitialize: (5) NetStatus %X\n", NetStatus);
        if (!KdNetErrorString)
        {
            KdNetErrorString = L"NIC hardware initialization failed.";
        }
        goto Finish;
    }

    Status = 0;
    LinkState = 1;

    *KdNicData.MacAddress = *KdNetData->MacAddress;

    if (NetParameters->PciDevice.VendorID != 0xFFFD && NetParameters->PciDevice.VendorID != 0xFFFC)
    {
        KdNetData->YourIp = KdTargetIP;
    }

    NetStatus = InitializeNetwork(KdNetData);
    if (!NT_SUCCESS(NetStatus))
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdNetInitialize: (6) NetStatus %X\n", NetStatus);

        if (!KdNetErrorString)
        {
            KdNetErrorString = L"Network initialization failed.";
        }

        goto Finish;
    }

    KdTargetIP = KdNetData->YourIp;

Finish:

    if (!NT_SUCCESS(NetStatus))
    {
        if (LoaderBlock && IsPciDeviceSetupOk && !NT_SUCCESS(NetStatus))
        {
            if (IsDbgComInitialized)
                DbgPrint0("KdNetInitialize: (7) NetStatus %X\n", NetStatus);

            if (IsDbgComInitialized)
                DbgPrint0("KdNetInitialize: Unimplemented! LoaderBlock %p\n", NetParameters, LoaderBlock);
            KeBugCheck(MANUALLY_INITIATED_CRASH);
            return STATUS_NOT_IMPLEMENTED;

            //((void (NTAPI *)(PKD_NET_PARAMETERS))*(&HalPrivateDispatchTable + 14))(NetParameters);
        }
    }

    KdNicUpdateStatus(&KdNicData, &Status, &LinkState);

    KdNetErrorStatus = NetStatus;

    Idx = ((UCHAR)KdNetInitializeCount - 1) & 7;
    KdNetErrorStatusLog[Idx] = NetStatus;
    KdNetErrorStringLog[Idx] = KdNetErrorString;

    return Status;
}

ULONG
NTAPI
KdpComputeChecksum(
    _In_ PUCHAR Buffer,
    _In_ ULONG Length)
{
    ULONG Checksum;

    for (Checksum = 0; Length; Length--)
        Checksum += *Buffer++;

    return Checksum;
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
    PCHAR LoaderOptions;
    PCHAR TargetIp;
    PCHAR HostIp;
    PCHAR HostPort;
    PCHAR Start;
    PCHAR Ptr;
    LARGE_INTEGER Value;
    ULONG ContextSize;
    ULONG _ip;
    BOOLEAN IsDebuggerActive;
    NTSTATUS Status = STATUS_INVALID_PARAMETER;

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

    InterlockedIncrement(&KdNetDebuggerInitialize0Count);

    //InitializeLogTiming(); // for USB3

    if (!KdNetInitialized)
    {
        KdNetNicInitialize();

        KdNetParameters.IsDebuggerActive = FALSE;
        KdNetParameters.IsEncryptionKey = FALSE;
        KdNetParameters.IsDhcp = TRUE;
        KdNetParameters.IsVerifyHostMac = FALSE;
        KdNetParameters.IsSendKdStatus = FALSE;

        KdNetParameters.HostPort2 = 0x14F4; // (5364)
        KdNetParameters.DebuggeePort = 0x14F4;

        RtlZeroMemory(&KdNetParameters, sizeof(KdNetParameters.PciDevice));

        KdNetParameters.PciDevice.Bus = 0xFFFFFFFF;
        KdNetParameters.PciDevice.Slot = 0xFFFFFFFF;
        KdNetParameters.PciDevice.Configured = 0;
        KdNetParameters.PciDevice.VendorID = 0xFFFF;
        KdNetParameters.PciDevice.DeviceID = 0xFFFF;
        KdNetParameters.PciDevice.BaseClass = 2;
        KdNetParameters.PciDevice.SubClass = 0;
        KdNetParameters.PciDevice.ProgIf = 0xFF;
        KdNetParameters.PciDevice.Segment = 0xFFFF;
    }

    if (!LoaderBlock)
    {
        IsDebuggerActive = FALSE;
        KdNetParameters.IsDebuggerActive = FALSE;

        KdNicSendEntered = 0;

        if (KdNetInitialized)
            goto NetInitializing;

        goto Exit;
    }

    LoaderOptions = LoaderBlock->LoadOptions;

    Status = InitializeKdNetExtensibility(LoaderOptions, &KdNetParameters.PciDevice);
    if (!NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdDebuggerInitialize0: InitializeKdNetExtensibility() ret %X\n", Status);

        KdNetErrorString = L"Kdnet extensibility initialization failed.";
        goto Exit;
    }

    KdNetHardwareContextSize = 0x70600;

    if (KdNetParameters.PciDevice.Memory.Length)
    {
        if (KdNetParameters.PciDevice.Memory.Length > 0x70600)
        {
            KdNetHardwareContextSize = KdNetParameters.PciDevice.Memory.Length;

            if (KdNetParameters.PciDevice.Memory.Length > 0x1000000)
            {
                if (IsDbgComInitialized)
                    DbgPrint0("KdDebuggerInitialize0: Requested too much memory (%X)\n", KdNetParameters.PciDevice.Memory.Length);

                KdNetErrorString = L"Kdnet extensibility module requested too much memory.";
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto Exit;
            }
        }
    }

    ContextSize = KdNetHardwareContextSize;

  #if 0
    // FIXME
    if (KdHvDetectHypervisor())
    {
        if (KdHvGetDebugDeviceOptions() & 4)
        {
        }
        else if (KdHvUseSyntheticDebugging())
        {
        }
    }
  #endif

    KdNetHardwareContextSize = ROUND_TO_PAGES(ContextSize);

  #if 0
    // FIXME
    LOADER_PARAMETER_EXTENSION* Extension LoaderBlockExtension;
    UCHAR RngBytesForNtoskrnl[1024];
  #endif

    if (!LoaderOptions)
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdDebuggerInitialize0: No OS loadoptions string was passed to kdnet.(%X)\n", Status);

        KdNetErrorString = L"No OS loadoptions string was passed to kdnet.";

        if (NT_SUCCESS(Status))
            return Status;

        goto Exit;
    }

    /* Parse options */
    _strupr(LoaderOptions);

    Ptr = strstr(LoaderOptions, "HOST_IP");
    if (Ptr)
    {
        for (HostIp = (Ptr + 7); ; HostIp++)
        {
            Ptr = HostIp;

            if (*HostIp != ' ')
                break;
        }

        if (IsDbgComInitialized)
           DbgPrint0("KdDebuggerInitialize0: HOST_IP '%s'\n", (HostIp + 1));

        if (*HostIp)
        {
            _ip = ((UCHAR)strtoull((HostIp + 1), &Ptr, 10) << 24);
            KdNetParameters.HostIp2 = _ip;

            HostIp = Ptr;
        }
        else
        {
            _ip = KdNetParameters.HostIp2;
        }

        if (*HostIp == '.')
        {
            _ip = (((UCHAR)strtoull((HostIp + 1), &Ptr, 10) << 16) | KdNetParameters.HostIp2);
            KdNetParameters.HostIp2 = _ip;

            if (*Ptr == '.')
            {
                _ip = (((UCHAR)strtoull((Ptr + 1), &Ptr, 10) << 8) | KdNetParameters.HostIp2);
                KdNetParameters.HostIp2 = _ip;

                if (*Ptr == '.')
                {
                    _ip = ((UCHAR)strtoull((Ptr + 1), &Ptr, 10) | KdNetParameters.HostIp2);
                    KdNetParameters.HostIp2 = _ip;
                }
            }
        }

        KdNetParameters.HostIp1 = _ip;

        if (IsDbgComInitialized)
           DbgPrint0("KdDebuggerInitialize0: HostIp1 %X, HostIp2 %X\n", KdNetParameters.HostIp1, KdNetParameters.HostIp2);
    }

    Ptr = strstr(LoaderOptions, "HOST_PORT");
    if (Ptr)
    {
        for (HostPort = (Ptr + 9); ; HostPort++)
        {
            Ptr = HostPort;
            if (*HostPort != ' ')
                break;
        }

        if (IsDbgComInitialized)
           DbgPrint0("KdDebuggerInitialize0: HOST_PORT '%s'\n", (HostPort + 1));

        if (*HostPort)
        {
            KdNetParameters.HostPort2 = KdNetParameters.HostPort1 = atol(HostPort + 1);
            KdNetParameters.DebuggeePort = KdNetParameters.HostPort1;
        }
    }

    Ptr = strstr(LoaderOptions, "SEND_KD_STATUS");
    if (Ptr)
        KdNetParameters.IsSendKdStatus = TRUE;

    Ptr = strstr(LoaderOptions, "NO_KDNIC");
    if (Ptr)
        KdNicEnabled = FALSE;

    Ptr = strstr(LoaderOptions, "NO_DHCP");
    if (Ptr)
        KdNetParameters.IsDhcp = FALSE;

    Ptr = strstr(LoaderOptions, "VERIFY_HOST_MAC");
    if (Ptr)
        KdNetParameters.IsVerifyHostMac = TRUE;

    Value.QuadPart = 0;

    Ptr = strstr(LoaderOptions, "ENCRYPTION_KEY");
    if (Ptr)
    {
        KdNetParameters.IsEncryptionKey = TRUE;

        for (Start = (Ptr + 0xE); ; Start++)
        {
            Ptr = Start;

            if (*Start != ' ')
                break;
        }

        if (*Start != '=')
        {
            if (IsDbgComInitialized)
                DbgPrint0("KdDebuggerInitialize0: Status %X\n", Status);

            KdNetErrorString = L"No kdnet encryption key was specified in the OS loadoptions string.";

            if (NT_SUCCESS(Status))
                return Status;

            goto Exit;
        }

      #if 0
        // FIXME
      #endif
    }

    if (!KdNetParameters.IsEncryptionKey || !Value.QuadPart)
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdDebuggerInitialize0: No kdnet encryption key was specified in the OS loadoptions string.(%X)\n", Status);

        KdNetErrorString = L"No kdnet encryption key was specified in the OS loadoptions string.";

        if (NT_SUCCESS(Status))
            return Status;

        goto Exit;
    }

  #if 0
    // FIXME
  #endif

    if (KdNetParameters.IsDhcp && !KdNetParameters.IsEncryptionKey)
       KdNetParameters.IsDhcp = FALSE;

    Ptr = strstr(LoaderOptions, "TARGET_IP");
    if (Ptr)
    {
        for (TargetIp = (Ptr + 9); ; TargetIp++)
        {
            Ptr = TargetIp;

            if (*TargetIp != ' ')
                break;
        }

        if (IsDbgComInitialized)
           DbgPrint0("KdDebuggerInitialize0: TARGET_IP '%s'\n", TargetIp + 1);

        if (*TargetIp)
        {
            _ip = ((UCHAR)strtoull((TargetIp + 1), &Ptr, 10) << 24);
            KdNetParameters.DebuggeeIp = _ip;

            TargetIp = Ptr;
        }
        else
        {
            _ip = KdNetParameters.DebuggeeIp;
        }

        if (*TargetIp == '.')
        {
            _ip = (((UCHAR)strtoull((TargetIp + 1), &Ptr, 10) << 16) | KdNetParameters.DebuggeeIp);
            KdNetParameters.DebuggeeIp = _ip;

            if (*Ptr == '.')
            {
                _ip = (((UCHAR)strtoull((Ptr + 1), &Ptr, 10) << 8) | KdNetParameters.DebuggeeIp);
                KdNetParameters.DebuggeeIp = _ip;

                if (*Ptr == '.')
                {
                    _ip = ((UCHAR)strtoull((Ptr + 1), &Ptr, 10) | KdNetParameters.DebuggeeIp);
                    KdNetParameters.DebuggeeIp = _ip;
                }
            }

            if (IsDbgComInitialized)
               DbgPrint0("KdDebuggerInitialize0: DebuggeeIp %X\n", KdNetParameters.DebuggeeIp);
        }
    }
    else
    {
        if (IsDbgComInitialized)
           DbgPrint0("KdDebuggerInitialize0: DebuggeeIp %X\n", KdNetParameters.DebuggeeIp);

        _ip = KdNetParameters.DebuggeeIp;
    }

    if (_ip && ((_ip & 0xFFFF0000) != 0xA9FE0000) && !KdNetParameters.IsEncryptionKey)
    {
        if (IsDbgComInitialized)
           DbgPrint0("KdDebuggerInitialize0: DebuggeeIp is 0\n");

        KdNetParameters.DebuggeeIp = 0;
    }

    if (strstr(LoaderOptions, "BUSPARAMS"))
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdDebuggerInitialize0: BUSPARAMS Unimplemented! KeBugCheck\n");

        //KeBugCheck(MANUALLY_INITIATED_CRASH);
        //return STATUS_NOT_IMPLEMENTED;
    }

    KdNetInitialized = TRUE;

    IsDebuggerActive = KdNetParameters.IsDebuggerActive;

NetInitializing:

    if (IsDebuggerActive)
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdDebuggerInitialize0: Debugger is active\n");

        return STATUS_SUCCESS;
    }

    Status = KdNetInitialize(&KdNetParameters, LoaderBlock);

    if (IsDbgComInitialized)
        DbgPrint0("KdDebuggerInitialize0: (1) Status %X\n", Status);

    if (LoaderBlock &&
        Status == STATUS_ADAPTER_HARDWARE_ERROR &&
        KdNetParameters.PciDevice.VendorID != 0xFFFD &&
        KdNetParameters.PciDevice.VendorID != 0xFFFC)
    {
        KdNetParameters.PciDevice.Bus = 0xFFFFFFFF;
        KdNetParameters.PciDevice.Slot = 0xFFFFFFFF;
        KdNetParameters.PciDevice.Segment = 0xFFFF;
        KdNetParameters.PciDevice.VendorID = 0xFFFF;
        KdNetParameters.PciDevice.DeviceID = 0xFFFF;
        KdNetParameters.PciDevice.BaseClass = 0x0C;
        KdNetParameters.PciDevice.SubClass = 0x03;
        KdNetParameters.PciDevice.ProgIf = 0xFF;
        KdNetParameters.PciDevice.Flags = 0xFF;
        KdNetParameters.PciDevice.Initialized = 0;
        KdNetParameters.PciDevice.Configured = 0;
        KdNetParameters.PciDevice.PortType = 0x8002;
        KdNetParameters.PciDevice.PortSubtype = 0xFFFF;
        KdNetParameters.PciDevice.NameSpace = 2;
        KdNetParameters.PciDevice.NameSpacePathLength = 0xFFFFFFFF;

        Status = KdNetInitialize(&KdNetParameters, LoaderBlock);
    }

    KdNetParameters.IsDebuggerActive = (NT_SUCCESS(Status));

    if (NT_SUCCESS(Status))
        return Status;

    if (IsDbgComInitialized)
        DbgPrint0("KdDebuggerInitialize0: (2) Status %X\n", Status);

Exit:

    if (!KdNetErrorStatus)
        KdNetErrorStatus = Status;

    return Status;
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

NTSTATUS
NTAPI
WaitForSpecificRxUdpPacket(
    _In_ PKD_NET_DATA NetData,
    _In_ PULONG OutPacketHandle,
    _In_ PVOID* OutPacket,
    _In_ PULONG OutPacketLength,
    _In_ PULONG OutCycleCount,
    _In_ USHORT* OutHostPort,
    _In_ USHORT* OutDebuggeePort)
{
    PUCHAR HostMac;

    if (!NetData->NetParameters->IsVerifyHostMac && (NetData->YourIp & 0xFFFF0000) != AUTOIP_NET)
        HostMac = NULL;
    else
        HostMac = NetData->NetParameters->HostMac;

    return WaitForSpecificRxUdpPacketEx(NetData,
                                        OutPacketHandle,
                                        OutPacket,
                                        OutPacketLength,
                                        OutCycleCount,
                                        HostMac,
                                        NetData->MacAddress,
                                        NetData->NetParameters->HostIp2,
                                        NetData->YourIp,
                                        OutHostPort,
                                        OutDebuggeePort);
}

ULONG
NTAPI
NetReadKdPacket(
    _In_ PKD_NET_DATA NetData,
    _In_ PKD_PACKET KdPacket,
    _In_ PSTRING MessageHeader,
    _In_ PSTRING MessageData,
    _In_ PULONG OutCycleCount,
    _In_ USHORT* OutHostPort,
    _In_ USHORT* OutDebuggeePort)
{
    PVOID Packet;
    ULONG OutPacketHandle;
    ULONG PacketLength;
    ULONG Length;
    ULONG Remain;
    ULONG KdStatus = 1;
    NTSTATUS Status;

    if (IsDbgComInitialized)
        DbgPrint0("NetReadKdPacket: %p, %p, %X, %X\n", NetData, KdPacket, MessageHeader, MessageData);

    Status = WaitForSpecificRxUdpPacket(NetData,
                                        &OutPacketHandle,
                                        &Packet,
                                        &PacketLength,
                                        OutCycleCount,
                                        OutHostPort,
                                        OutDebuggeePort);
    if (Status == STATUS_IO_TIMEOUT)
    {
        if (IsDbgComInitialized)
            DbgPrint0("NetReadKdPacket: STATUS_IO_TIMEOUT\n");

        return KdStatus;
    }

    if (!NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("NetReadKdPacket: Status %X\n", Status);

        return 2;
    }

    Status = DecryptKdPacket(NetData, &Packet, &PacketLength);
    if (!NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("NetReadKdPacket: KdNetRxKdPacketsHandedOff++\n");

        //KdNetRxKdPacketsHandedOff++;

        ProcessUnhandledPackets(NetData, OutPacketHandle);

        KdStatus = 2;
        goto Finish;
    }

    KdStatus = 0;

    *KdDebuggerNotPresent = 0;
    SharedUserData->KdDebuggerEnabled |= 2;

    if (PacketLength < sizeof(KD_PACKET))
        Length = PacketLength;
    else
        Length = sizeof(KD_PACKET);

    RtlCopyMemory(KdPacket, Packet, Length);

    if (Length < sizeof(KD_PACKET))
    {
        if (IsDbgComInitialized)
            DbgPrint0("NetReadKdPacket: Length %X\n", Length);

        KdStatus = 2;
        goto Finish;
    }

    Packet = Add2Ptr(Packet, Length);

    Remain = (PacketLength - Length);
    PacketLength -= Length;

    if (!MessageHeader)
    {
        if (IsDbgComInitialized)
            DbgPrint0("NetReadKdPacket: MessageHeader is NULL\n");

        goto Finish;
    }

    Length = MessageHeader->MaximumLength;

    if (Length > Remain)
        Length = Remain;

    RtlCopyMemory(MessageHeader->Buffer, Packet, Length);

    MessageHeader->Length = Length;

    if (Length < MessageHeader->MaximumLength)
    {
        if (IsDbgComInitialized)
            DbgPrint0("NetReadKdPacket: Length %X\n", Length);
        goto Finish;
    }

    Remain = (PacketLength - Length);
    Packet = Add2Ptr(Packet, Length);

    if (MessageData)
    {
        Length = MessageData->MaximumLength;

        if (Length > Remain)
            Length = Remain;

        RtlCopyMemory(MessageData->Buffer, Packet, Length);

        MessageData->Length = Length;
    }

Finish:

    ReleaseRxPacket(NetData, OutPacketHandle);

    if (IsDbgComInitialized)
        DbgPrint0("NetReadKdPacket: ret %X\n", KdStatus);

    return KdStatus;
}

NTSTATUS
NTAPI
KdNicQueueSendPackets(
    _In_ PKD_NET_DATA NetData)
{
    PSLIST_ENTRY TxSListEntry;

    if (IsDbgComInitialized)
        DbgPrint0("KdNicQueueSendPackets: %p\n", NetData);

    if (NetData->NicData != &KdNicData)
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdNicQueueSendPackets: %p\n", NetData->NicData);

        return STATUS_INVALID_PARAMETER;
    }

    TxSListEntry = ExInterlockedFlushSList(&NetData->NicData->TxSListHead);
    if (!TxSListEntry)
        return STATUS_SUCCESS;

    if (IsDbgComInitialized)
        DbgPrint0("KdNicQueueSendPackets: Unimplemented! TxSListEntry %p\n", TxSListEntry);

    KeBugCheck(MANUALLY_INITIATED_CRASH);

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
KdNicSendQueuedPackets(
    _In_ PKD_NET_DATA NetData)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdNicSendQueuedPackets: %p\n", NetData);

    if (NetData->NicData != &KdNicData)
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdNicSendQueuedPackets: STATUS_INVALID_PARAMETER %p\n", NetData->NicData);

        return STATUS_INVALID_PARAMETER;
    }

    while (TRUE)
    {
        if (IsListEmpty(&QueuedTxListHead))
            return STATUS_SUCCESS;

        if (IsDbgComInitialized)
            DbgPrint0("KdNicSendQueuedPackets: %p, %p\n", &QueuedTxListHead, QueuedTxListHead.Flink);

        if (IsDbgComInitialized)
            DbgPrint0("KdNicSendQueuedPackets: Unimplemented!\n");

        KeBugCheck(MANUALLY_INITIATED_CRASH);

        return STATUS_NOT_IMPLEMENTED;
    }

    if (IsDbgComInitialized)
        DbgPrint0("KdNicSendQueuedPackets: KdNicSendPacketsUnavailable++\n");

    //KdNicSendPacketsUnavailable++;

    KeBugCheck(MANUALLY_INITIATED_CRASH);

    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
KdNicFlushQueuedSendPackets(
    _In_ PKD_NIC_DATA NicData)
{
    if (NicData->Reserved0)
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdNicFlushQueuedSendPackets: exit (Reserved0 %p)\n", NicData->Reserved0);

        return;
    }

    if (IsListEmpty(&QueuedTxListHead))
        return;

    if (IsDbgComInitialized)
        DbgPrint0("KdNicFlushQueuedSendPackets: %p, %p\n", &QueuedTxListHead, QueuedTxListHead.Flink);

    if (IsDbgComInitialized)
        DbgPrint0("KdNicFlushQueuedSendPackets: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
}

NTSTATUS
NTAPI
KdNicSendPackets(
    _In_ PKD_NET_DATA NetData)
{
    NTSTATUS Status1;
    NTSTATUS Status2;

    if (IsDbgComInitialized)
        DbgPrint0("KdNicSendPackets: %p\n", NetData);

    if (InterlockedIncrement(&KdNicSendEntered) > 1)
    {
        InterlockedIncrement(&KdNicSendReentered);
        InterlockedDecrement(&KdNicSendEntered);

        return STATUS_LOCK_NOT_GRANTED;
    }

    //_SEH2_TRY

    Status1 = KdNicQueueSendPackets(NetData);
    Status2 = KdNicSendQueuedPackets(NetData);

    if (NT_SUCCESS(Status1) && !NT_SUCCESS(Status2))
    {
        Status1 = Status2;
    }

    KdNicFlushQueuedSendPackets(&KdNicData);

    //_SEH2_TRY

    InterlockedDecrement(&KdNicSendEntered);

    return Status1;
}

VOID
NTAPI
KdpSendControlPacket(
    _In_ PKD_NET_DATA NetData,
    _In_ USHORT PacketType,
    _In_ ULONG PacketId)
{
    PKD_PACKET KdPacket;
    ULONG PacketHandle;
    NTSTATUS Status;

    if (IsDbgComInitialized)
        DbgPrint0("KdpSendControlPacket: %X, %X\n", PacketType, PacketId);

    //KdNetKdSendControlPacketCalled++;

    Status = GetTxPacket(NetData, &PacketHandle);
    if (!NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdpSendControlPacket: (1) Status %X\n", Status);

        return;
    }

    KdPacket = GetPacketKdData(NetData, PacketHandle);

    KdPacket->PacketId = PacketId;
    KdPacket->Checksum = 0;
    KdPacket->ByteCount = 0;
    KdPacket->PacketLeader = 0x69696969;
    KdPacket->PacketType = PacketType;

    Status = SendKdPacket(NetData,
                          PacketHandle,
                          sizeof(KD_PACKET),
                          NetData->NetParameters->DebuggeePort,
                          NetData->NetParameters->HostPort2);

    if (!NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdpSendControlPacket: (2) Status %X\n", Status);
    }
    else
    {
        ;//KdNetKdSendControlPacketSucceeded++;
    }
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
    PSTRING Header;
    KD_PACKET KdPacket;
    ULONG CycleCount1;
    ULONG CycleCount2;
    ULONG DataLength;
    ULONG ByteCount;
    ULONG Checksum;
    ULONG KdStatus;

    if (IsDbgComInitialized)
        DbgPrint0("KdReceivePacket: %X, %p, %p\n", PacketType, MessageHeader, MessageData);

    if (!KdNetParameters.IsDebuggerActive)
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdReceivePacket: CalledDebuggerNotActive++\n");

        //KdNetKdReceivePacketCalledDebuggerNotActive++;

        return 2;
    }

    if (IsDbgComInitialized)
        DbgPrint0("KdReceivePacket: Called++, Retries--\n");

    //KdNetKdReceivePacketCalled++;
    //KdNetKdReceivePacketRetries--;

    CycleCount2 = CycleCount1 = (PacketType == 8 ? 0 : 500000);

    while (TRUE)
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdReceivePacket: Retries++\n");

        //KdNetKdReceivePacketRetries++;

        if (CycleCount1 < CycleCount2)
        {
            if (IsDbgComInitialized)
                DbgPrint0("KdReceivePacket: TimeoutWrap++\n");

            //KdNetKdReceivePacketTimeoutWrap++;

            CycleCount2 = CycleCount1;
        }

        CycleCount1 = CycleCount2;

        RtlZeroMemory(&KdPacket, sizeof(KdPacket));

        KdStatus = NetReadKdPacket(KdNetData,
                                   &KdPacket,
                                   MessageHeader,
                                   MessageData,
                                   &CycleCount2,
                                   &KdNetParameters.HostPort2,
                                   &KdNetParameters.DebuggeePort);

        if (KdStatus == 2 && (UCHAR)KdPacket.PacketLeader == 0x62)
        {
            if (PacketType == 8)
                break;

            KdContext->KdpControlCPending = 1;
        }

        if (PacketType == 8)
        {
            KdNicSendPackets(KdNetData);
            EnableHostReconnect(KdNetData, 0);

            if (IsDbgComInitialized)
                DbgPrint0("KdReceivePacket: [8] ret 1\n");

            return 1;
        }

        if (KdStatus != 0)
        {
            EnableHostReconnect(KdNetData, (CycleCount1 - CycleCount2));

            if (IsDbgComInitialized)
                DbgPrint0("KdReceivePacket: KdStatus %X\n", KdStatus);

            return KdStatus;
        }

        if (KdPacket.PacketLeader == 0x69696969)
        {
            if (KdPacket.PacketType == 4)
            {
                if (KdPacket.PacketId == KdNetTxPacketId)
                {
                    if (PacketType == 4)
                    {
                        if (IsDbgComInitialized)
                            DbgPrint0("KdReceivePacket: AckReceived++\n");

                        //KdNetKdReceivePacketAckReceived++;

                        return 0;
                    }

                    if (IsDbgComInitialized)
                        DbgPrint0("KdReceivePacket: AckIgnored++\n");

                    //KdNetKdReceivePacketAckIgnored++;
                }
                else
                {
                    if (IsDbgComInitialized)
                        DbgPrint0("KdReceivePacket: MismatchedAckPacketId++\n");

                    //KdNetKdReceivePacketMismatchedAckPacketId++;
                }
            }
            else
            {
                if (KdPacket.PacketType == 6)
                {
                    KdNetRxPacketId = KdPacket.PacketId;

                    KdpSendControlPacket(KdNetData, 6, KdNetTxPacketId);

                    if (IsDbgComInitialized)
                        DbgPrint0("KdReceivePacket: ResetReceived++\n");

                    //KdNetKdReceivePacketResetReceived++;

                    return 2;
                }

                if (KdPacket.PacketType == 5)
                {
                    if (IsDbgComInitialized)
                        DbgPrint0("KdReceivePacket: ResendReceived++\n");

                    //KdNetKdReceivePacketResendReceived++;

                    return 2;
                }

                if (IsDbgComInitialized)
                    DbgPrint0("KdReceivePacket: BadControlPacketType++\n");

                //KdNetKdReceivePacketBadControlPacketType++;
            }

            continue;
        }

        if (KdPacket.PacketLeader != 0x30303030)
        {
            if (IsDbgComInitialized)
                DbgPrint0("KdReceivePacket: BadPacketHeader++, ResendRequest++\n");

            //KdNetKdReceivePacketBadPacketHeader++;
            //KdNetKdReceivePacketResendRequest++;

            KdpSendControlPacket(KdNetData, 5, 0);
            continue;
        }

        if (PacketType == 4)
        {
            if (KdPacket.PacketId == KdNetRxPacketId)
            {
                KdpSendControlPacket(KdNetData, 5, 0);

                if (IsDbgComInitialized)
                    DbgPrint0("KdReceivePacket: AckPacketAssumed++\n");

                //KdNetKdReceivePacketAckPacketAssumed++;

                return 0;
            }

            KdpSendControlPacket(KdNetData, 4, KdPacket.PacketId);

            if (IsDbgComInitialized)
                DbgPrint0("KdReceivePacket: GratuitousAckSent++\n");

            //KdNetKdReceivePacketGratuitousAckSent++;

            return 2;
        }

        if (PacketType != KdPacket.PacketType)
        {
            if (IsDbgComInitialized)
                DbgPrint0("KdReceivePacket: BadPacketType++, ResendRequest++\n");

            //KdNetKdReceivePacketBadPacketType++;
            //KdNetKdReceivePacketResendRequest++;

            KdpSendControlPacket(KdNetData, 5, 0);
            continue;
        }

        Header = MessageHeader;

        ByteCount = 0;

        if (MessageHeader)
            ByteCount = MessageHeader->MaximumLength;

        if (KdPacket.ByteCount > 0x580 || KdPacket.ByteCount < (USHORT)ByteCount)
        {
            if (IsDbgComInitialized)
                DbgPrint0("KdReceivePacket: BadPacketSize++, ResendRequest++\n");

            //KdNetKdReceivePacketBadPacketSize++;
            //KdNetKdReceivePacketResendRequest++;

            KdpSendControlPacket(KdNetData, 5, 0);
            continue;
        }

        Checksum = 0;
        DataLength = KdPacket.ByteCount - ByteCount;

        if (MessageHeader)
        {
            Checksum = KdpComputeChecksum((PUCHAR)MessageHeader->Buffer, ByteCount);

            if (MessageData)
            {
                Checksum += KdpComputeChecksum((PUCHAR)MessageData->Buffer, DataLength);
                Header = MessageHeader;
            }
            else
            {
                Header = MessageHeader;
            }
        }

        if (Checksum == KdPacket.Checksum)
        {
            if (Header)
            {
                Header->Length = ByteCount;

                if (MessageData)
                    MessageData->Length = DataLength;
            }

            if (OutDataLength)
                *OutDataLength = DataLength;

            KdpSendControlPacket(KdNetData, 4, KdPacket.PacketId);

            KdNetRxPacketId += 2;

            break;
        }

        if (IsDbgComInitialized)
            DbgPrint0("KdReceivePacket: BadPacketChecksum++, ResendRequest++\n");

        //KdNetKdReceivePacketBadPacketChecksum++;
        //KdNetKdReceivePacketResendRequest++;

        KdpSendControlPacket(KdNetData, 5, 0);
    }

    if (IsDbgComInitialized)
        DbgPrint0("KdReceivePacket: (++) ret 0\n");

    //KdNetReceivedPackets++;

    return 0;
}

NTSTATUS
NTAPI
KdRestore(
    _In_ BOOLEAN SleepTransition)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdRestore: SleepTransition %X\n", SleepTransition);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdSave(
    _In_ BOOLEAN SleepTransition)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdSave: SleepTransition %X\n", SleepTransition);

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
    PKD_PACKET Packet;
    ULONG PacketLength;
    ULONG PacketHandle;
    ULONG HeaderLength;
    ULONG RetryCount;
    ULONG MessageId;
    ULONG Checksum;
    ULONG KdStatus;
    ULONG Length = 0;
    NTSTATUS Status;

    if (IsDbgComInitialized)
        DbgPrint0("KdSendPacket: %X, %p, %p\n", PacketType, MessageHeader, MessageData);

    if (!KdNetParameters.IsDebuggerActive)
    {
        //KdNetKdSendPacketCalledDebuggerNotActive++;
        goto NotActiveExit;
    }

    //KdNetKdSendPacketCalled++;

    RetryCount = KdNetRetryCount;

    while (TRUE)
    {
        Status = GetTxPacket(KdNetData, &PacketHandle);
        if (!NT_SUCCESS(Status))
        {
            if (IsDbgComInitialized)
                DbgPrint0("KdSendPacket: Status %X\n", Status);

            goto Exit;
        }

        Packet = GetPacketKdData(KdNetData, PacketHandle);

        Checksum = KdpComputeChecksum((PUCHAR)MessageHeader->Buffer, MessageHeader->Length);
        Packet->Checksum = Checksum;

        if (MessageData)
        {
            Length = MessageData->Length;
            Packet->Checksum = Checksum + KdpComputeChecksum((PUCHAR)MessageData->Buffer, MessageData->Length);
        }

        Packet->PacketLeader = 0x30303030; // PACKET_LEADER // FIXME
        Packet->ByteCount = Length + MessageHeader->Length;
        Packet->PacketType = PacketType;
        Packet->PacketId = KdNetTxPacketId;

        RtlCopyMemory(&Packet[1], MessageHeader->Buffer, MessageHeader->Length);

        HeaderLength = (sizeof(KD_PACKET) + MessageHeader->Length);

        if (MessageData)
        {
            RtlCopyMemory(Add2Ptr(&Packet[1], MessageHeader->Length), MessageData->Buffer, MessageData->Length);
            PacketLength = (MessageData->Length + HeaderLength);
        }
        else
        {
            PacketLength = (sizeof(KD_PACKET) + MessageHeader->Length);
        }

        SendKdPacket(KdNetData,
                     PacketHandle,
                     PacketLength,
                     KdNetData->NetParameters->DebuggeePort,
                     KdNetData->NetParameters->HostPort2);

        KdStatus = KdReceivePacket(4, NULL, NULL, NULL, KdContext);
        if (KdStatus == 0)
            break;

        if (KdStatus == 2)
        {
            //KdNetResendRequestsReceived++;
            RetryCount++;
        }

        if (!RetryCount)
        {
            MessageId = *(PULONG)MessageHeader->Buffer;

            switch (PacketType)
            {
                case 3:
                    if (MessageId == 0x3230)
                    {
                        //KdNetBailPrintString++;
                        goto NotActiveExit;
                    }
                    break;

                case 7:
                    if (MessageId == 0x3031)
                    {
                        //KdNetBailLoadSymbols++;
                        goto NotActiveExit;
                    }
                    break;

                case 0xB:
                    if (MessageId == 0x3430)
                    {
                        //KdNetBailCreateFile++;
                        goto NotActiveExit;
                    }
                    break;

                default:
                    if (PacketType == 9 && MessageId == 0x3330)
                    {
                        //KdNetBailTraceIo++;
                        goto NotActiveExit;
                    }
                    break;
            }
        }

        Length = 0;

        //KdNetKdSendPacketRetries++;

        RetryCount--;
    }

    if (IsDbgComInitialized)
        DbgPrint0("KdSendPacket: KdNetSentPackets++\n");

    //KdNetSentPackets++;

    KdNetTxPacketId += 2;

    if (KdContext->KdpDefaultRetries > KdNetRetryCount)
        KdNetRetryCount = KdContext->KdpDefaultRetries;

Exit:

    *KdDebuggerNotPresent = 0;
    SharedUserData->KdDebuggerEnabled |= 2;
    return;

NotActiveExit:

    *KdDebuggerNotPresent = 1;
    SharedUserData->KdDebuggerEnabled &= ~2;
    return;
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
