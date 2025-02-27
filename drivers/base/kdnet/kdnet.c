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

BOOLEAN KdNetInitialized;
BOOLEAN KdNicEnabled = TRUE;
BOOLEAN KdDbgLog = TRUE;

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

NTSTATUS
NTAPI
WaitForResponsePacket(
    _In_ PKD_NET_DATA NetData,
    _In_ PUCHAR DestinationMac,
    _In_ ULONG HostIp,
    _In_ USHORT Port,
    _In_ ULONG* OutCycleCount)
{
    if (IsDbgComInitialized)
        DbgPrint0("WaitForResponsePacket: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);

    return STATUS_NOT_IMPLEMENTED;
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
    if (IsDbgComInitialized)
        DbgPrint0("GetPacketAddress: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);

    return NULL;
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

    if (IsDbgComInitialized)
        DbgPrint0("GetTxPacket: %p\n", PacketHandle);

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

    if (IsDbgComInitialized)
        DbgPrint0("SendTxPacket: %p, %X, %X\n", NetData, PacketHandle, PacketLength);

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
ProcessUnhandledPackets(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG PacketHandle)
{
    if (IsDbgComInitialized)
        DbgPrint0("ProcessUnhandledPackets: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);

    return STATUS_NOT_IMPLEMENTED;
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
    if (IsDbgComInitialized)
        DbgPrint0("HandleArp: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);

    return STATUS_NOT_IMPLEMENTED;
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

VOID
NTAPI
EnableHostReconnect(
    _In_ PKD_NET_DATA NetData,
    _In_ ULONG AddTimeOut)
{
    if (IsDbgComInitialized)
        DbgPrint0("EnableHostReconnect: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
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

    NetStatus = InitializeEncryption(KdNetData, NetParameters);
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
