
#pragma once

/* Mm PTE/PDE to Hal PTE/PDE */
#define HalAddressToPde(x) (PHARDWARE_PTE)MiAddressToPde(x)
#define HalAddressToPte(x) (PHARDWARE_PTE)MiAddressToPte(x)

#define HAL_PIC_VECTORS  16

/* Usage flags */
#define IDT_REGISTERED          0x01
#define IDT_LATCHED             0x02
#define IDT_READ_ONLY           0x04
#define IDT_INTERNAL            0x11
#define IDT_DEVICE              0x21

/* CMOS Registers and Ports */
#define CMOS_CONTROL_PORT       (PUCHAR)0x70
#define CMOS_DATA_PORT          (PUCHAR)0x71
#define RTC_REGISTER_A          0x0A
#define   RTC_REG_A_UIP         0x80
#define RTC_REGISTER_B          0x0B
#define   RTC_REG_B_DS          0x01
#define   RTC_REG_B_HM          0x02
#define   RTC_REG_B_PI          0x40
#define RTC_REGISTER_C          0x0C
#define   RTC_REG_C_IRQ         0x80
#define RTC_REGISTER_D          0x0D
#define RTC_REGISTER_CENTURY    0x32

typedef struct _IDTUsageFlags
{
    UCHAR Flags;
} IDTUsageFlags;

typedef struct
{
    KIRQL Irql;
    UCHAR BusReleativeVector;
} IDTUsage;

#pragma pack(push, 1)
typedef struct _HalAddressUsage
{
    struct _HalAddressUsage *Next;
    CM_RESOURCE_TYPE Type;
    UCHAR Flags;
    struct
    {
        ULONG Start;
        ULONG Length;
    } Element[];

} ADDRESS_USAGE, *PADDRESS_USAGE;
#pragma pack(pop)

FORCEINLINE
VOID
WRMSR(_In_ ULONG Register,
      _In_ ULONGLONG Value)
{
    __writemsr(Register, Value);
}

/* bios.c */
BOOLEAN
NTAPI
HalpBiosDisplayReset(
    VOID
);

VOID
__cdecl
HalpRealModeStart(
    VOID
);

VOID
__cdecl
HalpTrap0D(
    VOID
);

VOID
FASTCALL
HalpExitToV86(
    PKTRAP_FRAME TrapFrame
);

/* cmos.c */
UCHAR
NTAPI
HalpReadCmos(
    IN UCHAR Reg
);

VOID
NTAPI
HalpWriteCmos(
    IN UCHAR Reg,
    IN UCHAR Value
);

/* dma.c */
PDMA_ADAPTER
NTAPI
HaliGetDmaAdapter(
    _In_ PVOID Context,
    _In_ PDEVICE_DESCRIPTION DeviceDescriptor,
    _Out_ PULONG NumberOfMapRegisters
);

VOID
NTAPI
HaliLocateHiberRanges(
    _In_ PVOID MemoryMap
);

NTSTATUS
NTAPI
HalpAllocateMapRegisters(
    _In_ PADAPTER_OBJECT AdapterObject,
    _In_ ULONG Unknown,
    _In_ ULONG Unknown2,
    _In_ PMAP_REGISTER_ENTRY Registers
);

VOID
NTAPI
HalpInitDma(
    VOID
);

BOOLEAN
NTAPI
HalpGrowMapBuffers(
    _In_ PADAPTER_OBJECT AdapterObject,
    _In_ ULONG SizeOfMapBuffers
);

BOOLEAN
NTAPI
HalpDmaInitializeEisaAdapter(
    _In_ PADAPTER_OBJECT AdapterObject,
    _In_ PDEVICE_DESCRIPTION DeviceDescriptor
);

/* halinit.c */
VOID
NTAPI
HalInitializeProcessor(
    IN ULONG ProcessorNumber,
    IN PLOADER_PARAMETER_BLOCK LoaderBlock
);

BOOLEAN
NTAPI
HalInitSystem(
    IN ULONG BootPhase,
    IN PLOADER_PARAMETER_BLOCK LoaderBlock
);

VOID
NTAPI
HalpGetParameters(
    _In_ PCHAR CommandLine
);

VOID
NTAPI
HalpInitNonBusHandler(
    VOID
);

/* halpnpdd.c */
NTSTATUS
NTAPI
HaliInitPnpDriver(
    VOID
);

/* kdpci.c */
NTSTATUS
NTAPI
HalpSetupPciDeviceForDebugging(
    _In_ PVOID LoaderBlock,
    _Inout_ OUT PDEBUG_DEVICE_DESCRIPTOR PciDevice
);

NTSTATUS
NTAPI
HalpReleasePciDeviceForDebugging(
    _Inout_ PDEBUG_DEVICE_DESCRIPTOR PciDevice
);

/* memory.c */
ULONG_PTR
NTAPI
HalpAllocPhysicalMemory(
    IN PLOADER_PARAMETER_BLOCK LoaderBlock,
    IN ULONG MaxAddress,
    IN PFN_NUMBER PageCount,
    IN BOOLEAN Aligned
);

PVOID
NTAPI
HalpMapPhysicalMemory64(
    IN PHYSICAL_ADDRESS PhysicalAddress,
    IN PFN_COUNT PageCount
);

VOID
NTAPI
HalpUnmapVirtualAddress(
    IN PVOID VirtualAddress,
    IN PFN_COUNT NumberPages
);

PVOID
NTAPI
HalpMapPhysicalMemoryWriteThrough64(
    _In_ PHYSICAL_ADDRESS PhysicalAddress,
    _In_ PFN_COUNT PageCount
);

PVOID
NTAPI
HalpRemapVirtualAddress64(
    _In_ PVOID VirtualAddress,
    _In_ PHYSICAL_ADDRESS PhysicalAddress,
    _In_ BOOLEAN IsWriteThrough
);

/* mics.c */
VOID
NTAPI
HalpFlushTLB(
    VOID
);

VOID
NTAPI
HalpReportSerialNumber(
    VOID
);

NTSTATUS
NTAPI
HalpMarkAcpiHal(
    VOID
);

NTSTATUS
NTAPI
HalpOpenRegistryKey(
    _In_ PHANDLE KeyHandle,
    _In_ HANDLE RootKey,
    _In_ PUNICODE_STRING KeyName,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ BOOLEAN Create
);

/* pic.c */
VOID
NTAPI
HalpInitializeLegacyPICs(
    _In_ BOOLEAN InterruptMode
);

/* pcibus.c */
ULONG
NTAPI
HaliPciInterfaceReadConfig(
    _In_ PBUS_HANDLER RootBusHandler,
    _In_ ULONG BusNumber,
    _In_ PCI_SLOT_NUMBER SlotNumber,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length
);

ULONG
NTAPI
HaliPciInterfaceWriteConfig(
    _In_ PBUS_HANDLER RootBusHandler,
    _In_ ULONG BusNumber,
    _In_ PCI_SLOT_NUMBER SlotNumber,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length
);

VOID
NTAPI
HalpInitializePciStubs(
    VOID
);

/* spinlock.c */
VOID
NTAPI
HalpAcquireCmosSpinLock(
    VOID
);

VOID
NTAPI
HalpReleaseCmosSpinLock(
    VOID
);

/* sysinfo.c */
NTSTATUS
NTAPI
HaliQuerySystemInformation(
    _In_ HAL_QUERY_INFORMATION_CLASS InformationClass,
    _In_ ULONG BufferSize,
    _Inout_ PVOID Buffer,
    _Out_ PULONG ReturnedLength
);

NTSTATUS
NTAPI
HaliSetSystemInformation(
    _In_ HAL_SET_INFORMATION_CLASS InformationClass,
    _In_ ULONG BufferSize,
    _Inout_ PVOID Buffer
);

/* usage.c */
VOID
NTAPI
HalpRegisterVector(
    _In_ UCHAR Flags,
    _In_ ULONG BusVector,
    _In_ ULONG SystemVector,
    _In_ KIRQL Irql
);

VOID
NTAPI
HalpReportResourceUsage(
    _In_ PUNICODE_STRING HalName,
    _In_ INTERFACE_TYPE InterfaceType
);

/* EOF */
