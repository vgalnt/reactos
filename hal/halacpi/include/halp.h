
#pragma once

/* Mm PTE/PDE to Hal PTE/PDE */
#define HalAddressToPde(x) (PHARDWARE_PTE)MiAddressToPde(x)
#define HalAddressToPte(x) (PHARDWARE_PTE)MiAddressToPte(x)

/* Usage flags */
#define IDT_REGISTERED          0x01
#define IDT_LATCHED             0x02
#define IDT_READ_ONLY           0x04
#define IDT_INTERNAL            0x11
#define IDT_DEVICE              0x21

typedef struct _IDTUsageFlags
{
    UCHAR Flags;
} IDTUsageFlags;

typedef struct
{
    KIRQL Irql;
    UCHAR BusReleativeVector;
} IDTUsage;

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

/* CMOS Registers and Ports */
#define CMOS_CONTROL_PORT       (PUCHAR)0x0070
#define CMOS_DATA_PORT          (PUCHAR)0x0071
#define RTC_REGISTER_A          0x0A
#define RTC_REG_A_UIP           0x80
#define RTC_REGISTER_B          0x0B
#define RTC_REG_B_PI            0x40
#define RTC_REGISTER_C          0x0C
#define RTC_REG_C_IRQ           0x80
//#define RTC_REGISTER_D          0x0D
//#define RTC_REGISTER_CENTURY    0x32

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
//INIT_FUNCTION
VOID
NTAPI
HalpInitializeCmos(
    VOID
);

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
HalpGetDmaAdapter(
    IN PVOID Context,
    IN PDEVICE_DESCRIPTION DeviceDescriptor,
    OUT PULONG NumberOfMapRegisters
);

NTSTATUS
NTAPI
HalpAllocateMapRegisters(
    _In_ PADAPTER_OBJECT AdapterObject,
    _In_ ULONG Unknown,
    _In_ ULONG Unknown2,
    PMAP_REGISTER_ENTRY Registers
);

VOID
NTAPI
HaliLocateHiberRanges(
    _In_ PVOID MemoryMap
);

//INIT_FUNCTION
VOID
NTAPI
HalpInitDma(
    VOID
);

/* halinit.c */
//INIT_FUNCTION
VOID
NTAPI
HalInitializeProcessor(
    IN ULONG ProcessorNumber,
    IN PLOADER_PARAMETER_BLOCK LoaderBlock
);

//INIT_FUNCTION
BOOLEAN
NTAPI
HalInitSystem(
    IN ULONG BootPhase,
    IN PLOADER_PARAMETER_BLOCK LoaderBlock
);

/* halpnpdd.c */
NTSTATUS
NTAPI
HaliInitPnpDriver(
    VOID
);

/* memory.c */
//INIT_FUNCTION
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

/* mics.c */
VOID
NTAPI
HalpFlushTLB(
    VOID
);

NTSTATUS
NTAPI
HalpOpenRegistryKey(
    IN PHANDLE KeyHandle,
    IN HANDLE RootKey,
    IN PUNICODE_STRING KeyName,
    IN ACCESS_MASK DesiredAccess,
    IN BOOLEAN Create
);

/* pcibus.c */
//INIT_FUNCTION
NTSTATUS
NTAPI
HalpSetupPciDeviceForDebugging(
    IN PVOID LoaderBlock,
    IN OUT PDEBUG_DEVICE_DESCRIPTOR PciDevice
);

//INIT_FUNCTION
NTSTATUS
NTAPI
HalpReleasePciDeviceForDebugging(
    IN OUT PDEBUG_DEVICE_DESCRIPTOR PciDevice
);

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

/* pic.c */
VOID
NTAPI
HalpInitializePICs(
    IN BOOLEAN EnableInterrupts
);

ULONG
NTAPI
HalpGetSystemInterruptVector(
    IN PBUS_HANDLER BusHandler,
    IN PBUS_HANDLER RootHandler,
    IN ULONG BusInterruptLevel,
    IN ULONG BusInterruptVector,
    OUT PKIRQL Irql,
    OUT PKAFFINITY Affinity
);

NTSTATUS
NTAPI
HalIrqTranslateResourcesRoot(
   _Inout_opt_ PVOID Context,
   _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR Source,
   _In_ RESOURCE_TRANSLATION_DIRECTION Direction,
   _In_opt_ ULONG AlternativesCount,
   _In_opt_ IO_RESOURCE_DESCRIPTOR Alternatives[],
   _In_ PDEVICE_OBJECT PhysicalDeviceObject,
   _Out_ PCM_PARTIAL_RESOURCE_DESCRIPTOR Target
);

NTSTATUS
NTAPI 
HalIrqTranslateResourceRequirementsRoot(
   _Inout_opt_ PVOID Context,
   _In_ PIO_RESOURCE_DESCRIPTOR InIoDesc,     // Source
   _In_ PDEVICE_OBJECT DeviceObject,          // PhysicalDeviceObject,
   _Out_ PULONG OutIoDescCount,               // TargetCount,
   _Out_ PIO_RESOURCE_DESCRIPTOR*  OutIoDesc  // Target
);

/* processor.c */
ULONG
NTAPI
HalpGetFeatureBits(
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
    IN HAL_QUERY_INFORMATION_CLASS InformationClass,
    IN ULONG BufferSize,
    IN OUT PVOID Buffer,
    OUT PULONG ReturnedLength
);

NTSTATUS
NTAPI
HaliSetSystemInformation(
    IN HAL_SET_INFORMATION_CLASS InformationClass,
    IN ULONG BufferSize,
    IN OUT PVOID Buffer
);

/* timer.c */
//INIT_FUNCTION
VOID
NTAPI
HalpInitializeClock(
    VOID
);

//#ifdef __REACTOS__
VOID
FASTCALL
RosKeUpdateSystemTime(
    _In_ PKTRAP_FRAME TrapFrame,
    _In_ ULONG Increment,
    _In_ UCHAR Vector,
    _In_ KIRQL Irql
);
//#else
VOID
NTAPI
KeUpdateSystemTime(
    VOID
);
//#endif

VOID
__cdecl
HalpClockInterrupt(
    VOID
);

VOID
__cdecl
HalpProfileInterrupt(
    VOID
);

/* usage.c */
//INIT_FUNCTION
VOID
NTAPI
HalpRegisterVector(
    IN UCHAR Flags,
    IN ULONG BusVector,
    IN ULONG SystemVector,
    IN KIRQL Irql
);

//INIT_FUNCTION
VOID
NTAPI
HalpReportResourceUsage(
    IN PUNICODE_STRING HalName,
    IN INTERFACE_TYPE InterfaceType
);

//INIT_FUNCTION
VOID
NTAPI
HalpBuildPartialFromIdt(
    IN ULONG Entry,
    IN PCM_PARTIAL_RESOURCE_DESCRIPTOR RawDescriptor,
    IN PCM_PARTIAL_RESOURCE_DESCRIPTOR TranslatedDescriptor
);

//INIT_FUNCTION
VOID
NTAPI
HalpBuildPartialFromAddress(
    IN INTERFACE_TYPE Interface,
    IN PADDRESS_USAGE CurrentAddress,
    IN ULONG Element,
    IN PCM_PARTIAL_RESOURCE_DESCRIPTOR RawDescriptor,
    IN PCM_PARTIAL_RESOURCE_DESCRIPTOR TranslatedDescriptor
);

/* EOF */
