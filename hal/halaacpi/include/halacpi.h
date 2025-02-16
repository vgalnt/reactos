
#pragma once

/* ACPI Specification constants */

/* Names within the namespace are 4 bytes long */
#define ACPI_NAMESEG_SIZE               4     // Fixed by ACPI spec

/* Sizes for ACPI table headers */
#define ACPI_OEM_ID_SIZE                6
#define ACPI_OEM_TABLE_ID_SIZE          8

/* Master ACPI Table Header.
   This common header is used by all ACPI tables except the RSDP and FACS.
*/
typedef struct _ACPI_TABLE_HEADER
{
    CHAR Signature[ACPI_NAMESEG_SIZE];        // ASCII table signature
    ULONG Length;                             // Length of table in bytes, including this header
    UCHAR Revision;                           // ACPI Specification minor version number
    UCHAR Checksum;                           // To make sum of entire table == 0
    CHAR OemId[ACPI_OEM_ID_SIZE];             // ASCII OEM identification
    CHAR OemTableId[ACPI_OEM_TABLE_ID_SIZE];  // ASCII OEM table identification
    ULONG OemRevision;                        // OEM revision number
    CHAR AslCompilerId[ACPI_NAMESEG_SIZE];    // ASCII ASL compiler vendor ID
    ULONG AslCompilerRevision;                // ASL compiler version

} ACPI_TABLE_HEADER, *PACPI_TABLE_HEADER;

/* Common subtable headers */

/* Generic subtable header (used in MADT, SRAT, etc.) */
typedef struct _ACPI_SUBTABLE_HEADER
{
    UCHAR Type;
    UCHAR Length;

} ACPI_SUBTABLE_HEADER, *PACPI_SUBTABLE_HEADER;

#define FADT_FORCE_APIC_CLUSTER_MODEL              0x00040000
#define FADT_FORCE_APIC_PHYSICAL_DESTINATION_MODE  0x00080000

#define FADT_TMR_VAL_EXT_32BIT  0x80000000
#define FADT_TMR_VAL_EXT_24BIT  0x00800000

/* WAET - Windows ACPI Emulated Devices Table */
typedef struct _ACPI_TABLE_WAET
{
    ACPI_TABLE_HEADER Header;
    ULONG Flags;
} ACPI_TABLE_WAET, *PACPI_TABLE_WAET;

/* Values for MADT subtable type in ACPI_SUBTABLE_HEADER */
enum AcpiMadtType
{
    ACPI_MADT_TYPE_LOCAL_APIC               = 0,
    ACPI_MADT_TYPE_IO_APIC                  = 1,
    ACPI_MADT_TYPE_INTERRUPT_OVERRIDE       = 2,
    ACPI_MADT_TYPE_NMI_SOURCE               = 3,
    ACPI_MADT_TYPE_LOCAL_APIC_NMI           = 4,
    ACPI_MADT_TYPE_LOCAL_APIC_OVERRIDE      = 5,
    ACPI_MADT_TYPE_IO_SAPIC                 = 6,
    ACPI_MADT_TYPE_LOCAL_SAPIC              = 7,
    ACPI_MADT_TYPE_INTERRUPT_SOURCE         = 8,
    ACPI_MADT_TYPE_LOCAL_X2APIC             = 9,
    ACPI_MADT_TYPE_LOCAL_X2APIC_NMI         = 10,
    ACPI_MADT_TYPE_GENERIC_INTERRUPT        = 11,
    ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR      = 12,
    ACPI_MADT_TYPE_GENERIC_MSI_FRAME        = 13,
    ACPI_MADT_TYPE_GENERIC_REDISTRIBUTOR    = 14,
    ACPI_MADT_TYPE_GENERIC_TRANSLATOR       = 15,
    ACPI_MADT_TYPE_RESERVED                 = 16 // 16 and greater are reserved
};

/* MADT Subtables, correspond to Type in ACPI_SUBTABLE_HEADER */

/* MADT Local APIC flags */
#define ACPI_MADT_ENABLED  1 // Processor is usable if set

/* MADT MPS INTI flags (IntiFlags). Table 5-24 (ACPI 3.0) */
#define ACPI_MADT_POLARITY_CONFORMS     0
#define ACPI_MADT_POLARITY_ACTIVE_HIGH  1
#define ACPI_MADT_POLARITY_RESERVED     2
#define ACPI_MADT_POLARITY_ACTIVE_LOW   3
#define ACPI_MADT_POLARITY_MASK         (3)      // Polarity of APIC I/O input signals

#define ACPI_MADT_TRIGGER_CONFORMS      (0)
#define ACPI_MADT_TRIGGER_EDGE          (1 << 2)
#define ACPI_MADT_TRIGGER_RESERVED      (2 << 2)
#define ACPI_MADT_TRIGGER_LEVEL         (3 << 2)
#define ACPI_MADT_TRIGGER_MASK          (3 << 2) // Trigger mode of APIC input signals

/* 0: Processor Local APIC */
typedef struct _ACPI_MADT_LOCAL_APIC
{
    ACPI_SUBTABLE_HEADER Header;
    UCHAR ProcessorId;          // ACPI processor id
    UCHAR Id;                   // Processor's local APIC id
    ULONG LapicFlags;

} ACPI_MADT_LOCAL_APIC, *PACPI_MADT_LOCAL_APIC;

/* 1: IO APIC */
typedef struct _ACPI_MADT_IO_APIC
{
    ACPI_SUBTABLE_HEADER Header;
    UCHAR Id;                   // I/O APIC ID
    UCHAR Reserved;             // Reserved - must be zero
    ULONG Address;              // APIC physical address
    ULONG GlobalIrqBase;        // Global system interrupt where INTI lines start

} ACPI_MADT_IO_APIC, *PACPI_MADT_IO_APIC;

/* 2: Interrupt Override. Table 5-23 (ACPI 3.0) */
#include <pshpack1.h>
typedef struct _ACPI_MADT_INTERRUPT_OVERRIDE
{
    ACPI_SUBTABLE_HEADER Header;
    UCHAR Bus;                  // 0 - ISA
    UCHAR SourceIrq;            // Interrupt source (IRQ)
    ULONG GlobalIrq;            // Global system interrupt
    USHORT IntiFlags;

} ACPI_MADT_INTERRUPT_OVERRIDE, *PACPI_MADT_INTERRUPT_OVERRIDE;
#include <poppack.h>

/* 3: NMI Source */
typedef struct _ACPI_MADT_NMI_SOURCE
{
    ACPI_SUBTABLE_HEADER Header;
    USHORT IntiFlags;
    ULONG GlobalIrq;            // Global system interrupt

} ACPI_MADT_NMI_SOURCE, *PACPI_MADT_NMI_SOURCE;

/* 4: Local APIC NMI */
typedef struct _ACPI_MADT_LOCAL_APIC_NMI
{
    ACPI_SUBTABLE_HEADER Header;
    UCHAR ProcessorId;          // ACPI processor id
    USHORT IntiFlags;
    UCHAR Lint;                 // LINTn to which NMI is connected
} ACPI_MADT_LOCAL_APIC_NMI;

/* Multiple APIC Description Table (MADT). Table 5-17 (ACPI 3.0) */

/* Values for PCATCompat flag */
#define ACPI_MADT_MULTIPLE_APIC  0
#define ACPI_MADT_DUAL_PIC       1

typedef struct _ACPI_TABLE_MADT
{
    ACPI_TABLE_HEADER Header;   // Common ACPI table header
    ULONG Address;              // Physical address of local APIC
    ULONG Flags;

} ACPI_TABLE_MADT, *PACPI_TABLE_MADT;

/* Internal HAL structure */
typedef struct _ACPI_CACHED_TABLE
{
    LIST_ENTRY Links;
    DESCRIPTION_HEADER Header;
    // table follows
    // ...
} ACPI_CACHED_TABLE, *PACPI_CACHED_TABLE;

#define ACPI_USE_PLATFORM_CLOCK  0x8000

#include <pshpack4.h>
typedef struct _HALP_TIMER_INFO
{
    PULONG TimerPort;
    LARGE_INTEGER AcpiTimeValue;
    ULONG TimerCarry;
    ULONG ValueExt;
    LARGE_INTEGER PerformanceCounter;
    ULONGLONG Reserved1;
    ULONG Reserved2;

} HALP_TIMER_INFO, *PHALP_TIMER_INFO;
#include <poppack.h>

PVOID
NTAPI
HalpAcpiGetTable(
    IN PLOADER_PARAMETER_BLOCK LoaderBlock,
    IN ULONG Signature
);

//INIT_FUNCTION
PVOID
NTAPI
HalAcpiGetTable(
    IN PLOADER_PARAMETER_BLOCK LoaderBlock,
    IN ULONG Signature
);

//INIT_FUNCTION
VOID
NTAPI
HalpCheckPowerButton(
    VOID
);

//INIT_FUNCTION
NTSTATUS
NTAPI
HalpSetupAcpiPhase0(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock
);

//INIT_FUNCTION
VOID
NTAPI
HalpAcpiDetectMachineSpecificActions(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock,
    _In_ PFADT DescriptionTable
);

//INIT_FUNCTION
VOID
NTAPI
HalpInitializeCmos(
    VOID
);

NTSTATUS
NTAPI
HalacpiGetInterruptTranslator(
    _In_ INTERFACE_TYPE ParentInterfaceType,
    _In_ ULONG ParentBusNumber,
    _In_ INTERFACE_TYPE BridgeInterfaceType,
    _In_ USHORT Size,
    _In_ USHORT Version,
    _Out_ PTRANSLATOR_INTERFACE Translator,
    _Out_ PULONG BridgeBusNumber
);

NTSTATUS
NTAPI
HaliInitPowerManagement(
    _In_ PPM_DISPATCH_TABLE PmDriverDispatchTable,
    _Out_ PPM_DISPATCH_TABLE* PmHalDispatchTable
);

VOID
NTAPI
HaliHaltSystem(
    VOID
);

VOID
NTAPI
HaliPmTimerQueryPerfCount(
    _Out_ LARGE_INTEGER* OutPerfCount,
    _Out_ LARGE_INTEGER* OutPerfFrequency
);

typedef
ULONGLONG
(__cdecl * PHALP_QUERY_TIMER)(
    VOID
);

ULONGLONG
__cdecl
HalpQueryPerformanceCounter(
    VOID
);

typedef
VOID
(NTAPI * PHALP_STALL_EXEC_PROC)(
    _In_ ULONG MicroSeconds
);

VOID
NTAPI
HalpPmTimerStallExecProc(
    _In_ ULONG MicroSeconds
);

typedef
VOID
(NTAPI * PHALP_CALIBRATE_PERF_COUNT)(
    _In_ volatile PLONG Count,
    _In_ ULONGLONG NewCount
);

VOID
NTAPI
HalpPmTimerCalibratePerfCount(
    _In_ volatile PLONG Count,
    _In_ ULONGLONG NewCount
);

typedef
LARGE_INTEGER
(NTAPI * PHALP_QUERY_PERF_COUNT)(
    _Out_opt_ LARGE_INTEGER* OutPerformanceFrequency
);

LARGE_INTEGER
NTAPI
HalpPmTimerQueryPerfCount(
    _Out_opt_ LARGE_INTEGER* OutPerformanceFrequency
);

typedef
ULONG
(NTAPI * PHALP_SET_TIME_INCREMENT)(
    _In_ ULONG Increment
);

ULONG
NTAPI
HalpPmTimerSetTimeIncrement(
    _In_ ULONG Increment
);

BOOLEAN
NTAPI
HalpFindBusAddressTranslation(
    _In_ PHYSICAL_ADDRESS BusAddress,
    _In_ OUT PULONG AddressSpace,
    _Out_ PPHYSICAL_ADDRESS TranslatedAddress,
    _In_ OUT PULONG_PTR Context,
    _In_ BOOLEAN NextBus
);

//INIT_FUNCTION
VOID
NTAPI
HalpGetNMICrashFlag(
    VOID
);

//INIT_FUNCTION
VOID
NTAPI
HalpInitializePciBus(
    VOID
);

BOOLEAN
NTAPI
HalpGetDebugPortTable(
    VOID
);

ULONG
NTAPI
HalpIs16BitPortDecodeSupported(
    VOID
);

//INIT_FUNCTION
VOID
NTAPI
HalReportResourceUsage(
    VOID
);

VOID
NTAPI
HalpWriteResetCommand(
    VOID
);

BOOLEAN
NTAPI
HalpTranslateBusAddress(
    _In_ INTERFACE_TYPE InterfaceType,
    _In_ ULONG BusNumber,
    _In_ PHYSICAL_ADDRESS BusAddress,
    _In_ OUT PULONG AddressSpace,
    _Out_ PPHYSICAL_ADDRESS TranslatedAddress
);

NTSTATUS
NTAPI
HalpAssignSlotResources(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PUNICODE_STRING DriverClassName,
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ INTERFACE_TYPE BusType,
    _In_ ULONG BusNumber,
    _In_ ULONG SlotNumber,
    _Inout_ PCM_RESOURCE_LIST* AllocatedResources
);

NTSTATUS
NTAPI
HalpQueryAcpiResourceRequirements(
    _Out_ PIO_RESOURCE_REQUIREMENTS_LIST* Requirements
);

VOID
NTAPI
HaliAcpiTimerInit(
    _In_ PULONG TimerPort,
    _In_ BOOLEAN TimerValExt
);

VOID
NTAPI
HalTranslatorDereference(
    IN PVOID Context
);

/* EOF */
