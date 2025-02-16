
#pragma once

/* Internal HAL structure */
typedef struct _ACPI_CACHED_TABLE
{
    LIST_ENTRY Links;
    DESCRIPTION_HEADER Header;
    // table follows
    // ...
} ACPI_CACHED_TABLE, *PACPI_CACHED_TABLE;


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
    IN PLOADER_PARAMETER_BLOCK LoaderBlock
);

VOID
NTAPI
HaliAcpiTimerInit(
    _In_ PULONG TimerPort,
    _In_ BOOLEAN TimerValExt
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

BOOLEAN
NTAPI
HalpTranslateBusAddress(
    IN INTERFACE_TYPE InterfaceType,
    IN ULONG BusNumber,
    IN PHYSICAL_ADDRESS BusAddress,
    IN OUT PULONG AddressSpace,
    OUT PPHYSICAL_ADDRESS TranslatedAddress
);

NTSTATUS
NTAPI
HalpAssignSlotResources(
    IN PUNICODE_STRING RegistryPath,
    IN PUNICODE_STRING DriverClassName,
    IN PDRIVER_OBJECT DriverObject,
    IN PDEVICE_OBJECT DeviceObject,
    IN INTERFACE_TYPE BusType,
    IN ULONG BusNumber,
    IN ULONG SlotNumber,
    IN OUT PCM_RESOURCE_LIST * AllocatedResources
);

BOOLEAN
NTAPI
HalpFindBusAddressTranslation(
    IN PHYSICAL_ADDRESS BusAddress,
    IN OUT PULONG AddressSpace,
    OUT PPHYSICAL_ADDRESS TranslatedAddress,
    IN OUT PULONG_PTR Context,
    IN BOOLEAN NextBus
);

NTSTATUS
NTAPI
HalacpiInitPowerManagement(
    _In_ PPM_DISPATCH_TABLE PmDriverDispatchTable,
    _Out_ PPM_DISPATCH_TABLE * PmHalDispatchTable
);

VOID
NTAPI
HaliHaltSystem(
    VOID
);

PVOID
NTAPI
HalpAcpiGetTable(
    IN PLOADER_PARAMETER_BLOCK LoaderBlock,
    IN ULONG Signature
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
HalpInitializePciBus(
    VOID
);

//INIT_FUNCTION
VOID
NTAPI
HalpGetNMICrashFlag(
    VOID
);

BOOLEAN
NTAPI
HalpGetDebugPortTable(
    VOID
);

NTSTATUS
NTAPI
HalpQueryAcpiResourceRequirements(
    OUT PIO_RESOURCE_REQUIREMENTS_LIST* Requirements
);

VOID
NTAPI
HalTranslatorDereference(
    IN PVOID Context
);

VOID
NTAPI
HalpWriteResetCommand(
    VOID
);

/* EOF */
