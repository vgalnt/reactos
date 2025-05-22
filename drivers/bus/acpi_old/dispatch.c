/*
 * PROJECT:     ACPI driver for NT 5.x
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IRP dispatching
 * COPYRIGHT:   Copyright 2019, 2023 Vadim Galyant <vgal@rambler.ru>
 */

#include "acpi.h"

#define NDEBUG
#include "debug.h"

#ifdef ALLOC_PRAGMA
  #pragma alloc_text(INIT, ACPIInitHalDispatchTable)
#endif

#ifdef ALLOC_PRAGMA
  #pragma alloc_text(PAGE, ACPIRootIrpStartDevice)
  #pragma alloc_text(PAGE, ACPIRootIrpQueryRemoveOrStopDevice)
  #pragma alloc_text(PAGE, ACPIRootIrpCancelRemoveOrStopDevice)
  #pragma alloc_text(PAGE, ACPIRootIrpStopDevice)
  #pragma alloc_text(PAGE, ACPIRootIrpQueryDeviceRelations)
  #pragma alloc_text(PAGE, ACPIRootIrpQueryInterface)
  #pragma alloc_text(PAGE, ACPIRootIrpQueryCapabilities)
  #pragma alloc_text(PAGE, ACPIFilterIrpDeviceUsageNotification)
  #pragma alloc_text(PAGE, ACPIInitialize)
#endif

/* GLOBALS *******************************************************************/
DEFINE_GUID(GUID_PCI_PME_INTERFACE, 0xAAC7E6AC, 0xBB0B, 0x11D2, 0xB4, 0x84, 0x00, 0xC0, 0x4F, 0x72, 0xDE, 0x8B); // FIXME
SYSTEM_POWER_STATE AcpiMostRecentSleepState = PowerSystemWorking;

PAMLI_NAME_SPACE_OBJECT ProcessorList[0x20];
ACPI_INTERFACE_STANDARD ACPIInterfaceTable;
ACPI_HAL_DISPATCH_TABLE AcpiHalDispatchTable;
PDEVICE_OBJECT FixedButtonDeviceObject;
PPM_DISPATCH_TABLE PmHalDispatchTable;
PACPI_INFORMATION AcpiInformation;
PPCI_PME_INTERFACE PciPmeInterface;
KSPIN_LOCK NotifyHandlerLock;
KSPIN_LOCK GpeTableLock;
ULONG AcpiSupportedSystemStates;
ULONG InterruptModel;
UCHAR ProcApics;
UCHAR ProcApicId;
BOOLEAN AcpiSystemInitialized;
BOOLEAN PciPmeInterfaceInstantiated;
BOOLEAN PciInterfacesInstantiated = FALSE;
BOOLEAN AcpiPowerLeavingS0;

ACPI_INTERNAL_DEVICE_FLAG AcpiInternalDeviceFlagTable[] =
{
    {"CPQB01D", 0x0000000080000000},
    {"IBM3760", 0x0000000080000000},
    {"ACPI0006", 0x0000002000120000},
    {"PNP0000", 0x0010000200300000},
    {"PNP0001", 0x0010000200300000},
    {"PNP0002", 0x0010000000300000},
    {"PNP0003", 0x0010000200300000},
    {"PNP0004", 0x0010000200300000},
    {"PNP0100", 0x0010000000300000},
    {"PNP0101", 0x0010000000300000},
    {"PNP0102", 0x0010000000300000},
    {"PNP0200", 0x0010000000300000},
    {"PNP0201", 0x0010000000300000},
    {"PNP0202", 0x0010000000300000},
    {"PNP0500", 0x0000000004000000},
    {"PNP0501", 0x0000000004000000},
    {"PNP0800", 0x0010000000300000},
    {"PNP0A00", 0x0000000000800000},
    {"PNP0A03", 0x0000000002000000},
    {"PNP0A05", 0x0000000001120000},
    {"PNP0A06", 0x0000000001120000},
    {"PNP0B00", 0x0010000800320000},
    {"PNP0C00", 0x0010000040300000},
    {"PNP0C01", 0x0010000040300000},
    {"PNP0C02", 0x0010000040300000},
    {"PNP0C04", 0x0010000000300000},
    {"PNP0C05", 0x0010000000300000},
    {"PNP0C09", 0x0000000000200000},
    {"PNP0C0B", 0x0010000000320000},
    {"PNP0C0C", 0x0010000800360000},
    {"PNP0C0D", 0x0010000800360000},
    {"PNP0C0E", 0x0010000800360000},
    {"PNP0C0F", 0x0000000010100001},
    {"PNP0C80", 0x0000008000000000},
    {"PNP8294", 0x0000000004000000},
    {"TOS6200", 0x0000000000020000},
    {NULL, 0}
};

ULONG AcpiBuildDevicePowerNameLookup[] =
{
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    'DJE_',
    0,
    'WRP_',
    0,
    '0RP_',
    0,
    '1RP_',
    0,
    '2RP_',
    0,
    'SRC_',
    0,
    'CSP_',
    0
};

ULONG AcpiSxDMethodTable[] =
{
    'DWS_',
    'D0S_',
    'D1S_',
    'D2S_',
    'D3S_',
    'D4S_',
    'D5S_'
};

PDRIVER_DISPATCH ACPIDispatchFdoPnpTable[] =
{
    NULL,
    ACPIRootIrpQueryRemoveOrStopDevice,
    ACPIRootIrpRemoveDevice,
    ACPIRootIrpCancelRemoveOrStopDevice,
    ACPIRootIrpStopDevice,
    ACPIRootIrpQueryRemoveOrStopDevice,
    ACPIRootIrpCancelRemoveOrStopDevice,
    ACPIRootIrpQueryDeviceRelations,
    ACPIRootIrpQueryInterface,
    ACPIRootIrpQueryCapabilities,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    ACPIFilterIrpDeviceUsageNotification,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp
};

PDRIVER_DISPATCH ACPIDispatchPdoPnpTable[] =
{
    NULL,
    ACPIBusIrpQueryRemoveOrStopDevice,
    ACPIBusIrpRemoveDevice,
    ACPIBusIrpCancelRemoveOrStopDevice,
    ACPIBusIrpStopDevice,
    ACPIBusIrpQueryRemoveOrStopDevice,
    ACPIBusIrpCancelRemoveOrStopDevice,
    ACPIBusIrpQueryDeviceRelations,
    ACPIBusIrpQueryInterface,
    ACPIBusIrpQueryCapabilities,
    ACPIBusIrpQueryResources,
    ACPIBusIrpQueryResourceRequirements,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpEject,
    ACPIBusIrpSetLock,
    ACPIBusIrpQueryId,
    ACPIBusIrpQueryPnpDeviceState,
    ACPIBusIrpUnhandled,
    ACPIBusIrpDeviceUsageNotification,
    ACPIBusIrpSurpriseRemoval,
    ACPIBusIrpUnhandled
};

PDRIVER_DISPATCH ACPIDispatchFdoPowerTable[] =
{
    ACPIWakeWaitIrp,
    ACPIDispatchForwardPowerIrp,
    ACPIRootIrpSetPower,
    ACPIRootIrpQueryPower,
    ACPIDispatchForwardPowerIrp
};

PDRIVER_DISPATCH ACPIDispatchBusPowerTable[] =
{
    ACPIWakeWaitIrp,
    ACPIDispatchPowerIrpUnhandled,
    ACPIBusIrpSetPower,
    ACPIBusIrpQueryPower,
    ACPIDispatchPowerIrpUnhandled
};

IRP_DISPATCH_TABLE AcpiFdoIrpDispatch =
{
    ACPIDispatchIrpSuccess,
    ACPIIrpDispatchDeviceControl,
    ACPIRootIrpStartDevice,
    ACPIDispatchFdoPnpTable,
    ACPIDispatchFdoPowerTable,
    ACPIDispatchWmiLog,
    ACPIDispatchForwardIrp,
    NULL
};

IRP_DISPATCH_TABLE AcpiPdoIrpDispatch =
{
    ACPIDispatchIrpInvalid,
    ACPIIrpDispatchDeviceControl,
    ACPIBusIrpStartDevice,
    ACPIDispatchPdoPnpTable,
    ACPIDispatchBusPowerTable,
    ACPIBusIrpUnhandled,
    ACPIDispatchIrpInvalid,
    NULL
};

PACPI_BUILD_DISPATCH AcpiBuildRunMethodDispatch[] =
{
    ACPIBuildProcessGenericComplete,
    NULL,
    NULL,
    ACPIBuildProcessRunMethodPhaseCheckSta,
    ACPIBuildProcessRunMethodPhaseCheckBridge,
    ACPIBuildProcessRunMethodPhaseRunMethod,
    ACPIBuildProcessRunMethodPhaseRecurse
};

PACPI_BUILD_DISPATCH AcpiBuildDeviceDispatch[] =
{
    ACPIBuildProcessGenericComplete,
    NULL,
    ACPIBuildProcessDeviceFailure,
    ACPIBuildProcessDevicePhaseAdrOrHid,
    ACPIBuildProcessDevicePhaseAdr,
    ACPIBuildProcessDevicePhaseHid,
    ACPIBuildProcessDevicePhaseUid,
    ACPIBuildProcessDevicePhaseCid,
    ACPIBuildProcessDevicePhaseSta,
    ACPIBuildProcessDeviceGenericEvalStrict,
    ACPIBuildProcessDevicePhaseEjd,
    ACPIBuildProcessDeviceGenericEvalStrict,
    ACPIBuildProcessDevicePhasePrw,
    ACPIBuildProcessDeviceGenericEvalStrict,
    ACPIBuildProcessDevicePhasePr0,
    ACPIBuildProcessDeviceGenericEvalStrict,
    ACPIBuildProcessDevicePhasePr1,
    ACPIBuildProcessDeviceGenericEvalStrict,
    ACPIBuildProcessDevicePhasePr2,
    ACPIBuildProcessDeviceGenericEvalStrict,
    ACPIBuildProcessDevicePhaseCrs,
    ACPIBuildProcessDeviceGenericEval,
    ACPIBuildProcessDevicePhasePsc
};

PACPI_BUILD_DISPATCH AcpiBuildPowerResourceDispatch[] =
{
    ACPIBuildProcessGenericComplete,
    NULL,
    ACPIBuildProcessPowerResourceFailure,
    ACPIBuildProcessPowerResourcePhase0,
    ACPIBuildProcessPowerResourcePhase1
};

PACPI_BUILD_DISPATCH AcpiBuildThermalZoneDispatch[] =
{
    ACPIBuildProcessGenericComplete,
    NULL,
    NULL,
    ACPIBuildProcessThermalZonePhase0
};

PDRIVER_DISPATCH ACPIDispatchBusFilterPnpTable[] =
{
    NULL,
    ACPIBusIrpQueryRemoveOrStopDevice,
    ACPIBusIrpRemoveDevice,
    ACPIBusIrpCancelRemoveOrStopDevice,
    ACPIBusIrpStopDevice,
    ACPIBusIrpQueryRemoveOrStopDevice,
    ACPIBusIrpCancelRemoveOrStopDevice,
    ACPIBusIrpQueryDeviceRelations,
    ACPIBusIrpQueryInterface,
    ACPIBusIrpQueryCapabilities,
    ACPIBusIrpQueryResources,
    ACPIBusIrpQueryResourceRequirements,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpEject,
    ACPIBusIrpSetLock,
    ACPIBusIrpQueryId,
    ACPIBusIrpQueryPnpDeviceState,
    ACPIBusIrpUnhandled,
    ACPIBusIrpDeviceUsageNotification,
    ACPIBusIrpSurpriseRemoval,
    ACPIBusIrpUnhandled
};

IRP_DISPATCH_TABLE AcpiBusFilterIrpDispatch =
{
    ACPIDispatchIrpInvalid,
    ACPIIrpDispatchDeviceControl,
    ACPIBusIrpStartDevice,
    ACPIDispatchBusFilterPnpTable,
    ACPIDispatchBusPowerTable,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    NULL
};

IRP_DISPATCH_TABLE AcpiGenericBusIrpDispatch =
{
    ACPIDispatchIrpInvalid,
    ACPIDispatchIrpInvalid,
    ACPIBusIrpStartDevice,
    ACPIDispatchBusFilterPnpTable,
    ACPIDispatchBusPowerTable,
    ACPIDispatchForwardIrp,
    ACPIDispatchIrpInvalid,
    NULL
};

PDRIVER_DISPATCH ACPIDispatchInternalDevicePnpTable[] =
{
    NULL,
    ACPIBusIrpQueryRemoveOrStopDevice,
    ACPIBusIrpRemoveDevice,
    ACPIBusIrpCancelRemoveOrStopDevice,
    ACPIBusIrpStopDevice,
    ACPIBusIrpQueryRemoveOrStopDevice,
    ACPIBusIrpCancelRemoveOrStopDevice,
    ACPIInternalDeviceQueryDeviceRelations,
    ACPIBusIrpQueryInterface,
    ACPIInternalDeviceQueryCapabilities,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpQueryId,
    ACPIBusIrpQueryPnpDeviceState,
    ACPIBusIrpUnhandled,
    ACPIBusIrpDeviceUsageNotification,
    ACPIBusIrpSurpriseRemoval,
    ACPIBusIrpUnhandled
};

PDRIVER_DISPATCH ACPIDispatchInternalDevicePowerTable[] =
{
    ACPIDispatchPowerIrpInvalid,
    ACPIDispatchPowerIrpUnhandled,
    ACPIDispatchPowerIrpSuccess,
    ACPIDispatchPowerIrpSuccess,
    ACPIDispatchPowerIrpUnhandled,
};

IRP_DISPATCH_TABLE AcpiFixedButtonIrpDispatch =
{
    ACPIDispatchIrpSuccess,
    ACPIButtonDeviceControl,
    ACPIButtonStartDevice,
    ACPIDispatchInternalDevicePnpTable,
    ACPIDispatchInternalDevicePowerTable,
    ACPIBusIrpUnhandled,
    ACPIDispatchIrpInvalid,
    NULL
};

PDRIVER_DISPATCH ACPIDispatchRawDevicePnpTable[] =
{
    NULL,
    ACPIBusIrpQueryRemoveOrStopDevice,
    ACPIBusIrpRemoveDevice,
    ACPIBusIrpCancelRemoveOrStopDevice,
    ACPIBusIrpStopDevice,
    ACPIBusIrpQueryRemoveOrStopDevice,
    ACPIBusIrpCancelRemoveOrStopDevice,
    ACPIInternalDeviceQueryDeviceRelations,
    ACPIBusIrpQueryInterface,
    ACPIInternalDeviceQueryCapabilities,
    ACPIBusIrpQueryResources,
    ACPIBusIrpQueryResourceRequirements,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpSetLock,
    ACPIBusIrpQueryId,
    ACPIBusIrpQueryPnpDeviceState,
    ACPIBusIrpUnhandled,
    ACPIBusIrpDeviceUsageNotification,
    ACPIBusIrpSurpriseRemoval,
    ACPIBusIrpUnhandled
};

IRP_DISPATCH_TABLE AcpiRawDeviceIrpDispatch =
{
    ACPIDispatchIrpInvalid,
    ACPIDispatchIrpInvalid,
    ACPIBusIrpStartDevice,
    ACPIDispatchRawDevicePnpTable,
    ACPIDispatchBusPowerTable,
    ACPIBusIrpUnhandled,
    ACPIDispatchIrpInvalid,
    NULL
};

PDRIVER_DISPATCH ACPIDispatchEIOBusPnpTable[] =
{
    NULL,
    ACPIBusIrpQueryRemoveOrStopDevice,
    ACPIBusIrpRemoveDevice,
    ACPIBusIrpCancelRemoveOrStopDevice,
    ACPIBusIrpStopDevice,
    ACPIBusIrpQueryRemoveOrStopDevice,
    ACPIBusIrpCancelRemoveOrStopDevice,
    ACPIBusIrpQueryDeviceRelations,
    ACPIBusIrpQueryInterface,
    ACPIBusIrpQueryCapabilities,
    ACPIBusIrpQueryResources,
    ACPIBusIrpQueryResourceRequirements,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpEject,
    ACPIBusIrpSetLock,
    ACPIBusIrpQueryId,
    ACPIBusIrpQueryPnpDeviceState,
    ACPIBusIrpQueryBusInformation,
    ACPIBusIrpDeviceUsageNotification,
    ACPIBusIrpSurpriseRemoval,
    ACPIBusIrpUnhandled
};

IRP_DISPATCH_TABLE AcpiEIOBusIrpDispatch =
{
    ACPIDispatchIrpInvalid,
    ACPIDispatchIrpInvalid,
    ACPIBusIrpStartDevice,
    ACPIDispatchEIOBusPnpTable,
    ACPIDispatchBusPowerTable,
    ACPIDispatchForwardIrp,
    ACPIDispatchIrpInvalid,
    NULL
};

IRP_DISPATCH_TABLE AcpiRealTimeClockIrpDispatch =
{
    ACPIDispatchIrpSuccess,
    ACPIDispatchIrpInvalid,
    ACPIInternalDeviceClockIrpStartDevice,
    ACPIDispatchRawDevicePnpTable,
    ACPIDispatchBusPowerTable,
    ACPIBusIrpUnhandled,
    ACPIDispatchIrpInvalid,
    NULL
};

IRP_DISPATCH_TABLE AcpiFanIrpDispatch =
{
    ACPIDispatchIrpSuccess,
    ACPIDispatchIrpInvalid,
    ACPIThermalFanStartDevice,
    ACPIDispatchRawDevicePnpTable,
    ACPIDispatchInternalDevicePowerTable,
    ACPIBusIrpUnhandled,
    ACPIDispatchIrpInvalid,
    NULL
};

PDRIVER_DISPATCH ACPIDispatchButtonPowerTable[] =
{
    ACPIWakeWaitIrp,
    ACPIDispatchPowerIrpUnhandled,
    ACPICMButtonSetPower,
    ACPIDispatchPowerIrpSuccess,
    ACPIDispatchPowerIrpUnhandled,
};

IRP_DISPATCH_TABLE AcpiPowerButtonIrpDispatch =
{
    ACPIDispatchIrpSuccess,
    ACPIButtonDeviceControl,
    ACPICMPowerButtonStart,
    ACPIDispatchInternalDevicePnpTable,
    ACPIDispatchButtonPowerTable,
    ACPIBusIrpUnhandled,
    ACPIDispatchIrpInvalid,
    NULL
};

PDRIVER_DISPATCH ACPIDispatchLidPowerTable[] =
{
    ACPIWakeWaitIrp,
    ACPIDispatchPowerIrpUnhandled,
    ACPICMLidSetPower,
    ACPIDispatchPowerIrpSuccess,
    ACPIDispatchPowerIrpUnhandled,
};

IRP_DISPATCH_TABLE AcpiLidIrpDispatch =
{
    ACPIDispatchIrpSuccess,
    ACPIButtonDeviceControl,
    ACPICMLidStart,
    ACPIDispatchInternalDevicePnpTable,
    ACPIDispatchLidPowerTable,
    ACPIBusIrpUnhandled,
    ACPIDispatchIrpInvalid,
    ACPICMLidWorker
};

IRP_DISPATCH_TABLE AcpiSleepButtonIrpDispatch =
{
    ACPIDispatchIrpSuccess,
    ACPIButtonDeviceControl,
    ACPICMSleepButtonStart,
    ACPIDispatchInternalDevicePnpTable,
    ACPIDispatchButtonPowerTable,
    ACPIBusIrpUnhandled,
    ACPIDispatchIrpInvalid,
    NULL
};

IRP_DISPATCH_TABLE AcpiBusFilterIrpDispatchSucceedCreate =
{
    ACPIDispatchIrpSuccess,
    ACPIIrpDispatchDeviceControl,
    ACPIBusIrpStartDevice,
    ACPIDispatchBusFilterPnpTable,
    ACPIDispatchBusPowerTable,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    NULL
};

PDRIVER_DISPATCH ACPIDispatchFilterPnpTable[] =
{
    NULL,
    ACPIRootIrpQueryRemoveOrStopDevice,
    ACPIFilterIrpRemoveDevice,
    ACPIRootIrpCancelRemoveOrStopDevice,
    ACPIFilterIrpStopDevice,
    ACPIRootIrpQueryRemoveOrStopDevice,
    ACPIRootIrpCancelRemoveOrStopDevice,
    ACPIFilterIrpQueryDeviceRelations,
    ACPIFilterIrpQueryInterface,
    ACPIFilterIrpQueryCapabilities,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    ACPIFilterIrpEject,
    ACPIFilterIrpSetLock,
    ACPIFilterIrpQueryId,
    ACPIFilterIrpQueryPnpDeviceState,
    ACPIDispatchForwardIrp,
    ACPIFilterIrpDeviceUsageNotification,
    ACPIFilterIrpSurpriseRemoval,
    ACPIDispatchForwardIrp
};

PDRIVER_DISPATCH ACPIDispatchFilterPowerTable[] =
{
    ACPIWakeWaitIrp,
    ACPIDispatchForwardPowerIrp,
    ACPIFilterIrpSetPower,
    ACPIFilterIrpQueryPower,
    ACPIDispatchForwardPowerIrp
};

IRP_DISPATCH_TABLE AcpiFilterIrpDispatch =
{
    ACPIDispatchForwardIrp,
    ACPIIrpDispatchDeviceControl,
    ACPIFilterIrpStartDevice,
    ACPIDispatchFilterPnpTable,
    ACPIDispatchFilterPowerTable,
    ACPIDispatchForwardIrp,
    ACPIDispatchForwardIrp,
    NULL
};

PDRIVER_DISPATCH ACPIDispatchDockPnpTable[] =
{
    NULL,
    ACPIDispatchIrpSuccess,
    ACPIDockIrpRemoveDevice,
    ACPIDispatchIrpSuccess,
    ACPIDispatchIrpSuccess,
    ACPIDispatchIrpSuccess,
    ACPIDispatchIrpSuccess,
    ACPIDockIrpQueryDeviceRelations,
    ACPIDockIrpQueryInterface,
    ACPIDockIrpQueryCapabilities,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIBusIrpUnhandled,
    ACPIDockIrpEject,
    ACPIDockIrpSetLock,
    ACPIDockIrpQueryID,
    ACPIDockIrpQueryPnpDeviceState,
    ACPIBusIrpUnhandled,
    ACPIDispatchIrpInvalid,
    ACPIDispatchIrpSuccess,
    ACPIBusIrpUnhandled
};

PDRIVER_DISPATCH ACPIDispatchDockPowerTable[] =
{
    ACPIDispatchPowerIrpInvalid,
    ACPIDispatchPowerIrpUnhandled,
    ACPIDockIrpSetPower,
    ACPIDockIrpQueryPower,
    ACPIDispatchPowerIrpUnhandled,
};

IRP_DISPATCH_TABLE AcpiDockPdoIrpDispatch =
{
    ACPIDispatchIrpInvalid,
    ACPIIrpDispatchDeviceControl,
    ACPIDockIrpStartDevice,
    ACPIDispatchDockPnpTable,
    ACPIDispatchDockPowerTable,
    ACPIBusIrpUnhandled,
    ACPIDispatchIrpInvalid,
    NULL
};

IRP_DISPATCH_TABLE AcpiThermalZoneIrpDispatch =
{
    ACPIDispatchIrpSuccess,
    ACPIThermalDeviceControl,
    ACPIThermalStartDevice,
    ACPIDispatchPdoPnpTable,
    ACPIDispatchBusPowerTable,
    ACPIThermalWmi,
    ACPIDispatchIrpInvalid,
    ACPIThermalWorker
};

IRP_DISPATCH_TABLE AcpiProcessorIrpDispatch =
{
    ACPIDispatchIrpInvalid,
    ACPIProcessorDeviceControl,
    ACPIProcessorStartDevice,
    ACPIDispatchRawDevicePnpTable,
    ACPIDispatchBusPowerTable,
    ACPIBusIrpUnhandled,
    ACPIDispatchIrpInvalid,
    NULL
};

PPOWER_PROCESS_DISPATCH AcpiDevicePowerProcessPhase0Table1[6] =
{
    ACPIDevicePowerProcessPhase0DeviceSubPhase1,
    ACPIDevicePowerProcessPhase0SystemSubPhase1,
    ACPIDevicePowerProcessForward,
    ACPIDevicePowerProcessForward,
    ACPIDevicePowerProcessForward,
    ACPIDevicePowerProcessInvalid
};
PPOWER_PROCESS_DISPATCH AcpiDevicePowerProcessPhase0Table2[6] =
{
    ACPIDevicePowerProcessPhase0DeviceSubPhase2,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid
};
PPOWER_PROCESS_DISPATCH* AcpiDevicePowerProcessPhase0Dispatch[5] =
{
    NULL,
    NULL,
    NULL,
    AcpiDevicePowerProcessPhase0Table1,
    AcpiDevicePowerProcessPhase0Table2
};

PPOWER_PROCESS_DISPATCH AcpiDevicePowerProcessPhase1Table1[6] =
{
    ACPIDevicePowerProcessPhase1DeviceSubPhase1,
    ACPIDevicePowerProcessForward,
    ACPIDevicePowerProcessForward,
    ACPIDevicePowerProcessForward,
    ACPIDevicePowerProcessForward,
    ACPIDevicePowerProcessInvalid
};
PPOWER_PROCESS_DISPATCH AcpiDevicePowerProcessPhase1Table2[6] =
{
    ACPIDevicePowerProcessPhase1DeviceSubPhase2,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid
};
PPOWER_PROCESS_DISPATCH AcpiDevicePowerProcessPhase1Table3[6] =
{
    ACPIDevicePowerProcessPhase1DeviceSubPhase3,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid
};
PPOWER_PROCESS_DISPATCH AcpiDevicePowerProcessPhase1Table4[6] =
{
    ACPIDevicePowerProcessPhase1DeviceSubPhase4,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid
};
PPOWER_PROCESS_DISPATCH* AcpiDevicePowerProcessPhase1Dispatch[7] =
{
    NULL,
    NULL,
    NULL,
    AcpiDevicePowerProcessPhase1Table1,
    AcpiDevicePowerProcessPhase1Table2,
    AcpiDevicePowerProcessPhase1Table3,
    AcpiDevicePowerProcessPhase1Table4
};

PPOWER_PROCESS_DISPATCH AcpiDevicePowerProcessPhase2Table1[6] =
{
    ACPIDevicePowerProcessForward,
    ACPIDevicePowerProcessPhase2SystemSubPhase1,
    ACPIDevicePowerProcessForward,
    ACPIDevicePowerProcessForward,
    ACPIDevicePowerProcessForward,
    ACPIDevicePowerProcessInvalid
};
PPOWER_PROCESS_DISPATCH AcpiDevicePowerProcessPhase2Table2[6] =
{
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessPhase2SystemSubPhase2,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid
};
PPOWER_PROCESS_DISPATCH AcpiDevicePowerProcessPhase2Table3[6] =
{
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessPhase2SystemSubPhase3,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid
};
PPOWER_PROCESS_DISPATCH* AcpiDevicePowerProcessPhase2Dispatch[6] =
{
    NULL,
    NULL,
    NULL,
    AcpiDevicePowerProcessPhase2Table1,
    AcpiDevicePowerProcessPhase2Table2,
    AcpiDevicePowerProcessPhase2Table3
};

PPOWER_PROCESS_DISPATCH AcpiDevicePowerProcessPhase5Table1[6] =
{
    ACPIDevicePowerProcessPhase5DeviceSubPhase1,
    ACPIDevicePowerProcessPhase5SystemSubPhase1,
    ACPIDevicePowerProcessForward,
    ACPIDevicePowerProcessPhase5WarmEjectSubPhase1,
    ACPIDevicePowerProcessForward,
    ACPIDevicePowerProcessInvalid
};
PPOWER_PROCESS_DISPATCH AcpiDevicePowerProcessPhase5Table2[6] =
{
    ACPIDevicePowerProcessPhase5DeviceSubPhase2,
    ACPIDevicePowerProcessPhase5SystemSubPhase2,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessPhase5WarmEjectSubPhase2,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid
};
PPOWER_PROCESS_DISPATCH AcpiDevicePowerProcessPhase5Table3[6] =
{
    ACPIDevicePowerProcessPhase5DeviceSubPhase3,
    ACPIDevicePowerProcessPhase5SystemSubPhase3,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid
};
PPOWER_PROCESS_DISPATCH AcpiDevicePowerProcessPhase5Table4[6] =
{
    ACPIDevicePowerProcessPhase5DeviceSubPhase4,
    ACPIDevicePowerProcessPhase5SystemSubPhase4,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid
};
PPOWER_PROCESS_DISPATCH AcpiDevicePowerProcessPhase5Table5[6] =
{
    ACPIDevicePowerProcessPhase5DeviceSubPhase5,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid
};
PPOWER_PROCESS_DISPATCH AcpiDevicePowerProcessPhase5Table6[6] =
{
    ACPIDevicePowerProcessPhase5DeviceSubPhase6,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid,
    ACPIDevicePowerProcessInvalid
};
PPOWER_PROCESS_DISPATCH* AcpiDevicePowerProcessPhase5Dispatch[9] =
{
    NULL,
    NULL,
    NULL,
    AcpiDevicePowerProcessPhase5Table1,
    AcpiDevicePowerProcessPhase5Table2,
    AcpiDevicePowerProcessPhase5Table3,
    AcpiDevicePowerProcessPhase5Table4,
    AcpiDevicePowerProcessPhase5Table5,
    AcpiDevicePowerProcessPhase5Table6
};

ACPI_INTERNAL_DEVICE AcpiInternalDeviceTable[] =
{
    {"ACPI0006", &AcpiGenericBusIrpDispatch},
    {"FixedButton", &AcpiFixedButtonIrpDispatch},
    {"PNP0000", &AcpiRawDeviceIrpDispatch},
    {"PNP0001", &AcpiRawDeviceIrpDispatch},
    {"PNP0002", &AcpiRawDeviceIrpDispatch},
    {"PNP0003", &AcpiRawDeviceIrpDispatch},
    {"PNP0004", &AcpiRawDeviceIrpDispatch},
    {"PNP0100", &AcpiRawDeviceIrpDispatch},
    {"PNP0101", &AcpiRawDeviceIrpDispatch},
    {"PNP0102", &AcpiRawDeviceIrpDispatch},
    {"PNP0200", &AcpiRawDeviceIrpDispatch},
    {"PNP0201", &AcpiRawDeviceIrpDispatch},
    {"PNP0202", &AcpiRawDeviceIrpDispatch},
    {"PNP0800", &AcpiRawDeviceIrpDispatch},
    {"PNP0A05", &AcpiGenericBusIrpDispatch},
    {"PNP0A06", &AcpiEIOBusIrpDispatch},
    {"PNP0B00", &AcpiRealTimeClockIrpDispatch},
    {"PNP0C00", &AcpiRawDeviceIrpDispatch},
    {"PNP0C01", &AcpiRawDeviceIrpDispatch},
    {"PNP0C02", &AcpiRawDeviceIrpDispatch},
    {"PNP0C04", &AcpiRawDeviceIrpDispatch},
    {"PNP0C05", &AcpiRawDeviceIrpDispatch},
    {"PNP0C0B", &AcpiFanIrpDispatch},
    {"PNP0C0C", &AcpiPowerButtonIrpDispatch},
    {"PNP0C0D", &AcpiLidIrpDispatch},
    {"PNP0C0E", &AcpiSleepButtonIrpDispatch},
    {"SNY5001", &AcpiBusFilterIrpDispatchSucceedCreate},
    {"IBM0062", &AcpiBusFilterIrpDispatchSucceedCreate},
    {"DockDevice", &AcpiDockPdoIrpDispatch},
    {"ThermalZone", &AcpiThermalZoneIrpDispatch},
    {"Processor", &AcpiProcessorIrpDispatch},
    {NULL, NULL}
};

SYSTEM_POWER_STATE SystemPowerStateTranslation[6] =
{
    1, 2, 3, 4, 5, 6
};

DEVICE_POWER_STATE DevicePowerStateTranslation[4] =
{
    1, 2, 3, 4
};

LONG AcpiSystemStateTranslation[] =
{
    -1, 0, 1, 2, 3, 4, 5
};

PCHAR StateName[] =
{
    "\\_S1",
    "\\_S2",
    "\\_S3",
    "\\_S4",
    "\\_S5"
};

WMIGUIDREGINFO ACPIThermalGuidList =
{
    &THERMAL_ZONE_GUID, 1, 0
};

UCHAR FirstSetLeftBit[] =
{
     0, 0,
     1, 1,
     2, 2, 2, 2,
     3, 3, 3, 3, 3, 3, 3, 3,
     4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
     5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
     6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
     6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
     7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
     7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
     7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
     7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7
};

extern NPAGED_LOOKASIDE_LIST BuildRequestLookAsideList;
extern NPAGED_LOOKASIDE_LIST RequestLookAsideList;
extern NPAGED_LOOKASIDE_LIST PswContextLookAsideList;
extern KSPIN_LOCK AcpiDeviceTreeLock;
extern KSPIN_LOCK AcpiBuildQueueLock;
extern KSPIN_LOCK AcpiPowerQueueLock;
extern KSPIN_LOCK AcpiGetLock;
extern LIST_ENTRY AcpiBuildDeviceList;
extern LIST_ENTRY AcpiBuildSynchronizationList;
extern LIST_ENTRY AcpiBuildQueueList;
extern LIST_ENTRY AcpiBuildRunMethodList;
extern LIST_ENTRY AcpiBuildOperationRegionList;
extern LIST_ENTRY AcpiBuildPowerResourceList;
extern LIST_ENTRY AcpiBuildThermalZoneList;
extern LIST_ENTRY AcpiPowerDelayedQueueList;
extern LIST_ENTRY AcpiGetListEntry;
extern LIST_ENTRY AcpiUnresolvedEjectList;
extern LIST_ENTRY AcpiPowerSynchronizeList;
extern LIST_ENTRY AcpiPowerQueueList;
extern LIST_ENTRY AcpiPowerPhase0List;
extern LIST_ENTRY AcpiPowerPhase1List;
extern LIST_ENTRY AcpiPowerPhase2List;
extern LIST_ENTRY AcpiPowerPhase3List;
extern LIST_ENTRY AcpiPowerPhase4List;
extern LIST_ENTRY AcpiPowerPhase5List;
extern LIST_ENTRY AcpiPowerWaitWakeList;
extern LIST_ENTRY AcpiPowerNodeList;
extern LIST_ENTRY AcpiButtonList;
extern LIST_ENTRY ACPIDeviceWorkQueue;
extern LIST_ENTRY AcpiThermalList;
extern KDPC AcpiBuildDpc;
extern KDPC AcpiPowerDpc;
extern KDPC AcpiGpeDpc;
extern BOOLEAN AcpiBuildDpcRunning;
extern BOOLEAN AcpiBuildWorkDone;
extern BOOLEAN AcpiPowerWorkDone;
extern BOOLEAN AcpiPowerDpcRunning;
extern BOOLEAN ACPIWorkerBusy;
extern PRSDTINFORMATION RsdtInformation;
extern PDEVICE_EXTENSION RootDeviceExtension;
extern ULONG AcpiOverrideAttributes;
extern KSPIN_LOCK AcpiPowerLock;
extern KSPIN_LOCK AcpiButtonLock;
extern KSPIN_LOCK ACPIWorkerSpinLock;
extern KSPIN_LOCK AcpiThermalLock;
extern PUCHAR GpeEnable;
extern PUCHAR GpeWakeHandler;
extern PUCHAR GpeSpecialHandler;
extern ARBITER_INSTANCE AcpiArbiter;
extern ANSI_STRING AcpiProcessorString;
extern KSPIN_LOCK gdwGContextSpinLock;
extern ULONG gdwcCTObjsMax;
extern PUCHAR GpeWakeEnable;
extern PUCHAR GpeCurEnable;
extern PUCHAR GpePending;
extern PUCHAR GpeIsLevel;
extern PUCHAR GpeMap;
extern PUCHAR GpeRunMethod;
extern PUCHAR GpeComplete;
extern PUCHAR GpeHandlerType;
extern BOOLEAN AcpiGpeWorkDone;
extern BOOLEAN AcpiGpeDpcRunning;
extern BOOLEAN AcpiGpeDpcScheduled;
extern WORK_QUEUE_ITEM ACPIWorkItem;

/* FUNCTIOS *****************************************************************/

VOID
NTAPI
ACPIInternalMoveList(
    _In_ PLIST_ENTRY List1,
    _In_ PLIST_ENTRY List2)
{
    PLIST_ENTRY Flink1;
    PLIST_ENTRY Blink1;
    PLIST_ENTRY Blink2;

    Flink1 = List1->Flink;

    if (!IsListEmpty(List1))
    {
        Blink1 = List1->Blink;
        Blink2 = List2->Blink;

        Blink1->Flink = List2;
        List2->Blink = Blink1;
        Flink1->Blink = Blink2;
        Blink2->Flink = Flink1;

        InitializeListHead(List1);
    }
}

PDEVICE_EXTENSION
NTAPI
ACPIInternalGetDeviceExtension(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PDEVICE_EXTENSION DeviceExtension;
    KIRQL OldIrql;

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &OldIrql);

    DeviceExtension = DeviceObject->DeviceExtension;

    if (DeviceExtension && DeviceExtension->Signature != '_SGP')
    {
        DPRINT1("ACPIInternalGetDeviceExtension: FIXME\n");
        ASSERT(FALSE);
    }

    KeReleaseSpinLock(&AcpiDeviceTreeLock, OldIrql);

    return DeviceExtension;
}

NTSTATUS
NTAPI
ACPIBuildProcessGenericComplete(
    _In_ PACPI_BUILD_REQUEST Entry)
{
    PACPI_BUILD_REQUEST BuildRequest = Entry;
    PDEVICE_EXTENSION DeviceExtension;

    //DPRINT("ACPIBuildProcessGenericComplete: %p\n", BuildRequest);

    if (Entry->CallBack)
    {
        ((VOID (NTAPI *)(PVOID, PVOID, NTSTATUS))Entry->CallBack)(Entry->Context, Entry->CallBackContext, Entry->Status);
    }

    if (Entry->Flags & 8)
    {
        DeviceExtension = Entry->Context;

        KeAcquireSpinLockAtDpcLevel(&AcpiDeviceTreeLock);
        InterlockedDecrement(&DeviceExtension->ReferenceCount);
        KeReleaseSpinLockFromDpcLevel(&AcpiDeviceTreeLock);
    }

    KeAcquireSpinLockAtDpcLevel(&AcpiBuildQueueLock);
    AcpiBuildWorkDone = TRUE;
    RemoveEntryList(&BuildRequest->Link);
    KeReleaseSpinLockFromDpcLevel(&AcpiBuildQueueLock);

    ExFreeToNPagedLookasideList(&BuildRequestLookAsideList, BuildRequest);

    return STATUS_SUCCESS;
}

VOID
NTAPI
ACPIBuildCompleteCommon(
    _In_ LONG* Destination,
    _In_ LONG ExChange)
{
    KIRQL OldIrql;

    DPRINT("ACPIBuildCompleteCommon: %X, %X\n", *Destination, ExChange);

    InterlockedCompareExchange(Destination, ExChange, 1);

    KeAcquireSpinLock(&AcpiBuildQueueLock, &OldIrql);

    AcpiBuildWorkDone = TRUE;

    if (!AcpiBuildDpcRunning)
    {
        DPRINT("ACPIBuildCompleteCommon: %X\n", *Destination);
        KeInsertQueueDpc(&AcpiBuildDpc, NULL, NULL);
    }

    KeReleaseSpinLock(&AcpiBuildQueueLock, OldIrql);
}

VOID
__cdecl
ACPIBuildCompleteMustSucceed(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ NTSTATUS Status,
    _In_ ULONG Unknown3,
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    LONG OldBuildReserved1;
    ULONG NameSeg;

    DPRINT("ACPIBuildCompleteMustSucceed: %p, %X\n", BuildRequest, Status);

    OldBuildReserved1 = BuildRequest->BuildReserved1;

    if (NT_SUCCESS(Status))
    {
        BuildRequest->BuildReserved1 = 2;
        ACPIBuildCompleteCommon(&BuildRequest->WorkDone, OldBuildReserved1);
        return;
    }

    BuildRequest->Status = Status;

    if (NsObject)
        NameSeg = NsObject->NameSeg;
    else
        NameSeg = 0;

    DPRINT1("ACPIBuildCompleteMustSucceed: KeBugCheckEx()\n");
    ASSERT(FALSE);

    KeBugCheckEx(0xA5, 3, (ULONG_PTR)NsObject, Status, NameSeg);
}

VOID
NTAPI 
ACPIInternalUpdateDeviceStatus(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ ULONG DeviceStatus)
{
    DEVICE_EXTENSION* Extension;
    ULONGLONG RetFlagValue;
    KIRQL OldIrql;

    //DPRINT("ACPIInternalUpdateDeviceStatus: %p, %X\n", DeviceExtension, DeviceStatus);

    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0080000000000000, (DeviceStatus & 8));
    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0000000020000000, (DeviceStatus & 4));
    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0040000000000000, !(DeviceStatus & 2));

    RetFlagValue = ACPIInternalUpdateFlags(&DeviceExtension->Flags, 2, (DeviceStatus & 1));

    if (RetFlagValue & 2)
        return;

    if (DeviceStatus & 1)
        return;

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &OldIrql);

    Extension = DeviceExtension->ParentExtension;
    if (Extension)
    {
        do
        {
            if (!(Extension->Flags & 8))
                break;

            Extension = Extension->ParentExtension;
        }
        while (Extension);

        if (Extension)
            IoInvalidateDeviceRelations(Extension->PhysicalDeviceObject, BusRelations);
    }

    KeReleaseSpinLock(&AcpiDeviceTreeLock, OldIrql);
}

NTSTATUS
NTAPI 
ACPIGetProcessorStatus(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _Out_ ULONG* OutProcessorStatus)
{
    PAMLI_PROCESSOR_OBJECT ProcObject;
    PACPI_SUBTABLE_HEADER ApicHeader;
    PVOID ApicTable;
    PVOID MapicEnd;
    PMAPIC Mapic;
    ULONG ProcessorStatus = 0xF;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ACPIGetProcessorStatus: %p\n", DeviceExtension);

    ASSERT(DeviceExtension->AcpiObject != NULL);
    ASSERT(DeviceExtension->AcpiObject->ObjData.DataType == 0xC);

    if (!DeviceExtension->AcpiObject ||
        DeviceExtension->AcpiObject->ObjData.DataType != 0xC ||
        !DeviceExtension->AcpiObject->ObjData.DataBuff)
    {
        Status = STATUS_INVALID_DEVICE_REQUEST;
        goto Exit;
    }

    ProcObject = DeviceExtension->AcpiObject->ObjData.DataBuff;

    Mapic = AcpiInformation->MultipleApicTable;
    if (!Mapic)
    {
        if (!ProcApics)
        {
            ProcApicId = ProcObject->ApicID;
            ProcApics++;
        }

        if (ProcApicId != ProcObject->ApicID)
            ProcessorStatus = 0;

        goto Exit;
    }

    ApicTable = Mapic->APICTables;
    MapicEnd = Add2Ptr(Mapic, Mapic->Header.Length);

    while (TRUE)
    {
        if (ApicTable >= MapicEnd)
        {
            ProcessorStatus = 0;
            break;
        }

        ApicHeader = ApicTable;

        if (ApicHeader->Type == 0 && ApicHeader->Length == 8)
        {
            PACPI_MADT_LOCAL_APIC LocalApic = ApicTable;

            if (LocalApic->ProcessorId == ProcObject->ApicID)
            {
                if (!(LocalApic->LapicFlags & 1))
                    ProcessorStatus = 0;

                break;
            }

            ApicTable = Add2Ptr(ApicTable, LocalApic->Header.Length);

            continue;
        }

        if (ApicHeader->Type == 7 && ApicHeader->Length == 0xC)
        {
            PACPI_MADT_LOCAL_SAPIC LocalSapic = ApicTable;

            if (LocalSapic->ProcessorId == ProcObject->ApicID)
            {
                if (!(LocalSapic->LapicFlags & 1))
                    ProcessorStatus = 0;

                break;
            }

            ApicTable = Add2Ptr(ApicTable, LocalSapic->Header.Length);

            continue;
        }

        if (!ApicHeader->Length)
        {
            ProcessorStatus = 0;
            break;
        }

        ApicTable = Add2Ptr(ApicTable, ApicHeader->Length);
    }

Exit:

    *OutProcessorStatus = ProcessorStatus;

    return Status;
}

NTSTATUS
NTAPI 
ACPIGetConvertToDevicePresence(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA AmliData,
    _In_ ULONG GetFlags,
    _Out_ PVOID* OutDataBuff,
    _Out_ ULONG* OutDataLen)
{
    PAMLI_NAME_SPACE_OBJECT Child;
    ULONGLONG UFlags;
    ULONG DeviceStatus = 0xF;
    ULONG ProcessorStatus;
    NTSTATUS Status;

    DPRINT("ACPIGetConvertToDevicePresence: %p\n", DeviceExtension);

    if (GetFlags & 0x08000000)
    {
        if (InStatus != STATUS_OBJECT_NAME_NOT_FOUND)
        {
            if (NT_SUCCESS(InStatus))
            {
                if (AmliData->DataType != 1)
                {
                    DPRINT1("ACPIGetConvertToDevicePresence: KeBugCheckEx()\n");
                    ASSERT(FALSE);
                    KeBugCheckEx(0xA5, 8, (ULONG_PTR)DeviceExtension, 0, AmliData->DataType);
                }

                DeviceStatus = (ULONG)AmliData->DataValue;
            }
            else
            {
                DeviceStatus = 0;
            }
        }

        goto Finish;
    }

    if (DeviceExtension->Flags & 0x0200000000000000)            // Prop_Dock
        UFlags = (DeviceExtension->Flags & 0x0000000400000000); // Cap_Unattached_Dock
    else
        UFlags = (DeviceExtension->Flags & 0x0008000000000000); // Prop_No_Object

    if (UFlags == 0)
    {
        if (InStatus == STATUS_OBJECT_NAME_NOT_FOUND)
        {
            if (DeviceExtension->Flags & 0x0000001000000000)    // Cap_Processor
            {
                Status = ACPIGetProcessorStatus(DeviceExtension, &ProcessorStatus);

                if (NT_SUCCESS(Status))
                    DeviceStatus = ProcessorStatus;
                else
                    DeviceStatus = 0;
            }
        }
        else
        {
            if (NT_SUCCESS(InStatus))
            {
                if (AmliData->DataType != 1)
                {
                    Child = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, 'ATS_');
                    DPRINT1("ACPIGetConvertToDevicePresence: KeBugCheckEx()\n");
                    ASSERT(FALSE);
                    KeBugCheckEx(0xA5, 8, (ULONG_PTR)Child, AmliData->DataType, AmliData->DataType);
                }

                DeviceStatus = (ULONG)AmliData->DataValue;
            }
            else
            {
                DeviceStatus = 0;
            }
        }
    }

    if ((DeviceExtension->Flags & 1) && !(GetFlags & 0x1000)) // Type_Never_Present
        DeviceStatus &= ~1;

    if (DeviceExtension->Flags & 0x40000000) // Cap_Never_show_in_UI
        DeviceStatus &= ~4;

    ACPIInternalUpdateDeviceStatus(DeviceExtension, DeviceStatus);

Finish:

    *OutDataBuff = (PVOID)DeviceStatus;

    if (OutDataLen)
        *OutDataLen = 4;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIGetConvertToAddress(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA AmliData,
    _In_ ULONG GetFlags,
    _Out_ PVOID* OutDataBuff,
    _Out_ ULONG* OutDataLen)
{
    PVOID DataBuff;

    DPRINT("ACPIGetConvertToAddress: %p\n", DeviceExtension);

    ASSERT(OutDataBuff != NULL);

    if (!(GetFlags & 0x08000000) && (DeviceExtension->Flags & 0x2000000000000000))
    {
        DataBuff = DeviceExtension->DeviceID;
        goto Finish;
    }

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT("ACPIGetConvertToAddress: InStatus %X\n", InStatus);
        return InStatus;
    }

    if (AmliData->DataType != 1)
    {
        DPRINT1("ACPIGetConvertToAddress: STATUS_ACPI_INVALID_DATA. DataType %X\n", AmliData->DataType);
        return STATUS_ACPI_INVALID_DATA;
    }

    DataBuff = AmliData->DataValue;

Finish:

    *OutDataBuff = DataBuff;

    if (OutDataLen)
        *OutDataLen = 4;

    return STATUS_SUCCESS;
}

VOID
__cdecl
ACPIGetWorkerForInteger(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA AmliData,
    _In_ PVOID Context)
{
    PACPI_GET_CONTEXT AcpiGetContext = Context;
    PAMLI_FN_ASYNC_CALLBACK CallBack;
    ULONG Flags;
    KIRQL OldIrql;
    NTSTATUS Status = InStatus;

    DPRINT("ACPIGetWorkerForInteger: %p\n", AcpiGetContext);

    ASSERT(AcpiGetContext->OutDataBuff);

    if (!AcpiGetContext->OutDataBuff)
    {
        DPRINT("ACPIGetWorkerForInteger: FIXME\n");
        ASSERT(FALSE);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Finish;
    }

    Flags = AcpiGetContext->Flags;

    if (Flags & 0x400)
    {
        Status = ACPIGetConvertToAddress(AcpiGetContext->DeviceExtension,
                                         InStatus,
                                         AmliData,
                                         Flags,
                                         AcpiGetContext->OutDataBuff,
                                         AcpiGetContext->OutDataLen);
        goto Finish;
    }

    if (Flags & 0x800)
    {
        Status = ACPIGetConvertToDevicePresence(AcpiGetContext->DeviceExtension,
                                                InStatus,
                                                AmliData,
                                                Flags,
                                                AcpiGetContext->OutDataBuff,
                                                AcpiGetContext->OutDataLen);
        goto Finish;
    }

    if (NT_SUCCESS(InStatus))
    {
        if ((Flags & 0x4000) && AmliData->DataType != 1)
        {
            DPRINT("ACPIGetWorkerForInteger: FIXME\n");
            ASSERT(FALSE);
            Status = STATUS_ACPI_INVALID_DATA;
        }
        else
        {
            *AcpiGetContext->OutDataBuff = AmliData->DataValue;

            if (AcpiGetContext->OutDataLen)
                *AcpiGetContext->OutDataLen = 4;

            Status = STATUS_SUCCESS;
        }
    }

Finish:

    AcpiGetContext->Status = Status;

    if (NT_SUCCESS(InStatus))
        AMLIFreeDataBuffs(AmliData, 1);

    if (AcpiGetContext->Flags & 0x20000000)
        return;

    CallBack = AcpiGetContext->CallBack;
    if (CallBack)
        CallBack(NsObject, Status, NULL, AcpiGetContext->CallBackContext);

    KeAcquireSpinLock(&AcpiGetLock, &OldIrql);
    RemoveEntryList(&AcpiGetContext->List);
    KeReleaseSpinLock(&AcpiGetLock, OldIrql);

    ExFreePool(AcpiGetContext);
}

VOID
NTAPI
ACPIAmliDoubleToName(
    _In_ PCHAR DataBuff,
    _In_ ULONG Index,
    _In_ BOOLEAN IsNameID)
{
    PCHAR Name = DataBuff;

    DPRINT("ACPIAmliDoubleToName: %X, %X, %X\n", DataBuff, Index, IsNameID);

    if (IsNameID)
        *DataBuff++ = '*';

    *DataBuff++ = (((Index >> 2) & 0x1F) + 0x40);
    *DataBuff++ = (((Index >> 0xD) & 7) + (8 * ((Index & 3) + 8)));
    *DataBuff = (((Index & 0x1F00) >> 8) + 0x40);

    sprintf((DataBuff + 1), "%02X%02X", (int)((Index & 0x00FF0000) >> 16), (int)(Index >> 24));

    DPRINT("ACPIAmliDoubleToName: '%s'\n", Name);
}

VOID
NTAPI
ACPIAmliDoubleToNameWide(
    _In_ PWCHAR DataBuff,
    _In_ ULONG Index,
    _In_ BOOLEAN IsNameID)
{
    PWCHAR Name = DataBuff;

    DPRINT("ACPIAmliDoubleToNameWide: %X, %X, %X\n", DataBuff, Index, IsNameID);

    if (IsNameID)
        *DataBuff++ = '*';

    *DataBuff++ = (((Index >> 2) & 0x1F) + 0x40);
    *DataBuff++ = (((Index >> 0xD) & 7) + (8 * ((Index & 3) + 8)));
    *DataBuff = (((Index & 0x1F00) >> 8) + 0x40);

    swprintf((DataBuff + 1), L"%02X%02X", (int)((Index & 0x00FF0000) >> 16), (int)(Index >> 24));

    DPRINT("ACPIAmliDoubleToNameWide: '%S'\n", Name);
}

NTSTATUS
NTAPI
ACPIGetConvertToPnpID(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA AmliData,
    _In_ ULONG GetFlags,
    _Out_ PVOID* OutDataBuff,
    _Out_ ULONG* OutDataLen)
{
    PCHAR DataBuff;
    PCHAR IdString;
    POOL_TYPE PoolType;
    ULONG DataLen;

    DPRINT("ACPIGetConvertToPnpID: GetFlags %X\n", GetFlags);

    if (GetFlags & 0x10000000)
        PoolType = NonPagedPool;
    else
        PoolType = PagedPool;

    if (!(GetFlags & 0x08000000) && (DeviceExtension->Flags & 0x0000800000000000))
    {
        DataLen = (strlen(DeviceExtension->DeviceID) - 3);

        DataBuff = ExAllocatePoolWithTag(PoolType, DataLen, 'SpcA');
        if (!DataBuff)
        {
            DPRINT1("ACPIGetConvertToPnpID: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(DataBuff, DataLen);

        sprintf(DataBuff, "*%s", (DeviceExtension->Address + 5));
        goto Exit;
    }

    if (!(GetFlags & 0x08000000) && (DeviceExtension->Flags & 0x0000004000000000))
    {
        DataLen = 0xE;

        DataBuff = ExAllocatePoolWithTag(PoolType, DataLen, 'SpcA');
        if (!DataBuff)
        {
            DPRINT1("ACPIGetConvertToPnpID: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(DataBuff, DataLen);

        sprintf(DataBuff, "*%s", "PciBarTarget");
        goto Exit;
    }

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT("ACPIGetConvertToPnpID: InStatus %X\n", InStatus);
        return InStatus;
    }

    if (AmliData->DataType == 1)
    {
        DataLen = 9;

        DataBuff = ExAllocatePoolWithTag(PoolType, DataLen, 'SpcA');
        if (!DataBuff)
        {
            DPRINT1("ACPIGetConvertToPnpID: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(DataBuff, DataLen);

        ACPIAmliDoubleToName(DataBuff, (ULONG)AmliData->DataValue, TRUE);
        goto Exit;
    }
    else if (AmliData->DataType == 2)
    {
        IdString = AmliData->DataBuff;

        if (*IdString == '*')
            IdString++;

        DataLen = (strlen(IdString) + 2);

        DataBuff = ExAllocatePoolWithTag(PoolType, DataLen, 'SpcA');
        if (!DataBuff)
        {
            DPRINT1("ACPIGetConvertToPnpID: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(DataBuff, DataLen);

        sprintf(DataBuff, "*%s", IdString);
        goto Exit;
    }
    else
    {
        DPRINT1("ACPIGetConvertToPnpID: AmliData->DataType %X\n", AmliData->DataType);
        return STATUS_ACPI_INVALID_DATA;
    }

Exit:

    *OutDataBuff = DataBuff;

    if (OutDataLen)
        *OutDataLen = DataLen;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIGetConvertToPnpIDWide(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA AmliData,
    _In_ ULONG GetFlags,
    _Out_ PVOID* OutDataBuff,
    _Out_ ULONG* OutDataLen)
{
    PCHAR PnpIdString;
    PWCHAR PnpId;
    POOL_TYPE PoolType;
    ULONG PnpIdLen;

    DPRINT("ACPIGetConvertToPnpIDWide: GetFlags %X\n", GetFlags);

    if (GetFlags & 0x10000000)
        PoolType = NonPagedPool;
    else
        PoolType = PagedPool;

    if (!(GetFlags & 0x08000000) && (DeviceExtension->Flags & 0x0000800000000000))
    {
        PnpIdLen = (strlen(DeviceExtension->DeviceID) - 3);

        PnpId = ExAllocatePoolWithTag(PoolType, (PnpIdLen * 2), 'SpcA');
        if (!PnpId)
        {
            DPRINT1("ACPIGetConvertToPnpIDWide: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(PnpId, (PnpIdLen * 2));

        swprintf(PnpId, L"*%S", (DeviceExtension->DeviceID + 5));
        goto Exit;
    }

    if (!(GetFlags & 0x08000000) && (DeviceExtension->Flags & 0x0000004000000000))
    {
        PnpIdLen = 0xE;

        PnpId = ExAllocatePoolWithTag(PoolType, (PnpIdLen * 2), 'SpcA');
        if (!PnpId)
        {
            DPRINT1("ACPIGetConvertToPnpIDWide: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(PnpId, (PnpIdLen * 2));

        swprintf(PnpId, L"*%S", "PciBarTarget");
        goto Exit;
    }

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT1("ACPIGetConvertToPnpIDWide: InStatus %X\n", InStatus);
        return InStatus;
    }

    if (AmliData->DataType == 1)
    {
        PnpIdLen = 9;

        PnpId = ExAllocatePoolWithTag(PoolType, (PnpIdLen * 2), 'SpcA');
        if (!PnpId)
        {
            DPRINT1("ACPIGetConvertToPnpIDWide: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(PnpId, (PnpIdLen * 2));

        ACPIAmliDoubleToNameWide(PnpId, (ULONG)AmliData->DataValue, TRUE);
    }
    else if (AmliData->DataType == 2)
    {
        PnpIdString = AmliData->DataBuff;
        if (*PnpIdString == '*')
            PnpIdString++;

        PnpIdLen = (2 + strlen(PnpIdString));

        PnpId = ExAllocatePoolWithTag(PoolType, (PnpIdLen * 2), 'SpcA');
        if (!PnpId)
        {
            DPRINT1("ACPIGetConvertToPnpIDWide: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(PnpId, (PnpIdLen * 2));

        swprintf(PnpId, L"*%S", PnpIdString);
    }
    else
    {
        return STATUS_ACPI_INVALID_DATA;
    }

Exit:

    *OutDataBuff = PnpId;

    if (OutDataLen)
        *OutDataLen = (PnpIdLen * 2);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIGetConvertToInstanceID(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA AmliData,
    _In_ ULONG GetFlags,
    _Out_ PVOID* OutDataBuff,
    _Out_ ULONG* OutDataLen)
{
    PVOID DataBuff;
    POOL_TYPE PoolType;
    ULONG DataLen;

    DPRINT("ACPIGetConvertToInstanceID: GetFlags %X\n", GetFlags);

    if (GetFlags & 0x10000000)
        PoolType = NonPagedPool;
    else
        PoolType = PagedPool;

    if (!(GetFlags & 0x8000000) && (DeviceExtension->Flags & 0x0001000000000000))
    {
        DataLen = (strlen(DeviceExtension->InstanceID) + 1);

        DataBuff = ExAllocatePoolWithTag(PoolType, DataLen, 'SpcA');
        if (!DataBuff)
        {
            DPRINT1("ACPIGetConvertToInstanceID: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        //RtlZeroMemory(DataBuff, DataLen);
        RtlCopyMemory(DataBuff, AmliData->DataBuff, DataLen);

        goto Finish;
    }

    if (!(GetFlags & 0x8000000) && (DeviceExtension->Flags & 0x0000004000000000))
    {
        DataLen = 9;

        DataBuff = ExAllocatePoolWithTag(PoolType, DataLen, 'SpcA');
        if (!DataBuff)
        {
            DPRINT1("ACPIGetConvertToInstanceID: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(DataBuff, DataLen);
        sprintf(DataBuff, "%lx", (ULONG)DeviceExtension->Address);

        goto Finish;
    }

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT1("ACPIGetConvertToInstanceID: InStatus %X\n", InStatus);
        return InStatus;
    }

    if (AmliData->DataType == 1)
    {
        DataLen = 9;

        DataBuff = ExAllocatePoolWithTag(PoolType, DataLen, 'SpcA');
        if (!DataBuff)
        {
            DPRINT1("ACPIGetConvertToInstanceID: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(DataBuff, DataLen);
        sprintf(DataBuff, "%lx", (ULONG)AmliData->DataValue);

        goto Finish;
    }

    if (AmliData->DataType != 2)
    {
        DPRINT1("ACPIGetConvertToInstanceID: STATUS_ACPI_INVALID_DATA\n");
        return STATUS_ACPI_INVALID_DATA;
    }

    DataLen = (strlen(AmliData->DataBuff) + 1);

    DataBuff = ExAllocatePoolWithTag(PoolType, DataLen, 'SpcA');
    if (!DataBuff)
    {
        DPRINT1("ACPIGetConvertToInstanceID: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //RtlZeroMemory(DataBuff, DataLen);
    RtlCopyMemory(DataBuff, AmliData->DataBuff, DataLen);

Finish:

    *OutDataBuff = DataBuff;

    if (OutDataLen)
        *OutDataLen = DataLen;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIGetProcessorID(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS InStatus,
    _In_  PAMLI_OBJECT_DATA AmliData,
    _In_  ULONG GetFlags,
    _In_  PVOID* OutDataBuff,
    _In_  ULONG* OutDataLen)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIGetConvertToDeviceID(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS InStatus,
    _In_  PAMLI_OBJECT_DATA AmliData,
    _In_  ULONG GetFlags,
    _In_  PVOID* OutDataBuff,
    _In_  ULONG* OutDataLen)
{
    PCHAR deviceID;
    PCHAR IdString;
    POOL_TYPE PoolType;
    ULONG DataLen;

    DPRINT("ACPIGetConvertToDeviceID: GetFlags %X\n", GetFlags);

    if (!(GetFlags & 0x08000000) && (DeviceExtension->Flags & 0x0000001000000000))
        return ACPIGetProcessorID(DeviceExtension, InStatus, AmliData, GetFlags, OutDataBuff, OutDataLen);

    if (GetFlags & 0x10000000)
        PoolType = NonPagedPool;
    else
        PoolType = PagedPool;

    if (!(GetFlags & 0x08000000))
    {
        if (DeviceExtension->Flags & 0x0000800000000000)
        {
            DataLen = strlen(DeviceExtension->DeviceID);
            DataLen++;

            deviceID = ExAllocatePoolWithTag(PoolType, DataLen, 'SpcA');
            if (!deviceID)
            {
                DPRINT1("ACPIGetConvertToDeviceID: STATUS_INSUFFICIENT_RESOURCES\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            //RtlZeroMemory(deviceID, DataLen);

            RtlCopyMemory(deviceID, DeviceExtension->DeviceID, DataLen);

            goto Finish;
        }

        if (DeviceExtension->Flags & 0x0000004000000000)
        {
            DataLen = 0x12;

            deviceID = ExAllocatePoolWithTag(PoolType, DataLen, 'SpcA');
            if (!deviceID)
            {
                DPRINT1("ACPIGetConvertToDeviceID: STATUS_INSUFFICIENT_RESOURCES\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlZeroMemory(deviceID, DataLen);

            strncpy(deviceID, "ACPI\\PciBarTarget", (DataLen - 1));
            goto Finish;
        }
    }

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT1("ACPIGetConvertToDeviceID: InStatus %X\n", InStatus);
        return InStatus;
    }

    if (AmliData->DataType == 1)
    {
        DataLen = 0xD;

        deviceID = ExAllocatePoolWithTag(PoolType, DataLen, 'SpcA');
        if (!deviceID)
        {
            DPRINT1("ACPIGetConvertToDeviceID: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(deviceID, DataLen);

        sprintf(deviceID, "ACPI\\");
        ACPIAmliDoubleToName((deviceID + 5), (ULONG)AmliData->DataValue, FALSE);

        goto Finish;
    }

    if (AmliData->DataType != 2)
    {
        DPRINT1("ACPIGetConvertToDeviceID: STATUS_ACPI_INVALID_DATA\n");
        return STATUS_ACPI_INVALID_DATA;
    }

    IdString = AmliData->DataBuff;
    if (*IdString == '*')
        IdString++;

    DataLen = (strlen(IdString) + 6);

    deviceID = ExAllocatePoolWithTag(PoolType, DataLen, 'SpcA');
    if (!deviceID)
    {
        DPRINT1("ACPIGetConvertToDeviceID: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(deviceID, DataLen);

    sprintf(deviceID, "ACPI\\%s", IdString);

Finish:

    *OutDataBuff = deviceID;

    if (OutDataLen)
        *OutDataLen = DataLen;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIGetConvertToString(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS InStatus,
    _In_  PAMLI_OBJECT_DATA AmliData,
    _In_  ULONG GetFlags,
    _In_  PVOID* OutDataBuff,
    _In_  ULONG* OutDataLen)
{
    PVOID DataBuff;
    POOL_TYPE PoolType;
    ULONG DataLen;
    NTSTATUS Status = InStatus;

    if (GetFlags & 0x10000000)
        PoolType = NonPagedPool;
    else
        PoolType = PagedPool;

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT1("ACPIGetConvertToString: Status %X\n", Status);
        return Status;
    }

    if (AmliData->DataType != 2)
    {
        DPRINT1("ACPIGetConvertToString: STATUS_INSUFFICIENT_RESOURCES\n");
        ASSERT(FALSE);
        return STATUS_ACPI_INVALID_DATA;
    }

    DataLen = (strlen(AmliData->DataBuff) + 1);

    DataBuff = ExAllocatePoolWithTag(PoolType, DataLen, 'SpcA');
    if (!DataBuff)
    {
        DPRINT1("ACPIGetConvertToString: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    //RtlZeroMemory(DataBuff, DataLen);

    RtlCopyMemory(DataBuff, AmliData->DataBuff, DataLen);

    *OutDataBuff = DataBuff;

    if (OutDataLen)
        *OutDataLen = DataLen;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIGetConvertToStringWide(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA AmliData,
    _In_ ULONG GetFlags,
    _Out_ PVOID* OutDataBuff,
    _Out_ ULONG* OutDataLen)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIGetConvertToCompatibleID(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS InStatus,
    _In_  PAMLI_OBJECT_DATA AmliData,
    _In_  ULONG GetFlags,
    _In_  PVOID* OutDataBuff,
    _In_  ULONG* OutDataLen)
{
    PAMLI_PACKAGE_OBJECT PackageObject;
    PCHAR* buffer1;//Array PCHAR`s (id)
    PULONG buffer2;//Array ULONG`s (id len)
    PCHAR buffer;
    PVOID DataBuff;
    POOL_TYPE PoolType;
    ULONG DataLen;
    ULONG Count;
    ULONG IdSize;
    ULONG ix = 0;
    ULONG NumberOfBytes = 0;
    NTSTATUS Status = InStatus;

    if (GetFlags & 0x10000000)
        PoolType = NonPagedPool;
    else
        PoolType = PagedPool;

    if (!(GetFlags & 0x08000000) && (DeviceExtension->Flags & 0x8000000000000000))
    {
        IdSize = (strlen(DeviceExtension->Processor.CompatibleID) + 2);

        DataBuff = ExAllocatePoolWithTag(PoolType, IdSize, 'SpcA');
        if (!DataBuff)
        {
            DPRINT1("ACPIGetConvertToCompatibleID: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        //RtlZeroMemory(DataBuff, IdSize);

        RtlCopyMemory(DataBuff, DeviceExtension->Processor.CompatibleID, IdSize);

        *OutDataBuff = DataBuff;

        if (OutDataLen)
            *OutDataLen = 0;

        return STATUS_SUCCESS;
    }

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT1("ACPIGetConvertToCompatibleID: Status %X\n", Status);
        return InStatus;
    }

    if (AmliData->DataType == 1 || AmliData->DataType == 2)
    {
        Count = 1;
    }
    else if (AmliData->DataType == 4)
    {
        PackageObject = AmliData->DataBuff;
        Count = PackageObject->Elements;
    }
    else
    {
        DPRINT1("ACPIGetConvertToCompatibleID: STATUS_ACPI_INVALID_DATA\n");
        ASSERT(FALSE);
        return STATUS_ACPI_INVALID_DATA;
    }

    buffer1 = ExAllocatePoolWithTag(NonPagedPool, (Count * 4), 'MpcA');
    if (!buffer1)
    {
        DPRINT1("ACPIGetConvertToCompatibleID: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(buffer1, (Count * 4));

    buffer2 = ExAllocatePoolWithTag(NonPagedPool, (Count * 4), 'MpcA');
    if (!buffer2)
    {
        DPRINT1("ACPIGetConvertToCompatibleID: STATUS_INSUFFICIENT_RESOURCES\n");
        ExFreePoolWithTag(buffer1, 'MpcA');
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(buffer2, (Count * 4));

    if (AmliData->DataType == 1)
    {
        Status = ACPIGetConvertToPnpID(DeviceExtension, InStatus, AmliData, GetFlags, (PVOID *)buffer1, buffer2);
        NumberOfBytes = *buffer2;
    }
    else if (AmliData->DataType == 2)
    {
        Status = ACPIGetConvertToString(DeviceExtension, InStatus, AmliData, GetFlags, (PVOID *)buffer1, buffer2);
        NumberOfBytes = *buffer2;
    }
    else if (AmliData->DataType == 4)//OBJTYPE_PKGDATA
    {
        for (ix = 0; ix < Count; ix++)
        {
            if (PackageObject->Data[ix].DataType == 1)
            {
                Status = ACPIGetConvertToPnpID(DeviceExtension,
                                               InStatus,
                                               &PackageObject->Data[ix],
                                               GetFlags,
                                               (PVOID *)&buffer1[ix],
                                               &buffer2[ix]);
            }
            else if (PackageObject->Data[ix].DataType == 2)
            {
                Status = ACPIGetConvertToString(DeviceExtension,
                                                InStatus,
                                                &PackageObject->Data[ix],
                                                GetFlags,
                                                (PVOID *)&buffer1[ix],
                                                &buffer2[ix]);
            }
            else
            {
                DPRINT1("ACPIGetConvertToCompatibleID: Error! DataType %X\n", PackageObject->Data[ix].DataType);
                ASSERT(FALSE);
                //ACPIInternalError(..);
            }

            if (!NT_SUCCESS(Status))
            {
                DPRINT1("ACPIGetConvertToCompatibleID: Status %X\n", Status);
                break;
            }

            if (buffer2[ix] == 1)
                buffer2[ix] = 0;

            NumberOfBytes += buffer2[ix];
        }
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIGetConvertToCompatibleID: Status %X\n", Status);
        Count = ix;
        goto Exit;
    }

    if (NumberOfBytes <= 1)
    {
        DPRINT1("ACPIGetConvertToCompatibleID: STATUS_ACPI_INVALID_DATA\n");
        ASSERT(FALSE);
        Status = STATUS_ACPI_INVALID_DATA;
        goto Exit;
    }

    DataLen = (NumberOfBytes + 1);

    DataBuff = ExAllocatePoolWithTag(PoolType, DataLen, 'SpcA');
    if (!DataBuff)
    {
        DPRINT1("ACPIGetConvertToCompatibleID: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    RtlZeroMemory(DataBuff, DataLen);

    buffer = DataBuff;
    for (ix = 0; ix < Count; ix++)
    {
        if (buffer1[ix])
            RtlCopyMemory(buffer, buffer1[ix], buffer2[ix]);

        buffer += buffer2[ix];
    }

    *OutDataBuff = DataBuff;

    if (OutDataLen)
        *OutDataLen = DataLen;

Exit:

    for (ix = 0; ix < Count; ix++)
    {
        if (buffer1[ix])
            ExFreePool(buffer1[ix]);
    }

    ExFreePoolWithTag(buffer2, 'MpcA');
    ExFreePoolWithTag(buffer1, 'MpcA');

    return Status;
}

NTSTATUS
NTAPI
ACPIGetProcessorIDWide(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA AmliData,
    _In_ ULONG GetFlags,
    _Out_ PVOID* OutProcessorId,
    _Out_ ULONG* OutIdLen)
{
    PWCHAR ProcessorId;
    PCHAR FamilyStr = NULL;
    PCHAR ModelStr = NULL;
    PCHAR ProcStr = NULL;
    POOL_TYPE PoolType;
    ULONG Size;
    ULONG Index1;
    ULONG Index2;
    ULONG Index3;
    ULONG Index4;

    DPRINT("ACPIGetProcessorIDWide: %p\n", DeviceExtension);

    Size = (strlen("ACPI\\") + strlen(AcpiProcessorString.Buffer) + 1);

    if (GetFlags & 0x40)
    {
        ProcStr = ExAllocatePoolWithTag(NonPagedPool, Size, 'SpcA');
        if (!ProcStr)
        {
            DPRINT1("ACPIGetProcessorIDWide: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(ProcStr, Size);

        strcpy(ProcStr, AcpiProcessorString.Buffer);

        ModelStr = strstr(ProcStr, "Model");
        FamilyStr = strstr(ProcStr, "Family");

        if (!ModelStr || !FamilyStr)
        {
            DPRINT1("ACPIGetProcessorIDWide: STATUS_UNSUCCESSFUL\n");
            ExFreePoolWithTag(ProcStr, 'SpcA');
            return STATUS_UNSUCCESSFUL;
        }

        Size = (3 * (strlen("ACPI\\") + strlen("*") + (2 * Size)) - 2 * (strlen(ModelStr) + strlen(FamilyStr)));
    }

    if (GetFlags & 0x10000000)
        PoolType = NonPagedPool;
    else
        PoolType = PagedPool;

    ProcessorId = ExAllocatePoolWithTag(PoolType, (2 * Size), 'SpcA');
    if (!ProcessorId)
    {
        DPRINT1("ACPIGetProcessorIDWide: STATUS_INSUFFICIENT_RESOURCES\n");

        *OutProcessorId = NULL;

        if (OutIdLen)
            *OutIdLen = 0;

        if (ProcStr)
            ExFreePoolWithTag(ProcStr, 'SpcA');

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ProcessorId, (2 * Size));

    if (GetFlags & 0x20)
    {
        swprintf(ProcessorId, L"%S%S", "ACPI\\", AcpiProcessorString.Buffer);
    }
    else if (GetFlags & 0x40)
    {
        Index1 = swprintf(ProcessorId, L"%S%S", "ACPI\\", ProcStr);
        Index2 = swprintf(&ProcessorId[Index1 + 1], L"%S%S", "*", ProcStr);

        *(ModelStr - 1) = 0;

        Index3 = (Index2 + Index1 + 2 + swprintf(&ProcessorId[Index2 + Index1 + 2], L"%S%S", "ACPI\\", ProcStr) + 1);
        Index4 = swprintf(&ProcessorId[Index3], L"%S%S", "*", ProcStr);

        *(FamilyStr - 1) = 0;

        swprintf(&ProcessorId[Index4 + Index3 + 1 + swprintf(&ProcessorId[Index4 + Index3 + 1], L"%S%S", "ACPI\\", ProcStr) + 1], L"%S%S", "*", ProcStr);
    }

    if (ProcStr)
        ExFreePoolWithTag(ProcStr, 'SpcA');

    *OutProcessorId = ProcessorId;

    if (OutIdLen)
        *OutIdLen = (2 * Size);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIGetConvertToDeviceIDWide(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA AmliData,
    _In_ ULONG GetFlags,
    _Out_ PVOID* OutDataBuff,
    _Out_ ULONG* OutDataLen)
{
    PCHAR String;
    PWSTR DataBuff;
    POOL_TYPE PoolType;
    ULONG DataLen;

    DPRINT("ACPIGetConvertToDeviceIDWide: %p\n", DeviceExtension);

    if (!(GetFlags & 0x8000000) && (DeviceExtension->Flags & 0x0000001000000000))
    {
        return ACPIGetProcessorIDWide(DeviceExtension, InStatus, AmliData, GetFlags, OutDataBuff, OutDataLen);
    }

    if (GetFlags & 0x10000000)
        PoolType = NonPagedPool;
    else
        PoolType = PagedPool;

    if (!(GetFlags & 0x08000000))
    {
        if (DeviceExtension->Flags & 0x0000800000000000)
        {
            DataLen = (strlen(DeviceExtension->DeviceID) + 1);

            DataBuff = ExAllocatePoolWithTag(PoolType, (DataLen * 2), 'SpcA');
            if (!DataBuff)
            {
                DPRINT1("ACPIGetConvertToDeviceIDWide: STATUS_INSUFFICIENT_RESOURCES\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlZeroMemory(DataBuff, (DataLen * 2));

            swprintf(DataBuff, L"%S", DeviceExtension->DeviceID);
            goto Finish;
        }

        if (DeviceExtension->Flags & 0x0000004000000000)
        {
            DataLen = 0x12;

            DataBuff = ExAllocatePoolWithTag(PoolType, 0x24, 'SpcA');
            if (!DataBuff)
            {
                DPRINT1("ACPIGetConvertToDeviceIDWide: STATUS_INSUFFICIENT_RESOURCES\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlZeroMemory(DataBuff, 0x24);

            swprintf(DataBuff, L"%S", "ACPI\\PciBarTarget");
            goto Finish;
        }
    }

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT1("ACPIGetConvertToDeviceIDWide: InStatus %X\n", InStatus);
        return InStatus;
    }

    if (AmliData->DataType == 1)
    {
        DataLen = 0xD;

        DataBuff = ExAllocatePoolWithTag(PoolType, 0x1A, 'SpcA');
        if (!DataBuff)
        {
            DPRINT1("ACPIGetConvertToDeviceIDWide: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(DataBuff, 0x1A);

        swprintf(DataBuff, L"ACPI\\");

        ACPIAmliDoubleToNameWide((DataBuff + 5), (ULONG)AmliData->DataValue, FALSE);
        goto Finish;
    }

    if (AmliData->DataType != 2)
    {
        DPRINT1("ACPIGetConvertToDeviceIDWide: FIXME\n");
        ASSERT(FALSE);
        return STATUS_ACPI_INVALID_DATA;
    }

    String = AmliData->DataBuff;
    if (*String == '*')
        String++;

    DataLen = (strlen(String) + 6);

    DataBuff = ExAllocatePoolWithTag(PoolType, (DataLen * 2), 'SpcA');
    if (!DataBuff)
    {
        DPRINT1("ACPIGetConvertToDeviceIDWide: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(DataBuff, (DataLen * 2));

    swprintf(DataBuff, L"ACPI\\%S", String);

Finish:

    *OutDataBuff = DataBuff;

    if (OutDataLen)
        *OutDataLen = (DataLen * 2);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIGetConvertToInstanceIDWide(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA AmliData,
    _In_ ULONG GetFlags,
    _Out_ PVOID* OutDataBuff,
    _Out_ ULONG* OutDataLen)
{
    PWCHAR String;
    POOL_TYPE PoolType;
    ULONG DataLen;

    DPRINT("ACPIGetConvertToInstanceIDWide: %p\n", DeviceExtension);

    if (GetFlags & 0x10000000)
        PoolType = NonPagedPool;
    else
        PoolType = PagedPool;

    if (!(GetFlags & 0x08000000) && (DeviceExtension->Flags & 0x0001000000000000))
    {
        DataLen = (strlen(DeviceExtension->InstanceID) + 1);

        String = ExAllocatePoolWithTag(PoolType, (DataLen * 2), 'SpcA');
        if (!String)
        {
            DPRINT1("ACPIGetConvertToInstanceIDWide: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(String, (DataLen * 2));

        swprintf(String, L"%S", DeviceExtension->InstanceID);
        goto Exit;
    }

    if (!(GetFlags & 0x08000000) && (DeviceExtension->Flags & 0x0000004000000000))
    {
        DataLen = 9;

        String = ExAllocatePoolWithTag(PoolType, (DataLen * 2), 'SpcA');
        if (!String)
        {
            DPRINT1("ACPIGetConvertToInstanceIDWide: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(String, (DataLen * 2));

        swprintf(String, L"%lx", AmliData->DataValue);
        goto Exit;
    }

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT("ACPIGetConvertToInstanceIDWide: InStatus %X\n", InStatus);
        return InStatus;
    }

    if (AmliData->DataType == 1)
    {
        DataLen = 9;

        String = ExAllocatePoolWithTag(PoolType, (DataLen * 2), 'SpcA');
        if (!String)
        {
            DPRINT1("ACPIGetConvertToInstanceIDWide: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(String, (DataLen * 2));

        swprintf(String, L"%lx", AmliData->DataValue);
        goto Exit;
    }

    if (AmliData->DataType != 2)
    {
        DPRINT1("ACPIGetConvertToInstanceIDWide: FIXME\n");
        ASSERT(FALSE);
        return STATUS_ACPI_INVALID_DATA;
    }

    DataLen = (strlen(AmliData->DataBuff) + 1);

    String = ExAllocatePoolWithTag(PoolType, (DataLen * 2), 'SpcA');
    if (!String)
    {
        DPRINT1("ACPIGetConvertToInstanceIDWide: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(String, (DataLen * 2));

    swprintf(String, L"%S", AmliData->DataBuff);
    goto Exit;

Exit:

    *OutDataBuff = String;

    if (OutDataLen)
        *OutDataLen = (DataLen * 2);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIGetConvertToHardwareIDWide(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA AmliData,
    _In_ ULONG GetFlags,
    _Out_ PVOID* OutDataBuff,
    _Out_ ULONG* OutDataLen)
{
    PCHAR IdString;
    PWCHAR HardwareID;
    POOL_TYPE PoolType;
    ULONG DataBuffLen;
    ULONG DataLen;
    BOOLEAN IsAllocated = FALSE;
    NTSTATUS Status;

    DPRINT("ACPIGetConvertToHardwareIDWide: %p\n", DeviceExtension);

    if (!(GetFlags & 0x08000000) && (DeviceExtension->Flags & 0x0000001000000000))
    {
        Status = ACPIGetProcessorIDWide(DeviceExtension, InStatus, AmliData, GetFlags, (PVOID *)&HardwareID, &GetFlags);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIGetConvertToHardwareIDWide: Status %X\n", Status);
            return Status;
        }

        goto Exit;
    }

    if (GetFlags & 0x10000000)
        PoolType = NonPagedPool;
    else
        PoolType = PagedPool;

    if (!(GetFlags & 0x08000000) && (DeviceExtension->Flags & 0x0000800000000000))
    {
        DataBuffLen = (strlen(DeviceExtension->DeviceID) - 4);

        IdString = ExAllocatePoolWithTag(PoolType, DataBuffLen, 'SpcA');
        if (!IdString)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(IdString, DataBuffLen);

        IsAllocated = TRUE;

        strncpy(IdString, (DeviceExtension->DeviceID + 5), (DataBuffLen - 1));
        goto Finish;
    }

    if (!(GetFlags & 0x08000000) && DeviceExtension->Flags & 0x0000004000000000)
    {
        DataBuffLen = 0xD;

        IdString = ExAllocatePoolWithTag(PoolType, DataBuffLen, 'SpcA');
        if (!IdString)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(IdString, DataBuffLen);

        IsAllocated = TRUE;

        strncpy(IdString, "PciBarTarget", (DataBuffLen - 1));
        goto Finish;
    }

    if (!NT_SUCCESS(InStatus))
    {
        return InStatus;
    }

    if (AmliData->DataType == 1)
    {
        DataBuffLen = 0x8;

        IdString = ExAllocatePoolWithTag(PoolType, DataBuffLen, 'SpcA');
        if (!IdString)
        {
            if (IsAllocated)
                ExFreePool(IdString);

            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(IdString, DataBuffLen);
        IsAllocated = TRUE;

        ACPIAmliDoubleToName(IdString, (ULONG)AmliData->DataValue, FALSE);
        goto Finish;
    }

    if (AmliData->DataType != 2)
    {
        ASSERT(FALSE);
        return STATUS_ACPI_INVALID_DATA;
    }

    IdString = AmliData->DataBuff;

    if (*IdString == '*')
        IdString++;

    DataBuffLen = (strlen(IdString) + 1);

Finish:

    DataLen = (7 + (DataBuffLen * 2));

    HardwareID = ExAllocatePoolWithTag(PoolType, (DataLen * 2), 'SpcA');
    if (!HardwareID)
    {
        if (IsAllocated)
            ExFreePool(IdString);

        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(HardwareID, (DataLen * 2));

    swprintf(HardwareID, L"ACPI\\%S", IdString);
    swprintf(&HardwareID[DataBuffLen + 5], L"*%S", IdString);

Exit:

    *(OutDataBuff) = HardwareID;

    if (OutDataLen)
        *(OutDataLen) = (DataLen * 2);

    if (IsAllocated)
        ExFreePool(IdString);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIGetConvertToCompatibleIDWide(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA AmliData,
    _In_ ULONG GetFlags,
    _Out_ PVOID* OutDataBuff,
    _Out_ ULONG* OutDataLen)
{
    PAMLI_PACKAGE_OBJECT PackageObject;
    PWCHAR CompatibleId;
    PWCHAR Id;
    PWCHAR* OutPnpId;
    ULONG* OutPnpIdLen;
    POOL_TYPE PoolType;
    ULONG DataLen;
    ULONG Len = 0;
    ULONG Count;
    ULONG ix;
    NTSTATUS Status = InStatus;

    DPRINT("ACPIGetConvertToCompatibleIDWide: %p\n", DeviceExtension);

    if (GetFlags & 0x10000000)
        PoolType = NonPagedPool;
    else
        PoolType = PagedPool;

    if (!(GetFlags & 0x08000000) && (DeviceExtension->Flags & 0x8000000000000000))
    {
        DataLen = ((strlen(DeviceExtension->Processor.CompatibleID) + 2) * 2);

        CompatibleId = ExAllocatePoolWithTag(PoolType, DataLen, 'SpcA');
        if (!CompatibleId)
        {
            DPRINT1("ACPIGetConvertToCompatibleIDWide: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(CompatibleId, DataLen);

        swprintf(CompatibleId, L"%S", DeviceExtension->Button.SpinLock);

        *OutDataBuff = CompatibleId;

        if (OutDataLen)
            *OutDataLen = 0;

        return STATUS_SUCCESS;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT("ACPIGetConvertToCompatibleIDWide: Status %X\n", Status);
        return Status;
    }

    if (AmliData->DataType != 1 && AmliData->DataType != 2 && AmliData->DataType != 4)
    {
        DPRINT1("ACPIGetConvertToCompatibleIDWide: DataType %X\n", AmliData->DataType);
        ASSERT(FALSE);
        return STATUS_ACPI_INVALID_DATA;
    }

    if (AmliData->DataType == 1 || AmliData->DataType == 2)
    {
        Count = 1;
    }
    else if (AmliData->DataType == 4)
    {
        PackageObject = AmliData->DataBuff;
        Count = PackageObject->Elements;
    }

    OutPnpId = ExAllocatePoolWithTag(NonPagedPool, (Count * 4), 'MpcA');
    if (!OutPnpId)
    {
        DPRINT1("ACPIGetConvertToCompatibleIDWide: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(OutPnpId, (Count * 4));

    OutPnpIdLen = ExAllocatePoolWithTag(NonPagedPool, (Count * 4), 'MpcA');
    if (!OutPnpIdLen)
    {
        DPRINT1("ACPIGetConvertToCompatibleIDWide: STATUS_INSUFFICIENT_RESOURCES\n");
        ExFreePoolWithTag(OutPnpId, 'MpcA');
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(OutPnpIdLen, (Count * 4));

    if (AmliData->DataType == 1)
    {
        Status = ACPIGetConvertToPnpIDWide(DeviceExtension, InStatus, AmliData, GetFlags, (PVOID *)OutPnpId, OutPnpIdLen);
        Len = *OutPnpIdLen;
    }
    else if (AmliData->DataType == 2)
    {
        DPRINT1("ACPIGetConvertToCompatibleIDWide: FIXME\n");
        ASSERT(FALSE);
    }
    else if (AmliData->DataType == 4)
    {
        for (ix = 0; ix < Count; ix++)
        {
            if (PackageObject->Data[ix].DataType == 1)
            {
                Status = ACPIGetConvertToPnpIDWide(DeviceExtension,
                                                   Status,
                                                   &PackageObject->Data[ix],
                                                   GetFlags,
                                                   (PVOID *)&OutPnpId[ix],
                                                   &OutPnpIdLen[ix]);
            }
            else if (PackageObject->Data[ix].DataType == 2)
            {
                Status = ACPIGetConvertToStringWide(DeviceExtension,
                                                    Status,
                                                    &PackageObject->Data[ix],
                                                    GetFlags,
                                                    (PVOID *)&OutPnpId[ix],
                                                    &OutPnpIdLen[ix]);
            }

            if (!NT_SUCCESS(Status))
                break;

            if (OutPnpIdLen[ix] == 1)
                OutPnpIdLen[ix] = 0;

            Len += OutPnpIdLen[ix];
        }

        if (!NT_SUCCESS(Status))
            Count = ix;
    }

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    if (Len <= 2)
    {
        DPRINT1("ACPIGetConvertToCompatibleIDWide: STATUS_ACPI_INVALID_DATA\n");
        Status = STATUS_ACPI_INVALID_DATA;
        goto Exit;
    }

    DataLen = (Len + 2);

    CompatibleId = ExAllocatePoolWithTag(PoolType, DataLen, 'SpcA');
    if (!CompatibleId)
    {
        DPRINT1("ACPIGetConvertToCompatibleIDWide: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    RtlZeroMemory(CompatibleId, DataLen);

    Id = CompatibleId;
    for (ix = 0; ix < Count; ix++)
    {
        if (OutPnpId[ix])
            RtlCopyMemory(Id, OutPnpId[ix], OutPnpIdLen[ix]);

        Id += (OutPnpIdLen[ix] / 2);
    }

    *OutDataBuff = CompatibleId;

    if (OutDataLen)
        *OutDataLen = DataLen;

Exit:

    for (ix = 0; ix < Count; ix++)
    {
        if (OutPnpId[ix])
            ExFreePool(OutPnpId[ix]);
    }

    ExFreePoolWithTag(OutPnpIdLen, 'MpcA');
    ExFreePoolWithTag(OutPnpId, 'MpcA');

    return Status;
}

VOID
__cdecl
ACPIGetWorkerForString(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA AmliData,
    _In_ PVOID Context)
{
    PACPI_GET_CONTEXT AcpiGetContext = Context;
    PDEVICE_EXTENSION DeviceExtension;
    PAMLI_FN_ASYNC_CALLBACK CallBack;
    PVOID* OutDataBuff;
    PULONG OutDataLen;
    ULONG GetFlags;
    KIRQL Irql;
    BOOLEAN IsSuccess = FALSE;
    NTSTATUS Status;

    DPRINT("ACPIGetWorkerForString: %p\n", AcpiGetContext, AcpiGetContext->Flags);

    if (NT_SUCCESS(InStatus))
        IsSuccess = TRUE;

    ASSERT(AcpiGetContext->OutDataBuff != NULL);

    OutDataBuff = AcpiGetContext->OutDataBuff;
    if (!OutDataBuff)
    {
        DPRINT1("ACPIGetWorkerForString: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Finish;
    }

    if (AmliData->DataType == 2 && (!AmliData->DataBuff || !AmliData->DataLen))
    {
        DPRINT1("ACPIGetWorkerForString: STATUS_ACPI_INVALID_DATA\n");
        Status = STATUS_ACPI_INVALID_DATA;
        goto Finish;
    }

    OutDataLen = AcpiGetContext->OutDataLen;
    GetFlags = AcpiGetContext->Flags;
    DeviceExtension = AcpiGetContext->DeviceExtension;

    if (GetFlags & 0x10)
    {
        if (GetFlags & 0x20)
        {
            Status = ACPIGetConvertToDeviceIDWide(DeviceExtension, InStatus, AmliData, GetFlags, OutDataBuff, OutDataLen);
        }
        else if (GetFlags & 0x40)
        {
            Status = ACPIGetConvertToHardwareIDWide(DeviceExtension, InStatus, AmliData, GetFlags, OutDataBuff, OutDataLen);
        }
        else if (GetFlags & 0x80)
        {
            Status = ACPIGetConvertToInstanceIDWide(DeviceExtension, InStatus, AmliData, GetFlags, OutDataBuff, OutDataLen);
        }
        else if (GetFlags & 0x0200)
        {
            Status = ACPIGetConvertToPnpIDWide(DeviceExtension, InStatus, AmliData, GetFlags, OutDataBuff, OutDataLen);
        }
        else if (GetFlags & 0x0100)
        {
            Status = ACPIGetConvertToCompatibleIDWide(DeviceExtension, InStatus, AmliData, GetFlags, OutDataBuff, OutDataLen);
        }
        else if (GetFlags & 0x2000)
        {
            DPRINT1("ACPIGetWorkerForString: FIXME\n");
            ASSERT(FALSE);
        }
        else
        {
            DPRINT1("ACPIGetWorkerForString: FIXME\n");
            ASSERT(FALSE);
        }
    }
    else if (GetFlags & 0x20)
    {
        Status = ACPIGetConvertToDeviceID(DeviceExtension, InStatus, AmliData, GetFlags, OutDataBuff, OutDataLen);
    }
    else if (GetFlags & 0x40)
    {
        DPRINT1("ACPIGetWorkerForString: FIXME\n");
        ASSERT(FALSE);
    }
    else if (GetFlags & 0x80)
    {
        Status = ACPIGetConvertToInstanceID(DeviceExtension, InStatus, AmliData, GetFlags, OutDataBuff, OutDataLen);
    }
    else if (GetFlags & 0x0200)
    {
        Status = ACPIGetConvertToPnpID(DeviceExtension, InStatus, AmliData, GetFlags, OutDataBuff, OutDataLen);
    }
    else if (GetFlags & 0x0100)
    {
        Status = ACPIGetConvertToCompatibleID(DeviceExtension, InStatus, AmliData, GetFlags, OutDataBuff, OutDataLen);
    }
    else
    {
        DPRINT1("ACPIGetWorkerForString: FIXME\n");
        ASSERT(FALSE);
    }

Finish:

    AcpiGetContext->Status = Status;

    if (IsSuccess)
        AMLIFreeDataBuffs(AmliData, 1);

    if (GetFlags & 0x20000000)
        return;

    if (AcpiGetContext->CallBack)
    {
        CallBack = AcpiGetContext->CallBack;
        CallBack(NsObject, Status, NULL, AcpiGetContext->CallBackContext);
    }

    KeAcquireSpinLock(&AcpiGetLock, &Irql);
    RemoveEntryList(&AcpiGetContext->List);
    KeReleaseSpinLock(&AcpiGetLock, Irql);

    ExFreePool(AcpiGetContext);
}

VOID
__cdecl
ACPIGetWorkerForBuffer(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA AmliData,
    _In_ PVOID Context)
{
    PACPI_GET_CONTEXT AcpiGetContext = Context;
    PAMLI_FN_ASYNC_CALLBACK CallBack;
    PVOID DataBuff;
    POOL_TYPE PoolType;
    KIRQL Irql;
    BOOLEAN IsSuccess = TRUE;

    DPRINT("ACPIGetWorkerForBuffer: %p, %X\n", AcpiGetContext, AcpiGetContext->Flags);

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT("ACPIGetWorkerForBuffer: InStatus %X\n", InStatus);
        IsSuccess = FALSE;
        goto Exit;
    }

    if (AmliData->DataType != 3)
    {
        DPRINT1("ACPIGetWorkerForBuffer: AmliData %p, DataType %X\n", AmliData, AmliData->DataType);
        ASSERT(FALSE);

        if (AcpiGetContext->Flags & 0x80000000)
        {
            DPRINT1("ACPIGetWorkerForBuffer: FIXME\n");
            ASSERT(FALSE);
            //ACPIInternalError(..);
        }

        InStatus = STATUS_ACPI_INVALID_DATA;
        goto Exit;
    }

    if (!AmliData->DataLen)
    {
        DPRINT1("ACPIGetWorkerForBuffer: AmliData %p, DataType %X\n", AmliData, AmliData->DataType);
        ASSERT(FALSE);
        InStatus = STATUS_ACPI_INVALID_DATA;
        goto Exit;
    }

    if (AcpiGetContext->Flags & 0x10000000)
        PoolType = NonPagedPool;
    else
        PoolType = PagedPool;

    DataBuff = ExAllocatePoolWithTag(PoolType, AmliData->DataLen, 'BpcA');
    if (!DataBuff)
    {
        DPRINT1("ACPIGetWorkerForBuffer: InStatus %X\n", InStatus);
        InStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    RtlCopyMemory(DataBuff, AmliData->DataBuff, AmliData->DataLen);

    if (AcpiGetContext->OutDataBuff)
    {
        *(AcpiGetContext->OutDataBuff) = DataBuff;

        if (AcpiGetContext->OutDataLen)
            *(AcpiGetContext->OutDataLen) = AmliData->DataLen;
    }

Exit:

    AcpiGetContext->Status = InStatus;

    if (IsSuccess)
        AMLIFreeDataBuffs(AmliData, 1);

    if (AcpiGetContext->Flags & 0x20000000)
        return;

    if (AcpiGetContext->CallBack)
    {
        CallBack = AcpiGetContext->CallBack;
        CallBack(NsObject, InStatus, NULL, AcpiGetContext->CallBackContext);
    }

    KeAcquireSpinLock(&AcpiGetLock, &Irql);
    RemoveEntryList(&AcpiGetContext->List);
    KeReleaseSpinLock(&AcpiGetLock, Irql);

    ExFreePool(AcpiGetContext);
}

VOID
__cdecl
ACPIGetWorkerForData(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA AmliData,
    _In_ PVOID Context)
{
    PACPI_GET_CONTEXT AcpiGetContext = Context;
    BOOLEAN IsFreeBuffs;
    KIRQL Irql;

    DPRINT("ACPIGetWorkerForData: %p, %X\n", AcpiGetContext, AcpiGetContext->Flags);

    if (NT_SUCCESS(InStatus))
        IsFreeBuffs = TRUE;
    else
        IsFreeBuffs = FALSE;

    ASSERT(AcpiGetContext->OutDataBuff);

    if (!AcpiGetContext->OutDataBuff)
    {
        DPRINT1("ACPIGetWorkerForData: STATUS_INSUFFICIENT_RESOURCES\n");
        InStatus = STATUS_INSUFFICIENT_RESOURCES;
    }

    if (NT_SUCCESS(InStatus))
    {
        RtlCopyMemory(AcpiGetContext->OutDataBuff, AmliData, sizeof(AMLI_OBJECT_DATA));
        RtlZeroMemory(AmliData, sizeof(*AmliData));

        IsFreeBuffs = FALSE;
    }

    AcpiGetContext->Status = InStatus;

    if (IsFreeBuffs)
        AMLIFreeDataBuffs(AmliData, 1);

    if (AcpiGetContext->Flags & 0x20000000)
        return;

    if (AcpiGetContext->CallBack)
    {
        DPRINT1("ACPIGetWorkerForData: FIXME\n");
        ASSERT(FALSE);
    }

    KeAcquireSpinLock(&AcpiGetLock, &Irql);
    RemoveEntryList(&AcpiGetContext->List);
    KeReleaseSpinLock(&AcpiGetLock, Irql);

    ExFreePool(AcpiGetContext);
}

VOID
__cdecl
ACPIGetWorkerForNothing(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA AmliData,
    _In_ PVOID Context)
{
    PACPI_GET_CONTEXT AcpiGetContext = Context;
    PAMLI_FN_ASYNC_CALLBACK CallBack;
    BOOLEAN IsFreeBuffs;
    KIRQL Irql;

    DPRINT("ACPIGetWorkerForNothing: %p, %X\n", AcpiGetContext, AcpiGetContext->Flags);

    if (NT_SUCCESS(InStatus))
        IsFreeBuffs = TRUE;
    else
        IsFreeBuffs = FALSE;

    AcpiGetContext->Status = InStatus;

    if (IsFreeBuffs)
        AMLIFreeDataBuffs(AmliData, 1);

    if (AcpiGetContext->Flags & 0x20000000)
        return;

    if (AcpiGetContext->CallBack)
    {
        CallBack = AcpiGetContext->CallBack;
        CallBack(NsObject, InStatus, NULL, AcpiGetContext->CallBackContext);
    }

    KeAcquireSpinLock(&AcpiGetLock, &Irql);
    RemoveEntryList(&AcpiGetContext->List);
    KeReleaseSpinLock(&AcpiGetLock, Irql);

    ExFreePool(AcpiGetContext);
}

NTSTATUS
NTAPI
ACPIGet(
    _In_ PVOID Context,
    _In_ ULONG NameSeg,
    _In_ ULONG Flags,
    _In_ PVOID SimpleArgumentBuff,
    _In_ ULONG SimpleArgumentSize,
    _In_ PVOID CallBack,
    _In_ PVOID CallBackContext,
    _Out_ PVOID* OutDataBuff,
    _Out_ ULONG* OutDataLen)
{
    PDEVICE_EXTENSION DeviceExtension;
    PAMLI_NAME_SPACE_OBJECT NsObject;
    PACPI_GET_CONTEXT AcpiGetContext;
    PAMLI_OBJECT_DATA DataArgs = NULL;
    PAMLI_FN_ASYNC_CALLBACK Worker;
    AMLI_OBJECT_DATA Argument = {0};
    ULONG ArgsCount = 0;
    BOOLEAN IsAsyncEval;
    BOOLEAN IsFlag8000000;
    KIRQL OldIrql;
    NTSTATUS Status;

    DPRINT("ACPIGet: %p, %X, %X, %X, %X, %X, %X\n", Context, NameSeg, Flags, SimpleArgumentBuff, SimpleArgumentSize, CallBack, CallBackContext);

    IsAsyncEval = ((Flags & 0x40000000) != 0);
    IsFlag8000000 = ((Flags & 0x8000000) != 0);

    if (!IsFlag8000000)
    {
        DeviceExtension = Context;
        NsObject = DeviceExtension->AcpiObject;
    }
    else
    {
        DeviceExtension = NULL;
        NsObject = Context;
    }

    if ((Flags & 0x1F0000) == 0x10000)
    {
        Worker = ACPIGetWorkerForBuffer;
    }
    else if ((Flags & 0x1F0000) == 0x20000)
    {
        Worker = ACPIGetWorkerForData;
    }
    else if ((Flags & 0x1F0000) == 0x40000)
    {
        Worker = ACPIGetWorkerForInteger;

        if ((Flags & 0x800) && !IsFlag8000000 && (DeviceExtension->Flags & 0x0200000000000000))
        {
            ASSERT(DeviceExtension->Dock.CorrospondingAcpiDevice);
            NsObject = DeviceExtension->Dock.CorrospondingAcpiDevice->AcpiObject;
        }
    }
    else if ((Flags & 0x1F0000) == 0x80000)
    {
        Worker = ACPIGetWorkerForString;
    }
    else if ((Flags & 0x1F0000) == 0x100000)
    {
        Worker = ACPIGetWorkerForNothing;
    }
    else
    {
        DPRINT1("ACPIGet: STATUS_INVALID_PARAMETER_3\n");
        return STATUS_INVALID_PARAMETER_3;
    }

    if (Flags & 0x7000000)
    {
        ASSERT(SimpleArgumentSize != 0);

        if (Flags & 0x1000000)
        {
            Argument.DataType = 1;
            Argument.DataValue = SimpleArgumentBuff;
        }
        else
        {
            if (Flags & 0x2000000)
            {
                Argument.DataType = 2;
            }
            else
            {
                if (!(Flags & 0x4000000))
                {
                    DPRINT1("ACPIGet: FIXME\n");
                    ASSERT(FALSE);
                }

                Argument.DataType = 3;
            }

            Argument.DataLen = SimpleArgumentSize;
            Argument.DataBuff = SimpleArgumentBuff;
        }

        ArgsCount = 1;
        DataArgs = &Argument;
    }

    AcpiGetContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(*AcpiGetContext), 'MpcA');
    if (!AcpiGetContext)
    {
        DPRINT1("ACPIGet: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(AcpiGetContext, sizeof(*AcpiGetContext));

    AcpiGetContext->DeviceExtension = DeviceExtension;
    AcpiGetContext->NsObject = NsObject;
    AcpiGetContext->NameSeg = NameSeg;
    AcpiGetContext->Flags = Flags;
    AcpiGetContext->CallBack = CallBack;
    AcpiGetContext->CallBackContext = CallBackContext;
    AcpiGetContext->OutDataBuff = OutDataBuff;
    AcpiGetContext->OutDataLen = OutDataLen;

    KeAcquireSpinLock(&AcpiGetLock, &OldIrql);
    InsertTailList(&AcpiGetListEntry, &AcpiGetContext->List);
    KeReleaseSpinLock(&AcpiGetLock, OldIrql);

    if (!IsFlag8000000 &&
        (DeviceExtension->Flags & 0x0008000000000000) &&
        !(DeviceExtension->Flags & 0x0200000000000000))
    {
        DPRINT("ACPIGet: STATUS_OBJECT_NAME_NOT_FOUND\n");
        Status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto Finish;
    }

    NsObject = ACPIAmliGetNamedChild(NsObject, NameSeg);
    if (!NsObject)
    {
        DPRINT("ACPIGet: STATUS_OBJECT_NAME_NOT_FOUND\n");
        Status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto Finish;
    }

    if (IsAsyncEval)
    {
        Status = AMLIAsyncEvalObject(NsObject,
                                     &AcpiGetContext->DataResult,
                                     ArgsCount,
                                     DataArgs,
                                     Worker,
                                     AcpiGetContext);
        if (Status == STATUS_PENDING)
            return STATUS_PENDING;
    }
    else
    {
        Status = AMLIEvalNameSpaceObject(NsObject, &AcpiGetContext->DataResult, ArgsCount, DataArgs);
    }

Finish:

    AcpiGetContext->Flags |= 0x20000000;

    Worker(NsObject, Status, &AcpiGetContext->DataResult, AcpiGetContext);

    Status = AcpiGetContext->Status;

    KeAcquireSpinLock(&AcpiGetLock, &OldIrql);
    RemoveEntryList(&AcpiGetContext->List);
    KeReleaseSpinLock(&AcpiGetLock, OldIrql);

    ExFreePoolWithTag(AcpiGetContext, 'MpcA');

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildProcessRunMethodPhaseCheckSta(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ACPIBuildProcessRunMethodPhaseCheckSta: %p\n", BuildRequest);

    DeviceExtension = BuildRequest->Context;
    BuildRequest->BuildReserved1 = 4;

    if (DeviceExtension->Flags & 0x0008000000000000)
    {
        BuildRequest->BuildReserved1 = 0;
        ACPIBuildCompleteMustSucceed(NULL, Status, 0, BuildRequest);
        return Status;
    }

    if (!(BuildRequest->RunMethod.Flags & 1))
    {
        ACPIBuildCompleteMustSucceed(NULL, Status, 0, BuildRequest);
        return Status;
    }

    Status = ACPIGet(DeviceExtension,
                     'ATS_',
                     0x40040802,
                     NULL,
                     0,
                     ACPIBuildCompleteMustSucceed,
                     BuildRequest,
                     (PVOID *)&BuildRequest->ListHeadForInsert,
                     NULL);


    if (Status != STATUS_PENDING)
        ACPIBuildCompleteMustSucceed(NULL, Status, 0, BuildRequest);

    DPRINT("ACPIBuildProcessRunMethodPhaseCheckSta: ret Status %X\n", Status);

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildProcessRunMethodPhaseCheckBridge(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension = BuildRequest->Context;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ACPIBuildProcessRunMethodPhaseCheckBridge: %p\n", BuildRequest);

    if ((BuildRequest->RunMethod.Flags & 1) && (DeviceExtension->Flags & 2))
    {
        BuildRequest->BuildReserved1 = 0;
        goto Finish;
    }

    BuildRequest->BuildReserved1 = 5;

    if (!(BuildRequest->RunMethod.Flags & 0x40))
        goto Finish;

    BuildRequest->DataBuff = NULL;

    Status = IsPciBusAsync(DeviceExtension->AcpiObject,
                           ACPIBuildCompleteMustSucceed,
                           BuildRequest,
                           (BOOLEAN *)&BuildRequest->DataBuff);

    DPRINT("ACPIBuildProcessRunMethodPhaseCheckBridge: Status %X\n", Status);

    if (Status == 0x103)
        return Status;

Finish:

    ACPIBuildCompleteMustSucceed(NULL, Status, 0, BuildRequest);
    return Status;
}

NTSTATUS
NTAPI
ACPIBuildProcessRunMethodPhaseRunMethod(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension = BuildRequest->Context;
    PAMLI_NAME_SPACE_OBJECT NsObject = NULL;
    AMLI_OBJECT_DATA amliData[2];
    PAMLI_OBJECT_DATA AmliData = NULL;
    ULONG ArgsCount = 0;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ACPIBuildProcessRunMethodPhaseRunMethod: %p\n", BuildRequest);

    if (!((BuildRequest->RunMethod.Flags & 0x40) == 0) && BuildRequest->DataBuff)
    {
        DPRINT("ACPIBuildProcessRunMethodPhaseRunMethod: Is PCI-PCI bridge\n");
        BuildRequest->BuildReserved1 = 0;
        goto Exit;
    }

    BuildRequest->BuildReserved1 = 6;

    NsObject = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, (ULONG)BuildRequest->RunMethod.Context);//?
    if (!NsObject)
    {
        goto Exit;
    }

    if (BuildRequest->RunMethod.Flags & 2)
    {
        if ((ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0020000000000000, FALSE) >> 0x20) & 0x200000)
            goto Exit;
    }

    else if (BuildRequest->RunMethod.Flags & 8)
    {
        if (!DeviceExtension->PowerInfo.WakeSupportCount)
            goto Exit;

        RtlZeroMemory(amliData, sizeof(AMLI_OBJECT_DATA));

        amliData[0].DataType = 1;
        amliData[0].DataValue = ULongToPtr(1);

        AmliData = amliData;
        ArgsCount = 1;
    }
    else if (BuildRequest->RunMethod.Flags & 0x30)
    {
        BuildRequest->RunMethod.Flags |= 0x40;

        RtlZeroMemory(amliData, sizeof(amliData));

        amliData[0].DataType = 1;
        amliData[0].DataValue = (PVOID)2;

        amliData[1].DataType = 1;
        amliData[1].DataValue = (((BuildRequest->RunMethod.Flags & 0x10) == 0x10) ? (PVOID)1 : (PVOID)0);

        AmliData = amliData;
        ArgsCount = 2;
    }

    BuildRequest->ChildObject = NsObject;

    Status = AMLIAsyncEvalObject(NsObject, NULL, ArgsCount, AmliData, (PVOID)ACPIBuildCompleteMustSucceed, BuildRequest);

Exit:

    if (Status == STATUS_PENDING)
        Status = STATUS_SUCCESS;
    else
        ACPIBuildCompleteMustSucceed(NsObject, Status, 0, BuildRequest);

    DPRINT("ACPIBuildProcessRunMethodPhaseRunMethod: retStatus %X\n", Status);

    return Status;
}

BOOLEAN
NTAPI
ACPIExtListIsFinished(
    _In_ PACPI_EXT_LIST_ENUM_DATA ExtList)
{
    BOOLEAN Result;

    if (Add2Ptr(ExtList->DeviceExtension, ExtList->Offset) == ExtList->List)
        Result = TRUE;
    else
        Result = FALSE;

    return Result;
}

PDEVICE_EXTENSION
__cdecl
ACPIExtListStartEnum(
    _In_ PACPI_EXT_LIST_ENUM_DATA ExtList)
{
    if (ExtList->ExtListEnum2)
        KeAcquireSpinLock(ExtList->SpinLock, &ExtList->Irql);

    ExtList->DeviceExtension = (PDEVICE_EXTENSION)((ULONG_PTR)ExtList->List->Flink - ExtList->Offset);

    if (ACPIExtListIsFinished(ExtList))
        return NULL ;

    return ExtList->DeviceExtension;
}

BOOLEAN
__cdecl
ACPIExtListTestElement(
    _In_ PACPI_EXT_LIST_ENUM_DATA ExtList,
    _In_ BOOLEAN IsParam2)
{
    BOOLEAN Result;

    if (ACPIExtListIsFinished(ExtList) || !IsParam2)
    {
        if (ExtList->ExtListEnum2)
            KeReleaseSpinLock(ExtList->SpinLock, ExtList->Irql);

        Result = FALSE;
    }
    else
    {
        if (ExtList->ExtListEnum2 == 1)
        {
            InterlockedIncrement(&ExtList->DeviceExtension->ReferenceCount);
            KeReleaseSpinLock(ExtList->SpinLock, ExtList->Irql);
        }

        Result = TRUE;
    }

    return Result;
}

VOID
NTAPI
ACPIInitDeleteDeviceExtension(
    _In_ PDEVICE_EXTENSION DeviceExtension)
{
    UNIMPLEMENTED_DBGBREAK();
}

PDEVICE_EXTENSION
__cdecl
ACPIExtListEnumNext(
    _In_ PACPI_EXT_LIST_ENUM_DATA ExtList)
{
    PLIST_ENTRY List;
    LONG RefCount;
    KIRQL OldIrql;
    BOOLEAN Result;

    //DPRINT("ACPIExtListEnumNext: %p\n", ExtList);

    if (ExtList->ExtListEnum2 != 1)
    {
        List = Add2Ptr(ExtList->DeviceExtension, ExtList->Offset);
        ExtList->DeviceExtension = (PDEVICE_EXTENSION)((ULONG_PTR)List->Flink - ExtList->Offset);

        Result = ACPIExtListIsFinished(ExtList);

        return (Result ? NULL : ExtList->DeviceExtension);
    }

    KeAcquireSpinLock(ExtList->SpinLock, &OldIrql);
    ExtList->Irql = OldIrql;

    RefCount = InterlockedDecrement(&ExtList->DeviceExtension->ReferenceCount);

    ASSERT(!ACPIExtListIsFinished(ExtList));

    List = Add2Ptr(ExtList->DeviceExtension, ExtList->Offset);
    ExtList->DeviceExtension = (PDEVICE_EXTENSION)((ULONG_PTR)List->Flink - ExtList->Offset);

    if (!RefCount)
        ACPIInitDeleteDeviceExtension(ExtList->DeviceExtension);

    Result = ACPIExtListIsFinished(ExtList);

    return (Result ? NULL : ExtList->DeviceExtension);
}

NTSTATUS
NTAPI
ACPIBuildProcessRunMethodPhaseRecurse(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension;
    ACPI_EXT_LIST_ENUM_DATA ExtList;
    BOOLEAN Result;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ACPIBuildProcessRunMethodPhaseRecurse: %p\n", BuildRequest);

    BuildRequest->BuildReserved1 = 0;

    if (!(BuildRequest->RunMethod.Flags & 4))
        goto Finish;

    ExtList.List = &(((PDEVICE_EXTENSION)BuildRequest->Context)->ChildDeviceList);
    ExtList.SpinLock = &AcpiDeviceTreeLock;
    ExtList.Offset = FIELD_OFFSET(DEVICE_EXTENSION, SiblingDeviceList);
    ExtList.ExtListEnum2 = 2;

    DeviceExtension = ACPIExtListStartEnum(&ExtList);

    for (Result = ACPIExtListTestElement(&ExtList, TRUE);
         Result;
         Result = ACPIExtListTestElement(&ExtList, NT_SUCCESS(Status)))
    {
        Status = ACPIBuildRunMethodRequest(DeviceExtension,
                                           NULL,
                                           NULL,
                                           BuildRequest->RunMethod.Context,
                                           BuildRequest->RunMethod.Flags,
                                           FALSE);

        DeviceExtension = ACPIExtListEnumNext(&ExtList);
    }

Finish:

    ACPIBuildCompleteMustSucceed(NULL, Status, 0, BuildRequest);

    DPRINT("ACPIBuildProcessRunMethodPhaseRecurse: ret Status %X\n", Status);

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildProcessDeviceFailure(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIBuildProcessDevicePhaseAdrOrHid(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension = BuildRequest->Context;
    PAMLI_NAME_SPACE_OBJECT ChildObject;
    PAMLI_NAME_SPACE_OBJECT HidChild;
    PAMLI_NAME_SPACE_OBJECT AdrChild;
    PAMLI_NAME_SPACE_OBJECT UidChild;
    PVOID CallBack;
    PCHAR* IdString;
    ULONG NameSeg;
    ULONG Flags;
    NTSTATUS Status;

    DPRINT("ACPIBuildProcessDevicePhaseAdrOrHid: %p\n", BuildRequest);

    HidChild = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, 'DIH_');
    if (!HidChild)
    {
        ChildObject = AdrChild = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, 'RDA_');

        if (!AdrChild)
        {
            DPRINT("ACPIBuildProcessDevicePhaseAdrOrHid: KeBugCheckEx(..)\n");
            ASSERT(FALSE);
            KeBugCheckEx(0xA5, 0xD, (ULONG_PTR)DeviceExtension, 'RDA_', 0);
        }

        NameSeg = 'RDA_';
        Flags = 0x40040402;
        IdString = &DeviceExtension->DeviceID;
        CallBack = ACPIBuildCompleteMustSucceed;

        BuildRequest->BuildReserved1 = 4;
        BuildRequest->ChildObject = AdrChild;

        goto Finish;
    }

    ChildObject = UidChild = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, 'DIU_');
    if (UidChild)
    {
        NameSeg = 'DIU_';
        Flags = 0x50080086;
        IdString = &DeviceExtension->InstanceID;
        CallBack = ACPIBuildCompleteMustSucceed;

        BuildRequest->BuildReserved1 = 6;
        BuildRequest->ChildObject = UidChild;

        goto Finish;
    }

    NameSeg = 'DIH_';
    Flags = 0x50080026;
    IdString = &DeviceExtension->DeviceID;
    CallBack = ACPIBuildCompleteMustSucceed;

    BuildRequest->BuildReserved1 = 5;
    BuildRequest->ChildObject = HidChild;

Finish:

    Status = ACPIGet(DeviceExtension, NameSeg, Flags, NULL, 0, CallBack, BuildRequest, (PVOID *)IdString, NULL);

    if (Status == STATUS_PENDING)
        Status = STATUS_SUCCESS;
    else
        ACPIBuildCompleteMustSucceed(ChildObject, Status, 0, BuildRequest);

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildProcessDevicePhaseAdr(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status;

    DeviceExtension = BuildRequest->Context;

    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0000100000000000, FALSE);
    BuildRequest->BuildReserved1 = 8;

    Status = ACPIGet(DeviceExtension,
                     'ATS_',
                     0x40040802,
                     NULL,
                     0,
                     ACPIBuildCompleteMustSucceed,
                     BuildRequest,
                     (PVOID *)&BuildRequest->ListHeadForInsert,
                     NULL);

    DPRINT("ACPIBuildProcessDevicePhaseAdr: Status %X\n", Status);

    if (Status == STATUS_PENDING)
        Status = STATUS_SUCCESS;
    else
        ACPIBuildCompleteMustSucceed(NULL, Status, 0, BuildRequest);

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildProcessDevicePhaseHid(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PAMLI_NAME_SPACE_OBJECT NsObject = NULL;
    PDEVICE_EXTENSION DeviceExtension;
    ULONG Flags;
    ULONG NameSeg;
    ULONG ix;
    BOOLEAN IsMatch = FALSE;
    NTSTATUS Status = STATUS_SUCCESS;

    DeviceExtension = BuildRequest->Context;

    for (ix = 0; AcpiInternalDeviceFlagTable[ix].StringId; ix++)
    {
        if (strstr(DeviceExtension->DeviceID, AcpiInternalDeviceFlagTable[ix].StringId))
        {
            ACPIInternalUpdateFlags(&DeviceExtension->Flags, AcpiInternalDeviceFlagTable[ix].Flags, FALSE);
            IsMatch = TRUE;
            break;
        }
    }

    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0000200000000000, FALSE);

    NsObject = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, 'DIC_');
    if (!NsObject || IsMatch)
    {
        NameSeg = 'ATS_';
        BuildRequest->BuildReserved1 = 8;
        Flags = 0x40040802;
    }
    else
    {
        NameSeg = 'DIC_';
        BuildRequest->BuildReserved1 = 7;
        Flags = 0x50080107;
    }

    Status = ACPIGet(DeviceExtension, NameSeg, Flags, NULL, 0, ACPIBuildCompleteMustSucceed, BuildRequest, &BuildRequest->DataBuff, NULL);
    if (Status == STATUS_PENDING)
        return STATUS_SUCCESS;

    ACPIBuildCompleteMustSucceed(NsObject, Status, 0, BuildRequest);

    DPRINT("ACPIBuildProcessDevicePhaseHid: Status %X\n", Status);

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildProcessDevicePhaseUid(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension;
    PAMLI_NAME_SPACE_OBJECT NsChild;
    NTSTATUS Status;

    DeviceExtension = BuildRequest->Context;

    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0000400000000000, FALSE);

    NsChild = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, 'DIH_');
    if (!NsChild)
    {
        DPRINT1("ACPIBuildProcessDevicePhaseUid: KeBugCheckEx()\n");
        ASSERT(FALSE);
        KeBugCheckEx(0xA5, 0xD, (ULONG_PTR)DeviceExtension, 'DIH_', 0);
    }

    BuildRequest->BuildReserved1 = 5;

    Status = ACPIGet(DeviceExtension,
                     'DIH_',
                     0x50080026,
                     NULL,
                     0,
                     ACPIBuildCompleteMustSucceed,
                     BuildRequest,
                     (PVOID *)&DeviceExtension->DeviceID,
                     NULL);

    DPRINT("ACPIBuildProcessDevicePhaseUid: Status %X\n", Status);

    if (Status == STATUS_PENDING)
        Status = STATUS_SUCCESS;
    else
        ACPIBuildCompleteMustSucceed(NsChild, Status, 0, BuildRequest);

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildProcessDevicePhaseCid(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension;
    PCHAR Cid;
    ULONG ix;
    NTSTATUS Status = STATUS_SUCCESS;

    DeviceExtension = BuildRequest->Context;

    for (Cid = BuildRequest->DataBuff; Cid && *Cid; )
    {
        Cid += strlen(Cid);

        if (!Cid[1])
            break;

        *Cid = ' ';
    }

    Cid = BuildRequest->DataBuff;

    for (ix = 0; AcpiInternalDeviceFlagTable[ix].StringId; ix++)
    {
        if (strstr(Cid, AcpiInternalDeviceFlagTable[ix].StringId))
        {
            ACPIInternalUpdateFlags(&DeviceExtension->Flags, AcpiInternalDeviceFlagTable[ix].Flags, FALSE);
            break;
        }
    }

    if (Cid)
        ExFreePool(Cid);

    BuildRequest->BuildReserved1 = 8;

    Status = ACPIGet(DeviceExtension,
                     'ATS_',
                     0x40040802,
                     NULL,
                     0,
                     ACPIBuildCompleteMustSucceed,
                     BuildRequest,
                     &BuildRequest->DataBuff,
                     NULL);

    DPRINT("ACPIBuildProcessDevicePhaseCid: Status %X\n", Status);

    if (Status != STATUS_PENDING)
    {
        ACPIBuildCompleteMustSucceed(NULL, Status, 0, BuildRequest);
        return Status;
    }

    return STATUS_SUCCESS;
}

VOID
__cdecl
ACPIExtListExitEnumEarly(
    _In_ PACPI_EXT_LIST_ENUM_DATA ExtList)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
ACPIDetectDuplicateHID(
    _In_ PDEVICE_EXTENSION DeviceExtension)
{
    PDEVICE_EXTENSION Extension;
    ACPI_EXT_LIST_ENUM_DATA ExtList;

    DPRINT("ACPIDetectDuplicateHID: DeviceExtension %X\n", DeviceExtension);

    if (!DeviceExtension->ParentExtension)
        return;

    if ((DeviceExtension->Flags & 0x0000000000000001) ||
        (DeviceExtension->Flags & 0x0002000000000002) ||
        !(DeviceExtension->Flags & 0x0000A00000000000))
    {
        return;
    }

    ExtList.List = &DeviceExtension->ParentExtension->ChildDeviceList;
    ExtList.Offset = FIELD_OFFSET(DEVICE_EXTENSION, SiblingDeviceList);
    ExtList.SpinLock = &AcpiDeviceTreeLock;
    ExtList.ExtListEnum2 = 2;

    Extension = ACPIExtListStartEnum(&ExtList);

    while (ACPIExtListTestElement(&ExtList, TRUE))
    {
        if (!Extension)
        {
            ACPIExtListExitEnumEarly(&ExtList);
            return;
        }

        if (Extension == DeviceExtension)
            goto Next;

        if ((Extension->Flags & 0x0000000000000001) ||
            (Extension->Flags & 0x0002000000000002) ||
            (Extension->Flags & 0x0000080000000000) ||
            !(Extension->Flags & 0x0000A00000000000))
        {
            goto Next;
        }

        if (!strstr(Extension->DeviceID, DeviceExtension->DeviceID))
            goto Next;

        if (!(Extension->Flags & 0x0001400000000000) || !(DeviceExtension->Flags & 0x0001400000000000))
        {
            DPRINT1("ACPIDetectDuplicateHID: matches with %X\n", Extension);
            ASSERT(FALSE);
            KeBugCheckEx(0xA5, 0xD, (ULONG_PTR)DeviceExtension, 'DIU_', 0);
        }

        if (!strcmp(Extension->InstanceID, DeviceExtension->InstanceID))
        {
            DPRINT1("ACPIDetectDuplicateHID: has _UID match with %X\n\t\tContact the Machine Vendor to get this problem fixed\n", Extension);
            ASSERT(FALSE);
            KeBugCheckEx(0xA5, 0xD, (ULONG_PTR)DeviceExtension, 'DIU_', 1);
        }

Next:
        Extension = ACPIExtListEnumNext(&ExtList);
    }
}

NTSTATUS
NTAPI
ACPIBuildProcessDevicePhaseSta(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension;

    DPRINT("ACPIBuildProcessDevicePhaseSta: BuildRequest %X\n", BuildRequest);

    DeviceExtension = BuildRequest->Context;
    BuildRequest->BuildReserved1 = 9;

    ACPIDetectDuplicateHID(DeviceExtension);
    ACPIBuildCompleteMustSucceed(NULL, STATUS_SUCCESS, 0, BuildRequest);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIBuildProcessDeviceGenericEvalStrict(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension;
    PAMLI_NAME_SPACE_OBJECT ChildObject;
    ULONG NameSeg;
    ULONG Idx;
    NTSTATUS Status;

    DPRINT("ACPIBuildProcessDeviceGenericEvalStrict: BuildRequest %X\n", BuildRequest);

    DeviceExtension = BuildRequest->Context;

    RtlZeroMemory(&BuildRequest->Device.Data, sizeof(BuildRequest->Device.Data));

    Idx = BuildRequest->BuildReserved0;
    NameSeg = AcpiBuildDevicePowerNameLookup[Idx];
    BuildRequest->BuildReserved1 = (Idx + 1);

    ChildObject = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, NameSeg);
    BuildRequest->ChildObject = ChildObject;

    if (ChildObject)
    {
        Status = AMLIAsyncEvalObject(ChildObject,
                                     &BuildRequest->Device.Data,
                                     0,
                                     NULL,
                                     (PVOID)ACPIBuildCompleteMustSucceed,
                                     BuildRequest);
    }
    else
    {
        Status = STATUS_SUCCESS;
    }

    DPRINT("ACPIBuildProcessDeviceGenericEvalStrict: Phase%X, Status %X\n", (BuildRequest->BuildReserved0 - 3), Status);

    if (Status != STATUS_PENDING)
    {
        ACPIBuildCompleteMustSucceed(BuildRequest->ChildObject,
                                     Status,
                                     (ULONG)&BuildRequest->Device.Data,
                                     BuildRequest);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIDockGetDockObject(
    _In_ PAMLI_NAME_SPACE_OBJECT ScopeObject,
    _Out_ PAMLI_NAME_SPACE_OBJECT* OutNsObject)
{
    return AMLIGetNameSpaceObject("_DCK", ScopeObject, OutNsObject, 1);
}

BOOLEAN
NTAPI
ACPIDockIsDockDevice(
    _In_ PAMLI_NAME_SPACE_OBJECT AcpiObject)
{
    PAMLI_NAME_SPACE_OBJECT dummy;

    if (NT_SUCCESS(ACPIDockGetDockObject(AcpiObject, &dummy)))
    {
        return TRUE;
    }

    return FALSE;
}

PDEVICE_EXTENSION
NTAPI
ACPIDockFindCorrespondingDock(
    _In_ PDEVICE_EXTENSION DeviceExtension)
{
    PDEVICE_EXTENSION DockExtension;
    ACPI_EXT_LIST_ENUM_DATA ExtList;

    DPRINT("ACPIDockFindCorrespondingDock: %p\n", DeviceExtension);

    ExtList.List = &RootDeviceExtension->ChildDeviceList;
    ExtList.SpinLock = &AcpiDeviceTreeLock;
    ExtList.Offset = FIELD_OFFSET(DEVICE_EXTENSION, SiblingDeviceList);
    ExtList.ExtListEnum2 = 2;

    DockExtension = ACPIExtListStartEnum(&ExtList);

    while (ACPIExtListTestElement(&ExtList, 1))
    {
        if (!DockExtension)
        {
            ACPIExtListExitEnumEarly(&ExtList);
            break;
        }

        if ((DockExtension->Flags & 0x0200000000000000) &&
            DockExtension->Dock.CorrospondingAcpiDevice == DeviceExtension)
        {
            ACPIExtListExitEnumEarly(&ExtList);
            break;
        }

        DockExtension = ACPIExtListEnumNext(&ExtList);
    }

    return DockExtension;
}

NTSTATUS
NTAPI
ACPIAmliBuildObjectPathname(
    _In_ PAMLI_NAME_SPACE_OBJECT PathNsObject,
    _Out_ PCHAR* OutInstanceID)
{
    PAMLI_NAME_SPACE_OBJECT ParentNsObject;
    PAMLI_NAME_SPACE_OBJECT NsObject;
    PCHAR InstanceID;
    ULONG Count;
    ULONG ix;
    ULONG jx;

    DPRINT("ACPIAmliBuildObjectPathname: %p\n", PathNsObject);

    ASSERT(PathNsObject);

    ParentNsObject = PathNsObject->Parent;

    for (Count = 0; ParentNsObject; Count++)
        ParentNsObject = ParentNsObject->Parent;

    InstanceID = ExAllocatePoolWithTag(NonPagedPool, ((Count * 5) + 1), 'SpcA');
    if (!InstanceID)
    {
        DPRINT1("ACPIAmliBuildObjectPathname: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    InstanceID[Count * 5] = 0;

    ix = Count;

    for (NsObject = PathNsObject; ; NsObject = ParentNsObject)
    {
        ParentNsObject = NsObject->Parent;
        if (!ParentNsObject)
            break;

        ix--;

        *(ULONG *)&InstanceID[(ix * 5)] = NsObject->NameSeg;

        for (jx = 0; jx < 4; jx++)
        {
            if (InstanceID[(ix * 5) + jx] == 0)
                InstanceID[(ix * 5) + jx] = '*';
        }

        InstanceID[(ix * 5) + 4] = '.';
    }

    if (Count)
        InstanceID[(Count * 5) - 1] = 0;

    *OutInstanceID = InstanceID;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIBuildDockExtension(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ PDEVICE_EXTENSION ParentDeviceExtension)
{
    PDEVICE_EXTENSION DockExtension = NULL;
    PCHAR InstanceID = NULL;
    PCHAR DeviceID;
    ULONG Size;
    NTSTATUS Status;

    Status = ACPIBuildDeviceExtension(NULL, ParentDeviceExtension, &DockExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIBuildDockExtension: Status %X\n", Status);
        return Status;
    }

    if (!DockExtension)
    {
        DPRINT1("ACPIBuildDockExtension: Status %X\n", Status);
        return Status;
    }

    Size = sizeof("ACPI\\DockDevice");

    DeviceID = ExAllocatePoolWithTag(NonPagedPool, Size, 'SpcA');
    if (!DeviceID)
    {
        DPRINT1("ACPIBuildDockExtension: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }
    RtlCopyMemory(DeviceID, "ACPI\\DockDevice", Size);

    DockExtension->DeviceID = DeviceID;

    Status = ACPIAmliBuildObjectPathname(NsObject, &InstanceID);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIBuildDockExtension: Status %X\n", Status);
        goto ErrorExit;
    }

    DockExtension->InstanceID = InstanceID;

    DockExtension->Dock.CorrospondingAcpiDevice = NsObject->Context;
    DockExtension->Dock.ProfileDepartureStyle = 4;
    DockExtension->Dock.IsolationState = 0;

    ACPIInternalUpdateFlags(&DockExtension->Flags, 0x0209E00000020008, FALSE);

    DPRINT("ACPIBuildDockExtension: Status %X\n", Status);

    return Status;

ErrorExit:

    DPRINT1("ACPIBuildDockExtension: Status %X\n", Status);

    if (InstanceID)
    {
        ACPIInternalUpdateFlags(&DockExtension->Flags, 0x0000A00000000000, TRUE);
        ExFreePoolWithTag(InstanceID, 0);
        DockExtension->InstanceID = 0;
    }

    if (DockExtension)
    {
        ACPIInternalUpdateFlags(&DockExtension->Flags, 0x0000A00000000000, TRUE);
        ExFreePoolWithTag(DockExtension, 0);
        DockExtension->Address = 0;
    }

    ACPIInternalUpdateFlags(&DockExtension->Flags, 0x0002000000000000, TRUE);

    return Status;
}

VOID
__cdecl
ACPIBuildCompleteGeneric(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA Data,
    _In_ PVOID Context)
{
    PACPI_BUILD_REQUEST BuildRequest = Context;
    LONG ExChange;

    DPRINT("ACPIBuildCompleteGeneric: BuildRequest %X\n", BuildRequest);

    ExChange = BuildRequest->BuildReserved1;

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT1("ACPIBuildCompleteGeneric: InStatus %X\n", InStatus);
        BuildRequest->Status = InStatus;
    }

    BuildRequest->BuildReserved1 = 2;

    ACPIBuildCompleteCommon(&BuildRequest->WorkDone, ExChange);
}

NTSTATUS
NTAPI
ACPIBuildProcessDevicePhaseEjd(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status;

    DPRINT("ACPIBuildProcessDevicePhaseEjd: BuildRequest %X\n", BuildRequest);

    DeviceExtension = BuildRequest->Context;

    if ((DeviceExtension->Flags & 0000000000000002) || !(DeviceExtension->Flags & 0x0000000004000000))
        BuildRequest->BuildReserved1 = 0x0B;
    else
        BuildRequest->BuildReserved1 = 0x13;

    if (BuildRequest->ChildObject)
    {
        AMLIFreeDataBuffs(&BuildRequest->Device.Data, TRUE);

        ExInterlockedInsertTailList(&AcpiUnresolvedEjectList, &DeviceExtension->EjectDeviceList, &AcpiDeviceTreeLock);

        if (DeviceExtension->DebugFlags & 1)
        {
            DPRINT1("ACPIBuildProcessDevicePhaseEjd: Ejector already found\n");
        }
        else
        {
            DeviceExtension->DebugFlags |= 1;
        }
    }

    if (!ACPIDockIsDockDevice(DeviceExtension->AcpiObject))
    {
        Status = STATUS_SUCCESS;
        goto Finish;
    }

    if (!AcpiInformation->Dockable)
    {
        DPRINT1("ACPIBuildProcessDevicePhaseEjd: BIOS BUG - DOCK bit not set\n");
        ASSERT(FALSE);
        KeBugCheckEx(0xA5, 0xC, (ULONG_PTR)DeviceExtension, (ULONG_PTR)BuildRequest->ChildObject, 0);
    }

    if (ACPIDockFindCorrespondingDock(DeviceExtension))
    {
        DPRINT1("ACPIBuildProcessDevicePhaseEjd: KeBugCheckEx()\n");
        ASSERT(FALSE);
        KeBugCheckEx(0xA5, 0xC, (ULONG_PTR)DeviceExtension, (ULONG_PTR)BuildRequest->ChildObject, 1);
    }

    KeAcquireSpinLockAtDpcLevel(&AcpiDeviceTreeLock);
    Status = ACPIBuildDockExtension(DeviceExtension->AcpiObject, RootDeviceExtension);
    KeReleaseSpinLockFromDpcLevel(&AcpiDeviceTreeLock);

Finish:

    DPRINT("ACPIBuildProcessDevicePhaseEjd: Status %X\n", Status);

    ACPIBuildCompleteGeneric(NULL, Status, NULL, BuildRequest);

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildDevicePowerNodes(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ PAMLI_OBJECT_DATA InData,
    _In_ DEVICE_POWER_STATE State)
{
    PAMLI_PACKAGE_OBJECT InPackageObject;
    PAMLI_NAME_SPACE_OBJECT PowerNsObject;
    PACPI_POWER_DEVICE_NODE PowerNode;
    PACPI_DEVICE_POWER_NODE Node;
    PAMLI_OBJECT_DATA Data;
    ULONG Elements;
    ULONG Offset;
    ULONG ix;
    NTSTATUS Status;

    DPRINT("ACPIBuildDevicePowerNodes: %p\n", DeviceExtension);

    InPackageObject = InData->DataBuff;

    if (State == PowerDeviceUnspecified)
    {
        if (InPackageObject->Elements < 2)
        {
            DPRINT1("ACPIBuildDevicePowerNodes: !!! KeBugCheckEx(), %X\n", InPackageObject->Elements);
            KeBugCheckEx(0xA5, 5, (ULONG_PTR)DeviceExtension, (ULONG_PTR)NsObject, InPackageObject->Elements);
        }

        Elements = (InPackageObject->Elements - 2);
        Offset = 2;
    }
    else
    {
        Elements = InPackageObject->Elements;
        Offset = 0;
    }

    if (!Elements)
        return STATUS_SUCCESS;

    Node = ExAllocatePoolWithTag(NonPagedPool, (Elements * sizeof(*Node)), 'PpcA');
    if (!Node)
    {
        DPRINT1("ACPIBuildDevicePowerNodes: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeAcquireSpinLockAtDpcLevel(&AcpiPowerLock);

    DeviceExtension->PowerInfo.PowerNode[State] = Node;

    for (ix = 0; ix < Elements; ix++, Offset++, Node++)
    {
        RtlZeroMemory(Node, sizeof(*Node));

        Data = &InPackageObject->Data[Offset];
        PowerNsObject = NULL;

        Status = AMLIGetNameSpaceObject(Data->DataBuff, NsObject, &PowerNsObject, 0);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIBuildDevicePowerNodes: '%s' Status %X\n", Data->DataBuff, Status);
            KeBugCheckEx(0xA5, 6, (ULONG_PTR)DeviceExtension, (ULONG_PTR)NsObject, (ULONG_PTR) Data->DataBuff);
        }

        if (!PowerNsObject || PowerNsObject->ObjData.DataType != 0xB)
        {
            DPRINT1("ACPIBuildDevicePowerNodes: '%s' references bad power object.\n", Data->DataBuff);
            KeBugCheckEx(0xA5, 0x12, (ULONG_PTR)DeviceExtension, (ULONG_PTR)NsObject, (ULONG_PTR)Data->DataBuff);
        }

        PowerNode = PowerNsObject->Context;

        Node->PowerNode = PowerNode;
        Node->SystemState = PowerNode->SystemLevel;
        Node->DeviceExtension = DeviceExtension;
        Node->AssociatedDeviceState = State;

        if (State == PowerDeviceUnspecified)
            Node->WakePowerResource = 1;

        if (State == PowerDeviceD0 && (DeviceExtension->Flags & 0x0000000000400000))
        {
            ULONGLONG Flags;
            ULONGLONG ExChange;
            ULONGLONG Comperand;

            Flags = Node->PowerNode->Flags;
            do
            {
                Comperand = Flags;
                ExChange = (Comperand | 0x0000000000000220);

                Flags = ExInterlockedCompareExchange64((PLONGLONG)&Node->PowerNode->Flags, (PLONGLONG)&ExChange, (PLONGLONG)&Comperand, NULL);
            }
            while (Comperand != Flags);
        }

        InsertTailList(&Node->PowerNode->DevicePowerListHead, &Node->DevicePowerListEntry);

        if (ix >= (Elements - 1))
            Node->Next = NULL;
        else
            Node->Next = &Node[1];
    }

    KeReleaseSpinLockFromDpcLevel(&AcpiPowerLock);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIBuildProcessDevicePhasePrw(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension;
    PAMLI_PACKAGE_OBJECT DataBuff;
    AMLI_OBJECT_DATA data;
    SYSTEM_POWER_STATE SystemPowerState;
    SYSTEM_POWER_STATE SystemWakeLevel;
    ULONG Idx;
    ULONG Mask;
    BOOLEAN IsOverride = FALSE;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ACPIBuildProcessDevicePhasePrw: BuildRequest %X\n", BuildRequest);

    DeviceExtension = BuildRequest->Context;
    BuildRequest->BuildReserved1 = 0xD;

    DeviceExtension->PowerInfo.PowerObject[0] = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, 'WSP_');

    if (!BuildRequest->ChildObject)
        goto Finish;

    if ((AcpiOverrideAttributes & 8) && !(DeviceExtension->Flags & 0x0000000800000000))
        IsOverride = TRUE;

    if (BuildRequest->Device.Data.DataType != 4) // Package
    {
        DPRINT1("ACPIBuildProcessDevicePhasePrw: KeBugCheckEx()\n");
        ASSERT(FALSE);
        KeBugCheckEx(0xA5, 9, (ULONG_PTR)DeviceExtension, (ULONG_PTR)BuildRequest->ChildObject, BuildRequest->Device.Data.DataType);
    }

    Status = ACPIBuildDevicePowerNodes(DeviceExtension, BuildRequest->ChildObject, &BuildRequest->Device.Data, 0);

    KeAcquireSpinLockAtDpcLevel(&AcpiPowerLock);

    DataBuff = BuildRequest->Device.Data.DataBuff;

    if (DataBuff->Data[0].DataType != 1) // Integer
    {
        DPRINT1("ACPIBuildProcessDevicePhasePrw: KeBugCheckEx()\n");
        ASSERT(FALSE);
        KeBugCheckEx(0xA5, 4, (ULONG_PTR)DeviceExtension, (ULONG_PTR)BuildRequest->ChildObject, DataBuff->Data[0].DataType);
    }

    if (DataBuff->Data[1].DataType != 1) // Integer
    {
        DPRINT1("ACPIBuildProcessDevicePhasePrw: KeBugCheckEx()\n");
        ASSERT(FALSE);
        KeBugCheckEx(0xA5, 4, (ULONG_PTR)DeviceExtension, (ULONG_PTR)BuildRequest->ChildObject, DataBuff->Data[1].DataType);
    }

    if (!IsOverride)
    {
        DeviceExtension->PowerInfo.WakeBit = (ULONG)DataBuff->Data[0].DataValue;

        SystemPowerState = (ULONG)DataBuff->Data[1].DataValue;

        if (SystemPowerState < PowerSystemShutdown)
            SystemWakeLevel = SystemPowerStateTranslation[SystemPowerState];
        else
            SystemWakeLevel = 0;

        DeviceExtension->PowerInfo.SystemWakeLevel = SystemWakeLevel;

        ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0000000000010000, FALSE);
    }

    KeReleaseSpinLockFromDpcLevel(&AcpiPowerLock);

    Idx = (((ULONG)DataBuff->Data[0].DataValue & 0xFF) / 8);
    Mask = (1 << (((ULONG)DataBuff->Data[0].DataValue & 0xFF) % 8));

    KeAcquireSpinLockAtDpcLevel(&GpeTableLock);

    if (GpeEnable[Idx] & Mask)
    {
        if (!(DeviceExtension->Flags & 0x0000000800000000))
        {
            if (!(GpeSpecialHandler[Idx] & Mask))
                GpeWakeHandler[Idx] |= Mask;
        }
        else
        {
            GpeSpecialHandler[Idx] |= Mask;

            if (GpeWakeHandler[Idx] & Mask)
                GpeWakeHandler[Idx] &= ~Mask;
        }
    }

    KeReleaseSpinLockFromDpcLevel(&GpeTableLock);

    AMLIFreeDataBuffs(&BuildRequest->Device.Data, 1);

    if (DeviceExtension->PowerInfo.PowerObject[0])
    {
        RtlZeroMemory(&data, sizeof(data));

        data.DataType = 1;
        data.DataValue = 0;

        AMLIAsyncEvalObject(DeviceExtension->PowerInfo.PowerObject[0], NULL, 1, &data, NULL, NULL);
    }

Finish:

    DPRINT("ACPIBuildProcessDevicePhasePrw: Status %X\n", Status);

    ACPIBuildCompleteMustSucceed(NULL, Status, 0, BuildRequest);

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildProcessDevicePhasePr0(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status = STATUS_SUCCESS;

    DeviceExtension = BuildRequest->Context;
    BuildRequest->BuildReserved1 = 0x0F;

    DeviceExtension->PowerInfo.PowerObject[1] = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, '0SP_');

    if (BuildRequest->ChildObject)
    {
        if (BuildRequest->Device.Data.DataType != 4)
        {
            DPRINT1("ACPIBuildProcessDevicePhasePr0: KeBugCheckEx()\n");
            ASSERT(FALSE);
            KeBugCheckEx(0xA5, 9, (ULONG_PTR)DeviceExtension, (ULONG_PTR)BuildRequest->ChildObject, BuildRequest->Device.Data.DataType);
        }

        Status = ACPIBuildDevicePowerNodes(DeviceExtension, BuildRequest->ChildObject, &BuildRequest->Device.Data, 1);

        AMLIFreeDataBuffs(&BuildRequest->Device.Data, 1);
    }

    DPRINT("ACPIBuildProcessDevicePhasePr0: Status %X\n", Status);

    ACPIBuildCompleteMustSucceed(NULL, Status, 0, BuildRequest);

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildProcessDevicePhasePr1(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status = STATUS_SUCCESS;

    DeviceExtension = BuildRequest->Context;
    BuildRequest->BuildReserved1 = 0x11;

    DeviceExtension->PowerInfo.PowerObject[2] = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, '1SP_');

    if (!DeviceExtension->PowerInfo.PowerObject[2])
        DeviceExtension->PowerInfo.PowerObject[2] = DeviceExtension->PowerInfo.PowerObject[1];

    if (BuildRequest->ChildObject)
    {
        if (BuildRequest->Device.Data.DataType != 4)
        {
            DPRINT1("ACPIBuildProcessDevicePhasePr1: KeBugCheckEx()\n");
            ASSERT(FALSE);
            KeBugCheckEx(0xA5, 9, (ULONG_PTR)DeviceExtension, (ULONG_PTR)BuildRequest->ChildObject, BuildRequest->Device.Data.DataType);
        }

        Status = ACPIBuildDevicePowerNodes(DeviceExtension, BuildRequest->ChildObject, &BuildRequest->Device.Data, 2);

        AMLIFreeDataBuffs(&BuildRequest->Device.Data, 1);
    }

    DPRINT("ACPIBuildProcessDevicePhasePr1: Status %X\n", Status);

    ACPIBuildCompleteMustSucceed(NULL, Status, 0, BuildRequest);

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildProcessDevicePhasePr2(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status = STATUS_SUCCESS;

    DeviceExtension = BuildRequest->Context;

    DeviceExtension->PowerInfo.PowerObject[3] = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, '2SP_');

    if (!DeviceExtension->PowerInfo.PowerObject[3])
        DeviceExtension->PowerInfo.PowerObject[3] = DeviceExtension->PowerInfo.PowerObject[2];

    if (BuildRequest->ChildObject)
    {
        if (BuildRequest->Device.Data.DataType != 4)
        {
            DPRINT1("ACPIBuildProcessDevicePhasePr2: KeBugCheckEx()\n");
            ASSERT(FALSE);
            KeBugCheckEx(0xA5, 9, (ULONG_PTR)DeviceExtension, (ULONG_PTR)BuildRequest->ChildObject, BuildRequest->Device.Data.DataType);
        }

        Status = ACPIBuildDevicePowerNodes(DeviceExtension, BuildRequest->ChildObject, &BuildRequest->Device.Data, 3);
        AMLIFreeDataBuffs(&BuildRequest->Device.Data, 1);
    }

    if (DeviceExtension->Flags & 2)
    {
        BuildRequest->ChildObject = NULL;
        BuildRequest->BuildReserved1 = 0x16;
    }
    else
    {
        BuildRequest->BuildReserved1 = 0x15;
    }

    DPRINT("ACPIBuildProcessDevicePhasePr2: Status %X\n", Status);

    ACPIBuildCompleteMustSucceed(NULL, Status, 0, BuildRequest);

    return Status;
}

VOID
NTAPI
ACPIMatchKernelPorts(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PAMLI_OBJECT_DATA Data)
{
    PUCHAR* kdComPortInUse = (PVOID)KdComPortInUse; // FIXME! KdComPortInUse PUCHAR or PUCHAR* ?
    HEADLESS_RSP_QUERY_INFO HeadlessInformation;
    PACPI_RESOURCE_DATA_TYPE ResDataType = Data->DataBuff;
    PUCHAR TerminalPortBaseAddress;
    PUCHAR KdAddress;
    SIZE_T InfoSize;
    ULONG Increment;
    ULONG Port;
    ULONG ix;
    UCHAR TagName;
    BOOLEAN IsFoundPort = FALSE;
    NTSTATUS Status;

    DPRINT("ACPIMatchKernelPorts: DeviceExtension %X, kdComPortInUse %X\n", DeviceExtension, kdComPortInUse);

    InfoSize = sizeof(HEADLESS_RSP_QUERY_INFO);
    Status = HeadlessDispatch(HeadlessCmdQueryInformation, NULL, 0, &HeadlessInformation, &InfoSize);

    if (NT_SUCCESS(Status) &&
        HeadlessInformation.PortType == HeadlessSerialPort &&
        HeadlessInformation.Serial.TerminalAttached)
    {
        TerminalPortBaseAddress = HeadlessInformation.Serial.TerminalPortBaseAddress;
    }
    else
    {
        TerminalPortBaseAddress = NULL;
    }

    if ((!kdComPortInUse /*|| !(*KdComPortInUse)*/) && !TerminalPortBaseAddress) // FIXME!
        return;

    if (kdComPortInUse)
        KdAddress = (PVOID)kdComPortInUse; // *KdComPortInUse
    else
        KdAddress = NULL;

    DPRINT("ACPIMatchKernelPorts: TerminalPortBaseAddress %X, KdAddress %X\n", TerminalPortBaseAddress, KdAddress);

    for (ix = 0; ix < Data->DataLen; )
    {
        if (!ResDataType->Small.Type)
        {
            Increment = (ResDataType->Small.Length + 1);
            TagName = ResDataType->Small.Name;
            DPRINT("ACPIMatchKernelPorts: Small TagName %X, Increment %X\n", TagName, Increment);
        }
        else
        {
            Increment = (ResDataType->Large.Length + 3);
            TagName = ResDataType->Large.Name;
            DPRINT("ACPIMatchKernelPorts: Large TagName %X, Increment %X\n", TagName, Increment);
        }

        if ((ResDataType->Small.Tag & 0xF8) == 0x78)
        {
            DPRINT("ACPIMatchKernelPorts: TAG_END\n");
            break;
        }

        if (!ResDataType->Small.Type)
        {
            switch (TagName)
            {
                case 0x08:
                {
                    PACPI_IO_PORT_DESCRIPTOR AcpiDesc = (PVOID)ResDataType;

                    DPRINT1("ACPIMatchKernelPorts: IO Port Descriptor - %X\n", AcpiDesc->Minimum);

                    Port = AcpiDesc->Minimum;
                    IsFoundPort = TRUE;

                    break;
                }
                case 0x09: // Fixed Location I/O Port Descriptor 
                {
                    DPRINT1("ACPIMatchKernelPorts: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                default:
                {
                    DPRINT1("ACPIMatchKernelPorts: unsupported TagName %X\n", TagName);
                    goto Next;
                }
            }
        }
        else
        {
            switch (TagName)
            {
                case 0x07: // DWORD Address Space Descriptor 
                {
                    DPRINT1("ACPIMatchKernelPorts: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x08: // WORD Address Space Descriptor 
                {
                    DPRINT1("ACPIMatchKernelPorts: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x0A: // QWORD Address Space Descriptor
                {
                    DPRINT1("ACPIMatchKernelPorts: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                default:
                {
                    DPRINT1("ACPIMatchKernelPorts: unsupported TagName %X\n", TagName);
                    goto Next;
                }
            }
        }

        if (!IsFoundPort)
            goto Next;

        if ((kdComPortInUse && Port == (ULONG_PTR)KdAddress) ||
            (TerminalPortBaseAddress && Port == (ULONG_PTR)TerminalPortBaseAddress))
        {
            ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0000000000680003, FALSE);

            if (kdComPortInUse && Port == (ULONG_PTR)KdAddress)
                DPRINT("ACPIMatchKernelPorts - Found KD Port at %X\n", Port);
            else
                DPRINT("ACPIMatchKernelPorts - Found Headless Port at %X\n", Port);
            break;
        }
Next:
        ResDataType = Add2Ptr(ResDataType, Increment);
        ix += Increment;
    }
}

NTSTATUS
NTAPI
ACPIBuildProcessDevicePhaseCrs(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension;

    DPRINT("ACPIBuildProcessDevicePhaseCrs: BuildRequest %X\n", BuildRequest);

    DeviceExtension = BuildRequest->Context;
    BuildRequest->BuildReserved1 = 0xB;

    if (BuildRequest->ChildObject)
    {
        if (BuildRequest->Device.Data.DataType != 3)
        {
            DPRINT1("ACPIBuildProcessDevicePhaseCrs: KeBugCheckEx()\n");
            ASSERT(FALSE);
            //KeBugCheckEx(0xA5, 7, DeviceExtension, BuildRequest->ChildObject, BuildRequest->Device.Data.DataType);
        }

        ACPIMatchKernelPorts(DeviceExtension, &BuildRequest->Device.Data);
        AMLIFreeDataBuffs(&BuildRequest->Device.Data, 1);
    }

    DPRINT("ACPIBuildProcessDevicePhaseCrs: STATUS_SUCCESS\n");

    ACPIBuildCompleteMustSucceed(NULL, STATUS_SUCCESS, 0, BuildRequest);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIBuildProcessDeviceGenericEval(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension;
    ULONG NameSeg;
    ULONG Idx;
    NTSTATUS Status;

    RtlZeroMemory(&BuildRequest->Device.Data, sizeof(BuildRequest->Device.Data));

    DeviceExtension = BuildRequest->Context;
    Idx = BuildRequest->BuildReserved0;
    NameSeg = AcpiBuildDevicePowerNameLookup[Idx];
    BuildRequest->BuildReserved1 = (Idx + 1);

    BuildRequest->ChildObject = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, NameSeg);
    if (!BuildRequest->ChildObject)
    {
        Status = STATUS_SUCCESS;

        ACPIBuildCompleteGeneric(BuildRequest->ChildObject, Status, &BuildRequest->Device.Data, BuildRequest);
        goto Exit;
    }

    Status = AMLIAsyncEvalObject(BuildRequest->ChildObject, &BuildRequest->Device.Data, 0, NULL, (PVOID)ACPIBuildCompleteGeneric, BuildRequest);
    if (Status != STATUS_PENDING)
    {
        ACPIBuildCompleteGeneric(BuildRequest->ChildObject, Status, &BuildRequest->Device.Data, BuildRequest);
        goto Exit;
    }

Exit:

    DPRINT("ACPIBuildProcessDeviceGenericEval: Phase%X, Status %X\n", (BuildRequest->BuildReserved0 - 3), Status);

    return STATUS_SUCCESS;
}

VOID
NTAPI
ACPIDeviceCompleteCommon(
    _In_ PLONG Destination,
    _In_ LONG ExChange)
{
    KIRQL Irql;

    DPRINT("ACPIDeviceCompleteCommon: %X, %X\n", *Destination, ExChange);

    InterlockedCompareExchange(Destination, ExChange, 1);

    KeAcquireSpinLock(&AcpiPowerQueueLock, &Irql);

    AcpiPowerWorkDone = TRUE;

    if (!AcpiPowerDpcRunning)
    {
        DPRINT("ACPIDeviceCompleteCommon: insert DPC (AcpiPowerDpc)\n");
        KeInsertQueueDpc(&AcpiPowerDpc, NULL, NULL);
    }

    KeReleaseSpinLock(&AcpiPowerQueueLock, Irql);
}

VOID
__cdecl
ACPIDeviceCompleteGenericPhase(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ NTSTATUS InStatus,
    _In_ PVOID Unknown3,
    _In_ PVOID Context)
{
    PACPI_POWER_REQUEST Request = Context;

    //DPRINT("ACPIDeviceCompleteGenericPhase: %p, %X, %X, %p\n", NsObject, InStatus, Unknown3, Context);

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT1("ACPIDeviceCompleteGenericPhase: InStatus %X\n", InStatus);

        Request->Status = InStatus;
        ACPIDeviceCompleteCommon(&Request->WorkDone, 2);

        return;
    }

    ACPIDeviceCompleteCommon(&Request->WorkDone, Request->NextWorkDone);

    //DPRINT("ACPIDeviceCompleteGenericPhase: exit\n");
}

NTSTATUS
NTAPI
ACPIDevicePowerProcessInvalid(
    _In_ PACPI_POWER_REQUEST Request)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIDevicePowerProcessForward(
    _In_ PACPI_POWER_REQUEST Request)
{
    DPRINT("ACPIDevicePowerProcessForward: %p\n", Request);

    InterlockedCompareExchange(&Request->WorkDone, 0, 1);

    KeAcquireSpinLockAtDpcLevel(&AcpiPowerQueueLock);
    AcpiPowerWorkDone = TRUE;
    KeReleaseSpinLockFromDpcLevel(&AcpiPowerQueueLock);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase0DeviceSubPhase1(_In_ PACPI_POWER_REQUEST Request)
{
    NTSTATUS Status;

    DPRINT("ACPIDevicePowerProcessPhase0DeviceSubPhase1: %p\n", Request);

    Request->NextWorkDone = 4;

    RtlZeroMemory(&Request->ResultData, sizeof(Request->ResultData));

    Status = ACPIGet(Request->DeviceExtension,
                     'ATS_',
                     0x40041802,
                     NULL,
                     0,
                     ACPIDeviceCompleteGenericPhase,
                     Request,
                     &Request->ResultData.DataValue,
                     &Request->ResultData.DataLen);

    if (Status == STATUS_PENDING)
        return Status;

    ACPIDeviceCompleteGenericPhase(NULL, Status, &Request->ResultData, Request);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase0SystemSubPhase1(_In_ PACPI_POWER_REQUEST Request)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase0DeviceSubPhase2(_In_ PACPI_POWER_REQUEST Request)
{
    DPRINT("ACPIDevicePowerProcessPhase0DeviceSubPhase2: %p\n", Request);

    if (!((ULONG)Request->ResultData.DataValue & 1))
    {
        Request->NextWorkDone = 2;
        Request->Status = STATUS_SUCCESS;
    }
    else
    {
        Request->NextWorkDone = 0;
    }

    ACPIDeviceCompleteGenericPhase(NULL, STATUS_SUCCESS, NULL, Request);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase1DeviceSubPhase1(_In_ PACPI_POWER_REQUEST Request)
{
    PDEVICE_EXTENSION DeviceExtension;
    PAMLI_NAME_SPACE_OBJECT NsObject = NULL;
    DEVICE_POWER_STATE State;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ACPIDevicePowerProcessPhase1DeviceSubPhase1: %p\n", Request);

    DeviceExtension = Request->DeviceExtension;
    State = Request->u.DevicePowerRequest.DevicePowerState;

    RtlZeroMemory(&Request->ResultData, sizeof(Request->ResultData));

    Request->ResultData.DataType = 1;

    if (State == PowerDeviceD0 || (Request->u.DevicePowerRequest.Flags & 0x10))
    {
        Request->NextWorkDone = 6;
        goto Exit;
    }

    if (DeviceExtension->Flags & 0x0008000000000000)
    {
        Request->NextWorkDone = 5;
        goto Exit;
    }

    Request->NextWorkDone = 4;

    if (State != PowerDeviceD3)
        goto Exit;

    NsObject = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, 'SID_');
    if (!NsObject)
        goto Exit;

    Status = AMLIAsyncEvalObject(NsObject, NULL, 0, NULL, (PVOID)ACPIDeviceCompleteGenericPhase, Request);
    if (Status == STATUS_PENDING)
        return Status;

Exit:

    ACPIDeviceCompleteGenericPhase(NsObject, Status, NULL, Request);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase1DeviceSubPhase2(_In_ PACPI_POWER_REQUEST Request)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase1DeviceSubPhase3(_In_ PACPI_POWER_REQUEST Request)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase1DeviceSubPhase4(_In_ PACPI_POWER_REQUEST Request)
{
    PDEVICE_EXTENSION DeviceExtension;
    PACPI_DEVICE_POWER_NODE Node;
    DEVICE_POWER_STATE State;
    KIRQL Irql;

    DPRINT("ACPIDevicePowerProcessPhase1DeviceSubPhase4: %p\n", Request);

    DeviceExtension = Request->DeviceExtension;

    AMLIFreeDataBuffs(&Request->ResultData, 1);
    RtlZeroMemory(&Request->ResultData, sizeof(Request->ResultData));

    KeAcquireSpinLock(&AcpiPowerLock, &Irql);

    if (DeviceExtension->PowerInfo.PowerState < PowerDeviceD0 ||
        DeviceExtension->PowerInfo.PowerState > PowerDeviceD2)
    {
        for (State = PowerDeviceD0; State < PowerDeviceD3; State++)
        {
             Node = DeviceExtension->PowerInfo.PowerNode[State];
             while (Node)
             {
                 InterlockedExchange(&Node->PowerNode->WorkDone, 3);
                 Node = Node->Next;
             }
        }

        State = Request->u.DevicePowerRequest.DevicePowerState;
    }
    else
    {
        Node = DeviceExtension->PowerInfo.PowerNode[DeviceExtension->PowerInfo.PowerState];
        while (Node)
        {
            InterlockedExchange(&Node->PowerNode->WorkDone, 3);
            Node = Node->Next;
        }

        State = Request->u.DevicePowerRequest.DevicePowerState;

        if (State >= PowerDeviceD0 && State <= PowerDeviceD2)
            Node = DeviceExtension->PowerInfo.PowerNode[State];

        while (Node)
        {
            InterlockedExchange(&Node->PowerNode->WorkDone, 3);
            Node = Node->Next;
        }
    }

    if (Request->u.DevicePowerRequest.Flags & 0x10)
    {
        Node = DeviceExtension->PowerInfo.PowerNode[PowerDeviceD0];
        while (Node)
        {
            ASSERT(FALSE);
        }
    }
    else if (Request->u.DevicePowerRequest.Flags & 0x20)
    {
        Node = DeviceExtension->PowerInfo.PowerNode[PowerDeviceD0];
        while (Node)
        {
            ASSERT(FALSE);
        }
    }

    DeviceExtension->PowerInfo.PowerState = PowerDeviceUnspecified;
    DeviceExtension->PowerInfo.DesiredPowerState = State;

    KeReleaseSpinLock(&AcpiPowerLock, Irql);

    ACPIDeviceCompleteCommon(&Request->WorkDone, 0);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase2SystemSubPhase1(_In_ PACPI_POWER_REQUEST Request)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase2SystemSubPhase2(_In_ PACPI_POWER_REQUEST Request)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase2SystemSubPhase3(_In_ PACPI_POWER_REQUEST Request)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
__cdecl
ACPIDeviceCompletePhase3On(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA Data,
    _In_ PVOID Context)
{
    PACPI_POWER_DEVICE_NODE PowerNode = Context;
    KIRQL Irql;

    DPRINT("ACPIDeviceCompletePhase3On: (ON) PowerNode %p, InStatus %X\n", PowerNode, InStatus);

    KeAcquireSpinLock(&AcpiPowerLock, &Irql);

    if (NT_SUCCESS(InStatus))
        ACPIInternalUpdateFlags(&PowerNode->Flags, 0x10, 0);
    else
        ACPIInternalUpdateFlags(&PowerNode->Flags, 0x10000, 0);

    KeReleaseSpinLock(&AcpiPowerLock, Irql);

    ACPIDeviceCompleteCommon(&PowerNode->WorkDone, 0);
}

NTSTATUS
NTAPI
ACPIDevicePowerProcessPhase3(VOID)
{
    PDEVICE_EXTENSION DeviceExtension;
    PACPI_POWER_DEVICE_NODE PowerNode;
    PACPI_DEVICE_POWER_NODE DeviceNode;
    PLIST_ENTRY PowerNodeEntry;
    PLIST_ENTRY DeviceNodeEntry;
    ULONG WakeSupportCount;
    ULONG UseCounts;
    ULONG WorkDone;
    BOOLEAN Result = FALSE;
    NTSTATUS Status;

    DPRINT("ACPIDevicePowerProcessPhase3()\n");

    KeAcquireSpinLockAtDpcLevel(&AcpiPowerLock);

    for (PowerNodeEntry = AcpiPowerNodeList.Flink; PowerNodeEntry != &AcpiPowerNodeList; )
    {
        PowerNode = CONTAINING_RECORD(PowerNodeEntry, ACPI_POWER_DEVICE_NODE, ListEntry);
        PowerNodeEntry = PowerNodeEntry->Flink;

        if (!(PowerNode->Flags & 2))
            continue;

        if (InterlockedCompareExchange((PLONG)&PowerNode->WorkDone, 4, 3) != 3)
            continue;

        UseCounts = 0;

        for (DeviceNodeEntry = PowerNode->DevicePowerListHead.Flink; DeviceNodeEntry != &PowerNode->DevicePowerListHead; )
        {
            DeviceNode = CONTAINING_RECORD(DeviceNodeEntry, ACPI_DEVICE_POWER_NODE, DevicePowerListEntry);
            DeviceNodeEntry = DeviceNodeEntry->Flink;

            DeviceExtension = DeviceNode->DeviceExtension;

            WakeSupportCount = InterlockedCompareExchange((PLONG)&DeviceExtension->PowerInfo.WakeSupportCount, 0, 0);

            if (DeviceExtension->PowerInfo.DesiredPowerState == DeviceNode->AssociatedDeviceState ||
                (WakeSupportCount && DeviceNode->WakePowerResource))
            {
                UseCounts++;
            }
        }

        InterlockedExchange((PLONG)&PowerNode->UseCounts, UseCounts);

        if (PowerNode->Flags & 0x440)
            continue;

        if (!(PowerNode->Flags & 0x220) && !UseCounts)
            continue;

        WorkDone = InterlockedCompareExchange((PLONG)&PowerNode->WorkDone, 1, 4);

        KeReleaseSpinLockFromDpcLevel(&AcpiPowerLock);

        Status = AMLIAsyncEvalObject(PowerNode->PowerOnObject, NULL, 0, NULL, ACPIDeviceCompletePhase3On, PowerNode);

        DPRINT("ACPIDevicePowerProcessPhase3: (ON) PowerNode %X, Status %X\n", PowerNode, Status);

        if (Status != STATUS_PENDING)
            ACPIDeviceCompletePhase3On(PowerNode->PowerOnObject, Status, NULL, PowerNode);
        else
            Result = TRUE;

        KeAcquireSpinLockAtDpcLevel(&AcpiPowerLock);
    }

    for (PowerNodeEntry = AcpiPowerNodeList.Blink; PowerNodeEntry != &AcpiPowerNodeList; )
    {
        PowerNode = CONTAINING_RECORD(PowerNodeEntry, ACPI_POWER_DEVICE_NODE, ListEntry);
        PowerNodeEntry = PowerNodeEntry->Blink;

        if (!(PowerNode->Flags & 2))
            continue;

        WorkDone = InterlockedCompareExchange((PLONG)&PowerNode->WorkDone, 1, 4);
        if (WorkDone == 4)
        {
            DPRINT1("ACPIDevicePowerProcessPhase3: FIXME\n");
            UNIMPLEMENTED_DBGBREAK();
            continue;
        }

        if (WorkDone)
            Result = TRUE;
    }

    KeReleaseSpinLockFromDpcLevel(&AcpiPowerLock);

    return (Result ? STATUS_PENDING : STATUS_SUCCESS);
}

NTSTATUS
NTAPI
ACPIDevicePowerProcessPhase4(VOID)
{
    PACPI_POWER_DEVICE_NODE PowerNode;
    PLIST_ENTRY PowerNodeEntry;

    DPRINT("ACPIDevicePowerProcessPhase4()\n");

    KeAcquireSpinLockAtDpcLevel(&AcpiPowerLock);

    for (PowerNodeEntry = AcpiPowerNodeList.Flink; PowerNodeEntry != &AcpiPowerNodeList; )
    {
        PowerNode = CONTAINING_RECORD(PowerNodeEntry, ACPI_POWER_DEVICE_NODE, ListEntry);
        PowerNodeEntry = PowerNodeEntry->Flink;

        if (!(PowerNode->Flags & 0x10000))
            continue;

        ACPIInternalUpdateFlags(&PowerNode->Flags, 0x10000, TRUE);

        DPRINT1("ACPIDevicePowerProcessPhase4: FIXME\n");
        UNIMPLEMENTED_DBGBREAK();
    }

    KeReleaseSpinLockFromDpcLevel(&AcpiPowerLock);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase5DeviceSubPhase1(_In_ PACPI_POWER_REQUEST Request)
{
    PDEVICE_EXTENSION DeviceExtension = Request->DeviceExtension;
    PAMLI_NAME_SPACE_OBJECT NsObject = NULL;
    PACPI_DEVICE_POWER_NODE Node;
    KIRQL Irql;
    BOOLEAN IsSuccess = TRUE;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ACPIDevicePowerProcessPhase5DeviceSubPhase1: %p\n", Request);

    if (Request->u.DevicePowerRequest.DevicePowerState != PowerDeviceD0)
    {
        Request->NextWorkDone = 5;
        goto Exit;
    }

    Request->NextWorkDone = 4;

    KeAcquireSpinLock(&AcpiPowerLock, &Irql);

    Node = DeviceExtension->PowerInfo.PowerNode[PowerDeviceD0];
    while (Node)
    {
        if (!(Node->PowerNode->Flags & 0x0010))
        {
            IsSuccess = FALSE;
            break;
        }

        Node = Node->Next;
    }

    KeReleaseSpinLock(&AcpiPowerLock, Irql);

    if (!IsSuccess)
    {
        Status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    NsObject = DeviceExtension->PowerInfo.PowerObject[Request->u.DevicePowerRequest.DevicePowerState];
    if (NsObject)
        Status = AMLIAsyncEvalObject(NsObject, NULL, 0, NULL, (PVOID)ACPIDeviceCompleteGenericPhase, Request);

    DPRINT("ACPIDevicePowerProcessPhase5DeviceSubPhase1: Status %X\n", Status);

    if (Status == STATUS_PENDING)
        return Status;

    Status = STATUS_SUCCESS;

Exit:

    ACPIDeviceCompleteGenericPhase(NsObject, Status, NULL, Request);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase5SystemSubPhase1(_In_ PACPI_POWER_REQUEST Request)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase5WarmEjectSubPhase1(_In_ PACPI_POWER_REQUEST Request)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase5DeviceSubPhase2(_In_ PACPI_POWER_REQUEST Request)
{
    PDEVICE_EXTENSION DeviceExtension;
    PAMLI_NAME_SPACE_OBJECT NsObject = NULL;
    KIRQL Irql;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ACPIDevicePowerProcessPhase5DeviceSubPhase2: %p\n", Request);

    DeviceExtension = Request->DeviceExtension;
    Request->NextWorkDone = 5;

    if (!(DeviceExtension->Flags & 0x0008000000000000))
        NsObject = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, 'SRS_');

    if (!NsObject)
    {
        ACPIDeviceCompleteGenericPhase(NsObject, STATUS_SUCCESS, NULL, Request);
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &Irql);

    if (DeviceExtension->PnpResourceList)
        Status = AMLIAsyncEvalObject(NsObject, NULL, 1, DeviceExtension->PnpResourceList, (PVOID)ACPIDeviceCompleteGenericPhase, Request);

    KeReleaseSpinLock(&AcpiDeviceTreeLock, Irql);

    if (Status == STATUS_PENDING)
        return Status;

    ACPIDeviceCompleteGenericPhase(NsObject, Status, NULL, Request);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase5SystemSubPhase2(_In_ PACPI_POWER_REQUEST Request)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase5WarmEjectSubPhase2(_In_ PACPI_POWER_REQUEST Request)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase5DeviceSubPhase3(_In_ PACPI_POWER_REQUEST Request)
{
    PDEVICE_EXTENSION DeviceExtension;
    PAMLI_NAME_SPACE_OBJECT NsObject = NULL;
    AMLI_OBJECT_DATA data;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ACPIDevicePowerProcessPhase5DeviceSubPhase3: %p\n", Request);

    DeviceExtension = Request->DeviceExtension;

    if (Request->u.DevicePowerRequest.DevicePowerState == PowerDeviceD0)
        Request->NextWorkDone = 6;
    else
        Request->NextWorkDone = 8;

    if (DeviceExtension->Flags & 0x0008000000000000)
        goto Exit;

    NsObject = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, 'KCL_');
    if (!NsObject)
        goto Exit;

    RtlZeroMemory(&data, sizeof(data));

    data.DataType = 1;

    if (Request->u.DevicePowerRequest.Flags & 0x00000004)
        data.DataValue = (PVOID)1;
    else if (Request->u.DevicePowerRequest.Flags & 0x00000008)
        data.DataValue = (PVOID)0;
    else
        goto Exit;

    Status = AMLIAsyncEvalObject(NsObject, NULL, 1, &data, (PVOID)ACPIDeviceCompleteGenericPhase, Request);

    DPRINT("ACPIDevicePowerProcessPhase5DeviceSubPhase3: %X\n", Status);

Exit:

    if (Status == STATUS_PENDING)
        return STATUS_SUCCESS;

    ACPIDeviceCompleteGenericPhase(NsObject, Status, NULL, Request);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase5SystemSubPhase3(_In_ PACPI_POWER_REQUEST Request)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase5DeviceSubPhase4(_In_ PACPI_POWER_REQUEST Request)
{
    NTSTATUS Status;

    DPRINT("ACPIDevicePowerProcessPhase5DeviceSubPhase4: %p\n", Request);

    Request->NextWorkDone = 7;

    RtlZeroMemory(&Request->ResultData, sizeof(Request->ResultData));

    Status = ACPIGet(Request->DeviceExtension, 'ATS_', 0x40041802, 0, 0, ACPIDeviceCompleteGenericPhase, Request, &Request->ResultData.DataValue, &Request->ResultData.DataLen);

    DPRINT("ACPIDevicePowerProcessPhase5DeviceSubPhase4: Status %X\n", Request, Status);

    if (Status == STATUS_PENDING)
        return Status;

    ACPIDeviceCompleteGenericPhase(NULL, Status, NULL, Request);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase5SystemSubPhase4(_In_ PACPI_POWER_REQUEST Request)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase5DeviceSubPhase5(_In_ PACPI_POWER_REQUEST Request)
{
    DPRINT("ACPIDevicePowerProcessPhase5DeviceSubPhase5: %p\n", Request);

    Request->NextWorkDone = 8;

    if (!((ULONG)Request->ResultData.DataValue & 1) ||
        !((ULONG)Request->ResultData.DataValue & 8) ||
        (!((ULONG)Request->ResultData.DataValue & 2) && !(Request->DeviceExtension->Flags & 0x0000000000000040)))
    {
        Request->Status = STATUS_INVALID_DEVICE_STATE;
        ACPIDeviceCompleteCommon(&Request->WorkDone, 2);
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&Request->ResultData, sizeof(Request->ResultData));

    ACPIDeviceCompleteGenericPhase(NULL, STATUS_SUCCESS, NULL, Request);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI ACPIDevicePowerProcessPhase5DeviceSubPhase6(_In_ PACPI_POWER_REQUEST Request)
{
    PDEVICE_EXTENSION DeviceExtension;
    PDEVICE_OBJECT DeviceObject;
    POWER_STATE State;

    DPRINT("ACPIDevicePowerProcessPhase5DeviceSubPhase6: %p\n", Request);

    DeviceExtension = Request->DeviceExtension;

    KeAcquireSpinLockAtDpcLevel(&AcpiPowerLock);

    DeviceExtension->PowerInfo.PowerState = DeviceExtension->PowerInfo.DesiredPowerState;
    State.DeviceState = DeviceExtension->PowerInfo.PowerState;
    DeviceObject = DeviceExtension->DeviceObject;

    KeReleaseSpinLockFromDpcLevel(&AcpiPowerLock);

    if (DeviceObject)
        PoSetPowerState(DeviceObject, DevicePowerState, State);

    Request->Status = STATUS_SUCCESS;

    ACPIDeviceCompleteCommon(&Request->WorkDone, 0);

    return STATUS_SUCCESS;
}

VOID
NTAPI
ACPIInternalMovePowerList(
    _In_ PLIST_ENTRY List1,
    _In_ PLIST_ENTRY List2)
{
    PACPI_POWER_REQUEST Request;
    PLIST_ENTRY Entry;

    DPRINT("ACPIInternalMovePowerList: %X %X\n", List1, List2);

    Entry = List1->Flink;

    while (Entry != List1)
    {
        Request = CONTAINING_RECORD(Entry, ACPI_POWER_REQUEST, ListEntry);

        if (Entry == &AcpiPowerPhase0List ||
            Entry == &AcpiPowerPhase1List ||
            Entry == &AcpiPowerPhase2List ||
            Entry == &AcpiPowerPhase3List ||
            Entry == &AcpiPowerPhase4List ||
            Entry == &AcpiPowerPhase5List ||
            Entry == &AcpiPowerWaitWakeList)
        {
            DPRINT1("ACPIInternalMoveList: %X is linked into %X\n", Entry, List1);
            DbgBreakPoint();
        }

        Entry = Entry->Flink;
        InterlockedExchange(&Request->WorkDone, 3);
    }

    ACPIInternalMoveList(List1, List2);
}

VOID
NTAPI
ACPIDeviceCompleteRequest(
    _In_ PACPI_POWER_REQUEST Request)
{
    PDEVICE_EXTENSION DeviceExtension;
    PACPI_POWER_REQUEST CurrentRequest;
    KIRQL Irql;

    DPRINT("ACPIDeviceCompleteRequest: %p\n", Request);

    DeviceExtension = Request->DeviceExtension;

    if (Request->RequestType == AcpiPowerRequestDevice &&
        DeviceExtension->PowerInfo.PowerState != PowerDeviceUnspecified)
    {
        if (!Request->FailedOnce && !NT_SUCCESS(Request->Status))
        {
            KeAcquireSpinLock(&AcpiPowerQueueLock, &Irql);

            Request->u.DevicePowerRequest.DevicePowerState = DeviceExtension->PowerInfo.PowerState;
            Request->FailedOnce = TRUE;

            RemoveEntryList(&Request->ListEntry);
            InsertTailList(&AcpiPowerQueueList, &Request->ListEntry);

            AcpiPowerWorkDone = TRUE;

            if (!AcpiPowerDpcRunning)
            {
                DPRINT("ACPIDeviceCompleteRequest: insert AcpiPowerDpc\n");
                KeInsertQueueDpc(&AcpiPowerDpc, NULL, NULL);
            }

            KeReleaseSpinLock(&AcpiPowerQueueLock, Irql);
            return;
        }

        if (DeviceExtension->PowerInfo.PowerState < Request->u.DevicePowerRequest.DevicePowerState)
            Request->Status = STATUS_SUCCESS;
    }

    if (Request->CallBack)
    {
        VOID (NTAPI* CallBack)(PDEVICE_EXTENSION, PVOID, NTSTATUS) = (PVOID)Request->CallBack;
        CallBack(DeviceExtension, Request->Context, Request->Status);
    }

    KeAcquireSpinLock(&AcpiPowerQueueLock, &Irql);

    RemoveEntryList(&Request->ListEntry);
    RemoveEntryList(&Request->SerialListEntry);

    if (!IsListEmpty(&DeviceExtension->PowerInfo.PowerRequestListEntry))
    {
        CurrentRequest = CONTAINING_RECORD(DeviceExtension->PowerInfo.PowerRequestListEntry.Flink,
                                           ACPI_POWER_REQUEST,
                                           SerialListEntry);

        InsertTailList(&AcpiPowerQueueList, &CurrentRequest->ListEntry);

        DeviceExtension->PowerInfo.CurrentPowerRequest = CurrentRequest;
    }
    else
    {
        DeviceExtension->PowerInfo.CurrentPowerRequest = NULL;
    }

    KeReleaseSpinLock(&AcpiPowerQueueLock, Irql);

    ExFreeToNPagedLookasideList(&RequestLookAsideList, Request);
}

NTSTATUS
NTAPI
ACPIDevicePowerProcessGenericPhase(
    _In_ PLIST_ENTRY PhaseList,
    _In_ PPOWER_PROCESS_DISPATCH** PhaseDispatchTables,
    _In_ BOOLEAN Param3)
{
    PACPI_POWER_REQUEST Request;
    PPOWER_PROCESS_DISPATCH* DispatchTable;
    PLIST_ENTRY Entry = PhaseList->Flink;
    PLIST_ENTRY NextEntry;
    ULONG Idx;
    BOOLEAN Result = TRUE;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ACPIDevicePowerProcessGenericPhase: %X, %X, %X\n", PhaseList, PhaseDispatchTables, Param3);

    while (Entry != PhaseList)
    {
        Request = CONTAINING_RECORD(Entry, ACPI_POWER_REQUEST, ListEntry);

        NextEntry = Entry->Flink;
        Idx = InterlockedCompareExchange(&Request->WorkDone, 1, 1);

        DispatchTable = PhaseDispatchTables[Idx];
        if (DispatchTable != NULL)
        {
            Idx = InterlockedCompareExchange(&Request->WorkDone, 1, Idx);

            Status = (DispatchTable[Request->RequestType])(Request);
            if (NT_SUCCESS(Status))
                continue;

            Idx = 0;
        }

        Entry = NextEntry;

        if (Idx != 0)
            Result = FALSE;

        if (Idx == 2)
        {
            ACPIDeviceCompleteRequest(Request);
            continue;
        }

        if (Param3 && !Idx)
            ACPIDeviceCompleteRequest(Request);
    }

    return (Result ? STATUS_SUCCESS : STATUS_PENDING);
}

VOID
NTAPI
ACPIDevicePowerDpc(
    _In_ PKDPC Dpc,
    _In_ PVOID DeferredContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2)
{
    LIST_ENTRY list;
    NTSTATUS Status;

    DPRINT("ACPIDevicePowerDpc: AcpiBuildDpcRunning %X (%X,%X)\n", AcpiPowerDpcRunning, KeGetCurrentIrql(), KeGetCurrentThread());

    KeAcquireSpinLockAtDpcLevel(&AcpiPowerQueueLock);

    if (AcpiPowerDpcRunning)
    {
        KeReleaseSpinLockFromDpcLevel(&AcpiPowerQueueLock);
        DPRINT("ACPIDevicePowerDpc: AcpiBuildDpcRunning %X\n", AcpiBuildDpcRunning);
        return;
    }

    AcpiPowerDpcRunning = TRUE;

    InitializeListHead(&list);

    do
    {
        AcpiPowerWorkDone = FALSE;

        if (!IsListEmpty(&AcpiPowerQueueList))
            ACPIInternalMovePowerList(&AcpiPowerQueueList, &AcpiPowerPhase0List);

        KeReleaseSpinLockFromDpcLevel(&AcpiPowerQueueLock);

        if (!IsListEmpty(&AcpiPowerPhase0List))
        {
            Status = ACPIDevicePowerProcessGenericPhase(&AcpiPowerPhase0List, AcpiDevicePowerProcessPhase0Dispatch, FALSE);
            if (NT_SUCCESS(Status) && Status != STATUS_PENDING)
                ACPIInternalMovePowerList(&AcpiPowerPhase0List, &AcpiPowerPhase1List);
        }

        if (!IsListEmpty(&AcpiPowerPhase1List) &&
            IsListEmpty(&AcpiPowerPhase0List))
        {
            Status = ACPIDevicePowerProcessGenericPhase(&AcpiPowerPhase1List, AcpiDevicePowerProcessPhase1Dispatch, FALSE);
            if (NT_SUCCESS(Status) && Status != STATUS_PENDING)
                ACPIInternalMovePowerList(&AcpiPowerPhase1List, &AcpiPowerPhase2List);
        }

        if (IsListEmpty(&AcpiPowerPhase0List) &&
            IsListEmpty(&AcpiPowerPhase1List) &&
            !IsListEmpty(&AcpiPowerPhase2List))
        {
            Status = ACPIDevicePowerProcessGenericPhase(&AcpiPowerPhase2List, AcpiDevicePowerProcessPhase2Dispatch, FALSE);
            if (NT_SUCCESS(Status) && Status != STATUS_PENDING)
                ACPIInternalMovePowerList(&AcpiPowerPhase2List, &AcpiPowerPhase3List);
        }

        if (IsListEmpty(&AcpiPowerPhase0List) &&
            IsListEmpty(&AcpiPowerPhase1List) &&
            IsListEmpty(&AcpiPowerPhase2List) &&
            !IsListEmpty(&AcpiPowerPhase3List))
        {
            Status = ACPIDevicePowerProcessPhase3();
            if (NT_SUCCESS(Status) && Status != STATUS_PENDING)
                ACPIInternalMovePowerList(&AcpiPowerPhase3List, &AcpiPowerPhase4List);
        }

        if (!IsListEmpty(&AcpiPowerPhase4List))
        {
            Status = ACPIDevicePowerProcessPhase4();
            if (NT_SUCCESS(Status) && Status != STATUS_PENDING)
                ACPIInternalMovePowerList(&AcpiPowerPhase4List, &AcpiPowerPhase5List);
        }

        if (!IsListEmpty(&AcpiPowerPhase5List))
        {
            Status = ACPIDevicePowerProcessGenericPhase(&AcpiPowerPhase5List, AcpiDevicePowerProcessPhase5Dispatch, TRUE);
        }

        KeAcquireSpinLockAtDpcLevel(&AcpiPowerQueueLock);
    }
    while (AcpiPowerWorkDone);

    AcpiPowerDpcRunning = FALSE;

    if (IsListEmpty(&AcpiPowerPhase0List) &&
        IsListEmpty(&AcpiPowerPhase1List) &&
        IsListEmpty(&AcpiPowerPhase2List) &&
        IsListEmpty(&AcpiPowerPhase3List) &&
        IsListEmpty(&AcpiPowerPhase4List) &&
        IsListEmpty(&AcpiPowerPhase5List))
    {
        DPRINT("ACPIDevicePowerDPC: Queues Empty. Terminating.\n");

        if (!IsListEmpty(&AcpiPowerSynchronizeList))
        {
            DPRINT1("ACPIDevicePowerDpc: FIXME\n");
            ASSERT(FALSE);
        }
    }

    KeReleaseSpinLockFromDpcLevel(&AcpiPowerQueueLock);

    if (!IsListEmpty(&list))
    {
        DPRINT1("ACPIDevicePowerDpc: FIXME\n");
        ASSERT(FALSE);
    }

    DPRINT("ACPIDevicePowerDpc: exit (%X,%X)\n", KeGetCurrentIrql(), KeGetCurrentThread());
}

VOID
NTAPI
ACPIDeviceInternalQueueRequest(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PACPI_POWER_REQUEST Request,
    _In_ ULONG Flags)
{
    if (Flags & 0x100)
    {
        InsertHeadList(&AcpiPowerSynchronizeList, &Request->ListEntry);
    }
    else if (IsListEmpty(&DeviceExtension->PowerInfo.PowerRequestListEntry))
    {
        InsertTailList(&DeviceExtension->PowerInfo.PowerRequestListEntry, &Request->SerialListEntry);

        if (Flags & 1)
        {
            InsertTailList(&AcpiPowerDelayedQueueList, &Request->ListEntry);
        }
        else
        {
            InsertTailList(&AcpiPowerQueueList, &Request->ListEntry);
        }
    }
    else
    {
        InsertTailList(&DeviceExtension->PowerInfo.PowerRequestListEntry, &Request->SerialListEntry);
    }

    AcpiPowerWorkDone = TRUE;

    if ((Flags & 1) || AcpiPowerDpcRunning)
        return;

    KeInsertQueueDpc(&AcpiPowerDpc, NULL, NULL);
}

VOID
NTAPI
ACPIDeviceIrpWaitWakeRequestComplete(
    _In_ PACPI_POWER_REQUEST Request)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
ACPIDeviceCancelWaitWakeIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
__cdecl
ACPIDeviceIrpWaitWakeRequestPending(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA Data,
    _In_ PVOID Context)
{
    PACPI_POWER_REQUEST Request = Context;
    PDEVICE_EXTENSION DeviceExtension;
    PIRP Irp;
    KIRQL Irql;

    DPRINT("ACPIDeviceIrpWaitWakeRequestPending: %p, %X\n", Request, InStatus);

    Irp = Request->Context;
    DeviceExtension = Request->DeviceExtension;

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT1("ACPIDeviceIrpWaitWakeRequestPending: %p, %X\n", Request, InStatus);
        Request->Status = InStatus;
        ACPIDeviceIrpWaitWakeRequestComplete(Request);
        return;
    }

    IoAcquireCancelSpinLock(&Irql);
    KeAcquireSpinLockAtDpcLevel(&AcpiPowerLock);

    InsertTailList(&AcpiPowerWaitWakeList, &Request->ListEntry);

    if (Irp->Cancel)
    {
        KeReleaseSpinLockFromDpcLevel(&AcpiPowerLock);
        ACPIDeviceCancelWaitWakeIrp(DeviceExtension->DeviceObject, Irp);
        return;
    }

    Request->u.WaitWakeRequest.Flags |= 0x40;

    ACPIWakeRemoveDevicesAndUpdate(NULL, NULL);

    IoSetCancelRoutine(Irp, ACPIDeviceCancelWaitWakeIrp);

    KeReleaseSpinLockFromDpcLevel(&AcpiPowerLock);
    IoReleaseCancelSpinLock(Irql);
}

VOID
NTAPI
ACPIWakeEnableDisablePciDevice(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ BOOLEAN PmeEnable)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
__cdecl
ACPIWakeEnableDisableAsyncCallBack(
    _In_ PAMLI_NAME_SPACE_OBJECT PowerObject,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA InData,
    _In_ PVOID Context)
{
    PACPI_PSW_CONTEXT PswContext = Context;
    PACPI_PSW_CONTEXT NextPswContext;
    PDEVICE_EXTENSION DeviceExtension;
    PAMLI_FN_ASYNC_CALLBACK CallBack;
    AMLI_OBJECT_DATA Data;
    ULONG Count;
    KIRQL Irql;
    BOOLEAN IsWakeSupportListEmpty = TRUE;
    NTSTATUS Status;

    DeviceExtension = PswContext->DeviceExtension;

    DPRINT1("ACPIWakeEnableDisableAsyncCallBack: InStatus %X\n", InStatus);

    KeAcquireSpinLock(&AcpiPowerLock, &Irql);

    RemoveEntryList(&PswContext->Link);

    if (!NT_SUCCESS(InStatus))
    {
        if (PswContext->IsEnable)
            Count = (DeviceExtension->PowerInfo.WakeSupportCount - PswContext->Count);
        else
            Count = (DeviceExtension->PowerInfo.WakeSupportCount + PswContext->Count);

        DPRINT1("ACPIWakeEnableDisableAsyncCallBack - RefCount: %lx %s %lx = %lx\n",
                DeviceExtension->PowerInfo.WakeSupportCount,
                (PswContext->IsEnable ? "-" : "+"),
                PswContext->Count,
                Count);

        if (PswContext->IsEnable)
            DeviceExtension->PowerInfo.WakeSupportCount -= PswContext->Count;
        else
            DeviceExtension->PowerInfo.WakeSupportCount += PswContext->Count;
    }

    KeReleaseSpinLock(&AcpiPowerLock, Irql);

    if ((DeviceExtension->Flags & 0x0800000000000000) && PswContext->IsEnable == TRUE)
        ACPIWakeEnableDisablePciDevice(DeviceExtension, 1);

    KeAcquireSpinLock(&AcpiPowerLock, &Irql);

    if (!IsListEmpty(&DeviceExtension->PowerInfo.WakeSupportList))
    {
        IsWakeSupportListEmpty = FALSE;
        NextPswContext = CONTAINING_RECORD(DeviceExtension->PowerInfo.WakeSupportList.Flink, ACPI_PSW_CONTEXT, Link);
    }

    KeReleaseSpinLock(&AcpiPowerLock, Irql);

    CallBack = PswContext->CallBack;
    CallBack(PowerObject, InStatus, InData, PswContext->Context);

    ExFreeToNPagedLookasideList(&PswContextLookAsideList, PswContext);

    if (IsWakeSupportListEmpty)
        return;

    RtlZeroMemory(&Data, sizeof(Data));

    Data.DataType = 1;
    Data.DataValue = ULongToPtr(NextPswContext->IsEnable != 0);

    if ((DeviceExtension->Flags & 0x0800000000000000) && !NextPswContext->IsEnable)
        ACPIWakeEnableDisablePciDevice(DeviceExtension, 0);

    Status = AMLIAsyncEvalObject(PowerObject, NULL, 1, &Data, (PVOID)ACPIWakeEnableDisableAsyncCallBack, NextPswContext);

    DPRINT1("ACPIWakeEnableDisableAsyncCallBack: Status %X\n", Status);

    if (Status != STATUS_PENDING)
        ACPIWakeEnableDisableAsyncCallBack(PowerObject, Status, NULL, NextPswContext);
}

NTSTATUS
NTAPI
ACPIWakeEnableDisableAsync(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ BOOLEAN IsEnable,
    _In_ PAMLI_FN_ASYNC_CALLBACK CallBack,
    _In_ PACPI_POWER_REQUEST Request)
{
    PAMLI_NAME_SPACE_OBJECT PowerObject = NULL;
    PACPI_PSW_CONTEXT PswContext;
    AMLI_OBJECT_DATA Data;
    KIRQL Irql;
    BOOLEAN IsWakeListEmpty = FALSE;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ACPIWakeEnableDisableAsync: %p, %X\n", DeviceExtension, IsEnable);

    if (IsEnable)
    {
        DeviceExtension->PowerInfo.WakeSupportCount++;

        DPRINT("ACPIWakeEnableDisableAsync: Count %X (+)\n", DeviceExtension->PowerInfo.WakeSupportCount);

        if (DeviceExtension->PowerInfo.WakeSupportCount != 1)
        {
            if (DeviceExtension->Flags & 0x800000000000000)
                ACPIWakeEnableDisablePciDevice(DeviceExtension, TRUE);

            goto Exit;
        }
    }
    else
    {
        ASSERT(DeviceExtension->PowerInfo.WakeSupportCount);
        DeviceExtension->PowerInfo.WakeSupportCount--;

        DPRINT("ACPIWakeEnableDisableAsync: Count %d (-)\n", DeviceExtension->PowerInfo.WakeSupportCount);

        if (DeviceExtension->PowerInfo.WakeSupportCount)
        {
            if (DeviceExtension->Flags & 0x800000000000000)
                ACPIWakeEnableDisablePciDevice(DeviceExtension, TRUE);

            goto Exit;
        }
    }

    PowerObject = DeviceExtension->PowerInfo.PowerObject[0];
    if (!PowerObject)
    {
        if (DeviceExtension->Flags & 0x800000000000000)
            ACPIWakeEnableDisablePciDevice(DeviceExtension, TRUE);

        goto Exit;
    }

    PswContext = ExAllocateFromNPagedLookasideList(&PswContextLookAsideList);
    if (PswContext)
    {
        PswContext->IsEnable = IsEnable;
        PswContext->CallBack = CallBack;
        PswContext->Context = Request;
        PswContext->DeviceExtension = DeviceExtension;
        PswContext->Count = 1;

        KeAcquireSpinLock(&AcpiPowerLock, &Irql);

        if (IsListEmpty(&DeviceExtension->PowerInfo.WakeSupportList))
            IsWakeListEmpty = TRUE;

        InsertTailList(&DeviceExtension->PowerInfo.WakeSupportList, &PswContext->Link);

        KeReleaseSpinLock(&AcpiPowerLock, Irql);

        if (!IsWakeListEmpty)
        {
            DPRINT("ACPIWakeEnableDisableAsync: ret STATUS_PENDING\n", STATUS_PENDING);
            return STATUS_PENDING;
        }

        if ((DeviceExtension->Flags & 0x800000000000000) && !PswContext->IsEnable)
            ACPIWakeEnableDisablePciDevice(DeviceExtension, FALSE);

        RtlZeroMemory(&Data, sizeof(Data));

        Data.DataType = 1;
        Data.DataValue = ULongToPtr(IsEnable != 0);

        Status = AMLIAsyncEvalObject(PowerObject, NULL, 1, &Data, ACPIWakeEnableDisableAsyncCallBack, PswContext);

        DPRINT("ACPIWakeEnableDisableAsync: Status %X\n", Status);

        if (Status != STATUS_PENDING)
            ACPIWakeEnableDisableAsyncCallBack(PowerObject, Status, NULL, PswContext);

        return STATUS_PENDING;
    }

    Status = STATUS_INSUFFICIENT_RESOURCES;

Exit:

    DPRINT("ACPIWakeEnableDisableAsync: Status %X\n", Status);

    CallBack(PowerObject, Status, NULL, Request);

    return STATUS_PENDING;
}

NTSTATUS
NTAPI
ACPIDeviceInitializePowerRequest(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ POWER_STATE State,
    _In_ PVOID CallBack,
    _In_ PVOID Context,
    _In_ POWER_ACTION ShutdownType,
    _In_ ACPI_POWER_REQUEST_TYPE RequestType,
    _In_ ULONG Flags)
{
    PACPI_POWER_REQUEST Request;
    KIRQL OldIrql;
    NTSTATUS Status;

    DPRINT("ACPIDeviceInitializePowerRequest: %p, %X\n", DeviceExtension, State.DeviceState);

    Request = ExAllocateFromNPagedLookasideList(&RequestLookAsideList);
    if (!Request)
    {
        if (CallBack)
        {
            DPRINT1("ACPIDeviceInitializePowerRequest: FIXME\n");
            ASSERT(FALSE);
        }

        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    RtlZeroMemory(Request, sizeof(*Request));

    Request->Status = STATUS_SUCCESS;
    Request->CallBack = CallBack;
    Request->Context = Context;
    Request->Signature = '_SGP';
    Request->DeviceExtension = DeviceExtension;
    Request->WorkDone = 3;
    Request->RequestType = RequestType;

    InitializeListHead(&Request->ListEntry);
    InitializeListHead(&Request->SerialListEntry);

    KeAcquireSpinLock(&AcpiPowerQueueLock, &OldIrql);

    if (RequestType == AcpiPowerRequestDevice)
    {
        if (InterlockedCompareExchange(&DeviceExtension->HibernatePathCount, 0, 0))
        {
            if (ShutdownType == PowerActionHibernate)
            {
                if (State.SystemState == 4)
                    Flags |= 0x10;
            }
            else if (State.SystemState == 1)
            {
                Flags |= 0x20;
            }
        }

        Request->u.DevicePowerRequest.DevicePowerState = State.DeviceState;
        Request->u.DevicePowerRequest.Flags = Flags;

        if (State.DeviceState > DeviceExtension->PowerInfo.PowerState)
        {
            if (DeviceExtension->DeviceObject)
                PoSetPowerState(DeviceExtension->DeviceObject, DevicePowerState, State);
        }

        goto Finish;
    }

    if (RequestType == AcpiPowerRequestSystem)
    {
        Request->u.DevicePowerRequest.Flags = State.SystemState;
        Request->u.SystemPowerRequest.SystemPowerAction = ShutdownType;
        goto Finish;
    }

    if (RequestType == AcpiPowerRequestWaitWake)
    {
        Request->u.DevicePowerRequest.DevicePowerState = State.DeviceState;
        Request->u.DevicePowerRequest.Flags = Flags;

        KeReleaseSpinLock(&AcpiPowerQueueLock, OldIrql);

        Status = ACPIWakeEnableDisableAsync(DeviceExtension, 1, ACPIDeviceIrpWaitWakeRequestPending, Request);
        if (Status == STATUS_PENDING)
        {
            return STATUS_MORE_PROCESSING_REQUIRED;
        }

        return Status;
    }

    if (RequestType == AcpiPowerRequestWarmEject)
    {
        Request->u.DevicePowerRequest.DevicePowerState = State.DeviceState;
    }
    else if (RequestType == AcpiPowerRequestSynchronize)
    {
        Request->u.DevicePowerRequest.Flags = Flags;
    }

Finish:

    if (!(Flags & 2))
    {
        ACPIDeviceInternalQueueRequest(DeviceExtension, Request, Flags);
    }

    KeReleaseSpinLock(&AcpiPowerQueueLock, OldIrql);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
ACPIDeviceInternalDelayedDeviceRequest(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ DEVICE_POWER_STATE DeviceState,
    _In_ PVOID CallBack,
    _In_ PIRP Irp)
{
    POWER_STATE PowerState;
    NTSTATUS Status;

    DPRINT("ACPIDeviceInternalDelayedDeviceRequest: Irp %p, Transition to D%X\n", Irp, (DeviceState - 1));

    PowerState.DeviceState = DeviceState;

    Status = ACPIDeviceInitializePowerRequest(DeviceExtension, PowerState, CallBack, Irp, 0, 0, 9);
    if (Status == STATUS_MORE_PROCESSING_REQUIRED)
        Status = STATUS_PENDING;

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildProcessDevicePhasePsc(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension;
    PACPI_DEVICE_POWER_NODE* PowerNodes;
    PACPI_DEVICE_POWER_NODE powerNode;
    DEVICE_POWER_STATE* OutDevicePowerMatrix;
    SYSTEM_POWER_STATE systemState = 2;
    DEVICE_POWER_STATE deviceState;
    DEVICE_POWER_STATE State;
    NTSTATUS Status;

    DeviceExtension = BuildRequest->Context;
    BuildRequest->BuildReserved1 = 0;

    DeviceExtension->PowerInfo.PowerObject[4] = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, '3SP_');

    KeAcquireSpinLockAtDpcLevel(&AcpiPowerLock);

    OutDevicePowerMatrix = &DeviceExtension->PowerInfo.DevicePowerMatrix[2];
    do
    {
        deviceState = 1;
        PowerNodes = &DeviceExtension->PowerInfo.PowerNode[1];

        while (TRUE)
        {
            powerNode = *PowerNodes;
            if (powerNode)
            {
                do
                {
                    if (powerNode->SystemState < systemState)
                        break;

                    powerNode = powerNode->Next;
                }
                while (powerNode);

                if (!powerNode)
                    break;
            }

            deviceState++;
            PowerNodes++;

            if (deviceState > 3)
                goto Next;
        }

        DPRINT("ACPIBuildProcessDevicePhasePsc: D%X <-> S%X\n", (deviceState - 1), (systemState - 1));

        *OutDevicePowerMatrix = deviceState;
Next:
        systemState++;
        OutDevicePowerMatrix++;
    }
    while (systemState <= 5);

    DeviceExtension->PowerInfo.DeviceWakeLevel = DeviceExtension->PowerInfo.DevicePowerMatrix[DeviceExtension->PowerInfo.SystemWakeLevel];

    KeReleaseSpinLockFromDpcLevel(&AcpiPowerLock);

    State = 1;

    if (DeviceExtension->Flags & 0x0000000080000000)
    {
        State = 4;
        goto Finish;
    }

    if (!BuildRequest->ChildObject)
    {
        goto Finish;
    }

    if (!NT_SUCCESS(BuildRequest->Status))
    {
        goto Finish;
    }

    if (DeviceExtension->Flags & 0x0000000000080000)
    {
        AMLIFreeDataBuffs(&BuildRequest->Device.Data, 1);
        DeviceExtension->PowerInfo.PowerState = 1;
        goto Finish;
    }

    if (BuildRequest->Device.Data.DataType != 1)
    {
        DPRINT1("ACPIBuildProcessDevicePhasePsc: KeBugCheckEx()\n");
        KeBugCheckEx(0xA5, 8, (ULONG_PTR)DeviceExtension, (ULONG_PTR)BuildRequest->ChildObject, BuildRequest->Device.Data.DataType);
    }

    if ((ULONG)BuildRequest->Device.Data.DataValue < 4)
        State = DevicePowerStateTranslation[(ULONG)BuildRequest->Device.Data.DataValue];
    else
        State = 0;

    AMLIFreeDataBuffs(&BuildRequest->Device.Data, 1);

Finish:

    Status = ACPIDeviceInternalDelayedDeviceRequest(DeviceExtension, State, NULL, NULL);

    DPRINT("ACPIBuildProcessDevicePhasePsc: Status %X\n", Status);

    ACPIBuildCompleteGeneric(NULL, Status, NULL, BuildRequest);

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildProcessPowerResourceFailure(
    _In_ PACPI_BUILD_REQUEST Entry)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIBuildProcessPowerResourcePhase0(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PAMLI_NAME_SPACE_OBJECT NsObject;
    PACPI_POWER_DEVICE_NODE Node;
    NTSTATUS Status;

    Node = BuildRequest->Context;
    BuildRequest->BuildReserved1 = 4;

    NsObject = ACPIAmliGetNamedChild(Node->PowerObject, 'FFO_');
    if (!NsObject)
    {
        DPRINT1("ACPIBuildProcessPowerResourcePhase0: KeBugCheckEx()\n");
        KeBugCheckEx(0xA5, 0xE, (ULONG_PTR)Node->PowerObject, 'FFO_', 0);
    }
    Node->PowerOffObject = NsObject;

    NsObject = ACPIAmliGetNamedChild(Node->PowerObject, '_NO_');
    if (!NsObject)
    {
        DPRINT1("ACPIBuildProcessPowerResourcePhase0: KeBugCheckEx()\n");
        KeBugCheckEx(0xA5, 0xE, (ULONG_PTR)Node->PowerObject, '_NO_', 0);
    }
    Node->PowerOnObject = NsObject;

    NsObject = ACPIAmliGetNamedChild(Node->PowerObject, 'ATS_');
    if (!NsObject)
    {
        DPRINT1("ACPIBuildProcessPowerResourcePhase0: KeBugCheckEx()\n");
        KeBugCheckEx(0xA5, 0xE, (ULONG_PTR)Node->PowerObject, 'ATS_', 0);
    }

    RtlZeroMemory(&BuildRequest->Device.Data, sizeof(BuildRequest->Device.Data));

    BuildRequest->ChildObject = NsObject;

    Status = AMLIAsyncEvalObject(NsObject, &BuildRequest->Device.Data, 0, NULL, ACPIBuildCompleteGeneric, BuildRequest);
    if (Status != STATUS_PENDING)
        ACPIBuildCompleteGeneric(NsObject, Status, &BuildRequest->Device.Data, BuildRequest);

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildProcessPowerResourcePhase1(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PACPI_POWER_DEVICE_NODE Node;

    Node = BuildRequest->Context;
    BuildRequest->BuildReserved1 = 0;

    if (BuildRequest->Device.Data.DataType != 1)
    {
        KeBugCheckEx(0xA5,
                     8,
                     (ULONG_PTR)Node->PowerObject,
                     (ULONG_PTR)BuildRequest->ChildObject,
                     BuildRequest->Device.Data.DataType);
    }

    KeAcquireSpinLockAtDpcLevel(&AcpiPowerLock);

    ACPIInternalUpdateFlags(&Node->Flags, 2, FALSE);
    ACPIInternalUpdateFlags(&Node->Flags, 1, (((ULONG_PTR)BuildRequest->Device.Data.DataValue & 1) == 0));

    KeReleaseSpinLockFromDpcLevel(&AcpiPowerLock);

    AMLIFreeDataBuffs(&BuildRequest->Device.Data, 1);
    ACPIBuildCompleteGeneric(NULL, STATUS_SUCCESS, NULL, BuildRequest);

    return STATUS_SUCCESS;
}

VOID
NTAPI
ACPIInternalGetDispatchTable(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PDEVICE_EXTENSION* OutDeviceExtension,
    _Out_ PIRP_DISPATCH_TABLE* OutIrpDispatch)
{
    PDEVICE_EXTENSION DeviceExtension;
    KIRQL OldIrql;

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &OldIrql);

    DeviceExtension = DeviceObject->DeviceExtension;

    *OutDeviceExtension = DeviceExtension;

    if (DeviceExtension)
        *OutIrpDispatch = DeviceExtension->DispatchTable;
    else
        *OutIrpDispatch = NULL;

    KeReleaseSpinLock(&AcpiDeviceTreeLock, OldIrql);
}

LONG
NTAPI
ACPIInternalDecrementIrpReferenceCount(
    _In_ PDEVICE_EXTENSION DeviceExtension)
{
    LONG OldReferenceCount;

    OldReferenceCount = InterlockedDecrement(&DeviceExtension->OutstandingIrpCount);

    if (!OldReferenceCount)
        OldReferenceCount = KeSetEvent(DeviceExtension->RemoveEvent, 0, FALSE);

    return OldReferenceCount;
}

NTSTATUS
NTAPI
ACPIDispatchIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    PDRIVER_DISPATCH DispatchEntry;
    PIRP_DISPATCH_TABLE IrpDispatch;
    PIO_STACK_LOCATION IoStack;
    KEVENT Event;
    LONG OldReferenceCount;
    UCHAR MinorFunction;
    UCHAR MajorFunction;
    NTSTATUS Status;

    DPRINT("ACPIDispatchIrp: Device %X, Irp %X\n", DeviceObject, Irp);

    IoStack = Irp->Tail.Overlay.CurrentStackLocation;

    ACPIInternalGetDispatchTable(DeviceObject, &DeviceExtension, &IrpDispatch);

    if (!DeviceExtension || (DeviceExtension->Flags & 4) || DeviceExtension->Signature != '_SGP')
    {
        DPRINT1("ACPIDispatchIrp: Deleted Device %p got Irp %p\n", DeviceObject, Irp);

        if (IoStack->MajorFunction == IRP_MJ_POWER)
        {
            DPRINT1("ACPIDispatchIrp: FIXME\n");
            ASSERT(FALSE);
            Status = STATUS_NOT_IMPLEMENTED;
        }
        else
        {
            DPRINT1("ACPIDispatchIrp: FIXME\n");
            ASSERT(FALSE);
            Status = STATUS_NOT_IMPLEMENTED;
        }

        return Status;
    }

    ASSERT(DeviceExtension->RemoveEvent == NULL);

    MajorFunction = IoStack->MajorFunction;
    MinorFunction = IoStack->MinorFunction;

    if (IoStack->MajorFunction == IRP_MJ_POWER)
    {
        if (MinorFunction >= 4)
            DispatchEntry = IrpDispatch->Power[4];
        else
            DispatchEntry = IrpDispatch->Power[MinorFunction];

        InterlockedIncrement(&DeviceExtension->OutstandingIrpCount);

        Status = DispatchEntry(DeviceObject, Irp);

        ACPIInternalDecrementIrpReferenceCount(DeviceExtension);

        return Status;
    }

    if (MajorFunction != IRP_MJ_PNP)
    {
        if (MajorFunction == IRP_MJ_DEVICE_CONTROL)
        {
            DispatchEntry = IrpDispatch->DeviceControl;
        }
        else if (MajorFunction == IRP_MJ_CREATE || MinorFunction == IRP_MJ_CLOSE)
        {
            DispatchEntry = IrpDispatch->CreateClose;
        }
        else if (MajorFunction == IRP_MJ_SYSTEM_CONTROL)
        {
            DispatchEntry = IrpDispatch->SystemControl;
        }
        else
        {
            DispatchEntry = IrpDispatch->Other;
        }

        InterlockedIncrement(&DeviceExtension->OutstandingIrpCount);

        Status = DispatchEntry(DeviceObject, Irp);

        ACPIInternalDecrementIrpReferenceCount(DeviceExtension);

        return Status;
    }

    /* IRP_MJ_PNP */

    if (MinorFunction == IRP_MN_START_DEVICE)
    {
        DispatchEntry = (PDRIVER_DISPATCH)IrpDispatch->PnpStartDevice;
        InterlockedIncrement(&DeviceExtension->OutstandingIrpCount);
        Status = DispatchEntry(DeviceObject, Irp);
        ACPIInternalDecrementIrpReferenceCount(DeviceExtension);
        return Status;
    }

    if (MinorFunction >= IRP_MN_QUERY_LEGACY_BUS_INFORMATION)
        DispatchEntry = IrpDispatch->Pnp[IRP_MN_QUERY_LEGACY_BUS_INFORMATION];
    else
        DispatchEntry = IrpDispatch->Pnp[MinorFunction];

    if (MinorFunction == IRP_MN_REMOVE_DEVICE || MinorFunction == IRP_MN_SURPRISE_REMOVAL)
    {
        KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
        DeviceExtension->RemoveEvent = &Event;

        DPRINT1("ACPIDispatchIrp: FIXME ACPIWakeEmptyRequestQueue()\n");
        ASSERT(FALSE);

        OldReferenceCount = InterlockedDecrement(&DeviceExtension->OutstandingIrpCount);
        ASSERT(OldReferenceCount >= 0);

        if (OldReferenceCount != 0)
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

        InterlockedIncrement(&DeviceExtension->OutstandingIrpCount);
        DeviceExtension->RemoveEvent = NULL;

        Status = DispatchEntry(DeviceObject, Irp);

        return Status;
    }

    InterlockedIncrement(&DeviceExtension->OutstandingIrpCount);

    Status = DispatchEntry(DeviceObject, Irp);

    ACPIInternalDecrementIrpReferenceCount(DeviceExtension);

    return Status;
}

VOID
NTAPI
ACPIFilterFastIoDetachCallback(
    _In_ PDEVICE_OBJECT SourceDevice,
    _In_ PDEVICE_OBJECT TargetDevice)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
ACPIBuildProcessQueueList(VOID)
{
    PACPI_BUILD_REQUEST BuildRequest;
    PLIST_ENTRY Entry;

    DPRINT("ACPIBuildProcessQueueList: start\n");

    Entry = AcpiBuildQueueList.Flink;
    while (Entry != &AcpiBuildQueueList)
    {
        BuildRequest = CONTAINING_RECORD(Entry, ACPI_BUILD_REQUEST, Link);

        RemoveEntryList(Entry);
        InsertTailList(BuildRequest->ListHeadForInsert, Entry);

        BuildRequest->Flags &= ~0x1000;
        BuildRequest->ListHeadForInsert = NULL;

        Entry = AcpiBuildQueueList.Flink;
    }

    DPRINT("ACPIBuildProcessQueueList: exit\n");
}

NTSTATUS
NTAPI
ACPIBuildProcessSynchronizationList(
    _In_ PLIST_ENTRY SynchronizationList)
{
    PACPI_BUILD_REQUEST BuildRequest;
    PLIST_ENTRY Entry;
    BOOLEAN Result = TRUE;

    DPRINT("ACPIBuildProcessSynchronizationList: %p\n", SynchronizationList);

    Entry = SynchronizationList->Flink;
    while (Entry != SynchronizationList)
    {
        BuildRequest = CONTAINING_RECORD(Entry, ACPI_BUILD_REQUEST, Link);

        Entry = Entry->Flink;

        if (!IsListEmpty(BuildRequest->Synchronize.ListHead))
        {
            Result = FALSE;
            continue;
        }

        DPRINT("ACPIBuildProcessSynchronizationList(%4s) = STATUS_SUCCESS\n", &BuildRequest->Synchronize.Context);

        ACPIBuildProcessGenericComplete(BuildRequest);
    }

    return (Result ? STATUS_SUCCESS : STATUS_PENDING);
}

NTSTATUS
NTAPI
ACPIBuildProcessGenericList(
    _In_ PLIST_ENTRY GenericList,
    _In_ PACPI_BUILD_DISPATCH* BuildDispatch)
{
    PACPI_BUILD_DISPATCH CallBack = NULL;
    PACPI_BUILD_REQUEST BuildRequest;
    PLIST_ENTRY Entry;
    PLIST_ENTRY NextValue;
    ULONG Idx;
    BOOLEAN allWorkComplete = TRUE;
    //NTSTATUS status = STATUS_SUCCESS;

    DPRINT("ACPIBuildProcessGenericList: %p, %p\n", BuildDispatch, *BuildDispatch);

    Entry = GenericList->Flink;
    while (Entry != GenericList)
    {
        BuildRequest = CONTAINING_RECORD(Entry, ACPI_BUILD_REQUEST, Link);

        //DPRINT("ACPIBuildProcessGenericList: %X '%s', %X\n", BuildRequest, NameSegString(BuildRequest->Signature), BuildRequest->WorkDone);

        NextValue = Entry->Flink;
        Idx = InterlockedCompareExchange(&(BuildRequest->WorkDone), 1, 1);

        //DPRINT("ACPIBuildProcessGenericList: [%X] %p, %p\n", Idx, GenericList, Entry);

        CallBack = BuildDispatch[Idx];
        if (!CallBack)
        {
            allWorkComplete = FALSE;
            Entry = NextValue;
            continue;
        }

        if (Idx != 2)
            BuildRequest->BuildReserved0 = Idx;

        Idx = InterlockedCompareExchange(&(BuildRequest->WorkDone), 1, Idx);
        /*status =*/ (CallBack)(BuildRequest);
        //DPRINT("ACPIBuildProcessGenericList: [%X] status %X\n", Idx, status);

        if (Idx == 0 || Idx == 2)
            Entry = NextValue;
    }

    DPRINT("ACPIBuildProcessGenericList: status %X\n", allWorkComplete ? STATUS_SUCCESS : STATUS_PENDING);

    return (allWorkComplete ? STATUS_SUCCESS : STATUS_PENDING);
}

VOID
NTAPI
ACPIBuildDeviceDpc(
    _In_ PKDPC Dpc,
    _In_ PVOID DeferredContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2)
{
    NTSTATUS Status;

    KeAcquireSpinLockAtDpcLevel(&AcpiBuildQueueLock);

    if (AcpiBuildDpcRunning)
    {
        KeReleaseSpinLockFromDpcLevel(&AcpiBuildQueueLock);
        DPRINT("ACPIBuildDeviceDpc: AcpiBuildDpcRunning %X\n", AcpiBuildDpcRunning);
        return;
    }

    AcpiBuildDpcRunning = TRUE;

    do
    {
        AcpiBuildWorkDone = FALSE;

        if (!IsListEmpty(&AcpiBuildQueueList))
            ACPIBuildProcessQueueList();

        KeReleaseSpinLockFromDpcLevel(&AcpiBuildQueueLock);

        if (!IsListEmpty(&AcpiBuildRunMethodList))
        {
            Status = ACPIBuildProcessGenericList(&AcpiBuildRunMethodList, AcpiBuildRunMethodDispatch);

            KeAcquireSpinLockAtDpcLevel(&AcpiBuildQueueLock);

            if (Status == STATUS_PENDING)
            {
                DPRINT("ACPIBuildDeviceDpc: continue Status == STATUS_PENDING\n");
                continue;
            }

            if (!IsListEmpty(&AcpiBuildQueueList))
            {
                AcpiBuildWorkDone = TRUE;
                continue;
            }

            KeReleaseSpinLockFromDpcLevel(&AcpiBuildQueueLock);
        }

        if (!IsListEmpty(&AcpiBuildOperationRegionList))
        {
            DPRINT1("ACPIBuildDeviceDpc: FIXME\n");
            ASSERT(FALSE);
        }

        if (!IsListEmpty(&AcpiBuildPowerResourceList))
        {
            Status = ACPIBuildProcessGenericList(&AcpiBuildPowerResourceList, AcpiBuildPowerResourceDispatch);
            if (Status == STATUS_PENDING)
            {
                KeAcquireSpinLockAtDpcLevel(&AcpiBuildQueueLock);
                continue;
            }
        }

        if (!IsListEmpty(&AcpiBuildDeviceList))
            Status = ACPIBuildProcessGenericList(&AcpiBuildDeviceList, AcpiBuildDeviceDispatch);

        if (!IsListEmpty(&AcpiBuildThermalZoneList))
            ACPIBuildProcessGenericList(&AcpiBuildThermalZoneList, AcpiBuildThermalZoneDispatch);

        if (IsListEmpty(&AcpiBuildDeviceList) &&
            IsListEmpty(&AcpiBuildOperationRegionList) &&
            IsListEmpty(&AcpiBuildPowerResourceList) &&
            IsListEmpty(&AcpiBuildRunMethodList) &&
            IsListEmpty(&AcpiBuildThermalZoneList))
        {
            KeAcquireSpinLockAtDpcLevel(&AcpiPowerQueueLock);

            if (!IsListEmpty(&AcpiPowerDelayedQueueList))
            {
                ACPIInternalMoveList(&AcpiPowerDelayedQueueList, &AcpiPowerQueueList);

                if (!AcpiPowerDpcRunning)
                    KeInsertQueueDpc(&AcpiPowerDpc, NULL, NULL);
            }

            KeReleaseSpinLockFromDpcLevel(&AcpiPowerQueueLock);
        }

        if (!IsListEmpty(&AcpiBuildSynchronizationList))
        {
            Status = ACPIBuildProcessSynchronizationList(&AcpiBuildSynchronizationList);
            DPRINT("ACPIBuildDeviceDpc: Status %X, AcpiBuildWorkDone %X\n", Status, AcpiBuildWorkDone);
        }

        KeAcquireSpinLockAtDpcLevel(&AcpiBuildQueueLock);
    }
    while (AcpiBuildWorkDone);

    AcpiBuildDpcRunning = FALSE;

    KeReleaseSpinLockFromDpcLevel(&AcpiBuildQueueLock);

    DPRINT("ACPIBuildDeviceDpc: exit (%p)\n", Dpc);
}

VOID
NTAPI
ACPISetDeviceWorker(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ ULONG Events)
{
    BOOLEAN IsNotBusy;
    KIRQL Irql;

    DPRINT("ACPISetDeviceWorker: %X, %X\n", DeviceExtension, Events);

    KeAcquireSpinLock(&ACPIWorkerSpinLock, &Irql);

    IsNotBusy = FALSE;

    DeviceExtension->WorkQueue.PendingEvents |= Events;

    if (!DeviceExtension->WorkQueue.Link.Flink)
    {
        InsertTailList(&ACPIDeviceWorkQueue, &DeviceExtension->WorkQueue.Link);

        IsNotBusy = (ACPIWorkerBusy == FALSE);
        ACPIWorkerBusy = TRUE;
    }

    KeReleaseSpinLock(&ACPIWorkerSpinLock, Irql);

    if (IsNotBusy)
        ExQueueWorkItem(&ACPIWorkItem, DelayedWorkQueue);
}

VOID
NTAPI
ACPIGpeUpdateCurrentEnable(
    _In_ ULONG ix,
    _In_ ULONG Complete)
{
    GpePending[ix] &= ~Complete;
    GpeCurEnable[ix] |= (Complete & (GpeWakeEnable[ix] | GpeEnable[ix]) & ~(~GpeWakeEnable[ix] & GpeWakeHandler[ix]));
}

VOID
__cdecl
ACPIInterruptEventCompletion(
    _In_ PAMLI_NAME_SPACE_OBJECT Object,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA Data,
    _In_ PVOID InContext)
{
    ULONG Context = (ULONG)InContext;
    KIRQL Irql;

    KeAcquireSpinLock(&GpeTableLock, &Irql);

    if (NT_SUCCESS(InStatus))
    {
        AcpiGpeWorkDone = TRUE;

        GpeComplete[Context & 0xFF] |= ((Context & 0xFF00) >> 8);

        if (!AcpiGpeDpcRunning)
            KeInsertQueueDpc(&AcpiGpeDpc, NULL, NULL);

        goto Exit;
    }

    GpeRunMethod[Context & 0xFF] |= ((Context & 0xFF00) >> 8);

    if (!AcpiGpeDpcScheduled)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

Exit:

    KeReleaseSpinLock(&GpeTableLock, Irql);
}

VOID
NTAPI
ACPIInterruptDispatchEventDpc(
    _In_ PKDPC Dpc,
    _In_ PVOID DeferredContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2)
{
    PAMLI_NAME_SPACE_OBJECT NsObject;
    NTSTATUS Status;
    ULONG GpeIndex;
    ULONG GpeSize;
    ULONG ix;
    UCHAR gpeRunMethod[32];
    UCHAR gpeWakeEnable[32];
    UCHAR gpeIsLevel[32];
    UCHAR gpeComplete[32];
    UCHAR GpeStatus;
    UCHAR RunMethod;
    UCHAR Complete;
    UCHAR GpeMask;
    UCHAR Bit;
    UCHAR Context[4];
    CHAR HexDigit[] = "0123456789ABCDEF";
    static CHAR ObjPath[11] = "\\_GPE._L00";

    GpeSize = AcpiInformation->GpeSize;

    KeAcquireSpinLockAtDpcLevel(&GpeTableLock);

    AcpiGpeDpcScheduled = FALSE;

    if (AcpiGpeDpcRunning)
        goto Exit;

    AcpiGpeDpcRunning = TRUE;

    RtlZeroMemory(gpeComplete, sizeof(gpeComplete));

    do
    {
        static int bWarnedOnce = 0;
        if (!bWarnedOnce)
        {
            bWarnedOnce++;
            DPRINT1("ACPIInterruptDispatchEventDpc: AcpiGpeDpcRunning %X\n", AcpiGpeDpcRunning);
        }
    } while (0);

    do
    {
        AcpiGpeWorkDone = FALSE;

        for (ix = 0; ix < GpeSize; )
        {
            gpeIsLevel[ix] = GpeIsLevel[ix];
            gpeRunMethod[ix] = GpeRunMethod[ix];
            gpeComplete[ix] |= GpeComplete[ix];

            ix++;

            GpeRunMethod[ix] = 0;
            GpeComplete[ix] = 0;
        }

        RtlCopyMemory(gpeWakeEnable, GpeWakeEnable, GpeSize);

        KeReleaseSpinLockFromDpcLevel(&GpeTableLock);

        for (ix = 0; ix < GpeSize; ix++)
        {
            Complete = 0;

            for (RunMethod = gpeRunMethod[ix]; RunMethod; )
            {
                Bit = FirstSetLeftBit[RunMethod];
                GpeMask = (1 << Bit);
                RunMethod &= ~GpeMask;
                GpeIndex = ACPIGpeRegisterToGpeIndex(ix, Bit);

                if (!(GpeMask & GpeHandlerType[ix]))
                {
                    if (GpeMask & (UCHAR)gpeWakeEnable[ix])
                    {
                        UNIMPLEMENTED_DBGBREAK();
                    }
                    else
                    {
                        UNIMPLEMENTED_DBGBREAK();
                    }
                }
                else
                {
                    ObjPath[7] = (GpeMask & gpeIsLevel[ix]) != 0 ? 'L' : 'E'; // 0x4C : 0x45
                    ObjPath[8] = HexDigit[GpeIndex >> 4];
                    ObjPath[9] = HexDigit[GpeIndex & 0xF];

                    Status = AMLIGetNameSpaceObject(ObjPath, NULL, &NsObject, 0);
                    if (!NT_SUCCESS(Status))
                    {
                        DPRINT1("ACPIInterruptDispatchEventDpc: Status %X\n", Status);
                        continue;
                    }

                    Context[0] = ix;
                    Context[1] = GpeMask;
                    Context[2] = gpeIsLevel[ix];

                    Status = AMLIAsyncEvalObject(NsObject, NULL, 0, NULL, ACPIInterruptEventCompletion, (PVOID)Context);
                    if (NT_SUCCESS(Status))
                    {
                        if (Status != 0x103)
                            Complete |= GpeMask;

                        continue;
                    }

                    DPRINT1("ACPIInterruptDispatchEventDpc: Status %X\n", Status);
                    UNIMPLEMENTED_DBGBREAK();
                }
            }

            gpeComplete[ix] |= Complete;
        }

        KeAcquireSpinLockAtDpcLevel(&GpeTableLock);
    }
    while (AcpiGpeWorkDone);

    for (ix = 0; ix < GpeSize; ix++)
    {
        Complete = gpeComplete[ix];

        GpeStatus = (Complete & gpeIsLevel[ix]);
        if (GpeStatus)
            ACPIWriteGpeStatusRegister(ix, GpeStatus);

        ACPIGpeUpdateCurrentEnable(ix, Complete);
    }

    AcpiGpeDpcRunning = FALSE;
    ACPIGpeEnableDisableEvents(1);

Exit:

    KeReleaseSpinLockFromDpcLevel(&GpeTableLock);
}

/* HAL FUNCTIOS *************************************************************/

VOID
NTAPI
ACPIGpeHalEnableDisableEvents(
    _In_ BOOLEAN IsEnable)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
ACPIWakeEnableWakeEvents(VOID)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
ACPIInitHalDispatchTable(VOID)
{
    AcpiHalDispatchTable.Signature = 'ACPI';
    AcpiHalDispatchTable.Version = 1;
    AcpiHalDispatchTable.Function1 = ACPIGpeHalEnableDisableEvents;
    AcpiHalDispatchTable.Function2 = ACPIEnableInitializeACPI;
    AcpiHalDispatchTable.Function3 = ACPIWakeEnableWakeEvents;

    HalInitPowerManagement((PPM_DISPATCH_TABLE)&AcpiHalDispatchTable, &PmHalDispatchTable);
}

/* ACPI interface FUNCTIONS *************************************************/

VOID
NTAPI
AcpiNullReference(
    _In_ PVOID Context)
{
    ;
}

NTSTATUS
NTAPI
ACPIVectorConnect(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG GpeNumber,
    _In_ KINTERRUPT_MODE Mode,
    _In_ BOOLEAN Shareable,
    _In_ PGPE_SERVICE_ROUTINE ServiceRoutine,
    _In_ PVOID ServiceContext,
    _In_ PVOID ObjectContext)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIVectorDisconnect(
    _In_ PVOID ObjectContext)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIVectorEnable(
    _In_ PDEVICE_OBJECT Context,
    _In_ PVOID ObjectContext)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIVectorDisable(
    _In_ PDEVICE_OBJECT Context,
    _In_ PVOID ObjectContext)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIVectorClear(
    _In_ PDEVICE_OBJECT Context,
    _In_ PVOID ObjectContext)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

PACPI_POWER_INFO
NTAPI
OSPowerFindPowerInfoByContext(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PDEVICE_EXTENSION DeviceExtension;

    ASSERT(DeviceObject != NULL);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    ASSERT(DeviceExtension->Signature == '_SGP');//ACPI_SIGNATURE

    return &DeviceExtension->PowerInfo;
}

NTSTATUS
NTAPI
ACPIRegisterForDeviceNotifications(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PDEVICE_NOTIFY_CALLBACK NotificationHandler,
    _In_ PVOID NotificationContext)
{
    PACPI_POWER_INFO PowerInfo;
    KIRQL Irql;

    DPRINT("ACPIRegisterForDeviceNotifications: %p, %X, %X\n", DeviceObject, NotificationHandler, NotificationContext);

    PowerInfo = OSPowerFindPowerInfoByContext(DeviceObject);
    if (!PowerInfo)
    {
        DPRINT1("ACPIRegisterForDeviceNotifications: STATUS_NO_SUCH_DEVICE\n");
        return STATUS_NO_SUCH_DEVICE;
    }

    KeAcquireSpinLock(&NotifyHandlerLock, &Irql);

    if (PowerInfo->DeviceNotifyHandler)
    {
        DPRINT1("ACPIRegisterForDeviceNotifications: STATUS_UNSUCCESSFUL\n");
        KeReleaseSpinLock(&NotifyHandlerLock, Irql);
        return STATUS_UNSUCCESSFUL;
    }

    PowerInfo->DeviceNotifyHandler = NotificationHandler;
    PowerInfo->HandlerContext = NotificationContext;

    KeReleaseSpinLock(&NotifyHandlerLock, Irql);

    return STATUS_SUCCESS;
}

VOID
NTAPI
ACPIUnregisterForDeviceNotifications(
    _In_ PDEVICE_OBJECT Context,
    _In_ PDEVICE_NOTIFY_CALLBACK NotificationHandler)
{
    UNIMPLEMENTED_DBGBREAK();
}

/* FDO PNP FUNCTIOS *********************************************************/

NTSTATUS
NTAPI
ACPIRootIrpCompleteRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PRKEVENT Event = Context;
    KeSetEvent(Event, 0, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

VOID
NTAPI
ACPIDevicePowerNotifyEvent(
    _In_ PVOID Param1,
    _In_ PVOID Context,
    _In_ ULONG Param3)
{
    PRKEVENT Event = Context;
    DPRINT("ACPIDevicePowerNotifyEvent: %p, %p, %X\n", Param1, Context, Param3);
    KeSetEvent(Event, 0, FALSE);
}

NTSTATUS
NTAPI
ACPIBuildSynchronizationRequest(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID CallBack,
    _In_ PKEVENT Event,
    _In_ PLIST_ENTRY BuildDeviceList,
    _In_ BOOLEAN IsAddDpc)
{
    PACPI_BUILD_REQUEST BuildRequest;
    KIRQL BuildQueueIrql;
    KIRQL DeviceTreeIrql;

    DPRINT("ACPIBuildSynchronizationRequest: %p, %X\n", DeviceExtension, IsAddDpc);

    BuildRequest = ExAllocateFromNPagedLookasideList(&BuildRequestLookAsideList);
    if (!BuildRequest)
    {
        DPRINT1("ACPIBuildSynchronizationRequest: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &DeviceTreeIrql);

    if (!DeviceExtension->ReferenceCount)
    {
        DPRINT1("ACPIBuildSynchronizationRequest: STATUS_DEVICE_REMOVED\n");
        ExFreeToNPagedLookasideList(&BuildRequestLookAsideList, BuildRequest);
        return STATUS_DEVICE_REMOVED;
    }

    InterlockedIncrement(&DeviceExtension->ReferenceCount);

    RtlZeroMemory(BuildRequest, sizeof(ACPI_BUILD_REQUEST));

    BuildRequest->Signature = '_SGP';
    BuildRequest->Flags = 0x100A;
    BuildRequest->WorkDone = 3;
    BuildRequest->BuildReserved1 = 0;
    BuildRequest->Context = DeviceExtension;
    BuildRequest->Status = 0;
    BuildRequest->CallBack = CallBack;
    BuildRequest->CallBackContext = Event;
    BuildRequest->Synchronize.ListHead = BuildDeviceList;
    BuildRequest->ListHeadForInsert = &AcpiBuildSynchronizationList;

    KeReleaseSpinLock(&AcpiDeviceTreeLock, DeviceTreeIrql);
    KeAcquireSpinLock(&AcpiBuildQueueLock, &BuildQueueIrql);

    InsertHeadList(&AcpiBuildQueueList, &BuildRequest->Link);

    if (IsAddDpc && !AcpiBuildDpcRunning)
        KeInsertQueueDpc(&AcpiBuildDpc, NULL, NULL);

    KeReleaseSpinLock(&AcpiBuildQueueLock, BuildQueueIrql);

    return STATUS_PENDING;
}

NTSTATUS
NTAPI
ACPIRootIrpQueryRemoveOrStopDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status;

    DPRINT("ACPIBusIrpQueryRemoveOrStopDevice: %X\n", DeviceObject);
    PAGED_CODE();

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    if (DeviceExtension->Flags & 0x0000000000200000)
    {
        Irp->IoStatus.Status = Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, 0);
    }
    else
    {
        DeviceExtension->PreviousState = DeviceExtension->DeviceState;
        DeviceExtension->DeviceState = 1;

        IoSkipCurrentIrpStackLocation(Irp);

        Status = IoCallDriver(DeviceExtension->TargetDeviceObject, Irp);
    }

    return Status;
}

NTSTATUS
NTAPI
ACPIRootIrpRemoveDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIRootIrpCancelRemoveOrStopDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status;
  
    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    DPRINT("ACPIRootIrpCancelRemoveOrStopDevice: %X\n", DeviceObject);
    PAGED_CODE();

    if (!(DeviceExtension->Flags & 0x0000000000200000) && DeviceExtension->DeviceState == 1)
        DeviceExtension->DeviceState = DeviceExtension->PreviousState;

    IoSkipCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    Status = IoCallDriver(DeviceExtension->TargetDeviceObject, Irp);

    return Status;
}

NTSTATUS
NTAPI
ACPIRootIrpStopDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
ACPIBuildMissingChildren(
    _In_ PDEVICE_EXTENSION DeviceExtension)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
ACPIBuildFlushQueue(
    _In_ PDEVICE_EXTENSION DeviceExtension)
{
    KEVENT Event;
    NTSTATUS Status;

    KeInitializeEvent(&Event, SynchronizationEvent, 0);

    Status = ACPIBuildSynchronizationRequest(DeviceExtension, ACPIDevicePowerNotifyEvent, &Event, &AcpiBuildDeviceList, TRUE);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = STATUS_SUCCESS;
    }

    return Status;
}

NTSTATUS
NTAPI
ACPIMatchHardwareId(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PUNICODE_STRING HardwareId,
    _Out_ BOOLEAN* OutSuccess)
{
    PWSTR QueryId;
    PWSTR CurrentId;
    UNICODE_STRING IdString;
    IO_STACK_LOCATION ioStack;
    NTSTATUS Status;

    DPRINT("ACPIMatchHardwareId: %p, '%wZ'\n", DeviceObject, HardwareId);
    DPRINT("\n");
    PAGED_CODE();

    ASSERT(DeviceObject != NULL);
    ASSERT(OutSuccess != NULL);

    RtlZeroMemory(&ioStack, sizeof(ioStack));
    RtlZeroMemory(&IdString, sizeof(IdString));

    *OutSuccess = FALSE;

    ioStack.MajorFunction = IRP_MJ_PNP;
    ioStack.MinorFunction = IRP_MN_QUERY_ID;

    ioStack.Parameters.QueryId.IdType = 1;

    Status = ACPIInternalSendSynchronousIrp(DeviceObject, &ioStack, (ULONG_PTR *)&QueryId);
    if (!NT_SUCCESS(Status))
        goto Exit;

    for (CurrentId = QueryId; CurrentId && *CurrentId; )
    {
        RtlInitUnicodeString(&IdString, CurrentId);
        CurrentId += (IdString.MaximumLength / 2);

        if (RtlEqualUnicodeString(&IdString, HardwareId, 1))
        {
            *OutSuccess = TRUE;
            break;
        }
    }

    ExFreePool(QueryId);

Exit:

    DPRINT("ACPIMatchHardwareId: '%ws', %X, %X\n", HardwareId->Buffer, DeviceObject, Status, *OutSuccess);

    return Status;
}

NTSTATUS
NTAPI
ACPIMatchHardwareAddress(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG Address,
    _Out_ BOOLEAN* OutSuccess)
{
    DEVICE_CAPABILITIES capabilities;
    NTSTATUS Status;

    DPRINT("ACPIMatchHardwareAddress: %p, %X\n", DeviceObject, Address);
    PAGED_CODE();

    ASSERT(DeviceObject != NULL);
    ASSERT(OutSuccess != NULL);

    *OutSuccess = FALSE;

    Status = ACPIInternalGetDeviceCapabilities(DeviceObject, &capabilities);

    if (NT_SUCCESS(Status) && Address == capabilities.Address)
        *OutSuccess = TRUE;

    DPRINT("ACPIMatchHardwareAddress: ret %X, %X\n", Status, *OutSuccess);

    return Status;
}

NTSTATUS
NTAPI
ACPIDetectCouldExtensionBeInRelation(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PDEVICE_RELATIONS DeviceRelation,
    _In_ BOOLEAN Param3,
    _In_ BOOLEAN Param4,
    _Out_ PDEVICE_OBJECT* OutPdoObject)
{
    UNICODE_STRING HardwareId;
    ULONG HardwareAddress;
    ULONG ix;
    BOOLEAN IsSuccess = FALSE;
    BOOLEAN IsAdr = FALSE;
    BOOLEAN IsHid = FALSE;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ACPIDetectCouldExtensionBeInRelation: %p, %X, %X\n", DeviceExtension, Param3, Param4);

    ASSERT(OutPdoObject != NULL);

    if (!OutPdoObject)
    {
        DPRINT1("ACPIDetectCouldExtensionBeInRelation: STATUS_INVALID_PARAMETER_1\n");
        return STATUS_INVALID_PARAMETER_1;
    }

    *OutPdoObject = NULL;

    RtlZeroMemory(&HardwareId, sizeof(UNICODE_STRING));

    if (Param3 && !(DeviceExtension->Flags & 0x0000100000000000))
    {
        DPRINT1("ACPIDetectCouldExtensionBeInRelation: STATUS_OBJECT_NAME_NOT_FOUND\n");
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    if (Param4 &&
        (!DeviceExtension->DeviceID || !(DeviceExtension->Flags & 0x0000200000000000)))
    {
        DPRINT("ACPIDetectCouldExtensionBeInRelation: STATUS_OBJECT_NAME_NOT_FOUND\n");
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    if (!DeviceRelation || !DeviceRelation->Count)
        return STATUS_SUCCESS;

    if (DeviceExtension->Flags & 0x2000100000000000)
    {
        IsAdr = TRUE;
        Status = ACPIGet(DeviceExtension, 'RDA_', 0x20040402, NULL, 0, NULL, NULL, (PVOID *)&HardwareAddress, NULL);
    }

    if (DeviceExtension->Flags & 0x0000A00000000000)
    {
        Status = ACPIGet(DeviceExtension, 'DIH_', 0x20080216, NULL, 0, NULL, NULL, (PVOID *)&HardwareId.Buffer, (ULONG *)&HardwareId.Length);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIDetectCouldExtensionBeInRelation: Status %X\n", Status);
            return Status;
        }

        HardwareId.MaximumLength = HardwareId.Length;
        IsHid = TRUE;
    }

    for (ix = 0; ix < DeviceRelation->Count; ix++)
    {
        IsSuccess = FALSE;

        if (IsHid)
        {
            Status = ACPIMatchHardwareId(DeviceRelation->Objects[ix], &HardwareId, &IsSuccess);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("ACPIDetectCouldExtensionBeInRelation: Status %X\n", Status);
                continue;
            }
        }

        if (!IsSuccess && !IsAdr)
            continue;

        if (IsAdr)
        {
            IsSuccess = FALSE;

            Status = ACPIMatchHardwareAddress(DeviceRelation->Objects[ix], HardwareAddress, &IsSuccess);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("ACPIDetectCouldExtensionBeInRelation: Status %X\n", Status);
                continue;
            }

            if (!IsSuccess)
                continue;
        }

        *OutPdoObject = DeviceRelation->Objects[ix];
        break;
    }

    return STATUS_SUCCESS;
}

BOOLEAN
NTAPI
ACPIDetectPdoMatch(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PDEVICE_RELATIONS DeviceRelation)
{
    PDEVICE_OBJECT DeviceObject = NULL;
    BOOLEAN Result;
    NTSTATUS Status;

    PAGED_CODE();

    if (!(DeviceExtension->Flags & 0x0000000000000008) ||
        (DeviceExtension->Flags & 0x0200000000000000) ||
        DeviceExtension->DeviceObject)
    {
        return TRUE;
    }

    Status = ACPIDetectCouldExtensionBeInRelation(DeviceExtension, DeviceRelation, FALSE, TRUE, &DeviceObject);

    Result = (DeviceObject || !NT_SUCCESS(Status));

    return Result;
}

NTSTATUS
NTAPI
ACPIBuildPdo(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PDEVICE_OBJECT InPdo,
    _In_ BOOLEAN IsFilterDO)
{
    PDEVICE_OBJECT FilterDO = NULL;
    PDEVICE_OBJECT Pdo = NULL;
    ULONG ix;
    KIRQL Irql;
    NTSTATUS Status;

    DPRINT("ACPIBuildPdo: %p, %p, %X\n", DeviceExtension, InPdo, IsFilterDO);

    Status = IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_ACPI, FILE_AUTOGENERATED_DEVICE_NAME, FALSE, &Pdo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIBuildPdo: Status %X\n", Status);
        return Status;
    }

    if (IsFilterDO)
    {
        if (!(DeviceExtension->Flags & 0x0000000000100000))
        {
            FilterDO = IoGetAttachedDeviceReference(InPdo);
            if (!FilterDO)
            {
                DPRINT1("ACPIBuildPdo: STATUS_NO_SUCH_DEVICE\n");
                IoDeleteDevice(Pdo);
                return STATUS_NO_SUCH_DEVICE;
            }
        }
        else
        {
            IsFilterDO = FALSE;
        }
    }

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &Irql);

    Pdo->DeviceExtension = DeviceExtension;
    DeviceExtension->DeviceObject = Pdo;
    DeviceExtension->PhysicalDeviceObject = Pdo;

    InterlockedIncrement(&DeviceExtension->ReferenceCount);

    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x00000000000001FF, TRUE);
    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0000000000000020, FALSE);

    DeviceExtension->PreviousState = DeviceExtension->DeviceState;
    DeviceExtension->DeviceState = 0;
    DeviceExtension->DispatchTable = &AcpiPdoIrpDispatch;

    if (IsFilterDO)
    {
        DeviceExtension->TargetDeviceObject = FilterDO;

        ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0000000000000040, FALSE);

        DeviceExtension->DispatchTable = &AcpiBusFilterIrpDispatch;

        Pdo->StackSize = (FilterDO->StackSize + 1);
        Pdo->AlignmentRequirement = FilterDO->AlignmentRequirement;

        if (FilterDO->Flags & 0x2000)
            Pdo->Flags |= 0x2000;
    }

    if (DeviceExtension->Flags & 0x0000001000000000)
    {
        DeviceExtension->DispatchTable = &AcpiProcessorIrpDispatch;
    }
    else if (DeviceExtension->Flags & 0x0000200000000000)
    {
        ASSERT(DeviceExtension->DeviceID);

        for (ix = 0; AcpiInternalDeviceTable[ix].StringId; ix++)
        {
            if (strstr(DeviceExtension->DeviceID, AcpiInternalDeviceTable[ix].StringId))
            {
                DeviceExtension->DispatchTable = AcpiInternalDeviceTable[ix].DispatchTable;
                break;
            }
        }
    }

    if ((DeviceExtension->Flags & 0x0000000000040000) && (DeviceExtension->Flags & 0x0008000000000000))
        FixedButtonDeviceObject = Pdo;

    KeReleaseSpinLock(&AcpiDeviceTreeLock, Irql);

    Pdo->Flags &= ~DO_DEVICE_INITIALIZING;

    if (DeviceExtension->Flags & 0x0010000000000000)
        Pdo->Flags |= 8;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIDetectPdoDevices(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PDEVICE_RELATIONS* OutDeviceRelation)
{
    PDEVICE_EXTENSION DeviceExtension;
    PDEVICE_EXTENSION Extension;
    PDEVICE_RELATIONS InDeviceRelation = NULL;
    PDEVICE_RELATIONS DeviceRelation;
    PDEVICE_OBJECT* Objects;
    PLIST_ENTRY Head;
    PLIST_ENTRY Entry;
    LONG RefCount;
    ULONG dummyData;
    ULONG count = 0;
    ULONG Size;
    ULONG ix;
    KIRQL Irql;
    BOOLEAN IsFound;
    NTSTATUS Status;

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    if (OutDeviceRelation && *OutDeviceRelation)
    {
        InDeviceRelation = *OutDeviceRelation;
        count = InDeviceRelation->Count;
    }

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &Irql);

    if (DeviceExtension->Flags & 0x0000020000000000)
    {
        DPRINT1("ACPIDetectPdoDevices: FIXME\n");
        ASSERT(FALSE);
    }

    KeReleaseSpinLock(&AcpiDeviceTreeLock, Irql);

    Status = ACPIBuildFlushQueue(DeviceExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIDetectPdoDevices: Status %X\n", Status);
        return Status;
    }

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &Irql);

    if (IsListEmpty(&DeviceExtension->ChildDeviceList))
    {
        KeReleaseSpinLock(&AcpiDeviceTreeLock, Irql);

        if (InDeviceRelation)
            return STATUS_SUCCESS;

        DeviceRelation = ExAllocatePoolWithTag(NonPagedPool, sizeof(*DeviceRelation), 'DpcA');
        if (!DeviceRelation)
        {
            DPRINT1("ACPIDetectPdoDevices: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(DeviceRelation, sizeof(*DeviceRelation));

        *OutDeviceRelation = DeviceRelation;

        return STATUS_SUCCESS;
    }

    Head = &DeviceExtension->ChildDeviceList;
    Extension = CONTAINING_RECORD(DeviceExtension->ChildDeviceList.Flink, DEVICE_EXTENSION, SiblingDeviceList);

    while (TRUE)
    {
        InterlockedIncrement(&Extension->ReferenceCount);

        KeReleaseSpinLock(&AcpiDeviceTreeLock, Irql);

        if (!Extension)
            break;

        ACPIInternalUpdateFlags(&Extension->Flags, 0x100, FALSE);

        Status = ACPIGet(Extension, 'ATS_', 0x20040802, NULL, 0, NULL, NULL, (PVOID *)&dummyData, NULL);
        if (NT_SUCCESS(Status))
        {
            if (!(Extension->Flags & 0x0002000000000002)) 
            {
                if (ACPIDetectPdoMatch(Extension, InDeviceRelation))
                {
                    if ((Extension->Flags & 0x0000000000000020) && Extension->DeviceObject)
                    {
                        if (InDeviceRelation && InDeviceRelation->Count)
                        {
                            ix = 0;
                            Objects = InDeviceRelation->Objects;
                            while (*Objects != Extension->DeviceObject)
                            {
                                Objects++;
                                ix++;
                                if (ix >= InDeviceRelation->Count)
                                {
                                    count++;
                                    ACPIInternalUpdateFlags(&Extension->Flags, 0x100, 1);
                                    break;
                                }
                            }
                        }
                        else
                        {
                            count++;
                            ACPIInternalUpdateFlags(&Extension->Flags, 0x100, 1);
                        }
                    }
                }
                else
                {
                    IsFound = FALSE;

                    if (!(DeviceExtension->Flags & 0x10))
                        IsFound = TRUE;

                    Status = ACPIBuildPdo(DeviceObject->DriverObject, Extension, DeviceExtension->PhysicalDeviceObject, IsFound);
                    if (NT_SUCCESS(Status))
                        count++;
                }
            }
        }

        KeAcquireSpinLock(&AcpiDeviceTreeLock, &Irql);
        RefCount = InterlockedDecrement(&Extension->ReferenceCount);

        Entry = Extension->SiblingDeviceList.Flink;
        if (Entry == Head)
        {
            if (!RefCount)
                ACPIInitDeleteDeviceExtension(Extension);

            KeReleaseSpinLock(&AcpiDeviceTreeLock, Irql);

            break;
        }

        Extension = CONTAINING_RECORD(Entry, DEVICE_EXTENSION, SiblingDeviceList);

        if (!RefCount)
        {
            DPRINT1("ACPIDetectPdoDevices: FIXME\n");
            ASSERT(FALSE);
        }
    }

    if (InDeviceRelation)
    {
        if (count == InDeviceRelation->Count)
            return STATUS_SUCCESS;
    }
    else if (!count)
    {
        return STATUS_SUCCESS;
    }

    Size = ((count + 1) * 4);

    DeviceRelation = ExAllocatePoolWithTag(NonPagedPool, Size, 'DpcA');
    if (!DeviceRelation)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(DeviceRelation, Size);

    if (InDeviceRelation)
    {
        RtlCopyMemory(DeviceRelation->Objects, InDeviceRelation->Objects, (InDeviceRelation->Count * sizeof(PDEVICE_OBJECT)));
        ix = InDeviceRelation->Count;
    }
    else
    {
        ix = 0;
    }

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &Irql);

    if (IsListEmpty(Head))
    {
        KeReleaseSpinLock(&AcpiDeviceTreeLock, Irql);
        ExFreePoolWithTag(DeviceRelation, 'DpcA');
        return STATUS_SUCCESS;
    }

    Extension = CONTAINING_RECORD(Head->Flink, DEVICE_EXTENSION, SiblingDeviceList);

    while (Extension)
    {
        if (Extension->Flags & 0x0000000000000020)
        {
            if (Extension->DeviceObject)
            {
                if (!(Extension->Flags & 0x0002000000000002))
                {
                    DeviceRelation->Objects[ix] = Extension->DeviceObject;
                    ACPIInternalUpdateFlags(&Extension->Flags, 0x0000000000000100, TRUE);
                    ix++;
                }
            }
        }

        if (count == ix)
            break;

        if (Extension->SiblingDeviceList.Flink == &DeviceExtension->ChildDeviceList)
            break;

        Extension = CONTAINING_RECORD(Extension->SiblingDeviceList.Flink, DEVICE_EXTENSION, SiblingDeviceList);
    }

    count = ix;
    DeviceRelation->Count = count;

    KeReleaseSpinLock(&AcpiDeviceTreeLock, Irql);

    if (InDeviceRelation)
        ix = InDeviceRelation->Count;
    else
        ix = 0;

    for (; ix < count; ix++)
    {
        Status = ObReferenceObjectByPointer(DeviceRelation->Objects[ix], 0, NULL, KernelMode);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIDetectPdoDevices: Status %X\n", Status);
            DPRINT1("ACPIDetectPdoDevices: FIXME\n");
            ASSERT(FALSE);
        }
    }

    if (InDeviceRelation)
        ExFreePool(*OutDeviceRelation);

    *OutDeviceRelation = DeviceRelation;

    return STATUS_SUCCESS;
}

BOOLEAN
__cdecl
ACPIExtListIsMemberOfRelation(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PDEVICE_RELATIONS DeviceRelation)
{
    ULONG ix;

    if (!DeviceRelation)
        return FALSE;

    if (!DeviceRelation->Count)
        return FALSE;

    for (ix = 0; ix < DeviceRelation->Count; ix++)
    {
        if (DeviceRelation->Objects[ix] == DeviceObject)
            return TRUE;
    }

    return FALSE;
}

NTSTATUS
NTAPI
ACPIDetectDockDevices(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _Out_ PDEVICE_RELATIONS* OutDeviceRelation)
{
    PDEVICE_EXTENSION ProviderExtension;
    PDEVICE_RELATIONS OldDeviceRelation;
    PDEVICE_RELATIONS NewDeviceRelation = NULL;
    PDEVICE_OBJECT PrevDeviceObject;
    ACPI_EXT_LIST_ENUM_DATA ExtList;
    PVOID dummy;
    ULONG DeviceCount;
    ULONG count = 0;
    ULONG ix = 0;
    ULONG Size;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ACPIDetectDockDevices: DeviceExtension %p\n", DeviceExtension);

    if (OutDeviceRelation && *OutDeviceRelation)
    {
        OldDeviceRelation = *OutDeviceRelation;
        DeviceCount = OldDeviceRelation->Count;
    }
    else
    {
        OldDeviceRelation = NULL;
        DeviceCount = 0;
    }

    ExtList.List = &DeviceExtension->ChildDeviceList;
    ExtList.SpinLock = &AcpiDeviceTreeLock;
    ExtList.Offset = FIELD_OFFSET(DEVICE_EXTENSION, SiblingDeviceList);
    ExtList.ExtListEnum2 = 1;

    ProviderExtension = ACPIExtListStartEnum(&ExtList);

    while (ACPIExtListTestElement(&ExtList, NT_SUCCESS(Status)))
    {
        if (!ProviderExtension)
        {
            ACPIExtListExitEnumEarly(&ExtList);
            break;
        }

        if (ProviderExtension->Flags & 0x0200000000000000)
        {
            Status = ACPIGet(ProviderExtension, 'ATS_', 0x20040802, NULL, 0, NULL, NULL, &dummy, NULL);

            if (!(ProviderExtension->Flags & 0x0002000000000002))
            {
                if (!ProviderExtension->DeviceObject)
                {
                    Status = ACPIBuildPdo(DeviceExtension->DeviceObject->DriverObject,
                                          ProviderExtension,
                                          DeviceExtension->DeviceObject,
                                          FALSE);

                    if (!NT_SUCCESS(Status))
                    {
                        DPRINT1("ACPIDetectDockDevices: Status %X\n", Status);
                        ASSERT(ProviderExtension->DeviceObject == NULL);
                    }
                }

                if (ProviderExtension->DeviceObject)
                {
                    if (!ACPIExtListIsMemberOfRelation(ProviderExtension->DeviceObject, OldDeviceRelation))
                        DeviceCount++;
                }
            }
        }

        ProviderExtension = ACPIExtListEnumNext(&ExtList);
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIDetectDockDevices: Status %X\n", Status);
        return Status;
    }

    if (OldDeviceRelation && OldDeviceRelation->Count == DeviceCount)
        return STATUS_SUCCESS;

    if (!OldDeviceRelation && !DeviceCount)
        return STATUS_SUCCESS;

    Size = ((DeviceCount + 1) * 4);

    NewDeviceRelation = ExAllocatePoolWithTag(NonPagedPool, Size, 'DpcA');
    if (!NewDeviceRelation)
    {
        DPRINT1("ACPIDetectDockDevices: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(NewDeviceRelation, Size);

    if (OldDeviceRelation)
    {
        RtlCopyMemory(NewDeviceRelation->Objects, OldDeviceRelation->Objects, (OldDeviceRelation->Count * 4));
        count = OldDeviceRelation->Count;
    }

    ExtList.List = &DeviceExtension->ChildDeviceList;
    ExtList.SpinLock = &AcpiDeviceTreeLock;
    ExtList.Offset = FIELD_OFFSET(DEVICE_EXTENSION, SiblingDeviceList);
    ExtList.ExtListEnum2 = 2;

    ProviderExtension = ACPIExtListStartEnum(&ExtList);

    while (ACPIExtListTestElement(&ExtList, (DeviceCount != count)))
    {
        if (!(ProviderExtension->Flags & 0x0002000000000002) &&
            (ProviderExtension->Flags & 0x0200000000000000) &&
            ProviderExtension->DeviceObject)
        {
            NewDeviceRelation->Objects[count] = ProviderExtension->PhysicalDeviceObject;
            count++;
        }

        ProviderExtension = ACPIExtListEnumNext(&ExtList);
    }

    DeviceCount = count;
    NewDeviceRelation->Count = DeviceCount;

    if (OldDeviceRelation)
        ix = OldDeviceRelation->Count;
    else
        ix = 0;

    for (; ix < DeviceCount; ix++)
    {
        Status = ObReferenceObjectByPointer(NewDeviceRelation->Objects[ix], 0, NULL, KernelMode);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIDetectDockDevices: Status %X\n", Status);

            NewDeviceRelation->Count--;

            PrevDeviceObject = NewDeviceRelation->Objects[NewDeviceRelation->Count];
            NewDeviceRelation->Objects[NewDeviceRelation->Count] = NewDeviceRelation->Objects[ix];
            NewDeviceRelation->Objects[ix] = PrevDeviceObject;
        }
    }

    if (OldDeviceRelation)
        ExFreePool(*OutDeviceRelation);

    *OutDeviceRelation = NewDeviceRelation;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIRootIrpQueryBusRelations(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _Out_ PDEVICE_RELATIONS* OutDeviceRelation)
{
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ACPIRootIrpQueryBusRelations: %p, %p\n", DeviceObject, Irp);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    if (!DeviceExtension->AcpiObject)
    {
        DPRINT1("ACPIRootIrpQueryBusRelations: STATUS_INVALID_PARAMETER\n");
        ASSERT(DeviceExtension->AcpiObject != NULL);
        return STATUS_INVALID_PARAMETER;
    }

    Status = ACPIDetectPdoDevices(DeviceObject, OutDeviceRelation);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIRootIrpQueryBusRelations: Status %X\n", Status);
        return Status;
    }

    Status = ACPIDetectDockDevices(DeviceExtension, OutDeviceRelation);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIRootIrpQueryBusRelations: Status %X\n", Status);
    }

    return Status;
}

NTSTATUS
NTAPI
ACPIDetectFilterMatch(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PDEVICE_RELATIONS DeviceRelation,
    _Out_ PDEVICE_OBJECT* OutPdo)
{
    ULONG ix;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ACPIDetectFilterMatch: %p, %p\n", DeviceExtension, DeviceRelation);

    ASSERT(OutPdo != NULL);

    if (!OutPdo)
    {
        DPRINT1("ACPIDetectFilterMatch: STATUS_INVALID_PARAMETER_1\n");
        return STATUS_INVALID_PARAMETER_1;
    }

    *OutPdo = NULL;

    if ((DeviceExtension->Flags & 0x0000000000000008) &&
        !(DeviceExtension->Flags & 0x0200000000000000) &&
        !DeviceExtension->DeviceObject)
    {
        Status = ACPIDetectCouldExtensionBeInRelation(DeviceExtension, DeviceRelation, TRUE, FALSE, OutPdo);
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
            Status = STATUS_SUCCESS;
        return Status;
    }

    if (!DeviceRelation)
        return STATUS_SUCCESS;

    if (!DeviceRelation->Count)
        return STATUS_SUCCESS;

    for (ix = 0; ix < DeviceRelation->Count; ix++)
    {
        if (DeviceExtension->PhysicalDeviceObject == DeviceRelation->Objects[ix])
            ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0000000000000100, TRUE);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIBuildFilter(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PDEVICE_OBJECT Pdo)
{
    PDEVICE_OBJECT AttachedToDevice;
    PDEVICE_OBJECT DeviceObject = NULL;
    KIRQL Irql;
    NTSTATUS Status;

    DPRINT("ACPIBuildFilter: %p, %p\n", DeviceObject, Pdo);

    Status = IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_ACPI, FILE_AUTOGENERATED_DEVICE_NAME, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIBuildFilter: Status %X\n", Status);
        return Status;
    }

    AttachedToDevice = IoAttachDeviceToDeviceStack(DeviceObject, Pdo);
    if (!AttachedToDevice)
    {
        DPRINT1("ACPIBuildFilter: STATUS_INVALID_PARAMETER_3\n");
        IoDeleteDevice(DeviceObject);
        return STATUS_INVALID_PARAMETER_3;
    }

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &Irql);

    DeviceObject->DeviceExtension = DeviceExtension;

    DeviceExtension->DeviceObject = DeviceObject;
    DeviceExtension->PhysicalDeviceObject = Pdo;
    DeviceExtension->TargetDeviceObject = AttachedToDevice;

    InterlockedIncrement(&DeviceExtension->ReferenceCount);

    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x00000000000001FF, 1);
    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0000000000000040, 0);

    DeviceExtension->PreviousState = DeviceExtension->DeviceState;
    DeviceExtension->DeviceState = 0;
    DeviceExtension->DispatchTable = &AcpiFilterIrpDispatch;

    DeviceObject->StackSize = (AttachedToDevice->StackSize + 1);
    DeviceObject->AlignmentRequirement = AttachedToDevice->AlignmentRequirement;

    if (AttachedToDevice->Flags & 0x2000)
        DeviceObject->Flags |= 0x2000;

    if (AttachedToDevice->Flags & 0x10)
        DeviceObject->Flags |= 0x10;

    if (AttachedToDevice->Flags & 4)
        DeviceObject->Flags |= 4;

    KeReleaseSpinLock(&AcpiDeviceTreeLock, Irql);

    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIDetectFilterDevices(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PDEVICE_RELATIONS DeviceRelation)
{
    PDEVICE_EXTENSION DeviceExtension;
    PDEVICE_EXTENSION ChildDeviceExtension;
    PDEVICE_OBJECT PhysicalDeviceObject = NULL;
    PLIST_ENTRY Entry;
    PVOID dummy;
    LONG RefCount;
    KIRQL OldIrql;
    NTSTATUS Status;

    DPRINT("ACPIDetectFilterDevices: %p, %p\n", DeviceObject, DeviceRelation);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &OldIrql);

    if (DeviceExtension->Flags & 0x0000020000000000)
    {
        ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0000020000000000, TRUE);
        ACPIBuildMissingChildren(DeviceExtension);
    }

    KeReleaseSpinLock(&AcpiDeviceTreeLock, OldIrql);

    Status = ACPIBuildFlushQueue(DeviceExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIDetectFilterDevices: Status %X\n", Status);
        return Status;
    }

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &OldIrql);

    if (IsListEmpty(&DeviceExtension->ChildDeviceList))
    {
        KeReleaseSpinLock(&AcpiDeviceTreeLock, OldIrql);
        return STATUS_SUCCESS;
    }

    ChildDeviceExtension = CONTAINING_RECORD(DeviceExtension->ChildDeviceList.Flink, DEVICE_EXTENSION, SiblingDeviceList);
    InterlockedIncrement(&ChildDeviceExtension->ReferenceCount);

    KeReleaseSpinLock(&AcpiDeviceTreeLock, OldIrql);

    while (ChildDeviceExtension)
    {
        Status = ACPIGet(ChildDeviceExtension, 'ATS_', 0x20040802, NULL, 0, NULL, NULL, &dummy, NULL);

        if (NT_SUCCESS(Status) && !(ChildDeviceExtension->Flags & 0x0002000000000002))
        {
            Status = ACPIDetectFilterMatch(ChildDeviceExtension, DeviceRelation, &PhysicalDeviceObject);

            if (NT_SUCCESS(Status))
            {
                if (PhysicalDeviceObject)
                {
                    Status = ACPIBuildFilter(DeviceObject->DriverObject, ChildDeviceExtension, PhysicalDeviceObject);
                    if (!NT_SUCCESS(Status))
                    {
                        DPRINT1("ACPIDetectFilterDevices: Status %X\n", Status);
                    }
                }
            }
            else
            {
                DPRINT1("ACPIDetectFilterDevices: Status %X\n", Status);
            }
        }

        KeAcquireSpinLock(&AcpiDeviceTreeLock, &OldIrql);

        RefCount = InterlockedDecrement(&ChildDeviceExtension->ReferenceCount);

        if (ChildDeviceExtension->SiblingDeviceList.Flink == &DeviceExtension->ChildDeviceList)
        {
            if (!RefCount)
                ACPIInitDeleteDeviceExtension(ChildDeviceExtension);

            KeReleaseSpinLock(&AcpiDeviceTreeLock, OldIrql);

            break;
        }

        ChildDeviceExtension = CONTAINING_RECORD(ChildDeviceExtension->SiblingDeviceList.Flink, DEVICE_EXTENSION, SiblingDeviceList);

        if (!RefCount)
        {
            Entry = RemoveTailList(&ChildDeviceExtension->SiblingDeviceList);
            ACPIInitDeleteDeviceExtension(CONTAINING_RECORD(Entry, DEVICE_EXTENSION, SiblingDeviceList));
        }

        InterlockedIncrement(&ChildDeviceExtension->ReferenceCount);
        KeReleaseSpinLock(&AcpiDeviceTreeLock, OldIrql);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIRootIrpQueryDeviceRelations(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    PDEVICE_RELATIONS DeviceRelation;
    PIO_STACK_LOCATION IoStack;
    KEVENT Event;
    BOOLEAN IsBusRelations = FALSE;
    NTSTATUS status;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ACPIRootIrpQueryDeviceRelations: %p, %p\n", DeviceObject, Irp);

    IoStack = Irp->Tail.Overlay.CurrentStackLocation;
    DeviceRelation = (PDEVICE_RELATIONS)Irp->IoStatus.Information;

    if (IoStack->Parameters.QueryDeviceRelations.Type == BusRelations)
    {
        IsBusRelations = TRUE;
        Status = ACPIRootIrpQueryBusRelations(DeviceObject, Irp, &DeviceRelation);
    }
    else
    {
        DPRINT1("ACPIRootIrpQueryDeviceRelations: Unhandled Type %X\n", IoStack->Parameters.QueryDeviceRelations.Type);
        Status = STATUS_NOT_SUPPORTED;
    }

    if (NT_SUCCESS(Status))
    {
        Irp->IoStatus.Status = Status;
        Irp->IoStatus.Information = (ULONG_PTR)DeviceRelation;
    }
    else if (Status != STATUS_NOT_SUPPORTED && !DeviceRelation)
    {
        DPRINT1("ACPIRootIrpQueryDeviceRelations: Status %X\n", Status);

        Irp->IoStatus.Status = Status;
        Irp->IoStatus.Information = 0;

        IoCompleteRequest(Irp, 0);
        return Status;
    }

    KeInitializeEvent(&Event, SynchronizationEvent, 0);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, ACPIRootIrpCompleteRoutine, &Event, TRUE, TRUE, TRUE);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    Status = IoCallDriver(DeviceExtension->TargetDeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    DeviceRelation = (PDEVICE_RELATIONS)Irp->IoStatus.Information;

    if ((NT_SUCCESS(Status) || Status == STATUS_NOT_SUPPORTED) && IsBusRelations)
    {
        status = ACPIDetectFilterDevices(DeviceObject, DeviceRelation);
        DPRINT("ACPIRootIrpQueryDeviceRelations: Status %X, status %X\n", Status, status);
    }

    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
ACPIRootIrpQueryInterface(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    GUID* InterfaceType;
    ARBITER_INTERFACE Interface;
    UNICODE_STRING GuidString;
    CM_RESOURCE_TYPE ResourceType;
    ULONG Size;
    NTSTATUS Status;

    PAGED_CODE();

    IoStack = Irp->Tail.Overlay.CurrentStackLocation;
    InterfaceType = (PVOID)IoStack->Parameters.QueryInterface.InterfaceType;
    ResourceType = (CM_RESOURCE_TYPE)IoStack->Parameters.QueryInterface.InterfaceSpecificData;

    Status = RtlStringFromGUID(IoStack->Parameters.QueryInterface.InterfaceType, &GuidString);
    if (NT_SUCCESS(Status))
    {
        DPRINT("ACPIRootIrpQueryInterface: %X, '%wZ'\n", ResourceType, &GuidString);
        RtlFreeUnicodeString(&GuidString);
    }

    if (InterfaceType == &GUID_ARBITER_INTERFACE_STANDARD ||
        (RtlCompareMemory(InterfaceType, &GUID_ARBITER_INTERFACE_STANDARD, sizeof(GUID)) == sizeof(GUID)))
    {
        if (ResourceType == CmResourceTypeInterrupt)
        {
            if (IoStack->Parameters.QueryInterface.Size <= sizeof(ARBITER_INTERFACE))
                Size = IoStack->Parameters.QueryInterface.Size;
            else
                Size = sizeof(ARBITER_INTERFACE);

            Interface.Size = sizeof(ARBITER_INTERFACE);
            Interface.Version = 1;
            Interface.Flags = 0;
            Interface.ArbiterHandler = ArbArbiterHandler;
            Interface.Context = &AcpiArbiter;
            Interface.InterfaceReference = AcpiNullReference;
            Interface.InterfaceDereference = AcpiNullReference;

            RtlCopyMemory(IoStack->Parameters.QueryInterface.Interface, &Interface, Size);

            Irp->IoStatus.Status = STATUS_SUCCESS;
        }
    }

    Status = Irp->IoStatus.Status;

    DPRINT("ACPIRootIrpQueryInterface: Status %X\n", Status);

    return ACPIDispatchForwardIrp(DeviceObject, Irp);
}

NTSTATUS
NTAPI
ACPISystemPowerGetSxD(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ SYSTEM_POWER_STATE SystemState,
    _Out_ DEVICE_POWER_STATE* OutDeviceState)
{
    DEVICE_POWER_STATE DeviceState = PowerDeviceUnspecified;
    ULONG DataBuff;
    NTSTATUS Status;

    PAGED_CODE();

    *OutDeviceState = PowerDeviceUnspecified;

    if ((DeviceExtension->Flags & 0x0008000000000000) ||
        (DeviceExtension->Flags & 0x0002000000000000))
    {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    Status = ACPIGet(DeviceExtension, AcpiSxDMethodTable[SystemState], 0x20040002, NULL, 0, NULL, NULL, (PVOID *)&DataBuff, NULL);
    if (NT_SUCCESS(Status))
    {
        if (DataBuff < 4)
            DeviceState = DevicePowerStateTranslation[DataBuff];

        *OutDeviceState = DeviceState;

        return Status;
    }

    if (Status != STATUS_OBJECT_NAME_NOT_FOUND)
    {
        DPRINT1("ACPISystemPowerGetSxD: Cannot run _S%cD - %X\n", (SystemState ? ((SystemState - 1) + '0') : 'w'), Status);
        return Status;
    }

    if (SystemState == PowerSystemSleeping1 &&
        (DeviceExtension->Flags & 0x0000A00000000000) &&
        (DeviceExtension->Flags & 0x0000000002000000))
    {
        *OutDeviceState = PowerDeviceD1;
        Status = STATUS_SUCCESS;
    }

    return Status;
}

NTSTATUS
NTAPI
ACPISystemPowerProcessSxD(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PDEVICE_POWER_STATE PowerMatrix,
    _Out_ BOOLEAN* OutMatchFound)
{
    SYSTEM_POWER_STATE SystemState;
    DEVICE_POWER_STATE DeviceState;
    NTSTATUS Status;

    PAGED_CODE();

    ASSERT(OutMatchFound);
    *OutMatchFound = FALSE;

    for (SystemState = PowerSystemWorking; SystemState < PowerSystemMaximum; SystemState++)
    {
        if (!(AcpiSupportedSystemStates & (1 << SystemState)))
        {
            PowerMatrix[SystemState] = PowerDeviceUnspecified;
            continue;
        }

        Status = ACPISystemPowerGetSxD(DeviceExtension, SystemState, &DeviceState);
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
            continue;

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPISystemPowerProcessSxD: Cannot Evaluate _SxD (%X)\n", Status);
            continue;
        }

        *OutMatchFound = TRUE;

        if (DeviceState > PowerMatrix[SystemState])
            PowerMatrix[SystemState] = DeviceState;
    }

    return STATUS_SUCCESS;
}

SYSTEM_POWER_STATE
NTAPI
ACPISystemPowerDetermineSupportedSystemState(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ DEVICE_POWER_STATE DeviceState)
{
    SYSTEM_POWER_STATE RetState = PowerSystemMaximum;
    PACPI_DEVICE_POWER_NODE Node;
  
    if (DeviceState == PowerDeviceD3)
    {
        RetState = PowerDeviceUnspecified;
        return RetState;
    }

    Node = DeviceExtension->PowerInfo.PowerNode[DeviceState];
    if (!Node)
    {
        RetState = PowerDeviceUnspecified;
        return RetState;
    }

    do
    {
        if (Node->SystemState < RetState)
            RetState = Node->SystemState;

        Node = Node->Next;
    }
    while (Node);

    if (RetState == PowerSystemMaximum)
        RetState = PowerDeviceUnspecified;

    return RetState;
}

NTSTATUS
NTAPI
ACPISystemPowerDetermineSupportedDeviceStates(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ SYSTEM_POWER_STATE SystemState,
    _Out_ DEVICE_POWER_STATE* OutSupportedDeviceStates)
{
    ACPI_EXT_LIST_ENUM_DATA ExtList;
    SYSTEM_POWER_STATE systemState;
    DEVICE_POWER_STATE DeviceState;
    PDEVICE_EXTENSION Extension;
    KIRQL Irql;
    BOOLEAN Result;
    NTSTATUS Status;

    ASSERT(SystemState >= PowerSystemWorking && SystemState <= PowerSystemShutdown);
    ASSERT(OutSupportedDeviceStates != NULL);

    ExtList.List = &DeviceExtension->ChildDeviceList;
    ExtList.SpinLock = &AcpiDeviceTreeLock;
    ExtList.Offset = FIELD_OFFSET(DEVICE_EXTENSION, SiblingDeviceList);
    ExtList.ExtListEnum2 = 1;

    Extension = ACPIExtListStartEnum(&ExtList);

    for (Result = ACPIExtListTestElement(&ExtList, TRUE);
         Result;
         Result = ACPIExtListTestElement(&ExtList, NT_SUCCESS(Status)))
    {
        Status = ACPISystemPowerDetermineSupportedDeviceStates(Extension, SystemState, OutSupportedDeviceStates);
        if (!NT_SUCCESS(Status))
        {
            Extension = ACPIExtListEnumNext(&ExtList);
            continue;
        }

        Status = ACPISystemPowerGetSxD(Extension, SystemState, &DeviceState);
        if (NT_SUCCESS(Status))
        {
            *OutSupportedDeviceStates |= (1 << DeviceState);
            DPRINT("ACPISystemPowerDetermineSupportedDeviceStates: S%x->D%x\n", (SystemState - 1), (DeviceState - 1));
            Extension = ACPIExtListEnumNext(&ExtList);
            continue;
        }

        if (Status != STATUS_OBJECT_NAME_NOT_FOUND)
        {
            DPRINT("ACPISystemPowerDetermineSupportedDeviceStates: Status %X\n", Status);
            Extension = ACPIExtListEnumNext(&ExtList);
            continue;
        }

        Status = STATUS_SUCCESS;

        KeAcquireSpinLock(&AcpiPowerLock, &Irql);
        DeviceState = PowerDeviceD0;

        do
        {
            systemState = ACPISystemPowerDetermineSupportedSystemState(Extension, DeviceState);
            if (systemState >= SystemState)
            {
                *OutSupportedDeviceStates |= (1 << DeviceState);
                DPRINT("ACPISystemPowerDetermineSupportedDeviceStates: PR%X maps to S%X, so S%X->D%X\n", (DeviceState - 1), (systemState - 1), (SystemState - 1), (DeviceState - 1));
            }

            DeviceState++;
        }
        while (DeviceState <= PowerDeviceD2);

        KeReleaseSpinLock(&AcpiPowerLock, Irql);
        Extension = ACPIExtListEnumNext(&ExtList);
     }
 
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPISystemPowerProcessRootMapping(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PDEVICE_POWER_STATE PowerMatrix)
{
    SYSTEM_POWER_STATE SystemState;
    DEVICE_POWER_STATE DeviceState;
    DEVICE_POWER_STATE SupportedDeviceStates;
    NTSTATUS Status;

    PAGED_CODE();

    SystemState = PowerSystemSleeping1;
    do
    {
        if ((1 << SystemState) & AcpiSupportedSystemStates)
        {
            SupportedDeviceStates = 0x10;

            Status = ACPISystemPowerDetermineSupportedDeviceStates(DeviceExtension, SystemState, &SupportedDeviceStates);
            if (NT_SUCCESS(Status))
            {
                for (DeviceState = PowerMatrix[SystemState]; DeviceState <= PowerDeviceD3; DeviceState++)
                {
                    if ((1 << DeviceState) & SupportedDeviceStates)
                    {
                        PowerMatrix[SystemState] = DeviceState;
                        break;
                    }
                }
            }
            else
            {
                DPRINT1("ACPISystemPowerProcessRootMapping: Cannot determine D state for S%x - %X\n", (SystemState - 1), Status);
                PowerMatrix[SystemState] = PowerDeviceD3;
            }
        }
        SystemState++;
    }
    while (SystemState <= PowerSystemShutdown);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPISystemPowerInitializeRootMapping(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PDEVICE_CAPABILITIES Capabilities)
{
    PDEVICE_POWER_STATE OutDeviceState;
    DEVICE_POWER_STATE deviceStates[7];
    ULONG ix;
    KIRQL Irql;
    BOOLEAN dummyMatchFound;
    NTSTATUS Status;

    if (DeviceExtension->Flags & 0x0400000000000000)
        goto Finish;

    if (DeviceExtension->DeviceState != Started)
        goto Finish;

    RtlCopyMemory(deviceStates, DeviceExtension->PowerInfo.DevicePowerMatrix, sizeof(deviceStates));

    deviceStates[1] = PowerDeviceD0;
    OutDeviceState = &Capabilities->DeviceState[2];

    ix = 2;
    do
    {
        if (*OutDeviceState)
            deviceStates[ix] = *OutDeviceState;
        ix++;
        OutDeviceState++;
    }
    while (ix <= 6);

    Status = ACPISystemPowerProcessSxD(DeviceExtension, deviceStates, &dummyMatchFound);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPISystemPowerInitializeRootMapping: Status %X\n", Status);
        return Status;
    }

    if (deviceStates[6] == PowerDeviceUnspecified)
        deviceStates[6] = PowerDeviceD3;

    Status = ACPISystemPowerProcessRootMapping(DeviceExtension, deviceStates);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPISystemPowerInitializeRootMapping: Status %X\n", Status);
        goto Finish;
    }

    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0400000000000000, FALSE);

    KeAcquireSpinLock(&AcpiPowerLock, &Irql);
    RtlCopyMemory(DeviceExtension->PowerInfo.DevicePowerMatrix, deviceStates, sizeof(DeviceExtension->PowerInfo.DevicePowerMatrix));
    KeReleaseSpinLock(&AcpiPowerLock, Irql);

Finish:

    RtlCopyMemory(Capabilities->DeviceState, DeviceExtension->PowerInfo.DevicePowerMatrix, sizeof(Capabilities->DeviceState));

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIRootIrpQueryCapabilities(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    PDEVICE_CAPABILITIES Capabilities;
    PIO_STACK_LOCATION IoStack;
    KEVENT Event;
    NTSTATUS Status;

    PAGED_CODE();

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    DPRINT("ACPIRootIrpQueryCapabilities: %p (%p), %p\n", DeviceObject, DeviceExtension, Irp);

    KeInitializeEvent(&Event, SynchronizationEvent, 0);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, ACPIRootIrpCompleteRoutine, &Event, TRUE, TRUE, TRUE);

    Status = IoCallDriver(DeviceExtension->TargetDeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    if (NT_SUCCESS(Status))
    {
        IoStack = Irp->Tail.Overlay.CurrentStackLocation;
        Capabilities = IoStack->Parameters.DeviceCapabilities.Capabilities;

        Capabilities->LockSupported = 0;
        Capabilities->EjectSupported = 0;
        Capabilities->Removable = 0;
        Capabilities->UniqueID = 1;
        Capabilities->RawDeviceOK = 0;
        Capabilities->SurpriseRemovalOK = 0;

        Capabilities->UINumber = 0xFFFFFFFF;
        Capabilities->Address = 0xFFFFFFFF;

        Capabilities->SystemWake = 0;
        Capabilities->DeviceWake = 0;

        Status = ACPISystemPowerInitializeRootMapping(DeviceExtension, Capabilities);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIRootIrpQueryCapabilities: %p (%p), %p - %X\n", DeviceObject, DeviceExtension, Irp, Status);
        }
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    DPRINT("ACPIRootIrpQueryCapabilities: %p (%p), %p - %X\n", DeviceObject, DeviceExtension, Irp, Status);

    return Status;
}

NTSTATUS
NTAPI
ACPIFilterIrpDeviceUsageNotification(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* FDO Power FUNCTIOS *******************************************************/

NTSTATUS
NTAPI
ACPIDeviceIrpWaitWakeRequest(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID CallBack)
{
    PDEVICE_EXTENSION DeviceExtension;
    POWER_STATE State;
    LONG Wake;

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    State.SystemState = IoGetCurrentIrpStackLocation(Irp)->Parameters.WaitWake.PowerState;

    if (State.SystemState < 7)
        Wake = AcpiSystemStateTranslation[State.SystemState];
    else
        Wake = -1;

    DPRINT1("ACPIDeviceIrpWaitWakeRequest: %p, %X\n", Irp, Wake);

    return ACPIDeviceInitializePowerRequest(DeviceExtension,
                                            State,
                                            CallBack,
                                            Irp,
                                            PowerActionNone,
                                            AcpiPowerRequestWaitWake,
                                            2);
}

VOID
NTAPI
ACPIDeviceIrpCompleteRequest(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID Context,
    _In_ NTSTATUS InStatus)
{
    PIRP Irp = Context;

    DPRINT("ACPIDeviceIrpCompleteRequest: %p, %X\n", Irp, InStatus);

    PoStartNextPowerIrp(Irp);
    IoMarkIrpPending(Irp);

    Irp->IoStatus.Status = InStatus;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    ACPIInternalDecrementIrpReferenceCount(DeviceExtension);
}

NTSTATUS
NTAPI
ACPIDispatchForwardOrFailPowerIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;

    DPRINT("ACPIDispatchForwardOrFailPowerIrp: %X\n", DeviceObject);

    PoStartNextPowerIrp(Irp);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    if (DeviceExtension->Flags & 0x20 || !DeviceExtension->TargetDeviceObject)
    {
        Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return Irp->IoStatus.Status;
    }

    IoCopyCurrentIrpStackLocationToNext(Irp);

    return PoCallDriver(DeviceExtension->TargetDeviceObject, Irp);
}

NTSTATUS
NTAPI
ACPIWakeWaitIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    PIO_STACK_LOCATION IoStack;
    SYSTEM_POWER_STATE SystemWakeState;
    SYSTEM_POWER_STATE IrpWakeState;
    DEVICE_POWER_STATE DeviceWakeState;
    DEVICE_POWER_STATE IrpPowerState;
    NTSTATUS Status;

    DPRINT("ACPIWakeWaitIrp: %p, %p\n", DeviceObject, Irp);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    if (!(DeviceExtension->Flags & 0x10000))
        return ACPIDispatchForwardOrFailPowerIrp(DeviceObject, Irp);

    SystemWakeState = DeviceExtension->PowerInfo.SystemWakeLevel;
    IoStack = IoGetCurrentIrpStackLocation(Irp);
    IrpWakeState = IoStack->Parameters.WaitWake.PowerState;

    if (SystemWakeState < IrpWakeState)
    {
        DPRINT1("ACPIWakeWaitIrp: STATUS_INVALID_DEVICE_STATE (%X, %X)\n", (SystemWakeState - 1), (IrpWakeState - 1));

        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_STATE;

        PoStartNextPowerIrp(Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_INVALID_DEVICE_STATE;
    }

    DeviceWakeState = DeviceExtension->PowerInfo.DeviceWakeLevel;
    IrpPowerState = DeviceExtension->PowerInfo.PowerState;

    if (DeviceWakeState < IrpPowerState)
    {
        DPRINT1("ACPIWakeWaitIrp: STATUS_INVALID_DEVICE_STATE (%X, %X)\n", (DeviceWakeState - 1), (IrpPowerState - 1));

        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_STATE;

        PoStartNextPowerIrp(Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_INVALID_DEVICE_STATE;
    }

    IoMarkIrpPending(Irp);

    InterlockedIncrement(&DeviceExtension->OutstandingIrpCount);

    Status = ACPIDeviceIrpWaitWakeRequest(DeviceObject, Irp, ACPIDeviceIrpCompleteRequest);

    if (Status == STATUS_MORE_PROCESSING_REQUIRED)
        Status = STATUS_PENDING;
    else
        ACPIInternalDecrementIrpReferenceCount(DeviceExtension);

    return Status;
}

NTSTATUS
NTAPI
ACPIDispatchForwardPowerIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status;

    PoStartNextPowerIrp(Irp);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    if (!DeviceExtension->TargetDeviceObject || (DeviceExtension->Flags & 0x20))
    {
        Status = Irp->IoStatus.Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Status;
    }

    IoSkipCurrentIrpStackLocation(Irp);

    return PoCallDriver(DeviceExtension->TargetDeviceObject, Irp);
}

NTSTATUS
NTAPI
ACPIRootIrpSetPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIRootIrpQueryPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* PDO PNP FUNCTIOS *********************************************************/

NTSTATUS
NTAPI
ACPIBusIrpQueryRemoveOrStopDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ACPIBusIrpQueryRemoveOrStopDevice: %X\n", DeviceObject);
    PAGED_CODE();

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    if (DeviceExtension->Flags & 0x0000000000200000)
    {
        Status = STATUS_INVALID_DEVICE_REQUEST;
    }
    else
    {
        DeviceExtension->PreviousState = DeviceExtension->DeviceState;
        DeviceExtension->DeviceState = 1;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
ACPIBusIrpRemoveDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIBusIrpCancelRemoveOrStopDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;

    DPRINT("ACPIBusIrpCancelRemoveOrStopDevice: %X\n", DeviceObject);
    PAGED_CODE();

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    if (!(DeviceExtension->Flags & 0x0000000000200000) && DeviceExtension->DeviceState == 1)
        DeviceExtension->DeviceState = DeviceExtension->PreviousState;

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, 0);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIBusIrpStopDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIBusIrpQueryBusRelations(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _Out_ PDEVICE_RELATIONS* DeviceRelations)
{
    PDEVICE_EXTENSION DeviceExtension;
    PAMLI_NAME_SPACE_OBJECT NsObject;
    NTSTATUS status;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ACPIBusIrpQueryBusRelations: %p\n", DeviceObject);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    NsObject = DeviceExtension->AcpiObject;
    if (!NsObject)
    {
        DPRINT1("ACPIBusIrpQueryBusRelations: invalid NsObject %p\n", NsObject);
        return STATUS_INVALID_PARAMETER;
    }

    Status = ACPIDetectPdoDevices(DeviceObject, DeviceRelations);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIBusIrpQueryBusRelations: enum Status %X\n", Status);
        return Status;
    }

    status = ACPIDetectFilterDevices(DeviceObject, *DeviceRelations);
    if (!NT_SUCCESS(status))
    {
        DPRINT1("ACPIBusIrpQueryBusRelations: status %X\n", status);
    }

    DPRINT("ACPIBusIrpQueryBusRelations: Status %X\n", Status);
    return Status;
}

NTSTATUS
NTAPI
ACPIBusIrpQueryTargetRelation(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _Out_ PDEVICE_RELATIONS* OutDeviceRelations)
{
    PDEVICE_RELATIONS DeviceRelations;
    NTSTATUS Status;

    DPRINT("ACPIBusIrpQueryBusRelations: %p\n", DeviceObject);

    PAGED_CODE();
    ASSERT(*OutDeviceRelations == NULL);

    *OutDeviceRelations = DeviceRelations = ExAllocatePoolWithTag(NonPagedPool, sizeof(*DeviceRelations), 'IpcA');
    if (!DeviceRelations)
    {
        DPRINT1("ACPIBusIrpQueryBusRelations: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = ObReferenceObjectByPointer(DeviceObject, 0, 0, 0);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIBusIrpQueryBusRelations: Status %X\n", Status);
        ExFreePoolWithTag(*OutDeviceRelations, 'IpcA');
        return Status;
    }

    (*OutDeviceRelations)->Count = 1;
    (*OutDeviceRelations)->Objects[0] = DeviceObject;
 
    return Status;
}

NTSTATUS
NTAPI
ACPIBusIrpQueryDeviceRelations(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_RELATIONS DeviceRelations;
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    DPRINT("ACPIBusIrpQueryDeviceRelations: %X, %X\n", DeviceObject, Irp);
    PAGED_CODE();

    DeviceRelations = (PDEVICE_RELATIONS)Irp->IoStatus.Information;

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    switch(IoStack->Parameters.QueryDeviceRelations.Type)
    {
        case BusRelations:
            Status = ACPIBusIrpQueryBusRelations(DeviceObject, Irp, &DeviceRelations);
            break;

        case EjectionRelations:
            DPRINT1("ACPIBusIrpQueryDeviceRelations: FIXME\n");
            ASSERT(FALSE);
            break;

        case TargetDeviceRelation:
            Status = ACPIBusIrpQueryTargetRelation(DeviceObject, Irp, &DeviceRelations);
            break;

        default:
            Status = STATUS_NOT_SUPPORTED;
            DPRINT1("ACPIBusIrpQueryDeviceRelations: Unhandled Type %X\n", IoStack->Parameters.QueryDeviceRelations.Type);
            ASSERT(FALSE);
            break;
    }

    if (NT_SUCCESS(Status))
    {
        Irp->IoStatus.Status = Status;
        Irp->IoStatus.Information = (ULONG_PTR)DeviceRelations;
    }
    else if (Status != STATUS_NOT_SUPPORTED && !DeviceRelations)
    {
        Irp->IoStatus.Status = Status;
        Irp->IoStatus.Information = 0;
    }
    else
    {
        Status = Irp->IoStatus.Status;
    }

    IoCompleteRequest(Irp, 0);

    DPRINT("ACPIBusIrpQueryDeviceRelations: Status %X\n", Status);

    return Status;
}

NTSTATUS
NTAPI
PciConfigInternal(
    _In_ ULONG Type,
    _In_ PAMLI_NAME_SPACE_OBJECT InNsObject,
    _In_ ULONG Offset,
    _In_ ULONG Length,
    _In_ PVOID Callback,
    _In_ PVOID Context,
    _In_ PVOID Buffer)
{
    PACPI_PCI_CONFIG_INT_CONTEXT PciCfgContext;
    NTSTATUS Status;

    DPRINT("PciConfigInternal: %p\n", InNsObject);

    PciCfgContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(*PciCfgContext), 'FpcA');
    if (!PciCfgContext)
    {
        DPRINT1("PciConfigInternal: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(PciCfgContext, sizeof(*PciCfgContext));

    PciCfgContext->NsObject.Context = InNsObject;

    PciCfgContext->PciConfig.Type = Type;
    PciCfgContext->PciConfig.NsObject = &PciCfgContext->NsObject;
    PciCfgContext->PciConfig.ParentNsObject = InNsObject;

    PciCfgContext->PciConfig.Buffer = Buffer;
    PciCfgContext->PciConfig.Length = Length;
    PciCfgContext->PciConfig.Offset = Offset;

    PciCfgContext->PciConfig.Handler = NULL;
    PciCfgContext->PciConfig.Callback = Callback;
    PciCfgContext->PciConfig.Context = Context;
    PciCfgContext->PciConfig.Unknown1 = 1;
    PciCfgContext->PciConfig.RefCount = -1;

    Status = PciConfigSpaceHandlerWorker(InNsObject, STATUS_SUCCESS, 0, &PciCfgContext->PciConfig);

    DPRINT("PciConfigInternal: ret %X\n", Status);

    return Status;
}

NTSTATUS
__cdecl
IsPciBusAsyncWorker(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ NTSTATUS InStatus,
    _In_ PVOID Param3,
    _In_ PVOID InContext)
{
    PIS_PCI_BUS_CONTEXT Context = InContext;
    PPCI_COMMON_CONFIG PciData;

    DPRINT("IsPciBusAsyncWorker: %X, %X, %X, %X\n", NsObject, InStatus, Param3, InContext);

    ASSERT(InContext);

    InterlockedIncrement(&Context->RefCount);

    if (!Context->NsObject)
    {
        *Context->OutIsBusAsync = FALSE;
        goto Finish;
    }

    if (!NT_SUCCESS(InStatus))
    {
        *Context->OutIsBusAsync = FALSE;
        goto Finish;
    }

    if (!(Context->Flags & 1))
    {
        Context->Flags |= 1;
        Context->HidId = NULL;

        if (ACPIAmliGetNamedChild(Context->NsObject, 'DIH_'))
        {
            InStatus = ACPIGet(Context->NsObject, 'DIH_', 0x58080206, NULL, 0, IsPciBusAsyncWorker, Context, (PVOID *)&Context->HidId, NULL);
            if (InStatus == STATUS_PENDING)
            {
                DPRINT("IsPciBusAsyncWorker: ret STATUS_PENDING\n");
                return STATUS_PENDING;
            }

            if (!NT_SUCCESS(InStatus))
            {
                *Context->OutIsBusAsync = FALSE;
                goto Finish;
            }
        }
    }

    if (Context->HidId)
    {
        if (strstr(Context->HidId, "PNP0A03"))
        {
            *Context->OutIsBusAsync = TRUE;
            goto Finish;
        }

        ExFreePool(Context->HidId);
        Context->HidId = NULL;
    }

    if (!(Context->Flags & 0x80))
    {
        Context->Flags |= 0x80;
        Context->CidId = NULL;

        if (ACPIAmliGetNamedChild(Context->NsObject, 'DIC_'))
        {
            InStatus = ACPIGet(Context->NsObject, 'DIC_', 0x58080107, NULL, 0, IsPciBusAsyncWorker, Context, (PVOID *)&Context->CidId, NULL);
            if (InStatus == STATUS_PENDING)
            {
                DPRINT("IsPciBusAsyncWorker: ret STATUS_PENDING\n");
                return STATUS_PENDING;
            }

            if (!NT_SUCCESS(InStatus))
            {
                *Context->OutIsBusAsync = FALSE;
                goto Finish;
            }
        }
    }

    if (Context->CidId)
    {
        if (strstr(Context->CidId, "PNP0A03"))
        {
            *Context->OutIsBusAsync = TRUE;
            goto Finish;
        }

        ExFreePool(Context->CidId);
        Context->CidId = NULL;
    }

    if (!(Context->Flags & 2))
    {
        Context->Flags |= 2;

        InStatus = IsPciDevice(Context->NsObject, IsPciBusAsyncWorker, (PVOID)Context, &Context->IsPciDevice);
        if (InStatus == STATUS_PENDING)
        {
            DPRINT("IsPciBusAsyncWorker: ret STATUS_PENDING\n");
            return STATUS_PENDING;
        }

        if (!NT_SUCCESS(InStatus))
        {
            *Context->OutIsBusAsync = FALSE;
            goto Finish;
        }
    }

    if (Context->IsPciDevice)
    {
        if (!(Context->Flags & 8))
        {
            Context->Flags |= 8;

            InStatus = ACPIGet(Context->NsObject, 'RDA_', 0x48040402, NULL, 0, IsPciBusAsyncWorker, Context, &Context->Adr, NULL);
            if (InStatus == STATUS_PENDING)
            {
                DPRINT("IsPciBusAsyncWorker: ret STATUS_PENDING\n");
                return STATUS_PENDING;
            }

            if (!NT_SUCCESS(InStatus))
            {
                *Context->OutIsBusAsync = FALSE;
                goto Finish;
            }
        }

        if (!(Context->Flags & 0x40))
        {
            Context->Flags |= 0x40;

            InStatus = PciConfigInternal(0, Context->NsObject, 0, 0x40, IsPciBusAsyncWorker, Context, Context->Buffer);
            if (InStatus == STATUS_PENDING)
            {
                DPRINT("IsPciBusAsyncWorker: ret STATUS_PENDING\n");
                return STATUS_PENDING;
            }

            if (!NT_SUCCESS(InStatus))
            {
                *Context->OutIsBusAsync = FALSE;
                goto Finish;
            }
        }

        PciData = (PPCI_COMMON_CONFIG)Context->Buffer;

        if (((PciData->HeaderType & 0x7F) != 1) && ((PciData->HeaderType & 0x7F) != 2))
            *Context->OutIsBusAsync = FALSE;
        else
            *Context->OutIsBusAsync = TRUE;
    }

Finish:

    if (InStatus == STATUS_OBJECT_NAME_NOT_FOUND)
        InStatus = STATUS_SUCCESS;

    if (Context->RefCount)
    {
        PAMLI_FN_CALLBACK2 CallBack = Context->CallBack;
        CallBack(Context->NsObject, InStatus, 0, Context->CallBackContext);
    }

    if (Context->HidId)
        ExFreePool(Context->HidId);

    if (Context->CidId)
        ExFreePool(Context->CidId);

    ExFreePool(Context);

    DPRINT("IsPciBusAsyncWorker: ret %X\n", InStatus);
    return InStatus;
}

NTSTATUS
NTAPI
IsPciBusAsync(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ PVOID CallBack,
    _In_ PVOID CallBackContext,
    _In_ BOOLEAN* OutIsBusAsync)
{
    PDEVICE_EXTENSION DeviceExtension;
    PIS_PCI_BUS_CONTEXT Context;
    NTSTATUS Status;

    DPRINT("IsPciBusAsync: NsObject %p\n", NsObject);

    DeviceExtension = NsObject->Context;
    if (DeviceExtension)
    {
        ASSERT(DeviceExtension->Signature == '_SGP');//ACPI_SIGNATURE

        if (DeviceExtension->Flags & 0x0000000002000000)
        {
            *OutIsBusAsync = TRUE;
            return STATUS_SUCCESS;
        }
    }

    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(IS_PCI_BUS_CONTEXT), 'FpcA');
    if (!Context)
    {
        DPRINT1("IsPciBusAsync: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(Context, sizeof(IS_PCI_BUS_CONTEXT));

    Context->NsObject = NsObject;
    Context->RefCount = -1;
    Context->CallBack = CallBack;
    Context->CallBackContext = CallBackContext;
    Context->OutIsBusAsync = OutIsBusAsync;

    *OutIsBusAsync = FALSE;

    Status = IsPciBusAsyncWorker(NsObject, STATUS_SUCCESS, NULL, Context);

    return Status;
}

BOOLEAN
NTAPI
IsNsobjPciBus(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject)
{
    PDEVICE_EXTENSION DeviceExtension;
    ACPI_WAIT_CONTEXT WaitContext;
    BOOLEAN IsBusAsync = FALSE;
    NTSTATUS Status;

    DPRINT("IsPciBusExtension: NsObject %p\n", NsObject);
    PAGED_CODE();

    DeviceExtension = NsObject->Context;
    if (DeviceExtension)
    {
        ASSERT(DeviceExtension->Signature == '_SGP'); // ACPI_SIGNATURE

        if (DeviceExtension->Flags & 0x0000000002000000)
            return TRUE;
    }

    KeInitializeEvent(&WaitContext.Event, SynchronizationEvent, FALSE);

    WaitContext.Status = STATUS_NOT_FOUND;

    Status = IsPciBusAsync(NsObject, AmlisuppCompletePassive, &WaitContext, &IsBusAsync);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&WaitContext.Event, Executive, KernelMode, FALSE, NULL);
    }

    return IsBusAsync;
}

BOOLEAN
NTAPI
IsPciBusExtension(
    _In_ PDEVICE_EXTENSION DeviceExtension)
{
    DPRINT("IsPciBusExtension: DeviceExtension %p\n", DeviceExtension);
    PAGED_CODE();
    return IsNsobjPciBus(DeviceExtension->AcpiObject);
}

BOOLEAN
NTAPI
IsPciBus(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PDEVICE_EXTENSION DeviceExtension;

    DPRINT("IsPciBus: DeviceObject %p\n", DeviceObject);
    PAGED_CODE();

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    return IsPciBusExtension(DeviceExtension);
}

NTSTATUS
NTAPI
TranslateEjectInterface(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    PIO_STACK_LOCATION IoStack;
    PIO_RESOURCE_DESCRIPTOR IoDescriptor;
    PTRANSLATOR_INTERFACE TranslateInterface;
    PIO_RESOURCE_REQUIREMENTS_LIST IoResource = NULL;
    PVOID Data = NULL;
    PHYSICAL_ADDRESS MinimumAddress;
    ULONG ix;
    ULONG DataLen;
    NTSTATUS Status;

    DPRINT("TranslateEjectInterface: DeviceObject %p\n", DeviceObject);
    PAGED_CODE();

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    ASSERT(DeviceExtension);
    ASSERT(DeviceExtension->AcpiObject);

    IoStack = Irp->Tail.Overlay.CurrentStackLocation;
    ASSERT(IoStack->Parameters.QueryInterface.Size >= sizeof(TRANSLATOR_INTERFACE));

    TranslateInterface = (PVOID)IoStack->Parameters.QueryInterface.Interface;
    ASSERT(TranslateInterface != NULL);

    Status = ACPIGet(DeviceExtension, 'SRC_', 0x20010008, NULL, 0, NULL, NULL, &Data, &DataLen);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("TranslateEjectInterface: Status %X\n", Status);
        Status = Irp->IoStatus.Status;
        goto Exit;
    }

    Status = PnpBiosResourcesToNtResources(Data, 1, &IoResource);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("TranslateEjectInterface: Status %X\n", Status);
        goto Exit;
    }

    if (!IoResource || !IoResource->List[0].Count)
    {
        DPRINT1("TranslateEjectInterface: Status %X\n", Status);
        Status = Irp->IoStatus.Status;
        goto Exit;
    }

    for (ix = 0; ix < IoResource->List[0].Count; ix++)
    {
        IoDescriptor = &IoResource->List[0].Descriptors[ix];

        if (IoResource->List[0].Descriptors[ix].Type == 0x81 &&
            (IoResource->List[0].Descriptors[ix].Flags & 0x6000))
        {
            ASSERT(ix != 0);

            MinimumAddress.LowPart  = IoDescriptor->u.DevicePrivate.Data[1];
            MinimumAddress.HighPart = IoDescriptor->u.DevicePrivate.Data[2];

            if (IoDescriptor->u.DevicePrivate.Data[0] != IoResource->List[0].Descriptors[ix - 1].Type ||
                (MinimumAddress.QuadPart != IoDescriptor[-1].u.Generic.MinimumAddress.QuadPart))
            {
                DPRINT1("TranslateEjectInterface: FIXME\n");
                ASSERT(FALSE);
                break;
            }
        }
    }

    Status = Irp->IoStatus.Status;

Exit:

    if (Data)
        ExFreePool(Data);

    if (IoResource)
        ExFreePool(IoResource);

    return Status;
}

VOID
NTAPI
PciInterfacePinToLine(
    _In_ PVOID Context,
    _In_ PPCI_COMMON_CONFIG PciData)
{
    ;
}

VOID
NTAPI
PciInterfaceLineToPin(
    _In_ PVOID Context,
    _In_ PPCI_COMMON_CONFIG PciNewData,
    _In_ PPCI_COMMON_CONFIG PciOldData)
{
    ;
}

NTSTATUS
NTAPI
PciBusEjectInterface(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_RESOURCE_REQUIREMENTS_LIST IoResource = NULL;
    PPCI_BUS_INTERFACE_STANDARD Interface;
    PIO_STACK_LOCATION IoStack;
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status;
    BOOLEAN IsFound = FALSE;
    AMLI_OBJECT_DATA Data;
    ULONG MinBusNumber;
    ULONG ix;

    DPRINT("PciBusEjectInterface: DeviceObject %p\n", DeviceObject);
    PAGED_CODE();

    ASSERT(PmHalDispatchTable->Function[6]);//HalPciInterfaceReadConfig
    ASSERT(PmHalDispatchTable->Function[7]);//HalPciInterfaceWriteConfig

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    ASSERT(DeviceExtension);
    ASSERT(DeviceExtension->AcpiObject);

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(IoStack->Parameters.QueryInterface.Size >= sizeof(PCI_BUS_INTERFACE_STANDARD));

    Interface = (PPCI_BUS_INTERFACE_STANDARD)IoStack->Parameters.QueryInterface.Interface;
    ASSERT(Interface);

    Status = ACPIGet(DeviceExtension, 'SRC_', 0x20020000, NULL, 0, NULL, NULL, (PVOID *)&Data, 0);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciBusEjectInterface: Status %X\n", Status);
        goto Finish;
    }

    ASSERT(Data.DataType == 3);//OBJTYPE_BUFFDATA

    Status = PnpBiosResourcesToNtResources(Data.DataBuff, 1, &IoResource);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciBusEjectInterface: Status %X\n", Status);
        AMLIFreeDataBuffs(&Data, 1);
        goto Finish;
    }

    if (!IoResource)
    {
        AMLIFreeDataBuffs(&Data, 1);
        goto Finish;
    }

    ASSERT(IoResource->AlternativeLists == 1);

    for (ix = 0; ix < IoResource->List[0].Count; ix++)
    {
        if (IoResource->List[0].Descriptors[ix].Type == CmResourceTypeBusNumber)
            break;
    }

    if (ix != IoResource->List[0].Count)
    {
        MinBusNumber = IoResource->List[0].Descriptors[ix].u.BusNumber.MinBusNumber;
        IsFound = TRUE;
    }

    AMLIFreeDataBuffs(&Data, 1);

Finish:

    if (!IsFound)
        MinBusNumber = 0;

    Interface->Size = sizeof(PCI_BUS_INTERFACE_STANDARD);
    Interface->Version = 1;
    Interface->Context = (PVOID)MinBusNumber;
    Interface->InterfaceReference = AcpiNullReference;
    Interface->InterfaceDereference = AcpiNullReference;
    Interface->ReadConfig = PmHalDispatchTable->Function[6];//HalPciInterfaceReadConfig;
    Interface->WriteConfig = PmHalDispatchTable->Function[7];//HalPciInterfaceWriteConfig;
    Interface->PinToLine = PciInterfacePinToLine;
    Interface->LineToPin = PciInterfaceLineToPin;

    if (IoResource)
        ExFreePool(IoResource);

    Irp->IoStatus.Status = STATUS_SUCCESS;

    return STATUS_SUCCESS;
}

VOID
NTAPI
SmashInterfaceQuery(
    _In_ PIRP Irp)
{
    GUID* InterfaceType;

    DPRINT("SmashInterfaceQuery: %p\n", Irp);
    PAGED_CODE();

    InterfaceType = (GUID*)(IoGetCurrentIrpStackLocation(Irp))->Parameters.QueryInterface.InterfaceType;

    RtlZeroMemory(InterfaceType, sizeof(*InterfaceType));

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
ACPIBusIrpQueryInterface(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    PACPI_INTERFACE_STANDARD Interface;
    PIO_STACK_LOCATION IoStack;
    GUID* InterfaceType;
    UNICODE_STRING GuidString;
    CM_RESOURCE_TYPE ResourceType;
    ULONG Size;
    NTSTATUS Status;

    DPRINT("ACPIBusIrpQueryInterface: DeviceObject %p\n", DeviceObject);
    PAGED_CODE();

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    IoStack = Irp->Tail.Overlay.CurrentStackLocation;

    InterfaceType = (PVOID)IoStack->Parameters.QueryInterface.InterfaceType;
    ResourceType = (CM_RESOURCE_TYPE)IoStack->Parameters.QueryInterface.InterfaceSpecificData;

    Status = RtlStringFromGUID(InterfaceType, &GuidString);
    if (NT_SUCCESS(Status))
    {
        DPRINT("ACPIBusIrpQueryInterface: %X, %X, '%wZ'\n", IoStack->MinorFunction, ResourceType, &GuidString);
        RtlFreeUnicodeString(&GuidString);
    }

    Status = STATUS_NOT_SUPPORTED;

    if (InterfaceType == &GUID_ACPI_INTERFACE_STANDARD ||
        RtlCompareMemory(InterfaceType, &GUID_ACPI_INTERFACE_STANDARD, sizeof(GUID)) == sizeof(GUID))
    {
        DPRINT("ACPIBusIrpQueryInterface: GUID_ACPI_INTERFACE_STANDARD\n");

        if (IoStack->Parameters.QueryInterface.Size <= sizeof(ACPI_INTERFACE_STANDARD))
            Size = IoStack->Parameters.QueryInterface.Size;
        else
            Size = sizeof(ACPI_INTERFACE_STANDARD);

        Interface = (PVOID)IoStack->Parameters.QueryInterface.Interface;
        RtlCopyMemory(Interface, &ACPIInterfaceTable, Size);

        if (Size > 8) // FIXME
            Interface->Context = DeviceObject;

        Irp->IoStatus.Status = Status = STATUS_SUCCESS;

        goto Exit;
    }

    if (InterfaceType == &GUID_TRANSLATOR_INTERFACE_STANDARD ||
        RtlCompareMemory(InterfaceType, &GUID_TRANSLATOR_INTERFACE_STANDARD, sizeof(GUID)) == sizeof(GUID))
    {
        DPRINT("ACPIBusIrpQueryInterface: GUID_TRANSLATOR_INTERFACE_STANDARD. ResourceType %X\n", ResourceType);

        if (ResourceType == CmResourceTypeInterrupt)
        {
            if (IsPciBus(DeviceObject))
                SmashInterfaceQuery(Irp);

            Status = Irp->IoStatus.Status;
        }
        else
        {
            if ((ResourceType == CmResourceTypePort || ResourceType == CmResourceTypeMemory) && IsPciBus(DeviceObject))
            {
                Status = TranslateEjectInterface(DeviceObject, Irp);
            }

            if (Status == STATUS_NOT_SUPPORTED)
                Status = Irp->IoStatus.Status;
            else
                Irp->IoStatus.Status = Status;
        }

        goto Exit;
    }

    if (InterfaceType == &GUID_PCI_BUS_INTERFACE_STANDARD ||
        RtlCompareMemory(InterfaceType, &GUID_PCI_BUS_INTERFACE_STANDARD, sizeof(GUID)) == sizeof(GUID))
    {
        if (!IsPciBus(DeviceObject))
        {
            Status = Irp->IoStatus.Status;
            goto Exit;
        }

        Status = PciBusEjectInterface(DeviceObject, Irp);

        if (Status == STATUS_NOT_SUPPORTED)
            Status = Irp->IoStatus.Status;
        else
            Irp->IoStatus.Status = Status;

        goto Exit;
    }

    if (InterfaceType == &GUID_BUS_INTERFACE_STANDARD ||
        RtlCompareMemory(InterfaceType, &GUID_BUS_INTERFACE_STANDARD, sizeof(GUID)) == sizeof(GUID))
    {
        DPRINT("ACPIBusIrpQueryInterface: GUID_BUS_INTERFACE_STANDARD\n");

        Irp->IoStatus.Status = STATUS_NOINTERFACE;

        if (DeviceExtension->ParentExtension)
        {
            if (DeviceExtension->ParentExtension->DeviceObject)
            {
                Irp->IoStatus.Status = ACPIInternalSendSynchronousIrp(DeviceExtension->ParentExtension->DeviceObject, IoStack, 0);
            }
        }

        Status = Irp->IoStatus.Status;

        goto Exit;
    }

    if (InterfaceType == &GUID_ARBITER_INTERFACE_STANDARD ||
        RtlCompareMemory(InterfaceType, &GUID_ARBITER_INTERFACE_STANDARD, sizeof(GUID)) == sizeof(GUID))
    {
        DPRINT("ACPIBusIrpQueryInterface: GUID_ARBITER_INTERFACE_STANDARD\n");

        if ((DeviceExtension->Flags & 0x0000002000000000) && DeviceExtension->Module.ArbitersNeeded)
        {
            DPRINT1("ACPIBusIrpQueryInterface: FIXME\n");
            ASSERT(FALSE);
            Irp->IoStatus.Status = Status = 0;//AcpiArblibEjectInterface(DeviceObject, Irp);

            if (Status == STATUS_NOT_SUPPORTED)
                Status = Irp->IoStatus.Status;

            goto Exit;
        }
    }

    Status = Irp->IoStatus.Status;

Exit:

    IoCompleteRequest(Irp, 0);
    return Status;
}

NTSTATUS
NTAPI
ACPIInternalSendSynchronousIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIO_STACK_LOCATION InIoStack,
    _Out_ ULONG_PTR* OutInformation)
{
    PDEVICE_OBJECT AttachedDevice;
    PIO_STACK_LOCATION IoStack;
    IO_STATUS_BLOCK ioStatus;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    PAGED_CODE();

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    AttachedDevice = IoGetAttachedDeviceReference(DeviceObject);

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP, AttachedDevice, NULL, 0, NULL, &Event, &ioStatus);
    if (!Irp)
    {
        DPRINT1("ACPIInternalSendSynchronousIrp: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;

    IoStack = IoGetNextIrpStackLocation(Irp);
    if (!IoStack)
    {
        DPRINT1("ACPIInternalSendSynchronousIrp: STATUS_INVALID_PARAMETER\n");
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    *IoStack = *InIoStack;

    IoSetCompletionRoutine(Irp, NULL, NULL, FALSE, FALSE, FALSE);

    Status = IoCallDriver(AttachedDevice, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = ioStatus.Status;
    }

    if (NT_SUCCESS(Status) && OutInformation)
        *OutInformation = ioStatus.Information;

Exit:

    DPRINT("ACPIInternalSendSynchronousIrp: DeviceObject %p, Status %X\n", DeviceObject, Status);

    ObDereferenceObject(AttachedDevice);

    return Status;
}

NTSTATUS
NTAPI
ACPIInternalGetDeviceCapabilities(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PDEVICE_CAPABILITIES Capabilities)
{
    IO_STACK_LOCATION ioStack;
    ULONG_PTR dummyInformation;

    PAGED_CODE();

    ASSERT(DeviceObject != NULL);
    ASSERT(Capabilities != NULL);

    RtlZeroMemory(&ioStack, sizeof(IO_STACK_LOCATION));
    RtlZeroMemory(Capabilities, sizeof(DEVICE_CAPABILITIES));

    Capabilities->Address = 0xFFFFFFFF;
    Capabilities->UINumber = 0xFFFFFFFF;

    ioStack.MajorFunction = IRP_MJ_PNP;
    ioStack.MinorFunction = IRP_MN_QUERY_CAPABILITIES;

    ioStack.Parameters.DeviceCapabilities.Capabilities = Capabilities;

    Capabilities->Size = sizeof(*Capabilities);
    Capabilities->Version = 1;

    return ACPIInternalSendSynchronousIrp(DeviceObject, &ioStack, (ULONG_PTR *)&dummyInformation);
}

NTSTATUS
NTAPI
ACPIDevicePowerDetermineSupportedDeviceStates(
     _In_ PDEVICE_EXTENSION DeviceExtension,
     _Out_ ULONG* OutSupportedPrStates,
     _Out_ ULONG* OutSupportedPsStates)
{
    ULONG PsNameSegment[4] = {'0SP_', '1SP_', '2SP_', '3SP_'};
    ULONG PrNameSegment[3] = {'0RP_', '1RP_', '2RP_'};
    ULONG PsStates = 0;
    ULONG PrStates = 0;
    ULONG Shift;
    ULONG ix;
    ULONG States;

    PAGED_CODE();

    ASSERT(DeviceExtension != NULL);
    ASSERT(OutSupportedPrStates != NULL);
    ASSERT(OutSupportedPsStates != NULL);

    *OutSupportedPrStates = 0;
    *OutSupportedPsStates = 0;

    if (DeviceExtension->Flags & 0x0008000000000000)
    {
        *OutSupportedPrStates = PrStates;
        *OutSupportedPsStates = 0x12;
        return STATUS_SUCCESS;
    }

    Shift = 1;
    for (ix = 0; Shift <= 4; ix++, Shift++)
    {
        if (ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, PsNameSegment[ix]))
            PsStates |= (1 << Shift);
    }

    Shift = 1;
    for (ix = 0; Shift <= 3; ix++, Shift++)
    {
        if (ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, PrNameSegment[ix]))
            PrStates |= ((1 << Shift) | 0x10);
    }

    States = (PrStates | PsStates);

    if (!States)
        return STATUS_SUCCESS;

    if (!(States & 2))
    {
        DPRINT("ACPIDevicePowerDetermineSupportedDeviceStates: does not support D0 power state!\n");
        ASSERT(FALSE);
        KeBugCheckEx(0xA5, 0xD, (ULONG_PTR)DeviceExtension, (PrStates ? '0RP_' : '0SP_'), 0);
    }
    else if (!(States & 0x10))
    {
        DPRINT("ACPIDevicePowerDetermineSupportedDeviceStates: does not support D3 power state!\n");
        ASSERT(FALSE);
        KeBugCheckEx(0xA5, 0xD, (ULONG_PTR)DeviceExtension, '3SP_', 0);
    }
    else
    {
        if (PrStates && PsStates && PrStates != PsStates)
        {
            DPRINT("ACPIDevicePowerDetermineSupportedDeviceStates: has mismatch between power plane and power source information!\n");
            PrStates &= PsStates;
            PsStates &= PrStates;
        }

        *OutSupportedPrStates = PrStates;
        *OutSupportedPsStates = PsStates;
    }

    return STATUS_SUCCESS;
}

DEVICE_POWER_STATE
NTAPI
ACPISystemPowerDetermineSupportedDeviceWakeState(
     _In_ PDEVICE_EXTENSION DeviceExtension)
{
    PACPI_DEVICE_POWER_NODE Node;
    DEVICE_POWER_STATE RetDeviceState = PowerDeviceMaximum;

    for (Node = DeviceExtension->PowerInfo.PowerNode[0];
         Node;
         Node = Node->Next)
    {
        if (RetDeviceState > Node->AssociatedDeviceState)
            RetDeviceState = Node->AssociatedDeviceState;
    }

    if (RetDeviceState == PowerDeviceMaximum)
        RetDeviceState = PowerDeviceUnspecified;

    return RetDeviceState;
}

NTSTATUS
NTAPI
ACPISystemPowerUpdateWakeCapabilitiesForPDOs(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PDEVICE_CAPABILITIES Capabilities,
    _In_ PDEVICE_CAPABILITIES OutCapabilities,
    _In_ DEVICE_POWER_STATE* States,
    _Out_ ULONG* OutDeviceWakeBit,
    _Out_ SYSTEM_POWER_STATE* OutSystemWakeLevel,
    _Out_ DEVICE_POWER_STATE* OutDeviceWakeLevel,
    _Out_ DEVICE_POWER_STATE* OutWakeLevel)
{
    DEVICE_POWER_STATE DeviceWakeLevel = 0;
    DEVICE_POWER_STATE DeviceWakeState;
    DEVICE_POWER_STATE WakeLevel = 0;
    SYSTEM_POWER_STATE SystemWakeLevel;
    BOOLEAN IsFound = FALSE;
    KIRQL OldIrql;
    NTSTATUS Status;

    DPRINT("ACPISystemPowerUpdateWakeCapabilitiesForPDOs: DeviceExtension %p\n", DeviceExtension);

    if (!(DeviceExtension->Flags & 0x0000000000010000))
    {
        SystemWakeLevel = 0;

        *OutDeviceWakeBit = 0;

        goto Finish;
    }

    KeAcquireSpinLock(&AcpiPowerLock, &OldIrql);
    SystemWakeLevel = DeviceExtension->PowerInfo.SystemWakeLevel;
    DeviceWakeState = ACPISystemPowerDetermineSupportedDeviceWakeState(DeviceExtension);
    KeReleaseSpinLock(&AcpiPowerLock, OldIrql);

    if (!((1 << SystemWakeLevel) & AcpiSupportedSystemStates))
    {
        if (!(AcpiOverrideAttributes & 4))
        {
            DPRINT1("ACPISystemPowerUpdateWakeCapabilitiesForPDOs: KeBugCheckEx()! FIXME\n");
            ASSERT(FALSE);
            //KeBugCheckEx(..);
        }

        DeviceWakeLevel = 0;
        SystemWakeLevel = 0;

        *OutDeviceWakeBit = 0;

        goto Finish;
    }

    if (DeviceWakeState != PowerDeviceUnspecified)
    {
        DeviceWakeLevel = DeviceWakeState;
        WakeLevel = DeviceWakeState;

        *OutDeviceWakeBit = (1 << DeviceWakeState);

        IsFound = TRUE;
    }

    Status = ACPISystemPowerGetSxD(DeviceExtension, SystemWakeLevel, &DeviceWakeState);
    if (NT_SUCCESS(Status))
    {
        DeviceWakeLevel = DeviceWakeState;
        WakeLevel = DeviceWakeState;

        IsFound = TRUE;
    }

    if (!IsFound)
    {
        DeviceWakeLevel = States[SystemWakeLevel];
        if (DeviceWakeLevel)
        {
            *OutDeviceWakeBit = (1 << DeviceWakeLevel);
            goto Finish;
        }

        DeviceWakeLevel = 4;
    }

    if (DeviceWakeLevel == PowerDeviceUnspecified)
    {
        *OutDeviceWakeBit = 0;
        goto Finish;
    }

    *OutDeviceWakeBit = (1 << DeviceWakeLevel);

  Finish:

    if (OutSystemWakeLevel)
        *OutSystemWakeLevel = SystemWakeLevel;

    if (OutDeviceWakeLevel)
        *OutDeviceWakeLevel = DeviceWakeLevel;

    if (OutWakeLevel)
        *OutWakeLevel = WakeLevel;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPISystemPowerUpdateWakeCapabilitiesForFilters(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PDEVICE_CAPABILITIES Capabilities,
    _In_ PDEVICE_CAPABILITIES OutCapabilities,
    _In_ DEVICE_POWER_STATE* States,
    _Out_ ULONG* OutDeviceWakeBit,
    _Out_ SYSTEM_POWER_STATE* OutSystemWakeLevel,
    _Out_ DEVICE_POWER_STATE* OutDeviceWakeLevel,
    _Out_ DEVICE_POWER_STATE* OutWakeLevel)
{
    DEVICE_POWER_STATE DeviceWake;
    DEVICE_POWER_STATE InDeviceWake;
    SYSTEM_POWER_STATE SystemWakeLevel;
    SYSTEM_POWER_STATE SystemWake;
    BOOLEAN IsFound = FALSE;
    BOOLEAN IsUnspecified;
    KIRQL Irql;
    NTSTATUS Status;

    DPRINT("ACPISystemPowerUpdateWakeCapabilitiesForFilters: %p\n", DeviceExtension);

    if (OutCapabilities->WakeFromD0)
        *OutDeviceWakeBit |= 0x02;

    if (OutCapabilities->WakeFromD1)
        *OutDeviceWakeBit |= 0x04;

    if (OutCapabilities->WakeFromD2)
        *OutDeviceWakeBit |= 0x08;

    if (OutCapabilities->WakeFromD3)
        *OutDeviceWakeBit |= 0x10;

    if (OutCapabilities->DeviceWake && OutCapabilities->SystemWake)
    {
        DeviceWake = OutCapabilities->DeviceWake;
        SystemWake = OutCapabilities->SystemWake;

        IsUnspecified = FALSE;
    }
    else
    {
        DeviceWake = 0;
        SystemWake = 0;

        IsUnspecified = TRUE;
    }

    if (DeviceExtension->Flags & 0x0000000000010000)
    {
        KeAcquireSpinLock(&AcpiPowerLock, &Irql);

        SystemWakeLevel = DeviceExtension->PowerInfo.SystemWakeLevel;
        InDeviceWake = ACPISystemPowerDetermineSupportedDeviceWakeState(DeviceExtension);

        KeReleaseSpinLock(&AcpiPowerLock, Irql);

        if (SystemWake > SystemWakeLevel || IsUnspecified)
            SystemWake = SystemWakeLevel;

        if (InDeviceWake)
        {
            DeviceWake = InDeviceWake;
            IsFound = TRUE;
        }

        Status = ACPISystemPowerGetSxD(DeviceExtension, SystemWakeLevel, &InDeviceWake);

        if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
            Status = ACPISystemPowerGetSxD(DeviceExtension, SystemWake, &InDeviceWake);

        if (NT_SUCCESS(Status))
        {
            DeviceWake = InDeviceWake;
            IsFound = TRUE;
        }

        if (!IsFound)
        {
            if (States[SystemWake] == PowerDeviceUnspecified)
                DeviceWake = 4;
            else
                DeviceWake = States[SystemWake];
        }

        if (!IsUnspecified && DeviceWake < 5)
        {
            do
            {
                if (*OutDeviceWakeBit & (1 << DeviceWake))
                    break;

                DeviceWake++;
            }
            while (DeviceWake < 5);
        }

        if (DeviceWake == 5 || DeviceWake == 0)
        {
            DeviceWake = 0;
            SystemWake = 0;

            *OutDeviceWakeBit = 0;
        }
        else
        {
            *OutDeviceWakeBit = (1 << DeviceWake);
        }

        goto Exit;
    }

    Status = ACPISystemPowerGetSxD(DeviceExtension, SystemWake, &InDeviceWake);
    if (NT_SUCCESS(Status))
    {
        for (; InDeviceWake > 0; InDeviceWake--)
        {
            if (*OutDeviceWakeBit & (1 << InDeviceWake))
            {
                DeviceWake = InDeviceWake;
                break;
            }
        }
    }

    for (; SystemWake > 0; SystemWake--)
    {
        if (!(AcpiSupportedSystemStates & (1 << SystemWake)) || States[SystemWake] == 0)
            continue;

        if (States[SystemWake] <= DeviceWake)
            break;

        if (*OutDeviceWakeBit & (1 << States[SystemWake]))
        {
            DeviceWake = States[SystemWake];
            break;
        }
    }

    if (!SystemWake)
    {
        DeviceWake = 0;
        *OutDeviceWakeBit = 0;
    }

Exit:

    if (OutSystemWakeLevel)
        *OutSystemWakeLevel = SystemWake;

    if (OutDeviceWakeLevel)
        *OutDeviceWakeLevel = DeviceWake;

    if (OutWakeLevel)
        *OutWakeLevel = DeviceWake;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPISystemPowerUpdateWakeCapabilities(
     _In_ PDEVICE_EXTENSION DeviceExtension,
     _In_ PDEVICE_CAPABILITIES Capabilities,
     _In_ DEVICE_CAPABILITIES* OutCapabilities,
     _In_ DEVICE_POWER_STATE* States,
     _Out_ ULONG* OutDeviceWakeBit,
     _Out_ SYSTEM_POWER_STATE* OutSystemWakeLevel,
     _Out_ DEVICE_POWER_STATE* OutDeviceWakeLevel,
     _Out_ DEVICE_POWER_STATE* OutWakeLevel)
{
    PAGED_CODE();

    if ((DeviceExtension->Flags & 0x0000000000000040) &&
        !(DeviceExtension->Flags & 0x0000000000000020))
    {
        return ACPISystemPowerUpdateWakeCapabilitiesForFilters(DeviceExtension, Capabilities, OutCapabilities, States, OutDeviceWakeBit, OutSystemWakeLevel, OutDeviceWakeLevel, OutWakeLevel);
    }

    if (OutWakeLevel)
        *OutWakeLevel = PowerDeviceUnspecified;

    return ACPISystemPowerUpdateWakeCapabilitiesForPDOs(DeviceExtension, Capabilities, OutCapabilities, States, OutDeviceWakeBit, OutSystemWakeLevel, OutDeviceWakeLevel, OutWakeLevel);
}

NTSTATUS
NTAPI
ACPISystemPowerUpdateDeviceCapabilities(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PDEVICE_CAPABILITIES Capabilities,
    _In_ DEVICE_CAPABILITIES* OutCapabilities)
{
    DEVICE_POWER_STATE deviceState[PowerSystemMaximum];
    DEVICE_POWER_STATE DeviceStateBit;
    DEVICE_POWER_STATE CurrentState;
    DEVICE_POWER_STATE DeviceWakeLevel = 0;
    DEVICE_POWER_STATE WakeLevel = 0;
    SYSTEM_POWER_STATE SystemState;
    SYSTEM_POWER_STATE SystemWakeLevel = 0;
    ULONG SupportedPsStates = 0;
    ULONG SupportedPrStates = 0;
    ULONG SupportedStates = 0;
    ULONG DeviceWakeBit = 0;
    ULONG Bits;
    KIRQL Irql;
    BOOLEAN IsFound;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ACPISystemPowerUpdateDeviceCapabilities: DeviceExtension %p\n", DeviceExtension);

    RtlCopyMemory(deviceState, Capabilities->DeviceState, sizeof(deviceState));

    if (deviceState[PowerSystemWorking] != PowerDeviceD0)
        deviceState[PowerSystemWorking] = PowerDeviceD0;

    Status = ACPIDevicePowerDetermineSupportedDeviceStates(DeviceExtension, &SupportedPrStates, &SupportedPsStates);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPISystemPowerUpdateDeviceCapabilities: %X\n", Status);
        return Status;
    }

    SupportedStates = (SupportedPrStates | SupportedPsStates);
    if (!SupportedStates)
    {
        if ((DeviceExtension->Flags & 0x0000000000000040) &&
            !(DeviceExtension->Flags & 0x0000000000000020) &&
            !(OutCapabilities->DeviceD1) &&
            !(OutCapabilities->DeviceD2))
        {
            goto Finish;
        }

        SupportedStates = 0x12;

        if (OutCapabilities->DeviceD1)
            SupportedStates = 0x16;

        if (OutCapabilities->DeviceD2)
            SupportedStates |= 0x08;
    }

    Status = ACPISystemPowerUpdateWakeCapabilities(DeviceExtension, Capabilities, OutCapabilities, deviceState, &DeviceWakeBit, &SystemWakeLevel, &DeviceWakeLevel, &WakeLevel);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPISystemPowerUpdateDeviceCapabilities: %X\n", Status);
        return Status;
    }

    for (SystemState = PowerSystemSleeping1; SystemState <= PowerSystemShutdown; SystemState++)
    {
        if (!(AcpiSupportedSystemStates & (1 << SystemState)))
            continue;

        Status = ACPISystemPowerGetSxD(DeviceExtension, SystemState, &DeviceStateBit);
        if (NT_SUCCESS(Status))
        {
            if (DeviceStateBit > deviceState[SystemState])
                deviceState[SystemState] = DeviceStateBit;

            continue;
        }

        if (Status != STATUS_OBJECT_NAME_NOT_FOUND)
        {
            DPRINT1("ACPISystemPowerUpdateDeviceCapabilities: %X\n", Status);
        }

        CurrentState = deviceState[SystemState];
        IsFound = FALSE;

        Bits = SupportedStates & ~((1 << CurrentState) - 1);

        while (Bits)
        {
            DeviceStateBit = (DEVICE_POWER_STATE)RtlFindLeastSignificantBit((ULONGLONG)Bits);
            Bits &= ~((1 << DeviceStateBit));

            if (SystemState <= SystemWakeLevel)
            {
                if ((DeviceWakeBit & Bits))
                    continue;

                if (DeviceStateBit == WakeLevel)
                {
                    deviceState[SystemState] = DeviceStateBit;
                    IsFound = TRUE;
                }
            }

            if (DeviceStateBit == PowerDeviceD3)
            {
                deviceState[SystemState] = DeviceStateBit;
                IsFound = TRUE;
                break;
            }

            if (!SupportedPrStates)
            {
                deviceState[SystemState] = DeviceStateBit;
                IsFound = TRUE;
                break;
            }

            KeAcquireSpinLock(&AcpiPowerLock, &Irql);

            DPRINT1("ACPISystemPowerUpdateDeviceCapabilities: FIXME\n");
            ASSERT(FALSE);
        }

        if (!IsFound)
        {
            DPRINT1("ACPISystemPowerUpdateDeviceCapabilities: No match found for S%x\n", (SystemState - 1));
            ASSERT(FALSE);
            KeBugCheckEx(0xA5, 0x10, (ULONG_PTR)DeviceExtension, 1, SystemState);
        }
    }

Finish:

    Status = ACPISystemPowerUpdateWakeCapabilities(DeviceExtension, Capabilities, OutCapabilities, deviceState, &DeviceWakeBit, &SystemWakeLevel, &DeviceWakeLevel, &WakeLevel);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPISystemPowerUpdateDeviceCapabilities: %X\n", Status);
        return Status;
    }

    KeAcquireSpinLock(&AcpiPowerLock, &Irql);

    RtlCopyMemory(DeviceExtension->PowerInfo.DevicePowerMatrix, deviceState, sizeof(DeviceExtension->PowerInfo.DevicePowerMatrix));

    DeviceExtension->PowerInfo.DeviceWakeLevel = DeviceWakeLevel;
    DeviceExtension->PowerInfo.SystemWakeLevel = SystemWakeLevel;

    DeviceExtension->PowerInfo.SupportDeviceD1 = ((SupportedStates & 0x04) != 0);
    DeviceExtension->PowerInfo.SupportDeviceD2 = ((SupportedStates & 0x08) != 0);

    DeviceExtension->PowerInfo.SupportWakeFromD0 = ((DeviceWakeBit & 0x02) != 0);
    DeviceExtension->PowerInfo.SupportWakeFromD1 = ((DeviceWakeBit & 0x04) != 0);
    DeviceExtension->PowerInfo.SupportWakeFromD2 = ((DeviceWakeBit & 0x08) != 0);
    DeviceExtension->PowerInfo.SupportWakeFromD3 = ((DeviceWakeBit & 0x10) != 0);

    KeReleaseSpinLock(&AcpiPowerLock, Irql);

    if (!(DeviceExtension->Flags & 0x0008000000000000))
        ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0100000000000000, FALSE);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPISystemPowerQueryDeviceCapabilities(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PDEVICE_CAPABILITIES Capabilities)
{
    DEVICE_CAPABILITIES capabilities;
    NTSTATUS Status;

    PAGED_CODE();

    if (!(DeviceExtension->Flags & 0x0400000000000000))
    {
        if ((DeviceExtension->Flags & 0x0000000000000040) &&
            !(DeviceExtension->Flags & 0x0000000000000020))
        {
            Status = ACPISystemPowerUpdateDeviceCapabilities(DeviceExtension, Capabilities, Capabilities);
        }
        else
        {
            Status = ACPIInternalGetDeviceCapabilities(DeviceExtension->ParentExtension->DeviceObject, &capabilities);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("ACPISystemPowerQueryDeviceCapabilities: Could not get parent caps (%X)\n", Status);
                return Status;
            }

            Status = ACPISystemPowerUpdateDeviceCapabilities(DeviceExtension, &capabilities, Capabilities);
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPISystemPowerQueryDeviceCapabilities: Could not update caps (%X)\n", Status);

            if ((DeviceExtension->Flags & 0x0000000000000020))
            {
                DPRINT1("ACPISystemPowerQueryDeviceCapabilities: FIXME\n");
                ASSERT(FALSE);
            }

            return Status;
        }

        ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0400000000000000, FALSE);
    }

    RtlCopyMemory(Capabilities->DeviceState, DeviceExtension->PowerInfo.DevicePowerMatrix, (7 * sizeof(DEVICE_POWER_STATE)));

    Capabilities->DeviceD1 = DeviceExtension->PowerInfo.SupportDeviceD1;
    Capabilities->DeviceD2 = DeviceExtension->PowerInfo.SupportDeviceD2;

    Capabilities->WakeFromD0 = DeviceExtension->PowerInfo.SupportWakeFromD0;
    Capabilities->WakeFromD1 = DeviceExtension->PowerInfo.SupportWakeFromD1;
    Capabilities->WakeFromD2 = DeviceExtension->PowerInfo.SupportWakeFromD2;
    Capabilities->WakeFromD3 = DeviceExtension->PowerInfo.SupportWakeFromD3;

    Capabilities->SystemWake = DeviceExtension->PowerInfo.SystemWakeLevel;
    Capabilities->DeviceWake = DeviceExtension->PowerInfo.DeviceWakeLevel;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIBusAndFilterIrpQueryCapabilities(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ ULONG Param3,
    _In_ BOOLEAN Param4)
{
    PDEVICE_CAPABILITIES Capabilities;
    PDEVICE_EXTENSION DeviceExtension;
    PIO_STACK_LOCATION IoStack;
    PAMLI_NAME_SPACE_OBJECT NsObject;
    PAMLI_NAME_SPACE_OBJECT ChildNsObject;
    ULONG DataBuff1;
    ULONG DataBuff2;
    ULONG UINumber;
    UCHAR MinorFunction;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ACPIBusAndFilterIrpQueryCapabilities: %p, %p, %X, %X\n", DeviceObject, Irp, Param3, Param4);

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = IoStack->MinorFunction;
    Capabilities = IoStack->Parameters.DeviceCapabilities.Capabilities;

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    NsObject = DeviceExtension->AcpiObject;

    if (!(DeviceExtension->Flags & 0x0000008000000000))
    {
        ChildNsObject = ACPIAmliGetNamedChild(NsObject, 'VMR_');
        if (ChildNsObject)
        {
            if (ChildNsObject->ObjData.DataType == 8)
            {
                Status = ACPIGet(DeviceExtension, 'VMR_', 0x20044002, NULL, 0, NULL, NULL, (PVOID *)&DataBuff1, NULL);

                if (!NT_SUCCESS(Status) || DataBuff1)
                {
                    Capabilities->Removable = 1;
                }
                else
                {
                    Capabilities->Removable = 0;
                }
            }
            else
            {
                Capabilities->Removable = 1;
            }
        }

        if (!ACPIDockIsDockDevice(NsObject))
        {
            if (ACPIAmliGetNamedChild(NsObject, '0JE_'))
            {
                Capabilities->EjectSupported = 1;
                Capabilities->Removable = 1;
            }

            if (ACPIAmliGetNamedChild(NsObject, '1JE_') ||
                ACPIAmliGetNamedChild(NsObject, '2JE_') ||
                ACPIAmliGetNamedChild(NsObject, '3JE_') ||
                ACPIAmliGetNamedChild(NsObject, '4JE_'))
            {
                Capabilities->WarmEjectSupported = 1;
                Capabilities->Removable = 1;
            }
        }
    }

    if (ACPIAmliGetNamedChild(NsObject, 'CRI_'))
        DeviceObject->Flags |= DO_POWER_INRUSH;

    Status = ACPIGet(DeviceExtension, 'ATS_', 0x20040802, NULL, 0, NULL, NULL, (PVOID *)&DataBuff2, NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIBusAndFilterIrpQueryCapabilities: Status %X\n", Status);
        goto Exit;
    }

    if (!(DeviceExtension->Flags & 0x0040000000000000))
    {
        if (ACPIAmliGetNamedChild(NsObject, 'SRC_') && !ACPIAmliGetNamedChild(NsObject, 'SRS_'))
            Capabilities->HardwareDisabled = 1;
        else if (Param4)
            Capabilities->HardwareDisabled = 0;

    }
    else if (!Param4)
    {
        if (AcpiOverrideAttributes & 2)
            Capabilities->HardwareDisabled = 1;
        else
            Capabilities->HardwareDisabled = 0;
    }

    if (!(DataBuff2 & 4))
        Capabilities->NoDisplayInUI = 1;

    if (ACPIAmliGetNamedChild(NsObject, 'NUS_'))
    {
        Status = ACPIGet(DeviceExtension, 'NUS_', 0x20040002, NULL, 0, NULL, NULL, (PVOID *)&UINumber, NULL);
        if (NT_SUCCESS(Status))
            Capabilities->UINumber = UINumber;
    }

    if (ACPIAmliGetNamedChild(NsObject, 'RDA_'))
    {
        Status = ACPIGet(DeviceExtension, 'RDA_', 0x20040402, NULL, 0, NULL, NULL, (PVOID *)&Capabilities->Address, NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIBusAndFilterIrpQueryCapabilities: Could query device address %X\n", Status);
            goto Exit;
        }
    }

    Status = ACPISystemPowerQueryDeviceCapabilities(DeviceExtension, Capabilities);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIBusAndFilterIrpQueryCapabilities: Could query device Capabilities %X\n", Status);
        goto Exit;
    }

    if (!Param4)
    {
        Capabilities->SilentInstall = 1;

        if (DeviceExtension->Flags & 0x0000000000020000)
            Capabilities->RawDeviceOK =  1;
        else
            Capabilities->RawDeviceOK = 0;

        if (DeviceExtension->InstanceID)
            Capabilities->UniqueID = 1;
        else
            Capabilities->UniqueID = 0;

        Status = STATUS_SUCCESS;
    }

Exit:

    DPRINT("ACPIBusAndFilterIrpQueryCapabilities: %X, %X, %X\n", Irp, MinorFunction, Status);

    return Status;
}

NTSTATUS
NTAPI
ACPIIrpInvokeDispatchRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ ULONG Param3,
    _In_ PVOID Callback,
    _In_ BOOLEAN Param5,
    _In_ BOOLEAN Param6)
{
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ACPIIrpInvokeDispatchRoutine: %p, %p, %X, %X, %X\n", DeviceObject, Irp, Param3, Param5, Param6);

    Status = STATUS_NOT_SUPPORTED;

    if (NT_SUCCESS(Irp->IoStatus.Status))
    {
        if (Param5)
            Status = ((NTSTATUS (NTAPI *)(PDEVICE_OBJECT, PIRP, ULONG, BOOLEAN))Callback)(DeviceObject, Irp, Param3, FALSE);
    }
    else if (Irp->IoStatus.Status == STATUS_NOT_SUPPORTED)
    {
        if (Param6)
            Status = ((NTSTATUS (NTAPI *)(PDEVICE_OBJECT, PIRP, ULONG, BOOLEAN))Callback)(DeviceObject, Irp, Param3, FALSE);
    }

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    if (DeviceExtension->Flags & 0x0000000000000020)
    {
        if (Status != STATUS_PENDING)
        {
            if (Status != STATUS_NOT_SUPPORTED)
                Irp->IoStatus.Status = Status;
            else
                Status = Irp->IoStatus.Status;

            IoCompleteRequest(Irp, IO_NO_INCREMENT);
        }
    }
    else if (Status != STATUS_PENDING)
    {
        if (Status != STATUS_NOT_SUPPORTED)
            Irp->IoStatus.Status = Status;

        if (NT_SUCCESS(Status) || (Status == STATUS_NOT_SUPPORTED))
            Status = IoCallDriver(DeviceExtension->TargetDeviceObject, Irp);
        else
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return Status;
}

NTSTATUS
NTAPI
ACPIBusIrpQueryCapabilities(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PAGED_CODE();
    return ACPIIrpInvokeDispatchRoutine(DeviceObject, Irp, 0, ACPIBusAndFilterIrpQueryCapabilities, TRUE, TRUE);
}

NTSTATUS
NTAPI
ACPIInitDosDeviceName(
    _In_ PDEVICE_EXTENSION DeviceExtension)
{
    PAMLI_NAME_SPACE_OBJECT Child;
    AMLI_OBJECT_DATA DataResult;
    UNICODE_STRING NameString;
    ANSI_STRING AnsiString;
    HANDLE DevInstRegKey;
    ULONG Data = 1;
    NTSTATUS Status;

    DPRINT("ACPIInitDosDeviceName: %p\n", DeviceExtension);

    RtlInitUnicodeString(&NameString, L"FirmwareIdentified");

    Status = IoOpenDeviceRegistryKey(DeviceExtension->PhysicalDeviceObject, 1, 0x00020000, &DevInstRegKey);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIInitDosDeviceName: Status %X\n", Status);
        return STATUS_SUCCESS;
    }

    Status = ZwSetValueKey(DevInstRegKey, &NameString, 0, REG_DWORD, &Data, sizeof(Data));
    RtlInitUnicodeString(&NameString, L"DosDeviceName");

    Child = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, 'NDD_');
    if (!Child)
    {
        ZwClose(DevInstRegKey);
        return STATUS_SUCCESS;
    }

    Status = AMLIEvalNameSpaceObject(Child, &DataResult, 0, NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIInitDosDeviceName: Status %X\n", Status);
        ZwClose(DevInstRegKey);
        return STATUS_SUCCESS;
    }

    if (DataResult.DataType != 2)
    {
        DPRINT1("ACPIInitDosDeviceName: eval returns wrong type %X\n", DataResult.DataType);
        AMLIFreeDataBuffs(&DataResult, 1);
        ZwClose(DevInstRegKey);
        return STATUS_SUCCESS;
    }

    RtlInitAnsiString(&AnsiString, DataResult.DataBuff);

    Status = RtlAnsiStringToUnicodeString(&NameString, &AnsiString, TRUE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIInitDosDeviceName: Status %X\n", Status);
        AMLIFreeDataBuffs(&DataResult, 1);
        ZwClose(DevInstRegKey);
        return Status;
    }

    Status = ZwSetValueKey(DevInstRegKey, &NameString, 0, REG_SZ, NameString.Buffer, NameString.Length);

    AMLIFreeDataBuffs(&DataResult, 1);
    ZwClose(DevInstRegKey);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIInitDosDeviceName: Status %X\n", Status);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PnpIoResourceListToCmResourceList(
    _In_ PIO_RESOURCE_REQUIREMENTS_LIST IoResource,
    _Out_ PCM_RESOURCE_LIST* OutCmResource)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PCM_RESOURCE_LIST CmResource;
    PIO_RESOURCE_DESCRIPTOR IoDescriptor;
    PIO_RESOURCE_LIST IoList;
    ULONG Size;
    ULONG ix;

    DPRINT("PnpIoResourceListToCmResourceList: %p\n", IoResource);
    PAGED_CODE();

    *OutCmResource = NULL;

    if (!IoResource)
    {
        DPRINT1("PnpIoResourceListToCmResourceList: STATUS_INVALID_DEVICE_REQUEST\n");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (!IoResource->List)
    {
        DPRINT1("PnpIoResourceListToCmResourceList: STATUS_INVALID_DEVICE_REQUEST\n");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (!IoResource->List[0].Count)
    {
        DPRINT1("PnpIoResourceListToCmResourceList: STATUS_INVALID_DEVICE_REQUEST\n");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    Size = (sizeof(CM_RESOURCE_LIST) + (IoResource->List[0].Count - 1) * sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));

    CmResource = ExAllocatePoolWithTag(PagedPool, Size, 'RpcA');
    if (!CmResource)
    {
        DPRINT1("PnpIoResourceListToCmResourceList: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(CmResource, Size);

    IoList = IoResource->List;

    CmResource->Count = 1;
    CmResource->List[0].InterfaceType = IoResource->InterfaceType;
    CmResource->List[0].BusNumber = IoResource->BusNumber;

    CmResource->List[0].PartialResourceList.Version = 1;
    CmResource->List[0].PartialResourceList.Revision = 1;
    CmResource->List[0].PartialResourceList.Count = IoList->Count;

    for (ix = 0; ix < IoList->Count; ix++)
    {
        IoDescriptor = &IoList->Descriptors[ix];
        CmDescriptor = &CmResource->List[0].PartialResourceList.PartialDescriptors[ix];

        CmDescriptor->Type = IoDescriptor->Type;
        CmDescriptor->ShareDisposition = IoDescriptor->ShareDisposition;
        CmDescriptor->Flags = IoDescriptor->Flags;

        switch (CmDescriptor->Type)
        {
            case CmResourceTypePort:
                CmDescriptor->u.Port.Start = IoDescriptor->u.Port.MinimumAddress;
                CmDescriptor->u.Port.Length = IoDescriptor->u.Port.Length;
                break;

            case CmResourceTypeInterrupt:
                CmDescriptor->u.Interrupt.Level = IoDescriptor->u.Interrupt.MinimumVector;
                CmDescriptor->u.Interrupt.Vector = IoDescriptor->u.Interrupt.MinimumVector;
                CmDescriptor->u.Interrupt.Affinity = 0xFFFFFFFF;
                break;

            case CmResourceTypeMemory:
                CmDescriptor->u.Memory.Start = IoDescriptor->u.Memory.MinimumAddress;
                CmDescriptor->u.Memory.Length = IoDescriptor->u.Memory.Length;
                break;

            case CmResourceTypeDma:
                CmDescriptor->u.Dma.Channel = IoDescriptor->u.Dma.MinimumChannel;
                CmDescriptor->u.Dma.Port = 0;
                break;

            case CmResourceTypeBusNumber:
                CmDescriptor->u.BusNumber.Start = IoDescriptor->u.BusNumber.MinBusNumber;
                CmDescriptor->u.BusNumber.Length = IoDescriptor->u.BusNumber.Length;
                break;

            default:
                CmDescriptor->u.DevicePrivate.Data[0] = IoDescriptor->u.DevicePrivate.Data[0];
                CmDescriptor->u.DevicePrivate.Data[1] = IoDescriptor->u.DevicePrivate.Data[1];
                CmDescriptor->u.DevicePrivate.Data[2] = IoDescriptor->u.DevicePrivate.Data[2];
                break;
        }
    }

    *OutCmResource = CmResource;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIRangeFilterPICInterrupt(
    _In_ PIO_RESOURCE_REQUIREMENTS_LIST IoResource)
{
    PIO_RESOURCE_LIST IoList;
    ULONG ix;
    ULONG jx;

    DPRINT("ACPIRangeFilterPICInterrupt: %p\n", IoResource);

    if (!IoResource)
        return STATUS_SUCCESS;

    IoList = IoResource->List;

    for (ix = 0; ix < IoResource->AlternativeLists; ix++)
    {
        for (jx = 0; jx < IoList->Count; jx++)
        {
            if (IoList->Descriptors[jx].Type == CmResourceTypeInterrupt)
            {
                if (IoList->Descriptors[jx].u.Interrupt.MinimumVector == 2)
                {
                    if (IoList->Descriptors[jx].u.Interrupt.MaximumVector == 2)
                        IoList->Descriptors[jx].Type = CmResourceTypeNull;
                    else
                        IoList->Descriptors[jx].u.Interrupt.MinimumVector++;
                }
                else if (IoList->Descriptors[jx].u.Interrupt.MaximumVector == 2)
                {
                    IoList->Descriptors[jx].u.Interrupt.MaximumVector--;
                }
                else if (IoList->Descriptors[jx].u.Interrupt.MinimumVector < 2 &&
                         IoList->Descriptors[jx].u.Interrupt.MaximumVector > 2)
                {
                    IoList->Descriptors[jx].u.Interrupt.MinimumVector = 3;
                }
            }
        }

        IoList = Add2Ptr(IoList, (FIELD_OFFSET(IO_RESOURCE_LIST, Descriptors) + IoList->Count * sizeof(IO_RESOURCE_DESCRIPTOR)));
    }

    return STATUS_SUCCESS;
}

VOID
NTAPI
ACPIRangeValidatePciMemoryResource(
    _In_ PIO_RESOURCE_LIST IoList,
    _In_ ULONG Idx,
    _In_ PACPI_BIOS_MULTI_NODE Node,
    _Out_ ULONG* OutErrors)
{
    PACPI_E820_ENTRY Entry;
    ULONGLONG Min;
    ULONGLONG Max;
    ULONG Alignment;
    ULONG ix;

    ASSERT(IoList != NULL);

    if (!Node)
    {
        DPRINT1("ACPIRangeValidatePciMemoryResource: Node is NULL\n");
        return;
    }

    Min = IoList->Descriptors[Idx].u.Memory.MinimumAddress.QuadPart;
    Max = IoList->Descriptors[Idx].u.Memory.MaximumAddress.QuadPart;
    Alignment = IoList->Descriptors[Idx].u.Memory.Alignment;

    for (ix = 0; ix < Node->Count; ix++)
    {
        Entry = &Node->E820Entry[ix];

        if (Entry->Type == 2)
            continue;

        if (Entry->Type == 4 || Entry->Type == 3)
        {
            ASSERT(Entry->Length.HighPart == 0);

            if (Entry->Length.HighPart)
            {
                DPRINT1("ACPI: E820 Entry [%X] (type %X) Length = %I64X > 32bit\n", ix, Entry->Type, Entry->Length.QuadPart);
                Entry->Length.HighPart = 0;
            }
        }

        if (Max < (ULONGLONG)Entry->Base.QuadPart)
            continue;

        if (Min >= (ULONGLONG)(Entry->Base.QuadPart + Entry->Length.QuadPart))
            continue;

        DPRINT1("ACPI: E820 Entry %X (Type %I64X) (%I64X-%I64X) overlaps\n"
                "ACPI: PCI Entry [%X] %I64X:%I64X:%X:%X\n",
                ix, Entry->Type, Entry->Base.QuadPart, (Entry->Base.QuadPart + Entry->Length.QuadPart),
                Idx,
                IoList->Descriptors[Idx].u.Memory.MinimumAddress.QuadPart,
                IoList->Descriptors[Idx].u.Memory.MaximumAddress.QuadPart,
                IoList->Descriptors[Idx].u.Memory.Length, Alignment);

        if (!(AcpiOverrideAttributes & 1))
        {
            ++*OutErrors;
            DPRINT1("ACPIRangeValidatePciMemoryResource: *OutErrors %X\n", *OutErrors);
            continue;
        }

        if (Entry->Type != 4)
        {
            ++*OutErrors;
            DPRINT1("ACPIRangeValidatePciMemoryResource: *OutErrors %X\n", *OutErrors);
            continue;
        }

        if (Max < (ULONGLONG)Entry->Base.QuadPart || Min >= (ULONGLONG)Entry->Base.QuadPart)
        {
            DPRINT1("ACPI: E820 Entry [%X] Overrides PCI Entry\n", ix);
            continue;
        }

        IoList->Descriptors[Idx].u.Memory.MaximumAddress.QuadPart = ((ULONGLONG)Entry->Base.QuadPart - 1);

        IoList->Descriptors[Idx].u.Memory.Length = (IoList->Descriptors[Idx].u.Memory.MaximumAddress.QuadPart -
                                                    IoList->Descriptors[Idx].u.Memory.MinimumAddress.QuadPart + 1);

        DPRINT1("ACPI: PCI Entry [%X] Changed to\nACPI: PCI Entry [%X] %I64X:%I64X:%X:%X\n",
                Idx, Idx,
                IoList->Descriptors[Idx].u.Memory.MinimumAddress.QuadPart,
                IoList->Descriptors[Idx].u.Memory.MaximumAddress.QuadPart,
                IoList->Descriptors[Idx].u.Memory.Length, Alignment);

        DPRINT1("ACPI: E820 Entry [%X] Overrides PCI Entry\n", ix);
    }
}

VOID
NTAPI
ACPIRangeValidatePciResources(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PIO_RESOURCE_REQUIREMENTS_LIST IoResource)
{
    PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 KeyInfo;
    PACPI_BIOS_MULTI_NODE AcpiMultiNode;
    PIO_RESOURCE_DESCRIPTOR Descriptor;
    PIO_RESOURCE_LIST IoList;
    ULONGLONG Length;
    ULONG Errors = 0;
    ULONG ix;
    ULONG jx;
    NTSTATUS Status;
    struct
    {
        CM_FULL_RESOURCE_DESCRIPTOR Descriptor;
        ACPI_BIOS_MULTI_NODE Node;
    } *Package;

    if (!IoResource)
    {
        DPRINT1("ACPIRangeValidatePciResources: No IoResList\n");
        KeBugCheckEx(0xA5, 2, (ULONG_PTR)DeviceExtension, 2, 0);
    }

    Status = OSReadAcpiConfigurationData(&KeyInfo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIRangeValidatePciResources: Cannot get Information %X\n", Status);
        return;
    }

    Package = (PVOID)KeyInfo->Data;
    AcpiMultiNode = &Package->Node;

    IoList = &IoResource->List[0];

    for (ix = 0; ix < IoResource->AlternativeLists; ix++)
    {
        DPRINT("ACPIRangeValidatePciResources: %p, %X\n", IoList, IoList->Count);

        for (jx = 0; jx < IoList->Count; jx++)
        {
            Descriptor = &IoList->Descriptors[jx];

            if (Descriptor->Type == CmResourceTypePort || Descriptor->Type == CmResourceTypeMemory)
            {
                Length = (Descriptor->u.Generic.MaximumAddress.QuadPart - Descriptor->u.Generic.MinimumAddress.QuadPart + 1);

                if (Length > MAXULONG)
                {
                    DPRINT1("ACPI: Invalid IO/Mem Length > MAXULONG)\nACPI: PCI Entry [%X] %I64X:%I64X:%X:%X\n",
                            jx,
                            Descriptor->u.Generic.MinimumAddress.QuadPart,
                            Descriptor->u.Generic.MaximumAddress.QuadPart,
                            Length,
                            Descriptor->u.Generic.Alignment);
                    Errors++;                    
                }

                if (Length != Descriptor->u.Generic.Length)
                {
                    DPRINT1("ACPI: Invalid IO/Mem Length - (Max - Min + 1) != Length)\nACPI: PCI Entry [%X] %I64X:%I64X:%X:%X\n",
                            jx,
                            Descriptor->u.Generic.MinimumAddress.QuadPart,
                            Descriptor->u.Generic.MaximumAddress.QuadPart,
                            Descriptor->u.Generic.Length,
                            Descriptor->u.Generic.Alignment);
                    Errors++;                    
                }

                if (!Descriptor->u.Generic.Alignment)
                {
                    DPRINT1("ACPI: Invalid IO/Mem Alignment\nACPI: PCI Entry [%X] %I64X:%I64X:%X:%X\n",
                            jx,
                            Descriptor->u.Generic.MinimumAddress.QuadPart,
                            Descriptor->u.Generic.MaximumAddress.QuadPart,
                            Descriptor->u.Generic.Length,
                            Descriptor->u.Generic.Alignment);
                    Errors++;
                }

                if (Descriptor->u.Generic.MinimumAddress.LowPart & (Descriptor->u.Generic.Alignment - 1))
                {
                    DPRINT1("ACPI: Invalid IO/Mem Alignment - (Min & (Align - 1)\nACPI: PCI Entry [%X] %I64X:%I64X:%X:%X\n",
                            jx,
                            Descriptor->u.Generic.MinimumAddress.QuadPart,
                            Descriptor->u.Generic.MaximumAddress.QuadPart,
                            Descriptor->u.Generic.Length,
                            Descriptor->u.Generic.Alignment);
                    Errors++;
                }
            }

            if (Descriptor->Type == CmResourceTypeBusNumber)
            {
                Length = (Descriptor->u.BusNumber.MaxBusNumber - Descriptor->u.BusNumber.MinBusNumber + 1);

                if (Length != Descriptor->u.BusNumber.Length)
                {
                    DPRINT1("ACPI: Invalid BusNumber Length - (Max - Min + 1) != Length)\nACPI: PCI Entry [%X] %X:%X:%X\n",
                            jx,
                            Descriptor->u.BusNumber.MinBusNumber,
                            Descriptor->u.BusNumber.MaxBusNumber,
                            Descriptor->u.BusNumber.Length);
                    Errors++;
                }
            }

            if (Descriptor->Type == CmResourceTypeMemory)
                ACPIRangeValidatePciMemoryResource(IoList, jx, AcpiMultiNode, &Errors);
        }


        IoList = (PIO_RESOURCE_LIST)(IoList->Descriptors + IoList->Count);
    }

    if (Errors)
    {
        DPRINT1("ACPIRangeValidatePciResources: FATAL BIOS ERROR - Need new BIOS to fix PCI problems\nThis machine will not boot after 8/26/98!!!!\n");
        KeBugCheckEx(0xA5, 2, (ULONG_PTR)DeviceExtension, (ULONG_PTR)IoResource, (ULONG_PTR)AcpiMultiNode);
    }

    ExFreePool(KeyInfo);
}

NTSTATUS
NTAPI
ACPIBusIrpQueryResources(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_RESOURCE_REQUIREMENTS_LIST IoResource = NULL;
    PCM_RESOURCE_LIST CmResource = NULL;
    PDEVICE_EXTENSION DeviceExtension;
    PVOID DataBuff;
    ULONG DataLen;
    NTSTATUS Status;

    DPRINT("ACPIBusIrpQueryResources: %p, %p\n", DeviceObject, Irp);
    PAGED_CODE();

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    ACPIInitDosDeviceName(DeviceExtension);

    Status = ACPIGet(DeviceExtension, 'ATS_', 0x20040802, NULL, 0, NULL, NULL, &DataBuff, NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIBusIrpQueryResources: Status %X\n", Status);
        goto Finish;
    }

    if (!(DeviceExtension->Flags & 0x0040000000000000))
    {
        DPRINT1("ACPIBusIrpQueryResources: STATUS_INVALID_DEVICE_STATE (Device not Enabled)\n");
        Status = STATUS_INVALID_DEVICE_STATE;
        goto Finish;
    }

    if (DeviceExtension->Flags & 0x0000002000000000)
    {
        DPRINT1("ACPIBusIrpQueryResources: STATUS_OBJECT_NAME_NOT_FOUND\n");
        Status = STATUS_OBJECT_NAME_NOT_FOUND;
    }
    else
    {
        DataBuff = NULL;
        Status = ACPIGet(DeviceExtension, 'SRC_', 0x20010008, NULL, 0, NULL, NULL, &DataBuff, &DataLen);
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT("ACPIBusIrpQueryResources: Status %X\n", Status);

        if (! (DeviceExtension->Flags & 0x0000000002000000))
            Status = Irp->IoStatus.Status;

        goto Finish;
    }

    Status = PnpDeviceBiosResourcesToNtResources(DeviceExtension, DataBuff, ((DeviceExtension->Flags & 0x0000000002000000) != 0), &IoResource);

    ExFreePool(DataBuff);

    if (!IoResource)
    {
        if (DeviceExtension->Flags & 0x0000000002000000)
            Status = STATUS_UNSUCCESSFUL;

        goto Finish;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIBusIrpQueryResources: Status %X\n", Status);
        goto Finish;
    }

    if (DeviceExtension->Flags & 0x0000000002000000)
    {
        Status = ACPIRangeSubtract(&IoResource, RootDeviceExtension->ResourceList);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIBusIrpQueryResources: Status %X\n", Status);
            ExFreePool(IoResource);
            goto Finish;
        }

        ACPIRangeValidatePciResources(DeviceExtension, IoResource);
    }
    else if (DeviceExtension->Flags & 0x0000000200000000)
    {
        Status = ACPIRangeFilterPICInterrupt(IoResource);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIBusIrpQueryResources: Status %X\n", Status);
            ExFreePool(IoResource);
            goto Finish;
        }
    }

    if (NT_SUCCESS(Status))
    {
        Status = PnpIoResourceListToCmResourceList(IoResource, &CmResource);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIBusIrpQueryResources: Status %X\n", Status);
            ExFreePool(IoResource);
            goto Finish;
        }
    }

    ExFreePool(IoResource);

Finish:

    if (!NT_SUCCESS(Status) && Status != STATUS_INSUFFICIENT_RESOURCES)
    {
        DPRINT("ACPIBusIrpQueryResources: Status %X\n", Status);

        if (DeviceExtension->Flags & 0x0000000002000000)
        {
            DPRINT1("ACPIBusIrpQueryResources: KeBugCheckEx()!!!n");
            ASSERT(FALSE);
            KeBugCheckEx(0xA5, 2, (ULONG_PTR)DeviceExtension, 0, (ULONG_PTR)Irp);
        }
    }

    Irp->IoStatus.Status = Status;
    if (NT_SUCCESS(Status))
        Irp->IoStatus.Information = (ULONG_PTR)CmResource;
    else
        Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, 0);

    DPRINT("ACPIBusIrpQueryResources: ret Status %X\n", Status);

    return Status;
}

NTSTATUS
NTAPI
ACPIInternalGrowBuffer(
    _Inout_ PVOID* OutIoResource,
    _In_ ULONG CopySize,
    _In_ ULONG AllocateSize)
{
    PIO_RESOURCE_LIST IoResource;

    DPRINT("ACPIInternalGrowBuffer: %X, %X\n", CopySize, AllocateSize);

    PAGED_CODE();
    ASSERT(OutIoResource != NULL);

    IoResource = ExAllocatePoolWithTag(PagedPool, AllocateSize, 'RpcA');
    if (!IoResource)
    {
        if (*OutIoResource)
        {
            ExFreePool(*OutIoResource);
            *OutIoResource = NULL;
        }

        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(IoResource, AllocateSize);

    if (*OutIoResource)
    {
        RtlCopyMemory(IoResource, *OutIoResource, CopySize);
        ExFreePool(*OutIoResource);
    }

    *OutIoResource = IoResource;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PnpiGrowResourceList(
    _Out_ PIO_RESOURCE_LIST** OutResourceListArray,
    _Out_ ULONG* OutResourceListArraySize)
{
    ULONG ResourceListArraySize;
    ULONG Count;
    SIZE_T Size;
    NTSTATUS Status;

    DPRINT("PnpiGrowResourceList: %X\n", *OutResourceListArray);

    PAGED_CODE();
    ASSERT(OutResourceListArray != NULL);

    if (!(*OutResourceListArray) || !(*OutResourceListArraySize))
    {
        DPRINT("PnpiGrowResourceList: %X -> %X, (%X)\n", 0, 8, sizeof(IO_RESOURCE_DESCRIPTOR));

        *OutResourceListArray = ExAllocatePoolWithTag(PagedPool, sizeof(IO_RESOURCE_DESCRIPTOR), 'RpcA');
        if (!(*OutResourceListArray))
        {
            DPRINT1("PnpiGrowResourceList: STATUS_INSUFFICIENT_RESOURCES\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(*OutResourceListArray, sizeof(IO_RESOURCE_DESCRIPTOR));

        *OutResourceListArraySize = 8;

        return STATUS_SUCCESS;
    }

    Count = *OutResourceListArraySize;

    Size = (sizeof(IO_RESOURCE_DESCRIPTOR) + (Count * sizeof(PIO_RESOURCE_LIST)));
    ResourceListArraySize = (Count + 8);

    DPRINT("PnpiGrowResourceList: %X -> %X, (%X)\n", Count, (Count + 8), Size);

    Status = ACPIInternalGrowBuffer((PVOID *)OutResourceListArray, (Count * sizeof(PIO_RESOURCE_LIST)), Size);

    if (NT_SUCCESS(Status))
        *OutResourceListArraySize = ResourceListArraySize;
    else
        *OutResourceListArraySize = 0;

    return Status;
}

NTSTATUS
NTAPI
PnpiGrowResourceDescriptor(
    _Inout_ PIO_RESOURCE_LIST* OutIoResource)
{
    PIO_RESOURCE_LIST IoResource;
    ULONG Count;
    ULONG Size;

    DPRINT("PnpiGrowResourceDescriptor: *OutIoResource %X\n", *OutIoResource);

    PAGED_CODE();
    ASSERT(OutIoResource != NULL);

    // FIXME sizeof ..

    IoResource = *OutIoResource;
    if (*OutIoResource)
    {
        Count = IoResource->Count;
        Size = (sizeof(IO_RESOURCE_LIST) + sizeof(IO_RESOURCE_DESCRIPTOR) * (Count - 1));

        DPRINT("PnpiGrowResourceDescriptor: %X -> %X, Size %X\n", Count, (Count + 8), (0x128 + sizeof(IO_RESOURCE_DESCRIPTOR) * (Count - 1)));

        return ACPIInternalGrowBuffer((PVOID *)OutIoResource, Size, (Size + 0x100));
    }

    DPRINT("PnpiGrowResourceDescriptor: %X -> %X, Size %X\n", 0, 8, 0x108);

    *OutIoResource = IoResource = ExAllocatePoolWithTag(PagedPool, 0x108, 'RpcA');
    if (!IoResource)
    {
        DPRINT1("PnpiGrowResourceDescriptor: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(IoResource, 0x108);

    IoResource->Version = 1;
    IoResource->Revision = 1;
    IoResource->Count = 0;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PnpiUpdateResourceList(
    _Inout_ PIO_RESOURCE_LIST* OutIoResource,
    _Out_ PIO_RESOURCE_DESCRIPTOR* OutIoDescriptors)
{
    PIO_RESOURCE_LIST IoResource;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("PnpiUpdateResourceList: %p\n", OutIoResource);

    PAGED_CODE();
    ASSERT(OutIoResource != NULL);

    IoResource = *OutIoResource;

    if (!IoResource || !(IoResource->Count & 7))
    {
        Status = PnpiGrowResourceDescriptor(OutIoResource);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PnpiUpdateResourceList: Status %X\n", Status);
            return Status;
        }
    }

    *OutIoDescriptors = &((*OutIoResource)->Descriptors[(*OutIoResource)->Count]);
    (*OutIoResource)->Count++;

    return Status;
}

VOID
NTAPI
PnpiBiosAddressHandlePortFlags(
    _In_ PVOID Data,
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    PACPI_WORD_ADDRESS_SPACE_DESCRIPTOR AcpiDesc = Data;

    PAGED_CODE();

    if (!(AcpiDesc->GeneralFlags & 2))
        IoDescriptor->Flags |= 0x20;
}

VOID
NTAPI
PnpiBiosAddressHandleBusFlags(
    _In_ PVOID Data,
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    PAGED_CODE();
    ASSERT(IoDescriptor->u.BusNumber.Length > 0);
}

NTSTATUS
NTAPI
PnpiBiosAddressHandleGlobalFlags(
    _In_ PVOID Data,
    _In_ PIO_RESOURCE_LIST* ResourceListArray,
    _In_ ULONG Index,
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    PACPI_WORD_ADDRESS_SPACE_DESCRIPTOR AcpiDesc = Data;
    NTSTATUS Status;

    DPRINT("PnpiBiosAddressHandleGlobalFlags: %p, %X\n", AcpiDesc, AcpiDesc->GeneralFlags);
    PAGED_CODE();

    if ((AcpiOverrideAttributes & 0x800) || (AcpiDesc->GeneralFlags & 1))
        IoDescriptor->ShareDisposition = 1;
    else
        IoDescriptor->ShareDisposition = 3;

    if ((AcpiDesc->GeneralFlags & 4) && (AcpiDesc->GeneralFlags & 8))
    {
        if (IoDescriptor->Type == CmResourceTypeBusNumber)
            IoDescriptor->u.BusNumber.Length = (IoDescriptor->u.BusNumber.MaxBusNumber - IoDescriptor->u.BusNumber.MinBusNumber + 1);
        else
            IoDescriptor->u.Memory.Length = (IoDescriptor->u.Memory.MaximumAddress.LowPart - IoDescriptor->u.Memory.MinimumAddress.LowPart + 1);

        goto Finish;
    }

    if (AcpiDesc->GeneralFlags & 8)
    {
        if (IoDescriptor->Type == CmResourceTypeBusNumber)
            IoDescriptor->u.BusNumber.MinBusNumber = (IoDescriptor->u.BusNumber.MaxBusNumber - IoDescriptor->u.BusNumber.Length + 1);
        else
            IoDescriptor->u.Memory.MinimumAddress.LowPart = (IoDescriptor->u.Memory.MaximumAddress.LowPart - IoDescriptor->u.Memory.Length + 1);

        goto Finish;
    }

    if (AcpiDesc->GeneralFlags & 4)
    {
        if (IoDescriptor->Type == CmResourceTypeBusNumber)
            IoDescriptor->u.BusNumber.MaxBusNumber = (IoDescriptor->u.BusNumber.MinBusNumber + IoDescriptor->u.BusNumber.Length - 1);
        else
            IoDescriptor->u.Memory.MaximumAddress.LowPart = (IoDescriptor->u.Memory.MinimumAddress.LowPart - IoDescriptor->u.Memory.Length - 1);
    }

Finish:

    if (AcpiDesc->GeneralFlags & 1)
        return STATUS_SUCCESS;

    Status = PnpiUpdateResourceList(&ResourceListArray[Index], &IoDescriptor);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PnpiBiosAddressHandleGlobalFlags: Status %X\n", Status);
        return Status;
    }
    RtlZeroMemory(IoDescriptor, sizeof(IO_RESOURCE_DESCRIPTOR));

    IoDescriptor->Type = 0x81;
    IoDescriptor->Flags = 1;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PnpiBiosAddressToIoDescriptor(
    _In_ PVOID Data,
    _In_ PIO_RESOURCE_LIST* ResourceListArray,
    _In_ ULONG Index,
    _In_ ULONG Param4)
{
    PACPI_WORD_ADDRESS_SPACE_DESCRIPTOR AcpiDesc = Data;
    PIO_RESOURCE_DESCRIPTOR IoDescriptor;
    PIO_RESOURCE_DESCRIPTOR DevicePrivateIoDescriptor;
    ULONG Length;
    ULONG Alignment;
    NTSTATUS Status;

    DPRINT("PnpiBiosAddressToIoDescriptor: %p, %X\n", AcpiDesc, AcpiDesc->ResourceType);

    PAGED_CODE();
    ASSERT(ResourceListArray != NULL);

    if ((AcpiDesc->GeneralFlags & 1) && AcpiDesc->ResourceType == 1 && (Param4 & 1))
        return STATUS_SUCCESS;

    if (!AcpiDesc->AddressLength)
        return STATUS_SUCCESS;

    Status = PnpiUpdateResourceList(&ResourceListArray[Index], &IoDescriptor);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PnpiBiosAddressToIoDescriptor: Status %X\n", Status);
        return Status;
    }

    if (AcpiDesc->ResourceType == 0 || AcpiDesc->ResourceType == 1)
    {
        Status = PnpiUpdateResourceList(&ResourceListArray[Index], &DevicePrivateIoDescriptor);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PnpiBiosAddressToIoDescriptor: Status %X\n", Status);
            return Status;
        }

        ASSERT(ResourceListArray[Index]->Count >= 2);

        IoDescriptor = (DevicePrivateIoDescriptor - 1);

        DevicePrivateIoDescriptor->Type = CmResourceTypeDevicePrivate;
        DevicePrivateIoDescriptor->Flags = 0x6000;
        DevicePrivateIoDescriptor->u.DevicePrivate.Data[2] = 0;
    }

    if (AcpiDesc->Length < 0xD)
    {
        DPRINT1("PnpiBiosAddressToIoDescriptor: KeBugCheckEx! Descriptor too small %X\n", AcpiDesc->Length);
        KeBugCheckEx(0xA5, 0xF, (ULONG_PTR)AcpiDesc, AcpiDesc->Tag, AcpiDesc->Length);
    }

    Length = AcpiDesc->AddressLength;
    Alignment = (AcpiDesc->Granularity + 1);

    if ((AcpiDesc->GeneralFlags & 4) && (AcpiDesc->GeneralFlags & 8))
    {
        if (AcpiDesc->AddressLength != (AcpiDesc->Maximum - AcpiDesc->Minimum + 1))
        {
            DPRINT1("PnpiBiosAddressToIoDescriptor: Length does not match fixed attributes\n");
            Length = (AcpiDesc->Maximum - AcpiDesc->Minimum + 1);
        }

        if ((AcpiDesc->Minimum & (ULONG)AcpiDesc->Granularity))
        {
            DPRINT1("PnpiBiosAddressToIoDescriptor: Granularity does not match fixed attributes\n");
            Alignment = 1;
        }
    }

    switch (AcpiDesc->ResourceType)
    {
        case 0:
        {
            DPRINT1("PnpiBiosAddressToIoDescriptor: FIXME\n");
            ASSERT(FALSE);

            IoDescriptor->u.Memory.Alignment = 1;
            break;
        }
        case 1:
        {
            IoDescriptor->Type = CmResourceTypePort;
            IoDescriptor->u.Port.Length = Length;
            IoDescriptor->u.Port.Alignment = Alignment;
            IoDescriptor->u.Port.MinimumAddress.LowPart = AcpiDesc->Minimum;
            IoDescriptor->u.Port.MinimumAddress.HighPart = 0;
            IoDescriptor->u.Port.MaximumAddress.LowPart = AcpiDesc->Maximum;
            IoDescriptor->u.Port.MaximumAddress.HighPart = 0;

            if (AcpiDesc->SpecificFlags & 0x20)
                DevicePrivateIoDescriptor->Flags |= 1;

            if (AcpiDesc->SpecificFlags & 0x10)
                DevicePrivateIoDescriptor->u.DevicePrivate.Data[0] = CmResourceTypeMemory;
            else
                DevicePrivateIoDescriptor->u.DevicePrivate.Data[0] = CmResourceTypePort;

            DevicePrivateIoDescriptor->u.DevicePrivate.Data[1] = AcpiDesc->Minimum;

            PnpiBiosAddressHandlePortFlags(AcpiDesc, IoDescriptor);

            IoDescriptor->u.Port.Alignment = 1;
            break;
        }
        case 2:
        {
            IoDescriptor->Type = CmResourceTypeBusNumber;

            IoDescriptor->u.BusNumber.MinBusNumber = AcpiDesc->Minimum;
            IoDescriptor->u.BusNumber.MaxBusNumber = AcpiDesc->Maximum;
            IoDescriptor->u.BusNumber.Length = Length;

            PnpiBiosAddressHandleBusFlags(AcpiDesc, IoDescriptor);

            break;
        }
        default:
        {
            DPRINT("PnpiBiosAddressToIoDescriptor: Unknown ResourceType %X\n", AcpiDesc->ResourceType);
            ASSERT(FALSE);
            break;
        }
    }

    PnpiBiosAddressHandleGlobalFlags(AcpiDesc, ResourceListArray, Index, IoDescriptor);

    return STATUS_SUCCESS;
}

VOID
NTAPI
PnpiBiosAddressHandleMemoryFlags(
    _In_ PVOID Data,
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    PACPI_WORD_ADDRESS_SPACE_DESCRIPTOR AcpiDesc = Data;

    PAGED_CODE();

    if (!(AcpiDesc->SpecificFlags & 0x1E))
        goto Finish;

    switch (AcpiDesc->SpecificFlags & 0x1E)
    {
        case 2:
            IoDescriptor->Flags |= 0x20;
            break;

        case 4:
            IoDescriptor->Flags |= 8;
            break;

        case 6:
            IoDescriptor->Flags |= 4;
            break;

        default:
            DPRINT1("PnpiBiosAddressHandleMemoryFlags: Unknown Memory TFlag 0x%02x\n", AcpiDesc->SpecificFlags);
            break;
    }

Finish:

    if (!(AcpiDesc->SpecificFlags & 1))
        IoDescriptor->Flags |= 1;
}

NTSTATUS
NTAPI
PnpiBiosAddressDoubleToIoDescriptor(
    _In_ PVOID Data,
    _In_ PIO_RESOURCE_LIST* ResourceListArray,
    _In_ ULONG Index,
    _In_ ULONG Param4)
{
    PACPI_DWORD_ADDRESS_SPACE_DESCRIPTOR AcpiDesc = Data;
    PIO_RESOURCE_DESCRIPTOR IoDescriptor;
    PIO_RESOURCE_DESCRIPTOR DevicePrivateIoDescriptor;
    ULONG Alignment;
    ULONG Length;
    NTSTATUS Status;

    PAGED_CODE();
    ASSERT(ResourceListArray != NULL);

    if ((AcpiDesc->GeneralFlags & 1) && AcpiDesc->ResourceType == 1 && (Param4 & 1))
        return STATUS_SUCCESS;

    if (!AcpiDesc->AddressLength)
        return STATUS_SUCCESS;

    Status = PnpiUpdateResourceList(&ResourceListArray[Index], &IoDescriptor);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PnpiBiosAddressDoubleToIoDescriptor: Status %X\n", Status);
        return Status;
    }

    if (AcpiDesc->ResourceType == 0 || AcpiDesc->ResourceType == 1)
    {
        Status = PnpiUpdateResourceList(&ResourceListArray[Index], &DevicePrivateIoDescriptor);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PnpiBiosAddressDoubleToIoDescriptor: Status %X\n", Status);
            return Status;
        }

        ASSERT(ResourceListArray[Index]->Count >= 2);

        IoDescriptor = (DevicePrivateIoDescriptor - 1);

        DevicePrivateIoDescriptor->Type = CmResourceTypeDevicePrivate;
        DevicePrivateIoDescriptor->Flags = 0x6000;
        DevicePrivateIoDescriptor->u.DevicePrivate.Data[2] = 0;
    }

    if (AcpiDesc->Length < 0x17)
    {
        DPRINT("PnpiBiosAddressDoubleToIoDescriptor: Descriptor too small %X\n", AcpiDesc->Length);
        KeBugCheckEx(0xA5, 0xF, (ULONG_PTR)AcpiDesc, AcpiDesc->Tag, AcpiDesc->Length);
    }

    Length =  AcpiDesc->AddressLength;
    Alignment = (AcpiDesc->Granularity + 1);

    if ((AcpiDesc->GeneralFlags & 4) && (AcpiDesc->GeneralFlags & 8))
    {
        if (Length != (AcpiDesc->Maximum - AcpiDesc->Minimum + 1))
        {
            DPRINT1("PnpiBiosAddressDoubleToIoDescriptor: Length does not match fixed attributes\n");
            Length = (AcpiDesc->Maximum - AcpiDesc->Minimum + 1);
        }

        if (AcpiDesc->Minimum & AcpiDesc->Granularity)
        {
            DPRINT1("PnpiBiosAddressDoubleToIoDescriptor: Granularity does not match fixed attributes\n");
            Alignment = 1;
        }
    }

    switch (AcpiDesc->ResourceType)
    {
        case 0:
        {
            IoDescriptor->Type = CmResourceTypeMemory;
            IoDescriptor->u.Memory.Length = Length;
            IoDescriptor->u.Memory.Alignment = Alignment;
            IoDescriptor->u.Memory.MinimumAddress.LowPart = AcpiDesc->Minimum;
            IoDescriptor->u.Memory.MinimumAddress.HighPart = 0;
            IoDescriptor->u.Memory.MaximumAddress.LowPart = AcpiDesc->Maximum;
            IoDescriptor->u.Memory.MaximumAddress.HighPart = 0;

            if (AcpiDesc->SpecificFlags & 0x20)
                DevicePrivateIoDescriptor->u.DevicePrivate.Data[0] = CmResourceTypePort;
            else
                DevicePrivateIoDescriptor->u.DevicePrivate.Data[0] = CmResourceTypeMemory;

            DevicePrivateIoDescriptor->u.DevicePrivate.Data[1] = (AcpiDesc->Minimum + AcpiDesc->Offset);

            PnpiBiosAddressHandleMemoryFlags(AcpiDesc, IoDescriptor);

            IoDescriptor->u.Memory.Alignment = 1;
            break;
        }
        case 1:
        {
            IoDescriptor->Type = CmResourceTypePort;
            IoDescriptor->u.Port.Length = Length;
            IoDescriptor->u.Port.Alignment = Alignment;
            IoDescriptor->u.Port.MinimumAddress.LowPart = AcpiDesc->Minimum;
            IoDescriptor->u.Port.MinimumAddress.HighPart = 0;
            IoDescriptor->u.Port.MaximumAddress.LowPart = AcpiDesc->Maximum;
            IoDescriptor->u.Port.MaximumAddress.HighPart = 0;

            if (AcpiDesc->SpecificFlags & 0x20)
                DevicePrivateIoDescriptor->Flags |= 1;

            if (AcpiDesc->SpecificFlags & 0x10)
                DevicePrivateIoDescriptor->u.DevicePrivate.Data[0] = CmResourceTypeMemory;
            else
                DevicePrivateIoDescriptor->u.DevicePrivate.Data[0] = CmResourceTypePort;

            DevicePrivateIoDescriptor->u.DevicePrivate.Data[1] = (AcpiDesc->Minimum + AcpiDesc->Offset);

            PnpiBiosAddressHandlePortFlags(AcpiDesc, IoDescriptor);

            IoDescriptor->u.Port.Alignment = 1;
            break;
        }
        case 2:
        {
            IoDescriptor->Type = CmResourceTypeBusNumber;
            IoDescriptor->u.BusNumber.Length = Length;
            IoDescriptor->u.BusNumber.MinBusNumber = AcpiDesc->Minimum;
            IoDescriptor->u.BusNumber.MaxBusNumber = AcpiDesc->Maximum;

            PnpiBiosAddressHandleBusFlags(AcpiDesc, IoDescriptor);

            break;
        }
        default:
        {
            DPRINT1("PnpiBiosAddressDoubleToIoDescriptor: Unknown ResourceType %X\n", AcpiDesc->ResourceType);
            break;
        }
    }

    PnpiBiosAddressHandleGlobalFlags(AcpiDesc, ResourceListArray, Index, IoDescriptor);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PnpiBiosAddressQuadToIoDescriptor(
    _In_ PVOID Data,
    _In_ PIO_RESOURCE_LIST* ResourceListArray,
    _In_ ULONG Index,
    _In_ ULONG Param4)
{
    PACPI_QWORD_ADDRESS_SPACE_DESCRIPTOR AcpiDesc = Data;
    PIO_RESOURCE_DESCRIPTOR PrivateIoDescriptor;
    PIO_RESOURCE_DESCRIPTOR IoDescriptor;
    ULONGLONG Length;
    ULONG Granularity;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PnpiBiosAddressQuadToIoDescriptor: %p, %X\n", Data, Param4);

    ASSERT(ResourceListArray != NULL);

    if ((AcpiDesc->GeneralFlags & 1) && // This device consumes this resource 
        AcpiDesc->ResourceType == 1 &&  // I/O range
        (Param4 & 1))
    {
        return STATUS_SUCCESS;
    }

    if (!AcpiDesc->AddressLength)
    {
        return STATUS_SUCCESS;
    }

    Status = PnpiUpdateResourceList(&ResourceListArray[Index], &PrivateIoDescriptor);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PnpiBiosAddressQuadToIoDescriptor: Status %X\n", Status);
        return Status;
    }

    if (AcpiDesc->ResourceType == 0 || // Memory range
        AcpiDesc->ResourceType == 1)   // I/O range
    {
        Status = PnpiUpdateResourceList(&ResourceListArray[Index], &PrivateIoDescriptor);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PnpiBiosAddressQuadToIoDescriptor: Status %X\n", Status);
            return Status;
        }

        PrivateIoDescriptor->Type = CmResourceTypeDevicePrivate;
        PrivateIoDescriptor->Flags = 0x6000;

        IoDescriptor = (PrivateIoDescriptor - 1);
    }
    else // ASSERT(AcpiDesc->ResourceType == 2) // Bus number range
    {
        IoDescriptor = PrivateIoDescriptor;
    }

    if (AcpiDesc->Length < 0x2B) // 43 (minimum value)
    {
        DPRINT1("PnpiBiosAddressQuadToIoDescriptor: Descriptor too small %X\n", AcpiDesc->Length);
        KeBugCheckEx(0xA5, 0xF, (ULONG_PTR)AcpiDesc, AcpiDesc->Tag, AcpiDesc->Length);
    }

    Length = AcpiDesc->AddressLength;

    Granularity = AcpiDesc->Granularity;
    Granularity++;

    if ((AcpiDesc->GeneralFlags & 4) && // The specified minimum address is fixed
        (AcpiDesc->GeneralFlags & 8))   // The specified maximum address is fixed
    {
        if ((AcpiDesc->Maximum - AcpiDesc->Minimum + 1) != AcpiDesc->AddressLength)
        {
            DPRINT("PnpiBiosAddressQuadToIoDescriptor: Length does not match fixed attributes\n");
            Length = (AcpiDesc->Maximum - AcpiDesc->Minimum + 1);
        }

        if (AcpiDesc->Minimum & AcpiDesc->Granularity)
        {
            DPRINT("PnpiBiosAddressQuadToIoDescriptor: Granularity does not match fixed attributes\n");
            Granularity = 1;
        }
    }

    if (Length > 0xFFFFFFFF)
    {
        DPRINT("ACPI: descriptor length %I64X exceeds MAXULONG\n", Length);

        if (!(AcpiOverrideAttributes & 0x80))
        {
            DPRINT1("ACPI: descriptor length %I64X exceeds MAXULONG\n", Length);
            KeBugCheckEx(0xA5, 0x14, (ULONG_PTR)AcpiDesc, AcpiDesc->Tag, (ULONG_PTR)&Length);
        }
        else if (AcpiDesc->Minimum < 0xFFFFFFFF)
        {
            DPRINT1("ACPI: descriptor length %I64X exceeds MAXULONG\n", Length);
            KeBugCheckEx(0xA5, 0x14, (ULONG_PTR)AcpiDesc, AcpiDesc->Tag, (ULONG_PTR)&Length);
        }
    }
  
    if (AcpiDesc->ResourceType == 0) // Memory range
    {
        IoDescriptor->Type = CmResourceTypeMemory;
        IoDescriptor->u.Memory.MinimumAddress.QuadPart = AcpiDesc->Minimum;
        IoDescriptor->u.Memory.MaximumAddress.QuadPart = AcpiDesc->Maximum;
        IoDescriptor->u.Memory.Length = Length;
        IoDescriptor->u.Memory.Alignment = Granularity;

        if (AcpiDesc->SpecificFlags & 0x20)
            PrivateIoDescriptor->u.DevicePrivate.Data[0] = CmResourceTypePort;
        else
            PrivateIoDescriptor->u.DevicePrivate.Data[0] = CmResourceTypeMemory;

        PrivateIoDescriptor->u.DevicePrivate.Data[1] = (ULONG)(AcpiDesc->Minimum + AcpiDesc->Offset);
        PrivateIoDescriptor->u.DevicePrivate.Data[2] = ((AcpiDesc->Minimum + AcpiDesc->Offset) >> 32);

        PnpiBiosAddressHandleMemoryFlags(Data, IoDescriptor);
    }
    else if (AcpiDesc->ResourceType == 1) // I/O range 
    {
        IoDescriptor->Type = CmResourceTypePort;
        IoDescriptor->u.Port.MinimumAddress.QuadPart = AcpiDesc->Minimum;
        IoDescriptor->u.Port.MaximumAddress.QuadPart = AcpiDesc->Maximum;
        IoDescriptor->u.Port.Length = Length;
        IoDescriptor->u.Port.Alignment = Granularity;

        if (AcpiDesc->SpecificFlags & 0x20)
            PrivateIoDescriptor->Flags |= 1;

        if (AcpiDesc->SpecificFlags & 0x10)
            PrivateIoDescriptor->u.DevicePrivate.Data[0] = CmResourceTypeMemory;
        else
            PrivateIoDescriptor->u.DevicePrivate.Data[0] = CmResourceTypePort;

        PrivateIoDescriptor->u.DevicePrivate.Data[1] = (ULONG)(AcpiDesc->Minimum + AcpiDesc->Offset);
        PrivateIoDescriptor->u.DevicePrivate.Data[2] = ((AcpiDesc->Minimum + AcpiDesc->Offset) >> 32);

        PnpiBiosAddressHandlePortFlags(Data, IoDescriptor);

        IoDescriptor->u.Port.Alignment = 1;
    }
    else if (AcpiDesc->ResourceType == 2) // Bus number range 
    {
        IoDescriptor->Type = CmResourceTypeBusNumber;
        IoDescriptor->u.BusNumber.MinBusNumber = (ULONG)AcpiDesc->Minimum;
        IoDescriptor->u.BusNumber.MaxBusNumber = (ULONG)AcpiDesc->Maximum;
        IoDescriptor->u.BusNumber.Length = Length;

        PnpiBiosAddressHandleBusFlags(Data, IoDescriptor);
    }
    else
    {
        DPRINT1("PnpiBiosAddressQuadToIoDescriptor: Unknown Type %X\n", AcpiDesc->ResourceType);
    }

    Status = PnpiBiosAddressHandleGlobalFlags(Data, ResourceListArray, Index, IoDescriptor);
    if (NT_SUCCESS(Status))
        Status = STATUS_SUCCESS;

    return Status;
}

NTSTATUS
NTAPI
PnpiBiosPortToIoDescriptor(
    _In_ PACPI_IO_PORT_DESCRIPTOR AcpiDesc,
    _In_ PIO_RESOURCE_LIST* ResourceListArray,
    _In_ ULONG Index,
    _In_ ULONG Param4)
{
    PIO_RESOURCE_DESCRIPTOR IoDescriptor;
    NTSTATUS Status;

    DPRINT("PnpiBiosPortToIoDescriptor: %p, %X\n", AcpiDesc, Param4);

    PAGED_CODE();
    ASSERT(ResourceListArray != NULL);

    if ((Param4 & 1) || !AcpiDesc->RangeLength)
        return STATUS_SUCCESS;

    Status = PnpiUpdateResourceList(&ResourceListArray[Index], &IoDescriptor);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PnpiBiosPortToIoDescriptor: Status %X\n", Status);
        return Status;
    }

    IoDescriptor->Type = CmResourceTypePort;
    IoDescriptor->Flags = 1;
    IoDescriptor->ShareDisposition = 1;

    IoDescriptor->u.Port.MinimumAddress.LowPart = AcpiDesc->Minimum;
    IoDescriptor->u.Port.MaximumAddress.LowPart = (AcpiDesc->Maximum + AcpiDesc->RangeLength - 1);
    IoDescriptor->u.Port.Length = AcpiDesc->RangeLength;
    IoDescriptor->u.Port.Alignment = AcpiDesc->Alignment;

    if (AcpiDesc)
        IoDescriptor->Flags |= CM_RESOURCE_PORT_16_BIT_DECODE;
    else
        IoDescriptor->Flags |= CM_RESOURCE_PORT_10_BIT_DECODE;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PnpiBiosPortFixedToIoDescriptor(
    _In_ PVOID Data,
    _In_ PIO_RESOURCE_LIST* ResourceListArray,
    _In_ ULONG Index,
    _In_ UCHAR Param4)
{
    PACPI_IO_PORT_10_DESCRIPTOR AcpiDesc = Data;
    PIO_RESOURCE_DESCRIPTOR IoDescriptor;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PnpiBiosPortFixedToIoDescriptor: %p, %X\n", Data, Param4);

    ASSERT(ResourceListArray != NULL);

    if (Param4 & 1)
        return STATUS_SUCCESS;

    if (!AcpiDesc->RangeLength)
        return STATUS_SUCCESS;

    Status = PnpiUpdateResourceList(&ResourceListArray[Index], &IoDescriptor);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PnpiBiosPortFixedToIoDescriptor: Status %X\n", Status);
        return Status;
    }

    IoDescriptor->Type = CmResourceTypePort;
    IoDescriptor->Flags = 5;
    IoDescriptor->ShareDisposition = 1;

    IoDescriptor->u.Port.MinimumAddress.LowPart = (AcpiDesc->BaseAddress & 0x3FF);
    IoDescriptor->u.Port.MaximumAddress.LowPart = ((AcpiDesc->BaseAddress & 0x3FF) + AcpiDesc->RangeLength - 1);
    IoDescriptor->u.Port.Length = AcpiDesc->RangeLength;
    IoDescriptor->u.Port.Alignment = 1;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PnpiBiosMemoryToIoDescriptor(
    _In_ PACPI_RESOURCE_DATA_TYPE Data,
    _In_ PIO_RESOURCE_LIST* ResourceListArray,
    _In_ ULONG Index,
    _In_ ULONG Param4)
{
    PIO_RESOURCE_DESCRIPTOR IoDesc;
    ULONG MinimumAddress;
    ULONG MaximumAddress;
    ULONG Length;
    ULONG Align;
    ULONG Flags = 0;
    UCHAR Tag;
    NTSTATUS Status;

    DPRINT("PnpiBiosMemoryToIoDescriptor: %p, %X\n", Data, Param4);

    PAGED_CODE();
    ASSERT(ResourceListArray != NULL);

    if ((Data->Large.Data[0] & 1) == 0) // Writeable
        Flags = 1;

    Tag = Data->Small.Tag;

    if (Tag == 0x81)
    {
        DPRINT1("PnpiBiosMemoryToIoDescriptor: FIXME\n");
        ASSERT(FALSE);
    }
    else if (Tag == 0x85)
    {
        DPRINT1("PnpiBiosMemoryToIoDescriptor: FIXME\n");
        ASSERT(FALSE);
    }
    else if (Tag == 0x86)
    {
        PACPI_FIXED_MEMORY32_DESCRIPTOR AcpiDesc = (PACPI_FIXED_MEMORY32_DESCRIPTOR)Data;

        Length = AcpiDesc->RangeLength;
        if (!Length)
        {
            DPRINT1("PnpiBiosMemoryToIoDescriptor: %X, %X\n", AcpiDesc->BaseAddress, AcpiDesc->RangeLength);
        }

        Align = 1;

        MinimumAddress = AcpiDesc->BaseAddress;
        MaximumAddress = (AcpiDesc->BaseAddress + Length - 1);
    }
    else
    {
        DPRINT1("PnpiBiosMemoryToIoDescriptor: FIXME\n");
        ASSERT(FALSE);
        return STATUS_SUCCESS;
    }

    if (!Length)
        return STATUS_SUCCESS;

    Status = PnpiUpdateResourceList(&ResourceListArray[Index], &IoDesc);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PnpiBiosMemoryToIoDescriptor: Status %X\n", Status);
        return Status;
    }

    IoDesc->Type = CmResourceTypeMemory;
    IoDesc->Flags = Flags;
    IoDesc->ShareDisposition = 1;

    IoDesc->u.Memory.MinimumAddress.u.LowPart = MinimumAddress;
    IoDesc->u.Memory.MinimumAddress.u.HighPart = 0;

    IoDesc->u.Memory.MaximumAddress.u.LowPart = MaximumAddress;
    IoDesc->u.Memory.MaximumAddress.u.HighPart = 0;

    IoDesc->u.Memory.Alignment = Align;
    IoDesc->u.Memory.Length = Length;

    return STATUS_SUCCESS;
}

VOID
NTAPI
PnpiClearAllocatedMemory(
    _In_ PIO_RESOURCE_LIST* ResourceListArray,
    _In_ ULONG ResourceListArraySize)
{
    ULONG Index = 0;

    DPRINT("PnpiClearAllocatedMemory: %p, %X\n", ResourceListArray, ResourceListArraySize);
    PAGED_CODE();

    if (ResourceListArray == NULL)
        return;

    if (ResourceListArraySize > Index)
    {
        do
        {
            if (ResourceListArray[Index])
                ExFreePool(ResourceListArray[Index]);

            Index++;
        }
        while (Index < ResourceListArraySize);
    }

    ExFreePool(ResourceListArray);
}

NTSTATUS
NTAPI
PnpiBiosIrqToIoDescriptor(
    _In_ PACPI_IRQ_DESCRIPTOR AcpiDesc,
    _In_ USHORT Vector,
    _In_ PIO_RESOURCE_LIST* ResourceListArray,
    _In_ ULONG Index,
    _In_ USHORT Count,
    _In_ ULONG Param6)
{
    PIO_RESOURCE_DESCRIPTOR IoDesc;
    NTSTATUS Status;

    DPRINT("PnpiBiosIrqToIoDescriptor: %p, %X\n", ResourceListArray, Vector);

    PAGED_CODE();
    ASSERT(ResourceListArray != NULL);

    Status = PnpiUpdateResourceList(&ResourceListArray[Index], &IoDesc);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PnpiBiosIrqToIoDescriptor: Status %X\n", Status);
        return Status;
    }

    IoDesc->Option = (!Count ? 0 : 8);
    IoDesc->Type = 2;
    IoDesc->u.Interrupt.MinimumVector = Vector;
    IoDesc->u.Interrupt.MaximumVector = Vector;

    if (AcpiDesc->Length != 3)
    {
        IoDesc->Flags = 1;
        IoDesc->ShareDisposition = 1;
        return Status;
    }

    IoDesc->Flags = 0;

    if (AcpiDesc->IntMode)
    {
        IoDesc->Flags |= 1;
        IoDesc->u.ConfigData.Reserved2 = 0; // ? FIXME
        IoDesc->ShareDisposition = (AcpiDesc->IntSharable + 1);
    }

    if (AcpiDesc->IntPolarity)
    {
        IoDesc->u.ConfigData.Reserved2 = 2; // ? FIXME
        IoDesc->ShareDisposition = (AcpiDesc->IntSharable ? 3 : 1);
    }

    return Status;
}

NTSTATUS
NTAPI 
PnpiBiosDmaToIoDescriptor(
    _In_ PACPI_DMA_DESCRIPTOR Data,
    _In_ UCHAR Channel,
    _In_ PIO_RESOURCE_LIST* ResourceListArray,
    _In_ ULONG Index,
    _In_ USHORT Count,
    _In_ ULONG Param6)
{
    PIO_RESOURCE_DESCRIPTOR IoDesc;
    NTSTATUS Status;

    DPRINT("PnpiBiosDmaToIoDescriptor: %p, %X\n", ResourceListArray, Channel);

    PAGED_CODE();
    ASSERT(ResourceListArray != NULL);

    Status = PnpiUpdateResourceList(&ResourceListArray[Index], &IoDesc);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PnpiBiosDmaToIoDescriptor: Status %X\n", Status);
        return Status;
    }

    IoDesc->Option = (Count == 0 ? 0 : 8);
    IoDesc->Type = 4;
    IoDesc->ShareDisposition = 1;
    IoDesc->u.Dma.MinimumChannel = Channel;
    IoDesc->u.Dma.MaximumChannel = Channel;

    if (Data->TransferType)
    {
        if (Data->TransferType == 1)
        {
            IoDesc->Flags |= 4;
        }
        else if (Data->TransferType == 2)
        {
            IoDesc->Flags |= 1;
        }
        else
        {
            ASSERT(Data->TransferType == 3);
            IoDesc->Flags |= 2;
        }
    }

    if (Data->IsBusMaster)
        IoDesc->Flags |= 8;

    switch (Data->SpeedSupported)
    {
        case 1:
            IoDesc->Flags |= 0x10;
            break;
        case 2:
            IoDesc->Flags |= 0x20;
            break;
        case 3:
            IoDesc->Flags |= 0x40;
            break;
    }

    return Status;
}

NTSTATUS
NTAPI 
PnpiBiosExtendedIrqToIoDescriptor(
    _In_ PACPI_EXTENDED_IRQ_DESCRIPTOR AcpiDesc,
    _In_ UCHAR ix,
    _In_ PIO_RESOURCE_LIST* ResourceListArray,
    _In_ ULONG Index,
    _In_ ULONG Param5)
{
    PIO_RESOURCE_DESCRIPTOR IoDescriptor;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PnpiBiosExtendedIrqToIoDescriptor: %p, %X\n", AcpiDesc, ix);

    ASSERT(ResourceListArray != NULL);

    if (ix >= AcpiDesc->TableLength)
    {
        DPRINT1("PnpiBiosExtendedIrqToIoDescriptor: STATUS_INVALID_PARAMETER (%p, %X, %X)\n",
                AcpiDesc, AcpiDesc->TableLength, ix);

        return STATUS_INVALID_PARAMETER;
    }

    if (!AcpiDesc->IntNumber[ix])
        return STATUS_SUCCESS;

    Status = PnpiUpdateResourceList(&ResourceListArray[Index], &IoDescriptor);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PnpiBiosExtendedIrqToIoDescriptor: Status %X\n", Status);
        return Status;
    }

    if (ix)
        IoDescriptor->Option = 8;
    else
        IoDescriptor->Option = 0;

    IoDescriptor->Type = 2;
    IoDescriptor->Flags = 0;

    IoDescriptor->u.Interrupt.MaximumVector = AcpiDesc->IntNumber[ix];
    IoDescriptor->u.Interrupt.MinimumVector = AcpiDesc->IntNumber[ix];

    if (AcpiDesc->VectorFlags & 2)
    {
        IoDescriptor->Flags = 1;

        if (AcpiDesc->VectorFlags & 8)
            IoDescriptor->ShareDisposition = 2;
        else
            IoDescriptor->ShareDisposition = 1;
    }
    else
    {
        IoDescriptor->Flags = 0;

        if (AcpiDesc->VectorFlags & 8)
            IoDescriptor->ShareDisposition = 3;
        else
            IoDescriptor->ShareDisposition = 1;
    }

    if ((AcpiDesc->VectorFlags & 4) == 4)
        IoDescriptor->u.ConfigData.Reserved2 = 2;
    else
        IoDescriptor->u.ConfigData.Reserved2 = 0;

    return Status;
}

NTSTATUS
NTAPI
PnpBiosResourcesToNtResources(
    _In_ PVOID Data,
    _In_ ULONG Param2,
    _Out_ PIO_RESOURCE_REQUIREMENTS_LIST* OutIoResource)
{
    PIO_RESOURCE_LIST* ResourceListArray = NULL;
    PIO_RESOURCE_LIST IoList;
    PACPI_RESOURCE_DATA_TYPE ResDataType;
    ULONG ResourceListArraySize = 0;
    ULONG Increment;
    ULONG Index = 0;
    ULONG MaxIndex = 0;
    ULONG Size;
    ULONG Count;
    ULONG ix = 0;
    ULONG jx = 0;
    UCHAR TagName;
    NTSTATUS Status;

    DPRINT("PnpBiosResourcesToNtResources: %p, %X\n", Data, Param2);

    PAGED_CODE();
    ASSERT(Data != NULL);

    Status = PnpiGrowResourceList(&ResourceListArray, &ResourceListArraySize);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PnpBiosResourcesToNtResources: Status %X\n", Status);
        return Status;
    }

    for (ResDataType = Data; ; )
    {
        if (!ResDataType->Small.Type)
        {
            Increment = (ResDataType->Small.Length + 1);
            TagName = ResDataType->Small.Name;
            DPRINT("PnpBiosResourcesToNtResources: Small TagName %X, Increment %X\n", TagName, Increment);
        }
        else
        {
            Increment = (ResDataType->Large.Length + 3);
            TagName = ResDataType->Large.Name;
            DPRINT("PnpBiosResourcesToNtResources: Large TagName %X, Increment %X\n", TagName, Increment);
        }

        if ((ResDataType->Small.Tag & 0xF8) == 0x78)
        {
            DPRINT("PnpBiosResourcesToNtResources: TAG_END\n");
            break;
        }

        ix++;

        if (!ResDataType->Small.Type)
        {
            switch (TagName)
            {
                case 0x04:
                {
                    ULONG Count = 0;
                    ULONG Vector = 0;
                    USHORT IrqMask;

                    for (IrqMask = ((PACPI_IRQ_DESCRIPTOR)Data)->IrqMask; IrqMask; IrqMask >>= 1)
                    {
                        if (Status < 0)
                            break;

                        if (IrqMask & 1)
                            Status = PnpiBiosIrqToIoDescriptor(Data, Vector, ResourceListArray, Index, Count++, Param2);

                        Vector++;
                    }

                    DPRINT("PnpBiosResourcesToNtResources: TAG_IRQ. Count %X, Status %X\n", Count, Status);
                    break;
                }
                case 0x05:
                {
                    USHORT Count = 0;
                    UCHAR Channel;
                    UCHAR ChannelMask;

                    ChannelMask = ((PACPI_DMA_DESCRIPTOR)Data)->ChannelMask;

                    for (Channel = 0; ChannelMask; Channel++)
                    {
                        if (!NT_SUCCESS(Status))
                            break;

                        if (ChannelMask & 1)
                        {
                            Status = PnpiBiosDmaToIoDescriptor(Data, Channel, ResourceListArray, Index, Count, Param2);
                            Count++;
                        }

                        ChannelMask >>= 1;
                    }

                    DPRINT("PnpBiosResourcesToNtResources: TAG_DMA. Count %X, Status %X\n", Count, Status);
                    break;
                }
                case 0x06:
                {
                    MaxIndex++;
                    Index = MaxIndex;

                    DPRINT("PnpBiosResourcesToNtResources: TAG_START_DEPEND(Index %X)\n", Index);

                    if (Index == ResourceListArraySize)
                        Status = PnpiGrowResourceList(&ResourceListArray, &ResourceListArraySize);

                    break;
                }
                case 0x07:
                {
                    DPRINT("PnpBiosResourcesToNtResources: TAG_END_DEPEND(Index %X)\n", Index);
                    Index = 0;
                    break;
                }
                case 0x08:
                {
                    Status = PnpiBiosPortToIoDescriptor(Data, ResourceListArray, Index, Param2);
                    DPRINT("PnpBiosResourcesToNtResources: TAG_IO, Status %X\n", Status);
                    break;
                }
                case 0x09:
                {
                    Status = PnpiBiosPortFixedToIoDescriptor(Data, ResourceListArray, Index, Param2);
                    DPRINT1("PnpBiosResourcesToNtResources: TAG_IO_FIXED, Status %X\n", Status);
                    break;
                }
                case 0x0E:
                {
                    DPRINT1("PnpBiosResourcesToNtResources: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                default:
                {
                    DPRINT1("PnpBiosResourcesToNtResources: Unsupported TagName %X\n", TagName);
                    //ASSERT(FALSE);
                    break;
                }
            }
        }
        else
        {
            switch (TagName)
            {
                case 0x01:
                {
                    DPRINT1("PnpBiosResourcesToNtResources: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x02:
                {
                    DPRINT1("PnpBiosResourcesToNtResources: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x03:
                {
                    DPRINT1("PnpBiosResourcesToNtResources: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x04:
                {
                    DPRINT1("PnpBiosResourcesToNtResources: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x05:
                {
                    DPRINT1("PnpBiosResourcesToNtResources: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x06:
                {
                    Status = PnpiBiosMemoryToIoDescriptor(Data, ResourceListArray, Index, Param2);
                    DPRINT("PnpBiosResourcesToNtResources: TAG_MEMORY = %X\n", Status);
                    break;
                }
                case 0x07:
                {
                    Status = PnpiBiosAddressDoubleToIoDescriptor(Data, ResourceListArray, Index, Param2);
                    DPRINT("PnpBiosResourcesToNtResources: TAG_DOUBLE_ADDRESS = %X\n", Status);
                    break;
                }
                case 0x08:
                {
                    Status = PnpiBiosAddressToIoDescriptor(Data, ResourceListArray, Index, Param2);
                    DPRINT("PnpBiosResourcesToNtResources: TAG_WORD_ADDRESS = %X\n", Status);
                    break;
                }
                case 0x09:
                {
                    PACPI_EXTENDED_IRQ_DESCRIPTOR AcpiDesc = Data;
                    ULONG ix;

                    for (ix = 0; ix < AcpiDesc->TableLength; ix++)
                    {
                        if (!NT_SUCCESS(Status))
                            break;

                        Status = PnpiBiosExtendedIrqToIoDescriptor(AcpiDesc, ix, ResourceListArray, Index, Param2);
                    }

                    DPRINT("PnpBiosResourcesToNtResources: TAG_EXTENDED_IRQ(count: %X) = %X\n", ix, Status);
                    break;
                }
                case 0x0A:
                {
                    Status = PnpiBiosAddressQuadToIoDescriptor(Data, ResourceListArray, Index, Param2);
                    DPRINT1("PnpBiosResourcesToNtResources: TAG_QUAD_ADDRESS = %X\n", Status);
                    break;
                }
                case 0x0B:
                {
                    DPRINT1("PnpBiosResourcesToNtResources: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                default:
                {
                    DPRINT1("PnpBiosResourcesToNtResources: Unsupported TagName %X\n", TagName);
                    //ASSERT(FALSE);
                    break;
                }
            }
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PnpBiosResourcesToNtResources: Failed on TagName %X, Status %X\n", TagName, Status);

            PnpiClearAllocatedMemory(ResourceListArray, ResourceListArraySize);
            return Status;
        }

        Data = ResDataType = Add2Ptr(ResDataType, Increment);
    }

    DPRINT("PnpBiosResourcesToNtResources: TAG_END\n");

    if (!NT_SUCCESS(Status))
    {
        DPRINT("PnpBiosResourcesToNtResources: Failed on TagName %X, Status %X\n", TagName, Status);

        PnpiClearAllocatedMemory(ResourceListArray, ResourceListArraySize);
        return Status;
    }

    //FIXME!
    //if (0)              // NT 5.1
    //if (ix && ix == jx) // NT 5.2
    if (!ix || ix == jx)  // NT 6.1
    {
        DPRINT("PnpBiosResourcesToNtResources: This _CRS contains vendor defined tags only. No resources will be allocated.\n");

        PnpiClearAllocatedMemory(ResourceListArray, ResourceListArraySize);
        *OutIoResource = NULL;
        return Status;
    }

    Size = sizeof(IO_RESOURCE_DESCRIPTOR);

    if (ResourceListArray[0])
        Count = ResourceListArray[0]->Count;
    else
        Count = 0;

    for (Index = 1; Index <= MaxIndex; Index++)
    {
        if (!(ResourceListArray[Index]))
        {
            DPRINT1("PnpBiosResourcesToNtResources: Bad List at Array[%X]\n", Index);
            PnpiClearAllocatedMemory(ResourceListArray, ResourceListArraySize);
            *OutIoResource = NULL;
            return STATUS_UNSUCCESSFUL;
        }

        if (ResourceListArray[Index]->Count)
        {
            DPRINT("PnpBiosResourcesToNtResources: Index %X, Size %X\n", Index, Size);
            Size += (sizeof(IO_RESOURCE_LIST) + ((ResourceListArray[Index]->Count + Count - 1) * sizeof(IO_RESOURCE_DESCRIPTOR)));
        }
    }

    if (!MaxIndex)
    {
        if (!ResourceListArray[0] || !ResourceListArray[0]->Count)
        {
            DPRINT1("PnpBiosResourcesToNtResources: No Resources to Report\n");
            PnpiClearAllocatedMemory(ResourceListArray, ResourceListArraySize);
            *OutIoResource = NULL;
            return STATUS_UNSUCCESSFUL;
        }

        Size += (sizeof(IO_RESOURCE_LIST) + ((ResourceListArray[0]->Count - 1) * sizeof(IO_RESOURCE_DESCRIPTOR)));
    }

    if (Size < sizeof(IO_RESOURCE_REQUIREMENTS_LIST))
    {
        DPRINT1("PnpBiosResourcesToNtResources: Resources smaller than a List\n");
        PnpiClearAllocatedMemory(ResourceListArray, ResourceListArraySize);
        *OutIoResource = NULL;
        return STATUS_UNSUCCESSFUL;
    }

    *OutIoResource = ExAllocatePoolWithTag(PagedPool, Size, 'RpcA');

    DPRINT("PnpBiosResourceToNtResources: %p, %X\n", *OutIoResource, Size);

    if (!(*OutIoResource))
    {
        DPRINT1("PnpBiosResourceToNtResources: Could not allocate memory for ResourceRequirementList\n");
        PnpiClearAllocatedMemory(ResourceListArray, ResourceListArraySize);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(*OutIoResource, Size);

    (*OutIoResource)->InterfaceType = 0xF;
    (*OutIoResource)->BusNumber = 0;
    (*OutIoResource)->ListSize = Size;

    IoList = (*OutIoResource)->List;

    for (Index = 1; Index <= MaxIndex; Index++)
    {
        if (!(ResourceListArray[Index]->Count))
            continue;

        Size = (sizeof(IO_RESOURCE_LIST) + ((ResourceListArray[Index]->Count - 1) * sizeof(IO_RESOURCE_DESCRIPTOR)));
        ResourceListArray[Index]->Count += Count;

        DPRINT("PnpBiosResourcesToNtResources: [%X] %p, %X, %X\n", Index, IoList, Size, ResourceListArray[Index]->Count);
        RtlCopyMemory(IoList, ResourceListArray[Index], Size);

        IoList = Add2Ptr(IoList, Size);

        if (Count)
        {
            RtlCopyMemory(IoList, ResourceListArray[0]->Descriptors, (Count * sizeof(IO_RESOURCE_DESCRIPTOR)));
            IoList = Add2Ptr(IoList, (Count * sizeof(IO_RESOURCE_DESCRIPTOR)));
        }

        (*OutIoResource)->AlternativeLists++;
    }

    if (!MaxIndex)
    {
        ASSERT(Count != 0);
        RtlCopyMemory(IoList, ResourceListArray[0], (sizeof(IO_RESOURCE_LIST) + ((Count - 1) * sizeof(IO_RESOURCE_DESCRIPTOR))));

        (*OutIoResource)->AlternativeLists++;
    }

    PnpiClearAllocatedMemory(ResourceListArray, ResourceListArraySize);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PnpDeviceBiosResourcesToNtResources(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID Data,
    _In_ ULONG Param3,
    _Inout_ PIO_RESOURCE_REQUIREMENTS_LIST* OutIoResource)
{
    KIRQL Irql;
    BOOLEAN IsFound;
    NTSTATUS Status;

    DPRINT("PnpDeviceBiosResourcesToNtResources: %p, %X\n", DeviceExtension, Param3);

    Status = PnpBiosResourcesToNtResources(Data, Param3, OutIoResource);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PnpDeviceBiosResourcesToNtResources: Status %X\n", Status);
        return Status;
    }

    if (!(*OutIoResource))
    {
        DPRINT1("PnpDeviceBiosResourcesToNtResources: IoResource is NULL!\n");
        return Status;
    }

    IsFound = FALSE;

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &Irql);

    while (DeviceExtension)
    {
        if (DeviceExtension->Flags & 0x0000002000000000)
        {
            IsFound = TRUE;
            break;
        }

        DeviceExtension = DeviceExtension->ParentExtension;
    }

    KeReleaseSpinLock(&AcpiDeviceTreeLock, Irql);

    if (!IsFound)
        return Status;

    DPRINT1("PnpDeviceBiosResourcesToNtResources: FIXME\n");
    ASSERT(FALSE);

    return Status;
}

NTSTATUS
NTAPI
ACPIRangeSortCmList(
    _In_ PCM_RESOURCE_LIST CmResource)
{
    PCM_PARTIAL_RESOURCE_LIST PartialList;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor1;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor2;
    CM_PARTIAL_RESOURCE_DESCRIPTOR descriptor;
    ULONG DescriptorCount;
    ULONG DescriptorSize;
    ULONG ix;
    ULONG jx;

    DPRINT("ACPIRangeSortCmList: %p\n", CmResource);

    PartialList = &CmResource->List[0].PartialResourceList;

    DescriptorCount = PartialList->Count;
    DescriptorSize = sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);

    for (ix = 0; ix < DescriptorCount; ix++)
    {
        Descriptor1 = &PartialList->PartialDescriptors[ix];

        for (jx = (ix + 1); jx < DescriptorCount; jx++)
        {
            Descriptor2 = &PartialList->PartialDescriptors[jx];

            if (Descriptor1->Type != Descriptor2->Type)
                continue;

            if (Descriptor1->Type == CmResourceTypePort)
            {
                if (Descriptor2->u.Port.Start.QuadPart < Descriptor1->u.Port.Start.QuadPart)
                    Descriptor1 = Descriptor2;

                continue;
            }

            if (Descriptor1->Type == CmResourceTypeMemory)
            {
                if (Descriptor2->u.Memory.Start.QuadPart < Descriptor1->u.Memory.Start.QuadPart)
                    Descriptor1 = Descriptor2;

                continue;
            }

            if (Descriptor1->Type == CmResourceTypeInterrupt)
            {
                if (Descriptor2->u.Interrupt.Vector < Descriptor1->u.Interrupt.Vector)
                    Descriptor1 = Descriptor2;

                continue;
            }

            if (Descriptor1->Type == CmResourceTypeDma)
            {
                if (Descriptor2->u.Dma.Channel < Descriptor1->u.Dma.Channel)
                    Descriptor1 = Descriptor2;
            }
        }

        if (Descriptor1 == &PartialList->PartialDescriptors[ix])
            continue;

        RtlCopyMemory(&descriptor, &PartialList->PartialDescriptors[ix], DescriptorSize);
        RtlCopyMemory(&PartialList->PartialDescriptors[ix], Descriptor1, DescriptorSize);
        RtlCopyMemory(Descriptor1, &descriptor, DescriptorSize);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIRangeSortIoList(
    _In_ PIO_RESOURCE_LIST IoList)
{
    PIO_RESOURCE_DESCRIPTOR Descriptor1;
    PIO_RESOURCE_DESCRIPTOR Descriptor2;
    IO_RESOURCE_DESCRIPTOR descriptor;
    ULONG Count;
    ULONG ix;
    ULONG jx;

    DPRINT("ACPIRangeSortIoList: %p\n", IoList);

    Count = IoList->Count;

    for (ix = 0; ix < Count; ix++)
    {
        Descriptor1 = &IoList->Descriptors[ix];

        for (jx = (ix + 1); jx < Count; jx++)
        {
            Descriptor2 = &IoList->Descriptors[jx];

            if (Descriptor1->Type != Descriptor2->Type)
                continue;

            if (Descriptor1->Type == CmResourceTypePort)
            {
                if (Descriptor2->u.Port.MinimumAddress.QuadPart < Descriptor1->u.Port.MinimumAddress.QuadPart)
                    Descriptor1 = Descriptor2;

                continue;
            }

            if (Descriptor1->Type == CmResourceTypeMemory)
            {
                if (Descriptor2->u.Memory.MinimumAddress.QuadPart < Descriptor1->u.Memory.MinimumAddress.QuadPart)
                    Descriptor1 = Descriptor2;

                continue;
            }

            if (Descriptor1->Type == CmResourceTypeInterrupt)
            {
                if (Descriptor2->u.Interrupt.MinimumVector < Descriptor1->u.Interrupt.MinimumVector)
                    Descriptor1 = Descriptor2;

                continue;
            }

            if (Descriptor1->Type == CmResourceTypeDma)
            {
                if (Descriptor2->u.Dma.MinimumChannel < Descriptor1->u.Dma.MaximumChannel)
                    Descriptor1 = Descriptor2;
            }
        }

        if (Descriptor1 == &IoList->Descriptors[ix])
            continue;

        RtlCopyMemory(&descriptor, &IoList->Descriptors[ix], sizeof(IO_RESOURCE_DESCRIPTOR));
        RtlCopyMemory(&IoList->Descriptors[ix], Descriptor1, sizeof(IO_RESOURCE_DESCRIPTOR));
        RtlCopyMemory(Descriptor1, &descriptor, sizeof(IO_RESOURCE_DESCRIPTOR));
    }

    return STATUS_SUCCESS;

}

NTSTATUS
NTAPI
ACPIRangeSubtractIoList(
    _In_ PIO_RESOURCE_LIST InIoList,
    _In_ PCM_RESOURCE_LIST CmResource,
    _Out_ PIO_RESOURCE_LIST* OutIoList)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PCM_PARTIAL_RESOURCE_LIST PartialList;
    PIO_RESOURCE_DESCRIPTOR IoDescriptor;
    PIO_RESOURCE_LIST IoList;
    ULONG DescriptorCount;
    ULONG Count;
    ULONG Size;
    ULONG ix;
    ULONG jx = 0;
    ULONG kx;

    DPRINT("ACPIRangeSubtractIoList: %p, %p\n", InIoList, CmResource);

    PartialList = &CmResource->List[0].PartialResourceList;

    DescriptorCount = PartialList->Count;
    Count = InIoList->Count;
    Size = (sizeof(IO_RESOURCE_LIST) + ((((DescriptorCount + Count) * 2) - 1)) * sizeof(IO_RESOURCE_DESCRIPTOR));

    IoList = ExAllocatePoolWithTag(NonPagedPool, Size, 'RpcA');
    if (!IoList)
    {
        DPRINT1("ACPIRangeSubtractIoList: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(IoList, Size);

    IoList->Version = InIoList->Version;
    IoList->Revision = InIoList->Revision;
    IoList->Count = InIoList->Count;

    for (ix = 0; ix < Count; ix++)
    {
        RtlCopyMemory(&IoList->Descriptors[jx], &InIoList->Descriptors[ix], sizeof(IO_RESOURCE_DESCRIPTOR));

        DPRINT("ACPIRangeSubtractIoList: InIoDesc[%X] %X -> IoDesc[%X] %X\n", ix, &InIoList->Descriptors[ix], jx, &IoList->Descriptors[jx]);

        IoDescriptor = &IoList->Descriptors[jx];
        jx++;

        for (kx = 0; kx < DescriptorCount; kx++)
        {
            if (!IoDescriptor)
                break;

            CmDescriptor = &PartialList->PartialDescriptors[kx];

            if (CmDescriptor->Type != IoDescriptor->Type)
                continue;

            if (IoDescriptor->Type == CmResourceTypePort ||
                IoDescriptor->Type == CmResourceTypeMemory)
            {
                DPRINT1("ACPIRangeSubtractIoList: FIXME\n");
                ASSERT(FALSE);
                continue;
            }

            if (IoDescriptor->Type == CmResourceTypeInterrupt)
            {
                DPRINT1("ACPIRangeSubtractIoList: FIXME\n");
                ASSERT(FALSE);
                continue;
            }

            if (IoDescriptor->Type == CmResourceTypeDma)
            {
                DPRINT1("ACPIRangeSubtractIoList: FIXME\n");
                ASSERT(FALSE);
                continue;
            }
        }

        IoDescriptor = &IoList->Descriptors[jx];
        RtlCopyMemory(IoDescriptor, &InIoList->Descriptors[ix], sizeof(IO_RESOURCE_DESCRIPTOR));
        IoDescriptor->Type = CmResourceTypeDevicePrivate;

        DPRINT("ACPIRangeSubtractIoList: InIoDesc[%X] %X -> IoDesc[%X] %X for backup\n", ix, &InIoList->Descriptors[ix], jx, IoDescriptor);

        jx++;
    }

    IoList->Count = jx;

    Size = (sizeof(IO_RESOURCE_LIST) + (jx - 1) * sizeof(IO_RESOURCE_DESCRIPTOR));

    *OutIoList = ExAllocatePoolWithTag(NonPagedPool, Size, 'RpcA');
    if (*OutIoList == NULL)
    {
        DPRINT1("ACPIRangeSubtractIoList: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(*OutIoList, IoList, Size);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIRangeSubtract(
    _Inout_ PIO_RESOURCE_REQUIREMENTS_LIST* OutIoResource,
    _In_ PCM_RESOURCE_LIST CmResource)
{
    PIO_RESOURCE_REQUIREMENTS_LIST IoResource;
    PIO_RESOURCE_LIST* ResourceListArray;
    PIO_RESOURCE_LIST IoList;
    ULONG ListCounter;
    ULONG ResourceSize;
    ULONG Size;
    ULONG ix;
    NTSTATUS Status;

    DPRINT("ACPIRangeSubtract: %p, %p\n", OutIoResource, CmResource);

    ListCounter = (*OutIoResource)->AlternativeLists;

    Status = ACPIRangeSortCmList(CmResource);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIRangeSubtract: Status %X\n", Status);
        return Status;
    }

    Size = (ListCounter * sizeof(PIO_RESOURCE_LIST));

    ResourceListArray = ExAllocatePoolWithTag(NonPagedPool, Size, 'RpcA');
    if (!ResourceListArray)
    {
        DPRINT1("ACPIRangeSubtract: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(ResourceListArray, Size);

    IoList = (*OutIoResource)->List;
    ResourceSize = (sizeof(IO_RESOURCE_REQUIREMENTS_LIST) - sizeof(IO_RESOURCE_LIST));

    Status = ACPIRangeSortIoList(IoList);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIRangeSubtract: Status %X\n", Status);
        return Status;
    }

    for (ix = 0; ix < ListCounter; ix++)
    {
        Status = ACPIRangeSubtractIoList(IoList, CmResource, &ResourceListArray[ix]);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIRangeSubtract: Status %X\n", Status);

            while (ix)
            {
                ExFreePool(ResourceListArray[ix]);
                ix--;
            }

            ExFreePool(ResourceListArray);

            return Status;
        }

        ResourceSize += (sizeof(IO_RESOURCE_LIST) + (((ResourceListArray[ix])->Count - 1) * sizeof(IO_RESOURCE_DESCRIPTOR)));
        Size = (sizeof(IO_RESOURCE_LIST) + (IoList->Count - 1) * sizeof(IO_RESOURCE_DESCRIPTOR));
        IoList = Add2Ptr(IoList, Size);
    }

    IoResource = ExAllocatePoolWithTag(NonPagedPool, ResourceSize, 'RpcA');
    if (!IoResource)
    {
        DPRINT1("ACPIRangeSubtract: STATUS_INSUFFICIENT_RESOURCES\n");

        do
        {
            ListCounter--;
            ExFreePool(ResourceListArray[ListCounter]);
        }
        while (ListCounter);

        ExFreePool(ResourceListArray);

        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(IoResource, ResourceSize);

    RtlCopyMemory(IoResource, *OutIoResource, (sizeof(IO_RESOURCE_REQUIREMENTS_LIST) - sizeof(IO_RESOURCE_LIST)));

    IoResource->ListSize = ResourceSize;
    IoList = IoResource->List;

    for (ix = 0; ix < ListCounter; ix++)
    {
        Size = sizeof(IO_RESOURCE_LIST) + ((((ResourceListArray[ix])->Count) - 1) * sizeof(IO_RESOURCE_DESCRIPTOR));
        RtlCopyMemory(IoList, ResourceListArray[ix], Size);
        IoList = Add2Ptr(IoList, Size);
        ExFreePool(ResourceListArray[ix]);
    }

    ExFreePool(ResourceListArray);
    ExFreePool(*OutIoResource);

    *OutIoResource = IoResource;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIBusIrpQueryResourceRequirements(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_RESOURCE_REQUIREMENTS_LIST IoResource = NULL;
    PDEVICE_EXTENSION DeviceExtension;
    PVOID CrsDataBuff = NULL;
    PVOID PrsDataBuff = NULL;
    ULONG CrsDataLen;
    ULONG PrsDataLen;
    NTSTATUS CrsStatus;
    NTSTATUS PrsStatus;
    NTSTATUS Status = Irp->IoStatus.Status;

    PAGED_CODE();
    DPRINT("ACPIBusIrpQueryResourceRequirements: %p, %p\n", DeviceObject, Irp);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    CrsStatus = ACPIGet(DeviceExtension, 'SRC_', 0x20010008, NULL, 0, NULL, NULL, &CrsDataBuff, &CrsDataLen);
    PrsStatus = ACPIGet(DeviceExtension, 'SRP_', 0x20010008, NULL, 0, NULL, NULL, &PrsDataBuff, &PrsDataLen);

    if (!NT_SUCCESS(CrsStatus) && !NT_SUCCESS(PrsStatus))
    {
        if (PrsStatus == STATUS_INSUFFICIENT_RESOURCES || CrsStatus == STATUS_INSUFFICIENT_RESOURCES)
            Status = STATUS_INSUFFICIENT_RESOURCES;

        DPRINT("ACPIBusIrpQueryResourceRequirements: Status %X\n", Status);
        goto Exit;
    }

    if (NT_SUCCESS(CrsStatus))
        Status = STATUS_NOT_SUPPORTED;

    if (NT_SUCCESS(PrsStatus))
    {
        Status = PnpDeviceBiosResourcesToNtResources(DeviceExtension, PrsDataBuff, 0, &IoResource);
        if (!NT_SUCCESS(Status))
        {
            //ASSERTMSG("The BIOS has reported inconsistent resources (_PRS). Please upgrade your BIOS.", NT_SUCCESS(Status));
            DPRINT1("The BIOS has reported inconsistent resources (_PRS). Please upgrade your BIOS. (%X)\n", Status);
        }

        ExFreePool(PrsDataBuff);
    }

    if (!NT_SUCCESS(Status) && NT_SUCCESS(CrsStatus))
    {
        Status = PnpDeviceBiosResourcesToNtResources(DeviceExtension,
                                                     CrsDataBuff,
                                                     ((DeviceExtension->Flags & 0x0000000002000000) != 0),
                                                     &IoResource);
        if (!NT_SUCCESS(Status))
        {
            //ASSERTMSG("The BIOS has reported inconsistent resources (_CRS). Please upgrade your BIOS.", NT_SUCCESS(Status));
            DPRINT1("The BIOS has reported inconsistent resources (_CRS). Please upgrade your BIOS. (%X)\n", Status);
        }
    }

    if (NT_SUCCESS(CrsStatus))
        ExFreePool(CrsDataBuff);

    if (!IoResource)
    {
        if (!(DeviceExtension->Flags & 0x0000000002000000))
            goto Exit;

        Status = STATUS_UNSUCCESSFUL;
    }

    if (DeviceExtension->Flags & 0x0000000002000000)
    {
        ACPIRangeValidatePciResources(DeviceExtension, IoResource);

        Status = ACPIRangeSubtract(&IoResource, RootDeviceExtension->ResourceList);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIBusIrpQueryResourceRequirements: Status %X\n", Status);
            ASSERT(NT_SUCCESS(Status));
            ExFreePool(IoResource);
            IoResource = NULL;
        }

        /* KeBugCheckEx() if !NT_SUCCESS(Status) */
        ACPIRangeValidatePciResources(DeviceExtension, IoResource);
    }
    else if (DeviceExtension->Flags & 0x0000000200000000)
    {
        Status = ACPIRangeFilterPICInterrupt(IoResource);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIBusIrpQueryResourceRequirements: Status %X\n", Status);
            ExFreePool(IoResource);
            IoResource = NULL;
        }
    }

    if (!NT_SUCCESS(Status))
    {
        Irp->IoStatus.Information = 0;
        goto Exit;
    }

    if (NT_SUCCESS(Status))
        Irp->IoStatus.Information = (ULONG_PTR)IoResource;
    else
        Irp->IoStatus.Information = 0;

Exit:

    if (!NT_SUCCESS(Status) &&
        Status != STATUS_INSUFFICIENT_RESOURCES &&
        (DeviceExtension->Flags & 0x0000000002000000))
    {
        DPRINT1("ACPIBusIrpQueryResourceRequirements: Status %X\n", Status);
        ASSERT(FALSE);
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
ACPIBusIrpEject(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIBusIrpSetLock(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIBusIrpQueryId(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    PIO_STACK_LOCATION IoStack;
    BUS_QUERY_ID_TYPE IdType;
    PVOID DataBuff;
    ULONG dummy;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ACPIBusIrpQueryId: %p, %p\n", DeviceObject, Irp);

    Status = Irp->IoStatus.Status;
    IoStack = Irp->Tail.Overlay.CurrentStackLocation;

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    IdType = IoStack->Parameters.QueryId.IdType;

    if (IdType == BusQueryDeviceID)
    {
        Status = ACPIGet(DeviceExtension, 'DIH_', 0x20080036, NULL, 0, NULL, NULL, &DataBuff, &dummy);
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
        {
            Status = STATUS_NOT_SUPPORTED;
            goto Finish;
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIBusIrpQueryId: Status %X\n", Status);
            goto Finish;
        }

        Irp->IoStatus.Information = (ULONG_PTR)DataBuff;
        goto Finish;
    }

    if (IdType == BusQueryHardwareIDs)
    {
        Status = ACPIGet(DeviceExtension, 'DIH_', 0x20080056, NULL, 0, NULL, NULL, &DataBuff, &dummy);
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
        {
            Status = STATUS_NOT_SUPPORTED;
            goto Finish;
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIBusIrpQueryId: Status %X\n", Status);
            goto Finish;
        }

        Irp->IoStatus.Information = (ULONG_PTR)DataBuff;
        goto Finish;
    }

    if (IdType == BusQueryCompatibleIDs)
    {
        Status = ACPIGet(DeviceExtension, 'DIC_', 0x20080117, NULL, 0, NULL, NULL, &DataBuff, &dummy);
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
        {
            Status = STATUS_NOT_SUPPORTED;
            goto Finish;
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIBusIrpQueryId: Status %X\n", Status);
            goto Finish;
        }

        Irp->IoStatus.Information = (ULONG_PTR)DataBuff;
        goto Finish;
    }

    if (IdType == BusQueryInstanceID)
    {
        Status = ACPIGet(DeviceExtension, 'DIU_', 0x20080096, NULL, 0, NULL, NULL, &DataBuff, &dummy);
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
        {
            Status = STATUS_NOT_SUPPORTED;
            goto Finish;
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIBusIrpQueryId: Status %X\n", Status);
            goto Finish;
        }

        Irp->IoStatus.Information = (ULONG_PTR)DataBuff;
        goto Finish;
    }

Finish:

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
ACPIBusAndFilterIrpQueryPnpDeviceState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ ULONG Param3,
    _In_ BOOLEAN Param4)
{
    PDEVICE_EXTENSION DeviceExtension;
    PAMLI_NAME_SPACE_OBJECT NsObject = NULL;
    PVOID DataBuff;
    BOOLEAN IsFoundChild;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ACPIBusAndFilterIrpQueryPnpDeviceState: %p, %p\n", DeviceObject, Irp);
    PAGED_CODE();

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    if (!(DeviceExtension->Flags & 0x0008000000000000))
    {
        NsObject = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, 'ATS_');
    }

    IsFoundChild = (NsObject != NULL);

    Status = ACPIGet(DeviceExtension, 'ATS_', 0x20040802, NULL, 0, NULL, NULL, &DataBuff, 0);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIBusAndFilterIrpQueryPnpDeviceState: Status %X\n", Status);
        goto Exit;
    }

    if (DeviceExtension->Flags & 0x0000000040000000)
        Irp->IoStatus.Information |= 2;
    else  if (DeviceExtension->Flags & 0x0000000020000000)
        Irp->IoStatus.Information |= 2;
    else if (IsFoundChild || !Param4)
        Irp->IoStatus.Information &= ~2;

    if (DeviceExtension->Flags & 0x0080000000000000)
        Irp->IoStatus.Information |= 4;
    else if (IsFoundChild && !Param4)
        Irp->IoStatus.Information &= ~4;

    if ((DeviceExtension->Flags & 0x0008000000000000) ||
        (DeviceExtension->Flags & 0x0000001000000000) ||
        (DeviceExtension->Flags & 0x0000000008000000) ||
        (DeviceExtension->Flags & 0x0000000000040000))
    {
        if (DeviceExtension->Flags & 0x0000000000200000)
            Irp->IoStatus.Information |= 0x20;

        goto Exit;
    }

    NsObject = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, 'SID_');

    if (Param4)
    {
        if (!NsObject)
        {
            NsObject = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, '3SP_');
            if (!NsObject)
                NsObject = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, '0RP_');
        }

        if (DeviceExtension->Flags & 0x0000000000200000)
            NsObject = NULL;

        if (NsObject)
            Irp->IoStatus.Information &= ~0x20;

        goto Exit;
    }

    if (!NsObject)
    {
        NsObject = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, '3SP_');
        if (!NsObject)
            NsObject = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, '0RP_');
    }

    if (DeviceExtension->Flags & 0x0000000000200000)
        NsObject = NULL;

    if (!NsObject)
        Irp->IoStatus.Information |= 0x20;

Exit:
    DPRINT("ACPIBusAndFilterIrpQueryPnpDeviceState: Irp->IoStatus.Information %p\n", Irp->IoStatus.Information);

    return Status;
}

NTSTATUS
NTAPI
ACPIBusIrpQueryPnpDeviceState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PAGED_CODE();
    return ACPIIrpInvokeDispatchRoutine(DeviceObject, Irp, 0, ACPIBusAndFilterIrpQueryPnpDeviceState, TRUE, TRUE);
}

NTSTATUS
NTAPI
ACPIBusIrpQueryBusInformation(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIBusIrpDeviceUsageNotification(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIBusIrpSurpriseRemoval(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* PDO Power FUNCTIOS *******************************************************/

NTSTATUS
NTAPI
ACPIDispatchPowerIrpUnhandled(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIBusIrpSetDevicePower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIBusIrpSetSystemPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack)
{
    PDEVICE_EXTENSION DeviceExtension;
    DEVICE_POWER_STATE DeviceState;

    DPRINT("ACPIBusIrpSetSystemPower: DeviceObject %p\n", DeviceObject);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    DeviceState = DeviceExtension->PowerInfo.DevicePowerMatrix[IoStack->Parameters.Power.State.SystemState];

    if (IoStack->Parameters.Power.ShutdownType != PowerActionWarmEject)
    {
        if (!(DeviceExtension->Flags & 0x0000000000020000) ||
            DeviceExtension->PowerInfo.PowerState == DeviceState)
        {
            return ACPIDispatchPowerIrpSuccess(DeviceObject, Irp);
        }

        DPRINT1("ACPIBusIrpSetSystemPower: %p, send D%d irp!\n", Irp, (DeviceState - PowerDeviceD0));

        DPRINT1("ACPIBusIrpSetSystemPower: FIXME\n");
        ASSERT(FALSE);
        return STATUS_NOT_IMPLEMENTED;
    }

    DPRINT1("ACPIBusIrpSetSystemPower: DeviceObject %p\n", DeviceObject);
    ASSERT(FALSE);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIBusIrpSetPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;

    DPRINT("ACPIBusIrpSetPower: DeviceObject %p\n", DeviceObject);

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (IoStack->Parameters.Power.Type == DevicePowerState)
        return ACPIBusIrpSetDevicePower(DeviceObject, Irp, IoStack);

    return ACPIBusIrpSetSystemPower(DeviceObject, Irp, IoStack);
}

NTSTATUS
NTAPI
ACPIBusIrpQueryPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* Internal Device FUNCTIOS *************************************************/

NTSTATUS
NTAPI
ACPIInternalDeviceQueryDeviceRelations(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    DPRINT("ACPIInternalDeviceQueryDeviceRelations: DeviceObject %p\n", DeviceObject);
    PAGED_CODE();

    IoStack = Irp->Tail.Overlay.CurrentStackLocation;

    if (IoStack->Parameters.QueryDeviceRelations.Type != TargetDeviceRelation)
    {
        DPRINT("ACPIInternalDeviceQueryDeviceRelations: Unhandled Type %X\n", IoStack->Parameters.QueryDeviceRelations.Type);
        Status = Irp->IoStatus.Status;
        goto Exit;
    }

    DPRINT1("ACPIInternalDeviceQueryDeviceRelations: FIXME\n");
    ASSERT(FALSE);

Exit:

    IoCompleteRequest(Irp, 0);
    return Status;
}

NTSTATUS
NTAPI
ACPIInternalDeviceQueryCapabilities(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    PIO_STACK_LOCATION IoStack;
    PDEVICE_CAPABILITIES Capabilities;
    NTSTATUS Status;

    DPRINT("ACPIInternalDeviceQueryCapabilities: DeviceObject %p\n", DeviceObject);
    PAGED_CODE();

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    Capabilities = IoStack->Parameters.DeviceCapabilities.Capabilities;

    if (DeviceExtension->InstanceID)
        Capabilities->UniqueID = 1;
    else
        Capabilities->UniqueID = 0;

    if (DeviceExtension->Flags & 0x0000000000020000)
        Capabilities->RawDeviceOK = 1;
    else
        Capabilities->RawDeviceOK = 0;

    Capabilities->SilentInstall = 1;

    Status = ACPISystemPowerQueryDeviceCapabilities(DeviceExtension, Capabilities);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIInternalDeviceQueryCapabilities: Could query device capabilities - %X", Status);
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

NTSTATUS
NTAPI
ACPIInternalWaitWakeLoop(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ UCHAR MinorFunction,
    _In_ POWER_STATE PowerState,
    _In_ PVOID Context,
    _In_ PIO_STATUS_BLOCK IoStatus)
{
    if (!NT_SUCCESS(IoStatus->Status))
        return IoStatus->Status;

    PoRequestPowerIrp(DeviceObject, MinorFunction, PowerState, (PREQUEST_POWER_COMPLETE)ACPIInternalWaitWakeLoop, Context, NULL);

    return STATUS_SUCCESS;
}

VOID
NTAPI
ACPIInternalDeviceClockIrpStartDeviceCompletion(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID Context,
    _In_ NTSTATUS InStatus)
{
    PIRP Irp = Context;
    POWER_STATE PowerState;
    IO_STATUS_BLOCK IoStatus;
    KIRQL Irql;
    NTSTATUS Status;

    DPRINT("ACPIInternalDeviceClockIrpStartDeviceCompletion: %p, %p\n", DeviceExtension, Irp);

    Irp->IoStatus.Status = InStatus;
    if (!NT_SUCCESS(InStatus))
    {
        DPRINT1("ACPIInternalDeviceClockIrpStartDeviceCompletion: InStatus %X\n", InStatus);
        goto Finish;
    }

    DeviceExtension->DeviceState = 2;

    if (!(DeviceExtension->Flags & 0x10000))
        goto Finish;

    KeAcquireSpinLock(&AcpiPowerLock, &Irql);
    PowerState.SystemState = DeviceExtension->PowerInfo.SystemWakeLevel;
    KeReleaseSpinLock(&AcpiPowerLock, Irql);

    IoStatus.Status = STATUS_SUCCESS;
    IoStatus.Information = 0;

    Status = ACPIInternalWaitWakeLoop(DeviceExtension->DeviceObject, 0, PowerState, NULL, &IoStatus);

    if (!NT_SUCCESS(Status))
        Irp->IoStatus.Status = Status;

Finish:

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

NTSTATUS
NTAPI
ACPIInternalDeviceClockIrpStartDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    NTSTATUS Status;

    PAGED_CODE();

    Status = ACPIInitStartDevice(DeviceObject, NULL, ACPIInternalDeviceClockIrpStartDeviceCompletion, Irp, Irp);
    if (NT_SUCCESS(Status))
        Status = STATUS_PENDING;

    return Status;
}

/* Internal Device Power FUNCTIOS *******************************************/

NTSTATUS
NTAPI
ACPIDispatchPowerIrpInvalid(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIDispatchPowerIrpSuccess(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PoStartNextPowerIrp(Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, 0);

    return STATUS_SUCCESS;
}

/* Fixed Button FUNCTIOS ****************************************************/

VOID
NTAPI
ACPIButtonCancelRequest(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
}

BOOLEAN
NTAPI
ACPIButtonCompletePendingIrps(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG Event)
{
    PLIST_ENTRY Entry;
    PIRP Irp;
    LIST_ENTRY list;
    KIRQL Irql;
    BOOLEAN Result = FALSE;

    DPRINT("ACPIButtonCompletePendingIrps: %X, %X", DeviceObject, Event);

    InitializeListHead(&list);

    KeAcquireSpinLock(&AcpiButtonLock, &Irql);

    for (Entry = AcpiButtonList.Flink; Entry != &AcpiButtonList; )
    {
        Irp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);
        Entry = Entry->Flink;

        if (IoGetCurrentIrpStackLocation(Irp)->DeviceObject != DeviceObject)
            continue;

        if (!IoSetCancelRoutine(Irp, NULL))
            continue;

        *(ULONG *)Irp->AssociatedIrp.SystemBuffer = Event;

        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = sizeof(Event);

        RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
        InsertTailList(&list, &Irp->Tail.Overlay.ListEntry);
    }

    KeReleaseSpinLock(&AcpiButtonLock, Irql);

    for (Entry = list.Flink; Entry != &list; )
    {
        Irp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);
        Entry = Entry->Flink;

        RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        Result = TRUE;
    }

    return Result;
}

NTSTATUS
NTAPI
ACPIButtonEvent(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG Event,
    _In_ ULONG Param3)
{
    PDEVICE_EXTENSION DeviceExtension;
    KIRQL Irql;
    BOOLEAN Result;

    DPRINT("ACPIButtonEvent: %X, %X", DeviceObject, Event);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    if ((Event & 0x80000003) && !(DeviceExtension->Button.Capabilities & 4))
        PoSetSystemState(4);

    if (!DeviceObject)
        return STATUS_SUCCESS;

    KeAcquireSpinLock(&DeviceExtension->Button.SpinLock, &Irql);

    DeviceExtension->Button.Events |= Event;

    if (DeviceExtension->Button.Events)
    {
        Result = ACPIButtonCompletePendingIrps(DeviceObject, DeviceExtension->Button.Events);
        if (Result)
            DeviceExtension->Button.Events = 0;
    }

    KeReleaseSpinLock(&DeviceExtension->Button.SpinLock, Irql);

    return STATUS_PENDING;
}

NTSTATUS
NTAPI
ACPIButtonDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    PIO_STACK_LOCATION IoStack;
    KIRQL Irql;
    NTSTATUS Status;

    DPRINT("ACPIButtonDeviceControl: %X, %X", DeviceObject, Irp);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (Irp->RequestorMode != KernelMode)
        return ACPIDispatchIrpInvalid(DeviceObject, Irp);

    if (IoStack->Parameters.DeviceIoControl.IoControlCode == 0x294140)
    {
        if (IoStack->Parameters.DeviceIoControl.OutputBufferLength == 4)
        {
            *(PULONG)Irp->AssociatedIrp.SystemBuffer = DeviceExtension->Button.Capabilities;
            Irp->IoStatus.Information = 4;
            Status = STATUS_SUCCESS;
        }
        else
        {
            DPRINT1("ACPIButtonDeviceControl: STATUS_INFO_LENGTH_MISMATCH");
            Irp->IoStatus.Information = 0;
            Status = STATUS_INFO_LENGTH_MISMATCH;
        }

        goto Exit;
    }

    if (IoStack->Parameters.DeviceIoControl.IoControlCode != 0x294144)
    {
        DPRINT1("ACPIButtonDeviceControl: STATUS_NOT_SUPPORTED (%X)", IoStack->Parameters.DeviceIoControl.IoControlCode);
        Status = STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    if (IoStack->Parameters.DeviceIoControl.OutputBufferLength != 4)
    {
        DPRINT1("ACPIButtonDeviceControl: STATUS_INFO_LENGTH_MISMATCH");
        Irp->IoStatus.Information = 0;
        Status = STATUS_INFO_LENGTH_MISMATCH;
        goto Exit;
    }

    KeAcquireSpinLock(&AcpiButtonLock, &Irql);
    IoSetCancelRoutine(Irp, ACPIButtonCancelRequest);

    if (!Irp->Cancel || !IoSetCancelRoutine(Irp, NULL))
    {
        IoMarkIrpPending(Irp);
        InsertTailList(&AcpiButtonList, &Irp->Tail.Overlay.ListEntry);

        KeReleaseSpinLock(&AcpiButtonLock, Irql);

        return ACPIButtonEvent(DeviceObject, 0, 0);
    }

    KeReleaseSpinLock(&AcpiButtonLock, Irql);

    Irp->IoStatus.Information = 0;
    Status = STATUS_CANCELLED;

Exit:

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
ACPIInternalSetDeviceInterface(
    IN PDEVICE_OBJECT DeviceObject,
    IN LPGUID InterfaceGuid)
{
    UNICODE_STRING SymbolicLinkName;
    NTSTATUS Status;

    Status = IoRegisterDeviceInterface(DeviceObject, InterfaceGuid, NULL, &SymbolicLinkName);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIInternalSetDeviceInterface: IoRegisterDeviceInterface ret %X", Status);
        return Status;
    }

    Status = IoSetDeviceInterfaceState(&SymbolicLinkName, TRUE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIInternalSetDeviceInterface: IoSetDeviceInterfaceState ret %X", Status);
    }

    return Status;
}

NTSTATUS
NTAPI
ACPIButtonStartDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    NTSTATUS Status;

    Status = ACPIInternalSetDeviceInterface(DeviceObject, (LPGUID)&GUID_DEVICE_SYS_BUTTON);

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

VOID
NTAPI
ACPICMButtonNotify(
    _In_ PVOID Context,
    _In_ ULONG NotifyCode)
{
    PDEVICE_OBJECT DeviceObject = Context;
    PDEVICE_EXTENSION DeviceExtension;

    DPRINT("ACPICMButtonNotify: %p\n", DeviceObject);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    if (NotifyCode == 2)
    {
        ACPIButtonEvent(DeviceObject, 0x80000000, 0);
        return;
    }

    if (NotifyCode != 0x80)
    {
        DPRINT1("ACPICMButtonNotify: Unknown CM butt notify code %d\n", NotifyCode);
        return;
    }

    if (DeviceExtension->Button.Capabilities & 4)
    {
        ACPISetDeviceWorker(DeviceExtension, 1);
        return;
    }

    ACPIButtonEvent(DeviceObject, (DeviceExtension->Button.Capabilities & 0x7FFFFFFF), 0);
}

VOID
NTAPI
ACPICMLidPowerStateCallBack(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2)
{
    PDEVICE_EXTENSION DeviceExtension = CallbackContext;
    SYSTEM_POWER_POLICY OutputBuffer;
    NTSTATUS Status;

    if (Argument1)
        return;

    Status = ZwPowerInformation(SystemPowerPolicyCurrent, NULL, 0, &OutputBuffer, sizeof(OutputBuffer));
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPICMLidPowerStateCallBack: Failed ZwPowerInformation %X\n", Status);
        return;
    }

    if (OutputBuffer.LidClose.Action != 0 && OutputBuffer.LidClose.Action != 1)
        ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x1000000000000000, TRUE);
    else
        ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x1000000000000000, FALSE);
}

VOID
NTAPI
ACPICMButtonStartWorker(
    _In_ PVOID Context)
{
    PDEVICE_OBJECT DeviceObject = Context;
    PDEVICE_EXTENSION DeviceExtension;
    PDEVICE_OBJECT AttachedTo;
    IO_STATUS_BLOCK IoStatus;
    POWER_STATE PowerState;
    PIRP Irp;
    NTSTATUS Status;
    KIRQL Irql;

    DPRINT("ACPICMButtonStartWorker: %p\n", Context);

    AttachedTo = DeviceObject->AttachedDevice;
    DeviceExtension = ACPIInternalGetDeviceExtension(AttachedTo);
    Irp = DeviceObject->CurrentIrp;

    Status = Irp->IoStatus.Status;
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPICMButtonStartWorker: Status %X\n", Status);
        goto Finish;
    }

    if (DeviceExtension->Button.Capabilities & 4)
    {
        ACPIInternalRegisterPowerCallBack(DeviceExtension, ACPICMLidPowerStateCallBack);
        ACPICMLidPowerStateCallBack(DeviceExtension, NULL, NULL);
        ACPISetDeviceWorker(DeviceExtension, 0);
    }
    else
    {
        IoStatus.Status = STATUS_SUCCESS;
        IoStatus.Information = 0;

        KeAcquireSpinLock(&AcpiPowerLock, &Irql);
        PowerState.SystemState = DeviceExtension->PowerInfo.SystemWakeLevel;
        KeReleaseSpinLock(&AcpiPowerLock, Irql);

        ACPIInternalWaitWakeLoop(AttachedTo, 0, PowerState, NULL, &IoStatus);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPICMButtonStartWorker: Status %X\n", Status);
            goto Finish;
        }
    }

    ACPIRegisterForDeviceNotifications(AttachedTo, ACPICMButtonNotify, AttachedTo);

    Status = ACPIInternalSetDeviceInterface(AttachedTo, (LPGUID)&GUID_DEVICE_SYS_BUTTON);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPICMButtonStartWorker: Status %X\n", Status);
    }

Finish:

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    DPRINT("ACPICMButtonStartWorker: (%p, %X) Status %X\n", Irp, IoGetCurrentIrpStackLocation(Irp)->MinorFunction, Status);
}

VOID
NTAPI
ACPICMButtonStartCompletion(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID Context,
    _In_ NTSTATUS InStatus)
{
    PIRP Irp = Context;
    PWORK_QUEUE_CONTEXT WorkContext;

    DPRINT("ACPICMButtonStartCompletion: %p, %p, %X\n", DeviceExtension, Context, InStatus);

    Irp->IoStatus.Status = InStatus;

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT1("ACPICMButtonStartCompletion: InStatus %X\n", InStatus);
        IoCompleteRequest(Irp, 0);
        return;
    }

    DeviceExtension->DeviceState = 2;

    WorkContext = &DeviceExtension->Filter.WorkContext;

    WorkContext->DeviceObject = DeviceExtension->DeviceObject;
    WorkContext->Irp = Irp;

    ExInitializeWorkItem(&WorkContext->Item, ACPICMButtonStartWorker, WorkContext);

    ExQueueWorkItem(&WorkContext->Item, DelayedWorkQueue);
}

NTSTATUS
NTAPI
ACPICMButtonStart(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ ULONG Capabilities)
{
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status;
  
    PAGED_CODE();
    DPRINT("ACPICMButtonStart: %p, %p, %X\n", DeviceObject, Irp, Capabilities);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    KeInitializeSpinLock(&DeviceExtension->Button.SpinLock);

    DeviceExtension->Button.Capabilities = Capabilities;

    Status = ACPIInitStartDevice(DeviceObject, NULL, ACPICMButtonStartCompletion, Irp, Irp);
    if (NT_SUCCESS(Status))
        Status = STATUS_PENDING;

    return Status;
}

NTSTATUS
NTAPI
ACPICMPowerButtonStart(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PAGED_CODE();
    return ACPICMButtonStart(DeviceObject, Irp, 0x80000001);
}

NTSTATUS
NTAPI
ACPICMButtonSetPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPICMSleepButtonStart(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PAGED_CODE();
    return ACPICMButtonStart(DeviceObject, Irp, 0x80000002);
}

/* Thermal Device FUNCTIOS **************************************************/

NTSTATUS
NTAPI
ACPIThermalFanStartDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;

    DPRINT("ACPIThermalFanStartDevice: %p, %p\n", DeviceObject, Irp);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    DeviceExtension->DeviceState = 2;

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, 0);

    DPRINT("ACPIThermalFanStartDevice: STATUS_SUCCESS (%p, %X)\n", Irp, IoGetCurrentIrpStackLocation(Irp)->MinorFunction);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIThermalDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
ACPIThermalEvent(
    _In_ PVOID Context,
    _In_ ULONG NotifyCode)
{
    PDEVICE_OBJECT DeviceObject = Context;
    PDEVICE_EXTENSION DeviceExtension;
    ULONGLONG Time;
    ULONG Flags;

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    Time = KeQueryInterruptTime();

    DPRINT("ACPIThermalEvent: (%I64X) Notify %X\n", Time, NotifyCode);

    if (NotifyCode == 0x80)
        Flags = 0x20000002;
    else if (NotifyCode == 0x81)
        Flags = 0x20000006;
    else
        Flags = 0;

    ACPIThermalLoop(DeviceExtension, Flags);
}

NTSTATUS
NTAPI
ACPIThermalQueryWmiRegInfo(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PULONG RegFlags,
    _In_ PUNICODE_STRING InstanceName,
    _Out_ PUNICODE_STRING* OutRegistryPath,
    _In_ PUNICODE_STRING MofResourceName,
    _Out_ PDEVICE_OBJECT* OutPdo)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIThermalQueryWmiDataBlock(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ ULONG GuidIndex,
    _In_ ULONG InstanceIndex,
    _In_ ULONG InstanceCount,
    _Out_ ULONG* OutInstanceLengthArray,
    _In_ ULONG BufferAvail,
    _Out_ UCHAR* OutBuffer)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
__cdecl
ACPIThermalTempatureRead(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA Result,
    _In_ PVOID Context)
{
    PDEVICE_EXTENSION DeviceExtension = Context;
    PACPI_THERMAL_INFO Info;
    ULONGLONG Time;

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT1("ACPIThermalTempatureRead: InStatus %X\n", InStatus);
        goto Finish;
    }

    ASSERT(Result->DataType == 1);//OBJTYPE_INTDATA

    Info = DeviceExtension->Thermal.Info;
    Info->Header.CurrentTemperature = (ULONG)Result->DataValue;

    AMLIFreeDataBuffs(Result, 1);

    Time = KeQueryInterruptTime();

    do
    {
        static int bWarnedOnce = 0;
        if (bWarnedOnce < 4)
        {
            bWarnedOnce++;
            DPRINT1("ACPIThermalTempatureRead: (%I64X) Current Temperature is %d.%dK\n",
                    Time, (Info->Header.CurrentTemperature / 0xA), (Info->Header.CurrentTemperature % 0xA));
        }
    } while (0);

Finish:

    ACPIThermalLoop(DeviceExtension, 0x40000000);
}

BOOLEAN
NTAPI
ACPIThermalCompletePendingIrps(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PACPI_THERMAL_INFO Info)
{
    BOOLEAN Result = FALSE;
    KIRQL Irql;

    KeAcquireSpinLock(&AcpiThermalLock, &Irql);

    if (!IsListEmpty(&AcpiThermalList))
    {
        Result = TRUE;
        UNIMPLEMENTED_DBGBREAK();
    }

    KeReleaseSpinLock(&AcpiThermalLock, Irql);

    return Result;
}

VOID
__cdecl
ACPIThermalComplete(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ NTSTATUS InStatus,
    _In_ ULONG Unknown3,
    _In_ PDEVICE_EXTENSION DeviceExtension)
{
    ACPIThermalLoop(DeviceExtension, 0x40000000);
}

VOID
NTAPI
ACPIThermalLoop(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ ULONG InFlags)
{
    PACPI_THERMAL_INFO Info;
    NTSTATUS Status;
    BOOLEAN IsLocked;
    KIRQL Irql;

    DPRINT("ACPIThermalLoop: %p, %X\n", DeviceExtension, InFlags);

    Info = DeviceExtension->Thermal.Info;

    KeAcquireSpinLock(&DeviceExtension->Thermal.SpinLock, &Irql);

    DeviceExtension->Thermal.Flags &= ~InFlags;

    if (DeviceExtension->Thermal.Flags & 0x80000000)
    {
        KeReleaseSpinLock(&DeviceExtension->Thermal.SpinLock, Irql);
        return;
    }

    IsLocked = TRUE;

    DPRINT("ACPIThermalLoop: %X, %X\n", DeviceExtension->Thermal.Flags, InFlags);

    DeviceExtension->Thermal.Flags |= 0x80000000;

    while (TRUE)
    {
        if (!IsLocked)
        {
            KeAcquireSpinLock(&DeviceExtension->Thermal.SpinLock, &Irql);
            IsLocked = TRUE;
        }

        if (DeviceExtension->Thermal.Flags & 0x40000000)
            break;

        if (!(DeviceExtension->Thermal.Flags & 0x00000010))
        {
            DeviceExtension->Thermal.Flags |= 0x40000010;
            ACPISetDeviceWorker(DeviceExtension, 0x11);
            continue;
        }

        if (!(DeviceExtension->Thermal.Flags & 0x00000008))
        {
            DeviceExtension->Thermal.Flags |= 0x40000008;

            KeReleaseSpinLock(&DeviceExtension->Thermal.SpinLock, Irql);

            IsLocked = FALSE;

            Status = ACPIGet(DeviceExtension,
                             'PCS_', // Set Cooling Policy
                             0x41100000,
                             (PVOID)Info->CoolingMode,
                             4,
                             ACPIThermalComplete,
                             DeviceExtension,
                             NULL,
                             NULL);

            if (Status != STATUS_PENDING)
                ACPIThermalLoop(DeviceExtension, 0x40000000);

            continue;
        }

        if (!(DeviceExtension->Thermal.Flags & 0x00000004))
        {
            DeviceExtension->Thermal.Flags |= 0x40000004;
            ACPISetDeviceWorker(DeviceExtension, 4);
            continue;
        }

        if (!(DeviceExtension->Thermal.Flags & 0x00000001))
        {
            DeviceExtension->Thermal.Flags |= 0x40000001;
            ACPISetDeviceWorker(DeviceExtension, 1);
            continue;
        }

        if ((DeviceExtension->Thermal.Flags & 0x20000000) &&
            (DeviceExtension->Thermal.Flags & 0x00000002))
        {
            break;
        }

        if (DeviceExtension->Thermal.Flags & 0x00000002)
        {
            if (!ACPIThermalCompletePendingIrps(DeviceExtension, Info))
                break;

            continue;
        }

        if (!Info->CurrentTemperatureMethod)
        {
            DPRINT1("ACPIThermalLoop: %X, %X\n", DeviceExtension->Thermal.Flags, InFlags);
            UNIMPLEMENTED_DBGBREAK();
        }

        Info->Header.ThermalStamp++;

        DeviceExtension->Thermal.Flags |= 0x40000002;

        KeReleaseSpinLock(&DeviceExtension->Thermal.SpinLock, Irql);

        RtlZeroMemory(&Info->TempatureData, sizeof(Info->TempatureData));

        IsLocked = FALSE;

        Info->TempatureData.DataType = 0;

        Status = AMLIAsyncEvalObject(Info->CurrentTemperatureMethod,
                                     &Info->TempatureData,
                                     0,
                                     NULL,
                                     ACPIThermalTempatureRead,
                                     DeviceExtension);

        if (Status != STATUS_PENDING)
            ACPIThermalTempatureRead(Info->CurrentTemperatureMethod, Status, &Info->TempatureData, DeviceExtension);
    }

    DeviceExtension->Thermal.Flags &= ~0x80000000;

    KeReleaseSpinLock(&DeviceExtension->Thermal.SpinLock, Irql);
}

NTSTATUS
NTAPI
ACPIThermalStartDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    PWMILIB_CONTEXT WmilibContext;
    NTSTATUS Status;

    DPRINT("ACPIThermalStartDevice: %p, %p\n", DeviceObject, Irp);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    Status = ACPIInternalSetDeviceInterface(DeviceObject, (LPGUID)&GUID_DEVICE_THERMAL_ZONE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIThermalStartDevice: Status %X\n", Status);
        goto Exit;
    }

    ACPIRegisterForDeviceNotifications(DeviceObject, ACPIThermalEvent, DeviceObject);

    WmilibContext = ExAllocatePoolWithTag(PagedPool, sizeof(*WmilibContext), 'TpcA');
    if (!WmilibContext)
    {
        DPRINT1("ACPIThermalStartDevice: IRP_MN_START_DEVICE\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    RtlZeroMemory(WmilibContext, sizeof(*WmilibContext));

    WmilibContext->GuidCount = 1;
    WmilibContext->GuidList = &ACPIThermalGuidList;
    WmilibContext->QueryWmiRegInfo = ACPIThermalQueryWmiRegInfo;
    WmilibContext->QueryWmiDataBlock = ACPIThermalQueryWmiDataBlock;

    DeviceExtension->Thermal.WmilibContext = WmilibContext;

    Status = IoWMIRegistrationControl(DeviceObject, 1);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIThermalStartDevice: Status %X\n", Status);

        DeviceExtension->Button.Capabilities = 0;

        ExFreePoolWithTag(WmilibContext, 'TpcA');
        goto Exit;
    }

    DeviceExtension->DeviceState = 2;

    Status = ACPIDeviceInternalDeviceRequest(DeviceExtension, 1, NULL, NULL, 0);
    if (Status == STATUS_PENDING)
        Status = STATUS_SUCCESS;

    ACPIThermalLoop(DeviceExtension, 0xC);
 
Exit:

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
ACPIThermalWmi(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
ACPIThermalPowerCallback(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID Context,
    _In_ NTSTATUS InStatus)
{
    if (!NT_SUCCESS(InStatus))
    {
        DPRINT1("ACPIThermalPowerCallback: failed power setting %X\n", InStatus);
    }
}

VOID
NTAPI
ACPIThermalCalculateProcessorMask(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ PTHERMAL_INFORMATION InfoHeader)
{
    PDEVICE_EXTENSION DeviceExtension;
    KIRQL Irql;

    if (!NsObject)
        return;

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &Irql);

    DeviceExtension = NsObject->Context;

    if (DeviceExtension)
        InfoHeader->Processors |= (1 << DeviceExtension->Processor.ProcessorIndex);

    KeReleaseSpinLock(&AcpiDeviceTreeLock, Irql);
}

VOID
NTAPI
ACPIThermalWorker(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ ULONG Flags)
{
    PAMLI_NAME_SPACE_OBJECT ScopeObject;
    PAMLI_NAME_SPACE_OBJECT PslObject;
    PAMLI_NAME_SPACE_OBJECT NsObject;
    PAMLI_PACKAGE_OBJECT PackageObject;
    PACPI_THERMAL_INFO Info;
    AMLI_OBJECT_DATA Data1;
    AMLI_OBJECT_DATA Data2;
    ULONGLONG Time;
    ULONG ActiveList[0xA];
    ULONG ActiveCooling[0xA];
    ULONG Count;
    ULONG jx;
    ULONG ix;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ACPIThermalWorker: %p, %X\n", DeviceExtension, Flags);

    Time = KeQueryInterruptTime();

    Info = DeviceExtension->Thermal.Info;
    ScopeObject = DeviceExtension->AcpiObject;

    if (Flags & 0x10)
    {
        ActiveList[0] = '0LA_';
        ActiveList[1] = '1LA_';
        ActiveList[2] = '2LA_';
        ActiveList[3] = '3LA_';
        ActiveList[4] = '4LA_';
        ActiveList[5] = '5LA_';
        ActiveList[6] = '6LA_';
        ActiveList[7] = '7LA_';
        ActiveList[8] = '8LA_';
        ActiveList[9] = '9LA_';

        Info->CoolingMode = 1;

        for (ix = 0; ix < 0xA; ix++)
        {
            NsObject = ACPIAmliGetNamedChild(ScopeObject, ActiveList[ix]);
            if (!NsObject)
                break;

            Info->NsObjects[ix] = NsObject;
        }
    }

    if (Flags & 1)
    {
        RtlZeroMemory(&Data1, sizeof(Data1));
        RtlZeroMemory(&Data2, sizeof(Data2));

        for (ix = 0; ix < 0xA; ix++)
        {
            if (!Info->NsObjects[ix])
                break;

            Status = AMLIEvalNameSpaceObject(Info->NsObjects[ix], &Data1, 0, NULL);
            if (!NT_SUCCESS(Status))
                break;

            PackageObject = Data1.DataBuff;
            Count = PackageObject->Elements;

            for (jx = 0; jx < Count; jx++)
            {
                Status = AMLIEvalPkgDataElement(&Data1, jx, &Data2);
                if (!NT_SUCCESS(Status))
                    break;

                DPRINT("ACPIThermalWorker: (%I64X) Turn '%s' %s\n", Time, (ix < Info->ActiveCoolingLevel ? "off" : "on "), Data2.DataBuff);

                Status = AMLIGetNameSpaceObject(Data2.DataBuff, ScopeObject, &NsObject, 0);
                AMLIFreeDataBuffs(&Data2, 1);

                if (!NT_SUCCESS(Status))
                    break;

                if (!NsObject->Context)
                    break;

                ACPIDeviceInternalDeviceRequest((PDEVICE_EXTENSION)NsObject->Context,
                                                (ix < Info->ActiveCoolingLevel ? 4 : 1),
                                                ACPIThermalPowerCallback,
                                                NULL,
                                                0);
            }

            AMLIFreeDataBuffs(&Data1, 1);
        }
    }

    if (Flags & 4)
        goto Finish;

    ActiveCooling[0] = '0CA_';
    ActiveCooling[1] = '1CA_';
    ActiveCooling[2] = '2CA_';
    ActiveCooling[3] = '3CA_';
    ActiveCooling[4] = '4CA_';
    ActiveCooling[5] = '5CA_';
    ActiveCooling[6] = '6CA_';
    ActiveCooling[7] = '7CA_';
    ActiveCooling[8] = '8CA_';
    ActiveCooling[9] = '9CA_';

    ACPIGet(DeviceExtension, '1CT_', 0x20040002, NULL, 0, NULL, 0, (PVOID *)&Info->Header.ThermalConstant1, NULL);
    DPRINT("ACPIThermalWorker: (%I64X) ThermalConstant1 %X\n", Time, Info->Header.ThermalConstant1);

    ACPIGet(DeviceExtension, '2CT_', 0x20040002, NULL, 0, NULL, 0, (PVOID *)&Info->Header.ThermalConstant2, NULL);
    DPRINT("ACPIThermalWorker: (%I64X) ThermalConstant2 X\n", Time, Info->Header.ThermalConstant2);

    ACPIGet(DeviceExtension, 'VSP_', 0x20040002, NULL, 0, NULL, 0, (PVOID *)&Info->Header.PassiveTripPoint, NULL);
    DPRINT("ACPIThermalWorker: (%I64X) PassiveTripPoint %d.%dK\n", Time, Info->Header.PassiveTripPoint / 0xA);

    ACPIGet(DeviceExtension, 'TRC_', 0x20040002, NULL, 0, NULL, 0, (PVOID *)&Info->Header.CriticalTripPoint, NULL);
    DPRINT("ACPIThermalWorker: (%I64X) CriticalTripPoint %d.%dK\n", Time, Info->Header.CriticalTripPoint / 0xA);

    ACPIGet(DeviceExtension, 'PST_', 0x20040002, NULL, 0, NULL, 0, (PVOID *)&Info->Header.SamplingPeriod, NULL);
    DPRINT("ACPIThermalWorker: (%I64X) SamplingPeriod %X\n", Time, Info->Header.SamplingPeriod);

    for (ix = 0; ix < 0xA; ix++)
    {
        Status = ACPIGet(DeviceExtension,
                         ActiveCooling[ix],
                         0x20040002,
                         NULL,
                         0,
                         NULL,
                         0,
                         (PVOID *)&Info->Header.ActiveTripPoint[ix],
                         NULL);

        if (!NT_SUCCESS(Status))
            break;

        DPRINT("ACPIThermalWorker: (%I64X) Active Cooling Level %x = %d.%dK\n",
               Time, ix, (Info->Header.ActiveTripPoint[ix] / 0xA), (Info->Header.ActiveTripPoint[ix] % 0xA));
    }

    Info->Header.ActiveTripPointCount = ix;

    RtlZeroMemory(&Data1, sizeof(Data1));
    RtlZeroMemory(&Data2, sizeof(Data2));

    Info->Header.Processors = 0;

    PslObject = ACPIAmliGetNamedChild(ScopeObject, 'LSP_');
    if (!PslObject)
        goto Finish;

    Status = AMLIEvalNameSpaceObject(PslObject, &Data1, 0, NULL);
    if (!NT_SUCCESS(Status))
        goto Finish;

    PackageObject = Data1.DataBuff;
    Count = PackageObject->Elements;

    for (jx = 0; jx < Count; jx++)
    {
        Status = AMLIEvalPkgDataElement(&Data1, jx, &Data2);
        if (!NT_SUCCESS(Status))
            break;

        Status = AMLIGetNameSpaceObject(Data2.DataBuff, 0, &NsObject, 0);
        AMLIFreeDataBuffs(&Data2, 1);

        if (!NT_SUCCESS(Status))
            break;

        ACPIThermalCalculateProcessorMask(NsObject, &Info->Header);
    }

    AMLIFreeDataBuffs(&Data1, 1);

Finish:

    ACPIThermalLoop(DeviceExtension, 0x40000002);
}

NTSTATUS
NTAPI
ACPIBuildProcessThermalZonePhase0(
    _In_ PACPI_BUILD_REQUEST BuildRequest)
{
    PDEVICE_EXTENSION DeviceExtension;
    PAMLI_NAME_SPACE_OBJECT Child;

    DPRINT("ACPIBuildProcessThermalZonePhase0: %p\n", BuildRequest);

    DeviceExtension = BuildRequest->Context;
    BuildRequest->BuildReserved1 = 0;

    Child = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, 'PMT_');
    DeviceExtension->Thermal.Info->CurrentTemperatureMethod = Child;

    if (!Child)
    {
        DPRINT1("ACPIBuildProcessThermalZonePhase0: !!! KeBugCheckEx()\n", BuildRequest);
        KeBugCheckEx(0xA5, 0xD, (ULONG_PTR)DeviceExtension, 'PMT_', 0);
    }

    ACPIBuildCompleteGeneric(NULL, STATUS_SUCCESS, NULL, BuildRequest);

    DPRINT("ACPIBuildProcessThermalZonePhase0: STATUS_SUCCESS\n");

    return STATUS_SUCCESS;
}

/* Lid FUNCTIOS **************************************************************/

NTSTATUS
NTAPI
ACPICMLidStart(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PAGED_CODE();
    return ACPICMButtonStart(DeviceObject, Irp, 4);
}

NTSTATUS
NTAPI
ACPICMLidSetPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
ACPICMLidWorker(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ ULONG Param2)
{
    ULONG LidState;
    KIRQL Irql;
    NTSTATUS Status;

    Status = ACPIGet(DeviceExtension, 'DIL_', 0x20040002, NULL, 0, NULL, NULL, (PVOID *)&LidState, NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1(" ACPICMLidWorker: Status %X\n", Status);
        return;
    }

    LidState = (LidState ? 1 : 0);

    KeAcquireSpinLock(&DeviceExtension->Button.SpinLock, &Irql);
    DeviceExtension->Button.LidState = (CHAR)LidState;
    KeReleaseSpinLock(&DeviceExtension->Button.SpinLock, Irql);

    if (Param2 & 1)
        ACPIButtonEvent(DeviceExtension->DeviceObject, (LidState ? 0x80000000 : 4), 0);
}

/* Dock Pdo FUNCTIOS ********************************************************/

NTSTATUS
NTAPI
ACPIInitUnicodeString(
    _Out_ UNICODE_STRING* UnicodeString,
    _In_ PCHAR IdString)
{
    ANSI_STRING AnsiId;
    ULONG Length;

    PAGED_CODE();
    DPRINT("ACPIInitUnicodeString: %p\n", UnicodeString);

    ASSERT(UnicodeString->Buffer == NULL);

    RtlInitAnsiString(&AnsiId, IdString);

    if (NlsMbCodePageTag)
        Length = RtlxAnsiStringToUnicodeSize(&AnsiId);
    else
        Length = ((AnsiId.Length + 1) * sizeof(WCHAR));

    if (Length > 0xFFFF)
    {
        DPRINT1("ACPIInitUnicodeString: STATUS_INVALID_PARAMETER_2 (%X)\n", Length);
        return STATUS_INVALID_PARAMETER_2;
    }

    UnicodeString->MaximumLength = Length;

    UnicodeString->Buffer = ExAllocatePoolWithTag(PagedPool, Length, 'SpcA');
    if (!UnicodeString->Buffer)
    {
        DPRINT1("ACPIInitUnicodeString: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return RtlAnsiStringToUnicodeString(UnicodeString, &AnsiId, FALSE);
}

NTSTATUS
ACPIInitMultiString(
    _Out_ UNICODE_STRING* MultiString,
    _In_ ...)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIDockIrpStartDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIDockIrpRemoveDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIDockIrpQueryDeviceRelations(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIDockIrpQueryInterface(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIDockIrpQueryCapabilities(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIDockIrpEject(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIDockIrpSetLock(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIDockIrpQueryID(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DocDeviceExtension;
    PDEVICE_EXTENSION DeviceExtension;
    PIO_STACK_LOCATION IoStack;
    BUS_QUERY_ID_TYPE IdType;
    UNICODE_STRING Id;
    PVOID DataBuff;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ACPIDockIrpQueryID: %p\n", DeviceObject);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    Id.Length = 0;
    Id.MaximumLength = 0;
    Id.Buffer = NULL;

    IdType = IoStack->Parameters.QueryId.IdType;

    if (IdType == BusQueryDeviceID)
    {
        Status = ACPIInitUnicodeString(&Id, DeviceExtension->DeviceID);
    }
    else if (IdType == BusQueryHardwareIDs)
    {
        Status = ACPIInitMultiString(&Id, "ACPI\\DockDevice", DeviceExtension->InstanceID, "ACPI\\DockDevice", NULL);
        if (NT_SUCCESS(Status))
            Id.Buffer[wcslen(Id.Buffer)] = L'&';
    }
    else if (IdType == BusQueryCompatibleIDs)
    {
        Status = STATUS_NOT_SUPPORTED;
    }
    else if (IdType == BusQueryInstanceID)
    {
        Status = ACPIInitUnicodeString(&Id, DeviceExtension->InstanceID);
    }
    else if (IdType == BusQueryDeviceSerialNumber)
    {
        DocDeviceExtension = DeviceExtension->Dock.CorrospondingAcpiDevice;
        if (!DocDeviceExtension)
        {
            DPRINT1("ACPIDockIrpQueryID: no corresponding extension!! (%p, %X)\n", Irp, IdType);
            ASSERT(0);
            Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
            IoCompleteRequest(Irp, 0);
            return Irp->IoStatus.Status;
        }

        Status = ACPIGet(DocDeviceExtension, 'DIU_', 0x00082016, NULL, 0, NULL, NULL, &DataBuff, NULL);
        if (NT_SUCCESS(Status))
            Id.Buffer = DataBuff;
    }
    else
    {
        DPRINT1("ACPIDockIrpQueryID: Unhandled Id (%p, %X)\n", Irp, IdType);
        Status = STATUS_NOT_SUPPORTED;
    }

    if (NT_SUCCESS(Status))
    {
        Irp->IoStatus.Information = (ULONG_PTR)Id.Buffer;
    }
    else
    {
        DPRINT1("ACPIDockIrpQueryID: %p, %X, %X\n", Irp, IdType, Status);
        Irp->IoStatus.Information = 0;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    DPRINT("ACPIDockIrpQueryID: %p, %X, %X\n", Irp, IdType, Status);

    return Status;
}

NTSTATUS
NTAPI
ACPIDockIrpQueryPnpDeviceState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIDockIrpSetPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIDockIrpQueryPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* Processor Device FUNCTIOS ************************************************/

NTSTATUS
NTAPI
ACPIProcessorDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIProcessorStartDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    NTSTATUS Status;

    Status = ACPIInternalSetDeviceInterface(DeviceObject, (LPGUID)&GUID_DEVICE_PROCESSOR);

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

/* Filter Device FUNCTIOS ***************************************************/

NTSTATUS
NTAPI
AcpiRegisterPciRegionSupport(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PACPI_PM_DISPATCH_TABLE HalAcpiDispatchTable = (PVOID)PmHalDispatchTable;
    PDEVICE_EXTENSION DeviceExtension;
    PBUS_INTERFACE_STANDARD Interface;
    ULONG_PTR dummyInformation;
    PCI_COMMON_CONFIG Buffer;
    IO_STACK_LOCATION IoStack;
    ULONG GetBytes;
    NTSTATUS Status;

    DPRINT("AcpiRegisterPciRegionSupport: %p\n", DeviceObject);
    PAGED_CODE();

    RtlZeroMemory(&IoStack, sizeof(IO_STACK_LOCATION));

    DeviceExtension = DeviceObject->DeviceExtension;

    if (DeviceExtension->Filter.Interface)
        return STATUS_SUCCESS;

    Interface = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Interface), 'FpcA');
    if (!Interface)
    {
        DPRINT1("AcpiRegisterPciRegionSupport: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DeviceObject = IoGetAttachedDeviceReference(DeviceExtension->TargetDeviceObject);

    IoStack.MajorFunction = IRP_MJ_PNP;
    IoStack.MinorFunction = IRP_MN_QUERY_INTERFACE;

    IoStack.Parameters.QueryInterface.InterfaceType = &GUID_BUS_INTERFACE_STANDARD;
    IoStack.Parameters.QueryInterface.Size = sizeof(*Interface);
    IoStack.Parameters.QueryInterface.Version = 1;
    IoStack.Parameters.QueryInterface.Interface = (PINTERFACE)Interface;
    IoStack.Parameters.QueryInterface.InterfaceSpecificData = NULL;

    Status = ACPIInternalSendSynchronousIrp(DeviceObject, &IoStack, &dummyInformation);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("AcpiRegisterPciRegionSupport: Status %X\n", Status);
        ExFreePoolWithTag(Interface, 'FpcA');
        goto Exit;
    }

    DeviceExtension->Filter.Interface = Interface;
    DeviceExtension->Filter.Interface->InterfaceReference(DeviceExtension->Filter.Interface->Context);

    GetBytes = Interface->GetBusData(Interface->Context, 0, &Buffer, 0, 0x40);
    ASSERT(GetBytes != 0);

    if ((Buffer.HeaderType & 0x7F) == 1 || (Buffer.HeaderType & 0x7F) == 2)
    {
        if (Buffer.u.type1.SecondaryBus)
            HalAcpiDispatchTable->HalSetMaxLegacyPciBusNumber(Buffer.u.type1.SecondaryBus);
    }

Exit:

    ObDereferenceObject(DeviceObject);
    return Status;
}

VOID
NTAPI
ACPIInitBusInterfaces(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PDEVICE_EXTENSION DeviceExtension;

    DPRINT("ACPIInitBusInterfaces: %p\n", DeviceObject);
    PAGED_CODE();

    DeviceExtension = DeviceObject->DeviceExtension;

    if (IsPciBus(DeviceExtension->ParentExtension->DeviceObject))
        AcpiRegisterPciRegionSupport(DeviceObject);
}

VOID
NTAPI
ACPIWakeInitializePciDevice(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PDEVICE_EXTENSION DeviceExtension;
    BOOLEAN PmeCapable;
    BOOLEAN PmeStatus;
    BOOLEAN PmeEnable;
    KIRQL Irql;

    DPRINT("ACPIWakeInitializePciDevice: %p\n", DeviceObject);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    if (DeviceExtension->Flags & 0x0000000000010000)
    {
        KeAcquireSpinLock(&AcpiPowerLock, &Irql);

        if (PciPmeInterfaceInstantiated)
        {
            PciPmeInterface->GetPmeInformation(DeviceExtension->PhysicalDeviceObject, &PmeCapable, &PmeStatus, &PmeEnable);

            if (PmeCapable)
            {
                ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0800000000000000, 0);

                if (PmeEnable)
                    PciPmeInterface->UpdateEnable(DeviceExtension->PhysicalDeviceObject, FALSE);
                else if (PmeStatus)
                    PciPmeInterface->ClearPmeStatus(DeviceExtension->PhysicalDeviceObject);
            }
        }

        KeReleaseSpinLock(&AcpiPowerLock, Irql);
    }
}

NTSTATUS
NTAPI
ACPIInternalIsPci(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PDEVICE_EXTENSION DeviceExtension;
    ACPI_WAIT_CONTEXT WaitContext;
    BOOLEAN isPciDevice;
    NTSTATUS Status;

    DPRINT("ACPIInternalIsPci: %p\n", DeviceObject);
    PAGED_CODE();

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    if ((DeviceExtension->Flags & 0x0000000002000000) || (DeviceExtension->Flags & 0x0000000100000000))
    {
        return STATUS_SUCCESS;
    }

    if (IsPciBus(DeviceExtension->DeviceObject))
    {
        ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0000000002000000, FALSE);
        return STATUS_SUCCESS;
    }

    WaitContext.Status = STATUS_NOT_FOUND;

    KeInitializeEvent(&WaitContext.Event, SynchronizationEvent, FALSE);

    Status = IsPciDevice(DeviceExtension->AcpiObject, AmlisuppCompletePassive, (PVOID)&WaitContext, &isPciDevice);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&WaitContext.Event, Executive, KernelMode, FALSE, NULL);
        Status = WaitContext.Status;
    }

    if (NT_SUCCESS(Status) && isPciDevice)
        ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0000000100000000, FALSE);

    return Status;
}

VOID
NTAPI
ACPIFilterIrpStartDeviceWorker(
    _In_ PVOID Context)
{
    PWORK_QUEUE_CONTEXT WorkContext = Context;
    PDEVICE_EXTENSION DeviceExtension;
    KEVENT Event;
    NTSTATUS Status;

    DPRINT("ACPIFilterIrpStartDeviceWorker: %p\n", WorkContext);
    PAGED_CODE();

    DeviceExtension = ACPIInternalGetDeviceExtension(WorkContext->DeviceObject);

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(WorkContext->Irp);
    IoSetCompletionRoutine(WorkContext->Irp, ACPIRootIrpCompleteRoutine, &Event, TRUE, TRUE, TRUE);

    Status = IoCallDriver(DeviceExtension->TargetDeviceObject, WorkContext->Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = WorkContext->Irp->IoStatus.Status;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIFilterIrpStartDeviceWorker: Status %X\n", Status);
        IoCompleteRequest(WorkContext->Irp, 0);
        return;
    }

    ACPIInitBusInterfaces(WorkContext->DeviceObject);

    Status = ACPIInternalIsPci(WorkContext->DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIFilterIrpStartDeviceWorker: Status %X\n", Status);
        IoCompleteRequest(WorkContext->Irp, 0);
        return;
    }

    if (DeviceExtension->Flags & 0x0000000002000000)
        EnableDisableRegions(DeviceExtension->AcpiObject, TRUE);

    if (DeviceExtension->Flags & 0x0000000102000000)
        ACPIWakeInitializePciDevice(WorkContext->DeviceObject);

    IoCompleteRequest(WorkContext->Irp, 0);
}

VOID
NTAPI
ACPIFilterIrpStartDeviceCompletion(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID Context,
    _In_ NTSTATUS InStatus)
{
    PIRP Irp = Context;
    PWORK_QUEUE_CONTEXT WorkContext;

    DPRINT("ACPIFilterIrpStartDeviceCompletion: %p, %p\n", DeviceExtension, Context);

    Irp->IoStatus.Status = InStatus;
    WorkContext = &DeviceExtension->Filter.WorkContext;

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT1("ACPIFilterIrpStartDeviceCompletion: InStatus %X\n", InStatus);
        IoCompleteRequest(Irp, 0);
        return;
    }

    DeviceExtension->DeviceState = 2;

    ExInitializeWorkItem(&WorkContext->Item, ACPIFilterIrpStartDeviceWorker, WorkContext);

    WorkContext->DeviceObject = DeviceExtension->DeviceObject;
    WorkContext->Irp = Irp;

    ExQueueWorkItem(&WorkContext->Item, DelayedWorkQueue);
}

NTSTATUS
NTAPI
ACPIFilterIrpStartDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    DPRINT("ACPIFilterIrpStartDevice: %p, %p\n", DeviceObject, Irp);
    PAGED_CODE();

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    Status = ACPIInitStartDevice(DeviceObject, IoStack->Parameters.StartDevice.AllocatedResources, ACPIFilterIrpStartDeviceCompletion, Irp, Irp);
    if (Status >= 0)
        Status = 0x103;

    return Status;
}

/* Filter PNP FUNCTIOS ******************************************************/

NTSTATUS
NTAPI
ACPIFilterIrpRemoveDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIFilterIrpStopDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIFilterIrpQueryDeviceRelations(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    PDEVICE_RELATIONS OutDeviceRelation;
    PIO_STACK_LOCATION IoStack;
    KEVENT Event;
    BOOLEAN IsBusRelation = FALSE;
    NTSTATUS Status;

    DPRINT("ACPIFilterIrpQueryDeviceRelations: %p\n", DeviceObject);
    PAGED_CODE();

    if (!NT_SUCCESS(Irp->IoStatus.Status))
        OutDeviceRelation = NULL;
    else
        OutDeviceRelation = (PVOID)Irp->IoStatus.Information;

    IoStack = Irp->Tail.Overlay.CurrentStackLocation;

    if (IoStack->Parameters.QueryDeviceRelations.Type == 0)
    {
        IsBusRelation = TRUE;
        Status = ACPIRootIrpQueryBusRelations(DeviceObject, Irp, &OutDeviceRelation);
    }
    else if (IoStack->Parameters.QueryDeviceRelations.Type == 1)
    {
        DPRINT("ACPIFilterIrpQueryDeviceRelations: FIXME\n");
        ASSERT(FALSE);
    }
    else
    {
        Status = STATUS_NOT_SUPPORTED;
    }

    if (Status != STATUS_NOT_SUPPORTED)
        Irp->IoStatus.Status = Status;

    DPRINT("ACPIFilterIrpQueryDeviceRelations: %X\n", Status);

    if (NT_SUCCESS(Status))
    {
        Irp->IoStatus.Information = (ULONG_PTR)OutDeviceRelation;
        goto Exit;
    }

    if (Status != STATUS_NOT_SUPPORTED)
        goto Exit;

    KeInitializeEvent(&Event, SynchronizationEvent, 0);

    IoCopyCurrentIrpStackLocationToNext( Irp );
    IoSetCompletionRoutine(Irp, ACPIRootIrpCompleteRoutine, &Event, TRUE, TRUE, TRUE);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    Status = IoCallDriver(DeviceExtension->TargetDeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    if (!NT_SUCCESS(Status) || !IsBusRelation)
    {
        DPRINT1("ACPIFilterIrpQueryDeviceRelations: %X\n", Status);
    }

Exit:

    IoCompleteRequest(Irp, 0);
    return Status;
}

NTSTATUS
NTAPI
ACPIFilterIrpQueryInterface(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    UNICODE_STRING GuidString;
    ULONG_PTR InterfaceSpecificData;
    ULONG InterfaceSize;
    NTSTATUS Status;

    PAGED_CODE();

    IoStack = Irp->Tail.Overlay.CurrentStackLocation;
    InterfaceSpecificData = (ULONG_PTR)IoStack->Parameters.QueryInterface.InterfaceSpecificData;

    Status = RtlStringFromGUID(IoStack->Parameters.QueryInterface.InterfaceType, &GuidString);
    if (NT_SUCCESS(Status))
    {
        DPRINT("ACPIRootIrpQueryInterface: %X, '%wZ'\n", InterfaceSpecificData, &GuidString);
        RtlFreeUnicodeString(&GuidString);
    }

    if (IoStack->Parameters.QueryInterface.InterfaceType == &GUID_ACPI_INTERFACE_STANDARD ||
        (RtlCompareMemory(IoStack->Parameters.QueryInterface.InterfaceType, &GUID_ACPI_INTERFACE_STANDARD, sizeof(GUID)) == sizeof(GUID)))
    {
        if (IoStack->Parameters.QueryInterface.Size <= sizeof(ACPI_INTERFACE_STANDARD))
            InterfaceSize = IoStack->Parameters.QueryInterface.Size;
        else
            InterfaceSize = sizeof(ACPI_INTERFACE_STANDARD);

        RtlCopyMemory(IoStack->Parameters.QueryInterface.Interface, &ACPIInterfaceTable, InterfaceSize);

        if (InterfaceSize > 8) // FIXME
            IoStack->Parameters.QueryInterface.Interface->Context = DeviceObject;

        Irp->IoStatus.Status = 0;
    }
    else if (IoStack->Parameters.QueryInterface.InterfaceType == &GUID_TRANSLATOR_INTERFACE_STANDARD ||
             (RtlCompareMemory(IoStack->Parameters.QueryInterface.InterfaceType, &GUID_TRANSLATOR_INTERFACE_STANDARD, sizeof(GUID)) == sizeof(GUID)))
    {
        if (InterfaceSpecificData == 2 && IsPciBus(DeviceObject))
            SmashInterfaceQuery(Irp);
    }

    return ACPIDispatchForwardIrp(DeviceObject, Irp);
}

VOID
NTAPI
ACPIIrpCompletionRoutineWorker(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PVOID Context)
{
    PACPI_FILTER_COMPLETION_CONTEXT CompletionContext = Context;
    PACPI_IRP_COMPLETION_ROUTINE CallBack = CompletionContext->CallBack;
    PIRP Irp = CompletionContext->Irp;
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status = STATUS_NOT_SUPPORTED;

    DPRINT("ACPIIrpCompletionRoutineWorker: %p\n", DeviceObject);
    PAGED_CODE();

    if (NT_SUCCESS(Irp->IoStatus.Status))
    {
        if (CompletionContext->Param5)
            Status = CallBack(DeviceObject, Irp, CompletionContext->CallBackContext, TRUE);
    }
    else if (Irp->IoStatus.Status == STATUS_NOT_SUPPORTED)
    {
        if (CompletionContext->Param6)
            Status = CallBack(DeviceObject, Irp, CompletionContext->CallBackContext, TRUE);
    }
    else if (CompletionContext->Param7)
    {
        Status = CallBack(DeviceObject, Irp, CompletionContext->CallBackContext, TRUE);
    }
    else if (Irp->Cancel && CompletionContext->Param8)
    {
        Status = CallBack(DeviceObject, Irp, CompletionContext->CallBackContext, TRUE);
    }

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    ACPIInternalDecrementIrpReferenceCount(DeviceExtension);

    IoFreeWorkItem(CompletionContext->WorkItem);
    ExFreePool(CompletionContext);

    if (Status == STATUS_PENDING)
        return;

    if (Status != STATUS_NOT_SUPPORTED)
        Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, 0);
}

NTSTATUS
NTAPI
ACPIIrpGenericFilterCompletionHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PACPI_FILTER_COMPLETION_CONTEXT CompletionContext = Context;

    DPRINT("ACPIIrpGenericFilterCompletionHandler: %p, %p\n", DeviceObject, Irp);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    if (!KeGetCurrentIrql())
    {
        ACPIIrpCompletionRoutineWorker(DeviceObject, Context);
    }
    else
    {
        IoQueueWorkItem(CompletionContext->WorkItem, ACPIIrpCompletionRoutineWorker, DelayedWorkQueue, CompletionContext);
    }

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
ACPIIrpSetPagableCompletionRoutineAndForward(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID CallBack,
    _In_ PVOID CallBackContext,
    _In_ BOOLEAN Param5,
    _In_ BOOLEAN Param6,
    _In_ BOOLEAN Param7,
    _In_ BOOLEAN Param8)
{
    PACPI_FILTER_COMPLETION_CONTEXT CompletionContext;
    PDEVICE_EXTENSION DeviceExtension;
    PIO_WORKITEM WorkItem;

    DPRINT("ACPIIrpSetPagableCompletionRoutineAndForward: %p, %p\n", DeviceObject, Irp);
    PAGED_CODE();

    CompletionContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(ACPI_FILTER_COMPLETION_CONTEXT), 'ipcA');
    if (!CompletionContext)
    {
        DPRINT1("ACPIIrpSetPagableCompletionRoutineAndForward: STATUS_INSUFFICIENT_RESOURCES\n");
        Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        IoCompleteRequest(Irp, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WorkItem = IoAllocateWorkItem(DeviceObject);
    if (!WorkItem)
    {
        DPRINT1("ACPIIrpSetPagableCompletionRoutineAndForward: STATUS_INSUFFICIENT_RESOURCES\n");
        ExFreePoolWithTag(CompletionContext, 'ipcA');
        Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        IoCompleteRequest(Irp, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    CompletionContext->DeviceObject = DeviceObject;
    CompletionContext->Irp = Irp;
    CompletionContext->WorkItem = WorkItem;
    CompletionContext->CallBack = CallBack;
    CompletionContext->CallBackContext = CallBackContext;
    CompletionContext->Param5 = Param5;
    CompletionContext->Param6 = Param6;
    CompletionContext->Param7 = Param7;
    CompletionContext->Param8 = Param8;

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    InterlockedIncrement(&DeviceExtension->OutstandingIrpCount);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, ACPIIrpGenericFilterCompletionHandler, CompletionContext, TRUE, TRUE, TRUE);

    IoMarkIrpPending(Irp);

    IoCallDriver(DeviceExtension->TargetDeviceObject, Irp);

    return STATUS_PENDING;
}

NTSTATUS
NTAPI
ACPIFilterIrpQueryCapabilities(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    DPRINT("ACPIFilterIrpQueryCapabilities: %p\n", DeviceObject);
    PAGED_CODE();
    return ACPIIrpSetPagableCompletionRoutineAndForward(DeviceObject, Irp, ACPIBusAndFilterIrpQueryCapabilities, NULL, TRUE, TRUE, FALSE, FALSE);
}

NTSTATUS
NTAPI
ACPIFilterIrpEject(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIFilterIrpSetLock(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIFilterIrpQueryId(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    PIO_STACK_LOCATION IoStack;
    BUS_QUERY_ID_TYPE IdType;

    DPRINT("ACPIFilterIrpQueryId: %p\n", DeviceObject);
    PAGED_CODE();

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    IoStack = Irp->Tail.Overlay.CurrentStackLocation;

    if (!(DeviceExtension->Flags & 0x0000004000000000))
        return ACPIDispatchForwardIrp(DeviceObject, Irp);

    IdType = IoStack->Parameters.QueryId.IdType;

    if ((IdType != 0 && IdType != 2 && IdType != 1))
        return ACPIDispatchForwardIrp(DeviceObject, Irp);

    return ACPIBusIrpQueryId(DeviceObject, Irp);
}

NTSTATUS
NTAPI
ACPIFilterIrpQueryPnpDeviceState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    DPRINT("ACPIFilterIrpQueryPnpDeviceState: %p\n", DeviceObject);
    PAGED_CODE();

    return ACPIIrpSetPagableCompletionRoutineAndForward(DeviceObject,
                                                        Irp,
                                                        ACPIBusAndFilterIrpQueryPnpDeviceState,
                                                        NULL,
                                                        TRUE,
                                                        TRUE,
                                                        FALSE,
                                                        FALSE);
}
NTSTATUS
NTAPI
ACPIFilterIrpSurpriseRemoval(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* Filter Power FUNCTIOS ****************************************************/

VOID
NTAPI
ACPIDeviceIrpForwardRequest(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID Context,
    _In_ NTSTATUS InStatus)
{
    PIRP Irp = Context;

    DPRINT("ACPIDeviceIrpForwardRequest: %p, %X\n", Irp, InStatus);

    if (NT_SUCCESS(InStatus))
    {
        ACPIDispatchForwardPowerIrp(IoGetCurrentIrpStackLocation(Irp)->DeviceObject, Irp);
        goto Finish;
    }

    PoStartNextPowerIrp(Irp);

    Irp->IoStatus.Status = InStatus;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

Finish:

    ACPIInternalDecrementIrpReferenceCount(DeviceExtension);
}

NTSTATUS
NTAPI
ACPIDeviceIrpDeviceRequest(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID CallBack)
{
    PDEVICE_EXTENSION DeviceExtension;
    PIO_STACK_LOCATION IoStack;
    POWER_ACTION ShutdownType;
    POWER_STATE PowerState;
    BOOLEAN IsShutdown = FALSE;
    NTSTATUS Status;

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    IoStack = Irp->Tail.Overlay.CurrentStackLocation;

    PowerState.SystemState = IoStack->Parameters.Power.State.SystemState;
    ShutdownType = IoStack->Parameters.Power.ShutdownType;

    DPRINT("ACPIDeviceIrpDeviceRequest: %p, %X\n", Irp, (PowerState.SystemState - 1));

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    Status = Irp->IoStatus.Status;

    if (!NT_SUCCESS(Status) && CallBack)
    {
        ((VOID (NTAPI *)(PDEVICE_EXTENSION, PVOID, NTSTATUS))CallBack)(DeviceExtension, Irp, Status);
        return Status;
    }

    if (ShutdownType == PowerActionShutdown ||
        ShutdownType == PowerActionShutdownReset ||
        ShutdownType == PowerActionShutdownOff)
    {
        IsShutdown = TRUE;
    }

    return ACPIDeviceInitializePowerRequest(DeviceExtension,
                                            PowerState,
                                            CallBack,
                                            Irp,
                                            ShutdownType,
                                            AcpiPowerRequestDevice,
                                            (IsShutdown ? 8 : 0));
}

NTSTATUS
NTAPI
ACPIBuildRegRequest(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID CallBack)
{
    PDEVICE_EXTENSION DeviceExtension;
    DEVICE_POWER_STATE DeviceState;
    KIRQL Irql;
    NTSTATUS Status;

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    DeviceState = IoGetCurrentIrpStackLocation(Irp)->Parameters.Power.State.DeviceState;

    DPRINT("ACPIBuildRegRequest: (%p) Handle D%d\n", Irp, (DeviceState - PowerDeviceD0));

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    if (!NT_SUCCESS(Irp->IoStatus.Status))
    {
        if (CallBack)
        {
            UNIMPLEMENTED_DBGBREAK();
        }
    }

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &Irql);

    Status = ACPIBuildRunMethodRequest(DeviceExtension,
                                       CallBack,
                                       Irp,
                                       ULongToPtr('GER_'),
                                       (DeviceState == PowerDeviceD0 ? 0x15 : 0x25),
                                       TRUE);

    KeReleaseSpinLock(&AcpiDeviceTreeLock, Irql);

    if (Status == STATUS_PENDING)
        Status = STATUS_MORE_PROCESSING_REQUIRED;

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildRegOnRequest(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID CallBack)
{
    ACPIBuildRegRequest(DeviceObject, Irp, CallBack);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
ACPIDeviceIrpDeviceFilterRequest(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID CallBack)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_MORE_PROCESSING_REQUIRED;
}

VOID
NTAPI
ACPIDeviceIrpDelayedDeviceOffRequest(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID Context,
    _In_ NTSTATUS InStatus)
{
    PIRP Irp = Context;

    DPRINT("ACPIDeviceIrpDelayedDeviceOffRequest: %p, %X\n", Irp, InStatus);

    if (!NT_SUCCESS(InStatus))
    {
        PoStartNextPowerIrp(Irp);
        Irp->IoStatus.Status = InStatus;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        goto Exit;
    }

    InterlockedIncrement(&DeviceExtension->OutstandingIrpCount);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, ACPIDeviceIrpDeviceFilterRequest, ACPIDeviceIrpCompleteRequest, TRUE, TRUE, TRUE);

    PoStartNextPowerIrp(Irp);

    ASSERT(DeviceExtension->TargetDeviceObject != NULL);
    PoCallDriver(DeviceExtension->TargetDeviceObject, Irp);

Exit:

    ACPIInternalDecrementIrpReferenceCount(DeviceExtension);
}

VOID
NTAPI
ACPIDeviceIrpDelayedDeviceOnRequest(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID Context,
    _In_ NTSTATUS InStatus)
{
    PIRP Irp = Context;

    DPRINT("ACPIDeviceIrpDelayedDeviceOnRequest: %p, %X\n", Irp, InStatus);

    if (!NT_SUCCESS(InStatus))
    {
        PoStartNextPowerIrp(Irp);
        Irp->IoStatus.Status = InStatus;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        goto Exit;
    }

    InterlockedIncrement(&DeviceExtension->OutstandingIrpCount);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, ACPIBuildRegOnRequest, ACPIDeviceIrpCompleteRequest, TRUE, TRUE, TRUE);

    ASSERT(DeviceExtension->TargetDeviceObject != NULL);
    PoCallDriver(DeviceExtension->TargetDeviceObject, Irp);

Exit:

    ACPIInternalDecrementIrpReferenceCount(DeviceExtension);
}

NTSTATUS
NTAPI
ACPIFilterIrpSetPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PAMLI_NAME_SPACE_OBJECT NsObject = NULL;
    PDEVICE_EXTENSION DeviceExtension;
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    DPRINT("ACPIFilterIrpSetPower: %p, %p\n", DeviceObject, Irp);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (IoStack->Parameters.Power.Type == SystemPowerState)
    {
        if (IoStack->Parameters.Power.ShutdownType != PowerActionWarmEject)
            return ACPIDispatchForwardPowerIrp(DeviceObject, Irp);

        UNIMPLEMENTED_DBGBREAK();
    }

    if (!(DeviceExtension->Flags & 0x0008000000000000))
        NsObject = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, 'GER_');

    if (IoStack->Parameters.Power.State.DeviceState == 1)
    {
        IoMarkIrpPending(Irp);

        InterlockedIncrement(&DeviceExtension->OutstandingIrpCount);

        Irp->IoStatus.Status = STATUS_SUCCESS;

        if (!NsObject)
            Status = ACPIDeviceIrpDeviceRequest(DeviceObject, Irp, ACPIDeviceIrpForwardRequest);
        else
            Status = ACPIDeviceIrpDeviceRequest(DeviceObject, Irp, ACPIDeviceIrpDelayedDeviceOnRequest);

        if (Status != STATUS_MORE_PROCESSING_REQUIRED)
            return Status;

        return STATUS_PENDING;
    }

    if (NsObject)
    {
        UNIMPLEMENTED_DBGBREAK();
        return STATUS_PENDING;
    }

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_PENDING;
}

NTSTATUS
NTAPI
ACPIFilterIrpQueryPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* IRP dispatch FUNCTIOS ****************************************************/

ULONG
NTAPI
RtlSizeOfCmResourceList(
    _In_ PCM_RESOURCE_LIST CmResource)
{
    PCM_FULL_RESOURCE_DESCRIPTOR FullList;
    ULONG FinalSize;
    ULONG ix;
    ULONG jx;

    PAGED_CODE();

    FinalSize = sizeof(CM_RESOURCE_LIST);

    for (ix = 0; ix < CmResource->Count; ix++)
    {
        FullList = &CmResource->List[ix];

        if (ix != 0)
            FinalSize += sizeof(CM_FULL_RESOURCE_DESCRIPTOR);

        for (jx = 0; jx < FullList->PartialResourceList.Count; jx++)
        {
            if (jx != 0)
                FinalSize += sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);
        }
    }

    return FinalSize;
}

PCM_RESOURCE_LIST
NTAPI
RtlDuplicateCmResourceList(
    _In_ POOL_TYPE PoolType,
    _In_ PCM_RESOURCE_LIST CmResource,
    _In_ ULONG Tag)
{
    PCM_RESOURCE_LIST OutCmResource;
    ULONG Size;

    PAGED_CODE();
    DPRINT("RtlDuplicateCmResourceList: %X, %p, %X\n", PoolType, CmResource, Tag);

    Size = RtlSizeOfCmResourceList(CmResource);

    OutCmResource = ExAllocatePoolWithTag(PoolType, Size, Tag);
    if (OutCmResource)
        RtlCopyMemory(OutCmResource, CmResource, Size);

    return OutCmResource;
}

PCM_PARTIAL_RESOURCE_DESCRIPTOR
NTAPI
RtlUnpackPartialDesc(
    _In_ UCHAR Type,
    _In_ PCM_RESOURCE_LIST CmResource,
    _Inout_ ULONG* OutStartIndex)
{
    ULONG Index = 0;
    ULONG ix;
    ULONG jx;

    if (OutStartIndex)
    {
        DPRINT("RtlUnpackPartialDesc: %X, %p, %X\n", Type, CmResource, *OutStartIndex);
    }
    else
    {
        DPRINT("RtlUnpackPartialDesc: %X, %p\n", Type, CmResource);
    }

    for (ix = 0; ix < CmResource->Count; ix++)
    {
        for (jx = 0; jx < CmResource->List[ix].PartialResourceList.Count; jx++)
        {
            if (CmResource->List[ix].PartialResourceList.PartialDescriptors[jx].Type == Type)
            {
                if (Index == *OutStartIndex)
                {
                    (*OutStartIndex)++;
                    return &CmResource->List[ix].PartialResourceList.PartialDescriptors[jx];
                }

                Index++;
            }
        }
    }

    return NULL;
}

VOID
NTAPI
ACPIEnablePMInterruptOnly(VOID)
{
    WRITE_PM1_ENABLE(AcpiInformation->pm1_en_bits);
}

VOID
NTAPI
ACPIInterruptDispatchEvents(VOID)
{
    ULONG ix;
    UCHAR GpeStatus;

    KeAcquireSpinLockAtDpcLevel(&GpeTableLock);

    for (ix = 0; ix < AcpiInformation->GpeSize; ix++)
    {
        GpeStatus = (ACPIReadGpeStatusRegister(ix) & GpeCurEnable[ix]);

        GpePending[ix] |= GpeStatus;
        GpeRunMethod[ix] |= GpeStatus;
        GpeCurEnable[ix] &= ~GpeStatus;

        GpeStatus &= ~GpeIsLevel[ix];
        if (GpeStatus)
            ACPIWriteGpeStatusRegister(ix, GpeStatus);
    }

    AcpiGpeWorkDone = TRUE;

    if (!AcpiGpeDpcRunning && !AcpiGpeDpcScheduled)
    {
        AcpiGpeDpcScheduled = TRUE;
        KeInsertQueueDpc(&AcpiGpeDpc, NULL, NULL);
    }

    KeReleaseSpinLockFromDpcLevel(&GpeTableLock);
}

VOID
NTAPI
ACPIInterruptServiceRoutineDPC(
    _In_ PKDPC Dpc,
    _In_ PVOID DeferredContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2)
{
    PDEVICE_EXTENSION DeviceExtension = DeferredContext;
    LONG Pm1Status;
    LONG Comparand;
    LONG Exchange;
    ULONG Event;

    while (TRUE)
    {
        Comparand = DeviceExtension->Fdo.Pm1Status;
        do
        {
            Pm1Status = Comparand;

            if (Comparand & 0x7FFFFFFF)
            {
                Exchange = 0x80000000;
            }
            else
            {
                ACPIEnablePMInterruptOnly();
                Exchange = 0;
            }

            Comparand = InterlockedCompareExchange((PLONG)&DeviceExtension->Fdo.Pm1Status, Exchange, Comparand);
        }
        while (Pm1Status != Comparand);

        if (!Exchange)
            break;

        Event = 0;

        if (Pm1Status & 0x100)
            Event = 1;

        if (Pm1Status & 0x200)
            Event |= 2;

        if (Event)
        {
            if (Pm1Status & 0x8000)
              Event = 0x80000000;

            ACPIButtonEvent(FixedButtonDeviceObject, Event, 0);
        }

        if (Pm1Status & 0x20)
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        if (Pm1Status & 0x10000)
            ACPIInterruptDispatchEvents();
    }
}

ULONG
NTAPI
ACPIIoReadPm1Status(VOID)
{
    ULONG Pm1Status = READ_PM1_STATUS();
    return (Pm1Status & (AcpiInformation->pm1_en_bits | 0x8401));
}

BOOLEAN
NTAPI
ACPIGpeIsEvent(VOID)
{
    ULONG ix = 0;

    if (!AcpiInformation->GpeSize)
        return FALSE;

    while (!(ACPIReadGpeStatusRegister(ix) & GpeCurEnable[ix]))
    {
        ix++;
        if (ix >= AcpiInformation->GpeSize)
            return FALSE;
    }

    return TRUE;
}

BOOLEAN
NTAPI
ACPIInterruptServiceRoutine(
    _In_ PKINTERRUPT Interrupt,
    _In_ PVOID ServiceContext)
{
    PACPI_PM_DISPATCH_TABLE HalAcpiDispatchTable = (PVOID)PmHalDispatchTable;
    PDEVICE_EXTENSION DeviceExtension = ServiceContext;
    ULONG Pm1Status;
    ULONG StatusBits;
    ULONG OldValue;
    ULONG Value;

    Pm1Status = ACPIIoReadPm1Status();

    DPRINT("ACPIInterruptServiceRoutine: %p, %p, %X\n", Interrupt, ServiceContext, Pm1Status);

    if (ACPIGpeIsEvent())
        Pm1Status |= 0x10000;

    if (!(AcpiOverrideAttributes & 0x0100) && !Pm1Status)
        Pm1Status = 0x10000;

    StatusBits = (Pm1Status & 0x11);

    if (StatusBits)
    {
        CLEAR_PM1_STATUS_BITS(StatusBits);

        if (Pm1Status & 1)
            ((VOID (NTAPI *)(VOID))(HalAcpiDispatchTable->HalAcpiTimerInterrupt))();

        Pm1Status &= ~StatusBits;
    }

    if (!Pm1Status)
        return (StatusBits != 0);

    if (!(Pm1Status & (~DeviceExtension->Fdo.Pm1Status)))
        Pm1Status |= 0x10000;

    if (Pm1Status & 0x10000)
        ACPIGpeEnableDisableEvents(FALSE);

    CLEAR_PM1_STATUS_BITS(Pm1Status);

    Pm1Status |= 0x80000000;

    Value = DeviceExtension->Fdo.Pm1Status;
    do
    {
        OldValue = Value;
        Value = InterlockedCompareExchange((PLONG)&DeviceExtension->Fdo.Pm1Status, (OldValue | Pm1Status), OldValue);
    }
    while (OldValue != Value);

    StatusBits |= (Pm1Status & ~Value);

    if (StatusBits & 0x80000000)
        KeInsertQueueDpc(&DeviceExtension->Fdo.InterruptDpc, NULL, NULL);

    return (StatusBits != 0);
}

BOOLEAN
NTAPI
OSInterruptVector(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialDesc;
    PDEVICE_EXTENSION DeviceExtension;
    ULONG StartIndex = 0;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("OSInterruptVector: %p\n", DeviceObject);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    PartialDesc = RtlUnpackPartialDesc(CmResourceTypeInterrupt, DeviceExtension->ResourceList, &StartIndex);
    if (!PartialDesc)
    {
        DPRINT1("OSInterruptVector: Could not find interrupt descriptor\n");
        ASSERT(FALSE);
        KeBugCheckEx(0xA5, 1, (ULONG_PTR)DeviceExtension, (ULONG_PTR)&DeviceExtension->ResourceList->Count, 1);
    }

    KeInitializeDpc(&DeviceExtension->Fdo.InterruptDpc, ACPIInterruptServiceRoutineDPC, DeviceExtension);

    Status = IoConnectInterrupt(&DeviceExtension->Fdo.InterruptObject,
                                ACPIInterruptServiceRoutine,
                                DeviceExtension,
                                NULL,
                                PartialDesc->u.Interrupt.Vector,
                                (KIRQL)PartialDesc->u.Generic.Start.LowPart,
                                (KIRQL)PartialDesc->u.Generic.Start.LowPart,
                                LevelSensitive,
                                CmResourceShareShared,
                                PartialDesc->u.Interrupt.Affinity,
                                FALSE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("OSInterruptVector: Could not connected to interrupt (%X)\n", Status);
        return FALSE;
    }

    ((PHAL_ACPI_TIMER_INIT)(PmHalDispatchTable->Function[0]))(NULL, FALSE);

    return TRUE;
}

/* DDB - Differentiated Definition Block */
NTSTATUS
NTAPI
ACPIInitializeDDB(
    _In_ ULONG Index)
{
    HANDLE Handle = NULL;
    PDSDT Dsdt;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ACPIInitializeDDB: Index %X\n", Index);

    Dsdt = RsdtInformation->Tables[Index].Address;

    DPRINT("ACPIInitializeDDB: FIXME ACPILoadTableCheckSum()\n");

    Status = AMLILoadDDB(Dsdt, &Handle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIInitializeDDB: AMLILoadDDB failed 0x%8x\n", Status);
        ASSERTMSG("ACPIInitializeDDB: AMLILoadDDB failed to load DDB\n", 0);
        KeBugCheckEx(0xA5, 0x11, 8, (ULONG_PTR)Dsdt, Dsdt->Header.CreatorRev);
    }

    RsdtInformation->Tables[Index].Flags |= 2;
    RsdtInformation->Tables[Index].Handle = Handle;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIInitializeDDBs(VOID)
{
    ULONG NumElements;
    ULONG index;
    ULONG ix;
    ULONG Flags;
    NTSTATUS Status;

    PAGED_CODE();

    NumElements = RsdtInformation->NumElements;
    if (!NumElements)
    {
        DPRINT1("ACPInitializeDDBs: No tables found in RSDT\n");
        ASSERTMSG("ACPIInitializeDDBs: No tables found in RSDT\n", NumElements != 0);
        return STATUS_ACPI_INVALID_TABLE;
    }

    index = (NumElements - 1);
    Flags = RsdtInformation->Tables[index].Flags;

    if (!(Flags & 1) || !(Flags & 4))
    {
        DPRINT1("ACPInitializeDDB: DSDT not mapped or loadable\n");

        ASSERTMSG("ACPIInitializeDDB: DSDT not mapped\n", (RsdtInformation->Tables[index].Flags & 1));//RSDTELEMENT_MAPPED
        ASSERTMSG("ACPIInitializeDDB: DSDT not loadable\n", (RsdtInformation->Tables[index].Flags & 4));//RSDTELEMENT_LOADABLE

        return STATUS_ACPI_INVALID_TABLE;
    }

    Status = ACPIInitializeDDB(index);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPInitializeDDBs: Status %X\n", Status);
        return Status;
    }

    if (NumElements == 1)
        return STATUS_SUCCESS;

    ix = 0;
    while (TRUE)
    {
        Flags = RsdtInformation->Tables[ix].Flags;

        if ((Flags & 1) && (Flags & 4))
        {
            Status = ACPIInitializeDDB(ix);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("ACPInitializeDDBs: Status %X\n", Status);
                break;
            }
        }

        ix++;
        if (ix >= index)
            return STATUS_SUCCESS;
    }

    return Status;
}

BOOLEAN
NTAPI
ACPIInitialize(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PRSDT RootSystemDescTable;
    NTSTATUS Status;
    BOOLEAN Result;

    PAGED_CODE();

    Status = ACPIInitializeAMLI();
    if (!NT_SUCCESS(Status))
    {
        ASSERTMSG("ACPIInitialize: AMLI failed initialization\n", NT_SUCCESS(Status));
        KeBugCheckEx(0xA5, 0x11, 0, 0, 0);
    }

    RootSystemDescTable = ACPILoadFindRSDT();
    if (!RootSystemDescTable)
    {
        ASSERTMSG("ACPIInitialize: ACPI RSDT Not Found\n", RootSystemDescTable);
        KeBugCheckEx(0xA5, 0x11, 1, 0, 0);
    }

    DPRINT("ACPIInitalize: ACPI RSDT found at %p \n", RootSystemDescTable);

    ACPIInterfaceTable.Size = sizeof(ACPIInterfaceTable);
    ACPIInterfaceTable.Version = 1;
    ACPIInterfaceTable.Context = DeviceObject;

    ACPIInterfaceTable.InterfaceReference = AcpiNullReference;
    ACPIInterfaceTable.InterfaceDereference = AcpiNullReference;

    ACPIInterfaceTable.GpeConnectVector = ACPIVectorConnect;
    ACPIInterfaceTable.GpeDisconnectVector = ACPIVectorDisconnect;
    ACPIInterfaceTable.GpeEnableEvent = ACPIVectorEnable;
    ACPIInterfaceTable.GpeDisableEvent = ACPIVectorDisable;
    ACPIInterfaceTable.GpeClearStatus = ACPIVectorClear;

    ACPIInterfaceTable.RegisterForDeviceNotifications = ACPIRegisterForDeviceNotifications;
    ACPIInterfaceTable.UnregisterForDeviceNotifications = ACPIUnregisterForDeviceNotifications;

    KeInitializeSpinLock(&NotifyHandlerLock);
    KeInitializeSpinLock(&GpeTableLock);

    RtlZeroMemory(ProcessorList, sizeof(ProcessorList));

    AcpiInformation = ExAllocatePoolWithTag(NonPagedPool, sizeof(*AcpiInformation), 'ipcA');
    if (!AcpiInformation)
    {
        ASSERTMSG("ACPIInitialize: Could not allocate AcpiInformation\n", AcpiInformation);
        KeBugCheckEx(0xA5, 0x11, 2, 0, 0);
    }

    RtlZeroMemory(AcpiInformation, sizeof(*AcpiInformation));

    AcpiInformation->ACPIOnly = TRUE;
    AcpiInformation->RootSystemDescTable = RootSystemDescTable;

    KeInitializeSpinLock(&AcpiInformation->GlobalLockQueueLock);
    InitializeListHead(&AcpiInformation->GlobalLockQueue);

    AcpiInformation->GlobalLockOwnerContext = 0;
    AcpiInformation->GlobalLockOwnerDepth = 0;

    Status = ACPILoadProcessRSDT();
    if (!NT_SUCCESS(Status))
    {
        ASSERTMSG("ACPIInitialize: ACPILoadProcessRSDT Failed\n", NT_SUCCESS(Status));
        KeBugCheckEx(0xA5, 0x11, 3, 0, 0);
    }

    ACPIEnableInitializeACPI(FALSE);

    Status = ACPIInitializeDDBs();
    if (!NT_SUCCESS(Status))
    {
        ASSERTMSG("ACPIInitialize: ACPIInitializeLoadDDBs Failed\n", NT_SUCCESS(Status));
        KeBugCheckEx(0xA5, 0x11, 4, 0, 0);
    }

    Result = OSInterruptVector(DeviceObject);
    if (!Result)
    {
        ASSERTMSG("ACPIInitialize: OSInterruptVector Failed!!\n", Result);
        KeBugCheckEx(0xA5, 0x11, 5, 0, 0);
    }

    DPRINT("ACPIInitialize: FIXME ACPIInitializeKernelTableHandler()\n");

    return TRUE;
}

NTSTATUS
NTAPI
NotifyHalWithMachineStates(VOID)
{
    PACPI_PM_DISPATCH_TABLE HalAcpiDispatchTable = (PVOID)PmHalDispatchTable;
    PAMLI_NAME_SPACE_OBJECT NsObject = NULL;
    PHALP_STATE_DATA StateData = NULL;
    AMLI_OBJECT_DATA DataArgs;
    SYSTEM_POWER_STATE State;
    ULONG ix;
    NTSTATUS Status;

    PAGED_CODE();

    for (ix = 0; ix < 32; ix++)
    {
        if (!ProcessorList[ix])
            break;
    }

    DPRINT("NotifyHalWithMachineStates: Number of processors - %X\n", ix);

    StateData = ExAllocatePoolWithTag(NonPagedPool, (5 * sizeof(*StateData)), 'MpcA');
    if (!StateData)
    {
        DPRINT1("NotifyHalWithMachineStates: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (AcpiOverrideAttributes & 4)
    {
        DPRINT1("NotifyHalWithMachineStates: FIXME\n");
        ASSERT(FALSE);
    }

    AcpiSupportedSystemStates = 0x62;

    State = 2;

    for (ix = 0; ix < 5; ix++, State++)
    {
        if ((State == 2 && (AcpiOverrideAttributes & 0x10)) ||
            (State == 3 && (AcpiOverrideAttributes & 0x20)) ||
            (State == 4 && (AcpiOverrideAttributes & 0x40)))
        {
            DPRINT("NotifyHalWithMachineStates: SleepState '%s' disabled due to override\n", StateName[ix]);
            ASSERT(FALSE);

            continue;
        }

        Status = AMLIGetNameSpaceObject(StateName[ix], NULL, &NsObject, 0);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("NotifyHalWithMachineStates: SleepState '%s' not supported\n", StateName[ix]);
            //ASSERT(FALSE);

            StateData[ix].Data0 = 0;

            DPRINT("NotifyHalWithMachineStates: FIXME ZwPowerInformation(SystemPowerLoggingEntry)\n");
            continue;
        }

        DPRINT("NotifyHalWithMachineStates: FIXME (check override State)\n");

        AcpiSupportedSystemStates |= (1 << State);
        StateData[ix].Data0 = 1;

        AMLIEvalPackageElement(NsObject, 0, &DataArgs);
        StateData[ix].Data1 = (UCHAR)(ULONG)DataArgs.DataValue;
        AMLIFreeDataBuffs(&DataArgs, 1);

        AMLIEvalPackageElement(NsObject, 1, &DataArgs);
        StateData[ix].Data2 = (UCHAR)(ULONG)DataArgs.DataValue;
        AMLIFreeDataBuffs(&DataArgs, 1);
    }

    HalAcpiDispatchTable->HalAcpiMachineStateInit(0, StateData, &InterruptModel);

    ExFreePoolWithTag(StateData, 'MpcA');

    if (!InterruptModel)
        return Status;

    Status = AMLIGetNameSpaceObject("\\_PIC", NULL, &NsObject, 0);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NotifyHalWithMachineStates: Status %X\n", Status);
        return Status;
    }

    RtlZeroMemory(&DataArgs, sizeof(DataArgs));

    DataArgs.DataValue = (PVOID)InterruptModel;
    DataArgs.DataType = 1;

    Status = AMLIEvalNameSpaceObject(NsObject, NULL, 1, &DataArgs);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NotifyHalWithMachineStates: KeBugCheckEx()\n");
        ASSERT(FALSE);
        KeBugCheckEx(0xA5, 0x2001, InterruptModel, Status, (ULONG_PTR)NsObject);
    }

    return Status;
}

NTSTATUS
NTAPI
ACPIInternalRegisterPowerCallBack(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PCALLBACK_FUNCTION CallbackFunction)
{
    PCALLBACK_OBJECT CallbackObject;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING NameString;
    NTSTATUS Status;

    if (DeviceExtension->Flags & 0x4000000000000000)
        return STATUS_SUCCESS;

    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x4000000000000000, FALSE);

    RtlInitUnicodeString( &NameString, L"\\Callback\\PowerState" );

    InitializeObjectAttributes(&ObjectAttributes, &NameString, (OBJ_PERMANENT | OBJ_CASE_INSENSITIVE), NULL, NULL);

    Status = ExCreateCallback(&CallbackObject, &ObjectAttributes, FALSE, TRUE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIInternalRegisterPowerCallBack: Failed to register callback %X", Status);
        ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x4000000000000000, TRUE);
        return STATUS_SUCCESS;
    }

    ExRegisterCallback(CallbackObject, CallbackFunction, DeviceExtension);

    return Status;
}

ULONG
NTAPI
ACPIGpeIndexToByteIndex(
    _In_ ULONG GpeIndex)
{
    if (GpeIndex < AcpiInformation->GP1_Base_Index)
        return GpeIndex;

    return (GpeIndex - AcpiInformation->GP1_Base_Index + AcpiInformation->Gpe0Size);
}

ULONG
NTAPI
ACPIGpeIndexToGpeRegister(
    _In_ ULONG GpeIndex)
{
    if (GpeIndex < AcpiInformation->GP1_Base_Index)
        return (GpeIndex >> 3);

    return (((GpeIndex - AcpiInformation->GP1_Base_Index) >> 3) + AcpiInformation->Gpe0Size);
}

ULONG
NTAPI
ACPIGpeRegisterToGpeIndex(
    _In_ ULONG ix,
    _In_ ULONG Bit)
{
    if (ix < AcpiInformation->Gpe0Size)
        return ((ix << 3) + Bit);

    ix -= AcpiInformation->Gpe0Size;

    return ((ix << 3) + (AcpiInformation->GP1_Base_Index + Bit));
}

VOID
NTAPI
ACPIWakeRemoveDevicesAndUpdate(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PLIST_ENTRY OutList)
{
    PDEVICE_EXTENSION Extension;
    PACPI_POWER_REQUEST Request;
    PLIST_ENTRY Entry;
    PIRP Irp;
    ULONG GpeIndex;
    ULONG Index;
    ULONG Mask;
    ULONG ix;

    DPRINT("ACPIWakeRemoveDevicesAndUpdate: %X, %X", DeviceExtension, OutList);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    KeAcquireSpinLockAtDpcLevel(&GpeTableLock);

    for (ix = 0; ix < AcpiInformation->GpeSize; ix++)
    {
        GpeCurEnable[ix] &= (GpeSpecialHandler[ix] | ~(GpeWakeEnable[ix] | GpeWakeHandler[ix]));
    }

    RtlZeroMemory(GpeWakeEnable, AcpiInformation->GpeSize);

    Entry = AcpiPowerWaitWakeList.Flink;
    while (Entry != &AcpiPowerWaitWakeList)
    {
        Request = CONTAINING_RECORD(Entry, ACPI_POWER_REQUEST, ListEntry);
        Entry = Entry->Flink;

        Extension = Request->DeviceExtension;
        if (Extension == DeviceExtension)
        {
            Irp = Request->Context;
            IoSetCancelRoutine(Irp, NULL);

            RemoveEntryList(&Request->ListEntry);
            InsertTailList(OutList, &Request->ListEntry);

            continue;
        }

        if (Request->u.WaitWakeRequest.SystemPowerState < AcpiMostRecentSleepState)
            continue;

        GpeIndex = Extension->PowerInfo.WakeBit;
        Index = ACPIGpeIndexToByteIndex(GpeIndex);

        if (GpeMap[Index])
        {
            DPRINT("ACPIWakeRemoveDevicesAndUpdate: %X cannot be used as awake pin\n", GpeIndex);
            continue;
        }

        ix = ACPIGpeIndexToGpeRegister(GpeIndex);
        Mask = (1 << ((UCHAR)GpeIndex % 8));

        if (Mask & GpeWakeEnable[ix])
            continue;

        GpeWakeEnable[ix] |= Mask;
        ACPIWriteGpeStatusRegister(ix, Mask);

        if ((Mask & GpeEnable[ix]) && !(Mask & GpeSpecialHandler[ix]))
        {
            GpeWakeHandler[ix] |= Mask;
            continue;
        }

        if (Mask & GpeCurEnable[ix])
            continue;

        GpeIsLevel[ix] |= Mask;
        GpeCurEnable[ix] |= Mask;
    }

    for (ix = 0; ix < AcpiInformation->GpeSize; ix++)
    {
        if (AcpiPowerLeavingS0)
            GpeCurEnable[ix] &= ~GpeWakeEnable[ix];
        else
            GpeCurEnable[ix] |= (GpeWakeEnable[ix] & ~GpePending[ix]);

        ACPIWriteGpeEnableRegister(ix, GpeCurEnable[ix]);
    }

    KeReleaseSpinLockFromDpcLevel(&GpeTableLock);
}

VOID
NTAPI
ACPIRootPowerCallBack(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2)
{
    KIRQL Irql;

    DPRINT("ACPIRootPowerCallBack: %X, %X", Argument1, Argument2);

    if ((ULONG_PTR)Argument1 != 3)
        return;

    KeAcquireSpinLock(&GpeTableLock, &Irql);
    AcpiPowerLeavingS0 = ((ULONG_PTR)Argument2 != 1);
    KeReleaseSpinLock(&GpeTableLock, Irql);

    IoAcquireCancelSpinLock(&Irql);

    KeAcquireSpinLockAtDpcLevel(&AcpiPowerLock);
    ACPIWakeRemoveDevicesAndUpdate(NULL, NULL);
    KeReleaseSpinLockFromDpcLevel(&AcpiPowerLock);

    IoReleaseCancelSpinLock(Irql);

    if (!Argument2)
    {
        KeAcquireSpinLock(&gdwGContextSpinLock, &Irql);
        gdwcCTObjsMax = 0;
        KeReleaseSpinLock(&gdwGContextSpinLock, Irql);
        return;
    }

    DPRINT1("ACPIRootPowerCallBack: FIXME");
    ASSERT(FALSE);
}

NTSTATUS
NTAPI
ACPIInitStartACPI(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PDEVICE_EXTENSION DeviceExtension;
    KEVENT Event;
    KIRQL DeviceTreeIrql;
    KIRQL PowerQueueIrql;
    NTSTATUS Status;

    DPRINT("ACPIInitStartACPI: DeviceObject %p\n", DeviceObject);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &DeviceTreeIrql);
    AcpiSystemInitialized = FALSE;
    KeReleaseSpinLock(&AcpiDeviceTreeLock, DeviceTreeIrql);

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    Status = ACPIBuildSynchronizationRequest(DeviceExtension, ACPIDevicePowerNotifyEvent, &Event, &AcpiBuildDeviceList, FALSE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("ACPIInitStartACPI: Status %X\n", Status);
        return Status;
    }

    if (!ACPIInitialize(DeviceObject))
    {
        DPRINT1("ACPIInitStartACPI: STATUS_DEVICE_DOES_NOT_EXIST\n");
        return STATUS_DEVICE_DOES_NOT_EXIST;
    }

    DPRINT("ACPIInitStartACPI: Status %X\n", Status);

    if (Status == STATUS_PENDING)
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

    DPRINT("ACPIInitStartACPI: Status %X\n", Status);

    NotifyHalWithMachineStates();

    ACPIInternalRegisterPowerCallBack(DeviceExtension, ACPIRootPowerCallBack);

    KeAcquireSpinLock(&AcpiPowerQueueLock, &PowerQueueIrql);
    if (!AcpiPowerDpcRunning)
        KeInsertQueueDpc(&AcpiPowerDpc, NULL, NULL);
    KeReleaseSpinLock(&AcpiPowerQueueLock, PowerQueueIrql);

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &DeviceTreeIrql);
    AcpiSystemInitialized = TRUE;
    KeReleaseSpinLock(&AcpiDeviceTreeLock, DeviceTreeIrql);

    AcpiInitIrqArbiter(DeviceObject);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIRootIrpStartDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    PCM_RESOURCE_LIST CmTranslated;
    PIO_STACK_LOCATION IoStack;
    KEVENT Event;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ACPIRootIrpStartDevice: %p, %p\n", DeviceObject, Irp);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, ACPIRootIrpCompleteRoutine, &Event, TRUE, TRUE, TRUE);

    Status = IoCallDriver(DeviceExtension->TargetDeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    IoStack = Irp->Tail.Overlay.CurrentStackLocation;

    if (NT_SUCCESS(Status))
    {
        CmTranslated = IoStack->Parameters.StartDevice.AllocatedResourcesTranslated;
        if (CmTranslated)
            CmTranslated = RtlDuplicateCmResourceList(NonPagedPool, CmTranslated, 'RpcA');

        DeviceExtension->ResourceList = CmTranslated;
        if (!DeviceExtension->ResourceList)
        {
            DPRINT1("ACPIRootIrpStartDevice: Did not find a resource list! KeBugCheckEx()\n");
            ASSERT(FALSE);
            KeBugCheckEx(0xA5, 1, (ULONG_PTR)DeviceExtension, 0, 0);
        }

        Status = ACPIInitStartACPI(DeviceObject);
        if (NT_SUCCESS(Status))
            DeviceExtension->DeviceState = Started;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

PAMLI_NAME_SPACE_OBJECT
NTAPI
OSConvertDeviceHandleToPNSOBJ(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PDEVICE_EXTENSION DeviceExtension;

    if (!DeviceObject)
    {
        ASSERT(DeviceObject != NULL);
        return NULL;
    }

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    if (!DeviceExtension)
    {
        ASSERT(DeviceExtension != NULL);
        return NULL;
    }

    return DeviceExtension->AcpiObject;
}

NTSTATUS
NTAPI
ACPIIoctlEvalPreProcessing(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack,
    _In_ POOL_TYPE PoolType,
    _Out_ PAMLI_NAME_SPACE_OBJECT* OutNsObject,
    _Out_ PAMLI_OBJECT_DATA* OutDataResult,
    _Out_ PAMLI_OBJECT_DATA* OutDataArgs,
    _Out_ ULONG* OutArgsCount)
{
    PACPI_EVAL_INPUT_BUFFER InBuffer;
    PAMLI_NAME_SPACE_OBJECT ScopeNsObject;
    PAMLI_NAME_SPACE_OBJECT NsObject;
    PAMLI_OBJECT_DATA DataArgs = NULL;
    PAMLI_OBJECT_DATA DataResult = NULL;
    CHAR ObjPath[8];
    ULONG ArgsCount = 0;
    ULONG InBufferLength;
    ULONG OutBufferLength;
    NTSTATUS Status;

    DPRINT("ACPIIoctlEvalPreProcessing: %p, %p\n", DeviceObject, Irp);

    InBufferLength = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    OutBufferLength = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    Irp->IoStatus.Information = 0;

    if (InBufferLength < sizeof(ACPI_EVAL_INPUT_BUFFER))
    {
        DPRINT1("ACPIIoctlEvalPreProcessing: STATUS_INFO_LENGTH_MISMATCH. InBufferLength %X\n", InBufferLength);
        ASSERT(FALSE);
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (OutBufferLength && OutBufferLength < sizeof(ACPI_EVAL_OUTPUT_BUFFER))
    {
        DPRINT1("ACPIIoctlEvalPreProcessing: STATUS_INFO_LENGTH_MISMATCH. OutBufferLength %X\n", OutBufferLength);
        ASSERT(FALSE);
        return STATUS_BUFFER_TOO_SMALL;
    }

    InBuffer = Irp->AssociatedIrp.SystemBuffer;

    RtlZeroMemory(ObjPath, sizeof(ObjPath));

    ASSERT(sizeof(InBuffer->MethodName) <= sizeof(ObjPath));
    RtlCopyMemory(ObjPath, InBuffer->MethodName, sizeof(InBuffer->MethodName));

    ScopeNsObject = OSConvertDeviceHandleToPNSOBJ(DeviceObject);
    if (!ScopeNsObject)
    {
        DPRINT("ACPIIoctlEvalPreProcessing: STATUS_NO_SUCH_DEVICE\n");
        ASSERT(FALSE);
        return STATUS_NO_SUCH_DEVICE;
    }

    Status = AMLIGetNameSpaceObject(ObjPath, ScopeNsObject, &NsObject, 1);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("ACPIIoctlEvalPreProcessing: Status %X\n", Status);
        return Status;
    }

    DataResult = ExAllocatePoolWithTag(PoolType, sizeof(*DataResult), 'RcpA');
    if (!DataResult)
    {
        DPRINT("ACPIIoctlEvalPreProcessing: STATUS_INSUFFICIENT_RESOURCES\n");
        ASSERT(FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (InBuffer->Signature == 'BieA')
        goto Exit;

    if (InBuffer->Signature == 'CieA')
    {
        DPRINT1("ACPIIoctlEvalPreProcessing: FIXME\n");
        ASSERT(FALSE);
        goto Exit;
    }

    if (InBuffer->Signature != 'IieA' &&
        InBuffer->Signature != 'SieA')
    {
        DPRINT("ACPIIoctlEvalPreProcessing: Unknown signature %X\n", InBuffer->Signature);
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER_1;
    }

    DPRINT1("ACPIIoctlEvalPreProcessing: FIXME\n");
    ASSERT(FALSE);

Exit:

    *OutNsObject = NsObject;
    *OutDataResult = DataResult;
    *OutDataArgs = DataArgs;
    *OutArgsCount = ArgsCount;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIIoctlCalculateOutputBufferSize(
    _In_ PAMLI_OBJECT_DATA DataResult,
    _Out_ PULONG OutLength,
    _Out_ PULONG OutCount,
    _In_ BOOLEAN IsAllowSelfCall)
{
    PAMLI_PACKAGE_OBJECT PackageObject;
    ULONG Length;
    ULONG dummy;
    ULONG ix;
    NTSTATUS Status;

    DPRINT1("ACPIIoctlCalculateOutputBufferSize: %p (%X), %X\n", DataResult, DataResult->DataType, IsAllowSelfCall);

    if (DataResult->DataType == 0)
    {
        Length = 0;
        *OutCount = 1;
        goto Exit;
    }

    if (DataResult->DataType == 1)
    {
        Length = 8;
        *OutCount = 1;
        goto Exit;
    }

    if (DataResult->DataType == 2 || DataResult->DataType == 3)
    {
        Length = (DataResult->DataLen + 4);
        *OutCount = 1;
        goto Exit;
    }

    if (DataResult->DataType != 4)
    {
        DPRINT1("ACPIIoctlCalculateOutputBufferSize: %p (%X), %X\n", DataResult, DataResult->DataType, IsAllowSelfCall);
        ASSERT(FALSE);
        return STATUS_ACPI_INVALID_DATA;
    }

    // DataResult->DataType == 4 (OBJTYPE_PKGDATA)

    PackageObject = DataResult->DataBuff;

    if (!IsAllowSelfCall)
    {
        Length = 4;
        *OutCount = 1;
    }
    else
    {
        Length = 0;
        *OutCount = PackageObject->Elements;
    }

    for (ix = 0; ix < PackageObject->Elements; ix++)
    {
        Status = ACPIIoctlCalculateOutputBufferSize(&PackageObject->Data[ix], OutLength, &dummy, FALSE);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ACPIIoctlCalculateOutputBufferSize: %p (%X), %X\n", DataResult, DataResult->DataType, IsAllowSelfCall);
            ASSERT(FALSE);
            return Status;
        }
    }

Exit:

    ASSERT(OutLength && OutCount);

    *OutLength += Length;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIIoctlCalculateOutputBuffer(
    _In_ PAMLI_OBJECT_DATA DataResult,
    _In_ PACPI_METHOD_ARGUMENT Argument,
    _In_ BOOLEAN IsAllowSelfCall)
{
    PAMLI_PACKAGE_OBJECT PackageObject;
    PAMLI_OBJECT_DATA Data;
    ULONG Length = 0;
    ULONG Count = 0;
    ULONG ix;
    NTSTATUS Status;

    DPRINT1("ACPIIoctlCalculateOutputBuffer: %p (%X), %X\n", DataResult, DataResult->DataType, IsAllowSelfCall);

    ASSERT(Argument);

    if (DataResult->DataType == 1)
    {
        Argument->Type = 0;
        Argument->DataLength = 4;
        Argument->Argument = (ULONG)DataResult->DataValue;
    }
    else if (DataResult->DataType == 2 || DataResult->DataType == 3)
    {
        DPRINT1("ACPIIoctlCalculateOutputBuffer: FIXME\n");
        ASSERT(FALSE);
    }
    else if (DataResult->DataType == 4)
    {
        PackageObject = DataResult->DataBuff;

        Status = ACPIIoctlCalculateOutputBufferSize(DataResult, &Length, &Count, TRUE);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }

        ASSERT(Count == PackageObject->Elements);

        if (!IsAllowSelfCall)
        {
            Argument->Type = 3;
            Argument->DataLength = (USHORT)Length;
            Argument = Add2Ptr(Argument, FIELD_OFFSET(ACPI_METHOD_ARGUMENT, Argument));
        }

        for (ix = 0; ix < PackageObject->Elements; ix++)
        {
            Data = &PackageObject->Data[ix];

            Status = ACPIIoctlCalculateOutputBuffer(Data, Argument, FALSE);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("ACPIIoctlCalculateOutputBuffer: %p (%X), %X\n", DataResult, DataResult->DataType, IsAllowSelfCall);
                ASSERT(FALSE);
                return Status;
            }

            Argument = ACPI_METHOD_NEXT_ARGUMENT(Argument);
        }
    }
    else
    {
        DPRINT1("ACPIIoctlCalculateOutputBuffer: %p (%X), %X\n", DataResult, DataResult->DataType, IsAllowSelfCall);
        ASSERT(FALSE);
        return STATUS_ACPI_INVALID_DATA;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIIoctlEvalPostProcessing(
    _In_ PIRP Irp,
    _In_ PAMLI_OBJECT_DATA DataResult)
{
    PACPI_EVAL_OUTPUT_BUFFER EvalBuffer;
    PACPI_METHOD_ARGUMENT Argument;
    ULONG BufferLength;
    ULONG Length = 0;
    ULONG Count = 0;
    NTSTATUS Status;

    DPRINT1("ACPIIoctlEvalPostProcessing: %p, %p\n", Irp, DataResult);

    BufferLength = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.OutputBufferLength;
    if (!BufferLength)
    {
        Irp->IoStatus.Information = 0;
        return STATUS_SUCCESS;
    }

    Length = 0;
    Count = 0;

    Status = ACPIIoctlCalculateOutputBufferSize(DataResult, &Length, &Count, TRUE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIIoctlEvalPostProcessing: Status %X\n", Status);
        Irp->IoStatus.Information = 0;
        return STATUS_SUCCESS;
    }

    Length += 0xC; // FIXME

    if (Length < sizeof(ACPI_EVAL_OUTPUT_BUFFER))
        Length = sizeof(ACPI_EVAL_OUTPUT_BUFFER);

    if (BufferLength >= sizeof(ACPI_EVAL_OUTPUT_BUFFER))
    {
        EvalBuffer = Irp->AssociatedIrp.SystemBuffer;

        EvalBuffer->Signature = 'BoeA';
        EvalBuffer->Length = Length;
        EvalBuffer->Count = Count;

        Argument = EvalBuffer->Argument;
    }

    if (Length > BufferLength)
    {
        DPRINT1("ACPIIoctlEvalPostProcessing: STATUS_BUFFER_OVERFLOW\n");
        Irp->IoStatus.Information = sizeof(ACPI_EVAL_OUTPUT_BUFFER);
        return STATUS_BUFFER_OVERFLOW;
    }

    Irp->IoStatus.Information = Length;

    Status = ACPIIoctlCalculateOutputBuffer(DataResult, Argument, TRUE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIIoctlEvalPostProcessing: Status %X\n", Status);
        Irp->IoStatus.Information = 0;
        return STATUS_SUCCESS;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIIoctlEvalControlMethod(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStack)
{
    PAMLI_NAME_SPACE_OBJECT NsObject;
    PAMLI_OBJECT_DATA DataResult = NULL;
    PAMLI_OBJECT_DATA DataArgs = NULL;
    ULONG ArgsCount = 0;
    NTSTATUS Status;

    DPRINT("ACPIIoctlEvalControlMethod: %p, %p, %p\n", DeviceObject, Irp, IoStack->Parameters.DeviceIoControl.IoControlCode);

    Status = ACPIIoctlEvalPreProcessing(DeviceObject, Irp, IoStack, PagedPool, &NsObject, &DataResult, &DataArgs, &ArgsCount);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("ACPIIoctlEvalControlMethod: Status %X\n", Status);
        goto Exit;
    }

    Status = AMLIEvalNameSpaceObject(NsObject, DataResult, ArgsCount, DataArgs);

    if (DataArgs)
        ExFreePool(DataArgs);

    if (NT_SUCCESS(Status))
    {
        Status = ACPIIoctlEvalPostProcessing(Irp, DataResult);
        AMLIFreeDataBuffs(DataResult, 1);
    }

Exit:

    if (DataResult)
        ExFreePool(DataResult);

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
ACPIIrpDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    DPRINT("ACPIIrpDispatchDeviceControl: %p, %p, %X\n", DeviceObject, Irp, IoStack->Parameters.DeviceIoControl.IoControlCode);

    if (Irp->RequestorMode != KernelMode)
        return ACPIDispatchForwardIrp(DeviceObject, Irp);

    switch (IoStack->Parameters.DeviceIoControl.IoControlCode)
    {
        case 0x32C000:
            DPRINT1("ACPIIrpDispatchDeviceControl: FIXME\n");
            ASSERT(FALSE);
            break;

        case 0x32C004:
            Status = ACPIIoctlEvalControlMethod(DeviceObject, Irp, IoStack);
            break;

        case 0x32C008:
            DPRINT1("ACPIIrpDispatchDeviceControl: FIXME\n");
            ASSERT(FALSE);
            break;

        case 0x32C00C:
            DPRINT1("ACPIIrpDispatchDeviceControl: FIXME\n");
            ASSERT(FALSE);
            break;

        case 0x32C010:
            DPRINT1("ACPIIrpDispatchDeviceControl: FIXME\n");
            ASSERT(FALSE);
            break;

        case 0x32C014:
            DPRINT1("ACPIIrpDispatchDeviceControl: FIXME\n");
            ASSERT(FALSE);
            break;

        default:
            return ACPIDispatchForwardIrp(DeviceObject, Irp);
    }

    return Status;
}

NTSTATUS
NTAPI
ACPIDispatchForwardIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    PDEVICE_OBJECT TargetDeviceObject;
    PIO_STACK_LOCATION IoStack;
    UCHAR MajorFunction;
    NTSTATUS Status;

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    MajorFunction = IoStack->MajorFunction;

    DPRINT("ACPIDispatchForwardIrp: %p, %p, (%X:%X)\n", DeviceObject, Irp, MajorFunction, IoStack->MinorFunction);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    TargetDeviceObject = DeviceExtension->TargetDeviceObject;
    if (TargetDeviceObject)
    {
        IoSkipCurrentIrpStackLocation(Irp);
        Status = IoCallDriver(TargetDeviceObject, Irp);
        return Status;
    }

    ASSERT(MajorFunction == IRP_MJ_PNP ||
           MajorFunction == IRP_MJ_DEVICE_CONTROL ||
           MajorFunction == IRP_MJ_SYSTEM_CONTROL);

    Status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
ACPIDispatchIrpSuccess(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, 0);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIDispatchWmiLog(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ACPIDispatchIrpInvalid(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
    IoCompleteRequest(Irp, 0);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PnpiCmResourceToBiosIoPort(
    _In_ PVOID Data,
    _In_ PCM_RESOURCE_LIST CmResources)
{
    PACPI_IO_PORT_DESCRIPTOR AcpiDesc = Data;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    ULONG ix;

    PAGED_CODE();
    DPRINT1("PnpiCmResourceToBiosIoPort: %p, %X\n", Data, CmResources);

    ASSERT((AcpiDesc->Tag & 7) == 7);//SMALL_TAG_SIZE_MASK
    ASSERT(CmResources->Count == 1);

    if (!CmResources->List[0].PartialResourceList.Count)
    {
        ASSERT(CmResources->List[0].PartialResourceList.Count);
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(AcpiDesc, sizeof(*AcpiDesc));

    CmDescriptor = &CmResources->List[0].PartialResourceList.PartialDescriptors[0];

    for (ix = 0; ix < CmResources->List[0].PartialResourceList.Count; ix++)
    {
        if (CmDescriptor[ix].Type == CmResourceTypePort)
        {
            AcpiDesc->Maximum = AcpiDesc->Minimum = CmDescriptor[ix].u.Port.Start.LowPart;
            AcpiDesc->RangeLength = CmDescriptor[ix].u.Port.Length;
            AcpiDesc->Alignment = 1;

            if (CmDescriptor[ix].Flags & CM_RESOURCE_PORT_16_BIT_DECODE)
                AcpiDesc->DecodingBitness = 1;//The logical device decodes 16-bit addresses
            else
                AcpiDesc->DecodingBitness = 0;//The logical device only decodes address bits[9:0]

            CmDescriptor[ix].Type = CmResourceTypeNull;
            break;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PnpiCmResourceToBiosIrq(
    _In_ PVOID Data,
    _In_ PCM_RESOURCE_LIST CmResources)
{
    PACPI_IRQ_DESCRIPTOR AcpiDesc = Data;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    ULONG ix;

    PAGED_CODE();
    DPRINT1("PnpiCmResourceToBiosIrq: %p, %X\n", Data, CmResources);

    ASSERT((AcpiDesc->Tag & 7) >= 2);//SMALL_TAG_SIZE_MASK
    ASSERT(CmResources->Count == 1);

    if (!CmResources->List[0].PartialResourceList.Count)
    {
        ASSERT(CmResources->List[0].PartialResourceList.Count);
        return STATUS_SUCCESS;
    }

    AcpiDesc->IrqMask = 0;

    CmDescriptor = &CmResources->List[0].PartialResourceList.PartialDescriptors[0];

    for (ix = 0; ix < CmResources->List[0].PartialResourceList.Count; ix++)
    {
        if (CmDescriptor[ix].Type == CmResourceTypeInterrupt &&
            CmDescriptor[ix].u.Interrupt.Level < 0x10)
        {
            AcpiDesc->IrqMask = (1 << CmDescriptor[ix].u.Interrupt.Level);

            if ((AcpiDesc->Tag & 7) == 3)
            {
                if (CmDescriptor[ix].Flags & CM_RESOURCE_INTERRUPT_LATCHED)
                {
                    AcpiDesc->IntMode = 1;
                    AcpiDesc->IntPolarity = 0;
                }
                else
                {
                    AcpiDesc->IntMode = 0;
                    AcpiDesc->IntPolarity = 1;
                }

                if (CmDescriptor[ix].ShareDisposition == CmResourceShareShared)
                    AcpiDesc->IntSharable = 1;
                else
                    AcpiDesc->IntSharable = 0;

                AcpiDesc->Reserved0 = 0;
                AcpiDesc->Reserved1 = 0;
            }

            CmDescriptor[ix].Type = CmResourceTypeNull;
            break;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PnpiCmResourceToBiosDma(
    _In_ PVOID Data,
    _In_ PCM_RESOURCE_LIST CmResources)
{
    PACPI_DMA_DESCRIPTOR AcpiDesc = Data;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    ULONG ix;

    PAGED_CODE();
    DPRINT1("PnpiCmResourceToBiosDma: %p, %X\n", Data, CmResources);

    ASSERT((AcpiDesc->Tag & 7) == 2);//SMALL_TAG_SIZE_MASK
    ASSERT(CmResources->Count == 1);

    if (!CmResources->List[0].PartialResourceList.Count)
    {
        ASSERT(CmResources->List[0].PartialResourceList.Count);
        return STATUS_SUCCESS;
    }

    AcpiDesc->ChannelMask = 0;

    CmDescriptor = &CmResources->List[0].PartialResourceList.PartialDescriptors[0];

    for (ix = 0; ix < CmResources->List[0].PartialResourceList.Count; ix++)
    {
        if (CmDescriptor[ix].Type == CmResourceTypeDma)
        {
            AcpiDesc->TransferType = 0;
            AcpiDesc->IsBusMaster = 0;
            AcpiDesc->NotUsed = 0;
            AcpiDesc->SpeedSupported = 0;
            AcpiDesc->Reserved = 0;

            AcpiDesc->ChannelMask = (1 << CmDescriptor->u.Dma.Channel);

            if (CmDescriptor->Flags & CM_RESOURCE_DMA_8_AND_16)
                AcpiDesc->TransferType = 1;
            else if (CmDescriptor->Flags & CM_RESOURCE_DMA_16)
                AcpiDesc->TransferType = 2;
            else if (CmDescriptor->Flags & CM_RESOURCE_DMA_32)
                AcpiDesc->TransferType = 3;

            if (CmDescriptor->Flags & CM_RESOURCE_DMA_BUS_MASTER)
                AcpiDesc->IsBusMaster |= 4;

            if (CmDescriptor->Flags & CM_RESOURCE_DMA_TYPE_A)
                AcpiDesc->SpeedSupported = 1;
            else if (CmDescriptor->Flags & CM_RESOURCE_DMA_TYPE_B)
                AcpiDesc->SpeedSupported = 2;
            else if (CmDescriptor->Flags & CM_RESOURCE_DMA_TYPE_F)
                AcpiDesc->SpeedSupported = 3;

            CmDescriptor[ix].Type = CmResourceTypeNull;
            break;
        }
    }

    return STATUS_SUCCESS;
}

BOOLEAN
NTAPI
PnpiCmResourceValidEmptyList(
    _In_ PCM_RESOURCE_LIST CmResources)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    ULONG ix;

    PAGED_CODE();
    DPRINT("PnpiCmResourceValidEmptyList: %p\n", CmResources);

    ASSERT(CmResources->Count == 1);

    if (!CmResources->List[0].PartialResourceList.Count)
    {
        ASSERT(CmResources->List[0].PartialResourceList.Count);
        return STATUS_SUCCESS;
    }

    CmDescriptor = &CmResources->List[0].PartialResourceList.PartialDescriptors[0];

    for (ix = 0; ix < CmResources->List[0].PartialResourceList.Count; ix++)
    {
        if (CmDescriptor[ix].Type == CmResourceTypeNull)
            break;
    }

    if (ix == CmResources->List[0].PartialResourceList.Count)
    {
        DPRINT1("PnpiCmResourceValidEmptyList: %X, %X\n", ix, CmResources->List[0].PartialResourceList.Count);
        RosDumpCmResources(CmResources, 0);
      
    }
    return (ix == CmResources->List[0].PartialResourceList.Count);
}

NTSTATUS
NTAPI
PnpCmResourcesToBiosResources(
    _In_ PCM_RESOURCE_LIST CmResources,
    _In_ PVOID Data)
{
    PACPI_RESOURCE_DATA_TYPE ResDataType;
    ULONG Increment;
    UCHAR TagName;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT1("PnpCmResourcesToBiosResources: %p, %X\n", CmResources, Data);

    ASSERT(Data != NULL);

    for (ResDataType = Data; ; )
    {
        if (!ResDataType->Small.Type)
        {
            Increment = (ResDataType->Small.Length + 1);
            TagName = ResDataType->Small.Name;
            DPRINT1("PnpCmResourcesToBiosResources: Small TagName %X, Increment %X\n", TagName, Increment);
        }
        else
        {
            Increment = (ResDataType->Large.Length + 3);
            TagName = ResDataType->Large.Name;
            DPRINT1("PnpCmResourcesToBiosResources: Large TagName %X, Increment %X\n", TagName, Increment);
        }

        if ((ResDataType->Small.Tag & 0xF8) == 0x78)
        {
            DPRINT1("PnpCmResourcesToBiosResources: TAG_END\n");
            break;
        }

        if (!ResDataType->Small.Type)
        {
            switch (TagName)
            {
                case 0x04:
                {
                    Status = PnpiCmResourceToBiosIrq(Data, CmResources);
                    DPRINT1("PnpCmResourcesToBiosResources: TAG_IRQ, Status %X\n", Status);
                    break;
                }
                case 0x05:
                {
                    Status = PnpiCmResourceToBiosDma(Data, CmResources);
                    DPRINT1("PnpCmResourcesToBiosResources: TAG_DMA, Status %X\n", Status);
                    break;
                }
                case 0x06:
                {
                    DPRINT1("PnpCmResourcesToBiosResources: TAG_START_DEPEND(TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x07:
                {
                    DPRINT1("PnpCmResourcesToBiosResources: TAG_END_DEPEND(TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x08:
                {
                    Status = PnpiCmResourceToBiosIoPort(Data, CmResources);
                    DPRINT1("PnpCmResourcesToBiosResources: TAG_IO, Status %X\n", Status);
                    break;
                }
                case 0x09:
                {
                    DPRINT1("PnpCmResourcesToBiosResources: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x0E:
                {
                    DPRINT1("PnpCmResourcesToBiosResources: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                default:
                {
                    DPRINT1("PnpCmResourcesToBiosResources: Unsupported TagName %X\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
            }
        }
        else
        {
            switch (TagName)
            {
                case 0x01:
                {
                    DPRINT1("PnpCmResourcesToBiosResources: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x02:
                {
                    DPRINT1("PnpCmResourcesToBiosResources: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x03:
                {
                    DPRINT1("PnpCmResourcesToBiosResources: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x04:
                {
                    DPRINT1("PnpCmResourcesToBiosResources: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x05:
                {
                    DPRINT1("PnpCmResourcesToBiosResources: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x06:
                {
                    DPRINT1("PnpCmResourcesToBiosResources: TAG_MEMORY(TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x07:
                {
                    DPRINT1("PnpCmResourcesToBiosResources: TAG_DOUBLE_ADDRESS(TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x08:
                {
                    DPRINT1("PnpCmResourcesToBiosResources: TAG_WORD_ADDRESS(TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x09:
                {
                    DPRINT1("PnpCmResourcesToBiosResources: TAG_EXTENDED_IRQ(TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x0A:
                {
                    DPRINT1("PnpCmResourcesToBiosResources: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                case 0x0B:
                {
                    DPRINT1("PnpCmResourcesToBiosResources: FIXME! (TagName %X)\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
                default:
                {
                    DPRINT1("PnpCmResourcesToBiosResources: Unsupported TagName %X\n", TagName);
                    ASSERT(FALSE);
                    break;
                }
            }
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PnpCmResourcesToBiosResources: Status %X for TagName %X\n", Status, TagName);
            return Status;
        }

        Data = ResDataType = Add2Ptr(ResDataType, Increment);
    }

    DPRINT1("PnpCmResourcesToBiosResources: TAG_END\n");

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PnpCmResourcesToBiosResources: Status %X for TagName %X\n", Status, TagName);
        return Status;
    }

    return (PnpiCmResourceValidEmptyList(CmResources) == TRUE ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS);
}

NTSTATUS
NTAPI
ACPIDeviceInternalDeviceRequest(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ DEVICE_POWER_STATE DeviceState,
    _In_ PVOID CallBack,
    _In_ PVOID Context,
    _In_ ULONG Flags)
{
    POWER_STATE State;
    NTSTATUS Status;

    DPRINT("ACPIDeviceInternalDeviceRequest: Transition to D%d\n", (DeviceState - 1));

    State.DeviceState = DeviceState;

    Status = ACPIDeviceInitializePowerRequest(DeviceExtension,
                                              State,
                                              CallBack,
                                              Context,
                                              PowerActionNone,
                                              AcpiPowerRequestDevice,
                                              Flags);

    if (Status == STATUS_MORE_PROCESSING_REQUIRED)
        Status = STATUS_PENDING;

    DPRINT("ACPIDeviceInternalDeviceRequest: ret %X\n", Status);
    return Status;
}

NTSTATUS
NTAPI
EnableDisableRegions(
    _In_ PAMLI_NAME_SPACE_OBJECT InNsObject,
    _In_ BOOLEAN IsEnable)
{
    PAMLI_NAME_SPACE_OBJECT NsObject;
    PAMLI_NAME_SPACE_OBJECT Child;
    AMLI_OBJECT_DATA data[2];
    NTSTATUS status;
    NTSTATUS Status;

    DPRINT("EnableDisableRegions: %p\n", InNsObject);
    PAGED_CODE();

    ASSERT(InNsObject->NameSeg);

    NsObject = ACPIAmliGetNamedChild(InNsObject, 'GER_');
    if (NsObject)
    {
        RtlZeroMemory(data, sizeof(data));

        data[0].DataType = 1;
        data[0].DataValue = (PVOID)2;

        data[1].DataType = 1;
        data[1].DataValue = (PVOID)(IsEnable ? 1 : 0);

        status = AMLIEvalNameSpaceObject(NsObject, NULL, 2, data);
    }

    Status = STATUS_SUCCESS;

    for (Child = InNsObject->FirstChild; Child; Child = (PVOID)Child->List.Next)
    {
        if (Child->ObjData.DataType == 6 && !IsNsobjPciBus(Child))
        {
            status = EnableDisableRegions(Child, IsEnable);
            if (!NT_SUCCESS(status))
            {
                DPRINT1("EnableDisableRegions: status %X\n", status);
                Status = status;
            }
        }

        if (!Child->Parent)
            break;

        if (Child->Parent->FirstChild == (PVOID)Child->List.Next)
            break;
    }

    return Status;
}

VOID
NTAPI
ACPIBusIrpStartDeviceWorker(
    _In_ PVOID Context)
{
    PWORK_QUEUE_CONTEXT WorkContext = Context;
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status;

    DPRINT("ACPIBusIrpStartDeviceWorker: %p\n", Context);
    PAGED_CODE();

    DeviceExtension = ACPIInternalGetDeviceExtension(WorkContext->DeviceObject);

    Status = WorkContext->Irp->IoStatus.Status;

    if (NT_SUCCESS(Status) && IsNsobjPciBus(DeviceExtension->AcpiObject))
        EnableDisableRegions(DeviceExtension->AcpiObject, TRUE);

    WorkContext->Irp->IoStatus.Status = Status;
    WorkContext->Irp->IoStatus.Information = 0;

    IoCompleteRequest(WorkContext->Irp, 0);

    DPRINT("ACPIBusIrpStartDeviceWorker: %p, %X\n", WorkContext->Irp, Status);
}

VOID
NTAPI
ACPIBusIrpStartDeviceCompletion(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID Context,
    _In_ NTSTATUS InStatus)
{
    PWORK_QUEUE_CONTEXT WorkContext;
    PIRP Irp = Context;

    DPRINT("ACPIBusIrpStartDeviceCompletion: %p\n", DeviceExtension);

    WorkContext = &DeviceExtension->Pdo.WorkContext;
    Irp->IoStatus.Status = InStatus;

    if (!NT_SUCCESS(InStatus))
    {
        IoCompleteRequest(Irp, 0);
        return;
    }

    DeviceExtension->DeviceState = Started;

    ExInitializeWorkItem(&WorkContext->Item, ACPIBusIrpStartDeviceWorker, WorkContext);
    WorkContext->DeviceObject = DeviceExtension->DeviceObject;
    WorkContext->Irp = Irp;
    ExQueueWorkItem(&WorkContext->Item, DelayedWorkQueue);
}

NTSTATUS
NTAPI
ACPIInitStartDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PCM_RESOURCE_LIST AllocatedResources,
    _In_ PVOID Callback,
    _In_ PVOID Context,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    PAMLI_NAME_SPACE_OBJECT NsObject;
    PCM_RESOURCE_LIST CmResources;
    PAMLI_OBJECT_DATA AmliData;
    AMLI_OBJECT_DATA DataResult;
    ULONG NewCmSize;
    ULONG Size;
    KIRQL Irql;
    NTSTATUS Status;

    DPRINT("ACPIInitStartDevice: %p\n", DeviceObject);

    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);

    if (!AllocatedResources || AllocatedResources->Count != 1)
        goto Finish;

    NsObject = ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, 'SRC_');
    if (!NsObject)
    {
        DPRINT("ACPIInitStartDevice: No CRS\n");
        goto Finish;
    }

    if (!ACPIAmliGetNamedChild(DeviceExtension->AcpiObject, 'SRS_'))
    {
        DPRINT("ACPIInitStartDevice: No SRS\n");
        goto Finish;
    }

    Status = AMLIEvalNameSpaceObject(NsObject, &DataResult, 0, NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIInitStartDevice: _CRS failed %X\n", Status);
        DPRINT1("ACPIInitStartDevice: FIXME\n");
        ASSERT(FALSE);
        return Status;
    }

    if (DataResult.DataType != 3 || !DataResult.DataLen || !DataResult.DataBuff)
    {
        DPRINT1("ACPIInitStartDevice: _CRS return invalid data\n", DataResult.DataType);
        AMLIFreeDataBuffs(&DataResult, 1);
        DPRINT1("ACPIInitStartDevice: FIXME\n");
        ASSERT(FALSE);
        return STATUS_UNSUCCESSFUL;
    }

    //FIXME
    //ACPIDebugCmResourceList(AllocatedResources, DeviceExtension);

    NewCmSize = (sizeof(CM_RESOURCE_LIST) + (AllocatedResources->List[0].PartialResourceList.Count - 1) * sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));

    CmResources = ExAllocatePoolWithTag(PagedPool, NewCmSize, 'SpcA');
    if (!CmResources)
    {
        DPRINT1("ACPIInitStartDevice: STATUS_INSUFFICIENT_RESOURCES\n");
        AMLIFreeDataBuffs(&DataResult, 1);
        DPRINT1("ACPIInitStartDevice: FIXME\n");
        ASSERT(FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(CmResources, AllocatedResources, NewCmSize);

    Size = (DataResult.DataLen + sizeof(AMLI_OBJECT_DATA));

    AmliData = ExAllocatePoolWithTag(NonPagedPool, Size, 'OpcA');
    if (!AmliData)
    {
        DPRINT1("ACPIInitStartDevice: STATUS_INSUFFICIENT_RESOURCES\n");
        AMLIFreeDataBuffs(&DataResult, 1);
        ExFreePoolWithTag(CmResources, 'SpcA');
        DPRINT1("ACPIInitStartDevice: FIXME\n");
        ASSERT(FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(AmliData, &DataResult, sizeof(AMLI_OBJECT_DATA));
    AmliData->DataBuff = &AmliData[1];
    RtlCopyMemory(AmliData->DataBuff, DataResult.DataBuff, DataResult.DataLen);
    AMLIFreeDataBuffs(&DataResult, 1);

    Status = PnpCmResourcesToBiosResources(CmResources, AmliData->DataBuff);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("ACPIInitStartDevice: PnpCmResourceToBiosResources = %X\n", Status);
        ExFreePoolWithTag(CmResources, 'SpcA');
        ExFreePoolWithTag(AmliData, 'OpcA');
        DPRINT1("ACPIInitStartDevice: FIXME\n");
        ASSERT(FALSE);
        return Status;
    }

    RtlCopyMemory(CmResources, AllocatedResources, NewCmSize);

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &Irql);

    if (DeviceExtension->PnpResourceList)
        ExFreePool(DeviceExtension->PnpResourceList);

    DeviceExtension->PnpResourceList = AmliData;

    KeReleaseSpinLock(&AcpiDeviceTreeLock, Irql);

    if (DeviceExtension->ResourceList)
        ExFreePool(DeviceExtension->ResourceList);

    DeviceExtension->ResourceList = CmResources;
 
Finish:

    IoMarkIrpPending(Irp);

    Status = ACPIDeviceInternalDeviceRequest(DeviceExtension, PowerDeviceD0, Callback, Context, 4);
    if (Status == STATUS_MORE_PROCESSING_REQUIRED)
        Status = STATUS_PENDING;

    DPRINT("ACPIInitStartDevice: ret %X\n", Status);
    return Status;
}

NTSTATUS
NTAPI
AcpiArbInitializePciRouting(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PARBITER_EXTENSION ArbExtension;
    PDEVICE_OBJECT AttachedDevice;
    PINTERFACE Interface;
    ULONG_PTR dummyInformation;
    IO_STACK_LOCATION ioStack;
    NTSTATUS Status;

    DPRINT("AcpiArbInitializePciRouting: %p\n", DeviceObject);
    PAGED_CODE();

    Interface = ExAllocatePoolWithTag(NonPagedPool, sizeof(INT_ROUTE_INTERFACE_STANDARD), 'ApcA');
    if (!Interface)
    {
        DPRINT1("AcpiArbInitializePciRouting: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    AttachedDevice = IoGetAttachedDeviceReference(DeviceObject);

    RtlZeroMemory(&ioStack, sizeof(ioStack));

    ioStack.MajorFunction = IRP_MJ_PNP;
    ioStack.MinorFunction = IRP_MN_QUERY_INTERFACE;

    ioStack.Parameters.QueryInterface.InterfaceType = &GUID_INT_ROUTE_INTERFACE_STANDARD;
    ioStack.Parameters.QueryInterface.Size = sizeof(INT_ROUTE_INTERFACE_STANDARD);
    ioStack.Parameters.QueryInterface.Version = 1;
    ioStack.Parameters.QueryInterface.Interface = Interface;

    Status = ACPIInternalSendSynchronousIrp(AttachedDevice, &ioStack, &dummyInformation);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("AcpiArbInitializePciRouting: Status %X\n", Status);
        ExFreePoolWithTag(Interface, 'ApcA');
        ObDereferenceObject(AttachedDevice);
        return Status;
    }

    ArbExtension = AcpiArbiter.Extension;
    ArbExtension->InterruptRouting = (PVOID)Interface;

    Interface->InterfaceReference(Interface->Context);

    PciInterfacesInstantiated = TRUE;

    ObDereferenceObject(AttachedDevice);

    return Status;
}

NTSTATUS
NTAPI
ACPIWakeInitializePmeRouting(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PINTERFACE Interface;
    IO_STACK_LOCATION ioStack;
    ULONG_PTR dummyInformation;
    KIRQL Irql;
    NTSTATUS Status;

    DPRINT("ACPIWakeInitializePmeRouting: %p\n", DeviceObject);

    Interface = ExAllocatePoolWithTag(NonPagedPool, sizeof(INT_ROUTE_INTERFACE_STANDARD), 'ApcA');
    if (!Interface)
    {
        DPRINT1("ACPIWakeInitializePmeRouting: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&ioStack, sizeof(ioStack));

    ioStack.MajorFunction = IRP_MJ_PNP;
    ioStack.MinorFunction = IRP_MN_QUERY_INTERFACE;

    ioStack.Parameters.QueryInterface.InterfaceType = &GUID_PCI_PME_INTERFACE;
    ioStack.Parameters.QueryInterface.Size = sizeof(INT_ROUTE_INTERFACE_STANDARD);
    ioStack.Parameters.QueryInterface.Version = 1;
    ioStack.Parameters.QueryInterface.Interface = Interface;

    Status = ACPIInternalSendSynchronousIrp(DeviceObject, &ioStack, &dummyInformation);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("ACPIWakeInitializePmeRouting: Status %X\n", Status);
        ExFreePoolWithTag(Interface, 'ApcA');
        return Status;
    }

    KeAcquireSpinLock(&AcpiPowerLock, &Irql);

    if (PciPmeInterfaceInstantiated)
    {
        ExFreePoolWithTag(Interface, 'ApcA');
    }
    else
    {
        PciPmeInterfaceInstantiated = TRUE;
        PciPmeInterface = (PVOID)Interface;
    }

    KeReleaseSpinLock(&AcpiPowerLock, Irql);

    return Status;
}

NTSTATUS
NTAPI
ACPIBusIrpStartDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension;
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("ACPIBusIrpStartDevice: DeviceObject %p\n");
    PAGED_CODE();

    DeviceExtension = ACPIInternalGetDeviceExtension(DeviceObject);
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (DeviceExtension->Flags & 0x0000000002000000)
    {
        if (!PciInterfacesInstantiated)
            AcpiArbInitializePciRouting(DeviceObject);

        if (!PciPmeInterfaceInstantiated)
            ACPIWakeInitializePmeRouting(DeviceObject);
    }

    if ((DeviceExtension->Flags & 0x0000002000000000) && DeviceExtension->Module.ArbitersNeeded)
    {
        DPRINT1("ACPIBusIrpStartDevice: FIXME\n");
        ASSERT(FALSE);
    }

    Status = ACPIInitStartDevice(DeviceObject,
                                 IoStack->Parameters.StartDevice.AllocatedResources,
                                 ACPIBusIrpStartDeviceCompletion,
                                 Irp,
                                 Irp);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("ACPIBusIrpStartDevice: Status %X\n", Status);
        return Status;
    }

    DPRINT("ACPIBusIrpStartDevice: return STATUS_PENDING\n");
    return STATUS_PENDING;
}

NTSTATUS
NTAPI
ACPIBusIrpUnhandled(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    IoCompleteRequest(Irp, 0);
    return Irp->IoStatus.Status;
}

/* FUNCTIOS *****************************************************************/

ULONGLONG
NTAPI
ACPIInternalUpdateFlags(
    _In_ ULONGLONG* FlagsForUpdating,
    _In_ ULONGLONG InputFlags,
    _In_ BOOLEAN IsResetFlags)
{
    ULONGLONG ReturnFlags;
    ULONGLONG ExChange;
    ULONGLONG Comperand;

    if (IsResetFlags)
    {
        ReturnFlags = *FlagsForUpdating;
        do
        {
            Comperand = ReturnFlags;
            ExChange = Comperand & ~InputFlags;

            ReturnFlags = ExInterlockedCompareExchange64((PLONGLONG)FlagsForUpdating, (PLONGLONG)&ExChange, (PLONGLONG)&Comperand, NULL);
        }
        while (Comperand != ReturnFlags);
    }
    else
    {
        ReturnFlags = *FlagsForUpdating;
        do
        {
            Comperand = ReturnFlags;
            ExChange = Comperand | InputFlags;

            ReturnFlags = ExInterlockedCompareExchange64((PLONGLONG)FlagsForUpdating, (PLONGLONG)&ExChange, (PLONGLONG)&Comperand, NULL);
        }
        while (Comperand != ReturnFlags);
    }

    return ReturnFlags;
}


/* EOF */
