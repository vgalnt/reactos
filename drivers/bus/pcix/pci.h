/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/pci.h
 * PURPOSE:         Main Header File
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

#ifndef _PCIX_PCH_
#define _PCIX_PCH_

#include <ntifs.h>
#include <wdmguid.h>
#include <wchar.h>
#include <acpiioct.h>
#include <drivers/pci/pci.h>
#include <drivers/acpi/acpi.h>
#include <ndk/halfuncs.h>
#include <ndk/rtlfuncs.h>
#include <ndk/vffuncs.h>
#include <arbiter.h>
#include <cmreslist.h>
#include <initguid.h>
#include <wdmguid.h>

// Tag used in all pool allocations (Pci Bus)
#define PCI_POOL_TAG    'BicP'

// Checks if the specified FDO is the FDO for the Root PCI Bus
#define PCI_IS_ROOT_FDO(x)                  ((x)->BusRootFdoExtension == x)

// Assertions to make sure we are dealing with the right kind of extension
#define ASSERT_FDO(x)                       ASSERT((x)->ExtensionType == PciFdoExtensionType);
#define ASSERT_PDO(x)                       ASSERT((x)->ExtensionType == PciPdoExtensionType);

// PCI Hack Entry Name Lengths
#define PCI_HACK_ENTRY_SIZE                 sizeof(L"VVVVdddd") - sizeof(UNICODE_NULL)
#define PCI_HACK_ENTRY_REV_SIZE             sizeof(L"VVVVddddRR") - sizeof(UNICODE_NULL)
#define PCI_HACK_ENTRY_SUBSYS_SIZE          sizeof(L"VVVVddddssssIIII") - sizeof(UNICODE_NULL)
#define PCI_HACK_ENTRY_FULL_SIZE            sizeof(L"VVVVddddssssIIIIRR") - sizeof(UNICODE_NULL)

// PCI Hack Entry Flags
#define PCI_HACK_HAS_REVISION_INFO          0x01
#define PCI_HACK_HAS_SUBSYSTEM_INFO         0x02

// PCI Interface Flags
#define PCI_INTERFACE_PDO                   0x01
#define PCI_INTERFACE_FDO                   0x02
#define PCI_INTERFACE_ROOT                  0x04

// PCI Skip Function Flags
#define PCI_SKIP_DEVICE_ENUMERATION         0x01
#define PCI_SKIP_RESOURCE_ENUMERATION       0x02

// PCI Apply Hack Flags
#define PCI_HACK_FIXUP_BEFORE_CONFIGURATION 0x00
#define PCI_HACK_FIXUP_AFTER_CONFIGURATION  0x01
#define PCI_HACK_FIXUP_BEFORE_UPDATE        0x03

// PCI Debugging Device Support
#define MAX_DEBUGGING_DEVICES_SUPPORTED     0x02

// PCI Driver Verifier Failures
#define PCI_VERIFIER_CODES                  0x04

// PCI ID Buffer ANSI Strings
#define MAX_ANSI_STRINGS                    0x08

#ifndef Add2Ptr
  #define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#endif

DEFINE_GUID(GUID_PCI_NATIVE_IDE_INTERFACE, 0x98F37D63, 0x42AE, 0x4AD9, 0x8C, 0x36, 0x93, 0x2D, 0x28, 0x38, 0x3D, 0xF8);

/* STRUCTURES ***************************************************************/

// Device Extension, Interface, Translator and Arbiter Signatures
typedef enum _PCI_SIGNATURE
{
    PciPdoExtensionType = 'icP0',
    PciFdoExtensionType = 'icP1',
    PciArb_Io = 'icP2',
    PciArb_Memory = 'icP3',
    PciArb_Interrupt = 'icP4',
    PciArb_BusNumber = 'icP5',
    PciTrans_Interrupt = 'icP6',
    PciInterface_BusHandler = 'icP7',
    PciInterface_IntRouteHandler = 'icP8',
    PciInterface_PciCb = 'icP9',
    PciInterface_LegacyDeviceDetection = 'icP:',
    PciInterface_PmeHandler = 'icP;',
    PciInterface_DevicePresent = 'icP<',
    PciInterface_NativeIde = 'icP=',
    PciInterface_AgpTarget = 'icP>',
    PciInterface_Location  = 'icP?'
} PCI_SIGNATURE, *PPCI_SIGNATURE;

// Driver-handled PCI Device Types
typedef enum _PCI_DEVICE_TYPES
{
    PciTypeInvalid,
    PciTypeHostBridge,
    PciTypePciBridge,
    PciTypeCardbusBridge,
    PciTypeDevice
} PCI_DEVICE_TYPES;

// Device Extension Logic States
typedef enum _PCI_STATE
{
    PciNotStarted,
    PciStarted,
    PciDeleted,
    PciStopped,
    PciSurpriseRemoved,
    PciSynchronizedOperation,
    PciMaxObjectState
} PCI_STATE;

// IRP Dispatch Logic Style
typedef enum _PCI_DISPATCH_STYLE
{
    IRP_COMPLETE,
    IRP_DOWNWARD,
    IRP_UPWARD,
    IRP_DISPATCH,
} PCI_DISPATCH_STYLE;

// PCI Hack Entry Information
typedef struct _PCI_HACK_ENTRY
{
    USHORT VendorID;
    USHORT DeviceID;
    USHORT SubVendorID;
    USHORT SubSystemID;
    ULONGLONG HackFlags;
    UCHAR RevisionID;
    UCHAR Flags;
} PCI_HACK_ENTRY, *PPCI_HACK_ENTRY;

// Power State Information for Device Extension
typedef struct _PCI_POWER_STATE
{
    SYSTEM_POWER_STATE CurrentSystemState;
    DEVICE_POWER_STATE CurrentDeviceState;
    SYSTEM_POWER_STATE SystemWakeLevel;
    DEVICE_POWER_STATE DeviceWakeLevel;
    DEVICE_POWER_STATE SystemStateMapping[7];
    PIRP WaitWakeIrp;
    PVOID SavedCancelRoutine;
    LONG Paging;
    LONG Hibernate;
    LONG CrashDump;
} PCI_POWER_STATE, *PPCI_POWER_STATE;

// Internal PCI Lock Structure
typedef struct _PCI_LOCK
{
    LONG Atom;
    BOOLEAN OldIrql;
} PCI_LOCK, *PPCI_LOCK;

// Device Extension for a Bus FDO
typedef struct _PCI_FDO_EXTENSION
{
    SINGLE_LIST_ENTRY List;
    ULONG ExtensionType;
    struct _PCI_MJ_DISPATCH_TABLE* IrpDispatchTable;
    BOOLEAN DeviceState;
    BOOLEAN TentativeNextState;
    KEVENT SecondaryExtLock;
    PDEVICE_OBJECT PhysicalDeviceObject;
    PDEVICE_OBJECT FunctionalDeviceObject;
    PDEVICE_OBJECT AttachedDeviceObject;
    KEVENT ChildListLock;
    struct _PCI_PDO_EXTENSION* ChildPdoList;
    struct _PCI_FDO_EXTENSION* BusRootFdoExtension;
    struct _PCI_FDO_EXTENSION* ParentFdoExtension;
    struct _PCI_PDO_EXTENSION* ChildBridgePdoList;
    PPCI_BUS_INTERFACE_STANDARD PciBusInterface;
    BOOLEAN MaxSubordinateBus;
    BUS_HANDLER* BusHandler;
    UCHAR BaseBus;
    BOOLEAN Fake;
    BOOLEAN ChildDelete;
    BOOLEAN Scanned;
    BOOLEAN ArbitersInitialized;
    BOOLEAN BrokenVideoHackApplied;
    BOOLEAN Hibernated;
    PCI_POWER_STATE PowerState;
    SINGLE_LIST_ENTRY SecondaryExtension;
    LONG ChildWaitWakeCount;
    PPCI_COMMON_CONFIG PreservedConfig;
    PCI_LOCK Lock;
    struct
    {
        BOOLEAN Acquired;
        UCHAR CacheLineSize;
        UCHAR LatencyTimer;
        BOOLEAN EnablePERR;
        BOOLEAN EnableSERR;
    } HotPlugParameters;
    LONG BusHackFlags;
} PCI_FDO_EXTENSION, *PPCI_FDO_EXTENSION;

typedef struct _PCI_FUNCTION_RESOURCES
{
    IO_RESOURCE_DESCRIPTOR Limit[7];
    CM_PARTIAL_RESOURCE_DESCRIPTOR Current[7];
} PCI_FUNCTION_RESOURCES, *PPCI_FUNCTION_RESOURCES;

typedef union _PCI_HEADER_TYPE_DEPENDENT
{
    struct
    {
        UCHAR Spare[4];
    } type0;
    struct
    {
        UCHAR PrimaryBus;
        UCHAR SecondaryBus;
        UCHAR SubordinateBus;
        UCHAR SubtractiveDecode:1;
        UCHAR IsaBitSet:1;
        UCHAR VgaBitSet:1;
        UCHAR WeChangedBusNumbers:1;
        UCHAR IsaBitRequired:1;
    } type1;
    struct
    {
        UCHAR PrimaryBus;
        UCHAR SecondaryBus;
        UCHAR SubordinateBus;
        UCHAR SubtractiveDecode:1;
        UCHAR IsaBitSet:1;
        UCHAR VgaBitSet:1;
        UCHAR WeChangedBusNumbers:1;
        UCHAR IsaBitRequired:1;
    } type2;
} PCI_HEADER_TYPE_DEPENDENT, *PPCI_HEADER_TYPE_DEPENDENT;

typedef struct _PCI_PDO_EXTENSION
{
    PVOID Next;
    ULONG ExtensionType;
    struct _PCI_MJ_DISPATCH_TABLE *IrpDispatchTable;
    BOOLEAN DeviceState;
    BOOLEAN TentativeNextState;

    KEVENT SecondaryExtLock;
    PCI_SLOT_NUMBER Slot;
    PDEVICE_OBJECT PhysicalDeviceObject;
    PPCI_FDO_EXTENSION ParentFdoExtension;
    SINGLE_LIST_ENTRY SecondaryExtension;
    LONG BusInterfaceReferenceCount;
    LONG AgpInterfaceReferenceCount;
    USHORT VendorId;
    USHORT DeviceId;
    USHORT SubsystemVendorId;
    USHORT SubsystemId;
    BOOLEAN RevisionId;
    BOOLEAN ProgIf;
    BOOLEAN SubClass;
    BOOLEAN BaseClass;
    BOOLEAN AdditionalResourceCount;
    BOOLEAN AdjustedInterruptLine;
    BOOLEAN InterruptPin;
    BOOLEAN RawInterruptLine;
    BOOLEAN CapabilitiesPtr;
    BOOLEAN SavedLatencyTimer;
    BOOLEAN SavedCacheLineSize;
    BOOLEAN HeaderType;
    BOOLEAN NotPresent;
    BOOLEAN ReportedMissing;
    BOOLEAN ExpectedWritebackFailure;
    BOOLEAN NoTouchPmeEnable;
    BOOLEAN LegacyDriver;
    BOOLEAN UpdateHardware;
    BOOLEAN MovedDevice;
    BOOLEAN DisablePowerDown;
    BOOLEAN NeedsHotPlugConfiguration;
    BOOLEAN IDEInNativeMode;
    BOOLEAN BIOSAllowsIDESwitchToNativeMode;
    BOOLEAN IoSpaceUnderNativeIdeControl;
    BOOLEAN OnDebugPath;
    BOOLEAN IoSpaceNotRequired;
    PCI_POWER_STATE PowerState;
    PCI_HEADER_TYPE_DEPENDENT Dependent;
    ULONGLONG HackFlags;
    PCI_FUNCTION_RESOURCES* Resources;
    PCI_FDO_EXTENSION* BridgeFdoExtension;
    struct _PCI_PDO_EXTENSION* NextBridge;
    struct _PCI_PDO_EXTENSION* NextHashEntry;
    PCI_LOCK Lock;
    PCI_PMC PowerCapabilities;
    BOOLEAN TargetAgpCapabilityId;
    USHORT CommandEnables;
    USHORT InitialCommand;
} PCI_PDO_EXTENSION, *PPCI_PDO_EXTENSION;

// IRP Dispatch Function Type
typedef NTSTATUS (NTAPI* PCI_DISPATCH_FUNCTION)(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PVOID DeviceExtension
);

// IRP Dispatch Minor Table
typedef struct _PCI_MN_DISPATCH_TABLE
{
    PCI_DISPATCH_STYLE DispatchStyle;
    PCI_DISPATCH_FUNCTION DispatchFunction;
} PCI_MN_DISPATCH_TABLE, *PPCI_MN_DISPATCH_TABLE;

// IRP Dispatch Major Table
typedef struct _PCI_MJ_DISPATCH_TABLE
{
    ULONG PnpIrpMaximumMinorFunction;
    PPCI_MN_DISPATCH_TABLE PnpIrpDispatchTable;
    ULONG PowerIrpMaximumMinorFunction;
    PPCI_MN_DISPATCH_TABLE PowerIrpDispatchTable;
    PCI_DISPATCH_STYLE SystemControlIrpDispatchStyle;
    PCI_DISPATCH_FUNCTION SystemControlIrpDispatchFunction;
    PCI_DISPATCH_STYLE OtherIrpDispatchStyle;
    PCI_DISPATCH_FUNCTION OtherIrpDispatchFunction;
} PCI_MJ_DISPATCH_TABLE, *PPCI_MJ_DISPATCH_TABLE;

// Generic PCI Interface Constructor and Initializer
typedef NTSTATUS (NTAPI* PCI_INTERFACE_CONSTRUCTOR)(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface
);

struct _PCI_ARBITER_INSTANCE;
typedef NTSTATUS (NTAPI* PCI_INTERFACE_INITIALIZER)(
    _In_ struct _PCI_ARBITER_INSTANCE* Instance
);

// Generic PCI Interface (Interface, Translator, Arbiter)
typedef struct _PCI_INTERFACE
{
    CONST GUID* InterfaceType;
    USHORT MinSize;
    USHORT MinVersion;
    USHORT MaxVersion;
    USHORT Flags;
    LONG ReferenceCount;
    PCI_SIGNATURE Signature;
    PCI_INTERFACE_CONSTRUCTOR Constructor;
    PCI_INTERFACE_INITIALIZER Initializer;
} PCI_INTERFACE, *PPCI_INTERFACE;

// Generic Secondary Extension Instance Header (Interface, Translator, Arbiter)
typedef struct PCI_SECONDARY_EXTENSION
{
    SINGLE_LIST_ENTRY List;
    PCI_SIGNATURE ExtensionType;
    PVOID Destructor;
} PCI_SECONDARY_EXTENSION, *PPCI_SECONDARY_EXTENSION;

// PCI Arbiter Instance
typedef struct _PCI_ARBITER_INSTANCE
{
    PCI_SECONDARY_EXTENSION Header;
    PPCI_INTERFACE Interface;
    PPCI_FDO_EXTENSION BusFdoExtension;
    WCHAR InstanceName[24];
    ARBITER_INSTANCE CommonInstance;
} PCI_ARBITER_INSTANCE, *PPCI_ARBITER_INSTANCE;

typedef struct _PCI_ARB_MEM_EXTENTION
{
    BOOLEAN IsPrefetchable;
    BOOLEAN IsStarted;
    USHORT Prefetches;
    ARBITER_ORDERING_LIST PrefetchOrderingList;
    ARBITER_ORDERING_LIST OrderingList;
    ARBITER_ORDERING_LIST ArbiterOrderingList;
} PCI_ARB_MEM_EXTENTION, *PPCI_ARB_MEM_EXTENTION;

// PCI Verifier Data
typedef struct _PCI_VERIFIER_DATA
{
    ULONG FailureCode;
    VF_FAILURE_CLASS FailureClass;
    ULONG AssertionControl;
    PCHAR DebuggerMessageText;
} PCI_VERIFIER_DATA, *PPCI_VERIFIER_DATA;

// PCI ID Buffer Descriptor
typedef struct _PCI_ID_BUFFER
{
    ULONG Count;
    ANSI_STRING Strings[MAX_ANSI_STRINGS];
    ULONG StringSize[MAX_ANSI_STRINGS];
    ULONG TotalLength;
    PCHAR CharBuffer;
    CHAR BufferData[256];
} PCI_ID_BUFFER, *PPCI_ID_BUFFER;

// PCI Configuration Callbacks
struct _PCI_CONFIGURATOR_CONTEXT;

typedef VOID (NTAPI* PCI_CONFIGURATOR_INITIALIZE)(
    _In_ struct _PCI_CONFIGURATOR_CONTEXT* Context
);

typedef VOID (NTAPI* PCI_CONFIGURATOR_RESTORE_CURRENT)(
    _In_ struct _PCI_CONFIGURATOR_CONTEXT* Context
);

typedef VOID (NTAPI* PCI_CONFIGURATOR_SAVE_LIMITS)(
    _In_ struct _PCI_CONFIGURATOR_CONTEXT* Context
);

typedef VOID (NTAPI* PCI_CONFIGURATOR_SAVE_CURRENT_SETTINGS)(
    _In_ struct _PCI_CONFIGURATOR_CONTEXT* Context
);

typedef VOID (NTAPI* PCI_CONFIGURATOR_CHANGE_RESOURCE_SETTINGS)(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PPCI_COMMON_HEADER PciData
);

typedef VOID (NTAPI* PCI_CONFIGURATOR_GET_ADDITIONAL_RESOURCE_DESCRIPTORS)(
    _In_ struct _PCI_CONFIGURATOR_CONTEXT* Context,
    _In_ PPCI_COMMON_HEADER PciData,
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor
);

typedef VOID (NTAPI* PCI_CONFIGURATOR_RESET_DEVICE)(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PPCI_COMMON_HEADER PciData
);

// PCI Configurator
typedef struct _PCI_CONFIGURATOR
{
    PCI_CONFIGURATOR_INITIALIZE Initialize;
    PCI_CONFIGURATOR_RESTORE_CURRENT RestoreCurrent;
    PCI_CONFIGURATOR_SAVE_LIMITS SaveLimits;
    PCI_CONFIGURATOR_SAVE_CURRENT_SETTINGS SaveCurrentSettings;
    PCI_CONFIGURATOR_CHANGE_RESOURCE_SETTINGS ChangeResourceSettings;
    PCI_CONFIGURATOR_GET_ADDITIONAL_RESOURCE_DESCRIPTORS GetAdditionalResourceDescriptors;
    PCI_CONFIGURATOR_RESET_DEVICE ResetDevice;
} PCI_CONFIGURATOR, *PPCI_CONFIGURATOR;

// PCI Configurator Context
typedef struct _PCI_CONFIGURATOR_CONTEXT
{
    PPCI_PDO_EXTENSION PdoExtension;
    PPCI_COMMON_HEADER Current;
    PPCI_COMMON_HEADER PciData;
    PPCI_CONFIGURATOR Configurator;
    USHORT SecondaryStatus;
    USHORT Status;
    USHORT Command;
} PCI_CONFIGURATOR_CONTEXT, *PPCI_CONFIGURATOR_CONTEXT;

// PCI IPI Function
typedef VOID (NTAPI* PCI_IPI_FUNCTION)(
    _In_ PVOID Reserved,
    _In_ PVOID Context
);

// PCI IPI Context
typedef struct _PCI_IPI_CONTEXT
{
    LONG RunCount;
    ULONG Barrier;
    PVOID DeviceExtension;
    PCI_IPI_FUNCTION Function;
    PVOID Context;
} PCI_IPI_CONTEXT, *PPCI_IPI_CONTEXT;

// PCI Legacy Device Location Cache
typedef struct _PCI_LEGACY_DEVICE
{
    struct _PCI_LEGACY_DEVICE* Next;
    PDEVICE_OBJECT DeviceObject;
    ULONG BusNumber;
    ULONG SlotNumber;
    UCHAR InterruptLine;
    UCHAR InterruptPin;
    UCHAR BaseClass;
    UCHAR SubClass;
    PDEVICE_OBJECT PhysicalDeviceObject;
    ROUTING_TOKEN RoutingToken;
    PPCI_PDO_EXTENSION PdoExtension;
} PCI_LEGACY_DEVICE, *PPCI_LEGACY_DEVICE;

typedef struct _PCI_RANGE_LIST
{
    struct _PCI_RANGE_LIST* Next;
    struct _PCI_RANGE_LIST* Previous;
    ULONGLONG Start;
    ULONGLONG End;
    BOOLEAN IsActive;
} PCI_RANGE_LIST, *PPCI_RANGE_LIST;

typedef struct _PCI_PARTIAL_LIST_CONTEXT
{
    PCM_PARTIAL_RESOURCE_LIST PartialList;
    CM_RESOURCE_TYPE DesiredType;
    ULONG Count;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR PointToNextDescriptor;
    CM_PARTIAL_RESOURCE_DESCRIPTOR CurrentDescriptor;
} PCI_PARTIAL_LIST_CONTEXT, *PPCI_PARTIAL_LIST_CONTEXT;

typedef struct _PCI_ROUTING_EXTENSION
{
    PCI_SECONDARY_EXTENSION SecondaryExtension;
    ROUTING_TOKEN RoutingToken;
} PCI_ROUTING_EXTENSION, *PPCI_ROUTING_EXTENSION;

/* FUNCTIONS ****************************************************************/

// IRP Dispatch Routines

DRIVER_DISPATCH PciDispatchIrp;

NTSTATUS
NTAPI
PciDispatchIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

NTSTATUS
NTAPI
PciIrpNotSupported(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPassIrpFromFdoToPdo(
    _In_ PPCI_FDO_EXTENSION DeviceExtension,
    _In_ PIRP Irp
);

NTSTATUS
NTAPI
PciCallDownIrpStack(
    _In_ PPCI_FDO_EXTENSION DeviceExtension,
    _In_ PIRP Irp
);

NTSTATUS
NTAPI
PciIrpInvalidDeviceRequest(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

// Power FDO Routines

NTSTATUS
NTAPI
PciFdoWaitWake(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciFdoSetPowerState(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciFdoIrpQueryPower(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciSetPowerManagedDevicePowerState(
    _In_ PPCI_PDO_EXTENSION DeviceExtension,
    _In_ DEVICE_POWER_STATE DeviceState,
    _In_ BOOLEAN IrpSet
);

// Power PDO Routines

NTSTATUS
NTAPI
PciPdoWaitWake(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoSetPowerState(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpQueryPower(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

// Bus FDO Routines

DRIVER_ADD_DEVICE PciAddDevice;

NTSTATUS
NTAPI
PciAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT PhysicalDeviceObject
);

NTSTATUS
NTAPI
PciFdoIrpStartDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciFdoIrpQueryRemoveDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciFdoIrpRemoveDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciFdoIrpCancelRemoveDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciFdoIrpStopDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciFdoIrpQueryStopDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciFdoIrpCancelStopDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciFdoIrpQueryDeviceRelations(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciFdoIrpQueryInterface(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciFdoIrpQueryCapabilities(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciFdoIrpDeviceUsageNotification(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciFdoIrpSurpriseRemoval(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciFdoIrpQueryLegacyBusInformation(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

PCM_PARTIAL_RESOURCE_DESCRIPTOR
NTAPI
PciGetNextCmPartialDescriptor(
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor
);

// Device PDO Routines

NTSTATUS
NTAPI
PciPdoCreate(
    _In_ PPCI_FDO_EXTENSION DeviceExtension,
    _In_ PCI_SLOT_NUMBER Slot,
    _Out_ PDEVICE_OBJECT* PdoDeviceObject
);

NTSTATUS
NTAPI
PciPdoWaitWake(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoSetPowerState(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpQueryPower(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpStartDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpQueryRemoveDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpRemoveDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpCancelRemoveDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpStopDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpQueryStopDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpCancelStopDevice(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpQueryDeviceRelations(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpQueryInterface(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpQueryCapabilities(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpQueryResources(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpQueryResourceRequirements(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpQueryDeviceText(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpReadConfig(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpWriteConfig(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpQueryId(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpQueryDeviceState(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpQueryBusInformation(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpDeviceUsageNotification(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpSurpriseRemoval(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciPdoIrpQueryLegacyBusInformation(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

BOOLEAN
NTAPI
PciIsOnVGAPath(
    _In_ PPCI_PDO_EXTENSION PdoExtension
);

// HAL Callback/Hook Routines

VOID
NTAPI
PciHookHal(
    VOID
);

// PCI Verifier Routines

VOID
NTAPI
PciVerifierInit(
    _In_ PDRIVER_OBJECT DriverObject
);

PPCI_VERIFIER_DATA
NTAPI
PciVerifierRetrieveFailureData(
    _In_ ULONG FailureCode
);

// Utility Routines

BOOLEAN
NTAPI
PciStringToUSHORT(
    _In_ PWCHAR String,
    _Out_ PUSHORT Value
);

BOOLEAN
NTAPI
PciAllowExtendedInterruptVectors(
    _In_ PUNICODE_STRING OptionString
);

NTSTATUS
NTAPI
PciBuildDefaultExclusionLists(
    VOID
);

BOOLEAN
NTAPI
PciUnicodeStringStrStr(
    _In_ PUNICODE_STRING InputString,
    _In_ PCUNICODE_STRING EqualString,
    _In_ BOOLEAN CaseInSensitive
);

BOOLEAN
NTAPI
PciOpenKey(
    _In_ PWCHAR KeyName,
    _In_ HANDLE RootKey,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE KeyHandle,
    _Out_ PNTSTATUS KeyStatus
);

NTSTATUS
NTAPI
PciGetRegistryValue(
    _In_ PWCHAR ValueName,
    _In_ PWCHAR KeyName,
    _In_ HANDLE RootHandle,
    _In_ ULONG Type,
    _Out_ PVOID* OutputBuffer,
    _Out_ PULONG OutputLength
);

PPCI_FDO_EXTENSION
NTAPI
PciFindParentPciFdoExtension(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PKEVENT Lock
);

VOID
NTAPI
PciInsertEntryAtTail(
    _In_ PSINGLE_LIST_ENTRY ListHead,
    _In_ PPCI_FDO_EXTENSION DeviceExtension,
    _In_ PKEVENT Lock
);

NTSTATUS
NTAPI
PciGetDeviceProperty(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ DEVICE_REGISTRY_PROPERTY DeviceProperty,
    _Out_ PVOID* OutputBuffer
);

NTSTATUS
NTAPI
PciSendIoctl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG IoControlCode,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength
);

VOID
NTAPI
PcipLinkSecondaryExtension(
    _In_ PSINGLE_LIST_ENTRY List,
    _In_ PVOID Lock,
    _In_ PPCI_SECONDARY_EXTENSION SecondaryExtension,
    _In_ PCI_SIGNATURE ExtensionType,
    _In_ PVOID Destructor
);

PPCI_SECONDARY_EXTENSION
NTAPI
PciFindNextSecondaryExtension(
    _In_ PSINGLE_LIST_ENTRY ListHead,
    _In_ PCI_SIGNATURE ExtensionType
);

ULONGLONG
NTAPI
PciGetHackFlags(
    _In_ USHORT VendorId,
    _In_ USHORT DeviceId,
    _In_ USHORT SubVendorId,
    _In_ USHORT SubSystemId,
    _In_ UCHAR RevisionId
);

PPCI_PDO_EXTENSION
NTAPI
PciFindPdoByFunction(
    _In_ PPCI_FDO_EXTENSION DeviceExtension,
    _In_ ULONG FunctionNumber,
    _In_ PPCI_COMMON_HEADER PciData
);

BOOLEAN
NTAPI
PciIsCriticalDeviceClass(
    _In_ UCHAR BaseClass,
    _In_ UCHAR SubClass
);

BOOLEAN
NTAPI
PciIsDeviceOnDebugPath(
    _In_ PPCI_PDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciGetBiosConfig(
    _In_ PPCI_PDO_EXTENSION DeviceExtension,
    _Out_ PPCI_COMMON_HEADER PciData
);

NTSTATUS
NTAPI
PciSaveBiosConfig(
    _In_ PPCI_PDO_EXTENSION DeviceExtension,
    _Out_ PPCI_COMMON_HEADER PciData
);

UCHAR
NTAPI
PciReadDeviceCapability(
    _In_ PPCI_PDO_EXTENSION DeviceExtension,
    _In_ UCHAR Offset,
    _In_ ULONG CapabilityId,
    _Out_ PPCI_CAPABILITIES_HEADER Buffer,
    _In_ ULONG Length
);

BOOLEAN
NTAPI
PciCanDisableDecodes(
    _In_ PPCI_PDO_EXTENSION DeviceExtension,
    _In_ PPCI_COMMON_HEADER Config,
    _In_ ULONGLONG HackFlags,
    _In_ BOOLEAN ForPowerDown
);

PCI_DEVICE_TYPES
NTAPI
PciClassifyDeviceType(
    _In_ PPCI_PDO_EXTENSION PdoExtension
);

KIPI_BROADCAST_WORKER PciExecuteCriticalSystemRoutine;

ULONG_PTR
NTAPI
PciExecuteCriticalSystemRoutine(
    _In_ ULONG_PTR IpiContext
);

BOOLEAN
NTAPI
PciCreateIoDescriptorFromBarLimit(
    PIO_RESOURCE_DESCRIPTOR ResourceDescriptor,
    _In_ PULONG BarArray,
    _In_ BOOLEAN Rom
);

BOOLEAN
NTAPI
PciIsSlotPresentInParentMethod(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ ULONG Method
);

VOID
NTAPI
PciDecodeEnable(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ BOOLEAN Enable,
    _Out_ PUSHORT Command
);

NTSTATUS
NTAPI
PciQueryBusInformation(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PPNP_BUS_INFORMATION* Buffer
);

NTSTATUS
NTAPI
PciQueryCapabilities(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _Inout_ PDEVICE_CAPABILITIES DeviceCapability
);

// Configuration Routines

NTSTATUS
NTAPI
PciGetConfigHandlers(
    _In_ PPCI_FDO_EXTENSION FdoExtension
);

VOID
NTAPI
PciReadSlotConfig(
    _In_ PPCI_FDO_EXTENSION DeviceExtension,
    _In_ PCI_SLOT_NUMBER Slot,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length
);

VOID
NTAPI
PciWriteDeviceConfig(
    _In_ PPCI_PDO_EXTENSION DeviceExtension,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length
);

VOID
NTAPI
PciReadDeviceConfig(
    _In_ PPCI_PDO_EXTENSION DeviceExtension,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length
);

UCHAR
NTAPI
PciGetAdjustedInterruptLine(
    _In_ PPCI_PDO_EXTENSION PdoExtension
);

// State Machine Logic Transition Routines

VOID
NTAPI
PciInitializeState(
    _In_ PPCI_FDO_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
PciBeginStateTransition(
    _In_ PPCI_FDO_EXTENSION DeviceExtension,
    _In_ PCI_STATE NewState
);

NTSTATUS
NTAPI
PciCancelStateTransition(
    _In_ PPCI_FDO_EXTENSION DeviceExtension,
    _In_ PCI_STATE NewState
);

VOID
NTAPI
PciCommitStateTransition(
    _In_ PPCI_FDO_EXTENSION DeviceExtension,
    _In_ PCI_STATE NewState
);

// Arbiter Support

NTSTATUS
NTAPI
PciInitializeArbiters(
    _In_ PPCI_FDO_EXTENSION FdoExtension
);

NTSTATUS
NTAPI
PciInitializeArbiterRanges(
    _In_ PPCI_FDO_EXTENSION DeviceExtension,
    _In_ PCM_RESOURCE_LIST Resources
);

VOID
NTAPI
PciReferenceArbiter(
    _In_ PVOID Context
);

VOID
NTAPI
PciDereferenceArbiter(
    _In_ PVOID Context
);

NTSTATUS
NTAPI
PciArbiterInitializeInterface(
    _In_ PVOID DeviceExtension,
    _In_ PCI_SIGNATURE Signature,
    _In_ PARBITER_INTERFACE ArbInterface
);

// Debug Helpers

BOOLEAN
NTAPI
PciDebugIrpDispatchDisplay(
    _In_ PIO_STACK_LOCATION IoStackLocation,
    _In_ PPCI_FDO_EXTENSION DeviceExtension,
    _In_ USHORT MaxMinor
);

VOID
NTAPI
PciDebugDumpCommonConfig(
    _In_ PPCI_COMMON_HEADER PciData
);

VOID
NTAPI
PciDebugDumpQueryCapabilities(
    _In_ PDEVICE_CAPABILITIES DeviceCaps
);

VOID
NTAPI
PciDebugPrintIoResReqList(
    _In_ PIO_RESOURCE_REQUIREMENTS_LIST Requirements
);

VOID
NTAPI
PciDebugPrintCmResList(
    _In_ PCM_RESOURCE_LIST ResourceList
);

VOID
NTAPI
PciDebugPrintPartialResource(
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialResource
);

// Interface Support

NTSTATUS
NTAPI
PciQueryInterface(
    _In_ PPCI_FDO_EXTENSION DeviceExtension,
    _In_ CONST GUID* InterfaceType,
    _In_ ULONG Size,
    _In_ ULONG Version,
    _In_ PVOID InterfaceData,
    _In_ PINTERFACE Interface,
    _In_ BOOLEAN LastChance
);

NTSTATUS
NTAPI
PciPmeInterfaceInitializer(
    _In_ PPCI_ARBITER_INSTANCE Instance
);

NTSTATUS
NTAPI
routeintrf_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance
);

NTSTATUS
NTAPI
arbusno_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance
);

NTSTATUS
NTAPI
agpintrf_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance
);

NTSTATUS
NTAPI
tranirq_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance
);

NTSTATUS
NTAPI
busintrf_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance
);

NTSTATUS
NTAPI
armem_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance
);

NTSTATUS
NTAPI
ario_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance
);

NTSTATUS
NTAPI
locintrf_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance
);

NTSTATUS
NTAPI
pcicbintrf_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance
);

NTSTATUS
NTAPI
lddintrf_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance
);

NTSTATUS
NTAPI
devpresent_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance
);

NTSTATUS
NTAPI
nativeIde_Initializer(
    _In_ PPCI_ARBITER_INSTANCE Instance
);

NTSTATUS
NTAPI
agpintrf_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface
);

NTSTATUS
NTAPI
arbusno_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface
);

NTSTATUS
NTAPI
tranirq_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface
);

NTSTATUS
NTAPI
armem_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface
);

NTSTATUS
NTAPI
busintrf_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface
);

NTSTATUS
NTAPI
ario_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface
);

VOID
NTAPI
ario_ApplyBrokenVideoHack(
    _In_ PPCI_FDO_EXTENSION FdoExtension
);

NTSTATUS
NTAPI
pcicbintrf_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface
);

NTSTATUS
NTAPI
lddintrf_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface
);

NTSTATUS
NTAPI
locintrf_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface
);

NTSTATUS
NTAPI
PciPmeInterfaceConstructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface
);

NTSTATUS
NTAPI
routeintrf_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface
);

NTSTATUS
NTAPI
devpresent_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface
);

NTSTATUS
NTAPI
nativeIde_Constructor(
    _In_ PVOID DeviceExtension,
    _In_ PVOID Instance,
    _In_ PVOID InterfaceData,
    _In_ USHORT Version,
    _In_ USHORT Size,
    _In_ PINTERFACE Interface
);

VOID
NTAPI
pcicbintrf_Dereference(
    _In_ PVOID Context
);

// PCI Enumeration and Resources

NTSTATUS
NTAPI
PciQueryDeviceRelations(
    _In_ PPCI_FDO_EXTENSION DeviceExtension,
    _Inout_ PDEVICE_RELATIONS* pDeviceRelations
);

NTSTATUS
NTAPI
PciQueryResources(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _Out_ PCM_RESOURCE_LIST* Buffer
);

NTSTATUS
NTAPI
PciQueryTargetDeviceRelations(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _Inout_ PDEVICE_RELATIONS* pDeviceRelations
);

NTSTATUS
NTAPI
PciQueryEjectionRelations(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _Inout_ PDEVICE_RELATIONS* pDeviceRelations
);

NTSTATUS
NTAPI
PciQueryRequirements(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _Inout_ PIO_RESOURCE_REQUIREMENTS_LIST* RequirementsList
);

BOOLEAN
NTAPI
PciComputeNewCurrentSettings(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PCM_RESOURCE_LIST ResourceList
);

NTSTATUS
NTAPI
PciSetResources(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ BOOLEAN DoReset,
    _In_ BOOLEAN SomethingSomethingDarkSide
);

NTSTATUS
NTAPI
PciBuildRequirementsList(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PPCI_COMMON_HEADER PciData,
    _Out_ PIO_RESOURCE_REQUIREMENTS_LIST* Buffer
);

// Identification Functions

PWCHAR
NTAPI
PciGetDeviceDescriptionMessage(
    _In_ UCHAR BaseClass,
    _In_ UCHAR SubClass
);

NTSTATUS
NTAPI
PciQueryDeviceText(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ DEVICE_TEXT_TYPE QueryType,
    _In_ ULONG Locale,
    _Out_ PWCHAR* Buffer
);

NTSTATUS
NTAPI
PciQueryId(
    _In_ PPCI_PDO_EXTENSION DeviceExtension,
    _In_ BUS_QUERY_ID_TYPE QueryType,
    _Out_ PWCHAR* Buffer
);

// CardBUS Support

VOID
NTAPI
Cardbus_MassageHeaderForLimitsDetermination(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context
);

VOID
NTAPI
Cardbus_SaveCurrentSettings(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context
);

VOID
NTAPI
Cardbus_SaveLimits(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context
);

VOID
NTAPI
Cardbus_RestoreCurrent(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context
);

VOID
NTAPI
Cardbus_GetAdditionalResourceDescriptors(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context,
    _In_ PPCI_COMMON_HEADER PciData,
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor
);

VOID
NTAPI
Cardbus_ResetDevice(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PPCI_COMMON_HEADER PciData
);

VOID
NTAPI
Cardbus_ChangeResourceSettings(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PPCI_COMMON_HEADER PciData
);

// PCI Device Support

VOID
NTAPI
Device_MassageHeaderForLimitsDetermination(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context
);

VOID
NTAPI
Device_SaveCurrentSettings(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context
);

VOID
NTAPI
Device_SaveLimits(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context
);

VOID
NTAPI
Device_RestoreCurrent(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context
);

VOID
NTAPI
Device_GetAdditionalResourceDescriptors(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context,
    _In_ PPCI_COMMON_HEADER PciData,
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor
);

VOID
NTAPI
Device_ResetDevice(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PPCI_COMMON_HEADER PciData
);

VOID
NTAPI
Device_ChangeResourceSettings(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PPCI_COMMON_HEADER PciData
);

// PCI-to-PCI Bridge Device Support

VOID
NTAPI
PPBridge_MassageHeaderForLimitsDetermination(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context
);

VOID
NTAPI
PPBridge_SaveCurrentSettings(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context
);

VOID
NTAPI
PPBridge_SaveLimits(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context
);

VOID
NTAPI
PPBridge_RestoreCurrent(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context
);

VOID
NTAPI
PPBridge_GetAdditionalResourceDescriptors(
    _In_ PPCI_CONFIGURATOR_CONTEXT Context,
    _In_ PPCI_COMMON_HEADER PciData,
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor
);

VOID
NTAPI
PPBridge_ResetDevice(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PPCI_COMMON_HEADER PciData
);

VOID
NTAPI
PPBridge_ChangeResourceSettings(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PPCI_COMMON_HEADER PciData
);

// Bus Number Routines

BOOLEAN
NTAPI
PciAreBusNumbersConfigured(
    _In_ PPCI_PDO_EXTENSION PdoExtension
);

// Routine Interface

NTSTATUS
NTAPI
PciCacheLegacyDeviceRouting(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG BusNumber,
    _In_ ULONG SlotNumber,
    _In_ UCHAR InterruptLine,
    _In_ UCHAR InterruptPin,
    _In_ UCHAR BaseClass,
    _In_ UCHAR SubClass,
    _In_ PDEVICE_OBJECT PhysicalDeviceObject,
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _Out_ PDEVICE_OBJECT* pFoundDeviceObject
);

VOID
NTAPI
RosDumpCmResourceDescriptor(
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor,
    _In_ ULONG DebugLevel
);

VOID
NTAPI
RosDumpIoResourceDescriptor(
    _In_ PIO_RESOURCE_DESCRIPTOR Descriptor,
    _In_ ULONG DebugLevel
);

// External Resources

extern SINGLE_LIST_ENTRY PciFdoExtensionListHead;
extern KEVENT PciGlobalLock;
extern PPCI_INTERFACE PciInterfaces[];
extern PCI_INTERFACE ArbiterInterfaceBusNumber;
extern PCI_INTERFACE ArbiterInterfaceMemory;
extern PCI_INTERFACE ArbiterInterfaceIo;
extern PCI_INTERFACE BusHandlerInterface;
extern PCI_INTERFACE PciRoutingInterface;
extern PCI_INTERFACE PciCardbusPrivateInterface;
extern PCI_INTERFACE PciLegacyDeviceDetectionInterface;
extern PCI_INTERFACE PciPmeInterface;
extern PCI_INTERFACE PciDevicePresentInterface;
extern PCI_INTERFACE PciNativeIdeInterface;
extern PCI_INTERFACE PciLocationInterface;
extern PCI_INTERFACE AgpTargetInterface;
extern PCI_INTERFACE TranslatorInterfaceInterrupt;
extern PDRIVER_OBJECT PciDriverObject;
extern PWATCHDOG_TABLE WdTable;
extern PPCI_HACK_ENTRY PciHackTable;
extern BOOLEAN PciAssignBusNumbers;
extern BOOLEAN PciEnableNativeModeATA;
extern PPCI_IRQ_ROUTING_TABLE PciIrqRoutingTable;
extern BOOLEAN PciExtendInterruptVector;
extern ULONG PciSystemWideHackFlags;
extern BOOLEAN PciLockDeviceResources;

/* Exported by NTOS, should this go in the NDK? */
extern NTSYSAPI BOOLEAN InitSafeBootMode;

#endif /* _PCIX_PCH_ */
