#ifndef _SCSIPORT_H_
#define _SCSIPORT_H_

/* INCLUDES *******************************************************************/

#include <ntifs.h>
#include <stdio.h>
#include <scsi.h>
#include <ntddscsi.h>
#include <ntdddisk.h>
#include <mountdev.h>
#include <initguid.h>
#include <wdmguid.h>
#include <devguid.h>

/* STRUCTURES ***************************************************************/

typedef struct _SCSI_HW_CHAIN_ENTRY
{
    HW_INITIALIZATION_DATA HwInitializationData;
    struct _SCSI_HW_CHAIN_ENTRY* Next;
} SCSI_HW_CHAIN_ENTRY, *PSCSI_HW_CHAIN_ENTRY;

typedef struct _SCSIPORT_DRIVER_EXTENSION
{
    PDRIVER_OBJECT DriverObject;
    UNICODE_STRING RegistryPath;
    PSCSI_HW_CHAIN_ENTRY ChainHeader;
    LONG Counter;
    ULONG BusType;
    BOOLEAN LegacyAdapterDetection;
    ULONG PnpInterfaceCount;
    ULONG IgnoreInitLegacyStatus;
} SCSI_PORT_DRIVER_EXTENSION, *PSCSI_PORT_DRIVER_EXTENSION;

typedef struct _SCSI_PORT_GUID_INTERFACE_MAPPING
{
    GUID Guid;
    INTERFACE_TYPE InterfaceType;
} SCSI_PORT_GUID_INTERFACE_MAPPING, *PSCSI_PORT_GUID_INTERFACE_MAPPING;

typedef struct _SCSI_PNP_INTERFACE
{
    INTERFACE_TYPE InterfaceType;
    ULONG Flags;
} SCSI_PNP_INTERFACE, *PSCSI_PNP_INTERFACE;

typedef struct _SCSI_PORT_ENUM_REQUEST
{
    struct _SCSI_PORT_ENUM_REQUEST* NextRequest;
    PVOID CompletionRoutine;
    PIO_STATUS_BLOCK IoStatus;
    PIRP Irp;
    BOOLEAN IsNotCompleteEnumRequest;
} SCSI_PORT_ENUM_REQUEST, *PSCSI_PORT_ENUM_REQUEST;

typedef struct _SCSI_PORT_SRB_DATA SCSI_PORT_SRB_DATA, *PSCSI_PORT_SRB_DATA;
typedef struct _SCSI_PORT_DEVICE_EXTENSION SCSI_PORT_DEVICE_EXTENSION, *PSCSI_PORT_DEVICE_EXTENSION;

typedef
VOID
(FASTCALL* PSP_FREE_SRBDATA)(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ PSCSI_PORT_SRB_DATA SrbData
);

typedef struct _SCSI_PORT_SRB_DATA
{
    SINGLE_LIST_ENTRY QueueTagsLink;
    USHORT Type;
    USHORT Size;
    PSP_FREE_SRBDATA FreeRoutine;
    LIST_ENTRY Link;
    ULONG Flags;
    struct _SCSI_PORT_LUN_EXTENSION* LunExtension;
    PIRP CurrentIrp;
    PSCSI_REQUEST_BLOCK CurrentSrb;
    PVOID CompletedRequests;
    ULONG OriginalDataTransferLength;
    struct _SCSI_PORT_DEVICE_EXTENSION* DeviceExtension;
    LONG QueueTag;
    PMDL RemappedMdl;
    PVOID ScatterGatherList;
} SCSI_PORT_SRB_DATA, *PSCSI_PORT_SRB_DATA;

typedef struct _SCSI_PORT_INTERRUPT_DATA
{
    ULONG Flags;
    PVOID CompletedRequests;
    struct _SCSI_PORT_LUN_EXTENSION* ReadyLogicalUnit;
    struct _SCSI_PORT_LUN_EXTENSION* AbortLogicalUnit;
    PHW_INTERRUPT HwTimerInt;
    ULONG MiniportTimerValue;
} SCSI_PORT_INTERRUPT_DATA, *PSCSI_PORT_INTERRUPT_DATA;

typedef struct _SCSI_PORT_ADDRESS_MAPPING
{
    struct _SCSI_PORT_ADDRESS_MAPPING* Next;
    PVOID MappedAddress;
    ULONG NumberOfBytes;
    SCSI_PHYSICAL_ADDRESS Address;
    ULONG SystemIoBusNumber;
} SCSI_PORT_ADDRESS_MAPPING, *PSCSI_PORT_ADDRESS_MAPPING;

typedef struct _SCSI_PORT_QUEUETAGS_ENTRY
{
    SINGLE_LIST_ENTRY Link;
    LONG Tag;
} SCSI_PORT_QUEUETAGS_ENTRY, *PSCSI_PORT_QUEUETAGS_ENTRY;

typedef struct _SCSI_PORT_COMPLETION_CONTEXT
{
    NTSTATUS Status;
    KEVENT Event;
} SCSI_PORT_COMPLETION_CONTEXT, *PSCSI_PORT_COMPLETION_CONTEXT;

typedef
BOOLEAN
(NTAPI* PSCSI_PORT_SYNCHRONIZE_EXECUTION)(
    _In_ PKINTERRUPT Interrupt,
    _In_ PKSYNCHRONIZE_ROUTINE Function,
    _In_ PVOID Context
);

typedef struct _SCSI_PORT_DEVICE_MAP_ENTRY
{
    HANDLE ScsiBusHandle;
    HANDLE InitiatorIdHandle;
} SCSI_PORT_DEVICE_MAP_ENTRY, *PSCSI_PORT_DEVICE_MAP_ENTRY;

typedef struct _COMMON_EXTENSION
{
    PDEVICE_OBJECT SelfDevice;
    struct
    {
        BOOLEAN IsPdo : 1;
        BOOLEAN IsInitialized : 1;
        BOOLEAN WmiInitialized : 1;
        BOOLEAN WmiDataProvider : 1;
        BOOLEAN Reserved2 : 1;
        BOOLEAN Reserved3 : 1;
        BOOLEAN Reserved4 : 1;
        BOOLEAN Reserved5 : 1;
    };
    UCHAR CurrentPnpState;
    UCHAR PreviousPnpState;
    ULONG IsRemoved;
    PDEVICE_OBJECT LowDevice;
    ULONG DefaultRequestFlags;
    PDRIVER_DISPATCH* MajorFunction;
    SYSTEM_POWER_STATE CurrentSystemState;
    DEVICE_POWER_STATE CurrentDeviceState;
    LONG RemoveLock;
    KEVENT Event;
    NPAGED_LOOKASIDE_LIST LookAsideList;
    ULONG PagingPathCount;
} COMMON_EXTENSION, *PCOMMON_EXTENSION;

/* PDO */
typedef struct _SCSI_PORT_LUN_EXTENSION
{
    COMMON_EXTENSION CommonExtension;
    ULONG LuFlags;
    ULONG Port;
    BOOLEAN DeviceClaimed;
    BOOLEAN IsEnumerated;
    BOOLEAN IsMissing;
    BOOLEAN IsVisible;
    BOOLEAN IsMismatchedDevice;
    BOOLEAN IsTemporary;
    ULONG NeedsVerification;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    PVOID SpecificLuExtension;
    struct _SCSI_PORT_DEVICE_EXTENSION* DeviceExtension;
    PVOID CurrentLockRequest;
    struct _SCSI_PORT_LUN_EXTENSION* NextLogicalUnit;
    struct _SCSI_PORT_LUN_EXTENSION* ReadyLogicalUnit;
    struct _SCSI_PORT_LUN_EXTENSION* AbortLogicalUnit;
    LONG RequestTimeoutCounter;
    LIST_ENTRY SrbDataList;
    PSCSI_PORT_SRB_DATA CurrentUntaggedRequest;
    UCHAR QueueDepth;
    INQUIRYDATA InquiryData;
    PVOID ActiveFailedRequest;
    PVOID BlockedFailedRequest;
    PLUN_LIST TargetLunList;
    ULONG SpecialTargetList[6];
    ANSI_STRING SerialNumber;
    PVPD_IDENTIFICATION_PAGE DeviceIdentifierPage;
    ULONG DeviceIdentifierPageSize;
    ULONG Capacity;
    ULONG QueueZoneCount;
    ULONG QueueZoneLength;
    ULONG MinQueueSector[4];
    ULONG MaxQueueSector[4];
    ULONG CurrentQueueZone;
    ULONG QueuePerZone;
    ULONG QueueSector[4];
    UCHAR QueuePerBlock[4];
    ULONG QueueZones[4];
    LIST_ENTRY BlockedRequests;
} SCSI_PORT_LUN_EXTENSION, *PSCSI_PORT_LUN_EXTENSION;

typedef struct _SCSI_PORT_LUN_ENTRY
{
    KSPIN_LOCK SpinLock;
    PSCSI_PORT_LUN_EXTENSION LunExtension;
} SCSI_PORT_LUN_ENTRY, *PSCSI_PORT_LUN_ENTRY;

/* FDO */
typedef struct _SCSI_PORT_DEVICE_EXTENSION
{
    COMMON_EXTENSION CommonExtension;
    PDEVICE_OBJECT LowerPdo;
    PVOID HwDeviceExtension;
    PVOID UncachedExtension;
    ULONG UncachedExtensionSize;
    ULONG PortScsiPort;
    ULONG PortScsi;
    LONG ActiveRequestCount;
    UCHAR Flags2;
    PCI_SLOT_NUMBER PciSlotNumber;
    ULONG BusNumber;
    ULONG SlotNumber;
    UCHAR NumberOfBuses;
    UCHAR MaximumNumberOfTargets;
    UCHAR MaximumLogicalUnit;
    ULONG Flags;
    ULONG DpcFlags;
    ULONG DisableCount;
    LONG TimeOut;
    PKINTERRUPT InterruptObject;
    PSCSI_PORT_SYNCHRONIZE_EXECUTION SynchronizeFunction;
    KSPIN_LOCK SpinLock;
    KSPIN_LOCK IrqLock;
    KSPIN_LOCK MiniPortLock;
    PVOID MapRegisterBase;
    PDMA_ADAPTER DmaAdapter;
    PPORT_CONFIGURATION_INFORMATION PortConfig;
    PCM_RESOURCE_LIST AllocatedResources;
    PCM_RESOURCE_LIST AllocatedResourcesTranslated;
    ULONG CommonBufferSize;
    ULONG SrbExtensionSize;
    BOOLEAN IsNotCacheAlignedCommonBuffer;
    ULONG NumberOfRequests;
    PVOID CommonBuffer;
    PVOID* SrbExtensionList;
    SLIST_HEADER QueueTagsListHead;
    PSCSI_PORT_QUEUETAGS_ENTRY QueueTagsList;
    UCHAR MaxQueueTag;
    ULONG SpecificLuExtensionSize;
    PSCSI_PORT_ADDRESS_MAPPING CurrentAddressMapping;
    PSCSI_PORT_ADDRESS_MAPPING AddressMapping;
    PHW_FIND_ADAPTER HwFindAdapter;
    PHW_INITIALIZE HwInitialize;
    PHW_STARTIO HwStartIo;
    PHW_INTERRUPT HwInterrupt;
    PHW_RESET_BUS HwResetBus;
    PHW_DMA_STARTED HwDmaStarted;
    PHW_INTERRUPT HwTimerInt;
    PHW_ADAPTER_CONTROL HwAdapterControl;
    ULONG BusInterruptLevel;
    ULONG IoAddress;
    RTL_BITMAP ScsiControlBitMap;
    ULONG ScsiControlBitMapBuffer;
    SCSI_PORT_LUN_ENTRY LunList[8];
    PSCSI_PORT_LUN_EXTENSION SrbDataLunExt;
    SCSI_PORT_INTERRUPT_DATA InterruptData;
    IO_SCSI_CAPABILITIES IoScsiCapabilities;
    KTIMER MiniPortTimer;
    KDPC MiniPortDpc;
    PHYSICAL_ADDRESS PhysicalCommonBuffer;
    UCHAR MapBuffers;
    BOOLEAN IsRemapBuffers;
    BOOLEAN NeedPhAddrForMasterDma;
    BOOLEAN TaggedQueuing;
    BOOLEAN AutoRequestSense;
    BOOLEAN MultipleRequestPerLu;
    BOOLEAN ReceiveEvent;
    BOOLEAN IsSrbExtensions;
    BOOLEAN CachesData;
    BOOLEAN Dma64BitAddresses;
    BOOLEAN Dma32BitAddresses;
    KMUTEX EnumMutex;
    FAST_MUTEX EnumFastMutex;
    LARGE_INTEGER EnumTime;
    LONG RunEnumSync;
    WORK_QUEUE_ITEM EnumWorkItem;
    PKTHREAD CurrentThread;
    BOOLEAN EnumerationRunning;
    PSCSI_PORT_ENUM_REQUEST RequestHead;
    PSCSI_PORT_ENUM_REQUEST AsyncEnumRequest;
    SCSI_PORT_ENUM_REQUEST EnumRequest;
    NPAGED_LOOKASIDE_LIST SrbDataLookAsideList;
    KSPIN_LOCK SrbDataSpinLock;
    LIST_ENTRY BlockedRequestList;
    PSCSI_PORT_SRB_DATA SrbData;
    BOOLEAN IsSrbDataList;
    BOOLEAN LowerBusInterfaceStandardRetrieved;
    HANDLE ScsiPortKeyHandle;
    PSCSI_PORT_DEVICE_MAP_ENTRY DeviceMapEntry;
    BUS_INTERFACE_STANDARD Interface;
    PWCHAR DeviceNameBuffer;
    GUID BusTypeGuid;
    UNICODE_STRING SymbolicLinkName;
    ULONG PnpDeviceState;
    PVOID InquiryData;
    PSENSE_DATA InquirySenseData;
    PIRP InquiryIrp;
    PMDL InquiryMdl;
    FAST_MUTEX PoFastMutex;
    PVOID RescanLun;
    UCHAR SenseDataBytes;
    PVOID VerifierExtension;
    PHYSICAL_ADDRESS MinimumUCXAddress;
    PHYSICAL_ADDRESS MaximumUCXAddress;
    PVOID ReservedMapping;
    PMDL ReservedMdl;
    ULONG RemainInReducedMaxQueueState;
    ULONG UncachedExtAlignment;
    ULONG TimeoutValue;
    BOOLEAN IsRequestQueue;
    ULONG ResetHoldTime;
    PVOID InitiatorLun;
    UCHAR CreateInitiatorLU;
    PSCSI_PORT_LUN_EXTENSION BlockedLun;
} SCSI_PORT_DEVICE_EXTENSION, *PSCSI_PORT_DEVICE_EXTENSION;

typedef struct _SCSI_PORT_HW_DATA
{
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    UCHAR HwDeviceExtension[0];
} SCSI_PORT_HW_DATA, *PSCSI_PORT_HW_DATA;

typedef struct _SCSI_PORT_CONFIG_CONTEXT
{
    UCHAR DisableTaggedQueuing;
    UCHAR DisableMultipleRequests;
    ULONG AdapterNumber;
    ULONG BusNumber;
    PCHAR DriverParameters;
    PVOID AccessRanges;
    PORT_CONFIGURATION_INFORMATION PortConfig;
} SCSI_PORT_CONFIG_CONTEXT, *PSCSI_PORT_CONFIG_CONTEXT;

typedef struct _SCSI_PORT_GET_INT_STATE_CONTEXT
{
    PSCSI_PORT_DEVICE_EXTENSION DeviceExtension;
    PSCSI_PORT_INTERRUPT_DATA InterruptData;
} SCSI_PORT_GET_INT_STATE_CONTEXT, *PSCSI_PORT_GET_INT_STATE_CONTEXT;

typedef union _LUN_LIST_LENGTH
{
    UCHAR LunListLength[4];
    ULONG AsUlong;
} LUN_LIST_LENGTH, *PLUN_LIST_LENGTH;

typedef union _LUN_LIST_ENTRY
{
    UCHAR LunListEntry[2];
    USHORT AsUshort;
} LUN_LIST_ENTRY, *PLUN_LIST_ENTRY;

typedef struct _SCSI_PORT_LUN_LIST
{
    UCHAR LunListLength[4];
    UCHAR Reserved[4];
    UCHAR Lun[0x10][8];
} SCSI_PORT_LUN_LIST, *PSCSI_PORT_LUN_LIST;

/* FUNCTIONS ****************************************************************/

#ifndef Add2Ptr
  #define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#endif

VOID
NTAPI
SpInitializeRequestSenseParams(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
SpGetCommonBuffer(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension,
    _In_ ULONG NumberOfBytes
);

PVOID
NTAPI
SpGetSrbExtensionBuffer(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension
);

VOID
NTAPI
SpInitializePowerParams(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension
);

VOID
NTAPI
SpInitializePerformanceParams(
    _In_ PSCSI_PORT_DEVICE_EXTENSION DeviceExtension
);

NTSTATUS
NTAPI
SpBuildDeviceMapEntry(
    _In_ PVOID DeviceObjectExtension
);

#endif /* _SCSIPORT_H_ */

/* EOF */
