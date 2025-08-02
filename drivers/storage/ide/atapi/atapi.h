#ifndef _PCIIDEX_PCH_
#define _PCIIDEX_PCH_

/* INCLUDES *******************************************************************/

#include <ntifs.h>
#include <ide.h>
#include <stdio.h>
#include <initguid.h>
#include <wdmguid.h>
#include <ndk/rtlfuncs.h>
#include <srb.h>
#include <acpiioct.h>
#include <ntddscsi.h> 
#include <ntddstor.h> 
#include <ntdddisk.h> 
#include <scsi.h> 
#include <ata.h> 

/* ACPI EVAL ****************************************************************/

/* 9.9.2.1.1 _GTM (Get Timing Mode) */

#define IDE_ACPI_TIMING_MODE_FLAG_UDMA                 0x00000001
#define IDE_ACPI_TIMING_MODE_FLAG_IORDY                0x00000002
#define IDE_ACPI_TIMING_MODE_FLAG_UDMA2                0x00000004
#define IDE_ACPI_TIMING_MODE_FLAG_IORDY2               0x00000008
#define IDE_ACPI_TIMING_MODE_FLAG_INDEPENDENT_TIMINGS  0x00000010
#define IDE_ACPI_TIMING_MODE_NOT_SUPPORTED             0xFFFFFFFF

typedef struct _IDE_ACPI_TIMING_MODE_BLOCK
{
    struct
    {
        ULONG PioSpeed;
        ULONG DmaSpeed;
    } Drive[MAX_IDE_DEVICE];
    ULONG ModeFlags;
} IDE_ACPI_TIMING_MODE_BLOCK, *PIDE_ACPI_TIMING_MODE_BLOCK;

/* STRUCTURES ***************************************************************/

DEFINE_GUID(GUID_PCIIDE_BUSMASTER_INTERFACE,      0x681190EA, 0xE4EA, 0x11D0, 0xAB, 0x82, 0x00, 0xA0, 0xC9, 0x06, 0x96, 0x2F);
DEFINE_GUID(GUID_PCIIDE_SYNC_ACCESS_INTERFACE,    0x681190EB, 0xE4EA, 0x11D0, 0xAB, 0x82, 0x00, 0xA0, 0xC9, 0x06, 0x96, 0x2F);
DEFINE_GUID(GUID_PCIIDE_XFER_MODE_INTERFACE,      0x681190EC, 0xE4EA, 0x11D0, 0xAB, 0x82, 0x00, 0xA0, 0xC9, 0x06, 0x96, 0x2F);
DEFINE_GUID(GUID_PCIIDE_REQUEST_PROPER_RESOURCES, 0x681190ED, 0xE4EA, 0x11D0, 0xAB, 0x82, 0x00, 0xA0, 0xC9, 0x06, 0x96, 0x2F);
DEFINE_GUID(GUID_PCIIDE_INTERRUPT_INTERFACE,      0x681190EE, 0xE4EA, 0x11D0, 0xAB, 0x82, 0x00, 0xA0, 0xC9, 0x06, 0x96, 0x2F);

#define IDE_DRIVE_SELECT    0xA0 

typedef struct _ATAPI_DRIVER_EXTENSION
{
    UNICODE_STRING RegistryPath;
} ATAPI_DRIVER_EXTENSION, *PATAPI_DRIVER_EXTENSION;

typedef struct _IDE_WAIT_CONTEXT
{
    KEVENT Event;
    NTSTATUS Status;
} IDE_WAIT_CONTEXT, *PIDE_WAIT_CONTEXT;

typedef struct _ATAPI_SET_POWER_CONTEXT
{
    BOOLEAN IsTimingsRestored;
    UCHAR Pad[3];
    PIRP Irp;
    POWER_STATE_TYPE Type;
    POWER_STATE State;
} ATAPI_SET_POWER_CONTEXT, *PATAPI_SET_POWER_CONTEXT;

typedef struct _IDE_RESOURCE_DATA
{
    ULONG TypeResForCmdBlock;
    ULONG TypeResForCtrlBlock;
    ULONG CmdBlockBase;
    ULONG CtrlBlockBase;
    ULONG IntResFlags;
    ULONG Vector;
    BOOLEAN PrimaryClaimed;
    BOOLEAN SecondaryClaimed;
} IDE_RESOURCE_DATA, *PIDE_RESOURCE_DATA;

typedef struct _IDE_CMD_BLOCK_REGS
{
    PUCHAR CmdBlockBase;
    PUSHORT Data;
    union
    {
        PUCHAR Error;           /* read */
        PUCHAR Features;        /* write */
    };
    union
    {
        PUCHAR SectorCount;
        PUCHAR InterruptReason; /* read ATAPI */
    };
    PUCHAR LbaLow;
    union
    {
        PUCHAR LbaMid;          /* ATA LBA */
        PUCHAR BytesLow;        /* ATAPI */
    };
    union
    {
        PUCHAR LbaHigh;         /* ATA LBA */
        PUCHAR BytesHigh;       /* ATAPI */
    };
    PUCHAR DeviceSelect;
    union
    {
        PUCHAR Status;          /* read */
        PUCHAR Command;         /* write */
    };
} IDE_CMD_BLOCK_REGS, *PIDE_CMD_BLOCK_REGS;

typedef struct _IDE_CTRL_BLOCK_REGS
{
    PUCHAR CtrlBlockBase;
    union
    {
        PUCHAR AltStatus;       /* read */
        PUCHAR DeviceControl;   /* write */
    };
    PUCHAR Control;
} IDE_CTRL_BLOCK_REGS, *PIDE_CTRL_BLOCK_REGS;

typedef union _ATA_SCSI_ADDRESS
{
    /* The ordering between Lun, TargetId, and PathId is important */
    struct
    {
        UCHAR Lun;      // 0-8
        UCHAR TargetId; // 0 - Master, 1 - Slave
        UCHAR PathId;   // 0 - Primary, 1 - Secondary
        UCHAR Reserved;
    };
    ULONG AsULONG;
} ATA_SCSI_ADDRESS, *PATA_SCSI_ADDRESS;

typedef struct _IDE_TRANSFER_MODE_INTERFACE
{
    ULONG IsTransferModeSelect;
    PVOID MiniControllerExtension;
    PVOID TransferModeSelect;
    PVOID PciIdeUseDma;
    PVOID Context;
    PVOID TransferModeTimingTable;
    ULONG TableLength;
    PVOID PciIdeUdmaModesSupported;
} IDE_TRANSFER_MODE_INTERFACE, *PIDE_TRANSFER_MODE_INTERFACE;

typedef struct _PCIIDE_INTERRUPT_INTERFACE
{
    PVOID InterruptControl;
    PVOID Context;
} PCIIDE_INTERRUPT_INTERFACE, *PPCIIDE_INTERRUPT_INTERFACE;

typedef struct _IDE_SYNC_ACCESS_INTERFACE
{
    PVOID AllocateAccessToken;
    PVOID FreeAccessToken;
    PVOID Context;
} IDE_SYNC_ACCESS_INTERFACE, *PIDE_SYNC_ACCESS_INTERFACE;

typedef struct _PCIIDE_BUS_MASTER_INTERFACE
{
    ULONG Size;
    ULONG SupportedTransferMode[4];
    ULONG MaximumPhysicalSize;
    PVOID Context;
    PVOID BmSetup;
    PVOID BmArm;
    PVOID BmDisarm;
    PVOID BmFlush;
    PVOID BmStatus;
    PVOID BmTimingSetup;
    BOOLEAN IgnoreActiveBitForAtaDevice;
    BOOLEAN AlwaysClearBusMasterInterrupt;
    ULONG ContextSize;
    PVOID BmSetupOnePage;
    PVOID BmCrashDumpInitialize;
    PVOID BmFlushAdapterBuffers;
} PCIIDE_BUS_MASTER_INTERFACE, *PPCIIDE_BUS_MASTER_INTERFACE;

typedef VOID (NTAPI* CHANNEL_REQUEST_PROPER_RESOURCES)(_In_ PDEVICE_OBJECT DeviceObject);

typedef struct _PCIIDE_PROPER_RESOURCES
{
    CHANNEL_REQUEST_PROPER_RESOURCES ChannelRequestProperResources;
} PCIIDE_PROPER_RESOURCES, *PPCIIDE_PROPER_RESOURCES;

typedef struct _ATAPI_ENUM_WORKITEM_CONTEXT
{
    PIO_WORKITEM WorkItem;
    PIRP Irp;
} ATAPI_ENUM_WORKITEM_CONTEXT, *PATAPI_ENUM_WORKITEM_CONTEXT;

typedef struct _ATA_PASS_THROUGH
{
    IDEREGS IdeReg;
    ULONG BufferSize;
    UCHAR Buffer[1];
} ATA_PASS_THROUGH, *PATA_PASS_THROUGH;

typedef struct _ATA_PASS_THROUGH_CONTEXT
{
    PDEVICE_OBJECT DeviceObject;
    PVOID CallBack;
    PVOID CallBackContext;
    PSCSI_REQUEST_BLOCK Srb;
    PVOID SenseInfoBuffer;
    BOOLEAN MustSucceed;
    UCHAR Pad[3];
    PATA_PASS_THROUGH AtaPassThr;
} ATA_PASS_THROUGH_CONTEXT, *PATA_PASS_THROUGH_CONTEXT;

typedef struct _IDE_STOP_QUEUE_CONTEX
{
    struct _PDO_DEVICE_EXTENSION* PdoExtension;
    KEVENT Event;
    ULONG QueueStopFlag;
    NTSTATUS Status;
    ATA_PASS_THROUGH AtaPassThr;
} IDE_STOP_QUEUE_CONTEX, *PIDE_STOP_QUEUE_CONTEX;

typedef struct _ATAPI_PRE_ALLOC_ENUM_STRUCT
{
    PIRP Irp;
    PSCSI_REQUEST_BLOCK Srb;
    PSENSE_DATA SenseInfoBuffer;
    PMDL Mdl;
    PVOID DataBuffer;
    ULONG DataBufferSize;
    PIDE_STOP_QUEUE_CONTEX StopQueueContext;
    PATAPI_ENUM_WORKITEM_CONTEXT EnumWorkItemContext;
    PATA_PASS_THROUGH_CONTEXT AtaPassThrContext;
} ATAPI_PRE_ALLOC_ENUM_STRUCT, *PATAPI_PRE_ALLOC_ENUM_STRUCT;

typedef struct _ATA_DEVICE_PARAMETERS
{
    ULONG MaxTransferSize;
    UCHAR IdePioReadCommand;
    UCHAR IdePioWriteCommand;
    UCHAR IdePioFlushCommand;
    UCHAR IdePioReadCommandExt;
    UCHAR IdePioWriteCommandExt;
    UCHAR IdePioFlushCommandExt;
    BOOLEAN IoReadySupported;
    UCHAR Pad;
    ULONG BestPioCycleTime;
    ULONG BestSwDmaCycleTime;
    ULONG BestMwDmaCycleTime;
    ULONG BestUDmaCycleTime;
    ULONG XferModeBitMap;
    ULONG BestPioXferMode;
    ULONG BestSwDmaXferMode;
    ULONG BestMwDmaXferMode;
    ULONG BestUDmaXferMode;
    ULONG XferCurrentMode;
    ULONG XferSelectedMode;
    ULONG XferMaskMode;
} ATA_DEVICE_PARAMETERS, *PATA_DEVICE_PARAMETERS;

typedef struct _ATA_DEVICE_EXTENSION
{
    PSCSI_REQUEST_BLOCK CurrentSrb;
    IDE_CMD_BLOCK_REGS CmdBlock;
    IDE_CTRL_BLOCK_REGS CtrlBlock;
    ULONG CmdBlockLength;
    ULONG CtrlBlockLength;
    ULONG MaxIdeDevice;
    ULONG NumberOfCylinders[4];
    ULONG NumberOfHeads[4];
    ULONG SectorsPerTrack[4];
    ULONG IntResFlags;
    PUCHAR TransferDataBuffer;
    ULONG TransferDataBytes;
    ULONG TimeOutLock[4];
    ULONG MultiLun[4];
    ULONG DeviceFlags[4];
    ULONG MaxIdeTargetId;
    ULONG EmptyDevice;
    ULONG EmptyWaitCount;
    ULONG EmptyResult;
    UCHAR MaximumBlockTransfer[4];
    UCHAR ExpectingInterrupt;
    BOOLEAN IsActiveDmaTransfer;
    BOOLEAN IsCdbSaved;
    BOOLEAN IsDscRestrictive;
    BOOLEAN IsDriverMustPoll;
    BOOLEAN IsPrimary;
    BOOLEAN IsSecondary;
    BOOLEAN IsTransferModeNotSelected;
    UCHAR ScsiCdb[0x10];
    UCHAR TypeSmartCommand;
    UCHAR CmdErrorCopy;
    IDENTIFY_DATA IdentifyData[4];
    PCIIDE_BUS_MASTER_INTERFACE BusMasterInterface;
    ATA_DEVICE_PARAMETERS DeviceParameters[4]; 
    ULONG BusyCount;
    ULONG States[2][17];
} ATA_DEVICE_EXTENSION, *PATA_DEVICE_EXTENSION;

typedef struct _PDOX_SRB_DATA
{
    LIST_ENTRY Requests;
    PSCSI_REQUEST_BLOCK CurrentSrb;
    PVOID CompletedRequests;
    ULONG RetryCount;
    ULONG SequenceNumber;
    PVOID Buffer;
    PVOID CommandLog;
    ULONG CommandLogCount;
    ULONG Flags;
} PDOX_SRB_DATA, *PPDOX_SRB_DATA;

typedef struct _ATAPI_INTERRUPT_DATA
{
    ULONG Flags;
    PPDOX_SRB_DATA CompletedRequests;
    UCHAR ErrorEntry[20];//FIXME
    struct _PDO_DEVICE_EXTENSION* CompletedAbort;
    PHW_TIMER HwTimerCallBack;
    LONG MiniportTimerValue;
    struct _PDO_DEVICE_EXTENSION* PdoExtensionResetBus;
} ATAPI_INTERRUPT_DATA, *PATAPI_INTERRUPT_DATA;

typedef struct _ATAPI_INIT_DATA
{
    ULONG Count;
    IDEREGS IdeReg[0];
} ATAPI_INIT_DATA, *PATAPI_INIT_DATA;

typedef struct _FDO_DEVICE_EXTENSION
{
    PDEVICE_OBJECT LowDevice;
    PDEVICE_OBJECT LowPdo;
    PDRIVER_OBJECT DriverObject;
    PDEVICE_OBJECT SelfDevice;
    ULONG Paging;
    ULONG Hibernation;
    ULONG DumpFile;
    SYSTEM_POWER_STATE SystemPowerState;
    DEVICE_POWER_STATE DevicePowerState;
    PIRP PendingSystemPowerIrp;
    PIRP PendingDevicePowerIrp;
    PDRIVER_DISPATCH PassDownToNextDriver;
    PDRIVER_DISPATCH* FdoPnpDispatchTable;
    PDRIVER_DISPATCH* FdoPowerDispatchTable;
    PDRIVER_DISPATCH* FdoWmiDispatchTable;
    PCM_RESOURCE_LIST ChannelResources;
    IDE_RESOURCE_DATA ResourceData;
    IDE_SYNC_ACCESS_INTERFACE SyncAccessInterface;
    IDE_TRANSFER_MODE_INTERFACE TransferModeInterface;
    PCIIDE_PROPER_RESOURCES ProperResources;
    PATA_DEVICE_EXTENSION HwDeviceExtension;
    BOOLEAN IsBmIfaceReceived;
    BOOLEAN SymlinkCreated;
    ULONG FdoIndex;
    ULONG ScsiPortCount;
    ULONG Flags;
    ULONG FdoState; 
    LONG TimeOutValue;
    ULONG ResetCallAgain;
    PSCSI_REQUEST_BLOCK ResetSrb;
    UCHAR MaxPdoCount;
    PKINTERRUPT InterruptObject;
    ULONG SequenceNumber;
    KSPIN_LOCK SpinLock;
    PHW_TIMER TimerCallBack;
    KSPIN_LOCK PdoArrayLock;
    UCHAR PdoCount1;
    UCHAR PdoCount2;
    BOOLEAN IsNeedUpdate;
    UCHAR HackFlags;
    ULONG PcmciaIdeHasSlaveDevice;
    struct _PDO_DEVICE_EXTENSION* PdoArray[8];
    ATAPI_INTERRUPT_DATA InterruptData;
    IO_SCSI_CAPABILITIES IoScsicapabilities;
    KTIMER Timer;
    KDPC Dpc;
    IDE_ACPI_TIMING_MODE_BLOCK TimingBlock0;
    IDE_ACPI_TIMING_MODE_BLOCK TimingBlock;
    PVOID DefaultTransferModeTimingTable;
    ULONG DmaDetectionLevel;
    ULONG DeviceParameter[4];
    ULONG UserChoiceTransferMode[4];
    ULONG UserChoiceAtapiTransferMode[4];
    ULONG TMAllowed[4];
    ATAPI_SET_POWER_CONTEXT PowerContext[2];
    LONG PowerContextLock[2];
    LONG EnumStructLock;
    PATAPI_PRE_ALLOC_ENUM_STRUCT PreAllocEnumStruct;
    PVOID ErrorLog[2];
    PVOID ReservedPages;
    PCIIDE_INTERRUPT_INTERFACE InterruptInterface;
    ULONG IsBigLbaEnabled;
    ULONG ResetErrorCountersOnSuccess;
    ATA_DEVICE_EXTENSION AtaExt;
} FDO_DEVICE_EXTENSION, *PFDO_DEVICE_EXTENSION;

typedef struct _PDO_DEVICE_EXTENSION
{
    PDEVICE_OBJECT LowDevice;
    PDEVICE_OBJECT LowPdo;
    PDRIVER_OBJECT DriverObject;
    PDEVICE_OBJECT SelfDevice;
    ULONG Paging;
    ULONG Hibernation;
    ULONG DumpFile;
    SYSTEM_POWER_STATE SystemPowerState;
    DEVICE_POWER_STATE DevicePowerState;
    PDRIVER_DISPATCH NoSupportIrp;
    PDRIVER_DISPATCH* PdoPnpDispatchTable;
    PDRIVER_DISPATCH* PdoPowerDispatchTable;
    PDRIVER_DISPATCH* PdoWmiDispatchTable;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PULONG IdleCounter;
    KEVENT Event;
    LONG TimeoutErrors;
    LONG DmaTimeouts;
    LONG FlushCacheTimeouts;
    LONG CrcErrors;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR RetriesDoRequest;
    ULONG PdoFlags;
    ULONG SortKey;
    struct _PDO_DEVICE_EXTENSION* LinkPdoExt;
    PSCSI_REQUEST_BLOCK AbortSrb;
    struct _PDO_DEVICE_EXTENSION* CompletedAbort;
    LONG TimeOut;
    PIRP PendingRequest;
    PIRP BusyRequest;
    PDOX_SRB_DATA PdoxSrbData;
    UCHAR ScsiDeviceType;
    UCHAR ModelId[0x29];
    UCHAR RevisionId[9];
    UCHAR SerialNumId[0x29];
    BOOLEAN IsWriteCache;
    KSPIN_LOCK PdoLock;
    PDEVICE_OBJECT Pdo;
    LONG ReferenceCount;
    ULONG PdoState;
    LONG Unknown1;
    ULONG DataCheckSum;
    PATAPI_INIT_DATA InitData;
    LONG ItemsQueued;
} PDO_DEVICE_EXTENSION, *PPDO_DEVICE_EXTENSION;

typedef struct _ATAPI_RESET_BUS_CONTEXT
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    UCHAR PathId;
    BOOLEAN IsUpdateResetSrb;
    UCHAR Pad[2];
    PSCSI_REQUEST_BLOCK Srb;
} ATAPI_RESET_BUS_CONTEXT, *PATAPI_RESET_BUS_CONTEXT;

typedef struct _ATA_DETECT_DEVICE_CONTEXT
{
    ATA_PASS_THROUGH AtaPassThr;
    IDENTIFY_DATA Identify;
} ATA_DETECT_DEVICE_CONTEX, *PATA_DETECT_DEVICE_CONTEX;

typedef struct _REQUEST_SENSE_CONTEXT
{
    SCSI_REQUEST_BLOCK Srb;
    PSCSI_REQUEST_BLOCK FailingSrb;
} REQUEST_SENSE_CONTEXT, *PREQUEST_SENSE_CONTEXT;

typedef struct _ATAPI_DEVICE_STATE_CONTEXT
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    ULONG State[2];
    ULONG MaxState;
    ULONG CountStates;
    ULONG CountInits;
    LONG FailedInits;
    PVOID CallBack;
    PVOID CallBackContext;
    ATA_PASS_THROUGH AtaPassThr;
} ATAPI_DEVICE_STATE_CONTEXT, *PATAPI_DEVICE_STATE_CONTEXT;

typedef struct _IDE_READ_CAPACITY_CONTEXT
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    PIRP Irp;
    PVOID DataBuffer;
    ATA_PASS_THROUGH AtaPassThr;
    IDENTIFY_DATA IdentifyData;
} IDE_READ_CAPACITY_CONTEXT, *PIDE_READ_CAPACITY_CONTEXT;

/* ACPI EVAL ****************************************************************/

typedef struct _ACPI_EVAL_SIGNATURE
{
    union
    {
        CHAR Char[4];
        ULONG AsULONG;
    };
} ACPI_EVAL_SIGNATURE, *PACPI_EVAL_SIGNATURE; 

/* FUNCTIONS ****************************************************************/

#ifndef Add2Ptr
  #define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#endif
#ifndef Or2Ptr
  #define Or2Ptr(P,Or) ((PVOID)((ULONG_PTR)(P) | (Or)))
#endif
#ifndef And2Ptr
  #define And2Ptr(P,And) ((PVOID)((ULONG_PTR)(P) & (And)))
#endif

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS NTAPI IdePortStatusSuccessAndPassDownToNextDriver(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI IdePortPassDownToNextDriver(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI IdePortNoSupportIrp(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI IdePortAlwaysStatusSuccessIrp(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI ChannelStartDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelRemoveDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelStopDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelQueryDeviceRelations(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelFilterResourceRequirements(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelQueryId(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelQueryPnPDeviceState(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelUsageNotification(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelSurpriseRemoveDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI IdePortSetFdoPowerState(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelQueryPowerState(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI DeviceStartDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI DeviceQueryStopRemoveDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI DeviceRemoveDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI DeviceStopDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI DeviceQueryDeviceRelations(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI DeviceQueryCapabilities(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI DeviceQueryText(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI DeviceQueryId(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI DeviceQueryPnPDeviceState(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI DeviceUsageNotification(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI IdePortSetPdoPowerState(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI DeviceQueryPowerState(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

VOID
NTAPI
RosDumpIoResources(
    _In_ PIO_RESOURCE_REQUIREMENTS_LIST IoResource,
    _In_ ULONG DebugLevel
);

VOID
NTAPI
RosDumpCmResources(
    _In_ PCM_RESOURCE_LIST CmResource,
    _In_ ULONG DebugLevel
);

NTSTATUS
NTAPI
FdoPowerCompletionRoutine(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp,
    _In_ PVOID context
);

VOID
NTAPI
IdePortTickHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PVOID Context
);

NTSTATUS
NTAPI
IssueSyncAtapiCommandSafe(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PCDB Cdb,
    _In_ PVOID DataBuffer,
    _In_ ULONG DataBufferSize,
    _In_ BOOLEAN IsDataIn,
    _In_ BOOLEAN IsBypassFrozen
);

NTSTATUS
NTAPI
IssueSyncAtapiCommand(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PCDB Cdb,
    _In_ PVOID DataBuffer,
    _In_ ULONG DataBufferSize,
    _In_ BOOLEAN IsDataIn,
    _In_ BOOLEAN IsBypassFrozen
);

VOID
NTAPI
AtapiHwInitialize(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ PUCHAR GetFlushCommand
);

NTSTATUS
NTAPI
DeviceInitDeviceState(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PVOID CallBack,
    _In_ PVOID CallBackContext
);

NTSTATUS
NTAPI
IssueAsyncAtaPassThroughSafe(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PATA_PASS_THROUGH AtaPassThr,
    _In_ BOOLEAN IsDataIn,
    _In_ PVOID CallBack,
    _In_ PVOID CallBackContext,
    _In_ UCHAR SrbFunctionType,
    _In_ LONG TimeOutValue,
    _In_ BOOLEAN MustSucceed
);

NTSTATUS
NTAPI
IssueSyncAtaPassThroughSafe(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PATA_PASS_THROUGH AtaPassThr,
    _In_ UCHAR IsDataIn,
    _In_ UCHAR SrbFunctionType,
    _In_ LONG TimeOutValue,
    _In_ BOOLEAN MustSucceed
);

BOOLEAN
NTAPI
AtapiInterrupt(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension
);

#endif /* _PCIIDEX_PCH_ */
