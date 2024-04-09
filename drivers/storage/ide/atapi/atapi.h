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
    ULONG SupportedTransferMode[2];
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

typedef struct _PCIIDE_PROPER_RESOURCES
{
    PVOID ChannelRequestProperResources; // VOID NTAPI* (PDEVICE_OBJECT)
} PCIIDE_PROPER_RESOURCES, *PPCIIDE_PROPER_RESOURCES;

typedef struct _ATA_DEVICE_EXTENSION
{
    PVOID CurrentSrb;
    IDE_CMD_BLOCK_REGS CmdBlock;
    IDE_CTRL_BLOCK_REGS CtrlBlock;
    ULONG CmdBlockLength;
    ULONG CtrlBlockLength;
    ULONG MaxIdeDevice;
    ULONG IntResFlags;
    ULONG DeviceFlags[2];
    ULONG MaxIdeTargetId;
    BOOLEAN IsDscRestrictive;
    BOOLEAN IsDriverMustPoll;
    BOOLEAN IsPrimary;
    BOOLEAN IsSecondary;
    IDENTIFY_DATA IdentifyData[2];
    PCIIDE_BUS_MASTER_INTERFACE BusMasterInterface;
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
    PCIIDE_PROPER_RESOURCES ProperResources;
    PATA_DEVICE_EXTENSION HwDeviceExtension;
    BOOLEAN IsBmIfaceReceived;
    BOOLEAN SymlinkCreated;
    ULONG FdoIndex;
    ULONG ScsiPortCount;
    ULONG Flags;
    ULONG FdoState; 
    LONG TimeOutValue;
    UCHAR MaxPdoCount;
    PKINTERRUPT InterruptObject;
    KSPIN_LOCK SpinLock;
    KSPIN_LOCK PdoArrayLock;
    UCHAR PdoCount1;
    UCHAR PdoCount2;
    UCHAR HackFlags;
    ULONG PcmciaIdeHasSlaveDevice;
    ATAPI_INTERRUPT_DATA InterruptData;
    IO_SCSI_CAPABILITIES IoScsicapabilities;
    KTIMER Timer;
    KDPC Dpc;
    IDE_ACPI_TIMING_MODE_BLOCK TimingBlock0;
    IDE_ACPI_TIMING_MODE_BLOCK TimingBlock;
    PVOID DefaultTransferModeTimingTable;
    ULONG DmaDetectionLevel;
    ULONG DeviceParameter[4];
    ATAPI_SET_POWER_CONTEXT PowerContext[2];
    LONG PowerContextLock[2];
    PVOID ErrorLog[2];
    PVOID ReservedPages;
    PCIIDE_INTERRUPT_INTERFACE InterruptInterface;
    ULONG ResetErrorCountersOnSuccess;
    ATA_DEVICE_EXTENSION AtaExt;
} FDO_DEVICE_EXTENSION, *PFDO_DEVICE_EXTENSION;

typedef struct _PDO_DEVICE_EXTENSION
{
    PDEVICE_OBJECT LowDevice;
    PDEVICE_OBJECT LowPdo;
    PDRIVER_OBJECT DriverObject;
    PDEVICE_OBJECT SelfDevice;
} PDO_DEVICE_EXTENSION, *PPDO_DEVICE_EXTENSION;

/* FUNCTIONS ****************************************************************/

#ifndef Add2Ptr
  #define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
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

#endif /* _PCIIDEX_PCH_ */
