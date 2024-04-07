#ifndef _PCIIDEX_PCH_
#define _PCIIDEX_PCH_

/* INCLUDES *******************************************************************/

#include <ntifs.h>
#include <ide.h>
#include <stdio.h>
#include <initguid.h>
#include <wdmguid.h>

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
    UCHAR Unknown1;
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
    ULONG MaxIdeTargetId;
    BOOLEAN IsDscRestrictive;
    BOOLEAN IsDriverMustPoll;
    BOOLEAN IsPrimary;
    BOOLEAN IsSecondary;
    PCIIDE_BUS_MASTER_INTERFACE BusMasterInterface;
} ATA_DEVICE_EXTENSION, *PATA_DEVICE_EXTENSION;

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
    ULONG FdoIndex;
    ULONG FdoState; 
    PKINTERRUPT InterruptObject;
    UCHAR HackFlags;
    PVOID DefaultTransferModeTimingTable;
    ATAPI_SET_POWER_CONTEXT PowerContext[2];
    LONG PowerContextLock[2];
    PVOID ErrorLog[2];
    PVOID ReservedPages;
    PCIIDE_INTERRUPT_INTERFACE InterruptInterface;
    ATA_DEVICE_EXTENSION AtaExt;
} FDO_DEVICE_EXTENSION, *PFDO_DEVICE_EXTENSION;

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

#endif /* _PCIIDEX_PCH_ */
