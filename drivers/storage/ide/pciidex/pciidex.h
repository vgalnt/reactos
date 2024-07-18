#ifndef _PCIIDEX_PCH_
#define _PCIIDEX_PCH_

/* INCLUDES *******************************************************************/

#include <ntifs.h>
#include <ide.h>
#include <stdio.h>
#include <initguid.h>
#include <wdmguid.h>
#include <ndk/rtlfuncs.h>

/* STRUCTURES ***************************************************************/

DEFINE_GUID(GUID_PCIIDE_BUSMASTER_INTERFACE,      0x681190EA, 0xE4EA, 0x11D0, 0xAB, 0x82, 0x00, 0xA0, 0xC9, 0x06, 0x96, 0x2F);
DEFINE_GUID(GUID_PCIIDE_SYNC_ACCESS_INTERFACE,    0x681190EB, 0xE4EA, 0x11D0, 0xAB, 0x82, 0x00, 0xA0, 0xC9, 0x06, 0x96, 0x2F);
DEFINE_GUID(GUID_PCIIDE_XFER_MODE_INTERFACE,      0x681190EC, 0xE4EA, 0x11D0, 0xAB, 0x82, 0x00, 0xA0, 0xC9, 0x06, 0x96, 0x2F);
DEFINE_GUID(GUID_PCIIDE_REQUEST_PROPER_RESOURCES, 0x681190ED, 0xE4EA, 0x11D0, 0xAB, 0x82, 0x00, 0xA0, 0xC9, 0x06, 0x96, 0x2F);
DEFINE_GUID(GUID_PCIIDE_INTERRUPT_INTERFACE,      0x681190EE, 0xE4EA, 0x11D0, 0xAB, 0x82, 0x00, 0xA0, 0xC9, 0x06, 0x96, 0x2F);
DEFINE_GUID(GUID_PCI_NATIVE_IDE_INTERFACE,        0x98F37D63, 0x42AE, 0x4AD9, 0x8C, 0x36, 0x93, 0x2D, 0x28, 0x38, 0x3D, 0xF8);

#define IDE_DRIVE_SELECT    0xA0 

typedef struct _IDE_SET_POWER_CONTEXT
{
    PIRP Irp;
    POWER_STATE_TYPE Type;
    POWER_STATE State;
} IDE_SET_POWER_CONTEXT, *PIDE_SET_POWER_CONTEXT;

typedef struct _IDE_WAIT_CONTEXT
{
    KEVENT Event;
    NTSTATUS Status;
} IDE_WAIT_CONTEXT, *PIDE_WAIT_CONTEXT;

typedef struct _PCIIDEX_DRIVER_EXTENSION
{
    PCONTROLLER_PROPERTIES HwGetControllerProperties;
    ULONG MiniControllerExtensionSize;
    PCIIDE_UDMA_MODES_SUPPORTED HwUdmaModesSupported;
} PCIIDEX_DRIVER_EXTENSION, *PPCIIDEX_DRIVER_EXTENSION;

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

#include <pshpack1.h>

typedef struct _PHYSICAL_REGION_DESCRIPTOR
{
    ULONG BaseAddress;
    ULONG ByteCount:16;
    ULONG Reserved:15;
    ULONG EndTable:1;
} PHYSICAL_REGION_DESCRIPTOR, *PPHYSICAL_REGION_DESCRIPTOR;

typedef struct _PHYSICAL_REGION_DESCRIPTOR_TABLE
{
    PHYSICAL_REGION_DESCRIPTOR Prd[1];
} PHYSICAL_REGION_DESCRIPTOR_TABLE, *PPHYSICAL_REGION_DESCRIPTOR_TABLE;

typedef struct _BUS_MASTER_IDE_REGISTERS
{
    UCHAR CommandPrimary;
    UCHAR DeviceSpecificPrimary0;
    UCHAR StatusPrimary;
    UCHAR DeviceSpecificPrimary1;
    PPHYSICAL_REGION_DESCRIPTOR_TABLE PrdTablePrimary;
    UCHAR CommandSecondary;
    UCHAR DeviceSpecificSecondary0;
    UCHAR StatusSecondary;
    UCHAR DeviceSpecificSecondary1;
    PPHYSICAL_REGION_DESCRIPTOR_TABLE PrdTableSecondary;
} BUS_MASTER_IDE_REGISTERS, *PBUS_MASTER_IDE_REGISTERS;

#include <poppack.h> 

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

typedef struct _PCIIDE_PROPER_RESOURCES
{
    PVOID ChannelRequestProperResources;
} PCIIDE_PROPER_RESOURCES, *PPCIIDE_PROPER_RESOURCES;

typedef VOID (NTAPI* PNATIVE_IDE_INTERRUPT_CONTROL)(PVOID Context, BOOLEAN IsEnableOrDisable);

typedef struct _PCI_NATIVE_IDE_INTERFACE
{
    INTERFACE StdInterface;
    PNATIVE_IDE_INTERRUPT_CONTROL InterruptControl;
} PCI_NATIVE_IDE_INTERFACE, *PPCI_NATIVE_IDE_INTERFACE;

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

typedef struct _IDE_RESOURCE_DATA
{
    ULONG TypeResForCmdBlock;
    ULONG TypeResForCtrlBlock;
    PUCHAR CmdBlockBase;
    PUCHAR CtrlBlockBase;
    ULONG IntResFlags;
    ULONG Vector;
    BOOLEAN PrimaryClaimed;
    BOOLEAN SecondaryClaimed;
} IDE_RESOURCE_DATA, *PIDE_RESOURCE_DATA;

typedef struct _IDE_INTERRUPT_SERVICE_CONTEXT
{
    struct _FDO_DEVICE_EXTENSION* FdoExtension;
    ULONG Channel;
} IDE_INTERRUPT_SERVICE_CONTEXT, *PIDE_INTERRUPT_SERVICE_CONTEXT;

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
    PDRIVER_DISPATCH PassToNextDriver;
    PDRIVER_DISPATCH* FdoPnpDispatchTable;
    PDRIVER_DISPATCH* FdoPowerDispatchTable;
    PDRIVER_DISPATCH* FdoWmiDispatchTable;
    ULONG FdoIndex;
    struct _PDO_DEVICE_EXTENSION* PdoExtension[2];
    ULONG NumberOfChildrenPowerUp;
    UCHAR NativeMode[2];
    BOOLEAN IsCmdBlockResource[2];
    BOOLEAN IsCtrlBlockResource[2];
    BOOLEAN IsIntResource[2];
    ULONG ChannelResourceSize[2];
    PCM_RESOURCE_LIST ChannelResources[2];
    ULONG BusMasterResourcesSize;
    PCM_RESOURCE_LIST BusMasterResources;
    ULONG BusMasterResType;
    PVOID TranslatedBusMasterBaseAddress;
    IDE_CONTROLLER_PROPERTIES ControllerProperties;
    PVOID MiniControllerExtension;
    PCONTROLLER_OBJECT ControllerObject;
    KSPIN_LOCK SpinLock;
    ULONG DeviceControlFlags;
    BUS_INTERFACE_STANDARD StdInterface;
    ULONG LastRescan;
    ULONG EnableUDMA66;
    PULONG TimingTable;
    ULONG TimingTableLength;
    IDE_SET_POWER_CONTEXT PowerContext[2];
    LONG PowerContextLock[2];
    PKINTERRUPT InterruptObject[2];
    IDE_INTERRUPT_SERVICE_CONTEXT ServiceContext[2];
    IDE_RESOURCE_DATA ResourceData;
    IDE_CMD_BLOCK_REGS CmdBlock[2];
    IDE_CTRL_BLOCK_REGS CtrlBlock[2];
    PCM_PARTIAL_RESOURCE_DESCRIPTOR InterruptDesc[2];
    ULONG CmdBlockLength[2];
    ULONG CtrlBlockLength[2];
    ULONG MaxIdeDevice[2];
    BOOLEAN ControllerIsrInstalled;
    BOOLEAN NativeInterruptEnabled;
    BOOLEAN BmMissing[2];
    PCI_NATIVE_IDE_INTERFACE PciNativeIdeInterface;
} FDO_DEVICE_EXTENSION, *PFDO_DEVICE_EXTENSION;

typedef struct _PDO_DEVICE_EXTENSION
{
    ULONG LowDevice;
    ULONG LowPdo;
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
    ULONG PdoIndex;
    KSPIN_LOCK SpinLock;
    ULONG PdoState;
    ULONG DmaDetectionLevel;
    ULONG PnPDeviceState;
    ULONG BusMasterBase;
    PDMA_ADAPTER DmaAdapter;
    ULONG MaximumPhysicalPages;
    PPHYSICAL_REGION_DESCRIPTOR_TABLE RegionDescriptors;
    PHYSICAL_ADDRESS PhysicalRegionDescriptorTable;
    PVOID TransferDataBuffer;
    PSCATTER_GATHER_LIST ScatterGather;
    ULONG TransferLength;
    PVOID MapRegisterBase;
    PMDL Mdl;
    UCHAR DataInFlag;
    PVOID BmCallback;
    PVOID BmCallbackContext;
    ULONG BmState;
    UCHAR BmStatus;
    BOOLEAN IsChannelEmpty;
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

NTSTATUS NTAPI StatusSuccessAndPassDownToNextDriver(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI PassDownToNextDriver(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI NoSupportIrp(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI ControllerStartDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ControllerRemoveDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ControllerStopDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ControllerQueryDeviceRelations(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ControllerQueryInterface(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ControllerQueryPnPDeviceState(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ControllerUsageNotification(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ControllerSurpriseRemoveDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI ChannelStartDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelQueryStopRemoveDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelRemoveDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI PciIdeXAlwaysStatusSuccessIrp(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelStopDevice(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelQueryDeviceRelations(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI PciIdeChannelQueryInterface(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelQueryCapabitilies(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelQueryResources(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelQueryResourceRequirements(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelQueryText(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelFilterResourceRequirements(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelQueryId(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelQueryPnPDeviceState(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI ChannelUsageNotification(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

NTSTATUS NTAPI PciIdeSetFdoPowerState(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI PciIdeSetPdoPowerState(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS NTAPI PciIdeXQueryPowerState(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

VOID
NTAPI
RosDumpCmResources(
    _In_ PCM_RESOURCE_LIST CmResource,
    _In_ ULONG DebugLevel
);

PPDO_DEVICE_EXTENSION
NTAPI
ChannelGetPdoExtension(
    _In_ PDEVICE_OBJECT Pdo
);

ULONG
NTAPI
BmStatus(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension
);

ULONG
NTAPI
PciIdeChannelEnabled(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ ULONG Channel
);

#endif /* _PCIIDEX_PCH_ */
