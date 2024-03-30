#ifndef _PCIIDEX_PCH_
#define _PCIIDEX_PCH_

/* INCLUDES *******************************************************************/

#include <ntifs.h>
#include <ide.h>
#include <stdio.h>
#include <initguid.h>
#include <wdmguid.h>

/* STRUCTURES ***************************************************************/

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

typedef struct _FDO_DEVICE_EXTENSION
{
    PDEVICE_OBJECT LowDevice;
    PDEVICE_OBJECT LowPdo;
    PDRIVER_OBJECT DriverObject;
    PDEVICE_OBJECT SelfDevice;
    SYSTEM_POWER_STATE SystemPowerState;
    DEVICE_POWER_STATE DevicePowerState;
    PDRIVER_DISPATCH PassToNextDriver;
    PDRIVER_DISPATCH* FdoPnpDispatchTable;
    PDRIVER_DISPATCH* FdoPowerDispatchTable;
    PDRIVER_DISPATCH* FdoWmiDispatchTable;
    ULONG FdoIndex;
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
    KSPIN_LOCK SpinLock;
    ULONG DeviceControlFlags;
    BUS_INTERFACE_STANDARD StdInterface;
    ULONG EnableUDMA66;
    IDE_SET_POWER_CONTEXT PowerContext[2];
    LONG PowerContextLock[2];
    PVOID PciNativeIdeInterface;
} FDO_DEVICE_EXTENSION, *PFDO_DEVICE_EXTENSION;

typedef struct _PDO_DEVICE_EXTENSION
{
    ULONG LowDevice;
    ULONG LowPdo;
    PDRIVER_OBJECT DriverObject;
    PDEVICE_OBJECT SelfDevice;
    SYSTEM_POWER_STATE SystemPowerState;
    DEVICE_POWER_STATE DevicePowerState;
    PDRIVER_DISPATCH NoSupportIrp;
    PDRIVER_DISPATCH* PdoPnpDispatchTable;
    PDRIVER_DISPATCH* PdoPowerDispatchTable;
    PDRIVER_DISPATCH* PdoWmiDispatchTable;
    PFDO_DEVICE_EXTENSION FdoExtension;
    ULONG PdoIndex;
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

#endif /* _PCIIDEX_PCH_ */
