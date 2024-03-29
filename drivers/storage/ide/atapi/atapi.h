#ifndef _PCIIDEX_PCH_
#define _PCIIDEX_PCH_

/* INCLUDES *******************************************************************/

#include <ntifs.h>
#include <ide.h>

/* STRUCTURES ***************************************************************/

typedef struct _ATAPI_DRIVER_EXTENSION
{
    UNICODE_STRING RegistryPath;
} ATAPI_DRIVER_EXTENSION, *PATAPI_DRIVER_EXTENSION;

/* FUNCTIONS ****************************************************************/

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

#endif /* _PCIIDEX_PCH_ */
