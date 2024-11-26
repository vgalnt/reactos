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

typedef struct _COMMON_EXTENSION
{
    PDEVICE_OBJECT SelfDevice;
    PDEVICE_OBJECT LowDevice;
} COMMON_EXTENSION, *PCOMMON_EXTENSION;

/* FDO */
typedef struct _SCSI_PORT_DEVICE_EXTENSION
{
    COMMON_EXTENSION CommonExtension;
    PDEVICE_OBJECT LowerPdo;
    UCHAR Flags2;
} SCSI_PORT_DEVICE_EXTENSION, *PSCSI_PORT_DEVICE_EXTENSION;

/* FUNCTIONS ****************************************************************/

#endif /* _SCSIPORT_H_ */

/* EOF */
