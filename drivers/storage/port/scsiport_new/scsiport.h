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
} COMMON_EXTENSION, *PCOMMON_EXTENSION;

/* PDO */
typedef struct _SCSI_PORT_LUN_EXTENSION
{
    COMMON_EXTENSION CommonExtension;
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
    ULONG PortScsiPort;
    ULONG PortScsi;
    UCHAR Flags2;
    SCSI_PORT_LUN_ENTRY LunList[8];
    KMUTEX EnumMutex;
    FAST_MUTEX EnumFastMutex;
    WORK_QUEUE_ITEM EnumWorkItem;
    PWCHAR DeviceNameBuffer;
    FAST_MUTEX PoFastMutex;
    PHYSICAL_ADDRESS MinimumUCXAddress;
    PHYSICAL_ADDRESS MaximumUCXAddress;
    PSCSI_PORT_LUN_EXTENSION BlockedLun;
} SCSI_PORT_DEVICE_EXTENSION, *PSCSI_PORT_DEVICE_EXTENSION;

/* FUNCTIONS ****************************************************************/

#ifndef Add2Ptr
  #define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#endif

#endif /* _SCSIPORT_H_ */

/* EOF */
