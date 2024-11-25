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
    PSCSI_HW_CHAIN_ENTRY ChainHeader;
    BOOLEAN LegacyAdapterDetection;
    ULONG IgnoreInitLegacyStatus;
} SCSI_PORT_DRIVER_EXTENSION, *PSCSI_PORT_DRIVER_EXTENSION;

typedef struct _SCSI_PORT_GUID_INTERFACE_MAPPING
{
    GUID Guid;
    INTERFACE_TYPE InterfaceType;
} SCSI_PORT_GUID_INTERFACE_MAPPING, *PSCSI_PORT_GUID_INTERFACE_MAPPING;

/* FUNCTIONS ****************************************************************/

#endif /* _SCSIPORT_H_ */

/* EOF */
