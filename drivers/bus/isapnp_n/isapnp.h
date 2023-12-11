/*
 * PROJECT:     ISA PnP Bus driver for NT 5.x
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Main header file
 * COPYRIGHT:   Copyright 2019, 2023 Vadim Galyant <vgal@rambler.ru>
 */

/* Based on "Plug and Play ISA Specification. Version 1.0a May 5, 1994" */

#ifndef _ISAPNP_H_
#define _ISAPNP_H_

/* INCLUDES *******************************************************************/

#include <ntifs.h>
#include <initguid.h>
#include <wdmguid.h>

/* STRUCTURES ***************************************************************/

typedef struct _ISAPNP_FDO_EXTENSION
{
    ULONG Flags;
    PVOID Rdp;
    PDEVICE_OBJECT AttachToPdo;
    PDEVICE_OBJECT Fdo;
    PDEVICE_OBJECT AttachedToDevice;
    ULONG BusNumber;
    SYSTEM_POWER_STATE SystemPowerState;
    DEVICE_POWER_STATE DevicePowerState;
} ISAPNP_FDO_EXTENSION, *PISAPNP_FDO_EXTENSION;

typedef struct _ISAPNP_BUS_EXTENSION
{
    struct _ISAPNP_BUS_EXTENSION* Next;
    PISAPNP_FDO_EXTENSION BusExtension;
} ISAPNP_BUS_EXTENSION, *PISAPNP_BUS_EXTENSION;

typedef struct _ISAPNP_DEVICE_INFO
{
    ULONG Flags;
    PDEVICE_OBJECT ReadDataPortDO;
    PISAPNP_FDO_EXTENSION FdoExtension;
    SINGLE_LIST_ENTRY Link;
    PCM_RESOURCE_LIST BootResources;
    ULONG BootResourcesSize;

} ISAPNP_DEVICE_INFO, *PISAPNP_DEVICE_INFO;

/* FUNCTIONS ****************************************************************/

#ifndef Add2Ptr
  #define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#endif

NTSTATUS NTAPI PiStartFdo(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI PiQueryRemoveStopFdo(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI PiRemoveFdo(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI PiCancelRemoveStopFdo(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI PiStopFdo(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI PiQueryDeviceRelationsFdo(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI PiQueryInterfaceFdo(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI PiQueryPnpDeviceState(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI PiSurpriseRemoveFdo(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI PiQueryLegacyBusInformationFdo(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NTAPI PipPassIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp);

#endif /* _ISAPNP_H_ */
