/*
 * PROJECT:     Universal serial bus modem driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     USB modem driver wmi functions.
 * COPYRIGHT:   Copyright 2022 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES ******************************************************************/

#include "usbser.h"

//#define NDEBUG
#include <debug.h>

/* DATA ***********************************************************************/

/* GLOBALS ********************************************************************/

/* FUNCTIONS *****************************************************************/

NTSTATUS
NTAPI
UsbSerSetWmiDataItem(IN PDEVICE_OBJECT DeviceObject,
                     IN PIRP PIrp,
                     IN ULONG GuidIndex,
                     IN ULONG InstanceIndex,
                     IN ULONG DataItemId,
                     IN ULONG BufferSize,
                     IN PUCHAR PBuffer)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerSetWmiDataBlock(IN PDEVICE_OBJECT DeviceObject,
                      IN PIRP PIrp,
                      IN ULONG GuidIndex,
                      IN ULONG InstanceIndex,
                      IN ULONG BufferSize,
                      IN PUCHAR PBuffer)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerQueryWmiDataBlock(IN PDEVICE_OBJECT DeviceObject,
                        IN PIRP PIrp,
                        IN ULONG GuidIndex, 
                        IN ULONG InstanceIndex,
                        IN ULONG InstanceCount,
                        IN OUT PULONG InstanceLengthArray,
                        IN ULONG OutBufferSize,
                        OUT PUCHAR PBuffer)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsbSerQueryWmiRegInfo(IN PDEVICE_OBJECT DeviceObject,
                      OUT PULONG PRegFlags,
                      OUT PUNICODE_STRING PInstanceName,
                      OUT PUNICODE_STRING * PRegistryPath,
                      OUT PUNICODE_STRING MofResourceName,
                      OUT PDEVICE_OBJECT * Pdo)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

/* EOF */
