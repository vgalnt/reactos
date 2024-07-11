/*
 * PROJECT:     Intel IDE bus driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Main file
 * COPYRIGHT:   Copyright 2024 Vadim Galyant <vgal@rambler.ru>
 */

#include "intelide.h"

//#define NDEBUG
#include <debug.h>


IDE_CHANNEL_STATE
NTAPI 
PiixIdeChannelEnabled(
    _In_ PVOID DeviceExtension,
    _In_ ULONG Channel)
{
    INTEL_MODES_TIMING_AND_CONTROL TimingAndControl[2];
    NTSTATUS Status;

    DPRINT("PiixIdeChannelEnabled: %p, %X\n", DeviceExtension, Channel);

    if (Channel & ~1)
    {
        DPRINT1("PiixIdeChannelEnabled: Channel %X\n", Channel);
        ASSERT((Channel & ~1) == 0);
        return 0;
    }

    Status = PciIdeXGetBusData(DeviceExtension, TimingAndControl, 0x40, sizeof(TimingAndControl));
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PiixIdeChannelEnabled: Status %X\n", Status);
        return 2;
    }

    return (TimingAndControl[Channel].IdeDecodeEnable ? 1 : 0);
}

BOOLEAN
NTAPI
PiixIdeSyncAccessRequired(
    _In_ PVOID DeviceExtension)
{
    return FALSE;
}

ULONG
NTAPI
PiixIdeUseDma(
    _In_ PVOID DeviceExtension,
    _In_ PUCHAR CdbCommand,
    _In_ PUCHAR Slave)
{
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

NTSTATUS
NTAPI
PiixIdeUdmaModesSupported(
    _In_ IDENTIFY_DATA IdentifyData,
    _Out_ ULONG* OutBestXferMode,
    _Out_ ULONG* OutCurrentXferMode)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiixIdeTransferModeSelect(
    _In_ PVOID InDeviceExtension,
    _In_ PPCIIDE_TRANSFER_MODE_SELECT XferModeSelect)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
PiixIdeGetControllerProperties(
    _In_ PVOID InDeviceExtension,
    _Out_ IDE_CONTROLLER_PROPERTIES* OutProperties)
{
    PINTEL_CONTROLLER_EXTENSION DeviceExtension = InDeviceExtension;
    PCI_COMMON_HEADER PciConfig;
    ULONG Mode;
    ULONG ix;
    ULONG jx;
    USHORT DeviceId;
    NTSTATUS Status;

    DPRINT("PiixIdeGetControllerProperties: %p\n", DeviceExtension);

    if (OutProperties->Size != sizeof(IDE_CONTROLLER_PROPERTIES))
    {
        DPRINT1("PiixIdeGetControllerProperties: STATUS_REVISION_MISMATCH\n");
        return STATUS_REVISION_MISMATCH;
    }

    Status = PciIdeXGetBusData(DeviceExtension, &PciConfig, 0, sizeof(PciConfig));
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PiixIdeGetControllerProperties: Status %X\n", Status);
        return Status;
    }
 
    if (PciConfig.VendorID != 0x8086)
    {
        DPRINT1("PiixIdeGetControllerProperties: STATUS_UNSUCCESSFUL\n");
        return STATUS_UNSUCCESSFUL;
    }

    DeviceExtension->DeviceId = DeviceId = PciConfig.DeviceID;
    DPRINT("PiixIdeGetControllerProperties: DeviceId %X\n", DeviceId);

    DeviceExtension->UdmaSpeed = 0;
    Mode = 0x1F;

    if (!(PciConfig.ProgIf & 0x80))
    {
        DPRINT1("PiixIdeGetControllerProperties: PciConfig.ProgIf %X\n", PciConfig.ProgIf);
        goto Finish;
    }

    Mode = 0x7FF;

    if (DeviceId == 0x7111 || DeviceId == 0x2421 || DeviceId == 0x7601 || DeviceId == 0x2411 || DeviceId == 0x7199 ||
        DeviceId == 0x2441 || DeviceId == 0x244A || DeviceId == 0x244B || DeviceId == 0x248A || DeviceId == 0x248B ||
        DeviceId == 0x24C1 || DeviceId == 0x24CA || DeviceId == 0x24CB || DeviceId == 0x24D1 || DeviceId == 0x24DB ||
        DeviceId == 0x25A2 || DeviceId == 0x25A3 || DeviceId == 0x2651 || DeviceId == 0x2652 || DeviceId == 0x2653 ||
        DeviceId == 0x266F)
    {
        Mode = 0x3FFF;
        DeviceExtension->UdmaSpeed = 1;
    }

    if (DeviceId == 0x2411 || DeviceId == 0x2441 || DeviceId == 0x244A || DeviceId == 0x244B || DeviceId == 0x248A ||
        DeviceId == 0x248B || DeviceId == 0x24C1 || DeviceId == 0x24CA || DeviceId == 0x24CB || DeviceId == 0x24D1 ||
        DeviceId == 0x24DB || DeviceId == 0x25A2 || DeviceId == 0x25A3 || DeviceId == 0x2651 || DeviceId == 0x2652 ||
        DeviceId == 0x2653 || DeviceId == 0x266F)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    if (DeviceId == 0x244A || DeviceId == 0x244B || DeviceId == 0x248A || DeviceId == 0x248B || DeviceId == 0x24C1 ||
        DeviceId == 0x24CA || DeviceId == 0x24CB || DeviceId == 0x24D1 || DeviceId == 0x24DB || DeviceId == 0x25A2 ||
        DeviceId == 0x25A3 || DeviceId == 0x2651 || DeviceId == 0x2652 || DeviceId == 0x2653 || DeviceId == 0x266F)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

Finish:

    for (ix = 0; ix < 2; ix++)
    {
        for (jx = 0; jx < 2; jx++)
        {
            OutProperties->SupportedTransferMode[ix][jx] = Mode;
            DeviceExtension->SupportedTransferMode[ix][jx] = Mode;
        }
    }

    OutProperties->PciIdeChannelEnabled = PiixIdeChannelEnabled;
    OutProperties->PciIdeSyncAccessRequired = PiixIdeSyncAccessRequired;
    OutProperties->PciIdeUseDma = PiixIdeUseDma;
    OutProperties->PciIdeUdmaModesSupported = PiixIdeUdmaModesSupported;
    OutProperties->AlignmentRequirement = 1;
    OutProperties->PciIdeTransferModeSelect = PiixIdeTransferModeSelect;

    return 0;
}

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;

    DPRINT("DriverEntry: %p, '%wZ'\n", DriverObject, RegistryPath);

    Status = PciIdeXInitialize(DriverObject,
                               RegistryPath,
                               PiixIdeGetControllerProperties,
                               sizeof(INTEL_CONTROLLER_EXTENSION));
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("DriverEntry: Status %X\n", Status);
    }

    return Status;
}

/* EOF*/
