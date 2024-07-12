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
    return 1;
}

NTSTATUS
NTAPI
PiixIdeUdmaModesSupported(
    _In_ IDENTIFY_DATA IdentifyData,
    _Out_ ULONG* OutBestXferMode,
    _Out_ ULONG* OutXferMode)
{
    IDENTIFY_DATA identify;
    ULONG BestXferMode;
    ULONG XferMode;
    ULONG TempMode;

    DPRINT("PiixIdeUdmaModesSupported()\n");

    RtlCopyMemory(&identify, &IdentifyData, sizeof(identify));

    if (!(IdentifyData.TranslationFieldsValid & 4))
    {
        DPRINT("PiixIdeUdmaModesSupported: TranslationFieldsValid %X\n", IdentifyData.TranslationFieldsValid);
        return STATUS_SUCCESS;
    }

    if (identify.UltraDMASupport)
    {
        TempMode = identify.UltraDMASupport;
        ASSERT(TempMode);

        for (BestXferMode = 0; TempMode; BestXferMode++)
            TempMode >>= 1;

        *OutBestXferMode = (BestXferMode - 1);
    }

    if (identify.UltraDMAActive)
    {
        TempMode = identify.UltraDMAActive;
        ASSERT(TempMode);

        for (XferMode = 0; TempMode; XferMode++)
            TempMode >>= 1;

        *OutXferMode = (XferMode - 1);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PiixIdepTransferModeSelect(
    _In_ PINTEL_CONTROLLER_EXTENSION DeviceExtension,
    _In_ PPCIIDE_TRANSFER_MODE_SELECT XferModeSelect,
    _Out_ ULONG* OutXferMode,
    _Out_ INTEL_MODES_TIMING_AND_CONTROL* OutTimingAndControl,
    _Out_ INTEL_SLAVE_IDE_TIMING* OutSlaveTiming,
    _Out_ INTEL_ULTRA_DMA_CONTROL* OutUdmaControl,
    _Out_ INTEL_ULTRA_DMA_TIMING* OutUdmaTiming)
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
    PINTEL_CONTROLLER_EXTENSION DeviceExtension = InDeviceExtension;
    INTEL_MODES_TIMING_AND_CONTROL TimingAndControl;
    INTEL_MODES_TIMING_AND_CONTROL OldTimingAndControl[2];
    INTEL_SLAVE_IDE_TIMING SlaveTiming;
    INTEL_SLAVE_IDE_TIMING OldSlaveTiming;
    INTEL_ULTRA_DMA_CONTROL UdmaControl;
    INTEL_ULTRA_DMA_CONTROL OldUdmaControl;
    INTEL_ULTRA_DMA_TIMING UdmaTiming;
    INTEL_ULTRA_DMA_TIMING OldUdmaTiming;
    ULONG XferMode[2];
    ULONG Channel;
    ULONG ix;
    USHORT DeviceId;
    USHORT DataMask;
    NTSTATUS Status;

    DPRINT("PiixIdeTransferModeSelect: DeviceExtension %p\n", DeviceExtension);

    for (ix = 0; ix < 2; ix++)
    {
        RtlCopyMemory(&DeviceExtension->IdentifyData[ix],
                      &XferModeSelect->IdentifyData[ix],
                      sizeof(DeviceExtension->IdentifyData[ix]));
    }

    Status = PiixIdepTransferModeSelect(DeviceExtension,
                                        XferModeSelect,
                                        XferMode,
                                        &TimingAndControl,
                                        &SlaveTiming,
                                        &UdmaControl,
                                        &UdmaTiming);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PiixIdeTransferModeSelect: Status %X\n", Status);
        goto Finish;
    }

    OldSlaveTiming.AsUCHAR = 0;
    OldUdmaControl.AsUCHAR = 0;
    OldUdmaTiming.AsUSHORT = 0;

    Channel = XferModeSelect->Channel;

    /* 40–41 IDE TIMING (Primary) R/W, 42–43 IDE TIMING (Secondary) R/W */
    PciIdeXGetBusData(DeviceExtension, OldTimingAndControl, 0x40, 4);

    DPRINT("PiixIdeTransferModeSelect: Old IDETIM %X\n", OldTimingAndControl[Channel].AsUSHORT);

    DeviceId = DeviceExtension->DeviceId;
    if (DeviceId != 0x1230)
    {
        /* 44 Slave IDE Timing (Primary and Secondary) R/W */
        PciIdeXGetBusData(DeviceExtension, &OldSlaveTiming, 0x44, 1);
        DPRINT("PiixIdeTransferModeSelect: Old SIDETIM %X\n", OldSlaveTiming.AsUCHAR);
    }

    if (DeviceId == 0x7111 || DeviceId == 0x2421 || DeviceId == 0x7601 || DeviceId == 0x2411 || DeviceId == 0x7199 ||
        DeviceId == 0x2441 || DeviceId == 0x244A || DeviceId == 0x244B || DeviceId == 0x248A || DeviceId == 0x248B ||
        DeviceId == 0x24C1 || DeviceId == 0x24CA || DeviceId == 0x24CB || DeviceId == 0x24D1 || DeviceId == 0x24DB ||
        DeviceId == 0x25A2 || DeviceId == 0x25A3 || DeviceId == 0x2651 || DeviceId == 0x2652 || DeviceId == 0x2653 ||
        DeviceId == 0x266F)
    {
        /* 48 Ultra DMA Control Register R/W */
        PciIdeXGetBusData(DeviceExtension, &OldUdmaControl, 0x48, 1);
        DPRINT("PiixIdeTransferModeSelect: Old SDMACTL %X\n", OldUdmaControl.AsUCHAR);

        /* 4A:4B Ultra DMA Timing Register R/W */
        PciIdeXGetBusData(DeviceExtension, &OldUdmaTiming, (0x4A + Channel), 2);
        DPRINT("PiixIdeTransferModeSelect: Old SDMATIM %X\n", OldUdmaTiming.AsUSHORT);
    }

    if (DeviceId == 0x2411 || DeviceId == 0x2421 || DeviceId == 0x7601)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    if (Channel == 0)
    {
        OldSlaveTiming.AsUCHAR = ((OldSlaveTiming.AsUCHAR & ~0xF) | (SlaveTiming.AsUCHAR & 0xF));
        OldUdmaControl.AsUCHAR = ((OldUdmaControl.AsUCHAR & ~3) | (UdmaControl.AsUCHAR & 3));
    }
    else
    {
        OldSlaveTiming.AsUCHAR = ((OldSlaveTiming.AsUCHAR & ~0xF0) | (SlaveTiming.AsUCHAR & 0xF0));
        OldUdmaControl.AsUCHAR = ((OldUdmaControl.AsUCHAR & ~0xC) | (UdmaControl.AsUCHAR & 0xC));
    }

    DPRINT("PiixIdeTransferModeSelect: New PIIX/ICH values - IDETIM %X, SIDETIM %X, SDMACTL %X, SDMATIM %X\n", 
           TimingAndControl.AsUSHORT, OldSlaveTiming.AsUCHAR, OldUdmaControl.AsUCHAR, UdmaTiming.AsUSHORT);

    DataMask = 0xFFFF;

    Status = PciIdeXSetBusData(DeviceExtension, &TimingAndControl, &DataMask, (0x40 + Channel * 2), 2);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PiixIdeTransferModeSelect: Status %X\n", Status);
        goto Finish;
    }

    if (DeviceId != 0x1230)
    {
        DataMask = (!XferModeSelect->Channel ? 0xF : 0xF0);

        Status = PciIdeXSetBusData(DeviceExtension, &SlaveTiming, &DataMask, 0x44, 1);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PiixIdeTransferModeSelect: Status %X\n", Status);
            ASSERT(!"Unable to set pci config data\n");
            goto Finish;
        }
    }

    if (DeviceId == 0x7111 || DeviceId == 0x2421 || DeviceId == 0x7601 || DeviceId == 0x2411 || DeviceId == 0x7199 ||
        DeviceId == 0x2441 || DeviceId == 0x244A || DeviceId == 0x244B || DeviceId == 0x248A || DeviceId == 0x248B ||
        DeviceId == 0x24C1 || DeviceId == 0x24CA || DeviceId == 0x24CB || DeviceId == 0x24D1 || DeviceId == 0x24DB ||
        DeviceId == 0x25A2 || DeviceId == 0x25A3 || DeviceId == 0x2651 || DeviceId == 0x2652 || DeviceId == 0x2653 ||
        DeviceId == 0x266F)
    {
        DataMask = (!XferModeSelect->Channel ? 3 : 0xC);

        Status = PciIdeXSetBusData(DeviceExtension, &UdmaControl, &DataMask, 0x48, 1);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PiixIdeTransferModeSelect: Status %X\n", Status);
            ASSERT(!"Unable to set pci config data\n");
            goto Finish;
        }

        DataMask = 0xFF;

        Status = PciIdeXSetBusData(DeviceExtension, &UdmaTiming, &DataMask, (0x4A + Channel), 2);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PiixIdeTransferModeSelect: Status %X\n", Status);
            ASSERT(!"Unable to set pci config data\n");
            goto Finish;
        }
    }

    if (DeviceId == 0x2411 || DeviceId == 0x2421 || DeviceId == 0x7601 ||
        DeviceId == 0x2441 || DeviceId == 0x244A || DeviceId == 0x244B)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

Finish:

    if (NT_SUCCESS(Status))
    {
        for (ix = 0; ix < 2; ix++)
            XferModeSelect->DeviceTransferModeSelected[ix] = XferMode[ix];
    }

    return Status;
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
