/*
 * PROJECT:     Intel IDE bus driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Main file
 * COPYRIGHT:   Copyright 2024 Vadim Galyant <vgal@rambler.ru>
 */

#include "intelide.h"

//#define NDEBUG
#include <debug.h>

UCHAR PiixSpecialTiming[5] =
{
    0, 2, 1, 3, 3
};

UCHAR PiixIoReadySamplePointClockSetting[5] =
{
    0, 0, 1, 2, 2
};

UCHAR PiixRecoveryTimeClockSetting[5] =
{
    0, 0, 0, 1, 3
};


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
    INTEL_MODES_TIMING_AND_CONTROL TimingAndControl;
    INTEL_SLAVE_IDE_TIMING SlaveTiming;
    INTEL_ULTRA_DMA_CONTROL UdmaControl;
    INTEL_ULTRA_DMA_TIMING UdmaTiming;
    PULONG TimingTable;
    ULONG XferModeSupported;
    ULONG EnableUdma66;
    ULONG XferMode[2];
    ULONG TempMode;
    ULONG Channel;
    ULONG Timing;
    ULONG Mode;
    ULONG Idx;
    ULONG ix;
    UCHAR DeviceUdmaTiming;

    Channel = XferModeSelect->Channel;
    DPRINT("PiixIdepTransferModeSelect: Channel %X\n", Channel);

    TimingAndControl.AsUSHORT = 0;
    SlaveTiming.AsUCHAR = 0;

    TimingTable = XferModeSelect->TransferModeTimingTable;
    ASSERT(TimingTable);

    for (ix = 0; ix < 2; ix++)
    {
        EnableUdma66 = XferModeSelect->EnableUDMA66;

        if (!XferModeSelect->DevicePresent[ix])
            continue;

        XferModeSupported = XferModeSelect->DeviceTransferModeSupported[ix];

        if (DeviceExtension->UdmaSpeed == 1)
            XferModeSupported &= 0x3FFF;
        else if (DeviceExtension->UdmaSpeed == 2)
            XferModeSupported &= 0xFFFF;
        else if (DeviceExtension->UdmaSpeed == 3)
            XferModeSupported &= 0x1FFFF;
        else
            XferModeSupported &= 0x7FF;

        if (DeviceExtension->UdmaSpeed == 3)
            EnableUdma66 = 1;

        if (!(DeviceExtension->CableReporting[Channel][ix] && EnableUdma66))
            XferModeSupported &= 0x3FFF;

        TempMode = (XferModeSupported >> 5);

        for (Mode = 5; TempMode; Mode++)
            TempMode >>= 1;

        Mode--;

        if (Mode >= 0xB)
            XferMode[ix] = (1 << Mode);
        else
            XferMode[ix] = 0;

        XferModeSupported = (XferModeSelect->DeviceTransferModeSupported[ix] & 0x7E0);

        TempMode = (XferModeSupported >> 5);

        for (Mode = 5; TempMode; Mode++)
            TempMode >>= 1;

        Mode--;

        if (Mode >= 9)
        {
            while (Mode >= 7)
            {
                if (Mode == 8)
                {
                    Mode--;
                    continue;
                }

                if (XferModeSelect->BestMwDmaCycleTime[ix] <= TimingTable[Mode])
                {
                    XferMode[ix] |= (1 << Mode);
                    break;
                }

                Mode--;
            }
        }
        else if (Mode == 7)
        {
            if (XferModeSelect->BestSwDmaCycleTime[ix] <= TimingTable[Mode])
                XferMode[ix] |= 0x80;
        }

        XferModeSupported = XferModeSelect->DeviceTransferModeSupported[ix];

        TempMode = ((XferModeSupported & 0x1F) >> 1);

        for (Mode = 0; TempMode; Mode++)
            TempMode >>= 1;

        if (Mode == 2)
        {
            XferMode[ix] |= (1 << Mode);
            continue;
        }

        while (Mode > 1)
        {
            if (XferModeSelect->BestPioCycleTime[ix] <= TimingTable[Mode])
            {
                XferMode[ix] |= (1 << Mode);
                break;
            }

            Mode--;
        }

        if (Mode <= 1)
            XferMode[ix] |= 1;
    }

    if (DeviceExtension->DeviceId == 0x1230)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    for (ix = 0; ix < 2; ix++)
    {
        Timing = 0;

        if (!XferModeSelect->DevicePresent[ix])
        {
            Idx = 0;
        }
        else
        {
            Idx = 1;

            if (!(XferMode[ix] & 0x7FFFFFE0))
            {
                if (XferMode[ix] & 1)
                {
                    Idx = 1;
                }
                else if (XferMode[ix] & 4)
                {
                    Idx = 2;

                    if (XferModeSelect->IoReadySupported[ix])
                        Timing |= 2;
                }
                else if (XferMode[ix] & 8)
                {
                    Idx = 3;
                }
                else if (XferMode[ix] & 0x10)
                {
                    Idx = 4;
                }
                else
                {
                    ASSERT(FALSE);
                }
            }
            else if (XferMode[ix] & 0x80)
            {
                Idx = 2;

                if (XferMode[ix] & 1)
                    Timing |= 8;

                if (XferModeSelect->IoReadySupported[ix])
                    Timing |= 2;
            }
            else if (XferMode[ix] & 0x200)
            {
                Idx = 3;

                if (XferMode[ix] & 5)
                    Timing |= 8;
            }
            else if (XferMode[ix] & 0x400)
            {
                if (XferMode[ix] & 8)
                    Idx = 3;
                else
                    Idx = 4;

                if (XferMode[ix] & 5)
                    Timing |= 8;
            }

            if (XferModeSelect->FixedDisk[ix])
                Timing |= 4;
        }

        Timing |= PiixSpecialTiming[Idx];

        if (!ix)
        {
            TimingAndControl.ISP = PiixIoReadySamplePointClockSetting[Idx];
            TimingAndControl.RecoveryTime = PiixRecoveryTimeClockSetting[Idx];

            TimingAndControl.TIME0 = ((Timing & 1) ? 1 : 0);
            TimingAndControl.IE0 = ((Timing & 2) ? 1 : 0);
            TimingAndControl.PPE0 = ((Timing & 4) ? 1 : 0);
            TimingAndControl.DTE0 = ((Timing & 8) ? 1 : 0);
        }
        else if (!Channel)
        {
            SlaveTiming.IordySamplePoint1 = PiixIoReadySamplePointClockSetting[Idx];
            SlaveTiming.RecoveryTime1 = PiixRecoveryTimeClockSetting[Idx];

            TimingAndControl.TIME1 = ((Timing & 1) ? 1 : 0);
            TimingAndControl.IE1 = ((Timing & 2) ? 1 : 0);
            TimingAndControl.PPE1 = ((Timing & 4) ? 1 : 0);
            TimingAndControl.DTE1 = ((Timing & 8) ? 1 : 0);
        }
        else
        {
            SlaveTiming.IordySamplePoint2 = PiixIoReadySamplePointClockSetting[Idx];
            SlaveTiming.RecoveryTime2 = PiixRecoveryTimeClockSetting[Idx];

            TimingAndControl.TIME1 = ((Timing & 1) ? 1 : 0);
            TimingAndControl.IE1 = ((Timing & 2) ? 1 : 0);
            TimingAndControl.PPE1 = ((Timing & 4) ? 1 : 0);
            TimingAndControl.DTE1 = ((Timing & 8) ? 1 : 0);
        }
    }

    if (DeviceExtension->DeviceId == 0x1230)
        SlaveTiming.AsUCHAR = 0;
    else
        TimingAndControl.SITRE = 1;        

    TimingAndControl.IdeDecodeEnable = 1;

    UdmaControl.AsUCHAR = 0;
    UdmaTiming.AsUSHORT = 0;

    for (ix = 0; ix < 2; ix++)
    {
        if (XferMode[ix] & 0x7FFFF800)
        {
            if (XferMode[ix] & 0x10000)
            {
                DeviceUdmaTiming = 1;
            }
            else if (XferMode[ix] & 0x8000)
            {
                DeviceUdmaTiming = 2;
            }
            else if (XferMode[ix] & 0x4000)
            {
                DeviceUdmaTiming = 1;
            }
            else if (XferMode[ix] & 0x2000)
            {
                DeviceUdmaTiming = 2;
            }
            else if (XferMode[ix] & 0x1000)
            {
                DeviceUdmaTiming = 1;
            }
            else if (XferMode[ix] & 0x800)
            {
                DeviceUdmaTiming = 0;
            }
            else
            {
                ASSERT(!"intelide: Unknown UDMA MODE\n");
                DeviceUdmaTiming = 1;
            }

            // ?? Why are only Primary used for UdmaTiming? (PCT0 and PCT1)

            if (ix == 0)
            {
                if (!Channel)
                    UdmaControl.PSDE0 = 1;
                else
                    UdmaControl.SSDE0 = 1;

                UdmaTiming.PCT0 = DeviceUdmaTiming;
            }
            else
            {
                ASSERT(ix == 1);

                if (!Channel)
                    UdmaControl.PSDE1 = 1;
                else
                    UdmaControl.SSDE1 = 1;

                UdmaTiming.PCT1 = DeviceUdmaTiming;
            }

            XferMode[ix] &= ~(0x700 | 0xE0);
        }
    }

    for (ix = 0; ix < 2; ix++)
        OutXferMode[ix] = XferMode[ix];

    *OutTimingAndControl = TimingAndControl;
    *OutSlaveTiming = SlaveTiming;
    *OutUdmaControl = UdmaControl;
    *OutUdmaTiming = UdmaTiming;

    return STATUS_SUCCESS;
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
    INTEL_PCI_CONFIGURATION IntelPciConfig;
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

    if (IS_UDMA33_CONTROLLER(DeviceId))
    {
        Mode = 0x3FFF;
        DeviceExtension->UdmaSpeed = 1;
    }

    if (IS_UDMA66_CONTROLLER(DeviceId))
    {
        Status = PciIdeXGetBusData(DeviceExtension, &IntelPciConfig, 0, sizeof(IntelPciConfig));
        if (NT_SUCCESS(Status))
        {
            DeviceExtension->CableReporting[0][0] = IntelPciConfig.IdeIoConfiguration.PCR0;
            DeviceExtension->CableReporting[0][1] = IntelPciConfig.IdeIoConfiguration.PCR1;
            DeviceExtension->CableReporting[1][0] = IntelPciConfig.IdeIoConfiguration.SCR0;
            DeviceExtension->CableReporting[1][1] = IntelPciConfig.IdeIoConfiguration.SCR1;

            Mode |= 0xC000;
        }

        DeviceExtension->UdmaSpeed = 2;
    }

    if (DeviceId == 0x244A || DeviceId == 0x244B || DeviceId == 0x248A || DeviceId == 0x248B || DeviceId == 0x24C1 ||
        DeviceId == 0x24CA || DeviceId == 0x24CB || DeviceId == 0x24D1 || DeviceId == 0x24DB || DeviceId == 0x25A2 ||
        DeviceId == 0x25A3 || DeviceId == 0x2651 || DeviceId == 0x2652 || DeviceId == 0x2653 || DeviceId == 0x266F)
    {
        ASSERT(IS_UDMA33_CONTROLLER(DeviceId));
        ASSERT(IS_UDMA66_CONTROLLER(DeviceId));

        if (NT_SUCCESS(Status))
            Mode |= 0x10000;

        DeviceExtension->UdmaSpeed = 3;
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
