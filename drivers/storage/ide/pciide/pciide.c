/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         PCI IDE bus driver
 * FILE:            drivers/storage/pciide/pciide.c
 * PURPOSE:         Main file
 * PROGRAMMERS:     Hervé Poussineau (hpoussin@reactos.org)
 */

#include "pciide.h"

#define NDEBUG
#include <debug.h>

IDE_CHANNEL_STATE NTAPI
PciIdeChannelEnabled(
    IN PVOID DeviceExtension,
    IN ULONG Channel)
{
    PCI_COMMON_CONFIG PciConfig;
    NTSTATUS Status;

    DPRINT("PciIdeChannelEnabled(%p, %lu)\n", DeviceExtension, Channel);

    Status = PciIdeXGetBusData(
        DeviceExtension,
        &PciConfig,
        0,
        PCI_COMMON_HDR_LENGTH);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("PciIdeXGetBusData() failed with status 0x%08lx\n", Status);
        return ChannelStateUnknown;
    }

    if (PCI_CONFIGURATION_TYPE(&PciConfig) != PCI_DEVICE_TYPE)
    {
        DPRINT("Wrong PCI card type. Disabling IDE channel #%lu\n", Channel);
        return ChannelDisabled;
    }

    if (PciConfig.BaseClass != PCI_CLASS_MASS_STORAGE_CTLR || PciConfig.SubClass != PCI_SUBCLASS_MSC_IDE_CTLR)
    {
        DPRINT("Wrong PCI card base class/sub class. Disabling IDE channel #%lu\n", Channel);
        return ChannelDisabled;
    }

    return ChannelStateUnknown;
}

BOOLEAN NTAPI
PciIdeSyncAccessRequired(
    IN PVOID DeviceExtension)
{
    DPRINT1("PciIdeSyncAccessRequired %p\n", DeviceExtension);

    return FALSE; /* FIXME */
}

ULONG NTAPI
PciIdeUseDma(
    IN PVOID DeviceExtension,
    IN PUCHAR CdbCommand,
    IN PUCHAR Slave)
{
    DPRINT("PciIdeUseDma(%p %p %p)\n", DeviceExtension, CdbCommand, Slave);

    /* Nothing should prevent us to use DMA */
    return 1;
}

NTSTATUS
NTAPI
PciIdeUdmaModesSupported(
    _In_ IDENTIFY_DATA IdentifyData,
    _Out_ ULONG* OutBestXferMode,
    _Out_ ULONG* OutXferMode)
{
    ULONG BestXferMode;
    ULONG XferMode;
    ULONG TempMode;

    DPRINT("PciIdeUdmaModesSupported()\n");

    if (!(IdentifyData.TranslationFieldsValid & 4))
    {
        DPRINT("PciIdeUdmaModesSupported: TranslationFieldsValid %X\n", IdentifyData.TranslationFieldsValid);
        return STATUS_SUCCESS;
    }

    if (IdentifyData.UltraDMASupport)
    {
        TempMode = IdentifyData.UltraDMASupport;
        ASSERT(TempMode);

        for (BestXferMode = 0; TempMode; BestXferMode++)
            TempMode >>= 1;

        *OutBestXferMode = (BestXferMode - 1);
        DPRINT("PciIdeUdmaModesSupported: *OutBestXferMode %X\n", *OutBestXferMode);
    }

    if (IdentifyData.UltraDMAActive)
    {
        TempMode = IdentifyData.UltraDMAActive;
        ASSERT(TempMode);

        for (XferMode = 0; TempMode; XferMode++)
            TempMode >>= 1;

        *OutXferMode = (XferMode - 1);
        DPRINT("PciIdeUdmaModesSupported: *OutXferMode %X\n", *OutXferMode);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciIdeGetControllerProperties(
    _In_ PVOID InDeviceExtension,
    _Out_ IDE_CONTROLLER_PROPERTIES* OutProperties)
{
    PPCIIDE_CONTROLLER_EXTENSION DeviceExtension = InDeviceExtension;
    USHORT DataBuffer;
    USHORT DataMask;
    ULONG Mode;
    ULONG ix;
    ULONG jx;
    NTSTATUS Status;

    DPRINT("PciIdeGetControllerProperties: %p\n", InDeviceExtension);

    if (OutProperties->Size != sizeof(IDE_CONTROLLER_PROPERTIES))
    {
        DPRINT1("PciIdeGetControllerProperties: STATUS_REVISION_MISMATCH\n");
        return STATUS_REVISION_MISMATCH;
    }

    Status = PciIdeXGetBusData(DeviceExtension, &DeviceExtension->PciConfig, 0, sizeof(DeviceExtension->PciConfig));
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciIdeGetControllerProperties: Status %X\n", Status);
        return Status;
    }

    if ((DeviceExtension->PciConfig.ProgIf & 0x80) && (DeviceExtension->PciConfig.Command & 4))
        Mode = 0x7FFFFFFF;
    else
        Mode = 0x1F;

    if (DeviceExtension->PciConfig.VendorID == 0x1039 && DeviceExtension->PciConfig.DeviceID == 0x5513)
        OutProperties->DefaultPIO = 1;

    if (DeviceExtension->PciConfig.VendorID == 0x10B9)
    {
        if (DeviceExtension->PciConfig.DeviceID == 0x5229)
        {
            DataBuffer = 0;
            DataMask = 0xCCCC;

            Status = PciIdeXSetBusData(DeviceExtension, &DataBuffer, &DataMask, 0x54, 2);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("PciIdeGetControllerProperties: Status %X\n", Status);
                return Status;
            }
        }

        if (DeviceExtension->PciConfig.VendorID == 0x10B9 &&
            DeviceExtension->PciConfig.DeviceID == 0x5229)
        {
            if (DeviceExtension->PciConfig.RevisionID == 0x20 ||
                DeviceExtension->PciConfig.RevisionID == 0xC1)
            {
                DPRINT1("PciIdeGetControllerProperties: overcome the sticky BM active bit problem in ALi controller\n");
                OutProperties->IgnoreActiveBitForAtaDevice = 1;
            }
        }
    }

    if (DeviceExtension->PciConfig.VendorID == 0xE11 &&
        DeviceExtension->PciConfig.DeviceID == 0xAE33 &&
        (DeviceExtension->PciConfig.ProgIf & 5))
    {
        DPRINT1("PciIdeGetControllerProperties: overcome the bogus busmaster interrupt in CPQ controller\n");
        OutProperties->AlwaysClearBusMasterInterrupt = 1;
    }

    for (ix = 0; ix < 2; ix++)
    {
        for (jx = 0; jx < 2; jx++)
        {
            OutProperties->SupportedTransferMode[ix][jx] = DeviceExtension->SupportedTransferMode[ix][jx] = Mode;
        }
    }

    OutProperties->PciIdeTransferModeSelect = NULL;
    OutProperties->PciIdeChannelEnabled = PciIdeChannelEnabled;
    OutProperties->PciIdeSyncAccessRequired = PciIdeSyncAccessRequired;
    OutProperties->PciIdeUdmaModesSupported = PciIdeUdmaModesSupported;
    OutProperties->PciIdeUseDma = PciIdeUseDma;
    OutProperties->AlignmentRequirement = 1;

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI
DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;

    Status = PciIdeXInitialize(
        DriverObject,
        RegistryPath,
        PciIdeGetControllerProperties,
        0);

    return Status;
}
