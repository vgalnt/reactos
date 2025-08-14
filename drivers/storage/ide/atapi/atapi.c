/*
 * PROJECT:         ReactOS Storage Stack
 * LICENSE:         See COPYING in the top level directory
 * FILE:            drivers/storage/atapi/atapi.c
 * PURPOSE:         ATAPI IDE miniport driver
 * PROGRAMMERS:     
 */

/* INCLUDES *******************************************************************/

#include "atapi.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ******************************************************************/

//ATAPI_FDO_LIST IdeGlobalFdoList = {-1, {NULL, NULL}, 0};
ULONG FdoIndex = 0;
LONG PdoIndex = 0;

PDRIVER_DISPATCH FdoPnpDispatchTable[] =
{
    ChannelStartDevice,
    IdePortStatusSuccessAndPassDownToNextDriver,
    ChannelRemoveDevice,
    IdePortStatusSuccessAndPassDownToNextDriver,
    ChannelStopDevice,
    IdePortStatusSuccessAndPassDownToNextDriver,
    IdePortStatusSuccessAndPassDownToNextDriver,
    ChannelQueryDeviceRelations,
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    ChannelFilterResourceRequirements,
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    ChannelQueryId,
    ChannelQueryPnPDeviceState,
    IdePortPassDownToNextDriver,
    ChannelUsageNotification,
    ChannelSurpriseRemoveDevice,
    IdePortPassDownToNextDriver
};

PDRIVER_DISPATCH PdoPnpDispatchTable[] =
{
    DeviceStartDevice,
    DeviceQueryStopRemoveDevice,
    DeviceRemoveDevice,
    IdePortAlwaysStatusSuccessIrp,
    DeviceStopDevice,
    DeviceQueryStopRemoveDevice,
    IdePortAlwaysStatusSuccessIrp,
    DeviceQueryDeviceRelations,
    IdePortNoSupportIrp,
    DeviceQueryCapabilities,
    IdePortNoSupportIrp,
    IdePortNoSupportIrp,
    DeviceQueryText,
    IdePortNoSupportIrp,
    IdePortNoSupportIrp,
    IdePortNoSupportIrp,
    IdePortNoSupportIrp,
    IdePortNoSupportIrp,
    IdePortNoSupportIrp,
    DeviceQueryId,
    DeviceQueryPnPDeviceState,
    IdePortNoSupportIrp,
    DeviceUsageNotification,
    DeviceRemoveDevice,
    IdePortNoSupportIrp
};

PDRIVER_DISPATCH FdoPowerDispatchTable[] =
{
    IdePortPassDownToNextDriver,
    IdePortPassDownToNextDriver,
    IdePortSetFdoPowerState,
    ChannelQueryPowerState
};

PDRIVER_DISPATCH PdoPowerDispatchTable[] =
{
    IdePortNoSupportIrp,
    IdePortNoSupportIrp,
    IdePortSetPdoPowerState,
    DeviceQueryPowerState
};

PCHAR PnpMinorNames[] =
{
    "IRP_MN_START_DEVICE",
    "IRP_MN_QUERY_REMOVE_DEVICE",
    "IRP_MN_REMOVE_DEVICE",
    "IRP_MN_CANCEL_REMOVE_DEVICE",
    "IRP_MN_STOP_DEVICE",
    "IRP_MN_QUERY_STOP_DEVICE",
    "IRP_MN_CANCEL_STOP_DEVICE",
    "IRP_MN_QUERY_DEVICE_RELATIONS",
    "IRP_MN_QUERY_INTERFACE",
    "IRP_MN_QUERY_CAPABILITIES",
    "IRP_MN_QUERY_RESOURCES",
    "IRP_MN_QUERY_RESOURCE_REQUIREMENTS",
    "IRP_MN_QUERY_DEVICE_TEXT",
    "IRP_MN_FILTER_RESOURCE_REQUIREMENTS",
    "an undefined PnP IRP",
    "IRP_MN_READ_CONFIG",
    "IRP_MN_WRITE_CONFIG",
    "IRP_MN_EJECT",
    "IRP_MN_SET_LOCK",
    "IRP_MN_QUERY_ID",
    "IRP_MN_QUERY_PNP_DEVICE_STATE",
    "IRP_MN_QUERY_BUS_INFORMATION",
    "IRP_MN_DEVICE_USAGE_NOTIFICATION",
    "IRP_MN_SURPRISE_REMOVAL",
    "IRP_MN_QUERY_LEGACY_BUS_INFORMATION"
};

PCHAR PowerMinorNames[] =
{
    "IRP_MN_WAIT_WAKE",
    "IRP_MN_POWER_SEQUENCE",
    "IRP_MN_SET_POWER",
    "IRP_MN_QUERY_POWER"
};

PWCHAR UserDeviceString[] =
{
    L"UserMasterDeviceType",
    L"UserSlaveDeviceType",
    L"UserMasterDeviceType2",
    L"UserSlaveDeviceType2",
    L"UserMasterDeviceTimingModeAllowed",
    L"UserSlaveDeviceTimingModeAllowed",
    L"UserMasterDeviceTimingModeAllowed2",
    L"UserSlaveDeviceTimingModeAllowed2"
};

PWSTR TypeName[] =
{
    L"MasterDeviceType",
    L"SlaveDeviceType",
    L"MasterDeviceType2",
    L"SlaveDeviceType2"
};

PWSTR DetectionTimeoutName[] =
{
    L"MasterDeviceDetectionTimeout",
    L"SlaveDeviceDetectionTimeout",
    NULL,
    NULL
};

PWSTR UserTimingModeAllowedName[] =
{
    L"UserMasterDeviceTimingModeAllowed",
    L"UserSlaveDeviceTimingModeAllowed",
    L"UserMasterDeviceTimingModeAllowed2",
    L"UserSlaveDeviceTimingModeAllowed2"
};

PWSTR TimingModeName[] =
{
    L"MasterDeviceTimingMode",
    L"SlaveDeviceTimingMode",
    L"MasterDeviceTimingMode2",
    L"SlaveDeviceTimingMode2"
};

PWSTR DataCheckSumName[] =
{
    L"MasterIdDataCheckSum",
    L"SlaveIdDataCheckSum",
    L"MasterIdDataCheckSum2",
    L"SlaveIdDataCheckSum2"
};

PWSTR TimingModeAllowedName[] =
{
    L"MasterDeviceTimingModeAllowed",
    L"SlaveDeviceTimingModeAllowed",
    L"MasterDeviceTimingModeAllowed2",
    L"SlaveDeviceTimingModeAllowed2"
};

PCHAR DeviceTypeName[10][3] =
{
    {"Disk", "GenDisk", "DiskPeripheral"},
    {"Sequential", "GenSequential", "TapePeripheral"},
    {"Printer", "GenPrinter", "PrinterPeripheral"},
    {"Processor", "GenProcessor", "ProcessorPeripheral"},
    {"Worm", "GenWorm", "WormPeripheral"},
    {"CdRom", "GenCdRom", "CdRomPeripheral"},
    {"Scanner", "GenScanner", "ScannerPeripheral"},
    {"Optical", "GenOptical", "OpticalDiskPeripheral"},
    {"Changer", "GenChanger", "MediumChangerPeripheral"},
    {"Net", "GenNet", "CommunicationPeripheral"}
};

extern NTSYSAPI BOOLEAN InitSafeBootMode;

/* PRIVATE FUNCTIONS ********************************************************/

VOID
NTAPI
IdePortUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
ChannelAddChannel(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT LowerPdo,
    _Out_ PFDO_DEVICE_EXTENSION* OutFdoExtension)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    UNICODE_STRING FdoName;
    WCHAR NameBuffer[0x40];
    PDEVICE_OBJECT Fdo;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ChannelAddChannel: %p, %p\n", DriverObject, LowerPdo);

    swprintf(NameBuffer, L"\\Device\\Ide\\IdePort%d", FdoIndex);
    RtlInitUnicodeString(&FdoName, NameBuffer);

    Status = IoCreateDevice(DriverObject, sizeof(*FdoExtension), &FdoName, 4, 0x100, 0, &Fdo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ChannelAddChannel: Status %X\n", Status);
        return Status;
    }

    FdoExtension = Fdo->DeviceExtension;
    RtlZeroMemory(FdoExtension, sizeof(*FdoExtension));

    FdoExtension->HwDeviceExtension = &FdoExtension->AtaExt;
    FdoExtension->LowPdo = LowerPdo;
    FdoExtension->DriverObject = DriverObject;
    FdoExtension->SelfDevice = Fdo;
    FdoExtension->PassDownToNextDriver = IdePortPassDownToNextDriver;
    FdoExtension->FdoPnpDispatchTable = FdoPnpDispatchTable;
    FdoExtension->FdoPowerDispatchTable = FdoPowerDispatchTable;
    //FdoExtension->FdoWmiDispatchTable = FdoWmiDispatchTable;

    FdoExtension->LowDevice = IoAttachDeviceToDeviceStack(Fdo, LowerPdo);
    if (!FdoExtension->LowDevice)
    {
        DPRINT1("ChannelAddChannel: STATUS_UNSUCCESSFUL\n");
        IoDeleteDevice(Fdo);
        return STATUS_UNSUCCESSFUL;
    }

    if (FdoExtension->LowDevice->AlignmentRequirement < 1)
        Fdo->AlignmentRequirement = 1;
    else
        Fdo->AlignmentRequirement = FdoExtension->LowDevice->AlignmentRequirement;

    FdoExtension->FdoIndex = FdoIndex++;

    *OutFdoExtension = FdoExtension;

    //IdeAddToFdoList(&IdeGlobalFdoList, FdoExtension);

    Fdo->Flags &= ~DO_DEVICE_INITIALIZING;

    DPRINT("ChannelAddChannel: DeviceObject %p returnd status %X from Addevice\n", LowerPdo, Status);

    return Status;
}

NTSTATUS
NTAPI
ChannelAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT LowerPdo)
{
    PFDO_DEVICE_EXTENSION dummy;
    return ChannelAddChannel(DriverObject, LowerPdo, &dummy);
}

VOID
NTAPI
AtapiTaskRegisterSnapshot(
    _In_ PIDE_CMD_BLOCK_REGS CmdBlock,
    _In_ PIDEREGS IdeReg)
{
    ASSERT(IdeReg);

    IdeReg->bFeaturesReg = READ_PORT_UCHAR(CmdBlock->Error);
    IdeReg->bSectorCountReg = READ_PORT_UCHAR(CmdBlock->SectorCount);
    IdeReg->bSectorNumberReg = READ_PORT_UCHAR(CmdBlock->LbaLow);
    IdeReg->bCylLowReg = READ_PORT_UCHAR(CmdBlock->LbaMid);
    IdeReg->bCylHighReg = READ_PORT_UCHAR(CmdBlock->LbaHigh);
    IdeReg->bDriveHeadReg = READ_PORT_UCHAR(CmdBlock->DeviceSelect);
    IdeReg->bCommandReg = READ_PORT_UCHAR(CmdBlock->Status);
}

VOID
NTAPI
IdeHardReset(
    _In_ PIDE_CMD_BLOCK_REGS CmdBlock,
    _In_ PIDE_CTRL_BLOCK_REGS CtrlBlock,
    _In_ UCHAR Value,
    _In_ BOOLEAN IsWaitOnBusy)
{
    UCHAR IdeStatus;
    ULONG ix;
    ULONG jx;

    DPRINT("IdeHardReset: Resetting controller.\n");

    WRITE_PORT_UCHAR(CmdBlock->DeviceSelect, IDE_DRIVE_SELECT);
    WRITE_PORT_UCHAR(CtrlBlock->DeviceControl, 6);
    KeStallExecutionProcessor(10);

    WRITE_PORT_UCHAR(CtrlBlock->DeviceControl, (!Value ? 0 : 2));
    KeStallExecutionProcessor(1);

    if (!IsWaitOnBusy)
        return;

    for (jx = 0; jx < 5000; jx++)
    {
        IdeStatus = READ_PORT_UCHAR(CmdBlock->Status);
        if (!(IdeStatus & 0x80))
            break;
        KeStallExecutionProcessor(100);
    }

    if (jx == 5000)
    {
        DPRINT("IdeHardReset: WaitOnBusyUntil failed. status %X\n", IdeStatus);
    }

    WRITE_PORT_UCHAR(CmdBlock->DeviceSelect, IDE_DRIVE_SELECT);

    if (READ_PORT_UCHAR(CmdBlock->DeviceSelect) != IDE_DRIVE_SELECT)
    {
        KeStallExecutionProcessor(1000);
        WRITE_PORT_UCHAR(CmdBlock->DeviceSelect, 0xB0);
    }

    for (ix = 0; ix < 31; ix++)
    {
        for (jx = 0; jx < 2500; jx++)
        {
            IdeStatus = READ_PORT_UCHAR(CmdBlock->Status);
            if (!(IdeStatus & 0x80))
                break;
            KeStallExecutionProcessor(400);
        }

        if (IdeStatus == 0xFF)
            break;

        if (!(IdeStatus & 0x80))
            return;

        DPRINT("IdeHardReset: WaitOnBusy failed. status %X\n", IdeStatus);
    }

    if (IdeStatus & 0x80)
    {
        DPRINT("IdeHardReset: WaitOnBusy failed. status %X\n", IdeStatus);
    }
}

BOOLEAN
NTAPI
IdePortIdentifyDevice(
    _In_ PIDE_CMD_BLOCK_REGS CmdBlock,
    _In_ PIDE_CTRL_BLOCK_REGS CtrlBlock,
    _In_ ULONG MaxIdeDevice)
{
    ULONG Device = 0;
    ULONG ix = 4;
    ULONG jx;
    UCHAR status;
    BOOLEAN Result = TRUE;

    DPRINT("IdePortIdentifyDevice: %X, %X, %X\n", CmdBlock->CmdBlockBase, CtrlBlock->CtrlBlockBase, MaxIdeDevice);

    while (TRUE)
    {
        WRITE_PORT_UCHAR(CmdBlock->DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT));
        WRITE_PORT_UCHAR(CmdBlock->BytesHigh, 0xAA);
        WRITE_PORT_UCHAR(CmdBlock->BytesLow, 0x55);

        if (READ_PORT_UCHAR(CmdBlock->LbaHigh) == 0xAA && READ_PORT_UCHAR(CmdBlock->LbaMid) == 0x55)
        {
            DPRINT("IdePortIdentifyDevice: Result = 0\n");
            Result = FALSE;
        }
        else
        {
            status = READ_PORT_UCHAR(CmdBlock->Status);

            DPRINT("IdePortIdentifyDevice: status read back from Master (%X)\n", status);

            if (status & 0x80)
            {
                for (jx = 0; jx < 0xA; jx++)
                {
                    KeStallExecutionProcessor(1000);
                    status = READ_PORT_UCHAR(CmdBlock->Status);

                    DPRINT("IdePortIdentifyDevice: First access to status %X\n", status);

                    if (!(status & 0x80))
                        break;
                }

                ix--;
                if (ix != 0 && !(status & 0x80))
                    continue;
            }

            Device++;

            WRITE_PORT_UCHAR(CmdBlock->DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT));
            WRITE_PORT_UCHAR(CmdBlock->BytesHigh, 0xAA);
            WRITE_PORT_UCHAR(CmdBlock->BytesLow, 0x55);

            if (READ_PORT_UCHAR(CmdBlock->LbaHigh) != 0xAA || READ_PORT_UCHAR(CmdBlock->LbaMid) != 0x55)
            {
                status = READ_PORT_UCHAR(CmdBlock->Status);
                DPRINT("IdePortIdentifyDevice: status read back from Slave (%X)\n", status);
            }
            else
            {
                DPRINT("IdePortIdentifyDevice: Result = 0\n");
                Result = FALSE;
            }
        }

        Device++;
        if (Device >= MaxIdeDevice || !Result)
            return Result;
    }
}

ULONG
NTAPI
IdePortChannelEmptyQuick(
    _In_ PIDE_CMD_BLOCK_REGS CmdBlock,
    _In_ PIDE_CTRL_BLOCK_REGS CtrlBlock,
    _In_ ULONG MaxIdeDevice,
    _In_ ULONG* OutDevice,
    _In_ ULONG* OutWaitCount,
    _In_ ULONG* OutEmptyResult)
{
    ULONG EmptyQuickResult;
    ULONG Device;
    ULONG ix;
    ULONG jx;
    UCHAR status = 0xFF;
    UCHAR GetStatus;
    BOOLEAN NoIdentifyDevice = TRUE;

    DPRINT("IdePortChannelEmptyQuick: %X, %X, %X, %X, %X\n", CmdBlock->CmdBlockBase, CtrlBlock->CtrlBlockBase, MaxIdeDevice, *OutWaitCount, *OutDevice);

    if (*OutWaitCount)
    {
        (*OutWaitCount)--;

        WRITE_PORT_UCHAR(CmdBlock->DeviceSelect, (((*OutDevice & 0x1) << 4) | IDE_DRIVE_SELECT));

        jx = 0;
        do
        {
            status = READ_PORT_UCHAR(CmdBlock->Status);
            if (status == 0xFF)
                break;

            if (!(status & 0x80))
                break;

            KeStallExecutionProcessor(5);

            jx++;
        }
        while (jx < 20);

        DPRINT("IdePortChannelEmptyQuick: Status after first retry %X\n", status);

        if (status == 0xFF)
        {
            (*OutDevice)++;
            *OutWaitCount = 0;
        }

        if (*OutWaitCount && status & 0x80)
            return 0xC000022D;
    }

    if (*OutEmptyResult || !(status & 0x80) || status == 0xFE)
    {
        if (status != 0xFF)
        {
            (*OutDevice)++;
            NoIdentifyDevice = 0;
        }
    }
    else if (status != 0xFF)
    {
        DPRINT("IdePortChannelEmptyQuick: channel looks busy %X. Try a reset\n", status);

        WRITE_PORT_UCHAR(CtrlBlock->DeviceControl, 4);
        KeStallExecutionProcessor(10);

        WRITE_PORT_UCHAR(CtrlBlock->DeviceControl, 0);
        WRITE_PORT_UCHAR(CmdBlock->DeviceSelect, (((*OutDevice & 0x1) << 4) | IDE_DRIVE_SELECT));

        jx = 0;
        do
        {
            status = READ_PORT_UCHAR(CmdBlock->Status);
            if (status == 0xFF)
                break;

            if (!(status & 0x80))
                break;

            KeStallExecutionProcessor(5);

            jx++;
        }
        while (jx < 20);

        if ((status & 0x80) && status != 0xFF)
        {
            *OutWaitCount = 2;
            *OutEmptyResult = 1;

            return STATUS_RETRY;
        }

        if (status != 0xFF)
        {
            (*OutDevice)++;
            NoIdentifyDevice = 0;
        }
    }

    ix = Device = *OutDevice;
    while (ix < MaxIdeDevice)
    {
        if (!NoIdentifyDevice)
        {
            EmptyQuickResult = IdePortIdentifyDevice(CmdBlock, CtrlBlock, MaxIdeDevice);
            DPRINT("IdePortChannelEmptyQuick: EmptyQuickResult %X\n", EmptyQuickResult);
            return (EmptyQuickResult != 0);
        }

        WRITE_PORT_UCHAR(CmdBlock->DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT));
        GetStatus = READ_PORT_UCHAR(CmdBlock->Status);

        DPRINT("IdePortChannelEmptyQuick: status for device %X after GetStatus %X\n", Device, GetStatus);

        if (GetStatus != 0xFF && GetStatus != 0xFE)
        {
            jx = 0;
            do
            {
                status = READ_PORT_UCHAR(CmdBlock->Status);
                if (status == 0xFF)
                    break;

                if (!(status & 0x80))
                    break;

                KeStallExecutionProcessor(5);

                jx++;
            }
            while (jx < 20);

            if ((status & 0xFE) != 0xFE)
            {
                if (status & 0x80)
                {
                    DPRINT("IdePortChannelEmptyQuick: Re-init the counts - device %X, status %X", Device, status);

                    *OutDevice = Device;
                    *OutWaitCount = 2;
                    *OutEmptyResult = 0;

                    return STATUS_RETRY;
                }

                if (status != 0xFF)
                    NoIdentifyDevice = 0;
            }
        }

        Device++;
        ix = Device;
    }

    if (NoIdentifyDevice)
        return 1;

    EmptyQuickResult = IdePortIdentifyDevice(CmdBlock, CtrlBlock, MaxIdeDevice);

    DPRINT("IdePortChannelEmptyQuick: EmptyQuickResult %X\n", EmptyQuickResult);

    return (EmptyQuickResult != 0);
}

UCHAR
NTAPI
IdeSendPassThroughCommand(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    PIDE_CTRL_BLOCK_REGS CtrlBlock;
    PATA_PASS_THROUGH AtaPassThr;
    PIDE_CMD_BLOCK_REGS CmdBlock;
    ULONG EmptyQuickResult;
    ULONG SectorCount;
    ULONG ix;
    ULONG jx;
    UCHAR SectorNumber;
    UCHAR SrbStatus;
    UCHAR status;

    CmdBlock = &HwDeviceExtension->CmdBlock;
    CtrlBlock = &HwDeviceExtension->CtrlBlock;

    AtaPassThr = Srb->DataBuffer;

    AtaPassThr->IdeReg.bDriveHeadReg &= ~0xB0;
    AtaPassThr->IdeReg.bDriveHeadReg |= (((Srb->TargetId & 0x1) << 4) | IDE_DRIVE_SELECT);

    DPRINT("IdeSendPassThroughCommand: %p, %p\n", HwDeviceExtension, Srb);

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, AtaPassThr->IdeReg.bDriveHeadReg);

    if (AtaPassThr->IdeReg.bReserved & 0x20)
    {
        SectorNumber = AtaPassThr->IdeReg.bSectorNumberReg;
        SectorCount = AtaPassThr->IdeReg.bSectorCountReg;

        if (SectorNumber)
        {
            if (SectorNumber > 30)
                SectorNumber = 30;

            status = READ_PORT_UCHAR(CmdBlock->Status);

            for (jx = 0; jx < (SectorNumber * 10000); jx++)
            {
                status = READ_PORT_UCHAR(CmdBlock->Status);
                if (!(status & 0x80))
                    break;

                KeStallExecutionProcessor(100);
            }

            if (jx == (SectorNumber * 10000))
            {
                DPRINT("IdeSendPassThroughCommand: WaitOnBusyUntil failed in '%s' line %u. status = %X\n", __FILE__, __LINE__, status);
            }
        }

        if (!SectorCount)
            SectorCount = 1;

        for (ix = SectorCount; ix; ix--)
        {
            KeStallExecutionProcessor(100);
            AtapiTaskRegisterSnapshot(CmdBlock, &AtaPassThr->IdeReg);
        }

        return 1;
    }

    if (AtaPassThr->IdeReg.bReserved & 4)
    {
        EmptyQuickResult = IdePortChannelEmptyQuick(CmdBlock, CtrlBlock, HwDeviceExtension->MaxIdeDevice,
                                                    &HwDeviceExtension->EmptyDevice, 
                                                    &HwDeviceExtension->EmptyWaitCount,
                                                    &HwDeviceExtension->EmptyResult);
        if (EmptyQuickResult)
        {
            return (EmptyQuickResult != STATUS_RETRY);
        }

        return 4;
    }

    if (AtaPassThr->IdeReg.bReserved & 8)
    {
        IdeHardReset(CmdBlock, CtrlBlock, 0, TRUE);
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect,
                         (AtaPassThr->IdeReg.bDriveHeadReg | (((Srb->TargetId & 0x1) << 4) | IDE_DRIVE_SELECT)));
    }

    status = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
    if (status & 0x80)
    {
        DPRINT("IdeSendPassThroughCommand: Returning BUSY status\n");
        return 5;
    }

    if (AtaPassThr->IdeReg.bReserved & 0x40 &&
        !(status & 0x40) &&
        (status || !(HwDeviceExtension->DeviceFlags[Srb->TargetId] & 0x100000)))
    {
        DPRINT("IdeSendPassThroughCommand: DRDY not ready\n");
        return 5;
    }

    if (AtaPassThr->IdeReg.bCommandReg == 8)
    {
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Srb->TargetId & 0x1) << 4) | IDE_DRIVE_SELECT));
        KeStallExecutionProcessor(500);

        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, 8);
        KeStallExecutionProcessor(500);

        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Srb->TargetId & 0x1) << 4) | IDE_DRIVE_SELECT));

        ix = 0;
        jx = 0;
        while (TRUE)
        {
            status = READ_PORT_UCHAR(CmdBlock->Status);
            if (!(status & 0x80))
                break;

            KeStallExecutionProcessor(40);

            jx++;
            if (jx < 25000)
                continue;

            DPRINT("IdeSendPassThroughCommand: after 1 sec wait, device is still busy with %X status = %X\n", CmdBlock->CmdBlockBase, status);

            ix++;
            if (ix >= 0xA)
            {
                if (status & 0x80)
                {
                    DPRINT("IdeSendPassThroughCommand: WaitOnBusy failed in '%s' line %u. %X status = %X\n", __FILE__, __LINE__, CmdBlock->CmdBlockBase, status);
                }

                break;
            }

            jx = 0;
        }

        KeStallExecutionProcessor(500);

        SrbStatus = 1;
    }
    else if ((HwDeviceExtension->DeviceFlags[Srb->TargetId] & 0x20000) &&
             AtaPassThr->IdeReg.bCommandReg == 0xEC &&
             !(AtaPassThr->IdeReg.bFeaturesReg & 0x10))
    {
        ASSERT(!(HwDeviceExtension->DeviceFlags[Srb->TargetId] & 0x10));//DFLAGS_REMOVABLE_DRIVE

        DPRINT("IdeSendPassThroughCommand: Bypassing identify command\n");

        RtlMoveMemory(AtaPassThr->Buffer, &HwDeviceExtension->IdentifyData[Srb->TargetId], AtaPassThr->BufferSize);

        return 1;
    }

    SrbStatus = 0;

    HwDeviceExtension->TransferDataBuffer = AtaPassThr->Buffer;
    HwDeviceExtension->TransferDataBytes = AtaPassThr->BufferSize;

    HwDeviceExtension->ExpectingInterrupt = 1;

    WRITE_PORT_UCHAR(CmdBlock->Features, AtaPassThr->IdeReg.bFeaturesReg);
    WRITE_PORT_UCHAR(CmdBlock->SectorCount, AtaPassThr->IdeReg.bSectorCountReg);
    WRITE_PORT_UCHAR(CmdBlock->LbaLow, AtaPassThr->IdeReg.bSectorNumberReg);
    WRITE_PORT_UCHAR(CmdBlock->BytesLow, AtaPassThr->IdeReg.bCylLowReg);
    WRITE_PORT_UCHAR(CmdBlock->BytesHigh, AtaPassThr->IdeReg.bCylHighReg);
    WRITE_PORT_UCHAR(CmdBlock->Command, AtaPassThr->IdeReg.bCommandReg);

    DPRINT("IdeSendPassThroughCommand: %X %X command = %X\n", CmdBlock->CmdBlockBase, Srb->TargetId, AtaPassThr->IdeReg.bCommandReg);

    return SrbStatus;
}

PPDOX_SRB_DATA
NTAPI
IdeGetSrbData(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
  
    if (!Srb->OriginalRequest)
        return NULL;

    PdoExtension = IoGetCurrentIrpStackLocation(Srb->OriginalRequest)->Parameters.Others.Argument4;
    if (!PdoExtension)
        return NULL;

    return &PdoExtension->PdoxSrbData;
}

VOID
__cdecl
IdePortNotification(
    _In_ ULONG NotificationType,
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    ...)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension = NULL;
    PSCSI_REQUEST_BLOCK Srb;
    PPDOX_SRB_DATA SrbData;
    UCHAR DataTransferLength;
    va_list va;

    va_start(va, HwDeviceExtension);

    FdoExtension = CONTAINING_RECORD(HwDeviceExtension, FDO_DEVICE_EXTENSION, AtaExt);
    DPRINT("IdePortNotification: %X\n", FdoExtension->InterruptData.CompletedRequests);

    switch (NotificationType)
    {
        case 0:
        {
            Srb = va_arg(va, PSCSI_REQUEST_BLOCK);

            ASSERT(Srb->SrbStatus != SRB_STATUS_PENDING);
            ASSERT(Srb->SrbStatus != SRB_STATUS_SUCCESS ||
                   Srb->ScsiStatus == SCSISTAT_GOOD ||
                   Srb->Function != SRB_FUNCTION_EXECUTE_SCSI);

            if (!(Srb->SrbFlags & 0x10000))
            {
                va_end(va);
                return;
            }

            Srb->SrbFlags &= ~0x10000;

            if (Srb->Function == 0x10)
            {
                PdoExtension->CompletedAbort = FdoExtension->InterruptData.CompletedAbort;

                FdoExtension->InterruptData.CompletedAbort = 
                    IoGetCurrentIrpStackLocation(Srb->OriginalRequest)->Parameters.Others.Argument4;
            }
            else
            {
                SrbData = IdeGetSrbData(FdoExtension, Srb);

                ASSERT(SrbData);
                ASSERT(SrbData->CurrentSrb != NULL && SrbData->CompletedRequests == NULL);

                if (Srb->SrbStatus == 1)
                {
                    DataTransferLength = Srb->Cdb[0];

                    if ((DataTransferLength == 0x28 || DataTransferLength == 0x2A))
                        ASSERT(Srb->DataTransferLength);
                }

                ASSERT(FdoExtension->InterruptData.CompletedRequests == NULL);

                SrbData->CompletedRequests = FdoExtension->InterruptData.CompletedRequests;
                FdoExtension->InterruptData.CompletedRequests = SrbData;

                UNIMPLEMENTED_ONCE;
                //IdeLogSaveTaskFile(..);
            }

            break;
        }
        case 1:
        {
            FdoExtension->InterruptData.Flags |= 8;
            break;
        }
        case 3:
        {
            Srb = va_arg(va, PSCSI_REQUEST_BLOCK);
            if (Srb)
                PdoExtension = IoGetCurrentIrpStackLocation(Srb->OriginalRequest)->Parameters.Others.Argument4;

            ASSERT(FdoExtension->InterruptData.PdoExtensionResetBus == NULL);

            FdoExtension->InterruptData.Flags |= 0x200;
            FdoExtension->InterruptData.PdoExtensionResetBus = PdoExtension;
            break;
        }
        case 6:
        {
            FdoExtension->InterruptData.Flags |= 0x10000;
            FdoExtension->InterruptData.HwTimerCallBack = va_arg(va, PHW_TIMER);
            FdoExtension->InterruptData.MiniportTimerValue = va_arg(va, ULONG);
            break;
        }
        case 0xA:
        {
            FdoExtension->InterruptData.Flags |= 0x20000;
            break;
        }
        case 0xB:
        {
            FdoExtension->InterruptData.Flags |= 0x40000;
            break;
        }
        default:
        {
            DPRINT1("IdePortNotification: Unknown NotificationType %X\n", NotificationType);
            ASSERT(FALSE);
            break;
        }
    }

    va_end(va);

    FdoExtension->InterruptData.Flags |= 4;
}

UCHAR
NTAPI
IdeReadWriteExt(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    VOID (NTAPI* BmArm)(PVOID);
    ULONG SectorCount;
    ULONG StartingSector;
    ULONG BytesXferred;
    ULONG jx;
    UCHAR IdeStatus;
    UCHAR StartIdeStatus;
    PCDB Cdb;
    ULONG Device;

    Device = Srb->TargetId;

    DPRINT("IdeReadWriteExt: %X, %X, %X\n", HwDeviceExtension->CmdBlock.CmdBlockBase, Device, Srb->SrbExtension);

    ASSERT(HwDeviceExtension->DeviceFlags[Device] & 0x200000);//DFLAGS_48BIT_LBA
    ASSERT(HwDeviceExtension->DeviceFlags[Device] & 0x400);//DFLAGS_LBA

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT));

    StartIdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
    if (StartIdeStatus & 0x80)
    {
        DPRINT("IdeReadWriteExt: Returning BUSY StartIdeStatus\n");
        return 5;
    }

    if (!(StartIdeStatus & 0x40))
    {
        DPRINT("IdeReadWriteExt: IDE_STATUS_DRDY not set\n");
        return 5;
    }

    HwDeviceExtension->TransferDataBuffer = (PUCHAR)Srb->DataBuffer;
    HwDeviceExtension->TransferDataBytes = Srb->DataTransferLength;

    HwDeviceExtension->ExpectingInterrupt = 1;

    SectorCount = ((Srb->DataTransferLength + (0x200 - 1)) / 0x200);
    ASSERT(SectorCount != 0);

    Cdb = (PCDB)Srb->Cdb;
    StartingSector = (Cdb->CDB10.LogicalBlockByte0 << 24) |
                     (Cdb->CDB10.LogicalBlockByte1 << 16) |
                     (Cdb->CDB10.LogicalBlockByte2 << 8) |
                     (Cdb->CDB10.LogicalBlockByte3);

    DPRINT("IdeReadWriteExt: StartingSector %X, SectorCount %X\n", StartingSector, SectorCount);

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT | 0x40));

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.SectorCount, (UCHAR)(SectorCount >> 8));
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaLow, (UCHAR)(StartingSector >> 24));
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaMid, 0);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaHigh, 0);

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.SectorCount, (UCHAR)SectorCount);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaLow, (UCHAR)StartingSector);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaMid, (UCHAR)(StartingSector >> 8));
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaHigh, (UCHAR)(StartingSector >> 16));

    if (Srb->SrbFlags & 0x40) // SRB_FLAGS_DATA_IN
    {
        if ((ULONG_PTR)Srb->SrbExtension & 2)
        {
            WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, 0x25);
            HwDeviceExtension->IsActiveDmaTransfer = 1;
            BmArm = HwDeviceExtension->BusMasterInterface.BmArm;
            BmArm(HwDeviceExtension->BusMasterInterface.Context);
        }
        else
        {
            ASSERT(HwDeviceExtension->DeviceParameters[Device].IdePioReadCommandExt);
            WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, HwDeviceExtension->DeviceParameters[Device].IdePioReadCommandExt);
        }

        return 0;
    }

    if ((ULONG_PTR)Srb->SrbExtension & 2)
    {
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, 0x35);

        HwDeviceExtension->IsActiveDmaTransfer = 1;

        BmArm = HwDeviceExtension->BusMasterInterface.BmArm;
        BmArm(HwDeviceExtension->BusMasterInterface.Context);

        return 0;
    }

    ASSERT(HwDeviceExtension->DeviceParameters[Device].IdePioWriteCommandExt);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, HwDeviceExtension->DeviceParameters[Device].IdePioWriteCommandExt);

    if (HwDeviceExtension->TransferDataBytes >= HwDeviceExtension->DeviceParameters[Device].MaxTransferSize)
        BytesXferred = HwDeviceExtension->DeviceParameters[Device].MaxTransferSize;
    else
        BytesXferred = HwDeviceExtension->TransferDataBytes;

    for (jx = 0; jx < 20000; jx++)
    {
        IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
        if (!(IdeStatus & 0x80))
            break;

        KeStallExecutionProcessor(150);
    }

    if (IdeStatus & 0x80)
    {
        DPRINT("IdeReadWriteExt 2: Returning BUSY StartIdeStatus %X\n", IdeStatus);
        return 5;
    }

    for (jx = 0; jx < 1000; jx++)
    {
        IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
        if (IdeStatus & 8)
            break;

        KeStallExecutionProcessor(200);
    }

    if (!(IdeStatus & 8))
    {
        DPRINT("IdeReadWriteExt: DRQ never asserted (%X) original StartIdeStatus (%X)\n", IdeStatus, StartIdeStatus);

        HwDeviceExtension->TransferDataBytes = 0;
        HwDeviceExtension->CurrentSrb = 0;
        HwDeviceExtension->ExpectingInterrupt = 0;

        return 9;
    }

    WRITE_PORT_BUFFER_USHORT(HwDeviceExtension->CmdBlock.Data,
                             (PUSHORT)HwDeviceExtension->TransferDataBuffer,
                             (BytesXferred >> 1));

    HwDeviceExtension->TransferDataBytes -= BytesXferred;
    HwDeviceExtension->TransferDataBuffer += BytesXferred;

    return 0;
}

UCHAR
NTAPI
IdeReadWrite(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    VOID (NTAPI* BmArm)(PVOID);
    PCDB Cdb;
    ULONG SectorsPerTrack;
    ULONG StartingSector;
    ULONG NumberOfHeads;
    ULONG BytesXferred;
    ULONG Device;
    ULONG Sector;
    ULONG Head;
    ULONG jx;
    UCHAR StartIdeStatus;
    UCHAR IdeStatus;

    Device = Srb->TargetId;

    DPRINT("IdeReadWrite: %X, %X\n", HwDeviceExtension->CmdBlock.CmdBlockBase, Device);

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT));

    StartIdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
    if (StartIdeStatus & 0x80)
    {
        DPRINT("IdeReadWrite: Returning BUSY status\n");
        return 5;
    }

    if (!(StartIdeStatus & 0x40))
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    HwDeviceExtension->TransferDataBuffer = (PUCHAR)Srb->DataBuffer;
    HwDeviceExtension->TransferDataBytes = Srb->DataTransferLength;

    HwDeviceExtension->ExpectingInterrupt = 1;

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.SectorCount, ((Srb->DataTransferLength + (0x200 - 1)) / 0x200));

    Cdb = (PCDB)Srb->Cdb;

    StartingSector = (Cdb->CDB10.LogicalBlockByte0 << 24) |
                     (Cdb->CDB10.LogicalBlockByte1 << 16) |
                     (Cdb->CDB10.LogicalBlockByte2 << 8) |
                     (Cdb->CDB10.LogicalBlockByte3);

    DPRINT("IdeReadWrite: Starting sector is %X, Number of bytes %X\n", StartingSector, Srb->DataTransferLength);

    if (HwDeviceExtension->DeviceFlags[Device] & 0x400)
    {
        Head = (0x40 | ((StartingSector >> 24) & 0x0F));
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT | Head));

        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaLow, StartingSector);
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaMid, (StartingSector >> 8));
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaHigh, (StartingSector >> 16));
    }
    else
    {
        SectorsPerTrack = HwDeviceExtension->SectorsPerTrack[Device];
        NumberOfHeads = HwDeviceExtension->NumberOfHeads[Device];
        Head = (StartingSector / SectorsPerTrack);
        Sector = (StartingSector % SectorsPerTrack);

        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaLow, (StartingSector % SectorsPerTrack + 1));
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaMid, (StartingSector / (NumberOfHeads * SectorsPerTrack)));
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaHigh, (StartingSector / (NumberOfHeads * SectorsPerTrack) >> 8));

        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT | (Head % NumberOfHeads)));

        DPRINT1("IdeReadWrite: Cylinder %X Head %X Sector %X\n",
                (StartingSector / (SectorsPerTrack * NumberOfHeads)),
                (Head % NumberOfHeads),
                (Sector + 1));
    }

    if (Srb->SrbFlags & 0x40)
    {
        if ((ULONG_PTR)Srb->SrbExtension & 2)
            WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, 0xC8);
        else
            WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, HwDeviceExtension->DeviceParameters[Device].IdePioReadCommand);
    }
    else
    {
        if ((ULONG_PTR)Srb->SrbExtension & 2)
            WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, 0xCA);
        else
            WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, HwDeviceExtension->DeviceParameters[Device].IdePioWriteCommand);

        if (!((ULONG_PTR)Srb->SrbExtension & 2))
        {
            if (HwDeviceExtension->TransferDataBytes >= HwDeviceExtension->DeviceParameters[Device].MaxTransferSize)
                BytesXferred = HwDeviceExtension->DeviceParameters[Device].MaxTransferSize;
            else
                BytesXferred = HwDeviceExtension->TransferDataBytes;

            for (jx = 0; jx < 20000; jx++)
            {
                IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
                if (!(IdeStatus & 0x80))
                    break;

                KeStallExecutionProcessor(150);
            }

            if (IdeStatus & 0x80)
            {
                DPRINT("IdeReadWrite 2: Returning BUSY status %X\n", IdeStatus);
                return 5;
            }

            for (jx = 0; jx < 1000; jx++)
            {
                IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
                if (IdeStatus & 8)
                    break;

                KeStallExecutionProcessor(200);
            }

            if (!(IdeStatus & 8))
            {
                DPRINT("IdeReadWrite: DRQ never asserted (%X) original status (%X)\n", IdeStatus, StartIdeStatus);

                HwDeviceExtension->TransferDataBytes = 0;
                HwDeviceExtension->CurrentSrb = 0;
                HwDeviceExtension->ExpectingInterrupt = 0;

                return 9;
            }

            WRITE_PORT_BUFFER_USHORT(HwDeviceExtension->CmdBlock.Data, (PUSHORT)HwDeviceExtension->TransferDataBuffer, (BytesXferred / 2));

            HwDeviceExtension->TransferDataBytes -= BytesXferred;
            HwDeviceExtension->TransferDataBuffer += BytesXferred;
        }
    }

    if ((ULONG_PTR)Srb->SrbExtension & 2)
    {
        HwDeviceExtension->IsActiveDmaTransfer = 1;

        BmArm = HwDeviceExtension->BusMasterInterface.BmArm;
        BmArm(HwDeviceExtension->BusMasterInterface.Context);
    }

    return 0;
}

UCHAR
NTAPI
IdeSendFlushCommand(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    UCHAR Command;

    Command = HwDeviceExtension->DeviceParameters[Srb->TargetId].IdePioFlushCommand;

    if (Command == 0xFF)
        return 1;

    DPRINT("IdeSendFlushCommand: device %X, srb %X\n", Srb->TargetId, Srb);

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Srb->TargetId & 0x1) << 4) | IDE_DRIVE_SELECT));

    HwDeviceExtension->TransferDataBuffer = (PUCHAR)Srb->DataBuffer;
    HwDeviceExtension->TransferDataBytes = Srb->DataTransferLength;
    HwDeviceExtension->ExpectingInterrupt = 1;

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Features, 0);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.SectorCount, 0);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaLow, 0);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaMid, 0);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaHigh, 0);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, Command);

    return 0;
}

UCHAR
NTAPI
IdeSendFlushCommandExt(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    UCHAR Command;

    Command = HwDeviceExtension->DeviceParameters[Srb->TargetId].IdePioFlushCommandExt;
    if (Command == 0xFF)
        return 1;

    DPRINT("IdeSendFlushCommandExt: device %X, srb %X\n", Srb->TargetId, Srb);

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Srb->TargetId & 0x1) << 4) | IDE_DRIVE_SELECT));

    HwDeviceExtension->TransferDataBuffer = (PUCHAR)Srb->DataBuffer;
    HwDeviceExtension->TransferDataBytes = Srb->DataTransferLength;

    HwDeviceExtension->ExpectingInterrupt = 1;

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Features, 0);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.SectorCount, 0);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaLow, 0);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaMid, 0);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaHigh, 0);

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Features, 0);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.SectorCount, 0);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaLow, 0);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaMid, 0);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaHigh, 0);

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, Command);

    return 0;
}

UCHAR
NTAPI
IdeSendCommand(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    PIDENTIFY_DATA Identify;
    INQUIRYDATA Inquiry;
    PCDB Cdb;
    ULONG Device;
    ULONG Length;
    ULONG ix;
    ULONG jx;
    UCHAR SrbStatus;
    UCHAR IdeStatus;
    UCHAR Command;
    UCHAR Error;

    Cdb = (PCDB)Srb->Cdb;
    Command = Cdb->CDB6GENERIC.OperationCode;
    Device = Srb->TargetId;

    DPRINT("IdeSendCommand: Command %X to device %X\n", Command, Device);

    if (Command == 0x28 || Command == 0x2A)
    {
        if (HwDeviceExtension->DeviceFlags[Device] & 0x200000)
            SrbStatus = IdeReadWriteExt(HwDeviceExtension, Srb);
        else
            SrbStatus = IdeReadWrite(HwDeviceExtension, Srb);

        return SrbStatus;
    }
    else if (Command == 0)
    {
        if (!(HwDeviceExtension->DeviceFlags[Device] & 0x20))
            return 1;

        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT));
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, 0xDA);

        for (ix = 0; ix < 10; ix++)
        {
            for (jx = 0; jx < 25000; jx++)
            {
                IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
                if (!(IdeStatus & 0x80))
                    break;

                KeStallExecutionProcessor(40);
            }

            if (!(IdeStatus & 0x80))
                break;

            DPRINT("AtapiSetTransferMode: after 1 sec wait, device is still busy with %X IdeStatus %X\n",
                   HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
        }

        if (IdeStatus & 0x80)
        {
            DPRINT("AtapiSetTransferMode: WaitOnBusy failed. %X IdeStatus %X\n",
                   HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
        }

        if (IdeStatus & 1)
        {
            Error = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Error);
            if (Error != 0x40)
            {
                HwDeviceExtension->CmdErrorCopy = Error;
                Srb->ScsiStatus = 2;
                Srb->SrbStatus = 4;
                return 4;
            }

            READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
        }
        else
        {
            HwDeviceExtension->ExpectingInterrupt = 0;
        }

        return 1;
    }
    else if (Command == 0x12)
    {
        if (Srb->Lun != 0)
        {
            DPRINT("IdeSendCommand: SRB_STATUS_SELECTION_TIMEOUT. Srb->Lun %X\n", Srb->Lun);
            return SRB_STATUS_SELECTION_TIMEOUT;
        }

        if (!(HwDeviceExtension->DeviceFlags[Device] & 1))
        {
            DPRINT("IdeSendCommand: SRB_STATUS_SELECTION_TIMEOUT. DeviceFlags %X\n", HwDeviceExtension->DeviceFlags[Device]);
            return SRB_STATUS_SELECTION_TIMEOUT;
        }

        Identify = &HwDeviceExtension->IdentifyData[Device];

        RtlZeroMemory(Srb->DataBuffer, Srb->DataTransferLength);
        RtlZeroMemory(&Inquiry, sizeof(Inquiry));

        Inquiry.DeviceTypeQualifier &= 0xE0;

        if (HwDeviceExtension->DeviceFlags[Device] & 0x10)
            Inquiry.RemovableMedia |= 0x80;

        for (ix = 0; ix < 8; ix += 2)
        {
            Inquiry.VendorId[ix] = Identify->ModelNumber[ix + 1];
            Inquiry.VendorId[ix + 1] = Identify->ModelNumber[ix];
        }

        for (ix = 0; ix < 12; ix += 2)
        {
            Inquiry.ProductId[ix] = Identify->ModelNumber[ix + 9];
            Inquiry.ProductId[ix + 1] = Identify->ModelNumber[ix + 8];
        }

        *(ULONG *)&Inquiry.ProductId[12] = '    ';

        for (ix = 0; ix < 4; ix += 2)
        {
            Inquiry.ProductRevisionLevel[ix] = Identify->FirmwareRevision[ix + 1];
            Inquiry.ProductRevisionLevel[ix + 1] = Identify->FirmwareRevision[ix];
        }

        if (Srb->DataTransferLength > sizeof(Inquiry))
            Length = sizeof(Inquiry);
        else
            Length = Srb->DataTransferLength;

        RtlMoveMemory(Srb->DataBuffer, &Inquiry, Length);

        return 1;
    }
    else if (Command == 0x35)
    {
        DPRINT("IdeSendCommand: Flush the cache for IDE device %X\n", Device);

        if (HwDeviceExtension->DeviceFlags[Device] & 0x200000)
        {
            if (HwDeviceExtension->DeviceParameters[Device].IdePioFlushCommandExt == 0xFF)
                return 1;

            SrbStatus = IdeSendFlushCommandExt(HwDeviceExtension, Srb);
        }
        else
        {
            if (HwDeviceExtension->DeviceParameters[Device].IdePioFlushCommand == 0xFF)
                return 1;

            SrbStatus = IdeSendFlushCommand(HwDeviceExtension, Srb);
        }

        return SrbStatus;
    }
    else
    {
        DPRINT1("IdeSendCommand: FIXME Command %X\n", Command);
        UNIMPLEMENTED_DBGBREAK();

        DPRINT("IdeSendCommand: Unsupported command %X\n", Command);
        return 6;
    }
   
}

VOID
NTAPI
Scsi2Atapi(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    PCDB Cdb = (PCDB)&Srb->Cdb;

    DPRINT("Scsi2Atapi: Operation %X (%X:%X)\n", Cdb->CDB10.OperationCode, Srb->TargetId, Srb->Lun);

    RtlCopyMemory(HwDeviceExtension->ScsiCdb, Srb->Cdb, sizeof(HwDeviceExtension->ScsiCdb));

    HwDeviceExtension->IsCdbSaved = FALSE;

    if (HwDeviceExtension->DeviceFlags[Srb->TargetId] & 4)
        return;

    if (Cdb->CDB6GENERIC.OperationCode == 4)//SCSIOP_FORMAT_UNIT
    {
        if (HwDeviceExtension->DeviceFlags[Srb->TargetId] & 0x8000)
        {
            Cdb->CDB6GENERIC.OperationCode = 0x24;
            HwDeviceExtension->IsCdbSaved = TRUE;
        }
    }
    else if (Cdb->CDB6GENERIC.OperationCode == 0x15)
    {
        DPRINT1("Scsi2Atapi: Error!\n");
        ASSERT(FALSE);
    }
    else if (Cdb->CDB6GENERIC.OperationCode == 0x1A)
    {
        DPRINT1("Scsi2Atapi: Error!\n");
        ASSERT(FALSE);
    }
    else if (Cdb->CDB6GENERIC.OperationCode == 0x1B)//SCSIOP_START_STOP_UNIT
    {
        if (Cdb->START_STOP.Immediate)
        {
            if (!Cdb->START_STOP.LoadEject && !Cdb->START_STOP.Start)
                Cdb->START_STOP.Immediate = 0;
        }

        HwDeviceExtension->IsCdbSaved = TRUE;
    }
}

UCHAR
NTAPI
AtapiSendCommand(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    VOID (NTAPI* BmArm)(PVOID);
    PCDB Cdb;
    ULONG ix;
    ULONG jx;
    UCHAR IdeStatus;

    ASSERT(!(HwDeviceExtension->DeviceFlags[Srb->TargetId] & 0x200000));//DFLAGS_48BIT_LBA

    Cdb = (PCDB)Srb->Cdb;

    DPRINT("AtapiSendCommand: Command %X to TargetId %X lun %X\n", Cdb->CDB10.OperationCode, Srb->TargetId, Srb->Lun);

    if (Srb->SrbFlags & 0xC0)
    {
        DPRINT("AtapiSendCommand: XferLength %X, LBA %X\n", Srb->DataTransferLength,
               (Cdb->CDB10.LogicalBlockByte0 | (Cdb->CDB10.LogicalBlockByte1 << 8) |
                (Cdb->CDB10.LogicalBlockByte2 << 16) | (Cdb->CDB10.LogicalBlockByte3 << 24)));
    }

    if (Srb->Lun > HwDeviceExtension->MultiLun[Srb->TargetId])
        return 0xA;

    if (!(HwDeviceExtension->DeviceFlags[Srb->TargetId] & 2))
        return 0xA;

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Srb->TargetId & 0x1) << 4) | IDE_DRIVE_SELECT));

    IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);

    DPRINT("AtapiSendCommand: Entered with IdeStatus %X\n", IdeStatus);

    if (IdeStatus & 0x80)
    {
        DPRINT("AtapiSendCommand: Device busy (%X)\n", IdeStatus);
        return 5;
    }

    if (!(IdeStatus & 0x10) &&
        HwDeviceExtension->IsDscRestrictive &&
        (HwDeviceExtension->DeviceFlags[Srb->TargetId] & 0x80000))
    {
        KeStallExecutionProcessor(1000);
        DPRINT("AtapiSendCommand: DSC not set (%X)\n", IdeStatus);
        return 5;
    }

    if ((ULONG_PTR)Srb->SrbExtension & 4)
    {
        DPRINT("AtapiSendCommand: %X mapped as DSC restrictive\n", Cdb->CDB10.OperationCode);

        HwDeviceExtension->IsDscRestrictive = TRUE;
        HwDeviceExtension->DeviceFlags[Srb->TargetId] |= 0x80000;
    }
    else
    {
        HwDeviceExtension->IsDscRestrictive = FALSE;
        HwDeviceExtension->DeviceFlags[Srb->TargetId] &= ~0x00080000;
    }

    Scsi2Atapi(HwDeviceExtension, Srb);

    HwDeviceExtension->TransferDataBuffer = Srb->DataBuffer;
    HwDeviceExtension->TransferDataBytes = Srb->DataTransferLength;

    for (ix = 0; ix < 10; ix++)
    {
        for (jx = 0; jx < 25000; jx++)
        {
            IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
            if (!(IdeStatus & 0x80))
                break;

            KeStallExecutionProcessor(40);
        }

        if (!(IdeStatus & 0x80))
            break;

        DPRINT("AtapiSendCommand: after 1 sec wait, device is still busy with %X IdeStatus %X\n",
               HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
    }

    if (IdeStatus & 0x80)
    {
        DPRINT("AtapiSendCommand: WaitOnBusy failed. %X IdeStatus %X\n",
               HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
    }

    if (Srb->DataTransferLength >= 0x10000)
    {
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.BytesLow, 0xFF);
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.BytesHigh, 0xFF);
    }
    else
    {
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.BytesLow, (Srb->DataTransferLength & 0xFF));
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.BytesHigh, ((Srb->DataTransferLength >> 8) & 0xFF));
    }

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Features, (((ULONG_PTR)Srb->SrbExtension & 2) ? 1 : 0));

    if (HwDeviceExtension->DeviceFlags[Srb->TargetId] & 8)
    {
        DPRINT("AtapiSendCommand: Wait for int. to send packet. IdeStatus %X\n", IdeStatus);

        HwDeviceExtension->ExpectingInterrupt = 1;
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, 0xA0);
        return SRB_STATUS_PENDING;
    }

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, 0xA0);

    for (ix = 0; ix < 20; ix++)
    {
        IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
        if (!(IdeStatus & 0x80))
            break;

        KeStallExecutionProcessor(5);
    }

    for (ix = 0; ix < 10; ix++)
    {
        for (jx = 0; jx < 25000; jx++)
        {
            IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
            if (!(IdeStatus & 0x80))
                break;

            KeStallExecutionProcessor(40);
        }

        if (!(IdeStatus & 0x80))
            break;

        DPRINT("AtapiSendCommand: after 1 sec wait, device is still busy with %X IdeStatus %X\n",
               HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
    }

    if (IdeStatus & 0x80)
    {
        DPRINT("AtapiSendCommand: WaitOnBusy failed. %X IdeStatus %X\n",
               HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
    }

    for (jx = 0; jx < 1000; jx++)
    {
        IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
        if (IdeStatus & 0x80)
        {
            KeStallExecutionProcessor(100);
            continue;
        }

        if (IdeStatus & 8)
            break;

        KeStallExecutionProcessor(200);
    }

    if (!(IdeStatus & 8))
    {
        DPRINT("AtapiSendCommand: DRQ never asserted (%X)\n", IdeStatus);
        return 4;
    }

    READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);

    HwDeviceExtension->ExpectingInterrupt = 1;

    for (ix = 0; ix < 10; ix++)
    {
        for (jx = 0; jx < 25000; jx++)
        {
            IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
            if (!(IdeStatus & 0x80))
                break;

            KeStallExecutionProcessor(40);
        }

        if (!(IdeStatus & 0x80))
            break;

        DPRINT("AtapiSendCommand: after 1 sec wait, device is still busy with %X IdeStatus %X\n",
               HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
    }

    if (IdeStatus & 0x80)
    {
        DPRINT("AtapiSendCommand: WaitOnBusy failed. %X IdeStatus %X\n",
               HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
    }

    WRITE_PORT_BUFFER_USHORT(HwDeviceExtension->CmdBlock.Data, (PUSHORT)&Srb->Cdb, 6);

    if ((ULONG_PTR)Srb->SrbExtension & 2)
    {
        HwDeviceExtension->IsActiveDmaTransfer = TRUE;

        BmArm = HwDeviceExtension->BusMasterInterface.BmArm;
        BmArm(HwDeviceExtension->BusMasterInterface.Context);
    }

    DPRINT("AtapiSendCommand: ret SRB_STATUS_PENDING (%p) \n", Srb);
    return SRB_STATUS_PENDING;
}

ULONG
NTAPI
IdeSendSmartCommand(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    PSENDCMDOUTPARAMS OutParameters;
    SENDCMDINPARAMS inParameters;
    ULONG TransferDataBytes;
    ULONG ix;
    ULONG jx;
    UCHAR IdeStatus;
    UCHAR Features;
    UCHAR Device;

    inParameters = *(SENDCMDINPARAMS *)Add2Ptr(Srb->DataBuffer, sizeof(SRB_IO_CONTROL));

    DPRINT("IdeSendSmartCommand: %p, %X, %X, %X\n",
           HwDeviceExtension, Srb, inParameters.irDriveRegs.bCommandReg, inParameters.irDriveRegs.bFeaturesReg);

    if (inParameters.irDriveRegs.bCommandReg != 0xB0)
        return 6;

    Device = inParameters.bDriveNumber;

    if (!(HwDeviceExtension->DeviceFlags[Device] & 1))
    {
        return 0xA;
    }

    if (HwDeviceExtension->DeviceFlags[Device] & 2)
    {
        return 0xA;
    }

    HwDeviceExtension->TypeSmartCommand = Features = inParameters.irDriveRegs.bFeaturesReg;
    Srb->TargetId = Device;

    OutParameters = Add2Ptr(Srb->DataBuffer, sizeof(SRB_IO_CONTROL));

    if (Features == 0xD0 || Features == 0xD1 || Features == 0xD5)
    {
        for (ix = 0; ix < 10; ix++)
        {
            for (jx = 0; jx < 25000; jx++)
            {
                IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
                if (!(IdeStatus & 0x80))
                    break;

                KeStallExecutionProcessor(40);
            }

            if (!(IdeStatus & 0x80))
                break;

            DPRINT("AtapiSetTransferMode: after 1 sec wait, device is still busy with %X IdeStatus %X\n",
                   HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
        }

        if (IdeStatus & 0x80)
        {
            DPRINT("AtapiSetTransferMode: WaitOnBusy failed. %X IdeStatus %X\n",
                   HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
        }

        if (IdeStatus & 0x80)
        {
            DPRINT1("IdeSendSmartCommand: Returning BUSY status\n");
            return 5;
        }

        if (inParameters.irDriveRegs.bFeaturesReg == 0xD5)
            TransferDataBytes = (inParameters.irDriveRegs.bSectorCountReg * 0x200);
        else
            TransferDataBytes = 0x200;

        if (TransferDataBytes != 0xFFFFFFF0)
            RtlZeroMemory(OutParameters, ((sizeof(*OutParameters) - 1) + TransferDataBytes));

        HwDeviceExtension->TransferDataBuffer = (PUCHAR)OutParameters->bBuffer;
        HwDeviceExtension->TransferDataBytes = TransferDataBytes;

        HwDeviceExtension->ExpectingInterrupt = 1;

        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT));

        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Features, inParameters.irDriveRegs.bFeaturesReg);
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.SectorCount, inParameters.irDriveRegs.bSectorCountReg);
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaLow, inParameters.irDriveRegs.bSectorNumberReg);
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.BytesLow, inParameters.irDriveRegs.bCylLowReg);
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.BytesHigh, inParameters.irDriveRegs.bCylHighReg);
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, 0xB0);

        return 0;
    }

    if (Features == 0xD8 || Features == 0xD9 || Features == 0xDA || Features == 0xD2 ||
        Features == 0xD4 || Features == 0xD3 || Features == 0xDB)
    {
        if (Features == 0xD4)
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        for (ix = 0; ix < 10; ix++)
        {
            for (jx = 0; jx < 25000; jx++)
            {
                IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
                if (!(IdeStatus & 0x80))
                    break;

                KeStallExecutionProcessor(40);
            }

            if (!(IdeStatus & 0x80))
                break;

            DPRINT("AtapiSetTransferMode: after 1 sec wait, device is still busy with %X IdeStatus %X\n",
                   HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
        }

        if (IdeStatus & 0x80)
        {
            DPRINT("AtapiSetTransferMode: WaitOnBusy failed. %X IdeStatus %X\n",
                   HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
        }

        if (IdeStatus & 0x80)
        {
            DPRINT1("IdeSendSmartCommand: Returning BUSY status\n");
            return 5;
        }

        RtlZeroMemory(OutParameters, sizeof(*OutParameters));

        HwDeviceExtension->TransferDataBytes = 0;
        HwDeviceExtension->TransferDataBuffer = (PUCHAR)OutParameters->bBuffer;

        HwDeviceExtension->ExpectingInterrupt = 1;

        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT));

        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Features, inParameters.irDriveRegs.bFeaturesReg);
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.SectorCount, inParameters.irDriveRegs.bSectorCountReg);
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaLow, inParameters.irDriveRegs.bSectorNumberReg);
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaMid, inParameters.irDriveRegs.bCylLowReg);
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaHigh, inParameters.irDriveRegs.bCylHighReg);
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, 0xB0);

        return 0;
    }

    if (Features != 0xD6)
    {
        DPRINT1("IdeSendSmartCommand: SRB_STATUS_INVALID_REQUEST (%p, %X, %X, %X)\n",
               HwDeviceExtension, Srb, inParameters.irDriveRegs.bCommandReg, inParameters.irDriveRegs.bFeaturesReg);

        return SRB_STATUS_INVALID_REQUEST;
    }

    UNIMPLEMENTED_DBGBREAK();

    return 0;
}

BOOLEAN
NTAPI
AtapiStartIo(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    PSRB_IO_CONTROL SrbIoControl;
    ULONG ControlCode;
    ULONG Device;
    UCHAR SrbStatus;
    union _PARAMS
    {
        PSENDCMDINPARAMS CmdIn;
        PSENDCMDOUTPARAMS CmdOut;
    } Buffer;

    DPRINT("AtapiStartIo: %p, %p\n", HwDeviceExtension, Srb);

    // FIXME IdeDebugSimulateHardHang

    if (Srb->Function == 0 ||    // SRB_FUNCTION_EXECUTE_SCSI
        Srb->Function == 7 ||    // SRB_FUNCTION_SHUTDOWN
        Srb->Function == 8 ||    // SRB_FUNCTION_FLUSH
        Srb->Function == 0xC7 ||
        Srb->Function == 0xC8 ||
        Srb->Function == 0xC9)
    {
        if (HwDeviceExtension->CurrentSrb)
        {
            DPRINT("AtapiStartIo: Already have a request!\n");
            Srb->SrbStatus = 5;
            IdePortNotification(0, HwDeviceExtension, Srb);
            return FALSE;
        }

        HwDeviceExtension->CurrentSrb = Srb;

        if (Srb->Function == 0xC9)
        {
            UNIMPLEMENTED_DBGBREAK();SrbStatus=4;
            DPRINT("AtapiStartIo: Srb %p complete with status %X\n", Srb, SrbStatus);
        }
        else if (Srb->Function == 0xC8 || Srb->Function == 0xC7)
        {
            SrbStatus = IdeSendPassThroughCommand(HwDeviceExtension, Srb);
            DPRINT("AtapiStartIo: Srb %p complete with status %X\n", Srb, SrbStatus);
        }
        else if ((HwDeviceExtension->DeviceFlags[Srb->TargetId] & 3) == 3)
        {
            SrbStatus = AtapiSendCommand(HwDeviceExtension, Srb);
            DPRINT("AtapiStartIo: Srb %p complete with status %X\n", Srb, SrbStatus);
        }
        else if (Srb->Function == 8 || Srb->Function == 7)
        {
            UNIMPLEMENTED_DBGBREAK();SrbStatus=4;
            DPRINT("AtapiStartIo: Srb %p complete with status %X\n", Srb, SrbStatus);
        }
        // Srb->Function == 0
        else if (!(HwDeviceExtension->DeviceFlags[Srb->TargetId] & 1))
        {
            SrbStatus = 0xA;
            DPRINT("AtapiStartIo: Srb %p complete with status %X\n", Srb, SrbStatus);
        }
        else
        {
            SrbStatus = IdeSendCommand(HwDeviceExtension, Srb);
            DPRINT("AtapiStartIo: Srb %p complete with status %X\n", Srb, SrbStatus);
        }
    }
    else if (Srb->Function == 2) // SRB_FUNCTION_IO_CONTROL
    {
        if (HwDeviceExtension->CurrentSrb)
        {
            DPRINT("AtapiStartIo: Already have a request!\n");
            Srb->SrbStatus = 5;
            IdePortNotification(0, HwDeviceExtension, Srb);
            return FALSE;
        }

        HwDeviceExtension->CurrentSrb = Srb;

        SrbIoControl = (PSRB_IO_CONTROL)Srb->DataBuffer;

        if (RtlCompareMemory(SrbIoControl->Signature, "SCSIDISK", 8) != 8)
        {
            DPRINT("AtapiStartIo: IoControl signature incorrect. Send '%s', expected '%s'\n", SrbIoControl->Signature, "SCSIDISK");
            SrbStatus = 6;
        }
        else
        {
            ControlCode = SrbIoControl->ControlCode;

            if (ControlCode == 0x1B0500)
            {
                UNIMPLEMENTED_DBGBREAK();
            }
            else if (ControlCode == 0x1B0501)
            {
                Buffer.CmdIn = Add2Ptr(SrbIoControl, sizeof(*SrbIoControl));

                if (Buffer.CmdIn->irDriveRegs.bCommandReg == 0xEC)
                {
                    Device = Buffer.CmdIn->bDriveNumber;

                    if ((HwDeviceExtension->DeviceFlags[Device] & 1) &&
                        !(HwDeviceExtension->DeviceFlags[Device] & 2))
                    {
                        RtlZeroMemory(Buffer.CmdIn, 0x210);

                        Buffer.CmdOut->cBufferSize = 0x200;
                        Buffer.CmdOut->DriverStatus.bDriverError = 0;
                        Buffer.CmdOut->DriverStatus.bIDEError = 0;

                        RtlMoveMemory(Buffer.CmdOut->bBuffer, &HwDeviceExtension->IdentifyData[Device], 0x200);
                        SrbStatus = 1;
                    }
                    else
                    {
                        SrbStatus = 0xA;
                    }
                }
                else
                {
                    SrbStatus = 6;
                }
            }
            else if (ControlCode == 0x1B0502 || ControlCode == 0x1B0503 || ControlCode == 0x1B0504 || ControlCode == 0x1B0505 ||
                     ControlCode == 0x1B0506 || ControlCode == 0x1B0507 || ControlCode == 0x1B0508 || ControlCode == 0x1B0509 ||
                     ControlCode == 0x1B050A || ControlCode == 0x1B050B || ControlCode == 0x1B050C)
            {
                SrbStatus = IdeSendSmartCommand(HwDeviceExtension, Srb);
                if (!SrbStatus)
                    return 1;

                DPRINT("AtapiStartIo: Srb %p complete with status %X\n", Srb, SrbStatus);
            }
            else
            {
                UNIMPLEMENTED_DBGBREAK();
            }
        }

        DPRINT("AtapiStartIo: Srb %p complete with status %X\n", Srb, SrbStatus);
    }
    else if (Srb->Function == 0x10) // SRB_FUNCTION_ABORT_COMMAND
    {
        UNIMPLEMENTED_DBGBREAK();SrbStatus=4;
        DPRINT("AtapiStartIo: Srb %p complete with status %X\n", Srb, SrbStatus);
    }
    else if (Srb->Function == 0x12) // SRB_FUNCTION_RESET_BUS
    {
         UNIMPLEMENTED_DBGBREAK();SrbStatus=4;
        DPRINT("AtapiStartIo: Srb %p complete with status %X\n", Srb, SrbStatus);
    }
    else
    {
        SrbStatus = 6;
        DPRINT("AtapiStartIo: Srb %p complete with status 6\n", Srb);
    }

    if (SrbStatus == 0)//SRB_STATUS_PENDING
        return TRUE;

    HwDeviceExtension->CurrentSrb = NULL;

    Srb->SrbStatus = SrbStatus;

    IdePortNotification(0, HwDeviceExtension, Srb);
    IdePortNotification(1, HwDeviceExtension, 0);

    return TRUE;
}

VOID
NTAPI
BuildResetStateTable(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension)
{
    ULONG NumStates;

    HwDeviceExtension->States[0][0] = 0;
    HwDeviceExtension->States[0][1] = 1;

    HwDeviceExtension->States[1][0] = ((HwDeviceExtension->DeviceFlags[0] & 1) ? 0 : 1);
    HwDeviceExtension->States[1][1] = ((HwDeviceExtension->DeviceFlags[0] & 1) ? 0 : 1);

    DPRINT("BuildResetStateTable: HwDeviceExtension->States[1][0] %X\n", HwDeviceExtension->States[1][0]);

    NumStates = 2;

    if (HwDeviceExtension->DeviceFlags[0] & 1)
    {
        if (HwDeviceExtension->DeviceFlags[0] & 2)
        {
            HwDeviceExtension->States[0][2] = 2;
            HwDeviceExtension->States[0][3] = 3;
            HwDeviceExtension->States[0][4] = 4;
        }
        else
        {
            HwDeviceExtension->States[0][2] = 5;
            HwDeviceExtension->States[0][3] = 6;
            HwDeviceExtension->States[0][4] = 7;
        }

        HwDeviceExtension->States[1][2] = 0;
        HwDeviceExtension->States[1][3] = 0;
        HwDeviceExtension->States[1][4] = 0;

        NumStates += 3;
    }

    if (HwDeviceExtension->DeviceFlags[1] & 1)
    {
        if (HwDeviceExtension->DeviceFlags[1] & 2)
        {
            HwDeviceExtension->States[0][NumStates + 0] = 2;
            HwDeviceExtension->States[0][NumStates + 1] = 3;
            HwDeviceExtension->States[0][NumStates + 2] = 4;
        }
        else
        {
            HwDeviceExtension->States[0][NumStates + 0] = 5;
            HwDeviceExtension->States[0][NumStates + 1] = 6;
            HwDeviceExtension->States[0][NumStates + 2] = 7;

        }

        HwDeviceExtension->States[1][NumStates + 0] = 1;
        HwDeviceExtension->States[1][NumStates + 1] = 1;
        HwDeviceExtension->States[1][NumStates + 2] = 1;

        NumStates += 3;
    }

    HwDeviceExtension->States[0][NumStates] = 8;
    HwDeviceExtension->States[1][NumStates] = ((HwDeviceExtension->DeviceFlags[0] & 1) ? 0 : 1);

    ASSERT(NumStates <= 0x10); // RESET_STATE_TABLE_LEN - 1
}

BOOLEAN
NTAPI 
TestForEnumProbing(
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    PATA_PASS_THROUGH AtaPassThr;

    if (!Srb)
        return FALSE;

    if (Srb->Function != 0xC7 && Srb->Function != 0xC8)
        return FALSE;

    AtaPassThr = Srb->DataBuffer;

    DPRINT("TestForEnumProbing: %p (%X), %X\n", Srb, Srb->DataBuffer, AtaPassThr->IdeReg.bReserved);

    return ((AtaPassThr->IdeReg.bReserved & 0x10) == 0x10);
}

VOID
NTAPI
IdeCompleteRequest(
   _In_ PFDO_DEVICE_EXTENSION FdoExtension,
   _In_ PPDOX_SRB_DATA SrbData,
   _In_ UCHAR SrbStatus)
{
    PSCSI_REQUEST_BLOCK Srb;

    ASSERT(SrbData->CurrentSrb);

    Srb = SrbData->CurrentSrb;
    DPRINT("IdeCompleteRequest: Srb %X\n", Srb);

    if (!Srb)
        return;

    if (!(Srb->SrbFlags & 0x10000))
        return;

    Srb->SrbStatus = SrbStatus;

    if (!((ULONG_PTR)Srb->SrbExtension & 2))
      Srb->DataTransferLength = 0;

    IdePortNotification(0, &FdoExtension->AtaExt, Srb);
}

VOID
NTAPI
IdePortCompleteRequest(
   _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
   _In_ PSCSI_REQUEST_BLOCK Srb,
   _In_ UCHAR SrbStatus)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    PIRP Irp;

    Irp = Srb->OriginalRequest;
    PdoExtension = IoGetCurrentIrpStackLocation(Irp)->Parameters.Others.Argument4;

    DPRINT("IdePortCompleteRequest: Complete requests for targetid %X\n", PdoExtension->TargetId);

    if (PdoExtension->AbortSrb)
    {
        PdoExtension->AbortSrb->SrbStatus = SrbStatus;
        IdePortNotification(0, HwDeviceExtension, PdoExtension->AbortSrb);
    }
 
    FdoExtension = CONTAINING_RECORD(HwDeviceExtension, FDO_DEVICE_EXTENSION, AtaExt);

    IdeCompleteRequest(FdoExtension, &PdoExtension->PdoxSrbData, SrbStatus);
}

NTSTATUS
NTAPI
IdePortpWaitOnBusyEx(
   _In_ PIDE_CMD_BLOCK_REGS CmdBlock,
   _Out_ UCHAR* OutIdeStatus,
   _In_ UCHAR InStatus)
{
    UCHAR IdeStatus;
    ULONG ix;
    ULONG jx;

    for (ix = 0; ix < 2; )
    {
        jx = 0;

        while (TRUE)
        {
            IdeStatus = READ_PORT_UCHAR(CmdBlock->Status);

            if (IdeStatus == InStatus || !(IdeStatus & 0x80))
            {
                ix = 2;
                break;
            }

            KeStallExecutionProcessor(5);

            jx++;
            if (jx < 200000)
                continue;

            if (!(IdeStatus & 0x80))
            {
                ix = 2;
                break;
            }

            DPRINT("ATAPI: after 1 sec wait, device is still busy with %X, status %X\n", CmdBlock->CmdBlockBase, IdeStatus);

            ix++;
            break;
        }
    }

    *OutIdeStatus = IdeStatus;

    if (!(IdeStatus & 0x80) || IdeStatus == InStatus)
        return STATUS_SUCCESS;

    DPRINT("WaitOnBusy failed. (%X) status %X\n", CmdBlock->CmdBlockBase, IdeStatus);

    return STATUS_UNSUCCESSFUL;
}

BOOLEAN
NTAPI
IdePortChannelEmpty(
   _In_ PIDE_CMD_BLOCK_REGS CmdBlock,
   _In_ PIDE_CTRL_BLOCK_REGS CtrlBlock,
   _In_ ULONG MaxIdeDevice)
{
    ULONG ix;
    UCHAR IdeStatus;
    BOOLEAN IsDoIdentifyDevice = FALSE;

    DPRINT("IdePortChannelEmpty: %X\n", CmdBlock->CmdBlockBase);

    if (!MaxIdeDevice)
        return TRUE;

    for (ix = 0; ix < MaxIdeDevice; ix++)
    {
        WRITE_PORT_UCHAR(CmdBlock->DeviceSelect, (((ix & 0x1) << 4) | IDE_DRIVE_SELECT));
        IdeStatus = READ_PORT_UCHAR(CmdBlock->Status);

        if (IdeStatus == 0xFF || IdeStatus == 0xFE)
            continue;

        IdePortpWaitOnBusyEx(CmdBlock, &IdeStatus, 0xFF);

        if ((IdeStatus & 0x80) && IdeStatus != 0xFE)
        {
            if (IdeStatus == 0xFF)
                continue;

            DPRINT("IdePortChannelEmpty: Channel looks busy %X. Try a reset\n", IdeStatus);

            WRITE_PORT_UCHAR(CtrlBlock->DeviceControl, 4);
            KeStallExecutionProcessor(10);
            WRITE_PORT_UCHAR(CtrlBlock->DeviceControl, 0);

            WRITE_PORT_UCHAR(CmdBlock->DeviceSelect, (((ix & 0x1) << 4) | IDE_DRIVE_SELECT));
            IdePortpWaitOnBusyEx(CmdBlock, &IdeStatus, 0xFF);
        }

        if (IdeStatus != 0xFF)
            IsDoIdentifyDevice = TRUE;
    }

    if (IsDoIdentifyDevice)
        return IdePortIdentifyDevice(CmdBlock, CtrlBlock, MaxIdeDevice);

    return TRUE;
}

BOOLEAN
NTAPI
AtapiResetController(
   _In_ PATA_DEVICE_EXTENSION HwDeviceExtension, 
   _In_ PULONG CallAgain)
{
    PIDE_CTRL_BLOCK_REGS CtrlBlock;
    PIDE_CMD_BLOCK_REGS CmdBlock;
    PATA_PASS_THROUGH AtaPassThr;
    ULONG State;
    ULONG PrevIdx;
    ULONG ix;
    ULONG jx;
    UCHAR IdeStatus;
    UCHAR Function;
    BOOLEAN ProbeResult;

    DPRINT("AtapiResetController: %X\n", *CallAgain);

    CmdBlock = &HwDeviceExtension->CmdBlock;
    CtrlBlock = &HwDeviceExtension->CtrlBlock;

    while (TRUE)
    {
        ProbeResult = FALSE;

        if (!*CallAgain)
            BuildResetStateTable(HwDeviceExtension);

        DPRINT("AtapiResetController: CallAgain %X, Device %X, BusyCount %X\n", *CallAgain, HwDeviceExtension->States[1][*CallAgain], HwDeviceExtension->BusyCount);

        PrevIdx = *CallAgain;

        State = HwDeviceExtension->States[0][*CallAgain];

        if (State == 0)
        {
            DPRINT("AtapiResetController: Reset %X IDE... (%X)\n", CmdBlock->CmdBlockBase, HwDeviceExtension->CurrentSrb);

            if (HwDeviceExtension->CurrentSrb)
            {
                ProbeResult = TestForEnumProbing(HwDeviceExtension->CurrentSrb);
                Function = HwDeviceExtension->CurrentSrb->Function;

                if (Function == 0xC7 || Function == 0xC8)
                {
                    AtaPassThr = HwDeviceExtension->CurrentSrb->DataBuffer;
                    AtapiTaskRegisterSnapshot(CmdBlock, &AtaPassThr->IdeReg);
                }
                else if (Function == 0xC9)
                {
                    UNIMPLEMENTED_DBGBREAK();
                }

                IdePortCompleteRequest(HwDeviceExtension, HwDeviceExtension->CurrentSrb, 0xE);

                HwDeviceExtension->CurrentSrb = 0;
                HwDeviceExtension->TransferDataBytes = 0;
                HwDeviceExtension->TransferDataBuffer = 0;

                IdePortNotification(1, HwDeviceExtension, 0);
            }

            if (HwDeviceExtension->IsActiveDmaTransfer)
            {
                UNIMPLEMENTED_DBGBREAK();
            }

            HwDeviceExtension->ExpectingInterrupt = 0;
            HwDeviceExtension->IsDscRestrictive = FALSE;

            if (ProbeResult)
            {
                DPRINT("AtapiResetController: [%X] ret TRUE\n");
                *CallAgain = 0;
                return TRUE;
            }

            IdeHardReset(CmdBlock, CtrlBlock, 1, FALSE);

            HwDeviceExtension->BusyCount = 0;

            (*CallAgain)++;

            HwDeviceExtension->BusyCount = 0;

            WRITE_PORT_UCHAR(CmdBlock->DeviceSelect, (((HwDeviceExtension->States[1][*CallAgain] & 0x1) << 4) | IDE_DRIVE_SELECT));
            READ_PORT_UCHAR(CmdBlock->Status);

            for (jx = 0; jx < 2000; jx++)
            {
                IdeStatus = READ_PORT_UCHAR(CmdBlock->Status);
                if (!(IdeStatus & 0x80))
                    break;
                KeStallExecutionProcessor(100);
            }

            if (jx == 2000)
                DPRINT("AtapiResetController: WaitOnBusyUntil failed. IdeStatus %X\n", IdeStatus);

            if (IdeStatus & 0x80)
            {
                DPRINT("AtapiResetController: ret TRUE\n");
                return TRUE;
            }

            continue;
        }
        else if (State == 1)
        {
            WRITE_PORT_UCHAR(CmdBlock->DeviceSelect, (((HwDeviceExtension->States[1][PrevIdx] & 0x1) << 4) | IDE_DRIVE_SELECT));
            goto State6;
        }
        else if (State == 2)
        {
            UNIMPLEMENTED_DBGBREAK();
            return FALSE;
        }
        else if (State == 3)
        {
            UNIMPLEMENTED_DBGBREAK();
            return FALSE;
        }
        else if (State == 4)
        {
            UNIMPLEMENTED_DBGBREAK();
            return FALSE;
        }
        else if (State == 5)
        {
            UNIMPLEMENTED_DBGBREAK();
            return FALSE;
        }
        else if (State == 6)
        {
State6:
            IdeStatus = READ_PORT_UCHAR(CmdBlock->Status);
            if (!(IdeStatus & 0x80))
            {
                (*CallAgain)++;
                continue;
            }

            HwDeviceExtension->BusyCount++;

            if (HwDeviceExtension->BusyCount > 30 || IdeStatus == 0xFF)
            {
                DPRINT("ATAPI ResetController: ATA soft reset fails\n");
                UNIMPLEMENTED_DBGBREAK();
                (*CallAgain)++;
                continue;
            }

            DPRINT("AtapiResetController: ResetController not ready (%X) ...wait for 1 sec\n", IdeStatus);
            DPRINT("AtapiResetController: ret TRUE\n");
            return TRUE;
        }
        else if (State == 7)
        {
            UNIMPLEMENTED_DBGBREAK();
            return FALSE;
        }
        else if (State == 8)
        {
            for (ix = 0; ix < (HwDeviceExtension->MaxIdeDevice / 2); ix++)
            {
                if (!(HwDeviceExtension->DeviceFlags[ix] & 1))
                    continue;

                WRITE_PORT_UCHAR(CmdBlock->DeviceSelect, (((ix & 0x1) << 4) | IDE_DRIVE_SELECT));

                for (jx = 0; jx < 1000; jx++)
                {
                    IdeStatus = READ_PORT_UCHAR(CmdBlock->Status);
                    if (!(IdeStatus & 0x80))
                        break;
                    KeStallExecutionProcessor(100);
                }

                if (jx == 1000)
                    DPRINT("AtapiResetController: WaitOnBusyUntil failed. IdeStatus %x\n", IdeStatus);

                if (IdeStatus & 0x80)
                {
                    HwDeviceExtension->DeviceFlags[ix] &= ~1;
                    HwDeviceExtension->DeviceFlags[ix] |= 0x400000;
                }
            }

            AtapiHwInitialize(HwDeviceExtension, 0);

            for (ix = 0; ix < (HwDeviceExtension->MaxIdeDevice / 2); ix++)
            {
                if (HwDeviceExtension->DeviceFlags[ix] & 0x400000)
                    HwDeviceExtension->DeviceFlags[ix] |= 1;
            }

            if (IdePortChannelEmpty(CmdBlock, CtrlBlock, HwDeviceExtension->MaxIdeDevice))
                IdePortNotification(0xA, HwDeviceExtension, 0);

            *CallAgain = 0;

            for (ix = 0; ix < (HwDeviceExtension->MaxIdeDevice / 2); ix++)
                WRITE_PORT_UCHAR(CtrlBlock->DeviceControl, 0);

            DPRINT("AtapiResetController: ret TRUE\n");
            return TRUE;
        }
        else
        {
            UNIMPLEMENTED_DBGBREAK();
            return FALSE;
        }

        UNIMPLEMENTED_DBGBREAK();
    }

    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

BOOLEAN
NTAPI
IdeStartIoSynchronized(
   _In_ PVOID SynchronizeContext)
{
    PDEVICE_OBJECT Fdo = SynchronizeContext;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    PIO_STACK_LOCATION IoStack;
    PSCSI_REQUEST_BLOCK Srb;
    BOOLEAN IsReset;
    BOOLEAN Result;

    IoStack = Fdo->CurrentIrp->Tail.Overlay.CurrentStackLocation;
    Srb = IoStack->Parameters.Scsi.Srb;

    FdoExtension = Fdo->DeviceExtension;
    PdoExtension = IoStack->Parameters.Others.Argument4;

    DPRINT("IdeStartIoSynchronized: %p, %p (%X)\n", FdoExtension, PdoExtension, PdoExtension->TimeOut);

    if (FdoExtension->InterruptData.Flags & 0x80)
    {
        DPRINT("IdeStartIoSynchronized: PD_RESET_HOLD set...request is held for later..\n");
        FdoExtension->InterruptData.Flags |= 0x100;
        return TRUE;
    }

    if ((Srb->Function == 0xC8 || Srb->Function == 0xC7) &&
        (((PATA_PASS_THROUGH)Srb->DataBuffer)->IdeReg.bReserved & 1))
    {
        IsReset = TRUE;
    }
    else
    {
        IsReset = FALSE;
    }

    FdoExtension->Flags |= 1;
    FdoExtension->TimeOutValue = Srb->TimeOutValue;

    if (PdoExtension->TimeOut == -1)
    {
        PdoExtension->TimeOut = Srb->TimeOutValue;
    }

    if (Srb->SrbFlags & 0x10)
    {
        if (Srb->Function == 0x10)
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        PdoExtension->PdoFlags &= ~4;
        if (Srb->SrbFlags & 4)
            FdoExtension->Flags &= ~0x1000;

        PdoExtension->TimeOut = Srb->TimeOutValue;
    }
    else
    {
        if (Srb->SrbFlags & 4)
            FdoExtension->Flags &= ~0x1000;

        PdoExtension->PdoFlags |= 2;
    }

    Srb->SrbFlags |= 0x10000;

    if (PdoExtension->PdoState & 0x40)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    if (Srb->SrbStatus == 0x30)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    if (IsReset)
    {
        UNIMPLEMENTED_DBGBREAK();
    }
    else
    {
        Result = AtapiStartIo(FdoExtension->HwDeviceExtension, Srb);
    }

    if (FdoExtension->InterruptData.Flags & 4)
        KeInsertQueueDpc(&FdoExtension->SelfDevice->Dpc, NULL, NULL);

    DPRINT("IdeStartIoSynchronized: Result %X, %p (%X)\n", Result, PdoExtension, PdoExtension->TimeOut);

    return Result;
}

BOOLEAN
NTAPI
IdeResetBusSynchronized(
    _In_ PVOID Context)
{
    PATAPI_RESET_BUS_CONTEXT ResetContext = Context;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PSCSI_REQUEST_BLOCK ResetSrb = NULL;
    PSCSI_REQUEST_BLOCK Srb;
    BOOLEAN ResetResult;

    DPRINT("IdeResetBusSynchronized: %X\n", Context);

    FdoExtension = ResetContext->FdoExtension;
    ASSERT(ResetContext->Srb == FdoExtension->ResetSrb);

    if (ResetContext->IsUpdateResetSrb)
    {
        if (FdoExtension->ResetCallAgain)
        {
            DPRINT("IdeResetBusSynchronized: WARNING: Resetting a reset\n");

            FdoExtension->ResetCallAgain = 0;

            if (FdoExtension->ResetSrb)
            {
                FdoExtension->ResetSrb->SrbStatus = 4;
                ResetSrb = FdoExtension->ResetSrb;
                FdoExtension->ResetSrb = NULL;
            }
        }

        FdoExtension->ResetSrb = ResetContext->Srb;
    }

    ResetResult = AtapiResetController(FdoExtension->HwDeviceExtension, &FdoExtension->ResetCallAgain);

    if (ResetResult && FdoExtension->ResetCallAgain)
    {
        FdoExtension->InterruptData.Flags |= 0x80;
        FdoExtension->TimeOutValue = 1;

        Srb = ResetSrb;
    }
    else
    {
        FdoExtension->InterruptData.Flags &= ~0x80;
        FdoExtension->TimeOutValue = -1;

        if (FdoExtension->ResetSrb)
        {
            Srb = FdoExtension->ResetSrb;
            FdoExtension->ResetSrb = NULL;
        }
        else
        {
            Srb = ResetSrb;
        }

        if (Srb)
            Srb->SrbStatus = (!ResetResult ? 4 : 1);

        if (ResetResult)
            IdePortNotification(3, FdoExtension->HwDeviceExtension, Srb);

        if (FdoExtension->InterruptData.Flags & 0x100)
        {
            FdoExtension->InterruptData.Flags &= ~0x100;
            IdeStartIoSynchronized(FdoExtension->SelfDevice);
        }
    }

    if (Srb)
    {
        IdePortNotification(0, FdoExtension->HwDeviceExtension, Srb);
        IdePortNotification(1, FdoExtension->HwDeviceExtension, 0);
    }

    if (FdoExtension->InterruptData.Flags & 4)
        KeInsertQueueDpc(&FdoExtension->SelfDevice->Dpc, NULL, NULL);

    return TRUE;
}

IO_ALLOCATION_ACTION
NTAPI
CallIdeStartIoSynchronized(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp,
    _In_ PVOID MapRegisterBase,
    _In_ PVOID Context)
{
    PDEVICE_OBJECT Fdo = Context;
    PFDO_DEVICE_EXTENSION FdoExtension;
    KIRQL Irql;

    FdoExtension = Fdo->DeviceExtension;

    KeAcquireSpinLock(&FdoExtension->SpinLock, &Irql);
    KeSynchronizeExecution(FdoExtension->InterruptObject, IdeStartIoSynchronized, Fdo);
    KeReleaseSpinLock(&FdoExtension->SpinLock, Irql);

    return 1;
}

VOID
NTAPI
IdePortAllocateAccessToken(
    _In_ PDEVICE_OBJECT Fdo)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    NTSTATUS (NTAPI* AllocateAccessToken)(PVOID Token, PDRIVER_CONTROL Callback, PVOID Context);

    DPRINT("IdePortAllocateAccessToken: Fdo %X\n", Fdo);

    FdoExtension = Fdo->DeviceExtension;

    if (FdoExtension->SyncAccessInterface.AllocateAccessToken)
    {
        AllocateAccessToken = FdoExtension->SyncAccessInterface.AllocateAccessToken;
        AllocateAccessToken(FdoExtension->SyncAccessInterface.Context, CallIdeStartIoSynchronized, Fdo);
    }
    else
    {
        CallIdeStartIoSynchronized(NULL, NULL, NULL, Fdo);
    }
}

VOID
NTAPI
IdePortStartIo(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    NTSTATUS (NTAPI* BmSetup)(PVOID Context, PVOID DataBuffer, ULONG Length, PMDL Mdl, UCHAR Flag, PVOID Callback, PVOID CallbackContext);
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    PIO_STACK_LOCATION IoStack;
    PSCSI_REQUEST_BLOCK Srb;
    PPDOX_SRB_DATA SrbData;
    NTSTATUS Status;

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Srb = IoStack->Parameters.Scsi.Srb;
    FdoExtension = Fdo->DeviceExtension;

    DPRINT("IdePortStartIo: Enter routine\n");

    PdoExtension = IoStack->Parameters.Others.Argument4;

    if (!(Srb->SrbFlags & 0x100000) && Srb->Function != 0xC7)
    {
        if (PdoExtension->IdleCounter)
            *PdoExtension->IdleCounter = 0;
    }

    SrbData = &PdoExtension->PdoxSrbData;
    if (!SrbData->SequenceNumber)
        SrbData->SequenceNumber = FdoExtension->SequenceNumber++;

    if (Srb->Function == 0x10)
    {
        ASSERT(PdoExtension->AbortSrb == NULL);
        PdoExtension->AbortSrb = Srb;
    }
    else
    {
        ASSERT(SrbData->CurrentSrb == NULL);
        SrbData->CurrentSrb = Srb;

        if ((FdoExtension->HwDeviceExtension->DeviceFlags[Srb->TargetId] & 0x200) &&
            !((ULONG_PTR)Srb->SrbExtension & 1))
        {
            ASSERT(!(((ULONG_PTR)Srb->SrbExtension) & ~7));
            Srb->SrbExtension = Or2Ptr(Srb->SrbExtension, 2);
        }
        else
        {
            ASSERT(!(((ULONG_PTR)Srb->SrbExtension) & ~7));
            Srb->SrbExtension = And2Ptr(Srb->SrbExtension, ~2);
        }
    }

    //IdeLogStartCommandLog(..);

    if (!(Srb->SrbFlags & 0xC0))
    {
        IdePortAllocateAccessToken(Fdo);
        return;
    }

    SrbData->Buffer = MmGetMdlVirtualAddress(Irp->MdlAddress);

    while ((ULONG_PTR)Srb->SrbExtension & 2)//SRB_USES_DMA(Srb)
    {
        if (FdoExtension->HackFlags & 2)
        {
            UNIMPLEMENTED_DBGBREAK();
            continue;
        }

        if (FdoExtension->HackFlags & 4)
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        BmSetup = FdoExtension->HwDeviceExtension->BusMasterInterface.BmSetup;

        Status = BmSetup(FdoExtension->HwDeviceExtension->BusMasterInterface.Context,
                         Srb->DataBuffer,
                         Srb->DataTransferLength,
                         Irp->MdlAddress,
                         (Srb->SrbFlags & 0x40),
                         IdePortAllocateAccessToken,
                         Fdo);

        if (NT_SUCCESS(Status))
            return;

        DPRINT1("IdePortStartIo: Status %X. Try PIO for Srb %p\n", Status, Srb);

        ASSERT(!(((ULONG_PTR)Srb->SrbExtension) & ~7));
        Srb->SrbExtension = And2Ptr(Srb->SrbExtension, ~2);
    }

    if (!Irp->MdlAddress)
    {
        IdePortAllocateAccessToken(Fdo);
        return;
    }

    SrbData->Buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, HighPagePriority);

    if (!SrbData->Buffer && FdoExtension->ReservedPages)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    if (!SrbData->Buffer)
    {
        DPRINT1("IdePortStartIo: SrbData->Buffer is NULL\n");
        Srb->SrbStatus = 0x30;
        Srb->InternalStatus = STATUS_INSUFFICIENT_RESOURCES;
        //IdePortLogNoMemoryErrorFn(..);
    }

    Srb->DataBuffer = Add2Ptr(Srb->DataBuffer, ((ULONG_PTR)SrbData->Buffer - (ULONG_PTR)MmGetMdlVirtualAddress(Irp->MdlAddress)));

    IdePortAllocateAccessToken(Fdo);

    DPRINT("IdePortStartIo: %p, %p, %p, %X\n", Irp, Srb, Srb->DataBuffer, Srb->DataTransferLength);
}

VOID
NTAPI
IdeInterlockedIncrement(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PLONG Addend,
    _In_ PVOID TagLock)
{
    DPRINT(">>>>>>>>>>>>>>>>>>>> Acquire PdoLock with tag = 0x%x\n", TagLock);
    //FIXME
    InterlockedIncrement(Addend);
}

LONG
NTAPI
IdeInterlockedDecrement(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PLONG Addend,
    _In_ PVOID TagLock)
{
    DPRINT(">>>>>>>>>>>>>>>>>>>> Release PdoLock with tag = %p\n", TagLock);
    return InterlockedDecrement(Addend);
}

PPDO_DEVICE_EXTENSION
NTAPI
RefPdoWithSpinLockHeld(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ BOOLEAN IsForceRef,
    _In_ PVOID TagLock)
{
    PPDO_DEVICE_EXTENSION PdoExtension;

    PdoExtension = Pdo->DeviceExtension;

    if ((PdoExtension->PdoState & 0x70) && !IsForceRef)
        PdoExtension = NULL;
    else
        IdeInterlockedIncrement(PdoExtension, &PdoExtension->ReferenceCount, TagLock);

    return PdoExtension;
}

PPDO_DEVICE_EXTENSION
NTAPI
RefPdo(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ BOOLEAN IsForceRef,
    _In_ PVOID TagLock)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    PPDO_DEVICE_EXTENSION pdoExtension2Return;
    KIRQL Irql;

    PdoExtension = Pdo->DeviceExtension;

    KeAcquireSpinLock(&PdoExtension->PdoLock, &Irql);

    pdoExtension2Return = RefPdoWithSpinLockHeld(Pdo, IsForceRef, TagLock);

    if (pdoExtension2Return)
    {
        ASSERT("pdoExtension2Return == pdoExtension");
    }

    KeReleaseSpinLock(&PdoExtension->PdoLock, Irql);

    return pdoExtension2Return;
}

PPDO_DEVICE_EXTENSION
NTAPI
RefLogicalUnitExtension(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ UCHAR PathId,
    _In_ UCHAR TargetId,
    _In_ UCHAR Lun,
    _In_ BOOLEAN IsForceRef,
    _In_ PVOID TagLock)
{
    PPDO_DEVICE_EXTENSION RetExtension = NULL;
    PPDO_DEVICE_EXTENSION PdoExt;
    KIRQL Irql;

    DPRINT("RefLogicalUnitExtension: %p, (%X:%X:%X)\n", FdoExtension, PathId, TargetId, Lun);

    if (TargetId >= FdoExtension->HwDeviceExtension->MaxIdeTargetId)
        return NULL;

    KeAcquireSpinLock(&FdoExtension->PdoArrayLock, &Irql);

    PdoExt = FdoExtension->PdoArray[(TargetId + Lun) % 8];
    while (PdoExt)
    {
        if (PdoExt->TargetId == TargetId && PdoExt->Lun == Lun && PdoExt->PathId == PathId)
            break;

        PdoExt = PdoExt->LinkPdoExt;
    }

    if (PdoExt)
        RetExtension = RefPdo(PdoExt->SelfDevice, IsForceRef, TagLock);

    KeReleaseSpinLock(&FdoExtension->PdoArrayLock, Irql);

    return RetExtension;
}

VOID
NTAPI
UnrefLogicalUnitExtension(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PVOID TagLock)
{
    BOOLEAN SetEvent = FALSE;
    KIRQL Irql;
  
    DPRINT("UnrefLogicalUnitExtension: %p, %p\n", FdoExtension, PdoExtension);

    ASSERT(PdoExtension);
    if (!PdoExtension)
        return;

    KeAcquireSpinLock(&PdoExtension->PdoLock, &Irql);

    ASSERT(PdoExtension->ReferenceCount > 0);

    if (!IdeInterlockedDecrement(PdoExtension, &PdoExtension->ReferenceCount, TagLock))
    {
        if (PdoExtension->PdoState & 0x40)
        {
            if (PdoExtension->PdoState & 0x20)
                SetEvent = TRUE;
        }
    }

    KeReleaseSpinLock(&PdoExtension->PdoLock, Irql);

    if (SetEvent)
        KeSetEvent(&PdoExtension->Event, IO_NO_INCREMENT, FALSE);
}

VOID
NTAPI
UnrefPdo(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PVOID TagLock)
{
    UnrefLogicalUnitExtension(PdoExtension->FdoExtension, PdoExtension, TagLock);
}

PPDO_DEVICE_EXTENSION
NTAPI
NextLogUnitExtension(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PATA_SCSI_ADDRESS ScsiAddress,
    _In_ BOOLEAN IsForceRef,
    _In_ PVOID TagLock)
{
    PPDO_DEVICE_EXTENSION Extension;

    while (TRUE)
    {
        DPRINT("NextLogUnitExtension: %p, %X, %X, %X\n", FdoExtension, ScsiAddress->PathId, ScsiAddress->TargetId, ScsiAddress->Lun);

        if (ScsiAddress->PathId >= 1)
        {
            DPRINT("NextLogUnitExtension: %p, %X, %X, %X\n", FdoExtension, ScsiAddress->PathId, ScsiAddress->TargetId, ScsiAddress->Lun);
            return NULL;
        }

        while (TRUE)
        {
            if (ScsiAddress->TargetId >= FdoExtension->HwDeviceExtension->MaxIdeTargetId)
            {
                ScsiAddress->PathId++;
                ScsiAddress->TargetId = 0;
                DPRINT("NextLogUnitExtension: %p, %X, %X, %X\n", FdoExtension, ScsiAddress->PathId, ScsiAddress->TargetId, ScsiAddress->Lun);
                break;
            }

            Extension = RefLogicalUnitExtension(FdoExtension, ScsiAddress->PathId, ScsiAddress->TargetId, ScsiAddress->Lun, IsForceRef, TagLock);
            if (Extension)
            {
                ScsiAddress->Lun++;
                DPRINT("NextLogUnitExtension: %p, %X, %X, %X\n", FdoExtension, ScsiAddress->PathId, ScsiAddress->TargetId, ScsiAddress->Lun);
                return Extension;
            }

            ScsiAddress->TargetId++;
            ScsiAddress->Lun = 0;
        }
    }
}

/* SCSI FUNCTIONS ***********************************************************/

NTSTATUS
NTAPI
IdePortFlushLogicalUnit(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ BOOLEAN IsFlushAlways)
{
    PKDEVICE_QUEUE_ENTRY Entry;
    PSCSI_REQUEST_BLOCK Srb;
    PIRP PowerRelatedIrp;
    PIRP EntryIrp;
    PIRP Irp;
    KIRQL Irql;

    DPRINT("IdePortFlushLogicalUnit: %p, %p, %X\n", FdoExtension, PdoExtension, IsFlushAlways);

    KeAcquireSpinLock(&FdoExtension->SpinLock, &Irql);

    if (!(PdoExtension->PdoFlags & 1) && !IsFlushAlways)
    {
        DPRINT("IdePortFlushLogicalUnit: Request to flush an unfrozen queue!\n");
        KeReleaseSpinLock(&FdoExtension->SpinLock, Irql);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    EntryIrp = NULL;
    PowerRelatedIrp = NULL;

    while ((Entry = KeRemoveByKeyDeviceQueueIfBusy(&PdoExtension->SelfDevice->DeviceQueue, 0)) != NULL)
    {
        Irp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.DeviceQueueEntry);
        Srb = IoGetCurrentIrpStackLocation(Irp)->Parameters.Scsi.Srb;

        if (Srb->Function == 0xC7)
        {
            ASSERT(!PowerRelatedIrp);
            PowerRelatedIrp = Irp;
        }
        else
        {
            Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
            Srb->SrbStatus = 0x16;

            Irp->Tail.Overlay.ListEntry.Flink = (PVOID)EntryIrp;
            EntryIrp = Irp;
        }
    }

    if (PdoExtension->PdoFlags & 8)
    {
        DPRINT1("IdePortFlushLogicalUnit: FIXME\n");
        UNIMPLEMENTED_DBGBREAK();
    }

    if (PdoExtension->PendingRequest)
    {
        DPRINT1("IdePortFlushLogicalUnit: FIXME\n");
        UNIMPLEMENTED_DBGBREAK();
    }

    PdoExtension->PdoFlags &= ~1;

    KeReleaseSpinLock(&FdoExtension->SpinLock, Irql);

    if (PowerRelatedIrp)
    {
        DPRINT1("IdePortFlushLogicalUnit: FIXME\n");
        UNIMPLEMENTED_DBGBREAK();
    }

    while (EntryIrp)
    {
        Irp = EntryIrp;
        EntryIrp = (PVOID)EntryIrp->Tail.Overlay.ListEntry.Flink;

        UnrefLogicalUnitExtension(FdoExtension, PdoExtension, Irp);

        IoCompleteRequest(Irp, 0);
    }

    DPRINT("IdePortFlushLogicalUnit:  ret STATUS_SUCCESS\n");
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IdePortInsertByKeyDeviceQueue(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PIRP Irp,
    _In_ ULONG SortKey,
    _In_ BOOLEAN* OutResult)
{
    PSCSI_REQUEST_BLOCK Srb;
    POWER_STATE State;
    KIRQL Irql;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("IdePortInsertByKeyDeviceQueue: %p, %p, %X\n", PdoExtension, Irp, SortKey);

    *OutResult = FALSE;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    if (PdoExtension->PdoFlags & 1)
    {
        DPRINT("IdePortInsertByKeyDeviceQueue:  Request put in frozen queue!\n");
    }

    *OutResult = KeInsertByKeyDeviceQueue(&PdoExtension->SelfDevice->DeviceQueue, &Irp->Tail.Overlay.DeviceQueueEntry, SortKey);
    if (*OutResult)
    {
        InterlockedIncrement(&PdoExtension->ItemsQueued);
        goto Exit;
    }

    Srb = IoGetCurrentIrpStackLocation(Irp)->Parameters.Scsi.Srb;

    if (PdoExtension->PdoState & 0x20)
    {
        KeLowerIrql(Irql);
        IdePortFlushLogicalUnit(PdoExtension->FdoExtension, PdoExtension, TRUE);

        Srb->SrbStatus = 0x16;
        Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;

        UnrefLogicalUnitExtension(PdoExtension->FdoExtension, PdoExtension, Irp);
        IoCompleteRequest(Irp, 0);

        *OutResult = TRUE;

        DPRINT("IdePortInsertByKeyDeviceQueue: STATUS_SUCCESS\n");
        return STATUS_SUCCESS;
    }

    if (PdoExtension->PdoState & 0x1F00)
    {
        ASSERT(PdoExtension->PendingRequest == NULL);
        PdoExtension->PendingRequest = Irp;

        *OutResult = TRUE;

        if (!(PdoExtension->PdoState & 0x1E00))
        {
            if (Srb->TimeOutValue < 0x1E) // 30
                Srb->TimeOutValue = 0x1E;

            State.DeviceState = PowerDeviceD0;

            Status = PoRequestPowerIrp(PdoExtension->SelfDevice, 2, State, NULL, NULL, NULL);
            ASSERT(NT_SUCCESS(Status));

            DPRINT("IdePortInsertByKeyDeviceQueue: %X %X need to spin up device, requeue irp %p\n",
                   PdoExtension->FdoExtension->ResourceData.CmdBlockBase, PdoExtension->TargetId, Irp);
        }

        goto Exit;
    }

    if (Srb->Function == 0xC7)
        goto Exit;

    if (PdoExtension->DevicePowerState == 1)
        goto Exit;

    if (PdoExtension->DevicePowerState != 4 && Srb->TimeOutValue < 0x1E)
        Srb->TimeOutValue = 0x1E;

    State.DeviceState = PowerDeviceD0;

    Status = PoRequestPowerIrp(PdoExtension->SelfDevice, 2, State, NULL, NULL, NULL);
    ASSERT(NT_SUCCESS(Status));
    Status = STATUS_SUCCESS;

    ASSERT(PdoExtension->PendingRequest == NULL);

    PdoExtension->PendingRequest = Irp;

    DPRINT("IdePortInsertByKeyDeviceQueue: %X %X need to spin up device, requeue irp %p\n",
           PdoExtension->FdoExtension->ResourceData.CmdBlockBase, PdoExtension->TargetId, Irp);

    *OutResult = TRUE;

Exit:
  
    KeLowerIrql(Irql);
    DPRINT("IdePortInsertByKeyDeviceQueue: ret Status %X\n", Status);
    return Status;
}

NTSTATUS
NTAPI
IdeClaimLogicalUnit(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PIRP Irp)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    PIO_STACK_LOCATION IoStack;
    PVOID ImageSectionHandle;
    PSCSI_REQUEST_BLOCK Srb;
    KIRQL Irql;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IdeClaimLogicalUnit: %X\n", FdoExtension->ResourceData.CmdBlockBase);

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Srb = IoStack->Parameters.Scsi.Srb;

    PdoExtension = IoStack->Parameters.Others.Argument4;
    ASSERT(PdoExtension);

    ImageSectionHandle = MmLockPagableDataSection(IdeClaimLogicalUnit);
    KeAcquireSpinLock(&PdoExtension->PdoLock, &Irql);

    if (Srb->Function == 6)
    {
        PdoExtension->PdoState &= ~3;
        KeReleaseSpinLock(&PdoExtension->PdoLock, Irql);

        Status = STATUS_SUCCESS;
        Srb->SrbStatus = 1;
        goto Exit;
    }

    if (PdoExtension->PdoState & 1)
    {
        KeReleaseSpinLock(&PdoExtension->PdoLock, Irql);

        Srb->SrbStatus = 5;
        Status = STATUS_DEVICE_BUSY;
        goto Exit;
    }

    if (Srb->Function == 1)
        PdoExtension->PdoState |= 1;

    if (Srb->Function == 5)
        PdoExtension->Pdo = Srb->DataBuffer;

    Srb->DataBuffer = PdoExtension->Pdo;

    if (IoGetCurrentIrpStackLocation(Irp)->DeviceObject == PdoExtension->FdoExtension->SelfDevice)
        PdoExtension->PdoState |= 2;

    Status = STATUS_SUCCESS;

    KeReleaseSpinLock(&PdoExtension->PdoLock, Irql);
    Srb->SrbStatus = 1;

Exit:

    MmUnlockPagableImageSection(ImageSectionHandle);
    return Status;
}

VOID
NTAPI
IdePortFudgeAtaIdentifyData(
    _In_ PIDENTIFY_DATA Identify)
{
    if (Identify->GeneralConfiguration == 0xFFFFFFFF)
        Identify->GeneralConfiguration = 0x7F7F;
}


VOID
NTAPI
InitDeviceGeometry(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ ULONG Device,
    _In_ ULONG NumberOfCylinders,
    _In_ ULONG NumberOfHeads,
    _In_ ULONG SectorsPerTrack)
{
    ASSERT(HwDeviceExtension);
    ASSERT(Device < HwDeviceExtension->MaxIdeDevice);
    ASSERT(NumberOfCylinders);
    ASSERT(NumberOfHeads);
    ASSERT(SectorsPerTrack);

    HwDeviceExtension->NumberOfCylinders[Device] = NumberOfCylinders;
    HwDeviceExtension->NumberOfHeads[Device] = NumberOfHeads;
    HwDeviceExtension->SectorsPerTrack[Device] = SectorsPerTrack;
}

VOID
NTAPI
DeviceIdeReadCapacityCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PVOID InContext,
    _In_ NTSTATUS InStatus)
{
    PIDE_READ_CAPACITY_CONTEXT Context = InContext;
    PATA_DEVICE_EXTENSION HwDeviceExtension;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PREAD_CAPACITY_DATA CapacityData;
    PSCSI_REQUEST_BLOCK Srb;
    PIDENTIFY_DATA Identify;
    PIRP Irp;
    ULONG SectorsPerTrack;
    ULONG NumCylinders;
    ULONG NumHeads;
    ULONG Chs;
    ULONG MaxLba;
    KIRQL Irql;

    Irp = Context->Irp;
    Srb = IoGetCurrentIrpStackLocation(Irp)->Parameters.Scsi.Srb;

    FdoExtension = Context->PdoExtension->FdoExtension;
    HwDeviceExtension = FdoExtension->HwDeviceExtension;

    DPRINT("DeviceIdeReadCapacityCompletionRoutine: %X, %p\n", FdoExtension->ResourceData.CmdBlockBase, Srb);

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT1("DeviceIdeReadCapacityCompletionRoutine: InStatus %X\n", InStatus);

        if (Srb)
        {
            if (InStatus == STATUS_INSUFFICIENT_RESOURCES)
            {
                Srb->SrbStatus = SRB_STATUS_INTERNAL_ERROR;
                Srb->InternalStatus = STATUS_INSUFFICIENT_RESOURCES;
            }
            else
            {
                Srb->SrbStatus = SRB_STATUS_ERROR;
            }
        }

        goto Exit;
    }

    Identify = (PIDENTIFY_DATA)Context->AtaPassThr.Buffer;

    IdePortFudgeAtaIdentifyData(Identify);

    if (Identify->MajorRevision &&
        Identify->NumberOfCurrentCylinders &&
        Identify->NumberOfCurrentHeads &&
        Identify->CurrentSectorsPerTrack)
    {
        NumCylinders = Identify->NumberOfCurrentCylinders;
        NumHeads = Identify->NumberOfCurrentHeads;
        SectorsPerTrack = Identify->CurrentSectorsPerTrack;

        if (Identify->UserAddressableSectors > (NumCylinders * NumHeads * SectorsPerTrack))
        {
            if (NumCylinders <= 0xFFF && NumHeads == 0x10 && SectorsPerTrack == 0x3F)
            {
                NumCylinders = (Identify->UserAddressableSectors / 0x3F0);
            }
        }
    }
    else
    {
        NumCylinders = Identify->NumCylinders;
        NumHeads = Identify->NumHeads;
        SectorsPerTrack = Identify->NumSectorsPerTrack;
    }

    if (!NumCylinders || !NumHeads || !SectorsPerTrack)
    {
        NumCylinders = 1;
        NumHeads = 1;
        SectorsPerTrack = 1;

        Chs = 0;
    }
    else
    {
        Chs = (NumHeads * NumCylinders * SectorsPerTrack);
    }

    KeAcquireSpinLock(&FdoExtension->SpinLock, &Irql);

    InitDeviceGeometry(HwDeviceExtension, Srb->TargetId, NumCylinders, NumHeads, SectorsPerTrack);

    if (HwDeviceExtension->DeviceFlags[Srb->TargetId] & 0x40000)
    {
        RtlMoveMemory(&HwDeviceExtension->IdentifyData[Srb->TargetId], Identify, sizeof(IDENTIFY_DATA));

        ASSERT(!(HwDeviceExtension->DeviceFlags[Srb->TargetId] & 0x10));

        HwDeviceExtension->DeviceFlags[Srb->TargetId] |= 0x20000;
        HwDeviceExtension->DeviceFlags[Srb->TargetId] &= ~0x40000;
    }

    if (!Srb)
    {
        KeReleaseSpinLock(&FdoExtension->SpinLock, Irql);
        goto Exit;
    }

    CapacityData = Srb->DataBuffer;
    CapacityData->BytesPerBlock = 0x20000;

    if (FdoExtension->HwDeviceExtension->DeviceFlags[Srb->TargetId] & 0x400)
    {
        if (Identify->UserAddressableSectors < 0x10000000)
            MaxLba = (Identify->UserAddressableSectors - 1);
        else
            MaxLba = 0x0FFFFFFF;

        if (FdoExtension->HwDeviceExtension->DeviceFlags[Srb->TargetId] & 0x200000)
        {
            MaxLba = (Identify->Max48BitLBA[0] - 1);
            ASSERT(Identify->Max48BitLBA[1] == 0);
        }

        DPRINT("IDE LBA disk %X - total # of sectors %X\n", Srb->TargetId, Identify->UserAddressableSectors);
    }
    else
    {
        MaxLba = (Chs - 1);

        DPRINT("IDE CHS disk %X - #sectors %X, #heads %X, #cylinders %X\n", Srb->TargetId, SectorsPerTrack, NumHeads, NumCylinders);

        DPRINT("IDE CHS disk Identify data %X - #sectors %X, #heads %X, #cylinders %X\n",
               Srb->TargetId, Identify->NumSectorsPerTrack, Identify->NumHeads, Identify->NumCylinders);

        DPRINT("IDE CHS disk Identify currentdata %X - #sectors %X, #heads %X, #cylinders %X\n",
               Srb->TargetId, Identify->CurrentSectorsPerTrack, Identify->NumberOfCurrentHeads, Identify->NumberOfCurrentCylinders);
    }

    CapacityData->LogicalBlockAddress = RtlUlongByteSwap(MaxLba);

    Srb->SrbStatus = SRB_STATUS_SUCCESS;
    Irp->IoStatus.Information = sizeof(*CapacityData);

    KeReleaseSpinLock(&FdoExtension->SpinLock, Irql);

Exit:

    if (Srb)
        Srb->DataBuffer = Context->DataBuffer;

    UnrefLogicalUnitExtension(FdoExtension, Context->PdoExtension, Irp);

    IoGetCurrentIrpStackLocation(Irp)->Parameters.Others.Argument4 = NULL;

    ExFreePoolWithTag(Context, 'PedI');

    Irp->IoStatus.Status = InStatus;
    IoCompleteRequest(Irp, 0);
}

NTSTATUS
NTAPI
DeviceIdeReadCapacity(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PIRP Irp)
{
    PIDE_READ_CAPACITY_CONTEXT Context;
    PSCSI_REQUEST_BLOCK Srb;
    ULONG_PTR Address;
    NTSTATUS Status;

    DPRINT("DeviceIdeReadCapacity: %X\n", PdoExtension->FdoExtension->ResourceData.CmdBlockBase);

    Srb = IoGetCurrentIrpStackLocation(Irp)->Parameters.Scsi.Srb;

    if (!(PdoExtension->FdoExtension->HwDeviceExtension->DeviceFlags[Srb->TargetId] & 1))
    {
        Srb->SrbStatus = 8;
        UnrefLogicalUnitExtension(PdoExtension->FdoExtension, PdoExtension, Irp);

        DPRINT1("DeviceIdeReadCapacity: STATUS_NO_SUCH_DEVICE\n");
        Irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
        IoCompleteRequest(Irp, 0);
        return Irp->IoStatus.Status;
    }

    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Context), 'PedI');

    if (!Context || !Irp->MdlAddress)
    {
        DPRINT1("DeviceIdeReadCapacity: STATUS_INSUFFICIENT_RESOURCES\n");

        if (!Irp->MdlAddress)
        {
            DPRINT1("DeviceIdeReadCapacity: Irp->MdlAddress is NULL\n");
            ExFreePoolWithTag(Context, 'PedI');
        }

        UnrefLogicalUnitExtension(PdoExtension->FdoExtension, PdoExtension, Irp);

        Srb->SrbStatus = 0x30;
        Srb->InternalStatus = STATUS_INSUFFICIENT_RESOURCES;

        //IdePortLogNoMemoryErrorFn(..);

        Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        IoCompleteRequest(Irp, 0);
        return Irp->IoStatus.Status;
    }

    Context->DataBuffer = Srb->DataBuffer;

    Address = (ULONG_PTR)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, HighPagePriority);

    Srb->DataBuffer = Add2Ptr(Srb->DataBuffer, Address);
    Srb->DataBuffer = Add2Ptr(Srb->DataBuffer, -(ULONG_PTR)MmGetMdlVirtualAddress(Irp->MdlAddress));

    Context->PdoExtension = PdoExtension;
    Context->Irp = Irp;

    if (!Address)
    {
        //IdePortLogNoMemoryErrorFn(..);
        DeviceIdeReadCapacityCompletionRoutine(PdoExtension->SelfDevice, Context, STATUS_INSUFFICIENT_RESOURCES);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    IoMarkIrpPending(Irp);

    RtlZeroMemory(&Context->AtaPassThr, sizeof(Context->AtaPassThr));

    Context->AtaPassThr.BufferSize = sizeof(IDENTIFY_DATA);
    Context->AtaPassThr.IdeReg.bCommandReg = 0xEC;
    Context->AtaPassThr.IdeReg.bReserved = 0x40;

    Status = IssueAsyncAtaPassThroughSafe(PdoExtension->FdoExtension,
                                          PdoExtension,
                                          &Context->AtaPassThr,
                                          TRUE,
                                          DeviceIdeReadCapacityCompletionRoutine,
                                          Context,
                                          0,
                                          0xF,
                                          FALSE);
    if (Status != STATUS_PENDING)
        DeviceIdeReadCapacityCompletionRoutine(PdoExtension->SelfDevice, Context, Status);

    return STATUS_PENDING;
}

NTSTATUS
NTAPI
DeviceIdeModeSense(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PIRP Irp)
{
    PATA_DEVICE_EXTENSION HwDeviceExtension;
    PMODE_PARAMETER_HEADER ModePageHeader;
    PMODE_CACHING_PAGE ModeCaching;
    ATA_PASS_THROUGH AtaPassThr;
    PSCSI_REQUEST_BLOCK Srb;
    PCDB Cdb;
    ULONG ModeDataBufferSize;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("DeviceIdeModeSense: %p, %p\n", PdoExtension, Irp);

    HwDeviceExtension = PdoExtension->FdoExtension->HwDeviceExtension;
    Srb = IoGetCurrentIrpStackLocation(Irp)->Parameters.Scsi.Srb;
    Cdb = (PCDB)Srb->Cdb;

    if (!(PdoExtension->FdoExtension->HwDeviceExtension->DeviceFlags[Srb->TargetId] & 1))
    {
        Srb->SrbStatus = 8;
        UnrefLogicalUnitExtension(PdoExtension->FdoExtension, PdoExtension, Irp);
        Irp->IoStatus.Status = Status = STATUS_NO_SUCH_DEVICE;
        IoCompleteRequest(Irp, 0);
        return Status;
    }

    ASSERT(Cdb->MODE_SENSE.OperationCode == SCSIOP_MODE_SENSE);

    if (Cdb->MODE_SENSE.LogicalUnitNumber != PdoExtension->Lun ||
        Cdb->MODE_SENSE.Pc & 0xC0)
    {
        Srb->SrbStatus = 6;
        UnrefPdo(PdoExtension, Irp);
        Irp->IoStatus.Status = Status = STATUS_INVALID_DEVICE_REQUEST;
        goto Exit;
    }

    ModeDataBufferSize = Srb->DataTransferLength;

    if (ModeDataBufferSize < sizeof(*ModePageHeader))
    {
        Srb->SrbStatus = 6;
        UnrefPdo(PdoExtension, Irp);
        Irp->IoStatus.Status = Status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    ModePageHeader = Srb->DataBuffer;
    ASSERT(ModePageHeader);

    ASSERT(ModeDataBufferSize);
    RtlZeroMemory(ModePageHeader, ModeDataBufferSize);

    ModePageHeader->ModeDataLength = 3;

    if (HwDeviceExtension->DeviceFlags[Srb->TargetId] & 0x20)
    {
        RtlZeroMemory(&AtaPassThr, sizeof(AtaPassThr));

        AtaPassThr.IdeReg.bCommandReg = 0xDA;
        AtaPassThr.IdeReg.bReserved = 0x40;

        IssueSyncAtaPassThroughSafe(PdoExtension->FdoExtension, PdoExtension, &AtaPassThr, 0, 0, 0xF, FALSE);

        if (AtaPassThr.IdeReg.bCommandReg & 1)
        {
            if (AtaPassThr.IdeReg.bFeaturesReg & 0x40)
                ModePageHeader->DeviceSpecificParameter |= 0x80;
        }
    }

    if ((Cdb->MODE_SENSE.PageCode & 0x3F) != 0x3F &&
        (Cdb->MODE_SENSE.PageCode & 0x3F) != 8)
    {
        Srb->DataTransferLength -= (ModeDataBufferSize - 4);
        Srb->SrbStatus = 1;
        Irp->IoStatus.Information = Srb->DataTransferLength;
        UnrefPdo(PdoExtension, Irp);
        Irp->IoStatus.Status = Status = STATUS_SUCCESS;
        goto Exit;
    }

    if ((ModeDataBufferSize - 4) < 0xC)
    {
        Srb->DataTransferLength -= (ModeDataBufferSize - 4);
        Srb->SrbStatus = 0x12;
        Irp->IoStatus.Information = Srb->DataTransferLength;
        UnrefPdo(PdoExtension, Irp);
        Irp->IoStatus.Status = Status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    ModeCaching = (PMODE_CACHING_PAGE)&ModePageHeader[1];

    ModeCaching->PageCode = 8;
    ModeCaching->PageLength = 0xA;
    ModeCaching->WriteCacheEnable = PdoExtension->IsWriteCache;

    ModePageHeader->ModeDataLength += 0xC;

    Srb->DataTransferLength -= (ModeDataBufferSize - 0x10);
    Srb->SrbStatus = 1;

    Irp->IoStatus.Information = Srb->DataTransferLength;
    UnrefPdo(PdoExtension, Irp);
    Irp->IoStatus.Status = Status = STATUS_SUCCESS;

Exit:

    IoCompleteRequest(Irp, 0);
    return Status;
}

NTSTATUS
NTAPI
IdePortDispatch(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    ULONG (NTAPI* PciIdeUseDma)(PVOID, PUCHAR, ULONG);
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION pdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    PIO_STACK_LOCATION IoStack;
    PSCSI_REQUEST_BLOCK Srb;
    PCDB Cdb;
    ULONG ix;
    UCHAR cdb[16];
    BOOLEAN IsInserted = FALSE;
    BOOLEAN IsFlushOrShutdown = FALSE;
    KIRQL Irql;
    KIRQL StartIrql = KeGetCurrentIrql();
    NTSTATUS Status;

    FdoExtension = Fdo->DeviceExtension;

    DPRINT("IdePortDispatch: %p, %p, %p\n", Fdo, Irp, FdoExtension->LowDevice);

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Srb = IoStack->Parameters.Scsi.Srb;

    if (!FdoExtension->LowDevice)
    {
        do
        {
            pdoExtension = (PVOID)FdoExtension; // if LowDevice is NULL then it PDO extension

            Srb->PathId = pdoExtension->PathId;
            Srb->TargetId = pdoExtension->TargetId;
            Srb->Lun = pdoExtension->Lun;

            if (Srb->Function == 0)
            {
                Cdb = (PVOID)Srb->Cdb;
                Cdb->CDB6GENERIC.LogicalUnitNumber = pdoExtension->Lun;
            }

            Fdo = pdoExtension->FdoExtension->SelfDevice;
            FdoExtension = Fdo->DeviceExtension;
        }
        while (!FdoExtension->LowDevice);
    }

    PdoExtension = RefLogicalUnitExtension(FdoExtension, Srb->PathId, Srb->TargetId, Srb->Lun, TRUE, Irp);
    if (!PdoExtension)
    {
        DPRINT("IdePortDispatch: Bad logical unit address.\n");
        UNIMPLEMENTED_DBGBREAK();
        return STATUS_NO_SUCH_DEVICE;
    }

    IoStack->Parameters.Others.Argument4 = (PVOID)PdoExtension;

    if (Srb->Function != 0xC9)
    {
        if (PdoExtension->ScsiDeviceType == 1 &&
            (Srb->Cdb[0] == 0x19 || Srb->Cdb[0] == 0x1B || Srb->Cdb[0] == 0x2B ||
             Srb->Cdb[0] == 0x01 || Srb->Cdb[0] == 0x11 || Srb->Cdb[0] == 0x10))
        {
            Srb->SrbExtension = ULongToPtr(4);
        }
        else if (PdoExtension->ScsiDeviceType == 5 && Srb->Cdb[0] == 0x2B)
        {
            Srb->SrbExtension = ULongToPtr(4);
        }
        else
        {
            Srb->SrbExtension = NULL;
        }
    }

    if (!((ULONG_PTR)Srb->SrbExtension & 1) && Srb->Function != 0xC9)
    {
        if (Srb->SrbFlags & SRB_FLAGS_UNSPECIFIED_DIRECTION) //  (SRB_FLAGS_DATA_IN | SRB_FLAGS_DATA_OUT)
        {
            if (FdoExtension->HwDeviceExtension->DeviceFlags[Srb->TargetId] & 2)
            {
                if (Srb->Cdb[0] == 0x1A)
                {
                    UNIMPLEMENTED_DBGBREAK();
                }
                else if (Srb->Cdb[0] == 0x15)
                {
                    UNIMPLEMENTED_DBGBREAK();
                }
                else if (Srb->Cdb[0] == 3)
                {
                    ASSERT(!(((ULONG_PTR)Srb->SrbExtension) & ~7));
                    Srb->SrbExtension = Or2Ptr(Srb->SrbExtension, 1);
                }
                else if (Srb->Function == 0xC7 || Srb->Function == 0xC8)
                {
                    ASSERT(!(((ULONG_PTR)Srb->SrbExtension) & ~7));
                    Srb->SrbExtension = Or2Ptr(Srb->SrbExtension, 1);
                }
                else if (Srb->Cdb[0] == 0x5A || Srb->Cdb[0] == 0x55 ||
                         Srb->Cdb[0] == 0x12 || Srb->Cdb[0] == 0x4A || Srb->Cdb[0] == 0x46)
                {
                    ASSERT(!(((ULONG_PTR)Srb->SrbExtension) & ~7));
                    Srb->SrbExtension = Or2Ptr(Srb->SrbExtension, 1);
                }
            }
            else
            {
                if (Srb->Cdb[0] != 0x28 && Srb->Cdb[0] != 0x2A)
                {
                    ASSERT(!(((ULONG_PTR)Srb->SrbExtension) & ~7));
                    Srb->SrbExtension = Or2Ptr(Srb->SrbExtension, 1);

                    if (Srb->Cdb[0] == 0x25)
                    {
                        if (StartIrql != KeGetCurrentIrql())
                        {
                            DPRINT1("IdePortDispatch: StartIrql %X, CurrentIrql %X\n", StartIrql, KeGetCurrentIrql());
                            ASSERT(FALSE);
                        }

                        Status = DeviceIdeReadCapacity(PdoExtension, Irp);
                        DPRINT("IdePortDispatch: ret Status %X\n", Status);
                        return Status;
                    }
                    else if (Srb->Cdb[0] == 0x1A)
                    {
                        if (StartIrql != KeGetCurrentIrql())
                        {
                            DPRINT1("IdePortDispatch: StartIrql %X, CurrentIrql %X\n", StartIrql, KeGetCurrentIrql());
                            ASSERT(FALSE);
                        }

                        Status = DeviceIdeModeSense(PdoExtension, Irp);
                        DPRINT("IdePortDispatch: ret Status %X\n", Status);
                        return Status;
                    }
                    else if (Srb->Cdb[0] == 0x15)
                    {
                        UNIMPLEMENTED_DBGBREAK();
                    }
                }
            }

            ASSERT(FdoExtension->LowDevice);

            if (Srb->CdbLength)
                RtlCopyMemory(cdb, Srb->Cdb, Srb->CdbLength);

            if (FdoExtension->TransferModeInterface.PciIdeUseDma)
            {
                PciIdeUseDma = FdoExtension->TransferModeInterface.PciIdeUseDma;
                if (!PciIdeUseDma(FdoExtension->TransferModeInterface.MiniControllerExtension, Srb->Cdb, Srb->TargetId))
                {
                    ASSERT(!(((ULONG_PTR)Srb->SrbExtension) & ~7));
                    Srb->SrbExtension = Or2Ptr(Srb->SrbExtension, 1);
                }
            }

            for (ix = 0; ix < Srb->CdbLength; ix++)
            {
                if (cdb[ix] != Srb->Cdb[ix])
                {
                    DPRINT1("IdePortDispatch: Miniport modified the Cdb\n");
                    ASSERT(FALSE);
                }
            }

            if (PdoExtension->DmaTimeouts >= 6 || PdoExtension->CrcErrors >= 6)
            {
                ASSERT(!(((ULONG_PTR)Srb->SrbExtension) & ~7));
                Srb->SrbExtension = Or2Ptr(Srb->SrbExtension, 1);
            }
        }
        else
        {
            ASSERT(!(((ULONG_PTR)Srb->SrbExtension) & ~7));
            Srb->SrbExtension = Or2Ptr(Srb->SrbExtension, 1);
        }
    }


    if (Srb->Function == SRB_FUNCTION_SHUTDOWN || Srb->Function == SRB_FUNCTION_FLUSH)
    {
        if (Srb->Function == SRB_FUNCTION_SHUTDOWN)
        {
            DPRINT("IdePortDispatch: SRB_FUNCTION_SHUTDOWN...\n");
        }

        if (!(FdoExtension->HwDeviceExtension->DeviceFlags[Srb->TargetId] & 2) &&
            (PdoExtension->FlushCacheTimeouts >= 3 ||
             PdoExtension->FdoExtension->HwDeviceExtension->DeviceParameters[PdoExtension->TargetId].IdePioFlushCommand == 0xFF))
        {
            Status = STATUS_SUCCESS;
            Srb->SrbStatus = 1;

            if (StartIrql != KeGetCurrentIrql())
            {
                DPRINT1("IdePortDispatch: StartIrql %X, CurrentIrql %X\n", StartIrql, KeGetCurrentIrql());
                ASSERT(FALSE);
            }

            goto Exit;
        }

        DPRINT("IdePortDispatch: SRB_FUNCTION_%X to target %x\n", Srb->Function, Srb->TargetId);

        if (!(FdoExtension->HwDeviceExtension->DeviceFlags[Srb->TargetId] & 2))
        {
            Status = STATUS_SUCCESS;
            Srb->SrbStatus = 1;

            if (StartIrql != KeGetCurrentIrql())
            {
                DPRINT1("IdePortDispatch: StartIrql %X, CurrentIrql %X\n", StartIrql, KeGetCurrentIrql());
                ASSERT(FALSE);
            }

            goto Exit;
        }

        IsFlushOrShutdown = TRUE;
    }

    if (IsFlushOrShutdown ||
        Srb->Function == 0xC7 || Srb->Function == 0xC8 || Srb->Function == 0xC9 ||
        Srb->Function == 0x00 || Srb->Function == 0x02)
    {
        if (PdoExtension->PdoState & 0x40)
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        if ((Srb->SrbFlags & SRB_FLAGS_NO_KEEP_AWAKE) && PdoExtension->DevicePowerState != 1)
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        IoMarkIrpPending(Irp);

        if (Srb->SrbFlags & SRB_FLAGS_BYPASS_FROZEN_QUEUE)
        {
            DPRINT("IdePortDispatch: Bypass frozen queue, IRP %lx\n", Irp);
            IoStartPacket(Fdo, Irp, NULL, NULL);
        }
        else
        {
            KeRaiseIrql(DISPATCH_LEVEL, &Irql);

            Status = IdePortInsertByKeyDeviceQueue(PdoExtension, Irp, Srb->QueueSortKey, &IsInserted);

            if (!NT_SUCCESS(Status) || !IsInserted)
            {
                PdoExtension->PdoFlags &= ~2;
                PdoExtension->RetriesDoRequest = 0;
                IoStartPacket(Fdo, Irp, NULL, NULL);
            }

            KeLowerIrql(Irql);
        }

        DPRINT("IdePortDispatch: return STATUS_PENDING\n");
        return STATUS_PENDING;
    }

    DPRINT("IdePortDispatch: SRB %p, Function %X\n", Srb, Srb->Function);

    if (Srb->Function == 1 || Srb->Function == 5 || Srb->Function == 6)
    {
        Status = IdeClaimLogicalUnit(FdoExtension, Irp);

        if (StartIrql != KeGetCurrentIrql())
        {
            DPRINT1("IdePortDispatch: StartIrql %X, CurrentIrql %X\n", StartIrql, KeGetCurrentIrql());
            ASSERT(FALSE);
        }

        goto Exit;
    }
    else if (Srb->Function == 4)
    {
        UNIMPLEMENTED_DBGBREAK();
    }
    else if (Srb->Function == 0x10)
    {
        UNIMPLEMENTED_DBGBREAK();
    }
    else if (Srb->Function == 0x12)
    {
        UNIMPLEMENTED_DBGBREAK();
    }
    else if (Srb->Function == 0x15)
    {
        DPRINT("IdePortDispatch: SCSI flush queue command\n");

        Status = IdePortFlushLogicalUnit(FdoExtension, PdoExtension, 0);

        Srb->SrbStatus = (!NT_SUCCESS(Status) ? 4 : 1);

        if (StartIrql != KeGetCurrentIrql())
        {
            DPRINT1("IdePortDispatch: StartIrql %X, CurrentIrql %X\n", StartIrql, KeGetCurrentIrql());
            ASSERT(FALSE);
        }

        goto Exit;
    }
    else if (Srb->Function == 0x16)
    {
        UNIMPLEMENTED_DBGBREAK();
    }
    else
    {
        DPRINT("IdePortDispatch: Unsupported function, SRB %p\n", Srb);
        UNIMPLEMENTED_DBGBREAK();
    }

Exit:

    Irp->IoStatus.Status = Status;

    if (StartIrql != KeGetCurrentIrql())
    {
        DPRINT1("IdePortDispatch: StartIrql %X, CurrentIrql %X\n", StartIrql, KeGetCurrentIrql());
        ASSERT(FALSE);
    }

    UnrefLogicalUnitExtension(FdoExtension, PdoExtension, Irp);

    IoStack->Parameters.Others.Argument4 = NULL;

    if (StartIrql != KeGetCurrentIrql())
    {
        DPRINT1("IdePortDispatch: StartIrql %X, CurrentIrql %X\n", StartIrql, KeGetCurrentIrql());
        ASSERT(FALSE);
    }

    IoCompleteRequest(Irp, 0);

    if (StartIrql != KeGetCurrentIrql())
    {
        DPRINT1("IdePortDispatch: StartIrql %X, CurrentIrql %X\n", StartIrql, KeGetCurrentIrql());
        ASSERT(FALSE);
    }

    return Status;
}

/* POWER FUNCTIONS **********************************************************/

/* PDO POWER FUNCTIONS ******************************************************/

NTSTATUS
NTAPI
IdePortSetPdoPowerState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceQueryPowerState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* FDO POWER FUNCTIONS ******************************************************/

NTSTATUS
NTAPI
IdePortPowerCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PIDE_WAIT_CONTEXT WaitContext = Context;

    DPRINT("IdePortPowerCompletionRoutine: %p, %X, %X\n", DeviceObject, Irp, Context);

    if (WaitContext)
    {
        WaitContext->Status = Irp->IoStatus.Status;
        KeSetEvent(&WaitContext->Event, EVENT_INCREMENT, FALSE);
    }

    IoFreeIrp(Irp);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
IdePortIssueSetPowerState(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ POWER_STATE_TYPE PowerType,
    _In_ POWER_STATE State,
    _In_ BOOLEAN IsWait)
{
    PIO_STACK_LOCATION IoStack;
    IDE_WAIT_CONTEXT Context;
    PIRP Irp;
    NTSTATUS Status;

    DPRINT("IdePortIssueSetPowerState: %p, %X, %X, %X\n", FdoExtension, PowerType, State.SystemState, IsWait);

    if (IsWait)
        KeInitializeEvent(&Context.Event, NotificationEvent, FALSE);

    Irp = IoAllocateIrp(FdoExtension->SelfDevice->StackSize, FALSE);
    if (!Irp)
    {
        DPRINT1("IdePortIssueSetPowerState: STATUS_NO_MEMORY\n");
        return STATUS_NO_MEMORY;
    }

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    IoStack = IoGetNextIrpStackLocation(Irp);

    IoStack->MajorFunction = IRP_MJ_POWER;
    IoStack->MinorFunction = IRP_MN_SET_POWER;

    IoStack->Parameters.Power.SystemContext = 0;
    IoStack->Parameters.Power.Type = PowerType;
    IoStack->Parameters.Power.State = State;

    IoSetCompletionRoutine(Irp, IdePortPowerCompletionRoutine, (IsWait ? &Context : NULL), TRUE, TRUE, TRUE);

    Status = PoCallDriver(FdoExtension->SelfDevice, Irp);

    if (IsWait)
    {
        KeWaitForSingleObject(&Context.Event, Executive, KernelMode, FALSE, NULL);
        Status = Context.Status;
    }

    return Status;
}

VOID
NTAPI
FdoContingentPowerCompletionRoutine(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ UCHAR MinorFunction,
    _In_ POWER_STATE PowerState,
    _In_ PVOID Context,
    _In_ PIO_STATUS_BLOCK IoStatus)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
FdoSystemPowerUpCompletionRoutine(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ UCHAR MinorFunction,
    _In_ POWER_STATE PowerState,
    _In_ PVOID Context,
    _In_ PIO_STATUS_BLOCK IoStatus)
{
    PIRP Irp = Context;

    DPRINT("FdoSystemPowerUpCompletionRoutine: %p, %X, %p\n", Fdo, MinorFunction, Context);

    ((PFDO_DEVICE_EXTENSION)Fdo->DeviceExtension)->PendingSystemPowerIrp = NULL;

    PoStartNextPowerIrp(Irp);

    if (!NT_SUCCESS(IoStatus->Status))
    {
        DPRINT1("FdoSystemPowerUpCompletionRoutine: %X\n", IoStatus->Status);
        Irp->IoStatus.Status = IoStatus->Status;
    }

    IoCompleteRequest(Irp, 0);
}

VOID
NTAPI
ChannelRestoreTimingCompletionRoutine(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ NTSTATUS Status,
    _In_ PATAPI_SET_POWER_CONTEXT Context)
{
    DPRINT("ChannelRestoreTimingCompletionRoutine: %p, %X, %p\n", Fdo, Status, Context);

    Context->IsTimingsRestored = TRUE;
    Context->Irp->IoStatus.Status = Status;

    FdoPowerCompletionRoutine(IoGetCurrentIrpStackLocation(Context->Irp)->DeviceObject, Context->Irp, Context);

    IoCompleteRequest(Context->Irp, 0);
}

NTSTATUS
NTAPI
ChannelRestoreTiming(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PVOID CallBack,
    _In_ PATAPI_SET_POWER_CONTEXT Context)
{
    VOID (NTAPI* callBack)(PDEVICE_OBJECT, NTSTATUS, PATAPI_SET_POWER_CONTEXT) = CallBack;
    PIDE_ACPI_TIMING_MODE_BLOCK TimingBlock;
    PIDENTIFY_DATA identify[2];
    ULONG ix;

    DPRINT("ChannelRestoreTiming: %p, %X, %X\n", FdoExtension, FdoExtension->PdoCount1, identify);

    if (FdoExtension->PdoCount1)
    {
        TimingBlock = &FdoExtension->TimingBlock;

        if (TimingBlock->Drive[0].PioSpeed != 0xFFFFFFFF ||
            FdoExtension->TimingBlock.Drive[1].PioSpeed != 0xFFFFFFFF)
        {
            for (ix = 0; ix < 2; ix++)
            {
                if (FdoExtension->HwDeviceExtension->DeviceFlags[ix] & 1)
                {
                    identify[ix] =  &FdoExtension->HwDeviceExtension->IdentifyData[ix];
                }
                else
                {
                    identify[ix] =  NULL;
                }
            }

            DPRINT1("ChannelRestoreTiming: FIXME\n");
            ASSERT(FALSE);
        }

        DPRINT1("ChannelRestoreTiming: FIXME\n");
        ASSERT(FALSE);
    }

    callBack(FdoExtension->SelfDevice, STATUS_SUCCESS, Context);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
FdoPowerCompletionRoutine(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp,
    _In_ PVOID context)
{
    PATAPI_SET_POWER_CONTEXT Context = context;
    PFDO_DEVICE_EXTENSION FdoExtension;
    POWER_STATE State;
    BOOLEAN IsCompleted = TRUE;
    BOOLEAN IsLockedContext = TRUE;
    BOOLEAN IsSetDeviceSet;
    NTSTATUS Status;

    DPRINT("FdoPowerCompletionRoutine: %p, %p, %p\n", Fdo, Irp, Context);

    FdoExtension = Fdo->DeviceExtension;

    if (!NT_SUCCESS(Irp->IoStatus.Status))
    {
        DPRINT1("FdoPowerCompletionRoutine: devobj %p failed power irp %p\n", FdoExtension->LowDevice, Irp);

        if (Context->Type == SystemPowerState)
        {
            ASSERT(FdoExtension->PendingSystemPowerIrp == Irp);
            FdoExtension->PendingSystemPowerIrp = NULL;
        }
        else if (Context->Type == DevicePowerState)
        {
            ASSERT(FdoExtension->PendingDevicePowerIrp == Irp);
            FdoExtension->PendingDevicePowerIrp = NULL;
        }

        goto Finish;
    }

    if (Context->Type == SystemPowerState)
    {
        FdoExtension->SystemPowerState = Context->State.SystemState;

        if (Context->State.SystemState == PowerSystemWorking)
        {
            ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[0]), 0, 1) == 1);
            IsLockedContext = FALSE;

            ASSERT(FdoExtension->PendingSystemPowerIrp == Irp);
            IsCompleted = FALSE;

            State.SystemState = PowerSystemWorking;

            Status = PoRequestPowerIrp(FdoExtension->SelfDevice,
                                       IRP_MN_SET_POWER,
                                       State,
                                       FdoSystemPowerUpCompletionRoutine,
                                       Irp,
                                       NULL);

            ASSERT(Status == STATUS_PENDING);
        }

        if (IsCompleted)
            FdoExtension->PendingSystemPowerIrp = NULL;

        DPRINT("FdoPowerCompletionRoutine: (%X) New system power state %X\n",
               FdoExtension->ResourceData.CmdBlockBase, Context->State.SystemState);

        PoSetPowerState(Fdo, Context->Type, Context->State);

        goto Finish;
    }

    if (Context->Type != DevicePowerState)
    {
        DPRINT1("FdoPowerCompletionRoutine: Context->Type %X\n", Context->Type);
        ASSERT(FALSE);
        goto Finish;
    }

    if (Context->State.DeviceState == PowerDeviceD0 && (FdoExtension->HackFlags & 1))
    {
        DPRINT1("FdoPowerCompletionRoutine: FIXME\n");
        ASSERT(FALSE);
    }

    if (Context->State.DeviceState == PowerDeviceD0 && !Context->IsTimingsRestored)
    {
        Status = ChannelRestoreTiming(FdoExtension, ChannelRestoreTimingCompletionRoutine, Context);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("FdoPowerCompletionRoutine: FIXME\n");
            ASSERT(FALSE);
        }

        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    ASSERT(FdoExtension->PendingDevicePowerIrp == Irp);
    FdoExtension->PendingDevicePowerIrp = NULL;

    if (FdoExtension->DevicePowerState == PowerDeviceD0)
        IsSetDeviceSet = FALSE;
    else
        IsSetDeviceSet = TRUE;

    FdoExtension->DevicePowerState = Context->State.DeviceState;

    if (FdoExtension->DevicePowerState == PowerDeviceD0 && (FdoExtension->FdoState & 2))
        IoInvalidateDeviceRelations(FdoExtension->LowPdo, 0);

    if (IsSetDeviceSet)
    {
        DPRINT("FdoPowerCompletionRoutine: (%X) New device power state %X\n",
               FdoExtension->ResourceData.CmdBlockBase, Context->State.DeviceState);

        PoSetPowerState(Fdo, Context->Type, Context->State);
    }

Finish:

    if (IsLockedContext)
    {
        if (Context->Type == SystemPowerState)
            ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[0]), 0, 1) == 1);
        else
            ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[1]), 0, 1) == 1);
    }

    if (IsCompleted)
    {
        PoStartNextPowerIrp(Irp);
        Status = Irp->IoStatus.Status;
    }
    else
    {
        Status = STATUS_MORE_PROCESSING_REQUIRED;
    }

    return Status;
}

NTSTATUS
NTAPI
IdePortSetFdoPowerState(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PATAPI_SET_POWER_CONTEXT PowerContext;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PIO_STACK_LOCATION IoStack;
    POWER_STATE State;
    BOOLEAN SystemPowerContext = FALSE;
    BOOLEAN DevicePowerContext = FALSE;
    BOOLEAN IsNeedChangeState = FALSE;
    NTSTATUS Status;

    DPRINT("IdePortSetFdoPowerState: %p, %p\n", Fdo, Irp);

    FdoExtension = Fdo->DeviceExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (IoStack->Parameters.Power.Type == 0)
    {
        SystemPowerContext = TRUE;
        ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[0]), 1, 0) == 0);
        PowerContext = &FdoExtension->PowerContext[0];
    }
    else
    {
        DevicePowerContext = TRUE;
        ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[1]), 1, 0) == 0);
        PowerContext = &FdoExtension->PowerContext[1];
    }

    if (!PowerContext)
    {
        DPRINT1("IdePortSetFdoPowerState: STATUS_NO_MEMORY\n");
        ASSERT(PowerContext);
        Status = STATUS_NO_MEMORY;
        goto ErrorExit;
    }

    PowerContext->IsTimingsRestored = FALSE;
    PowerContext->Irp = Irp;
    PowerContext->Type = IoStack->Parameters.Power.Type;
    PowerContext->State = IoStack->Parameters.Power.State;

    if (IoStack->Parameters.Power.Type == 0)
    {
        if (FdoExtension->SystemPowerState != IoStack->Parameters.Power.State.SystemState)
        {
            ASSERT(FdoExtension->PendingSystemPowerIrp == NULL);
            FdoExtension->PendingSystemPowerIrp = Irp;

            if (FdoExtension->SystemPowerState == 1)
            {
                if (IoStack->Parameters.Power.State.SystemState == PowerSystemShutdown &&
                    IoStack->Parameters.Power.ShutdownType == PowerActionShutdownReset)
                {
                    State.SystemState = 1;
                }
                else
                {
                    State.SystemState = 4;
                }

                IoMarkIrpPending(Irp);

                PoRequestPowerIrp(FdoExtension->SelfDevice, 2, State, FdoContingentPowerCompletionRoutine, PowerContext, 0);
                return STATUS_PENDING;
            }

            IsNeedChangeState = TRUE;
        }
    }
    else if (IoStack->Parameters.Power.Type == 1)
    {
        if (FdoExtension->DevicePowerState != IoStack->Parameters.Power.State.DeviceState)
        {
            DPRINT("IdePortSetFdoPowerState: New Fdo %X device power state %X\n", FdoExtension->ResourceData.CmdBlockBase, IoStack->Parameters.Power.State.DeviceState);

            ASSERT(FdoExtension->PendingDevicePowerIrp == NULL);
            FdoExtension->PendingDevicePowerIrp = Irp;

            if (FdoExtension->DevicePowerState == 1)
                PoSetPowerState(Fdo, DevicePowerState, IoStack->Parameters.Power.State);

            IsNeedChangeState = TRUE;
        }
    }
    else 
    {
        DPRINT1("IdePortSetFdoPowerState: STATUS_NOT_IMPLEMENTED\n");
        ASSERT(FALSE);
        Status = STATUS_NOT_IMPLEMENTED;
        goto ErrorExit;
    }

    IoMarkIrpPending(Irp);
    IoCopyCurrentIrpStackLocationToNext(Irp);

    if (IsNeedChangeState)
    {
        IoSetCompletionRoutine(Irp, FdoPowerCompletionRoutine, PowerContext, TRUE, TRUE, TRUE);
    }
    else
    {
        if (SystemPowerContext)
        {
            ASSERT(DevicePowerContext == FALSE);
            ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[0]), 0, 1) == 1);
        }
        if (DevicePowerContext)
        {
            ASSERT(SystemPowerContext == FALSE);
            ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[1]), 0, 1) == 1);
        }

        PoStartNextPowerIrp(Irp);
    }

    PoCallDriver(FdoExtension->LowDevice, Irp);
    return STATUS_PENDING;

ErrorExit:

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = Status;

    if (PowerContext)
    {
        if (SystemPowerContext)
        {
            ASSERT(DevicePowerContext == FALSE);
            ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[0]), 0, 1) == 1);
        }
        if (DevicePowerContext)
        {
            ASSERT(SystemPowerContext == FALSE);
            ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[1]), 0, 1) == 1);
        }
    }

    PoStartNextPowerIrp(Irp);
    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
ChannelQueryPowerState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
IdePortDispatchPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    ULONG CmdBlockBase;
    UCHAR MinorFunction;
    BOOLEAN IsFdo;

    DPRINT("IdePortDispatchPower: %p, %p\n", DeviceObject, Irp);

    FdoExtension = DeviceObject->DeviceExtension;
    MinorFunction = (IoGetCurrentIrpStackLocation(Irp))->MinorFunction;

    if (FdoExtension->LowDevice)
    {
        CmdBlockBase = FdoExtension->ResourceData.CmdBlockBase;
        DPRINT("IdePortDispatchPower: FDO %d (%X) got %s\n", FdoExtension->FdoIndex, CmdBlockBase, PowerMinorNames[MinorFunction]);
        IsFdo = TRUE;
    }
    else
    {
        DPRINT1("IdePortDispatchPower: FIXME\n");
        ASSERT(FALSE);
        IsFdo = FALSE;
    }

    if (MinorFunction <= IRP_MN_QUERY_LEGACY_BUS_INFORMATION)
    {
        if (IsFdo)
            return FdoExtension->FdoPowerDispatchTable[MinorFunction](DeviceObject, Irp);
        else
            {ASSERT(FALSE);return 0;}
    }

    if (MinorFunction >= 4)
        ASSERT(!"ATAPI: Power Dispatch Table too small\\n");

    if (IsFdo)
        return FdoExtension->PassDownToNextDriver(DeviceObject, Irp);
    else
        {ASSERT(FALSE);return 0;}
}

/* PNP FUNCTIONS ************************************************************/

NTSTATUS
NTAPI
IdePortStatusSuccessAndPassDownToNextDriver(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;

    return IdePortPassDownToNextDriver(Fdo, Irp);
}

NTSTATUS
NTAPI
IdePortPassDownToNextDriver(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;

    PAGED_CODE();
    DPRINT("IdePortPassDownToNextDriver: %p, %p\n", Fdo, Irp);

    FdoExtension = Fdo->DeviceExtension;
    ASSERT(FdoExtension->LowDevice);

    if ((IoGetCurrentIrpStackLocation(Irp))->MajorFunction == IRP_MJ_POWER)
    {
        PoStartNextPowerIrp(Irp);
        IoSkipCurrentIrpStackLocation(Irp);
        return PoCallDriver(FdoExtension->LowDevice, Irp);
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(FdoExtension->LowDevice, Irp);
}

NTSTATUS
NTAPI
IdePortNoSupportIrp(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Status = Irp->IoStatus.Status;

    if (IoStack->MajorFunction == IRP_MJ_POWER)
        PoStartNextPowerIrp(Irp);

    DPRINT("IdePortNoSupportIrp: %p failing unsupported Irp (%X:%X) with %X\n", Pdo, IoStack->MajorFunction, IoStack->MinorFunction, Status);

    IoCompleteRequest(Irp, 0);
    return Status;
}

NTSTATUS
NTAPI
IdePortAlwaysStatusSuccessIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, 0);
    return STATUS_SUCCESS;
}

/* FDO PNP FUNCTIONS ********************************************************/

NTSTATUS
NTAPI
ChannelStartDeviceCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PRKEVENT Event = Context;
    DPRINT("ChannelStartDeviceCompletionRoutine: %p\n", Context);
    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
IdePortGenericCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PRKEVENT Event = Context;

    DPRINT("IdePortGenericCompletionRoutine: %p\n", Context);

    KeSetEvent(Event, EVENT_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
IdePortSyncSendIrp(
    _In_ PDEVICE_OBJECT LowDevice,
    _In_ PIO_STACK_LOCATION IoStack,
    _Out_ PIO_STATUS_BLOCK OutIoStatus)
{
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    ASSERT(LowDevice);
    ASSERT(IoStack);

    DPRINT("IdePortSyncSendIrp: %p, %p, %p\n", LowDevice, IoStack, OutIoStatus);
    Irp = IoAllocateIrp(LowDevice->StackSize, FALSE);
    if (!Irp)
    {
        DPRINT1("IdePortSyncSendIrp: Unable to get allocate an irp");
        return STATUS_NO_MEMORY;
    }
    RtlMoveMemory(IoGetNextIrpStackLocation(Irp), IoStack, sizeof(*IoStack));

    if (OutIoStatus)
        Irp->IoStatus.Status = OutIoStatus->Status;
    else
        Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    IoSetCompletionRoutine(Irp, IdePortGenericCompletionRoutine, &Event, TRUE, TRUE, TRUE);

    if (IoCallDriver(LowDevice, Irp) == STATUS_PENDING)
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

    Status = Irp->IoStatus.Status;

    if (OutIoStatus)
    {
        OutIoStatus->Status = Status;
        OutIoStatus->Information = Irp->IoStatus.Information;
    }

    IoFreeIrp(Irp);

    return Status;
}

VOID
NTAPI
AtapiCallBack(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension)
{
    PSCSI_REQUEST_BLOCK Srb;
    PCDB Cdb;

    Srb = HwDeviceExtension->CurrentSrb;

    DPRINT1("AtapiCallBack: Srb %X\n", Srb);

    if (!HwDeviceExtension->CurrentSrb)
        goto Finish;

    if (HwDeviceExtension->ExpectingInterrupt)
        goto Finish;

    Cdb = (PCDB)Srb->Cdb;

    if (!((ULONG_PTR)Srb->SrbExtension & 4))
    {
        DPRINT1("AtapiCallBack: Invalid CDB marked as RDP %X\n", Cdb->CDB6GENERIC.OperationCode);
    }

    if (HwDeviceExtension->IsDscRestrictive)
    {
        if (READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status) & 0x10)
        {
            IdePortNotification(0, HwDeviceExtension, Srb);

            HwDeviceExtension->CurrentSrb = NULL;
            HwDeviceExtension->IsDscRestrictive = FALSE;

            IdePortNotification(1, HwDeviceExtension, 0);
        }
        else
        {
            DPRINT1("AtapiCallBack: Requesting another timer for Op %X\n", Cdb->CDB6GENERIC.OperationCode);
            IdePortNotification(6, HwDeviceExtension, AtapiCallBack, 1000);
        }

        return;
    }

Finish:

    DPRINT1("AtapiCallBack: Calling ISR directly due to BUSY\n");

    AtapiInterrupt(HwDeviceExtension);
}

ULONG
NTAPI
MapError(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    PCDB Cdb;
    UCHAR Error;
    UCHAR SrbStatus;

    Error = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Error);
    Cdb = (PCDB)Srb->Cdb;

    DPRINT("MapError: cdb %X and Error register is %X\n", Cdb->CDB6GENERIC.OperationCode, Error);

    if (HwDeviceExtension->DeviceFlags[Srb->TargetId] & 2)
    {
        switch (Error >> 4) /* Sense codes */
        {
            case 0:
                DPRINT("MapError: No sense information\n");
                break;

            case 1:
                DPRINT("MapError: Recovered error\n");
                break;

            case 2:
                DPRINT("MapError: Device not ready\n");
                break;

            case 3:
                DPRINT("MapError: Media error\n");
                break;

            case 4:
                DPRINT("MapError: Hardware error\n");
                break;

            case 5:
                DPRINT("MapError: Illegal request\n");
                break;

            case 6:
                DPRINT("MapError: Unit attention\n");
                break;

            case 7:
                DPRINT("MapError: Data protect\n");
                break;

            case 8:
                DPRINT("MapError: Blank check\n");
                break;

            case 0xB:
                DPRINT("MapError: Command Aborted\n");
                break;

            default:
                DPRINT("MapError: Invalid sense information\n");
                break;
        }

        SrbStatus = 4;
        goto Exit;
    }

    UNIMPLEMENTED_DBGBREAK();

Exit:
    Srb->ScsiStatus = 2;
    return SrbStatus;
}

BOOLEAN
NTAPI
AtapiInterrupt(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension)
{
    PSENDCMDOUTPARAMS OutParameters;
    PSCSI_REQUEST_BLOCK CurrentSrb;
    PATA_PASS_THROUGH AtaPassThr;
    ULONG bmStatus = 0;
    ULONG SrbStatus=6;
    ULONG BytesXferred = 0;
    ULONG BytesRequested;
    ULONG PioModeSize = 0x200;
    ULONG BytesLow;
    ULONG BytesHigh;
    ULONG ix;
    ULONG jx;
    UCHAR InterruptReason;
    UCHAR IdeStatus;
    UCHAR MaximumBlockTransfer;
    UCHAR Error;
    BOOLEAN IsActiveDmaTransfer = FALSE;
    BOOLEAN IsIdeCommanSleep = FALSE;
    BOOLEAN Result = FALSE;
    BOOLEAN IsAtapiDevice;
    ULONG (NTAPI* BmDisarm)(PVOID);
    ULONG (NTAPI* BmStatus)(PVOID);

    DPRINT("AtapiInterrupt: %p\n", HwDeviceExtension);

    if (HwDeviceExtension->BusMasterInterface.AlwaysClearBusMasterInterrupt &&
        HwDeviceExtension->BusMasterInterface.BmStatus)
    {
        BmStatus = HwDeviceExtension->BusMasterInterface.BmStatus;
        bmStatus = BmStatus(HwDeviceExtension->BusMasterInterface.Context);

        if (bmStatus & 4)
        {
            BmDisarm = HwDeviceExtension->BusMasterInterface.BmDisarm;
            BmDisarm(HwDeviceExtension->BusMasterInterface.Context);
            Result = TRUE;
        }
    }

    if (!HwDeviceExtension->CurrentSrb)
    {
        DPRINT("AtapiInterrupt: CurrentSrb is NULL. Bogus Interrupt\n");

        if (!HwDeviceExtension->IntResFlags && HwDeviceExtension->CmdBlock.CmdBlockBase)
            READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);

        return Result;
    }

    if (!HwDeviceExtension->ExpectingInterrupt)
    {
        DPRINT("AtapiInterrupt: Unexpected interrupt.\n");
        return Result;
    }

    if (!HwDeviceExtension->BusMasterInterface.AlwaysClearBusMasterInterrupt &&
        HwDeviceExtension->BusMasterInterface.BmStatus)
    {
        BmStatus = HwDeviceExtension->BusMasterInterface.BmStatus;
        bmStatus = BmStatus(HwDeviceExtension->BusMasterInterface.Context);

        if (bmStatus & 4)
        {
            BmDisarm = HwDeviceExtension->BusMasterInterface.BmDisarm;
            BmDisarm(HwDeviceExtension->BusMasterInterface.Context);
        }
    }

    CurrentSrb = HwDeviceExtension->CurrentSrb;

    if (HwDeviceExtension->IsActiveDmaTransfer)
    {
        if (!(bmStatus & 4) && !HwDeviceExtension->IsDriverMustPoll)
        {
            DPRINT("AtapiInterrupt: No BusMaster Interrupt\n");
            ASSERT(Result == FALSE);
            return FALSE;
        }

        IsActiveDmaTransfer = TRUE;
        HwDeviceExtension->IsActiveDmaTransfer = 0;

        if (HwDeviceExtension->BusMasterInterface.IgnoreActiveBitForAtaDevice &&
            !(HwDeviceExtension->DeviceFlags[CurrentSrb->TargetId] & 2))
        {
            bmStatus &= ~1;
        }
    }

    IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);

    if (CurrentSrb->Function == 0xC8 || CurrentSrb->Function == 0xC7 || CurrentSrb->Function == 0xC9)
    {
        IsAtapiDevice = FALSE;

        AtaPassThr = (PATA_PASS_THROUGH)(CurrentSrb->Function == 0xC9 ? CurrentSrb->Cdb : CurrentSrb->DataBuffer);

        if (AtaPassThr->IdeReg.bCommandReg == 0xE6)
        {
            IsIdeCommanSleep = TRUE;
            IdeStatus = 0x50;
        }
    }
    else
    {
        IsAtapiDevice = ((HwDeviceExtension->DeviceFlags[CurrentSrb->TargetId] & 2) == 2);
    }

    DPRINT("AtapiInterrupt: (%X) Entered with IdeStatus (%X)\n", IsAtapiDevice, IdeStatus);

    if (IdeStatus & 0x80)
    {
        if (HwDeviceExtension->IsDriverMustPoll)
        {
            DPRINT1("AtapiInterrupt: Hit IdeStatus %X while polling during crashdump.\n", IdeStatus);
            HwDeviceExtension->IsActiveDmaTransfer = 1;
            return TRUE;
        }

        if (IsActiveDmaTransfer)
        {
            DPRINT("AtapiInterrupt: End of DMA transfer but device is still BUSY. IdeStatus %X\n", IdeStatus);
            HwDeviceExtension->ExpectingInterrupt = 0;
            return Result;
        }

        for (ix = 0; ix < 10; ix++)
        {
            IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
            if (!(IdeStatus & 0x80))
                break;
        }

        if (ix == 10)
        {
            DPRINT1("AtapiInterrupt: BUSY on entry. Status %X, Base IO %X\n", IdeStatus, &HwDeviceExtension->CmdBlock);
            IdePortNotification(6, HwDeviceExtension, AtapiCallBack, 500);
            return Result;
        }
    }

    if ((IdeStatus & 1) && CurrentSrb->Cdb[0] != 3)
    {
        SrbStatus = 4;
        goto Finish;
    }

    InterruptReason = 4;

    if (IsAtapiDevice)
    {
        InterruptReason = (READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.InterruptReason) & 3);
        DPRINT("AtapiInterrupt: InterruptReason %X\n", InterruptReason);

        if (IsActiveDmaTransfer && InterruptReason != 3)
        {
            DPRINT("AtapiInterrupt: Interrupt during DMA transfer, reason %X != 0x3\n", InterruptReason);
            HwDeviceExtension->ExpectingInterrupt = 0;
            return Result;
        }

        PioModeSize = 0x200;
    }
    else if (IsActiveDmaTransfer)
    {
        InterruptReason = 3;
    }
    else if (IdeStatus & 8)
    {
        MaximumBlockTransfer = HwDeviceExtension->MaximumBlockTransfer[CurrentSrb->TargetId];
        if (MaximumBlockTransfer)
            PioModeSize = (MaximumBlockTransfer << 9);

        if (CurrentSrb->SrbFlags & 0x40)
        {
            InterruptReason = 2;
        }
        else if (CurrentSrb->SrbFlags & 0x80)
        {
            InterruptReason = 0;
        }
        else
        {
            SrbStatus = 4;
            goto Finish;
        }
    }
    else if (IdeStatus & 0x80)
    {
        ASSERT(Result == FALSE);
        return FALSE;
    }
    else if (HwDeviceExtension->TransferDataBytes)
    {
        return Result;
    }
    else
    {
        InterruptReason = 3;
    }

    DPRINT("AtapiInterrupt: InterruptReason %X\n", InterruptReason);

    if (InterruptReason == 1 && (IdeStatus & 8))
    {
        //Write Atapi
        DPRINT("AtapiInterrupt: Writing Atapi packet.\n");
        DPRINT1("AtapiInterrupt: FIXME\n");
        ASSERT(FALSE);
        return Result;
    }
    else if (InterruptReason == 0 && (IdeStatus & 8))
    {
        // Write ATA
        if (IsAtapiDevice)
        {
            DPRINT1("AtapiInterrupt: FIXME\n");
            ASSERT(FALSE);
        }
        else
        {
            if (HwDeviceExtension->TransferDataBytes >= PioModeSize)
                BytesXferred = PioModeSize;
            else
                BytesXferred = HwDeviceExtension->TransferDataBytes;
        }

        if (!(CurrentSrb->SrbFlags & 0x80))
        {
            DPRINT1("AtapiInterrupt: Int reason 0, but srb is for a write %X\n", CurrentSrb);
            SrbStatus = 4;
            goto Finish;
        }

        DPRINT("AtapiInterrupt: Write interrupt\n");

        for (ix = 0; ix < 10; ix++)
        {
            for (jx = 0; jx < 25000; jx++)
            {
                IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
                if (!(IdeStatus & 0x80))
                    break;

                KeStallExecutionProcessor(40);
            }

            if (!(IdeStatus & 0x80))
                break;

            DPRINT1("AtapiInterrupt: after 1 sec wait, device is still busy with %X IdeStatus %X\n",
                    HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
        }

        if (IdeStatus & 0x80)
        {
            DPRINT1("AtapiInterrupt: WaitOnBusy failed. %X IdeStatus %X\n",
                    HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
        }

        WRITE_PORT_BUFFER_USHORT(HwDeviceExtension->CmdBlock.Data, (PUSHORT)HwDeviceExtension->TransferDataBuffer, (BytesXferred / 2));

        if (BytesXferred & 1)
            WRITE_PORT_UCHAR((PUCHAR)HwDeviceExtension->CmdBlock.Data, HwDeviceExtension->TransferDataBuffer[BytesXferred - 1]);

        HwDeviceExtension->TransferDataBuffer += BytesXferred;
        HwDeviceExtension->TransferDataBytes -= BytesXferred;

        return Result;
    }
    else if (InterruptReason == 2 && (IdeStatus & 8))
    {
        // Read
        BytesRequested = HwDeviceExtension->TransferDataBytes;

        if (IsAtapiDevice)
        {
            BytesLow = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.BytesLow);
            BytesHigh = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.BytesHigh);

            BytesXferred = (BytesLow | (BytesHigh << 8));

            if (BytesXferred != BytesRequested)
            {
                DPRINT("AtapiInterrupt: %X bytes requested, %X bytes xferred\n", BytesRequested, BytesXferred);
            }

            if (BytesXferred > BytesRequested)
                BytesXferred = BytesRequested;
        }
        else
        {
            if (BytesRequested >= PioModeSize)
                BytesXferred = PioModeSize;
            else
                BytesXferred = BytesRequested;
        }

        if (CurrentSrb->SrbFlags & 0x40)
        {
            DPRINT("AtapiInterrupt: Read interrupt\n");

            ix = 0;
            while (TRUE)
            {
                for (jx = 0; jx < 25000; jx++)
                {
                    IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
                    if (!(IdeStatus & 0x80))
                        break;

                    KeStallExecutionProcessor(40);
                }

                if (!(IdeStatus & 0x80))
                    break;

                DPRINT("AtapiInterrupt: after 1 sec wait, device is still busy with %X IdeStatus %X\n",
                       HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);

                ix++;
                if (ix >= 0xA)
                {
                    if (IdeStatus & 0x80)
                    {
                        DPRINT("WaitOnBusy failed in '%s' line %u. %X IdeStatus %X\n",
                               __FILE__, __LINE__, HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
                    }

                    break;
                }
            }

            READ_PORT_BUFFER_USHORT(HwDeviceExtension->CmdBlock.Data,
                                    (PUSHORT)HwDeviceExtension->TransferDataBuffer,
                                    (BytesXferred >> 1));

            if (BytesXferred & 1)
                HwDeviceExtension->TransferDataBuffer[BytesXferred - 1] = READ_PORT_UCHAR((PUCHAR)HwDeviceExtension->CmdBlock.Data);

            if (HwDeviceExtension->IsCdbSaved)
            {
                DPRINT1("AtapiInterrupt: FIXME\n");
                ASSERT(FALSE);
            }

            HwDeviceExtension->TransferDataBuffer += BytesXferred;
            HwDeviceExtension->TransferDataBytes -= BytesXferred;

            if (HwDeviceExtension->TransferDataBytes)
            {
                DPRINT("AtapiInterrupt: BytesLeft %X\n", HwDeviceExtension->TransferDataBytes);
                return Result;
            }

            if (IsAtapiDevice)
            {
                if (!(HwDeviceExtension->DeviceFlags[CurrentSrb->TargetId] & 0x800) &&
                    CurrentSrb->Cdb[0] == 0x25)
                {
                    DPRINT1("AtapiInterrupt: FIXME\n");
                    ASSERT(FALSE);
                }

                return Result;
            }
            else
            {
                SrbStatus = 1;
                goto Finish;
            }
        }
        else
        {
            DPRINT("AtapiInterrupt: Int reason %X, but srb is for a read %X\n", 2, CurrentSrb);
            SrbStatus = 4;
            goto Finish;
        }
    }
    else if (InterruptReason == 3)
    {
        // Complete
        if (!IsActiveDmaTransfer)
        {
            if (HwDeviceExtension->TransferDataBytes)
            {
                DPRINT("AtapiInterrupt: HwDeviceExtension->TransferDataBytes %X\n", HwDeviceExtension->TransferDataBytes);
            }

            SrbStatus = (HwDeviceExtension->TransferDataBytes ? 0x12 : 1);
        }
        else
        {
            HwDeviceExtension->TransferDataBytes = 0;

            if (!(bmStatus & ~4))
                SrbStatus = 1;
            else if (bmStatus & 1)
                SrbStatus = 0x12;
            else if (bmStatus & 2)
                SrbStatus = 4;
            else
                SrbStatus = 4;
        }
    }
    else
    {
        DPRINT("AtapiInterrupt: Unexpected interrupt. InterruptReason %X, Status %X\n", InterruptReason, IdeStatus);
        ASSERT(Result == FALSE);
        return Result;
    }

Finish:

    if (SrbStatus != 4)
    {
        for (jx = 0; jx < 60; jx++)
        {
            if (IsIdeCommanSleep)
                IdeStatus = 0x50;
            else
                IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);

            if (!(IdeStatus & 0x80))
                break;

            KeStallExecutionProcessor(500);
        }

        if (jx == 60)
        {
            DPRINT("AtapiInterrupt: Resetting due to BSY still up %X. Base Io %X\n", IdeStatus, &HwDeviceExtension->CmdBlock);

            if (!HwDeviceExtension->IsDriverMustPoll)
            {
                IdePortNotification(0xB, HwDeviceExtension, 0);
                return Result;
            }

            SrbStatus = 0xE;
        }

        if (IdeStatus & 8)
        {
            DPRINT1("AtapiInterrupt: FIXME\n");
            ASSERT(FALSE);
        }
    }
    else
    {
        Error = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Error);

        DPRINT("AtapiInterrupt: last command return IdeStatus byte %X and error byte %X\n", IdeStatus, Error);

        if (HwDeviceExtension->IsCdbSaved)
        {
            DPRINT1("AtapiInterrupt: FIXME\n");
            ASSERT(FALSE);
        }

        if (CurrentSrb->Function == 8 || CurrentSrb->Function == 7)
        {
            SrbStatus = 1;
        }
        else if (CurrentSrb->Function != 0xC8 && CurrentSrb->Function != 0xC7 && CurrentSrb->Function != 0xC9)
        {
            SrbStatus = MapError(HwDeviceExtension, CurrentSrb);
        }

        HwDeviceExtension->IsDscRestrictive = FALSE;
    }

    HwDeviceExtension->ExpectingInterrupt = 0;
    CurrentSrb->SrbStatus = SrbStatus;
    DPRINT("AtapiInterrupt: CurrentSrb %p, SrbStatus %X\n", CurrentSrb, SrbStatus);

    if (HwDeviceExtension->TransferDataBytes)
    {
        if ((HwDeviceExtension->DeviceFlags[CurrentSrb->TargetId] & 4) || SrbStatus == 0x12)
            CurrentSrb->DataTransferLength -= HwDeviceExtension->TransferDataBytes;
        else
            CurrentSrb->DataTransferLength = 0;
    }

    if (CurrentSrb->Function == 0xC8 || CurrentSrb->Function == 0xC7)
    {
        AtapiTaskRegisterSnapshot(&HwDeviceExtension->CmdBlock, CurrentSrb->DataBuffer);
    }
    else if (HwDeviceExtension->CurrentSrb->Function == 0xC9)
    {
        DPRINT1("AtapiInterrupt: FIXME\n");
        ASSERT(FALSE);
    }

    if (CurrentSrb->Function == 2)
    {
        OutParameters = Add2Ptr(CurrentSrb->DataBuffer, sizeof(SRB_IO_CONTROL));

        if (SrbStatus == 1)
            Error = 0;
        else
            Error = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Error);

        OutParameters->cBufferSize = BytesXferred;
        OutParameters->DriverStatus.bDriverError = ((Error) ? 1 : 0);
        OutParameters->DriverStatus.bIDEError = Error;

        if (HwDeviceExtension->TypeSmartCommand == 0xDA)
        {
            OutParameters->bBuffer[0] = 0xDA;
            OutParameters->bBuffer[1] = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.InterruptReason);
            OutParameters->bBuffer[2] = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.LbaLow);
            OutParameters->bBuffer[3] = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.BytesLow);
            OutParameters->bBuffer[4] = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.BytesHigh);
            OutParameters->bBuffer[5] = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect);
            OutParameters->bBuffer[6] = 0xB0;
            OutParameters->cBufferSize = 8;
        }

        IdePortNotification(0, HwDeviceExtension, CurrentSrb);
    }
    else if (HwDeviceExtension->IsDscRestrictive)
    {
        DPRINT1("AtapiInterrupt: FIXME\n");
        ASSERT(FALSE);
    }
    else if (!HwDeviceExtension->IsDriverMustPoll)
    {
        IdePortNotification(0, HwDeviceExtension, CurrentSrb);
    }

    if (!HwDeviceExtension->IsDscRestrictive)
    {
        HwDeviceExtension->CurrentSrb = 0;

        if (!HwDeviceExtension->IsDriverMustPoll)
            IdePortNotification(1, HwDeviceExtension, 0);
    }
    else
    {
        ASSERT(!HwDeviceExtension->IsDriverMustPoll);
        IdePortNotification(6, HwDeviceExtension, AtapiCallBack, 2000);
    }

    DPRINT("AtapiInterrupt: Result %X\n", Result);
    return Result;
}

BOOLEAN
NTAPI
IdePortInterrupt(
    _In_ PKINTERRUPT Interrupt,
    _In_ PVOID ServiceContext)
{
    PDEVICE_OBJECT Fdo = ServiceContext;
    PFDO_DEVICE_EXTENSION FdoExtension;
    BOOLEAN Result;

    FdoExtension = Fdo->DeviceExtension;

    Result = AtapiInterrupt(FdoExtension->HwDeviceExtension);

    if (FdoExtension->InterruptData.Flags & 4)
        KeInsertQueueDpc(&FdoExtension->SelfDevice->Dpc, NULL, NULL);

    return Result;
}

VOID
NTAPI
AtapiBuildIoAddress(
    _In_ PUCHAR CmdBlockBase,
    _In_ PUCHAR CtrlBlockBase,
    _Out_ IDE_CMD_BLOCK_REGS* BaseIoAddress1,
    _Out_ IDE_CTRL_BLOCK_REGS* BaseIoAddress2,
    _Out_ ULONG* OutBaseIoAddress1Length,
    _Out_ ULONG* OutBaseIoAddress2Length,
    _Out_ ULONG* OutMaxIdeDevice,
    _Out_ ULONG* OutMaxIdeTargetId)
{
    DPRINT("AtapiBuildIoAddress: %p, %p\n", CmdBlockBase, CtrlBlockBase);

    if (BaseIoAddress1)
    {
        BaseIoAddress1->CmdBlockBase = CmdBlockBase;

        BaseIoAddress1->Data = (PUSHORT)CmdBlockBase;
        BaseIoAddress1->Error = (CmdBlockBase + 1);
        BaseIoAddress1->SectorCount = (CmdBlockBase + 2);
        BaseIoAddress1->LbaLow = (CmdBlockBase + 3);
        BaseIoAddress1->LbaMid = (CmdBlockBase + 4);
        BaseIoAddress1->LbaHigh = (CmdBlockBase + 5);
        BaseIoAddress1->DeviceSelect = (CmdBlockBase + 6);
        BaseIoAddress1->Status = (CmdBlockBase + 7);
    }

    if (BaseIoAddress2)
    {
        BaseIoAddress2->CtrlBlockBase = CtrlBlockBase;

        BaseIoAddress2->AltStatus = CtrlBlockBase;
        BaseIoAddress2->Control = (CtrlBlockBase + 1);
    }

    if (OutBaseIoAddress1Length)
        *OutBaseIoAddress1Length = 8;

    if (OutBaseIoAddress2Length)
        *OutBaseIoAddress2Length = 1;

    if (OutMaxIdeDevice)
        *OutMaxIdeDevice = 2;

    if (OutMaxIdeTargetId)
        *OutMaxIdeTargetId = 2;
}

NTSTATUS
NTAPI
DigestResourceList(
    _In_ PIDE_RESOURCE_DATA ResourceData,
    _In_ PCM_RESOURCE_LIST CmResources,
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR* OutInterruptDesc)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR FirstDescriptor;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PCM_FULL_RESOURCE_DESCRIPTOR CmList;
    IDE_CMD_BLOCK_REGS BaseIoAddress1;
    PHYSICAL_ADDRESS Start;
    SIZE_T BaseIoAddress1Length;
    ULONG Length;
    ULONG ix;
    ULONG jx;
    UCHAR Type;
    BOOLEAN IsFoundPrimary = FALSE;
    BOOLEAN IsFoundSecond = FALSE;
    BOOLEAN IsFoundCmdBlockBase = FALSE;
    BOOLEAN IsFoundCtrlBlockBase = FALSE;
    BOOLEAN IsFoundInterrupt = FALSE;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("DigestResourceList: %p\n", CmResources);

    CmList = CmResources->List;

    *OutInterruptDesc = NULL;

    for (ix = 0; ix < CmResources->Count; ix++)
    {
        if (!NT_SUCCESS(Status))
            break;

        CmDescriptor = CmList->PartialResourceList.PartialDescriptors;

        AtapiBuildIoAddress((PUCHAR)CmDescriptor[0].u.Port.Start.LowPart,
                            NULL,
                            &BaseIoAddress1,
                            NULL,
                            &BaseIoAddress1Length,
                            NULL,
                            NULL,
                            NULL);

        FirstDescriptor = CmDescriptor;

        for (jx = 0; jx < CmList->PartialResourceList.Count; jx++)
        {
            if (!NT_SUCCESS(Status))
                break;

            Type = CmDescriptor[jx].Type;
            Start = CmDescriptor[jx].u.Generic.Start;
            Length = CmDescriptor[jx].u.Generic.Length;

            if ((Type == 1 || Type == 3) && Length == BaseIoAddress1Length && !IsFoundCmdBlockBase)
            {
                if (Start.QuadPart == 0x1F0)
                    IsFoundPrimary = TRUE;
                else if (Start.QuadPart == 0x170)
                    IsFoundSecond = TRUE;

                if (Type == 1)
                {
                    ResourceData->CmdBlockBase = Start.LowPart;
                    ResourceData->TypeResForCmdBlock = 1;
                }
                else if (Type == 3)
                {
                    ResourceData->CmdBlockBase = (ULONG)MmMapIoSpace(Start, BaseIoAddress1Length, MmNonCached);
                    ResourceData->TypeResForCmdBlock = 0;
                }
                else
                {
                    ASSERT(FALSE);
                    ResourceData->CmdBlockBase = 0;
                }

                if (ResourceData->CmdBlockBase)
                    IsFoundCmdBlockBase = TRUE;
                else
                    Status = STATUS_INVALID_PARAMETER;
            }
            else if ((Type == 1 || Type == 3) && (Length == 1 || Length == 2 || Length == 4) && !IsFoundCtrlBlockBase)
            {
                if (Length == 4)
                    Start.QuadPart += 2;

                if (Type == 1)
                {
                    ResourceData->CtrlBlockBase = Start.LowPart;
                    ResourceData->TypeResForCtrlBlock = 1;
                }
                else if (Type == 3)
                {
                    ResourceData->CtrlBlockBase = (ULONG)MmMapIoSpace(Start, 1, MmNonCached);
                    ResourceData->TypeResForCtrlBlock = 0;
                }
                else
                {
                    DPRINT1("DigestResourceList: Type %X\n", Type);
                    ASSERT(FALSE);
                    ResourceData->CtrlBlockBase = 0;
                }

                if (ResourceData->CtrlBlockBase)
                    IsFoundCtrlBlockBase = TRUE;
                else
                    Status = STATUS_INVALID_PARAMETER;
            }
            else if (Type == 2 && !IsFoundInterrupt)
            {
                IsFoundInterrupt = TRUE;

                ResourceData->Vector = CmDescriptor[jx].u.Interrupt.Level;
                ResourceData->IntResFlags = (CmDescriptor[jx].Flags & 1);

                *OutInterruptDesc = &CmDescriptor[jx];
            }
            else if ((Type == 1 || Type == 3) && Length >= 0x10 && Length <= 0x20 && !IsFoundCmdBlockBase && !IsFoundCtrlBlockBase)
            {
                if (Type == 1)
                {
                    ResourceData->TypeResForCmdBlock = 1;
                    ResourceData->CmdBlockBase = Start.LowPart;

                    ResourceData->TypeResForCtrlBlock = 1;
                    Start.QuadPart += (Length - 2);
                    ResourceData->CtrlBlockBase = Start.LowPart;
                }
                else if (Type == 3)
                {
                    ResourceData->TypeResForCmdBlock = 0;
                    ResourceData->CmdBlockBase = (ULONG)MmMapIoSpace(Start, BaseIoAddress1Length, MmNonCached);

                    ResourceData->TypeResForCtrlBlock = 0;
                    Start.QuadPart += (Length - 2);
                    ResourceData->CtrlBlockBase = (ULONG)MmMapIoSpace(Start, 1, MmNonCached);
                }
                else
                {
                    DPRINT1("DigestResourceList: Type %X\n", Type);
                    ASSERT(FALSE);

                    ResourceData->CmdBlockBase = 0;
                    ResourceData->CtrlBlockBase = 0;
                }

                if (ResourceData->CmdBlockBase)
                    IsFoundCmdBlockBase = TRUE;
                else
                    Status = STATUS_INVALID_PARAMETER;

                if (ResourceData->CtrlBlockBase)
                    IsFoundCtrlBlockBase = TRUE;
                else
                    Status = STATUS_INVALID_PARAMETER;
            }
        }

        CmList = (PCM_FULL_RESOURCE_DESCRIPTOR)&FirstDescriptor[CmList->PartialResourceList.Count];
    }

    if (IsFoundCmdBlockBase && IsFoundCtrlBlockBase && NT_SUCCESS(Status))
    {
        ResourceData->PrimaryClaimed = IsFoundPrimary;
        ResourceData->SecondaryClaimed = IsFoundSecond;

        return STATUS_SUCCESS;
    }

    DPRINT1("DigestResourceList: pnp manager gave me bad ressources!\n");

    if (IsFoundCmdBlockBase && !ResourceData->TypeResForCmdBlock)
    {
        MmUnmapIoSpace((PVOID)ResourceData->CmdBlockBase, BaseIoAddress1Length);
        ResourceData->CmdBlockBase = 0;
    }

    if (IsFoundCtrlBlockBase && !ResourceData->TypeResForCtrlBlock)
    {
        MmUnmapIoSpace((PVOID)ResourceData->CtrlBlockBase, 1);
        ResourceData->CtrlBlockBase = 0;
    }

    return STATUS_INVALID_PARAMETER;
}

BOOLEAN
NTAPI
IdeGetInterruptState(
    _In_ PVOID Context)
{
    PVOID* SynchronizeContext = Context;
    PATAPI_INTERRUPT_DATA InterruptData = SynchronizeContext[1];
    PFDO_DEVICE_EXTENSION FdoExtension = SynchronizeContext[0];
    PPDO_DEVICE_EXTENSION PdoExtension;
    PSCSI_REQUEST_BLOCK Srb;
    PPDOX_SRB_DATA SrbData;
    ULONG Limit = 0;

    DPRINT("IdeGetInterruptState: %p, %p\n", FdoExtension, SynchronizeContext);

    if (!(FdoExtension->InterruptData.Flags & 4))
    {
        DPRINT("IdeGetInterruptState: return 0\n");
        return FALSE;
    }

    RtlCopyMemory(InterruptData, &FdoExtension->InterruptData, sizeof(*InterruptData));

    FdoExtension->InterruptData.Flags &= 0x4180;
    FdoExtension->InterruptData.CompletedRequests = NULL;
    FdoExtension->InterruptData.CompletedAbort = NULL;
    FdoExtension->InterruptData.PdoExtensionResetBus = NULL;

    for (SrbData = InterruptData->CompletedRequests;
         SrbData;
         SrbData = SrbData->CompletedRequests)
    {
        Limit++;
        ASSERT(Limit++ < 100);

        ASSERT(SrbData->CurrentSrb != NULL);
        Srb = SrbData->CurrentSrb;

        PdoExtension = IoGetCurrentIrpStackLocation(Srb->OriginalRequest)->Parameters.Others.Argument4;

        if (Srb->SrbStatus != 1 &&
            Srb->ScsiStatus == 2 &&
            !(Srb->SrbStatus & 0x80) &&
            Srb->SenseInfoBuffer && Srb->SenseInfoBufferLength)
        {
            if (PdoExtension->PdoFlags & 4)
            {
                Srb->ScsiStatus = 0;
                Srb->SrbStatus = 0x10;
            }
            else
            {
                PdoExtension->PdoFlags |= 4;
            }
        }

        PdoExtension->TimeOut = -1;
    }

    return TRUE;
}

NTSTATUS
NTAPI
IdeTranslateSrbStatus(
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    NTSTATUS Status;

    if ((Srb->SrbStatus & 0x3F) > 0x30)
    {
        DPRINT1("IdeTranslateSrbStatus: STATUS_IO_DEVICE_ERROR\n");
        return STATUS_IO_DEVICE_ERROR;
    }

    if ((Srb->SrbStatus & 0x3F) == 0x30)
    {
        return Srb->InternalStatus;
    }

    switch (Srb->SrbStatus & 0x3F)
    {
        case 8:
        case 0x11:
        case 0x20:
        case 0x21:
            DPRINT1("IdeTranslateSrbStatus: STATUS_DEVICE_DOES_NOT_EXIST\n");
            Status = STATUS_DEVICE_DOES_NOT_EXIST;
            break;

        case 9:
        case 0xB:
        case 0xE:
            DPRINT1("IdeTranslateSrbStatus: STATUS_IO_TIMEOUT\n");
            Status = STATUS_IO_TIMEOUT;
            break;

        case 0xA:
            DPRINT("IdeTranslateSrbStatus: STATUS_DEVICE_NOT_CONNECTED\n");
            Status = STATUS_DEVICE_NOT_CONNECTED;
            break;

        case 6:
        case 0x15:
        case 0x22:
            DPRINT1("IdeTranslateSrbStatus: STATUS_INVALID_DEVICE_REQUEST\n");
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;

        case 0x12:
            DPRINT("IdeTranslateSrbStatus: STATUS_INVALID_DEVICE_REQUEST\n");
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;

        default:
            DPRINT1("IdeTranslateSrbStatus: STATUS_IO_DEVICE_ERROR. SrbStatus (%X)\n", Srb->SrbStatus);
            Status = STATUS_IO_DEVICE_ERROR;
            break;
    }

    return Status;
}

VOID
NTAPI
GetNextLuRequest2(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PCHAR File,
    _In_ ULONG Line)
{
    PKDEVICE_QUEUE_ENTRY Entry;
    PSCSI_REQUEST_BLOCK Srb;
    POWER_STATE State;
    NTSTATUS Status;
    PIRP Irp;
    BOOLEAN RequeueIrp = FALSE;

    DPRINT("GetNextLuRequest2: %p %X\n", FdoExtension->ResourceData.CmdBlockBase, PdoExtension->TargetId);

    //IdeLogGetNextLuCaller(..);

    if ((!(PdoExtension->PdoFlags & 2) && !PdoExtension->PendingRequest) ||
        PdoExtension->PdoxSrbData.CurrentSrb)
    {
        DPRINT("GetNextLuRequest2: %X, %X NOT PD_LOGICAL_UNIT_IS_ACTIVE\n",
               FdoExtension->ResourceData.CmdBlockBase, PdoExtension->TargetId);

        KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);
        return;
    }

    if (PdoExtension->PdoFlags & 0x1D || PdoExtension->PdoState & 0x30)
    {
        DPRINT("GetNextLuRequest2: %X, %X Ignoring a get next lu call.\n",
               FdoExtension->ResourceData.CmdBlockBase, PdoExtension->TargetId);

        KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);
        return;
    }

    PdoExtension->PdoFlags &= ~2;
    PdoExtension->RetriesDoRequest = 0;

    if (PdoExtension->PendingRequest)
    {
        Irp = PdoExtension->PendingRequest;
        PdoExtension->PendingRequest = NULL;
    }
    else
    {
        Entry = KeRemoveByKeyDeviceQueue(&PdoExtension->SelfDevice->DeviceQueue, PdoExtension->SortKey);

        if (Entry)
        {
            Irp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.DeviceQueueEntry);
            InterlockedDecrement(&PdoExtension->ItemsQueued);
        }
        else
        {
            Irp = NULL;
        }
    }

    if (Irp)
    {
        Srb = IoGetCurrentIrpStackLocation(Irp)->Parameters.Scsi.Srb;

        if (PdoExtension->PdoState & 0x1F00)
        {
            DPRINT("GetNextLuRequest2: %X, %X Lu must queue\n", FdoExtension->ResourceData.CmdBlockBase, PdoExtension->TargetId);

            if (!(PdoExtension->PdoState & 0x1E00))
            {
                if (Srb->TimeOutValue < 0x1E)
                    Srb->TimeOutValue = 0x1E;

                RequeueIrp = TRUE;

                DPRINT("GetNextLuRequest2: %X, %X need to spin up device, requeue irp %p\n",
                       FdoExtension->ResourceData.CmdBlockBase, PdoExtension->TargetId, Irp);
            }

            ASSERT(PdoExtension->PendingRequest == NULL);
            PdoExtension->PendingRequest = Irp;

            Irp = NULL;
        }

        if (Irp)
        {
            PdoExtension->SortKey = (Srb->QueueSortKey + 1);
            KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);
            IoStartPacket(FdoExtension->SelfDevice, Irp, NULL, NULL);
            return;
        }
    }
    else
    {
        DPRINT("GetNextLuRequest2: %X, %X no irp to processing\n", FdoExtension->ResourceData.CmdBlockBase, PdoExtension->TargetId);
    }

    KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);

    if (RequeueIrp)
    {
        State.DeviceState = PowerDeviceD0;
        Status = PoRequestPowerIrp(PdoExtension->SelfDevice, 2, State, NULL, NULL, NULL);
        ASSERT(NT_SUCCESS(Status));
    }
}

VOID
NTAPI
GetNextLuPendingRequest(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    if (PdoExtension->PendingRequest)
        GetNextLuRequest2(FdoExtension, PdoExtension, __FILE__, __LINE__);
    else
        KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);
}

NTSTATUS
NTAPI
IdeBuildAndSendIrp(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PREQUEST_SENSE_CONTEXT Ctx,
    _In_ PIO_COMPLETION_ROUTINE CompletionRoutine,
    _In_ PVOID CompletionContext)
{
    LARGE_INTEGER StartingOffset;
    PIO_STACK_LOCATION IoStack;
    PIRP Irp;

    DPRINT("IdeBuildAndSendIrp: %p\n", PdoExtension);

    StartingOffset.QuadPart = 1;

    Irp = IoBuildAsynchronousFsdRequest(IRP_MJ_READ,
                                        PdoExtension->SelfDevice,
                                        Ctx->Srb.DataBuffer,
                                        Ctx->Srb.DataTransferLength,
                                        &StartingOffset,
                                        NULL);
    if (!Irp)
    {
        DPRINT1("IdeBuildAndSendIrp: STATUS_INSUFFICIENT_RESOURCES\n");
        //IdePortLogNoMemoryErrorFn(..);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    IoSetCompletionRoutine(Irp, CompletionRoutine, CompletionContext, TRUE, TRUE, TRUE);

    IoStack = IoGetNextIrpStackLocation(Irp);
    IoStack->MajorFunction = IRP_MJ_SCSI;
    IoStack->Parameters.Scsi.Srb = &Ctx->Srb;

    Ctx->Srb.OriginalRequest = Irp;

    IoCallDriver(PdoExtension->SelfDevice, Irp);

    return STATUS_PENDING;
}

VOID
IdeFreeIrpAndMdl(
    _In_ PIRP Irp)
{
    ASSERT(Irp);

    if (Irp->MdlAddress)
    {
        MmUnlockPages(Irp->MdlAddress);
        IoFreeMdl(Irp->MdlAddress);
        Irp->MdlAddress = NULL;
    }

    IoFreeIrp(Irp);
}

NTSTATUS
NTAPI
IdePortInternalCompletion(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PREQUEST_SENSE_CONTEXT SenseContext = Context;
    PPDO_DEVICE_EXTENSION PdoExtension;
    PSCSI_REQUEST_BLOCK FailingSrb;
    PIO_STACK_LOCATION IoStack;
    PIRP FailingIrp;
    UCHAR SrbStatus;
    KIRQL Irql;

    DPRINT("IdePortInternalCompletion: Enter routine\n");

    if (SenseContext->Srb.Function == 0x10 || SenseContext->Srb.Function == 0x12)
    {
        DPRINT("IdePortInternalCompletion: STATUS_MORE_PROCESSING_REQUIRED\n");
        ExFreePool(SenseContext);
        IoFreeIrp(Irp);
        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    FailingSrb = SenseContext->FailingSrb;
    FailingIrp = FailingSrb->OriginalRequest;

    IoStack = FailingIrp->Tail.Overlay.CurrentStackLocation;
    PdoExtension = IoStack->Parameters.Others.Argument4;

    SrbStatus = (SenseContext->Srb.SrbStatus & 0x3F);

    if (SrbStatus == 1 || SrbStatus == 0x12)
    {
        FailingSrb->SrbStatus |= 0x80;
        FailingSrb->SenseInfoBufferLength = SenseContext->Srb.DataTransferLength;
    }

    KeAcquireSpinLock(&PdoExtension->FdoExtension->SpinLock, &Irql);
    PdoExtension->PdoFlags &= ~4;
    KeReleaseSpinLock(&PdoExtension->FdoExtension->SpinLock, Irql);

    ASSERT(FailingSrb->SrbStatus & 0x40);//SRB_STATUS_QUEUE_FROZEN

    if ((FailingSrb->SrbFlags & 0x100) && (FailingSrb->SrbStatus & 0x40))
    {
        PdoExtension->PdoFlags &= ~1;

        KeAcquireSpinLock(&PdoExtension->FdoExtension->SpinLock, &Irql);
        GetNextLuRequest2(PdoExtension->FdoExtension, PdoExtension, __FILE__, __LINE__);
        KeLowerIrql(Irql);

        FailingSrb->SrbStatus &= ~0x40;
    }

    UnrefLogicalUnitExtension(PdoExtension->FdoExtension, PdoExtension, FailingIrp);

    ExFreePool(SenseContext);
    IdeFreeIrpAndMdl(Irp);

    IoCompleteRequest(FailingIrp, 1);

    DPRINT("IdePortInternalCompletion: ret STATUS_MORE_PROCESSING_REQUIRED\n");
    return STATUS_MORE_PROCESSING_REQUIRED;
}

VOID
NTAPI
IssueRequestSense(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PSCSI_REQUEST_BLOCK FailingSrb)
{
    PPDO_DEVICE_EXTENSION FailingPdoe;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PREQUEST_SENSE_CONTEXT Ctx;
    PIO_STACK_LOCATION IoStack;
    PCDB Cdb;
    KIRQL Irql;
    NTSTATUS Status;

    DPRINT("IssueRequestSense: Enter routine\n");

    IoStack = IoGetCurrentIrpStackLocation(FailingSrb->OriginalRequest);
    FailingPdoe = IoStack->Parameters.Others.Argument4;

    Ctx = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Ctx), 'PedI');
    if (!Ctx)
    {
        DPRINT1("IssueRequestSense: pool allocation failed\n");
        goto ErrorExit;
    }
    RtlZeroMemory(Ctx, sizeof(*Ctx));

    Ctx->FailingSrb = FailingSrb;

    Ctx->Srb.CdbLength = 6;

    Cdb = (PCDB)&Ctx->Srb.Cdb;
    Cdb->CDB6INQUIRY.OperationCode = 3;
    Cdb->CDB6INQUIRY.LogicalUnitNumber = 0;
    Cdb->CDB6INQUIRY.PageCode = 0;
    Cdb->CDB6INQUIRY.IReserved = 0;
    Cdb->CDB6INQUIRY.AllocationLength = FailingSrb->SenseInfoBufferLength;
    Cdb->CDB6INQUIRY.Control = 0;

    Ctx->Srb.TargetId = FailingSrb->TargetId;
    Ctx->Srb.Lun = FailingSrb->Lun;
    Ctx->Srb.PathId = FailingSrb->PathId;

    Ctx->Srb.Function = 0;
    Ctx->Srb.Length = sizeof(Ctx->Srb);
    Ctx->Srb.TimeOutValue = 0x10;

    Ctx->Srb.SenseInfoBufferLength = 0;
    Ctx->Srb.SenseInfoBuffer = NULL;

    if (FailingSrb->SrbFlags & 8)
        Ctx->Srb.SrbFlags = 0x5C;
    else
        Ctx->Srb.SrbFlags = 0x54;

    Ctx->Srb.DataBuffer = FailingSrb->SenseInfoBuffer;
    Ctx->Srb.DataTransferLength = FailingSrb->SenseInfoBufferLength;

    Ctx->Srb.SrbStatus = 0;
    Ctx->Srb.ScsiStatus = 0;

    Ctx->Srb.NextSrb = NULL;

    ASSERT(FailingSrb->OriginalRequest);
    ASSERT(FailingPdoe);

    Status = IdeBuildAndSendIrp(PdoExtension, Ctx, IdePortInternalCompletion, Ctx);
    if (NT_SUCCESS(Status))
        return;

    ASSERT(Status == STATUS_INSUFFICIENT_RESOURCES);
    ExFreePoolWithTag(Ctx, 0);

ErrorExit:

    KeAcquireSpinLock(&FailingPdoe->FdoExtension->SpinLock, &Irql);
    FdoExtension = FailingPdoe->FdoExtension;
    FailingPdoe->PdoFlags &= ~4;
    KeReleaseSpinLock(&FdoExtension->SpinLock, Irql);

    ASSERT(FailingSrb->SrbStatus & 0x40);//SRB_STATUS_QUEUE_FROZEN

    if (FailingSrb->SrbFlags & 0x100)
    {
        if (FailingSrb->SrbStatus & 0x40)
        {
            FailingPdoe->PdoFlags &= ~1;

            KeAcquireSpinLock(&FailingPdoe->FdoExtension->SpinLock, &Irql);
            GetNextLuRequest2(FailingPdoe->FdoExtension, FailingPdoe, __FILE__, __LINE__);
            KeLowerIrql(Irql);

            FailingSrb->SrbStatus &= ~0x40;
        }
    }

    UnrefLogicalUnitExtension(FailingPdoe->FdoExtension, FailingPdoe, FailingSrb->OriginalRequest);

    IoCompleteRequest(FailingSrb->OriginalRequest, 1);
    return;
}

VOID
NTAPI
IdeProcessCompletedRequest(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDOX_SRB_DATA SrbData,
    _Out_ BOOLEAN* OutIsStartNextIo)
{
    PATA_DEVICE_EXTENSION HwDeviceExtension = FdoExtension->HwDeviceExtension;
    ATAPI_RESET_BUS_CONTEXT ResetContext;
    PPDO_DEVICE_EXTENSION PdoExtension;
    PSCSI_REQUEST_BLOCK Srb = SrbData->CurrentSrb;
    PIRP Irp = Srb->OriginalRequest;
    ULONG TimeoutErrors;
    ULONG ErrorCount;

    ASSERT(SrbData->CurrentSrb);

    if (Irp->CurrentLocation > (CHAR)(Irp->StackCount + 1))
    {
        DPRINT1("IdeProcessCompletedRequest: %p, %p, %p, %X\n",
                Srb->OriginalRequest, Srb, Srb->DataBuffer, Srb->DataTransferLength);

        KeBugCheckEx(0x44, (ULONG_PTR)Irp, (ULONG_PTR)Srb, 0, 0);
    }

    PdoExtension = (PPDO_DEVICE_EXTENSION)IoGetCurrentIrpStackLocation(Irp)->Parameters.Others.Argument4;

    DPRINT("IdeProcessCompletedRequest: %p, %p, %p, %X (%X)\n",
           Srb->OriginalRequest, Srb, Srb->DataBuffer, Srb->DataTransferLength, PdoExtension->TimeOut);

    if ((Srb->SrbFlags & 0xC0) && !((ULONG_PTR)Srb->SrbExtension & 2) && Irp->MdlAddress)
    {
        Srb->DataBuffer = Add2Ptr(Srb->DataBuffer,
                                  ((ULONG_PTR)MmGetMdlVirtualAddress(Irp->MdlAddress) - (ULONG_PTR)SrbData->Buffer));

        if (SrbData->Flags & 0x100)
        {
            UNIMPLEMENTED_DBGBREAK();
        }
    }

    //IdeLogCompletedCommand(..);

    SrbData->CurrentSrb = NULL;

    if (Srb->SrbFlags & 4)
    {
        KeAcquireSpinLockAtDpcLevel(&FdoExtension->SpinLock);

        FdoExtension->Flags |= 0x1000;

        if (!(FdoExtension->InterruptData.Flags & 0x80))
            FdoExtension->TimeOutValue = -1;

        KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);

        if (!(FdoExtension->Flags & 1) && !(*OutIsStartNextIo) && !(FdoExtension->Flags & 0x800))
            IoStartNextPacket(FdoExtension->SelfDevice, FALSE);
    }

    if (Srb->SrbFlags & 0x40000)
        Srb->SrbFlags &= ~0x40000;

    KeAcquireSpinLockAtDpcLevel(&FdoExtension->SpinLock);

    Irp->IoStatus.Information = Srb->DataTransferLength;

    SrbData->SequenceNumber = 0;
    SrbData->RetryCount = 0;

    if (FdoExtension->Flags & 0x800)
    {
        FdoExtension->Flags &= ~0x800;
        *OutIsStartNextIo = TRUE;
    }

    if ((Srb->SrbStatus & 0x3F) == 1)
    {
        Irp->IoStatus.Status = STATUS_SUCCESS;

        if (Srb->Function == 0xC7)
        {
            KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);
            UnrefLogicalUnitExtension(FdoExtension, PdoExtension, Irp);
            IoCompleteRequest(Irp, 1);
            Irp = NULL;
            KeAcquireSpinLockAtDpcLevel(&FdoExtension->SpinLock);

            GetNextLuRequest2(FdoExtension, PdoExtension, __FILE__, __LINE__);
        }
        else if (Srb->SrbFlags & 0x10 || PdoExtension->TimeOut != -1)
        {
            KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);
        }
        else
        {
            GetNextLuRequest2(FdoExtension, PdoExtension, __FILE__, __LINE__);
        }

        if (Irp)
        {
            if (FdoExtension->ResetErrorCountersOnSuccess)
            {
                UNIMPLEMENTED_DBGBREAK();
            }

            UnrefLogicalUnitExtension(FdoExtension, PdoExtension, Irp);
            IoCompleteRequest(Irp, 1);
        }

        return;
    }

    Irp->IoStatus.Status = IdeTranslateSrbStatus(Srb);

    if (FdoExtension->ResetErrorCountersOnSuccess)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    if (Srb->SrbStatus == 9 || Srb->SrbStatus == 14)
    {
        if ((ULONG_PTR)Srb->SrbExtension & 2)
        {
            DPRINT("IdeProcessCompletedRequest: retrying dma Srb %p with pio\n", Srb);

            ASSERT(!(((ULONG_PTR)Srb->SrbExtension) & ~7));
            Srb->SrbExtension = (PVOID)((ULONG_PTR)Srb->SrbExtension | 1);

            Srb->SrbStatus = 0;
            Srb->ScsiStatus = 0;

            if ((Srb->SrbFlags & 0x10) == 0)
            {
                KeInsertByKeyDeviceQueue(&PdoExtension->SelfDevice->DeviceQueue,
                                         &Irp->Tail.Overlay.DeviceQueueEntry,
                                         Srb->QueueSortKey);

                GetNextLuRequest2(FdoExtension, PdoExtension, __FILE__, __LINE__);
            }
            else
            {
                KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);
                IoStartPacket(FdoExtension->SelfDevice, Irp, NULL, NULL);
            }

            if (InterlockedIncrement(&PdoExtension->DmaTimeouts) == 6)
            {
                //IdeLogError(..);

                if (!(PdoExtension->PdoFlags & 0x8000))
                    IoInvalidateDeviceRelations(FdoExtension->LowPdo, 0);
            }

            return;
        }

        if (!TestForEnumProbing(Srb))
        {
            if (Srb->Function != 0xC7 && Srb->Function != 0xC9 && Srb->Function != 0xC8)
            {
                if (Srb->Function == 8 || Srb->Function == 7 || Srb->Cdb[0] == 0x35)
                {
                    ErrorCount = InterlockedIncrement(&PdoExtension->FlushCacheTimeouts);
                    DPRINT("IdeProcessCompletedRequest: FlushCacheTimeout incremented to %X\n", ErrorCount);

                    if ((ULONG)ErrorCount >= 3)
                    {
                        HwDeviceExtension->DeviceParameters[Srb->TargetId].IdePioFlushCommand = -1;
                        HwDeviceExtension->DeviceParameters[Srb->TargetId].IdePioFlushCommandExt = -1;

                        ASSERT(ErrorCount <= 3);//PDO_FLUSH_TIMEOUT_LIMIT
                    }

                    Srb->SrbStatus = 1;
                    Irp->IoStatus.Status = 0;
                }
                else
                {
                    TimeoutErrors = InterlockedIncrement(&PdoExtension->TimeoutErrors);

                    DPRINT("IdeProcessCompletedRequest: %X target %X has %X timeout errors so far\n",
                           PdoExtension->FdoExtension->ResourceData.CmdBlockBase, PdoExtension->TargetId, TimeoutErrors);

                    if (TimeoutErrors == 3 && !(PdoExtension->PdoFlags & 0x8000))
                        IoInvalidateDeviceRelations(FdoExtension->LowPdo, 0);

                    if (TimeoutErrors >= (PdoExtension->Paging != 0 ? 20 : 6))
                    {
                        DPRINT("IdeProcessCompletedRequest: %X target %X has too many timeout. it is a goner...\n",
                               PdoExtension->FdoExtension->ResourceData.CmdBlockBase, PdoExtension->TargetId);

                        //IdeLogError(..);

                        KeAcquireSpinLockAtDpcLevel(&PdoExtension->PdoLock);
                        PdoExtension->PdoState |= 0x40;
                        KeReleaseSpinLockFromDpcLevel(&PdoExtension->PdoLock);

                        if (!(PdoExtension->PdoFlags & 0x8000))
                            IoInvalidateDeviceRelations(FdoExtension->LowPdo, 0);
                    }
                }
            }
        }
    }
    else
    {
        InterlockedExchange(&PdoExtension->TimeoutErrors, 0);
    }

    if ((Srb->SrbStatus & 0x3F) == 0xF && InterlockedIncrement(&PdoExtension->CrcErrors) == 6)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    if ((Srb->ScsiStatus == 8 || Srb->SrbStatus == 5 || Srb->ScsiStatus == 0x28) && !(Srb->SrbFlags & 0x10))
    {
        DPRINT("IdeProcessCompletedRequest: Busy SRB status %X, SCSI status %X)\n", Srb->SrbStatus, Srb->ScsiStatus);

        if (PdoExtension->PdoFlags & 9)
        {
            DPRINT("IdeProcessCompletedRequest: Requeuing busy request\n");

            Srb->SrbStatus = 0;
            Srb->ScsiStatus = 0;

            if (KeInsertByKeyDeviceQueue(&PdoExtension->SelfDevice->DeviceQueue,
                                         &Irp->Tail.Overlay.DeviceQueueEntry,
                                         Srb->QueueSortKey))
            {
                KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);
                return;
            }

            Srb->SrbStatus = 4;
            Srb->ScsiStatus = 8;

            ASSERT(FALSE);
        }
        else if (PdoExtension->RetriesDoRequest++ < 0x14)
        {
            Srb->SrbStatus = 0;
            Srb->ScsiStatus = 0;

            PdoExtension->PdoFlags |= 8;
            PdoExtension->BusyRequest = Irp;

            if (PdoExtension->RetriesDoRequest == 0xA)
            {
                DPRINT("IdeProcessCompletedRequest: PDO %p %X seems to be DEAD. Try a reset to bring it back.\n",
                       PdoExtension, PdoExtension->FdoExtension->ResourceData.CmdBlockBase);

                ResetContext.Srb = NULL;
                ResetContext.PathId = Srb->PathId;
                ResetContext.FdoExtension = FdoExtension;
                ResetContext.IsUpdateResetSrb = TRUE;

                KeSynchronizeExecution(FdoExtension->InterruptObject, IdeResetBusSynchronized, &ResetContext);

                //IdeDebugHungControllerCounter = 0;
            }

            KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);
            return;
        }

        if (!(Srb->SrbFlags & 0x100))
        {
            Srb->SrbStatus |= 0x40;
            PdoExtension->PdoFlags |= 1;
        }

        if (Srb->SrbFlags & 0x10 || PdoExtension->TimeOut != -1)
            KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);
        else
            GetNextLuRequest2(FdoExtension, PdoExtension, __FILE__, __LINE__);

        if (!TestForEnumProbing(Srb))
        {
            UNIMPLEMENTED_DBGBREAK();
            //IdeLogError(..);
        }

        Irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
        UnrefLogicalUnitExtension(FdoExtension, PdoExtension, Irp);

        IoCompleteRequest(Irp, 1);
        return;
    }

    if (Srb->ScsiStatus != 2 || (Srb->SrbStatus & 0x80) || !Srb->SenseInfoBuffer || !Srb->SenseInfoBufferLength)
    {
        if (Srb->SrbFlags & 0x100)
        {
            if (PdoExtension->TimeOut == -1)
                GetNextLuRequest2(FdoExtension, PdoExtension, __FILE__, __LINE__);
            else
                KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);

            UnrefLogicalUnitExtension(FdoExtension, PdoExtension, Irp);
            IoCompleteRequest(Irp, 1);
            return;
        }

        Srb->SrbStatus |= 0x40;
        PdoExtension->PdoFlags |= 1;
    }

    if (Srb->ScsiStatus != 2)
    {
        KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);
    }
    else if ((Srb->SrbStatus & 0x80) || !Srb->SenseInfoBuffer || !Srb->SenseInfoBufferLength)
    {
        KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);
    }
    else
    {
        Srb->SrbStatus = Srb->SrbStatus | 0x40;
        PdoExtension->PdoFlags |= 1;

        if (!(PdoExtension->PdoFlags & 8))
        {
            KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);
            IssueRequestSense(PdoExtension, Srb);
            return;
        }

        DPRINT("IdeProcessCompletedRequest: Requeueing busy request to allow request sense.\n");

        if (KeInsertByKeyDeviceQueue(&PdoExtension->SelfDevice->DeviceQueue,
                                     &PdoExtension->BusyRequest->Tail.Overlay.DeviceQueueEntry,
                                     Srb->QueueSortKey))
        {
            UNIMPLEMENTED_DBGBREAK();
            return;
        }

        ASSERT(FALSE);
        KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);
    }

    UnrefLogicalUnitExtension(FdoExtension, PdoExtension, Irp);
    IoCompleteRequest(Irp, 1);
}

VOID
NTAPI
IdePortCompletionDpc(
    _In_ PKDPC Dpc,
    _In_ PVOID DeferredContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2)
{
    PDEVICE_OBJECT Fdo = DeferredContext;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    PPDO_DEVICE_EXTENSION Pdox;
    PVOID SynchronizeContext[2];
    PPDOX_SRB_DATA SrbData;
    PIRP Irp;
    ATAPI_INTERRUPT_DATA InterruptData;
    ATAPI_RESET_BUS_CONTEXT ResetContext;
    ATA_SCSI_ADDRESS ScsiAddress;
    LARGE_INTEGER DueTime;
    POWER_STATE State;
    BOOLEAN IsStartNextIo = FALSE;
    BOOLEAN IsDeadmeat;
    VOID (NTAPI* FreeAccessToken)(PVOID Context);
    VOID (NTAPI* BmFlush)(PVOID Context);

    DPRINT("IdePortCompletionDpc: %p\n", Fdo);

    FdoExtension = Fdo->DeviceExtension;

    KeAcquireSpinLockAtDpcLevel(&FdoExtension->SpinLock);

    SynchronizeContext[1] = &InterruptData;
    SynchronizeContext[0] = FdoExtension;

    if (!KeSynchronizeExecution(FdoExtension->InterruptObject, IdeGetInterruptState, SynchronizeContext))
    {
        KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);
        return;
    }

    if (InterruptData.CompletedRequests)
    {
        SrbData = InterruptData.CompletedRequests;
        ASSERT(SrbData->CurrentSrb);

        if (SrbData->CurrentSrb->SrbFlags & 0xC0 &&
            ((ULONG_PTR)SrbData->CurrentSrb->SrbExtension & 2))//SRB_USES_DMA(Srb)
        {
            BmFlush = FdoExtension->HwDeviceExtension->BusMasterInterface.BmFlush;
            BmFlush(FdoExtension->HwDeviceExtension->BusMasterInterface.Context);
        }
    }

    if (InterruptData.Flags & 0x20000)
    {
        ScsiAddress.AsULONG = 0;
        IsDeadmeat = FALSE;

        for (PdoExtension = NextLogUnitExtension(FdoExtension, &ScsiAddress, 1, IdePortCompletionDpc);
             PdoExtension;
             PdoExtension = NextLogUnitExtension(FdoExtension, &ScsiAddress, 1, IdePortCompletionDpc))
        {
            KeAcquireSpinLockAtDpcLevel(&PdoExtension->PdoLock);

            PdoExtension->PdoState |= 0x40;

            if (PdoExtension->PdoFlags & 0x8000)
                IsDeadmeat = TRUE;

            KeReleaseSpinLockFromDpcLevel(&PdoExtension->PdoLock);

            UnrefPdo(PdoExtension, IdePortCompletionDpc);
        }

        if (IsDeadmeat)
        {
            DPRINT1("The device marked deadmeat during enumeration\n");
        }
        else
        {
            IoInvalidateDeviceRelations(FdoExtension->LowPdo, 0);
        }
    }

    if (InterruptData.Flags & 0x10000)
    {
        FdoExtension->TimerCallBack = InterruptData.HwTimerCallBack;

        if (InterruptData.MiniportTimerValue)
        {
            DueTime.QuadPart = (-10 * InterruptData.MiniportTimerValue);
            KeSetTimer(&FdoExtension->Timer, DueTime, &FdoExtension->Dpc);
        }
        else
        {
            KeCancelTimer(&FdoExtension->Timer);
        }
    }

    if (InterruptData.Flags & 0x40000)
    {
        InterruptData.Flags &= ~0x40000;

        ResetContext.FdoExtension = FdoExtension;
        ResetContext.PathId = 0;
        ResetContext.IsUpdateResetSrb = TRUE;
        ResetContext.Srb = NULL;

        if (!KeSynchronizeExecution(FdoExtension->InterruptObject, IdeResetBusSynchronized, &ResetContext))
        {
            DPRINT1("IdePortCompletionDpc: Reset failed\n");
        }
    }

    if (InterruptData.Flags & 8)
    {
        if ((FdoExtension->Flags & 0x1001) != 0x1001)
        {
            FdoExtension->Flags &= ~1;
            InterruptData.Flags &= ~8;
        }
        else
        {
            FdoExtension->Flags &= ~1;

            if (!(InterruptData.Flags & 0x80))
                FdoExtension->TimeOutValue = -1;
        }
    }

    KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);

    if (InterruptData.CompletedRequests && FdoExtension->SyncAccessInterface.FreeAccessToken)
    {
        FreeAccessToken = FdoExtension->SyncAccessInterface.FreeAccessToken;
        FreeAccessToken(FdoExtension->SyncAccessInterface.Context);
    }

    if (InterruptData.Flags & 8)
        IoStartNextPacket(FdoExtension->SelfDevice, FALSE);

    if (InterruptData.Flags & 0x40)
    {
        DPRINT1("IdePortCompletionDpc: FIXME LogErrorEntry()\n");
        ASSERT(FALSE);
        //LogErrorEntry(..);
    }

    while (InterruptData.CompletedRequests)
    {
        SrbData = InterruptData.CompletedRequests;

        InterruptData.CompletedRequests = SrbData->CompletedRequests;
        SrbData->CompletedRequests = NULL;

        ASSERT(InterruptData.CompletedRequests == NULL);

        //IdeLogStopCommandLog(..);

        IdeProcessCompletedRequest(FdoExtension, SrbData, &IsStartNextIo);
    }

    while (InterruptData.CompletedAbort)
    {
        Pdox = InterruptData.CompletedAbort;
        InterruptData.CompletedAbort = InterruptData.CompletedAbort->CompletedAbort;

        KeAcquireSpinLockAtDpcLevel(&FdoExtension->SpinLock);

        Irp = Pdox->AbortSrb->OriginalRequest;

        if ((Pdox->AbortSrb->SrbStatus & 0x3F) == 1)
            Irp->IoStatus.Status = STATUS_SUCCESS;
        else
            Irp->IoStatus.Status = IdeTranslateSrbStatus(Pdox->AbortSrb);

        Irp->IoStatus.Information = 0;

        Pdox->AbortSrb = NULL;
        KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);

        UnrefLogicalUnitExtension(FdoExtension, (PPDO_DEVICE_EXTENSION)IoGetCurrentIrpStackLocation(Irp)->Parameters.Others.Argument4, Irp);
        IoCompleteRequest(Irp, 1);
    }

    if (IsStartNextIo)
    {
        ASSERT(Fdo->CurrentIrp != NULL);
        IdePortStartIo(Fdo, Fdo->CurrentIrp);
    }

    if (InterruptData.Flags & 0x200)
    {
        ScsiAddress.AsULONG = 0;

        while (TRUE)
        {
            PdoExtension = NextLogUnitExtension(FdoExtension, &ScsiAddress, FALSE, IdePortCompletionDpc);
            if (!PdoExtension)
                break;

            State.DeviceState = PowerDeviceD0;

            if (PdoExtension != InterruptData.PdoExtensionResetBus &&
                !(PdoExtension->PdoFlags & 0x8000))
            {
                PoRequestPowerIrp(PdoExtension->SelfDevice, 2, State, NULL, NULL, NULL);
            }

            UnrefLogicalUnitExtension(FdoExtension, PdoExtension, IdePortCompletionDpc);
        }
    }

    DPRINT("IdePortCompletionDpc: exit (%p)\n", Fdo);
}

BOOLEAN
NTAPI
AtapiRestartBusyRequest(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    PIRP BusyRequest;

    if (!(PdoExtension->PdoFlags & 8))
    {
        return FALSE;
    }

    if (PdoExtension->PdoFlags & 5)
        return TRUE;

    DPRINT("AtapiRestartBusyRequest: Retrying busy status request\n");

    PdoExtension->PdoFlags &= ~0x18;

    BusyRequest = PdoExtension->BusyRequest;
    PdoExtension->BusyRequest = NULL;

    if (PdoExtension->PdoState & 0x30)
    {
        IoGetCurrentIrpStackLocation(BusyRequest)->Parameters.Scsi.Srb->SrbStatus = 8;
        BusyRequest->IoStatus.Status = STATUS_NO_SUCH_DEVICE;

        UnrefLogicalUnitExtension(FdoExtension, PdoExtension, BusyRequest);

        IoCompleteRequest(BusyRequest, 0);
    }
    else
    {
        KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);
        IoStartPacket(FdoExtension->SelfDevice, BusyRequest, NULL, NULL);
        KeAcquireSpinLockAtDpcLevel(&FdoExtension->SpinLock);
    }

    return TRUE;
}

BOOLEAN
NTAPI
IdeTimeoutSynchronized(
   _In_ PVOID SynchronizeContext)
{
    PDEVICE_OBJECT Fdo = SynchronizeContext;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PATA_DEVICE_EXTENSION HwDeviceExtension;
    BOOLEAN IsLock = FALSE;
    BOOLEAN ProbeResult = FALSE;

    FdoExtension = Fdo->DeviceExtension;

    DPRINT("IdeTimeoutSynchronized: Enter routine (%X)\n", FdoExtension->ResetCallAgain);

    FdoExtension->TimeOutValue = -1;

    if (FdoExtension->InterruptData.Flags & 0x80)
    {
        FdoExtension->InterruptData.Flags &= ~0x80;

        if (FdoExtension->InterruptData.Flags & 0x100)
        {
            FdoExtension->InterruptData.Flags &= ~0x100;
            IdeStartIoSynchronized(Fdo);
        }

        return FALSE;
    }

    HwDeviceExtension = FdoExtension->HwDeviceExtension;

    if (!HwDeviceExtension->CurrentSrb)
    {
        DPRINT("IdeTimeoutSynchronized: (%p) Next request timed out. Resetting bus.. currentSrb %p\n",
               Fdo, FdoExtension->HwDeviceExtension->CurrentSrb);
    }
    else
    {
        ++HwDeviceExtension->TimeOutLock[HwDeviceExtension->CurrentSrb->TargetId];

        if (HwDeviceExtension->TimeOutLock[HwDeviceExtension->CurrentSrb->TargetId] == 1)
            IsLock = TRUE;

        ProbeResult = TestForEnumProbing(HwDeviceExtension->CurrentSrb);
        if (!ProbeResult)
        {
            DPRINT("IdeTimeoutSynchronized: (%p) Next request timed out. Resetting bus.. currentSrb %p\n",
                   Fdo, FdoExtension->HwDeviceExtension->CurrentSrb);
        }
    }

    ASSERT(FdoExtension->ResetSrb == NULL);
    FdoExtension->ResetSrb = NULL;

    FdoExtension->ResetCallAgain = 0;

    AtapiResetController(FdoExtension->HwDeviceExtension, &FdoExtension->ResetCallAgain);

    if (ProbeResult)
    {
        ASSERT(FdoExtension->ResetCallAgain == 0);
    }
    else if (FdoExtension->ResetCallAgain)
    {
        FdoExtension->InterruptData.Flags |= 0x80;
        FdoExtension->TimeOutValue = 1;
    }

    if (FdoExtension->InterruptData.Flags & 4)
    {
        DPRINT("IdeTimeoutSynchronized: KeInsertQueueDpc()\n");
        KeInsertQueueDpc(&FdoExtension->SelfDevice->Dpc, NULL, NULL);
    }

    if (ProbeResult || IsLock)
    {
        DPRINT("IdeTimeoutSynchronized: ret FALSE\n");
        return FALSE;
    }

    DPRINT("IdeTimeoutSynchronized: ret TRUE\n");
    return TRUE;
}

VOID
NTAPI
IdePortTickHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PVOID Context)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    ATAPI_RESET_BUS_CONTEXT ResetContext;
    ATA_SCSI_ADDRESS ScsiAddress;

    DPRINT("IdePortTickHandler: %p\n", DeviceObject);

    FdoExtension = DeviceObject->DeviceExtension;

#if 0
    if (IdeDebugRescanBusFreq)
    {
        ..
    }
#endif

    KeAcquireSpinLockAtDpcLevel(&FdoExtension->SpinLock);

    if (FdoExtension->HwDeviceExtension->EmptyWaitCount)
    {
        UNIMPLEMENTED_DBGBREAK();
    }
    else if (FdoExtension->ResetCallAgain)
    {
        UNIMPLEMENTED_DBGBREAK();
    }
    else if (FdoExtension->TimeOutValue <= 0)
    {
        ScsiAddress.AsULONG = 0;

        while (TRUE)
        {
            PdoExtension = NextLogUnitExtension(FdoExtension, &ScsiAddress, TRUE, IdePortTickHandler);
            if (!PdoExtension)
                break;

            if (!AtapiRestartBusyRequest(FdoExtension, PdoExtension))
            {
                if (PdoExtension->TimeOut)
                {
                    if (PdoExtension->TimeOut > 0)
                        PdoExtension->TimeOut--;
                }
                else
                {
                    DPRINT("IdePortTickHandler: Request timed out\n");

                    PdoExtension->TimeOut = -1;

                    ResetContext.FdoExtension = FdoExtension;
                    ResetContext.PathId = PdoExtension->PathId;
                    ResetContext.IsUpdateResetSrb = TRUE;
                    ResetContext.Srb = NULL;

                    if (FdoExtension->InterruptObject)
                    {
                        if (KeSynchronizeExecution(FdoExtension->InterruptObject, IdeResetBusSynchronized, &ResetContext))
                        {
                            ;//IdeLogResetError(..);
                        }
                        else
                        {
                            DPRINT1("IdePortTickHanlder: Reset failed\n");
                        }
                    }
                }
            }

            UnrefLogicalUnitExtension(FdoExtension, PdoExtension, IdePortTickHandler);
        }
    }
    else
    {
        FdoExtension->TimeOutValue--;

        if (!FdoExtension->TimeOutValue)
        {
            if (FdoExtension->InterruptObject)
            {
                if (KeSynchronizeExecution(FdoExtension->InterruptObject, IdeTimeoutSynchronized, FdoExtension->SelfDevice))
                {
                    if (FdoExtension->SelfDevice->CurrentIrp)
                    {
                        UNIMPLEMENTED_DBGBREAK();
                    }
                }
            }
            else
            {
                UNIMPLEMENTED_DBGBREAK();
            }
        }

        ScsiAddress.AsULONG = 0;

        while (TRUE)
        {
            PdoExtension = NextLogUnitExtension(FdoExtension, &ScsiAddress, TRUE, IdePortTickHandler);
            if (!PdoExtension)
                break;

            AtapiRestartBusyRequest(FdoExtension, PdoExtension);
            UnrefLogicalUnitExtension(FdoExtension, PdoExtension, IdePortTickHandler);
        }
    }

    KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);

    DPRINT("IdePortTickHandler: exit\n");
}

VOID
NTAPI
IdeMiniPortTimerDpc(
    _In_ PKDPC Dpc,
    _In_ PVOID DeferredContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2)
{
    PDEVICE_OBJECT Fdo = DeferredContext;
    PFDO_DEVICE_EXTENSION FdoExtension;

    FdoExtension = Fdo->DeviceExtension;

    KeAcquireSpinLockAtDpcLevel(&FdoExtension->SpinLock);

    if (FdoExtension->TimerCallBack)
    {
        KeSynchronizeExecution(FdoExtension->InterruptObject,
                               (PKSYNCHRONIZE_ROUTINE)FdoExtension->TimerCallBack,
                               FdoExtension->HwDeviceExtension);
    }

    KeReleaseSpinLockFromDpcLevel(&FdoExtension->SpinLock);

    if (FdoExtension->InterruptData.Flags & 4)
        IdePortCompletionDpc(NULL, FdoExtension->SelfDevice, NULL, NULL);
}

NTSTATUS
NTAPI
IdePortGetDeviceParameter(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PWCHAR Name,
    _In_ ULONG* OutParameter)
{
    NTSTATUS Status;
    RTL_QUERY_REGISTRY_TABLE QueryTable[2];
    HANDLE DevInstRegKey;
    ULONG OldParameter;

    PAGED_CODE();
    DPRINT("IdePortGetDeviceParameter: %p, '%S'\n", FdoExtension, Name);

    Status = IoOpenDeviceRegistryKey(FdoExtension->LowPdo, PLUGPLAY_REGKEY_DRIVER, KEY_READ, &DevInstRegKey);
    if (!NT_SUCCESS(Status))
    {
        if (Status != STATUS_OBJECT_NAME_NOT_FOUND)
        {
            DPRINT1("IdePortGetDeviceParameter: Status %X\n", Status);
        }
        else
        {
            DPRINT("IdePortGetDeviceParameter: Status %X\n", Status);
        }

        return Status;
    }

    RtlZeroMemory(QueryTable, sizeof(QueryTable));

    OldParameter = *OutParameter;

    QueryTable[0].Name = Name;
    QueryTable[0].DefaultType = 4;
    QueryTable[0].DefaultLength = 4;
    QueryTable[0].Flags = 0x24;
    QueryTable[0].EntryContext = OutParameter;
    QueryTable[0].DefaultData = &OldParameter;

    Status = RtlQueryRegistryValues(RTL_REGISTRY_HANDLE, DevInstRegKey, QueryTable, NULL, NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IdePortGetDeviceParameter: Status %X\n", Status);
        *OutParameter = OldParameter;
    }

    ZwClose(DevInstRegKey);

    return Status;
}

VOID
NTAPI
IdePortInitFdo(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    ULONG ix;

    DPRINT("IdePortInitFdo: %p\n", FdoExtension);

    FdoExtension->HwDeviceExtension = &FdoExtension->AtaExt;
    FdoExtension->SelfDevice->Flags |= 0x10;
    FdoExtension->MaxPdoCount = 8;
    FdoExtension->TimeOutValue = -1;

    KeInitializeSpinLock(&FdoExtension->SpinLock);
    KeInitializeSpinLock(&FdoExtension->PdoArrayLock);

    KeInitializeDpc(&FdoExtension->SelfDevice->Dpc, IdePortCompletionDpc, FdoExtension->SelfDevice);
    IoInitializeTimer(FdoExtension->SelfDevice, IdePortTickHandler, NULL);
    KeInitializeTimer(&FdoExtension->Timer);
    KeInitializeDpc(&FdoExtension->Dpc, IdeMiniPortTimerDpc, FdoExtension->SelfDevice);
    IoStartTimer(FdoExtension->SelfDevice);

    FdoExtension->Flags |= 0x1000;

    if (FdoExtension->InterruptData.Flags & 0x40)
    {
        DPRINT1("IdePortInitFdo: FIXME\n");
        ASSERT(FALSE);
    }

    FdoExtension->IoScsicapabilities.Length = 0x18;

    if (FdoExtension->IsBmIfaceReceived)
    {
        if (FdoExtension->HwDeviceExtension->BusMasterInterface.MaximumPhysicalSize >= 0x20000)
            FdoExtension->IoScsicapabilities.MaximumTransferLength = 0x20000;
        else
            FdoExtension->IoScsicapabilities.MaximumTransferLength = FdoExtension->HwDeviceExtension->BusMasterInterface.MaximumPhysicalSize;
    }
    else
    {
        FdoExtension->IoScsicapabilities.MaximumTransferLength = 0x20000;
    }

    FdoExtension->IoScsicapabilities.TaggedQueuing = 0;
    FdoExtension->IoScsicapabilities.AdapterScansDown = 0;
    FdoExtension->IoScsicapabilities.AlignmentMask = FdoExtension->SelfDevice->AlignmentRequirement;
    FdoExtension->IoScsicapabilities.MaximumPhysicalPages = BYTES_TO_PAGES(FdoExtension->IoScsicapabilities.MaximumTransferLength);

    if (FdoExtension->ResourceData.CmdBlockBase)
    {
        DPRINT("IdePortInitFdo: Translated IO Base address %x\n", FdoExtension->ResourceData.CmdBlockBase);
    }

    for (ix = 0; ix < 4; ix++)
    {
        FdoExtension->DeviceParameter[ix] = 0;
        IdePortGetDeviceParameter(FdoExtension, UserDeviceString[ix], &FdoExtension->DeviceParameter[ix]);
    }

    for (ix = 0; ix < 2; ix++)
    {
        FdoExtension->TimingBlock0.Drive[ix].PioSpeed = 0xFFFFFFFF;
        FdoExtension->TimingBlock0.Drive[ix].DmaSpeed = 0xFFFFFFFF;
    }

    FdoExtension->DmaDetectionLevel = 1;
    IdePortGetDeviceParameter(FdoExtension, L"DmaDetectionLevel", &FdoExtension->DmaDetectionLevel);

    DPRINT("IdePortInitFdo: FIXME ChannelQueryPcmciaParent()\n");
    FdoExtension->PcmciaIdeHasSlaveDevice = 1;

    FdoExtension->ResetErrorCountersOnSuccess = 0;
    IdePortGetDeviceParameter(FdoExtension, L"ResetErrorCountersOnSuccess", &FdoExtension->ResetErrorCountersOnSuccess);
}

BOOLEAN
NTAPI
IdePreAllocEnumStructs(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    PATAPI_PRE_ALLOC_ENUM_STRUCT enumStruct;

    PAGED_CODE();
    DPRINT("IdePreAllocEnumStructs: %p\n", FdoExtension);

    ASSERT(InterlockedCompareExchange(&(FdoExtension->EnumStructLock), 1, 0) == 0);

    if (FdoExtension->PreAllocEnumStruct)
    {
        ASSERT(InterlockedCompareExchange(&(FdoExtension->EnumStructLock), 0, 1) == 1);
        return TRUE;
    }

    enumStruct = ExAllocatePoolWithTag(NonPagedPool, sizeof(*enumStruct), 'PedI');
    if (!enumStruct)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        ASSERT(InterlockedCompareExchange(&(FdoExtension->EnumStructLock), 0, 1) == 1);
        ASSERT(FdoExtension->EnumStructLock == 0);
    }
    RtlZeroMemory(enumStruct, sizeof(*enumStruct));

    enumStruct->AtaPassThrContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(*enumStruct->AtaPassThrContext), 'PedI');
    if (!enumStruct->AtaPassThrContext)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        goto ErrorExit;
    }

    ASSERT(enumStruct->EnumWorkItemContext == NULL);

    enumStruct->EnumWorkItemContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(*enumStruct->EnumWorkItemContext), 'PedI');
    if (!enumStruct->EnumWorkItemContext)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        goto ErrorExit;
    }

    enumStruct->EnumWorkItemContext->WorkItem = IoAllocateWorkItem(FdoExtension->SelfDevice);
    if (!enumStruct->EnumWorkItemContext->WorkItem)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        goto ErrorExit;
    }

    enumStruct->StopQueueContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(*enumStruct->StopQueueContext), 'PedI');
    if (!enumStruct->StopQueueContext)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        goto ErrorExit;
    }

    enumStruct->SenseInfoBuffer = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, sizeof(*enumStruct->SenseInfoBuffer), 'PedI');
    if (!enumStruct->SenseInfoBuffer)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        goto ErrorExit;
    }

    enumStruct->Srb = ExAllocatePoolWithTag(NonPagedPool, sizeof(*enumStruct->Srb), 'PedI');
    if (!enumStruct->Srb)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        goto ErrorExit;
    }

    enumStruct->Irp = IoAllocateIrp(1, FALSE);
    if (!enumStruct->Irp)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        goto ErrorExit;
    }

    enumStruct->DataBuffer = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, 0x234, 'PedI'); // ?
    if (!enumStruct->DataBuffer)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        enumStruct->DataBufferSize = 0;
        goto ErrorExit;
    }
    else
    {
        enumStruct->DataBufferSize = 0x234;
    }

    enumStruct->Mdl = IoAllocateMdl(enumStruct->DataBuffer, enumStruct->DataBufferSize, FALSE, FALSE, NULL);
    if (!enumStruct->Mdl)
    {
        DPRINT1("IdePreAllocEnumStructs: Allocate failed\n");
        goto ErrorExit;
    }
    MmBuildMdlForNonPagedPool(enumStruct->Mdl);

    FdoExtension->PreAllocEnumStruct = enumStruct;
    ASSERT(InterlockedCompareExchange(&(FdoExtension->EnumStructLock), 0, 1) == 1);
    return TRUE;

ErrorExit:

    DPRINT1("IdePreAllocEnumStructs: FIXME IdeFreeEnumStructs\n");
    ASSERT(FALSE);

    FdoExtension->PreAllocEnumStruct = NULL;
    ASSERT(InterlockedCompareExchange(&(FdoExtension->EnumStructLock), 0, 1) == 1);

    return FALSE;
}

VOID
NTAPI
ChannelEnableInterrupt(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    ULONG ix;

    for (ix = 0; ix < (FdoExtension->HwDeviceExtension->MaxIdeDevice / 2); ix++)
    {
        DPRINT("ChannelEnableInterrupt: DeviceControl %X\n", FdoExtension->HwDeviceExtension->CtrlBlock.DeviceControl);
        WRITE_PORT_UCHAR(FdoExtension->HwDeviceExtension->CtrlBlock.DeviceControl, 0);
    }
}

NTSTATUS
NTAPI
ChannelCreateSymblicLinks(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    UNICODE_STRING SymbolicLinkName;
    UNICODE_STRING DeviceName;
    WCHAR DeviceNameBuffer[64];
    WCHAR ScsiNameBuffer[64];
    ULONG ix;
    NTSTATUS Status;

    DPRINT("ChannelCreateSymblicLinks: %p\n", FdoExtension);

    swprintf(DeviceNameBuffer, L"\\Device\\Ide\\IdePort%d", FdoExtension->FdoIndex);
    RtlInitUnicodeString(&DeviceName, DeviceNameBuffer);

    for (ix = 0; ix <= IoGetConfigurationInformation()->ScsiPortCount; ix++)
    {
        swprintf(ScsiNameBuffer, L"\\Device\\ScsiPort%d", ix);
        RtlInitUnicodeString(&SymbolicLinkName, ScsiNameBuffer);

        Status = IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
        if (NT_SUCCESS(Status))
        {
            swprintf(ScsiNameBuffer, L"\\DosDevices\\Scsi%d:", ix);
            RtlInitUnicodeString(&SymbolicLinkName, ScsiNameBuffer);
            IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
            break;
        }
    }

    if (NT_SUCCESS(Status))
    {
        FdoExtension->SymlinkCreated = TRUE;
        FdoExtension->ScsiPortCount = ix;

        IoGetConfigurationInformation()->ScsiPortCount++;
    }

    return Status;
}

NTSTATUS
NTAPI
ChannelStartChannel(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PCM_RESOURCE_LIST CmResources)
{
    NTSTATUS (NTAPI* IntControl)(PVOID Context, BOOLEAN IsDisconnectOrReconnect);
    PCM_PARTIAL_RESOURCE_DESCRIPTOR InterruptDescriptor;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor;
    PCONFIGURATION_INFORMATION ConfigInfo;
    PCM_FULL_RESOURCE_DESCRIPTOR List;
    PULONG TimingTable;
    IO_STACK_LOCATION ioStack;
    POWER_STATE State;
    ULONG ix;
    ULONG jx;
    NTSTATUS Status;

    DPRINT("ChannelStartChannel: %p\n", FdoExtension);

  #if DBG
    DPRINT1("ChannelStartChannel: %p\n", CmResources);
    RosDumpCmResources(CmResources, 0);
  #endif

    List = CmResources->List;
    for (ix = 0; ix < CmResources->Count; ix++)
    {
        for (jx = 0; jx < List->PartialResourceList.Count; jx++)
        {
            Descriptor = List->PartialResourceList.PartialDescriptors;

            if (Descriptor[jx].Type == 1)
            {
                DPRINT("ChannelStartChannel: IO Port %I64X, Lenght %X\n",
                       Descriptor[jx].u.Port.Start.QuadPart, Descriptor[jx].u.Port.Length);
            }
            else if (Descriptor[jx].Type == 2)
            {
                DPRINT("ChannelStartChannel: Int Level %X, Vector %X\n",
                       Descriptor[jx].u.Interrupt.Level, Descriptor[jx].u.Interrupt.Vector);
            }
            else
            {
                DPRINT("ChannelStartChannel: Unknown resource\n");
            }
        }

        List = (PCM_FULL_RESOURCE_DESCRIPTOR)&List->PartialResourceList.PartialDescriptors[jx];
    }

    Status = DigestResourceList(&FdoExtension->ResourceData, CmResources, &InterruptDescriptor);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ChannelStartChannel: Status %X\n", Status);
        goto ErrorExit;
    }

    ConfigInfo = IoGetConfigurationInformation();

    if (FdoExtension->ResourceData.PrimaryClaimed)
    {
        FdoExtension->HwDeviceExtension->IsPrimary = TRUE;
        FdoExtension->HwDeviceExtension->IsSecondary = FALSE;
        ConfigInfo->AtDiskPrimaryAddressClaimed = TRUE;
    }

    if (FdoExtension->ResourceData.SecondaryClaimed)
    {
        FdoExtension->HwDeviceExtension->IsPrimary = FALSE;
        FdoExtension->HwDeviceExtension->IsSecondary = TRUE;
        ConfigInfo->AtDiskSecondaryAddressClaimed = TRUE;
    }

    AtapiBuildIoAddress((PUCHAR)FdoExtension->ResourceData.CmdBlockBase,
                        (PUCHAR)FdoExtension->ResourceData.CtrlBlockBase,
                        &FdoExtension->HwDeviceExtension->CmdBlock,
                        &FdoExtension->HwDeviceExtension->CtrlBlock,
                        &FdoExtension->HwDeviceExtension->CmdBlockLength,
                        &FdoExtension->HwDeviceExtension->CtrlBlockLength,
                        &FdoExtension->HwDeviceExtension->MaxIdeDevice,
                        &FdoExtension->HwDeviceExtension->MaxIdeTargetId);

    //IdePortIsThisAPanasonicPCMCIACard(FdoExtension);
    //IdePortIsThisAnATIController(FdoExtension);

    State.SystemState = 1;
    Status = IdePortIssueSetPowerState(FdoExtension, SystemPowerState, State, TRUE);

    if (Status == STATUS_INVALID_DEVICE_REQUEST)
    {
        DPRINT1("ChannelStartChannel: STATUS_INVALID_DEVICE_REQUEST\n");
        FdoExtension->SystemPowerState = 1;
    }
    else if (!NT_SUCCESS(Status))
    {
        DPRINT1("ChannelStartChannel: Status %X\n", Status);
        goto ErrorExit;
    }

    State.DeviceState = 1;
    Status = IdePortIssueSetPowerState(FdoExtension, DevicePowerState, State, TRUE);

    if (Status == STATUS_INVALID_DEVICE_REQUEST)
    {
        DPRINT1("ChannelStartChannel: STATUS_INVALID_DEVICE_REQUEST\n");
        FdoExtension->DevicePowerState = 1;
    }
    else if (!NT_SUCCESS(Status))
    {
        DPRINT1("ChannelStartChannel: Status %X\n", Status);
        goto ErrorExit;
    }

    FdoExtension->HwDeviceExtension->IntResFlags = FdoExtension->ResourceData.IntResFlags;

    RtlZeroMemory(&ioStack, sizeof(ioStack));

    ioStack.MajorFunction = IRP_MJ_PNP;
    ioStack.MinorFunction = IRP_MN_QUERY_INTERFACE;

    ioStack.Parameters.QueryInterface.InterfaceType = &GUID_PCIIDE_INTERRUPT_INTERFACE;
    ioStack.Parameters.QueryInterface.Size = sizeof(PCIIDE_INTERRUPT_INTERFACE);
    ioStack.Parameters.QueryInterface.Version = 1;
    ioStack.Parameters.QueryInterface.Interface = (PINTERFACE)&FdoExtension->InterruptInterface;
    ioStack.Parameters.QueryInterface.InterfaceSpecificData = NULL;

    DPRINT("ChannelStartChannel: Querying interrupt interface for Fdoe %X\n", FdoExtension);

    IdePortSyncSendIrp(FdoExtension->LowDevice, &ioStack, NULL);

    if (InterruptDescriptor)
    {
        Status = IoConnectInterrupt(&FdoExtension->InterruptObject,                    // OUT PKINTERRUPT* InterruptObject
                                    IdePortInterrupt,                                  // PKSERVICE_ROUTINE ServiceRoutine
                                    FdoExtension->SelfDevice,                          // IN PVOID  ServiceContext,
                                    NULL,                                              // PKSPIN_LOCK SpinLock OPTIONAL,
                                    InterruptDescriptor->u.Interrupt.Vector,           // IN ULONG Vector,
                                    InterruptDescriptor->u.Interrupt.Level,            // IN KIRQL Irql,
                                    InterruptDescriptor->u.Interrupt.Level,            // IN KIRQL SynchronizeIrql,
                                    (InterruptDescriptor->Flags & 1),                  // IN KINTERRUPT_MODE InterruptMode,
                                    InterruptDescriptor->ShareDisposition == 3,        // IN BOOLEAN ShareVector,
                                    InterruptDescriptor->u.Interrupt.Affinity,         // IN KAFFINITY ProcessorEnableMask,
                                    FALSE);                                            // IN BOOLEAN FloatingSave
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ChannelStartChannel:  Can't connect interrupt %X\n", InterruptDescriptor->u.Interrupt.Vector);
            FdoExtension->InterruptObject = NULL;
            goto ErrorExit;
        }

        if (FdoExtension->InterruptInterface.InterruptControl)
        {
            DPRINT("ChannelStartChannel: %X fdoe %X Invoking disconnect\n", InterruptDescriptor->u.Interrupt.Vector, FdoExtension);

            IntControl = FdoExtension->InterruptInterface.InterruptControl;
            Status = IntControl(FdoExtension->InterruptInterface.Context, TRUE);
            ASSERT(NT_SUCCESS(Status));
        }

        ChannelEnableInterrupt(FdoExtension);
    }

    RtlZeroMemory(&ioStack, sizeof(ioStack));
    RtlZeroMemory(&FdoExtension->SyncAccessInterface, sizeof(FdoExtension->SyncAccessInterface));

    ioStack.MajorFunction = IRP_MJ_PNP;
    ioStack.MinorFunction = IRP_MN_QUERY_INTERFACE;

    ioStack.Parameters.QueryInterface.InterfaceType = &GUID_PCIIDE_SYNC_ACCESS_INTERFACE;
    ioStack.Parameters.QueryInterface.Size = sizeof(IDE_SYNC_ACCESS_INTERFACE);
    ioStack.Parameters.QueryInterface.Version = 1;
    ioStack.Parameters.QueryInterface.Interface = (PINTERFACE)&FdoExtension->SyncAccessInterface;
    ioStack.Parameters.QueryInterface.InterfaceSpecificData = NULL;

    Status = IdePortSyncSendIrp(FdoExtension->LowDevice, &ioStack, NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ChannelStartChannel: Status %X\n", Status);
        FdoExtension->SyncAccessInterface.AllocateAccessToken = NULL;
        FdoExtension->SyncAccessInterface.Context = NULL;
    }

    if (FdoExtension->FdoState & 4)
    {
        Status = STATUS_SUCCESS;
    }
    else
    {
        RtlZeroMemory(&ioStack, sizeof(ioStack));

        ioStack.MajorFunction = IRP_MJ_PNP;
        ioStack.MinorFunction = IRP_MN_QUERY_INTERFACE;

        ioStack.Parameters.QueryInterface.InterfaceType = &GUID_PCIIDE_BUSMASTER_INTERFACE;
        ioStack.Parameters.QueryInterface.Size = sizeof(PCIIDE_BUS_MASTER_INTERFACE);
        ioStack.Parameters.QueryInterface.Version = 1;
        ioStack.Parameters.QueryInterface.Interface = (PINTERFACE)&FdoExtension->HwDeviceExtension->BusMasterInterface;
        ioStack.Parameters.QueryInterface.InterfaceSpecificData = NULL;

        Status = IdePortSyncSendIrp(FdoExtension->LowDevice, &ioStack, NULL);
        DPRINT("ChannelStartChannel: Status %X\n", Status);

        if (!NT_SUCCESS(Status))
            FdoExtension->IsBmIfaceReceived = FALSE;
        else
            FdoExtension->IsBmIfaceReceived = TRUE;

        if (!FdoExtension->DefaultTransferModeTimingTable)
        {
            TimingTable = ExAllocatePoolWithTag(NonPagedPool, (18 * sizeof(ULONG)), 'PedI');
            if (!TimingTable)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                DPRINT1("ChannelStartChannel: Status %X\n", Status);
                goto ErrorExit;
            }

            TimingTable[0] = 600;
            TimingTable[1] = 383;
            TimingTable[2] = 240;
            TimingTable[3] = 180;
            TimingTable[4] = 120;
            TimingTable[5] = 960;
            TimingTable[6] = 480;
            TimingTable[7] = 240;
            TimingTable[8] = 480;
            TimingTable[9] = 150;
            TimingTable[10] = 120;
            TimingTable[11] = 120;
            TimingTable[12] = 80;
            TimingTable[13] = 60;
            TimingTable[14] = 45;
            TimingTable[15] = 30;
            TimingTable[16] = 20;
            TimingTable[17] = 15;

            FdoExtension->DefaultTransferModeTimingTable = TimingTable;
            ASSERT(FdoExtension->DefaultTransferModeTimingTable);
        }

        RtlZeroMemory(&ioStack, sizeof(ioStack));
        FdoExtension->ProperResources.ChannelRequestProperResources = NULL;

        ioStack.MajorFunction = IRP_MJ_PNP;
        ioStack.MinorFunction = IRP_MN_QUERY_INTERFACE;

        ioStack.Parameters.QueryInterface.InterfaceType = &GUID_PCIIDE_REQUEST_PROPER_RESOURCES;
        ioStack.Parameters.QueryInterface.Size = sizeof(PCIIDE_PROPER_RESOURCES);
        ioStack.Parameters.QueryInterface.Version = 1;
        ioStack.Parameters.QueryInterface.Interface = (PINTERFACE)&FdoExtension->ProperResources;
        ioStack.Parameters.QueryInterface.InterfaceSpecificData = NULL;

        IdePortSyncSendIrp(FdoExtension->LowDevice, &ioStack, NULL);

        Status = ChannelCreateSymblicLinks(FdoExtension);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ChannelStartChannel: Status %X\n", Status);
            goto ErrorExit;
        }

        IdePortInitFdo(FdoExtension);

        for (ix = 0; ix < 2; ix++)
        {
            if (!FdoExtension->ErrorLog[ix])
                FdoExtension->ErrorLog[ix] = IoAllocateErrorLogEntry(FdoExtension->SelfDevice, 0x40);//FIXME
        }

        if (!IdePreAllocEnumStructs(FdoExtension))
        {
            DPRINT1("ChannelStartChannel: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto ErrorExit;
        }

        if (!FdoExtension->ReservedPages)
        {
            FdoExtension->ReservedPages = MmAllocateMappingAddress(PAGE_SIZE, 'PedI');
            ASSERT(FdoExtension->ReservedPages);
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("ChannelStartChannel: Status %X\n", Status);
            goto ErrorExit;
        }
    }

    FdoExtension->FdoState = ((FdoExtension->FdoState & ~4) | 2);

    if (FdoExtension->ChannelResources)
    {
        ExFreePool(FdoExtension->ChannelResources);
        FdoExtension->ChannelResources = NULL;
    }

    FdoExtension->ChannelResources = CmResources;

    return Status;

ErrorExit:

    DPRINT1("ChannelStartChannel: FIXME ChannelRemoveChannel()! Status %X\n", Status);
    ASSERT(FALSE);
    return Status;
}

NTSTATUS
NTAPI
ChannelStartDevice(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PCM_RESOURCE_LIST CmResources;
    PCM_FULL_RESOURCE_DESCRIPTOR CmList;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PCM_RESOURCE_LIST NewCmResources;
    PCM_FULL_RESOURCE_DESCRIPTOR NewCmList;
    PCM_RESOURCE_LIST ParentCmResources;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PIO_STACK_LOCATION IoStack;
    PIRP irp;
    IO_STATUS_BLOCK IoStatusBlock;
    KEVENT Event;
    ULONG PartialSize;
    ULONG Size1 = 0;
    ULONG Size2;
    ULONG size;
    ULONG ix;
    ULONG jx;
    NTSTATUS Status;

    DPRINT("ChannelStartDevice: %p, %p\n", Fdo, Irp);

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    FdoExtension = Fdo->DeviceExtension;
    ASSERT(!(FdoExtension->FdoState & 2));//FDOS_STARTED

    CmResources = IoStack->Parameters.StartDevice.AllocatedResourcesTranslated;
    if (CmResources)
    {
      #if DBG
        DPRINT1("ChannelStartDevice: %p, %p\n", Fdo, CmResources);
        RosDumpCmResources(CmResources, 0);
      #endif

        CmList = CmResources->List;

        for (ix = 0; ix < CmResources->Count; ix = (jx + 1))
        {
            CmDescriptor = CmList->PartialResourceList.PartialDescriptors;
            PartialSize = 0;

            for (jx = 0; jx < CmList->PartialResourceList.Count; jx++)
            {
                PartialSize += sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);

                if (CmDescriptor[jx].Type == 5)
                    PartialSize += CmDescriptor[jx].u.DeviceSpecificData.DataSize;
            }

            Size1 += PartialSize + FIELD_OFFSET(CM_FULL_RESOURCE_DESCRIPTOR, PartialResourceList.PartialDescriptors);

            CmList = Add2Ptr(CmList, Size1);
        }

        Size1 += FIELD_OFFSET(CM_RESOURCE_LIST, List);
    }

    size = (sizeof(CM_RESOURCE_LIST) + (2 * sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR)));

    ParentCmResources = ExAllocatePoolWithTag(PagedPool, size, 'PedI');
    if (!ParentCmResources)
    {
        DPRINT1("ChannelStartDevice: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    RtlZeroMemory(ParentCmResources, size);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    irp = IoBuildDeviceIoControlRequest(0x41414,
                                        FdoExtension->LowDevice,
                                        ParentCmResources,
                                        size,
                                        ParentCmResources,
                                        size,
                                        TRUE,
                                        &Event,
                                        &IoStatusBlock);
    if (!irp)
    {
        DPRINT1("ChannelStartDevice: Unable to allocate Irp to bind with busmaster parent\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        ExFreePoolWithTag(ParentCmResources, 'PedI');
        goto Exit;
    }

    Status = IoCallDriver(FdoExtension->LowDevice, irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }

    if (NT_SUCCESS(Status))
    {
        DPRINT1("ChannelStartDevice: %p, %p\n", Fdo, ParentCmResources);
        RosDumpCmResources(ParentCmResources, 0);
        Size2 = IoStatusBlock.Information;
    }
    else
    {
        DPRINT("ChannelStartDevice: Status %X\n", Status);
        Size2 = 0;
    }

    if (Size1 + Size2)
        NewCmResources = ExAllocatePoolWithTag(NonPagedPool, (Size1 + Size2), 'PedI');
    else
        NewCmResources = NULL;

    if (!NewCmResources)
    {
        DPRINT1("ChannelStartDevice: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        ExFreePoolWithTag(ParentCmResources, 'PedI');
        goto Exit;
    }

    NewCmResources->Count = 0;

    if (Size1)
    {
        RtlCopyMemory(NewCmResources->List, CmResources->List, (Size1 - FIELD_OFFSET(CM_RESOURCE_LIST, List)));
        NewCmList = Add2Ptr(NewCmResources->List, (Size1 - FIELD_OFFSET(CM_RESOURCE_LIST, List)));
        NewCmResources->Count = CmResources->Count;
    }
    else
    {
        NewCmList = NewCmResources->List;
    }

    if (Size2)
    {
        RtlCopyMemory(NewCmList, ParentCmResources->List, (Size2 - FIELD_OFFSET(CM_RESOURCE_LIST, List)));
        NewCmList = Add2Ptr(NewCmList, (Size2 - FIELD_OFFSET(CM_RESOURCE_LIST, List)));
        NewCmResources->Count += ParentCmResources->Count;
    }

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, ChannelStartDeviceCompletionRoutine, &Event, TRUE, TRUE, TRUE);

    Status = IoCallDriver(FdoExtension->LowDevice, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ChannelStartDevice: Status %X\n", Status);
        ExFreePoolWithTag(NewCmResources, 'PedI');
        ExFreePoolWithTag(ParentCmResources, 'PedI');
        goto Exit;
    }

    Status = ChannelStartChannel(FdoExtension, NewCmResources);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ChannelStartDevice: Status %X\n", Status);
        ExFreePoolWithTag(NewCmResources, 'PedI');
    }

    ExFreePoolWithTag(ParentCmResources, 'PedI');

Exit:

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
ChannelRemoveDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
ChannelDisableInterrupt(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    PATA_DEVICE_EXTENSION HwDeviceExtension;
    ULONG Device;

    HwDeviceExtension = FdoExtension->HwDeviceExtension;

    for (Device = 0; Device < (HwDeviceExtension->MaxIdeDevice / 2); Device++)
    {
        WRITE_PORT_UCHAR(HwDeviceExtension->CtrlBlock.DeviceControl, 2);
        HwDeviceExtension = FdoExtension->HwDeviceExtension;
    }
}

NTSTATUS
NTAPI
ChannelStopDevice(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    NTSTATUS (NTAPI* IntControl)(PVOID Context, BOOLEAN IsDisconnectOrReconnect);
    PFDO_DEVICE_EXTENSION FdoExtension;
    NTSTATUS Status;

    FdoExtension = Fdo->DeviceExtension;

    DPRINT("ChannelStopDevice: %p (%X) got a STOP device\n", Fdo->DeviceExtension, FdoExtension->ResourceData.CmdBlockBase);

    ChannelDisableInterrupt(FdoExtension);

    if (FdoExtension->InterruptObject)
    {
        if (FdoExtension->InterruptInterface.InterruptControl)
        {
            DPRINT("ChannelStopDevice: %p invoking reconnect\n", FdoExtension);

            IntControl = FdoExtension->InterruptInterface.InterruptControl;
            Status = IntControl(FdoExtension->InterruptInterface.Context, FALSE);
            ASSERT(NT_SUCCESS(Status));
        }

        IoDisconnectInterrupt(FdoExtension->InterruptObject);
        FdoExtension->InterruptObject = NULL;
    }

    if (FdoExtension->FdoState & 2)
    {
        FdoExtension->FdoState &= ~2;
        FdoExtension->FdoState |= 4;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    return IoCallDriver(FdoExtension->LowDevice, Irp);
}

NTSTATUS
NTAPI
DeviceQueryACPISettingsCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PKEVENT Event = Context;

    if (!NT_ERROR(Irp->IoStatus.Status))
        RtlCopyMemory(Irp->UserBuffer, Irp->AssociatedIrp.MasterIrp, Irp->IoStatus.Information);

    KeSetEvent(Event, EVENT_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
DeviceQueryACPISettings(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ACPI_EVAL_SIGNATURE MethodSign,
    _Out_ PACPI_EVAL_OUTPUT_BUFFER* OutQueryResult)
{
    PACPI_EVAL_OUTPUT_BUFFER QueryResult;
    PACPI_EVAL_INPUT_BUFFER AcpiInput;
    PIO_STACK_LOCATION IoStack;
    PDEVICE_OBJECT LowDevice;
    KEVENT Event;
    PIRP Irp = NULL;
    ULONG ix;
    NTSTATUS Status;

    DPRINT("DeviceQueryACPISettings: '%c%c%c%c'\n", MethodSign.Char[0], MethodSign.Char[1], MethodSign.Char[2], MethodSign.Char[3]);

    LowDevice = IoGetAttachedDeviceReference(DeviceObject);

    for (ix = 0; ix < 2; ix++)
    {
        DPRINT("DeviceQueryACPISettings: _GTM try %X\n", ix);

        QueryResult = ExAllocatePoolWithTag(NonPagedPool, sizeof(*QueryResult), 'PedI');
        if (!QueryResult)
        {
            DPRINT1("DeviceQueryACPISettings: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        KeInitializeEvent(&Event, NotificationEvent, FALSE);

        Irp = IoAllocateIrp(LowDevice->StackSize, FALSE);
        if (!Irp)
        {
            DPRINT1("DeviceQueryACPISettings: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        Irp->AssociatedIrp.SystemBuffer = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, sizeof(ACPI_EVAL_OUTPUT_BUFFER), 'PedI');
        if (!Irp->AssociatedIrp.SystemBuffer)
        {
            DPRINT1("DeviceQueryACPISettings: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        IoStack = IoGetNextIrpStackLocation(Irp);
        IoStack->MajorFunction = IRP_MJ_DEVICE_CONTROL;

        IoStack->Parameters.DeviceIoControl.OutputBufferLength = sizeof(ACPI_EVAL_OUTPUT_BUFFER);
        IoStack->Parameters.DeviceIoControl.InputBufferLength = sizeof(ACPI_EVAL_INPUT_BUFFER);
        IoStack->Parameters.DeviceIoControl.IoControlCode = 0x32C000;

        AcpiInput = Irp->AssociatedIrp.SystemBuffer;
        AcpiInput->Signature = 'BieA';
        AcpiInput->MethodNameAsUlong = MethodSign.AsULONG;

        Irp->Flags = 0x50;
        Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
        Irp->UserBuffer = QueryResult;

        IoSetCompletionRoutine(Irp, DeviceQueryACPISettingsCompletionRoutine, &Event, TRUE, TRUE, TRUE);

        Status = IoCallDriver(LowDevice, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = Irp->IoStatus.Status;
        }

        if (NT_SUCCESS(Status) && QueryResult->Signature != 'BoeA')
        {
            ASSERT(QueryResult->Signature == ACPI_EVAL_OUTPUT_BUFFER_SIGNATURE);

            if (QueryResult->Signature != 'BoeA')
                Status = STATUS_UNSUCCESSFUL;
        }

        ExFreePoolWithTag(Irp->AssociatedIrp.SystemBuffer, 'PedI');
        IoFreeIrp(Irp);
        Irp = NULL;

        if (!NT_SUCCESS(Status))
        {
            QueryResult->Length = sizeof(ACPI_EVAL_OUTPUT_BUFFER);
            ExFreePoolWithTag(QueryResult, 'PedI');
            QueryResult = NULL;

            if (Status != STATUS_BUFFER_OVERFLOW)
            {
                DPRINT("DeviceQueryACPISettings: Status %X\n", Status);
                break;
            }
        }
    }

    ObDereferenceObject(LowDevice);

    if (Irp)
    {
        if (Irp->AssociatedIrp.SystemBuffer)
            ExFreePoolWithTag(Irp->AssociatedIrp.SystemBuffer, 'PedI');

        IoFreeIrp(Irp);
    }

    *OutQueryResult = QueryResult;

    return Status;
}

VOID
NTAPI
DeviceQueryChannelTimingSettings(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PIDE_ACPI_TIMING_MODE_BLOCK TimingBlock)
{
    PACPI_EVAL_OUTPUT_BUFFER QueryResult;
    ACPI_EVAL_SIGNATURE Signature;
    ULONG ix;
    NTSTATUS Status;

    DPRINT("DeviceQueryChannelTimingSettings: %p, %p\n", FdoExtension, TimingBlock);

    Signature.AsULONG = 'MTG_';

    Status = DeviceQueryACPISettings(FdoExtension->SelfDevice, Signature, &QueryResult);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("DeviceQueryChannelTimingSettings: Status %X\n", Status);
        goto ErrorExit;
    }

    if (QueryResult->Count != 1)
    {
        DPRINT1("DeviceQueryChannelTimingSettings: QueryResult->Count %X\n", QueryResult->Count);
        ASSERT(QueryResult->Count == 1);
        Status = STATUS_UNSUCCESSFUL;
        goto ErrorExit;
    }

    if (QueryResult->Argument[0].Type != 2 ||
        QueryResult->Argument[0].DataLength < sizeof(IDE_ACPI_TIMING_MODE_BLOCK))
    {
        DPRINT1("DeviceQueryChannelTimingSettings: Type %X\n", QueryResult->Argument[0].Type);
        ASSERT(QueryResult->Argument[0].Type == 2);//ACPI_METHOD_ARGUMENT_BUFFER
        Status = STATUS_UNSUCCESSFUL;
        goto ErrorExit;
    }

    RtlCopyMemory(TimingBlock, &QueryResult->Argument[0].Argument, sizeof(*TimingBlock));

    DPRINT("DeviceQueryChannelTimingSettings: _GTM Data:\n");

    for (ix = 0; ix < 2; ix++)
    {
        DPRINT("PIO Speed [%d] %X\n", ix, TimingBlock->Drive[ix].PioSpeed);
        DPRINT("DMA Speed [%d] %X\n", ix, TimingBlock->Drive[ix].DmaSpeed);
    }

    DPRINT("Flags %X\n", TimingBlock->ModeFlags);

    if (QueryResult)
        ExFreePool(QueryResult);

    return;

ErrorExit:

    for (ix = 0; ix < 2; ix++)
    {
        TimingBlock->Drive[ix].PioSpeed = 0xFFFFFFFF;
        TimingBlock->Drive[ix].DmaSpeed = 0xFFFFFFFF;
    }
}

NTSTATUS
NTAPI
ChannelAcpiTransferModeSelect(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPCIIDE_TRANSFER_MODE_SELECT Xmode)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
ChannelQueryTransferModeInterface(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    IO_STACK_LOCATION ioStack;
    ULONG ix;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ChannelQueryTransferModeInterface: %p\n", FdoExtension);

    RtlZeroMemory(&ioStack, sizeof(ioStack));

    ioStack.MajorFunction = IRP_MJ_PNP;
    ioStack.MinorFunction = IRP_MN_QUERY_INTERFACE;

    ioStack.Parameters.QueryInterface.InterfaceType = &GUID_PCIIDE_XFER_MODE_INTERFACE;
    ioStack.Parameters.QueryInterface.Size = sizeof(FdoExtension->TransferModeInterface);
    ioStack.Parameters.QueryInterface.Version = 1;

    ioStack.Parameters.QueryInterface.Interface = (PINTERFACE)&FdoExtension->TransferModeInterface;
    ioStack.Parameters.QueryInterface.InterfaceSpecificData = NULL;

    Status = IdePortSyncSendIrp(FdoExtension->LowDevice, &ioStack, NULL);
    if (NT_SUCCESS(Status))
    {
        if (FdoExtension->TransferModeInterface.IsTransferModeSelect != 1)
        {
            for (ix = 0; ix < 2; ix++)
            {
                if (FdoExtension->TimingBlock.Drive[ix].PioSpeed != 0xFFFFFFFF)
                    Status = STATUS_UNSUCCESSFUL;
            }
        }

        ASSERT(FdoExtension->TransferModeInterface.TransferModeTimingTable);
    }

    for (ix = 0; ix < 2; ix++)
    {
        if (FdoExtension->TimingBlock.Drive[ix].PioSpeed != 0xFFFFFFFF)
            Status = STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(Status))
    {
        FdoExtension->TransferModeInterface.Context = FdoExtension;
        FdoExtension->TransferModeInterface.TransferModeSelect = ChannelAcpiTransferModeSelect;

        FdoExtension->TransferModeInterface.IsTransferModeSelect = FdoExtension->TimingBlock.Drive[0].PioSpeed != 0xFFFFFFFF ||
                                                                   FdoExtension->TimingBlock.Drive[1].PioSpeed != 0xFFFFFFFF;

        if (!FdoExtension->TransferModeInterface.TransferModeTimingTable)
        {
            FdoExtension->TransferModeInterface.TransferModeTimingTable = FdoExtension->DefaultTransferModeTimingTable;
            FdoExtension->TransferModeInterface.TableLength = 0x12;//(18)
        }
    }

    if (!FdoExtension->TransferModeInterface.IsTransferModeSelect)
        FdoExtension->HwDeviceExtension->IsTransferModeNotSelected = TRUE;

    ASSERT(FdoExtension->TransferModeInterface.TransferModeSelect);
    ASSERT(FdoExtension->TransferModeInterface.TransferModeTimingTable);
}

PDEVICE_OBJECT
NTAPI
DeviceCreatePhysicalDeviceObject(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PUNICODE_STRING DeviceName)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    PDEVICE_OBJECT Pdo = NULL;
    NTSTATUS Status;

    Status = IoCreateDevice(DriverObject, sizeof(PDO_DEVICE_EXTENSION), DeviceName, 0x2D, 0x100, 0, &Pdo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("DeviceCreatePhysicalDeviceObject: Status %X\n", Status);
        return Pdo;
    }

    Pdo->Flags |= 0x4010;

    Pdo->AlignmentRequirement = FdoExtension->SelfDevice->AlignmentRequirement;
    if (Pdo->AlignmentRequirement < 1)
        Pdo->AlignmentRequirement = 1;

    PdoExtension = Pdo->DeviceExtension;
    RtlZeroMemory(PdoExtension, sizeof(*PdoExtension));

    PdoExtension->DriverObject = DriverObject;
    PdoExtension->SelfDevice = Pdo;
    PdoExtension->SystemPowerState = 1;
    PdoExtension->DevicePowerState = 1;
    PdoExtension->FdoExtension = FdoExtension;

    PdoExtension->NoSupportIrp = IdePortNoSupportIrp;
    PdoExtension->PdoPnpDispatchTable = PdoPnpDispatchTable;
    PdoExtension->PdoPowerDispatchTable = PdoPowerDispatchTable;
    //PdoExtension->PdoWmiDispatchTable = PdoWmiDispatchTable;

    return Pdo;
}

PPDO_DEVICE_EXTENSION
NTAPI
AllocatePdo(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ ATA_SCSI_ADDRESS ScsiAddress,
    _In_ PVOID TagLock)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    UNICODE_STRING PdoName;
    PDEVICE_OBJECT Pdo;
    ULONG Idx;
    WCHAR NameBuffer[64];
    KIRQL Irql;

    PAGED_CODE();
    DPRINT("AllocatePdo: scan bus %X\n", FdoExtension->ResourceData.CmdBlockBase);

    swprintf(NameBuffer,
             L"\\Device\\Ide\\IdeDeviceP%dT%dL%d-%x",
             FdoExtension->FdoIndex,
             ScsiAddress.TargetId,
             ScsiAddress.Lun,
             (InterlockedIncrement(&PdoIndex) - 1));

    RtlInitUnicodeString(&PdoName, NameBuffer);

    Pdo = DeviceCreatePhysicalDeviceObject(FdoExtension->DriverObject, FdoExtension, &PdoName);
    if (!Pdo)
    {
        DPRINT1("AllocatePdo: Unable to create device object\n", NameBuffer);
        return NULL;
    }

    PdoExtension = Pdo->DeviceExtension;
    PdoExtension->TimeOut = -1;
    PdoExtension->PdoFlags |= 0x8000;
    PdoExtension->Pdo = Pdo;

    PdoExtension->PathId = ScsiAddress.PathId;
    PdoExtension->TargetId = ScsiAddress.TargetId;
    PdoExtension->Lun = ScsiAddress.Lun;

    KeInitializeSpinLock(&PdoExtension->PdoLock);
    InitializeListHead(&PdoExtension->PdoxSrbData.Requests);
    KeInitializeEvent(&PdoExtension->Event, NotificationEvent, FALSE);

    Idx = ((ScsiAddress.Lun + ScsiAddress.TargetId) & 7);

    KeAcquireSpinLock(&FdoExtension->PdoArrayLock, &Irql);

    PdoExtension->LinkPdoExt = FdoExtension->PdoArray[Idx];
    //IdeLogOpenCommandLog(..);
    FdoExtension->PdoArray[Idx] = PdoExtension;

    FdoExtension->PdoCount1++;
    FdoExtension->PdoCount2++;

    IdeInterlockedIncrement(PdoExtension, &PdoExtension->ReferenceCount, TagLock);

    KeReleaseSpinLock(&FdoExtension->PdoArrayLock, Irql);

    DPRINT("AllocatePdo: %p %X\n", PdoExtension, PdoExtension->TimeOut);
    return PdoExtension;
}

VOID
NTAPI
SyncAtaPassThroughCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIDE_WAIT_CONTEXT WaitContext,
    _In_ NTSTATUS InStatus)
{
    DPRINT("SyncAtaPassThroughCompletionRoutine: %p, %X\n", WaitContext, InStatus);

    WaitContext->Status = InStatus;
    KeSetEvent(&WaitContext->Event, IO_NO_INCREMENT, FALSE);

    DPRINT("SyncAtaPassThroughCompletionRoutine: InStatus %X\n", InStatus);
}

NTSTATUS
NTAPI
AtaPassThroughCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID InContext)
{
    PATA_PASS_THROUGH_CONTEXT Context = InContext;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    PATA_PASS_THROUGH AtaPassThr;
    KIRQL Irql;

    DPRINT("AtaPassThroughCompletionRoutine: %p, %X\n", Irp, Irp->IoStatus.Status);

    if (Context->Srb->SrbStatus & 0x40)
    {
        DPRINT("AtaPassThroughCompletionRoutine: Unfreeze Queue TID %X\n", Context->Srb->TargetId);

        PdoExtension = Context->DeviceObject->DeviceExtension;
        ASSERT(PdoExtension);

        PdoExtension->PdoFlags &= ~1;
        FdoExtension = PdoExtension->FdoExtension;

        KeAcquireSpinLock(&FdoExtension->SpinLock, &Irql);
        GetNextLuRequest2(PdoExtension->FdoExtension, PdoExtension, __FILE__, __LINE__);
        KeLowerIrql(Irql);
    }

    AtaPassThr = Context->Srb->DataBuffer;

    if (AtaPassThr->IdeReg.bReserved & 2)
        Irp->IoStatus.Status = STATUS_SUCCESS;

    if (Context->MustSucceed)
    {
        RtlCopyMemory(Context->AtaPassThr, Context->Srb->DataBuffer, Context->Srb->DataTransferLength);
    }

    if (Context->CallBack)
    {
        VOID (NTAPI* CallBack)(PDEVICE_OBJECT, PVOID, NTSTATUS) = Context->CallBack;
        CallBack(Context->DeviceObject, Context->CallBackContext, Irp->IoStatus.Status);
    }

    if (!Context->MustSucceed)
    {
        ExFreePool(Context->SenseInfoBuffer);
        ExFreePool(Context->Srb);
        ExFreePool(Context);

        if (Irp->MdlAddress)
            IoFreeMdl(Irp->MdlAddress);

        IoFreeIrp(Irp);
    }

    DPRINT("AtaPassThroughCompletionRoutine: %X\n", STATUS_MORE_PROCESSING_REQUIRED);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
IssueAsyncAtaPassThroughSafe(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PATA_PASS_THROUGH AtaPassThr,
    _In_ BOOLEAN IsDataIn,
    _In_ PVOID CallBack,
    _In_ PVOID CallBackContext,
    _In_ UCHAR SrbFunctionType,
    _In_ LONG TimeOutValue,
    _In_ BOOLEAN MustSucceed)
{
    PATAPI_PRE_ALLOC_ENUM_STRUCT EnumStruct;
    PSENSE_DATA SenseInfoBuffer = NULL;
    PATA_PASS_THROUGH_CONTEXT Context;
    PSCSI_REQUEST_BLOCK Srb = NULL;
    PIO_STACK_LOCATION IoStack;
    PIRP Irp = NULL;
    ULONG TotalBufferSize;

    DPRINT("IssueAsyncAtaPassThroughSafe: %X\n", FdoExtension->ResourceData.CmdBlockBase);

    if (MustSucceed)
    {
        EnumStruct = FdoExtension->PreAllocEnumStruct;

        if (EnumStruct)
        {
            Context = EnumStruct->AtaPassThrContext;
            ASSERT(Context);

            SenseInfoBuffer = EnumStruct->SenseInfoBuffer;
            ASSERT(SenseInfoBuffer);

            Srb = EnumStruct->Srb;
            ASSERT(Srb);

            TotalBufferSize = (FIELD_OFFSET(ATA_PASS_THROUGH, Buffer) + AtaPassThr->BufferSize);

            Irp = EnumStruct->Irp;
            ASSERT(Irp);

            IoInitializeIrp(Irp, IoSizeOfIrp(1), 1); 
            Irp->MdlAddress = EnumStruct->Mdl;

            ASSERT(EnumStruct->DataBufferSize >= TotalBufferSize);

            RtlCopyMemory(EnumStruct->DataBuffer, AtaPassThr, TotalBufferSize);

            goto Finish;
        }
        else
        {
            ASSERT(FdoExtension->PreAllocEnumStruct);
            MustSucceed = FALSE;
        }
    }

    Context = ExAllocatePoolWithTag(0, sizeof(*Context), 'PedI');
    if (!Context)
    {
        DPRINT("IssueAsyncAtaPassThroughSafe: Can't allocate Context buffer\n");
        UNIMPLEMENTED_DBGBREAK();
        goto ErrorExit;
    }

    SenseInfoBuffer = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, sizeof(*SenseInfoBuffer), 'PedI');
    if (!SenseInfoBuffer)
    {
        DPRINT("IssueAsyncAtaPassThroughSafe: Can't allocate request sense buffer\n");
        UNIMPLEMENTED_DBGBREAK();
        goto ErrorExit;
    }

    Srb = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Srb), 'PedI');
    if (!Srb)
    {
        DPRINT( "IssueAsyncAtaPassThroughSafe: Can't SRB\n");
        UNIMPLEMENTED_DBGBREAK();
        goto ErrorExit;
    }

    Irp = IoAllocateIrp(PdoExtension->SelfDevice->StackSize, FALSE);
    if (!Irp)
    {
        UNIMPLEMENTED_DBGBREAK();
        goto ErrorExit;
    }

    TotalBufferSize = (FIELD_OFFSET(ATA_PASS_THROUGH, Buffer) + AtaPassThr->BufferSize);

    Irp->MdlAddress = IoAllocateMdl(AtaPassThr, TotalBufferSize, FALSE, FALSE, NULL);
    if (!Irp->MdlAddress)
    {
        UNIMPLEMENTED_DBGBREAK();
        goto ErrorExit;
    }

    MmBuildMdlForNonPagedPool(Irp->MdlAddress);

Finish:

    IoStack = IoGetNextIrpStackLocation(Irp);
    IoStack->MajorFunction = IRP_MJ_SCSI;

    RtlZeroMemory(Srb, sizeof(*Srb));

    IoStack->Parameters.Scsi.Srb = Srb;
    DPRINT("IssueAsyncAtaPassThroughSafe: %p, %p, %p\n", Irp, IoStack, IoStack->Parameters.Scsi.Srb);

    Srb->PathId = PdoExtension->PathId;
    Srb->TargetId = PdoExtension->TargetId;
    Srb->Lun = PdoExtension->Lun;

    if (SrbFunctionType)
    {
        Srb->QueueSortKey = 0xFFFFFFFF;
        Srb->Function = 0xC7;
    }
    else
    {
        Srb->QueueSortKey = 0;
        Srb->Function = 0xC8;
    }

    Srb->Length = sizeof(*Srb);

    if (IsDataIn)
        Srb->SrbFlags = 0x40; // SRB_FLAGS_DATA_IN
    else
        Srb->SrbFlags = 0x80; // SRB_FLAGS_DATA_OUT

    if (AtaPassThr->IdeReg.bReserved & 0x80)
        Srb->SrbFlags |= 0x10; // SRB_FLAGS_BYPASS_FROZEN_QUEUE

    Srb->SrbFlags |= 0x8; // SRB_FLAGS_DISABLE_SYNCH_TRANSFER

    Srb->NextSrb = NULL;
    Srb->TimeOutValue = TimeOutValue;
    Srb->SenseInfoBuffer = SenseInfoBuffer;
    Srb->ScsiStatus = 0;
    Srb->SrbStatus = 0;
    Srb->OriginalRequest = Irp;
    Srb->CdbLength = 6;
    Srb->SenseInfoBufferLength = sizeof(*SenseInfoBuffer);
    Srb->DataTransferLength = TotalBufferSize;
    Srb->DataBuffer = MmGetMdlVirtualAddress(Irp->MdlAddress);

    IoSetCompletionRoutine(Irp, AtaPassThroughCompletionRoutine, Context, TRUE, TRUE, TRUE);

    Context->DeviceObject = PdoExtension->SelfDevice;
    Context->CallBack = CallBack;
    Context->CallBackContext = CallBackContext;
    Context->SenseInfoBuffer = SenseInfoBuffer;
    Context->MustSucceed = MustSucceed;
    Context->Srb = Srb;
    Context->AtaPassThr = AtaPassThr;

    IoCallDriver(PdoExtension->SelfDevice, Irp);
    return STATUS_PENDING;

ErrorExit:

    DPRINT("IssueAsyncAtaPassThroughSafe: %X\n", FdoExtension->ResourceData.CmdBlockBase);
    //IdePortLogNoMemoryErrorFn(..);

    ASSERT(MustSucceed == FALSE);

    if (Context)
        ExFreePoolWithTag(Context, 'PedI');

    if (SenseInfoBuffer)
        ExFreePoolWithTag(SenseInfoBuffer, 'PedI');

    if (Srb)
        ExFreePoolWithTag(Srb, 'PedI');

    if (Irp)
    {
        if (Irp->MdlAddress)
            IoFreeMdl(Irp->MdlAddress);

        IoFreeIrp(Irp);
    }

    return STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS
NTAPI
IssueSyncAtaPassThroughSafe(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PATA_PASS_THROUGH AtaPassThr,
    _In_ UCHAR IsDataIn,
    _In_ UCHAR SrbFunctionType,
    _In_ LONG TimeOutValue,
    _In_ BOOLEAN MustSucceed)
{
    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;
    IDE_WAIT_CONTEXT WaitContext;
    ULONG ix;

    DPRINT("IssueSyncAtaPassThroughSafe: %X\n", FdoExtension->ResourceData.CmdBlockBase);

    if (MustSucceed)
    {
        ASSERT(InterlockedCompareExchange(&FdoExtension->EnumStructLock, 1, 0) == 0);
    }

    for (ix = 0; ix < 0xA; ix++)
    {
        KeInitializeEvent(&WaitContext.Event, NotificationEvent, FALSE);

        Status = IssueAsyncAtaPassThroughSafe(FdoExtension,
                                              PdoExtension,
                                              AtaPassThr,
                                              IsDataIn,
                                              SyncAtaPassThroughCompletionRoutine,
                                              &WaitContext,
                                              SrbFunctionType,
                                              TimeOutValue,
                                              MustSucceed);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&WaitContext.Event,  Executive, KernelMode, FALSE, NULL);
            Status = WaitContext.Status;
        }

        if (Status == STATUS_UNSUCCESSFUL)
        {
            DPRINT1("Retrying flushed request\n");
        }

        if (Status != STATUS_UNSUCCESSFUL && Status != STATUS_INSUFFICIENT_RESOURCES)
            break;
    }

    if (MustSucceed)
    {
        ASSERT(InterlockedCompareExchange(&FdoExtension->EnumStructLock, 0, 1) == 1);
    }

    if (NT_SUCCESS(Status))
        return WaitContext.Status;

    DPRINT("IssueSyncAtaPassThroughSafe: ret Status %X\n", Status);
    return Status;
}

NTSTATUS
NTAPI
IdePortSaveDeviceParameter(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PWSTR ValueName,
    _In_ ULONG ValueData)
{
    HANDLE DevInstRegKey;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IdePortSaveDeviceParameter: '%S' %X\n", ValueName, ValueData);

    Status = IoOpenDeviceRegistryKey(FdoExtension->LowPdo, PLUGPLAY_REGKEY_DRIVER, KEY_WRITE, &DevInstRegKey);
    if (!NT_SUCCESS(Status))
    {
        if (Status != STATUS_OBJECT_NAME_NOT_FOUND)
        {
            DPRINT1("IdePortSaveDeviceParameter: Status %X\n", Status);
        }
        else
        {
            DPRINT("IdePortSaveDeviceParameter: Status %X\n", Status);
        }

        return Status;
    }

    Status = RtlWriteRegistryValue(RTL_REGISTRY_HANDLE, DevInstRegKey, ValueName, REG_DWORD, &ValueData, 4);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IdePortSaveDeviceParameter: Status %X\n", Status);
    }

    ZwClose(DevInstRegKey);

    return Status;
}

ULONG
NTAPI
AtapiDetectDevice(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PIDENTIFY_DATA Identify,
    _In_ BOOLEAN MustSucceed)
{
    ATA_DETECT_DEVICE_CONTEX Detect;
    PIDE_CMD_BLOCK_REGS CmdBlock;
    IDEREGS ideRegs[3];
    PIDEREGS IdeRegs;
    ULONG TimeoutValue = 0;
    ULONG DeviceFlags;
    ULONG DeviceType;
    ULONG ix;
    ULONG nx;
    BOOLEAN IsIdentifyCommand;
    BOOLEAN IsFoundChild = FALSE;
    BOOLEAN IsNoTimeout = FALSE;
    CHAR StrBuffer[0x2C];
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("AtapiDetectDevice: %X\n", MustSucceed);

    ASSERT(FdoExtension);
    ASSERT(PdoExtension);
    ASSERT(PdoExtension->PathId == 0);
    ASSERT(PdoExtension->TargetId < FdoExtension->HwDeviceExtension->MaxIdeTargetId);

    CmdBlock = &FdoExtension->HwDeviceExtension->CmdBlock;

    if (FdoExtension->DeviceParameter[PdoExtension->TargetId] == 3)
    {
        DeviceType = 3;
    }
    else
    {
        DeviceType = 0;

        IdePortGetDeviceParameter(FdoExtension, TypeName[PdoExtension->TargetId], &DeviceType);

        DPRINT("AtapiDetectDevice: last boot config deviceType %X\n", DeviceType);

        IdePortGetDeviceParameter(FdoExtension, DetectionTimeoutName[PdoExtension->TargetId], &TimeoutValue);
        if (!TimeoutValue)
        {
            IsNoTimeout = TRUE;
            TimeoutValue = ((PdoExtension->TargetId & 1) ? 3 : 0xA);
        }

        if (InitSafeBootMode == 1)
            TimeoutValue = ((PdoExtension->TargetId & 1) != 0 ? 3 : 0xA);

        IdePortSaveDeviceParameter(FdoExtension, TypeName[PdoExtension->TargetId], 0);

        if (PdoExtension->TargetId == 1 && !FdoExtension->PcmciaIdeHasSlaveDevice)
            DeviceType = 3;
    }

    RtlZeroMemory(ideRegs, sizeof(ideRegs));

    DPRINT("AtapiDetectDevice: DeviceType %X\n", DeviceType);

    if (DeviceType == 3)
    {
        UNIMPLEMENTED_DBGBREAK();
        return 3;
    }

    if (DeviceType == 1)
    {
        ideRegs[0].bCommandReg = 0xEC;
        ideRegs[0].bReserved = 0x50;

        ideRegs[1].bCommandReg = 0xA1;
        ideRegs[1].bReserved = 0x10;
    }
    else
    {
        ideRegs[0].bCommandReg = 0xA1;
        ideRegs[0].bReserved = 0x10;

        ideRegs[1].bCommandReg = 0xEC;
        ideRegs[1].bReserved = 0x50;
    }

    RtlZeroMemory(&Detect.AtaPassThr, sizeof(Detect.AtaPassThr));

    Detect.AtaPassThr.IdeReg.bReserved = 0x30;
    Detect.AtaPassThr.IdeReg.bSectorCountReg = 0xA;

    IssueSyncAtaPassThroughSafe(FdoExtension, PdoExtension, &Detect.AtaPassThr, 0, 0, 3, MustSucceed);

    DPRINT("AtapiDetectDevice: Hack for device %X at %X took 0 ms\n",
           PdoExtension->TargetId, FdoExtension->ResourceData.CmdBlockBase);

    if (Detect.AtaPassThr.IdeReg.bCommandReg == 0xFF)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    if (Detect.AtaPassThr.IdeReg.bCommandReg & 0x80)
    {
        RtlZeroMemory(&Detect.AtaPassThr, sizeof(Detect.AtaPassThr));
        Detect.AtaPassThr.IdeReg.bReserved = 1;

        IssueSyncAtaPassThroughSafe(FdoExtension, PdoExtension, &Detect.AtaPassThr, 0, 0, 0x1E, MustSucceed);

        DPRINT("AtapiDetectDevice: Reset device %X ata %X took 0 ms\n",
               PdoExtension->TargetId, FdoExtension->ResourceData.CmdBlockBase);
    }

    for (ix = 0, nx = 0, IdeRegs = ideRegs; ix < 2; ix++, IdeRegs++)
    {
        RtlZeroMemory(&Detect.AtaPassThr, sizeof(Detect.AtaPassThr));
        Detect.AtaPassThr.IdeReg.bReserved = 0x30;

        IsIdentifyCommand = (ideRegs[ix].bCommandReg == 0xEC);
        if (IsIdentifyCommand)
        {
            Detect.AtaPassThr.IdeReg.bSectorCountReg = 0xA;

            IssueSyncAtaPassThroughSafe(FdoExtension, PdoExtension, &Detect.AtaPassThr, 0, 0, 3, MustSucceed);

            if (Detect.AtaPassThr.IdeReg.bCommandReg == 0 || Detect.AtaPassThr.IdeReg.bCommandReg == 1)
                continue;

            DeviceType = 1;
        }
        else
        {
            IssueSyncAtaPassThroughSafe(FdoExtension, PdoExtension, &Detect.AtaPassThr, 0, 0, 3, MustSucceed);
            DeviceType = 2;
        }

        if (Detect.AtaPassThr.IdeReg.bCommandReg == 0xFF || Detect.AtaPassThr.IdeReg.bCommandReg == 0xFE)
        {
            UNIMPLEMENTED_DBGBREAK();
        }

        RtlZeroMemory(&Detect.AtaPassThr, sizeof(Detect.AtaPassThr));

        Detect.AtaPassThr.BufferSize = 0x200;
        RtlMoveMemory(&Detect, IdeRegs, sizeof(Detect.AtaPassThr.IdeReg));

        ASSERT(TimeoutValue);

        Status = IssueSyncAtaPassThroughSafe(FdoExtension, PdoExtension, &Detect.AtaPassThr, 1, 0, TimeoutValue, MustSucceed);

        if (!NT_SUCCESS(Status))
        {
            DPRINT("AtapiDetectDevice: The irp with command %X, %X target %X failed %X with status %X\n",
                   ix, CmdBlock->CmdBlockBase, PdoExtension->TargetId, ideRegs[ix].bCommandReg, Status);

            UNIMPLEMENTED_ONCE;

            DeviceType = 3;
            DeviceFlags = FdoExtension->HwDeviceExtension->DeviceFlags[PdoExtension->TargetId];

            if (DeviceFlags & 1 && !(DeviceFlags & 2) && nx < 2)
            {
                if (ideRegs[ix].bCommandReg == 0xEC)
                {
                    ideRegs[ix--].bReserved |= 8;
                    ix--;
                    nx++;
                }

                continue;
            }

            if (Status == STATUS_IO_TIMEOUT)
            {
                if (PdoExtension->TargetId & 1 && IsNoTimeout)
                {
                    DPRINT("AtapiDetectDevice: Updating the registry with 1s value for device %d\n", PdoExtension->TargetId);
                    IdePortSaveDeviceParameter(FdoExtension, DetectionTimeoutName[PdoExtension->TargetId], 1);
                }

                break;
            }
        }
        else
        {
            if (!(Detect.AtaPassThr.IdeReg.bCommandReg & 1))
            {
                DPRINT("AtapiDetectDevice: Found a child on %X target %X\n", CmdBlock->CmdBlockBase, PdoExtension->TargetId);
                IsFoundChild = TRUE;

                if (IsIdentifyCommand)
                    IdePortFudgeAtaIdentifyData((PIDENTIFY_DATA)Detect.AtaPassThr.Buffer);

                break;
            }

            DPRINT("AtapiDetectDevice: Command %X, %X target %X failed %X with status %X\n",
                   ix, CmdBlock->CmdBlockBase, PdoExtension->TargetId, ideRegs[ix].bCommandReg, Detect.AtaPassThr.IdeReg.bCommandReg);
        }
    }

    DPRINT("AtapiDetectDevice: Identify Data for device %X at %X took 0 ms\n",
           PdoExtension->TargetId, FdoExtension->ResourceData.CmdBlockBase, 0);

    IdePortSaveDeviceParameter(FdoExtension, TypeName[PdoExtension->TargetId], (DeviceType != 3 ? DeviceType : 0));

    if (IsFoundChild)
    {
        RtlMoveMemory(Identify, Detect.AtaPassThr.Buffer, sizeof(IDENTIFY_DATA));

        for (ix = 0; ix < 8; ix += 2)
        {
            StrBuffer[ix] = Identify->FirmwareRevision[ix + 1];
            StrBuffer[ix + 1] = Identify->FirmwareRevision[ix];
        }
        StrBuffer[ix] = 0;

        DPRINT("AtapiDetectDevice: firmware version: '%s'\n", StrBuffer);

        for (ix = 0; ix < 0x28; ix += 2)
        {
            StrBuffer[ix] = Identify->ModelNumber[ix + 1];
            StrBuffer[ix + 1] = Identify->ModelNumber[ix];
        }
        StrBuffer[ix] = 0;

        DPRINT("AtapiDetectDevice: model number: '%s'\n", StrBuffer);

        for (ix = 0; ix < 0x14; ix += 2)
        {
            StrBuffer[ix] = Identify->SerialNumber[ix + 1];
            StrBuffer[ix + 1] = Identify->SerialNumber[ix];
        }
        StrBuffer[ix] = 0;

        DPRINT("AtapiDetectDevice: serial number: '%s'\n", StrBuffer);
    }
    else
    {
        DeviceType = 3;
    }

    if (DeviceType == 3)
    {
        UNIMPLEMENTED_ONCE;
    }

    DPRINT("AtapiDetectDevice: ret %X\n", DeviceType);

    return DeviceType;
}

ULONG
NTAPI
IdePortSimpleCheckSum(
    _In_ ULONG CheckSum,
    _In_ PVOID CheckSumBuffer,
    _In_ ULONG Length)
{
    PUSHORT Buffer = (PUSHORT)CheckSumBuffer;

    DPRINT("IdePortSimpleCheckSum: %X\n", Length);

    Length /= 2;

    while (Length--)
    {
        CheckSum += *Buffer;
        Buffer++;
        CheckSum = ((USHORT)CheckSum + (CheckSum >> 16));
    }

    return CheckSum;
}

NTSTATUS
NTAPI
IdePortRegQueryRoutine(
    _In_ PWSTR ValueName,
    _In_ ULONG ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueLength,
    _In_ PVOID Context,
    _In_ PVOID EntryContext)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

HANDLE
NTAPI
IdePortOpenServiceSubKey(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING Name)
{
    PATAPI_DRIVER_EXTENSION DriverExtension;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE DriverHandle;
    HANDLE KeyHandle;
    NTSTATUS Status;

    DPRINT("IdePortOpenServiceSubKey: '%wZ'\n", Name);

    DriverExtension = IoGetDriverObjectExtension(DriverObject, DriverEntry);
    if (!DriverExtension)
    {
        DPRINT1("IdePortOpenServiceSubKey: DriverExtension is NULL\n");
        return NULL;
    }

    InitializeObjectAttributes(&ObjectAttributes, &DriverExtension->RegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwOpenKey(&DriverHandle, KEY_ALL_ACCESS, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        if (Status != STATUS_OBJECT_NAME_NOT_FOUND)
        {
            DPRINT1("IdePortOpenServiceSubKey: Status %X\n", Status);
        }
        else
        {
            DPRINT("IdePortOpenServiceSubKey: Status %X\n", Status);
        }

        return NULL;
    }

    InitializeObjectAttributes(&ObjectAttributes, Name, OBJ_CASE_INSENSITIVE, DriverHandle, NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    ZwClose(DriverHandle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("IdePortOpenServiceSubKey: Status %X\n", Status);
        return NULL;
    }

    return KeyHandle;
}

NTSTATUS
NTAPI
IdePortGetParameterFromServiceSubKey(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PWSTR RegKeyValue,
    _In_ ULONG Type,
    _In_ BOOLEAN IsRegQuery,
    _In_ PVOID* OutParameter,
    _In_ ULONG DataSize)
{
    RTL_QUERY_REGISTRY_TABLE QueryTable[2];
    UNICODE_STRING ValueName;
    UNICODE_STRING SubKeyUs;
    ANSI_STRING SubKeyAs;
    HANDLE KeyHandle;
    CHAR SubKeyString[0x34];
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IdePortGetParameterFromServiceSubKey: '%S'\n", RegKeyValue);

    *OutParameter = NULL;

    sprintf(SubKeyString, "Parameters");
    RtlInitAnsiString(&SubKeyAs, SubKeyString);

    Status = RtlAnsiStringToUnicodeString(&SubKeyUs, &SubKeyAs, TRUE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IdePortGetParameterFromServiceSubKey: Status %X\n", Status);
        return Status;
    }

    KeyHandle = IdePortOpenServiceSubKey(DriverObject, &SubKeyUs);
    RtlFreeUnicodeString(&SubKeyUs);
    if (!KeyHandle)
        return Status;

    if (IsRegQuery)
    {
        RtlZeroMemory(QueryTable, sizeof(QueryTable));

        QueryTable[0].Name = RegKeyValue;
        QueryTable[0].QueryRoutine = IdePortRegQueryRoutine;
        QueryTable[0].Flags = 0x14;
        QueryTable[0].EntryContext = OutParameter;
        QueryTable[0].DefaultType = 0;
        QueryTable[0].DefaultData = NULL;
        QueryTable[0].DefaultLength = 0;

        Status = RtlQueryRegistryValues(RTL_REGISTRY_HANDLE, KeyHandle, QueryTable, ULongToPtr(Type), NULL);
    }
    else
    {
        RtlInitUnicodeString(&ValueName, RegKeyValue);
        Status = ZwSetValueKey(KeyHandle, &ValueName, 0, Type, OutParameter, DataSize);
    }

    ZwClose(KeyHandle);

    return Status;
}

BOOLEAN
NTAPI
IdePortSearchDeviceInRegMultiSzList(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PIDENTIFY_DATA IdentifyData,
    _In_ PWSTR RegKeyValue)
{
    PVOID ParameterData;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IdePortSearchDeviceInRegMultiSzList: '%S'\n", RegKeyValue);

    ASSERT(IdentifyData);
    ASSERT(RegKeyValue);

    Status = IdePortGetParameterFromServiceSubKey(FdoExtension->DriverObject, RegKeyValue, 7, TRUE, &ParameterData, 0);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IdePortSearchDeviceInRegMultiSzList: Status %X\n", Status);
        return FALSE;
    }

    if (!ParameterData)
    {
        DPRINT("IdePortSearchDeviceInRegMultiSzList: ParameterData is NULL\n");
        return FALSE;
    }

    DPRINT1("IdePortSearchDeviceInRegMultiSzList: FIXME\n");
    UNIMPLEMENTED_DBGBREAK();

    return FALSE;
}

BOOLEAN
NTAPI
IdePortMustBePio(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PIDENTIFY_DATA Identify)
{
    PAGED_CODE();
    return IdePortSearchDeviceInRegMultiSzList(FdoExtension, Identify, L"PioOnlyDevice");
}

BOOLEAN
NTAPI
IdePortPioByDefaultDevice(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PIDENTIFY_DATA Identify)
{
    PAGED_CODE();
    return IdePortSearchDeviceInRegMultiSzList(FdoExtension, Identify, L"DefaultPioAtapiDevice");
}

UCHAR
NTAPI
IdePortGetFlushCommand(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PIDENTIFY_DATA Identify)
{
    ATA_PASS_THROUGH AtaPassThr;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IdePortGetFlushCommand: %X\n", FdoExtension->ResourceData.CmdBlockBase);

    ASSERT(FdoExtension);
    ASSERT(PdoExtension);
    ASSERT(Identify);

    if (IdePortSearchDeviceInRegMultiSzList(FdoExtension, Identify, (PWSTR)L"NoFlushDevice"))
    {
        DPRINT("IdePortGetFlushCommand: found a device that couldn't handle any flush command\n");
        return 0xFF;
    }

    if (IdePortSearchDeviceInRegMultiSzList(FdoExtension, Identify, (PWSTR)L"UseCheckPowerForFlush"))
    {
        DPRINT("IdePortGetFlushCommand: found a device that has to use check power mode command to flush\n");
        return 0xE5;
    }

    if (Identify->MajorRevision != 0 &&
        Identify->MajorRevision != 0xFFFF &&
        Identify->MajorRevision & 0xFFF0)
    {
        return 0xE7;
    }

    RtlZeroMemory(&AtaPassThr, sizeof(AtaPassThr));

    AtaPassThr.IdeReg.bCommandReg = 0xE7;
    AtaPassThr.IdeReg.bReserved = 0x50;

    Status = IssueSyncAtaPassThroughSafe(FdoExtension, PdoExtension, &AtaPassThr, FALSE, FALSE, 0xF, FALSE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("IdePortGetFlushCommand: Status %X\n", Status);
        return 0xE5;
    }

    if (AtaPassThr.IdeReg.bCommandReg & 1)
        return 0xE5;

    return 0xE7;
}

BOOLEAN
NTAPI
IdePortDeviceHasNonRemovableMedia(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PIDENTIFY_DATA Identify)
{
    PIDENTIFY_DEVICE_DATA IdentifyDevice = (PIDENTIFY_DEVICE_DATA)Identify;

    PAGED_CODE();
    DPRINT("IdePortDeviceHasNonRemovableMedia: %X\n", IdentifyDevice->GeneralConfiguration.RemovableMedia);

    if (IdentifyDevice->GeneralConfiguration.RemovableMedia)
        return TRUE;

    return FALSE;
}

BOOLEAN
NTAPI
IdePortDeviceIsLs120(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PIDENTIFY_DATA Identify)
{
    ULONG ix;
    CHAR Model[0x28+2] = {0};

    PAGED_CODE();
    DPRINT("IdePortDeviceIsLs120: %X\n", FdoExtension->ResourceData.CmdBlockBase);

    for (ix = 0; ix < 0x28; ix += 2)
    {
        Model[ix] = Identify->ModelNumber[ix + 1];
        Model[ix + 1] = Identify->ModelNumber[ix];
        ix += 2;
    }

    Model[ix] = 0;

    return (strstr(_strupr(Model), "LS-120") != 0);
}

BOOLEAN
NTAPI
IdePortNoPowerDown(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PIDENTIFY_DATA Identify)
{
    PAGED_CODE();
    DPRINT("IdePortNoPowerDown: %X\n", FdoExtension->ResourceData.CmdBlockBase);
    return IdePortSearchDeviceInRegMultiSzList(FdoExtension, Identify, L"NoPowerDownDevice");
}

VOID
NTAPI
InitHwExtWithIdentify(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ ULONG Drive,
    _In_ UCHAR IdentifyCommand,
    _In_ PIDENTIFY_DATA Identify,
    _In_ BOOLEAN IsForceRemovableMedia)
{
    PIDENTIFY_DEVICE_DATA IdentifyDevice = (PIDENTIFY_DEVICE_DATA)Identify;

    if (Identify->MediaStatusNotification == 1)
    {
        DPRINT("InitHwExtWithIdentify: Marking drive %X as removable. SFE %X\n", Drive, Identify->MediaStatusNotification);
        HwDeviceExtension->DeviceFlags[Drive] |= 0x1000;
    }

    if (IsForceRemovableMedia)
    {
        DPRINT("InitHwExtWithIdentify: Device media is removable\n");

        HwDeviceExtension->DeviceFlags[Drive] &= ~0x20000;
        HwDeviceExtension->DeviceFlags[Drive] |= 0x10;
    }
    else
    {
        DPRINT("InitHwExtWithIdentify: Device media is NOT removable\n");
    }

    if ((Identify->GeneralConfiguration & 0x20) && IdentifyCommand != 0xEC)
    {
        DPRINT("InitHwExtWithIdentify: Device interrupts on assertion of DRQ.\n");
        HwDeviceExtension->DeviceFlags[Drive] |= 8;
    }
    else
    {
        DPRINT("InitHwExtWithIdentify: Device does not interrupt on assertion of DRQ.\n");
    }

    if ((Identify->GeneralConfiguration & 0xF00) != 0x100 || IdentifyCommand == 0xEC)
    {
        DPRINT("InitHwExtWithIdentify: Device is not a tape drive.\n");
    }
    else
    {
        DPRINT("InitHwExtWithIdentify: Device is a tape drive.\n");
        HwDeviceExtension->DeviceFlags[Drive] |= 4;
    }

    if (IdentifyDevice->SecurityStatus.SecuritySupported &&
        IdentifyDevice->SecurityStatus.SecurityEnabled &&
        IdentifyDevice->SecurityStatus.SecurityLocked)
    {
        HwDeviceExtension->DeviceFlags[Drive] |= 0x01000000;
    }
}

BOOLEAN
NTAPI
SetDriveParameters(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ ULONG Device,
    _In_ BOOLEAN IsWait)
{
    ULONG ix;
    ULONG jx;
    UCHAR status;

    DPRINT("SetDriveParameters: Number of heads %X\n", HwDeviceExtension->NumberOfHeads[Device]);
    DPRINT("SetDriveParameters: Sectors per track %X\n", HwDeviceExtension->SectorsPerTrack[Device]);

    if (HwDeviceExtension->DeviceFlags[Device] & 0x20000)
    {
        ASSERT(!(HwDeviceExtension->DeviceFlags[Device] & 0x10));//DFLAGS_REMOVABLE_DRIVE

        HwDeviceExtension->DeviceFlags[Device] &= ~0x20000;
        HwDeviceExtension->DeviceFlags[Device] |= 0x40000;
    }

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect,
                     (((Device & 0x1) << 4) | IDE_DRIVE_SELECT | (HwDeviceExtension->NumberOfHeads[Device] - 1)));

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.SectorCount, HwDeviceExtension->SectorsPerTrack[Device]);

    DPRINT("SetDriveParameters: ... \n");
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status, 0x91);
    DPRINT("SetDriveParameters: ... \n");

    if (!IsWait)
        return TRUE;

    DPRINT("SetDriveParameters: ... \n");

    ix = 0;
    while (TRUE)
    {
          for (jx = 0; jx < 25000; jx++)
          {
              status = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
              if (!(status & 0x80))
                  break;

              KeStallExecutionProcessor(40);
          }

          if (!(status & 0x80))
              break;

          DPRINT("SetDriveParameters: after 1 sec wait, device is still busy with %X, status %X\n",
                 HwDeviceExtension->CmdBlock.CmdBlockBase, status);

          ix++;
          if (ix >= 0xA)
          {
              if (status & 0x80)
              {
                  DPRINT("SetDriveParameters: WaitOnBusy failed. (%X %X)\n", HwDeviceExtension->CmdBlock.CmdBlockBase, status);
              }

              break;
          }
    }

    DPRINT("SetDriveParameters: ... \n");

    if (status & 0x80)
        return 0;

    if (status & 1)
    {
        DPRINT("SetDriveParameters: Error bit set. (%X %X)\n", READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Error), status);
        return FALSE;
    }

    return TRUE;
}

VOID
NTAPI
IdePortSelectCHS(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ ULONG Device,
    _In_ PIDENTIFY_DATA Identify)
{
    PATA_DEVICE_EXTENSION HwDeviceExtension;
    ULONG CurrentChs;
    ULONG Chs;
    ULONG ix;
    ULONG jx;
    UCHAR status;

    PAGED_CODE();

    //ASSERT(IdePAGESCANLockCount > 0);
    ASSERT(FdoExtension);
    ASSERT(Identify);

    HwDeviceExtension = FdoExtension->HwDeviceExtension;

    ASSERT(HwDeviceExtension);
    ASSERT(Device < HwDeviceExtension->MaxIdeDevice);

    DPRINT("IdePortSelectCHS: %X\n", HwDeviceExtension->CmdBlock.CmdBlockBase);

    if (!(HwDeviceExtension->DeviceFlags[Device] & 1))
        return;

    if (HwDeviceExtension->DeviceFlags[Device] & 2)
        return;

    CurrentChs = (Identify->NumberOfCurrentCylinders * Identify->CurrentSectorsPerTrack * Identify->NumberOfCurrentHeads);
    Chs = (Identify->NumCylinders * Identify->NumHeads * Identify->NumSectorsPerTrack);

    if (CurrentChs >= Chs &&
        Identify->MajorRevision &&
        Identify->NumberOfCurrentCylinders &&
        Identify->NumberOfCurrentHeads &&
        Identify->CurrentSectorsPerTrack)
    {
        HwDeviceExtension->NumberOfCylinders[Device] = Identify->NumberOfCurrentCylinders;
        HwDeviceExtension->NumberOfHeads[Device] = Identify->NumberOfCurrentHeads;
        HwDeviceExtension->SectorsPerTrack[Device] = Identify->CurrentSectorsPerTrack;
    }
    else
    {
        HwDeviceExtension->NumberOfCylinders[Device] = Identify->NumCylinders;
        HwDeviceExtension->NumberOfHeads[Device] = Identify->NumHeads;
        HwDeviceExtension->SectorsPerTrack[Device] = Identify->NumSectorsPerTrack;
    }

    if (Identify->NumCylinders != Identify->NumberOfCurrentCylinders ||
        Identify->NumHeads != Identify->NumberOfCurrentHeads ||
        Identify->NumSectorsPerTrack != Identify->CurrentSectorsPerTrack)
    {
        DPRINT("IdePortSelectCHS: %X device %X current CHS (%X, %X, %X) differs from default CHS (%X, %X, %X)\n",
               HwDeviceExtension->CmdBlock.CmdBlockBase, Device,
               Identify->NumberOfCurrentCylinders, Identify->NumberOfCurrentHeads, Identify->CurrentSectorsPerTrack,
               Identify->NumCylinders, Identify->NumHeads, Identify->NumSectorsPerTrack);
    }

    if (HwDeviceExtension->SectorsPerTrack[Device] == 0x35)
    {
        if (HwDeviceExtension->NumberOfHeads[Device] == 7)
        {
            DPRINT("IdePortSelectCHS: Fix up the geometry for ESDI!\n");
            HwDeviceExtension->SectorsPerTrack[Device] = 0x34;
            HwDeviceExtension->NumberOfHeads[Device] = 0xE;
        }

        if (HwDeviceExtension->SectorsPerTrack[Device] == 0x35 && HwDeviceExtension->NumberOfHeads[Device] == 0xF)
        {
            DPRINT("IdePortSelectCHS: Fix up the geometry for ESDI!\n");
            HwDeviceExtension->SectorsPerTrack[Device] = 0x34;
            HwDeviceExtension->NumberOfHeads[Device] = 0xF;
        }
    }

    if (HwDeviceExtension->SectorsPerTrack[Device] == 0x36 && HwDeviceExtension->NumberOfHeads[Device] == 7)
    {
        DPRINT("IdePortSelectCHS: Fix up the geometry for ESDI!\n");
        HwDeviceExtension->SectorsPerTrack[Device] = 0x3F;
        HwDeviceExtension->NumberOfHeads[Device] = 0x10;
        return;
    }

    //DebugPrintTickCount(..);
    DPRINT("IdePortSelectCHS: ... \n");
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT));
    DPRINT("IdePortSelectCHS: ... \n");

    for (ix = 0; ix < 10; ix++)
    {
        for (jx = 0; jx < 25000; jx++)
        {
            status = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
            if (!(status & 0x80))
                break;

            KeStallExecutionProcessor(40);
        }

        if (!(status & 0x80))
            break;

        DPRINT("IdePortSelectCHS: after 1 sec wait, device is still busy (%X %X)\n", HwDeviceExtension->CmdBlock, status);
    }

    if (status & 0x80)
    {
        DPRINT("IdePortSelectCHS: WaitOnBusy failed. (%X %X)\n", HwDeviceExtension->CmdBlock, status);
    }

    DPRINT("IdePortSelectCHS: ... \n");
    if (status & 0x80)
    {
        DPRINT1("IdePortSelectCHS: FIXME\n");
        UNIMPLEMENTED_DBGBREAK();
    }
    DPRINT("IdePortSelectCHS: ... \n");

    ix = 0;
    while (TRUE)
    {
        for (jx = 0; jx < 25000; jx++)
        {
            status = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
            if (!(status & 0x80))
                break;

            KeStallExecutionProcessor(40);
        }

        if (!(status & 0x80))
            break;

        DPRINT("IdePortSelectCHS: after 1 sec wait, device is still busy (%X %X)\n", HwDeviceExtension->CmdBlock, status);

        ix++;
        if (ix >= 10)
        {
            if (status & 0x80)
            {
                DPRINT("IdePortSelectCHS: WaitOnBusy failed. (%X %X)\n", HwDeviceExtension->CmdBlock, status);
            }

            break;
        }
    }

    DPRINT("IdePortSelectCHS: ... \n");
    //DebugPrintTickCount(..);
    DPRINT("FindDevices: Status before SetDriveParameters (%X %X)\n", status, READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect));
    DPRINT("IdePortSelectCHS: ... \n");

    if (!SetDriveParameters(HwDeviceExtension, Device, TRUE))
    {
        DPRINT("IdePortSelectCHS: Set drive parameters for device %X failed\n", Device);
        HwDeviceExtension->DeviceFlags[Device] = 0;
    }

    DPRINT("IdePortSelectCHS: ... \n");
}

VOID
NTAPI
DeviceUnregisterIdleDetection(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    if (!PdoExtension->IdleCounter)
        return;

    PoRegisterDeviceForIdleDetection(PdoExtension->SelfDevice, 0, 0, PowerDeviceD3);

    PdoExtension->IdleCounter = NULL;
}

NTSTATUS
NTAPI
FreePdo(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ BOOLEAN IsWait,
    _In_ BOOLEAN IsDeleteDevice,
    _In_ PVOID TagLock)
{
    PFDO_DEVICE_EXTENSION FdoExtension = PdoExtension->FdoExtension;
    PPDO_DEVICE_EXTENSION CurrentPdoe;
    PPDO_DEVICE_EXTENSION LastPdoe = NULL;
    LONG ReferenceCount;
    KIRQL Irql;

    DPRINT("FreePdo: %X, %X, %X\n", FdoExtension->ResourceData.CmdBlockBase, IsWait, IsDeleteDevice);

    KeAcquireSpinLock(&FdoExtension->PdoArrayLock, &Irql);

    CurrentPdoe = FdoExtension->PdoArray[(PdoExtension->TargetId + PdoExtension->Lun) & 7];
    while (TRUE)
    {
        if (!CurrentPdoe)
        {
            KeReleaseSpinLock(&FdoExtension->PdoArrayLock, Irql);

            if (IsDeleteDevice)
            {
                DPRINT("FreePdo: deleting device %p that was PROBABLY surprise removed\n", PdoExtension->SelfDevice);

                if (!(PdoExtension->PdoState & 0x20) || PdoExtension->PdoState & 0x10)
                {
                    UNIMPLEMENTED_DBGBREAK();
                }
            }

            return STATUS_SUCCESS;
        }

        if (CurrentPdoe == PdoExtension)
            break;

        LastPdoe = CurrentPdoe;
        CurrentPdoe = CurrentPdoe->LinkPdoExt;
    }

    if (LastPdoe)
        LastPdoe->LinkPdoExt = CurrentPdoe->LinkPdoExt;
    else
        FdoExtension->PdoArray[(PdoExtension->TargetId + PdoExtension->Lun) & 7] = CurrentPdoe->LinkPdoExt;

    ASSERT(!(CurrentPdoe->PdoState & 2));//PDOS_LEGACY_ATTACHER

    if (CurrentPdoe->ReferenceCount > 1)
    {
        DPRINT("FreePdo: pdoe %p ReferenceCount is %X\n", CurrentPdoe, CurrentPdoe->ReferenceCount);
    }

    FdoExtension->PdoCount1--;

    if (CurrentPdoe->DevicePowerState <= 1)
        FdoExtension->PdoCount2--;

    KeReleaseSpinLock(&FdoExtension->PdoArrayLock, Irql);

    KeAcquireSpinLock(&CurrentPdoe->PdoLock, &Irql);

    ASSERT(!(CurrentPdoe->PdoState & 2));//PDOS_LEGACY_ATTACHER
    ASSERT(CurrentPdoe->ReferenceCount > 0);

    ReferenceCount = IdeInterlockedDecrement(CurrentPdoe, &CurrentPdoe->ReferenceCount, TagLock);

    CurrentPdoe->PdoState |= 0x60;
    KeReleaseSpinLock(&CurrentPdoe->PdoLock, Irql);

    DeviceUnregisterIdleDetection(PdoExtension);

    if (PdoExtension->InitData)
    {
        ExFreePool(PdoExtension->InitData);
        PdoExtension->InitData = NULL;
    }

    IdePortFlushLogicalUnit(FdoExtension, PdoExtension, TRUE);

    if (ReferenceCount && IsWait)
        KeWaitForSingleObject(&CurrentPdoe->Event, Executive, KernelMode, FALSE, NULL);

    if (IsDeleteDevice)
    {
        UNIMPLEMENTED_ONCE;
        //IdeLogFreeCommandLog(..);
        IoDeleteDevice(CurrentPdoe->SelfDevice);
    }

    return STATUS_SUCCESS;
}

BOOLEAN
NTAPI
AtapiDMACapable(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ ULONG Idx)
{
    PATA_DEVICE_EXTENSION HwDeviceExtension;
    CHAR Model[0x28 + 1];
    ULONG ix;

    PAGED_CODE();
    DPRINT("AtapiDMACapable: %X, %X\n", FdoExtension->ResourceData.CmdBlockBase, Idx);

    //ASSERT(IdePAGESCANLockCount > 0);

    HwDeviceExtension = FdoExtension->HwDeviceExtension;

    if (!(HwDeviceExtension->DeviceFlags[Idx] & 1))
        return FALSE;

    for (ix = 0; ix < 0x28; ix += 2)
    {
        Model[ix + 0] = HwDeviceExtension->IdentifyData[Idx].ModelNumber[ix + 1];
        Model[ix + 1] = HwDeviceExtension->IdentifyData[Idx].ModelNumber[ix + 0];
    }

    Model[ix] = 0;

    if (RtlCompareMemory(Model, "WDC", 3) != 3)
        return TRUE;

    if ((HwDeviceExtension->DeviceParameters[Idx].XferModeBitMap & 0x600) != 0x200)
        return TRUE;

    UNIMPLEMENTED_DBGBREAK();

    return FALSE;
}

VOID
NTAPI
AnalyzeDeviceCapabilities(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ BOOLEAN* OutIsMustBePio)
{
    NTSTATUS (NTAPI* PciIdeUdmaModesSupported)(IDENTIFY_DATA, PULONG, PULONG);
    PATA_DEVICE_EXTENSION HwDeviceExtension;
    PATA_DEVICE_PARAMETERS DeviceParameters;
    PULONG TransferModeTimingTable;
    ULONG TableLength;
    ULONG UserAddressableSectors;
    ULONG NumSectorsPerTrack;
    ULONG NumCylinders;
    ULONG NumHeads;
    ULONG MaxLBA;
    ULONG BestXferMode;
    ULONG CurrentMode;
    ULONG CycleTime;
    ULONG XferMode;
    ULONG TempMode;
    ULONG Mode;
    ULONG ix;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("AnalyzeDeviceCapabilities: %X\n", FdoExtension->ResourceData.CmdBlockBase);

    //ASSERT(IdePAGESCANLockCount > 0);

    TableLength = FdoExtension->TransferModeInterface.TableLength;
    TransferModeTimingTable = FdoExtension->TransferModeInterface.TransferModeTimingTable;
    ASSERT(TransferModeTimingTable);

    HwDeviceExtension = FdoExtension->HwDeviceExtension;

    for (ix = 0; ix < HwDeviceExtension->MaxIdeDevice; ix++)
    {
        if (!(HwDeviceExtension->DeviceFlags[ix] & 1))
            continue;

        DeviceParameters = &HwDeviceExtension->DeviceParameters[ix];

        HwDeviceExtension->DeviceFlags[ix] &= ~0x400;

        UserAddressableSectors = HwDeviceExtension->IdentifyData[ix].UserAddressableSectors;
        if (UserAddressableSectors > 0xFBFC10) // 16514064
        {
            NumCylinders = HwDeviceExtension->IdentifyData[ix].NumCylinders;
            NumHeads = HwDeviceExtension->IdentifyData[ix].NumHeads;
            NumSectorsPerTrack = HwDeviceExtension->IdentifyData[ix].NumSectorsPerTrack;

            if (NumCylinders == 0x3FFF && NumHeads <= 0x10 && NumSectorsPerTrack == 0x3F)
                HwDeviceExtension->DeviceFlags[ix] |= 0x400;

            if (UserAddressableSectors > (NumCylinders * NumHeads * NumSectorsPerTrack) &&
                NumCylinders <= 0xFFF &&
                NumHeads == 0x10 &&
                NumSectorsPerTrack == 0x3F)
            {
                HwDeviceExtension->DeviceFlags[ix] |= 0x400;
            }
        }

        if ((HwDeviceExtension->IdentifyData[ix].CommandSetSupport & 0x400) &&
            (HwDeviceExtension->IdentifyData[ix].CommandSetActive & 0x400))
        {
            ASSERT(HwDeviceExtension->IdentifyData[ix].Max48BitLBA[0] != 0);
            MaxLBA = HwDeviceExtension->IdentifyData[ix].Max48BitLBA[0];

            ASSERT(HwDeviceExtension->IdentifyData[ix].Max48BitLBA[1] == 0);
            ASSERT(MaxLBA >= HwDeviceExtension->IdentifyData[ix].UserAddressableSectors);

            DPRINT("AnalyzeDeviceCapabilities: Max LBA supported is %X\n", MaxLBA);

            if (FdoExtension->IsBigLbaEnabled != 1 || MaxLBA < 0x10000000)
            {
                DPRINT("AnalyzeDeviceCapabilities: big lba disabled\n");
            }
            else
            {
                HwDeviceExtension->DeviceFlags[ix] |= 0x200400;
            }
        }

        if (HwDeviceExtension->DeviceFlags[ix] & 0x400)
        {
            DPRINT("AnalyzeDeviceCapabilities: target %X supports LBA\n", ix);
        }

        XferMode  = 0;
        CycleTime = 0xFFFFFFFF;
        BestXferMode = 0;

        if (HwDeviceExtension->IdentifyData[ix].Capabilities & 0x800)
            DeviceParameters->IoReadySupported = TRUE;
        else
            DeviceParameters->IoReadySupported = FALSE;

        BestXferMode = (HwDeviceExtension->IdentifyData[ix].PioCycleTimingMode & 0xFF);

        if (BestXferMode > 2)
            BestXferMode = 0;

        ASSERT(BestXferMode < 3);//PIO3

        CycleTime = TransferModeTimingTable[BestXferMode];
        ASSERT(CycleTime);

        XferMode |= (0xFFFFFFFF >> (0x1F - BestXferMode));
        CurrentMode = (1 << BestXferMode);

        if (HwDeviceExtension->IdentifyData[ix].TranslationFieldsValid & 2)
        {
            if (DeviceParameters->IoReadySupported)
                CycleTime = HwDeviceExtension->IdentifyData[ix].MinimumPIOCycleTimeIORDY;
            else
                CycleTime = HwDeviceExtension->IdentifyData[ix].MinimumPIOCycleTime;

            if (HwDeviceExtension->IdentifyData[ix].AdvancedPIOModes & 1)
            {
                XferMode |= 8;
                BestXferMode = 3;
                CurrentMode = 8;
            }

            if (HwDeviceExtension->IdentifyData[ix].AdvancedPIOModes & 2)
            {
                XferMode |= 0x10;
                BestXferMode = 4;
                CurrentMode = 0x10;
            }

            if (HwDeviceExtension->IdentifyData[ix].AdvancedPIOModes)
            {
                TempMode = HwDeviceExtension->IdentifyData[ix].AdvancedPIOModes;
                ASSERT(TempMode);

                for (BestXferMode = 0; TempMode; BestXferMode++)
                    TempMode >>= 1;

                BestXferMode += 2;

                if (BestXferMode > 4)
                {
                    DPRINT("AnalyzeDeviceCapabilities: AdvancePIOMode > PIO_MODE4. Defaulting to PIO_MODE4.\n");
                    BestXferMode = 4;
                }

                CurrentMode = (1 << BestXferMode);
                XferMode |= CurrentMode;
            }

            DPRINT("AnalyzeDeviceCapabilities: [%X] AdvancedPIOModes %X\n",
                   ix, HwDeviceExtension->IdentifyData[ix].AdvancedPIOModes);
        }

        ASSERT(CycleTime != 0xFFFFFFFF);
        ASSERT(XferMode);
        ASSERT(CurrentMode);

        DeviceParameters->BestPioCycleTime = CycleTime;
        DeviceParameters->BestPioXferMode = BestXferMode;
        DeviceParameters->XferCurrentMode = CurrentMode;

        CurrentMode = 0;
        CycleTime = 0xFFFFFFFF;
        BestXferMode = 0x7FFFFFFF;

        if (HwDeviceExtension->IdentifyData[ix].SingleWordDMASupport)
        {
            DPRINT("AnalyzeDeviceCapabilities: [%X] SingleWordDMASupport %X\n",
                   ix, HwDeviceExtension->IdentifyData[ix].SingleWordDMASupport);

            DPRINT("AnalyzeDeviceCapabilities: [%X] SingleWordDMAActive %X\n",
                   ix, HwDeviceExtension->IdentifyData[ix].SingleWordDMAActive);

            TempMode = HwDeviceExtension->IdentifyData[ix].SingleWordDMASupport;
            ASSERT(TempMode);

            for (BestXferMode = 0; TempMode; BestXferMode++)
                TempMode >>= 1;

            BestXferMode--;

            if (BestXferMode > 2)
                BestXferMode = 2;

            CycleTime = TransferModeTimingTable[BestXferMode + 5];
            ASSERT(CycleTime);

            Mode = (0xFFFFFFFF >> (0x1F - BestXferMode));
            XferMode |= (Mode << 5);

            if (HwDeviceExtension->IdentifyData[ix].SingleWordDMAActive)
            {
                TempMode = HwDeviceExtension->IdentifyData[ix].SingleWordDMAActive;
                ASSERT(TempMode);

                for (CurrentMode = 0; TempMode; CurrentMode++)
                    TempMode >>= 1;

                CurrentMode--;

                if (CurrentMode > 2)
                    CurrentMode = 2;

                CurrentMode = (1 << (CurrentMode + 5));
            }
        }

        DeviceParameters->BestSwDmaCycleTime = CycleTime;
        DeviceParameters->BestSwDmaXferMode = BestXferMode;

        CycleTime = 0xFFFFFFFF;
        BestXferMode = 0x7FFFFFFF;

        if (HwDeviceExtension->IdentifyData[ix].MultiWordDMASupport)
        {
            DPRINT("AnalyzeDeviceCapabilities: [%X] MultiWordDMASupport %X\n",
                   ix, HwDeviceExtension->IdentifyData[ix].MultiWordDMASupport);

            DPRINT("AnalyzeDeviceCapabilities: [%X] MultiWordDMAActive %X\n",
                   ix, HwDeviceExtension->IdentifyData[ix].MultiWordDMAActive);

            TempMode = HwDeviceExtension->IdentifyData[ix].MultiWordDMASupport;
            ASSERT(TempMode);

            for (BestXferMode = 0; TempMode; BestXferMode++)
                TempMode >>= 1;

            BestXferMode--;

            if (BestXferMode > 2)
                BestXferMode = 2;

            CycleTime = TransferModeTimingTable[BestXferMode + 8];
            ASSERT(CycleTime);

            Mode = (0xFFFFFFFF >> (0x1F - BestXferMode));
            XferMode |= (Mode << 8);

            if (HwDeviceExtension->IdentifyData[ix].MultiWordDMAActive)
            {
                TempMode = HwDeviceExtension->IdentifyData[ix].MultiWordDMAActive;
                ASSERT(TempMode);

                for (CurrentMode = 0; TempMode; CurrentMode++)
                    TempMode >>= 1;

                CurrentMode--;

                if (CurrentMode > 2)
                    CurrentMode = 2;

                CurrentMode = (1 << (CurrentMode + 8));
            }
        }

        if (HwDeviceExtension->IdentifyData[ix].TranslationFieldsValid & 2)
        {
            DPRINT("AnalyzeDeviceCapabilities: [%X] IdentifyData word 64-70 are valid\n", ix);

            if (HwDeviceExtension->IdentifyData[ix].MinimumMWXferCycleTime &&
                HwDeviceExtension->IdentifyData[ix].RecommendedMWXferCycleTime)
            {
                DPRINT("AnalyzeDeviceCapabilities: [%X] MinimumMWXferCycleTime %X\n",
                       ix, HwDeviceExtension->IdentifyData[ix].MinimumMWXferCycleTime);

                DPRINT("AnalyzeDeviceCapabilities: [%X] RecommendedMWXferCycleTime %X\n",
                       ix, HwDeviceExtension->IdentifyData[ix].RecommendedMWXferCycleTime);

                CycleTime = HwDeviceExtension->IdentifyData[ix].MinimumMWXferCycleTime;
            }
        }

        DeviceParameters->BestMwDmaCycleTime = CycleTime;
        DeviceParameters->BestMwDmaXferMode = BestXferMode;

        CycleTime = 0xFFFFFFFF;
        BestXferMode = 0x7FFFFFFF;
        Mode = 0x7FFFFFFF;

        PciIdeUdmaModesSupported = FdoExtension->TransferModeInterface.PciIdeUdmaModesSupported;

        if (PciIdeUdmaModesSupported)
        {
            Status = PciIdeUdmaModesSupported(HwDeviceExtension->IdentifyData[ix], &BestXferMode, &Mode);
            if (!NT_SUCCESS(Status))
            {
                BestXferMode = 0x7FFFFFFF;
                Mode = 0x7FFFFFFF;
            }
        }
        else if (HwDeviceExtension->IdentifyData[ix].TranslationFieldsValid & 4)
        {
            if (HwDeviceExtension->IdentifyData[ix].UltraDMASupport)
            {
                TempMode = HwDeviceExtension->IdentifyData[ix].UltraDMASupport;
                ASSERT(TempMode);

                for (BestXferMode = 0; TempMode; BestXferMode++)
                    TempMode >>= 1;

                BestXferMode--;
            }

            if (HwDeviceExtension->IdentifyData[ix].UltraDMAActive)
            {
                TempMode = HwDeviceExtension->IdentifyData[ix].UltraDMASupport;
                ASSERT(TempMode);

                for (Mode = 0; TempMode; Mode++)
                    TempMode >>= 1;

                Mode--;
            }
        }

        if (Mode != 0x7FFFFFFF)
        {
            CurrentMode = Mode;

            if (CurrentMode >= (TableLength - 0xB)) // 11
                CurrentMode = (TableLength - 0xC);  // 12

            CurrentMode = (1 << (CurrentMode + 0xB));
        }

        if (BestXferMode != 0x7FFFFFFF)
        {
            if (BestXferMode >= (TableLength - 0xB))
                BestXferMode = (TableLength - 0xC);

            CycleTime = TransferModeTimingTable[BestXferMode + 0xB];
            ASSERT(CycleTime);

            Mode = (0xFFFFFFFF >> (0x1F - BestXferMode));
            XferMode |= (Mode << 0xB);
        }

        DeviceParameters->BestUDmaCycleTime = CycleTime;
        DeviceParameters->BestUDmaXferMode = BestXferMode;
        DeviceParameters->XferModeBitMap = XferMode;
        DeviceParameters->XferCurrentMode |= CurrentMode;

        if (OutIsMustBePio[ix] ||
            !AtapiDMACapable(FdoExtension, ix) ||
            InitSafeBootMode == 1) // #ifndef __REACTOS__ --> *InitSafeBootMode
        {
            DPRINT("AnalyzeDeviceCapabilities: Reseting DMA Information\n");

            DeviceParameters->XferCurrentMode &= 0x1F;
            DeviceParameters->XferModeBitMap &= 0x1F;

            DeviceParameters->BestSwDmaCycleTime = 0;
            DeviceParameters->BestMwDmaCycleTime = 0;
            DeviceParameters->BestUDmaCycleTime = 0;
            DeviceParameters->BestSwDmaXferMode = 0;
            DeviceParameters->BestMwDmaXferMode = 0;
            DeviceParameters->BestUDmaXferMode = 0;
        }

        if (DeviceParameters->BestPioXferMode > 2)
             HwDeviceExtension->MaximumBlockTransfer[ix] = HwDeviceExtension->IdentifyData[ix].MaximumBlockTransfer;
        else
            HwDeviceExtension->MaximumBlockTransfer[ix] = 0;

        DPRINT("AnalyzeDeviceCapabilities: [%X] transfer timing:\n", ix);
        DPRINT("PIO supported   - %4X and best cycle time - %5d ns\n", (XferMode & 0x1F), DeviceParameters->BestPioCycleTime);
        DPRINT("SWDMA supported - %4X and best cycle time - %5d ns\n", (XferMode & 0xE0), DeviceParameters->BestSwDmaCycleTime);
        DPRINT("MWDMA supported - %4X and best cycle time - %5d ns\n", (XferMode & 0x700), DeviceParameters->BestMwDmaCycleTime);
        DPRINT("UDMA supported  - %X and best cycle time - %5d ns\n", (XferMode & 0x7FFFF800), DeviceParameters->BestUDmaCycleTime);
        DPRINT("Current bitmap  - %4X\n", DeviceParameters->XferCurrentMode);
    }
}

VOID
NTAPI
AtapiSyncSelectTransferMode(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ PULONG TMAllowed)
{
    NTSTATUS (NTAPI* TransferModeSelect)(PVOID, PPCIIDE_TRANSFER_MODE_SELECT);
    PATA_DEVICE_PARAMETERS DeviceParameters;
    PCIIDE_TRANSFER_MODE_SELECT Xmode;
    ULONG ix;
    NTSTATUS Status;

    DPRINT("AtapiSyncSelectTransferMode: %X\n", FdoExtension->ResourceData.CmdBlockBase);

    RtlZeroMemory(&Xmode, sizeof(Xmode));

    for (ix = 0; ix < HwDeviceExtension->MaxIdeDevice; ix++)
    {
        Xmode.DevicePresent[ix] = ((HwDeviceExtension->DeviceFlags[ix] & 1) == 1);
        Xmode.FixedDisk[ix] = !(HwDeviceExtension->DeviceFlags[ix] & 2);

        DeviceParameters = &HwDeviceExtension->DeviceParameters[ix];

        Xmode.BestPioCycleTime[ix] = DeviceParameters->BestPioCycleTime;
        Xmode.BestSwDmaCycleTime[ix] = DeviceParameters->BestSwDmaCycleTime;
        Xmode.BestMwDmaCycleTime[ix] = DeviceParameters->BestMwDmaCycleTime;
        Xmode.BestUDmaCycleTime[ix] = DeviceParameters->BestUDmaCycleTime;

        Xmode.IoReadySupported[ix] = DeviceParameters->IoReadySupported;

        Xmode.DeviceTransferModeSupported[ix] = DeviceParameters->XferModeBitMap;
        Xmode.DeviceTransferModeCurrent[ix] = DeviceParameters->XferCurrentMode;

        if (!FdoExtension->IsBmIfaceReceived)
        {
            Xmode.DeviceTransferModeSupported[ix] &= 0x1F;
            Xmode.DeviceTransferModeCurrent[ix] &= 0x1F;
        }

        Xmode.IdentifyData[ix] = HwDeviceExtension->IdentifyData[ix];
        Xmode.UserChoiceTransferMode[ix] = FdoExtension->UserChoiceTransferMode[ix];

        Xmode.DeviceTransferModeSupported[ix] &= TMAllowed[ix];
        Xmode.DeviceTransferModeCurrent[ix] &= TMAllowed[ix];
    }

    Xmode.TransferModeTimingTable = FdoExtension->TransferModeInterface.TransferModeTimingTable;
    Xmode.TransferModeTableLength = FdoExtension->TransferModeInterface.TableLength;

    ASSERT(FdoExtension->TransferModeInterface.TransferModeSelect);
    TransferModeSelect = FdoExtension->TransferModeInterface.TransferModeSelect;

    Status = TransferModeSelect(FdoExtension->TransferModeInterface.Context, &Xmode);
    if (!NT_SUCCESS(Status))
    {
        for (ix = 0; ix < HwDeviceExtension->MaxIdeDevice; ix++)
        {
            DeviceParameters = &HwDeviceExtension->DeviceParameters[ix];
            DeviceParameters->XferSelectedMode = (DeviceParameters->XferCurrentMode & 0x1F);

            DPRINT("AtapiSyncSelectTransferMode: DEFAULT device %d transfer mode current %X and selected bitmap %X\n",
                   ix, DeviceParameters->XferCurrentMode, DeviceParameters->XferSelectedMode);
        }

        return;
    }

    for (ix = 0; ix < HwDeviceExtension->MaxIdeDevice; ix++)
    {
        DeviceParameters = &HwDeviceExtension->DeviceParameters[ix];
        DeviceParameters->XferSelectedMode = Xmode.DeviceTransferModeSelected[ix];

        DPRINT("AtapiSyncSelectTransferMode: device %d transfer mode current %X and selected bitmap %X\n",
               ix, DeviceParameters->XferCurrentMode, DeviceParameters->XferSelectedMode);
    }                         
}

NTSTATUS
NTAPI
AtapiSetTransferMode(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ ULONG Device,
    _In_ UCHAR Mode)
{
    ULONG ix;
    ULONG jx;
    UCHAR IdeStatus;

    DPRINT("AtapiSetTransferMode: %X, %X, %X\n", HwDeviceExtension->CmdBlock.CmdBlockBase, Device, Mode);

    if (HwDeviceExtension->CurrentSrb)
    {
        DPRINT1("HwDeviceExtension->CurrentSrb %X\n", HwDeviceExtension->CurrentSrb);
        ASSERT(HwDeviceExtension->CurrentSrb == NULL);
    }

    ASSERT(HwDeviceExtension->ExpectingInterrupt == FALSE);

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT));

    for (ix = 0; ix < 10; ix++)
    {
        for (jx = 0; jx < 25000; jx++)
        {
            IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
            if (!(IdeStatus & 0x80))
                break;

            KeStallExecutionProcessor(40);
        }

        if (!(IdeStatus & 0x80))
            break;

        DPRINT("AtapiSetTransferMode: after 1 sec wait, device is still busy with %X IdeStatus %X\n",
               HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
    }

    if (IdeStatus & 0x80)
    {
        DPRINT("AtapiSetTransferMode: WaitOnBusy failed. %X IdeStatus %X\n",
               HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
    }

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Features, 3);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.SectorCount, Mode);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, 0xEF);

    for (ix = 0; ix < 10; ix++)
    {
        for (jx = 0; jx < 25000; jx++)
        {
            IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
            if (!(IdeStatus & 0x80))
                break;

            KeStallExecutionProcessor(40);
        }

        if (!(IdeStatus & 0x80))
            break;

        DPRINT("AtapiSetTransferMode: after 1 sec wait, device is still busy with %X IdeStatus %X\n",
               HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
    }

    if (IdeStatus & 0x80)
    {
        DPRINT("AtapiSetTransferMode: WaitOnBusy failed. %X IdeStatus %X\n",
               HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
    }

    return ((IdeStatus & 0x81) != 0 ? STATUS_INVALID_DEVICE_REQUEST : STATUS_SUCCESS);
}

VOID
NTAPI
AtapiProgramTransferMode(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension)
{
    ULONG SelectedMode;
    ULONG CurrentMode;
    ULONG SupportMode;
    ULONG ix;
    UCHAR Mode;
    NTSTATUS Status;

    for (ix = 0; ix < HwDeviceExtension->MaxIdeDevice; ix++)
    {
        if (!(HwDeviceExtension->DeviceFlags[ix] & 1))
            continue;

        SelectedMode = HwDeviceExtension->DeviceParameters[ix].XferSelectedMode;

        DPRINT("AtapiProgramTransferMode: [%X] TMSelected %X\n", ix, SelectedMode);

        HwDeviceExtension->DeviceFlags[ix] &= ~0x10200;

        if (!HwDeviceExtension->IsTransferModeNotSelected)
        {
            SupportMode = ((SelectedMode >> 1) & 0xF);

            for (CurrentMode = 0; SupportMode; CurrentMode++)
                SupportMode >>= 1;

            if (CurrentMode > 2)
            {
                DPRINT("AtapiProgramTransferMode: [%X] setting PIOmode %X\n", ix, CurrentMode);

                Status = AtapiSetTransferMode(HwDeviceExtension, ix, (CurrentMode | 8));
                if (!NT_SUCCESS(Status))
                {
                    DPRINT1("AtapiProgramTransferMode: Unable to set pio xfer mode %X for %X device %X\n",
                            CurrentMode, HwDeviceExtension->CmdBlock.CmdBlockBase, ix);
                }
            }
        }

        SupportMode = (SelectedMode >> 5);

        for (CurrentMode = 5; SupportMode; CurrentMode++)
            SupportMode >>= 1;

        CurrentMode--;

        if (CurrentMode >= 0xB)
            Mode = ((CurrentMode - 0xB) | 0x40);
        else if (CurrentMode >= 8)
            Mode = ((CurrentMode - 8) | 0x20);
        else if (CurrentMode >= 5)
            Mode = ((CurrentMode - 5) | 0x10);

        if (CurrentMode < 5)
            continue;

        DPRINT("AtapiProgramTransferMode: [%X] setting DMAmode %X\n", ix, CurrentMode);

        Status = AtapiSetTransferMode(HwDeviceExtension, ix, Mode);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("AtapiProgramTransferMode: Unable to set DMA mode %X for %X device %X\n",
                    CurrentMode, HwDeviceExtension->CmdBlock.CmdBlockBase, ix);

            continue;
        }

        HwDeviceExtension->DeviceFlags[ix] |= 0x200;

        if (CurrentMode >= 0xB)
            HwDeviceExtension->DeviceFlags[ix] |= 0x10000;
    }
}

VOID
NTAPI
InitDeviceParameters(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ PUCHAR GetFlushCommand)
{
    PATA_DEVICE_PARAMETERS DeviceParameters;
    ULONG Device;

    for (Device = 0; Device < HwDeviceExtension->MaxIdeDevice; Device++)
    {
        DeviceParameters = &HwDeviceExtension->DeviceParameters[Device];

        if (!(HwDeviceExtension->DeviceFlags[Device] & 1))
            continue;

        DPRINT1("InitDeviceParameters: (%X:%X) is going to do ", HwDeviceExtension->CmdBlock.CmdBlockBase, Device);

        if (HwDeviceExtension->DeviceFlags[Device] & 0x200)
            DbgPrint("DMA\n");
        else
            DbgPrint("PIO\n");

        if (HwDeviceExtension->DeviceFlags[Device] & 2)
        {
            DeviceParameters->MaxTransferSize = 0x200;
            continue;
        }

        if (HwDeviceExtension->MaximumBlockTransfer[Device])
        {
            DPRINT("InitDeviceParameters: [%X] is going to do PIO Multiple\n", Device);

            DeviceParameters->IdePioReadCommand = 0xC4;
            DeviceParameters->IdePioWriteCommand = 0xC5;

            if (HwDeviceExtension->DeviceFlags[Device] & 0x200000)
            {
                DeviceParameters->IdePioReadCommandExt = 0x29;
                DeviceParameters->IdePioWriteCommandExt = 0x39;
            }

            DeviceParameters->MaxTransferSize = (HwDeviceExtension->MaximumBlockTransfer[Device] * 0x200);
        }
        else
        {
            DPRINT("InitDeviceParameters: [%X] is going to do PIO Single\n", Device);

            DeviceParameters->IdePioReadCommand = 0x20;
            DeviceParameters->IdePioWriteCommand = 0x30;

            if (HwDeviceExtension->DeviceFlags[Device] & 0x200000)
            {
                DeviceParameters->IdePioReadCommandExt = 0x24;
                DeviceParameters->IdePioWriteCommandExt = 0x34;
            }

            DeviceParameters->MaxTransferSize = 0x200;
        }

        if (!GetFlushCommand)
            continue;

        if (HwDeviceExtension->DeviceFlags[Device] & 0x200000)
        {
            DeviceParameters->IdePioFlushCommand = 0xFF;
            DeviceParameters->IdePioFlushCommandExt = 0xEA;
        }
        else
        {
            DeviceParameters->IdePioFlushCommand = GetFlushCommand[Device];
        }
    }
}

VOID
NTAPI
IdeMediaStatus(
    _In_ BOOLEAN IsEnable,
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ ULONG Device)
{
    UCHAR IdeError;
    UCHAR IdeStatus;
    ULONG jx;

    DPRINT("IdeMediaStatus: %X, %X, %X\n", HwDeviceExtension->CmdBlock.CmdBlockBase, Device, IsEnable);

    if (IsEnable)
    {
        if (!(HwDeviceExtension->DeviceFlags[Device] & 0x1000))
            return;

        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT));
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Features, 0x95);
        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, 0xEF);

        for (jx = 0; jx < 20000; jx++)
        {
            IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
            if (!(IdeStatus & 0x80))
                break;
            KeStallExecutionProcessor(150);
        }

        if (IdeStatus & 1)
        {
            IdeError = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Error);
            DPRINT("IdeMediaStatus: Error enabling media IdeStatus. Status %X, error %X\n", IdeStatus, IdeError);
        }
        else
        {
            DPRINT("IdeMediaStatus: Media Status Notification Supported\n");

            HwDeviceExtension->DeviceFlags[Device] |= 0x20;
            HwDeviceExtension->CmdErrorCopy = 0;
        }

        return;
    }

    if (!(HwDeviceExtension->DeviceFlags[Device] & 0x20))
        return;

    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT));
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Features, 0x31);
    WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, 0xEF);

    for (jx = 0; jx < 20000; jx++)
    {
        IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
        if (!(IdeStatus & 0x80))
            break;

        KeStallExecutionProcessor(150);
    }

    HwDeviceExtension->DeviceFlags[Device] &= ~0x20;
}

VOID
NTAPI
AtapiHwInitialize(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ PUCHAR GetFlushCommand)
{
    ULONG Device;
    ULONG ix;
    ULONG jx;
    UCHAR IdeStatus;
    UCHAR IdeError;

    DPRINT("AtapiHwInitialize: %X\n", HwDeviceExtension->CmdBlock.CmdBlockBase);

    for (Device = 0; Device < HwDeviceExtension->MaxIdeDevice; Device++)
    {
        if (!(HwDeviceExtension->DeviceFlags[Device] & 1))
            continue;

        WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT));

        if (!(HwDeviceExtension->DeviceFlags[Device] & 2))
        {
            ix = 0;

            while (TRUE)
            {
                for (jx = 0; jx < 25000; jx++)
                {
                    IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
                    if (!(IdeStatus & 0x80))
                        break;

                    KeStallExecutionProcessor(40);
                }

                if (!(IdeStatus & 0x80))
                    break;

                DPRINT("AtapiHwInitialize: after 1 sec wait, device is still busy with %X, IdeStatus %X\n",
                       HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);

                ix++;
                if (ix >= 10)
                {
                    if (IdeStatus & 0x80)
                    {
                        DPRINT("AtapiHwInitialize: WaitOnBusy failed. (%X) IdeStatus %X\n",
                               HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
                    }

                    break;
                }
            }

            for (jx = 0; jx < 20000; jx++)
            {
                IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
                if (IdeStatus & 0x50)
                    break;

                KeStallExecutionProcessor(150);
            }

            if (jx == 20000)
            {
                DPRINT("AtapiHwInitialize: WaitForDRDY failed. (%X) IdeStatus %X\n",
                       HwDeviceExtension->CmdBlock.CmdBlockBase, IdeStatus);
            }
        }

        if (!(HwDeviceExtension->DeviceFlags[Device] & 2))
        {
            IdeMediaStatus(TRUE, HwDeviceExtension, Device);

            if (HwDeviceExtension->MaximumBlockTransfer[Device])
            {
                WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.DeviceSelect, (((Device & 0x1) << 4) | IDE_DRIVE_SELECT));
                WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.SectorCount, HwDeviceExtension->MaximumBlockTransfer[Device]);
                WRITE_PORT_UCHAR(HwDeviceExtension->CmdBlock.Command, 0xC6);

                for (jx = 0; jx < 20000; jx++)
                {
                    IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
                    if (!(IdeStatus & 0x80))
                        break;

                    KeStallExecutionProcessor(150);
                }

                if (IdeStatus & 1)
                {
                    IdeError = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Error);

                    DPRINT("AtapiHwInitialize: IdeError setting multiple mode. Status %X, error byte %X\n", IdeStatus, IdeError);

                    HwDeviceExtension->MaximumBlockTransfer[Device] = 0;
                }
                else
                {
                    DPRINT("AtapiHwInitialize: Using Multiblock on Device %d. Blocks / int - %X\n",
                           Device, HwDeviceExtension->MaximumBlockTransfer[Device]);
                }
            }
        }

        if (!(HwDeviceExtension->DeviceFlags[Device] & 2))
            continue;

        IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);

        for (ix = 0; ix < 10000; ix++)
        {
            if (!(IdeStatus & 0x80))
                break;

            KeStallExecutionProcessor(100);

            IdeStatus = READ_PORT_UCHAR(HwDeviceExtension->CmdBlock.Status);
        }
    }

    AtapiProgramTransferMode(HwDeviceExtension);
    InitDeviceParameters(HwDeviceExtension, GetFlushCommand);
}

VOID
NTAPI
IdeStopQueueCompletionRoutine(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIDE_STOP_QUEUE_CONTEX StopContext,
    _In_ NTSTATUS InStatus)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    KIRQL Irq;

    PdoExtension = StopContext->PdoExtension;
    StopContext->Status = InStatus;

    if (!NT_SUCCESS(InStatus))
    {
        DPRINT("IdeStopQueueCompletionRoutine: unable to stop pdox %p\n", PdoExtension);
    }
    else
    {
        KeAcquireSpinLock(&PdoExtension->PdoLock, &Irq);

        if (StopContext->QueueStopFlag == 0x400)
            PdoExtension->PdoState |= 8;

        PdoExtension->PdoState |= StopContext->QueueStopFlag;

        DPRINT("IdeStopQueueCompletionRoutine: pdo %p is pnp stopped with %X items queued\n", Pdo, PdoExtension->ItemsQueued);

        KeReleaseSpinLock(&PdoExtension->PdoLock, Irq);
    }

    KeSetEvent(&StopContext->Event, IO_NO_INCREMENT, FALSE);
}

NTSTATUS
NTAPI
DeviceStopDeviceQueueSafe(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ ULONG QueueStopFlag,
    _In_ BOOLEAN IsPreAllocStruct)
{
    PATAPI_PRE_ALLOC_ENUM_STRUCT EnumStruct;
    PIDE_STOP_QUEUE_CONTEX Context;
    ULONG RetryCount = 1;
    KIRQL Irql;
    BOOLEAN IsSync = FALSE;
    NTSTATUS Status;

    DPRINT("DeviceStopDeviceQueueSafe: %X\n", PdoExtension->FdoExtension->HwDeviceExtension->CmdBlock.CmdBlockBase);

    ASSERT(QueueStopFlag & 0x1E00);//PDOS_MUST_QUEUE

    if (IsPreAllocStruct)
    {
        ASSERT(InterlockedCompareExchange(&(PdoExtension->FdoExtension->EnumStructLock), 1, 0) == 0);

        EnumStruct = PdoExtension->FdoExtension->PreAllocEnumStruct;
        if (!EnumStruct)
        {
            DPRINT1("DeviceStopDeviceQueueSafe: failed\n");
            ASSERT(EnumStruct);
            return STATUS_NO_MEMORY;
        }

        Context = EnumStruct->StopQueueContext;
        RetryCount = 5;
    }
    else
    {
        Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Context), 'PedI');
        if (!Context)
        {
            DPRINT1("DeviceStopDeviceQueueSafe: Allocate failed\n");
            return STATUS_NO_MEMORY;
        }
    }


    KeAcquireSpinLock(&PdoExtension->PdoLock, &Irql);

    if (PdoExtension->PdoState & 0x1F40)
    {
        PdoExtension->PdoState |= QueueStopFlag;
        IsSync = TRUE;
    }

    KeReleaseSpinLock(&PdoExtension->PdoLock, Irql);

    RtlZeroMemory(Context, sizeof(*Context));

    KeInitializeEvent(&Context->Event, NotificationEvent, FALSE);

    Context->PdoExtension = PdoExtension;
    Context->QueueStopFlag = QueueStopFlag;
    Context->AtaPassThr.IdeReg.bReserved = 0x20;

    if (IsSync)
    {
        Status = STATUS_SUCCESS;
        IdeStopQueueCompletionRoutine(PdoExtension->SelfDevice, Context, Status);
    }
    else
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        do
        {
            if (!RetryCount)
                break;
            RetryCount--;

            Status = IssueAsyncAtaPassThroughSafe(PdoExtension->FdoExtension,
                                                  PdoExtension,
                                                  &Context->AtaPassThr,
                                                  FALSE,
                                                  IdeStopQueueCompletionRoutine,
                                                  Context,
                                                  1,
                                                  0xF,
                                                  IsPreAllocStruct);
            ASSERT(NT_SUCCESS(Status));

            if (Status == STATUS_PENDING)
                KeWaitForSingleObject(&Context->Event, Executive, KernelMode, FALSE, NULL);

            Status = Context->Status;
        }
        while (Status == STATUS_INSUFFICIENT_RESOURCES);
    }

    if (IsPreAllocStruct)
    {
        ASSERT(InterlockedCompareExchange(&(PdoExtension->FdoExtension->EnumStructLock), 0, 1) == 1);
    }
    else
    {
        ExFreePoolWithTag(Context, 'PedI');
    }

    return Status;
}

VOID
NTAPI
DeviceStartDeviceQueue(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ ULONG ResetState)
{
    ULONG PdoState;
    KIRQL Irql;
    BOOLEAN IsItemsQueued;

    KeAcquireSpinLock(&PdoExtension->PdoLock, &Irql);

    PdoState = PdoExtension->PdoState;
    PdoExtension->PdoState = (PdoState & ~ResetState);

    if (PdoExtension->PdoState & 0x40)
    {
        IsItemsQueued = FALSE;
    }
    else if ((PdoState & 0x1E00) != (PdoExtension->PdoState & 0x1E00) && !(PdoExtension->PdoState & 0x1E00))
    {
        IsItemsQueued = TRUE;
    }
    else
    {
        IsItemsQueued = FALSE;
    }

    KeReleaseSpinLock(&PdoExtension->PdoLock, Irql);

    if (!IsItemsQueued)
        return;

    KeAcquireSpinLock(&PdoExtension->FdoExtension->SpinLock, &Irql);
    GetNextLuPendingRequest(PdoExtension->FdoExtension, PdoExtension);
    KeLowerIrql(Irql);

    DPRINT("DeviceStartDeviceQueue: pdo %p is pnp started with %X items queued\n", PdoExtension->SelfDevice, PdoExtension->ItemsQueued);
}

VOID
NTAPI
AtapiHwInitializeMultiLun(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ ULONG TargetId,
    _In_ ULONG NonCdNumLun)
{
    DPRINT("AtapiHwInitializeMultiLun: %X, %X, %X\n", HwDeviceExtension->CmdBlock.CmdBlockBase, TargetId, NonCdNumLun);

    HwDeviceExtension->DeviceFlags[TargetId] |= 0x800;
    HwDeviceExtension->MultiLun[TargetId] = (NonCdNumLun ? (NonCdNumLun - 1) : 0);
}

NTSTATUS
NTAPI
IssueInquirySafe(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PINQUIRYDATA Inquiry,
    _In_ BOOLEAN IsSafe)
{
    CDB Cdb;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IssueInquirySafe: %X, %X\n", PdoExtension->FdoExtension->ResourceData.CmdBlockBase, IsSafe);

    RtlZeroMemory(Inquiry, sizeof(*Inquiry));
    RtlZeroMemory(&Cdb, sizeof(Cdb));

    Cdb.CDB6INQUIRY.OperationCode = 0x12;
    Cdb.CDB6INQUIRY.LogicalUnitNumber = PdoExtension->Lun;
    Cdb.CDB6INQUIRY.AllocationLength = 0x24;

    if (IsSafe)
        Status = IssueSyncAtapiCommandSafe(FdoExtension, PdoExtension, &Cdb, Inquiry, 0x24, TRUE, FALSE);
    else
        Status = IssueSyncAtapiCommand(FdoExtension, PdoExtension, &Cdb, Inquiry, 0x24, TRUE, FALSE);

    return Status;
}

VOID
NTAPI
DeviceInitDeviceType(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PINQUIRYDATA Inquiry)
{
    DPRINT("DeviceInitDeviceType: %p, %X, %X\n", PdoExtension, Inquiry->DeviceType, Inquiry->RemovableMedia);

    PdoExtension->ScsiDeviceType = Inquiry->DeviceType;

    if (Inquiry->RemovableMedia)
        PdoExtension->SelfDevice->Characteristics |= FILE_REMOVABLE_MEDIA;
}

VOID
NTAPI
CopyField(
    _Out_ PUCHAR Destination,
    _In_ PUCHAR Source,
    _In_ ULONG Length,
    _In_ UCHAR DefaultCharacter)
{
    ULONG ix;
    BOOLEAN IsCopyDefault = FALSE;

    PAGED_CODE();
    DPRINT("CopyField: %X\n", Length);

    for (ix = 0; ix < Length; ix++)
    {
        if (IsCopyDefault)
        {
            Destination[ix] = DefaultCharacter;
            continue;
        }

        if (!Source[ix])
        {
            IsCopyDefault = TRUE;
            Destination[ix] = DefaultCharacter;
            continue;
        }

        if (Source[ix] <= ' ' || Source[ix] > 0x7F || Source[ix] == ',')
        {
            Destination[ix] = DefaultCharacter;
            continue;
        }

        Destination[ix] = Source[ix];
    }

    Destination[ix] = 0;
}

VOID
NTAPI
DeviceInitIdStrings(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ ULONG DeviceType,
    _In_ PINQUIRYDATA Inquiry,
    _In_ PIDENTIFY_DATA Identify)
{
    PUCHAR ModelId;
    ULONG SpecialDevice;
    LONG ix;
    UCHAR Swap;

    PAGED_CODE();
    DPRINT("DeviceInitIdStrings: %X, %X\n", PdoExtension->FdoExtension->ResourceData.CmdBlockBase, DeviceType);

    ASSERT(PdoExtension);
    ASSERT(Identify);

    if (DeviceType == 1)
    {
        CopyField(PdoExtension->ModelId, Identify->ModelNumber, 0x28, ' ');
        CopyField(PdoExtension->RevisionId, Identify->FirmwareRevision, 8, ' ' );

        for (ix = 0; ix < (sizeof(PdoExtension->ModelId) - 1); ix += 2)
        {
            Swap = PdoExtension->ModelId[ix];

            PdoExtension->ModelId[ix] = PdoExtension->ModelId[ix + 1];
            PdoExtension->ModelId[ix + 1] = Swap;
        }

        for (ix = 0; ix < 8; ix += 2)
        {
            Swap = PdoExtension->RevisionId[ix];

            PdoExtension->RevisionId[ix] = PdoExtension->RevisionId[ix + 1];
            PdoExtension->RevisionId[ix + 1] = Swap;
        }
    }
    else if (DeviceType == 2)
    {
        DPRINT("DeviceInitIdStrings: (%p) Inquiry '%s', '%s', '%s'\n",
               PdoExtension, Inquiry->VendorId, Inquiry->ProductId, Inquiry->ProductRevisionLevel);

        CopyField(PdoExtension->ModelId, Inquiry->VendorId, 8, ' ');
        ModelId = PdoExtension->ModelId;

        for (ix = 7; ix >= 0; ix--)
        {
            if (ModelId[ix] != ' ')
            {
                ModelId[ix + 1] = ' ';
                ModelId += (ix + 2);
                break;
            }
        }

        CopyField(ModelId, Inquiry->ProductId, 0x10, ' ');
        ModelId += 0x10;

        for (ix = 0; (ULONG_PTR)&ModelId[ix] < (ULONG_PTR)&PdoExtension->ModelId[0x28]; ix++)
            ModelId[ix] = ' ';

        CopyField(PdoExtension->RevisionId, Inquiry->ProductRevisionLevel, 4, ' ');

        for (ix = 4; ix < 8; ++ix)
            PdoExtension->RevisionId[ix] = ' ';
    }
    else
    {
        ASSERT(FALSE);
    }

    for (ix = 0x27; ix >= 0; ix--)
    {
        if (PdoExtension->ModelId[ix] != ' ')
        {
            PdoExtension->ModelId[ix + 1] = 0;
            break;
        }
    }

    for (ix = 7; ix >= 0; ix--)
    {
        if (PdoExtension->RevisionId[ix] != ' ')
        {
            PdoExtension->RevisionId[ix + 1] = 0;
            break;
        }
    }

    UNIMPLEMENTED_ONCE;
    SpecialDevice = 0;//IdeFindSpecialDevice(..);

    if (SpecialDevice != 1 && Identify->SerialNumber[0] != ' ' && Identify->SerialNumber[0] != 0)
    {
        for (ix = 0; ix < 0x14; ix++)
        {
            sprintf((PCHAR)&PdoExtension->SerialNumId[ix * 2], "%2x", Identify->SerialNumber[ix]);
        }

        PdoExtension->SerialNumId[0x28] = 0;
    }
    else
    {
        PdoExtension->SerialNumId[0] = 0;
    }

    DPRINT("DeviceInitIdStrings: (%p) Full IDs '%s', '%s', '%s'\n",
           PdoExtension, PdoExtension->ModelId, PdoExtension->RevisionId, PdoExtension->SerialNumId);
}

VOID
NTAPI
DeviceRegisterIdleDetection(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ ULONG ConservationIdleTime,
    _In_ ULONG PerformanceIdleTime)
{
    ATA_PASS_THROUGH AtaPassThr;
    NTSTATUS Status;
    KIRQL Irql;

    if (PdoExtension->PdoState & 0x80)
        return;

    if (PdoExtension->DumpFile)
        return;

    RtlZeroMemory(&AtaPassThr, sizeof(AtaPassThr));

    AtaPassThr.IdeReg.bCommandReg = 0xE7;
    AtaPassThr.IdeReg.bReserved = 0x50;

    Status = IssueSyncAtaPassThroughSafe(PdoExtension->FdoExtension, PdoExtension, &AtaPassThr, FALSE, FALSE, 0xF, FALSE);

    if (!NT_SUCCESS(Status))
    {
        KeAcquireSpinLock(&PdoExtension->PdoLock, &Irql);
        PdoExtension->PdoState |= 0x80;
        KeReleaseSpinLock(&PdoExtension->PdoLock, Irql);

        DPRINT("DeviceRegisterIdleDetection: Pdoe %p DOES NOT support power managerment command\n", PdoExtension);
    }
    else
    {
        PdoExtension->IdleCounter = PoRegisterDeviceForIdleDetection(PdoExtension->SelfDevice,
                                                                     ConservationIdleTime,
                                                                     PerformanceIdleTime,
                                                                     PowerDeviceD3);

        DPRINT("DeviceRegisterIdleDetection: Pdoe %p support power managerment command\n", PdoExtension);
    }
}

NTSTATUS
NTAPI
IdeCreateNumericKey(
    _In_ HANDLE RootDirectory, 
    _In_ ULONG NumericValue, 
    _In_ PWSTR NameString, 
    _In_ HANDLE* OutHanle)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING NumericKeyUs;
    UNICODE_STRING ObjectName;
    WCHAR ObjectNameBuffer[0x40];
    WCHAR Buffer[0x10];
    ULONG Disposition;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IdeCreateNumericKey: '%S'\n", NameString);

    ObjectName.Length = 0;
    ObjectName.MaximumLength = 0x40;
    ObjectName.Buffer = ObjectNameBuffer;

    RtlInitUnicodeString(&NumericKeyUs, NameString);
    RtlCopyUnicodeString(&ObjectName, &NumericKeyUs);

    NumericKeyUs.Length = 0;
    NumericKeyUs.MaximumLength = 0x10;
    NumericKeyUs.Buffer = Buffer;

    Status = RtlIntegerToUnicodeString(NumericValue, 10, &NumericKeyUs);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IdeCreateNumericKey: Status %X\n", Status);
        return Status;
    }

    RtlAppendUnicodeStringToString(&ObjectName, &NumericKeyUs);

    InitializeObjectAttributes(&ObjectAttributes, &ObjectName, OBJ_CASE_INSENSITIVE, RootDirectory, NULL);

    return ZwCreateKey(OutHanle, 0x2001F, &ObjectAttributes, 0, NULL, REG_OPTION_VOLATILE, &Disposition);
}

VOID
NTAPI
IdeBuildDeviceMap(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PATAPI_DRIVER_EXTENSION DriverExtension)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING ObjectName;
    HANDLE NumericKeyHandle;
    HANDLE KeyHandle;
    ULONG Disposition;
    ULONG DMAEnabled;
    ULONG ix;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IdeBuildDeviceMap: %X\n", FdoExtension->ResourceData.CmdBlockBase);

    RtlInitUnicodeString(&ObjectName, L"\\Registry\\Machine\\Hardware\\DeviceMap\\Scsi");
    InitializeObjectAttributes(&ObjectAttributes, &ObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwCreateKey(&KeyHandle, 0x2001F, &ObjectAttributes, 0, NULL, REG_OPTION_VOLATILE, &Disposition);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IdeBuildDeviceMap: Status %X\n", Status);
        return;
    }

    Status = IdeCreateNumericKey(KeyHandle, FdoExtension->ScsiPortCount, L"Scsi Port ", &NumericKeyHandle);
    ZwClose(KeyHandle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IdeBuildDeviceMap: Status %X\n", Status);
        return;
    }

    DMAEnabled = 0;

    for (ix = 0; ix < FdoExtension->HwDeviceExtension->MaxIdeDevice; ix++)
    {
        if (FdoExtension->HwDeviceExtension->DeviceFlags[ix] & 0x200)
            DMAEnabled |= (1 << ix);
    }

    RtlInitUnicodeString(&ObjectName, L"DMAEnabled");
    ZwSetValueKey(NumericKeyHandle, &ObjectName, 0, 4, &DMAEnabled, 4);

    if (DriverExtension)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    UNIMPLEMENTED_DBGBREAK();
}

BOOLEAN
NTAPI
IdePortSlaveIsGhost(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PIDENTIFY_DATA Identify1,
    _In_ PIDENTIFY_DATA Identify2)
{
    PAGED_CODE();
    DPRINT("IdePortSlaveIsGhost: scan bus %X\n", FdoExtension->ResourceData.CmdBlockBase);

    if (RtlCompareMemory(Identify1->ModelNumber, Identify2->ModelNumber, 0x28) != 0x28)
        return FALSE;

    if (!IdePortSearchDeviceInRegMultiSzList(FdoExtension, Identify1, L"GhostSlave"))
        return FALSE;

    DPRINT("IdePortSlaveIsGhost: Found a ghost slave\n");

    return TRUE;
}

NTSTATUS
NTAPI
SyncAtapiSafeCompletion(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context)
{
    PKEVENT Event = Context;
    KeSetEvent(Event, 0, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
IssueSyncAtapiCommandSafe(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PCDB Cdb,
    _In_ PVOID DataBuffer,
    _In_ ULONG DataBufferSize,
    _In_ BOOLEAN IsDataIn,
    _In_ BOOLEAN IsBypassFrozen)
{
    PATAPI_PRE_ALLOC_ENUM_STRUCT EnumStruct;
    PIO_STACK_LOCATION IoStack;
    PSCSI_REQUEST_BLOCK Srb;
    KEVENT Event;
    PIRP Irp;
    ULONG FlushCount;
    ULONG ix;
    KIRQL Irql;
    NTSTATUS Status;

    DPRINT("IssueSyncAtapiCommandSafe: %X\n", FdoExtension->ResourceData.CmdBlockBase);

    ASSERT(InterlockedCompareExchange(&(FdoExtension->EnumStructLock), 1, 0) == 0);

    EnumStruct = FdoExtension->PreAllocEnumStruct;
    if (!EnumStruct)
    {
        ASSERT(FdoExtension->PreAllocEnumStruct);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ASSERT(EnumStruct->SenseInfoBuffer);

    DPRINT("IssueSyncAtapiCommandSafe: Using Sync Atapi safe!\n");

    Srb = EnumStruct->Srb;
    ASSERT(Srb);

    Irp = EnumStruct->Irp;
    ASSERT(Irp);

    ASSERT(EnumStruct->DataBufferSize >= DataBufferSize);

    FlushCount = 100;
    ix = 5;

    Status = STATUS_UNSUCCESSFUL;
    while (!NT_SUCCESS(Status))
    {
        ix--;
        if (!ix)
            break;

        KeInitializeEvent(&Event, NotificationEvent, FALSE);

        IoInitializeIrp(Irp, IoSizeOfIrp(1), 1); 
        Irp->MdlAddress = EnumStruct->Mdl;

        IoStack = IoGetNextIrpStackLocation(Irp);
        IoStack->MajorFunction = IRP_MJ_SCSI;
        IoStack->Parameters.Scsi.Srb = Srb;

        if (DataBuffer)
            RtlCopyMemory(EnumStruct->DataBuffer, DataBuffer, DataBufferSize);

        RtlZeroMemory(Srb, sizeof(*Srb));

        Srb->Function = 0;
        Srb->Length = sizeof(*Srb);

        Srb->PathId = PdoExtension->PathId;
        Srb->TargetId = PdoExtension->TargetId;
        Srb->Lun = PdoExtension->Lun;

        Srb->SrbFlags = 8;

        if (IsDataIn)
            Srb->SrbFlags |= 0x40;
        else
            Srb->SrbFlags |= 0x80;

        if (IsBypassFrozen)
            Srb->SrbFlags |= 0x10;

        Srb->OriginalRequest = Irp;
        Srb->NextSrb = NULL;

        Srb->ScsiStatus = 0;
        Srb->SrbStatus = 0;

        if (Cdb->CDB10.OperationCode == 0x28)
            Srb->TimeOutValue = 0xA;
        else
            Srb->TimeOutValue = 4;

        Srb->CdbLength = 6;

        Srb->SenseInfoBuffer = EnumStruct->SenseInfoBuffer;
        Srb->SenseInfoBufferLength = 0x12;

        Srb->DataBuffer = MmGetMdlVirtualAddress(Irp->MdlAddress);
        Srb->DataTransferLength = DataBufferSize;

        RtlCopyMemory(Srb->Cdb, Cdb, sizeof(Srb->Cdb));

        IoSetCompletionRoutine(Irp, SyncAtapiSafeCompletion, &Event, TRUE, TRUE, TRUE);

        if (IoCallDriver(PdoExtension->SelfDevice, Irp) == STATUS_PENDING)
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

        RtlCopyMemory(DataBuffer, Srb->DataBuffer, DataBufferSize);

        if ((Srb->SrbStatus & 0x3F) == 1)
        {
            Status = STATUS_SUCCESS;
            continue;
        }

        DPRINT("IssueSyncAtapiCommandSafe: atapi command failed SRB status %X\n", Srb->SrbStatus);

        if ((Srb->SrbStatus & 0x3F) == 0x16)
        {
            FlushCount--;
            if (FlushCount)
                ix++;
        }

        if ((Srb->SrbStatus & 0x3F) != 0x12)
            Status = STATUS_UNSUCCESSFUL;
        else
            Status = STATUS_DATA_OVERRUN;

        if (Srb->SrbStatus & 0x40)
        {
            DPRINT("IssueSyncAtapiCommandSafe: Unfreeze Queue TID %X\n", Srb->TargetId);

            PdoExtension->PdoFlags &= ~1;

            KeAcquireSpinLock(&FdoExtension->SpinLock, &Irql);
            GetNextLuRequest2(FdoExtension, PdoExtension, __FILE__, __LINE__);
            KeLowerIrql(Irql);
        }

        if ((Srb->SrbStatus & 0x80) && (EnumStruct->SenseInfoBuffer->FileMark & 0xF) == 5)
        {
            ix = 0;
            Status = STATUS_INVALID_DEVICE_REQUEST;
        }
    }

    if (FlushCount != 100)
        DPRINT("IssueSyncAtapiCommandSafe: FlushCount is %X\n", FlushCount);

    ASSERT(InterlockedCompareExchange(&(FdoExtension->EnumStructLock), 0, 1) == 1);

    DPRINT("IssueSyncAtapiCommandSafe: ret %X\n", Status);
    return Status;
}

NTSTATUS
NTAPI
IssueSyncAtapiCommand(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PCDB Cdb,
    _In_ PVOID DataBuffer,
    _In_ ULONG DataBufferSize,
    _In_ BOOLEAN IsDataIn,
    _In_ BOOLEAN IsBypassFrozen)
{
    IO_STATUS_BLOCK IoStatusBlock;
    SCSI_REQUEST_BLOCK Srb;
    PSENSE_DATA SenseInfo;
    PIRP Irp;
    KEVENT Event;
    ULONG IoControlCode;
    ULONG FlushCount;
    ULONG ix;
    UCHAR SrbStatus;
    KIRQL Irql;
    NTSTATUS Status;

    DPRINT("IssueSyncAtapiCommand: %X\n", FdoExtension->ResourceData.CmdBlockBase);

    SenseInfo = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, sizeof(*SenseInfo), 'PedI');
    if (!SenseInfo)
    {
        DPRINT1("IssueSyncAtapiCommand: Can't allocate request sense buffer\n");
        UNIMPLEMENTED_DBGBREAK();
        //IdePortLogNoMemoryErrorFn(..);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = STATUS_UNSUCCESSFUL;

    FlushCount = 0x64; // 100

    ix = 5;
    do
    {
        if (!ix--)
            break;

        KeInitializeEvent(&Event, NotificationEvent, FALSE);

        IoControlCode = (IsDataIn ? IOCTL_SCSI_EXECUTE_IN : IOCTL_SCSI_EXECUTE_OUT);

        Irp = IoBuildDeviceIoControlRequest(IoControlCode,
                                            FdoExtension->SelfDevice,
                                            DataBuffer,
                                            DataBufferSize,
                                            DataBuffer,
                                            DataBufferSize,
                                            TRUE,
                                            &Event,
                                            &IoStatusBlock);
        if (!Irp)
        {
            UNIMPLEMENTED_DBGBREAK();
            //IdePortLogNoMemoryErrorFn(..);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        IoGetNextIrpStackLocation(Irp)->Parameters.Scsi.Srb = &Srb;

        RtlZeroMemory(&Srb, sizeof(Srb));

        Srb.PathId = PdoExtension->PathId;
        Srb.TargetId = PdoExtension->TargetId;
        Srb.Lun = PdoExtension->Lun;

        Srb.Function = 0;
        Srb.Length = 0x40;

        Srb.SrbFlags = 0x108;
        Srb.SrbFlags = (IsDataIn != 0 ? 0x40 : 0x80);

        if (IsBypassFrozen)
            Srb.SrbFlags |= 0x10;

        Srb.NextSrb = NULL;
        Srb.OriginalRequest = Irp;

        Srb.ScsiStatus = 0;
        Srb.SrbStatus = 0;

        if (Cdb->CDB6GENERIC.OperationCode == 0x28)
            Srb.TimeOutValue = 0xA;
        else
            Srb.TimeOutValue = 4;

        Srb.CdbLength = 6;

        Srb.SenseInfoBuffer = SenseInfo;
        Srb.SenseInfoBufferLength = sizeof(*SenseInfo);

        Srb.DataBuffer = MmGetMdlVirtualAddress(Irp->MdlAddress);
        Srb.DataTransferLength = DataBufferSize;

        RtlCopyMemory(Srb.Cdb, Cdb, sizeof(Srb.Cdb));

        if (IoCallDriver(PdoExtension->SelfDevice, Irp) == STATUS_PENDING)
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

        DPRINT("IssueSyncAtapiCommand: Srb.SrbStatus %X\n", Srb.SrbStatus);

        if ((Srb.SrbStatus & 0x3F) == 1)
        {
            Status = STATUS_SUCCESS;
            continue;
        }

        DPRINT("IssueSyncAtapiCommand: atapi command failed SRB status %X\n", Srb.SrbStatus);

        SrbStatus = (Srb.SrbStatus & 0x3F);
        if (SrbStatus == 0x16)
        {
            FlushCount--;
            if (FlushCount)
                ix++;
        }

        Status = (SrbStatus != 0x12 ? STATUS_UNSUCCESSFUL : STATUS_DATA_OVERRUN);

        if (Srb.SrbStatus & 0x40)
        {
            UNIMPLEMENTED_ONCE;//ASSERT((Srb.SrbStatus & 0x40) == 0);//SRB_STATUS_QUEUE_FROZEN

            DPRINT("IssueSyncAtapiCommand: Unfreeze Queue TID %X\n", Srb.TargetId);

            PdoExtension->PdoFlags &= ~1;

            KeAcquireSpinLock(&FdoExtension->SpinLock, &Irql);
            GetNextLuRequest2(FdoExtension, PdoExtension, __FILE__, __LINE__);
            KeLowerIrql(Irql);
        }

        if ((Srb.SrbStatus & 0x80) && SenseInfo->SenseKey == 5)
        {
            Status = STATUS_INVALID_DEVICE_REQUEST;
            ix = 0;
        }
    }
    while (!NT_SUCCESS(Status));

    ExFreePoolWithTag(SenseInfo, 'PedI');

    if (FlushCount != 0x64)
    {
        DPRINT("IssueSyncAtapiCommand: flushCount is %X\n", FlushCount);
    }

    return Status;
}

BOOLEAN
NTAPI
IdePortVerifyDma(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ ULONG DeviceType)
{
    INQUIRYDATA Source1;
    INQUIRYDATA Source2;
    PVOID ReadBuffer;
    CDB Cdb;
    LONG DmaTimeouts;
    NTSTATUS Status;
    BOOLEAN Result = TRUE;

    DPRINT1("IdePortVerifyDma: %p, %X\n", PdoExtension, DeviceType);

    if (PdoExtension->DmaTimeouts >= 6)
    {
        Result = FALSE;
        goto ErrorExit;
    }

    if (DeviceType == 2)
    {
        Status = IssueInquirySafe(PdoExtension->FdoExtension, PdoExtension, &Source1, FALSE);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("IdePortVerifyDma: Status %X\n", Status);
            return Result;
        }

        DmaTimeouts = InterlockedExchange(&PdoExtension->DmaTimeouts, 6);

        Status = IssueInquirySafe(PdoExtension->FdoExtension, PdoExtension, &Source2, FALSE);

        if (!NT_SUCCESS(Status) || RtlCompareMemory(&Source1, &Source2, sizeof(INQUIRYDATA)) == sizeof(INQUIRYDATA))
        {
            DPRINT1("IdePortVerifyDma: Status %X\n", Status);
            InterlockedExchange(&PdoExtension->DmaTimeouts, DmaTimeouts);
            return Result;
        }

        Result = FALSE;
        goto ErrorExit;
    }

    if (DeviceType != 1)
        return Result;

    ReadBuffer = ExAllocatePoolWithTag(NonPagedPool, (2 * 0x200), 'PedI');
    if (!ReadBuffer)
    {
        return Result;
    }

    RtlZeroMemory(&Cdb, sizeof(Cdb));

    Cdb.CDB10.OperationCode = SCSIOP_READ;
    Cdb.CDB10.TransferBlocksLsb = 1;

    Status = IssueSyncAtapiCommandSafe(PdoExtension->FdoExtension,
                                       PdoExtension,
                                       &Cdb,
                                       ReadBuffer,
                                       0x200,
                                       TRUE,
                                       FALSE);
    if (NT_SUCCESS(Status))
    {
        RtlZeroMemory(&Cdb, sizeof(Cdb));

        Cdb.CDB10.OperationCode = SCSIOP_READ;
        Cdb.CDB10.TransferBlocksLsb = 1;

        DmaTimeouts = InterlockedExchange(&PdoExtension->DmaTimeouts, 6);

        Status = IssueSyncAtapiCommand(PdoExtension->FdoExtension,
                                       PdoExtension,
                                       &Cdb,
                                       Add2Ptr(ReadBuffer, 0x200),
                                       0x200,
                                       TRUE,
                                       FALSE);

        if (!NT_SUCCESS(Status) || RtlCompareMemory(ReadBuffer, Add2Ptr(ReadBuffer, 0x200), 0x200) == 0x200)
            InterlockedExchange(&PdoExtension->DmaTimeouts, DmaTimeouts);
        else
            Result = FALSE;
    }

    DPRINT1("IdePortVerifyDma: Status %X\n", Status);

    ExFreePoolWithTag(ReadBuffer, 'PedI');

    if (Result)
        return Result;

ErrorExit:

    DPRINT1("IdePortVerifyDma: system and/or device lies about its dma capability. pdoe %p\n", PdoExtension);
    UNIMPLEMENTED_DBGBREAK();

    return Result;
}

BOOLEAN
NTAPI
IdePortInSetup(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    RTL_QUERY_REGISTRY_TABLE QueryTable[2];
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING ObjectName;
    ULONG OobeInProgress;
    ULONG SetupInProgress = 0;
    HANDLE KeyHandle;
    BOOLEAN IsBootSetup = TRUE;
    NTSTATUS Status;

    PAGED_CODE();

    RtlInitUnicodeString(&ObjectName, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\setupdd");
    InitializeObjectAttributes(&ObjectAttributes, &ObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    DPRINT("IdePortInSetup: Status %X\n", Status);

    if (NT_SUCCESS(Status))
        ZwClose(KeyHandle);
    else
        IsBootSetup = FALSE;

    RtlInitUnicodeString(&ObjectName, L"\\Registry\\Machine\\System\\setup");
    InitializeObjectAttributes(&ObjectAttributes, &ObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    DPRINT("IdePortInSetup: Status %X\n", Status);
    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    RtlZeroMemory(QueryTable, sizeof(QueryTable));

    OobeInProgress = 0;

    QueryTable[0].EntryContext = &OobeInProgress;
    QueryTable[0].DefaultData = &OobeInProgress;
    QueryTable[0].QueryRoutine = NULL;
    QueryTable[0].Flags = 0x34;
    QueryTable[0].Name = L"OobeInProgress";
    QueryTable[0].DefaultType = 4;
    QueryTable[0].DefaultLength = 4;

    RtlQueryRegistryValues(RTL_REGISTRY_HANDLE, KeyHandle, QueryTable, NULL, NULL);

    DPRINT("IdePortInSetup: OobeInProgress %X\n", OobeInProgress);

    if (OobeInProgress)
    {
        ZwClose(KeyHandle);
        goto Exit;
    }

    RtlZeroMemory(QueryTable, sizeof(QueryTable));

    QueryTable[0].EntryContext = &SetupInProgress;
    QueryTable[0].DefaultData = &SetupInProgress;
    QueryTable[0].QueryRoutine = NULL;
    QueryTable[0].Flags = 0x34;
    QueryTable[0].Name = L"SystemSetupInProgress";
    QueryTable[0].DefaultType = 4;
    QueryTable[0].DefaultLength = 4;

    RtlQueryRegistryValues(RTL_REGISTRY_HANDLE, KeyHandle, QueryTable, NULL, NULL);
    DPRINT("IdePortInSetup: SetupInProgress %X\n", SetupInProgress);

    ZwClose(KeyHandle);

Exit:

    return (IsBootSetup || SetupInProgress);
}

ULONG
NTAPI
IdePortQueryNonCdNumLun(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ BOOLEAN IsBypassFrozen)
{
    PMODE_PARAMETER_HEADER10 Header;
    CDB Cdb;
    ULONG Size;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IdePortQueryNonCdNumLun: %X, %X\n", FdoExtension->ResourceData.CmdBlockBase, IsBypassFrozen);

    Size = (sizeof(*Header) + 0xC);

    Header = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, Size, 'PedI');
    if (!Header)
    {
        DPRINT1("IdePortQueryNonCdNumLun: Can't allocate Header buffer\n");
        return 0;
    }

    RtlZeroMemory(Header, Size);
    RtlZeroMemory(&Cdb, sizeof(Cdb));

    Cdb.MODE_SENSE10.OperationCode = 0x5A;
    Cdb.MODE_SENSE10.PageCode = 0x1B;
    Cdb.MODE_SENSE10.AllocationLength[1] = Size;

    Status = IssueSyncAtapiCommand(FdoExtension, PdoExtension, &Cdb, Header, Size, TRUE, IsBypassFrozen);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IdePortQueryNonCdNumLun: Status %X\n", Status);
        goto Exit;
    }

    UNIMPLEMENTED_DBGBREAK();
    return 0;

Exit:

    ExFreePoolWithTag(Header, 'PedI');

    if (!NT_SUCCESS(Status))
    {
        return 0;
    }

    return 2;
}

BOOLEAN
NTAPI
IdePortDmaCdromDrive(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ BOOLEAN IsSafe)
{
    PCDVD_CAPABILITIES_PAGE Capabilities;
    PVOID Buffer;
    CDB Cdb;
    BOOLEAN Result = FALSE;
    NTSTATUS Status;

    DPRINT("IdePortDmaCdromDrive: %X, %X\n", FdoExtension->ResourceData.CmdBlockBase, IsSafe);

    Buffer = ExAllocatePoolWithTag(NonPagedPoolCacheAligned, 0x20, 'PedI');
    if (!Buffer)
    {
        DPRINT1("IdePortDmaCdromDrive: Allocate failed\n");
        return FALSE;
    }
    RtlZeroMemory(Buffer, 0x20);

    RtlZeroMemory(&Cdb, sizeof(Cdb));

    Cdb.MODE_SENSE10.OperationCode = 0x5A;
    Cdb.MODE_SENSE10.Dbd = 1;
    Cdb.MODE_SENSE10.PageCode = 0x2A;
    Cdb.MODE_SENSE10.AllocationLength[0] = 0;
    Cdb.MODE_SENSE10.AllocationLength[1] = 0x20;

    if (IsSafe)
        Status = IssueSyncAtapiCommandSafe(FdoExtension, PdoExtension, &Cdb, Buffer, 0x20, TRUE, FALSE);
    else
        Status = IssueSyncAtapiCommand(FdoExtension, PdoExtension, &Cdb, Buffer, 0x20, TRUE, FALSE);

    if (!NT_SUCCESS(Status) && Status != STATUS_DATA_OVERRUN)
    {
        DPRINT1("IdePortDmaCdromDrive: Status %X\n", Status);
        goto Exit;
    }

    Capabilities = Add2Ptr(Buffer, sizeof(MODE_PARAMETER_HEADER10));

    if (Capabilities->PageCode != 0x2A)
    {
        DPRINT1("IdePortDmaCdromDrive: PageCode %X\n", Capabilities->PageCode);
        goto Exit;
    }

    if (Capabilities->CDRWrite ||
        Capabilities->CDEWrite ||
        Capabilities->DVDROMRead ||
        Capabilities->DVDRRead ||
        Capabilities->DVDRAMRead ||
        Capabilities->DVDRWrite ||
        Capabilities->DVDRAMWrite)
    {
        Result = TRUE;
    }

Exit:

    ExFreePoolWithTag(Buffer, 'PedI');

    return Result;
} 

VOID
NTAPI
IdePortScanBus(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    //PATAPI_DRIVER_EXTENSION DriverExtension; 
    PATA_DEVICE_EXTENSION HwDeviceExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    PVOID ImageSectionHandle;
    ATA_SCSI_ADDRESS ScsiAddress;
    ATA_PASS_THROUGH AtaPassThr;
    IDENTIFY_DATA Identify[4];
    INQUIRYDATA Inquiry;
    ULONG RegTimingModeAllowed[4];
    ULONG RegTransferMode[4];
    ULONG SpecialDevice[4];
    ULONG DeviceType[4];
    ULONG SelectedMode;
    ULONG NonCdNumLun;
    ULONG RegCheckSum;
    ULONG checkSum[4];
    ULONG CheckSum;
    ULONG TMAllowed;
    ULONG TMMask;
    ULONG ix;
    ULONG jx;
    BOOLEAN IsPioByDefaultDevice[4];
    BOOLEAN IsNonRemovableMedia[4];
    BOOLEAN IsEqualCheckSum[4];
    BOOLEAN IsNoPowerDown[4];
    BOOLEAN IsMustBePio[4];
    BOOLEAN IsLs120[4];
    BOOLEAN IsEmptyChannelCheck;
    BOOLEAN IsNewDevice;
    BOOLEAN IsInSetup;
    UCHAR GetFlushCommand[4];
    KIRQL Irql;
    NTSTATUS Status;

    ImageSectionHandle = MmLockPagableDataSection(IdePortScanBus);

    ASSERT(FdoExtension);
    ASSERT(FdoExtension->PreAllocEnumStruct);

    HwDeviceExtension = FdoExtension->HwDeviceExtension;

    if (!FdoExtension->InterruptObject)
    {
        DPRINT1("IdePortScanBus: no InterruptObject for %p\n", FdoExtension);

        if (!IdePortChannelEmpty(&HwDeviceExtension->CmdBlock, &HwDeviceExtension->CtrlBlock, HwDeviceExtension->MaxIdeDevice))
        {
            if (FdoExtension->ProperResources.ChannelRequestProperResources)
                FdoExtension->ProperResources.ChannelRequestProperResources(FdoExtension->LowPdo);
            else
                DPRINT1("IdePortScanBus: no interface to request resources. Probably a pcmcia parent\n");
        }

        goto Exit;
    }

    DPRINT("IdePortScanBus: scan bus %X\n", FdoExtension->ResourceData.CmdBlockBase);

    IsInSetup = IdePortInSetup(FdoExtension);
    DPRINT("IdePortScanBus: IsInSetup %X\n", IsInSetup);

    IsEmptyChannelCheck = TRUE;
    ScsiAddress.AsULONG = 0;

    for (ix = 0; ix < HwDeviceExtension->MaxIdeTargetId; ix++)
    {
        ScsiAddress.Lun = 0;
        ScsiAddress.TargetId = ix;

        DPRINT("IdePortScanBus: (%X) scan %X:%X:%X\n", FdoExtension->ResourceData.CmdBlockBase, ScsiAddress.PathId, ScsiAddress.TargetId, ScsiAddress.Lun);

        PdoExtension = RefLogicalUnitExtension(FdoExtension,
                                               ScsiAddress.PathId,
                                               ScsiAddress.TargetId,
                                               ScsiAddress.Lun,
                                               TRUE,
                                               IdePortScanBus);
        if (PdoExtension)
        {
            if (PdoExtension->PdoState & 0x40)
            {
                UNIMPLEMENTED_DBGBREAK();
            }

            IsNewDevice = FALSE;
        }
        else
        {
            PdoExtension = AllocatePdo(FdoExtension, ScsiAddress, IdePortScanBus);
            IsNewDevice = TRUE;
        }

        DPRINT("IdePortScanBus: IsNewDevice %X\n", IsNewDevice);

        if (PdoExtension)
        {
            if (IsEmptyChannelCheck)
            {
                IsEmptyChannelCheck = FALSE;

                RtlZeroMemory(&AtaPassThr, sizeof(AtaPassThr));
                AtaPassThr.IdeReg.bReserved = 4;

                Status = IssueSyncAtaPassThroughSafe(FdoExtension, PdoExtension, &AtaPassThr, 0, 0, 0x1E, TRUE);//30

                DPRINT("IdePortScanBus: Empty Channel check for fdoe %p took 0 ms\n", FdoExtension);
            }

            DPRINT("IdePortScanBus: Status %X\n", Status);

            if (NT_SUCCESS(Status))
            {
                DPRINT("IdePortScanBus: IdeDevicePresent %X detected no device %X\n",
                       FdoExtension->ResourceData.CmdBlockBase, ix);

                IdePortSaveDeviceParameter(FdoExtension, TypeName[PdoExtension->TargetId], 0);
                DeviceType[ix] = 3;
            }
            else
            {
                DeviceType[ix] = AtapiDetectDevice(FdoExtension, PdoExtension, &Identify[ix], TRUE);

                if (DeviceType[ix] == 3)
                {
                    DPRINT("IdePortScanBus: Didn't detect the device %X\n", ix);
                }
                else
                {
                    HwDeviceExtension->DeviceFlags[ix] |= 1;

                    if (DeviceType[ix] == 2)
                        HwDeviceExtension->DeviceFlags[ix] |= 2;

                    /* FIXME IdeFindSpecialDevice() for names:
                       "TOSHIBA CD-ROM XM-1702B"
                       "TOSHIBA CD-ROM XM-6202B"
                       "COMPAQ DVD-ROM DRD-U424"
                       "           "
                       "KENWOOD CD-ROM"
                       "MEMORYSTICK"
                    */
                    SpecialDevice[ix] = 0;
                    if (SpecialDevice[ix] == 2)
                    {
                        UNIMPLEMENTED_ONCE;
                    }
                }
            }

            DPRINT("IdePortScanBus: Detect device %X for %X took 0 ms\n", ix, FdoExtension->ResourceData.CmdBlockBase);

            ASSERT(DeviceType[ix] <= 3);//DeviceNotExist
            ASSERT(DeviceType[ix] != 0);//DeviceUnknown
            ASSERT(PdoExtension->TargetId == ix);

            if (DeviceType[ix] != 3 && (ix & 1) && DeviceType[ix - 1] != 3)
            {
                if (IdePortSlaveIsGhost(FdoExtension, &Identify[ix - 1], &Identify[ix]))
                    DeviceType[ix] = 3;
            }

            ASSERT(DeviceType[ix] <= 3);//DeviceNotExist

            CheckSum = IdePortSimpleCheckSum(0, Identify[ix].ModelNumber, 0x28);
            CheckSum += IdePortSimpleCheckSum(CheckSum, Identify[ix].SerialNumber, 0x14);
            CheckSum += IdePortSimpleCheckSum(CheckSum, Identify[ix].FirmwareRevision, 8);

            checkSum[ix] = CheckSum;

            if (IsNewDevice)
            {
                FdoExtension->IsNeedUpdate = TRUE;
                DPRINT("IdePortScanBus: Found a new device. pdoe %p\n", PdoExtension);
            }
            else if (checkSum[ix] != PdoExtension->DataCheckSum)
            {
                DPRINT("IdePortScanBus: bad bad bad user. A device is replaced by a different device. pdoe %p\n", PdoExtension);
                UNIMPLEMENTED_DBGBREAK();
            }

            ASSERT(DeviceType[ix] <= 3);//DeviceNotExist

            if (DeviceType[ix] != 3)
            {
                IsMustBePio[ix] = IdePortMustBePio(FdoExtension, &Identify[ix]);
                IsPioByDefaultDevice[ix] = IdePortPioByDefaultDevice(FdoExtension, &Identify[ix]);

                ASSERT(DeviceType[ix] <= 3);//DeviceNotExist

                if (DeviceType[ix] != 2)
                    GetFlushCommand[ix] = IdePortGetFlushCommand(FdoExtension, PdoExtension, &Identify[ix]);
                else
                    GetFlushCommand[ix] = 0xFF;

                DPRINT("IdePortScanBus: Flush command for device %X at %X took 0 ms\n",
                       ix, FdoExtension->ResourceData.CmdBlockBase);

                ASSERT(DeviceType[ix] <= 3);//DeviceNotExist

                IsNonRemovableMedia[ix] = IdePortDeviceHasNonRemovableMedia(FdoExtension, &Identify[ix]);

                ASSERT(DeviceType[ix] <= 3);//DeviceNotExist

                IsLs120[ix] = IdePortDeviceIsLs120(FdoExtension, &Identify[ix]);

                ASSERT(DeviceType[ix] <= 3);//DeviceNotExist

                IsNoPowerDown[ix] = IdePortNoPowerDown(FdoExtension, &Identify[ix]);

                ASSERT(DeviceType[ix] <= 3);//DeviceNotExist

                FdoExtension->UserChoiceTransferMode[ix] = 0x12345678;

                IdePortGetDeviceParameter(FdoExtension, UserTimingModeAllowedName[ix], &FdoExtension->UserChoiceTransferMode[ix]);

                if (FdoExtension->UserChoiceTransferMode[ix] == 0x12345678)
                {
                    FdoExtension->UserChoiceTransferMode[ix] = 0x7FFFFFFF;
                    FdoExtension->UserChoiceAtapiTransferMode[ix] = 0x1F;
                }
                else
                {
                    FdoExtension->UserChoiceAtapiTransferMode[ix] = 0xFFFFFFFF;
                }

                IdePortGetDeviceParameter(FdoExtension, TimingModeName[ix], &RegTransferMode[ix]);

                RegCheckSum = 0;
                IdePortGetDeviceParameter(FdoExtension, DataCheckSumName[ix], &RegCheckSum);

                ASSERT(DeviceType[ix] <= 3);//DeviceNotExist

                RegTimingModeAllowed[ix] = 0xFFFFFFFF;

                if (RegCheckSum == checkSum[ix])
                {
                    IdePortGetDeviceParameter(FdoExtension, TimingModeAllowedName[ix], &RegTimingModeAllowed[ix]);
                    IsEqualCheckSum[ix] = TRUE;
                }
                else
                {
                    IsEqualCheckSum[ix] = FALSE;
                }

                ASSERT(DeviceType[ix] <= 3);//DeviceNotExist

                TMAllowed = (FdoExtension->UserChoiceTransferMode[ix] & RegTimingModeAllowed[ix]);
                TMMask = HwDeviceExtension->DeviceParameters[ix].XferMaskMode;

                FdoExtension->TMAllowed[ix] = (TMAllowed & ~TMMask);

                if (PdoExtension->CrcErrors >= 6)
                    PdoExtension->CrcErrors = 0;

                DPRINT("IdePortScanBus: TMAllowed %X, TMMask %X, UserChoice %X\n",
                       FdoExtension->TMAllowed[ix], TMMask, FdoExtension->UserChoiceTransferMode[ix]);

                ASSERT(DeviceType[ix] <= 3);//DeviceNotExist

                if (DeviceType[ix] == 2)
                {
                    if (IsInSetup)
                        IsMustBePio[ix] = TRUE;

                    if (SpecialDevice[ix] != 3 && !IsMustBePio[ix] && !IsPioByDefaultDevice[ix])
                    {
                        if (IdePortDmaCdromDrive(FdoExtension, PdoExtension, TRUE))
                        {
                            DPRINT("IdePortScanBus: USE DMA FOR ix %d\n", ix);
                            FdoExtension->UserChoiceAtapiTransferMode[ix] = 0xFFFFFFFF;
                        }
                    }

                    FdoExtension->TMAllowed[ix] &= FdoExtension->UserChoiceAtapiTransferMode[ix];
                }
            }

            if (IsNewDevice)
                FreePdo(PdoExtension, TRUE, TRUE, IdePortScanBus);
            else
                UnrefLogicalUnitExtension(FdoExtension, PdoExtension, IdePortScanBus);
        }
        else
        {
            DPRINT("IdePortScanBus() is unable to get pdo (%X,%X,%X)\n",
                   ScsiAddress.PathId, ScsiAddress.TargetId, ScsiAddress.Lun);

            DeviceType[ix] = 3;
        }
    }

    FdoExtension->IsBigLbaEnabled = TRUE;

    DPRINT("IdePortScanBus: detect a change of device...re-initializing\n");

    ScsiAddress.AsULONG = 0;
    Status = STATUS_SUCCESS;

    while ((PdoExtension = NextLogUnitExtension(FdoExtension, &ScsiAddress, TRUE, IdePortScanBus)) != NULL)
    {
        DPRINT("IdePortScanBus: stopping pdo %p\n", PdoExtension);
        Status = DeviceStopDeviceQueueSafe(PdoExtension, 0x800, TRUE);
        DPRINT("IdePortScanBus: stopped pdo %p\n", PdoExtension);

        UnrefLogicalUnitExtension(FdoExtension, PdoExtension, IdePortScanBus);

        if (!NT_SUCCESS(Status))
            break;
    }

    if (NT_SUCCESS(Status))
    {
        IsEmptyChannelCheck = TRUE;

        DPRINT("IdePortScanBus: all children are stoped\n");

        ScsiAddress.AsULONG = 0;
        for (ix = 0; ix < HwDeviceExtension->MaxIdeTargetId; ix++)
        {
            ASSERT(DeviceType[ix] <= 3);//DeviceNotExist

            if (DeviceType[ix] == 3)
            {
                HwDeviceExtension->DeviceFlags[ix] = 0;
            }
            else
            {
                ScsiAddress.TargetId = ix;
                IsNewDevice = FALSE;

                PdoExtension = RefLogicalUnitExtension(FdoExtension,
                                                       ScsiAddress.PathId,
                                                       ScsiAddress.TargetId,
                                                       ScsiAddress.Lun,
                                                       TRUE, IdePortScanBus);
                if (!PdoExtension)
                {
                    PdoExtension = AllocatePdo(FdoExtension, ScsiAddress, IdePortScanBus);
                    IsNewDevice = TRUE;
                }

                if (PdoExtension)
                {
                    IsEmptyChannelCheck = FALSE;

                    HwDeviceExtension->DeviceFlags[ix] |= 1;

                    if (DeviceType[ix] == 2)
                        HwDeviceExtension->DeviceFlags[ix] |= 2;

                    if (IsLs120[ix])
                        HwDeviceExtension->DeviceFlags[ix] |= 0x8000;

                    RtlMoveMemory(&HwDeviceExtension->IdentifyData[ix], &Identify[ix], 0x200);

                    HwDeviceExtension->DeviceFlags[ix] |= 0x20000;

                    DPRINT("IdePortScanBus: Calling InitHwExtWithIdentify\n");

                    InitHwExtWithIdentify(HwDeviceExtension,
                                          ix,
                                          (DeviceType[ix] != 2 ? 0xEC : 0xA1),
                                          &HwDeviceExtension->IdentifyData[ix],
                                          IsNonRemovableMedia[ix]);

                    DPRINT("IdePortScanBus: Calling IdePortSelectCHS\n");
                    IdePortSelectCHS(FdoExtension, ix, &Identify[ix]);
                    DPRINT("IdePortScanBus: back from IdePortSelectCHS\n");

                    if (IsNewDevice)
                        FreePdo(PdoExtension, TRUE, TRUE, IdePortScanBus);
                    else
                        UnrefLogicalUnitExtension(FdoExtension, PdoExtension, IdePortScanBus);
                }
            }
        }

        if (!IsEmptyChannelCheck)
        {
            DPRINT("IdePortScanBus: Calling AnalyzeDeviceCapabilities\n");
            AnalyzeDeviceCapabilities(FdoExtension, IsMustBePio);

            DPRINT("IdePortScanBus: Calling AtapiSelectTransferMode\n");
            AtapiSyncSelectTransferMode(FdoExtension, HwDeviceExtension, FdoExtension->TMAllowed);

            DPRINT("IdePortScanBus: Calling AtapiHwInitialize\n");
            AtapiHwInitialize(FdoExtension->HwDeviceExtension, GetFlushCommand);
        }
    }

    ScsiAddress.AsULONG = 0;
    while ((PdoExtension = NextLogUnitExtension(FdoExtension, &ScsiAddress, TRUE, IdePortScanBus)) != NULL)
    {
        DPRINT("IdePortScanBus: re-start pdo %p\n", PdoExtension);
        DeviceStartDeviceQueue(PdoExtension, 0x800);
        UnrefLogicalUnitExtension(FdoExtension, PdoExtension, IdePortScanBus);
    }

    DPRINT("IdePortScanBus: Critical section %X took 0 ms\n", FdoExtension->ResourceData.CmdBlockBase);

    if (NT_SUCCESS(Status))
    {
        ScsiAddress.AsULONG = 0;

        for (ix = 0; ix < HwDeviceExtension->MaxIdeTargetId; ix++)
        {
            if (DeviceType[ix] == 3)
                continue;

            ScsiAddress.TargetId = ix;

            for (jx = 0; jx < FdoExtension->MaxPdoCount; jx++)
            {
                ScsiAddress.Lun = jx;
                IsNewDevice = FALSE;

                DPRINT("IdePortScanBus: (%X) scan %X:%X:%X\n", FdoExtension->ResourceData.CmdBlockBase, ScsiAddress.PathId, ScsiAddress.TargetId, ScsiAddress.Lun);

                PdoExtension = RefLogicalUnitExtension(FdoExtension,
                                                       ScsiAddress.PathId,
                                                       ScsiAddress.TargetId,
                                                       ScsiAddress.Lun,
                                                       TRUE,
                                                       IdePortScanBus);
                if (!PdoExtension)
                {
                    PdoExtension = AllocatePdo(FdoExtension, ScsiAddress, IdePortScanBus);
                    IsNewDevice = TRUE;
                }

                ASSERT(PdoExtension);

                if (!PdoExtension)
                {
                    DPRINT1("IdePortScanBus: unable to create new pdo\n");
                    continue;
                }

                DPRINT("IdePortScanBus: jx %X\n", jx);

                if (!jx)
                {
                    if (FdoExtension->HwDeviceExtension->DeviceParameters[ix].XferSelectedMode & 0x7FFFFFE0)
                    {
                        if (!IsEqualCheckSum[ix] ||
                            FdoExtension->HwDeviceExtension->DeviceParameters[ix].XferSelectedMode != RegTransferMode[ix])
                        {
                            IdePortVerifyDma(PdoExtension, DeviceType[ix]);
                        }
                        else
                        {
                            DPRINT("IdePortScanBus: Skip dma test for %X\n", ix);
                        }

                        DPRINT("IdePortScanBus: VerifyDma for %X device %X took 0 ms\n",
                               FdoExtension->ResourceData.CmdBlockBase, ix);
                    }

                    NonCdNumLun = 0;

                    if (DeviceType[ix] == 2)
                    {
                        if (SpecialDevice[ix] != 3)
                        {
                            NonCdNumLun = IdePortQueryNonCdNumLun(FdoExtension, PdoExtension, 0);
                            DPRINT("IdePortScanBus: NonCdNumLun %X\n", NonCdNumLun);
                        }
                        else
                        {
                            DPRINT("IdePortScanBus: Skip modesense\n");
                        }

                    }

                    DPRINT("IdePortScanBus: Initialize Luns for %X device %X took 0 ms\n",
                           FdoExtension->ResourceData.CmdBlockBase, ix);

                    AtapiHwInitializeMultiLun(FdoExtension->HwDeviceExtension, PdoExtension->TargetId, NonCdNumLun);
                }

                Status = IssueInquirySafe(FdoExtension, PdoExtension, &Inquiry, TRUE);

                DPRINT("IdePortScanBus: Inquiry %X for Lun %X device %X took 0 ms\n",
                       FdoExtension->ResourceData.CmdBlockBase, jx, ix);

                if (NT_SUCCESS(Status) || Status == STATUS_DATA_OVERRUN)
                {
                    DeviceInitDeviceType(PdoExtension, &Inquiry);
                    DeviceInitIdStrings(PdoExtension, DeviceType[ix], &Inquiry, &Identify[ix]);

                    PdoExtension->PdoFlags &= ~0x80;

                    DPRINT("IdePortScanBus: Found device at\n");
                    DPRINT("   Bus         %X\n", PdoExtension->PathId);
                    DPRINT("   Target Id   %X\n", PdoExtension->TargetId);
                    DPRINT("   LUN         %X\n", PdoExtension->Lun);

                    if (IsNoPowerDown[ix] || PdoExtension->ScsiDeviceType == 5)
                    {
                        KeAcquireSpinLock(&PdoExtension->PdoLock, &Irql);
                        PdoExtension->PdoState |= 0x80;
                        KeReleaseSpinLock(&PdoExtension->PdoLock, Irql);
                    }

                    PdoExtension->DataCheckSum = checkSum[ix];
                    UnrefLogicalUnitExtension(FdoExtension, PdoExtension, IdePortScanBus);
                    PdoExtension = NULL;
                }

                if (!PdoExtension)
                    continue;

                if (!IsNewDevice)
                {
                    DPRINT("IdePortScanBus: pdoe %p is missing (physically removed)\n", PdoExtension);
                }

                KeAcquireSpinLock(&PdoExtension->PdoLock, &Irql);
                PdoExtension->PdoState |= 0x40;
                KeReleaseSpinLock(&PdoExtension->PdoLock, Irql);

                if (IsNewDevice)
                    FreePdo(PdoExtension, TRUE, TRUE, IdePortScanBus);
                else
                    UnrefLogicalUnitExtension(FdoExtension, PdoExtension, IdePortScanBus);
            }
        }

        ScsiAddress.AsULONG = 0;
        while ((PdoExtension = NextLogUnitExtension(FdoExtension, &ScsiAddress, TRUE, IdePortScanBus)) != NULL)
        {
            DeviceRegisterIdleDetection(PdoExtension, 0xFFFFFFFF, 0xFFFFFFFF);
            PdoExtension->SelfDevice->Flags &= ~DO_DEVICE_INITIALIZING;
            UnrefLogicalUnitExtension(FdoExtension, PdoExtension, IdePortScanBus);
        }

        //DriverExtension = IoGetDriverObjectExtension(FdoExtension->DriverObject, DriverEntry);
        //IdeBuildDeviceMap(FdoExtension, DriverExtension);
    }

    DPRINT("IdePortScanBus: Last Stage scanning for %X took 0 ms\n", FdoExtension->ResourceData.CmdBlockBase);

    for (ix = 0; ix < HwDeviceExtension->MaxIdeTargetId; ix++)
    {
        PdoExtension = RefLogicalUnitExtension(FdoExtension, 0, ix, 0, TRUE, IdePortScanBus);
        if (!PdoExtension)
        {
            IdePortSaveDeviceParameter(FdoExtension, TimingModeName[ix], 0);
            continue;
        }

        SelectedMode = FdoExtension->HwDeviceExtension->DeviceParameters[ix].XferSelectedMode;

        if (PdoExtension->DmaTimeouts >= 6)
        {
            SelectedMode &= 0x1F;
            RegTimingModeAllowed[ix] &= 0x1F;
        }

        UnrefLogicalUnitExtension(FdoExtension, PdoExtension, IdePortScanBus);

        if (DeviceType[ix] == 3)
        {
            UNIMPLEMENTED_DBGBREAK();
        }
        else
        {
            IdePortSaveDeviceParameter(FdoExtension, TimingModeName[ix], SelectedMode);
            IdePortSaveDeviceParameter(FdoExtension, TimingModeAllowedName[ix], RegTimingModeAllowed[ix]);
        }

        IdePortSaveDeviceParameter(FdoExtension, DataCheckSumName[ix], checkSum[ix]);
    }

Exit:

    MmUnlockPagableImageSection(ImageSectionHandle);
}

PDEVICE_RELATIONS
NTAPI
ChannelBuildDeviceRelationList(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    PDEVICE_RELATIONS DeviceRelations;
    ATA_SCSI_ADDRESS ScsiAddress;
    ULONG Size;
    ULONG Count = 0;
    KIRQL Irql;
    BOOLEAN IsDeadMeat;

    DPRINT("ChannelBuildDeviceRelationList: %%p\n", FdoExtension);

    ScsiAddress.AsULONG = 0;

    PdoExtension = NextLogUnitExtension(FdoExtension, &ScsiAddress, TRUE, ChannelBuildDeviceRelationList);
    for (Count = 0; PdoExtension; Count++)
    {
        UnrefLogicalUnitExtension(FdoExtension, PdoExtension, ChannelBuildDeviceRelationList);
        PdoExtension = NextLogUnitExtension(FdoExtension, &ScsiAddress, TRUE, ChannelBuildDeviceRelationList);
    }

    //FIXME
    if (Count)
        Size = ((Count + 1) * 4);
    else
        Size = 8;

    DeviceRelations = ExAllocatePoolWithTag(NonPagedPool, Size, 'PedI');
    if (!DeviceRelations)
    {
        DPRINT1("ChannelBuildDeviceRelationList: Unable to allocate DeviceRelations structures\n");
        return NULL;
    }

    ScsiAddress.AsULONG = 0;

    for (DeviceRelations->Count = 0; DeviceRelations->Count < Count; )
    {
        PdoExtension = NextLogUnitExtension(FdoExtension, &ScsiAddress, TRUE, ChannelBuildDeviceRelationList);
        if (!PdoExtension)
            break;

        KeAcquireSpinLock(&PdoExtension->PdoLock, &Irql);
        IsDeadMeat = ((PdoExtension->PdoState & 0x40) == 0x40);
        KeReleaseSpinLock(&PdoExtension->PdoLock, Irql);

        if (IsDeadMeat)
        {
            KeAcquireSpinLock(&PdoExtension->PdoLock, &Irql);
            PdoExtension->PdoState &= ~0x8000;
            KeReleaseSpinLock(&PdoExtension->PdoLock, Irql);

            DPRINT("ChannelBuildDeviceRelationList: %X target %X pdoExtension %p is marked DEADMEAT\n",
                   PdoExtension->FdoExtension->ResourceData.CmdBlockBase, PdoExtension->TargetId, PdoExtension);
        }
        else
        {
            KeAcquireSpinLock(&PdoExtension->PdoLock, &Irql);
            PdoExtension->PdoState |= 0x8000;
            KeReleaseSpinLock(&PdoExtension->PdoLock, Irql);

            DeviceRelations->Objects[DeviceRelations->Count] = PdoExtension->SelfDevice;
            ObReferenceObjectByPointer(DeviceRelations->Objects[DeviceRelations->Count++], 0, 0, 0);
        }

        UnrefLogicalUnitExtension(FdoExtension, PdoExtension, ChannelBuildDeviceRelationList);
    }

    DPRINT("ChannelBuildDeviceRelationList: returning %X children\n", DeviceRelations->Count);

    return DeviceRelations;
}

VOID
NTAPI
ChannelQueryBusRelation(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PVOID Context)
{
    PATAPI_ENUM_WORKITEM_CONTEXT WorkerContext = Context;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PDEVICE_RELATIONS DeviceRelations;
    PIRP Irp;

    DPRINT("ChannelQueryBusRelation: %p, %p\n", Fdo, Context);

    Irp = WorkerContext->Irp;
    FdoExtension = IoGetCurrentIrpStackLocation(Irp)->DeviceObject->DeviceExtension;

    DeviceQueryChannelTimingSettings(FdoExtension, &FdoExtension->TimingBlock);
    ChannelQueryTransferModeInterface(FdoExtension);
    IdePortScanBus(FdoExtension);

    DeviceRelations = ChannelBuildDeviceRelationList(FdoExtension);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoSkipCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Information = (ULONG_PTR)DeviceRelations;

    IoCallDriver(FdoExtension->LowDevice, Irp);
}

NTSTATUS
NTAPI
ChannelQueryDeviceRelations(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PATAPI_ENUM_WORKITEM_CONTEXT WorkerContext;

    DPRINT("ChannelQueryDeviceRelations: %p, %p\n", Fdo, Irp);

    FdoExtension = Fdo->DeviceExtension;

    if (!(FdoExtension->FdoState & 2))
    {
        Irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
        IoCompleteRequest(Irp, 0);
        return Irp->IoStatus.Status;
    }

    if (IoGetCurrentIrpStackLocation(Irp)->Parameters.QueryDeviceRelations.Type != 0)
    {
        DPRINT("ChannelQueryDeviceRelations: Unsupported device relation\n");
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(FdoExtension->LowDevice, Irp);
    }

    DPRINT("ChannelQueryDeviceRelations: bus relations\n");

    ASSERT(FdoExtension->PreAllocEnumStruct);
    WorkerContext = FdoExtension->PreAllocEnumStruct->EnumWorkItemContext;

    ASSERT(WorkerContext);
    ASSERT(WorkerContext->WorkItem);

    WorkerContext->Irp = Irp;

    Irp->IoStatus.Status = STATUS_PENDING;
    IoMarkIrpPending(Irp);

    IoQueueWorkItem(WorkerContext->WorkItem, ChannelQueryBusRelation, DelayedWorkQueue, WorkerContext);

    return STATUS_PENDING;
}

NTSTATUS
NTAPI
ChannelFilterResourceRequirements(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PIO_RESOURCE_DESCRIPTOR CommandPortDescriptor;
    PIO_RESOURCE_DESCRIPTOR ControlPortDescriptor;
    PIO_RESOURCE_DESCRIPTOR InterruptDescriptor;
    PIO_RESOURCE_DESCRIPTOR FirstDescriptor;
    PIO_RESOURCE_DESCRIPTOR NewDescriptor;
    PIO_RESOURCE_DESCRIPTOR CurrentDescriptor;
    PIO_RESOURCE_REQUIREMENTS_LIST NewIoResources;
    PIO_RESOURCE_REQUIREMENTS_LIST IoResources;
    PIO_RESOURCE_LIST NewIoList;
    PIO_RESOURCE_LIST IoList;
    PFDO_DEVICE_EXTENSION FdoExtension;
    PIO_STACK_LOCATION IoStack;
    IDE_TRANSFER_MODE_INTERFACE Iface;
    IO_STACK_LOCATION ioStack;
    ULONG Length;
    ULONG Size;
    ULONG ix;
    ULONG jx;
    ULONG kx;
    NTSTATUS Status;

    PAGED_CODE();

    IoStack = IoGetCurrentIrpStackLocation(Irp);

    DPRINT("ChannelFilterResourceRequirements: %p, %p\n",
           Fdo, IoStack->Parameters.FilterResourceRequirements.IoResourceRequirementList);

    RtlZeroMemory(&ioStack, sizeof(ioStack));

    ioStack.MajorFunction = IRP_MJ_PNP;
    ioStack.MinorFunction = IRP_MN_QUERY_INTERFACE;

    ioStack.Parameters.QueryInterface.Size = sizeof(Iface);
    ioStack.Parameters.QueryInterface.Version = 1;
    ioStack.Parameters.QueryInterface.InterfaceType = &GUID_PCIIDE_XFER_MODE_INTERFACE;
    ioStack.Parameters.QueryInterface.Interface = (PINTERFACE)&Iface;
    ioStack.Parameters.QueryInterface.InterfaceSpecificData = NULL;

    FdoExtension = Fdo->DeviceExtension;

    Status = IdePortSyncSendIrp(FdoExtension->LowDevice, &ioStack, NULL);
    if (NT_SUCCESS(Status))
    {
        goto Exit;
    }

    if (!NT_SUCCESS(Irp->IoStatus.Status))
    {
        DPRINT1("ChannelFilterResourceRequirements: Irp->IoStatus.Status %X\n", Irp->IoStatus.Status);
        IoResources = IoStack->Parameters.FilterResourceRequirements.IoResourceRequirementList;
    }
    else
    {
        ASSERT(Irp->IoStatus.Information);
        IoResources = (PIO_RESOURCE_REQUIREMENTS_LIST)Irp->IoStatus.Information;
    }

    if (!IoResources)
    {
        DPRINT("ChannelFilterResourceRequirements: IoResources is NULL\n");
        goto Exit;
    }

    if (!IoResources->AlternativeLists)
    {
        DPRINT("ChannelFilterResourceRequirements: IoResources->AlternativeLists is 0\n");
        goto Exit;
    }

    RosDumpIoResources(IoResources, 0);

    Size = (IoResources->ListSize + (IoResources->AlternativeLists * sizeof(IO_RESOURCE_DESCRIPTOR)));

    NewIoResources = ExAllocatePoolWithTag(PagedPool, Size, 'PedI');
    if (!NewIoResources)
    {
        DPRINT1("ChannelFilterResourceRequirements: Allocate failed\n");
        goto Exit;
    }
    RtlCopyMemory(NewIoResources, IoResources, sizeof(IO_RESOURCE_REQUIREMENTS_LIST));

    NewIoResources->ListSize = Size;

    IoList = IoResources->List;
    NewIoList = NewIoResources->List;

    for (ix = 0; ix < IoResources->AlternativeLists; ix++)
    {
        InterruptDescriptor = 0;
        CommandPortDescriptor = 0;
        ControlPortDescriptor = 0;

        FirstDescriptor = IoList->Descriptors;

        for (jx = 0; jx < IoList->Count; jx++)
        {
            if (IoList->Descriptors[jx].Type == 1)
            {
                Length = IoList->Descriptors[jx].u.Port.Length;

                if (Length == 8 && !CommandPortDescriptor)
                {
                    CommandPortDescriptor = &IoList->Descriptors[jx];
                }
                else if ((Length == 1 || Length == 2 || Length == 4) && !ControlPortDescriptor)
                {
                    ControlPortDescriptor = &IoList->Descriptors[jx];
                }
                else if (Length >= 0x10 && !CommandPortDescriptor && !ControlPortDescriptor)
                {
                    CommandPortDescriptor = ControlPortDescriptor = &IoList->Descriptors[jx];
                }
            }
            else if (IoList->Descriptors[jx].Type == 2 && !InterruptDescriptor)
            {
                InterruptDescriptor = &IoList->Descriptors[jx];
            }
        }

        RtlCopyMemory(NewIoList, IoList, sizeof(IO_RESOURCE_LIST));

        if (CommandPortDescriptor && 
            (CommandPortDescriptor->u.Port.MaximumAddress.QuadPart - CommandPortDescriptor->u.Port.MinimumAddress.QuadPart) == 7 &&
            !ControlPortDescriptor)
        {
            NewDescriptor = NewIoList->Descriptors;
            CurrentDescriptor = FirstDescriptor;

            for (jx = 0; jx < NewIoList->Count; jx++)
            {
                RtlCopyMemory(NewDescriptor, CurrentDescriptor, sizeof(IO_RESOURCE_DESCRIPTOR));

                NewDescriptor++;

                if (CurrentDescriptor == CommandPortDescriptor)
                {
                    RtlCopyMemory(NewDescriptor, CurrentDescriptor, sizeof(IO_RESOURCE_DESCRIPTOR));

                    NewDescriptor->u.Port.Length = 1;
                    NewDescriptor->u.Port.Alignment = 1;
                    NewDescriptor->u.Port.MaximumAddress.QuadPart = (CommandPortDescriptor->u.Port.MinimumAddress.QuadPart + 0x206);//518
                    NewDescriptor++;
                }

                CurrentDescriptor++;
            }

            NewIoList->Count++;
        }
        else
        {
            NewDescriptor = NewIoList->Descriptors;
            CurrentDescriptor = FirstDescriptor;

            for (kx = 0; kx < NewIoList->Count; kx++)
            {
                RtlCopyMemory(NewDescriptor, CurrentDescriptor, sizeof(IO_RESOURCE_DESCRIPTOR));

                NewDescriptor++;
                CurrentDescriptor++;
            }
        }

        IoList = (PIO_RESOURCE_LIST)&FirstDescriptor[IoList->Count];
    }

    if (!NT_SUCCESS(Irp->IoStatus.Status))
        Irp->IoStatus.Status = STATUS_SUCCESS;
    else
        ExFreePool((PVOID)Irp->IoStatus.Information);

    Irp->IoStatus.Information = (ULONG_PTR)NewIoResources;

Exit:

    return IdePortPassDownToNextDriver(Fdo, Irp);
}

NTSTATUS
NTAPI
ChannelQueryId(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ChannelQueryPnPDeviceState(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension = Fdo->DeviceExtension;

    DPRINT("ChannelQueryPnPDeviceState: QUERY_DEVICE_STATE for FDOE %p\n", FdoExtension);

    if (FdoExtension->Paging)
        Irp->IoStatus.Information |= 0x20;

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoSkipCurrentIrpStackLocation(Irp);

    return IoCallDriver(FdoExtension->LowDevice, Irp);
}

NTSTATUS
NTAPI
ChannelUsageNotification(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
ChannelSurpriseRemoveDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* PDO PNP FUNCTIONS ********************************************************/

VOID
NTAPI
DeviceInitDeviceStateCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PATAPI_DEVICE_STATE_CONTEXT InContext,
    _In_ NTSTATUS InStatus)
{
    PATAPI_DEVICE_STATE_CONTEXT Context = InContext;
    VOID (NTAPI* CallBack)(PVOID, NTSTATUS);
    PPDO_DEVICE_EXTENSION PdoExtension;
    PATAPI_INIT_DATA InitData;
    ULONG MaxState;
    NTSTATUS Status;

    while (TRUE)
    {
        if (!NT_SUCCESS(InStatus))
        {
            InterlockedIncrement(&Context->FailedInits);
            DPRINT("DeviceInitDeviceStateCompletionRoutine: Last init. command failed with status %X\n", InStatus);
        }

        PdoExtension = Context->PdoExtension;

        MaxState = Context->State[Context->MaxState];
        if (MaxState)
        {
            if (MaxState != 1)
            {
                ASSERT(FALSE);
                break;
            }

            CallBack = Context->CallBack;
            CallBack(Context->CallBackContext, (Context->FailedInits ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS));

            UnrefPdo(Context->PdoExtension, DeviceInitDeviceState);
            ExFreePoolWithTag(Context, 'PedI');
            break;
        }

        InitData = Context->PdoExtension->InitData;
        ASSERT(InitData);

        RtlZeroMemory(&Context->AtaPassThr, sizeof(Context->AtaPassThr));

        Context->AtaPassThr.IdeReg = InitData->IdeReg[Context->CountInits];
        Context->AtaPassThr.IdeReg.bReserved |= 0xC0;

        Context->CountInits++;
        if (Context->CountInits >= InitData->Count)
            Context->MaxState++;

        if (Context->AtaPassThr.IdeReg.bFeaturesReg == 2 &&
            Context->AtaPassThr.IdeReg.bCommandReg == 0xEF)
        {
            ASSERT(PdoExtension->ScsiDeviceType == DIRECT_ACCESS_DEVICE);

            if (!PdoExtension->IsWriteCache)
                Context->AtaPassThr.IdeReg.bFeaturesReg = 0x82;
        }

        DPRINT("DeviceInitDeviceStateCompletionRoutine: restore firmware settings from ACPI BIOS. IdeReg = %X %X %X %X %X %X %X\n",
               Context->AtaPassThr.IdeReg.bFeaturesReg,
               Context->AtaPassThr.IdeReg.bSectorCountReg,
               Context->AtaPassThr.IdeReg.bSectorNumberReg,
               Context->AtaPassThr.IdeReg.bCylLowReg,
               Context->AtaPassThr.IdeReg.bCylHighReg,
               Context->AtaPassThr.IdeReg.bDriveHeadReg,
               Context->AtaPassThr.IdeReg.bCommandReg);

        Status = IssueAsyncAtaPassThroughSafe(PdoExtension->FdoExtension,
                                              PdoExtension,
                                              &Context->AtaPassThr,
                                              TRUE,
                                              DeviceInitDeviceStateCompletionRoutine,
                                              Context,
                                              0,
                                              0xF,
                                              FALSE);
        if (NT_SUCCESS(Status))
            break;

        InStatus = Status;
    }
}

NTSTATUS
NTAPI
DeviceInitDeviceState(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PVOID InCallBack,
    _In_ PVOID CallBackContext)
{
    VOID (NTAPI* CallBack)(PVOID, NTSTATUS) = InCallBack;
    PATAPI_DEVICE_STATE_CONTEXT Context;
    ULONG NumState;

    DPRINT("DeviceInitDeviceState: %p\n", PdoExtension);

    if (!InterlockedExchange(&PdoExtension->Unknown1, 0))
        return STATUS_SUCCESS;

    if (!(PdoExtension->PdoState & 4))
    {
        DPRINT("DeviceInitDeviceState: device not started...skipping acpi init\n");
        CallBack(CallBackContext, STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }

    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Context), 'PedI');
    if (!Context)
    {
        DPRINT1("DeviceInitDeviceState: STATUS_NO_MEMORY\n");
        return STATUS_NO_MEMORY;
    }

    if (!RefPdo(PdoExtension->SelfDevice, FALSE, DeviceInitDeviceState))
    {
        DPRINT1("DeviceInitDeviceState: STATUS_NO_SUCH_DEVICE\n");
        ExFreePoolWithTag(Context, 'PedI');
        return STATUS_NO_SUCH_DEVICE;
    }

    RtlZeroMemory(Context, sizeof(*Context));

    if (PdoExtension->InitData)
    {
        Context->State[0] = 0;
        NumState = 1;
    }
    else
    {
        NumState = 0;
    }

    Context->State[NumState] = 1;

    NumState++;
    ASSERT(NumState <= 2);//deviceInitState_max

    Context->PdoExtension = PdoExtension;
    Context->CountStates = NumState;
    Context->CallBack = InCallBack;
    Context->CallBackContext = CallBackContext;

    DeviceInitDeviceStateCompletionRoutine(PdoExtension->SelfDevice, Context, STATUS_SUCCESS);

    return STATUS_PENDING;
}

VOID
NTAPI
IdePortWmiRegister(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    //UNIMPLEMENTED_DBGBREAK();
    UNIMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceQueryFirmwareBootSettings(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _Out_ PATAPI_INIT_DATA* OutInitData)
{
    PACPI_EVAL_OUTPUT_BUFFER QueryResult;
    ACPI_EVAL_SIGNATURE MethodSign;
    NTSTATUS Status;

    DPRINT("DeviceQueryFirmwareBootSettings: %p\n", PdoExtension);

    *OutInitData = NULL;

    MethodSign.AsULONG = 'FTG_';

    Status = DeviceQueryACPISettings(PdoExtension->SelfDevice, MethodSign, &QueryResult);
    if (NT_SUCCESS(Status))
    {
        if (QueryResult->Count != 1)
        {
            ASSERT(QueryResult->Count == 1);
            Status = STATUS_UNSUCCESSFUL;
        }
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("DeviceQueryFirmwareBootSettings: Status %X\n", Status);
        goto Exit;
    }

    UNIMPLEMENTED_DBGBREAK();

Exit:

    if (QueryResult)
        ExFreePoolWithTag(QueryResult, 'PedI');

    return Status;
}

VOID
NTAPI
DeviceQueryInitData(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    PPDO_DEVICE_EXTENSION Lun0PdoExtension;
    PATAPI_INIT_DATA NewInitData;
    PATAPI_INIT_DATA InitData;
    ULONG NewCount;
    ULONG ix;
    ULONG jx;
    UCHAR Command;

    PAGED_CODE();

    DPRINT("DeviceQueryInitData: Init. pdoe %p (%X, %X, %X)\n",
           PdoExtension, PdoExtension->PathId, PdoExtension->TargetId, PdoExtension->Lun);

    if (PdoExtension->InitData)
        return;

    InitData = PdoExtension->InitData;
    Lun0PdoExtension = RefLogicalUnitExtension(PdoExtension->FdoExtension,
                                               PdoExtension->PathId,
                                               PdoExtension->TargetId,
                                               0,
                                               TRUE,
                                               DeviceQueryInitData);
    if (Lun0PdoExtension)
    {
        ASSERT(Lun0PdoExtension->TargetId == PdoExtension->TargetId);
        DeviceQueryFirmwareBootSettings(Lun0PdoExtension, &InitData);
        UnrefPdo(Lun0PdoExtension, DeviceQueryInitData);
    }

    if (InitData)
    {
        for (ix = 0; ix < InitData->Count; ix++)
        {
            Command = InitData->IdeReg[ix].bCommandReg;

            if ((Command != 0xEF || InitData->IdeReg[ix].bFeaturesReg != 3) &&
                Command != 0x91 &&
                Command != 0xC6)
            {
                continue;
            }

            DPRINT("DeviceQueryInitData: Ignoring Command %X in GTF\n", Command);

            InitData->Count--;

            for (jx = ix; jx < InitData->Count; jx++)
                InitData->IdeReg[jx] = InitData->IdeReg[jx + 1];

            if (ix < InitData->Count)
                ix--;
        }
    }

    if (!PdoExtension->ScsiDeviceType)
        NewCount = 2;
    else
        NewCount = 1;

    if (InitData)
    {
        NewCount += InitData->Count;
        ix = InitData->Count;
    }
    else
    {
        ix = 0;
    }

    NewInitData = ExAllocatePoolWithTag(NonPagedPool, (sizeof(*NewInitData) + (NewCount * sizeof(IDEREGS))), 'PedI');
    if (!NewInitData)
    {
        DPRINT1("DeviceQueryInitData: Allocate failed\n");
        PdoExtension->InitData = InitData;
        return;
    }

    NewInitData->Count = NewCount;

    if (InitData)
    {
        RtlCopyMemory(&NewInitData->IdeReg, &InitData->IdeReg, (InitData->Count * sizeof(IDEREGS)));

        ExFreePoolWithTag(InitData, 'PedI');
        InitData = NULL;
    }

    RtlZeroMemory(&NewInitData->IdeReg[ix], sizeof(IDEREGS));

    NewInitData->IdeReg[ix].bFeaturesReg = 0x66;
    NewInitData->IdeReg[ix].bCommandReg = 0xEF;
    NewInitData->IdeReg[ix].bReserved = 0x42;

    if (!PdoExtension->ScsiDeviceType)
    {
        RtlZeroMemory(&NewInitData->IdeReg[ix + 1], sizeof(IDEREGS));

        NewInitData->IdeReg[ix + 1].bFeaturesReg = 2;
        NewInitData->IdeReg[ix + 1].bCommandReg = 0xEF;
        NewInitData->IdeReg[ix + 1].bReserved = 0x42;
    }

    PdoExtension->InitData = NewInitData;
}

VOID
NTAPI
DeviceInitCompletionRoutine(
    _In_ PVOID Context,
    _In_ NTSTATUS Status)
{
    PRKEVENT Event = Context;

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("DeviceInitCompletionRoutine: ERROR: DeviceInitDeviceStateFailed with Status %X\n", Status);
    }

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
}

NTSTATUS
NTAPI
DeviceStartDevice(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    KEVENT Event;
    KIRQL Irql;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("DeviceStartDevice: %p, %p\n", Pdo, Irp);

    PdoExtension = RefPdo(Pdo, TRUE, DeviceStartDevice);
    if (!PdoExtension)
    {
        DPRINT1("DeviceStartDevice: STATUS_DEVICE_DOES_NOT_EXIST\n");
        Status = STATUS_DEVICE_DOES_NOT_EXIST;
        goto Exit;
    }

    if (PdoExtension->PdoState & 4)
    {
        DPRINT("DeviceStartDevice: PDOe %p Didn't register for WMI\n", PdoExtension);
    }
    else
    {
        IdePortWmiRegister(PdoExtension);
    }

    KeAcquireSpinLock(&PdoExtension->PdoLock, &Irql);
    PdoExtension->PdoState &= ~0x2038;
    PdoExtension->PdoState |= 4;
    KeReleaseSpinLock(&PdoExtension->PdoLock, Irql);

    InterlockedIncrement(&PdoExtension->Unknown1);

    DeviceStopDeviceQueueSafe(PdoExtension, 0x1000, 0);
    DeviceStartDeviceQueue(PdoExtension, 0x400);

    KeInitializeEvent(&Event, IO_NO_INCREMENT, FALSE);

    DeviceQueryInitData(PdoExtension);

    PdoExtension->IsWriteCache = TRUE;

    Status = DeviceInitDeviceState(PdoExtension, DeviceInitCompletionRoutine, &Event);
    DPRINT("DeviceStartDevice: Status %X\n", Status);

    if (NT_SUCCESS(Status))
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
    }
    else
    {
        ASSERT(NT_SUCCESS(Status));
        DeviceInitCompletionRoutine(&Event, Status);
    }

    DeviceStartDeviceQueue(PdoExtension, 0x1000);
    UnrefPdo(PdoExtension, DeviceStartDevice);
    Status = STATUS_SUCCESS;

Exit:

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);
    return Status;
}

NTSTATUS
NTAPI
DeviceQueryStopRemoveDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceRemoveDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceStopDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceQueryDeviceRelations(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PDEVICE_RELATIONS DeviceRelations;
    NTSTATUS Status;

    DPRINT("DeviceQueryDeviceRelations: %p, %p\n", Pdo, Irp);

    if (IoGetCurrentIrpStackLocation(Irp)->Parameters.QueryDeviceRelations.Type != TargetDeviceRelation)
    {
        goto Exit;
    }

    DeviceRelations = ExAllocatePoolWithTag(NonPagedPool, (sizeof(*DeviceRelations) + sizeof(PDEVICE_OBJECT)), 'PedI');
    if (!DeviceRelations)
    {
        DPRINT1("DeviceQueryDeviceRelations: STATUS_NO_MEMORY\n");
        Irp->IoStatus.Status = STATUS_NO_MEMORY;
        Irp->IoStatus.Information = 0;
        goto Exit;
    }

    DeviceRelations->Count = 1;
    DeviceRelations->Objects[0] = Pdo;

    ObReferenceObjectByPointer(Pdo, 0, NULL, KernelMode);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = (ULONG_PTR)DeviceRelations;

Exit:

    Status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, 0);
    return Status;
}

NTSTATUS
NTAPI
IdeGetDeviceCapabilities(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PDEVICE_CAPABILITIES Capabilities)
{
    IO_STATUS_BLOCK IoStatusBlock;
    PIO_STACK_LOCATION IoStack;
    PDEVICE_OBJECT AttachedDo;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;
  
    PAGED_CODE();
    DPRINT("IdeGetDeviceCapabilities: %p\n", DeviceObject);

    RtlZeroMemory(Capabilities, sizeof(*Capabilities));

    Capabilities->Address = 0xFFFFFFFF;
    Capabilities->UINumber = 0xFFFFFFFF;
    Capabilities->Size = sizeof(*Capabilities);
    Capabilities->Version = 1;

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    AttachedDo = IoGetAttachedDeviceReference(DeviceObject);

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP, AttachedDo, NULL, 0, NULL, &Event, &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("IdeGetDeviceCapabilities: STATUS_INSUFFICIENT_RESOURCES\n");
        ObDereferenceObject(AttachedDo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    IoStack = IoGetNextIrpStackLocation(Irp);
    if (!IoStack)
    {
        DPRINT1("IdeGetDeviceCapabilities: STATUS_INVALID_PARAMETER\n");
        ObDereferenceObject(AttachedDo);
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(IoStack, sizeof(*IoStack));

    IoStack->MajorFunction = IRP_MJ_PNP;
    IoStack->MinorFunction = IRP_MN_QUERY_CAPABILITIES;
    IoStack->Parameters.DeviceCapabilities.Capabilities = Capabilities;

    IoSetCompletionRoutine(Irp, NULL, NULL, FALSE, FALSE, FALSE);

    Status = IoCallDriver(AttachedDo, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }

    ObDereferenceObject(AttachedDo);
    return Status;
}

NTSTATUS
NTAPI
DeviceQueryCapabilities(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    PDEVICE_CAPABILITIES Capabilities;
    DEVICE_CAPABILITIES capabilities;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("DeviceQueryCapabilities: %p, %p\n", Pdo, Irp);

    Capabilities = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceCapabilities.Capabilities;

    PdoExtension = RefPdo(Pdo, TRUE, DeviceQueryCapabilities);
    if (!PdoExtension)
    {
        DPRINT1("DeviceQueryCapabilities: STATUS_DEVICE_DOES_NOT_EXIST\n");
        Status = STATUS_DEVICE_DOES_NOT_EXIST;
        goto Finish;
    }

    Status = IdeGetDeviceCapabilities(PdoExtension->FdoExtension->LowPdo, &capabilities);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("DeviceQueryCapabilities: Status %p\n", Status);
        UnrefPdo(PdoExtension, DeviceQueryCapabilities);
        goto Finish;
    }

    RtlMoveMemory(Capabilities, &capabilities, sizeof(*Capabilities));

    if (PdoExtension->SerialNumId[0])
        Capabilities->UniqueID = 1;
    else
        Capabilities->UniqueID = 0;

    Capabilities->Removable = 0;
    Capabilities->SurpriseRemovalOK = 0;

    Capabilities->Address = ((PdoExtension->TargetId & 0xF) | (PdoExtension->Lun << 4));
    Capabilities->UINumber = PdoExtension->TargetId;

    Capabilities->D1Latency = 0x4BAF0;//310000
    Capabilities->D2Latency = 0x4BAF0;
    Capabilities->D3Latency = 0x4BAF0;

    UnrefPdo(PdoExtension, DeviceQueryCapabilities);

Finish:

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);
    return Status;
}

NTSTATUS
NTAPI
DeviceQueryText(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    PWCHAR DeviceText = NULL;
    UNICODE_STRING ModelIdUs;
    ANSI_STRING ModelIdAs;
    DEVICE_TEXT_TYPE Type;
    LONG ix;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("DeviceQueryText: %p, %p\n", Pdo, Irp);

    Irp->IoStatus.Information = 0;

    PdoExtension = RefPdo(Pdo, TRUE, DeviceQueryText);
    if (!PdoExtension)
    {
        DPRINT1("DeviceQueryText: STATUS_DEVICE_DOES_NOT_EXIST\n");
        Status = STATUS_DEVICE_DOES_NOT_EXIST;
        goto Finish;
    }

    Status = STATUS_NO_MEMORY;

    Type = IoGetCurrentIrpStackLocation(Irp)->Parameters.QueryDeviceText.DeviceTextType;
    if (Type == DeviceTextDescription)
    {
        DeviceText = ExAllocatePoolWithTag(PagedPool, 0x52, 'PedI');
        if (DeviceText)
        {
            ModelIdUs.Length = 0;
            ModelIdUs.MaximumLength = 0x52;
            ModelIdUs.Buffer = DeviceText;

            RtlInitAnsiString(&ModelIdAs, (PCHAR)PdoExtension->ModelId);
            RtlAnsiStringToUnicodeString(&ModelIdUs, &ModelIdAs, FALSE);

            ASSERT(ModelIdUs.Length < ModelIdUs.MaximumLength);

            ix = (ModelIdUs.Length / 2);
            while (TRUE)
            {
                ix--;
                if (ix < 0)
                    break;

                if (DeviceText[ix] != ' ' && DeviceText[ix] != 0)
                   break;
            }

            DeviceText[ix + 1] = 0;
            Status = STATUS_SUCCESS;
        }
    }
    else if (Type == DeviceTextLocationInformation)
    {
        DeviceText = ExAllocatePoolWithTag(PagedPool, 0x64, 'PedI');
        if (DeviceText)
        {
            wcscpy(DeviceText, ((PdoExtension->TargetId & 1) ? L"1" : L"0"));

            RtlInitUnicodeString(&ModelIdUs, DeviceText);
            ModelIdUs.Buffer[ModelIdUs.Length / 2] = 0;

            Status = STATUS_SUCCESS;
        }
    }
    else
    {
        Status = STATUS_NOT_SUPPORTED;
    }

    UnrefPdo(PdoExtension, DeviceQueryText);

Finish:

    DPRINT("DeviceQueryText: DeviceText '%S'\n", DeviceText);

    Irp->IoStatus.Information = (ULONG_PTR)DeviceText;
    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, 0);

    return Status;
}

PWCHAR
NTAPI
DeviceBuildBusId(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    UNICODE_STRING IdUs;
    ANSI_STRING IdAs;
    PCHAR DeviceTypeString;
    PCHAR IdStr;
    PWCHAR Id;
    USHORT Length;
    CHAR TypeStrBuffer[12];

    PAGED_CODE();
    DPRINT("DeviceBuildBusId: %p\n", PdoExtension);

    if (PdoExtension->ScsiDeviceType >= 0xA)
    {
        sprintf(TypeStrBuffer, "Type%d", PdoExtension->ScsiDeviceType);
        DeviceTypeString = TypeStrBuffer;
    }
    else
    {
        DeviceTypeString = DeviceTypeName[PdoExtension->ScsiDeviceType][0];
    }

    Length = (strlen(DeviceTypeString) + 0x60);

    Id = ExAllocatePoolWithTag(PagedPool, (Length * 2), 'PedI');
    IdStr  = ExAllocatePoolWithTag(PagedPool, Length, 'PedI');

    if (!IdStr)
    {
        if (!Id)
        {
            DPRINT1("DeviceBuildBusId: allocate failed\n");
            return NULL;
        }

        ExFreePoolWithTag(Id, 'PedI');
        goto Exit;
    }

    if (!Id)
    {
        DPRINT1("DeviceBuildBusId: allocate failed\n");
        goto Exit;
    }

    sprintf(IdStr, "IDE\\");

    CopyField((PUCHAR)&IdStr[strlen(IdStr)], (PUCHAR)DeviceTypeString, strlen(DeviceTypeString), '_');
    CopyField((PUCHAR)&IdStr[strlen(IdStr)], PdoExtension->ModelId, 0x28, '_');
    CopyField((PUCHAR)&IdStr[strlen(IdStr)], PdoExtension->RevisionId, 8, '_');

    RtlInitAnsiString(&IdAs, IdStr);

    IdUs.Length = 0;
    IdUs.MaximumLength = (Length * 2);
    IdUs.Buffer = Id;

    RtlAnsiStringToUnicodeString(&IdUs, &IdAs, FALSE);

    IdUs.Buffer[IdUs.Length / 2] = 0;

Exit:

    if (IdStr)
        ExFreePoolWithTag(IdStr, 'PedI');

    DPRINT("DeviceBuildBusId: ret Id '%S'\n", Id);
    return Id;
}

PWCHAR
NTAPI
DeviceBuildHardwareId(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    UNICODE_STRING IdUs;
    ANSI_STRING IdAs;
    PCHAR DeviceTypeString;
    PCHAR CompatibleString;
    PWCHAR IdLine;
    PWCHAR Id;
    ULONG ix;
    CHAR CompatibleBuffer[0x14];
    CHAR TypeStrBuffer[0x14];
    CHAR Buffer[0x40];

    PAGED_CODE();
    DPRINT("DeviceBuildHardwareId: %p\n", PdoExtension);

    Id = ExAllocatePoolWithTag(PagedPool, 0x282, 'PedI');
    if (!Id)
    {
        DPRINT1("DeviceBuildHardwareId: allocate failed\n");
        return NULL;
    }

    if (PdoExtension->ScsiDeviceType >= 0xA)
    {
        sprintf(TypeStrBuffer, "Type%d", PdoExtension->ScsiDeviceType);
        DeviceTypeString = TypeStrBuffer;
    }
    else
    {
        DeviceTypeString = DeviceTypeName[PdoExtension->ScsiDeviceType][0];
    }

    if (PdoExtension->FdoExtension->HwDeviceExtension->DeviceFlags[PdoExtension->TargetId] & 0x8000)
    {
        CompatibleString = "GenSFloppy";
    }
    else if (PdoExtension->ScsiDeviceType >= 0xA)
    {
        sprintf(CompatibleBuffer, "GenType%d", PdoExtension->ScsiDeviceType);
        CompatibleString = CompatibleBuffer;
    }
    else
    {
        CompatibleString = DeviceTypeName[PdoExtension->ScsiDeviceType][1];
    }

    RtlZeroMemory(Id, 0x282);

    IdLine = Id;

    for (ix = 0; ix < 5; ix++)
    {
        if (ix == 0)
        {
            sprintf(Buffer, "IDE\\%s", DeviceTypeString);

            CopyField((PUCHAR)&Buffer[strlen(Buffer)], PdoExtension->ModelId, 0x28, '_');
            CopyField((PUCHAR)&Buffer[strlen(Buffer)], PdoExtension->RevisionId, 8, '_');
        }
        else if (ix == 1)
        {
            sprintf(Buffer, "IDE\\");

            CopyField((PUCHAR)&Buffer[strlen(Buffer)], PdoExtension->ModelId, 0x28, '_');
            CopyField((PUCHAR)&Buffer[strlen(Buffer)], PdoExtension->RevisionId, 8, '_');
        }
        else if (ix == 2)
        {
            sprintf(Buffer, "IDE\\%s", DeviceTypeString);

            CopyField((PUCHAR)&Buffer[strlen(Buffer)], PdoExtension->ModelId, 0x28, '_');
        }
        else if (ix == 3)
        {
            CopyField((PUCHAR)Buffer, PdoExtension->ModelId, 0x28, '_');
            CopyField((PUCHAR)&Buffer[strlen(Buffer)], PdoExtension->RevisionId, 8, '_');
        }
        else if (ix == 4)
        {
            strcpy(Buffer, CompatibleString);
        }
        else
        {
            ASSERT(0);
        }

        RtlInitAnsiString(&IdAs, Buffer);

        IdUs.Length = 0;

        if (NlsMbCodePageTag)
            IdUs.MaximumLength = RtlxAnsiStringToUnicodeSize(&IdAs);
        else
            IdUs.MaximumLength = ((IdAs.Length + 1) * 2);

        IdUs.Buffer = IdLine;

        RtlAnsiStringToUnicodeString(&IdUs, &IdAs, FALSE);

        IdLine[IdUs.Length / 2] = 0;
        IdLine += ((IdUs.Length / 2) + 1);
    }

    IdLine[0] = L'\0';

    DPRINT("DeviceBuildHardwareId: ret Id '%S'\n", Id);
    return Id;
}

PWCHAR
NTAPI
DeviceBuildCompatibleId(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    PCHAR CompatibleString;
    PWCHAR Id;
    UNICODE_STRING IdUs;
    ANSI_STRING IdAs;
    ULONG Length;

    PAGED_CODE();
    DPRINT("DeviceBuildCompatibleId: %p\n", PdoExtension);

    if (PdoExtension->FdoExtension->HwDeviceExtension->DeviceFlags[PdoExtension->TargetId] & 0x8000)
    {
        CompatibleString = "GenSFloppy";
    }
    else if (PdoExtension->ScsiDeviceType >= 0xA)
    {
        CompatibleString = NULL;
    }
    else
    {
        CompatibleString = DeviceTypeName[PdoExtension->ScsiDeviceType][1];
    }

    RtlInitAnsiString(&IdAs, CompatibleString);

    if (NlsMbCodePageTag)
        Length = RtlxAnsiStringToUnicodeSize(&IdAs);
    else
        Length = ((IdAs.Length + 1) * 2);

    IdUs.Length = 0;
    IdUs.MaximumLength = Length;

    IdUs.Buffer = Id = ExAllocatePoolWithTag(PagedPool, (Length + 4), 'PedI');
    if (!Id)
    {
        DPRINT1("DeviceBuildCompatibleId: allocate failed\n");
        return NULL;
    }

    RtlAnsiStringToUnicodeString(&IdUs, &IdAs, FALSE);

    IdUs.Buffer[IdUs.Length / 2] = 0;
    IdUs.Buffer[(IdUs.Length / 2) + 1] = 0;

    DPRINT("DeviceBuildCompatibleId: ret Id '%S'\n", Id);
    return Id;
}

PWCHAR
NTAPI
DeviceBuildInstanceId(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension)
{
    UNICODE_STRING IdUs;
    ANSI_STRING IdAs;
    PWCHAR Id;

    PAGED_CODE();
    DPRINT("DeviceBuildInstanceId: %p\n", PdoExtension);

    Id = ExAllocatePoolWithTag(PagedPool, 0x54, 'PedI');
    if (!Id)
    {
        DPRINT1("DeviceBuildInstanceId: allocate failed\n");
        return NULL;
    }

    if (!PdoExtension->SerialNumId[0])
    {
        swprintf(Id, L"%x.%x.%x", PdoExtension->PathId, PdoExtension->TargetId, PdoExtension->Lun);
        return Id;
    }

    RtlInitAnsiString(&IdAs, (PCHAR)PdoExtension->SerialNumId);

    IdUs.Length = 0;
    IdUs.MaximumLength = 0x54;
    IdUs.Buffer = Id;

    RtlAnsiStringToUnicodeString(&IdUs, &IdAs, FALSE);
    Id[IdUs.Length / 2] = 0;

    DPRINT("DeviceBuildInstanceId: ret Id '%S'\n", Id);
    return Id;
}

NTSTATUS
NTAPI
DeviceQueryId(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    PWCHAR Id = NULL;
    BUS_QUERY_ID_TYPE IdType;
    NTSTATUS Status = STATUS_DEVICE_DOES_NOT_EXIST;

    PAGED_CODE();

    PdoExtension = RefPdo(Pdo, TRUE, DeviceQueryId);
    if (!PdoExtension)
    {
        DPRINT1("DeviceQueryId: STATUS_DEVICE_DOES_NOT_EXIST\n");
        goto Finish;
    }

    IdType = IoGetCurrentIrpStackLocation(Irp)->Parameters.QueryId.IdType;
    switch (IdType)
    {
        case BusQueryDeviceID:
            Id = DeviceBuildBusId(PdoExtension);
            break;

        case BusQueryHardwareIDs:
            Id = DeviceBuildHardwareId(PdoExtension);
            break;

        case BusQueryCompatibleIDs:
            Id = DeviceBuildCompatibleId(PdoExtension);
            break;

        case BusQueryInstanceID:
            Id = DeviceBuildInstanceId(PdoExtension);
            break;

        default:
            DPRINT("DeviceQueryId: type %X not supported\n", IdType);
            Status = STATUS_NOT_SUPPORTED;
            break;
    }

    UnrefPdo(PdoExtension, DeviceQueryId);

    if (Id)
    {
        Irp->IoStatus.Information = (ULONG_PTR)Id;
        Status = STATUS_SUCCESS;
    }

Finish:

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);
    return Status;
}

NTSTATUS
NTAPI
DeviceQueryPnPDeviceState(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    NTSTATUS Status = STATUS_SUCCESS;

    PdoExtension = RefPdo(Pdo, TRUE, DeviceQueryPnPDeviceState);
    if (!PdoExtension)
    {
        DPRINT1("DeviceQueryPnPDeviceState: STATUS_DEVICE_DOES_NOT_EXIST\n");
        Status = STATUS_DEVICE_DOES_NOT_EXIST;
        goto Exit;
    }

    DPRINT("DeviceQueryPnPDeviceState: QUERY_DEVICE_STATE for PDOE %p\n", PdoExtension);

    if (PdoExtension->Paging)
        Irp->IoStatus.Information |= 0x20;

    UnrefPdo(PdoExtension, DeviceQueryPnPDeviceState);

Exit:

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);
    return Status;
}

NTSTATUS
NTAPI
DeviceUsageNotification(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
IdePortDispatchPnp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    ULONG CmdBlockBase;
    UCHAR MinorFunction;
    BOOLEAN IsFdo;

    PAGED_CODE();
    DPRINT("IdePortDispatchPnp: %p:%X, %p\n", DeviceObject, DeviceObject->Flags, Irp);

    FdoExtension = DeviceObject->DeviceExtension;
    MinorFunction = (IoGetCurrentIrpStackLocation(Irp))->MinorFunction;

    if (FdoExtension->LowDevice)
    {
        CmdBlockBase = FdoExtension->ResourceData.CmdBlockBase;
        DPRINT("IdePortDispatchPnp: FDO %X (%X) got '%s'\n", FdoExtension->FdoIndex, CmdBlockBase, PnpMinorNames[MinorFunction]);
        IsFdo = TRUE;
    }
    else
    {
        PdoExtension = DeviceObject->DeviceExtension;
        CmdBlockBase = PdoExtension->FdoExtension->ResourceData.CmdBlockBase;
        DPRINT("IdePortDispatchPnp: PDO %d (%X) got %s\n", PdoExtension->TargetId, CmdBlockBase, PnpMinorNames[MinorFunction]);
        IsFdo = FALSE;
    }

    if (MinorFunction <= IRP_MN_QUERY_LEGACY_BUS_INFORMATION)
    {
        if (IsFdo)
            return FdoExtension->FdoPnpDispatchTable[MinorFunction](DeviceObject, Irp);
        else
            return PdoExtension->PdoPnpDispatchTable[MinorFunction](DeviceObject, Irp);
    }

    if (MinorFunction != 0xFF)
        ASSERT(!"ATAPI: PnP Dispatch Table too small\\n");

    if (IsFdo)
        return FdoExtension->PassDownToNextDriver(DeviceObject, Irp);
    else
        return PdoExtension->NoSupportIrp(DeviceObject, Irp);
}

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
ChannelDeviceIoControl(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PSTORAGE_PROPERTY_QUERY PropertyQuery;
    PFDO_DEVICE_EXTENSION FdoExtension;
    STORAGE_ADAPTER_DESCRIPTOR Adapter;
    PIO_STACK_LOCATION IoStack;
    ULONG Size;
    NTSTATUS Status;

    DPRINT("ChannelDeviceIoControl: %p, %p\n", Fdo, Irp);

    FdoExtension = Fdo->DeviceExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    if (IoStack->Parameters.DeviceIoControl.IoControlCode != IOCTL_STORAGE_QUERY_PROPERTY)
    {
        if (IoStack->DeviceObject == Fdo)
        {
            IoSkipCurrentIrpStackLocation(Irp);
            return IoCallDriver(FdoExtension->LowDevice, Irp);
        }

        Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        goto Exit;
    }

    PropertyQuery = Irp->AssociatedIrp.SystemBuffer;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(STORAGE_PROPERTY_QUERY))
    {
        DPRINT1("ChannelDeviceIoControl: STATUS_INVALID_PARAMETER\n");
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (PropertyQuery->PropertyId != StorageAdapterProperty)
    {
        DPRINT("ChannelDeviceIoControl: STATUS_NOT_IMPLEMENTED\n");
        Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        goto Exit;
    }

    if (PropertyQuery->QueryType == PropertyExistsQuery)
    {
        DPRINT("ChannelDeviceIoControl: IOCTL_STORAGE_QUERY_PROPERTY PropertyExistsQuery\n");
        Irp->IoStatus.Status = STATUS_SUCCESS;
        goto Exit;
    }

    if (PropertyQuery->QueryType == PropertyMaskQuery)
    {
        DPRINT1("ChannelDeviceIoControl: IOCTL_STORAGE_QUERY_PROPERTY PropertyMaskQuery\n");
        Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        goto Exit;
    }

    if (PropertyQuery->QueryType != PropertyStandardQuery)
    {
        DPRINT1("ChannelDeviceIoControl: IOCTL_STORAGE_QUERY_PROPERTY unknown type\n");
        Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        goto Exit;
    }

    DPRINT("ChannelDeviceIoControl: IOCTL_STORAGE_QUERY_PROPERTY PropertyStandardQuery\n");

    Size = sizeof(Adapter);
    RtlZeroMemory(&Adapter, Size);

    Adapter.Version = Size;
    Adapter.Size = Size;
    Adapter.MaximumTransferLength = FdoExtension->IoScsicapabilities.MaximumTransferLength;
    Adapter.MaximumPhysicalPages = FdoExtension->IoScsicapabilities.MaximumPhysicalPages;
    Adapter.AlignmentMask = Fdo->AlignmentRequirement;
    Adapter.AdapterUsesPio = TRUE;
    Adapter.AdapterScansDown = FALSE;
    Adapter.CommandQueueing = FALSE;
    Adapter.AcceleratedTransfer = FALSE;
    Adapter.BusType = 3;
    Adapter.BusMajorVersion = 1;
    Adapter.BusMinorVersion = 0;

    if (Size > IoStack->Parameters.DeviceIoControl.OutputBufferLength)
        Size = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &Adapter, Size);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = Size;

Exit:

    Status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, 0);
    return Status;
}

NTSTATUS
NTAPI
IdeSendMiniPortIoctl(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PIRP InIrp)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    PIO_STACK_LOCATION IoStack;
    PSRB_IO_CONTROL SrbControl;
    PIRP Irp;
    KEVENT Event;
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER StartingOffset;
    ATA_SCSI_ADDRESS ScsiAddress;
    SCSI_REQUEST_BLOCK Srb;
    ULONG OutputLength;
    ULONG InputLength;
    ULONG Length;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IdeSendMiniPortIoctl: %p, %X\n", FdoExtension, InIrp);

    StartingOffset.QuadPart = 1;

    SrbControl = InIrp->AssociatedIrp.SystemBuffer;
    IoStack = InIrp->Tail.Overlay.CurrentStackLocation;
    InIrp->IoStatus.Information = 0;

    if (InIrp->RequestorMode != KernelMode)
    {
        DPRINT1("IdeSendMiniPortIoctl: STATUS_INVALID_PARAMETER\n");
        Status = STATUS_INVALID_PARAMETER;
        goto ErrorExit;
    }

    InputLength = IoStack->Parameters.DeviceIoControl.InputBufferLength, InputLength;

    if (InputLength < sizeof(SRB_IO_CONTROL))
    {
        DPRINT1("IdeSendMiniPortIoctl: STATUS_INVALID_PARAMETER\n");
        Status = STATUS_INVALID_PARAMETER;
        goto ErrorExit;
    }

    if (SrbControl->HeaderLength != sizeof(SRB_IO_CONTROL))
    {
        DPRINT1("IdeSendMiniPortIoctl: STATUS_REVISION_MISMATCH\n");
        Status = STATUS_REVISION_MISMATCH;
        goto ErrorExit;
    }

    Length = (SrbControl->HeaderLength + SrbControl->Length);

    if (Length < SrbControl->HeaderLength)
    {
        DPRINT1("IdeSendMiniPortIoctl: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (Length < SrbControl->Length)
    {
        DPRINT1("IdeSendMiniPortIoctl: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    OutputLength = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (OutputLength < Length && InputLength < Length)
    {
        DPRINT1("IdeSendMiniPortIoctl: STATUS_BUFFER_TOO_SMALL\n");
        Status = STATUS_BUFFER_TOO_SMALL;
        goto ErrorExit;
    }

    ScsiAddress.AsULONG = 0;

    while (TRUE)
    {
        PdoExtension = NextLogUnitExtension(FdoExtension, &ScsiAddress, FALSE, InIrp);
        if (!PdoExtension)
        {
            DPRINT1("IdeSendMiniPortIoctl: STATUS_DEVICE_DOES_NOT_EXIST\n");
            Status = STATUS_DEVICE_DOES_NOT_EXIST;
            goto ErrorExit;
        }

        if (!(PdoExtension->PdoFlags & 0x8000))
            break;

        UnrefLogicalUnitExtension(FdoExtension, PdoExtension, InIrp);
    }

    KeInitializeEvent(&Event, IO_NO_INCREMENT, FALSE);

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_SCSI,
                                       PdoExtension->SelfDevice,
                                       SrbControl,
                                       Length,
                                       &StartingOffset,
                                       &Event,
                                       &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("IdeSendMiniPortIoctl: IoBuildSynchronousFsdRequest() failed\n");
        ASSERT(FALSE);
        UnrefLogicalUnitExtension(FdoExtension, PdoExtension, InIrp);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }

    RtlZeroMemory(&Srb, sizeof(Srb));

    Srb.PathId = PdoExtension->PathId;
    Srb.TargetId = PdoExtension->TargetId;
    Srb.Lun = PdoExtension->Lun;

    Srb.Function = SRB_FUNCTION_IO_CONTROL;
    Srb.Length = sizeof(Srb);
    Srb.SrbFlags = 0x140;
    Srb.OriginalRequest = Irp;
    Srb.DataBuffer = SrbControl;
    Srb.TimeOutValue = SrbControl->Timeout;
    Srb.DataTransferLength = Length;

    IoStack = IoGetNextIrpStackLocation(Irp);
    IoStack->MajorFunction = IRP_MJ_SCSI;
    IoStack->Parameters.Scsi.Srb = &Srb;

    IoCallDriver(PdoExtension->SelfDevice, Irp);

    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

    if (Srb.DataTransferLength > OutputLength)
        InIrp->IoStatus.Information = OutputLength;
    else
        InIrp->IoStatus.Information = Srb.DataTransferLength;

    InIrp->IoStatus.Status = IoStatusBlock.Status;

    UnrefLogicalUnitExtension(FdoExtension, PdoExtension, InIrp);

    return InIrp->IoStatus.Status;

ErrorExit:

    InIrp->IoStatus.Status = Status;
    return Status;
}

NTSTATUS
NTAPI
IdePortDeviceControl(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PIO_STACK_LOCATION IoStack;
    ULONG ix;
    NTSTATUS Status;

    FdoExtension = Fdo->DeviceExtension;
    IoStack = IoGetCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Information = 0;

    DPRINT("IdePortDeviceControl: %p, %p, %X\n", Fdo, Irp, IoStack->Parameters.DeviceIoControl.IoControlCode);

    if (IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCSI_GET_INQUIRY_DATA)
    {
        DPRINT1("IdePortDeviceControl: FIXME\n");
        ASSERT(FALSE);
    }
    else if (IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCSI_GET_CAPABILITIES)
    {
        if (IoStack->Parameters.Read.Length < sizeof(FdoExtension->IoScsicapabilities))
        {
            Status = STATUS_BUFFER_TOO_SMALL;
        }
        else
        {
            FdoExtension->IoScsicapabilities.AdapterUsesPio = FALSE;

            for (ix = 0; ix < FdoExtension->HwDeviceExtension->MaxIdeDevice; ix++)
            {
                if (!(FdoExtension->HwDeviceExtension->DeviceFlags[ix] & 0x200))
                    FdoExtension->IoScsicapabilities.AdapterUsesPio = TRUE;
            }

            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer,
                          &FdoExtension->IoScsicapabilities,
                          sizeof(FdoExtension->IoScsicapabilities));

            Irp->IoStatus.Information = sizeof(FdoExtension->IoScsicapabilities);
            Status = STATUS_SUCCESS;
        }
    }
    else if (IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCSI_RESCAN_BUS)
    {
        IoInvalidateDeviceRelations(FdoExtension->LowPdo, 0);
        Status = STATUS_SUCCESS;
    }
    else if (IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCSI_PASS_THROUGH)
    {
        DPRINT1("IdePortDeviceControl: FIXME\n");
        ASSERT(FALSE);
    }
    else if (IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCSI_MINIPORT)
    {
        Status = IdeSendMiniPortIoctl(FdoExtension, Irp);
    }
    else if (IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SCSI_PASS_THROUGH_DIRECT)
    {
        DPRINT1("IdePortDeviceControl: FIXME\n");
        ASSERT(FALSE);
    }
    else
    {
        return ChannelDeviceIoControl(Fdo, Irp);
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, 0);

    return Status;
}

NTSTATUS
NTAPI
DeviceBuildStorageDeviceDescriptor(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PSTORAGE_DEVICE_DESCRIPTOR StorageDeviceDescriptor,
    _Out_ ULONG* OutputLength)
{
    PATA_DEVICE_EXTENSION HwDeviceExtension;
    STORAGE_DEVICE_DESCRIPTOR Descriptor;
    INQUIRYDATA Inquiry;
    PUCHAR Buffer;
    ULONG Length1;
    ULONG Length2;
    ULONG Length3;
    ULONG Remain;
    ULONG Length;
    NTSTATUS Status;

    ASSERT(PdoExtension);
    ASSERT(StorageDeviceDescriptor);

    Length1 = (strlen((PCHAR)PdoExtension->ModelId) + 1);
    Length2 = (strlen((PCHAR)PdoExtension->RevisionId) + 1);
    Length3 = (strlen((PCHAR)PdoExtension->SerialNumId) + 1);

    RtlZeroMemory(&Descriptor, sizeof(Descriptor));

    Descriptor.Version = sizeof(Descriptor);
    Descriptor.Size = (sizeof(Descriptor) + sizeof(Inquiry) + Length1 + Length2 + Length3);
    Descriptor.DeviceType = PdoExtension->ScsiDeviceType;

    HwDeviceExtension = PdoExtension->FdoExtension->HwDeviceExtension;

    if (HwDeviceExtension->DeviceFlags[PdoExtension->TargetId] & 0x10)
        Descriptor.RemovableMedia = 1;

    if (HwDeviceExtension->DeviceFlags[PdoExtension->TargetId] & 2)
        Descriptor.BusType = 2;
    else
        Descriptor.BusType = 3;

    Buffer = (PUCHAR)StorageDeviceDescriptor;
    Remain = *OutputLength;

    if (Remain)
    {
        if (Remain > sizeof(Descriptor))
            Length = sizeof(Descriptor);
        else
            Length = Remain;

        RtlCopyMemory(StorageDeviceDescriptor, &Descriptor, Length);

        Buffer += Length;
        Remain -= Length;
    }

    if (Remain)
    {
        Status = IssueInquirySafe(PdoExtension->FdoExtension, PdoExtension, &Inquiry, FALSE);

        if (NT_SUCCESS(Status) || (Status == STATUS_DATA_OVERRUN))
        {
            if (Remain > sizeof(Inquiry))
                Length = sizeof(Inquiry);
            else
                Length = Remain;

            RtlCopyMemory(Buffer, &Inquiry, Length);

            StorageDeviceDescriptor->RawPropertiesLength = Length;

            Buffer += Length;
            Remain -= Length;
        }
    }

    if (Remain)
    {
        if (Remain > Length1)
            Length = Length1;
        else
            Length = Remain;

        RtlCopyMemory(Buffer, PdoExtension->ModelId, Length);
        Buffer[Length - 1] = 0;

        StorageDeviceDescriptor->ProductIdOffset = (*OutputLength - Remain);

        Buffer += Length;
        Remain -= Length;
    }

    if (Remain)
    {
        if (Remain > Length1)
            Length = Length1;
        else
            Length = Remain;

        RtlCopyMemory(Buffer, PdoExtension->RevisionId, Length);
        Buffer[Length - 1] = 0;

        StorageDeviceDescriptor->ProductRevisionOffset = (*OutputLength - Remain);

        Buffer += Length;
        Remain -= Length;
    }

    if (Remain)
    {
        if (Remain > Length3)
            Length = Length3;
        else
            Length = Remain;

        RtlCopyMemory(Buffer, PdoExtension->SerialNumId, Length);
        Buffer[Length - 1] = 0;

        StorageDeviceDescriptor->SerialNumberOffset = (*OutputLength - Remain);
        Remain -= Length;
    }

    *OutputLength -= Remain;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
DeviceStorageQueryProperty(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PIRP Irp)
{
    PSTORAGE_PROPERTY_QUERY PropertyQuery;
    PIO_STACK_LOCATION IoStack;
    STORAGE_QUERY_TYPE QueryType;
    ULONG OutputBufferLength;
    NTSTATUS Status = STATUS_NOT_SUPPORTED;

    PAGED_CODE();
    DPRINT("DeviceStorageQueryProperty: %p, %p\n", PdoExtension, Irp);

    IoStack = Irp->Tail.Overlay.CurrentStackLocation;
    PropertyQuery = Irp->AssociatedIrp.SystemBuffer;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < 0xC)
    {
        DPRINT1("DeviceStorageQueryProperty: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (PropertyQuery->PropertyId != StorageDeviceProperty)
    {
        DPRINT("DeviceStorageQueryProperty: ret Status %X (%X)\n", Status, PropertyQuery->PropertyId);
        return Status;
    }

    QueryType = PropertyQuery->QueryType;

    if (QueryType == 0)
    {
        DPRINT("DeviceStorageQueryProperty: IOCTL_STORAGE_QUERY_PROPERTY PropertyStandardQuery\n");

        OutputBufferLength = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

        Status = DeviceBuildStorageDeviceDescriptor(PdoExtension, Irp->AssociatedIrp.SystemBuffer, &OutputBufferLength);
        if (NT_SUCCESS(Status))
            Irp->IoStatus.Information = (ULONG_PTR)OutputBufferLength;
    }
    else if (QueryType == 1)
    {
        DPRINT("DeviceStorageQueryProperty: IOCTL_STORAGE_QUERY_PROPERTY PropertyExistsQuery\n");
        Status = STATUS_SUCCESS;
    }
    else if (QueryType == 2)
    {
        DPRINT("DeviceStorageQueryProperty: IOCTL_STORAGE_QUERY_PROPERTY PropertyMaskQuery\n");
        Status = STATUS_NOT_IMPLEMENTED;
    }
    else
    {
        DPRINT("DeviceStorageQueryProperty: IOCTL_STORAGE_QUERY_PROPERTY unknown type\n");
        Status = STATUS_NOT_IMPLEMENTED;
    }

    return Status;
}

NTSTATUS
NTAPI
DeviceScsiGetAddress(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ PIRP Irp)
{
    PSCSI_ADDRESS Address;

    PAGED_CODE();
    DPRINT("DeviceScsiGetAddress: %p, %p\n", PdoExtension, Irp);

    if (IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.OutputBufferLength < sizeof(*Address))
    {
        DPRINT1("DeviceScsiGetAddress: STATUS_BUFFER_TOO_SMALL\n");
        return STATUS_BUFFER_TOO_SMALL;
    }

    Address = Irp->AssociatedIrp.SystemBuffer;

    Address->Length = sizeof(*Address);
    Address->PortNumber = (UCHAR)PdoExtension->FdoExtension->ScsiPortCount;
    Address->PathId = PdoExtension->PathId;
    Address->TargetId = PdoExtension->TargetId;
    Address->Lun = PdoExtension->Lun;

    Irp->IoStatus.Information = sizeof(*Address);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
DeviceDeviceIoControl(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    PPDO_DEVICE_EXTENSION PdoExtension;
    ULONG IoCtl;
    BOOLEAN IsCallPortDevice;
    NTSTATUS Status;
  
    IoCtl = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.IoControlCode;

    DPRINT("DeviceDeviceIoControl: %p, %p, %X\n", Pdo, Irp, IoCtl);

    if ((IoCtl & 0xFFFF0000) != 0x2D0000 && (IoCtl & 0xFFFF0000) != 0x40000)
    {
        Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
        IoCompleteRequest(Irp, 0);

        DPRINT1("DeviceDeviceIoControl: (%p:%X) ret Status %X\n", Pdo, IoCtl, Irp->IoStatus.Status);
        return Irp->IoStatus.Status;
    }

    PdoExtension = RefPdo(Pdo, FALSE, Irp);
    if (!PdoExtension)
    {
        IsCallPortDevice = FALSE;
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_STATE;
        DPRINT1("DeviceDeviceIoControl: (%p:%X) ret Status %X\n", Pdo, IoCtl, Irp->IoStatus.Status);
        goto Finish;
    }

    if (IoCtl == 0x4D008 || IoCtl == 0x4100C || IoCtl == 0x41010)
    {
          IsCallPortDevice = TRUE;
    }
    else if (IoCtl == 0x41018)
    {
        Irp->IoStatus.Status = Status = DeviceScsiGetAddress(PdoExtension, Irp);
        IsCallPortDevice = FALSE;
    }
    else if (IoCtl == 0x41020)
    {
        IsCallPortDevice = FALSE;
        UNIMPLEMENTED_DBGBREAK();
    }
    else if (IoCtl == 0x4D004 || IoCtl == 0x4D014)
    {
        UNIMPLEMENTED_DBGBREAK();
        IsCallPortDevice = FALSE;
    }
    else if (IoCtl == 0x4D02C)
    {
        UNIMPLEMENTED_DBGBREAK();
        IsCallPortDevice = FALSE;
    }
    else if (IoCtl == 0x4D030)
    {
        UNIMPLEMENTED_DBGBREAK();
        IsCallPortDevice = FALSE;
    }
    else if (IoCtl == 0x2D1400)
    {
        Status = DeviceStorageQueryProperty(PdoExtension, Irp);
        DPRINT("DeviceDeviceIoControl: Status %X\n", Status);

        if (Status != STATUS_NOT_SUPPORTED)
        {
            IsCallPortDevice = FALSE;
            Irp->IoStatus.Status = Status;
        }
        else
        {
            IsCallPortDevice = TRUE;
        }
    }
    else
    {
        IsCallPortDevice = FALSE;
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    }

    UnrefPdo(PdoExtension, Irp);

Finish:

    if (IsCallPortDevice)
    {
        Status = IdePortDeviceControl(PdoExtension->FdoExtension->SelfDevice, Irp);
        DPRINT("DeviceDeviceIoControl: ret Status %X\n", Status);
        return Status;
    }

    IoCompleteRequest(Irp, 0);

    DPRINT("DeviceDeviceIoControl: ret Status %X\n", Irp->IoStatus.Status);
    return Irp->IoStatus.Status;
}

NTSTATUS
NTAPI
IdePortDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    NTSTATUS Status;

    if (((PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->LowDevice)
        Status = IdePortDeviceControl(DeviceObject, Irp);
    else
        Status = DeviceDeviceIoControl(DeviceObject, Irp);

    return Status;
}

NTSTATUS
NTAPI
IdePortDispatchSystemControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
IdePortWmiInit(VOID)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
IdeCreateIdeDirectory(VOID)
{
    UNICODE_STRING DirectoryName = RTL_CONSTANT_STRING(L"\\Device\\Ide");
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Handle;
    PVOID Object;
    NTSTATUS Status;

    PAGED_CODE();

    InitializeObjectAttributes(&ObjectAttributes,
                               &DirectoryName,
                               (OBJ_CASE_INSENSITIVE | OBJ_PERMANENT),
                               NULL,
                               NULL);

    Status = ZwCreateDirectoryObject(&Handle, DIRECTORY_ALL_ACCESS, &ObjectAttributes);
    if (NT_SUCCESS(Status))
    {
        ObReferenceObjectByHandle(Handle, 0x80, NULL, KernelMode, &Object, NULL);
        ZwClose(Handle);
    }
}

BOOLEAN
NTAPI
IdePortOkToDetectLegacy(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING ObjectName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Pnp");
    RTL_QUERY_REGISTRY_TABLE QueryTable[2];
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE KeyHandle;
    ULONG Value;
    NTSTATUS Status;

    DPRINT("IdePortOkToDetectLegacy: %p\n", DriverObject);

    InitializeObjectAttributes(&ObjectAttributes, &ObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    if (NT_SUCCESS(Status))
    {
        RtlZeroMemory(QueryTable, sizeof(QueryTable));

        Value = 0;

        QueryTable[0].Name = L"DisableFirmwareMapper";
        QueryTable[0].EntryContext = &Value;
        QueryTable[0].DefaultData = &Value;
        QueryTable[0].QueryRoutine = NULL;
        QueryTable[0].Flags = 0x34;
        QueryTable[0].DefaultType = 4;
        QueryTable[0].DefaultLength = 4;

        RtlQueryRegistryValues(RTL_REGISTRY_HANDLE, KeyHandle, QueryTable, NULL, NULL);
        ZwClose(KeyHandle);

        if (Value)
            return FALSE;
    }

    UNIMPLEMENTED_DBGBREAK();

    return FALSE;
}

VOID
NTAPI
IdePortDetectLegacyController(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    DPRINT("IdePortDetectLegacyController: %p, %p\n", DriverObject, RegistryPath);

    if (!IdePortOkToDetectLegacy(DriverObject))
        return;

    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    PATAPI_DRIVER_EXTENSION DriverExtension;
    NTSTATUS Status;

    DPRINT("DriverEntry: %p, '%wZ'\n", DriverObject, RegistryPath);

    if (!DriverObject)
    {
        UNIMPLEMENTED_DBGBREAK();
        //AtapiCrashDumpDriverEntry(RegistryPath);
        return STATUS_NOT_IMPLEMENTED;
    }

    Status = IoAllocateDriverObjectExtension(DriverObject, DriverEntry, sizeof(*DriverExtension), (PVOID*)&DriverExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("DriverEntry: Status %X\n", Status);
        return Status;
    }

    ASSERT(DriverExtension);
    RtlZeroMemory(DriverExtension, sizeof(*DriverExtension));

    DriverExtension->RegistryPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, (RegistryPath->Length * 2), 'PedI');
    if (!DriverExtension->RegistryPath.Buffer)
    {
        DPRINT1("DriverEntry: Unable to allocate memory for registry path\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DriverExtension->RegistryPath.Length = 0;
    DriverExtension->RegistryPath.MaximumLength = RegistryPath->Length;

    RtlCopyUnicodeString(&DriverExtension->RegistryPath, RegistryPath);

    DriverObject->DriverExtension->AddDevice = ChannelAddDevice;
    DriverObject->DriverStartIo = IdePortStartIo;
    DriverObject->DriverUnload = IdePortUnload;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = IdePortAlwaysStatusSuccessIrp;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = IdePortAlwaysStatusSuccessIrp;
    DriverObject->MajorFunction[IRP_MJ_SCSI] = IdePortDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IdePortDispatchDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_POWER] = IdePortDispatchPower;
    DriverObject->MajorFunction[IRP_MJ_PNP] = IdePortDispatchPnp;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = IdePortDispatchSystemControl;

    //IdePortWmiInit();
    IdeCreateIdeDirectory();
    //IdeInitializeFdoList(&IdeGlobalFdoList);
    IdePortDetectLegacyController(DriverObject, RegistryPath);
    //PortRegisterBugcheckCallback(&ATAPI_DUMP_ID, AtapiDumpCallback);

    return STATUS_SUCCESS;
}
