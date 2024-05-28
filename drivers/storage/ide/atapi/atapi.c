/*
 * PROJECT:         ReactOS Storage Stack
 * LICENSE:         See COPYING in the top level directory
 * FILE:            drivers/storage/atapi/atapi.c
 * PURPOSE:         ATAPI IDE miniport driver
 * PROGRAMMERS:     
 */

/* INCLUDES *******************************************************************/

#include "atapi.h"

//#define NDEBUG
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
            DPRINT("IdePortNotification: Unknown NotificationType %X\n", NotificationType);
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
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

UCHAR
NTAPI
IdeReadWrite(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    PCDB Cdb;
    ULONG StartingSector;
    ULONG Device;
    ULONG Head;
    UCHAR StartIdeStatus;

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
        UNIMPLEMENTED_DBGBREAK();
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
        UNIMPLEMENTED_DBGBREAK();
    }

    if ((ULONG_PTR)Srb->SrbExtension & 2)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

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
        UNIMPLEMENTED_DBGBREAK();
    }

    DPRINT("AtapiSendCommand: ret SRB_STATUS_PENDING (%p) \n", Srb);
    return SRB_STATUS_PENDING;
}

BOOLEAN
NTAPI
AtapiStartIo(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    UCHAR SrbStatus;

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
            UNIMPLEMENTED_DBGBREAK();
        }
        else if (Srb->Function == 0xC8 || Srb->Function == 0xC7)
        {
            SrbStatus = IdeSendPassThroughCommand(HwDeviceExtension, Srb);
        }
        else if ((HwDeviceExtension->DeviceFlags[Srb->TargetId] & 3) == 3)
        {
            SrbStatus = AtapiSendCommand(HwDeviceExtension, Srb);
        }
        else if (Srb->Function == 8 || Srb->Function == 7)
        {
            UNIMPLEMENTED_DBGBREAK();
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
        }
    }
    else if (Srb->Function == 2) // SRB_FUNCTION_IO_CONTROL
    {
        UNIMPLEMENTED_DBGBREAK();
    }
    else if (Srb->Function == 0x10) // SRB_FUNCTION_ABORT_COMMAND
    {
        UNIMPLEMENTED_DBGBREAK();
    }
    else if (Srb->Function == 0x12) // SRB_FUNCTION_RESET_BUS
    {
        UNIMPLEMENTED_DBGBREAK();
    }
    else
    {
        SrbStatus = 6;
        DPRINT("AtapiStartIo: Srb %x complete with status %x\n", Srb, SrbStatus);
    }

    DPRINT("AtapiStartIo: Srb %p complete with status %X\n", Srb, SrbStatus);

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
    UNIMPLEMENTED_DBGBREAK();
}

BOOLEAN
NTAPI 
TestForEnumProbing(
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

VOID
NTAPI
IdeCompleteRequest(
   _In_ PFDO_DEVICE_EXTENSION FdoExtension,
   _In_ PPDOX_SRB_DATA SrbData,
   _In_ UCHAR SrbStatus)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
IdePortCompleteRequest(
   _In_ PATA_DEVICE_EXTENSION HwDeviceExtension,
   _In_ PSCSI_REQUEST_BLOCK Srb,
   _In_ UCHAR SrbStatus)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
IdePortpWaitOnBusyEx(
   _In_ PIDE_CMD_BLOCK_REGS CmdBlock,
   _Out_ UCHAR* OutIdeStatus,
   _In_ UCHAR InStatus)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

BOOLEAN
NTAPI
IdePortChannelEmpty(
PIDE_CMD_BLOCK_REGS CmdBlock,
   _In_ PIDE_CTRL_BLOCK_REGS CtrlBlock,
   _In_ ULONG MaxIdeDevice)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
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

VOID
NTAPI
CallIdeStartIoSynchronized(
    _In_ PDEVICE_OBJECT Fdo)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    KIRQL Irql;

    FdoExtension = Fdo->DeviceExtension;

    KeAcquireSpinLock(&FdoExtension->SpinLock, &Irql);
    KeSynchronizeExecution(FdoExtension->InterruptObject, IdeStartIoSynchronized, Fdo);
    KeReleaseSpinLock(&FdoExtension->SpinLock, Irql);
}

VOID
NTAPI
IdePortAllocateAccessToken(
    _In_ PDEVICE_OBJECT Fdo)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    VOID (NTAPI* AllocateAccessToken)(PVOID Token, PVOID Callback, PVOID Context);

    DPRINT("IdePortAllocateAccessToken: Fdo %X\n", Fdo);

    FdoExtension = Fdo->DeviceExtension;

    if (FdoExtension->SyncAccessInterface.AllocateAccessToken)
    {
        AllocateAccessToken = FdoExtension->SyncAccessInterface.AllocateAccessToken;
        AllocateAccessToken(FdoExtension->SyncAccessInterface.Context, CallIdeStartIoSynchronized, Fdo);
    }
    else
    {
        CallIdeStartIoSynchronized(Fdo);
    }
}

VOID
NTAPI
IdePortStartIo(
    _In_ PDEVICE_OBJECT Fdo,
    _In_ PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    PIO_STACK_LOCATION IoStack;
    PSCSI_REQUEST_BLOCK Srb;
    PPDOX_SRB_DATA SrbData;

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
        UNIMPLEMENTED_DBGBREAK();
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
    PIRP PowerRelatedIrp;
    PIRP EntryIrp;
    KIRQL Irql;

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
        DPRINT1("IdePortFlushLogicalUnit: FIXME\n");
        UNIMPLEMENTED_DBGBREAK();
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
        DPRINT1("IdePortFlushLogicalUnit: FIXME\n");
        UNIMPLEMENTED_DBGBREAK();
    }

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
    KIRQL Irql;
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
                    UNIMPLEMENTED_DBGBREAK();
                }
                else if (Srb->Function == 0xC7 || Srb->Function == 0xC8)
                {
                    UNIMPLEMENTED_DBGBREAK();
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
                        UNIMPLEMENTED_DBGBREAK();
                    }
                    else if (Srb->Cdb[0] == 0x1A)
                    {
                        UNIMPLEMENTED_DBGBREAK();
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
                    DPRINT("Miniport modified the Cdb\n");
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
            UNIMPLEMENTED_DBGBREAK();
        }
    }

    if (Srb->Function == 0xC7 || Srb->Function == 0xC8 || Srb->Function == 0xC9 ||
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
    else if (Srb->Function == SRB_FUNCTION_SHUTDOWN || Srb->Function == SRB_FUNCTION_FLUSH)
    {
        UNIMPLEMENTED_DBGBREAK();
    }

    UNIMPLEMENTED_DBGBREAK();

    return STATUS_NOT_IMPLEMENTED;
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
    BOOLEAN IsSetSystemWorking = FALSE;
    BOOLEAN IsSetDeviceSet;
    NTSTATUS Status;

    DPRINT("FdoPowerCompletionRoutine: %p, %p, %p\n", Fdo, Irp, Context);

    FdoExtension = Fdo->DeviceExtension;

    if (!NT_SUCCESS(Irp->IoStatus.Status))
    {
        DPRINT("FdoPowerCompletionRoutine: devobj %p failed power irp %p\n", FdoExtension->LowDevice, Irp);

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
    }
    else
    {
        if (Context->Type == SystemPowerState)
        {
            FdoExtension->SystemPowerState = Context->State.SystemState;

            if (Context->State.SystemState == PowerSystemWorking)
            {
                ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[0]), 0, 1) == 1);
                ASSERT(FdoExtension->PendingSystemPowerIrp == Irp);

                IsSetSystemWorking = TRUE;
                State.SystemState = PowerSystemWorking;

                Status = PoRequestPowerIrp(FdoExtension->SelfDevice, IRP_MN_SET_POWER, State, FdoSystemPowerUpCompletionRoutine, Irp, NULL);
                ASSERT(Status == STATUS_PENDING);

                DPRINT("FdoPowerCompletionRoutine: New Fdo %X system power state %X\n", FdoExtension->ResourceData.CmdBlockBase, FdoExtension->SystemPowerState);

                PoSetPowerState(Fdo, Context->Type, Context->State);
                goto Exit;
            }
            else
            {
                FdoExtension->PendingSystemPowerIrp = NULL;

                DPRINT("FdoPowerCompletionRoutine: New Fdo %X system power state %X\n", FdoExtension->ResourceData.CmdBlockBase, FdoExtension->SystemPowerState);

                PoSetPowerState(Fdo, Context->Type, Context->State);
            }
        }
        else if (Context->Type == DevicePowerState)
        {
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

            if (FdoExtension->DevicePowerState == PowerDeviceD0 && FdoExtension->FdoState & 2)
                IoInvalidateDeviceRelations(FdoExtension->LowPdo, 0);

            if (IsSetDeviceSet)
            {
                PoSetPowerState(Fdo, Context->Type, Context->State);

                if (Context->Type == SystemPowerState && Context->State.SystemState == PowerSystemWorking)
                    goto Exit;
            }
        }
    }

    if (Context->Type == SystemPowerState)
        ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[0]), 0, 1) == 1);
    else
        ASSERT(InterlockedCompareExchange(&(FdoExtension->PowerContextLock[1]), 0, 1) == 1);

Exit:

    if (IsSetSystemWorking)
    {
        Status = STATUS_MORE_PROCESSING_REQUIRED;
    }
    else
    {
        PoStartNextPowerIrp(Irp);
        Status = Irp->IoStatus.Status;
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
    NTSTATUS Status;
    BOOLEAN IsNeedChangeState;

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

            IsNeedChangeState = 1;
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
        else
        {
            IsNeedChangeState = FALSE;
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
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
IdePortAlwaysStatusSuccessIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
    UNIMPLEMENTED_DBGBREAK();
}

BOOLEAN
NTAPI
AtapiInterrupt(
    _In_ PATA_DEVICE_EXTENSION HwDeviceExtension)
{
    PSCSI_REQUEST_BLOCK CurrentSrb;
    PATA_PASS_THROUGH AtaPassThr;
    ULONG bmStatus = 0;
    ULONG SrbStatus=6;
    ULONG BytesXferred = 0;
    ULONG PioModeSize = 0x200;
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
        DPRINT1("AtapiInterrupt: FIXME\n");
        ASSERT(FALSE);
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
        DPRINT1("AtapiInterrupt: FIXME\n");
        ASSERT(FALSE);
    }

    if ((IdeStatus & 1) && CurrentSrb->Cdb[0] != 3)
    {
        SrbStatus = 4;
        goto Finish;
    }

    InterruptReason = 4;

    if (IsAtapiDevice)
    {
        DPRINT1("AtapiInterrupt: FIXME\n");
        ASSERT(FALSE);
    }
    else if (IsActiveDmaTransfer)
    {
        DPRINT1("AtapiInterrupt: FIXME\n");
        ASSERT(FALSE);
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
        DPRINT1("AtapiInterrupt: FIXME\n");
        ASSERT(FALSE);
    }
    else if (HwDeviceExtension->TransferDataBytes)
    {
        DPRINT1("AtapiInterrupt: FIXME\n");
        ASSERT(FALSE);
    }
    else
    {
        DPRINT1("AtapiInterrupt: FIXME\n");
        ASSERT(FALSE);
    }

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
            DPRINT1("AtapiInterrupt: FIXME\n");
            ASSERT(FALSE);
        }

        if (CurrentSrb->SrbFlags & 0x80)
        {
            DPRINT("AtapiInterrupt: Write interrupt\n");
            DPRINT1("AtapiInterrupt: FIXME\n");
            ASSERT(FALSE);
        }
        else
        {
            DPRINT("AtapiInterrupt: Int reason 0, but srb is for a write %X\n", CurrentSrb);
            SrbStatus = 4;
            goto Finish;
        }
    }
    else if (InterruptReason == 2 && (IdeStatus & 8))
    {
        // Read
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
                DPRINT1("AtapiInterrupt: FIXME\n");
                ASSERT(FALSE);
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
        DPRINT1("AtapiInterrupt: FIXME\n");
        ASSERT(FALSE);
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
            DPRINT1("AtapiInterrupt: FIXME\n");
            ASSERT(FALSE);
        }

        HwDeviceExtension->IsDscRestrictive = FALSE;
    }

    HwDeviceExtension->ExpectingInterrupt = 0;
    CurrentSrb->SrbStatus = SrbStatus;

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
        DPRINT1("AtapiInterrupt: FIXME\n");
        ASSERT(FALSE);
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

    InterruptData;
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
            DPRINT1("IdeTranslateSrbStatus: STATUS_DEVICE_NOT_CONNECTED\n");
            Status = STATUS_DEVICE_NOT_CONNECTED;
            break;

        case 6:
        case 0x15:
        case 0x22:
            DPRINT1("IdeTranslateSrbStatus: STATUS_INVALID_DEVICE_REQUEST\n");
            Status = 0xC0000010;
            break;

        case 0x12:
            DPRINT1("IdeTranslateSrbStatus: STATUS_IO_DEVICE_ERROR\n");
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;

        default:
            return STATUS_IO_DEVICE_ERROR;
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
            UNIMPLEMENTED_DBGBREAK();
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
            UNIMPLEMENTED_DBGBREAK();
            IsDeadmeat = TRUE;
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
        DPRINT("IdePortCompletionDpc: FIXME LogErrorEntry()\n");
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
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

VOID
NTAPI
IdePortTickHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PVOID Context)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
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
                    UNIMPLEMENTED_DBGBREAK();
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
    UNIMPLEMENTED_DBGBREAK();
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
        DPRINT1("IdePortGetDeviceParameter: Status %X\n", Status);
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
        DPRINT("IdePortInitFdo: FIXME\n");
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

    //enumStruct->Unknown = ExAllocatePoolWithTag(..);

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

NTSTATUS
NTAPI
ChannelStopDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
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

    LowDevice = IoGetAttachedDeviceReference(FdoExtension->SelfDevice);

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
                DPRINT1("DeviceQueryACPISettings: Status %X\n", Status);
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

    Status = DeviceQueryACPISettings(FdoExtension, Signature, &QueryResult);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("DeviceQueryChannelTimingSettings: Status %X\n", Status);
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
        DPRINT1("AllocatePdo: Status %X\n", Status);
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
        DPRINT1("IdePortSaveDeviceParameter: Status %X\n", Status);
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

VOID
NTAPI
IdePortFudgeAtaIdentifyData(
    _In_ PIDENTIFY_DATA Identify)
{
    if (Identify->GeneralConfiguration == 0xFFFFFFFF)
        Identify->GeneralConfiguration = 0x7F7F;
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
        UNIMPLEMENTED_DBGBREAK();
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
        DPRINT1("IdePortOpenServiceSubKey: Status %X\n", Status);
        return NULL;
    }

    InitializeObjectAttributes(&ObjectAttributes, Name, OBJ_CASE_INSENSITIVE, DriverHandle, NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    ZwClose(DriverHandle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IdePortOpenServiceSubKey: Status %X\n", Status);
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
        DPRINT1("IdePortSearchDeviceInRegMultiSzList: ParameterData is NULL\n");
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
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
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
    CHAR Model[0x28];

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

NTSTATUS
NTAPI
DeviceStopDeviceQueueSafe(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ ULONG QueueStopFlag,
    _In_ BOOLEAN IsLockEnum)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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

    if (PdoExtension->PdoxUnknown1)
    {
        ExFreePool(PdoExtension->PdoxUnknown1);
        PdoExtension->PdoxUnknown1 = NULL;
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
            UNIMPLEMENTED_DBGBREAK();
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

            UNIMPLEMENTED_DBGBREAK();
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

            CycleTime = TransferModeTimingTable[BestXferMode + 5];
            ASSERT(CycleTime);

            Mode = (0xFFFFFFFF >> (0x1F - BestXferMode));
            XferMode |= (Mode << 5);

            if (HwDeviceExtension->IdentifyData[ix].MultiWordDMAActive)
            {
                TempMode = HwDeviceExtension->IdentifyData[ix].MultiWordDMAActive;
                ASSERT(TempMode);

                for (CurrentMode = 0; TempMode; CurrentMode++)
                    TempMode >>= 1;

                CurrentMode--;

                if (CurrentMode > 2)
                    CurrentMode = 2;

                CurrentMode = (1 << (CurrentMode + 5));
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
        else
        {
            UNIMPLEMENTED_DBGBREAK();
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
            UNIMPLEMENTED_DBGBREAK();
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

        if (CurrentMode < 6)
            continue;

        CurrentMode--;

        if (CurrentMode >= 0xB)
            Mode = ((CurrentMode - 0xB) | 0x40);
        else if (CurrentMode >= 8)
            Mode = ((CurrentMode - 8) | 0x20);
        else if (CurrentMode >= 5)
            Mode = ((CurrentMode - 5) | 0x10);

        DPRINT("AtapiProgramTransferMode: [%X] setting DMAmode %X\n", ix, CurrentMode);

        Status = AtapiSetTransferMode(HwDeviceExtension, ix, Mode);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("AtapiProgramTransferMode: Unable to set DMA mode %X for %X device %X\n",
                    CurrentMode, HwDeviceExtension->CmdBlock.CmdBlockBase, ix);

            continue;
        }

        if (CurrentMode >= 0xB)
            HwDeviceExtension->DeviceFlags[ix] |= 0x10000;
        else
            HwDeviceExtension->DeviceFlags[ix] |= 0x200;
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

        DPRINT("InitDeviceParameters: (%X:%X) is going to do ", HwDeviceExtension->CmdBlock.CmdBlockBase, Device);

        if (HwDeviceExtension->DeviceFlags[Device] & 0x200)
            DbgPrint("DMA\n");
        else
            DbgPrint("PIO\n");

        if (HwDeviceExtension->DeviceFlags[Device] & 2)
        {
            DeviceParameters->Unknown1 = 0x200;
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

            DeviceParameters->Unknown1 = (HwDeviceExtension->MaximumBlockTransfer[Device] / 0x200);
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

            DeviceParameters->Unknown1 = 0x200;
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
            return;

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
DeviceStartDeviceQueue(
    _In_ PPDO_DEVICE_EXTENSION PdoExtension,
    _In_ ULONG ResetState)
{
    UNIMPLEMENTED_DBGBREAK();
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
    PdoExtension->ScsiDeviceType = (Inquiry->DeviceTypeQualifier & 0x1F);

    if (Inquiry->RemovableMedia & 0x80)
        PdoExtension->SelfDevice->Characteristics |= 1;
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
        UNIMPLEMENTED_DBGBREAK();
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
            sprintf((PCHAR)&PdoExtension->SerialNumId[ix * 2], "%2x", Identify->SerialNumber[ix]);

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
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
IdeBuildDeviceMap(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension,
    _In_ PATAPI_DRIVER_EXTENSION DriverExtension)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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

        RtlCopyMemory(Srb->Cdb, Cdb, sizeof(*Srb->Cdb));

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
        ix--;
        if (!ix)
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

        RtlCopyMemory(Srb.Cdb, Cdb, sizeof(*Srb.Cdb));

        if (IoCallDriver(PdoExtension->SelfDevice, Irp) == STATUS_PENDING)
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

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
            ASSERT((Srb.SrbStatus & 0x40) == 0);//SRB_STATUS_QUEUE_FROZEN

            if (Srb.SrbStatus & 0x40)
            {
                DPRINT("IssueSyncAtapiCommand: Unfreeze Queue TID %X\n", Srb.TargetId);

                PdoExtension->PdoFlags &= ~1;

                KeAcquireSpinLock(&FdoExtension->SpinLock, &Irql);
                GetNextLuRequest2(FdoExtension, PdoExtension, __FILE__, __LINE__);
                KeLowerIrql(Irql);
            }
        }

        if ((Srb.SrbStatus & 0x80) && (SenseInfo->FileMark & 0xF) == 5)
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

VOID
NTAPI
IdePortScanBus(
    _In_ PFDO_DEVICE_EXTENSION FdoExtension)
{
    PATAPI_DRIVER_EXTENSION DriverExtension; 
    PATA_DEVICE_EXTENSION HwDeviceExtension;
    PPDO_DEVICE_EXTENSION PdoExtension;
    PVOID ImageSectionHandle;
    ATA_SCSI_ADDRESS ScsiAddress;
    ATA_PASS_THROUGH AtaPassThr;
    IDENTIFY_DATA Identify[4];
    INQUIRYDATA Inquiry;
    ULONG RegTimingModeAllowed[4];
    ULONG RegTransferMode[4];
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
    //BOOLEAN IsPioByDefaultDevice[4];
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
        UNIMPLEMENTED_DBGBREAK();
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
                    if (DeviceType[ix] == 2)
                        HwDeviceExtension->DeviceFlags[ix] |= 2;
                    else
                        HwDeviceExtension->DeviceFlags[ix] |= 1;

                    /* FIXME IdeFindSpecialDevice() for names:
                       "TOSHIBA CD-ROM XM-1702B"
                       "TOSHIBA CD-ROM XM-6202B"
                       "COMPAQ DVD-ROM DRD-U424"
                       "           "
                       "KENWOOD CD-ROM"
                       "MEMORYSTICK"
                    */
                    UNIMPLEMENTED_ONCE;
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
                //IsPioByDefaultDevice[ix] = IdePortPioByDefaultDevice(FdoExtension, &Identify[ix]);

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

                if (ix == 2)
                {
                    DPRINT1("IdePortScanBus: FIXME\n");
                    UNIMPLEMENTED_DBGBREAK();
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
                        UNIMPLEMENTED_DBGBREAK();
                    }

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
            PdoExtension->SelfDevice->Flags &= DO_DEVICE_INITIALIZING;
            UnrefLogicalUnitExtension(FdoExtension, PdoExtension, IdePortScanBus);
        }

        DriverExtension = IoGetDriverObjectExtension(FdoExtension->DriverObject, DriverEntry);
        IdeBuildDeviceMap(FdoExtension, DriverExtension);
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
    UNIMPLEMENTED_DBGBREAK();
    return NULL;
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

    DPRINT("AtaFdoFilterResourceRequirements: %p, %p\n",
           Fdo, IoStack->Parameters.FilterResourceRequirements.IoResourceRequirementList);

    RosDumpIoResources(IoStack->Parameters.FilterResourceRequirements.IoResourceRequirementList, 0);

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
        DPRINT1("AtaFdoFilterResourceRequirements: Irp->IoStatus.Status %X\n", Irp->IoStatus.Status);
        IoResources = IoStack->Parameters.FilterResourceRequirements.IoResourceRequirementList;
    }
    else
    {
        ASSERT(Irp->IoStatus.Information);
        IoResources = (PIO_RESOURCE_REQUIREMENTS_LIST)Irp->IoStatus.Information;
    }

    if (!IoResources)
    {
        DPRINT("AtaFdoFilterResourceRequirements: IoResources is NULL\n");
        goto Exit;
    }

    if (!IoResources->AlternativeLists)
    {
        DPRINT("AtaFdoFilterResourceRequirements: IoResources->AlternativeLists is 0\n");
        goto Exit;
    }

    Size = (IoResources->ListSize + (IoResources->AlternativeLists * sizeof(IO_RESOURCE_DESCRIPTOR)));

    NewIoResources = ExAllocatePoolWithTag(PagedPool, Size, 'PedI');
    if (!NewIoResources)
    {
        DPRINT1("AtaFdoFilterResourceRequirements: Allocate failed\n");
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

NTSTATUS
NTAPI
DeviceStartDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceQueryCapabilities(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceQueryText(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceQueryId(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
DeviceQueryPnPDeviceState(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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
    ULONG CmdBlockBase;
    UCHAR MinorFunction;
    BOOLEAN IsFdo;

    PAGED_CODE();
    DPRINT("IdePortDispatchPnp: %p, %p\n", DeviceObject, Irp);

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
        ASSERT(FALSE);
        IsFdo = FALSE;
    }

    if (MinorFunction <= IRP_MN_QUERY_LEGACY_BUS_INFORMATION)
    {
        if (IsFdo)
            return FdoExtension->FdoPnpDispatchTable[MinorFunction](DeviceObject, Irp);
        else
            ASSERT(FALSE);
    }

    if (MinorFunction != 0xFF)
        ASSERT(!"ATAPI: PnP Dispatch Table too small\\n");

    if (IsFdo)
        return FdoExtension->PassDownToNextDriver(DeviceObject, Irp);
    else
        {ASSERT(FALSE);return 0;}
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
        DPRINT1("ChannelDeviceIoControl: STATUS_NOT_IMPLEMENTED\n");
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
        DPRINT1("IdePortDeviceControl: FIXME\n");
        ASSERT(FALSE);
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
DeviceDeviceIoControl(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ PIRP Irp)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
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

    //DriverObject->MajorFunction[IRP_MJ_CREATE] = IdePortAlwaysStatusSuccessIrp;
    //DriverObject->MajorFunction[IRP_MJ_CLOSE] = IdePortAlwaysStatusSuccessIrp;
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
