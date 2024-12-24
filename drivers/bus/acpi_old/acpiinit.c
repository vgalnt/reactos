/*
 * PROJECT:     ACPI driver for NT 5.x
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Driver initialization code
 * COPYRIGHT:   Copyright 2019, 2023 Vadim Galyant <vgal@rambler.ru>
 */

#include "acpi.h"

#define NDEBUG
#include <debug.h>

#ifdef ALLOC_PRAGMA
  #pragma alloc_text(INIT, DriverEntry)
#endif

#ifdef ALLOC_PRAGMA
  #pragma alloc_text(PAGE, ACPILoadProcessRSDT)
  #pragma alloc_text(PAGE, ACPILoadProcessFADT)
  #pragma alloc_text(PAGE, ACPILoadFindRSDT)
#endif

/* GLOBALS *******************************************************************/

PCHAR AcpiProcessorCompatId = "ACPI\\Processor";
PCHAR ACPIFixedButtonId = "ACPI\\FixedButton";

PACPI_READ_REGISTER AcpiReadRegisterRoutine = DefPortReadAcpiRegister;
PACPI_WRITE_REGISTER AcpiWriteRegisterRoutine = DefPortWriteAcpiRegister;

PDRIVER_OBJECT AcpiDriverObject;
UNICODE_STRING AcpiRegistryPath;
FAST_IO_DISPATCH ACPIFastIoDispatch;
PDEVICE_EXTENSION RootDeviceExtension;
PRSDTINFORMATION RsdtInformation;
WORK_QUEUE_ITEM ACPIWorkItem;
ARBITER_INSTANCE AcpiArbiter;
PDEVICE_OBJECT AcpiArbiterDeviceObject;
PACPI_VECTOR_BLOCK IrqHashTable;
KDPC AcpiBuildDpc;
KDPC AcpiPowerDpc;
KDPC AcpiGpeDpc;
PVOID ACPIThread;

PUCHAR GpeEnable;
PUCHAR GpeCurEnable;
PUCHAR GpeIsLevel;
PUCHAR GpeHandlerType;
PUCHAR GpeWakeEnable;
PUCHAR GpeWakeHandler;
PUCHAR GpeSpecialHandler;
PUCHAR GpePending;
PUCHAR GpeRunMethod;
PUCHAR GpeComplete;
PUCHAR GpeSavedWakeMask;
PUCHAR GpeSavedWakeStatus;
PUCHAR GpeMap;
ULONG GpeVectorTableSize;

NPAGED_LOOKASIDE_LIST DeviceExtensionLookAsideList;
NPAGED_LOOKASIDE_LIST BuildRequestLookAsideList;
NPAGED_LOOKASIDE_LIST RequestLookAsideList;
NPAGED_LOOKASIDE_LIST PswContextLookAsideList;
KSPIN_LOCK AcpiDeviceTreeLock;
KSPIN_LOCK AcpiBuildQueueLock;
KSPIN_LOCK ACPIWorkerSpinLock;
KSPIN_LOCK AcpiPowerQueueLock;
KSPIN_LOCK AcpiGetLock;
KSPIN_LOCK AcpiPowerLock;
KSPIN_LOCK AcpiButtonLock;
KSPIN_LOCK AcpiThermalLock;
KEVENT ACPIWorkToDoEvent;
KEVENT ACPITerminateEvent;
LIST_ENTRY ACPIDeviceWorkQueue;
LIST_ENTRY ACPIWorkQueue;
LIST_ENTRY AcpiBuildDeviceList;
LIST_ENTRY AcpiBuildSynchronizationList;
LIST_ENTRY AcpiBuildRunMethodList;
LIST_ENTRY AcpiBuildQueueList;
LIST_ENTRY AcpiBuildOperationRegionList;
LIST_ENTRY AcpiBuildPowerResourceList;
LIST_ENTRY AcpiBuildThermalZoneList;
LIST_ENTRY AcpiPowerDelayedQueueList;
LIST_ENTRY AcpiGetListEntry;
LIST_ENTRY AcpiUnresolvedEjectList;
LIST_ENTRY AcpiPowerSynchronizeList;
LIST_ENTRY AcpiPowerQueueList;
LIST_ENTRY AcpiPowerPhase0List;
LIST_ENTRY AcpiPowerPhase1List;
LIST_ENTRY AcpiPowerPhase2List;
LIST_ENTRY AcpiPowerPhase3List;
LIST_ENTRY AcpiPowerPhase4List;
LIST_ENTRY AcpiPowerPhase5List;
LIST_ENTRY AcpiPowerWaitWakeList;
LIST_ENTRY AcpiPowerNodeList;
LIST_ENTRY AcpiButtonList;
LIST_ENTRY AcpiThermalList;
LONG AcpiTableDelta = 0;
ULONG AcpiSciVector;
ULONG AcpiIrqDistributionDisposition;
UCHAR AcpiIrqDefaultBootConfig;
UCHAR AcpiArbPciAlternativeRotation;
BOOLEAN AcpiLoadSimulatorTable = TRUE;
BOOLEAN AcpiBuildDpcRunning;
BOOLEAN AcpiBuildFixedButtonEnumerated;
BOOLEAN AcpiBuildWorkDone;
BOOLEAN AcpiPowerWorkDone;
BOOLEAN AcpiPowerDpcRunning;
BOOLEAN AcpiArbCardbusPresent;
BOOLEAN AcpiInterruptRoutingFailed = FALSE;
BOOLEAN ACPIWorkerBusy;
BOOLEAN AcpiGpeWorkDone;
BOOLEAN AcpiGpeDpcRunning;
BOOLEAN AcpiGpeDpcScheduled;

extern IRP_DISPATCH_TABLE AcpiFdoIrpDispatch;
extern PACPI_INFORMATION AcpiInformation;
extern PAMLI_NAME_SPACE_OBJECT ProcessorList[0x20];
extern ANSI_STRING AcpiProcessorString;
extern ULONG AcpiOverrideAttributes;
extern KSPIN_LOCK GpeTableLock;
extern KSPIN_LOCK NotifyHandlerLock;
extern PPM_DISPATCH_TABLE PmHalDispatchTable;
extern ULONG InterruptModel;
extern BOOLEAN PciInterfacesInstantiated;
extern SYSTEM_POWER_STATE SystemPowerStateTranslation[6];

/* ACPI TABLES FUNCTIONS ****************************************************/

USHORT
NTAPI
DefPortReadAcpiRegister(
    _In_ ULONG RegType,
    _In_ ULONG Size)
{
    USHORT RetValue;

    switch (RegType)
    {
        case 0:
            return READ_PORT_USHORT((PUSHORT)(AcpiInformation->PM1a_BLK + 2));

        case 1:
            return READ_PORT_USHORT((PUSHORT)(AcpiInformation->PM1b_BLK + 2));

        case 2:
            return READ_PORT_USHORT((PUSHORT)AcpiInformation->PM1a_BLK);

        case 3:
            return READ_PORT_USHORT((PUSHORT)AcpiInformation->PM1b_BLK);

        case 4:
            return READ_PORT_USHORT((PUSHORT)AcpiInformation->PM1a_CTRL_BLK);

        case 5:
            return READ_PORT_USHORT((PUSHORT)AcpiInformation->PM1b_CTRL_BLK);

        case 6:
            if (Size < AcpiInformation->Gpe0Size)
                RetValue = READ_PORT_UCHAR((PUCHAR)(AcpiInformation->GP0_BLK + Size));
            else
                RetValue = READ_PORT_UCHAR((PUCHAR)(AcpiInformation->GP1_BLK - AcpiInformation->Gpe0Size + Size));
            return (RetValue & 0xFF);

        case 7:
            if (Size >= AcpiInformation->Gpe0Size)
                RetValue = READ_PORT_UCHAR((PUCHAR)(AcpiInformation->GP1_ENABLE - AcpiInformation->Gpe0Size + Size));
            else
                RetValue = READ_PORT_UCHAR((PUCHAR)(AcpiInformation->GP0_ENABLE + Size));
            return (RetValue & 0xFF);

        case 8:
            RetValue = READ_PORT_UCHAR((PUCHAR)AcpiInformation->SMI_CMD);
            return (RetValue & 0xFF);

        default:
            return 0xFFFF;
    }
}

VOID
NTAPI
DefPortWriteAcpiRegister(
    _In_ ULONG RegType,
    _In_ ULONG Size,
    _In_ USHORT Value)
{
    switch (RegType)
    {
        case 0:
            WRITE_PORT_USHORT((PUSHORT)(AcpiInformation->PM1a_BLK + 2), Value);
            break;

        case 1:
            WRITE_PORT_USHORT((PUSHORT)(AcpiInformation->PM1b_BLK + 2), Value);
            break;

        case 2:
            WRITE_PORT_USHORT((PUSHORT)AcpiInformation->PM1a_BLK, Value);
            break;

        case 3:
            WRITE_PORT_USHORT((PUSHORT)AcpiInformation->PM1b_BLK, Value);
            break;

        case 4:
            WRITE_PORT_USHORT((PUSHORT)AcpiInformation->PM1a_CTRL_BLK, Value);
            break;

        case 5:
            WRITE_PORT_USHORT((PUSHORT)AcpiInformation->PM1b_CTRL_BLK, Value);
            break;

        case 6:
            if (Size < AcpiInformation->Gpe0Size)
                WRITE_PORT_UCHAR((PUCHAR)(AcpiInformation->GP0_BLK + Size), Value);
            else
                WRITE_PORT_UCHAR((PUCHAR)(AcpiInformation->GP1_BLK - AcpiInformation->Gpe0Size + Size), Value);
            break;

        case 7:
            if (Size >= AcpiInformation->Gpe0Size)
                WRITE_PORT_UCHAR((PUCHAR)(AcpiInformation->GP1_ENABLE - AcpiInformation->Gpe0Size + Size), Value);
            else
                WRITE_PORT_UCHAR((PUCHAR)(AcpiInformation->GP0_ENABLE + Size), Value);
            break;

        case 8:
            WRITE_PORT_UCHAR((PUCHAR)AcpiInformation->SMI_CMD, Value);
            break;

        default:
            break;
    }
}

USHORT
NTAPI
DefRegisterReadAcpiRegister(
    _In_ ULONG RegType,
    _In_ ULONG Size)
{
    USHORT RetValue;

    switch (RegType)
    {
        case 0:
            return READ_REGISTER_USHORT((PUSHORT)(AcpiInformation->PM1a_BLK + 2));

        case 1:
            return READ_REGISTER_USHORT((PUSHORT)(AcpiInformation->PM1b_BLK + 2));

        case 2:
            return READ_REGISTER_USHORT((PUSHORT)AcpiInformation->PM1a_BLK);

        case 3:
            return READ_REGISTER_USHORT((PUSHORT)AcpiInformation->PM1b_BLK);

        case 4:
            return READ_REGISTER_USHORT((PUSHORT)AcpiInformation->PM1a_CTRL_BLK);

        case 5:
            return READ_REGISTER_USHORT((PUSHORT)AcpiInformation->PM1b_CTRL_BLK);

        case 6:
            if (Size < AcpiInformation->Gpe0Size)
                RetValue = READ_REGISTER_UCHAR((PUCHAR)(AcpiInformation->GP0_BLK + Size));
            else
                RetValue = READ_REGISTER_UCHAR((PUCHAR)(AcpiInformation->GP1_BLK - AcpiInformation->Gpe0Size + Size));
            return (RetValue & 0xFF);

        case 7:
            if (Size >= AcpiInformation->Gpe0Size)
                RetValue = READ_REGISTER_UCHAR((PUCHAR)(AcpiInformation->GP1_ENABLE - AcpiInformation->Gpe0Size + Size));
            else
                RetValue = READ_REGISTER_UCHAR((PUCHAR)(AcpiInformation->GP0_ENABLE + Size));
            return (RetValue & 0xFF);

        case 8:
            RetValue = READ_PORT_UCHAR((PUCHAR)AcpiInformation->SMI_CMD);
            return (RetValue & 0xFF);

        default:
            return 0xFFFF;
    }
}

VOID
NTAPI
DefRegisterWriteAcpiRegister(
    _In_ ULONG RegType,
    _In_ ULONG Size,
    _In_ USHORT Value)
{
    switch (RegType)
    {
        case 0:
            WRITE_REGISTER_USHORT((PUSHORT)(AcpiInformation->PM1a_BLK + 2), Value);
            break;

        case 1:
            WRITE_REGISTER_USHORT((PUSHORT)(AcpiInformation->PM1b_BLK + 2), Value);
            break;

        case 2:
            WRITE_REGISTER_USHORT((PUSHORT)AcpiInformation->PM1a_BLK, Value);
            break;

        case 3:
            WRITE_REGISTER_USHORT((PUSHORT)AcpiInformation->PM1b_BLK, Value);
            break;

        case 4:
            WRITE_REGISTER_USHORT((PUSHORT)AcpiInformation->PM1a_CTRL_BLK, Value);
            break;

        case 5:
            WRITE_REGISTER_USHORT((PUSHORT)AcpiInformation->PM1b_CTRL_BLK, Value);
            break;

        case 6:
            if (Size < AcpiInformation->Gpe0Size)
                WRITE_REGISTER_UCHAR((PUCHAR)(AcpiInformation->GP0_BLK + Size), Value);
            else
                WRITE_REGISTER_UCHAR((PUCHAR)(AcpiInformation->GP1_BLK - AcpiInformation->Gpe0Size + Size), Value);
            break;

        case 7:
            if (Size >= AcpiInformation->Gpe0Size)
                WRITE_REGISTER_UCHAR((PUCHAR)(AcpiInformation->GP1_ENABLE - AcpiInformation->Gpe0Size + Size), Value);
            else
                WRITE_REGISTER_UCHAR((PUCHAR)(AcpiInformation->GP0_ENABLE + Size), Value);
            break;

        case 8:
            WRITE_PORT_UCHAR((PUCHAR)AcpiInformation->SMI_CMD, Value);
            break;

        default:
            break;
    }
}

USHORT
NTAPI
ACPIReadGpeStatusRegister(
    _In_ ULONG Size)
{
    DPRINT("ACPIReadGpeStatusRegister: Size %X\n", Size);
    return AcpiReadRegisterRoutine(6, Size);
}

VOID
NTAPI
ACPIWriteGpeStatusRegister(
    _In_ ULONG Size,
    _In_ UCHAR Value)
{
    AcpiWriteRegisterRoutine(6, Size, Value);
}

VOID
NTAPI
ACPIWriteGpeEnableRegister(
    _In_ ULONG Size,
    _In_ UCHAR Value)
{
    DPRINT("ACPIWriteGpeEnableRegister: Writing GPE Enable register %X = %X\n", Size, Value);
    AcpiWriteRegisterRoutine(7, Size, Value);
}

PRSDT
NTAPI
ACPILoadFindRSDT(VOID)
{
    PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 KeyInfo;
    PACPI_BIOS_MULTI_NODE AcpiMultiNode;
    PRSDT Rsdt;
    PRSDT OutRsdt;
    NTSTATUS Status;
    struct
    {
        CM_FULL_RESOURCE_DESCRIPTOR Descriptor;
        ACPI_BIOS_MULTI_NODE Node;
    } *Package;

    PAGED_CODE();
    DPRINT("ACPILoadFindRSDT()\n");

    Status = OSReadAcpiConfigurationData(&KeyInfo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPILoadFindRSDT: Cannot open Configuration Data - %X\n", Status);
        DbgBreakPoint();
        return NULL;
    }

    Package = (PVOID)KeyInfo->Data;
    AcpiMultiNode = &Package->Node;

  #if !defined(_M_AMD64)
    ASSERT(AcpiMultiNode->RsdtAddress.HighPart == 0);
  #endif

    Rsdt = MmMapIoSpace(AcpiMultiNode->RsdtAddress, sizeof(DESCRIPTION_HEADER), MmNonCached);
    if (!Rsdt)
    {
        DPRINT1("ACPILoadFindRSDT: Cannot Map RSDT Pointer %X\n", AcpiMultiNode->RsdtAddress.LowPart);
        DbgBreakPoint();
        ExFreePool(KeyInfo);
        return NULL;
    }

    if (Rsdt->Header.Signature == 'TDSR' || Rsdt->Header.Signature == 'TDSX')
    {
      #if !defined(_M_AMD64)
        ASSERT(AcpiMultiNode->RsdtAddress.HighPart == 0);
      #endif

        OutRsdt = MmMapIoSpace(AcpiMultiNode->RsdtAddress, Rsdt->Header.Length, MmNonCached);
        MmUnmapIoSpace(Rsdt, sizeof(DESCRIPTION_HEADER));

        if (!OutRsdt)
        {
            DPRINT1("ACPILoadFindRSDT: Cannot Map RSDT Pointer %X\n", AcpiMultiNode->RsdtAddress.LowPart);
            DbgBreakPoint();
            ExFreePool(KeyInfo);
            return NULL;
        }
    }
    else
    {
        DPRINT1("ACPILoadFindRSDT: RSDT %X has invalid signature\n", Rsdt);
        DbgBreakPoint();
        MmUnmapIoSpace(Rsdt, sizeof(DESCRIPTION_HEADER));
    }

    ExFreePool(KeyInfo);

    return OutRsdt;
}

NTSTATUS
NTAPI
ACPILoadProcessFACS(
    _In_ ULONG_PTR FacsPointer)
{
    PHYSICAL_ADDRESS PhysicalAddress;
    PFACS Facs;

    DPRINT("ACPILoadProcessFACS: %IX\n", FacsPointer);

    if (!FacsPointer)
        return STATUS_SUCCESS;

    PhysicalAddress.QuadPart = (ULONGLONG)FacsPointer;

  #if !defined(_M_AMD64)
    ASSERT(PhysicalAddress.HighPart == 0);
  #endif

    Facs = MmMapIoSpace(PhysicalAddress, sizeof(FACS), MmNonCached);
    if (!Facs)
    {
        ASSERT(Facs != NULL);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (Facs->Signature != 'SCAF')
    {
        DPRINT1("ACPILoadProcessFACS: %X does not have FACS signature\n", Facs);
        return STATUS_ACPI_INVALID_TABLE;
    }

    if (Facs->Length != sizeof(FACS))
    {
        DPRINT1("ACPILoadProcessFACS: %X does not have correct FACS length\n", Facs);
        return STATUS_ACPI_INVALID_TABLE;
    }

    DPRINT("ACPILoadProcessFACS: FACS located at %X\n", Facs);

    AcpiInformation->FirmwareACPIControlStructure = Facs;
    AcpiInformation->GlobalLock = &Facs->GlobalLock;

    DPRINT("ACPILoadProcessFACS: Initial GlobalLock state: %X\n", *AcpiInformation->GlobalLock);

    return STATUS_SUCCESS;
}

ULONG
NTAPI
GetFadtTablePointerEntry(
    _In_ PFADT Fadt,
    _In_ PULONG IoPort,
    _In_ PGEN_ADDR GenAddr,
    _In_ SIZE_T NumberOfBytes)
{
    ULONG RetValue;

  #if !defined(_M_AMD64)
    // ? ASSERT(GenAddr->Address.HighPart == 0);
  #endif

    //DPRINT("GetFadtTablePointerEntry: %p, %p, %p, %X, %X\n", Fadt, IoPort, GenAddr, NumberOfBytes, Fadt->Header.Revision);

    if (Fadt->Header.Revision >= 3)
    {
        //DPRINT("GetFadtTablePointerEntry: AddressSpaceID %X\n", GenAddr->AddressSpaceID);
        if (GenAddr->AddressSpaceID)
        {
            if (GenAddr->AddressSpaceID != 1)
            {
                DPRINT1("GetFadtTablePointerEntry: AddressSpaceID %X\n", GenAddr->AddressSpaceID);
                ASSERT(FALSE);
            }
        }
        else
        {
            //DPRINT("GetFadtTablePointerEntry: Address.QuadPart %I64X\n", GenAddr->Address.QuadPart);
            if (GenAddr->Address.QuadPart)
            {
                if (MmMapIoSpace(GenAddr->Address, NumberOfBytes, MmNonCached))
                {
                    DPRINT("GetFadtTablePointerEntry: %p, %p, %p, %p\n", AcpiReadRegisterRoutine, DefPortReadAcpiRegister, AcpiWriteRegisterRoutine, DefPortWriteAcpiRegister);

                    if (AcpiReadRegisterRoutine == DefPortReadAcpiRegister &&
                        AcpiWriteRegisterRoutine == DefPortWriteAcpiRegister)
                    {
                        AcpiReadRegisterRoutine = DefRegisterReadAcpiRegister;
                        AcpiWriteRegisterRoutine = DefRegisterWriteAcpiRegister;
                    }
                }
                else
                {
                    DPRINT1("GetFadtTablePointerEntry: Address.QuadPart %I64X\n", GenAddr->Address.QuadPart);
                    ASSERT(FALSE);
                }
            }
        }
    }

    //DPRINT("GetFadtTablePointerEntry: IoPort %X\n", IoPort);
    RetValue = *IoPort;

    if (AcpiReadRegisterRoutine == DefRegisterReadAcpiRegister &&
        AcpiWriteRegisterRoutine == DefRegisterWriteAcpiRegister)
    {
        AcpiReadRegisterRoutine = DefPortReadAcpiRegister;
        AcpiWriteRegisterRoutine = DefPortWriteAcpiRegister;
    }

    DPRINT("GetFadtTablePointerEntry: RetValue %X\n", RetValue);

    return RetValue;
}

VOID
NTAPI
ACPIGpeClearRegisters(VOID)
{
    ULONG ix;
    UCHAR Status;

    DPRINT("ACPIGpeClearRegisters: GpeSize %X\n", AcpiInformation->GpeSize);

    for (ix = 0; ix < AcpiInformation->GpeSize; ix++)
    {
        Status = ACPIReadGpeStatusRegister(ix);
        ACPIWriteGpeStatusRegister(ix, (Status & (GpeEnable[ix] | GpeWakeEnable[ix])));
    }
}

VOID
NTAPI
ACPIGpeEnableDisableEvents(
    _In_ BOOLEAN IsEnableEvents)
{
    ULONG ix;

    DPRINT("ACPIGpeEnableDisableEvents: GpeSize %X\n", AcpiInformation->GpeSize);

    for (ix = 0; ix < AcpiInformation->GpeSize; ix++)
    {
        ACPIWriteGpeEnableRegister(ix, (IsEnableEvents == FALSE ? 0 : GpeCurEnable[ix]));
    }
}

NTSTATUS
NTAPI
ACPILoadProcessDSDT(
    _In_ PHYSICAL_ADDRESS PhysicalAddress)
{
    PDSDT Dsdt;
    ULONG numElements;
    ULONG Length;

    DPRINT("ACPILoadProcessDSDT: PhysicalAddress %I64X\n", PhysicalAddress.QuadPart);

  #if !defined(_M_AMD64)
    ASSERT(PhysicalAddress.HighPart == 0);
  #endif

    Dsdt = MmMapIoSpace(PhysicalAddress, sizeof(DESCRIPTION_HEADER), MmNonCached);
    if (!Dsdt)
    {
        DPRINT1("ACPILoadProcessDSDT: not mapped Dsdt\n");
        ASSERT(Dsdt != NULL);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if ( Dsdt->Header.Signature != 'TDSD')
    {
        DPRINT1("ACPILoadProcessDSDT: %X does not have DSDT signature\n", Dsdt);
        return STATUS_ACPI_INVALID_TABLE;
    }

    Length = Dsdt->Header.Length;
    MmUnmapIoSpace(Dsdt, sizeof(DESCRIPTION_HEADER));

  #if !defined(_M_AMD64)
    ASSERT(PhysicalAddress.HighPart == 0);
  #endif

    Dsdt = MmMapIoSpace(PhysicalAddress, Length, MmNonCached);
    if (!Dsdt)
    {
        DPRINT1("ACPILoadProcessDSDT: not mapped Dsdt\n");
        ASSERT(Dsdt != NULL);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!RsdtInformation->NumElements)
    {
        return STATUS_ACPI_NOT_INITIALIZED;
    }

    numElements = (RsdtInformation->NumElements - 1);

    if (ACPIRegReadAMLRegistryEntry((PDESCRIPTION_HEADER *)&Dsdt, TRUE))
    {
        DPRINT1("ACPILoadProcessDSDT: DSDT Overloaded from registry (%X)\n", Dsdt);
        RsdtInformation->Tables[numElements].Flags |= 8;
    }

    AcpiInformation->DiffSystemDescTable = Dsdt;

    RsdtInformation->Tables[numElements].Flags |= 5;
    RsdtInformation->Tables[numElements].Address = Dsdt;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPILoadProcessFADT(
    _In_ PFADT Fadt)
{
    PHYSICAL_ADDRESS PhysicalAddress;
    PVOID GpeTables;
    ULONG Size;
    BOOLEAN IsEnableEvents = FALSE;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ACPILoadProcessFADT: Fadt %p\n", Fadt);

    Status = ACPILoadProcessFACS(Fadt->facs);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPILoadProcessFADT: Status %X\n", Status);
        return Status;
    }

    //DPRINT("ACPILoadProcessFADT: %I64X\n", Fadt->x_pm1a_evt_blk.Address.QuadPart);
    AcpiInformation->PM1a_BLK = GetFadtTablePointerEntry(Fadt, &Fadt->pm1a_evt_blk_io_port, &Fadt->x_pm1a_evt_blk, 4);

    //DPRINT("ACPILoadProcessFADT: %I64X\n", Fadt->x_pm1b_evt_blk.Address.QuadPart);
    AcpiInformation->PM1b_BLK = GetFadtTablePointerEntry(Fadt, &Fadt->pm1b_evt_blk_io_port, &Fadt->x_pm1b_evt_blk, 4);

    //DPRINT("ACPILoadProcessFADT: %I64X\n", Fadt->x_pm1a_ctrl_blk.Address.QuadPart);
    AcpiInformation->PM1a_CTRL_BLK = GetFadtTablePointerEntry(Fadt, &Fadt->pm1a_ctrl_blk_io_port, &Fadt->x_pm1a_ctrl_blk, 4);

    //DPRINT("ACPILoadProcessFADT: %I64X\n", Fadt->x_pm1b_ctrl_blk.Address.QuadPart);
    AcpiInformation->PM1b_CTRL_BLK = GetFadtTablePointerEntry(Fadt, &Fadt->pm1b_ctrl_blk_io_port, &Fadt->x_pm1b_ctrl_blk, 4);

    //DPRINT("ACPILoadProcessFADT: %I64X\n", Fadt->x_pm2_ctrl_blk.Address.QuadPart);
    AcpiInformation->PM2_CTRL_BLK = GetFadtTablePointerEntry(Fadt, &Fadt->pm2_ctrl_blk_io_port, &Fadt->x_pm2_ctrl_blk, 4);

    //DPRINT("ACPILoadProcessFADT: %I64X\n", Fadt->x_pm_tmr_blk.Address.QuadPart);
    AcpiInformation->PM_TMR = GetFadtTablePointerEntry(Fadt, &Fadt->pm_tmr_blk_io_port, &Fadt->x_pm_tmr_blk, 4);

    AcpiInformation->SMI_CMD = Fadt->smi_cmd_io_port;

    DPRINT("ACPILoadProcessFADT: PM1a_BLK located at port %p\nACPILoadProcessFADT: PM1b_BLK located at port %p\n", AcpiInformation->PM1a_BLK, AcpiInformation->PM1b_BLK);
    DPRINT("ACPILoadProcessFADT: PM1a_CTRL_BLK located at port %p\nACPILoadProcessFADT: PM1b_CTRL_BLK located at port %p\n", AcpiInformation->PM1a_CTRL_BLK, AcpiInformation->PM1b_CTRL_BLK);
    DPRINT("ACPILoadProcessFADT: PM2_CTRL_BLK located at port %p\nACPILoadProcessFADT: PM_TMR located at port %p\n", AcpiInformation->PM2_CTRL_BLK, AcpiInformation->PM_TMR);

    AcpiInformation->GP1_Base_Index = -1;

    //DPRINT("ACPILoadProcessFADT: %I64X\n", Fadt->x_gp0_blk.Address.QuadPart);
    AcpiInformation->GP0_BLK = GetFadtTablePointerEntry(Fadt, &Fadt->gp0_blk_io_port, &Fadt->x_gp0_blk, Fadt->gp0_blk_len);
    if (AcpiInformation->GP0_BLK)
    {
        AcpiInformation->GP0_LEN = Fadt->gp0_blk_len;
        //ACPIAssert(Fadt->gp0_blk_len != 0, 0x100B, 0, 0, 5);
        ASSERT(Fadt->gp0_blk_len != 0);
    }

    //DPRINT("ACPILoadProcessFADT: %I64X\n", Fadt->x_gp1_blk.Address.QuadPart);
    AcpiInformation->GP1_BLK = GetFadtTablePointerEntry(Fadt, &Fadt->gp1_blk_io_port, &Fadt->x_gp1_blk, Fadt->gp1_blk_len);
    if (AcpiInformation->GP1_BLK)
    {
        AcpiInformation->GP1_LEN = Fadt->gp1_blk_len;
        AcpiInformation->GP1_Base_Index = Fadt->gp1_base;
        //ACPIAssert(Fadt->gp1_blk_len != 0, 0x100C, 0, 0, 5);
        ASSERT(Fadt->gp1_blk_len != 0);
    }

    AcpiInformation->Gpe0Size = ((UCHAR)AcpiInformation->GP0_LEN >> 1);
    AcpiInformation->Gpe1Size = ((UCHAR)AcpiInformation->GP1_LEN >> 1);

    AcpiInformation->GpeSize = (AcpiInformation->Gpe0Size + AcpiInformation->Gpe1Size);

    AcpiInformation->GP0_ENABLE = (AcpiInformation->GP0_BLK + AcpiInformation->Gpe0Size);
    AcpiInformation->GP1_ENABLE = (AcpiInformation->GP1_BLK + AcpiInformation->Gpe1Size);

    if (AcpiInformation->GpeSize)
    {
        Size = ((12 + 8) * AcpiInformation->GpeSize);

        GpeTables = ExAllocatePoolWithTag(NonPagedPool, Size, 'gpcA');
        if (!GpeTables)
        {
            DPRINT1("ACPILoadProcessFADT: Could not allocate GPE tables, size = %X\n", Size);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(GpeTables, Size);

        GpeEnable = GpeTables;
        GpeCurEnable = Add2Ptr(GpeTables, AcpiInformation->GpeSize);
        GpeIsLevel = Add2Ptr(GpeCurEnable, AcpiInformation->GpeSize);
        GpeHandlerType = Add2Ptr(GpeIsLevel, AcpiInformation->GpeSize);
        GpeWakeEnable = Add2Ptr(GpeHandlerType, AcpiInformation->GpeSize);
        GpeWakeHandler = Add2Ptr(GpeWakeEnable, AcpiInformation->GpeSize);
        GpeSpecialHandler = Add2Ptr(GpeWakeHandler, AcpiInformation->GpeSize);
        GpePending = Add2Ptr(GpeSpecialHandler, AcpiInformation->GpeSize);
        GpeRunMethod = Add2Ptr(GpePending, AcpiInformation->GpeSize);
        GpeComplete = Add2Ptr(GpeRunMethod, AcpiInformation->GpeSize);
        GpeSavedWakeMask = Add2Ptr(GpeComplete, AcpiInformation->GpeSize);
        GpeSavedWakeStatus = Add2Ptr(GpeSavedWakeMask, AcpiInformation->GpeSize);
        GpeMap = Add2Ptr(GpeSavedWakeStatus, AcpiInformation->GpeSize); // size of GpeMap = (8 * AcpiInformation->GpeSize)

        IsEnableEvents = FALSE;
    }

    DPRINT("ACPILoadProcessFADT: GP0_BLK located at port %p length %X\nACPILoadProcessFADT: GP1_BLK located at port %p length %X\nACPILoadProcessFADT: GP1_Base_Index = %X\n",
           AcpiInformation->GP0_BLK, AcpiInformation->GP0_LEN, AcpiInformation->GP1_BLK, AcpiInformation->GP1_LEN, AcpiInformation->GP1_Base_Index);

    ACPIGpeClearRegisters();
    ACPIGpeEnableDisableEvents(IsEnableEvents);

    AcpiInformation->ACPI_Flags = 0;
    AcpiInformation->ACPI_Capabilities = 0;
    AcpiInformation->Dockable = ((Fadt->flags >> 9) & 1);
    AcpiInformation->pm1_en_bits = 0x21;

    if (Fadt->flags & 0x10)
    {
        DPRINT("ACPILoadProcessFADT: Power Button not fixed event or not present\n");
    }
    else
    {
        AcpiInformation->pm1_en_bits |= 0x100;
        DPRINT("ACPILoadProcessFADT: Power Button in Fixed Feature Space\n");
    }

    if (Fadt->flags & 0x20)
    {
        DPRINT("ACPILoadProcessFADT: Sleep Button not fixed event or not present\n");
    }
    else
    {
        AcpiInformation->pm1_en_bits |= 0x200;
        DPRINT("ACPILoadProcessFADT: Sleep Button in Fixed Feature Space\n");
    }

    PhysicalAddress.QuadPart = (ULONGLONG)Fadt->dsdt;

    Status = ACPILoadProcessDSDT(PhysicalAddress);
    return Status;
}

NTSTATUS
NTAPI
ACPILoadProcessRSDT(VOID)
{
    PDESCRIPTION_HEADER MappedAddress;
    PDESCRIPTION_HEADER SimulatorTable;
    PHYSICAL_ADDRESS PhysicalAddress;
    PRSDT Rsdt;
    PXSDT Xsdt;
    ULONG NumElements;
    ULONG FullSize;
    ULONG Offset;
    ULONG Size;
    ULONG ix;
    BOOLEAN IsForceSuccesStatus = FALSE;
    BOOLEAN IsXsdtTable = FALSE;
    BOOLEAN Result = FALSE;

    PAGED_CODE();
    DPRINT("ACPILoadProcessRSDT()\n");

    FullSize = AcpiInformation->RootSystemDescTable->Header.Length;
    Offset = FIELD_OFFSET(RSDT, Tables);

    if (AcpiInformation->RootSystemDescTable->Header.Signature == 'TDSX')
    {
        Xsdt = (PXSDT)AcpiInformation->RootSystemDescTable;

        if (FullSize < Offset)
            Offset = AcpiInformation->RootSystemDescTable->Header.Length;

        NumElements = ((FullSize - Offset) / sizeof(PHYSICAL_ADDRESS));

        IsXsdtTable = TRUE;
    }
    else
    {
        Rsdt = (PRSDT)AcpiInformation->RootSystemDescTable;

        if (FullSize < Offset)
            Offset = AcpiInformation->RootSystemDescTable->Header.Length;

        NumElements = ((FullSize - Offset) / sizeof(ULONG));
    }

    DPRINT("ACPILoadProcessRSDT: RSDT contains %u tables\n", NumElements);

    if (!NumElements)
    {
        DPRINT1("ACPILoadProcessRSDT: STATUS_ACPI_INVALID_TABLE\n");
        return STATUS_ACPI_INVALID_TABLE;
    }

    Size = (sizeof(RSDTINFORMATION) + ((NumElements + 1) * sizeof(RSDTELEMENT)));

    RsdtInformation = ExAllocatePoolWithTag(NonPagedPool, Size, 'tpcA');
    if (!RsdtInformation)
    {
        DPRINT1("ACPILoadProcessRSDT: STATUS_ACPI_INVALID_TABLE\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(RsdtInformation, Size);

    RsdtInformation->NumElements = (NumElements + 2);

    for (ix = 0; ix < NumElements; ix++)
    {
        DPRINT("ACPILoadProcessRSDT: ix %X \n", ix);

        if (IsXsdtTable)
            PhysicalAddress.QuadPart = Xsdt->Tables[ix].QuadPart;
        else
            PhysicalAddress.QuadPart = Rsdt->Tables[ix];

      #if !defined(_M_AMD64)
        ASSERT(PhysicalAddress.HighPart == 0);
      #endif

        MappedAddress = MmMapIoSpace(PhysicalAddress, sizeof(DESCRIPTION_HEADER), MmNonCached);
        if (!MappedAddress)
        {
            DPRINT1("ACPILoadProcessRSDT: STATUS_ACPI_INVALID_TABLE\n");
            ASSERT(MappedAddress != NULL);
            return STATUS_ACPI_INVALID_TABLE;
        }

        if (MappedAddress->Signature == 'TSBS')
        {
            DPRINT("ACPILoadProcessRSDT: SBST Found at %X\n", MappedAddress);
            MmUnmapIoSpace(MappedAddress, sizeof(DESCRIPTION_HEADER));
            continue;
        }

        if (MappedAddress->Signature != 'PCAF' &&
            MappedAddress->Signature != 'TDSS' &&
            MappedAddress->Signature != 'TDSP' &&
            MappedAddress->Signature != 'CIPA')
        {
            DPRINT("ACPILoadProcessRSDT: Unrecognized table signature %X\n", MappedAddress->Signature);
            MmUnmapIoSpace(MappedAddress, sizeof(DESCRIPTION_HEADER));
            continue;
        }

        Size = MappedAddress->Length;
        MmUnmapIoSpace(MappedAddress, sizeof(DESCRIPTION_HEADER));

      #if !defined(_M_AMD64)
        ASSERT(PhysicalAddress.HighPart == 0);
      #endif

        MappedAddress = MmMapIoSpace(PhysicalAddress, Size, MmNonCached);
        if (!MappedAddress)
        {
            DPRINT1("ACPILoadProcesRSDT: Could not load table at %X\n", AcpiInformation->RootSystemDescTable->Tables[ix]);
            return STATUS_ACPI_INVALID_TABLE;
        }

        Result = ACPIRegReadAMLRegistryEntry(&MappedAddress, TRUE);
        if (Result)
        {
            DPRINT1("ACPILoadProcessRSDT: Table Overloaded from registry (%X)\n", MappedAddress);
            RsdtInformation->Tables[ix].Flags |= 8;
        }

        RsdtInformation->Tables[ix].Flags |= 1;
        RsdtInformation->Tables[ix].Address = MappedAddress;

        if (MappedAddress->Signature == 'PCAF')
        {
            AcpiInformation->FixedACPIDescTable = (PFADT)MappedAddress;
            IsForceSuccesStatus = TRUE;
            ACPILoadProcessFADT(AcpiInformation->FixedACPIDescTable);
        }
        else if (MappedAddress->Signature == 'CIPA')
        {
            AcpiInformation->MultipleApicTable = (PMAPIC)MappedAddress;
        }
        else
        {
            RsdtInformation->Tables[ix].Flags |= 4;
        }
    }

    Size = sizeof(*SimulatorTable);
    DPRINT("ACPILoadProcessRSDT: Size %X \n", Size);

    SimulatorTable = ExAllocatePoolWithTag(NonPagedPool, Size, 'tpcA');
    if (SimulatorTable)
    {
        RtlZeroMemory(SimulatorTable, Size);

        SimulatorTable->Signature = 'TDSS';
        SimulatorTable->Length = Size;
        SimulatorTable->Revision = 1;
        SimulatorTable->Checksum = 0;
        SimulatorTable->OEMRevision = 1;
        SimulatorTable->CreatorRev = 1;

        RtlCopyMemory(SimulatorTable->OEMID, "MSFT", 4 );
        RtlCopyMemory(SimulatorTable->OEMTableID, "simulatr", 8);
        RtlCopyMemory(SimulatorTable->CreatorID, "MSFT", 4);

        if (AcpiLoadSimulatorTable)
        {
            Result = ACPIRegReadAMLRegistryEntry(&SimulatorTable, FALSE);
        }

        if (Result)
        {
            DPRINT("ACPILoadProcessRSDT: Simulator Table Overloaded from registry (%X)\n", MappedAddress);

            RsdtInformation->Tables[NumElements].Flags |= (1 + 4 + 8);
            RsdtInformation->Tables[NumElements].Address = SimulatorTable;
        }
        else
        {
            ExFreePoolWithTag(SimulatorTable, 'tpcA');
        }
    }

    DPRINT("ACPILoadProcessRSDT: Size %X \n", Size);
    ACPIRegDumpAcpiTables();

    if (IsForceSuccesStatus)
        return STATUS_SUCCESS;

    DPRINT1("ACPILoadProcessRSDT: Did not find an FADT\n");
    return STATUS_ACPI_INVALID_TABLE;
}

/* ACPI INIT FUNCTIONS ******************************************************/

VOID
NTAPI
CLEAR_PM1_STATUS_REGISTER(VOID)
{
    USHORT Value;

    if (AcpiInformation->PM1a_BLK)
    {
        Value = AcpiReadRegisterRoutine(2, 0);
        AcpiWriteRegisterRoutine(2, 0, Value);
    }

    if (AcpiInformation->PM1b_BLK)
    {
        Value = AcpiReadRegisterRoutine(3, 0);
        AcpiWriteRegisterRoutine(3, 0, Value);
    }
}

USHORT
NTAPI
READ_PM1_CONTROL(VOID)
{
    USHORT RetValue = 0;

    if (AcpiInformation->PM1a_CTRL_BLK)
        RetValue = AcpiReadRegisterRoutine(4, 0);

    if (AcpiInformation->PM1b_CTRL_BLK)
        RetValue |= AcpiReadRegisterRoutine(5, 0);

    return RetValue;
}

USHORT
NTAPI
READ_PM1_STATUS(VOID)
{
    USHORT RetValue = 0;

    if (AcpiInformation->PM1a_BLK)
        RetValue = AcpiReadRegisterRoutine(2, 0);

    if (AcpiInformation->PM1b_BLK)
        RetValue |= AcpiReadRegisterRoutine(3, 0);

    return RetValue;
}

USHORT
NTAPI
READ_PM1_ENABLE(VOID)
{
    USHORT RetValue = 0;

    if (AcpiInformation->PM1a_BLK)
        RetValue = AcpiReadRegisterRoutine(0, 0);

    if (AcpiInformation->PM1b_BLK)
        RetValue |= AcpiReadRegisterRoutine(1, 0);

    return RetValue;
}

VOID
NTAPI
WRITE_PM1_ENABLE(
    _In_ USHORT Value)
{
    if (AcpiInformation->PM1a_BLK)
      AcpiWriteRegisterRoutine(0, 0, Value);

    if (AcpiInformation->PM1b_BLK)
      AcpiWriteRegisterRoutine(1, 0, Value);
}

VOID
NTAPI
WRITE_PM1_CONTROL(
    _In_ USHORT Value,
    _In_ BOOLEAN Param2,
    _In_ UCHAR Flags)
{
    USHORT value;
  
    if (Param2)
    {
        ASSERT((Flags & 4) || (Value & 1));

        if (Flags & 1 && AcpiInformation->PM1a_BLK)
            AcpiWriteRegisterRoutine(4, 0, Value);

        if (Flags & 2 && AcpiInformation->PM1b_BLK)
            AcpiWriteRegisterRoutine(5, 0, Value);

        return;
    }

    if ((Flags & 1) && AcpiInformation->PM1a_BLK)
    {
        value = AcpiReadRegisterRoutine(4, 0);
        AcpiWriteRegisterRoutine(4, 0, (Value | value));
    }

    if ((Flags & 2) && AcpiInformation->PM1b_BLK)
    {
        value = AcpiReadRegisterRoutine(5, 0);
        AcpiWriteRegisterRoutine(5, 0, (Value | value));
    }
}

VOID
NTAPI
CLEAR_PM1_STATUS_BITS(
    _In_ ULONG Value)
{
    if (AcpiInformation->PM1a_BLK)
        (AcpiWriteRegisterRoutine)(2, 0, Value);

    if (AcpiInformation->PM1b_BLK)
        (AcpiWriteRegisterRoutine)(3, 0, Value);
}

VOID
NTAPI
ACPIEnableEnterACPIMode(
    _In_ BOOLEAN IsNotRevertAffinity)
{
    BOOLEAN IsNeedRevert = FALSE;
    UCHAR acpi_on_value;
    ULONG ix;

    ASSERTMSG("ACPIEnableEnterACPIMode: System already in ACPI mode!\n", !(READ_PM1_CONTROL() & 1));
    ASSERTMSG("ACPIEnableEnterACPIMode: System SMI_CMD port is zero\n", (AcpiInformation->SMI_CMD != 0));

    DPRINT("ACPIEnableEnterACPIMode: Enabling ACPI\n");

    if (!IsNotRevertAffinity)
    {
        if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
        {
            ASSERTMSG("ACPIEnableEnterACPIMode: IRQL >= DISPATCH_LEVEL\n", FALSE);
        }
        else
        {
            KeSetSystemAffinityThread(1);
            IsNeedRevert = TRUE;
        }
    }

    acpi_on_value = AcpiInformation->FixedACPIDescTable->acpi_on_value;

    AcpiWriteRegisterRoutine(8, 0, acpi_on_value);

    for (ix = 0; !(READ_PM1_CONTROL() & 1); ix++)
    {
        if (ix > 0xFFFFFF)
        {
            KeBugCheckEx(0xA5, 0x11, 6, 0, 0);
        }
    }

    if (IsNeedRevert)
        KeRevertToUserAffinityThread();
}

VOID
NTAPI
ACPIEnableInitializeACPI(
    _In_ BOOLEAN IsNotRevertAffinity)
{
    USHORT pm1_control;
    USHORT contents;

    if (!(READ_PM1_CONTROL() & 1))
    {
        AcpiInformation->ACPIOnly = FALSE;
        ACPIEnableEnterACPIMode(IsNotRevertAffinity);
    }

    CLEAR_PM1_STATUS_REGISTER();

    contents = (READ_PM1_STATUS() & 0xFBEF);
    if (contents)
    {
        CLEAR_PM1_STATUS_REGISTER();

        contents = (READ_PM1_STATUS() & 0xFBEF);
        ASSERTMSG("ACPIEnableInitializeACPI: Cannot clear PM1 Status Register\n", (contents == 0));
    }

    WRITE_PM1_ENABLE(AcpiInformation->pm1_en_bits);

    ASSERTMSG("ACPIEnableInitializeACPI: Cannot write all PM1 Enable Bits\n", (READ_PM1_ENABLE() == AcpiInformation->pm1_en_bits));

    if (IsNotRevertAffinity)
    {
        ACPIGpeClearRegisters();
        ACPIGpeEnableDisableEvents(TRUE);
    }

    pm1_control = READ_PM1_CONTROL();
    WRITE_PM1_CONTROL((pm1_control & ~0x2002), 1, 3);
}

NTSTATUS
NTAPI
ACPIBuildDeviceExtension(
    _In_ PAMLI_NAME_SPACE_OBJECT AcpiObject,
    _In_ PDEVICE_EXTENSION ParentDeviceExtension,
    _Out_ PDEVICE_EXTENSION* OutDeviceExtension)
{
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status;

    DPRINT("ACPIBuildDeviceExtension: Parent %p\n", ParentDeviceExtension);

    if (ParentDeviceExtension)
    {
        ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    }

    if (AcpiObject && AcpiObject->Context)
    {
        DeviceExtension = AcpiObject->Context;
        ASSERT(DeviceExtension->ParentExtension == ParentDeviceExtension);
        Status = ((DeviceExtension->ParentExtension != ParentDeviceExtension) ? STATUS_NO_SUCH_DEVICE : STATUS_SUCCESS);
        return Status;
    }

    DeviceExtension = ExAllocateFromNPagedLookasideList(&DeviceExtensionLookAsideList);
    if (!DeviceExtension)
    {
        DPRINT1("ACPIBuildDeviceExtension: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(DeviceExtension, sizeof(*DeviceExtension));

    DeviceExtension->ReferenceCount++;
    DeviceExtension->OutstandingIrpCount++;
    DeviceExtension->AcpiObject = AcpiObject;
    DeviceExtension->Signature = '_SGP';
    DeviceExtension->Flags = 0xA;

    *OutDeviceExtension = DeviceExtension;

    DeviceExtension->PowerInfo.DevicePowerMatrix[0] = 0;
    DeviceExtension->PowerInfo.DevicePowerMatrix[1] = 1;
    DeviceExtension->PowerInfo.DevicePowerMatrix[2] = 1;
    DeviceExtension->PowerInfo.DevicePowerMatrix[3] = 1;
    DeviceExtension->PowerInfo.DevicePowerMatrix[4] = 1;
    DeviceExtension->PowerInfo.DevicePowerMatrix[5] = 4;
    DeviceExtension->PowerInfo.DevicePowerMatrix[6] = 4;

    InitializeListHead(&DeviceExtension->ChildDeviceList);
    InitializeListHead(&DeviceExtension->EjectDeviceHead);
    InitializeListHead(&DeviceExtension->EjectDeviceList);
    InitializeListHead(&DeviceExtension->PowerInfo.WakeSupportList);
    InitializeListHead(&DeviceExtension->PowerInfo.PowerRequestListEntry);

    DeviceExtension->ParentExtension = ParentDeviceExtension;

    if (ParentDeviceExtension)
    {
        InterlockedIncrement(&ParentDeviceExtension->ReferenceCount);
        InsertTailList(&ParentDeviceExtension->ChildDeviceList, &DeviceExtension->SiblingDeviceList);
    }

    if (AcpiObject)
        AcpiObject->Context = DeviceExtension;

    return STATUS_SUCCESS;
}

/* ACPI CALLBACKS ***********************************************************/

VOID
NTAPI
ACPIGpeClearEventMasks(VOID)
{
    KIRQL Irql;

    DPRINT("ACPIGpeClearEventMasks()\n");

    KeAcquireSpinLock(&GpeTableLock, &Irql);

    ACPIGpeEnableDisableEvents(FALSE);
    ACPIGpeClearRegisters();

    RtlZeroMemory(GpeCurEnable, AcpiInformation->GpeSize);
    RtlZeroMemory(GpeEnable, AcpiInformation->GpeSize);
    RtlZeroMemory(GpeWakeEnable, AcpiInformation->GpeSize);
    RtlZeroMemory(GpeWakeHandler, AcpiInformation->GpeSize);
    RtlZeroMemory(GpeSpecialHandler, AcpiInformation->GpeSize);
    RtlZeroMemory(GpeRunMethod, AcpiInformation->GpeSize);
    RtlZeroMemory(GpePending, AcpiInformation->GpeSize);
    RtlZeroMemory(GpeComplete, AcpiInformation->GpeSize);
    RtlZeroMemory(GpeIsLevel, AcpiInformation->GpeSize);
    RtlZeroMemory(GpeHandlerType, AcpiInformation->GpeSize);

    KeReleaseSpinLock(&GpeTableLock, Irql);
}

BOOLEAN
NTAPI
ACPIInternalConvertToNumber(
    _In_ UCHAR Char1,
    _In_ UCHAR Char2,
    _Out_ ULONG* OutNumber)
{
    UCHAR Number1;
    UCHAR Number2;

    if (!OutNumber)
        return FALSE;

    if (Char2 >= '0' && Char2 <= '9')
    {
        Number1 = (0x10 * (Char2 - '0'));
    }
    else if (Char2 >= 'A' && Char2 <= 'F')
    {
        Number1 = (0x10 * (Char2 - '7'));
    }
    else
    {
        return FALSE;
    }

    if (Char1 >= '0' && Char1 <= '9')
    {
        Number2 = (Char2 - '0');
    }
    else if (Char1 >= 'A' && Char1 <= 'F')
    {
        Number2 = (Char2 - '7');
    }
    else
    {
        return FALSE;
    }

    *OutNumber = (Number1 | Number2);

    return TRUE;
}

BOOLEAN
NTAPI
ACPIGpeValidIndex(
    _In_ ULONG Index)
{
    if (Index < AcpiInformation->GP1_Base_Index)
        return (Index < (AcpiInformation->Gpe0Size << 3));

    return (Index < (AcpiInformation->GP1_Base_Index + (AcpiInformation->Gpe1Size << 3)));
}

BOOLEAN
NTAPI
ACPIGpeInstallRemoveIndex(
    _In_ ULONG Index,
    _In_ ULONG OperationType,
    _In_ ULONG SetHandlerType,
    _Out_ BOOLEAN* OutIsEnabled)
{
    ULONG GpeMask;
    ULONG ix;

    DPRINT("ACPIGpeInstallRemoveIndex: %X, %X, %X\n", Index, OperationType, SetHandlerType);

    if (!AcpiInformation->GP0_LEN)
    {
        UNIMPLEMENTED_DBGBREAK();
        return FALSE;
    }

    if (!ACPIGpeValidIndex(Index))
        return FALSE;

    GpeMask = (1 << (Index & 7));

    ix = ACPIGpeIndexToGpeRegister(Index);
    ASSERT(ix < (ULONG) AcpiInformation->GpeSize);

    if (ix >= AcpiInformation->GpeSize)
        return FALSE;

    if (OperationType == 2)
    {
        if (*OutIsEnabled)
        {
            GpeEnable[ix] |= GpeMask;
            GpeCurEnable[ix] |= GpeMask;
            GpeHandlerType[ix] |= GpeMask;
        }
        else
        {
            GpeEnable[ix] &= ~GpeMask;
            GpeCurEnable[ix] &= ~GpeMask;
            GpeHandlerType[ix] &= ~GpeMask;

            ASSERT(!(GpeWakeEnable[ix] & GpeMask));
        }

        DPRINT("ACPIGpeInstallRemoveIndex: Removing GPE #%X - Byte %X, bit %X\n", Index, ix, (Index & 7));
        return TRUE;
    }

    if (!(GpeEnable[ix] & GpeMask))
    {
        *OutIsEnabled = FALSE;
    }
    else if (!(GpeHandlerType[ix] & GpeMask))
    {
        return FALSE;
    }
    else
    {
        *OutIsEnabled = TRUE;
    }

    GpeEnable[ix] |= GpeMask;
    GpeCurEnable[ix] |= GpeMask;

    if (OperationType == 1)
        GpeIsLevel[ix] |= GpeMask;
    else
        GpeIsLevel[ix] &= ~GpeMask;

    if (SetHandlerType == 1)
        GpeHandlerType[ix] |= GpeMask;
    else
        GpeHandlerType[ix] &= ~GpeMask;

    DPRINT("ACPIGpeInstallRemoveIndex: Setting GPE #%X - Byte %X, bit %X\n", Index, ix, (Index & 7));
    return TRUE;
}

VOID
NTAPI
ACPIVectorBuildVectorMasks(VOID)
{
    ULONG ix;

    for (ix = 0; ix < GpeVectorTableSize; ix++)
    {
        UNIMPLEMENTED_DBGBREAK();
    }
}

VOID
NTAPI
ACPIGpeBuildEventMasks(VOID)
{
    PAMLI_NAME_SPACE_OBJECT NsObject;
    PAMLI_NAME_SPACE_OBJECT Child;
    ULONG OperationType;
    ULONG Index;
    KIRQL Irql;
    BOOLEAN IsEnabled;
    NTSTATUS Status;

    DPRINT("ACPIGpeBuildEventMasks()\n");

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &Irql);
    KeAcquireSpinLockAtDpcLevel(&GpeTableLock);

    Status = AMLIGetNameSpaceObject("\\_GPE", NULL, &NsObject, 0);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("ACPIGpeBuildEventMasks: Could not find \\_GPE object (%X)\n", Status);
        goto Finish;
    }

    for (Child = NsObject->FirstChild; Child; )
    {
        if (Child->ObjData.DataType == 8)
        {
            if (ACPIInternalConvertToNumber((Child->NameSeg >> 24),
                                            ((Child->NameSeg & 0xFF0000) >> 16),
                                            &Index))
            {
                if ((Child->NameSeg & 0xFF00) == 0x4C00) // 'L'
                {
                    OperationType = 1;
                    ACPIGpeInstallRemoveIndex(Index, OperationType, 1, &IsEnabled);
                }
                else if ((Child->NameSeg & 0xFF00) == 0x4500) // 'E'
                {
                    OperationType = 0;
                    ACPIGpeInstallRemoveIndex(Index, OperationType, 1, &IsEnabled);
                }
            }
        }

        if (!Child->Parent)
            break;

        Child = (PAMLI_NAME_SPACE_OBJECT)Child->List.Next;

        if (Child->Parent->FirstChild == Child)
            break;
    }

Finish:

    ACPIVectorBuildVectorMasks();
    ACPIGpeEnableDisableEvents(TRUE);

    KeReleaseSpinLockFromDpcLevel(&GpeTableLock);
    KeReleaseSpinLock(&AcpiDeviceTreeLock, Irql);
}

VOID
NTAPI
ACPITableLoadCallBack(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID Param2,
    _In_ NTSTATUS Param3)
{
    DPRINT("ACPITableLoadCallBack: %p\n", DeviceExtension);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    KeAcquireSpinLockAtDpcLevel(&AcpiDeviceTreeLock);
    KeAcquireSpinLockAtDpcLevel(&GpeTableLock);

    DPRINT("ACPITableLoadCallBack: FIXME ACPIGpeBuildWakeMasks()\n");

    KeReleaseSpinLockFromDpcLevel(&GpeTableLock);
    KeReleaseSpinLockFromDpcLevel(&AcpiDeviceTreeLock);

    KeAcquireSpinLockAtDpcLevel(&AcpiPowerQueueLock);

    if (!IsListEmpty(&AcpiPowerDelayedQueueList))
    {
        DPRINT1("ACPITableLoadCallBack: FIXME\n");
        ASSERT(FALSE);
    }

    KeReleaseSpinLockFromDpcLevel(&AcpiPowerQueueLock);
}

USHORT
NTAPI
ACPIEnableQueryFixedEnables(VOID)
{
    return AcpiInformation->pm1_en_bits;
}

NTSTATUS
NTAPI
ACPIBuildFixedButtonExtension(
    _In_ PDEVICE_EXTENSION RootDeviceExtension,
    _Out_ PDEVICE_EXTENSION* OutDeviceExtension)
{
    PDEVICE_EXTENSION DeviceExtension;
    ULONG ButtonCaps;
    USHORT EnBits;
    NTSTATUS Status;

    DPRINT("ACPIBuildFixedButtonExtension: %p\n", RootDeviceExtension);

    if (AcpiBuildFixedButtonEnumerated)
    {
        *OutDeviceExtension = NULL;
        return STATUS_SUCCESS;
    }

    AcpiBuildFixedButtonEnumerated = TRUE;

    EnBits = ACPIEnableQueryFixedEnables();

    ButtonCaps = 0;

    if (EnBits & 0x100)
        ButtonCaps = 1;

    if (EnBits & 0x200)
        ButtonCaps |= 2;

    if (!ButtonCaps)
    {
        *OutDeviceExtension = NULL;
        return STATUS_SUCCESS;
    }

    Status = ACPIBuildDeviceExtension(NULL, RootDeviceExtension, OutDeviceExtension);
    if (!NT_SUCCESS(Status))
    {
        *OutDeviceExtension = NULL;
        return Status;
    }

    DeviceExtension = *OutDeviceExtension;

    ACPIInternalUpdateFlags(&(*OutDeviceExtension)->Flags, 0x0018000000360000, FALSE);

    KeInitializeSpinLock(&DeviceExtension->Button.SpinLock);

    DeviceExtension->Button.Capabilities = (ButtonCaps | 0x80000000);

    DeviceExtension->Address = ExAllocatePoolWithTag(NonPagedPool, (strlen(ACPIFixedButtonId) + 1), 'SpcA');
    if (!DeviceExtension->Address)
    {
        ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0002000000000000, FALSE);
        *OutDeviceExtension = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    strcpy(DeviceExtension->Address, ACPIFixedButtonId);

    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0000A00000000000, FALSE);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIBuildRunMethodRequest(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID CallBack,
    _In_ PVOID CallBackContext,
    _In_ PVOID Context,
    _In_ ULONG Flags,
    _In_ BOOLEAN IsInsertDpc)
{
    PACPI_BUILD_REQUEST RunMethodRequest;
    PACPI_BUILD_REQUEST SynchronizationRequest;

    DPRINT("ACPIBuildRunMethodRequest: %p, %X, %X\n", DeviceExtension, Flags, IsInsertDpc);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    RunMethodRequest = ExAllocateFromNPagedLookasideList(&BuildRequestLookAsideList);
    if (!RunMethodRequest)
    {
        if (!CallBack)
            return STATUS_INSUFFICIENT_RESOURCES;

        DPRINT1("ACPIBuildRunMethodRequest: FIXME\n");
        ASSERT(FALSE);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (CallBack)
    {
        SynchronizationRequest = ExAllocateFromNPagedLookasideList(&BuildRequestLookAsideList);
        if (!SynchronizationRequest)
        {
            ExFreeToNPagedLookasideList(&BuildRequestLookAsideList, RunMethodRequest);

            DPRINT1("ACPIBuildRunMethodRequest: FIXME\n");
            ASSERT(FALSE);

            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    else
    {
        DPRINT("ACPIBuildRunMethodRequest: No CallBack\n");
    }

    if (!DeviceExtension->ReferenceCount)
    {
        ExFreeToNPagedLookasideList(&BuildRequestLookAsideList, RunMethodRequest);

        if (CallBack)
        {
            DPRINT1("ACPIBuildRunMethodRequest: FIXME\n");
            ASSERT(FALSE);
            ExFreeToNPagedLookasideList(&BuildRequestLookAsideList, SynchronizationRequest);
        }

        DPRINT1("ACPIBuildRunMethodRequest: STATUS_DEVICE_REMOVED\n");
        return STATUS_DEVICE_REMOVED;
    }

    InterlockedIncrement(&DeviceExtension->ReferenceCount);

    if (CallBack)
        InterlockedIncrement(&DeviceExtension->ReferenceCount);

    RtlZeroMemory(RunMethodRequest, sizeof(ACPI_BUILD_REQUEST));

    RunMethodRequest->Signature = '_SGP';
    RunMethodRequest->Status = STATUS_SUCCESS;
    RunMethodRequest->Flags = 0x100C;
    RunMethodRequest->Context = DeviceExtension;
    RunMethodRequest->ListHeadForInsert = &AcpiBuildRunMethodList;
    RunMethodRequest->WorkDone = 3;
    RunMethodRequest->RunMethod.Context = Context;
    RunMethodRequest->RunMethod.Flags = Flags;

    if (CallBack)
    {
        RtlZeroMemory(SynchronizationRequest, sizeof(ACPI_BUILD_REQUEST));

        SynchronizationRequest->Signature = '_SGP';
        SynchronizationRequest->Status = STATUS_SUCCESS;
        SynchronizationRequest->Flags = 0x100A;
        SynchronizationRequest->Context = DeviceExtension;
        SynchronizationRequest->CallBack = CallBack;
        SynchronizationRequest->CallBackContext = CallBackContext;
        SynchronizationRequest->ListHeadForInsert = &AcpiBuildSynchronizationList;
        SynchronizationRequest->WorkDone = 3;
        SynchronizationRequest->BuildReserved1 = 0;

        SynchronizationRequest->Synchronize.ListHead = &AcpiBuildRunMethodList;
        SynchronizationRequest->Synchronize.Context = Context;
        SynchronizationRequest->Synchronize.Reserved1 = 1;
    }

    KeAcquireSpinLockAtDpcLevel(&AcpiBuildQueueLock);

    InsertTailList(&AcpiBuildQueueList, &RunMethodRequest->Link);

    if (CallBack)
        InsertTailList(&AcpiBuildQueueList, &SynchronizationRequest->Link);

    if (IsInsertDpc && !AcpiBuildDpcRunning)
        KeInsertQueueDpc(&AcpiBuildDpc, NULL, NULL);

    KeReleaseSpinLockFromDpcLevel(&AcpiBuildQueueLock);

    return STATUS_PENDING;
}

VOID
NTAPI
ACPITableLoad(VOID)
{
    PAMLI_NAME_SPACE_OBJECT ChildObject;
    PDEVICE_EXTENSION DeviceExtension = NULL;
    PAMLI_NAME_SPACE_OBJECT NsObject;
    BOOLEAN IsGetChild = FALSE;
    KIRQL OldIrql;
    NTSTATUS Status;

    DPRINT("ACPITableLoad()\n");

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &OldIrql);

    /* System bus tree */
    Status = AMLIGetNameSpaceObject("\\_SB", NULL, &NsObject, 0);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPITableLoad: No SB Object!\n");
        ASSERT(FALSE);
    }

    if (!RootDeviceExtension->AcpiObject)
    {
        IsGetChild = TRUE;

        InterlockedIncrement(&RootDeviceExtension->ReferenceCount);

        RootDeviceExtension->AcpiObject = NsObject;
        NsObject->Context = RootDeviceExtension;

        Status = ACPIBuildFixedButtonExtension(RootDeviceExtension, &DeviceExtension);

        if (NT_SUCCESS(Status) && DeviceExtension)
            InterlockedIncrement(&DeviceExtension->ReferenceCount);
    }

    Status = ACPIBuildRunMethodRequest(RootDeviceExtension, NULL, NULL, (PVOID)'INI_', 7, FALSE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPITableLoad: FIXME\n");
        ASSERT(FALSE);
    }

    KeReleaseSpinLock(&AcpiDeviceTreeLock, OldIrql);

    if (IsGetChild)
    {
        ChildObject = ACPIAmliGetNamedChild(NsObject->Parent, 'INI_');
        if (ChildObject)
            AMLIAsyncEvalObject(ChildObject, NULL, 0, NULL, NULL, NULL);
    }

    DPRINT("ACPITableLoad: ACPITableLoadCallBack %X\n", ACPITableLoadCallBack);

    Status = ACPIBuildSynchronizationRequest(RootDeviceExtension, ACPITableLoadCallBack, NULL, &AcpiBuildDeviceList, FALSE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPITableLoad: FIXME\n");
        ASSERT(FALSE);
    }
    DPRINT("ACPITableLoad: Status %X\n", Status);

    KeAcquireSpinLock(&AcpiBuildQueueLock, &OldIrql);
    if (!AcpiBuildDpcRunning)
        KeInsertQueueDpc(&AcpiBuildDpc, NULL, NULL);
    KeReleaseSpinLock(&AcpiBuildQueueLock, OldIrql);

    DPRINT("ACPITableLoad: exit\n");
}

NTSTATUS
__cdecl
ACPICallBackLoad(
    _In_ int Param1,
    _In_ int Param2)
{
    DPRINT("ACPICallBackLoad: Param1 %X, Param2 %X\n", Param1, Param2);

    if (Param2 == 1)
    {
        if (InterlockedIncrement(&AcpiTableDelta) == 1)
            ACPIGpeClearEventMasks();
    }
    else if (!InterlockedDecrement(&AcpiTableDelta))
    {
        ACPIGpeBuildEventMasks();
        ACPITableLoad();
    }

    DPRINT("ACPICallBackLoad: ret STATUS_SUCCESS\n");
    return STATUS_SUCCESS;
}

NTSTATUS
__cdecl
ACPICallBackUnload(
    _In_ int Param1,
    _In_ int Param2)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
__cdecl
ACPITableNotifyFreeObject(
    _In_ int Param1,
    _In_ int Param2,
    _In_ int Param3)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

PACPI_POWER_INFO
NTAPI
OSPowerFindPowerInfo(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject)
{
    PDEVICE_EXTENSION DeviceExtension;
    PACPI_POWER_INFO PowerInfo;
    KIRQL OldIrql;

    ASSERT(NsObject != NULL);

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &OldIrql);

    DeviceExtension = NsObject->Context;
    if (!DeviceExtension)
    {
        KeReleaseSpinLock(&AcpiDeviceTreeLock, OldIrql);
        return NULL;
    }

    ASSERT(DeviceExtension->Signature == '_SGP');//ACPI_SIGNATURE

    KeReleaseSpinLock(&AcpiDeviceTreeLock, OldIrql);

    PowerInfo = &DeviceExtension->PowerInfo;

    return PowerInfo;
}

NTSTATUS
__cdecl
NotifyHandler(
    _In_ ULONG EventType,
    _In_ ULONG Notify,
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject)
{
    VOID (NTAPI* DeviceNotifyHandler)(PVOID, ULONG);
    PACPI_POWER_INFO Info;
    PVOID HandlerContext;
    KIRQL Irql;

    ASSERT(EventType == 2);//EVTYPE_NOTIFY

    DPRINT("ACPINotifyHandler: Notify on %p value %X, object type %X\n", NsObject, Notify, NsObject->ObjData.DataType);

    switch (Notify)
    {
        case 0:
            UNIMPLEMENTED_DBGBREAK();
            break;

        case 1:
            UNIMPLEMENTED_DBGBREAK();
            break;

        case 2:
            UNIMPLEMENTED_DBGBREAK();
            break;

        case 3:
            UNIMPLEMENTED_DBGBREAK();
            break;
    }

    Info = OSPowerFindPowerInfo(NsObject);
    if (!Info)
        return STATUS_SUCCESS;

    KeAcquireSpinLock(&NotifyHandlerLock, &Irql);

    DeviceNotifyHandler = Info->DeviceNotifyHandler;
    HandlerContext = Info->HandlerContext;

    KeReleaseSpinLock(&NotifyHandlerLock, Irql);

    if (DeviceNotifyHandler)
        DeviceNotifyHandler(HandlerContext, Notify);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
ACPIBuildDeviceRequest(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID CallBack,
    _In_ PVOID CallBackContext,
    _In_ BOOLEAN IsInsertDpc)
{
    PACPI_BUILD_REQUEST BuildRequest;

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    BuildRequest = ExAllocateFromNPagedLookasideList(&BuildRequestLookAsideList);
    if (!BuildRequest)
    {
        DPRINT1("ACPIBuildDeviceRequest: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!DeviceExtension->ReferenceCount)
    {
        DPRINT1("ACPIBuildDeviceRequest: STATUS_DEVICE_REMOVED\n");
        ExFreeToNPagedLookasideList(&BuildRequestLookAsideList, BuildRequest);
        return STATUS_DEVICE_REMOVED;
    }

    InterlockedIncrement(&DeviceExtension->ReferenceCount);

    RtlZeroMemory(BuildRequest, sizeof(*BuildRequest));

    BuildRequest->Context = DeviceExtension;
    BuildRequest->CallBack = CallBack;
    BuildRequest->Signature = '_SGP';
    BuildRequest->ListHeadForInsert = &AcpiBuildDeviceList;
    BuildRequest->WorkDone = 3;
    BuildRequest->Status = STATUS_SUCCESS;
    BuildRequest->CallBackContext = CallBackContext;
    BuildRequest->Flags = 0x1001;

    KeAcquireSpinLockAtDpcLevel(&AcpiBuildQueueLock);

    InsertTailList(&AcpiBuildQueueList, &BuildRequest->Link);

    if (IsInsertDpc && !AcpiBuildDpcRunning)
        KeInsertQueueDpc(&AcpiBuildDpc, NULL, NULL);

    KeReleaseSpinLockFromDpcLevel(&AcpiBuildQueueLock);

    return STATUS_PENDING;
}

NTSTATUS
NTAPI
OSNotifyCreateDevice(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ ULONGLONG FlagValue)
{
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status;
    PDEVICE_EXTENSION Destination = NULL;

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(NsObject != NULL);
    ASSERT(NsObject->Parent != NULL);

    DeviceExtension = NsObject->Parent->Context;
    if (!DeviceExtension)
    {
        DeviceExtension = RootDeviceExtension;
        ASSERT(RootDeviceExtension != NULL);
    }

    Status = ACPIBuildDeviceExtension(NsObject, DeviceExtension, &Destination);
    if (!Destination)
    {
        DPRINT1("OSNotifyCreateDevice: STATUS_UNSUCCESSFUL\n");
        Status = STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("OSNotifyCreateDevice: NSObj %p, Status %X\n", NsObject, Status);
        return Status;
    }

    InterlockedIncrement(&Destination->ReferenceCount);

    ACPIInternalUpdateFlags(&Destination->Flags, FlagValue, FALSE);

    Status = ACPIBuildDeviceRequest(Destination, NULL, NULL, FALSE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("OSNotifyCreateDevice: Destination %p, Status %X\n", Destination, Status);
    }

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildProcessorRequest(
    _In_ PDEVICE_EXTENSION ProcessorExt,
    _In_ ULONG Param2,
    _In_ ULONG Param3,
    _In_ ULONG Param4)
{
    return STATUS_PENDING;
}

NTSTATUS
NTAPI
ACPIBuildProcessorExtension(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ PDEVICE_EXTENSION ParentDeviceExtension,
    _Out_ PDEVICE_EXTENSION* OutDeviceExtension,
    _In_ ULONG ProcessorIndex)
{
    PDEVICE_EXTENSION DeviceExtension;
    PCHAR CompatIdStr;
    CHAR Char;
    NTSTATUS Status;

    if (!AcpiProcessorString.Buffer)
    {
        DPRINT1("ACPIBuildProcessorExtension: STATUS_OBJECT_NAME_NOT_FOUND\n");
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    Status = ACPIBuildDeviceExtension(NsObject, ParentDeviceExtension, OutDeviceExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIBuildProcessorExtension: Status %X\n", Status);
        return Status;
    }

    DeviceExtension = *OutDeviceExtension;
    if (DeviceExtension == NULL)
    {
        DPRINT1("ACPIBuildProcessorExtension: Status %X\n", Status);
        return Status;
    }

    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0010001000300000, FALSE);

    DeviceExtension->Processor.ProcessorIndex = ProcessorIndex;

    DeviceExtension->DeviceID = ExAllocatePoolWithTag(NonPagedPool, AcpiProcessorString.Length, 'SpcA');
    if (!DeviceExtension->DeviceID)
    {
        DPRINT1("ACPIBuildProcessorExtension: failed to allocate %X bytes\n", AcpiProcessorString.Length);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }

    RtlCopyMemory(DeviceExtension->DeviceID, AcpiProcessorString.Buffer, AcpiProcessorString.Length);

    CompatIdStr = AcpiProcessorCompatId;

    DeviceExtension->Processor.CompatibleID = ExAllocatePoolWithTag(NonPagedPool, (strlen(AcpiProcessorCompatId) + 1), 'SpcA');
    if (!DeviceExtension->Processor.CompatibleID)
    {
        do
            Char = *CompatIdStr++;
        while (Char);

        DPRINT1("ACPIBuildProcessorExtension: failed to allocate %X bytes\n", (CompatIdStr - (AcpiProcessorCompatId + 1) + 1));
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }

    strcpy(DeviceExtension->Processor.CompatibleID, AcpiProcessorCompatId);

    DeviceExtension->InstanceID = ExAllocatePoolWithTag(NonPagedPool, 3, 'SpcA');
    if (DeviceExtension->InstanceID)
    {
        sprintf(DeviceExtension->InstanceID, "%2d", (int)ProcessorIndex);
        ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x8001E00000000000, FALSE);
        DPRINT("ACPIBuildProcessorExtension: Status %X\n", Status);
        return Status;
    }

    DPRINT1("ACPIBuildProcessorExtension: failed to allocate %X bytes\n", 3);
    Status = STATUS_INSUFFICIENT_RESOURCES;

ErrorExit:

    if (DeviceExtension->InstanceID)
    {
        ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0001400000000000, TRUE);
        ExFreePoolWithTag(DeviceExtension->InstanceID, 'SpcA');
        DeviceExtension->InstanceID = NULL;
    }

    if (DeviceExtension->DeviceID)
    {
        ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0000A00000000000, TRUE);
        ExFreePoolWithTag(DeviceExtension->DeviceID, 'SpcA');
        DeviceExtension->DeviceID = NULL;
    }

    if (DeviceExtension->Processor.CompatibleID)
    {
        ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x8000000000000000, TRUE);
        ExFreePoolWithTag(DeviceExtension->Processor.CompatibleID, 'SpcA');
        DeviceExtension->Processor.CompatibleID = NULL;
    }

    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0002000000000000, TRUE);

    return Status;
}

NTSTATUS
NTAPI
OSNotifyCreateProcessor(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ ULONGLONG FlagValue)
{
    PDEVICE_EXTENSION ParentDeviceExt;
    PDEVICE_EXTENSION ProcessorExt = NULL;
    PAMLI_NAME_SPACE_OBJECT NsParentObject;
    ULONG ix;
    NTSTATUS Status;

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(NsObject != NULL);

    for (ix = 0; ix < 0x20; ix++)
    {
        if (!ProcessorList[ix])
            break;
    }

    if (ix >= 0x20)
        return STATUS_UNSUCCESSFUL;

    if (ProcessorList[ix])
        return STATUS_UNSUCCESSFUL;

    DPRINT("OSNotifyCreateProcessor: Processor %X, NsObject %p\n", (ix + 1), NsObject);

    ProcessorList[ix] = NsObject;

    NsParentObject = NsObject->Parent;
    ASSERT(NsParentObject != NULL);

    ParentDeviceExt = NsParentObject->Context;
    if (!ParentDeviceExt)
    {
        ParentDeviceExt = RootDeviceExtension;
        ASSERT(ParentDeviceExt != NULL);
    }

    Status = ACPIBuildProcessorExtension(NsObject, ParentDeviceExt, &ProcessorExt, ix);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("OSNotifyCreateProcessor: NSObj %p Failed %08lx\n", NsObject, Status);
        return Status;
    }

    InterlockedIncrement(&ProcessorExt->ReferenceCount);

    ACPIInternalUpdateFlags(&ProcessorExt->Flags, FlagValue, FALSE);

    Status = ACPIBuildProcessorRequest(ProcessorExt, 0, 0, 0);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("OSNotifyCreateProcessor: Status %X\n", Status);
    }

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildThermalZoneExtension(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ PDEVICE_EXTENSION ParentDeviceExtension,
    _Out_ PDEVICE_EXTENSION* OutDeviceExtension)
{
    PDEVICE_EXTENSION DeviceExtension;
    NTSTATUS Status;

    DPRINT("ACPIBuildThermalZoneExtension: %p, %p\n", NsObject, ParentDeviceExtension);

    Status = ACPIBuildDeviceExtension(NsObject, ParentDeviceExtension, OutDeviceExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIBuildThermalZoneExtension: Status %X\n", Status);
        return Status;
    }

    DeviceExtension = *OutDeviceExtension;
    if (!DeviceExtension)
    {
        DPRINT1("ACPIBuildThermalZoneExtension: Status %X\n", Status);
        return Status;
    }

    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0010000008320000, 0);

    DeviceExtension->Thermal.Info = ExAllocatePoolWithTag(NonPagedPool, sizeof(*DeviceExtension->Thermal.Info), 'TpcA');
    if (!DeviceExtension->Thermal.Info)
    {
        DPRINT1("ACPIBuildThermalZoneExtension: failed to allocate %X bytes\n", 0x94);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }
    RtlZeroMemory(DeviceExtension->Thermal.Info, sizeof(*DeviceExtension->Thermal.Info));

    DeviceExtension->DeviceID = ExAllocatePoolWithTag(NonPagedPool, (strlen("ACPI\\ThermalZone") + 1), 'SpcA');
    if (!DeviceExtension->DeviceID)
    {
        DPRINT1("ACPIBuildThermalZoneExtension: failed to allocate %X bytes\n", (strlen("ACPI\\ThermalZone") + 1));
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }
    strcpy(DeviceExtension->DeviceID, "ACPI\\ThermalZone");

    DeviceExtension->InstanceID = ExAllocatePoolWithTag(NonPagedPool, 5, 'SpcA');
    if (!DeviceExtension->InstanceID)
    {
        DPRINT1("ACPIBuildThermalZoneExtension: failed to allocate %X bytes\n", 5);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }

    RtlCopyMemory(DeviceExtension->InstanceID, (PCHAR)&DeviceExtension->AcpiObject->NameSeg, 4);
    DeviceExtension->InstanceID[4] = 0;

    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0001E00000000000, 0);

    DPRINT("ACPIBuildThermalZoneExtension: Status %X\n", Status);

    return Status;

ErrorExit:

    DPRINT1("ACPIBuildThermalZoneExtension: STATUS_INSUFFICIENT_RESOURCES\n");

    if (DeviceExtension->InstanceID)
    {
        ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0001400000000000, 1);
        ExFreePoolWithTag(DeviceExtension->InstanceID, 'SpcA');
        DeviceExtension->InstanceID = NULL;
    }

    if (DeviceExtension->Address)
    {
        ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0000A00000000000, 1);
        ExFreePoolWithTag(DeviceExtension->DeviceID, 'SpcA');
        DeviceExtension->Address = NULL;
    }

    if (DeviceExtension->Thermal.Info)
    {
        ExFreePoolWithTag(DeviceExtension->Thermal.Info, 'TpcA');
        DeviceExtension->Thermal.Info = NULL;
    }

    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0002000000000000, 1);

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildThermalZoneRequest(
    _In_ PDEVICE_EXTENSION DeviceExtension,
    _In_ PVOID CallBack,
    _In_ PVOID CallBackContext)
{
    PACPI_BUILD_REQUEST BuildRequest;

    DPRINT("ACPIBuildThermalZoneRequest: %p\n", DeviceExtension);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    BuildRequest = ExAllocateFromNPagedLookasideList(&BuildRequestLookAsideList);
    if (!BuildRequest)
    {
        DPRINT1("ACPIBuildThermalZoneRequest: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!DeviceExtension->ReferenceCount)
    {
        DPRINT1("ACPIBuildThermalZoneRequest: STATUS_DEVICE_REMOVED\n");
        ExFreeToNPagedLookasideList(&BuildRequestLookAsideList, BuildRequest);
        return STATUS_DEVICE_REMOVED;
    }

    InterlockedIncrement(&DeviceExtension->ReferenceCount);

    RtlZeroMemory(BuildRequest, sizeof(*BuildRequest));

    BuildRequest->Signature = '_SGP';
    BuildRequest->Flags = 0x1008;
    BuildRequest->WorkDone = 3;
    BuildRequest->Context = DeviceExtension;
    BuildRequest->Status = STATUS_SUCCESS;
    BuildRequest->CallBack = CallBack;
    BuildRequest->CallBackContext = CallBackContext;
    BuildRequest->ListHeadForInsert = &AcpiBuildThermalZoneList;

    KeAcquireSpinLockAtDpcLevel(&AcpiBuildQueueLock);
    InsertTailList(&AcpiBuildQueueList, &BuildRequest->Link);
    KeReleaseSpinLockFromDpcLevel(&AcpiBuildQueueLock);

    return STATUS_PENDING;
}

NTSTATUS
NTAPI
OSNotifyCreateThermalZone(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ ULONGLONG FlagValue)
{
    PDEVICE_EXTENSION DeviceExtension = NULL;
    NTSTATUS Status;

    DPRINT("OSNotifyCreateThermalZone: %p, %I64X\n", NsObject, FlagValue);

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(NsObject != NULL);

    Status = ACPIBuildThermalZoneExtension(NsObject, RootDeviceExtension, &DeviceExtension);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("OSNotifyCreateThermalZone: %p, %X\n", NsObject, Status);
        return Status;
    }

    InterlockedIncrement(&DeviceExtension->ReferenceCount);

    ACPIInternalUpdateFlags(&DeviceExtension->Flags, FlagValue, 0);

    Status = ACPIBuildThermalZoneRequest(DeviceExtension, NULL, NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("OSNotifyCreateThermalZone: Status %X\n", Status);
    }

    return Status;
}

NTSTATUS
NTAPI
ACPIBuildPowerResourceExtension(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _Out_ PACPI_POWER_DEVICE_NODE* OutPowerNode)
{
    PAMLI_POWER_RES_OBJECT PowerResObject;
    PACPI_POWER_DEVICE_NODE PowerNode;
    PACPI_POWER_DEVICE_NODE Node;
    PLIST_ENTRY Entry;
 
    PowerNode = ExAllocatePoolWithTag(NonPagedPool, sizeof(*PowerNode), 'DpcA');
    if (!PowerNode)
    {
        DPRINT("ACPIBuildPowerResourceExtension: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(PowerNode, sizeof(*PowerNode));

    PowerResObject = NsObject->ObjData.DataBuff;

    PowerNode->Flags = 4;
    PowerNode->PowerObject = NsObject;
    PowerNode->ResourceOrder = PowerResObject->ResOrder;
    PowerNode->WorkDone = 3;

    if (PowerResObject->SystemLevel < 6)
        PowerNode->SystemLevel = SystemPowerStateTranslation[PowerResObject->SystemLevel];
    else
        PowerNode->SystemLevel = 0;

    InitializeListHead(&PowerNode->DevicePowerListHead);

    *OutPowerNode = PowerNode;
    NsObject->Context = PowerNode;

    KeAcquireSpinLockAtDpcLevel(&AcpiPowerLock);

    for (Entry = AcpiPowerNodeList.Flink; Entry != &AcpiPowerNodeList; Entry = Entry->Flink)
    {
        Node = CONTAINING_RECORD(Entry, ACPI_POWER_DEVICE_NODE, ListEntry);

        if (Node->ResourceOrder >= PowerNode->ResourceOrder)
        {
            InsertTailList(Entry, &PowerNode->ListEntry);
            break;
        }
    }

    if (Entry == &AcpiPowerNodeList)
        InsertTailList(Entry, &PowerNode->ListEntry);

    KeReleaseSpinLockFromDpcLevel(&AcpiPowerLock);
 
    return STATUS_PENDING;
}

NTSTATUS
NTAPI
ACPIBuildPowerResourceRequest(
    _In_ PACPI_POWER_DEVICE_NODE PowerNode)
{
    PACPI_BUILD_REQUEST BuildRequest;

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    BuildRequest = ExAllocateFromNPagedLookasideList(&BuildRequestLookAsideList);
    if (!BuildRequest)
    {
        DPRINT1("ACPIBuildPowerResourceRequest: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(BuildRequest, sizeof(*BuildRequest));

    BuildRequest->Signature = '_SGP';
    BuildRequest->Flags = 0x1000;
    BuildRequest->WorkDone = 3;
    BuildRequest->Context = PowerNode;
    BuildRequest->Status = STATUS_SUCCESS;
    BuildRequest->ListHeadForInsert = &AcpiBuildPowerResourceList;

    KeAcquireSpinLockAtDpcLevel(&AcpiBuildQueueLock);
    InsertTailList(&AcpiBuildQueueList, &BuildRequest->Link);
    KeReleaseSpinLockFromDpcLevel(&AcpiBuildQueueLock);

    return STATUS_PENDING;
}

NTSTATUS
NTAPI
OSNotifyCreatePowerResource(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject)
{
    PACPI_POWER_DEVICE_NODE PowerNode;
    NTSTATUS Status;

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    ASSERT(NsObject != NULL);

    Status = ACPIBuildPowerResourceExtension(NsObject, &PowerNode);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("OSNotifyCreatePowerResource: (%p) Status %X\n", NsObject, Status);
        return Status;
    }

    Status = ACPIBuildPowerResourceRequest(PowerNode);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("OSNotifyCreatePowerResource: (%p) Status %X\n", PowerNode, Status);
    }

    return Status;
}

static CHAR NameObject[8];

PCHAR
NTAPI
ACPIAmliNameObject(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject)
{
    RtlZeroMemory(NameObject, sizeof(NameObject));

    ASSERT(sizeof(NameObject) >= sizeof(NsObject->NameSeg));
    RtlCopyMemory(NameObject, &NsObject->NameSeg, sizeof(NsObject->NameSeg));

    NameObject[4] = 0;

    return NameObject;
}

NTSTATUS
__cdecl
OSNotifyCreate(
    _In_ ULONG Type,
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject)
{
    KIRQL OldIrql;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("OSNotifyCreate: Type %X, NsObject %p\n");

    ASSERT(NsObject != NULL);

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &OldIrql);

    switch (Type)
    {
        case 6:
            Status = OSNotifyCreateDevice(NsObject, 0);
            break;

        case 0xA:
            DPRINT("OSNotifyCreate: FIXME\n");
            ASSERT(FALSE);
            break;

        case 0xB:
            Status = OSNotifyCreatePowerResource(NsObject);
            break;

        case 0xC:
            Status = OSNotifyCreateProcessor(NsObject, 0);
            break;

        case 0xD:
            Status = OSNotifyCreateThermalZone(NsObject, 0);
            break;

        default:
            DPRINT("OSNotifyCreate: received unhandled type %X\n", Type);
            break;
    }

    KeReleaseSpinLock(&AcpiDeviceTreeLock, OldIrql);

    DPRINT("OSNotifyCreate: (%p) '%s', Status %X\n", NsObject, ACPIAmliNameObject(NsObject), Status);

    return STATUS_SUCCESS;
}

NTSTATUS
__cdecl
OSNotifyFatalError(
    _In_ int Param1,
    _In_ int Param2,
    _In_ int Param3,
    _In_ int Param4)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/* ACPI ARBITER ROUTINES *****************************************************/

PACPI_VECTOR_BLOCK
NTAPI
HashVector(
    _In_ ULONG Vector)
{
    PACPI_VECTOR_BLOCK VectorBlock;
    ULONG CurrentVector;
    ULONG ix;

    PAGED_CODE();
    DPRINT("HashVector: Vector %X\n", Vector);

    VectorBlock = &IrqHashTable[2 * (Vector % 0x1F)];

    while (TRUE)
    {
        for (ix = 0; ix < 2; ix++)
        {
            CurrentVector = VectorBlock->Entry.Vector;

            if (VectorBlock->Chain.Token == 'WWWW')
                break;

            if (CurrentVector == Vector)
                return VectorBlock;

            if (CurrentVector == 'XXXX')
                return NULL;

            if (ix == 1)
                return NULL;

            VectorBlock++;
        }

        ASSERT(VectorBlock->Chain.Token == 'WWWW');//TOKEN_VALUE

        VectorBlock = VectorBlock->Chain.Next;
    }

    DPRINT1("HashVector: FIXME\n");
    ASSERT(FALSE);

    return NULL;
}

NTSTATUS
NTAPI
LookupIsaVectorOverride(
    _In_ ULONG IntVector,
    _Out_ ULONG* OutGlobalVector,
    _Out_ UCHAR* OutFlags)
{
    PACPI_MADT_INTERRUPT_OVERRIDE EntryHeader;
    PMAPIC Mapic;
    ULONG_PTR EndMapic;

    PAGED_CODE();
    DPRINT("LookupIsaVectorOverride: IntVector %X\n", IntVector);

    if (!InterruptModel)
    {
        DPRINT1("LookupIsaVectorOverride: STATUS_NOT_FOUND\n");
        return STATUS_NOT_FOUND;
    }

    if (IntVector >= 0x10)
    {
        DPRINT1("LookupIsaVectorOverride: STATUS_NOT_FOUND\n");
        return STATUS_NOT_FOUND;
    }

    Mapic = AcpiInformation->MultipleApicTable;
    if (!Mapic)
    {
        DPRINT1("LookupIsaVectorOverride: STATUS_NOT_FOUND\n");
        return STATUS_NOT_FOUND;
    }

    EntryHeader = (PACPI_MADT_INTERRUPT_OVERRIDE)Mapic->APICTables;
    EndMapic = (ULONG_PTR)Add2Ptr(Mapic, Mapic->Header.Length);

    while ((ULONG_PTR)EntryHeader < EndMapic)
    {
        if (EntryHeader->Header.Type == 2 &&
            EntryHeader->Header.Length == 0xA &&
            EntryHeader->SourceIrq == IntVector)
        {
            if (OutGlobalVector)
                *OutGlobalVector = EntryHeader->GlobalIrq;

            if (!OutFlags)
                return STATUS_SUCCESS;

            *OutFlags = 0;

            if ((EntryHeader->IntiFlags & 3) != 1 && (EntryHeader->IntiFlags & 3))
                *OutFlags = 2;

            if ((EntryHeader->IntiFlags & 0xC) == 4)
                return STATUS_SUCCESS;

            if (EntryHeader->IntiFlags & 0xC)
                *OutFlags |= 1;

            return STATUS_SUCCESS;
        }

        if (!EntryHeader->Header.Length)
        {
            DPRINT1("LookupIsaVectorOverride: STATUS_NOT_FOUND\n");
            return STATUS_NOT_FOUND;
        }

        EntryHeader = Add2Ptr(EntryHeader, EntryHeader->Header.Length);
    }

    DPRINT("LookupIsaVectorOverride: STATUS_NOT_FOUND\n");
    return STATUS_NOT_FOUND;
}

NTSTATUS
NTAPI
AddVectorToTable(
    _In_ ULONG Vector,
    _In_ UCHAR Count,
    _In_ UCHAR TempCount,
    _In_ UCHAR Flags)
{
    PACPI_VECTOR_BLOCK VectorBlock;
    PACPI_VECTOR_BLOCK NewEntries;
    ULONG ix;

    PAGED_CODE();
    DPRINT("AddVectorToTable: %X, %X, %X, %X\n", Vector, Count, TempCount, Flags);

    ASSERT((Flags & 0xF8) == 0);// ~(VECTOR_MODE | VECTOR_POLARITY | VECTOR_TYPE)

    for (VectorBlock = &IrqHashTable[2 * (Vector % 0x1F)];
         ;
         VectorBlock = VectorBlock->Chain.Next)
    {
        for (ix = 0; ix < 2; ix++, VectorBlock++)
        {
            if (VectorBlock->Entry.Vector == 'WWWW')
                break;

            if (VectorBlock->Entry.Vector == 'XXXX')
            {
                VectorBlock->Entry.Vector = Vector;
                VectorBlock->Entry.Count = Count;
                VectorBlock->Entry.TempCount = TempCount;
                VectorBlock->Entry.Flags = Flags;
                VectorBlock->Entry.TempFlags = Flags;

                return STATUS_SUCCESS;
            }

            if (ix == 1)
            {
                NewEntries = ExAllocatePoolWithTag(PagedPool, (2 * sizeof(ACPI_VECTOR_BLOCK)), 'ApcA');
                if (!NewEntries)
                {
                    DPRINT1("AddVectorToTable: STATUS_INSUFFICIENT_RESOURCES (%X)\n", (2 * sizeof(ACPI_VECTOR_BLOCK)));
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                RtlFillMemory(NewEntries, (2 * sizeof(ACPI_VECTOR_BLOCK)), 'XX');
                RtlMoveMemory(NewEntries, VectorBlock, sizeof(*VectorBlock));

                VectorBlock->Chain.Next = NewEntries;
                VectorBlock->Entry.Vector = 'WWWW';

                break;
            }
        }
    }

    DPRINT1("AddVectorToTable: FIXME\n");
    ASSERT(FALSE);

    return STATUS_UNSUCCESSFUL;
}

VOID
NTAPI
ReferenceVector(
    _In_ ULONG Vector,
    _In_ UCHAR Flags)
{
    PACPI_VECTOR_BLOCK VectorBlock;

    PAGED_CODE();

    ASSERT((Flags & 0xF8) == 0);// ~(VECTOR_MODE | VECTOR_POLARITY | VECTOR_TYPE)

    VectorBlock = HashVector(Vector);

    DPRINT("ReferenceVector: Flags %X, Vector %X (%X-%X)\n", Flags, Vector, 
           (VectorBlock ? VectorBlock->Entry.Count : 0), (VectorBlock ? VectorBlock->Entry.TempCount : 0));

    if (!VectorBlock)
    {
        AddVectorToTable(Vector, 0, 1, Flags);
        return;
    }

    if ((VectorBlock->Entry.TempCount + VectorBlock->Entry.Count) == 0)
        VectorBlock->Entry.TempFlags = Flags;

    VectorBlock->Entry.TempCount++;

    ASSERT(Flags == VectorBlock->Entry.TempFlags);
    ASSERT(VectorBlock->Entry.Count <= 0xFF);
}

VOID
NTAPI
DereferenceVector(
    _In_ ULONG Vector)
{
    PACPI_VECTOR_BLOCK VectorBlock;

    VectorBlock = HashVector(Vector);
    ASSERT(VectorBlock);

    DPRINT("DereferenceVector: %X, %X, %X\n", Vector, VectorBlock->Entry.Count, VectorBlock->Entry.TempCount);

    VectorBlock->Entry.TempCount--;
    ASSERT((VectorBlock->Entry.TempCount * -1) <= VectorBlock->Entry.Count);
}

VOID
NTAPI
MakeTempVectorCountsPermanent(
    VOID)
{
    PACPI_PM_DISPATCH_TABLE HalAcpiDispatchTable = (PVOID)PmHalDispatchTable;
    PACPI_VECTOR_BLOCK HashEntry;
    ULONG CurrentVector;
    ULONG jx;
    ULONG ix;

    PAGED_CODE();
    DPRINT("MakeTempVectorCountsPermanent()\n");

    for (ix = 0; ix < 0x3E; ix += 2)
    {
        HashEntry = &IrqHashTable[ix];

StartHash:

        for (jx = 0; jx < 2; jx++)
        {
            CurrentVector = HashEntry->Entry.Vector;

            if (HashEntry->Chain.Token == 'WWWW')
            {
                HashEntry = HashEntry->Chain.Next;
                goto StartHash;
            }

            if (CurrentVector == 'XXXX')
                break;

            if ((HashEntry->Entry.Count + HashEntry->Entry.TempCount) != 0)
            {
                if (!HashEntry->Entry.Count || HashEntry->Entry.TempFlags != HashEntry->Entry.Flags)
                {
                    HalAcpiDispatchTable->HalSetVectorState(CurrentVector, HashEntry->Entry.TempFlags);
                }
            }

            HashEntry->Entry.Flags = HashEntry->Entry.TempFlags;
            HashEntry->Entry.Count += HashEntry->Entry.TempCount;

            HashEntry++;
        }
    }
}

VOID
NTAPI
ClearTempVectorCounts(
    VOID)
{
    PACPI_VECTOR_BLOCK VectorBlock;
    ULONG Idx = 0;
    ULONG ix;
  
    PAGED_CODE();

    do
    {
        VectorBlock = &IrqHashTable[Idx];

Start:

        for (ix = 0; ix < 2; ix++)
        {
            if (VectorBlock->Entry.Vector == 'WWWW')
            {
                VectorBlock = VectorBlock->Chain.Next;
                goto Start;
            }

            if (VectorBlock->Entry.Vector == 'XXXX')
                break;

            VectorBlock->Entry.TempCount = 0;
            VectorBlock->Entry.TempFlags = VectorBlock->Entry.Flags;

            VectorBlock++;
        }

        Idx += 2;
    }
    while (Idx < 0x3E);
}

NTSTATUS
__cdecl
DisableLinkNodesAsyncWorker(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ NTSTATUS InStatus,
    _In_ ULONG Param3,
    _In_ PVOID InContext)
{
    PDISABLE_LINK_NODES_CONTEXT Context = InContext;
    PAMLI_NAME_SPACE_OBJECT Child;
    PAMLI_NAME_SPACE_OBJECT Current;
    PCHAR IdString;
    NTSTATUS Status = STATUS_SUCCESS;

    ASSERT(Context);

    InterlockedIncrement(&Context->RefCount);

    while (Context->Type == 0)
    {
        Context->Type = 1;

        Status = ACPIGet(Context->NsObject, 'DIH_', 0x58080206, NULL, 0, DisableLinkNodesAsyncWorker, Context, &Context->DataBuff, NULL);
        if (Status == STATUS_PENDING)
            return STATUS_PENDING;

        if (NT_SUCCESS(Status))
            break;

        Context->Type = 3;
    }

    if (Context->Type == 1)
    {
        Context->Type = 3;

        IdString = Context->DataBuff;
        if (!IdString || !strstr(IdString, "PNP0C0F"))
            goto Type3;

        Child = ACPIAmliGetNamedChild(Context->NsObject, 'SID_');
        if (!Child)
        {
            DPRINT1("DisableLinkNodesAsyncWorker: KeBugCheckEx(..)\n");
            KeBugCheckEx(0xA5, 0x10006, (ULONG_PTR)Context->NsObject, 0, 0);
        }

        Context->Type = 2;

        Status = AMLIAsyncEvalObject(Child, NULL, 0, NULL, (PVOID)DisableLinkNodesAsyncWorker, Context);
        if (Status == STATUS_PENDING)
            return STATUS_PENDING;

        if (NT_SUCCESS(Status))
            goto Finish;

        goto Type3;
    }
    else if (Context->Type == 3)
    {
Type3:
        Context->ChildNsObject = Context->NsObject->FirstChild;
        if (!Context->ChildNsObject)
        {
            Status = STATUS_SUCCESS;
            goto Finish;
        }

        Context->Type = 4;
        goto Type4;
    }
    else if (Context->Type == 4)
    {
Type4:
        while (Context->ChildNsObject)
        {
            Current = Context->ChildNsObject;

            if (Current->Parent && (ULONG_PTR)Current->Parent->FirstChild != (ULONG_PTR)Current->List.Next)
                Context->ChildNsObject = (PAMLI_NAME_SPACE_OBJECT)Current->List.Next;
            else
                Context->ChildNsObject = NULL;

            if (Current->ObjData.DataType == 6)
                Status = DisableLinkNodesAsync(Current, DisableLinkNodesAsyncWorker, (PVOID)Context);

            if (Status == STATUS_PENDING)
                return STATUS_PENDING;
        }
    }

Finish:

    if (Context->RefCount)
    {
        PAMLI_FN_ASYNC_CALLBACK CallBack = Context->Callback;
        CallBack(Context->NsObject, Status, 0, Context->Context);
    }

    if (Context->DataBuff)
        ExFreePool(Context->DataBuff);

    ExFreePool(Context);

    return Status;
}

NTSTATUS
NTAPI
DisableLinkNodesAsync(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ PVOID Callback,
    _In_ PVOID InContext)
{
    PDISABLE_LINK_NODES_CONTEXT Context;
    NTSTATUS Status;

    DPRINT("DisableLinkNodesAsync: NsObject %X\n", NsObject);

    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Context), 'ApcA');
    if (!Context)
    {
        DPRINT1("DisableLinkNodesAsync: STATUS_INSUFFICIENT_RESOURCES (%X)\n", sizeof(*Context));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Context, sizeof(*Context));

    Context->NsObject = NsObject;
    Context->Type = 0;
    Context->Callback = Callback;
    Context->Context = InContext;
    Context->RefCount = -1;

    Status = DisableLinkNodesAsyncWorker(NsObject, STATUS_SUCCESS, 0, Context);

    return Status;
}

VOID
__cdecl
AmlisuppCompletePassive(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ NTSTATUS InStatus,
    _In_ ULONG Param3,
    _In_ PVOID Context)
{
    PACPI_WAIT_CONTEXT WaitContext = Context;

    ASSERT(WaitContext);

    WaitContext->Status = InStatus;
    KeSetEvent(&WaitContext->Event, 0, FALSE);
}

NTSTATUS
NTAPI
AcpiArbUnpackRequirement(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _Out_ PULONGLONG OutMinimumAddress,
    _Out_ PULONGLONG OutMaximumAddress,
    _Out_ PULONG OutLength,
    _Out_ PULONG OutAlignment)
{
    PAGED_CODE();
    DPRINT("AcpiArbUnpackRequirement: [%p] %I64X, %I64X, %X\n", IoDescriptor, IoDescriptor->u.Generic.MinimumAddress.QuadPart,
           IoDescriptor->u.Generic.MaximumAddress.QuadPart, IoDescriptor->u.Generic.Length);

    ASSERT(IoDescriptor);
    ASSERT(IoDescriptor->Type == CmResourceTypeInterrupt);

    *OutMinimumAddress = IoDescriptor->u.Port.Length;
    *OutMaximumAddress = IoDescriptor->u.Dma.MaximumChannel;
    *OutLength = 1;
    *OutAlignment = 1;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
AcpiArbPackResource(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _In_ ULONGLONG Start,
    _Out_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor)
{
    DPRINT("AcpiArbPackResource: %p, %I64X\n", IoDescriptor, Start);
    PAGED_CODE();

    ASSERT(CmDescriptor);
    ASSERT(Start < 0xFFFFFFFF);
    ASSERT(IoDescriptor);
    ASSERT(IoDescriptor->Type == CmResourceTypeInterrupt);

    CmDescriptor->Type = CmResourceTypeInterrupt;
    CmDescriptor->Flags = IoDescriptor->Flags;
    CmDescriptor->ShareDisposition = IoDescriptor->ShareDisposition;

    CmDescriptor->u.Interrupt.Vector = Start;
    CmDescriptor->u.Interrupt.Level = Start;
    CmDescriptor->u.Interrupt.Affinity = 0xFFFFFFFF;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
AcpiArbUnpackResource(
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor,
    _Out_ PULONGLONG Start,
    _Out_ PULONG OutLength)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

LONG
NTAPI
AcpiArbScoreRequirement(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    UNIMPLEMENTED_DBGBREAK();
    return 0;
}

BOOLEAN
NTAPI
LinkNodeInUse(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PAMLI_NAME_SPACE_OBJECT LinkNode,
    _Out_ ULONG* OutIrq,
    _Out_ UCHAR* OutFlags)
{
    PARBITER_EXTENSION ArbExtension;
    PACPI_LINK_NODE Node;

    PAGED_CODE();
    ASSERT(LinkNode);

    ArbExtension = Arbiter->Extension;

    if (IsListEmpty(&ArbExtension->LinkNodeHead))
    {
        DPRINT1("LinkNodeInUse: LinkNode list empty\n");
        return FALSE;
    }

    Node = CONTAINING_RECORD(ArbExtension->LinkNodeHead.Flink, ACPI_LINK_NODE, List);

    while (Node->NameSpaceObject != LinkNode)
    {
        Node = CONTAINING_RECORD(Node->List.Flink, ACPI_LINK_NODE, List);

        if (&Node->List == &ArbExtension->LinkNodeHead)
        {
            DPRINT1("LinkNodeInUse: Didn't find our link node (%p) on the Link Node List\n", LinkNode);
            return FALSE;
        }
    }

    if ((LONG)(Node->ReferenceCount + Node->TempRefCount) <= 0)
    {
        DPRINT1("LinkNodeInUse: Link Node %p is currently unreferenced\n", LinkNode);
        return FALSE;
    }

    if (OutIrq)
        *OutIrq = (ULONG)Node->TempIrq;

    if (OutFlags)
        *OutFlags = Node->Flags;

    DPRINT1("LinkNodeInUse: Link Node %p is in use\n", LinkNode);

    return TRUE;
}

NTSTATUS
NTAPI
AcpiArbGetLinkNodeOptions(
    _In_ PAMLI_NAME_SPACE_OBJECT LinkNode,
    _In_ PCM_RESOURCE_LIST* OutCmResource,
    _Out_ UCHAR* OutOptions)
{
    PIO_RESOURCE_REQUIREMENTS_LIST IoResource = NULL;
    PCM_RESOURCE_LIST CmResource = NULL;
    PVOID Data = NULL;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("AcpiArbGetLinkNodeOptions: %p\n", LinkNode);

    ASSERT(LinkNode);
    ACPIGet(LinkNode, 'SRP_', 0x28010008, NULL, 0, NULL, 0, &Data, NULL);

    if (!Data)
    {
        DPRINT1("AcpiArbGetLinkNodeOptions: STATUS_NOT_FOUND\n");
        return STATUS_NOT_FOUND;
    }

    Status = PnpBiosResourcesToNtResources(Data, 0, &IoResource);

    ExFreePool(Data);

    if (!IoResource)
    {
        DPRINT1("AcpiArbGetLinkNodeOptions: STATUS_UNSUCCESSFUL\n");
        return STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("AcpiArbGetLinkNodeOptions: Status %X\n", Status);
        return Status;
    }

    *OutOptions = 0;

    ASSERT(IoResource->AlternativeLists == 1);

    *OutOptions |= (UCHAR)IoResource->List[0].Descriptors[0].u.ConfigData.Reserved2;

    if (IoResource->List[0].Descriptors[0].Flags != 1)
        *OutOptions |= 1;
    else
        *OutOptions |= 0;

    Status = PnpIoResourceListToCmResourceList(IoResource, &CmResource);

    ExFreePool(IoResource);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("AcpiArbGetLinkNodeOptions: Status %X\n", Status);
        return Status;
    }

    *OutCmResource = CmResource;

    return STATUS_SUCCESS;
}

BOOLEAN
NTAPI
AcpiArbFindSuitableRange(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    PACPI_PM_DISPATCH_TABLE HalAcpiDispatchTable = (PVOID)PmHalDispatchTable;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PAMLI_NAME_SPACE_OBJECT LinkNode = NULL;
    PARBITER_EXTENSION ArbExtension;
    PCM_RESOURCE_LIST CmResource;
    ULONG DeviceIrq = 0;
    ULONG Vector;
    ULONG Count;
    ULONG ix;
    UCHAR VectorFlags;
    UCHAR Options;
    UCHAR Flags;
    NTSTATUS Status;

    DPRINT("AcpiArbFindSuitableRange: %p\n", Arbiter);
    PAGED_CODE();

    if (!ArbFindSuitableRange(Arbiter, ArbState))
        return FALSE;

    Status = AcpiArbCrackPRT(ArbState->Entry->PhysicalDeviceObject, &LinkNode, &DeviceIrq);
    if (Status == STATUS_UNSUCCESSFUL)
        return FALSE;

    if (Status != STATUS_SUCCESS)
    {
        for (Vector = ArbState->Start; Vector <= ArbState->End; Vector++)
        {
            Status = GetIsaVectorFlags(Vector, &VectorFlags);
            if (!NT_SUCCESS(Status))
            {
                VectorFlags = ((ArbState->CurrentAlternative->Descriptor->Flags == 1) ? 0 : 3);
            }

            Status = GetVectorProperties(Vector, &Flags);
            if (NT_SUCCESS(Status))
            {
                if (VectorFlags != Flags)
                    continue;
            }

            if (!HalAcpiDispatchTable->HalIsVectorValid(Vector))
            {
                DPRINT1("AcpiArbFindSuitableRange: Status %X\n", Status);
                ASSERT(FALSE);
            }

            ArbState->Start = Vector;
            ArbState->End = Vector;
            ArbState->CurrentAlternative->Length = 1;

            return TRUE;
        }

        return FALSE;
    }

    if (!LinkNode)
    {
        Status = GetVectorProperties(DeviceIrq, &Flags);
        if (NT_SUCCESS(Status))
        {
            if (!(Flags & 1) || !(Flags & 2))
                return FALSE;
        }

        if (ArbState->CurrentMinimum > DeviceIrq || ArbState->CurrentMaximum < DeviceIrq)
            return FALSE;

        DPRINT("AcpiArbFindSuitableRange: found %X from a static mapping.\n", (ULONG)ArbState->Start);

        if (!HalAcpiDispatchTable->HalIsVectorValid(DeviceIrq))
        {
            DPRINT1("AcpiArbFindSuitableRange: Status %X\n", Status);
            ASSERT(FALSE);
        }

        ArbState->Start = DeviceIrq;
        ArbState->End = DeviceIrq;
        ArbState->CurrentAlternative->Length = 1;

        return TRUE;
    }

    if (!LinkNodeInUse(Arbiter, LinkNode, &DeviceIrq, NULL))
    {
        Status = AcpiArbGetLinkNodeOptions(LinkNode, &CmResource, &Options);

        DPRINT("AcpiArbFindSuitableRange: Link node contained CM(%p)\n", CmResource);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("AcpiArbFindSuitableRange: (%p) Status %X\n", CmResource, Status);
            return FALSE;
        }

        ArbExtension = Arbiter->Extension;
        ASSERT(ArbExtension);

        ASSERT(CmResource->Count == 1);
        Count = CmResource->List[0].PartialResourceList.Count;

        for (ix = 0; ix < Count; ix++)
        {
            CmDescriptor = &CmResource->List[0].PartialResourceList.PartialDescriptors[(ix + AcpiArbPciAlternativeRotation) % Count];
            ASSERT(CmDescriptor->Type == CmResourceTypeInterrupt);

            Status = GetVectorProperties(CmDescriptor->u.Interrupt.Vector, &Flags);

            if (NT_SUCCESS(Status) && Options != Flags)
                continue;

            if (CmDescriptor->u.Interrupt.Vector < ArbState->CurrentMinimum ||
                CmDescriptor->u.Interrupt.Vector > ArbState->CurrentMaximum)
            {
                continue;
            }

            if (!HalAcpiDispatchTable->HalIsVectorValid(CmDescriptor->u.Interrupt.Vector))
            {
                DPRINT1("AcpiArbFindSuitableRange: Status %X\n", Status);
                ASSERT(FALSE);
            }

            ArbState->Start = CmDescriptor->u.Interrupt.Vector;
            ArbState->End = CmDescriptor->u.Interrupt.Vector;
            ArbState->CurrentAlternative->Length = 1;

            DPRINT1("AcpiArbFindSuitableRange: found %X from an unused link node.\n", CmDescriptor->u.Interrupt.Vector);

            ExFreePool(CmResource);

            ArbExtension->CurrentLinkNode = LinkNode;
            ArbExtension->LastPciIrq[ArbExtension->LastPciIrqIndex] = ArbState->Start;
            ArbExtension->LastPciIrqIndex = ((ArbExtension->LastPciIrqIndex + 1) % 0xA);

            return TRUE;
        }

        ExFreePool(CmResource);

        DPRINT1("AcpiArbFindSuitableRange: %X, %X\n", ix, Count);

        return FALSE;
    }

    if (ArbState->CurrentMinimum > DeviceIrq || ArbState->CurrentMaximum < DeviceIrq)
    {
        DPRINT1("AcpiArbFindSuitableRange: Status %X\n", Status);
        ASSERT(FALSE);
        return FALSE;
    }

    DPRINT1("AcpiArbFindSuitableRange: Status %X\n", Status);
    ASSERT(FALSE);


    return FALSE;
}

NTSTATUS
NTAPI
ClearTempLinkNodeCounts(
    _In_ PARBITER_INSTANCE Arbiter)
{
    PARBITER_EXTENSION ArbExtension;
    PLIST_ENTRY Entry;
    PACPI_LINK_NODE Node;

    DPRINT("ClearTempLinkNodeCounts: %X\n", Arbiter);
    PAGED_CODE();

    ArbExtension = Arbiter->Extension;

    for (Entry = ArbExtension->LinkNodeHead.Flink;
         Entry != &ArbExtension->LinkNodeHead;
         Entry = Entry->Flink)
    {
        Node = CONTAINING_RECORD(Entry, ACPI_LINK_NODE, List);

        Node->TempRefCount = 0;
        Node->TempIrq = Node->CurrentIrq;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
UnreferenceArbitrationList(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PLIST_ENTRY ArbitrationList)
{
    PAMLI_NAME_SPACE_OBJECT LinkNode;
    PARBITER_LIST_ENTRY Entry;
    PRTL_RANGE Range;
    RTL_RANGE_LIST_ITERATOR Iterator;
    ULONG Vector;
    UCHAR Flags;
    NTSTATUS Status;

    DPRINT("UnreferenceArbitrationList: %p\n", Arbiter);
    PAGED_CODE();

    RtlGetFirstRange(Arbiter->Allocation, &Iterator, &Range);

    while (Range)
    {
        DPRINT("UnreferenceArbitrationList: Looking at range: %X-%X (%p)\n", (ULONG)Range->Start, (ULONG)Range->End, Range->Owner);

        Entry = CONTAINING_RECORD(ArbitrationList->Flink, ARBITER_LIST_ENTRY, ListEntry);

        while (ArbitrationList != &Entry->ListEntry)
        {
            DPRINT("UnreferenceArbitrationList: Unreferencing allocations for device %p\n", Entry->PhysicalDeviceObject);

            if (Range->Owner == Entry->PhysicalDeviceObject)
            {
                for (Vector = (ULONG)Range->Start; Vector <= (ULONG)Range->End; Vector++)
                {
                    Status = GetVectorProperties(Vector, &Flags);
                    if (NT_SUCCESS(Status))
                    {
                        DPRINT("UnreferenceArbitrationList: Dereferencing %X\n", Vector);
                        DereferenceVector(Vector);
                    }
                }

                if (!(Range->Attributes & 1))
                {
                    Status = AcpiArbCrackPRT(Entry->PhysicalDeviceObject, &LinkNode, &Vector);
                    if (NT_SUCCESS(Status))
                    {
                        if (LinkNode)
                        {
                            DPRINT1("UnreferenceArbitrationList: Dereferencing %X\n", Vector);
                            ASSERT(FALSE);
                        }
                    }
                }
            }

            Entry = CONTAINING_RECORD(Entry->ListEntry.Flink, ARBITER_LIST_ENTRY, ListEntry);
        }

        RtlGetNextRange(&Iterator, &Range, TRUE);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
AcpiArbTestAllocation(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PLIST_ENTRY ArbitrationList)
{
    NTSTATUS Status;

    DPRINT("AcpiArbTestAllocation: %p, %p\n", Arbiter, ArbitrationList);
    PAGED_CODE();

    ClearTempVectorCounts();

    Status = ClearTempLinkNodeCounts(Arbiter);
    ASSERT(NT_SUCCESS(Status));

    Status = UnreferenceArbitrationList(Arbiter, ArbitrationList);
    ASSERT(NT_SUCCESS(Status));

    Status = ArbTestAllocation(Arbiter, ArbitrationList);

    DPRINT("AcpiArbTestAllocation: ret Status %X\n", Status);
    return Status;
}

NTSTATUS
NTAPI
AcpiArbBootAllocation(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PLIST_ENTRY ArbitrationList)
{
    NTSTATUS Status;

    DPRINT("AcpiArbBootAllocation: %p\n", Arbiter);
    PAGED_CODE();

    ClearTempVectorCounts();

    Status = ArbBootAllocation(Arbiter, ArbitrationList);

    MakeTempVectorCountsPermanent();

    return Status;
}

NTSTATUS
NTAPI
AcpiArbRetestAllocation(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PLIST_ENTRY ArbitrationList)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
AcpiArbRollbackAllocation(
    _In_ PARBITER_INSTANCE Arbiter)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
__cdecl
AcpiArbSetLinkNodeIrqWorker(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ NTSTATUS InStatus,
    _In_ PAMLI_OBJECT_DATA Data,
    _In_ PVOID InContext)
{
    PSET_LINK_NODE_IRQ Context = InContext;
    PACPI_EXTENDED_IRQ_DESCRIPTOR ExtendedIrqDesc;
    PACPI_RESOURCE_DATA_TYPE ResourceData;
    PAMLI_FN_ASYNC_CALLBACK CallBack;
    PAMLI_NAME_SPACE_OBJECT Child;
    PACPI_IRQ_DESCRIPTOR IrqDesc;
    PUCHAR Ptr;
    ULONG Length = 0;
    USHORT IrqTagLength = 0;
    USHORT Increment;
    UCHAR Checksum;
    BOOLEAN IsTagEnd = FALSE;
    BOOLEAN IsExtendedIrq = FALSE;
    BOOLEAN IsFoundIrqTag = FALSE;
    NTSTATUS Status;

    DPRINT("AcpiArbSetLinkNodeIrqWorker: %p, %X\n", NsObject, InStatus);

    Status = InStatus;

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("AcpiArbSetLinkNodeIrqWorker: Status %X\n", Status);
        goto Finish;
    }

    ASSERT(Context->CmDescriptor->Type == CmResourceTypeInterrupt);

    InterlockedIncrement(&Context->ReferenceCount);

    if (Context->Phase > 2)
    {
        DPRINT1("AcpiArbSetLinkNodeIrqWorker: KeBugCheckEx()! %X\n", Context->Phase);
        KeBugCheckEx(0xA3, 1, 5, 0, 0);
        goto Finish;
    }

    if (Context->Phase == 0)
    {
        Context->Phase = 1;

        Status = ACPIGet(Context->NsObject,
                         'SRP_',
                         0x58010008,
                         NULL,
                         0,
                         AcpiArbSetLinkNodeIrqWorker,
                         Context,
                         &Context->DataBuff,
                         NULL);

        if (Status == STATUS_PENDING)
            return STATUS_PENDING;

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("AcpiArbSetLinkNodeIrqWorker: Status %X\n", Status);
            goto Finish;
        }
    }
    else if (Context->Phase == 2)
    {
        ExFreePoolWithTag(Context->IrqTag, 'ApcA');
        Status = STATUS_SUCCESS;
        goto Finish;
    }

    Context->Phase = 2;

    if (!Context->DataBuff)
    {
        Status = STATUS_NOT_FOUND;
        goto Finish;
    }

    DPRINT("AcpiArbSetLinkNodeIrqWorker: Read _PRS buffer %p\n", Context->DataBuff);

    ResourceData = Context->DataBuff;

    if (!ResourceData->Small.Tag)
    {
        ExFreePool(Context->DataBuff);
        Status = STATUS_NOT_FOUND;
        goto Finish;
    }

    while (ResourceData->Small.Tag)
    {
        if (ResourceData->Large.Type)
        {
            Increment = (ResourceData->Large.Length + 3);

            if (ResourceData->Large.Name == 0x09) // Extended IRQ Descriptor
            {
                IsFoundIrqTag = TRUE;
                IsExtendedIrq = TRUE;

                IrqTagLength = 9;
                Length += 9;
            }
        }
        else
        {
            Increment = (ResourceData->Small.Length + 1);

            if (ResourceData->Small.Name == 0x0F) // End Tag Descriptor 
            {
                Length += Increment;

                if (Increment > 1)
                    IsTagEnd = 1;

                break;
            }

            if (ResourceData->Small.Name == 0x04) // IRQ Format Descriptor
            {
                IsFoundIrqTag = TRUE;

                IrqTagLength = Increment;
                Length += Increment;
            }
        }

        ResourceData = Add2Ptr(ResourceData, Increment);
    }

    if (!IsFoundIrqTag)
    {
        ExFreePool(Context->DataBuff);
        Status = STATUS_NOT_FOUND;
        goto Finish;
    }

    Context->IrqTag = ExAllocatePoolWithTag(NonPagedPool, Length, 'ApcA');
    if (!Context->IrqTag)
    {
        ExFreePool(Context->DataBuff);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Finish;
    }

    ASSERT(IrqTagLength <= Length);

    RtlCopyMemory(Context->IrqTag, Context->DataBuff, IrqTagLength);

    ExFreePool(Context->DataBuff);

    if (IsExtendedIrq)
    {
        DPRINT("AcpiArbSetLinkNodeIrqWorker: Found large IRQ descriptor\n");

        ExtendedIrqDesc = Context->IrqTag;

        ExtendedIrqDesc->Length = (IrqTagLength - 3);
        ExtendedIrqDesc->TableLength = 1;
        ExtendedIrqDesc->IntNumber[0] = Context->CmDescriptor->u.Interrupt.Level;
    }
    else
    {
        IrqDesc = Context->IrqTag;
        IrqDesc->IrqMask = (1 << Context->CmDescriptor->u.Interrupt.Level);
    }

    ResourceData = Add2Ptr(Context->IrqTag, IrqTagLength);

    if (IsTagEnd)
    {
        ResourceData->Small.Tag = (0x78 + 1);

        for (Ptr = Context->IrqTag; *Ptr != ResourceData->Small.Tag; Ptr++)
            Checksum = *Ptr;

        *((PUCHAR)ResourceData + 1) = (0x100 - Checksum);
    }
    else
    {
        ResourceData->Small.Tag = 0x78;
    }

    Child = ACPIAmliGetNamedChild(Context->NsObject, 'SRS_');
    if (!Child)
    {
        ExFreePoolWithTag(Context->IrqTag, 'ApcA');
        Status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto Finish;
    }

    Context->DataArgs.DataLen = Length;
    Context->DataArgs.DataType = 3;
    Context->DataArgs.DataBuff = Context->IrqTag;

    DPRINT("AcpiArbSetLinkNodeIrqWorker: Running _SRS\n");

    Status = AMLIAsyncEvalObject(Child, NULL, 1, &Context->DataArgs, (PVOID)AcpiArbSetLinkNodeIrqWorker, Context);
    if (Status == STATUS_PENDING)
        return STATUS_PENDING;

    if (NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Context->IrqTag, 'ApcA');
        Status = STATUS_SUCCESS;
    }
    else
    {
        DPRINT1("AcpiArbSetLinkNodeIrqWorker: Status %X\n", Status);
    }

Finish:

    if (Context->ReferenceCount)
    {
        CallBack = Context->CallBack;
        CallBack(NsObject, Status, NULL, Context->CallBackContext);
    }

    ExFreePool(Context);

    DPRINT("AcpiArbSetLinkNodeIrqWorker: Status %X\n", Status);

    return Status;
}

NTSTATUS
NTAPI
AcpiArbSetLinkNodeIrqAsync(
    _In_ PAMLI_NAME_SPACE_OBJECT LinkNode,
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor,
    _In_ PVOID CallBack,
    _In_ PVOID CallBackContext)
{
    PSET_LINK_NODE_IRQ Context;

    DPRINT("AcpiArbSetLinkNodeIrqAsync: %p\n", LinkNode);
    ASSERT(LinkNode);

    Context = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Context), 'ApcA');
    if (!Context)
    {
        DPRINT1("AcpiArbSetLinkNodeIrqAsync: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(Context, sizeof(*Context));

    Context->NsObject = LinkNode;
    Context->CmDescriptor = CmDescriptor;
    Context->CallBack = CallBack;
    Context->CallBackContext = CallBackContext;
    Context->Phase = 0;
    Context->ReferenceCount = -1;

    return AcpiArbSetLinkNodeIrqWorker(LinkNode, STATUS_SUCCESS, NULL, Context);
}

NTSTATUS
NTAPI
AcpiArbSetLinkNodeIrq(
    _In_ PAMLI_NAME_SPACE_OBJECT NsObject,
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor)
{
    ACPI_WAIT_CONTEXT WaitContext;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("AcpiArbSetLinkNodeIrq: %p\n", NsObject);

    KeInitializeEvent(&WaitContext.Event, SynchronizationEvent, FALSE);
    WaitContext.Status = STATUS_NOT_FOUND;

    Status = AcpiArbSetLinkNodeIrqAsync(NsObject, CmDescriptor, AmlisuppCompletePassive, &WaitContext);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&WaitContext.Event, Executive, KernelMode, FALSE, NULL);
        Status = WaitContext.Status;
    }

    return Status;
}

NTSTATUS
NTAPI
MakeTempLinkNodeCountsPermanent(
    _In_ PARBITER_INSTANCE Arbiter)
{
    CM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PAMLI_NAME_SPACE_OBJECT NsObject;
    PARBITER_EXTENSION ArbExtension;
    PACPI_LINK_NODE Node;
    PACPI_LINK_NODE NextNode;

    PAGED_CODE();
    DPRINT("MakeTempLinkNodeCountsPermanent: %p\n", Arbiter);

    ArbExtension = Arbiter->Extension;

    Node = CONTAINING_RECORD(ArbExtension->LinkNodeHead.Flink, ACPI_LINK_NODE, List);

    while (&Node->List != &ArbExtension->LinkNodeHead)
    {
        NextNode = CONTAINING_RECORD(Node->List.Flink, ACPI_LINK_NODE, List);

        DPRINT("MakeTempLinkNodeCountsPermanent: %p, %X, %X\n", Node, Node->ReferenceCount, Node->TempRefCount);

        ASSERT(Node);
        ASSERT(Node->List.Flink);
        ASSERT(Node->ReferenceCount <= 70);
        ASSERT(Node->TempRefCount <= 70);
        ASSERT(Node->TempRefCount >= -70);
        ASSERT(Node->CurrentIrq < 0x80000000);
        ASSERT((Node->Flags & ~(1 | 2)) == 0); // ASSERT((Node->Flags & ~(VECTOR_MODE | VECTOR_POLARITY)) == 0);

        if (!Node->ReferenceCount || Node->CurrentIrq != Node->TempIrq)
        {
            if (Node->ReferenceCount + Node->TempRefCount)
            {
                CmDescriptor.Type = 2;
                CmDescriptor.ShareDisposition = 3;
                CmDescriptor.Flags = 0;

                CmDescriptor.u.Interrupt.Level = (ULONG)Node->TempIrq;
                CmDescriptor.u.Interrupt.Vector = (ULONG)Node->TempIrq;
                CmDescriptor.u.Interrupt.Affinity = 0xFFFFFFFF;

                AcpiArbSetLinkNodeIrq(Node->NameSpaceObject, &CmDescriptor);
            }
        }

        if (!(Node->ReferenceCount + Node->TempRefCount))
        {
            NsObject = ACPIAmliGetNamedChild(Node->NameSpaceObject, 'SID_');
            if (NsObject)
                AMLIEvalNameSpaceObject(NsObject, NULL, 0, NULL);
        }

        Node->ReferenceCount += Node->TempRefCount;
        Node->TempRefCount = 0;
        Node->CurrentIrq = Node->TempIrq;

        Node = NextNode;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
AcpiArbCommitAllocation(
    _In_ PARBITER_INSTANCE Arbiter)
{
    PINT_ROUTE_INTERFACE_STANDARD PciInterface = NULL;
    RTL_RANGE_LIST_ITERATOR Iterator;
    PRTL_RANGE_LIST OldAllocation;
    PRTL_RANGE Range;
    PDEVICE_OBJECT Pdo;
    PCI_SLOT_NUMBER PciSlot;
    ROUTING_TOKEN RoutingToken;
    ULONG Bus;
    UCHAR InterruptLine;
    UCHAR Line;
    UCHAR InterruptPin;
    UCHAR ClassCode;
    UCHAR SubClassCode;
    UCHAR Flags;
    NTSTATUS Status;

    DPRINT("AcpiArbCommitAllocation: %p\n", Arbiter);
    PAGED_CODE();

    if (PciInterfacesInstantiated)
    {
        PciInterface = ((PARBITER_EXTENSION)AcpiArbiter.Extension)->InterruptRouting;
        ASSERT(PciInterface);

        for (RtlGetFirstRange(Arbiter->PossibleAllocation, &Iterator, &Range);
             Range != NULL;
             RtlGetNextRange(&Iterator, &Range, TRUE))
        {
            if (Range->Owner)
            {
                Bus = 0xFFFFFFFF;
                PciSlot.u.AsULONG = 0xFFFFFFFF;

                Status = PciInterface->GetInterruptRouting(Range->Owner,
                                                           &Bus,
                                                           &PciSlot.u.AsULONG,
                                                           &InterruptLine,
                                                           &InterruptPin,
                                                           &ClassCode,
                                                           &SubClassCode,
                                                           &Pdo,
                                                           &RoutingToken,
                                                           &Flags);
                if (NT_SUCCESS(Status))
                {
                    if (Range->Start <= 0xFF)
                        Line = (UCHAR)Range->Start;
                    else
                        Line = 0;

                    if (InterruptLine != Line)
                        PciInterface->UpdateInterruptLine(Range->Owner, Line);
                }
                else
                {
                    DPRINT("AcpiArbCommitAllocation: Status %X\n", Status);
                }
            }
        }
    }

    RtlFreeRangeList(Arbiter->Allocation);

    OldAllocation = Arbiter->Allocation;

    Arbiter->Allocation = Arbiter->PossibleAllocation;
    Arbiter->PossibleAllocation = OldAllocation;

    MakeTempVectorCountsPermanent();

    Status = MakeTempLinkNodeCountsPermanent(Arbiter);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("AcpiArbCommitAllocation: Status %X\n", Status);
    }

    return Status;
}

PDEVICE_OBJECT
NTAPI
AcpiGetFilter(
    _In_ PDEVICE_OBJECT Root,
    _In_ PDEVICE_OBJECT Pdo)
{
    PDEVICE_EXTENSION DeviceExtension;
    PDEVICE_EXTENSION StartExtension;
    PDEVICE_EXTENSION CurrentExtension;
    PDEVICE_OBJECT FilterDevice;
    PLIST_ENTRY Entry;

    DPRINT("AcpiGetFilter: %p, %p\n", Root, Pdo);

    DeviceExtension = Root->DeviceExtension;

    if (((DeviceExtension->Flags & 0x0000000000000020) || (DeviceExtension->Flags & 0x0000000000000040)) &&
        DeviceExtension->PhysicalDeviceObject == Pdo)
    {
        DPRINT("AcpiGetFilter: ret %p\n", Root);
        ASSERT(Root->Type == IO_TYPE_DEVICE);
        return Root;
    }

    Entry = DeviceExtension->ChildDeviceList.Flink;
    if (Entry == &DeviceExtension->ChildDeviceList)
    {
        DPRINT("AcpiGetFilter: ret NULL\n");
        return NULL;
    }

    CurrentExtension = StartExtension = CONTAINING_RECORD(Entry, DEVICE_EXTENSION, SiblingDeviceList);

    while (TRUE)
    {
        if (CurrentExtension->DeviceObject)
        {
            FilterDevice = AcpiGetFilter(CurrentExtension->DeviceObject, Pdo);
            if (FilterDevice)
            {
                DPRINT("AcpiGetFilter: ret %p\n", FilterDevice);
                return FilterDevice;
            }
        }

        CurrentExtension = CONTAINING_RECORD(CurrentExtension->SiblingDeviceList.Flink, DEVICE_EXTENSION, SiblingDeviceList);
        if (CurrentExtension == StartExtension)
            break;
    }

    DPRINT("AcpiGetFilter: ret NULL\n");
    return NULL;
}

NTSTATUS
NTAPI
AcpiArbCrackPRT(
    _In_ PDEVICE_OBJECT Pdo,
    _Out_ PAMLI_NAME_SPACE_OBJECT* OutLinkNode,
    _Out_ ULONG* OutVector)
{
    PACPI_PM_DISPATCH_TABLE HalAcpiDispatchTable = (PVOID)PmHalDispatchTable;
    PINT_ROUTE_INTERFACE_STANDARD PciInterface;
    PAMLI_NAME_SPACE_OBJECT PrtNsObject;
    PDEVICE_OBJECT ParentPdo;
    PDEVICE_OBJECT FilterDo;
    AMLI_OBJECT_DATA PrtData;
    AMLI_OBJECT_DATA DataResult;
    AMLI_OBJECT_DATA InterruptPinData;
    AMLI_OBJECT_DATA LinkNodeData;
    AMLI_OBJECT_DATA VectorData;
    ROUTING_TOKEN RoutingToken;
    PCI_SLOT_NUMBER PciSlot;
    PCI_SLOT_NUMBER Slot;
    ULONG Index = 0;
    ULONG Bus;
    UCHAR InterruptLine;
    UCHAR Line;
    UCHAR InterruptPin;
    UCHAR pin;
    UCHAR ClassCode;
    UCHAR SubClassCode;
    UCHAR CfgBuffer;
    UCHAR Flags;
    UCHAR flags;
    KIRQL Irql;
    BOOLEAN IsSuccess = FALSE;
    NTSTATUS Status;

    DPRINT("AcpiArbCrackPRT: %p\n", Pdo);

    if (Pdo->DriverObject == AcpiDriverObject)
    {
        ASSERT(((PDEVICE_EXTENSION)Pdo->DeviceExtension)->Flags & 0x0000000000000020);//DEV_TYPE_PDO
        ASSERT(((PDEVICE_EXTENSION)Pdo->DeviceExtension)->Signature == '_SGP');//ACPI_SIGNATURE

        if (((PDEVICE_EXTENSION)Pdo->DeviceExtension)->Flags & 0x0000000002000000)
        {
            DPRINT("AcpiArbCrackPRT: STATUS_NOT_FOUND\n");
            return STATUS_NOT_FOUND;
        }
    }

    ASSERT(PciInterfacesInstantiated);

    *OutLinkNode = NULL;

    PciInterface = ((PARBITER_EXTENSION)AcpiArbiter.Extension)->InterruptRouting;
    ASSERT(PciInterface);

    Bus = 0xFFFFFFFF;
    PciSlot.u.AsULONG = 0xFFFFFFFF;

    Status = PciInterface->GetInterruptRouting(Pdo,
                                               &Bus,
                                               &PciSlot.u.AsULONG,
                                               &InterruptLine,
                                               &InterruptPin,
                                               &ClassCode,
                                               &SubClassCode,
                                               &ParentPdo,
                                               &RoutingToken,
                                               &Flags);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("AcpiArbCrackPRT: STATUS_NOT_FOUND\n");
        return STATUS_NOT_FOUND;
    }

    if (ClassCode == 1 && SubClassCode == 1)
    {
        HalAcpiDispatchTable->HalPciInterfaceReadConfig(NULL, Bus, PciSlot, &CfgBuffer, 9, 1); // FIXME

        if (!(CfgBuffer & 5))
            return STATUS_RESOURCE_REQUIREMENTS_CHANGED;
    }

    if (RoutingToken.LinkNode || (RoutingToken.Flags & 2))
    {
        if (RoutingToken.LinkNode)
            *OutLinkNode = RoutingToken.LinkNode;
        else
            *OutVector = RoutingToken.StaticVector;

        return STATUS_SUCCESS;
    }

    while (TRUE)
    {
        KeAcquireSpinLock(&AcpiDeviceTreeLock, &Irql);
        FilterDo = AcpiGetFilter(AcpiArbiterDeviceObject, ParentPdo);
        KeReleaseSpinLock(&AcpiDeviceTreeLock, Irql);

        if (FilterDo)
        {
            ASSERT(IsPciBus(FilterDo));

            PrtNsObject = ACPIAmliGetNamedChild((((PDEVICE_EXTENSION)FilterDo->DeviceExtension)->AcpiObject), 'TRP_');
            if (PrtNsObject)
            {
                DPRINT("AcpiArbCrackPRT: PrtNsObject %p\n", PrtNsObject);
                break;
            }
        }

        Bus = 0xFFFFFFFF;
        Slot.u.AsULONG = 0xFFFFFFFF;

        Status = PciInterface->GetInterruptRouting(ParentPdo,
                                                   &Bus,
                                                   &Slot.u.AsULONG,
                                                   &Line,
                                                   &pin,
                                                   &ClassCode,
                                                   &SubClassCode,
                                                   &ParentPdo,
                                                   &RoutingToken,
                                                   &flags);

        DPRINT("AcpiArbCrackPRT: Status %X (%X:%X)\n", Status, ClassCode, SubClassCode);

        if (!NT_SUCCESS(Status) || ClassCode != 6)
        {
            *OutVector = InterruptLine;
            AcpiInterruptRoutingFailed = TRUE;
            return STATUS_SUCCESS;
        }

        if (SubClassCode == 4)
        {
            InterruptPin = ((((PciSlot.u.bits.DeviceNumber % 4) + InterruptPin - 1) % 4) + 1);
            PciSlot.u.AsULONG = Slot.u.AsULONG;
            DPRINT("AcpiArbCrackPRT: InterruptPin %X, PciSlot.u.AsULONG %X\n", InterruptPin, PciSlot.u.AsULONG);
        }
        else if (SubClassCode == 7)
        {
            InterruptPin = pin;
            PciSlot.u.AsULONG = Slot.u.AsULONG;
            DPRINT("AcpiArbCrackPRT: InterruptPin %X, PciSlot.u.AsULONG %X\n", InterruptPin, PciSlot.u.AsULONG);
        }
        else
        {
            DPRINT("AcpiArbCrackPRT: InterruptLine %X\n", InterruptLine);
            *OutVector = InterruptLine;
            AcpiInterruptRoutingFailed = TRUE;
            return STATUS_SUCCESS;
        }
    }

    if (AcpiInterruptRoutingFailed)
    {
        DPRINT1("AcpiArbCrackPRT: KeBugCheckEx()\n");
        ASSERT(FALSE);
        //KeBugCheckEx(..);
    }

    InterruptPin--;

    DPRINT("AcpiArbCrackPRT: PCI Device %p had _ADR of %X\n", Pdo, PciSlot.u.AsULONG);
    DPRINT("AcpiArbCrackPRT: This device connected to Pin %X (%p) \n", InterruptPin, PrtNsObject);

    do
    {
        Status = AMLIEvalPackageElement(PrtNsObject, Index++, &PrtData);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("AcpiArbCrackPRT: Status %X\n", Status);
            break;
        }

        ASSERT(PrtData.DataType == 4);

        if (NT_SUCCESS(AMLIEvalPkgDataElement(&PrtData, 0, &DataResult)))
        {
            if (PciSlot.u.bits.DeviceNumber == ((ULONG)DataResult.DataValue >> 0x10))
            {
                if (((ULONG)DataResult.DataValue & 0xFFFF) != 0xFFFF)
                {
                    DPRINT1("AcpiArbCrackPRT: FIXME\n");
                    ASSERT(FALSE);
                }

                if (NT_SUCCESS(AMLIEvalPkgDataElement(&PrtData, 1, &InterruptPinData)))
                {
                    if ((ULONG)InterruptPinData.DataValue == InterruptPin)
                    {
                        if (NT_SUCCESS(AMLIEvalPkgDataElement(&PrtData, 2, &LinkNodeData)))
                            IsSuccess = TRUE;

                        if (NT_SUCCESS(AMLIEvalPkgDataElement(&PrtData, 3, &VectorData)))
                            IsSuccess = TRUE;
                    }

                    AMLIFreeDataBuffs(&InterruptPinData, 1);
                }
            }

            AMLIFreeDataBuffs(&DataResult, 1);
        }

        AMLIFreeDataBuffs(&PrtData, 1);
    }
    while (!IsSuccess);

    if (IsSuccess)
    {
        if (LinkNodeData.DataType == 2 && LinkNodeData.DataBuff)
        {
            Status = AMLIGetNameSpaceObject(LinkNodeData.DataBuff, PrtNsObject, OutLinkNode, 0);
            if (NT_SUCCESS(Status))
            {
                RoutingToken.StaticVector = 0;
                RoutingToken.Flags = 0;
                RoutingToken.LinkNode = *OutLinkNode;

                PciInterface->SetInterruptRoutingToken(Pdo, &RoutingToken);

                AMLIFreeDataBuffs(&LinkNodeData, 1);
                AMLIFreeDataBuffs(&VectorData, 1);

                return Status;
            }
        }

        if (VectorData.DataType != 1)
        {
            DPRINT1("AcpiArbCrackPRT: STATUS_INVALID_IMAGE_FORMAT\n");
            AMLIFreeDataBuffs(&LinkNodeData, 1);
            AMLIFreeDataBuffs(&VectorData, 1);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        *OutVector = (ULONG)VectorData.DataValue;

        RoutingToken.LinkNode = 0;
        RoutingToken.StaticVector = *OutVector;
        RoutingToken.Flags = 2;

        PciInterface->SetInterruptRoutingToken(Pdo, &RoutingToken);

        AMLIFreeDataBuffs(&LinkNodeData, 1);
        AMLIFreeDataBuffs(&VectorData, 1);

        DPRINT("AcpiArbCrackPRT: STATUS_SUCCESS\n");
        return STATUS_SUCCESS;
    }

    DPRINT1("AcpiArbCrackPRT: FIXME\n");
    ASSERT(FALSE);

    DPRINT("AcpiArbCrackPRT: ret STATUS_UNSUCCESSFUL\n");
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS
NTAPI
GetIsaVectorFlags(
    _In_ ULONG InVector,
    _Out_ UCHAR* OutFlags)
{
    ULONG Vector = 0;
    ULONG GlobalVector;
    UCHAR Flags;
    NTSTATUS Status;

    DPRINT("GetIsaVectorFlags: %X\n", InVector);
    PAGED_CODE();

    while (TRUE)
    {
        Status = LookupIsaVectorOverride(Vector, &GlobalVector, &Flags);
        if (NT_SUCCESS(Status) && GlobalVector == InVector)
        {
            break;
        }

        Vector++;
        if (Vector >= 0x10)
        {
            DPRINT("GetIsaVectorFlags: STATUS_NOT_FOUND\n");
            return STATUS_NOT_FOUND;
        }
    }

    *OutFlags = Flags;

    ASSERT((Flags & ~0x07) == 0); // (VECTOR_MODE | VECTOR_POLARITY | VECTOR_TYPE)

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
GetVectorProperties(
    _In_ ULONG InVector,
    _Out_ UCHAR* OutFlags)
{
    PACPI_VECTOR_BLOCK VectorBlock;

    DPRINT("GetVectorProperties: %X\n", InVector);
    PAGED_CODE();

    VectorBlock = HashVector(InVector);
    if (!VectorBlock)
    {
        DPRINT("GetVectorProperties: STATUS_NOT_FOUND\n");
        return STATUS_NOT_FOUND;
    }

    if (VectorBlock->Entry.Vector == 'XXXX')
    {
        DPRINT1("GetVectorProperties: STATUS_NOT_FOUND\n");
        return STATUS_NOT_FOUND;
    }

    ASSERT(VectorBlock->Entry.Vector == InVector);

    if (!(VectorBlock->Entry.Count + VectorBlock->Entry.TempCount))
    {
        DPRINT1("GetVectorProperties: STATUS_NOT_FOUND\n");
        return STATUS_NOT_FOUND;
    }

    *OutFlags = VectorBlock->Entry.TempFlags;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
AcpiArbReferenceLinkNode(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PAMLI_NAME_SPACE_OBJECT LinkNode,
    _In_ ULONG Irq)
{
    PCM_RESOURCE_LIST CmResource = NULL;
    PARBITER_EXTENSION ArbExtension;
    PACPI_LINK_NODE Node;
    UCHAR Flags;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("AcpiArbReferenceLinkNode: %p, %X\n", LinkNode, Irq);

    ASSERT(LinkNode);

    ArbExtension = Arbiter->Extension;

    Node = CONTAINING_RECORD(ArbExtension->LinkNodeHead.Flink, ACPI_LINK_NODE, List);

    while (&Node->List != &ArbExtension->LinkNodeHead)
    {
        if (Node->NameSpaceObject == LinkNode)
        {
            if (Node->ReferenceCount || Node->TempRefCount)
            {
                Status = AcpiArbGetLinkNodeOptions(LinkNode, &CmResource, &Flags);

                if (CmResource)
                    ExFreePool(CmResource);

                ASSERT(NT_SUCCESS(Status));
                ASSERT(Flags == Node->Flags);
            }

            DPRINT("AcpiArbReferenceLinkNode: (%d:%d)\n", Node->ReferenceCount, Node->TempRefCount);
            goto Finish;
        }

        Node = CONTAINING_RECORD(Node->List.Flink, ACPI_LINK_NODE, List);
    }

    Node = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Node), 'ApcA');
    if (!Node)
    {
        DPRINT1("AcpiArbReferenceLinkNode: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(Node, sizeof(*Node));

    Node->CurrentIrq = Irq;
    Node->TempIrq = Irq;

    Node->NameSpaceObject = LinkNode;
    Node->AttachedDevices.Next = &Node->AttachedDevices;

    InsertTailList(&ArbExtension->LinkNodeHead, &Node->List);

    Status = AcpiArbGetLinkNodeOptions(LinkNode, &CmResource, &Flags);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("AcpiArbReferenceLinkNode: Status %X\n", Status);

        ASSERT(NT_SUCCESS(Status));
        Node->Flags = 3;
    }
    else
    {
        ExFreePool(CmResource);
        Node->Flags = Flags;
    }

    DPRINT("AcpiArbReferenceLinkNode: Link node object connected to vector %X (%d:%d)\n", Irq, Node->ReferenceCount, Node->TempRefCount);

Finish:

    Node->TempIrq = Irq;
    Node->TempRefCount++;

    return STATUS_SUCCESS;
}

VOID
NTAPI
AcpiArbAddAllocation(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    PAMLI_NAME_SPACE_OBJECT LinkNode;
    PVOID UserData = NULL;
    ULONG Vector;
    ULONG RangeFlags = 0;
    UCHAR PreviousFlags;
    UCHAR Flags;
    UCHAR RangeAttributes = 0;
    NTSTATUS Status;

    DPRINT("AcpiArbAddAllocation: %p, %p, %p, %X\n",
           Arbiter, ArbState, ArbState->Entry->PhysicalDeviceObject, (ULONG)(ArbState->Start & 0xFFFFFFFF));

    PAGED_CODE();
    ASSERT(ArbState->CurrentAlternative->Descriptor->Type == CmResourceTypeInterrupt);

    Status = AcpiArbCrackPRT(ArbState->Entry->PhysicalDeviceObject, &LinkNode, &Vector);

    if (NT_SUCCESS(Status))
    {
        Flags = 3;

        ASSERT(ArbState->Start == ArbState->End);

        if (!(ArbState->Flags & 2))
        {
            if (LinkNode)
            {
                AcpiArbReferenceLinkNode(Arbiter, LinkNode, (ULONG)ArbState->Start);

                UserData = LinkNode;

                if (!LinkNodeInUse(Arbiter, LinkNode, 0, &Flags))
                {
                    DPRINT1("AcpiArbAddAllocation: %p, %p\n", Arbiter, LinkNode);
                    ASSERT(FALSE);
                }

                ASSERT((Flags & ~0x07) == 0);//(VECTOR_MODE | VECTOR_POLARITY | VECTOR_TYPE)

                //ASSERT(ArbState->CurrentAlternative->Descriptor->Flags == CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE ?
                //       (Flags & VECTOR_MODE) == VECTOR_LEVEL : (Flags & VECTOR_MODE) == VECTOR_EDGE);
                ASSERT(ArbState->CurrentAlternative->Descriptor->Flags == CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE ?
                       (Flags & 1) == 1 : (Flags & 1) == 0);

                //FIXME TrackDevicesConnectedToLinkNode(..);

                Status = GetVectorProperties((ULONG)ArbState->Start, &PreviousFlags);
                if (NT_SUCCESS(Status))
                {
                    ASSERT((PreviousFlags & ~0x07) == 0);//(VECTOR_MODE | VECTOR_POLARITY | VECTOR_TYPE)
                    ASSERT(Flags == PreviousFlags);
                }
            }
            else
            {
               ASSERT(Vector == ArbState->Start);
            }
        }
        else if (InterruptModel == 1)
        {
            DPRINT("AcpiArbAddAllocation: Skipping this allocation. It's for a PCI device in APIC mode\n");
            return;
        }
    }
    else
    {
        Status = GetIsaVectorFlags((ULONG)ArbState->Start, &Flags);
        if (!NT_SUCCESS(Status))
        {
            Flags = (ArbState->CurrentAlternative->Descriptor->Flags == 1) ? 0 : 3;
        }

        ASSERT((Flags & ~0x07) == 0); // (VECTOR_MODE | VECTOR_POLARITY | VECTOR_TYPE)
    }

    if (ArbState->Flags & 2)
    {
        RangeAttributes = 1;

        Status = GetVectorProperties((ULONG)ArbState->Start, &PreviousFlags);
        if (NT_SUCCESS(Status))
        {
            if ((Flags ^ PreviousFlags) & ~4)
            {
                DPRINT("AcpiArbAddAllocation: Skipping this allocation. It's for a vector that's incompatible.\n");
                return;
            }
        }
    }

    ReferenceVector((ULONG)ArbState->Start, Flags);

    if (!(Flags & 4))
    {
        if (ArbState->CurrentAlternative->Flags & 1)
            RangeFlags = 3;
        else
            RangeFlags = 1;
    }

    Status = RtlAddRange(Arbiter->PossibleAllocation,
                         ArbState->Start,
                         ArbState->End,
                         RangeAttributes,
                         RangeFlags,
                         UserData,
                         ArbState->Entry->PhysicalDeviceObject);

    ASSERT(NT_SUCCESS(Status));

    DPRINT("AcpiArbAddAllocation: exit %p, %p\n", Arbiter, ArbState);
}

VOID
NTAPI
AcpiArbBacktrackAllocation(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    UNIMPLEMENTED_DBGBREAK();
}

NTSTATUS
NTAPI
AcpiArbPreprocessEntry(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    UCHAR Attributes;

    DPRINT("AcpiArbPreprocessEntry: %p\n", Arbiter);
    PAGED_CODE();

    Attributes = ArbState->RangeAttributes;

    if (ArbState->Alternatives->Descriptor->Flags & 1)
        Attributes = ((Attributes & 0xEF) | 0x20);
    else
        Attributes = ((Attributes & 0xDF) | 0x10);

    ArbState->RangeAttributes = Attributes;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
AcpiArbOverrideConflict(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
AcpiArbQueryConflict(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIO_RESOURCE_DESCRIPTOR ConflictingResource,
    _Out_ ULONG* OutConflictCount,
    _Out_ PARBITER_CONFLICT_INFO* OutConflicts)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
FindBootConfig(
    _In_ PARBITER_INSTANCE Arbiter,
    _In_ PARBITER_ALLOCATION_STATE ArbState,
    _In_ ULONGLONG* OutVector)
{
    RTL_RANGE_LIST_ITERATOR Iterator;
    PRTL_RANGE Range;

    DPRINT("FindBootConfig: %p\n", Arbiter);

    RtlGetFirstRange(Arbiter->Allocation, &Iterator, &Range);

    while (Range)
    {
        if (Range->Attributes & 1)
        {
            if (ArbState->Entry->PhysicalDeviceObject == Range->Owner)
            {
                ASSERT(Range->Start == Range->End);
                *OutVector = Range->Start;
                return STATUS_SUCCESS;
            }
        }

        RtlGetNextRange(&Iterator, &Range, TRUE);
    }

    return STATUS_NOT_FOUND;
}

BOOLEAN
NTAPI
AcpiArbGetNextAllocationRange(
    _In_ PARBITER_INSTANCE Arbiter,
    _Inout_ PARBITER_ALLOCATION_STATE ArbState)
{
    PINT_ROUTE_INTERFACE_STANDARD PciInterface;
    PDEVICE_OBJECT Pdo;
    ROUTING_TOKEN RoutingToken;
    PCI_SLOT_NUMBER PciSlot;
    ULONGLONG vector;
    ULONG Bus;
    UCHAR InterruptLine;
    UCHAR InterruptPin;
    UCHAR ClassCode;
    UCHAR SubClassCode;
    UCHAR Flags;
    BOOLEAN IsNewRevision = FALSE;
    NTSTATUS Status;

    DPRINT("AcpiArbGetNextAllocationRange: %p\n", Arbiter);
    PAGED_CODE();

    if (ArbState->Entry->PhysicalDeviceObject->DriverObject == AcpiDriverObject)
    {
        ASSERT(((PDEVICE_EXTENSION)ArbState->Entry->PhysicalDeviceObject->DeviceExtension)->Flags & 0x0000000000000020);
        ASSERT(((PDEVICE_EXTENSION)ArbState->Entry->PhysicalDeviceObject->DeviceExtension)->Signature == '_SGP');

        if (((PDEVICE_EXTENSION)ArbState->Entry->PhysicalDeviceObject->DeviceExtension)->Flags & 0x0000000002000000)
        {
            return ArbGetNextAllocationRange(Arbiter, ArbState);
        }
    }

    if (!PciInterfacesInstantiated)
        return ArbGetNextAllocationRange(Arbiter, ArbState);

    PciInterface = ((PARBITER_EXTENSION)AcpiArbiter.Extension)->InterruptRouting;
    ASSERT(PciInterface);

    Status = PciInterface->GetInterruptRouting(ArbState->Entry->PhysicalDeviceObject,
                                               &Bus,
                                               &PciSlot.u.AsULONG,
                                               &InterruptLine,
                                               &InterruptPin,
                                               &ClassCode,
                                               &SubClassCode,
                                               &Pdo,
                                               &RoutingToken,
                                               &Flags);
    if (Status != STATUS_SUCCESS)
    {
        DPRINT("AcpiArbGetNextAllocationRange: Status %X\n", Status);
        return ArbGetNextAllocationRange(Arbiter, ArbState);
    }

    if ((AcpiInformation->FixedACPIDescTable->Header.Revision > 1) && !(AcpiInformation->FixedACPIDescTable->boot_arch & 1))
        IsNewRevision = TRUE;

    if (!ArbState->CurrentAlternative)
        ArbState->WorkSpace = 0x1000;

    while (TRUE)
    {
        ASSERT((ArbState->WorkSpace > 0x0FFF) /*AcpiIrqNextRangeMinState*/ && (ArbState->WorkSpace < 0x1009 /*AcpiIrqNextRangeMaxState*/));

        DPRINT("AcpiArbGetNextAllocationRange: ArbState->WorkSpace %X\n", ArbState->WorkSpace);

        switch (ArbState->WorkSpace)
        {
            case 0x1000:
                if (AcpiIrqDistributionDisposition == 1)
                    ArbState->WorkSpace = 0x1007;
                else if (AcpiIrqDistributionDisposition == 2)
                    ArbState->WorkSpace = 0x1003;
                else
                    ArbState->WorkSpace = 0x1001;
                break;

            case 0x1001:
                if (InterruptModel == 0)
                    ArbState->WorkSpace = 0x1002;
                else
                    ArbState->WorkSpace = 0x1006;
                break;

            case 0x1002:
                if (IsNewRevision || !AcpiArbCardbusPresent)
                    ArbState->WorkSpace = 0x1006;
                else
                    ArbState->WorkSpace = 0x1003;
                break;

            case 0x1003:
                if (AcpiIrqDefaultBootConfig)
                    ArbState->WorkSpace = 0x1004;
                else
                    ArbState->WorkSpace = 0x1005;
                break;

            case 0x1004:
                ArbState->WorkSpace = 0x1007;
                DPRINT1("AcpiArbGetNextAllocationRange: FIXME\n");
                ASSERT(FALSE);
                break;

            case 0x1005:
                ArbState->WorkSpace = 0x1006;
                DPRINT1("AcpiArbGetNextAllocationRange: FIXME\n");
                ASSERT(FALSE);
                break;

            case 0x1006:
                ArbState->WorkSpace = 0x1007;
                Status = FindBootConfig(Arbiter, ArbState, &vector);
                if (NT_SUCCESS(Status))
                {
                    DPRINT1("AcpiArbGetNextAllocationRange: FIXME\n");
                    ASSERT(FALSE);
                }
                break;

            case 0x1007:
                ArbState->WorkSpace = 0x1008;
                ArbState->CurrentAlternative = &ArbState->Alternatives[0];
                ArbState->CurrentMinimum = ArbState->CurrentAlternative->Minimum;
                ArbState->CurrentMaximum = ArbState->CurrentAlternative->Maximum;
                goto Exit;

            case 0x1008:
                if (++ArbState->CurrentAlternative >= &ArbState->Alternatives[ArbState->AlternativeCount])
                    return FALSE;

                DPRINT("AcpiArbGetNextAllocationRange: No next allocation range, exhausted all %X alternatives", ArbState->AlternativeCount);

                ArbState->CurrentMinimum = ArbState->CurrentAlternative->Minimum;
                ArbState->CurrentMaximum = ArbState->CurrentAlternative->Maximum;
                goto Exit;
        }
    }

Exit:

    DPRINT("AcpiArbGetNextAllocationRange: Next allocation range 0x%I64x-0x%I64x\n", ArbState->CurrentMinimum, ArbState->CurrentMaximum);

    AcpiArbPciAlternativeRotation++;

    return TRUE;
}

NTSTATUS
NTAPI
AcpiInitIrqArbiter(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PACPI_PM_DISPATCH_TABLE HalAcpiDispatchTable = (PVOID)PmHalDispatchTable;
    PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 RegistryValue = NULL;
    PARBITER_EXTENSION ArbiterExtension;
    PDEVICE_EXTENSION DeviceExtension;
    ACPI_WAIT_CONTEXT WaitContext;
    PCI_COMMON_CONFIG PciConfig;
    PCI_SLOT_NUMBER SlotNumber;
    UNICODE_STRING NameString;
    HANDLE Handle = NULL;
    ULONG Device;
    ULONG Function;
    ULONG Vector;
    UCHAR Flags;
    UCHAR SubordinateBus;
    UCHAR BusNumber;
    BOOLEAN IsNotFound;
    BOOLEAN IsBootConfig;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("AcpiInitIrqArbiter: DeviceObject %p\n", DeviceObject);

    ArbiterExtension = ExAllocatePoolWithTag(NonPagedPool, sizeof(*ArbiterExtension), 'ApcA');
    if (!ArbiterExtension)
    {
        DPRINT1("AcpiInitIrqArbiter: STATUS_INSUFFICIENT_RESOURCES (%X)\n", sizeof(*ArbiterExtension));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(ArbiterExtension, sizeof(*ArbiterExtension));

    InitializeListHead(&ArbiterExtension->LinkNodeHead);
    AcpiArbiter.Extension = ArbiterExtension;

    AcpiArbiterDeviceObject = DeviceObject;

    AcpiArbiter.UnpackRequirement = AcpiArbUnpackRequirement;
    AcpiArbiter.PackResource = AcpiArbPackResource;
    AcpiArbiter.UnpackResource = AcpiArbUnpackResource;
    AcpiArbiter.ScoreRequirement = AcpiArbScoreRequirement;
    AcpiArbiter.FindSuitableRange = AcpiArbFindSuitableRange;
    AcpiArbiter.TestAllocation = AcpiArbTestAllocation;
    AcpiArbiter.BootAllocation = AcpiArbBootAllocation;
    AcpiArbiter.RetestAllocation = AcpiArbRetestAllocation;
    AcpiArbiter.RollbackAllocation = AcpiArbRollbackAllocation;
    AcpiArbiter.CommitAllocation = AcpiArbCommitAllocation;
    AcpiArbiter.AddAllocation = AcpiArbAddAllocation;
    AcpiArbiter.BacktrackAllocation = AcpiArbBacktrackAllocation;
    AcpiArbiter.PreprocessEntry = AcpiArbPreprocessEntry;
    AcpiArbiter.OverrideConflict = AcpiArbOverrideConflict;
    AcpiArbiter.QueryConflict = AcpiArbQueryConflict;
    AcpiArbiter.GetNextAllocationRange = AcpiArbGetNextAllocationRange;

    IrqHashTable = ExAllocatePoolWithTag(PagedPool, (0x3E * sizeof(ACPI_VECTOR_BLOCK)), 'ApcA');
    if (!IrqHashTable)
    {
        DPRINT1("AcpiInitIrqArbiter: STATUS_INSUFFICIENT_RESOURCES (%X)\n", (0x3E * sizeof(ACPI_VECTOR_BLOCK)));
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }
    RtlFillMemory(IrqHashTable, (0x3E * sizeof(ACPI_VECTOR_BLOCK)), 'X'); // FIXME

    Status = ArbInitializeArbiterInstance(&AcpiArbiter, DeviceObject, CmResourceTypeInterrupt, L"ACPI_IRQ", L"Root", NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("AcpiInitIrqArbiter: Status %X\n", Status);
        Status = STATUS_UNSUCCESSFUL;
        goto ErrorExit;
    }

    Vector = AcpiInformation->FixedACPIDescTable->sci_int_vector;
    Flags = 3;

    LookupIsaVectorOverride(Vector, &Vector, &Flags);

    DeviceExtension = DeviceObject->DeviceExtension;
    RtlAddRange(AcpiArbiter.Allocation, Vector, Vector, 0, 2, NULL, DeviceExtension->PhysicalDeviceObject);

    ReferenceVector(Vector, Flags);
    AcpiSciVector = Vector;

    MakeTempVectorCountsPermanent();

    KeInitializeEvent(&WaitContext.Event, SynchronizationEvent, 0);
    WaitContext.Status = STATUS_UNSUCCESSFUL;

    Status = DisableLinkNodesAsync(DeviceExtension->AcpiObject, AmlisuppCompletePassive, &WaitContext);
    if (Status == STATUS_PENDING)
        KeWaitForSingleObject(&WaitContext, Executive, KernelMode, FALSE, NULL);

    IsBootConfig = FALSE;
    IsNotFound = FALSE;

    BusNumber = 0;
    SubordinateBus = 0;

    do
    {
        SlotNumber.u.AsULONG = 0;
        Device = 0;

        do
        {
            Function = 0;

            while (TRUE)
            {
                SlotNumber.u.bits.DeviceNumber = Device;
                SlotNumber.u.bits.FunctionNumber = Function;

                HalAcpiDispatchTable->HalPciInterfaceReadConfig(NULL, BusNumber, SlotNumber, &PciConfig, 0, 0x40);

                if (PciConfig.VendorID == -1)
                    break;

                if (PciConfig.HeaderType & 0x7F)
                {
                    if (SubordinateBus <= PciConfig.u.type1.SubordinateBus)
                        SubordinateBus = PciConfig.u.type1.SubordinateBus;

                    if ((PciConfig.HeaderType & 0x7F) == 2)
                        AcpiArbCardbusPresent = TRUE;
                }
                else if (PciConfig.u.type0.InterruptPin &&
                         PciConfig.u.type0.InterruptLine &&
                         PciConfig.u.type0.InterruptLine < 0xFF)
                {
                    if (!IsBootConfig)
                    {
                        AcpiIrqDefaultBootConfig = PciConfig.u.type0.InterruptLine;
                        IsBootConfig = TRUE;
                    }
                    else if (PciConfig.u.type0.InterruptLine != AcpiIrqDefaultBootConfig)
                    {
                        IsNotFound = TRUE;
                        break;
                    }
                }

                if (PciConfig.HeaderType & 0x80 || Function)
                {
                    Function++;
                    if (Function < 8)
                        continue;
                }

                break;
            }

            Device++;
        }
        while (Device < 0x20);

        BusNumber++;
    }
    while (SubordinateBus != BusNumber);

    if (!IsBootConfig || IsNotFound || !AcpiArbCardbusPresent)
        AcpiIrqDefaultBootConfig = 0;

    RtlInitUnicodeString(&NameString, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ACPI\\Parameters");

    Status = OSOpenUnicodeHandle(&NameString, NULL, &Handle);
    if (!NT_SUCCESS(Status))
        return STATUS_SUCCESS;

    Status = OSGetRegistryValue(Handle, L"IRQDistribution", (PVOID *)&RegistryValue);
    if (NT_SUCCESS(Status))
    {
        if (RegistryValue->DataLength && RegistryValue->Type == 4)
            AcpiIrqDistributionDisposition = *(PULONG)&RegistryValue->Data[0];

        ExFreePoolWithTag(RegistryValue, 'SpcA');
    }

    Status = OSGetRegistryValue(Handle, L"ForcePCIBootConfig", (PVOID *)&RegistryValue);
    if (NT_SUCCESS(Status))
    {
        if (RegistryValue->DataLength && RegistryValue->Type == 4)
            AcpiIrqDefaultBootConfig = RegistryValue->Data[0];

        ExFreePoolWithTag(RegistryValue, 'SpcA');
    }

    OSCloseHandle(Handle);
    return STATUS_SUCCESS;

ErrorExit:

    ExFreePoolWithTag(ArbiterExtension, 'ApcA');

    if (IrqHashTable)
        ExFreePoolWithTag(IrqHashTable, 'ApcA');

    if (Handle)
        OSCloseHandle(Handle);

    if (RegistryValue)
        ExFreePoolWithTag(RegistryValue, 'SpcA');

    return Status;
}

/* INIT DRIVER ROUTINES *****************************************************/

NTSTATUS
NTAPI
ACPIDispatchAddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT TargetDevice)
{
    PDEVICE_EXTENSION DeviceExtension = NULL;
    PDEVICE_OBJECT AttachedToDevice = NULL;
    PDEVICE_OBJECT DeviceObject = NULL;
    PACPI_POWER_INFO PowerInfo;
    PCHAR InstanceID;
    PCHAR Address;
    KIRQL OldIrql;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("ACPIDispatchAddDevice: %p, %p\n", DriverObject, TargetDevice);

    Address = ExAllocatePoolWithTag(NonPagedPool, 0xE, 'SpcA');
    if (!Address)
    {
        DPRINT1("ACPIDispatchAddDevice: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(Address, 0xE);
    RtlCopyMemory(Address, "ACPI\\PNP0C08", sizeof("ACPI\\PNP0C08"));

    InstanceID = ExAllocatePoolWithTag(NonPagedPool, 0xB, 'SpcA');
    if (!InstanceID)
    {
        DPRINT1("ACPIDispatchAddDevice: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    RtlZeroMemory(InstanceID, 0xB);
    RtlCopyMemory(InstanceID, "0x5F534750", sizeof("0x5F534750"));

    Status = IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_ACPI, 0, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ACPIDispatchAddDevice: Status %X\n", Status);
        goto Exit;
    }

    AttachedToDevice = IoAttachDeviceToDeviceStack(DeviceObject, TargetDevice);
    if (!AttachedToDevice)
    {
        DPRINT1("ACPIDispatchAddDevice: STATUS_NO_SUCH_DEVICE\n");
        Status = STATUS_NO_SUCH_DEVICE;
        goto Exit;
    }

    DeviceExtension = ExAllocateFromNPagedLookasideList(&DeviceExtensionLookAsideList);
    if (!DeviceExtension)
    {
        DPRINT1("ACPIDispatchAddDevice: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    RtlZeroMemory(DeviceExtension, sizeof(*DeviceExtension));

    InterlockedIncrement(&DeviceExtension->ReferenceCount);
    InterlockedIncrement(&DeviceExtension->OutstandingIrpCount);

    DeviceObject->DeviceExtension = DeviceExtension;
    DeviceExtension->DeviceObject = DeviceObject;
    DeviceExtension->PhysicalDeviceObject = TargetDevice;
    DeviceExtension->TargetDeviceObject = AttachedToDevice;
    DeviceExtension->Address = Address;
    DeviceExtension->InstanceID = InstanceID;

    PowerInfo = &DeviceExtension->PowerInfo;

    DeviceExtension->Signature = '_SGP';
    DeviceExtension->DispatchTable = &AcpiFdoIrpDispatch;

    PowerInfo->DevicePowerMatrix[1] = 1;
    PowerInfo->DevicePowerMatrix[2] = 1;
    PowerInfo->DevicePowerMatrix[3] = 1;
    PowerInfo->DevicePowerMatrix[4] = 1;
    PowerInfo->DevicePowerMatrix[0] = 0;
    PowerInfo->DevicePowerMatrix[5] = 4;
    PowerInfo->DevicePowerMatrix[6] = 4;

    PowerInfo->SystemWakeLevel = 0;
    PowerInfo->DeviceWakeLevel = 0;

    ACPIInternalUpdateFlags(&DeviceExtension->Flags, 0x0001E00000200010, FALSE);

    InitializeListHead(&DeviceExtension->ChildDeviceList);
    InitializeListHead(&DeviceExtension->SiblingDeviceList);
    InitializeListHead(&DeviceExtension->EjectDeviceHead);
    InitializeListHead(&DeviceExtension->EjectDeviceList);
    InitializeListHead(&DeviceExtension->PowerInfo.PowerRequestListEntry);

    KeAcquireSpinLock(&AcpiDeviceTreeLock, &OldIrql);
    RootDeviceExtension = DeviceExtension;
    KeReleaseSpinLock(&AcpiDeviceTreeLock, OldIrql);

    // FIXME Interfaces and WMI ...

    DeviceObject->Flags &= ~0x80;

    if (NT_SUCCESS(Status))
    {
        DPRINT("ACPIDispatchAddDevice: Status %X\n", Status);
        return Status;
    }

    DPRINT1("ACPIDispatchAddDevice: Status %X\n", Status);

Exit:

    ExFreePoolWithTag(Address, 'SpcA');

    if (InstanceID)
        ExFreePoolWithTag(InstanceID, 'SpcA');

    if (AttachedToDevice)
        IoDetachDevice(AttachedToDevice);

    if (DeviceObject)
        IoDeleteDevice(DeviceObject);

    if (DeviceExtension)
        ExFreeToNPagedLookasideList(&DeviceExtensionLookAsideList, DeviceExtension);

    DPRINT("ACPIDispatchAddDevice: Status %X\n", Status);
    return Status;
}

VOID
NTAPI
ACPIUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNIMPLEMENTED_DBGBREAK();
}

VOID
NTAPI
OSQueueWorkItem(
    _In_ PWORK_QUEUE_ITEM WorkQueueItem)
{
    KIRQL OldIrql;

    ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

    KeAcquireSpinLock(&ACPIWorkerSpinLock, &OldIrql);

    if (IsListEmpty(&ACPIWorkQueue))
        KeSetEvent(&ACPIWorkToDoEvent, 0, FALSE);

    InsertTailList(&ACPIWorkQueue, &WorkQueueItem->List);
 
    KeReleaseSpinLock(&ACPIWorkerSpinLock, OldIrql);
}

VOID
NTAPI
ACPIWorkerThread(PVOID Context)
{
    PDEVICE_EXTENSION DeviceExtension;
    PLIST_ENTRY Entry;
    ULONG Events;
    KIRQL Irql;

    DPRINT("ACPIWorkerThread()\n");

    KeAcquireSpinLock(&ACPIWorkerSpinLock, &Irql);

    ACPIWorkerBusy = TRUE;

    while (!IsListEmpty(&ACPIDeviceWorkQueue))
    {
        Entry = ACPIDeviceWorkQueue.Flink;
        RemoveEntryList(Entry);
        Entry->Flink = NULL;

        DeviceExtension = CONTAINING_RECORD(Entry, DEVICE_EXTENSION, WorkQueue.Link);

        Events = DeviceExtension->WorkQueue.PendingEvents;
        DeviceExtension->WorkQueue.PendingEvents = 0;

        KeReleaseSpinLock(&ACPIWorkerSpinLock, Irql);
        DeviceExtension->DispatchTable->Worker(DeviceExtension, Events);
        KeAcquireSpinLock(&ACPIWorkerSpinLock, &Irql);
    }

    ACPIWorkerBusy = FALSE;

    KeReleaseSpinLock(&ACPIWorkerSpinLock, Irql);
}

VOID
NTAPI
ACPIWorker(PVOID StartContext)
{
    PWORK_QUEUE_ITEM WorkQueueItem;
    KWAIT_BLOCK WaitBlockArray;
    PLIST_ENTRY Entry;
    PVOID Object[2];
    KIRQL OldIrql;
    NTSTATUS Status;

    DPRINT("ACPIWorker()\n");

    ACPIThread = KeGetCurrentThread();

    Object[0] = &ACPIWorkToDoEvent;
    Object[1] = &ACPITerminateEvent;

    while (TRUE)
    {
        Status = KeWaitForMultipleObjects(2, Object, WaitAny, Executive, KernelMode, FALSE, NULL, &WaitBlockArray);
        if (Status == STATUS_WAIT_1)
            PsTerminateSystemThread(STATUS_SUCCESS);

        KeAcquireSpinLock(&ACPIWorkerSpinLock, &OldIrql);

        ASSERT(!IsListEmpty(&ACPIWorkQueue));

        Entry = RemoveHeadList(&ACPIWorkQueue);
        WorkQueueItem = CONTAINING_RECORD(Entry, WORK_QUEUE_ITEM, List);

        if (IsListEmpty(&ACPIWorkQueue))
            KeClearEvent(&ACPIWorkToDoEvent);

        KeReleaseSpinLock(&ACPIWorkerSpinLock, OldIrql);

        //_SEH2_TRY

        WorkQueueItem->WorkerRoutine(WorkQueueItem->Parameter);

        if (KeGetCurrentIrql())
        {
            OldIrql = KeGetCurrentIrql();

            DPRINT1("ACPIWorker: worker exit at IRQL %X, worker routine %X, parameter %X, item %X\n",
                    OldIrql, WorkQueueItem->WorkerRoutine, WorkQueueItem->Parameter, WorkQueueItem);

            DbgBreakPoint();
        }

        //_SEH2_END
    }
}

VOID
NTAPI
ACPIInitializeWorker()
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    PVOID Object;
    HANDLE ThreadHandle;

    DPRINT("ACPIInitializeWorker()\n");

    KeInitializeSpinLock(&ACPIWorkerSpinLock);

    ExInitializeWorkItem(&ACPIWorkItem, ACPIWorkerThread, NULL);

    KeInitializeEvent(&ACPIWorkToDoEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&ACPITerminateEvent, NotificationEvent, FALSE);

    InitializeListHead(&ACPIDeviceWorkQueue);
    InitializeListHead(&ACPIWorkQueue);
    InitializeListHead(&AcpiBuildQueueList);

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    if (PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, &ObjectAttributes, 0, NULL, ACPIWorker, NULL))
    {
        DPRINT1("DriverEntry: PsCreateSystemThread() failed\n");
        ASSERT(FALSE);
    }

    if (ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, NULL, KernelMode, &Object, NULL))
    {
        DPRINT1("DriverEntry: ObReferenceObjectByHandle() failed\n");
        ASSERT(FALSE);
    }
}

NTSTATUS
NTAPI
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    ULONG Size;
    ULONG ix;

    DPRINT("DriverEntry: %X, '%wZ'\n", DriverObject, RegistryPath);

    AcpiDriverObject = DriverObject;

    Size = (RegistryPath->Length + sizeof(WCHAR));

    AcpiRegistryPath.Length = 0;
    AcpiRegistryPath.MaximumLength = Size;
    AcpiRegistryPath.Buffer = ExAllocatePoolWithTag(PagedPool, Size, 'MpcA');

    if (AcpiRegistryPath.Buffer)
        RtlCopyUnicodeString(&AcpiRegistryPath, RegistryPath);
    else
        AcpiRegistryPath.MaximumLength = 0;

    if ((AcpiOverrideAttributes & 4) && KeQueryActiveProcessors() == 1)
        AcpiOverrideAttributes &= ~4;

    ACPIInitReadRegistryKeys();

    KeInitializeDpc(&AcpiBuildDpc, ACPIBuildDeviceDpc, NULL);
    KeInitializeDpc(&AcpiPowerDpc, ACPIDevicePowerDpc, NULL);
    KeInitializeDpc(&AcpiGpeDpc, ACPIInterruptDispatchEventDpc, NULL);

    KeInitializeSpinLock(&AcpiDeviceTreeLock);
    KeInitializeSpinLock(&AcpiBuildQueueLock);
    KeInitializeSpinLock(&AcpiPowerQueueLock);
    KeInitializeSpinLock(&AcpiGetLock);
    KeInitializeSpinLock(&AcpiPowerLock);
    KeInitializeSpinLock(&AcpiButtonLock);
    KeInitializeSpinLock(&AcpiThermalLock);

    InitializeListHead(&AcpiBuildDeviceList);
    InitializeListHead(&AcpiBuildSynchronizationList);
    InitializeListHead(&AcpiBuildRunMethodList);
    InitializeListHead(&AcpiBuildOperationRegionList);
    InitializeListHead(&AcpiBuildPowerResourceList);
    InitializeListHead(&AcpiBuildThermalZoneList);
    InitializeListHead(&AcpiPowerDelayedQueueList);
    InitializeListHead(&AcpiGetListEntry);
    InitializeListHead(&AcpiUnresolvedEjectList);
    InitializeListHead(&AcpiPowerSynchronizeList);
    InitializeListHead(&AcpiPowerQueueList);
    InitializeListHead(&AcpiPowerPhase0List);
    InitializeListHead(&AcpiPowerPhase1List);
    InitializeListHead(&AcpiPowerPhase2List);
    InitializeListHead(&AcpiPowerPhase3List);
    InitializeListHead(&AcpiPowerPhase4List);
    InitializeListHead(&AcpiPowerPhase5List);
    InitializeListHead(&AcpiPowerWaitWakeList);
    InitializeListHead(&AcpiPowerNodeList);
    InitializeListHead(&AcpiButtonList);
    InitializeListHead(&AcpiThermalList);

    AcpiBuildFixedButtonEnumerated = FALSE;
    AcpiBuildWorkDone = FALSE;
    AcpiPowerWorkDone = FALSE;
    AcpiPowerDpcRunning = FALSE;
    AcpiGpeWorkDone = FALSE;
    AcpiGpeDpcRunning = FALSE;
    AcpiGpeDpcScheduled = FALSE;

    ExInitializeNPagedLookasideList(&DeviceExtensionLookAsideList, NULL, NULL, 0, sizeof(DEVICE_EXTENSION), 'DpcA', 0x40);
    ExInitializeNPagedLookasideList(&BuildRequestLookAsideList, NULL, NULL, 0, sizeof(ACPI_BUILD_REQUEST), 'DpcA', 0x38);
    ExInitializeNPagedLookasideList(&RequestLookAsideList, NULL, NULL, 0, sizeof(ACPI_POWER_REQUEST), 'PpcA', 0xCC);
    ExInitializeNPagedLookasideList(&PswContextLookAsideList, NULL, NULL, 0, sizeof(ACPI_PSW_CONTEXT), 'PpcA', 0x10);

    ACPIInitializeWorker();

    DriverObject->DriverUnload = ACPIUnload;
    DriverObject->DriverExtension->AddDevice = ACPIDispatchAddDevice;

    for (ix = 0; ix <= IRP_MJ_MAXIMUM_FUNCTION; ix++)
        DriverObject->MajorFunction[ix] = ACPIDispatchIrp;

    RtlZeroMemory(&ACPIFastIoDispatch, sizeof(ACPIFastIoDispatch));

    ACPIFastIoDispatch.SizeOfFastIoDispatch = sizeof(ACPIFastIoDispatch);
    ACPIFastIoDispatch.FastIoDetachDevice = ACPIFilterFastIoDetachCallback;

    DriverObject->FastIoDispatch = &ACPIFastIoDispatch;

    ACPIInitHalDispatchTable();

    DPRINT("DriverEntry: return STATUS_SUCCESS\n");
    return STATUS_SUCCESS;
}

/* EOF */
