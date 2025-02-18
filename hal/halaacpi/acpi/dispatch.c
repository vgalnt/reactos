
/* INCLUDES ******************************************************************/

#include <hal.h>
#include "dispatch.h"
#include "../../../drivers/usb/usbohci/hardware.h"
#include "../../../drivers/usb/usbuhci/hardware.h"
#include "apic.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

PPM_DISPATCH_TABLE PmAcpiDispatchTable;
ACPI_PM_DISPATCH_TABLE HalAcpiDispatchTable =
{
    0x48414C20, // 'HAL '
    2,
    HaliAcpiTimerInit,
    NULL,
    HaliAcpiMachineStateInit,
    HaliAcpiQueryFlags,
    HalpAcpiPicStateIntact,
    HalpRestoreInterruptControllerState,
    HaliPciInterfaceReadConfig,
    HaliPciInterfaceWriteConfig,
    HaliSetVectorState,
    HalpGetApicVersion,
    HaliSetMaxLegacyPciBusNumber,
    HaliIsVectorValid 
};

ULONG HalpShutdownContext = 0;
PVOID HalpWakeVector = NULL;
BOOLEAN HalpWakeupState[2];
BOOLEAN HalpDisableHibernate;
BOOLEAN HalpDisableS5Hibernation;

extern FADT HalpFixedAcpiDescTable;
extern HALP_TIMER_INFO TimerInfo;
extern ULONG HalpWAETDeviceFlags;
extern BOOLEAN HalpBrokenAcpiTimer;
extern ULONG HalpMaxPciBus;

/* PRIVATE FUNCTIONS *********************************************************/

NTSTATUS
NTAPI
HalpGetChipHacks(
    _In_ USHORT VendorID,
    _In_ USHORT DeviceID,
    _In_ UCHAR RevisionID,
    _Out_ ULONG* OutChipHacks
);

VOID NTAPI HalpPiix4Detect(_In_ BOOLEAN IsInitialize);
VOID NTAPI HaliSetWakeEnable(_In_ BOOLEAN Enable);

VOID
NTAPI
HaliSetWakeAlarm(
    _In_ ULONGLONG AlartTime,
    _In_ PTIME_FIELDS WakeTimeFields
);

NTSTATUS
NTAPI
HaliInitPowerManagement(
    _In_ PPM_DISPATCH_TABLE PmDriverDispatchTable,
    _Out_ PPM_DISPATCH_TABLE* PmHalDispatchTable
);

NTSTATUS
NTAPI
HaliAcpiSleep(
    _In_opt_ PVOID Context,
    _In_opt_ PENTER_STATE_SYSTEM_HANDLER SystemHandler,
    _In_opt_ PVOID SystemContext,
    _In_ LONG NumberProcessors,
    _In_opt_ LONG volatile * Number
);

VOID
NTAPI
HaliAcpiMachineStateInit(
    _In_ ULONG Par1,
    _In_ PHALP_STATE_DATA StateData,
    _Out_ ULONG* OutInterruptModel
);

ULONG NTAPI HaliAcpiQueryFlags(VOID);
UCHAR NTAPI HalpAcpiPicStateIntact(VOID);
VOID NTAPI HalpRestoreInterruptControllerState(VOID);

VOID
NTAPI
HaliSetVectorState(
    _In_ ULONG Vector,
    _In_ ULONG Par2
);

ULONG NTAPI HalpGetApicVersion(_In_ ULONG Par1);
BOOLEAN NTAPI HaliIsVectorValid(_In_ ULONG Vector);

#ifdef ALLOC_PRAGMA
  #pragma alloc_text(PAGE, HalpGetChipHacks)
  #pragma alloc_text(PAGELK, HalpPiix4Detect)
  #pragma alloc_text(PAGELK, HaliSetWakeEnable)
  #pragma alloc_text(PAGELK, HaliSetWakeAlarm)
  #pragma alloc_text(PAGE, HaliInitPowerManagement)
  #pragma alloc_text(PAGELK, HaliAcpiSleep)
  #pragma alloc_text(PAGE, HaliAcpiMachineStateInit)
  #pragma alloc_text(PAGE, HaliAcpiQueryFlags)
  #pragma alloc_text(PAGELK, HalpAcpiPicStateIntact)
  #pragma alloc_text(PAGELK, HalpRestoreInterruptControllerState)
  #pragma alloc_text(PAGE, HaliSetVectorState)
  #pragma alloc_text(PAGELK, HalpGetApicVersion)
  #pragma alloc_text(PAGE, HaliIsVectorValid)
#endif

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HalpGetChipHacks(
    _In_ USHORT VendorID,
    _In_ USHORT DeviceID,
    _In_ UCHAR RevisionID,
    _Out_ ULONG* OutChipHacks)
{
    KEY_VALUE_PARTIAL_INFORMATION KeyValueInfo;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING DestinationString;
    HANDLE KeyHandle = NULL;
    ULONG ResultLength;
    ULONG ChipHacks;
    WCHAR SourceString[10];
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("HalpGetChipHacks: VendorID %X, DeviceID %X\n", VendorID, DeviceID);

    RtlInitUnicodeString(&DestinationString, L"\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\Control\\HAL");

    InitializeObjectAttributes(&ObjectAttributes, &DestinationString, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpGetChipHacks: Status %X\n", Status);
        KeFlushWriteBuffer();
        return Status;
    }

    swprintf(SourceString, L"%04X%04X", VendorID, DeviceID);
    RtlInitUnicodeString(&DestinationString, SourceString);

    Status = ZwQueryValueKey(KeyHandle,
                             &DestinationString,
                             KeyValuePartialInformation,
                             &KeyValueInfo,
                             sizeof(KeyValueInfo),
                             &ResultLength);
    if (!NT_SUCCESS(Status))
    {
        ZwClose(KeyHandle);
        KeFlushWriteBuffer();
        return Status;
    }

    ChipHacks = *(PULONG)KeyValueInfo.Data;
    DPRINT1("HalpGetChipHacks: ChipHacks %X\n", ChipHacks);

    if (RevisionID && (RevisionID >= (ChipHacks >> 24)))
    {
        DPRINT1("HalpGetChipHacks: RevisionID %X\n", RevisionID);
        ASSERT(FALSE); // HalpDbgBreakPointEx();
        ChipHacks >>= 12;
    }

    ChipHacks &= 0xFFF;

    if (HalpWAETDeviceFlags & 2)
    {
        DPRINT1("HalpGetChipHacks: HalpWAETDeviceFlags %X\n", HalpWAETDeviceFlags);
        ASSERT(FALSE); // HalpDbgBreakPointEx();
        ChipHacks &= 0xFFFFFFFE;
    }

    *OutChipHacks = ChipHacks;

    ZwClose(KeyHandle);
    KeFlushWriteBuffer();

    return Status;
}

VOID
NTAPI
HalpStopOhciInterrupt(
    _In_ ULONG BusNumber,
    _In_ ULONG SlotNumber)
{
    POHCI_OPERATIONAL_REGISTERS OperationalRegs;
    PHYSICAL_ADDRESS PhysicalAddresses;
    PCI_COMMON_CONFIG PciHeader;
    ULONG ix;

    DPRINT("HalpStopOhciInterrupt: Bus %X, Slot %X\n", BusNumber, SlotNumber);

    HalGetBusData(PCIConfiguration, BusNumber, SlotNumber, &PciHeader, sizeof(PciHeader));

    if (!(PciHeader.Command & PCI_ENABLE_MEMORY_SPACE))
        goto Exit;

    PhysicalAddresses.QuadPart = (PciHeader.u.type0.BaseAddresses[0] & PCI_ADDRESS_MEMORY_ADDRESS_MASK);
    if (!PhysicalAddresses.QuadPart)
        goto Exit;

    OperationalRegs = HalpMapPhysicalMemory64(PhysicalAddresses, 1);
    if (!OperationalRegs)
    {
        DPRINT1("HalpStopOhciInterrupt: failed HalpMapPhysicalMemory64()\n");
        goto Exit;
    }

    if (!OperationalRegs->HcControl.InterruptRouting)
        goto Exit1;

    if (OperationalRegs->HcControl.InterruptRouting &&
        !OperationalRegs->HcInterruptEnable.AsULONG)
    {
        OperationalRegs->HcControl.AsULONG = 0;
        goto Exit1;
    }

    OperationalRegs->HcInterruptDisable.RootHubStatusChange = 1;
    OperationalRegs->HcInterruptEnable.OwnershipChange = 1;
    OperationalRegs->HcInterruptEnable.MasterInterruptEnable = 1;

    OperationalRegs->HcCommandStatus.OwnershipChangeRequest = 1;

    for (ix = 0; ix < 500; ix++)
    {
        KeStallExecutionProcessor(1000);

        if (!OperationalRegs->HcControl.InterruptRouting)
            break;
    }

Exit1:
    OperationalRegs->HcInterruptDisable.MasterInterruptEnable = 1;
    HalpUnmapVirtualAddress(OperationalRegs, 1);

Exit:
    KeFlushWriteBuffer();
}

VOID
NTAPI
HalpStopUhciInterrupt(
    _In_ ULONG BusNumber,
    _In_ ULONG SlotNumber,
    _In_ BOOLEAN IsIntel)
{
    PCI_COMMON_CONFIG PciHeader;
    PUSHORT Port;
    ULONG LegacySupport = 0;

    DPRINT("HalpStopUhciInterrupt: Bus %X, Slot %X, IsIntel %X\n", BusNumber, SlotNumber, IsIntel);

    if (!IsIntel)
    {
        HalGetBusDataByOffset(PCIConfiguration, BusNumber, SlotNumber, &LegacySupport, PCI_LEGSUP, sizeof(LegacySupport));
        LegacySupport &= 0x4000;
        HalSetBusDataByOffset(PCIConfiguration, BusNumber, SlotNumber, &LegacySupport, PCI_LEGSUP, sizeof(LegacySupport));

        goto Exit;
    }

    LegacySupport = 0;
    HalSetBusDataByOffset(PCIConfiguration, BusNumber, SlotNumber, &LegacySupport, PCI_LEGSUP, sizeof(LegacySupport));

    HalGetBusData(PCIConfiguration, BusNumber, SlotNumber, &PciHeader, sizeof(PciHeader));
    if (!(PciHeader.Command & 1))
        goto Exit;

    Port = (PUSHORT)(PciHeader.u.type0.BaseAddresses[4] & PCI_ADDRESS_IO_ADDRESS_MASK);
    if (!Port)
        goto Exit;

    if ((ULONG_PTR)Port >= 0xFFFF)
        goto Exit;

    if (READ_PORT_USHORT(Port) & 8)
        goto Exit;

    WRITE_PORT_USHORT(Port, 4);
    KeStallExecutionProcessor(10000);
    WRITE_PORT_USHORT(Port, 0);

Exit:

    KeFlushWriteBuffer();
}

CODE_SEG("PAGELK")
VOID
NTAPI
HalpPiix4Detect(
    _In_ BOOLEAN IsInitialize)
{
    BOOLEAN IsBroken440BX = FALSE;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING DestinationString;
    PCI_COMMON_CONFIG PciHeader;
    PCI_SLOT_NUMBER SlotNumber;
    HANDLE KeyHandle = NULL;
    HANDLE Handle = NULL;
    ULONG Disposition;
    ULONG BusNumber;
    ULONG Device;
    ULONG Function;
    ULONG BytesRead;
    ULONG ChipHacks;
    NTSTATUS Status;

    DPRINT("HalpPiix4Detect: IsInitialize %X\n", IsInitialize);

    if (IsInitialize)
    {
        PAGED_CODE();

        RtlInitUnicodeString(&DestinationString, L"\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET");
        InitializeObjectAttributes(&ObjectAttributes, &DestinationString, OBJ_CASE_INSENSITIVE, NULL, NULL);

        Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
        if (!NT_SUCCESS(Status))
        {
            KeFlushWriteBuffer();
            return;
        }

        RtlInitUnicodeString(&DestinationString, L"Control\\HAL");
        InitializeObjectAttributes(&ObjectAttributes, &DestinationString, OBJ_CASE_INSENSITIVE, KeyHandle, NULL);

        Status = ZwCreateKey(&Handle, KEY_READ, &ObjectAttributes, 0, NULL, 0, &Disposition);
        if (!NT_SUCCESS(Status))
            goto Exit;
    }

    for (BusNumber = 0; BusNumber < 0xFF; BusNumber++)
    {
        SlotNumber.u.AsULONG = 0;

        for (Device = 0; Device < 0x20; Device++)
        {
            for (Function = 0; Function < 8; Function++)
            {
                DPRINT("HalpPiix4Detect: Bus %X, Dev %X, Func %X, Slot %X\n", BusNumber, Device, Function, SlotNumber.u.AsULONG);

                SlotNumber.u.bits.DeviceNumber = Device;
                SlotNumber.u.bits.FunctionNumber = Function;

                BytesRead = HalGetBusData(PCIConfiguration, BusNumber, SlotNumber.u.AsULONG, &PciHeader, 0x40);
                if (!BytesRead)
                    goto Finish;

                if (PciHeader.VendorID == 0xFFFF)
                    continue;

                DPRINT("HalpPiix4Detect: VendorID %X, DeviceID %X\n", PciHeader.VendorID, PciHeader.DeviceID);

                if (IsInitialize)
                {
                    if (PciHeader.VendorID == 0x8086 &&
                        (PciHeader.DeviceID == 0x7190 || PciHeader.DeviceID == 0x7192) &&
                        PciHeader.RevisionID <= 2)
                    {
                        DPRINT1("HalpPiix4Detect: PciHeader.RevisionID %X\n", PciHeader.RevisionID);
                        ASSERT(FALSE); // HalpDbgBreakPointEx();
                    }

                    Status = HalpGetChipHacks(PciHeader.VendorID, PciHeader.DeviceID, PciHeader.RevisionID, &ChipHacks);
                    if (NT_SUCCESS(Status))
                    {
                        DPRINT1("HalpPiix4Detect: ChipHacks %X\n", ChipHacks);

                        if (ChipHacks & 1)
                        {
                            ASSERT(FALSE); // HalpDbgBreakPointEx();
                            HalpBrokenAcpiTimer = 1;
                        }

                        if (ChipHacks & 2)
                        {
                            ASSERT(FALSE); // HalpDbgBreakPointEx();
                        }

                        if (ChipHacks & 8)
                        {
                            ASSERT(FALSE); // HalpDbgBreakPointEx();
                        }
                    }
                }
                else
                {
                    DPRINT("HalpPiix4Detect: VendorID %X, DeviceID %X\n", PciHeader.VendorID, PciHeader.DeviceID);
                }

                if (PciHeader.VendorID == 0x8086 && PciHeader.DeviceID == 0x7110)
                {
                    DPRINT1("HalpPiix4Detect: VendorID %X, DeviceID %X\n", PciHeader.VendorID, PciHeader.DeviceID);
                    ASSERT(FALSE); // HalpDbgBreakPointEx();
                    goto Finish;
                }

                if (PciHeader.BaseClass == 0xC && PciHeader.SubClass == 3)
                {
                    if (PciHeader.ProgIf == 0x10)
                    {
                        HalpStopOhciInterrupt(BusNumber, SlotNumber.u.AsULONG);
                    }
                    else
                    {
                        if (PciHeader.VendorID == 0x8086)
                        {
                            HalpStopUhciInterrupt(BusNumber, SlotNumber.u.AsULONG, TRUE);
                        }
                        else
                        {
                            if (PciHeader.VendorID == 0x1106)
                                HalpStopUhciInterrupt(BusNumber, SlotNumber.u.AsULONG, FALSE);
                        }
                    }
                }

                if (Function == 0)
                {
                    if (!(PciHeader.HeaderType & PCI_MULTIFUNCTION))
                        break;
                }
            }
        }
    }

Finish:

    if (!IsInitialize)
    {
        KeFlushWriteBuffer();
        return;
    }

    if (Handle)
    {
        ZwClose(Handle);
        Handle = 0;
    }

    if (!IsBroken440BX)
        goto Exit;

    DPRINT1("HalpPiix4Detect: IsBroken440BX TRUE\n");
    ASSERT(FALSE); // HalpDbgBreakPointEx();

Exit:

    if (Handle)
        ZwClose(Handle);

    if (KeyHandle)
        ZwClose(KeyHandle);

    KeFlushWriteBuffer();
}

VOID
NTAPI
HalAcpiBrokenPiix4TimerCarry(VOID)
{
    /* Nothing */
    ;
}

VOID
NTAPI
HalAcpiTimerCarry(VOID)
{
    LARGE_INTEGER Value;
    ULONG Time;

    Time = READ_PORT_ULONG(TimerInfo.TimerPort);
    DPRINT("HalAcpiTimerCarry: Time %X\n", Time);

    Value.QuadPart = (TimerInfo.AcpiTimeValue.QuadPart + TimerInfo.ValueExt);
    Value.QuadPart += ((Value.LowPart ^ Time) & TimerInfo.ValueExt);

    TimerInfo.TimerCarry = Value.HighPart;
    TimerInfo.AcpiTimeValue.QuadPart = Value.QuadPart;
}

CODE_SEG("PAGELK")
VOID
NTAPI
HaliSetWakeEnable(
    _In_ BOOLEAN Enable)
{
    DPRINT("HaliSetWakeEnable: Enable %X\n", Enable);

    HalpWakeupState[0] = Enable;
    HalpWakeupState[1] = FALSE;
}

CODE_SEG("PAGELK")
VOID
NTAPI
HaliSetWakeAlarm(
    _In_ ULONGLONG AlartTime,
    _In_ PTIME_FIELDS WakeTimeFields)
{
    DPRINT("HaliSetWakeAlarm: AlartTime %I64X\n", AlartTime);

    if (!AlartTime)
    {
        DPRINT1("HaliSetWakeAlarm: AlartTime is 0\n");
        ASSERT(FALSE); // HalpDbgBreakPointEx();
        return;
    }

    ASSERT(WakeTimeFields);

    DPRINT1("HaliSetWakeAlarm: ... \n");
    ASSERT(FALSE); // HalpDbgBreakPointEx();
}

/* halfplemented */
VOID
NTAPI
HalpPowerStateCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2)
{
    DPRINT("HalpPowerStateCallback: CallbackContext %X, Arg1 %X, Arg2 %X\n", CallbackContext, Argument1, Argument2);

    if (Argument1 != ULongToPtr(3))
    {
        DPRINT1("HalpPowerStateCallback: Argument1 != 3\n");
        ASSERT(FALSE); // HalpDbgBreakPointEx();
        return;
    }

    if (Argument2 == ULongToPtr(0))
    {
        DPRINT1("HalpPowerStateCallback: FIXME HalpMapNvsArea()\n");
        return;
    }

    if (Argument2 == ULongToPtr(1))
    {
        DPRINT1("HalpPowerStateCallback: FIXME HalpFreeNvsBuffers()\n");
        ASSERT(FALSE); // HalpDbgBreakPointEx();
        return;
    }

    DPRINT1("HalpPowerStateCallback: Unsupported Arg2 %X\n", Argument2);
    ASSERT(FALSE); // HalpDbgBreakPointEx();
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HaliInitPowerManagement(
    _In_ PPM_DISPATCH_TABLE PmDriverDispatchTable,
    _Out_ PPM_DISPATCH_TABLE* PmHalDispatchTable)
{
    UNICODE_STRING CallbackName = RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
    OBJECT_ATTRIBUTES ObjectAttributes;
    PCALLBACK_OBJECT CallbackObject;
    PHYSICAL_ADDRESS PhysicalAddress;
    PFACS Facs;

    PAGED_CODE();
    HalpPiix4Detect(TRUE);

    DPRINT("HaliInitPowerManagement: FIXME HalpPutAcpiHacksInRegistry() \n");

    PmAcpiDispatchTable = PmDriverDispatchTable; // interface with acpi.sys

    if (HalpBrokenAcpiTimer)
    {
        DPRINT1("HaliInitPowerManagement: HalpBrokenAcpiTimer is TRUE\n");
        ASSERT(FALSE); // HalpDbgBreakPointEx();
        HalAcpiDispatchTable.HalAcpiTimerInterrupt = HalAcpiBrokenPiix4TimerCarry;
    }
    else
    {
        HalAcpiDispatchTable.HalAcpiTimerInterrupt = HalAcpiTimerCarry;
    }

    *PmHalDispatchTable = (PPM_DISPATCH_TABLE)&HalAcpiDispatchTable; // HAL export interface

    HalSetWakeEnable = HaliSetWakeEnable;
    HalSetWakeAlarm = HaliSetWakeAlarm;

    /* Create a power callback */    
    InitializeObjectAttributes(&ObjectAttributes,
                               &CallbackName,
                               (OBJ_CASE_INSENSITIVE | OBJ_PERMANENT),
                               NULL,
                               NULL);

    ExCreateCallback(&CallbackObject, &ObjectAttributes, FALSE, TRUE);
    ExRegisterCallback(CallbackObject, HalpPowerStateCallback, NULL);

    if (!HalpFixedAcpiDescTable.facs)
        return STATUS_SUCCESS;

    PhysicalAddress.QuadPart = HalpFixedAcpiDescTable.facs;
    Facs = MmMapIoSpace(PhysicalAddress, sizeof(*Facs), MmNonCached);

    if (Facs && (Facs->Signature == 'SCAF'))
        HalpWakeVector = &Facs->pFirmwareWakingVector;

    return STATUS_SUCCESS;
}

/* PM DISPATCH FUNCTIONS *****************************************************/

CODE_SEG("PAGELK")
NTSTATUS
NTAPI
HaliAcpiSleep(
    _In_opt_ PVOID Context,
    _In_opt_ PENTER_STATE_SYSTEM_HANDLER SystemHandler,
    _In_opt_ PVOID SystemContext,
    _In_ LONG NumberProcessors,
    _In_opt_ LONG volatile * Number)
{
    UNIMPLEMENTED;
    ASSERT(FALSE);//HalpDbgBreakPointEx();
    return STATUS_NOT_IMPLEMENTED;
}

CODE_SEG("PAGE")
VOID
NTAPI
HaliAcpiMachineStateInit(
    _In_ ULONG Par1,
    _In_ PHALP_STATE_DATA StateData,
    _Out_ ULONG* OutInterruptModel)
{
    POWER_STATE_HANDLER handler;
    HALP_STATE_CONTEXT Context;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("HaliAcpiMachineStateInit: StateData %p\n", StateData);

    HalpWakeupState[0] = 1;
    HalpWakeupState[1] = 0;

    //*OutInterruptModel = 0; // PIC HAL
    *OutInterruptModel = 1; // APIC HAL

    if (StateData[0].Data0)
    {
        handler.Type = 0;
        handler.RtcWake = TRUE;
        handler.Handler = HaliAcpiSleep;

        Context.AsULONG = 0;
        Context.Data1 = StateData[0].Data1;
        Context.Data2 = StateData[0].Data2;
        Context.Flags = 0x4;

        handler.Context = UlongToPtr(Context.AsULONG);

        Status = ZwPowerInformation(SystemPowerStateHandler, &handler, sizeof(handler), NULL, 0);
        ASSERT(NT_SUCCESS(Status));
    }

    if (StateData[1].Data0 && HalpWakeVector)
    {
        handler.Type = PowerStateSleeping2;
        handler.RtcWake = TRUE;
        handler.Handler = HaliAcpiSleep;

        Context.AsULONG = 0;
        Context.Data1 = StateData[1].Data1;
        Context.Data2 = StateData[1].Data2;
        Context.Flags = 0x17;

        handler.Context = UlongToPtr(Context.AsULONG);

        Status = ZwPowerInformation(SystemPowerStateHandler, &handler, sizeof(handler), NULL, 0);
        ASSERT(NT_SUCCESS(Status));
    }

    if (StateData[2].Data0 && HalpWakeVector)
    {
        handler.Type = PowerStateSleeping3;
        handler.RtcWake = TRUE;
        handler.Handler = HaliAcpiSleep;

        Context.AsULONG = 0;
        Context.Data1 = StateData[2].Data1;
        Context.Data2 = StateData[2].Data2;
        Context.Flags = 0x17;

        handler.Context = UlongToPtr(Context.AsULONG);

        Status = ZwPowerInformation(SystemPowerStateHandler, &handler, sizeof(handler), NULL, 0);
        ASSERT(NT_SUCCESS(Status));
    }

    if (!HalpDisableHibernate)
    {
        if (StateData[3].Data0)
        {
            handler.Type = PowerStateSleeping4;
            handler.RtcWake = ((HalpFixedAcpiDescTable.flags & 0x80) == 0x80);
            handler.Handler = HaliAcpiSleep;

            Context.AsULONG = 0;
            Context.Data1 = StateData[3].Data1;
            Context.Data2 = StateData[3].Data2;
            Context.Flags = 0x14;

            handler.Context = UlongToPtr(Context.AsULONG);

            Status = ZwPowerInformation(SystemPowerStateHandler, &handler, sizeof(handler), NULL, 0);
            ASSERT(NT_SUCCESS(Status));
        }
        else if (!StateData[4].Data0)
        {
            KeFlushWriteBuffer();
            return;
        }
        else if (!HalpDisableS5Hibernation)
        {
            handler.Type = PowerStateSleeping4;
            handler.RtcWake = ((HalpFixedAcpiDescTable.flags & 0x80) == 0x80);
            handler.Handler = HaliAcpiSleep;

            Context.AsULONG = 0;
            Context.Data1 = StateData[4].Data1;
            Context.Data2 = StateData[4].Data2;
            Context.Flags = 0x14;

            handler.Context = UlongToPtr(Context.AsULONG);

            Status = ZwPowerInformation(SystemPowerStateHandler, &handler, sizeof(handler), NULL, 0);
            ASSERT(NT_SUCCESS(Status));
        }
    }

    if (StateData[4].Data0)
    {
        handler.Type = PowerStateShutdownOff;
        handler.RtcWake = FALSE;
        handler.Handler = HaliAcpiSleep;

        Context.AsULONG = 0;
        Context.Data1 = StateData[4].Data1;
        Context.Data2 = StateData[4].Data2;
        Context.Flags = 0x8;

        HalpShutdownContext = Context.AsULONG;
        handler.Context = UlongToPtr(Context.AsULONG);

        Status = ZwPowerInformation(SystemPowerStateHandler, &handler, sizeof(handler), NULL, 0);
        ASSERT(NT_SUCCESS(Status));
    }

    KeFlushWriteBuffer();
}

CODE_SEG("PAGE")
ULONG
NTAPI
HaliAcpiQueryFlags(VOID)
{
    UNIMPLEMENTED;
    ASSERT(FALSE);// HalpDbgBreakPointEx();
    return 0;
}

CODE_SEG("PAGELK")
UCHAR
NTAPI
HalpAcpiPicStateIntact(VOID)
{
    UNIMPLEMENTED;
    ASSERT(FALSE);// HalpDbgBreakPointEx();
    return 0;
}

CODE_SEG("PAGELK")
VOID
NTAPI
HalpRestoreInterruptControllerState(VOID)
{
    UNIMPLEMENTED;
    ASSERT(FALSE);// HalpDbgBreakPointEx();
}

CODE_SEG("PAGE")
VOID
NTAPI
HaliSetVectorState(
    _In_ ULONG Vector,
    _In_ ULONG Par2)
{
    HalpSetVectorState(Vector, Par2);
}

CODE_SEG("PAGELK")
ULONG
NTAPI
HalpGetApicVersion(
    _In_ ULONG Par1)
{
    UNIMPLEMENTED;
    ASSERT(FALSE);// HalpDbgBreakPointEx();
    return 0;
}

VOID
NTAPI
HaliSetMaxLegacyPciBusNumber(
    _In_ ULONG MaxLegacyPciBusNumber)
{
    HalpMaxPciBus = max(HalpMaxPciBus, MaxLegacyPciBusNumber);
}

CODE_SEG("PAGE")
BOOLEAN
NTAPI
HaliIsVectorValid(
    _In_ ULONG Vector)
{
    USHORT IntI;
    BOOLEAN Result;

    DPRINT("HaliIsVectorValid: Vector %X\n", Vector);
    PAGED_CODE();

    Result = HalpGetApicInterruptDesc(Vector, &IntI);
    DPRINT("HaliIsVectorValid: return Result %X\n", Result);

    return Result;
}

/* EOF */
