
/* INCLUDES ******************************************************************/

#include <hal.h>
#include "dispatch.h"
#include "../../../drivers/usb/usbohci/hardware.h"
#include "../../../drivers/usb/usbuhci/hardware.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

PPM_DISPATCH_TABLE PmAcpiDispatchTable; // It is ACPI_HAL_DISPATCH_TABLE. See ACPIInitHalDispatchTable() in acpi.sys driver.
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

HALP_TIMER_INFO TimerInfo;
PVOID HalpWakeVector = NULL;
BOOLEAN HalpBrokenAcpiTimer = FALSE;
BOOLEAN HalpWakeupState[2];
BOOLEAN HalpDisableHibernate;
BOOLEAN HalpDisableS5Hibernation;

extern FADT HalpFixedAcpiDescTable;
extern ULONG HalpWAETDeviceFlags;
extern ULONG HalpMaxPciBus;
extern ULONG HalpShutdownContext;

/* PRIVATE FUNCTIONS *********************************************************/

VOID
NTAPI
HalaAcpiTimerInit(_In_ PULONG TimerPort,
                  _In_ BOOLEAN IsTimerValExt)
{
    DPRINT("HalaAcpiTimerInit: Port %X, IsValExt %X\n", TimerPort, IsTimerValExt);

    RtlZeroMemory(&TimerInfo, sizeof(TimerInfo));

    TimerInfo.TimerPort = TimerPort;

    if (IsTimerValExt)
        TimerInfo.ValueExt = 0x80000000; // 32-bit
    else
        TimerInfo.ValueExt = 0x00800000; // 24-bit

    if (!HalpBrokenAcpiTimer)
    {
        DPRINT("HalpBrokenAcpiTimer - FALSE\n");
        return;
    }

    DPRINT1("HalaAcpiTimerInit: FIXME HalpQueryBrokenPiix4()\n");
    ASSERT(0); // HalpDbgBreakPointEx();

}

VOID
NTAPI
HaliAcpiTimerInit(_In_ PULONG TimerPort,
                  _In_ BOOLEAN TimerValExt)
{
    PAGED_CODE();

    DPRINT("HaliAcpiTimerInit: Port %X, ValExt %X\n", TimerPort, TimerValExt);
    DPRINT("HalpFixedAcpiDescTable.flags - %08X\n", HalpFixedAcpiDescTable.flags);

    /* Is this in the init phase? */
    if (!TimerPort)
    {
        /* Get the data from the FADT */

        /* System port address of the Power Management Timer Control Register Block */
        TimerPort = (PULONG)HalpFixedAcpiDescTable.pm_tmr_blk_io_port;

        /* A zero indicates TMR_VAL is implemented as a 24-bit value.
           A one indicates TMR_VAL is implemented as a 32-bit value.
        */
        TimerValExt = ((HalpFixedAcpiDescTable.flags & ACPI_TMR_VAL_EXT) != 0);
        DPRINT1("TimerPort %X, TimerValExt %X\n", TimerPort, TimerValExt);
    }

    /* FIXME: Now proceed to the timer initialization */
    HalaAcpiTimerInit(TimerPort, TimerValExt);
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

VOID
NTAPI
HalAcpiBrokenPiix4TimerCarry(VOID)
{
    /* Nothing */
    ;
}

VOID
NTAPI
HaliSetWakeEnable(_In_ BOOLEAN Enable)
{
    DPRINT("HaliSetWakeEnable: Enable %X\n", Enable);

    HalpWakeupState[1] = 0;
    HalpWakeupState[0] = Enable;
}

VOID
NTAPI
HaliSetWakeAlarm(_In_ ULONGLONG AlartTime,
                 _In_ PTIME_FIELDS WakeTimeFields)
{
    DPRINT("HaliSetWakeAlarm: AlartTime %I64X\n", AlartTime);

    if (!AlartTime)
    {
        DPRINT1("HaliSetWakeAlarm: AlartTime is 0\n");
        ASSERT(0); // HalpDbgBreakPointEx();
        return;
    }

    ASSERT(WakeTimeFields);

    DPRINT1("HaliSetWakeAlarm: ... \n");
    ASSERT(0); // HalpDbgBreakPointEx();
}

/* halfplemented */
VOID
NTAPI
HalpPowerStateCallback(_In_ PVOID CallbackContext,
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
        //ASSERT(FALSE); // HalpDbgBreakPointEx();
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

NTSTATUS
NTAPI
HalpGetChipHacks(_In_ USHORT VendorID,
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
        ASSERT(0); // HalpDbgBreakPointEx();
        ChipHacks >>= 12;
    }

    ChipHacks &= 0xFFF;

    if (HalpWAETDeviceFlags & 2)
    {
        DPRINT1("HalpGetChipHacks: HalpWAETDeviceFlags %X\n", HalpWAETDeviceFlags);
        ASSERT(0); // HalpDbgBreakPointEx();
        ChipHacks &= 0xFFFFFFFE;
    }

    *OutChipHacks = ChipHacks;

    ZwClose(KeyHandle);
    KeFlushWriteBuffer();

    return Status;
}

VOID
NTAPI
HalpStopOhciInterrupt(_In_ ULONG BusNumber,
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
HalpStopUhciInterrupt(_In_ ULONG BusNumber,
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

VOID
NTAPI
HalpPiix4Detect(_In_ BOOLEAN IsInitialize)
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
                        ASSERT(0); // HalpDbgBreakPointEx();
                    }

                    Status = HalpGetChipHacks(PciHeader.VendorID, PciHeader.DeviceID, PciHeader.RevisionID, &ChipHacks);
                    if (NT_SUCCESS(Status))
                    {
                        DPRINT1("HalpPiix4Detect: ChipHacks %X\n", ChipHacks);

                        if (ChipHacks & 1)
                        {
                            ASSERT(0); // HalpDbgBreakPointEx();
                            HalpBrokenAcpiTimer = 1;
                        }
                        if (ChipHacks & 2)
                        {
                            ASSERT(0); // HalpDbgBreakPointEx();
                        }
                        if (ChipHacks & 8)
                        {
                            ASSERT(0); // HalpDbgBreakPointEx();
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
                    ASSERT(0); // HalpDbgBreakPointEx();
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
                    if ((PciHeader.HeaderType & PCI_MULTIFUNCTION) == 0)
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
    ASSERT(0); // HalpDbgBreakPointEx();

Exit:

    if (Handle)
        ZwClose(Handle);

    if (KeyHandle)
        ZwClose(KeyHandle);

    KeFlushWriteBuffer();
}

NTSTATUS
NTAPI
HalacpiInitPowerManagement(
    _In_ PPM_DISPATCH_TABLE PmDriverDispatchTable,
    _Out_ PPM_DISPATCH_TABLE * PmHalDispatchTable)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    PHYSICAL_ADDRESS PhysicalAddress;
    PCALLBACK_OBJECT CallbackObject;
    UNICODE_STRING CallbackName;
    PFACS Facs;

    PAGED_CODE();
    HalpPiix4Detect(TRUE);

    DPRINT("HalacpiInitPowerManagement: FIXME HalpPutAcpiHacksInRegistry() \n");

    PmAcpiDispatchTable = PmDriverDispatchTable; // interface with acpi.sys

    HalAcpiDispatchTable.HalAcpiTimerInterrupt = HalAcpiTimerCarry;
    if (HalpBrokenAcpiTimer)
    {
        DPRINT1("HalacpiInitPowerManagement: HalpBrokenAcpiTimer is TRUE\n");
        ASSERT(0); // HalpDbgBreakPointEx();
        HalAcpiDispatchTable.HalAcpiTimerInterrupt = HalAcpiBrokenPiix4TimerCarry;
    }

    *PmHalDispatchTable = (PPM_DISPATCH_TABLE)&HalAcpiDispatchTable; // HAL export interface

    HalSetWakeEnable = HaliSetWakeEnable;
    HalSetWakeAlarm = HaliSetWakeAlarm;

    DPRINT("HalacpiInitPowerManagement: FIXME Callbacks\\PowerState \n");

    /* Create a power callback */    
    RtlInitUnicodeString(&CallbackName, L"\\Callback\\PowerState");

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
    Facs = MmMapIoSpace(PhysicalAddress, 0x40, MmNonCached);

    if (Facs && (Facs->Signature == 'SCAF'))
        HalpWakeVector = &Facs->pFirmwareWakingVector;

    return STATUS_SUCCESS;
}

/* PM DISPATCH FUNCTIONS *****************************************************/

NTSTATUS
NTAPI
HaliAcpiSleep(_In_opt_ PVOID Context,
              _In_opt_ PENTER_STATE_SYSTEM_HANDLER SystemHandler,
              _In_opt_ PVOID SystemContext,
              _In_ LONG NumberProcessors,
              _In_opt_ LONG volatile * Number)
{
    UNIMPLEMENTED;
    ASSERT(FALSE);//HalpDbgBreakPointEx();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
NTAPI
HaliAcpiMachineStateInit(_In_ ULONG Par1,
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

    *OutInterruptModel = 0; // PIC HAL
    //*OutInterruptModel = 1; // APIC HAL

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

ULONG
NTAPI
HaliAcpiQueryFlags(VOID)
{
    UNIMPLEMENTED;
    ASSERT(0);// HalpDbgBreakPointEx();
    return 0;
}

UCHAR
NTAPI
HalpAcpiPicStateIntact(VOID)
{
    UNIMPLEMENTED;
    ASSERT(0);// HalpDbgBreakPointEx();
    return 0;
}

VOID
NTAPI
HalpRestoreInterruptControllerState(VOID)
{
    UNIMPLEMENTED;
    ASSERT(0);// HalpDbgBreakPointEx();
}

VOID
NTAPI
HaliSetVectorState(_In_ ULONG Par1,
                   _In_ ULONG Par2)
{
    /* Nothing for PIC */
    return;
}

ULONG
NTAPI
HalpGetApicVersion(_In_ ULONG Par1)
{
    UNIMPLEMENTED;
    ASSERT(0);// HalpDbgBreakPointEx();
    return 0;
}

VOID
NTAPI
HaliSetMaxLegacyPciBusNumber(_In_ ULONG MaxLegacyPciBusNumber)
{
    HalpMaxPciBus = max(HalpMaxPciBus, MaxLegacyPciBusNumber);
}

BOOLEAN
NTAPI
HaliIsVectorValid(_In_ ULONG Vector)
{
    DPRINT("HaliIsVectorValid: Vector %X\n", Vector);

    if (Vector >= 0x10)
    {
        DPRINT1("HaliIsVectorValid: Vector %X\n", Vector);
        //ASSERT(Vector < 0x10);
    }

    return (Vector < 0x10);
}

/* EOF */
