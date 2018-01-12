#include "usbuhci.h"

#define NDEBUG
#include <debug.h>

VOID
NTAPI
UhciRHGetRootHubData(IN PVOID uhciExtension,
                     IN PVOID rootHubData)
{
    PUHCI_EXTENSION UhciExtension = uhciExtension;
    PUSBPORT_ROOT_HUB_DATA RootHubData = rootHubData;
    USBPORT_HUB_11_CHARACTERISTICS HubCharacteristics;

    DPRINT("UhciRHGetRootHubData: ...\n");

    HubCharacteristics.AsUSHORT = 0;
    HubCharacteristics.PowerControlMode = 1;
    HubCharacteristics.NoPowerSwitching = 1;
    HubCharacteristics.OverCurrentProtectionMode = 1;

    if (UhciExtension->HcFlavor != UHCI_Piix4)
        HubCharacteristics.NoOverCurrentProtection = 1;

    RootHubData->NumberOfPorts = UHCI_NUM_ROOT_HUB_PORTS;
    RootHubData->HubCharacteristics.Usb11HubCharacteristics = HubCharacteristics;
    RootHubData->PowerOnToPowerGood = 1;
    RootHubData->HubControlCurrent = 0;
}

MPSTATUS
NTAPI
UhciRHGetStatus(IN PVOID uhciExtension,
                IN PUSHORT Status)
{
    DPRINT("UhciRHGetStatus: ...\n");
    *Status = UHCI_RH_STATUS_SUCCESS;
    return MP_STATUS_SUCCESS;
}

MPSTATUS
NTAPI
UhciRHGetPortStatus(IN PVOID uhciExtension,
                    IN USHORT Port,
                    IN PUSB_PORT_STATUS_AND_CHANGE PortStatus)
{
    PUHCI_EXTENSION UhciExtension = uhciExtension;
    PUHCI_HW_REGISTERS BaseRegister;
    PUSHORT PortControlRegister;
    UHCI_PORT_STATUS_CONTROL PortControl;
    ULONG port;
    USB_20_PORT_STATUS portStatus;
    USB_20_PORT_CHANGE portChange;

    //DPRINT("UhciRHGetPortStatus: ...\n");

    ASSERT(Port != 0);

    BaseRegister = UhciExtension->BaseRegister;
    PortControlRegister = &BaseRegister->PortControl[Port-1].AsUSHORT;
    PortControl.AsUSHORT = READ_PORT_USHORT(PortControlRegister);

    portStatus.AsUshort16 = 0;
    portChange.AsUshort16 = 0;

    portStatus.CurrentConnectStatus = PortControl.CurrentConnectStatus;
    portStatus.PortEnabledDisabled = PortControl.PortEnabledDisabled;

    if (PortControl.Suspend == 1 &&
        PortControl.PortEnabledDisabled == 1)
    {
        portStatus.Suspend = 1;
    }
    else
    {
        portStatus.Suspend = 0;
    }

    // FIXME HcFlavor in usbport
    //if (UhciExtension->HcFlavor == UHCI_Piix4)
    if (TRUE)
    {
        portStatus.OverCurrent = PortControl.Reserved2 & 1;
        portStatus.PortPower = (~PortControl.Reserved2 & 1);
        portChange.OverCurrentIndicatorChange = (PortControl.Reserved2 & 2) != 0;
    }
    else
    {
        portStatus.OverCurrent = 0;
        portStatus.PortPower = 1;
        portChange.OverCurrentIndicatorChange = 0;
    }

    portStatus.HighSpeedDeviceAttached = 0;

    portStatus.Reset = PortControl.PortReset;
    portStatus.LowSpeedDeviceAttached = PortControl.LowSpeedDevice;
    portChange.ConnectStatusChange = PortControl.ConnectStatusChange;

    port = 1 << (Port - 1);

    if (UhciExtension->ResetPortMask & port)
    {
        portChange.ConnectStatusChange = 0;
        portChange.PortEnableDisableChange = 0;
    }
    else
    {
        portChange.PortEnableDisableChange = PortControl.PortEnableDisableChange;
    }

    if (UhciExtension->SuspendChangePortMask & port)
        portChange.SuspendChange = 1;

    if (UhciExtension->ResetChangePortMask & port)
        portChange.ResetChange = 1;

    PortStatus->PortStatus.Usb20PortStatus = portStatus;
    PortStatus->PortChange.Usb20PortChange = portChange;

    //DPRINT("UhciRHGetPortStatus: PortControl.AsUSHORT[%x] - %X, PortStatus - %X\n",
    //       Port,
    //       PortControl.AsUSHORT,
    //       PortStatus->AsUlong32);

    return MP_STATUS_SUCCESS;
}

MPSTATUS
NTAPI
UhciRHGetHubStatus(IN PVOID uhciExtension,
                   IN PUSB_HUB_STATUS_AND_CHANGE HubStatus)
{
    //DPRINT("UhciRHGetHubStatus: ...\n");
    HubStatus->AsUlong32 = 0;
    return MP_STATUS_SUCCESS;
}

VOID
NTAPI
UhciRHPortResetComplete(IN PVOID uhciExtension,
                        IN PVOID pPort)
{
    PUHCI_EXTENSION UhciExtension = uhciExtension;
    ULONG ix;
    PUHCI_HW_REGISTERS BaseRegister;
    PUSHORT PortControlRegister;
    UHCI_PORT_STATUS_CONTROL PortControl;
    USHORT Port;

    DPRINT("UhciRHPortResetComplete: ...\n");

    BaseRegister = UhciExtension->BaseRegister;
    ASSERT(*(PUSHORT)pPort != 0);
    Port = *(PUSHORT)pPort - 1;

    PortControlRegister = &BaseRegister->PortControl[Port].AsUSHORT;
    PortControl.AsUSHORT = READ_PORT_USHORT(PortControlRegister);

    PortControl.ConnectStatusChange = 0;
    PortControl.PortEnableDisableChange = 0;
    PortControl.PortReset = 0;

    WRITE_PORT_USHORT(PortControlRegister, PortControl.AsUSHORT);

    while (UhciHardwarePresent(UhciExtension))
    {
        PortControl.AsUSHORT = READ_PORT_USHORT(PortControlRegister);

        if (PortControl.PortReset == 1)
            continue;

        for (ix = 0; ix < 10; ++ix)
        {
            KeStallExecutionProcessor(50);

            PortControl.AsUSHORT = READ_PORT_USHORT(PortControlRegister);

            if (PortControl.PortEnabledDisabled == 1)
                break;

            PortControl.PortEnabledDisabled = 1;
            WRITE_PORT_USHORT(PortControlRegister, PortControl.AsUSHORT);
        }

        PortControl.ConnectStatusChange = 1;
        PortControl.PortEnableDisableChange = 1;
        WRITE_PORT_USHORT(PortControlRegister, PortControl.AsUSHORT);

        if (UhciExtension->HcFlavor == UHCI_VIA &&
            UhciExtension->HcFlavor == UHCI_VIA_x01 &&
            UhciExtension->HcFlavor == UHCI_VIA_x02 &&
            UhciExtension->HcFlavor == UHCI_VIA_x03 &&
            UhciExtension->HcFlavor == UHCI_VIA_x04)
        {
            DPRINT("UhciRHPortResetComplete: Via chip. FIXME\n");
            DbgBreakPoint();
            return;
        }

        UhciExtension->ResetChangePortMask |= (1 << Port);
        UhciExtension->ResetPortMask &= ~(1 << Port);

        RegPacket.UsbPortInvalidateRootHub(UhciExtension);

        return;
    }
}

VOID
NTAPI
UhciRHSetFeaturePortResetWorker(IN PUHCI_EXTENSION UhciExtension,
                                IN PUSHORT pPort)
{
    PUHCI_HW_REGISTERS BaseRegister;
    PUSHORT PortControlRegister;
    UHCI_PORT_STATUS_CONTROL PortControl;
    USHORT Port;

    DPRINT("UhciRHSetFeaturePortResetWorker: ...\n");

    BaseRegister = UhciExtension->BaseRegister;

    ASSERT(*pPort != 0);
    Port = *pPort - 1;

    PortControlRegister = &BaseRegister->PortControl[Port].AsUSHORT;
    PortControl.AsUSHORT = READ_PORT_USHORT(PortControlRegister);

    PortControl.ConnectStatusChange = 0;
    PortControl.PortEnableDisableChange = 0;
    PortControl.PortReset = 1;

    WRITE_PORT_USHORT(PortControlRegister, PortControl.AsUSHORT);

    RegPacket.UsbPortRequestAsyncCallback(UhciExtension,
                                          10, // TimerValue
                                          pPort,
                                          sizeof(pPort),
                                          UhciRHPortResetComplete);
}

MPSTATUS
NTAPI
UhciRHSetFeaturePortReset(IN PVOID uhciExtension,
                          IN USHORT Port)
{
    PUHCI_EXTENSION UhciExtension = uhciExtension;
    ULONG ResetPortMask;
    ULONG port;

    DPRINT("UhciRHSetFeaturePortReset: ...\n");

    ASSERT(Port != 0);

    ResetPortMask = UhciExtension->ResetPortMask;
    port = 1 << (Port - 1);

    if (ResetPortMask & port)
        return MP_STATUS_FAILURE;

    UhciExtension->ResetPortMask = ResetPortMask | port;

    if (UhciExtension->HcFlavor == UHCI_VIA &&
        UhciExtension->HcFlavor == UHCI_VIA_x01 &&
        UhciExtension->HcFlavor == UHCI_VIA_x02 &&
        UhciExtension->HcFlavor == UHCI_VIA_x03 &&
        UhciExtension->HcFlavor == UHCI_VIA_x04)
    {
        DPRINT1("UhciRHSetFeaturePortReset: Via chip. FIXME\n");
        return MP_STATUS_SUCCESS;
    }

    UhciRHSetFeaturePortResetWorker(UhciExtension, &Port);

    return MP_STATUS_SUCCESS;
}

MPSTATUS
NTAPI
UhciRHSetFeaturePortPower(IN PVOID uhciExtension,
                          IN USHORT Port)
{
    DPRINT("UhciRHSetFeaturePortPower: ...\n");
    ASSERT(Port != 0);
    return MP_STATUS_SUCCESS;
}

MPSTATUS
NTAPI
UhciRHPortEnable(IN PVOID uhciExtension,
                 IN USHORT Port,
                 IN BOOLEAN IsSet)
{
    PUHCI_EXTENSION UhciExtension = uhciExtension;
    PUHCI_HW_REGISTERS BaseRegister;
    PUSHORT PortControlRegister;
    UHCI_PORT_STATUS_CONTROL PortControl;

    DPRINT("UhciRHPortEnable: ...\n");

    ASSERT(Port != 0);

    BaseRegister = UhciExtension->BaseRegister;
    PortControlRegister = &BaseRegister->PortControl[Port-1].AsUSHORT;

    PortControl.AsUSHORT = READ_PORT_USHORT(PortControlRegister);

    PortControl.ConnectStatusChange = 0;
    PortControl.PortEnableDisableChange = 0;

    if (IsSet)
        PortControl.PortEnabledDisabled = 1;
    else
        PortControl.PortEnabledDisabled = 0;

    WRITE_PORT_USHORT(PortControlRegister, PortControl.AsUSHORT);

    return MP_STATUS_SUCCESS;
}

MPSTATUS
NTAPI
UhciRHSetFeaturePortEnable(IN PVOID uhciExtension,
                           IN USHORT Port)
{
    PUHCI_EXTENSION UhciExtension = uhciExtension;
    DPRINT("UhciRHSetFeaturePortEnable: ...\n");
    ASSERT(Port != 0);
    return UhciRHPortEnable(UhciExtension, Port, TRUE);
}

MPSTATUS
NTAPI
UhciRHSetFeaturePortSuspend(IN PVOID uhciExtension,
                            IN USHORT Port)
{
    DPRINT("UhciRHSetFeaturePortSuspend: UNIMPLEMENTED. FIXME\n");
    ASSERT(Port != 0);
    return MP_STATUS_SUCCESS;
}

MPSTATUS
NTAPI
UhciRHClearFeaturePortEnable(IN PVOID uhciExtension,
                             IN USHORT Port)
{
    PUHCI_EXTENSION UhciExtension = uhciExtension;
    DPRINT("UhciRHClearFeaturePortEnable: ...\n");
    ASSERT(Port != 0);
    return UhciRHPortEnable(UhciExtension, Port, FALSE);
}

MPSTATUS
NTAPI
UhciRHClearFeaturePortPower(IN PVOID uhciExtension,
                            IN USHORT Port)
{
    DPRINT("UhciRHClearFeaturePortPower: UNIMPLEMENTED. FIXME\n");
    ASSERT(Port != 0);
    return MP_STATUS_SUCCESS;
}

MPSTATUS
NTAPI
UhciRHClearFeaturePortSuspend(IN PVOID uhciExtension,
                              IN USHORT Port)
{
    DPRINT("UhciRHClearFeaturePortSuspend: UNIMPLEMENTED. FIXME\n");
    ASSERT(Port != 0);
    return MP_STATUS_SUCCESS;
}

MPSTATUS
NTAPI
UhciRHClearFeaturePortEnableChange(IN PVOID uhciExtension,
                                   IN USHORT Port)
{
    PUHCI_EXTENSION UhciExtension = uhciExtension;
    PUHCI_HW_REGISTERS BaseRegister;
    PUSHORT PortControlRegister;
    UHCI_PORT_STATUS_CONTROL PortControl;

    DPRINT("UhciRHClearFeaturePortEnableChange: ...\n");

    ASSERT(Port != 0);

    BaseRegister = UhciExtension->BaseRegister;
    PortControlRegister = (PUSHORT)&BaseRegister->PortControl[Port - 1];
    PortControl.AsUSHORT = READ_PORT_USHORT(PortControlRegister);

    PortControl.ConnectStatusChange = 0;
    PortControl.PortEnableDisableChange = 1;
    WRITE_PORT_USHORT(PortControlRegister, PortControl.AsUSHORT);

    return MP_STATUS_SUCCESS;
}

MPSTATUS
NTAPI
UhciRHClearFeaturePortConnectChange(IN PVOID uhciExtension,
                                    IN USHORT Port)
{
    PUHCI_EXTENSION UhciExtension = uhciExtension;
    PUHCI_HW_REGISTERS BaseRegister;
    PUSHORT PortControlRegister;
    UHCI_PORT_STATUS_CONTROL PortControl;

    DPRINT("UhciRHClearFeaturePortConnectChange: Port - %04X\n", Port);

    ASSERT(Port != 0);

    BaseRegister = UhciExtension->BaseRegister;
    PortControlRegister = (PUSHORT)&BaseRegister->PortControl[Port - 1];
    PortControl.AsUSHORT = READ_PORT_USHORT(PortControlRegister);

    if (PortControl.ConnectStatusChange == 1)
    {
        /* WC (Write Clear) bits */
        PortControl.PortEnableDisableChange = 0;
        PortControl.ConnectStatusChange = 1;
        WRITE_PORT_USHORT(PortControlRegister, PortControl.AsUSHORT);
    }

    return MP_STATUS_SUCCESS;
}

MPSTATUS
NTAPI
UhciRHClearFeaturePortResetChange(IN PVOID uhciExtension,
                                  IN USHORT Port)
{
    PUHCI_EXTENSION UhciExtension = uhciExtension;
    DPRINT("UhciRHClearFeaturePortResetChange: ...\n");
    ASSERT(Port != 0);
    UhciExtension->ResetChangePortMask &= ~(1 << (Port - 1));
    return MP_STATUS_SUCCESS;
}

MPSTATUS
NTAPI
UhciRHClearFeaturePortSuspendChange(IN PVOID uhciExtension,
                                    IN USHORT Port)
{
    DPRINT("UhciRHClearFeaturePortSuspendChange: UNIMPLEMENTED. FIXME\n");
    ASSERT(Port != 0);
    return MP_STATUS_SUCCESS;
}

MPSTATUS
NTAPI
UhciRHClearFeaturePortOvercurrentChange(IN PVOID uhciExtension,
                                        IN USHORT Port)
{
    DPRINT("UhciRHClearFeaturePortOvercurrentChange: UNIMPLEMENTED. FIXME\n");
    ASSERT(Port != 0);
    return MP_STATUS_SUCCESS;
}

VOID
NTAPI
UhciRHDisableIrq(IN PVOID uhciExtension)
{
    //DPRINT("UhciRHDisableIrq: \n");
    return;
}

VOID
NTAPI
UhciRHEnableIrq(IN PVOID uhciExtension)
{
    //DPRINT("UhciRHEnableIrq: \n");
    return;
}

