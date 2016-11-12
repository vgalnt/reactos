#include "usbehci.h"

//#define NDEBUG
#include <debug.h>

#define NDEBUG_EHCI_TRACE
#include "dbg_ehci.h"

USBPORT_REGISTRATION_PACKET RegPacket;


MPSTATUS
NTAPI
EHCI_OpenEndpoint(IN PVOID ehciExtension,
                  IN PVOID endpointParameters,
                  IN PVOID ehciEndpoint)
{
    DPRINT1("EHCI_OpenEndpoint: UNIMPLEMENTED. FIXME\n");
    return 0;
}

MPSTATUS
NTAPI
EHCI_ReopenEndpoint(IN PVOID ehciExtension,
                    IN PVOID endpointParameters,
                    IN PVOID ehciEndpoint)
{
    DPRINT1("EHCI_ReopenEndpoint: UNIMPLEMENTED. FIXME\n");
    return 0;
}

VOID
NTAPI
EHCI_QueryEndpointRequirements(IN PVOID ehciExtension,
                               IN PVOID endpointParameters,
                               IN PULONG EndpointRequirements)
{
    DPRINT1("EHCI_QueryEndpointRequirements: UNIMPLEMENTED. FIXME\n");
}

VOID
NTAPI
EHCI_CloseEndpoint(IN PVOID ehciExtension,
                   IN PVOID ehciEndpoint,
                   IN BOOLEAN IsDoDisablePeriodic)
{
    DPRINT1("EHCI_CloseEndpoint: UNIMPLEMENTED. FIXME\n");
}

MPSTATUS
NTAPI
EHCI_InitializeSchedule(IN PEHCI_EXTENSION EhciExtension,
                        IN PVOID resourcesStartVA,
                        IN PVOID resourcesStartPA)
{
    DPRINT1("EHCI_InitializeSchedule: UNIMPLEMENTED. FIXME\n");
    return 0;
}

MPSTATUS
NTAPI
EHCI_InitializeHardware(IN PEHCI_EXTENSION EhciExtension)
{
    PULONG BaseIoAdress;
    PULONG OperationalRegs;
    EHCI_USB_COMMAND Command;
    LARGE_INTEGER CurrentTime = {{0, 0}};
    LARGE_INTEGER LastTime = {{0, 0}};
    EHCI_HC_STRUCTURAL_PARAMS StructuralParams;

    DPRINT_EHCI("EHCI_InitializeHardware: ... \n");

    OperationalRegs = EhciExtension->OperationalRegs;
    BaseIoAdress = EhciExtension->BaseIoAdress;

    Command.AsULONG = READ_REGISTER_ULONG(OperationalRegs + EHCI_USBCMD);
    Command.Reset = 1;
    WRITE_REGISTER_ULONG(OperationalRegs + EHCI_USBCMD, Command.AsULONG);

    KeQuerySystemTime(&CurrentTime);
    CurrentTime.QuadPart += 100 * 10000; // 100 msec

    DPRINT_EHCI("EHCI_InitializeHardware: Start reset ... \n");

    while (TRUE)
    {
        KeQuerySystemTime(&LastTime);
        Command.AsULONG = READ_REGISTER_ULONG(OperationalRegs + EHCI_USBCMD);

        if (Command.Reset != 1)
        {
            break;
        }

        if (LastTime.QuadPart >= CurrentTime.QuadPart)
        {
            if (Command.Reset == 1)
            {
                DPRINT1("EHCI_InitializeHardware: Reset failed!\n");
                return 7;
            }

            break;
        }
    }

    DPRINT("EHCI_InitializeHardware: Reset - OK\n");

    StructuralParams.AsULONG = READ_REGISTER_ULONG(BaseIoAdress + 1); // HCSPARAMS register

    EhciExtension->NumberOfPorts = StructuralParams.PortCount;
    EhciExtension->PortPowerControl = StructuralParams.PortPowerControl;

    DPRINT("EHCI_InitializeHardware: StructuralParams - %p\n", StructuralParams.AsULONG);
    DPRINT("EHCI_InitializeHardware: PortPowerControl - %x\n", EhciExtension->PortPowerControl);
    DPRINT("EHCI_InitializeHardware: N_PORTS          - %x\n", EhciExtension->NumberOfPorts);

    WRITE_REGISTER_ULONG(OperationalRegs + EHCI_PERIODICLISTBASE, 0);
    WRITE_REGISTER_ULONG(OperationalRegs + EHCI_ASYNCLISTBASE, 0);

    EhciExtension->InterruptMask.AsULONG = 0;
    EhciExtension->InterruptMask.PortChangeInterrupt = 1;

    return 0;
}

MPSTATUS
NTAPI
EHCI_TakeControlHC(IN PEHCI_EXTENSION EhciExtension)
{
    DPRINT1("EHCI_TakeControlHC: UNIMPLEMENTED. FIXME\n");
    return 0;
}

VOID
NTAPI
EHCI_GetRegistryParameters(IN PEHCI_EXTENSION EhciExtension)
{
    DPRINT1("EHCI_GetRegistryParameters: UNIMPLEMENTED. FIXME\n");
}

MPSTATUS
NTAPI
EHCI_StartController(IN PVOID ehciExtension,
                     IN PUSBPORT_RESOURCES Resources)
{
    PEHCI_EXTENSION EhciExtension;
    PULONG BaseIoAdress;
    PULONG OperationalRegs;
    MPSTATUS MPStatus;
    EHCI_USB_COMMAND Command;
    UCHAR CapabilityRegLength;
    UCHAR Fladj;

    DPRINT_EHCI("EHCI_StartController: ... \n");

    if ((Resources->TypesResources & 6) != 6) // (Interrupt | Memory)
    {
        DPRINT1("EHCI_StartController: Resources->TypesResources - %x\n",
                Resources->TypesResources);

        return 4;
    }

    EhciExtension = (PEHCI_EXTENSION)ehciExtension;

    BaseIoAdress = (PULONG)Resources->ResourceBase;
    EhciExtension->BaseIoAdress = BaseIoAdress;

    CapabilityRegLength = (UCHAR)READ_REGISTER_ULONG(BaseIoAdress);
    OperationalRegs = (PULONG)((ULONG)BaseIoAdress + CapabilityRegLength);
    EhciExtension->OperationalRegs = OperationalRegs;

    DPRINT("EHCI_StartController: BaseIoAdress    - %p\n", BaseIoAdress);
    DPRINT("EHCI_StartController: OperationalRegs - %p\n", OperationalRegs);

    RegPacket.UsbPortReadWriteConfigSpace(EhciExtension,
                                          1,
                                          &Fladj,
                                          0x61,
                                          1);

    EhciExtension->FrameLengthAdjustment = Fladj;

    EHCI_GetRegistryParameters(EhciExtension);

    MPStatus = EHCI_TakeControlHC(EhciExtension);

    if (MPStatus)
    {
        DPRINT1("EHCI_StartController: Unsuccessful TakeControlHC()\n");
        return MPStatus;
    }

    MPStatus = EHCI_InitializeHardware(EhciExtension);

    if (MPStatus)
    {
        DPRINT1("EHCI_StartController: Unsuccessful InitializeHardware()\n");
        return MPStatus;
    }

    MPStatus = EHCI_InitializeSchedule(EhciExtension,
                                       Resources->StartVA,
                                       Resources->StartPA);

    if (MPStatus)
    {
        DPRINT1("EHCI_StartController: Unsuccessful InitializeSchedule()\n");
        return MPStatus;
    }

    RegPacket.UsbPortReadWriteConfigSpace(EhciExtension,
                                          1,
                                          &Fladj,
                                          0x61,
                                          1);

    if (Fladj != EhciExtension->FrameLengthAdjustment)
    {
        Fladj = EhciExtension->FrameLengthAdjustment;

        RegPacket.UsbPortReadWriteConfigSpace(EhciExtension,
                                              0, // write
                                              &Fladj,
                                              0x61,
                                              1);
    }

    /* Port routing control logic default-routes all ports to this HC */
    WRITE_REGISTER_ULONG(OperationalRegs + EHCI_CONFIGFLAG, 1);
    EhciExtension->PortRoutingControl = 1;

    Command.AsULONG = READ_REGISTER_ULONG(OperationalRegs + EHCI_USBCMD);
    Command.InterruptThreshold = 1; // one micro-frame
    WRITE_REGISTER_ULONG(OperationalRegs + EHCI_USBCMD, Command.AsULONG);

    Command.AsULONG = READ_REGISTER_ULONG(OperationalRegs + EHCI_USBCMD);
    Command.Run = 1; // execution of the schedule
    WRITE_REGISTER_ULONG(OperationalRegs + EHCI_USBCMD, Command.AsULONG);

    EhciExtension->IsStarted = 1;

    if (Resources->Reserved1)
    {
        DPRINT1("EHCI_StartController: FIXME\n");
        DbgBreakPoint();
    }

    return MPStatus;
}

VOID
NTAPI
EHCI_StopController(IN PVOID ehciExtension,
                    IN BOOLEAN IsDoDisableInterrupts)
{
    DPRINT1("EHCI_StopController: UNIMPLEMENTED. FIXME\n");
}

VOID
NTAPI
EHCI_SuspendController(IN PVOID ehciExtension)
{
    DPRINT1("EHCI_SuspendController: UNIMPLEMENTED. FIXME\n");
}

MPSTATUS
NTAPI
EHCI_ResumeController(IN PVOID ehciExtension)
{
    DPRINT1("EHCI_ResumeController: UNIMPLEMENTED. FIXME\n");
    return 0;
}

BOOLEAN
NTAPI
EHCI_InterruptService(IN PVOID ehciExtension)
{
    DPRINT1("EHCI_InterruptService: UNIMPLEMENTED. FIXME\n");
    return 0;
}

VOID
NTAPI
EHCI_InterruptDpc(IN PVOID ehciExtension,
                  IN BOOLEAN IsDoEnableInterrupts)
{
    DPRINT1("EHCI_InterruptDpc: UNIMPLEMENTED. FIXME\n");
}

MPSTATUS
NTAPI
EHCI_SubmitTransfer(IN PVOID ehciExtension,
                    IN PVOID ehciEndpoint,
                    IN PVOID transferParameters,
                    IN PVOID ehciTransfer,
                    IN PVOID sgList)
{
    DPRINT1("EHCI_SubmitTransfer: UNIMPLEMENTED. FIXME\n");
    return 0;
}

MPSTATUS
NTAPI
EHCI_SubmitIsoTransfer(IN PVOID ehciExtension,
                       IN PVOID ehciEndpoint,
                       IN PVOID transferParameters,
                       IN PVOID ehciTransfer,
                       IN PVOID isoParameters)
{
    DPRINT1("EHCI_SubmitIsoTransfer: UNIMPLEMENTED. FIXME\n");
    return 0;
}

VOID
NTAPI
EHCI_AbortTransfer(IN PVOID ehciExtension,
                   IN PVOID ehciEndpoint,
                   IN PVOID ehciTransfer,
                   IN PULONG CompletedLength)
{
    DPRINT1("EHCI_AbortTransfer: UNIMPLEMENTED. FIXME\n");
}

ULONG
NTAPI
EHCI_GetEndpointState(IN PVOID ehciExtension,
                      IN PVOID ehciEndpoint)
{
    DPRINT1("EHCI_GetEndpointState: UNIMPLEMENTED. FIXME\n");
    return 0;
}

VOID
NTAPI
EHCI_SetEndpointState(IN PVOID ehciExtension,
                      IN PVOID ehciEndpoint,
                      IN ULONG EndpointState)
{
    DPRINT1("EHCI_SetEndpointState: UNIMPLEMENTED. FIXME\n");
}

VOID
NTAPI
EHCI_PollEndpoint(IN PVOID ohciExtension,
                  IN PVOID ohciEndpoint)
{
    DPRINT1("EHCI_PollEndpoint: UNIMPLEMENTED. FIXME\n");
}

VOID
NTAPI
EHCI_CheckController(IN PVOID ehciExtension)
{
    DPRINT1("EHCI_CheckController: UNIMPLEMENTED. FIXME\n");
}

ULONG
NTAPI
EHCI_Get32BitFrameNumber(IN PVOID ehciExtension)
{
    DPRINT1("EHCI_Get32BitFrameNumber: UNIMPLEMENTED. FIXME\n");
    return 0;
}

VOID
NTAPI
EHCI_InterruptNextSOF(IN PVOID ehciExtension)
{
    DPRINT1("EHCI_InterruptNextSOF: UNIMPLEMENTED. FIXME\n");
}

VOID
NTAPI
EHCI_EnableInterrupts(IN PVOID ehciExtension)
{
    DPRINT1("EHCI_EnableInterrupts: UNIMPLEMENTED. FIXME\n");
}

VOID
NTAPI
EHCI_DisableInterrupts(IN PVOID ehciExtension)
{
    DPRINT1("EHCI_DisableInterrupts: UNIMPLEMENTED. FIXME\n");
}

VOID
NTAPI
EHCI_PollController(IN PVOID ehciExtension)
{
    DPRINT1("EHCI_PollController: UNIMPLEMENTED. FIXME\n");
}

VOID
NTAPI
EHCI_SetEndpointDataToggle(IN PVOID ehciExtension,
                           IN PVOID ehciEndpoint,
                           IN ULONG DataToggle)
{
    DPRINT1("EHCI_SetEndpointDataToggle: UNIMPLEMENTED. FIXME\n");
}

ULONG
NTAPI
EHCI_GetEndpointStatus(IN PVOID ehciExtension,
                       IN PVOID ehciEndpoint)
{
    DPRINT1("EHCI_GetEndpointStatus: UNIMPLEMENTED. FIXME\n");
    return 0;
}

VOID
NTAPI
EHCI_SetEndpointStatus(IN PVOID ehciExtension,
                       IN PVOID ehciEndpoint,
                       IN ULONG EndpointStatus)
{
    DPRINT1("EHCI_SetEndpointStatus: UNIMPLEMENTED. FIXME\n");
}

VOID
NTAPI
EHCI_ResetController(IN PVOID ehciExtension)
{
    DPRINT1("EHCI_ResetController: UNIMPLEMENTED. FIXME\n");
}

MPSTATUS
NTAPI
EHCI_StartSendOnePacket(IN PVOID ehciExtension,
                        IN PVOID PacketParameters,
                        IN PVOID Data,
                        IN PULONG pDataLength,
                        IN PVOID BufferVA,
                        IN PVOID BufferPA,
                        IN ULONG BufferLength,
                        IN USBD_STATUS * pUSBDStatus)
{
    DPRINT1("EHCI_StartSendOnePacket: UNIMPLEMENTED. FIXME\n");
    return 0;
}

MPSTATUS
NTAPI
EHCI_EndSendOnePacket(IN PVOID ehciExtension,
                      IN PVOID PacketParameters,
                      IN PVOID Data,
                      IN PULONG pDataLength,
                      IN PVOID BufferVA,
                      IN PVOID BufferPA,
                      IN ULONG BufferLength,
                      IN USBD_STATUS * pUSBDStatus)
{
    DPRINT1("EHCI_EndSendOnePacket: UNIMPLEMENTED. FIXME\n");
    return 0;
}

MPSTATUS
NTAPI
EHCI_PassThru(IN PVOID ehciExtension,
              IN PVOID passThruParameters,
              IN ULONG ParameterLength,
              IN PVOID pParameters)
{
    DPRINT1("EHCI_PassThru: UNIMPLEMENTED. FIXME\n");
    return 0;
}

VOID
NTAPI
EHCI_RebalanceEndpoint(IN PVOID ohciExtension,
                       IN PVOID endpointParameters,
                       IN PVOID ohciEndpoint)
{
    DPRINT1("EHCI_RebalanceEndpoint: UNIMPLEMENTED. FIXME\n");
}

VOID
NTAPI
EHCI_FlushInterrupts(IN PVOID ohciExtension)
{
    DPRINT1("EHCI_FlushInterrupts: UNIMPLEMENTED. FIXME\n");
}

MPSTATUS
NTAPI
EHCI_RH_ChirpRootPort(IN PVOID ehciExtension,
                      IN USHORT Port)
{
    DPRINT1("EHCI_RH_ChirpRootPort: UNIMPLEMENTED. FIXME\n");
    return 0;
}

VOID
NTAPI
EHCI_TakePortControl(IN PVOID ohciExtension)
{
    DPRINT1("EHCI_TakePortControl: UNIMPLEMENTED. FIXME\n");
}

VOID
NTAPI
EHCI_Unload()
{
    DPRINT1("EHCI_Unload: UNIMPLEMENTED. FIXME\n");
}

NTSTATUS
NTAPI
DriverEntry(IN PDRIVER_OBJECT DriverObject,
            IN PUNICODE_STRING RegistryPath)
{
    DPRINT("DriverEntry: DriverObject - %p, RegistryPath - %wZ\n",
           DriverObject,
           RegistryPath);

    if (USBPORT_GetHciMn() != 0x10000001)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&RegPacket, sizeof(USBPORT_REGISTRATION_PACKET));

    RegPacket.MiniPortVersion = USB_MINIPORT_VERSION_EHCI;

    RegPacket.MiniPortFlags = USB_MINIPORT_FLAGS_INTERRUPT |
                              USB_MINIPORT_FLAGS_MEMORY_IO |
                              USB_MINIPORT_FLAGS_USB2 |
                              USB_MINIPORT_FLAGS_POLLING |
                              USB_MINIPORT_FLAGS_WAKE_SUPPORT;

    RegPacket.MiniPortBusBandwidth = 400000;

    RegPacket.MiniPortExtensionSize = sizeof(EHCI_EXTENSION);
    RegPacket.MiniPortEndpointSize = sizeof(EHCI_ENDPOINT);
    RegPacket.MiniPortTransferSize = sizeof(EHCI_TRANSFER);
    RegPacket.MiniPortResourcesSize = sizeof(EHCI_HC_RESOURCES);

    RegPacket.OpenEndpoint = EHCI_OpenEndpoint;
    RegPacket.ReopenEndpoint = EHCI_ReopenEndpoint;
    RegPacket.QueryEndpointRequirements = EHCI_QueryEndpointRequirements;
    RegPacket.CloseEndpoint = EHCI_CloseEndpoint;
    RegPacket.StartController = EHCI_StartController;
    RegPacket.StopController = EHCI_StopController;
    RegPacket.SuspendController = EHCI_SuspendController;
    RegPacket.ResumeController = EHCI_ResumeController;
    RegPacket.InterruptService = EHCI_InterruptService;
    RegPacket.InterruptDpc = EHCI_InterruptDpc;
    RegPacket.SubmitTransfer = EHCI_SubmitTransfer;
    RegPacket.SubmitIsoTransfer = EHCI_SubmitIsoTransfer;
    RegPacket.AbortTransfer = EHCI_AbortTransfer;
    RegPacket.GetEndpointState = EHCI_GetEndpointState;
    RegPacket.SetEndpointState = EHCI_SetEndpointState;
    RegPacket.PollEndpoint = EHCI_PollEndpoint;
    RegPacket.CheckController = EHCI_CheckController;
    RegPacket.Get32BitFrameNumber = EHCI_Get32BitFrameNumber;
    RegPacket.InterruptNextSOF = EHCI_InterruptNextSOF;
    RegPacket.EnableInterrupts = EHCI_EnableInterrupts;
    RegPacket.DisableInterrupts = EHCI_DisableInterrupts;
    RegPacket.PollController = EHCI_PollController;
    RegPacket.SetEndpointDataToggle = EHCI_SetEndpointDataToggle;
    RegPacket.GetEndpointStatus = EHCI_GetEndpointStatus;
    RegPacket.SetEndpointStatus = EHCI_SetEndpointStatus;
    RegPacket.RH_GetRootHubData = EHCI_RH_GetRootHubData;
    RegPacket.RH_GetStatus = EHCI_RH_GetStatus;
    RegPacket.RH_GetPortStatus = EHCI_RH_GetPortStatus;
    RegPacket.RH_GetHubStatus = EHCI_RH_GetHubStatus;
    RegPacket.RH_SetFeaturePortReset = EHCI_RH_SetFeaturePortReset;
    RegPacket.RH_SetFeaturePortPower = EHCI_RH_SetFeaturePortPower;
    RegPacket.RH_SetFeaturePortEnable = EHCI_RH_SetFeaturePortEnable;
    RegPacket.RH_SetFeaturePortSuspend = EHCI_RH_SetFeaturePortSuspend;
    RegPacket.RH_ClearFeaturePortEnable = EHCI_RH_ClearFeaturePortEnable;
    RegPacket.RH_ClearFeaturePortPower = EHCI_RH_ClearFeaturePortPower;
    RegPacket.RH_ClearFeaturePortSuspend = EHCI_RH_ClearFeaturePortSuspend;
    RegPacket.RH_ClearFeaturePortEnableChange = EHCI_RH_ClearFeaturePortEnableChange;
    RegPacket.RH_ClearFeaturePortConnectChange = EHCI_RH_ClearFeaturePortConnectChange;
    RegPacket.RH_ClearFeaturePortResetChange = EHCI_RH_ClearFeaturePortResetChange;
    RegPacket.RH_ClearFeaturePortSuspendChange = EHCI_RH_ClearFeaturePortSuspendChange;
    RegPacket.RH_ClearFeaturePortOvercurrentChange = EHCI_RH_ClearFeaturePortOvercurrentChange;
    RegPacket.RH_DisableIrq = EHCI_RH_DisableIrq;
    RegPacket.RH_EnableIrq = EHCI_RH_EnableIrq;
    RegPacket.StartSendOnePacket = EHCI_StartSendOnePacket;
    RegPacket.EndSendOnePacket = EHCI_EndSendOnePacket;
    RegPacket.PassThru = EHCI_PassThru;
    RegPacket.RebalanceEndpoint = EHCI_RebalanceEndpoint;
    RegPacket.FlushInterrupts = EHCI_FlushInterrupts;
    RegPacket.RH_ChirpRootPort = EHCI_RH_ChirpRootPort;
    RegPacket.TakePortControl = EHCI_TakePortControl;

    DriverObject->DriverUnload = (PDRIVER_UNLOAD)EHCI_Unload;

    return USBPORT_RegisterUSBPortDriver(DriverObject, 200, &RegPacket);
}
