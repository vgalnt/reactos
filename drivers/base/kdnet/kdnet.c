/*
 * COPYRIGHT:       GPL, see COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            drivers/base/kdnet/kdnet.c
 * PURPOSE:         Functions for the kernel debugger over Net.
 * PROGRAMMER:      
 */

/* NTDDI_WINBLUE */
#include "kdnet.h"

/* GLOBALS ********************************************************************/

ULONG (*DbgPrint0)(_In_ const PCHAR Format, ...);
BOOLEAN IsDbgComInitialized = FALSE;

KDNET_EXTENSIBILITY_EXPORT KdNetExports;
KD_NET_PARAMETERS KdNetParameters;
KD_NIC_DATA KdNicData;

LONG KdNetDebuggerInitialize0Count;
LONG KdNetExtensibilityInitCount;
LONG KdNicSendEntered;

BOOLEAN KdNetInitialized;
BOOLEAN KdNicEnabled = TRUE;

LIST_ENTRY QueuedTxListHead;
NTSTATUS KdNetExtensibilityInitStatus = STATUS_ALREADY_REGISTERED;
NTSTATUS KdNetErrorStatus;
PWSTR KdNetErrorString;
ULONG KdNetHardwareContextSize;
ULONG KdNetHardwareID;

/* PRIVATE FUNCTIONS **********************************************************/

VOID
NTAPI
KdNetNicInitialize(VOID)
{
    KdNicData.Version = 3;
    KdNicData.Size = sizeof(KD_NIC_DATA);

    KdNicData.Reserved0 = 0;
    KdNicData.LinkSpeed1 = 1000;

    KdNicData.Status = STATUS_ADAPTER_HARDWARE_ERROR;

    KdNicData.Reserved1 = 0;
    KdNicData.Reserved2 = 0;

    InitializeSListHead(&KdNicData.sListHead);
    InitializeSListHead(&KdNicData.sListHead1);
    InitializeSListHead(&KdNicData.sListHead2);

    KdNicData.LinkState = 0;
    KdNicData.Reserved3 = 0;
    KdNicData.LinkSpeed2 = 1000;

    InitializeListHead(&QueuedTxListHead);
}

ULONG
NTAPI
KdNetGetPciDataByOffset(
    _In_ ULONG Bus,
    _In_ ULONG Slot,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdNetGetPciDataByOffset: %X, %X, %p, %X, %X\n", Bus, Slot, Buffer, Offset, Length);

    if (IsDbgComInitialized)
        DbgPrint0("KdNetGetPciDataByOffset: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
    return 0;
}

ULONG
NTAPI
KdNetSetPciDataByOffset(
    _In_ ULONG Bus,
    _In_ ULONG Slot,
    _In_ PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdNetSetPciDataByOffset: %X, %X, %p, %X, %X\n", Bus, Slot, Buffer, Offset, Length);

    if (IsDbgComInitialized)
        DbgPrint0("KdNetGetPciDataByOffset: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
    return 0;
}

VOID
NTAPI
KdStallExecutionProcessor(
    _In_ ULONG MicroSeconds)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdStallExecutionProcessor: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
}

VOID
NTAPI
KdNetSetHiberRange(
    _In_ PVOID MemoryMap,
    _In_ ULONG Flags,
    _In_ PVOID Address,
    _In_ ULONG_PTR Length,
    _In_ ULONG Tag)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdNetSetHiberRange: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
}

NTSTATUS
NTAPI
InitializeKdNetExtensibility(
    _In_ PCHAR LoaderOptions,
    _In_ PDEBUG_DEVICE_DESCRIPTOR PciDevice)
{
    if (IsDbgComInitialized)
        DbgPrint0("InitializeKdNetExtensibility: %X, %X\n", LoaderOptions, PciDevice);

    if (InterlockedIncrement(&KdNetExtensibilityInitCount) != 1)
    {
        if (IsDbgComInitialized)
            DbgPrint0("InitializeKdNetExtensibility: exit (KdNetExtensibilityInitCount %X)\n", KdNetExtensibilityInitCount);

        return KdNetExtensibilityInitStatus;
    }

    RtlZeroMemory(&KdNetExports, sizeof(KdNetExports));

    KdNetExports.FunctionCount = 24;

    KdNetExports.GetPciDataByOffset = KdNetGetPciDataByOffset;
    KdNetExports.SetPciDataByOffset = KdNetSetPciDataByOffset;
    KdNetExports.GetPhysicalAddress = MmGetPhysicalAddress;
    KdNetExports.StallExecutionProcessor = KdStallExecutionProcessor;
    KdNetExports.ReadRegisterUChar = READ_REGISTER_UCHAR;
    KdNetExports.ReadRegisterUShort = READ_REGISTER_USHORT;
    KdNetExports.ReadRegisterULong = READ_REGISTER_ULONG;
    KdNetExports.WriteRegisterUChar = WRITE_REGISTER_UCHAR;
    KdNetExports.WriteRegisterUShort = WRITE_REGISTER_USHORT;
    KdNetExports.WriteRegisterULong = WRITE_REGISTER_ULONG;
    KdNetExports.ReadPortUChar = READ_PORT_UCHAR;
    KdNetExports.ReadPortUShort = READ_PORT_USHORT;
    KdNetExports.ReadPortULong = READ_PORT_ULONG;
    KdNetExports.WritePortUChar = WRITE_PORT_UCHAR;
    KdNetExports.WritePortUShort = WRITE_PORT_USHORT;
    KdNetExports.WritePortULong = WRITE_PORT_ULONG;
    KdNetExports._KdNetErrorStatus = &KdNetErrorStatus;
    KdNetExports._KdNetErrorString = &KdNetErrorString;
    KdNetExports._KdNetHardwareID = &KdNetHardwareID;
    KdNetExports.SetHiberRange = KdNetSetHiberRange;

    KdNetExtensibilityInitStatus = KdInitializeLibrary((PVOID)&KdNetExports, LoaderOptions, PciDevice);

    if (IsDbgComInitialized)
        DbgPrint0("InitializeKdNetExtensibility: Status %X\n", KdNetExtensibilityInitStatus);

    return KdNetExtensibilityInitStatus;
}

NTSTATUS
NTAPI
KdNetInitialize(
    _In_ PKD_NET_PARAMETERS NetParameters,
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdNetInitialize: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
}

/* PUBLIC FUNCTIONS ***********************************************************/

NTSTATUS
NTAPI
KdD0Transition(VOID)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdD0Transition: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
KdD3Transition(VOID)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdD3Transition: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
KdDebuggerInitialize0(
    _In_opt_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    PCHAR LoaderOptions;
    PCHAR TargetIp;
    PCHAR HostIp;
    PCHAR Start;
    PCHAR Ptr;
    LARGE_INTEGER Value;
    ULONG ContextSize;
    ULONG _ip;
    BOOLEAN IsDebuggerActive;
    NTSTATUS Status = STATUS_INVALID_PARAMETER;

    if (!IsDbgComInitialized)
    {
        if (LoaderBlock->u.I386.CommonDataArea)
        {
            DbgPrint0 = LoaderBlock->u.I386.CommonDataArea;
            IsDbgComInitialized = TRUE;
        }
    }

    if (IsDbgComInitialized)
        DbgPrint0("KdDebuggerInitialize0: LoaderBlock %p\n", LoaderBlock);

    InterlockedIncrement(&KdNetDebuggerInitialize0Count);

    //InitializeLogTiming(); // for USB3

    if (!KdNetInitialized)
    {
        KdNetNicInitialize();

        KdNetParameters.IsDebuggerActive = FALSE;
        KdNetParameters.IsEncryptionKey = FALSE;
        KdNetParameters.IsDhcp = TRUE;
        KdNetParameters.IsVerifyHostMac = FALSE;
        KdNetParameters.IsSendKdStatus = FALSE;

        KdNetParameters.HostPort2 = 0x14F4; // (5364)
        KdNetParameters.DebuggeePort = 0x14F4;

        RtlZeroMemory(&KdNetParameters, sizeof(KdNetParameters.PciDevice));

        KdNetParameters.PciDevice.Bus = 0xFFFFFFFF;
        KdNetParameters.PciDevice.Slot = 0xFFFFFFFF;
        KdNetParameters.PciDevice.Configured = 0;
        KdNetParameters.PciDevice.VendorID = 0xFFFF;
        KdNetParameters.PciDevice.DeviceID = 0xFFFF;
        KdNetParameters.PciDevice.BaseClass = 2;
        KdNetParameters.PciDevice.SubClass = 0;
        KdNetParameters.PciDevice.ProgIf = 0xFF;
        KdNetParameters.PciDevice.Segment = 0xFFFF;
    }

    if (!LoaderBlock)
    {
        IsDebuggerActive = FALSE;
        KdNetParameters.IsDebuggerActive = FALSE;

        KdNicSendEntered = 0;

        if (KdNetInitialized)
            goto NetInitializing;
    }

    LoaderOptions = LoaderBlock->LoadOptions;

    Status = InitializeKdNetExtensibility(LoaderOptions, &KdNetParameters.PciDevice);
    if (!NT_SUCCESS(Status))
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdDebuggerInitialize0: InitializeKdNetExtensibility() ret %X\n", Status);

        KdNetErrorString = L"Kdnet extensibility initialization failed.";
        goto Exit;
    }

    KdNetHardwareContextSize = 0x70600;

    if (KdNetParameters.PciDevice.Memory.Length)
    {
        if (KdNetParameters.PciDevice.Memory.Length > 0x70600)
        {
            KdNetHardwareContextSize = KdNetParameters.PciDevice.Memory.Length;

            if (KdNetParameters.PciDevice.Memory.Length > 0x1000000)
            {
                if (IsDbgComInitialized)
                    DbgPrint0("KdDebuggerInitialize0: Requested too much memory (%X)\n", KdNetParameters.PciDevice.Memory.Length);

                KdNetErrorString = L"Kdnet extensibility module requested too much memory.";
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto Exit;
            }
        }
    }

    ContextSize = KdNetHardwareContextSize;

  #if 0
    // FIXME
    if (KdHvDetectHypervisor())
    {
        if (KdHvGetDebugDeviceOptions() & 4)
        {
        }
        else if (KdHvUseSyntheticDebugging())
        {
        }
    }
  #endif

    KdNetHardwareContextSize = ROUND_TO_PAGES(ContextSize);

  #if 0
    // FIXME
    LOADER_PARAMETER_EXTENSION* Extension LoaderBlockExtension;
    UCHAR RngBytesForNtoskrnl[1024];
  #endif

    if (!LoaderOptions)
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdDebuggerInitialize0: No OS loadoptions string was passed to kdnet.(%X)\n", Status);

        KdNetErrorString = L"No OS loadoptions string was passed to kdnet.";

        if (NT_SUCCESS(Status))
            return Status;

        goto Exit;
    }

    /* Parse options */
    _strupr(LoaderOptions);

    Ptr = strstr(LoaderOptions, "HOST_IP");
    if (Ptr)
    {
        for (HostIp = (Ptr + 7); ; HostIp++)
        {
            Ptr = HostIp;

            if (*HostIp != ' ')
                break;
        }

        if (IsDbgComInitialized)
           DbgPrint0("KdDebuggerInitialize0: HOST_IP '%s'\n", (HostIp + 1));

        if (*HostIp)
        {
            _ip = ((UCHAR)strtoull((HostIp + 1), &Ptr, 10) << 24);
            KdNetParameters.HostIp2 = _ip;

            HostIp = Ptr;
        }
        else
        {
            _ip = KdNetParameters.HostIp2;
        }

        if (*HostIp == '.')
        {
            _ip = (((UCHAR)strtoull((HostIp + 1), &Ptr, 10) << 16) | KdNetParameters.HostIp2);
            KdNetParameters.HostIp2 = _ip;

            if (*Ptr == '.')
            {
                _ip = (((UCHAR)strtoull((Ptr + 1), &Ptr, 10) << 8) | KdNetParameters.HostIp2);
                KdNetParameters.HostIp2 = _ip;

                if (*Ptr == '.')
                {
                    _ip = ((UCHAR)strtoull((Ptr + 1), &Ptr, 10) | KdNetParameters.HostIp2);
                    KdNetParameters.HostIp2 = _ip;
                }
            }
        }

        KdNetParameters.HostIp1 = _ip;

        if (IsDbgComInitialized)
           DbgPrint0("KdDebuggerInitialize0: HostIp1 %X, HostIp2 %X\n", KdNetParameters.HostIp1, KdNetParameters.HostIp2);
    }

    Ptr = strstr(LoaderOptions, "SEND_KD_STATUS");
    if (Ptr)
        KdNetParameters.IsSendKdStatus = TRUE;

    Ptr = strstr(LoaderOptions, "NO_KDNIC");
    if (Ptr)
        KdNicEnabled = FALSE;

    Ptr = strstr(LoaderOptions, "NO_DHCP");
    if (Ptr)
        KdNetParameters.IsDhcp = FALSE;

    Ptr = strstr(LoaderOptions, "VERIFY_HOST_MAC");
    if (Ptr)
        KdNetParameters.IsVerifyHostMac = TRUE;

    Value.QuadPart = 0;

    Ptr = strstr(LoaderOptions, "ENCRYPTION_KEY");
    if (Ptr)
    {
        KdNetParameters.IsEncryptionKey = TRUE;

        for (Start = (Ptr + 0xE); ; Start++)
        {
            Ptr = Start;

            if (*Start != ' ')
                break;
        }

        if (*Start != '=')
        {
            if (IsDbgComInitialized)
                DbgPrint0("KdDebuggerInitialize0: Status %X\n", Status);

            KdNetErrorString = L"No kdnet encryption key was specified in the OS loadoptions string.";

            if (NT_SUCCESS(Status))
                return Status;

            goto Exit;
        }

      #if 0
        // FIXME
      #endif
    }

    if (!KdNetParameters.IsEncryptionKey || !Value.QuadPart)
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdDebuggerInitialize0: No kdnet encryption key was specified in the OS loadoptions string.(%X)\n", Status);

        KdNetErrorString = L"No kdnet encryption key was specified in the OS loadoptions string.";

        if (NT_SUCCESS(Status))
            return Status;

        goto Exit;
    }

  #if 0
    // FIXME
  #endif

    if (KdNetParameters.IsDhcp && !KdNetParameters.IsEncryptionKey)
       KdNetParameters.IsDhcp = FALSE;

    Ptr = strstr(LoaderOptions, "TARGET_IP");
    if (Ptr)
    {
        for (TargetIp = (Ptr + 9); ; TargetIp++)
        {
            Ptr = TargetIp;

            if (*TargetIp != ' ')
                break;
        }

        if (IsDbgComInitialized)
           DbgPrint0("KdDebuggerInitialize0: TARGET_IP '%s'\n", TargetIp + 1);

        if (*TargetIp)
        {
            _ip = ((UCHAR)strtoull((TargetIp + 1), &Ptr, 10) << 24);
            KdNetParameters.DebuggeeIp = _ip;

            TargetIp = Ptr;
        }
        else
        {
            _ip = KdNetParameters.DebuggeeIp;
        }

        if (*TargetIp == '.')
        {
            _ip = (((UCHAR)strtoull((TargetIp + 1), &Ptr, 10) << 16) | KdNetParameters.DebuggeeIp);
            KdNetParameters.DebuggeeIp = _ip;

            if (*Ptr == '.')
            {
                _ip = (((UCHAR)strtoull((Ptr + 1), &Ptr, 10) << 8) | KdNetParameters.DebuggeeIp);
                KdNetParameters.DebuggeeIp = _ip;

                if (*Ptr == '.')
                {
                    _ip = ((UCHAR)strtoull((Ptr + 1), &Ptr, 10) | KdNetParameters.DebuggeeIp);
                    KdNetParameters.DebuggeeIp = _ip;
                }
            }

            if (IsDbgComInitialized)
               DbgPrint0("KdDebuggerInitialize0: DebuggeeIp %X\n", KdNetParameters.DebuggeeIp);
        }
    }
    else
    {
        if (IsDbgComInitialized)
           DbgPrint0("KdDebuggerInitialize0: DebuggeeIp %X\n", KdNetParameters.DebuggeeIp);

        _ip = KdNetParameters.DebuggeeIp;
    }

    if (_ip && ((_ip & 0xFFFF0000) != 0xA9FE0000) && !KdNetParameters.IsEncryptionKey)
    {
        if (IsDbgComInitialized)
           DbgPrint0("KdDebuggerInitialize0: DebuggeeIp is 0\n");

        KdNetParameters.DebuggeeIp = 0;
    }

    if (strstr(LoaderOptions, "BUSPARAMS"))
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdDebuggerInitialize0: BUSPARAMS Unimplemented! KeBugCheck\n");

        //KeBugCheck(MANUALLY_INITIATED_CRASH);
        //return STATUS_NOT_IMPLEMENTED;
    }

    KdNetInitialized = TRUE;

    IsDebuggerActive = KdNetParameters.IsDebuggerActive;

NetInitializing:

    if (IsDebuggerActive)
    {
        if (IsDbgComInitialized)
            DbgPrint0("KdDebuggerInitialize0: Debugger is active\n");

        return STATUS_SUCCESS;
    }

    Status = KdNetInitialize(&KdNetParameters, LoaderBlock);

    if (IsDbgComInitialized)
        DbgPrint0("KdDebuggerInitialize0: (1) Status %X\n", Status);

    if (LoaderBlock &&
        Status == STATUS_ADAPTER_HARDWARE_ERROR &&
        KdNetParameters.PciDevice.VendorID != 0xFFFD &&
        KdNetParameters.PciDevice.VendorID != 0xFFFC)
    {
        KdNetParameters.PciDevice.Bus = 0xFFFFFFFF;
        KdNetParameters.PciDevice.Slot = 0xFFFFFFFF;
        KdNetParameters.PciDevice.Segment = 0xFFFF;
        KdNetParameters.PciDevice.VendorID = 0xFFFF;
        KdNetParameters.PciDevice.DeviceID = 0xFFFF;
        KdNetParameters.PciDevice.BaseClass = 0x0C;
        KdNetParameters.PciDevice.SubClass = 0x03;
        KdNetParameters.PciDevice.ProgIf = 0xFF;
        KdNetParameters.PciDevice.Flags = 0xFF;
        KdNetParameters.PciDevice.Initialized = 0;
        KdNetParameters.PciDevice.Configured = 0;
        KdNetParameters.PciDevice.PortType = 0x8002;
        KdNetParameters.PciDevice.PortSubtype = 0xFFFF;
        KdNetParameters.PciDevice.NameSpace = 2;
        KdNetParameters.PciDevice.NameSpacePathLength = 0xFFFFFFFF;

        Status = KdNetInitialize(&KdNetParameters, LoaderBlock);
    }

    KdNetParameters.IsDebuggerActive = (NT_SUCCESS(Status));

    if (NT_SUCCESS(Status))
        return Status;

    if (IsDbgComInitialized)
        DbgPrint0("KdDebuggerInitialize0: (2) Status %X\n", Status);

Exit:

    if (!KdNetErrorStatus)
        KdNetErrorStatus = Status;

    return Status;
}

NTSTATUS
NTAPI
KdDebuggerInitialize1(
    _In_opt_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdDebuggerInitialize1: Unimplemented! LoaderBlock %p\n", LoaderBlock);

    KeBugCheck(MANUALLY_INITIATED_CRASH);
    return STATUS_NOT_IMPLEMENTED;
}

KDP_STATUS
NTAPI
KdReceivePacket(
    _In_ ULONG PacketType,
    _Out_ PSTRING MessageHeader,
    _Out_ PSTRING MessageData,
    _Out_ ULONG* OutDataLength,
    _Inout_ PKD_CONTEXT KdContext)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdReceivePacket: %X, %p, %p\n", PacketType, MessageHeader, MessageData);

    KeBugCheck(MANUALLY_INITIATED_CRASH);
    return 0;
}

NTSTATUS
NTAPI
KdRestore(
    _In_ BOOLEAN SleepTransition)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdRestore: SleepTransition %x\n", SleepTransition);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdSave(
    _In_ BOOLEAN SleepTransition)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdSave: SleepTransition %x\n", SleepTransition);
    return STATUS_SUCCESS;
}

VOID
NTAPI
KdSendPacket(
    _In_ ULONG PacketType,
    _In_ PSTRING MessageHeader,
    _In_ PSTRING MessageData,
    _Inout_ PKD_CONTEXT KdContext)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdSendPacket: %X, %p, %p\n", PacketType, MessageHeader, MessageData);
    KeBugCheck(MANUALLY_INITIATED_CRASH);
}

NTSTATUS
NTAPI
KdSetHiberRange(VOID)
{
    if (IsDbgComInitialized)
        DbgPrint0("KdD0Transition: Unimplemented!\n");

    KeBugCheck(MANUALLY_INITIATED_CRASH);
    return STATUS_NOT_IMPLEMENTED;
}

/* EOF */
