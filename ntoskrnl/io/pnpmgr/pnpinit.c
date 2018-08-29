/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            ntoskrnl/io/pnpmgr/pnpinit.c
 * PURPOSE:         PnP Initialization Code
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "../pnpio.h"

//#define NDEBUG
#include <debug.h>

#include "../mm/ARM3/miarm.h"

/* GLOBALS ********************************************************************/

PNP_ALLOCATE_RESOURCES_ROUTINE IopAllocateBootResourcesRoutine;

PUNICODE_STRING PiInitGroupOrderTable;
USHORT PiInitGroupOrderTableCount;
INTERFACE_TYPE PnpDefaultInterfaceType;

PCM_RESOURCE_LIST IopInitHalResources;
extern PPHYSICAL_MEMORY_DESCRIPTOR MmPhysicalMemoryBlock;
PPNP_RESERVED_RESOURCES_CONTEXT IopInitReservedResourceList = NULL;
LIST_ENTRY IopLegacyBusInformationTable[MaximumInterfaceType];

ARBITER_INSTANCE IopRootBusNumberArbiter;
ARBITER_INSTANCE IopRootIrqArbiter;
ARBITER_INSTANCE IopRootDmaArbiter;
ARBITER_INSTANCE IopRootMemArbiter;
ARBITER_INSTANCE IopRootPortArbiter;

PDEVICE_NODE IopRootDeviceNode = NULL;
LONG IopNumberDeviceNodes = 0;
ULONG IopMaxDeviceNodeLevel = 0; 

KSPIN_LOCK IopPnPSpinLock;
LIST_ENTRY IopPnpEnumerationRequestList;
extern KEVENT PiEnumerationLock;
ERESOURCE PiEngineLock;
ERESOURCE PiDeviceTreeLock;

KSEMAPHORE PpRegistrySemaphore;

BOOLEAN PnPBootDriversLoaded = FALSE;
BOOLEAN PnPBootDriversInitialized = FALSE;
BOOLEAN IopBootConfigsReserved = FALSE;

BOOLEAN PpDisableFirmwareMapper = FALSE;
BOOLEAN PiCriticalDeviceDatabaseEnabled = TRUE;

/* FUNCTIONS ******************************************************************/

VOID
NTAPI
IopInitializeResourceMap(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    PCM_RESOURCE_LIST CmResources;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialDesc;
    PPHYSICAL_MEMORY_DESCRIPTOR MemoryDescriptor;
    UNICODE_STRING ResourceName;
    UNICODE_STRING ValueName;
    UNICODE_STRING DescriptionName;
    HANDLE ResourceMapHandle;
    ULONG Runs;
    ULONG Size;
    ULONG Type;
    ULONG ix;
    UNICODE_STRING ResourceMapName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\HARDWARE\\RESOURCEMAP");
    NTSTATUS Status;
    BOOLEAN IncludeType[LoaderMaximum];

    DPRINT("IopInitializeResourceMap: LoaderBlock - %p\n", LoaderBlock);

    RtlInitUnicodeString(&ResourceName, L"System Resources");

    for (Type = 0; Type < 3; Type++)
    {
        if (Type == 0)
        {
            RtlInitUnicodeString(&DescriptionName, L"Physical Memory");
            RtlInitUnicodeString(&ValueName, L".Translated");

            MemoryDescriptor = MmPhysicalMemoryBlock;
        }
        else if (Type == 1)
        {
            RtlInitUnicodeString(&DescriptionName, L"Reserved");
            RtlInitUnicodeString(&ValueName, L".Translated");

            RtlZeroMemory(IncludeType, sizeof(IncludeType));

            IncludeType[LoaderSpecialMemory] = TRUE;
            IncludeType[LoaderHALCachedMemory] = TRUE;

            MemoryDescriptor = MmInitializeMemoryLimits(LoaderBlock, IncludeType);

            if (!MemoryDescriptor)
            {
                continue;
            }
        }
        else
        {
            RtlInitUnicodeString(&DescriptionName, L"Loader Reserved");
            RtlInitUnicodeString(&ValueName, L".Raw");

            RtlZeroMemory(IncludeType, sizeof(IncludeType));

            IncludeType[LoaderBad] = TRUE;
            IncludeType[LoaderFirmwarePermanent] = TRUE;
            IncludeType[LoaderSpecialMemory] = TRUE;
            IncludeType[LoaderBBTMemory] = TRUE;
            IncludeType[LoaderHALCachedMemory] = TRUE;

            MemoryDescriptor = MmInitializeMemoryLimits(LoaderBlock, IncludeType);

            if (!MemoryDescriptor)
            {
                return;
            }
        }

        Runs = MemoryDescriptor->NumberOfRuns;

        if (!Runs)
        {
            if (Type != 0)
            {
                ExFreePoolWithTag(MemoryDescriptor, 'lMmM');
            }
            continue;
        }

        Size = sizeof(CM_RESOURCE_LIST) +
               sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) * (Runs - 1);

        CmResources = ExAllocatePoolWithTag(PagedPool, Size, '  pP');

        if (!CmResources)
        {
            if (Type != 0)
            {
                ExFreePoolWithTag(MemoryDescriptor, 'lMmM');
            }
            return;
        }

        RtlZeroMemory(CmResources, Size);

        CmResources->Count = 1;
        CmResources->List[0].PartialResourceList.Count = Runs;

        PartialDesc = CmResources->List[0].PartialResourceList.PartialDescriptors;

        for (ix = 0; ix < Runs; ix++, PartialDesc++)
        {
            PartialDesc->Type = CmResourceTypeMemory;
            PartialDesc->ShareDisposition = CmResourceShareDeviceExclusive;

            PartialDesc->u.Memory.Start.QuadPart = MemoryDescriptor->Run[ix].BasePage;
            PartialDesc->u.Memory.Start.QuadPart <<= PAGE_SHIFT;
            PartialDesc->u.Memory.Length = MemoryDescriptor->Run[ix].PageCount;
            PartialDesc->u.Memory.Length <<= PAGE_SHIFT;
        }

        Status = IopCreateRegistryKeyEx(&ResourceMapHandle,
                                        NULL,
                                        &ResourceMapName,
                                        KEY_READ | KEY_WRITE,
                                        REG_OPTION_VOLATILE,
                                        NULL);

        if (NT_SUCCESS(Status))
        {
            IopDumpCmResourceList(CmResources);

            IopWriteResourceList(ResourceMapHandle,
                                 &ResourceName,
                                 &DescriptionName,
                                 &ValueName,
                                 CmResources,
                                 Size);

            ZwClose(ResourceMapHandle);
        }

        ExFreePoolWithTag(CmResources, '  pP');

        if (Type != 0)
        {
            ExFreePoolWithTag(MemoryDescriptor, 'lMmM');
        }
    }
}

INTERFACE_TYPE
NTAPI
IopDetermineDefaultInterfaceType(VOID)
{
    /* FIXME: ReactOS doesn't support MicroChannel yet */
    return Isa;
}

NTSTATUS
NTAPI
IopInitializeArbiters(VOID)
{
    NTSTATUS Status;

    Status = IopPortInitialize();

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = IopMemInitialize();

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = IopDmaInitialize();

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = IopIrqInitialize();

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    return IopBusNumberInitialize();
}

NTSTATUS
NTAPI
INIT_FUNCTION
PiInitCacheGroupInformation(VOID)
{
    HANDLE KeyHandle;
    NTSTATUS Status;
    PKEY_VALUE_FULL_INFORMATION KeyValueInformation;
    PUNICODE_STRING GroupTable;
    ULONG Count;
    UNICODE_STRING GroupString =
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet"
                            L"\\Control\\ServiceGroupOrder");

    /* Open the registry key */
    Status = IopOpenRegistryKeyEx(&KeyHandle,
                                  NULL,
                                  &GroupString,
                                  KEY_READ);
    if (NT_SUCCESS(Status))
    {
        /* Get the list */
        Status = IopGetRegistryValue(KeyHandle, L"List", &KeyValueInformation);
        ZwClose(KeyHandle);

        /* Make sure we got it */
        if (NT_SUCCESS(Status))
        {
            /* Make sure it's valid */
            if ((KeyValueInformation->Type == REG_MULTI_SZ) &&
                (KeyValueInformation->DataLength))
            {
                /* Convert it to unicode strings */
                Status = PnpRegMultiSzToUnicodeStrings(KeyValueInformation,
                                                       &GroupTable,
                                                       &Count);

                /* Cache it for later */
                if (NT_SUCCESS(Status))
                {
                    PiInitGroupOrderTable = GroupTable;
                    PiInitGroupOrderTableCount = (USHORT)Count;
                }
                else
                {
                    DPRINT1("PiInitCacheGroupInformation: Status - %p\n", Status);
                    PiInitGroupOrderTable = NULL;
                    PiInitGroupOrderTableCount = 0;
                }
            }
            else
            {
                /* Fail */
                Status = STATUS_UNSUCCESSFUL;
            }

            /* Free the information */
            ExFreePool(KeyValueInformation);
        }
    }

    /* Return status */
    return Status;
}

USHORT
NTAPI
PpInitGetGroupOrderIndex(IN HANDLE ServiceHandle)
{
    NTSTATUS Status;
    PKEY_VALUE_FULL_INFORMATION KeyValueInformation;
    USHORT i;
    PVOID Buffer;
    UNICODE_STRING Group;
    PAGED_CODE();

    /* Make sure we have a cache */
    if (!PiInitGroupOrderTable) return -1;

    /* If we don't have a handle, the rest is easy -- return the count */
    if (!ServiceHandle) return PiInitGroupOrderTableCount + 1;

    /* Otherwise, get the group value */
    Status = IopGetRegistryValue(ServiceHandle, L"Group", &KeyValueInformation);
    if (!NT_SUCCESS(Status)) return PiInitGroupOrderTableCount;

    /* Make sure we have a valid string */
    ASSERT(KeyValueInformation->Type == REG_SZ);
    ASSERT(KeyValueInformation->DataLength);

    /* Convert to unicode string */
    Buffer = (PVOID)((ULONG_PTR)KeyValueInformation + KeyValueInformation->DataOffset);
    PnpRegSzToString(Buffer, KeyValueInformation->DataLength, &Group.Length);
    Group.MaximumLength = (USHORT)KeyValueInformation->DataLength;
    Group.Buffer = Buffer;

    /* Loop the groups */
    for (i = 0; i < PiInitGroupOrderTableCount; i++)
    {
        /* Try to find a match */
        if (RtlEqualUnicodeString(&Group, &PiInitGroupOrderTable[i], TRUE)) break;
    }

    /* We're done */
    ExFreePool(KeyValueInformation);
    return i;
}

USHORT
NTAPI
PipGetDriverTagPriority(IN HANDLE ServiceHandle)
{
    NTSTATUS Status;
    HANDLE KeyHandle = NULL;
    PKEY_VALUE_FULL_INFORMATION KeyValueInformation = NULL;
    PKEY_VALUE_FULL_INFORMATION KeyValueInformationTag;
    PKEY_VALUE_FULL_INFORMATION KeyValueInformationGroupOrderList;
    PVOID Buffer;
    UNICODE_STRING Group;
    PULONG GroupOrder;
    ULONG Count, Tag = 0;
    USHORT i = -1;
    UNICODE_STRING GroupString =
    RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet"
                        L"\\Control\\ServiceGroupOrder");

    /* Open the key */
    Status = IopOpenRegistryKeyEx(&KeyHandle, NULL, &GroupString, KEY_READ);
    if (!NT_SUCCESS(Status)) goto Quickie;

    /* Read the group */
    Status = IopGetRegistryValue(ServiceHandle, L"Group", &KeyValueInformation);
    if (!NT_SUCCESS(Status)) goto Quickie;

    /* Make sure we have a group */
    if ((KeyValueInformation->Type == REG_SZ) &&
        (KeyValueInformation->DataLength))
    {
        /* Convert to unicode string */
        Buffer = (PVOID)((ULONG_PTR)KeyValueInformation + KeyValueInformation->DataOffset);
        PnpRegSzToString(Buffer, KeyValueInformation->DataLength, &Group.Length);
        Group.MaximumLength = (USHORT)KeyValueInformation->DataLength;
        Group.Buffer = Buffer;
    }

    /* Now read the tag */
    Status = IopGetRegistryValue(ServiceHandle, L"Tag", &KeyValueInformationTag);
    if (!NT_SUCCESS(Status)) goto Quickie;

    /* Make sure we have a tag */
    if ((KeyValueInformationTag->Type == REG_DWORD) &&
        (KeyValueInformationTag->DataLength))
    {
        /* Read it */
        Tag = *(PULONG)((ULONG_PTR)KeyValueInformationTag +
                        KeyValueInformationTag->DataOffset);
    }

    /* We can get rid of this now */
    ExFreePool(KeyValueInformationTag);

    /* Now let's read the group's tag order */
    Status = IopGetRegistryValue(KeyHandle,
                                 Group.Buffer,
                                 &KeyValueInformationGroupOrderList);

    /* We can get rid of this now */
Quickie:
    if (KeyValueInformation) ExFreePool(KeyValueInformation);
    if (KeyHandle) NtClose(KeyHandle);
    if (!NT_SUCCESS(Status)) return -1;

    /* We're on the success path -- validate the tag order*/
    if ((KeyValueInformationGroupOrderList->Type == REG_BINARY) &&
        (KeyValueInformationGroupOrderList->DataLength))
    {
        /* Get the order array */
        GroupOrder = (PULONG)((ULONG_PTR)KeyValueInformationGroupOrderList +
                              KeyValueInformationGroupOrderList->DataOffset);

        /* Get the count */
        Count = *GroupOrder;
        ASSERT(((Count + 1) * sizeof(ULONG)) <=
               KeyValueInformationGroupOrderList->DataLength);

        /* Now loop each tag */
        GroupOrder++;
        for (i = 1; i <= Count; i++)
        {
            /* If we found it, we're out */
            if (Tag == *GroupOrder) break;

            /* Try the next one */
            GroupOrder++;
        }
    }

    /* Last buffer to free */
    ExFreePool(KeyValueInformationGroupOrderList);
    return i;
}

NTSTATUS
NTAPI
INIT_FUNCTION
IopInitializePlugPlayServices(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock,
    _In_ ULONG Phase)
{
    NTSTATUS Status;
    ULONG Disposition;
    HANDLE KeyHandle, EnumHandle, ParentHandle, TreeHandle, ControlHandle;
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET");
    UNICODE_STRING PnpManagerDriverName = RTL_CONSTANT_STRING(DRIVER_ROOT_NAME L"PnpManager");
    PDEVICE_OBJECT Pdo;
    ULONG ix;

    if (Phase != 0 && Phase != 1)
    {
        DPRINT1("IopInitializePlugPlayServices: Phase - %X\n", Phase);
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Phase == 1)
    {
        DPRINT1("IopInitializePlugPlayServices: Phase - %X\n", Phase);

        MapperProcessFirmwareTree(PpDisableFirmwareMapper);
        MapperConstructRootEnumTree(PpDisableFirmwareMapper);

        DPRINT("IopInitializePlugPlayServices: FIXME PnPBiosMapper\n");
        DPRINT("IopInitializePlugPlayServices: FIXME MapperPhantomizeDetectedComPorts\n");
        DPRINT("IopInitializePlugPlayServices: FIXME EisaBuildEisaDeviceNode\n");

        MapperFreeList();

        PipRequestDeviceAction(IopRootDeviceNode->PhysicalDeviceObject,
                               PipEnumRootDevices,
                               0,
                               0,
                               NULL,
                               NULL);
        return Status;
    }

    /* Initialize locks and such */
    KeInitializeSpinLock(&IopPnPSpinLock);
    KeInitializeSpinLock(&IopDeviceTreeLock);
    KeInitializeSpinLock(&IopDeviceActionLock);
    InitializeListHead(&IopDeviceActionRequestList);
    InitializeListHead(&IopPnpEnumerationRequestList);
    KeInitializeEvent(&PiEnumerationLock, NotificationEvent, TRUE);
    ExInitializeResourceLite(&PiEngineLock);
    ExInitializeResourceLite(&PiDeviceTreeLock);
    KeInitializeSemaphore(&PpRegistrySemaphore, 1, 1);

    for (ix = Internal; ix < MaximumInterfaceType; ix++)
    {
        InitializeListHead(&IopLegacyBusInformationTable[ix]);
    }

    IopAllocateBootResourcesRoutine = IopReportBootResources;

    /* Get the default interface */
    PnpDefaultInterfaceType = IopDetermineDefaultInterfaceType();

    /* Setup the group cache */
    Status = PiInitCacheGroupInformation();
    if (!NT_SUCCESS(Status)) return Status;

    /* Initialize memory resources */
    IopInitializeResourceMap(LoaderBlock);

    /* Initialize arbiters */
    Status = IopInitializeArbiters();
    if (!NT_SUCCESS(Status)) return Status;

    /* Open the current control set */
    Status = IopOpenRegistryKeyEx(&KeyHandle,
                                  NULL,
                                  &KeyName,
                                  KEY_ALL_ACCESS);
    if (!NT_SUCCESS(Status)) return Status;

    /* !!! Test the control key */
    RtlInitUnicodeString(&KeyName, L"Control");
    Status = IopOpenRegistryKeyEx(&ControlHandle,
                                  KeyHandle,
                                  &KeyName,
                                  KEY_ALL_ACCESS);
    if (!NT_SUCCESS(Status))
    {
        ASSERT(FALSE);
        return Status;
    }

    /* Create the enum key */
    RtlInitUnicodeString(&KeyName, REGSTR_KEY_ENUM);
    Status = IopCreateRegistryKeyEx(&EnumHandle,
                                    KeyHandle,
                                    &KeyName,
                                    KEY_ALL_ACCESS,
                                    REG_OPTION_NON_VOLATILE,
                                    &Disposition);
    if (!NT_SUCCESS(Status)) return Status;

    /* Check if it's a new key */
    if (Disposition == REG_CREATED_NEW_KEY)
    {
        /* FIXME: DACLs */
    }

    /* Create the root key */
    ParentHandle = EnumHandle;
    RtlInitUnicodeString(&KeyName, REGSTR_KEY_ROOTENUM);
    Status = IopCreateRegistryKeyEx(&EnumHandle,
                                    ParentHandle,
                                    &KeyName,
                                    KEY_ALL_ACCESS,
                                    REG_OPTION_NON_VOLATILE,
                                    &Disposition);
    NtClose(ParentHandle);
    if (!NT_SUCCESS(Status)) return Status;
    NtClose(EnumHandle);

    /* Open the root key now */
    RtlInitUnicodeString(&KeyName, L"\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\ENUM");
    Status = IopOpenRegistryKeyEx(&EnumHandle,
                                  NULL,
                                  &KeyName,
                                  KEY_ALL_ACCESS);
    if (NT_SUCCESS(Status))
    {
        /* Create the root dev node */
        RtlInitUnicodeString(&KeyName, REGSTR_VAL_ROOT_DEVNODE);
        Status = IopCreateRegistryKeyEx(&TreeHandle,
                                        EnumHandle,
                                        &KeyName,
                                        KEY_ALL_ACCESS,
                                        REG_OPTION_NON_VOLATILE,
                                        NULL);
        NtClose(EnumHandle);
        if (NT_SUCCESS(Status)) NtClose(TreeHandle);
    }

    /* Create the root driver */
    Status = IoCreateDriver(&PnpManagerDriverName, PnpRootDriverEntry);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IoCreateDriverObject() failed\n");
        KeBugCheckEx(PHASE1_INITIALIZATION_FAILED, Status, 0, 0, 0);
    }

    /* Create the root PDO */
    Status = IoCreateDevice(IopRootDriverObject,
                            sizeof(IOPNP_DEVICE_EXTENSION),
                            NULL,
                            FILE_DEVICE_CONTROLLER,
                            0,
                            FALSE,
                            &Pdo);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IoCreateDevice() failed\n");
        KeBugCheckEx(PHASE1_INITIALIZATION_FAILED, Status, 0, 0, 0);
    }

    /* This is a bus enumerated device */
    Pdo->Flags |= DO_BUS_ENUMERATED_DEVICE;

    /* Create the root device node */
    IopRootDeviceNode = PipAllocateDeviceNode(Pdo);
    if (!IopRootDeviceNode)
    {
        DPRINT1("PipAllocateDeviceNode() failed\n");
        KeBugCheckEx(PHASE1_INITIALIZATION_FAILED, Status, 0, 0, 0);
    }

    /* Set flags */
    IopRootDeviceNode->Flags |= DNF_MADEUP +
                                DNF_ENUMERATED +
                                DNF_IDS_QUERIED +
                                DNF_NO_RESOURCE_REQUIRED;

    /* Create instance path */
    RtlCreateUnicodeString(&IopRootDeviceNode->InstancePath,
                           REGSTR_VAL_ROOT_DEVNODE);

    Status = IopMapDeviceObjectToDeviceInstance(IopRootDeviceNode->PhysicalDeviceObject,
                                                &IopRootDeviceNode->InstancePath);
    if (!NT_SUCCESS(Status)) return Status;

    PipSetDevNodeState(IopRootDeviceNode, DeviceNodeStarted, NULL);

    /* Initialize PnP-Event notification support */
    Status = IopInitPlugPlayEvents();
    if (!NT_SUCCESS(Status)) return Status;

    /* Report the device to the user-mode pnp manager */
    IopQueueTargetDeviceEvent(&GUID_DEVICE_ARRIVAL,
                              &IopRootDeviceNode->InstancePath);

    /* Initialize the Bus Type GUID List */
    PnpBusTypeGuidList = ExAllocatePool(PagedPool, sizeof(IO_BUS_TYPE_GUID_LIST));
    RtlZeroMemory(PnpBusTypeGuidList, sizeof(IO_BUS_TYPE_GUID_LIST));
    ExInitializeFastMutex(&PnpBusTypeGuidList->Lock);

    PipRequestDeviceAction(IopRootDeviceNode->PhysicalDeviceObject,
                           PipEnumRootDevices,
                           0,
                           0,
                           NULL,
                           NULL);

    /* Close the handle to the control set */
    NtClose(KeyHandle);

    /* We made it */
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopInitializeAttributesAndCreateObject(
    _In_ PUNICODE_STRING ObjectName,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PVOID * OutObject)
{
    PDRIVER_OBJECT DriverObject;
    SIZE_T ObjectSize;
    NTSTATUS Status;

    ObjectSize = sizeof(DRIVER_OBJECT) + sizeof(EXTENDED_DRIVER_EXTENSION);

    InitializeObjectAttributes(ObjectAttributes,
                               ObjectName,
                               OBJ_PERMANENT | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);
 
    /* Create the Object */
    Status = ObCreateObject(KernelMode,
                            IoDriverObjectType,
                            ObjectAttributes,
                            KernelMode,
                            NULL,
                            ObjectSize,
                            0,
                            0,
                            (PVOID *)&DriverObject);

    *OutObject = DriverObject;

    return Status;
}

BOOLEAN
FASTCALL
INIT_FUNCTION
IopInitializeBootDrivers(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    DPRINT("IopInitializeBootDrivers: LoaderBlock - %X\n", LoaderBlock);

#if DBG
    DPRINT("Dumping Nodes:\n");
    devnode(NULL, 1+2+4+8, NULL);
    DPRINT("\n");
    ASSERT(FALSE);
#endif

    return FALSE;
}

/* EOF */
