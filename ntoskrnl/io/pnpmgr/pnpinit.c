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

PLIST_ENTRY IopGroupTable; // rointer to array[IopGroupIndex]
USHORT IopGroupIndex;

USHORT PiInitGroupOrderTableCount;
PUNICODE_STRING PiInitGroupOrderTable;

INTERFACE_TYPE PnpDefaultInterfaceType;

PDEVICE_NODE IopInitHalDeviceNode;
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
ULONG IoDeviceNodeTreeSequence = 0;

KSPIN_LOCK IopPnPSpinLock;
LIST_ENTRY IopPnpEnumerationRequestList;
KEVENT PiEnumerationLock;

ERESOURCE PiEngineLock;
ERESOURCE PiDeviceTreeLock;

KSEMAPHORE PpRegistrySemaphore;
extern ERESOURCE PpRegistryDeviceResource;

KEVENT PiEventQueueEmpty;
PPNP_DEVICE_EVENT_LIST PpDeviceEventList;
KGUARDED_MUTEX PiNotificationInProgressLock;

BOOLEAN PnPBootDriversLoaded = FALSE;
BOOLEAN PnPBootDriversInitialized = FALSE;
BOOLEAN IopBootConfigsReserved = FALSE;
BOOLEAN PnpSystemInit = FALSE;

BOOLEAN PpDisableFirmwareMapper;
BOOLEAN PiCriticalDeviceDatabaseEnabled = TRUE;

/* FUNCTIONS ******************************************************************/

BOOLEAN
NTAPI
IopWaitForBootDevicesStarted(VOID)
{
    NTSTATUS Status;

    Status = KeWaitForSingleObject(&PiEnumerationLock,
                                   Executive,
                                   KernelMode,
                                   FALSE,
                                   NULL);

    return NT_SUCCESS(Status);
}

BOOLEAN
NTAPI
IopWaitForBootDevicesDeleted(VOID)
{
    NTSTATUS Status;

    Status = KeWaitForSingleObject(&PiEventQueueEmpty,
                                   Executive,
                                   KernelMode,
                                   FALSE,
                                   NULL);

    return NT_SUCCESS(Status);
}

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
    HANDLE ServiceGroupOrderHandle;
    NTSTATUS Status;
    PKEY_VALUE_FULL_INFORMATION KeyValueInformation;
    PUNICODE_STRING GroupTable;
    ULONG Count;
    UNICODE_STRING GroupString;

    /* Open 'CurrentControlSet\Control\ServiceGroupOrder' key */
    RtlInitUnicodeString(&GroupString, IO_REG_KEY_SERVICEGROUPORDER);
    Status = IopOpenRegistryKeyEx(&ServiceGroupOrderHandle,
                                  NULL,
                                  &GroupString,
                                  KEY_READ);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PiInitCacheGroupInformation: Status - %X\n", Status);
        return Status;
    }

    /* Get the 'list' value */
    Status = IopGetRegistryValue(ServiceGroupOrderHandle,
                                 L"List",
                                 &KeyValueInformation);

    ZwClose(ServiceGroupOrderHandle);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PiInitCacheGroupInformation: Status - %X\n", Status);
        return Status;
    }

    /* Make sure it's valid */
    if ((KeyValueInformation->Type == REG_MULTI_SZ) &&
        (KeyValueInformation->DataLength))
    {
        /* Convert it to unicode strings */
        Status = PnpRegMultiSzToUnicodeStrings(KeyValueInformation,
                                               &GroupTable,
                                               &Count);
    }
    else
    {
        /* Fail */
        Status = STATUS_UNSUCCESSFUL;
    }

    /* Free the information */
    ExFreePool(KeyValueInformation);

    /* Cache it for later */
    if (NT_SUCCESS(Status))
    {
        PiInitGroupOrderTable = GroupTable;
        PiInitGroupOrderTableCount = (USHORT)Count;
        DPRINT("PiInitCacheGroupInformation: Count - %X\n", Count);
    }
    else
    {
        DPRINT1("PiInitCacheGroupInformation: Status - %p\n", Status);
        PiInitGroupOrderTable = NULL;
        PiInitGroupOrderTableCount = 0;
    }

    return Status;
}

VOID
NTAPI
PiInitReleaseCachedGroupInformation(VOID)
{
    ASSERT(PnpSystemInit);

    if (!PiInitGroupOrderTable)
    {
        DPRINT("PiInitReleaseCachedGroupInformation: PiInitGroupOrderTable == NULL\n");
        return;
    }

    PnpFreeUnicodeStringList(PiInitGroupOrderTable, PiInitGroupOrderTableCount);

    PiInitGroupOrderTable = NULL;
    PiInitGroupOrderTableCount = 0;
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
    HANDLE ControlSetHandle, EnumHandle, TreeHandle, EnumRootHandle;
    UNICODE_STRING KeyName;
    UNICODE_STRING PnpManagerDriverName = RTL_CONSTANT_STRING(DRIVER_ROOT_NAME L"PnpManager");
    PDEVICE_OBJECT Pdo;
    ULONG ix;

    DPRINT1("IopInitializePlugPlayServices: Phase - %X\n", Phase);

    if (Phase != 0 && Phase != 1)
    {
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Phase == 1)
    {
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
        return STATUS_SUCCESS;
    }

    DPRINT("IopInitializePlugPlayServices: FIXME Hive Limits\n");
    DPRINT("IopInitializePlugPlayServices: FIXME PpInitializeBootDDB()\n");

    /* Initialize locks and such */
    KeInitializeSpinLock(&IopPnPSpinLock);
    KeInitializeSpinLock(&IopDeviceTreeLock);
    KeInitializeSpinLock(&IopDeviceActionLock);
    InitializeListHead(&IopDeviceActionRequestList);
    InitializeListHead(&IopPnpEnumerationRequestList);
    KeInitializeEvent(&PiEnumerationLock, NotificationEvent, TRUE);
    KeInitializeEvent(&PiEventQueueEmpty, NotificationEvent, TRUE);
    ExInitializeResourceLite(&PiEngineLock);
    ExInitializeResourceLite(&PiDeviceTreeLock);
    KeInitializeSemaphore(&PpRegistrySemaphore, 1, 1);

    /* Get the default interface */
    PnpDefaultInterfaceType = IopDetermineDefaultInterfaceType();

    /* Setup the group cache */
    Status = PiInitCacheGroupInformation();
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    for (ix = Internal; ix < MaximumInterfaceType; ix++)
    {
        InitializeListHead(&IopLegacyBusInformationTable[ix]);
    }

    IopAllocateBootResourcesRoutine = IopReportBootResources;

    /* Initialize memory resources */
    IopInitializeResourceMap(LoaderBlock);

    /* Initialize arbiters */
    Status = IopInitializeArbiters();
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    /* Open the current control set */
    RtlInitUnicodeString(&KeyName, IO_REG_KEY_CURRENTCONTROLSET);
    Status = IopOpenRegistryKeyEx(&ControlSetHandle,
                                  NULL,
                                  &KeyName,
                                  KEY_ALL_ACCESS);
    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    DPRINT("IopInitializePlugPlayServices: FIXME test 'Win2000StartOrder' and 'ReturnHandleInfo'\n");

    /* Create the enum key */
    RtlInitUnicodeString(&KeyName, REGSTR_KEY_ENUM);
    Status = IopCreateRegistryKeyEx(&EnumHandle,
                                    ControlSetHandle,
                                    &KeyName,
                                    KEY_ALL_ACCESS,
                                    REG_OPTION_NON_VOLATILE,
                                    &Disposition);
    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    /* Check if it's a new key */
    if (Disposition == REG_CREATED_NEW_KEY)
    {
        /* FIXME: DACLs */
        DPRINT1("IopInitializePlugPlayServices: FIXME Create DACLs\n");
    }

    /* Create the root key */
    RtlInitUnicodeString(&KeyName, REGSTR_KEY_ROOT);
    Status = IopCreateRegistryKeyEx(&EnumRootHandle,
                                    EnumHandle,
                                    &KeyName,
                                    KEY_ALL_ACCESS,
                                    REG_OPTION_NON_VOLATILE,
                                    &Disposition);
    NtClose(EnumHandle);
    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    NtClose(EnumRootHandle);

    /* Open the enum key now */
    RtlInitUnicodeString(&KeyName, IO_REG_KEY_ENUM);
    Status = IopOpenRegistryKeyEx(&EnumHandle,
                                  NULL,
                                  &KeyName,
                                  KEY_ALL_ACCESS);
    if (NT_SUCCESS(Status))
    {
        /* Create the root tree dev node key */
        RtlInitUnicodeString(&KeyName, REGSTR_VAL_ROOT_DEVNODE);
        Status = IopCreateRegistryKeyEx(&TreeHandle,
                                        EnumHandle,
                                        &KeyName,
                                        KEY_ALL_ACCESS,
                                        REG_OPTION_NON_VOLATILE,
                                        NULL);
        NtClose(EnumHandle);
        if (NT_SUCCESS(Status))
        {
            NtClose(TreeHandle);
        }
    }

    DPRINT("IopInitializePlugPlayServices: FIXME PpProfileInit()\n");
    //PpProfileInit();

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
    DPRINT("IopInitializePlugPlayServices: IopRootDeviceNode - %p\n", IopRootDeviceNode);

    /* Set flags */
    IopRootDeviceNode->Flags |= DNF_MADEUP +
                                DNF_ENUMERATED +
                                DNF_IDS_QUERIED +
                                DNF_NO_RESOURCE_REQUIRED;

    /* Create instance path */
    if (RtlCreateUnicodeString(&IopRootDeviceNode->InstancePath,
                               REGSTR_VAL_ROOT_DEVNODE) == FALSE)
    {
        ASSERT(IopRootDeviceNode->InstancePath.Buffer);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    } 

    /* Map PDO to Instance */
    Status = IopMapDeviceObjectToDeviceInstance(IopRootDeviceNode->PhysicalDeviceObject,
                                                &IopRootDeviceNode->InstancePath);
    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    PipSetDevNodeState(IopRootDeviceNode, DeviceNodeStarted, NULL);

    /* Initialize PnP-Event notification support */
    Status = IopInitPlugPlayEvents();
    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    PpDeviceEventList = ExAllocatePoolWithTag(NonPagedPool, sizeof(PNP_DEVICE_EVENT_LIST), 'LEpP');
    if (!PpDeviceEventList)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    KeInitializeMutex(&PpDeviceEventList->EventQueueMutex, 0);
    KeInitializeGuardedMutex(&PpDeviceEventList->Lock);
    InitializeListHead(&PpDeviceEventList->List);

    PpDeviceEventList->Status = STATUS_PENDING;

    KeInitializeGuardedMutex(&PiNotificationInProgressLock);

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

    Status = STATUS_SUCCESS;

Exit:

    if (ControlSetHandle)
    {
        NtClose(ControlSetHandle);
    }

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

NTSTATUS
NTAPI
PipCreateMadeupNode(
    _In_ PUNICODE_STRING ServiceKeyName,
    _Out_ PHANDLE OutInstanceHandle,
    _Out_ PUNICODE_STRING OutMadeupPath,
    _In_ BOOLEAN IsLocked)
{
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    UNICODE_STRING EnumRootKeyName = RTL_CONSTANT_STRING(
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\Root");
    UNICODE_STRING LegacyPrefix = RTL_CONSTANT_STRING(L"LEGACY_");
    UNICODE_STRING MadeupName;
    UNICODE_STRING ValueName;
    UNICODE_STRING InstanceName;
    UNICODE_STRING RootName;
    UNICODE_STRING TmpString;
    HANDLE EnumRootHandle;
    HANDLE MadeupHandle;
    HANDLE InstanceHandle;
    HANDLE ControlHandle;
    HANDLE ServiceHandle;
    PWSTR ServiceName;
    ULONG Disposition  = 0;
    ULONG Data;
    BOOLEAN IsInternalLocked = FALSE;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PipCreateMadeupNode: ServiceKeyName - %wZ, IsLocked - %X\n",
           ServiceKeyName, IsLocked);

    if (!IsLocked)
    {
        KeEnterCriticalRegion();
        ExAcquireResourceSharedLite(&PpRegistryDeviceResource, TRUE);
        IsInternalLocked = TRUE;
    }

    Status = IopOpenRegistryKeyEx(&EnumRootHandle,
                                  NULL,
                                  &EnumRootKeyName,
                                  KEY_ALL_ACCESS);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("PipCreateMadeupNode: Status - %X\n", Status);
        ASSERT(FALSE);
        goto ErrorExit;
    }

    MadeupName.Length = 0;
    MadeupName.MaximumLength = LegacyPrefix.Length +
                               ServiceKeyName->Length +
                               sizeof(WCHAR);

    MadeupName.Buffer = ExAllocatePoolWithTag(PagedPool,
                                              MadeupName.MaximumLength,
                                              'uspP');
    if (!MadeupName.Buffer)
    {
        DPRINT("PipCreateMadeupNode: STATUS_INSUFFICIENT_RESOURCES\n");
        ZwClose(EnumRootHandle);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto ErrorExit;
    }

    RtlAppendUnicodeStringToString(&MadeupName, &LegacyPrefix);
    RtlAppendUnicodeStringToString(&MadeupName, ServiceKeyName);
    DPRINT("PipCreateMadeupNode: &MadeupName - %wZ\n", &MadeupName);

    Status = IopCreateRegistryKeyEx(&MadeupHandle,
                                    EnumRootHandle,
                                    &MadeupName,
                                    KEY_ALL_ACCESS,
                                    REG_OPTION_NON_VOLATILE,
                                    NULL);
    ZwClose(EnumRootHandle);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("PipCreateMadeupNode: Status - %X\n", Status);
        ASSERT(FALSE);
        RtlFreeUnicodeString(&MadeupName);
        goto ErrorExit;
    }

    Data = 1;
    RtlInitUnicodeString(&ValueName, L"NextInstance");
    ZwSetValueKey(MadeupHandle,
                  &ValueName,
                  0,
                  REG_DWORD,
                  &Data,
                  sizeof(Data));

    RtlInitUnicodeString(&InstanceName, L"0000");
    Status = IopCreateRegistryKeyEx(&InstanceHandle,
                                    MadeupHandle,
                                    &InstanceName,
                                    KEY_ALL_ACCESS,
                                    REG_OPTION_NON_VOLATILE,
                                    &Disposition);
    ZwClose(MadeupHandle);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("PipCreateMadeupNode: Status - %X\n", Status);
        ASSERT(FALSE);
        RtlFreeUnicodeString(&MadeupName);
        goto ErrorExit;
    }

    RtlInitUnicodeString(&RootName, L"Root\\");

    Status = PnpConcatenateUnicodeStrings(&TmpString,
                                          &RootName,
                                          &MadeupName);
    RtlFreeUnicodeString(&MadeupName);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("PipCreateMadeupNode: Status - %X\n", Status);
        ASSERT(FALSE);
        goto ErrorExit;
    }

    RtlInitUnicodeString(&InstanceName, L"\\0000");

    Status = PnpConcatenateUnicodeStrings(OutMadeupPath,
                                          &TmpString,
                                          &InstanceName);
    RtlFreeUnicodeString(&TmpString);

    DPRINT("PipCreateMadeupNode: OutMadeupPath - %wZ, Status - %X\n",
           OutMadeupPath, Status);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("PipCreateMadeupNode: Status - %X\n", Status);
        ASSERT(FALSE);
        goto ErrorExit;
    }

    if (Disposition != REG_CREATED_NEW_KEY)
    {
        DPRINT("PipCreateMadeupNode: Disposition  - %X\n", Disposition);
        goto Exit;
    }

    RtlInitUnicodeString(&ValueName, L"Control");

    Status = IopCreateRegistryKeyEx(&ControlHandle,
                                    InstanceHandle,
                                    &ValueName,
                                    KEY_ALL_ACCESS,
                                    REG_OPTION_VOLATILE,
                                    NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("PipCreateMadeupNode: Status - %X\n", Status);
        ASSERT(FALSE);
    }
    else
    {
        Data = 0;
        RtlInitUnicodeString(&ValueName, L"NewlyCreated");

        ZwSetValueKey(ControlHandle,
                      &ValueName,
                      0,
                      REG_DWORD,
                      &Data,
                      sizeof(Data));

        ZwClose(ControlHandle);
    }

    *OutInstanceHandle = InstanceHandle;

    ServiceName = ExAllocatePoolWithTag(PagedPool,
                                        ServiceKeyName->Length + sizeof(WCHAR),
                                        'uspP');

    if (!ServiceName)
    {
        DPRINT("PipCreateMadeupNode: STATUS_INSUFFICIENT_RESOURCES\n");
        ASSERT(FALSE);
    }
    else
    {
        RtlInitUnicodeString(&ValueName, L"Service");
        RtlCopyMemory(ServiceName,
                      ServiceKeyName->Buffer,
                      ServiceKeyName->Length);

        ServiceName[ServiceKeyName->Length / sizeof(WCHAR)] = UNICODE_NULL;

        ZwSetValueKey(InstanceHandle,
                      &ValueName,
                      0,
                      REG_SZ,
                      ServiceName,
                      ServiceKeyName->Length + sizeof(WCHAR));
    }

    Data = 1;
    RtlInitUnicodeString(&ValueName, L"Legacy");

    ZwSetValueKey(InstanceHandle,
                  &ValueName,
                  0,
                  REG_DWORD,
                  &Data,
                  sizeof(Data));

    Data = 0;
    RtlInitUnicodeString(&ValueName, L"ConfigFlags");

    ZwSetValueKey(InstanceHandle,
                  &ValueName,
                  0,
                  REG_DWORD,
                  &Data,
                  sizeof(Data));

    RtlInitUnicodeString(&ValueName, L"Class");

    ZwSetValueKey(InstanceHandle,
                  &ValueName,
                  0,
                  REG_SZ,
                  L"LegacyDriver",
                  sizeof(L"LegacyDriver"));

    RtlInitUnicodeString(&ValueName, L"ClassGUID");

    ZwSetValueKey(InstanceHandle,
                  &ValueName,
                  0,
                  REG_SZ,
                  L"{8ECC055D-047F-11D1-A537-0000F8753ED1}",
                  sizeof(L"{8ECC055D-047F-11D1-A537-0000F8753ED1}"));

    Status = PipOpenServiceEnumKeys(ServiceKeyName,
                                    KEY_READ,
                                    &ServiceHandle,
                                    NULL,
                                    FALSE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("PipCreateMadeupNode: Status - %X\n", Status);
        ASSERT(FALSE);

        if (ServiceName)
        {
            ExFreePoolWithTag(ServiceName, 'uspP');
        }

        goto Exit;
    }

    ValueInfo = NULL;
    TmpString.Length = 0;

    Status = IopGetRegistryValue(ServiceHandle,
                                 L"DisplayName",
                                 &ValueInfo);

    if (NT_SUCCESS(Status) && ValueInfo->Type == REG_SZ)
    {
        DPRINT("PipCreateMadeupNode: Status - %X\n", Status);

        if (ValueInfo->DataLength > sizeof(WCHAR))
        {
            USHORT length;

            PnpRegSzToString((PWCHAR)((ULONG_PTR)ValueInfo + ValueInfo->DataOffset),
                             ValueInfo->DataLength,
                             &length);

            TmpString.Length = length;
            TmpString.MaximumLength = ValueInfo->DataLength;

            TmpString.Buffer = (PWSTR)((ULONG_PTR)ValueInfo +
                                       ValueInfo->DataOffset);
        }
    }
    else
    {
        if (NT_SUCCESS(Status))
        {
            DPRINT("PipCreateMadeupNode: Not valid Type - %X\n",
                   ValueInfo->Type);
        }
        else
        {
            DPRINT("PipCreateMadeupNode: Status - %X\n", Status);
        }
    }

    ZwClose(ServiceHandle);

    if (ValueInfo)
    {
        ExFreePoolWithTag(ValueInfo, 'uspP');
    }

    if (ServiceName)
    {
        ExFreePoolWithTag(ServiceName, 'uspP');
    }

Exit:

    ExReleaseResourceLite(&PpRegistryDeviceResource);
    KeLeaveCriticalRegion();
    IsInternalLocked = FALSE;

    Status = PpDeviceRegistration(OutMadeupPath, TRUE, NULL);

    if (IsLocked)
    {
        KeEnterCriticalRegion();
        ExAcquireResourceSharedLite(&PpRegistryDeviceResource, TRUE);
    }

    //RtlFreeUnicodeString(&TmpString);

    if (NT_SUCCESS(Status))
    {
        return Status;
    }

    DPRINT("PipCreateMadeupNode: Status - %X\n", Status);

    ZwClose(*OutInstanceHandle);
    RtlFreeUnicodeString(OutMadeupPath);

ErrorExit:

    if (IsInternalLocked)
    {
        ExReleaseResourceLite(&PpRegistryDeviceResource);
        KeLeaveCriticalRegion();
    }

    return Status;
}

NTSTATUS
NTAPI
IopPrepareDriverLoading(
    _In_ PUNICODE_STRING ServiceKeyName,
    _In_ HANDLE ServiceKeyHandle,
    _In_ PVOID ImageBase,
    _In_ BOOLEAN IsFilter)
{
    PIMAGE_NT_HEADERS NtHeader;
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    UNICODE_STRING EnumKeyString;
    UNICODE_STRING InstancePath;
    UNICODE_STRING ValueName;
    HANDLE Handle;
    HANDLE KeyHandle;
    HANDLE EnumHandle = NULL;
    ULONG Count;
    NTSTATUS Status;
    BOOLEAN IsPnpDrv = FALSE;
    BOOLEAN IsAnyEnabled;

    DPRINT("IopPrepareDriverLoading: ServiceKeyName - %wZ, ImageBase - %p\n",
           ServiceKeyName, ImageBase);

    NtHeader = RtlImageNtHeader(ImageBase);

    if (NtHeader &&
        (NtHeader->OptionalHeader.DllCharacteristics &
         IMAGE_DLLCHARACTERISTICS_WDM_DRIVER))
    {
        IsPnpDrv = TRUE;
    }
    else
    {
        IsPnpDrv = FALSE;
    }

    IsAnyEnabled = IopIsAnyDeviceInstanceEnabled(ServiceKeyName,
                                                 ServiceKeyHandle,
                                                 IsPnpDrv == FALSE);
    if (IsAnyEnabled)
    {
       DPRINT("IopPrepareDriverLoading: IsAnyEnabled - TRUE\n");
       goto Exit;
    }
    if (IsPnpDrv)
    {
       DPRINT("IopPrepareDriverLoading: IsPnpDrv - TRUE\n");
       goto Exit;
    }

    DPRINT("IopPrepareDriverLoading: IsAnyEnabled - FALSE && IsPnpDrv - FALSE\n");
    //ASSERT(FALSE);

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&PpRegistryDeviceResource, TRUE);

    RtlInitUnicodeString(&EnumKeyString, L"Enum");

    Status = IopCreateRegistryKeyEx(&EnumHandle,
                                    ServiceKeyHandle,
                                    &EnumKeyString,
                                    KEY_ALL_ACCESS,
                                    REG_OPTION_VOLATILE,
                                    NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopPrepareDriverLoading: Status - %X\n", Status);
        goto ErrorExit;
    }

    Count = 0;

    Status = IopGetRegistryValue(EnumHandle, L"Count", &ValueInfo);

    if (NT_SUCCESS(Status))
    {
        if (ValueInfo->Type == REG_DWORD &&
            ValueInfo->DataLength >= sizeof(ULONG))
        {
            Count = *(PULONG)((ULONG_PTR)ValueInfo +
                              ValueInfo->DataOffset);
            DPRINT("IopPrepareDriverLoading: Count - %X\n", Count);
        }

        ExFreePoolWithTag(ValueInfo, 'uspP');
    }
    else if (Status != STATUS_OBJECT_PATH_NOT_FOUND &&
             Status != STATUS_OBJECT_NAME_NOT_FOUND)
    {
        DPRINT("IopPrepareDriverLoading: Status - %X\n", Status);
        ZwClose(EnumHandle);
        goto ErrorExit;
    }

    if (Count)
    {
        DPRINT("IopPrepareDriverLoading: FIXME! Count - %X\n", Count);
    ASSERT(FALSE);
        Status = 0;//STATUS_PLUGPLAY_NO_DEVICE;
        ZwClose(EnumHandle);
        goto ErrorExit;
    }

    Status = PipCreateMadeupNode(ServiceKeyName, &Handle, &InstancePath, TRUE);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopPrepareDriverLoading: Status - %X\n", Status);
        ZwClose(EnumHandle);
        goto ErrorExit;
    }

    RtlFreeUnicodeString(&InstancePath);
    RtlInitUnicodeString(&ValueName, L"Control");

    Status = IopCreateRegistryKeyEx(&KeyHandle,
                                    Handle,
                                    &ValueName,
                                    KEY_ALL_ACCESS,
                                    REG_OPTION_VOLATILE,
                                    NULL);
    if (NT_SUCCESS(Status))
    {
        RtlInitUnicodeString(&ValueName, L"ActiveService");

        ZwSetValueKey(KeyHandle,
                      &ValueName,
                      0,
                      REG_SZ,
                      ServiceKeyName->Buffer,
                      ServiceKeyName->Length + sizeof(WCHAR));

        ZwClose(KeyHandle);
    }

    Count++;

    RtlInitUnicodeString(&ValueName, L"Count");
    ZwSetValueKey(EnumHandle, &ValueName, 0, REG_DWORD, &Count, sizeof(Count));

    RtlInitUnicodeString(&ValueName, L"NextInstance");
    ZwSetValueKey(EnumHandle, &ValueName, 0, REG_DWORD, &Count, sizeof(Count));

    Status = STATUS_SUCCESS;

    ZwClose(Handle);
    ZwClose(EnumHandle);

ErrorExit:

    ExReleaseResourceLite(&PpRegistryDeviceResource);
    KeLeaveCriticalRegion();

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopPrepareDriverLoading: Status - %X\n", Status);
        return Status;
    }

Exit:

    DPRINT("IopPrepareDriverLoading: FIXME PpCheckInDriverDatabase()\n");
    Status = STATUS_SUCCESS;
    return Status;
}

NTSTATUS
NTAPI
IopInitializeBuiltinDriver(
    _In_ PUNICODE_STRING DriverName,
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PDRIVER_INITIALIZE EntryPoint,
    _In_ PLDR_DATA_TABLE_ENTRY BootLdrEntry,
    _In_ BOOLEAN IsFilter,
    _Out_ PDRIVER_OBJECT * OutDriverObject)
{
    UNICODE_STRING HardwareKeyName = 
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Hardware\\Description\\System");
    OBJECT_ATTRIBUTES ObjectAttributes;
    PDRIVER_OBJECT DriverObject;
    PDRIVER_EXTENSION DriverExtension;
    PLIST_ENTRY Entry;
    PVOID ImageBase;
    PIMAGE_NT_HEADERS NtHeader;
    PWCHAR ServiceNameBuffer;
    PWCHAR Buffer;
    PWSTR Ptr;
    HANDLE KeyHandle;
    HANDLE Handle;
    ULONG RegPathLength;
    ULONG Size;
    ULONG ix;
    NTSTATUS Status;

    DPRINT("\n");
    DPRINT("IopInitializeBuiltinDriver: DriverName - %wZ, RegistryPath - %wZ, BootLdrEntry - %p\n",
           DriverName, RegistryPath, BootLdrEntry);

    *OutDriverObject = NULL;

    Status = IopInitializeAttributesAndCreateObject(DriverName,
                                                    &ObjectAttributes,
                                                    (PVOID *)&DriverObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopInitializeBuiltinDriver: Status - %X\n", Status);
        return Status;
    }

    RtlZeroMemory(DriverObject,
                  sizeof(DRIVER_OBJECT) +
                  sizeof(EXTENDED_DRIVER_EXTENSION));

    DriverObject->DriverExtension = (PDRIVER_EXTENSION)(DriverObject + 1);
    DriverObject->DriverExtension->DriverObject = DriverObject;

    /* Loop all Major Functions */
    for (ix = 0; ix <= IRP_MJ_MAXIMUM_FUNCTION; ix++)
    {
        /* Invalidate each function */
        DriverObject->MajorFunction[ix] = IopInvalidDeviceRequest;
    }

    DriverObject->Type = IO_TYPE_DRIVER;
    DriverObject->Size = sizeof(DRIVER_OBJECT);
    DriverObject->DriverInit = EntryPoint;

    Status = ObInsertObject(DriverObject,
                            NULL,
                            FILE_READ_DATA,
                            0,
                            NULL,
                            &Handle);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopInitializeBuiltinDriver: Status - %X\n", Status);
        return Status;
    }

    Status = ObReferenceObjectByHandle(Handle,
                                       0,
                                       IoDriverObjectType,
                                       KernelMode,
                                       (PVOID *)&DriverObject,
                                       NULL);

    ASSERT(Status == STATUS_SUCCESS);

    for (Entry = PsLoadedModuleList.Flink;
         Entry != &PsLoadedModuleList && BootLdrEntry;
         Entry = Entry->Flink)
    {
        PLDR_DATA_TABLE_ENTRY LdrEntry;

        LdrEntry = CONTAINING_RECORD(Entry,
                                     LDR_DATA_TABLE_ENTRY,
                                     InLoadOrderLinks);

        if (RtlEqualUnicodeString(&BootLdrEntry->BaseDllName,
                                  &LdrEntry->BaseDllName,
                                  TRUE))
        {
            DriverObject->DriverSection = LdrEntry;
            break;
        }
    }

    if (!BootLdrEntry)
    {
        DPRINT("IopInitializeBuiltinDriver: BootLdrEntry = NULL\n");
        ImageBase = NULL;
        DriverObject->Flags |= DRVO_LEGACY_DRIVER;
    }
    else
    {
        ImageBase = BootLdrEntry->DllBase;
        NtHeader = RtlImageNtHeader(ImageBase);

        DriverObject->DriverStart = ImageBase;
        DriverObject->DriverSize = NtHeader->OptionalHeader.SizeOfImage;

        if (!(NtHeader->OptionalHeader.DllCharacteristics &
              IMAGE_DLLCHARACTERISTICS_WDM_DRIVER))
        {
            DriverObject->Flags |= DRVO_LEGACY_DRIVER;
        }

        /* Display 'Loading XXX...' message */
        IopDisplayLoadingMessage(&BootLdrEntry->BaseDllName);
    }

    InbvIndicateProgress();

    Buffer = ExAllocatePoolWithTag(PagedPool,
                                   DriverName->MaximumLength + sizeof(WCHAR),
                                   TAG_IO);
    if (Buffer)
    {
        RtlCopyMemory(Buffer, DriverName->Buffer, DriverName->MaximumLength);
        Buffer[DriverName->Length / sizeof(WCHAR)] = UNICODE_NULL;

        DriverObject->DriverName.Buffer = Buffer;
        DriverObject->DriverName.MaximumLength = DriverName->MaximumLength;
        DriverObject->DriverName.Length = DriverName->Length;
    }
    else
    {
        DPRINT1("IopInitializeBuiltinDriver: Buffer not allocated!\n");
    }

    DriverExtension = DriverObject->DriverExtension;
    RegPathLength = RegistryPath->Length;

    if (!RegistryPath || RegPathLength == 0)
    {
        RtlZeroMemory(&DriverExtension->ServiceKeyName, sizeof(UNICODE_STRING));
    }
    else
    {
        RegPathLength /= sizeof(WCHAR);
        Ptr = &RegistryPath->Buffer[RegPathLength - 1];

        if (*Ptr == '\\')
        {
            Buffer = &RegistryPath->Buffer[RegPathLength - 2];
        }
        else
        {
            Buffer = &RegistryPath->Buffer[RegPathLength - 1];
        }

        for (Size = 0; Ptr != RegistryPath->Buffer; Size += sizeof(WCHAR))
        {
            if (*Ptr == '\\')
            {
                Ptr += 1;
                Buffer = Ptr;
                break;
            }

            Ptr -= 1;
            Buffer = Ptr;
        }

        if (Ptr == RegistryPath->Buffer)
        {
            Size += sizeof(WCHAR);
            DPRINT("IopInitializeBuiltinDriver: Size - %X\n", Size);
        }

        ServiceNameBuffer = ExAllocatePoolWithTag(NonPagedPool,
                                                  Size + sizeof(WCHAR),
                                                  TAG_IO);
        if (!ServiceNameBuffer)
        {
            DriverExtension->ServiceKeyName.Buffer = NULL;
            DriverExtension->ServiceKeyName.Length = 0;

            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        RtlCopyMemory(ServiceNameBuffer, Ptr, Size);
        ServiceNameBuffer[Size / sizeof(WCHAR)] = UNICODE_NULL;

        DriverExtension->ServiceKeyName.Length = Size;
        DriverExtension->ServiceKeyName.MaximumLength = Size + sizeof(WCHAR);
        DriverExtension->ServiceKeyName.Buffer = ServiceNameBuffer;

        DPRINT("IopInitializeBuiltinDriver: ServiceKeyName - %wZ\n",
               &DriverExtension->ServiceKeyName);

        Status = IopOpenRegistryKeyEx(&KeyHandle,
                                      NULL,
                                      RegistryPath,
                                      KEY_ALL_ACCESS);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("IopInitializeBuiltinDriver: Status - %X\n", Status);
            ASSERT(FALSE);
            goto Exit;
        }

        Status = IopPrepareDriverLoading(&DriverExtension->ServiceKeyName,
                                         KeyHandle,
                                         ImageBase,
                                         IsFilter);
        NtClose(KeyHandle);

        if (!NT_SUCCESS(Status))
        {
            DPRINT("IopInitializeBuiltinDriver: DriverInit Status - %X\n", Status);

            goto Exit;
        }
    }

    DriverObject->HardwareDatabase = &HardwareKeyName;

    Status = DriverObject->DriverInit(DriverObject, RegistryPath);
    DPRINT("IopInitializeBuiltinDriver: DriverInit Status - %X\n", Status);

Exit:

    NtClose(Handle);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopInitializeBuiltinDriver: Status - %X\n", Status);

        if (Status != STATUS_PLUGPLAY_NO_DEVICE)
        {
            DPRINT("IopInitializeBuiltinDriver: DriverInit Status - %X\n", Status);
            DriverObject->DriverSection = NULL;
            DPRINT("IopInitializeBuiltinDriver: FIXME IopDriverLoadingFailed\n");
        }

        ObMakeTemporaryObject(DriverObject);
        ObDereferenceObject(DriverObject);
    }
    else
    {
        DPRINT("IopInitializeBuiltinDriver: ServiceKeyName - %wZ\n",
               &DriverExtension->ServiceKeyName);

        IopReadyDeviceObjects(DriverObject);
        *OutDriverObject = DriverObject;
    }

    DPRINT("IopInitializeBuiltinDriver: Status - %X\n", Status);
    return Status;
}

VOID
NTAPI
PipInsertDriverList(
    _In_ PLIST_ENTRY DriverList,
    _In_ PLIST_ENTRY Link)
{
    PLIST_ENTRY Entry;
    USHORT EntryTagPosition;
    USHORT LinkTagPosition;

    LinkTagPosition = (CONTAINING_RECORD(Link,
                                         DRIVER_INFORMATION,
                                         Link))->TagPosition;
    for (Entry = DriverList->Flink;
         Entry != DriverList;
         Entry = Entry->Flink)
    {
        EntryTagPosition = (CONTAINING_RECORD(Entry,
                                              DRIVER_INFORMATION,
                                              Link))->TagPosition;

        if (EntryTagPosition > LinkTagPosition)
        {
            break;
        }
    }

    InsertHeadList(Entry->Blink, Link);
}

PDRIVER_GROUP_LIST_ENTRY
NTAPI
PipLookupGroupName(
    _In_ PUNICODE_STRING GroupString,
    _In_ BOOLEAN IsCreateEntry)
{
    PDRIVER_GROUP_LIST_ENTRY Entry;
    PDRIVER_GROUP_LIST_ENTRY NewEntry;
    PDRIVER_GROUP_LIST_ENTRY SameEntry;

    DPRINT("PipLookupGroupName: GroupString - %wZ, IsCreateEntry - %X\n", GroupString, IsCreateEntry);

    Entry = IopGroupListHead;
    if (!IopGroupListHead)
    {
        if (IsCreateEntry)
        {
            NewEntry = PipCreateEntry(GroupString);
            IopGroupListHead = NewEntry;
        }
        else
        {
            NewEntry = NULL;
        }

        return NewEntry;
    }

    while (TRUE)
    {
        if (GroupString->Length >= Entry->GroupName.Length)
        {
            if (GroupString->Length > Entry->GroupName.Length)
            {
                if (!Entry->LongEntry)
                {
                    if (!IsCreateEntry)
                    {
                        Entry = NULL;
                        break;
                    }

                    NewEntry = PipCreateEntry(GroupString);
                    Entry->LongEntry = NewEntry;
                    Entry = NewEntry;
                    break;
                }

                Entry = Entry->LongEntry;
            }
            else
            {
                if (RtlEqualUnicodeString(GroupString, &Entry->GroupName, TRUE))
                {
                    break;
                }

                for (SameEntry = Entry;
                     ;
                     SameEntry = SameEntry->NextSameEntry)
                {
                    Entry = Entry->NextSameEntry;

                    if (!Entry)
                    {
                        if (IsCreateEntry)
                        {
                            NewEntry = PipCreateEntry(GroupString);
                            SameEntry->NextSameEntry = NewEntry;
                            Entry = NewEntry;
                            break;
                        }

                        Entry = NULL;
                        break;
                    }

                    if (RtlEqualUnicodeString(GroupString, &Entry->GroupName, TRUE))
                    {
                        break;
                    }
                }

                break;
            }
        }
        else
        {
            /* GroupString->Length < Entry->GroupName.Length */
            if (!Entry->ShortEntry)
            {
                if (!IsCreateEntry)
                {
                    Entry = NULL;
                    break;
                }

                NewEntry = PipCreateEntry(GroupString);
                Entry->ShortEntry = NewEntry;
                Entry = NewEntry;
                break;
            }

            Entry = Entry->ShortEntry;
        }
    }

    return Entry;
}

BOOLEAN
NTAPI
PipCheckDependencies(
    _In_ HANDLE KeyHandle)
{
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    PDRIVER_GROUP_LIST_ENTRY Entry;
    UNICODE_STRING GroupString;
    PWSTR DependString;
    ULONG Length;
    NTSTATUS Status;
    BOOLEAN Result = TRUE;

    DPRINT("PipCheckDependencies: KeyHandle - %X\n", KeyHandle);

    Status = IopGetRegistryValue(KeyHandle, L"DependOnGroup", &ValueInfo);
    if (!NT_SUCCESS(Status))
    {
        return TRUE;
    }

    Length = ValueInfo->DataLength;
    DependString = (PWSTR)((PUCHAR)ValueInfo + ValueInfo->DataOffset);

    while (Length)
    {
        RtlInitUnicodeString(&GroupString, DependString);
        GroupString.Length = GroupString.MaximumLength;

        Entry = PipLookupGroupName(&GroupString, FALSE);
        if (Entry && Entry->NumberOfLoads == 0)
        {
            Result = FALSE;
            break;
        }

        DependString = (PWSTR)((PUCHAR)DependString + GroupString.MaximumLength);
        Length -= GroupString.MaximumLength;
    }

    ExFreePool(ValueInfo);

    return Result;
}

BOOLEAN
FASTCALL
INIT_FUNCTION
IopInitializeBootDrivers(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    UNICODE_STRING RawFsName;
    UNICODE_STRING RegistryPath;
    UNICODE_STRING DriverName;
    UNICODE_STRING GroupName;
    PDRIVER_OBJECT DriverObject;
    PLDR_DATA_TABLE_ENTRY BootLdrEntry;
    PBOOT_DRIVER_LIST_ENTRY BootEntry;
    PDRIVER_INFORMATION DriverInfo;
    PDRIVER_EXTENSION DriverExtension;
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    PLIST_ENTRY ListHead;
    PLIST_ENTRY Entry;
    PLIST_ENTRY NextEntry;
    HANDLE ServiceHandle;
    ULONG ix;
    ULONG Idx;
    NTSTATUS Status;
    BOOLEAN IsWithoutGroupOrderIndex = FALSE;

    DPRINT("IopInitializeBootDrivers: LoaderBlock - %X\n", LoaderBlock);

#if DBG
    DPRINT("Dumping Nodes:\n");
    IopDumpDeviceNode(NULL, 1+2+4+8, NULL);
    DPRINT("\n");
    ASSERT(FALSE);
#endif

    RtlInitUnicodeString(&RawFsName, L"\\FileSystem\\RAW");
    RtlInitUnicodeString(&RegistryPath, L"");

    IopInitializeBuiltinDriver(&RawFsName,
                               &RegistryPath,
                               RawFsDriverEntry,
                               NULL,
                               FALSE,
                               &DriverObject);
    if (!DriverObject)
    {
        DPRINT("IopInitializeBootDrivers: Failed to initialize RAW filsystem\n");
        ASSERT(FALSE);
        return FALSE;
    }

    IopGroupIndex = PpInitGetGroupOrderIndex(NULL);

    if (IopGroupIndex == 0xFFFF)
    {
        DPRINT("IopInitializeBootDrivers: IopGroupIndex == 0xFFFF\n");
        ASSERT(FALSE);
        return FALSE;
    }

    DPRINT("IopInitializeBootDrivers: IopGroupIndex - %X\n", IopGroupIndex);

    IopGroupTable = ExAllocatePoolWithTag(PagedPool,
                                          IopGroupIndex * sizeof(LIST_ENTRY),
                                          'nipP');
    if (!IopGroupTable)
    {
        DPRINT("IopInitializeBootDrivers: IopGroupTable == NULL\n");
        ASSERT(FALSE);
        return FALSE;
    }

    for (ix = 0; ix < IopGroupIndex; ix++)
    {
        InitializeListHead(&IopGroupTable[ix]);
    }

    ListHead = &KeLoaderBlock->LoadOrderListHead;
    NextEntry = ListHead->Flink;

    while (ListHead != NextEntry)
    {
        BootLdrEntry = CONTAINING_RECORD(NextEntry,
                                         LDR_DATA_TABLE_ENTRY,
                                         InLoadOrderLinks);

        DPRINT("IopInitializeBootDrivers: FullDllName - %wZ, Flags - %X\n",
               &BootLdrEntry->FullDllName, BootLdrEntry->Flags);

        /* Check if the DLL needs to be initialized */
        if (BootLdrEntry->Flags & LDRP_DRIVER_DEPENDENT_DLL)
        {
            /* Call its entrypoint */
            MmCallDllInitialize(BootLdrEntry, NULL);
        }
 
        /* Go to the next driver */
        NextEntry = NextEntry->Flink;
    }

    for (Entry = LoaderBlock->BootDriverListHead.Flink;
         Entry != &LoaderBlock->BootDriverListHead;
         Entry = Entry->Flink)
    {
        /* Get the entry */
        BootEntry = CONTAINING_RECORD(Entry,
                                      BOOT_DRIVER_LIST_ENTRY,
                                      Link);

        /* Get the driver loader entry */
        BootLdrEntry = BootEntry->LdrEntry;

        DriverInfo = ExAllocatePoolWithTag(PagedPool,
                                           sizeof(DRIVER_INFORMATION),
                                           'nipP');
        if (!DriverInfo)
        {
            continue;
        }

        RtlZeroMemory(DriverInfo, sizeof(DRIVER_INFORMATION));

        InitializeListHead(&DriverInfo->Link);
        DriverInfo->DataTableEntry = BootEntry;

        Status = IopOpenRegistryKeyEx(&ServiceHandle,
                                      NULL,
                                      &BootEntry->RegistryPath,
                                      KEY_READ);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("IopInitializeBootDrivers: RegistryPath - %wZ, Flags - %X\n",
                   &BootEntry->RegistryPath, BootLdrEntry->Flags);

            ExFreePoolWithTag(DriverInfo, 'nipP');
            continue;
        }

        DriverInfo->ServiceHandle = ServiceHandle;

        Idx = PpInitGetGroupOrderIndex(ServiceHandle);

        if (Idx)
        {
            DriverInfo->TagPosition = PipGetDriverTagPriority(ServiceHandle);

            DPRINT("\n");
            DPRINT("IopInitializeBootDrivers: BootEntry - %p, RegistryPath - %wZ, TagPosition - %X, Idx - %X\n",
                   BootEntry, &BootEntry->RegistryPath, DriverInfo->TagPosition, Idx);

            PipInsertDriverList(&IopGroupTable[Idx], &DriverInfo->Link);
        }
        else
        {
            DPRINT("IopInitializeBootDrivers: Idx = 0\n");
            ASSERT(FALSE);

            IsWithoutGroupOrderIndex = TRUE;

            Status = IopGetDriverNameFromKeyNode(ServiceHandle, &DriverName);

            if (NT_SUCCESS(Status))
            {
                DriverInfo->Failed = IopInitializeBuiltinDriver(&DriverName,
                                                                &BootEntry->RegistryPath,
                                                                BootLdrEntry->EntryPoint,
                                                                BootLdrEntry,
                                                                FALSE,
                                                                &DriverObject);
                ZwClose(ServiceHandle);

                ExFreePoolWithTag(DriverName.Buffer, 0);
                ExFreePoolWithTag(DriverInfo, 'nipP');

                if (!DriverObject)
                {
                    ExFreePoolWithTag(IopGroupTable, 'nipP');
                    return FALSE;
                }

                DPRINT("IopInitializeBootDrivers: FIXME PipNotifySetupDevices\n");
            }
        }
    }

    /* Loop each group index */
    for (ix = 0; ix < IopGroupIndex; ix++)
    {
        DPRINT("IopInitializeBootDrivers: ix - %X\n", ix);

        /* Loop each group table */
        NextEntry = IopGroupTable[ix].Flink;
        while (NextEntry != &IopGroupTable[ix])
        {
            /* Get the entry */
            DriverInfo = CONTAINING_RECORD(NextEntry,
                                           DRIVER_INFORMATION,
                                           Link);

            ServiceHandle = DriverInfo->ServiceHandle;

            /* Get the driver loader entry */
            BootLdrEntry = DriverInfo->DataTableEntry->LdrEntry;
            DriverInfo->Processed = 1;

            DPRINT("IopInitializeBootDrivers: driver name for %wZ\n",
                   &DriverInfo->DataTableEntry->RegistryPath);

            Status = IopGetDriverNameFromKeyNode(ServiceHandle, &DriverName);

            if (!NT_SUCCESS(Status))
            {
                DPRINT("IopInitializeBootDrivers: Could not get driver name for %wZ\n",
                       &DriverInfo->DataTableEntry->RegistryPath);

                DriverInfo->Failed = 1;
                goto Next;
            }

            Status = IopGetRegistryValue(ServiceHandle,
                                         L"Group",
                                         &ValueInfo);
            if (!NT_SUCCESS(Status))
            {
                GroupListEntry = NULL;
            }
            else
            {
                if (ValueInfo->DataLength)
                {
                    GroupName.Length = ValueInfo->DataLength;
                    GroupName.MaximumLength = GroupName.Length + sizeof(WCHAR);

                    GroupName.Buffer = (PWSTR)((ULONG_PTR)ValueInfo +
                                               ValueInfo->DataOffset);

                    DPRINT("IopInitializeBootDrivers: Group - %S\n",
                           GroupName.Buffer);

                    GroupListEntry = PipLookupGroupName(&GroupName, TRUE);
                }
                else
                {
                    GroupListEntry = NULL;
                }

                ExFreePoolWithTag(ValueInfo, 'uspP');
            }

            DriverObject = NULL;

            if (PipCheckDependencies(ServiceHandle))
            {
                DriverObject = DriverInfo->DriverObject;

                if (DriverObject)
                {
                    if (GroupListEntry)
                    {
                        GroupListEntry->NumberOfLoads++;
                    }

                    DriverInfo->DriverObject = DriverObject;
                    ExFreePoolWithTag(DriverName.Buffer, 0);
                    goto Next;
                }

                if (!DriverInfo->Failed)
                {

                    //DriverInfo->Status = IopInitializeBuiltinDriver(
                    Status = IopInitializeBuiltinDriver(&DriverName,
                                                        &DriverInfo->DataTableEntry->RegistryPath,
                                                        BootLdrEntry->EntryPoint,
                                                        BootLdrEntry,
                                                        0,
                                                        &DriverObject);

                    if (!DriverObject)
                    {
                        DPRINT("IopInitializeBootDrivers: Status - %X\n", Status);
                        DriverInfo->Failed = 1;
                        ExFreePoolWithTag(DriverName.Buffer, 0);
                        goto Next;
                    }

                    ObReferenceObject(DriverObject);

                    if (!IopIsLegacyDriver(DriverObject))
                    {
                        if (DriverObject->DeviceObject)
                        {
                            IopDeleteLegacyKey(DriverObject);
                        }
                        else
                        {
                            DriverExtension = DriverObject->DriverExtension;
                            if (!DriverExtension->ServiceKeyName.Buffer)
                            {
                                IopDeleteLegacyKey(DriverObject);
                            }
                            else
                            {
                                if (IopIsAnyDeviceInstanceEnabled(&DriverExtension->ServiceKeyName,
                                                                  NULL,
                                                                  FALSE))
                                {
                                    IopDeleteLegacyKey(DriverObject);
                                }
                                else
                                {
                                    if (IsWithoutGroupOrderIndex && !(DriverObject->Flags & 8))
                                    {
                                        DriverObject = DriverObject;
                                        DPRINT("IopInitializeBootDrivers: ASSERT\n");
                                        ASSERT(FALSE);
                                        //IopDriverLoadingFailed(0, &DriverObject->DriverExtension->ServiceKeyName);
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    DPRINT("IopInitializeBootDrivers: ASSERT\n");
                    ASSERT(FALSE);
                }
            }

            if (DriverObject)
            {
                if (GroupListEntry)
                {
                    GroupListEntry->NumberOfLoads++;
                }

                DriverInfo->DriverObject = DriverObject;
                ExFreePoolWithTag(DriverName.Buffer, 0);
            }
            else
            {
                DriverInfo->Failed = 1;
                ExFreePoolWithTag(DriverName.Buffer, 0);
            }

Next:
            if (!DriverInfo->Failed)
            {
                PipAddDevicesToBootDriver(DriverObject);

                PipRequestDeviceAction(NULL,
                                       PipEnumBootDevices,
                                       0,
                                       0,
                                       NULL,
                                       NULL);
            }

            DPRINT("IopInitializeBootDrivers: FIXME PipWaitForBootDevicesDeleted\n");

            NextEntry = NextEntry->Flink;
        }
 
        if (ix == 2) // ServiceGroupName - "Boot Bus Extender"
        {
            DPRINT("IopInitializeBootDrivers: ix == 2. IopAllocateLegacyBootResources(0, 0)\n");

            IopAllocateLegacyBootResources(0, 0);
            IopAllocateBootResourcesRoutine = IopAllocateBootResources;

            ASSERT(IopInitHalResources == NULL);
            ASSERT(IopInitReservedResourceList == NULL);

            IopBootConfigsReserved = TRUE;
        }
    }

    PnPBootDriversLoaded = TRUE;

    PipRequestDeviceAction(NULL,
                           PipEnumAssignResources,
                           0,
                           0,
                           NULL,
                           NULL);

#if 0 // FIXME. For tcp/ip remote boot
    {
        LARGE_INTEGER Interval;
        DPRINT("IopInitializeBootDrivers: 1 sec wait\n");
        Interval.QuadPart = -10000LL * 1000; // 1 sec.
        KeDelayExecutionThread(KernelMode, FALSE, &Interval);
        DPRINT("IopInitializeBootDrivers: 1 sec wait end\n");
    }
#endif

    DPRINT("IopInitializeBootDrivers: FIXME Check IsLegacy drivers \n");
    DPRINT("IopInitializeBootDrivers: FIXME Free IopGroupTable \n");
    DPRINT("IopInitializeBootDrivers: end\n");

#if DBG
    DPRINT("Dumping Nodes:\n");
    IopDumpDeviceNode(NULL, 1+2+4+8, NULL);
    DPRINT("\n");
    ASSERT(FALSE);
#endif

    return TRUE;
}

VOID
FASTCALL
INIT_FUNCTION
IopInitializeSystemDrivers(VOID)
{
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    PDRIVER_GROUP_LIST_ENTRY Entry;
    PDRIVER_OBJECT DriverObject;
    UNICODE_STRING DriverName;
    UNICODE_STRING EnumName;
    UNICODE_STRING GroupName;
    PHANDLE pHandleArray;
    PHANDLE DriverList;
    HANDLE DriverHandle;
    HANDLE EnumHandle;
    KEVENT Event;
    NTSTATUS Status;

    DPRINT("IopInitializeSystemDrivers()\n");

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Status = PipRequestDeviceAction(IopRootDeviceNode->PhysicalDeviceObject,
                                    PipEnumStartSystemDevices,
                                    0,
                                    0,
                                    &Event,
                                    NULL);
    if (NT_SUCCESS(Status))
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
    }

    /* Get the driver list */
    pHandleArray = CmGetSystemDriverList();
    if (!pHandleArray)
    {
        DPRINT("IopInitializeSystemDrivers: pHandleArray == NULL\n");
        ASSERT(pHandleArray);
        goto Exit;
    }

    /* Loop it */
    for (DriverList = pHandleArray; *DriverList; DriverList++)
    {
        DriverHandle = *DriverList;
        Status = IopGetDriverNameFromKeyNode(DriverHandle, &DriverName);

        if (NT_SUCCESS(Status))
        {
            DPRINT("IopInitializeSystemDrivers: DriverName - %wZ\n", &DriverName);

            DriverObject = IopReferenceDriverObjectByName(&DriverName);
            RtlFreeUnicodeString(&DriverName);

            if (DriverObject)
            {
                ObDereferenceObject(DriverObject);
                ZwClose(DriverHandle);
                continue;
            }
        }
        else
        {
            DPRINT("IopInitializeSystemDrivers: Status - %X\n", Status);
        }

        RtlInitUnicodeString(&EnumName, L"Enum");
        Status = IopOpenRegistryKeyEx(&EnumHandle, DriverHandle, &EnumName, KEY_READ);

        if (NT_SUCCESS(Status))
        {
            ULONG InitStartFailed = 0;

            Status = IopGetRegistryValue(EnumHandle, L"INITSTARTFAILED", &ValueInfo);

            if (NT_SUCCESS(Status))
            {
                if (ValueInfo->DataLength == sizeof(ULONG))
                {
                    InitStartFailed = *(PULONG)((ULONG_PTR)ValueInfo + ValueInfo->DataOffset);
                }

                ExFreePool(ValueInfo);
            }

            ZwClose(EnumHandle);

            if (InitStartFailed)
            {
                ZwClose(DriverHandle);
                continue;
            }
        }

        Status = IopGetRegistryValue(DriverHandle, L"Group", &ValueInfo);

        if (!NT_SUCCESS(Status))
        {
            Entry = NULL;
        }
        else
        {
            if (ValueInfo->DataLength)
            {
                GroupName.Length = (USHORT)ValueInfo->DataLength;
                GroupName.MaximumLength = GroupName.Length;
                GroupName.Buffer = (PWSTR)((ULONG_PTR)ValueInfo + ValueInfo->DataOffset);

                Entry = PipLookupGroupName(&GroupName, TRUE);
            }
            else
            {
                Entry = NULL;
            }

            ExFreePool(ValueInfo);
        }

        if (PipCheckDependencies(DriverHandle))
        {
            NTSTATUS InitStatus;

            Status = IopLoadDriver(DriverHandle, TRUE, FALSE, &InitStatus);

            if (NT_SUCCESS(Status) && Entry != NULL)
            {
                Entry->NumberOfLoads++;
            }
        }
        else
        {
            ZwClose(DriverHandle);
        }

        InbvIndicateProgress();
    }

    /* Free the list */
    ExFreePoolWithTag(pHandleArray, TAG_CM);

Exit:

    PipRequestDeviceAction(IopRootDeviceNode->PhysicalDeviceObject,
                           PipEnumStartSystemDevices,
                           0,
                           0,
                           NULL,
                           NULL);
    PnpSystemInit = TRUE;

    PiInitReleaseCachedGroupInformation();

    DPRINT("IopInitializeSystemDrivers: FIXME PpReleaseBootDDB()\n");
    //PpReleaseBootDDB();

    if (IopGroupListHead)
    {
        PipFreeGroupTree(IopGroupListHead);
    }

    DPRINT("IopInitializeSystemDrivers: exit \n");
}

/* EOF */
