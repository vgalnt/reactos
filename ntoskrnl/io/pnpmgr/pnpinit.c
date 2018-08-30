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
extern ERESOURCE PpRegistryDeviceResource;

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

    /* ReactOS HACK for SETUPLDR */
    if (KeLoaderBlock->SetupLdrBlock)
    {
        DPRINT1("WARNING!! In PiInitCacheGroupInformation, using ReactOS HACK for SETUPLDR!!\n");

        /* Bogus data */
        PiInitGroupOrderTableCount = 0;
        PiInitGroupOrderTable = (PVOID)(ULONG_PTR)0xBABEB00BBABEB00BULL;
        return STATUS_SUCCESS;
    }

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

        ASSERT(FALSE);
        Status = 0;//IopPrepareDriverLoading(&DriverExtension->ServiceKeyName,
                   //                      KeyHandle,
                   //                      ImageBase,
                   //                      IsFilter);
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
    devnode(NULL, 1+2+4+8, NULL);
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

                ExFreePoolWithTag(DriverName.Buffer, TAG_IO);
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
                DPRINT("IopInitializeBootDrivers: Status - %X\n", Status);
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

                    DPRINT("IopInitializeBootDrivers: FIXME PipLookupGroupName\n");
                }
                else
                {
                    DPRINT("IopInitializeBootDrivers: ValueInfo->DataLength == 0\n");
                }

                ExFreePoolWithTag(ValueInfo, 'uspP');
            }

            DriverObject = NULL;

            DPRINT("IopInitializeBootDrivers: FIXME PipCheckDependencies\n");

            DriverObject = DriverInfo->DriverObject;

            if (DriverObject)
            {
                DriverInfo->DriverObject = DriverObject;
                ExFreePoolWithTag(DriverName.Buffer, TAG_IO);
                goto Next;
            }

            if (!DriverInfo->Failed)
            {
                DriverInfo->Status =
                    IopInitializeBuiltinDriver(
                        &DriverName,
                        &DriverInfo->DataTableEntry->RegistryPath,
                        BootLdrEntry->EntryPoint,
                        BootLdrEntry,
                        FALSE,
                        &DriverObject);

                if (!DriverObject)
                {
                    DPRINT("IopInitializeBootDrivers: DriverInfo->Status - %p\n",
                           DriverInfo->Status);

                    DriverInfo->Failed = 1;
                    ExFreePoolWithTag(DriverName.Buffer, TAG_IO);
                    goto Next;
                }

                ObReferenceObject(DriverObject);

                if (!IopIsLegacyDriver(DriverObject))
                {
                    if (DriverObject->DeviceObject)
                    {
                        DPRINT("IopInitializeBootDrivers: FIXME IopDeleteLegacyKey\n");
                        ASSERT(FALSE);
                    }
                    else
                    {
                        DriverExtension = DriverObject->DriverExtension;

                        if (!DriverExtension->ServiceKeyName.Buffer)
                        {
                            DPRINT("IopInitializeBootDrivers: FIXME IopDeleteLegacyKey\n");
                            ASSERT(FALSE);
                        }
                        else
                        {
                            if (IopIsAnyDeviceInstanceEnabled(&DriverExtension->ServiceKeyName,
                                                              NULL,
                                                              FALSE))
                            {
                                DPRINT("IopInitializeBootDrivers: FIXME IopDeleteLegacyKey\n");
                                ASSERT(FALSE);
                            }
                            else
                            {
                                if (IsWithoutGroupOrderIndex &&
                                    !(DriverObject->Flags & DRVO_REINIT_REGISTERED))
                                {
                                    DriverObject = DriverObject;
                                    DPRINT("IopInitializeBootDrivers: FIXME IopDriverLoadingFailed\n");
                                    ASSERT(FALSE);
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

            if (DriverObject)
            {
                DriverInfo->DriverObject = DriverObject;
                ExFreePoolWithTag(DriverName.Buffer, TAG_IO);
            }
            else
            {
                DriverInfo->Failed = 1;
                ExFreePoolWithTag(DriverName.Buffer, TAG_IO);
            }

Next:
            if (!DriverInfo->Failed)
            {
                DPRINT("IopInitializeBootDrivers: FIXME PipAddDevicesToBootDriver\n");
                ASSERT(FALSE);

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
            DPRINT("IopInitializeBootDrivers: FIXME IopAllocateLegacyBootResources\n");
            ASSERT(FALSE);
            //IopAllocateLegacyBootResources(0, 0);

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
    devnode(NULL, 1+2+4+8, NULL);
    DPRINT("\n");
    ASSERT(FALSE);
#endif

    return TRUE;
}

/* EOF */
