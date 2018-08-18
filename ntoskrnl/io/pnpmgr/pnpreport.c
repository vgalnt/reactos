/*
 * PROJECT:         ReactOS Kernel
 * COPYRIGHT:       GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/pnpmgr/pnpreport.c
 * PURPOSE:         Device Changes Reporting Functions
 * PROGRAMMERS:     Cameron Gutman (cameron.gutman@reactos.org)
 *                  Pierre Schweitzer
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* TYPES *******************************************************************/

typedef struct _INTERNAL_WORK_QUEUE_ITEM
{
  WORK_QUEUE_ITEM WorkItem;
  PDEVICE_OBJECT PhysicalDeviceObject;
  PDEVICE_CHANGE_COMPLETE_CALLBACK Callback;
  PVOID Context;
  PTARGET_DEVICE_CUSTOM_NOTIFICATION NotificationStructure;
} INTERNAL_WORK_QUEUE_ITEM, *PINTERNAL_WORK_QUEUE_ITEM;

NTSTATUS
NTAPI
IopCreateDeviceKeyPath(IN PCUNICODE_STRING RegistryPath,
                       IN ULONG CreateOptions,
                       OUT PHANDLE Handle);

NTSTATUS
IopSetDeviceInstanceData(HANDLE InstanceKey,
                         PDEVICE_NODE DeviceNode);

NTSTATUS
IopActionInterrogateDeviceStack(PDEVICE_NODE DeviceNode,
                                PVOID Context);

NTSTATUS
PpSetCustomTargetEvent(IN PDEVICE_OBJECT DeviceObject,
                       IN OUT PKEVENT SyncEvent OPTIONAL,
                       IN OUT PNTSTATUS SyncStatus OPTIONAL,
                       IN PDEVICE_CHANGE_COMPLETE_CALLBACK Callback OPTIONAL,
                       IN PVOID Context OPTIONAL,
                       IN PTARGET_DEVICE_CUSTOM_NOTIFICATION NotificationStructure);

/* PRIVATE FUNCTIONS *********************************************************/

PWCHAR
IopGetInterfaceTypeString(INTERFACE_TYPE IfType)
{
    switch (IfType)
    {
       case Internal:
         return L"Internal";

       case Isa:
         return L"Isa";

       case Eisa:
         return L"Eisa";

       case MicroChannel:
         return L"MicroChannel";

       case TurboChannel:
         return L"TurboChannel";

       case PCIBus:
         return L"PCIBus";

       case VMEBus:
         return L"VMEBus";

       case NuBus:
         return L"NuBus";

       case PCMCIABus:
         return L"PCMCIABus";

       case CBus:
         return L"CBus";

       case MPIBus:
         return L"MPIBus";

       case MPSABus:
         return L"MPSABus";

       case ProcessorInternal:
         return L"ProcessorInternal";

       case PNPISABus:
         return L"PNPISABus";

       case PNPBus:
         return L"PNPBus";

       case Vmcs:
         return L"Vmcs";

       default:
         DPRINT1("Invalid bus type: %d\n", IfType);
         return NULL;
    }
}

VOID
NTAPI
IopReportTargetDeviceChangeAsyncWorker(PVOID Context)
{
  PINTERNAL_WORK_QUEUE_ITEM Item;

  Item = (PINTERNAL_WORK_QUEUE_ITEM)Context;
  PpSetCustomTargetEvent(Item->PhysicalDeviceObject, NULL, NULL, Item->Callback, Item->Context, Item->NotificationStructure);
  ObDereferenceObject(Item->PhysicalDeviceObject);
  ExFreePoolWithTag(Context, '  pP');
}

NTSTATUS
PpSetCustomTargetEvent(IN PDEVICE_OBJECT DeviceObject,
                       IN OUT PKEVENT SyncEvent OPTIONAL,
                       IN OUT PNTSTATUS SyncStatus OPTIONAL,
                       IN PDEVICE_CHANGE_COMPLETE_CALLBACK Callback OPTIONAL,
                       IN PVOID Context OPTIONAL,
                       IN PTARGET_DEVICE_CUSTOM_NOTIFICATION NotificationStructure)
{
    ASSERT(NotificationStructure != NULL);
    ASSERT(DeviceObject != NULL);

    if (SyncEvent)
    {
        ASSERT(SyncStatus);
        *SyncStatus = STATUS_PENDING;
    }

    /* That call is totally wrong but notifications handler must be fixed first */
    IopNotifyPlugPlayNotification(DeviceObject,
                                  EventCategoryTargetDeviceChange,
                                  &GUID_PNP_CUSTOM_NOTIFICATION,
                                  NotificationStructure,
                                  NULL);

    if (SyncEvent)
    {
        KeSetEvent(SyncEvent, IO_NO_INCREMENT, FALSE);
        *SyncStatus = STATUS_SUCCESS;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PpCreateLegacyDeviceIds(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PUNICODE_STRING ServiceName,
    _In_ PCM_RESOURCE_LIST ResourceList)
{
    PPNP_LEGACY_DEVICE_EXTENSION DeviceExtension;
    INTERFACE_TYPE InterfaceType;
    PWCHAR BusName;
    WCHAR Buffer[200];
    size_t Remaining = sizeof(Buffer);
    PWCHAR EndBuffer;
    PWCHAR Id = NULL;
    ULONG Length;

    DPRINT("PpCreateLegacyDeviceIds: DeviceObject - %p, ServiceName - %wZ\n",
           DeviceObject, ServiceName);

    if (ResourceList)
    {
        InterfaceType = ResourceList->List[0].InterfaceType;

        if (InterfaceType > MaximumInterfaceType ||
            InterfaceType < InterfaceTypeUndefined)
        {
            InterfaceType = MaximumInterfaceType;
        }
    }
    else
    {
        InterfaceType = Internal;
    }

    BusName = IopGetBusName(InterfaceType);
    DPRINT("PpCreateLegacyDeviceIds: InterfaceType - %S\n", BusName);

    RtlZeroMemory(Buffer, sizeof(Buffer));
    RtlStringCbPrintfExW(Buffer,
                         Remaining,
                         &EndBuffer,
                         &Remaining,
                         0,
                         L"%ws%ws\\%wZ",
                         L"DETECTED",
                         BusName,
                         ServiceName);
    DPRINT("PpCreateLegacyDeviceIds: Buffer - %S\n", Buffer);

    EndBuffer++;
    Remaining -= sizeof(UNICODE_NULL);

    RtlStringCbPrintfExW(EndBuffer,
                         Remaining,
                         NULL,
                         &Remaining,
                         0,
                         L"%ws\\%wZ",
                         L"DETECTED",
                         ServiceName);
    DPRINT("PpCreateLegacyDeviceIds: EndBuffer - %S\n", EndBuffer);

    Length = sizeof(Buffer) - (Remaining - 2 * sizeof(UNICODE_NULL));

    Id = ExAllocatePoolWithTag(PagedPool, Length, 'oipP');
    if (!Id)
    {
        DPRINT("PpCreateLegacyDeviceIds: error\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(Id, Buffer, Length);

    DeviceExtension = DeviceObject->DeviceExtension;
    DeviceExtension->CompatibleIDs = Id;
    DeviceExtension->CompatibleIdsLenght = Length;

    return STATUS_SUCCESS;
}

/* PUBLIC FUNCTIONS **********************************************************/

/*
 * @implemented
 */
NTSTATUS
NTAPI
IoReportDetectedDevice(IN PDRIVER_OBJECT DriverObject,
                       IN INTERFACE_TYPE LegacyBusType,
                       IN ULONG BusNumber,
                       IN ULONG SlotNumber,
                       IN PCM_RESOURCE_LIST ResourceList,
                       IN PIO_RESOURCE_REQUIREMENTS_LIST ResourceRequirements OPTIONAL,
                       IN BOOLEAN ResourceAssigned,
                       IN OUT PDEVICE_OBJECT *DeviceObject OPTIONAL)
{
    UNICODE_STRING DriverName;
    UNICODE_STRING EnumKeyName = RTL_CONSTANT_STRING(ENUM_ROOT);
    UNICODE_STRING InstancePath;
    UNICODE_STRING InstanceSubKeyName;
    UNICODE_STRING ValueName;
    PUNICODE_STRING ServiceKeyName;
    PUNICODE_STRING LegacyServiceName;
    PDEVICE_OBJECT Pdo;
    PDEVICE_NODE DeviceNode;
    HANDLE EnumKeyHandle;
    HANDLE EnumServiceHandle;
    HANDLE InstanceKeyHandle;
    HANDLE InstanceControlKeyHandle;
    HANDLE Handle;
    PWSTR serviceKeyName;
    PWSTR NameString;
    ULONG Disposition;
    ULONG Data;
    WCHAR Buffer[200];
    PWCHAR BufferEnd;
    ULONG Length;
    NTSTATUS Status;
    SIZE_T ResourceListSize = 0;
    BOOLEAN IsNeedCleanup = FALSE;

    PAGED_CODE();
    DPRINT("IoReportDetectedDevice: ResourceAssigned - %X, DeviceObject - %p\n",
           ResourceAssigned, DeviceObject ? *DeviceObject : NULL);

    if (*DeviceObject)
    {
        /* Caller supplies a PDO, the PnP manager does not create a new PDO */
        Pdo = *DeviceObject;

        DeviceNode = IopGetDeviceNode(Pdo);
        if (!DeviceNode)
        {
            DPRINT("IoReportDetectedDevice: STATUS_NO_SUCH_DEVICE \n");
            return STATUS_NO_SUCH_DEVICE;
        }

        DPRINT("IoReportDetectedDevice: DeviceNode - %X\n", DeviceNode);
        ASSERT(FALSE);
        goto AssignResources;
    }

    *DeviceObject = NULL;

    ServiceKeyName = &DriverObject->DriverExtension->ServiceKeyName;
    DPRINT("IoReportDetectedDevice: ServiceKeyName - %wZ\n", ServiceKeyName);

    if (DriverObject->Flags & DRVO_BUILTIN_DRIVER)
    {
        BufferEnd = &ServiceKeyName->Buffer[(ServiceKeyName->Length / sizeof(WCHAR)) - 1];
        DriverName.Length = 0;

        while (*BufferEnd != '\\')
        {
            if (BufferEnd == ServiceKeyName->Buffer)
            {
                DPRINT("IoReportDetectedDevice: error\n");
                return STATUS_UNSUCCESSFUL;
            }

            BufferEnd--;
            DriverName.Length += sizeof(WCHAR);
        }

        if (BufferEnd == ServiceKeyName->Buffer)
        {
            DPRINT("IoReportDetectedDevice: error\n");
            return STATUS_UNSUCCESSFUL;
        }

        DriverName.Buffer = BufferEnd + 1;
        DriverName.MaximumLength = DriverName.Length + sizeof(WCHAR);
    }
    else
    {
        DPRINT("IoReportDetectedDevice: ASSERT(FALSE)\n");
        ASSERT(FALSE);
        goto AssignResources;
    }

    Status = IoCreateDevice(IopRootDriverObject,
                            sizeof(IOPNP_DEVICE_EXTENSION),
                            NULL,
                            FILE_DEVICE_CONTROLLER,
                            FILE_AUTOGENERATED_DEVICE_NAME,
                            FALSE,
                            &Pdo);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IoReportDetectedDevice: Status - %p\n", Status);
        return Status;
    }

    Pdo->Flags |= DO_BUS_ENUMERATED_DEVICE;

    DeviceNode = PipAllocateDeviceNode(Pdo);

    if (DeviceNode == NULL) //|| PpSystemHiveTooLarge)
    {
        DPRINT("IoReportDetectedDevice: error\n");
        IoDeleteDevice(Pdo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!(DriverObject->Flags & DRVO_BUILTIN_DRIVER))
    {
        DPRINT("IoReportDetectedDevice: FIXME IopDeleteLegacyKey()\n");
        ASSERT(FALSE);
        LegacyServiceName = &DriverObject->DriverExtension->ServiceKeyName;
    }
    else
    {
        LegacyServiceName = &DriverName;
    }

    Status = PpCreateLegacyDeviceIds(Pdo, LegacyServiceName, ResourceList);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("IoReportDetectedDevice: Status - %p\n", Status);
        IoDeleteDevice(*DeviceObject);
        return Status;
    }

    if (DriverObject->Flags & DRVO_BUILTIN_DRIVER)
    {
        NameString = DriverName.Buffer;
    }
    else
    {
        NameString = ServiceKeyName->Buffer;
    }

    RtlZeroMemory(Buffer, sizeof(Buffer));

    RtlStringCbPrintfExW(Buffer,
                         sizeof(Buffer) / sizeof(WCHAR),
                         &BufferEnd,
                         NULL,
                         0,
                         L"Root\\%ws",
                         NameString);

    Length = (ULONG)(BufferEnd - Buffer);
    ASSERT(Length <= (sizeof(Buffer) - sizeof(L"Root\\")));

    InstancePath.Length = Length * sizeof(WCHAR);
    InstancePath.MaximumLength = sizeof(Buffer);
    InstancePath.Buffer = Buffer;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&PpRegistryDeviceResource, TRUE);

    Status = IopOpenRegistryKeyEx(&EnumKeyHandle,
                                  NULL,
                                  &EnumKeyName,
                                  KEY_ALL_ACCESS);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("IoReportDetectedDevice: Status - %p\n", Status);
        ExReleaseResourceLite(&PpRegistryDeviceResource);
        KeLeaveCriticalRegion();
        IoDeleteDevice(*DeviceObject);
        return Status;
    }

    Status = IopCreateRegistryKeyEx(&EnumServiceHandle,
                                    EnumKeyHandle,
                                    &InstancePath,
                                    KEY_ALL_ACCESS,
                                    REG_OPTION_NON_VOLATILE,
                                    &Disposition);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("IoReportDetectedDevice: Status - %p\n", Status);
        ZwClose(EnumKeyHandle);
        ExReleaseResourceLite(&PpRegistryDeviceResource);
        KeLeaveCriticalRegion();
        IoDeleteDevice(*DeviceObject);
        return Status;
    }

    InstancePath.Buffer[InstancePath.Length / sizeof(WCHAR)] = '\\';
    InstancePath.Length += sizeof(WCHAR);
    DPRINT("IoReportDetectedDevice: InstancePath - %wZ\n", &InstancePath);

    if (Disposition != REG_CREATED_NEW_KEY)
    {
        DPRINT("IoReportDetectedDevice: ASSERT\n");
        ASSERT(FALSE);
    }
    else
    {
        RtlStringCbPrintfExW(Buffer + (InstancePath.Length / sizeof(WCHAR)),
                             sizeof(Buffer) - InstancePath.Length,
                             &BufferEnd,
                             NULL,
                             0,
                             L"%04u",
                             0);

        RtlInitUnicodeString(&InstanceSubKeyName,
                             Buffer + (InstancePath.Length / sizeof(WCHAR)));

        InstancePath.Length = (ULONG)(BufferEnd - Buffer) * sizeof(WCHAR);

        DPRINT("IoReportDetectedDevice: InstanceSubKeyName - %wZ\n", &InstanceSubKeyName);

        Status = IopCreateRegistryKeyEx(&InstanceKeyHandle,
                                        EnumServiceHandle,
                                        &InstanceSubKeyName,
                                        KEY_ALL_ACCESS,
                                        REG_OPTION_NON_VOLATILE,
                                        &Disposition);
        ZwClose(EnumServiceHandle);

        if (!NT_SUCCESS(Status))
        {
            DPRINT("IoReportDetectedDevice: Status - %p\n", Status);
            ZwClose(EnumKeyHandle);
            ExReleaseResourceLite(&PpRegistryDeviceResource);
            KeLeaveCriticalRegion();
            IoDeleteDevice(*DeviceObject);
            return Status;
        }

        ASSERT(Disposition == REG_CREATED_NEW_KEY);

        IsNeedCleanup = TRUE;

        if (ResourceAssigned)
        {
            Data = 1;
            RtlInitUnicodeString(&ValueName, L"NoResourceAtInitTime");
            ZwSetValueKey(InstanceKeyHandle,
                          &ValueName,
                          0,
                          REG_DWORD,
                          &Data,
                          sizeof(Data));
        }

        Handle = NULL;
        RtlInitUnicodeString(&ValueName, L"LogConf");
        Status = IopCreateRegistryKeyEx(&Handle,
                                        InstanceKeyHandle,
                                        &ValueName,
                                        KEY_ALL_ACCESS,
                                        REG_OPTION_NON_VOLATILE,
                                        NULL);
        if (NT_SUCCESS(Status))
        {
            if (ResourceList)
            {
                RtlInitUnicodeString(&ValueName, L"BootConfig");
                ResourceListSize = PnpDetermineResourceListSize(ResourceList);
                ZwSetValueKey(Handle,
                              &ValueName,
                              0,
                              REG_RESOURCE_LIST,
                              ResourceList,
                              ResourceListSize);
            }

            if (ResourceRequirements)
            {
                RtlInitUnicodeString(&ValueName, L"BasicConfigVector");
                ZwSetValueKey(Handle,
                              &ValueName,
                              0,
                              REG_RESOURCE_REQUIREMENTS_LIST,
                              ResourceRequirements,
                              ResourceRequirements->ListSize);
            }
        }
        else
        {
            ASSERT(Status == STATUS_SUCCESS);
        }

        Data = 0x400;
        RtlInitUnicodeString(&ValueName, L"ConfigFlags");
        ZwSetValueKey(InstanceKeyHandle,
                      &ValueName,
                      0,
                      REG_DWORD,
                      &Data,
                      sizeof(Data));
        Data = 0;
        RtlInitUnicodeString(&ValueName, L"Legacy");
        ZwSetValueKey(InstanceKeyHandle,
                      &ValueName,
                      0,
                      REG_DWORD,
                      &Data,
                      sizeof(Data));

        InstanceControlKeyHandle = NULL;
        RtlInitUnicodeString(&ValueName, L"Control");
        Status = IopCreateRegistryKeyEx(&InstanceControlKeyHandle,
                                        InstanceKeyHandle,
                                        &ValueName,
                                        KEY_ALL_ACCESS,
                                        REG_OPTION_VOLATILE,
                                        NULL);

        ASSERT(Status == STATUS_SUCCESS);

        Data = 1;
        RtlInitUnicodeString(&ValueName, L"DeviceReported");
        ZwSetValueKey(InstanceControlKeyHandle,
                      &ValueName,
                      0,
                      REG_DWORD,
                      &Data,
                      sizeof(Data));

        Status = ZwSetValueKey(InstanceKeyHandle,
                               &ValueName,
                               0,
                               REG_DWORD,
                               &Data,
                               sizeof(Data));

        ZwClose(EnumKeyHandle);


        serviceKeyName = ExAllocatePoolWithTag(PagedPool,
                                               ServiceKeyName->Length + sizeof(WCHAR),
                                               '  pP');
        if (!serviceKeyName)
        {
            ExReleaseResourceLite(&PpRegistryDeviceResource);
            KeLeaveCriticalRegion();
            goto Cleanup;
        }

        RtlMoveMemory(serviceKeyName,
                      ServiceKeyName->Buffer,
                      ServiceKeyName->Length);
        serviceKeyName[ServiceKeyName->Length / sizeof(WCHAR)] = UNICODE_NULL;

        RtlInitUnicodeString(&ValueName, L"Service");
        ZwSetValueKey(InstanceKeyHandle,
                      &ValueName,
                      0,
                      REG_SZ,
                      serviceKeyName,
                      ServiceKeyName->Length + sizeof(WCHAR));

        if (DriverObject->Flags & DRVO_BUILTIN_DRIVER)
        {
            DeviceNode->ServiceName = *ServiceKeyName;
            DPRINT("IoReportDetectedDevice: DeviceNode->ServiceName - %wZ\n",
                   &DeviceNode->ServiceName);
        }
        else
        {
            ExFreePoolWithTag(serviceKeyName, '  pP');
        }

        ExReleaseResourceLite(&PpRegistryDeviceResource);
        KeLeaveCriticalRegion();

        if (!(DriverObject->Flags & DRVO_BUILTIN_DRIVER))
        {
            PpDeviceRegistration(&InstancePath, TRUE, &DeviceNode->ServiceName);
        }

        Status = PnpConcatenateUnicodeStrings(&DeviceNode->InstancePath,
                                              &InstancePath,
                                              NULL);
        DPRINT("IoReportDetectedDevice: DeviceNode->InstancePath - %wZ\n",
               &DeviceNode->InstancePath);

        if (!NT_SUCCESS(Status))
        {
            DPRINT("IoReportDetectedDevice: Error. Status - %p\n", Status);
            DeviceNode->InstancePath.Length = 0;
            DeviceNode->InstancePath.MaximumLength = 0;
            IoDeleteDevice(Pdo);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        DeviceNode->Flags = DNF_MADEUP + DNF_ENUMERATED;
        PipSetDevNodeState(DeviceNode, DeviceNodeInitialized, NULL);
        PpDevNodeInsertIntoTree(IopRootDeviceNode, DeviceNode);

        Status = IopMapDeviceObjectToDeviceInstance(Pdo, &DeviceNode->InstancePath);
        ASSERT(Status == STATUS_SUCCESS);
        ObReferenceObject(Pdo);

        DPRINT("IoReportDetectedDevice: FIXME IopNotifySetupDeviceArrival()\n");

        /* Report the device's enumeration to umpnpmgr */
         IopQueueTargetDeviceEvent(&GUID_DEVICE_ENUMERATED,
                                   &DeviceNode->InstancePath);

         /* Report the device's arrival to umpnpmgr */
         IopQueueTargetDeviceEvent(&GUID_DEVICE_ARRIVAL,
                                   &DeviceNode->InstancePath);

AssignResources:
        DPRINT("IoReportDetectedDevice: AssignResources\n");

        if (ResourceAssigned)
        {
            ASSERT(FALSE);
            DeviceNode->Flags |= DNF_NO_RESOURCE_REQUIRED;

            if (ResourceList)
            {
                DPRINT("IoReportDetectedDevice: FIXME IopDetermineResourceListSize()\n");
                DPRINT("IoReportDetectedDevice: FIXME IopWriteAllocatedResourcesToRegistry()\n");
                DPRINT("IoReportDetectedDevice: ASSERT(FALSE)\n");
                ASSERT(FALSE);
            }
        }
        else if (ResourceList &&
                 ResourceList->Count &&
                 ResourceList->List[0].PartialResourceList.Count)
        {
            DPRINT("IoReportDetectedDevice: ASSERT(FALSE)\n");
            ASSERT(FALSE);
        }
        else
        {
            if (DriverObject)
            {
                ASSERT(ResourceRequirements == NULL);
            }

            DeviceNode->Flags |= DNF_NO_RESOURCE_REQUIRED;
        }

        if (NT_SUCCESS(Status))
        {
            DPRINT("IoReportDetectedDevice: FIXME IopDoDeferredSetInterfaceState()\n");

            PipSetDevNodeState(DeviceNode, DeviceNodeStartPostWork, NULL);

            *DeviceObject = Pdo;

            if (IsNeedCleanup)
            {
                if (InstanceControlKeyHandle)
                {
                    ZwClose(InstanceControlKeyHandle);
                }
                if (Handle)
                {
                    ZwClose(Handle);
                }
                ZwClose(InstanceKeyHandle);
            }

            PipRequestDeviceAction(Pdo,
                                   PipEnumDeviceOnly,
                                   0,
                                   0,
                                   NULL,
                                   NULL);
            return Status;
        }

Cleanup:
        DPRINT("IoReportDetectedDevice: FIXME IopReleaseDeviceResources()\n");

        if (IsNeedCleanup)
        {
            IoDeleteDevice(Pdo);

            if (InstanceControlKeyHandle)
            {
                ZwDeleteKey(InstanceControlKeyHandle);
            }
            if (Handle)
            {
                ZwDeleteKey(Handle);
            }
            if (InstanceKeyHandle)
            {
                ZwDeleteKey(InstanceKeyHandle);
            }
        }

        DPRINT("IoReportDetectedDevice: ASSERT(FALSE)\n");
        ASSERT(FALSE);
    }

    return STATUS_SUCCESS;
}

/*
 * @halfplemented
 */
NTSTATUS
NTAPI
IoReportResourceForDetection(IN PDRIVER_OBJECT DriverObject,
                             IN PCM_RESOURCE_LIST DriverList OPTIONAL,
                             IN ULONG DriverListSize OPTIONAL,
                             IN PDEVICE_OBJECT DeviceObject OPTIONAL,
                             IN PCM_RESOURCE_LIST DeviceList OPTIONAL,
                             IN ULONG DeviceListSize OPTIONAL,
                             OUT PBOOLEAN ConflictDetected)
{
    PCM_RESOURCE_LIST ResourceList;
    NTSTATUS Status;

    *ConflictDetected = FALSE;

    if (!DriverList && !DeviceList)
        return STATUS_INVALID_PARAMETER;

    /* Find the real list */
    if (!DriverList)
        ResourceList = DeviceList;
    else
        ResourceList = DriverList;

    /* Look for a resource conflict */
    Status = IopDetectResourceConflict(ResourceList, FALSE, NULL);
    if (Status == STATUS_CONFLICTING_ADDRESSES)
    {
        /* Oh noes */
        *ConflictDetected = TRUE;
    }
    else if (NT_SUCCESS(Status))
    {
        /* Looks like we're good to go */

        /* TODO: Claim the resources in the ResourceMap */
    }

    return Status;
}

VOID
NTAPI
IopSetEvent(IN PVOID Context)
{
    PKEVENT Event = Context;

    /* Set the event */
    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
IoReportTargetDeviceChange(IN PDEVICE_OBJECT PhysicalDeviceObject,
                           IN PVOID NotificationStructure)
{
    KEVENT NotifyEvent;
    NTSTATUS Status, NotifyStatus;
    PTARGET_DEVICE_CUSTOM_NOTIFICATION notifyStruct = (PTARGET_DEVICE_CUSTOM_NOTIFICATION)NotificationStructure;

    ASSERT(notifyStruct);

    /* Check for valid PDO */
    if (!IopIsValidPhysicalDeviceObject(PhysicalDeviceObject))
    {
        KeBugCheckEx(PNP_DETECTED_FATAL_ERROR, 0x2, (ULONG_PTR)PhysicalDeviceObject, 0, 0);
    }

    /* FileObject must be null. PnP will fill in it */
    ASSERT(notifyStruct->FileObject == NULL);

    /* Do not handle system PnP events */
    if ((RtlCompareMemory(&(notifyStruct->Event), &(GUID_TARGET_DEVICE_QUERY_REMOVE), sizeof(GUID)) != sizeof(GUID)) ||
        (RtlCompareMemory(&(notifyStruct->Event), &(GUID_TARGET_DEVICE_REMOVE_CANCELLED), sizeof(GUID)) != sizeof(GUID)) ||
        (RtlCompareMemory(&(notifyStruct->Event), &(GUID_TARGET_DEVICE_REMOVE_COMPLETE), sizeof(GUID)) != sizeof(GUID)))
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (notifyStruct->Version != 1)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    /* Initialize even that will let us know when PnP will have finished notify */
    KeInitializeEvent(&NotifyEvent, NotificationEvent, FALSE);

    Status = PpSetCustomTargetEvent(PhysicalDeviceObject, &NotifyEvent, &NotifyStatus, NULL, NULL, notifyStruct);
    /* If no error, wait for the notify to end and return the status of the notify and not of the event */
    if (NT_SUCCESS(Status))
    {
        KeWaitForSingleObject(&NotifyEvent, Executive, KernelMode, FALSE, NULL);
        Status = NotifyStatus;
    }

    return Status;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
IoReportTargetDeviceChangeAsynchronous(IN PDEVICE_OBJECT PhysicalDeviceObject,
                                       IN PVOID NotificationStructure,
                                       IN PDEVICE_CHANGE_COMPLETE_CALLBACK Callback OPTIONAL,
                                       IN PVOID Context OPTIONAL)
{
    PINTERNAL_WORK_QUEUE_ITEM Item = NULL;
    PTARGET_DEVICE_CUSTOM_NOTIFICATION notifyStruct = (PTARGET_DEVICE_CUSTOM_NOTIFICATION)NotificationStructure;

    ASSERT(notifyStruct);

    /* Check for valid PDO */
    if (!IopIsValidPhysicalDeviceObject(PhysicalDeviceObject))
    {
        KeBugCheckEx(PNP_DETECTED_FATAL_ERROR, 0x2, (ULONG_PTR)PhysicalDeviceObject, 0, 0);
    }

    /* FileObject must be null. PnP will fill in it */
    ASSERT(notifyStruct->FileObject == NULL);

    /* Do not handle system PnP events */
    if ((RtlCompareMemory(&(notifyStruct->Event), &(GUID_TARGET_DEVICE_QUERY_REMOVE), sizeof(GUID)) != sizeof(GUID)) ||
        (RtlCompareMemory(&(notifyStruct->Event), &(GUID_TARGET_DEVICE_REMOVE_CANCELLED), sizeof(GUID)) != sizeof(GUID)) ||
        (RtlCompareMemory(&(notifyStruct->Event), &(GUID_TARGET_DEVICE_REMOVE_COMPLETE), sizeof(GUID)) != sizeof(GUID)))
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (notifyStruct->Version != 1)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    /* We need to store all the data given by the caller with the WorkItem, so use our own struct */
    Item = ExAllocatePoolWithTag(NonPagedPool, sizeof(INTERNAL_WORK_QUEUE_ITEM), '  pP');
    if (!Item) return STATUS_INSUFFICIENT_RESOURCES;

    /* Initialize all stuff */
    ObReferenceObject(PhysicalDeviceObject);
    Item->NotificationStructure = notifyStruct;
    Item->PhysicalDeviceObject = PhysicalDeviceObject;
    Item->Callback = Callback;
    Item->Context = Context;
    ExInitializeWorkItem(&(Item->WorkItem), IopReportTargetDeviceChangeAsyncWorker, Item);

    /* Finally, queue the item, our work here is done */
    ExQueueWorkItem(&(Item->WorkItem), DelayedWorkQueue);

    return STATUS_PENDING;
}
