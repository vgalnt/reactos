/*
 * PROJECT:         ReactOS Kernel
 * COPYRIGHT:       GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/pnpmgr/pnpenum.c
 * PURPOSE:         Device enumeration functions
 * PROGRAMMERS:     
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#include "../pnpio.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

extern PNP_ALLOCATE_RESOURCES_ROUTINE IopAllocateBootResourcesRoutine;

extern ERESOURCE PpRegistryDeviceResource;

extern KSPIN_LOCK IopPnPSpinLock;
extern LIST_ENTRY IopPnpEnumerationRequestList;
extern KEVENT PiEnumerationLock;
extern BOOLEAN PnPBootDriversLoaded;
extern BOOLEAN PiCriticalDeviceDatabaseEnabled;

/* DATA **********************************************************************/

WORK_QUEUE_ITEM PipDeviceEnumerationWorkItem;
BOOLEAN PipEnumerationInProgress;

/* FUNCTIONS *****************************************************************/

#define MAX_DEVICE_ID_LEN          200
#define MAX_SEPARATORS_INSTANCEID  0
#define MAX_SEPARATORS_DEVICEID    1
#define MAX_SEPARATORS_MULTI_SZ    -1

ULONG
NTAPI
PiFixupID(
    _In_ PWCHAR Id,
    _In_ ULONG MaxIdLen,
    _In_ BOOLEAN IsMultiSz,
    _In_ ULONG MaxSeparators,
    _In_ PUNICODE_STRING ServiceName)
{
    PWCHAR PtrPrevChar;
    PWCHAR PtrChar;
    PWCHAR StringEnd;
    WCHAR Char;
    ULONG SeparatorsCount;

    PAGED_CODE();
    DPRINT("PiFixupID: Id - %S\n", Id);

    SeparatorsCount = MAX_SEPARATORS_INSTANCEID;
    StringEnd = Id + MAX_DEVICE_ID_LEN;
    PtrPrevChar = NULL;

    for (PtrChar = Id; PtrChar < StringEnd; PtrChar++)
    {
        Char = *PtrChar;

        if (Char == UNICODE_NULL)
        {
            if (!IsMultiSz || (PtrPrevChar && PtrChar == PtrPrevChar + 1))
            {
                if (PtrChar < StringEnd &&
                    (MaxSeparators == MAX_SEPARATORS_MULTI_SZ ||
                     MaxSeparators == SeparatorsCount))
                {
                    return (PtrChar - Id) + 1;
                }

                break;
            }

            StringEnd += MAX_DEVICE_ID_LEN;
            PtrPrevChar = PtrChar;
        }
        else if (Char == ' ')
        {
            *PtrChar = '_';
        }
        else if (Char < ' ' || Char > 0x7Fu || Char == ',')
        {
            DPRINT("PiFixupID: Invalid character - %02X\n", *PtrChar);

            if (ServiceName)
            {
                DPRINT("PiFixupID: FIXME Log\n");
                ASSERT(FALSE);
                return 0;
            }

            return 0;
        }
        else if (Char == '\\')
        {
            SeparatorsCount++;

            if (SeparatorsCount > MaxSeparators)
            {
                DPRINT("PiFixupID: SeparatorsCount - %X, MaxSeparators - %X\n",
                       SeparatorsCount, MaxSeparators);

                if (ServiceName)
                {
                    DPRINT("PiFixupID: FIXME Log\n");
                    ASSERT(FALSE);
                }

                return 0;
            }
        }
    }

    DPRINT("PiFixupID: ID (%p) not valid\n", Id);

    if (ServiceName)
    {
        DPRINT("PiFixupID: FIXME Log\n");
        ASSERT(FALSE);
    }

    return 0;
}

NTSTATUS
NTAPI
PpQueryID(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ BUS_QUERY_ID_TYPE IdType,
    _Out_ PWCHAR *OutID,
    _In_ PULONG OutIdSize)
{
    PUNICODE_STRING ServiceName;
    ULONG MaxSeparators;
    SIZE_T Size;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PpQueryID: DeviceNode - %X, IdType - %X\n", DeviceNode, IdType);

    ASSERT(IdType == BusQueryDeviceID ||
           IdType == BusQueryInstanceID ||
           IdType == BusQueryHardwareIDs ||
           IdType == BusQueryCompatibleIDs);

    *OutIdSize = 0;

    Status = PpIrpQueryID(DeviceNode->PhysicalDeviceObject, IdType, OutID);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("PpQueryID: Status - %X\n", Status);
        goto ErrorExit;
    }

    switch (IdType)
    {
        case BusQueryDeviceID:
            ServiceName = &DeviceNode->Parent->ServiceName;
            MaxSeparators = MAX_SEPARATORS_DEVICEID;

            Size = PiFixupID(*OutID,
                             MAX_DEVICE_ID_LEN,
                             FALSE,
                             MaxSeparators,
                             ServiceName);

            *OutIdSize = Size * sizeof(WCHAR);
            break;

        case BusQueryHardwareIDs:
        case BusQueryCompatibleIDs:

            Size = PiFixupID(*OutID,
                             MAX_DEVICE_ID_LEN,
                             TRUE,
                             MAX_SEPARATORS_MULTI_SZ,
                             &DeviceNode->Parent->ServiceName);

            *OutIdSize = Size * sizeof(WCHAR);
            break;

        case BusQueryInstanceID:
            ServiceName = &DeviceNode->Parent->ServiceName;
            MaxSeparators = MAX_SEPARATORS_INSTANCEID;

            Size = PiFixupID(*OutID,
                             MAX_DEVICE_ID_LEN,
                             FALSE,
                             MaxSeparators,
                             ServiceName);

            *OutIdSize = Size * sizeof(WCHAR);
            break;

        default:
            *OutIdSize = 0;
            break;
    }

    if (*OutIdSize == 0)
    {
        Status = STATUS_PNP_INVALID_ID;
    }

    if (NT_SUCCESS(Status))
    {
        return Status;
    }

ErrorExit:

    DPRINT("PpIrpQueryID: Error Status %X\n", Status);

    if (Status == STATUS_PNP_INVALID_ID || IdType == BusQueryDeviceID)
    {
        DPRINT("PpIrpQueryID: Set CM_PROB_INVALID_DATA\n");
        PipSetDevNodeProblem(DeviceNode, CM_PROB_INVALID_DATA);

        if (!(DeviceNode->Parent->Flags & DNF_CHILD_WITH_INVALID_ID))
        {
            DeviceNode->Parent->Flags |= DNF_CHILD_WITH_INVALID_ID;

            DPRINT("PpIrpQueryID: FIXME PpSetInvalidIDEvent\n");
        }
    }

    if (Status == STATUS_PNP_INVALID_ID)
    {
        DPRINT("PpIrpQueryID: Invalid ID. ServiceName - %wZ\n",
               &DeviceNode->Parent->ServiceName);

        ASSERT(Status != STATUS_PNP_INVALID_ID);
    }
    else
    {
        if (IdType || Status == STATUS_INSUFFICIENT_RESOURCES)
        {
            if (*OutID)
            {
                ExFreePool(*OutID);
                *OutID = NULL;
                *OutIdSize = 0;
            }

            return Status;
        }

        DPRINT("PpIrpQueryID: FIXME Log\n");
        DPRINT("PpIrpQueryID: ServiceName - %wZ, Status - %X\n",
               &DeviceNode->Parent->ServiceName, Status);

        ASSERT(IdType != BusQueryDeviceID);
    }

    if (*OutID)
    {
        ExFreePool(*OutID);
        *OutID = NULL;
        *OutIdSize = 0;
    }

    return Status;
}

NTSTATUS
NTAPI
PpSaveDeviceCapabilities(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ PDEVICE_CAPABILITIES DeviceCapabilities)
{
    UNICODE_STRING ValueName;
    HANDLE KeyHandle = NULL;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PpSaveDeviceCapabilities: DeviceNode - %p, InstancePath - %wZ\n",
           DeviceNode, &DeviceNode->InstancePath);

    ASSERT(DeviceNode);
    ASSERT(DeviceCapabilities);

    Status = PnpDeviceObjectToDeviceInstance(DeviceNode->PhysicalDeviceObject,
                                             &KeyHandle,
                                             KEY_ALL_ACCESS);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("PpSaveDeviceCapabilities: Status - %X, Pdo - %p\n",
               Status, DeviceNode->PhysicalDeviceObject);

        ASSERT(NT_SUCCESS(Status));
        return Status;
    }

    ASSERT(KeyHandle);

    if (DeviceNode->Flags & DNF_HAS_BOOT_CONFIG)
    {
        DeviceCapabilities->SurpriseRemovalOK = 0;
    }

    DeviceNode->CapabilityFlags = *(PULONG)((ULONG_PTR)&DeviceCapabilities->Version +
                                            sizeof(DeviceCapabilities->Version));

    RtlInitUnicodeString(&ValueName, L"Capabilities");

    ZwSetValueKey(KeyHandle,
                  &ValueName,
                  0,
                  REG_DWORD,
                  &DeviceNode->CapabilityFlags,
                  sizeof(DeviceNode->CapabilityFlags));

    RtlInitUnicodeString(&ValueName, L"UINumber");

    if (DeviceCapabilities->UINumber == -1)
    {
        ZwDeleteValueKey(KeyHandle, &ValueName);
    }
    else
    {
        ZwSetValueKey(KeyHandle,
                      &ValueName,
                      0,
                      REG_DWORD,
                      &DeviceCapabilities->UINumber,
                      sizeof(DeviceCapabilities->UINumber));
    }

    ZwClose(KeyHandle);
    return Status;
}

NTSTATUS
NTAPI
IopQueryAndSaveDeviceNodeCapabilities(
    _In_ PDEVICE_NODE DeviceNode)
{
    DEVICE_CAPABILITIES DeviceCapabilities;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IopQueryAndSaveDeviceNodeCapabilities: DeviceNode - %p\n", DeviceNode);

    ASSERT(DeviceNode);

    Status = PpIrpQueryCapabilities(DeviceNode->PhysicalDeviceObject,
                                    &DeviceCapabilities);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopQueryAndSaveDeviceNodeCapabilities: Status - %X\n", Status);
        return Status;
    }

    Status = PpSaveDeviceCapabilities(DeviceNode, &DeviceCapabilities);

    return Status;
}

static
VOID
NTAPI
IopIncDisableableDepends(
    _In_ PDEVICE_NODE DeviceNode)
{
    PDEVICE_NODE node;

    for (node = DeviceNode;
         node && InterlockedIncrement((PLONG)&node->DisableableDepends) == 1;
         node = node->Parent)
    {
        ;
    }
}

static
VOID
NTAPI
IopDecDisableableDepends(
    _In_ PDEVICE_NODE DeviceNode)
{
    PDEVICE_NODE node;

    for (node = DeviceNode;
         node && !InterlockedDecrement((PLONG)&node->DisableableDepends);
         node = node->Parent)
    {
        ;
    }
}

NTSTATUS
NTAPI
PiProcessQueryDeviceState(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    PDEVICE_NODE DeviceNode;
    PNP_DEVICE_STATE State;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PiProcessQueryDeviceState: DeviceObject - %p\n", DeviceObject);

    Status = IopQueryDeviceState(DeviceObject, &State);

    if (!NT_SUCCESS(Status))
    {
        return STATUS_SUCCESS;
    }

    DeviceNode = IopGetDeviceNode(DeviceObject);

    if (State & PNP_DEVICE_DONT_DISPLAY_IN_UI)
    {
        DeviceNode->UserFlags |= DNUF_DONT_SHOW_IN_UI;
    }
    else
    {
        DeviceNode->UserFlags &= ~DNUF_DONT_SHOW_IN_UI;
    }

    if (State & PNP_DEVICE_NOT_DISABLEABLE)
    {
        DeviceNode->UserFlags = DeviceNode->UserFlags;

        if (!(DeviceNode->UserFlags & DNUF_NOT_DISABLEABLE))
        {
            DeviceNode->UserFlags = DeviceNode->UserFlags | DNUF_NOT_DISABLEABLE;
            IopIncDisableableDepends(DeviceNode);
        }
    }
    else
    {
        if (DeviceNode->UserFlags & DNUF_NOT_DISABLEABLE)
        {
            IopDecDisableableDepends(DeviceNode);
            DeviceNode->UserFlags &= ~DNUF_NOT_DISABLEABLE;
        }
    }

    if (State & (PNP_DEVICE_REMOVED | PNP_DEVICE_DISABLED))
    {
        DPRINT("PiProcessQueryDeviceState: FIXME PipRequestDeviceRemoval\n");
        ASSERT(FALSE);
        return STATUS_UNSUCCESSFUL;
    }

    if (State & PNP_DEVICE_RESOURCE_REQUIREMENTS_CHANGED)
    {
        DPRINT("PiProcessQueryDeviceState: FIXME IopResourceRequirementsChanged\n");
        ASSERT(FALSE);
    }
    else if (State & PNP_DEVICE_FAILED)
    {
        DPRINT("PiProcessQueryDeviceState: FIXME PipRequestDeviceRemoval\n");
        ASSERT(FALSE);
        return STATUS_UNSUCCESSFUL;
    }

    return Status;
}

static
BOOLEAN
NTAPI
PpCompareMultiLineIDs(
    _In_ PWCHAR Id1,
    _In_ PWCHAR Id2)
{

    for (;
         *Id2 != UNICODE_NULL;
         Id2 += wcslen(Id2) + 1, Id1 += wcslen(Id1) + 1)
    {
        if (*Id1 == UNICODE_NULL)
        {
            break;
        }

        if (_wcsicmp(Id2, Id1) != 0)
        {
            break;
        }
    }

    if (*Id2 != UNICODE_NULL || *Id1 != UNICODE_NULL)
    {
        DPRINT("PpCompareMultiLineIDs: different IDs\n");
        return TRUE;
    }

    return FALSE;
}

NTSTATUS
NTAPI
PipProcessStartPhase3(
    _In_ PDEVICE_NODE DeviceNode)
{
    KEY_VALUE_PARTIAL_INFORMATION ValuePartialInfo;
    PKEY_VALUE_FULL_INFORMATION ValueFullInfo;
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING ValueName;
    HANDLE KeyHandle;
    PWCHAR HardwareIDs;
    PWCHAR CompatibleIDs;
    PWCHAR PrevIDs;
    ULONG ResultLength;
    ULONG HardwareIDsSize;
    ULONG CompatibleIDsSize;
    ULONG ConfigFlags;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PipProcessStartPhase3: DeviceNode - %p, Instance - %wZ\n",
           DeviceNode,  &DeviceNode->InstancePath);

    DeviceObject = DeviceNode->PhysicalDeviceObject;

    if (DeviceNode->Flags & DNF_IDS_QUERIED)
    {
        DPRINT("PipProcessStartPhase3: DeviceNode->Flags & DNF_IDS_QUERIED\n");
        goto Exit;
    }

    Status = PnpDeviceObjectToDeviceInstance(DeviceObject, &KeyHandle, KEY_READ);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("PipProcessStartPhase3: Status - %X\n", Status);
        goto Exit;
    }

    PpQueryID(DeviceNode, BusQueryHardwareIDs, &HardwareIDs, &HardwareIDsSize);
    PpQueryID(DeviceNode, BusQueryCompatibleIDs, &CompatibleIDs, &CompatibleIDsSize);

    if (!HardwareIDs && !CompatibleIDs)
    {
        ZwClose(KeyHandle);
        DeviceNode->Flags |= DNF_IDS_QUERIED;
        goto Exit;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&PpRegistryDeviceResource, TRUE);

    RtlInitUnicodeString(&ValueName, L"ConfigFlags");

    Status = ZwQueryValueKey(KeyHandle,
                             &ValueName,
                             KeyValuePartialInformation,
                             &ValuePartialInfo,
                             sizeof(ValuePartialInfo) + sizeof(ULONG),
                             &ResultLength);

    if (NT_SUCCESS(Status) && ValuePartialInfo.Type == REG_DWORD)
    {
        ConfigFlags = ValuePartialInfo.Data[0];
    }
    else
    {
        ConfigFlags = 0;
    }

    if (HardwareIDs)
    {
        if (!(ConfigFlags & 0x400))
        {
            Status = IopGetRegistryValue(KeyHandle,
                                         L"HardwareID",
                                         &ValueFullInfo);

            if (NT_SUCCESS(Status))
            {
                if (ValueFullInfo->Type == REG_MULTI_SZ)
                {
                    PrevIDs = (PWCHAR)((ULONG_PTR)ValueFullInfo +
                                      ValueFullInfo->DataOffset);

                    if (PpCompareMultiLineIDs(HardwareIDs, PrevIDs))
                    {
                        DPRINT("PipProcessStartPhase3: HardwareID changed\n");
                        ConfigFlags |= 0x400;
                    }
                }

                ExFreePoolWithTag(ValueFullInfo, 'uspP');
            }
        }

        RtlInitUnicodeString(&ValueName, L"HardwareID");
        ZwSetValueKey(KeyHandle,
                      &ValueName,
                      0,
                      REG_MULTI_SZ,
                      HardwareIDs,
                      HardwareIDsSize);

        ExFreePoolWithTag(HardwareIDs, 0);
    }

    if (CompatibleIDs)
    {
        if (!(ConfigFlags & 0x400))
        {
            Status = IopGetRegistryValue(KeyHandle,
                                         L"CompatibleIDs",
                                         &ValueFullInfo);

            if (NT_SUCCESS(Status))
            {
                if (ValueFullInfo->Type == REG_MULTI_SZ)
                {
                    PrevIDs = (PWCHAR)((ULONG_PTR)ValueFullInfo +
                                      ValueFullInfo->DataOffset);

                    if (PpCompareMultiLineIDs(HardwareIDs, PrevIDs))
                    {
                        DPRINT("PipProcessStartPhase3: CompatibleID changed\n");
                        ConfigFlags |= 0x400;
                    }
                }

                ExFreePoolWithTag(ValueFullInfo, 'uspP');
            }
        }

        RtlInitUnicodeString(&ValueName, L"CompatibleIDs");
        ZwSetValueKey(KeyHandle,
                      &ValueName,
                      0,
                      REG_MULTI_SZ,
                      CompatibleIDs,
                      CompatibleIDsSize);

        ExFreePoolWithTag(CompatibleIDs, 0);
    }

    if (ConfigFlags & 0x400)
    {
        RtlInitUnicodeString(&ValueName, L"ConfigFlags");
        ZwSetValueKey(KeyHandle,
                      &ValueName,
                      0,
                      REG_DWORD,
                      &ConfigFlags,
                      sizeof(ConfigFlags));
    }

    ExReleaseResourceLite(&PpRegistryDeviceResource);
    KeLeaveCriticalRegion();

    ZwClose(KeyHandle);
    DeviceNode->Flags |= DNF_IDS_QUERIED;


Exit:

    if (DeviceNode->Flags & DNF_HAS_PROBLEM &&
        DeviceNode->Problem == CM_PROB_INVALID_DATA)
    {
        return STATUS_UNSUCCESSFUL;
    }

    DeviceNode->Flags |= DNF_REENUMERATE;

    IopQueryAndSaveDeviceNodeCapabilities(DeviceNode);

    Status = PiProcessQueryDeviceState(DeviceObject);

    DPRINT("PipProcessStartPhase3: FIXME PpSetPlugPlayEvent\n");
    //PpSetPlugPlayEvent(&GUID_DEVICE_ARRIVAL, DeviceNode->PhysicalDeviceObject);

    /* Report the device to the user-mode pnp manager */
    IopQueueTargetDeviceEvent(&GUID_DEVICE_ARRIVAL,//GUID_DEVICE_ENUMERATED
                              &DeviceNode->InstancePath);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    DPRINT("PipProcessStartPhase3: FIXME PpvUtilTestStartedPdoStack\n");
    //PpvUtilTestStartedPdoStack(DeviceObject);

    PipSetDevNodeState(DeviceNode, DeviceNodeStarted, NULL);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PipEnumerateCompleted(
    _In_ PDEVICE_NODE DeviceNode)
{
    PDEVICE_OBJECT DeviceObject;
    PEXTENDED_DEVOBJ_EXTENSION DeviceExt;
    PDEVICE_RELATIONS DeviceRelations;
    PDEVICE_NODE ChildDeviceNode;
    BOOLEAN RemovalChild;
    ULONG ix;
    BOOLEAN IsNoChildDeviceNode;

    PAGED_CODE();
    DPRINT("PipEnumerateCompleted: DeviceNode - %p\n", DeviceNode);

    if (!DeviceNode->OverUsed1.PendingDeviceRelations)
    {
        PipSetDevNodeState(DeviceNode, DeviceNodeStarted, NULL);
        return STATUS_SUCCESS;
    }

    for (ChildDeviceNode = DeviceNode->Child;
         ChildDeviceNode;
         ChildDeviceNode = ChildDeviceNode->Sibling)
    {
        ChildDeviceNode->Flags &= ~DNF_ENUMERATED;
    }

    for (ix = 0;
         ix < DeviceNode->OverUsed1.PendingDeviceRelations->Count;
         ix++)
    {
        DeviceRelations = DeviceNode->OverUsed1.PendingDeviceRelations;
        DeviceObject = DeviceRelations->Objects[ix];

        if (DeviceObject->Flags & DO_DEVICE_INITIALIZING)
        {
            DPRINT("PipEnumerateCompleted: DO_DEVICE_INITIALIZING! DeviceObject - %p\n",
                   DeviceObject);
        }

        DeviceExt = IoGetDevObjExtension(DeviceObject);

        if (DeviceExt->ExtensionFlags & DOE_DELETE_PENDING)
        {
            DPRINT("PipEnumerateCompleted: FIXME dump\n");
            ASSERT(FALSE);

            KeBugCheckEx(PNP_DETECTED_FATAL_ERROR,
                         4,
                         (ULONG_PTR)DeviceObject,
                         0,
                         0);
        }

        if (DeviceExt->DeviceNode)
        {
            ChildDeviceNode = DeviceExt->DeviceNode;
            ChildDeviceNode->Flags |= DNF_ENUMERATED;

            if (ChildDeviceNode->DockInfo.DockStatus == DOCK_EJECTIRP_COMPLETED)
            {
                DPRINT("PipEnumerateCompleted: FIXME PpProfileCancelTransitioningDock\n");
                ASSERT(FALSE);
            }

            ASSERT(!(ChildDeviceNode->Flags & DNF_DEVICE_GONE));

            ObDereferenceObject(DeviceObject);
        }
        else
        {
            ChildDeviceNode = PipAllocateDeviceNode(DeviceObject);
            DPRINT("PipEnumerateCompleted: ChildDeviceNode - %p\n", ChildDeviceNode);

            if (ChildDeviceNode)
            {
                ChildDeviceNode->Flags |= DNF_ENUMERATED;
                DeviceObject->Flags |= DO_BUS_ENUMERATED_DEVICE;

                PpDevNodeInsertIntoTree(DeviceNode, ChildDeviceNode);

                DPRINT("PipEnumerateCompleted: FIXME PpSystemHiveTooLarge\n");
            }
            else
            {
                DPRINT1("PipEnumerateCompleted: Not allocated device node!\n");
                ObDereferenceObject(DeviceObject);
            }
        }
    }

    ExFreePoolWithTag(DeviceNode->OverUsed1.PendingDeviceRelations, 0);
    DeviceNode->OverUsed1.PendingDeviceRelations = NULL;

    RemovalChild = FALSE;
    ChildDeviceNode = DeviceNode->Child;

    for (IsNoChildDeviceNode = ChildDeviceNode == NULL;
         IsNoChildDeviceNode == FALSE;
         IsNoChildDeviceNode = ChildDeviceNode == NULL)
    {
        if (!(ChildDeviceNode->Flags & DNF_ENUMERATED) &&
            !(ChildDeviceNode->Flags & DNF_DEVICE_GONE))
        {
            ChildDeviceNode->Flags |= DNF_DEVICE_GONE;

            DPRINT1("PipEnumerateCompleted: FIXME PipRequestDeviceRemoval\n");
            ASSERT(FALSE);

            RemovalChild = TRUE;
        }

        ChildDeviceNode = ChildDeviceNode->Sibling;
    }

    ASSERT(DeviceNode->State == DeviceNodeEnumerateCompletion);
    PipSetDevNodeState(DeviceNode, DeviceNodeStarted, NULL);

    if (RemovalChild && DeviceNode != IopRootDeviceNode)
    {
        return STATUS_PNP_RESTART_ENUMERATION;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PpQueryDeviceID(
    _In_ PDEVICE_NODE DeviceNode,
    _Out_ PWCHAR *OutFullDeviceID,
    _Out_ PWCHAR *OutDeviceID)
{
    PWCHAR Id;
    PWCHAR Separator;
    ULONG IdLength;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PpQueryDeviceID: DeviceNode - %p\n", DeviceNode);

    *OutFullDeviceID = NULL;
    *OutDeviceID = NULL;

    Status = PpQueryID(DeviceNode, BusQueryDeviceID, &Id, &IdLength);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("PpQueryDeviceID: Status - %p\n", Status);
        ASSERT(Id == NULL && IdLength == 0);
        return Status;
    }

    ASSERT(Id && IdLength);

    *OutFullDeviceID = Id;

    Separator = wcschr(Id, L'\\');
    ASSERT(Separator);
    *Separator = UNICODE_NULL;

    *OutDeviceID = Separator + 1;

    return Status;
}

NTSTATUS
NTAPI
PipMakeGloballyUniqueId(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PWCHAR InstanceID,
    _Out_ PWCHAR *OutUniqueId)
{
    UNICODE_STRING EnumKeyName = RTL_CONSTANT_STRING(ENUM_ROOT);
    UNICODE_STRING ValueName;
    KEY_VALUE_PARTIAL_INFORMATION KeyValue;
    PKEY_VALUE_PARTIAL_INFORMATION PrefixBuffer;
    PDEVICE_NODE ParentNode;
    PWCHAR UniqueIdBuffer;
    PWSTR UniqueIdString = NULL;
    PWCHAR UniqueIdStringEnd;
    HANDLE Handle;
    HANDLE KeyHandle;
    ULONG InstanceCounter;
    ULONG ResultLength;
    ULONG UniqueParentID;
    ULONG InstanceIdLen;
    PWSTR pChar;
    ULONG Key;
    ULONG Hash;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PipMakeGloballyUniqueId: InstanceID - %S\n", InstanceID);

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&PpRegistryDeviceResource, TRUE);

    ParentNode = (IopGetDeviceNode(DeviceObject))->Parent;

    Status = IopOpenRegistryKeyEx(&Handle,
                                  NULL,
                                  &EnumKeyName,
                                  KEY_READ | KEY_WRITE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PipMakeGloballyUniqueId: Status - %X\n", Status);

        ExReleaseResourceLite(&PpRegistryDeviceResource);
        KeLeaveCriticalRegion();

        *OutUniqueId = NULL;
        return Status;
    }

    Status = IopOpenRegistryKeyEx(&KeyHandle,
                                  Handle,
                                  &ParentNode->InstancePath,
                                  KEY_READ | KEY_WRITE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("PipMakeGloballyUniqueId: Status - %X\n", Status);
        goto Exit;
    }

    RtlInitUnicodeString(&ValueName, L"UniqueParentID");

    Status = ZwQueryValueKey(KeyHandle,
                             &ValueName,
                             KeyValuePartialInformation,
                             &KeyValue,
                             sizeof(KEY_VALUE_PARTIAL_INFORMATION),
                             &ResultLength);

    if (NT_SUCCESS(Status))
    {
        ASSERT(KeyValue.Type == REG_DWORD);
        ASSERT(KeyValue.DataLength == sizeof(ULONG));

        if (KeyValue.Type != REG_DWORD ||
            KeyValue.DataLength != sizeof(ULONG))
        {
            Status = STATUS_INVALID_PARAMETER;
            ZwClose(KeyHandle);
            goto Exit;
        }

        UniqueParentID = KeyValue.Data[0];

        UniqueIdString = ExAllocatePoolWithTag(PagedPool,
                                               9 * sizeof(WCHAR),
                                               'nepP');
        if (!UniqueIdString)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            ZwClose(KeyHandle);
            goto Exit;
        }

        RtlStringCbPrintfW(UniqueIdString,
                           9 * sizeof(WCHAR),
                           L"%x",
                           UniqueParentID);

        goto MakeUniqueId;
    }

    /* 
        Format key "ParentIdPrefix" ("%x&%x&%x"):
        [ParentNode->Level] + "&" + [Hash] + "&" + [InstanceCounter]
                      8        1      8       1        8
    */

    ResultLength = 66; // (sizeof(KEY_VALUE_PARTIAL_INFORMATION) - (1+3)) + (8+1+8+1+8)*2 + sizeof(UNICODE_NULL)

    PrefixBuffer = ExAllocatePoolWithTag(PagedPool, ResultLength, 'nepP');

    if (!PrefixBuffer)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        ZwClose(KeyHandle);
        goto Exit;
    }

    RtlInitUnicodeString(&ValueName, L"ParentIdPrefix");

    Status = ZwQueryValueKey(KeyHandle,
                             &ValueName,
                             KeyValuePartialInformation,
                             PrefixBuffer,
                             ResultLength,
                             &ResultLength);

    if (!NT_SUCCESS(Status))
    {
        /* 
            Format key "NextParentID" ("%s.%x.%x"):
            "NextParentID" + "." + [Hash] + "." + [ParentNode->Level]
                              1      8       1        8
        */

        ResultLength = wcslen(L"NextParentID") + 19; // (1+8+1+8) + 1

        Status = RtlUpcaseUnicodeString(&ValueName,
                                        &ParentNode->InstancePath,
                                        TRUE);
        if (!NT_SUCCESS(Status))
        {
            ZwClose(KeyHandle);
            goto Exit;
        }

        /* Calculate hash for UniqueId */
        Key = 0;

        for (pChar = ValueName.Buffer;
             pChar < &ValueName.Buffer[ValueName.Length / sizeof(WCHAR)];
             pChar++)
        {
            Key = *pChar + 37 * Key; // ?37?
        }

        Hash = abs(CMP_HASH_IRRATIONAL * Key) % CMP_HASH_PRIME;

        RtlFreeUnicodeString(&ValueName);

        UniqueIdString = ExAllocatePoolWithTag(PagedPool,
                                               ResultLength * sizeof(WCHAR),
                                               'nepP');
        if (!UniqueIdString)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            ZwClose(KeyHandle);
            goto Exit;
        }

        RtlStringCbPrintfW(UniqueIdString,
                           ResultLength * sizeof(WCHAR),
                           L"%s.%x.%x",
                           L"NextParentID",
                           Hash,
                           ParentNode->Level);

        RtlInitUnicodeString(&ValueName, UniqueIdString);

        Status = ZwQueryValueKey(Handle,
                                 &ValueName,
                                 KeyValuePartialInformation,
                                 &KeyValue,
                                 sizeof(KEY_VALUE_PARTIAL_INFORMATION),
                                 &ResultLength);

        if (NT_SUCCESS(Status) &&
            KeyValue.Type == REG_DWORD &&
            KeyValue.DataLength == sizeof(ULONG))
        {
            InstanceCounter = KeyValue.Data[0];
        }
        else
        {
            InstanceCounter = 0;
        }

        InstanceCounter++;

        Status = ZwSetValueKey(Handle,
                               &ValueName,
                               0,
                               REG_DWORD,
                               &InstanceCounter,
                               sizeof(ULONG));

        if (!NT_SUCCESS(Status))
        {
            ZwClose(KeyHandle);
            goto Exit;
        }

        InstanceCounter--;

        RtlStringCchPrintfExW(UniqueIdString,
                              ResultLength,
                              &UniqueIdStringEnd,
                              NULL,
                              0,
                              L"%x&%x&%x",
                              ParentNode->Level,
                              Hash,
                              InstanceCounter);

        ResultLength = (UniqueIdStringEnd - UniqueIdString) + 1;

        RtlInitUnicodeString(&ValueName, L"ParentIdPrefix");

        Status = ZwSetValueKey(KeyHandle,
                               &ValueName,
                               0,
                               REG_SZ,
                               UniqueIdString,
                               ResultLength * sizeof(WCHAR));

        if (!NT_SUCCESS(Status))
        {
            ZwClose(KeyHandle);
            goto Exit;
        }
    }
    else
    {
        if (PrefixBuffer->Type != REG_SZ)
        {
            ASSERT(PrefixBuffer->Type == REG_SZ);

            if (PrefixBuffer->Type != REG_SZ)
            {
                Status = STATUS_INVALID_PARAMETER;
                ZwClose(KeyHandle);
                goto Exit;
            }
        }

        UniqueIdString = ExAllocatePoolWithTag(PagedPool,
                                               PrefixBuffer->DataLength,
                                               'nepP');

        if (!UniqueIdString)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            ZwClose(KeyHandle);
            goto Exit;
        }

        RtlStringCbCopyW(UniqueIdString,
                         PrefixBuffer->DataLength,
                         (PWSTR)PrefixBuffer->Data);
    }

MakeUniqueId:

    if (InstanceID)
    {
        InstanceIdLen = wcslen(InstanceID);
    }
    else
    {
        InstanceIdLen = 0;
    }

    ResultLength = wcslen(UniqueIdString) + InstanceIdLen + 2;

    UniqueIdBuffer = ExAllocatePoolWithTag(PagedPool,
                                           ResultLength * sizeof(WCHAR),
                                           'nepP');
    if (!UniqueIdBuffer)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    if (InstanceID)
    {
        RtlStringCchPrintfW(UniqueIdBuffer,
                            ResultLength,
                            L"%s&%s",
                            UniqueIdString,
                            InstanceID);
    }
    else
    {
        RtlStringCchCopyW(UniqueIdBuffer,
                          ResultLength,
                          UniqueIdString);
    }

    ZwClose(KeyHandle);

Exit:

    ZwClose(Handle);

    ExReleaseResourceLite(&PpRegistryDeviceResource);
    KeLeaveCriticalRegion();

    if (PrefixBuffer)
    {
        ExFreePoolWithTag(PrefixBuffer, 'nepP');
    }

    if (UniqueIdString)
    {
        ExFreePoolWithTag(UniqueIdString, 'nepP');
    }

    *OutUniqueId = UniqueIdBuffer;

    return Status;
}

NTSTATUS
NTAPI
PiBuildDeviceNodeInstancePath(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ PWCHAR DeviceType,
    _In_ PWCHAR DeviceID,
    _In_ PWCHAR InstanceID)
{
    SIZE_T Lenght;
    PWCHAR InstancePath;

    PAGED_CODE();
    DPRINT("PiBuildDeviceNodeInstancePath: DeviceNode - %p, DeviceType - %S, DeviceID - %S, InstanceID - %S\n",
           DeviceNode, DeviceType, DeviceID, InstanceID);

    if (!DeviceType || !DeviceID || !InstanceID)
    {
        DPRINT("PiBuildDeviceNodeInstancePath: !DeviceType || !DeviceID || !InstanceID\n");

        ASSERT((DeviceNode->Flags & DNF_HAS_PROBLEM) != 0);
        ASSERT(DeviceNode->Problem == CM_PROB_INVALID_DATA ||
               DeviceNode->Problem == CM_PROB_OUT_OF_MEMORY ||
               DeviceNode->Problem == CM_PROB_REGISTRY);

        return STATUS_UNSUCCESSFUL;
    }

    Lenght = (wcslen(DeviceType) + 1 +
              wcslen(DeviceID) + 1 +
              wcslen(InstanceID) + 1) * sizeof(WCHAR);

    InstancePath = ExAllocatePoolWithTag(PagedPool, Lenght, 'nepP');

    if (!InstancePath)
    {
        DPRINT1("PiBuildDeviceNodeInstancePath: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlStringCbPrintfW(InstancePath,
                       Lenght,
                       L"%s\\%s\\%s",
                       DeviceType,
                       DeviceID,
                       InstanceID);

    if (DeviceNode->InstancePath.Buffer)
    {
        IopCleanupDeviceRegistryValues(&DeviceNode->InstancePath);
        ExFreePoolWithTag(DeviceNode->InstancePath.Buffer, 'nepP');
    }

    RtlInitUnicodeString(&DeviceNode->InstancePath, InstancePath);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PiCreateDeviceInstanceKey(
    _In_ PDEVICE_NODE DeviceNode,
    _Out_ PHANDLE OutKeyHandle,
    _Out_ PULONG OutDisposition)
{
    UNICODE_STRING EnumKeyName = RTL_CONSTANT_STRING(ENUM_ROOT);
    UNICODE_STRING ValueName;
    PKEY_VALUE_FULL_INFORMATION KeyInfo;
    HANDLE EnumHandle;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PiCreateDeviceInstanceKey: DeviceNode %p\n", DeviceNode);

    *OutKeyHandle = NULL;
    *OutDisposition = 0;

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&PpRegistryDeviceResource, TRUE);

    Status = IopOpenRegistryKeyEx(&EnumHandle,
                                  NULL,
                                  &EnumKeyName,
                                  KEY_ALL_ACCESS);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("PiCreateDeviceInstanceKey: Status - %X\n", Status);
        ASSERT(EnumHandle != NULL);
        goto Exit;
    }

    Status = IopCreateRegistryKeyEx(OutKeyHandle,
                                    EnumHandle,
                                    &DeviceNode->InstancePath,
                                    KEY_ALL_ACCESS,
                                    REG_OPTION_NON_VOLATILE,
                                    OutDisposition);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("PiCreateDeviceInstanceKey: Status - %X\n", Status);
        ASSERT(*OutKeyHandle != NULL);
        goto Exit;
    }

    if (*OutDisposition == REG_CREATED_NEW_KEY)
    {
        goto Exit;
    }

    KeyInfo = NULL;
    IopGetRegistryValue(*OutKeyHandle, L"Migrated", &KeyInfo);

    if (!KeyInfo)
    {
        goto Exit;
    }

    if (KeyInfo->Type == REG_DWORD &&
        KeyInfo->DataLength == sizeof(ULONG) &&
        *(PULONG)((ULONG_PTR)&KeyInfo->TitleIndex + KeyInfo->DataOffset))
    {
        *OutDisposition = REG_CREATED_NEW_KEY;
    }

    RtlInitUnicodeString(&ValueName, L"Migrated");
    ZwDeleteValueKey(*OutKeyHandle, &ValueName);

    ExFreePoolWithTag(KeyInfo, 'uspP');

Exit:

    if (EnumHandle)
    {
        ZwClose(EnumHandle);
    }

    ExReleaseResourceLite(&PpRegistryDeviceResource);
    KeLeaveCriticalRegion();

    return Status;
}

VOID
NTAPI
PpMarkDeviceStackStartPending(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ BOOLEAN MarkType)
{
    PDEVICE_OBJECT Device;
    PEXTENDED_DEVOBJ_EXTENSION DevObjExtension;
    KSPIN_LOCK DeviceStackLock;
    KIRQL OldIrql;

    DPRINT("PpMarkDeviceStackStartPending: DeviceObject %p\n", DeviceObject);

    KeAcquireSpinLock(&DeviceStackLock, &OldIrql);

    for (Device = DeviceObject;
         Device;
         Device = Device->AttachedDevice)
    {
        DevObjExtension = IoGetDevObjExtension(Device);

        if (MarkType)
        {
            DevObjExtension->ExtensionFlags |= DOE_START_PENDING;
        }
        else
        {
            DevObjExtension->ExtensionFlags &= ~DOE_START_PENDING;
        }
    }

    KeReleaseSpinLock(&DeviceStackLock, OldIrql);
}

NTSTATUS
NTAPI
PiQueryResourceRequirements(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ HANDLE KeyHandle)
{
    PIO_RESOURCE_REQUIREMENTS_LIST IoResource;
    UNICODE_STRING ValueName;
    ULONG ListSize;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PiQueryResourceRequirements: DeviceNode - %p, KeyHandle - %p\n",
           DeviceNode, KeyHandle);

    Status = PpIrpQueryResourceRequirements(DeviceNode->PhysicalDeviceObject,
                                            &IoResource);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("PiQueryResourceRequirements: Status - %X\n", Status);
        ASSERT(IoResource == NULL);
        IoResource = NULL;
    }

    if (IoResource)
    {
        ListSize = IoResource->ListSize;
    }
    else
    {
        ListSize = 0;
    }

    if (!KeyHandle)
    {
        if (IoResource)
        {
            ExFreePool(IoResource);
        }

        DPRINT("PiQueryResourceRequirements: Status - %X\n", Status);
        return Status;
    }

    RtlInitUnicodeString(&ValueName, L"BasicConfigVector");

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&PpRegistryDeviceResource, TRUE);

    if (IoResource)
    {
        ZwSetValueKey(KeyHandle,
                      &ValueName,
                      0,
                      REG_RESOURCE_REQUIREMENTS_LIST,
                      IoResource,
                      ListSize);

        DeviceNode->Flags |= DNF_RESOURCE_REQUIREMENTS_NEED_FILTERED;
        DeviceNode->ResourceRequirements = IoResource;
    }
    else
    {
        ZwDeleteValueKey(KeyHandle, &ValueName);
    }

    ExReleaseResourceLite(&PpRegistryDeviceResource);
    KeLeaveCriticalRegion();

    if (DeviceNode->ResourceRequirements)
    {
        DPRINT("PiQueryResourceRequirements: DeviceNode->ResourceRequirements - %p\n",
               DeviceNode->ResourceRequirements);

        IopDumpResourceRequirementsList(DeviceNode->ResourceRequirements);
    }

    return Status;
}

NTSTATUS
NTAPI
PpQueryBusInformation(
    _In_ PDEVICE_NODE DeviceNode)
{
    PPNP_BUS_INFORMATION BusInfo;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PpQueryBusInformation: DeviceNode - %p\n", DeviceNode);

    Status = PpIrpQueryBusInformation(DeviceNode->PhysicalDeviceObject, &BusInfo);

    if (!NT_SUCCESS(Status))
    {
        ASSERT(BusInfo == NULL);

        DeviceNode->ChildBusTypeIndex = -1;
        DeviceNode->ChildInterfaceType = InterfaceTypeUndefined;
        DeviceNode->ChildBusNumber = 0xFFFFFFF0;
    }
    else
    {
        ASSERT(BusInfo);

        DeviceNode->ChildBusTypeIndex = IopGetBusTypeGuidIndex(&BusInfo->BusTypeGuid);
        DeviceNode->ChildInterfaceType = BusInfo->LegacyBusType;
        DeviceNode->ChildBusNumber = BusInfo->BusNumber;

        ExFreePool(BusInfo);
    }

    return Status;
}

NTSTATUS
NTAPI
PiQueryAndAllocateBootResources(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ HANDLE KeyHandle)
{
    PCM_RESOURCE_LIST CmResource = NULL;
    UNICODE_STRING ValueName;
    ULONG CmLength = 0;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();
    ASSERT(DeviceNode);

    DPRINT("PiQueryAndAllocateBootResources: DeviceNode - %p, DeviceNode->BootResources - %p\n",
           DeviceNode, DeviceNode->BootResources);

    if (DeviceNode->BootResources == NULL)
    {
        Status = PpIrpQueryResources(DeviceNode->PhysicalDeviceObject,
                                     &CmResource,
                                     &CmLength);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("PiQueryAndAllocateBootResources: Status - %X, DeviceNode->BootResources - %p\n",
                   Status, DeviceNode->BootResources);

            ASSERT(CmResource == NULL && CmLength == 0);

            CmResource = NULL;
            CmLength = 0;
        }
    }
    else
    {
        DPRINT("PiQueryAndAllocateBootResources: %S already has BOOT config in PiQueryAndAllocateBootResources!\n",
               DeviceNode->InstancePath.Buffer);
    }

    if (!KeyHandle || DeviceNode->BootResources)
    {
        if (CmResource)
        {
            ExFreePoolWithTag(CmResource, 0);
        }

        DPRINT("PiQueryAndAllocateBootResources: DeviceNode->BootResources - %X\n",
               DeviceNode->BootResources);

        return Status;
    }
    else
    {
        DPRINT("PiQueryAndAllocateBootResources: KeyHandle - %X\n", KeyHandle);
    }

    RtlInitUnicodeString(&ValueName, L"BootConfig");

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&PpRegistryDeviceResource, TRUE);

    if (CmResource)
    {
        ZwSetValueKey(KeyHandle,
                      &ValueName,
                      0,
                      REG_RESOURCE_LIST,
                      CmResource,
                      CmLength);
    }
    else
    {
        ZwDeleteValueKey(KeyHandle, &ValueName);
    }

    ExReleaseResourceLite(&PpRegistryDeviceResource);
    KeLeaveCriticalRegion();

    if (!CmResource)
    {
        return Status;
    }

    Status = IopAllocateBootResourcesRoutine(4,
                                             DeviceNode->PhysicalDeviceObject,
                                             CmResource);

    DPRINT("PiQueryAndAllocateBootResources: DeviceNode->BootResources - %X, Status - %X\n",
           DeviceNode->BootResources, Status);

    if (DeviceNode->BootResources)
    {
        IopDumpCmResourceList(DeviceNode->BootResources);
    }

    if (NT_SUCCESS(Status))
    {
        DeviceNode->Flags |= DNF_HAS_BOOT_CONFIG;
    }

    if (CmResource)
    {
        ExFreePoolWithTag(CmResource, 0);
    }

    return Status;
}

NTSTATUS
NTAPI
PiCriticalQueryRegistryValueCallback(
    _In_ PWSTR ValueName,
    _In_ ULONG ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueLength,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID EntryContext)
{
    /* "Security" key */

    DPRINT("PiCriticalQueryRegistryValueCallback: ValueName - %S\n", ValueName);

    if (ValueType != REG_BINARY)
    {
        DPRINT("PiCriticalQueryRegistryValueCallback: ValueType - %X\n", ValueType);
        return STATUS_SUCCESS;
    }

    if (!ValueLength)
    {
        DPRINT("PiCriticalQueryRegistryValueCallback: ValueLength == 0\n");
        return STATUS_SUCCESS;
    }

    if (!ValueData)
    {
        DPRINT("PiCriticalQueryRegistryValueCallback: ValueData == NULL\n");
        return STATUS_SUCCESS;
    }

    DPRINT("PiCriticalQueryRegistryValueCallback: FIXME ...\n");
    ASSERT(FALSE);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PiCriticalCopyCriticalDeviceProperties(
    _In_ HANDLE KeyHandle,
    _In_ HANDLE CriticalHandle)
{
    PKEY_VALUE_FULL_INFORMATION KeyValueFullInfo;
    RTL_QUERY_REGISTRY_TABLE QueryTable[9];
    PVOID SecurityContext = NULL;
    UNICODE_STRING LowerFiltersString;
    UNICODE_STRING UpperFiltersString;
    UNICODE_STRING ClassGuidString;
    UNICODE_STRING ServiceString;
    UNICODE_STRING ValueName;
    ULONG DataSize = 0;
    ULONG defaultData = 0;
    ULONG DeviceCharacteristicsContext = 0;
    ULONG ExclusiveData = 0;
    ULONG DeviceTypeData = 0;
    NTSTATUS status;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PiCriticalCopyCriticalDeviceProperties()\n");

    if (!KeyHandle || !CriticalHandle)
    {
        ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&QueryTable, sizeof(QueryTable));

    QueryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    QueryTable[0].Name = L"Service";
    QueryTable[0].EntryContext = &ServiceString;
    QueryTable[0].DefaultType = REG_SZ;
    QueryTable[0].DefaultData = L"";
    QueryTable[0].DefaultLength = 0;

    QueryTable[1].Flags = RTL_QUERY_REGISTRY_DIRECT;
    QueryTable[1].Name = L"ClassGUID";
    QueryTable[1].EntryContext = &ClassGuidString;
    QueryTable[1].DefaultType = REG_SZ;
    QueryTable[1].DefaultData = L"";
    QueryTable[1].DefaultLength = 0;

    QueryTable[2].Flags = RTL_QUERY_REGISTRY_DIRECT + RTL_QUERY_REGISTRY_NOEXPAND;
    QueryTable[2].Name = L"LowerFilters";
    QueryTable[2].EntryContext = &LowerFiltersString;
    QueryTable[2].DefaultType = REG_MULTI_SZ;
    QueryTable[2].DefaultData = L"";
    QueryTable[2].DefaultLength = 0;

    QueryTable[3].Flags = RTL_QUERY_REGISTRY_DIRECT + RTL_QUERY_REGISTRY_NOEXPAND;
    QueryTable[3].Name = L"UpperFilters";
    QueryTable[3].EntryContext = &UpperFiltersString;
    QueryTable[3].DefaultType = REG_MULTI_SZ;
    QueryTable[3].DefaultData = L"";
    QueryTable[3].DefaultLength = 0;

    QueryTable[4].Flags = RTL_QUERY_REGISTRY_DIRECT;
    QueryTable[4].Name = L"DeviceType";
    QueryTable[4].EntryContext = &DeviceTypeData;
    QueryTable[4].DefaultType = REG_DWORD;
    QueryTable[4].DefaultData = &defaultData;
    QueryTable[4].DefaultLength = sizeof(defaultData);

    QueryTable[5].Flags = RTL_QUERY_REGISTRY_DIRECT;
    QueryTable[5].Name = L"Exclusive";
    QueryTable[5].EntryContext = &ExclusiveData;
    QueryTable[5].DefaultType = REG_DWORD;
    QueryTable[5].DefaultData = &defaultData;
    QueryTable[5].DefaultLength = sizeof(defaultData);

    QueryTable[6].Flags = RTL_QUERY_REGISTRY_DIRECT;
    QueryTable[6].Name = L"DeviceCharacteristics";
    QueryTable[6].EntryContext = &DeviceCharacteristicsContext;
    QueryTable[6].DefaultType = REG_DWORD;
    QueryTable[6].DefaultData = &defaultData;
    QueryTable[6].DefaultLength = sizeof(defaultData);

    QueryTable[7].QueryRoutine = PiCriticalQueryRegistryValueCallback;
    QueryTable[7].Flags = 0;
    QueryTable[7].Name = L"Security";
    QueryTable[7].EntryContext = &SecurityContext;
    QueryTable[7].DefaultType = REG_BINARY;
    QueryTable[7].DefaultData = 0;
    QueryTable[7].DefaultLength = 0;

    RtlZeroMemory(&ServiceString, sizeof(ServiceString));
    RtlZeroMemory(&ClassGuidString, sizeof(ClassGuidString));
    RtlZeroMemory(&LowerFiltersString, sizeof(LowerFiltersString));
    RtlZeroMemory(&UpperFiltersString, sizeof(UpperFiltersString));

    Status = RtlQueryRegistryValues(RTL_REGISTRY_HANDLE | RTL_REGISTRY_OPTIONAL,
                                    (PCWSTR)CriticalHandle,
                                    QueryTable,
                                    NULL,
                                    NULL);
    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    if (!ServiceString.Length && ServiceString.Buffer)
    {
        RtlFreeUnicodeString(&ServiceString);
    }

    if (!ClassGuidString.Length && ClassGuidString.Buffer)
    {
        RtlFreeUnicodeString(&ClassGuidString);
    }

    if (UpperFiltersString.Length <= sizeof(WCHAR) && UpperFiltersString.Buffer)
    {
        RtlFreeUnicodeString(&UpperFiltersString);
    }

    if (LowerFiltersString.Length <= sizeof(WCHAR) && LowerFiltersString.Buffer)
    {
        RtlFreeUnicodeString(&LowerFiltersString);
    }

    DPRINT("PiCriticalCopyCriticalDeviceProperties: Setup critical service\n");

    if (!ServiceString.Buffer)
    {
        DPRINT1("PiCriticalCopyCriticalDeviceProperties: ServiceString.Buffer == NULL\n");
        ASSERT(ServiceString.Buffer);
        Status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    RtlInitUnicodeString(&ValueName, L"Service");

    DPRINT("PiCriticalCopyCriticalDeviceProperties: ServiceString - %wZ, ValueName - %wZ\n",
           &ServiceString, &ValueName);

    Status = ZwSetValueKey(KeyHandle,
                           &ValueName,
                           0,
                           REG_SZ,
                           ServiceString.Buffer,
                           ServiceString.Length + sizeof(WCHAR));

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PiCriticalCopyCriticalDeviceProperties: Status - %X\n", Status);
        goto Exit;
    }

    if (ClassGuidString.Buffer)
    {
        RtlInitUnicodeString(&ValueName, L"ClassGUID");

        DPRINT("PiCriticalCopyCriticalDeviceProperties: ClassGuidString - %wZ, ValueName - %wZ\n",
               &ClassGuidString, &ValueName);

        ZwSetValueKey(KeyHandle,
                      &ValueName,
                      0,
                      REG_SZ,
                      ClassGuidString.Buffer,
                      ClassGuidString.Length + sizeof(WCHAR));
    }

    if (LowerFiltersString.Buffer)
    {
        RtlInitUnicodeString(&ValueName, L"LowerFilters");

        DPRINT("PiCriticalCopyCriticalDeviceProperties: LowerFiltersString - %wZ, ValueName - %wZ\n",
               &LowerFiltersString, &ValueName);

        ZwSetValueKey(KeyHandle,
                      &ValueName,
                      0,
                      REG_MULTI_SZ,
                      LowerFiltersString.Buffer,
                      LowerFiltersString.Length);
    }

    if (UpperFiltersString.Buffer)
    {
        RtlInitUnicodeString(&ValueName, L"UpperFilters");

        DPRINT("PiCriticalCopyCriticalDeviceProperties: UpperFiltersString - %wZ, ValueName - %wZ\n",
               &UpperFiltersString, &ValueName);

        ZwSetValueKey(KeyHandle,
                      &ValueName,
                      0,
                      REG_MULTI_SZ,
                      UpperFiltersString.Buffer,
                      UpperFiltersString.Length);
    }

    if (DeviceTypeData)
    {
        RtlInitUnicodeString(&ValueName, L"DeviceType");

        DPRINT("PiCriticalCopyCriticalDeviceProperties: DeviceType - %X, ValueName - %wZ\n",
               &DeviceTypeData, &ValueName);

        Status = ZwSetValueKey(KeyHandle,
                               &ValueName,
                               0,
                               REG_DWORD,
                               &DeviceTypeData,
                               sizeof(DeviceTypeData));

        if (!NT_SUCCESS(Status))
        {
            DPRINT("PiCriticalCopyCriticalDeviceProperties: Status - %X\n", Status);
            goto Exit;
        }
    }

    if (ExclusiveData)
    {
        RtlInitUnicodeString(&ValueName, L"Exclusive");

        DPRINT("PiCriticalCopyCriticalDeviceProperties: ValueName - %wZ\n", &ValueName);

        Status = ZwSetValueKey(KeyHandle,
                               &ValueName,
                               0,
                               REG_DWORD,
                               &ExclusiveData,
                               sizeof(ExclusiveData));

        if (!NT_SUCCESS(Status))
        {
            DPRINT("PiCriticalCopyCriticalDeviceProperties: Status - %X\n", Status);
            goto Exit;
        }
    }

    if (DeviceCharacteristicsContext)
    {
        RtlInitUnicodeString(&ValueName, L"DeviceCharacteristics");

        DPRINT("PiCriticalCopyCriticalDeviceProperties: ValueName - %wZ\n", &ValueName);

        Status = ZwSetValueKey(KeyHandle,
                               &ValueName,
                               0,
                               REG_DWORD,
                               &DeviceCharacteristicsContext,
                               sizeof(DeviceCharacteristicsContext));

        if (!NT_SUCCESS(Status))
        {
            DPRINT("PiCriticalCopyCriticalDeviceProperties: Status - %X\n", Status);
            goto Exit;
        }
    }

    if (SecurityContext)
    {
        RtlInitUnicodeString(&ValueName, L"Security");

        DPRINT("PiCriticalCopyCriticalDeviceProperties: ValueName - %wZ\n", &ValueName);

        Status = ZwSetValueKey(KeyHandle,
                               &ValueName,
                               0,
                               REG_DWORD,
                               SecurityContext,
                               DataSize);

        if (!NT_SUCCESS(Status))
        {
            DPRINT("PiCriticalCopyCriticalDeviceProperties: Status - %X\n", Status);
            goto Exit;
        }
    }

    KeyValueFullInfo = NULL;

    status = IopGetRegistryValue(CriticalHandle,
                                 L"PreservePreInstall",
                                 &KeyValueFullInfo);

    if (!NT_SUCCESS(status))
    {
        DPRINT("PiCriticalCopyCriticalDeviceProperties: Status - %X\n", Status);
        goto Exit;
    }

    ASSERT(KeyValueFullInfo);
    ASSERT(KeyValueFullInfo->Type == REG_DWORD);
    ASSERT(KeyValueFullInfo->DataLength == sizeof(ULONG));

    if (KeyValueFullInfo->Type == REG_DWORD &&
        KeyValueFullInfo->DataLength == sizeof(ULONG))
    {
        RtlInitUnicodeString(&ValueName, L"PreservePreInstall");

        status = ZwSetValueKey(KeyHandle,
                               &ValueName,
                               KeyValueFullInfo->TitleIndex,
                               KeyValueFullInfo->Type,
                               (PUCHAR)KeyValueFullInfo + KeyValueFullInfo->DataOffset,
                               KeyValueFullInfo->DataLength);

        if (!NT_SUCCESS(status))
        {
            DPRINT("PiCriticalCopyCriticalDeviceProperties: Status - %X\n", Status);
        }
    }

    ExFreePoolWithTag(KeyValueFullInfo, 'uspP');

Exit:

    RtlFreeUnicodeString(&ServiceString);
    RtlFreeUnicodeString(&ClassGuidString);
    RtlFreeUnicodeString(&LowerFiltersString);
    RtlFreeUnicodeString(&UpperFiltersString);

    if (SecurityContext)
    {
        ExFreePool(SecurityContext);
    }

    return Status;
}

BOOLEAN
NTAPI
PiCriticalCallbackVerifyCriticalEntry(HANDLE KeyHandle)
{
    PKEY_VALUE_FULL_INFORMATION KeyValueFullInfo;
    ULONG Type;
    ULONG DataLength;
    ULONG ClassGUIDLenght;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PiCriticalCallbackVerifyCriticalEntry()\n");

    if (!KeyHandle)
    {
        DPRINT("PiCriticalCallbackVerifyCriticalEntry: KeyHandle - NULL\n");
        return FALSE;
    }

    KeyValueFullInfo = NULL;

    Status = IopGetRegistryValue(KeyHandle, L"Service", &KeyValueFullInfo);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("PiCriticalCallbackVerifyCriticalEntry: Status - %X\n", Status);
        ASSERT(KeyValueFullInfo == NULL);
        return FALSE;
    }

    ASSERT(KeyValueFullInfo);

    Type = KeyValueFullInfo->Type;
    DataLength = KeyValueFullInfo->DataLength;

    ExFreePoolWithTag(KeyValueFullInfo, 'uspP');

    if (Type != REG_SZ || DataLength <= sizeof(WCHAR))
    {
        DPRINT("PiCriticalCallbackVerifyCriticalEntry: Type - %X, DataLength - %X\n",
               Type, DataLength);

        return FALSE;
    }

    KeyValueFullInfo = NULL;

    Status = IopGetRegistryValue(KeyHandle, L"ClassGUID", &KeyValueFullInfo);

    if (!NT_SUCCESS(Status))
    {
        ASSERT(KeyValueFullInfo == NULL);

        if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
        {
            Status = STATUS_SUCCESS;
        }

        DPRINT("PiCriticalCallbackVerifyCriticalEntry: Status %X\n", Status);
        return FALSE;
    }

    ASSERT(KeyValueFullInfo != NULL);

    Type = KeyValueFullInfo->Type;
    DataLength = KeyValueFullInfo->DataLength;

    ExFreePoolWithTag(KeyValueFullInfo, 'uspP');

    ClassGUIDLenght = strlen("{00000000-0000-0000-0000-000000000000}") * sizeof(WCHAR);

    if (Type != REG_SZ ||
        (DataLength > sizeof(WCHAR) && DataLength < ClassGUIDLenght))
    {
        DPRINT("PiCriticalCallbackVerifyCriticalEntry: Type - %X, DataLength - %X\n",
               Type, DataLength);

        Status = STATUS_UNSUCCESSFUL;
    }

    return NT_SUCCESS(Status);
}

NTSTATUS
NTAPI
PiCriticalOpenFirstMatchingSubKey(
    _In_ PWSTR IdString,
    _In_ HANDLE DatabaseRootHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PIP_CRITICAL_CALLBACK_VERIFY_CRITICAL_ENTRY CallbackRoutine,
    _Out_ PHANDLE MatchingKeyHandle)
{
    UNICODE_STRING MatchingString;
    PWCHAR String;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PiCriticalOpenFirstMatchingSubKey: IdString - %S\n", IdString);

    if (!IdString || !DatabaseRootHandle || !MatchingKeyHandle)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *MatchingKeyHandle = NULL;
    Status = STATUS_OBJECT_NAME_NOT_FOUND;

    if (!*IdString)
    {
        return Status;
    }

    for (String = IdString;
         *String;
         String += wcslen(String) + 1)
    {
        RtlInitUnicodeString(&MatchingString, String);

        Status = IopOpenRegistryKeyEx(MatchingKeyHandle,
                                      DatabaseRootHandle,
                                      &MatchingString,
                                      DesiredAccess);
        if (!NT_SUCCESS(Status))
        {
            ASSERT(*MatchingKeyHandle == NULL);
            *MatchingKeyHandle = NULL;
            continue;
        }

        ASSERT(*MatchingKeyHandle != NULL);

        if (CallbackRoutine)
        {
            if (CallbackRoutine(*MatchingKeyHandle))
            {
                DPRINT("PiCriticalOpenFirstMatchingSubKey: Callback return TRUE\n");
                break;
            }
        }
        else
        {
            DPRINT("PiCriticalOpenFirstMatchingSubKey: CallbackRoutine == NULL\n");
            break;
        }

        Status = STATUS_OBJECT_NAME_NOT_FOUND;

        ZwClose(*MatchingKeyHandle);
        *MatchingKeyHandle = NULL;
    }

    if (!NT_SUCCESS(Status))
    {
        ASSERT(*MatchingKeyHandle == NULL);
    }
    else if (!*MatchingKeyHandle)
    {
        ASSERT(*MatchingKeyHandle != NULL);
    }

    return Status;
}

NTSTATUS
NTAPI
PiCriticalOpenCriticalDeviceKey(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ HANDLE Handle,
    _In_ PHANDLE CriticalDeviceEntryHandle)
{
    PDEVICE_OBJECT DeviceObject;
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    HANDLE DatabaseRootHandle;
    HANDLE DeviceInstanceHandle;
    UNICODE_STRING CddNameString;
    PWSTR IdNameString[2];
    PWCHAR IdBuffer;
    ULONG ix;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PiCriticalOpenCriticalDeviceKey: DeviceNode - %p\n", DeviceNode);

    if (!DeviceNode || !CriticalDeviceEntryHandle)
    {
        DPRINT("PiCriticalOpenCriticalDeviceKey: CriticalDeviceEntryHandle - %p\n",
               CriticalDeviceEntryHandle);

        return STATUS_INVALID_PARAMETER;
    }

    *CriticalDeviceEntryHandle = NULL;

    if (Handle)
    {
        DatabaseRootHandle = Handle;
    }
    else
    {
        RtlInitUnicodeString(&CddNameString,
                             L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CriticalDeviceDatabase");

        Status = IopOpenRegistryKeyEx(&DatabaseRootHandle,
                                      NULL,
                                      &CddNameString,
                                      KEY_READ);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("PiCriticalOpenCriticalDeviceKey: Status - %X\n", Status);
            return Status;
        }
    }

    ASSERT(DatabaseRootHandle);

    DeviceObject = DeviceNode->PhysicalDeviceObject;
    DeviceInstanceHandle = NULL;

    Status = PnpDeviceObjectToDeviceInstance(DeviceObject,
                                             &DeviceInstanceHandle,
                                             KEY_READ);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("PiCriticalOpenCriticalDeviceKey: Status - %X\n", Status);
        ASSERT(!DeviceInstanceHandle);
        goto Exit;
    }

    ASSERT(DeviceInstanceHandle);

    IdNameString[0] = L"HardwareID";
    IdNameString[1] = L"CompatibleIDs";

    for (ix = 0; ix < 2; ix++)
    {
        ValueInfo = NULL;

        Status = IopGetRegistryValue(DeviceInstanceHandle,
                                     IdNameString[ix],
                                     &ValueInfo);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("PiCriticalOpenCriticalDeviceKey: Status - %X\n", Status);
        }
        else
        {
            ASSERT(ValueInfo);

            if (ValueInfo->Type == REG_MULTI_SZ)
            {
                IdBuffer = (PWCHAR)((ULONG_PTR)ValueInfo + ValueInfo->DataOffset);

                CddNameString.Buffer = IdBuffer;
                CddNameString.Length = ValueInfo->DataLength;
                CddNameString.MaximumLength = CddNameString.Length;

                Status = IopReplaceSeparatorWithPound(&CddNameString,
                                                      &CddNameString);
                ASSERT(NT_SUCCESS(Status));

                Status = PiCriticalOpenFirstMatchingSubKey(IdBuffer,
                                                           DatabaseRootHandle,
                                                           KEY_READ,
                                                           PiCriticalCallbackVerifyCriticalEntry,
                                                           CriticalDeviceEntryHandle);

                ExFreePoolWithTag(ValueInfo, 'uspP');

                if (!NT_SUCCESS(Status))
                {
                    DPRINT("PiCriticalOpenCriticalDeviceKey: Status - %X\n", Status);
                    continue;
                }
                else
                {
                    ASSERT(*CriticalDeviceEntryHandle);
                    ZwClose(DeviceInstanceHandle);
                    goto Exit;
                }
            }

            Status = STATUS_UNSUCCESSFUL;
            ExFreePoolWithTag(ValueInfo, 'uspP');
        }
    }

    if (DeviceInstanceHandle)
    {
        ZwClose(DeviceInstanceHandle);
    }

Exit:

    if (!Handle && DatabaseRootHandle)
    {
        ZwClose(DatabaseRootHandle);
    }

    return Status;
}


VOID
NTAPI
PipEnumerationWorker(
    _In_ PVOID Context)
{
    DPRINT("PipEnumerationWorker()\n");
    ASSERT(FALSE);
}

NTSTATUS
NTAPI
PipRequestDeviceAction(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIP_ENUM_TYPE RequestType,
    _In_ UCHAR ReorderingBarrier,
    _In_ ULONG_PTR RequestArgument,
    _In_ PKEVENT CompletionEvent,
    _Inout_ NTSTATUS * CompletionStatus)
{
    PPIP_ENUM_REQUEST Request;
    PDEVICE_OBJECT RequestDeviceObject;
    KIRQL OldIrql;

    DPRINT("PipRequestDeviceAction: DeviceObject - %p, RequestType - %X\n",
           DeviceObject,
           RequestType);

    //FIXME: check ShuttingDown

    Request = ExAllocatePoolWithTag(NonPagedPool,
                                    sizeof(PIP_ENUM_REQUEST),
                                    TAG_IO);
    if (!Request)
    {
        DPRINT1("PipRequestDeviceAction: error\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!DeviceObject)
    {
        RequestDeviceObject = IopRootDeviceNode->PhysicalDeviceObject;
    }
    else
    {
        RequestDeviceObject = DeviceObject;
    }

    ObReferenceObject(RequestDeviceObject);

    Request->DeviceObject = RequestDeviceObject;
    Request->RequestType = RequestType;
    Request->ReorderingBarrier = ReorderingBarrier;
    Request->RequestArgument = RequestArgument;
    Request->CompletionEvent = CompletionEvent;
    Request->CompletionStatus = CompletionStatus;

    InitializeListHead(&Request->RequestLink);

    KeAcquireSpinLock(&IopPnPSpinLock, &OldIrql);

    InsertTailList(&IopPnpEnumerationRequestList, &Request->RequestLink);
    DPRINT("PipRequestDeviceAction: Inserted Request - %p\n", Request);

    if (RequestType == PipEnumAddBootDevices ||
        RequestType == PipEnumBootDevices ||
        RequestType == PipEnumRootDevices)
    {
        ASSERT(!PipEnumerationInProgress);

        PipEnumerationInProgress = TRUE;
        KeClearEvent(&PiEnumerationLock);
        KeReleaseSpinLock(&IopPnPSpinLock, OldIrql);

        PipEnumerationWorker(Request);

        return STATUS_SUCCESS;
    }

    if (!PnPBootDriversLoaded)
    {
        DPRINT("PipRequestDeviceAction: PnPBootDriversLoaded - FALSE\n");
        KeReleaseSpinLock(&IopPnPSpinLock, OldIrql);
        return STATUS_SUCCESS;
    }

    if (PipEnumerationInProgress)
    {
        DPRINT("PipRequestDeviceAction: PipEnumerationInProgress\n");
        KeReleaseSpinLock(&IopPnPSpinLock, OldIrql);
        return STATUS_SUCCESS;
    }

    PipEnumerationInProgress = TRUE;
    KeClearEvent(&PiEnumerationLock);
    KeReleaseSpinLock(&IopPnPSpinLock, OldIrql);

    ExInitializeWorkItem(&PipDeviceEnumerationWorkItem,
                         PipEnumerationWorker,
                         Request);

    ExQueueWorkItem(&PipDeviceEnumerationWorkItem, DelayedWorkQueue);
    DPRINT("PipRequestDeviceAction: Queue &PipDeviceEnumerationWorkItem - %p\n",
           &PipDeviceEnumerationWorkItem);

    return STATUS_SUCCESS;
}

/* EOF */
