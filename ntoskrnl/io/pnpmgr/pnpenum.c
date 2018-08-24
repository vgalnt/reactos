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
                ExFreePoolWithTag(*OutID, 0);
                *OutID = 0;
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
        ExFreePoolWithTag(*OutID, 0);
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
