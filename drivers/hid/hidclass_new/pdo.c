/*
 * PROJECT:     ReactOS Universal Serial Bus Human Interface Device Driver
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        drivers/hid/hidclass/fdo.c
 * PURPOSE:     HID Class Driver
 * PROGRAMMERS:
 *              Michael Martin (michael.martin@reactos.org)
 *              Johannes Anderwald (johannes.anderwald@reactos.org)
 */

#include "precomp.h"

#include <wdmguid.h>

#define NDEBUG
#include <debug.h>

NTSTATUS
NTAPI
HidClassSymbolicLinkOnOff(
    IN PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension,
    IN ULONG CollectionNumber,
    IN BOOLEAN IsEnable,
    IN PDEVICE_OBJECT PDODeviceObject)
{
    PHIDCLASS_COLLECTION HidCollection;
    NTSTATUS Status;

    DPRINT("HidClassSymbolicLinkOnOff: CollectionNumber - %x, IsEnable - %x\n",
           CollectionNumber,
           IsEnable);

    HidCollection = GetHidclassCollection(PDODeviceExtension->FDODeviceExtension,
                                          CollectionNumber);

    if (!HidCollection)
    {
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    if (IsEnable)
    {
        PDODeviceObject->Flags |= DO_DIRECT_IO;
        PDODeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

        Status = IoRegisterDeviceInterface(PDODeviceObject,
                                           &GUID_DEVINTERFACE_HID,
                                           NULL,
                                           &HidCollection->SymbolicLinkName);

        DPRINT("HidClassSymbolicLinkOnOff: SymbolicLinkName - %wZ\n",
               &HidCollection->SymbolicLinkName);

        if (NT_SUCCESS(Status))
        {
            Status = IoSetDeviceInterfaceState(&HidCollection->SymbolicLinkName,
                                               TRUE);
        }
    }
    else
    {
        if (HidCollection->SymbolicLinkName.Buffer)
        {
            DPRINT("HidClassSymbolicLinkOnOff: SymbolicLinkName - %wZ\n",
                   &HidCollection->SymbolicLinkName);

            Status = IoSetDeviceInterfaceState(&HidCollection->SymbolicLinkName,
                                               FALSE);

            ExFreePoolWithTag(HidCollection->SymbolicLinkName.Buffer,
                              HIDCLASS_TAG);

            HidCollection->SymbolicLinkName.Buffer = NULL;
        }
        else
        {
            Status = STATUS_SUCCESS;
        }
    }

    return Status;
}

PHIDP_COLLECTION_DESC
HidClassPDO_GetCollectionDescription(
    PHIDP_DEVICE_DESC DeviceDescription,
    ULONG CollectionNumber)
{
    ULONG Index;

    for(Index = 0; Index < DeviceDescription->CollectionDescLength; Index++)
    {
        if (DeviceDescription->CollectionDesc[Index].CollectionNumber == CollectionNumber)
        {
            //
            // found collection
            //
            return &DeviceDescription->CollectionDesc[Index];
        }
    }

    //
    // failed to find collection
    //
    DPRINT1("[HIDCLASS] GetCollectionDescription CollectionNumber %x not found\n", CollectionNumber);
    ASSERT(FALSE);
    return NULL;
}

PHIDP_REPORT_IDS
HidClassPDO_GetReportDescription(
    PHIDP_DEVICE_DESC DeviceDescription,
    ULONG CollectionNumber)
{
    ULONG Index;

    for (Index = 0; Index < DeviceDescription->ReportIDsLength; Index++)
    {
        if (DeviceDescription->ReportIDs[Index].CollectionNumber == CollectionNumber)
        {
            //
            // found collection
            //
            return &DeviceDescription->ReportIDs[Index];
        }
    }

    //
    // failed to find collection
    //
    DPRINT1("[HIDCLASS] GetReportDescription CollectionNumber %x not found\n", CollectionNumber);
    ASSERT(FALSE);
    return NULL;
}

NTSTATUS
HidClassPDO_HandleQueryDeviceId(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    NTSTATUS Status;
    LPWSTR Buffer;
    LPWSTR NewBuffer, Ptr;
    ULONG Length;

    //
    // copy current stack location
    //
    IoCopyCurrentIrpStackLocationToNext(Irp);

    //
    // call mini-driver
    //
    Status = HidClassFDO_DispatchRequestSynchronous(DeviceObject, Irp);
    if (!NT_SUCCESS(Status))
    {
        //
        // failed
        //
        return Status;
    }

    //
    // get buffer
    //
    Buffer = (LPWSTR)Irp->IoStatus.Information;
    Length = wcslen(Buffer);

    //
    // allocate new buffer
    //
    NewBuffer = ExAllocatePoolWithTag(NonPagedPool, (Length + 1) * sizeof(WCHAR), HIDCLASS_TAG);
    if (!NewBuffer)
    {
        //
        // failed to allocate buffer
        //
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // replace bus
    //
    wcscpy(NewBuffer, L"HID\\");

    //
    // get offset to first '\\'
    //
    Ptr = wcschr(Buffer, L'\\');
    if (Ptr)
    {
        //
        // append result
        //
        wcscat(NewBuffer, Ptr + 1);
    }

    //
    // free old buffer
    //
    ExFreePoolWithTag(Buffer, HIDCLASS_TAG);

    //
    // store result
    //
    DPRINT("NewBuffer %S\n", NewBuffer);
    Irp->IoStatus.Information = (ULONG_PTR)NewBuffer;
    return STATUS_SUCCESS;
}

NTSTATUS
HidClassPDO_HandleQueryHardwareId(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    NTSTATUS Status;
    PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension;
    WCHAR Buffer[200];
    ULONG Offset = 0;
    LPWSTR Ptr;
    PHIDP_COLLECTION_DESC CollectionDescription;

    //
    // get device extension
    //
    PDODeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(PDODeviceExtension->Common.IsFDO == FALSE);

    //
    // copy current stack location
    //
    IoCopyCurrentIrpStackLocationToNext(Irp);

    //
    // call mini-driver
    //
    Status = HidClassFDO_DispatchRequestSynchronous(DeviceObject, Irp);
    if (!NT_SUCCESS(Status))
    {
        //
        // failed
        //
        return Status;
    }

    if (PDODeviceExtension->Common.DeviceDescription.CollectionDescLength > 1)
    {
        //
        // multi-tlc device
        //
        Offset = swprintf(&Buffer[Offset], L"HID\\Vid_%04x&Pid_%04x&Rev_%04x&Col%02x", PDODeviceExtension->Common.Attributes.VendorID, PDODeviceExtension->Common.Attributes.ProductID, PDODeviceExtension->Common.Attributes.VersionNumber, PDODeviceExtension->CollectionNumber) + 1;
        Offset += swprintf(&Buffer[Offset], L"HID\\Vid_%04x&Pid_%04x&Col%02x", PDODeviceExtension->Common.Attributes.VendorID, PDODeviceExtension->Common.Attributes.ProductID, PDODeviceExtension->CollectionNumber) + 1;
    }
    else
    {
        //
        // single tlc device
        //
        Offset = swprintf(&Buffer[Offset], L"HID\\Vid_%04x&Pid_%04x&Rev_%04x", PDODeviceExtension->Common.Attributes.VendorID, PDODeviceExtension->Common.Attributes.ProductID, PDODeviceExtension->Common.Attributes.VersionNumber) + 1;
        Offset += swprintf(&Buffer[Offset], L"HID\\Vid_%04x&Pid_%04x", PDODeviceExtension->Common.Attributes.VendorID, PDODeviceExtension->Common.Attributes.ProductID) + 1;
    }

    //
    // get collection description
    //
    CollectionDescription = HidClassPDO_GetCollectionDescription(&PDODeviceExtension->Common.DeviceDescription, PDODeviceExtension->CollectionNumber);
    ASSERT(CollectionDescription);

    if (CollectionDescription->UsagePage == HID_USAGE_PAGE_GENERIC)
    {
        switch (CollectionDescription->Usage)
        {
            case HID_USAGE_GENERIC_POINTER:
            case HID_USAGE_GENERIC_MOUSE:
                //
                // Pointer / Mouse
                //
                Offset += swprintf(&Buffer[Offset], L"HID_DEVICE_SYSTEM_MOUSE") + 1;
                break;
            case HID_USAGE_GENERIC_GAMEPAD:
            case HID_USAGE_GENERIC_JOYSTICK:
                //
                // Joystick / Gamepad
                //
                Offset += swprintf(&Buffer[Offset], L"HID_DEVICE_SYSTEM_GAME") + 1;
                break;
            case HID_USAGE_GENERIC_KEYBOARD:
            case HID_USAGE_GENERIC_KEYPAD:
                //
                // Keyboard / Keypad
                //
                Offset += swprintf(&Buffer[Offset], L"HID_DEVICE_SYSTEM_KEYBOARD") + 1;
                break;
            case HID_USAGE_GENERIC_SYSTEM_CTL:
                //
                // System Control
                //
                Offset += swprintf(&Buffer[Offset], L"HID_DEVICE_SYSTEM_CONTROL") + 1;
                break;
        }
    }
    else if (CollectionDescription->UsagePage  == HID_USAGE_PAGE_CONSUMER && CollectionDescription->Usage == HID_USAGE_CONSUMERCTRL)
    {
        //
        // Consumer Audio Control
        //
        Offset += swprintf(&Buffer[Offset], L"HID_DEVICE_SYSTEM_CONSUMER") + 1;
    }

    //
    // add HID_DEVICE_UP:0001_U:0002'
    //
    Offset += swprintf(&Buffer[Offset], L"HID_DEVICE_UP:%04x_U:%04x", CollectionDescription->UsagePage, CollectionDescription->Usage) + 1;

    //
    // add HID
    //
    Offset +=swprintf(&Buffer[Offset], L"HID_DEVICE") + 1;

    //
    // free old buffer
    //
    ExFreePoolWithTag((PVOID)Irp->IoStatus.Information, HIDCLASS_TAG);

    //
    // allocate buffer
    //
    Ptr = ExAllocatePoolWithTag(NonPagedPool, (Offset + 1) * sizeof(WCHAR), HIDCLASS_TAG);
    if (!Ptr)
    {
        //
        // no memory
        //
        Irp->IoStatus.Information = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // copy buffer
    //
    RtlCopyMemory(Ptr, Buffer, Offset * sizeof(WCHAR));
    Ptr[Offset] = UNICODE_NULL;

    //
    // store result
    //
    Irp->IoStatus.Information = (ULONG_PTR)Ptr;
    return STATUS_SUCCESS;
}

NTSTATUS
HidClassPDO_HandleQueryInstanceId(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    LPWSTR Buffer;
    PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension;

    //
    // get device extension
    //
    PDODeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(PDODeviceExtension->Common.IsFDO == FALSE);

    //
    // allocate buffer
    //
    Buffer = ExAllocatePoolWithTag(NonPagedPool, 5 * sizeof(WCHAR), HIDCLASS_TAG);
    if (!Buffer)
    {
        //
        // failed
        //
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // write device id
    //
    swprintf(Buffer, L"%04x", PDODeviceExtension->CollectionNumber);
    Irp->IoStatus.Information = (ULONG_PTR)Buffer;

    //
    // done
    //
    return STATUS_SUCCESS;
}

NTSTATUS
HidClassPDO_HandleQueryCompatibleId(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    LPWSTR Buffer;

    Buffer = ExAllocatePoolWithTag(NonPagedPool, 2 * sizeof(WCHAR), HIDCLASS_TAG);
    if (!Buffer)
    {
        //
        // no memory
        //
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // zero buffer
    //
    Buffer[0] = 0;
    Buffer[1] = 0;

    //
    // store result
    //
    Irp->IoStatus.Information = (ULONG_PTR)Buffer;
    return STATUS_SUCCESS;
}

BOOLEAN
NTAPI
HidClassAnyPdoInitialized(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension)
{
    PDEVICE_RELATIONS DeviceRelations;
    PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension;
    ULONG ix = 0;

    DPRINT("HidClassAnyPdoInitialized: ... \n");

    DeviceRelations = FDODeviceExtension->DeviceRelations;

    if (!DeviceRelations)
    {
        return FALSE;
    }

    do
    {
        PDODeviceExtension = DeviceRelations->Objects[ix]->DeviceExtension;

        if (PDODeviceExtension->HidPdoState != HIDCLASS_STATE_NOT_INIT)
        {
            return TRUE;
        }

        ++ix;
    }
    while (ix < DeviceRelations->Count);

    return FALSE;
}

BOOLEAN
NTAPI
HidClassAllPdoInitialized(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension,
    IN BOOLEAN Type)
{
    PDEVICE_RELATIONS DeviceRelations;
    ULONG ix;
    BOOLEAN Result = TRUE;

    DPRINT("HidClassAllPdoInitialized: FDODeviceExtension - %p, Type - %x\n",
           FDODeviceExtension,
           Type);

    DeviceRelations = FDODeviceExtension->DeviceRelations;

    if (DeviceRelations)
    {
        ix = 0;

        if (DeviceRelations->Count)
        {
            while ((Type == FALSE) != 
                   (((PHIDCLASS_PDO_DEVICE_EXTENSION)(DeviceRelations->Objects[ix]->DeviceExtension))->HidPdoState != 1))
            {
                ++ix;

                if ( ix >= DeviceRelations->Count )
                {
                    DPRINT("HidClassAllPdoInitialized: Result - %x\n", Result);
                    return Result;
                }
            }

            Result = FALSE;
        }
    }
    else
    {
        Result = (Type == FALSE);
    }

    DPRINT("HidClassAllPdoInitialized: Result - %x\n", Result);
    return Result;
}

NTSTATUS
NTAPI
HidClassPdoStart(
    IN PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension,
    IN PIRP Irp)
{
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    PHIDCLASS_COLLECTION HidCollection;
    NTSTATUS Status;

    DPRINT("HidClassPdoStart: Irp - %p, HidPdoState - %x\n",
           Irp,
           PDODeviceExtension->HidPdoState);

    FDODeviceExtension = PDODeviceExtension->FDODeviceExtension;

    if (PDODeviceExtension->HidPdoState == HIDCLASS_STATE_NOT_INIT)
    {
        PDODeviceExtension->HidPdoState = HIDCLASS_STATE_STARTING;
    }

    HidCollection = GetHidclassCollection(FDODeviceExtension,
                                          PDODeviceExtension->CollectionNumber);

    if (!HidCollection)
    {
        return STATUS_DEVICE_DATA_ERROR;
    }

    // FIXME: HidclassGetSessionSecurityState(...);

    if (HidClassAnyPdoInitialized(FDODeviceExtension))
    {
        DPRINT("[HIDCLASS] HidClassAnyPdoInitialized return TRUE\n");

        if (HidCollection->HidCollectInfo.Polled)
        {
            DPRINT1("[HIDCLASS] Polled collections not implemented! FIXME\n");
            ASSERT(PDODeviceExtension->Common.DriverExtension->DevicesArePolled == FALSE);
            return STATUS_NOT_SUPPORTED;
        }
        else if (!FDODeviceExtension->NotAllocCollectResources)
        {
            Status = HidClassAllShuttlesStart(FDODeviceExtension);

            if (!NT_SUCCESS(Status))
            {
                return Status;
            }
        }
    }

    PDODeviceExtension->HidPdoState = HIDCLASS_STATE_STARTED;

    HidClassSymbolicLinkOnOff(PDODeviceExtension,
                              PDODeviceExtension->CollectionNumber,
                              TRUE,
                              PDODeviceExtension->SelfDevice);

    if (!PDODeviceExtension->IsGenericHid &&
         PDODeviceExtension->Capabilities.DeviceWake > 1 &&
         PDODeviceExtension->Capabilities.SystemWake > 1)
    {
        DPRINT("HidClassPdoStart: FIXME RemoteWake and WMI\n");
        //IoWMIRegistrationControl(PDODeviceExtension->SelfDevice,
        //                         WMIREG_ACTION_REGISTER);
    }

    if (HidClassAllPdoInitialized(FDODeviceExtension, 1))
    {
        DPRINT("HidClassPdoStart: FIXME HidClassStartIdleTimeout\n");
        //HidClassStartIdleTimeout(FDODeviceExtension, 1);
    }

    return Status;
}

VOID
NTAPI
HidClassCompleteReadsForCollection(
    IN PHIDCLASS_COLLECTION HidCollection)
{
    KIRQL OldIrql;
    PLIST_ENTRY ReportList;
    PLIST_ENTRY Entry;
    LIST_ENTRY ListHead;
    PKSPIN_LOCK SpinLock;
    PHIDCLASS_FILEOP_CONTEXT FileContext;

    DPRINT("HidClassCompleteReadsForCollection: HidCollection - %p\n", HidCollection);

    InitializeListHead(&ListHead);

    SpinLock = &HidCollection->CollectSpinLock;
    KeAcquireSpinLock(&HidCollection->CollectSpinLock, &OldIrql);

    ReportList = &HidCollection->InterruptReportList;

    while (!IsListEmpty(ReportList))
    {
        Entry = RemoveHeadList(ReportList);
        InsertTailList(&ListHead, Entry);
    }

    while (!IsListEmpty(&ListHead))
    {
        Entry = RemoveHeadList(&ListHead);
        InsertTailList(&HidCollection->InterruptReportList, Entry);

        KeReleaseSpinLock(SpinLock, OldIrql);

        FileContext = CONTAINING_RECORD(Entry,
                                        HIDCLASS_FILEOP_CONTEXT,
                                        InterruptReportLink);

        HidClassCompleteReadsForFileContext(HidCollection, FileContext);

        KeAcquireSpinLock(SpinLock, &OldIrql);
    }

    KeReleaseSpinLock(SpinLock, OldIrql);
}

VOID
NTAPI
HidClassRemoveCollection(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension,
    IN PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension,
    IN PIRP Irp)
{
    PHIDCLASS_COLLECTION HidCollections;

    DPRINT("HidClassRemoveCollection: Irp - %p\n", Irp);

    if (PDODeviceExtension->HidPdoPrevState == HIDCLASS_STATE_NOT_INIT ||
        PDODeviceExtension->HidPdoState == HIDCLASS_STATE_NOT_INIT)
    {
        PDODeviceExtension->HidPdoState = HIDCLASS_STATE_NOT_INIT;
        return;
    }

    if (!PDODeviceExtension->IsGenericHid && FDODeviceExtension &&
        FDODeviceExtension->Capabilities.DeviceWake > 1 && //FIXME const.
        FDODeviceExtension->Capabilities.SystemWake > 1)
    {
        DPRINT("HidClassRemoveCollection: FIXME WMI\n");
        //WMIRegistrationControl(PDODeviceExtension->SelfDevice,
        //                         WMIREG_ACTION_DEREGISTER);
    }

    DPRINT("HidClassRemoveCollection: FIXME cancel Wake Irp\n");

    PDODeviceExtension->HidPdoState = HIDCLASS_STATE_NOT_INIT;

    if (FDODeviceExtension)
    {
        HidCollections = FDODeviceExtension->HidCollections;

        if (HidCollections)
        {
            PHIDCLASS_COLLECTION HidCollection;

            HidCollection = &HidCollections[PDODeviceExtension->PdoIdx];

            HidClassCompleteReadsForCollection(HidCollection);

            if (HidCollection->HidCollectInfo.Polled)
            {
                DPRINT("HidClassRemoveCollection: FIXME stop polling\n");
            }

            DPRINT("HidClassRemoveCollection: FIXME handle PowerEvent Irp\n");
        }
    }
}

NTSTATUS
NTAPI
HidClassQueryInterface(
    IN PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension,
    IN PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    //PINTERFACE Interface;

    DPRINT("HidClassQueryInterface: ... \n");

    IoStack = Irp->Tail.Overlay.CurrentStackLocation;

    if (RtlCompareMemory(IoStack->Parameters.QueryInterface.InterfaceType,
                         &GUID_HID_INTERFACE_NOTIFY,
                         sizeof(GUID)) == sizeof(GUID))
    {
        DPRINT("HidClassQueryInterface: GUID_HID_INTERFACE_NOTIFY not implemented \n");
    }
    else if (RtlCompareMemory(IoStack->Parameters.QueryInterface.InterfaceType,
                              &GUID_HID_INTERFACE_HIDPARSE,
                              sizeof(GUID)) == sizeof(GUID))
    {
        DPRINT("HidClassQueryInterface: GUID_HID_INTERFACE_HIDPARSE not implemented \n");
    }

    return Irp->IoStatus.Status;
}

NTSTATUS
HidClassPDO_PnP(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;
    PPNP_BUS_INFORMATION BusInformation;
    PDEVICE_RELATIONS DeviceRelation;
    ULONG OldState;
    ULONG PdoIdx;
    BOOLEAN IsDeleteDevice = FALSE;
    BOOLEAN IsNotPendingDelete = FALSE;
    KIRQL OldIrql;

    //
    // Get device extensions
    //
    PDODeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(PDODeviceExtension->Common.IsFDO == FALSE);
    FDODeviceExtension = PDODeviceExtension->FDODeviceExtension;

    if (FDODeviceExtension)
    {
        IsNotPendingDelete = TRUE;

        KeAcquireSpinLock(&FDODeviceExtension->HidRemoveDeviceSpinLock, &OldIrql);

        //
        // FIXME remove lock
        //
        if (0)//IoAcquireRemoveLock(&FDODeviceExtension->HidRemoveLock, 0) == STATUS_DELETE_PENDING)
        {
            DPRINT("[HIDCLASS]: PDO STATUS_DELETE_PENDING\n");
            IsNotPendingDelete = FALSE;
        }

        KeReleaseSpinLock(&FDODeviceExtension->HidRemoveDeviceSpinLock, OldIrql);
    }

    //
    // get current irp stack location
    //
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    switch (IoStack->MinorFunction)
    {
        case IRP_MN_QUERY_ID:
        {
            DPRINT("[HIDCLASS]: PDO IRP_MN_QUERY_ID IdType - %x\n",
                   IoStack->Parameters.QueryId.IdType);

            if (IoStack->Parameters.QueryId.IdType == BusQueryDeviceID)
            {
                Status = HidClassPDO_HandleQueryDeviceId(DeviceObject, Irp);
                break;
            }
            else if (IoStack->Parameters.QueryId.IdType == BusQueryHardwareIDs)
            {
                Status = HidClassPDO_HandleQueryHardwareId(DeviceObject, Irp);
                break;
            }
            else if (IoStack->Parameters.QueryId.IdType == BusQueryInstanceID)
            {
                Status = HidClassPDO_HandleQueryInstanceId(DeviceObject, Irp);
                break;
            }
            else if (IoStack->Parameters.QueryId.IdType == BusQueryCompatibleIDs)
            {
                Status = HidClassPDO_HandleQueryCompatibleId(DeviceObject, Irp);
                break;
            }

            //
            // BusQueryDeviceSerialNumber (serial number for device) or unknown
            //
            DPRINT1("[HIDCLASS]: IRP_MN_QUERY_ID IdType %x unimplemented\n",
                    IoStack->Parameters.QueryId.IdType);

            Status = Irp->IoStatus.Status;
            break;
        }
        case IRP_MN_QUERY_CAPABILITIES:
        {
            PDEVICE_CAPABILITIES DeviceCapabilities;

            DPRINT("[HIDCLASS]: PDO IRP_MN_QUERY_CAPABILITIES\n");
            DeviceCapabilities = IoStack->Parameters.DeviceCapabilities.Capabilities;

            if (DeviceCapabilities == NULL)
            {
                //
                // Invalid parameter of request
                //
                Irp->IoStatus.Information = 0;
                Status = STATUS_DEVICE_CONFIGURATION_ERROR;
                break;
            }

            //
            // Copy capabilities from PDO extension
            //
            RtlCopyMemory(DeviceCapabilities,
                          &PDODeviceExtension->Capabilities,
                          sizeof(DEVICE_CAPABILITIES));

            //
            // Correcting capabilities fields
            //
            DeviceCapabilities->LockSupported = 0;
            DeviceCapabilities->EjectSupported = 0;
            DeviceCapabilities->Removable = 0;
            DeviceCapabilities->DockDevice = 0;
            DeviceCapabilities->UniqueID = 0;
            DeviceCapabilities->SilentInstall = 1;

            if (PDODeviceExtension->IsGenericHid)
            {
                DeviceCapabilities->RawDeviceOK = 1;
            }
            else
            {
                DeviceCapabilities->RawDeviceOK = 0;
            }

            Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = (ULONG_PTR)DeviceCapabilities;
            break;
        }
        case IRP_MN_QUERY_BUS_INFORMATION:
        {
            DPRINT("[HIDCLASS]: PDO IRP_MN_QUERY_BUS_INFORMATION\n");

            BusInformation = ExAllocatePoolWithTag(NonPagedPool,
                                                   sizeof(PNP_BUS_INFORMATION),
                                                   HIDCLASS_TAG);

            if (!BusInformation)
            {
                Irp->IoStatus.Information = 0;
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            //
            // fill in result
            //
            RtlCopyMemory(&BusInformation->BusTypeGuid,
                          &GUID_BUS_TYPE_HID,
                          sizeof(GUID));

            BusInformation->LegacyBusType = PNPBus;
            BusInformation->BusNumber = FDODeviceExtension->BusNumber;

            Irp->IoStatus.Information = (ULONG_PTR)BusInformation;
            Status = STATUS_SUCCESS;
            break;
        }
        case IRP_MN_QUERY_PNP_DEVICE_STATE:
        {
            DPRINT("[HIDCLASS]: PDO IRP_MN_QUERY_PNP_DEVICE_STATE (%x)\n",
                   PDODeviceExtension->HidPdoState);

            if (PDODeviceExtension->HidPdoState == HIDCLASS_STATE_FAILED)
            {
                Irp->IoStatus.Information |= PNP_DEVICE_FAILED;
            }
            else if (PDODeviceExtension->HidPdoState == HIDCLASS_STATE_DISABLED)
            {
                Irp->IoStatus.Information |= PNP_DEVICE_DISABLED;
            }
            else if (PDODeviceExtension->HidPdoState == HIDCLASS_STATE_REMOVED ||
                     PDODeviceExtension->HidPdoState == HIDCLASS_STATE_DELETED)
            {
                Irp->IoStatus.Information |= PNP_DEVICE_REMOVED;
            }

            Status = STATUS_SUCCESS;
            break;
        }
        case IRP_MN_QUERY_DEVICE_RELATIONS:
        {
            DPRINT("[HIDCLASS]: PDO IRP_MN_QUERY_DEVICE_RELATIONS Type - %x\n",
                   IoStack->Parameters.QueryDeviceRelations.Type);

            //
            // only target relations are supported
            //
            if (IoStack->Parameters.QueryDeviceRelations.Type != TargetDeviceRelation)
            {
                //
                // not supported
                //
                Status = Irp->IoStatus.Status;
                break;
            }

            //
            // allocate device relations
            //
            DeviceRelation = ExAllocatePoolWithTag(NonPagedPool,
                                                   sizeof(DEVICE_RELATIONS),
                                                   HIDCLASS_TAG);

            if (!DeviceRelation)
            {
                //
                // no memory
                //
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            //
            // init device relation
            //
            DeviceRelation->Count = 1;
            DeviceRelation->Objects[0] = PDODeviceExtension->SelfDevice;
            ObReferenceObject(PDODeviceExtension->SelfDevice);

            //
            // store result
            //
            Irp->IoStatus.Information = (ULONG_PTR)DeviceRelation;
            Status = STATUS_SUCCESS;
            break;
        }
        case IRP_MN_START_DEVICE:
        {
            DPRINT("[HIDCLASS]: PDO IRP_MN_START_DEVICE\n");
            Status = HidClassPdoStart(PDODeviceExtension, Irp);

            if (NT_SUCCESS(Status))
            {
                DPRINT("[HIDCLASS] FIXME interface GUID_HID_INTERFACE_NOTIFY support\n");
            }

            break;
        }
        case IRP_MN_REMOVE_DEVICE:
        {
            DPRINT("[HIDCLASS]: PDO IRP_MN_REMOVE_DEVICE\n");
            HidClassRemoveCollection(FDODeviceExtension, PDODeviceExtension, Irp);

            DPRINT("[HIDCLASS] FIXME interface GUID_HID_INTERFACE_NOTIFY support\n");

            Status = STATUS_SUCCESS;

            if (IsNotPendingDelete && FDODeviceExtension->IsRelationsOn)
            {
                break;
            }

            IsDeleteDevice = TRUE;
            break;
        }
        case IRP_MN_QUERY_INTERFACE:
        {
            DPRINT("[HIDCLASS]: PDO IRP_MN_QUERY_INTERFACE\n");
            Status = HidClassQueryInterface(PDODeviceExtension, Irp);
            break;
        }
        case IRP_MN_CANCEL_STOP_DEVICE:
        {
            DPRINT("[HIDCLASS]: PDO IRP_MN_CANCEL_STOP_DEVICE\n");
            PDODeviceExtension->HidPdoState = PDODeviceExtension->HidPdoPrevState;
            Status = STATUS_SUCCESS;
            break;
        }
        case IRP_MN_QUERY_STOP_DEVICE:
        {
            DPRINT("[HIDCLASS]: PDO IRP_MN_QUERY_STOP_DEVICE\n");
            PDODeviceExtension->HidPdoPrevState = PDODeviceExtension->HidPdoState;
            PDODeviceExtension->HidPdoState = HIDCLASS_STATE_FAILED;
            Status = STATUS_SUCCESS;
            break;
        }
        case IRP_MN_CANCEL_REMOVE_DEVICE:
        {
            BOOLEAN IsStarted;

            DPRINT("[HIDCLASS]: PDO IRP_MN_CANCEL_REMOVE_DEVICE\n");

            IsStarted = (PDODeviceExtension->HidPdoPrevState ==
                         HIDCLASS_STATE_STARTED);

            PDODeviceExtension->HidPdoState = PDODeviceExtension->HidPdoPrevState;

            if (IsStarted)
            {
                HidClassSymbolicLinkOnOff(PDODeviceExtension,
                                          PDODeviceExtension->CollectionNumber,
                                          TRUE,
                                          PDODeviceExtension->SelfDevice);
            }

            Status = STATUS_SUCCESS;
            break;
        }
        case IRP_MN_QUERY_REMOVE_DEVICE:
        {
            DPRINT("[HIDCLASS]: PDO IRP_MN_QUERY_REMOVE_DEVICE\n");
            goto Removal;
        }
        case IRP_MN_SURPRISE_REMOVAL:
        {
            DPRINT("[HIDCLASS]: PDO IRP_MN_SURPRISE_REMOVAL\n");
Removal:
            OldState = PDODeviceExtension->HidPdoState;
            PDODeviceExtension->HidPdoPrevState = OldState;
            PDODeviceExtension->HidPdoState = HIDCLASS_STATE_DISABLED;

            if (((OldState == HIDCLASS_STATE_STARTED) &&
                 (HidClassSymbolicLinkOnOff(PDODeviceExtension,
                                            PDODeviceExtension->CollectionNumber,
                                            FALSE,
                                            PDODeviceExtension->SelfDevice),
                     OldState = PDODeviceExtension->HidPdoPrevState,
                     PDODeviceExtension->HidPdoPrevState == HIDCLASS_STATE_STARTED))
                 || OldState == HIDCLASS_STATE_STOPPING)
            {
                PHIDCLASS_COLLECTION HidCollection;

                PdoIdx = PDODeviceExtension->PdoIdx;
                HidCollection = &FDODeviceExtension->HidCollections[PdoIdx];
                HidClassCompleteReadsForCollection(HidCollection);

                //
                // FIXME: CompleteAllPdoPowerDelayedIrps();
                //
            }

            Status = STATUS_SUCCESS;
            break;
        }
        case IRP_MN_STOP_DEVICE:
        {
            DPRINT("[HIDCLASS]: PDO IRP_MN_STOP_DEVICE\n");
            if (PDODeviceExtension->HidPdoPrevState != HIDCLASS_STATE_NOT_INIT)
            {
                HidClassSymbolicLinkOnOff(PDODeviceExtension,
                                          PDODeviceExtension->CollectionNumber,
                                          FALSE,
                                          PDODeviceExtension->SelfDevice);

                //
                // FIXME: handle PowerEvent Irp;
                //

                PDODeviceExtension->HidPdoState = HIDCLASS_STATE_STOPPING;

                DPRINT("[HIDCLASS] FIXME interface GUID_HID_INTERFACE_NOTIFY support\n");
            }

            Status = STATUS_SUCCESS;
            break;
        }
        default:
        {
            DPRINT("[HIDCLASS]: PDO not handled IRP_MN_\n");
            Status = Irp->IoStatus.Status;
            break;
        }
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (IsDeleteDevice)
    {
        if (IsNotPendingDelete)
        {
            PdoIdx = PDODeviceExtension->PdoIdx;
            FDODeviceExtension->ClientPdoExtensions[PdoIdx] = NULL;
        }

        DPRINT("HidClassPDO_PnP: IoDeleteDevice (%x)\n",
               PDODeviceExtension->SelfDevice);

        ObDereferenceObject(PDODeviceExtension->SelfDevice);
        IoDeleteDevice(PDODeviceExtension->SelfDevice);
    }

    if (IsNotPendingDelete)
    {
        DPRINT("HidClassPDO_PnP: FIXME remove lock\n");
        //IoReleaseRemoveLock(&FDODeviceExtension->HidRemoveLock, 0);
    }

    DPRINT("HidClassPDO_PnP: exit Status - %x\n", Status);
    return Status;
}

NTSTATUS
HidClassCreatePDOs(
    IN PDEVICE_OBJECT DeviceObject,
    OUT PDEVICE_RELATIONS *OutDeviceRelations)
{
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    NTSTATUS Status = STATUS_SUCCESS;
    PDEVICE_OBJECT PDODeviceObject;
    PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension;
    ULONG PdoIdx = 0;
    PDEVICE_RELATIONS DeviceRelations;
    PHIDCLASS_DRIVER_EXTENSION DriverExtension;
    PHIDP_DEVICE_DESC DeviceDescription;
    ULONG DescLength;
    ULONG CollectionNumber;
    PHIDP_COLLECTION_DESC CollectionDesc;
    USHORT UsagePage;
    USHORT Usage;
    KIRQL OldIrql;

    DPRINT("[HIDCLASS] HidClassCreatePDOs: DeviceObject %p\n", DeviceObject);

    //
    // get device extension
    //
    FDODeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(FDODeviceExtension->Common.IsFDO);

    DriverExtension = RefDriverExt(FDODeviceExtension->Common.DriverExtension->DriverObject);

    if (!DriverExtension)
    {
        DPRINT1("[HIDCLASS] Error: DriverExtension is NULL\n");
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    DeviceDescription = &FDODeviceExtension->Common.DeviceDescription;
    DescLength = DeviceDescription->CollectionDescLength;

    if (!DescLength)
    {
        DPRINT1("[HIDCLASS] Error: CollectionDescLength is 0\n");
        Status = STATUS_DEVICE_CONFIGURATION_ERROR;
        DerefDriverExt(FDODeviceExtension->Common.DriverExtension->DriverObject);
        return Status;
    }

    //
    // first allocate device relations
    //
    if (*OutDeviceRelations == NULL)
    {
        ULONG RelationsLength;

        RelationsLength = sizeof(DEVICE_RELATIONS) +
                          DescLength * sizeof(PDEVICE_OBJECT);

        DeviceRelations = ExAllocatePoolWithTag(NonPagedPool,
                                                RelationsLength,
                                                HIDCLASS_TAG);
    }

    if (!DeviceRelations)
    {
        DPRINT1("[HIDCLASS]: Allocate DeviceRelations failed\n");
        DerefDriverExt(FDODeviceExtension->Common.DriverExtension->DriverObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // allocate ClientPdoExtensions array
    //
    if (!FDODeviceExtension->ClientPdoExtensions)
    {
        PVOID clientPdoExtensions;
        ULONG Length;

        Length = DescLength * sizeof(PHIDCLASS_PDO_DEVICE_EXTENSION);

        clientPdoExtensions = ExAllocatePoolWithTag(NonPagedPool,
                                                    Length,
                                                    HIDCLASS_TAG);

        FDODeviceExtension->ClientPdoExtensions = clientPdoExtensions;
    }

    if (!FDODeviceExtension->ClientPdoExtensions)
    {
        DPRINT1("[HIDCLASS]: Allocate DeviceRelations failed\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;

        if (!NT_SUCCESS(Status))
        {
            ExFreePoolWithTag(DeviceRelations, HIDCLASS_TAG);
            FDODeviceExtension->DeviceRelations = NULL;
        }

        goto Exit;
    }

    DeviceRelations->Count = DescLength;

    if (DescLength <= 0)
    {
        DPRINT1("[HIDCLASS] Error: CollectionDescLength is <= 0\n");
        DerefDriverExt(FDODeviceExtension->Common.DriverExtension->DriverObject);
        return Status;
    }

    //
    // let's create a PDOs for top level collections
    //
    do
    {
        CollectionNumber = DeviceDescription->CollectionDesc[PdoIdx].CollectionNumber;

        //
        // let's create the device object
        //
        Status = IoCreateDevice(DriverExtension->DriverObject,
                                sizeof(HIDCLASS_PDO_DEVICE_EXTENSION),
                                NULL,
                                FILE_DEVICE_UNKNOWN,
                                FILE_AUTOGENERATED_DEVICE_NAME,
                                FALSE,
                                &PDODeviceObject);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("[HIDCLASS] Failed to create PDO %x\n", Status);
            goto ErrorExit;
        }

        DPRINT("[HIDCLASS] HidClassCreatePDOs: added PDO IoCreateDevice (%p)\n",
               PDODeviceObject);

        CollectionDesc = &DeviceDescription->CollectionDesc[PdoIdx];
        UsagePage = CollectionDesc->UsagePage;
        Usage = CollectionDesc->Usage;

        ObReferenceObject(PDODeviceObject);

        //
        // patch stack size
        //
        PDODeviceObject->StackSize = DeviceObject->StackSize + 1;

        //
        // get device extension
        //
        PDODeviceExtension = PDODeviceObject->DeviceExtension;
        RtlZeroMemory(PDODeviceExtension, sizeof(HIDCLASS_PDO_DEVICE_EXTENSION));

        //
        // init device extension
        //
        PDODeviceExtension->Common.IsFDO = FALSE;

        PDODeviceExtension->Common.HidDeviceExtension.MiniDeviceExtension =
        FDODeviceExtension->Common.HidDeviceExtension.MiniDeviceExtension;

        PDODeviceExtension->Common.HidDeviceExtension.NextDeviceObject =
        FDODeviceExtension->Common.HidDeviceExtension.NextDeviceObject;

        PDODeviceExtension->Common.HidDeviceExtension.PhysicalDeviceObject =
        FDODeviceExtension->Common.HidDeviceExtension.PhysicalDeviceObject;

        PDODeviceExtension->Common.DriverExtension =
        FDODeviceExtension->Common.DriverExtension;

        PDODeviceExtension->SelfDevice = PDODeviceObject;
        PDODeviceExtension->FDODeviceObject = DeviceObject;
        PDODeviceExtension->PdoIdx = PdoIdx;
        PDODeviceExtension->CollectionNumber = CollectionNumber;
        PDODeviceExtension->HidPdoState = HIDCLASS_STATE_NOT_INIT;

        KeAcquireSpinLock(&FDODeviceExtension->HidRemoveDeviceSpinLock, &OldIrql);
        PDODeviceExtension->FDODeviceExtension = FDODeviceExtension;
        KeReleaseSpinLock(&FDODeviceExtension->HidRemoveDeviceSpinLock, OldIrql);

        PDODeviceExtension->IsSessionSecurity = FALSE;

        PDODeviceExtension->IsGenericHid = (UsagePage == HID_USAGE_PAGE_GENERIC) &&
                                            (Usage == HID_USAGE_GENERIC_POINTER ||
                                             Usage == HID_USAGE_GENERIC_MOUSE ||
                                             Usage == HID_USAGE_GENERIC_KEYBOARD ||
                                             Usage == HID_USAGE_GENERIC_KEYPAD);

        //
        // copy device data
        //
        RtlCopyMemory(&PDODeviceExtension->Common.Attributes,
                      &FDODeviceExtension->Common.Attributes,
                      sizeof(HID_DEVICE_ATTRIBUTES));

        RtlCopyMemory(&PDODeviceExtension->Common.DeviceDescription,
                      &FDODeviceExtension->Common.DeviceDescription,
                      sizeof(HIDP_DEVICE_DESC));

        RtlCopyMemory(&PDODeviceExtension->Capabilities,
                      &FDODeviceExtension->Capabilities,
                      sizeof(DEVICE_CAPABILITIES));

        //
        // store device object in device relations
        //
        DeviceRelations->Objects[PdoIdx] = PDODeviceObject;
        FDODeviceExtension->ClientPdoExtensions[PdoIdx] = PDODeviceExtension;

        //
        // set device flags
        //
        PDODeviceObject->Flags |= DO_POWER_PAGABLE;

        //
        // device is initialized
        //
        PDODeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

        //
        // move to next
        //
        PdoIdx++;

    }
    while (PdoIdx < DescLength);

    //
    // store device relations
    //
    *OutDeviceRelations = DeviceRelations;

    if (!NT_SUCCESS(Status))
    {
ErrorExit:
        ExFreePoolWithTag(FDODeviceExtension->ClientPdoExtensions,
                          HIDCLASS_TAG);

        FDODeviceExtension->ClientPdoExtensions = NULL;

        if (!NT_SUCCESS(Status))
        {
            ExFreePoolWithTag(DeviceRelations, HIDCLASS_TAG);
            FDODeviceExtension->DeviceRelations = NULL;
        }
    }

Exit:
    DerefDriverExt(FDODeviceExtension->Common.DriverExtension->DriverObject);
    return Status;
}
