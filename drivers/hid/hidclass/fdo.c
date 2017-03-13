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

#define NDEBUG
#include <debug.h>

PVOID
NTAPI
HidClassGetSystemAddressForMdlSafe(
    IN PMDL MemoryDescriptorList)
{
    PVOID VAddress = NULL;

    if (MemoryDescriptorList)
    {
        MemoryDescriptorList->MdlFlags |= MDL_MAPPING_CAN_FAIL;

        if (MemoryDescriptorList->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA |
                                              MDL_SOURCE_IS_NONPAGED_POOL))
        {
            VAddress = MemoryDescriptorList->MappedSystemVa;
        }
        else
        {
            VAddress = MmMapLockedPages(MemoryDescriptorList, KernelMode);
        }

        MemoryDescriptorList->MdlFlags &= ~MDL_MAPPING_CAN_FAIL;
    }

    return VAddress;
}

VOID
NTAPI
HidClassEnqueueInterruptReport(
    IN PHIDCLASS_FILEOP_CONTEXT FileContext,
    IN PHIDCLASS_INT_REPORT_HEADER Header)
{
    PLIST_ENTRY Entry;

    DPRINT("HidClassEnqueueInterruptReport: ... \n");

    Entry = NULL;

    if (FileContext->PendingReports >= FileContext->MaxReportQueueSize)
    {
        DPRINT1("[HIDCLASS] Report queue (size %x) is full \n",
                FileContext->MaxReportQueueSize);

        Entry = RemoveHeadList(&FileContext->ReportList);
        FileContext->PendingReports--;
    }

    InsertTailList(&FileContext->ReportList, &Header->ReportLink);
    FileContext->PendingReports++;

    if (Entry)
    {
        ExFreePoolWithTag(Entry, 0);
    }
}

PHIDCLASS_INT_REPORT_HEADER
NTAPI
HidClassDequeueInterruptReport(
    IN PHIDCLASS_FILEOP_CONTEXT FileContext,
    IN ULONG  ReadLength)
{
    PLIST_ENTRY ReportList;
    PHIDCLASS_INT_REPORT_HEADER Header;

    DPRINT("HidClassDequeueInterruptReport: ... \n");

    if (IsListEmpty(&FileContext->ReportList))
    {
        return NULL;
    }

    ReportList = &FileContext->ReportList;

    Header = CONTAINING_RECORD(ReportList->Flink,
                               HIDCLASS_INT_REPORT_HEADER,
                               ReportLink);

    RemoveHeadList(ReportList);

    if (ReadLength > 0 && (Header->InputLength > ReadLength))
    {
        InsertHeadList(ReportList, &Header->ReportLink);
        return NULL;
    }

    InitializeListHead(&Header->ReportLink);

    FileContext->PendingReports--;

    return Header;
}

VOID
NTAPI
HidClassCancelReadIrp(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    PHIDCLASS_COLLECTION HidCollection;
    PIO_STACK_LOCATION IoStack;
    PHIDCLASS_FILEOP_CONTEXT FileContext;
    KIRQL OldIrql;

    DPRINT("HidClassCancelReadIrp: Irp - %p\n", Irp);

    PDODeviceExtension = DeviceObject->DeviceExtension;
    FDODeviceExtension = PDODeviceExtension->FDODeviceExtension;

    HidCollection = &FDODeviceExtension->HidCollections[PDODeviceExtension->PdoIdx];
    IoStack = Irp->Tail.Overlay.CurrentStackLocation;

    FileContext = IoStack->FileObject->FsContext;

    IoReleaseCancelSpinLock(Irp->CancelIrql);

    KeAcquireSpinLock(&FileContext->Lock, &OldIrql);
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);

    HidCollection->NumPendingReads--;
    KeReleaseSpinLock(&FileContext->Lock, OldIrql);

    Irp->IoStatus.Status = STATUS_CANCELLED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

NTSTATUS
NTAPI
HidClassEnqueueInterruptReadIrp(
    IN PHIDCLASS_COLLECTION HidCollection,
    IN PHIDCLASS_FILEOP_CONTEXT FileContext,
    IN PIRP Irp)
{
    DPRINT("HidClassEnqueueInterruptReadIrp: Irp - %p\n", Irp);

    IoSetCancelRoutine(Irp, HidClassCancelReadIrp);

    if (Irp->Cancel)
    {
        if (IoSetCancelRoutine(Irp, NULL))
        {
            return STATUS_CANCELLED;
        }

        InitializeListHead(&Irp->Tail.Overlay.ListEntry);
    }
    else
    {
        InsertTailList(&FileContext->InterruptReadIrpList,
                       &Irp->Tail.Overlay.ListEntry);
    }

    ++HidCollection->NumPendingReads;
    IoMarkIrpPending(Irp);

    return STATUS_PENDING;
}

PIRP
NTAPI
HidClassDequeueInterruptReadIrp(
    IN PHIDCLASS_COLLECTION HidCollection,
    IN PHIDCLASS_FILEOP_CONTEXT FileContext)
{
    PLIST_ENTRY ReadIrpList;
    PLIST_ENTRY Entry;
    PIRP Irp = NULL;

    ReadIrpList = &FileContext->InterruptReadIrpList;

    do
    {
        if (ReadIrpList->Flink == ReadIrpList)
        {
            break;
        }

        Entry = RemoveHeadList(ReadIrpList);

        Irp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);

        if (IoSetCancelRoutine(Irp, NULL))
        {
            HidCollection->NumPendingReads--;
        }
        else
        {
            InitializeListHead(Entry);
            Irp = NULL;
        }
    }
    while (!Irp);

    DPRINT("HidClassDequeueInterruptReadIrp: Irp - %p\n", Irp);

    return Irp;
}

PHIDP_COLLECTION_DESC
NTAPI
GetCollectionDesc(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension,
    IN UCHAR CollectionNumber)
{
    PHIDP_COLLECTION_DESC CollectionDescArray;
    PHIDP_COLLECTION_DESC HidCollectionDesc = NULL;
    ULONG NumCollections;
    ULONG Idx = 0;

    DPRINT("GetCollectionDesc: CollectionNumber - %x\n", CollectionNumber);

    CollectionDescArray = FDODeviceExtension->Common.DeviceDescription.CollectionDesc;

    if (CollectionDescArray)
    {
        NumCollections = FDODeviceExtension->Common.DeviceDescription.CollectionDescLength;

        if (NumCollections)
        {
            while (CollectionDescArray[Idx].CollectionNumber != CollectionNumber)
            {
                ++Idx;

                if (Idx >= NumCollections)
                {
                    return HidCollectionDesc;
                }
            }

            HidCollectionDesc = &CollectionDescArray[Idx];
        }
    }

    return HidCollectionDesc;
}

PHIDCLASS_COLLECTION
NTAPI
GetHidclassCollection(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension,
    IN ULONG CollectionNumber)
{
    PHIDCLASS_COLLECTION HidCollections;
    ULONG NumCollections;
    ULONG Idx = 0;
    PHIDCLASS_COLLECTION HidCollection = NULL;

    DPRINT("GetHidclassCollection: CollectionNumber - %x\n", CollectionNumber);

    HidCollections = FDODeviceExtension->HidCollections;

    if (HidCollections && HidCollections != HIDCLASS_NULL_POINTER)
    {
        NumCollections = FDODeviceExtension->Common.DeviceDescription.CollectionDescLength;

        if (NumCollections)
        {
            while (HidCollections[Idx].CollectionNumber != CollectionNumber)
            {
                ++Idx;

                if (Idx >= NumCollections)
                {
                    return HidCollection;
                }
            }

            HidCollection = &HidCollections[Idx];
        }
    }

    return HidCollection;
}

PHIDP_REPORT_IDS
NTAPI
GetReportIdentifier(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension,
    IN UCHAR Id)
{
    PHIDP_DEVICE_DESC DeviceDescription;
    PHIDP_REPORT_IDS ReportIDs;
    PHIDP_REPORT_IDS Result = NULL;
    ULONG NumCollections;
    ULONG Idx;

    DPRINT("GetReportIdentifier: Id - %x\n", Id);

    DeviceDescription = &FDODeviceExtension->Common.DeviceDescription;

    ReportIDs = DeviceDescription->ReportIDs;

    if (ReportIDs)
    {
        NumCollections = DeviceDescription->ReportIDsLength;

        Idx = 0;

        if (NumCollections)
        {
            while (DeviceDescription->ReportIDs[Idx].ReportID != Id)
            {
                ++Idx;

                if (Idx >= NumCollections)
                {
                    return Result;
                }
            }

            Result = &ReportIDs[Idx];
        }
    }

    return Result;
}

PHIDCLASS_SHUTTLE
NTAPI
GetShuttleFromIrp(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension,
    IN PIRP Irp)
{
    ULONG ShuttleCount;
    ULONG ix;
    PHIDCLASS_SHUTTLE Shuttle;
    PHIDCLASS_SHUTTLE Result = NULL;

    ShuttleCount = FDODeviceExtension->ShuttleCount;

    ix = 0;

    if (ShuttleCount)
    {
        Shuttle = &FDODeviceExtension->Shuttles[0];

        while (Shuttle[ix].ShuttleIrp != Irp)
        {
            ++ix;

            if (ix >= ShuttleCount)
            {
                return Result;
            }
        }

        Result = &Shuttle[ix];
    }

    DPRINT("GetShuttleFromIrp: Irp - %p, Shuttle - %p\n",
           Irp,
           Result);

    return Result;
}

ULONG
NTAPI
HidClassSetMaxReportSize(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension)
{
    PHIDP_DEVICE_DESC DeviceDescription;
    PHIDP_REPORT_IDS ReportId;
    ULONG Idx = 0;
    ULONG InputLength;

    DeviceDescription = &FDODeviceExtension->Common.DeviceDescription;
    FDODeviceExtension->MaxReportSize = 0;

    DPRINT("HidClassSetMaxReportSize: ReportIDsLength - %x\n",
           DeviceDescription->ReportIDsLength);

    if (DeviceDescription->ReportIDsLength)
    {
        do
        {
            ReportId = &DeviceDescription->ReportIDs[Idx];

            if (GetHidclassCollection(FDODeviceExtension, ReportId->CollectionNumber))
            {
                InputLength = ReportId->InputLength;

                if (InputLength > FDODeviceExtension->MaxReportSize)
                {
                    FDODeviceExtension->MaxReportSize = InputLength;
                }
            }

            ++Idx;
        }
        while (Idx < DeviceDescription->ReportIDsLength);
    }

    DPRINT("HidClassSetMaxReportSize: MaxReportSize - %x\n",
           FDODeviceExtension->MaxReportSize);

    return FDODeviceExtension->MaxReportSize;
}

NTSTATUS
NTAPI
HidClassGetCollectionDescriptor(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension,
    IN UCHAR CollectionNumber,
    OUT PVOID OutCollectionData,
    OUT PULONG OutLength)
{
    PHIDP_COLLECTION_DESC HidCollectionDesc;
    ULONG Length;
    NTSTATUS Status;

    DPRINT("HidClassGetCollectionDescriptor: CollectionNumber - %x\n", CollectionNumber);

    HidCollectionDesc = GetCollectionDesc(FDODeviceExtension,
                                          CollectionNumber);

    if (HidCollectionDesc)
    {
        Length = HidCollectionDesc->PreparsedDataLength;

        if (*OutLength >= Length)
        {
            Status = 0;
        }
        else
        {
            Length = *OutLength;
            Status = STATUS_INVALID_BUFFER_SIZE;
        }

        RtlCopyMemory(OutCollectionData,
                      HidCollectionDesc->PreparsedData,
                      Length);

        *OutLength = HidCollectionDesc->PreparsedDataLength;
    }
    else
    {
        DPRINT1("[HIDCLASS] Not found collection descriptor\n");
        Status = STATUS_DATA_ERROR;
    }

    return Status;
}

NTSTATUS
NTAPI
HidClassCopyInputReportToUser(
    IN PHIDCLASS_FILEOP_CONTEXT FileContext,
    IN PVOID InputReportBuffer,
    IN PULONG OutLength,
    IN PVOID VAddress)
{
    PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    PHIDP_REPORT_IDS ReportId;
    UCHAR CollectionNumber;
    PHIDP_COLLECTION_DESC HidCollectionDesc;
    ULONG InputLength;
    UCHAR Id;
    NTSTATUS Status = STATUS_DEVICE_DATA_ERROR;

    DPRINT("HidClassCopyInputReportToUser: FileContext - %x\n", FileContext);

    PDODeviceExtension = FileContext->DeviceExtension;
    FDODeviceExtension = PDODeviceExtension->FDODeviceExtension;

    /* first byte of the buffer is the report ID for the report */
    Id = *(PUCHAR)InputReportBuffer;

    ReportId = GetReportIdentifier(FDODeviceExtension, Id);

    if (!ReportId)
    {
        return Status;
    }

    CollectionNumber = ReportId->CollectionNumber;
    HidCollectionDesc = GetCollectionDesc(FDODeviceExtension, CollectionNumber);

    if (!HidCollectionDesc)
    {
        return Status;
    }

    if (!GetHidclassCollection(FDODeviceExtension, CollectionNumber))
    {
        return Status;
    }

    InputLength = HidCollectionDesc->InputLength;

    if (*OutLength < InputLength)
    {
        Status = STATUS_INVALID_BUFFER_SIZE;
    }
    else
    {
        RtlCopyMemory(VAddress, InputReportBuffer, InputLength);

        Status = STATUS_SUCCESS;
    }

    *OutLength = InputLength;

    return Status;
}

NTSTATUS
NTAPI
HidClassProcessInterruptReport(
    IN PHIDCLASS_COLLECTION HidCollection,
    IN PHIDCLASS_FILEOP_CONTEXT FileContext,
    IN PVOID InputReport,
    IN ULONG InputLength,
    IN PIRP * OutIrp)
{
    PIRP Irp;
    PIO_STACK_LOCATION IoStack;
    PVOID VAddress;
    NTSTATUS Status;
    PHIDCLASS_INT_REPORT_HEADER ReportHeader;
    KIRQL OldIrql;
    ULONG ReturnedLength;

    KeAcquireSpinLock(&FileContext->Lock, &OldIrql);

    Irp = HidClassDequeueInterruptReadIrp(HidCollection, FileContext);

    DPRINT("HidClassProcessInterruptReport: FileContext - %p, Irp - %p\n",
           FileContext,
           Irp);

    if (Irp)
    {
        IoStack = Irp->Tail.Overlay.CurrentStackLocation;

        VAddress = HidClassGetSystemAddressForMdlSafe(Irp->MdlAddress);

        if (VAddress)
        {
            ReturnedLength = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

            Status = HidClassCopyInputReportToUser(FileContext,
                                                   InputReport,
                                                   &ReturnedLength,
                                                   VAddress);

            Irp->IoStatus.Status = Status;
            Irp->IoStatus.Information = ReturnedLength;
        }
        else
        {
            Status = STATUS_INVALID_USER_BUFFER;
            Irp->IoStatus.Status = STATUS_INVALID_USER_BUFFER;
        }
    }
    else
    {
        ReportHeader = ExAllocatePoolWithTag(NonPagedPool,
                                             InputLength + sizeof(HIDCLASS_INT_REPORT_HEADER),
                                             HIDCLASS_TAG);

        if (ReportHeader)
        {
            ReportHeader->InputLength = InputLength;

            RtlCopyMemory((PVOID)((ULONG_PTR)ReportHeader + sizeof(HIDCLASS_INT_REPORT_HEADER)),
                          InputReport,
                          InputLength);

            HidClassEnqueueInterruptReport(FileContext, ReportHeader);

            Status = STATUS_PENDING;
        }
        else
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    KeReleaseSpinLock(&FileContext->Lock, OldIrql);

    *OutIrp = Irp;

    return Status;
}

VOID
NTAPI
HidClassHandleInterruptReport(
    IN PHIDCLASS_COLLECTION HidCollection,
    IN PVOID InputReport,
    IN ULONG InputLength,
    IN BOOLEAN IsSessionSecurity)
{
    PHIDCLASS_FILEOP_CONTEXT FileContext;
    PLIST_ENTRY Entry;
    LIST_ENTRY IrpList;
    PIRP Irp;
    KIRQL OldIrql;

    DPRINT("HidClassHandleInterruptReport: ... \n");

    InitializeListHead(&IrpList);

    KeAcquireSpinLock(&HidCollection->CollectSpinLock, &OldIrql);

    Entry = HidCollection->InterruptReportList.Flink;

    while (Entry != &HidCollection->InterruptReportList)
    {
        FileContext = CONTAINING_RECORD(Entry,
                                        HIDCLASS_FILEOP_CONTEXT,
                                        InterruptReportLink);

        if ((!HidCollection->CloseFlag || FileContext->IsMyPrivilegeTrue) &&
            !IsSessionSecurity)
        {
            HidClassProcessInterruptReport(HidCollection,
                                           FileContext,
                                           InputReport,
                                           InputLength,
                                           &Irp);

            if (Irp)
            {
                InsertTailList(&IrpList, &Irp->Tail.Overlay.ListEntry);
            }
        }

        Entry = Entry->Flink;
    }

    KeReleaseSpinLock(&HidCollection->CollectSpinLock, OldIrql);

    while (TRUE)
    {
        Entry = IrpList.Flink;

        if (IsListEmpty(&IrpList))
        {
            break;
        }

        RemoveHeadList(&IrpList);

        Irp = CONTAINING_RECORD(Entry,
                                IRP,
                                Tail.Overlay.ListEntry);

        DPRINT("HidClassHandleInterruptReport: IoCompleteRequest - %p\n",
               Irp);

        IoCompleteRequest(Irp, IO_KEYBOARD_INCREMENT);
    }
}

VOID
NTAPI
HidClassSetDeviceBusy(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension)
{
    DPRINT("HidClassSetDeviceBusy: FIXME \n");
}

NTSTATUS
NTAPI
HidClassInterruptReadComplete(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID Context)
{
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    PHIDCLASS_SHUTTLE Shuttle;
    PHIDP_REPORT_IDS ReportId;
    ULONG HidDataLen;
    PHIDCLASS_COLLECTION HidCollection;
    PHIDP_COLLECTION_DESC HidCollectionDesc;
    PHIDCLASS_PDO_DEVICE_EXTENSION * ClientPdoExtensions;
    PHIDCLASS_PDO_DEVICE_EXTENSION PDODeviceExtension;
    LONG Length;
    PVOID InputReport;
    LONG OldState;
    UCHAR Id;

    DPRINT("HidClassInterruptReadComplete: Irp - %p\n", Irp);

    FDODeviceExtension = (PHIDCLASS_FDO_EXTENSION)Context;

    InterlockedExchangeAdd(&FDODeviceExtension->OutstandingRequests, -1);

    Shuttle = GetShuttleFromIrp(FDODeviceExtension, Irp);

    if (!Shuttle)
    {
        DPRINT1("[HIDCLASS] Shuttle could not be found\n");
        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    OldState = InterlockedCompareExchange(&Shuttle->ShuttleState,
                                          HIDCLASS_SHUTTLE_DISABLED,
                                          HIDCLASS_SHUTTLE_START_READ);

    if (Irp->IoStatus.Status >= 0)
    {
        InputReport = Irp->UserBuffer;
        Length = Irp->IoStatus.Information;

        if (Irp->IoStatus.Information > 0)
        {
            while (TRUE)
            {
                if (FDODeviceExtension->Common.DeviceDescription.ReportIDs->ReportID)
                {
                    /* First byte of the buffer is the report ID for the report */
                    Id = *(PUCHAR)InputReport;
                    InputReport = (PUCHAR)InputReport + 1;
                    --Length;
                }
                else
                {
                    Id = 0;
                }

                ReportId = GetReportIdentifier(FDODeviceExtension, Id);

                if (!ReportId)
                {
                    break;
                }

                if (Id)
                {
                    HidDataLen = ReportId->InputLength - 1;
                }
                else
                {
                    HidDataLen = ReportId->InputLength;
                }

                if (HidDataLen <= 0 || HidDataLen > Length)
                {
                    break;
                }

                HidCollection = GetHidclassCollection(FDODeviceExtension,
                                                      ReportId->CollectionNumber);

                HidCollectionDesc = GetCollectionDesc(FDODeviceExtension,
                                                      ReportId->CollectionNumber);

                if (!HidCollection || !HidCollectionDesc)
                {
                    break;
                }

                ClientPdoExtensions = FDODeviceExtension->ClientPdoExtensions;

                if (!ClientPdoExtensions ||
                    ClientPdoExtensions == HIDCLASS_NULL_POINTER)
                {
                    goto NextData;
                }

                PDODeviceExtension = ClientPdoExtensions[HidCollection->CollectionIdx];

                if (!PDODeviceExtension)
                {
                    goto NextData;
                }

                if (PDODeviceExtension == HIDCLASS_NULL_POINTER ||
                    PDODeviceExtension->HidPdoState != HIDCLASS_STATE_STARTED)
                {
                    goto NextData;
                }

                /* First byte of the buffer is the report ID for the report */
                *(PUCHAR)HidCollection->InputReport = Id;

                RtlCopyMemory((PUCHAR)HidCollection->InputReport + 1,
                              InputReport,
                              HidDataLen);

                DPRINT("HidClassInterruptReadComplete: FIXME CheckReportPowerEvent()\n");
                //CheckReportPowerEvent(FDODeviceExtension,
                //                      HidCollection,
                //                      HidCollection->InputReport,
                //                      HidCollectionDesc->InputLength);

                HidClassHandleInterruptReport(HidCollection,
                                              HidCollection->InputReport,
                                              HidCollectionDesc->InputLength,
                                              PDODeviceExtension->IsSessionSecurity);

NextData:
                /* Next hid data (HID_DATA) */
                InputReport = (PUCHAR)InputReport + HidDataLen;
                Length -= HidDataLen;

                if (Length <= 0)
                {
                    break;
                }
            }
        }

        Shuttle->TimerPeriod.HighPart = -1;
        Shuttle->TimerPeriod.LowPart = -10000000;
    }

    if (OldState != HIDCLASS_SHUTTLE_START_READ)
    {
        if (Shuttle->CancellingShuttle)
        {
            DPRINT1("[HIDCLASS] Cancelling Shuttle %p\n", Shuttle);
            KeSetEvent(&Shuttle->ShuttleDoneEvent, IO_NO_INCREMENT, FALSE);
        }
        else if (Irp->IoStatus.Status < 0)
        {
            DPRINT1("[HIDCLASS] Status - %x, TimerPeriod - %p, Shuttle - %p\n",
                     Irp->IoStatus.Status,
                     Shuttle->TimerPeriod.LowPart,
                     Shuttle);

            KeSetTimer(&Shuttle->ShuttleTimer,
                       Shuttle->TimerPeriod,
                       &Shuttle->ShuttleTimerDpc);
        }
        else
        {
            BOOLEAN IsSending;

            HidClassSubmitInterruptRead(FDODeviceExtension,
                                        Shuttle,
                                        &IsSending);
        }
    }

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
NTAPI
HidClassSubmitInterruptRead(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension,
    IN PHIDCLASS_SHUTTLE Shuttle,
    IN BOOLEAN * OutIsSending)
{
    PIRP Irp;
    PIO_STACK_LOCATION IoStack;
    LARGE_INTEGER DueTime;
    LONG OldState;
    NTSTATUS Status;

    Irp = Shuttle->ShuttleIrp;

    *OutIsSending = 0;

    DPRINT("HidClassSubmitInterruptRead: ShuttleIrp - %p\n", Irp);

    do
    {
        HidClassSetDeviceBusy(FDODeviceExtension);

        InterlockedExchange(&Shuttle->ShuttleState, HIDCLASS_SHUTTLE_START_READ);

        IoStack = Irp->Tail.Overlay.CurrentStackLocation;
        Irp->Cancel = FALSE;
        Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

        IoStack--;

        IoStack->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
        IoStack->Parameters.DeviceIoControl.IoControlCode = IOCTL_HID_READ_REPORT;
        IoStack->Parameters.DeviceIoControl.InputBufferLength = 0;
        IoStack->Parameters.DeviceIoControl.OutputBufferLength = FDODeviceExtension->MaxReportSize;

        IoSetCompletionRoutine(Irp,
                               HidClassInterruptReadComplete,
                               FDODeviceExtension,
                               TRUE,
                               TRUE,
                               TRUE);

        KeResetEvent(&Shuttle->ShuttleEvent);

        if (Shuttle->CancellingShuttle)
        {
            DPRINT("HidClassSubmitInterruptRead: Shuttle->CancellingShuttle\n");
            KeSetEvent(&Shuttle->ShuttleEvent, IO_NO_INCREMENT, FALSE);
            KeSetEvent(&Shuttle->ShuttleDoneEvent, IO_NO_INCREMENT, FALSE);
            return STATUS_CANCELLED;
        }

        InterlockedExchangeAdd(&FDODeviceExtension->OutstandingRequests, 1);

        Status = HidClassFDO_DispatchRequest(FDODeviceExtension->FDODeviceObject,
                                             Irp);

        KeSetEvent(&Shuttle->ShuttleEvent, IO_NO_INCREMENT, FALSE);

        *OutIsSending = TRUE;

        OldState = InterlockedExchange(&Shuttle->ShuttleState,
                                       HIDCLASS_SHUTTLE_END_READ);

        if (OldState != HIDCLASS_SHUTTLE_DISABLED)
        {
            return Status;
        }

        Status = Irp->IoStatus.Status;
    }
    while (Irp->IoStatus.Status >= 0);

    if (Shuttle->CancellingShuttle)
    {
        DPRINT("HidClassSubmitInterruptRead: Shuttle->CancellingShuttle\n");
        KeSetEvent(&Shuttle->ShuttleDoneEvent, IO_NO_INCREMENT, FALSE);
        return Status;
    }

    DueTime = Shuttle->TimerPeriod;

    KeSetTimer(&Shuttle->ShuttleTimer,
               DueTime,
               &Shuttle->ShuttleTimerDpc);

    return Status;
}

VOID
NTAPI
HidClassCancelAllShuttleIrps(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension)
{
    PHIDCLASS_SHUTTLE Shuttle;
    ULONG ix;

    DPRINT("HidClassCancelAllShuttleIrps: ShuttleCount - %x\n",
           FDODeviceExtension->ShuttleCount);


    if (FDODeviceExtension->ShuttleCount)
    {
        ix = 0;

        do
        {
            Shuttle = &FDODeviceExtension->Shuttles[ix];

            InterlockedExchangeAdd(&Shuttle->CancellingShuttle, 1);

            KeWaitForSingleObject(&Shuttle->ShuttleEvent,
                                  Executive,
                                  KernelMode,
                                  FALSE,
                                  NULL);

            IoCancelIrp(Shuttle->ShuttleIrp);

            KeWaitForSingleObject(&Shuttle->ShuttleDoneEvent,
                                  Executive,
                                  KernelMode,
                                  FALSE,
                                  NULL);

            InterlockedExchangeAdd(&Shuttle->CancellingShuttle, -1);

            ++ix;
        }
        while (ix < FDODeviceExtension->ShuttleCount);
    }

    return;
}

VOID
NTAPI
HidClassDestroyShuttles(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension)
{
    PHIDCLASS_SHUTTLE Shuttles;
    ULONG ix;

    DPRINT("HidClassDestroyShuttles: ShuttleCount - %x\n",
           FDODeviceExtension->ShuttleCount);

    Shuttles = FDODeviceExtension->Shuttles;

    if (Shuttles && Shuttles != HIDCLASS_NULL_POINTER)
    {
        HidClassCancelAllShuttleIrps(FDODeviceExtension);

        ix = 0;

        if (FDODeviceExtension->ShuttleCount)
        {
            do
            {
                DPRINT("HidClassDestroyShuttles: Free ShuttleIrp - %p\n",
                       FDODeviceExtension->Shuttles[ix].ShuttleIrp);

                IoFreeIrp(FDODeviceExtension->Shuttles[ix].ShuttleIrp);
                ExFreePoolWithTag(FDODeviceExtension->Shuttles[ix].ShuttleBuffer, 0);

                ++ix;
            }
            while (ix < FDODeviceExtension->ShuttleCount);
        }

        ExFreePoolWithTag(FDODeviceExtension->Shuttles, 0);
        FDODeviceExtension->Shuttles = HIDCLASS_NULL_POINTER;
    }
}

VOID
NTAPI
HidClassShuttleTimerDpc(
    IN KDPC *Dpc,
    IN PVOID DeferredContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2)
{
    PHIDCLASS_SHUTTLE Shuttle;
    LONG TimerValue;
    BOOLEAN IsSending;

    Shuttle = (PHIDCLASS_SHUTTLE)DeferredContext;
    TimerValue = Shuttle->TimerPeriod.LowPart;

    if (TimerValue > (-5000 * 10000))
    {
        Shuttle->TimerPeriod.LowPart = TimerValue - 1000 * 10000;
    }

    HidClassSubmitInterruptRead(Shuttle->FDODeviceExtension,
                                Shuttle,
                                &IsSending);
}

NTSTATUS
NTAPI
HidClassInitializeShuttleIrps(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension)
{
    PHIDCLASS_SHUTTLE Shuttles;
    PIRP Irp;
    SIZE_T NumberOfBytes;
    NTSTATUS Status = 0;
    ULONG ix;

    DPRINT("HidClassInitializeShuttleIrps: ... \n");

    Shuttles = ExAllocatePoolWithTag(NonPagedPool,
                                     FDODeviceExtension->ShuttleCount * sizeof(HIDCLASS_SHUTTLE),
                                     HIDCLASS_TAG);

    FDODeviceExtension->Shuttles = Shuttles;

    if (!Shuttles)
    {
        DPRINT1("[HIDCLASS] Alocate shuttles failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NumberOfBytes = FDODeviceExtension->MaxReportSize;

    RtlZeroMemory(Shuttles,
                  FDODeviceExtension->ShuttleCount * sizeof(HIDCLASS_SHUTTLE));

    ix = 0;

    if (!FDODeviceExtension->ShuttleCount)
    {
        return Status;
    }

    while (TRUE)
    {
        FDODeviceExtension->Shuttles[ix].FDODeviceExtension = FDODeviceExtension;
        FDODeviceExtension->Shuttles[ix].CancellingShuttle = 0;
        FDODeviceExtension->Shuttles[ix].TimerPeriod.HighPart = -1;
        FDODeviceExtension->Shuttles[ix].TimerPeriod.LowPart = -1000 * 10000;

        KeInitializeTimer(&FDODeviceExtension->Shuttles[ix].ShuttleTimer);

        KeInitializeDpc(&FDODeviceExtension->Shuttles[ix].ShuttleTimerDpc,
                        HidClassShuttleTimerDpc,
                        &FDODeviceExtension->Shuttles[ix]);

        FDODeviceExtension->Shuttles[ix].ShuttleBuffer = ExAllocatePoolWithTag(NonPagedPool,
                                                                               NumberOfBytes,
                                                                               HIDCLASS_TAG);

        if (!FDODeviceExtension->Shuttles[ix].ShuttleBuffer)
        {
            DPRINT1("[HIDCLASS] Alocate shuttle buffer failed\n");
            break;
        }

        Irp = IoAllocateIrp(FDODeviceExtension->FDODeviceObject->StackSize - 1,
                            FALSE);

        if (!Irp)
        {
            DPRINT1("[HIDCLASS] Alocate shuttle IRP failed\n");
            break;
        }

        DPRINT("HidClassInitializeShuttleIrps: Allocate Irp - %p\n", Irp);

        Irp->UserBuffer = FDODeviceExtension->Shuttles[ix].ShuttleBuffer;
        FDODeviceExtension->Shuttles[ix].ShuttleIrp = Irp;

        KeInitializeEvent(&FDODeviceExtension->Shuttles[ix].ShuttleEvent,
                          NotificationEvent,
                          TRUE);

        KeInitializeEvent(&FDODeviceExtension->Shuttles[ix].ShuttleDoneEvent,
                          NotificationEvent,
                          TRUE);

        ++ix;

        if (ix >= FDODeviceExtension->ShuttleCount)
        {
            return Status;
        }
    }

    return STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS
NTAPI
HidClassFDO_QueryCapabilitiesCompletionRoutine(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID Context)
{
    //
    // set event
    //
    KeSetEvent(Context, 0, FALSE);

    //
    // completion is done in the HidClassFDO_QueryCapabilities routine
    //
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
HidClassFDO_QueryCapabilities(
    IN PDEVICE_OBJECT DeviceObject,
    IN OUT PDEVICE_CAPABILITIES Capabilities)
{
    PIRP Irp;
    KEVENT Event;
    NTSTATUS Status;
    PIO_STACK_LOCATION IoStack;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;

    //
    // get device extension
    //
    FDODeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(FDODeviceExtension->Common.IsFDO);

    //
    // init event
    //
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    //
    // now allocate the irp
    //
    Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
    if (!Irp)
    {
        //
        // no memory
        //
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // get next stack location
    //
    IoStack = IoGetNextIrpStackLocation(Irp);

    //
    // init stack location
    //
    IoStack->MajorFunction = IRP_MJ_PNP;
    IoStack->MinorFunction = IRP_MN_QUERY_CAPABILITIES;
    IoStack->Parameters.DeviceCapabilities.Capabilities = Capabilities;

    //
    // set completion routine
    //
    IoSetCompletionRoutine(Irp, HidClassFDO_QueryCapabilitiesCompletionRoutine, &Event, TRUE, TRUE, TRUE);

    //
    // init capabilities
    //
    RtlZeroMemory(Capabilities, sizeof(DEVICE_CAPABILITIES));
    Capabilities->Size = sizeof(DEVICE_CAPABILITIES);
    Capabilities->Version = 1; // FIXME hardcoded constant
    Capabilities->Address = MAXULONG;
    Capabilities->UINumber = MAXULONG;

    //
    // pnp irps have default completion code
    //
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    //
    // call lower  device
    //
    Status = IoCallDriver(FDODeviceExtension->Common.HidDeviceExtension.NextDeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        //
        // wait for completion
        //
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
    }

    //
    // get status
    //
    Status = Irp->IoStatus.Status;

    //
    // complete request
    //
    IoFreeIrp(Irp);

    //
    // done
    //
    return Status;
}

NTSTATUS
NTAPI
HidClassFDO_DispatchRequestSynchronousCompletion(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID Context)
{
    //
    // signal event
    //
    KeSetEvent(Context, 0, FALSE);

    //
    // done
    //
    return STATUS_MORE_PROCESSING_REQUIRED;
}


NTSTATUS
HidClassFDO_DispatchRequestSynchronous(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    KEVENT Event;
    PHIDCLASS_COMMON_DEVICE_EXTENSION CommonDeviceExtension;
    NTSTATUS Status;
    PIO_STACK_LOCATION IoStack;

    //
    // init event
    //
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    //
    // get device extension
    //
    CommonDeviceExtension = DeviceObject->DeviceExtension;

    //
    // set completion routine
    //
    IoSetCompletionRoutine(Irp, HidClassFDO_DispatchRequestSynchronousCompletion, &Event, TRUE, TRUE, TRUE);

    ASSERT(Irp->CurrentLocation > 0);
    //
    // create stack location
    //
    IoSetNextIrpStackLocation(Irp);

    //
    // get next stack location
    //
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    //
    // store device object
    //
    IoStack->DeviceObject = DeviceObject;

    //
    // sanity check
    //
    ASSERT(CommonDeviceExtension->DriverExtension->MajorFunction[IoStack->MajorFunction] != NULL);

    //
    // call minidriver (hidusb)
    //
    Status = CommonDeviceExtension->DriverExtension->MajorFunction[IoStack->MajorFunction](DeviceObject, Irp);

    //
    // wait for the request to finish
    //
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

        //
        // update status
        //
        Status = Irp->IoStatus.Status;
    }

    //
    // done
    //
    return Status;
}

NTSTATUS
HidClassFDO_DispatchRequest(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PHIDCLASS_COMMON_DEVICE_EXTENSION CommonDeviceExtension;
    NTSTATUS Status;
    PIO_STACK_LOCATION IoStack;

    //
    // get device extension
    //
    CommonDeviceExtension = DeviceObject->DeviceExtension;

    ASSERT(Irp->CurrentLocation > 0);

    //
    // create stack location
    //
    IoSetNextIrpStackLocation(Irp);

    //
    // get next stack location
    //
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    //
    // store device object
    //
    IoStack->DeviceObject = DeviceObject;

    //
    // sanity check
    //
    ASSERT(CommonDeviceExtension->DriverExtension->MajorFunction[IoStack->MajorFunction] != NULL);

    //
    // call driver
    //
    Status = CommonDeviceExtension->DriverExtension->MajorFunction[IoStack->MajorFunction](DeviceObject, Irp);

    //
    // done
    //
    return Status;
}

NTSTATUS
HidClassFDO_GetDescriptors(
    IN PDEVICE_OBJECT DeviceObject)
{
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    PIRP Irp;
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;
    PHID_DESCRIPTOR HidDescriptor;
    PHIDP_REPORT_DESCRIPTOR ReportDesc;
    SIZE_T ReportLength;
    ULONG nx;

    //
    // get device extension
    //
    FDODeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(FDODeviceExtension->Common.IsFDO);
    HidDescriptor = &FDODeviceExtension->HidDescriptor;
    //
    // let's allocate irp
    //
    Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
    if (!Irp)
    {
        //
        // no memory
        //
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // get stack location
    //
    IoStack = IoGetNextIrpStackLocation(Irp);

    //
    // init stack location
    //
    IoStack->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
    IoStack->Parameters.DeviceIoControl.IoControlCode = IOCTL_HID_GET_DEVICE_DESCRIPTOR;
    IoStack->Parameters.DeviceIoControl.OutputBufferLength = sizeof(HID_DESCRIPTOR);
    IoStack->Parameters.DeviceIoControl.InputBufferLength = 0;
    IoStack->Parameters.DeviceIoControl.Type3InputBuffer = NULL;
    Irp->UserBuffer = HidDescriptor;

    //
    // send request
    //
    Status = HidClassFDO_DispatchRequestSynchronous(DeviceObject, Irp);
    if (!NT_SUCCESS(Status))
    {
        //
        // failed to get device descriptor
        //
        DPRINT1("[HIDCLASS] IOCTL_HID_GET_DEVICE_DESCRIPTOR failed with %x\n", Status);
        IoFreeIrp(Irp);
        return Status;
    }

    if (Irp->IoStatus.Information != sizeof(HID_DESCRIPTOR))
    {
        DPRINT1("[HIDCLASS] IOCTL_HID_GET_DEVICE_DESCRIPTOR: not valid size %x\n",
                Irp->IoStatus.Information);

        IoFreeIrp(Irp);
        return STATUS_DEVICE_DATA_ERROR;
    }

    //
    // let's get device attributes
    //
    IoStack->Parameters.DeviceIoControl.IoControlCode = IOCTL_HID_GET_DEVICE_ATTRIBUTES;
    IoStack->Parameters.DeviceIoControl.OutputBufferLength = sizeof(HID_DEVICE_ATTRIBUTES);
    Irp->UserBuffer = &FDODeviceExtension->Common.Attributes;

    //
    // send request
    //
    Status = HidClassFDO_DispatchRequestSynchronous(DeviceObject, Irp);
    if (!NT_SUCCESS(Status))
    {
        //
        // failed to get device descriptor
        //
        DPRINT1("[HIDCLASS] IOCTL_HID_GET_DEVICE_ATTRIBUTES failed with %x\n", Status);
        IoFreeIrp(Irp);
        return Status;
    }

    //
    // sanity checks
    //
    ASSERT(HidDescriptor->bLength == sizeof(HID_DESCRIPTOR));
    ASSERT(HidDescriptor->bNumDescriptors > 0);

    if (HidDescriptor->DescriptorList[0].bReportType != HID_REPORT_DESCRIPTOR_TYPE)
    {
        DPRINT1("[HIDCLASS] bReportType != HID_REPORT_DESCRIPTOR_TYPE (%x)\n",
                HidDescriptor->DescriptorList[0].bReportType);

        IoFreeIrp(Irp);
        return STATUS_DEVICE_DATA_ERROR;
    }

    ReportLength = HidDescriptor->DescriptorList[0].wReportLength;

    if (!ReportLength)
    {
        DPRINT1("[HIDCLASS] wReportLength == 0 \n");
        IoFreeIrp(Irp);
        return STATUS_DEVICE_DATA_ERROR;
    }

    /* allocate report descriptor */ 
    ReportDesc = ExAllocatePoolWithTag(NonPagedPool, ReportLength, HIDCLASS_TAG);

    if (!ReportDesc)
    {
        DPRINT1("[HIDCLASS] report descriptor not allocated \n");
        IoFreeIrp(Irp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    nx = 0;

    while (TRUE)
    {
        IoStack->Parameters.DeviceIoControl.IoControlCode = IOCTL_HID_GET_REPORT_DESCRIPTOR;
        IoStack->Parameters.DeviceIoControl.OutputBufferLength = ReportLength;
        Irp->UserBuffer = ReportDesc;

        Status = HidClassFDO_DispatchRequestSynchronous(DeviceObject, Irp);

        if (NT_SUCCESS(Status))
        {
            break;
        }

  Retry:
        ++nx;

        if (nx >= 3)
        {
            goto Exit;
        }
    }

    if (Irp->IoStatus.Information != ReportLength)
    {
        Status = STATUS_DEVICE_DATA_ERROR;
        goto Retry;
    }

    /* save pointer on report descriptor in extension */ 
    FDODeviceExtension->ReportDescriptor = ReportDesc;

Exit:

    /* deallocate report descriptor if not success */ 
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(ReportDesc, 0);
    }

    IoFreeIrp(Irp);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
HidClassAllocCollectionResources(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension,
    IN ULONG CollectionNumber)
{
    PHIDCLASS_COLLECTION HIDCollection;
    ULONG DescriptorSize;
    PHIDP_COLLECTION_DESC CollectionDescArray;
    PVOID CollectionData;
    PVOID InputReport;
    PHIDP_DEVICE_DESC DeviceDescription;
    ULONG InputLength;
    NTSTATUS Status;

    DPRINT("[HIDCLASS] HidClassAllocCollectionResources (%x)\n", CollectionNumber);

    DeviceDescription = &FDODeviceExtension->Common.DeviceDescription;

    HIDCollection = GetHidclassCollection(FDODeviceExtension, CollectionNumber);

    if (!HIDCollection)
    {
        DPRINT1("[HIDCLASS] No HIDCollection\n");
        return STATUS_DEVICE_DATA_ERROR;
    }

    DescriptorSize = HIDCollection->HidCollectInfo.DescriptorSize;

    if (!DescriptorSize)
    {
        DPRINT1("[HIDCLASS] DescriptorSize is 0\n");
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    CollectionData = ExAllocatePoolWithTag(NonPagedPool,
                                           DescriptorSize,
                                           HIDCLASS_TAG);

    HIDCollection->CollectionData = CollectionData;

    if (CollectionData)
    {
        Status = HidClassGetCollectionDescriptor(FDODeviceExtension,
                                                 HIDCollection->CollectionNumber,
                                                 CollectionData,
                                                 &DescriptorSize);
    }
    else
    {
        DPRINT1("[HIDCLASS] Failed allocate CollectionData\n");
        HIDCollection->CollectionData = HIDCLASS_NULL_POINTER;
        Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    CollectionDescArray = DeviceDescription->CollectionDesc;
    InputLength = CollectionDescArray[HIDCollection->CollectionIdx].InputLength;

    if (InputLength)
    {
        if (HIDCollection->HidCollectInfo.Polled)
        {
            HIDCollection->InputReport = HIDCLASS_NULL_POINTER;
        }
        else
        {
            InputReport = ExAllocatePoolWithTag(NonPagedPool,
                                                InputLength,
                                                HIDCLASS_TAG);


            HIDCollection->InputReport = InputReport;

            if (!InputReport)
            {
                DPRINT1("[HIDCLASS] Failed allocate InputReport\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        FDODeviceExtension->NotAllocCollectResources = FALSE;
    }
    else
    {
        DPRINT1("[HIDCLASS] InputLength is 0\n");
        HIDCollection->InputReport = HIDCLASS_NULL_POINTER;
    }

    return Status;
}

NTSTATUS
NTAPI
HidClassInitializeCollection(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension,
    IN ULONG CollectionIdx)
{
    PHIDCLASS_COLLECTION HIDCollection;
    PHIDP_COLLECTION_DESC HidCollectionDesc;
    HID_COLLECTION_INFORMATION CollectionInfo;
    PHIDP_DEVICE_DESC DeviceDescription;
    ULONG CollectionNumber;

    DPRINT("[HIDCLASS] HidClassAllocCollectionResources (%x)\n", CollectionIdx);

    DeviceDescription = &FDODeviceExtension->Common.DeviceDescription;
    HIDCollection = &FDODeviceExtension->HidCollections[CollectionIdx];

    RtlZeroMemory(HIDCollection, sizeof(HIDCLASS_COLLECTION));

    CollectionNumber = DeviceDescription->CollectionDesc[CollectionIdx].CollectionNumber;
    HIDCollection->CollectionNumber = CollectionNumber;
    HIDCollection->CollectionIdx = CollectionIdx;
    HIDCollection->CloseFlag = 0;

    InitializeListHead(&HIDCollection->InterruptReportList);
    KeInitializeSpinLock(&HIDCollection->CollectSpinLock);
    KeInitializeSpinLock(&HIDCollection->CollectCloseSpinLock);

    HidCollectionDesc = GetCollectionDesc(FDODeviceExtension, CollectionNumber);

    if (!HidCollectionDesc)
    {
        DPRINT1("[HIDCLASS] No HidCollectionDesc (%x)\n", CollectionNumber);
        return STATUS_DATA_ERROR;
    }

    CollectionInfo.DescriptorSize = HidCollectionDesc->PreparsedDataLength;
    CollectionInfo.Polled = FDODeviceExtension->Common.DriverExtension->DevicesArePolled;
    CollectionInfo.VendorID = FDODeviceExtension->Common.Attributes.VendorID;
    CollectionInfo.ProductID = FDODeviceExtension->Common.Attributes.ProductID;
    CollectionInfo.VersionNumber = FDODeviceExtension->Common.Attributes.VersionNumber;

    RtlCopyMemory(&HIDCollection->HidCollectInfo,
                  &CollectionInfo,
                  sizeof(HID_COLLECTION_INFORMATION));

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
HidClassFDO_StartDevice(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    NTSTATUS Status;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    ULONG OldFdoState;
    PHIDCLASS_COLLECTION HidCollections;
    PHIDP_DEVICE_DESC DeviceDescription;
    ULONG CollectionIdx;
    ULONG CollectionNumber;
    SIZE_T Length;

    /* Get device extension */
    FDODeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(FDODeviceExtension->Common.IsFDO);

    /* Begin FDO start */
    OldFdoState = FDODeviceExtension->HidFdoState;
    FDODeviceExtension->HidFdoState = HIDCLASS_STATE_STARTING;

    /* Query capabilities */
    Status = HidClassFDO_QueryCapabilities(DeviceObject,
                                           &FDODeviceExtension->Capabilities);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("[HIDCLASS] Failed to retrieve capabilities %x\n", Status);
        FDODeviceExtension->HidFdoState = HIDCLASS_STATE_FAILED;
        goto ExitError;
    }

    /* Let's start the lower device too */
    IoSkipCurrentIrpStackLocation(Irp);
    Status = HidClassFDO_DispatchRequestSynchronous(DeviceObject, Irp);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("[HIDCLASS] Failed to start lower device with %x\n", Status);
        FDODeviceExtension->HidFdoState = HIDCLASS_STATE_FAILED;
        goto ExitError;
    }

    /* Only first time initialize needed */
    if (OldFdoState == HIDCLASS_STATE_NOT_INIT)
    {
        /* Let's get the descriptors */
        Status = HidClassFDO_GetDescriptors(DeviceObject);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("[HIDCLASS] Failed to retrieve the descriptors %x\n", Status);
            FDODeviceExtension->HidFdoState = HIDCLASS_STATE_FAILED;
            FDODeviceExtension->ReportDescriptor = HIDCLASS_NULL_POINTER;
            goto ExitError;
        }

        DeviceDescription = &FDODeviceExtension->Common.DeviceDescription;

        /* Now get the the collection description */
        Status = HidP_GetCollectionDescription(FDODeviceExtension->ReportDescriptor,
                                               FDODeviceExtension->HidDescriptor.DescriptorList[0].wReportLength,
                                               NonPagedPool,
                                               DeviceDescription);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("[HIDCLASS] Failed to retrieve the collection description %x\n", Status);
            FDODeviceExtension->HidFdoState = HIDCLASS_STATE_FAILED;
            goto ExitError;
        }

        /* Device resources alloceted successful */
        FDODeviceExtension->IsDeviceResourcesAlloceted = TRUE;

        /* Now allocete array of HIDCLASS_COLLECTION */
        Length = DeviceDescription->CollectionDescLength * sizeof(HIDCLASS_COLLECTION);
        HidCollections = ExAllocatePoolWithTag(NonPagedPool, Length, HIDCLASS_TAG);
        FDODeviceExtension->HidCollections = HidCollections;

        if (HidCollections)
        {
            RtlZeroMemory(HidCollections, Length);
        }
        else
        {
            DPRINT1("[HIDCLASS] HidCollections not allocated\n");
            FDODeviceExtension->ReportDescriptor = HIDCLASS_NULL_POINTER;
            FDODeviceExtension->HidFdoState = HIDCLASS_STATE_FAILED;
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto ExitError;
        }

        /* Initialize collections array */
        if (DeviceDescription->CollectionDescLength)
        {
            CollectionIdx = 0;

            do
            {
                Status = HidClassInitializeCollection(FDODeviceExtension,
                                                      CollectionIdx);

                if (!NT_SUCCESS(Status))
                {
                    DPRINT1("[HIDCLASS] Failed initialize Collection (Idx %x)\n",
                            CollectionIdx);
                    break;
                }

                CollectionNumber = DeviceDescription->CollectionDesc[CollectionIdx].CollectionNumber;

                /* Allocete resources for current collection */
                Status = HidClassAllocCollectionResources(FDODeviceExtension,
                                                          CollectionNumber);

                if (!NT_SUCCESS(Status))
                {
                    DPRINT1("[HIDCLASS] Failed alloc Collection (Idx %x) resources\n",
                            CollectionIdx);
                    break;
                }

                ++CollectionIdx;
            }
            while (CollectionIdx < DeviceDescription->CollectionDescLength);
        }

        /* For polled devices shuttles not needed */
        if (FDODeviceExtension->Common.DriverExtension->DevicesArePolled)
        {
            DPRINT("[HIDCLASS] DevicesArePolled \n");
            FDODeviceExtension->ShuttleCount = 0;
            FDODeviceExtension->Shuttles = HIDCLASS_NULL_POINTER;
        }

        /* Initialize shuttle IRPs for first time */
        if (!FDODeviceExtension->NotAllocCollectResources &&
            !FDODeviceExtension->Common.DriverExtension->DevicesArePolled)
        {
            HidClassDestroyShuttles(FDODeviceExtension);

            if (HidClassSetMaxReportSize(FDODeviceExtension))
            {
                FDODeviceExtension->ShuttleCount = HIDCLASS_MINIMUM_SHUTTLE_IRPS;

                Status = HidClassInitializeShuttleIrps(FDODeviceExtension);

                if (!NT_SUCCESS(Status))
                {
                    DPRINT1("[HIDCLASS] Failed initialize ShuttleIrps\n");
                    FDODeviceExtension->ShuttleCount = 0;
                }
            }
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("[HIDCLASS] Failed alloc Collection (Idx %x) resources\n",
                    CollectionIdx);

            FDODeviceExtension->HidFdoState = HIDCLASS_STATE_FAILED;
            goto ExitError;
        }

        /* Re-enumerate PhysicalDeviceObject */
        IoInvalidateDeviceRelations(FDODeviceExtension->Common.HidDeviceExtension.PhysicalDeviceObject,
                                    BusRelations);
    }
    else if (OldFdoState != HIDCLASS_STATE_DISABLED)
    {
        DPRINT1("[HIDCLASS] FDO (%p) should be stopped before starting.\n",
                DeviceObject);

        FDODeviceExtension->HidFdoState = HIDCLASS_STATE_FAILED;
        Status = STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    if (!NT_SUCCESS(Status))
    {
ExitError:
        FDODeviceExtension->HidFdoState = HIDCLASS_STATE_FAILED;
        return Status;
    }

    /* FDO start successful */
    FDODeviceExtension->HidFdoState = HIDCLASS_STATE_STARTED;

    /* Complete request */
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS
NTAPI
HidClassCleanUpFDO(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension)
{
    NTSTATUS Status;

    DPRINT("HidClassCleanUpFDO: OpenCount - %x\n", FDODeviceExtension->OpenCount);

    if (FDODeviceExtension->OpenCount)
    {
        Status = STATUS_UNSUCCESSFUL;
    }
    else
    {
        HidClassFreeDeviceResources(FDODeviceExtension);

        // FIXME:
        //IoWMIRegistrationControl(FDODeviceExtension->FDODeviceObject,
        //                         WMIREG_ACTION_DEREGISTER);

        HidClassDeleteDeviceObjects(FDODeviceExtension);
        Status = STATUS_SUCCESS;
    }

    return Status;
}

NTSTATUS
NTAPI
HidClassFDO_RemoveDevice(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    NTSTATUS Status;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    PHID_DEVICE_EXTENSION HidDeviceExtension;
    ULONG FdoPrevState;

    DPRINT("HidClassFDO_RemoveDevice: Irp - %p\n", Irp);

    // get device extension
    FDODeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(FDODeviceExtension->Common.IsFDO);

    FdoPrevState = FDODeviceExtension->HidFdoPrevState;

    if (FdoPrevState == HIDCLASS_STATE_FAILED ||
        FdoPrevState == HIDCLASS_STATE_DISABLED ||
        HidClassAllPdoInitialized(FDODeviceExtension, 0))
    {
        HidClassDestroyShuttles(FDODeviceExtension);

        Irp->IoStatus.Status = STATUS_SUCCESS;

        IoSkipCurrentIrpStackLocation(Irp);

        Status = HidClassFDO_DispatchRequest(FDODeviceExtension->FDODeviceObject,
                                             Irp);

        FDODeviceExtension->HidFdoState = HIDCLASS_STATE_DELETED;

        DerefDriverExt(FDODeviceExtension->Common.DriverExtension->DriverObject);
        FDODeviceExtension->Common.DriverExtension = HIDCLASS_NULL_POINTER;

        HidDeviceExtension = &FDODeviceExtension->Common.HidDeviceExtension;
        IoDetachDevice(HidDeviceExtension->NextDeviceObject);

        HidClassCleanUpFDO(FDODeviceExtension);
    }
    else
    {
        Status = STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    return Status;
}

NTSTATUS
HidClassFDO_DeviceRelations(
    IN PHIDCLASS_FDO_EXTENSION FDODeviceExtension,
    IN PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    NTSTATUS Status;
    PDEVICE_RELATIONS DeviceRelations;
    ULONG PdoIdx;
    KIRQL OldIrql;

    ASSERT(FDODeviceExtension->Common.IsFDO);

    DPRINT("[HIDCLASS]: HidClassFDO_DeviceRelations FDODeviceExtension %p\n",
           FDODeviceExtension);

    //
    // get current irp stack location
    //
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    //
    // check relations type
    //
    if (IoStack->Parameters.QueryDeviceRelations.Type != BusRelations)
    {
        //
        // only bus relations are handled
        //
        IoSkipCurrentIrpStackLocation(Irp);

        return IoCallDriver(FDODeviceExtension->Common.HidDeviceExtension.NextDeviceObject,
                            Irp);
    }

    if (FDODeviceExtension->DeviceRelations &&
        FDODeviceExtension->DeviceRelations != HIDCLASS_NULL_POINTER)
    {
        Status = STATUS_SUCCESS;
    }
    else
    {
        /* time to create the pdos */
        Status = HidClassCreatePDOs(FDODeviceExtension->FDODeviceObject,
                                    &FDODeviceExtension->DeviceRelations);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("[HIDCLASS] HidClassPDO_CreatePDO failed with %x\n", Status);
            Irp->IoStatus.Status = Status;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return Status;
        }

        ASSERT(FDODeviceExtension->DeviceRelations->Count > 0);
    }

    DeviceRelations = FDODeviceExtension->DeviceRelations;
    KeAcquireSpinLock(&FDODeviceExtension->HidRelationSpinLock, &OldIrql);

    DPRINT("[HIDCLASS] IsNotifyPresence - %x\n",
           FDODeviceExtension->IsNotifyPresence);

    if (FDODeviceExtension->IsNotifyPresence)
    {
        PDEVICE_RELATIONS NewDeviceRelations;
        PDEVICE_OBJECT DeviceObject;
        ULONG Length;

        FDODeviceExtension->IsRelationsOn = TRUE;
        KeReleaseSpinLock(&FDODeviceExtension->HidRelationSpinLock, OldIrql);

        /* now copy device relations */
        Length = sizeof(DEVICE_RELATIONS) +
                 DeviceRelations->Count * sizeof(PDEVICE_OBJECT);

        NewDeviceRelations = ExAllocatePoolWithTag(PagedPool,
                                                   Length,
                                                   HIDCLASS_TAG);

        RtlCopyMemory(NewDeviceRelations, DeviceRelations, Length);

        /* store result */
        Irp->IoStatus.Status = Status;
        Irp->IoStatus.Information = (ULONG_PTR)NewDeviceRelations;

        DPRINT("[HIDCLASS] IoStatus: Status %x, Information - %p\n",
               Status,
               NewDeviceRelations);

        if (NewDeviceRelations)
        {
            PdoIdx = 0;

            DPRINT("[HIDCLASS] DeviceRelations->Count - %x\n",
                   DeviceRelations->Count);

            if ( FDODeviceExtension->DeviceRelations->Count )
            {
                do
                {
                    ObReferenceObject(FDODeviceExtension->DeviceRelations->Objects[PdoIdx]);
                    DeviceObject = FDODeviceExtension->DeviceRelations->Objects[PdoIdx];
                    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
                    ++PdoIdx;
                }
                while ( PdoIdx < FDODeviceExtension->DeviceRelations->Count );
            }
        }
    }
    else
    {
        FDODeviceExtension->IsRelationsOn = FALSE;
        KeReleaseSpinLock(&FDODeviceExtension->HidRelationSpinLock, OldIrql);

        DeviceRelations = ExAllocatePoolWithTag(PagedPool,
                                                sizeof(DEVICE_RELATIONS),
                                                HIDCLASS_TAG);

        Irp->IoStatus.Information = (ULONG_PTR)DeviceRelations;

        if (DeviceRelations)
        {
            if (DeviceRelations != HIDCLASS_NULL_POINTER)
            {
                ExFreePoolWithTag(DeviceRelations, 0);
            }

            DeviceRelations = HIDCLASS_NULL_POINTER;
            DeviceRelations->Count = 0;
            DeviceRelations->Objects[0] = NULL;
        }
    }

    if (!Irp->IoStatus.Information)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    return Status;
}

NTSTATUS
HidClassFDO_PnP(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PIO_STACK_LOCATION IoStack;
    PHIDCLASS_FDO_EXTENSION FDODeviceExtension;
    NTSTATUS Status;
    BOOLEAN IsCompleteIrp = FALSE;

    // get device extension
    FDODeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(FDODeviceExtension->Common.IsFDO);

    // get current irp stack location
    IoStack = IoGetCurrentIrpStackLocation(Irp);

    DPRINT1("[HIDCLASS]: FDO IoStack->MinorFunction %x\n",
            IoStack->MinorFunction);

    switch (IoStack->MinorFunction)
    {
        case IRP_MN_START_DEVICE:
        {
             return HidClassFDO_StartDevice(DeviceObject, Irp);
        }
        case IRP_MN_REMOVE_DEVICE:
        {
             return HidClassFDO_RemoveDevice(DeviceObject, Irp);
        }
        case IRP_MN_QUERY_DEVICE_RELATIONS:
        {
            DPRINT("HidClassFDO_PnP: QueryDeviceRelations.Type - %x\n",
                   IoStack->Parameters.QueryDeviceRelations.Type);

            if (IoStack->Parameters.QueryDeviceRelations.Type != BusRelations)
            {
                break;
            }

            Status = HidClassFDO_DeviceRelations(FDODeviceExtension, Irp);

            if (NT_SUCCESS(Status))
            {
                Irp->IoStatus.Status = Status;
                break;
            }

            IsCompleteIrp = 1;
            break;
        }
        case IRP_MN_SURPRISE_REMOVAL:
        {
            /* FIXME cancel IdleNotification */
            HidClassDestroyShuttles(FDODeviceExtension);
            /* fall through */
        }
        case IRP_MN_QUERY_REMOVE_DEVICE:
        {
            /* FIXME handle power Irps */
            Irp->IoStatus.Status = STATUS_SUCCESS;
            FDODeviceExtension->HidFdoPrevState = FDODeviceExtension->HidFdoState;
            FDODeviceExtension->HidFdoState = HIDCLASS_STATE_REMOVED;
            break;
        }
        case IRP_MN_QUERY_STOP_DEVICE:
        {
            Irp->IoStatus.Status = STATUS_SUCCESS;
            FDODeviceExtension->HidFdoPrevState = FDODeviceExtension->HidFdoState;
            FDODeviceExtension->HidFdoState = HIDCLASS_STATE_STOPPING;
            break;
        }
        case IRP_MN_CANCEL_REMOVE_DEVICE:
        {
            Irp->IoStatus.Status = STATUS_SUCCESS;
            FDODeviceExtension->HidFdoState = FDODeviceExtension->HidFdoPrevState;
            break;
        }
        case IRP_MN_CANCEL_STOP_DEVICE:
        {
            Irp->IoStatus.Status = STATUS_SUCCESS;
            FDODeviceExtension->HidFdoState = FDODeviceExtension->HidFdoPrevState;
            break;
        }
        case IRP_MN_STOP_DEVICE:
        {
            if (FDODeviceExtension->HidFdoPrevState == HIDCLASS_STATE_STARTED)
            {
                HidClassCancelAllShuttleIrps(FDODeviceExtension);
            }

            FDODeviceExtension->HidFdoState = HIDCLASS_STATE_DISABLED;
            IoCopyCurrentIrpStackLocationToNext(Irp);

            Status = HidClassFDO_DispatchRequestSynchronous(DeviceObject, Irp);

            IsCompleteIrp = 1;
            break;
        }
        default:
        {
            break;
        }
    }

    if (!IsCompleteIrp)
    {
        IoCopyCurrentIrpStackLocationToNext(Irp);
        Status = HidClassFDO_DispatchRequest(DeviceObject, Irp);
        return Status;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}
