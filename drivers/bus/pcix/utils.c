/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/utils.c
 * PURPOSE:         Utility/Helper Support Code
 * PROGRAMMERS:     ReactOS Portable Systems Group
 *                  Copyright 2023 Vadim Galyant <vgal@rambler.ru>
 */

/* INCLUDES *******************************************************************/

#include <pci.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

ULONG PciDebugPortsCount;

RTL_RANGE_LIST PciIsaBitExclusionList;
RTL_RANGE_LIST PciVgaAndIsaBitExclusionList;

extern PCI_DEBUG_PORT PciDebugPorts[2];
extern ULONG PciDebugPortsCount;

/* FUNCTIONS ******************************************************************/

BOOLEAN
NTAPI
PciUnicodeStringStrStr(
    _In_ PUNICODE_STRING InputString,
    _In_ PCUNICODE_STRING EqualString,
    _In_ BOOLEAN CaseInSensitive)
{
    UNICODE_STRING PartialString;
    LONG EqualChars;
    LONG TotalChars;

    DPRINT("PciUnicodeStringStrStr: '%wZ', '%wZ' (%X)\n", InputString, EqualString, CaseInSensitive);

    /* Build a partial string with the smaller substring */
    PartialString.Length = EqualString->Length;
    PartialString.MaximumLength = InputString->MaximumLength;
    PartialString.Buffer = InputString->Buffer;

    /* Check how many characters that need comparing */
    EqualChars = 0;
    TotalChars = ((InputString->Length - EqualString->Length) / sizeof(WCHAR));

    /* If the substring is bigger, just fail immediately */
    if (TotalChars < 0)
        return FALSE;

    /* Keep checking each character */
    while (!RtlEqualUnicodeString(EqualString, &PartialString, CaseInSensitive))
    {
        /* Continue checking until all the required characters are equal */
        PartialString.Buffer++;
        PartialString.MaximumLength -= sizeof(WCHAR);

        if (++EqualChars > TotalChars)
            return FALSE;
    }

    /* The string is equal */
    return TRUE;
}

BOOLEAN
NTAPI
PciStringToUSHORT(IN PWCHAR String,
                  OUT PUSHORT Value)
{
    USHORT Short;
    ULONG Low, High, Length;
    WCHAR Char;

    //DPRINT("PciStringToUSHORT: .. \n");

    /* Initialize everything to zero */
    Short = 0;
    Length = 0;
    while (TRUE)
    {
        /* Get the character and set the high byte based on the previous one */
        Char = *String++;
        High = 16 * Short;

        /* Check for numbers */
        if ( Char >= '0' && Char <= '9' )
        {
            /* Convert them to a byte */
            Low = Char - '0';
        }
        else if ( Char >= 'A' && Char <= 'F' )
        {
            /* Convert upper-case hex letters into a byte */
            Low = Char - '7';
        }
        else if ( Char >= 'a' && Char <= 'f' )
        {
            /* Convert lower-case hex letters into a byte */
            Low = Char - 'W';
        }
        else
        {
            /* Invalid string, fail the conversion */
            return FALSE;
        }

        /* Combine the high and low byte */
        Short = High | Low;

        /* If 4 letters have been reached, the 16-bit integer should exist */
        if (++Length >= 4)
        {
            /* Return it to the caller */
            *Value = Short;
            return TRUE;
        }
    }
}

BOOLEAN
NTAPI
PciIsSuiteVersion(
    _In_ USHORT SuiteMask)
{
    RTL_OSVERSIONINFOEXW VersionInfo;
    ULONGLONG Mask = 0;

    DPRINT("PciIsSuiteVersion: SuiteMask %X\n", SuiteMask);

    /* Initialize the version information */
    RtlZeroMemory(&VersionInfo, sizeof(RTL_OSVERSIONINFOEXW));

    VersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
    VersionInfo.wSuiteMask = SuiteMask;

    /* Set the comparison mask and return if the passed suite mask matches */
    VER_SET_CONDITION(Mask, VER_SUITENAME, VER_AND);

    return NT_SUCCESS(RtlVerifyVersionInfo(&VersionInfo, VER_SUITENAME, Mask));
}

BOOLEAN
NTAPI
PciAllowExtendedInterruptVectors(
    _In_ PUNICODE_STRING OptionString)
{
    PVOID Value = NULL;
    ULONG ResultLength = 0;
    BOOLEAN Result = FALSE; // Assume this isn't Datacenter
    NTSTATUS Status;

    DPRINT("PciAllowExtendedInterruptVectors: Options -'%wZ'\n", OptionString);

    /* First, try opening the setup key */
    Status = PciGetRegistryValue(L"",
                                 L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\setupdd",
                                 0,
                                 REG_BINARY,
                                 &Value,
                                 &ResultLength);
    if (!NT_SUCCESS(Status))
    {
        /* This is not an in-progress Setup boot, so query the suite version */
        DPRINT("PciAllowExtendedInterruptVectors: Status %X\n", Status);

        if (PciIsSuiteVersion(VER_SUITE_DATACENTER))
            return TRUE;

        if (PciIsSuiteVersion(VER_SUITE_ENTERPRISE))
        {
            ASSERT(FALSE);
        }

        return FALSE;
    }

    /* This scenario shouldn't happen yet, since SetupDD isn't used */
    UNIMPLEMENTED_FATAL("ReactOS doesn't use SetupDD for its installation program. Therefore this scenario must not happen!\n");

    return Result;
}

BOOLEAN
NTAPI
PciOpenKey(
    _In_ PWCHAR KeyName,
    _In_ HANDLE RootKey,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ HANDLE* OutHandle,
    _Out_ NTSTATUS* OutStatus)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KeyString;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciOpenKey: '%S'\n", KeyName);

    /* Initialize the object attributes */
    RtlInitUnicodeString(&KeyString, KeyName);
    InitializeObjectAttributes(&ObjectAttributes, &KeyString, OBJ_CASE_INSENSITIVE, RootKey, NULL);

    /* Open the key, returning a boolean, and the status, if requested */
    Status = ZwOpenKey(OutHandle, DesiredAccess, &ObjectAttributes);

    if (OutStatus)
        *OutStatus = Status;

    if (!NT_SUCCESS(Status))
    {
        DPRINT("PciOpenKey: Status %X for '%S'\n", Status, KeyName);
    }

    return NT_SUCCESS(Status);
}

NTSTATUS
NTAPI
PciGetRegistryValue(
    _In_ PWCHAR ValueName,
    _In_ PWCHAR KeyName,
    _In_ HANDLE RootHandle,
    _In_ ULONG Type,
    _Out_ PVOID* OutputBuffer,
    _Out_ ULONG* OutputLength)
{
    PKEY_VALUE_PARTIAL_INFORMATION PartialInfo = NULL;
    UNICODE_STRING ValueString;
    HANDLE KeyHandle = NULL;
    ULONG NeededLength;
    ULONG ActualLength;
    BOOLEAN Result;
    NTSTATUS Status;

    DPRINT("PciGetRegistryValue: '%S', '%S'\n", ValueName, KeyName);

    do
    {
        /* Open the key by name, rooted off the handle passed */
        Result = PciOpenKey(KeyName, RootHandle, KEY_QUERY_VALUE, &KeyHandle, &Status);
        if (!Result)
            break;

        /* Query for the size that's needed for the value that was passed in */
        RtlInitUnicodeString(&ValueString, ValueName);

        Status = ZwQueryValueKey(KeyHandle, &ValueString, KeyValuePartialInformation, NULL, 0, &NeededLength);
        ASSERT(!NT_SUCCESS(Status));
        if (Status != STATUS_BUFFER_TOO_SMALL)
        {
            DPRINT1("PciGetRegistryValue: Status %X\n", Status);
            break;
        }
        ASSERT(NeededLength != 0);

        /* Allocate an appropriate buffer for the size that was returned */
        PartialInfo = ExAllocatePoolWithTag(PagedPool, NeededLength, PCI_POOL_TAG);
        if (!PartialInfo)
        {
            DPRINT1("PciGetRegistryValue: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        /* Query the actual value information now that the size is known */
        Status = ZwQueryValueKey(KeyHandle, &ValueString, KeyValuePartialInformation, PartialInfo, NeededLength, &ActualLength);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PciGetRegistryValue: Status %X\n", Status);
            break;
        }

        /* Make sure it's of the type that the caller expects */
        if (PartialInfo->Type != Type)
        {
            DPRINT1("PciGetRegistryValue: STATUS_INVALID_PARAMETER (%X-%X)\n", PartialInfo->Type, Type);
            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        /* Subtract the registry-specific header, to get the data size */
        ASSERT(NeededLength == ActualLength);
        NeededLength -= FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data);
        ASSERT(NeededLength != 0);

        /* Allocate a buffer to hold the data and return it to the caller */
        *OutputBuffer = ExAllocatePoolWithTag(PagedPool, NeededLength, PCI_POOL_TAG);
        if (!*OutputBuffer)
        {
            DPRINT1("PciGetRegistryValue: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        /* Copy the data into the buffer and return its length to the caller */
        RtlCopyMemory(*OutputBuffer, PartialInfo->Data, NeededLength);

        if (OutputLength)
            *OutputLength = NeededLength;

        Status = STATUS_SUCCESS;
    }
    while (FALSE);

    /* Close any opened keys and free temporary allocations */

    if (KeyHandle)
        ZwClose(KeyHandle);

    if (PartialInfo)
        ExFreePoolWithTag(PartialInfo, PCI_POOL_TAG);

    return Status;
}

NTSTATUS
NTAPI
PciBuildDefaultExclusionLists(VOID)
{
    ULONG Start;
    NTSTATUS Status;

    DPRINT("PciBuildDefaultExclusionLists()\n");

    ASSERT(PciIsaBitExclusionList.Count == 0);
    ASSERT(PciVgaAndIsaBitExclusionList.Count == 0);

    /* Initialize the range lists */
    RtlInitializeRangeList(&PciIsaBitExclusionList);
    RtlInitializeRangeList(&PciVgaAndIsaBitExclusionList);

    /* Loop x86 I/O ranges */
    for (Start = 0; Start <= 0xFFFF; Start += 0x400)
    {
        /* Add the ISA I/O ranges */
        Status = RtlAddRange(&PciIsaBitExclusionList,
                             (Start + 0x100),
                             (Start + 0x3FF),
                             0,
                             RTL_RANGE_LIST_ADD_IF_CONFLICT,
                             NULL,
                             NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PciBuildDefaultExclusionLists: Status %X\n", Status);
            break;
        }

        /* Add the ISA I/O ranges */
        Status = RtlAddRange(&PciVgaAndIsaBitExclusionList,
                             (Start + 0x100),
                             (Start + 0x3AF),
                             0,
                             RTL_RANGE_LIST_ADD_IF_CONFLICT,
                             NULL,
                             NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PciBuildDefaultExclusionLists: Status %X\n", Status);
            break;
        }

        /* Add the VGA I/O range for Monochrome Video */
        Status = RtlAddRange(&PciVgaAndIsaBitExclusionList,
                             (Start + 0x3BC),
                             (Start + 0x3BF),
                             0,
                             RTL_RANGE_LIST_ADD_IF_CONFLICT,
                             NULL,
                             NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PciBuildDefaultExclusionLists: Status %X\n", Status);
            break;
        }

        /* Add the VGA I/O range for certain CGA adapters */
        Status = RtlAddRange(&PciVgaAndIsaBitExclusionList,
                             (Start + 0x3E0),
                             (Start + 0x3FF),
                             0,
                             RTL_RANGE_LIST_ADD_IF_CONFLICT,
                             NULL,
                             NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PciBuildDefaultExclusionLists: Status %X\n", Status);
            break;
        }

        /* Success, ranges added done */
    };

    RtlFreeRangeList(&PciIsaBitExclusionList);
    RtlFreeRangeList(&PciVgaAndIsaBitExclusionList);

    return Status;
}

PPCI_FDO_EXTENSION
NTAPI
PciFindParentPciFdoExtension(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PKEVENT Lock)
{
    PPCI_FDO_EXTENSION FdoExtension;
    PPCI_PDO_EXTENSION SearchExtension;
    PPCI_PDO_EXTENSION FoundExtension;

    DPRINT("PciFindParentPciFdoExtension: %p\n", DeviceObject);

    /* Assume we'll find nothing */
    SearchExtension = DeviceObject->DeviceExtension;
    FoundExtension = NULL;

    /* Check if a lock was specified */
    if (Lock)
    {
        /* Wait for the lock to be released */
        KeEnterCriticalRegion();
        KeWaitForSingleObject(Lock, Executive, KernelMode, FALSE, NULL);
    }

    /* Now search for the extension */
    FdoExtension = (PPCI_FDO_EXTENSION)PciFdoExtensionListHead.Next;
    while (FdoExtension)
    {
        /* Acquire this device's lock */
        KeEnterCriticalRegion();
        KeWaitForSingleObject(&FdoExtension->ChildListLock, Executive, KernelMode, FALSE, NULL);

        /* Scan all children PDO, stop when no more PDOs, or found it */
        for (FoundExtension = FdoExtension->ChildPdoList;
             (FoundExtension && FoundExtension != SearchExtension);
             FoundExtension = FoundExtension->Next);

        /* Release this device's lock */
        KeSetEvent(&FdoExtension->ChildListLock, IO_NO_INCREMENT, FALSE);
        KeLeaveCriticalRegion();

        /* If we found it, break out */
        if (FoundExtension)
            break;

        /* Move to the next device */
        FdoExtension = (PPCI_FDO_EXTENSION)FdoExtension->List.Next;
    }

    /* Check if we had acquired a lock previously */
    if (Lock)
    {
        /* Release it */
        KeSetEvent(Lock, IO_NO_INCREMENT, FALSE);
        KeLeaveCriticalRegion();
    }

    /* Return which extension was found, if any */
    return FdoExtension;
}

VOID
NTAPI
PciInsertEntryAtTail(
    _In_ PSINGLE_LIST_ENTRY ListHead,
    _In_ PPCI_FDO_EXTENSION FdoExtension,
    _In_ PKEVENT Lock)
{
    PSINGLE_LIST_ENTRY NextEntry;

    PAGED_CODE();
    DPRINT("PciInsertEntryAtTail: %p, %p, %p\n", ListHead, FdoExtension, Lock);

    /* Check if a lock was specified */
    if (Lock)
    {
        /* Wait for the lock to be released */
        KeEnterCriticalRegion();
        KeWaitForSingleObject(Lock, Executive, KernelMode, FALSE, NULL);
    }

    /* Loop the list until we get to the end, then insert this entry there */
    for (NextEntry = ListHead;
         NextEntry->Next;
         NextEntry = NextEntry->Next)
        ;

    NextEntry->Next = &FdoExtension->List;

    /* Check if we had acquired a lock previously */
    if (Lock)
    {
        /* Release it */
        KeSetEvent(Lock, IO_NO_INCREMENT, FALSE);
        KeLeaveCriticalRegion();
    }
}

VOID
NTAPI
PciInsertEntryAtHead(
    _In_ PSINGLE_LIST_ENTRY ListHead,
    _In_ PSINGLE_LIST_ENTRY Entry,
    _In_ PKEVENT Lock)
{
    PAGED_CODE();
    //DPRINT("PciInsertEntryAtHead: %p, %p\n", ListHead, Entry);

    /* Check if a lock was specified */
    if (Lock)
    {
        /* Wait for the lock to be released */
        KeEnterCriticalRegion();
        KeWaitForSingleObject(Lock, Executive, KernelMode, FALSE, NULL);
    }

    /* Make the entry point to the current head and make the head point to it */
    Entry->Next = ListHead->Next;
    ListHead->Next = Entry;

    /* Check if we had acquired a lock previously */
    if (Lock)
    {
        /* Release it */
        KeSetEvent(Lock, IO_NO_INCREMENT, FALSE);
        KeLeaveCriticalRegion();
    }
}

VOID
NTAPI
PcipLinkSecondaryExtension(
    _In_ PSINGLE_LIST_ENTRY List,
    _In_ PVOID Lock,
    _In_ PPCI_SECONDARY_EXTENSION SecondaryExtension,
    _In_ PCI_SIGNATURE ExtensionType,
    _In_ PVOID Destructor)
{
    PAGED_CODE();
    DPRINT("PcipLinkSecondaryExtension: %p, %p, %p, %X\n", List, Lock, SecondaryExtension, ExtensionType);

    /* Setup the extension data, and insert it into the primary's list */
    SecondaryExtension->ExtensionType = ExtensionType;
    SecondaryExtension->Destructor = Destructor;

    PciInsertEntryAtHead(List, &SecondaryExtension->List, Lock);
}

NTSTATUS
NTAPI
PciGetDeviceProperty(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ DEVICE_REGISTRY_PROPERTY DeviceProperty,
    _Out_ PVOID* OutputBuffer)
{
    PVOID Buffer;
    ULONG BufferLength;
    ULONG ResultLength;
    NTSTATUS Status;

    DPRINT("PciGetDeviceProperty: %p, %X\n", DeviceObject, DeviceProperty);

    do
    {
        /* Query the requested property size */
        Status = IoGetDeviceProperty(DeviceObject, DeviceProperty, 0, NULL, &BufferLength);
        if (Status != STATUS_BUFFER_TOO_SMALL)
        {
            /* Call should've failed with buffer too small! */
            DPRINT1("PciGetDeviceProperty: Unexpected status from GetDeviceProperty, saw %X, expected %X\n", Status, STATUS_BUFFER_TOO_SMALL);
            *OutputBuffer = NULL;
            ASSERTMSG("PCI Successfully did the impossible!\n", FALSE);
            break;
        }

        /* Allocate the required buffer */
        Buffer = ExAllocatePoolWithTag(PagedPool, BufferLength, 'BicP');
        if (!Buffer)
        {
            /* No memory, fail the request */
            DPRINT1("PciGetDeviceProperty: Failed to allocate DeviceProperty buffer (%X bytes).\n", BufferLength);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        /* Do the actual property query call */
        Status = IoGetDeviceProperty(DeviceObject, DeviceProperty, BufferLength, Buffer, &ResultLength);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PciGetDeviceProperty: Status %X\n", Status);
            break;
        }

        /* Return the buffer to the caller */
        ASSERT(BufferLength == ResultLength);
        *OutputBuffer = Buffer;

        return STATUS_SUCCESS;
    }
    while (FALSE);

    /* Failure path */
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS
NTAPI
PciSendIoctl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG IoControlCode,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength)
{
    PDEVICE_OBJECT AttachedDevice;
    IO_STATUS_BLOCK IoStatusBlock;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciSendIoctl: %p, %X, %p, %X, %p, %X\n", DeviceObject, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);

    /* Initialize the pending IRP event */
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    /* Get a reference to the root PDO (ACPI) */
    AttachedDevice = IoGetAttachedDeviceReference(DeviceObject);
    if (!AttachedDevice)
    {
        DPRINT1("PciSendIoctl: STATUS_INVALID_PARAMETER\n");
        return STATUS_INVALID_PARAMETER;
    }

    /* Build the requested IOCTL IRP */
    Irp = IoBuildDeviceIoControlRequest(IoControlCode,
                                        AttachedDevice,
                                        InputBuffer,
                                        InputBufferLength,
                                        OutputBuffer,
                                        OutputBufferLength,
                                        0,
                                        &Event,
                                        &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("PciSendIoctl: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Send the IOCTL to the driver */
    Status = IoCallDriver(AttachedDevice, Irp);
    if (Status == STATUS_PENDING)
    {
        /* Wait for a response */
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    /* Take away the reference we took and return the result to the caller */
    ObDereferenceObject(AttachedDevice);
    return Status;
}

PPCI_SECONDARY_EXTENSION
NTAPI
PciFindNextSecondaryExtension(
    _In_ PSINGLE_LIST_ENTRY ListHead,
    _In_ PCI_SIGNATURE ExtensionType)
{
    PPCI_SECONDARY_EXTENSION Extension;
    PSINGLE_LIST_ENTRY NextEntry;

    DPRINT("PciFindNextSecondaryExtension: %p, %X\n", ListHead, ExtensionType);

    /* Scan the list */
    for (NextEntry = ListHead; NextEntry; NextEntry = NextEntry->Next)
    {
        /* Grab each extension and check if it's the one requested */
        Extension = CONTAINING_RECORD(NextEntry, PCI_SECONDARY_EXTENSION, List);
        if (Extension->ExtensionType == ExtensionType)
            return Extension;
    }

    /* Nothing was found */
    return NULL;
}

ULONGLONG
NTAPI
PciGetHackFlags(
    _In_ USHORT VendorId,
    _In_ USHORT DeviceId,
    _In_ USHORT SubVendorId,
    _In_ USHORT SubSystemId,
    _In_ UCHAR RevisionId)
{
    PPCI_HACK_ENTRY HackEntry;
    ULONGLONG HackFlags;
    ULONG LastWeight, MatchWeight;
    ULONG EntryFlags;

    DPRINT("PciGetHackFlags: %X, %X, %X, %X, %X\n", VendorId, DeviceId, SubVendorId, SubSystemId, RevisionId);

    if (!PciHackTable)
    {
        DPRINT("PciGetHackFlags: ReactOS SetupLDR Hack!\n");
        return 0;
    }

    /* Initialize the variables before looping */
    LastWeight = 0;
    HackFlags = 0;

    ASSERT(PciHackTable);

    /* Scan the hack table */
    for (HackEntry = PciHackTable; HackEntry->VendorID != PCI_INVALID_VENDORID; HackEntry++)
    {
        /* Check if there's an entry for this device */
        if (HackEntry->DeviceID == DeviceId && HackEntry->VendorID == VendorId)
        {
            /* This is a basic match */
            EntryFlags = HackEntry->Flags;
            MatchWeight = 1;

            /* Does the entry have revision information? */
            if (EntryFlags & PCI_HACK_HAS_REVISION_INFO)
            {
                /* Check if the revision matches, if so, this is a better match */
                if (HackEntry->RevisionID != RevisionId)
                    continue;

                MatchWeight = 3;
            }

            /* Does the netry have subsystem information? */
            if (EntryFlags & PCI_HACK_HAS_SUBSYSTEM_INFO)
            {
                /* Check if it matches, if so, this is the best possible match */
                if (HackEntry->SubVendorID != SubVendorId)
                    continue;

                if (HackEntry->SubSystemID != SubSystemId)
                    continue;

                MatchWeight += 4;
            }

            /* Is this the best match yet? */
            if (MatchWeight > LastWeight)
            {
                /* This is the best match for now, use this as the hack flags */
                HackFlags = HackEntry->HackFlags;
                LastWeight = MatchWeight;
            }
        }
    }

    /* Return the best match */
    return HackFlags;
}

BOOLEAN
NTAPI
PciIsCriticalDeviceClass(
    _In_ UCHAR BaseClass,
    _In_ UCHAR SubClass)
{
    DPRINT("PciIsCriticalDeviceClass: %X, %X\n", BaseClass, SubClass);

    /* Check for system or bridge devices */
    if (BaseClass == PCI_CLASS_BASE_SYSTEM_DEV)
        /* Interrupt controllers are critical */
        return SubClass == PCI_SUBCLASS_SYS_INTERRUPT_CTLR;

    if (BaseClass == PCI_CLASS_BRIDGE_DEV)
        /* ISA Bridges are critical */
        return SubClass == PCI_SUBCLASS_BR_ISA;

    /* All display controllers are critical */
    return BaseClass == PCI_CLASS_DISPLAY_CTLR;
}

PPCI_PDO_EXTENSION
NTAPI
PciFindPdoByFunction(
    _In_ PPCI_FDO_EXTENSION FdoExtension,
    _In_ ULONG FunctionNumber,
    _In_ PPCI_COMMON_HEADER PciData)
{
    PPCI_PDO_EXTENSION PdoExtension;
    KIRQL Irql;

    DPRINT("PciFindPdoByFunction: %p, %X, %p\n", FdoExtension, FunctionNumber, PciData);

    /* Get the current IRQL when this call was made */
    Irql = KeGetCurrentIrql();

    /* Is this a low-IRQL call? */
    if (Irql < DISPATCH_LEVEL)
    {
        /* Acquire this device's lock */
        KeEnterCriticalRegion();
        KeWaitForSingleObject(&FdoExtension->ChildListLock, Executive, KernelMode, FALSE, NULL);
    }

    /* Loop every child PDO */
    for (PdoExtension = FdoExtension->ChildPdoList;
         PdoExtension;
         PdoExtension = PdoExtension->Next)
    {
        /* Find only enumerated PDOs */
        if (PdoExtension->ReportedMissing)
            continue;

        /* Check if the function number and header data matches */
        if (FunctionNumber == PdoExtension->Slot.u.AsULONG &&
            PdoExtension->VendorId == PciData->VendorID &&
            PdoExtension->DeviceId == PciData->DeviceID &&
            PdoExtension->RevisionId == PciData->RevisionID)
        {
            /* This is considered to be the same PDO */
            break;
        }
    }

    /* Was this a low-IRQL call? */
    if (Irql < DISPATCH_LEVEL)
    {
        /* Release this device's lock */
        KeSetEvent(&FdoExtension->ChildListLock, IO_NO_INCREMENT, FALSE);
        KeLeaveCriticalRegion();
    }

    /* If the search found something, this is non-NULL, otherwise it's NULL */
    return PdoExtension;
}

BOOLEAN
NTAPI
PciIsDeviceOnDebugPath(
    _In_ PPCI_PDO_EXTENSION PdoExtension)
{
    PPCI_FDO_EXTENSION ParentExtension;
    PCI_COMMON_HEADER BiosData;
    ULONG ix;
    UCHAR Bus;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciIsDeviceOnDebugPath: %p\n", PdoExtension);

    /* Check for too many, or no, debug ports */
    ASSERT(PciDebugPortsCount <= MAX_DEBUGGING_DEVICES_SUPPORTED);

    if (!PciDebugPortsCount)
    {
        DPRINT1("PciIsDeviceOnDebugPath: ret FALSE\n");
        return FALSE;
    }

    RtlZeroMemory(&BiosData, sizeof(BiosData));

    if (PdoExtension->HeaderType == 1 || PdoExtension->HeaderType == 2)
    {
        Status = PciGetBiosConfig(PdoExtension, &BiosData);
        ASSERT(NT_SUCCESS(Status));

        for (ix = 0; ix < MAX_DEBUGGING_DEVICES_SUPPORTED; ix++)
        {
            if (PciDebugPorts[ix].Bus >= BiosData.u.type1.SecondaryBus &&
                PciDebugPorts[ix].Bus <= BiosData.u.type1.SubordinateBus &&
                BiosData.u.type1.SecondaryBus &&
                BiosData.u.type1.SubordinateBus)
            {
                DPRINT1("PciIsDeviceOnDebugPath: [%X] ret TRUE\n", ix);
                return TRUE;
            }
        }

        DPRINT1("PciIsDeviceOnDebugPath: [%X] ret FALSE\n", ix);
        return FALSE;
    }

    ParentExtension = PdoExtension->ParentFdoExtension;

    if (ParentExtension == ParentExtension->BusRootFdoExtension)
    {
        Bus = ParentExtension->BaseBus;
    }
    else
    {
        Status = PciGetBiosConfig((PPCI_PDO_EXTENSION)ParentExtension->PhysicalDeviceObject->DeviceExtension, &BiosData);
        ASSERT(NT_SUCCESS(Status));

        if (!BiosData.u.type1.SecondaryBus ||
            !BiosData.u.type1.SubordinateBus)
        {
            DPRINT1("PciIsDeviceOnDebugPath: ret FALSE\n");
            return FALSE;
        }

        Bus = BiosData.u.type1.SecondaryBus;
    }

    for (ix = 0; ix < MAX_DEBUGGING_DEVICES_SUPPORTED; ix++)
    {
        if (PciDebugPorts[ix].Bus == Bus &&
            PciDebugPorts[ix].PciSlot.u.AsULONG == PdoExtension->Slot.u.AsULONG)
        {
            DPRINT1("PciIsDeviceOnDebugPath: [%X] ret TRUE\n", ix);
            return TRUE;
        }
    }

    DPRINT1("PciIsDeviceOnDebugPath: [%X] ret FALSE\n", ix);
    return FALSE;
}

NTSTATUS
NTAPI
PciGetBiosConfig(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _Out_ PPCI_COMMON_HEADER PciData)
{
    WCHAR DataBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + PCI_COMMON_HDR_LENGTH];
    PKEY_VALUE_PARTIAL_INFORMATION PartialInfo = (PVOID)DataBuffer;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KeyName;
    UNICODE_STRING KeyValue;
    HANDLE KeyHandle;
    HANDLE SubKeyHandle;
    ULONG ResultLength;
    WCHAR Buffer[32];
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciGetBiosConfig: %p, %p\n", PdoExtension, PciData);

    /* Open the PCI key */
    Status = IoOpenDeviceRegistryKey(PdoExtension->ParentFdoExtension->PhysicalDeviceObject,
                                     TRUE,
                                     KEY_ALL_ACCESS,
                                     &KeyHandle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciGetBiosConfig: Status %X\n", Status);
        return Status;
    }

    /* Create a volatile BIOS configuration key */
    RtlInitUnicodeString(&KeyName, L"BiosConfig");
    InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_KERNEL_HANDLE, KeyHandle, NULL);

    Status = ZwCreateKey(&SubKeyHandle, KEY_READ, &ObjectAttributes, 0, NULL, REG_OPTION_VOLATILE, NULL);
    ZwClose(KeyHandle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciGetBiosConfig: Status %X\n", Status);
        return Status;
    }

    /* Create the key value based on the device and function number */
    swprintf(Buffer, L"DEV_%02x&FUN_%02x", PdoExtension->Slot.u.bits.DeviceNumber, PdoExtension->Slot.u.bits.FunctionNumber);
    RtlInitUnicodeString(&KeyValue, Buffer);

    /* Query the value information (PCI BIOS configuration header) */
    Status = ZwQueryValueKey(SubKeyHandle, &KeyValue, KeyValuePartialInformation, PartialInfo, sizeof(DataBuffer), &ResultLength);
    ZwClose(SubKeyHandle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("PciGetBiosConfig: Status %X\n", Status);
        return Status;
    }

    /* If any information was returned, go ahead and copy its data */
    ASSERT(PartialInfo->DataLength == PCI_COMMON_HDR_LENGTH);
    RtlCopyMemory(PciData, PartialInfo->Data, PCI_COMMON_HDR_LENGTH);

    return Status;
}

NTSTATUS
NTAPI
PciSaveBiosConfig(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _Out_ PPCI_COMMON_HEADER PciData)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KeyName;
    UNICODE_STRING KeyValue;
    HANDLE KeyHandle;
    HANDLE SubKeyHandle;
    WCHAR Buffer[32];
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciSaveBiosConfig: %p, %p\n", PdoExtension, PciData);

    /* Open the PCI key */
    Status = IoOpenDeviceRegistryKey(PdoExtension->ParentFdoExtension->PhysicalDeviceObject,
                                     TRUE,
                                     (KEY_READ | KEY_WRITE),
                                     &KeyHandle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciSaveBiosConfig: Status %X\n", Status);
        return Status;
    }

    /* Create a volatile BIOS configuration key */
    RtlInitUnicodeString(&KeyName, L"BiosConfig");
    InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_KERNEL_HANDLE, KeyHandle, NULL);

    Status = ZwCreateKey(&SubKeyHandle, (KEY_READ | KEY_WRITE), &ObjectAttributes, 0, NULL, REG_OPTION_VOLATILE, NULL);
    ZwClose(KeyHandle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciSaveBiosConfig: Status %X\n", Status);
        return Status;
    }

    /* Create the key value based on the device and function number */
    swprintf(Buffer, L"DEV_%02x&FUN_%02x", PdoExtension->Slot.u.bits.DeviceNumber, PdoExtension->Slot.u.bits.FunctionNumber);
    RtlInitUnicodeString(&KeyValue, Buffer);

    /* Set the value data (the PCI BIOS configuration header) */
    Status = ZwSetValueKey(SubKeyHandle, &KeyValue, 0, REG_BINARY, PciData, PCI_COMMON_HDR_LENGTH);
    ZwClose(SubKeyHandle);

    return Status;
}

UCHAR
NTAPI
PciReadDeviceCapability(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ UCHAR Offset,
    _In_ ULONG CapabilityId,
    _Out_ PPCI_CAPABILITIES_HEADER CapabilitiesHeader,
    _In_ ULONG Length)
{
    ULONG CapabilityCount = 0;

    DPRINT("PciReadDeviceCapability: %p, %X, %X, %X\n", PdoExtension, Offset, CapabilityId, Length);

    /* If the device has no capabilility list, fail */
    if (!Offset)
        return 0;

    /* Validate a PDO with capabilities, a valid buffer, and a valid length */
    ASSERT(PdoExtension->ExtensionType == PciPdoExtensionType);
    ASSERT(PdoExtension->CapabilitiesPtr != 0);
    ASSERT(CapabilitiesHeader);
    ASSERT(Length >= sizeof(PCI_CAPABILITIES_HEADER));

    /* Loop all capabilities */
    while (Offset)
    {
        /* Make sure the pointer is spec-aligned and spec-sized */
        ASSERT((Offset >= PCI_COMMON_HDR_LENGTH) && ((Offset & 0x3) == 0));

        /* Read the capability header */
        PciReadDeviceConfig(PdoExtension, CapabilitiesHeader, Offset, sizeof(PCI_CAPABILITIES_HEADER));

        /* Check if this is the capability being looked up */
        if (CapabilitiesHeader->CapabilityID == CapabilityId || !CapabilityId)
        {
            /* Check if was at a valid offset and length */
            if (Offset && Length > sizeof(PCI_CAPABILITIES_HEADER))
            {
                /* Sanity check */
                ASSERT(Length <= (sizeof(PCI_COMMON_CONFIG) - Offset));

                /* Now read the whole capability data into the buffer */
                PciReadDeviceConfig(PdoExtension,
                                    Add2Ptr(CapabilitiesHeader, sizeof(PCI_CAPABILITIES_HEADER)),
                                    (Offset + sizeof(PCI_CAPABILITIES_HEADER)),
                                    (Length - sizeof(PCI_CAPABILITIES_HEADER)));
            }

            /* Return the offset where the capability was found */
            return Offset;
        }

        /* Try the next capability instead */
        CapabilityCount++;
        Offset = CapabilitiesHeader->Next;

        /* There can't be more than 48 capabilities (256 bytes max) */
        if (CapabilityCount > 0x30)
        {
            /* Fail, since this is basically a broken PCI device */
            DPRINT1("PciReadDeviceCapability: PCI device %p capabilities list is broken.\n", PdoExtension);
            return 0;
        }
    }

    /* Capability wasn't found, fail */
    return 0;
}

BOOLEAN
NTAPI
PciCanDisableDecodes(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PPCI_COMMON_HEADER Config,
    _In_ ULONGLONG HackFlags,
    _In_ BOOLEAN ForPowerDown)
{
    UCHAR BaseClass;
    UCHAR SubClass;
    BOOLEAN IsVga;

    DPRINT("PciCanDisableDecodes: %p, %p, %I64X, %X\n", PdoExtension, Config, HackFlags, ForPowerDown);

    /* Is there a device extension or should the PCI header be used? */
    if (PdoExtension)
    {
        /* Never disable decodes for a debug PCI Device */
        if (PdoExtension->OnDebugPath)
            return FALSE;

        /* Hack flags will be obtained from the extension, not the caller */
        ASSERT(HackFlags == 0);

        /* Get hacks and classification from the device extension */
        HackFlags = PdoExtension->HackFlags;
        SubClass = PdoExtension->SubClass;
        BaseClass = PdoExtension->BaseClass;
    }
    else
    {
        /* There must be a PCI header, go read the classification information */
        ASSERT(Config != NULL);

        BaseClass = Config->BaseClass;
        SubClass = Config->SubClass;
    }

    /* Check for hack flags that prevent disabling the decodes */
    if (HackFlags & (PCI_HACK_PRESERVE_COMMAND | PCI_HACK_CB_SHARE_CMD_BITS | PCI_HACK_DONT_DISABLE_DECODES))
        /* Don't do it */
        return FALSE;

    /* Is this a VGA adapter? */
    if (BaseClass == PCI_CLASS_DISPLAY_CTLR && SubClass == PCI_SUBCLASS_VID_VGA_CTLR)
        /* Never disable decodes if this is for power down */
        return ForPowerDown;

    /* Check for legacy devices */
    if (BaseClass == PCI_CLASS_PRE_20)
    {
        /* Never disable video adapter cards if this is for power down */
        if (SubClass == PCI_SUBCLASS_PRE_20_VGA)
            return ForPowerDown;
    }
    else if (BaseClass == PCI_CLASS_DISPLAY_CTLR)
    {
        /* Never disable VGA adapters if this is for power down */
        if (SubClass == PCI_SUBCLASS_VID_VGA_CTLR)
            return ForPowerDown;
    }
    else if (BaseClass == PCI_CLASS_BRIDGE_DEV)
    {
        /* Check for legacy bridges */
        if (SubClass == PCI_SUBCLASS_BR_ISA ||
            SubClass == PCI_SUBCLASS_BR_EISA ||
            SubClass == PCI_SUBCLASS_BR_MCA ||
            SubClass == PCI_SUBCLASS_BR_HOST ||
            SubClass == PCI_SUBCLASS_BR_OTHER)
        {
            /* Never disable these */
            return FALSE;
        }

        if (SubClass == PCI_SUBCLASS_BR_PCI_TO_PCI || SubClass == PCI_SUBCLASS_BR_CARDBUS)
        {
            /* This is a supported bridge, but does it have a VGA card? */
            if (!PdoExtension)
                /* Read the bridge control flag from the PCI header */
                IsVga = (Config->u.type1.BridgeControl & PCI_ENABLE_BRIDGE_VGA);
            else
                /* Read the cached flag in the device extension */
                IsVga = PdoExtension->Dependent.type1.VgaBitSet;

            /* Never disable VGA adapters if this is for power down */
            if (IsVga)
                return ForPowerDown;
        }
    }

    /* Finally, never disable decodes if there's no power management */
    return !(HackFlags & PCI_HACK_NO_PM_CAPS);
}

PCI_DEVICE_TYPES
NTAPI
PciClassifyDeviceType(IN PPCI_PDO_EXTENSION PdoExtension)
{
    DPRINT("PciClassifyDeviceType: %p\n", PdoExtension);

    ASSERT(PdoExtension->ExtensionType == PciPdoExtensionType);

    /* Differentiate between devices and bridges */
    if (PdoExtension->BaseClass != PCI_CLASS_BRIDGE_DEV)
        return PciTypeDevice;

    /* The PCI Bus driver handles only CardBus and PCI bridges (plus host) */
    if (PdoExtension->SubClass == PCI_SUBCLASS_BR_HOST)
        return PciTypeHostBridge;

    if (PdoExtension->SubClass == PCI_SUBCLASS_BR_PCI_TO_PCI)
        return PciTypePciBridge;

    if (PdoExtension->SubClass == PCI_SUBCLASS_BR_CARDBUS)
        return PciTypeCardbusBridge;

    /* Any other kind of bridge is treated like a device */
    return PciTypeDevice;
}

ULONG_PTR
NTAPI
PciExecuteCriticalSystemRoutine(
    _In_ ULONG_PTR IpiContext)
{
    PPCI_IPI_CONTEXT Context = (PPCI_IPI_CONTEXT)IpiContext;

    DPRINT("PciExecuteCriticalSystemRoutine: %p\n", IpiContext);

    /* Check if the IPI is already running */
    if (InterlockedDecrement(&Context->RunCount))
    {
        /* Spin until it has finished running */
        while (Context->Barrier)
            ;

        return 0;
    }

    /* Nope, this is the first instance, so execute the IPI function */
    Context->Function(Context->DeviceExtension, Context->Context);

    /* Notify anyone that was spinning that they can stop now */
    Context->Barrier = 0;

    /* Done */
    return 0;
}

BOOLEAN
NTAPI
PciIsSlotPresentInParentMethod(IN PPCI_PDO_EXTENSION PdoExtension,
                               IN ULONG Method)
{
    BOOLEAN FoundSlot;
    PACPI_METHOD_ARGUMENT Argument;
    ACPI_EVAL_INPUT_BUFFER InputBuffer;
    PACPI_EVAL_OUTPUT_BUFFER OutputBuffer;
    ULONG i, Length;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PCIX: .. \n");

    /* Assume slot is not part of the parent method */
    FoundSlot = FALSE;

    /* Allocate a 2KB buffer for the method return parameters */
    Length = sizeof(ACPI_EVAL_OUTPUT_BUFFER) + 2048;
    OutputBuffer = ExAllocatePoolWithTag(PagedPool, Length, 'BicP');
    if (OutputBuffer)
    {
        /* Clear out the output buffer */
        RtlZeroMemory(OutputBuffer, Length);

        /* Initialize the input buffer with the method requested */
        InputBuffer.Signature = 0;
        *(PULONG)InputBuffer.MethodName = Method;
        InputBuffer.Signature = ACPI_EVAL_INPUT_BUFFER_SIGNATURE;

        /* Send it to the ACPI driver */
        Status = PciSendIoctl(PdoExtension->ParentFdoExtension->PhysicalDeviceObject,
                              IOCTL_ACPI_EVAL_METHOD,
                              &InputBuffer,
                              sizeof(ACPI_EVAL_INPUT_BUFFER),
                              OutputBuffer,
                              Length);
        if (NT_SUCCESS(Status))
        {
            /* Scan all output arguments */
            for (i = 0; i < OutputBuffer->Count; i++)
            {
                /* Make sure it's an integer */
                Argument = &OutputBuffer->Argument[i];
                if (Argument->Type != ACPI_METHOD_ARGUMENT_INTEGER) continue;

                /* Check if the argument matches this PCI slot structure */
                if (Argument->Argument == ((PdoExtension->Slot.u.bits.DeviceNumber) |
                                           ((PdoExtension->Slot.u.bits.FunctionNumber) << 16)))
                {
                    /* This slot has been found, return it */
                    FoundSlot = TRUE;
                    break;
                }
            }
        }

        /* Finished with the buffer, free it */
        ExFreePoolWithTag(OutputBuffer, 0);
    }

    /* Return if the slot was found */
    return FoundSlot;
}

ULONG
NTAPI
PciGetLengthFromBar(
    _In_ ULONG Bar)
{
    ULONG Length;

    DPRINT("PciGetLengthFromBar: %X\n", Bar);

    /* I/O addresses vs. memory addresses start differently due to alignment */
    Length = (1 << ((Bar & PCI_ADDRESS_IO_SPACE) ? 2 : 4));

    /* Keep going until a set bit */
    while (!(Length & Bar) && Length)
        Length <<= 1;

    /* Return the length (might be 0 on 64-bit because it's the low-word) */
    if ((Bar & PCI_ADDRESS_MEMORY_TYPE_MASK) != PCI_TYPE_64BIT)
    {
        ASSERT(Length);
    }

    return Length;
}

BOOLEAN
NTAPI
PciCreateIoDescriptorFromBarLimit(
    _In_ PIO_RESOURCE_DESCRIPTOR IoDescriptor,
    _In_ PULONG BarArray,
    _In_ BOOLEAN IsRomAddress)
{
    ULONG CurrentBar;
    ULONG BarLength;
    ULONG BarMask;
    BOOLEAN Is64BitBar = FALSE;

    DPRINT("PciCreateIoDescriptorFromBarLimit: %p, %p, %X\n", IoDescriptor, BarArray, IsRomAddress);

    /* Check if the BAR is nor I/O nor memory */
    CurrentBar = BarArray[0];
    if (!(CurrentBar & ~PCI_ADDRESS_IO_SPACE))
    {
        /* Fail this descriptor */
        IoDescriptor->Type = CmResourceTypeNull;
        return FALSE;
    }

    /* Set default flag and clear high words */
    IoDescriptor->Flags = 0;
    IoDescriptor->u.Generic.MaximumAddress.HighPart = 0;
    IoDescriptor->u.Generic.MinimumAddress.LowPart = 0;
    IoDescriptor->u.Generic.MinimumAddress.HighPart = 0;

    /* Check for ROM Address */
    if (IsRomAddress)
    {
        /* Clean up the BAR to get just the address */
        CurrentBar &= PCI_ADDRESS_ROM_ADDRESS_MASK;
        if (!CurrentBar)
        {
            /* Invalid ar, fail this descriptor */
            IoDescriptor->Type = CmResourceTypeNull;
            return FALSE;
        }

        /* ROM Addresses are always read only */
        IoDescriptor->Flags = CM_RESOURCE_MEMORY_READ_ONLY;
    }

    /* Compute the length, assume it's the alignment for now */
    BarLength = PciGetLengthFromBar(CurrentBar);

    IoDescriptor->u.Generic.Length = BarLength;
    IoDescriptor->u.Generic.Alignment = BarLength;

    /* Check what kind of BAR this is */
    if (CurrentBar & PCI_ADDRESS_IO_SPACE)
    {
        /* Use correct mask to decode the address */
        BarMask = PCI_ADDRESS_IO_ADDRESS_MASK;

        /* Set this as an I/O Port descriptor */
        IoDescriptor->Type = CmResourceTypePort;
        IoDescriptor->Flags = CM_RESOURCE_PORT_IO;
    }
    else
    {
        /* Use correct mask to decode the address */
        BarMask = PCI_ADDRESS_MEMORY_ADDRESS_MASK;

        /* Set this as a memory descriptor */
        IoDescriptor->Type = CmResourceTypeMemory;

        /* Check if it's 64-bit or 20-bit decode */
        if ((CurrentBar & PCI_ADDRESS_MEMORY_TYPE_MASK) == PCI_TYPE_64BIT)
        {
            /* The next BAR has the high word, read it */
            IoDescriptor->u.Port.MaximumAddress.HighPart = BarArray[1];
            Is64BitBar = TRUE;
        }
        else if ((CurrentBar & PCI_ADDRESS_MEMORY_TYPE_MASK) == PCI_TYPE_20BIT)
        {
            /* Use the correct mask to decode the address */
            BarMask = ~0xFFF0000F;
        }

        /* Check if the BAR is listed as prefetchable memory */
        if (CurrentBar & PCI_ADDRESS_MEMORY_PREFETCHABLE)
            /* Mark the descriptor in the same way */
            IoDescriptor->Flags |= CM_RESOURCE_MEMORY_PREFETCHABLE;
    }

    /* Now write down the maximum address based on the base + length */
    IoDescriptor->u.Port.MaximumAddress.QuadPart = ((CurrentBar & BarMask) + BarLength - 1);

    /* Return if this is a 64-bit BAR, so the loop code knows to skip the next one */
    return Is64BitBar;
}

VOID
NTAPI
PciDecodeEnable(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ BOOLEAN IsEnable,
    _Out_ PUSHORT OutCommand)
{
    USHORT CommandValue;

    DPRINT("PciDecodeEnable: %p, %X\n", PdoExtension, IsEnable);

    /*
     * If decodes are being disabled, make sure it's allowed, and in both cases,
     * make sure that a hackflag isn't preventing touching the decodes at all.
     */
    if ((IsEnable || PciCanDisableDecodes(PdoExtension, 0, 0, 0)) &&
        !(PdoExtension->HackFlags & PCI_HACK_PRESERVE_COMMAND))
    {
        /* Did the caller already have a command word? */
        if (OutCommand)
        {
            /* Use the caller's */
            CommandValue = *OutCommand;
        }
        else
        {
            /* Otherwise, read the current command */
            PciReadDeviceConfig(PdoExtension,
                                &OutCommand,
                                FIELD_OFFSET(PCI_COMMON_HEADER, Command),
                                sizeof(USHORT));
        }

        /* Turn off decodes by default */
        CommandValue &= ~(PCI_ENABLE_IO_SPACE |
                          PCI_ENABLE_MEMORY_SPACE |
                          PCI_ENABLE_BUS_MASTER);

        /* If requested, enable the decodes that were enabled at init time */
        if (IsEnable)
            CommandValue |= (PdoExtension->CommandEnables & (PCI_ENABLE_IO_SPACE | PCI_ENABLE_MEMORY_SPACE | PCI_ENABLE_BUS_MASTER));

        /* Update the command word */
        PciWriteDeviceConfig(PdoExtension,
                             &CommandValue,
                             FIELD_OFFSET(PCI_COMMON_HEADER, Command),
                             sizeof(USHORT));
    }
}

NTSTATUS
NTAPI
PciQueryBusInformation(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ PPNP_BUS_INFORMATION* OutBusInfo)
{
    PPNP_BUS_INFORMATION BusInfo;

    DPRINT("PciQueryBusInformation: %p\n", PdoExtension);

    /* Allocate a structure for the bus information */
    BusInfo = ExAllocatePoolWithTag(PagedPool, sizeof(PNP_BUS_INFORMATION), 'BicP');
    if (!BusInfo)
    {
        DPRINT1("PciQueryBusInformation: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Write the correct GUID and bus type identifier, and fill the bus number */
    BusInfo->BusTypeGuid = GUID_BUS_TYPE_PCI;
    BusInfo->LegacyBusType = PCIBus;
    BusInfo->BusNumber = PdoExtension->ParentFdoExtension->BaseBus;

    *OutBusInfo = BusInfo;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciDetermineSlotNumber(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _Out_ ULONG* OutSlotNumber)
{
    PPCI_FDO_EXTENSION ParentExtension = PdoExtension->ParentFdoExtension;
    PSLOT_INFO SlotInfo;
    ULONG ResultLength;

    DPRINT("PciDetermineSlotNumber: Slot lookup for %X.%X.%X\n", (ParentExtension ? ParentExtension->BaseBus : -1),
           PdoExtension->Slot.u.bits.DeviceNumber, PdoExtension->Slot.u.bits.FunctionNumber);

    /* Check if a $PIR from the BIOS is used (legacy IRQ routing) */
    if (PciIrqRoutingTable && ParentExtension)
    {
        /* Read every slot information entry */
        SlotInfo = &PciIrqRoutingTable->Slot[0];

        DPRINT("PciDetermineSlotNumber: %p, %X, %p\n", PciIrqRoutingTable, PciIrqRoutingTable->TableSize, SlotInfo);

        while (SlotInfo < (PSLOT_INFO)((ULONG_PTR)PciIrqRoutingTable + PciIrqRoutingTable->TableSize))
        {
            DPRINT("PciDetermineSlotNumber: %X.%X->#%X\n", SlotInfo->BusNumber, SlotInfo->DeviceNumber, SlotInfo->SlotNumber);

            /* Check if this slot information matches the PDO being queried */
            if (ParentExtension->BaseBus == SlotInfo->BusNumber &&
                PdoExtension->Slot.u.bits.DeviceNumber == (SlotInfo->DeviceNumber >> 3) &&
                SlotInfo->SlotNumber)
            {
                /* We found it, return it and return success */
                *OutSlotNumber = SlotInfo->SlotNumber;
                return STATUS_SUCCESS;
            }

            /* Try the next slot */
            SlotInfo++;
        }
    }

    /* Otherwise, grab the parent FDO and check if it's the root */
    if (PCI_IS_ROOT_FDO(ParentExtension))
    {
        /* The root FDO doesn't have a slot number */
        return STATUS_UNSUCCESSFUL;
    }

    /* Otherwise, query the slot/UI address/number as a device property */
    return IoGetDeviceProperty(ParentExtension->PhysicalDeviceObject,
                               DevicePropertyUINumber,
                               sizeof(ULONG),
                               OutSlotNumber,
                               &ResultLength);
}

NTSTATUS
NTAPI
PciGetDeviceCapabilities(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PDEVICE_CAPABILITIES DeviceCapability)
{
    IO_STATUS_BLOCK IoStatusBlock;
    PDEVICE_OBJECT AttachedDevice;
    PIO_STACK_LOCATION IoStack;
    PIRP Irp;
    KEVENT Event;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PciGetDeviceCapabilities: %p, %p\n", DeviceObject, DeviceCapability);

    /* Zero out capabilities and set undefined values to start with */
    RtlZeroMemory(DeviceCapability, sizeof(DEVICE_CAPABILITIES));

    DeviceCapability->Size = sizeof(DEVICE_CAPABILITIES);
    DeviceCapability->Version = 1;
    DeviceCapability->Address = -1;
    DeviceCapability->UINumber = -1;

    /* Build the wait event for the IOCTL */
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    /* Find the device the PDO is attached to */
    AttachedDevice = IoGetAttachedDeviceReference(DeviceObject);

    /* And build an IRP for it */
    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP, AttachedDevice, NULL, 0, NULL, &Event, &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("PciGetDeviceCapabilities: STATUS_INSUFFICIENT_RESOURCES\n");

        /* The IRP failed, fail the request as well */
        ObDereferenceObject(AttachedDevice);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Set default status */
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    /* Get a stack location in this IRP */
    IoStack = IoGetNextIrpStackLocation(Irp);
    ASSERT(IoStack);

    /* Initialize it as a query capabilities IRP, with no completion routine */
    RtlZeroMemory(IoStack, sizeof(IO_STACK_LOCATION));

    IoStack->MajorFunction = IRP_MJ_PNP;
    IoStack->MinorFunction = IRP_MN_QUERY_CAPABILITIES;
    IoStack->Parameters.DeviceCapabilities.Capabilities = DeviceCapability;
    IoSetCompletionRoutine(Irp, NULL, NULL, FALSE, FALSE, FALSE);

    /* Send the IOCTL to the driver */
    Status = IoCallDriver(AttachedDevice, Irp);
    if (Status == STATUS_PENDING)
    {
        /* Wait for a response and update the actual status */
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    /* Done, dereference the attached device and return the final result */
    ObDereferenceObject(AttachedDevice);

    return Status;
}

NTSTATUS
NTAPI
PciQueryPowerCapabilities(
    _In_ IN PPCI_PDO_EXTENSION PdoExtension,
    _In_ IN PDEVICE_CAPABILITIES DeviceCapability)
{
    PDEVICE_OBJECT DeviceObject;
    SYSTEM_POWER_STATE DeepestWakeState;
    SYSTEM_POWER_STATE SystemWakeState;
    SYSTEM_POWER_STATE CurrentState;
    DEVICE_POWER_STATE DevicePowerState;
    DEVICE_POWER_STATE DeviceWakeLevel;
    DEVICE_POWER_STATE DeviceWakeState;
    DEVICE_POWER_STATE NewPowerState;
    DEVICE_CAPABILITIES AttachedCaps;
    NTSTATUS Status;

    DPRINT("PciQueryPowerCapabilities: %p, %p\n", PdoExtension, DeviceCapability);

    /* Nothing is known at first */
    DeviceWakeState = PowerDeviceUnspecified;
    SystemWakeState = DeepestWakeState = PowerSystemUnspecified;

    /* Get the PCI capabilities for the parent PDO */
    DeviceObject = PdoExtension->ParentFdoExtension->PhysicalDeviceObject;

    Status = PciGetDeviceCapabilities(DeviceObject, &AttachedCaps);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciQueryPowerCapabilities: Status %X\n", Status);
        ASSERT(NT_SUCCESS(Status));
        return Status;
    }

    /* Check if there's not an existing device state for S0 */
    if (!AttachedCaps.DeviceState[PowerSystemWorking])
        /* Set D0<->S0 mapping */
        AttachedCaps.DeviceState[PowerSystemWorking] = PowerDeviceD0;

    /* Check if there's not an existing device state for S3 */
    if (!AttachedCaps.DeviceState[PowerSystemShutdown])
        /* Set D3<->S3 mapping */
        AttachedCaps.DeviceState[PowerSystemShutdown] = PowerDeviceD3;

    /* Check for a PDO with broken, or no, power capabilities */
    if (PdoExtension->HackFlags & PCI_HACK_NO_PM_CAPS)
    {
        /* Unknown wake device states */
        DeviceCapability->DeviceWake = PowerDeviceUnspecified;
        DeviceCapability->SystemWake = PowerSystemUnspecified;

        /* No device state support */
        DeviceCapability->DeviceD1 = FALSE;
        DeviceCapability->DeviceD2 = FALSE;

        /* No waking from any low-power device state is supported */
        DeviceCapability->WakeFromD0 = FALSE;
        DeviceCapability->WakeFromD1 = FALSE;
        DeviceCapability->WakeFromD2 = FALSE;
        DeviceCapability->WakeFromD3 = FALSE;

        /* For the rest, copy whatever the parent PDO had */
        RtlCopyMemory(DeviceCapability->DeviceState, AttachedCaps.DeviceState, sizeof(DeviceCapability->DeviceState));

        return STATUS_SUCCESS;
    }

    /* The PCI Device has power capabilities, so read which ones are supported */
    DeviceCapability->DeviceD1 = PdoExtension->PowerCapabilities.Support.D1;
    DeviceCapability->DeviceD2 = PdoExtension->PowerCapabilities.Support.D2;

    DeviceCapability->WakeFromD0 = PdoExtension->PowerCapabilities.Support.PMED0;
    DeviceCapability->WakeFromD1 = PdoExtension->PowerCapabilities.Support.PMED1;
    DeviceCapability->WakeFromD2 = PdoExtension->PowerCapabilities.Support.PMED2;

    /* Can the attached device wake from D3? */
    if (AttachedCaps.DeviceWake != PowerDeviceD3)
    {
        /* It can't, so check if this PDO supports hot D3 wake */
        DeviceCapability->WakeFromD3 = PdoExtension->PowerCapabilities.Support.PMED3Hot;
    }
    /* It can, is this the root bus? */
    else if (PCI_IS_ROOT_FDO(PdoExtension->ParentFdoExtension))
    {
        /* This is the root bus, so just check if it supports hot D3 wake */
        DeviceCapability->WakeFromD3 = PdoExtension->PowerCapabilities.Support.PMED3Hot;
    }
    else
    {
        /* Take the minimums? -- need to check with briang at work */
        DeviceCapability->WakeFromD3 = PdoExtension->PowerCapabilities.Support.PMED3Cold;
    }

    /* Now loop each system power state to determine its device state mapping */
    for (CurrentState = PowerSystemWorking; CurrentState < PowerSystemMaximum; CurrentState++)
    {
        /* Read the current mapping from the attached device */
        DevicePowerState = AttachedCaps.DeviceState[CurrentState];
        NewPowerState = DevicePowerState;

        /* The attachee supports D1, but this PDO does not */
        if (NewPowerState == PowerDeviceD1 && !PdoExtension->PowerCapabilities.Support.D1)
            /* Fall back to D2 */
            NewPowerState = PowerDeviceD2;

        /* The attachee supports D2, but this PDO does not */
        if (NewPowerState == PowerDeviceD2 && !PdoExtension->PowerCapabilities.Support.D2)
            /* Fall back to D3 */
            NewPowerState = PowerDeviceD3;

        /* Set the mapping based on the best state supported */
        DeviceCapability->DeviceState[CurrentState] = NewPowerState;

        /* Check if sleep states are being processed, and a mapping was found */
        if (CurrentState < PowerSystemHibernate && NewPowerState != PowerDeviceUnspecified)
            /* Save this state as being the deepest one found until now */
            DeepestWakeState = CurrentState;

        /*
         * Finally, check if the computed sleep state is within the states that
         * this device can wake the system from, and if it's higher or equal to
         * the sleep state mapping that came from the attachee, assuming that it
         * had a valid mapping to begin with.
         *
         * It this is the case, then make sure that the computed sleep state is
         * matched by the device's ability to actually wake from that state.
         *
         * For devices that support D3, the PCI device only needs Hot D3 as long
         * as the attachee's state is less than D3. Otherwise, if the attachee
         * might also be at D3, this would require a Cold D3 wake, so check that
         * the device actually support this.
         */
        if (CurrentState < AttachedCaps.SystemWake &&
            NewPowerState >= DevicePowerState &&
            DevicePowerState != PowerDeviceUnspecified &&
            ((NewPowerState == PowerDeviceD0 && DeviceCapability->WakeFromD0) ||
             (NewPowerState == PowerDeviceD1 && DeviceCapability->WakeFromD1) ||
             (NewPowerState == PowerDeviceD2 && DeviceCapability->WakeFromD2) ||
             (NewPowerState == PowerDeviceD3 && PdoExtension->PowerCapabilities.Support.PMED3Hot &&
              (DevicePowerState < PowerDeviceD3 || PdoExtension->PowerCapabilities.Support.PMED3Cold))))
        {
            /* The mapping is valid, so this will be the lowest wake state */
            SystemWakeState = CurrentState;
            DeviceWakeState = NewPowerState;
        }
    }

    /* Read the current wake level */
    DeviceWakeLevel = PdoExtension->PowerState.DeviceWakeLevel;

    /* Check if the attachee's wake levels are valid, and the PDO's is higher */
    if (AttachedCaps.SystemWake == PowerSystemUnspecified ||
        AttachedCaps.DeviceWake == PowerDeviceUnspecified ||
        DeviceWakeLevel == PowerDeviceUnspecified ||
        DeviceWakeLevel < AttachedCaps.DeviceWake)
    {
        /* No valid sleep states, no latencies to worry about */
        DeviceCapability->D1Latency = 0;
        DeviceCapability->D2Latency = 0;
        DeviceCapability->D3Latency = 0;

        /* This function always succeeds, even without power management support */
        return STATUS_SUCCESS;
    }

    /* Inherit the system wake from the attachee, and this PDO's wake level */
    DeviceCapability->SystemWake = AttachedCaps.SystemWake;
    DeviceCapability->DeviceWake = DeviceWakeLevel;

    /* Now check if the wake level is D0, but the PDO doesn't support it */
    if (DeviceCapability->DeviceWake == PowerDeviceD0 && !DeviceCapability->WakeFromD0)
        /* Bump to D1 */
        DeviceCapability->DeviceWake = PowerDeviceD1;

    /* Now check if the wake level is D1, but the PDO doesn't support it */
    if (DeviceCapability->DeviceWake == PowerDeviceD1 && !DeviceCapability->WakeFromD1)
        /* Bump to D2 */
        DeviceCapability->DeviceWake = PowerDeviceD2;

    /* Now check if the wake level is D2, but the PDO doesn't support it */
    if (DeviceCapability->DeviceWake == PowerDeviceD2 && !DeviceCapability->WakeFromD2)
        /* Bump it to D3 */
        DeviceCapability->DeviceWake = PowerDeviceD3;

    /* Now check if the wake level is D3, but the PDO doesn't support it */
    if (DeviceCapability->DeviceWake == PowerDeviceD3 && !DeviceCapability->WakeFromD3)
    {
        /* Then no valid wake state exists */
        DeviceCapability->DeviceWake = PowerDeviceUnspecified;
        DeviceCapability->SystemWake = PowerSystemUnspecified;
    }

    /* Check if no valid wake state was found */
    if (DeviceCapability->DeviceWake == PowerDeviceUnspecified ||
        DeviceCapability->SystemWake == PowerSystemUnspecified)
    {
        /* Check if one was computed earlier */
        if (SystemWakeState != PowerSystemUnspecified &&
            DeviceWakeState != PowerDeviceUnspecified)
        {
            /* Use the wake state that had been computed earlier */
            DeviceCapability->DeviceWake = DeviceWakeState;
            DeviceCapability->SystemWake = SystemWakeState;

            /* If that state was D3, then the device supports Hot/Cold D3 */
            if (DeviceWakeState == PowerDeviceD3)
                DeviceCapability->WakeFromD3 = TRUE;
        }
    }

    /*
     * Finally, check for off states (lower than S3, such as hibernate) and
     * make sure that the device both supports waking from D3 as well as
     * supports a Cold wake
     */
    if (DeviceCapability->SystemWake > PowerSystemSleeping3 &&
        (DeviceCapability->DeviceWake != PowerDeviceD3 || !PdoExtension->PowerCapabilities.Support.PMED3Cold))
    {
        /* It doesn't, so pick the computed lowest wake state from earlier */
        DeviceCapability->SystemWake = DeepestWakeState;
    }

    /* Set the PCI Specification mandated maximum latencies for transitions */
    DeviceCapability->D1Latency = 0;
    DeviceCapability->D2Latency = 2;
    DeviceCapability->D3Latency = 0x64; // 100

    /* Sanity check */
    ASSERT(DeviceCapability->DeviceState[PowerSystemWorking] == PowerDeviceD0);

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
PciQueryCapabilities(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _Inout_ PDEVICE_CAPABILITIES DeviceCapability)
{
    NTSTATUS Status;

    DPRINT("PciQueryCapabilities: %p, %p\n", PdoExtension, DeviceCapability);

    /* A PDO ID is never unique, and its address is its function and device */
    DeviceCapability->UniqueID = FALSE;
    DeviceCapability->Address = (PdoExtension->Slot.u.bits.FunctionNumber | (PdoExtension->Slot.u.bits.DeviceNumber << 16));

    /* Check for host bridges */
    if (PdoExtension->BaseClass == PCI_CLASS_BRIDGE_DEV && PdoExtension->SubClass == PCI_SUBCLASS_BR_HOST)
        /* Raw device opens to a host bridge are acceptable */
        DeviceCapability->RawDeviceOK = TRUE;
    else
        /* Otherwise, other PDOs cannot be directly opened */
        DeviceCapability->RawDeviceOK = FALSE;

    /* PCI PDOs are pretty fixed things */
    DeviceCapability->LockSupported = FALSE;
    DeviceCapability->EjectSupported = FALSE;
    DeviceCapability->Removable = FALSE;
    DeviceCapability->DockDevice = FALSE;

    /* The slot number is stored as a device property, go query it */
    PciDetermineSlotNumber(PdoExtension, &DeviceCapability->UINumber);

    /* Finally, query and power capabilities and convert them for PnP usage */
    Status = PciQueryPowerCapabilities(PdoExtension, DeviceCapability);

    /* Dump the capabilities if it all worked, and return the status */
    if (NT_SUCCESS(Status))
        PciDebugDumpQueryCapabilities(DeviceCapability);

    return Status;
}

/* EOF */
