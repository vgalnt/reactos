/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/pci/id.c
 * PURPOSE:         PCI Device Identification
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include <pci.h>
#include <stdio.h>

//#define NDEBUG
#include <debug.h>

/* FUNCTIONS ******************************************************************/

PWCHAR
NTAPI
PciGetDescriptionMessage(
    _In_ ULONG Identifier,
    _Out_ ULONG* OutLength)
{
    PMESSAGE_RESOURCE_ENTRY Entry;
    ANSI_STRING MessageString;
    UNICODE_STRING UnicodeString;
    PWCHAR Description;
    PWCHAR Buffer;
    ULONG TextLength;
    NTSTATUS Status;

    DPRINT("PciGetDescriptionMessage: %X\n", Identifier);

    /* Find the message identifier in the message table */
    MessageString.Buffer = NULL;

    Status = RtlFindMessage(PciDriverObject->DriverStart,
                            11, // RT_MESSAGETABLE
                            LANG_NEUTRAL,
                            Identifier,
                            &Entry);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("PciGetDescriptionMessage: Status %X\n", Status);
        return NULL;
    }

    /* Check if the resource data is Unicode or ANSI */
    if (Entry->Flags & MESSAGE_RESOURCE_UNICODE)
    {
        /* Subtract one space for the end-of-message terminator */
        TextLength = (Entry->Length - FIELD_OFFSET(MESSAGE_RESOURCE_ENTRY, Text) - 2 * sizeof(WCHAR));

        /* Grab the text */
        Description = (PWCHAR)Entry->Text;
        if (!Description[TextLength / sizeof(WCHAR)])
            TextLength -= sizeof(WCHAR);

        /* Validate valid message length, ending with a newline character */
        ASSERT(TextLength > 1);
        ASSERT(Description[TextLength / sizeof(WCHAR)] == L'\n');

        /* Allocate the buffer to hold the message string */
        Buffer = ExAllocatePoolWithTag(PagedPool, TextLength, 'BicP');
        if (!Buffer)
        {
            DPRINT1("PciGetDescriptionMessage: allocate failed\n");
            return NULL;
        }

        /* Copy the message, minus the newline character, and terminate it */
        RtlCopyMemory(Buffer, Entry->Text, (TextLength - sizeof(WCHAR)));
        Buffer[TextLength / sizeof(WCHAR) - 1] = UNICODE_NULL;

        /* Return the length to the caller, minus the terminating NULL */
        if (OutLength)
            *OutLength = (TextLength - 1);
    }
    else
    {
        /* Initialize the entry as a string */
        RtlInitAnsiString(&MessageString, (PCHAR)Entry->Text);

        /* Remove the newline character */
        MessageString.Length -= sizeof(CHAR);

        /* Convert it to Unicode */
        RtlAnsiStringToUnicodeString(&UnicodeString, &MessageString, TRUE);
        Buffer = UnicodeString.Buffer;

        /* Return the length to the caller */
        if (OutLength)
            *OutLength = UnicodeString.Length;
    }

    /* Return the message buffer to the caller */
    return Buffer;
}

PWCHAR
NTAPI
PciGetDeviceDescriptionMessage(IN UCHAR BaseClass,
                               IN UCHAR SubClass)
{
    PWCHAR Message;
    ULONG Identifier;

    /* The message identifier in the table is encoded based on the PCI class */
    Identifier = (BaseClass << 8) | SubClass;

    /* Go grab the description message for this device */
    Message = PciGetDescriptionMessage(Identifier, NULL);
    if (!Message)
    {
        /* It wasn't found, allocate a buffer for a generic description */
        Message = ExAllocatePoolWithTag(PagedPool, sizeof(L"PCI Device"), 'bicP');
        if (Message) RtlCopyMemory(Message, L"PCI Device", sizeof(L"PCI Device"));
    }

    /* Return the description message */
    return Message;
}

VOID
NTAPI
PciInitIdBuffer(IN PPCI_ID_BUFFER IdBuffer)
{
    /* Initialize the sizes to zero and the pointer to the start of the buffer */
    IdBuffer->TotalLength = 0;
    IdBuffer->Count = 0;
    IdBuffer->CharBuffer = IdBuffer->BufferData;
}

ULONG
__cdecl
PciIdPrintf(IN PPCI_ID_BUFFER IdBuffer,
            IN PCCH Format,
            ...)
{
    ULONG Size, Length;
    PANSI_STRING AnsiString;
    va_list va;

    ASSERT(IdBuffer->Count < MAX_ANSI_STRINGS);
 
    /* Do the actual string formatting into the character buffer */
    va_start(va, Format);
    vsprintf(IdBuffer->CharBuffer, Format, va);
    va_end(va);

    /* Initialize the ANSI_STRING that will hold this string buffer */
    AnsiString = &IdBuffer->Strings[IdBuffer->Count];
    RtlInitAnsiString(AnsiString, IdBuffer->CharBuffer);
    
    /* Calculate the final size of the string, in Unicode */
    Size = RtlAnsiStringToUnicodeSize(AnsiString);
 
    /* Update hte buffer with the size,and update the character pointer */
    IdBuffer->StringSize[IdBuffer->Count] = Size;
    IdBuffer->TotalLength += Size;
    Length = AnsiString->Length + sizeof(ANSI_NULL);
    IdBuffer->CharBuffer += Length;
    
    /* Move to the next string for next time */
    IdBuffer->Count++;
    
    /* Return the length */
    return Length;
}

ULONG
__cdecl
PciIdPrintfAppend(IN PPCI_ID_BUFFER IdBuffer,
                  IN PCCH Format,
                  ...)
{
    ULONG NextId, Size, Length, MaxLength;
    PANSI_STRING AnsiString;
    va_list va;

    ASSERT(IdBuffer->Count);
  
    /* Choose the next static ANSI_STRING to use */
    NextId = IdBuffer->Count - 1;
  
    /* Max length is from the end of the buffer up until the current pointer */
    MaxLength = (PCHAR)(IdBuffer + 1) - IdBuffer->CharBuffer; 
    
    /* Do the actual append, and return the length this string took */
    va_start(va, Format);
    Length = vsprintf(IdBuffer->CharBuffer - 1, Format, va);
    va_end(va);
    ASSERT(Length < MaxLength);

    /* Select the static ANSI_STRING, and update its length information */
    AnsiString = &IdBuffer->Strings[NextId];
    AnsiString->Length += Length;
    AnsiString->MaximumLength += Length;
  
    /* Calculate the final size of the string, in Unicode */
    Size = RtlAnsiStringToUnicodeSize(AnsiString);
  
    /* Update the buffer with the size, and update the character pointer */
    IdBuffer->StringSize[NextId] = Size;
    IdBuffer->TotalLength += Size;
    IdBuffer->CharBuffer += Length;
    
    /* Return the size */
    return Size;
}

NTSTATUS
NTAPI
PciQueryId(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ BUS_QUERY_ID_TYPE QueryType,
    _Out_ PWCHAR* OutId)
{
    PPCI_FDO_EXTENSION ParentFdoExtension;
    PPCI_PDO_EXTENSION ParentPdoExtension;
    UNICODE_STRING DestinationString;
    PANSI_STRING NextString;
    PCI_ID_BUFFER IdBuffer;
    CHAR VendorString[22];
    PWCHAR StringBuffer;
    ULONG SubsysId;
    ULONG Size;
    ULONG ix;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();
    DPRINT("PciQueryId: %p, %X\n", PdoExtension, QueryType);

    /* Assume failure */
    *OutId = NULL;

    /* Start with the genric vendor string, which is the vendor ID + device ID */
    sprintf(VendorString, "PCI\\VEN_%04X&DEV_%04X", PdoExtension->VendorId, PdoExtension->DeviceId);

    /* Initialize the PCI ID Buffer */
    PciInitIdBuffer(&IdBuffer);

    /* Build the subsystem ID as shown in PCI ID Strings */
    SubsysId = (PdoExtension->SubsystemVendorId | (PdoExtension->SubsystemId << 16));

    /* Check what the caller is requesting */
    switch (QueryType)
    {
        case BusQueryDeviceID:
        {
            /* A single ID, the vendor string + the revision ID */
            PciIdPrintf(&IdBuffer, "%s&SUBSYS_%08X&REV_%02X", VendorString, SubsysId, PdoExtension->RevisionId);
            break;
        }
        case BusQueryHardwareIDs:
        {
            /* First the vendor string + the subsystem ID + the revision ID */
            PciIdPrintf(&IdBuffer, "%s&SUBSYS_%08X&REV_%02X", VendorString, SubsysId, PdoExtension->RevisionId);

            /* Next, without the revision */
            PciIdPrintf(&IdBuffer, "%s&SUBSYS_%08X", VendorString, SubsysId);

            /* Next, the vendor string + the base class + sub class + progif */
            PciIdPrintf(&IdBuffer, "%s&CC_%02X%02X%02X",
                        VendorString, PdoExtension->BaseClass, PdoExtension->SubClass, PdoExtension->ProgIf);

            /* Next, without the progif */
            PciIdPrintf(&IdBuffer, "%s&CC_%02X%02X", VendorString, PdoExtension->BaseClass, PdoExtension->SubClass);

            /* And finally, a terminator */
            PciIdPrintf(&IdBuffer, "\0");
            break;
        }
        case BusQueryCompatibleIDs:
        {
            /* First, the vendor + revision ID only */
            PciIdPrintf(&IdBuffer, "%s&REV_%02X", VendorString, PdoExtension->RevisionId);

            /* Next, the vendor string alone */
            PciIdPrintf(&IdBuffer, "%s", VendorString);

            /* Next, the vendor ID + the base class + the sub class + progif */
            PciIdPrintf(&IdBuffer, "PCI\\VEN_%04X&CC_%02X%02X%02X",
                        PdoExtension->VendorId, PdoExtension->BaseClass, PdoExtension->SubClass, PdoExtension->ProgIf);

            /* Now without the progif */
            PciIdPrintf(&IdBuffer, "PCI\\VEN_%04X&CC_%02X%02X",
                        PdoExtension->VendorId, PdoExtension->BaseClass, PdoExtension->SubClass);

            /* And then just the vendor ID itself */
            PciIdPrintf(&IdBuffer, "PCI\\VEN_%04X", PdoExtension->VendorId);

            /* Then the base class + subclass + progif, without any vendor */
            PciIdPrintf(&IdBuffer, "PCI\\CC_%02X%02X%02X",
                        PdoExtension->BaseClass, PdoExtension->SubClass, PdoExtension->ProgIf);

            /* Next, without the progif */
            PciIdPrintf(&IdBuffer, "PCI\\CC_%02X%02X", PdoExtension->BaseClass, PdoExtension->SubClass);

            /* And finally, a terminator */
            PciIdPrintf(&IdBuffer, "\0");
            break;
        }
        case BusQueryInstanceID:
        {
            /* Start with a terminator */
            PciIdPrintf(&IdBuffer, "\0");

            /* And then encode the device and function number */
            PciIdPrintfAppend(&IdBuffer, "%02X",
                              ((PdoExtension->Slot.u.bits.DeviceNumber << 3) | PdoExtension->Slot.u.bits.FunctionNumber));

            /* Loop every parent until the root */
            ParentFdoExtension = PdoExtension->ParentFdoExtension;
            while (!PCI_IS_ROOT_FDO(ParentFdoExtension))
            {
                /* And encode the parent's device and function number as well */
                ParentPdoExtension = ParentFdoExtension->PhysicalDeviceObject->DeviceExtension;

                PciIdPrintfAppend(&IdBuffer, "%02X",
                                  (ParentPdoExtension->Slot.u.bits.DeviceNumber << 3) |
                                   ParentPdoExtension->Slot.u.bits.FunctionNumber);
            }
            break;
        }
        default:
        {
            /* Unknown query type */
            DPRINT1("PciQueryId: PciQueryId expected ID type %X\n", QueryType);
            return STATUS_NOT_SUPPORTED;
        }
    }

    /* Something should've been generated if this has been reached */
    ASSERT(IdBuffer.Count > 0);

    /* Allocate the final string buffer to hold the ID */
    StringBuffer = ExAllocatePoolWithTag(PagedPool, IdBuffer.TotalLength, 'BicP');
    if (!StringBuffer)
    {
        DPRINT1("PciQueryId: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Build the UNICODE_STRING structure for it */
    DPRINT1("PciQueryId: QueryType %X\n", QueryType);

    DestinationString.Buffer = StringBuffer;
    DestinationString.MaximumLength = IdBuffer.TotalLength;

    /* Loop every ID in the buffer */
    for (ix = 0; ix < IdBuffer.Count; ix++)
    {
        /* Select the ANSI_STRING for the ID */
        NextString = &IdBuffer.Strings[ix];

        DPRINT1("'%s'\n", NextString->Buffer);

        /* Convert it to a UNICODE_STRING */
        Status = RtlAnsiStringToUnicodeString(&DestinationString, NextString, FALSE);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("PciQueryId: Status %X\n", Status);
            ASSERT(NT_SUCCESS(Status));
        }

        /* Add it into the final destination buffer */
        Size = IdBuffer.StringSize[ix];
        DestinationString.MaximumLength -= Size;
        DestinationString.Buffer += (Size / sizeof(WCHAR));
    }

    /* Return the buffer to the caller and return status (should be success) */
    *OutId = StringBuffer;

    return Status;
}

NTSTATUS
NTAPI
PciQueryDeviceText(
    _In_ PPCI_PDO_EXTENSION PdoExtension,
    _In_ DEVICE_TEXT_TYPE QueryType,
    _In_ ULONG Locale,
    _Out_ PWCHAR* OutDeviceText)
{
    PWCHAR MessageBuffer;
    PWCHAR LocationBuffer;
    ULONG Length;
    NTSTATUS Status;

    DPRINT("PciQueryId: %p, %X, %X\n", PdoExtension, QueryType, Locale);

    /* Check what the caller is requesting */
    switch (QueryType)
    {
        case DeviceTextDescription:
        {
            /* Get the message from the resource section */
            MessageBuffer = PciGetDeviceDescriptionMessage(PdoExtension->BaseClass, PdoExtension->SubClass);

            /* Return it to the caller, and select proper status code */
            *OutDeviceText = MessageBuffer;

            Status = (MessageBuffer ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED);
            break;
        }
        case DeviceTextLocationInformation:
        {
            /* Get the message from the resource section */
            MessageBuffer = PciGetDescriptionMessage(0x10000, &Length);
            if (!MessageBuffer)
            {
                /* It should be there, but fail if it wasn't found for some reason */
                Status = STATUS_NOT_SUPPORTED;
                break;
            }

            /* Add space for a null-terminator, and allocate the buffer */
            Length += (2 * sizeof(UNICODE_NULL));

            *OutDeviceText = LocationBuffer = ExAllocatePoolWithTag(PagedPool, Length * sizeof(WCHAR), 'BicP');

            /* Check if the allocation succeeded */
            if (LocationBuffer)
            {
                /* Build the location string based on bus, function, and device */
                swprintf(LocationBuffer, MessageBuffer, PdoExtension->ParentFdoExtension->BaseBus,
                         PdoExtension->Slot.u.bits.FunctionNumber, PdoExtension->Slot.u.bits.DeviceNumber);
            }

            /* Free the original string from the resource section */
            ExFreePool(MessageBuffer);

            /* Select the correct status */
            Status = (LocationBuffer ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES);
            break;
        }
        default:
        {
            /* Anything else is unsupported */
            DPRINT1("PciQueryId: unsupported QueryType %X\n", QueryType);
            Status = STATUS_NOT_SUPPORTED;
            break;
        }
    }

    /* Return whether or not a device text string was indeed found */
    return Status;
}

/* EOF */
