/*
* PROJECT:         ReactOS Kernel
* LICENSE:         GPL - See COPYING in the top level directory
* FILE:            ntoskrnl/fstub/disksup.c
* PURPOSE:         I/O HAL Routines for Disk Access
* PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
*                  Eric Kohl
*                  Casper S. Hornstrup (chorns@users.sourceforge.net)
*/

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#include <internal/hal.h>
#define NDEBUG
#include <debug.h>

#define EFI_PMBR_OSTYPE_EFI 0xEE

extern BOOLEAN IoRemoteBootClient;

/* PRIVATE FUNCTIONS *********************************************************/

NTSTATUS
NTAPI
HalpGetFullGeometry(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PDISK_GEOMETRY Geometry,
    _Out_ PULONGLONG RealSectorCount)
{
    PARTITION_INFORMATION PartitionInfo;
    IO_STATUS_BLOCK IoStatusBlock;
    PKEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    PAGED_CODE();

    Event = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Event), TAG_FILE_SYSTEM);
    if (!Event)
    {
        DPRINT1("HalpGetFullGeometry: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeEvent(Event, NotificationEvent, FALSE);

    /* Build the IRP */
    Irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_DRIVE_GEOMETRY,
                                        DeviceObject,
                                        NULL,
                                        0UL,
                                        Geometry,
                                        sizeof(*Geometry),
                                        FALSE,
                                        Event,
                                        &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("HalpGetFullGeometry: STATUS_INSUFFICIENT_RESOURCES\n");
        ExFreePoolWithTag(Event, TAG_FILE_SYSTEM);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpGetFullGeometry: Status %X\n", Status);
        goto Exit;
    }

    /* Build another IRP */
    Irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_PARTITION_INFO,
                                        DeviceObject,
                                        NULL,
                                        0UL,
                                        &PartitionInfo,
                                        sizeof(PartitionInfo),
                                        FALSE,
                                        Event,
                                        &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("HalpGetFullGeometry: STATUS_INSUFFICIENT_RESOURCES\n");
        ExFreePoolWithTag(Event, TAG_FILE_SYSTEM);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Reset event */
    KeClearEvent(Event);

    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpGetFullGeometry: Status %X\n", Status);
        goto Exit;
    }

    /* Get the number of sectors */
    *RealSectorCount = (PartitionInfo.PartitionLength.QuadPart / Geometry->BytesPerSector);

Exit:
    ExFreePoolWithTag(Event, TAG_FILE_SYSTEM);
    return Status;
}

BOOLEAN
NTAPI
HalpIsValidPartitionEntry(
    _In_ PPARTITION_DESCRIPTOR Entry,
    _In_ ULONGLONG MaxOffset,
    _In_ ULONGLONG MaxSector)
{
    ULONGLONG EndingSector;

    PAGED_CODE();

    /* Unused partitions are considered valid */
    if (Entry->PartitionType == PARTITION_ENTRY_UNUSED)
        return TRUE;

    /* Get the last sector of the partition */
    EndingSector = (GET_STARTING_SECTOR(Entry) +  GET_PARTITION_LENGTH(Entry));

    /* Check if it's more then the maximum sector */
    if (EndingSector > MaxSector)
    {
        DPRINT1("HalpIsValidPartitionEntry: entry is invalid\n");
        goto ErrorExit;
    }

    if (GET_STARTING_SECTOR(Entry) <= MaxOffset)
        return TRUE;

    DPRINT1("HalpIsValidPartitionEntry: entry is invalid\n");

ErrorExit:

    DPRINT1("HalpIsValidPartitionEntry: offset %X, len %X, end %I64X, max %I64X\n",
            GET_STARTING_SECTOR(Entry), GET_PARTITION_LENGTH(Entry), EndingSector, MaxSector);

    return FALSE;
}

VOID
NTAPI
HalpCalculateChsValues(
    _In_ PLARGE_INTEGER PartitionOffset,
    _In_ PLARGE_INTEGER PartitionLength,
    _In_ CCHAR ShiftCount,
    _In_ ULONG SectorsPerTrack,
    _In_ ULONG NumberOfTracks,
    _In_ ULONG ConventionalCylinders,
    _Out_ PPARTITION_DESCRIPTOR PartitionDescriptor)
{
    LARGE_INTEGER FirstSector, SectorCount;
    ULONG LastSector, Remainder, SectorsPerCylinder;
    ULONG StartingCylinder, EndingCylinder;
    ULONG StartingTrack, EndingTrack;
    ULONG StartingSector, EndingSector;

    PAGED_CODE();

    /* Calculate the number of sectors for each cylinder */
    SectorsPerCylinder = (SectorsPerTrack * NumberOfTracks);

    FirstSector.QuadPart = (PartitionOffset->QuadPart >> ShiftCount);
    SectorCount.QuadPart = (PartitionLength->QuadPart >> ShiftCount);

    LastSector = (FirstSector.LowPart + SectorCount.LowPart - 1);

    StartingCylinder = (FirstSector.LowPart / SectorsPerCylinder);
    EndingCylinder = (LastSector / SectorsPerCylinder);

    if (!ConventionalCylinders)
        ConventionalCylinders = 0x400;

    if (StartingCylinder >= ConventionalCylinders)
        StartingCylinder = (ConventionalCylinders - 1);

    if (EndingCylinder >= ConventionalCylinders)
        EndingCylinder = (ConventionalCylinders - 1);

    /* Calculate the starting head and sector that still remain */
    Remainder = (FirstSector.LowPart % SectorsPerCylinder);
    StartingTrack = (Remainder / SectorsPerTrack);
    StartingSector = (Remainder % SectorsPerTrack);

    /* Calculate the ending head and sector that still remain */
    Remainder = (LastSector % SectorsPerCylinder);
    EndingTrack = (Remainder / SectorsPerTrack);
    EndingSector = (Remainder % SectorsPerTrack);

    /* Set cylinder data for the MSB */
    PartitionDescriptor->StartingCylinderMsb = (UCHAR)StartingCylinder;
    PartitionDescriptor->EndingCylinderMsb = (UCHAR)EndingCylinder;

    /* Set the track data */
    PartitionDescriptor->StartingTrack = (UCHAR)StartingTrack;
    PartitionDescriptor->EndingTrack = (UCHAR)EndingTrack;

    /* Update cylinder data for the LSB */
    StartingCylinder = (((StartingSector + 1) & 0x3F) | ((StartingCylinder >> 2) & 0xC0));
    EndingCylinder = (((EndingSector + 1) & 0x3F) | ((EndingCylinder >> 2) & 0xC0));

    /* Set the cylinder data for the LSB */
    PartitionDescriptor->StartingCylinderLsb = (UCHAR)StartingCylinder;
    PartitionDescriptor->EndingCylinderLsb = (UCHAR)EndingCylinder;
}

VOID
FASTCALL
xHalGetPartialGeometry(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PULONG ConventionalCylinders,
    _In_ PLONGLONG DiskSize)
{
    PDISK_GEOMETRY DiskGeometry = NULL;
    PIO_STATUS_BLOCK IoStatusBlock = NULL;
    PKEVENT Event = NULL;
    PIRP Irp;
    NTSTATUS Status;

    *ConventionalCylinders = 0;
    *DiskSize = 0;

    DiskGeometry = ExAllocatePoolWithTag(NonPagedPool, sizeof(*DiskGeometry), TAG_FILE_SYSTEM);
    if (!DiskGeometry)
    {
        DPRINT1("xHalGetPartialGeometry: Allocate failed\n");
        goto Cleanup;
    }

    IoStatusBlock = ExAllocatePoolWithTag(NonPagedPool, sizeof(*IoStatusBlock), TAG_FILE_SYSTEM);
    if (!IoStatusBlock)
    {
        DPRINT1("xHalGetPartialGeometry: Allocate failed\n");
        goto Cleanup;
    }

    Event = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Event), TAG_FILE_SYSTEM);
    if (!Event)
    {
        DPRINT1("xHalGetPartialGeometry: Allocate failed\n");
        goto Cleanup;
    }

    KeInitializeEvent(Event, NotificationEvent, FALSE);

    Irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_DRIVE_GEOMETRY,
                                        DeviceObject,
                                        NULL,
                                        0,
                                        DiskGeometry,
                                        sizeof(*DiskGeometry),
                                        FALSE,
                                        Event,
                                        IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("xHalGetPartialGeometry: Build failed\n");
        goto Cleanup;
    }

    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock->Status;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("xHalGetPartialGeometry: Status %X\n", Status);
        goto Cleanup;
    }

    /* Return the cylinder count */
    *ConventionalCylinders = DiskGeometry->Cylinders.LowPart;

    if (DiskGeometry->Cylinders.LowPart >= 0x400)
        *ConventionalCylinders = 0x400;

    /* Calculate the disk size */
    *DiskSize = DiskGeometry->Cylinders.QuadPart *
                DiskGeometry->TracksPerCylinder *
                DiskGeometry->SectorsPerTrack *
                DiskGeometry->BytesPerSector;

Cleanup:

    if (Event)
        ExFreePoolWithTag(Event, TAG_FILE_SYSTEM);

    if (IoStatusBlock)
        ExFreePoolWithTag(IoStatusBlock, TAG_FILE_SYSTEM);

    if (DiskGeometry)
        ExFreePoolWithTag(DiskGeometry, TAG_FILE_SYSTEM);

    return;
}

VOID
NTAPI
FstubFixupEfiPartition(
    _In_ PPARTITION_DESCRIPTOR PartitionDescriptor,
    _In_ ULONGLONG MaxOffset)
{
    ULONG PartitionMaxOffset;
    ULONG PartitionLength;

    PAGED_CODE();

    /* Compute partition length (according to MBR entry) */
    PartitionMaxOffset = (GET_STARTING_SECTOR(PartitionDescriptor) + GET_PARTITION_LENGTH(PartitionDescriptor));

    /* In case the partition length goes beyond disk size... */
    if (PartitionMaxOffset > MaxOffset)
    {
        /* Resize partition to its maximum real length */
        PartitionLength = (ULONG)(PartitionMaxOffset - GET_STARTING_SECTOR(PartitionDescriptor));
        SET_PARTITION_LENGTH(PartitionDescriptor, PartitionLength);
    }
}

/* PUBLIC FUNCTIONS **********************************************************/

VOID
FASTCALL
HalExamineMBR(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG SectorSize,
    _In_ ULONG MbrTypeIdentifier,
    _Out_ PVOID* MbrBuffer)
{
    PPARTITION_DESCRIPTOR PartitionDescriptor;
    PIO_STACK_LOCATION IoStackLocation;
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER Offset;
    PUCHAR Buffer;
    KEVENT Event;
    PIRP Irp;
    ULONG BufferSize;
    NTSTATUS Status;

    *MbrBuffer = NULL;

    BufferSize = max(SectorSize, 0x200);
    BufferSize = (PAGE_SIZE > BufferSize ? PAGE_SIZE : BufferSize);

    Buffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize, TAG_FILE_SYSTEM);
    if (!Buffer)
    {
        DPRINT1("HalExamineMBR: Allocate failed\n");
        return;
    }

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Offset.QuadPart = 0;

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ,
                                       DeviceObject,
                                       Buffer,
                                       BufferSize,
                                       &Offset,
                                       &Event,
                                       &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("HalExamineMBR: Build failed\n");
        ExFreePoolWithTag(Buffer, TAG_FILE_SYSTEM);
        return;
    }

    /* Make sure to override volume verification */
    IoStackLocation = IoGetNextIrpStackLocation(Irp);
    IoStackLocation->Flags |= SL_OVERRIDE_VERIFY_VOLUME;

    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalExamineMBR: Status %X\n", Status);
        return;
    }

    /* Validate the MBR Signature */
    if (((PUSHORT)Buffer)[BOOT_SIGNATURE_OFFSET] != BOOT_RECORD_SIGNATURE)
    {
        DPRINT1("HalExamineMBR: Signature %X\n", ((PUSHORT)Buffer)[BOOT_SIGNATURE_OFFSET]);
        ExFreePoolWithTag(Buffer, TAG_FILE_SYSTEM);
        return;
    }

    /* Get the partition entry */
    PartitionDescriptor = (PPARTITION_DESCRIPTOR)&(((PUSHORT)Buffer)[PARTITION_TABLE_OFFSET]);

    /* Make sure it's what the caller wanted */
    if (PartitionDescriptor->PartitionType != MbrTypeIdentifier)
    {
        DPRINT1("HalExamineMBR: PartitionDescriptor->PartitionType %X\n", PartitionDescriptor->PartitionType);
        ExFreePoolWithTag(Buffer, TAG_FILE_SYSTEM);
        return;
    }

    /* Check if this is a secondary entry */
    if (PartitionDescriptor->PartitionType == 0x54)
    {
        /* Return our buffer, but at sector 63 */
        *(PULONG)Buffer = 63;
        *MbrBuffer = Buffer;
    }
    else if (PartitionDescriptor->PartitionType == 0x55)
    {
        /* EZ Drive, return the buffer directly */
        *MbrBuffer = Buffer;
    }
    else
    {
        /* Otherwise crash on debug builds */
        ASSERT(PartitionDescriptor->PartitionType == 0x55);
    }
}

NTSTATUS
FASTCALL
IoReadPartitionTable(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG SectorSize,
    _In_ BOOLEAN ReturnRecognizedPartitions,
    _Inout_ PDRIVE_LAYOUT_INFORMATION* PartitionBuffer)
{
    PDRIVE_LAYOUT_INFORMATION DriveLayoutInfo = NULL;
    PPARTITION_DESCRIPTOR PartitionDescriptor;
    PPARTITION_INFORMATION PartitionInfo;
    PIO_STACK_LOCATION IoStackLocation;
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER HiddenSectors64;
    DISK_GEOMETRY DiskGeometry;
    PUCHAR Buffer = NULL;
    LONGLONG EndSector;
    LONGLONG MaxSector;
    LONGLONG StartOffset;
    ULONGLONG MaxOffset;
    LARGE_INTEGER Offset;
    LARGE_INTEGER VolumeOffset;
    PVOID MbrBuffer;
    KEVENT Event;
    PIRP Irp;
    ULONG BufferSize = 0x800;
    ULONG InputSize;
    LONG jx = -1;
    LONG ix = -1;
    LONG kx;
    BOOLEAN IsPrimary = TRUE;
    BOOLEAN IsEzDrive = FALSE;
    BOOLEAN MbrFound = FALSE;
    BOOLEAN IsValid;
    BOOLEAN IsEmpty = TRUE;
    UCHAR PartitionType;
    CCHAR Entry;
    NTSTATUS Status;

    DPRINT1("IoReadPartitionTable: DeviceObject %p\n", DeviceObject);
    PAGED_CODE();

    *PartitionBuffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize, TAG_FILE_SYSTEM);
    if (!(*PartitionBuffer))
    {
        DPRINT1("IoReadPartitionTable: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    InputSize = max(0x200, SectorSize);

    VolumeOffset.QuadPart = 0;
    Offset.QuadPart = 0;

    /* Check for EZ Drive */
    HalExamineMBR(DeviceObject, InputSize, 0x55, &MbrBuffer);
    if (MbrBuffer)
    {
        /* EZ Drive found, bias the offset */
        IsEzDrive = TRUE;
        ExFreePoolWithTag(MbrBuffer, TAG_FILE_SYSTEM);
        Offset.QuadPart = 0x200;
    }

    Status = HalpGetFullGeometry(DeviceObject, &DiskGeometry, &MaxOffset);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IoReadPartitionTable: Status %X\n", Status);
        ExFreePoolWithTag(*PartitionBuffer, TAG_FILE_SYSTEM);
        *PartitionBuffer = NULL;
        return Status;
    }

    EndSector = MaxOffset;
    MaxSector = (MaxOffset << 1);

    DPRINT("IoReadPartitionTable: MaxOffset %I64X, MaxSector %I64X\n", MaxOffset, MaxSector);

    Buffer = ExAllocatePoolWithTag(NonPagedPool, InputSize, TAG_FILE_SYSTEM);
    if (!Buffer)
    {
        DPRINT1("IoReadPartitionTable: STATUS_INSUFFICIENT_RESOURCES\n");
        ExFreePoolWithTag(*PartitionBuffer, TAG_FILE_SYSTEM);
        *PartitionBuffer = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Start partition loop */
    do
    {
        IsValid = TRUE;

        KeInitializeEvent(&Event, NotificationEvent, FALSE);
        RtlZeroMemory(Buffer, InputSize);

        Irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ,
                                           DeviceObject,
                                           Buffer,
                                           InputSize,
                                           &Offset,
                                           &Event,
                                           &IoStatusBlock);
        if (!Irp)
        {
            DPRINT1("IoReadPartitionTable: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        /* Make sure to disable volume verification */
        IoStackLocation = IoGetNextIrpStackLocation(Irp);
        IoStackLocation->Flags |= SL_OVERRIDE_VERIFY_VOLUME;

        Status = IoCallDriver(DeviceObject, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoStatusBlock.Status;
        }

        /* Normalize status code and check for failure */
        if (Status == STATUS_NO_DATA_DETECTED)
            Status = STATUS_SUCCESS;

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("IoReadPartitionTable: Status %X\n", Status);
            break;
        }

        /* If we biased for EZ-Drive, unbias now */
        if (IsEzDrive && (Offset.QuadPart == 0x200))
            Offset.QuadPart = 0;

        /* Make sure this is a valid MBR */
        if (((PUSHORT)Buffer)[BOOT_SIGNATURE_OFFSET] != BOOT_RECORD_SIGNATURE)
        {
            /* It's not, fail */
            DPRINT1("IoReadPartitionTable: 0xaa55 not found in %X\n", (jx + 1));
            break;
        }

        /* At this point we have a valid MBR */
        MbrFound = TRUE;

        /* Check if we weren't given an offset */
        if (!Offset.QuadPart)
        {
            /* Then read the signature off the disk */
            (*PartitionBuffer)->Signature = ((PULONG)Buffer)[PARTITION_TABLE_OFFSET / 2 - 1];
        }

        /* Get the partition descriptor array */
        PartitionDescriptor = (PPARTITION_DESCRIPTOR)&(((PUSHORT)Buffer)[PARTITION_TABLE_OFFSET]);

        /* Start looping partitions */
        jx++;

        DPRINT("IoReadPartitionTable: Partition Table %X\n", jx);

        for (Entry = 1, kx = 0; Entry <= 4; Entry++, PartitionDescriptor++)
        {
            PartitionType = PartitionDescriptor->PartitionType;

            DPRINT("IoReadPartitionTable: [%X] Entry %X, Type %X (%s)\n",
                    jx, Entry, PartitionType, (PartitionDescriptor->ActiveFlag ? "Active" : ""));

            DPRINT("IoReadPartitionTable: Offset %X for %X Sectors\n",
                   GET_STARTING_SECTOR(PartitionDescriptor), GET_PARTITION_LENGTH(PartitionDescriptor));

            /* Check whether we're facing a protective MBR */
            if (PartitionType == EFI_PMBR_OSTYPE_EFI)
            {
                /* Partition length might be bigger than disk size */
                FstubFixupEfiPartition(PartitionDescriptor, MaxOffset);
            }

            /* Make sure that the partition is valid, unless it's the first */
            if (!(HalpIsValidPartitionEntry(PartitionDescriptor, MaxOffset, MaxSector)) && !jx)
            {
                /* It's invalid, so fail */
                IsValid = FALSE;
                break;
            }

            /* Check if it's a container */
            if (IsContainerPartition(PartitionType))
            {
                /* Increase the count of containers */
                if (++kx != 1)
                {
                    /* More then one table is invalid */
                    DPRINT1("IoReadPartitionTable: Multiple container partitions in %X\n", jx);
                    IsValid = FALSE;
                    break;
                }
            }

            /* Check if the partition is supposedly empty */
            if (IsEmpty)
            {
                /* But check if it actually has a start and/or length */
                if ((GET_STARTING_SECTOR(PartitionDescriptor)) ||
                    (GET_PARTITION_LENGTH(PartitionDescriptor)))
                {
                    /* So then it's not really empty */
                    IsEmpty = FALSE;
                }
            }

            /* Check if the caller wanted only recognized partitions */
            if (ReturnRecognizedPartitions)
            {
                /* Then check if this one is unused, or a container */
                if ((PartitionType == PARTITION_ENTRY_UNUSED) ||
                    IsContainerPartition(PartitionType))
                {
                    /* Skip it, since the caller doesn't want it */
                    continue;
                }
            }

            /* Increase the structure count and check if they can fit */
            if ((sizeof(DRIVE_LAYOUT_INFORMATION) + (++ix * sizeof(PARTITION_INFORMATION))) > BufferSize)
            {
                /* Allocate a new buffer that's twice as big */
                DriveLayoutInfo = ExAllocatePoolWithTag(NonPagedPool, (BufferSize * 2), TAG_FILE_SYSTEM);
                if (!DriveLayoutInfo)
                {
                    DPRINT1("IoReadPartitionTable: STATUS_INSUFFICIENT_RESOURCES\n");
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    ix--;
                    break;
                }

                /* Copy the contents of the old buffer */
                RtlMoveMemory(DriveLayoutInfo, *PartitionBuffer, BufferSize);

                /* Free the old buffer and set this one as the new one */
                ExFreePoolWithTag(*PartitionBuffer, TAG_FILE_SYSTEM);
                *PartitionBuffer = DriveLayoutInfo;

                /* Double the size */
                BufferSize *= 2;
            }

            /* Now get the current structure being filled and initialize it */
            PartitionInfo = &(*PartitionBuffer)->PartitionEntry[ix];
            PartitionInfo->PartitionType = PartitionType;
            PartitionInfo->RewritePartition = FALSE;

            /* Check if we're dealing with a partition that's in use */
            if (PartitionType == PARTITION_ENTRY_UNUSED)
            {
                /* Otherwise, clear all the relevant fields */
                PartitionInfo->BootIndicator = FALSE;
                PartitionInfo->RecognizedPartition = FALSE;
                PartitionInfo->StartingOffset.QuadPart = 0;
                PartitionInfo->PartitionLength.QuadPart = 0;
                PartitionInfo->HiddenSectors = 0;
                PartitionInfo->PartitionNumber = 0;

                continue;
            }

            /* Check if it's bootable */
            PartitionInfo->BootIndicator = (PartitionDescriptor->ActiveFlag & 0x80 ? TRUE : FALSE);

            /* Check if its' a container */
            if (IsContainerPartition(PartitionType))
            {
                /* Then don't recognize it and use the volume offset */
                PartitionInfo->RecognizedPartition = FALSE;
                StartOffset = VolumeOffset.QuadPart;
            }
            else
            {
                /* Then recognize it and use the partition offset */
                PartitionInfo->RecognizedPartition = TRUE;
                StartOffset = Offset.QuadPart;
            }

            /* Get the starting offset */
            PartitionInfo->StartingOffset.QuadPart = (StartOffset + UInt32x32To64(GET_STARTING_SECTOR(PartitionDescriptor), SectorSize));

            /* Calculate the number of hidden sectors */
            HiddenSectors64.QuadPart = ((PartitionInfo->StartingOffset.QuadPart - StartOffset) / SectorSize);
            PartitionInfo->HiddenSectors = HiddenSectors64.LowPart;

            /* Get the partition length */
            PartitionInfo->PartitionLength.QuadPart = (UInt32x32To64(GET_PARTITION_LENGTH(PartitionDescriptor), SectorSize));

            /* Get the partition number */
            PartitionInfo->PartitionNumber = ((!IsContainerPartition(PartitionType)) ? (ix + 1) : 0);
        }

        /* Finish debug log, and check for failure */
        DPRINT("\n");

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("IoReadPartitionTable: Status %X\n", Status);
            break;
        }

        /* Also check if we hit an invalid entry here */
        if (!IsValid)
        {
            /* We did, so break out of the loop minus one entry */
            jx--;
            break;
        }

        Offset.QuadPart = 0;

        /* Go back to the descriptor array and loop it */
        PartitionDescriptor = (PPARTITION_DESCRIPTOR)&(((PUSHORT)Buffer)[PARTITION_TABLE_OFFSET]);

        for (Entry = 1; Entry <= 4; Entry++, PartitionDescriptor++)
        {
            /* Check if this is a container partition, since we skipped them */
            if (!IsContainerPartition(PartitionDescriptor->PartitionType))
                continue;

            /* Get its offset */
            Offset.QuadPart = (VolumeOffset.QuadPart + UInt32x32To64(GET_STARTING_SECTOR(PartitionDescriptor), SectorSize));

            /* If this is a primary partition, this is the volume offset */
            if (IsPrimary)
                VolumeOffset = Offset;

            /* Also update the maximum sector */
            MaxSector = GET_PARTITION_LENGTH(PartitionDescriptor);
            DPRINT1("IoReadPartitionTable: MaxSector now %I64X\n", MaxSector);
            break;
        }

        /* Loop the next partitions, which are not primary anymore */
        IsPrimary = FALSE;
    }
    while (Offset.HighPart | Offset.LowPart);

    /* Check if this is a removable device that's probably a super-floppy */
    if ((DiskGeometry.MediaType == RemovableMedia) && !jx && MbrFound && IsEmpty)
    {
        PBOOT_SECTOR_INFO BootSectorInfo = (PBOOT_SECTOR_INFO)Buffer;

        /* Read the jump bytes to detect super-floppy */
        if ((BootSectorInfo->JumpByte[0] == 0xeb) ||
            (BootSectorInfo->JumpByte[0] == 0xe9))
        {
            /* Jump byte found along with empty partition table - disk is a super floppy and has no valid MBR
               Super floppes don't have typical MBRs, so skip them
            */
            DPRINT1("IoReadPartitionTable: JumpByte %#x\n", BootSectorInfo->JumpByte);
            jx = -1;
        }
    }

    /* Check if we're still at partition -1 */
    if (jx == -1)
    {
        /* The likely cause is the super floppy detection above */
        if (MbrFound || (DiskGeometry.MediaType == RemovableMedia))
        {
            /* Print out debugging information */
            DPRINT1("IoReadPartitionTable: DeviceObject %p has no valid MBR.\n", DeviceObject);
            DPRINT1("IoReadPartitionTable: Drive has %I64X sectors and is %#016I64X bytes large\n", EndSector, (EndSector * DiskGeometry.BytesPerSector));

            /* We should at least have some sectors */
            if (EndSector > 0)
            {
                /* Get the entry we'll use */
                PartitionInfo = &(*PartitionBuffer)->PartitionEntry[0];

                /* Fill it out with data for a super-floppy */
                PartitionInfo->RewritePartition = FALSE;
                PartitionInfo->RecognizedPartition = TRUE;
                PartitionInfo->PartitionType = PARTITION_FAT_16;
                PartitionInfo->BootIndicator = FALSE;
                PartitionInfo->HiddenSectors = 0;
                PartitionInfo->StartingOffset.QuadPart = 0;
                PartitionInfo->PartitionLength.QuadPart = (EndSector * DiskGeometry.BytesPerSector);

                /* FIXME: REACTOS HACK */
                PartitionInfo->PartitionNumber = 0;

                /* Set the signature and set the count back to 0 */
                (*PartitionBuffer)->Signature = 1;
                ix = 0;
            }
        }
        else
        {
            /* Otherwise, this isn't a super floppy, so set an invalid count */
            ix = -1;
        }
    }

    /* Set the partition count */
    (*PartitionBuffer)->PartitionCount = ++ix;

    /* If we have no count, delete the signature */
    if (!ix)
        (*PartitionBuffer)->Signature = 0;

    if (Buffer)
        ExFreePoolWithTag(Buffer, TAG_FILE_SYSTEM);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IoReadPartitionTable: Status %X\n", Status);
        ExFreePoolWithTag(*PartitionBuffer, TAG_FILE_SYSTEM);
        *PartitionBuffer = NULL;
    }

    return Status;
}

NTSTATUS
FASTCALL
IoSetPartitionInformation(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG SectorSize,
    _In_ ULONG PartitionNumber,
    _In_ ULONG PartitionType)
{
    PPARTITION_DESCRIPTOR PartitionDescriptor;
    PIO_STACK_LOCATION IoStackLocation;
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER VolumeOffset;
    LARGE_INTEGER Offset;
    PUCHAR Buffer = NULL;
    PVOID MbrBuffer;
    PIRP Irp;
    KEVENT Event;
    ULONG BufferSize;
    ULONG ix = 0;
    ULONG Entry;
    BOOLEAN IsPrimary = TRUE;
    BOOLEAN IsEzDrive = FALSE;
    NTSTATUS Status;

    PAGED_CODE();

    BufferSize = max(0x200, SectorSize);

    Offset.QuadPart = 0;
    VolumeOffset.QuadPart = 0;

    /* Check for EZ Drive */
    HalExamineMBR(DeviceObject, BufferSize, 0x55, &MbrBuffer);
    if (MbrBuffer)
    {
        /* EZ Drive found, bias the offset */
        IsEzDrive = TRUE;
        ExFreePoolWithTag(MbrBuffer, TAG_FILE_SYSTEM);
        Offset.QuadPart = 0x200;
    }

    Buffer = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, TAG_FILE_SYSTEM);
    if (!Buffer)
    {
        DPRINT1("IoSetPartitionInformation: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    do
    {
        /* Reset the event since we reuse it */
        KeClearEvent(&Event);

        Irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ,
                                           DeviceObject,
                                           Buffer,
                                           BufferSize,
                                           &Offset,
                                           &Event,
                                           &IoStatusBlock);
        if (!Irp)
        {
            DPRINT1("IoSetPartitionInformation: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        /* Make sure to disable volume verification */
        IoStackLocation = IoGetNextIrpStackLocation(Irp);
        IoStackLocation->Flags |= SL_OVERRIDE_VERIFY_VOLUME;

        Status = IoCallDriver(DeviceObject, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoStatusBlock.Status;
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("IoSetPartitionInformation: Status %X\n", Status);
            break;
        }

        /* If we biased for EZ-Drive, unbias now */
        if (IsEzDrive && (Offset.QuadPart == 0x200))
            Offset.QuadPart = 0;

        /* Make sure this is a valid MBR */
        if (((PUSHORT)Buffer)[BOOT_SIGNATURE_OFFSET] != BOOT_RECORD_SIGNATURE)
        {
            /* It's not, fail */
            Status = STATUS_BAD_MASTER_BOOT_RECORD;
            break;
        }

        /* Get the partition descriptors and loop them */
        PartitionDescriptor = (PPARTITION_DESCRIPTOR)&(((PUSHORT)Buffer)[PARTITION_TABLE_OFFSET]);

        for (Entry = 1; Entry <= 4; Entry++, PartitionDescriptor++)
        {
            /* Check if it's unused or a container partition */
            if (PartitionDescriptor->PartitionType == PARTITION_ENTRY_UNUSED)
                continue;

            if (IsContainerPartition(PartitionDescriptor->PartitionType))
                continue;

            /* It's a valid partition, so increase the partition count */
            if (++ix != PartitionNumber)
                continue;

            /* We found a match, set the type */
            PartitionDescriptor->PartitionType = (UCHAR)PartitionType;

            /* Reset the reusable event */
            KeClearEvent(&Event);

            Irp = IoBuildSynchronousFsdRequest(IRP_MJ_WRITE,
                                               DeviceObject,
                                               Buffer,
                                               BufferSize,
                                               &Offset,
                                               &Event,
                                               &IoStatusBlock);
            if (!Irp)
            {
                DPRINT1("IoSetPartitionInformation: STATUS_INSUFFICIENT_RESOURCES\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            /* Disable volume verification */
            IoStackLocation = IoGetNextIrpStackLocation(Irp);
            IoStackLocation->Flags |= SL_OVERRIDE_VERIFY_VOLUME;

            Status = IoCallDriver(DeviceObject, Irp);
            if (Status == STATUS_PENDING)
            {
                KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
                Status = IoStatusBlock.Status;
            }

            /* We're done, break out of the loop */
            break;
        }

        /* If we looped all the partitions, break out */
        if (Entry <= NUM_PARTITION_TABLE_ENTRIES)
            break;

        /* Nothing found yet, get the partition array again */
        PartitionDescriptor = (PPARTITION_DESCRIPTOR)&(((PUSHORT)Buffer)[PARTITION_TABLE_OFFSET]);

        for (Entry = 1; Entry <= 4; Entry++, PartitionDescriptor++)
        {
            /* Check if this was a container partition (we skipped these) */
            if (!IsContainerPartition(PartitionDescriptor->PartitionType))
                continue;

            /* Update the partition offset */
            Offset.QuadPart = (VolumeOffset.QuadPart + GET_STARTING_SECTOR(PartitionDescriptor) * SectorSize);

            /* If this was the primary partition, update the volume too */
            if (IsPrimary)
                VolumeOffset = Offset;

            break;
        }

        /* Check if we already searched all the partitions */
        if (Entry > NUM_PARTITION_TABLE_ENTRIES)
        {
            /* Then we failed to find a good MBR */
            Status = STATUS_BAD_MASTER_BOOT_RECORD;
            break;
        }

        /* Loop the next partitions, which are not primary anymore */
        IsPrimary = FALSE;
    }
    while (ix < PartitionNumber);

    if (Buffer)
        ExFreePoolWithTag(Buffer, TAG_FILE_SYSTEM);

    return Status;
}

NTSTATUS
FASTCALL
IoWritePartitionTable(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG SectorSize,
    _In_ ULONG SectorsPerTrack,
    _In_ ULONG NumberOfHeads,
    _In_ PDRIVE_LAYOUT_INFORMATION PartitionBuffer)
{
    PPARTITION_INFORMATION PartitionInfo = PartitionBuffer->PartitionEntry;
    PPARTITION_INFORMATION TableEntry;
    PDISK_LAYOUT DiskLayout = (PDISK_LAYOUT)PartitionBuffer;
    PIO_STACK_LOCATION IoStackLocation;
    PPARTITION_TABLE PartitionTable;
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER StartOffset;
    LARGE_INTEGER PartitionLength;
    LARGE_INTEGER Offset;
    LARGE_INTEGER NextOffset;
    LARGE_INTEGER ExtendedOffset;
    LARGE_INTEGER SectorOffset;
    LONGLONG DiskSize;
    PVOID MbrBuffer;
    PUSHORT Buffer;
    PPTE Entry;
    PIRP Irp;
    KEVENT Event;
    ULONG ConventionalCylinders;
    ULONG BufferSize;
    ULONG ix;
    ULONG jx;
    CCHAR kx;
    UCHAR PartitionType;
    BOOLEAN IsEzDrive = FALSE;
    BOOLEAN IsSuperFloppy = FALSE;
    BOOLEAN DoRewrite = FALSE;
    BOOLEAN IsMbr;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    BufferSize = max(0x200, SectorSize);

    ExtendedOffset.QuadPart = 0;
    NextOffset.QuadPart = 0;
    Offset.QuadPart = 0;

    /* Get the partial drive geometry */
    xHalGetPartialGeometry(DeviceObject, &ConventionalCylinders, &DiskSize);

    /* Check for EZ Drive */
    HalExamineMBR(DeviceObject, BufferSize, 0x55, &MbrBuffer);
    if (MbrBuffer)
    {
        /* EZ Drive found, bias the offset */
        IsEzDrive = TRUE;
        ExFreePoolWithTag(MbrBuffer, TAG_FILE_SYSTEM);
        Offset.QuadPart = 0x200;
    }

    /* Get the number of bits to shift to multiply by the sector size */
    for (kx = 0; kx < 0x20; kx++)
    {
        if ((SectorSize >> kx) == 1)
            break;
    }

    /* Check if there's only one partition */
    if (PartitionBuffer->PartitionCount == 1)
    {
        /* Check if it has no starting offset or hidden sectors */
        if (!(PartitionInfo->StartingOffset.QuadPart) &&
            !(PartitionInfo->HiddenSectors))
        {
            /* Then it's a super floppy */
            IsSuperFloppy = TRUE;

            /* Which also means it must be non-bootable FAT-16 */
            if ((PartitionInfo->PartitionNumber) ||
                (PartitionInfo->PartitionType != PARTITION_FAT_16) ||
                (PartitionInfo->BootIndicator))
            {
                /* It's not, so we fail */
                return STATUS_INVALID_PARAMETER;
            }

            /* Check if it needs a rewrite, and disable EZ drive for sure */
            if (PartitionInfo->RewritePartition)
                DoRewrite = TRUE;

            IsEzDrive = FALSE;
        }
    }

    /* Count the number of partition tables */
    DiskLayout->TableCount = ((PartitionBuffer->PartitionCount + 4 - 1) / 4);

    /* Allocate our partition buffer */
    Buffer = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, TAG_FILE_SYSTEM);
    if (!Buffer)
    {
        DPRINT1("IoWritePartitionTable: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Loop the entries */
    Entry = (PPTE)&Buffer[PARTITION_TABLE_OFFSET];

    for (ix = 0; ix < DiskLayout->TableCount; ix++)
    {
        /* Set if this is the MBR partition */
        IsMbr = (ix == 0);

        KeInitializeEvent(&Event, NotificationEvent, FALSE);

        /* Build the read IRP */
        Irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ,
                                           DeviceObject,
                                           Buffer,
                                           BufferSize,
                                           &Offset,
                                           &Event,
                                           &IoStatusBlock);
        if (!Irp)
        {
            DPRINT1("IoWritePartitionTable: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        /* Make sure to disable volume verification */
        IoStackLocation = IoGetNextIrpStackLocation(Irp);
        IoStackLocation->Flags |= SL_OVERRIDE_VERIFY_VOLUME;

        Status = IoCallDriver(DeviceObject, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoStatusBlock.Status;
        }

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("IoWritePartitionTable: Status %X\n", Status);
            break;
        }

        /* If we biased for EZ-Drive, unbias now */
        if (IsEzDrive && (Offset.QuadPart == 0x200))
            Offset.QuadPart = 0;

        /* Check if this is a normal disk */
        if (!IsSuperFloppy)
        {
            /* Set the boot record signature */
            Buffer[BOOT_SIGNATURE_OFFSET] = BOOT_RECORD_SIGNATURE;

            /* By default, don't require a rewrite */
            DoRewrite = FALSE;

            /* Check if we don't have an offset */
            if (!Offset.QuadPart)
            {
                /* Check if the signature doesn't match */
                if (((PULONG)Buffer)[PARTITION_TABLE_OFFSET / 2 - 1] != PartitionBuffer->Signature)
                {
                    /* Then write the signature and now we need a rewrite */
                    ((PULONG)Buffer)[PARTITION_TABLE_OFFSET / 2 - 1] = PartitionBuffer->Signature;
                    DoRewrite = TRUE;
                }
            }

            /* Loop the partition table entries */
            PartitionTable = &DiskLayout->PartitionTable[ix];

            for (jx = 0; jx < 4; jx++)
            {
                /* Get the current entry and type */
                TableEntry = &PartitionTable->PartitionEntry[jx];
                PartitionType = TableEntry->PartitionType;

                /* Check if the entry needs a rewrite */
                if (TableEntry->RewritePartition)
                {
                    /* Then we need one too */
                    DoRewrite = TRUE;

                    /* Save the type and if it's a bootable partition */
                    Entry[jx].PartitionType = TableEntry->PartitionType;
                    Entry[jx].ActiveFlag = (TableEntry->BootIndicator ? 0x80 : 0);

                    /* Make sure it's used */
                    if (PartitionType != PARTITION_ENTRY_UNUSED)
                    {
                        /* Make sure it's not a container (unless primary) */
                        if (IsMbr || !IsContainerPartition(PartitionType))
                            StartOffset.QuadPart = Offset.QuadPart; /* Use the partition offset */
                        else
                            StartOffset.QuadPart = ExtendedOffset.QuadPart; /* Use the extended logical partition offset */

                        /* Set the sector offset */
                        SectorOffset.QuadPart = (TableEntry->StartingOffset.QuadPart - StartOffset.QuadPart);

                        /* Now calculate the starting sector */
                        StartOffset.QuadPart = (SectorOffset.QuadPart >> kx);
                        Entry[jx].StartingSector = StartOffset.LowPart;

                        /* As well as the length */
                        PartitionLength.QuadPart = (TableEntry->PartitionLength.QuadPart >> kx);
                        Entry[jx].PartitionLength = PartitionLength.LowPart;

                        /* Calculate the CHS values */
                        HalpCalculateChsValues(&TableEntry->StartingOffset,
                                               &TableEntry->PartitionLength,
                                               kx,
                                               SectorsPerTrack,
                                               NumberOfHeads,
                                               ConventionalCylinders,
                                               (PPARTITION_DESCRIPTOR)&Entry[jx]);
                    }
                    else
                    {
                        /* Otherwise set up an empty entry */
                        Entry[jx].StartingSector = 0;
                        Entry[jx].PartitionLength = 0;
                        Entry[jx].StartingTrack = 0;
                        Entry[jx].EndingTrack = 0;
                        Entry[jx].StartingCylinder = 0;
                        Entry[jx].EndingCylinder = 0;
                    }
                }

                /* Check if this is a container partition */
                if (IsContainerPartition(PartitionType))
                {
                    /* Then update the offset to use */
                    NextOffset = TableEntry->StartingOffset;
                }
            }
        }

        /* Check if we need to write back the buffer */
        if (DoRewrite)
        {
            /* We don't need to do this again */
            DoRewrite = FALSE;

            KeInitializeEvent(&Event, NotificationEvent, FALSE);

            /* If we unbiased for EZ-Drive, rebias now */
            if ((IsEzDrive) && !(Offset.QuadPart))
                Offset.QuadPart = 0x200;

            /* Build the write IRP */
            Irp = IoBuildSynchronousFsdRequest(IRP_MJ_WRITE,
                                               DeviceObject,
                                               Buffer,
                                               BufferSize,
                                               &Offset,
                                               &Event,
                                               &IoStatusBlock);
            if (!Irp)
            {
                DPRINT1("IoWritePartitionTable: STATUS_INSUFFICIENT_RESOURCES\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            /* Make sure to disable volume verification */
            IoStackLocation = IoGetNextIrpStackLocation(Irp);
            IoStackLocation->Flags |= SL_OVERRIDE_VERIFY_VOLUME;

            Status = IoCallDriver(DeviceObject, Irp);
            if (Status == STATUS_PENDING)
            {
                KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
                Status = IoStatusBlock.Status;
            }

            if (!NT_SUCCESS(Status))
            {
                DPRINT1("IoWritePartitionTable: Status %X\n", Status);
                break;
            }

            /* If we biased for EZ-Drive, unbias now */
            if (IsEzDrive && (Offset.QuadPart == 0x200))
                Offset.QuadPart = 0;
        }

        /* Update the partition offset and set the extended offset if needed */
        Offset = NextOffset;

        if (IsMbr)
            ExtendedOffset = NextOffset;
    }

    if (Buffer)
        ExFreePoolWithTag(Buffer, TAG_FILE_SYSTEM);

    return Status;
}

//---------------------------------
// IoAssignDriveLetters
//---------------------------------

PULONG
NTAPI
IopComputeHarddiskDerangements(
    _In_ ULONG DiskCount)
{
    STORAGE_DEVICE_NUMBER StorageDeviceNumber;
    UNICODE_STRING DestinationString;
    PDEVICE_OBJECT DeviceObject;
    IO_STATUS_BLOCK IoStatus;
    PFILE_OBJECT FileObject;
    WCHAR SourceString[50];
    PULONG NumbersArray;
    KEVENT Event;
    PIRP Irp;
    ULONG ix;
    ULONG jx;
    ULONG nx;
    NTSTATUS Status;

    if (!DiskCount)
    {
        DPRINT1("IopComputeHarddiskDerangements: DiskCount is 0\n");
        return NULL;
    }

    DPRINT("IopComputeHarddiskDerangements: DiskCount %X\n", DiskCount);

    NumbersArray = ExAllocatePoolWithTag((PagedPool | POOL_COLD_ALLOCATION), (DiskCount * 4), 'btsF');
    if (!NumbersArray)
    {
        DPRINT1("IopComputeHarddiskDerangements: Allocate failed\n");
        return NULL;
    }

    for (ix = 0; ix < DiskCount; ix++)
    {
        swprintf(SourceString, L"\\ArcName\\multi(0)disk(0)rdisk(%d)", ix);
        RtlInitUnicodeString(&DestinationString, SourceString);

        Status = IoGetDeviceObjectPointer(&DestinationString, FILE_READ_ATTRIBUTES, &FileObject, &DeviceObject);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("IopComputeHarddiskDerangements: Status %X\n", Status);
            NumbersArray[ix] = 0xFFFFFFFF;
            continue;
        }

        DeviceObject = IoGetAttachedDeviceReference(FileObject->DeviceObject);
        ObDereferenceObject(FileObject);

        KeInitializeEvent(&Event, NotificationEvent, FALSE);

        Irp = IoBuildDeviceIoControlRequest(IOCTL_STORAGE_GET_DEVICE_NUMBER,
                                            DeviceObject,
                                            NULL,
                                            0UL,
                                            &StorageDeviceNumber,
                                            sizeof(StorageDeviceNumber),
                                            FALSE,
                                            &Event,
                                            &IoStatus);
        if (!Irp)
        {
            DPRINT1("IopComputeHarddiskDerangements: Build IRP failed\n");
            ObDereferenceObject(DeviceObject);
            NumbersArray[ix] = 0xFFFFFFFF;
            continue;
        }

        Status = IoCallDriver(DeviceObject, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoStatus.Status;
        }

        ObDereferenceObject(DeviceObject);

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("IopComputeHarddiskDerangements: Status %X\n", Status);
            NumbersArray[ix] = 0xFFFFFFFF;
        }
        else
        {
            NumbersArray[ix] = StorageDeviceNumber.DeviceNumber;
        }
    }

    for (jx = 0; jx < DiskCount; jx++)
    {
        for (nx = 0; nx < DiskCount; nx++)
        {
            if (NumbersArray[nx] == jx)
                break;
        }

        if (nx < DiskCount)
            continue;

        for (nx = 0; nx < DiskCount; nx++)
        {
            if (NumbersArray[nx] == 0xFFFFFFFF)
            {
                NumbersArray[nx] = jx;
                break;
            }
        }
    }

    return NumbersArray;
}

NTSTATUS
NTAPI
HalpQueryDriveLayout(
    _In_ PUNICODE_STRING DeviceName,
    _Out_ PDRIVE_LAYOUT_INFORMATION* OutDriveLayoutInfo)
{
    PDRIVE_LAYOUT_INFORMATION DriveLayoutInfo;
    PDEVICE_OBJECT DeviceObject = NULL;
    IO_STATUS_BLOCK IoStatus;
    PFILE_OBJECT FileObject;
    SIZE_T LayoutInfoSize;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("HalpQueryDriveLayout: Device '%wZ'\n", DeviceName);

    Status = IoGetDeviceObjectPointer(DeviceName, FILE_READ_ATTRIBUTES, &FileObject, &DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpQueryDriveLayout: Status %X\n", Status);
        return Status;
    }

    DeviceObject = IoGetAttachedDeviceReference(FileObject->DeviceObject);
    ObDereferenceObject(FileObject);
    if (DeviceObject->Characteristics & 1)
    {
        ObDereferenceObject(DeviceObject);
        return STATUS_NO_MEMORY;
    }

    LayoutInfoSize = PAGE_SIZE;
    DriveLayoutInfo = NULL;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    do
    {
        KeClearEvent(&Event);

        if (DriveLayoutInfo)
        {
            ExFreePoolWithTag(DriveLayoutInfo, 'BtsF');
            LayoutInfoSize *= 2;
        }

        DriveLayoutInfo = ExAllocatePoolWithTag(0, LayoutInfoSize, 'BtsF');
        if (!DriveLayoutInfo)
        {
            DPRINT1("HalpQueryDriveLayout: STATUS_NO_MEMORY\n");
            Status = STATUS_NO_MEMORY;
            goto Exit;
        }

        Irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_DRIVE_LAYOUT,
                                            DeviceObject,
                                            NULL,
                                            0UL,
                                            DriveLayoutInfo,
                                            LayoutInfoSize,
                                            FALSE,
                                            &Event,
                                            &IoStatus);
        if (!Irp)
        {
            DPRINT1("HalpQueryDriveLayout: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        Status = IoCallDriver(DeviceObject, Irp);
        if (Status == STATUS_PENDING)
        {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoStatus.Status;
        }
    }
    while (Status == STATUS_BUFFER_TOO_SMALL);

Exit:

    if (DeviceObject)
        ObDereferenceObject(DeviceObject);

    if (NT_SUCCESS(Status))
    {
        ASSERT(DriveLayoutInfo);
        *OutDriveLayoutInfo = DriveLayoutInfo;
    }

    return Status;
}

NTSTATUS
NTAPI
HalpQueryPartitionType(
    _In_ PUNICODE_STRING PartitionName,
    _In_ PDRIVE_LAYOUT_INFORMATION DriveLayoutInfo,
    _Out_ PULONG OutPartitionType)
{
    PARTITION_INFORMATION_EX PartitionInfo;
    PARTITION_INFORMATION* PartitionEntry;
    IO_STATUS_BLOCK IoStatusBlock;
    PDEVICE_OBJECT DeviceObject;
    PFILE_OBJECT FileObject;
    KEVENT Event;
    PIRP Irp;
    ULONG ix;
    UCHAR PartitionType;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("HalpQueryPartitionType: Partition '%wZ'\n", PartitionName);

    Status = IoGetDeviceObjectPointer(PartitionName, FILE_READ_ATTRIBUTES, &FileObject, &DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("HalpQueryPartitionType: Status %X\n", Status);
        return Status;
    }

    DeviceObject = IoGetAttachedDeviceReference(FileObject->DeviceObject);
    ObDereferenceObject(FileObject);

    if (DeviceObject->Characteristics & 1)
    {
        ObDereferenceObject(DeviceObject);
        goto Exit;
    }

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_PARTITION_INFO_EX,
                                        DeviceObject,
                                        NULL,
                                        0UL,
                                        &PartitionInfo,
                                        sizeof(PartitionInfo),
                                        FALSE,
                                        &Event,
                                        &IoStatusBlock);
    if (!Irp)
    {
        DPRINT1("HalpQueryPartitionType: STATUS_INSUFFICIENT_RESOURCES\n");
        ObDereferenceObject(DeviceObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }

    ObDereferenceObject(DeviceObject);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("HalpQueryPartitionType: Status %X\n", Status);

        if (DriveLayoutInfo)
            return Status;

        goto Exit;
    }

    if (PartitionInfo.PartitionStyle)
    {
        if (PartitionInfo.PartitionStyle != 1)
        {
            *OutPartitionType = 4;
            return STATUS_SUCCESS;
        }

        if (RtlCompareMemory(&PartitionInfo.Gpt.PartitionType, &PARTITION_BASIC_DATA_GUID, sizeof(GUID)) == sizeof(GUID))
        {
            *OutPartitionType = 5;
            return STATUS_SUCCESS;
        }

        *OutPartitionType = 4;
        return STATUS_SUCCESS;
    }

    PartitionType = (PartitionInfo.Mbr.PartitionType & 0x80);

    DPRINT("HalpQueryPartitionType: FIXME test partition type\n");

    if (IsRecognizedPartition(PartitionType))
    {
        *OutPartitionType = 4;
        return STATUS_SUCCESS;
    }

    if (PartitionType)
    {
        *OutPartitionType = 3;
        return STATUS_SUCCESS;
    }

    if (!DriveLayoutInfo)
    {
        DPRINT("HalpQueryPartitionType: DriveLayoutInfo is NULL\n");
        goto Exit;
    }

    PartitionEntry = DriveLayoutInfo->PartitionEntry;
    
    for (ix = 0; ix < 4; ix++)
    {
        if (PartitionInfo.StartingOffset.QuadPart == PartitionEntry->StartingOffset.QuadPart)
        {
            *OutPartitionType = (PartitionInfo.Mbr.BootIndicator == 0);
            return STATUS_SUCCESS;
        }

        PartitionEntry++;
    }

Exit:
    *OutPartitionType = 2;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
HalpNextMountLetter(
    _In_ PCUNICODE_STRING PartitionName,
    _In_ PCHAR NextLetter)
{
    PMOUNTMGR_DRIVE_LETTER_TARGET DriveLetterTarget;
    MOUNTMGR_DRIVE_LETTER_INFORMATION OutputBuffer;
    UNICODE_STRING MntMgrDeviceName;
    PDEVICE_OBJECT DeviceObject;
    IO_STATUS_BLOCK IoStatus;
    PFILE_OBJECT FileObject;
    KEVENT Event;
    PIRP Irp;
    ULONG DriveLetterTargetSize;
    NTSTATUS Status;

    DPRINT("HalpNextMountLetter: Partition '%wZ'\n", PartitionName);

    RtlInitUnicodeString(&MntMgrDeviceName, L"\\Device\\MountPointManager");

    Status = IoGetDeviceObjectPointer(&MntMgrDeviceName, FILE_READ_ATTRIBUTES, &FileObject, &DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpNextMountLetter: return Status %X\n", Status);
        return Status;
    }

    DriveLetterTarget = ExAllocatePoolWithTag(PagedPool, (PartitionName->Length + 4), 'btsF');
    if (!DriveLetterTarget)
    {
        DPRINT1("HalpNextMountLetter: STATUS_INSUFFICIENT_RESOURCES\n");
        ObDereferenceObject(FileObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DriveLetterTarget->DeviceNameLength = PartitionName->Length;

    RtlCopyMemory(DriveLetterTarget->DeviceName, PartitionName->Buffer, PartitionName->Length);

    DriveLetterTargetSize = (PartitionName->Length + 4);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    RtlZeroMemory(&OutputBuffer, sizeof(OutputBuffer));

    Irp = IoBuildDeviceIoControlRequest(IOCTL_MOUNTMGR_NEXT_DRIVE_LETTER,
                                        DeviceObject,
                                        DriveLetterTarget,
                                        DriveLetterTargetSize,
                                        &OutputBuffer,
                                        sizeof(OutputBuffer),
                                        FALSE,
                                        &Event,
                                        &IoStatus);
    if (!Irp)
    {
        DPRINT1("HalpNextMountLetter: STATUS_INSUFFICIENT_RESOURCES\n");
        ExFreePoolWithTag(DriveLetterTarget, 'btsF');
        ObDereferenceObject(FileObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
        DPRINT("HalpNextMountLetter: IoStatus.Status %X\n", Status);
    }
    else if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpNextMountLetter: Status %X\n", Status);
    }

    ExFreePoolWithTag(DriveLetterTarget, 'btsF');
    ObDereferenceObject(FileObject);

    *NextLetter = OutputBuffer.CurrentDriveLetter;

 #if DBG
    if (OutputBuffer.DriveLetterWasAssigned)
    {
        DPRINT("HalpNextMountLetter: NextLetter %C, ret %X\n", *NextLetter, Status);
    }
    else
    {
        DPRINT1("HalpNextMountLetter: DriveLetterWasAssigned is FALSE for '%wZ'\n", PartitionName);
    }
 #endif

    return Status;
}

NTSTATUS
NTAPI
HalpSetMountLetter(
    _In_ PUNICODE_STRING DeviceName,
    _In_ CHAR MountLetter)
{
    PMOUNTMGR_CREATE_POINT_INPUT CreatePoint;
    UNICODE_STRING MntMgrDeviceName;
    UNICODE_STRING LinkName;
    PDEVICE_OBJECT DeviceObject;
    PFILE_OBJECT FileObject;
    IO_STATUS_BLOCK IoStatus;
    WCHAR SourceString[30];
    KEVENT Event;
    PIRP Irp;
    ULONG InputBufferLength;
    NTSTATUS Status;

    DPRINT("HalpSetMountLetter: Device '%wZ', MountLetter '%C'\n", DeviceName, MountLetter);

    swprintf(SourceString, L"\\DosDevices\\%c:", MountLetter);
    RtlInitUnicodeString(&LinkName, SourceString);

    InputBufferLength = (LinkName.Length + DeviceName->Length + sizeof(MOUNTMGR_CREATE_POINT_INPUT));

    DPRINT("HalpSetMountLetter: Link '%wZ', Len %X\n", &LinkName, InputBufferLength);

    CreatePoint = ExAllocatePoolWithTag(PagedPool, InputBufferLength, 'btsF');
    if (!CreatePoint)
    {
        DPRINT1("HalpSetMountLetter: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    CreatePoint->SymbolicLinkNameOffset = sizeof(MOUNTMGR_CREATE_POINT_INPUT);
    CreatePoint->SymbolicLinkNameLength = LinkName.Length;

    CreatePoint->DeviceNameOffset = (sizeof(MOUNTMGR_CREATE_POINT_INPUT) + LinkName.Length);
    CreatePoint->DeviceNameLength = DeviceName->Length;

    RtlCopyMemory(&CreatePoint[1], LinkName.Buffer, LinkName.Length);

    RtlCopyMemory((PVOID)((ULONG_PTR)CreatePoint + CreatePoint->DeviceNameOffset),
                  DeviceName->Buffer,
                  DeviceName->Length);

    RtlInitUnicodeString(&MntMgrDeviceName, L"\\Device\\MountPointManager");

    Status = IoGetDeviceObjectPointer(&MntMgrDeviceName, FILE_READ_ATTRIBUTES, &FileObject, &DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpSetMountLetter: return Status %X\n", Status);
        ExFreePoolWithTag(CreatePoint, 'btsF');
        return Status;
    }

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildDeviceIoControlRequest(IOCTL_MOUNTMGR_CREATE_POINT,
                                        DeviceObject,
                                        CreatePoint,
                                        InputBufferLength,
                                        NULL,
                                        0UL,
                                        FALSE,
                                        &Event,
                                        &IoStatus);
    if (!Irp)
    {
        DPRINT1("HalpSetMountLetter: STATUS_INSUFFICIENT_RESOURCES\n");
        ObDereferenceObject(FileObject);
        ExFreePoolWithTag(CreatePoint, 'btsF');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
    }

    ObDereferenceObject(FileObject);
    ExFreePoolWithTag(CreatePoint, 'btsF');

    DPRINT("HalpSetMountLetter: return Status %X\n", Status);
    return Status;
}

CHAR
NTAPI
HalpNextDriveLetter(
    _In_ PUNICODE_STRING PartitionName,
    _In_ PSTRING NtDeviceName,
    _Out_ PCHAR OutNextLetter,
    _In_ BOOLEAN AsiignLetter)
{
    UNICODE_STRING FloppyName;
    UNICODE_STRING SymbolicLinkName;
    UNICODE_STRING CdRomName;
    UNICODE_STRING UnicodeString;
    CHAR NextLetter;
    WCHAR Buffer[40];
    CHAR letter;
    BOOLEAN IsCdRom;
    BOOLEAN IsFloppy;
    NTSTATUS Status;

    DPRINT("HalpNextDriveLetter: '%wZ', AsiignLetter %X\n", PartitionName, AsiignLetter);

    Status = HalpNextMountLetter(PartitionName, &NextLetter);
    if (NT_SUCCESS(Status))
    {
        DPRINT("HalpNextDriveLetter: NextLetter '%C'\n", NextLetter);
        return NextLetter;
    }

    if (!NtDeviceName || !OutNextLetter)
    {
        DPRINT("HalpNextDriveLetter: !NtDeviceName || !OutNextLetter\n");
        return -1;
    }

    if (!AsiignLetter)
    {
        DPRINT("HalpNextDriveLetter: AsiignLetter is FALSE\n");
        return 0;
    }

    RtlInitUnicodeString(&FloppyName, L"\\Device\\Floppy");
    IsFloppy = RtlPrefixUnicodeString(&FloppyName, PartitionName, TRUE);

    if (IsFloppy)
    {
        letter = 'A';
    }
    else
    {
        RtlInitUnicodeString(&CdRomName, L"\\Device\\CdRom");
        IsCdRom = RtlPrefixUnicodeString(&CdRomName, PartitionName, TRUE);

        if (IsCdRom)
            letter = 'D';
        else
            letter = 'C';
    }

    DPRINT("HalpNextDriveLetter: NextLetter '%C'\n", letter);
    
    for (NextLetter = letter; NextLetter <= 'Z'; NextLetter++)
    {
        Status = HalpSetMountLetter(PartitionName, NextLetter);
        if (!NT_SUCCESS(Status))
            continue;

        DPRINT("HalpNextDriveLetter: NextLetter '%C'\n", NextLetter);

        Status = RtlAnsiStringToUnicodeString(&UnicodeString, NtDeviceName, TRUE);
        if (!NT_SUCCESS(Status))
            return NextLetter;

        if (RtlEqualUnicodeString(&UnicodeString, PartitionName, TRUE))
            *OutNextLetter = NextLetter;

        RtlFreeUnicodeString(&UnicodeString);
        return NextLetter;
    }

    for (NextLetter = letter; NextLetter <= 'Z'; NextLetter++)
    {
        DPRINT("HalpNextDriveLetter: NextLetter '%C'\n", NextLetter);

        swprintf(Buffer, L"\\DosDevices\\%c:", NextLetter);
        RtlInitUnicodeString(&SymbolicLinkName, Buffer);

        Status = IoCreateSymbolicLink(&SymbolicLinkName, PartitionName);
        if (!NT_SUCCESS(Status))
            continue;

        Status = RtlAnsiStringToUnicodeString(&UnicodeString, NtDeviceName, TRUE);
        if (!NT_SUCCESS(Status))
            return NextLetter;

        if (RtlEqualUnicodeString(&UnicodeString, PartitionName, TRUE))
            *OutNextLetter = NextLetter;

        RtlFreeUnicodeString(&UnicodeString);
        return NextLetter;
    }

    return 0;
}

NTSTATUS
NTAPI
HalpEnableAutomaticDriveLetterAssignment(
    VOID)
{
    UNICODE_STRING MntMgrDeviceName;
    PDEVICE_OBJECT DeviceObject;
    PFILE_OBJECT FileObject;
    IO_STATUS_BLOCK IoStatus;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;

    DPRINT("HalpEnableAutomaticDriveLetterAssignment()\n");

    RtlInitUnicodeString(&MntMgrDeviceName, L"\\Device\\MountPointManager");

    Status = IoGetDeviceObjectPointer(&MntMgrDeviceName, FILE_READ_ATTRIBUTES, &FileObject, &DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpEnableAutomaticDriveLetterAssignment: Status %X\n", Status);
        return Status;
    }

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildDeviceIoControlRequest(IOCTL_MOUNTMGR_AUTO_DL_ASSIGNMENTS,
                                        DeviceObject,
                                        NULL,
                                        0UL,
                                        NULL,
                                        0UL,
                                        FALSE,
                                        &Event,
                                        &IoStatus);
    if (!Irp)
    {
        DPRINT1("HalpEnableAutomaticDriveLetterAssignment: Build failed\n");
        goto Exit;
    }

    if (IoCallDriver(DeviceObject, Irp) == STATUS_PENDING)
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

Exit:
    return ObDereferenceObject(FileObject);
}

NTSTATUS
NTAPI
HalpDeleteMountLetter(
    _In_ CHAR MountLetter)
{
    UNIMPLEMENTED;
    ASSERT(FALSE); // FsbDbgBreakPointEx();
    return STATUS_NOT_IMPLEMENTED;
}

VOID
FASTCALL
IoAssignDriveLetters(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock,
    _In_ PSTRING NtDeviceName,
    _Out_ PUCHAR NtSystemPath,
    _Out_ PSTRING NtSystemPathString)
{
    PDRIVE_LAYOUT_INFORMATION DriveLayoutInfo;
    PCONFIGURATION_INFORMATION ConfigInfo;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    UNICODE_STRING SymbolicLinkName;
    UNICODE_STRING CdRomString;
    UNICODE_STRING FloppyString;
    UNICODE_STRING DeviceName;
    UNICODE_STRING PartitionName;
    WCHAR PartitionStr[50];
    PCHAR DeviceNameBuffer;
    PCHAR OutDriveLetter;
    PCHAR LinkNameBuffer;
    PULONG NumbersArray;
    HANDLE FileHandle;
    ULONG PartitionNumber;
    ULONG PartitionType;
    ULONG DeviceNumber;
    ULONG FloppyCount;
    ULONG CdRomCount;
    ULONG DiskCount;
    ULONG failCount;
    ULONG realCount;
    ULONG ix;
    CHAR DriveLetter;
    BOOLEAN IsActivePartition;
    NTSTATUS Status;

    PAGED_CODE();

 #ifndef NDEBUG
 {
    UNICODE_STRING BootDevice;
    NTSTATUS Status;

    Status = RtlAnsiStringToUnicodeString(&BootDevice, NtDeviceName, TRUE);
    ASSERT(NT_SUCCESS(Status));

    DPRINT("IoAssignDriveLetters: NtDevice '%wZ'\n", &BootDevice);
    //ASSERT(FALSE); // FsbDbgBreakPointEx();
 }
 #endif

    ConfigInfo = IoGetConfigurationInformation();

    DiskCount = ConfigInfo->DiskCount;
    FloppyCount = ConfigInfo->FloppyCount;
    CdRomCount = ConfigInfo->CdRomCount;

    DPRINT("DiskCount %X\n", DiskCount);
    DPRINT("FloppyCount %X\n", FloppyCount);
    DPRINT("CdRomCount %X\n", CdRomCount);

    DeviceNameBuffer = ExAllocatePoolWithTag(0, 0x80, 'btsF');
    if (!DeviceNameBuffer)
    {
        DPRINT1("IoAssignDriveLetters: Allocate failed, KeBugCheck()\n");
        ASSERT(FALSE);KeBugCheck(ASSIGN_DRIVE_LETTERS_FAILED);
    }

    LinkNameBuffer = ExAllocatePoolWithTag(0, 0x40, 'btsF');
    if (!LinkNameBuffer)
    {
        DPRINT1("IoAssignDriveLetters: Allocate failed, KeBugCheck()\n");
        ASSERT(FALSE);KeBugCheck(ASSIGN_DRIVE_LETTERS_FAILED);
    }

    OutDriveLetter = (PCHAR)NtSystemPath;

    if (IoRemoteBootClient)
    {
        DPRINT1("IoAssignDriveLetters: FIXME! IoRemoteBootClient is TRUE\n");
        ASSERT(FALSE); // FsbDbgBreakPointEx();
    }

    for (ix = 0, failCount = 0, realCount = 0; ix < DiskCount; ix++)
    {
        STRING DeviceStr;
        STRING LinkStr;

        sprintf(DeviceNameBuffer, "\\Device\\Harddisk%d\\Partition%d", (int)ix, 0);
        RtlInitAnsiString(&DeviceStr, DeviceNameBuffer);

        Status = RtlAnsiStringToUnicodeString(&DeviceName, &DeviceStr, TRUE);
        if (!NT_SUCCESS(Status))
        {
             DPRINT1("IoAssignDriveLetters: Status %X\n", Status);
             goto FailOpen;
        }

        DPRINT("IoAssignDriveLetters: Device '%wZ'\n", &DeviceName);

        InitializeObjectAttributes(&ObjectAttributes, &DeviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        Status = ZwOpenFile(&FileHandle,
                            (FILE_READ_DATA | SYNCHRONIZE),
                            &ObjectAttributes,
                            &IoStatusBlock,
                            FILE_SHARE_READ,
                            FILE_SYNCHRONOUS_IO_NONALERT);

        if (!NT_SUCCESS(Status))
        {
             DPRINT1("IoAssignDriveLetters: Status %X\n", Status);
             RtlFreeUnicodeString(&DeviceName);
             goto FailOpen;
        }

        sprintf(LinkNameBuffer, "\\DosDevices\\PhysicalDrive%d", (int)ix);
        RtlInitAnsiString(&LinkStr, LinkNameBuffer);

        Status = RtlAnsiStringToUnicodeString(&SymbolicLinkName, &LinkStr, TRUE);
        if (NT_SUCCESS(Status))
        {
            DPRINT("IoAssignDriveLetters: SymbolicLink '%wZ', Device '%wZ'\n", &SymbolicLinkName, &DeviceName);
            IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
            RtlFreeUnicodeString(&SymbolicLinkName);
        }

        realCount = (ix + 1);

        ZwClose(FileHandle);
        RtlFreeUnicodeString(&DeviceName);

        if (NT_SUCCESS(Status))
            continue;

        DPRINT1("IoAssignDriveLetters: Status %X\n", Status);

FailOpen:
        DPRINT1("IoAssignDriveLetters: Failed to open %wZ\n", DeviceName);

        if (failCount < 0x32)
        {
            failCount++;
            DiskCount++;
        }
    }

    ExFreePoolWithTag(DeviceNameBuffer, 'btsF');
    ExFreePoolWithTag(LinkNameBuffer, 'btsF');

    if (LoaderBlock->LoadOptions)
    {
        PCHAR LoadOptions;

        LoadOptions = _strupr(LoaderBlock->LoadOptions);

        if (strstr(LoadOptions, "MININT"))
        {
            Status = RtlAnsiStringToUnicodeString(&DeviceName, NtDeviceName, TRUE);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("IoAssignDriveLetters: Status %X\n", Status);
                ASSERT(FALSE); // FsbDbgBreakPointEx();
            }
            else
            {
                Status = HalpSetMountLetter(&DeviceName, 'X');
                if (NT_SUCCESS(Status))
                {
                    DPRINT("IoAssignDriveLetters: *OutDriveLetter is 'X'\n");
                    *OutDriveLetter = 'X';
                }

                RtlFreeUnicodeString(&DeviceName);
            }
        }
    }
    else
    {
        DPRINT1("IoAssignDriveLetters: LoadOptions is NULL\n");
    }

    DiskCount -= failCount;

    if (DiskCount < realCount)
        DiskCount = realCount;

    DPRINT("IoAssignDriveLetters: DiskCount %X\n", DiskCount);

    NumbersArray = IopComputeHarddiskDerangements(DiskCount);
    
    for (ix = 0, DeviceNumber = 0; ix < DiskCount; ix++)
    {
        if (NumbersArray)
            DeviceNumber = NumbersArray[ix];

        swprintf(PartitionStr, L"\\Device\\Harddisk%d\\Partition0", DeviceNumber);
        RtlInitUnicodeString(&PartitionName, PartitionStr);

        Status = HalpQueryDriveLayout(&PartitionName, &DriveLayoutInfo);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("IoAssignDriveLetters: Status %X\n", Status);
            DriveLayoutInfo = NULL;
        }

        IsActivePartition = FALSE;

        for (PartitionNumber = 1; ; PartitionNumber++)
        {
            swprintf(PartitionStr, L"\\Device\\Harddisk%d\\Partition%d", DeviceNumber, PartitionNumber);
            RtlInitUnicodeString(&PartitionName, PartitionStr);

            Status = HalpQueryPartitionType(&PartitionName, DriveLayoutInfo, &PartitionType);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("IoAssignDriveLetters: Status %X\n", Status);
                break;
            }

            if (PartitionType == 0 || PartitionType == 5)
            {
                IsActivePartition = TRUE;

                HalpNextDriveLetter(&PartitionName, NtDeviceName, OutDriveLetter, FALSE);

                if (PartitionType == 0)
                    break;
            }
        }

        if (IsActivePartition)
        {
            if (DriveLayoutInfo)
                ExFreePoolWithTag(DriveLayoutInfo, 'BtsF');

            continue;
        }

        for (PartitionNumber = 1; ; PartitionNumber++)
        {
            swprintf(PartitionStr, L"\\Device\\Harddisk%d\\Partition%d", DeviceNumber, PartitionNumber);
            RtlInitUnicodeString(&PartitionName, PartitionStr);

            Status = HalpQueryPartitionType(&PartitionName, DriveLayoutInfo, &PartitionType);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("IoAssignDriveLetters: Status %X\n", Status);
                break;
            }

            if (PartitionType == 1)
            {
                HalpNextDriveLetter(&PartitionName, NtDeviceName, OutDriveLetter, FALSE);
                break;
            }
        }

        if (DriveLayoutInfo)
            ExFreePoolWithTag(DriveLayoutInfo, 'BtsF');

        DeviceNumber = (ix + 1);
    }

    for (ix = 0; ix < DiskCount; ix++)
    {
        if (NumbersArray)
            DeviceNumber = NumbersArray[ix];
        else
            DeviceNumber = ix;

        swprintf(PartitionStr, L"\\Device\\Harddisk%d\\Partition0", DeviceNumber);
        RtlInitUnicodeString(&PartitionName, PartitionStr);

        Status = HalpQueryDriveLayout(&PartitionName, &DriveLayoutInfo);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("IoAssignDriveLetters: Status %X\n", Status);
            DriveLayoutInfo = NULL;
        }

        for (PartitionNumber = 1; ; PartitionNumber++)
        {
            swprintf(PartitionStr, L"\\Device\\Harddisk%d\\Partition%d", DeviceNumber, PartitionNumber);
            RtlInitUnicodeString(&PartitionName, PartitionStr);

            Status = HalpQueryPartitionType(&PartitionName, DriveLayoutInfo, &PartitionType);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("IoAssignDriveLetters: Status %X\n", Status);
                break;
            }

            if (PartitionType == 2)
                HalpNextDriveLetter(&PartitionName, NtDeviceName, OutDriveLetter, FALSE);
        }

        if (DriveLayoutInfo)
            ExFreePoolWithTag(DriveLayoutInfo, 'BtsF');
    }

    for (ix = 0; ix < DiskCount; ix++)
    {
        ULONG number = 0;

        if (NumbersArray)
            DeviceNumber = NumbersArray[ix];
        else
            DeviceNumber = ix;

        swprintf(PartitionStr, L"\\Device\\Harddisk%d\\Partition0", DeviceNumber);
        RtlInitUnicodeString(&PartitionName, PartitionStr);

        Status = HalpQueryDriveLayout(&PartitionName, &DriveLayoutInfo);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("IoAssignDriveLetters: Status %X\n", Status);
            DriveLayoutInfo = NULL;
        }

        for (PartitionNumber = 1; ; PartitionNumber++)
        {
            swprintf(PartitionStr, L"\\Device\\Harddisk%d\\Partition%d", DeviceNumber, PartitionNumber);
            RtlInitUnicodeString(&PartitionName, PartitionStr);

            Status = HalpQueryPartitionType(&PartitionName, DriveLayoutInfo, &PartitionType);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("IoAssignDriveLetters: Status %X\n", Status);
                break;
            }

            if ((PartitionType == 0) || (PartitionType == 1 && number == 0))
            {
                number = PartitionNumber;
                DPRINT1("IoAssignDriveLetters: number %X\n", number);
            }
        }

        for (PartitionNumber = 1; ; PartitionNumber++)
        {
            if (PartitionNumber == number)
                continue;

            swprintf(PartitionStr, L"\\Device\\Harddisk%d\\Partition%d", DeviceNumber, PartitionNumber);
            RtlInitUnicodeString(&PartitionName, PartitionStr);

            Status = HalpQueryPartitionType(&PartitionName, DriveLayoutInfo, &PartitionType);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("IoAssignDriveLetters: Status %X\n", Status);
                break;
            }

            if (PartitionType == 1 || PartitionType == 3)
                HalpNextDriveLetter(&PartitionName, NtDeviceName, OutDriveLetter, FALSE);
        }

        if (DriveLayoutInfo)
            ExFreePoolWithTag(DriveLayoutInfo, 'BtsF');
    }

    if (NumbersArray)
        ExFreePoolWithTag(NumbersArray, 'btsF');

    if (FloppyCount)
    {
        DPRINT1("IoAssignDriveLetters: FIXME! FloppyCount %X\n", FloppyCount);
        ASSERT(FALSE); // FsbDbgBreakPointEx();
    }

#if 0
    for (DeviceNumber = 0; DeviceNumber < FloppyCount; DeviceNumber++)
    {
        swprintf(PartitionStr, L"\\Device\\Floppy%d", DeviceNumber);
        RtlInitUnicodeString(&PartitionName, PartitionStr);

        if (HalpIsOldStyleFloppy(&PartitionName))
            HalpNextDriveLetter(&PartitionName, NtDeviceName, OutDriveLetter, TRUE);

        DeviceNumber++;
    }

    for (DeviceNumber = 0; DeviceNumber < FloppyCount; DeviceNumber++)
    {
        swprintf(PartitionStr, L"\\Device\\Floppy%d", DeviceNumber);
        RtlInitUnicodeString(&PartitionName, PartitionStr);

        if (!HalpIsOldStyleFloppy(&PartitionName))
            HalpNextDriveLetter(&PartitionName, NtDeviceName, OutDriveLetter, TRUE);
    }
#endif

    for (DeviceNumber = 0; DeviceNumber < CdRomCount; DeviceNumber++)
    {
        swprintf(PartitionStr, L"\\Device\\CdRom%d", DeviceNumber);
        RtlInitUnicodeString(&PartitionName, PartitionStr);
        HalpNextDriveLetter(&PartitionName, NtDeviceName, OutDriveLetter, TRUE);
    }

    if (IoRemoteBootClient)
    {
        DPRINT1("IoAssignDriveLetters: FIXME! IoRemoteBootClient is TRUE\n");
        ASSERT(FALSE); // FsbDbgBreakPointEx();
        goto Exit;
    }

    Status = RtlAnsiStringToUnicodeString(&DeviceName, NtDeviceName, TRUE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IoAssignDriveLetters: Status %X\n", Status);
        goto Exit;
    }

    DriveLetter = HalpNextDriveLetter(&DeviceName, NULL, NULL, TRUE);
    if (DriveLetter)
    {
        if (DriveLetter != -1)
        {
            DPRINT1("IoAssignDriveLetters: DriveLetter %X\n", DriveLetter);
            *OutDriveLetter = DriveLetter;
        }

        RtlFreeUnicodeString(&DeviceName);
        goto Exit;
    }

    RtlInitUnicodeString(&FloppyString, L"\\Device\\Floppy");
    RtlInitUnicodeString(&CdRomString, L"\\Device\\CdRom");

    if (RtlPrefixUnicodeString(&FloppyString, &DeviceName, TRUE))
    {
        DriveLetter = 'A';
    }
    else if (!RtlPrefixUnicodeString(&CdRomString, &DeviceName, TRUE))
    {
        DriveLetter = 'C';
    }
    else
    {
        DriveLetter = 'D';
    }

    for (; (DriveLetter <= 'Z'); DriveLetter++)
    {
        Status = HalpSetMountLetter(&DeviceName, DriveLetter);
        if (NT_SUCCESS(Status))
        {
            DPRINT1("IoAssignDriveLetters: DriveLetter %X\n", DriveLetter);
            *OutDriveLetter = DriveLetter;
            break;
        }
    }

    if (DriveLetter > 'Z')
    {
        DPRINT1("IoAssignDriveLetters: Assign letter for drive failed\n");
        ASSERT(FALSE); // FsbDbgBreakPointEx();

        HalpDeleteMountLetter('Z');
        HalpSetMountLetter(&DeviceName, 'Z');
        *OutDriveLetter = 'Z';

        DPRINT1("IoAssignDriveLetters: DriveLetter %X\n", *OutDriveLetter);
    }

    RtlFreeUnicodeString(&DeviceName);

Exit:
    HalpEnableAutomaticDriveLetterAssignment();
}

/* EOF */
