
/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#include "ARM3/miarm.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

PMMPAGING_FILE MmPagingFile[MAX_PAGING_FILES]; /* List of paging files, both used and free */
KGUARDED_MUTEX MmPageFileCreationLock;         /* Lock for examining the list of paging files */

ULONG MmNumberOfPagingFiles; /* Number of paging files */
PFN_COUNT MiFreeSwapPages;   /* Number of pages that are available for swapping */
PFN_COUNT MiUsedSwapPages;   /* Number of pages that have been allocated for swapping */
BOOLEAN MmZeroPageFile;

/* Number of pages that have been reserved for swapping but not yet allocated */
static PFN_COUNT MiReservedSwapPages;

static BOOLEAN MmSwapSpaceMessage = FALSE;
static BOOLEAN MmSystemPageFileLocated = FALSE;
static BOOLEAN IsFirstPrint = TRUE;

extern SIZE_T MmTotalCommitLimitMaximum;

/* FUNCTIONS ******************************************************************/

#if defined (ALLOC_PRAGMA)
  #pragma alloc_text(INIT, MmInitPagingFile)
  #pragma alloc_text(PAGE, NtCreatePagingFile)
#endif

BOOLEAN
NTAPI
MmIsFileObjectAPagingFile(PFILE_OBJECT FileObject)
{
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

CODE_SEG("INIT")
VOID
NTAPI
MmInitPagingFile(VOID)
{
    ULONG ix;

    KeInitializeGuardedMutex(&MmPageFileCreationLock);

    MiFreeSwapPages = 0;
    MiUsedSwapPages = 0;
    MiReservedSwapPages = 0;

    for (ix = 0; ix < MAX_PAGING_FILES; ix++)
        MmPagingFile[ix] = NULL;

    MmNumberOfPagingFiles = 0;
}

BOOLEAN
NTAPI
MiReleasePageFileSpace(
    _In_ MMPTE PteContents)
{
    if (IsFirstPrint)
    {
        UNIMPLEMENTED;
        IsFirstPrint = FALSE;
    }

    return FALSE;
}

VOID
NTAPI
MiInsertPageFileInList(VOID)
{
    PFN_NUMBER FreeSpace;
    PFN_NUMBER MaximumSize;
    KIRQL OldIrql;

    //FIXME

    DPRINT1("MiInsertPageFileInList: MmTotalCommittedPages     %X\n", MmTotalCommittedPages);
    DPRINT1("MiInsertPageFileInList: MmTotalCommitLimit        %X\n", MmTotalCommitLimit);
    DPRINT1("MiInsertPageFileInList: MmTotalCommitLimitMaximum %X\n", MmTotalCommitLimitMaximum);

    OldIrql = MiLockPfnDb(APC_LEVEL);
    FreeSpace = MmPagingFile[MmNumberOfPagingFiles - 1]->FreeSpace;
    MaximumSize = MmPagingFile[MmNumberOfPagingFiles - 1]->MaximumSize;
    MiUnlockPfnDb(OldIrql, APC_LEVEL);

    InterlockedExchangeAddSizeT(&MmTotalCommitLimitMaximum, MaximumSize);
    InterlockedExchangeAddSizeT(&MmTotalCommitLimit, FreeSpace);

    DPRINT1("MiInsertPageFileInList: MmTotalCommittedPages     %X\n", MmTotalCommittedPages);
    DPRINT1("MiInsertPageFileInList: MmTotalCommitLimit        %X\n", MmTotalCommitLimit);
    DPRINT1("MiInsertPageFileInList: MmTotalCommitLimitMaximum %X\n", MmTotalCommitLimitMaximum);
}

/* SYSTEM CALLS ***************************************************************/

CODE_SEG("PAGE")
NTSTATUS
NTAPI
NtCreatePagingFile(
    _In_ PUNICODE_STRING FileName,
    _In_ PLARGE_INTEGER MinimumSize,
    _In_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG Reserved)
{
    FILE_FS_DEVICE_INFORMATION FsDeviceInfo;
    SECURITY_DESCRIPTOR SecurityDescriptor;
    OBJECT_ATTRIBUTES ObjectAttributes;
    LARGE_INTEGER SafeMinimumSize;
    LARGE_INTEGER SafeMaximumSize;
    LARGE_INTEGER AllocationSize;
    KPROCESSOR_MODE PreviousMode;
    UNICODE_STRING PageFileName;
    PMMPAGING_FILE PagingFile;
    IO_STATUS_BLOCK IoStatus;
    PFILE_OBJECT FileObject;
    HANDLE FileHandle;
    PWSTR Buffer;
    PACL Dacl;
    DEVICE_TYPE DeviceType;
    SIZE_T AllocMapSize;
    ULONG Count;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("NtCreatePagingFile: '%wZ', (%I64X:%I64X)\n", FileName, MinimumSize->QuadPart, MaximumSize->QuadPart);

    if (MmNumberOfPagingFiles >= MAX_PAGING_FILES)
    {
        DPRINT1("NtCreatePagingFile: STATUS_TOO_MANY_PAGING_FILES\n");
        return STATUS_TOO_MANY_PAGING_FILES;
    }

    PreviousMode = ExGetPreviousMode();

    if (PreviousMode != KernelMode)
    {
        if (SeSinglePrivilegeCheck(SeCreatePagefilePrivilege, PreviousMode) != TRUE)
        {
            DPRINT1("NtCreatePagingFile: STATUS_PRIVILEGE_NOT_HELD\n");
            return STATUS_PRIVILEGE_NOT_HELD;
        }

        _SEH2_TRY
        {
            SafeMinimumSize = ProbeForReadLargeInteger(MinimumSize);
            SafeMaximumSize = ProbeForReadLargeInteger(MaximumSize);
            PageFileName = ProbeForReadUnicodeString(FileName);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        SafeMinimumSize = *MinimumSize;
        SafeMaximumSize = *MaximumSize;

        PageFileName = *FileName;
    }

    /* Pagefiles can't be larger than 4GB and of course the minimum should be smaller than the maximum. */
    // TODO: Actually validate the lower bound of these sizes!
    if (SafeMinimumSize.u.HighPart)
    {
        DPRINT1("NtCreatePagingFile: STATUS_INVALID_PARAMETER_2\n");
        return STATUS_INVALID_PARAMETER_2;
    }

    if (SafeMaximumSize.u.HighPart)
    {
        DPRINT1("NtCreatePagingFile: STATUS_INVALID_PARAMETER_3\n");
        return STATUS_INVALID_PARAMETER_3;
    }

    if (SafeMaximumSize.u.LowPart < SafeMinimumSize.u.LowPart)
    {
        DPRINT1("NtCreatePagingFile: STATUS_INVALID_PARAMETER_MIX\n");
        return STATUS_INVALID_PARAMETER_MIX;
    }

    /* Validate the name length */
    if (!PageFileName.Length || PageFileName.Length > (128 * sizeof(WCHAR)))
    {
        DPRINT1("NtCreatePagingFile: STATUS_OBJECT_NAME_INVALID\n");
        return STATUS_OBJECT_NAME_INVALID;
    }

    /* We don't care about any potential UNICODE_NULL */
    PageFileName.MaximumLength = PageFileName.Length;

    /* Allocate a buffer to keep the name copy */
    Buffer = ExAllocatePoolWithTag(PagedPool, PageFileName.Length, TAG_MM);
    if (!Buffer)
    {
        DPRINT1("NtCreatePagingFile: STATUS_INSUFFICIENT_RESOURCES\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Copy the name */
    if (PreviousMode != KernelMode)
    {
        _SEH2_TRY
        {
            ProbeForRead(PageFileName.Buffer, PageFileName.Length, sizeof(WCHAR));
            RtlCopyMemory(Buffer, PageFileName.Buffer, PageFileName.Length);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            ExFreePoolWithTag(Buffer, TAG_MM);

            /* Return the exception code */
            _SEH2_YIELD(return _SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }
    else
    {
        RtlCopyMemory(Buffer, PageFileName.Buffer, PageFileName.Length);
    }

    /* Replace caller's buffer with ours */
    PageFileName.Buffer = Buffer;

    /* Create the security descriptor for the page file */
    Status = RtlCreateSecurityDescriptor(&SecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtCreatePagingFile: Status %X\n", Status);
        ExFreePoolWithTag(Buffer, TAG_MM);
        return Status;
    }

    /* Create the DACL: we will only allow two SIDs */
    Count = (sizeof(ACE) + RtlLengthSid(SeLocalSystemSid)) + sizeof(ACL);
    Count += (sizeof(ACE) + RtlLengthSid(SeAliasAdminsSid));

    Dacl = ExAllocatePoolWithTag(PagedPool, Count, 'lcaD');
    if (!Dacl)
    {
        DPRINT1("NtCreatePagingFile: STATUS_INSUFFICIENT_RESOURCES\n");
        ExFreePoolWithTag(Buffer, TAG_MM);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Initialize the DACL */
    Status = RtlCreateAcl(Dacl, Count, ACL_REVISION);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtCreatePagingFile: Status %X\n", Status);
        ExFreePoolWithTag(Dacl, 'lcaD');
        ExFreePoolWithTag(Buffer, TAG_MM);
        return Status;
    }

    /* Grant full access to admins */
    Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_ALL_ACCESS, SeAliasAdminsSid);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtCreatePagingFile: Status %X\n", Status);
        ExFreePoolWithTag(Dacl, 'lcaD');
        ExFreePoolWithTag(Buffer, TAG_MM);
        return Status;
    }

    /* Grant full access to SYSTEM */
    Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_ALL_ACCESS, SeLocalSystemSid);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtCreatePagingFile: Status %X\n", Status);
        ExFreePoolWithTag(Dacl, 'lcaD');
        ExFreePoolWithTag(Buffer, TAG_MM);
        return Status;
    }

    /* Attach the DACL to the security descriptor */
    Status = RtlSetDaclSecurityDescriptor(&SecurityDescriptor, TRUE, Dacl, FALSE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtCreatePagingFile: Status %X\n", Status);
        ExFreePoolWithTag(Dacl, 'lcaD');
        ExFreePoolWithTag(Buffer, TAG_MM);
        return Status;
    }

    InitializeObjectAttributes(&ObjectAttributes,
                               &PageFileName,
                               OBJ_KERNEL_HANDLE,
                               NULL,
                               &SecurityDescriptor);

    /* Make sure we can at least store a complete page:
       If we have 2048 BytesPerAllocationUnit (FAT16 < 128MB) there is a problem if the paging file is fragmented.
       Suppose the first cluster of the paging file is cluster 3042 but cluster 3043 is NOT part of the paging file but of another file.
       We can't write a complete page (4096 bytes) to the physical location of cluster 3042 then.
    */
    AllocationSize.QuadPart = (SafeMinimumSize.QuadPart + PAGE_SIZE);

    /* First, attempt to replace the page file, if existing */
    Status = IoCreateFile(&FileHandle,
                          (SYNCHRONIZE | WRITE_DAC | FILE_READ_DATA | FILE_WRITE_DATA),
                          &ObjectAttributes,
                          &IoStatus,
                          &AllocationSize,
                          (FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN),
                          FILE_SHARE_WRITE,
                          FILE_SUPERSEDE,
                          (FILE_DELETE_ON_CLOSE | FILE_NO_COMPRESSION | FILE_NO_INTERMEDIATE_BUFFERING),
                          NULL,
                          0,
                          CreateFileTypeNone,
                          NULL,
                          (SL_OPEN_PAGING_FILE | IO_NO_PARAMETER_CHECKING));

    /* If we failed, relax a bit constraints, someone may be already holding the the file, so share write,
       don't attempt to replace and don't delete on close (basically, don't do anything conflicting).
       This can happen if the caller attempts to extend a page file.
    */
    if (!NT_SUCCESS(Status))
    {
        ULONG ix;

        DPRINT1("NtCreatePagingFile: Status %X\n", Status);

        Status = IoCreateFile(&FileHandle,
                              (SYNCHRONIZE | FILE_WRITE_DATA),
                              &ObjectAttributes,
                              &IoStatus,
                              &AllocationSize,
                              (FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN),
                              (FILE_SHARE_WRITE | FILE_SHARE_READ),
                              FILE_OPEN,
                              (FILE_NO_COMPRESSION | FILE_NO_INTERMEDIATE_BUFFERING),
                              NULL,
                              0,
                              CreateFileTypeNone,
                              NULL,
                              (SL_OPEN_PAGING_FILE | IO_NO_PARAMETER_CHECKING));

        if (!NT_SUCCESS(Status))
        {
            DPRINT1("NtCreatePagingFile: Status %X\n", Status);
            ExFreePoolWithTag(Dacl, 'lcaD');
            ExFreePoolWithTag(Buffer, TAG_MM);
            return Status;
        }

        /* We opened it! Check we are that "someone" ;-)
           First, get the opened file object.
        */
        Status = ObReferenceObjectByHandle(FileHandle,
                                           (FILE_READ_DATA | FILE_WRITE_DATA),
                                           IoFileObjectType,
                                           KernelMode,
                                           (PVOID *)&FileObject,
                                           NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("NtCreatePagingFile: Status %X\n", Status);
            ZwClose(FileHandle);
            ExFreePoolWithTag(Dacl, 'lcaD');
            ExFreePoolWithTag(Buffer, TAG_MM);
            return Status;
        }

        /* Find if it matches a previous page file */
        PagingFile = NULL;

        /* FIXME: should be calling unsafe instead, we should already be in a guarded region */
        KeAcquireGuardedMutex(&MmPageFileCreationLock);

        if (MmNumberOfPagingFiles > 0)
        {
            ix = 0;

            while (MmPagingFile[ix]->FileObject->SectionObjectPointer != FileObject->SectionObjectPointer)
            {
                ix++;
                if (ix >= MmNumberOfPagingFiles)
                    break;
            }

            /* This is the matching page file */
            PagingFile = MmPagingFile[ix];
        }

        /* If we didn't find the page file, fail */
        if (!PagingFile)
        {
            KeReleaseGuardedMutex(&MmPageFileCreationLock);
            ObDereferenceObject(FileObject);
            ZwClose(FileHandle);
            ExFreePoolWithTag(Dacl, 'lcaD');
            ExFreePoolWithTag(Buffer, TAG_MM);
            return STATUS_NOT_FOUND;
        }

        /* Don't allow page file shrinking */
        if (PagingFile->MinimumSize > (SafeMinimumSize.QuadPart / PAGE_SIZE))
        {
            KeReleaseGuardedMutex(&MmPageFileCreationLock);
            ObDereferenceObject(FileObject);
            ZwClose(FileHandle);
            ExFreePoolWithTag(Dacl, 'lcaD');
            ExFreePoolWithTag(Buffer, TAG_MM);
            return STATUS_INVALID_PARAMETER_2;
        }

        if (PagingFile->MaximumSize > (SafeMaximumSize.QuadPart / PAGE_SIZE))
        {
            KeReleaseGuardedMutex(&MmPageFileCreationLock);
            ObDereferenceObject(FileObject);
            ZwClose(FileHandle);
            ExFreePoolWithTag(Dacl, 'lcaD');
            ExFreePoolWithTag(Buffer, TAG_MM);
            return STATUS_INVALID_PARAMETER_3;
        }

        /* FIXME: implement parameters checking and page file extension */
        UNIMPLEMENTED;

        KeReleaseGuardedMutex(&MmPageFileCreationLock);
        ObDereferenceObject(FileObject);
        ZwClose(FileHandle);
        ExFreePoolWithTag(Dacl, 'lcaD');
        ExFreePoolWithTag(Buffer, TAG_MM);
        return STATUS_NOT_IMPLEMENTED;
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtCreatePagingFile: Status %X\n", Status);
        ExFreePoolWithTag(Dacl, 'lcaD');
        ExFreePoolWithTag(Buffer, TAG_MM);
        return Status;
    }

    /* Set the security descriptor */
    if (NT_SUCCESS(IoStatus.Status))
    {
        Status = ZwSetSecurityObject(FileHandle, DACL_SECURITY_INFORMATION, &SecurityDescriptor);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("NtCreatePagingFile: Status %X\n", Status);
            ExFreePoolWithTag(Dacl, 'lcaD');
            ZwClose(FileHandle);
            ExFreePoolWithTag(Buffer, TAG_MM);
            return Status;
        }
    }

    /* DACL is no longer needed, free it */
    ExFreePoolWithTag(Dacl, 'lcaD');

    /* FIXME: To enable once page file managment is moved to ARM3 */
#if 0
    /* Check we won't overflow commit limit with the page file */
    if (MmTotalCommitLimitMaximum + (SafeMaximumSize.QuadPart / PAGE_SIZE) <= MmTotalCommitLimitMaximum)
    {
        ZwClose(FileHandle);
        ExFreePoolWithTag(Buffer, TAG_MM);
        return STATUS_INVALID_PARAMETER_3;
    }
#endif

    /* Set its end of file to minimal size */
    Status = ZwSetInformationFile(FileHandle,
                                  &IoStatus,
                                  &SafeMinimumSize,
                                  sizeof(LARGE_INTEGER),
                                  FileEndOfFileInformation);

    if (!NT_SUCCESS(Status) || !NT_SUCCESS(IoStatus.Status))
    {
        DPRINT1("NtCreatePagingFile: Status %X, IoStatus.Status %X\n", Status, IoStatus.Status);
        ZwClose(FileHandle);
        ExFreePoolWithTag(Buffer, TAG_MM);
        return Status;
    }

    Status = ObReferenceObjectByHandle(FileHandle,
                                       (FILE_READ_DATA | FILE_WRITE_DATA),
                                       IoFileObjectType,
                                       KernelMode,
                                       (PVOID *)&FileObject,
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtCreatePagingFile: Status %X\n", Status);
        ZwClose(FileHandle);
        ExFreePoolWithTag(Buffer, TAG_MM);
        return Status;
    }

    /* Only allow page file on a few device types */
    DeviceType = IoGetRelatedDeviceObject(FileObject)->DeviceType;

    if (DeviceType != FILE_DEVICE_DISK_FILE_SYSTEM &&
        DeviceType != FILE_DEVICE_NETWORK_FILE_SYSTEM &&
        DeviceType != FILE_DEVICE_DFS_VOLUME &&
        DeviceType != FILE_DEVICE_DFS_FILE_SYSTEM)
    {
        ObDereferenceObject(FileObject);
        ZwClose(FileHandle);
        ExFreePoolWithTag(Buffer, TAG_MM);
        return Status;
    }

    /* Deny page file creation on a floppy disk */
    FsDeviceInfo.Characteristics = 0;
    IoQueryVolumeInformation(FileObject, FileFsDeviceInformation, sizeof(FsDeviceInfo), &FsDeviceInfo, &Count);

    if (BooleanFlagOn(FsDeviceInfo.Characteristics, FILE_FLOPPY_DISKETTE))
    {
        DPRINT1("NtCreatePagingFile: STATUS_FLOPPY_VOLUME\n");
        ObDereferenceObject(FileObject);
        ZwClose(FileHandle);
        ExFreePoolWithTag(Buffer, TAG_MM);
        return STATUS_FLOPPY_VOLUME;
    }

    PagingFile = ExAllocatePoolWithTag(NonPagedPool, sizeof(*PagingFile), TAG_MM);
    if (!PagingFile)
    {
        DPRINT1("NtCreatePagingFile: STATUS_INSUFFICIENT_RESOURCES\n");
        ObDereferenceObject(FileObject);
        ZwClose(FileHandle);
        ExFreePoolWithTag(Buffer, TAG_MM);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(PagingFile, sizeof(*PagingFile));

    PagingFile->FileHandle = FileHandle;
    PagingFile->FileObject = FileObject;

    PagingFile->Size = (SafeMinimumSize.QuadPart / PAGE_SIZE);
    PagingFile->MinimumSize = PagingFile->Size;
    PagingFile->MaximumSize = (SafeMaximumSize.QuadPart / PAGE_SIZE);

    /* First page is never used: it's the header
       TODO: write it
    */
    PagingFile->FreeSpace = (ULONG)(PagingFile->Size - 1);
    PagingFile->CurrentUsage = 0;
    PagingFile->PageFileName = PageFileName;

    ASSERT(PagingFile->Size == (PagingFile->FreeSpace + PagingFile->CurrentUsage + 1));

    AllocMapSize = sizeof(RTL_BITMAP);
    AllocMapSize += (((PagingFile->MaximumSize + 31) / 32) * sizeof(ULONG));

    PagingFile->Bitmap = ExAllocatePoolWithTag(NonPagedPool, AllocMapSize, TAG_MM);
    if (!PagingFile->Bitmap)
    {
        DPRINT1("NtCreatePagingFile: STATUS_INSUFFICIENT_RESOURCES\n");
        ExFreePoolWithTag(PagingFile, TAG_MM);
        ObDereferenceObject(FileObject);
        ZwClose(FileHandle);
        ExFreePoolWithTag(Buffer, TAG_MM);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitializeBitMap(PagingFile->Bitmap,
                        (PULONG)(PagingFile->Bitmap + 1),
                        (ULONG)(PagingFile->MaximumSize));

    RtlClearAllBits(PagingFile->Bitmap);

    /* FIXME: should be calling unsafe instead, we should already be in a guarded region */
    KeAcquireGuardedMutex(&MmPageFileCreationLock);

    ASSERT(MmPagingFile[MmNumberOfPagingFiles] == NULL);
    MmPagingFile[MmNumberOfPagingFiles] = PagingFile;

    MmNumberOfPagingFiles++;
    MiInsertPageFileInList();

    MiFreeSwapPages += PagingFile->FreeSpace;

    KeReleaseGuardedMutex(&MmPageFileCreationLock);

    MmSwapSpaceMessage = FALSE;

    if (MmSystemPageFileLocated)
        return STATUS_SUCCESS;

    if (BooleanFlagOn(FileObject->DeviceObject->Flags, DO_SYSTEM_BOOT_PARTITION))
        MmSystemPageFileLocated = IoInitializeCrashDump(FileHandle);

    return STATUS_SUCCESS;
}

/* EOF */
