
/* INCLUDES *******************************************************************/

#include <hal.h>
//#define NDEBUG
#include <debug.h>

/* GLOBALS  *******************************************************************/

UCHAR HalpSerialLen;
CHAR HalpSerialNumber[31];

/* This determines the HAL type */
BOOLEAN HalDisableFirmwareMapper = TRUE;

/* PRIVATE FUNCTIONS **********************************************************/

#if defined(ALLOC_PRAGMA) && !defined(_MINIHAL_)
  #pragma alloc_text(PAGE, HalpOpenRegistryKey)
  #pragma alloc_text(INIT, HalpReportSerialNumber)
  #pragma alloc_text(PAGE, HalpMarkAcpiHal)
#endif

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HalpOpenRegistryKey(
    _In_ PHANDLE KeyHandle,
    _In_ HANDLE RootKey,
    _In_ PUNICODE_STRING KeyName,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ BOOLEAN Create)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    ULONG Disposition;
    NTSTATUS Status;

    /* Setup the attributes we received */
    InitializeObjectAttributes(&ObjectAttributes, KeyName, OBJ_CASE_INSENSITIVE, RootKey, NULL);

    /* What to do? */
    if (!Create)
    {
        /* Open the key */
        Status = ZwOpenKey(KeyHandle, DesiredAccess, &ObjectAttributes);
        return Status;
    }

    /* Create the key */
    Status = ZwCreateKey(KeyHandle, DesiredAccess, &ObjectAttributes, 0, NULL, REG_OPTION_VOLATILE, &Disposition);
    return Status;
}

CODE_SEG("INIT")
VOID
NTAPI
HalpReportSerialNumber(VOID)
{
    UNICODE_STRING KeyString;
    HANDLE Handle;
    NTSTATUS Status;

    /* Make sure there is a serial number */
    if (!HalpSerialLen)
        return;

    /* Open the system key */
    RtlInitUnicodeString(&KeyString, L"\\Registry\\Machine\\Hardware\\Description\\System");

    Status = HalpOpenRegistryKey(&Handle, 0, &KeyString, KEY_ALL_ACCESS, FALSE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpReportSerialNumber: Status %X\n", Status);
        return;
    }

    /* Add the serial number */
    RtlInitUnicodeString(&KeyString, L"Serial Number");

    ZwSetValueKey(Handle, &KeyString, 0, REG_BINARY, HalpSerialNumber, HalpSerialLen);

    /* Close the handle */
    ZwClose(Handle);
}

CODE_SEG("PAGE")
NTSTATUS
NTAPI
HalpMarkAcpiHal(VOID)
{
    ULONG Value = (HalDisableFirmwareMapper ? 1 : 0);
    UNICODE_STRING KeyString;
    HANDLE KeyHandle;
    HANDLE Handle;
    NTSTATUS Status;

    /* Open the control set key */
    RtlInitUnicodeString(&KeyString, L"\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET");

    Status = HalpOpenRegistryKey(&Handle, 0, &KeyString, KEY_ALL_ACCESS, FALSE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpMarkAcpiHal: Status %X\n", Status);
        return Status;
    }

    /* Open the PNP key */
    RtlInitUnicodeString(&KeyString, L"Control\\Pnp");

    Status = HalpOpenRegistryKey(&KeyHandle, Handle, &KeyString, KEY_ALL_ACCESS, TRUE);

    /* Close root key */
    ZwClose(Handle);

    /* Check if PNP BIOS key exists */
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpMarkAcpiHal: Status %X\n", Status);
        return Status;
    }

    /* Set the disable value to false -- we need the mapper */
    RtlInitUnicodeString(&KeyString, L"DisableFirmwareMapper");

    Status = ZwSetValueKey(KeyHandle, &KeyString, 0, REG_DWORD, &Value, sizeof(Value));
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("HalpMarkAcpiHal: Status %X\n", Status);
    }

    /* Close subkey */
    ZwClose(KeyHandle);

    /* Return status */
    return Status;
}

VOID
NTAPI
HalpFlushTLB(VOID)
{
    ULONG_PTR Flags, Cr4;
    INT CpuInfo[4];
    ULONG_PTR PageDirectory;

    /* Disable interrupts */
    Flags = __readeflags();
    _disable();

    /* Get page table directory base */
    PageDirectory = __readcr3();

    /* Check for CPUID support */
    if (KeGetCurrentPrcb()->CpuID)
    {
        /* Check for global bit in CPU features */
        __cpuid(CpuInfo, 1);

        if (CpuInfo[3] & 0x2000)
        {
            /* Get current CR4 value */
            Cr4 = __readcr4();

            /* Disable global bit */
            __writecr4(Cr4 & ~CR4_PGE);

            /* Flush TLB and re-enable global bit */
            __writecr3(PageDirectory);
            __writecr4(Cr4);

            /* Restore interrupts */
            __writeeflags(Flags);
            return;
        }
    }

    /* Legacy: just flush TLB */
    __writecr3(PageDirectory);
    __writeeflags(Flags);
}

VOID
NTAPI
KeFlushWriteBuffer(VOID)
{
    // Not implemented on x86
    return;
}

/* PUBLIC FUNCTIONS **********************************************************/

VOID
NTAPI
HalHandleNMI(
    _In_ PVOID NmiInfo)
{
    UNIMPLEMENTED;
    ASSERT(FALSE); // HalpDbgBreakPointEx();

    /* Freeze the system */
    while (TRUE);
}

UCHAR
FASTCALL
HalSystemVectorDispatchEntry(
    _In_ ULONG Vector,
    _Out_ PKINTERRUPT_ROUTINE** FlatDispatch,
    _Out_ PKINTERRUPT_ROUTINE* NoConnection)
{
    return 0;
}

/* EOF */
