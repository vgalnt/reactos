/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/kd64/kd0.c
 * PURPOSE:         KD64 functions the kernel debugger for Phase 0.
 * PROGRAMMERS:     
 */

/* INCLUDES *****************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

#if DBG_KD0

BOOLEAN KdPitchKd0 = TRUE; // "NODEBUG" option in Command Line
BOOLEAN EnabledKd0 = FALSE;
BOOLEAN EnabledComKd0 = FALSE;
BOOLEAN EnabledScreenKd0 = FALSE;
BOOLEAN EnabledFileKd0 = FALSE;

/* Serial debug connection */
#define DEFAULT_DEBUG_PORT 2 /* COM2 */
#define DEFAULT_DEBUG_BAUD_RATE 115200 /* 115200 Baud */

const ULONG BaseArray[] = {0, 0x3F8, 0x2F8, 0x3E8, 0x2E8};

CPPORT KdComPort0 = {NULL, 0, TRUE};

/* DbgPrint0 Buffer */
CHAR KdPrintDefaultCircularBuffer_Kd0[KD_DEFAULT_LOG_BUFFER_SIZE];
PCHAR KdPrintWritePointer_Kd0 = KdPrintDefaultCircularBuffer_Kd0;
ULONG KdPrintRolloverCount_Kd0;
PCHAR KdPrintCircularBuffer_Kd0 = KdPrintDefaultCircularBuffer_Kd0;
ULONG KdPrintBufferSize_Kd0 = sizeof(KdPrintDefaultCircularBuffer_Kd0);
ULONG KdPrintBufferChanges_Kd0 = 0;
//KSPIN_LOCK KdpPrintSpinLock_Kd0;

#endif

/* FUNCTIONS *****************************************************************/

#if DBG_KD0

VOID
NTAPI
PatchKdStub(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"kdstub");
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    PIMAGE_NT_HEADERS NtHeaders;
    PLIST_ENTRY Entry;
    PVOID ImageBase = NULL;
    PULONG Cookie;
    ULONG LoadConfig;
    ULONG Size;
    BOOLEAN IsFound = FALSE;

    DbgPrint0("PatchKdStub: Flink %p\n", LoaderBlock->LoadOrderListHead.Flink);

    for (Entry = LoaderBlock->LoadOrderListHead.Flink;
         Entry != &LoaderBlock->LoadOrderListHead;
         Entry = Entry->Flink)
    {
        LdrEntry = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (LdrEntry->BaseDllName.Buffer[0] == Name.Buffer[0] &&
            LdrEntry->BaseDllName.Buffer[1] == Name.Buffer[1] &&
            LdrEntry->BaseDllName.Buffer[2] == Name.Buffer[2] &&
            LdrEntry->BaseDllName.Buffer[3] == Name.Buffer[3] &&
            LdrEntry->BaseDllName.Buffer[4] == Name.Buffer[4] &&
            LdrEntry->BaseDllName.Buffer[5] == Name.Buffer[5])
        {
            ImageBase = LdrEntry->DllBase;
            IsFound = TRUE;
            break;
        }
    }

    if (!IsFound)
    {
        DbgPrint0("PatchKdStub: Not found\n");
        return;
    }

    if (!ImageBase)
    {
        DbgPrint0("PatchKdStub: ImageBase is NULL\n");
        return;
    }

    DbgPrint0("PatchKdStub: Found %p\n", ImageBase);

    NtHeaders = RtlImageNtHeader(ImageBase);
    if (!NtHeaders)
    {
        DbgPrint0("PatchKdStub: NtHeaders is NULL\n");
        return;
    }

    LoadConfig = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
    Size = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;

    if (!LoadConfig)
    {
        DbgPrint0("PatchKdStub: LoadConfig is 0\n");
        return;
    }

    DbgPrint0("PatchKdStub: LoadConfig %X, Size %X\n", LoadConfig, Size);

    Cookie = *(PULONG *)Add2Ptr(ImageBase, (LoadConfig + 0x3C));

    DbgPrint0("PatchKdStub: Cookie %X\n", Cookie);

    if (!Cookie)
    {
        DbgPrint0("PatchKdStub: Cookie is 0\n");
        return;
    }

    DbgPrint0("PatchKdStub: *Cookie %X\n", *Cookie);

    if (*Cookie == 0xBB40E64E)
       *Cookie = 0xEFBEADDE;
}

VOID
NTAPI
KdLogDbgPrint0(
    _In_ PSTRING String)
{
    SIZE_T Length, Remaining;
    //KIRQL OldIrql;

    /* If the string is empty, bail out */
    if (!String->Buffer || (String->Length == 0))
        return;

    /* If no log buffer available, bail out */
    if (!KdPrintCircularBuffer_Kd0)
        return;

    /* Acquire the log spinlock without waiting at raised IRQL */
    //OldIrql = KdpAcquireLock(&KdpPrintSpinLock_Kd0);

    Length = min(String->Length, KdPrintBufferSize_Kd0);
    Remaining = KdPrintCircularBuffer_Kd0 + KdPrintBufferSize_Kd0 - KdPrintWritePointer_Kd0;

    if (Length < Remaining)
    {
        KdpMoveMemory(KdPrintWritePointer_Kd0, String->Buffer, Length);
        KdPrintWritePointer_Kd0 += Length;
    }
    else
    {
        KdpMoveMemory(KdPrintWritePointer_Kd0, String->Buffer, Remaining);
        Length -= Remaining;
        if (Length > 0)
            KdpMoveMemory(KdPrintCircularBuffer_Kd0, String->Buffer + Remaining, Length);

        KdPrintWritePointer_Kd0 = KdPrintCircularBuffer_Kd0 + Length;

        /* Got a rollover, update count (handle wrapping, must always be >= 1) */
        KdPrintRolloverCount_Kd0++;
        if (KdPrintRolloverCount_Kd0 == 0)
            KdPrintRolloverCount_Kd0++;
    }

    /* Release the spinlock */
    //KdpReleaseLock(&KdpPrintSpinLock_Kd0, OldIrql);
}

ULONG
__cdecl
DbgKdPrint0(
    _In_ PCHAR Format,
    ...)
{
    CHAR PrintBuffer[255];
    STRING OutputString;
    PCHAR pChar;
    USHORT Length;
    va_list ap;

    if (!EnabledKd0)
        return 0;

    va_start(ap, Format);

    if (ExpInitializationPhase != 0)
        return vDbgPrintExWithPrefix("", -1, DPFLTR_ERROR_LEVEL, Format, ap);

    /* Format the string */
    Length = (USHORT)_vsnprintf(PrintBuffer, sizeof(PrintBuffer), Format, ap);

    va_end(ap);

    /* Check if we went past the buffer */
    if (Length == 0xFFFF)
    {
        /* Terminate it if we went over-board */
        PrintBuffer[sizeof(PrintBuffer) - 1] = '\n';

        /* Put maximum */
        Length = sizeof(PrintBuffer);
    }

    /* Setup the output string */
    OutputString.Buffer = PrintBuffer;
    OutputString.Length = OutputString.MaximumLength = Length;

    /* Log the print */
    KdLogDbgPrint0(&OutputString);

    if (EnabledComKd0)
    {
        pChar = PrintBuffer;

        while (Length--)
        {
            //if (*pChar == '\n')
            //    CpPutByte(&KdComPort0, '\r');
            CpPutByte(&KdComPort0, *pChar++);
        }
    }

    if (EnabledScreenKd0)
    {
        ;
    }

    if (EnabledFileKd0)
    {
        ;
    }

    return 0;
}

NTSTATUS
NTAPI
KdpPortInitialize0(
    _In_ ULONG ComPortNumber,
    _In_ ULONG ComPortBaudRate)
{
    NTSTATUS Status;

    Status = CpInitialize(&KdComPort0, UlongToPtr(BaseArray[ComPortNumber]), ComPortBaudRate);
    if (!NT_SUCCESS(Status))
    {
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    return STATUS_SUCCESS;
}

VOID
NTAPI
KdInitDbg0(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    PSTR CommandLine;
    PSTR DebugLine;
    PSTR DebugOptionStart;
    PSTR DebugOptionEnd;
    SIZE_T DebugOptionLength;
    PCHAR PortString;
    PCHAR BaudString;
    ULONG Value;
    ULONG ComPortNumber = DEFAULT_DEBUG_PORT;
    ULONG ComPortBaudRate = DEFAULT_DEBUG_BAUD_RATE;
    NTSTATUS Status;

    /* Check if we have a loader block */
    if (!LoaderBlock)
    {
        KdPitchKd0 = TRUE;
        EnabledKd0 = FALSE;
        return;
    }

    /* Check if we have a command line */
    CommandLine = LoaderBlock->LoadOptions;
    if (!CommandLine)
    {
        KdPitchKd0 = TRUE;
        EnabledKd0 = FALSE;
        return;
    }

    /* Upcase it */
    _strupr(CommandLine);

    /* Assume we'll disable KD0 */
    EnabledKd0 = FALSE;

    /* Check for CRASHDEBUG, NODEBUG and just DEBUG */
    if (strstr(CommandLine, "CRASHDEBUG"))
    {
        /* Don't enable KD0 now, but allow it to be enabled later */
        KdPitchKd0 = FALSE;
    }
    else if (strstr(CommandLine, "NODEBUG"))
    {
        /* Don't enable KD0 and don't let it be enabled later */
        KdPitchKd0 = TRUE;
    }
    else if (strstr(CommandLine, "DEBUG") != NULL && (DebugLine = strstr(CommandLine, "DEBUGKD0")) != NULL)
    {
        /* Enable KD0 */
        EnabledKd0 = TRUE;

        /* Save pointers */
        DebugOptionStart = DebugOptionEnd = &DebugLine[9];

        /* Ex.: "/DEBUGKD0=COMKD0-COM1-115200,SCREENKD0,FILEKD0" */

        /* Scan the string for debug options */
        while (TRUE)
        {
            /* Loop until we reach the end of the string */
            while (*DebugOptionEnd != ANSI_NULL)
            {
                /* Check if this is a comma, a space or a tab */
                if (*DebugOptionEnd == ',' ||
                    *DebugOptionEnd == ' ' ||
                    *DebugOptionEnd == '\t')
                {
                    /* We reached the end of the option or the end of the string, break out */
                    break;
                }
                else
                {
                    /* Move on to the next character */
                    DebugOptionEnd++;
                }
            }

            /* Calculate the length of the current option */
            DebugOptionLength = (DebugOptionEnd - DebugOptionStart);

            /* Break out if we reached the last option or if there were no options at all */
            if (!DebugOptionLength) break;

            /* Now check which option this is */
            if (!(strncmp(DebugOptionStart, "COMKD0", 6)) && DebugOptionLength >= 16 && DebugOptionLength <= 18)
            {
                PortString = (DebugOptionStart + 6);
                BaudString = (DebugOptionStart + 11);

                if (PortString[0] == '-' && PortString[1] == 'C' && PortString[2] == 'O' && PortString[3] == 'M')
                {
                    Value = atol(PortString + 4);
                    if (Value < (sizeof(BaseArray) / sizeof(BaseArray[0])))
                    {
                        /* Set the port to use */
                        ComPortNumber = Value;

                        if (BaudString[0] == '-')
                        {
                            /* Read and set it */
                            Value = atol(BaudString + 1);
                            if (Value)
                                ComPortBaudRate = Value;
                        }
                   }
                }
            }
            else if (!(strncmp(DebugOptionStart, "SCREENKD0", 9)) && DebugOptionLength == 9)
            {
                EnabledScreenKd0 = TRUE;
            }
            else if (!(strncmp(DebugOptionStart, "FILEKD0", 7)) && DebugOptionLength == 7)
            {
                EnabledFileKd0 = TRUE;
            }

            /* If there are more options then the next character should be a comma */
            if (*DebugOptionEnd != ',')
                /* It isn't, break out  */
                break;

            /* Move on to the next option */
            DebugOptionEnd++;
            DebugOptionStart = DebugOptionEnd;
        }
    }

    /* Initialize the COM port */
    Status =  KdpPortInitialize0(ComPortNumber, ComPortBaudRate);

    if (!NT_SUCCESS(Status))
    {
        EnabledComKd0 = FALSE;
    }
    else
    {
        EnabledComKd0 = TRUE;
    }

    if (EnabledComKd0 || EnabledScreenKd0 || EnabledFileKd0)
    {
        EnabledKd0 = TRUE;
        DbgPrint0("KdInitDbg0: EnabledKd0 is TRUE (%X, %X, %X)\n", EnabledComKd0, EnabledScreenKd0, EnabledFileKd0);
    }
}

#endif

/* EOF */
