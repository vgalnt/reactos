
/* INCLUDES *******************************************************************/

#include <hal.h>
#define NDEBUG
#include <debug.h>

#include "apic.h"
#include "apicacpi.h"
#include "ioapic.h"

#ifdef ALLOC_PRAGMA
  #pragma alloc_text(INIT, HalpInitMpInfo)
  #pragma alloc_text(INIT, HalpVerifyIOUnit)
  #pragma alloc_text(INIT, HalpMarkProcessorStarted)
#endif

/* DATA ***********************************************************************/

LOCAL_APIC HalpStaticProcLocalApicTable[MAX_CPUS] = {{0}};
IO_APIC_VERSION_REGISTER HalpIOApicVersion[MAX_IOAPICS];
UCHAR HalpIoApicId[MAX_IOAPICS] = {0};
UCHAR HalpMaxProcs = 0;
PLOCAL_APIC HalpProcLocalApicTable = NULL;
PVOID * HalpLocalNmiSources = NULL;

/* GLOBALS ********************************************************************/

/* APIC */
extern HALP_MP_INFO_TABLE HalpMpInfoTable;
extern APIC_INTI_INFO HalpIntiInfo[MAX_INTI];
extern USHORT HalpMaxApicInti[MAX_IOAPICS];

/* ACPI */
extern ULONG HalpPicVectorRedirect[HAL_PIC_VECTORS];
extern ULONG HalpPicVectorFlags[HAL_PIC_VECTORS];

/* FUNCTIONS ******************************************************************/

//INIT_FUNCTION
VOID
NTAPI
HalpMarkProcessorStarted(
    _In_ UCHAR Id,
    _In_ ULONG PrcNumber)
{
    ULONG ix;

    for (ix = 0; ix < HalpMpInfoTable.ProcessorCount; ix++)
    {
        if (HalpProcLocalApicTable[ix].Id == Id)
        {
            HalpProcLocalApicTable[ix].ProcessorStarted = TRUE;
            HalpProcLocalApicTable[ix].ProcessorNumber = PrcNumber;

            if (PrcNumber == 0)
                HalpProcLocalApicTable[ix].FirstProcessor = TRUE;

            break;
        }
    }
}

//INIT_FUNCTION
BOOLEAN
NTAPI 
HalpVerifyIOUnit(
    _In_ PIO_APIC_REGISTERS IOUnitRegs)
{
    IO_APIC_VERSION_REGISTER IoApicVersion1;
    IO_APIC_VERSION_REGISTER IoApicVersion2;

    IOUnitRegs->IoRegisterSelect = IOAPIC_VER;
    IOUnitRegs->IoWindow = 0;

    IOUnitRegs->IoRegisterSelect = IOAPIC_VER;
    IoApicVersion1.AsULONG = IOUnitRegs->IoWindow;

    IOUnitRegs->IoRegisterSelect = IOAPIC_VER;
    IOUnitRegs->IoWindow = 0;

    IOUnitRegs->IoRegisterSelect = IOAPIC_VER;
    IoApicVersion2.AsULONG = IOUnitRegs->IoWindow;

    if (IoApicVersion1.ApicVersion != IoApicVersion2.ApicVersion ||
        IoApicVersion1.MaxRedirectionEntry != IoApicVersion2.MaxRedirectionEntry)
    {
        return FALSE;
    }

    return TRUE;
}

//INIT_FUNCTION
VOID
NTAPI 
HalpInitMpInfo(
    _In_ PACPI_TABLE_MADT ApicTable,
    _In_ ULONG Phase,
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    PACPI_SUBTABLE_HEADER Header;
    PACPI_MADT_LOCAL_APIC LocalApic;
    PIO_APIC_REGISTERS IoApicRegs;
    ULONG_PTR TableEnd;
    IO_APIC_VERSION_REGISTER IoApicVersion;
    PHYSICAL_ADDRESS PhAddress;
    PFN_COUNT PageCount;
    ULONG NmiIdx = 0;
    ULONG Size;
    ULONG ix = 0;
    ULONG Idx;
    UCHAR NumberProcs = 0;

    HalpMpInfoTable.LocalApicversion = 0x10;

    if (!(ApicTable->Flags & ACPI_MADT_DUAL_PIC))
    {
        KeBugCheckEx(MISMATCHED_HAL, 6, 0, 0, 0);
    }

    if (Phase == 0 && !HalpProcLocalApicTable)
    {
        /* First initialization */

        Header = (PACPI_SUBTABLE_HEADER)&ApicTable[1];
        TableEnd = ((ULONG_PTR)ApicTable + ApicTable->Header.Length);

        HalpProcLocalApicTable = HalpStaticProcLocalApicTable;

        while ((ULONG_PTR)Header < TableEnd)
        {
            LocalApic = (PACPI_MADT_LOCAL_APIC)Header;

            if (LocalApic->Header.Type == ACPI_MADT_TYPE_LOCAL_APIC && // Processor Local APIC
                LocalApic->Header.Length == sizeof(ACPI_MADT_LOCAL_APIC) &&
                LocalApic->LapicFlags & ACPI_MADT_ENABLED)
            {
                ix++;
            }

            if (!Header->Length)
                break;

            Header = (PACPI_SUBTABLE_HEADER)((ULONG_PTR)Header + Header->Length);
        }

        if (ix > MAX_CPUS)
        {
            Size = (ix * LOCAL_APIC_SIZE);
            PageCount = BYTES_TO_PAGES(Size);

            PhAddress.QuadPart = HalpAllocPhysicalMemory(LoaderBlock, 0xFFFFFFFF, PageCount, FALSE);
            if (!PhAddress.QuadPart)
            {
                ASSERT(PhAddress.QuadPart != 0);
                KeBugCheckEx(HAL_INITIALIZATION_FAILED, 0x105, 1, Size, PageCount);
            }

            HalpProcLocalApicTable = HalpMapPhysicalMemory64(PhAddress, PageCount);
            if (!HalpProcLocalApicTable)
            {
                ASSERT(HalpProcLocalApicTable != NULL);
                KeBugCheckEx(HAL_INITIALIZATION_FAILED, 0x105, 2, Size, PageCount);
            }

            RtlZeroMemory(HalpProcLocalApicTable, Size);
        }
    }

    Header = (PACPI_SUBTABLE_HEADER)&ApicTable[1];
    TableEnd = ((ULONG_PTR)ApicTable + ApicTable->Header.Length);

    for (ix = 0; ((ULONG_PTR)Header < TableEnd); )
    {
        if (Header->Type == ACPI_MADT_TYPE_LOCAL_APIC && // Processor Local APIC
            Header->Length == sizeof(ACPI_MADT_LOCAL_APIC))
        {
            LocalApic = (PACPI_MADT_LOCAL_APIC)Header;

            if (Phase == 0 && (LocalApic->LapicFlags & ACPI_MADT_ENABLED))
            {
                Idx = HalpMpInfoTable.ProcessorCount;

                HalpProcLocalApicTable[Idx].Id = LocalApic->Id;
                HalpProcLocalApicTable[Idx].ProcessorId = LocalApic->ProcessorId;

                HalpMpInfoTable.ProcessorCount++;
            }

            ix++;
            NumberProcs = ix;

            HalpMaxProcs = max(NumberProcs, HalpMaxProcs);

            Header = (PACPI_SUBTABLE_HEADER)((ULONG_PTR)Header + Header->Length);
        }
        else if (Header->Type == ACPI_MADT_TYPE_IO_APIC && // I/O APIC
                Header->Length == sizeof(ACPI_MADT_IO_APIC))
        {
            Idx = HalpMpInfoTable.IoApicCount;

            if (Phase == 0 && Idx < MAX_IOAPICS)
            {
                PACPI_MADT_IO_APIC IoApic = (PACPI_MADT_IO_APIC)Header;

                HalpIoApicId[Idx] = IoApic->Id;

                HalpMpInfoTable.IoApicIrqBase[Idx] = IoApic->GlobalIrqBase;
                HalpMpInfoTable.IoApicPA[Idx] = IoApic->Address;

                PhAddress.QuadPart = IoApic->Address;
                IoApicRegs = HalpMapPhysicalMemoryWriteThrough64(PhAddress, 1);

                if (!IoApicRegs)
                {
                    ASSERT(IoApicRegs != NULL);
                    KeBugCheckEx(HAL_INITIALIZATION_FAILED, 0x106, (ULONG_PTR)IoApic->Address, (ULONG_PTR)IoApic->Address, 0);
                }

                HalpMpInfoTable.IoApicVA[Idx] = (ULONG)IoApicRegs;

                IoApicRegs->IoRegisterSelect = IOAPIC_VER;
                IoApicRegs->IoWindow = 0;

                IoApicRegs->IoRegisterSelect = IOAPIC_VER;
                IoApicVersion.AsULONG = IoApicRegs->IoWindow;

                HalpIOApicVersion[Idx] = IoApicVersion;

                HalpMaxApicInti[Idx] = (IoApicVersion.MaxRedirectionEntry + 1);
                HalpMpInfoTable.IoApicCount++;

                ASSERT(HalpMpInfoTable.IoApicPA[Idx] == IoApic->Address);
            }

            ix = NumberProcs;
            Header = (PACPI_SUBTABLE_HEADER)((ULONG_PTR)Header + Header->Length);
        }
        else if (Header->Type == ACPI_MADT_TYPE_INTERRUPT_OVERRIDE && // Interrupt Source Override
                Header->Length == sizeof(ACPI_MADT_INTERRUPT_OVERRIDE))
        {
            if (Phase == 0)
            {
                PACPI_MADT_INTERRUPT_OVERRIDE InterruptOverride;
                InterruptOverride = (PACPI_MADT_INTERRUPT_OVERRIDE)Header;

                Idx = InterruptOverride->SourceIrq;
                HalpPicVectorRedirect[Idx] = InterruptOverride->GlobalIrq;
                HalpPicVectorFlags[Idx] = InterruptOverride->IntiFlags;

                ASSERT(HalpPicVectorRedirect[Idx] == InterruptOverride->GlobalIrq);
                ASSERT(HalpPicVectorFlags[Idx] == InterruptOverride->IntiFlags);
            }

            Header = (PACPI_SUBTABLE_HEADER)((ULONG_PTR)Header + Header->Length);
        }
        else if (Header->Type == ACPI_MADT_TYPE_NMI_SOURCE && // Non-maskable Interrupt Source (NMI)
                Header->Length == sizeof(ACPI_MADT_NMI_SOURCE))
        {
            if (Phase == 1)
            {
                PACPI_MADT_NMI_SOURCE NmiSource = (PACPI_MADT_NMI_SOURCE)Header;
                USHORT IntI;

                ASSERT(FALSE); // HalpDbgBreakPointEx();
                IntI=0;
                //if (HalpGetApicInterruptDesc(NmiSource->GlobalIrq, &IntI)) // Dbg1
                {
                    HalpIntiInfo[IntI].Type = 1; // NMI type

                    if ((NmiSource->IntiFlags & (8|4)) == 4 || // Edge-triggered
                        (NmiSource->IntiFlags & (8|4)) == 0)   // Conforms to specifications of the bus 
                    {
                        HalpIntiInfo[IntI].TriggerMode = 0; // Edge-triggered
                    }
                    else
                    {
                        HalpIntiInfo[IntI].TriggerMode = 1; // Level-triggered
                    }

                    HalpIntiInfo[IntI].Polarity = (USHORT)(NmiSource->IntiFlags & 0xFFFC);
                }
            }

            Header = (PACPI_SUBTABLE_HEADER)((ULONG_PTR)Header + Header->Length);
        }
        else if (Header->Type == ACPI_MADT_TYPE_LOCAL_APIC_NMI && // Local APIC NMI
                Header->Length == sizeof(ACPI_MADT_LOCAL_APIC_NMI))
        {
            if (Phase == 1)
            {
                if (!HalpLocalNmiSources)
                {
                    HalpLocalNmiSources = ExAllocatePoolWithTag(NonPagedPool, (HalpMaxProcs * 8), TAG_HAL);
                    if (!HalpLocalNmiSources)
                    {
                        ASSERT(HalpLocalNmiSources != NULL);
                        ASSERT(FALSE); // HalpDbgBreakPointEx();
                        KeBugCheckEx(HAL_INITIALIZATION_FAILED, 0x107, (ULONG_PTR)HalpMaxProcs, 0, 0);
                    }

                    RtlZeroMemory(HalpLocalNmiSources, (HalpMaxProcs * 8));
                }

                HalpLocalNmiSources[NmiIdx] = Header;
                NmiIdx++;
            }

            Header = (PACPI_SUBTABLE_HEADER)((ULONG_PTR)Header + Header->Length);
        }
        else
        {
            Header = (PACPI_SUBTABLE_HEADER)((ULONG_PTR)Header + 1);
        }
    }
}

/* EOF */
