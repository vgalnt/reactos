
#ifndef _APICACPI_H_
#define _APICACPI_H_

typedef union _IO_APIC_VERSION_REGISTER
{
    struct
    {
        UCHAR ApicVersion;
        UCHAR Reserved0;
        UCHAR MaxRedirectionEntry;
        UCHAR Reserved2;
    };
    ULONG AsULONG;

} IO_APIC_VERSION_REGISTER, *PIO_APIC_VERSION_REGISTER;

#include <pshpack1.h>
typedef struct _LOCAL_APIC
{
    UCHAR ProcessorId;
    UCHAR Id;
    UCHAR ProcessorNumber;
    BOOLEAN ProcessorStarted;
    BOOLEAN FirstProcessor;

} LOCAL_APIC, *PLOCAL_APIC;
#define LOCAL_APIC_SIZE sizeof(LOCAL_APIC)
#include <poppack.h>

//INIT_FUNCTION
BOOLEAN
NTAPI 
HalpVerifyIOUnit(
    _In_ PIO_APIC_REGISTERS IOUnitRegs
);

//INIT_FUNCTION
VOID
NTAPI
HalpMarkProcessorStarted(
    _In_ UCHAR Id,
    _In_ ULONG PrcNumber
);

#endif /* !_APICACPI_H_ */
