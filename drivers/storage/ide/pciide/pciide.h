#ifndef _PCIIDE_PCH_
#define _PCIIDE_PCH_

#include <ntddk.h>
#include <ide.h>

typedef struct _PCIIDE_CONTROLLER_EXTENSION
{
    PCI_COMMON_HEADER PciConfig;
    ULONG SupportedTransferMode[2][2];
    IDENTIFY_DATA IdentifyData[2];
} PCIIDE_CONTROLLER_EXTENSION, *PPCIIDE_CONTROLLER_EXTENSION;

#endif /* _PCIIDE_PCH_ */