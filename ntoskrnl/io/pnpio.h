#ifndef _PNPIO_H
#define _PNPIO_H

//
// debug.c
//
VOID
NTAPI
IopDumpCmResourceList(
    _In_ PCM_RESOURCE_LIST CmResource
);

VOID
NTAPI
IopDumpCmResourceDescriptor(
    _In_ PSTR Tab,
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor
);

//
// pnpres.c
//
NTSTATUS
NTAPI
IopWriteResourceList(
    _In_ HANDLE ResourceHandle,
    _In_ PUNICODE_STRING ResourceName,
    _In_ PUNICODE_STRING Description,
    _In_ PUNICODE_STRING ValueName,
    _In_ PCM_RESOURCE_LIST CmResource,
    _In_ ULONG ListSize
);

#endif  /* _PNPIO_H */
