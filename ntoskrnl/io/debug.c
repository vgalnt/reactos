/*
 * PROJECT:         ReactOS Kernel
 * COPYRIGHT:       GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/debug.c
 * PURPOSE:         functions for debug
 * PROGRAMMERS:     
 */

#include <ntoskrnl.h>
//#define NDEBUG
#include <debug.h>

VOID
NTAPI
IopDumpCmResourceDescriptor(
    _In_ PSTR Tab,
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor)
{
    PAGED_CODE();

    if ( !Descriptor )
    {
        DPRINT("IopDumpCmResourceDescriptor: Descriptor == NULL\n");
        return;
    }

    switch ( Descriptor->Type )
    {
        case 1:
            DPRINT("%s[%p] Share - %X, Flags - %X, IO:  Start - %X:%08X, Length - %X\n", Tab, Descriptor, Descriptor->ShareDisposition, Descriptor->Flags, Descriptor->u.Port.Start.HighPart, Descriptor->u.Port.Start.LowPart, Descriptor->u.Port.Length);
            break;
        case 2:
            DPRINT("%s[%p] Share - %X, Flags - %X, INT: Level - %X, Vector - %X, Affinity - %X\n", Tab, Descriptor, Descriptor->ShareDisposition, Descriptor->Flags, Descriptor->u.Interrupt.Level, Descriptor->u.Interrupt.Vector, Descriptor->u.Interrupt.Affinity);
            break;
        case 3:
            DPRINT("%s[%p] Share - %X, Flags - %X, MEM: Start - %X:%08X, Length - %X\n", Tab, Descriptor, Descriptor->ShareDisposition, Descriptor->Flags, Descriptor->u.Memory.Start.HighPart, Descriptor->u.Memory.Start.LowPart, Descriptor->u.Memory.Length);
            break;
        case 4:
            DPRINT("%s[%p] Share - %X, Flags - %X, DMA: Channel - %X, Port - %X\n", Tab, Descriptor, Descriptor->ShareDisposition, Descriptor->Flags, Descriptor->u.Dma.Channel, Descriptor->u.Dma.Port);
            break;
        case 5:
            DPRINT("%s[%p] Share - %X, Flags - %X, DAT: DataSize - %X\n", Tab, Descriptor, Descriptor->ShareDisposition, Descriptor->Flags, Descriptor->u.DeviceSpecificData.DataSize);
            break;
        case 6:
            DPRINT("%s[%p] Share - %X, Flags - %X, BUS: Start - %X, Length - %X, Reserved - %X\n", Tab, Descriptor, Descriptor->ShareDisposition, Descriptor->Flags, Descriptor, Descriptor->u.BusNumber.Start, Descriptor->u.BusNumber.Length, Descriptor->u.BusNumber.Reserved);
            break;
        default:
            DPRINT("%s[%p] Unknown Descriptor type %X\n", Tab, Descriptor, Descriptor->Type);
            break;
    }
}

static
PCM_PARTIAL_RESOURCE_DESCRIPTOR
NTAPI
IopGetNextCmPartialDescriptor(
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR NextDescriptor;

    /* Assume the descriptors are the fixed size ones */
    NextDescriptor = CmDescriptor + 1;

    /* But check if this is actually a variable-sized descriptor */
    if (CmDescriptor->Type == CmResourceTypeDeviceSpecific)
    {
        /* Add the size of the variable section as well */
        NextDescriptor = (PVOID)((ULONG_PTR)NextDescriptor +
                                 CmDescriptor->u.DeviceSpecificData.DataSize);
    }

    /* Now the correct pointer has been computed, return it */
    return NextDescriptor;
}

VOID
NTAPI
IopDumpCmResourceList(
    _In_ PCM_RESOURCE_LIST CmResource)
{
    PCM_FULL_RESOURCE_DESCRIPTOR FullList;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor;
    ULONG ix;
    ULONG jx;

    PAGED_CODE();
    DPRINT("IopDumpCmResourceList: CmResource - %p\n", CmResource);

    if ( !CmResource )
    {
        DPRINT("IopDumpCmResourceList: CmResource == NULL\n");
        return;
    }

    if ( !CmResource->Count )
    {
        DPRINT("IopDumpCmResourceList: CmResource->Count == 0\n");
        return;
    }

    DPRINT("  FullList Count - %x\n", CmResource->Count);

    FullList = &CmResource->List[0];

    for (ix = 0; ix < CmResource->Count; ix++)
    {
        DPRINT("  FullList #%X, InterfaceType - %X, Bus #%X, Ver.%X, Rev.%X, Descriptors count - %X\n",
               ix,
               FullList->InterfaceType,
               FullList->BusNumber,
               FullList->PartialResourceList.Version,
               FullList->PartialResourceList.Revision,
               FullList->PartialResourceList.Count);

        Descriptor = FullList->PartialResourceList.PartialDescriptors;

        for (jx = 0; jx < FullList->PartialResourceList.Count; jx++)
        {
            IopDumpCmResourceDescriptor("    ", Descriptor);
            Descriptor = IopGetNextCmPartialDescriptor(Descriptor);
        }

        FullList = (PCM_FULL_RESOURCE_DESCRIPTOR)IopGetNextCmPartialDescriptor(Descriptor);
    }
}

VOID
NTAPI
IopDumpIoResourceDescriptor(
    _In_ PSTR Tab,
    _In_ PIO_RESOURCE_DESCRIPTOR Descriptor)
{
    PAGED_CODE();

    if (!Descriptor)
    {
        DPRINT("IopDumpResourceDescriptor: Descriptor == 0\n");
        return;
    }

    switch (Descriptor->Type)
    {
        case CmResourceTypePort:
        {
            DPRINT("%s[%p] Opt - %X, Share - %X, IO:  Min - %X:%08X, Max - %X:%08X, Align - %X, Len - %X\n", Tab, Descriptor, Descriptor->Option, Descriptor->ShareDisposition, Descriptor->u.Port.MinimumAddress.HighPart, Descriptor->u.Port.MinimumAddress.LowPart, Descriptor->u.Port.MaximumAddress.HighPart, Descriptor->u.Port.MaximumAddress.LowPart, Descriptor->u.Port.Alignment, Descriptor->u.Port.Length);
            break;
        }
        case CmResourceTypeInterrupt:
        {
            DPRINT("%s[%p] Opt - %X, Share - %X, INT: Min - %X, Max - %X\n", Tab, Descriptor, Descriptor->Option, Descriptor->ShareDisposition, Descriptor->u.Interrupt.MinimumVector, Descriptor->u.Interrupt.MaximumVector);
            break;
        }
        case CmResourceTypeMemory:
        {
            DPRINT("%s[%p] Opt - %X, Share - %X, MEM: Min - %X:%08X, Max - %X:%08X, Align - %X, Len - %X\n", Tab, Descriptor, Descriptor->Option, Descriptor->ShareDisposition, Descriptor->u.Memory.MinimumAddress.HighPart, Descriptor->u.Memory.MinimumAddress.LowPart, Descriptor->u.Memory.MaximumAddress.HighPart, Descriptor->u.Memory.MaximumAddress.LowPart, Descriptor->u.Memory.Alignment, Descriptor->u.Memory.Length);
            break;
        }
        case CmResourceTypeDma:
        {
            DPRINT("%s[%p] Opt - %X, Share - %X, DMA: Min - %X, Max - %X\n", Tab, Descriptor, Descriptor->Option, Descriptor->ShareDisposition, Descriptor->u.Dma.MinimumChannel, Descriptor->u.Dma.MaximumChannel);
            break;
        }
        case CmResourceTypeBusNumber:
        {
            DPRINT("%s[%p] Opt - %X, Share - %X, BUS: Min - %X, Max - %X, Length - %X\n", Tab, Descriptor, Descriptor->Option, Descriptor->ShareDisposition, Descriptor->u.BusNumber.MinBusNumber, Descriptor->u.BusNumber.MaxBusNumber, Descriptor->u.BusNumber.Length);
            break;
        }
        case CmResourceTypeConfigData: //0x80
        {
            DPRINT("%s[%p] Opt - %X, Share - %X, CFG: Priority - %X\n", Tab, Descriptor, Descriptor->Option, Descriptor->ShareDisposition, Descriptor->u.ConfigData.Priority);
            break;
        }
        case CmResourceTypeDevicePrivate: //0x81
        {
            DPRINT("%s[%p] Opt - %X, Share - %X, DAT: %X, %X, %X\n", Tab, Descriptor, Descriptor->Option, Descriptor->ShareDisposition, Descriptor->u.DevicePrivate.Data[0], Descriptor->u.DevicePrivate.Data[1], Descriptor->u.DevicePrivate.Data[2]);
            break;
        }
        default:
        {
            DPRINT("%s[%p] Opt - %X, Share - %X. Unknown Descriptor type %X\n", Tab, Descriptor, Descriptor->Option, Descriptor->ShareDisposition, Descriptor->Type);
            break;
        }
    }
}

VOID
NTAPI
IopDumpResourceRequirementsList(
    _In_ PIO_RESOURCE_REQUIREMENTS_LIST IoResource)
{
    PIO_RESOURCE_LIST AltList;
    PIO_RESOURCE_DESCRIPTOR Descriptor;
    ULONG ix;
    ULONG jx;

    PAGED_CODE();
    DPRINT("IopDumpResourceRequirementsList: IoResource - %p\n", IoResource);

    if (!IoResource)
    {
        DPRINT("IopDumpResourceRequirementsList: IoResource == 0\n");
        return;
    }

    DPRINT("Interface - %X, Bus - %X, Slot - %X, AlternativeLists - %X\n",
           IoResource->InterfaceType,
           IoResource->BusNumber,
           IoResource->SlotNumber,
           IoResource->AlternativeLists);

    AltList = &IoResource->List[0];

    //ASSERT(IoResource->AlternativeLists < 2);

    if (IoResource->AlternativeLists < 1)
    {
        DPRINT("IopDumpResourceRequirementsList: IoResource->AlternativeLists < 1\n");
        return;
    }

    for (ix = 0; ix < IoResource->AlternativeLists; ix++)
    {
        DPRINT("  AltList - %p, AltList->Count - %X\n", AltList, AltList->Count);

        for (jx = 0; jx < AltList->Count; jx++)
        {
            Descriptor = &AltList->Descriptors[jx];
            IopDumpIoResourceDescriptor("    ", Descriptor);
        }

        AltList = (PIO_RESOURCE_LIST)(AltList->Descriptors + AltList->Count);
        DPRINT("End Descriptors - %p\n", AltList);
    }
}

/* EOF */
