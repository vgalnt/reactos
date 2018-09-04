/*
 * PROJECT:         ReactOS Kernel
 * COPYRIGHT:       GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/debug.c
 * PURPOSE:         functions for debug
 * PROGRAMMERS:     
 */

#include <ntoskrnl.h>
#include "pnpio.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

extern PDEVICE_NODE IopRootDeviceNode;

/* FUNCTIONS ******************************************************************/

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

        FullList = (PCM_FULL_RESOURCE_DESCRIPTOR)Descriptor;
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

PWCHAR
NTAPI
IopGetBusName(
    _In_ INTERFACE_TYPE IfType)
{
    switch (IfType)
    {
       case Internal:
         return L"Internal";

       case Isa:
         return L"Isa";

       case Eisa:
         return L"Eisa";

       case MicroChannel:
         return L"MicroChannel";

       case TurboChannel:
         return L"TurboChannel";

       case PCIBus:
         return L"PCIBus";

       case VMEBus:
         return L"VMEBus";

       case NuBus:
         return L"NuBus";

       case PCMCIABus:
         return L"PCMCIABus";

       case CBus:
         return L"CBus";

       case MPIBus:
         return L"MPIBus";

       case MPSABus:
         return L"MPSABus";

       case ProcessorInternal:
         return L"ProcessorInternal";

       case PNPISABus:
         return L"PNPISABus";

       case PNPBus:
         return L"PNPBus";

       case Vmcs:
         return L"Other";

       case MaximumInterfaceType:
         return L"Root";

       default:
         DPRINT1("Invalid bus type: %d\n", IfType);
         return NULL;
    }
}

PWSTR
NTAPI
PipGetDeviceNodeStateName(
    _In_ PNP_DEVNODE_STATE State)
{
    PWSTR Name;

    switch (State)
    {
        case DeviceNodeUnspecified:
            Name = L"DeviceNodeUnspecified";
            break;
        case DeviceNodeUninitialized:
            Name = L"DeviceNodeUninitialized";
            break;
        case DeviceNodeInitialized:
            Name = L"DeviceNodeInitialized";
            break;
        case DeviceNodeDriversAdded:
            Name = L"DeviceNodeDriversAdded";
            break;
        case DeviceNodeResourcesAssigned:
            Name = L"DeviceNodeResourcesAssigned";
            break;
        case DeviceNodeStartPending:
            Name = L"DeviceNodeStartPending";
            break;
        case DeviceNodeStartCompletion:
            Name = L"DeviceNodeStartCompletion";
            break;
        case DeviceNodeStartPostWork:
            Name = L"DeviceNodeStartPostWork";
            break;
        case DeviceNodeStarted:
            Name = L"DeviceNodeStarted";
            break;
        case DeviceNodeQueryStopped:
            Name = L"DeviceNodeQueryStopped";
            break;
        case DeviceNodeStopped:
            Name = L"DeviceNodeStopped";
            break;
        case DeviceNodeRestartCompletion:
            Name = L"DeviceNodeRestartCompletion";
            break;
        case DeviceNodeEnumeratePending:
            Name = L"DeviceNodeEnumeratePending";
            break;
        case DeviceNodeEnumerateCompletion:
            Name = L"DeviceNodeEnumerateCompletion";
            break;
        case DeviceNodeAwaitingQueuedDeletion:
            Name = L"DeviceNodeAwaitingQueuedDeletion";
            break;
        case DeviceNodeAwaitingQueuedRemoval:
            Name = L"DeviceNodeAwaitingQueuedRemoval";
            break;
        case DeviceNodeQueryRemoved:
            Name = L"DeviceNodeQueryRemoved";
            break;
        case DeviceNodeRemovePendingCloses:
            Name = L"DeviceNodeRemovePendingCloses";
            break;
        case DeviceNodeRemoved:
            Name = L"DeviceNodeRemoved";
            break;
        case DeviceNodeDeletePendingCloses:
            Name = L"DeviceNodeDeletePendingCloses";
            break;
        case DeviceNodeDeleted:
            Name = L"DeviceNodeDeleted";
            break;
        default:
            if (State != MaxDeviceNodeState)
            {
                ASSERT(FALSE);
            }
            break;
    }

    return Name;
}

VOID
NTAPI
PipDumpDeviceNodes(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ ULONG Level,
    _In_ ULONG Flags)
{
    PDEVICE_NODE ChildDeviceNode;
    PPI_RESOURCE_ARBITER_ENTRY ArbiterEntry;
    PARBITER_INSTANCE Arbiter;
    PLIST_ENTRY ArbiterListHead;
    PLIST_ENTRY Entry;

    DPRINT("Level - %X DevNode - %p for PDO - %p\n", Level, DeviceNode, DeviceNode->PhysicalDeviceObject);
    DPRINT("InstancePath    - %wZ\n", &DeviceNode->InstancePath);
    if (DeviceNode->ServiceName.Length)
    {
    DPRINT("ServiceName     - %wZ\n", &DeviceNode->ServiceName);
    }

    DPRINT("State           - %X, %S\n", DeviceNode->State, PipGetDeviceNodeStateName(DeviceNode->State));
    DPRINT("Previous State  - %X, %S\n", DeviceNode->PreviousState, PipGetDeviceNodeStateName(DeviceNode->PreviousState));
    if (DeviceNode->Problem)
    {
    DPRINT("Problem         - %X\n", DeviceNode->Problem);
    }

    ArbiterListHead = &DeviceNode->DeviceArbiterList;

    for (Entry = DeviceNode->DeviceArbiterList.Flink;
         Entry != ArbiterListHead;
         Entry = Entry->Flink)
    {
        ArbiterEntry = CONTAINING_RECORD(Entry, PI_RESOURCE_ARBITER_ENTRY, DeviceArbiterList);
        ASSERT(ArbiterEntry);

        Arbiter = (PARBITER_INSTANCE)ArbiterEntry->ArbiterInterface->Context;
        ASSERT(Arbiter);

        DPRINT("ArbiterEntry(%X) - %X\n", ArbiterEntry->ResourceType, ArbiterEntry);
        DPRINT("Arbiter           - %S\n", Arbiter->Name);
    }

    if (Flags & 2)
    {
        /* Display boot configuration (reported by IRP_MN_QUERY_RESOURCES) and AllocatedResources */
        if (DeviceNode->ResourceList)
        {
            DPRINT("------------ ResourceList ------------\n");
            IopDumpCmResourceList(DeviceNode->ResourceList);
        }

        if (DeviceNode->BootResources)
        {
            DPRINT("------------ BootResources ------------\n");
            IopDumpCmResourceList(DeviceNode->BootResources);
        }
    }

    if (Flags & 4)
    {
        /* Display resources required (reported by IRP_MN_FILTER_RESOURCE_REQUIREMENTS) */
        if (DeviceNode->ResourceRequirements)
        {
            DPRINT("------------ ResourceRequirements ------------\n");
            IopDumpResourceRequirementsList(DeviceNode->ResourceRequirements);
        }

    }

    if (Flags & 8)
    {
        /* Display translated resources (AllocatedResourcesTranslated)  */
        if (DeviceNode->ResourceListTranslated)
        {
            DPRINT("------------ ResourceListTranslated ------------\n");
            IopDumpCmResourceList(DeviceNode->ResourceListTranslated);
        }
    }

    if (Flags & 1)
    {
        /* Traversal of all children nodes */
        for (ChildDeviceNode = DeviceNode->Child;
             ChildDeviceNode != NULL;
             ChildDeviceNode = ChildDeviceNode->Sibling)
        {
            PipDumpDeviceNodes(ChildDeviceNode, Level + 1, Flags);
        }
    }
}

/* Displays information about a node in the device tree.
   See !devnode extension for WinDbg.
   devnode (Address [Flags] [Service])
   devnode (NULL,     1,      NULL)   - displays the entire device tree.
   devnode (1,        0,      NULL)   - displays all pending removals of device objects
   devnode (2,        0,      NULL)   - displays all pending ejects of device objects
*/

VOID
NTAPI
devnode(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ ULONG Flags,
    _In_ PUNICODE_STRING ServiceName)
{
    DPRINT("devnode: DeviceNode - %X, Flags - %X, ServiceName - %X\n",
           DeviceNode, Flags, ServiceName);

    if (DeviceNode == ULongToPtr(1) ||
        DeviceNode == ULongToPtr(2))
    {
        DPRINT("devnode: FIXME [pending removals] and [pending ejects] NOT IMPLEMENTED\n");
        ASSERT(FALSE);
        return;
    }

    if (ServiceName)
    {
        DPRINT("devnode: FIXME [ServiceName] - %zW NOT IMPLEMENTED\n", ServiceName);
        ASSERT(FALSE);
    }

    if (!DeviceNode)
    {
        DeviceNode = IopRootDeviceNode;
    }

    PipDumpDeviceNodes(DeviceNode, 0, Flags);
}

//--------------------------------------------------------------------------

VOID
NTAPI
IopDumpReqDescriptor(
    _In_ PPNP_REQ_DESCRIPTOR Descriptor,
    _In_ ULONG Idx)
{
    PAGED_CODE();
    DPRINT("=== IopDumpReqDescriptor [%X]: %p ======\n", Idx, Descriptor);
    DPRINT("InterfaceType                - %X\n", Descriptor->InterfaceType);
    DPRINT("BusNumber                    - %X\n", Descriptor->BusNumber);
    DPRINT("IsArbitrated                 - %X\n", Descriptor->IsArbitrated);
    DPRINT("AltList                      - %p\n", Descriptor->AltList);
    DPRINT("DescNumber                   - %X\n", Descriptor->DescNumber);
    DPRINT("TranslatedReqDesc            - %p\n", Descriptor->TranslatedReqDesc);
    DPRINT("-------------------------------------\n");
    DPRINT("ReqEntry.Link.Flink          - %p\n", Descriptor->ReqEntry.Link.Flink);
    DPRINT("ReqEntry.Link.Blink          - %p\n", Descriptor->ReqEntry.Link.Blink);
    DPRINT("ReqEntry.Count               - %X\n", Descriptor->ReqEntry.Count);
    DPRINT("ReqEntry.IoDescriptor        - %p\n", Descriptor->ReqEntry.IoDescriptor);
    DPRINT("ReqEntry.PhysicalDevice      - %p\n", Descriptor->ReqEntry.PhysicalDevice);
    DPRINT("ReqEntry.AllocationType      - %X\n", Descriptor->ReqEntry.AllocationType);
    DPRINT("ReqEntry.Reserved1           - %X\n", Descriptor->ReqEntry.Reserved1);
    DPRINT("ReqEntry.Reserved2           - %X\n", Descriptor->ReqEntry.Reserved2);
    DPRINT("ReqEntry.InterfaceType       - %X\n", Descriptor->ReqEntry.InterfaceType);
    DPRINT("ReqEntry.SlotNumber          - %X\n", Descriptor->ReqEntry.SlotNumber);
    DPRINT("ReqEntry.BusNumber           - %X\n", Descriptor->ReqEntry.BusNumber);
    DPRINT("ReqEntry.pCmDescriptor       - %p\n", Descriptor->ReqEntry.pCmDescriptor);
    DPRINT("ReqEntry.Reserved3           - %X\n", Descriptor->ReqEntry.Reserved3);
    DPRINT("ReqEntry.Reserved4           - %X\n", Descriptor->ReqEntry.Reserved4);
    DPRINT("ReqEntry.CmDesc.Type         - %X\n", Descriptor->ReqEntry.CmDescriptor.Type);
    DPRINT("ReqEntry.CmDesc.Share        - %X\n", Descriptor->ReqEntry.CmDescriptor.ShareDisposition);
    DPRINT("ReqEntry.CmDesc.Flags        - %X\n", Descriptor->ReqEntry.CmDescriptor.Flags);
    DPRINT("ReqEntry.CmDesc.StartLo      - %X\n", Descriptor->ReqEntry.CmDescriptor.u.Generic.Start.LowPart);
    DPRINT("ReqEntry.CmDesc.StartHi      - %X\n", Descriptor->ReqEntry.CmDescriptor.u.Generic.Start.HighPart);
    DPRINT("ReqEntry.CmDesc.Length       - %X\n", Descriptor->ReqEntry.CmDescriptor.u.Generic.Length);
    DPRINT("-------------------------------------\n");
    DPRINT("DescriptorsCount             - %p\n", Descriptor->DescriptorsCount);
    DPRINT("DevicePrivateIoDesc          - %p\n", Descriptor->DevicePrivateIoDesc);
    DPRINT("(Arbiter|Translator)Entry    - %p\n", Descriptor->ArbiterEntry);
    DPRINT("=== IopDumpReqDescriptor end ===========\n");
    DPRINT("\n");
}

VOID
NTAPI
IopDumpAltList(
    _In_ PPNP_REQ_ALT_LIST AltList,
    _In_ ULONG Idx)
{
    ULONG ix;
    PAGED_CODE();

    DPRINT("=== IopDumpAltList [%X]: %p ======\n", Idx, AltList);
    DPRINT("ConfigPriority               - %X\n", AltList->ConfigPriority);
    DPRINT("Priority                     - %X\n", AltList->Priority);
    DPRINT("ReqList                      - %p\n", AltList->ReqList);
    DPRINT("ListNumber                   - %X\n", AltList->ListNumber);
    DPRINT("CountDescriptors             - %X\n", AltList->CountDescriptors);
    DPRINT("=== IopDumpAltList end =================\n");

    for (ix = 0; ix < AltList->CountDescriptors; ix++)
    {
        IopDumpReqDescriptor(AltList->ReqDescriptors[ix], ix);
    }
}

VOID
NTAPI
IopDumpResRequest(
    _In_ PPNP_RESOURCE_REQUEST ResRequest)
{
    ULONG ix;
    PAGED_CODE();

    DPRINT("=== IopDumpResRequest %p =======\n", ResRequest);
    DPRINT("PhysicalDevice               - %p\n", ResRequest->PhysicalDevice);
    DPRINT("Flags                        - %X\n", ResRequest->Flags);
    DPRINT("AllocationType               - %X\n", ResRequest->AllocationType);
    DPRINT("Priority                     - %X\n", ResRequest->Priority);
    DPRINT("Position                     - %X\n", ResRequest->Position);
    DPRINT("ResourceRequirements         - %p\n", ResRequest->ResourceRequirements);
    DPRINT("ReqList                      - %p\n", ResRequest->ReqList);
    DPRINT("ResourceAssignment           - %p\n", ResRequest->ResourceAssignment);
    DPRINT("TranslatedResourceAssignment - %p\n", ResRequest->TranslatedResourceAssignment);
    DPRINT("Status                       - %X\n", ResRequest->Status);
    DPRINT("=== IopDumpResRequest end ===========\n");

    if (!ResRequest->ReqList)
    {
        return;
    }

    DPRINT("InterfaceType                - %X\n", ResRequest->ReqList->InterfaceType);
    DPRINT("BusNumber                    - %X\n", ResRequest->ReqList->BusNumber);
    DPRINT("ResRequest                   - %p\n", ResRequest->ReqList->ResRequest);
    DPRINT("AltList1                     - %p\n", ResRequest->ReqList->AltList1);
    DPRINT("AltList2                     - %p\n", ResRequest->ReqList->AltList2);
    DPRINT("Count                        - %X\n", ResRequest->ReqList->Count);
    DPRINT("IopDumpResRequest: ===========================\n");

    for (ix = 0; ix < ResRequest->ReqList->Count; ix++)
    {
        IopDumpAltList(ResRequest->ReqList->AltLists[ix], ix);
    }
}

//--------------------------------------------------------------------------

/* EOF */
