/*
 * PROJECT:         ReactOS Kernel
 * COPYRIGHT:       GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/io/pnpmgr/pnpres.c
 * PURPOSE:         Resource handling code
 * PROGRAMMERS:     Cameron Gutman (cameron.gutman@reactos.org)
 *                  ReactOS Portable Systems Group
 */

#include <ntoskrnl.h>
#include "../pnpio.h"

//#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

extern PPNP_RESERVED_RESOURCES_CONTEXT IopInitReservedResourceList;
extern KSEMAPHORE PpRegistrySemaphore;
extern INTERFACE_TYPE PnpDefaultInterfaceType;
extern BOOLEAN IopBootConfigsReserved;
extern LIST_ENTRY IopLegacyBusInformationTable[MaximumInterfaceType];

/* DATA **********************************************************************/

/* FUNCTIONS *****************************************************************/

static
BOOLEAN
IopCheckDescriptorForConflict(PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDesc, OPTIONAL PCM_PARTIAL_RESOURCE_DESCRIPTOR ConflictingDescriptor)
{
   CM_RESOURCE_LIST CmList;
   NTSTATUS Status;

   CmList.Count = 1;
   CmList.List[0].InterfaceType = InterfaceTypeUndefined;
   CmList.List[0].BusNumber = 0;
   CmList.List[0].PartialResourceList.Version = 1;
   CmList.List[0].PartialResourceList.Revision = 1;
   CmList.List[0].PartialResourceList.Count = 1;
   CmList.List[0].PartialResourceList.PartialDescriptors[0] = *CmDesc;

   Status = IopDetectResourceConflict(&CmList, TRUE, ConflictingDescriptor);
   if (Status == STATUS_CONFLICTING_ADDRESSES)
       return TRUE;

   return FALSE;
}

static
BOOLEAN
IopFindBusNumberResource(
   IN PIO_RESOURCE_DESCRIPTOR IoDesc,
   OUT PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDesc)
{
   ULONG Start;
   CM_PARTIAL_RESOURCE_DESCRIPTOR ConflictingDesc;

   ASSERT(IoDesc->Type == CmDesc->Type);
   ASSERT(IoDesc->Type == CmResourceTypeBusNumber);

   for (Start = IoDesc->u.BusNumber.MinBusNumber;
        Start <= IoDesc->u.BusNumber.MaxBusNumber - IoDesc->u.BusNumber.Length + 1;
        Start++)
   {
        CmDesc->u.BusNumber.Length = IoDesc->u.BusNumber.Length;
        CmDesc->u.BusNumber.Start = Start;

        if (IopCheckDescriptorForConflict(CmDesc, &ConflictingDesc))
        {
            Start += ConflictingDesc.u.BusNumber.Start + ConflictingDesc.u.BusNumber.Length;
        }
        else
        {
            DPRINT1("Satisfying bus number requirement with 0x%x (length: 0x%x)\n", Start, CmDesc->u.BusNumber.Length);
            return TRUE;
        }
   }

   return FALSE;
}

static
BOOLEAN
IopFindMemoryResource(
   IN PIO_RESOURCE_DESCRIPTOR IoDesc,
   OUT PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDesc)
{
   ULONGLONG Start;
   CM_PARTIAL_RESOURCE_DESCRIPTOR ConflictingDesc;

   ASSERT(IoDesc->Type == CmDesc->Type);
   ASSERT(IoDesc->Type == CmResourceTypeMemory);

   /* HACK */
   if (IoDesc->u.Memory.Alignment == 0) IoDesc->u.Memory.Alignment = 1;

   for (Start = (ULONGLONG)IoDesc->u.Memory.MinimumAddress.QuadPart;
        Start <= (ULONGLONG)IoDesc->u.Memory.MaximumAddress.QuadPart - IoDesc->u.Memory.Length + 1;
        Start += IoDesc->u.Memory.Alignment)
   {
        CmDesc->u.Memory.Length = IoDesc->u.Memory.Length;
        CmDesc->u.Memory.Start.QuadPart = (LONGLONG)Start;

        if (IopCheckDescriptorForConflict(CmDesc, &ConflictingDesc))
        {
            Start += (ULONGLONG)ConflictingDesc.u.Memory.Start.QuadPart +
                     ConflictingDesc.u.Memory.Length;
        }
        else
        {
            DPRINT1("Satisfying memory requirement with 0x%I64x (length: 0x%x)\n", Start, CmDesc->u.Memory.Length);
            return TRUE;
        }
   }

   return FALSE;
}

static
BOOLEAN
IopFindPortResource(
   IN PIO_RESOURCE_DESCRIPTOR IoDesc,
   OUT PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDesc)
{
   ULONGLONG Start;
   CM_PARTIAL_RESOURCE_DESCRIPTOR ConflictingDesc;

   ASSERT(IoDesc->Type == CmDesc->Type);
   ASSERT(IoDesc->Type == CmResourceTypePort);

   /* HACK */
   if (IoDesc->u.Port.Alignment == 0) IoDesc->u.Port.Alignment = 1;

   for (Start = (ULONGLONG)IoDesc->u.Port.MinimumAddress.QuadPart;
       Start <= (ULONGLONG)IoDesc->u.Port.MaximumAddress.QuadPart - IoDesc->u.Port.Length + 1;
        Start += IoDesc->u.Port.Alignment)
   {
        CmDesc->u.Port.Length = IoDesc->u.Port.Length;
        CmDesc->u.Port.Start.QuadPart = (LONGLONG)Start;

        if (IopCheckDescriptorForConflict(CmDesc, &ConflictingDesc))
        {
            Start += (ULONGLONG)ConflictingDesc.u.Port.Start.QuadPart + ConflictingDesc.u.Port.Length;
        }
        else
        {
            DPRINT("Satisfying port requirement with 0x%I64x (length: 0x%x)\n", Start, CmDesc->u.Port.Length);
            return TRUE;
        }
   }

   DPRINT1("IopFindPortResource failed!\n");
   return FALSE;
}

static
BOOLEAN
IopFindDmaResource(
   IN PIO_RESOURCE_DESCRIPTOR IoDesc,
   OUT PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDesc)
{
   ULONG Channel;

   ASSERT(IoDesc->Type == CmDesc->Type);
   ASSERT(IoDesc->Type == CmResourceTypeDma);

   for (Channel = IoDesc->u.Dma.MinimumChannel;
        Channel <= IoDesc->u.Dma.MaximumChannel;
        Channel++)
   {
        CmDesc->u.Dma.Channel = Channel;
        CmDesc->u.Dma.Port = 0;

        if (!IopCheckDescriptorForConflict(CmDesc, NULL))
        {
            DPRINT1("Satisfying DMA requirement with channel 0x%x\n", Channel);
            return TRUE;
        }
   }

   return FALSE;
}

static
BOOLEAN
IopFindInterruptResource(
   IN PIO_RESOURCE_DESCRIPTOR IoDesc,
   OUT PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDesc)
{
   ULONG Vector;

   ASSERT(IoDesc->Type == CmDesc->Type);
   ASSERT(IoDesc->Type == CmResourceTypeInterrupt);

   for (Vector = IoDesc->u.Interrupt.MinimumVector;
        Vector <= IoDesc->u.Interrupt.MaximumVector;
        Vector++)
   {
        CmDesc->u.Interrupt.Vector = Vector;
        CmDesc->u.Interrupt.Level = Vector;
        CmDesc->u.Interrupt.Affinity = (KAFFINITY)-1;

        if (!IopCheckDescriptorForConflict(CmDesc, NULL))
        {
            DPRINT1("Satisfying interrupt requirement with IRQ 0x%x\n", Vector);
            return TRUE;
        }
   }

   return FALSE;
}

NTSTATUS NTAPI
IopFixupResourceListWithRequirements(
   IN PIO_RESOURCE_REQUIREMENTS_LIST RequirementsList,
   OUT PCM_RESOURCE_LIST *ResourceList)
{
    ULONG i, OldCount;
    BOOLEAN AlternateRequired = FALSE;

    /* Save the initial resource count when we got here so we can restore if an alternate fails */
    if (*ResourceList != NULL)
        OldCount = (*ResourceList)->List[0].PartialResourceList.Count;
    else
        OldCount = 0;

    for (i = 0; i < RequirementsList->AlternativeLists; i++)
    {
        ULONG ii;
        PIO_RESOURCE_LIST ResList = &RequirementsList->List[i];

        /* We need to get back to where we were before processing the last alternative list */
        if (OldCount == 0 && *ResourceList != NULL)
        {
            /* Just free it and kill the pointer */
            ExFreePool(*ResourceList);
            *ResourceList = NULL;
        }
        else if (OldCount != 0)
        {
            PCM_RESOURCE_LIST NewList;

            /* Let's resize it */
            (*ResourceList)->List[0].PartialResourceList.Count = OldCount;

            /* Allocate the new smaller list */
            NewList = ExAllocatePool(PagedPool, PnpDetermineResourceListSize(*ResourceList));
            if (!NewList)
                return STATUS_NO_MEMORY;

            /* Copy the old stuff back */
            RtlCopyMemory(NewList, *ResourceList, PnpDetermineResourceListSize(*ResourceList));

            /* Free the old one */
            ExFreePool(*ResourceList);

            /* Store the pointer to the new one */
            *ResourceList = NewList;
        }

        for (ii = 0; ii < ResList->Count; ii++)
        {
            ULONG iii;
            PCM_PARTIAL_RESOURCE_LIST PartialList = (*ResourceList) ? &(*ResourceList)->List[0].PartialResourceList : NULL;
            PIO_RESOURCE_DESCRIPTOR IoDesc = &ResList->Descriptors[ii];
            BOOLEAN Matched = FALSE;

            /* Skip alternates if we don't need one */
            if (!AlternateRequired && (IoDesc->Option & IO_RESOURCE_ALTERNATIVE))
            {
                DPRINT("Skipping unneeded alternate\n");
                continue;
            }

            /* Check if we couldn't satsify a requirement or its alternates */
            if (AlternateRequired && !(IoDesc->Option & IO_RESOURCE_ALTERNATIVE))
            {
                DPRINT1("Unable to satisfy preferred resource or alternates in list %lu\n", i);

                /* Break out of this loop and try the next list */
                break;
            }

            for (iii = 0; PartialList && iii < PartialList->Count && !Matched; iii++)
            {
                PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDesc = &PartialList->PartialDescriptors[iii];

                /* First check types */
                if (IoDesc->Type != CmDesc->Type)
                    continue;

                switch (IoDesc->Type)
                {
                    case CmResourceTypeInterrupt:
                        /* Make sure it satisfies our vector range */
                        if (CmDesc->u.Interrupt.Vector >= IoDesc->u.Interrupt.MinimumVector &&
                            CmDesc->u.Interrupt.Vector <= IoDesc->u.Interrupt.MaximumVector)
                        {
                            /* Found it */
                            Matched = TRUE;
                        }
                        else
                        {
                            DPRINT("Interrupt - Not a match! 0x%x not inside 0x%x to 0x%x\n",
                                   CmDesc->u.Interrupt.Vector,
                                   IoDesc->u.Interrupt.MinimumVector,
                                   IoDesc->u.Interrupt.MaximumVector);
                        }
                        break;

                    case CmResourceTypeMemory:
                    case CmResourceTypePort:
                        /* Make sure the length matches and it satisfies our address range */
                        if (CmDesc->u.Memory.Length == IoDesc->u.Memory.Length &&
                            (ULONGLONG)CmDesc->u.Memory.Start.QuadPart >= (ULONGLONG)IoDesc->u.Memory.MinimumAddress.QuadPart &&
                            (ULONGLONG)CmDesc->u.Memory.Start.QuadPart + CmDesc->u.Memory.Length - 1 <= (ULONGLONG)IoDesc->u.Memory.MaximumAddress.QuadPart)
                        {
                            /* Found it */
                            Matched = TRUE;
                        }
                        else
                        {
                            DPRINT("Memory/Port - Not a match! 0x%I64x with length 0x%x not inside 0x%I64x to 0x%I64x with length 0x%x\n",
                                   CmDesc->u.Memory.Start.QuadPart,
                                   CmDesc->u.Memory.Length,
                                   IoDesc->u.Memory.MinimumAddress.QuadPart,
                                   IoDesc->u.Memory.MaximumAddress.QuadPart,
                                   IoDesc->u.Memory.Length);
                        }
                        break;

                    case CmResourceTypeBusNumber:
                        /* Make sure the length matches and it satisfies our bus number range */
                        if (CmDesc->u.BusNumber.Length == IoDesc->u.BusNumber.Length &&
                            CmDesc->u.BusNumber.Start >= IoDesc->u.BusNumber.MinBusNumber &&
                            CmDesc->u.BusNumber.Start + CmDesc->u.BusNumber.Length - 1 <= IoDesc->u.BusNumber.MaxBusNumber)
                        {
                            /* Found it */
                            Matched = TRUE;
                        }
                        else
                        {
                            DPRINT("Bus Number - Not a match! 0x%x with length 0x%x not inside 0x%x to 0x%x with length 0x%x\n",
                                   CmDesc->u.BusNumber.Start,
                                   CmDesc->u.BusNumber.Length,
                                   IoDesc->u.BusNumber.MinBusNumber,
                                   IoDesc->u.BusNumber.MaxBusNumber,
                                   IoDesc->u.BusNumber.Length);
                        }
                        break;

                    case CmResourceTypeDma:
                        /* Make sure it fits in our channel range */
                        if (CmDesc->u.Dma.Channel >= IoDesc->u.Dma.MinimumChannel &&
                            CmDesc->u.Dma.Channel <= IoDesc->u.Dma.MaximumChannel)
                        {
                            /* Found it */
                            Matched = TRUE;
                        }
                        else
                        {
                            DPRINT("DMA - Not a match! 0x%x not inside 0x%x to 0x%x\n",
                                   CmDesc->u.Dma.Channel,
                                   IoDesc->u.Dma.MinimumChannel,
                                   IoDesc->u.Dma.MaximumChannel);
                        }
                        break;

                    default:
                        /* Other stuff is fine */
                        Matched = TRUE;
                        break;
                }
            }

            /* Check if we found a matching descriptor */
            if (!Matched)
            {
                PCM_RESOURCE_LIST NewList;
                CM_PARTIAL_RESOURCE_DESCRIPTOR NewDesc;
                PCM_PARTIAL_RESOURCE_DESCRIPTOR DescPtr;
                BOOLEAN FoundResource = TRUE;

                /* Setup the new CM descriptor */
                NewDesc.Type = IoDesc->Type;
                NewDesc.Flags = IoDesc->Flags;
                NewDesc.ShareDisposition = IoDesc->ShareDisposition;

                /* Let'se see if we can find a resource to satisfy this */
                switch (IoDesc->Type)
                {
                    case CmResourceTypeInterrupt:
                        /* Find an available interrupt */
                        if (!IopFindInterruptResource(IoDesc, &NewDesc))
                        {
                            DPRINT1("Failed to find an available interrupt resource (0x%x to 0x%x)\n",
                                    IoDesc->u.Interrupt.MinimumVector, IoDesc->u.Interrupt.MaximumVector);

                            FoundResource = FALSE;
                        }
                        break;

                    case CmResourceTypePort:
                        /* Find an available port range */
                        if (!IopFindPortResource(IoDesc, &NewDesc))
                        {
                            DPRINT1("Failed to find an available port resource (0x%I64x to 0x%I64x length: 0x%x)\n",
                                    IoDesc->u.Port.MinimumAddress.QuadPart, IoDesc->u.Port.MaximumAddress.QuadPart,
                                    IoDesc->u.Port.Length);

                            FoundResource = FALSE;
                        }
                        break;

                    case CmResourceTypeMemory:
                        /* Find an available memory range */
                        if (!IopFindMemoryResource(IoDesc, &NewDesc))
                        {
                            DPRINT1("Failed to find an available memory resource (0x%I64x to 0x%I64x length: 0x%x)\n",
                                    IoDesc->u.Memory.MinimumAddress.QuadPart, IoDesc->u.Memory.MaximumAddress.QuadPart,
                                    IoDesc->u.Memory.Length);

                            FoundResource = FALSE;
                        }
                        break;

                    case CmResourceTypeBusNumber:
                        /* Find an available bus address range */
                        if (!IopFindBusNumberResource(IoDesc, &NewDesc))
                        {
                            DPRINT1("Failed to find an available bus number resource (0x%x to 0x%x length: 0x%x)\n",
                                    IoDesc->u.BusNumber.MinBusNumber, IoDesc->u.BusNumber.MaxBusNumber,
                                    IoDesc->u.BusNumber.Length);

                            FoundResource = FALSE;
                        }
                        break;

                    case CmResourceTypeDma:
                        /* Find an available DMA channel */
                        if (!IopFindDmaResource(IoDesc, &NewDesc))
                        {
                            DPRINT1("Failed to find an available dma resource (0x%x to 0x%x)\n",
                                    IoDesc->u.Dma.MinimumChannel, IoDesc->u.Dma.MaximumChannel);

                            FoundResource = FALSE;
                        }
                        break;

                    default:
                        DPRINT1("Unsupported resource type: %x\n", IoDesc->Type);
                        FoundResource = FALSE;
                        break;
                }

                /* Check if it's missing and required */
                if (!FoundResource && IoDesc->Option == 0)
                {
                    /* Break out of this loop and try the next list */
                    DPRINT1("Unable to satisfy required resource in list %lu\n", i);
                    break;
                }
                else if (!FoundResource)
                {
                    /* Try an alternate for this preferred descriptor */
                    AlternateRequired = TRUE;
                    continue;
                }
                else
                {
                    /* Move on to the next preferred or required descriptor after this one */
                    AlternateRequired = FALSE;
                }

                /* Figure out what we need */
                if (PartialList == NULL)
                {
                    /* We need a new list */
                    NewList = ExAllocatePool(PagedPool, sizeof(CM_RESOURCE_LIST));
                    if (!NewList)
                        return STATUS_NO_MEMORY;

                    /* Set it up */
                    NewList->Count = 1;
                    NewList->List[0].InterfaceType = RequirementsList->InterfaceType;
                    NewList->List[0].BusNumber = RequirementsList->BusNumber;
                    NewList->List[0].PartialResourceList.Version = 1;
                    NewList->List[0].PartialResourceList.Revision = 1;
                    NewList->List[0].PartialResourceList.Count = 1;

                    /* Set our pointer */
                    DescPtr = &NewList->List[0].PartialResourceList.PartialDescriptors[0];
                }
                else
                {
                    /* Allocate the new larger list */
                    NewList = ExAllocatePool(PagedPool, PnpDetermineResourceListSize(*ResourceList) + sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
                    if (!NewList)
                        return STATUS_NO_MEMORY;

                    /* Copy the old stuff back */
                    RtlCopyMemory(NewList, *ResourceList, PnpDetermineResourceListSize(*ResourceList));

                    /* Set our pointer */
                    DescPtr = &NewList->List[0].PartialResourceList.PartialDescriptors[NewList->List[0].PartialResourceList.Count];

                    /* Increment the descriptor count */
                    NewList->List[0].PartialResourceList.Count++;

                    /* Free the old list */
                    ExFreePool(*ResourceList);
                }

                /* Copy the descriptor in */
                *DescPtr = NewDesc;

                /* Store the new list */
                *ResourceList = NewList;
            }
        }

        /* Check if we need an alternate with no resources left */
        if (AlternateRequired)
        {
            DPRINT1("Unable to satisfy preferred resource or alternates in list %lu\n", i);

            /* Try the next alternate list */
            continue;
        }

        /* We're done because we satisfied one of the alternate lists */
        return STATUS_SUCCESS;
    }

    /* We ran out of alternates */
    DPRINT1("Out of alternate lists!\n");

    /* Free the list */
    if (*ResourceList)
    {
        ExFreePool(*ResourceList);
        *ResourceList = NULL;
    }

    /* Fail */
    return STATUS_CONFLICTING_ADDRESSES;
}

static
BOOLEAN
IopCheckResourceDescriptor(
   IN PCM_PARTIAL_RESOURCE_DESCRIPTOR ResDesc,
   IN PCM_RESOURCE_LIST ResourceList,
   IN BOOLEAN Silent,
   OUT OPTIONAL PCM_PARTIAL_RESOURCE_DESCRIPTOR ConflictingDescriptor)
{
   ULONG i, ii;
   BOOLEAN Result = FALSE;

   for (i = 0; i < ResourceList->Count; i++)
   {
      PCM_PARTIAL_RESOURCE_LIST ResList = &ResourceList->List[i].PartialResourceList;
      for (ii = 0; ii < ResList->Count; ii++)
      {
         PCM_PARTIAL_RESOURCE_DESCRIPTOR ResDesc2 = &ResList->PartialDescriptors[ii];

         /* We don't care about shared resources */
         if (ResDesc->ShareDisposition == CmResourceShareShared &&
             ResDesc2->ShareDisposition == CmResourceShareShared)
             continue;

         /* Make sure we're comparing the same types */
         if (ResDesc->Type != ResDesc2->Type)
             continue;

         switch (ResDesc->Type)
         {
             case CmResourceTypeMemory:
                 if (((ULONGLONG)ResDesc->u.Memory.Start.QuadPart < (ULONGLONG)ResDesc2->u.Memory.Start.QuadPart &&
                      (ULONGLONG)ResDesc->u.Memory.Start.QuadPart + ResDesc->u.Memory.Length >
                      (ULONGLONG)ResDesc2->u.Memory.Start.QuadPart) || ((ULONGLONG)ResDesc2->u.Memory.Start.QuadPart <
                      (ULONGLONG)ResDesc->u.Memory.Start.QuadPart && (ULONGLONG)ResDesc2->u.Memory.Start.QuadPart +
                      ResDesc2->u.Memory.Length > (ULONGLONG)ResDesc->u.Memory.Start.QuadPart))
                 {
                      if (!Silent)
                      {
                          DPRINT1("Resource conflict: Memory (0x%I64x to 0x%I64x vs. 0x%I64x to 0x%I64x)\n",
                                  ResDesc->u.Memory.Start.QuadPart, ResDesc->u.Memory.Start.QuadPart +
                                  ResDesc->u.Memory.Length, ResDesc2->u.Memory.Start.QuadPart,
                                  ResDesc2->u.Memory.Start.QuadPart + ResDesc2->u.Memory.Length);
                      }

                      Result = TRUE;

                      goto ByeBye;
                 }
                 break;

             case CmResourceTypePort:
                 if (((ULONGLONG)ResDesc->u.Port.Start.QuadPart < (ULONGLONG)ResDesc2->u.Port.Start.QuadPart &&
                      (ULONGLONG)ResDesc->u.Port.Start.QuadPart + ResDesc->u.Port.Length >
                      (ULONGLONG)ResDesc2->u.Port.Start.QuadPart) || ((ULONGLONG)ResDesc2->u.Port.Start.QuadPart <
                      (ULONGLONG)ResDesc->u.Port.Start.QuadPart && (ULONGLONG)ResDesc2->u.Port.Start.QuadPart +
                      ResDesc2->u.Port.Length > (ULONGLONG)ResDesc->u.Port.Start.QuadPart))
                 {
                      if (!Silent)
                      {
                          DPRINT1("Resource conflict: Port (0x%I64x to 0x%I64x vs. 0x%I64x to 0x%I64x)\n",
                                  ResDesc->u.Port.Start.QuadPart, ResDesc->u.Port.Start.QuadPart +
                                  ResDesc->u.Port.Length, ResDesc2->u.Port.Start.QuadPart,
                                  ResDesc2->u.Port.Start.QuadPart + ResDesc2->u.Port.Length);
                      }

                      Result = TRUE;

                      goto ByeBye;
                 }
                 break;

             case CmResourceTypeInterrupt:
                 if (ResDesc->u.Interrupt.Vector == ResDesc2->u.Interrupt.Vector)
                 {
                      if (!Silent)
                      {
                          DPRINT1("Resource conflict: IRQ (0x%x 0x%x vs. 0x%x 0x%x)\n",
                                  ResDesc->u.Interrupt.Vector, ResDesc->u.Interrupt.Level,
                                  ResDesc2->u.Interrupt.Vector, ResDesc2->u.Interrupt.Level);
                      }

                      Result = TRUE;

                      goto ByeBye;
                 }
                 break;

             case CmResourceTypeBusNumber:
                 if ((ResDesc->u.BusNumber.Start < ResDesc2->u.BusNumber.Start &&
                      ResDesc->u.BusNumber.Start + ResDesc->u.BusNumber.Length >
                      ResDesc2->u.BusNumber.Start) || (ResDesc2->u.BusNumber.Start <
                      ResDesc->u.BusNumber.Start && ResDesc2->u.BusNumber.Start +
                      ResDesc2->u.BusNumber.Length > ResDesc->u.BusNumber.Start))
                 {
                      if (!Silent)
                      {
                          DPRINT1("Resource conflict: Bus number (0x%x to 0x%x vs. 0x%x to 0x%x)\n",
                                  ResDesc->u.BusNumber.Start, ResDesc->u.BusNumber.Start +
                                  ResDesc->u.BusNumber.Length, ResDesc2->u.BusNumber.Start,
                                  ResDesc2->u.BusNumber.Start + ResDesc2->u.BusNumber.Length);
                      }

                      Result = TRUE;

                      goto ByeBye;
                 }
                 break;

             case CmResourceTypeDma:
                 if (ResDesc->u.Dma.Channel == ResDesc2->u.Dma.Channel)
                 {
                     if (!Silent)
                     {
                         DPRINT1("Resource conflict: Dma (0x%x 0x%x vs. 0x%x 0x%x)\n",
                                 ResDesc->u.Dma.Channel, ResDesc->u.Dma.Port,
                                 ResDesc2->u.Dma.Channel, ResDesc2->u.Dma.Port);
                     }

                     Result = TRUE;

                     goto ByeBye;
                 }
                 break;
         }
      }
   }

ByeBye:

   if (Result && ConflictingDescriptor)
   {
       RtlCopyMemory(ConflictingDescriptor,
                     ResDesc,
                     sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
   }

   return Result;
}

static
NTSTATUS
IopUpdateControlKeyWithResources(IN PDEVICE_NODE DeviceNode)
{
   UNICODE_STRING EnumRoot = RTL_CONSTANT_STRING(ENUM_ROOT);
   UNICODE_STRING Control = RTL_CONSTANT_STRING(L"Control");
   UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"AllocConfig");
   HANDLE EnumKey, InstanceKey, ControlKey;
   NTSTATUS Status;
   OBJECT_ATTRIBUTES ObjectAttributes;

   /* Open the Enum key */
   Status = IopOpenRegistryKeyEx(&EnumKey, NULL, &EnumRoot, KEY_ENUMERATE_SUB_KEYS);
   if (!NT_SUCCESS(Status))
       return Status;

   /* Open the instance key (eg. Root\PNP0A03) */
   Status = IopOpenRegistryKeyEx(&InstanceKey, EnumKey, &DeviceNode->InstancePath, KEY_ENUMERATE_SUB_KEYS);
   ZwClose(EnumKey);

   if (!NT_SUCCESS(Status))
       return Status;

   /* Create/Open the Control key */
   InitializeObjectAttributes(&ObjectAttributes,
                              &Control,
                              OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                              InstanceKey,
                              NULL);
   Status = ZwCreateKey(&ControlKey,
                        KEY_SET_VALUE,
                        &ObjectAttributes,
                        0,
                        NULL,
                        REG_OPTION_VOLATILE,
                        NULL);
   ZwClose(InstanceKey);

   if (!NT_SUCCESS(Status))
       return Status;

   /* Write the resource list */
   Status = ZwSetValueKey(ControlKey,
                          &ValueName,
                          0,
                          REG_RESOURCE_LIST,
                          DeviceNode->ResourceList,
                          PnpDetermineResourceListSize(DeviceNode->ResourceList));
   ZwClose(ControlKey);

   if (!NT_SUCCESS(Status))
       return Status;

   return STATUS_SUCCESS;
}

static
NTSTATUS
IopFilterResourceRequirements(IN PDEVICE_NODE DeviceNode)
{
   IO_STACK_LOCATION Stack;
   IO_STATUS_BLOCK IoStatusBlock;
   NTSTATUS Status;

   DPRINT("Sending IRP_MN_FILTER_RESOURCE_REQUIREMENTS to device stack\n");

   Stack.Parameters.FilterResourceRequirements.IoResourceRequirementList = DeviceNode->ResourceRequirements;
   Status = IopInitiatePnpIrp(
      DeviceNode->PhysicalDeviceObject,
      &IoStatusBlock,
      IRP_MN_FILTER_RESOURCE_REQUIREMENTS,
      &Stack);
   if (!NT_SUCCESS(Status) && Status != STATUS_NOT_SUPPORTED)
   {
      DPRINT1("IopInitiatePnpIrp(IRP_MN_FILTER_RESOURCE_REQUIREMENTS) failed\n");
      return Status;
   }
   else if (NT_SUCCESS(Status) && IoStatusBlock.Information)
   {
      DeviceNode->ResourceRequirements = (PIO_RESOURCE_REQUIREMENTS_LIST)IoStatusBlock.Information;
   }

   return STATUS_SUCCESS;
}


NTSTATUS
IopUpdateResourceMap(IN PDEVICE_NODE DeviceNode, PWCHAR Level1Key, PWCHAR Level2Key)
{
  NTSTATUS Status;
  ULONG Disposition;
  HANDLE PnpMgrLevel1, PnpMgrLevel2, ResourceMapKey;
  UNICODE_STRING KeyName;
  OBJECT_ATTRIBUTES ObjectAttributes;

  RtlInitUnicodeString(&KeyName,
               L"\\Registry\\Machine\\HARDWARE\\RESOURCEMAP");
  InitializeObjectAttributes(&ObjectAttributes,
                 &KeyName,
                 OBJ_CASE_INSENSITIVE | OBJ_OPENIF | OBJ_KERNEL_HANDLE,
                 NULL,
                 NULL);
  Status = ZwCreateKey(&ResourceMapKey,
               KEY_ALL_ACCESS,
               &ObjectAttributes,
               0,
               NULL,
               REG_OPTION_VOLATILE,
               &Disposition);
  if (!NT_SUCCESS(Status))
      return Status;

  RtlInitUnicodeString(&KeyName, Level1Key);
  InitializeObjectAttributes(&ObjectAttributes,
                 &KeyName,
                 OBJ_CASE_INSENSITIVE | OBJ_OPENIF | OBJ_KERNEL_HANDLE,
                 ResourceMapKey,
                 NULL);
  Status = ZwCreateKey(&PnpMgrLevel1,
                       KEY_ALL_ACCESS,
                       &ObjectAttributes,
                       0,
                       NULL,
                       REG_OPTION_VOLATILE,
                       &Disposition);
  ZwClose(ResourceMapKey);
  if (!NT_SUCCESS(Status))
      return Status;

  RtlInitUnicodeString(&KeyName, Level2Key);
  InitializeObjectAttributes(&ObjectAttributes,
                 &KeyName,
                 OBJ_CASE_INSENSITIVE | OBJ_OPENIF | OBJ_KERNEL_HANDLE,
                 PnpMgrLevel1,
                 NULL);
  Status = ZwCreateKey(&PnpMgrLevel2,
                       KEY_ALL_ACCESS,
                       &ObjectAttributes,
                       0,
                       NULL,
                       REG_OPTION_VOLATILE,
                       &Disposition);
  ZwClose(PnpMgrLevel1);
  if (!NT_SUCCESS(Status))
      return Status;

  if (DeviceNode->ResourceList)
  {
      UNICODE_STRING NameU;
      UNICODE_STRING RawSuffix, TranslatedSuffix;
      ULONG OldLength = 0;

      ASSERT(DeviceNode->ResourceListTranslated);

      RtlInitUnicodeString(&TranslatedSuffix, L".Translated");
      RtlInitUnicodeString(&RawSuffix, L".Raw");

      Status = IoGetDeviceProperty(DeviceNode->PhysicalDeviceObject,
                                   DevicePropertyPhysicalDeviceObjectName,
                                   0,
                                   NULL,
                                   &OldLength);
      if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL)
      {
          ASSERT(OldLength);

          NameU.Buffer = ExAllocatePool(PagedPool, OldLength + TranslatedSuffix.Length);
          if (!NameU.Buffer)
          {
              ZwClose(PnpMgrLevel2);
              return STATUS_INSUFFICIENT_RESOURCES;
          }

          NameU.Length = 0;
          NameU.MaximumLength = (USHORT)OldLength + TranslatedSuffix.Length;

          Status = IoGetDeviceProperty(DeviceNode->PhysicalDeviceObject,
                                       DevicePropertyPhysicalDeviceObjectName,
                                       NameU.MaximumLength,
                                       NameU.Buffer,
                                       &OldLength);
          if (!NT_SUCCESS(Status))
          {
              ZwClose(PnpMgrLevel2);
              ExFreePool(NameU.Buffer);
              return Status;
          }
      }
      else if (!NT_SUCCESS(Status))
      {
          /* Some failure */
          ZwClose(PnpMgrLevel2);
          return Status;
      }
      else
      {
          /* This should never happen */
          ASSERT(FALSE);
      }

      NameU.Length = (USHORT)OldLength;

      RtlAppendUnicodeStringToString(&NameU, &RawSuffix);

      Status = ZwSetValueKey(PnpMgrLevel2,
                             &NameU,
                             0,
                             REG_RESOURCE_LIST,
                             DeviceNode->ResourceList,
                             PnpDetermineResourceListSize(DeviceNode->ResourceList));
      if (!NT_SUCCESS(Status))
      {
          ZwClose(PnpMgrLevel2);
          ExFreePool(NameU.Buffer);
          return Status;
      }

      /* "Remove" the suffix by setting the length back to what it used to be */
      NameU.Length = (USHORT)OldLength;

      RtlAppendUnicodeStringToString(&NameU, &TranslatedSuffix);

      Status = ZwSetValueKey(PnpMgrLevel2,
                             &NameU,
                             0,
                             REG_RESOURCE_LIST,
                             DeviceNode->ResourceListTranslated,
                             PnpDetermineResourceListSize(DeviceNode->ResourceListTranslated));
      ZwClose(PnpMgrLevel2);
      ExFreePool(NameU.Buffer);

      if (!NT_SUCCESS(Status))
          return Status;
  }
  else
  {
      ZwClose(PnpMgrLevel2);
  }

  return STATUS_SUCCESS;
}

NTSTATUS
IopUpdateResourceMapForPnPDevice(IN PDEVICE_NODE DeviceNode)
{
  return IopUpdateResourceMap(DeviceNode, L"PnP Manager", L"PnpManager");
}

static
NTSTATUS
IopTranslateDeviceResources(
   IN PDEVICE_NODE DeviceNode)
{
   PCM_PARTIAL_RESOURCE_LIST pPartialResourceList;
   PCM_PARTIAL_RESOURCE_DESCRIPTOR DescriptorRaw, DescriptorTranslated;
   ULONG i, j, ListSize;
   NTSTATUS Status;

   if (!DeviceNode->ResourceList)
   {
      DeviceNode->ResourceListTranslated = NULL;
      return STATUS_SUCCESS;
   }

   /* That's easy to translate a resource list. Just copy the
    * untranslated one and change few fields in the copy
    */
   ListSize = PnpDetermineResourceListSize(DeviceNode->ResourceList);

   DeviceNode->ResourceListTranslated = ExAllocatePool(PagedPool, ListSize);
   if (!DeviceNode->ResourceListTranslated)
   {
      Status = STATUS_NO_MEMORY;
      goto cleanup;
   }
   RtlCopyMemory(DeviceNode->ResourceListTranslated, DeviceNode->ResourceList, ListSize);

   for (i = 0; i < DeviceNode->ResourceList->Count; i++)
   {
      pPartialResourceList = &DeviceNode->ResourceList->List[i].PartialResourceList;
      for (j = 0; j < pPartialResourceList->Count; j++)
      {
         DescriptorRaw = &pPartialResourceList->PartialDescriptors[j];
         DescriptorTranslated = &DeviceNode->ResourceListTranslated->List[i].PartialResourceList.PartialDescriptors[j];
         switch (DescriptorRaw->Type)
         {
            case CmResourceTypePort:
            {
               ULONG AddressSpace = 1; /* IO space */
               if (!HalTranslateBusAddress(
                  DeviceNode->ResourceList->List[i].InterfaceType,
                  DeviceNode->ResourceList->List[i].BusNumber,
                  DescriptorRaw->u.Port.Start,
                  &AddressSpace,
                  &DescriptorTranslated->u.Port.Start))
               {
                  Status = STATUS_UNSUCCESSFUL;
                  DPRINT1("Failed to translate port resource (Start: 0x%I64x)\n", DescriptorRaw->u.Port.Start.QuadPart);
                  goto cleanup;
               }

               if (AddressSpace == 0)
               {
                   DPRINT1("Guessed incorrect address space: 1 -> 0\n");

                   /* FIXME: I think all other CM_RESOURCE_PORT_XXX flags are
                    * invalid for this state but I'm not 100% sure */
                   DescriptorRaw->Flags =
                   DescriptorTranslated->Flags = CM_RESOURCE_PORT_MEMORY;
               }
               break;
            }
            case CmResourceTypeInterrupt:
            {
               DescriptorTranslated->u.Interrupt.Vector = HalGetInterruptVector(
                  DeviceNode->ResourceList->List[i].InterfaceType,
                  DeviceNode->ResourceList->List[i].BusNumber,
                  DescriptorRaw->u.Interrupt.Level,
                  DescriptorRaw->u.Interrupt.Vector,
                  (PKIRQL)&DescriptorTranslated->u.Interrupt.Level,
                  &DescriptorTranslated->u.Interrupt.Affinity);

               if (!DescriptorTranslated->u.Interrupt.Vector)
               {
                   Status = STATUS_UNSUCCESSFUL;
                   DPRINT1("Failed to translate interrupt resource (Vector: 0x%x | Level: 0x%x)\n", DescriptorRaw->u.Interrupt.Vector,
                                                                                                   DescriptorRaw->u.Interrupt.Level);
                   goto cleanup;
               }
               break;
            }
            case CmResourceTypeMemory:
            {
               ULONG AddressSpace = 0; /* Memory space */
               if (!HalTranslateBusAddress(
                  DeviceNode->ResourceList->List[i].InterfaceType,
                  DeviceNode->ResourceList->List[i].BusNumber,
                  DescriptorRaw->u.Memory.Start,
                  &AddressSpace,
                  &DescriptorTranslated->u.Memory.Start))
               {
                  Status = STATUS_UNSUCCESSFUL;
                  DPRINT1("Failed to translate memory resource (Start: 0x%I64x)\n", DescriptorRaw->u.Memory.Start.QuadPart);
                  goto cleanup;
               }

               if (AddressSpace != 0)
               {
                   DPRINT1("Guessed incorrect address space: 0 -> 1\n");

                   /* This should never happen for memory space */
                   ASSERT(FALSE);
               }
            }

            case CmResourceTypeDma:
            case CmResourceTypeBusNumber:
            case CmResourceTypeDeviceSpecific:
               /* Nothing to do */
               break;
            default:
               DPRINT1("Unknown resource descriptor type 0x%x\n", DescriptorRaw->Type);
               Status = STATUS_NOT_IMPLEMENTED;
               goto cleanup;
         }
      }
   }
   return STATUS_SUCCESS;

cleanup:
   /* Yes! Also delete ResourceList because ResourceList and
    * ResourceListTranslated should be a pair! */
   ExFreePool(DeviceNode->ResourceList);
   DeviceNode->ResourceList = NULL;
   if (DeviceNode->ResourceListTranslated)
   {
      ExFreePool(DeviceNode->ResourceListTranslated);
      DeviceNode->ResourceList = NULL;
   }
   return Status;
}

NTSTATUS
NTAPI
IopAssignDeviceResources(
   IN PDEVICE_NODE DeviceNode)
{
   NTSTATUS Status;
   ULONG ListSize;

ASSERT(FALSE);
   //IopDeviceNodeSetFlag(DeviceNode, DNF_ASSIGNING_RESOURCES);

   Status = IopFilterResourceRequirements(DeviceNode);
   if (!NT_SUCCESS(Status))
       goto ByeBye;

   if (!DeviceNode->BootResources && !DeviceNode->ResourceRequirements)
   {
ASSERT(FALSE);
      //DeviceNode->Flags |= DNF_NO_RESOURCE_REQUIRED;
      //DeviceNode->Flags &= ~DNF_ASSIGNING_RESOURCES;

      /* No resource needed for this device */
      DeviceNode->ResourceList = NULL;
      DeviceNode->ResourceListTranslated = NULL;

      return STATUS_SUCCESS;
   }

   if (DeviceNode->BootResources)
   {
       ListSize = PnpDetermineResourceListSize(DeviceNode->BootResources);

       DeviceNode->ResourceList = ExAllocatePool(PagedPool, ListSize);
       if (!DeviceNode->ResourceList)
       {
           Status = STATUS_NO_MEMORY;
           goto ByeBye;
       }

       RtlCopyMemory(DeviceNode->ResourceList, DeviceNode->BootResources, ListSize);

       Status = IopDetectResourceConflict(DeviceNode->ResourceList, FALSE, NULL);
       if (!NT_SUCCESS(Status))
       {
           DPRINT1("Boot resources for %wZ cause a resource conflict!\n", &DeviceNode->InstancePath);
           ExFreePool(DeviceNode->ResourceList);
           DeviceNode->ResourceList = NULL;
       }
   }
   else
   {
       /* We'll make this from the requirements */
       DeviceNode->ResourceList = NULL;
   }

   /* No resources requirements */
   if (!DeviceNode->ResourceRequirements)
       goto Finish;

   /* Call HAL to fixup our resource requirements list */
   HalAdjustResourceList(&DeviceNode->ResourceRequirements);

   /* Add resource requirements that aren't in the list we already got */
   Status = IopFixupResourceListWithRequirements(DeviceNode->ResourceRequirements,
                                                 &DeviceNode->ResourceList);
   if (!NT_SUCCESS(Status))
   {
       DPRINT1("Failed to fixup a resource list from supplied resources for %wZ\n", &DeviceNode->InstancePath);
       DeviceNode->Problem = CM_PROB_NORMAL_CONFLICT;
       goto ByeBye;
   }

   /* IopFixupResourceListWithRequirements should NEVER give us a conflicting list */
   ASSERT(IopDetectResourceConflict(DeviceNode->ResourceList, FALSE, NULL) != STATUS_CONFLICTING_ADDRESSES);

Finish:
   Status = IopTranslateDeviceResources(DeviceNode);
   if (!NT_SUCCESS(Status))
   {
       DeviceNode->Problem = CM_PROB_TRANSLATION_FAILED;
       DPRINT1("Failed to translate resources for %wZ\n", &DeviceNode->InstancePath);
       goto ByeBye;
   }

   Status = IopUpdateResourceMapForPnPDevice(DeviceNode);
   if (!NT_SUCCESS(Status))
       goto ByeBye;

   Status = IopUpdateControlKeyWithResources(DeviceNode);
   if (!NT_SUCCESS(Status))
       goto ByeBye;

ASSERT(FALSE);
   //IopDeviceNodeSetFlag(DeviceNode, DNF_RESOURCE_ASSIGNED);

ASSERT(FALSE);
   //IopDeviceNodeClearFlag(DeviceNode, DNF_ASSIGNING_RESOURCES);

   return STATUS_SUCCESS;

ByeBye:
   if (DeviceNode->ResourceList)
   {
      ExFreePool(DeviceNode->ResourceList);
      DeviceNode->ResourceList = NULL;
   }

   DeviceNode->ResourceListTranslated = NULL;

ASSERT(FALSE);
   //IopDeviceNodeClearFlag(DeviceNode, DNF_ASSIGNING_RESOURCES);

   return Status;
}

static
BOOLEAN
IopCheckForResourceConflict(
   IN PCM_RESOURCE_LIST ResourceList1,
   IN PCM_RESOURCE_LIST ResourceList2,
   IN BOOLEAN Silent,
   OUT OPTIONAL PCM_PARTIAL_RESOURCE_DESCRIPTOR ConflictingDescriptor)
{
   ULONG i, ii;
   BOOLEAN Result = FALSE;

   for (i = 0; i < ResourceList1->Count; i++)
   {
      PCM_PARTIAL_RESOURCE_LIST ResList = &ResourceList1->List[i].PartialResourceList;
      for (ii = 0; ii < ResList->Count; ii++)
      {
         PCM_PARTIAL_RESOURCE_DESCRIPTOR ResDesc = &ResList->PartialDescriptors[ii];

         Result = IopCheckResourceDescriptor(ResDesc,
                                             ResourceList2,
                                             Silent,
                                             ConflictingDescriptor);
         if (Result) goto ByeBye;
      }
   }

ByeBye:

   return Result;
}

NTSTATUS NTAPI
IopDetectResourceConflict(
   IN PCM_RESOURCE_LIST ResourceList,
   IN BOOLEAN Silent,
   OUT OPTIONAL PCM_PARTIAL_RESOURCE_DESCRIPTOR ConflictingDescriptor)
{
   OBJECT_ATTRIBUTES ObjectAttributes;
   UNICODE_STRING KeyName;
   HANDLE ResourceMapKey = NULL, ChildKey2 = NULL, ChildKey3 = NULL;
   ULONG KeyInformationLength, RequiredLength, KeyValueInformationLength, KeyNameInformationLength;
   PKEY_BASIC_INFORMATION KeyInformation;
   PKEY_VALUE_PARTIAL_INFORMATION KeyValueInformation;
   PKEY_VALUE_BASIC_INFORMATION KeyNameInformation;
   ULONG ChildKeyIndex1 = 0, ChildKeyIndex2 = 0, ChildKeyIndex3 = 0;
   NTSTATUS Status;

   RtlInitUnicodeString(&KeyName, L"\\Registry\\Machine\\HARDWARE\\RESOURCEMAP");
   InitializeObjectAttributes(&ObjectAttributes,
                              &KeyName,
                              OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                              NULL,
                              NULL);
   Status = ZwOpenKey(&ResourceMapKey, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &ObjectAttributes);
   if (!NT_SUCCESS(Status))
   {
      /* The key is missing which means we are the first device */
      return STATUS_SUCCESS;
   }

   while (TRUE)
   {
      Status = ZwEnumerateKey(ResourceMapKey,
                              ChildKeyIndex1,
                              KeyBasicInformation,
                              NULL,
                              0,
                              &RequiredLength);
      if (Status == STATUS_NO_MORE_ENTRIES)
          break;
      else if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL)
      {
          KeyInformationLength = RequiredLength;
          KeyInformation = ExAllocatePoolWithTag(PagedPool,
                                                 KeyInformationLength,
                                                 TAG_IO);
          if (!KeyInformation)
          {
              Status = STATUS_INSUFFICIENT_RESOURCES;
              goto cleanup;
          }

          Status = ZwEnumerateKey(ResourceMapKey,
                                  ChildKeyIndex1,
                                  KeyBasicInformation,
                                  KeyInformation,
                                  KeyInformationLength,
                                  &RequiredLength);
      }
      else
         goto cleanup;
      ChildKeyIndex1++;
      if (!NT_SUCCESS(Status))
      {
          ExFreePoolWithTag(KeyInformation, TAG_IO);
          goto cleanup;
      }

      KeyName.Buffer = KeyInformation->Name;
      KeyName.MaximumLength = KeyName.Length = (USHORT)KeyInformation->NameLength;
      InitializeObjectAttributes(&ObjectAttributes,
                                 &KeyName,
                                 OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                 ResourceMapKey,
                                 NULL);
      Status = ZwOpenKey(&ChildKey2,
                         KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
                         &ObjectAttributes);
      ExFreePoolWithTag(KeyInformation, TAG_IO);
      if (!NT_SUCCESS(Status))
          goto cleanup;

      while (TRUE)
      {
          Status = ZwEnumerateKey(ChildKey2,
                                  ChildKeyIndex2,
                                  KeyBasicInformation,
                                  NULL,
                                  0,
                                  &RequiredLength);
          if (Status == STATUS_NO_MORE_ENTRIES)
              break;
          else if (Status == STATUS_BUFFER_TOO_SMALL)
          {
              KeyInformationLength = RequiredLength;
              KeyInformation = ExAllocatePoolWithTag(PagedPool,
                                                     KeyInformationLength,
                                                     TAG_IO);
              if (!KeyInformation)
              {
                  Status = STATUS_INSUFFICIENT_RESOURCES;
                  goto cleanup;
              }

              Status = ZwEnumerateKey(ChildKey2,
                                      ChildKeyIndex2,
                                      KeyBasicInformation,
                                      KeyInformation,
                                      KeyInformationLength,
                                      &RequiredLength);
          }
          else
              goto cleanup;
          ChildKeyIndex2++;
          if (!NT_SUCCESS(Status))
          {
              ExFreePoolWithTag(KeyInformation, TAG_IO);
              goto cleanup;
          }

          KeyName.Buffer = KeyInformation->Name;
          KeyName.MaximumLength = KeyName.Length = (USHORT)KeyInformation->NameLength;
          InitializeObjectAttributes(&ObjectAttributes,
                                     &KeyName,
                                     OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                     ChildKey2,
                                     NULL);
          Status = ZwOpenKey(&ChildKey3, KEY_QUERY_VALUE, &ObjectAttributes);
          ExFreePoolWithTag(KeyInformation, TAG_IO);
          if (!NT_SUCCESS(Status))
              goto cleanup;

          while (TRUE)
          {
              Status = ZwEnumerateValueKey(ChildKey3,
                                           ChildKeyIndex3,
                                           KeyValuePartialInformation,
                                           NULL,
                                           0,
                                           &RequiredLength);
              if (Status == STATUS_NO_MORE_ENTRIES)
                  break;
              else if (Status == STATUS_BUFFER_TOO_SMALL)
              {
                  KeyValueInformationLength = RequiredLength;
                  KeyValueInformation = ExAllocatePoolWithTag(PagedPool,
                                                              KeyValueInformationLength,
                                                              TAG_IO);
                  if (!KeyValueInformation)
                  {
                      Status = STATUS_INSUFFICIENT_RESOURCES;
                      goto cleanup;
                  }

                  Status = ZwEnumerateValueKey(ChildKey3,
                                               ChildKeyIndex3,
                                               KeyValuePartialInformation,
                                               KeyValueInformation,
                                               KeyValueInformationLength,
                                               &RequiredLength);
              }
              else
                  goto cleanup;
              if (!NT_SUCCESS(Status))
              {
                  ExFreePoolWithTag(KeyValueInformation, TAG_IO);
                  goto cleanup;
              }

              Status = ZwEnumerateValueKey(ChildKey3,
                                           ChildKeyIndex3,
                                           KeyValueBasicInformation,
                                           NULL,
                                           0,
                                           &RequiredLength);
              if (Status == STATUS_BUFFER_TOO_SMALL)
              {
                  KeyNameInformationLength = RequiredLength;
                  KeyNameInformation = ExAllocatePoolWithTag(PagedPool,
                                                             KeyNameInformationLength + sizeof(WCHAR),
                                                             TAG_IO);
                  if (!KeyNameInformation)
                  {
                      Status = STATUS_INSUFFICIENT_RESOURCES;
                      goto cleanup;
                  }

                  Status = ZwEnumerateValueKey(ChildKey3,
                                               ChildKeyIndex3,
                                               KeyValueBasicInformation,
                                               KeyNameInformation,
                                               KeyNameInformationLength,
                                               &RequiredLength);
              }
              else
                  goto cleanup;
              ChildKeyIndex3++;
              if (!NT_SUCCESS(Status))
              {
                  ExFreePoolWithTag(KeyNameInformation, TAG_IO);
                  goto cleanup;
              }

              KeyNameInformation->Name[KeyNameInformation->NameLength / sizeof(WCHAR)] = UNICODE_NULL;

              /* Skip translated entries */
              if (wcsstr(KeyNameInformation->Name, L".Translated"))
              {
                  ExFreePoolWithTag(KeyNameInformation, TAG_IO);
                  ExFreePoolWithTag(KeyValueInformation, TAG_IO);
                  continue;
              }

              ExFreePoolWithTag(KeyNameInformation, TAG_IO);

              if (IopCheckForResourceConflict(ResourceList,
                                              (PCM_RESOURCE_LIST)KeyValueInformation->Data,
                                              Silent,
                                              ConflictingDescriptor))
              {
                  ExFreePoolWithTag(KeyValueInformation, TAG_IO);
                  Status = STATUS_CONFLICTING_ADDRESSES;
                  goto cleanup;
              }

              ExFreePoolWithTag(KeyValueInformation, TAG_IO);
          }
      }
   }

cleanup:
   if (ResourceMapKey != NULL)
       ObCloseHandle(ResourceMapKey, KernelMode);
   if (ChildKey2 != NULL)
       ObCloseHandle(ChildKey2, KernelMode);
   if (ChildKey3 != NULL)
       ObCloseHandle(ChildKey3, KernelMode);

   if (Status == STATUS_NO_MORE_ENTRIES)
       Status = STATUS_SUCCESS;

   return Status;
}

NTSTATUS
NTAPI
IopWriteResourceList(
    _In_ HANDLE Handle,
    _In_ PUNICODE_STRING ResourceName,
    _In_ PUNICODE_STRING Description,
    _In_ PUNICODE_STRING ValueName,
    _In_ PCM_RESOURCE_LIST CmResource,
    _In_ ULONG ListSize)
{
    NTSTATUS Status;
    HANDLE ResourceHandle;
    HANDLE DescriptionHandle;

    PAGED_CODE();

    if (ResourceName)
        DPRINT("IopWriteResourceList: ResourceName - %wZ\n", ResourceName);
    if (Description)
        DPRINT("IopWriteResourceList: Description - %wZ\n", Description);
    if (ResourceName)
        DPRINT("IopWriteResourceList: ValueName - %wZ\n", ValueName);

    Status = IopCreateRegistryKeyEx(&ResourceHandle,
                                    Handle,
                                    ResourceName,
                                    KEY_READ | KEY_WRITE,
                                    REG_OPTION_VOLATILE,
                                    NULL);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = IopCreateRegistryKeyEx(&DescriptionHandle,
                                    ResourceHandle,
                                    Description,
                                    KEY_READ | KEY_WRITE,
                                    REG_OPTION_VOLATILE,
                                    NULL);

    ZwClose(ResourceHandle);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    if (CmResource->Count)
    {
        Status = ZwSetValueKey(DescriptionHandle,
                               ValueName,
                               0,
                               REG_RESOURCE_LIST,
                               CmResource,
                               ListSize);
    }
    else
    {
        Status = ZwDeleteValueKey(DescriptionHandle, ValueName);
    }

    ZwClose(DescriptionHandle);

    return Status;
}

PDEVICE_NODE
NTAPI
IopFindLegacyBusDeviceNode(
    _In_ INTERFACE_TYPE InterfaceType,
    _In_ ULONG LegacyBusNumber)
{
    PDEVICE_NODE DeviceNode;
    PLIST_ENTRY Header;
    PLIST_ENTRY Entry;
    ULONG BusNumber;

    PAGED_CODE();
    DPRINT("IopFindLegacyBusDeviceNode: InterfaceType - %X\n", InterfaceType);

    DeviceNode = IopRootDeviceNode;

    if (InterfaceType >= MaximumInterfaceType ||
        InterfaceType < InterfaceTypeUndefined ||
        InterfaceType == PNPBus)
    {
        DPRINT("IopFindLegacyBusDeviceNode: return IopRootDeviceNode\n");
        return DeviceNode;
    }

    if (InterfaceType == Eisa)
    {
        Header = &IopLegacyBusInformationTable[Isa];
    }
    else
    {
        Header = &IopLegacyBusInformationTable[InterfaceType];
        DPRINT("IopFindLegacyBusDeviceNode: Header - %p\n", Header);
    }

    for (Entry = Header->Flink;
         Entry != Header;
         Entry = Entry->Flink)
    {
        BusNumber = CONTAINING_RECORD(Entry,
                                      DEVICE_NODE,
                                      LegacyBusListEntry)->BusNumber;

        if (BusNumber == LegacyBusNumber)
        {
            DeviceNode = CONTAINING_RECORD(Entry,
                                           DEVICE_NODE,
                                           LegacyBusListEntry);
            break;
        }

        if (BusNumber > LegacyBusNumber)
        {
            break;
        }
    }

    if (DeviceNode == IopRootDeviceNode)
    {
        DPRINT("IopFindLegacyBusDeviceNode: return IopRootDeviceNode\n");
    }
    else
    {
        DPRINT("IopFindLegacyBusDeviceNode: Found - %wZ, Interface - %X, Bus - %X\n",
               &DeviceNode->InstancePath, InterfaceType, LegacyBusNumber);
    }

    return DeviceNode;
}

BOOLEAN
NTAPI
IopFindResourceHandlerInfo(
    _In_ ULONG Type,
    _In_ PDEVICE_NODE DeviceNode,
    _In_ UCHAR IoDescriptorType,
    _In_ PVOID * OutArbEntry)
{
    PPI_RESOURCE_ARBITER_ENTRY ArbEntry;
    PLIST_ENTRY Head;
    PLIST_ENTRY Entry;
    USHORT NoBitMask;
    USHORT QueryBitMask;
    USHORT TypesBitMask;
    BOOLEAN Result;

    DPRINT("IopFindResourceHandlerInfo: Type - %X, DeviceNode - %p, IoDescriptorType - %X\n",
           Type, DeviceNode, IoDescriptorType);

    *OutArbEntry = NULL;

    if (Type == IOP_RES_HANDLER_TYPE_TRANSLATOR)
    {
        NoBitMask = DeviceNode->NoTranslatorMask;
        QueryBitMask = DeviceNode->QueryTranslatorMask;
        Head = &DeviceNode->DeviceTranslatorList;
    }
    else if (Type == IOP_RES_HANDLER_TYPE_ARBITER)
    {
        NoBitMask = DeviceNode->NoArbiterMask;
        QueryBitMask = DeviceNode->QueryArbiterMask;
        Head = &DeviceNode->DeviceArbiterList;
    }
    else
    {
        DPRINT("IopFindResourceHandlerInfo: Unknown Type - %X\n", Type);
        ASSERT(FALSE);
        return FALSE;
    }

    TypesBitMask = 1 << IoDescriptorType;

    DPRINT("IopFindResourceHandlerInfo: TypesBitMask - %04X, NoBitMask - %04X\n",
           TypesBitMask, NoBitMask);

    if (NoBitMask & TypesBitMask)
    {
        DPRINT("IopFindResourceHandlerInfo: return TRUE\n");
        Result = TRUE;
    }
    else if (QueryBitMask & TypesBitMask)
    {
        for (Entry = Head->Flink;
             Entry != Head;
             Entry = Entry->Flink)
        {
            ArbEntry = CONTAINING_RECORD(Entry,
                                         PI_RESOURCE_ARBITER_ENTRY,
                                         DeviceArbiterList);

            if (ArbEntry->ResourceType == IoDescriptorType)
            {
                break;
            }
        }

        ASSERT(Entry != Head);
        *OutArbEntry = ArbEntry;

        DPRINT("IopFindResourceHandlerInfo: return TRUE\n");
        Result = TRUE;
    }
    else
    {
        if (IoDescriptorType > IOP_MAX_MAIN_RESOURCE_TYPE)
        {
            for (Entry = Head->Flink;
                 Entry != Head;
                 Entry = Entry->Flink)
            {
                ArbEntry = CONTAINING_RECORD(Entry,
                                             PI_RESOURCE_ARBITER_ENTRY,
                                             DeviceArbiterList);

                if (ArbEntry->ResourceType == IoDescriptorType)
                {
                    break;
                }
            }

            if (ArbEntry->ArbiterInterface)
            {
                *OutArbEntry = ArbEntry;
            }

            DPRINT("IopFindResourceHandlerInfo: return TRUE\n");
            Result = TRUE;
        }
        else
        {
            DPRINT("IopFindResourceHandlerInfo: return FALSE\n");
            Result = FALSE;
        }
    }

    return Result;
}

NTSTATUS
NTAPI
IopSetupArbiterAndTranslators(
    _In_ PPNP_REQ_DESCRIPTOR ReqDescriptor)
{
    PDEVICE_OBJECT PhysicalDevice;
    ARBITER_REQUEST_SOURCE AllocationType;
    PDEVICE_NODE DeviceNode;
    PPI_RESOURCE_ARBITER_ENTRY ResArbiterEntry;
    PPI_RESOURCE_TRANSLATOR_ENTRY TranslatorEntry;
    PPNP_REQ_DESCRIPTOR TranslatedReqDesc;
    USHORT TypesBitMask;
    PVOID Interface;
    NTSTATUS Status;
    UCHAR IoDescriptorType;
    BOOLEAN IsFindTranslator = TRUE;
    BOOLEAN IsTranslatorFound = FALSE;
    BOOLEAN IsFindBus;
    BOOLEAN IsArbiterFound = FALSE;
    BOOLEAN Result;

    PhysicalDevice = ReqDescriptor->ReqEntry.PhysicalDevice;
    AllocationType = ReqDescriptor->ReqEntry.AllocationType;
    IoDescriptorType = ReqDescriptor->TranslatedReqDesc->ReqEntry.IoDescriptor->Type;

    DPRINT("IopSetupArbiterAndTranslators: ReqDescriptor - %p, PhysicalDevice - %p, descriptor type - %X\n",
           ReqDescriptor, PhysicalDevice, IoDescriptorType);

    if (AllocationType == ArbiterRequestHalReported &&
        ReqDescriptor->InterfaceType == Internal)
    {
        IsFindBus = FALSE;
    }
    else
    {
        IsFindBus = TRUE;
    }

    if (PhysicalDevice &&
        AllocationType != ArbiterRequestHalReported)
    {
        DeviceNode = IopGetDeviceNode(PhysicalDevice);
    }
    else
    {
        DeviceNode = IopRootDeviceNode;
    }

    while (DeviceNode)
    {
        if (DeviceNode == IopRootDeviceNode &&
            !IsTranslatorFound &&
            IsFindBus)
        {
            IsFindBus = FALSE;

            DeviceNode = IopFindLegacyBusDeviceNode(ReqDescriptor->InterfaceType,
                                                    ReqDescriptor->BusNumber);

            if (DeviceNode == IopRootDeviceNode &&
                ReqDescriptor->AltList->ReqList->InterfaceType == Internal)
            {
                DeviceNode = IopFindLegacyBusDeviceNode(Isa, 0);
            }

            continue;
        }

        if (!IsArbiterFound &&
            DeviceNode->PhysicalDeviceObject != PhysicalDevice)
        {
            Result = IopFindResourceHandlerInfo(IOP_RES_HANDLER_TYPE_ARBITER,
                                                DeviceNode,
                                                IoDescriptorType,
                                                (PVOID *)&ResArbiterEntry);
            if (!Result)
            {
                if (IoDescriptorType <= IOP_MAX_MAIN_RESOURCE_TYPE)
                {
                    TypesBitMask = 1 << IoDescriptorType;
                }
                else
                {
                    TypesBitMask = 0;
                }

                DeviceNode->QueryArbiterMask |= TypesBitMask;

                Status = IopQueryResourceHandlerInterface(IOP_RES_HANDLER_TYPE_ARBITER,
                                                          DeviceNode->PhysicalDeviceObject,
                                                          IoDescriptorType,
                                                          &Interface);
                if (!NT_SUCCESS(Status))
                {
                    DeviceNode->NoArbiterMask |= TypesBitMask;

                    if (IoDescriptorType <= IOP_MAX_MAIN_RESOURCE_TYPE)
                    {
                        ASSERT(ResArbiterEntry == NULL);
                        goto FindTranslator;
                    }

                    Interface = NULL;
                }

                ResArbiterEntry = ExAllocatePoolWithTag(PagedPool,
                                                        sizeof(PI_RESOURCE_ARBITER_ENTRY),
                                                        'erpP');
                if (!ResArbiterEntry)
                {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                ResArbiterEntry->ResourcesChanged = 0;
                ResArbiterEntry->State = 0;

                InitializeListHead(&ResArbiterEntry->ActiveArbiterList);
                InitializeListHead(&ResArbiterEntry->BestConfig);
                InitializeListHead(&ResArbiterEntry->ResourceList);
                InitializeListHead(&ResArbiterEntry->BestResourceList);
                InitializeListHead(&ResArbiterEntry->DeviceArbiterList);

                InsertTailList(&DeviceNode->DeviceArbiterList,
                               &ResArbiterEntry->DeviceArbiterList);

                ResArbiterEntry->ResourceType = IoDescriptorType;
                ResArbiterEntry->Level = DeviceNode->Level;
                ResArbiterEntry->ArbiterInterface = Interface;

                if (!Interface)
                {
                    ResArbiterEntry = NULL;
                }
            }

            if (ResArbiterEntry)
            {
                if (ResArbiterEntry->ArbiterInterface->Flags & 1) // FIXME
                {
                    ASSERT(FALSE);

                    Status = 0;//IopCallArbiter(ResArbiterEntry,
                               //             ArbiterActionQueryArbitrate,
                               //             ReqDescriptor->TranslatedReqDesc,
                               //             NULL,
                               //             NULL);

                    if (!NT_SUCCESS(Status))
                    {
                        IsArbiterFound = FALSE;
                    }
                }
                else
                {
                    IsArbiterFound = TRUE;

                    ResArbiterEntry->State = 0;
                    ResArbiterEntry->ResourcesChanged = 0;

                    ReqDescriptor->ArbiterEntry = ResArbiterEntry;
                }
            }
        }

FindTranslator:

        if (!IsFindTranslator)
        {
            DeviceNode = DeviceNode->Parent;
            continue;
        }

        Result = IopFindResourceHandlerInfo(IOP_RES_HANDLER_TYPE_TRANSLATOR,
                                            DeviceNode,
                                            IoDescriptorType,
                                            (PVOID *)&TranslatorEntry);
        if (!Result)
        {
            BOOLEAN IsFind = FALSE;

            if (IoDescriptorType <= IOP_MAX_MAIN_RESOURCE_TYPE)
            {
                TypesBitMask = 1 << IoDescriptorType;
            }
            else
            {
                TypesBitMask = 0;
            }

            Status = IopQueryResourceHandlerInterface(IOP_RES_HANDLER_TYPE_TRANSLATOR,
                                                      DeviceNode->PhysicalDeviceObject,
                                                      IoDescriptorType,
                                                      &Interface);

            DeviceNode->QueryTranslatorMask |= TypesBitMask;

            if (!NT_SUCCESS(Status))
            {
                DeviceNode->NoTranslatorMask |= TypesBitMask;

                if (IoDescriptorType > IOP_MAX_MAIN_RESOURCE_TYPE)
                {
                    Interface = NULL;
                }
                else
                {
                    IsFind = TRUE;
                }
            }

            if (!IsFind)
            {
                TranslatorEntry = ExAllocatePoolWithTag(PagedPool,
                                                        sizeof(PI_RESOURCE_TRANSLATOR_ENTRY),
                                                        'erpP');
                if (!TranslatorEntry)
                {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                TranslatorEntry->ResourceType = IoDescriptorType;
                TranslatorEntry->TranslatorInterface = Interface;
                TranslatorEntry->DeviceNode = DeviceNode;

                InitializeListHead(&TranslatorEntry->DeviceTranslatorList);

                InsertTailList(&DeviceNode->DeviceTranslatorList,
                               &TranslatorEntry->DeviceTranslatorList);

                if (!Interface)
                {
                    TranslatorEntry = NULL;
                }
            }
        }

        if (TranslatorEntry)
        {
            IsTranslatorFound = TRUE;
        }

        if (!IsArbiterFound && TranslatorEntry)
        {
            ASSERT(FALSE);TranslatedReqDesc = 0;
            Status = 0;//IopTranslateAndAdjustReqDesc(ReqDescriptor->TranslatedReqDesc,
                       //                           TranslatorEntry,
                       //                           &TranslatedReqDesc);

            if (!NT_SUCCESS(Status))
            {
                DPRINT("IopSetupArbiterAndTranslators: Status - %X\n", Status);
                return Status;
            }

            ASSERT(TranslatedReqDesc);

            IoDescriptorType = TranslatedReqDesc->ReqEntry.IoDescriptor->Type;
            TranslatedReqDesc->TranslatedReqDesc = ReqDescriptor->TranslatedReqDesc;
            ReqDescriptor->TranslatedReqDesc = TranslatedReqDesc;

            if (Status == STATUS_TRANSLATION_COMPLETE)
            {
                IsFindTranslator = FALSE;
            }
        }

        DeviceNode = DeviceNode->Parent;
    }

    if (IsArbiterFound)
    {
        return STATUS_SUCCESS;
    }

    DPRINT("IopSetupArbiterAndTranslators: no arbiter for resource type - %X \n",
           IoDescriptorType);

    ASSERT(IsArbiterFound);

    return STATUS_RESOURCE_TYPE_NOT_FOUND;
}

VOID
NTAPI
IopFreeReqAlternative(
    _In_ PPNP_REQ_ALT_LIST AltList)
{
    PPNP_REQ_DESCRIPTOR * ReqDescriptors;
    PPNP_REQ_DESCRIPTOR Current;
    PPNP_REQ_DESCRIPTOR reqDesc;
    PIO_RESOURCE_DESCRIPTOR IoDescriptor;
    ULONG ix;

    PAGED_CODE();
    DPRINT("IopFreeReqAlternative: AltList - %p\n", AltList);

    if (!AltList)
    {
        return;
    }

    ReqDescriptors = AltList->ReqDescriptors;

    for (ix = 0; ix < AltList->CountDescriptors; ix++)
    {
        Current = (*ReqDescriptors)->TranslatedReqDesc;

        while (Current && !Current->AltList)
        {
            IoDescriptor = Current->ReqEntry.IoDescriptor;

            if (IoDescriptor)
            {
                DPRINT("IopFreeReqAlternative: Free IoDescriptor - %p\n", IoDescriptor);
                ExFreePool(IoDescriptor);
            }

            reqDesc = Current;
            Current = Current->TranslatedReqDesc;

            DPRINT("IopFreeReqAlternative: Free reqDesc - %p\n", reqDesc);
            ExFreePool(reqDesc);
        }

        ReqDescriptors++;
    }
}

VOID
NTAPI
IopFreeReqList(
    _In_ PPNP_REQ_LIST ReqList)
{
    PPNP_REQ_ALT_LIST * AltList;
    ULONG ix;

    PAGED_CODE();
    DPRINT("IopFreeReqList: ReqList - %p\n", ReqList);

    if (!ReqList)
    {
        return;
    }

    AltList = ReqList->AltLists;

    for (ix = 0; ix < ReqList->Count; ix++)
    {
        IopFreeReqAlternative(*AltList);
        AltList++;
    }

    DPRINT("IopFreeReqList: Free ReqList - %p\n", ReqList);
    ExFreePoolWithTag(ReqList, 'erpP');
}

/*
PPNP_REQ_LIST ReqList:
|=====================================================================
| fields ...
| PPNP_REQ_ALT_LIST AltLists[000]; // pointer to alternative list 000
| PPNP_REQ_ALT_LIST AltLists[...]; // pointer to alternative list ...
| PPNP_REQ_ALT_LIST AltLists[xxx]; // pointer to alternative list xxx
|=====================================================================
|  AltListsPool:
|=====================================================================
|--- struct _PNP_REQ_ALT_LIST [000] ----------------------------------
| fields ... 
| PPNP_REQ_DESCRIPTOR ReqDescriptors[000]; // pointer to descriptor
| PPNP_REQ_DESCRIPTOR ReqDescriptors[...]; // pointer to descriptor
| PPNP_REQ_DESCRIPTOR ReqDescriptors[mmm]; // pointer to descriptor
|---------------------------------------------------------------------
|
| ...
| ...
| ...
|
|--- struct _PNP_REQ_ALT_LIST [xxx] ----------------------------------
| fields ... 
| PPNP_REQ_DESCRIPTOR ReqDescriptors[nnn]; // pointer to descriptor
| PPNP_REQ_DESCRIPTOR ReqDescriptors[...]; // pointer to descriptor
| PPNP_REQ_DESCRIPTOR ReqDescriptors[zzz]; // pointer to descriptor
|=====================================================================
| ReqDescsPool:
|=====================================================================
|--- struct _PNP_REQ_DESCRIPTOR [000] --------------------------------
| ...
|---------------------------------------------------------------------
|--- struct _PNP_REQ_DESCRIPTOR [...] --------------------------------
| ...
|---------------------------------------------------------------------
|--- struct _PNP_REQ_DESCRIPTOR [mmm] --------------------------------
| ...
|---------------------------------------------------------------------
|
| ...
| ...
| ...
|
|--- struct _PNP_REQ_DESCRIPTOR [nnn] --------------------------------
| ...
|---------------------------------------------------------------------
|--- struct _PNP_REQ_DESCRIPTOR [...] --------------------------------
| ...
|---------------------------------------------------------------------
|--- struct _PNP_REQ_DESCRIPTOR [zzz] --------------------------------
| ...
|---------------------------------------------------------------------
|=====================================================================
end ReqList
*/

NTSTATUS
NTAPI
IopResourceRequirementsListToReqList(
    _In_ PPNP_RESOURCE_REQUEST ResRequest,
    _Out_ PPNP_REQ_LIST * OutReqList)
{
    PIO_RESOURCE_REQUIREMENTS_LIST IoResources;
    ULONG_PTR IoResourcesEnd;
    PIO_RESOURCE_LIST IoList;
    ULONG ListsCount;
    PIO_RESOURCE_DESCRIPTOR IoDescriptor;
    PIO_RESOURCE_DESCRIPTOR IoDescriptorEnd;
    PIO_RESOURCE_DESCRIPTOR FirstIoDescriptor;
    ULONG IoDescCount;
    ULONG AltIoDescCount;
    ULONG PrefIoDescCount;
    ULONG ListPoolSize;
    PPNP_REQ_ALT_LIST AltListsPool;
    ULONG AltListsPoolSize;
    PPNP_REQ_DESCRIPTOR ReqDescsPool;
    ULONG ReqDescsPoolSize;
    PPNP_REQ_LIST ReqList;
    ULONG ReqListSize;
    PPNP_REQ_ALT_LIST * pAltLists; // pointer to array AlternativeLists pointers
    PPNP_REQ_ALT_LIST CurrentAltList;
    PPNP_REQ_DESCRIPTOR * pReqDescs; // pointer to array ReqDescriptors pointers
    PPNP_REQ_DESCRIPTOR ReqDesc;
    PPNP_REQ_RESOURCE_ENTRY ReqEntry;
    PPNP_REQ_DESCRIPTOR CurrentReqDesc;
    ULONG_PTR EndPtr;
    ULONG BusNumber;
    ULONG CountAlts;
    INTERFACE_TYPE InterfaceType;
    ULONG IoDescriptorsCount;
    ULONG ix;
    ULONG jx;
    ULONG kx;
    NTSTATUS Status;
    BOOLEAN NoDefaultOrPreferredDescs;
    UCHAR Type;

    PAGED_CODE();

    *OutReqList = NULL;
    IoResources = ResRequest->ResourceRequirements;

    DPRINT("IopResourceRequirementsListToReqList: ResRequest - %p, AlternativeLists - %X\n",
           ResRequest, IoResources->AlternativeLists);

    if (!IoResources->AlternativeLists)
    {
        DPRINT("IopResourceRequirementsListToReqList: AlternativeLists == 0\n");
        return STATUS_SUCCESS;
    }

    IoResourcesEnd = (ULONG_PTR)IoResources + IoResources->ListSize;
    IoList = &IoResources->List[0];

    IoDescCount = 0;
    AltIoDescCount = 0;

    for (ix = 0; ix < IoResources->AlternativeLists; ix++)
    {
        if (IoList->Count == 0)
        {
            DPRINT("IopResourceRequirementsListToReqList: IoList->Count == 0\n");
            return STATUS_SUCCESS;
        }

        IoDescriptor = &IoList->Descriptors[0];

        IoDescriptorEnd = (PIO_RESOURCE_DESCRIPTOR)
                          ((ULONG_PTR)IoList + sizeof(IO_RESOURCE_LIST) +
                           (IoList->Count - 1) * sizeof(IO_RESOURCE_DESCRIPTOR));

        if (IoDescriptor > IoDescriptorEnd ||
            (ULONG_PTR)IoDescriptor > IoResourcesEnd ||
            (ULONG_PTR)IoDescriptorEnd > IoResourcesEnd)
        {
            DPRINT("IopResourceRequirementsListToReqList: Invalid ResReqList\n");
            return STATUS_INVALID_PARAMETER;
        }

        /* ConfigData descriptors are per-LogConf
           and should be at the beginning of an AlternativeList */

        if (IoDescriptor->Type == CmResourceTypeConfigData)
        {
            DPRINT("IopResourceRequirementsListToReqList: ConfigData descriptor\n");
            IoDescriptor++;
        }

        FirstIoDescriptor = IoDescriptor;

        NoDefaultOrPreferredDescs = TRUE;

        while (IoDescriptor < IoDescriptorEnd)
        {
            Type = IoDescriptor->Type;

            if (Type == CmResourceTypeConfigData)
            {
                DPRINT("IopResourceRequirementsListToReqList: Invalid ResReq list!\n");
                return STATUS_INVALID_PARAMETER;
            }

            if ( Type == CmResourceTypeDevicePrivate )
            {
                while (IoDescriptor < IoDescriptorEnd &&
                       IoDescriptor->Type == CmResourceTypeDevicePrivate)
                {
                    if ( IoDescriptor == FirstIoDescriptor )
                    {
                        DPRINT("IopResourceRequirementsListToReqList: FirstIoDescriptor can not be a DevicePrivate descriptor.\n");
                        return STATUS_INVALID_PARAMETER;
                    }

                    IoDescCount++;
                    IoDescriptor++;
                }

                NoDefaultOrPreferredDescs = TRUE;
                continue;
            }

            IoDescCount++;

            if (Type & CmResourceTypeConfigData || Type == CmResourceTypeNull)
            {
                if (Type == 0xF0)
                {
                    DPRINT("IopResourceRequirementsListToReqList: Type == 0xF0\n");
                    IoDescCount--;
                }

                IoDescriptor->Option = IO_RESOURCE_PREFERRED;
                IoDescriptor++;

                NoDefaultOrPreferredDescs = TRUE;
                continue;
            }

            if (IoDescriptor->Option & IO_RESOURCE_ALTERNATIVE)
            {
                if (NoDefaultOrPreferredDescs)
                {
                    DPRINT("IopResourceRequirementsListToReqList: Alternative without Default or Preferred!\n");
                    return STATUS_INVALID_PARAMETER;
                }

                AltIoDescCount++;
                DPRINT("IopResourceRequirementsListToReqList: AltIoDescCount - %X\n",
                       AltIoDescCount);
            }
            else
            {
                NoDefaultOrPreferredDescs = FALSE;
            }

            IoDescriptor++;
        }

        ASSERT(IoDescriptor == IoDescriptorEnd);
        IoList = (PIO_RESOURCE_LIST)IoDescriptorEnd;
    }

    Status = STATUS_UNSUCCESSFUL;

    ListsCount = IoResources->AlternativeLists;
    PrefIoDescCount = IoDescCount - AltIoDescCount;

    ListPoolSize = FIELD_OFFSET(PNP_REQ_LIST, AltLists) +
                   ListsCount * sizeof(PPNP_REQ_ALT_LIST);
    DPRINT("IopResourceRequirementsListToReqList: ListsCount - %X, ListPoolSize - %X\n",
           ListsCount, ListPoolSize);

    AltListsPoolSize = ListsCount * (FIELD_OFFSET(PNP_REQ_ALT_LIST, ReqDescriptors) +
                       PrefIoDescCount * sizeof(PPNP_REQ_DESCRIPTOR));
    DPRINT("IopResourceRequirementsListToReqList: AltListsPoolSize  - %X\n",
           AltListsPoolSize);

    ReqDescsPoolSize = PrefIoDescCount * sizeof(PNP_REQ_DESCRIPTOR);
    DPRINT("IopResourceRequirementsListToReqList: PrefIoDescCount - %X, ReqDescsPoolSize - %X\n",
           PrefIoDescCount, ReqDescsPoolSize);

    ReqListSize = ListPoolSize + AltListsPoolSize + ReqDescsPoolSize;

    ReqList = ExAllocatePoolWithTag(PagedPool, ReqListSize, 'erpP');

    if (!ReqList)
    {
        ASSERT(FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ReqList, ReqListSize);
    DPRINT("IopResourceRequirementsListToReqList: ReqList - %X, ReqListSize - %X\n",
           ReqList, ReqListSize);

    pAltLists = &ReqList->AltLists[0];
    DPRINT("IopResourceRequirementsListToReqList: pAltLists - %X, ListsCount - %X\n",
           pAltLists, ListsCount);

    AltListsPool = (PPNP_REQ_ALT_LIST)((ULONG_PTR)ReqList + ListPoolSize);
    DPRINT("IopResourceRequirementsListToReqList: AltListsPool - %X, AltListsPoolSize - %X\n",
           AltListsPool, AltListsPoolSize);

    ReqDescsPool = (PPNP_REQ_DESCRIPTOR)((ULONG_PTR)AltListsPool + AltListsPoolSize);
    DPRINT("IopResourceRequirementsListToReqList: ReqDescsPool - %X, ReqDescsPoolSize - %X\n",
           ReqDescsPool, ReqDescsPoolSize);

    InterfaceType = IoResources->InterfaceType;

    if (InterfaceType == InterfaceTypeUndefined)
    {
        InterfaceType = PnpDefaultInterfaceType;
    }

    ReqList->InterfaceType = InterfaceType;
    ReqList->BusNumber = IoResources->BusNumber;
    ReqList->ResRequest = ResRequest;
    ReqList->AltList1 = NULL;
    ReqList->Count = ListsCount;

    IoList = &IoResources->List[0];

    InterfaceType = IoResources->InterfaceType;
    BusNumber = IoResources->BusNumber;

    CountAlts = 0;
    CurrentReqDesc = ReqDescsPool;

    EndPtr = (ULONG_PTR)AltListsPool;

    for (ix = 0; ix < ListsCount; ix++)
    {
        DPRINT("IopResourceRequirementsListToReqList: ix - %X\n", ix);

        IoDescriptorsCount = IoList->Count;
        IoDescriptor = &IoList->Descriptors[0];
        IoDescriptorEnd = &IoDescriptor[IoDescriptorsCount];

        CurrentAltList = (PPNP_REQ_ALT_LIST)EndPtr;
        *pAltLists = CurrentAltList;
        pAltLists++;

        CurrentAltList->ListNumber = CountAlts++;
        CurrentAltList->CountDescriptors = 0;
        CurrentAltList->ReqList = ReqList;

        if (IoDescriptor->Type == CmResourceTypeConfigData)
        {
            CurrentAltList->ConfigPriority = IoDescriptor->u.ConfigData.Priority;
            IoDescriptor++;
        }
        else
        {
            CurrentAltList->ConfigPriority = LCPRI_NORMAL;
        }

        pReqDescs = &CurrentAltList->ReqDescriptors[0];
        EndPtr = (ULONG_PTR)pReqDescs;

        if (IoDescriptor >= IoDescriptorEnd)
        {
            goto NextList;
        }

        for (jx = 0; IoDescriptor < IoDescriptorEnd; jx++)
        {
            if (IoDescriptor->Type == 0xF0)
            {
                InterfaceType = IoDescriptor->u.DevicePrivate.Data[0];

                if (InterfaceType == InterfaceTypeUndefined)
                {
                    InterfaceType = PnpDefaultInterfaceType;
                }

                BusNumber = IoDescriptor->u.DevicePrivate.Data[1];

                IoDescriptor++;
                continue;
            }

            DPRINT("IopResourceRequirementsListToReqList: jx - %X\n", jx);

            ReqDesc = CurrentReqDesc;
            ReqDesc->IsArbitrated = (IoDescriptor->Type != CmResourceTypeNull);
            ReqDesc->AltList = CurrentAltList;
            ReqDesc->InterfaceType = InterfaceType;
            ReqDesc->TranslatedReqDesc = ReqDesc;
            ReqDesc->BusNumber = BusNumber;
            ReqDesc->DescriptorsCount = 0;
            ReqDesc->DevicePrivateIoDesc = NULL;
            ReqDesc->DescNumber = jx;

            ReqEntry = &ReqDesc->ReqEntry;
            ReqEntry->InterfaceType = InterfaceType;
            ReqEntry->SlotNumber = IoResources->SlotNumber;
            ReqEntry->BusNumber = IoResources->BusNumber;
            ReqEntry->PhysicalDevice = ResRequest->PhysicalDevice;
            ReqEntry->AllocationType = ResRequest->AllocationType;
            ReqEntry->IoDescriptor = IoDescriptor;
            ReqEntry->pCmDescriptor = &ReqDesc->ReqEntry.CmDescriptor;
            ReqEntry->Count = 0;
            ReqEntry->Reserved1 = CurrentAltList->ConfigPriority == LCPRI_BOOTCONFIG;
            ReqEntry->Reserved2 = 0;
            ReqEntry->Reserved4 = -1;

            InitializeListHead(&ReqEntry->Link);

            CurrentAltList->CountDescriptors++;
            *pReqDescs = ReqDesc;
            pReqDescs++;
            CurrentReqDesc++;
            EndPtr = (ULONG_PTR)pReqDescs;

            if (ReqDesc->IsArbitrated)
            {
                NTSTATUS status;

                ASSERT(!(IoDescriptor->Option & IO_RESOURCE_ALTERNATIVE));

                ReqDesc->ReqEntry.CmDescriptor.Type = 7; // ?
                ReqDesc->ReqEntry.Count++;

                for (kx = ReqDesc->ReqEntry.Count; ; kx++)
                {
                    IoDescriptor++;

                    if (IoDescriptor >= IoDescriptorEnd)
                    {
                        break;
                    }

                    if (IoDescriptor->Type == CmResourceTypeDevicePrivate)
                    {
                        DPRINT("IopResourceRequirementsListToReqList: kx - %X\n", kx);
                        ReqDesc->DevicePrivateIoDesc = IoDescriptor;

                        while (IoDescriptor < IoDescriptorEnd &&
                               IoDescriptor->Type == CmResourceTypeDevicePrivate)
                        {
                            ReqDesc->DescriptorsCount++;
                            IoDescriptor++;
                        }

                        break;
                    }

                    if (!(IoDescriptor->Option & IO_RESOURCE_ALTERNATIVE))
                    {
                        break;
                    }

                    ReqDesc->ReqEntry.Count = kx;
                }

                IopDumpReqDescriptor(ReqDesc, jx+1);
                status = IopSetupArbiterAndTranslators(ReqDesc);
                IopDumpReqDescriptor(ReqDesc, jx+1);

                if (!NT_SUCCESS(status))
                {
                    DPRINT("IopResourceRequirementsListToReqList: Unable to setup Arbiter and Translators\n");

                    CountAlts--;
                    pAltLists--;
                    ReqList->Count--;

                    ASSERT(FALSE);
                    //IopFreeReqAlternative(CurrentAltList);

                    Status = status;
                    break;
                }
            }
            else
            {
                PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;

                CmDescriptor = &ReqDesc->ReqEntry.CmDescriptor;
                CmDescriptor->Type = IoDescriptor->Type;
                CmDescriptor->ShareDisposition = IoDescriptor->ShareDisposition;
                CmDescriptor->Flags = IoDescriptor->Flags;

                CmDescriptor->u.DevicePrivate.Data[0] = IoDescriptor->u.DevicePrivate.Data[0];
                CmDescriptor->u.DevicePrivate.Data[1] = IoDescriptor->u.DevicePrivate.Data[1];
                CmDescriptor->u.DevicePrivate.Data[2] = IoDescriptor->u.DevicePrivate.Data[2];

                IoDescriptor++;
            }
        }

NextList:
        IoList = (PIO_RESOURCE_LIST)IoDescriptorEnd;
    }

    if (CountAlts != 0)
    {
        *OutReqList = ReqList;
        return STATUS_SUCCESS;
    }

    IopFreeReqList(ReqList);

    if (Status != STATUS_SUCCESS)
    {
        return Status;
    }

    *OutReqList = ReqList;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IopAssignResourcesToDevices(
    _In_ ULONG DeviceCount,
    _In_ PPNP_RESOURCE_REQUEST ResContext,
    _In_ BOOLEAN Config,
    _Out_ BOOLEAN * OutIsAssigned)
{
    KEY_VALUE_PARTIAL_INFORMATION KeyValueInformation;
    PDEVICE_NODE DeviceNode;
    ULONG DeviceReported;
    UNICODE_STRING ValueName;
    ULONG ResultLength;
    HANDLE KeyHandle;
    ULONG Idx;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IopAssignResourcesToDevices: ResContext - %p, DeviceCount - %X\n",
           ResContext, DeviceCount);

    ASSERT(DeviceCount);

    for (Idx = 0; Idx < DeviceCount; Idx++)
    {
        ResContext[Idx].Flags = 0;
        ResContext[Idx].AllocationType = ArbiterRequestPnpEnumerated;
        ResContext[Idx].ResourceAssignment = NULL;
        ResContext[Idx].Status = STATUS_SUCCESS;

        DeviceNode = IopGetDeviceNode(ResContext[Idx].PhysicalDevice);

        DPRINT("IopAssignResourcesToDevices: Idx - %X, DeviceNode - %p, Flags - %X\n",
               Idx, DeviceNode, DeviceNode->Flags);

        if (!(DeviceNode->Flags & DNF_MADEUP))
        {
            goto Next;
        }

        DeviceReported = 0;

        Status = PnpDeviceObjectToDeviceInstance(ResContext[Idx].PhysicalDevice,
                                                 &KeyHandle,
                                                 KEY_READ);
        if (!NT_SUCCESS(Status))
        {
            goto Next;
        }

        ResultLength = 0;
        RtlInitUnicodeString(&ValueName, L"DeviceReported");

        Status = ZwQueryValueKey(KeyHandle,
                                 &ValueName,
                                 KeyValuePartialInformation,
                                 &KeyValueInformation,
                                 sizeof(KEY_VALUE_PARTIAL_INFORMATION) +
                                   sizeof(DeviceReported),
                                 &ResultLength);

        if (NT_SUCCESS(Status))
        {
            DeviceReported = *(PULONG)&KeyValueInformation.Data[0];
        }

        ZwClose(KeyHandle);

        if (DeviceReported != 0)
        {
            ASSERT(FALSE);
            ResContext[Idx].AllocationType = ArbiterRequestLegacyReported;
        }

Next:
        ResContext[Idx].ResourceRequirements = NULL;
        IopDumpResRequest(&ResContext[Idx]);
    }

 ASSERT(FALSE);
    Status = 0;//IopAllocateResources(&DeviceCount,
               //                   &ResContext,
               //                   FALSE,
               //                   Config,
               //                   OutIsAssigned);
    return Status;
}

NTSTATUS
IopProcessAssignResourcesWorker(
    _In_ PDEVICE_NODE DeviceNode,
    _Inout_ PVOID Context)
{
    PPIP_ASSIGN_RESOURCES_CONTEXT AssignContext;

    PAGED_CODE();
    AssignContext = Context;

    if (AssignContext->IncludeFailedDevices)
    {
        if ((DeviceNode->Flags & DNF_HAS_PROBLEM) && 
            ((DeviceNode->Problem == CM_PROB_NORMAL_CONFLICT) ||
             (DeviceNode->Problem == CM_PROB_TRANSLATION_FAILED) ||
             (DeviceNode->Problem == CM_PROB_IRQ_TRANSLATION_FAILED)))
        {
            PipClearDevNodeProblem(DeviceNode);
        }
    }

    if ((DeviceNode->Flags & DNF_HAS_PROBLEM)||
        (DeviceNode->Flags & DNF_HAS_PRIVATE_PROBLEM))
    {
        DPRINT("IopProcessAssignResourcesWorker: PDO - %p, DeviceNode - %p, DeviceNode->Flags - %X\n",
               DeviceNode->PhysicalDeviceObject, DeviceNode, DeviceNode->Flags);
        return STATUS_SUCCESS;
    }

    if (DeviceNode->State == DeviceNodeDriversAdded)
    {
        AssignContext->DeviceList[AssignContext->DeviceCount] = DeviceNode->PhysicalDeviceObject;
        DPRINT("IopProcessAssignResourcesWorker: PhysicalDeviceObject - %p\n",
               DeviceNode->PhysicalDeviceObject);

        AssignContext->DeviceCount++;
        DPRINT("IopProcessAssignResourcesWorker: DeviceCount - %X\n", AssignContext->DeviceCount);
    }

    return STATUS_SUCCESS;
}

BOOLEAN
NTAPI
IopProcessAssignResources(
    _In_ PDEVICE_NODE DeviceNode,
    _In_ BOOLEAN IncludeFailedDevices,
    _Inout_ BOOLEAN *OutIsAssigned)
{
    PPIP_ASSIGN_RESOURCES_CONTEXT AssignContext;
    DEVICETREE_TRAVERSE_CONTEXT Context;
    PPNP_RESOURCE_REQUEST ResRequest;
    PDEVICE_NODE node;
    ULONG AssignContextSize;
    ULONG DeviceCount;
    ULONG MaxConfigs;
    ULONG ConfigNum;
    ULONG ix;
    NTSTATUS Status;
    BOOLEAN IsRetry = TRUE;
    BOOLEAN IsAssignBootConfig;
    BOOLEAN Result = FALSE;

    PAGED_CODE();

    if (IopBootConfigsReserved)
    {
         MaxConfigs = 1;
    }
    else
    {
         MaxConfigs = 2;
    }

    DPRINT("IopProcessAssignResources: DeviceNode - %p, IncludeFailedDevices - %X, MaxConfigs - %X\n",
           DeviceNode, IncludeFailedDevices, MaxConfigs);

    for (ConfigNum = 0; ; ConfigNum++)
    {
        DPRINT("IopProcessAssignResources: ConfigNum %X\n", ConfigNum);

        if (IsRetry == FALSE || ConfigNum >= MaxConfigs)
        {
            DPRINT("IopProcessAssignResources: return Result - %X\n", Result);
            Result = FALSE;
            break;
        }

        IsRetry = FALSE;

        AssignContextSize = sizeof(PNP_RESOURCE_REQUEST) +
                            IopNumberDeviceNodes * sizeof(PDEVICE_OBJECT);

        AssignContext = ExAllocatePoolWithTag(PagedPool, AssignContextSize, 'ddpP');
        if (!AssignContext)
        {
            ASSERT(FALSE);
            Result = FALSE;
            break;
        }

        AssignContext->DeviceCount = 0;
        AssignContext->IncludeFailedDevices = IncludeFailedDevices;

        IopInitDeviceTreeTraverseContext(&Context,
                                         DeviceNode,
                                         IopProcessAssignResourcesWorker,
                                         AssignContext);

        Status = IopTraverseDeviceTree(&Context);

        DeviceCount = AssignContext->DeviceCount;
        if (DeviceCount == 0)
        {
            DPRINT("IopProcessAssignResources: DeviceCount == 0\n");
            ExFreePoolWithTag(AssignContext, 'ddpP');
            Result = FALSE;
            break;
        }

        DPRINT("IopProcessAssignResources: DeviceCount - %x\n", DeviceCount);
        ResRequest = ExAllocatePoolWithTag(PagedPool,
                                           DeviceCount * sizeof(PNP_RESOURCE_REQUEST),
                                           'ddpP');
        if (!ResRequest)
        {
            ASSERT(FALSE);
            goto Next;
        }

        for (ix = 0; ix < DeviceCount; ix++)
        {
            ResRequest[ix].PhysicalDevice = AssignContext->DeviceList[ix];
            ResRequest[ix].ReqList = NULL;
            ResRequest[ix].Priority = 0;
        }

        if (ConfigNum == 0)
        {
            IsAssignBootConfig = IopBootConfigsReserved;
        }
        else
        {
            IsAssignBootConfig = TRUE;
        }

        IopAssignResourcesToDevices(DeviceCount, ResRequest, IsAssignBootConfig, OutIsAssigned);

        for (ix = 0; ix < DeviceCount; ix++)
        {
            ;//PipDumpResRequest(&ResRequest[ix]);
        }

        for (ix = 0; ix < DeviceCount; ix++)
        {
            node = IopGetDeviceNode(ResRequest[ix].PhysicalDevice);
            Status = ResRequest[ix].Status;

            DPRINT("IopProcessAssignResources: ConfigNum - %X, Status[%X] - %X\n",
                    ConfigNum, ix, Status);

            if (!NT_SUCCESS(Status))
            {
                switch (Status)
                {
                    case STATUS_RESOURCE_TYPE_NOT_FOUND:
                        ASSERT(FALSE);
                        PipSetDevNodeProblem(node, CM_PROB_UNKNOWN_RESOURCE);
                        break;

                    case STATUS_DEVICE_CONFIGURATION_ERROR:
                        ASSERT(FALSE);
                        PipSetDevNodeProblem(node, CM_PROB_NO_SOFTCONFIG);
                        break;

                    case STATUS_RETRY:
                        DPRINT("IopProcessAssignResources: STATUS_RETRY\n");
                        IsRetry = TRUE;
                        break;

                    case STATUS_PNP_BAD_MPS_TABLE:
                        ASSERT(FALSE);
                        PipSetDevNodeProblem(node, CM_PROB_BIOS_TABLE);
                        break;

                    case STATUS_PNP_TRANSLATION_FAILED:
                        ASSERT(FALSE);
                        PipSetDevNodeProblem(node, CM_PROB_TRANSLATION_FAILED);
                        break;

                    case STATUS_PNP_IRQ_TRANSLATION_FAILED:
                        ASSERT(FALSE);
                        PipSetDevNodeProblem(node, CM_PROB_IRQ_TRANSLATION_FAILED);
                        break;

                    default:
                        ASSERT(FALSE);
                        PipSetDevNodeProblem(node, CM_PROB_NORMAL_CONFLICT);
                        break;
                }
            }
            else
            {
                if (ResRequest[ix].ResourceAssignment)
                {
                    node->ResourceList = ResRequest[ix].ResourceAssignment;
                    node->ResourceListTranslated = ResRequest[ix].TranslatedResourceAssignment;
                }
                else
                {
                    node->Flags |= DNF_NO_RESOURCE_REQUIRED;
                }

                PipSetDevNodeState(node, DeviceNodeResourcesAssigned, FALSE);
                node->UserFlags &= ~4;

                Result = TRUE;
            }
        }

        ExFreePoolWithTag(ResRequest, 'ddpP');

Next:
        ExFreePoolWithTag(AssignContext, 'ddpP');

        if (Result)
        {
           break;
        }
    }

    return Result;
}

NTSTATUS
NTAPI
PipReadDeviceConfiguration(
    _In_ HANDLE KeyHandle,
    _In_ ULONG ConfigType,
    _Out_ PCM_RESOURCE_LIST * OutCmResource,
    _Out_ SIZE_T * OutSize)
{
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    PCM_RESOURCE_LIST CmResource;
    PCM_FULL_RESOURCE_DESCRIPTOR FullList;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor;
    PWCHAR ValueName;
    SIZE_T Length;
    ULONG ix;
    ULONG jx;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("PipReadDeviceConfiguration: KeyHandle - %p, ConfigType - %X\n", KeyHandle, ConfigType);

    *OutCmResource = NULL;
    *OutSize = 0;

    if (ConfigType == 1)
    {
        ValueName = L"AllocConfig";
    }
    else if (ConfigType == 2)
    {
        ValueName = L"ForcedConfig";
    }
    else if (ConfigType == 4)
    {
        ValueName = L"BootConfig";
    }
    else
    {
        DPRINT("PipReadDeviceConfiguration: Unknown ConfigType - %X\n", ConfigType);
        return STATUS_INVALID_PARAMETER_2;
    }

    Status = IopGetRegistryValue(KeyHandle, ValueName, &ValueInfo);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("PipReadDeviceConfiguration: Status - %X\n", Status);
        return Status;
    }

    if (ValueInfo->Type != REG_RESOURCE_LIST)
    {
        DPRINT("PipReadDeviceConfiguration: ValueInfo->Type != REG_RESOURCE_LIST\n");
        Status = STATUS_UNSUCCESSFUL;
        ExFreePoolWithTag(ValueInfo, 'uspP');
        return Status;
    }

    Length = ValueInfo->DataLength;

    if (!Length)
    {
        DPRINT("PipReadDeviceConfiguration: Length - 0\n");
        ExFreePoolWithTag(ValueInfo, 'uspP');
        return Status;
    }

    *OutCmResource = ExAllocatePoolWithTag(PagedPool, Length, 'uspP');

    if (!*OutCmResource)
    {
        DPRINT1("PipReadDeviceConfiguration: STATUS_INSUFFICIENT_RESOURCES\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        ExFreePoolWithTag(ValueInfo, 'uspP');
        return Status;
    }

    *OutSize = ValueInfo->DataLength;

    CmResource = *OutCmResource;

    RtlCopyMemory(CmResource,
                  (PUCHAR)ValueInfo + ValueInfo->DataOffset,
                  ValueInfo->DataLength);

    FullList = CmResource->List;

    for (ix = 0; ix < CmResource->Count; ix++)
    {
        DPRINT("PipReadDeviceConfiguration: ix - %X\n", ix);

        if (FullList->InterfaceType == InterfaceTypeUndefined)
        {
            FullList->BusNumber = 0;
            FullList->InterfaceType = PnpDefaultInterfaceType;
        }

        CmDescriptor = FullList->PartialResourceList.PartialDescriptors;

        for (jx = 0; jx < FullList->PartialResourceList.Count; jx++)
        {
            CmDescriptor = IopGetNextCmPartialDescriptor(CmDescriptor);
        }

        FullList = (PCM_FULL_RESOURCE_DESCRIPTOR)CmDescriptor;
    }

    ExFreePoolWithTag(ValueInfo, 'uspP');

    return Status;
}

NTSTATUS
NTAPI
IopGetDeviceResourcesFromRegistry(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ BOOLEAN ResourcesType,
    _In_ ULONG Flags,
    _Out_ PVOID * OutResource,
    _Out_ SIZE_T * OutSize)
{
    PIO_RESOURCE_REQUIREMENTS_LIST IoResource;
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    UNICODE_STRING ValueName;
    HANDLE InstanceKeyHandle = NULL;
    HANDLE KeyHandle = NULL;
    PWCHAR ConfigVectorName;
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IopGetDeviceResourcesFromRegistry: DeviceObject - %p, Res.Type - %X, Flags - %X\n",
           DeviceObject, ResourcesType, Flags);

    *OutResource = NULL;
    *OutSize = 0;

    Status = PnpDeviceObjectToDeviceInstance(DeviceObject,
                                             &InstanceKeyHandle,
                                             KEY_READ);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopGetDeviceResourcesFromRegistry: Status - %X\n", Status);
        return Status;
    }

    if (ResourcesType)
    {
        /* ResourcesType == TRUE (PIO_RESOURCE_REQUIREMENTS_LIST) */

        RtlInitUnicodeString(&ValueName, L"LogConf");

        Status = IopOpenRegistryKeyEx(&KeyHandle,
                                      InstanceKeyHandle,
                                      &ValueName,
                                      KEY_READ);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("IopGetDeviceResourcesFromRegistry: Status - %X\n", Status);
            ZwClose(InstanceKeyHandle);
            return Status;
        }

        if (Flags & 1)
        {
            ConfigVectorName = L"OverrideConfigVector";
        }
        else if (Flags & 2)
        {
            ConfigVectorName = L"BasicConfigVector";
        }
        else
        {
            goto Exit;
        }

        Status = IopGetRegistryValue(KeyHandle, ConfigVectorName, &ValueInfo);

        if (!NT_SUCCESS(Status))
        {
            DPRINT("IopGetDeviceResourcesFromRegistry: Status - %X\n", Status);
            goto Exit;
        }

        if (ValueInfo->Type != REG_RESOURCE_REQUIREMENTS_LIST ||
            ValueInfo->DataLength == 0)
        {
            ExFreePoolWithTag(ValueInfo, 'uspP');
            goto Exit;
        }

        IoResource = ExAllocatePoolWithTag(PagedPool,
                                           ValueInfo->DataLength,
                                           'uspP');
        *OutResource = IoResource;

        if (!IoResource)
        {
            DPRINT1("IopGetDeviceResourcesFromRegistry: STATUS_INSUFFICIENT_RESOURCES\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            ExFreePoolWithTag(ValueInfo, 'uspP');
            goto Exit;
        }

        *OutSize = ValueInfo->DataLength;

        RtlCopyMemory(IoResource,
                      (PUCHAR)ValueInfo + ValueInfo->DataOffset,
                      ValueInfo->DataLength);

        if (IoResource->InterfaceType == InterfaceTypeUndefined)
        {
            IoResource->BusNumber = 0;
            IoResource->InterfaceType = PnpDefaultInterfaceType;
        }

        ExFreePoolWithTag(ValueInfo, 'uspP');
        goto Exit;
    }

    /* ResourcesType == FALSE (PCM_RESOURCE_LIST) */

    if (Flags & 1)
    {
        RtlInitUnicodeString(&ValueName, L"Control");

        Status = IopOpenRegistryKeyEx(&KeyHandle,
                                      InstanceKeyHandle,
                                      &ValueName,
                                      KEY_READ);
        if (NT_SUCCESS(Status))
        {
            Status = PipReadDeviceConfiguration(KeyHandle,
                                                1,
                                                (PCM_RESOURCE_LIST *)OutResource,
                                                OutSize);
            ZwClose(KeyHandle);

            if (NT_SUCCESS(Status))
            {
                goto Exit;
            }

            DPRINT("IopGetDeviceResourcesFromRegistry: Status - %X\n", Status);
        }
        else
        {
            DPRINT("IopGetDeviceResourcesFromRegistry: Status - %X\n", Status);
        }
    }

    KeyHandle = NULL;

    if (Flags & 2)
    {
        RtlInitUnicodeString(&ValueName, L"LogConf");

        Status = IopOpenRegistryKeyEx(&KeyHandle,
                                      InstanceKeyHandle,
                                      &ValueName,
                                      KEY_READ);
        if (!NT_SUCCESS(Status))
        {
            DPRINT("IopGetDeviceResourcesFromRegistry: Status - %X\n", Status);
            ZwClose(InstanceKeyHandle);
            return Status;
        }

        Status = PipReadDeviceConfiguration(KeyHandle,
                                            2,
                                            (PCM_RESOURCE_LIST *)OutResource,
                                            OutSize);
        if (NT_SUCCESS(Status))
        {
            goto Exit;
        }

        DPRINT("IopGetDeviceResourcesFromRegistry: Status - %X\n", Status);
    }

    if (Flags & 4)
    {
        if (!KeyHandle)
        {
            RtlInitUnicodeString(&ValueName, L"LogConf");

            Status = IopOpenRegistryKeyEx(&KeyHandle,
                                          InstanceKeyHandle,
                                          &ValueName,
                                          KEY_READ);
            if (!NT_SUCCESS(Status))
            {
                DPRINT("IopGetDeviceResourcesFromRegistry: Status - %X\n", Status);
                goto Exit;
            }
        }

        Status = PipReadDeviceConfiguration(KeyHandle,
                                            4,
                                            (PCM_RESOURCE_LIST *)OutResource,
                                            OutSize);
    }

Exit:

    if (!KeyHandle)
    {
        ZwClose(KeyHandle);
    }

    if (!InstanceKeyHandle)
    {
        ZwClose(InstanceKeyHandle);
    }

    return Status;
}

VOID
NTAPI
IopAddRemoveReqDescs(
    _In_ PPNP_REQ_DESCRIPTOR * ResDescriptor,
    _In_ ULONG Count,
    _In_ PLIST_ENTRY List,
    _In_ BOOLEAN AddOrRemove)
{
    PPNP_REQ_LIST ResList;
    PDEVICE_OBJECT DeviceObject;
    PDEVICE_NODE DeviceNode;
    PPNP_REQ_DESCRIPTOR Descriptor;
    PPI_RESOURCE_ARBITER_ENTRY ArbiterEntry;
    ULONG ix;

    PAGED_CODE();
    DPRINT("IopAddRemoveReqDescs: ResDescriptor - %p, Count - %X, AddOrRemove - %X\n",
           ResDescriptor, Count, AddOrRemove);

    if (!Count)
    {
        ASSERT(FALSE);
        return;
    }

    ResList = (*ResDescriptor)->AltList->ReqList;

    DeviceObject = ResList->ResRequest->PhysicalDevice;
    ASSERT(DeviceObject);

    DeviceNode = IopGetDeviceNode(DeviceObject);

    if (AddOrRemove)
    {
        DPRINT("IopAddRemoveReqDescs: Adding %X/%X req alt list to the arbiters for %wZ\n",
               ResList->AltList1[0]->ListNumber + 1,
               ResList->Count,
               &DeviceNode->InstancePath);
    }
    else
    {
        DPRINT("IopAddRemoveReqDescs: Removing %X/%X req alt list from the arbiters for %wZ\n",
               ResList->AltList1[0]->ListNumber + 1,
               ResList->Count,
               &DeviceNode->InstancePath);
    }

    for (ix = 0; ix < Count; ix++)
    {
        Descriptor = ResDescriptor[ix];

        if (Descriptor->IsArbitrated)
        {
            DPRINT("IopAddRemoveReqDescs: Descriptor - %p, ix - %X\n", Descriptor, ix);
        }
        else
        {
            DPRINT("IopAddRemoveReqDescs: Continue, ix - %X\n", ix);
            continue;
        }

        ArbiterEntry = Descriptor->ArbiterEntry;
        ASSERT(ArbiterEntry);

        if (ArbiterEntry->State & 1) // ?
        {
            ASSERT(FALSE);
            ArbiterEntry->State &= ~1;

            ArbiterEntry->ArbiterInterface->
                ArbiterHandler(ArbiterEntry->ArbiterInterface->Context,
                               ArbiterActionRollbackAllocation,
                               NULL);
        }

        ArbiterEntry->ResourcesChanged = 1;

        if (AddOrRemove == 1)
        {
            InitializeListHead(&Descriptor->TranslatedReqDesc->ReqEntry.Link);

            InsertTailList(&ArbiterEntry->ResourceList,
                           &Descriptor->TranslatedReqDesc->ReqEntry.Link);

            if (IsListEmpty(&ArbiterEntry->ActiveArbiterList))
            {
                PLIST_ENTRY entry;
                PPI_RESOURCE_ARBITER_ENTRY arbEntry;

                DPRINT("IopAddRemoveReqDescs: entry - %p, ArbiterEntry - %p\n",
                       entry, ArbiterEntry);

                for (entry = List->Flink;
                     entry != List;
                     entry = entry->Flink)
                {
                    arbEntry = CONTAINING_RECORD(entry,
                                                 PI_RESOURCE_ARBITER_ENTRY,
                                                 ActiveArbiterList);

                    if (arbEntry->Level >= ArbiterEntry->Level)
                    {
                        break;
                    }
                }

                InsertTailList(entry, &ArbiterEntry->ActiveArbiterList);
            }
        }
        else
        {
            ASSERT(FALSE);
            ASSERT(!IsListEmpty(&ArbiterEntry->ResourceList));

            RemoveEntryList(&Descriptor->TranslatedReqDesc->ReqEntry.Link);
            InitializeListHead(&Descriptor->TranslatedReqDesc->ReqEntry.Link);

            if (IsListEmpty(&ArbiterEntry->ResourceList))
            {
                RemoveEntryList(&ArbiterEntry->ActiveArbiterList);
                InitializeListHead(&ArbiterEntry->ActiveArbiterList);
            }
        }
    }
}

VOID
NTAPI
IopCheckDataStructuresWorker(
    _In_ PDEVICE_NODE DeviceNode)
{
    PPI_RESOURCE_ARBITER_ENTRY ArbiterEntry;
    PLIST_ENTRY Entry;

    PAGED_CODE();

    for (Entry = DeviceNode->DeviceArbiterList.Flink;
         Entry != &DeviceNode->DeviceArbiterList;
         Entry = Entry->Flink)
    {
        ArbiterEntry = CONTAINING_RECORD(Entry,
                                         PI_RESOURCE_ARBITER_ENTRY,
                                         DeviceArbiterList);

        if (ArbiterEntry->ArbiterInterface)
        {
            ASSERT(IsListEmpty(&ArbiterEntry->ResourceList));
            ASSERT(IsListEmpty(&ArbiterEntry->ActiveArbiterList));
        }
    }
}

VOID
NTAPI
IopCheckDataStructures(
    _In_ PDEVICE_NODE DeviceNode)
{
    PDEVICE_NODE deviceNode;

    PAGED_CODE();

    for (deviceNode = DeviceNode;
         deviceNode;
         deviceNode = deviceNode->Sibling)
    {
        IopCheckDataStructuresWorker(deviceNode);
    }

    for (deviceNode = DeviceNode;
         deviceNode;
         deviceNode = deviceNode->Sibling)
    {
        if (deviceNode->Child)
        {
            IopCheckDataStructures(deviceNode->Child);
        }
    }
}

NTSTATUS
NTAPI
IopBootAllocation(
    _In_ PPNP_REQ_LIST ReqList)
{
    PPI_RESOURCE_ARBITER_ENTRY ArbiterEntry;
    PPNP_REQ_RESOURCE_ENTRY ReqResDesc;
    ARBITER_PARAMETERS ArbiterParams;
    PLIST_ENTRY Entry;
    PLIST_ENTRY NextEntry;
    LIST_ENTRY List;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();
    DPRINT("IopBootAllocation: ReqList - %p\n", ReqList);

    InitializeListHead(&List);

    ReqList->AltList1 = ReqList->AltLists;

    IopAddRemoveReqDescs(ReqList->AltLists[0]->ReqDescriptors,
                         ReqList->AltLists[0]->CountDescriptors,
                         &List,
                         TRUE);

    for (Entry = List.Flink; !IsListEmpty(&List); Entry = NextEntry)
    {
        ArbiterEntry = CONTAINING_RECORD(Entry,
                                         PI_RESOURCE_ARBITER_ENTRY,
                                         ActiveArbiterList);
        NextEntry = Entry->Flink;

        if (ArbiterEntry->ResourcesChanged)
        {
            ASSERT(IsListEmpty(&ArbiterEntry->ResourceList) == FALSE);

            ArbiterParams.Parameters.BootAllocation.ArbitrationList =
                                     &ArbiterEntry->ResourceList;

            Status = ArbiterEntry->ArbiterInterface->
                     ArbiterHandler(ArbiterEntry->ArbiterInterface->Context,
                                    ArbiterActionBootAllocation,
                                    &ArbiterParams);

            if (!NT_SUCCESS(Status))
            {
                ReqResDesc = CONTAINING_RECORD(ArbiterEntry,
                                               PNP_REQ_RESOURCE_ENTRY,
                                               Link);
                DPRINT("IopBootAllocation: Failed. Count - %X, PDO - %X\n",
                       ReqResDesc->Count, ReqResDesc->PhysicalDevice);

                ASSERT(FALSE);
                IopDumpIoResourceDescriptor("    ", ReqResDesc->IoDescriptor);
            }

            ArbiterEntry->ResourcesChanged = 0; // FIXME UCHAR ==>> BOOLEAN
            ArbiterEntry->State = 0;

            InitializeListHead(&ArbiterEntry->ActiveArbiterList);
            InitializeListHead(&ArbiterEntry->BestConfig);
            InitializeListHead(&ArbiterEntry->ResourceList);
            InitializeListHead(&ArbiterEntry->BestResourceList);
        }

        if (NextEntry == &List)
        {
            break;
        }
    }

    IopCheckDataStructures(IopRootDeviceNode);

    return Status;
}

NTSTATUS
NTAPI
IopAllocateBootResourcesInternal(
    _In_ ARBITER_REQUEST_SOURCE AllocationType,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PCM_RESOURCE_LIST CmResource)
{
    PDEVICE_NODE DeviceNode = NULL;
    PIO_RESOURCE_REQUIREMENTS_LIST IoResources;
    NTSTATUS Status;
    SIZE_T ListSize;
    PCM_RESOURCE_LIST NewList;
    PNP_RESOURCE_REQUEST ResRequest;
    PPNP_REQ_LIST ReqList;

    PAGED_CODE();
    DPRINT("IopAllocateBootResourcesInternal: AllocationType - %X, DeviceObject - %p\n",
           AllocationType, DeviceObject);

    IoResources = IopCmResourcesToIoResources(0, CmResource, LCPRI_BOOTCONFIG);

    if (!IoResources)
    {
        ASSERT(FALSE);
        DPRINT("IopAllocateBootResourcesInternal: STATUS_UNSUCCESSFUL\n");
        return STATUS_UNSUCCESSFUL;
    }

    DeviceNode = IopGetDeviceNode(DeviceObject);

    DPRINT("IopAllocateBootResourcesInternal: IoResources->AlternativeLists - %X, DeviceNode->BootResources - %p\n",
           IoResources->AlternativeLists, DeviceNode->BootResources);

    DPRINT("\n");
    DPRINT("=== BootResourceRequirementsList =======================\n");
    IopDumpResourceRequirementsList(IoResources);
    DPRINT("=== BootResourceRequirementsList end ===================\n");

    ResRequest.AllocationType = AllocationType;
    ResRequest.ResourceRequirements = IoResources;
    ResRequest.PhysicalDevice = DeviceObject;

    DPRINT("\n");
    DPRINT("==IopResourceRequirementsListToReqList()=================================\n");
    Status = IopResourceRequirementsListToReqList(&ResRequest, &ReqList);
    DPRINT("==IopResourceRequirementsListToReqList() end=============================\n");
    DPRINT("\n");

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopAllocateBootResourcesInternal: Status - %X\n", Status);
        ASSERT(FALSE);
        goto Exit;
    }

    if (!ReqList)
    {
        ASSERT(FALSE);
        Status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    Status = IopBootAllocation(ReqList);

    if (!NT_SUCCESS(Status))
    {
        IopFreeReqList(ReqList);
        goto Exit;
    }

    if (!DeviceNode)
    {
        IopFreeReqList(ReqList);
        goto Exit;
    }

    DeviceNode->Flags |= DNF_BOOT_CONFIG_RESERVED;

    if (DeviceNode->BootResources)
    {
        IopFreeReqList(ReqList);
        goto Exit;
    }

    ListSize = PnpDetermineResourceListSize(CmResource);

    NewList = ExAllocatePoolWithTag(PagedPool, ListSize, 'erpP');
    DeviceNode->BootResources = NewList;

    if (!NewList)
    {
        DPRINT1("IopAllocateBootResourcesInternal: STATUS_INSUFFICIENT_RESOURCES\n");
        ASSERT(FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(NewList, CmResource, ListSize);

    IopFreeReqList(ReqList);

Exit:

    ExFreePoolWithTag(IoResources, 'uspP');

    if (!NT_SUCCESS(Status))
    {
        DPRINT("IopAllocateBootResourcesInternal: Status %X\n", Status);
    }

    return Status;
}

NTSTATUS
NTAPI
IopAllocateBootResources(
    _In_ ARBITER_REQUEST_SOURCE AllocationType,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PCM_RESOURCE_LIST CmResource)
{
    NTSTATUS Status;

    PAGED_CODE();
    DPRINT("IopAllocateBootResources: DeviceObject %p\n", DeviceObject);

    KeEnterCriticalRegion();

    KeWaitForSingleObject(&PpRegistrySemaphore,
                          DelayExecution,
                          KernelMode,
                          FALSE,
                          NULL);

    Status = IopAllocateBootResourcesInternal(AllocationType,
                                              DeviceObject,
                                              CmResource);

    KeReleaseSemaphore(&PpRegistrySemaphore, IO_NO_INCREMENT, 1, FALSE);

    KeLeaveCriticalRegion();

    return Status;
}

NTSTATUS
NTAPI
IopReportBootResources(
    _In_ ARBITER_REQUEST_SOURCE AllocationType,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PCM_RESOURCE_LIST CmResource)
{
    PPNP_RESERVED_RESOURCES_CONTEXT ReservedContext;
    PCM_RESOURCE_LIST NewList;
    PCM_RESOURCE_LIST ReservedResource;
    PDEVICE_NODE DeviceNode;
    SIZE_T ListSize;

    DPRINT("IopReportBootResources: DeviceObject - %p, AllocationType - %X\n",
           DeviceObject, AllocationType);

    ListSize = PnpDetermineResourceListSize(CmResource);

    if (!ListSize)
    {
        ASSERT(FALSE);
        return STATUS_SUCCESS;
    }

    if (DeviceObject)
    {
        DeviceNode = IopGetDeviceNode(DeviceObject);
        ASSERT(DeviceNode);

        if (!(DeviceNode->Flags & DNF_MADEUP))
        {
            return IopAllocateBootResources(AllocationType,
                                            DeviceObject,
                                            CmResource);
        }

        if (DeviceNode->BootResources == NULL)
        {
            NewList = ExAllocatePoolWithTag(PagedPool, ListSize, 'erpP');

            DeviceNode->BootResources = NewList;

            if (!NewList)
            {
                ASSERT(FALSE);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            RtlCopyMemory(NewList, CmResource, ListSize);
        }
    }
    else
    {
        ASSERT(FALSE);
        DeviceNode = NULL;
    }

    ReservedContext = ExAllocatePoolWithTag(PagedPool,
                                            sizeof(PNP_RESERVED_RESOURCES_CONTEXT),
                                            'erpP');
    if (!ReservedContext)
    {
        ASSERT(FALSE);

        if (!DeviceNode)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (DeviceNode->BootResources)
        {
            ExFreePoolWithTag(DeviceNode->BootResources, 0);
        }
    }

    if (DeviceNode)
    {
        ReservedResource = DeviceNode->BootResources;
        DPRINT("IopReportBootResources: DeviceNode - %p, InstancePath - %wZ, ServiceName - %wZ\n",
               DeviceNode, &DeviceNode->InstancePath, &DeviceNode->ServiceName);
    }
    else
    {
        ReservedResource = CmResource;
    }

    ReservedContext->ReservedResource = ReservedResource;
    ReservedContext->DeviceObject = DeviceObject;
    ReservedContext->NextReservedContext = IopInitReservedResourceList;

    IopInitReservedResourceList = ReservedContext;

    DPRINT("IopReportBootResources: IopInitReservedResourceList - %p\n",
           IopInitReservedResourceList);

    return STATUS_SUCCESS;
}

/* EOF */
